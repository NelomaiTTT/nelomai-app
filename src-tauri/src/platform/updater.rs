use async_trait::async_trait;
use nelomai_client_api::{
    is_transient_http_io_failure, panel_backup_url, AccessSnapshot, ClientApi, ClientApiError,
    UpdateTransport,
};
#[cfg(not(windows))]
use nelomai_client_updater::InstalledUpdate;
use nelomai_client_updater::{
    DownloadProgress, DownloadValidator, InstallResult, PartialDownload, PreparedCache,
    PreparedUpdate, ResolvedUpdate, ResumedDownload, StagedFile, UpdateBackend, UpdateBackendError,
    UpdateBarrierPhase, UpdateEndpointPolicy,
};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Manager, Runtime};
use tauri_plugin_updater::UpdaterExt;
use tokio::sync::OwnedMutexGuard;

const PANEL_BASE: &str = "https://nelomai.ru";
const MAX_PACKAGE_BYTES: u64 = 1024 * 1024 * 1024;

pub struct DesktopUpdateBackend<R: Runtime> {
    app: AppHandle<R>,
    endpoint_policy: UpdateEndpointPolicy,
    public_key: String,
    api: ClientApi,
    cache: Arc<PreparedCache>,
    download_gate: Arc<tokio::sync::Mutex<()>>,
    selected: Mutex<Option<(ResolvedUpdate, tauri_plugin_updater::Update)>>,
}
impl<R: Runtime> DesktopUpdateBackend<R> {
    pub fn from_build(app: AppHandle<R>, api: ClientApi) -> Result<Self, UpdateBackendError> {
        let key = option_env!("NELOMAI_UPDATER_PUBLIC_KEY")
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| UpdateBackendError::new("updater_public_key_missing"))?;
        Self::new(app, api, PANEL_BASE, key)
    }
    pub fn new(
        app: AppHandle<R>,
        api: ClientApi,
        panel_base: &str,
        public_key: impl Into<String>,
    ) -> Result<Self, UpdateBackendError> {
        let public_key = public_key.into();
        if public_key.trim().is_empty() {
            return Err(UpdateBackendError::new("updater_public_key_missing"));
        }
        let endpoint_policy = UpdateEndpointPolicy::new(panel_base)
            .map_err(|_| UpdateBackendError::new("invalid_update_endpoint"))?;
        let root = app
            .path()
            .app_cache_dir()
            .map_err(|_| UpdateBackendError::new("update_cache_unavailable"))?
            .join("prepared-updates");
        let cache = Arc::new(PreparedCache::open(root)?);
        cache.recover(&app.package_info().version.to_string())?;
        Ok(Self {
            app,
            api,
            endpoint_policy,
            public_key,
            cache,
            download_gate: Arc::new(tokio::sync::Mutex::new(())),
            selected: Mutex::new(None),
        })
    }
    fn validate_descriptor(
        &self,
        resolved: &ResolvedUpdate,
    ) -> Result<tauri::Url, UpdateBackendError> {
        let url = tauri::Url::parse(&resolved.artifact_url)
            .map_err(|_| UpdateBackendError::new("untrusted_update_artifact"))?;
        if !self.endpoint_policy.is_trusted_artifact(&url)
            || resolved.key_identity != self.public_key
            || tauri_plugin_updater::target().as_deref() != Some(resolved.target.as_str())
        {
            return Err(UpdateBackendError::new("untrusted_update_artifact"));
        }
        Ok(url)
    }
}
fn physical_client(
    builder: reqwest_updater::ClientBuilder,
    transport: &UpdateTransport,
) -> reqwest_updater::ClientBuilder {
    let builder = configure_updater_client(builder);
    #[cfg(unix)]
    let builder = builder.unix_socket(transport.unix_socket());
    #[cfg(windows)]
    let builder = builder.windows_named_pipe(transport.windows_named_pipe());
    builder
}
fn download_request(
    client: &reqwest_updater::Client,
    url: &reqwest_updater::Url,
    partial: Option<&PartialDownload>,
) -> reqwest_updater::RequestBuilder {
    use reqwest_updater::header;

    let request = client
        .get(url.clone())
        .header(header::ACCEPT_ENCODING, "identity");
    match partial.and_then(|saved| saved.etag_for(url.as_str()).map(|tag| (saved, tag))) {
        Some((saved, etag)) => request
            .header(header::RANGE, format!("bytes={}-", saved.received()))
            .header(header::IF_RANGE, etag),
        None => request,
    }
}

enum DownloadFile {
    Fresh(StagedFile),
    Resumed(Box<ResumedDownload>),
}

impl DownloadFile {
    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Fresh(file) => file.write_all(bytes),
            Self::Resumed(file) => file.write_all(bytes),
        }
    }
}

async fn download_response(
    cache: &Arc<PreparedCache>,
    resolved: &ResolvedUpdate,
    mut response: reqwest_updater::Response,
    saved: Option<PartialDownload>,
    deadline: tokio::time::Instant,
    mut guard: OwnedMutexGuard<()>,
    mut progress: impl FnMut(DownloadProgress),
) -> Result<(StagedFile, OwnedMutexGuard<()>), UpdateBackendError> {
    use reqwest_updater::{header, StatusCode};

    let header_value = |name: header::HeaderName| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
    };
    let url = response.url().as_str();
    let etag = header_value(header::ETAG);
    let length = response.content_length();
    if response.headers().contains_key(header::CONTENT_ENCODING)
        && header_value(header::CONTENT_ENCODING) != Some("identity")
    {
        return Err(UpdateBackendError::new("update_download_encoding_invalid"));
    }
    let (resume, total, validator) = match response.status() {
        StatusCode::OK if !response.headers().contains_key(header::CONTENT_RANGE) => (
            false,
            length,
            etag.zip(length)
                .and_then(|(etag, total)| DownloadValidator::new(url, etag, total)),
        ),
        StatusCode::PARTIAL_CONTENT => {
            let valid = saved.as_ref().filter(|saved| {
                saved.accepts_range(
                    url,
                    etag.unwrap_or_default(),
                    header_value(header::CONTENT_RANGE).unwrap_or_default(),
                    length,
                )
            });
            let Some(valid) = valid else {
                if let Some(saved) = saved.filter(|saved| saved.etag_for(url).is_some()) {
                    let _ = cache.discard_admitted_partial(saved);
                }
                return Err(UpdateBackendError::new("update_download_range_invalid"));
            };
            let validator = valid.validator().clone();
            (true, Some(validator.total()), Some(validator))
        }
        StatusCode::RANGE_NOT_SATISFIABLE
            if saved
                .as_ref()
                .is_some_and(|saved| saved.etag_for(url).is_some()) =>
        {
            if let Some(saved) = saved {
                let _ = cache.discard_admitted_partial(saved);
            }
            return Err(UpdateBackendError::new("update_download_range_invalid"));
        }
        status => {
            let code = match status {
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                    "update_download_http_unauthorized"
                }
                StatusCode::NOT_FOUND | StatusCode::GONE => "update_download_http_unavailable",
                status if status.is_server_error() => "update_download_http_server_error",
                _ => "update_download_http_rejected",
            };
            return Err(UpdateBackendError::new(code));
        }
    };
    if total.is_some_and(|n| n > MAX_PACKAGE_BYTES) {
        return Err(UpdateBackendError::new("update_package_too_large"));
    }
    if resolved
        .size_bytes
        .zip(total)
        .is_some_and(|(expected, actual)| expected != actual)
    {
        return Err(UpdateBackendError::new("update_download_length_invalid"));
    }
    if total == Some(0) {
        return Err(UpdateBackendError::new("update_download_incomplete"));
    }
    let cache_error = || UpdateBackendError::new("update_cache_unavailable");
    let (mut file, initial) = match saved {
        Some(saved) if resume => {
            let initial = saved.received();
            (
                DownloadFile::Resumed(Box::new(cache.begin_resume(saved)?)),
                initial,
            )
        }
        saved => {
            if let Some(saved) = saved {
                let _ = cache.discard_admitted_partial(saved);
            }
            (DownloadFile::Fresh(cache.begin()?), 0)
        }
    };
    let mut downloaded = initial;
    progress(DownloadProgress { downloaded, total });
    let body_error = loop {
        let chunk = match tokio::time::timeout_at(deadline, response.chunk()).await {
            Ok(Ok(Some(chunk))) => chunk,
            Ok(Ok(None)) => break None,
            Ok(Err(error)) if !error.is_timeout() => break Some("update_download_interrupted"),
            Ok(Err(_)) | Err(_) => break Some("update_download_timeout"),
        };
        downloaded = downloaded
            .checked_add(chunk.len() as u64)
            .filter(|n| *n <= MAX_PACKAGE_BYTES)
            .ok_or_else(|| UpdateBackendError::new("update_package_too_large"))?;
        if total.is_some_and(|total| downloaded > total) {
            return Err(UpdateBackendError::new("update_download_length_invalid"));
        }
        // Keep the exclusive download guard with the blocking write even if
        // consent is withdrawn and the awaiting download future is dropped.
        (file, guard) = tokio::task::spawn_blocking(move || {
            file.write_all(&chunk)?;
            Ok::<_, io::Error>((file, guard))
        })
        .await
        .map_err(|_| cache_error())?
        .map_err(|_| cache_error())?;
        progress(DownloadProgress { downloaded, total });
    };
    if let Some(code) = body_error.or_else(|| {
        (downloaded == 0 || total.is_some_and(|n| n != downloaded))
            .then_some("update_download_incomplete")
    }) {
        if let Some(validator) = validator.filter(|_| downloaded > initial) {
            let cache = cache.clone();
            let identity = resolved.clone();
            tokio::task::spawn_blocking(move || {
                let _guard = guard;
                match file {
                    DownloadFile::Fresh(file) => cache.save_partial(file, &identity, &validator),
                    DownloadFile::Resumed(file) => cache.checkpoint_resume(*file),
                }
            })
            .await
            .map_err(|_| cache_error())??;
        }
        return Err(UpdateBackendError::new(code));
    }
    let temporary = match file {
        DownloadFile::Fresh(file) => file,
        DownloadFile::Resumed(file) => cache.finish_resume(*file)?,
    };
    Ok((temporary, guard))
}

#[async_trait]
impl<R: Runtime> UpdateBackend for DesktopUpdateBackend<R> {
    async fn resolve(
        &self,
        access: &AccessSnapshot,
        expected_version: &str,
    ) -> Result<Option<ResolvedUpdate>, UpdateBackendError> {
        let target = tauri_plugin_updater::target()
            .ok_or_else(|| UpdateBackendError::new("unsupported_update_target"))?;
        let endpoint = self
            .endpoint_policy
            .manifest_url(&target, &self.app.package_info().version.to_string())
            .map_err(|_| UpdateBackendError::new("invalid_update_endpoint"))?;
        let update = updater_request(
            endpoint,
            tokio::time::Instant::now() + Duration::from_secs(20),
            |temporary| {
                if temporary {
                    UpdateBackendError::manifest_temporarily_unavailable()
                } else {
                    UpdateBackendError::new("update_check_failed")
                }
            },
            |endpoint, remaining| async move {
                let transport = self
                    .api
                    .update_transport(&endpoint)
                    .map_err(manifest_transport_failure)?;
                let server_error = Arc::new(AtomicBool::new(false));
                let observe = server_error.clone();
                let host = endpoint.host_str().unwrap_or_default().to_owned();
                let mut builder = self
                    .app
                    .updater_builder()
                    .pubkey(self.public_key.clone())
                    .endpoints(vec![endpoint])
                    .map_err(|_| UpdateBackendError::new("updater_configuration_failed"))?
                    .timeout(remaining)
                    .configure_client(move |builder| {
                        observe_manifest_status(
                            physical_client(builder, &transport),
                            host.clone(),
                            observe.clone(),
                        )
                    });
                for (name, value) in access.bearer_headers() {
                    builder = builder
                        .header(name, value)
                        .map_err(|_| UpdateBackendError::new("updater_authorization_failed"))?;
                }
                let result = builder
                    .build()
                    .map_err(|_| UpdateBackendError::new("updater_configuration_failed"))?
                    .check()
                    .await;
                // Tauri 2.10.1 returns ReleaseNotFound for all non-success
                // HTTP statuses. Only the observed 5xx is temporary.
                match result {
                    Err(tauri_plugin_updater::Error::ReleaseNotFound)
                        if server_error.load(Ordering::Relaxed) =>
                    {
                        Err(UpdaterAttemptError::TemporarilyUnavailable)
                    }
                    result => result.map_err(UpdaterAttemptError::Transport),
                }
            },
        )
        .await?;
        let Some(mut update) = update else {
            *self.selected.lock().expect("updater selection poisoned") = None;
            return Ok(None);
        };
        if update.version != expected_version {
            return Err(UpdateBackendError::new("update_version_changed"));
        }
        let resolved = ResolvedUpdate {
            version: update.version.clone(),
            target,
            artifact_url: update.download_url.to_string(),
            signature: update.signature.clone(),
            key_identity: self.public_key.clone(),
            sha256: None,
            size_bytes: None,
        };
        self.validate_descriptor(&resolved)?;
        #[cfg(target_os = "macos")]
        MacosUpdatePackage::from_url(&update.download_url)?;
        // Native installation needs the plugin's platform configuration, not a token.
        update.headers.clear();
        *self.selected.lock().expect("updater selection poisoned") =
            Some((resolved.clone(), update));
        Ok(Some(resolved))
    }
    async fn prepare(
        &self,
        access: &AccessSnapshot,
        resolved: &ResolvedUpdate,
        progress: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
    ) -> Result<PreparedUpdate, UpdateBackendError> {
        let mut observed = DownloadProgress {
            downloaded: 0,
            total: resolved.size_bytes,
        };
        let result = async {
            let url = self.validate_descriptor(resolved)?;
            let guard = self.download_gate.clone().lock_owned().await;
            let cache = self.cache.clone();
            let identity = resolved.clone();
            let (prepared, guard) = cached_update(guard, move || {
                if let Some((_, file)) = cache.open_cached_package(&identity)? {
                    let verified_sha256 = verify_package_signature(
                        &file,
                        &identity.signature,
                        &identity.key_identity,
                    )
                    .map_err(|error| error.at_stage("verification"))?;
                    return cache
                        .admit_verified(identity, &file, &verified_sha256)
                        .map(Some)
                        .map_err(|error| error.at_stage("verification"));
                }
                Ok(None)
            })
            .await?;
            if let Some(prepared) = prepared {
                return Ok(prepared);
            }
            let primary_partial = self.cache.download_partial_for(resolved, false)?;
            let alternate_partial = self.cache.download_partial_for(resolved, true)?;
            let primary_url = &url;
            let primary_saved = primary_partial.as_ref();
            let alternate_saved = alternate_partial.as_ref();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(15 * 60);
            // A body failure saves a prefix for a later explicit or scheduled check.
            // Only pre-HTTP failures can select a different origin in this attempt.
            let (response, _transport) = updater_request(
                url.clone(),
                deadline,
                |_| UpdateBackendError::new("update_download_request_failed"),
                |url, remaining| async move {
                    let saved = if &url == primary_url {
                        primary_saved
                    } else {
                        alternate_saved
                    };
                    let transport = self
                        .api
                        .update_transport(&url)
                        .map_err(|_| UpdateBackendError::new("update_transport_unavailable"))?;
                    let client = physical_client(reqwest_updater::Client::builder(), &transport)
                        .no_gzip()
                        .no_brotli()
                        .no_zstd()
                        .no_deflate()
                        .timeout(remaining)
                        .build()
                        .map_err(|_| UpdateBackendError::new("updater_configuration_failed"))?;
                    let mut request = download_request(&client, &url, saved);
                    for (name, value) in access.bearer_headers() {
                        request = request.header(name, value);
                    }
                    let response = request
                        .send()
                        .await
                        .map_err(|e| UpdaterAttemptError::Transport(e.into()))?;
                    Ok((response, transport))
                },
            )
            .await?;
            let partial = if response.url() == &url {
                drop(alternate_partial);
                primary_partial
            } else {
                drop(primary_partial);
                alternate_partial
            };
            let (temporary, guard) = download_response(
                &self.cache,
                resolved,
                response,
                partial,
                deadline,
                guard,
                |current| {
                    observed = current;
                    progress(current);
                },
            )
            .await?;
            let cache = self.cache.clone();
            let identity = resolved.clone();
            tokio::task::spawn_blocking(move || {
                let _guard = guard;
                let verified_sha256 = verify_package_signature(
                    temporary.as_file(),
                    &identity.signature,
                    &identity.key_identity,
                )
                .map_err(|error| error.at_stage("verification"))?;
                cache
                    .commit_verified(temporary, identity, &verified_sha256)
                    .map_err(|error| error.at_stage("verification"))
            })
            .await
            .map_err(|_| {
                UpdateBackendError::new("update_verification_failed").at_stage("verification")
            })?
        }
        .await;
        result.map_err(|error| error.at_stage("download").with_progress(observed))
    }
    async fn install_prepared(
        &self,
        prepared: &PreparedUpdate,
        barrier: UpdateBarrierPhase,
    ) -> Result<InstallResult, UpdateBackendError> {
        debug_assert_eq!(barrier, UpdateBarrierPhase::LocalStopped);
        let url = self.validate_descriptor(prepared.resolved())?;
        let update = self
            .selected
            .lock()
            .expect("updater selection poisoned")
            .as_ref()
            .filter(|(identity, _)| identity == prepared.resolved())
            .map(|(_, update)| update.clone())
            .ok_or_else(|| UpdateBackendError::new("update_offer_changed"))?;
        let checked = prepared.clone();
        let bytes = tokio::task::spawn_blocking(move || {
            checked.revalidate()?;
            // Verify the exact Vec passed to the installer, closing a path
            // replacement race between revalidation and reading the payload.
            let bytes = read_package(checked.path())?;
            verify_package_bytes(
                &bytes,
                &checked.resolved().signature,
                &checked.resolved().key_identity,
            )?;
            Ok::<_, UpdateBackendError>(bytes)
        })
        .await
        .map_err(|_| {
            UpdateBackendError::new("update_verification_failed").at_stage("verification")
        })?
        .map_err(|error| error.at_stage("verification"))?;
        #[cfg(target_os = "macos")]
        let macos_package = MacosUpdatePackage::from_url(&url)?;
        #[cfg(not(target_os = "macos"))]
        let _ = url;
        let stop_proof = crate::container::begin_installation(&self.app, &update.version)
            .await
            .map_err(|_| UpdateBackendError::new("update_stop_proof_unavailable"))?;
        #[cfg(windows)]
        {
            crate::desktop::set_tray_visible(&self.app, false);
            let result = crate::container::handoff_windows_installer(&self.app, stop_proof, || {
                update
                    .install(bytes)
                    .map_err(|_| std::io::Error::other("update install failed"))
            })
            .await;
            crate::desktop::set_tray_visible(&self.app, true);
            Err(UpdateBackendError::new(if result.is_err() {
                "update_install_failed"
            } else {
                "update_install_outcome_unknown"
            }))
        }
        #[cfg(not(windows))]
        {
            #[cfg(target_os = "linux")]
            {
                install_linux_common(bytes)
                    .await
                    .map_err(|_| UpdateBackendError::new("update_install_failed"))?;
                crate::container::installation_succeeded(&self.app, stop_proof)
                    .await
                    .map_err(|_| UpdateBackendError::new("update_stop_proof_changed"))?;
            }
            #[cfg(target_os = "macos")]
            crate::container::handoff_macos_installation(
                &self.app,
                stop_proof,
                install_macos_common(bytes, macos_package),
            )
            .await?;
            let _ = self.cache.consumed(prepared); // Startup recovery retries cleanup if filesystem is temporarily unavailable.
            Ok(InstallResult::Installed(InstalledUpdate {
                version: update.version,
            }))
        }
    }
}
async fn cached_update(
    guard: OwnedMutexGuard<()>,
    verify: impl FnOnce() -> Result<Option<PreparedUpdate>, UpdateBackendError> + Send + 'static,
) -> Result<(Option<PreparedUpdate>, OwnedMutexGuard<()>), UpdateBackendError> {
    // A cancelled waiter can leave the blocking verification and cleanup running.
    tokio::task::spawn_blocking(move || verify().map(|prepared| (prepared, guard)))
        .await
        .map_err(|_| UpdateBackendError::new("update_cache_unavailable"))?
}

fn signature_material(
    signature: &str,
    key: &str,
) -> Result<(minisign_verify::PublicKey, minisign_verify::Signature), UpdateBackendError> {
    use base64::Engine;
    let decode = |text: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or_else(|| UpdateBackendError::new("update_signature_invalid"))
    };
    Ok((
        minisign_verify::PublicKey::decode(&decode(key)?)
            .map_err(|_| UpdateBackendError::new("update_signature_invalid"))?,
        minisign_verify::Signature::decode(&decode(signature)?)
            .map_err(|_| UpdateBackendError::new("update_signature_invalid"))?,
    ))
}
fn package_size(metadata: std::fs::Metadata) -> Result<u64, UpdateBackendError> {
    if metadata.is_file() && (1..=MAX_PACKAGE_BYTES).contains(&metadata.len()) {
        Ok(metadata.len())
    } else {
        Err(UpdateBackendError::new("update_cache_invalid"))
    }
}

fn open_package(path: &std::path::Path) -> Result<(File, u64), UpdateBackendError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| UpdateBackendError::new("update_cache_invalid"))?;
    let size = package_size(metadata)?;
    let file = File::open(path).map_err(|_| UpdateBackendError::new("update_cache_invalid"))?;
    Ok((file, size))
}

fn read_package(path: &std::path::Path) -> Result<Vec<u8>, UpdateBackendError> {
    let (file, size) = open_package(path)?;
    read_package_file(&file, size)
}

fn read_package_file(file: &File, expected_size: u64) -> Result<Vec<u8>, UpdateBackendError> {
    let mut bytes = Vec::new();
    file.take(MAX_PACKAGE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| UpdateBackendError::new("update_cache_invalid"))?;
    if bytes.len() as u64 != expected_size {
        return Err(UpdateBackendError::new("update_cache_invalid"));
    }
    Ok(bytes)
}
fn verify_package_bytes(
    bytes: &[u8],
    signature: &str,
    key: &str,
) -> Result<(), UpdateBackendError> {
    let (key, signature) = signature_material(signature, key)?;
    key.verify(bytes, &signature, true)
        .map_err(|_| UpdateBackendError::new("update_signature_invalid"))
}
fn verify_package_signature(
    mut file: &File,
    signature: &str,
    key: &str,
) -> Result<String, UpdateBackendError> {
    let (public_key, signature_value) = signature_material(signature, key)?;
    let metadata = file
        .metadata()
        .map_err(|_| UpdateBackendError::new("update_cache_invalid"))?;
    let expected_size = package_size(metadata)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| UpdateBackendError::new("update_cache_invalid"))?;
    let mut sha256 = Sha256::new();
    let result = public_key.verify_stream(&signature_value);
    match result {
        Ok(mut verifier) => {
            let mut buffer = [0_u8; 64 * 1024];
            let mut size = 0_u64;
            loop {
                let n = file
                    .read(&mut buffer)
                    .map_err(|_| UpdateBackendError::new("update_cache_invalid"))?;
                if n == 0 {
                    break;
                }
                size += n as u64;
                if size > MAX_PACKAGE_BYTES {
                    return Err(UpdateBackendError::new("update_package_too_large"));
                }
                let bytes = &buffer[..n];
                verifier.update(bytes);
                sha256.update(bytes);
            }
            if size != expected_size {
                return Err(UpdateBackendError::new("update_cache_invalid"));
            }
            verifier
                .finalize()
                .map_err(|_| UpdateBackendError::new("update_signature_invalid"))?;
        }
        Err(minisign_verify::Error::UnsupportedLegacyMode) => {
            let bytes = read_package_file(file, expected_size)?;
            public_key
                .verify(&bytes, &signature_value, true)
                .map_err(|_| UpdateBackendError::new("update_signature_invalid"))?;
            sha256.update(&bytes);
        }
        Err(_) => return Err(UpdateBackendError::new("update_signature_invalid")),
    }
    Ok(format!("{:x}", sha256.finalize()))
}

/// Like Linux, macOS activates the complete root-owned common bundle in one
/// authorization. Stock Update::install leaves a user-owned extracted bundle,
/// which otherwise forces another privileged repair during pre-auth startup.
#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MacosUpdatePackage {
    Archive,
    Dmg,
}

#[cfg(target_os = "macos")]
impl MacosUpdatePackage {
    fn from_url(url: &tauri::Url) -> Result<Self, UpdateBackendError> {
        if url.path().ends_with(".app.tar.gz") {
            Ok(Self::Archive)
        } else if url.path().ends_with(".dmg") {
            Ok(Self::Dmg)
        } else {
            Err(UpdateBackendError::new("unsupported_update_package"))
        }
    }
    fn filename(self) -> &'static str {
        match self {
            Self::Archive => "Nelomai.app.tar.gz",
            Self::Dmg => "Nelomai.dmg",
        }
    }
}

#[cfg(target_os = "macos")]
async fn install_macos_common(
    bytes: Vec<u8>,
    package: MacosUpdatePackage,
) -> Result<(), UpdateBackendError> {
    let resources = std::path::Path::new(
        "/Library/Application Support/Nelomai/common/Nelomai.app/Contents/Resources",
    );
    for name in [
        "install-common-macos.sh",
        "install-common-macos.applescript",
    ] {
        for path in resources.join(name).ancestors() {
            nelomai_contracts::dispatcher::trusted(path, 0)
                .map_err(|_| UpdateBackendError::new("common_installer_untrusted"))?;
        }
    }
    let (staging, mut command) =
        stage_macos_update(&bytes, resources, unsafe { libc::getuid() }, package)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _staging = staging;
        let status = super::unix::installer_status(&mut command)
            .map_err(|_| UpdateBackendError::new("update_install_failed"))?;
        if !status.success() {
            return Err(UpdateBackendError::new("update_install_failed"));
        }
        Ok(())
    })
    .await
    .map_err(|_| UpdateBackendError::new("update_install_failed"))?
}

/// Caller verified Update::download's signature, stop barrier and root-owned
/// installer paths. Keep staging alive through authorization; the installer
/// hashes its protected copy before extraction, closing the source-file race.
#[cfg(target_os = "macos")]
fn stage_macos_update(
    bytes: &[u8],
    resources: &std::path::Path,
    owner_uid: libc::uid_t,
    package: MacosUpdatePackage,
) -> Result<(tempfile::TempDir, std::process::Command), UpdateBackendError> {
    use std::{
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };
    if owner_uid == 0 {
        return Err(UpdateBackendError::new("helper_owner_is_root"));
    }
    let staging = tempfile::Builder::new()
        .prefix("nelomai-verified-update-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .map_err(|_| UpdateBackendError::new("update_staging_failed"))?;
    let archive = staging.path().join(package.filename());
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&archive)
        .map_err(|_| UpdateBackendError::new("update_staging_failed"))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| UpdateBackendError::new("update_staging_failed"))?;
    let mut command = std::process::Command::new("/usr/bin/osascript");
    command
        .arg(resources.join("install-common-macos.applescript"))
        .arg(resources.join("install-common-macos.sh"))
        .arg(owner_uid.to_string())
        .arg(archive)
        .arg(nelomai_contracts::dispatcher::digest(bytes));
    Ok((staging, command))
}

/// `Update::download` has already verified the updater signature. The root
/// installer copies and hashes these exact bytes before extracting/activating
/// the complete AppImage; auth and stop barriers stay in the common updater.
#[cfg(target_os = "linux")]
async fn install_linux_common(bytes: Vec<u8>) -> Result<(), UpdateBackendError> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt, path::Path};
    let installer = Path::new("/usr/local/libexec/nelomai/common/install-common-linux.sh");
    for path in installer.ancestors() {
        nelomai_contracts::dispatcher::trusted(path, 0)
            .map_err(|_| UpdateBackendError::new("common_installer_untrusted"))?;
    }
    let staging = tempfile::Builder::new()
        .prefix("nelomai-verified-update-")
        .tempdir()
        .map_err(|_| UpdateBackendError::new("update_staging_failed"))?;
    let image = staging.path().join("Nelomai.AppImage");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&image)
        .map_err(|_| UpdateBackendError::new("update_staging_failed"))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| UpdateBackendError::new("update_staging_failed"))?;
    drop(file);
    let sha = nelomai_contracts::dispatcher::digest(&bytes);
    tauri::async_runtime::spawn_blocking(move || {
        let _staging = staging;
        let status = super::unix::installer_status(
            std::process::Command::new("/usr/bin/pkexec")
                .arg("/bin/sh")
                .arg(installer)
                .arg(image)
                .arg(sha),
        )
        .map_err(|_| UpdateBackendError::new("update_install_failed"))?;
        if !status.success() {
            return Err(UpdateBackendError::new("update_install_failed"));
        }
        Ok(())
    })
    .await
    .map_err(|_| UpdateBackendError::new("update_install_failed"))?
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;
    use std::{ffi::OsString, os::unix::fs::PermissionsExt, path::Path};

    #[test]
    fn macos_update_handoff_pins_private_bytes_and_installed_installer() {
        let resources =
            Path::new("/Library/Application Support/Nelomai/common/Nelomai.app/Contents/Resources");
        let (staging, command) =
            stage_macos_update(b"abc", resources, 501, MacosUpdatePackage::Archive).unwrap();
        let archive = staging.path().join("Nelomai.app.tar.gz");
        assert_eq!(std::fs::read(&archive).unwrap(), b"abc");
        assert_eq!(
            std::fs::metadata(&archive).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(staging.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
        assert_eq!(command.get_program(), "/usr/bin/osascript");
        assert_eq!(
            command.get_args().map(OsString::from).collect::<Vec<_>>(),
            vec![
                resources
                    .join("install-common-macos.applescript")
                    .into_os_string(),
                resources.join("install-common-macos.sh").into_os_string(),
                OsString::from("501"),
                archive.clone().into_os_string(),
                OsString::from("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            ]
        );
        drop(staging);
        assert!(!archive.exists());
    }

    #[test]
    fn dmg_update_stages_verified_image_and_removes_it_on_drop() {
        let package = MacosUpdatePackage::from_url(
            &tauri::Url::parse("https://nelomai.ru/api/artifacts/verified.dmg?token=fixture")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(package, MacosUpdatePackage::Dmg);
        let (staging, command) =
            stage_macos_update(b"signed-image", Path::new("/installed"), 501, package).unwrap();
        let image = staging.path().join("Nelomai.dmg");
        assert_eq!(std::fs::read(&image).unwrap(), b"signed-image");
        assert_eq!(
            std::fs::metadata(&image).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(command.get_args().any(|arg| arg == image.as_os_str()));
        drop(staging);
        assert!(!image.exists());
    }

    #[test]
    fn macos_update_format_uses_only_supported_url_path_suffix() {
        for path in [
            "update.exe",
            "update.zip",
            "update.dmg/other",
            "update.bin?name=update.dmg",
        ] {
            let url = tauri::Url::parse(&format!("https://nelomai.ru/{path}")).unwrap();
            assert!(MacosUpdatePackage::from_url(&url).is_err());
        }
        assert_eq!(
            MacosUpdatePackage::from_url(
                &tauri::Url::parse("https://nelomai.ru/old.app.tar.gz").unwrap()
            )
            .unwrap(),
            MacosUpdatePackage::Archive
        );
    }

    #[test]
    fn macos_update_rejects_root_owner_before_authorization() {
        assert!(
            stage_macos_update(b"abc", Path::new("/unused"), 0, MacosUpdatePackage::Archive)
                .is_err()
        );
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;

    #[tokio::test]
    async fn interrupted_manifest_body_is_temporary_without_fallback() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = reqwest_updater::Url::parse(&format!(
            "http://{}/manifest",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let server = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                assert!(request.len() < 4096);
                request.push(stream.read_u8().await.unwrap());
            }
            assert!(request.starts_with(b"GET /manifest "));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 32\r\nConnection: close\r\n\r\n{\"part\":",
                )
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        };
        let client = configure_updater_client(reqwest_updater::Client::builder())
            .build()
            .unwrap();
        let request = async {
            client
                .get(url.clone())
                .send()
                .await
                .unwrap()
                .json::<serde_json::Value>()
                .await
                .unwrap_err()
        };
        let (error, ()) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(request, server)
        })
        .await
        .unwrap();
        assert!(error.is_decode(), "{error:?}");
        let error = tauri_plugin_updater::Error::from(error);
        assert!(temporary_updater_transport_failure(&error), "{error:?}");
        assert!(!safe_updater_connect_failure(&error, &url));
    }

    #[tokio::test]
    async fn manifest_observer_distinguishes_server_errors_from_definite_http_outcomes() {
        use tokio::net::TcpListener;

        let _ = rustls::crypto::ring::default_provider().install_default();
        for (status, temporary) in [
            ("503 Service Unavailable", true),
            ("401 Unauthorized", false),
            ("403 Forbidden", false),
            ("404 Not Found", false),
            ("302 Found", false),
            ("204 No Content", false),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/manifest", listener.local_addr().unwrap());
            let server = async {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await.unwrap());
                }
                assert!(request.starts_with(b"GET /manifest "));
                let response =
                    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            };
            let observed = Arc::new(AtomicBool::new(false));
            let client = observe_manifest_status(
                configure_updater_client(reqwest_updater::Client::builder()),
                "127.0.0.1".into(),
                observed.clone(),
            )
            .build()
            .unwrap();
            let (response, ()) = tokio::time::timeout(Duration::from_secs(1), async {
                tokio::join!(client.get(&url).send(), server)
            })
            .await
            .unwrap();
            assert_eq!(response.unwrap().status().as_str(), &status[..3]);
            assert_eq!(observed.load(Ordering::Relaxed), temporary, "{status}");
        }
    }

    #[tokio::test]
    async fn manifest_backup_outage_does_not_hide_a_primary_tls_failure() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let result: Result<(), _> = updater_request(
            reqwest_updater::Url::parse("https://nelomai.ru/check").unwrap(),
            tokio::time::Instant::now() + Duration::from_secs(1),
            |temporary| {
                if temporary {
                    UpdateBackendError::manifest_temporarily_unavailable()
                } else {
                    UpdateBackendError::new("update_check_failed")
                }
            },
            |url, _| async move {
                if url.host_str() == Some("nelomai.top") {
                    Err(UpdaterAttemptError::TemporarilyUnavailable)
                } else {
                    Err(UpdaterAttemptError::Transport(
                        pre_http_tls_failure(url).await.into(),
                    ))
                }
            },
        )
        .await;
        assert!(!result.unwrap_err().is_manifest_temporarily_unavailable());
    }

    #[tokio::test]
    async fn manifest_relay_failure_is_temporary_unless_the_origin_or_primary_is_invalid() {
        use std::sync::atomic::AtomicUsize;
        let _ = rustls::crypto::ring::default_provider().install_default();
        for (primary_tls_failed, invalid_origin, expected, calls) in [
            (false, false, "update_manifest_temporarily_unavailable", 1),
            (true, false, "update_check_failed", 2),
            (false, true, "update_transport_unavailable", 1),
        ] {
            let attempts = AtomicUsize::new(0);
            let result: Result<(), _> = updater_request(
                reqwest_updater::Url::parse("https://nelomai.ru/check").unwrap(),
                tokio::time::Instant::now() + Duration::from_secs(2),
                |temporary| {
                    if temporary {
                        UpdateBackendError::manifest_temporarily_unavailable()
                    } else {
                        UpdateBackendError::new("update_check_failed")
                    }
                },
                |url, _| {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    async move {
                        if primary_tls_failed && url.host_str() == Some("nelomai.ru") {
                            return Err(UpdaterAttemptError::Transport(
                                pre_http_tls_failure(url).await.into(),
                            ));
                        }
                        let error = if invalid_origin {
                            ClientApiError::InvalidPayload {
                                code: "control_origin_mismatch",
                            }
                        } else {
                            ClientApiError::ControlTransportUnavailable
                        };
                        Err(manifest_transport_failure(error))
                    }
                },
            )
            .await;
            assert_eq!(result.unwrap_err().code(), expected);
            assert_eq!(attempts.load(Ordering::SeqCst), calls);
        }
    }

    #[tokio::test]
    async fn production_updater_loop_retries_manifest_and_download_once_and_keeps_budget() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let _ = rustls::crypto::ring::default_provider().install_default();
        for operation in ["manifest", "download"] {
            let url =
                reqwest_updater::Url::parse(&format!("https://nelomai.ru/api/{operation}?x=a%2Fb"))
                    .unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let seen = calls.clone();
            let result = updater_request(
                url,
                tokio::time::Instant::now() + Duration::from_secs(1),
                |_| UpdateBackendError::new("fixture_failure"),
                move |url, _| {
                    let seen = seen.clone();
                    async move {
                        seen.fetch_add(1, Ordering::SeqCst);
                        if url.host_str() == Some("nelomai.top") {
                            return Ok(url.to_string());
                        }
                        let error = pre_http_tls_failure(url).await;
                        Err(UpdaterAttemptError::Transport(error.into()))
                    }
                },
            )
            .await
            .unwrap();
            assert_eq!(
                calls.load(Ordering::SeqCst),
                2,
                "{operation} loop omitted its safe alternate"
            );
            assert_eq!(
                result,
                format!("https://nelomai.top/api/{operation}?x=a%2Fb")
            );
        }
        // HTTP/parse failures represented by plugin ReleaseNotFound and
        // configuration errors never select the second origin.
        for backend in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let seen = calls.clone();
            let result: Result<(), _> = updater_request(
                reqwest_updater::Url::parse("https://nelomai.ru/check").unwrap(),
                tokio::time::Instant::now() + Duration::from_secs(1),
                |_| UpdateBackendError::new("fixture_failure"),
                move |_, _| {
                    seen.fetch_add(1, Ordering::SeqCst);
                    async move {
                        if backend {
                            Err(UpdaterAttemptError::Backend(UpdateBackendError::new(
                                "configuration",
                            )))
                        } else {
                            Err(UpdaterAttemptError::Transport(
                                tauri_plugin_updater::Error::ReleaseNotFound,
                            ))
                        }
                    }
                },
            )
            .await;
            assert!(result.is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        // Obtain the real connect error before timing the loop: neither the
        // deadline test nor its second-attempt count depends on OS refusal latency.
        let mut timeout_error = Some(
            pre_http_tls_failure(reqwest_updater::Url::parse("https://nelomai.ru/check").unwrap())
                .await,
        );
        let start = std::time::Instant::now();
        let result = updater_request(
            reqwest_updater::Url::parse("https://nelomai.ru/check").unwrap(),
            tokio::time::Instant::now() + Duration::from_millis(120),
            |_| UpdateBackendError::new("fixture_timeout"),
            move |url, _| {
                let seen = seen.clone();
                let error = timeout_error.take();
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(80)).await;
                    if url.host_str() == Some("nelomai.top") {
                        Ok(())
                    } else {
                        Err(UpdaterAttemptError::Transport(error.unwrap().into()))
                    }
                }
            },
        )
        .await;
        assert_eq!(result.unwrap_err().code(), "fixture_timeout");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(start.elapsed() < Duration::from_millis(180));
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let result: Result<(), _> = updater_request(
            reqwest_updater::Url::parse("https://nelomai.ru/check").unwrap(),
            tokio::time::Instant::now() + Duration::from_secs(1),
            |_| UpdateBackendError::new("fixture_failure"),
            move |url, _| {
                let seen = seen.clone();
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    Err(UpdaterAttemptError::Transport(
                        pre_http_tls_failure(url).await.into(),
                    ))
                }
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "backup failure recursively retried"
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let cancelled = updater_request(
            reqwest_updater::Url::parse("https://nelomai.ru/check").unwrap(),
            tokio::time::Instant::now() + Duration::from_secs(1),
            |_| UpdateBackendError::new("fixture_failure"),
            move |_, _| {
                seen.fetch_add(1, Ordering::SeqCst);
                async {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    Ok::<_, UpdaterAttemptError>(())
                }
            },
        );
        assert!(tokio::time::timeout(Duration::from_millis(20), cancelled)
            .await
            .is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Avoid depending on OS closed-port refusal latency: observe a real
    // TLS ClientHello and reject the handshake before
    // HTTP. The DNS override keeps the production HTTPS/default-port URL intact.
    // Both futures are owned here and dropped together on timeout/cancellation.
    async fn pre_http_tls_failure(url: reqwest_updater::Url) -> reqwest_updater::Error {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = configure_updater_client(reqwest_updater::Client::builder())
            .resolve_to_addrs(url.host_str().unwrap(), &[listener.local_addr().unwrap()])
            .build()
            .unwrap();
        let (response, ()) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(client.post(url.clone()).body("once").send(), async {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut header = [0; 5];
                socket.read_exact(&mut header).await.unwrap();
                assert_eq!(
                    header[0], 22,
                    "expected TLS handshake, not HTTP: {header:?}"
                );
                assert_eq!(header[1], 3, "expected TLS record version: {header:?}");
                let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
                assert!(
                    (4..=16384).contains(&length),
                    "invalid ClientHello record length"
                );
                let mut hello = vec![0; length];
                socket.read_exact(&mut hello).await.unwrap();
                assert_eq!(hello[0], 1, "expected TLS ClientHello");
                // TLS fatal handshake_failure alert; no certificate or HTTP response.
                socket.write_all(&[21, 3, 3, 0, 2, 2, 40]).await.unwrap();
                socket.shutdown().await.unwrap();
            })
        })
        .await
        .expect("local TLS failure fixture exceeded its bound");
        let error = response.unwrap_err();
        assert!(
            error.is_connect() && !error.is_timeout() && error.url() == Some(&url),
            "TLS fixture: connect={} timeout={} url={:?} error={error:?}",
            error.is_connect(),
            error.is_timeout(),
            error.url()
        );
        error
    }

    // Real reqwest 0.13 errors: textual error matching would not establish
    // whether HTTP bytes had already reached the peer.
    #[tokio::test]
    async fn updater_classifier_accepts_only_initial_pre_http_connect_failure() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let url = reqwest_updater::Url::parse("https://nelomai.ru/initial").unwrap();
        let error = tauri_plugin_updater::Error::from(pre_http_tls_failure(url.clone()).await);
        eprintln!("local pre-HTTP TLS fixture returned {error:?}");
        assert!(safe_updater_connect_failure(&error, &url), "{error:?}");
        assert!(!temporary_updater_transport_failure(&error), "{error:?}");
        assert!(
            !safe_updater_connect_failure(&error, &url.join("/later").unwrap()),
            "a connect error for a different URL qualified for fallback: {error:?}"
        );
        let client = configure_updater_client(reqwest_updater::Client::builder())
            .timeout(Duration::from_secs(1))
            .build()
            .unwrap();
        for mode in 0..4 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = reqwest_updater::Url::parse(&format!(
                "http://{}/initial",
                listener.local_addr().unwrap()
            ))
            .unwrap();
            let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let later = format!("http://{}/later", closed.local_addr().unwrap());
            drop(closed);
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = [0; 4096];
                assert!(socket.read(&mut bytes).await.unwrap() > 0);
                if mode == 1 {
                    socket.write_all(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                } else if mode == 2 {
                    socket.write_all(format!("HTTP/1.1 307 Redirect\r\nLocation: {later}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
                } else if mode == 3 {
                    socket
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Len")
                        .await
                        .unwrap();
                }
            });
            // Exercise the production policy: even a same-operation later
            // connect error cannot turn an accepted redirect into a replay.
            let result = client
                .post(url.clone())
                .body("once")
                .send()
                .await
                .and_then(|r| r.error_for_status());
            if mode == 2 {
                assert_eq!(
                    result.unwrap().status(),
                    307,
                    "redirect was followed after HTTP was sent"
                );
            } else {
                let error = tauri_plugin_updater::Error::from(result.unwrap_err());
                assert!(
                    !safe_updater_connect_failure(&error, &url),
                    "ambiguous outcome mode {mode} qualified for fallback"
                );
                assert_eq!(
                    temporary_updater_transport_failure(&error),
                    matches!(mode, 0 | 3),
                    "mode {mode}: {error:?}"
                );
            }
            server.await.unwrap();
        }
        assert!(!safe_updater_connect_failure(
            &tauri_plugin_updater::Error::ReleaseNotFound,
            &url
        ));
    }
}

fn safe_updater_connect_failure(
    error: &tauri_plugin_updater::Error,
    url: &reqwest_updater::Url,
) -> bool {
    matches!(error, tauri_plugin_updater::Error::Reqwest(error)
        if error.is_connect() && error.url() == Some(url))
}

// The connect classifier is safe only when no previous HTTP hop can have run.
fn configure_updater_client(
    builder: reqwest_updater::ClientBuilder,
) -> reqwest_updater::ClientBuilder {
    builder
        .no_proxy()
        .redirect(reqwest_updater::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(8))
}

// The plugin's client callback can observe the response without a second
// authenticated request. Returning success from the classifier disables retries.
fn observe_manifest_status(
    builder: reqwest_updater::ClientBuilder,
    host: String,
    server_error: Arc<AtomicBool>,
) -> reqwest_updater::ClientBuilder {
    builder.retry(
        reqwest_updater::retry::for_host(host).classify_fn(move |exchange| {
            server_error.store(
                exchange
                    .status()
                    .is_some_and(|status| status.is_server_error()),
                Ordering::Relaxed,
            );
            exchange.success()
        }),
    )
}

fn temporary_updater_transport_failure(error: &tauri_plugin_updater::Error) -> bool {
    matches!(
        error,
        tauri_plugin_updater::Error::Reqwest(error)
            if error.is_timeout() || is_transient_http_io_failure(error)
    )
}

fn manifest_transport_failure(error: ClientApiError) -> UpdaterAttemptError {
    match error {
        ClientApiError::ControlTransportUnavailable => UpdaterAttemptError::TemporarilyUnavailable,
        _ => UpdateBackendError::new("update_transport_unavailable").into(),
    }
}

#[derive(Debug)]
enum UpdaterAttemptError {
    Backend(UpdateBackendError),
    TemporarilyUnavailable,
    Transport(tauri_plugin_updater::Error),
}
impl From<UpdateBackendError> for UpdaterAttemptError {
    fn from(error: UpdateBackendError) -> Self {
        Self::Backend(error)
    }
}

// Both real plugin operations use this loop; the attempt seam leaves their
// signature/version/artifact checks in place while making retries testable.
async fn updater_request<T, F, Fut>(
    mut url: reqwest_updater::Url,
    deadline: tokio::time::Instant,
    failure: impl Fn(bool) -> UpdateBackendError,
    mut attempt: F,
) -> Result<T, UpdateBackendError>
where
    F: FnMut(reqwest_updater::Url, Duration) -> Fut,
    Fut: std::future::Future<Output = Result<T, UpdaterAttemptError>>,
{
    let mut backup = panel_backup_url(&url);
    let mut only_temporary = true;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(failure(only_temporary));
        }
        match tokio::time::timeout_at(deadline, attempt(url.clone(), remaining)).await {
            Ok(Ok(value)) => return Ok(value),
            Ok(Err(UpdaterAttemptError::Backend(error))) => return Err(error),
            Ok(Err(UpdaterAttemptError::Transport(error)))
                if safe_updater_connect_failure(&error, &url) =>
            {
                only_temporary &= temporary_updater_transport_failure(&error);
                url = backup.take().ok_or_else(|| failure(only_temporary))?;
            }
            Ok(Err(UpdaterAttemptError::Transport(error))) => {
                return Err(failure(
                    only_temporary && temporary_updater_transport_failure(&error),
                ));
            }
            Ok(Err(UpdaterAttemptError::TemporarilyUnavailable)) | Err(_) => {
                return Err(failure(only_temporary));
            }
        }
    }
}

#[cfg(test)]
mod prepared_signature_tests {
    use super::*;
    use base64::Engine;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn cancelled_cached_admission_holds_the_download_gate_until_worker_finishes() {
        let gate = Arc::new(tokio::sync::Mutex::new(()));
        let guard = gate.clone().lock_owned().await;
        let (entered, entered_worker) = oneshot::channel();
        let (release, release_worker) = std::sync::mpsc::channel();
        let lookup = tokio::spawn(cached_update(guard, move || {
            entered.send(()).unwrap();
            release_worker.recv().unwrap();
            Ok(None)
        }));
        entered_worker.await.unwrap();

        lookup.abort();
        assert!(lookup.await.unwrap_err().is_cancelled());
        let gate_held_after_cancellation = gate.try_lock().is_err();
        release.send(()).unwrap();
        assert!(gate_held_after_cancellation);

        let guard = tokio::time::timeout(Duration::from_secs(5), gate.clone().lock_owned())
            .await
            .unwrap();
        let (prepared, guard) = cached_update(guard, || Ok(None)).await.unwrap();
        assert!(prepared.is_none());
        assert!(gate.try_lock().is_err());
        drop(guard);
        assert!(gate.try_lock().is_ok());
    }

    async fn read_request(socket: &mut TcpStream) -> String {
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            assert!(request.len() < 4096);
            request.push(socket.read_u8().await.unwrap());
        }
        String::from_utf8(request).unwrap().to_ascii_lowercase()
    }

    #[tokio::test]
    async fn alternate_response_keeps_primary_and_resumes_its_own_interrupted_body() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        enum Prefix {
            Current,
            Stale,
            LinkedStale,
        }
        for (headers, expected_size, expected_error, prefix, body) in [
            (
                "200 OK\r\nContent-Length: 11\r\nETag: \"alternate\"",
                Some(11),
                None,
                Prefix::Current,
                Some("hello world"),
            ),
            (
                "200 OK\r\nContent-Length: 11",
                Some(11),
                Some("update_download_interrupted"),
                Prefix::Current,
                Some("hey"),
            ),
            (
                "200 OK\r\nContent-Length: 11\r\nETag: \"alternate\"",
                Some(11),
                Some("update_download_interrupted"),
                Prefix::Current,
                Some("go"),
            ),
            (
                "200 OK\r\nContent-Length: 11",
                Some(11),
                None,
                Prefix::Stale,
                Some("hello world"),
            ),
            (
                "200 OK\r\nContent-Length: 11",
                Some(11),
                None,
                Prefix::LinkedStale,
                Some("hello world"),
            ),
            (
                "200 OK\r\nContent-Length: 12",
                Some(11),
                Some("update_download_length_invalid"),
                Prefix::Current,
                None,
            ),
            (
                "200 OK\r\nContent-Length: 0",
                None,
                Some("update_download_incomplete"),
                Prefix::Current,
                None,
            ),
            (
                "200 OK\r\nContent-Length: 11\r\nContent-Encoding: gzip",
                Some(11),
                Some("update_download_encoding_invalid"),
                Prefix::Current,
                None,
            ),
            (
                "206 Partial Content\r\nContent-Length: 6\r\nContent-Range: bytes 5-10/11",
                Some(11),
                Some("update_download_range_invalid"),
                Prefix::Current,
                None,
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("packages");
            let cache = Arc::new(PreparedCache::open(path.clone()).unwrap());
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            // Resolve the alternate host to loopback at the HTTP test seam.
            let primary = format!("http://nelomai.ru:{port}/artifact");
            let alternate: reqwest_updater::Url = format!("http://nelomai.top:{port}/artifact")
                .parse()
                .unwrap();
            let descriptor = ResolvedUpdate {
                version: "0.4.3".into(),
                target: "test-target".into(),
                artifact_url: primary.clone(),
                signature: "signature".into(),
                key_identity: "key".into(),
                sha256: None,
                size_bytes: expected_size,
            };
            let old_is_alternate = !matches!(prefix, Prefix::Current);
            let old_url = if old_is_alternate {
                alternate.as_str()
            } else {
                &primary
            };
            let validator = DownloadValidator::new(old_url, "\"artifact-a\"", 11).unwrap();
            let mut old_descriptor = descriptor.clone();
            if old_is_alternate {
                old_descriptor.signature = "older artifact".into();
            }
            let mut old_file = cache.begin().unwrap();
            old_file.write_all(b"hello").unwrap();
            cache
                .save_partial(old_file, &old_descriptor, &validator)
                .unwrap();
            let old_path = path.join(if old_is_alternate {
                "resume-download-alternate.bin"
            } else {
                "resume-download.bin"
            });
            let outside = root.path().join("outside");
            if matches!(prefix, Prefix::LinkedStale) {
                std::fs::hard_link(&old_path, &outside).unwrap();
            }
            let saved = cache.download_partial_for(&descriptor, true).unwrap();
            assert_eq!(saved.is_some(), matches!(prefix, Prefix::Stale));
            let (start_body, ready) = oneshot::channel();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let server = async {
                let (mut socket, _) = listener.accept().await.unwrap();
                let request = read_request(&mut socket).await;
                assert!(request.contains("\r\nhost: nelomai.top:"));
                assert!(!request.contains("\r\nrange:"));
                assert!(!request.contains("\r\nif-range:"));
                socket
                    .write_all(
                        format!("HTTP/1.1 {headers}\r\nConnection: close\r\n\r\n").as_bytes(),
                    )
                    .await
                    .unwrap();
                if let Some(body) = body {
                    ready.await.unwrap();
                    socket.write_all(body.as_bytes()).await.unwrap();
                }
                socket.shutdown().await.unwrap();
            };
            let download = async {
                let client = configure_updater_client(reqwest_updater::Client::builder())
                    .resolve("nelomai.top", listener.local_addr().unwrap())
                    .no_gzip()
                    .build()
                    .unwrap();
                let response = download_request(&client, &alternate, saved.as_ref())
                    .send()
                    .await
                    .unwrap();
                let gate = Arc::new(tokio::sync::Mutex::new(()));
                let mut start_body = Some(start_body);
                let result = download_response(
                    &cache,
                    &descriptor,
                    response,
                    saved,
                    deadline,
                    gate.lock_owned().await,
                    |progress| {
                        assert!(body.is_some());
                        if progress.downloaded == 0 {
                            assert_eq!(old_path.exists(), !matches!(prefix, Prefix::Stale));
                            assert_eq!(
                                cache.partial(&descriptor).unwrap().is_some(),
                                matches!(prefix, Prefix::Current)
                            );
                            start_body.take().unwrap().send(()).unwrap();
                        }
                    },
                )
                .await;
                if let Some(code) = expected_error {
                    assert_eq!(result.unwrap_err().code(), code);
                    let reopened = PreparedCache::open(path.clone()).unwrap();
                    reopened.recover("0.4.0").unwrap();
                    let retained = reopened
                        .download_partial_for(&descriptor, false)
                        .unwrap()
                        .unwrap();
                    assert_eq!(retained.received(), 5);
                    assert_eq!(retained.etag_for(&primary), Some("\"artifact-a\""));
                    assert_eq!(std::fs::read(&old_path).unwrap(), b"hello");
                    let alternate_partial =
                        reopened.download_partial_for(&descriptor, true).unwrap();
                    if let Some(body) = body.filter(|_| headers.contains("ETag:")) {
                        let saved = alternate_partial.unwrap();
                        assert_eq!(saved.received(), body.len() as u64);
                        assert!(saved.etag_for(&primary).is_none());
                        let request = download_request(&client, &alternate, Some(&saved))
                            .build()
                            .unwrap();
                        let range = format!("bytes={}-", body.len());
                        assert_eq!(
                            request.headers()[reqwest_updater::header::RANGE],
                            range.as_str()
                        );
                        assert_eq!(
                            request.headers()[reqwest_updater::header::IF_RANGE],
                            "\"alternate\""
                        );
                        let server = async {
                            let (mut socket, _) = listener.accept().await.unwrap();
                            let request = read_request(&mut socket).await;
                            assert!(request.contains("\r\nrange: bytes=2-\r\n"));
                            assert!(request.contains("\r\nif-range: \"alternate\"\r\n"));
                            socket.write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Length: 9\r\nContent-Range: bytes 2-10/11\r\nETag: \"alternate\"\r\nConnection: close\r\n\r\nod bytes!").await.unwrap();
                            socket.shutdown().await.unwrap();
                        };
                        let reopened = Arc::new(reopened);
                        let resume = async {
                            let response = client.execute(request).await.unwrap();
                            let gate = Arc::new(tokio::sync::Mutex::new(()));
                            download_response(
                                &reopened,
                                &descriptor,
                                response,
                                Some(saved),
                                deadline,
                                gate.lock_owned().await,
                                |_| {},
                            )
                            .await
                            .unwrap()
                        };
                        let ((), (complete, _)) = tokio::join!(server, resume);
                        assert_eq!(std::fs::read(complete.path()).unwrap(), b"good bytes!");
                        assert_eq!(std::fs::read(&old_path).unwrap(), b"hello");
                    } else {
                        assert!(alternate_partial.is_none());
                    }
                } else {
                    let (complete, _) = result.unwrap();
                    assert_eq!(std::fs::read(complete.path()).unwrap(), b"hello world");
                    if matches!(prefix, Prefix::LinkedStale) {
                        assert_eq!(std::fs::read(outside).unwrap(), b"hello");
                    }
                }
            };
            tokio::time::timeout_at(deadline, async { tokio::join!(server, download) })
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn http_responses_preserve_a_partial_replaced_after_the_request() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        enum Replacement {
            Data,
            Sidecar,
            StaleData,
        }
        const FULL: &str = "200 OK\r\nContent-Length: 11\r\n\r\nhello world";
        for (response_bytes, expected_error, replacement) in [
            (FULL, None, Replacement::Data),
            (FULL, None, Replacement::Sidecar),
            (FULL, None, Replacement::StaleData),
            (
                "206 Partial Content\r\nContent-Length: 6\r\nContent-Range: bytes 4-9/11\r\n\r\n world",
                Some("update_download_range_invalid"),
                Replacement::Data,
            ),
            (
                "416 Range Not Satisfiable\r\nContent-Length: 0\r\n\r\n",
                Some("update_download_range_invalid"),
                Replacement::Data,
            ),
            (
                "200 OK\r\nContent-Length: 11\r\n\r\nhello",
                Some("update_download_interrupted"),
                Replacement::Data,
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("packages");
            let cache = Arc::new(PreparedCache::open(path.clone()).unwrap());
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url: reqwest_updater::Url = format!("http://{}/artifact", listener.local_addr().unwrap())
                .parse().unwrap();
            let descriptor = ResolvedUpdate {
                version: "0.4.3".into(),
                target: "test-target".into(),
                artifact_url: url.to_string(),
                signature: "signature".into(),
                key_identity: "key".into(),
                sha256: None,
                size_bytes: Some(11),
            };
            let validator = DownloadValidator::new(url.as_str(), "\"artifact-a\"", 11).unwrap();
            let mut prefix = cache.begin().unwrap();
            prefix.write_all(b"hello").unwrap();
            let mut prior = descriptor.clone();
            let stale = matches!(replacement, Replacement::StaleData);
            if stale {
                prior.signature = "older artifact".into();
            }
            cache.save_partial(prefix, &prior, &validator).unwrap();
            let saved = cache.download_partial(&descriptor).unwrap().unwrap();
            let data = path.join("resume-download.bin");
            let sidecar = path.join("resume-download.json");
            let metadata = std::fs::read(&sidecar).unwrap();
            let (written, close) = oneshot::channel();
            let server = async {
                let (mut socket, _) = listener.accept().await.unwrap();
                let request = read_request(&mut socket).await;
                assert_eq!(request.contains("\r\nrange: bytes=5-\r\n"), !stale);
                if matches!(replacement, Replacement::Sidecar) {
                    std::fs::rename(&sidecar, root.path().join("admitted")).unwrap();
                    std::fs::write(&sidecar, &metadata).unwrap();
                } else {
                    std::fs::rename(&data, root.path().join("admitted")).unwrap();
                    std::fs::write(&data, b"other").unwrap();
                }
                let reply = response_bytes.replacen(
                    "\r\n",
                    "\r\nETag: \"artifact-a\"\r\nConnection: close\r\n",
                    1,
                );
                socket
                    .write_all(format!("HTTP/1.1 {reply}").as_bytes())
                    .await
                    .unwrap();
                if expected_error == Some("update_download_interrupted") {
                    close.await.unwrap();
                }
                socket.shutdown().await.unwrap();
            };
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let download = async {
                let client = configure_updater_client(reqwest_updater::Client::builder()).build().unwrap();
                let response = download_request(&client, &url, Some(&saved)).send().await.unwrap();
                let gate = Arc::new(tokio::sync::Mutex::new(()));
                let mut written = Some(written);
                let result = download_response(
                    &cache,
                    &descriptor,
                    response,
                    Some(saved),
                    deadline,
                    gate.lock_owned().await,
                    |status| {
                        if expected_error == Some("update_download_interrupted") && status.downloaded == 5 {
                            written.take().unwrap().send(()).unwrap();
                        }
                    },
                ).await;
                if let Some(error) = expected_error {
                    assert_eq!(result.unwrap_err().code(), error);
                } else {
                    let (temporary, _guard) = result.unwrap();
                    let verified_sha256 = format!("{:x}", Sha256::digest(b"hello world"));
                    let prepared = cache
                        .commit_verified(temporary, descriptor, &verified_sha256)
                        .unwrap();
                    assert_eq!(std::fs::read(prepared.path()).unwrap(), b"hello world");
                }
            };
            tokio::time::timeout_at(deadline, async { tokio::join!(server, download) }).await.unwrap();
            let expected_data = if matches!(replacement, Replacement::Sidecar) {
                b"hello"
            } else {
                b"other"
            };
            assert_eq!(std::fs::read(&data).unwrap(), expected_data);
            assert_eq!(std::fs::read(&sidecar).unwrap(), metadata);
        }
    }

    #[tokio::test]
    async fn broken_http_body_resumes_after_cache_reopen() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("packages");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url: reqwest_updater::Url =
            format!("http://{}/artifact", listener.local_addr().unwrap())
                .parse()
                .unwrap();
        let descriptor = ResolvedUpdate {
            version: "0.4.3".into(),
            target: "test-target".into(),
            artifact_url: url.to_string(),
            signature: "signature".into(),
            key_identity: "key".into(),
            sha256: None,
            size_bytes: Some(11),
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let (received_prefix, close_first) = oneshot::channel();
        let server = async {
            let (mut first, _) = listener.accept().await.unwrap();
            let request = read_request(&mut first).await;
            assert!(!request.contains("\r\nrange:"));
            first.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nETag: \"artifact-a\"\r\nConnection: close\r\n\r\nhello").await.unwrap();
            close_first.await.unwrap();
            first.shutdown().await.unwrap();
            drop(first);
            let (mut next, _) = listener.accept().await.unwrap();
            let request = read_request(&mut next).await;
            assert!(request.contains("\r\nrange: bytes=5-\r\n"));
            assert!(request.contains("\r\nif-range: \"artifact-a\"\r\n"));
            next.write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Length: 6\r\nContent-Range: bytes 5-10/11\r\nETag: \"artifact-a\"\r\nConnection: close\r\n\r\n world").await.unwrap();
            next.shutdown().await.unwrap();
        };
        let download = async {
            let client = configure_updater_client(reqwest_updater::Client::builder())
                .build()
                .unwrap();
            let cache = Arc::new(PreparedCache::open(path.clone()).unwrap());
            let response = download_request(&client, &url, None).send().await.unwrap();
            let mut received_prefix = Some(received_prefix);
            let gate = Arc::new(tokio::sync::Mutex::new(()));
            let error = download_response(
                &cache,
                &descriptor,
                response,
                None,
                deadline,
                gate.clone().lock_owned().await,
                |status| {
                    if status.downloaded == 5 {
                        assert_eq!(status.total, Some(11));
                        received_prefix.take().unwrap().send(()).unwrap();
                    }
                },
            )
            .await
            .unwrap_err();
            assert_eq!(error.code(), "update_download_interrupted");
            drop(cache);

            #[cfg(unix)]
            let original_inode = {
                use std::os::unix::fs::MetadataExt;
                std::fs::metadata(path.join("resume-download.bin"))
                    .unwrap()
                    .ino()
            };
            let cache = Arc::new(PreparedCache::open(path).unwrap());
            cache.recover("0.4.2").unwrap();
            let saved = cache.partial(&descriptor).unwrap().unwrap();
            let response = download_request(&client, &url, Some(&saved))
                .send()
                .await
                .unwrap();
            let mut counts = Vec::new();
            let (complete, _guard) = download_response(
                &cache,
                &descriptor,
                response,
                Some(saved),
                deadline,
                gate.lock_owned().await,
                |status| {
                    counts.push(status.downloaded);
                },
            )
            .await
            .unwrap();
            assert_eq!(counts, [5, 11]);
            assert_eq!(std::fs::read(complete.path()).unwrap(), b"hello world");
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                assert_eq!(
                    complete.as_file().metadata().unwrap().ino(),
                    original_inode,
                    "resuming must reuse the saved file's storage"
                );
            }
        };
        tokio::time::timeout_at(deadline, async { tokio::join!(server, download) })
            .await
            .unwrap();
    }

    fn signed_package_material(legacy: bool) -> (String, String) {
        // Public minisign-verify 0.2.5 vectors for the exact bytes `test`.
        let key="untrusted comment: minisign public key E7620F1842B4E81F\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
        let signature = if legacy {
            "untrusted comment: signature from minisign secret key\nRWQf6LRCGA9i59SLOFxz6NxvASXDJeRtuZykwQepbDEGt87ig1BNpWaVWuNrm73YiIiJbq71Wi+dP9eKL8OC351vwIasSSbXxwA=\ntrusted comment: timestamp:1555779966\tfile:test\nQtKMXWyYcwdpZAlPF7tE2ENJkRd1ujvKjlj1m9RtHTBnZPa5WKU5uWRs5GoP5M/VqE81QFuMKI5k/SfNQUaOAA=="
        } else {
            "untrusted comment: signature from minisign secret key\nRUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\ntrusted comment: timestamp:1556193335\tfile:test\ny/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg=="
        };
        let encoded = base64::engine::general_purpose::STANDARD;
        (encoded.encode(signature), encoded.encode(key))
    }

    #[test]
    fn cached_package_requires_real_signature_again_before_install() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("package");
        let expected_sha256 = format!("{:x}", Sha256::digest(b"test"));
        for legacy in [false, true] {
            let (signature, key) = signed_package_material(legacy);
            std::fs::write(&file, b"test").unwrap();
            let (package, _) = open_package(&file).unwrap();
            assert_eq!(
                verify_package_signature(&package, &signature, &key).unwrap(),
                expected_sha256
            );
            std::fs::write(&file, b"Test").unwrap();
            assert!(verify_package_signature(&package, &signature, &key).is_err());
        }
    }

    #[test]
    fn staged_signature_verifies_the_pinned_file_after_path_replacement() {
        let root = tempfile::tempdir().unwrap();
        let cache = PreparedCache::open(root.path().join("packages")).unwrap();
        let mut staged = cache.begin().unwrap();
        staged.write_all(b"Test").unwrap();
        let replacement = staged.path().to_owned();
        let original = root.path().join("original");
        std::fs::rename(&replacement, &original).unwrap();
        std::fs::write(&replacement, b"test").unwrap();

        for legacy in [false, true] {
            let (signature, key) = signed_package_material(legacy);
            assert_eq!(
                verify_package_signature(staged.as_file(), &signature, &key)
                    .unwrap_err()
                    .code(),
                "update_signature_invalid"
            );
        }
        drop(staged);
        assert_eq!(std::fs::read(replacement).unwrap(), b"test");
        assert_eq!(std::fs::read(original).unwrap(), b"Test");
    }

    #[test]
    fn staged_commit_rejects_same_size_mutation_after_signature_verification() {
        let (signature, key) = signed_package_material(false);
        let root = tempfile::tempdir().unwrap();
        let cache = PreparedCache::open(root.path().join("packages")).unwrap();
        let mut staged = cache.begin().unwrap();
        staged.write_all(b"test").unwrap();
        let verified_sha256 = verify_package_signature(staged.as_file(), &signature, &key).unwrap();
        std::fs::write(staged.path(), b"Test").unwrap();

        let descriptor = ResolvedUpdate {
            version: "0.4.3".into(),
            target: "test-target".into(),
            artifact_url: "https://nelomai.ru/artifact".into(),
            signature,
            key_identity: key,
            sha256: None,
            size_bytes: Some(4),
        };
        assert_eq!(
            cache
                .commit_verified(staged, descriptor.clone(), &verified_sha256)
                .unwrap_err()
                .code(),
            "update_hash_mismatch"
        );
        assert!(cache.cached_path(&descriptor).unwrap().is_none());
    }
}
