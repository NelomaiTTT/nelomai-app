use crate::{
    AndroidManifestError, AndroidUpdateManifest, DownloadProgress, InstallResult, InstalledUpdate,
    PreparedUpdate, ResolvedUpdate, UpdateBackend, UpdateBackendError, UpdateBarrierPhase,
    UpdateEndpointPolicy,
};
use async_trait::async_trait;
use nelomai_client_api::{execute_panel_request, panel_http_client_builder, AccessSnapshot};
use reqwest::{Client, StatusCode};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PANEL_BASE: &str = "https://nelomai.ru";
const ANDROID_TARGET: &str = "android-aarch64";

#[async_trait]
pub trait AndroidApkInstaller: Send + Sync {
    async fn validate_apk(
        &self,
        _path: &Path,
        _version: &str,
        _signer: &str,
    ) -> Result<(), UpdateBackendError> {
        Err(UpdateBackendError::new("apk_validation_unavailable"))
    }
    async fn install_apk(
        &self,
        path: &Path,
        version: &str,
        signer: &str,
    ) -> Result<bool, UpdateBackendError>;
}

pub struct AndroidUpdateBackend {
    current_container_version: String,
    installer: Arc<dyn AndroidApkInstaller>,
    endpoint_policy: UpdateEndpointPolicy,
    http: Client,
    update_dir: PathBuf,
    cache_use: Arc<tokio::sync::Mutex<()>>,
}

impl AndroidUpdateBackend {
    pub fn new(
        update_dir: PathBuf,
        current_container_version: String,
        installer: Arc<dyn AndroidApkInstaller>,
    ) -> Result<Self, UpdateBackendError> {
        let endpoint_policy = UpdateEndpointPolicy::new(PANEL_BASE)
            .map_err(|_| UpdateBackendError::new("invalid_update_endpoint"))?;
        let http = panel_http_client_builder()
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(15 * 60))
            .build()
            .map_err(|_| UpdateBackendError::new("updater_configuration_failed"))?;
        Ok(Self {
            current_container_version,
            installer,
            endpoint_policy,
            http,
            update_dir,
            cache_use: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    fn validated_resolved(
        &self,
        resolved: &ResolvedUpdate,
    ) -> Result<crate::ValidatedAndroidUpdate, UpdateBackendError> {
        if resolved.target != ANDROID_TARGET || resolved.key_identity != resolved.signature {
            return Err(UpdateBackendError::new("invalid_update_manifest"));
        }
        AndroidUpdateManifest {
            version: resolved.version.clone(),
            url: resolved.artifact_url.clone(),
            signature: resolved.signature.clone(),
            sha256: resolved.sha256.clone().unwrap_or_default(),
            size_bytes: resolved.size_bytes.unwrap_or_default(),
        }
        .validate(&resolved.version, &self.endpoint_policy)
        .map_err(manifest_error)
    }

    async fn download(
        &self,
        access_token: &AccessSnapshot,
        update: &crate::ValidatedAndroidUpdate,
        progress: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
    ) -> Result<PathBuf, UpdateBackendError> {
        fs::create_dir_all(&self.update_dir)
            .await
            .map_err(|_| UpdateBackendError::new("update_cache_unavailable"))?;
        let temporary = self.update_dir.join(".nelomai-update.part");
        let destination = self
            .update_dir
            .join(format!("nelomai-{}.apk", update.version));
        remove_if_exists(&temporary).await?;

        let mut request = self.http.get(update.artifact_url.clone());
        for (name, value) in access_token.bearer_headers() {
            request = request.header(name, value);
        }
        let mut response = execute_panel_request(
            &self.http,
            request
                .build()
                .map_err(|_| UpdateBackendError::new("update_download_failed"))?,
            Duration::from_secs(15 * 60),
        )
        .await
        .map_err(|_| UpdateBackendError::new("update_download_failed"))?;
        if !response.status().is_success() {
            return Err(UpdateBackendError::new("update_download_failed"));
        }
        if response
            .content_length()
            .is_some_and(|size| size != update.size_bytes)
        {
            return Err(UpdateBackendError::new("update_size_mismatch"));
        }

        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .await
            .map_err(|_| UpdateBackendError::new("update_cache_unavailable"))?;
        let mut digest = Sha256::new();
        let mut downloaded = 0_u64;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| UpdateBackendError::new("update_download_failed"))?
        {
            downloaded = downloaded
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| UpdateBackendError::new("update_size_mismatch"))?;
            if downloaded > update.size_bytes {
                drop(output);
                let _ = fs::remove_file(&temporary).await;
                return Err(UpdateBackendError::new("update_size_mismatch"));
            }
            digest.update(&chunk);
            output
                .write_all(&chunk)
                .await
                .map_err(|_| UpdateBackendError::new("update_cache_unavailable"))?;
            progress(DownloadProgress {
                downloaded,
                total: Some(update.size_bytes),
            });
        }
        output
            .flush()
            .await
            .map_err(|_| UpdateBackendError::new("update_cache_unavailable"))?;
        output
            .sync_all()
            .await
            .map_err(|_| UpdateBackendError::new("update_cache_unavailable"))?;
        drop(output);

        if downloaded != update.size_bytes {
            let _ = fs::remove_file(&temporary).await;
            return Err(UpdateBackendError::new("update_size_mismatch"));
        }
        if format!("{:x}", digest.finalize()) != update.sha256 {
            let _ = fs::remove_file(&temporary).await;
            return Err(UpdateBackendError::new("update_hash_mismatch"));
        }
        fs::rename(&temporary, &destination)
            .await
            .map_err(|_| UpdateBackendError::new("update_cache_unavailable"))?;
        Ok(destination)
    }

    async fn cached_apk(
        &self,
        update: &crate::ValidatedAndroidUpdate,
    ) -> Result<Option<PathBuf>, UpdateBackendError> {
        let path = self
            .update_dir
            .join(format!("nelomai-{}.apk", update.version));
        let metadata = match fs::symlink_metadata(&path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(UpdateBackendError::new("update_cache_unavailable")),
        };
        if !metadata.is_file() || metadata.len() != update.size_bytes {
            remove_if_exists(&path).await?;
            return Ok(None);
        }
        let mut file = File::open(&path)
            .await
            .map_err(|_| UpdateBackendError::new("update_cache_unavailable"))?;
        let mut buffer = vec![0_u8; 256 * 1024];
        let mut digest = Sha256::new();
        loop {
            let count = file
                .read(&mut buffer)
                .await
                .map_err(|_| UpdateBackendError::new("update_cache_unavailable"))?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        if format!("{:x}", digest.finalize()) != update.sha256 {
            remove_if_exists(&path).await?;
            return Ok(None);
        }
        Ok(Some(path))
    }
}

#[async_trait]
impl UpdateBackend for AndroidUpdateBackend {
    async fn resolve(
        &self,
        access_token: &AccessSnapshot,
        expected_version: &str,
    ) -> Result<Option<ResolvedUpdate>, UpdateBackendError> {
        let current_version = &self.current_container_version;
        let endpoint = self
            .endpoint_policy
            .manifest_url(ANDROID_TARGET, current_version)
            .map_err(|_| UpdateBackendError::new("invalid_update_endpoint"))?;
        let mut request = self.http.get(endpoint);
        for (name, value) in access_token.bearer_headers() {
            request = request.header(name, value);
        }
        let response = execute_panel_request(
            &self.http,
            request
                .build()
                .map_err(|_| UpdateBackendError::new("update_check_failed"))?,
            Duration::from_secs(15 * 60),
        )
        .await
        .map_err(|_| UpdateBackendError::new("update_check_failed"))?;
        if response.status() == StatusCode::NO_CONTENT {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(UpdateBackendError::new("update_check_failed"));
        }
        let manifest = response
            .json::<AndroidUpdateManifest>()
            .await
            .map_err(|_| UpdateBackendError::new("invalid_update_manifest"))?;
        let update = manifest
            .validate(expected_version, &self.endpoint_policy)
            .map_err(manifest_error)?;
        Ok(Some(ResolvedUpdate {
            version: update.version,
            target: ANDROID_TARGET.into(),
            artifact_url: update.artifact_url.to_string(),
            signature: update.signer_sha256.clone(),
            key_identity: update.signer_sha256,
            sha256: Some(update.sha256),
            size_bytes: Some(update.size_bytes),
        }))
    }

    async fn prepare(
        &self,
        access_token: &AccessSnapshot,
        resolved: &ResolvedUpdate,
        progress: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
    ) -> Result<PreparedUpdate, UpdateBackendError> {
        let _cache = self
            .cache_use
            .try_lock()
            .map_err(|_| UpdateBackendError::new("update_operation_busy"))?;
        let update = self.validated_resolved(resolved)?;
        let apk = match self.cached_apk(&update).await? {
            Some(path) => {
                progress(DownloadProgress {
                    downloaded: update.size_bytes,
                    total: Some(update.size_bytes),
                });
                path
            }
            None => self.download(access_token, &update, progress).await?,
        };
        self.installer
            .validate_apk(&apk, &update.version, &update.signer_sha256)
            .await?;
        let resolved = resolved.clone();
        let prepared =
            tokio::task::spawn_blocking(move || PreparedUpdate::from_verified_file(resolved, apk))
                .await
                .map_err(|_| UpdateBackendError::new("update_cache_invalid"))??;
        // Prune only after the replacement is fully verified. A failed download
        // must not remove another ready package; a live installer owns this gate.
        cleanup_stale_updates(&self.update_dir, prepared.path()).await?;
        Ok(prepared)
    }

    async fn install_prepared(
        &self,
        prepared: &PreparedUpdate,
        barrier: UpdateBarrierPhase,
    ) -> Result<InstallResult, UpdateBackendError> {
        debug_assert_eq!(barrier, UpdateBarrierPhase::LocalStopped);
        let cache = self
            .cache_use
            .clone()
            .try_lock_owned()
            .map_err(|_| UpdateBackendError::new("update_operation_busy"))?;
        let update = self.validated_resolved(prepared.resolved())?;
        let apk = self
            .update_dir
            .join(format!("nelomai-{}.apk", update.version));
        if prepared.path() != apk {
            return Err(UpdateBackendError::new("update_cache_invalid"));
        }
        let prepared = prepared.clone();
        let installer = self.installer.clone();
        // Dropping the requesting future cannot cancel the JNI/system installer.
        // Keep its file lease until the actual consumer completes, including cancel.
        tokio::spawn(async move {
            let _cache = cache;
            prepared.revalidate_async().await?;
            installer
                .validate_apk(&apk, &update.version, &update.signer_sha256)
                .await?;
            if !installer
                .install_apk(&apk, &update.version, &update.signer_sha256)
                .await?
            {
                return Err(UpdateBackendError::new("apk_install_cancelled"));
            }
            // Cleanup is best effort after success; a disk error cannot undo installation.
            let _ = remove_if_exists(&apk).await;
            Ok(InstallResult::InstallerOpened(InstalledUpdate {
                version: update.version,
            }))
        })
        .await
        .map_err(|_| UpdateBackendError::new("apk_installer_unavailable"))?
    }
}

fn manifest_error(error: AndroidManifestError) -> UpdateBackendError {
    let code = match error {
        AndroidManifestError::VersionChanged => "update_version_changed",
        AndroidManifestError::UntrustedArtifact => "untrusted_update_artifact",
        _ => "invalid_update_manifest",
    };
    UpdateBackendError::new(code)
}

async fn remove_if_exists(path: &Path) -> Result<(), UpdateBackendError> {
    match fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(UpdateBackendError::new("update_cache_unavailable")),
    }
}

async fn cleanup_stale_updates(directory: &Path, current: &Path) -> Result<(), UpdateBackendError> {
    let mut entries = fs::read_dir(directory)
        .await
        .map_err(|_| UpdateBackendError::new("update_cache_unavailable"))?;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|_| UpdateBackendError::new("update_cache_unavailable"))?
    {
        let path = entry.path();
        if path == current {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let owned_apk = name
            .strip_prefix("nelomai-")
            .and_then(|name| name.strip_suffix(".apk"))
            .is_some_and(|version| semver::Version::parse(version).is_ok());
        if owned_apk || name == ".nelomai-update.part" {
            remove_if_exists(&path).await?;
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    async fn install_candidate(
        backend: &AndroidUpdateBackend,
        access: &AccessSnapshot,
        version: &str,
    ) -> Result<InstallResult, UpdateBackendError> {
        let Some(resolved) = backend.resolve(access, version).await? else {
            return Ok(InstallResult::NoUpdate);
        };
        let prepared = backend.prepare(access, &resolved, Arc::new(|_| {})).await?;
        backend
            .install_prepared(&prepared, UpdateBarrierPhase::LocalStopped)
            .await
    }
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    };

    struct ValidatingInstaller {
        calls: Mutex<Vec<&'static str>>,
        reject: AtomicBool,
    }
    #[async_trait]
    impl AndroidApkInstaller for ValidatingInstaller {
        async fn validate_apk(
            &self,
            path: &Path,
            version: &str,
            signer: &str,
        ) -> Result<(), UpdateBackendError> {
            self.calls.lock().unwrap().push("validate");
            assert_eq!(std::fs::read(path).unwrap(), b"abc");
            assert_eq!(version, "0.3.13");
            assert_eq!(signer, "a".repeat(64));
            if self.reject.load(Ordering::SeqCst) {
                return Err(UpdateBackendError::new("apk_signer_mismatch"));
            }
            Ok(())
        }
        async fn install_apk(
            &self,
            _: &Path,
            _: &str,
            _: &str,
        ) -> Result<bool, UpdateBackendError> {
            self.calls.lock().unwrap().push("install");
            Ok(true)
        }
    }
    fn split_fixture() -> (
        tempfile::TempDir,
        AndroidUpdateBackend,
        Arc<ValidatingInstaller>,
        ResolvedUpdate,
        AccessSnapshot,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let installer = Arc::new(ValidatingInstaller {
            calls: Mutex::new(Vec::new()),
            reject: AtomicBool::new(false),
        });
        let backend =
            AndroidUpdateBackend::new(dir.path().into(), "0.3.12".into(), installer.clone())
                .unwrap();
        let resolved = ResolvedUpdate {
            version: "0.3.13".into(),
            target: "android-aarch64".into(),
            artifact_url: "https://nelomai.ru/api/client/v1/updates/artifacts/update.apk".into(),
            signature: "a".repeat(64),
            key_identity: "a".repeat(64),
            sha256: Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into()),
            size_bytes: Some(3),
        };
        std::fs::write(dir.path().join("nelomai-0.3.13.apk"), b"abc").unwrap();
        let access = AccessSnapshot::new(
            "synthetic".into(),
            nelomai_contracts::RuntimeIdentity {
                container_version: "0.3.12".into(),
                runtime_version: "0.3.12".into(),
                runtime_contract_version: 1,
                slot: nelomai_contracts::RuntimeSlot::Latest,
                session_generation: Some(1),
            },
            1,
            "fixture-family".into(),
        )
        .unwrap();
        (dir, backend, installer, resolved, access)
    }
    #[tokio::test]
    async fn apk_prepare_validates_without_install_and_rechecks_bytes_before_handoff() {
        let (_dir, backend, installer, resolved, access) = split_fixture();
        let prepared = backend
            .prepare(&access, &resolved, Arc::new(|_| {}))
            .await
            .unwrap();
        assert_eq!(*installer.calls.lock().unwrap(), vec!["validate"]);
        assert_eq!(prepared.resolved(), &resolved);
        std::fs::write(prepared.path(), b"xyz").unwrap();
        assert_eq!(
            backend
                .install_prepared(&prepared, UpdateBarrierPhase::LocalStopped)
                .await
                .unwrap_err()
                .code(),
            "update_hash_mismatch"
        );
        assert_eq!(*installer.calls.lock().unwrap(), vec!["validate"]);
    }
    #[tokio::test]
    async fn apk_prepared_signature_is_rechecked_and_success_cleans_only_owned_file() {
        let (dir, backend, installer, resolved, access) = split_fixture();
        std::fs::write(dir.path().join("unrelated.apk"), b"keep").unwrap();
        let prepared = backend
            .prepare(&access, &resolved, Arc::new(|_| {}))
            .await
            .unwrap();
        installer.reject.store(true, Ordering::SeqCst);
        assert_eq!(
            backend
                .install_prepared(&prepared, UpdateBarrierPhase::LocalStopped)
                .await
                .unwrap_err()
                .code(),
            "apk_signer_mismatch"
        );
        assert!(prepared.path().exists());
        assert_eq!(
            *installer.calls.lock().unwrap(),
            vec!["validate", "validate"]
        );
        installer.reject.store(false, Ordering::SeqCst);
        assert!(matches!(
            backend
                .install_prepared(&prepared, UpdateBarrierPhase::LocalStopped)
                .await
                .unwrap(),
            InstallResult::InstallerOpened(_)
        ));
        assert_eq!(
            *installer.calls.lock().unwrap(),
            vec!["validate", "validate", "validate", "install"]
        );
        assert!(!prepared.path().exists());
        assert_eq!(
            std::fs::read(dir.path().join("unrelated.apk")).unwrap(),
            b"keep"
        );
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn apk_cache_rejects_symlink_without_following_or_removing_target() {
        let (dir, backend, _, resolved, _) = split_fixture();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("foreign.apk");
        std::fs::write(&target, b"abc").unwrap();
        let path = dir.path().join("nelomai-0.3.13.apk");
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(backend
            .cached_apk(&backend.validated_resolved(&resolved).unwrap())
            .await
            .unwrap()
            .is_none());
        assert_eq!(std::fs::read(target).unwrap(), b"abc");
    }
    #[tokio::test]
    async fn failed_apk_download_preserves_ready_file_and_retry_replaces_partial() {
        use std::io::{Read, Write};
        let (dir, mut backend, installer, mut resolved, access) = split_fixture();
        std::fs::remove_file(dir.path().join("nelomai-0.3.13.apk")).unwrap();
        let previous = dir.path().join("nelomai-0.3.12.apk");
        std::fs::write(&previous, b"previous").unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        backend.endpoint_policy = UpdateEndpointPolicy {
            panel_origin: origin.parse().unwrap(),
        };
        resolved.artifact_url = format!("{origin}/api/client/v1/updates/artifacts/update.apk");
        let server = std::thread::spawn(move || {
            for body in [b"ab".as_slice(), b"abc".as_slice()] {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut request = [0; 4096];
                assert!(stream.read(&mut request).unwrap() > 0);
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\n")
                    .unwrap();
                stream.write_all(body).unwrap();
            }
        });
        assert!(backend
            .prepare(&access, &resolved, Arc::new(|_| {}))
            .await
            .is_err());
        assert!(installer.calls.lock().unwrap().is_empty());
        assert_eq!(std::fs::read(&previous).unwrap(), b"previous");
        assert!(!dir.path().join("nelomai-0.3.13.apk").exists());
        let prepared = backend
            .prepare(&access, &resolved, Arc::new(|_| {}))
            .await
            .unwrap();
        assert_eq!(std::fs::read(prepared.path()).unwrap(), b"abc");
        assert_eq!(*installer.calls.lock().unwrap(), vec!["validate"]);
        assert!(!dir.path().join(".nelomai-update.part").exists());
        assert!(!previous.exists());
        server.join().unwrap();
    }
    #[tokio::test]
    async fn active_installer_file_is_not_pruned_and_cancelled_package_is_reusable() {
        struct BlockingInstaller {
            validation: Arc<ValidatingInstaller>,
            entered: tokio::sync::Notify,
            release: tokio::sync::Notify,
        }
        #[async_trait]
        impl AndroidApkInstaller for BlockingInstaller {
            async fn validate_apk(
                &self,
                path: &Path,
                version: &str,
                signer: &str,
            ) -> Result<(), UpdateBackendError> {
                self.validation.validate_apk(path, version, signer).await
            }
            async fn install_apk(
                &self,
                _: &Path,
                _: &str,
                _: &str,
            ) -> Result<bool, UpdateBackendError> {
                self.entered.notify_one();
                self.release.notified().await;
                Ok(false)
            }
        }
        let (_dir, mut backend, validation, resolved, access) = split_fixture();
        let prepared = backend
            .prepare(&access, &resolved, Arc::new(|_| {}))
            .await
            .unwrap();
        let installer = Arc::new(BlockingInstaller {
            validation,
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        backend.installer = installer.clone();
        let backend = Arc::new(backend);
        let installing = {
            let backend = backend.clone();
            let prepared = prepared.clone();
            tokio::spawn(async move {
                backend
                    .install_prepared(&prepared, UpdateBarrierPhase::LocalStopped)
                    .await
            })
        };
        installer.entered.notified().await;
        assert_eq!(
            backend
                .prepare(&access, &resolved, Arc::new(|_| {}))
                .await
                .unwrap_err()
                .code(),
            "update_operation_busy"
        );
        assert_eq!(std::fs::read(prepared.path()).unwrap(), b"abc");
        installer.release.notify_one();
        assert_eq!(
            installing.await.unwrap().unwrap_err().code(),
            "apk_install_cancelled"
        );
        assert!(prepared.path().exists());
        assert_eq!(
            backend
                .prepare(&access, &resolved, Arc::new(|_| {}))
                .await
                .unwrap()
                .sha256(),
            prepared.sha256()
        );
        let abandoned = {
            let backend = backend.clone();
            let prepared = prepared.clone();
            tokio::spawn(async move {
                backend
                    .install_prepared(&prepared, UpdateBarrierPhase::LocalStopped)
                    .await
            })
        };
        installer.entered.notified().await;
        abandoned.abort();
        assert!(abandoned.await.unwrap_err().is_cancelled());
        assert_eq!(
            backend
                .prepare(&access, &resolved, Arc::new(|_| {}))
                .await
                .unwrap_err()
                .code(),
            "update_operation_busy",
            "cancelling the caller does not finish the native installer consumer"
        );
        installer.release.notify_one();
        drop(
            tokio::time::timeout(Duration::from_secs(1), backend.cache_use.lock())
                .await
                .unwrap(),
        );
        assert!(prepared.path().exists());
    }
    #[tokio::test]
    async fn https_backup_fetches_manifest_and_apk_and_rejects_tampering() {
        use rustls::{
            pki_types::{CertificateDer, PrivatePkcs8KeyDer},
            ServerConfig, ServerConnection, StreamOwned,
        };
        use std::{
            io::{Read, Write},
            net::TcpListener,
            sync::atomic::{AtomicUsize, Ordering},
            thread,
        };
        fn server(
            apk: &'static [u8],
        ) -> (
            std::net::SocketAddr,
            thread::JoinHandle<(usize, Vec<String>)>,
        ) {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(
                    include_bytes!("../../client-api/src/panel_dns_testdata/backup-server.der")
                        .to_vec(),
                )],
                PrivatePkcs8KeyDer::from(
                    include_bytes!("../../client-api/src/panel_dns_testdata/backup-server-key.der")
                        .to_vec(),
                )
                .into(),
            )
            .unwrap();
            let thread = thread::spawn(move || {
                let mut connections = 0;
                let mut requests = Vec::new();
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                while connections < 2 && std::time::Instant::now() < deadline {
                    let socket = match listener.accept() {
                        Ok((socket, _)) => socket,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(3));
                            continue;
                        }
                        Err(e) => panic!("{e}"),
                    };
                    connections += 1;
                    socket.set_nonblocking(false).unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    socket
                        .set_write_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut stream = StreamOwned::new(
                        ServerConnection::new(Arc::new(config.clone())).unwrap(),
                        socket,
                    );
                    let mut data = Vec::new();
                    loop {
                        let mut buffer = [0; 2048];
                        match stream.read(&mut buffer) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => data.extend_from_slice(&buffer[..n]),
                        }
                        assert!(data.len() < 16384);
                        if data.windows(4).any(|v| v == b"\r\n\r\n") {
                            break;
                        }
                    }
                    if data.is_empty() {
                        continue;
                    }
                    assert_eq!(stream.conn.server_name(), Some("nelomai.top"));
                    let request = String::from_utf8(data).unwrap();
                    assert!(request
                        .to_ascii_lowercase()
                        .contains("host: nelomai.top\r\n"));
                    assert!(request
                        .to_ascii_lowercase()
                        .contains("authorization: bearer synthetic\r\n"));
                    let body = if request.starts_with("GET /api/client/v1/updates/manifest/") {
                        serde_json::json!({"version":"0.3.10","url":"https://nelomai.ru/api/client/v1/updates/artifacts/update.apk","signature":"a".repeat(64),"sha256":format!("{:x}",Sha256::digest(b"abc")),"size_bytes":3}).to_string().into_bytes()
                    } else {
                        assert!(
                            request.starts_with("GET /api/client/v1/updates/artifacts/update.apk ")
                        );
                        apk.to_vec()
                    };
                    requests.push(request);
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .unwrap();
                    stream.write_all(&body).unwrap();
                    stream.flush().unwrap();
                }
                (connections, requests)
            });
            (address, thread)
        }
        struct Installer(Arc<AtomicUsize>);
        #[async_trait]
        impl AndroidApkInstaller for Installer {
            async fn validate_apk(
                &self,
                path: &Path,
                _: &str,
                signer: &str,
            ) -> Result<(), UpdateBackendError> {
                assert_eq!(std::fs::read(path).unwrap(), b"abc");
                assert_eq!(signer, "a".repeat(64));
                Ok(())
            }
            async fn install_apk(
                &self,
                path: &Path,
                _: &str,
                signer: &str,
            ) -> Result<bool, UpdateBackendError> {
                assert_eq!(std::fs::read(path).unwrap(), b"abc");
                assert_eq!(signer, "a".repeat(64));
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(true)
            }
        }
        for apk in [b"abc".as_slice(), b"abd".as_slice()] {
            let (primary, primary_thread) = server(apk);
            let (backup, backup_thread) = server(apk);
            let dir = tempfile::tempdir().unwrap();
            let installed = Arc::new(AtomicUsize::new(0));
            let mut backend = AndroidUpdateBackend::new(
                dir.path().into(),
                "0.3.9".into(),
                Arc::new(Installer(installed.clone())),
            )
            .unwrap();
            backend.http = panel_http_client_builder()
                .no_proxy()
                .add_root_certificate(
                    reqwest::Certificate::from_der(include_bytes!(
                        "../../client-api/src/panel_dns_testdata/backup-ca.der"
                    ))
                    .unwrap(),
                )
                .resolve("nelomai.ru", primary)
                .resolve("nelomai.top", backup)
                .build()
                .unwrap();
            let access = AccessSnapshot::new(
                "synthetic".into(),
                nelomai_contracts::RuntimeIdentity {
                    container_version: "0.3.9".into(),
                    runtime_version: "0.3.9".into(),
                    runtime_contract_version: 1,
                    slot: nelomai_contracts::RuntimeSlot::Latest,
                    session_generation: Some(1),
                },
                1,
                "test-family".into(),
            )
            .unwrap();
            let result = install_candidate(&backend, &access, "0.3.10").await;
            let (count, requests) = primary_thread.join().unwrap();
            assert_eq!(count, 2);
            assert!(
                requests.is_empty(),
                "credentials reached primary despite its wrong certificate"
            );
            assert_eq!(backup_thread.join().unwrap().1.len(), 2);
            if apk == b"abc" {
                assert!(matches!(result.unwrap(), InstallResult::InstallerOpened(_)));
                assert_eq!(installed.load(Ordering::SeqCst), 1);
            } else {
                assert_eq!(result.unwrap_err().code(), "update_hash_mismatch");
                assert_eq!(installed.load(Ordering::SeqCst), 0);
                assert!(!dir.path().join(".nelomai-update.part").exists());
            }
        }
    }

    #[tokio::test]
    async fn installer_cancellation_is_distinct_from_open_failure() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        struct Installer(u8);
        #[async_trait]
        impl AndroidApkInstaller for Installer {
            async fn validate_apk(
                &self,
                path: &Path,
                _: &str,
                signer: &str,
            ) -> Result<(), UpdateBackendError> {
                assert_eq!(std::fs::read(path).unwrap(), b"abc");
                assert_eq!(signer, "a".repeat(64));
                Ok(())
            }
            async fn install_apk(
                &self,
                path: &Path,
                version: &str,
                signer: &str,
            ) -> Result<bool, UpdateBackendError> {
                assert_eq!(std::fs::read(path).unwrap(), b"abc");
                assert_eq!(version, "0.3.7");
                assert_eq!(signer, "a".repeat(64));
                match self.0 {
                    0 => Ok(false),
                    1 => Err(UpdateBackendError::new("apk_installer_unavailable")),
                    _ => Ok(true),
                }
            }
        }
        for mode in 0..3 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let manifest = serde_json::json!({
                "version":"0.3.7", "url":format!("{origin}/api/client/v1/updates/artifacts/update.apk"),
                "signature":"a".repeat(64), "sha256":format!("{:x}", Sha256::digest(b"abc")), "size_bytes":3,
            }).to_string();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut request = [0; 4096];
                assert!(stream.read(&mut request).unwrap() > 0);
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{manifest}",manifest.len()).unwrap();
            });
            let directory = tempfile::tempdir().unwrap();
            std::fs::write(directory.path().join("nelomai-0.3.7.apk"), b"abc").unwrap();
            let mut backend = AndroidUpdateBackend::new(
                directory.path().into(),
                "0.3.6".into(),
                Arc::new(Installer(mode)),
            )
            .unwrap();
            // A private loopback policy keeps this test offline. Production's
            // public constructor still requires HTTPS and the trusted origin.
            backend.endpoint_policy = UpdateEndpointPolicy {
                panel_origin: origin.parse().unwrap(),
            };
            let access = AccessSnapshot::new(
                "synthetic".into(),
                nelomai_contracts::RuntimeIdentity {
                    container_version: "0.3.6".into(),
                    runtime_version: "0.3.6".into(),
                    runtime_contract_version: 1,
                    slot: nelomai_contracts::RuntimeSlot::Latest,
                    session_generation: Some(1),
                },
                1,
                "synthetic-family".into(),
            )
            .unwrap();
            let result = install_candidate(&backend, &access, "0.3.7").await;
            server.join().unwrap();
            match mode {
                0 => assert_eq!(result.unwrap_err().code(), "apk_install_cancelled"),
                1 => assert_eq!(result.unwrap_err().code(), "apk_installer_unavailable"),
                _ => assert!(matches!(result.unwrap(), InstallResult::InstallerOpened(_))),
            }
        }
    }

    struct NoInstaller;
    #[async_trait::async_trait]
    impl AndroidApkInstaller for NoInstaller {
        async fn install_apk(
            &self,
            _: &std::path::Path,
            _: &str,
            _: &str,
        ) -> Result<bool, crate::UpdateBackendError> {
            panic!("cache validation must not open installer")
        }
    }
    #[tokio::test]
    async fn cached_apk_is_rehashed_and_tampering_is_removed_without_installer() {
        let dir = tempfile::tempdir().unwrap();
        let backend = AndroidUpdateBackend::new(
            dir.path().to_path_buf(),
            "0.2.16".into(),
            std::sync::Arc::new(NoInstaller),
        )
        .unwrap();
        let update = crate::ValidatedAndroidUpdate {
            version: "0.2.17".into(),
            artifact_url: "https://nelomai.ru/api/client/v1/updates/artifacts/update.apk"
                .parse()
                .unwrap(),
            signer_sha256: "a".repeat(64),
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
            size_bytes: 3,
        };
        let path = dir.path().join("nelomai-0.2.17.apk");
        std::fs::write(&path, b"abc").unwrap();
        assert_eq!(
            backend.cached_apk(&update).await.unwrap(),
            Some(path.clone())
        );
        std::fs::write(&path, b"xyz").unwrap();
        assert_eq!(backend.cached_apk(&update).await.unwrap(), None);
        assert!(!path.exists());
    }
}
