use crate::{
    AndroidManifestError, AndroidUpdateManifest, DownloadProgress, InstallResult, InstalledUpdate,
    UpdateBackend, UpdateBackendError, UpdateBarrierPhase, UpdateEndpointPolicy,
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
        })
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
        cleanup_stale_updates(&self.update_dir, &destination).await?;
        remove_if_exists(&temporary).await?;
        remove_if_exists(&destination).await?;

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
        let metadata = match fs::metadata(&path).await {
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
    async fn install(
        &self,
        access_token: &AccessSnapshot,
        expected_version: &str,
        barrier: UpdateBarrierPhase,
        progress: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
    ) -> Result<InstallResult, UpdateBackendError> {
        debug_assert_eq!(barrier, UpdateBarrierPhase::LocalStopped);
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
            return Ok(InstallResult::NoUpdate);
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
        let installer_opened = self
            .installer
            .install_apk(&apk, &update.version, &update.signer_sha256)
            .await?;
        if !installer_opened {
            return Err(UpdateBackendError::new("apk_installer_unavailable"));
        }
        Ok(InstallResult::InstallerOpened(InstalledUpdate {
            version: update.version,
        }))
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
        if name.ends_with(".apk") || name.ends_with(".part") {
            remove_if_exists(&path).await?;
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
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
            let result = backend
                .install(
                    &access,
                    "0.3.10",
                    UpdateBarrierPhase::LocalStopped,
                    Arc::new(|_| {}),
                )
                .await;
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
