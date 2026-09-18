use crate::{
    AndroidManifestError, AndroidUpdateManifest, DownloadProgress, InstallResult, InstalledUpdate,
    UpdateBackend, UpdateBackendError, UpdateBarrierPhase, UpdateEndpointPolicy,
};
use async_trait::async_trait;
use nelomai_client_api::AccessSnapshot;
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
        let http = Client::builder()
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
        let mut response = request
            .send()
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
        let response = request
            .send()
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
