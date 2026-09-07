use async_trait::async_trait;
use nelomai_client_api::AccessSnapshot;
use nelomai_client_updater::{
    DownloadProgress, InstallResult, InstalledUpdate, UpdateBackend, UpdateBackendError,
    UpdateBarrierPhase, UpdateEndpointPolicy,
};
use std::sync::Arc;
use tauri::{AppHandle, Runtime};
use tauri_plugin_updater::UpdaterExt;

const PANEL_BASE: &str = "https://nelomai.ru";

pub struct DesktopUpdateBackend<R: Runtime> {
    app: AppHandle<R>,
    endpoint_policy: UpdateEndpointPolicy,
    public_key: String,
}

impl<R: Runtime> DesktopUpdateBackend<R> {
    pub fn from_build(app: AppHandle<R>) -> Result<Self, UpdateBackendError> {
        let public_key = option_env!("NELOMAI_UPDATER_PUBLIC_KEY")
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| UpdateBackendError::new("updater_public_key_missing"))?;
        Self::new(app, PANEL_BASE, public_key)
    }

    pub fn new(
        app: AppHandle<R>,
        panel_base: &str,
        public_key: impl Into<String>,
    ) -> Result<Self, UpdateBackendError> {
        let public_key = public_key.into();
        if public_key.trim().is_empty() {
            return Err(UpdateBackendError::new("updater_public_key_missing"));
        }
        let endpoint_policy = UpdateEndpointPolicy::new(panel_base)
            .map_err(|_| UpdateBackendError::new("invalid_update_endpoint"))?;
        Ok(Self {
            app,
            endpoint_policy,
            public_key,
        })
    }
}

#[async_trait]
impl<R: Runtime> UpdateBackend for DesktopUpdateBackend<R> {
    async fn install(
        &self,
        access_token: &AccessSnapshot,
        expected_version: &str,
        barrier: UpdateBarrierPhase,
        progress: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
    ) -> Result<InstallResult, UpdateBackendError> {
        debug_assert_eq!(barrier, UpdateBarrierPhase::LocalStopped);
        let target = tauri_plugin_updater::target()
            .ok_or_else(|| UpdateBackendError::new("unsupported_update_target"))?;
        let current_version = self.app.package_info().version.to_string();
        let endpoint = self
            .endpoint_policy
            .manifest_url(&target, &current_version)
            .map_err(|_| UpdateBackendError::new("invalid_update_endpoint"))?;
        let mut builder = self
            .app
            .updater_builder()
            .pubkey(self.public_key.clone())
            .endpoints(vec![endpoint])
            .map_err(|_| UpdateBackendError::new("updater_configuration_failed"))?;
        // The updater carries these same headers into Update.download().
        for (name, value) in access_token.bearer_headers() {
            builder = builder
                .header(name, value)
                .map_err(|_| UpdateBackendError::new("updater_authorization_failed"))?;
        }
        let updater = builder
            .build()
            .map_err(|_| UpdateBackendError::new("updater_configuration_failed"))?;
        let Some(update) = updater
            .check()
            .await
            .map_err(|_| UpdateBackendError::new("update_check_failed"))?
        else {
            return Ok(InstallResult::NoUpdate);
        };
        if update.version != expected_version {
            return Err(UpdateBackendError::new("update_version_changed"));
        }
        if !self
            .endpoint_policy
            .is_trusted_artifact(&update.download_url)
        {
            return Err(UpdateBackendError::new("untrusted_update_artifact"));
        }

        let mut downloaded = 0_u64;
        let bytes = update
            .download(
                |chunk, total| {
                    downloaded = downloaded.saturating_add(chunk as u64);
                    progress(DownloadProgress { downloaded, total });
                },
                || {},
            )
            .await
            .map_err(|_| UpdateBackendError::new("update_install_failed"))?;

        let stop_proof = crate::container::begin_installation(&self.app, expected_version)
            .await
            .map_err(|_| UpdateBackendError::new("update_stop_proof_unavailable"))?;
        #[cfg(windows)]
        crate::desktop::set_tray_visible(&self.app, false);
        #[cfg(target_os = "linux")]
        let install = install_linux_common(bytes).await;
        #[cfg(not(target_os = "linux"))]
        let install = update
            .install(bytes)
            .map_err(|_| UpdateBackendError::new("update_install_failed"));
        #[cfg(windows)]
        if install.is_err() {
            crate::desktop::set_tray_visible(&self.app, true);
        }
        install.map_err(|_| UpdateBackendError::new("update_install_failed"))?;
        crate::container::installation_succeeded(&self.app, stop_proof)
            .await
            .map_err(|_| UpdateBackendError::new("update_stop_proof_changed"))?;
        Ok(InstallResult::Installed(InstalledUpdate {
            version: update.version,
        }))
    }
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
