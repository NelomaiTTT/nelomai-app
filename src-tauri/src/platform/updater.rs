use async_trait::async_trait;
use nelomai_client_updater::{
    DownloadProgress, InstallResult, InstalledUpdate, UpdateBackend, UpdateBackendError,
    UpdateEndpointPolicy,
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
        access_token: &str,
        expected_version: &str,
        progress: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
    ) -> Result<InstallResult, UpdateBackendError> {
        let target = tauri_plugin_updater::target()
            .ok_or_else(|| UpdateBackendError::new("unsupported_update_target"))?;
        let current_version = self.app.package_info().version.to_string();
        let endpoint = self
            .endpoint_policy
            .manifest_url(&target, &current_version)
            .map_err(|_| UpdateBackendError::new("invalid_update_endpoint"))?;
        let updater = self
            .app
            .updater_builder()
            .pubkey(self.public_key.clone())
            .endpoints(vec![endpoint])
            .map_err(|_| UpdateBackendError::new("updater_configuration_failed"))?
            .header("Authorization", format!("Bearer {access_token}"))
            .map_err(|_| UpdateBackendError::new("updater_authorization_failed"))?
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
        update
            .download_and_install(
                |chunk, total| {
                    downloaded = downloaded.saturating_add(chunk as u64);
                    progress(DownloadProgress { downloaded, total });
                },
                || {},
            )
            .await
            .map_err(|_| UpdateBackendError::new("update_install_failed"))?;
        Ok(InstallResult::Installed(InstalledUpdate {
            version: update.version,
        }))
    }
}
