use async_trait::async_trait;
use nelomai_client_api::AccessSnapshot;
use nelomai_client_updater::{
    AndroidApkInstaller, DownloadProgress, InstallResult, UpdateBackend, UpdateBackendError,
    UpdateBarrierPhase,
};
use std::{path::Path, sync::Arc};
use tauri::{AppHandle, Manager, Runtime};
use tauri_plugin_updater_android::{InstallApkRequest, UpdaterAndroidExt};

pub struct AndroidUpdateBackend<R: Runtime> {
    backend: nelomai_client_updater::AndroidUpdateBackend,
    _runtime: std::marker::PhantomData<fn() -> R>,
}
struct TauriInstaller<R: Runtime>(AppHandle<R>);
#[async_trait]
impl<R: Runtime> AndroidApkInstaller for TauriInstaller<R> {
    async fn install_apk(
        &self,
        path: &Path,
        version: &str,
        signer: &str,
    ) -> Result<bool, UpdateBackendError> {
        self.0
            .updater_android()
            .install_apk(InstallApkRequest {
                path: path.to_string_lossy().into_owned(),
                expected_version: version.into(),
                expected_signer_sha256: signer.into(),
            })
            .map(|v| v.installer_opened)
            .map_err(|error| UpdateBackendError::new(plugin_error_code(&error.to_string())))
    }
}
impl<R: Runtime> AndroidUpdateBackend<R> {
    pub fn from_build(app: AppHandle<R>) -> Result<Self, UpdateBackendError> {
        let update_dir = app
            .path()
            .app_cache_dir()
            .map_err(|_| UpdateBackendError::new("update_cache_unavailable"))?
            .join("updates");
        let current = app.package_info().version.to_string();
        Ok(Self {
            backend: nelomai_client_updater::AndroidUpdateBackend::new(
                update_dir,
                current,
                Arc::new(TauriInstaller(app)),
            )?,
            _runtime: std::marker::PhantomData,
        })
    }
}
#[async_trait]
impl<R: Runtime> UpdateBackend for AndroidUpdateBackend<R> {
    async fn install(
        &self,
        access: &AccessSnapshot,
        version: &str,
        barrier: UpdateBarrierPhase,
        progress: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
    ) -> Result<InstallResult, UpdateBackendError> {
        self.backend
            .install(access, version, barrier, progress)
            .await
    }
}
fn plugin_error_code(error: &str) -> &str {
    const CODES: &[&str] = &[
        "install_permission_denied",
        "update_install_in_progress",
        "invalid_apk_path",
        "invalid_apk",
        "apk_package_mismatch",
        "apk_version_mismatch",
        "apk_signature_mismatch",
        "apk_installer_unavailable",
    ];
    CODES
        .iter()
        .copied()
        .find(|code| error.contains(code))
        .unwrap_or("update_install_failed")
}
