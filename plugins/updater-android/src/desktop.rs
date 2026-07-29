use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::models::{InstallApkRequest, InstallApkResponse};

pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<UpdaterAndroid<R>> {
    Ok(UpdaterAndroid(app.clone()))
}

pub struct UpdaterAndroid<R: Runtime>(AppHandle<R>);

impl<R: Runtime> UpdaterAndroid<R> {
    pub fn install_apk(&self, _request: InstallApkRequest) -> crate::Result<InstallApkResponse> {
        Err(crate::Error::Unsupported)
    }
}
