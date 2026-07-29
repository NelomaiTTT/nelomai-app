use serde::de::DeserializeOwned;
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

use crate::models::{InstallApkRequest, InstallApkResponse};

pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    api: PluginApi<R, C>,
) -> crate::Result<UpdaterAndroid<R>> {
    let handle = api.register_android_plugin("ru.nelomai.updater", "UpdaterPlugin")?;
    Ok(UpdaterAndroid(handle))
}

pub struct UpdaterAndroid<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> UpdaterAndroid<R> {
    pub fn install_apk(&self, request: InstallApkRequest) -> crate::Result<InstallApkResponse> {
        self.0
            .run_mobile_plugin("installApk", request)
            .map_err(Into::into)
    }
}
