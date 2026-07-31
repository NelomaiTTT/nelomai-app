use serde::de::DeserializeOwned;
use serde::Serialize;
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

use crate::models::PushTokenResponse;

#[derive(Serialize)]
struct EmptyRequest {}

#[derive(Serialize)]
struct TokenRequest<'a> {
    token: &'a str,
}

pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    api: PluginApi<R, C>,
) -> crate::Result<PushAndroid<R>> {
    let handle = api.register_android_plugin("ru.nelomai.push", "PushPlugin")?;
    Ok(PushAndroid(handle))
}

pub struct PushAndroid<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> PushAndroid<R> {
    pub fn prepare(&self) -> crate::Result<PushTokenResponse> {
        self.0
            .run_mobile_plugin("prepare", EmptyRequest {})
            .map_err(Into::into)
    }

    pub fn confirm(&self, token: &str) -> crate::Result<()> {
        self.0
            .run_mobile_plugin("confirm", TokenRequest { token })
            .map_err(Into::into)
    }

    pub fn disable(&self) -> crate::Result<()> {
        self.0
            .run_mobile_plugin("disable", EmptyRequest {})
            .map_err(Into::into)
    }
}
