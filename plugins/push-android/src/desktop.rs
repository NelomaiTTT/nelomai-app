use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::models::PushTokenResponse;

pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<PushAndroid<R>> {
    Ok(PushAndroid(app.clone()))
}

pub struct PushAndroid<R: Runtime>(#[allow(dead_code)] AppHandle<R>);

impl<R: Runtime> PushAndroid<R> {
    pub fn prepare(&self) -> crate::Result<PushTokenResponse> {
        Err(crate::Error::Unsupported)
    }

    pub fn confirm(&self, _token: &str) -> crate::Result<()> {
        Err(crate::Error::Unsupported)
    }

    pub fn disable(&self) -> crate::Result<()> {
        Err(crate::Error::Unsupported)
    }
}
