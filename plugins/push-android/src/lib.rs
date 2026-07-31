use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

#[cfg(not(target_os = "android"))]
mod desktop;
mod error;
#[cfg(target_os = "android")]
mod mobile;
mod models;

#[cfg(not(target_os = "android"))]
use desktop::PushAndroid;
#[cfg(target_os = "android")]
use mobile::PushAndroid;

pub use error::{Error, Result};
pub use models::PushTokenResponse;

pub trait PushAndroidExt<R: Runtime> {
    fn push_android(&self) -> &PushAndroid<R>;
}

impl<R: Runtime, T: Manager<R>> PushAndroidExt<R> for T {
    fn push_android(&self) -> &PushAndroid<R> {
        self.state::<PushAndroid<R>>().inner()
    }
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("push-android")
        .setup(|app, api| {
            #[cfg(target_os = "android")]
            let push = mobile::init(app, api)?;
            #[cfg(not(target_os = "android"))]
            let push = desktop::init(app, api)?;
            app.manage(push);
            Ok(())
        })
        .build()
}
