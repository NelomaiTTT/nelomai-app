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
use desktop::UpdaterAndroid;
#[cfg(target_os = "android")]
use mobile::UpdaterAndroid;

pub use error::{Error, Result};
pub use models::{InstallApkRequest, InstallApkResponse};

pub trait UpdaterAndroidExt<R: Runtime> {
    fn updater_android(&self) -> &UpdaterAndroid<R>;
}

impl<R: Runtime, T: Manager<R>> UpdaterAndroidExt<R> for T {
    fn updater_android(&self) -> &UpdaterAndroid<R> {
        self.state::<UpdaterAndroid<R>>().inner()
    }
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("updater-android")
        .setup(|app, api| {
            #[cfg(target_os = "android")]
            let updater = mobile::init(app, api)?;
            #[cfg(not(target_os = "android"))]
            let updater = desktop::init(app, api)?;
            app.manage(updater);
            Ok(())
        })
        .build()
}
