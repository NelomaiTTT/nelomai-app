use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

pub use models::*;

#[cfg(desktop)]
mod desktop;
#[cfg(mobile)]
mod mobile;

mod commands;
mod error;
mod models;

pub use error::{Error, Result};

#[cfg(desktop)]
use desktop::TunnelAndroid;
#[cfg(mobile)]
use mobile::TunnelAndroid;

/// Extensions to [`tauri::App`], [`tauri::AppHandle`] and [`tauri::Window`] to access the tunnel-android APIs.
pub trait TunnelAndroidExt<R: Runtime> {
    fn tunnel_android(&self) -> &TunnelAndroid<R>;
}

impl<R: Runtime, T: Manager<R>> crate::TunnelAndroidExt<R> for T {
    fn tunnel_android(&self) -> &TunnelAndroid<R> {
        self.state::<TunnelAndroid<R>>().inner()
    }
}

/// Initializes the plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("tunnel-android")
        .invoke_handler(tauri::generate_handler![
            commands::probe,
            commands::request_vpn_permission,
            commands::start_smoke_tunnel,
            commands::stop_smoke_tunnel,
            commands::smoke_tunnel_status
        ])
        .setup(|app, api| {
            #[cfg(mobile)]
            let tunnel_android = mobile::init(app, api)?;
            #[cfg(desktop)]
            let tunnel_android = desktop::init(app, api)?;
            app.manage(tunnel_android);
            Ok(())
        })
        .build()
}
