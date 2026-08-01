use crate::{commands, NativeApplication};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    App, AppHandle, Emitter, Manager,
};

const SHOW_ID: &str = "tray-show";
const TOGGLE_ID: &str = "tray-toggle";
const QUIT_ID: &str = "tray-quit";
static TOGGLE_RUNNING: AtomicBool = AtomicBool::new(false);
static EXIT_RUNNING: AtomicBool = AtomicBool::new(false);

pub fn setup_tray(app: &mut App) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, SHOW_ID, "Открыть Nelomai", true, None::<&str>)?;
    let toggle = MenuItem::with_id(
        app,
        TOGGLE_ID,
        "Включить или отключить VPN",
        true,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(app, QUIT_ID, "Выйти", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &toggle, &quit])?;
    let mut tray = TrayIconBuilder::new()
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip("Nelomai")
        .on_menu_event(|app, event| match event.id().as_ref() {
            SHOW_ID => show_window(app),
            TOGGLE_ID => toggle_connection(app.clone()),
            QUIT_ID => quit_application(app.clone()),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if matches!(
                event,
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                }
            ) {
                show_window(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon().cloned() {
        tray = tray.icon(icon);
    }
    tray.build(app)?;
    Ok(())
}

fn show_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn toggle_connection(app: AppHandle) {
    if TOGGLE_RUNNING.swap(true, Ordering::AcqRel) {
        return;
    }
    tauri::async_runtime::spawn(async move {
        let application = app.state::<Arc<NativeApplication>>().inner().clone();
        let result = commands::quick_toggle(&app, application.as_ref(), false).await;
        TOGGLE_RUNNING.store(false, Ordering::Release);
        if result.is_err() {
            show_window(&app);
        }
        let _ = app.emit(
            "native-connection-changed",
            result.err().map(|error| error.message().to_string()),
        );
    });
}

pub fn quit_application(app: AppHandle) {
    if EXIT_RUNNING.swap(true, Ordering::AcqRel) {
        return;
    }
    tauri::async_runtime::spawn(async move {
        let application = app.state::<Arc<NativeApplication>>().inner().clone();
        let result = application.stop_for_shutdown().await.map(|_| ());
        match result {
            Ok(()) => app.exit(0),
            Err(error) => {
                EXIT_RUNNING.store(false, Ordering::Release);
                show_window(&app);
                let _ = app.emit(
                    "native-connection-changed",
                    Some(format!("Не удалось завершить подключение: {error}")),
                );
            }
        }
    });
}
