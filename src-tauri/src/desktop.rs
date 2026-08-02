use crate::{commands, connection_metrics::ConnectionMetricsTracker, NativeApplication};
use nelomai_client_core::Phase;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tauri::{
    image::Image,
    menu::{Menu, MenuItem},
    tray::{MouseButton, TrayIconBuilder, TrayIconEvent},
    App, AppHandle, Emitter, Manager,
};

const SHOW_ID: &str = "tray-show";
const TOGGLE_ID: &str = "tray-toggle";
const QUIT_ID: &str = "tray-quit";
const TRAY_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
static TOGGLE_RUNNING: AtomicBool = AtomicBool::new(false);
static EXIT_RUNNING: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Debug, PartialEq, Eq)]
struct TrayPresentation {
    toggle_text: &'static str,
    traffic_text: String,
}

struct TrayMenuState {
    toggle: MenuItem<tauri::Wry>,
    traffic: MenuItem<tauri::Wry>,
    last_presentation: Mutex<Option<TrayPresentation>>,
}

pub fn setup_tray(app: &mut App) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, SHOW_ID, "Открыть приложение", true, None::<&str>)?;
    let toggle = MenuItem::with_id(app, TOGGLE_ID, "Включить VPN", true, None::<&str>)?;
    let traffic = MenuItem::with_id(
        app,
        "tray-traffic",
        "Трафик сессии: нет подключения",
        false,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(app, QUIT_ID, "Выйти", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &toggle, &traffic, &quit])?;
    let menu_state = Arc::new(TrayMenuState {
        toggle: toggle.clone(),
        traffic: traffic.clone(),
        last_presentation: Mutex::new(None),
    });
    app.manage(menu_state);

    TrayIconBuilder::new()
        .menu(&menu)
        .show_menu_on_left_click(cfg!(target_os = "macos"))
        .icon(tray_icon())
        .icon_as_template(cfg!(target_os = "macos"))
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
                TrayIconEvent::DoubleClick {
                    button: MouseButton::Left,
                    ..
                }
            ) {
                show_window(tray.app_handle());
            }
        })
        .build(app)?;

    start_tray_refresh(app.handle().clone());
    Ok(())
}

fn tray_icon() -> Image<'static> {
    Image::new(include_bytes!("../icons/tray-icon.rgba"), 64, 64)
}

fn start_tray_refresh(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut interval = tokio::time::interval(TRAY_REFRESH_INTERVAL);
        loop {
            interval.tick().await;
            refresh_tray(&app).await;
        }
    });
}

async fn refresh_tray(app: &AppHandle) {
    let application = app.state::<Arc<NativeApplication>>().inner().clone();
    let metrics = app.state::<Arc<ConnectionMetricsTracker>>().inner().clone();
    let state = application.state().await;
    let presentation = if state.phase == Phase::Connected {
        metrics.mark_observed().await;
        let traffic_text = match state.connection.as_ref() {
            Some(connection) => metrics
                .snapshot(&connection.lease_id)
                .await
                .map(|metrics| {
                    format!(
                        "Трафик сессии: ↓ {}  ↑ {}",
                        format_bytes(metrics.received_bytes),
                        format_bytes(metrics.sent_bytes)
                    )
                })
                .unwrap_or_else(|| "Трафик сессии: подсчитывается...".to_string()),
            None => "Трафик сессии: подсчитывается...".to_string(),
        };
        TrayPresentation {
            toggle_text: "Отключить VPN",
            traffic_text,
        }
    } else {
        TrayPresentation {
            toggle_text: "Включить VPN",
            traffic_text: "Трафик сессии: нет подключения".to_string(),
        }
    };

    let tray = app.state::<Arc<TrayMenuState>>().inner().clone();
    let changed = tray
        .last_presentation
        .lock()
        .map(|mut current| {
            if current.as_ref() == Some(&presentation) {
                false
            } else {
                *current = Some(presentation.clone());
                true
            }
        })
        .unwrap_or(true);
    if changed {
        let _ = tray.toggle.set_text(presentation.toggle_text);
        let _ = tray.traffic.set_text(presentation.traffic_text);
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit]).replace('.', ",")
    }
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
        let result = commands::stop_for_shutdown(&app, application.as_ref()).await;
        match result {
            Ok(()) => app.exit(0),
            Err(error) => {
                EXIT_RUNNING.store(false, Ordering::Release);
                show_window(&app);
                let _ = app.emit(
                    "native-connection-changed",
                    Some(format!(
                        "Не удалось завершить подключение: {}",
                        error.message()
                    )),
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::format_bytes;

    #[test]
    fn formats_session_traffic_for_the_tray() {
        assert_eq!(format_bytes(900), "900 Б");
        assert_eq!(format_bytes(1_536), "1,5 КБ");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5,0 МБ");
    }
}
