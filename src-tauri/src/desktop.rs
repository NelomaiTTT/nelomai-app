use crate::{
    commands, connection_metrics::ConnectionMetricsTracker, diagnostics::AppDiagnostics,
    NativeApplication,
};
use nelomai_client_core::Phase;
use serde::Serialize;
#[cfg(target_os = "macos")]
use std::sync::atomic::AtomicU64;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
#[cfg(windows)]
use tauri::Runtime;
use tauri::{
    image::Image,
    menu::{Menu, MenuItem},
    tray::{MouseButton, TrayIconBuilder, TrayIconEvent},
    App, AppHandle, Emitter, Manager,
};

const SHOW_ID: &str = "tray-show";
const TOGGLE_ID: &str = "tray-toggle";
const DIAGNOSTICS_ID: &str = "tray-diagnostics";
const QUIT_ID: &str = "tray-quit";
const TRAY_ID: &str = "nelomai-main-tray";
const TRAY_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
#[cfg(target_os = "macos")]
const DOCK_HIDE_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(1100);
static TOGGLE_RUNNING: AtomicBool = AtomicBool::new(false);
static EXIT_RUNNING: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "macos")]
static DOCK_VISIBILITY_GENERATION: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, PartialEq, Eq)]
struct TrayPresentation {
    toggle_text: &'static str,
    traffic_text: String,
}

struct TrayMenuState {
    toggle: MenuItem<tauri::Wry>,
    traffic: MenuItem<tauri::Wry>,
    last_presentation: Mutex<Option<TrayPresentation>>,
    last_icon: Mutex<Option<crate::tray_update::IconState>>,
    #[cfg(windows)]
    theme: Mutex<crate::tray_update::ThemeWatcher>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeConnectionChangedEvent {
    error: Option<commands::CommandError>,
    action: &'static str,
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
    let diagnostics = MenuItem::with_id(app, DIAGNOSTICS_ID, "Диагностика", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, QUIT_ID, "Выйти", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &toggle, &traffic, &diagnostics, &quit])?;
    let menu_state = Arc::new(TrayMenuState {
        toggle: toggle.clone(),
        traffic: traffic.clone(),
        last_presentation: Mutex::new(None),
        last_icon: Mutex::new(None),
        #[cfg(windows)]
        theme: Mutex::new(crate::tray_update::ThemeWatcher::new()),
    });
    app.manage(menu_state);

    let icon = tray_icon();

    TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .show_menu_on_left_click(cfg!(target_os = "macos"))
        .icon(icon)
        .icon_as_template(cfg!(target_os = "macos"))
        .tooltip("Nelomai")
        .on_menu_event(|app, event| match event.id().as_ref() {
            SHOW_ID => show_window(app),
            TOGGLE_ID => toggle_connection(app.clone()),
            DIAGNOSTICS_ID => crate::container::show_support_diagnostics(app.clone()),
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
    crate::tray_update::IconState {
        dark: false,
        update: false,
    }
    .image()
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

fn tray_disconnect_action(
    phase: Phase,
    intent: nelomai_client_core::ConnectionIntentStatus,
) -> bool {
    matches!(
        phase,
        Phase::Connected | Phase::Connecting | Phase::Stopping
    ) || intent != nelomai_client_core::ConnectionIntentStatus::None
}

pub(crate) async fn runtime_presentation(app: &AppHandle) -> crate::runtime::TraySnapshot {
    // Report native visibility through the admitted V2 channel.
    let visible = app
        .get_webview_window("main")
        .and_then(|window| {
            window
                .is_visible()
                .ok()
                .zip(window.is_minimized().ok())
                .map(|(visible, minimized)| visible && !minimized)
        })
        .unwrap_or(true);
    let updater = app
        .state::<Arc<crate::updates::NativeUpdater>>()
        .inner()
        .clone();
    let _ = updater.report_desktop_visibility(visible).await;
    let application = app.state::<Arc<NativeApplication>>().inner().clone();
    let metrics = app.state::<Arc<ConnectionMetricsTracker>>().inner().clone();
    let state = application.state().await;
    let intent = app
        .state::<Arc<crate::connection_intent::DesktopConnectionIntent>>()
        .snapshot()
        .await;
    let disconnect_action = tray_disconnect_action(state.phase, intent.status);
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
    } else if disconnect_action {
        TrayPresentation {
            toggle_text: "Отключить VPN",
            traffic_text: "Трафик сессии: подключение восстанавливается".to_string(),
        }
    } else {
        TrayPresentation {
            toggle_text: "Включить VPN",
            traffic_text: "Трафик сессии: нет подключения".to_string(),
        }
    };

    crate::runtime::TraySnapshot {
        disconnect: presentation.toggle_text == "Отключить VPN",
        traffic: presentation.traffic_text,
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn notify_update(app: &AppHandle, version: String) {
    use tauri_plugin_notification::NotificationExt;

    let _ = app
        .notification()
        .builder()
        .title("Доступно обновление Nelomai")
        .body(format!(
            "Найдена версия {version}. Откройте приложение для установки."
        ))
        .show();
}

#[cfg(target_os = "macos")]
pub(crate) fn notify_update(app: &AppHandle, version: String) {
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSBundle, NSError, NSString};
    use objc2_user_notifications::{
        UNAuthorizationOptions, UNMutableNotificationContent, UNNotificationRequest,
        UNUserNotificationCenter,
    };

    let scheduled = app.run_on_main_thread(move || {
        if NSBundle::mainBundle().bundleIdentifier().is_none() {
            eprintln!("Nelomai update notification: application bundle unavailable");
            return;
        }
        let center = UNUserNotificationCenter::currentNotificationCenter();
        let authorized = RcBlock::new(move |granted: Bool, error: *mut NSError| {
            if !granted.as_bool() || !error.is_null() {
                eprintln!("Nelomai update notification: macOS did not grant alert authorization");
                return;
            }
            let content = UNMutableNotificationContent::new();
            content.setTitle(&NSString::from_str("Доступно обновление Nelomai"));
            content.setBody(&NSString::from_str(&format!(
                "Найдена версия {version}. Откройте приложение для установки."
            )));
            let request = UNNotificationRequest::requestWithIdentifier_content_trigger(
                &NSString::from_str(&format!("nelomai-update-{version}")),
                &content,
                None,
            );
            let submitted = RcBlock::new(|error: *mut NSError| {
                if !error.is_null() {
                    eprintln!("Nelomai update notification: macOS rejected the request");
                }
            });
            UNUserNotificationCenter::currentNotificationCenter()
                .addNotificationRequest_withCompletionHandler(&request, Some(&submitted));
        });
        center.requestAuthorizationWithOptions_completionHandler(
            UNAuthorizationOptions::Alert,
            &authorized,
        );
    });
    if scheduled.is_err() {
        eprintln!("Nelomai update notification: main thread unavailable");
    }
}

async fn refresh_tray(app: &AppHandle) {
    let snapshot = crate::container::tray_snapshot(app).unwrap_or_default();
    let presentation = TrayPresentation {
        toggle_text: if snapshot.disconnect {
            "Отключить VPN"
        } else {
            "Включить VPN"
        },
        traffic_text: snapshot.traffic,
    };

    let tray = app.state::<Arc<TrayMenuState>>().inner().clone();
    let update = crate::container::update_presentation(app);
    #[cfg(windows)]
    let dark = tray
        .theme
        .lock()
        .map(|mut theme| theme.dark())
        .unwrap_or(true);
    #[cfg(not(windows))]
    let dark = crate::tray_update::system_dark();
    let icon_state = crate::tray_update::IconState { dark, update };
    if let Ok(mut last) = tray.last_icon.lock() {
        if *last != Some(icon_state) {
            if let Some(icon) = app.tray_by_id(TRAY_ID) {
                if icon
                    .set_icon_with_as_template(Some(icon_state.image()), icon_state.template())
                    .is_ok()
                {
                    *last = Some(icon_state);
                }
            }
        }
    }

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

pub fn show_window(app: &AppHandle) {
    if crate::container::queue_action(app, crate::runtime::RuntimeAction::Show) {
        return;
    }
    #[cfg(target_os = "macos")]
    {
        DOCK_VISIBILITY_GENERATION.fetch_add(1, Ordering::AcqRel);
        let _ = app.set_dock_visibility(true);
    }

    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

pub fn hide_window(window: &tauri::Window) {
    let _ = window.hide();
    #[cfg(target_os = "macos")]
    hide_dock_when_window_stays_hidden(window.app_handle().clone());
}

pub(crate) fn close_runtime_window(close_to_tray: bool, hide: impl FnOnce(), quit: impl FnOnce()) {
    if close_to_tray {
        hide();
    } else {
        quit();
    }
}

#[cfg(target_os = "macos")]
fn hide_dock_when_window_stays_hidden(app: AppHandle) {
    let generation = DOCK_VISIBILITY_GENERATION
        .fetch_add(1, Ordering::AcqRel)
        .wrapping_add(1);
    let _ = app.set_dock_visibility(false);
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(DOCK_HIDE_RETRY_DELAY).await;
        if DOCK_VISIBILITY_GENERATION.load(Ordering::Acquire) != generation {
            return;
        }
        let window_is_hidden = app
            .get_webview_window("main")
            .and_then(|window| window.is_visible().ok())
            .is_none_or(|visible| !visible);
        if window_is_hidden {
            let _ = app.set_dock_visibility(false);
        }
    });
}

#[cfg(windows)]
pub fn set_tray_visible<R: Runtime>(app: &AppHandle<R>, visible: bool) {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_visible(visible);
    }
}

pub(crate) fn toggle_connection(app: AppHandle) {
    if crate::container::queue_action(&app, crate::runtime::RuntimeAction::Toggle) {
        return;
    }
    if TOGGLE_RUNNING.swap(true, Ordering::AcqRel) {
        return;
    }
    tauri::async_runtime::spawn(async move {
        let application = app.state::<Arc<NativeApplication>>().inner().clone();
        let intent = app
            .state::<Arc<crate::connection_intent::DesktopConnectionIntent>>()
            .snapshot()
            .await;
        let action = if matches!(
            application.state().await.phase,
            Phase::Connected | Phase::Stopping
        ) || intent.status != nelomai_client_core::ConnectionIntentStatus::None
        {
            "stop"
        } else {
            "start"
        };
        let result = commands::quick_toggle(&app, application.as_ref(), false).await;
        TOGGLE_RUNNING.store(false, Ordering::Release);
        if result.is_err() {
            show_window(&app);
        }
        let error = result.err();
        let _ = app.emit(
            "native-connection-changed",
            NativeConnectionChangedEvent { error, action },
        );
    });
}

pub fn quit_application(app: AppHandle) {
    if crate::container::queue_action(&app, crate::runtime::RuntimeAction::Quit) {
        return;
    }
    if EXIT_RUNNING.swap(true, Ordering::AcqRel) {
        return;
    }
    tauri::async_runtime::spawn(async move {
        let installed = app
            .state::<Arc<crate::updates::NativeUpdater>>()
            .status()
            .await
            .is_ok_and(|status| status.phase == "ready_to_restart");
        if installed {
            // This status only chooses the route. Common independently
            // validates the successful-install stop proof before using it.
            if let Ok(owner) = crate::runtime::native() {
                if owner
                    .control(crate::runtime::NativeControl::Exit {
                        reason: crate::runtime::NativeExitReason::Shutdown,
                    })
                    .await
                    .is_ok()
                {
                    app.exit(0);
                    return;
                }
            }
        }
        let application = app.state::<Arc<NativeApplication>>().inner().clone();
        let result = commands::stop_for_shutdown(&app, application.as_ref()).await;
        match result {
            Ok(()) => {
                let diagnostics = app.state::<Arc<AppDiagnostics>>().inner().clone();
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    crate::upload_automatic_diagnostics_once(&application, &diagnostics),
                )
                .await;
                if let Ok(owner) = crate::runtime::native() {
                    let _ = owner
                        .control(crate::runtime::NativeControl::Exit {
                            reason: crate::runtime::NativeExitReason::Shutdown,
                        })
                        .await;
                }
                app.exit(0);
            }
            Err(error) => {
                EXIT_RUNNING.store(false, Ordering::Release);
                show_window(&app);
                let _ = app.emit(
                    "native-connection-changed",
                    NativeConnectionChangedEvent {
                        error: Some(error),
                        action: "stop",
                    },
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::format_bytes;

    #[test]
    fn recovery_keeps_tray_disconnect_action() {
        use nelomai_client_core::{ConnectionIntentStatus as Intent, Phase};
        assert!(super::tray_disconnect_action(
            Phase::Error,
            Intent::Recovering
        ));
        assert!(super::tray_disconnect_action(
            Phase::Error,
            Intent::BlockedTerminal
        ));
        assert!(super::tray_disconnect_action(
            Phase::Connecting,
            Intent::None
        ));
        assert!(super::tray_disconnect_action(
            Phase::Connected,
            Intent::None
        ));
        assert!(!super::tray_disconnect_action(Phase::Ready, Intent::None));
    }

    #[test]
    fn closing_to_tray_never_requests_common_process_exit() {
        let events = std::cell::RefCell::new(Vec::new());
        super::close_runtime_window(
            true,
            || events.borrow_mut().push("hide"),
            || events.borrow_mut().push("common-exit"),
        );
        assert_eq!(*events.borrow(), ["hide"]);
        events.borrow_mut().clear();
        super::close_runtime_window(
            false,
            || events.borrow_mut().push("hide"),
            || events.borrow_mut().push("common-exit"),
        );
        assert_eq!(*events.borrow(), ["common-exit"]);
    }

    #[test]
    fn formats_session_traffic_for_the_tray() {
        assert_eq!(format_bytes(900), "900 Б");
        assert_eq!(format_bytes(1_536), "1,5 КБ");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5,0 МБ");
    }
}
