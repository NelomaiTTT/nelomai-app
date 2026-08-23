use super::backend::{resolve_endpoint, WindowsServiceBackend};
use super::install::{load_policy, record_service_diagnostic, record_service_message};
use super::ipc::{finish_request, wake_server, PipeServer};
use super::routes::WindowsRouteManager;
use super::{platform_error, wide};
use crate::{
    ServiceError, TunnelRequestHandler, AMNEZIAWG_TUNNEL_SERVICE_NAME, MANAGER_SERVICE_NAME,
    MAX_FRAME_SIZE,
};
use std::ffi::OsString;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_sys::Win32::Foundation::FreeLibrary;
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
};

define_windows_service!(manager_service_main, manager_service_entry);

const REQUEST_WATCHDOG_TIMEOUT: Duration = Duration::from_secs(40);

struct RequestWatchdog {
    completed: Arc<(Mutex<bool>, Condvar)>,
}

impl RequestWatchdog {
    fn arm() -> Result<Self, ServiceError> {
        let completed = Arc::new((Mutex::new(false), Condvar::new()));
        let completed_for_thread = Arc::clone(&completed);
        std::thread::Builder::new()
            .name("nelomai-service-watchdog".to_string())
            .spawn(move || {
                let (lock, condition) = &*completed_for_thread;
                let guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                let (guard, timeout) = condition
                    .wait_timeout_while(guard, REQUEST_WATCHDOG_TIMEOUT, |completed| !*completed)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if timeout.timed_out() && !*guard {
                    record_service_diagnostic(
                        "manager request watchdog",
                        &ServiceError::Backend("service_timeout".to_string()),
                    );
                    // Recovery actions restart the manager service. The WireGuard tunnel
                    // itself runs in a separate service and is not interrupted here.
                    std::process::exit(1);
                }
            })
            .map_err(|error| platform_error("start manager request watchdog", error))?;
        Ok(Self { completed })
    }

    fn complete(self) {
        let (lock, condition) = &*self.completed;
        let mut completed = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *completed = true;
        condition.notify_one();
    }
}

pub fn run_manager_service() -> Result<(), ServiceError> {
    service_dispatcher::start(MANAGER_SERVICE_NAME, manager_service_main)
        .map_err(|error| platform_error("start manager service dispatcher", error))
}

fn manager_service_entry(_arguments: Vec<OsString>) {
    record_service_message(
        "manager lifecycle",
        &format!(
            "started pid={} version={}",
            std::process::id(),
            env!("CARGO_PKG_VERSION")
        ),
    );
    if let Err(error) = manager_service_loop() {
        record_service_diagnostic("manager service stopped", &error);
    } else {
        record_service_message("manager lifecycle", "stopped cleanly");
    }
}

fn manager_service_loop() -> Result<(), ServiceError> {
    let stopping = Arc::new(AtomicBool::new(false));
    let stopping_for_handler = Arc::clone(&stopping);
    let status_handle =
        service_control_handler::register(MANAGER_SERVICE_NAME, move |event| match event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                stopping_for_handler.store(true, Ordering::Release);
                wake_server();
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        })
        .map_err(|error| platform_error("register manager service control handler", error))?;
    set_status(
        &status_handle,
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
    )?;

    let server = PipeServer::new(load_policy()?);
    let mut handler =
        TunnelRequestHandler::new(WindowsServiceBackend::new()?, env!("CARGO_PKG_VERSION"));
    set_status(
        &status_handle,
        ServiceState::Running,
        ServiceControlAccept::STOP,
    )?;
    record_service_message("manager lifecycle", "running");
    while !stopping.load(Ordering::Acquire) {
        match server.accept() {
            Ok(Some((request, pipe))) => {
                if stopping.load(Ordering::Acquire) {
                    let _ = finish_request(pipe, &crate::Response::failure("service_stopping"));
                    break;
                }
                let action = request.diagnostic_name();
                let lifecycle_event = request.is_lifecycle_event();
                if lifecycle_event {
                    record_service_message("manager request", &format!("started action={action}"));
                }
                let response = match RequestWatchdog::arm() {
                    Ok(watchdog) => {
                        let response = handler.handle(request);
                        watchdog.complete();
                        response
                    }
                    Err(error) => {
                        record_service_diagnostic("start request watchdog", &error);
                        crate::Response::failure(error.code())
                    }
                };
                if lifecycle_event {
                    record_service_message(
                        "manager request",
                        &format!(
                            "completed action={action} ok={} state={:?} error={}",
                            response.ok,
                            response.state,
                            response.error_code.as_deref().unwrap_or("none")
                        ),
                    );
                }
                if let Err(error) = finish_request(pipe, &response) {
                    record_service_diagnostic("send pipe response", &error);
                }
            }
            Ok(None) => {}
            Err(_) if stopping.load(Ordering::Acquire) => break,
            Err(error) => {
                record_service_diagnostic("accept pipe request", &error);
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    record_service_message("manager lifecycle", "SCM stop requested");
    set_status(
        &status_handle,
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
    )
}

fn set_status(
    handle: &service_control_handler::ServiceStatusHandle,
    state: ServiceState,
    accepted: ServiceControlAccept,
) -> Result<(), ServiceError> {
    handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accepted,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .map_err(|error| platform_error("update manager service status", error))
}

pub fn run_wireguard_service(configuration: &Path) -> Result<(), ServiceError> {
    record_service_message(
        "WireGuard tunnel lifecycle",
        &format!("started pid={}", std::process::id()),
    );
    let tunnel_dll = std::env::current_exe()
        .map_err(|error| platform_error("resolve tunnel service executable", error))?
        .with_file_name("tunnel.dll");
    let tunnel_dll = wide(tunnel_dll.as_os_str());
    let module = unsafe {
        LoadLibraryExW(
            tunnel_dll.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
        )
    };
    if module.is_null() {
        return Err(platform_error(
            "load tunnel.dll",
            std::io::Error::last_os_error(),
        ));
    }
    let procedure = unsafe { GetProcAddress(module, c"WireGuardTunnelService".as_ptr().cast()) };
    let Some(procedure) = procedure else {
        unsafe {
            FreeLibrary(module);
        }
        return Err(platform_error(
            "resolve WireGuardTunnelService",
            std::io::Error::last_os_error(),
        ));
    };
    type WireGuardTunnelService = unsafe extern "C" fn(*const u16) -> bool;
    let service: WireGuardTunnelService =
        unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, _>(procedure) };
    let configuration = wide(configuration.as_os_str());
    let succeeded = unsafe { service(configuration.as_ptr()) };
    unsafe {
        FreeLibrary(module);
    }
    if succeeded {
        record_service_message(
            "WireGuard tunnel lifecycle",
            "service function returned success",
        );
        Ok(())
    } else {
        record_service_message(
            "WireGuard tunnel lifecycle",
            "service function returned failure",
        );
        Err(ServiceError::Backend(
            "WireGuardTunnelService returned failure".to_string(),
        ))
    }
}

pub fn run_amneziawg_service(configuration: &Path) -> Result<(), ServiceError> {
    record_service_message(
        "AmneziaWG tunnel lifecycle",
        &format!("started pid={}", std::process::id()),
    );
    let metadata = std::fs::metadata(configuration)
        .map_err(|error| platform_error("read AmneziaWG configuration metadata", error))?;
    if metadata.len() as usize > MAX_FRAME_SIZE {
        return Err(ServiceError::FrameTooLarge);
    }
    let configuration_text = zeroize::Zeroizing::new(
        std::fs::read_to_string(configuration)
            .map_err(|error| platform_error("read AmneziaWG configuration", error))?,
    );
    let endpoint = resolve_endpoint(configuration_text.as_str())
        .filter(std::net::IpAddr::is_ipv4)
        .ok_or_else(|| ServiceError::Backend("endpoint_route_unavailable".to_string()))?;
    start_amneziawg_endpoint_route_watchdog(endpoint)?;
    let tunnel_dll = std::env::current_exe()
        .map_err(|error| platform_error("resolve tunnel service executable", error))?
        .with_file_name("amneziawg-tunnel.dll");
    let tunnel_dll = wide(tunnel_dll.as_os_str());
    let module = unsafe {
        LoadLibraryExW(
            tunnel_dll.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
        )
    };
    if module.is_null() {
        return Err(platform_error(
            "load amneziawg-tunnel.dll",
            std::io::Error::last_os_error(),
        ));
    }
    let procedure = unsafe { GetProcAddress(module, c"WireGuardTunnelService".as_ptr().cast()) };
    let Some(procedure) = procedure else {
        unsafe {
            FreeLibrary(module);
        }
        return Err(platform_error(
            "resolve AmneziaWG tunnel service",
            std::io::Error::last_os_error(),
        ));
    };
    type AmneziaWgTunnelService = unsafe extern "C" fn(*const u16, *const u16) -> bool;
    let service: AmneziaWgTunnelService =
        unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, _>(procedure) };
    let configuration_text =
        zeroize::Zeroizing::new(wide(std::ffi::OsStr::new(configuration_text.as_str())));
    let service_name = wide(std::ffi::OsStr::new(AMNEZIAWG_TUNNEL_SERVICE_NAME));
    let succeeded = unsafe { service(configuration_text.as_ptr(), service_name.as_ptr()) };
    unsafe {
        FreeLibrary(module);
    }
    if succeeded {
        record_service_message(
            "AmneziaWG tunnel lifecycle",
            "service function returned success",
        );
        Ok(())
    } else {
        record_service_message(
            "AmneziaWG tunnel lifecycle",
            "service function returned failure",
        );
        Err(ServiceError::Backend(
            "AmneziaWG tunnel service returned failure".to_string(),
        ))
    }
}

fn start_amneziawg_endpoint_route_watchdog(endpoint: std::net::IpAddr) -> Result<(), ServiceError> {
    std::thread::Builder::new()
        .name("nelomai-awg-endpoint-route-watchdog".to_string())
        .spawn(move || loop {
            let result = WindowsRouteManager::new()
                .and_then(|routes| routes.verify_protected_endpoint(Some(endpoint)));
            if let Err(error) = result {
                record_service_diagnostic("AmneziaWG endpoint route watchdog", &error);
                std::process::exit(1);
            }
            std::thread::sleep(Duration::from_secs(1));
        })
        .map(|_| ())
        .map_err(|error| platform_error("start AmneziaWG endpoint route watchdog", error))
}
