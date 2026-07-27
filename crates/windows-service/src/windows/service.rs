use super::backend::WindowsServiceBackend;
use super::install::{load_policy, record_service_diagnostic};
use super::ipc::{finish_request, wake_server, PipeServer};
use super::{platform_error, wide};
use crate::{ServiceError, TunnelRequestHandler, MANAGER_SERVICE_NAME};
use std::ffi::OsString;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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

pub fn run_manager_service() -> Result<(), ServiceError> {
    service_dispatcher::start(MANAGER_SERVICE_NAME, manager_service_main)
        .map_err(|error| platform_error("start manager service dispatcher", error))
}

fn manager_service_entry(_arguments: Vec<OsString>) {
    if let Err(error) = manager_service_loop() {
        record_service_diagnostic("manager service stopped", &error);
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
        TunnelRequestHandler::new(WindowsServiceBackend::new(), env!("CARGO_PKG_VERSION"));
    set_status(
        &status_handle,
        ServiceState::Running,
        ServiceControlAccept::STOP,
    )?;
    while !stopping.load(Ordering::Acquire) {
        match server.accept() {
            Ok(Some((request, pipe))) => {
                if stopping.load(Ordering::Acquire) {
                    let _ = finish_request(pipe, &crate::Response::failure("service_stopping"));
                    break;
                }
                let response = handler.handle(request);
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
        Ok(())
    } else {
        Err(ServiceError::Backend(
            "WireGuardTunnelService returned failure".to_string(),
        ))
    }
}
