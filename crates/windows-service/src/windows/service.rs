use super::backend::{resolve_endpoint, WindowsServiceBackend};
use super::install::{record_service_diagnostic, record_service_message};
use super::ipc::{finish_frame, wake_server, PipeServer, DISPATCHER_PIPE_NAME};
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

#[path = "../engine_channel.rs"]
mod engine_channel;

define_windows_service!(manager_service_main, manager_service_entry);

const REQUEST_WATCHDOG_TIMEOUT: Duration = Duration::from_secs(40);

pub(crate) struct RequestWatchdog {
    completed: Arc<(Mutex<bool>, Condvar)>,
}

impl RequestWatchdog {
    pub(crate) fn arm() -> Result<Self, ServiceError> {
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

    pub(crate) fn complete(self) {
        let (lock, condition) = &*self.completed;
        let mut completed = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *completed = true;
        condition.notify_one();
    }
}

/// One broker wakeup loop for the existing manager, sharing the same serialized
/// dispatcher owner as GUI exchanges. No engine launch or server/API scheduling.
struct IdleBroker {
    stopping: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl IdleBroker {
    fn start(
        owner: Arc<Mutex<nelomai_contracts::dispatcher::ProcessDispatcher>>,
        stopping: Arc<AtomicBool>,
    ) -> Result<Self, ServiceError> {
        let thread_stopping = Arc::clone(&stopping);
        let thread = std::thread::Builder::new()
            .name("nelomai-idle-engine-broker".into())
            .spawn(move || {
                let mut failure_reported = false;
                while !thread_stopping.load(Ordering::Acquire) {
                    std::thread::park_timeout(Duration::from_secs(1));
                    if thread_stopping.load(Ordering::Acquire) {
                        break;
                    }
                    // An active GUI exchange already services primitives. Never
                    // queue a competing exchange behind it or spawn a child.
                    let Ok(mut dispatcher) = owner.try_lock() else {
                        continue;
                    };
                    if thread_stopping.load(Ordering::Acquire) || !dispatcher.supports_idle_tick() {
                        continue;
                    }
                    let Ok(watchdog) = RequestWatchdog::arm() else {
                        continue;
                    };
                    let result = dispatcher.idle_tick(&mut |action, engine| {
                        super::install::engine_primitive(action, engine)
                    });
                    watchdog.complete();
                    if result.is_err() && !failure_reported {
                        // A failed exchange fences the channel. A transient
                        // ownership-lock failure is logged once until recovery.
                        record_service_diagnostic(
                            "idle engine broker",
                            &ServiceError::Backend("engine_idle_tick_failed".into()),
                        );
                    }
                    failure_reported = result.is_err();
                }
            })
            .map_err(|error| platform_error("start idle engine broker", error))?;
        Ok(Self {
            stopping,
            thread: Some(thread),
        })
    }
}

impl Drop for IdleBroker {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.thread().unpark();
            // A live exchange is covered by the existing 40s process watchdog.
            let _ = thread.join();
        }
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
    crate::service_lifecycle::run(
        |status| set_status(&status_handle, status),
        |report| serve_manager(stopping, report),
    )
}

fn serve_manager(
    stopping: Arc<AtomicBool>,
    report: &mut dyn FnMut(crate::service_lifecycle::Status) -> Result<(), ServiceError>,
) -> Result<(), ServiceError> {
    use nelomai_contracts::dispatcher as d;
    let installation = d::Installation::production(&super::install::installation_directory()?)
        .map_err(|_| ServiceError::UnauthorizedClient)?;
    let dispatcher =
        d::ProcessDispatcher::new(installation).map_err(|_| ServiceError::UnauthorizedClient)?;
    let broker = dispatcher.layout.broker.clone();
    let policy = crate::ClientPolicy {
        owner_sid: broker.owner.clone(),
        installed_client_path: broker.executable.clone(),
    };
    let server = PipeServer::new(policy.clone(), broker.clone(), DISPATCHER_PIPE_NAME);
    let private = PipeServer::new(policy, broker, crate::PIPE_NAME);
    let owner = Arc::new(Mutex::new(dispatcher));
    let recovery_identity = owner
        .lock()
        .map_err(|_| ServiceError::InvalidRequest)?
        .layout
        .identity
        .clone();
    if owner
        .lock()
        .map_err(|_| ServiceError::InvalidRequest)?
        .installation
        .root
        .join(d::ACTIVE_ENGINE_NAME)
        .exists()
    {
        let frame = d::encode_frame(&d::DispatcherRequest::Stop {
            contract_version: 1,
            identity: recovery_identity,
        })
        .map_err(|_| ServiceError::InvalidRequest)?;
        let result = serve_owned_frame(&owner, &frame, false);
        let response: d::DispatcherResponse = serde_json::from_slice(
            d::frame_body(&result, d::MAX_DISPATCHER_FRAME)
                .map_err(|_| ServiceError::InvalidRequest)?,
        )
        .map_err(|_| ServiceError::InvalidRequest)?;
        if !response.ok {
            return Err(ServiceError::Backend("dispatcher_recovery_pending".into()));
        }
    }
    let idle_broker = IdleBroker::start(Arc::clone(&owner), Arc::clone(&stopping))?;
    let private_owner = Arc::clone(&owner);
    std::thread::spawn(move || {
        let mut failures = 0_u64;
        loop {
            match private.accept() {
                Ok(Some((frame, pipe))) => {
                    failures = 0;
                    let output = serve_owned_frame(&private_owner, &frame, true);
                    let _ = finish_frame(pipe, &output);
                }
                Ok(None) => failures = 0,
                Err(error) => {
                    failures = failures.saturating_add(1);
                    if failures == 1 || failures % 100 == 0 {
                        record_service_diagnostic("accept private pipe request", &error);
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    });
    report(crate::service_lifecycle::Status::Running)?;
    record_service_message("manager lifecycle", "running");
    let mut accept_failures = 0_u64;
    while !stopping.load(Ordering::Acquire) {
        match server.accept() {
            Ok(Some((frame, pipe))) => {
                accept_failures = 0;
                if stopping.load(Ordering::Acquire) {
                    let _ = finish_frame(
                        pipe,
                        &d::encode_frame(&d::DispatcherResponse::failure())
                            .map_err(|_| ServiceError::InvalidRequest)?,
                    );
                    break;
                }
                let response = serve_owned_frame(&owner, &frame, false);
                if let Err(error) = finish_frame(pipe, &response) {
                    record_service_diagnostic("send pipe response", &error);
                }
            }
            Ok(None) => accept_failures = 0,
            Err(_) if stopping.load(Ordering::Acquire) => break,
            Err(error) => {
                accept_failures = accept_failures.saturating_add(1);
                if accept_failures == 1 || accept_failures % 100 == 0 {
                    record_service_diagnostic("accept pipe request", &error);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    drop(idle_broker);
    record_service_message("manager lifecycle", "SCM stop requested");
    if let Ok(mut dispatcher) = owner.lock() {
        let identity = dispatcher.layout.identity.clone();
        let response = dispatcher.handle(
            d::DispatcherRequest::Stop {
                contract_version: 1,
                identity,
            },
            &mut |action, engine| super::install::engine_primitive(action, engine),
        );
        if !response.ok {
            record_service_message("dispatcher stop", "cleanup remains pending");
            return Err(ServiceError::Backend("dispatcher_recovery_pending".into()));
        }
    } else {
        return Err(ServiceError::Backend("dispatcher_recovery_pending".into()));
    }
    Ok(())
}

fn serve_owned_frame(
    owner: &Arc<Mutex<nelomai_contracts::dispatcher::ProcessDispatcher>>,
    frame: &[u8],
    private: bool,
) -> Vec<u8> {
    use nelomai_contracts::dispatcher as d;
    let failure = || d::encode_frame(&d::DispatcherResponse::failure()).unwrap_or_default();
    let Ok(watchdog) = RequestWatchdog::arm() else {
        return failure();
    };
    let output = (|| {
        let mut dispatcher = owner.try_lock().map_err(|_| d::blocked())?;
        if private {
            dispatcher.relay(frame, &mut |action, engine| {
                super::install::engine_primitive(action, engine)
            })
        } else {
            let response = dispatcher.handle(d::decode_request(frame)?, &mut |action, engine| {
                super::install::engine_primitive(action, engine)
            });
            d::encode_frame(&response)
        }
    })()
    .unwrap_or_else(|_: std::io::Error| failure());
    watchdog.complete();
    output
}

pub fn run_engine_mode(root: &Path) -> Result<(), ServiceError> {
    use nelomai_contracts::dispatcher as d;
    let installation =
        d::Installation::production(root).map_err(|_| ServiceError::UnauthorizedClient)?;
    let layout = installation
        .load_engine(
            &std::fs::canonicalize(std::env::current_exe().map_err(|_| ServiceError::UnsafePath)?)
                .map_err(|_| ServiceError::UnsafePath)?,
        )
        .map_err(|_| ServiceError::UnauthorizedClient)?;
    let _lease = d::MutationGuard::at(&root.join("engine-owner.lock"))
        .map_err(|_| ServiceError::UnauthorizedClient)?;
    let factory = super::member_pair::NativePairFactory::from_service(
        layout.identity.clone(),
        &layout.engine_path(),
    )
    .map_err(|_| ServiceError::Backend("member_runtime_factory_failed".into()))?;
    let backend = crate::member_actor::CompositeBackend::new(
        layout.identity.slot,
        WindowsServiceBackend::new()?,
        factory,
    )?;
    let handler = TunnelRequestHandler::new(backend, layout.identity.runtime_version);
    let mut owner = EngineHandler {
        handler,
        shutting_down: false,
        stopped: false,
    };
    let (frames, client) =
        engine_channel::spawn_input(std::io::stdin()).map_err(|_| ServiceError::InvalidRequest)?;
    // This function returns directly to engine main, which must exit: the sole
    // detached reader may remain blocked in the process-owned input pipe.
    engine_channel::with_owner(client, || {
        nelomai_client_tunnel::redundancy::engine_channel::run_receiver(
            frames,
            &mut std::io::stdout(),
            &mut owner,
        )
    })
    .map_err(|_| ServiceError::InvalidRequest)?
    .map_err(|_| ServiceError::Backend("engine_channel_failed".into()))
}

struct EngineHandler<B> {
    handler: TunnelRequestHandler<B>,
    shutting_down: bool,
    stopped: bool,
}

impl<B: crate::ServiceTunnelBackend> nelomai_client_tunnel::redundancy::engine_channel::Handler
    for EngineHandler<B>
{
    fn handle(&mut self, frame: &[u8]) -> std::io::Result<Vec<u8>> {
        use nelomai_contracts::dispatcher as d;
        engine_channel::ensure_healthy()?;
        let value: serde_json::Value =
            serde_json::from_slice(d::frame_body(frame, MAX_FRAME_SIZE)?)
                .map_err(|_| d::blocked())?;
        match value
            .get("dispatcher_control")
            .and_then(|value| value.as_str())
        {
            Some("stop") => {
                let stopped = self.shutdown().is_ok();
                d::encode_frame(&serde_json::json!({"engine_stopped":stopped}))
            }
            _ if self.shutting_down => {
                d::encode_frame(&crate::Response::failure("engine_stopping"))
            }
            Some("ready") => {
                d::encode_frame(&serde_json::json!({"engine_ready":true,"supports_idle_tick":true}))
            }
            Some("tick") => d::encode_frame(&serde_json::json!({"engine_tick":true})),
            _ => {
                let response = match crate::decode_request(frame) {
                    Ok(request) => self.handler.handle(request),
                    Err(error) => {
                        let _ = self.shutdown();
                        crate::Response::failure(error.code())
                    }
                };
                d::encode_frame(&response)
            }
        }
    }

    fn tick(&mut self, now: u64) -> std::io::Result<()> {
        engine_channel::ensure_healthy()?;
        if self.shutting_down {
            return Ok(());
        }
        self.handler
            .tick(now)
            .map_err(|error| std::io::Error::other(error.code().to_owned()))
    }

    fn shutdown(&mut self) -> std::io::Result<()> {
        self.shutting_down = true;
        if self.stopped {
            return Ok(());
        }
        let state = self
            .handler
            .shutdown()
            .map_err(|error| std::io::Error::other(error.code().to_owned()))?;
        if state != crate::ServiceTunnelState::Stopped {
            return Err(std::io::Error::other("engine_cleanup_pending"));
        }
        self.stopped = true;
        Ok(())
    }
}

pub(crate) fn request_primitive(
    action: nelomai_contracts::dispatcher::EnginePrimitive,
) -> Result<(), ServiceError> {
    engine_channel::request_primitive(action, &mut std::io::stdout())
        .map_err(|_| ServiceError::Backend("dispatcher_primitive_failed".into()))
}

fn set_status(
    handle: &service_control_handler::ServiceStatusHandle,
    status: crate::service_lifecycle::Status,
) -> Result<(), ServiceError> {
    use crate::service_lifecycle::Status;
    let (state, accepted, exit_code, checkpoint, wait_hint) = match status {
        Status::StartPending => (
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            ServiceExitCode::Win32(0),
            1,
            REQUEST_WATCHDOG_TIMEOUT,
        ),
        Status::Running => (
            ServiceState::Running,
            ServiceControlAccept::STOP,
            ServiceExitCode::Win32(0),
            0,
            Duration::ZERO,
        ),
        Status::Stopped { failed } => (
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            if failed {
                ServiceExitCode::ServiceSpecific(1)
            } else {
                ServiceExitCode::Win32(0)
            },
            0,
            Duration::ZERO,
        ),
    };
    handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accepted,
            exit_code,
            checkpoint,
            wait_hint,
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
    run_named_amneziawg_service(configuration, AMNEZIAWG_TUNNEL_SERVICE_NAME)
}

pub fn run_amneziawg_slot_service(
    configuration: &Path,
    slot: nelomai_contracts::dispatcher::TunnelSlot,
) -> Result<(), ServiceError> {
    if configuration != super::install::slot_config_path(slot)? {
        return Err(ServiceError::UnsafePath);
    }
    run_named_amneziawg_service(
        configuration,
        crate::redundancy::slot_service_name(
            slot,
            nelomai_client_tunnel::TunnelTransport::AmneziaWg3,
        ),
    )
}

fn run_named_amneziawg_service(
    configuration: &Path,
    service_name: &str,
) -> Result<(), ServiceError> {
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
    crate::redundancy::prepare_awg_route_supervision(service_name, || {
        start_amneziawg_endpoint_route_watchdog(endpoint)
    })?;
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
    let service_name = wide(std::ffi::OsStr::new(service_name));
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
