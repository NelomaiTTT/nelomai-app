use super::routes::WindowsRouteManager;
use super::{platform_error, wide};
use crate::{
    manager_service_spec, pipe_security_descriptor, private_directory_security_descriptor,
    tunnel_service_spec, ServiceError, ServiceSpec, ServiceStartMode,
    AMNEZIAWG_TUNNEL_SERVICE_NAME, MANAGER_SERVICE_NAME, TUNNEL_SERVICE_NAME,
};
use nelomai_client_tunnel::TunnelTransport;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceDependency,
    ServiceErrorControl, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo,
    ServiceSidType, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Foundation::{
    ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_MARKED_FOR_DELETE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
};

const TUNNEL_CONFIG_FILE: &str = "nelomai.conf";
const DIAGNOSTIC_LOG_FILE: &str = "service-diagnostics.log";
const MAX_DIAGNOSTIC_LOG_SIZE: u64 = 64 * 1024;

#[derive(Debug, Clone)]
pub struct InstallOptions {
    pub owner_sid: String,
    pub installed_client_path: PathBuf,
}

pub fn install(options: InstallOptions) -> Result<(), ServiceError> {
    let executable =
        env::current_exe().map_err(|error| platform_error("resolve service executable", error))?;
    let installed_client_path =
        validate_install_location(&executable, &options.installed_client_path)?;
    // Task 9 installs the common container and its signed runtime tree together.
    // The elevated installer derives the source from that trusted container,
    // never from a runtime IPC request or an update-supplied verification key.
    let source = installed_client_path
        .parent()
        .ok_or(ServiceError::UnsafePath)?
        .join("runtime");
    let install_root = installation_directory()?;
    fs::create_dir_all(&install_root)
        .map_err(|error| platform_error("create privileged layout", error))?;
    apply_private_acl(&install_root)?;
    let installation = nelomai_contracts::dispatcher::Installation::production(&install_root)
        .map_err(|_| ServiceError::UnauthorizedClient)?;
    let previous =
        match fs::read_to_string(install_root.join(nelomai_contracts::dispatcher::POINTER_NAME)) {
            Ok(value) => Some(value),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(platform_error("read previous dispatcher pointer", error)),
        };
    let layout = installation
        .install(
            &source,
            &installed_client_path,
            &options.owner_sid,
            &nelomai_contracts::dispatcher::RealInstallIo,
        )
        .map_err(|_| ServiceError::UnauthorizedClient)?;
    let activation = (|| {
        pipe_security_descriptor(&options.owner_sid)?;
        let root = state_directory()?;
        fs::create_dir_all(&root)
            .map_err(|error| platform_error("create service state directory", error))?;
        apply_private_acl(&root)?;
        let _ = fs::remove_file(root.join(DIAGNOSTIC_LOG_FILE));
        remove_service(MANAGER_SERVICE_NAME)?;
        let spec = manager_service_spec(&layout.dispatcher_path())?;
        let manager =
            service_manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
        let service = create_service(&manager, &spec)?;
        service
            .set_description("Controls Nelomai WireGuard tunnels for the installed desktop client.")
            .map_err(|error| platform_error("set manager service description", error))?;
        configure_manager_recovery(&service)?;
        service
            .start(&[] as &[&str])
            .map_err(|error| platform_error("start manager service", error))?;
        wait_until_running(&service)
    })();
    if let Err(error) = activation {
        remove_service(MANAGER_SERVICE_NAME)?;
        let published = layout
            .directory
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(ServiceError::UnsafePath)?;
        installation
            .rollback_activation(published, previous.as_deref())
            .map_err(|_| ServiceError::Backend("dispatcher_activation_rollback_failed".into()))?;
        if let Some(previous) = previous {
            let executable = install_root
                .join("releases")
                .join(previous)
                .join("dispatcher/1/nelomai-windows-service.exe");
            let spec = manager_service_spec(&executable)?;
            let manager = service_manager(
                ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
            )?;
            let service = create_service(&manager, &spec)?;
            configure_manager_recovery(&service)?;
            service.start(&[] as &[&str]).map_err(|failure| {
                platform_error("restore previous dispatcher service", failure)
            })?;
            wait_until_running(&service)?;
        }
        return Err(error);
    }
    Ok(())
}

fn configure_manager_recovery(service: &Service) -> Result<(), ServiceError> {
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(1),
                },
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(5),
                },
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(30),
                },
                ServiceAction {
                    action_type: ServiceActionType::None,
                    delay: Duration::default(),
                },
            ]),
        })
        .map_err(|error| platform_error("configure manager service recovery", error))?;
    service
        .set_failure_actions_on_non_crash_failures(true)
        .map_err(|error| platform_error("enable manager service recovery", error))
}

pub fn uninstall() -> Result<(), ServiceError> {
    remove_tunnel_service()?;
    remove_service(MANAGER_SERVICE_NAME)?;
    WindowsRouteManager::new()?.cleanup()?;
    let root = state_directory()?;
    if root.exists() {
        fs::remove_dir_all(&root)
            .map_err(|error| platform_error("remove service state directory", error))?;
    }
    Ok(())
}

pub(crate) fn tunnel_config_path() -> Result<PathBuf, ServiceError> {
    Ok(state_directory()?.join(TUNNEL_CONFIG_FILE))
}

pub(crate) fn record_service_diagnostic(context: &str, error: &ServiceError) {
    record_service_message(context, &error.to_string());
}

pub(crate) fn read_service_diagnostics() -> Result<String, ServiceError> {
    let path = state_directory()?.join(DIAGNOSTIC_LOG_FILE);
    match fs::read_to_string(path) {
        Ok(value) => Ok(value.trim_start_matches('\u{feff}').to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(platform_error("read service diagnostics", error)),
    }
}

pub(crate) fn record_service_message(context: &str, message: &str) {
    let Ok(root) = state_directory() else {
        return;
    };
    let path = root.join(DIAGNOSTIC_LOG_FILE);
    let truncate = fs::metadata(&path)
        .map(|metadata| metadata.len() >= MAX_DIAGNOSTIC_LOG_SIZE)
        .unwrap_or(false);
    let write_bom = truncate || !path.exists();
    let Ok(mut log) = OpenOptions::new()
        .create(true)
        .write(true)
        .append(!truncate)
        .truncate(truncate)
        .open(path)
    else {
        return;
    };
    if write_bom {
        let _ = log.write_all(&[0xEF, 0xBB, 0xBF]);
    }
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    let message = message.replace(['\r', '\n'], " ");
    let _ = writeln!(log, "{timestamp} {context}: {message}");
}

pub(crate) fn create_or_replace_tunnel_service(
    executable: &Path,
    configuration: &Path,
    transport: TunnelTransport,
) -> Result<Service, ServiceError> {
    remove_tunnel_service()?;
    let spec = tunnel_service_spec(executable, configuration, transport)?;
    let manager =
        service_manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let service = create_service(&manager, &spec)?;
    service
        .set_config_service_sid_info(ServiceSidType::Unrestricted)
        .map_err(|error| platform_error("set WireGuard service SID", error))?;
    Ok(service)
}

pub(crate) fn engine_primitive(
    action: nelomai_contracts::dispatcher::EnginePrimitive,
    engine: &Path,
) -> std::io::Result<()> {
    use nelomai_contracts::dispatcher::EnginePrimitive;
    let result = (|| match action {
        EnginePrimitive::StartWireguard | EnginePrimitive::StartAmneziawg => {
            let transport = if matches!(action, EnginePrimitive::StartWireguard) {
                TunnelTransport::WireGuard
            } else {
                TunnelTransport::AmneziaWg3
            };
            let service =
                create_or_replace_tunnel_service(engine, &tunnel_config_path()?, transport)?;
            service
                .start(&[] as &[&str])
                .map_err(|error| platform_error("start versioned tunnel", error))?;
            wait_until_running(&service)
        }
        EnginePrimitive::StopServices => remove_tunnel_service(),
        EnginePrimitive::RebindService => {
            let service = open_tunnel_service()?.ok_or(ServiceError::InvalidRequest)?;
            let deadline = Instant::now() + Duration::from_secs(3);
            service
                .stop()
                .map_err(|error| platform_error("stop tunnel for rebind", error))?;
            wait_until_stopped_until(&service, deadline)?;
            service
                .start(&[] as &[&str])
                .map_err(|error| platform_error("restart tunnel for rebind", error))?;
            wait_until_running_until(&service, deadline)
        }
    })();
    result.map_err(|_| nelomai_contracts::dispatcher::blocked())
}

pub(crate) fn installation_directory() -> Result<PathBuf, ServiceError> {
    let program_files = env::var_os("ProgramFiles").ok_or(ServiceError::UnsafePath)?;
    Ok(PathBuf::from(program_files)
        .join("Nelomai")
        .join("privileged"))
}

pub(crate) fn open_tunnel_service() -> Result<Option<Service>, ServiceError> {
    let manager = service_manager(ServiceManagerAccess::CONNECT)?;
    let mut active = None;
    for name in [TUNNEL_SERVICE_NAME, AMNEZIAWG_TUNNEL_SERVICE_NAME] {
        match manager.open_service(
            name,
            ServiceAccess::QUERY_STATUS
                | ServiceAccess::START
                | ServiceAccess::STOP
                | ServiceAccess::DELETE,
        ) {
            Ok(service) if active.is_none() => active = Some(service),
            Ok(_) => {
                return Err(ServiceError::Backend(
                    "multiple_tunnel_services_detected".to_string(),
                ));
            }
            Err(windows_service::Error::Winapi(error))
                if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) => {}
            Err(error) => return Err(platform_error("open tunnel service", error)),
        }
    }
    Ok(active)
}

pub(crate) fn remove_tunnel_service() -> Result<(), ServiceError> {
    let mut first_error = None;
    for name in [TUNNEL_SERVICE_NAME, AMNEZIAWG_TUNNEL_SERVICE_NAME] {
        if let Err(error) = remove_service(name) {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn create_service(manager: &ServiceManager, spec: &ServiceSpec) -> Result<Service, ServiceError> {
    let service_info = ServiceInfo {
        name: OsString::from(&spec.name),
        display_name: OsString::from(&spec.display_name),
        service_type: ServiceType::OWN_PROCESS,
        start_type: match spec.start_mode {
            ServiceStartMode::Automatic => ServiceStartType::AutoStart,
            ServiceStartMode::OnDemand => ServiceStartType::OnDemand,
        },
        error_control: ServiceErrorControl::Normal,
        executable_path: spec.executable_path.clone(),
        launch_arguments: spec.arguments.iter().map(OsString::from).collect(),
        dependencies: spec
            .dependencies
            .iter()
            .map(|dependency| ServiceDependency::Service(OsString::from(dependency)))
            .collect(),
        account_name: None,
        account_password: None,
    };
    manager
        .create_service(
            &service_info,
            ServiceAccess::QUERY_STATUS
                | ServiceAccess::START
                | ServiceAccess::STOP
                | ServiceAccess::DELETE
                | ServiceAccess::CHANGE_CONFIG,
        )
        .map_err(|error| platform_error("create Windows service", error))
}

fn remove_service(name: &str) -> Result<(), ServiceError> {
    let manager = service_manager(ServiceManagerAccess::CONNECT)?;
    let service = match manager.open_service(
        name,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        Ok(service) => service,
        Err(windows_service::Error::Winapi(error))
            if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) =>
        {
            return Ok(());
        }
        Err(error) => return Err(platform_error("open Windows service", error)),
    };

    let status = service
        .query_status()
        .map_err(|error| platform_error("query Windows service", error))?;
    if status.current_state != ServiceState::Stopped {
        let _ = service.stop();
        wait_until_stopped(&service)?;
    }
    if let Err(error) = service.delete() {
        match error {
            windows_service::Error::Winapi(ref source)
                if source.raw_os_error() == Some(ERROR_SERVICE_MARKED_FOR_DELETE as i32) => {}
            _ => return Err(platform_error("delete Windows service", error)),
        }
    }
    drop(service);

    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        match manager.open_service(name, ServiceAccess::QUERY_STATUS) {
            Err(windows_service::Error::Winapi(error))
                if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) =>
            {
                return Ok(());
            }
            Err(error) => return Err(platform_error("wait for Windows service deletion", error)),
            Ok(service) => drop(service),
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(ServiceError::Backend(
        "Windows service deletion did not finish within 15 seconds".to_string(),
    ))
}

pub(crate) fn wait_until_stopped(service: &Service) -> Result<(), ServiceError> {
    let deadline = Instant::now() + Duration::from_secs(15);
    wait_until_stopped_until(service, deadline)
}

pub(crate) fn wait_until_stopped_until(
    service: &Service,
    deadline: Instant,
) -> Result<(), ServiceError> {
    while Instant::now() < deadline {
        if service
            .query_status()
            .map_err(|error| platform_error("query stopping Windows service", error))?
            .current_state
            == ServiceState::Stopped
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(ServiceError::Backend(
        "Windows service did not stop before the deadline".to_string(),
    ))
}

pub(crate) fn wait_until_running(service: &Service) -> Result<(), ServiceError> {
    let deadline = Instant::now() + Duration::from_secs(15);
    wait_until_running_until(service, deadline)
}

pub(crate) fn wait_until_running_until(
    service: &Service,
    deadline: Instant,
) -> Result<(), ServiceError> {
    while Instant::now() < deadline {
        match service
            .query_status()
            .map_err(|error| platform_error("query starting Windows service", error))?
            .current_state
        {
            ServiceState::Running => return Ok(()),
            ServiceState::Stopped | ServiceState::StopPending => {
                return Err(ServiceError::Backend(
                    "WireGuard tunnel service stopped during startup".to_string(),
                ));
            }
            _ => thread::sleep(Duration::from_millis(100)),
        }
    }
    Err(ServiceError::Backend(
        "WireGuard tunnel service did not start before the deadline".to_string(),
    ))
}

fn service_manager(access: ServiceManagerAccess) -> Result<ServiceManager, ServiceError> {
    ServiceManager::local_computer(None::<&str>, access)
        .map_err(|error| platform_error("open Windows service manager", error))
}

pub(crate) fn state_directory() -> Result<PathBuf, ServiceError> {
    let program_data = env::var_os("ProgramData")
        .ok_or_else(|| ServiceError::Backend("ProgramData is unavailable".to_string()))?;
    Ok(PathBuf::from(program_data).join("Nelomai").join("Tunnel"))
}

pub(crate) fn validate_install_location(
    service_executable: &Path,
    installed_client_path: &Path,
) -> Result<PathBuf, ServiceError> {
    let program_files = env::var_os("ProgramFiles")
        .ok_or_else(|| ServiceError::Backend("ProgramFiles is unavailable".to_string()))?;
    let program_files = fs::canonicalize(program_files)
        .map_err(|error| platform_error("resolve Program Files", error))?;
    let service_executable = fs::canonicalize(service_executable)
        .map_err(|error| platform_error("resolve service executable", error))?;
    let installed_client_path = fs::canonicalize(installed_client_path)
        .map_err(|error| platform_error("resolve installed client", error))?;
    if !service_executable.starts_with(&program_files)
        || !installed_client_path.starts_with(&program_files)
        || service_executable.parent() != installed_client_path.parent()
    {
        return Err(ServiceError::UnauthorizedClient);
    }
    Ok(installed_client_path)
}

fn apply_private_acl(path: &Path) -> Result<(), ServiceError> {
    let sddl = wide(private_directory_security_descriptor());
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(platform_error(
            "create private directory security descriptor",
            std::io::Error::last_os_error(),
        ));
    }
    let path = wide(path.as_os_str());
    let result = unsafe {
        SetFileSecurityW(
            path.as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
    };
    unsafe {
        LocalFree(descriptor);
    }
    if result == 0 {
        Err(platform_error(
            "apply private directory ACL",
            std::io::Error::last_os_error(),
        ))
    } else {
        Ok(())
    }
}
