#[cfg(windows)]
fn main() {
    if let Err(error) = windows_main() {
        eprintln!("Nelomai Windows service failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn windows_main() -> Result<(), nelomai_windows_service::ServiceError> {
    use nelomai_windows_service::windows::{
        configure_exclusion, install, run_amneziawg_service, run_engine_mode, run_manager_service,
        run_wireguard_service, uninstall, InstallOptions,
    };
    use nelomai_windows_service::ServiceError;
    use std::path::PathBuf;

    let mut arguments = std::env::args_os().skip(1);
    match arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .as_deref()
    {
        Some("--manager-service") if arguments.next().is_none() => run_manager_service(),
        Some("--engine-mode") => {
            let root = arguments
                .next()
                .map(PathBuf::from)
                .ok_or(ServiceError::InvalidRequest)?;
            if arguments.next().is_some() {
                return Err(ServiceError::InvalidRequest);
            }
            run_engine_mode(&root)
        }
        Some("--wireguard-service") => {
            let path = arguments
                .next()
                .map(PathBuf::from)
                .ok_or(ServiceError::InvalidRequest)?;
            if arguments.next().is_some() {
                return Err(ServiceError::InvalidRequest);
            }
            run_wireguard_service(&path)
        }
        Some("--amneziawg-service") => {
            let path = arguments
                .next()
                .map(PathBuf::from)
                .ok_or(ServiceError::InvalidRequest)?;
            if arguments.next().is_some() {
                return Err(ServiceError::InvalidRequest);
            }
            run_amneziawg_service(&path)
        }
        Some("--amneziawg-slot-service") => {
            use nelomai_contracts::dispatcher::TunnelSlot;
            let path = arguments
                .next()
                .map(PathBuf::from)
                .ok_or(ServiceError::InvalidRequest)?;
            let slot = match arguments
                .next()
                .and_then(|s| s.into_string().ok())
                .as_deref()
            {
                Some("a") => TunnelSlot::A,
                Some("b") => TunnelSlot::B,
                _ => return Err(ServiceError::InvalidRequest),
            };
            if arguments.next().is_some() {
                return Err(ServiceError::InvalidRequest);
            }
            nelomai_windows_service::windows::run_amneziawg_slot_service(&path, slot)
        }
        Some("install") => {
            let mut owner_sid = None;
            let mut client_path = None;
            while let Some(argument) = arguments.next() {
                match argument.to_string_lossy().as_ref() {
                    "--owner-sid" => {
                        owner_sid = arguments.next().and_then(|value| value.into_string().ok())
                    }
                    "--client-path" => client_path = arguments.next().map(PathBuf::from),
                    _ => return Err(ServiceError::InvalidRequest),
                }
            }
            install(InstallOptions {
                owner_sid: owner_sid.ok_or(ServiceError::InvalidRequest)?,
                installed_client_path: client_path.ok_or(ServiceError::InvalidRequest)?,
            })
        }
        Some("configure-defender-exclusion") => {
            let client_path = match arguments.next() {
                Some(option) if option.to_string_lossy() == "--client-path" => {
                    arguments.next().map(PathBuf::from)
                }
                _ => None,
            }
            .ok_or(ServiceError::InvalidRequest)?;
            if arguments.next().is_some() {
                return Err(ServiceError::InvalidRequest);
            }
            configure_exclusion(&client_path)
        }
        Some("uninstall") if arguments.next().is_none() => uninstall(),
        _ => Err(ServiceError::InvalidRequest),
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("nelomai-windows-service is only available on Windows");
    std::process::exit(1);
}
