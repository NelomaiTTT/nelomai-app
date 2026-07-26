use nelomai_windows_service::{
    manager_service_spec, pipe_security_descriptor, private_directory_security_descriptor,
    tunnel_service_spec, ServiceStartMode, MANAGER_SERVICE_NAME, TUNNEL_SERVICE_NAME,
};
use std::path::Path;

#[test]
fn manager_service_runs_as_system_on_boot() {
    let spec = manager_service_spec(Path::new(
        r"C:\Program Files\Nelomai\nelomai-windows-service.exe",
    ))
    .expect("manager service spec");

    assert_eq!(spec.name, MANAGER_SERVICE_NAME);
    assert_eq!(spec.start_mode, ServiceStartMode::Automatic);
    assert!(spec.run_as_local_system);
    assert_eq!(spec.arguments, ["--manager-service"]);
    assert!(spec.dependencies.is_empty());
}

#[test]
fn tunnel_service_matches_official_wireguard_requirements() {
    let spec = tunnel_service_spec(
        Path::new(r"C:\Program Files\Nelomai\nelomai-windows-service.exe"),
        Path::new(r"C:\ProgramData\Nelomai\tunnel\nelomai.conf"),
    )
    .expect("tunnel service spec");

    assert_eq!(spec.name, TUNNEL_SERVICE_NAME);
    assert_eq!(spec.start_mode, ServiceStartMode::Automatic);
    assert_eq!(spec.dependencies, ["Nsi", "TcpIp"]);
    assert!(spec.run_as_local_system);
    assert!(spec.unrestricted_service_sid);
    assert_eq!(
        spec.arguments,
        [
            "--wireguard-service",
            r"C:\ProgramData\Nelomai\tunnel\nelomai.conf"
        ]
    );
}

#[test]
fn security_descriptors_expose_no_config_to_the_desktop_user() {
    assert_eq!(
        private_directory_security_descriptor(),
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    );
    assert_eq!(
        pipe_security_descriptor("S-1-5-21-1000").unwrap(),
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;S-1-5-21-1000)"
    );
}

#[test]
fn pipe_descriptor_rejects_sddl_injection() {
    assert!(pipe_security_descriptor("S-1-5-21-1000)(A;;GA;;;WD").is_err());
    assert!(pipe_security_descriptor("not-a-sid").is_err());
}
