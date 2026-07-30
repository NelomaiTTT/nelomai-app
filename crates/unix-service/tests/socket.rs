use nelomai_unix_service::{
    bind_listener, serve_one, ClientPolicy, ServiceError, ServiceTunnelBackend, ServiceTunnelState,
    TunnelRequestHandler, UnixSocketTransport,
};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use tempfile::tempdir;

#[derive(Default)]
struct MemoryBackend {
    state: ServiceTunnelState,
}

impl ServiceTunnelBackend for MemoryBackend {
    fn start(
        &mut self,
        _configuration: &nelomai_unix_service::ParsedConfiguration,
        _options: &nelomai_client_tunnel::DesktopTunnelOptions,
    ) -> Result<ServiceTunnelState, ServiceError> {
        self.state = ServiceTunnelState::Running;
        Ok(self.state)
    }

    fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        self.state = ServiceTunnelState::Stopped;
        Ok(self.state)
    }

    fn status(&self) -> Result<ServiceTunnelState, ServiceError> {
        Ok(self.state)
    }
}

#[tokio::test]
async fn unix_socket_round_trip_is_owner_only_and_bounded() {
    let directory = tempdir().expect("create temporary directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("protect temporary directory");
    let socket_path = directory.path().join("tunnel.sock");
    let uid = unsafe { libc::geteuid() };
    let listener = bind_listener(&socket_path, uid).expect("bind helper socket");
    let metadata = fs::metadata(&socket_path).expect("read socket metadata");

    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.uid(), uid);

    let server = std::thread::spawn(move || {
        let policy = ClientPolicy { owner_uid: uid };
        let mut handler = TunnelRequestHandler::new(MemoryBackend::default(), "test");
        serve_one(&listener, &policy, &mut handler).expect("serve request");
    });

    let transport = UnixSocketTransport::new(socket_path);
    let response = nelomai_unix_service::ServiceTransport::exchange(
        &transport,
        nelomai_unix_service::Request::status(),
    )
    .await
    .expect("exchange request");

    assert_eq!(response.state, Some(ServiceTunnelState::Stopped));
    server.join().expect("join helper thread");
}
