use nelomai_unix_service::{UnixSocketTransport, UnixTunnelController, DEFAULT_SOCKET_PATH};

pub type PlatformTunnelController = UnixTunnelController<UnixSocketTransport>;

pub fn tunnel_controller() -> PlatformTunnelController {
    UnixTunnelController::new(UnixSocketTransport::new(DEFAULT_SOCKET_PATH))
}
