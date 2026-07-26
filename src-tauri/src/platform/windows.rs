use nelomai_windows_service::{windows::NamedPipeTransport, WindowsTunnelController};

pub type PlatformTunnelController = WindowsTunnelController<NamedPipeTransport>;

pub fn tunnel_controller() -> PlatformTunnelController {
    WindowsTunnelController::new(NamedPipeTransport::new())
}
