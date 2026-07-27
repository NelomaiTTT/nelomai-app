use async_trait::async_trait;
use nelomai_client_tunnel::{TunnelConfiguration, TunnelController, TunnelError, TunnelStatus};
use nelomai_unix_service::{
    authorize_peer, decode_request, encode_request, parse_configuration, ClientIdentity,
    ClientPolicy, Request, Response, ServiceError, ServiceTransport, ServiceTunnelBackend,
    ServiceTunnelState, TunnelRequestHandler, UnixTunnelController, MAX_FRAME_SIZE,
    PROTOCOL_VERSION,
};
use std::sync::Mutex;

const PRIVATE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const PUBLIC_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

fn valid_configuration() -> String {
    format!(
        "\
[Interface]
PrivateKey = {PRIVATE_KEY}
Address = 10.8.1.2/32, fd00::2/128
DNS = 8.8.8.8, 1.1.1.1
MTU = 1280

[Peer]
PublicKey = {PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.test:10001
PersistentKeepalive = 21
"
    )
}

#[test]
fn parser_accepts_panel_wireguard_configuration() {
    let parsed = parse_configuration(&valid_configuration()).expect("parse configuration");

    assert_eq!(parsed.addresses.len(), 2);
    assert_eq!(parsed.dns.len(), 2);
    assert_eq!(parsed.mtu, Some(1280));
    assert_eq!(parsed.peers.len(), 1);
    assert_eq!(parsed.peers[0].endpoint.host(), "vpn.example.test");
    assert_eq!(parsed.peers[0].endpoint.port(), 10001);
    assert_eq!(parsed.peers[0].persistent_keepalive, Some(21));
    assert_eq!(parsed.peers[0].allowed_ips.len(), 2);
}

#[test]
fn parser_rejects_shell_directives() {
    let configuration = valid_configuration().replace(
        "MTU = 1280",
        "MTU = 1280\nPostUp = touch /tmp/should-never-run",
    );

    let error = parse_configuration(&configuration).expect_err("reject PostUp");

    assert_eq!(error.code(), "unsafe_configuration_directive");
}

#[test]
fn configuration_debug_redacts_private_and_preshared_keys() {
    let configuration = valid_configuration().replace(
        "PublicKey =",
        &format!("PresharedKey = {PRIVATE_KEY}\nPublicKey ="),
    );
    let parsed = parse_configuration(&configuration).expect("parse configuration");
    let debug = format!("{parsed:?}");

    assert!(!debug.contains(PRIVATE_KEY));
    assert!(debug.contains("<redacted>"));
}

#[test]
fn protocol_rejects_unknown_commands_and_oversized_frames() {
    let unknown = br#"{"command":"run_shell","protocolVersion":1}"#;
    let mut frame = Vec::new();
    frame.extend_from_slice(&(unknown.len() as u32).to_le_bytes());
    frame.extend_from_slice(unknown);
    assert_eq!(
        decode_request(&frame).expect_err("reject unknown command"),
        ServiceError::InvalidRequest
    );

    let request = Request::start("x".repeat(MAX_FRAME_SIZE));
    assert_eq!(
        encode_request(&request).expect_err("reject oversized frame"),
        ServiceError::FrameTooLarge
    );
}

#[test]
fn peer_authorization_requires_the_installed_owner_uid() {
    let policy = ClientPolicy { owner_uid: 501 };

    authorize_peer(&policy, &ClientIdentity { uid: 501 }).expect("authorize owner");
    assert_eq!(
        authorize_peer(&policy, &ClientIdentity { uid: 502 }).expect_err("reject another user"),
        ServiceError::UnauthorizedClient
    );
}

#[derive(Default)]
struct RecordingBackend {
    starts: usize,
    stops: usize,
    state: ServiceTunnelState,
}

impl ServiceTunnelBackend for RecordingBackend {
    fn start(
        &mut self,
        configuration: &nelomai_unix_service::ParsedConfiguration,
    ) -> Result<ServiceTunnelState, ServiceError> {
        assert_eq!(configuration.peers.len(), 1);
        self.starts += 1;
        self.state = ServiceTunnelState::Running;
        Ok(self.state)
    }

    fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        self.stops += 1;
        self.state = ServiceTunnelState::Stopped;
        Ok(self.state)
    }

    fn status(&self) -> Result<ServiceTunnelState, ServiceError> {
        Ok(self.state)
    }
}

#[test]
fn handler_validates_protocol_and_configuration_before_mutation() {
    let backend = RecordingBackend::default();
    let mut handler = TunnelRequestHandler::new(backend, "1.2.3");

    let bad_protocol = handler.handle(Request::Status {
        protocol_version: PROTOCOL_VERSION + 1,
    });
    let bad_configuration = handler.handle(Request::start("[Interface]".to_string()));
    let started = handler.handle(Request::start(valid_configuration()));
    let stopped = handler.handle(Request::stop());
    let version = handler.handle(Request::version());

    assert_eq!(
        bad_protocol.error_code.as_deref(),
        Some("unsupported_protocol")
    );
    assert_eq!(
        bad_configuration.error_code.as_deref(),
        Some("invalid_configuration")
    );
    assert_eq!(started.state, Some(ServiceTunnelState::Running));
    assert_eq!(stopped.state, Some(ServiceTunnelState::Stopped));
    assert_eq!(version.service_version.as_deref(), Some("1.2.3"));
    assert_eq!(handler.backend().starts, 1);
    assert_eq!(handler.backend().stops, 1);
}

struct RecordingTransport {
    requests: Mutex<Vec<&'static str>>,
    response: Response,
}

#[async_trait]
impl ServiceTransport for RecordingTransport {
    async fn exchange(&self, request: Request) -> Result<Response, ServiceError> {
        let command = match request {
            Request::Start { .. } => "start",
            Request::Stop { .. } => "stop",
            Request::Status { .. } => "status",
            Request::Version { .. } => "version",
        };
        self.requests.lock().unwrap().push(command);
        Ok(self.response.clone())
    }
}

#[tokio::test]
async fn controller_maps_helper_responses_to_shared_tunnel_contract() {
    let controller = UnixTunnelController::new(RecordingTransport {
        requests: Mutex::new(Vec::new()),
        response: Response::success(Some(ServiceTunnelState::Running)),
    });

    controller
        .start(TunnelConfiguration::new(valid_configuration()))
        .await
        .expect("start tunnel");
    assert_eq!(
        controller.status().await.expect("read status"),
        TunnelStatus::Running
    );
    assert_eq!(
        controller.transport().requests.lock().unwrap().as_slice(),
        ["start", "status"]
    );
}

#[tokio::test]
async fn controller_reads_the_installed_helper_version() {
    let mut response = Response::success(None);
    response.service_version = Some("1.2.3".to_string());
    let controller = UnixTunnelController::new(RecordingTransport {
        requests: Mutex::new(Vec::new()),
        response,
    });

    assert_eq!(
        controller.service_version().await.expect("read version"),
        "1.2.3"
    );
    assert_eq!(
        controller.transport().requests.lock().unwrap().as_slice(),
        ["version"]
    );
}

#[tokio::test]
async fn controller_propagates_stable_helper_error_codes() {
    let controller = UnixTunnelController::new(RecordingTransport {
        requests: Mutex::new(Vec::new()),
        response: Response::failure("service_unavailable"),
    });

    let error = controller.stop().await.expect_err("reject failed response");

    assert!(matches!(
        error,
        TunnelError::Backend(message) if message == "service_unavailable"
    ));
}
