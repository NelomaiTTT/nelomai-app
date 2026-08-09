use async_trait::async_trait;
use nelomai_client_tunnel::{
    TunnelConfiguration, TunnelController, TunnelError, TunnelMetrics, TunnelStartRequest,
    TunnelStatus, TunnelTransport,
};
use nelomai_unix_service::{
    authorize_peer, decode_request, decode_response, encode_request, parse_configuration,
    ClientIdentity, ClientPolicy, Request, Response, ServiceError, ServiceTransport,
    ServiceTunnelBackend, ServiceTunnelState, TunnelRequestHandler, UnixTunnelController,
    MAX_FRAME_SIZE, PROTOCOL_VERSION,
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
    assert_eq!(parsed.transport, TunnelTransport::WireGuard);
    assert!(parsed.awg3.is_none());
}

#[test]
fn parser_accepts_and_redacts_panel_awg3_configuration() {
    let header_key = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
    let configuration = valid_configuration().replace(
        "MTU = 1280",
        &format!(
            "MTU = 1280\nJc = 5\nJmin = 64\nJmax = 96\nS1 = 16\nS2 = 24\nS3 = 32\nS4 = 40\nH1 = 100-200\nH2 = 201\nH3 = 202\nH4 = 203\nI1 = <r 32>\nHeaderProtectionKey = {header_key}\nContentPaddingAddition = 0-64"
        ),
    );

    let parsed = parse_configuration(&configuration).expect("parse AWG3 configuration");
    assert_eq!(parsed.transport, TunnelTransport::AmneziaWg3);
    assert!(parsed.awg3.is_some());
    let debug = format!("{parsed:?}");
    assert!(!debug.contains(header_key));
    assert!(!debug.contains("<r 32>"));
    assert!(debug.contains("header_protection_key"));
}

#[test]
fn parser_rejects_partial_or_invalid_awg3_configuration() {
    let partial = valid_configuration().replace("MTU = 1280", "MTU = 1280\nJc = 5");
    assert_eq!(
        parse_configuration(&partial).expect_err("reject partial AWG3"),
        nelomai_unix_service::ConfigurationError::MissingField
    );

    let reversed_range = valid_configuration().replace(
        "MTU = 1280",
        "MTU = 1280\nHeaderProtectionKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nContentPaddingAddition = 64-0",
    );
    assert_eq!(
        parse_configuration(&reversed_range).expect_err("reject invalid AWG3 range"),
        nelomai_unix_service::ConfigurationError::InvalidValue
    );
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
fn old_start_request_decodes_for_an_explicit_protocol_rejection() {
    let payload =
        br#"{"command":"start","protocolVersion":2,"configuration":"PrivateKey = redacted"}"#;
    let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(payload);

    let request = decode_request(&frame).expect("decode previous protocol request");

    assert_eq!(request.protocol_version(), 2);
}

#[test]
fn previous_helper_response_decodes_without_a_fingerprint_field() {
    let payload = br#"{"protocolVersion":2,"ok":true,"state":"running","serviceVersion":"0.1.6","errorCode":null}"#;
    let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(payload);

    let response = decode_response(&frame).expect("decode previous helper response");

    assert_eq!(response.protocol_version, 2);
    assert_eq!(response.physical_network_fingerprint, None);
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
        _options: &nelomai_client_tunnel::DesktopTunnelOptions,
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

    fn physical_network_fingerprint(&self) -> Result<String, ServiceError> {
        Ok("ab".repeat(32))
    }

    fn metrics(&self, probe: bool) -> Result<TunnelMetrics, ServiceError> {
        Ok(TunnelMetrics {
            received_bytes: 120,
            sent_bytes: 45,
            probe_target: probe.then(|| "192.0.2.10".to_string()),
        })
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
    let fingerprint = handler.handle(Request::physical_network_fingerprint());
    let metrics = handler.handle(Request::metrics(true));

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
    assert_eq!(
        fingerprint.physical_network_fingerprint.as_deref(),
        Some("abababababababababababababababababababababababababababababababab")
    );
    assert_eq!(handler.backend().starts, 1);
    assert_eq!(handler.backend().stops, 1);
    assert_eq!(
        metrics.metrics,
        Some(TunnelMetrics {
            received_bytes: 120,
            sent_bytes: 45,
            probe_target: Some("192.0.2.10".to_string()),
        })
    );
}

#[tokio::test]
async fn controller_maps_helper_metrics_without_exposing_configuration() {
    let mut response = Response::success(None);
    response.metrics = Some(TunnelMetrics {
        received_bytes: 512,
        sent_bytes: 128,
        probe_target: Some("192.0.2.23".to_string()),
    });
    let controller = UnixTunnelController::new(RecordingTransport {
        requests: Mutex::new(Vec::new()),
        response,
    });

    assert_eq!(
        controller.metrics(true).await.unwrap(),
        Some(TunnelMetrics {
            received_bytes: 512,
            sent_bytes: 128,
            probe_target: Some("192.0.2.23".to_string()),
        })
    );
    assert_eq!(
        controller.transport().requests.lock().unwrap().as_slice(),
        ["metrics"]
    );
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
            Request::PhysicalNetworkFingerprint { .. } => "fingerprint",
            Request::Metrics { .. } => "metrics",
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
        .start(TunnelStartRequest::full_tunnel(TunnelConfiguration::new(
            valid_configuration(),
        )))
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
async fn controller_reads_only_the_opaque_physical_network_fingerprint() {
    let mut response = Response::success(None);
    response.physical_network_fingerprint = Some("cd".repeat(32));
    let controller = UnixTunnelController::new(RecordingTransport {
        requests: Mutex::new(Vec::new()),
        response,
    });

    let fingerprint = controller
        .physical_network_fingerprint()
        .await
        .expect("read fingerprint");
    assert_eq!(fingerprint, Some("cd".repeat(32)));
    assert_eq!(
        controller.transport().requests.lock().unwrap().as_slice(),
        ["fingerprint"]
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
