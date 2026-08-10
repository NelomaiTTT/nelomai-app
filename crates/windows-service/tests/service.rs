use async_trait::async_trait;
use nelomai_client_tunnel::{
    DesktopTunnelOptions, TunnelConfiguration, TunnelController, TunnelError, TunnelMetrics,
    TunnelStartRequest, TunnelStatus, TunnelTransport,
};
use nelomai_windows_service::{
    Request, Response, ServiceError, ServiceTransport, ServiceTunnelBackend, ServiceTunnelState,
    TunnelRequestHandler, WindowsTunnelController, PROTOCOL_VERSION,
};
use std::sync::Mutex;

#[derive(Default)]
struct RecordingBackend {
    starts: Vec<String>,
    transports: Vec<TunnelTransport>,
    stops: usize,
    state: ServiceTunnelState,
}

impl ServiceTunnelBackend for RecordingBackend {
    fn start(
        &mut self,
        configuration: &str,
        _options: &nelomai_client_tunnel::DesktopTunnelOptions,
        transport: TunnelTransport,
    ) -> Result<ServiceTunnelState, ServiceError> {
        self.starts.push(configuration.to_string());
        self.transports.push(transport);
        self.state = ServiceTunnelState::Running;
        Ok(self.state)
    }

    fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        self.stops += 1;
        self.state = ServiceTunnelState::Stopped;
        Ok(self.state)
    }

    fn status(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        Ok(self.state)
    }

    fn physical_network_fingerprint(&self) -> Result<String, ServiceError> {
        Ok("ab".repeat(32))
    }

    fn metrics(&mut self, probe: bool) -> Result<TunnelMetrics, ServiceError> {
        Ok(TunnelMetrics {
            received_bytes: 120,
            sent_bytes: 45,
            latest_handshake_epoch_millis: None,
            probe_target: probe.then(|| "192.0.2.10".to_string()),
        })
    }

    fn diagnostics(&mut self) -> Result<String, ServiceError> {
        Ok("[amneziawg.ringlogger]\n[TUN] handshake".to_string())
    }
}

#[test]
fn handler_rejects_unknown_protocol_before_backend_mutation() {
    let backend = RecordingBackend::default();
    let mut handler = TunnelRequestHandler::new(backend, "1.2.3");
    let request = Request::Status {
        protocol_version: PROTOCOL_VERSION + 1,
    };

    let response = handler.handle(request);

    assert_eq!(response.error_code.as_deref(), Some("unsupported_protocol"));
    assert!(handler.backend().starts.is_empty());
    assert_eq!(handler.backend().stops, 0);
}

#[test]
fn handler_executes_only_typed_tunnel_operations() {
    let backend = RecordingBackend::default();
    let mut handler = TunnelRequestHandler::new(backend, "1.2.3");

    let started = handler.handle(Request::start("PrivateKey = transient".to_string()));
    let status = handler.handle(Request::status());
    let stopped = handler.handle(Request::stop());
    let version = handler.handle(Request::version());
    let fingerprint = handler.handle(Request::physical_network_fingerprint());
    let metrics = handler.handle(Request::metrics(true));
    let diagnostics = handler.handle(Request::diagnostics());

    assert_eq!(started.state, Some(ServiceTunnelState::Running));
    assert_eq!(status.state, Some(ServiceTunnelState::Running));
    assert_eq!(stopped.state, Some(ServiceTunnelState::Stopped));
    assert_eq!(version.service_version.as_deref(), Some("1.2.3"));
    assert_eq!(
        fingerprint.physical_network_fingerprint.as_deref(),
        Some("abababababababababababababababababababababababababababababababab")
    );
    assert_eq!(handler.backend().starts, vec!["PrivateKey = transient"]);
    assert_eq!(handler.backend().transports, [TunnelTransport::WireGuard]);
    assert_eq!(handler.backend().stops, 1);
    assert_eq!(
        metrics.metrics,
        Some(TunnelMetrics {
            received_bytes: 120,
            sent_bytes: 45,
            latest_handshake_epoch_millis: None,
            probe_target: Some("192.0.2.10".to_string()),
        })
    );
    assert_eq!(
        diagnostics.diagnostics.as_deref(),
        Some("[amneziawg.ringlogger]\n[TUN] handshake")
    );
}

#[tokio::test]
async fn controller_maps_service_metrics_without_exposing_configuration() {
    let mut response = Response::success(None);
    response.metrics = Some(TunnelMetrics {
        received_bytes: 512,
        sent_bytes: 128,
        latest_handshake_epoch_millis: None,
        probe_target: Some("192.0.2.23".to_string()),
    });
    let controller = WindowsTunnelController::new(RecordingTransport {
        requests: Mutex::new(Vec::new()),
        response,
    });

    assert_eq!(
        controller.metrics(true).await.unwrap(),
        Some(TunnelMetrics {
            received_bytes: 512,
            sent_bytes: 128,
            latest_handshake_epoch_millis: None,
            probe_target: Some("192.0.2.23".to_string()),
        })
    );
    assert_eq!(
        controller.transport().requests.lock().unwrap().as_slice(),
        ["metrics"]
    );
}

#[test]
fn handler_avoids_windows_firewall_blocking_mode_for_address_split() {
    let backend = RecordingBackend::default();
    let mut handler = TunnelRequestHandler::new(backend, "1.2.3");
    let configuration = "\
[Interface]\r
PrivateKey = transient\r
\r
[Peer]\r
PublicKey = peer\r
AllowedIPs = 0.0.0.0/0, ::/0\r
";

    let response = handler.handle(Request::start_with_options(
        configuration.to_string(),
        DesktopTunnelOptions {
            excluded_ipv4_cidrs: vec!["203.0.113.0/24".to_string()],
            exclude_local_networks: true,
            policy_hash: Some("sha256:test".to_string()),
        },
    ));

    assert!(response.ok);
    assert_eq!(
        handler.backend().starts,
        vec![
            "\
[Interface]\r
PrivateKey = transient\r
\r
[Peer]\r
PublicKey = peer\r
AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1\r
"
        ]
    );
}

#[test]
fn handler_preserves_full_range_allowed_ips_without_address_split() {
    let backend = RecordingBackend::default();
    let mut handler = TunnelRequestHandler::new(backend, "1.2.3");
    let configuration = "\
[Interface]
PrivateKey = transient

[Peer]
AllowedIPs = 0.0.0.0/0, ::/0
";

    let response = handler.handle(Request::start(configuration.to_string()));

    assert!(response.ok);
    assert_eq!(handler.backend().starts, vec![configuration]);
}

#[test]
fn handler_selects_amneziawg_only_for_complete_awg3_markers() {
    let backend = RecordingBackend::default();
    let mut handler = TunnelRequestHandler::new(backend, "1.2.3");
    let configuration = "\
[Interface]
PrivateKey = transient
HeaderProtectionKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
ContentPaddingAddition = 0-64

[Peer]
AllowedIPs = 0.0.0.0/0
";

    let response = handler.handle(Request::start(configuration.to_string()));

    assert!(response.ok);
    assert_eq!(handler.backend().transports, [TunnelTransport::AmneziaWg3]);
    assert!(handler.backend().starts[0].contains("AllowedIPs = 0.0.0.0/1, 128.0.0.0/1"));
}

struct RecordingTransport {
    requests: Mutex<Vec<String>>,
    response: Response,
}

impl RecordingTransport {
    fn running() -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            response: Response::success(Some(ServiceTunnelState::Running)),
        }
    }
}

#[async_trait]
impl ServiceTransport for RecordingTransport {
    async fn exchange(&self, request: Request) -> Result<Response, ServiceError> {
        let summary = match request {
            Request::Start { configuration, .. } => {
                assert_eq!(configuration.as_str(), "PrivateKey = client-only");
                "start"
            }
            Request::Stop { .. } => "stop",
            Request::Status { .. } => "status",
            Request::Version { .. } => "version",
            Request::PhysicalNetworkFingerprint { .. } => "fingerprint",
            Request::Metrics { .. } => "metrics",
            Request::Diagnostics { .. } => "diagnostics",
        };
        self.requests.lock().unwrap().push(summary.to_string());
        Ok(self.response.clone())
    }
}

#[tokio::test]
async fn controller_maps_service_response_to_shared_tunnel_contract() {
    let controller = WindowsTunnelController::new(RecordingTransport::running());

    controller
        .start(TunnelStartRequest::full_tunnel(TunnelConfiguration::new(
            "PrivateKey = client-only".to_string(),
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
async fn controller_reads_installed_service_version() {
    let mut response = Response::success(None);
    response.service_version = Some("1.2.3".to_string());
    let controller = WindowsTunnelController::new(RecordingTransport {
        requests: Mutex::new(Vec::new()),
        response,
    });

    assert_eq!(
        controller
            .service_version()
            .await
            .expect("read service version"),
        "1.2.3"
    );
    assert_eq!(
        controller.transport().requests.lock().unwrap().as_slice(),
        ["version"]
    );
}

#[tokio::test]
async fn controller_reads_bounded_service_diagnostics() {
    let mut response = Response::success(None);
    response.diagnostics = Some("[amneziawg.ringlogger]\n[TUN] handshake".to_string());
    let controller = WindowsTunnelController::new(RecordingTransport {
        requests: Mutex::new(Vec::new()),
        response,
    });

    assert_eq!(
        controller.diagnostics().await.expect("read diagnostics"),
        "[amneziawg.ringlogger]\n[TUN] handshake"
    );
    assert_eq!(
        controller.transport().requests.lock().unwrap().as_slice(),
        ["diagnostics"]
    );
}

#[tokio::test]
async fn controller_reads_only_the_opaque_physical_network_fingerprint() {
    let mut response = Response::success(None);
    response.physical_network_fingerprint = Some("cd".repeat(32));
    let controller = WindowsTunnelController::new(RecordingTransport {
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
async fn controller_rejects_failed_service_response() {
    let transport = RecordingTransport {
        requests: Mutex::new(Vec::new()),
        response: Response::failure("service_unavailable"),
    };
    let controller = WindowsTunnelController::new(transport);

    let error = controller.stop().await.unwrap_err();

    assert!(matches!(
        error,
        TunnelError::Backend(message) if message == "service_unavailable"
    ));
}
