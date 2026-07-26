use async_trait::async_trait;
use nelomai_client_tunnel::{TunnelConfiguration, TunnelController, TunnelError, TunnelStatus};
use nelomai_windows_service::{
    Request, Response, ServiceError, ServiceTransport, ServiceTunnelBackend, ServiceTunnelState,
    TunnelRequestHandler, WindowsTunnelController, PROTOCOL_VERSION,
};
use std::sync::Mutex;

#[derive(Default)]
struct RecordingBackend {
    starts: Vec<String>,
    stops: usize,
    state: ServiceTunnelState,
}

impl ServiceTunnelBackend for RecordingBackend {
    fn start(&mut self, configuration: &str) -> Result<ServiceTunnelState, ServiceError> {
        self.starts.push(configuration.to_string());
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

    assert_eq!(started.state, Some(ServiceTunnelState::Running));
    assert_eq!(status.state, Some(ServiceTunnelState::Running));
    assert_eq!(stopped.state, Some(ServiceTunnelState::Stopped));
    assert_eq!(version.service_version.as_deref(), Some("1.2.3"));
    assert_eq!(handler.backend().starts, vec!["PrivateKey = transient"]);
    assert_eq!(handler.backend().stops, 1);
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
        };
        self.requests.lock().unwrap().push(summary.to_string());
        Ok(self.response.clone())
    }
}

#[tokio::test]
async fn controller_maps_service_response_to_shared_tunnel_contract() {
    let controller = WindowsTunnelController::new(RecordingTransport::running());

    controller
        .start(TunnelConfiguration::new(
            "PrivateKey = client-only".to_string(),
        ))
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
