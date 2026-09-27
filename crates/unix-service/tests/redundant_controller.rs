use async_trait::async_trait;
use nelomai_client_tunnel::{
    redundancy::{
        protocol::{Command, Snapshot},
        session::SessionState,
        SessionScope, Slot,
    },
    DesktopTunnelOptions, TunnelController, TunnelError, TunnelStartRequest, TunnelStatus,
};
use nelomai_contracts::RuntimeSlot;
use nelomai_unix_service::{
    ParsedConfiguration, Request, Response, ServiceError, ServiceTransport, ServiceTunnelBackend,
    ServiceTunnelState, TunnelRequestHandler, UnixTunnelController, PROTOCOL_VERSION,
};
use std::{collections::VecDeque, sync::Mutex};

fn scope() -> SessionScope {
    SessionScope {
        runtime: RuntimeSlot::Latest,
        runtime_generation: 10,
        session_id: "11111111-1111-4111-8111-111111111111".into(),
        connection_generation: 3,
    }
}
fn snapshot() -> Snapshot {
    Snapshot {
        session: SessionState::new(scope(), Slot::A, 1, 1)
            .unwrap()
            .snapshot(),
        leases: [None, None],
        current_leases: [None, None],
        primary_ready: false,
        standby_ready: false,
        standby_failed: false,
        stalled: false,
        cleanup_pending: false,
        warm_stop_v1: false,
    }
}
fn response(snapshot: Option<Snapshot>) -> Response {
    let mut result = Response::success(Some(ServiceTunnelState::Stopped));
    result.redundancy = snapshot;
    result
}
struct Transport {
    responses: Mutex<VecDeque<Response>>,
    requests: Mutex<Vec<Request>>,
}
#[async_trait]
impl ServiceTransport for Transport {
    async fn exchange(&self, request: Request) -> Result<Response, ServiceError> {
        self.requests.lock().unwrap().push(request);
        Ok(self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected extra/fallback request"))
    }
}
fn controller(responses: impl IntoIterator<Item = Response>) -> UnixTunnelController<Transport> {
    UnixTunnelController::new(Transport {
        responses: Mutex::new(responses.into_iter().collect()),
        requests: Mutex::new(vec![]),
    })
}
struct LegacyController;
#[async_trait]
impl TunnelController for LegacyController {
    async fn start(&self, _: TunnelStartRequest) -> Result<(), TunnelError> {
        panic!("ordinary fallback")
    }
    async fn stop(&self) -> Result<(), TunnelError> {
        panic!("ordinary fallback")
    }
    async fn status(&self) -> Result<TunnelStatus, TunnelError> {
        panic!("ordinary fallback")
    }
}

#[tokio::test]
async fn trait_defaults_are_unsupported_without_any_ordinary_fallback() {
    assert!(!LegacyController.desktop_redundancy_absent().await.unwrap());
    assert!(!LegacyController
        .desktop_redundancy_supported()
        .await
        .unwrap());
    assert!(LegacyController
        .desktop_redundancy_command(Command::Status { scope: scope() })
        .await
        .is_err());
}

#[tokio::test]
async fn desktop_absence_requires_one_stopped_status_without_any_pair() {
    for state in [
        ServiceTunnelState::Stopped,
        ServiceTunnelState::Starting,
        ServiceTunnelState::Running,
        ServiceTunnelState::Stopping,
        ServiceTunnelState::Failed,
    ] {
        for present in [false, true] {
            let mut reply = Response::success(Some(state));
            if present {
                let mut foreign = snapshot();
                foreign.session.scope.connection_generation += 1;
                reply.redundancy = Some(foreign);
            }
            let controller = controller([reply]);
            assert_eq!(
                controller.desktop_redundancy_absent().await.unwrap(),
                state == ServiceTunnelState::Stopped && !present
            );
            assert!(matches!(
                controller.transport().requests.lock().unwrap().as_slice(),
                [Request::Status { .. }]
            ));
        }
    }
    let mut wrong_version = response(None);
    wrong_version.protocol_version += 1;
    for reply in [
        Response::success(None),
        Response::failure("denied"),
        wrong_version,
    ] {
        let controller = controller([reply]);
        assert!(controller.desktop_redundancy_absent().await.is_err());
        assert!(matches!(
            controller.transport().requests.lock().unwrap().as_slice(),
            [Request::Status { .. }]
        ));
    }
}

#[tokio::test]
async fn desktop_absence_transport_error_is_not_absence() {
    struct FailedTransport;
    #[async_trait]
    impl ServiceTransport for FailedTransport {
        async fn exchange(&self, request: Request) -> Result<Response, ServiceError> {
            assert!(matches!(request, Request::Status { .. }));
            Err(ServiceError::InvalidRequest)
        }
    }
    assert!(UnixTunnelController::new(FailedTransport)
        .desktop_redundancy_absent()
        .await
        .is_err());
}

#[tokio::test]
async fn old_response_defaults_false_and_new_capability_is_version_only() {
    let old:Response=serde_json::from_value(serde_json::json!({"protocolVersion":PROTOCOL_VERSION,"ok":true,"state":null,"serviceVersion":"old","errorCode":null})).unwrap();
    assert!(!old.desktop_redundancy_v1);
    assert!(serde_json::to_value(&old)
        .unwrap()
        .get("desktopRedundancyV1")
        .is_none());
    let mut supported = Response::success(None);
    supported.desktop_redundancy_v1 = true;
    let controller = controller([old, supported]);
    assert!(!controller.desktop_redundancy_supported().await.unwrap());
    assert!(controller.desktop_redundancy_supported().await.unwrap());
    assert!(controller
        .transport()
        .requests
        .lock()
        .unwrap()
        .iter()
        .all(|r| matches!(r, Request::Version { .. })));
    assert!(!controller.owns_redundant_session().await.unwrap());
}

#[tokio::test]
async fn private_roundtrip_validates_exact_scope_and_rejects_bad_responses_without_fallback() {
    let expected = snapshot();
    let controller = controller([response(Some(expected.clone()))]);
    assert_eq!(
        controller
            .desktop_redundancy_command(Command::Status { scope: scope() })
            .await
            .unwrap(),
        expected
    );
    assert!(
        matches!(&controller.transport().requests.lock().unwrap()[0],Request::Redundant{request:Command::Status{scope:s},..} if s==&scope())
    );
    let mut wrong = snapshot();
    wrong.session.scope.connection_generation += 1;
    let mut bad_protocol = response(Some(snapshot()));
    bad_protocol.protocol_version += 1;
    for reply in [
        response(Some(wrong)),
        response(None),
        Response::failure("scoped_stop_failed"),
        bad_protocol,
    ] {
        let controller = self::controller([reply]);
        assert!(controller
            .desktop_redundancy_command(Command::Stop { scope: scope() })
            .await
            .is_err());
        assert_eq!(controller.transport().requests.lock().unwrap().len(), 1);
    }
    let controller = self::controller([]);
    let mut bad = scope();
    bad.runtime_generation = 0;
    assert!(controller
        .desktop_redundancy_command(Command::Status { scope: bad })
        .await
        .is_err());
    assert!(controller.transport().requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn capability_rejects_failed_or_wrong_protocol_response() {
    let mut bad = Response::success(None);
    bad.desktop_redundancy_v1 = true;
    bad.protocol_version += 1;
    for reply in [Response::failure("unavailable"), bad] {
        let controller = controller([reply]);
        assert!(controller.desktop_redundancy_supported().await.is_err());
    }
}

#[tokio::test]
async fn generic_stop_uses_fresh_helper_scope_and_never_ordinary_stop() {
    let mut stopped = snapshot();
    stopped.session.phase = nelomai_client_tunnel::redundancy::session::SessionPhase::Stopped;
    let controller = controller([response(Some(snapshot())), response(Some(stopped))]);
    controller.stop().await.unwrap();
    let requests = controller.transport().requests.lock().unwrap();
    assert!(matches!(requests[0], Request::Status { .. }));
    assert!(
        matches!(&requests[1],Request::Redundant{request:Command::Stop{scope:s},..} if s==&scope())
    );
    assert_eq!(requests.len(), 2);
}

#[tokio::test]
async fn legacy_cleanup_stop_never_acquires_authority_over_current_pair() {
    let controller = controller([Response::failure("redundancy_session_owned")]);
    assert!(controller.stop_if_unowned().await.is_err());
    assert!(matches!(
        controller.transport().requests.lock().unwrap().as_slice(),
        [Request::Stop { .. }]
    ));
}

#[tokio::test]
async fn generic_rebind_uses_fresh_scoped_network_change_and_retains_legacy_path() {
    let mut running = snapshot();
    running.session.phase = nelomai_client_tunnel::redundancy::session::SessionPhase::Running;
    let controller = controller([response(Some(running.clone())), response(Some(running))]);
    assert!(controller.rebind_udp().await.unwrap());
    {
        let requests = controller.transport().requests.lock().unwrap();
        assert!(matches!(requests[0], Request::Status { .. }));
        assert!(
            matches!(&requests[1],Request::Redundant{request:Command::NetworkChanged{scope:s},..} if s==&scope())
        );
    }
    let legacy = self::controller([
        response(None),
        Response::success(Some(ServiceTunnelState::Running)),
    ]);
    assert!(legacy.rebind_udp().await.unwrap());
    let requests = legacy.transport().requests.lock().unwrap();
    assert!(matches!(
        requests.as_slice(),
        [Request::Status { .. }, Request::RebindUdp { .. }]
    ));
}

#[tokio::test]
async fn legacy_stop_remains_ordinary_but_failed_status_never_authorizes_fallback() {
    let controller = controller([response(None), response(None)]);
    controller.stop().await.unwrap();
    assert!(matches!(
        controller.transport().requests.lock().unwrap().as_slice(),
        [Request::Status { .. }, Request::Stop { .. }]
    ));
    for rebind in [false, true] {
        let controller = self::controller([Response::failure("status_denied")]);
        assert!(if rebind {
            controller.rebind_udp().await.map(|_| ())
        } else {
            controller.stop().await
        }
        .is_err());
        assert!(matches!(
            controller.transport().requests.lock().unwrap().as_slice(),
            [Request::Status { .. }]
        ));
    }
}

#[tokio::test]
async fn stale_scoped_stop_reply_or_cleanup_pending_is_not_success_or_fallback() {
    let mut wrong = snapshot();
    wrong.session.scope.connection_generation += 1;
    let mut pending = snapshot();
    pending.session.phase = nelomai_client_tunnel::redundancy::session::SessionPhase::Stopped;
    pending.cleanup_pending = true;
    for reply in [
        response(Some(wrong)),
        response(Some(pending)),
        response(Some(snapshot())),
        Response::failure("scope_changed"),
    ] {
        let controller = controller([response(Some(snapshot())), reply]);
        assert!(controller.stop().await.is_err());
        assert!(matches!(
            controller.transport().requests.lock().unwrap().as_slice(),
            [Request::Status { .. }, Request::Redundant { .. }]
        ));
    }
}

struct Backend;
impl ServiceTunnelBackend for Backend {
    fn supports_redundancy(&self) -> bool {
        true
    }
    fn current_redundancy_snapshot(&self) -> Option<Snapshot> {
        Some(snapshot())
    }
    fn start(
        &mut self,
        _: &ParsedConfiguration,
        _: &DesktopTunnelOptions,
    ) -> Result<ServiceTunnelState, ServiceError> {
        panic!("native Start")
    }
    fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        panic!("native Stop")
    }
    fn status(&self) -> Result<ServiceTunnelState, ServiceError> {
        Ok(ServiceTunnelState::Starting)
    }
}
#[test]
fn version_reports_backend_support_and_status_includes_current_snapshot() {
    let mut handler = TunnelRequestHandler::new(Backend, "test");
    assert!(handler.handle(Request::version()).desktop_redundancy_v1);
    assert_eq!(
        handler.handle(Request::status()).redundancy,
        Some(snapshot())
    );
}
