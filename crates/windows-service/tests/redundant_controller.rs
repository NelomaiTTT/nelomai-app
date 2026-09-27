use async_trait::async_trait;
use nelomai_client_tunnel::{
    redundancy::{
        protocol::{Command, Snapshot},
        session::{SessionPhase, SessionState},
        SessionScope, Slot,
    },
    TunnelController,
};
use nelomai_contracts::RuntimeSlot;
use nelomai_windows_service::{
    Request, Response, ServiceError, ServiceTransport, ServiceTunnelState, WindowsTunnelController,
    PROTOCOL_VERSION,
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
fn snapshot(phase: SessionPhase) -> Snapshot {
    let mut session = SessionState::new(scope(), Slot::A, 1, 1)
        .unwrap()
        .snapshot();
    session.phase = phase;
    Snapshot {
        session,
        leases: [None, None],
        current_leases: [None, None],
        standby_failed: false,
        stalled: false,
        primary_ready: true,
        standby_ready: false,
        cleanup_pending: false,
        warm_stop_v1: false,
    }
}
fn response(snapshot: Option<Snapshot>) -> Response {
    let mut response = Response::success(Some(ServiceTunnelState::Stopped));
    response.redundancy = snapshot;
    response
}
struct FakeCommandChannel {
    responses: Mutex<VecDeque<Result<Response, ServiceError>>>,
    requests: Mutex<Vec<Request>>,
}
#[async_trait]
impl ServiceTransport for FakeCommandChannel {
    async fn exchange(&self, request: Request) -> Result<Response, ServiceError> {
        self.requests.lock().unwrap().push(request);
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected fallback request")
    }
}
fn controller(
    responses: impl IntoIterator<Item = Result<Response, ServiceError>>,
) -> WindowsTunnelController<FakeCommandChannel> {
    WindowsTunnelController::new(FakeCommandChannel {
        responses: Mutex::new(responses.into_iter().collect()),
        requests: Mutex::new(vec![]),
    })
}

#[tokio::test]
async fn capability_is_negotiated_by_version_and_old_response_defaults_false() {
    let old: Response =
        serde_json::from_value(serde_json::json!({"protocolVersion":PROTOCOL_VERSION,"ok":true}))
            .unwrap();
    let mut wire = serde_json::to_value(&old).unwrap();
    assert!(wire.get("desktopRedundancyV1").is_none());
    wire["desktopRedundancyV1"] = true.into();
    let supported = serde_json::from_value(wire).unwrap();
    let controller = controller([Ok(old), Ok(supported)]);
    assert!(!controller.desktop_redundancy_supported().await.unwrap());
    assert!(controller.desktop_redundancy_supported().await.unwrap());
    assert!(matches!(
        controller.transport().requests.lock().unwrap().as_slice(),
        [Request::Version { .. }, Request::Version { .. }]
    ));
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
                let mut foreign = snapshot(SessionPhase::Starting);
                foreign.session.scope.connection_generation += 1;
                reply.redundancy = Some(foreign);
            }
            let controller = controller([Ok(reply)]);
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
        Ok(Response::success(None)),
        Ok(Response::failure("denied")),
        Ok(wrong_version),
        Err(ServiceError::InvalidRequest),
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
async fn legacy_cleanup_stop_never_acquires_authority_over_current_pair() {
    let controller = controller([Ok(Response::failure("redundancy_session_owned"))]);
    assert!(controller.stop_if_unowned().await.is_err());
    assert!(matches!(
        controller.transport().requests.lock().unwrap().as_slice(),
        [Request::Stop { .. }]
    ));
}

#[tokio::test]
async fn private_command_returns_exact_snapshot_and_checks_all_scope_fields() {
    let expected = snapshot(SessionPhase::Running);
    let controller = controller([Ok(response(Some(expected.clone())))]);
    assert_eq!(
        controller
            .desktop_redundancy_command(Command::Status { scope: scope() })
            .await
            .unwrap(),
        expected
    );
    for field in 0..4 {
        let mut wrong = snapshot(SessionPhase::Stopped);
        match field {
            0 => wrong.session.scope.runtime = RuntimeSlot::Stable,
            1 => wrong.session.scope.runtime_generation += 1,
            2 => wrong.session.scope.session_id = "22222222-2222-4222-8222-222222222222".into(),
            _ => wrong.session.scope.connection_generation += 1,
        }
        let controller = self::controller([Ok(response(Some(wrong)))]);
        let error = controller
            .desktop_redundancy_command(Command::Stop { scope: scope() })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("redundancy_scope_mismatch"));
        assert_eq!(controller.transport().requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn command_and_capability_errors_never_fall_back() {
    let mut bad_protocol = response(Some(snapshot(SessionPhase::Stopped)));
    bad_protocol.protocol_version += 1;
    for reply in [
        Ok(Response::failure("denied")),
        Ok(bad_protocol),
        Err(ServiceError::InvalidRequest),
    ] {
        let controller = controller([reply.clone()]);
        assert!(controller.desktop_redundancy_supported().await.is_err());
        assert_eq!(controller.transport().requests.lock().unwrap().len(), 1);
        let controller = self::controller([reply]);
        assert!(controller
            .desktop_redundancy_command(Command::Stop { scope: scope() })
            .await
            .is_err());
        assert_eq!(controller.transport().requests.lock().unwrap().len(), 1);
    }
    let controller = controller([Ok(response(None))]);
    assert!(controller
        .desktop_redundancy_command(Command::Status { scope: scope() })
        .await
        .unwrap_err()
        .to_string()
        .contains("missing_redundancy_snapshot"));
}

#[tokio::test]
async fn prepare_stop_and_remove_standby_validate_before_transport() {
    for action in ["prepare_stop", "remove_standby"] {
        let mut wire = serde_json::json!({"action":action,"scope":scope(), "slot":"B",
            "lease_id":"22222222-2222-4222-8222-222222222222", "expected_revision":1,
            "expected_network_epoch":1,"expected_membership_generation":1});
        if action == "prepare_stop" {
            wire = serde_json::json!({"action":action,"scope":scope()});
        }
        let command: Command = serde_json::from_value(wire.clone()).unwrap();
        let controller = controller([Ok(response(Some(snapshot(SessionPhase::Stopping))))]);
        controller
            .desktop_redundancy_command(command)
            .await
            .unwrap();
        assert!(matches!(
            controller.transport().requests.lock().unwrap().as_slice(),
            [Request::Redundant { .. }]
        ));
        wire["scope"]["connection_generation"] = 0.into();
        let command = serde_json::from_value(wire).unwrap();
        let controller = self::controller([]);
        assert!(controller
            .desktop_redundancy_command(command)
            .await
            .unwrap_err()
            .to_string()
            .contains("invalid_redundant_command"));
        assert!(controller.transport().requests.lock().unwrap().is_empty());
    }
}

#[test]
fn prepare_recovery_stop_equality_covers_exact_scope_revision_epoch_and_variant() {
    let request = |scope, revision, epoch| Request::Redundant {
        protocol_version: PROTOCOL_VERSION,
        request: Command::PrepareRecoveryStop {
            scope,
            expected_revision: revision,
            expected_network_epoch: epoch,
        },
    };
    assert_eq!(request(scope(), 3, 7), request(scope(), 3, 7));
    for field in 0..6 {
        let mut wrong = scope();
        match field {
            0 => wrong.runtime = RuntimeSlot::Stable,
            1 => wrong.runtime_generation += 1,
            2 => wrong.connection_generation += 1,
            3 => wrong.session_id = "22222222-2222-4222-8222-222222222222".into(),
            _ => (),
        }
        let other = request(wrong, 3 + u64::from(field == 4), 7 + u64::from(field == 5));
        assert_ne!(request(scope(), 3, 7), other);
        assert_ne!(other, request(scope(), 3, 7));
    }
    assert_ne!(
        request(scope(), 3, 7),
        Request::Redundant {
            protocol_version: PROTOCOL_VERSION,
            request: Command::PrepareStop { scope: scope() }
        }
    );
}

#[tokio::test]
async fn stop_and_rebind_capture_fresh_scope_on_every_call() {
    for rebind in [false, true] {
        let mut responses = vec![];
        for generation in [3, 4] {
            let mut current = snapshot(if rebind {
                SessionPhase::Running
            } else {
                SessionPhase::Stopped
            });
            current.session.scope.connection_generation = generation;
            responses.extend([
                Ok(response(Some(current.clone()))),
                Ok(response(Some(current))),
            ]);
        }
        let controller = controller(responses);
        for _ in 0..2 {
            if rebind {
                assert!(controller.rebind_udp().await.unwrap());
            } else {
                controller.stop().await.unwrap();
            }
        }
        let requests = controller.transport().requests.lock().unwrap();
        assert_eq!(requests.len(), 4);
        for (index, generation) in [(0, 3), (2, 4)] {
            assert!(matches!(requests[index], Request::Status { .. }));
            let Request::Redundant { request, .. } = &requests[index + 1] else {
                panic!("unscoped mutation")
            };
            assert_eq!(request.scope().connection_generation, generation);
            assert!(matches!(
                (rebind, request),
                (true, Command::NetworkChanged { .. }) | (false, Command::Stop { .. })
            ));
        }
    }
}

#[tokio::test]
async fn legacy_stop_and_rebind_require_successful_status_without_snapshot() {
    for rebind in [false, true] {
        let controller = controller([
            Ok(response(None)),
            Ok(Response::success(Some(if rebind {
                ServiceTunnelState::Running
            } else {
                ServiceTunnelState::Stopped
            }))),
        ]);
        if rebind {
            assert!(controller.rebind_udp().await.unwrap());
        } else {
            controller.stop().await.unwrap();
        }
        let requests = controller.transport().requests.lock().unwrap();
        assert!(matches!(requests[0], Request::Status { .. }));
        assert!(matches!(
            (rebind, &requests[1]),
            (true, Request::RebindUdp { .. }) | (false, Request::Stop { .. })
        ));
    }
}

#[tokio::test]
async fn bad_status_never_authorizes_unscoped_mutation() {
    let mut bad_protocol = response(None);
    bad_protocol.protocol_version += 1;
    let mut invalid_scope = snapshot(SessionPhase::Running);
    invalid_scope.session.scope.runtime_generation = 0;
    for rebind in [false, true] {
        for reply in [
            Ok(Response::failure("denied")),
            Ok(Response::success(None)),
            Ok(bad_protocol.clone()),
            Ok(response(Some(invalid_scope.clone()))),
            Err(ServiceError::InvalidRequest),
        ] {
            let controller = controller([reply]);
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
}

#[tokio::test]
async fn scoped_reply_error_wrong_scope_or_incomplete_cleanup_has_no_fallback() {
    for rebind in [false, true] {
        let mut wrong = snapshot(SessionPhase::Stopped);
        wrong.session.scope.connection_generation += 1;
        let mut pending = snapshot(if rebind {
            SessionPhase::Running
        } else {
            SessionPhase::Stopped
        });
        pending.cleanup_pending = true;
        for reply in [
            response(Some(wrong)),
            response(Some(pending)),
            response(Some(snapshot(SessionPhase::Starting))),
            response(None),
            Response::failure("scope_changed"),
        ] {
            let controller = controller([
                Ok(response(Some(snapshot(SessionPhase::Running)))),
                Ok(reply),
            ]);
            assert!(if rebind {
                controller.rebind_udp().await.map(|_| ())
            } else {
                controller.stop().await
            }
            .is_err());
            assert!(matches!(
                controller.transport().requests.lock().unwrap().as_slice(),
                [Request::Status { .. }, Request::Redundant { .. }]
            ));
        }
    }
}

struct LegacyBackend;
impl nelomai_windows_service::ServiceTunnelBackend for LegacyBackend {
    fn start(
        &mut self,
        _: &str,
        _: &nelomai_client_tunnel::DesktopTunnelOptions,
        _: nelomai_client_tunnel::TunnelTransport,
    ) -> Result<ServiceTunnelState, ServiceError> {
        panic!("native start")
    }
    fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        panic!("native stop")
    }
    fn status(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        Ok(ServiceTunnelState::Stopped)
    }
}
struct SnapshotBackend;
impl nelomai_windows_service::ServiceTunnelBackend for SnapshotBackend {
    fn supports_redundancy(&self) -> bool {
        true
    }
    fn current_redundancy_snapshot(&self) -> Option<Snapshot> {
        Some(snapshot(SessionPhase::Starting))
    }
    fn start(
        &mut self,
        _: &str,
        _: &nelomai_client_tunnel::DesktopTunnelOptions,
        _: nelomai_client_tunnel::TunnelTransport,
    ) -> Result<ServiceTunnelState, ServiceError> {
        panic!("native start")
    }
    fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        panic!("native stop")
    }
    fn status(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        Ok(ServiceTunnelState::Starting)
    }
}

#[test]
fn backend_defaults_never_advertise_support_or_snapshot() {
    let mut handler = nelomai_windows_service::TunnelRequestHandler::new(LegacyBackend, "test");
    let version = serde_json::to_value(handler.handle(Request::version())).unwrap();
    assert!(version.get("desktopRedundancyV1").is_none());
    assert!(handler.handle(Request::status()).redundancy.is_none());
    assert!(serde_json::to_value(Response::failure("test"))
        .unwrap()
        .get("desktopRedundancyV1")
        .is_none());
}

#[test]
fn version_and_status_use_explicit_backend_hooks() {
    let mut handler = nelomai_windows_service::TunnelRequestHandler::new(SnapshotBackend, "test");
    let version = serde_json::to_value(handler.handle(Request::version())).unwrap();
    assert_eq!(version["desktopRedundancyV1"], true);
    let status = handler.handle(Request::status());
    assert_eq!(status.redundancy, Some(snapshot(SessionPhase::Starting)));
    assert!(serde_json::to_value(status)
        .unwrap()
        .get("desktopRedundancyV1")
        .is_none());
}
