use nelomai_client_tunnel::{
    redundancy::{protocol, session::SessionPhase},
    DesktopTunnelOptions, TunnelTransport,
};
use nelomai_windows_service::{
    decode_request, decode_response, encode_request, encode_response, Request, Response,
    ServiceError, MAX_FRAME_SIZE, PROTOCOL_VERSION,
};
use nelomai_windows_service::{
    dispatcher, exchange_selected, ServiceTunnelBackend, ServiceTunnelState, TunnelRequestHandler,
};
use serde_json::{json, Value};

fn scope() -> Value {
    json!({"runtime":"latest","runtime_generation":19,
        "session_id":"11111111-1111-4111-8111-111111111111","connection_generation":7})
}
fn member(slot: &str) -> Value {
    json!({"slot":slot,"lease_id":"22222222-2222-4222-8222-222222222222",
        "configuration":"[Interface]\nPrivateKey=IPC-SECRET\n[Peer]\nPresharedKey=IPC-PSK\n",
        "probe":{"kind":"dns_a","target_ipv4":"10.0.0.1","query_name":"example.com","timeout_ms":2000}})
}
fn start() -> Value {
    json!({"action":"start","scope":scope(),"primary":member("A"),
        "role_generation":3,"membership_generation":4,"warm_stop_v1":true,
        "options":{"excludedIpv4Cidrs":[],"excludeLocalNetworks":false,"policyHash":null}})
}
fn attach() -> Value {
    json!({"action":"attach","scope":scope(),"member":member("B"),
        "expected_revision":5,"expected_network_epoch":6,
        "expected_membership_generation":4,"membership_generation":5})
}
fn command(action: &str) -> Value {
    json!({"action":action,"scope":scope()})
}
fn remove_standby() -> Value {
    json!({"action":"remove_standby","scope":scope(),"slot":"B",
        "lease_id":"22222222-2222-4222-8222-222222222222","expected_revision":5,
        "expected_network_epoch":6,"expected_membership_generation":4})
}
fn panel_session() -> Value {
    json!({"session_id":"11111111-1111-4111-8111-111111111111","state":"connected",
        "active_lease_id":"22222222-2222-4222-8222-222222222222",
        "slot_a_lease_id":"22222222-2222-4222-8222-222222222222","slot_b_lease_id":null,
        "standby_desired":true,"role_generation":3,"membership_generation":4,"reason":null})
}
fn commands() -> Vec<Value> {
    vec![
        start(),
        attach(),
        remove_standby(),
        command("status"),
        command("stop"),
        command("prepare_stop"),
        command("network_changed"),
        json!({"action":"stage_candidate","scope":scope(),"member":member("B"),
            "expected_revision":5,"expected_network_epoch":6,"expected_membership_generation":4}),
        json!({"action":"commit_candidate","scope":scope(),"slot":"B",
            "expected_revision":5,"expected_network_epoch":6,"session":panel_session()}),
        json!({"action":"confirm_role","scope":scope(),"expected_revision":5,"expected_network_epoch":6,
            "response":{"api_version":"1","request_id":"fake-role-response","action":"acknowledged",
                "local_active_lease_id":"22222222-2222-4222-8222-222222222222","session":panel_session()}}),
    ]
}
fn frame(value: &Value) -> Vec<u8> {
    let body = serde_json::to_vec(value).unwrap();
    let mut frame = (body.len() as u32).to_le_bytes().to_vec();
    frame.extend(body);
    frame
}
fn request(value: Value) -> Request {
    decode_request(&frame(
        &json!({"command":"redundant","protocolVersion":PROTOCOL_VERSION,"request":value}),
    ))
    .unwrap()
}

#[test]
fn shared_commands_roundtrip_with_redacted_debug_and_safe_diagnostic_names() {
    for value in commands() {
        let request = request(value.clone());
        let encoded = encode_request(&request).unwrap();
        let wire: Value = serde_json::from_slice(&encoded[4..]).unwrap();
        assert_eq!(wire["request"], value);
        assert_eq!(wire["command"], "redundant");
        assert_eq!(decode_request(&encoded).unwrap(), request);
        assert_eq!(request.diagnostic_name(), "redundant");
        assert_eq!(request.protocol_version(), PROTOCOL_VERSION);
        assert_eq!(request.is_lifecycle_event(), value["action"] != "status");
        let debug = format!("{request:?}");
        for secret in [
            "IPC-SECRET",
            "IPC-PSK",
            "11111111-1111-4111-8111-111111111111",
        ] {
            assert!(!debug.contains(secret));
        }
    }
}

#[test]
fn request_equality_includes_scope_command_fences_and_secret_configuration() {
    let original = start();
    for (path, value) in [
        ("/scope/connection_generation", json!(8)),
        ("/primary/configuration", json!("PrivateKey=DIFFERENT")),
        ("/role_generation", json!(99)),
        ("/warm_stop_v1", json!(false)),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(path).unwrap() = value;
        assert_ne!(request(original.clone()), request(changed));
    }
    assert_ne!(request(command("status")), request(command("stop")));
}

#[test]
fn remove_standby_equality_includes_every_ownership_and_generation_fence() {
    let original = remove_standby();
    assert_eq!(request(original.clone()), request(original.clone()));
    for (path, value) in [
        ("/scope/connection_generation", json!(8)),
        ("/slot", json!("A")),
        ("/lease_id", json!("33333333-3333-4333-8333-333333333333")),
        ("/expected_revision", json!(9)),
        ("/expected_network_epoch", json!(10)),
        ("/expected_membership_generation", json!(11)),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(path).unwrap() = value;
        assert_ne!(request(original.clone()), request(changed));
    }
}

#[test]
fn prepare_stop_is_a_distinct_scoped_request_for_idempotency() {
    let original = command("prepare_stop");
    assert_eq!(request(original.clone()), request(original.clone()));
    assert_ne!(request(original.clone()), request(command("stop")));
    let mut changed = original.clone();
    changed["scope"]["connection_generation"] = json!(8);
    assert_ne!(request(original), request(changed));
}

#[test]
fn scoped_stop_and_removal_keep_shared_validation_and_authenticated_private_routing() {
    use nelomai_contracts::RuntimeSlot;
    for value in [command("stop"), command("prepare_stop"), remove_standby()] {
        let Request::Redundant {
            request: shared, ..
        } = request(value.clone())
        else {
            unreachable!()
        };
        // The composite supplies its actual runtime; the IPC handler must not
        // invent one or bypass the shared validator for these new commands.
        assert!(shared.validate(RuntimeSlot::Latest).is_ok());
        assert!(shared.validate(RuntimeSlot::Stable).is_err());
        let mut malformed = value.clone();
        malformed["scope"]["connection_generation"] = json!(0);
        let Request::Redundant {
            request: shared, ..
        } = request(malformed)
        else {
            unreachable!()
        };
        assert!(shared.validate(RuntimeSlot::Latest).is_err());
        let result = exchange_selected(
            request(value),
            Some(&identity()),
            |_| {
                let mut foreign = identity();
                foreign.manifest_sha256 = "b".repeat(64);
                Ok(dispatcher::DispatcherResponse::success(foreign, true))
            },
            |_| panic!("unauthenticated identity must never reach private transport"),
        );
        assert_eq!(result.unwrap_err(), ServiceError::UnauthorizedClient);
    }
    for (path, bad) in [
        ("/lease_id", json!("invalid")),
        ("/expected_revision", json!(0)),
        ("/expected_network_epoch", json!(0)),
        ("/expected_membership_generation", json!(u64::MAX)),
    ] {
        let mut value = remove_standby();
        *value.pointer_mut(path).unwrap() = bad;
        let Request::Redundant {
            request: shared, ..
        } = request(value)
        else {
            unreachable!()
        };
        assert!(shared.validate(RuntimeSlot::Latest).is_err());
    }
}

#[test]
fn nested_configuration_and_outer_frame_bounds_remain_enforced() {
    assert!(encode_request(&request(start())).is_ok());
    for config in [String::new(), "x\0y".into(), "x".repeat(512 * 1024 + 1)] {
        let mut value = start();
        value["primary"]["configuration"] = json!(config);
        assert_eq!(
            decode_request(&frame(
                &json!({"command":"redundant","protocolVersion":PROTOCOL_VERSION,"request":value})
            ))
            .unwrap_err(),
            ServiceError::InvalidRequest
        );
    }
    assert_eq!(
        decode_request(&(MAX_FRAME_SIZE as u32 + 1).to_le_bytes()).unwrap_err(),
        ServiceError::FrameTooLarge
    );
    let mut value = start();
    value["primary"]["configuration"] = json!("\n".repeat(512 * 1024));
    // Shared configuration length is valid, but JSON escaping exceeds the IPC frame.
    let request: Request = serde_json::from_value(
        json!({"command":"redundant","protocolVersion":PROTOCOL_VERSION,"request":value}),
    )
    .unwrap();
    assert_eq!(
        encode_request(&request).unwrap_err(),
        ServiceError::FrameTooLarge
    );
}

#[test]
fn legacy_responses_omit_redundancy_and_new_snapshots_roundtrip() {
    let old = Response::success(None);
    let wire = encode_response(&old).unwrap();
    let value: Value = serde_json::from_slice(&wire[4..]).unwrap();
    assert!(value.get("redundancy").is_none());
    assert_eq!(decode_response(&wire).unwrap(), old);
    let mut with_snapshot = value;
    with_snapshot["redundancy"] = json!({
        "session":{"scope":scope(),"phase":"Starting","active":"A","installed":[true,false],
            "committed":[true,false],"network_epoch":6,"local_revision":5,
            "role_generation":3,"membership_generation":4,"role_confirmed":true},
        "leases":["22222222-2222-4222-8222-222222222222",null],
        "current_leases":["22222222-2222-4222-8222-222222222222",null],"standby_failed":false,"stalled":false,
        "primary_ready":false,"standby_ready":false,"cleanup_pending":false,"warm_stop_v1":true});
    let restored = decode_response(&frame(&with_snapshot)).unwrap();
    assert_eq!(serde_json::to_value(restored).unwrap(), with_snapshot);
}

fn snapshot(phase: SessionPhase, primary_ready: bool, cleanup_pending: bool) -> protocol::Snapshot {
    serde_json::from_value(json!({
        "session":{"scope":scope(),"phase":phase,"active":"A","installed":[true,false],
            "committed":[true,false],"network_epoch":6,"local_revision":5,
            "role_generation":3,"membership_generation":4,"role_confirmed":true},
        "leases":["22222222-2222-4222-8222-222222222222",null],
        "current_leases":["22222222-2222-4222-8222-222222222222",null],"standby_failed":false,"stalled":false,
        "primary_ready":primary_ready,"standby_ready":false,"cleanup_pending":cleanup_pending,"warm_stop_v1":true})).unwrap()
}

struct Backend {
    seen: Vec<protocol::Command>,
    reply: protocol::Snapshot,
    ticks: Vec<u64>,
    shutdowns: usize,
    fail: bool,
}
impl Backend {
    fn new(reply: protocol::Snapshot) -> Self {
        Self {
            seen: vec![],
            reply,
            ticks: vec![],
            shutdowns: 0,
            fail: false,
        }
    }
}
impl ServiceTunnelBackend for Backend {
    fn start(
        &mut self,
        _: &str,
        _: &DesktopTunnelOptions,
        _: TunnelTransport,
    ) -> Result<ServiceTunnelState, ServiceError> {
        panic!("redundant start must stay typed")
    }
    fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        panic!("redundant stop must stay scoped")
    }
    fn status(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        panic!("redundant status must stay scoped")
    }
    fn redundant(
        &mut self,
        request: protocol::Command,
    ) -> Result<protocol::Snapshot, ServiceError> {
        self.seen.push(request);
        if self.fail {
            return Err(ServiceError::Backend("raw IPC-SECRET OS details".into()));
        }
        Ok(self.reply.clone())
    }
    fn tick(&mut self, now: u64) -> Result<(), ServiceError> {
        self.ticks.push(now);
        Ok(())
    }
    fn shutdown(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        self.shutdowns += 1;
        Ok(ServiceTunnelState::Stopping)
    }
}

#[test]
fn handler_passes_every_command_and_exact_scope_without_guessing_runtime() {
    for runtime in ["latest", "stable"] {
        for mut value in commands() {
            value["scope"]["runtime"] = json!(runtime);
            let reply = snapshot(SessionPhase::Running, true, false);
            let mut handler = TunnelRequestHandler::new(Backend::new(reply.clone()), "test");
            let response = handler.handle(request(value.clone()));
            assert!(response.ok);
            assert_eq!(response.redundancy, Some(reply));
            assert_eq!(handler.backend().seen.len(), 1);
            assert_eq!(
                serde_json::to_value(&handler.backend().seen[0]).unwrap(),
                value
            );
        }
    }
}

#[test]
fn response_state_respects_phase_readiness_and_cleanup_priority() {
    for phase in [
        SessionPhase::Starting,
        SessionPhase::Running,
        SessionPhase::Stopping,
        SessionPhase::Stopped,
    ] {
        for ready in [false, true] {
            for cleanup in [false, true] {
                let reply = snapshot(phase, ready, cleanup);
                let mut handler = TunnelRequestHandler::new(Backend::new(reply.clone()), "test");
                let response = handler.handle(request(command("status")));
                let expected = if cleanup {
                    ServiceTunnelState::Stopping
                } else {
                    match phase {
                        SessionPhase::Starting => ServiceTunnelState::Starting,
                        SessionPhase::Running if ready => ServiceTunnelState::Running,
                        SessionPhase::Running => ServiceTunnelState::Starting,
                        SessionPhase::Stopping => ServiceTunnelState::Stopping,
                        SessionPhase::Stopped => ServiceTunnelState::Stopped,
                    }
                };
                assert_eq!(
                    response.state,
                    Some(expected),
                    "phase={phase:?}, ready={ready}, cleanup={cleanup}"
                );
                assert_eq!(response.redundancy, Some(reply));
            }
        }
    }
}

#[test]
fn handler_rejects_version_before_backend_and_redacts_backend_failures() {
    let mut handler = TunnelRequestHandler::new(
        Backend::new(snapshot(SessionPhase::Running, true, false)),
        "test",
    );
    let mut bad = request(start());
    if let Request::Redundant {
        protocol_version, ..
    } = &mut bad
    {
        *protocol_version += 1;
    }
    let response = handler.handle(bad);
    assert_eq!(response.error_code.as_deref(), Some("unsupported_protocol"));
    assert!(handler.backend().seen.is_empty());
    let mut backend = Backend::new(snapshot(SessionPhase::Running, true, false));
    backend.fail = true;
    let mut handler = TunnelRequestHandler::new(backend, "test");
    let response = handler.handle(request(start()));
    assert!(!response.ok);
    assert!(response.redundancy.is_none());
    assert_eq!(response.error_code.as_deref(), Some("service_unavailable"));
    assert!(!format!("{response:?}").contains("IPC-SECRET"));
}

fn identity() -> dispatcher::EngineIdentity {
    dispatcher::EngineIdentity {
        slot: nelomai_contracts::RuntimeSlot::Latest,
        runtime_version: "0.3.3".into(),
        runtime_contract_version: 1,
        container_version: "0.3.3".into(),
        manifest_sha256: "a".repeat(64),
    }
}

#[test]
fn only_redundant_start_launches_engine_and_stop_never_becomes_dispatcher_stop() {
    for running in [false, true] {
        for value in commands() {
            let mut calls = vec![];
            let private_called = std::cell::Cell::new(false);
            let is_start = value["action"] == "start";
            let result = exchange_selected(
                request(value.clone()),
                Some(&identity()),
                |action| {
                    let ready = match action {
                        dispatcher::DispatcherRequest::Version { .. } => {
                            calls.push("version");
                            running
                        }
                        dispatcher::DispatcherRequest::Start {
                            identity: actual, ..
                        } => {
                            assert_eq!(*actual, identity());
                            calls.push("start");
                            true
                        }
                        _ => panic!("no dispatcher stop or other lifecycle mutation is permitted"),
                    };
                    Ok(dispatcher::DispatcherResponse::success(identity(), ready))
                },
                |seen| {
                    private_called.set(true);
                    assert_eq!(serde_json::to_value(seen).unwrap()["request"], value);
                    Ok(Response::success(None))
                },
            );
            assert_eq!(
                calls,
                if is_start {
                    vec!["version", "start"]
                } else {
                    vec!["version"]
                }
            );
            assert_eq!(private_called.get(), running || is_start);
            if running || is_start {
                assert!(result.is_ok());
            } else {
                assert_eq!(
                    result.unwrap_err(),
                    ServiceError::Backend("engine_not_running".into())
                );
            }
        }
    }
}

#[test]
fn failed_or_wrong_identity_start_never_reaches_private_engine() {
    for wrong_identity in [false, true] {
        let result = exchange_selected(
            request(start()),
            Some(&identity()),
            |action| {
                let mut response = identity();
                match action {
                    dispatcher::DispatcherRequest::Version { .. } => {
                        Ok(dispatcher::DispatcherResponse::success(response, false))
                    }
                    dispatcher::DispatcherRequest::Start { .. } => {
                        if wrong_identity {
                            response.runtime_version = "foreign".into();
                        }
                        Ok(dispatcher::DispatcherResponse::success(
                            response,
                            wrong_identity,
                        ))
                    }
                    _ => panic!("unexpected lifecycle mutation"),
                }
            },
            |_| panic!("unconfirmed start must not reach private transport"),
        );
        assert_eq!(
            result.unwrap_err(),
            ServiceError::Backend("dispatcher_start_failed".into())
        );
    }
}

#[test]
fn backend_defaults_remain_unsupported_noop_tick_and_legacy_stop_shutdown() {
    #[derive(Default)]
    struct Legacy {
        stops: usize,
    }
    impl ServiceTunnelBackend for Legacy {
        fn start(
            &mut self,
            _: &str,
            _: &DesktopTunnelOptions,
            _: TunnelTransport,
        ) -> Result<ServiceTunnelState, ServiceError> {
            Ok(ServiceTunnelState::Running)
        }
        fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
            self.stops += 1;
            Ok(ServiceTunnelState::Stopped)
        }
        fn status(&mut self) -> Result<ServiceTunnelState, ServiceError> {
            Ok(ServiceTunnelState::Stopped)
        }
    }
    let mut handler = TunnelRequestHandler::new(Legacy::default(), "test");
    let response = handler.handle(request(start()));
    assert!(!response.ok);
    assert!(response.redundancy.is_none());
    assert_eq!(
        response.error_code.as_deref(),
        Some("redundancy_unsupported")
    );
    handler.tick(123).unwrap();
    assert_eq!(handler.backend().stops, 0);
    assert_eq!(handler.shutdown().unwrap(), ServiceTunnelState::Stopped);
    assert_eq!(handler.backend().stops, 1);
    let mut handler = TunnelRequestHandler::new(
        Backend::new(snapshot(SessionPhase::Running, true, false)),
        "test",
    );
    handler.tick(456).unwrap();
    assert_eq!(handler.backend().ticks, [456]);
    assert_eq!(handler.shutdown().unwrap(), ServiceTunnelState::Stopping);
    assert_eq!(handler.backend().shutdowns, 1);
}
