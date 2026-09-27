use nelomai_client_tunnel::{
    redundancy::{
        protocol::{Command, Snapshot},
        session::{SessionPhase, SessionState},
        SessionScope, Slot,
    },
    DesktopTunnelOptions,
};
use nelomai_contracts::{dispatcher as d, RuntimeSlot};
use nelomai_unix_service::{
    decode_request, decode_response, encode_request, encode_response, ParsedConfiguration, Request,
    Response, ServiceError, ServiceTransport, ServiceTunnelBackend, ServiceTunnelState,
    TunnelRequestHandler, UnixSocketTransport, PROTOCOL_VERSION,
};
use serde_json::json;

fn scope() -> SessionScope {
    SessionScope {
        runtime: RuntimeSlot::Latest,
        runtime_generation: 10,
        session_id: "11111111-1111-4111-8111-111111111111".into(),
        connection_generation: 3,
    }
}
fn start() -> Command {
    serde_json::from_value(json!({"action":"start","scope":scope(),
        "primary":{"slot":"A","lease_id":"22222222-2222-4222-8222-222222222222",
        "configuration":"[Interface]\nPrivateKey=SECRET_DO_NOT_LOG\n[Peer]\n",
        "probe":{"kind":"dns_a","target_ipv4":"10.0.0.1","query_name":"example.com","timeout_ms":2000}},
        "role_generation":1,"membership_generation":1,"warm_stop_v1":true,
        "options":DesktopTunnelOptions::default()})).unwrap()
}
fn request(command: Command) -> Request {
    Request::Redundant {
        protocol_version: PROTOCOL_VERSION,
        request: command,
    }
}
fn snapshot(phase: SessionPhase, ready: bool, cleanup: bool) -> Snapshot {
    let mut session = SessionState::new(scope(), Slot::A, 1, 1)
        .unwrap()
        .snapshot();
    session.phase = phase;
    Snapshot {
        session,
        leases: [Some("22222222-2222-4222-8222-222222222222".into()), None],
        current_leases: [Some("22222222-2222-4222-8222-222222222222".into()), None],
        primary_ready: ready,
        standby_ready: false,
        standby_failed: false,
        stalled: false,
        cleanup_pending: cleanup,
        warm_stop_v1: true,
    }
}

#[derive(Default)]
struct Legacy {
    stops: usize,
    stop_state: ServiceTunnelState,
}
impl ServiceTunnelBackend for Legacy {
    fn start(
        &mut self,
        _: &ParsedConfiguration,
        _: &DesktopTunnelOptions,
    ) -> Result<ServiceTunnelState, ServiceError> {
        Ok(ServiceTunnelState::Running)
    }
    fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        self.stops += 1;
        Ok(self.stop_state)
    }
    fn status(&self) -> Result<ServiceTunnelState, ServiceError> {
        Ok(ServiceTunnelState::Stopped)
    }
}
struct FakeBackend {
    snapshot: Snapshot,
    commands: usize,
    stops: usize,
    shutdowns: usize,
    ticks: Vec<u64>,
}
impl FakeBackend {
    fn new(snapshot: Snapshot) -> Self {
        Self {
            snapshot,
            commands: 0,
            stops: 0,
            shutdowns: 0,
            ticks: vec![],
        }
    }
}
impl ServiceTunnelBackend for FakeBackend {
    fn start(
        &mut self,
        _: &ParsedConfiguration,
        _: &DesktopTunnelOptions,
    ) -> Result<ServiceTunnelState, ServiceError> {
        panic!("redundant command reached legacy start")
    }
    fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        self.stops += 1;
        Ok(ServiceTunnelState::Stopped)
    }
    fn status(&self) -> Result<ServiceTunnelState, ServiceError> {
        Ok(ServiceTunnelState::Stopped)
    }
    fn redundant(&mut self, _: Command) -> Result<Snapshot, ServiceError> {
        self.commands += 1;
        Ok(self.snapshot.clone())
    }
    fn tick(&mut self, now_ms: u64) -> Result<(), ServiceError> {
        self.ticks.push(now_ms);
        Ok(())
    }
    fn shutdown(&mut self) -> Result<(), ServiceError> {
        self.shutdowns += 1;
        Ok(())
    }
}

#[test]
fn redundant_start_round_trips_and_debug_redacts_entire_payload() {
    let input = request(start());
    let wire = encode_request(&input).unwrap();
    let decoded = decode_request(&wire).unwrap();
    assert_eq!(encode_request(&decoded).unwrap(), wire);
    let value = serde_json::to_value(&decoded).unwrap();
    assert_eq!(value["command"], "redundant");
    assert_eq!(value["protocolVersion"], PROTOCOL_VERSION);
    assert_eq!(value["request"]["action"], "start");
    let debug = format!("{decoded:?}");
    assert!(debug.contains("<redacted>"));
    for secret in [
        "SECRET_DO_NOT_LOG",
        "example.com",
        "11111111-1111-4111-8111-111111111111",
    ] {
        assert!(!debug.contains(secret));
    }
}

#[test]
fn legacy_responses_omit_redundancy_and_decode_without_it() {
    for response in [
        Response::success(Some(ServiceTunnelState::Stopped)),
        Response::failure("invalid_request"),
    ] {
        assert!(!serde_json::to_value(&response)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("redundancy"));
        let decoded = decode_response(&encode_response(&response).unwrap()).unwrap();
        assert_eq!(decoded.redundancy, None);
    }
}

#[test]
fn phase_mapping_requires_primary_proof_and_prioritizes_pending_cleanup() {
    for (phase, ready, cleanup, expected) in [
        (
            SessionPhase::Starting,
            true,
            false,
            ServiceTunnelState::Starting,
        ),
        (
            SessionPhase::Running,
            false,
            false,
            ServiceTunnelState::Starting,
        ),
        (
            SessionPhase::Running,
            true,
            false,
            ServiceTunnelState::Running,
        ),
        (
            SessionPhase::Stopping,
            true,
            false,
            ServiceTunnelState::Stopping,
        ),
        (
            SessionPhase::Stopped,
            false,
            false,
            ServiceTunnelState::Stopped,
        ),
        (
            SessionPhase::Stopped,
            false,
            true,
            ServiceTunnelState::Stopping,
        ),
        (
            SessionPhase::Running,
            true,
            true,
            ServiceTunnelState::Stopping,
        ),
    ] {
        let expected_snapshot = snapshot(phase, ready, cleanup);
        let mut handler =
            TunnelRequestHandler::new(FakeBackend::new(expected_snapshot.clone()), "test");
        let response = handler.handle(request(Command::Status { scope: scope() }));
        assert!(response.ok);
        assert_eq!(response.state, Some(expected));
        assert_eq!(response.redundancy, Some(expected_snapshot));
        assert_eq!(
            decode_response(&encode_response(&response).unwrap()).unwrap(),
            response
        );
    }
}

#[test]
fn old_protocol_and_malformed_commands_are_rejected_before_backend() {
    let mut handler = TunnelRequestHandler::new(
        FakeBackend::new(snapshot(SessionPhase::Running, true, false)),
        "test",
    );
    let old = Request::Redundant {
        protocol_version: PROTOCOL_VERSION - 1,
        request: start(),
    };
    let old = decode_request(&encode_request(&old).unwrap()).unwrap();
    assert_eq!(
        handler.handle(old).error_code.as_deref(),
        Some("unsupported_protocol")
    );
    let mut bad_scope = scope();
    bad_scope.connection_generation = 0;
    assert_eq!(
        handler
            .handle(request(Command::Status { scope: bad_scope }))
            .error_code
            .as_deref(),
        Some("invalid_request")
    );
    let mut bad_start = start();
    if let Command::Start { primary, .. } = &mut bad_start {
        primary.probe.timeout_ms = 1;
    }
    assert_eq!(
        handler.handle(request(bad_start)).error_code.as_deref(),
        Some("invalid_request")
    );
    assert_eq!(handler.backend().commands, 0);
}

#[test]
fn structural_validation_does_not_guess_native_runtime() {
    let mut handler = TunnelRequestHandler::new(
        FakeBackend::new(snapshot(SessionPhase::Running, true, false)),
        "test",
    );
    for runtime in [RuntimeSlot::Stable, RuntimeSlot::Latest] {
        let mut scope = scope();
        scope.runtime = runtime;
        assert!(handler.handle(request(Command::Status { scope })).ok);
    }
    assert_eq!(handler.backend().commands, 2);
}

#[test]
fn legacy_backend_rejects_redundancy_and_retains_default_tick_shutdown() {
    let mut handler = TunnelRequestHandler::new(Legacy::default(), "test");
    assert!(!handler.handle(request(start())).ok);
    handler.tick(100).unwrap();
    assert_eq!(handler.backend().stops, 0);
    handler.shutdown().unwrap();
    assert_eq!(handler.backend().stops, 1);
}

#[test]
fn default_shutdown_does_not_confirm_incomplete_legacy_cleanup() {
    let mut handler = TunnelRequestHandler::new(
        Legacy {
            stops: 0,
            stop_state: ServiceTunnelState::Stopping,
        },
        "test",
    );
    assert!(handler.shutdown().is_err());
}

#[test]
fn scoped_stop_and_ordinary_stop_do_not_invoke_force_shutdown_but_eof_does() {
    let mut handler = TunnelRequestHandler::new(
        FakeBackend::new(snapshot(SessionPhase::Stopped, false, false)),
        "test",
    );
    assert!(handler
        .handle(request(Command::Stop { scope: scope() }))
        .redundancy
        .is_some());
    assert_eq!(handler.backend().stops, 0);
    assert!(handler.handle(Request::stop()).ok);
    assert_eq!(handler.backend().stops, 1);
    assert_eq!(handler.backend().shutdowns, 0);
    handler.tick(123).unwrap();
    assert_eq!(handler.backend().ticks, vec![123]);
    nelomai_unix_service::run_engine_channel(&mut [].as_slice(), &mut vec![], &mut handler)
        .unwrap();
    assert_eq!(handler.backend().shutdowns, 1);
}

// Fake lifecycle/private endpoints: only temporary Unix sockets, no engine,
// dispatcher installation, native backend, hardware or external network.
struct FakeTransport {
    _root: tempfile::TempDir,
    transport: UnixSocketTransport,
    paths: [std::path::PathBuf; 2],
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
    calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}
impl FakeTransport {
    fn new(initially_running: bool, snapshot: Snapshot) -> Self {
        use std::{
            io::Write,
            os::unix::net::UnixListener,
            sync::{
                atomic::{AtomicBool, Ordering},
                Arc, Mutex,
            },
        };
        let root = tempfile::tempdir().unwrap();
        let paths = [
            root.path().join("lifecycle.sock"),
            root.path().join("private.sock"),
        ];
        let calls = Arc::new(Mutex::new(vec![]));
        let done = Arc::new(AtomicBool::new(false));
        let mut threads = vec![];
        for (index, path) in paths.iter().enumerate() {
            let listener = UnixListener::bind(path).unwrap();
            let calls = calls.clone();
            let done = done.clone();
            let snapshot = snapshot.clone();
            threads.push(std::thread::spawn(move || {
                let mut running = initially_running;
                for stream in listener.incoming() {
                    if done.load(Ordering::SeqCst) {
                        break;
                    }
                    let mut stream = stream.unwrap();
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                        .unwrap();
                    let input = d::read_frame(&mut stream, d::MAX_ENGINE_FRAME).unwrap();
                    let value: serde_json::Value =
                        serde_json::from_slice(d::frame_body(&input, d::MAX_ENGINE_FRAME).unwrap())
                            .unwrap();
                    let output = if index == 0 {
                        let command: d::DispatcherRequest = serde_json::from_value(value).unwrap();
                        let label = match command {
                            d::DispatcherRequest::Version { .. } => "version",
                            d::DispatcherRequest::Start { .. } => {
                                running = true;
                                "start"
                            }
                            d::DispatcherRequest::Stop { .. } => {
                                running = false;
                                "stop"
                            }
                            _ => panic!("unexpected dispatcher command"),
                        };
                        calls.lock().unwrap().push(format!("dispatcher:{label}"));
                        d::encode_frame(&d::DispatcherResponse::success(
                            d::EngineIdentity {
                                slot: RuntimeSlot::Latest,
                                runtime_version: "test".into(),
                                runtime_contract_version: 1,
                                container_version: "test".into(),
                                manifest_sha256: "ab".repeat(32),
                            },
                            running,
                        ))
                        .unwrap()
                    } else {
                        let label = value["request"]["action"]
                            .as_str()
                            .or_else(|| value["command"].as_str())
                            .unwrap();
                        calls.lock().unwrap().push(format!("engine:{label}"));
                        let mut response = Response::success(Some(ServiceTunnelState::Stopped));
                        if label == "version" {
                            response.desktop_redundancy_v1 = true;
                            response.service_version = Some("test".into());
                        } else {
                            response.redundancy = Some(snapshot.clone());
                        }
                        encode_response(&response).unwrap()
                    };
                    stream.write_all(&output).unwrap();
                }
            }));
        }
        let transport = UnixSocketTransport::with_dispatcher(&paths[1], &paths[0]);
        Self {
            _root: root,
            transport,
            paths,
            done,
            threads,
            calls,
        }
    }
}
impl Drop for FakeTransport {
    fn drop(&mut self) {
        self.done.store(true, std::sync::atomic::Ordering::SeqCst);
        for path in &self.paths {
            let _ = std::os::unix::net::UnixStream::connect(path);
        }
        for thread in self.threads.drain(..) {
            thread.join().unwrap();
        }
    }
}

#[tokio::test]
async fn only_redundant_start_launches_engine_and_scoped_stop_returns_native_snapshot() {
    let expected = snapshot(SessionPhase::Stopped, false, true);
    let fake = FakeTransport::new(false, expected.clone());
    assert!(fake.transport.exchange(request(start())).await.unwrap().ok);
    let stopped = fake
        .transport
        .exchange(request(Command::Stop { scope: scope() }))
        .await
        .unwrap();
    assert_eq!(stopped.redundancy, Some(expected));
    assert_eq!(
        *fake.calls.lock().unwrap(),
        [
            "dispatcher:version",
            "dispatcher:start",
            "engine:start",
            "dispatcher:version",
            "engine:stop"
        ]
    );
}

#[tokio::test]
async fn passive_status_and_scoped_stop_never_start_an_absent_engine() {
    let fake = FakeTransport::new(false, snapshot(SessionPhase::Stopped, false, false));
    for command in [
        Command::Status { scope: scope() },
        Command::Stop { scope: scope() },
        Command::NetworkChanged { scope: scope() },
    ] {
        assert!(fake.transport.exchange(request(command)).await.is_err());
    }
    assert_eq!(
        *fake.calls.lock().unwrap(),
        [
            "dispatcher:version",
            "dispatcher:version",
            "dispatcher:version"
        ]
    );
}

#[tokio::test]
async fn malformed_start_is_rejected_before_dispatcher_launch() {
    let fake = FakeTransport::new(false, snapshot(SessionPhase::Stopped, false, false));
    let mut command = start();
    if let Command::Start { primary, .. } = &mut command {
        primary.probe.timeout_ms = 1;
    }
    assert_eq!(
        fake.transport.exchange(request(command)).await.unwrap_err(),
        ServiceError::InvalidRequest
    );
    assert!(fake.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn legacy_stop_still_uses_dispatcher_lifecycle() {
    let fake = FakeTransport::new(true, snapshot(SessionPhase::Stopped, false, false));
    assert_eq!(
        fake.transport
            .exchange(Request::stop())
            .await
            .unwrap()
            .state,
        Some(ServiceTunnelState::Stopped)
    );
    assert_eq!(
        *fake.calls.lock().unwrap(),
        ["dispatcher:version", "dispatcher:stop"]
    );
}

#[tokio::test]
async fn version_can_launch_engine_for_capability_but_never_starts_a_tunnel() {
    let fake = FakeTransport::new(false, snapshot(SessionPhase::Stopped, false, false));
    let binding = d::CommonEngineBinding::default();
    binding.bind(fake_identity()).unwrap();
    let transport = fake.transport.clone().for_common(binding);
    assert!(
        transport
            .exchange(Request::version())
            .await
            .unwrap()
            .desktop_redundancy_v1
    );
    assert_eq!(
        *fake.calls.lock().unwrap(),
        ["dispatcher:version", "dispatcher:start", "engine:version"]
    );
    fake.calls.lock().unwrap().clear();
    assert!(
        transport
            .exchange(Request::version())
            .await
            .unwrap()
            .desktop_redundancy_v1
    );
    assert_eq!(
        *fake.calls.lock().unwrap(),
        ["dispatcher:version", "engine:version"]
    );
}

#[tokio::test]
async fn ordinary_status_stop_and_attach_never_launch_absent_engine() {
    let fake = FakeTransport::new(false, snapshot(SessionPhase::Stopped, false, false));
    assert_eq!(
        fake.transport
            .exchange(Request::status())
            .await
            .unwrap()
            .state,
        Some(ServiceTunnelState::Stopped)
    );
    assert!(fake.transport.exchange(Request::stop()).await.unwrap().ok);
    let Command::Start { primary, .. } = start() else {
        unreachable!()
    };
    let attach = Command::Attach {
        scope: scope(),
        member: primary,
        expected_revision: 1,
        expected_network_epoch: 1,
        expected_membership_generation: 1,
        membership_generation: 2,
    };
    assert!(fake.transport.exchange(request(attach)).await.is_err());
    assert_eq!(
        *fake.calls.lock().unwrap(),
        [
            "dispatcher:version",
            "dispatcher:version",
            "dispatcher:stop",
            "dispatcher:version"
        ]
    );
}

fn fake_identity() -> d::EngineIdentity {
    d::EngineIdentity {
        slot: RuntimeSlot::Latest,
        runtime_version: "test".into(),
        runtime_contract_version: 1,
        container_version: "test".into(),
        manifest_sha256: "ab".repeat(32),
    }
}

#[tokio::test]
async fn version_preserves_common_binding_and_exact_started_identity_gates() {
    let fake = FakeTransport::new(false, snapshot(SessionPhase::Stopped, false, false));
    let unbound = d::CommonEngineBinding::default();
    assert!(
        !fake
            .transport
            .clone()
            .for_common(unbound)
            .exchange(Request::version())
            .await
            .unwrap()
            .desktop_redundancy_v1
    );
    assert_eq!(*fake.calls.lock().unwrap(), ["dispatcher:version"]);
    fake.calls.lock().unwrap().clear();
    let bound = d::CommonEngineBinding::default();
    let mut identity = fake_identity();
    identity.manifest_sha256 = "cd".repeat(32);
    bound.bind(identity).unwrap();
    assert!(fake
        .transport
        .clone()
        .for_common(bound)
        .exchange(Request::version())
        .await
        .is_err());
    assert_eq!(*fake.calls.lock().unwrap(), ["dispatcher:version"]);
    fake.calls.lock().unwrap().clear();
    let bound = d::CommonEngineBinding::default();
    let mut identity = fake_identity();
    identity.runtime_version = "other".into();
    bound.bind(identity).unwrap();
    assert!(fake
        .transport
        .clone()
        .for_common(bound)
        .exchange(Request::version())
        .await
        .is_err());
    assert_eq!(
        *fake.calls.lock().unwrap(),
        ["dispatcher:version", "dispatcher:start"]
    );
}

#[test]
fn ordinary_backend_version_does_not_advertise_redundancy() {
    let mut handler = TunnelRequestHandler::new(Legacy::default(), "old");
    let response = handler.handle(Request::version());
    assert!(!response.desktop_redundancy_v1);
    assert!(serde_json::to_value(response)
        .unwrap()
        .get("desktopRedundancyV1")
        .is_none());
}
