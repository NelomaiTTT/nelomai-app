//! Real App/Core/intent composition; only auth, storage, panel and helper I/O
//! are injected. No UI, filesystem journal, native routes or singleton calls.
use super::*;
use async_trait::async_trait;
use nelomai_client_api::{AccessSnapshot, RuntimeAuthState, RuntimeLogin};
use nelomai_client_application::{ApplicationApi, ClientApplication};
use nelomai_client_core::{CoreApi, CoreLocalStop, NoopLogger, RuntimeAuthProvider};
use nelomai_client_storage::{
    RuntimeAuthScope, RuntimePaths, RuntimeStateStore, RuntimeStateV1, StorageError,
    StoredDesktopRedundancy,
};
use nelomai_client_tunnel::{
    redundancy::{protocol::Command, session::SessionState, SessionScope, Slot},
    TunnelController, TunnelError, TunnelStartRequest, TunnelStatus,
};
use nelomai_contracts::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex as StdMutex,
};

struct Auth(AccessSnapshot);
#[async_trait]
impl RuntimeAuthProvider for Auth {
    async fn state(&self) -> Result<RuntimeAuthState, CoreError> {
        Ok(RuntimeAuthState::Active)
    }
    async fn access(&self, _: Option<&AccessSnapshot>) -> Result<AccessSnapshot, CoreError> {
        Ok(self.0.clone())
    }
    async fn login(&self, _: RuntimeLogin) -> Result<AccessSnapshot, CoreError> {
        panic!("no login")
    }
    async fn logout(&self) -> Result<(), CoreError> {
        panic!("no logout")
    }
}

struct Journal {
    paths: RuntimePaths,
    value: StdMutex<RuntimeStateV1>,
    lose_ack: AtomicBool,
    lost_ack_write: StdMutex<Option<RuntimeStateV1>>,
}
impl RuntimeStateStore for Journal {
    fn paths(&self) -> &RuntimePaths {
        &self.paths
    }
    fn load(&self) -> Result<Option<RuntimeStateV1>, StorageError> {
        Ok(Some(self.value.lock().unwrap().clone()))
    }
    fn save(&self, value: &RuntimeStateV1) -> Result<(), StorageError> {
        *self.value.lock().unwrap() = value.clone();
        if self.lose_ack.swap(false, Ordering::SeqCst) {
            *self.lost_ack_write.lock().unwrap() = Some(value.clone());
            return Err(StorageError::RecoveryRequired(
                "write persisted; acknowledgement lost",
            ));
        }
        Ok(())
    }
}

struct Panel {
    stopped: Connection,
    current: Connection,
    fail_stop: AtomicBool,
    async_stop: AtomicBool,
    starts: StdMutex<Vec<ConnectionStartRequest>>,
    requests: StdMutex<Vec<RedundantStopRequest>>,
}
#[async_trait]
impl CoreApi for Panel {
    async fn bootstrap(&self, _: &AccessSnapshot) -> Result<Bootstrap, CoreApiError> {
        let mut bootstrap: Bootstrap = serde_json::from_str(include_str!(
            "../../contracts/fixtures/valid/bootstrap.json"
        ))
        .unwrap();
        bootstrap.connection = Some(self.current.clone());
        Ok(bootstrap)
    }
    async fn start_connection(
        &self,
        _: &AccessSnapshot,
        request: &ConnectionStartRequest,
    ) -> Result<ConnectionStartResponse, CoreApiError> {
        self.starts.lock().unwrap().push(request.clone());
        let mut response: ConnectionStartResponse = serde_json::from_str(include_str!(
            "../../contracts/fixtures/valid/connection-start-redundant-response.json"
        ))
        .unwrap();
        let session = response.redundancy.as_mut().unwrap();
        session.session_id = "40000000-0000-4000-8000-000000000001".into();
        session.standby = None;
        response.connection.lease_id = "40000000-0000-4000-8000-000000000002".into();
        response.connection.session_id = Some(session.session_id.clone());
        response
            .configuration
            .push_str("[Peer]\nEndpoint = 192.0.2.1:51820\n");
        Ok(response)
    }
    async fn stop_connection(
        &self,
        _: &AccessSnapshot,
        _: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        panic!("no singleton Stop")
    }
    async fn pin_stray(
        &self,
        _: &AccessSnapshot,
        _: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        panic!("no pin")
    }
    async fn unpin_stray(
        &self,
        _: &AccessSnapshot,
        _: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        panic!("no unpin")
    }
    async fn stop_redundant_connection(
        &self,
        _: &AccessSnapshot,
        request: &RedundantStopRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        self.requests.lock().unwrap().push(request.clone());
        if self.fail_stop.load(Ordering::SeqCst) {
            return Err(CoreApiError::Retryable);
        }
        Ok(ConnectionOperationResponse {
            stop_acceptance: self.async_stop.load(Ordering::SeqCst).then(|| {
                assert!(request.background_cleanup);
                ClientStopAcceptance {
                    operation_id: request.operation_id.clone(),
                    session_id: request.session_id.clone(),
                    lease_id: request.lease_id.clone(),
                    accepted: true,
                    cleanup_pending: true,
                }
            }),
            api_version: ApiVersion::V1,
            request_id: "cold-cleanup".into(),
            connection: if self.async_stop.load(Ordering::SeqCst) {
                let mut accepted = self.current.clone();
                accepted.lease_id = request.lease_id.clone();
                accepted.status = LeaseStatus::Issued;
                accepted
            } else if request.lease_id == self.stopped.lease_id {
                self.stopped.clone()
            } else {
                let mut stopped = self.current.clone();
                stopped.lease_id = request.lease_id.clone();
                stopped.status = LeaseStatus::Released;
                stopped.session_id = None;
                stopped.stopped_at = self.stopped.stopped_at.clone();
                stopped
            },
        })
    }
}
#[async_trait]
impl ApplicationApi for Panel {
    async fn peer_options(&self, _: &AccessSnapshot) -> Result<PeerOptions, CoreApiError> {
        panic!("no peers")
    }
    async fn bind_peer(
        &self,
        _: &AccessSnapshot,
        _: &BindPeerRequest,
    ) -> Result<PeerBindingResponse, CoreApiError> {
        panic!("no bind")
    }
    async fn unbind_peer(&self, _: &AccessSnapshot) -> Result<PeerBindingResponse, CoreApiError> {
        panic!("no unbind")
    }
    async fn server_candidates(
        &self,
        _: &AccessSnapshot,
        _: Layer,
        _: EgressMode,
    ) -> Result<ServerCandidatesResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
    async fn probe_latency_ms(&self, _: &str) -> Option<f64> {
        panic!("no probes")
    }
}

struct Helper {
    crashed: AtomicBool,
    unknown: AtomicBool,
    starts: std::sync::atomic::AtomicUsize,
    snapshot: StdMutex<PairSnapshot>,
    fail_close: AtomicBool,
}
#[async_trait]
impl TunnelController for Helper {
    async fn start(&self, _: TunnelStartRequest) -> Result<(), TunnelError> {
        panic!("no singleton Start")
    }
    async fn stop(&self) -> Result<(), TunnelError> {
        panic!("no singleton Stop")
    }
    async fn stop_if_unowned(&self) -> Result<(), TunnelError> {
        assert!(self.crashed.load(Ordering::SeqCst));
        Ok(())
    }
    async fn desktop_redundancy_absent(&self) -> Result<bool, TunnelError> {
        Ok(self.crashed.load(Ordering::SeqCst) && !self.unknown.load(Ordering::SeqCst))
    }
    async fn desktop_redundancy_supported(&self) -> Result<bool, TunnelError> {
        Ok(true)
    }
    async fn status(&self) -> Result<TunnelStatus, TunnelError> {
        if self.unknown.load(Ordering::SeqCst) {
            return Err(TunnelError::Backend("status_unavailable".into()));
        }
        if self.crashed.load(Ordering::SeqCst) {
            return Ok(TunnelStatus::Stopped);
        }
        Ok(
            if self.snapshot.lock().unwrap().session.phase == SessionPhase::Stopped {
                TunnelStatus::Stopped
            } else {
                TunnelStatus::Running
            },
        )
    }
    async fn desktop_redundancy_command(
        &self,
        command: Command,
    ) -> Result<PairSnapshot, TunnelError> {
        if let Command::Start {
            scope,
            primary,
            role_generation,
            membership_generation,
            ..
        } = &command
        {
            let mut native = SessionState::new(
                scope.clone(),
                Slot::A,
                *role_generation,
                *membership_generation,
            )
            .unwrap();
            native.primary_started(scope).unwrap();
            let snapshot = PairSnapshot {
                session: native.snapshot(),
                leases: [Some(primary.lease_id.clone()), None],
                current_leases: [Some(primary.lease_id.clone()), None],
                primary_ready: true,
                standby_ready: false,
                standby_failed: false,
                stalled: false,
                cleanup_pending: false,
                retirement_pending: false,
                warm_stop_v1: false,
            };
            *self.snapshot.lock().unwrap() = snapshot.clone();
            self.crashed.store(false, Ordering::SeqCst);
            self.starts.fetch_add(1, Ordering::SeqCst);
            return Ok(snapshot);
        }
        if self.crashed.load(Ordering::SeqCst) {
            return Err(TunnelError::Backend("engine_not_running".into()));
        }
        let mut snapshot = self.snapshot.lock().unwrap();
        assert_eq!(command.scope(), &snapshot.session.scope);
        match command {
            Command::Status { .. } => (),
            Command::PrepareRecoveryStop {
                expected_revision,
                expected_network_epoch,
                ..
            } => {
                assert_eq!(expected_revision, snapshot.session.local_revision);
                assert_eq!(expected_network_epoch, snapshot.session.network_epoch);
                assert!(snapshot.stalled && !snapshot.primary_ready);
                if snapshot.session.phase == SessionPhase::Running {
                    snapshot.session.phase = SessionPhase::Stopping;
                    snapshot.session.local_revision += 1;
                }
            }
            Command::Stop { .. } => {
                if self.fail_close.load(Ordering::SeqCst) {
                    return Err(TunnelError::Backend("cleanup pending".into()));
                }
                snapshot.session.phase = SessionPhase::Stopped;
                snapshot.session.installed = [false; 2];
                snapshot.session.committed = [false; 2];
                snapshot.session.local_revision += 1;
            }
            _ => panic!("no manual freeze, adoption or native Start"),
        }
        Ok(snapshot.clone())
    }
}

type App = ClientApplication<Panel, Journal, Helper, NoopLogger>;
struct Fixture {
    app: Arc<App>,
    writers: Arc<nelomai_client_core::RuntimeWriterGates>,
    state: Mutex<RuntimeState>,
    journal: Arc<Journal>,
    helper: Arc<Helper>,
    panel: Arc<Panel>,
    generation: IntentGeneration,
}
fn fixture(lose_ack: bool) -> Fixture {
    let response: ConnectionStartResponse = serde_json::from_str(include_str!(
        "../../contracts/fixtures/valid/connection-start-redundant-response.json"
    ))
    .unwrap();
    let session = response.redundancy.unwrap();
    let mut current = response.connection;
    current.session_id = Some(session.session_id.clone());
    current.status = LeaseStatus::Connected;
    let mut stopped = session.standby.as_ref().unwrap().connection.clone();
    // A full session Stop receipt has no remaining session association.
    stopped.session_id = None;
    stopped.status = LeaseStatus::Released;
    stopped.stopped_at = Some("2026-09-27T00:00:00Z".into());
    let access = AccessSnapshot::new(
        "synthetic-access".into(),
        RuntimeIdentity {
            slot: RuntimeSlot::Latest,
            runtime_version: "0.3.3".into(),
            container_version: "0.3.3".into(),
            runtime_contract_version: 1,
            session_generation: Some(1),
        },
        0,
        "synthetic-family".into(),
    )
    .unwrap();
    let paths = RuntimePaths::new(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../.tmp/recovery-test-no-io"),
        RuntimeSlot::Latest,
        "0.3.3",
    )
    .unwrap();
    let mut value = RuntimeStateV1::empty(&paths, false);
    value.auth_scope = Some(RuntimeAuthScope {
        auth_epoch: access.auth_epoch(),
        family: access.family().into(),
        identity: access.identity().clone(),
    });
    value.desktop_redundancy = Some(StoredDesktopRedundancy {
        primary_reported: true,
        runtime_generation: 1,
        connection_generation: 7,
        start_operation_id: "30000000-0000-4000-8000-000000000001".into(),
        request_fingerprint: "ab".repeat(32),
        connection: current.clone(),
        session,
        pending_acquire: None,
        candidate: None,
        stop: None,
    });
    let scope = SessionScope {
        runtime: RuntimeSlot::Latest,
        runtime_generation: 1,
        connection_generation: 7,
        session_id: current.session_id.clone().unwrap(),
    };
    let mut native = SessionState::new(scope.clone(), Slot::B, 0, 0).unwrap();
    native.primary_started(&scope).unwrap();
    native
        .standby_installed(native.install_ticket(&scope, Slot::A).unwrap(), 0)
        .unwrap();
    let leases = [
        Some(current.lease_id.clone()),
        Some(stopped.lease_id.clone()),
    ];
    let snapshot = PairSnapshot {
        session: native.snapshot(),
        current_leases: leases.clone(),
        leases,
        primary_ready: false,
        standby_ready: false,
        standby_failed: true,
        stalled: true,
        cleanup_pending: false,
        retirement_pending: false,
        warm_stop_v1: false,
    };
    let helper = Arc::new(Helper {
        crashed: AtomicBool::new(false),
        unknown: AtomicBool::new(false),
        starts: std::sync::atomic::AtomicUsize::new(0),
        snapshot: StdMutex::new(snapshot.clone()),
        fail_close: AtomicBool::new(true),
    });
    let journal = Arc::new(Journal {
        paths,
        value: StdMutex::new(value),
        lose_ack: AtomicBool::new(lose_ack),
        lost_ack_write: StdMutex::new(None),
    });
    let panel = Arc::new(Panel {
        stopped,
        current: current.clone(),
        fail_stop: AtomicBool::new(false),
        async_stop: AtomicBool::new(false),
        starts: StdMutex::new(Vec::new()),
        requests: StdMutex::new(Vec::new()),
    });
    let local = CoreLocalStop::new(helper.clone());
    let writers = local.runtime_writer_gates();
    let app = Arc::new(ClientApplication::new(
        panel.clone(),
        journal.clone(),
        Arc::new(Auth(access)),
        local,
        Arc::new(NoopLogger),
    ));
    let mut state = RuntimeState::default();
    let options = quick_toggle_placeholder_options();
    let StartDisposition::Recovering { generation, .. } = state
        .coordinator
        .start_or_resume(options.clone(), 10)
        .unwrap()
    else {
        panic!("new intent")
    };
    initialize_episode(&mut state, options, generation, 10, true);
    assert!(state.coordinator.begin_attempt(generation));
    assert_eq!(
        state
            .coordinator
            .mark_connected(generation, current.clone()),
        RecoveryDecision::Accept
    );
    state.cancel_epoch = Some(app.start_cancellation_epoch());
    state.armed = true;
    state.owned_lease_id = Some(current.lease_id.clone());
    assert!(queue_redundant_recovery(
        &mut state, generation, &current, snapshot, 20
    ));
    Fixture {
        app,
        writers,
        state: Mutex::new(state),
        journal,
        helper,
        panel,
        generation,
    }
}

#[tokio::test]
async fn redundant_stall_accepted_receipt_survives_cleanup_before_start_attempt() {
    for lose_ack in [false, true] {
        let f = fixture(lose_ack);
        let app = &f.app;
        let run = advance_redundant_recovery(
            &f.state,
            20,
            || f.app.desktop_redundancy_status(),
            |snapshot| async move { app.prepare_desktop_recovery(&snapshot).await },
        )
        .await;
        assert_eq!(
            run,
            Some(f.generation),
            "durable cold request is acceptance even when native close needs retry"
        );
        let stored = f.journal.value.lock().unwrap().clone();
        let pending = stored.pending_compensation_stop.as_ref().unwrap();
        let stop = stored
            .desktop_redundancy
            .as_ref()
            .unwrap()
            .stop
            .as_ref()
            .unwrap();
        assert_eq!(pending.lease_id, "20000000-0000-4000-8000-000000000003");
        assert_eq!(
            pending.redundant_session_id.as_deref(),
            Some("20000000-0000-4000-8000-000000000001")
        );
        assert_eq!(pending.recovery_contract_version, Some(2));
        assert!(!pending.accept_warm && !stop.retain_active_peer);
        assert_eq!(stop.operation_id, pending.operation_id);
        if lose_ack {
            assert!(
                f.journal.lost_ack_write.lock().unwrap().as_ref() == Some(&stored),
                "complete actual write, not inferred stop metadata"
            );
        }
        // Acceptance is not completion: the very same reconciliation used by
        // run_attempt must reject while the scoped native close still fails.
        assert!(f.app.reconcile_pending_operation_for_retry().await.is_err());
        assert_eq!(
            f.journal
                .value
                .lock()
                .unwrap()
                .pending_compensation_stop
                .as_ref(),
            Some(pending)
        );
        f.helper.fail_close.store(false, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_millis(50), f.app.wait_for_pending_stop())
            .await
            .unwrap();
        assert!(f.app.retry_pending_stop().await.unwrap().is_some());
        assert!(f.journal.value.lock().unwrap().desktop_redundancy.is_none());
        assert!(f.app.desktop_redundancy_status().await.unwrap().is_none());
        f.app.reconcile_pending_operation_for_retry().await.unwrap();
        let expected = RedundantStopRequest {
            background_cleanup: false,
            operation_id: pending.operation_id.clone(),
            lease_id: pending.lease_id.clone(),
            session_id: pending.redundant_session_id.clone().unwrap(),
            recovery_contract_version: RecoveryContractV2,
            retain_active_peer: false,
        };
        {
            let requests = f.panel.requests.lock().unwrap();
            assert!(!requests.is_empty());
            assert!(
                requests.iter().all(|request| request == &expected),
                "worker must replay the exact persisted request"
            );
        }
        assert_eq!(
            advance_redundant_recovery(
                &f.state,
                21,
                || async { panic!("accepted receipt needs no later Status") },
                |_| async { panic!("no second prepare") }
            )
            .await,
            None
        );
        let mut state = f.state.lock().await;
        assert_eq!(
            state.coordinator.status(),
            ConnectionIntentStatus::Recovering
        );
        assert_eq!(state.attempt_kind, AttemptKind::Start);
        assert!(state.reconcile_before_attempt && state.reserve_requested);
        assert!(state.coordinator.begin_attempt(run.unwrap()));
    }
}

#[tokio::test]
async fn redundant_stall_actual_lost_ack_receipt_does_not_override_user_stop() {
    let f = fixture(true);
    let fixture = &f;
    let run = advance_redundant_recovery(
        &f.state,
        20,
        || f.app.desktop_redundancy_status(),
        |snapshot| async move {
            let accepted = fixture.app.prepare_desktop_recovery(&snapshot).await;
            assert!(matches!(accepted, Ok(true)));
            assert!(fixture
                .state
                .lock()
                .await
                .coordinator
                .cancel_intent(fixture.generation));
            accepted
        },
    )
    .await;
    assert_eq!(run, None);
    let mut state = f.state.lock().await;
    assert!(!state.coordinator.begin_attempt(f.generation));
    assert!(!state.reconcile_before_attempt);
    assert!(f
        .journal
        .value
        .lock()
        .unwrap()
        .pending_compensation_stop
        .is_some());
}

#[tokio::test]
async fn engine_crash_cleanup_preserves_original_start_cancellation_epoch() {
    let f = fixture(false);
    f.app
        .bootstrap_without_refresh(1_800_000_000)
        .await
        .unwrap();
    assert_eq!(f.app.state().await.phase, Phase::Connected);
    let original_epoch = f.app.begin_start_attempt();
    f.app.finish_start_attempt();
    f.helper.crashed.store(true, Ordering::SeqCst);
    let observation = f.app.begin_foreground_observation().await;
    assert_eq!(
        f.app
            .foreground_state_guarded(observation, None, || true)
            .await
            .phase,
        Phase::Stopping
    );
    let completion = f.app.retry_pending_stop().await.unwrap().unwrap();
    let mut intent = f.state.lock().await;
    intent.pending_redundant_recovery = None;
    assert!(queue_engine_recovery(&mut intent, &completion, 22));
    assert_eq!(intent.cancel_epoch, Some(original_epoch));
    assert_eq!(intent.next_retry_at_unix, Some(22));
    assert!(intent.reserve_requested);
    assert!(
        !queue_engine_recovery(&mut intent, &completion, 22),
        "receipt is consumed once"
    );
    let after_cleanup = f.app.begin_start_attempt();
    f.app.finish_start_attempt();
    assert_eq!(
        original_epoch, after_cleanup,
        "background cleanup must not impersonate a user Stop and cancel recovery"
    );
    assert!(f.journal.value.lock().unwrap().desktop_redundancy.is_none());
    assert!(!f.panel.requests.lock().unwrap()[0].retain_active_peer);
}

#[tokio::test]
async fn engine_cleanup_receipt_cannot_restart_after_logout_signal_before_owner_reply() {
    let f = fixture(false);
    f.app
        .bootstrap_without_refresh(1_800_000_000)
        .await
        .unwrap();
    f.helper.crashed.store(true, Ordering::SeqCst);
    let observation = f.app.begin_foreground_observation().await;
    f.app
        .foreground_state_guarded(observation, None, || true)
        .await;
    let completion = f.app.retry_pending_stop().await.unwrap().unwrap();
    let mut state = f.state.lock().await;
    assert!(queue_engine_recovery(&mut state, &completion, 22));
    let options = state.options.clone().unwrap();
    let epoch = state.cancel_epoch.unwrap();
    drop(state);
    // This is the immediate signal used by Stop and Core::sign_out, before
    // either operation waits for a lifecycle gate or the protected owner.
    f.app.signal_start_cancellation();
    assert!(matches!(
        f.app
            .desktop_connection_intent_attempt_at_epoch(options, 1_800_000_001, true, epoch, || {
                true
            },)
            .await,
        Err(ApplicationError::Core(CoreError::StartCancelled))
    ));
}

#[tokio::test]
async fn manual_stop_cleanup_does_not_arm_engine_recovery() {
    let f = fixture(false);
    f.app
        .bootstrap_without_refresh(1_800_000_000)
        .await
        .unwrap();
    f.helper.crashed.store(true, Ordering::SeqCst);
    f.app.stop().await.unwrap();
    let completion = f.app.retry_pending_stop().await.unwrap().unwrap();
    assert!(!queue_engine_recovery(
        &mut *f.state.lock().await,
        &completion,
        22
    ));
}

#[tokio::test]
async fn engine_cleanup_receipt_rejects_changed_session_and_intent() {
    for changed in ["session", "epoch", "generation"] {
        let f = fixture(false);
        f.app
            .bootstrap_without_refresh(1_800_000_000)
            .await
            .unwrap();
        f.helper.crashed.store(true, Ordering::SeqCst);
        let observation = f.app.begin_foreground_observation().await;
        f.app
            .foreground_state_guarded(observation, None, || true)
            .await;
        let mut completion = f.app.retry_pending_stop().await.unwrap().unwrap();
        let mut state = f.state.lock().await;
        match changed {
            "session" => {
                completion.cleaned_pair.as_mut().unwrap().session_id = "another-session".into()
            }
            "epoch" => {
                f.app.signal_start_cancellation();
                completion.cancel_epoch = f.app.start_cancellation_epoch();
            }
            "generation" => {
                state.coordinator.cancel_intent(f.generation);
            }
            _ => unreachable!(),
        }
        assert!(
            !queue_engine_recovery(&mut state, &completion, 22),
            "{changed}"
        );
    }
}

#[tokio::test]
async fn engine_crash_restarts_same_intent_only_after_cold_cleanup_retry() {
    let f = fixture(false);
    f.app
        .bootstrap_without_refresh(1_800_000_000)
        .await
        .unwrap();
    f.helper.crashed.store(true, Ordering::SeqCst);
    f.helper.unknown.store(true, Ordering::SeqCst);
    assert!(
        f.app.retry_pending_stop().await.unwrap().is_none(),
        "unknown helper is not proof of an outage"
    );
    assert!(f.panel.requests.lock().unwrap().is_empty());
    f.helper.unknown.store(false, Ordering::SeqCst);
    f.panel.fail_stop.store(true, Ordering::SeqCst);
    assert!(f.app.retry_pending_stop().await.is_err());
    assert!(f
        .journal
        .value
        .lock()
        .unwrap()
        .pending_compensation_stop
        .is_some());
    assert_eq!(f.helper.starts.load(Ordering::SeqCst), 0);
    f.panel.fail_stop.store(false, Ordering::SeqCst);
    let completion = f.app.retry_pending_stop().await.unwrap().unwrap();
    let mut state = f.state.lock().await;
    assert!(queue_engine_recovery(&mut state, &completion, 22));
    let options = state.options.clone().unwrap();
    let epoch = state.cancel_epoch.unwrap();
    assert!(state.coordinator.begin_attempt(f.generation));
    drop(state);
    f.app.reconcile_pending_operation_for_retry().await.unwrap();
    let connection = f
        .app
        .desktop_connection_intent_attempt_at_epoch(options, 1_800_000_001, true, epoch, || true)
        .await
        .unwrap();
    assert_eq!(
        connection.session_id.as_deref(),
        Some("40000000-0000-4000-8000-000000000001")
    );
    assert_eq!(f.helper.starts.load(Ordering::SeqCst), 1);
    assert_eq!(f.app.state().await.phase, Phase::Connected);
    assert_eq!(
        f.state
            .lock()
            .await
            .coordinator
            .mark_connected(f.generation, connection),
        RecoveryDecision::Accept
    );
    let requests = f.panel.requests.lock().unwrap();
    assert!(requests.len() >= 2);
    assert!(
        requests.iter().all(|request| request == &requests[0]),
        "partial cleanup replays exact operation"
    );
    assert!(!requests[0].retain_active_peer);
    let starts = f.panel.starts.lock().unwrap();
    assert_eq!(starts.len(), 1);
    assert_eq!(starts[0].reserve_enabled, Some(true));
}

#[tokio::test]
async fn engine_cleanup_acceptance_and_changed_member_preserve_recovery() {
    for changed_member in [false, true] {
        let f = fixture(false);
        f.app
            .bootstrap_without_refresh(1_800_000_000)
            .await
            .unwrap();
        {
            let mut stored = f.journal.value.lock().unwrap();
            let pair = stored.desktop_redundancy.as_mut().unwrap();
            pair.session.async_stop_v1 = !changed_member;
            if changed_member {
                pair.connection.lease_id = "50000000-0000-4000-8000-000000000002".into();
            }
        }
        f.panel.async_stop.store(!changed_member, Ordering::SeqCst);
        f.helper.crashed.store(true, Ordering::SeqCst);
        let completion = f.app.retry_pending_stop().await.unwrap().unwrap();
        assert!(f.journal.value.lock().unwrap().desktop_redundancy.is_none());
        let mut state = f.state.lock().await;
        assert!(
            queue_engine_recovery(&mut state, &completion, 22),
            "changed_member={changed_member}"
        );
        let options = state.options.clone().unwrap();
        let epoch = state.cancel_epoch.unwrap();
        drop(state);
        f.app.reconcile_pending_operation_for_retry().await.unwrap();
        f.app
            .desktop_connection_intent_attempt_at_epoch(options, 1_800_000_001, true, epoch, || {
                true
            })
            .await
            .unwrap();
        assert_eq!(f.helper.starts.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn queued_engine_restart_cannot_adopt_new_epoch_after_busy_lifecycle_gate() {
    let f = fixture(false);
    let epoch = f.app.start_cancellation_epoch();
    let gate = f.writers.lifecycle();
    let held = gate.lock().await;
    let app = f.app.clone();
    let mut attempt = tokio::spawn(async move {
        app.desktop_connection_intent_attempt_at_epoch(
            quick_toggle_placeholder_options(),
            1_800_000_001,
            true,
            epoch,
            || true,
        )
        .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut attempt)
            .await
            .is_err()
    );
    f.app.signal_start_cancellation();
    drop(held);
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), attempt)
            .await
            .unwrap()
            .unwrap(),
        Err(ApplicationError::Core(CoreError::StartCancelled))
    ));
    assert!(f.panel.starts.lock().unwrap().is_empty());
    assert_eq!(f.helper.starts.load(Ordering::SeqCst), 0);
}
