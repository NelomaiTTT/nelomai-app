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
    requests: StdMutex<Vec<RedundantStopRequest>>,
}
#[async_trait]
impl CoreApi for Panel {
    async fn bootstrap(&self, _: &AccessSnapshot) -> Result<Bootstrap, CoreApiError> {
        panic!("no bootstrap")
    }
    async fn start_connection(
        &self,
        _: &AccessSnapshot,
        _: &ConnectionStartRequest,
    ) -> Result<ConnectionStartResponse, CoreApiError> {
        panic!("no lease before reconciliation")
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
        Ok(ConnectionOperationResponse {
            api_version: ApiVersion::V1,
            request_id: "cold-cleanup".into(),
            connection: self.stopped.clone(),
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
        panic!("no discovery")
    }
    async fn probe_latency_ms(&self, _: &str) -> Option<f64> {
        panic!("no probes")
    }
}

struct Helper {
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
    async fn status(&self) -> Result<TunnelStatus, TunnelError> {
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
    app: App,
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
        warm_stop_v1: false,
    };
    let helper = Arc::new(Helper {
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
        requests: StdMutex::new(Vec::new()),
    });
    let app = ClientApplication::new(
        panel.clone(),
        journal.clone(),
        Arc::new(Auth(access)),
        CoreLocalStop::new(helper.clone()),
        Arc::new(NoopLogger),
    );
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
    state.armed = true;
    state.owned_lease_id = Some(current.lease_id.clone());
    assert!(queue_redundant_recovery(
        &mut state, generation, &current, snapshot, 20
    ));
    Fixture {
        app,
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
