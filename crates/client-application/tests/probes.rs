mod support;
use async_trait::async_trait;
use nelomai_client_api::AccessSnapshot;
use nelomai_client_api::{LoginRequest, TokenResponse};
use nelomai_client_application::{ApplicationApi, ApplicationError, ClientApplication};
use nelomai_client_core::{
    ConnectOptions, CoreApi, CoreApiError, CoreError, CoreLocalStop, NoopLogger,
    RuntimeStartPreflight,
};
use nelomai_client_storage::{
    MemorySplitTunnelStore, SecretStore, StorageError, StoredAuth, StoredCompatibility,
};
use nelomai_client_tunnel::{TunnelController, TunnelError, TunnelStartRequest, TunnelStatus};
use nelomai_contracts::{
    ApiVersion, BindPeerRequest, Bootstrap, Connection, ConnectionOperationRequest,
    ConnectionOperationResponse, ConnectionStartRequest, ConnectionStartResponse, EgressMode,
    Layer, LeaseStatus, PeerBindingResponse, PeerOptions, ProbeResult, RouteMode, ServerCandidate,
    ServerCandidatesResponse, TicConnectionMode,
};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};

struct ProbeApi {
    candidate_calls: AtomicUsize,
    probe_calls: AtomicUsize,
    all_probes_fail: AtomicBool,
    start_request: Mutex<Option<ConnectionStartRequest>>,
    candidate_modes: Mutex<Vec<EgressMode>>,
    candidate_failure: AtomicBool,
    acquire_requests: Mutex<Vec<nelomai_contracts::RedundantStandbyAcquireRequest>>,
}

#[async_trait]
impl CoreApi for ProbeApi {
    async fn acquire_redundant_standby(
        &self,
        _access_token: &AccessSnapshot,
        request: &nelomai_contracts::RedundantStandbyAcquireRequest,
    ) -> Result<nelomai_contracts::RedundantStandbyAcquireResponse, CoreApiError> {
        self.acquire_requests.lock().unwrap().push(request.clone());
        Err(CoreApiError::Retryable)
    }
    async fn bootstrap(&self, _access_token: &AccessSnapshot) -> Result<Bootstrap, CoreApiError> {
        unreachable!("bootstrap is not used by this test")
    }

    async fn start_connection(
        &self,
        _access_token: &AccessSnapshot,
        request: &ConnectionStartRequest,
    ) -> Result<ConnectionStartResponse, CoreApiError> {
        *self.start_request.lock().unwrap() = Some(request.clone());
        Ok(ConnectionStartResponse {
            api_version: ApiVersion::V1,
            request_id: "start-request".to_string(),
            connection: Connection {
                lease_id: "lease-1".to_string(),
                session_id: None,
                pool_id: None,
                layer: request.layer,
                transport_protocol: Default::default(),
                tic_connection_mode: request.tic_connection_mode,
                route_mode: request.route_mode,
                egress_mode: request.egress_mode,
                probe_url: Some("https://1a.example.test/probe".to_string()),
                status: LeaseStatus::Issued,
                pinned: false,
                stopped_at: None,
            },
            configuration: "PrivateKey = test".to_string(),
            health_probe: None,
            reused: false,
            redundancy: None,
        })
    }

    async fn stop_connection(
        &self,
        _access_token: &AccessSnapshot,
        _request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        unreachable!("stop is not used by this test")
    }

    async fn pin_stray(
        &self,
        _access_token: &AccessSnapshot,
        _request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        unreachable!("pin is not used by this test")
    }

    async fn unpin_stray(
        &self,
        _access_token: &AccessSnapshot,
        _request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        unreachable!("unpin is not used by this test")
    }
}

#[async_trait]
impl ApplicationApi for ProbeApi {
    async fn peer_options(
        &self,
        _access_token: &AccessSnapshot,
    ) -> Result<PeerOptions, CoreApiError> {
        unreachable!("peer options are not used by this test")
    }

    async fn bind_peer(
        &self,
        _access_token: &AccessSnapshot,
        _request: &BindPeerRequest,
    ) -> Result<PeerBindingResponse, CoreApiError> {
        unreachable!("peer binding is not used by this test")
    }

    async fn unbind_peer(
        &self,
        _access_token: &AccessSnapshot,
    ) -> Result<PeerBindingResponse, CoreApiError> {
        unreachable!("peer unbinding is not used by this test")
    }

    async fn server_candidates(
        &self,
        _access_token: &AccessSnapshot,
        layer: Layer,
        egress_mode: EgressMode,
    ) -> Result<ServerCandidatesResponse, CoreApiError> {
        self.candidate_calls.fetch_add(1, Ordering::SeqCst);
        self.candidate_modes.lock().unwrap().push(egress_mode);
        if self.candidate_failure.load(Ordering::SeqCst) {
            return Err(CoreApiError::Retryable);
        }
        Ok(ServerCandidatesResponse {
            api_version: ApiVersion::V1,
            request_id: "candidate-request".to_string(),
            candidates: vec![
                candidate("candidate-fast", layer, "https://fast.example/probe"),
                candidate("candidate-down", layer, "https://down.example/probe"),
            ],
        })
    }

    async fn probe_latency_ms(&self, probe_url: &str) -> Option<f64> {
        self.probe_calls.fetch_add(1, Ordering::SeqCst);
        (!self.all_probes_fail.load(Ordering::SeqCst) && probe_url.contains("fast")).then_some(24.5)
    }
}

#[tokio::test]
async fn probe_cache_is_separate_for_ipv4_and_ipv6_pools() {
    let (application, api) = application();

    application
        .refresh_probes(Layer::Tic, EgressMode::Ipv4, 1_800_000_000)
        .await
        .unwrap();
    application
        .refresh_probes(Layer::Tic, EgressMode::PreferIpv6, 1_800_000_001)
        .await
        .unwrap();

    assert_eq!(api.candidate_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        *api.candidate_modes.lock().unwrap(),
        vec![EgressMode::Ipv4, EgressMode::PreferIpv6]
    );
}

#[cfg(not(target_os = "android"))]
#[tokio::test]
async fn automatic_attempts_defer_when_power_changes_during_probes() {
    for (replacement, probes_fail) in [(false, false), (false, true), (true, false), (true, true)] {
        let (application, api) = application();
        api.all_probes_fail.store(probes_fail, Ordering::SeqCst);
        let options = ConnectOptions {
            layer: Layer::Stray,
            tic_connection_mode: TicConnectionMode::Dynamic,
            route_mode: RouteMode::Standalone,
            egress_mode: EgressMode::Ipv4,
            probes: Vec::new(),
            allow_alternate: true,
        };
        // Initially allowed; the actual probe phase crosses into a deferred state.
        let allowed = || api.probe_calls.load(Ordering::SeqCst) == 0;
        assert!(allowed());
        let result = if replacement {
            application
                .replace_stalled_connection_guarded(options.clone(), 1_800_000_000, allowed)
                .await
        } else {
            application
                .connection_intent_attempt_guarded(options.clone(), 1_800_000_000, allowed)
                .await
        };
        assert!(
            matches!(result, Err(ApplicationError::RecoveryDeferred)),
            "{result:?}"
        );
        assert!(api.start_request.lock().unwrap().is_none());
        // Manual starts keep their existing path, even while the automatic guard denies.
        api.all_probes_fail.store(false, Ordering::SeqCst);
        assert!(application.start(options, 1_800_000_001).await.is_ok());
        assert!(api.start_request.lock().unwrap().is_some());
    }
}

#[derive(Default)]
struct MemoryStore(Mutex<Option<StoredAuth>>);

impl SecretStore for MemoryStore {
    fn load(&self) -> Result<Option<StoredAuth>, StorageError> {
        Ok(self.0.lock().unwrap().clone())
    }

    fn save(&self, auth: &StoredAuth) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = Some(auth.clone());
        Ok(())
    }

    fn delete(&self) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

struct StoppedTunnel;

#[cfg(not(target_os = "android"))]
#[tokio::test]
async fn desktop_reserve_never_falls_back_to_single_on_an_old_helper() {
    let (app, api) = application();
    let options = ConnectOptions::unix_desktop_default();
    let result = app
        .desktop_connection_intent_attempt_guarded(options, 1_800_000_000, true, || true)
        .await;
    assert!(
        matches!(result, Err(ApplicationError::Core(CoreError::Tunnel(ref code))) if code == "desktop_redundancy_unsupported")
    );
    assert!(api.start_request.lock().unwrap().is_none());
}

#[cfg(not(target_os = "android"))]
#[tokio::test]
async fn desktop_reserve_guard_cancels_before_any_start_and_old_caller_keeps_single_contract() {
    let (app, api) = application();
    let options = ConnectOptions::unix_desktop_default();
    assert!(matches!(
        app.desktop_connection_intent_attempt_guarded(options.clone(), 1_800_000_000, true, || {
            false
        })
        .await,
        Err(ApplicationError::RecoveryDeferred)
    ));
    assert!(api.start_request.lock().unwrap().is_none());
    let _ = app
        .connection_intent_attempt_guarded(options, 1_800_000_001, || true)
        .await;
    let request = api
        .start_request
        .lock()
        .unwrap()
        .clone()
        .expect("legacy panel request");
    assert_ne!(request.reserve_enabled, Some(true));
}

#[cfg(not(target_os = "android"))]
#[tokio::test]
async fn desktop_tick_and_status_do_not_refresh_probes_or_start_an_ordinary_tunnel() {
    let (app, api) = application();
    app.refresh_probes(Layer::Stray, EgressMode::Ipv4, 1_800_000_000)
        .await
        .unwrap();
    let calls = (
        api.candidate_calls.load(Ordering::SeqCst),
        api.probe_calls.load(Ordering::SeqCst),
    );
    for now in [1_800_000_001, 1_800_000_600, 1_900_000_000] {
        assert!(app.desktop_redundancy_tick(now).await.unwrap().is_none());
        assert!(app.desktop_redundancy_status().await.unwrap().is_none());
    }
    assert_eq!(
        (
            api.candidate_calls.load(Ordering::SeqCst),
            api.probe_calls.load(Ordering::SeqCst)
        ),
        calls
    );
    assert!(api.start_request.lock().unwrap().is_none());
}

#[cfg(not(target_os = "android"))]
mod desktop_reserve_probes {
    use super::*;
    use nelomai_client_storage::{
        RuntimeAuthScope, RuntimePaths, RuntimeStateStore, RuntimeStateV1, StoredDesktopRedundancy,
    };
    use nelomai_client_tunnel::redundancy::{
        protocol::{Command, Snapshot},
        session::SessionState,
        SessionScope, Slot,
    };
    use nelomai_contracts::RuntimeSlot;

    struct PairStore {
        paths: RuntimePaths,
        state: Mutex<RuntimeStateV1>,
    }
    impl RuntimeStateStore for PairStore {
        fn paths(&self) -> &RuntimePaths {
            &self.paths
        }
        fn load(&self) -> Result<Option<RuntimeStateV1>, StorageError> {
            Ok(Some(self.state.lock().unwrap().clone()))
        }
        fn save(&self, state: &RuntimeStateV1) -> Result<(), StorageError> {
            *self.state.lock().unwrap() = state.clone();
            Ok(())
        }
    }
    struct PairTunnel(Mutex<Snapshot>);
    #[async_trait]
    impl TunnelController for PairTunnel {
        async fn start(&self, _: TunnelStartRequest) -> Result<(), TunnelError> {
            panic!("no ordinary Start")
        }
        async fn stop(&self) -> Result<(), TunnelError> {
            panic!("no ordinary Stop")
        }
        async fn status(&self) -> Result<TunnelStatus, TunnelError> {
            Ok(TunnelStatus::Running)
        }
        async fn desktop_redundancy_command(
            &self,
            command: Command,
        ) -> Result<Snapshot, TunnelError> {
            let snapshot = self.0.lock().unwrap();
            assert_eq!(command.scope(), &snapshot.session.scope);
            assert!(
                matches!(command, Command::Status { .. }),
                "unexpected native effect"
            );
            Ok(snapshot.clone())
        }
    }
    type PairApp = ClientApplication<ProbeApi, PairStore, PairTunnel, NoopLogger>;
    fn pair_application() -> (PairApp, Arc<ProbeApi>, Arc<PairStore>, Arc<PairTunnel>) {
        let (_, api) = application();
        let response: ConnectionStartResponse = serde_json::from_str(include_str!(
            "../../../contracts/fixtures/valid/connection-start-redundant-response.json"
        ))
        .unwrap();
        let mut session = response.redundancy.unwrap();
        session.standby = None;
        let pair = StoredDesktopRedundancy {
            primary_reported: true,
            runtime_generation: 1,
            connection_generation: 1,
            start_operation_id: "30000000-0000-4000-8000-000000000001".into(),
            request_fingerprint: "ab".repeat(32),
            connection: response.connection,
            session,
            pending_acquire: None,
            candidate: None,
            stop: None,
        };
        let scope = SessionScope {
            runtime: RuntimeSlot::Stable,
            runtime_generation: 1,
            connection_generation: 1,
            session_id: pair.session.session_id.clone(),
        };
        let mut native = SessionState::new(
            scope.clone(),
            Slot::A,
            pair.session.role_generation,
            pair.session.membership_generation,
        )
        .unwrap();
        native.primary_started(&scope).unwrap();
        let tunnel = Arc::new(PairTunnel(Mutex::new(Snapshot {
            session: native.snapshot(),
            leases: [Some(pair.connection.lease_id.clone()), None],
            current_leases: [Some(pair.connection.lease_id.clone()), None],
            primary_ready: true,
            standby_ready: false,
            standby_failed: false,
            stalled: false,
            cleanup_pending: false,
            warm_stop_v1: pair.session.warm_stop_v1,
        })));
        let paths = RuntimePaths::new(
            "/synthetic-no-filesystem-access",
            RuntimeSlot::Stable,
            "0.2.16",
        )
        .unwrap();
        let mut state = RuntimeStateV1::empty(&paths, false);
        let access = support::snapshot("access-token");
        state.auth_scope = Some(RuntimeAuthScope {
            auth_epoch: access.auth_epoch(),
            family: access.family().into(),
            identity: access.identity().clone(),
        });
        state.desktop_redundancy = Some(pair);
        let store = Arc::new(PairStore {
            paths,
            state: Mutex::new(state),
        });
        let mut auth = StoredAuth::new_install();
        auth.access_token = Some("access-token".into());
        auth.refresh_token = Some("refresh-token".into());
        let auth_store = Arc::new(MemoryStore(Mutex::new(Some(auth))));
        let local = CoreLocalStop::new(tunnel.clone());
        let auth = Arc::new(support::TestOwner::new(
            api.clone(),
            auth_store,
            local.clone(),
        ));
        let app = ClientApplication::new(
            api.clone(),
            store.clone(),
            auth,
            local,
            Arc::new(NoopLogger),
        );
        (app, api, store, tunnel)
    }

    #[tokio::test]
    async fn missing_reserve_refreshes_expired_cache_before_measured_acquire() {
        let (app, api, store, _) = pair_application();
        let first = app
            .refresh_probes(Layer::Stray, EgressMode::Ipv4, 1_800_000_000)
            .await
            .unwrap();
        assert!(app.desktop_redundancy_tick(1_800_000_600).await.is_err()); // synthetic acquire failure
        assert_eq!(api.candidate_calls.load(Ordering::SeqCst), 2);
        let requests = api.acquire_requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let probes = &requests[0].probes;
        assert_eq!(probes.len(), 2);
        let fast = probes
            .iter()
            .find(|p| p.candidate_id == "candidate-fast")
            .unwrap();
        assert_eq!(fast.latency_ms, Some(24.5));
        assert_ne!(
            fast.measured_at,
            first
                .probes
                .iter()
                .find(|p| p.candidate_id == "candidate-fast")
                .unwrap()
                .measured_at
        );
        assert_eq!(
            store
                .state
                .lock()
                .unwrap()
                .desktop_redundancy
                .as_ref()
                .unwrap()
                .pending_acquire
                .as_ref()
                .unwrap()
                .probes,
            *probes
        );
        assert!(api.start_request.lock().unwrap().is_none());
    }
    #[tokio::test]
    async fn missing_reserve_refresh_error_never_sends_unmeasured_acquire() {
        let (app, api, store, _) = pair_application();
        app.refresh_probes(Layer::Stray, EgressMode::Ipv4, 1_800_000_000)
            .await
            .unwrap();
        api.candidate_failure.store(true, Ordering::SeqCst);
        assert!(app.desktop_redundancy_tick(1_800_000_600).await.is_err());
        assert!(api.acquire_requests.lock().unwrap().is_empty());
        assert!(store
            .state
            .lock()
            .unwrap()
            .desktop_redundancy
            .as_ref()
            .unwrap()
            .pending_acquire
            .is_none());
        assert_eq!(api.candidate_calls.load(Ordering::SeqCst), 2);
    }
    #[tokio::test]
    async fn missing_reserve_reuses_fresh_scoped_measurement() {
        let (app, api, store, _) = pair_application();
        {
            let mut state = store.state.lock().unwrap();
            let connection = &mut state.desktop_redundancy.as_mut().unwrap().connection;
            connection.layer = Layer::Tic;
            connection.egress_mode = EgressMode::PreferIpv6;
        }
        app.refresh_probes(Layer::Stray, EgressMode::Ipv4, 1_800_000_000)
            .await
            .unwrap();
        let measured = app
            .refresh_probes(Layer::Tic, EgressMode::PreferIpv6, 1_800_000_000)
            .await
            .unwrap();
        assert!(app.desktop_redundancy_tick(1_800_000_001).await.is_err());
        assert_eq!(api.candidate_calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            api.acquire_requests.lock().unwrap()[0].probes,
            measured.probes
        );
    }
    #[tokio::test]
    async fn pending_acquire_replay_refreshes_measurements_but_keeps_operation_identity() {
        let (app, api, store, _) = pair_application();
        let measured = app
            .refresh_probes(Layer::Stray, EgressMode::Ipv4, 1_800_000_000)
            .await
            .unwrap();
        let mut request = {
            let mut state = store.state.lock().unwrap();
            let pair = state.desktop_redundancy.as_mut().unwrap();
            let request = nelomai_contracts::RedundantStandbyAcquireRequest {
                operation_id: "30000000-0000-4000-8000-000000000002".into(),
                session_id: pair.session.session_id.clone(),
                expected_role_generation: 0,
                expected_membership_generation: 0,
                replace_lease_id: None,
                probes: measured.probes,
            };
            pair.pending_acquire = Some(request.clone());
            request
        };
        assert!(app.desktop_redundancy_tick(1_800_000_600).await.is_err());
        assert_eq!(api.candidate_calls.load(Ordering::SeqCst), 2);
        for probe in &mut request.probes {
            probe.measured_at = "2027-01-15T08:10:00Z".into();
        }
        assert_eq!(*api.acquire_requests.lock().unwrap(), vec![request.clone()]);
        assert_eq!(
            store
                .state
                .lock()
                .unwrap()
                .desktop_redundancy
                .as_ref()
                .unwrap()
                .pending_acquire,
            Some(request)
        );
    }
    #[tokio::test]
    async fn healthy_absent_stopping_and_candidate_pairs_never_refresh() {
        for case in ["healthy", "absent", "stopping", "candidate"] {
            let (app, api, store, tunnel) = pair_application();
            app.refresh_probes(Layer::Stray, EgressMode::Ipv4, 1_800_000_000)
                .await
                .unwrap();
            {
                let mut state = store.state.lock().unwrap();
                let mut native = tunnel.0.lock().unwrap();
                let pair = state.desktop_redundancy.as_mut().unwrap();
                match case {
                    "healthy" => {
                        let response: ConnectionStartResponse = serde_json::from_str(include_str!("../../../contracts/fixtures/valid/connection-start-redundant-response.json")).unwrap();
                        pair.session.standby = response.redundancy.unwrap().standby;
                        let lease = pair
                            .session
                            .standby
                            .as_ref()
                            .unwrap()
                            .connection
                            .lease_id
                            .clone();
                        native.leases[1] = Some(lease.clone());
                        native.current_leases[1] = Some(lease);
                        native.session.installed[1] = true;
                        native.session.committed[1] = true;
                        native.standby_ready = true;
                    }
                    "absent" => state.desktop_redundancy = None,
                    "stopping" => {
                        pair.stop = Some(nelomai_client_storage::StoredDesktopRedundantStop {
                            operation_id: "30000000-0000-4000-8000-000000000002".into(),
                            active_lease_id: pair.connection.lease_id.clone(),
                            role_generation: 0,
                            membership_generation: 0,
                            committed_leases: native.current_leases.clone(),
                            retain_active_peer: false,
                            role_confirmed: true,
                        });
                        native.session.phase =
                            nelomai_client_tunnel::redundancy::session::SessionPhase::Stopping;
                        native.primary_ready = false;
                    }
                    "candidate" => {
                        let mut candidate: nelomai_contracts::RedundantStandbyAcquireResponse = serde_json::from_str(include_str!("../../../contracts/fixtures/valid/connection-redundant-standby-acquire-response.json")).unwrap();
                        candidate.candidate_slot = nelomai_contracts::RedundancyMemberSlot::B;
                        candidate.session.active_lease_id = Some(pair.connection.lease_id.clone());
                        candidate.session.slot_b_lease_id = None;
                        candidate.session.role_generation = 0;
                        candidate.session.membership_generation = 0;
                        native.leases[1] = Some(candidate.candidate_lease_id.clone());
                        native.session.installed[1] = true;
                        pair.candidate = Some(candidate);
                    }
                    _ => unreachable!(),
                }
            }
            // An unconditional refresh would now fail instead of coordinating.
            api.candidate_failure.store(true, Ordering::SeqCst);
            assert!(
                app.desktop_redundancy_tick(1_800_000_600).await.is_ok(),
                "{case}"
            );
            assert_eq!(api.candidate_calls.load(Ordering::SeqCst), 1, "{case}");
            assert_eq!(api.probe_calls.load(Ordering::SeqCst), 2, "{case}");
            assert!(api.acquire_requests.lock().unwrap().is_empty(), "{case}");
        }
    }
}

#[cfg(not(target_os = "android"))]
#[tokio::test]
async fn desktop_personal_tic_remains_single_even_when_preference_is_on() {
    let (app, api) = application();
    let _ = app
        .desktop_connection_intent_attempt_guarded(
            ConnectOptions::android_default(),
            1_800_000_000,
            true,
            || true,
        )
        .await;
    let request = api
        .start_request
        .lock()
        .unwrap()
        .clone()
        .expect("personal single request");
    assert_ne!(request.reserve_enabled, Some(true));
    assert_eq!(api.probe_calls.load(Ordering::SeqCst), 0);
}

#[async_trait]
impl TunnelController for StoppedTunnel {
    async fn start(&self, _request: TunnelStartRequest) -> Result<(), TunnelError> {
        Ok(())
    }

    async fn stop(&self) -> Result<(), TunnelError> {
        Ok(())
    }

    async fn status(&self) -> Result<TunnelStatus, TunnelError> {
        Ok(TunnelStatus::Stopped)
    }
}

#[tokio::test]
async fn probes_are_cached_for_five_minutes_with_failures() {
    let (application, api) = application();

    let first = application
        .refresh_probes(Layer::Stray, EgressMode::Ipv4, 1_800_000_000)
        .await
        .unwrap();
    let cached = application
        .refresh_probes(Layer::Stray, EgressMode::Ipv4, 1_800_000_299)
        .await
        .unwrap();
    let refreshed = application
        .refresh_probes(Layer::Stray, EgressMode::Ipv4, 1_800_000_300)
        .await
        .unwrap();

    assert_eq!(first, cached);
    assert_ne!(
        cached.probes[0].measured_at,
        refreshed.probes[0].measured_at
    );
    assert_eq!(first.probes.len(), 2);
    let fast = first
        .probes
        .iter()
        .find(|probe| probe.candidate_id == "candidate-fast")
        .unwrap();
    let down = first
        .probes
        .iter()
        .find(|probe| probe.candidate_id == "candidate-down")
        .unwrap();
    assert_eq!(fast.latency_ms, Some(24.5));
    assert_eq!(fast.failure_code, None);
    assert_eq!(down.latency_ms, None);
    assert_eq!(
        down.failure_code,
        Some(nelomai_contracts::ProbeFailureCode::Unknown)
    );
    assert_eq!(api.candidate_calls.load(Ordering::SeqCst), 2);
    assert_eq!(api.probe_calls.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn concurrent_refreshes_share_one_measurement() {
    let (application, api) = application();

    let (first, second) = tokio::join!(
        application.refresh_probes(Layer::Stray, EgressMode::Ipv4, 1_800_000_000),
        application.refresh_probes(Layer::Stray, EgressMode::Ipv4, 1_800_000_000),
    );

    assert_eq!(first.unwrap(), second.unwrap());
    assert_eq!(api.candidate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(api.probe_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn completely_failed_probe_set_is_remeasured_on_next_attempt() {
    let (application, api) = application();
    api.all_probes_fail.store(true, Ordering::SeqCst);

    let first = application
        .refresh_probes(Layer::Stray, EgressMode::Ipv4, 1_800_000_000)
        .await
        .unwrap();
    let second = application
        .refresh_probes(Layer::Stray, EgressMode::Ipv4, 1_800_000_001)
        .await
        .unwrap();

    assert!(first.probes.iter().all(|probe| probe.latency_ms.is_none()));
    assert!(second.probes.iter().all(|probe| probe.latency_ms.is_none()));
    assert_eq!(api.candidate_calls.load(Ordering::SeqCst), 2);
    assert_eq!(api.probe_calls.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn expired_candidate_tokens_are_refreshed_before_connection() {
    let (application, api) = application();
    application
        .refresh_probes(Layer::Stray, EgressMode::Ipv4, 1_800_000_000)
        .await
        .unwrap();

    application
        .start(
            ConnectOptions {
                layer: Layer::Stray,
                tic_connection_mode: TicConnectionMode::Dynamic,
                route_mode: RouteMode::Standalone,
                egress_mode: EgressMode::Ipv4,
                probes: Vec::new(),
                allow_alternate: true,
            },
            1_893_456_001,
        )
        .await
        .unwrap();

    assert_eq!(api.candidate_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn connection_uses_native_probe_cache_instead_of_webview_values() {
    let (application, api) = application();
    application
        .refresh_probes(Layer::Stray, EgressMode::Ipv4, 1_800_000_000)
        .await
        .unwrap();

    application
        .start(
            ConnectOptions {
                layer: Layer::Stray,
                tic_connection_mode: TicConnectionMode::Dynamic,
                route_mode: RouteMode::Standalone,
                egress_mode: EgressMode::Ipv4,
                probes: vec![ProbeResult {
                    candidate_id: "injected-from-webview".to_string(),
                    latency_ms: Some(0.1),
                    failure_code: None,
                    measured_at: "2026-01-01T00:00:00Z".to_string(),
                }],
                allow_alternate: true,
            },
            1_800_000_010,
        )
        .await
        .unwrap();

    let request = api.start_request.lock().unwrap().clone().unwrap();
    assert_eq!(request.probes.len(), 2);
    assert!(request
        .probes
        .iter()
        .any(|probe| probe.candidate_id == "candidate-fast" && probe.latency_ms == Some(24.5)));
    assert!(request.probes.iter().any(|probe| {
        probe.candidate_id == "candidate-down"
            && probe.failure_code == Some(nelomai_contracts::ProbeFailureCode::Unknown)
    }));
    assert_eq!(api.candidate_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn personal_tic_connection_skips_server_candidates() {
    let (application, api) = application();

    application
        .start(
            ConnectOptions {
                layer: Layer::Tic,
                tic_connection_mode: TicConnectionMode::Personal,
                route_mode: RouteMode::ViaTak,
                egress_mode: EgressMode::Ipv4,
                probes: Vec::new(),
                allow_alternate: true,
            },
            1_800_000_000,
        )
        .await
        .unwrap();

    let request = api.start_request.lock().unwrap().clone().unwrap();
    assert!(request.probes.is_empty());
    assert_eq!(api.candidate_calls.load(Ordering::SeqCst), 0);
    assert_eq!(api.probe_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn quick_connection_sends_no_probes_and_does_not_measure_candidates() {
    let (application, api) = application();

    application
        .start_without_probe_refresh(
            ConnectOptions {
                layer: Layer::Stray,
                tic_connection_mode: TicConnectionMode::Dynamic,
                route_mode: RouteMode::Standalone,
                egress_mode: EgressMode::Ipv4,
                probes: vec![ProbeResult {
                    candidate_id: "must-be-discarded".to_string(),
                    latency_ms: Some(1.0),
                    failure_code: None,
                    measured_at: "2026-01-01T00:00:00Z".to_string(),
                }],
                allow_alternate: true,
            },
            1_800_000_000,
        )
        .await
        .unwrap();

    let request = api.start_request.lock().unwrap().clone().unwrap();
    assert!(request.probes.is_empty());
    assert_eq!(api.candidate_calls.load(Ordering::SeqCst), 0);
    assert_eq!(api.probe_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn probe_tokens_are_not_reused_after_logout() {
    let (application, _) = application();
    application
        .refresh_probes(Layer::Stray, EgressMode::Ipv4, 1_800_000_000)
        .await
        .unwrap();

    application.logout().await.unwrap();
    let error = application
        .refresh_probes(Layer::Stray, EgressMode::Ipv4, 1_800_000_010)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        ApplicationError::Core(CoreError::SignedOut)
    ));
}

fn application() -> (
    ClientApplication<ProbeApi, support::LegacyRuntime<MemoryStore>, StoppedTunnel, NoopLogger>,
    Arc<ProbeApi>,
) {
    application_with_preflight(Arc::new(nelomai_client_core::AllowRuntimeStart))
}

fn application_with_preflight(
    preflight: Arc<dyn RuntimeStartPreflight>,
) -> (
    ClientApplication<ProbeApi, support::LegacyRuntime<MemoryStore>, StoppedTunnel, NoopLogger>,
    Arc<ProbeApi>,
) {
    let api = Arc::new(ProbeApi {
        candidate_calls: AtomicUsize::new(0),
        probe_calls: AtomicUsize::new(0),
        all_probes_fail: AtomicBool::new(false),
        start_request: Mutex::new(None),
        candidate_modes: Mutex::new(Vec::new()),
        candidate_failure: AtomicBool::new(false),
        acquire_requests: Mutex::new(Vec::new()),
    });
    let store = Arc::new(MemoryStore::default());
    let mut auth = StoredAuth::new_install();
    auth.access_token = Some("access-token".to_string());
    auth.refresh_token = Some("refresh-token".to_string());
    auth.compatibility = Some(StoredCompatibility {
        update_required: false,
        observed_at_unix: 1_800_000_000,
    });
    *store.0.lock().unwrap() = Some(auth);
    let local = CoreLocalStop::new(Arc::new(StoppedTunnel));
    let auth = Arc::new(support::TestOwner::new(
        api.clone(),
        store.clone(),
        local.clone(),
    ));
    let application = ClientApplication::with_split_tunnel_store_and_preflight(
        api.clone(),
        Arc::new(support::LegacyRuntime::new(store)),
        Arc::new(MemorySplitTunnelStore::default()),
        auth,
        local,
        Arc::new(NoopLogger),
        preflight,
    );
    (application, api)
}

struct RejectStart {
    preflight_calls: AtomicUsize,
    reject_in_preflight: bool,
}

#[derive(Default)]
struct PausedPreflight {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait]
impl RuntimeStartPreflight for PausedPreflight {
    async fn before_tunnel_start(&self) -> Result<(), CoreError> {
        self.entered.notify_one();
        self.release.notified().await;
        Ok(())
    }
    fn check_start_barrier(&self) -> Result<(), CoreError> {
        Ok(())
    }
}

#[tokio::test]
async fn recovery_v2_keeps_user_cancellation_across_preflight() {
    let preflight = Arc::new(PausedPreflight::default());
    let (application, api) = application_with_preflight(preflight.clone());
    let application = Arc::new(application);
    let task_application = application.clone();
    let start = tokio::spawn(async move {
        task_application
            .start_recovery_v2(
                ConnectOptions {
                    layer: Layer::Stray,
                    tic_connection_mode: TicConnectionMode::Dynamic,
                    route_mode: RouteMode::Standalone,
                    egress_mode: EgressMode::Ipv4,
                    probes: Vec::new(),
                    allow_alternate: true,
                },
                1_800_000_000,
                true,
            )
            .await
    });
    preflight.entered.notified().await;
    assert!(application.signal_start_cancellation());
    preflight.release.notify_one();
    assert!(matches!(
        start.await.unwrap(),
        Err(ApplicationError::Core(CoreError::StartCancelled))
    ));
    assert_eq!(api.candidate_calls.load(Ordering::SeqCst), 0);
    assert!(api.start_request.lock().unwrap().is_none());
}

#[async_trait]
impl RuntimeStartPreflight for RejectStart {
    async fn before_tunnel_start(&self) -> Result<(), CoreError> {
        self.preflight_calls.fetch_add(1, Ordering::SeqCst);
        if self.reject_in_preflight {
            Err(CoreError::AuthRecoveryRequired)
        } else {
            Ok(())
        }
    }
    fn check_start_barrier(&self) -> Result<(), CoreError> {
        Err(CoreError::AuthRecoveryRequired)
    }
}

#[tokio::test]
async fn every_application_start_path_runs_transition_preflight_before_network_or_tunnel_work() {
    for reject_in_preflight in [true, false] {
        assert_all_start_paths_reject(Arc::new(RejectStart {
            preflight_calls: AtomicUsize::new(0),
            reject_in_preflight,
        }))
        .await;
    }
}

async fn assert_all_start_paths_reject(preflight: Arc<RejectStart>) {
    let (application, api) = application_with_preflight(preflight.clone());
    let options = ConnectOptions {
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
        probes: Vec::new(),
        allow_alternate: true,
    };
    assert!(matches!(
        application.start(options.clone(), 1_800_000_000).await,
        Err(ApplicationError::Core(CoreError::AuthRecoveryRequired))
    ));
    assert!(matches!(
        application
            .start_recovery_v2(options.clone(), 1_800_000_000, true)
            .await,
        Err(ApplicationError::Core(CoreError::AuthRecoveryRequired))
    ));
    assert!(matches!(
        application
            .start_without_probe_refresh(options.clone(), 1_800_000_000)
            .await,
        Err(ApplicationError::Core(CoreError::AuthRecoveryRequired))
    ));
    #[cfg(not(target_os = "android"))]
    assert!(matches!(
        application
            .connection_intent_attempt(options.clone(), 1_800_000_000)
            .await,
        Err(ApplicationError::Core(CoreError::AuthRecoveryRequired))
    ));
    #[cfg(not(target_os = "android"))]
    assert!(matches!(
        application
            .replace_stalled_connection(options, 1_800_000_000)
            .await,
        Err(ApplicationError::Core(CoreError::AuthRecoveryRequired))
    ));
    assert!(matches!(
        application.start_saved_stray_offline(1_800_000_000).await,
        Err(ApplicationError::Core(CoreError::AuthRecoveryRequired))
    ));
    #[cfg(not(target_os = "android"))]
    assert_eq!(preflight.preflight_calls.load(Ordering::SeqCst), 6);
    assert!(api.start_request.lock().unwrap().is_none());
    assert_eq!(api.candidate_calls.load(Ordering::SeqCst), 0);
}

fn candidate(id: &str, layer: Layer, probe_url: &str) -> ServerCandidate {
    ServerCandidate {
        candidate_id: id.to_string(),
        layer,
        region_label: "Тест".to_string(),
        probe_url: probe_url.to_string(),
        expires_at: "2030-01-01T00:00:00Z".to_string(),
    }
}

#[async_trait]
impl support::TestAuthApi for ProbeApi {
    async fn refresh(&self, _refresh_token: &str) -> Result<TokenResponse, CoreApiError> {
        unreachable!("refresh is not used by this test")
    }

    async fn login(&self, _request: &LoginRequest) -> Result<TokenResponse, CoreApiError> {
        unreachable!("login is not used by this test")
    }

    async fn logout(&self, _access_token: &str) -> Result<(), CoreApiError> {
        Ok(())
    }
}
