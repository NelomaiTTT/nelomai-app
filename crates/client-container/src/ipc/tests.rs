#![cfg(unix)]
use super::*;
use crate::{AuthBroker, RuntimeClientProfile};
use nelomai_client_api::{ClientApi, RuntimeTarget};
use nelomai_client_core::{CoreLocalStop, RuntimeAuthProvider};
use nelomai_client_storage::*;
use nelomai_client_tunnel::{TunnelController, TunnelError, TunnelStartRequest, TunnelStatus};
use nelomai_contracts::{Platform, RuntimeSlot};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

#[tokio::test(start_paused = true)]
async fn frame_read_and_incoming_queue_do_not_regenerate_request_budget() {
    let (mut sender, receiver) = tokio::io::duplex(4096);
    let (outbox, mut incoming) = transport::connect(receiver);
    let started = Instant::now();
    let bytes =
        serde_json::to_vec(&FrameV1::new(1, MessageV1::Request(AuthRequestV1::State))).unwrap();
    let header = (bytes.len() as u32).to_be_bytes();
    sender.write_all(&header[..1]).await.unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(6)).await;
    sender.write_all(&header[1..]).await.unwrap();
    sender.write_all(&bytes).await.unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(3)).await;
    let (_, deadline) = incoming.recv().await.unwrap();
    assert_eq!(deadline, started + REQUEST_BUDGET);
    assert_eq!(deadline - Instant::now(), Duration::from_secs(1));
    outbox.close();
}

#[tokio::test]
async fn outbox_rejects_oversize_before_queueing_owned_credentials() {
    let (stream, _peer) = tokio::io::duplex(8);
    let (outbox, _) = transport::connect(stream);
    let frame = FrameV1::new(
        1,
        MessageV1::Request(AuthRequestV1::Login {
            stamp: None,
            request: RuntimeLogin {
                login: "synthetic".into(),
                password: "x".repeat(MAX_FRAME_BYTES + 1),
                device_name: "fixture".into(),
            },
        }),
    );
    assert_eq!(
        outbox.enqueue(frame, Instant::now() + REQUEST_BUDGET),
        Err(PrivateError::Protocol)
    );
}

#[tokio::test]
async fn dropping_client_logout_waiter_does_not_abort_already_started_owner_revocation() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let incoming = entered.clone();
    let released = release.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let router = axum::Router::new().route("/api/client/v1/auth/logout-runtime", axum::routing::post(move || {
        let incoming = incoming.clone(); let released = released.clone();
        async move { incoming.notify_one(); released.notified().await; axum::Json(serde_json::json!({"api_version":"1","request_id":"synthetic","code":"session_revoked_cleanup_accepted"})) }
    }));
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let fixture = Fixture::new(api, true);
    fixture
        .parent
        .admit_empty_current(&fixture.broker)
        .await
        .unwrap();
    fixture.client.state().await.unwrap();
    let client = fixture.client.clone();
    let logout = tokio::spawn(async move { client.logout().await });
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .unwrap();
    logout.abort();
    assert!(logout.await.unwrap_err().is_cancelled());
    assert_eq!(
        fixture.auth.load().unwrap().unwrap().logout_state,
        LogoutState::Pending
    );
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(1), async {
        while fixture.auth.load().unwrap().unwrap().logout_state != LogoutState::LoggedOut {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("owner must complete HTTP revocation after waiter drop");
    assert!(fixture
        .auth
        .load()
        .unwrap()
        .unwrap()
        .refresh_token
        .is_none());
    server.abort();
}

#[derive(Clone, Default)]
struct Record(Arc<Mutex<Option<Vec<u8>>>>);
impl ProtectedRecordStore for Record {
    fn load_record(&self) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn save_record(&self, bytes: &[u8]) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = Some(bytes.into());
        Ok(())
    }
    fn delete_record(&self) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}
#[derive(Default)]
struct Tunnel(AtomicUsize);
#[async_trait::async_trait]
impl TunnelController for Tunnel {
    async fn start(&self, _: TunnelStartRequest) -> Result<(), TunnelError> {
        Ok(())
    }
    async fn stop(&self) -> Result<(), TunnelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn status(&self) -> Result<TunnelStatus, TunnelError> {
        Ok(TunnelStatus::Stopped)
    }
}

struct Fixture {
    _root: tempfile::TempDir,
    _service: OwnerService,
    parent: Arc<RemoteOwner>,
    broker: Arc<AuthBroker>,
    client: Arc<PrivateRuntimeAuthClient>,
    child: Arc<ChildAdmission>,
    auth: Arc<ProtectedAuthStore<Record>>,
    tunnel: Arc<Tunnel>,
    record: Arc<RuntimeRecordOwner<ProtectedRuntimeStore<Record>>>,
}
impl Fixture {
    fn new(api: ClientApi, active: bool) -> Self {
        Self::with_background(api, active, None)
    }
    fn with_background(
        api: ClientApi,
        active: bool,
        background: Option<Arc<dyn PrivateBackgroundDispatcher>>,
    ) -> Self {
        Self::with_pause(api, active, background, None)
    }
    fn with_pause(
        api: ClientApi,
        active: bool,
        background: Option<Arc<dyn PrivateBackgroundDispatcher>>,
        pause: Option<Arc<AdmissionPause>>,
    ) -> Self {
        let root = tempfile::tempdir().unwrap();
        let auth = Arc::new(ProtectedAuthStore::new(Record::default()));
        let legacy = StoredAuth::new_install();
        let target = RuntimeTarget {
            container_version: "0.2.16".into(),
            runtime_version: "0.2.16".into(),
            runtime_contract_version: 1,
            runtime_slot: RuntimeSlot::Stable,
        };
        let mut initial_auth = AuthStoreV1::from_legacy(&legacy);
        if active {
            initial_auth.access_token = Some("synthetic-access".into());
            initial_auth.refresh_token = Some("synthetic-refresh".into());
            initial_auth.confirmed_identity = Some(target.identity(Some(1)).unwrap());
            initial_auth.session_generation = Some(1);
        }
        auth.save(&initial_auth).unwrap();
        let paths = RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap();
        let store = ProtectedRuntimeStore::new(Record::default(), paths);
        let mut initial = RuntimeStateV1::import_legacy(
            &legacy,
            StoredSplitTunnelState::default(),
            store.paths(),
        );
        initial.cleanup_only = false;
        store.save(&initial).unwrap();
        let record = RuntimeRecordOwner::new(store);
        let tunnel = Arc::new(Tunnel::default());
        let stop = CoreLocalStop::new(tunnel.clone());
        let child = Arc::new(ChildAdmission::new(
            "fixture-child".into(),
            stop.runtime_writer_gates(),
            record.clone(),
        ));
        let (parent_socket, child_socket) = match pause {
            Some(pause) => pause.sockets(),
            None => private_socketpair().unwrap(),
        };
        let parent = RemoteOwner::new_with_background(
            parent_socket,
            LaunchBinding::fixture(target, "fixture-child"),
            RuntimeClientProfile {
                platform: Platform::Macos,
                platform_version: None,
                architecture: "aarch64".into(),
            },
            background,
        )
        .unwrap();
        let broker = Arc::new(AuthBroker::new(api, auth.clone(), parent.clone()).unwrap());
        let service = parent.serve(broker.clone()).unwrap();
        let client = Arc::new(PrivateRuntimeAuthClient::new(
            child_socket,
            child.clone(),
            stop,
        ));
        Self {
            _root: root,
            _service: service,
            parent,
            broker,
            client,
            child,
            auth,
            tunnel,
            record,
        }
    }
}

struct AdmissionPause {
    after_commit: bool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    grants: AtomicUsize,
}
impl AdmissionPause {
    fn sockets(self: &Arc<Self>) -> (tokio::net::UnixStream, tokio::net::UnixStream) {
        let (owner, upstream) = private_socketpair().unwrap();
        let (downstream, child) = private_socketpair().unwrap();
        let (mut from_owner, mut to_owner) = upstream.into_split();
        let (mut from_child, mut to_child) = downstream.into_split();
        let observe = self.clone();
        tokio::spawn(async move {
            loop {
                let Ok(frame) = read_frame(&mut from_owner, Instant::now() + REQUEST_BUDGET).await
                else {
                    break;
                };
                if matches!(frame.message, MessageV1::Control(ControlV1::Grant { .. })) {
                    observe.grants.fetch_add(1, Ordering::SeqCst);
                }
                if write_frame(&mut to_child, frame, Instant::now() + REQUEST_BUDGET)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let pause = self.clone();
        tokio::spawn(async move {
            let mut held = false;
            loop {
                let Ok(frame) = read_frame(&mut from_child, Instant::now() + REQUEST_BUDGET).await
                else {
                    break;
                };
                let boundary = matches!(frame.message, MessageV1::Ack(ControlAckV1::Committed))
                    && pause.after_commit
                    || matches!(frame.message, MessageV1::Ack(ControlAckV1::Prepared { .. }))
                        && !pause.after_commit;
                if boundary && !held {
                    held = true;
                    pause.entered.notify_one();
                    pause.release.notified().await;
                }
                if write_frame(&mut to_owner, frame, Instant::now() + REQUEST_BUDGET)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        (owner, child)
    }
}

#[tokio::test]
async fn logout_at_prepared_or_committed_ack_prevents_final_grant() {
    for after_commit in [false, true] {
        let (api, _, server) = logout_panel().await;
        let pause = Arc::new(AdmissionPause {
            after_commit,
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            grants: AtomicUsize::new(0),
        });
        let fixture = Fixture::with_pause(api, true, None, Some(pause.clone()));
        let owner = fixture.parent.clone();
        let broker = fixture.broker.clone();
        let admission = tokio::spawn(async move { owner.admit_empty_current(&broker).await });
        tokio::time::timeout(Duration::from_secs(1), pause.entered.notified())
            .await
            .unwrap();
        let broker = fixture.broker.clone();
        let logout = tokio::spawn(async move { broker.logout().await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while fixture.auth.load().unwrap().unwrap().auth_epoch == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        pause.release.notify_one();
        assert!(admission.await.unwrap().is_err());
        logout.await.unwrap().unwrap();
        assert_eq!(pause.grants.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture
                .record
                .operational()
                .load()
                .unwrap()
                .unwrap()
                .auth_scope
                .is_some(),
            after_commit
        );
        server.abort();
    }
}

struct Recover(AtomicUsize);
#[async_trait::async_trait]
impl PrivateBackgroundDispatcher for Recover {
    async fn prepare_revocation(&self, _: u64) -> Result<(), crate::BrokerError> {
        Ok(())
    }
    async fn dispatch(
        &self,
        _: crate::NativeAuthRequest,
        action: BackgroundAction,
    ) -> Result<Option<nelomai_client_api::TokenResponse>, crate::NativeAuthFailure> {
        assert!(matches!(action, BackgroundAction::Recover));
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Some(serde_json::from_value(serde_json::json!({"api_version":"1","request_id":"synthetic","token_type":"Bearer","access_token":"recovered-access","access_expires_in":900,"refresh_token":"recovered-refresh","refresh_expires_in":3600,"access":{"state":"active","can_login":true,"can_connect":true,"expires_at":null},"device":{"id":"device","name":"synthetic","platform":"macos","container_version":"0.2.16","runtime_version":"0.2.16","runtime_contract_version":1,"runtime_slot":"stable","session_generation":1}})).unwrap()))
    }
}

#[tokio::test]
async fn closed_restart_recovers_only_matching_persisted_scope_after_lost_refresh() {
    for matching in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let router = axum::Router::new().route(
            "/api/client/v1/auth/refresh",
            axum::routing::post(|| async { axum::http::StatusCode::INTERNAL_SERVER_ERROR }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let native = Arc::new(Recover(AtomicUsize::new(0)));
        let fixture = Fixture::with_background(api, true, Some(native.clone()));
        let mut initial = fixture.auth.load().unwrap().unwrap();
        initial.broker.as_mut().unwrap().confirmed_device_id = Some("device".into());
        fixture.auth.save(&initial).unwrap();
        let access = fixture.broker.access_token(None).await.unwrap();
        if matching {
            fixture
                .record
                .bind_empty_scope(&transport::scope(&access))
                .unwrap();
        }
        assert!(fixture.child.check(&transport::scope(&access)).is_err());
        assert!(fixture.broker.access_token(Some(&access)).await.is_err());
        assert!(fixture
            .auth
            .load()
            .unwrap()
            .unwrap()
            .broker
            .unwrap()
            .pending_request
            .is_some());
        assert_eq!(
            fixture.client.state().await.unwrap(),
            RuntimeAuthState::RecoveryRequired
        );
        let result = fixture.client.background(BackgroundAction::Recover).await;
        if matching {
            assert!(
                matches!(result, Ok(AuthResponseV1::Access { .. })),
                "known persisted scope must recover with initial CLOSED latch: {result:?}"
            );
            assert_eq!(
                fixture.client.access(None).await.unwrap().access_token(),
                "recovered-access"
            );
            assert_eq!(native.0.load(Ordering::SeqCst), 1);
        } else {
            assert!(result.is_err());
            assert_eq!(native.0.load(Ordering::SeqCst), 0);
        }
        server.abort();
    }
}

struct Provision(AtomicUsize, AtomicUsize);
#[async_trait::async_trait]
impl PrivateBackgroundDispatcher for Provision {
    async fn prepare_revocation(&self, _: u64) -> Result<(), crate::BrokerError> {
        self.1.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn dispatch(
        &self,
        request: crate::NativeAuthRequest,
        action: BackgroundAction,
    ) -> Result<Option<nelomai_client_api::TokenResponse>, crate::NativeAuthFailure> {
        assert!(matches!(action, BackgroundAction::Provision));
        assert_eq!(request.access.access_token(), "synthetic-access");
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }
}
#[tokio::test]
async fn background_action_stays_owner_side_and_stale_action_never_dispatches() {
    let (api, _, server) = logout_panel().await;
    let native = Arc::new(Provision(AtomicUsize::new(0), AtomicUsize::new(0)));
    let fixture = Fixture::with_background(api, true, Some(native.clone()));
    // Known device ID is owner migration/enrollment input, never runtime JSON.
    let mut initial = fixture.auth.load().unwrap().unwrap();
    initial.broker.as_mut().unwrap().confirmed_device_id = Some("device".into());
    fixture.auth.save(&initial).unwrap();
    fixture
        .parent
        .admit_empty_current(&fixture.broker)
        .await
        .unwrap();
    fixture.client.state().await.unwrap();
    fixture
        .client
        .background(BackgroundAction::Provision)
        .await
        .unwrap();
    assert_eq!(native.0.load(Ordering::SeqCst), 1);
    assert!(fixture
        .auth
        .load()
        .unwrap()
        .unwrap()
        .broker
        .unwrap()
        .pending_recovery
        .is_none());
    let (old_stamp, _) = fixture.broker.observe_stamped().await.unwrap();
    fixture.client.logout().await.unwrap();
    assert_eq!(
        native.1.load(Ordering::SeqCst),
        1,
        "remote owner must preserve native durable handoff before HTTP"
    );
    fixture.client.state().await.unwrap();
    assert!(fixture
        .client
        .request(
            AuthRequestV1::BackgroundCredential {
                stamp: Some(old_stamp),
                action: BackgroundAction::Provision
            },
            Instant::now() + REQUEST_BUDGET
        )
        .await
        .is_err());
    assert_eq!(native.0.load(Ordering::SeqCst), 1);
    server.abort();
}

async fn logout_panel() -> (ClientApi, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let incoming = calls.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let router = axum::Router::new().route("/api/client/v1/auth/logout-runtime", axum::routing::post(move || {
        incoming.fetch_add(1, Ordering::SeqCst);
        async { axum::Json(serde_json::json!({"api_version":"1","request_id":"synthetic","code":"session_revoked_cleanup_accepted"})) }
    }));
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (api, calls, server)
}

#[tokio::test]
async fn owner_originated_logout_revokes_real_child_latch() {
    let (api, calls, server) = logout_panel().await;
    let fixture = Fixture::new(api, true);
    fixture
        .parent
        .admit_empty_current(&fixture.broker)
        .await
        .unwrap();
    let access = fixture.client.access(None).await.unwrap();
    fixture.child.check(&transport::scope(&access)).unwrap();
    fixture.broker.logout().await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
        fixture.child.check(&transport::scope(&access)).is_err(),
        "owner logout must close remote admission"
    );
    server.abort();
}

#[tokio::test]
async fn closed_or_saturated_revoke_outbox_cannot_suppress_logout_http_or_lose_proof() {
    for saturate in [false, true] {
        let (api, calls, server) = logout_panel().await;
        let fixture = Fixture::new(api, true);
        if saturate {
            // No yield: the real bounded writer outbox fills before its worker
            // can drain. Revoke must fail closed but cleanup must still run.
            for _ in 0..OUTBOX_CAPACITY {
                let id = fixture.parent.outbox.id().unwrap();
                fixture
                    .parent
                    .outbox
                    .enqueue(
                        FrameV1::new(id, MessageV1::Control(ControlV1::Revoke)),
                        Instant::now() + REQUEST_BUDGET,
                    )
                    .unwrap();
            }
        } else {
            fixture.parent.revoke_peer();
        }
        let result = fixture.broker.logout().await;
        assert!(
            result.is_err(),
            "missing physical-stop ACK is not a success"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let saved = fixture.auth.load().unwrap().unwrap();
        assert_eq!(saved.logout_state, LogoutState::LoggedOut);
        assert!(
            saved.refresh_token.is_none(),
            "only real HTTP ACK clears proof"
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while fixture.tunnel.0.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("EOF must reach independent stop pump");
        assert!(
            fixture.tunnel.0.load(Ordering::SeqCst) > 0,
            "EOF must poll child physical stop"
        );
        server.abort();
    }
}

#[tokio::test]
async fn same_client_logout_cancels_its_login_after_ticket_and_real_http_started() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let entered_server = entered.clone();
    let release_server = release.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let router = axum::Router::new()
        .route("/api/client/v1/auth/login", axum::routing::post(move || {
            let entered = entered_server.clone(); let release = release_server.clone();
            async move {
                entered.notify_one(); release.notified().await;
                axum::Json(serde_json::json!({"api_version":"1","request_id":"synthetic","token_type":"Bearer","access_token":"late-access","access_expires_in":900,"refresh_token":"late-refresh","refresh_expires_in":3600,"access":{"state":"active","can_login":true,"can_connect":true,"expires_at":null},"device":{"id":"device","name":"synthetic","platform":"macos","container_version":"0.2.16","runtime_version":"0.2.16","runtime_contract_version":1,"runtime_slot":"stable","session_generation":1}}))
            }
        }))
        .route("/api/client/v1/auth/logout-runtime", axum::routing::post(|| async { axum::Json(serde_json::json!({"api_version":"1","request_id":"synthetic","code":"session_revoked_cleanup_accepted"})) }));
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let fixture = Fixture::new(api, false);
    fixture.client.state().await.unwrap();
    let client = fixture.client.clone();
    let login = tokio::spawn(async move {
        client
            .login(RuntimeLogin {
                login: "synthetic".into(),
                password: "synthetic".into(),
                device_name: "fixture".into(),
            })
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .unwrap();
    let issued = fixture.auth.load().unwrap().unwrap();
    assert_eq!(issued.auth_epoch, 1);
    let (old_stamp, _) = fixture
        .parent
        .logins
        .lock()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .clone();
    let own_id = fixture.client.pending_login.lock().unwrap().unwrap();
    assert!(
        matches!(
            fixture
                .client
                .request(
                    AuthRequestV1::Logout {
                        stamp: Some(old_stamp),
                        cancel_login_request: Some(own_id + 999)
                    },
                    Instant::now() + REQUEST_BUDGET
                )
                .await,
            Err(PrivateError::Cancelled)
        ),
        "unrelated request ID cannot authorize own-login exception"
    );
    assert_eq!(fixture.auth.load().unwrap().unwrap(), issued);
    let (old_stamp, _) = fixture
        .parent
        .logins
        .lock()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .clone();
    let (other_owner_socket, mut other_child_socket) = private_socketpair().unwrap();
    let other = RemoteOwner::new(
        other_owner_socket,
        LaunchBinding::fixture(
            RuntimeTarget {
                container_version: "0.2.16".into(),
                runtime_version: "0.2.16".into(),
                runtime_contract_version: 1,
                runtime_slot: RuntimeSlot::Stable,
            },
            "other-incarnation",
        ),
        RuntimeClientProfile {
            platform: Platform::Macos,
            platform_version: None,
            architecture: "aarch64".into(),
        },
    )
    .unwrap();
    let _other_service = other.serve(fixture.broker.clone()).unwrap();
    let deadline = Instant::now() + REQUEST_BUDGET;
    write_frame(
        &mut other_child_socket,
        FrameV1::new(
            1,
            MessageV1::Request(AuthRequestV1::Logout {
                stamp: Some(old_stamp),
                cancel_login_request: Some(own_id),
            }),
        ),
        deadline,
    )
    .await
    .unwrap();
    assert!(matches!(
        read_frame(&mut other_child_socket, deadline)
            .await
            .unwrap()
            .message,
        MessageV1::Response(AuthResponseV1::Error {
            error: PrivateError::Cancelled
        })
    ));
    assert_eq!(fixture.auth.load().unwrap().unwrap(), issued);
    assert!(
        fixture.client.logout().await.is_err(),
        "lost initial login has no remote proof yet"
    );
    let cancelled = fixture.auth.load().unwrap().unwrap();
    assert_eq!(
        cancelled.auth_epoch, 2,
        "same client's new logout must cancel its own issued login"
    );
    assert_eq!(cancelled.logout_state, LogoutState::Pending);
    assert!(fixture.tunnel.0.load(Ordering::SeqCst) >= 2);
    release.notify_one();
    assert!(login.await.unwrap().is_err());
    assert!(fixture.parent.logins.lock().unwrap().is_empty());
    assert!(fixture.client.pending_login.lock().unwrap().is_none());
    assert_eq!(
        fixture.auth.load().unwrap().unwrap().logout_state,
        LogoutState::LoggedOut
    );
    server.abort();
}

#[tokio::test]
async fn old_logout_cannot_reuse_completed_login_ticket_or_new_state_sync() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let router = axum::Router::new().route("/api/client/v1/auth/login", axum::routing::post(|| async {
        axum::Json(serde_json::json!({"api_version":"1","request_id":"synthetic","token_type":"Bearer","access_token":"new-access","access_expires_in":900,"refresh_token":"new-refresh","refresh_expires_in":3600,"access":{"state":"active","can_login":true,"can_connect":true,"expires_at":null},"device":{"id":"device","name":"synthetic","platform":"macos","container_version":"0.2.16","runtime_version":"0.2.16","runtime_contract_version":1,"runtime_slot":"stable","session_generation":1}}))
    }));
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let fixture = Fixture::new(api, false);
    let (old, _) = fixture.broker.observe_stamped().await.unwrap();
    fixture.client.state().await.unwrap();
    let access = fixture
        .client
        .login(RuntimeLogin {
            login: "synthetic".into(),
            password: "synthetic".into(),
            device_name: "fixture".into(),
        })
        .await
        .unwrap();
    assert!(fixture.parent.logins.lock().unwrap().is_empty());
    assert!(fixture.client.pending_login.lock().unwrap().is_none());
    assert_eq!(
        fixture.client.state().await.unwrap(),
        RuntimeAuthState::Active
    );
    let saved = fixture.auth.load().unwrap();
    assert!(matches!(
        fixture
            .client
            .request(
                AuthRequestV1::Logout {
                    stamp: Some(old),
                    cancel_login_request: Some(2)
                },
                Instant::now() + REQUEST_BUDGET
            )
            .await,
        Err(PrivateError::Cancelled)
    ));
    assert_eq!(fixture.auth.load().unwrap(), saved);
    fixture.child.check(&transport::scope(&access)).unwrap();
    assert_eq!(fixture.client.access(None).await.unwrap(), access);
    server.abort();
}

#[tokio::test]
async fn remote_logout_and_stop_work_while_real_child_writer_blocks_login() {
    let root = tempfile::tempdir().unwrap();
    let auth = Arc::new(ProtectedAuthStore::new(Record::default()));
    let legacy = StoredAuth::new_install();
    auth.save(&AuthStoreV1::from_legacy(&legacy)).unwrap();
    let paths = RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap();
    let store = ProtectedRuntimeStore::new(Record::default(), paths);
    let mut initial =
        RuntimeStateV1::import_legacy(&legacy, StoredSplitTunnelState::default(), store.paths());
    initial.cleanup_only = false;
    store.save(&initial).unwrap();
    let record = RuntimeRecordOwner::new(store);
    let tunnel = Arc::new(Tunnel::default());
    let stop = CoreLocalStop::new(tunnel.clone());
    let writers = stop.runtime_writer_gates();
    let child = Arc::new(ChildAdmission::new(
        "fixture-child".into(),
        writers.clone(),
        record.clone(),
    ));
    let (parent_socket, child_socket) = private_socketpair().unwrap();
    let binding = LaunchBinding::fixture(
        RuntimeTarget {
            container_version: "0.2.16".into(),
            runtime_version: "0.2.16".into(),
            runtime_contract_version: 1,
            runtime_slot: RuntimeSlot::Stable,
        },
        "fixture-child",
    );
    let parent = RemoteOwner::new(
        parent_socket,
        binding,
        RuntimeClientProfile {
            platform: Platform::Macos,
            platform_version: None,
            architecture: "aarch64".into(),
        },
    )
    .unwrap();
    let broker = Arc::new(
        AuthBroker::new(
            ClientApi::new("http://127.0.0.1:9").unwrap(),
            auth.clone(),
            parent.clone(),
        )
        .unwrap(),
    );
    let service = parent.serve(broker.clone()).unwrap();
    let client = Arc::new(PrivateRuntimeAuthClient::new(
        child_socket,
        child.clone(),
        stop,
    ));
    client.state().await.unwrap();
    let gate = writers.lifecycle();
    let held = gate.lock().await;
    let login_client = client.clone();
    let login = tokio::spawn(async move {
        login_client
            .login(RuntimeLogin {
                login: "synthetic".into(),
                password: "synthetic".into(),
                device_name: "fixture".into(),
            })
            .await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    client.logout().await.unwrap();
    assert!(tunnel.0.load(Ordering::SeqCst) > 0);
    assert!(tokio::time::timeout(Duration::from_millis(500), login)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    assert_eq!(
        auth.load().unwrap().unwrap().logout_state,
        LogoutState::LoggedOut
    );
    assert_eq!(record.operational().load().unwrap().unwrap(), initial);
    drop(held);
    drop(service);
    drop(client);
}

#[test]
fn private_child_process_control_fixture() {
    if std::env::var("NELOMAI_PRIVATE_TEST_CHILD").as_deref() != Ok("1") {
        return;
    }
    use std::os::fd::BorrowedFd;
    // Fixture contract: the parent's pre_exec transfers only its socket to fd3.
    let fd = unsafe { BorrowedFd::borrow_raw(3) }
        .try_clone_to_owned()
        .unwrap();
    unsafe {
        libc::close(3);
    }
    let stream = std::os::unix::net::UnixStream::from(fd);
    stream.set_nonblocking(true).unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let root = tempfile::tempdir().unwrap();
            let paths = RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap();
            let record = ProtectedRuntimeStore::new(Record::default(), paths);
            let mut value = RuntimeStateV1::import_legacy(
                &StoredAuth::new_install(),
                StoredSplitTunnelState::default(),
                record.paths(),
            );
            value.cleanup_only = false;
            record.save(&value).unwrap();
            let record = RuntimeRecordOwner::new(record);
            let stop = CoreLocalStop::new(Arc::new(Tunnel::default()));
            let child = Arc::new(ChildAdmission::new(
                "process-fixture".into(),
                stop.runtime_writer_gates(),
                record,
            ));
            let client = PrivateRuntimeAuthClient::new(
                tokio::net::UnixStream::from_std(stream).unwrap(),
                child,
                stop,
            );
            assert_eq!(
                client
                    .login(RuntimeLogin {
                        login: "synthetic".into(),
                        password: "synthetic".into(),
                        device_name: "child".into()
                    })
                    .await
                    .unwrap()
                    .access_token(),
                "child-access"
            );
            client.logout().await.unwrap();
        });
}

#[tokio::test]
async fn eof_at_each_child_admission_stage_closes_latch_releases_guards_and_stops() {
    for phase in 0..3 {
        let root = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap();
        let store = ProtectedRuntimeStore::new(Record::default(), paths);
        let mut value = RuntimeStateV1::import_legacy(
            &StoredAuth::new_install(),
            StoredSplitTunnelState::default(),
            store.paths(),
        );
        value.cleanup_only = false;
        store.save(&value).unwrap();
        let record = RuntimeRecordOwner::new(store);
        let tunnel = Arc::new(Tunnel::default());
        let stop = CoreLocalStop::new(tunnel.clone());
        let writers = stop.runtime_writer_gates();
        let child = Arc::new(ChildAdmission::new(
            "raw-child".into(),
            writers.clone(),
            record.clone(),
        ));
        let (mut owner_socket, child_socket) = private_socketpair().unwrap();
        let _client = PrivateRuntimeAuthClient::new(child_socket, child.clone(), stop);
        let deadline = Instant::now() + REQUEST_BUDGET;
        let expected = RuntimeAuthScope {
            auth_epoch: 1,
            family: "synthetic".into(),
            identity: RuntimeTarget {
                container_version: "0.2.16".into(),
                runtime_version: "0.2.16".into(),
                runtime_contract_version: 1,
                runtime_slot: RuntimeSlot::Stable,
            }
            .identity(Some(1))
            .unwrap(),
        };
        if phase > 0 {
            write_frame(
                &mut owner_socket,
                FrameV1::new(
                    1,
                    MessageV1::Control(ControlV1::Prepare {
                        incarnation: "raw-child".into(),
                    }),
                ),
                deadline,
            )
            .await
            .unwrap();
            let MessageV1::Ack(ControlAckV1::Prepared { lease }) =
                read_frame(&mut owner_socket, deadline)
                    .await
                    .unwrap()
                    .message
            else {
                panic!("actual child lease expected");
            };
            assert!(writers.lifecycle().try_lock().is_err());
            if phase > 1 {
                write_frame(
                    &mut owner_socket,
                    FrameV1::new(
                        2,
                        MessageV1::Control(ControlV1::CommitAdmission {
                            lease,
                            scope: expected.clone(),
                        }),
                    ),
                    deadline,
                )
                .await
                .unwrap();
                assert!(matches!(
                    read_frame(&mut owner_socket, deadline)
                        .await
                        .unwrap()
                        .message,
                    MessageV1::Ack(ControlAckV1::Committed)
                ));
            }
        }
        drop(owner_socket);
        tokio::time::timeout(Duration::from_secs(1), async {
            while tunnel.0.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(writers.lifecycle().try_lock().is_ok());
        assert!(child.check(&expected).is_err());
        assert_eq!(
            record
                .operational()
                .load()
                .unwrap()
                .unwrap()
                .auth_scope
                .is_some(),
            phase == 2,
            "EOF must preserve committed cleanup provenance"
        );
    }
}

#[tokio::test]
async fn prepared_ack_cannot_substitute_another_request_lease() {
    let fixture = Fixture::new(ClientApi::new("http://127.0.0.1:9").unwrap(), true);
    let (parent, mut peer) = private_socketpair().unwrap();
    let owner = RemoteOwner::new(
        parent,
        LaunchBinding::fixture(
            RuntimeTarget {
                container_version: "0.2.16".into(),
                runtime_version: "0.2.16".into(),
                runtime_contract_version: 1,
                runtime_slot: RuntimeSlot::Stable,
            },
            "ack-fixture",
        ),
        RuntimeClientProfile {
            platform: Platform::Macos,
            platform_version: None,
            architecture: "aarch64".into(),
        },
    )
    .unwrap();
    let _service = owner.serve(fixture.broker.clone()).unwrap();
    let broker = fixture.broker.clone();
    let admission = tokio::spawn(async move { owner.admit_empty_current(&broker).await });
    let deadline = Instant::now() + REQUEST_BUDGET;
    let prepare = read_frame(&mut peer, deadline).await.unwrap();
    write_frame(
        &mut peer,
        FrameV1::new(
            prepare.id,
            MessageV1::Ack(ControlAckV1::Prepared {
                lease: PreparedLease {
                    incarnation: "ack-fixture".into(),
                    request: prepare.id + 1,
                    cancel_generation: 0,
                },
            }),
        ),
        deadline,
    )
    .await
    .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(100), admission)
            .await
            .expect("wrong request lease must reject before Commit")
            .unwrap(),
        Err(PrivateError::Protocol)
    );
}

#[tokio::test(start_paused = true)]
async fn owner_control_timeout_at_prepare_or_commit_keeps_one_budget_and_closes_peer() {
    for acknowledge_prepare in [false, true] {
        let fixture = Fixture::new(ClientApi::new("http://127.0.0.1:9").unwrap(), true);
        let (parent, mut peer) = private_socketpair().unwrap();
        let owner = RemoteOwner::new(
            parent,
            LaunchBinding::fixture(
                RuntimeTarget {
                    container_version: "0.2.16".into(),
                    runtime_version: "0.2.16".into(),
                    runtime_contract_version: 1,
                    runtime_slot: RuntimeSlot::Stable,
                },
                "timeout-fixture",
            ),
            RuntimeClientProfile {
                platform: Platform::Macos,
                platform_version: None,
                architecture: "aarch64".into(),
            },
        )
        .unwrap();
        let _service = owner.serve(fixture.broker.clone()).unwrap();
        let broker = fixture.broker.clone();
        let started = Instant::now();
        let admission = tokio::spawn(async move { owner.admit_empty_current(&broker).await });
        let prepare = read_frame(&mut peer, started + REQUEST_BUDGET)
            .await
            .unwrap();
        if acknowledge_prepare {
            tokio::time::advance(Duration::from_secs(6)).await;
            write_frame(
                &mut peer,
                FrameV1::new(
                    prepare.id,
                    MessageV1::Ack(ControlAckV1::Prepared {
                        lease: PreparedLease {
                            incarnation: "timeout-fixture".into(),
                            request: prepare.id,
                            cancel_generation: 0,
                        },
                    }),
                ),
                started + REQUEST_BUDGET,
            )
            .await
            .unwrap();
            assert!(matches!(
                read_frame(&mut peer, started + REQUEST_BUDGET)
                    .await
                    .unwrap()
                    .message,
                MessageV1::Control(ControlV1::CommitAdmission { .. })
            ));
        }
        assert_eq!(admission.await.unwrap(), Err(PrivateError::Timeout));
        assert_eq!(started.elapsed(), REQUEST_BUDGET);
        assert!(read_frame(&mut peer, Instant::now() + REQUEST_BUDGET)
            .await
            .is_err());
    }
}

#[tokio::test]
async fn inherited_socket_drives_auth_and_actual_record_in_separate_child_process() {
    use std::os::{fd::AsRawFd, unix::process::CommandExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let router = axum::Router::new()
        .route("/api/client/v1/auth/login", axum::routing::post(|| async { axum::Json(serde_json::json!({"api_version":"1","request_id":"synthetic","token_type":"Bearer","access_token":"child-access","access_expires_in":900,"refresh_token":"child-refresh","refresh_expires_in":3600,"access":{"state":"active","can_login":true,"can_connect":true,"expires_at":null},"device":{"id":"device","name":"synthetic","platform":"macos","container_version":"0.2.16","runtime_version":"0.2.16","runtime_contract_version":1,"runtime_slot":"stable","session_generation":1}})) }))
        .route("/api/client/v1/auth/logout-runtime", axum::routing::post(|| async { axum::Json(serde_json::json!({"api_version":"1","request_id":"synthetic","code":"session_revoked_cleanup_accepted"})) }));
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let (parent, child) = private_socketpair().unwrap();
    assert_ne!(
        unsafe { libc::fcntl(parent.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    assert_ne!(
        unsafe { libc::fcntl(child.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    let child = child.into_std().unwrap();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "ipc::tests::private_child_process_control_fixture",
            "--nocapture",
        ])
        .env("NELOMAI_PRIVATE_TEST_CHILD", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(child.as_raw_fd(), 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut process = command.spawn().unwrap();
    drop(command);
    let owner = RemoteOwner::new(
        parent,
        LaunchBinding::fixture(
            RuntimeTarget {
                container_version: "0.2.16".into(),
                runtime_version: "0.2.16".into(),
                runtime_contract_version: 1,
                runtime_slot: RuntimeSlot::Stable,
            },
            "process-fixture",
        ),
        RuntimeClientProfile {
            platform: Platform::Macos,
            platform_version: None,
            architecture: "aarch64".into(),
        },
    )
    .unwrap();
    let auth = Arc::new(ProtectedAuthStore::new(Record::default()));
    auth.save(&AuthStoreV1::from_legacy(&StoredAuth::new_install()))
        .unwrap();
    let broker = Arc::new(AuthBroker::new(api, auth.clone(), owner.clone()).unwrap());
    let _service = owner.serve(broker).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            if let Some(status) = process.try_wait().unwrap() {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if result.is_err() {
        process.kill().unwrap();
        process.wait().unwrap();
    }
    assert!(result.unwrap().success());
    assert_eq!(
        auth.load().unwrap().unwrap().logout_state,
        LogoutState::LoggedOut
    );
    server.abort();
}
