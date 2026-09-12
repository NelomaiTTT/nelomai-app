#![cfg(unix)]
use super::*;
use crate::{AuthBroker, RuntimeClientProfile};
use nelomai_client_api::{ClientApi, RuntimeTarget};
use nelomai_client_core::{CoreLocalStop, RuntimeAuthProvider, RuntimeStartPreflight};
use nelomai_client_storage::*;
use nelomai_client_tunnel::{TunnelController, TunnelError, TunnelStartRequest, TunnelStatus};
use nelomai_contracts::{Platform, RuntimeSlot};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

// Poll exactly to the next real async boundary; no task abort or scheduler
// timing may stand in for the broker's own post-wait validation.
async fn poll_pending<T>(future: std::pin::Pin<&mut impl std::future::Future<Output = T>>) {
    let mut future = future;
    std::future::poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
}

async fn queued_remote_issuance_is_cancelled(login: bool, expire: bool) {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let router = axum::Router::new().fallback(move || {
        let observed = observed.clone();
        async move {
            observed.fetch_add(1, Ordering::SeqCst);
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        }
    });
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let fixture = Fixture::new(api, !login);
    let (stream, mut peer) = private_socketpair().unwrap();
    let owner = RemoteOwner::new(
        stream,
        LaunchBinding::fixture(
            RuntimeTarget {
                container_version: "0.2.16".into(),
                runtime_version: "0.2.16".into(),
                runtime_contract_version: 1,
                runtime_slot: RuntimeSlot::Stable,
            },
            "queued-peer",
        ),
        RuntimeClientProfile {
            platform: Platform::Macos,
            platform_version: None,
            architecture: "aarch64".into(),
        },
    )
    .unwrap();
    let (stamp, observation) = fixture.broker.observe_stamped().await.unwrap();
    let request = if login {
        AuthRequestV1::Login {
            stamp: Some(stamp),
            request: RuntimeLogin {
                login: "synthetic".into(),
                password: "synthetic".into(),
                device_name: "fixture".into(),
            },
        }
    } else {
        AuthRequestV1::AccessToken {
            stamp: Some(stamp),
            stale: observation.access,
        }
    };
    let held = crate::auth_broker::hold_test_issuance(&fixture.broker).await;
    let before = fixture.auth.load().unwrap();
    let deadline = Instant::now() + REQUEST_BUDGET;
    let work = owner.request(&fixture.broker, 500, request, deadline);
    tokio::pin!(work);
    poll_pending(work.as_mut()).await;
    let control = read_frame(&mut peer, deadline).await.unwrap();
    let ack = match control.message {
        MessageV1::Control(ControlV1::Prepare { incarnation }) => ControlAckV1::Prepared {
            lease: PreparedLease {
                incarnation,
                request: control.id,
                cancel_generation: 0,
            },
        },
        MessageV1::Control(ControlV1::CheckScope { .. }) => ControlAckV1::Done,
        _ => panic!("expected issuance prerequisite"),
    };
    remote::acknowledge_test_control(&owner, control.id, ack);
    // ACK is already resolved, so this poll reaches the held issuance mutex.
    poll_pending(work.as_mut()).await;
    if expire {
        tokio::time::advance(REQUEST_BUDGET).await;
    } else {
        owner.revoke_peer();
    }
    drop(held);
    assert!(work.await.is_err());
    assert_eq!(
        fixture.auth.load().unwrap(),
        before,
        "queued cancelled request must not persist a protected ticket"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "queued cancelled request must not dispatch HTTP"
    );
    server.abort();
}

#[tokio::test(start_paused = true)]
async fn revoked_peer_cannot_issue_queued_login() {
    queued_remote_issuance_is_cancelled(true, false).await;
}
#[tokio::test(start_paused = true)]
async fn revoked_peer_cannot_issue_queued_refresh() {
    queued_remote_issuance_is_cancelled(false, false).await;
}
#[tokio::test(start_paused = true)]
async fn expired_peer_cannot_issue_queued_login() {
    queued_remote_issuance_is_cancelled(true, true).await;
}

#[tokio::test]
async fn cleanup_snapshot_requires_live_child_writer_lease_over_private_channel() {
    let fixture = Fixture::new(ClientApi::new("http://127.0.0.1:9").unwrap(), true);
    fixture
        .parent
        .admit_empty_current(&fixture.broker)
        .await
        .unwrap();
    let deadline = Instant::now() + REQUEST_BUDGET;
    let lease = fixture.parent.prepare(deadline).await.unwrap();
    let requested_scope = fixture.record.cleanup_snapshot().unwrap().auth_scope;
    let reply = fixture
        .parent
        .control(
            ControlV1::CleanupSourceSnapshot {
                lease: lease.clone(),
                scope: requested_scope.clone(),
            },
            deadline,
        )
        .await
        .unwrap();
    let snapshot = match reply {
        ControlAckV1::CleanupSnapshot { snapshot } => snapshot,
        _ => panic!("expected actual runtime cleanup snapshot"),
    };
    assert_eq!(snapshot.slot, RuntimeSlot::Stable);
    assert_eq!(snapshot.runtime_version, "0.2.16");
    assert_eq!(
        snapshot
            .auth_scope
            .as_ref()
            .unwrap()
            .identity
            .session_generation,
        Some(1)
    );
    assert!(snapshot.lease_ids.is_empty());
    fixture.child.abort(&lease);
    assert!(fixture
        .parent
        .control(
            ControlV1::CleanupSourceSnapshot {
                lease,
                scope: requested_scope
            },
            deadline
        )
        .await
        .is_err());
    assert_eq!(fixture.record.cleanup_snapshot().unwrap(), snapshot);
}

#[tokio::test]
async fn cleanup_cannot_bind_foreign_runtime_or_mutate_without_held_lease() {
    let fixture = Fixture::new(ClientApi::new("http://127.0.0.1:9").unwrap(), true);
    fixture
        .parent
        .admit_empty_current(&fixture.broker)
        .await
        .unwrap();
    let snapshot = fixture.record.cleanup_snapshot().unwrap();
    let deadline = Instant::now() + REQUEST_BUDGET;
    let lease = fixture.parent.prepare(deadline).await.unwrap();
    let mut scope = snapshot.auth_scope.clone().unwrap();
    scope.identity.slot = RuntimeSlot::Latest;
    let reply = fixture
        .parent
        .control(
            ControlV1::CompleteCleanup {
                lease: lease.clone(),
                snapshot: snapshot.clone(),
                scope,
            },
            deadline,
        )
        .await;
    assert!(reply.is_err());
    assert_eq!(fixture.record.cleanup_snapshot().unwrap(), snapshot);
    fixture.child.abort(&lease);
    let reply = fixture
        .parent
        .control(
            ControlV1::CompleteCleanup {
                lease,
                snapshot: snapshot.clone(),
                scope: snapshot.auth_scope.clone().unwrap(),
            },
            deadline,
        )
        .await;
    assert!(reply.is_err());
    assert_eq!(fixture.record.cleanup_snapshot().unwrap(), snapshot);
}

#[tokio::test]
async fn remote_cleanup_rebinds_only_after_broker_generation_changes() {
    let fixture = Fixture::new(ClientApi::new("http://127.0.0.1:9").unwrap(), true);
    fixture
        .parent
        .admit_empty_current(&fixture.broker)
        .await
        .unwrap();
    let frozen = fixture.record.cleanup_snapshot().unwrap();
    let mut auth = fixture.auth.load().unwrap().unwrap();
    auth.session_generation = Some(2);
    auth.confirmed_identity.as_mut().unwrap().session_generation = Some(2);
    fixture.auth.save(&auth).unwrap();
    let access = fixture.broker.access_token(None).await.unwrap();
    fixture
        .parent
        .complete_runtime_cleanup(&fixture.broker, &frozen, &access)
        .await
        .unwrap();
    let current = fixture.record.cleanup_snapshot().unwrap();
    assert_eq!(
        current.auth_scope.unwrap().identity.session_generation,
        Some(2)
    );
    assert_eq!(
        fixture
            .client
            .access(None)
            .await
            .unwrap()
            .identity()
            .session_generation,
        Some(2)
    );
}

#[tokio::test]
async fn remote_handoff_closes_admission_until_explicit_recovery() {
    let fixture = Fixture::new(ClientApi::new("http://127.0.0.1:9").unwrap(), true);
    let mut auth = fixture.auth.load().unwrap().unwrap();
    auth.broker.as_mut().unwrap().confirmed_device_id = Some("device".into());
    fixture.auth.save(&auth).unwrap();
    fixture
        .parent
        .admit_empty_current(&fixture.broker)
        .await
        .unwrap();
    let source = fixture.broker.transition_source().await.unwrap();
    let handoff = fixture
        .parent
        .runtime_cleanup_handoff(&source)
        .await
        .unwrap();
    assert_eq!(handoff.snapshot().runtime_version, "0.2.16");
    assert!(
        nelomai_client_core::RuntimeStartPreflight::check_start_barrier(fixture.client.as_ref())
            .is_err()
    );
    assert!(fixture.client.access(None).await.is_err());
    drop(handoff);
    fixture
        .parent
        .admit_empty_current(&fixture.broker)
        .await
        .unwrap();
    assert!(fixture.client.access(None).await.is_ok());
    assert!(
        nelomai_client_core::RuntimeStartPreflight::check_start_barrier(fixture.client.as_ref())
            .is_ok()
    );
}

#[tokio::test]
async fn child_inventory_cleans_exact_retained_source_without_importing_its_state_into_target() {
    let fixture = Fixture::new(ClientApi::new("http://127.0.0.1:9").unwrap(), true);
    fixture
        .parent
        .admit_empty_current(&fixture.broker)
        .await
        .unwrap();
    let target_scope = fixture
        .record
        .cleanup_snapshot()
        .unwrap()
        .auth_scope
        .unwrap();
    let mut source_scope = target_scope.clone();
    source_scope.identity.runtime_version = "0.2.15".into();
    let paths = RuntimePaths::new(fixture._root.path(), RuntimeSlot::Stable, "0.2.15").unwrap();
    let store = ProtectedRuntimeStore::new(Record::default(), paths);
    let mut old = RuntimeStateV1::import_legacy(
        &StoredAuth::new_install(),
        StoredSplitTunnelState::default(),
        store.paths(),
    );
    old.auth_scope = Some(source_scope.clone());
    store.save(&old).unwrap();
    let source = RuntimeRecordOwner::new(store);
    let inventory = Arc::new(RuntimeRecordInventory::new(
        fixture.record.clone(),
        vec![source.clone()],
    ));
    let child = ChildAdmission::new(
        "retained-source".into(),
        Arc::new(nelomai_client_core::RuntimeWriterGates::default()),
        inventory,
    );
    let lease = child
        .prepare(1, "retained-source", Instant::now() + REQUEST_BUDGET)
        .await
        .unwrap();
    let frozen = child
        .cleanup_snapshot_for(&lease, Some(&source_scope))
        .unwrap();
    assert_eq!(frozen.runtime_version, "0.2.15");
    child
        .complete_cleanup(&lease, &frozen, &target_scope)
        .unwrap();
    assert!(!source.cleanup_snapshot().unwrap().cleanup_only);
    let target = fixture.record.cleanup_snapshot().unwrap();
    assert_eq!(target.auth_scope, Some(target_scope));
    assert_eq!(target.runtime_version, "0.2.16");
    assert!(target.lease_ids.is_empty());
}
#[tokio::test(start_paused = true)]
async fn expired_peer_cannot_issue_queued_refresh() {
    queued_remote_issuance_is_cancelled(false, true).await;
}

struct HeldNative {
    request: Mutex<Option<crate::NativeAuthRequest>>,
    response: tokio::sync::Mutex<
        Option<tokio::sync::oneshot::Receiver<nelomai_client_api::TokenResponse>>,
    >,
}
#[async_trait::async_trait]
impl PrivateBackgroundDispatcher for HeldNative {
    async fn prepare_revocation(&self, _: u64) -> Result<(), crate::BrokerError> {
        Ok(())
    }
    async fn dispatch(
        &self,
        request: crate::NativeAuthRequest,
        _: BackgroundAction,
    ) -> Result<Option<nelomai_client_api::TokenResponse>, crate::NativeAuthFailure> {
        *self.request.lock().unwrap() = Some(request);
        self.response
            .lock()
            .await
            .take()
            .unwrap()
            .await
            .map(Some)
            .map_err(|_| crate::NativeAuthFailure::OutcomeUnknown)
    }
}

async fn delayed_remote_native(case: u8) {
    let fixture = Fixture::new(ClientApi::new("http://127.0.0.1:9").unwrap(), true);
    let mut auth = fixture.auth.load().unwrap().unwrap();
    auth.broker.as_mut().unwrap().confirmed_device_id = Some("device".into());
    fixture.auth.save(&auth).unwrap();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let native = Arc::new(HeldNative {
        request: Mutex::new(None),
        response: tokio::sync::Mutex::new(Some(receiver)),
    });
    let (stream, mut peer) = private_socketpair().unwrap();
    let owner = RemoteOwner::new_with_background(
        stream,
        LaunchBinding::fixture(
            RuntimeTarget {
                container_version: "0.2.16".into(),
                runtime_version: "0.2.16".into(),
                runtime_contract_version: 1,
                runtime_slot: RuntimeSlot::Stable,
            },
            "native-budget",
        ),
        RuntimeClientProfile {
            platform: Platform::Macos,
            platform_version: None,
            architecture: "aarch64".into(),
        },
        Some(native.clone()),
    )
    .unwrap();
    let (stamp, _) = fixture.broker.observe_stamped().await.unwrap();
    let deadline = Instant::now() + REQUEST_BUDGET;
    let work = owner.request(
        &fixture.broker,
        500,
        AuthRequestV1::BackgroundCredential {
            stamp: Some(stamp),
            action: BackgroundAction::Recover,
        },
        deadline,
    );
    tokio::pin!(work);
    poll_pending(work.as_mut()).await;
    let prepare = read_frame(&mut peer, deadline).await.unwrap();
    assert!(matches!(
        prepare.message,
        MessageV1::Control(ControlV1::Prepare { .. })
    ));
    tokio::time::advance(Duration::from_secs(4)).await;
    remote::acknowledge_test_control(
        &owner,
        prepare.id,
        ControlAckV1::Prepared {
            lease: PreparedLease {
                incarnation: "native-budget".into(),
                request: prepare.id,
                cancel_generation: 0,
            },
        },
    );
    poll_pending(work.as_mut()).await;
    let validate = read_frame(&mut peer, deadline).await.unwrap();
    assert!(matches!(
        validate.message,
        MessageV1::Control(ControlV1::ValidateScope { .. })
    ));
    tokio::time::advance(Duration::from_secs(2)).await;
    remote::acknowledge_test_control(&owner, validate.id, ControlAckV1::Done);
    poll_pending(work.as_mut()).await;
    let request = native
        .request
        .lock()
        .unwrap()
        .take()
        .expect("native operation dispatched");
    let before = fixture.auth.load().unwrap();
    if case == 0 {
        let wire: serde_json::Value =
            serde_json::from_str(&request.operation_json().unwrap()).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let remaining = wire["expires_at_unix_ms"]
            .as_u64()
            .unwrap()
            .saturating_sub(now);
        assert!(
            (3_900..=4_000).contains(&remaining),
            "six seconds in controls must leave only four native seconds; got {remaining}ms"
        );
        return;
    }
    tokio::time::advance(Duration::from_secs(4)).await;
    if case == 2 {
        sender.send(recovered_response()).unwrap();
    }
    let result = tokio::time::timeout(Duration::from_millis(1), work.as_mut()).await;
    assert!(
        matches!(result, Ok(Err(PrivateError::Timeout))),
        "native wait and ready late callback must expire at the original deadline: {result:?}"
    );
    assert_eq!(
        fixture.auth.load().unwrap(),
        before,
        "late callback must not mutate protected auth"
    );
}

#[tokio::test(start_paused = true)]
async fn remote_native_preparation_spends_original_budget() {
    delayed_remote_native(0).await;
}
#[tokio::test(start_paused = true)]
async fn remote_native_wait_expires_at_original_deadline() {
    delayed_remote_native(1).await;
}
#[tokio::test(start_paused = true)]
async fn remote_native_ready_late_callback_cannot_mutate_auth() {
    delayed_remote_native(2).await;
}

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

struct HeldRuntimeRestart {
    entered: tokio::sync::Notify,
    stop_checks_complete: tokio::sync::Notify,
    stage: AtomicUsize,
}

#[async_trait::async_trait]
impl crate::host::PrivateOwnerCommands for HeldRuntimeRestart {
    async fn dispatch(
        &self,
        _: &RuntimeTarget,
        request: crate::host::HostRequestV1,
    ) -> Result<crate::host::HostResponseV1, PrivateError> {
        assert!(matches!(
            request,
            crate::host::HostRequestV1::RuntimeRestart
        ));
        self.stage.store(1, Ordering::SeqCst);
        self.entered.notify_one();
        self.stop_checks_complete.notified().await;
        self.stage.store(2, Ordering::SeqCst);
        Ok(crate::host::HostResponseV1::Done)
    }
}

#[tokio::test]
async fn accepted_runtime_restart_survives_peer_eof_until_owner_release() {
    let fixture = Fixture::new(ClientApi::new("http://127.0.0.1:9").unwrap(), true);
    let commands = Arc::new(HeldRuntimeRestart {
        entered: tokio::sync::Notify::new(),
        stop_checks_complete: tokio::sync::Notify::new(),
        stage: AtomicUsize::new(0),
    });
    let (owner_socket, mut runtime_socket) = private_socketpair().unwrap();
    let owner = RemoteOwner::new_with_owner(
        owner_socket,
        LaunchBinding::fixture(
            RuntimeTarget {
                container_version: "0.2.16".into(),
                runtime_version: "0.2.16".into(),
                runtime_contract_version: 1,
                runtime_slot: RuntimeSlot::Stable,
            },
            "restart-eof",
        ),
        RuntimeClientProfile {
            platform: Platform::Android,
            platform_version: None,
            architecture: "aarch64".into(),
        },
        None,
        Some(commands.clone()),
    )
    .unwrap();
    let _service = owner.serve(fixture.broker.clone()).unwrap();
    write_frame(
        &mut runtime_socket,
        FrameV1::new(
            42,
            MessageV1::Request(AuthRequestV1::Owner {
                request: crate::host::HostRequestV1::RuntimeRestart,
            }),
        ),
        Instant::now() + REQUEST_BUDGET,
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(1), commands.entered.notified())
        .await
        .expect("restart must enter common owner dispatch");
    drop(runtime_socket);
    tokio::time::timeout(Duration::from_secs(1), async {
        while owner.is_connected() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("runtime EOF must reach owner pump");
    assert_eq!(commands.stage.load(Ordering::SeqCst), 1);
    commands.stop_checks_complete.notify_one();
    tokio::time::timeout(Duration::from_millis(100), async {
        while commands.stage.load(Ordering::SeqCst) != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("accepted restart must release owner after stop checks despite peer EOF");
}

#[derive(Clone, Default)]
struct Record(Arc<Mutex<Option<Vec<u8>>>>);

#[tokio::test]
async fn legacy_logout_recovers_empty_orphan_scope_but_preserves_operational_state() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let router = axum::Router::new().route("/api/client/v1/auth/logout-runtime", axum::routing::post(|| async {
        axum::Json(serde_json::json!({"api_version":"1","request_id":"synthetic","code":"session_revoked_cleanup_accepted", "cleanup_reconcile_operation_id":"22222222-2222-4222-8222-222222222222"}))
    }));
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let fixture = Fixture::new(api, true);
    fixture
        .parent
        .admit_empty_current(&fixture.broker)
        .await
        .unwrap();
    // Reproduce the pre-provider Android lost update: owner auth is legacy,
    // while the runtime has already durably bound a different scoped family.
    let mut auth = fixture.auth.load().unwrap().unwrap();
    auth.confirmed_identity = None;
    auth.session_generation = None;
    let meta = auth.broker.as_mut().unwrap();
    meta.family = "33333333-3333-4333-8333-333333333333".into();
    meta.confirmed_device_id = Some("11111111-1111-4111-8111-111111111111".into());
    fixture.auth.save(&auth).unwrap();
    fixture.broker.logout().await.unwrap();
    let receipt = fixture
        .broker
        .completed_runtime_logout()
        .await
        .unwrap()
        .unwrap();
    assert!(receipt.source.identity.is_none());
    let operational = fixture.record.operational();
    let empty = operational.load().unwrap().unwrap();
    assert_ne!(
        empty.auth_scope.as_ref().unwrap().family,
        receipt.source.family
    );
    let deadline = Instant::now() + REQUEST_BUDGET;
    let lease = fixture.parent.prepare(deadline).await.unwrap();
    fixture
        .broker
        .stop_runtime_logout_cleanup(&receipt)
        .await
        .unwrap();
    let mut nonempty = empty.clone();
    nonempty.compatibility = Some(StoredCompatibility {
        update_required: false,
        observed_at_unix: 1,
    });
    let mut pending = empty.clone();
    pending.pending_compensation_stop = Some(StoredPendingCompensationStop {
        operation_id: "synthetic-stop".into(),
        lease_id: "synthetic-lease".into(),
        accept_warm: false,
        failure_code: None,
    });
    let mut split = empty.clone();
    split.applied_split_tunnel.last_full_sync_unix = Some(1);
    for state in [nonempty, pending, split] {
        operational.save(&state).unwrap();
        fixture
            .record
            .split()
            .save(&state.applied_split_tunnel)
            .unwrap();
        assert!(!operational.load().unwrap().unwrap().operationally_empty());
        let before = fixture.runtime_backend.load_record().unwrap();
        assert!(matches!(
            fixture
                .parent
                .control(
                    ControlV1::CompleteLogout {
                        lease: lease.clone(),
                        receipt: receipt.clone()
                    },
                    deadline
                )
                .await,
            Err(_) | Ok(ControlAckV1::Error { .. })
        ));
        assert_eq!(fixture.runtime_backend.load_record().unwrap(), before);
    }
    operational.save(&empty).unwrap();
    fixture
        .record
        .split()
        .save(&empty.applied_split_tunnel)
        .unwrap();
    assert!(matches!(
        fixture
            .parent
            .control(
                ControlV1::CompleteLogout {
                    lease: lease.clone(),
                    receipt
                },
                deadline
            )
            .await
            .unwrap(),
        ControlAckV1::Done
    ));
    let cleared = operational.load().unwrap().unwrap();
    assert!(cleared.auth_scope.is_none());
    assert!(cleared.operationally_empty());
    fixture.child.abort(&lease);
    fixture
        .broker
        .finish_runtime_logout_cleanup(
            &fixture
                .broker
                .completed_runtime_logout()
                .await
                .unwrap()
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(
        fixture.client.access(None).await,
        Err(nelomai_client_core::CoreError::SignedOut)
    ));
    server.abort();
}

#[tokio::test]
async fn completed_logout_clears_only_receipt_source_under_live_child_lease() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let router = axum::Router::new().route("/api/client/v1/auth/logout-runtime", axum::routing::post(|| async {
        axum::Json(serde_json::json!({"api_version":"1","request_id":"synthetic","code":"session_revoked_cleanup_accepted", "cleanup_reconcile_operation_id":"22222222-2222-4222-8222-222222222222"}))
    }));
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let fixture = Fixture::new(api, true);
    let mut auth = fixture.auth.load().unwrap().unwrap();
    auth.broker.as_mut().unwrap().confirmed_device_id =
        Some("11111111-1111-4111-8111-111111111111".into());
    fixture.auth.save(&auth).unwrap();
    fixture
        .parent
        .admit_empty_current(&fixture.broker)
        .await
        .unwrap();
    fixture.client.access(None).await.unwrap();
    fixture.broker.logout().await.unwrap();
    let receipt = fixture
        .broker
        .completed_runtime_logout()
        .await
        .unwrap()
        .unwrap();
    assert!(fixture
        .record
        .cleanup_snapshot()
        .unwrap()
        .auth_scope
        .is_some());
    let deadline = Instant::now() + REQUEST_BUDGET;
    let lease = fixture.parent.prepare(deadline).await.unwrap();
    let mut foreign = receipt.clone();
    foreign.source.identity.as_mut().unwrap().runtime_version = "0.2.17".into();
    let before = fixture.record.cleanup_snapshot().unwrap();
    assert!(matches!(
        fixture
            .parent
            .control(
                ControlV1::CompleteLogout {
                    lease: lease.clone(),
                    receipt: foreign
                },
                deadline
            )
            .await,
        Err(_) | Ok(ControlAckV1::Error { .. })
    ));
    assert_eq!(fixture.record.cleanup_snapshot().unwrap(), before);
    assert!(matches!(
        fixture
            .parent
            .control(
                ControlV1::CompleteLogout {
                    lease: lease.clone(),
                    receipt
                },
                deadline
            )
            .await
            .unwrap(),
        ControlAckV1::Done
    ));
    assert!(fixture
        .record
        .cleanup_snapshot()
        .unwrap()
        .auth_scope
        .is_none());
    assert!(fixture.client.check_start_barrier().is_err());
    fixture.child.abort(&lease);
    server.abort();
}
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
    auth_backend: Record,
    runtime_backend: Record,
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
        let auth_backend = Record::default();
        let auth = Arc::new(ProtectedAuthStore::new(auth_backend.clone()));
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
        let runtime_backend = Record::default();
        let store = ProtectedRuntimeStore::new(runtime_backend.clone(), paths);
        let mut initial = RuntimeStateV1::import_legacy(
            &legacy,
            StoredSplitTunnelState::default(),
            store.paths(),
        );
        initial.cleanup_only = false;
        store.save(&initial).unwrap();
        Self::from_records(root, api, auth_backend, runtime_backend, background, pause)
    }

    fn from_records(
        root: tempfile::TempDir,
        api: ClientApi,
        auth_backend: Record,
        runtime_backend: Record,
        background: Option<Arc<dyn PrivateBackgroundDispatcher>>,
        pause: Option<Arc<AdmissionPause>>,
    ) -> Self {
        let target = RuntimeTarget {
            container_version: "0.2.16".into(),
            runtime_version: "0.2.16".into(),
            runtime_contract_version: 1,
            runtime_slot: RuntimeSlot::Stable,
        };
        let auth = Arc::new(ProtectedAuthStore::new(auth_backend.clone()));
        let paths = RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap();
        let store = ProtectedRuntimeStore::new(runtime_backend.clone(), paths);
        let record = RuntimeRecordOwner::new(store);
        let tunnel = Arc::new(Tunnel::default());
        let stop = CoreLocalStop::new(tunnel.clone());
        let child = Arc::new(ChildAdmission::new(
            "fixture-child".into(),
            stop.runtime_writer_gates(),
            Arc::new(RuntimeRecordInventory::new(record.clone(), vec![])),
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
            auth_backend,
            runtime_backend,
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
#[tokio::test]
async fn private_access_waits_for_live_refresh_without_false_recovery() {
    for stale_request in [false, true] {
        private_access_during_refresh(stale_request, false).await;
    }
}

#[tokio::test]
async fn private_access_preserves_recovery_after_failed_refresh() {
    private_access_during_refresh(false, true).await;
}

async fn private_access_during_refresh(stale_request: bool, fail: bool) {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let incoming = entered.clone();
    let released = release.clone();
    let observed = calls.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let router = axum::Router::new().route("/api/client/v1/auth/refresh-recoverable", axum::routing::post(move || {
        let incoming = incoming.clone();
        let released = released.clone();
        let observed = observed.clone();
        async move {
            use axum::response::IntoResponse;
            observed.fetch_add(1, Ordering::SeqCst);
            incoming.notify_one();
            released.notified().await;
            if fail {
                axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
            } else {
                axum::Json(serde_json::json!({
                    "api_version":"1", "request_id":"synthetic", "token_type":"Bearer",
                    "access_token":"recovered-access", "access_expires_in":900,
                    "refresh_token":"recovered-refresh", "refresh_expires_in":3600,
                    "access":{"state":"active","can_login":true,"can_connect":true,"expires_at":null},
                    "device":{"id":"device","name":"synthetic","platform":"macos",
                        "container_version":"0.2.16","runtime_version":"0.2.16",
                        "runtime_contract_version":1,"runtime_slot":"stable","session_generation":1}
                })).into_response()
            }
        }
    }));
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let fixture = Fixture::new(api, true);
    let mut initial = fixture.auth.load().unwrap().unwrap();
    initial.broker.as_mut().unwrap().confirmed_device_id = Some("device".into());
    fixture.auth.save(&initial).unwrap();
    fixture
        .parent
        .admit_empty_current(&fixture.broker)
        .await
        .unwrap();
    let old = fixture.client.access(None).await.unwrap();
    let client = fixture.client.clone();
    let stale = old.clone();
    let refresh = tokio::spawn(async move { client.access(Some(&stale)).await });
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .unwrap();
    let mut waiting = Box::pin(fixture.client.access(stale_request.then_some(&old)));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut waiting)
            .await
            .is_err(),
        "live refresh must be awaited, not reported as broken authorization"
    );
    release.notify_one();
    let refreshed = refresh.await.unwrap();
    let result = waiting.await;
    if fail {
        assert!(refreshed.is_err());
        assert!(matches!(
            result,
            Err(nelomai_client_core::CoreError::Api(
                nelomai_client_core::CoreApiError::Retryable
            ))
        ));
        assert!(fixture.client.access(None).await.is_err());
        assert!(fixture
            .auth
            .load()
            .unwrap()
            .unwrap()
            .broker
            .unwrap()
            .pending_request
            .is_some());
    } else {
        let refreshed = refreshed.unwrap();
        assert_eq!(result.unwrap(), refreshed);
        assert_eq!(refreshed.access_token(), "recovered-access");
        assert_eq!(refreshed.identity(), old.identity());
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "never rotate the same refresh proof twice"
    );
    server.abort();
}

fn recovered_response() -> nelomai_client_api::TokenResponse {
    serde_json::from_value(serde_json::json!({"api_version":"1","request_id":"synthetic","token_type":"Bearer","access_token":"recovered-access","access_expires_in":900,"refresh_token":"recovered-refresh","refresh_expires_in":3600,"access":{"state":"active","can_login":true,"can_connect":true,"expires_at":null},"device":{"id":"device","name":"synthetic","platform":"macos","container_version":"0.2.16","runtime_version":"0.2.16","runtime_contract_version":1,"runtime_slot":"stable","session_generation":1}})).unwrap()
}
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
        Ok(Some(recovered_response()))
    }
}

#[tokio::test]
async fn closed_restart_recovers_only_matching_persisted_scope_after_lost_refresh() {
    for persisted_scope in ["matching", "missing", "foreign"] {
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
        let fixture = Fixture::with_background(api.clone(), true, Some(native.clone()));
        let mut initial = fixture.auth.load().unwrap().unwrap();
        initial.broker.as_mut().unwrap().confirmed_device_id = Some("device".into());
        fixture.auth.save(&initial).unwrap();
        let access = fixture.broker.access_token(None).await.unwrap();
        if persisted_scope != "missing" {
            let mut scope = transport::scope(&access);
            if persisted_scope == "foreign" {
                scope.family = "another-persisted-family".into();
            }
            fixture.record.bind_empty_scope(&scope).unwrap();
        }
        assert!(fixture.child.check(&transport::scope(&access)).is_err());
        assert!(fixture.broker.access_token(Some(&access)).await.is_err());
        let failed = fixture.auth.load().unwrap().unwrap();
        assert_eq!(
            failed
                .broker
                .as_ref()
                .unwrap()
                .pending_request
                .as_ref()
                .unwrap()
                .kind,
            BrokerRequestKind::Refresh
        );
        let retained_runtime = fixture.record.operational().load().unwrap();
        // Copy the actual encoded protected records, then destroy the first
        // owner, child, transport, gates and runtime record owner completely.
        let auth_bytes = fixture.auth_backend.load_record().unwrap();
        let runtime_bytes = fixture.runtime_backend.load_record().unwrap();
        let old_owner = Arc::downgrade(&fixture.parent);
        let old_broker = Arc::downgrade(&fixture.broker);
        drop(fixture);
        tokio::time::timeout(Duration::from_secs(1), async {
            while old_owner.upgrade().is_some() || old_broker.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("old owner and broker must actually terminate before reconstruction");
        let fixture = Fixture::from_records(
            tempfile::tempdir().unwrap(),
            api,
            Record(Arc::new(Mutex::new(auth_bytes))),
            Record(Arc::new(Mutex::new(runtime_bytes))),
            Some(native.clone()),
            None,
        );
        assert_eq!(fixture.auth.load().unwrap(), Some(failed.clone()));
        assert_eq!(
            fixture.record.operational().load().unwrap(),
            retained_runtime
        );
        assert!(
            fixture.child.check(&transport::scope(&access)).is_err(),
            "fresh child admission starts CLOSED"
        );
        assert_eq!(
            fixture.client.state().await.unwrap(),
            RuntimeAuthState::RecoveryRequired
        );
        let result = fixture.client.background(BackgroundAction::Recover).await;
        if persisted_scope == "matching" {
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
            assert_eq!(fixture.auth.load().unwrap(), Some(failed));
            assert_eq!(
                fixture.record.operational().load().unwrap(),
                retained_runtime
            );
            assert!(fixture.child.check(&transport::scope(&access)).is_err());
        }
        server.abort();
    }
}

struct Provision(AtomicUsize, AtomicUsize);

struct RefuseRecovery(bool);
#[async_trait::async_trait]
impl PrivateBackgroundDispatcher for RefuseRecovery {
    async fn prepare_revocation(&self, _: u64) -> Result<(), crate::BrokerError> {
        Ok(())
    }
    async fn dispatch(
        &self,
        _: crate::NativeAuthRequest,
        action: BackgroundAction,
    ) -> Result<Option<nelomai_client_api::TokenResponse>, crate::NativeAuthFailure> {
        assert!(matches!(action, BackgroundAction::Recover));
        Err(if self.0 {
            crate::NativeAuthFailure::OutcomeUnknown
        } else {
            crate::NativeAuthFailure::NotIssued
        })
    }
}

#[tokio::test]
async fn refused_private_recovery_restores_only_known_current_admission_for_refresh_fallback() {
    for unknown in [false, true] {
        let fixture = Fixture::with_background(
            ClientApi::new("http://127.0.0.1:9").unwrap(),
            true,
            Some(Arc::new(RefuseRecovery(unknown))),
        );
        let mut auth = fixture.auth.load().unwrap().unwrap();
        auth.broker.as_mut().unwrap().confirmed_device_id = Some("synthetic-device".into());
        fixture.auth.save(&auth).unwrap();
        fixture
            .parent
            .admit_empty_current(&fixture.broker)
            .await
            .unwrap();
        let original = fixture.client.access(None).await.unwrap();
        assert!(fixture
            .client
            .background(BackgroundAction::Recover)
            .await
            .is_err());
        let fallback = fixture.client.access(None).await;
        if unknown {
            assert!(fallback.is_err());
            assert!(fixture.child.check(&transport::scope(&original)).is_err());
        } else {
            assert_eq!(fallback.unwrap(), original);
            fixture.child.check(&transport::scope(&original)).unwrap();
        }
        assert_eq!(
            fixture.auth.load().unwrap().unwrap().refresh_token,
            auth.refresh_token
        );
    }
}

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
        let check = read_frame(&mut peer, started + REQUEST_BUDGET)
            .await
            .unwrap();
        assert!(matches!(
            check.message,
            MessageV1::Control(ControlV1::CheckScope { .. })
        ));
        write_frame(
            &mut peer,
            FrameV1::new(
                check.id,
                MessageV1::Ack(ControlAckV1::Error {
                    error: PrivateError::RecoveryRequired,
                }),
            ),
            started + REQUEST_BUDGET,
        )
        .await
        .unwrap();
        let prepare = read_frame(&mut peer, started + REQUEST_BUDGET)
            .await
            .unwrap();
        assert!(matches!(
            prepare.message,
            MessageV1::Control(ControlV1::Prepare { .. })
        ));
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
