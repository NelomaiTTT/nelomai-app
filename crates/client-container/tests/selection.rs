use ed25519_dalek::{Signer, SigningKey};
use nelomai_client_container::{InstalledRuntimeSelection, SelectionRecovery, SlotSelectionV1};
use nelomai_client_storage::{
    ContainerOwnerLock, ProtectedRecordFactory, ProtectedRecordStore, SecretStore, StorageError,
    StoredAuth,
};
use nelomai_contracts::{
    ContainerManifestV1, RuntimeArtifactManifestV1, RuntimeFileRole, RuntimeFileV1, RuntimeSlot,
    RuntimeSlotManifestV1, CONTAINER_MANIFEST_SIGNATURE_DOMAIN,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Clone, Default)]
struct Records {
    values: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    fail_once: Arc<Mutex<Option<String>>>,
    legacy: Legacy,
}

#[derive(Clone, Default)]
struct Legacy(Arc<Mutex<Option<StoredAuth>>>);

impl SecretStore for Legacy {
    fn load(&self) -> Result<Option<StoredAuth>, StorageError> {
        Ok(self.0.lock().unwrap().clone())
    }

    fn save(&self, value: &StoredAuth) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = Some(value.clone());
        Ok(())
    }

    fn delete(&self) -> Result<(), StorageError> {
        panic!("selection startup must not delete the legacy store")
    }
}

struct Record {
    key: String,
    records: Records,
}

impl ProtectedRecordStore for Record {
    fn load_record(&self) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.records.values.lock().unwrap().get(&self.key).cloned())
    }

    fn save_record(&self, bytes: &[u8]) -> Result<(), StorageError> {
        let mut fail = self.records.fail_once.lock().unwrap();
        if fail.as_deref() == Some(&self.key) {
            *fail = None;
            return Err(StorageError::RecoveryRequired(
                "synthetic one-shot record save failure",
            ));
        }
        self.records
            .values
            .lock()
            .unwrap()
            .insert(self.key.clone(), bytes.to_vec());
        Ok(())
    }

    fn delete_record(&self) -> Result<(), StorageError> {
        self.records.values.lock().unwrap().remove(&self.key);
        Ok(())
    }
}

impl ProtectedRecordFactory for Records {
    type Record = Record;

    fn record(&self, namespace: &str) -> Self::Record {
        Record {
            key: namespace.to_owned(),
            records: self.clone(),
        }
    }

    fn legacy(&self) -> &dyn SecretStore {
        &self.legacy
    }
}

fn artifact(version: &str, slot: RuntimeSlot) -> RuntimeSlotManifestV1 {
    RuntimeSlotManifestV1 {
        slot,
        manifest: RuntimeArtifactManifestV1 {
            format_version: 1,
            runtime_version: version.to_owned(),
            source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            platform: "linux".to_owned(),
            architecture: "x86_64".to_owned(),
            contract_version: 1,
            files: vec![RuntimeFileV1 {
                path: "bin/nelomai-runtime".to_owned(),
                size_bytes: 17,
                sha256: {
                    use sha2::Digest;
                    format!("{:x}", sha2::Sha256::digest(b"synthetic-runtime"))
                },
                role: RuntimeFileRole::Executable,
            }],
        },
    }
}

fn install_manifest(resources: &std::path::Path, version: &str, stable: bool) -> [u8; 32] {
    install_manifest_platform(resources, version, stable, "linux", "x86_64")
}

fn install_manifest_platform(
    resources: &std::path::Path,
    version: &str,
    stable: bool,
    platform: &str,
    architecture: &str,
) -> [u8; 32] {
    std::fs::create_dir_all(resources).unwrap();
    let mut slots = vec![artifact(version, RuntimeSlot::Latest)];
    let (stable_release_set_sha256, stable_platform_manifest_sha256) = if stable {
        slots.push(artifact("0.2.15", RuntimeSlot::Stable));
        (Some("b".repeat(64)), Some("c".repeat(64)))
    } else {
        (None, None)
    };
    for slot in &mut slots {
        slot.manifest.platform = platform.into();
        slot.manifest.architecture = architecture.into();
        let name = match slot.slot {
            RuntimeSlot::Latest => "latest",
            RuntimeSlot::Stable => "stable",
        };
        let directory = resources
            .join("engines")
            .join(name)
            .join(&slot.manifest.runtime_version)
            .join("bin");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("nelomai-runtime"), b"synthetic-runtime").unwrap();
    }
    let manifest = ContainerManifestV1 {
        format_version: 1,
        container_version: version.to_owned(),
        release_set_id: format!("runtime-{version}"),
        minimum_runtime_contract: 1,
        maximum_runtime_contract: 1,
        stable_release_set_sha256,
        stable_platform_manifest_sha256,
        slots,
    };
    let bytes = serde_json::to_vec(&serde_json::to_value(manifest).unwrap()).unwrap();
    let key = SigningKey::from_bytes(&[41; 32]);
    let mut signed = CONTAINER_MANIFEST_SIGNATURE_DOMAIN.to_vec();
    signed.extend_from_slice(&bytes);
    std::fs::write(resources.join("container-manifest-v1.json"), bytes).unwrap();
    std::fs::write(
        resources.join("container-manifest-v1.sig"),
        key.sign(&signed).to_bytes(),
    )
    .unwrap();
    key.verifying_key().to_bytes()
}

fn selection_path(root: &std::path::Path) -> std::path::PathBuf {
    root.join("common/runtime-selection-v1.json")
}

#[test]
fn common_host_rejects_bad_manifest_before_constructing_secret_backend() {
    let data = tempfile::tempdir().unwrap();
    let resources = tempfile::tempdir().unwrap();
    let key = install_manifest(resources.path(), "0.2.16", false);
    std::fs::write(resources.path().join("container-manifest-v1.sig"), [0; 64]).unwrap();
    let result = nelomai_client_container::host::prepare_host(
        data.path(),
        resources.path(),
        Some(&key),
        "linux",
        "x86_64",
        || -> Records { panic!("unverified startup reached protected backend") },
    );
    assert!(result.is_err());
    assert!(!selection_path(data.path()).exists());
}

#[test]
fn common_host_rejects_second_owner_before_constructing_secret_backend() {
    let data = tempfile::tempdir().unwrap();
    let resources = tempfile::tempdir().unwrap();
    let key = install_manifest(resources.path(), "0.2.16", false);
    let _owner = ContainerOwnerLock::try_acquire(data.path()).unwrap();
    let result = nelomai_client_container::host::prepare_host(
        data.path(),
        resources.path(),
        Some(&key),
        "linux",
        "x86_64",
        || -> Records { panic!("secondary startup reached protected backend") },
    );
    assert!(result.is_err());
}

#[test]
fn durable_requested_intent_recovers_pending_and_next_startup_target_without_second_write() {
    use nelomai_client_container::{
        CleanupEngineRoleV1, CleanupEnvelopeV1, SwitchCoordinator, SwitchJournalV1,
    };
    let data = tempfile::tempdir().unwrap();
    let resources = tempfile::tempdir().unwrap();
    let key = install_manifest(resources.path(), "0.2.16", true);
    let records = Records::default();
    let host = nelomai_client_container::host::prepare_host(
        data.path(),
        resources.path(),
        Some(&key),
        "linux",
        "x86_64",
        || records.clone(),
    )
    .unwrap();
    let coordinator =
        SwitchCoordinator::open(host.owner.clone(), host.selection.manifest().clone()).unwrap();
    let target = nelomai_client_api::RuntimeTarget::from_identity(
        &host
            .selection
            .manifest()
            .identity(RuntimeSlot::Stable, None)
            .unwrap(),
    );
    let journal = SwitchJournalV1::requested(
        "11111111-1111-4111-8111-111111111111".into(),
        "b".repeat(64),
        None,
        Some("device-a".into()),
        "c".repeat(64),
        target.clone(),
        None,
        CleanupEnvelopeV1 {
            cleanup_contract_version: 1,
            lease_ids: vec![],
            redundant_session_ids: vec![],
            operations: vec![],
            engine_role: CleanupEngineRoleV1::Primary,
            background_reference: None,
        },
    );
    coordinator.begin_requested(journal.clone()).unwrap();
    // The only committed write is the Requested journal: simulate death before
    // any projection write, without modifying the committed journal afterward.
    assert_eq!(
        coordinator
            .status_for(host.selection.target())
            .unwrap()
            .pending_slot,
        Some(RuntimeSlot::Stable)
    );
    assert_eq!(host.selection.target().runtime_slot, RuntimeSlot::Latest);
    drop(coordinator);
    drop(host);
    let reopened = nelomai_client_container::host::prepare_host(
        data.path(),
        resources.path(),
        Some(&key),
        "linux",
        "x86_64",
        || records.clone(),
    )
    .unwrap();
    assert_eq!(reopened.selection.target(), &target);
    let coordinator = SwitchCoordinator::open(
        reopened.owner.clone(),
        reopened.selection.manifest().clone(),
    )
    .unwrap();
    assert_eq!(coordinator.snapshot().unwrap(), Some(journal));
}

#[test]
fn common_host_keeps_exclusive_owner_and_preserves_install_identity_on_reopen() {
    let data = tempfile::tempdir().unwrap();
    let resources = tempfile::tempdir().unwrap();
    let key = install_manifest(resources.path(), "0.2.16", false);
    let records = Records::default();
    let host = nelomai_client_container::host::prepare_host(
        data.path(),
        resources.path(),
        Some(&key),
        "linux",
        "x86_64",
        || records.clone(),
    )
    .unwrap();
    assert_eq!(host.selection.target().runtime_version, "0.2.16");
    assert_eq!(host.selection.target().runtime_slot, RuntimeSlot::Latest);
    assert!(host
        .selection
        .target()
        .identity(None)
        .unwrap()
        .session_generation
        .is_none());
    assert!(ContainerOwnerLock::try_acquire(data.path()).is_err());
    let first = records
        .values
        .lock()
        .unwrap()
        .get("auth-v1")
        .unwrap()
        .clone();
    drop(host);
    let _reopened = nelomai_client_container::host::prepare_host(
        data.path(),
        resources.path(),
        Some(&key),
        "linux",
        "x86_64",
        || records.clone(),
    )
    .unwrap();
    assert_eq!(
        records.values.lock().unwrap().get("auth-v1").unwrap(),
        &first
    );
}

#[cfg(unix)]
struct NoNativeWork;
#[cfg(unix)]
#[async_trait::async_trait]
impl nelomai_client_container::LocalAuthStop for NoNativeWork {
    async fn stop_local(&self) -> Result<(), nelomai_client_container::BrokerError> {
        Ok(())
    }
}
#[cfg(unix)]
#[async_trait::async_trait]
impl nelomai_client_container::ipc::PrivateBackgroundDispatcher for NoNativeWork {
    async fn prepare_revocation(
        &self,
        _: u64,
    ) -> Result<(), nelomai_client_container::BrokerError> {
        Ok(())
    }
    async fn dispatch(
        &self,
        _: nelomai_client_container::NativeAuthRequest,
        _: nelomai_client_container::ipc::BackgroundAction,
    ) -> Result<
        Option<nelomai_client_api::TokenResponse>,
        nelomai_client_container::NativeAuthFailure,
    > {
        panic!("logged-out startup must not issue native credentials")
    }
}

#[cfg(unix)]
#[tokio::test]
async fn common_owner_is_ready_without_loading_product_runtime_and_rejects_foreign_uid() {
    use nelomai_client_container::host::{CommonHost, HostNativePorts, RuntimeAttachRequest};
    let data = tempfile::tempdir().unwrap();
    let resources = tempfile::tempdir().unwrap();
    let key = install_manifest_platform(resources.path(), "0.2.16", false, "android", "aarch64");
    let host = CommonHost::open(
        data.path(),
        resources.path(),
        Some(&key),
        "android",
        "aarch64",
        Records::default,
        nelomai_client_api::ClientApi::new("http://127.0.0.1:9").unwrap(),
        nelomai_client_container::RuntimeClientProfile {
            platform: nelomai_contracts::Platform::Android,
            platform_version: None,
            architecture: "aarch64".into(),
        },
        HostNativePorts {
            stop: Arc::new(NoNativeWork),
            force: Arc::new(nelomai_client_container::UnavailableRuntimeForceStop),
            background: Arc::new(NoNativeWork),
            updater: None,
            storage: None,
            relaunch: None,
        },
    )
    .unwrap();
    let view = host.selection().await.unwrap();
    assert_eq!(view.target.runtime_slot, RuntimeSlot::Latest);
    assert_eq!(view.target.container_version, "0.2.16");
    assert_eq!(view.session_generation, None);
    assert_eq!(view.pending_slot, None);
    assert!(ContainerOwnerLock::try_acquire(data.path()).is_err());
    let (stream, _peer) = tokio::io::duplex(1024);
    let request = RuntimeAttachRequest {
        target: view.target,
        session_generation: None,
        incarnation: view.incarnation,
    };
    let uid = unsafe { libc::geteuid() };
    assert!(host
        .attach_android(stream, 999, uid + 1, uid, &request)
        .await
        .is_err());
    assert_eq!(
        host.broker().observe().await.unwrap().state,
        nelomai_client_container::BrokerAuthState::RecoveryRequired
    );
    let (stream, mut accepted_peer) = tokio::io::duplex(1024);
    assert!(host
        .attach_android(stream, 999, uid, uid, &request)
        .await
        .is_ok());
    use nelomai_client_container::ipc::*;
    let deadline = tokio::time::Instant::now() + REQUEST_BUDGET;
    write_frame(
        &mut accepted_peer,
        FrameV1::new(
            1,
            MessageV1::Request(AuthRequestV1::Owner {
                request: nelomai_client_container::host::HostRequestV1::RuntimeStatus,
            }),
        ),
        deadline,
    )
    .await
    .unwrap();
    let response = read_frame(&mut accepted_peer, deadline).await.unwrap();
    assert_eq!(response.id, 1);
    match response.message {
        MessageV1::Response(AuthResponseV1::Owner {
            response: nelomai_client_container::host::HostResponseV1::RuntimeStatus { status },
        }) => {
            assert_eq!(status.selected_slot, RuntimeSlot::Latest);
            assert_eq!(status.pending_slot, None);
            assert!(!status.stable_available);
        }
        _ => panic!("private common owner status was not delivered"),
    }
    write_frame(
        &mut accepted_peer,
        FrameV1::new(
            2,
            MessageV1::Request(AuthRequestV1::Owner {
                request: nelomai_client_container::host::HostRequestV1::UpdateSetAutomatic {
                    enabled: false,
                },
            }),
        ),
        deadline,
    )
    .await
    .unwrap();
    match read_frame(&mut accepted_peer, deadline)
        .await
        .unwrap()
        .message
    {
        MessageV1::Response(AuthResponseV1::Owner {
            response: nelomai_client_container::host::HostResponseV1::UpdateStatus { status },
        }) => {
            assert!(!status.automatic);
            assert!(!status.supported);
            assert_eq!(status.phase, "idle");
        }
        _ => panic!("common updater preference was not applied"),
    }
    assert!(data.path().join("updates/preferences.json").is_file());
    write_frame(
        &mut accepted_peer,
        FrameV1::new(
            3,
            MessageV1::Request(AuthRequestV1::Owner {
                request: nelomai_client_container::host::HostRequestV1::RuntimeReady,
            }),
        ),
        deadline,
    )
    .await
    .unwrap();
    assert!(matches!(
        read_frame(&mut accepted_peer, deadline)
            .await
            .unwrap()
            .message,
        MessageV1::Response(AuthResponseV1::Owner {
            response: nelomai_client_container::host::HostResponseV1::Done
        })
    ));
    // Fresh/unauthenticated startup is permitted to display login, but must not
    // fabricate an access generation or grant the child start admission.
    assert_eq!(host.selection().await.unwrap().session_generation, None);
}

#[test]
fn first_start_persists_latest_only_after_real_storage_startup_succeeds() {
    let app_data = tempfile::tempdir().unwrap();
    let resources = tempfile::tempdir().unwrap();
    let key = install_manifest(resources.path(), "0.2.16", false);
    let lock = ContainerOwnerLock::try_acquire(app_data.path()).unwrap();
    let records = Records::default();

    let prepared =
        InstalledRuntimeSelection::prepare(resources.path(), &lock, Some(&key), "linux", "x86_64")
            .unwrap();
    assert_eq!(prepared.storage_slot(), RuntimeSlot::Latest);
    assert!(prepared.requires_storage_confirmation());
    assert!(!selection_path(app_data.path()).exists());

    let (selection, _storage) = prepared.prepare_runtime_storage(&lock, &records).unwrap();
    assert_eq!(selection.state().selected_slot, RuntimeSlot::Latest);
    assert_eq!(selection.state().pending_slot, None);
    assert_eq!(selection.state().container_version, "0.2.16");
    assert_eq!(selection.recovery(), None);

    let persisted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(selection_path(app_data.path())).unwrap()).unwrap();
    assert_eq!(persisted["schema_version"], 1);
    assert_eq!(persisted["container_version"], "0.2.16");
    assert_eq!(persisted["selected_slot"], "latest");
    assert!(persisted["pending_slot"].is_null());
    assert!(!app_data.path().join("runtime-selection-v1.json").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn common_host_admits_real_private_child_and_preserves_generation_without_access() {
    common_host_restart_case(false, false, false, false).await;
}

#[cfg(unix)]
#[tokio::test]
async fn common_host_cancels_prepared_apply_before_restart_without_resurrecting_stable() {
    common_host_restart_case(true, false, false, false).await;
}

#[cfg(unix)]
#[tokio::test]
async fn common_host_retries_selected_binding_when_exact_old_source_clear_failed() {
    common_host_restart_case(false, true, false, false).await;
}

#[cfg(unix)]
#[tokio::test]
async fn common_host_rejects_changed_source_before_binding_selected_empty_runtime() {
    common_host_restart_case(false, false, true, false).await;
}

#[cfg(unix)]
#[tokio::test]
async fn common_host_recovers_pending_refresh_before_real_runtime_ready_admission() {
    common_host_restart_case(false, false, false, true).await;
}

#[cfg(unix)]
async fn common_host_restart_case(
    cancel_before_restart: bool,
    fail_source_clear: bool,
    change_source: bool,
    pending_refresh: bool,
) {
    use axum::{routing::post, Json, Router};
    use nelomai_client_container::{host::*, ipc::*};
    use nelomai_client_core::{RuntimeAuthProvider, RuntimeStartPreflight, RuntimeWriterGates};
    use nelomai_client_storage::*;
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let data = tempfile::tempdir().unwrap();
    let resources = tempfile::tempdir().unwrap();
    let key = install_manifest_platform(resources.path(), "0.2.16", true, "android", "aarch64");
    let records = Records::default();
    let resume_calls = Arc::new(AtomicUsize::new(0));
    let counted = resume_calls.clone();
    let refresh_calls = Arc::new(AtomicUsize::new(0));
    let refresh_counted = refresh_calls.clone();
    let router = Router::new()
        .route("/api/client/v1/auth/refresh-recoverable", post(move |Json(body): Json<Value>| {
            let count = refresh_counted.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                assert!(matches!(body["mode"].as_str(), Some("recover_legacy_pending" | "refresh")));
                assert_eq!(body["source_identity"]["session_generation"], 7);
                let mut device = body["source_identity"].clone();
                device["id"] = body["device_id"].clone();
                device["name"] = json!("synthetic");
                device["platform"] = json!("android");
                Json(json!({"api_version":"1", "request_id":"synthetic", "device":device,
                    "token_type":"Bearer", "access_token":"recovered-access", "refresh_token":"recovered-refresh",
                    "access_expires_in":900, "refresh_expires_in":3600,
                    "access":{"state":"active", "can_login":true, "can_connect":true, "expires_at":null}}))
            }
        }))
        .route(
            "/api/client/v1/connections/runtime-switch/reconcile",
            post(|Json(body): Json<Value>| async move {
                Json(json!({"state":"clean", "operation_id":body["operation_id"],
                "retired_lease_ids":[], "retired_session_ids":[], "retired_operation_ids":[],
                "retry_after_seconds":null}))
            }),
        )
        .route(
            "/api/client/v1/auth/runtime/resume",
            post(move |Json(body): Json<Value>| {
                let counted = counted.clone();
                async move {
                    counted.fetch_add(1, Ordering::SeqCst);
                    let mut identity = body["target_identity"].clone();
                    identity["session_generation"] =
                        json!(body["expected_session_generation"].as_u64().unwrap() + 1);
                    Json(json!({"identity":identity, "access_token":"resumed-access",
                    "token_type":"Bearer", "access_expires_in":900}))
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let host = CommonHost::open(
        data.path(),
        resources.path(),
        Some(&key),
        "android",
        "aarch64",
        || records.clone(),
        nelomai_client_api::ClientApi::new(&api_url).unwrap(),
        nelomai_client_container::RuntimeClientProfile {
            platform: nelomai_contracts::Platform::Android,
            platform_version: None,
            architecture: "aarch64".into(),
        },
        HostNativePorts {
            stop: Arc::new(NoNativeWork),
            force: Arc::new(nelomai_client_container::UnavailableRuntimeForceStop),
            background: Arc::new(NoNativeWork),
            updater: None,
            storage: None,
            relaunch: None,
        },
    )
    .unwrap();
    let initial = host.selection().await.unwrap();
    let auth = ProtectedAuthStore::new(records.record("auth-v1"));
    let mut state = auth.load().unwrap().unwrap();
    state.refresh_token = Some("synthetic-refresh".into());
    state.confirmed_identity = Some(initial.target.identity(Some(7)).unwrap());
    state.session_generation = Some(7);
    state.broker.as_mut().unwrap().confirmed_device_id = Some("device-a".into());
    auth.save(&state).unwrap();
    assert_eq!(
        host.selection().await.unwrap().session_generation,
        Some(7),
        "missing access must not erase confirmed generation"
    );
    state.access_token = Some("synthetic-access".into());
    if pending_refresh {
        let meta = state.broker.as_mut().unwrap();
        meta.next_attempt += 1;
        meta.pending_request = Some(BrokerRequestV1 {
            kind: BrokerRequestKind::Refresh,
            operation_id: uuid::Uuid::new_v4().to_string(),
            auth_epoch: state.auth_epoch,
            attempt: meta.next_attempt,
            source_identity: state.confirmed_identity.clone(),
            source_device_id: meta.confirmed_device_id.clone(),
            prior_login_outcome_unknown: false,
            resume: None,
            refresh: None,
        });
    }
    auth.save(&state).unwrap();
    let view = host.selection().await.unwrap();
    let paths = view.runtime_paths().unwrap();
    let selected = paths
        .iter()
        .find(|path| {
            path.slot() == view.target.runtime_slot
                && path.runtime_version() == view.target.runtime_version
        })
        .unwrap();
    let record = RuntimeRecordOwner::new(ProtectedRuntimeStore::new(
        records.record(selected.namespace()),
        selected.clone(),
    ));
    let child = Arc::new(ChildAdmission::new(
        view.incarnation.clone(),
        Arc::new(RuntimeWriterGates::default()),
        Arc::new(RuntimeRecordInventory::new(record.clone(), vec![])),
    ));
    let (parent, child_socket) = private_socketpair().unwrap();
    let request = RuntimeAttachRequest {
        target: view.target,
        session_generation: view.session_generation,
        incarnation: view.incarnation,
    };
    let uid = unsafe { libc::geteuid() };
    host.attach_android(parent, std::process::id(), uid, uid, &request)
        .await
        .unwrap();
    let client = PrivateRuntimeAuthClient::new(child_socket, child, Arc::new(NoNativeWork));
    assert!(client.access(None).await.is_err());
    assert!(client.check_start_barrier().is_err());
    let ready = client.owner_request(HostRequestV1::RuntimeReady).await;
    assert!(
        matches!(ready, Ok(HostResponseV1::Done)),
        "ready={ready:?}, refresh_calls={}, pending={:?}",
        refresh_calls.load(Ordering::SeqCst),
        auth.load()
            .unwrap()
            .unwrap()
            .broker
            .unwrap()
            .pending_request
    );
    assert_eq!(
        client
            .access(None)
            .await
            .unwrap()
            .identity()
            .session_generation,
        Some(7)
    );
    assert!(client.check_start_barrier().is_ok());
    // A visible UI repeats RuntimeReady while admitted schedulers request access.
    // Re-admission must not temporarily revoke their scope or close the channel.
    for iteration in 0..100 {
        let (access, ready) = tokio::join!(client.access(None), async {
            for _ in 0..(iteration % 8) {
                tokio::task::yield_now().await;
            }
            client.owner_request(HostRequestV1::RuntimeReady).await
        });
        assert!(access.is_ok(), "iteration {iteration}: access={access:?}");
        assert!(ready.is_ok(), "iteration {iteration}: ready={ready:?}");
        assert!(client.check_start_barrier().is_ok());
    }
    assert_eq!(
        refresh_calls.load(Ordering::SeqCst),
        usize::from(pending_refresh)
    );
    if pending_refresh {
        // A refresh after admission must be durable without a second RuntimeReady
        // or a diagnostic IPC drain (manual reports read this journal directly).
        let stale = client.access(None).await.unwrap();
        client.access(Some(&stale)).await.unwrap();
        let journal = selected
            .operational_state
            .parent()
            .unwrap()
            .join("diagnostics/auth-refresh.jsonl");
        let saved = std::fs::read_to_string(&journal).unwrap_or_default();
        assert!(
            saved.contains("auth.refresh.begin"),
            "ordinary refresh not persisted"
        );
        assert!(saved.contains("auth.refresh.complete"));
        assert!(!saved.contains("recovered-refresh"));
        // A failed diagnostic append must not turn a successful refresh into
        // an authorization failure. Only this disposable fixture is changed.
        let directory = journal.parent().unwrap();
        let retained = directory.with_file_name("diagnostics-retained");
        std::fs::rename(directory, &retained).unwrap();
        std::fs::write(directory, "blocked diagnostic directory").unwrap();
        let stale = client.access(None).await.unwrap();
        assert!(client.access(Some(&stale)).await.is_ok());
        std::fs::remove_file(directory).unwrap();
        std::fs::rename(retained, directory).unwrap();
        let HostResponseV1::AuthRefreshDiagnostics { events } = client
            .owner_request(HostRequestV1::AuthRefreshDiagnostics)
            .await
            .unwrap()
        else {
            panic!("expected refresh diagnostics")
        };
        assert!(events
            .iter()
            .any(|event| event.kind == "auth.refresh.replay"));
        assert!(events
            .iter()
            .any(|event| event.kind == "auth.refresh.complete"));
        let safe = serde_json::to_string(&events).unwrap();
        for secret in [
            "synthetic-access",
            "synthetic-refresh",
            "recovered-access",
            "recovered-refresh",
        ] {
            assert!(!safe.contains(secret));
        }
    }
    assert!(record.cleanup_snapshot().unwrap().auth_scope.is_some());
    let installed = host.native_target().clone();
    let _reply = client
        .owner_request(HostRequestV1::RuntimeSelect {
            slot: RuntimeSlot::Stable,
        })
        .await
        .unwrap();
    assert_eq!(
        resume_calls.load(Ordering::SeqCst),
        0,
        "old host issued Apply before full restart"
    );
    assert_eq!(auth.load().unwrap().unwrap().session_generation, Some(7));
    let pending = host.selection().await.unwrap();
    assert_eq!(pending.pending_slot, Some(RuntimeSlot::Stable));
    assert_eq!(pending.target, installed);
    assert_eq!(
        host.native_target(),
        &installed,
        "pending preference retargeted the live common incarnation"
    );
    assert!(auth
        .load()
        .unwrap()
        .unwrap()
        .broker
        .unwrap()
        .pending_request
        .is_none());
    if cancel_before_restart {
        client
            .owner_request(HostRequestV1::RuntimeCancel)
            .await
            .unwrap();
        assert_eq!(resume_calls.load(Ordering::SeqCst), 1);
        let current = auth.load().unwrap().unwrap();
        assert_eq!(
            current.confirmed_identity.unwrap().slot,
            RuntimeSlot::Latest
        );
        assert_eq!(current.session_generation, Some(8));
        assert!(!host
            .coordinator()
            .status_for(host.native_target())
            .unwrap()
            .restart_required());
    }
    let expected_slot = if cancel_before_restart {
        RuntimeSlot::Latest
    } else {
        RuntimeSlot::Stable
    };
    let old_incarnation = pending.incarnation;
    drop(client);
    drop(host);
    // Closing the private channel releases its task's retained owner handle.
    let host = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if let Ok(host) = CommonHost::open(
                data.path(),
                resources.path(),
                Some(&key),
                "android",
                "aarch64",
                || records.clone(),
                nelomai_client_api::ClientApi::new(&api_url).unwrap(),
                nelomai_client_container::RuntimeClientProfile {
                    platform: nelomai_contracts::Platform::Android,
                    platform_version: None,
                    architecture: "aarch64".into(),
                },
                HostNativePorts {
                    stop: Arc::new(NoNativeWork),
                    force: Arc::new(nelomai_client_container::UnavailableRuntimeForceStop),
                    background: Arc::new(NoNativeWork),
                    updater: None,
                    storage: None,
                    relaunch: None,
                },
            ) {
                break host;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("previous common owner released after private channel exit");
    let view = host.selection().await.unwrap();
    assert_ne!(view.incarnation, old_incarnation);
    assert_eq!(view.target.runtime_slot, expected_slot);
    assert_eq!(
        resume_calls.load(Ordering::SeqCst),
        usize::from(cancel_before_restart)
    );
    let paths = view.runtime_paths().unwrap();
    let selected_index = paths
        .iter()
        .position(|path| path.slot() == expected_slot)
        .unwrap();
    let source_namespace = paths
        .iter()
        .find(|path| path.slot() == RuntimeSlot::Latest)
        .unwrap()
        .namespace()
        .to_owned();
    let mut owners: Vec<_> = paths
        .into_iter()
        .map(|path| {
            RuntimeRecordOwner::new(ProtectedRuntimeStore::new(
                records.record(path.namespace()),
                path,
            ))
        })
        .collect();
    let selected = owners.remove(selected_index);
    let selected_record = selected.clone();
    if change_source {
        let mut state = record.operational().load().unwrap().unwrap();
        state.pending_compensation_stop = Some(StoredPendingCompensationStop {
            operation_id: "changed-after-handoff".into(),
            lease_id: "synthetic-changed-lease".into(),
            accept_warm: false,
            failure_code: None,
        });
        record.operational().save(&state).unwrap();
    }
    let child = Arc::new(ChildAdmission::new(
        view.incarnation.clone(),
        Arc::new(RuntimeWriterGates::default()),
        Arc::new(RuntimeRecordInventory::new(selected, owners)),
    ));
    let (parent, child_socket) = private_socketpair().unwrap();
    host.attach_android(
        parent,
        std::process::id(),
        uid,
        uid,
        &RuntimeAttachRequest {
            target: view.target,
            session_generation: view.session_generation,
            incarnation: view.incarnation,
        },
    )
    .await
    .unwrap();
    let client = PrivateRuntimeAuthClient::new(child_socket, child, Arc::new(NoNativeWork));
    if change_source {
        assert!(client
            .owner_request(HostRequestV1::RuntimeReady)
            .await
            .is_err());
        assert!(client.check_start_barrier().is_err());
        let selected = selected_record.cleanup_snapshot().unwrap();
        assert!(selected.cleanup_only && selected.auth_scope.is_none());
        assert_eq!(
            record.cleanup_snapshot().unwrap().lease_ids,
            ["synthetic-changed-lease"]
        );
        server.abort();
        return;
    }
    if fail_source_clear {
        *records.fail_once.lock().unwrap() = Some(source_namespace);
        assert!(client
            .owner_request(HostRequestV1::RuntimeReady)
            .await
            .is_err());
        assert!(
            records.fail_once.lock().unwrap().is_none(),
            "fault reached actual old source save"
        );
        assert_eq!(resume_calls.load(Ordering::SeqCst), 1);
        assert!(client.check_start_barrier().is_err());
    }
    for _ in 0..2 {
        let ready = client.owner_request(HostRequestV1::RuntimeReady).await;
        assert!(
            matches!(ready, Ok(HostResponseV1::Done)),
            "ready={ready:?}, calls={}, generation={:?}, status={:?}",
            resume_calls.load(Ordering::SeqCst),
            auth.load().unwrap().unwrap().session_generation,
            host.coordinator().status_for(host.native_target())
        );
        let access = client.access(None).await.unwrap();
        assert_eq!(access.identity().slot, expected_slot);
        assert_eq!(access.identity().session_generation, Some(8));
        assert_eq!(
            resume_calls.load(Ordering::SeqCst),
            1,
            "new incarnation must apply exactly once"
        );
    }
    server.abort();
}

#[test]
fn missing_selection_is_not_created_when_protected_inventory_is_corrupt() {
    let app_data = tempfile::tempdir().unwrap();
    let resources = tempfile::tempdir().unwrap();
    let key = install_manifest(resources.path(), "0.2.16", false);
    let lock = ContainerOwnerLock::try_acquire(app_data.path()).unwrap();
    let records = Records::default();
    records
        .values
        .lock()
        .unwrap()
        .insert("auth-v1".to_owned(), b"orphan-corrupt-record".to_vec());

    let prepared =
        InstalledRuntimeSelection::prepare(resources.path(), &lock, Some(&key), "linux", "x86_64")
            .unwrap();
    assert!(prepared.prepare_runtime_storage(&lock, &records).is_err());
    assert!(!selection_path(app_data.path()).exists());
    assert_eq!(
        records.values.lock().unwrap().get("auth-v1").unwrap(),
        b"orphan-corrupt-record"
    );
}

#[test]
fn retry_after_selection_persist_failure_reuses_the_committed_install_identity() {
    let app_data = tempfile::tempdir().unwrap();
    let resources = tempfile::tempdir().unwrap();
    let key = install_manifest(resources.path(), "0.2.16", false);
    let lock = ContainerOwnerLock::try_acquire(app_data.path()).unwrap();
    let records = Records::default();
    let path = selection_path(app_data.path());
    let journal_path = app_data.path().join("common/runtime-switch-v1.json");
    let unfinished = br#"{"unfinished":"survives-finalize-retry"}"#;
    std::fs::write(&journal_path, unfinished).unwrap();

    let prepared =
        InstalledRuntimeSelection::prepare(resources.path(), &lock, Some(&key), "linux", "x86_64")
            .unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(prepared.prepare_runtime_storage(&lock, &records).is_err());
    let committed_auth = records
        .values
        .lock()
        .unwrap()
        .get("auth-v1")
        .cloned()
        .expect("protected startup committed auth before selection persistence");
    assert_eq!(std::fs::read(&journal_path).unwrap(), unfinished);

    std::fs::remove_dir(&path).unwrap();
    let retry =
        InstalledRuntimeSelection::prepare(resources.path(), &lock, Some(&key), "linux", "x86_64")
            .unwrap();
    assert!(retry.requires_storage_confirmation());
    let (selection, _storage) = retry.prepare_runtime_storage(&lock, &records).unwrap();

    assert_eq!(selection.state().selected_slot, RuntimeSlot::Latest);
    assert_eq!(
        records.values.lock().unwrap().get("auth-v1").unwrap(),
        &committed_auth
    );
    assert_eq!(std::fs::read(&journal_path).unwrap(), unfinished);
    assert!(path.is_file());
}

#[test]
fn bad_manifest_never_creates_or_defaults_selection() {
    let app_data = tempfile::tempdir().unwrap();
    let resources = tempfile::tempdir().unwrap();
    let key = install_manifest(resources.path(), "0.2.16", false);
    let lock = ContainerOwnerLock::try_acquire(app_data.path()).unwrap();
    std::fs::write(resources.path().join("container-manifest-v1.sig"), [0; 64]).unwrap();

    assert!(InstalledRuntimeSelection::prepare(
        resources.path(),
        &lock,
        Some(&key),
        "linux",
        "x86_64"
    )
    .is_err());
    assert!(!selection_path(app_data.path()).exists());
}

#[test]
fn container_reset_clears_pending_preference_but_preserves_unfinished_journal() {
    let app_data = tempfile::tempdir().unwrap();
    let resources = tempfile::tempdir().unwrap();
    let key = install_manifest(resources.path(), "0.2.16", false);
    let lock = ContainerOwnerLock::try_acquire(app_data.path()).unwrap();
    let path = selection_path(app_data.path());
    let old = SlotSelectionV1 {
        container_version: "0.2.15".to_owned(),
        selected_slot: RuntimeSlot::Stable,
        pending_slot: Some(RuntimeSlot::Latest),
    };
    std::fs::write(&path, old.to_persisted_bytes().unwrap()).unwrap();
    let journal_path = app_data.path().join("common/runtime-switch-v1.json");
    let unfinished = br#"{"unfinished":"must-survive-selection-reset"}"#;
    std::fs::write(&journal_path, unfinished).unwrap();

    let prepared =
        InstalledRuntimeSelection::prepare(resources.path(), &lock, Some(&key), "linux", "x86_64")
            .unwrap();
    assert_eq!(
        prepared.recovery(),
        Some(&SelectionRecovery::ContainerVersionChanged)
    );
    let (selection, _storage) = prepared
        .prepare_runtime_storage(&lock, &Records::default())
        .unwrap();
    assert_eq!(selection.state().selected_slot, RuntimeSlot::Latest);
    assert_eq!(selection.state().pending_slot, None);
    assert_eq!(std::fs::read(journal_path).unwrap(), unfinished);
}

#[test]
fn unavailable_stable_and_corrupt_selection_recover_to_latest_with_typed_notice() {
    for (stored, expected) in [
        (
            SlotSelectionV1 {
                container_version: "0.2.16".to_owned(),
                selected_slot: RuntimeSlot::Stable,
                pending_slot: None,
            }
            .to_persisted_bytes()
            .unwrap(),
            SelectionRecovery::UnavailableSlot(RuntimeSlot::Stable),
        ),
        (b"not-json".to_vec(), SelectionRecovery::InvalidSelection),
    ] {
        let app_data = tempfile::tempdir().unwrap();
        let resources = tempfile::tempdir().unwrap();
        let key = install_manifest(resources.path(), "0.2.16", false);
        let lock = ContainerOwnerLock::try_acquire(app_data.path()).unwrap();
        std::fs::write(selection_path(app_data.path()), stored).unwrap();

        let prepared = InstalledRuntimeSelection::prepare(
            resources.path(),
            &lock,
            Some(&key),
            "linux",
            "x86_64",
        )
        .unwrap();
        assert_eq!(prepared.recovery(), Some(&expected));
        let (selection, _storage) = prepared
            .prepare_runtime_storage(&lock, &Records::default())
            .unwrap();
        assert_eq!(selection.state().selected_slot, RuntimeSlot::Latest);
        assert_eq!(selection.state().pending_slot, None);
    }
}

#[test]
fn ordinary_runtime_restart_preserves_a_valid_stable_choice() {
    let app_data = tempfile::tempdir().unwrap();
    let resources = tempfile::tempdir().unwrap();
    let key = install_manifest(resources.path(), "0.3.0", true);
    let lock = ContainerOwnerLock::try_acquire(app_data.path()).unwrap();
    let state = SlotSelectionV1 {
        container_version: "0.3.0".to_owned(),
        selected_slot: RuntimeSlot::Stable,
        pending_slot: None,
    };
    let path = selection_path(app_data.path());
    std::fs::write(&path, state.to_persisted_bytes().unwrap()).unwrap();

    let prepared =
        InstalledRuntimeSelection::prepare(resources.path(), &lock, Some(&key), "linux", "x86_64")
            .unwrap();
    assert_eq!(prepared.storage_slot(), RuntimeSlot::Stable);
    assert_eq!(prepared.recovery(), None);
    let (selection, _storage) = prepared
        .prepare_runtime_storage(&lock, &Records::default())
        .unwrap();
    assert_eq!(selection.target().runtime_slot, RuntimeSlot::Stable);
    assert_eq!(
        std::fs::read(path).unwrap(),
        state.to_persisted_bytes().unwrap()
    );
}
