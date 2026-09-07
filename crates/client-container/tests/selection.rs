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
    use nelomai_client_container::{host::*, ipc::*};
    use nelomai_client_core::{RuntimeAuthProvider, RuntimeStartPreflight, RuntimeWriterGates};
    use nelomai_client_storage::*;
    let data = tempfile::tempdir().unwrap();
    let resources = tempfile::tempdir().unwrap();
    let key = install_manifest_platform(resources.path(), "0.2.16", false, "android", "aarch64");
    let records = Records::default();
    let host = CommonHost::open(
        data.path(),
        resources.path(),
        Some(&key),
        "android",
        "aarch64",
        || records.clone(),
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
    let initial = host.selection().await.unwrap();
    let auth = ProtectedAuthStore::new(records.record("auth-v1"));
    let mut state = auth.load().unwrap().unwrap();
    state.refresh_token = Some("synthetic-refresh".into());
    state.confirmed_identity = Some(initial.target.identity(Some(7)).unwrap());
    state.session_generation = Some(7);
    auth.save(&state).unwrap();
    assert_eq!(
        host.selection().await.unwrap().session_generation,
        Some(7),
        "missing access must not erase confirmed generation"
    );
    state.access_token = Some("synthetic-access".into());
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
    assert!(matches!(
        client
            .owner_request(HostRequestV1::RuntimeReady)
            .await
            .unwrap(),
        HostResponseV1::Done
    ));
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
    assert!(record.cleanup_snapshot().unwrap().auth_scope.is_some());
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
