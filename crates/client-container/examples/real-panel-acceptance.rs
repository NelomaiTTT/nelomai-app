//! Local instrumented acceptance driver. Real broker, HTTP and protected file
//! persistence; no keychain, production endpoint or release approval.
use async_trait::async_trait;
use nelomai_client_api::{
    ClientApi, ClientApiError, LoginRequest, RuntimeLogin, RuntimeSwitchReconcileRequest,
    RuntimeTarget,
};
use nelomai_client_container::{
    AuthBroker, BrokerError, FrozenReconcileRequest, LocalAuthStop, LocalStopReceiptV1,
    OwnerRuntimeAuth, ResumeArguments, RuntimeAdmission, RuntimeCleanupHandoff,
    RuntimeClientProfile, RuntimeSwitchControl, SwitchCoordinator,
};
use nelomai_client_core::{
    CoreError, RuntimeAuthProvider, RuntimeWriterGates, RuntimeWriterQuiescence,
};
use nelomai_client_storage::{
    AuthStore, AuthStoreV1, ContainerOwnerLock, ProtectedAuthStore, ProtectedRecordStore,
    RuntimeAuthScope, RuntimeCleanupSnapshotV1, StorageError, StoredAuth,
};
use nelomai_contracts::{
    ConnectionStartRequest, EgressMode, Layer, Platform, RouteMode, RuntimeSlot, TicConnectionMode,
};
use serde_json::json;
use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
};

struct FileRecord(PathBuf);
impl ProtectedRecordStore for FileRecord {
    fn load_record(&self) -> Result<Option<Vec<u8>>, StorageError> {
        match fs::read(&self.0) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
    fn save_record(&self, bytes: &[u8]) -> Result<(), StorageError> {
        let parent = self.0.parent().unwrap();
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.write_all(bytes)?;
        temporary.as_file().sync_all()?;
        temporary.persist(&self.0).map_err(|error| error.error)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    }
    fn delete_record(&self) -> Result<(), StorageError> {
        fs::remove_file(&self.0)?;
        Ok(())
    }
}

struct NativeEffects {
    root: PathBuf,
    child: Mutex<Option<Child>>,
    writers: Arc<RuntimeWriterGates>,
}
impl NativeEffects {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            child: Mutex::new(None),
            writers: Arc::new(RuntimeWriterGates::default()),
        }
    }
    fn start(&self) -> std::io::Result<()> {
        let mut child = Command::new(std::env::current_exe()?)
            .arg("native-effect")
            .arg(&self.root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut ready = [0];
        child.stdout.as_mut().unwrap().read_exact(&mut ready)?;
        if ready != [1] {
            return Err(std::io::Error::other(
                "native effect did not acquire its lease",
            ));
        }
        *self.child.lock().unwrap() = Some(child);
        Ok(())
    }
}

struct FileAdmission(PathBuf);
impl RuntimeAdmission for FileAdmission {
    fn check(&self, access: &nelomai_client_api::AccessSnapshot) -> Result<(), CoreError> {
        let expected = access
            .identity()
            .session_generation
            .ok_or(CoreError::AuthRecoveryRequired)?
            .to_string();
        if fs::read_to_string(self.0.join("authenticated-generation"))
            .is_ok_and(|value| value == expected)
        {
            Ok(())
        } else {
            Err(CoreError::AuthRecoveryRequired)
        }
    }

    fn bind_empty(
        &self,
        access: &nelomai_client_api::AccessSnapshot,
        _: &RuntimeWriterQuiescence,
    ) -> Result<(), CoreError> {
        fs::write(
            self.0.join("authenticated-generation"),
            access
                .identity()
                .session_generation
                .ok_or(CoreError::AuthRecoveryRequired)?
                .to_string(),
        )
        .map_err(|_| CoreError::Storage)
    }

    fn complete_logout(
        &self,
        receipt: &nelomai_client_storage::CompletedRuntimeLogoutV1,
        _: &RuntimeWriterQuiescence,
    ) -> Result<(), CoreError> {
        if receipt.operation_id.is_empty()
            || !matches!(
                receipt.code.as_str(),
                "already_inactive" | "session_revoked_cleanup_accepted"
            )
        {
            return Err(CoreError::AuthRecoveryRequired);
        }
        match fs::remove_file(self.0.join("authenticated-generation")) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(CoreError::Storage),
        }
        fs::write(self.0.join("logout-cleanup-complete"), b"complete")
            .map_err(|_| CoreError::Storage)
    }
}
#[async_trait]
impl LocalAuthStop for NativeEffects {
    async fn stop_local(&self) -> Result<(), BrokerError> {
        if self.root.join("fail-native-stop").exists() {
            return Err(BrokerError::RecoveryRequired);
        }
        if let Some(mut child) = self.child.lock().unwrap().take() {
            drop(child.stdin.take());
            child.wait().map_err(|_| BrokerError::RecoveryRequired)?;
        }
        // The inherited stdin lifetime also stops this external effect after a
        // broker process crash. Never adopt or kill a PID read from a file.
        let _lease =
            nelomai_contracts::dispatcher::MutationGuard::at(&self.root.join("native-effect.lock"))
                .map_err(|_| BrokerError::RecoveryRequired)?;
        fs::write(self.root.join("native-stopped"), b"stopped")
            .map_err(|_| BrokerError::RecoveryRequired)?;
        Ok(())
    }
}
#[async_trait]
impl RuntimeSwitchControl for NativeEffects {
    async fn handoff_cleanup(
        &self,
        source: &nelomai_client_container::TransitionSourceSnapshot,
    ) -> Result<RuntimeCleanupHandoff, BrokerError> {
        let identity = source.identity().ok_or(BrokerError::RecoveryRequired)?;
        let snapshot = RuntimeCleanupSnapshotV1 {
            slot: identity.slot,
            runtime_version: identity.runtime_version.clone(),
            auth_scope: Some(RuntimeAuthScope {
                auth_epoch: source.auth_epoch(),
                family: source.family().into(),
                identity: identity.clone(),
            }),
            lease_ids: vec![],
            operations: vec![],
            cleanup_only: false,
        };
        Ok(RuntimeCleanupHandoff::new(
            snapshot,
            self.writers.quiesce().await,
        ))
    }
    async fn graceful_stop(
        &self,
        _: &str,
        _: &RuntimeCleanupSnapshotV1,
    ) -> Result<(), BrokerError> {
        self.stop_local().await
    }
    async fn force_stop(&self, _: &str, _: &RuntimeCleanupSnapshotV1) -> Result<(), BrokerError> {
        self.stop_local().await
    }
    async fn complete_cleanup_and_admit(
        &self,
        _: &RuntimeCleanupSnapshotV1,
        _: &LocalStopReceiptV1,
        access: &nelomai_client_api::AccessSnapshot,
    ) -> Result<(), BrokerError> {
        self.stop_local().await?;
        fs::write(
            self.root.join("admitted-generation"),
            access.identity().session_generation.unwrap().to_string(),
        )
        .map_err(|_| BrokerError::RecoveryRequired)?;
        Ok(())
    }
}

fn test_manifest() -> nelomai_contracts::VerifiedContainerManifest {
    use ed25519_dalek::{Signer, SigningKey};
    let slots: Vec<_> = [RuntimeSlot::Latest, RuntimeSlot::Stable].into_iter().map(|slot| json!({"slot":slot,"manifest":{"format_version":1,"runtime_version":target(slot).runtime_version,"source_commit":"d7267ae2153b9dc29a89f2e4ca174599608a0768","platform":"linux","architecture":"x86_64","contract_version":1,"files":[{"path":"native-effect","size_bytes":1,"sha256":"a".repeat(64),"role":"executable"}]}})).collect();
    let bytes = serde_json::to_vec(&json!({"format_version":1,"container_version":"0.2.16","release_set_id":"local-panel-matrix","minimum_runtime_contract":1,"maximum_runtime_contract":1,"stable_release_set_sha256":"b".repeat(64),"stable_platform_manifest_sha256":"c".repeat(64),"slots":slots})).unwrap();
    let key = SigningKey::from_bytes(&[12; 32]);
    let mut message = nelomai_contracts::CONTAINER_MANIFEST_SIGNATURE_DOMAIN.to_vec();
    message.extend(&bytes);
    nelomai_contracts::verify_container_manifest(
        &bytes,
        &key.sign(&message).to_bytes(),
        &key.verifying_key().to_bytes(),
        "linux",
        "x86_64",
    )
    .unwrap()
}

fn target(slot: RuntimeSlot) -> RuntimeTarget {
    RuntimeTarget {
        container_version: "0.2.16".into(),
        runtime_version: if slot == RuntimeSlot::Latest {
            "0.2.17"
        } else {
            "0.2.16"
        }
        .into(),
        runtime_contract_version: 1,
        runtime_slot: slot,
    }
}

fn connection_start_request() -> ConnectionStartRequest {
    ConnectionStartRequest {
        operation_id: uuid::Uuid::new_v4().to_string(),
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        egress_mode: EgressMode::Ipv4,
        probes: Vec::new(),
        allow_alternate: false,
        require_measured_selection: false,
        recovery_contract_version: None,
        redundancy_contract_version: None,
        reserve_enabled: None,
        request_fingerprint: None,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = std::env::args().collect();
    if arguments.len() == 3 && arguments[1] == "native-effect" {
        let _lease = nelomai_contracts::dispatcher::MutationGuard::at(
            &PathBuf::from(&arguments[2]).join("native-effect.lock"),
        )?;
        std::io::stdout().write_all(&[1])?;
        std::io::stdout().flush()?;
        let mut byte = [0];
        let _ = std::io::stdin().read(&mut byte)?;
        return Ok(());
    }
    if arguments.len() != 5 {
        return Err("usage: real-panel-acceptance login-reconcile LOOPBACK_URL PRIVATE_DIRECTORY SYNTHETIC_LOGIN".into());
    }
    let url = &arguments[2];
    let source_slot = match std::env::var("NELOMAI_TEST_SOURCE_SLOT").as_deref() {
        Ok("stable") => RuntimeSlot::Stable,
        Ok("latest") | Err(_) => RuntimeSlot::Latest,
        _ => return Err("invalid synthetic source slot".into()),
    };
    let target_slot = if source_slot == RuntimeSlot::Latest {
        RuntimeSlot::Stable
    } else {
        RuntimeSlot::Latest
    };
    let endpoint: std::net::SocketAddr = url
        .strip_prefix("http://")
        .ok_or("isolated HTTP panel required")?
        .parse()?;
    if endpoint.ip() != std::net::Ipv4Addr::LOCALHOST || endpoint.port() == 0 {
        return Err("isolated loopback panel required".into());
    }
    let root = PathBuf::from(&arguments[3]);
    fs::create_dir_all(&root)?;
    let store = Arc::new(ProtectedAuthStore::new(FileRecord(root.join("auth-v1"))));
    if store.load()?.is_none() {
        store.save(&AuthStoreV1::from_legacy(&StoredAuth::new_install()))?;
    }
    let native = Arc::new(NativeEffects::new(root.clone()));
    let broker = Arc::new(AuthBroker::new(
        ClientApi::new(url)?,
        store.clone(),
        native.clone(),
    )?);
    match arguments[1].as_str() {
        "controlled-logout" => {
            broker.logout().await?;
            let receipt = broker
                .completed_runtime_logout()
                .await?
                .ok_or("missing durable runtime logout cleanup receipt")?;
            assert!(root.join("native-stopped").exists());
            println!(
                "{}",
                json!({
                    "case":"controlled-logout",
                    "logged_out":true,
                    "local_stop_complete":true,
                    "cleanup_receipt_pending":true,
                    "operation_id":receipt.operation_id,
                    "cleanup_reconcile_operation_id":receipt.cleanup_reconcile_operation_id,
                    "code":receipt.code
                })
            );
        }
        "controlled-login" => {
            let owner = Arc::new(ContainerOwnerLock::try_acquire(&root)?);
            let coordinator = Arc::new(
                SwitchCoordinator::open(owner, test_manifest())?
                    .attach(broker.clone(), native.clone()),
            );
            let port = OwnerRuntimeAuth::new(
                broker.clone(),
                target(source_slot),
                RuntimeClientProfile {
                    platform: Platform::Linux,
                    platform_version: None,
                    architecture: "x86_64".into(),
                },
                Arc::new(FileAdmission(root.clone())),
                native.writers.clone(),
            )?
            .with_switch_coordinator(coordinator.clone());
            let access = port
                .login(RuntimeLogin {
                    login: arguments[4].clone(),
                    password: "synthetic-task12-password".into(),
                    device_name: "Task12 controlled reauthentication".into(),
                })
                .await?;
            ClientApi::new(url)?
                .with_access_snapshot(&access)?
                .bootstrap(access.access_token())
                .await?;
            assert!(coordinator.snapshot()?.is_none());
            assert!(broker.completed_runtime_logout().await?.is_none());
            println!(
                "{}",
                json!({
                    "case":"controlled-login",
                    "usable_access":true,
                    "local_switch_journal_retired":coordinator.snapshot()?.is_none(),
                    "generation":access.identity().session_generation,
                    "slot":access.identity().slot,
                    "cleanup_receipt_consumed":true
                })
            );
        }
        "assert-start-blocked" => {
            let access = broker.access_token(None).await?;
            let error = ClientApi::new(url)?
                .with_access_snapshot(&access)?
                .start_connection(access.access_token(), &connection_start_request())
                .await
                .expect_err("server admitted a connection before cleanup ACK");
            let (status, code) = match &error {
                ClientApiError::Api { status, code, .. } => (status.as_u16(), code.as_str()),
                _ => return Err(error.into()),
            };
            assert_eq!((status, code), (409, "runtime_switch_pending"));
            assert!(!root.join("admitted-generation").exists());
            let _lease =
                nelomai_contracts::dispatcher::MutationGuard::at(&root.join("native-effect.lock"))?;
            println!(
                "{}",
                json!({"case":"assert-start-blocked","status":status,"code":code,"no_native_start":true})
            );
        }
        "assert-start-unblocked" => {
            let access = broker.access_token(None).await?;
            let api = ClientApi::new(url)?.with_access_snapshot(&access)?;
            let error = api
                .start_connection(access.access_token(), &connection_start_request())
                .await
                .expect_err("isolated fixture unexpectedly allocated a connection");
            let (status, code) = match &error {
                ClientApiError::Api { status, code, .. } => (status.as_u16(), code.as_str()),
                _ => return Err(error.into()),
            };
            assert_eq!((status, code), (409, "peer_binding_required"));
            api.bootstrap(access.access_token()).await?;
            assert!(!root.join("admitted-generation").exists());
            let _lease =
                nelomai_contracts::dispatcher::MutationGuard::at(&root.join("native-effect.lock"))?;
            println!(
                "{}",
                json!({"case":"assert-start-unblocked","status":status,"code":code,"runtime_switch_barrier_absent":true,"bootstrap_usable":true,"no_native_start":true,"generation":access.identity().session_generation})
            );
        }
        "assert-reauth-required" => {
            assert_eq!(
                broker.observe_stamped().await?.1.state,
                nelomai_client_container::BrokerAuthState::RecoveryRequired
            );
            assert!(broker.access_token(None).await.is_err());
            let _lease =
                nelomai_contracts::dispatcher::MutationGuard::at(&root.join("native-effect.lock"))?;
            assert!(!root.join("admitted-generation").exists());
            println!(
                "{}",
                json!({"case":"expired-refresh","controlled_reauthentication_required":true,"native_stopped":true,"no_admission":true})
            );
        }
        "race-refresh" | "race-resume" => {
            native.start()?;
            let pending = if arguments[1] == "race-refresh" {
                let current = broker.access_token(None).await?;
                let broker = broker.clone();
                tokio::spawn(async move { broker.access_token(Some(&current)).await.map(|_| true) })
            } else {
                let auth = store.load()?.unwrap();
                let authority = auth
                    .broker
                    .as_ref()
                    .unwrap()
                    .transition_authorities
                    .last()
                    .ok_or("missing reconcile authority")?;
                let args = ResumeArguments {
                    operation_id: uuid::Uuid::new_v4().to_string(),
                    reconcile_operation_id: authority.reconcile_operation_id.clone(),
                    decision: "apply".into(),
                    target: target(target_slot),
                    expected_session_generation: authority.expected_session_generation,
                };
                let broker = broker.clone();
                tokio::spawn(async move {
                    broker
                        .resume_transition(args)
                        .await
                        .map(|result| result.current_access().is_some())
                })
            };
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                while !root.join("response-held").exists() {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await?;
            assert!(
                broker.logout().await.is_err(),
                "expected actual dropped logout ACK"
            );
            assert!(broker.access_token(None).await.is_err());
            let cancelled = store.load()?.unwrap();
            assert_eq!(
                cancelled.logout_state,
                nelomai_client_storage::LogoutState::Pending
            );
            fs::write(root.join("release-response"), b"release")?;
            assert!(matches!(
                pending.await?,
                Err(BrokerError::Cancelled) | Ok(false)
            ));
            let after = store.load()?.unwrap();
            assert_eq!(after.auth_epoch, cancelled.auth_epoch);
            assert_eq!(after.logout_state, cancelled.logout_state);
            assert_eq!(after.access_token, cancelled.access_token);
            assert_eq!(after.refresh_token, cancelled.refresh_token);
            assert_eq!(
                after.broker.as_ref().unwrap().pending_logout,
                cancelled.broker.as_ref().unwrap().pending_logout
            );
            println!(
                "{}",
                json!({"case":arguments[1],"late_response_cancelled":true,"logout_ack_lost":true})
            );
        }
        "logout-replay-new-login" => {
            let auth = store.load()?.unwrap();
            let pending = auth
                .broker
                .as_ref()
                .and_then(|meta| meta.pending_logout.as_ref())
                .ok_or("missing durable logout proof")?;
            let old_request = nelomai_client_api::RuntimeLogoutRequest {
                operation_id: pending.operation_id.clone(),
                refresh_token: pending.refresh_proof.clone(),
            };
            broker.logout().await?;
            assert!(broker.access_token(None).await.is_err());
            let request = LoginRequest {
                login: arguments[4].clone(),
                password: "synthetic-task12-password".into(),
                install_secret: auth.install_secret,
                device_name: "Task12 fresh family".into(),
                platform: Platform::Linux,
                platform_version: None,
                architecture: "x86_64".into(),
                app_version: "0.2.16".into(),
            };
            let access = broker.login(&request, &target(source_slot)).await?;
            native.start()?;
            if root.join("require-new-lease").exists() {
                fs::write(root.join("new-family-ready"), b"ready")?;
                tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    while !root.join("new-lease-ready").exists() {
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                })
                .await?;
            }
            ClientApi::new(url)?.logout_runtime(&old_request).await?;
            ClientApi::new(url)?
                .with_access_snapshot(&access)?
                .bootstrap(access.access_token())
                .await?;
            assert!(
                native
                    .child
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .try_wait()?
                    .is_none(),
                "old logout stopped new native effect"
            );
            native.stop_local().await?;
            println!(
                "{}",
                json!({"case":"logout-replay-new-login","old_operation_id":old_request.operation_id,"new_family_usable":true,"new_native_survived_old_replay":true})
            );
        }
        "auth-status" => {
            let auth = store.load()?.unwrap();
            println!(
                "{}",
                json!({"logout_state":auth.logout_state,"has_access":auth.access_token.is_some(),"has_refresh":auth.refresh_token.is_some(),"generation":auth.session_generation,"pending_issuance":auth.broker.as_ref().and_then(|meta| meta.pending_request.as_ref()).map(|ticket| format!("{:?}",ticket.kind))})
            );
        }
        "login" | "login-reconcile" | "reconcile" => {
            let request = LoginRequest {
                login: arguments[4].clone(),
                password: "synthetic-task12-password".into(),
                install_secret: store.load()?.unwrap().install_secret,
                device_name: "Task12 isolated broker".into(),
                platform: Platform::Linux,
                platform_version: None,
                architecture: "x86_64".into(),
                app_version: "0.2.16".into(),
            };
            if arguments[1] != "reconcile" {
                let access =
                    broker
                        .login(&request, &target(source_slot))
                        .await
                        .map_err(|error| {
                            if let BrokerError::Api(ref api) = error {
                                eprintln!(
                                    "login rejected: {}",
                                    api.stable_code().unwrap_or("transport_or_response")
                                );
                            }
                            error
                        })?;
                assert_eq!(access.identity().session_generation, Some(1));
            }
            if arguments[1] == "login" {
                println!("{}", json!({"case":"real-login", "generation":1}));
                return Ok(());
            }
            let source = broker.transition_source().await?;
            let request = RuntimeSwitchReconcileRequest {
                operation_id: store
                    .load()?
                    .unwrap()
                    .broker
                    .as_ref()
                    .and_then(|meta| meta.transition_authorities.last())
                    .map(|authority| authority.reconcile_operation_id.clone())
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                source_identity: source.identity().cloned(),
                target_identity: target(target_slot),
                expected_session_generation: source.expected_session_generation(),
                cleanup_contract_version: 1,
                lease_ids: vec![],
                redundant_session_ids: vec![],
                client_operation_ids: vec![],
            };
            let frozen = FrozenReconcileRequest::new(request, &source)?;
            let operation_id = frozen.request().operation_id.clone();
            let response = broker.reconcile_transition(frozen).await?;
            println!(
                "{}",
                json!({"case":"real-login-reconcile", "state":format!("{:?}", response.state), "operation_id":operation_id, "source_generation":source.expected_session_generation()})
            );
        }
        "resume" => {
            let auth = store.load()?.unwrap();
            let authority = auth
                .broker
                .as_ref()
                .unwrap()
                .transition_authorities
                .last()
                .ok_or("missing real reconcile authority")?;
            let path = root.join("resume-operation");
            if !path.exists() {
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)?;
                file.write_all(uuid::Uuid::new_v4().to_string().as_bytes())?;
                file.sync_all()?;
                fs::File::open(&root)?.sync_all()?;
            }
            let operation_id = fs::read_to_string(path)?;
            let response = broker
                .resume_transition(ResumeArguments {
                    operation_id: operation_id.clone(),
                    reconcile_operation_id: authority.reconcile_operation_id.clone(),
                    decision: "apply".into(),
                    target: target(target_slot),
                    expected_session_generation: authority.expected_session_generation,
                })
                .await?;
            let access = response
                .current_access()
                .ok_or("resume did not recover current access")?;
            assert_eq!(access.identity().session_generation, Some(2));
            assert_eq!(access.identity().slot, target_slot);
            ClientApi::new(url)?
                .with_access_snapshot(access)?
                .bootstrap(access.access_token())
                .await?;
            println!(
                "{}",
                json!({"case":"real-resume", "operation_id":operation_id, "generation":access.identity().session_generation, "access_usable":true})
            );
        }
        "switch" | "recover" => {
            let owner = Arc::new(ContainerOwnerLock::try_acquire(&root)?);
            let selection = root.join("common/runtime-selection-v1.json");
            if !selection.exists() {
                fs::create_dir_all(selection.parent().unwrap())?;
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(selection)?;
                file.write_all(&serde_json::to_vec(&json!({"schema_version":1,"container_version":"0.2.16","selected_slot":source_slot,"pending_slot":null}))?)?;
                file.sync_all()?;
            }
            let mut coordinator = SwitchCoordinator::open(owner.clone(), test_manifest())?
                .attach(broker.clone(), native.clone());
            if arguments[1] == "recover" {
                // This is a new process with no running source child. Resolve
                // the durable restart selection through the owner API before
                // constructing its selected coordinator. Native admission here
                // remains an instrumented effect, not the production peer.
                let active = target(source_slot);
                if coordinator.status_for(&active)?.restart_required() {
                    coordinator.prepare_runtime_restart(&active).await?;
                    drop(coordinator);
                    coordinator = SwitchCoordinator::open(owner, test_manifest())?
                        .attach(broker.clone(), native.clone());
                }
            }
            let result = if arguments[1] == "switch" {
                native.start()?;
                coordinator.request(target_slot).await
            } else {
                coordinator.recover().await
            };
            let result = match result {
                Ok(result) => result,
                Err(error)
                    if arguments[1] == "switch"
                        && coordinator
                            .status_for(&target(source_slot))?
                            .restart_required()
                        && coordinator
                            .status_for(&target(source_slot))?
                            .local_stop_confirmed()
                        && coordinator.snapshot()?.is_some_and(|journal| {
                            journal.phase() == nelomai_client_container::SwitchPhase::AuthResuming
                        }) =>
                {
                    let _ = error;
                    nelomai_client_container::SwitchProgress::Pending {
                        retry_after_seconds: 1,
                    }
                }
                Err(error) => return Err(error.into()),
            };
            let journal = coordinator.snapshot()?.ok_or("switch journal missing")?;
            let saved = serde_json::to_value(&journal)?;
            let access = if journal.phase() == nelomai_client_container::SwitchPhase::Complete {
                let access = broker.access_token(None).await?;
                ClientApi::new(url)?
                    .with_access_snapshot(&access)?
                    .bootstrap(access.access_token())
                    .await?;
                Some(access)
            } else {
                None
            };
            println!(
                "{}",
                json!({"case":arguments[1],"progress":format!("{result:?}"),"phase":journal.phase(),"barrier":nelomai_client_core::RuntimeStartPreflight::check_start_barrier(&coordinator).is_err(),"operation_id":saved["operation_id"],"active_operation_id":saved["active_reconcile_operation_id"],"target":journal.target_identity(),"confirmed_identity":access.as_ref().map(|access| access.identity())})
            );
        }
        _ => return Err("unsupported acceptance operation".into()),
    }
    Ok(())
}
