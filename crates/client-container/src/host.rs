//! Common, UI-independent startup. Both native Android and desktop launchers
//! enter here before loading a product runtime or opening protected records.
pub use crate::host_updater::HostUpdateStatusV1;
use crate::host_updater::HostUpdater;
use crate::ipc::{
    LaunchBinding, OwnerService, PrivateBackgroundDispatcher, PrivateError, RemoteOwner,
};
use crate::{
    AuthBroker, BrokerError, LocalAuthStop, LocalStopReceiptV1, RuntimeCleanupHandoff,
    RuntimeClientProfile, RuntimeForceStop, RuntimeSwitchControl, SelectionRecovery,
    SwitchCoordinator, TransitionSourceSnapshot,
};
use crate::{InstalledRuntimeSelection, SelectionStartupError};
use nelomai_client_api::{AccessSnapshot, ClientApi, RuntimeTarget};
use nelomai_client_storage::{ContainerOwnerLock, PreparedRuntimeStorage, ProtectedRecordFactory};
use nelomai_client_storage::{RuntimeCleanupSnapshotV1, RuntimeStateStore};
use nelomai_contracts::RuntimeSlot;
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc};
use std::{path::PathBuf, sync::Mutex};
use tokio::io::{AsyncRead, AsyncWrite};

/// Startup transfers the prepared runtime records to their runtime owner; the
/// common broker retains only auth and its owner lock. This value is not Clone.
pub struct PreparedHost<F: ProtectedRecordFactory> {
    pub owner: Arc<ContainerOwnerLock>,
    pub selection: InstalledRuntimeSelection,
    pub storage: PreparedRuntimeStorage<F::Record>,
    pub records: F,
}

pub fn prepare_host<F: ProtectedRecordFactory>(
    data_root: &Path,
    resource_root: &Path,
    pinned_key: Option<&[u8]>,
    platform: &str,
    architecture: &str,
    create_records: impl FnOnce() -> F,
) -> Result<PreparedHost<F>, SelectionStartupError> {
    crate::startup_diagnostics::stage("host.owner_lock");
    let owner = Arc::new(ContainerOwnerLock::try_acquire(data_root)?);
    crate::startup_diagnostics::stage("host.runtime_selection");
    let prepared = InstalledRuntimeSelection::prepare(
        resource_root,
        owner.as_ref(),
        pinned_key,
        platform,
        architecture,
    )?;
    // The factory itself may initialize native keychain/keystore context, so it
    // must not run until both exclusivity and manifest trust are established.
    crate::startup_diagnostics::stage("host.record_factory");
    let records = create_records();
    crate::startup_diagnostics::stage("host.prepare_storage");
    let (selection, storage) = prepared.prepare_runtime_storage(owner.as_ref(), &records)?;
    crate::startup_diagnostics::stage("host.storage_ready");
    Ok(PreparedHost {
        owner,
        selection,
        storage,
        records,
    })
}

pub struct HostNativePorts {
    pub stop: Arc<dyn LocalAuthStop>,
    pub force: Arc<dyn RuntimeForceStop>,
    pub background: Arc<dyn PrivateBackgroundDispatcher>,
    pub updater: Option<Arc<dyn nelomai_client_updater::UpdateBackend>>,
    pub storage: Option<Arc<dyn NativeRuntimeStorage>>,
    pub relaunch: Option<Arc<dyn NativeRuntimeRelaunch>>,
}

#[async_trait::async_trait]
pub trait NativeRuntimeRelaunch: Send + Sync {
    async fn relaunch_runtime(&self, runtime_pid: u32) -> Result<(), BrokerError>;
    async fn release_owner_reload(
        &self,
        runtime_pid: u32,
        success: bool,
    ) -> Result<(), BrokerError>;
}

pub trait NativeRuntimeStorage: Send + Sync {
    fn prepare(
        &self,
        slot: RuntimeSlot,
        runtime_version: &str,
        legacy_migration: bool,
        migration_complete: bool,
    ) -> Result<(), BrokerError>;
    fn acknowledge(&self) -> Result<(), BrokerError>;
}

trait MigrationCompletion: Send + Sync {
    fn acknowledge(&self) -> Result<(), BrokerError>;
}
struct HostMigration<F: ProtectedRecordFactory> {
    records: Mutex<F>,
    root: PathBuf,
    paths: nelomai_client_storage::RuntimePaths,
    native: Option<Arc<dyn NativeRuntimeStorage>>,
}
impl<F: ProtectedRecordFactory + Send> MigrationCompletion for HostMigration<F> {
    fn acknowledge(&self) -> Result<(), BrokerError> {
        use nelomai_client_storage::*;
        let records = self
            .records
            .lock()
            .map_err(|_| BrokerError::RecoveryRequired)?;
        let auth = ProtectedAuthStore::new(records.record("auth-v1"));
        let runtime =
            ProtectedRuntimeStore::new(records.record(self.paths.namespace()), self.paths.clone());
        let split = FileSplitTunnelStore::new(&self.root);
        let journal = FileMigrationJournal::new(self.root.join("common/auth-migration-v1.json"));
        acknowledge_migration_bootstrap(
            &LegacyMigrationSource::new(records.legacy(), &split),
            &auth,
            &runtime,
            &journal,
        )?;
        if let Some(native) = &self.native {
            native.acknowledge()?;
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAttachRequest {
    pub target: RuntimeTarget,
    pub session_generation: Option<u64>,
    pub incarnation: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBootstrapV1 {
    pub target: RuntimeTarget,
    pub session_generation: Option<u64>,
    pub incarnation: String,
    pub data_root: PathBuf,
    pub runtime_namespaces: Vec<String>,
    pub pending_slot: Option<RuntimeSlot>,
}

impl RuntimeBootstrapV1 {
    /// Derive only the protected runtime records admitted by the common host.
    /// The common auth namespace must never be opened in a product process.
    pub fn runtime_paths(&self) -> Result<Vec<nelomai_client_storage::RuntimePaths>, HostError> {
        use nelomai_client_storage::RuntimePaths;
        if self.runtime_namespaces.is_empty() || self.runtime_namespaces.len() > 64 {
            return Err(HostError::RecoveryRequired);
        }
        let selected = RuntimePaths::new(
            &self.data_root,
            self.target.runtime_slot,
            &self.target.runtime_version,
        )
        .map_err(|_| HostError::RecoveryRequired)?;
        let mut seen = std::collections::HashSet::new();
        let paths = self
            .runtime_namespaces
            .iter()
            .map(|namespace| {
                if !seen.insert(namespace.as_str()) {
                    return Err(HostError::RecoveryRequired);
                }
                let parts: Vec<_> = namespace.split('/').collect();
                if parts.len() != 5
                    || parts[0] != "runtime"
                    || parts[2] != "state"
                    || parts[4] != "state-v1.json"
                {
                    return Err(HostError::RecoveryRequired);
                }
                let slot = match parts[1] {
                    "latest" => RuntimeSlot::Latest,
                    "stable" => RuntimeSlot::Stable,
                    _ => return Err(HostError::RecoveryRequired),
                };
                let path = RuntimePaths::new(&self.data_root, slot, parts[3])
                    .map_err(|_| HostError::RecoveryRequired)?;
                if path.namespace() != namespace {
                    return Err(HostError::RecoveryRequired);
                }
                Ok(path)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if !paths.contains(&selected) {
            return Err(HostError::RecoveryRequired);
        }
        Ok(paths)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostRequestV1 {
    RuntimeReady,
    AuthRefreshDiagnostics,
    PushCleanup,
    RuntimeStatus,
    RuntimeSelect { slot: RuntimeSlot },
    RuntimeCancel,
    RuntimeRestart,
    BeforeTunnelStart,
    UpdateStatus,
    UpdateRefresh,
    UpdateSetAutomatic { enabled: bool },
    UpdateInstall,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostResponseV1 {
    AuthRefreshDiagnostics {
        events: Vec<crate::auth_broker::RefreshDiagnosticV1>,
    },
    UpdateStatus {
        status: HostUpdateStatusV1,
    },
    RuntimeStatus {
        status: crate::RuntimeSwitchStatusV1,
    },
    Done,
}
#[async_trait::async_trait]
pub trait PrivateOwnerCommands: Send + Sync {
    async fn dispatch(
        &self,
        target: &RuntimeTarget,
        request: HostRequestV1,
    ) -> Result<HostResponseV1, PrivateError>;
}
struct HostCommands {
    target: RuntimeTarget,
    coordinator: Arc<SwitchCoordinator>,
    updater: Arc<HostUpdater>,
    bridge: std::sync::Weak<HostBridge>,
    ready_gate: Arc<tokio::sync::Mutex<()>>,
    migration: Option<Arc<dyn MigrationCompletion>>,
    runtime_pid: Option<u32>,
}
#[async_trait::async_trait]
impl PrivateOwnerCommands for HostCommands {
    async fn dispatch(
        &self,
        target: &RuntimeTarget,
        request: HostRequestV1,
    ) -> Result<HostResponseV1, PrivateError> {
        if target != &self.target {
            return Err(PrivateError::Cancelled);
        }
        match request {
            HostRequestV1::AuthRefreshDiagnostics => {
                let bridge = self.bridge.upgrade().ok_or(PrivateError::Closed)?;
                let broker = bridge
                    .broker
                    .get()
                    .and_then(std::sync::Weak::upgrade)
                    .ok_or(PrivateError::Closed)?;
                return Ok(HostResponseV1::AuthRefreshDiagnostics {
                    events: broker.take_refresh_events(),
                });
            }
            HostRequestV1::PushCleanup => {
                self.bridge
                    .upgrade()
                    .ok_or(PrivateError::Closed)?
                    .replay_push_cleanup()
                    .await
                    .map_err(|_| PrivateError::RecoveryRequired)?;
                return Ok(HostResponseV1::Done);
            }
            HostRequestV1::RuntimeReady => {
                let _ready = self.ready_gate.lock().await;
                let bridge = self.bridge.upgrade().ok_or(PrivateError::Closed)?;
                let broker = bridge
                    .broker
                    .get()
                    .and_then(std::sync::Weak::upgrade)
                    .ok_or(PrivateError::Closed)?;
                let peer = bridge.peer().map_err(|_| PrivateError::Closed)?;
                peer.recover_logout(&broker, &self.coordinator).await?;
                self.coordinator
                    .recover_refresh_before_start()
                    .await
                    .map_err(|error| match error {
                        crate::SwitchError::Broker(crate::BrokerError::RefreshPending) => {
                            PrivateError::RefreshPending
                        }
                        crate::SwitchError::Broker(crate::BrokerError::RefreshRejected) => {
                            PrivateError::RefreshRejected
                        }
                        _ => PrivateError::RecoveryRequired,
                    })?;
                self.updater.recover().await?;
                self.coordinator
                    .before_tunnel_start()
                    .await
                    .map_err(|_| PrivateError::RecoveryRequired)?;
                if broker
                    .observe()
                    .await
                    .map_err(|_| PrivateError::RecoveryRequired)?
                    .state
                    == crate::BrokerAuthState::Active
                {
                    peer.admit_current_after(&broker, || {
                        if let Some(migration) = &self.migration {
                            migration
                                .acknowledge()
                                .map_err(|_| PrivateError::RecoveryRequired)?;
                        }
                        Ok(())
                    })
                    .await?;
                }
                return Ok(HostResponseV1::Done);
            }
            HostRequestV1::UpdateStatus => {
                return Ok(HostResponseV1::UpdateStatus {
                    status: self.updater.status()?,
                })
            }
            HostRequestV1::UpdateRefresh => {
                return Ok(HostResponseV1::UpdateStatus {
                    status: self.updater.refresh().await?,
                })
            }
            HostRequestV1::UpdateSetAutomatic { enabled } => {
                let status = self.updater.set_automatic(enabled)?;
                if enabled && status.supported {
                    self.updater.install(true)?;
                }
                return Ok(HostResponseV1::UpdateStatus { status });
            }
            HostRequestV1::UpdateInstall => {
                self.updater.refresh().await?;
                return Ok(HostResponseV1::UpdateStatus {
                    status: self.updater.install(false)?,
                });
            }
            HostRequestV1::RuntimeStatus => {}
            HostRequestV1::RuntimeSelect { slot } => {
                if self.coordinator.request(slot).await.is_err() {
                    let status = self
                        .coordinator
                        .status_for(target)
                        .map_err(|_| PrivateError::RecoveryRequired)?;
                    if !status.restart_required() || !status.local_stop_confirmed() {
                        return Err(PrivateError::RecoveryRequired);
                    }
                }
            }
            HostRequestV1::RuntimeCancel => {
                self.coordinator
                    .cancel_pending_for(target)
                    .await
                    .map_err(|_| PrivateError::RecoveryRequired)?;
            }
            HostRequestV1::RuntimeRestart => {
                let status = self
                    .coordinator
                    .prepare_runtime_restart(target)
                    .await
                    .map_err(|_| PrivateError::RecoveryRequired)?;
                if let Some(runtime_pid) = self.runtime_pid {
                    let bridge = self.bridge.upgrade().ok_or(PrivateError::Closed)?;
                    let relaunch = bridge
                        .native
                        .relaunch
                        .as_ref()
                        .ok_or(PrivateError::RecoveryRequired)?
                        .clone();
                    let peer = bridge.peer().map_err(|_| PrivateError::Closed)?;
                    relaunch
                        .relaunch_runtime(runtime_pid)
                        .await
                        .map_err(|_| PrivateError::RecoveryRequired)?;
                    tokio::spawn(async move {
                        let deadline =
                            tokio::time::Instant::now() + std::time::Duration::from_secs(2);
                        while peer.is_connected() && tokio::time::Instant::now() < deadline {
                            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                        }
                        let _ = relaunch
                            .release_owner_reload(runtime_pid, !peer.is_connected())
                            .await;
                    });
                }
                return Ok(HostResponseV1::RuntimeStatus { status });
            }
            HostRequestV1::BeforeTunnelStart => {
                self.updater.recover().await?;
                self.coordinator
                    .before_tunnel_start_for(target)
                    .await
                    .map_err(|_| PrivateError::RecoveryRequired)?;
                return Ok(HostResponseV1::Done);
            }
        }
        Ok(HostResponseV1::RuntimeStatus {
            status: self
                .coordinator
                .status_for(target)
                .map_err(|_| PrivateError::RecoveryRequired)?,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HostError {
    #[error(transparent)]
    Startup(#[from] SelectionStartupError),
    #[error(transparent)]
    Broker(#[from] BrokerError),
    #[error("common runtime owner requires recovery")]
    RecoveryRequired,
}

struct HostPeer {
    owner: Arc<RemoteOwner>,
    _service: OwnerService,
}
struct HostBridge {
    peer: Mutex<Option<HostPeer>>,
    native: HostNativePorts,
    broker: std::sync::OnceLock<std::sync::Weak<AuthBroker>>,
    push_gate: Arc<tokio::sync::Mutex<()>>,
}
impl HostBridge {
    async fn replay_push_cleanup(&self) -> Result<(), BrokerError> {
        let _gate = self.push_gate.lock().await;
        let broker = self
            .broker
            .get()
            .and_then(std::sync::Weak::upgrade)
            .ok_or(BrokerError::RecoveryRequired)?;
        if let Some(epoch) = broker.pending_push_cleanup().await? {
            if broker.push_cleanup_is_current(epoch).await? {
                self.native.background.cleanup_push().await?;
                broker.finish_push_cleanup(epoch).await?;
            }
        }
        Ok(())
    }
    fn peer(&self) -> Result<Arc<RemoteOwner>, BrokerError> {
        self.peer
            .lock()
            .map_err(|_| BrokerError::RecoveryRequired)?
            .as_ref()
            .map(|peer| peer.owner.clone())
            .ok_or(BrokerError::RecoveryRequired)
    }
    fn close(&self) {
        if let Ok(mut peer) = self.peer.lock() {
            if let Some(old) = peer.take() {
                old.owner.revoke_peer();
            }
        }
    }
}
#[async_trait::async_trait]
impl LocalAuthStop for HostBridge {
    fn revoke_runtime(&self) {
        if let Ok(peer) = self.peer() {
            peer.revoke_runtime();
        }
        self.native.stop.revoke_runtime();
    }
    async fn prepare_revocation(&self, epoch: u64) -> Result<(), BrokerError> {
        self.native.background.prepare_revocation(epoch).await?;
        let broker = self
            .broker
            .get()
            .and_then(std::sync::Weak::upgrade)
            .ok_or(BrokerError::RecoveryRequired)?;
        broker.stage_push_cleanup(epoch).await?;
        let background = self.native.background.clone();
        let gate = self.push_gate.clone();
        // Completion remains in the common owner even if the UI waiter exits.
        // Failure leaves the protected marker for startup/registration replay.
        tokio::spawn(async move {
            let _gate = gate.lock().await;
            if broker.push_cleanup_is_current(epoch).await.unwrap_or(false)
                && background.cleanup_push().await.is_ok()
            {
                let _ = broker.finish_push_cleanup(epoch).await;
            }
        });
        Ok(())
    }
    async fn stop_local(&self) -> Result<(), BrokerError> {
        // Native stop is independent: channel EOF is never a VPN stop receipt.
        let runtime = match self.peer() {
            Ok(peer) => peer.stop_local().await,
            Err(_) => Ok(()),
        };
        let native = self.native.stop.stop_local().await;
        runtime.and(native)
    }
}
#[async_trait::async_trait]
impl RuntimeSwitchControl for HostBridge {
    async fn handoff_cleanup(
        &self,
        source: &TransitionSourceSnapshot,
    ) -> Result<RuntimeCleanupHandoff, BrokerError> {
        self.peer()?
            .runtime_cleanup_handoff(source)
            .await
            .map_err(|_| BrokerError::RecoveryRequired)
    }
    async fn graceful_stop(
        &self,
        _: &str,
        _: &RuntimeCleanupSnapshotV1,
    ) -> Result<(), BrokerError> {
        self.stop_local().await
    }
    async fn force_stop(
        &self,
        operation: &str,
        _: &RuntimeCleanupSnapshotV1,
    ) -> Result<(), BrokerError> {
        self.native.force.force_stop(operation).await
    }
    async fn complete_cleanup_and_admit(
        &self,
        snapshot: &RuntimeCleanupSnapshotV1,
        receipt: &LocalStopReceiptV1,
        access: &AccessSnapshot,
    ) -> Result<(), BrokerError> {
        if receipt.runtime_slot != snapshot.slot
            || receipt.runtime_version != snapshot.runtime_version
        {
            return Err(BrokerError::IdentityMismatch);
        }
        let broker = self
            .broker
            .get()
            .and_then(std::sync::Weak::upgrade)
            .ok_or(BrokerError::RecoveryRequired)?;
        self.peer()?
            .complete_runtime_cleanup(&broker, snapshot, access)
            .await
            .map_err(|_| BrokerError::RecoveryRequired)
    }
}

/// UI-independent common owner. Runtime record wrappers are dropped at startup;
/// selected child alone opens the declared runtime namespaces for full writes.
pub struct CommonHost {
    owner: Arc<ContainerOwnerLock>,
    installed: InstalledRuntimeSelection,
    resources: PathBuf,
    broker: Arc<AuthBroker>,
    coordinator: Arc<SwitchCoordinator>,
    updater: Arc<HostUpdater>,
    bridge: Arc<HostBridge>,
    profile: RuntimeClientProfile,
    incarnation: String,
    namespaces: Vec<String>,
    attach_gate: tokio::sync::Mutex<()>,
    ready_gate: Arc<tokio::sync::Mutex<()>>,
    migration: Option<Arc<dyn MigrationCompletion>>,
}
impl Drop for CommonHost {
    fn drop(&mut self) {
        self.bridge.close();
    }
}
impl CommonHost {
    #[allow(clippy::too_many_arguments)]
    pub fn open<F: ProtectedRecordFactory + Send + 'static>(
        data_root: &Path,
        resource_root: &Path,
        pinned_key: Option<&[u8]>,
        platform: &str,
        architecture: &str,
        create_records: impl FnOnce() -> F,
        api: ClientApi,
        profile: RuntimeClientProfile,
        native: HostNativePorts,
    ) -> Result<Self, HostError>
    where
        F::Record: 'static,
    {
        let PreparedHost {
            owner,
            selection,
            storage,
            records,
        } = prepare_host(
            data_root,
            resource_root,
            pinned_key,
            platform,
            architecture,
            create_records,
        )?;
        let requires_transition = matches!(
            selection.recovery(),
            Some(SelectionRecovery::ContainerVersionChanged)
        ) || storage
            .runtime
            .load()
            .map_err(BrokerError::from)?
            .is_some_and(|state| state.cleanup_only);
        if let Some(native_storage) = &native.storage {
            // Native migration adapters are runtime classes too. Verify their
            // selected payload before a JNI callback can load any such class.
            #[cfg(unix)]
            verify_android_payload(
                resource_root,
                selection.manifest(),
                selection.target().runtime_slot,
                unsafe { libc::geteuid() },
            )?;
            #[cfg(not(unix))]
            return Err(HostError::RecoveryRequired);
            use nelomai_client_storage::MigrationOutcome;
            native_storage.prepare(
                selection.target().runtime_slot,
                &selection.target().runtime_version,
                matches!(storage.migration, Some(MigrationOutcome::AwaitingBootstrap)),
                matches!(storage.migration, Some(MigrationOutcome::Complete)),
            )?;
            if matches!(storage.migration, Some(MigrationOutcome::Complete)) {
                native_storage.acknowledge()?;
            }
        }
        let migration = matches!(
            storage.migration,
            Some(nelomai_client_storage::MigrationOutcome::AwaitingBootstrap)
        )
        .then(|| {
            Arc::new(HostMigration {
                records: Mutex::new(records),
                root: owner.root().into(),
                paths: storage.runtime.paths().clone(),
                native: native.storage.clone(),
            }) as Arc<dyn MigrationCompletion>
        });
        let namespaces = std::iter::once(&storage.runtime)
            .chain(storage.retained.iter())
            .map(|record| record.paths().namespace().to_owned())
            .collect();
        let bridge = Arc::new(HostBridge {
            peer: Mutex::new(None),
            native,
            broker: std::sync::OnceLock::new(),
            push_gate: Arc::new(tokio::sync::Mutex::new(())),
        });
        let api = api
            .with_app_version(&selection.target().container_version)
            .map_err(|_| HostError::RecoveryRequired)?;
        crate::startup_diagnostics::stage("host.auth_broker");
        let refresh_diagnostics_directory = storage
            .runtime
            .paths()
            .operational_state
            .parent()
            .ok_or(HostError::RecoveryRequired)?
            .join("diagnostics");
        let broker = Arc::new(
            AuthBroker::new(api.clone(), Arc::new(storage.auth), bridge.clone())?
                .with_refresh_diagnostics(refresh_diagnostics_directory),
        );
        bridge
            .broker
            .set(Arc::downgrade(&broker))
            .map_err(|_| HostError::RecoveryRequired)?;
        crate::startup_diagnostics::stage("host.switch_coordinator");
        let mut coordinator = SwitchCoordinator::open(owner.clone(), selection.manifest().clone())
            .map_err(|_| HostError::RecoveryRequired)?
            .attach(broker.clone(), bridge.clone());
        if requires_transition {
            coordinator = coordinator.require_initial_transition(selection.state().selected_slot);
        }
        let coordinator = Arc::new(coordinator);
        crate::startup_diagnostics::stage("host.updater");
        let updater = Arc::new(
            HostUpdater::new(
                owner.root(),
                api,
                broker.clone(),
                coordinator.clone(),
                selection.target().container_version.clone(),
                bridge.native.updater.clone(),
            )
            .map_err(|_| HostError::RecoveryRequired)?,
        );
        Ok(Self {
            owner,
            installed: selection,
            resources: resource_root.to_owned(),
            broker,
            coordinator,
            updater,
            bridge,
            profile,
            incarnation: uuid::Uuid::new_v4().to_string(),
            namespaces,
            attach_gate: tokio::sync::Mutex::new(()),
            ready_gate: Arc::new(tokio::sync::Mutex::new(())),
            migration,
        })
    }
    pub fn broker(&self) -> &Arc<AuthBroker> {
        &self.broker
    }
    /// The admitted target of this common incarnation, never pending preference.
    pub fn native_target(&self) -> &RuntimeTarget {
        self.installed.target()
    }
    pub fn coordinator(&self) -> &Arc<SwitchCoordinator> {
        &self.coordinator
    }
    pub fn updater_status(&self) -> Result<HostUpdateStatusV1, HostError> {
        self.updater
            .status()
            .map_err(|_| HostError::RecoveryRequired)
    }
    #[cfg(not(target_os = "android"))]
    pub fn update_stop_proof(
        &self,
        target: &str,
        phase: crate::UpdateJournalPhase,
    ) -> Result<crate::UpdateStopProof, HostError> {
        self.updater
            .stop_proof(target, phase)
            .map_err(|_| HostError::RecoveryRequired)
    }
    #[cfg(not(target_os = "android"))]
    pub fn native_start_blocked(&self) -> Result<bool, HostError> {
        self.updater
            .native_start_blocked()
            .map_err(|_| HostError::RecoveryRequired)
    }

    #[cfg(not(target_os = "android"))]
    pub async fn before_native_tunnel_start(&self) -> Result<(), HostError> {
        self.coordinator
            .before_tunnel_start_for(self.installed.target())
            .await
            .map_err(|_| HostError::RecoveryRequired)
    }

    #[cfg(not(target_os = "android"))]
    pub async fn prepare_runtime_restart(&self) -> Result<crate::RuntimeSwitchStatusV1, HostError> {
        self.coordinator
            .prepare_runtime_restart(self.installed.target())
            .await
            .map_err(|_| HostError::RecoveryRequired)
    }

    #[cfg(not(target_os = "android"))]
    pub fn runtime_restart_ready(&self) -> Result<bool, HostError> {
        if self
            .updater
            .native_start_blocked()
            .map_err(|_| HostError::RecoveryRequired)?
        {
            return Ok(false);
        }
        let status = self
            .coordinator
            .status_for(self.installed.target())
            .map_err(|_| HostError::RecoveryRequired)?;
        Ok(status.restart_required() && status.local_stop_confirmed())
    }
    /// Only this verified launch path creates desktop auth admission. A PID or
    /// manifest claimed by a connecting client is never accepted as authority.
    #[cfg(not(target_os = "android"))]
    pub async fn launch_desktop(
        &self,
        payload_owner: u32,
    ) -> Result<crate::desktop::VerifiedChild, HostError> {
        let _gate = self.attach_gate.lock().await;
        let selected = self.selection().await?;
        if self
            .bridge
            .peer
            .lock()
            .map_err(|_| HostError::RecoveryRequired)?
            .as_ref()
            .is_some_and(|peer| peer.owner.is_connected())
        {
            return Err(HostError::RecoveryRequired);
        }
        crate::startup_diagnostics::stage("runtime.verify_selected");
        let runtime = crate::desktop::VerifiedRuntime::from_verified(
            &self.resources,
            self.installed.manifest().clone(),
            selected.target.runtime_slot,
            payload_owner,
        )
        .inspect_err(|error| crate::startup_diagnostics::error("runtime.verify_selected", error))
        .map_err(|_| HostError::RecoveryRequired)?;
        let mut child = tokio::task::spawn_blocking(move || {
            runtime
                .spawn()
                .inspect_err(|error| crate::startup_diagnostics::error("runtime.spawn", error))
        })
        .await
        .map_err(|_| HostError::RecoveryRequired)?
        .map_err(|_| HostError::RecoveryRequired)?;
        child
            .verify_alive()
            .map_err(|_| HostError::RecoveryRequired)?;
        if child.target != selected.target {
            return Err(HostError::RecoveryRequired);
        }
        let stream = child.take_auth().map_err(|_| HostError::RecoveryRequired)?;
        let bytes = serde_json::to_vec(&selected).map_err(|_| HostError::RecoveryRequired)?;
        if bytes.len() > 65536 {
            return Err(HostError::RecoveryRequired);
        }
        #[cfg(unix)]
        {
            stream
                .set_nonblocking(true)
                .map_err(|_| HostError::RecoveryRequired)?;
        }
        #[cfg(unix)]
        let mut stream =
            tokio::net::UnixStream::from_std(stream).map_err(|_| HostError::RecoveryRequired)?;
        #[cfg(windows)]
        let mut stream = stream;
        {
            use tokio::io::AsyncWriteExt;
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                stream.write_u32_le(bytes.len() as u32).await?;
                stream.write_all(&bytes).await
            })
            .await
            .map_err(|_| HostError::RecoveryRequired)?
            .map_err(|_| HostError::RecoveryRequired)?;
        }
        self.attach_verified(stream, &selected)?;
        Ok(child)
    }
    #[cfg(not(target_os = "android"))]
    fn attach_verified<S>(&self, stream: S, selected: &RuntimeBootstrapV1) -> Result<(), HostError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut current = self
            .bridge
            .peer
            .lock()
            .map_err(|_| HostError::RecoveryRequired)?;
        if current
            .as_ref()
            .is_some_and(|peer| peer.owner.is_connected())
        {
            return Err(HostError::RecoveryRequired);
        }
        let peer = RemoteOwner::new_with_owner(
            stream,
            LaunchBinding::from_common_host(selected.target.clone(), selected.incarnation.clone()),
            self.profile.clone(),
            Some(self.bridge.native.background.clone()),
            Some(Arc::new(HostCommands {
                target: selected.target.clone(),
                coordinator: self.coordinator.clone(),
                updater: self.updater.clone(),
                bridge: Arc::downgrade(&self.bridge),
                ready_gate: self.ready_gate.clone(),
                migration: self.migration.clone(),
                runtime_pid: None,
            })),
        )
        .map_err(|_| HostError::RecoveryRequired)?;
        let service = peer
            .serve(self.broker.clone())
            .map_err(|_| HostError::RecoveryRequired)?;
        *current = Some(HostPeer {
            owner: peer,
            _service: service,
        });
        Ok(())
    }
    pub async fn selection(&self) -> Result<RuntimeBootstrapV1, HostError> {
        let (stamp, _) = self.broker.observe_stamped().await?;
        let generation = stamp.session_generation();
        let status = self
            .coordinator
            .status()
            .map_err(|_| HostError::RecoveryRequired)?;
        Ok(RuntimeBootstrapV1 {
            target: self.installed.target().clone(),
            session_generation: generation,
            incarnation: self.incarnation.clone(),
            data_root: self.owner.root().to_owned(),
            runtime_namespaces: self.namespaces.clone(),
            pending_slot: status.pending_slot,
        })
    }
    /// Caller UID/PID are supplied by the common non-exported Binder service,
    /// never decoded from the runtime's request. It transfers the endpoint to
    /// that exact caller only after this admission succeeds.
    pub async fn attach_android<S>(
        &self,
        stream: S,
        caller_pid: u32,
        caller_uid: u32,
        own_uid: u32,
        request: &RuntimeAttachRequest,
    ) -> Result<RuntimeBootstrapV1, HostError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let _gate = self.attach_gate.lock().await;
        if caller_pid == 0
            || caller_uid != own_uid
            || self.profile.platform != nelomai_contracts::Platform::Android
        {
            return Err(HostError::RecoveryRequired);
        }
        let selected = self.selection().await?;
        if request.target != selected.target
            || request.session_generation != selected.session_generation
            || request.incarnation != selected.incarnation
        {
            return Err(HostError::RecoveryRequired);
        }
        verify_android_payload(
            &self.resources,
            self.installed.manifest(),
            selected.target.runtime_slot,
            own_uid,
        )?;
        let mut current = self
            .bridge
            .peer
            .lock()
            .map_err(|_| HostError::RecoveryRequired)?;
        if current
            .as_ref()
            .is_some_and(|peer| peer.owner.is_connected())
        {
            return Err(HostError::RecoveryRequired);
        }
        let peer = RemoteOwner::new_with_owner(
            stream,
            LaunchBinding::from_common_host(selected.target.clone(), selected.incarnation.clone()),
            self.profile.clone(),
            Some(self.bridge.native.background.clone()),
            Some(Arc::new(HostCommands {
                target: selected.target.clone(),
                coordinator: self.coordinator.clone(),
                updater: self.updater.clone(),
                bridge: Arc::downgrade(&self.bridge),
                ready_gate: self.ready_gate.clone(),
                migration: self.migration.clone(),
                runtime_pid: Some(caller_pid),
            })),
        )
        .map_err(|_| HostError::RecoveryRequired)?;
        let service = peer
            .serve(self.broker.clone())
            .map_err(|_| HostError::RecoveryRequired)?;
        *current = Some(HostPeer {
            owner: peer,
            _service: service,
        });
        Ok(selected)
    }
}

fn verify_android_payload(
    resources: &Path,
    manifest: &nelomai_contracts::VerifiedContainerManifest,
    selected: RuntimeSlot,
    uid: u32,
) -> Result<(), HostError> {
    let runtime = manifest
        .selected(selected)
        .ok_or(HostError::RecoveryRequired)?;
    let slot = match selected {
        RuntimeSlot::Latest => "latest",
        RuntimeSlot::Stable => "stable",
    };
    let mut root = resources.to_owned();
    for part in [
        None,
        Some("engines"),
        Some(slot),
        Some(runtime.runtime_version.as_str()),
    ] {
        if let Some(part) = part {
            root.push(part);
        }
        nelomai_contracts::dispatcher::trusted(&root, uid)
            .map_err(|_| HostError::RecoveryRequired)?;
    }
    for entry in &runtime.files {
        let mut path = root.clone();
        for component in Path::new(&entry.path).components() {
            path.push(component);
            nelomai_contracts::dispatcher::trusted(&path, uid)
                .map_err(|_| HostError::RecoveryRequired)?;
        }
        let metadata = std::fs::metadata(&path).map_err(|_| HostError::RecoveryRequired)?;
        if !metadata.is_file()
            || metadata.len() != entry.size_bytes
            || nelomai_contracts::dispatcher::file_digest(&path)
                .map_err(|_| HostError::RecoveryRequired)?
                != entry.sha256
        {
            return Err(HostError::RecoveryRequired);
        }
    }
    Ok(())
}
