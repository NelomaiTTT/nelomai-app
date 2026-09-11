//! Durable nonsecret switch ownership. Network/auth/stop execution is added by
//! later checkpoints; this foundation only creates and reloads Requested work.
use crate::{
    atomic_nonsecret_write, current_selection, digest_json, finish_selection, valid_fingerprint,
    AuthBroker, BrokerError, CleanupEngineRoleV1, CleanupEnvelopeV1, FrozenReconcileRequest,
    ResumeArguments,
};
use async_trait::async_trait;
use nelomai_client_api::{
    AccessSnapshot, ClientApiError, RuntimeSwitchReconcileRequest, RuntimeSwitchState,
    RuntimeTarget,
};
use nelomai_client_core::{CoreError, RuntimeStartPreflight, RuntimeWriterQuiescence};
use nelomai_client_storage::{ContainerOwnerLock, RuntimeCleanupSnapshotV1};
use nelomai_contracts::{RuntimeIdentity, VerifiedContainerManifest};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{self, Read},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use uuid::Uuid;

const SWITCH_SCHEMA_VERSION: u32 = 1;
const MAX_SWITCH_JOURNAL_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchPhase {
    Requested,
    CleanupHandedOff,
    RuntimeStopping,
    LocalStopped,
    ServerReconciling,
    AuthResuming,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchDecision {
    Apply,
    Cancel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwitchRetryV1 {
    pub attempt: u32,
    pub retry_after_seconds: u32,
    pub retry_not_before_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalStopReceiptV1 {
    pub operation_id: String,
    pub source_scope_fingerprint: String,
    pub runtime_slot: nelomai_contracts::RuntimeSlot,
    pub runtime_version: String,
    pub forced: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwitchJournalV1 {
    schema_version: u32,
    operation_id: String,
    request_fingerprint: String,
    #[serde(default)]
    active_reconcile_operation_id: Option<String>,
    #[serde(default)]
    active_session_generation: Option<u64>,
    source_identity: Option<RuntimeIdentity>,
    source_device_id: Option<String>,
    source_scope_fingerprint: String,
    target_identity: RuntimeTarget,
    expected_session_generation: Option<u64>,
    cleanup_envelope: CleanupEnvelopeV1,
    #[serde(default)]
    runtime_snapshot: Option<RuntimeCleanupSnapshotV1>,
    phase: SwitchPhase,
    resume_operation_id: Option<String>,
    decision: Option<SwitchDecision>,
    retry: Option<SwitchRetryV1>,
    #[serde(default)]
    supersede_operation_id: Option<String>,
    #[serde(default)]
    supersede_target: Option<RuntimeTarget>,
    #[serde(default)]
    local_stop_receipt: Option<LocalStopReceiptV1>,
    #[serde(default)]
    force_stop_requested: bool,
    #[serde(default)]
    cancel_requested: bool,
}

impl SwitchJournalV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn requested(
        operation_id: String,
        request_fingerprint: String,
        source_identity: Option<RuntimeIdentity>,
        source_device_id: Option<String>,
        source_scope_fingerprint: String,
        target_identity: RuntimeTarget,
        expected_session_generation: Option<u64>,
        cleanup_envelope: CleanupEnvelopeV1,
    ) -> Self {
        Self {
            schema_version: SWITCH_SCHEMA_VERSION,
            operation_id,
            request_fingerprint,
            active_reconcile_operation_id: None,
            active_session_generation: None,
            source_identity,
            source_device_id,
            source_scope_fingerprint,
            target_identity,
            expected_session_generation,
            cleanup_envelope,
            runtime_snapshot: None,
            phase: SwitchPhase::Requested,
            resume_operation_id: None,
            decision: None,
            retry: None,
            supersede_operation_id: None,
            supersede_target: None,
            local_stop_receipt: None,
            force_stop_requested: false,
            cancel_requested: false,
        }
    }

    pub fn phase(&self) -> SwitchPhase {
        self.phase
    }

    pub fn source_identity(&self) -> Option<&RuntimeIdentity> {
        self.source_identity.as_ref()
    }

    pub fn target_identity(&self) -> &RuntimeTarget {
        &self.target_identity
    }

    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub(crate) fn local_stop_receipt(&self) -> Option<&LocalStopReceiptV1> {
        self.local_stop_receipt.as_ref()
    }

    pub(crate) fn supersede_target(&self) -> Option<&RuntimeTarget> {
        self.supersede_target.as_ref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchProgress {
    Ready,
    Pending { retry_after_seconds: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeSwitchStatusV1 {
    pub container_version: String,
    pub selected_slot: nelomai_contracts::RuntimeSlot,
    pub active_slot: nelomai_contracts::RuntimeSlot,
    pub pending_slot: Option<nelomai_contracts::RuntimeSlot>,
    pub latest_version: String,
    pub stable_version: Option<String>,
    pub runtime_contract_version: u32,
    pub manifest_verified: bool,
    pub stable_available: bool,
    pub switch_id: Option<String>,
    pub phase: Option<SwitchPhase>,
    pub engine_role: CleanupEngineRoleV1,
}

impl RuntimeSwitchStatusV1 {
    pub fn restart_required(&self) -> bool {
        self.pending_slot
            .is_some_and(|pending| pending != self.active_slot)
            || self.selected_slot != self.active_slot
    }

    pub fn local_stop_confirmed(&self) -> bool {
        matches!(
            self.phase,
            Some(
                SwitchPhase::LocalStopped
                    | SwitchPhase::ServerReconciling
                    | SwitchPhase::AuthResuming
                    | SwitchPhase::Complete
            )
        )
    }
}

pub struct RuntimeCleanupHandoff {
    snapshot: RuntimeCleanupSnapshotV1,
    _quiescence: Box<dyn Send>,
}

impl RuntimeCleanupHandoff {
    pub fn new(snapshot: RuntimeCleanupSnapshotV1, quiescence: RuntimeWriterQuiescence) -> Self {
        Self {
            snapshot,
            _quiescence: Box::new(quiescence),
        }
    }

    pub(crate) fn remote(snapshot: RuntimeCleanupSnapshotV1, lease: impl Send + 'static) -> Self {
        Self {
            snapshot,
            _quiescence: Box::new(lease),
        }
    }

    pub fn snapshot(&self) -> &RuntimeCleanupSnapshotV1 {
        &self.snapshot
    }
}

#[async_trait]
pub trait RuntimeSwitchControl: Send + Sync {
    async fn handoff_cleanup(
        &self,
        source: &crate::TransitionSourceSnapshot,
    ) -> Result<RuntimeCleanupHandoff, BrokerError>;
    async fn graceful_stop(
        &self,
        operation_id: &str,
        snapshot: &RuntimeCleanupSnapshotV1,
    ) -> Result<(), BrokerError>;
    async fn force_stop(
        &self,
        operation_id: &str,
        snapshot: &RuntimeCleanupSnapshotV1,
    ) -> Result<(), BrokerError>;
    async fn complete_cleanup_and_admit(
        &self,
        snapshot: &RuntimeCleanupSnapshotV1,
        receipt: &LocalStopReceiptV1,
        access: &AccessSnapshot,
    ) -> Result<(), BrokerError>;
}

#[derive(Debug, thiserror::Error)]
pub enum SwitchError {
    #[error(transparent)]
    Journal(#[from] SwitchJournalError),
    #[error(transparent)]
    Broker(#[from] BrokerError),
    #[error("runtime switch requires recovery")]
    RecoveryRequired,
}

#[derive(Debug, thiserror::Error)]
pub enum SwitchJournalError {
    #[error("runtime switch journal I/O failed")]
    Io(#[from] io::Error),
    #[error("runtime switch journal requires recovery")]
    Invalid,
    #[error("another runtime transition is pending")]
    Pending,
}

pub struct SwitchCoordinator {
    owner: Arc<ContainerOwnerLock>,
    path: PathBuf,
    manifest: VerifiedContainerManifest,
    installed_target: Option<RuntimeTarget>,
    broker: Option<Arc<AuthBroker>>,
    control: Option<Arc<dyn RuntimeSwitchControl>>,
    required_initial_target: Option<nelomai_contracts::RuntimeSlot>,
    initial_transition_satisfied: AtomicBool,
    execution: tokio::sync::Mutex<()>,
}

impl SwitchCoordinator {
    /// Retains the common container owner lock for the coordinator's lifetime.
    /// The fixed path prevents a second public switch journal.
    pub fn open(
        owner: Arc<ContainerOwnerLock>,
        manifest: VerifiedContainerManifest,
    ) -> Result<Self, SwitchJournalError> {
        // Selection adoption happens in verified startup, never from a live
        // pending preference. Retain that incarnation's target immutably.
        let installed_target = current_selection(&owner, &manifest).ok().and_then(|state| {
            manifest
                .identity(state.selected_slot, None)
                .ok()
                .map(|identity| RuntimeTarget::from_identity(&identity))
        });
        let coordinator = Self {
            path: owner.root().join("common/runtime-switch-v1.json"),
            owner,
            manifest,
            installed_target,
            broker: None,
            control: None,
            required_initial_target: None,
            initial_transition_satisfied: AtomicBool::new(false),
            execution: tokio::sync::Mutex::new(()),
        };
        coordinator.snapshot()?;
        Ok(coordinator)
    }

    pub fn attach(
        mut self,
        broker: Arc<AuthBroker>,
        control: Arc<dyn RuntimeSwitchControl>,
    ) -> Self {
        self.broker = Some(broker);
        self.control = Some(control);
        self
    }

    pub fn require_initial_transition(mut self, target: nelomai_contracts::RuntimeSlot) -> Self {
        self.required_initial_target = Some(target);
        self
    }

    /// Checkpoint-one primitive used by the later request orchestration. It
    /// accepts only a complete, frozen Requested record and never replaces
    /// unresolved work.
    pub fn begin_requested(&self, journal: SwitchJournalV1) -> Result<(), SwitchJournalError> {
        let _guard = self.owner.lock_transition_journal()?;
        validate_journal(&journal)?;
        validate_new_target(&journal, &self.manifest)?;
        if journal.phase != SwitchPhase::Requested
            || journal.resume_operation_id.is_some()
            || journal.decision.is_some()
            || journal.retry.is_some()
            || journal.active_reconcile_operation_id.is_some()
            || journal.active_session_generation.is_some()
            || journal.supersede_operation_id.is_some()
            || journal.supersede_target.is_some()
        {
            return Err(SwitchJournalError::Invalid);
        }
        let bytes = serde_json::to_vec(&journal).map_err(|_| SwitchJournalError::Invalid)?;
        if bytes.len() > MAX_SWITCH_JOURNAL_BYTES {
            return Err(SwitchJournalError::Invalid);
        }
        if load_journal(&self.path)?.is_some_and(|current| {
            current.phase != SwitchPhase::Complete || current.resume_operation_id.is_none()
        }) {
            return Err(SwitchJournalError::Pending);
        }
        atomic_nonsecret_write(&self.path, &bytes)?;
        Ok(())
    }

    pub fn snapshot(&self) -> Result<Option<SwitchJournalV1>, SwitchJournalError> {
        let _guard = self.owner.lock_transition_journal()?;
        load_journal(&self.path)
    }

    pub fn status(&self) -> Result<RuntimeSwitchStatusV1, SwitchError> {
        let selection =
            current_selection(&self.owner, &self.manifest).map_err(SwitchJournalError::Io)?;
        let active = RuntimeTarget::from_identity(
            &self
                .manifest
                .identity(selection.selected_slot, None)
                .map_err(|_| SwitchError::RecoveryRequired)?,
        );
        self.status_for(&active)
    }

    /// Projects the persisted selection against the runtime that the common
    /// owner actually admitted for this process incarnation.
    pub fn status_for(&self, active: &RuntimeTarget) -> Result<RuntimeSwitchStatusV1, SwitchError> {
        if !self.is_verified_manifest_target(active) {
            return Err(SwitchError::RecoveryRequired);
        }
        let selection =
            current_selection(&self.owner, &self.manifest).map_err(SwitchJournalError::Io)?;
        let latest = self.manifest.latest();
        let stable = self.manifest.stable();
        let journal = self.snapshot()?;
        Ok(RuntimeSwitchStatusV1 {
            container_version: self.manifest.manifest().container_version.clone(),
            selected_slot: selection.selected_slot,
            active_slot: active.runtime_slot,
            pending_slot: selection.pending_slot,
            latest_version: latest.runtime_version.clone(),
            stable_version: stable.map(|runtime| runtime.runtime_version.clone()),
            runtime_contract_version: active.runtime_contract_version,
            manifest_verified: true,
            stable_available: stable.is_some(),
            switch_id: journal.as_ref().map(|journal| journal.operation_id.clone()),
            phase: journal.as_ref().map(|journal| journal.phase),
            engine_role: journal
                .as_ref()
                .map(|journal| journal.cleanup_envelope.engine_role)
                .unwrap_or(CleanupEngineRoleV1::Primary),
        })
    }

    pub async fn request(
        &self,
        target_slot: nelomai_contracts::RuntimeSlot,
    ) -> Result<SwitchProgress, SwitchError> {
        let _execution = self.execution.lock().await;
        self.request_locked(target_slot, false).await
    }

    async fn request_locked(
        &self,
        target_slot: nelomai_contracts::RuntimeSlot,
        recovering_installed_update: bool,
    ) -> Result<SwitchProgress, SwitchError> {
        if !recovering_installed_update && crate::update_barrier_pending(&self.owner)? {
            return Err(SwitchError::RecoveryRequired);
        }
        if self
            .snapshot()?
            .is_some_and(|journal| journal.phase != SwitchPhase::Complete)
        {
            return Err(SwitchJournalError::Pending.into());
        }
        let (broker, control) = self.components()?;
        let source = broker.transition_source().await?;
        let handoff = control.handoff_cleanup(&source).await?;
        let runtime_snapshot = handoff.snapshot().clone();
        if !source.matches_runtime_scope(runtime_snapshot.auth_scope.as_ref())
            || source.identity().is_some_and(|identity| {
                identity.slot != runtime_snapshot.slot
                    || identity.runtime_version != runtime_snapshot.runtime_version
            })
        {
            return Err(SwitchError::RecoveryRequired);
        }
        let cleanup_envelope = CleanupEnvelopeV1::from_runtime_snapshot(
            &runtime_snapshot,
            CleanupEngineRoleV1::Primary,
            None,
        )
        .map_err(|_| SwitchError::RecoveryRequired)?;
        let target_identity = RuntimeTarget::from_identity(
            &self
                .manifest
                .identity(target_slot, None)
                .map_err(|_| SwitchError::RecoveryRequired)?,
        );
        let operation_id = Uuid::new_v4().to_string();
        let request = RuntimeSwitchReconcileRequest {
            operation_id: operation_id.clone(),
            source_identity: source.identity().cloned(),
            target_identity: target_identity.clone(),
            expected_session_generation: source.expected_session_generation(),
            cleanup_contract_version: cleanup_envelope.cleanup_contract_version,
            lease_ids: cleanup_envelope.lease_ids.clone(),
            redundant_session_ids: cleanup_envelope.redundant_session_ids.clone(),
            client_operation_ids: cleanup_envelope
                .operations
                .iter()
                .map(|operation| operation.operation_id.clone())
                .collect(),
        };
        let frozen = FrozenReconcileRequest::new(request, &source)?;
        let mut journal = SwitchJournalV1::requested(
            operation_id,
            frozen.request_fingerprint().into(),
            source.identity().cloned(),
            Some(source.device_id().into()),
            source.scope_fingerprint().into(),
            target_identity,
            source.expected_session_generation(),
            cleanup_envelope,
        );
        journal.runtime_snapshot = Some(runtime_snapshot);
        self.begin_requested(journal)?;
        self.stop_handoff(control, handoff).await?;
        self.recover_locked(broker, control).await
    }

    pub async fn recover(&self) -> Result<SwitchProgress, SwitchError> {
        let _execution = self.execution.lock().await;
        let (broker, control) = self.components()?;
        self.recover_locked(broker, control).await
    }

    pub(crate) fn installed_container_version(&self) -> &str {
        &self.manifest.manifest().container_version
    }

    pub(crate) fn owner_lock(&self) -> Arc<ContainerOwnerLock> {
        self.owner.clone()
    }

    pub(crate) fn is_verified_manifest_target(&self, target: &RuntimeTarget) -> bool {
        self.manifest
            .identity(target.runtime_slot, None)
            .is_ok_and(|identity| RuntimeTarget::from_identity(&identity) == *target)
    }

    pub(crate) async fn prepare_update_stop<F>(
        &self,
        expected_operation_id: Option<&str>,
        persist_requested: F,
    ) -> Result<SwitchJournalV1, SwitchError>
    where
        F: FnOnce(&SwitchJournalV1, nelomai_contracts::RuntimeSlot) -> Result<(), SwitchError>,
    {
        let _execution = self.execution.lock().await;
        let (broker, control) = self.components()?;
        if let Some(expected) = expected_operation_id {
            let journal = self.snapshot()?.ok_or(SwitchError::RecoveryRequired)?;
            if journal.operation_id != expected {
                return Err(SwitchError::RecoveryRequired);
            }
            match journal.phase {
                SwitchPhase::Requested
                | SwitchPhase::CleanupHandedOff
                | SwitchPhase::RuntimeStopping => {
                    let snapshot = journal
                        .runtime_snapshot
                        .as_ref()
                        .ok_or(SwitchError::RecoveryRequired)?;
                    let source = broker.transition_source().await?;
                    let handoff = control.handoff_cleanup(&source).await?;
                    if !source.matches_runtime_scope(snapshot.auth_scope.as_ref())
                        || handoff.snapshot() != snapshot
                    {
                        return Err(SwitchError::RecoveryRequired);
                    }
                    self.stop_handoff(control, handoff).await?;
                }
                SwitchPhase::LocalStopped => {}
                _ => return Err(SwitchError::RecoveryRequired),
            }
            let stopped = self.snapshot()?.ok_or(SwitchError::RecoveryRequired)?;
            if stopped.operation_id != expected || stopped.phase != SwitchPhase::LocalStopped {
                return Err(SwitchError::RecoveryRequired);
            }
            return Ok(stopped);
        }
        if self
            .snapshot()?
            .is_some_and(|journal| journal.phase != SwitchPhase::Complete)
        {
            return Err(SwitchJournalError::Pending.into());
        }
        let selection =
            current_selection(&self.owner, &self.manifest).map_err(SwitchJournalError::Io)?;
        let source = broker.transition_source().await?;
        let source_identity = source
            .identity()
            .cloned()
            .ok_or(SwitchError::RecoveryRequired)?;
        let selected_identity = self
            .manifest
            .identity(selection.selected_slot, None)
            .map_err(|_| SwitchError::RecoveryRequired)?;
        if RuntimeTarget::from_identity(&source_identity)
            != RuntimeTarget::from_identity(&selected_identity)
        {
            return Err(SwitchError::RecoveryRequired);
        }
        let handoff = control.handoff_cleanup(&source).await?;
        let runtime_snapshot = handoff.snapshot().clone();
        if !source.matches_runtime_scope(runtime_snapshot.auth_scope.as_ref())
            || source_identity.slot != runtime_snapshot.slot
            || source_identity.runtime_version != runtime_snapshot.runtime_version
        {
            return Err(SwitchError::RecoveryRequired);
        }
        let cleanup_envelope = CleanupEnvelopeV1::from_runtime_snapshot(
            &runtime_snapshot,
            CleanupEngineRoleV1::Primary,
            None,
        )
        .map_err(|_| SwitchError::RecoveryRequired)?;
        let target_identity = RuntimeTarget::from_identity(&source_identity);
        let operation_id = Uuid::new_v4().to_string();
        let request = RuntimeSwitchReconcileRequest {
            operation_id: operation_id.clone(),
            source_identity: Some(source_identity.clone()),
            target_identity: target_identity.clone(),
            expected_session_generation: source.expected_session_generation(),
            cleanup_contract_version: cleanup_envelope.cleanup_contract_version,
            lease_ids: cleanup_envelope.lease_ids.clone(),
            redundant_session_ids: cleanup_envelope.redundant_session_ids.clone(),
            client_operation_ids: cleanup_envelope
                .operations
                .iter()
                .map(|operation| operation.operation_id.clone())
                .collect(),
        };
        let frozen = FrozenReconcileRequest::new(request, &source)?;
        let mut journal = SwitchJournalV1::requested(
            operation_id,
            frozen.request_fingerprint().into(),
            Some(source_identity),
            Some(source.device_id().into()),
            source.scope_fingerprint().into(),
            target_identity,
            source.expected_session_generation(),
            cleanup_envelope,
        );
        journal.runtime_snapshot = Some(runtime_snapshot);
        persist_requested(&journal, selection.selected_slot)?;
        self.begin_requested(journal)?;
        self.stop_handoff(control, handoff).await?;
        let stopped = self.snapshot()?.ok_or(SwitchError::RecoveryRequired)?;
        if stopped.phase != SwitchPhase::LocalStopped {
            return Err(SwitchError::RecoveryRequired);
        }
        Ok(stopped)
    }

    pub(crate) async fn cancel_update_stop(
        &self,
        operation_id: &str,
    ) -> Result<SwitchProgress, SwitchError> {
        let _execution = self.execution.lock().await;
        self.cancel_update_stop_locked(operation_id).await
    }

    async fn cancel_update_stop_locked(
        &self,
        operation_id: &str,
    ) -> Result<SwitchProgress, SwitchError> {
        let Some(journal) = self.snapshot()? else {
            return Ok(SwitchProgress::Ready);
        };
        if journal.operation_id != operation_id {
            return if journal.phase == SwitchPhase::Complete {
                Ok(SwitchProgress::Ready)
            } else {
                Err(SwitchError::RecoveryRequired)
            };
        }
        if journal.phase == SwitchPhase::Complete {
            return match journal.decision {
                Some(SwitchDecision::Cancel) => Ok(SwitchProgress::Ready),
                _ => Err(SwitchError::RecoveryRequired),
            };
        }
        let (broker, control) = self.components()?;
        self.update(|journal| journal.cancel_requested = true)?;
        self.recover_locked(broker, control).await
    }

    pub(crate) fn restore_update_selection(
        &self,
        previous: nelomai_contracts::RuntimeSlot,
    ) -> Result<(), SwitchError> {
        finish_selection(&self.owner, &self.manifest, previous)
            .map_err(SwitchJournalError::Io)
            .map_err(Into::into)
    }

    pub(crate) async fn lock_logout_cleanup(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.execution.lock().await
    }

    /// Caller holds execution and writer quiescence and has successfully
    /// stopped/cleared the exact logout source. Keep the protected ACK until
    /// selection and journal retirement are both durable.
    pub(crate) async fn retire_logout_journal(
        &self,
        receipt: &nelomai_client_storage::CompletedRuntimeLogoutV1,
    ) -> Result<(), SwitchError> {
        let Some(journal) = self.snapshot()? else {
            return Ok(());
        };
        let (broker, _) = self.components()?;
        if !broker
            .logout_covers_transition(
                receipt,
                &journal.operation_id,
                &journal.source_scope_fingerprint,
                journal.source_device_id.as_deref(),
            )
            .await?
        {
            return Ok(());
        }
        let selection =
            current_selection(&self.owner, &self.manifest).map_err(SwitchJournalError::Io)?;
        finish_selection(&self.owner, &self.manifest, selection.selected_slot)
            .map_err(SwitchJournalError::Io)?;
        let _journal = self
            .owner
            .lock_transition_journal()
            .map_err(SwitchJournalError::Io)?;
        if load_journal(&self.path)?.as_ref() != Some(&journal) {
            return Err(SwitchError::RecoveryRequired);
        }
        std::fs::remove_file(&self.path).map_err(SwitchJournalError::Io)?;
        #[cfg(unix)]
        File::open(self.path.parent().ok_or(SwitchJournalError::Invalid)?)
            .and_then(|directory| directory.sync_all())
            .map_err(SwitchJournalError::Io)?;
        Ok(())
    }

    pub async fn recover_refresh_before_start(&self) -> Result<(), SwitchError> {
        let _execution = self.execution.lock().await;
        if let Some(broker) = &self.broker {
            broker.recover_pending_refresh().await?;
        }
        Ok(())
    }

    pub async fn before_tunnel_start(&self) -> Result<(), SwitchError> {
        let _execution = self.execution.lock().await;
        self.before_tunnel_start_locked_for(None).await
    }

    pub async fn before_tunnel_start_for(&self, active: &RuntimeTarget) -> Result<(), SwitchError> {
        let _execution = self.execution.lock().await;
        self.before_tunnel_start_locked_for(Some(active)).await
    }

    async fn before_tunnel_start_locked_for(
        &self,
        active: Option<&RuntimeTarget>,
    ) -> Result<(), SwitchError> {
        if active.is_some_and(|target| {
            self.status_for(target)
                .map(|status| status.restart_required())
                .unwrap_or(true)
        }) {
            return Err(SwitchError::RecoveryRequired);
        }
        match crate::update_start_recovery(self)? {
            crate::UpdateStartRecovery::None => self.before_tunnel_start_locked(false).await,
            crate::UpdateStartRecovery::Blocked => Err(SwitchError::RecoveryRequired),
            recovery => self.recover_update_for_start_locked(recovery).await,
        }
    }

    /// Prepares a full runtime-process relaunch without weakening update
    /// replacement gates. Recovery may remain server-pending, but local stop
    /// and its durable handoff must already be complete before relaunch.
    pub async fn prepare_runtime_restart(
        &self,
        active: &RuntimeTarget,
    ) -> Result<RuntimeSwitchStatusV1, SwitchError> {
        let _execution = self.execution.lock().await;
        if crate::update_barrier_pending(&self.owner)? {
            return Err(SwitchError::RecoveryRequired);
        }
        let status = self.status_for(active)?;
        if !status.restart_required() {
            return Err(SwitchError::RecoveryRequired);
        }
        if status
            .phase
            .is_some_and(|phase| phase != SwitchPhase::Complete)
        {
            let (broker, control) = self.components()?;
            let recovered = self.recover_locked(broker, control).await;
            if recovered.is_err() {
                let status = self.status_for(active)?;
                if !status.restart_required() || !status.local_stop_confirmed() {
                    return Err(SwitchError::RecoveryRequired);
                }
            }
        }
        let mut status = self.status_for(active)?;
        if !status.restart_required() || !status.local_stop_confirmed() {
            return Err(SwitchError::RecoveryRequired);
        }
        if let Some(pending) = status.pending_slot {
            finish_selection(&self.owner, &self.manifest, pending)
                .map_err(SwitchJournalError::Io)?;
            status = self.status_for(active)?;
        }
        Ok(status)
    }

    pub(crate) async fn recover_installed_update(&self) -> Result<(), SwitchError> {
        let _execution = self.execution.lock().await;
        let recovery = crate::update_start_recovery(self)?;
        if !matches!(recovery, crate::UpdateStartRecovery::Installed { .. }) {
            return Err(SwitchError::RecoveryRequired);
        }
        self.recover_update_for_start_locked(recovery).await
    }

    async fn recover_update_for_start_locked(
        &self,
        recovery: crate::UpdateStartRecovery,
    ) -> Result<(), SwitchError> {
        let operation_id = match recovery {
            crate::UpdateStartRecovery::Cancel {
                operation_id,
                previous_slot,
            } => {
                if matches!(
                    self.cancel_update_stop_locked(&operation_id).await?,
                    SwitchProgress::Pending { .. }
                ) {
                    return Err(SwitchError::RecoveryRequired);
                }
                self.restore_update_selection(previous_slot)?;
                operation_id
            }
            crate::UpdateStartRecovery::Installed { operation_id } => {
                self.before_tunnel_start_locked(true).await?;
                operation_id
            }
            crate::UpdateStartRecovery::None | crate::UpdateStartRecovery::Blocked => {
                return Err(SwitchError::RecoveryRequired)
            }
        };
        crate::finish_update_recovery(&self.owner, &operation_id)?;
        Ok(())
    }

    async fn before_tunnel_start_locked(
        &self,
        recovering_installed_update: bool,
    ) -> Result<(), SwitchError> {
        let (broker, control) = self.components()?;
        if matches!(
            self.recover_locked(broker, control).await?,
            SwitchProgress::Pending { .. }
        ) {
            return Err(SwitchError::RecoveryRequired);
        }
        if !self.initial_transition_required(self.snapshot()?.as_ref())? {
            self.initial_transition_satisfied
                .store(true, Ordering::SeqCst);
            return Ok(());
        }
        let target = self
            .required_initial_target
            .ok_or(SwitchError::RecoveryRequired)?;
        match self
            .request_locked(target, recovering_installed_update)
            .await?
        {
            SwitchProgress::Ready => {
                self.initial_transition_satisfied
                    .store(true, Ordering::SeqCst);
                Ok(())
            }
            SwitchProgress::Pending { .. } => Err(SwitchError::RecoveryRequired),
        }
    }

    fn initial_transition_required(
        &self,
        journal: Option<&SwitchJournalV1>,
    ) -> Result<bool, SwitchError> {
        // Startup admission is one obligation. Once fulfilled, a subsequent
        // explicit slot selection must not be replaced by the startup target.
        // After restart the host derives the obligation again from the record.
        if self.initial_transition_satisfied.load(Ordering::SeqCst) {
            return Ok(false);
        }
        let Some(slot) = self.required_initial_target else {
            return Ok(false);
        };
        let target = RuntimeTarget::from_identity(
            &self
                .manifest
                .identity(slot, None)
                .map_err(|_| SwitchError::RecoveryRequired)?,
        );
        let completed_target = journal
            .filter(|journal| journal.phase == SwitchPhase::Complete)
            .and_then(|journal| match journal.decision {
                Some(SwitchDecision::Apply) => Some(journal.target_identity.clone()),
                Some(SwitchDecision::Cancel) => journal
                    .source_identity
                    .as_ref()
                    .map(RuntimeTarget::from_identity),
                None => None,
            });
        Ok(completed_target.as_ref() != Some(&target))
    }

    /// Non-recovering admission check used only under the lifecycle writer
    /// gate. A request must acquire that gate before publishing Requested, so
    /// the journal cannot cross from ready to pending until this start exits.
    fn check_start_barrier(&self) -> Result<(), SwitchError> {
        let journal = self.snapshot()?;
        if journal
            .as_ref()
            .is_some_and(|journal| journal.phase != SwitchPhase::Complete)
            || crate::update_barrier_pending(&self.owner)?
            || self.initial_transition_required(journal.as_ref())?
        {
            return Err(SwitchError::RecoveryRequired);
        }
        Ok(())
    }

    pub async fn cancel_pending(&self) -> Result<SwitchProgress, SwitchError> {
        let _execution = self.execution.lock().await;
        if crate::update_barrier_pending(&self.owner)? {
            return Err(SwitchError::RecoveryRequired);
        }
        let (broker, control) = self.components()?;
        self.update(|journal| journal.cancel_requested = true)?;
        self.recover_locked(broker, control).await
    }

    pub async fn cancel_pending_for(
        &self,
        active: &RuntimeTarget,
    ) -> Result<SwitchProgress, SwitchError> {
        let _execution = self.execution.lock().await;
        if crate::update_barrier_pending(&self.owner)? || !self.is_verified_manifest_target(active)
        {
            return Err(SwitchError::RecoveryRequired);
        }
        let journal = self.snapshot()?.ok_or(SwitchError::RecoveryRequired)?;
        if journal
            .source_identity
            .as_ref()
            .map(RuntimeTarget::from_identity)
            .as_ref()
            != Some(active)
        {
            return Err(SwitchError::RecoveryRequired);
        }
        if journal.phase == SwitchPhase::Complete {
            if journal.decision != Some(SwitchDecision::Apply)
                || journal.target_identity.runtime_slot == active.runtime_slot
            {
                return Err(SwitchError::RecoveryRequired);
            }
            // A completed Apply is immutable. Returning to the still-active
            // runtime is a fresh reverse transition with its own authority,
            // never a replay of the completed operation as Cancel.
            return self.request_locked(active.runtime_slot, false).await;
        }
        self.update(|journal| journal.cancel_requested = true)?;
        let (broker, control) = self.components()?;
        self.recover_locked(broker, control).await
    }

    fn components(
        &self,
    ) -> Result<(&Arc<AuthBroker>, &Arc<dyn RuntimeSwitchControl>), SwitchError> {
        Ok((
            self.broker.as_ref().ok_or(SwitchError::RecoveryRequired)?,
            self.control.as_ref().ok_or(SwitchError::RecoveryRequired)?,
        ))
    }

    async fn recover_locked(
        &self,
        broker: &AuthBroker,
        control: &Arc<dyn RuntimeSwitchControl>,
    ) -> Result<SwitchProgress, SwitchError> {
        loop {
            let journal = match self.snapshot()? {
                Some(journal) => journal,
                None => return Ok(SwitchProgress::Ready),
            };
            broker
                .retire_completed_transitions(
                    &journal.operation_id,
                    journal.active_reconcile_operation_id.as_deref(),
                )
                .await?;
            let snapshot = journal
                .runtime_snapshot
                .as_ref()
                .ok_or(SwitchError::RecoveryRequired)?;
            match journal.phase {
                SwitchPhase::Requested
                | SwitchPhase::CleanupHandedOff
                | SwitchPhase::RuntimeStopping => {
                    let source = broker.transition_source().await?;
                    let handoff = control.handoff_cleanup(&source).await?;
                    if !source.matches_runtime_scope(snapshot.auth_scope.as_ref())
                        || handoff.snapshot() != snapshot
                    {
                        return Err(SwitchError::RecoveryRequired);
                    }
                    self.stop_handoff(control, handoff).await?;
                }
                SwitchPhase::LocalStopped => {
                    self.update(|journal| journal.phase = SwitchPhase::ServerReconciling)?;
                }
                SwitchPhase::ServerReconciling => {
                    if let Some(retry) = &journal.retry {
                        let now = unix_time_ms();
                        if now < retry.retry_not_before_unix_ms {
                            return Ok(SwitchProgress::Pending {
                                retry_after_seconds: retry.retry_after_seconds,
                            });
                        }
                    }
                    let attempt = journal
                        .retry
                        .as_ref()
                        .map_or(1, |retry| retry.attempt.saturating_add(1).min(32));
                    let delay = retry_delay(attempt);
                    self.update(|journal| {
                        journal.retry = Some(SwitchRetryV1 {
                            attempt,
                            retry_after_seconds: delay,
                            retry_not_before_unix_ms: unix_time_ms()
                                .saturating_add(u64::from(delay) * 1000),
                        });
                    })?;
                    let request = journal.reconcile_request();
                    let frozen = FrozenReconcileRequest::from_persisted(
                        request,
                        journal
                            .source_device_id
                            .clone()
                            .ok_or(SwitchError::RecoveryRequired)?,
                        journal.source_scope_fingerprint.clone(),
                        Some(&journal.request_fingerprint),
                    )?;
                    let receipt = match broker.reconcile_transition(frozen.clone()).await {
                        Ok(receipt) => receipt,
                        Err(BrokerError::Timeout)
                        | Err(BrokerError::Api(ClientApiError::Transport(_))) => {
                            return Ok(SwitchProgress::Pending {
                                retry_after_seconds: delay,
                            });
                        }
                        Err(error) => return Err(error.into()),
                    };
                    if receipt.state == RuntimeSwitchState::Retry {
                        let delay = receipt
                            .retry_after_seconds
                            .unwrap_or(delay)
                            .max(delay)
                            .min(30);
                        self.update(|journal| {
                            journal.retry = Some(SwitchRetryV1 {
                                attempt,
                                retry_after_seconds: delay,
                                retry_not_before_unix_ms: unix_time_ms()
                                    .saturating_add(u64::from(delay) * 1000),
                            });
                        })?;
                        return Ok(SwitchProgress::Pending {
                            retry_after_seconds: delay,
                        });
                    }
                    if !journal.cancel_requested {
                        let selection = current_selection(&self.owner, &self.manifest)
                            .map_err(SwitchJournalError::Io)?;
                        let desired_slot =
                            selection.pending_slot.unwrap_or(selection.selected_slot);
                        let desired = RuntimeTarget::from_identity(
                            &self
                                .manifest
                                .identity(desired_slot, None)
                                .map_err(|_| SwitchError::RecoveryRequired)?,
                        );
                        if desired != journal.target_identity {
                            let supersede_operation_id = match &journal.supersede_operation_id {
                                Some(operation_id)
                                    if journal.supersede_target.as_ref() == Some(&desired) =>
                                {
                                    operation_id.clone()
                                }
                                Some(_) => return Err(SwitchError::RecoveryRequired),
                                None => {
                                    let operation_id = Uuid::new_v4().to_string();
                                    let saved_operation_id = operation_id.clone();
                                    let saved_target = desired.clone();
                                    self.update(|journal| {
                                        journal.supersede_operation_id = Some(saved_operation_id);
                                        journal.supersede_target = Some(saved_target);
                                    })?;
                                    operation_id
                                }
                            };
                            let superseded = match broker
                                .supersede_transition(
                                    &supersede_operation_id,
                                    frozen,
                                    desired.clone(),
                                )
                                .await
                            {
                                Ok(response) => response,
                                Err(BrokerError::Timeout)
                                | Err(BrokerError::Api(ClientApiError::Transport(_))) => {
                                    return Ok(SwitchProgress::Pending {
                                        retry_after_seconds: delay,
                                    });
                                }
                                Err(error) => return Err(error.into()),
                            };
                            if superseded.state == RuntimeSwitchState::Retry {
                                let delay = superseded
                                    .retry_after_seconds
                                    .unwrap_or(delay)
                                    .max(delay)
                                    .min(30);
                                self.update(|journal| {
                                    journal.retry = Some(SwitchRetryV1 {
                                        attempt,
                                        retry_after_seconds: delay,
                                        retry_not_before_unix_ms: unix_time_ms()
                                            .saturating_add(u64::from(delay) * 1000),
                                    });
                                })?;
                                return Ok(SwitchProgress::Pending {
                                    retry_after_seconds: delay,
                                });
                            }
                            let successor_id = superseded.reconcile_operation_id.clone();
                            let successor_source = broker.transition_source().await?;
                            let mut successor_request = journal.reconcile_request();
                            successor_request.operation_id = successor_id.clone();
                            successor_request.source_identity =
                                successor_source.identity().cloned();
                            successor_request.expected_session_generation =
                                successor_source.expected_session_generation();
                            successor_request.target_identity = desired.clone();
                            let successor =
                                FrozenReconcileRequest::new(successor_request, &successor_source)?;
                            let successor_fingerprint = successor.request_fingerprint().to_owned();
                            self.update(|journal| {
                                journal.active_reconcile_operation_id = Some(successor_id.clone());
                                journal.active_session_generation =
                                    successor_source.expected_session_generation();
                                journal.target_identity = desired;
                                journal.request_fingerprint = successor_fingerprint;
                                journal.retry = None;
                                journal.resume_operation_id = Some(Uuid::new_v4().to_string());
                                journal.decision = Some(SwitchDecision::Apply);
                                journal.phase = SwitchPhase::AuthResuming;
                            })?;
                            broker
                                .finish_supersede(
                                    &supersede_operation_id,
                                    &superseded.reconcile_operation_id,
                                )
                                .await?;
                            self.update(|journal| {
                                journal.supersede_operation_id = None;
                                journal.supersede_target = None;
                            })?;
                            continue;
                        }
                    }
                    self.update(|journal| {
                        journal.retry = None;
                        journal.resume_operation_id = Some(Uuid::new_v4().to_string());
                        journal.decision = Some(if journal.cancel_requested {
                            SwitchDecision::Cancel
                        } else {
                            SwitchDecision::Apply
                        });
                        journal.phase = SwitchPhase::AuthResuming;
                    })?;
                }
                SwitchPhase::AuthResuming => {
                    if journal.cancel_requested
                        && journal.decision == Some(SwitchDecision::Apply)
                        && journal.active_reconcile_operation_id.is_none()
                        && broker
                            .transition_resume_is_undispatched(
                                journal
                                    .active_reconcile_operation_id
                                    .as_deref()
                                    .unwrap_or(&journal.operation_id),
                            )
                            .await?
                    {
                        // Prepared intent may be cancelled; a protected ticket
                        // (even outcome unknown) must instead replay unchanged.
                        self.update(|journal| {
                            journal.decision = Some(SwitchDecision::Cancel);
                            journal.resume_operation_id = Some(Uuid::new_v4().to_string());
                            journal.retry = None;
                        })?;
                        continue;
                    }
                    if let Some(retry) = &journal.retry {
                        if unix_time_ms() < retry.retry_not_before_unix_ms {
                            return Ok(SwitchProgress::Pending {
                                retry_after_seconds: retry.retry_after_seconds,
                            });
                        }
                    }
                    if let (Some(operation_id), Some(supersede_target), Some(successor_id)) = (
                        journal.supersede_operation_id.as_deref(),
                        journal.supersede_target.as_ref(),
                        journal.active_reconcile_operation_id.as_deref(),
                    ) {
                        if &journal.target_identity == supersede_target {
                            broker.finish_supersede(operation_id, successor_id).await?;
                            self.update(|journal| {
                                journal.supersede_operation_id = None;
                                journal.supersede_target = None;
                            })?;
                            continue;
                        }
                    }
                    let decision = journal.decision.ok_or(SwitchError::RecoveryRequired)?;
                    let target = match decision {
                        SwitchDecision::Apply => journal.target_identity.clone(),
                        SwitchDecision::Cancel => RuntimeTarget::from_identity(
                            journal
                                .source_identity
                                .as_ref()
                                .ok_or(SwitchError::RecoveryRequired)?,
                        ),
                    };
                    let resumed = broker
                        .resume_transition_for_installed_target(
                            ResumeArguments {
                                operation_id: journal
                                    .resume_operation_id
                                    .clone()
                                    .ok_or(SwitchError::RecoveryRequired)?,
                                reconcile_operation_id: journal
                                    .active_reconcile_operation_id
                                    .clone()
                                    .unwrap_or_else(|| journal.operation_id.clone()),
                                decision: match decision {
                                    SwitchDecision::Apply => "apply",
                                    SwitchDecision::Cancel => "cancel",
                                }
                                .into(),
                                target,
                                expected_session_generation: journal
                                    .active_session_generation
                                    .or(journal.expected_session_generation),
                            },
                            self.installed_target.as_ref(),
                        )
                        .await?;
                    if decision == SwitchDecision::Apply {
                        let selection = current_selection(&self.owner, &self.manifest)
                            .map_err(SwitchJournalError::Io)?;
                        let desired_slot =
                            selection.pending_slot.unwrap_or(selection.selected_slot);
                        let desired = RuntimeTarget::from_identity(
                            &self
                                .manifest
                                .identity(desired_slot, None)
                                .map_err(|_| SwitchError::RecoveryRequired)?,
                        );
                        if RuntimeTarget::from_identity(resumed.identity()) != desired {
                            let source = broker.transition_source().await?;
                            if source.identity() != Some(resumed.identity()) {
                                return Err(SwitchError::RecoveryRequired);
                            }
                            let predecessor = broker
                                .restore_transition_request(
                                    journal.reconcile_request(),
                                    &journal.request_fingerprint,
                                )
                                .await?;
                            let operation_id = match &journal.supersede_operation_id {
                                Some(operation_id)
                                    if journal.supersede_target.as_ref() == Some(&desired) =>
                                {
                                    operation_id.clone()
                                }
                                Some(_) => return Err(SwitchError::RecoveryRequired),
                                None => {
                                    let operation_id = Uuid::new_v4().to_string();
                                    let saved_id = operation_id.clone();
                                    let saved_target = desired.clone();
                                    self.update(|journal| {
                                        journal.supersede_operation_id = Some(saved_id);
                                        journal.supersede_target = Some(saved_target);
                                    })?;
                                    operation_id
                                }
                            };
                            let attempt = journal
                                .retry
                                .as_ref()
                                .map_or(1, |retry| retry.attempt.saturating_add(1).min(32));
                            let delay = retry_delay(attempt);
                            self.update(|journal| {
                                journal.retry = Some(SwitchRetryV1 {
                                    attempt,
                                    retry_after_seconds: delay,
                                    retry_not_before_unix_ms: unix_time_ms()
                                        .saturating_add(u64::from(delay) * 1000),
                                });
                            })?;
                            let superseded = match broker
                                .supersede_transition(&operation_id, predecessor, desired.clone())
                                .await
                            {
                                Ok(response) => response,
                                Err(BrokerError::Timeout)
                                | Err(BrokerError::Api(ClientApiError::Transport(_))) => {
                                    return Ok(SwitchProgress::Pending {
                                        retry_after_seconds: delay,
                                    });
                                }
                                Err(error) => return Err(error.into()),
                            };
                            if superseded.state == RuntimeSwitchState::Retry {
                                let delay = superseded
                                    .retry_after_seconds
                                    .unwrap_or(delay)
                                    .max(delay)
                                    .min(30);
                                self.update(|journal| {
                                    journal.retry = Some(SwitchRetryV1 {
                                        attempt,
                                        retry_after_seconds: delay,
                                        retry_not_before_unix_ms: unix_time_ms()
                                            .saturating_add(u64::from(delay) * 1000),
                                    });
                                })?;
                                return Ok(SwitchProgress::Pending {
                                    retry_after_seconds: delay,
                                });
                            }
                            let mut successor_request = journal.reconcile_request();
                            successor_request.operation_id =
                                superseded.reconcile_operation_id.clone();
                            successor_request.source_identity = source.identity().cloned();
                            successor_request.expected_session_generation =
                                source.expected_session_generation();
                            successor_request.target_identity = desired.clone();
                            let successor =
                                FrozenReconcileRequest::new(successor_request, &source)?;
                            let successor_id = superseded.reconcile_operation_id.clone();
                            let successor_fingerprint = successor.request_fingerprint().to_owned();
                            self.update(|journal| {
                                journal.active_reconcile_operation_id = Some(successor_id);
                                journal.active_session_generation =
                                    source.expected_session_generation();
                                journal.target_identity = desired;
                                journal.request_fingerprint = successor_fingerprint;
                                journal.resume_operation_id = Some(Uuid::new_v4().to_string());
                                journal.retry = None;
                            })?;
                            broker
                                .finish_supersede(&operation_id, &superseded.reconcile_operation_id)
                                .await?;
                            self.update(|journal| {
                                journal.supersede_operation_id = None;
                                journal.supersede_target = None;
                            })?;
                            continue;
                        }
                    }
                    let access = resumed
                        .current_access()
                        .ok_or(SwitchError::RecoveryRequired)?;
                    let local = journal
                        .local_stop_receipt
                        .as_ref()
                        .ok_or(SwitchError::RecoveryRequired)?;
                    control
                        .complete_cleanup_and_admit(snapshot, local, access)
                        .await?;
                    let selected = match decision {
                        SwitchDecision::Apply => journal.target_identity.runtime_slot,
                        SwitchDecision::Cancel => {
                            journal
                                .source_identity
                                .as_ref()
                                .ok_or(SwitchError::RecoveryRequired)?
                                .slot
                        }
                    };
                    finish_selection(&self.owner, &self.manifest, selected)
                        .map_err(SwitchJournalError::Io)?;
                    self.update(|journal| journal.phase = SwitchPhase::Complete)?;
                }
                SwitchPhase::Complete => return Ok(SwitchProgress::Ready),
            }
        }
    }

    async fn stop_handoff(
        &self,
        control: &Arc<dyn RuntimeSwitchControl>,
        handoff: RuntimeCleanupHandoff,
    ) -> Result<(), SwitchError> {
        let journal = self.snapshot()?.ok_or(SwitchJournalError::Invalid)?;
        let snapshot = handoff.snapshot();
        if journal.runtime_snapshot.as_ref() != Some(snapshot) {
            return Err(SwitchError::RecoveryRequired);
        }
        if journal.phase == SwitchPhase::Requested {
            self.update(|journal| journal.phase = SwitchPhase::CleanupHandedOff)?;
        }
        self.update(|journal| journal.phase = SwitchPhase::RuntimeStopping)?;
        let forced = if journal.force_stop_requested {
            control.force_stop(&journal.operation_id, snapshot).await?;
            true
        } else {
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                control.graceful_stop(&journal.operation_id, snapshot),
            )
            .await
            {
                Ok(Ok(())) => false,
                Ok(Err(_)) | Err(_) => {
                    self.update(|journal| journal.force_stop_requested = true)?;
                    control.force_stop(&journal.operation_id, snapshot).await?;
                    true
                }
            }
        };
        let receipt = LocalStopReceiptV1 {
            operation_id: journal.operation_id,
            source_scope_fingerprint: journal.source_scope_fingerprint,
            runtime_slot: snapshot.slot,
            runtime_version: snapshot.runtime_version.clone(),
            forced,
        };
        self.update(|journal| {
            journal.local_stop_receipt = Some(receipt);
            journal.phase = SwitchPhase::LocalStopped;
        })?;
        Ok(())
    }

    fn update(
        &self,
        change: impl FnOnce(&mut SwitchJournalV1),
    ) -> Result<SwitchJournalV1, SwitchJournalError> {
        let _guard = self.owner.lock_transition_journal()?;
        let mut journal = load_journal(&self.path)?.ok_or(SwitchJournalError::Invalid)?;
        change(&mut journal);
        validate_journal(&journal)?;
        let bytes = serde_json::to_vec(&journal).map_err(|_| SwitchJournalError::Invalid)?;
        if bytes.len() > MAX_SWITCH_JOURNAL_BYTES {
            return Err(SwitchJournalError::Invalid);
        }
        atomic_nonsecret_write(&self.path, &bytes)?;
        Ok(journal)
    }
}

#[async_trait]
impl RuntimeStartPreflight for SwitchCoordinator {
    async fn before_tunnel_start(&self) -> Result<(), CoreError> {
        match SwitchCoordinator::before_tunnel_start(self).await {
            Ok(()) => Ok(()),
            Err(_) => Err(CoreError::AuthRecoveryRequired),
        }
    }
    fn check_start_barrier(&self) -> Result<(), CoreError> {
        SwitchCoordinator::check_start_barrier(self).map_err(|_| CoreError::AuthRecoveryRequired)
    }
}

impl SwitchJournalV1 {
    fn reconcile_request(&self) -> RuntimeSwitchReconcileRequest {
        RuntimeSwitchReconcileRequest {
            operation_id: self
                .active_reconcile_operation_id
                .clone()
                .unwrap_or_else(|| self.operation_id.clone()),
            source_identity: self.source_identity.clone(),
            target_identity: self.target_identity.clone(),
            expected_session_generation: self.expected_session_generation,
            cleanup_contract_version: self.cleanup_envelope.cleanup_contract_version,
            lease_ids: self.cleanup_envelope.lease_ids.clone(),
            redundant_session_ids: self.cleanup_envelope.redundant_session_ids.clone(),
            client_operation_ids: self
                .cleanup_envelope
                .operations
                .iter()
                .map(|operation| operation.operation_id.clone())
                .collect(),
        }
    }
}

fn unix_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or_default()
}

fn retry_delay(attempt: u32) -> u32 {
    1_u32
        .checked_shl(attempt.saturating_sub(1).min(5))
        .unwrap_or(30)
        .min(30)
}

/// The journal rename is the sole switch-intent commit. Preference consumers
/// project this validated intent; a second selection-file write is not required
/// to remember Requested. Terminal/foreign-container journals cannot retarget it.
pub(crate) fn desired_slot_from_journal(
    path: &PathBuf,
    manifest: &VerifiedContainerManifest,
) -> io::Result<Option<nelomai_contracts::RuntimeSlot>> {
    let Some(journal) = load_journal(path).map_err(|_| crate::installed_runtime::blocked())? else {
        return Ok(None);
    };
    if journal.phase == SwitchPhase::Complete
        || journal.target_identity.container_version != manifest.manifest().container_version
    {
        return Ok(None);
    }
    let target = if journal.cancel_requested {
        journal
            .source_identity
            .as_ref()
            .map(RuntimeTarget::from_identity)
    } else {
        Some(journal.target_identity)
    };
    Ok(target
        .filter(|target| {
            manifest
                .identity(target.runtime_slot, None)
                .is_ok_and(|identity| RuntimeTarget::from_identity(&identity) == *target)
        })
        .map(|target| target.runtime_slot))
}

fn load_journal(path: &PathBuf) -> Result<Option<SwitchJournalV1>, SwitchJournalError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    file.take((MAX_SWITCH_JOURNAL_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SWITCH_JOURNAL_BYTES {
        return Err(SwitchJournalError::Invalid);
    }
    let journal: SwitchJournalV1 =
        serde_json::from_slice(&bytes).map_err(|_| SwitchJournalError::Invalid)?;
    validate_journal(&journal)?;
    Ok(Some(journal))
}

fn validate_journal(journal: &SwitchJournalV1) -> Result<(), SwitchJournalError> {
    if journal.schema_version != SWITCH_SCHEMA_VERSION
        || !canonical_uuid(&journal.operation_id)
        || !valid_fingerprint(&journal.request_fingerprint)
        || !valid_fingerprint(&journal.source_scope_fingerprint)
        || !journal.cleanup_envelope.validate()
        || journal
            .source_device_id
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 256)
    {
        return Err(SwitchJournalError::Invalid);
    }
    match &journal.source_identity {
        Some(source)
            if source.validate().is_ok()
                && source.session_generation == journal.expected_session_generation
                && source.session_generation.is_some() => {}
        None if journal.expected_session_generation.is_none() => {}
        _ => return Err(SwitchJournalError::Invalid),
    }
    journal
        .target_identity
        .identity(None)
        .map_err(|_| SwitchJournalError::Invalid)?;
    if journal
        .resume_operation_id
        .as_ref()
        .is_some_and(|value| !canonical_uuid(value))
        || journal.resume_operation_id.is_some() != journal.decision.is_some()
        || journal
            .active_reconcile_operation_id
            .as_ref()
            .is_some_and(|value| !canonical_uuid(value) || value == &journal.operation_id)
        || journal.active_reconcile_operation_id.is_some()
            != journal.active_session_generation.is_some()
        || journal
            .active_session_generation
            .is_some_and(|generation| generation == 0 || generation > i64::MAX as u64)
        || journal.supersede_operation_id.is_some() != journal.supersede_target.is_some()
        || journal
            .supersede_operation_id
            .as_ref()
            .is_some_and(|value| !canonical_uuid(value))
        || journal
            .supersede_target
            .as_ref()
            .is_some_and(|target| target.identity(None).is_err())
        || journal.supersede_operation_id.is_some()
            && !matches!(
                journal.phase,
                SwitchPhase::ServerReconciling | SwitchPhase::AuthResuming
            )
        || journal.retry.as_ref().is_some_and(|retry| {
            !(1..=32).contains(&retry.attempt)
                || !(1..=30).contains(&retry.retry_after_seconds)
                || retry.retry_not_before_unix_ms == 0
        })
        || matches!(
            journal.phase,
            SwitchPhase::AuthResuming | SwitchPhase::Complete
        ) != (journal.resume_operation_id.is_some() && journal.decision.is_some())
    {
        return Err(SwitchJournalError::Invalid);
    }
    if let Some(snapshot) = &journal.runtime_snapshot {
        validate_runtime_snapshot(journal, snapshot)?;
    }
    if matches!(
        journal.phase,
        SwitchPhase::LocalStopped
            | SwitchPhase::ServerReconciling
            | SwitchPhase::AuthResuming
            | SwitchPhase::Complete
    ) {
        let receipt = journal
            .local_stop_receipt
            .as_ref()
            .ok_or(SwitchJournalError::Invalid)?;
        let snapshot = journal
            .runtime_snapshot
            .as_ref()
            .ok_or(SwitchJournalError::Invalid)?;
        if receipt.operation_id != journal.operation_id
            || receipt.source_scope_fingerprint != journal.source_scope_fingerprint
            || receipt.runtime_slot != snapshot.slot
            || receipt.runtime_version != snapshot.runtime_version
        {
            return Err(SwitchJournalError::Invalid);
        }
    } else if journal.local_stop_receipt.is_some() {
        return Err(SwitchJournalError::Invalid);
    }
    Ok(())
}

fn validate_runtime_snapshot(
    journal: &SwitchJournalV1,
    snapshot: &RuntimeCleanupSnapshotV1,
) -> Result<(), SwitchJournalError> {
    if snapshot.runtime_version.is_empty()
        || snapshot.runtime_version.len() > 64
        || snapshot.operations.iter().any(|operation| {
            operation.request_fingerprint.is_some() != operation.contract_version.is_some()
        })
    {
        return Err(SwitchJournalError::Invalid);
    }
    let projected =
        CleanupEnvelopeV1::from_runtime_snapshot(snapshot, CleanupEngineRoleV1::Primary, None)
            .map_err(|_| SwitchJournalError::Invalid)?;
    if projected != journal.cleanup_envelope {
        return Err(SwitchJournalError::Invalid);
    }
    match (&journal.source_identity, &snapshot.auth_scope) {
        (None, None) if snapshot.cleanup_only => {}
        (Some(identity), Some(scope)) if !snapshot.cleanup_only => {
            scope.validate().map_err(|_| SwitchJournalError::Invalid)?;
            if &scope.identity != identity
                || snapshot.slot != identity.slot
                || snapshot.runtime_version != identity.runtime_version
            {
                return Err(SwitchJournalError::Invalid);
            }
            let fingerprint = digest_json(&serde_json::json!({
                "auth_epoch": scope.auth_epoch,
                "family": scope.family,
                "identity": identity,
                "device_id": journal.source_device_id,
            }))
            .map_err(|_| SwitchJournalError::Invalid)?;
            if fingerprint != journal.source_scope_fingerprint {
                return Err(SwitchJournalError::Invalid);
            }
        }
        _ => return Err(SwitchJournalError::Invalid),
    }
    Ok(())
}

fn validate_new_target(
    journal: &SwitchJournalV1,
    manifest: &VerifiedContainerManifest,
) -> Result<(), SwitchJournalError> {
    let selected = manifest
        .identity(journal.target_identity.runtime_slot, None)
        .map_err(|_| SwitchJournalError::Invalid)?;
    if RuntimeTarget::from_identity(&selected) != journal.target_identity {
        return Err(SwitchJournalError::Invalid);
    }
    Ok(())
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}
