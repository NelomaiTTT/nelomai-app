//! Durable nonsecret switch ownership. Network/auth/stop execution is added by
//! later checkpoints; this foundation only creates and reloads Requested work.
use crate::{
    atomic_nonsecret_write, valid_fingerprint, AuthBroker, BrokerError, CleanupEngineRoleV1,
    CleanupEnvelopeV1, FrozenReconcileRequest, ResumeArguments,
};
use async_trait::async_trait;
use nelomai_client_api::{
    AccessSnapshot, RuntimeSwitchReconcileRequest, RuntimeSwitchState, RuntimeTarget,
};
use nelomai_client_storage::{ContainerOwnerLock, RuntimeCleanupSnapshotV1};
use nelomai_contracts::{RuntimeIdentity, VerifiedContainerManifest};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{self, Read},
    path::PathBuf,
    sync::Arc,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchProgress {
    Ready,
    Pending { retry_after_seconds: u32 },
}

#[async_trait]
pub trait RuntimeSwitchControl: Send + Sync {
    async fn handoff_cleanup(
        &self,
        source: &crate::TransitionSourceSnapshot,
    ) -> Result<RuntimeCleanupSnapshotV1, BrokerError>;
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
    broker: Option<Arc<AuthBroker>>,
    control: Option<Arc<dyn RuntimeSwitchControl>>,
    execution: tokio::sync::Mutex<()>,
}

impl SwitchCoordinator {
    /// Retains the common container owner lock for the coordinator's lifetime.
    /// The fixed path prevents a second public switch journal.
    pub fn open(
        owner: Arc<ContainerOwnerLock>,
        manifest: VerifiedContainerManifest,
    ) -> Result<Self, SwitchJournalError> {
        let coordinator = Self {
            path: owner.root().join("common/runtime-switch-v1.json"),
            owner,
            manifest,
            broker: None,
            control: None,
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

    pub async fn request(
        &self,
        target_slot: nelomai_contracts::RuntimeSlot,
    ) -> Result<SwitchProgress, SwitchError> {
        let _execution = self.execution.lock().await;
        if self
            .snapshot()?
            .is_some_and(|journal| journal.phase != SwitchPhase::Complete)
        {
            return Err(SwitchJournalError::Pending.into());
        }
        let (broker, control) = self.components()?;
        let source = broker.transition_source().await?;
        let runtime_snapshot = control.handoff_cleanup(&source).await?;
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
        self.update(|journal| journal.phase = SwitchPhase::CleanupHandedOff)?;
        self.recover_locked(broker, control).await
    }

    pub async fn recover(&self) -> Result<SwitchProgress, SwitchError> {
        let _execution = self.execution.lock().await;
        let (broker, control) = self.components()?;
        self.recover_locked(broker, control).await
    }

    pub async fn before_tunnel_start(&self) -> Result<(), SwitchError> {
        match self.recover().await? {
            SwitchProgress::Ready => Ok(()),
            SwitchProgress::Pending { .. } => Err(SwitchError::RecoveryRequired),
        }
    }

    pub async fn cancel_pending(&self) -> Result<SwitchProgress, SwitchError> {
        let _execution = self.execution.lock().await;
        let (broker, control) = self.components()?;
        self.update(|journal| journal.cancel_requested = true)?;
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
            let snapshot = journal
                .runtime_snapshot
                .as_ref()
                .ok_or(SwitchError::RecoveryRequired)?;
            match journal.phase {
                SwitchPhase::Requested => {
                    let source = broker.transition_source().await?;
                    if !source.matches_runtime_scope(snapshot.auth_scope.as_ref())
                        || control.handoff_cleanup(&source).await? != *snapshot
                    {
                        return Err(SwitchError::RecoveryRequired);
                    }
                    self.update(|journal| journal.phase = SwitchPhase::CleanupHandedOff)?;
                }
                SwitchPhase::CleanupHandedOff => {
                    self.update(|journal| journal.phase = SwitchPhase::RuntimeStopping)?;
                }
                SwitchPhase::RuntimeStopping => {
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
                            Ok(result) => {
                                result?;
                                false
                            }
                            Err(_) => {
                                self.update(|journal| journal.force_stop_requested = true)?;
                                control.force_stop(&journal.operation_id, snapshot).await?;
                                true
                            }
                        }
                    };
                    let receipt = LocalStopReceiptV1 {
                        operation_id: journal.operation_id.clone(),
                        source_scope_fingerprint: journal.source_scope_fingerprint.clone(),
                        runtime_slot: snapshot.slot,
                        runtime_version: snapshot.runtime_version.clone(),
                        forced,
                    };
                    self.update(|journal| {
                        journal.local_stop_receipt = Some(receipt);
                        journal.phase = SwitchPhase::LocalStopped;
                    })?;
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
                    let receipt = broker.reconcile_transition(frozen).await?;
                    if receipt.state == RuntimeSwitchState::Retry {
                        let attempt = journal.retry.as_ref().map_or(1, |retry| retry.attempt + 1);
                        let exponential = 1_u32
                            .checked_shl((attempt - 1).min(5))
                            .unwrap_or(30)
                            .min(30);
                        let delay = receipt
                            .retry_after_seconds
                            .unwrap_or(exponential)
                            .max(exponential)
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
                        .resume_transition(ResumeArguments {
                            operation_id: journal
                                .resume_operation_id
                                .clone()
                                .ok_or(SwitchError::RecoveryRequired)?,
                            reconcile_operation_id: journal.operation_id.clone(),
                            decision: match decision {
                                SwitchDecision::Apply => "apply",
                                SwitchDecision::Cancel => "cancel",
                            }
                            .into(),
                            target,
                            expected_session_generation: journal.expected_session_generation,
                        })
                        .await?;
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
                    self.update(|journal| journal.phase = SwitchPhase::Complete)?;
                }
                SwitchPhase::Complete => return Ok(SwitchProgress::Ready),
            }
        }
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

impl SwitchJournalV1 {
    fn reconcile_request(&self) -> RuntimeSwitchReconcileRequest {
        RuntimeSwitchReconcileRequest {
            operation_id: self.operation_id.clone(),
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
        || journal.retry.as_ref().is_some_and(|retry| {
            retry.attempt == 0
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
        if snapshot.runtime_version.is_empty()
            || snapshot.runtime_version.len() > 64
            || snapshot.operations.iter().any(|operation| {
                operation.request_fingerprint.is_some() != operation.contract_version.is_some()
            })
        {
            return Err(SwitchJournalError::Invalid);
        }
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
