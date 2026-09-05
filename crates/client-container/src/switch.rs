//! Durable nonsecret switch ownership. Network/auth/stop execution is added by
//! later checkpoints; this foundation only creates and reloads Requested work.
use crate::{atomic_nonsecret_write, valid_fingerprint, CleanupEnvelopeV1};
use nelomai_client_api::RuntimeTarget;
use nelomai_client_storage::ContainerOwnerLock;
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
    phase: SwitchPhase,
    resume_operation_id: Option<String>,
    decision: Option<SwitchDecision>,
    retry: Option<SwitchRetryV1>,
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
            phase: SwitchPhase::Requested,
            resume_operation_id: None,
            decision: None,
            retry: None,
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
        };
        coordinator.snapshot()?;
        Ok(coordinator)
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
            retry.attempt == 0 || !(1..=30).contains(&retry.retry_after_seconds)
        })
        || matches!(
            journal.phase,
            SwitchPhase::AuthResuming | SwitchPhase::Complete
        ) != (journal.resume_operation_id.is_some() && journal.decision.is_some())
    {
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
