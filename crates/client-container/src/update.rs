use crate::{
    atomic_nonsecret_write, SwitchCoordinator, SwitchError, SwitchJournalError, SwitchPhase,
};
use nelomai_client_storage::ContainerOwnerLock;
use nelomai_contracts::{RuntimeIdentity, RuntimeSlot};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{self, Read},
    path::PathBuf,
    sync::Arc,
};

const UPDATE_SCHEMA_VERSION: u32 = 1;
const MAX_UPDATE_JOURNAL_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateJournalPhase {
    Requested,
    LocalStopped,
    InstallerOpened,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateJournalV1 {
    schema_version: u32,
    operation_id: String,
    source_container: String,
    source_runtime: RuntimeIdentity,
    target_container: String,
    previous_slot: RuntimeSlot,
    phase: UpdateJournalPhase,
}

impl UpdateJournalV1 {
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn source_container(&self) -> &str {
        &self.source_container
    }

    pub fn source_runtime(&self) -> &RuntimeIdentity {
        &self.source_runtime
    }

    pub fn target_container(&self) -> &str {
        &self.target_container
    }

    pub fn previous_slot(&self) -> RuntimeSlot {
        self.previous_slot
    }

    pub fn phase(&self) -> UpdateJournalPhase {
        self.phase
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdatePrepare {
    LocalStopped,
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateBarrierError {
    #[error("update journal I/O failed")]
    Io(#[from] io::Error),
    #[error("update journal requires recovery")]
    Invalid,
    #[error("another update is pending")]
    Pending,
    #[error(transparent)]
    Switch(#[from] SwitchError),
}

pub struct UpdateBarrier {
    coordinator: Arc<SwitchCoordinator>,
    owner: Arc<ContainerOwnerLock>,
    path: PathBuf,
    operation: tokio::sync::Mutex<()>,
}

impl UpdateBarrier {
    pub fn open(coordinator: Arc<SwitchCoordinator>) -> Result<Self, UpdateBarrierError> {
        let owner = coordinator.owner_lock();
        let barrier = Self {
            path: owner.root().join("common/update-journal-v1.json"),
            coordinator,
            owner,
            operation: tokio::sync::Mutex::new(()),
        };
        if let Some(journal) = barrier.snapshot()? {
            barrier.validate_switch_link(&journal)?;
        }
        Ok(barrier)
    }

    pub fn snapshot(&self) -> Result<Option<UpdateJournalV1>, UpdateBarrierError> {
        let _guard = self.owner.lock_transition_journal()?;
        load_journal(&self.path)
    }

    pub async fn prepare(&self, target_version: &str) -> Result<UpdatePrepare, UpdateBarrierError> {
        let _operation = self.operation.lock().await;
        validate_version(target_version)?;
        let current_container = self.coordinator.installed_container_version();
        if target_version == current_container {
            return Err(UpdateBarrierError::Invalid);
        }
        let existing = self.snapshot()?;
        if let Some(journal) = &existing {
            if journal.source_container != current_container
                || journal.target_container != target_version
            {
                return Err(UpdateBarrierError::Pending);
            }
            self.validate_switch_link(journal)?;
            if matches!(
                journal.phase,
                UpdateJournalPhase::LocalStopped | UpdateJournalPhase::InstallerOpened
            ) {
                return Ok(UpdatePrepare::LocalStopped);
            }
        }
        let expected = existing
            .as_ref()
            .map(|journal| journal.operation_id.as_str());
        let requested_target = target_version.to_owned();
        let result = self
            .coordinator
            .prepare_update_stop(expected, |switch, previous_slot| {
                let source_runtime = switch
                    .source_identity()
                    .cloned()
                    .ok_or(SwitchError::RecoveryRequired)?;
                let journal = UpdateJournalV1 {
                    schema_version: UPDATE_SCHEMA_VERSION,
                    operation_id: switch.operation_id().to_owned(),
                    source_container: source_runtime.container_version.clone(),
                    source_runtime,
                    target_container: requested_target,
                    previous_slot,
                    phase: UpdateJournalPhase::Requested,
                };
                self.replace(&journal)
                    .map_err(|_| SwitchError::RecoveryRequired)
            })
            .await;
        let stopped = match result {
            Ok(stopped) => stopped,
            Err(error) => {
                if self.coordinator.snapshot().is_ok_and(|journal| {
                    journal.is_none_or(|journal| journal.phase() == SwitchPhase::Complete)
                }) {
                    let _ = self.remove();
                }
                return Err(error.into());
            }
        };
        let mut journal = self.snapshot()?.ok_or(UpdateBarrierError::Invalid)?;
        self.validate_switch_link(&journal)?;
        if journal.operation_id != stopped.operation_id()
            || stopped.phase() != SwitchPhase::LocalStopped
        {
            return Err(UpdateBarrierError::Invalid);
        }
        journal.phase = UpdateJournalPhase::LocalStopped;
        self.replace(&journal)?;
        Ok(UpdatePrepare::LocalStopped)
    }

    pub async fn installer_opened(&self) -> Result<(), UpdateBarrierError> {
        let _operation = self.operation.lock().await;
        let mut journal = self.snapshot()?.ok_or(UpdateBarrierError::Invalid)?;
        if !matches!(
            journal.phase,
            UpdateJournalPhase::LocalStopped | UpdateJournalPhase::InstallerOpened
        ) {
            return Err(UpdateBarrierError::Invalid);
        }
        journal.phase = UpdateJournalPhase::InstallerOpened;
        self.replace(&journal)
    }

    pub async fn installer_failed(&self) -> Result<(), UpdateBarrierError> {
        let _operation = self.operation.lock().await;
        self.installer_failed_locked().await
    }

    async fn installer_failed_locked(&self) -> Result<(), UpdateBarrierError> {
        let Some(journal) = self.snapshot()? else {
            return Ok(());
        };
        if self.coordinator.installed_container_version() != journal.source_container {
            return Err(UpdateBarrierError::Invalid);
        }
        self.coordinator
            .cancel_update_stop(&journal.operation_id)
            .await?;
        self.coordinator
            .restore_update_selection(journal.previous_slot)?;
        self.remove()
    }

    pub async fn recover(
        &self,
        installed_container_version: &str,
    ) -> Result<(), UpdateBarrierError> {
        let _operation = self.operation.lock().await;
        let Some(journal) = self.snapshot()? else {
            return Ok(());
        };
        if installed_container_version != self.coordinator.installed_container_version() {
            return Err(UpdateBarrierError::Invalid);
        }
        if installed_container_version == journal.source_container {
            return self.installer_failed_locked().await;
        }
        if installed_container_version != journal.target_container {
            return Err(UpdateBarrierError::Invalid);
        }
        self.coordinator.recover_installed_update().await?;
        self.remove()
    }

    fn replace(&self, journal: &UpdateJournalV1) -> Result<(), UpdateBarrierError> {
        let _guard = self.owner.lock_transition_journal()?;
        validate_journal(journal)?;
        let bytes = serde_json::to_vec(journal).map_err(|_| UpdateBarrierError::Invalid)?;
        if bytes.len() > MAX_UPDATE_JOURNAL_BYTES {
            return Err(UpdateBarrierError::Invalid);
        }
        atomic_nonsecret_write(&self.path, &bytes)?;
        Ok(())
    }

    fn validate_switch_link(&self, journal: &UpdateJournalV1) -> Result<(), UpdateBarrierError> {
        let Some(switch) = self.coordinator.snapshot().map_err(SwitchError::Journal)? else {
            return Ok(());
        };
        if switch.phase() == SwitchPhase::Complete {
            return Ok(());
        }
        if switch.operation_id() != journal.operation_id
            || switch.source_identity() != Some(&journal.source_runtime)
            || switch.target_identity()
                != &nelomai_client_api::RuntimeTarget::from_identity(&journal.source_runtime)
            || (matches!(
                journal.phase,
                UpdateJournalPhase::LocalStopped | UpdateJournalPhase::InstallerOpened
            ) && switch.phase() != SwitchPhase::LocalStopped)
        {
            return Err(UpdateBarrierError::Invalid);
        }
        Ok(())
    }

    fn remove(&self) -> Result<(), UpdateBarrierError> {
        let _guard = self.owner.lock_transition_journal()?;
        match std::fs::remove_file(&self.path) {
            Ok(()) => {
                #[cfg(unix)]
                File::open(self.path.parent().ok_or(UpdateBarrierError::Invalid)?)?.sync_all()?;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

pub(crate) fn update_barrier_pending(
    owner: &ContainerOwnerLock,
) -> Result<bool, SwitchJournalError> {
    let _guard = owner.lock_transition_journal()?;
    let path = owner.root().join("common/update-journal-v1.json");
    load_journal(&path)
        .map(|journal| journal.is_some())
        .map_err(|error| match error {
            UpdateBarrierError::Io(error) => SwitchJournalError::Io(error),
            _ => SwitchJournalError::Invalid,
        })
}

fn load_journal(path: &PathBuf) -> Result<Option<UpdateJournalV1>, UpdateBarrierError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    file.take((MAX_UPDATE_JOURNAL_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_UPDATE_JOURNAL_BYTES {
        return Err(UpdateBarrierError::Invalid);
    }
    let journal = serde_json::from_slice(&bytes).map_err(|_| UpdateBarrierError::Invalid)?;
    validate_journal(&journal)?;
    Ok(Some(journal))
}

fn validate_journal(journal: &UpdateJournalV1) -> Result<(), UpdateBarrierError> {
    validate_version(&journal.source_container)?;
    validate_version(&journal.target_container)?;
    if journal.schema_version != UPDATE_SCHEMA_VERSION
        || journal.source_container == journal.target_container
        || journal.source_runtime.container_version != journal.source_container
        || journal.source_runtime.slot != journal.previous_slot
        || journal.source_runtime.validate().is_err()
        || !uuid::Uuid::parse_str(&journal.operation_id)
            .is_ok_and(|operation| operation.to_string() == journal.operation_id)
    {
        return Err(UpdateBarrierError::Invalid);
    }
    Ok(())
}

fn validate_version(version: &str) -> Result<(), UpdateBarrierError> {
    if version.is_empty()
        || version.len() > 64
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(UpdateBarrierError::Invalid);
    }
    Ok(())
}
