//! Owner-locked runtime preference recovery. A missing preference remains
//! provisional until real protected storage startup proves a fresh or legacy
//! installation; manifest trust is always established first.
use crate::installed_runtime::{blocked, read_bounded, verify_installed_manifest};
use nelomai_client_api::RuntimeTarget;
use nelomai_client_storage::{
    prepare_runtime_storage, ContainerOwnerLock, PreparedRuntimeStorage, ProtectedRecordFactory,
    StorageError,
};
use nelomai_contracts::{RuntimeSlot, VerifiedContainerManifest};
use serde::{Deserialize, Serialize};
use std::{fs, io, io::Write, path::Path};

const SELECTION_SCHEMA_VERSION: u32 = 1;
const MAX_SELECTION_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotSelectionV1 {
    pub container_version: String,
    pub selected_slot: RuntimeSlot,
    pub pending_slot: Option<RuntimeSlot>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSlotSelectionV1 {
    schema_version: u32,
    container_version: String,
    selected_slot: RuntimeSlot,
    pending_slot: Option<RuntimeSlot>,
}

impl SlotSelectionV1 {
    pub fn to_persisted_bytes(&self) -> io::Result<Vec<u8>> {
        validate_basic_selection(self)?;
        serde_json::to_vec(&StoredSlotSelectionV1 {
            schema_version: SELECTION_SCHEMA_VERSION,
            container_version: self.container_version.clone(),
            selected_slot: self.selected_slot,
            pending_slot: self.pending_slot,
        })
        .map_err(|_| blocked())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionRecovery {
    ContainerVersionChanged,
    InvalidSelection,
    UnavailableSlot(RuntimeSlot),
}

pub struct InstalledRuntimeSelection {
    manifest: VerifiedContainerManifest,
    state: SlotSelectionV1,
    target: RuntimeTarget,
    recovery: Option<SelectionRecovery>,
}

pub struct PreparedInstalledRuntimeSelection {
    root: std::path::PathBuf,
    path: std::path::PathBuf,
    manifest: VerifiedContainerManifest,
    state: SlotSelectionV1,
    recovery: Option<SelectionRecovery>,
    persist_after_storage: bool,
    missing_selection: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum SelectionStartupError {
    #[error("runtime selection I/O failed")]
    Io(#[from] io::Error),
    #[error("runtime protected storage startup failed")]
    Storage(#[from] StorageError),
}

impl InstalledRuntimeSelection {
    /// Compatibility entry point for callers that already have a durable
    /// selection. Missing selection remains an error because this path has no
    /// protected-storage evidence with which to authorize initialization.
    pub fn load(
        resources: &Path,
        selection: &Path,
        pinned_raw_key: Option<&[u8]>,
        platform: &str,
        architecture: &str,
    ) -> io::Result<Self> {
        let manifest =
            verify_installed_manifest(resources, pinned_raw_key, platform, architecture)?;
        let bytes = read_bounded(selection, MAX_SELECTION_BYTES)?;
        let (state, recovery) = recover_bytes(&manifest, &bytes);
        from_verified(manifest, state, recovery)
    }

    /// Actual owner startup path. No selection bytes are written here.
    pub fn prepare(
        resources: &Path,
        owner: &ContainerOwnerLock,
        pinned_raw_key: Option<&[u8]>,
        platform: &str,
        architecture: &str,
    ) -> io::Result<PreparedInstalledRuntimeSelection> {
        let manifest =
            verify_installed_manifest(resources, pinned_raw_key, platform, architecture)?;
        let path = owner.root().join("common/runtime-selection-v1.json");
        let (state, recovery, persist_after_storage, missing_selection) =
            match read_optional_bounded(&path, MAX_SELECTION_BYTES)? {
                Some(bytes) => {
                    let (state, recovery) = recover_bytes(&manifest, &bytes);
                    (state, recovery, recovery.is_some(), false)
                }
                None => (latest_selection(&manifest), None, true, true),
            };
        Ok(PreparedInstalledRuntimeSelection {
            root: owner.root().to_owned(),
            path,
            manifest,
            state,
            recovery,
            persist_after_storage,
            missing_selection,
        })
    }

    pub fn manifest(&self) -> &VerifiedContainerManifest {
        &self.manifest
    }

    pub fn state(&self) -> &SlotSelectionV1 {
        &self.state
    }

    pub fn target(&self) -> &RuntimeTarget {
        &self.target
    }

    pub fn recovery(&self) -> Option<&SelectionRecovery> {
        self.recovery.as_ref()
    }
}

impl PreparedInstalledRuntimeSelection {
    pub fn storage_slot(&self) -> RuntimeSlot {
        self.state.selected_slot
    }

    pub fn recovery(&self) -> Option<&SelectionRecovery> {
        self.recovery.as_ref()
    }

    pub fn requires_storage_confirmation(&self) -> bool {
        self.missing_selection
    }

    /// The sole initialization finalizer: actual protected inventory/migration
    /// must complete under the same container owner before the preference can
    /// become durable.
    pub fn prepare_runtime_storage<F: ProtectedRecordFactory>(
        self,
        owner: &ContainerOwnerLock,
        records: &F,
    ) -> Result<(InstalledRuntimeSelection, PreparedRuntimeStorage<F::Record>), SelectionStartupError>
    {
        if owner.root() != self.root {
            return Err(io::Error::other("runtime selection owner changed").into());
        }
        let storage =
            prepare_runtime_storage(owner, &self.manifest, self.state.selected_slot, records)?;
        if self.persist_after_storage {
            atomic_nonsecret_write(&self.path, &self.state.to_persisted_bytes()?)?;
        }
        Ok((
            from_verified(self.manifest, self.state, self.recovery)?,
            storage,
        ))
    }
}

pub(crate) fn set_pending_selection(
    owner: &ContainerOwnerLock,
    manifest: &VerifiedContainerManifest,
    pending: RuntimeSlot,
) -> io::Result<()> {
    update_selection(owner, manifest, |state| {
        state.pending_slot = (state.selected_slot != pending).then_some(pending);
    })
}

pub(crate) fn finish_selection(
    owner: &ContainerOwnerLock,
    manifest: &VerifiedContainerManifest,
    selected: RuntimeSlot,
) -> io::Result<()> {
    update_selection(owner, manifest, |state| {
        state.selected_slot = selected;
        state.pending_slot = None;
    })
}

pub(crate) fn current_selection(
    owner: &ContainerOwnerLock,
    manifest: &VerifiedContainerManifest,
) -> io::Result<SlotSelectionV1> {
    let _guard = owner.lock_transition_journal()?;
    let path = owner.root().join("common/runtime-selection-v1.json");
    let bytes = read_bounded(&path, MAX_SELECTION_BYTES)?;
    let stored: StoredSlotSelectionV1 = serde_json::from_slice(&bytes).map_err(|_| blocked())?;
    let state = SlotSelectionV1 {
        container_version: stored.container_version,
        selected_slot: stored.selected_slot,
        pending_slot: stored.pending_slot,
    };
    if stored.schema_version != SELECTION_SCHEMA_VERSION
        || state.container_version != manifest.manifest().container_version
        || manifest.selected(state.selected_slot).is_none()
        || state
            .pending_slot
            .is_some_and(|slot| manifest.selected(slot).is_none())
    {
        return Err(blocked());
    }
    Ok(state)
}

fn update_selection(
    owner: &ContainerOwnerLock,
    manifest: &VerifiedContainerManifest,
    change: impl FnOnce(&mut SlotSelectionV1),
) -> io::Result<()> {
    let _guard = owner.lock_transition_journal()?;
    let path = owner.root().join("common/runtime-selection-v1.json");
    let bytes = read_bounded(&path, MAX_SELECTION_BYTES)?;
    let stored: StoredSlotSelectionV1 = serde_json::from_slice(&bytes).map_err(|_| blocked())?;
    let mut state = SlotSelectionV1 {
        container_version: stored.container_version,
        selected_slot: stored.selected_slot,
        pending_slot: stored.pending_slot,
    };
    if stored.schema_version != SELECTION_SCHEMA_VERSION
        || state.container_version != manifest.manifest().container_version
        || manifest.selected(state.selected_slot).is_none()
    {
        return Err(blocked());
    }
    change(&mut state);
    validate_basic_selection(&state)?;
    if manifest.selected(state.selected_slot).is_none()
        || state
            .pending_slot
            .is_some_and(|slot| manifest.selected(slot).is_none())
    {
        return Err(blocked());
    }
    atomic_nonsecret_write(&path, &state.to_persisted_bytes()?)
}

fn from_verified(
    manifest: VerifiedContainerManifest,
    state: SlotSelectionV1,
    recovery: Option<SelectionRecovery>,
) -> io::Result<InstalledRuntimeSelection> {
    let identity = manifest
        .identity(state.selected_slot, None)
        .map_err(|_| blocked())?;
    Ok(InstalledRuntimeSelection {
        manifest,
        state,
        target: RuntimeTarget::from_identity(&identity),
        recovery,
    })
}

fn latest_selection(manifest: &VerifiedContainerManifest) -> SlotSelectionV1 {
    SlotSelectionV1 {
        container_version: manifest.manifest().container_version.clone(),
        selected_slot: RuntimeSlot::Latest,
        pending_slot: None,
    }
}

fn recover_bytes(
    manifest: &VerifiedContainerManifest,
    bytes: &[u8],
) -> (SlotSelectionV1, Option<SelectionRecovery>) {
    let stored: StoredSlotSelectionV1 = match serde_json::from_slice(bytes) {
        Ok(stored) => stored,
        Err(_) => {
            return (
                latest_selection(manifest),
                Some(SelectionRecovery::InvalidSelection),
            )
        }
    };
    let state = SlotSelectionV1 {
        container_version: stored.container_version,
        selected_slot: stored.selected_slot,
        pending_slot: stored.pending_slot,
    };
    if stored.schema_version != SELECTION_SCHEMA_VERSION
        || validate_basic_selection(&state).is_err()
    {
        return (
            latest_selection(manifest),
            Some(SelectionRecovery::InvalidSelection),
        );
    }
    if state.container_version != manifest.manifest().container_version {
        return (
            latest_selection(manifest),
            Some(SelectionRecovery::ContainerVersionChanged),
        );
    }
    if manifest.selected(state.selected_slot).is_none() {
        return (
            latest_selection(manifest),
            Some(SelectionRecovery::UnavailableSlot(state.selected_slot)),
        );
    }
    if let Some(pending) = state.pending_slot {
        if manifest.selected(pending).is_none() {
            return (
                latest_selection(manifest),
                Some(SelectionRecovery::UnavailableSlot(pending)),
            );
        }
    }
    (state, None)
}

fn validate_basic_selection(state: &SlotSelectionV1) -> io::Result<()> {
    if state.container_version.is_empty()
        || state.container_version.len() > 64
        || state.pending_slot == Some(state.selected_slot)
    {
        return Err(blocked());
    }
    Ok(())
}

fn read_optional_bounded(path: &Path, max: usize) -> io::Result<Option<Vec<u8>>> {
    match fs::metadata(path) {
        Ok(metadata) if !metadata.is_file() || metadata.len() > max as u64 => Ok(Some(Vec::new())),
        Ok(_) => read_bounded(path, max).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) fn atomic_nonsecret_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("runtime journal has no parent"))?;
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    temporary.write_all(bytes)?;
    temporary.as_file_mut().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
