//! Actual runtime/lock/storage/native-name gate for retained registry key IO.
//! This does NOT authorize DLL loading, driver maintenance or NIC adoption.
//! Factory remains disabled; original creator inventory must be composed by it.
#![allow(dead_code)]

use super::member_carrier_keys::{effect_matches_storage, Effect, NativeAuthority};
use super::member_session::{NativeSessionFiles, RecordKind, SessionFiles};
use crate::member_carrier::{CarrierError as Error, Result};
use crate::member_carrier_native_ownership::{Binding, Context, Record};
use nelomai_contracts::dispatcher::{EngineIdentity, Installation, MutationGuard};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIfTable2, MIB_IF_ROW2, MIB_IF_TABLE2,
};

/// Must inspect the actual retained original-creator capabilities under the
/// SAME engine-owner lease. Absence of journal proofs or native name lookup
/// alone is not absence of live creator handles. No successful default exists.
pub(crate) trait OriginalCreatorInventory {
    fn assert_absent(&mut self, context: &Context, binding: &Binding) -> Result<()>;
}

static KEY_MUTATIONS: Mutex<()> = Mutex::new(());

/// Borrow of an actual held file lock, not a lock bit, path or serialized token.
/// Its constructor is private; only the independently authenticated owner below
/// returns it. Keeping an Arc alive retains the same private locked File.
pub(crate) struct KeyLock {
    owner: Arc<MutationGuard>,
    // No Clone or Send: one actual process-wide borrow, held across all key
    // inspections/effects and the before_adapter_create receipt borrow.
    _serialized: MutexGuard<'static, ()>,
}
pub(crate) struct KeyAuthority<I> {
    context: Context,
    identity: EngineIdentity,
    directory: PathBuf,
    executable: PathBuf,
    installation: Installation,
    owner: Arc<MutationGuard>,
    pin: Box<dyn Fn() -> Result<()>>,
    files: NativeSessionFiles,
    originals: I,
}

impl<I: OriginalCreatorInventory> KeyAuthority<I> {
    /// No caller-supplied engine identity or executable is accepted as proof.
    /// The expected Context comes from validated pair intent; actual runtime,
    /// boot/epoch and scope claim are independently checked before use.
    pub(crate) fn new(
        root: &Path,
        owner: Arc<MutationGuard>,
        files: NativeSessionFiles,
        context: Context,
        originals: I,
    ) -> Result<(Self, KeyLock)> {
        let serialized = KEY_MUTATIONS.try_lock().map_err(|_| Error::Conflict)?;
        owner
            .verify_at(&root.join("engine-owner.lock"))
            .map_err(|_| Error::Conflict)?;
        let pinned =
            super::member_files::pin_private_directory(root).map_err(|_| Error::Conflict)?;
        let installation = Installation::production(root).map_err(|_| Error::Conflict)?;
        let executable = actual_executable()?;
        let layout = installation
            .load_engine(&executable)
            .map_err(|_| Error::Conflict)?;
        let mut authority = Self {
            context,
            identity: layout.identity,
            directory: layout.directory,
            executable,
            installation,
            owner: owner.clone(),
            pin: Box::new(move || pinned.verify().map_err(|_| Error::Conflict)),
            files,
            originals,
        };
        let mut lock = KeyLock {
            owner,
            _serialized: serialized,
        };
        let context = authority.context.clone();
        authority.verify(&mut lock, &context)?;
        Ok((authority, lock))
    }
    fn runtime(&self, lock: &KeyLock, context: &Context) -> Result<()> {
        if *context != self.context
            || !Arc::ptr_eq(&lock.owner, &self.owner)
            || context.provenance.runtime != self.identity
        {
            return Err(Error::Conflict);
        }
        self.owner
            .verify_at(&self.installation.root.join("engine-owner.lock"))
            .map_err(|_| Error::Conflict)?;
        (self.pin)()?;
        if actual_executable()? != self.executable
            || super::member_boot::boot_id().map_err(|_| Error::Native)?
                != context.provenance.boot_id
        {
            return Err(Error::Conflict);
        }
        // Reauthenticate actual installed signatures and every runtime payload
        // hash; this is deliberately not dispatcher::trusted() on a path.
        // It does not pin/load a DLL and grants no module/driver authority.
        let live = self
            .installation
            .load_engine(&self.executable)
            .map_err(|_| Error::Conflict)?;
        if live.identity != self.identity
            || live.directory != self.directory
            || std::fs::canonicalize(live.engine_path()).map_err(|_| Error::Native)?
                != self.executable
        {
            return Err(Error::Conflict);
        }
        (self.pin)()?;
        self.owner
            .verify_at(&self.installation.root.join("engine-owner.lock"))
            .map_err(|_| Error::Conflict)
    }
}
fn actual_executable() -> Result<PathBuf> {
    std::fs::canonicalize(std::env::current_exe().map_err(|_| Error::Native)?)
        .map_err(|_| Error::Native)
}
impl<I: OriginalCreatorInventory> NativeAuthority for KeyAuthority<I> {
    type Lock = KeyLock;
    fn verify(&mut self, lock: &mut KeyLock, context: &Context) -> Result<()> {
        self.runtime(lock, context)?;
        self.files
            .native_carrier_access(&context.intent.scope)
            .map_err(|_| Error::Journal)?
            .require_native_context(context)
            .map_err(|_| Error::Conflict)?;
        self.runtime(lock, context)
    }
    fn authorize_effect(
        &mut self,
        lock: &mut KeyLock,
        pending: &Record,
        binding: &Binding,
        effect: Effect,
    ) -> Result<()> {
        self.verify(lock, &pending.context)?;
        let access = self
            .files
            .native_carrier_access(&pending.context.intent.scope)
            .map_err(|_| Error::Journal)?;
        access
            .require_native_context(&pending.context)
            .map_err(|_| Error::Conflict)?;
        let bytes = self
            .files
            .read(
                &pending.context.intent.scope,
                RecordKind::NativeCarrierReceipts,
            )
            .map_err(|_| Error::Journal)?
            .ok_or(Error::Journal)?;
        let actual = Record::decode(&bytes)?;
        effect_matches_storage(pending, binding, effect, &actual, access.is_fresh())?;
        self.originals.assert_absent(&pending.context, binding)?;
        self.verify(lock, &pending.context)?;
        // Runtime hashing/boot queries may take time. Re-read the protected
        // permission and exact pending bytes LAST before returning authority.
        // The held engine lease + key mutex serialize cooperating key actors;
        // Task5 must also serialize other lifecycle/storage writers under the
        // enclosing engine actor. This is not a kernel atomic registry CAS.
        let access = self
            .files
            .native_carrier_access(&pending.context.intent.scope)
            .map_err(|_| Error::Journal)?;
        access
            .require_native_context(&pending.context)
            .map_err(|_| Error::Conflict)?;
        let bytes = self
            .files
            .read(
                &pending.context.intent.scope,
                RecordKind::NativeCarrierReceipts,
            )
            .map_err(|_| Error::Journal)?
            .ok_or(Error::Journal)?;
        let actual = Record::decode(&bytes)?;
        effect_matches_storage(pending, binding, effect, &actual, access.is_fresh())?;
        self.originals.assert_absent(&pending.context, binding)?;
        let absence = native_absence(binding)?;
        if absence != (true, true) {
            return Err(Error::Conflict);
        }
        self.originals.assert_absent(&pending.context, binding)?;
        self.owner
            .verify_at(&self.installation.root.join("engine-owner.lock"))
            .map_err(|_| Error::Conflict)
    }
    fn nic_absence(
        &mut self,
        lock: &mut KeyLock,
        context: &Context,
        binding: &Binding,
    ) -> Result<(bool, bool, bool)> {
        self.verify(lock, context)?;
        if !context.bindings.contains(binding) {
            return Err(Error::Conflict);
        }
        self.originals.assert_absent(context, binding)?;
        let (name_absent, guid_absent) = native_absence(binding)?;
        // Check retained creators again after the bounded native inventory.
        // There is no reconstruction from a numeric index or saved JSON.
        self.originals.assert_absent(context, binding)?;
        self.verify(lock, context)?;
        Ok((name_absent, guid_absent, true))
    }
}
fn native_absence(binding: &Binding) -> Result<(bool, bool)> {
    struct Table(*mut MIB_IF_TABLE2);
    impl Drop for Table {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    FreeMibTable(self.0.cast());
                }
            }
        }
    }
    let mut table = Table(std::ptr::null_mut());
    if unsafe { GetIfTable2(&mut table.0) } != 0 || table.0.is_null() {
        return Err(Error::Native);
    }
    let count = unsafe { (*table.0).NumEntries } as usize;
    if count > 4096 {
        return Err(Error::Invalid);
    }
    let rows = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*table.0).Table).cast::<MIB_IF_ROW2>(),
            count,
        )
    };
    let mut name_absent = true;
    let mut guid_absent = true;
    for row in rows {
        let end = row
            .Alias
            .iter()
            .position(|c| *c == 0)
            .ok_or(Error::Invalid)?;
        let alias = String::from_utf16(&row.Alias[..end]).map_err(|_| Error::Invalid)?;
        let guid = &row.InterfaceGuid;
        let mut bytes = [0; 16];
        bytes[..4].copy_from_slice(&guid.data1.to_be_bytes());
        bytes[4..6].copy_from_slice(&guid.data2.to_be_bytes());
        bytes[6..8].copy_from_slice(&guid.data3.to_be_bytes());
        bytes[8..].copy_from_slice(&guid.data4);
        name_absent &= !alias.eq_ignore_ascii_case(&binding.name);
        guid_absent &= bytes != binding.guid;
    }
    Ok((name_absent, guid_absent))
}
