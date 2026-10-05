//! Actual runtime/lock/storage/native-name gate for retained registry key IO.
//! This does NOT authorize DLL loading, driver maintenance or NIC adoption.
//! Factory remains disabled; original creator inventory must be composed by it.
#![allow(dead_code)]

use super::member_carrier_keys::{effect_matches_storage, Effect, NativeAuthority};
use super::member_session::{
    epoch::NativeExecutionRoot, NativeSessionFiles, RecordKind, SessionFiles,
};
use crate::member_carrier::{CarrierError as Error, Result};
use crate::member_carrier_native_ownership::{Binding, Context, Record};
use crate::member_serialized_lease::{ReadPin, SerializedLease};
use nelomai_contracts::dispatcher::{EngineIdentity, Installation, MutationGuard};
use std::{
    cell::{Cell, RefCell},
    path::{Path, PathBuf},
    rc::Rc,
    sync::{Arc, Mutex},
};

/// Must inspect the actual retained original-creator capabilities under the
/// SAME engine-owner lease. The complete independent MIB/PnP query checks the
/// target name/GUID on every read, with original handles and current protected
/// revision/runtime/image fenced before/after. Returned booleans are current
/// facts only; neither journal proofs nor name lookup supply a creator ACK.
/// No successful default exists.
pub(crate) trait OriginalCreatorInventory {
    fn inspect_absence(
        &mut self,
        context: &Context,
        binding: &Binding,
    ) -> Result<(bool, bool, bool)>;
}

static KEY_MUTATIONS: Mutex<()> = Mutex::new(());

/// Borrow of an actual held file lock, not a lock bit, path or serialized token.
/// Its constructor is private; only the independently authenticated owner below
/// returns it. BOTH original file lock and actual process-wide MutexGuard stay
/// retained until the canonical lock AND all read-only pins have gone away.
pub(crate) struct KeyLock {
    lease: SerializedLease<'static, Arc<MutationGuard>>,
}
/// No mutable lock/effect API. Created ONLY from a real authenticated KeyLock.
pub(crate) struct KeyLockPin(ReadPin<'static, Arc<MutationGuard>>);
impl KeyLock {
    pub(super) fn pin(&self) -> KeyLockPin {
        KeyLockPin(self.lease.pin())
    }
    pub(super) fn matches_pin(&self, pin: &KeyLockPin) -> bool {
        self.lease.matches(&pin.0)
    }
    pub(super) fn verify_source(
        &self,
        source: &super::member_carrier_payload::native::WintunSource,
    ) -> Result<()> {
        source.verify_owner(self.lease.owner())
    }
}
impl KeyLockPin {
    pub(super) fn read_pin(&self) -> Self {
        Self(self.0.read_pin())
    }
    pub(super) fn verify_source(
        &self,
        source: &super::member_carrier_payload::native::WintunSource,
    ) -> Result<()> {
        source.verify_owner(self.0.owner())
    }
}
struct Runtime {
    context: Context,
    identity: EngineIdentity,
    directory: PathBuf,
    executable: PathBuf,
    installation: Installation,
    owner: Arc<MutationGuard>,
    lease: KeyLockPin,
    pin: Box<dyn Fn() -> Result<()>>,
    files: RefCell<NativeSessionFiles>,
    original_files: NativeSessionFiles,
    execution: RefCell<Option<Rc<NativeExecutionRoot>>>,
    forward_closed: Cell<bool>,
}
/// Fresh, independently authenticated READ-only runtime/context checks. Holds
/// the SAME original serialized guard; cannot authorize native effects or read
/// creator inventory recursively. No constructor from paths/context/JSON.
pub(crate) struct RuntimeRead {
    runtime: Rc<Runtime>,
    lease: KeyLockPin,
}
pub(crate) struct KeyAuthority<I> {
    runtime: Rc<Runtime>,
    files: NativeSessionFiles,
    original_files: NativeSessionFiles,
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
        let (runtime, mut lock) = RuntimeRead::new(root, owner, files, context)?;
        let authority = Self::from_read(&runtime, originals, &mut lock)?;
        Ok((authority, lock))
    }
    /// Compose actual creator inventory only AFTER independent runtime pins
    /// exist; no temporary always-empty inventory or recursive self-reference.
    pub(super) fn from_read(read: &RuntimeRead, originals: I, lock: &mut KeyLock) -> Result<Self> {
        if !read.matches_lock(lock) {
            return Err(Error::Conflict);
        }
        read.verify(&read.runtime.context)?;
        let files = read
            .runtime
            .files
            .try_borrow()
            .map_err(|_| Error::Conflict)?
            .clone();
        let mut authority = Self {
            runtime: read.runtime.clone(),
            original_files: files.clone(),
            files,
            originals,
        };
        authority.verify(lock, &read.runtime.context)?;
        Ok(authority)
    }
    fn runtime(&self, lock: &KeyLock, context: &Context) -> Result<()> {
        if !lock.matches_pin(&self.runtime.lease) {
            return Err(Error::Conflict);
        }
        self.runtime.verify(&lock.pin(), context)
    }
    pub(super) fn read_pin(&self, lock: &KeyLock) -> Result<RuntimeRead> {
        self.runtime(lock, &self.runtime.context)?;
        let read = RuntimeRead {
            runtime: self.runtime.clone(),
            lease: lock.pin(),
        };
        read.verify(&self.runtime.context)?;
        Ok(read)
    }
}
impl RuntimeRead {
    /// Factual SAME held service-owner identity, not a freshness, SDK absence
    /// or effect grant. Recovery must still verify the original runtime/lease.
    pub(super) fn matches_owner(&self, owner: &Arc<MutationGuard>) -> bool {
        Arc::ptr_eq(&self.runtime.owner, owner)
    }
    /// Identity of the original authenticated runtime and serialized lease;
    /// comparison only, not permission derived from equal context metadata.
    pub(super) fn same_original_runtime(&self, other: &RuntimeRead) -> bool {
        Rc::ptr_eq(&self.runtime, &other.runtime) && self.lease.0.matches(&other.lease.0)
    }
    pub(super) fn read_pin(&self) -> Result<Self> {
        self.verify(&self.runtime.context)?;
        Ok(Self {
            runtime: self.runtime.clone(),
            lease: self.lease.read_pin(),
        })
    }
    pub(super) fn matches_pin(&self, pin: &KeyLockPin) -> bool {
        self.lease.0.matches(&pin.0)
    }
    pub(super) fn new(
        root: &Path,
        owner: Arc<MutationGuard>,
        files: NativeSessionFiles,
        context: Context,
    ) -> Result<(Self, KeyLock)> {
        let serialized = KEY_MUTATIONS.try_lock().map_err(|_| Error::Conflict)?;
        owner
            .verify_at(&root.join("engine-owner.lock"))
            .map_err(|_| Error::Conflict)?;
        let pinned =
            super::member_files::pin_private_directory(root).map_err(|_| Error::Conflict)?;
        #[cfg(test)]
        let installation = super::member_carrier_factory_test_os::installation(root)
            .map(Ok)
            .unwrap_or_else(|| Installation::production(root))
            .map_err(|_| Error::Conflict)?;
        #[cfg(not(test))]
        let installation = Installation::production(root).map_err(|_| Error::Conflict)?;
        let executable = actual_executable()?;
        let layout = installation
            .load_engine(&executable)
            .map_err(|_| Error::Conflict)?;
        let lock = KeyLock {
            lease: SerializedLease::new(owner.clone(), serialized),
        };
        let runtime = Rc::new(Runtime {
            context,
            identity: layout.identity,
            directory: layout.directory,
            executable,
            installation,
            owner: owner.clone(),
            lease: lock.pin(),
            pin: Box::new(move || pinned.verify().map_err(|_| Error::Conflict)),
            files: RefCell::new(files.clone()),
            original_files: files,
            execution: RefCell::new(None),
            forward_closed: Cell::new(false),
        });
        let read = Self {
            runtime,
            lease: lock.pin(),
        };
        read.verify(&read.runtime.context)?;
        Ok((read, lock))
    }
}
impl Runtime {
    fn verify(&self, pin: &KeyLockPin, context: &Context) -> Result<()> {
        if *context != self.context
            || !pin.0.matches(&self.lease.0)
            || !Arc::ptr_eq(pin.0.owner(), &self.owner)
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
        #[cfg(test)]
        super::member_carrier_factory_test_os::trace_step(
            "runtime begin installed payload authentication",
        );
        let live = self
            .installation
            .load_engine(&self.executable)
            .map_err(|_| Error::Conflict)?;
        #[cfg(test)]
        super::member_carrier_factory_test_os::trace_step(
            "runtime end installed payload authentication",
        );
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
impl RuntimeRead {
    /// Deferred until the actual common Starting CAS. The factory's fresh
    /// claim has no Session ACK yet and cannot mint an execution selection.
    /// Retain this SAME original root before view/postflight can fail; it is
    /// storage lineage only, never evidence of native readiness or SDK authority.
    pub(super) fn bind_native_execution_birth(
        &self,
        context: &Context,
    ) -> Result<Rc<NativeExecutionRoot>> {
        if self.runtime.forward_closed.get() {
            return Err(Error::Conflict);
        }
        self.verify(context)?;
        if self
            .runtime
            .execution
            .try_borrow()
            .map_err(|_| Error::Conflict)?
            .is_some()
        {
            return Err(Error::Conflict);
        }
        let files = self
            .runtime
            .files
            .try_borrow()
            .map_err(|_| Error::Conflict)?
            .clone();
        let origin = files
            .session_ack_root(&context.intent.scope)
            .map_err(|_| Error::Journal)?;
        let ack = origin
            .inspect(|facts| Ok(facts.ack.clone()))
            .map_err(|_| Error::Conflict)?;
        let execution = Rc::new(
            origin
                .bind_native_birth(context, &ack)
                .map_err(|_| Error::Conflict)?,
        );
        *self
            .runtime
            .execution
            .try_borrow_mut()
            .map_err(|_| Error::Conflict)? = Some(execution.clone());
        let view = files
            .native_birth_view(&execution)
            .map_err(|_| Error::Conflict)?;
        *self
            .runtime
            .files
            .try_borrow_mut()
            .map_err(|_| Error::Conflict)? = view;
        self.verify(context)?;
        Ok(execution)
    }
    /// Factual original lineage access BEFORE explicit epoch renewal. Do not
    /// require the old selected Session ACK to be current here: the common owner
    /// has just persisted n+1. Full runtime/signature/boot/lease checks bracket
    /// this getter; only actor's native proof may authorize subsequent effects.
    pub(super) fn native_execution_root(
        &self,
        context: &Context,
    ) -> Result<Rc<NativeExecutionRoot>> {
        if self.runtime.forward_closed.get() {
            return Err(Error::Conflict);
        }
        self.runtime.verify(&self.lease, context)?;
        let root = self
            .runtime
            .execution
            .try_borrow()
            .map_err(|_| Error::Conflict)?
            .as_ref()
            .ok_or(Error::Conflict)?
            .clone();
        self.runtime.verify(&self.lease, context)?;
        Ok(root)
    }
    /// Resolve only THIS runtime's canonical native view and SAME claimed
    /// storage origin. Readers created before Starting keep their original ACK,
    /// but must not keep an unbound epoch view after explicit execution binding.
    pub(super) fn native_files_for_original(
        &self,
        context: &Context,
        original: &NativeSessionFiles,
    ) -> Result<NativeSessionFiles> {
        self.verify(context)?;
        let canonical = self
            .runtime
            .files
            .try_borrow()
            .map_err(|_| Error::Conflict)?
            .clone();
        if !canonical.same_original_backend(original) {
            return Err(Error::Conflict);
        }
        let execution = self
            .runtime
            .execution
            .try_borrow()
            .map_err(|_| Error::Conflict)?;
        if let Some(root) = execution.as_ref() {
            if !root.matches_origin(original) && !root.matches_native_view(original) {
                return Err(Error::Conflict);
            }
        }
        drop(execution);
        self.verify(context)?;
        Ok(canonical)
    }
    /// Explicit authenticated Stop entry: only SAME original private storage.
    /// No Closing ACK is required to write the first Closing record; native
    /// actions STILL require that actual returned ACK in independent gates.
    /// Once entered, no failure or retry may re-enable forward selection.
    pub(super) fn begin_native_cleanup_storage(
        &self,
        context: &Context,
        original: &NativeSessionFiles,
    ) -> Result<NativeSessionFiles> {
        if *context != self.runtime.context
            || !self.runtime.original_files.same_original_backend(original)
        {
            return Err(Error::Conflict);
        }
        self.runtime.forward_closed.set(true);
        self.runtime.verify(&self.lease, context)?;
        let execution = self
            .runtime
            .execution
            .try_borrow()
            .map_err(|_| Error::Conflict)?;
        let mut view = if let Some(root) = execution.as_ref() {
            if !root.matches_origin(original) && !root.matches_native_view(original) {
                return Err(Error::Conflict);
            }
            root.native_cleanup_view(&self.runtime.original_files)
                .map_err(|_| Error::Conflict)?
                .into_files()
        } else {
            let mut files = self.runtime.original_files.clone();
            files
                .recovery_view(context.intent.scope.runtime)
                .map_err(|_| Error::Journal)?
                .ok_or(Error::Conflict)?
                .0
        };
        drop(execution);
        let access = view
            .native_carrier_access(&context.intent.scope)
            .map_err(|_| Error::Journal)?;
        access
            .require_native_context(context)
            .map_err(|_| Error::Conflict)?;
        if access.is_fresh() {
            return Err(Error::Conflict);
        }
        *self
            .runtime
            .files
            .try_borrow_mut()
            .map_err(|_| Error::Conflict)? = view;
        self.verify(context)?;
        self.runtime
            .files
            .try_borrow()
            .map(|files| files.clone())
            .map_err(|_| Error::Conflict)
    }
    pub(super) fn native_birth_files(&self, context: &Context) -> Result<NativeSessionFiles> {
        let execution = self.native_execution_root(context)?;
        let lease = execution.current_lease().map_err(|_| Error::Conflict)?;
        let facts = execution
            .verify_current(&lease)
            .map_err(|_| Error::Conflict)?;
        if facts.context != *context {
            return Err(Error::Conflict);
        }
        self.verify(context)?;
        self.runtime
            .files
            .try_borrow()
            .map(|files| files.clone())
            .map_err(|_| Error::Conflict)
    }
    pub(super) fn verify(&self, context: &Context) -> Result<()> {
        self.runtime.verify(&self.lease, context)?;
        self.runtime
            .files
            .try_borrow_mut()
            .map_err(|_| Error::Conflict)?
            .native_carrier_access(&context.intent.scope)
            .map_err(|_| Error::Journal)?
            .require_native_context(context)
            .map_err(|_| Error::Conflict)?;
        self.runtime.verify(&self.lease, context)
    }
    /// Bind storage to THIS retained authenticated runtime and shared backend,
    /// not an independent reopen with equal directory/scope/JSON. Identity
    /// comparison is bracketed by actual lease, private-root/runtime and current
    /// protected-context reads. It supplies no native effect or freshness grant.
    pub(super) fn verify_same_session_files(
        &self,
        context: &Context,
        files: &NativeSessionFiles,
    ) -> Result<()> {
        // native_files_for_original already brackets this SAME backend
        // comparison with full runtime authentication and also checks the
        // original execution birth/view. Keep its original owner checks once.
        self.native_files_for_original(context, files)?
            .native_carrier_access(&context.intent.scope)
            .map_err(|_| Error::Journal)?
            .require_native_context(context)
            .map_err(|_| Error::Conflict)?;
        self.verify(context)
    }
    pub(super) fn matches_lock(&self, lock: &KeyLock) -> bool {
        lock.matches_pin(&self.lease)
    }
    pub(super) fn verify_source(
        &self,
        source: &super::member_carrier_payload::native::WintunSource,
    ) -> Result<()> {
        let context = &self.runtime.context;
        let current = || {
            self.runtime
                .files
                .try_borrow_mut()
                .map_err(|_| Error::Conflict)?
                .native_carrier_access(&context.intent.scope)
                .map_err(|_| Error::Journal)?
                .require_native_context(context)
                .map_err(|_| Error::Conflict)
        };
        // One full authentication bracket spans this readonly composition.
        // Preserve BOTH current protected-context reads around the original
        // source's independent full signed-runtime/payload verification.
        // No native effect or permission can precede the final authentication.
        self.runtime.verify(&self.lease, context)?;
        current()?;
        self.lease.verify_source(source)?;
        if source.identity() != &self.runtime.identity {
            return Err(Error::Conflict);
        }
        current()?;
        self.runtime.verify(&self.lease, context)
    }
    /// Actual signed member sources, not member service/NIC ownership or effect
    /// permission. Compare the SAME held serialized owner, not equal JSON or a
    /// separately acquired installation lock, before/after current claim reads.
    pub(super) fn verify_member_source(
        &self,
        context: &Context,
        source: &super::member_carrier_payload::native::MemberSource,
    ) -> Result<()> {
        self.verify(context)?;
        source.verify_owner(self.lease.0.owner())?;
        if source.identity() != &self.runtime.identity {
            return Err(Error::Conflict);
        }
        self.verify(context)?;
        source.verify_owner(self.lease.0.owner())?;
        self.verify(context)
    }
    /// Current SAME runtime/source and the actual retained member intent, not
    /// a service name or caller path. This is factual comparison, never Start.
    pub(super) fn verify_member_intent(
        &self,
        context: &Context,
        source: &super::member_carrier_payload::native::MemberSource,
        intent: &crate::member_owner::Intent,
    ) -> Result<()> {
        self.verify_member_source(context, source)?;
        if intent.engine != self.runtime.executable
            || intent.scope != context.intent.scope
            || intent.transport != source.transport()
        {
            return Err(Error::Conflict);
        }
        self.verify_member_source(context, source)
    }
    /// Query current protected claim, not a retained permission bit. This alone
    /// is NOT effect authorization; exact durable generation/phase and actual
    /// original-creator/native ordering remain separate mandatory gates.
    pub(super) fn fresh(&self, context: &Context) -> Result<bool> {
        crate::member_fresh_read::read(
            // The actual current read below requires the SAME protected
            // context on BOTH observations. Authenticate the original runtime
            // around those reads directly: RuntimeRead::verify would add a
            // second full authentication around the identical context read.
            // Both signed slots, boot, owner and serialized pin are checked
            // twice here; no cached verification or effect grant is returned.
            || self.runtime.verify(&self.lease, context),
            || {
                let access = self
                    .runtime
                    .files
                    .try_borrow_mut()
                    .map_err(|_| Error::Conflict)?
                    .native_carrier_access(&context.intent.scope)
                    .map_err(|_| Error::Journal)?;
                access
                    .require_native_context(context)
                    .map_err(|_| Error::Conflict)?;
                Ok(!self.runtime.forward_closed.get() && access.is_fresh())
            },
        )
    }
    pub(super) fn record(&self, context: &Context, kind: RecordKind) -> Result<Vec<u8>> {
        self.optional_record(context, kind)?.ok_or(Error::Journal)
    }
    /// Factual authenticated absence only. No fresh permission is inferred from
    /// an absent file; the same private claim/context and runtime fence remain
    /// mandatory around the actual read. Native effect gates separately require
    /// live original receipts and exact lifecycle/guard/resource ordering.
    pub(super) fn optional_record(
        &self,
        context: &Context,
        kind: RecordKind,
    ) -> Result<Option<Vec<u8>>> {
        self.optional_records(context, &[kind])?
            .pop()
            .ok_or(Error::Journal)
    }
    /// One factual inventory, reread in full AFTER actual runtime authentication.
    /// Every record still uses the original private backend's own claim/birth/
    /// payload checks. No cache, publication ACK or effect permission is returned.
    pub(super) fn optional_records(
        &self,
        context: &Context,
        kinds: &[RecordKind],
    ) -> Result<Vec<Option<Vec<u8>>>> {
        crate::member_fresh_read::read(
            // The actual current read below requires the SAME protected
            // context on BOTH observations. Authenticate the original runtime
            // around those reads directly: RuntimeRead::verify would add a
            // second full authentication around the identical context read.
            // Both signed slots, boot, owner and serialized pin are checked
            // twice here; no cached verification or effect grant is returned.
            || self.runtime.verify(&self.lease, context),
            || {
                let mut files = self
                    .runtime
                    .files
                    .try_borrow_mut()
                    .map_err(|_| Error::Conflict)?;
                // An empty batch still authenticates the protected context.
                if kinds.is_empty() {
                    files
                        .native_carrier_access(&context.intent.scope)
                        .map_err(|_| Error::Journal)?
                        .require_native_context(context)
                        .map_err(|_| Error::Conflict)?;
                }
                let mut records = Vec::with_capacity(kinds.len());
                for &kind in kinds {
                    files
                        .native_carrier_access(&context.intent.scope)
                        .map_err(|_| Error::Journal)?
                        .require_native_context(context)
                        .map_err(|_| Error::Conflict)?;
                    let record = if kind == RecordKind::Network {
                        // Legacy absence is a common-storage fact, never a native
                        // birth receipt. Keep the native facet's explicit denial;
                        // bracket the SAME original backend read with the selected
                        // native context. Consumers still reject any present record.
                        if !files.same_original_backend(&self.runtime.original_files) {
                            return Err(Error::Conflict);
                        }
                        let record = self
                            .runtime
                            .original_files
                            .clone()
                            .read(&context.intent.scope, kind)
                            .map_err(|_| Error::Journal)?;
                        files
                            .native_carrier_access(&context.intent.scope)
                            .map_err(|_| Error::Journal)?
                            .require_native_context(context)
                            .map_err(|_| Error::Conflict)?;
                        record
                    } else {
                        files
                            .read(&context.intent.scope, kind)
                            .map_err(|_| Error::Journal)?
                    };
                    records.push(record);
                }
                Ok(records)
            },
        )
    }
}
fn actual_executable() -> Result<PathBuf> {
    #[cfg(test)]
    if let Some(path) = crate::windows::member_carrier_factory_test_os::executable() {
        return std::fs::canonicalize(path).map_err(|_| Error::Native);
    }
    std::fs::canonicalize(std::env::current_exe().map_err(|_| Error::Native)?)
        .map_err(|_| Error::Native)
}
impl<I: OriginalCreatorInventory> NativeAuthority for KeyAuthority<I> {
    type Lock = KeyLock;
    fn verify(&mut self, lock: &mut KeyLock, context: &Context) -> Result<()> {
        self.runtime(lock, context)?;
        let read = RuntimeRead {
            runtime: self.runtime.clone(),
            lease: lock.pin(),
        };
        self.files = read.native_files_for_original(context, &self.original_files)?;
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
        if self.originals.inspect_absence(&pending.context, binding)? != (true, true, true) {
            return Err(Error::Conflict);
        }
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
        // The complete original inventory above already brackets both physical
        // MIB/PnP snapshots and every original handle. Repeating that entire
        // query here would not provide another native ACK. The exact effect
        // permission/bytes just read remain LAST after expensive authentication.
        self.runtime
            .owner
            .verify_at(&self.runtime.installation.root.join("engine-owner.lock"))
            .map_err(|_| Error::Conflict)
    }
    fn nic_absence(
        &mut self,
        lock: &mut KeyLock,
        context: &Context,
        binding: &Binding,
    ) -> Result<(bool, bool, bool)> {
        #[cfg(test)]
        super::member_carrier_factory_test_os::trace_step("key absence runtime preflight begin");
        self.verify(lock, context)?;
        #[cfg(test)]
        super::member_carrier_factory_test_os::trace_step("key absence runtime preflight end");
        if !context.bindings.contains(binding) {
            return Err(Error::Conflict);
        }
        #[cfg(test)]
        super::member_carrier_factory_test_os::trace_step(
            "key absence full original inventory begin",
        );
        let absence = self.originals.inspect_absence(context, binding)?;
        #[cfg(test)]
        super::member_carrier_factory_test_os::trace_step(
            "key absence full original inventory end",
        );
        self.verify(lock, context)?;
        #[cfg(test)]
        super::member_carrier_factory_test_os::trace_step("key absence runtime postflight end");
        Ok(absence)
    }
}
