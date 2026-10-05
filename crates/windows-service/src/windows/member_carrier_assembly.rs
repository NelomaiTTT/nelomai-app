//! Caller-retained native assembly. Main supplies G and CarrierPairIo.
//! Integration prerequisite: Keys must retain its internal NEW-key ACK before
//! fallible post-create checks. The two active regression tests cover this
//! gate; the report records the dependency failure found before main's fix.
#![allow(dead_code)]
use crate::member_carrier::{CarrierError as Error, Result};
use crate::member_carrier_native_ownership::{
    self as receipt, Context, InitialRead, InitializedJournal, NativeJournal, NativeKeyAttachment,
    NativeKeyIo, NativeOwnership, PendingNativeOwnership, PrecreationReceipt, Record,
};

type Owner<J, I> = NativeOwnership<InitializedJournal<J>, I>;
type Receipt<'a, I> =
    PrecreationReceipt<'a, <I as NativeKeyIo>::Key, <I as NativeKeyIo>::MutationLock>;

/// Original initialized journal before ANY key/authority/C entry. Unlike Never
/// this permits cold loader entry; it supplies no native absence/unload grant.
struct ModuleOnlyAssemblyRead<J> {
    origin: std::rc::Rc<()>,
    initial: std::rc::Rc<InitialRead<J>>,
    allowed: std::rc::Rc<std::cell::Cell<bool>>,
    selected: std::rc::Rc<TerminalCallState>,
}
impl<J> ModuleOnlyAssemblyRead<J> {
    // SAME owner-created revocation cell and successful original selection.
    // Readonly detached-origin fence; never SDK absence or release permission.
    fn verify_no_constructor_seal(&self) -> Result<()> {
        if !self.allowed.get() {
            return Err(Error::Retired);
        }
        self.selected.verify().map_err(|_| Error::Retired)
    }
}

/// SAME initial publication only, with explicit one-way original-J cleanup
/// selection before its current bytes are checked. No native/disposal grant.
pub(crate) fn inspect_module_only_initial<J: NativeJournal>(
    initial: &InitialRead<J>,
    context: &Context,
    observed: &[u8],
    select: impl FnOnce(&mut J, &Record) -> Result<()>,
) -> Result<()> {
    initial.inspect_original_initial_cleanup(context, |journal, acknowledged| {
        select(journal, acknowledged)?;
        if acknowledged.encode()?.as_slice() != observed {
            return Err(Error::Conflict);
        }
        Ok(())
    })
}

#[cfg(windows)]
use super::member_carrier_terminal_release::TerminalCallState;
#[cfg(not(windows))]
use crate::member_carrier_terminal_release::TerminalCallState;

/// Registration only. The caller selects the SAME journal's canonical cleanup
/// view; no DATA identity or callback result supplies SDK/disposal permission.
pub(crate) fn retain_initial_cleanup_data<D>(
    destination: &std::cell::RefCell<Option<D>>,
    capture_state: &TerminalCallState,
    select_cleanup: impl FnOnce() -> Result<()>,
    capture: impl FnOnce() -> Result<D>,
    postflight: impl FnOnce(&D) -> Result<()>,
) -> Result<()> {
    capture_state
        .run(|| {
            if destination
                .try_borrow()
                .map_err(|_| std::io::Error::other("initial_data_busy"))?
                .is_some()
            {
                return Err(std::io::Error::other("initial_data_duplicate"));
            }
            select_cleanup().map_err(|_| std::io::Error::other("initial_data_cleanup"))?;
            let original = capture().map_err(|_| std::io::Error::other("initial_data_capture"))?;
            let mut slot = destination
                .try_borrow_mut()
                .map_err(|_| std::io::Error::other("initial_data_busy"))?;
            *slot = Some(original);
            postflight(
                slot.as_ref()
                    .ok_or_else(|| std::io::Error::other("initial_data_missing"))?,
            )
            .map_err(|_| std::io::Error::other("initial_data_postflight"))
        })
        .map_err(|_| Error::Retired)
}

/// Retained destination only; never a terminal/disarm capability. Unknown Drop
/// leaves the exact contents alive. Native handoff goes ONLY into the actual
/// terminal release root, whose mandatory G independently proves disarm ACKs.
pub(crate) struct TerminalResources<T> {
    original: Option<T>,
    terminal_disposal_attempted: bool,
}
impl<T> TerminalResources<T> {
    pub(crate) fn new(original: T) -> Self {
        Self {
            original: Some(original),
            terminal_disposal_attempted: false,
        }
    }
    /// Authenticated caller disposal only; there is no default check or success
    /// on empty. Native consumers must supply SAME opaque completed ACKs.
    pub(crate) fn release_original_with(
        &mut self,
        check: impl FnOnce(&T) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        let conflict = || std::io::Error::other("terminal_original_disposal_unknown");
        if std::mem::replace(&mut self.terminal_disposal_attempted, true) {
            return Err(conflict());
        }
        check(self.original.as_ref().ok_or_else(conflict)?)?;
        drop(self.original.take().ok_or_else(conflict)?);
        Ok(())
    }
    pub(crate) fn retained(&self) -> &T {
        self.original.as_ref().expect("retained terminal resources")
    }
    pub(crate) fn retained_mut(&mut self) -> &mut T {
        self.original.as_mut().expect("retained terminal resources")
    }
    /// Owning handoff only. The destination must already be caller-retained;
    /// this neither acknowledges disarm nor grants native/resource release.
    pub(crate) fn transfer_original_into(&mut self, destination: &mut Option<T>) -> Result<()> {
        if self.original.is_none() {
            return Err(Error::Retired);
        }
        transfer_terminal_slot(&mut self.original, destination)
    }
    #[cfg(windows)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn into_terminal_root<G>(
        mut self,
        context: Context,
        runtime: crate::windows::member_carrier_key_authority::RuntimeRead,
        source: std::rc::Rc<crate::windows::member_carrier_runtime::native::NativeSourceRead>,
        retired: std::rc::Rc<crate::windows::member_carrier_runtime::native::RetiredCarrierRead>,
        stopped: std::rc::Rc<
            crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead,
        >,
        expected: crate::member_carrier_pair::Record,
        image: std::rc::Rc<crate::windows::member_carrier_module::native::OriginalImage>,
        supervisor: std::rc::Rc<crate::windows::member_native_deadline::NativeDeadline>,
        gate: G,
    ) -> std::rc::Rc<
        crate::windows::member_carrier_terminal_release::native::NativeTerminalReleaseRoot<T, G>,
    >
    where
        G: crate::windows::member_carrier_terminal_release::native::NativeTerminalResourceGate<T>,
    {
        // No callback/check/native operation between extracting actual originals
        // and retaining them in the REAL root. Unknown root Drop still retains.
        crate::windows::member_carrier_terminal_release::native::NativeTerminalReleaseRoot::new(
            context,
            runtime,
            source,
            retired,
            stopped,
            expected,
            image,
            supervisor,
            self.original.take().expect("retained terminal handoff"),
            gate,
        )
    }
}
impl<T> Drop for TerminalResources<T> {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            // Unknown output abandonment is not a close/disarm ACK. Inert
            // ordinary Drop is enabled ONLY by the real root's gated handoff.
            std::mem::forget(original);
        }
    }
}

pub(crate) fn drain_before_postflight<T>(
    attempted: &mut bool,
    destination: &mut Option<T>,
    initialize: impl FnOnce() -> T,
    transfer: impl FnOnce(&mut T),
    postflight: impl FnOnce(&T) -> Result<()>,
) -> Result<()> {
    if std::mem::replace(attempted, true) || destination.is_some() {
        return Err(Error::Retired);
    }
    *destination = Some(initialize());
    transfer(destination.as_mut().expect("retained raw destination"));
    postflight(destination.as_ref().expect("retained raw destination"))
}

pub(crate) fn transfer_terminal_slot<T>(
    source: &mut Option<T>,
    destination: &mut Option<T>,
) -> Result<()> {
    if source.is_none() {
        return Ok(());
    }
    if destination.is_some() {
        return Err(Error::Conflict);
    }
    *destination = source.take();
    Ok(())
}

/// Raw SAME assembly owners, not the Assembly wrapper with unknown Drop.
/// No field is a disarm/absence grant. Keep this under TerminalResources or
/// NativeTerminalReleaseRoot; the actual G must prove every destructor inert.
pub(crate) struct AssemblyTerminalParts<J: NativeJournal, I: NativeKeyAttachment<J>, A, B> {
    origin: Option<std::rc::Rc<()>>,
    pub(crate) pending: Option<PendingNativeOwnership<J>>,
    pub(crate) initial: Option<std::rc::Rc<InitialRead<J>>>,
    pub(crate) io: std::cell::RefCell<Option<I>>,
    pub(crate) owner: std::cell::RefCell<Option<Owner<J, I>>>,
    pub(crate) assets: std::cell::RefCell<Option<A>>,
    pub(crate) bootstrap: Option<B>,
    pub(crate) disabled: Option<Record>,
    pub(crate) closing: Option<Record>,
    pub(crate) member_disabled: [Option<Record>; 2],
    pub(crate) member_key_retired: [Option<std::rc::Rc<receipt::MemberKeyRetirement>>; 2],
}
impl<J: NativeJournal, I: NativeKeyAttachment<J>, A, B> AssemblyTerminalParts<J, I, A, B> {
    fn with_original_key_owner<T>(
        &self,
        call: impl FnOnce(&mut Owner<J, I>) -> Result<T>,
    ) -> Result<T> {
        if self.origin.is_none() || self.io.try_borrow().map_err(|_| Error::Conflict)?.is_some() {
            return Err(Error::Conflict);
        }
        let mut original = self.owner.try_borrow_mut().map_err(|_| Error::Conflict)?;
        call(original.as_mut().ok_or(Error::Pending)?)
    }
    fn empty() -> Self {
        Self {
            origin: None,
            pending: None,
            initial: None,
            io: std::cell::RefCell::new(None),
            owner: std::cell::RefCell::new(None),
            assets: std::cell::RefCell::new(None),
            bootstrap: None,
            disabled: None,
            closing: None,
            member_disabled: [None, None],
            member_key_retired: [None, None],
        }
    }
}

struct Assembly<J: NativeJournal, I: NativeKeyAttachment<J>, A, B> {
    origin: std::rc::Rc<()>,
    // Original, irreversible no-SDK aperture. Readers share this private fence;
    // no later absence/failed-return can undo a constructor entry.
    no_sdk: std::rc::Rc<std::cell::Cell<bool>>,
    initial_noc_issued: std::cell::Cell<bool>,
    pending: Option<PendingNativeOwnership<J>>,
    initial: Option<std::rc::Rc<InitialRead<J>>>,
    initial_original: Option<std::rc::Weak<InitialRead<J>>>,
    module_only_allowed: std::rc::Rc<std::cell::Cell<bool>>,
    module_only_selection: std::rc::Rc<TerminalCallState>,
    io: Option<I>,
    owner: Option<Owner<J, I>>,
    assets: Option<A>,
    bootstrap: Option<B>,
    disabled: Option<Record>,
    initialize_attempted: bool,
    attach_attempted: bool,
    prepare_attempted: bool,
    precreation_attempted: bool,
    member_attempted: [bool; 2],
    member_disabled: [Option<Record>; 2],
    member_key_retired: [Option<std::rc::Rc<receipt::MemberKeyRetirement>>; 2],
    member_cleanup_only: bool,
    closing: Option<Record>,
    initialized: bool,
    attached: bool,
    prepared: bool,
    terminal_attempted: bool,
}
impl<J: NativeJournal, I: NativeKeyAttachment<J>, A, B> Assembly<J, I, A, B> {
    fn retain_module_only_source_into(
        &self,
        destination: &mut Option<std::rc::Rc<ModuleOnlyAssemblyRead<J>>>,
        postflight: impl FnOnce(&ModuleOnlyAssemblyRead<J>) -> Result<()>,
    ) -> Result<()> {
        self.module_only_selection
            .run(|| {
                if destination.is_some() {
                    return Err(std::io::Error::other("module_only_duplicate"));
                }
                *destination = Some(std::rc::Rc::new(ModuleOnlyAssemblyRead {
                    origin: self.origin.clone(),
                    initial: self
                        .initial
                        .as_ref()
                        .ok_or_else(|| std::io::Error::other("module_only_initial"))?
                        .clone(),
                    allowed: self.module_only_allowed.clone(),
                    selected: self.module_only_selection.clone(),
                }));
                let actual = destination
                    .as_ref()
                    .expect("retained module-only initial source");
                self.verify_module_only_origin(actual)
                    .map_err(|_| std::io::Error::other("module_only_origin"))?;
                let initial = self
                    .pending
                    .as_ref()
                    .ok_or_else(|| std::io::Error::other("module_only_initial"))?
                    .verify_initial()
                    .map_err(|_| std::io::Error::other("module_only_initial"))?;
                postflight(actual).map_err(|_| std::io::Error::other("module_only_postflight"))?;
                self.verify_module_only_origin(actual)
                    .map_err(|_| std::io::Error::other("module_only_origin"))?;
                if self
                    .pending
                    .as_ref()
                    .ok_or_else(|| std::io::Error::other("module_only_initial"))?
                    .verify_initial()
                    .map_err(|_| std::io::Error::other("module_only_initial"))?
                    != initial
                {
                    return Err(std::io::Error::other("module_only_initial_drift"));
                }
                Ok(())
            })
            .map_err(|_| Error::Retired)
    }
    fn verify_module_only_source(&self, source: &ModuleOnlyAssemblyRead<J>) -> Result<()> {
        self.verify_module_only_origin(source)?;
        source.verify_no_constructor_seal()
    }
    fn verify_module_only_origin(&self, source: &ModuleOnlyAssemblyRead<J>) -> Result<()> {
        if !source.allowed.get()
            || !std::rc::Rc::ptr_eq(&source.origin, &self.origin)
            || !std::rc::Rc::ptr_eq(&source.allowed, &self.module_only_allowed)
            || !std::rc::Rc::ptr_eq(&source.selected, &self.module_only_selection)
            || !self.initialized
            || !self.initialize_attempted
            || self.attach_attempted
            || self.prepare_attempted
            || self.precreation_attempted
            || self.member_attempted.iter().any(|a| *a)
            || self.owner.is_some()
            || self.io.is_some()
            || self.assets.is_some()
            || self
                .initial_original
                .as_ref()
                .and_then(std::rc::Weak::upgrade)
                .is_none_or(|actual| !std::rc::Rc::ptr_eq(&actual, &source.initial))
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn claim_initial_noc_source(&self) -> Result<(std::rc::Rc<()>, std::rc::Rc<InitialRead<J>>)> {
        if self.initial_noc_issued.replace(true) {
            return Err(Error::Retired);
        }
        self.initial_noc_source()
    }
    fn verify_initial_noc_original(
        &self,
        origin: &std::rc::Rc<()>,
        pin: &std::rc::Rc<InitialRead<J>>,
    ) -> Result<()> {
        if !self.no_sdk.get()
            || !std::rc::Rc::ptr_eq(origin, &self.origin)
            || self
                .initial_original
                .as_ref()
                .and_then(std::rc::Weak::upgrade)
                .is_none_or(|actual| !std::rc::Rc::ptr_eq(&actual, pin))
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn initial_noc_source(&self) -> Result<(std::rc::Rc<()>, std::rc::Rc<InitialRead<J>>)> {
        if !self.no_sdk.get()
            || !self.initialize_attempted
            || !self.initialized
            || self.terminal_attempted
            || self.attach_attempted
            || self.prepare_attempted
            || self.precreation_attempted
            || self.member_attempted.iter().any(|attempt| *attempt)
            || self.pending.is_none()
            || self.io.is_some()
            || self.owner.is_some()
            || self.assets.is_some()
            || self.disabled.is_some()
            || self.closing.is_some()
            || self.member_disabled.iter().any(Option::is_some)
            || self.member_key_retired.iter().any(Option::is_some)
        {
            return Err(Error::Conflict);
        }
        let pin = self.initial.as_ref().ok_or(Error::Pending)?;
        let registered = self
            .initial_original
            .as_ref()
            .and_then(std::rc::Weak::upgrade)
            .ok_or(Error::Pending)?;
        if !std::rc::Rc::ptr_eq(pin, &registered) {
            return Err(Error::Conflict);
        }
        Ok((self.origin.clone(), pin.clone()))
    }
    fn drain_terminal_into(
        &mut self,
        destination: &mut Option<AssemblyTerminalParts<J, I, A, B>>,
        postflight: impl FnOnce(&AssemblyTerminalParts<J, I, A, B>) -> Result<()>,
    ) -> Result<()> {
        self.member_cleanup_only = true;
        drain_before_postflight(
            &mut self.terminal_attempted,
            destination,
            AssemblyTerminalParts::empty,
            |raw| {
                raw.origin = Some(self.origin.clone());
                raw.pending = self.pending.take();
                raw.initial = self.initial.take();
                *raw.io.get_mut() = self.io.take();
                *raw.owner.get_mut() = self.owner.take();
                *raw.assets.get_mut() = self.assets.take();
                raw.bootstrap = self.bootstrap.take();
                raw.disabled = self.disabled.take();
                raw.closing = self.closing.take();
                raw.member_disabled = std::mem::take(&mut self.member_disabled);
                raw.member_key_retired = std::mem::take(&mut self.member_key_retired);
                self.initialized = false;
                self.attached = false;
                self.prepared = false;
            },
            postflight,
        )
    }
    /// ONLY empty wrapper proof, not raw owner disarm. The raw destination
    /// retains all original keys/bootstrap/journal resources for mandatory G.
    fn verify_drained_original(&self, raw: &AssemblyTerminalParts<J, I, A, B>) -> Result<()> {
        if !self.terminal_attempted
            || raw
                .origin
                .as_ref()
                .is_none_or(|origin| !std::rc::Rc::ptr_eq(origin, &self.origin))
            || self.pending.is_some()
            || self.initial.is_some()
            || self.io.is_some()
            || self.owner.is_some()
            || self.assets.is_some()
            || self.bootstrap.is_some()
            || self.disabled.is_some()
            || self.closing.is_some()
            || self.member_disabled.iter().any(Option::is_some)
            || self.member_key_retired.iter().any(Option::is_some)
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    /// Factual original no-constructor cut. Loader entry stays recorded; this
    /// does not certify the owning DLL's release or authorize raw disposal.
    fn verify_module_only_terminal_cut(
        &self,
        raw: &AssemblyTerminalParts<J, I, A, B>,
        source: &ModuleOnlyAssemblyRead<J>,
    ) -> Result<()> {
        self.verify_drained_original(raw)?;
        source.verify_no_constructor_seal()?;
        if !self.initialize_attempted
            || self.attach_attempted
            || self.prepare_attempted
            || self.precreation_attempted
            || self.member_attempted.iter().any(|attempt| *attempt)
            || !std::rc::Rc::ptr_eq(&source.origin, &self.origin)
            || !std::rc::Rc::ptr_eq(&source.allowed, &self.module_only_allowed)
            || !std::rc::Rc::ptr_eq(&source.selected, &self.module_only_selection)
            || self
                .initial_original
                .as_ref()
                .and_then(std::rc::Weak::upgrade)
                .is_none_or(|initial| !std::rc::Rc::ptr_eq(&initial, &source.initial))
            || raw
                .initial
                .as_ref()
                .is_none_or(|initial| !std::rc::Rc::ptr_eq(initial, &source.initial))
            || raw.pending.is_none()
            || raw.bootstrap.is_none()
            || raw.io.try_borrow().map_err(|_| Error::Conflict)?.is_some()
            || raw
                .owner
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .is_some()
            || raw
                .assets
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .is_some()
            || raw.disabled.is_some()
            || raw.closing.is_some()
            || raw.member_disabled.iter().any(Option::is_some)
            || raw.member_key_retired.iter().any(Option::is_some)
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    /// Factual no-SDK initial-journal cut, not native absence or disposal.
    /// Requires the exact opaque initial ACK minted by this original Assembly.
    fn verify_initial_terminal_cut(
        &self,
        raw: &AssemblyTerminalParts<J, I, A, B>,
        context: &Context,
    ) -> Result<()> {
        self.verify_drained_original(raw)?;
        if !self.no_sdk.get()
            || !self.initialize_attempted
            || self.attach_attempted
            || self.prepare_attempted
            || self.precreation_attempted
            || self.member_attempted.iter().any(|attempt| *attempt)
            || raw.pending.is_none()
            || raw.io.try_borrow().map_err(|_| Error::Conflict)?.is_some()
            || raw
                .owner
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .is_some()
            || raw
                .assets
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .is_some()
            || raw.disabled.is_some()
            || raw.closing.is_some()
            || raw.member_disabled.iter().any(Option::is_some)
            || raw.member_key_retired.iter().any(Option::is_some)
        {
            return Err(Error::Conflict);
        }
        let actual = raw.initial.as_ref().ok_or(Error::Pending)?;
        let original = self
            .initial_original
            .as_ref()
            .and_then(std::rc::Weak::upgrade)
            .ok_or(Error::Pending)?;
        if !std::rc::Rc::ptr_eq(actual, &original) {
            return Err(Error::Conflict);
        }
        actual.verify(context).map(|_| ())
    }
    fn restore_member_key(
        &mut self,
        role: receipt::Role,
        lock: &mut I::MutationLock,
    ) -> Result<Record> {
        if self.member_cleanup_only {
            return Err(Error::Retired);
        }
        let index = match role {
            receipt::Role::MemberA => 0,
            receipt::Role::MemberB => 1,
            receipt::Role::RoleCarrier => return Err(Error::Retired),
        };
        let mut attempt = MemberAttempt {
            cleanup_only: &mut self.member_cleanup_only,
            succeeded: false,
        };
        let owner = self.owner.as_mut().ok_or(Error::Pending)?;
        let current = owner.snapshot()?.ok_or(Error::Pending)?;
        let result =
            owner.restore_member_key(&current, role, &mut self.member_key_retired[index], lock)?;
        attempt.succeeded = true;
        Ok(result)
    }
    fn begin_cleanup(&mut self, lock: &mut I::MutationLock) -> Result<()> {
        self.member_cleanup_only = true;
        let owner = self.owner.as_mut().ok_or(Error::Pending)?;
        let current = owner.snapshot()?.ok_or(Error::Pending)?;
        // SAME retained owner validates its current successful publication ACK.
        // This is the Closing journal transition ONLY: no key restoration,
        // native address/session/member effect or inferred absence.
        self.closing = Some(owner.begin_cleanup(&current, lock)?);
        Ok(())
    }
    fn with_original_terminal_owner<T>(
        &mut self,
        call: impl FnOnce(&mut Owner<J, I>) -> Result<T>,
    ) -> Result<T> {
        self.member_cleanup_only = true;
        if self.terminal_attempted {
            return Err(Error::Retired);
        }
        call(self.owner.as_mut().ok_or(Error::Pending)?)
    }
    fn with_member_precreation(
        &mut self,
        role: receipt::Role,
        lock: &mut I::MutationLock,
        call: impl FnOnce(Receipt<'_, I>) -> Result<()>,
    ) -> Result<()> {
        self.with_member_precreation_in(role, lock, &mut |call| call(), call)
    }
    fn with_member_precreation_in(
        &mut self,
        role: receipt::Role,
        lock: &mut I::MutationLock,
        run: &mut impl FnMut(&mut dyn FnMut() -> Result<()>) -> Result<()>,
        call: impl FnOnce(Receipt<'_, I>) -> Result<()>,
    ) -> Result<()> {
        self.no_sdk.set(false);
        if self.member_cleanup_only {
            return Err(Error::Retired);
        }
        let member = match role {
            receipt::Role::MemberA => 0,
            receipt::Role::MemberB => 1,
            receipt::Role::RoleCarrier => return Err(Error::Retired),
        };
        let repeated = self.member_attempted[member];
        if repeated && self.member_key_retired[member].is_none() {
            return Err(Error::Retired);
        }
        self.member_attempted[member] = true;
        let mut attempt = MemberAttempt {
            cleanup_only: &mut self.member_cleanup_only,
            succeeded: false,
        };
        if !self.prepared {
            return Err(Error::Pending);
        }
        // C's assets now belong to the retained carrier root. Only the SAME
        // attached key owner prepares A/B; no replacement owner or key IO.
        let owner = self.owner.as_mut().ok_or(Error::Pending)?;
        self.member_disabled[member] = Some(if repeated {
            let mut disabled = None;
            receipt::preparation_call(run, || {
                let current = owner.snapshot()?.ok_or(Error::Pending)?;
                disabled = Some(
                    owner.redisable_member_key(
                        &current,
                        role,
                        self.member_key_retired[member]
                            .as_deref()
                            .ok_or(Error::Retired)?,
                        lock,
                    )?,
                );
                Ok(())
            })?;
            disabled.ok_or(Error::Pending)?
        } else {
            owner.prepare_role_in(role, lock, &mut *run)?
        });
        receipt::preparation_call(run, || {
            let receipt = owner.before_adapter_create(role, lock)?;
            receipt::validate_record(receipt.record)?;
            let index = member + 1;
            let key = &receipt.record.keys[index];
            if receipt.record.phase != receipt::Phase::Preparing
                || receipt.binding != &receipt.record.context.bindings[index]
                || key.phase != receipt::KeyPhase::Disabled
                || !key.new_key_ack
                || key.baseline != receipt::Value::Absent
                || key.current != receipt::Value::DwordZero
                || key.pending.is_some()
            {
                return Err(Error::Conflict);
            }
            receipt::validate_carrier_create_stage(
                receipt.record,
                &receipt.record.context,
                &receipt.record.context.bindings[0],
                receipt.record.generation,
            )?;
            call(receipt)
        })?;
        attempt.succeeded = true;
        Ok(())
    }
    fn new(context: Context, journal: J, bootstrap: B) -> Self {
        Self {
            origin: std::rc::Rc::new(()),
            no_sdk: std::rc::Rc::new(std::cell::Cell::new(true)),
            initial_noc_issued: std::cell::Cell::new(false),
            pending: Some(PendingNativeOwnership::new(context, journal)),
            initial: None,
            initial_original: None,
            module_only_allowed: std::rc::Rc::new(std::cell::Cell::new(true)),
            module_only_selection: std::rc::Rc::new(TerminalCallState::new()),
            io: None,
            owner: None,
            assets: None,
            bootstrap: Some(bootstrap),
            disabled: None,
            initialize_attempted: false,
            attach_attempted: false,
            prepare_attempted: false,
            precreation_attempted: false,
            member_attempted: [false; 2],
            member_disabled: [None, None],
            member_key_retired: [None, None],
            member_cleanup_only: false,
            closing: None,
            initialized: false,
            attached: false,
            prepared: false,
            terminal_attempted: false,
        }
    }
    fn initialize(&mut self) -> Result<()> {
        enter(&mut self.initialize_attempted)?;
        let pending = self.pending.as_mut().ok_or(Error::Pending)?;
        pending.initialize()?;
        let initial = std::rc::Rc::new(pending.read_pin()?);
        self.initial_original = Some(std::rc::Rc::downgrade(&initial));
        self.initial = Some(initial);
        self.initialized = true;
        Ok(())
    }
    fn attach_keys(&mut self, lock: &mut I::MutationLock) -> Result<()> {
        self.module_only_allowed.set(false);
        self.no_sdk.set(false);
        enter(&mut self.attach_attempted)?;
        if !self.initialized || self.assets.is_none() {
            return Err(Error::Pending);
        }
        // The actual attachment checks BOTH originals while they remain in
        // these slots, including its final fresh read after identity callbacks.
        PendingNativeOwnership::attach(&mut self.pending, &mut self.io, &mut self.owner, lock)?;
        self.attached = true;
        Ok(())
    }
    fn prepare_carrier(&mut self, lock: &mut I::MutationLock) -> Result<()> {
        self.prepare_carrier_in(lock, |call| call())
    }
    fn prepare_carrier_in(
        &mut self,
        lock: &mut I::MutationLock,
        run: impl FnMut(&mut dyn FnMut() -> Result<()>) -> Result<()>,
    ) -> Result<()> {
        self.module_only_allowed.set(false);
        self.no_sdk.set(false);
        enter(&mut self.prepare_attempted)?;
        if !self.attached {
            return Err(Error::Pending);
        }
        self.disabled = Some(self.owner.as_mut().ok_or(Error::Pending)?.prepare_role_in(
            receipt::Role::RoleCarrier,
            lock,
            run,
        )?);
        let record = self.disabled.as_ref().expect("retained Disabled return");
        receipt::validate_carrier_create_stage(
            record,
            &record.context,
            &record.context.bindings[0],
            record.generation,
        )?;
        self.prepared = true;
        Ok(())
    }
    fn with_precreation(
        &mut self,
        lock: &mut I::MutationLock,
        call: impl FnOnce(&mut Option<A>, Receipt<'_, I>, u64) -> Result<()>,
    ) -> Result<()> {
        self.with_precreation_in(lock, &mut |call| call(), call)
    }
    fn with_precreation_in(
        &mut self,
        lock: &mut I::MutationLock,
        run: &mut impl FnMut(&mut dyn FnMut() -> Result<()>) -> Result<()>,
        call: impl FnOnce(&mut Option<A>, Receipt<'_, I>, u64) -> Result<()>,
    ) -> Result<()> {
        self.no_sdk.set(false);
        enter(&mut self.precreation_attempted)?;
        if !self.prepared {
            return Err(Error::Pending);
        }
        if self.assets.is_none() {
            return Err(Error::Pending);
        }
        let receipt = self
            .owner
            .as_mut()
            .ok_or(Error::Pending)?
            .before_adapter_create_in(receipt::Role::RoleCarrier, lock, run)?;
        // Use the actual CURRENT borrowed receipt, including later legitimate
        // journal revisions. A remembered/precomputed generation is not used.
        receipt::validate_carrier_create_stage(
            receipt.record,
            &receipt.record.context,
            receipt.binding,
            receipt.record.generation,
        )?;
        let generation = receipt.record.generation;
        call(&mut self.assets, receipt, generation)
    }
}

struct MemberAttempt<'a> {
    cleanup_only: &'a mut bool,
    succeeded: bool,
}
impl Drop for MemberAttempt<'_> {
    fn drop(&mut self) {
        if !self.succeeded {
            *self.cleanup_only = true;
        }
    }
}

fn enter(attempted: &mut bool) -> Result<()> {
    if std::mem::replace(attempted, true) {
        Err(Error::Retired)
    } else {
        Ok(())
    }
}

/// Comparison only. Actual Source/Runtime/Pair ACK/Calling brackets this at
/// native entry; this does not grant member, network or WFP effects.
fn validate_member_key_window(
    context: &Context,
    record: &crate::member_carrier_pair::Record,
    role: receipt::Role,
    carrier: &crate::member_carrier_guard::Carrier,
    egress: &[Option<crate::member_carrier_guard::Identity>; 2],
) -> Result<()> {
    use crate::{member_carrier_pair as p, member_owner as o};
    use nelomai_client_tunnel::redundancy::Slot;
    let (index, target) = match role {
        receipt::Role::MemberA => (0, Slot::A),
        receipt::Role::MemberB => (1, Slot::B),
        receipt::Role::RoleCarrier => return Err(Error::Conflict),
    };
    record.validate().map_err(|_| Error::Conflict)?;
    let member = record.members[index].as_ref().ok_or(Error::Conflict)?;
    let operation_matches = match (record.phase, record.operation) {
        (p::Phase::Starting, Some(p::Operation::Start(slot))) => {
            slot == target && record.active.is_none()
        }
        (p::Phase::Running, Some(p::Operation::Attach(slot))) => {
            slot == target && record.active != Some(target)
        }
        _ => false,
    };
    if !operation_matches
        || record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || record.pending != Some(p::Effect::MemberStart(target))
        || record.stop_stage != 0
        || record.pending_guard.is_some()
        || record.network.as_ref().is_some_and(|n| n.pending.is_some())
        || member.owner.phase != o::Phase::Prepared
        || member.owner.proof.is_some()
        || member.owner.retired_proof.is_some()
        || member.owner.previous_config_sha256.is_some()
        || egress[index].is_some()
        || carrier.identity.scope != record.scope
        || carrier.identity.proof.guid != context.bindings[0].guid
        || carrier.identity.proof.index == 0
        || carrier.identity.proof.luid == 0
        || Some(carrier.identity.proof) != record.carrier
        || carrier.sources
            != record
                .addresses
                .iter()
                .map(|a| a.addr())
                .collect::<Vec<_>>()
    {
        return Err(Error::Conflict);
    }
    for (i, actual) in egress.iter().enumerate() {
        if i == index {
            continue;
        }
        let expected = record.members[i].as_ref().and_then(|m| m.owner.proof);
        match (expected, actual) {
            (None, None) => {}
            (Some(proof), Some(actual))
                if actual.scope == record.scope
                    && actual.proof == proof.interface
                    && actual.proof.guid == context.bindings[i + 1].guid => {}
            _ => return Err(Error::Conflict),
        }
    }
    Ok(())
}
/// Comparison only; original Source window supplies closed history, and the
/// actual opaque Pair ACK/held lock/native key owner remain mandatory.
fn validate_member_restore_window(
    context: &Context,
    record: &crate::member_carrier_pair::Record,
    role: receipt::Role,
    carrier: &crate::member_carrier_guard::Carrier,
    egress: &[Option<crate::member_carrier_guard::Identity>; 2],
    closed: (
        &crate::member_owner::Intent,
        crate::member_owner::NativeProof,
    ),
) -> Result<()> {
    use crate::{member_carrier_pair as p, member_owner as o};
    use nelomai_client_tunnel::redundancy::Slot;
    let (index, target, active) = match role {
        receipt::Role::MemberA => (0, Slot::A, Slot::B),
        receipt::Role::MemberB => (1, Slot::B, Slot::A),
        receipt::Role::RoleCarrier => return Err(Error::Conflict),
    };
    record.validate().map_err(|_| Error::Conflict)?;
    let member = record.members[index].as_ref().ok_or(Error::Conflict)?;
    let other = record.members[1 - index].as_ref().ok_or(Error::Conflict)?;
    let network = record.network.as_ref().ok_or(Error::Conflict)?;
    if record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || record.phase != p::Phase::Running
        || record.operation != Some(p::Operation::Retire(target))
        || record.pending != Some(p::Effect::RestoreKeys)
        || record.active != Some(active)
        || record.stop_stage != 0
        || record.pending_guard.is_some()
        || network.pending.is_some()
        || member.owner.phase != o::Phase::Running
        || other.owner.phase != o::Phase::Running
        || member.owner.intent != *closed.0
        || member.owner.proof != Some(closed.1)
        || closed.1.interface.guid != context.bindings[index + 1].guid
        || egress[index].is_some()
        || record.guard.members[index].is_some()
        || record.guard.permits
        || !record.guard.installed
        || record.guard.carrier.as_ref() != Some(carrier)
        || Some(carrier.identity.proof) != record.carrier
        || carrier.identity.scope != record.scope
        || carrier.identity.proof.guid != context.bindings[0].guid
        || carrier.sources
            != record
                .addresses
                .iter()
                .map(|a| a.addr())
                .collect::<Vec<_>>()
        || network
            .current
            .routes
            .iter()
            .any(|r| r.interface == closed.1.interface.index)
    {
        return Err(Error::Conflict);
    }
    let actual = egress[1 - index].as_ref().ok_or(Error::Conflict)?;
    let proof = other.owner.proof.ok_or(Error::Conflict)?;
    if actual.scope != record.scope
        || actual.proof != proof.interface
        || actual.proof.guid != context.bindings[2 - index].guid
        || record.guard.members[1 - index]
            .as_ref()
            .is_none_or(|m| m.identity != *actual)
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
impl<J: NativeJournal, I: NativeKeyAttachment<J>, A, B> Drop for Assembly<J, I, A, B> {
    fn drop(&mut self) {
        // Abandonment has no absence/close/cleanup ACK. Preserve ALL original
        // pins, including an internally captured key or a consumed journal.
        retain_unknown(&mut self.pending);
        retain_unknown(&mut self.initial);
        retain_unknown(&mut self.io);
        retain_unknown(&mut self.owner);
        retain_unknown(&mut self.assets);
        retain_unknown(&mut self.bootstrap);
    }
}
fn retain_unknown<T>(slot: &mut Option<T>) {
    if let Some(original) = slot.take() {
        std::mem::forget(original);
    }
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::member_carrier_pair::{self as pair, Record as PairRecord};
    use crate::windows::{
        member_carrier_bootstrap::native::{
            BootstrapAssets, NativeBootstrapModuleOnlyRead, NativeBootstrapSlot,
        },
        member_carrier_creators::{self as creators, Producer},
        member_carrier_key_authority::{KeyAuthority, KeyLock, RuntimeRead},
        member_carrier_keys::{win32, Keys},
        member_carrier_members::native::MemberInventoryRead,
        member_carrier_module::native::{LoadedWintun, OriginalImage},
        member_carrier_pair_store::native_store::NativePairIntentRead,
        member_carrier_payload::native::WintunSource,
        member_carrier_wintun::native::{OriginalKeyInventory, OriginalWintun},
        member_native_deadline::NativeDeadline,
        member_session::{
            InitialDataRetirementAck, InitialNativeDataRead, NativeSessionFiles,
            OriginalInitialNativeDataRetirement, WindowsNativeCarrierReceiptStore,
        },
    };
    use std::{
        rc::Rc,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };

    pub(crate) type NativeJournalStore = WindowsNativeCarrierReceiptStore<NativeSessionFiles>;
    pub(crate) type NativeKeys = Keys<win32::Kernel, KeyAuthority<OriginalKeyInventory>>;
    pub(crate) type KeyOwner = Owner<NativeJournalStore, NativeKeys>;
    pub(crate) type NativePrecreation<'a> = Receipt<'a, NativeKeys>;
    pub(crate) type NativeAssemblyTerminalParts = AssemblyTerminalParts<
        NativeJournalStore,
        NativeKeys,
        NativeAssemblyAssets,
        NativeBootstrapSlot,
    >;
    pub(crate) struct NativeAssemblyTerminalResources {
        pub(crate) parts: Option<NativeAssemblyTerminalParts>,
        pub(crate) incoming: Option<BootstrapAssets>,
        module_only_source: Option<Rc<ModuleOnlyAssemblyRead<NativeJournalStore>>>,
    }
    impl NativeAssemblyTerminalResources {
        /// Access only: SAME actual key owner stays in its retained raw slot
        /// through the callback's Err/unwind. No terminal or HKEY permission.
        pub(crate) fn with_terminal_original_key_owner<T>(
            &self,
            call: impl FnOnce(&mut KeyOwner) -> Result<T>,
        ) -> Result<T> {
            self.parts
                .as_ref()
                .ok_or(Error::Pending)?
                .with_original_key_owner(call)
        }
    }

    /// All remaining ACTUAL bootstrap objects. No new runtime, inventory,
    /// supervisor, cancellation signal, journal, module or source is created.
    /// Main retains construction output in its own owning slot INSIDE the
    /// callback before any fallible G/carrier construction postflight.
    pub(crate) struct NativeAssemblyAssets {
        pub(crate) module: LoadedWintun,
        pub(crate) runtime: RuntimeRead,
        pub(crate) image: OriginalImage,
        pub(crate) producer: Producer<OriginalWintun>,
        pub(crate) observer: creators::Observer<OriginalWintun>,
        pub(crate) members: MemberInventoryRead,
        pub(crate) context: Context,
        pub(crate) expected: PairRecord,
        pub(crate) source: Rc<WintunSource>,
        pub(crate) supervisor: Rc<NativeDeadline>,
        pub(crate) cancelled: Arc<AtomicBool>,
        pub(crate) pair_intent: Rc<NativePairIntentRead>,
    }

    /// Original initialized-only journal, sealed by this SAME Assembly before
    /// any bootstrap/attachment/native constructor access. Not a native receipt
    /// or absence permit. The mandatory Never reader still checks all SDK,
    /// service, key, private inventory and actual Calling facts independently.
    pub(crate) struct NativeInitialAssemblyNoCRead {
        origin: Rc<()>,
        initial: Rc<InitialRead<NativeJournalStore>>,
        initial_data: std::cell::RefCell<Option<InitialNativeDataRead>>,
        data_capture: TerminalCallState,
        no_sdk: Rc<std::cell::Cell<bool>>,
        runtime: Rc<RuntimeRead>,
        context: Context,
        canonical: std::cell::RefCell<Option<NativeSessionFiles>>,
        cleanup: crate::windows::member_carrier_terminal_release::TerminalCallState,
    }
    impl NativeInitialAssemblyNoCRead {
        pub(crate) fn original_initial_data_read(&self) -> Result<InitialNativeDataRead> {
            self.initial_data
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .as_ref()
                .cloned()
                .ok_or(Error::Pending)
        }
        /// Deferred private DATA retirement, not SDK access. The completed
        /// original NoC issuer authenticates inside the private transaction.
        /// No active-journal reread is possible AFTER real index retirement.
        pub(crate) fn retire_original_initial_data(
            &self,
            proof: &dyn OriginalInitialNativeDataRetirement,
            retain: impl FnOnce(Rc<InitialDataRetirementAck>) -> std::io::Result<()>,
        ) -> Result<()> {
            self.verify_ready(&self.runtime, &self.context)?;
            let expected = self.original_initial_data_read()?;
            self.initial
                .retire_original_initial_data(&self.context, |journal, acknowledged| {
                    if expected.acknowledged() != acknowledged {
                        return Err(Error::Conflict);
                    }
                    let retired = journal
                        .retire_original_initial_data(proof, retain)
                        .map_err(|_| Error::Journal)?;
                    if !retired.matches_original(&expected) {
                        return Err(Error::Conflict);
                    }
                    Ok(())
                })
        }
        fn verify_origin(&self, runtime: &RuntimeRead, context: &Context) -> Result<()> {
            if !self.no_sdk.get()
                || !std::ptr::eq(self.runtime.as_ref(), runtime)
                || context != &self.context
            {
                return Err(Error::Conflict);
            }
            Ok(())
        }
        pub(crate) fn verify_ready(&self, runtime: &RuntimeRead, context: &Context) -> Result<()> {
            self.verify_origin(runtime, context)?;
            self.cleanup.verify().map_err(|_| Error::Retired)
        }
        /// Factual initial DATA during cold preparation, before cleanup and SDK
        /// entry. Inspect the SAME initialized journal/ACK in its forward view;
        /// an equal record cannot substitute for this original reader.
        pub(crate) fn verify_forward_current(
            &self,
            runtime: &RuntimeRead,
            context: &Context,
            observed_native_receipt_bytes: &[u8],
        ) -> Result<()> {
            self.verify_origin(runtime, context)?;
            if !runtime.fresh(context)? {
                return Err(Error::Retired);
            }
            self.initial.inspect_initial(context, |_, acknowledged| {
                if Record::decode(observed_native_receipt_bytes)? != *acknowledged {
                    return Err(Error::Conflict);
                }
                self.verify_origin(runtime, context)
            })?;
            if !runtime.fresh(context)? {
                return Err(Error::Retired);
            }
            self.verify_origin(runtime, context)
        }
        /// SDK-free handoff only. Retains the actual canonical cleanup view
        /// BEFORE original journal handoff/postflight. No record rewrite and
        /// no Stopped/native/module ACK is minted here.
        pub(crate) fn enter_cleanup(
            &self,
            runtime: &RuntimeRead,
            context: &Context,
            canonical: NativeSessionFiles,
        ) -> Result<()> {
            self.cleanup
                .run(|| {
                    *self
                        .canonical
                        .try_borrow_mut()
                        .map_err(|_| std::io::Error::other("initial_noc_busy"))? =
                        Some(canonical.clone());
                    self.verify_origin(runtime, context)
                        .map_err(|_| std::io::Error::other("initial_noc_origin"))?;
                    self.initial
                        .inspect_original_initial_cleanup(context, |journal, acknowledged| {
                            let journal = std::cell::RefCell::new(journal);
                            retain_initial_cleanup_data(
                                &self.initial_data,
                                &self.data_capture,
                                || {
                                    journal
                                        .borrow_mut()
                                        .enter_original_initial_cleanup(canonical)
                                        .map_err(|_| Error::Journal)
                                },
                                || {
                                    journal
                                        .borrow()
                                        .original_initial_data_read()
                                        .map_err(|_| Error::Journal)
                                },
                                |original| {
                                    if original.acknowledged() != acknowledged {
                                        return Err(Error::Conflict);
                                    }
                                    self.verify_origin(runtime, context)
                                },
                            )
                        })
                        .map_err(|_| std::io::Error::other("initial_noc_journal"))?;
                    self.verify_origin(runtime, context)
                        .map_err(|_| std::io::Error::other("initial_noc_origin"))
                })
                .map_err(|_| Error::Retired)
        }
        /// Compare current protected bytes ONLY to this actual original
        /// initialization ACK in its SAME cleanup journal. Matching JSON from
        /// another journal/Assembly cannot construct or replace this reader.
        pub(crate) fn verify_current(
            &self,
            runtime: &RuntimeRead,
            context: &Context,
            observed_native_receipt_bytes: &[u8],
        ) -> Result<()> {
            self.verify_ready(runtime, context)?;
            let canonical = self
                .canonical
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .as_ref()
                .ok_or(Error::Pending)?
                .clone();
            self.initial
                .inspect_original_initial_cleanup(context, |journal, acknowledged| {
                    journal
                        .enter_original_initial_cleanup(canonical)
                        .map_err(|_| Error::Journal)?;
                    if Record::decode(observed_native_receipt_bytes)? != *acknowledged {
                        return Err(Error::Conflict);
                    }
                    self.verify_origin(runtime, context)
                })?;
            self.verify_origin(runtime, context)
        }
    }

    /// Caller creates and retains this root BEFORE initialize/load/assembly.
    /// It is never an owning value returned through a supervisor Result.
    pub(crate) struct NativeAssemblySlot {
        root: Assembly<NativeJournalStore, NativeKeys, NativeAssemblyAssets, NativeBootstrapSlot>,
        incoming: Option<BootstrapAssets>,
        assembly_attempted: bool,
        prepare_call_attempted: bool,
        precreation_call_attempted: bool,
        member_call_attempted: [bool; 2],
        assembled: bool,
        prepared: bool,
        terminal_attempted: bool,
        module_only_source: Option<Rc<ModuleOnlyAssemblyRead<NativeJournalStore>>>,
    }
    pub(crate) struct NativeAssemblyModuleOnlyRead {
        source: Rc<ModuleOnlyAssemblyRead<NativeJournalStore>>,
        bootstrap: std::cell::RefCell<Option<Rc<NativeBootstrapModuleOnlyRead>>>,
    }
    impl NativeAssemblyModuleOnlyRead {
        /// Original owner-created seal is revoked before every constructor/key
        /// entry. No native facts or unload right are inferred from this check.
        pub(crate) fn verify_no_constructor_seal(&self) -> Result<()> {
            self.source.verify_no_constructor_seal()
        }
        pub(crate) fn bootstrap(&self) -> Result<Rc<NativeBootstrapModuleOnlyRead>> {
            self.bootstrap
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .as_ref()
                .cloned()
                .ok_or(Error::Pending)
        }
    }
    impl NativeAssemblySlot {
        /// Factual candidate only. The original source was rooted before cold
        /// load; native load ACK, full empty SDK and unload permit are separate.
        pub(crate) fn retain_module_only_candidate_in_call(
            &self,
            pair: &Rc<NativePairIntentRead>,
            expected: &PairRecord,
            destination: &mut Option<Rc<NativeAssemblyModuleOnlyRead>>,
        ) -> Result<()> {
            if destination.is_some() {
                return Err(Error::Retired);
            }
            let source = self
                .module_only_source
                .as_ref()
                .ok_or(Error::Pending)?
                .clone();
            *destination = Some(Rc::new(NativeAssemblyModuleOnlyRead {
                source,
                bootstrap: std::cell::RefCell::new(None),
            }));
            let original = destination.as_ref().expect("retained module-only Assembly");
            self.verify_module_only_source(&original.source)?;
            self.root
                .bootstrap
                .as_ref()
                .ok_or(Error::Pending)?
                .retain_module_only_read_in_call(
                    pair,
                    expected,
                    &mut original.bootstrap.borrow_mut(),
                )?;
            self.verify_module_only_source(&original.source)
        }
        fn verify_module_only_source(
            &self,
            source: &Rc<ModuleOnlyAssemblyRead<NativeJournalStore>>,
        ) -> Result<()> {
            if self.assembly_attempted
                || self.prepare_call_attempted
                || self.precreation_call_attempted
                || self.member_call_attempted.iter().any(|a| *a)
                || self.incoming.is_some()
                || self.terminal_attempted
                || self
                    .module_only_source
                    .as_ref()
                    .is_none_or(|s| !Rc::ptr_eq(s, source))
            {
                return Err(Error::Conflict);
            }
            self.root.verify_module_only_source(source)
        }
        pub(crate) fn verify_module_only_candidate(
            &self,
            original: &NativeAssemblyModuleOnlyRead,
            pair: &Rc<NativePairIntentRead>,
            expected: &PairRecord,
        ) -> Result<()> {
            self.verify_module_only_source(&original.source)?;
            self.root
                .bootstrap
                .as_ref()
                .ok_or(Error::Pending)?
                .verify_module_only_read(original.bootstrap()?.as_ref(), pair, expected)
        }
        pub(crate) fn with_original_module_only(
            &mut self,
            original: &NativeAssemblyModuleOnlyRead,
            pair: &Rc<NativePairIntentRead>,
            expected: &PairRecord,
            call: impl FnOnce(&mut LoadedWintun) -> Result<()>,
        ) -> Result<()> {
            self.verify_module_only_candidate(original, pair, expected)?;
            let result = self
                .root
                .bootstrap
                .as_mut()
                .ok_or(Error::Pending)?
                .with_original_module_only(original.bootstrap()?.as_ref(), pair, expected, call);
            self.verify_module_only_candidate(original, pair, expected)?;
            result
        }
        pub(crate) fn verify_module_only_load_read(
            &self,
            original: &NativeAssemblyModuleOnlyRead,
            pair: &Rc<NativePairIntentRead>,
            expected: &PairRecord,
            read: &Rc<crate::windows::member_carrier_module::native::NativeOriginalModuleLoadRead>,
        ) -> Result<()> {
            self.verify_module_only_candidate(original, pair, expected)?;
            self.root
                .bootstrap
                .as_ref()
                .ok_or(Error::Pending)?
                .verify_module_only_load_read(
                    original.bootstrap()?.as_ref(),
                    pair,
                    expected,
                    read,
                )?;
            self.verify_module_only_candidate(original, pair, expected)
        }
        pub(crate) fn retain_module_only_load_read_into(
            &self,
            original: &NativeAssemblyModuleOnlyRead,
            pair: &Rc<NativePairIntentRead>,
            expected: &PairRecord,
            destination: &mut Option<
                Rc<crate::windows::member_carrier_module::native::NativeOriginalModuleLoadRead>,
            >,
        ) -> Result<()> {
            self.verify_module_only_candidate(original, pair, expected)?;
            self.root
                .bootstrap
                .as_ref()
                .ok_or(Error::Pending)?
                .retain_module_only_load_read_into(
                    original.bootstrap()?.as_ref(),
                    pair,
                    expected,
                    destination,
                )?;
            self.verify_module_only_load_read(
                original,
                pair,
                expected,
                destination.as_ref().ok_or(Error::Pending)?,
            )
        }
        /// Root the actual source pin before ANY fallible journal-view read.
        /// One destination only; no replacement/equal-data capability minting.
        pub(crate) fn retain_initial_noc_read_into(
            &self,
            runtime: &Rc<RuntimeRead>,
            context: &Context,
            destination: &mut Option<Rc<NativeInitialAssemblyNoCRead>>,
        ) -> Result<()> {
            let (origin, initial) = self.root.claim_initial_noc_source()?;
            if destination.is_some()
                || self.assembly_attempted
                || self.prepare_call_attempted
                || self.precreation_call_attempted
                || self.member_call_attempted.iter().any(|attempt| *attempt)
                || self.incoming.is_some()
                || self.terminal_attempted
            {
                return Err(Error::Conflict);
            }
            *destination = Some(Rc::new(NativeInitialAssemblyNoCRead {
                origin,
                initial,
                initial_data: std::cell::RefCell::new(None),
                data_capture: TerminalCallState::new(),
                no_sdk: self.root.no_sdk.clone(),
                runtime: runtime.clone(),
                context: context.clone(),
                canonical: std::cell::RefCell::new(None),
                cleanup: crate::windows::member_carrier_terminal_release::TerminalCallState::new(),
            }));
            // Only original J/initial ACK/source are rooted here. DATA's
            // execution identity must be captured AFTER canonical cleanup.
            Ok(())
        }
        /// Exact owning cut after separately completed native own-DLL release.
        /// Native constructors/keys remain disjoint from this original source.
        pub(crate) fn drain_module_only_bootstrap<
            P: crate::windows::member_carrier_module::native::NativeNoConstructorModuleReleaseProof,
        >(
            &self,
            raw: &mut NativeAssemblyTerminalResources,
            original: &NativeAssemblyModuleOnlyRead,
            expected: &PairRecord,
            ack: &crate::windows::member_carrier_module::native::NativeNoConstructorModuleReleased<
                P,
            >,
            bootstrap: &mut crate::windows::member_carrier_bootstrap::native::NativeBootstrapTerminalResources,
        ) -> Result<()> {
            self.verify_terminal_drained_into(raw)?;
            if self.assembly_attempted
                || self.prepare_call_attempted
                || self.precreation_call_attempted
                || self.member_call_attempted.iter().any(|a| *a)
                || raw.incoming.is_some()
                || raw
                    .module_only_source
                    .as_ref()
                    .is_none_or(|source| !Rc::ptr_eq(source, &original.source))
            {
                return Err(Error::Conflict);
            }
            let parts = raw.parts.as_mut().ok_or(Error::Pending)?;
            self.root
                .verify_module_only_terminal_cut(parts, &original.source)?;
            parts
                .bootstrap
                .as_mut()
                .ok_or(Error::Pending)?
                .drain_no_constructor_after_release(
                    original.bootstrap()?.as_ref(),
                    expected,
                    ack,
                    bootstrap,
                )?;
            self.root
                .verify_module_only_terminal_cut(parts, &original.source)
        }
        pub(crate) fn verify_completed_no_constructor_release<
            P: crate::windows::member_carrier_module::native::NativeNoConstructorModuleReleaseProof,
        >(
            &self,
            original: &NativeAssemblyModuleOnlyRead,
            pair: &Rc<NativePairIntentRead>,
            expected: &PairRecord,
            ack: &crate::windows::member_carrier_module::native::NativeNoConstructorModuleReleased<
                P,
            >,
        ) -> Result<()> {
            self.verify_module_only_candidate(original, pair, expected)?;
            self.root
                .bootstrap
                .as_ref()
                .ok_or(Error::Pending)?
                .verify_completed_no_constructor_release(
                    original.bootstrap()?.as_ref(),
                    expected,
                    ack,
                )
        }
        pub(crate) fn verify_released_module_only_cut<
            P: crate::windows::member_carrier_module::native::NativeNoConstructorModuleReleaseProof,
        >(
            &self,
            raw: &NativeAssemblyTerminalResources,
            original: &NativeAssemblyModuleOnlyRead,
            ack: &crate::windows::member_carrier_module::native::NativeNoConstructorModuleReleased<
                P,
            >,
            bootstrap: &crate::windows::member_carrier_bootstrap::native::NativeBootstrapTerminalParts,
        ) -> Result<()> {
            self.verify_terminal_drained_into(raw)?;
            if self.assembly_attempted
                || self.prepare_call_attempted
                || self.precreation_call_attempted
                || self.member_call_attempted.iter().any(|a| *a)
                || raw.incoming.is_some()
                || raw
                    .module_only_source
                    .as_ref()
                    .is_none_or(|source| !Rc::ptr_eq(source, &original.source))
            {
                return Err(Error::Conflict);
            }
            let parts = raw.parts.as_ref().ok_or(Error::Pending)?;
            self.root
                .verify_module_only_terminal_cut(parts, &original.source)?;
            parts
                .bootstrap
                .as_ref()
                .ok_or(Error::Pending)?
                .verify_no_constructor_terminal_cut(bootstrap, original.bootstrap()?.as_ref(), ack)
        }

        /// Only actual initialized/no-SDK originals can have inert raw Drop.
        /// Native whole-Never terminal checks remain a separate prerequisite.
        pub(crate) fn verify_initial_noc_terminal_cut(
            &self,
            raw: &NativeAssemblyTerminalResources,
            original: &NativeInitialAssemblyNoCRead,
        ) -> Result<()> {
            self.verify_terminal_drained_into(raw)?;
            self.root
                .verify_initial_noc_original(&original.origin, &original.initial)?;
            if self.assembly_attempted
                || self.prepare_call_attempted
                || self.precreation_call_attempted
                || self.member_call_attempted.iter().any(|attempt| *attempt)
                || raw.incoming.is_some()
            {
                return Err(Error::Conflict);
            }
            let parts = raw.parts.as_ref().ok_or(Error::Pending)?;
            if parts
                .initial
                .as_ref()
                .is_none_or(|pin| !Rc::ptr_eq(pin, &original.initial))
                || parts.pending.is_none()
                || parts
                    .io
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .is_some()
                || parts
                    .owner
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .is_some()
                || parts
                    .assets
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .is_some()
                || parts.bootstrap.is_none()
                || parts.disabled.is_some()
                || parts.closing.is_some()
                || parts.member_disabled.iter().any(Option::is_some)
                || parts.member_key_retired.iter().any(Option::is_some)
            {
                return Err(Error::Conflict);
            }
            original.verify_origin(&original.runtime, &original.context)
        }
        /// Borrow the SAME canonical key owner without moving it into Result.
        /// Caller must hold the original terminal Pair/Calling/full SDK lease;
        /// NativeOwnership and each native close fence authenticate that lease.
        /// This access itself grants neither native close nor owner destruction.
        pub(crate) fn with_original_terminal_key_owner<T>(
            &mut self,
            call: impl FnOnce(&mut KeyOwner) -> Result<T>,
        ) -> Result<T> {
            if self.terminal_attempted {
                return Err(Error::Retired);
            }
            self.root.with_original_terminal_owner(call)
        }
        /// No key/native/module permission: proves this wrapper, and ONLY this
        /// wrapper, transferred every owning slot into SAME retained raw.
        pub(crate) fn verify_terminal_drained_into(
            &self,
            raw: &NativeAssemblyTerminalResources,
        ) -> Result<()> {
            if !self.terminal_attempted
                || self.incoming.is_some()
                || self.module_only_source.is_some()
            {
                return Err(Error::Conflict);
            }
            if let Some(source) = &raw.module_only_source {
                if !Rc::ptr_eq(&source.origin, &self.root.origin)
                    || !Rc::ptr_eq(&source.selected, &self.root.module_only_selection)
                    || raw
                        .parts
                        .as_ref()
                        .and_then(|p| p.initial.as_ref())
                        .is_none_or(|actual| !Rc::ptr_eq(actual, &source.initial))
                {
                    return Err(Error::Conflict);
                }
            }
            self.root
                .verify_drained_original(raw.parts.as_ref().ok_or(Error::Pending)?)
        }
        pub(crate) fn new(context: Context, journal: NativeJournalStore) -> Self {
            Self {
                root: Assembly::new(context, journal, NativeBootstrapSlot::empty()),
                incoming: None,
                assembly_attempted: false,
                prepare_call_attempted: false,
                precreation_call_attempted: false,
                member_call_attempted: [false; 2],
                assembled: false,
                prepared: false,
                terminal_attempted: false,
                module_only_source: None,
            }
        }
        /// FIRST: initialize/read_pin, before key IO or cold DLL effects.
        /// Destination MUST be a field of caller-retained TerminalResources.
        /// This cuts the Assembly wrapper, not private Bootstrap/Keys owners.
        pub(crate) fn drain_terminal_into(
            &mut self,
            destination: &mut Option<NativeAssemblyTerminalResources>,
        ) -> Result<()> {
            self.assembled = false;
            self.prepared = false;
            let mut root_attempted = self.terminal_attempted;
            // Fence this native wrapper even if portable nested transfer fails.
            self.terminal_attempted = true;
            drain_before_postflight(
                &mut root_attempted,
                destination,
                || NativeAssemblyTerminalResources {
                    parts: None,
                    incoming: None,
                    module_only_source: None,
                },
                |raw| {
                    raw.incoming = self.incoming.take();
                    raw.module_only_source = self.module_only_source.take();
                },
                |_| Ok(()),
            )?;
            self.root.drain_terminal_into(
                &mut destination.as_mut().expect("retained assembly raw").parts,
                |_| Ok(()),
            )
        }
        pub(crate) fn initialize(&mut self) -> Result<()> {
            self.root.initialize()
        }

        /// Main passes this ORIGINAL opaque pin to the existing load_cold.
        /// The first pin stays retained here; neither creates native permission.
        pub(crate) fn initial_read_pin(&self) -> Result<InitialRead<NativeJournalStore>> {
            if !self.root.initialized || self.assembly_attempted {
                return Err(Error::Retired);
            }
            self.root.pending.as_ref().ok_or(Error::Pending)?.read_pin()
        }
        /// Main calls existing load_cold then compose_originals on this SAME
        /// retained slot with its actual RuntimeRead/KeyLock/Pair/signal inputs.
        pub(crate) fn bootstrap_mut(&mut self) -> Result<&mut NativeBootstrapSlot> {
            if self.module_only_source.is_none() {
                self.root
                    .retain_module_only_source_into(&mut self.module_only_source, |_| Ok(()))?;
            }
            self.root.no_sdk.set(false);
            if !self.root.initialized || self.assembly_attempted {
                return Err(Error::Retired);
            }
            self.root.bootstrap.as_mut().ok_or(Error::Pending)
        }
        /// Transfer, split and attach under the ORIGINAL whole CarrierReady
        /// ACK and SAME supervisor. This performs no NIC, address or G effect.
        pub(crate) fn assemble(
            &mut self,
            lock: &mut KeyLock,
            original_pair_intent: &Rc<NativePairIntentRead>,
        ) -> Result<()> {
            self.root.module_only_allowed.set(false);
            self.root.no_sdk.set(false);
            enter(&mut self.assembly_attempted)?;
            if !self.root.initialized {
                return Err(Error::Pending);
            }
            let originals = self
                .root
                .bootstrap
                .as_ref()
                .ok_or(Error::Pending)?
                .originals()?;
            let supervisor = originals.supervisor.clone();
            let context = originals.context.clone();
            let expected = originals.expected.clone();
            // Main already retains the original Rc minted by its SAME store.
            // take_for_assembly checks bootstrap's own original Pair/Calling;
            // after retaining that transfer, typed Rc identity joins the two
            // pins before any attachment or registry key effect is attempted.
            let intent = original_pair_intent.clone();
            let cancelled = originals.cancelled.clone();
            // No callback may return an owning BootstrapAssets/Keys/KeyOwner:
            // postflight failure must leave them in the caller's retained root.
            supervisor.run_intent(
                &context,
                &intent,
                &expected,
                pair::Effect::CarrierReady,
                || {
                    check_cancelled(&cancelled)?;
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step(
                        "assembly begin original transfer",
                    );
                    self.incoming = Some(
                        self.root
                            .bootstrap
                            .as_mut()
                            .ok_or(Error::Pending)?
                            .take_for_assembly(lock)?,
                    );
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step(
                        "assembly end original transfer",
                    );
                    if !Rc::ptr_eq(
                        &self.incoming.as_ref().ok_or(Error::Pending)?.pair_intent,
                        &intent,
                    ) {
                        return Err(Error::Conflict);
                    }
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step(
                        "assembly begin split keys",
                    );
                    self.split_keys()?;
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step(
                        "assembly end split keys",
                    );
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step(
                        "assembly begin original attach",
                    );
                    self.root.attach_keys(lock)?;
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step(
                        "assembly end original attach",
                    );
                    check_cancelled(&cancelled)
                },
            )?;
            self.assembled = true;
            Ok(())
        }
        fn split_keys(&mut self) -> Result<()> {
            if self.root.assets.is_some() || self.root.io.is_some() || self.root.owner.is_some() {
                return Err(Error::Conflict);
            }
            // Allocation/clone happens while ALL owners still occupy incoming.
            let key_context = self
                .incoming
                .as_ref()
                .expect("retained bootstrap assets")
                .context
                .clone();
            let BootstrapAssets {
                module,
                runtime,
                image,
                producer,
                observer,
                members,
                key_authority,
                context,
                expected,
                source,
                supervisor,
                cancelled,
                pair_intent,
            } = self.incoming.take().expect("retained bootstrap assets");
            // From this destructure to installing BOTH slots: infallible moves
            // only. In particular Keys::new has no Result or native callbacks.
            self.root.assets = Some(NativeAssemblyAssets {
                module,
                runtime,
                image,
                producer,
                observer,
                members,
                context,
                expected,
                source,
                supervisor,
                cancelled,
                pair_intent,
            });
            self.root.io = Some(
                Keys::<win32::Kernel, KeyAuthority<OriginalKeyInventory>>::new(
                    win32::Kernel,
                    key_authority,
                    key_context,
                ),
            );
            Ok(())
        }
        /// Actual prepareCkeys. Every durable step uses the SAME supervisor;
        /// returned handles stay in the original owner through all postflights.
        pub(crate) fn prepare_carrier(&mut self, lock: &mut KeyLock) -> Result<()> {
            self.root.module_only_allowed.set(false);
            enter(&mut self.prepare_call_attempted)?;
            if !self.assembled {
                return Err(Error::Pending);
            }
            let assets = self.root.assets.as_ref().ok_or(Error::Pending)?;
            if !assets.runtime.matches_lock(lock) {
                return Err(Error::Conflict);
            }
            let supervisor = assets.supervisor.clone();
            let intent = assets.pair_intent.clone();
            let context = assets.context.clone();
            let expected = assets.expected.clone();
            let cancelled = assets.cancelled.clone();
            self.root.prepare_carrier_in(lock, |call| {
                supervisor.run_intent(
                    &context,
                    &intent,
                    &expected,
                    pair::Effect::CarrierReady,
                    || {
                        check_cancelled(&cancelled)?;
                        call()?;
                        check_cancelled(&cancelled)
                    },
                )
            })?;
            self.prepared = true;
            Ok(())
        }
        /// Independently supervised precreation read, then caller's existing
        /// G/carrier steps under the SAME supervisor and original borrowed ACK.
        /// Scope is derived only from the actual CURRENT borrowed Disabled
        /// receipt, never from bootstrap or a future predicted revision.
        /// Callback returns only (), and must retain every owning construction
        /// output in main's caller-owned slots before its own Err/unwind.
        pub(crate) fn with_carrier_precreation(
            &mut self,
            lock: &mut KeyLock,
            call: impl FnOnce(
                &mut Option<NativeAssemblyAssets>,
                NativePrecreation<'_>,
                creators::Scope,
            ) -> Result<()>,
        ) -> Result<()> {
            self.root.module_only_allowed.set(false);
            enter(&mut self.precreation_call_attempted)?;
            if !self.prepared {
                return Err(Error::Pending);
            }
            let assets = self.root.assets.as_ref().ok_or(Error::Pending)?;
            let supervisor = assets.supervisor.clone();
            let intent = assets.pair_intent.clone();
            let context = assets.context.clone();
            let expected = assets.expected.clone();
            let cancelled = assets.cancelled.clone();
            if !assets.runtime.matches_lock(lock) {
                return Err(Error::Conflict);
            }
            self.root.with_precreation_in(
                lock,
                &mut |body| {
                    supervisor.run_intent(
                        &context,
                        &intent,
                        &expected,
                        pair::Effect::CarrierReady,
                        || {
                            check_cancelled(&cancelled)?;
                            body()?;
                            check_cancelled(&cancelled)
                        },
                    )
                },
                |assets, receipt, generation| {
                    let scope = creators::Scope {
                        context: receipt.record.context.clone(),
                        binding: receipt.binding.clone(),
                        generation,
                    };
                    call(assets, receipt, scope)
                },
            )
        }
        /// Actual mutable key owner and remaining assets, including partial
        /// failure state, for main's independent G/CarrierPairIo and cleanup.
        /// Merely borrowing these objects supplies no effect/forward authority.
        pub(crate) fn retained_parts(
            &mut self,
        ) -> (&mut Option<KeyOwner>, &mut Option<NativeAssemblyAssets>) {
            (&mut self.root.owner, &mut self.root.assets)
        }

        /// Journal-only bridge before NativeDeadline::run_cleanup. That
        /// supervisor deliberately requires the actual native Closing record
        /// BEFORE arming any SDK cleanup. Original Pair CAS + held lease/key
        /// owner authenticate this transition; no native effect occurs here.
        pub(crate) fn begin_cleanup(
            &mut self,
            lock: &mut KeyLock,
            runtime: &RuntimeRead,
            intent: &Rc<NativePairIntentRead>,
        ) -> Result<()> {
            self.root.member_cleanup_only = true;
            if !runtime.matches_lock(lock) || !intent.matches_runtime(runtime) {
                return Err(Error::Conflict);
            }
            let current = self
                .root
                .owner
                .as_mut()
                .ok_or(Error::Pending)?
                .snapshot()?
                .ok_or(Error::Pending)?;
            runtime.verify(&current.context)?;
            intent
                .verify_cleanup_entry(runtime, &current.context)
                .map_err(|_| Error::Conflict)?;
            self.root.begin_cleanup(lock)?;
            intent
                .verify_cleanup_entry(runtime, &current.context)
                .map_err(|_| Error::Conflict)?;
            runtime.verify(&current.context)
        }

        /// Actual A/B key preparation after C assets transferred to ReadyRoot.
        /// Only the SAME Source/Runtime/lock/Calling is accepted; owning member
        /// outputs must be installed in the caller's retained slot in `call`.
        /// MemberController's concrete G remains separately mandatory.
        pub(crate) fn restore_member_key_in_call(
            &mut self,
            lock: &mut KeyLock,
            pins: &crate::windows::member_carrier_ready::native::NativeCarrierPins,
            intent: &Rc<NativePairIntentRead>,
            expected: &PairRecord,
            role: receipt::Role,
        ) -> Result<()> {
            let slot = match role {
                receipt::Role::MemberA => nelomai_contracts::dispatcher::TunnelSlot::A,
                receipt::Role::MemberB => nelomai_contracts::dispatcher::TunnelSlot::B,
                receipt::Role::RoleCarrier => return Err(Error::Retired),
            };
            if !self.prepared
                || self.root.member_cleanup_only
                || !pins.runtime.matches_lock(lock)
                || !intent.matches_runtime(&pins.runtime)
            {
                return Err(Error::Conflict);
            }
            let check = || -> Result<()> {
                check_cancelled(&pins.cancelled)?;
                intent
                    .inspect_effect(
                        &pins.runtime,
                        &pins.supervisor,
                        expected,
                        pair::Effect::RestoreKeys,
                        |_| Ok(()),
                    )
                    .map_err(|_| Error::Conflict)?;
                pins.source
                    .inspect_window(|window| {
                        if !window.matches_source(&pins.source)
                            || !window.matches_runtime(&pins.runtime)
                        {
                            return Err(super::super::member_carrier_wintun::Error::Conflict);
                        }
                        let closed = window
                            .closed_member(slot)
                            .ok_or(super::super::member_carrier_wintun::Error::Conflict)?;
                        let bindings = window.bindings();
                        validate_member_restore_window(
                            &pins.context,
                            expected,
                            role,
                            bindings
                                .carrier
                                .as_ref()
                                .ok_or(super::super::member_carrier_wintun::Error::Conflict)?,
                            &bindings.egress,
                            (&closed.intent, closed.proof),
                        )
                        .map_err(|_| super::super::member_carrier_wintun::Error::Conflict)
                    })
                    .map_err(|_| Error::Conflict)
            };
            check()?;
            // Do not enclose private journal CAS/registry effects in a Source
            // read bracket. Keys independently reattests actual native absence
            // and the SAME originally-created retained handle on every effect.
            self.root.restore_member_key(role, lock)?;
            check()
        }

        /// SAME supervisor for each durable key step and the final native create.
        pub(crate) fn with_member_precreation(
            &mut self,
            lock: &mut KeyLock,
            pins: &crate::windows::member_carrier_ready::native::NativeCarrierPins,
            intent: &Rc<NativePairIntentRead>,
            expected: &PairRecord,
            role: receipt::Role,
            call: impl FnOnce(NativePrecreation<'_>, creators::Scope) -> Result<()>,
        ) -> Result<()> {
            let (index, target) = match role {
                receipt::Role::MemberA => (0, nelomai_client_tunnel::redundancy::Slot::A),
                receipt::Role::MemberB => (1, nelomai_client_tunnel::redundancy::Slot::B),
                receipt::Role::RoleCarrier => return Err(Error::Retired),
            };
            if self.member_call_attempted[index] && self.root.member_key_retired[index].is_none() {
                return Err(Error::Retired);
            }
            self.member_call_attempted[index] = true;
            if !self.prepared
                || !pins.runtime.matches_lock(lock)
                || !intent.matches_runtime(&pins.runtime)
            {
                return Err(Error::Conflict);
            }
            let effect = pair::Effect::MemberStart(target);
            let check =
                || -> Result<()> {
                    intent
                        .inspect_effect(&pins.runtime, &pins.supervisor, expected, effect, |_| {
                            Ok(())
                        })
                        .map_err(|_| Error::Conflict)?;
                    pins.source
                        .inspect_bindings(|bindings| {
                            validate_member_key_window(
                                &pins.context,
                                expected,
                                role,
                                bindings
                                    .carrier
                                    .as_ref()
                                    .ok_or(super::super::member_carrier_wintun::Error::Conflict)?,
                                &bindings.egress,
                            )
                            .map_err(|_| super::super::member_carrier_wintun::Error::Conflict)
                        })
                        .map_err(|_| Error::Conflict)
                };
            self.root.with_member_precreation_in(
                role,
                lock,
                &mut |call| {
                    pins.supervisor
                        .run_intent(&pins.context, intent, expected, effect, || {
                            check_cancelled(&pins.cancelled)?;
                            check()?;
                            call()?;
                            // A final callback may have started the member. Read the
                            // full original Source, not the pre-NIC egress shape.
                            pins.source
                                .inspect(|c| {
                                    if Some(c.identity.proof) != expected.carrier
                                        || c.identity.scope != expected.scope
                                        || c.sources
                                            != expected
                                                .addresses
                                                .iter()
                                                .map(|a| a.addr())
                                                .collect::<Vec<_>>()
                                    {
                                        return Err(
                                            super::super::member_carrier_wintun::Error::Conflict,
                                        );
                                    }
                                    Ok(())
                                })
                                .map_err(|_| Error::Conflict)?;
                            check_cancelled(&pins.cancelled)
                        })
                },
                |receipt| {
                    // Registry changes advance NativeReceipt revision. A fresh
                    // read-only source bracket follows them, never encloses CAS.
                    check()?;
                    let scope = creators::Scope {
                        context: receipt.record.context.clone(),
                        binding: receipt.binding.clone(),
                        generation: receipt.record.generation,
                    };
                    if scope.context != pins.context {
                        return Err(Error::Conflict);
                    }
                    call(receipt, scope)
                },
            )
        }
    }
    impl Drop for NativeAssemblySlot {
        fn drop(&mut self) {
            retain_unknown(&mut self.incoming);
        }
    }
    fn check_cancelled(signal: &AtomicBool) -> Result<()> {
        if signal.load(Ordering::Acquire) {
            Err(Error::Retired)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "member_carrier_assembly_tests.rs"]
mod tests;
