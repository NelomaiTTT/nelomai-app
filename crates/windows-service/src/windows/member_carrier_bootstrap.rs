//! Actual cold bootstrap composition; main owns lifecycle permission and wiring.
#![allow(dead_code)]

#[cfg(windows)]
use super::member_carrier_terminal_release::TerminalCallState;
#[cfg(not(windows))]
use crate::member_carrier_terminal_release::TerminalCallState;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum LoadError<E> {
    AlreadyAttempted,
    MissingAcknowledgement,
    Boundary(E),
}

/// Retention/one-attempt bookkeeping only. This supplies no authentication,
/// native permission, watchdog, or successful boundary implementation.
pub(super) struct LoadSlot<T> {
    attempted: bool,
    pub(super) acknowledged: Option<T>,
    origin: std::rc::Rc<()>,
    terminal_attempted: bool,
    load_returned: std::rc::Rc<std::cell::Cell<bool>>,
    module_only_capture: std::rc::Rc<TerminalCallState>,
    module_only_selected: std::cell::Cell<bool>,
}
/// Successful ORIGINAL loader boundary return only. NOT a LoadLibrary ACK,
/// module/image constructor, no-C SDK absence or unload/disposal permission.
/// The concrete LoadedWintun must independently supply its opaque native ACK.
pub(crate) struct ModuleOnlyLoadRead {
    origin: std::rc::Rc<()>,
    returned: std::rc::Rc<std::cell::Cell<bool>>,
    capture: std::rc::Rc<TerminalCallState>,
    call: TerminalCallState,
}
impl ModuleOnlyLoadRead {
    fn same_loader<T>(&self, source: &LoadSlot<T>) -> bool {
        std::rc::Rc::ptr_eq(&self.origin, &source.origin)
            && std::rc::Rc::ptr_eq(&self.returned, &source.load_returned)
            && std::rc::Rc::ptr_eq(&self.capture, &source.module_only_capture)
    }
}
/// Raw SAME owning return, held only by a caller-retained terminal destination.
/// No custom unknown Drop is carried into inert T. This is NOT a native-close
/// ACK: the actual loader must remain separately owned outside resource T.
pub(super) struct TerminalLoad<T> {
    origin: std::rc::Rc<()>,
    pub(super) attempted: bool,
    pub(super) acknowledged: Option<T>,
    module_transfer: Option<std::rc::Rc<()>>,
}
/// Exact owning module wrapper outside resource T. No native handle, image or
/// ACK is synthesized here; an absent internal return remains absent.
pub(crate) struct TerminalModule<T> {
    origin: std::rc::Rc<()>,
    transfer: std::rc::Rc<()>,
    original: Option<T>,
}
impl<T> TerminalModule<T> {
    fn original(&self) -> Result<&T, LoadError<()>> {
        self.original
            .as_ref()
            .ok_or(LoadError::MissingAcknowledgement)
    }
    fn original_mut(&mut self) -> Result<&mut T, LoadError<()>> {
        self.original
            .as_mut()
            .ok_or(LoadError::MissingAcknowledgement)
    }
}
impl<T> TerminalLoad<T> {
    fn separate_module_into<E>(
        &mut self,
        destination: &mut Vec<TerminalModule<T>>,
        postflight: impl FnOnce(&TerminalModule<T>) -> Result<(), E>,
    ) -> Result<(), LoadError<E>> {
        if self.module_transfer.is_some() {
            return Err(LoadError::AlreadyAttempted);
        }
        // Reserve before taking ANY original. An allocation unwind leaves the
        // source owning wrapper untouched in its retained raw destination.
        destination.reserve(1);
        let transfer = std::rc::Rc::new(());
        self.module_transfer = Some(transfer.clone());
        destination.push(TerminalModule {
            origin: self.origin.clone(),
            transfer,
            original: self.acknowledged.take(),
        });
        postflight(destination.last().expect("retained original module"))
            .map_err(LoadError::Boundary)
    }
    fn verify_module_transfer(&self, module: &TerminalModule<T>) -> Result<(), LoadError<()>> {
        if self.acknowledged.is_some()
            || !std::rc::Rc::ptr_eq(&self.origin, &module.origin)
            || !self
                .module_transfer
                .as_ref()
                .is_some_and(|original| std::rc::Rc::ptr_eq(original, &module.transfer))
        {
            return Err(LoadError::AlreadyAttempted);
        }
        Ok(())
    }
}
impl<T> LoadSlot<T> {
    pub(super) fn empty() -> Self {
        Self {
            attempted: false,
            acknowledged: None,
            origin: std::rc::Rc::new(()),
            terminal_attempted: false,
            load_returned: std::rc::Rc::new(std::cell::Cell::new(false)),
            module_only_capture: std::rc::Rc::new(TerminalCallState::new()),
            module_only_selected: std::cell::Cell::new(false),
        }
    }
    fn retain_module_only_read_into<E>(
        &self,
        destination: &mut Option<std::rc::Rc<ModuleOnlyLoadRead>>,
        postflight: impl FnOnce(&ModuleOnlyLoadRead) -> Result<(), E>,
    ) -> Result<(), LoadError<E>> {
        let mut callback_error = None;
        let result = self.module_only_capture.run(|| {
            self.module_only_selected.set(true);
            if destination.is_some() {
                return Err(std::io::Error::other("module_only_duplicate"));
            }
            *destination = Some(std::rc::Rc::new(ModuleOnlyLoadRead {
                origin: self.origin.clone(),
                returned: self.load_returned.clone(),
                capture: self.module_only_capture.clone(),
                call: TerminalCallState::new(),
            }));
            if self.terminal_attempted || !self.load_returned.get() || self.acknowledged.is_none() {
                return Err(std::io::Error::other("module_only_unknown_load"));
            }
            if let Err(error) = postflight(destination.as_ref().expect("retained module-only read"))
            {
                callback_error = Some(error);
                return Err(std::io::Error::other("module_only_postflight"));
            }
            Ok(())
        });
        if let Some(error) = callback_error {
            return Err(LoadError::Boundary(error));
        }
        result.map_err(|_| LoadError::AlreadyAttempted)
    }
    fn verify_module_only_read(&self, read: &ModuleOnlyLoadRead) -> Result<(), LoadError<()>> {
        if !read.same_loader(self) || !self.load_returned.get() || self.acknowledged.is_none() {
            return Err(LoadError::MissingAcknowledgement);
        }
        read.capture
            .verify()
            .map_err(|_| LoadError::AlreadyAttempted)
    }
    fn with_original_module_only<E>(
        &mut self,
        read: &ModuleOnlyLoadRead,
        call: impl FnOnce(&mut T) -> Result<(), E>,
    ) -> Result<(), LoadError<E>> {
        let mut callback_error = None;
        let result = read.call.run(|| {
            self.verify_module_only_read(read)
                .map_err(|_| std::io::Error::other("module_only_original"))?;
            if let Err(error) = call(
                self.acknowledged
                    .as_mut()
                    .ok_or_else(|| std::io::Error::other("module_only_owner"))?,
            ) {
                callback_error = Some(error);
            }
            self.verify_module_only_read(read)
                .map_err(|_| std::io::Error::other("module_only_original"))?;
            if callback_error.is_some() {
                return Err(std::io::Error::other("module_only_callback"));
            }
            Ok(())
        });
        if let Some(error) = callback_error {
            return Err(LoadError::Boundary(error));
        }
        result.map_err(|_| LoadError::AlreadyAttempted)
    }
    /// Ownership only. The native caller uses a retained TerminalResources
    /// field; error/unwind leaves the exact return there before any callback.
    fn drain_terminal_into<E>(
        &mut self,
        destination: &mut Option<TerminalLoad<T>>,
        postflight: impl FnOnce(&TerminalLoad<T>) -> Result<(), E>,
    ) -> Result<(), LoadError<E>> {
        if std::mem::replace(&mut self.terminal_attempted, true) || destination.is_some() {
            return Err(LoadError::AlreadyAttempted);
        }
        *destination = Some(TerminalLoad {
            origin: self.origin.clone(),
            attempted: self.attempted,
            acknowledged: self.acknowledged.take(),
            module_transfer: None,
        });
        postflight(destination.as_ref().expect("retained same load original"))
            .map_err(LoadError::Boundary)
    }
    fn verify_terminal_transfer(&self, original: &TerminalLoad<T>) -> Result<(), LoadError<()>> {
        if !self.terminal_attempted
            || self.acknowledged.is_some()
            || self.attempted != original.attempted
            || !std::rc::Rc::ptr_eq(&self.origin, &original.origin)
        {
            return Err(LoadError::AlreadyAttempted);
        }
        Ok(())
    }
    /// Comparison-only original owner aperture, not the once-only effect borrow.
    fn verify_module_only_terminal_cut<E>(
        &self,
        raw: &TerminalLoad<T>,
        read: &ModuleOnlyLoadRead,
        verify_native_ack: impl FnOnce(&T) -> Result<(), E>,
    ) -> Result<(), LoadError<E>> {
        self.verify_terminal_transfer(raw)
            .map_err(|_| LoadError::AlreadyAttempted)?;
        if !read.same_loader(self)
            || !self.load_returned.get()
            || !raw.attempted
            || raw.module_transfer.is_some()
        {
            return Err(LoadError::MissingAcknowledgement);
        }
        read.capture
            .verify()
            .map_err(|_| LoadError::AlreadyAttempted)?;
        read.call
            .verify()
            .map_err(|_| LoadError::AlreadyAttempted)?;
        verify_native_ack(
            raw.acknowledged
                .as_ref()
                .ok_or(LoadError::MissingAcknowledgement)?,
        )
        .map_err(LoadError::Boundary)
    }

    /// Comparison-only original owner aperture, not the once-only effect borrow.
    /// The concrete loader must separately compare its actual native ACK pin.
    fn verify_original_loaded_read<E>(
        &self,
        read: &ModuleOnlyLoadRead,
        verify: impl FnOnce(&T) -> Result<(), E>,
    ) -> Result<(), LoadError<E>> {
        if self.terminal_attempted {
            return Err(LoadError::AlreadyAttempted);
        }
        self.verify_module_only_read(read)
            .map_err(|_| LoadError::MissingAcknowledgement)?;
        verify(
            self.acknowledged
                .as_ref()
                .ok_or(LoadError::MissingAcknowledgement)?,
        )
        .map_err(LoadError::Boundary)
    }
    pub(super) fn load_into<S, E>(
        &mut self,
        state: &mut S,
        before: impl FnOnce(&mut S) -> Result<(), E>,
        load: impl FnOnce(&mut S, &mut Option<T>) -> Result<(), E>,
        after: impl FnOnce(&mut S, &mut T) -> Result<(), E>,
    ) -> Result<(), LoadError<E>> {
        if self.terminal_attempted
            || self.attempted
            || self.module_only_selected.get()
            || self.acknowledged.is_some()
        {
            return Err(LoadError::AlreadyAttempted);
        }
        self.attempted = true;
        before(state).map_err(LoadError::Boundary)?;
        load(state, &mut self.acknowledged).map_err(LoadError::Boundary)?;
        self.load_returned.set(true);
        let original = self
            .acknowledged
            .as_mut()
            .ok_or(LoadError::MissingAcknowledgement)?;
        after(state, original).map_err(LoadError::Boundary)
    }
    #[cfg(test)]
    pub(super) fn load<S, E>(
        &mut self,
        state: &mut S,
        before: impl FnOnce(&mut S) -> Result<(), E>,
        load: impl FnOnce(&mut S) -> Result<T, E>,
        after: impl FnOnce(&mut S, &mut T) -> Result<(), E>,
    ) -> Result<(), LoadError<E>> {
        if self.terminal_attempted || self.attempted || self.module_only_selected.get() {
            return Err(LoadError::AlreadyAttempted);
        }
        self.attempted = true;
        before(state).map_err(LoadError::Boundary)?;
        self.acknowledged = Some(load(state).map_err(LoadError::Boundary)?);
        self.load_returned.set(true);
        after(
            state,
            self.acknowledged.as_mut().expect("just retained SDK ACK"),
        )
        .map_err(LoadError::Boundary)?;
        Ok(())
    }
}
impl<T> Drop for LoadSlot<T> {
    fn drop(&mut self) {
        if let Some(value) = self.acknowledged.take() {
            // Only independently authorized explicit cleanup may release an
            // unknown native obligation. Abandonment retains it to process exit.
            std::mem::forget(value);
        }
    }
}

#[cfg(windows)]
pub(crate) mod native {
    use super::{LoadError, LoadSlot, ModuleOnlyLoadRead, TerminalLoad, TerminalModule};
    use crate::member_carrier::{CarrierError as Error, Result};
    use crate::member_carrier_native_ownership::{
        self as receipts, Context, InitialRead, KeyPhase,
    };
    use crate::member_carrier_pair::{self as pair, Record as PairRecord};
    use crate::windows::{
        member_carrier_assembly::TerminalResources,
        member_carrier_creators::{self as creators, Producer},
        member_carrier_key_authority::{KeyAuthority, KeyLock, RuntimeRead},
        member_carrier_members::native::{MemberInventory, MemberInventoryRead},
        member_carrier_module::{
            self as module,
            native::{LoadedWintun, OriginalImage},
        },
        member_carrier_pair_store::native_store::{NativeCarrierPairStore, NativePairIntentRead},
        member_carrier_payload::native::WintunSource,
        member_carrier_preload::native::WintunPreload,
        member_carrier_wintun::native::{OriginalKeyInventory, OriginalUniverse, OriginalWintun},
        member_native_deadline::{NativeDeadline, NativeDeadlineReadPin},
        member_session::{
            InitialDataRetirementAck, InitialNativeDataRead, NativeSessionFiles,
            OriginalInitialNativeDataRetirement, RecordKind, WindowsNativeCarrierReceiptStore,
        },
    };
    use sha2::{Digest, Sha256};
    use std::{
        rc::Rc,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };

    struct Inputs {
        runtime: RuntimeRead,
        files: NativeSessionFiles,
        source: Rc<WintunSource>,
        context: Context,
        expected: PairRecord,
        intent: Rc<NativePairIntentRead>,
        initial: InitialRead<WindowsNativeCarrierReceiptStore<NativeSessionFiles>>,
        native_bytes: Vec<u8>,
        supervisor: Rc<NativeDeadline>,
        deadline: NativeDeadlineReadPin,
        cancelled: Arc<AtomicBool>,
    }
    impl Inputs {
        fn current(&self) -> Result<()> {
            cancelled(&self.cancelled)?;
            self.runtime
                .verify_same_session_files(&self.context, &self.files)?;
            self.runtime.verify_source(&self.source)?;
            self.deadline
                .verify_runtime(&self.supervisor, &self.runtime, &self.context)?;
            if !self.runtime.fresh(&self.context)? {
                return Err(Error::Retired);
            }
            let current = read_original_initial(&self.runtime, &self.context, &self.initial)?;
            if current != self.native_bytes {
                return Err(Error::Conflict);
            }
            self.runtime
                .verify_same_session_files(&self.context, &self.files)?;
            cancelled(&self.cancelled)
        }
        fn calling(&self) -> Result<()> {
            self.deadline.verify_call(&self.supervisor, &self.context)?;
            self.current()?;
            // This is the ORIGINAL acknowledged whole Pair window, freshly
            // reread before the load and again after it. inspect_effect is a
            // READ-ONLY callback; the DLL load is never hidden inside it.
            self.intent
                .inspect_effect(
                    &self.runtime,
                    &self.supervisor,
                    &self.expected,
                    pair::Effect::CarrierReady,
                    |record| {
                        if record != &self.expected {
                            return Err(std::io::Error::other("bootstrap_pair_changed"));
                        }
                        Ok(())
                    },
                )
                .map_err(|_| Error::Conflict)?;
            self.current()?;
            self.deadline.verify_call(&self.supervisor, &self.context)
        }
    }

    /// One caller-owned slot for the entire attempt. Never return this slot
    /// through a fallible supervisor Result. Keep it in the actual actor before
    /// calling bootstrap; partial fields are native cleanup obligations.
    ///
    /// The loader writes its owning wrapper into this retained slot before the
    /// OS load and retains the actual module inside it before post-load queries.
    /// An error or unwind cannot discard an internally acknowledged module.
    pub(crate) struct NativeBootstrapSlot {
        inputs: Option<Rc<Inputs>>,
        module: LoadSlot<LoadedWintun>,
        preload: Option<WintunPreload>,
        image: Option<OriginalImage>,
        members: Option<MemberInventoryRead>,
        registry: Option<(Producer<OriginalWintun>, creators::Observer<OriginalWintun>)>,
        keys: Option<KeyAuthority<OriginalKeyInventory>>,
        cold_verified: bool,
        compose_attempted: bool,
        ready: bool,
        transferred: bool,
        terminal_origin: Rc<()>,
        terminal_attempted: bool,
    }
    impl NativeBootstrapSlot {
        pub(crate) fn empty() -> Self {
            Self {
                inputs: None,
                module: LoadSlot::empty(),
                preload: None,
                image: None,
                members: None,
                registry: None,
                keys: None,
                cold_verified: false,
                compose_attempted: false,
                ready: false,
                transferred: false,
                terminal_origin: Rc::new(()),
                terminal_attempted: false,
            }
        }

        /// Uses only authenticated ORIGINAL inputs. Source construction by main
        /// uses WintunSource::new(root, SAME Arc<MutationGuard>); RuntimeRead
        /// verifies its pointer-bound owner and original private SessionFiles.
        /// The supervisor and signal are the SAME actual actor's retained ones;
        /// this function neither creates a watchdog nor a replacement false flag.
        /// There is no record publication, HKEY/native NIC/session/address/WFP/
        /// route/DNS/service effect here. Only the audited cold DLL loader runs.
        #[allow(clippy::too_many_arguments)]
        pub(crate) fn load_cold(
            &mut self,
            runtime: &RuntimeRead,
            lock: &mut KeyLock,
            store: &mut NativeCarrierPairStore,
            files: &NativeSessionFiles,
            source: &Rc<WintunSource>,
            context: &Context,
            expected: &PairRecord,
            original_intent: Rc<NativePairIntentRead>,
            logical_configuration: &str,
            supervisor: &Rc<NativeDeadline>,
            actor_cancelled: &Arc<AtomicBool>,
            initial: InitialRead<WindowsNativeCarrierReceiptStore<NativeSessionFiles>>,
        ) -> Result<()> {
            macro_rules! step {
                ($label:literal, $result:expr) => {{
                    let value = $result.inspect_err(|_error| {
                        #[cfg(test)]
                        super::super::member_carrier_factory_test_os::trace_native($label, _error);
                    })?;
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step($label);
                    value
                }};
            }
            if self.terminal_attempted
                || self.inputs.is_some()
                || self.module.attempted
                || self.transferred
            {
                return Err(Error::Pending);
            }
            cancelled(actor_cancelled)?;
            step!(
                "cold load requested CarrierReady frame",
                validate_requested(context, expected, logical_configuration)
            );
            if !runtime.matches_lock(lock) {
                return Err(Error::Conflict);
            }
            step!(
                "cold load same storage",
                runtime.verify_same_session_files(context, files)
            );
            step!("cold load original source", runtime.verify_source(source));
            step!("cold load original lock", lock.verify_source(source));
            if !runtime.fresh(context)? {
                return Err(Error::Retired);
            }
            // Use the actor's SAME opaque publication Rc. A fresh equal pin
            // would fail the later Assembly pointer join, and equal protected
            // bytes from another independently acknowledged store are refused.
            store
                .verify_original_intent(&original_intent, expected)
                .map_err(|_| Error::Journal)?;
            if !original_intent.matches_runtime(runtime) {
                return Err(Error::Conflict);
            }
            let native_bytes = step!(
                "cold load original initial ACK",
                read_original_initial(runtime, context, &initial)
            );
            let deadline = step!("cold load original deadline pin", supervisor.read_pin());
            step!(
                "cold load deadline/runtime",
                deadline.verify_runtime(supervisor, runtime, context)
            );
            self.inputs = Some(Rc::new(Inputs {
                runtime: runtime.read_pin()?,
                files: files.clone(),
                source: source.clone(),
                context: context.clone(),
                expected: expected.clone(),
                intent: original_intent,
                initial,
                native_bytes,
                supervisor: supervisor.clone(),
                deadline,
                cancelled: actor_cancelled.clone(),
            }));
            // Marked retained before any fallible supervised operation. Failed
            // postflight/rundown cannot discard the caller's owning slot.
            let input = self.inputs.as_ref().expect("retained original inputs");
            // Passive package/inventory preparation grants no loader authority.
            // Keep these SAME originals before Calling; input.calling and the
            // audited loader still reauthenticate immediately before the effect.
            self.preload = Some(step!(
                "cold load original Wintun preflight",
                WintunPreload::new(&input.source)
            ));
            self.members = Some(step!(
                "cold load original member inventory",
                MemberInventory::retain(
                    &input.runtime,
                    input.context.clone(),
                    input.source.clone(),
                )
            ));
            let members = step!(
                "cold load original member inventory read",
                self.members.as_ref().expect("retained members").read_all()
            );
            if !members.is_empty() {
                return Err(Error::Conflict);
            }
            let result = supervisor.run_intent(
                context,
                &input.intent,
                expected,
                pair::Effect::CarrierReady,
                || {
                    // The whole original Calling input is checked immediately
                    // before LoadLibrary below and again after its retained ACK.
                    // SAME slot's factual marker is set only after the real OS
                    // return is rooted in LoadedWintun, before fallible image/
                    // package postflight. Wrapper presence alone is not an ACK.
                    let actual_load_returned = self.module.load_returned.clone();
                    self.module
                        .load_into(
                            lock,
                            |lock| {
                                step!("cold load original Calling input", input.calling());
                                if !input.runtime.matches_lock(lock) {
                                    return Err(Error::Conflict);
                                }
                                lock.verify_source(&input.source)
                            },
                            |lock, slot| {
                                LoadedWintun::load_cold_into(
                                    slot,
                                    &input.source,
                                    lock,
                                    &input.cancelled,
                                    &actual_load_returned,
                                )
                                .map_err(module_error)
                            },
                            |_, _module| {
                                // module is ALREADY in our caller-owned slot. Every
                                // later fallible check (including image construction)
                                // leaves that exact owner there, even on unwind.
                                input.calling()
                            },
                        )
                        .map_err(|error| match error {
                            LoadError::AlreadyAttempted => Error::Pending,
                            LoadError::MissingAcknowledgement => Error::Pending,
                            LoadError::Boundary(error) => error,
                        })?;
                    Ok(())
                },
            );
            result?;
            // Final current publication check AFTER actual supervisor postflight
            // and worker rundown; failures keep every original field retained.
            input.current()?;
            store
                .verify_original_intent(&input.intent, expected)
                .map_err(|_| Error::Journal)?;
            input.current()?;
            self.cold_verified = true;
            Ok(())
        }

        /// Derive the opaque image only from the SAME retained audited loader;
        /// no caller image minting callback or raw-HMODULE constructor exists.
        pub(crate) fn compose_originals(
            &mut self,
            lock: &mut KeyLock,
            store: &mut NativeCarrierPairStore,
        ) -> Result<()> {
            macro_rules! step {
                ($label:literal, $result:expr) => {{
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step(concat!(
                        "compose begin ",
                        $label
                    ));
                    let value = $result.inspect_err(|_error| {
                        #[cfg(test)]
                        super::super::member_carrier_factory_test_os::trace_native(
                            concat!("compose ", $label),
                            _error,
                        );
                    })?;
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step(concat!(
                        "compose end ",
                        $label
                    ));
                    value
                }};
            }
            if self.terminal_attempted
                || !self.cold_verified
                || self.compose_attempted
                || self.ready
                || self.transferred
            {
                return Err(Error::Pending);
            }
            self.compose_attempted = true;
            let input = self.inputs.as_ref().ok_or(Error::Pending)?;
            if self.module.acknowledged.is_none() || !input.runtime.matches_lock(lock) {
                return Err(Error::Conflict);
            }
            let supervisor = input.supervisor.clone();
            // run_intent already authenticates this SAME original Pair and
            // Calling before/after each readonly stage. Keep source, storage,
            // initial-native/freshness and original deadline checks here once;
            // Inputs::calling would repeat that Pair window and current read.
            supervisor.run_intent(
                &input.context,
                &input.intent,
                &input.expected,
                pair::Effect::CarrierReady,
                || {
                    step!("current originals", input.current());
                    step!(
                        "current Calling",
                        input.deadline.verify_call(&supervisor, &input.context)
                    );
                    let module = self.module.acknowledged.as_mut().ok_or(Error::Pending)?;
                    // Retain the actual image return BEFORE any subsequent check.
                    // The loaded module has been in the slot throughout the mint.
                    self.image = Some(step!(
                        "original image",
                        module
                            .original_image(lock, &input.cancelled)
                            .map_err(module_error)
                    ));
                    let image = self.image.as_ref().expect("retained image");
                    if !image.matches_source(&input.source)
                        || !image.matches_runtime(&input.runtime)
                    {
                        return Err(Error::Conflict);
                    }
                    step!(
                        "live image",
                        image
                            .verify_live_runtime(&input.runtime)
                            .map_err(module_error)
                    );
                    if step!(
                        "cold module",
                        module
                            .original_cold_module(lock, &input.cancelled)
                            .map_err(module_error)
                    ) != step!("image module", image.module().map_err(module_error))
                    {
                        return Err(Error::Conflict);
                    }
                    step!("current originals", input.current());
                    step!(
                        "current Calling",
                        input.deadline.verify_call(&supervisor, &input.context)
                    );
                    Ok(())
                },
            )?;
            // Image, universe, full registry read and key authority are
            // separate readonly operations. Keep every original in THIS slot
            // across their SAME-supervisor fences; no stage grants C effects.
            supervisor.run_intent(
                &input.context,
                &input.intent,
                &input.expected,
                pair::Effect::CarrierReady,
                || {
                    step!("current originals", input.current());
                    step!(
                        "current Calling",
                        input.deadline.verify_call(&supervisor, &input.context)
                    );
                    let image = self.image.as_ref().ok_or(Error::Pending)?;
                    let members = self.members.as_ref().ok_or(Error::Pending)?;
                    // read_all checks its original inventory; with_members
                    // below performs the SAME runtime/image join itself.
                    if !step!("member inventory", members.read_all()).is_empty() {
                        return Err(Error::Conflict);
                    }
                    let universe = step!(
                        "original universe",
                        OriginalUniverse::new(&input.runtime, image)
                            .and_then(|universe| universe.with_members(members.read_pin()))
                            .map_err(|_| Error::Conflict)
                    );
                    self.registry = Some(step!(
                        "registry intent",
                        Producer::<OriginalWintun>::intent(input.context.clone(), universe)
                            .map_err(|_| Error::Conflict)
                    ));
                    step!("current originals", input.current());
                    step!(
                        "current Calling",
                        input.deadline.verify_call(&supervisor, &input.context)
                    );
                    Ok(())
                },
            )?;
            supervisor.run_intent(
                &input.context,
                &input.intent,
                &input.expected,
                pair::Effect::CarrierReady,
                || {
                    step!("current originals", input.current());
                    step!(
                        "current Calling",
                        input.deadline.verify_call(&supervisor, &input.context)
                    );
                    let (producer, observer) = self.registry.as_ref().ok_or(Error::Pending)?;
                    if !observer.same_original_registry(&producer.observer())
                        || observer.context() != &input.context
                        || !step!(
                            "whole registry",
                            observer
                                .observe_all(&input.context)
                                .map_err(|_| Error::Conflict)
                        )
                        .originals
                        .is_empty()
                    {
                        return Err(Error::Conflict);
                    }
                    step!("current originals", input.current());
                    step!(
                        "current Calling",
                        input.deadline.verify_call(&supervisor, &input.context)
                    );
                    Ok(())
                },
            )?;
            supervisor.run_intent(
                &input.context,
                &input.intent,
                &input.expected,
                pair::Effect::CarrierReady,
                || {
                    step!("current originals", input.current());
                    step!(
                        "current Calling",
                        input.deadline.verify_call(&supervisor, &input.context)
                    );
                    let image = self.image.as_ref().ok_or(Error::Pending)?;
                    let (producer, _) = self.registry.as_ref().ok_or(Error::Pending)?;
                    let originals = step!(
                        "original key inventory",
                        OriginalKeyInventory::from_producer(producer, &input.runtime, image)
                            .map_err(|_| Error::Conflict)
                    );
                    self.keys = Some(step!(
                        "key authority",
                        KeyAuthority::from_read(&input.runtime, originals, lock)
                    ));
                    step!(
                        "live image",
                        image
                            .verify_live_runtime(&input.runtime)
                            .map_err(module_error)
                    );
                    step!("current originals", input.current());
                    step!(
                        "current Calling",
                        input.deadline.verify_call(&supervisor, &input.context)
                    );
                    Ok(())
                },
            )?;
            input.current()?;
            store
                .verify_original_intent(&input.intent, &input.expected)
                .map_err(|_| Error::Journal)?;
            input.current()?;
            self.ready = true;
            Ok(())
        }

        /// Factual originals for main's concrete G registration. No effect
        /// permission or unsupervised native lifecycle API is supplied here.
        pub(crate) fn originals(&self) -> Result<BootstrapOriginals<'_>> {
            if self.terminal_attempted || !self.ready || self.transferred {
                return Err(Error::Pending);
            }
            let input = self.inputs.as_ref().ok_or(Error::Pending)?;
            Ok(BootstrapOriginals {
                runtime: &input.runtime,
                context: &input.context,
                expected: &input.expected,
                pair_intent: &input.intent,
                image: self.image.as_ref().ok_or(Error::Pending)?,
                members: self.members.as_ref().ok_or(Error::Pending)?,
                observer: &self.registry.as_ref().ok_or(Error::Pending)?.1,
                supervisor: &input.supervisor,
                cancelled: &input.cancelled,
            })
        }

        /// Transfer actual owners ONCE during main's SAME Calling assembly.
        /// The slot keeps a separately retained ORIGINAL image/source/runtime/
        /// package/actor pin if NativeCarrierAuthority::new consumes the owners
        /// and then fails. Main must keep this slot across construction, native
        /// creation, and cleanup; dropping it retains unknown pins to process exit.
        pub(crate) fn take_for_assembly(&mut self, lock: &mut KeyLock) -> Result<BootstrapAssets> {
            if self.terminal_attempted || !self.ready || self.transferred {
                return Err(Error::Pending);
            }
            let input = self.inputs.as_ref().ok_or(Error::Pending)?;
            input.calling()?;
            if !input.runtime.matches_lock(lock) {
                return Err(Error::Conflict);
            }
            let image = self.image.as_ref().ok_or(Error::Pending)?;
            image
                .verify_live_runtime(&input.runtime)
                .map_err(module_error)?;
            let assembly_image = image.read_pin().map_err(module_error)?;
            let runtime = input.runtime.read_pin()?;
            let pair_intent = &input.intent;
            if !pair_intent.matches_runtime(&runtime)
                || self.module.acknowledged.is_none()
                || self.registry.is_none()
                || self.keys.is_none()
                || self.members.is_none()
            {
                return Err(Error::Pending);
            }
            input.calling()?;
            // Prepare every fallible read/clone BEFORE moving any owning field.
            let context = input.context.clone();
            let expected = input.expected.clone();
            let source = input.source.clone();
            let supervisor = input.supervisor.clone();
            let cancelled = input.cancelled.clone();
            let pair_intent = input.intent.clone();
            let members = self.members.as_ref().expect("checked members").read_pin();
            self.transferred = true;
            self.ready = false;
            let (producer, observer) = self.registry.take().expect("checked registry");
            Ok(BootstrapAssets {
                module: self
                    .module
                    .acknowledged
                    .take()
                    .expect("checked loaded module"),
                runtime,
                image: assembly_image,
                producer,
                observer,
                members,
                key_authority: self.keys.take().expect("checked key authority"),
                context,
                expected,
                source,
                supervisor,
                cancelled,
                pair_intent,
            })
        }
    }

    /// Raw aliases from the SAME bootstrap; no unknown-retaining Bootstrap Drop
    /// is carried inside terminal resource T. The loader is separated to the
    /// independently retained module root BEFORE C/G may authorize T release.
    pub(crate) struct NativeBootstrapTerminalParts {
        origin: Option<Rc<()>>,
        inputs: Option<Rc<Inputs>>,
        module: Option<TerminalLoad<LoadedWintun>>,
        pub(crate) preload: Option<WintunPreload>,
        pub(crate) image: Option<OriginalImage>,
        pub(crate) members: Option<MemberInventoryRead>,
        pub(crate) registry: Option<(Producer<OriginalWintun>, creators::Observer<OriginalWintun>)>,
        pub(crate) keys: Option<KeyAuthority<OriginalKeyInventory>>,
        cold_verified: bool,
        compose_attempted: bool,
        transferred_to_assembly: bool,
    }
    pub(crate) type NativeBootstrapTerminalResources =
        TerminalResources<NativeBootstrapTerminalParts>;
    pub(crate) type NativeBootstrapTerminalModule = TerminalModule<LoadedWintun>;

    /// Sealed loader-boundary lineage only. The module remains in its SAME
    /// owning slot. No C/SourceRead/image/SDK absence or native load ACK is minted.
    pub(crate) struct NativeBootstrapModuleOnlyRead {
        origin: Rc<()>,
        inputs: Rc<Inputs>,
        pair: Rc<NativePairIntentRead>,
        expected: PairRecord,
        load: std::cell::RefCell<Option<Rc<ModuleOnlyLoadRead>>>,
        canonical: std::cell::RefCell<Option<NativeSessionFiles>>,
        initial_cleanup: crate::windows::member_carrier_terminal_release::TerminalCallState,
        initial_data: std::cell::RefCell<Option<InitialNativeDataRead>>,
        data_capture: crate::windows::member_carrier_terminal_release::TerminalCallState,
    }
    impl NativeBootstrapModuleOnlyRead {
        /// Actual SAME initial-J ACK under its explicit original cleanup view.
        /// Called only inside original finite Calling/Pair bracket. This is
        /// SDK-free bookkeeping/read authentication, never native permission.
        pub(crate) fn verify_current_initial(
            &self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            observed: &[u8],
        ) -> Result<()> {
            let input = &self.inputs;
            let check = || -> Result<()> {
                crate::windows::member_carrier_startup::compare_module_only_read_progress(
                    &input.context,
                    &self.expected,
                    expected,
                )?;
                if observed != input.native_bytes.as_slice() {
                    return Err(Error::Conflict);
                }
                let load = self.load.try_borrow().map_err(|_| Error::Conflict)?;
                let load = load.as_ref().ok_or(Error::Pending)?;
                load.capture.verify().map_err(|_| Error::Retired)?;
                if !load.returned.get() {
                    return Err(Error::Retired);
                }
                input
                    .deadline
                    .verify_call(&input.supervisor, &input.context)?;
                if !pair.same_store_origin(&self.pair) {
                    return Err(Error::Conflict);
                }
                pair.verify_module_only_read_bracket(
                    &input.runtime,
                    &input.supervisor,
                    &input.context,
                    expected,
                )
                .map_err(|_| Error::Conflict)?;
                input.runtime.verify_source(&input.source)?;
                input
                    .runtime
                    .verify_same_session_files(&input.context, &input.files)
            };
            if self
                .canonical
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .is_none()
            {
                self.initial_cleanup
                    .run(|| {
                        check().map_err(|_| std::io::Error::other("module_initial_frame"))?;
                        let canonical = input
                            .runtime
                            .native_files_for_original(&input.context, &input.files)
                            .map_err(|_| std::io::Error::other("module_initial_original_view"))?;
                        // Retain SAME selected view before journal handoff/readback.
                        *self
                            .canonical
                            .try_borrow_mut()
                            .map_err(|_| std::io::Error::other("module_initial_busy"))? =
                            Some(canonical.clone());
                        crate::windows::member_carrier_assembly::inspect_module_only_initial(
                            &input.initial,
                            &input.context,
                            observed,
                            |journal, acknowledged| {
                                let journal = std::cell::RefCell::new(journal);
                                crate::windows::member_carrier_assembly::retain_initial_cleanup_data(
                                    &self.initial_data, &self.data_capture,
                                    || journal.borrow_mut()
                                        .enter_original_initial_cleanup(canonical)
                                        .map_err(|_| Error::Journal),
                                    || journal.borrow().original_initial_data_read()
                                        .map_err(|_| Error::Journal),
                                    |original| {
                                        if original.acknowledged() != acknowledged {
                                            return Err(Error::Conflict);
                                        }
                                        check()
                                    },
                                )
                            },
                        )
                        .map_err(|_| std::io::Error::other("module_initial_handoff"))?;
                        check().map_err(|_| std::io::Error::other("module_initial_postflight"))
                    })
                    .map_err(|_| Error::Retired)?;
            }
            self.initial_cleanup.verify().map_err(|_| Error::Retired)?;
            check()?;
            let canonical = self
                .canonical
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .as_ref()
                .ok_or(Error::Pending)?
                .clone();
            crate::windows::member_carrier_assembly::inspect_module_only_initial(
                &input.initial,
                &input.context,
                observed,
                |journal, _| {
                    journal
                        .enter_original_initial_cleanup(canonical)
                        .map_err(|_| Error::Journal)
                },
            )?;
            check()
        }
        /// SDK-free SAME initialized-journal pin captured during canonical
        /// cleanup. Not a native-effect, absence or retirement authorization.
        pub(crate) fn original_initial_data_read(&self) -> Result<InitialNativeDataRead> {
            self.initial_cleanup.verify().map_err(|_| Error::Retired)?;
            self.data_capture.verify().map_err(|_| Error::Retired)?;
            self.initial_data
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .as_ref()
                .cloned()
                .ok_or(Error::Pending)
        }
        pub(crate) fn retire_original_initial_data(
            &self,
            proof: &dyn OriginalInitialNativeDataRetirement,
            retain: impl FnOnce(Rc<InitialDataRetirementAck>) -> std::io::Result<()>,
        ) -> Result<()> {
            let original = self.original_initial_data_read()?;
            self.inputs.initial.retire_original_initial_data(
                &self.inputs.context,
                |journal, acknowledged| {
                    if original.acknowledged() != acknowledged {
                        return Err(Error::Conflict);
                    }
                    let ack = journal
                        .retire_original_initial_data(proof, retain)
                        .map_err(|_| Error::Journal)?;
                    if !ack.matches_original(&original) {
                        return Err(Error::Conflict);
                    }
                    Ok(())
                },
            )
        }
        pub(crate) fn original_inputs(&self) -> NativeBootstrapTerminalInputs<'_> {
            let input = &self.inputs;
            NativeBootstrapTerminalInputs {
                runtime: &input.runtime,
                files: &input.files,
                source: &input.source,
                context: &input.context,
                original_intent: &input.intent,
                initial: &input.initial,
                supervisor: &input.supervisor,
                deadline: &input.deadline,
                cancelled: &input.cancelled,
                capture_record: &input.expected,
                capture_native_bytes: &input.native_bytes,
            }
        }
    }
    impl NativeBootstrapSlot {
        /// Must be called INSIDE the actual outer terminal Pair read frame and
        /// Calling. Retains candidate before all fallible boundary checks. It
        /// cannot authorize FreeLibrary or substitute for actual full absence.
        pub(crate) fn retain_module_only_read_in_call(
            &self,
            pair: &Rc<NativePairIntentRead>,
            expected: &PairRecord,
            destination: &mut Option<Rc<NativeBootstrapModuleOnlyRead>>,
        ) -> Result<()> {
            if destination.is_some() {
                return Err(Error::Retired);
            }
            let input = self.inputs.as_ref().ok_or(Error::Pending)?.clone();
            *destination = Some(Rc::new(NativeBootstrapModuleOnlyRead {
                origin: self.terminal_origin.clone(),
                inputs: input.clone(),
                pair: pair.clone(),
                expected: expected.clone(),
                load: std::cell::RefCell::new(None),
                canonical: std::cell::RefCell::new(None),
                initial_cleanup:
                    crate::windows::member_carrier_terminal_release::TerminalCallState::new(),
                initial_data: std::cell::RefCell::new(None),
                data_capture:
                    crate::windows::member_carrier_terminal_release::TerminalCallState::new(),
            }));
            let original = destination
                .as_ref()
                .expect("retained module-only candidate");
            self.module
                .retain_module_only_read_into(&mut original.load.borrow_mut(), |_| {
                    if self.terminal_attempted
                        || self.compose_attempted
                        || self.transferred
                        || self.ready
                        || self.image.is_some()
                        || self.registry.is_some()
                        || self.keys.is_some()
                        || !input.intent.same_store_origin(pair)
                        || !pair.matches_runtime(&input.runtime)
                    {
                        return Err(Error::Conflict);
                    }
                    pair.verify_module_only_read_bracket(
                        &input.runtime,
                        &input.supervisor,
                        &input.context,
                        expected,
                    )
                    .map_err(|_| Error::Conflict)
                })
                .map_err(terminal_error)
        }
        pub(crate) fn verify_module_only_read(
            &self,
            original: &NativeBootstrapModuleOnlyRead,
            pair: &Rc<NativePairIntentRead>,
            expected: &PairRecord,
        ) -> Result<()> {
            if self.terminal_attempted
                || self.compose_attempted
                || self.transferred
                || self.ready
                || self.image.is_some()
                || self.registry.is_some()
                || self.keys.is_some()
                || !Rc::ptr_eq(&self.terminal_origin, &original.origin)
                || self
                    .inputs
                    .as_ref()
                    .is_none_or(|input| !Rc::ptr_eq(input, &original.inputs))
                || !pair.same_store_origin(&original.pair)
            {
                return Err(Error::Conflict);
            }
            crate::windows::member_carrier_startup::compare_module_only_read_progress(
                &original.inputs.context,
                &original.expected,
                expected,
            )?;
            self.module
                .verify_module_only_read(
                    original
                        .load
                        .try_borrow()
                        .map_err(|_| Error::Conflict)?
                        .as_ref()
                        .ok_or(Error::Pending)?,
                )
                .map_err(|_| Error::Conflict)
        }
        /// SAME owning loader comparison only. It does not consume the separate
        /// once-only terminal effect borrow or turn a boundary return into ACK.
        pub(crate) fn verify_module_only_load_read(
            &self,
            original: &NativeBootstrapModuleOnlyRead,
            pair: &Rc<NativePairIntentRead>,
            expected: &PairRecord,
            read: &Rc<module::native::NativeOriginalModuleLoadRead>,
        ) -> Result<()> {
            self.verify_module_only_read(original, pair, expected)?;
            let load = original.load.try_borrow().map_err(|_| Error::Conflict)?;
            self.module
                .verify_original_loaded_read(load.as_ref().ok_or(Error::Pending)?, |owner| {
                    owner
                        .verify_original_load_read(read)
                        .map_err(|_| Error::Conflict)
                })
                .map_err(terminal_error)?;
            self.verify_module_only_read(original, pair, expected)
        }
        pub(crate) fn retain_module_only_load_read_into(
            &self,
            original: &NativeBootstrapModuleOnlyRead,
            pair: &Rc<NativePairIntentRead>,
            expected: &PairRecord,
            destination: &mut Option<Rc<module::native::NativeOriginalModuleLoadRead>>,
        ) -> Result<()> {
            self.verify_module_only_read(original, pair, expected)?;
            let load = original.load.try_borrow().map_err(|_| Error::Conflict)?;
            self.module
                .verify_original_loaded_read(load.as_ref().ok_or(Error::Pending)?, |owner| {
                    owner
                        .retain_original_load_read_into(destination)
                        .map_err(|_| Error::Conflict)
                })
                .map_err(terminal_error)?;
            drop(load);
            self.verify_module_only_load_read(
                original,
                pair,
                expected,
                destination.as_ref().ok_or(Error::Pending)?,
            )
        }
        /// SAME retained wrapper only; the callback must supply independent
        /// actual native load ACK + terminal gate/permit. No raw HMODULE access.
        pub(crate) fn with_original_module_only(
            &mut self,
            original: &NativeBootstrapModuleOnlyRead,
            pair: &Rc<NativePairIntentRead>,
            expected: &PairRecord,
            call: impl FnOnce(&mut LoadedWintun) -> Result<()>,
        ) -> Result<()> {
            self.verify_module_only_read(original, pair, expected)?;
            let input = &original.inputs;
            pair.verify_terminal_bracket(
                &input.runtime,
                &input.supervisor,
                &input.context,
                expected,
            )
            .map_err(|_| Error::Conflict)?;
            let load = original.load.try_borrow().map_err(|_| Error::Conflict)?;
            self.module
                .with_original_module_only(load.as_ref().ok_or(Error::Pending)?, |module| {
                    let result = call(module);
                    // Even callback Err requires the same factual postflight.
                    pair.verify_terminal_bracket(
                        &input.runtime,
                        &input.supervisor,
                        &input.context,
                        expected,
                    )
                    .map_err(|_| Error::Conflict)?;
                    result
                })
                .map_err(terminal_error)
        }
    }
    impl NativeBootstrapTerminalParts {
        pub(crate) fn empty() -> Self {
            Self {
                origin: None,
                inputs: None,
                module: None,
                preload: None,
                image: None,
                members: None,
                registry: None,
                keys: None,
                cold_verified: false,
                compose_attempted: false,
                transferred_to_assembly: false,
            }
        }
        /// Borrow original facts without forward Runtime/Authority/SDK reentry.
        /// A failed early attempt can have no Inputs; this is NOT absence proof.
        pub(crate) fn original_inputs(&self) -> Option<NativeBootstrapTerminalInputs<'_>> {
            self.inputs
                .as_ref()
                .map(|input| NativeBootstrapTerminalInputs {
                    runtime: &input.runtime,
                    files: &input.files,
                    source: &input.source,
                    context: &input.context,
                    original_intent: &input.intent,
                    initial: &input.initial,
                    supervisor: &input.supervisor,
                    deadline: &input.deadline,
                    cancelled: &input.cancelled,
                    capture_record: &input.expected,
                    capture_native_bytes: &input.native_bytes,
                })
        }
        /// Factual attempt ledger only, never a substitute for the native module
        /// owner/receipt or current terminal SDK proof.
        pub(crate) fn attempt_facts(&self) -> (bool, bool, bool, bool) {
            (
                self.module.as_ref().is_some_and(|module| module.attempted),
                self.cold_verified,
                self.compose_attempted,
                self.transferred_to_assembly,
            )
        }
        /// Caller retains its module container OUTSIDE resource T. No owning
        /// LoadedWintun return crosses a fallible Result; callback runs AFTER
        /// the SAME actual wrapper has been rooted in that destination.
        pub(crate) fn transfer_loaded_module_into<T>(
            &mut self,
            destination: &mut TerminalResources<T>,
            project: fn(&mut T) -> &mut Vec<NativeBootstrapTerminalModule>,
            retained: impl FnOnce(&NativeBootstrapTerminalModule) -> Result<()>,
        ) -> Result<()> {
            if self.origin.is_none() {
                return Err(Error::Pending);
            }
            self.module
                .as_mut()
                .ok_or(Error::Pending)?
                .separate_module_into(project(destination.retained_mut()), retained)
                .map_err(terminal_error)
        }
        pub(crate) fn verify_original_module_transfer(
            &self,
            module: &NativeBootstrapTerminalModule,
        ) -> Result<()> {
            if self.origin.is_none() {
                return Err(Error::Pending);
            }
            self.module
                .as_ref()
                .ok_or(Error::Pending)?
                .verify_module_transfer(module)
                .map_err(|_| Error::Conflict)
        }
    }
    impl TerminalModule<LoadedWintun> {
        /// Borrows the actual retained audited loader. Its private module ACK
        /// and mandatory native terminal permit remain independently required.
        /// An unknown/missing owning return cannot reconstruct a loader.
        pub(crate) fn with_original_loaded_module<T>(
            &mut self,
            read: impl FnOnce(&mut LoadedWintun) -> Result<T>,
        ) -> Result<T> {
            read(self.original_mut().map_err(|_| Error::Pending)?)
        }
    }
    pub(crate) struct NativeBootstrapTerminalInputs<'a> {
        pub(crate) runtime: &'a RuntimeRead,
        pub(crate) files: &'a NativeSessionFiles,
        pub(crate) source: &'a Rc<WintunSource>,
        pub(crate) context: &'a Context,
        pub(crate) original_intent: &'a Rc<NativePairIntentRead>,
        pub(crate) initial: &'a InitialRead<WindowsNativeCarrierReceiptStore<NativeSessionFiles>>,
        pub(crate) supervisor: &'a Rc<NativeDeadline>,
        pub(crate) deadline: &'a NativeDeadlineReadPin,
        pub(crate) cancelled: &'a Arc<AtomicBool>,
        pub(crate) capture_record: &'a PairRecord,
        pub(crate) capture_native_bytes: &'a [u8],
    }
    impl NativeBootstrapSlot {
        /// SAME original loader wrapper only, after its actual typed native
        /// disposition. The caller retains this raw before any transfer/check.
        /// No SDK/image query, release retry or constructor absence inference.
        pub(crate) fn verify_completed_no_constructor_release<
            P: module::native::NativeNoConstructorModuleReleaseProof,
        >(
            &self,
            original: &NativeBootstrapModuleOnlyRead,
            expected: &PairRecord,
            ack: &module::native::NativeNoConstructorModuleReleased<P>,
        ) -> Result<()> {
            self.verify_module_only_read(original, &original.pair, expected)?;
            let load = original.load.try_borrow().map_err(|_| Error::Conflict)?;
            let load = load.as_ref().ok_or(Error::Pending)?;
            load.call.verify().map_err(|_| Error::Retired)?;
            self.module
                .verify_original_loaded_read(load, |module| {
                    module
                        .verify_no_constructor_disposition(ack)
                        .map_err(|_| Error::Retired)
                })
                .map_err(terminal_error)
        }
        pub(crate) fn drain_no_constructor_after_release<
            P: module::native::NativeNoConstructorModuleReleaseProof,
        >(
            &mut self,
            original: &NativeBootstrapModuleOnlyRead,
            expected: &PairRecord,
            ack: &module::native::NativeNoConstructorModuleReleased<P>,
            destination: &mut NativeBootstrapTerminalResources,
        ) -> Result<()> {
            self.verify_completed_no_constructor_release(original, expected, ack)?;
            original.original_initial_data_read()?;
            self.drain_terminal_into(destination)?;
            self.verify_no_constructor_terminal_cut(destination.retained(), original, ack)
        }
        pub(crate) fn verify_no_constructor_terminal_cut<
            P: module::native::NativeNoConstructorModuleReleaseProof,
        >(
            &self,
            raw: &NativeBootstrapTerminalParts,
            original: &NativeBootstrapModuleOnlyRead,
            ack: &module::native::NativeNoConstructorModuleReleased<P>,
        ) -> Result<()> {
            self.verify_original_terminal_transfer(raw)?;
            if raw
                .inputs
                .as_ref()
                .is_none_or(|input| !Rc::ptr_eq(input, &original.inputs))
                || raw
                    .origin
                    .as_ref()
                    .is_none_or(|origin| !Rc::ptr_eq(origin, &original.origin))
                || raw.compose_attempted
                || raw.transferred_to_assembly
                || raw.image.is_some()
                || raw.members.is_some()
                || raw.registry.is_some()
                || raw.keys.is_some()
            {
                return Err(Error::Conflict);
            }
            self.module
                .verify_module_only_terminal_cut(
                    raw.module.as_ref().ok_or(Error::Pending)?,
                    original
                        .load
                        .try_borrow()
                        .map_err(|_| Error::Conflict)?
                        .as_ref()
                        .ok_or(Error::Pending)?,
                    |module| {
                        module
                            .verify_no_constructor_disposition(ack)
                            .map_err(|_| Error::Retired)
                    },
                )
                .map_err(terminal_error)
        }

        pub(crate) fn drain_terminal_into(
            &mut self,
            destination: &mut NativeBootstrapTerminalResources,
        ) -> Result<()> {
            self.drain_terminal_with(destination, |raw| raw, |_| Ok(()))
        }
        /// Pure once-owning transfer, NOT terminal authorization. Occupied
        /// destinations and retry deny without overwriting any original. All
        /// aliases and internal ACKs survive error/unwind in caller-retained raw.
        pub(crate) fn drain_terminal_with<T>(
            &mut self,
            destination: &mut TerminalResources<T>,
            project: fn(&mut T) -> &mut NativeBootstrapTerminalParts,
            postflight: impl FnOnce(&NativeBootstrapTerminalParts) -> Result<()>,
        ) -> Result<()> {
            if std::mem::replace(&mut self.terminal_attempted, true) {
                return Err(Error::Pending);
            }
            let raw = project(destination.retained_mut());
            if raw.origin.is_some()
                || raw.inputs.is_some()
                || raw.module.is_some()
                || raw.preload.is_some()
                || raw.image.is_some()
                || raw.members.is_some()
                || raw.registry.is_some()
                || raw.keys.is_some()
            {
                return Err(Error::Conflict);
            }
            raw.origin = Some(self.terminal_origin.clone());
            raw.inputs = self.inputs.take();
            raw.preload = self.preload.take();
            raw.image = self.image.take();
            raw.members = self.members.take();
            raw.registry = self.registry.take();
            raw.keys = self.keys.take();
            raw.cold_verified = self.cold_verified;
            raw.compose_attempted = self.compose_attempted;
            raw.transferred_to_assembly = self.transferred;
            self.ready = false;
            self.module
                .drain_terminal_into(&mut raw.module, |_| Ok::<_, Error>(()))
                .map_err(terminal_error)?;
            self.verify_original_terminal_transfer(raw)?;
            postflight(raw)
        }
        /// Empty source-shell proof tied to THIS original raw destination. It
        /// does not claim closed native handles, DLL absence or inert contents.
        pub(crate) fn verify_original_terminal_transfer(
            &self,
            raw: &NativeBootstrapTerminalParts,
        ) -> Result<()> {
            if !self.terminal_attempted
                || self.ready
                || !raw
                    .origin
                    .as_ref()
                    .is_some_and(|origin| Rc::ptr_eq(origin, &self.terminal_origin))
                || self.inputs.is_some()
                || self.preload.is_some()
                || self.image.is_some()
                || self.members.is_some()
                || self.registry.is_some()
                || self.keys.is_some()
                || self.cold_verified != raw.cold_verified
                || self.compose_attempted != raw.compose_attempted
                || self.transferred != raw.transferred_to_assembly
            {
                return Err(Error::Conflict);
            }
            self.module
                .verify_terminal_transfer(raw.module.as_ref().ok_or(Error::Pending)?)
                .map_err(|_| Error::Conflict)
        }
    }
    fn terminal_error(error: LoadError<Error>) -> Error {
        match error {
            LoadError::Boundary(error) => error,
            LoadError::AlreadyAttempted | LoadError::MissingAcknowledgement => Error::Pending,
        }
    }

    /// Actual opaque objects for main's NativeCarrierAuthority assembly. After
    /// preparing C's keys, main derives creators::Scope.generation from that
    /// CURRENT Disabled receipt; bootstrap does not guess the future generation.
    pub(crate) struct BootstrapAssets {
        pub(crate) module: LoadedWintun,
        pub(crate) runtime: RuntimeRead,
        pub(crate) image: OriginalImage,
        pub(crate) producer: Producer<OriginalWintun>,
        pub(crate) observer: creators::Observer<OriginalWintun>,
        pub(crate) members: MemberInventoryRead,
        pub(crate) key_authority: KeyAuthority<OriginalKeyInventory>,
        pub(crate) context: Context,
        pub(crate) expected: PairRecord,
        pub(crate) source: Rc<WintunSource>,
        pub(crate) supervisor: Rc<NativeDeadline>,
        pub(crate) cancelled: Arc<AtomicBool>,
        pub(crate) pair_intent: Rc<NativePairIntentRead>,
    }
    pub(crate) struct BootstrapOriginals<'a> {
        pub(crate) runtime: &'a RuntimeRead,
        pub(crate) context: &'a Context,
        pub(crate) expected: &'a PairRecord,
        pub(crate) pair_intent: &'a NativePairIntentRead,
        pub(crate) image: &'a OriginalImage,
        pub(crate) members: &'a MemberInventoryRead,
        pub(crate) observer: &'a creators::Observer<OriginalWintun>,
        pub(crate) supervisor: &'a Rc<NativeDeadline>,
        pub(crate) cancelled: &'a Arc<AtomicBool>,
    }

    impl Drop for NativeBootstrapSlot {
        fn drop(&mut self) {
            if self.module.acknowledged.is_some() || self.image.is_some() {
                // Retain ALL factual/actor/package pins after an acknowledged
                // load or assembly transfer. No unload or creator Drop under
                // an unknown obligation; one slot/one attempt bounds retention.
                if let Some(value) = self.inputs.take() {
                    std::mem::forget(value);
                }
                if let Some(value) = self.preload.take() {
                    std::mem::forget(value);
                }
                if let Some(value) = self.image.take() {
                    std::mem::forget(value);
                }
                if let Some(value) = self.members.take() {
                    std::mem::forget(value);
                }
                if let Some(value) = self.registry.take() {
                    std::mem::forget(value);
                }
                if let Some(value) = self.keys.take() {
                    std::mem::forget(value);
                }
            }
        }
    }

    fn cancelled(signal: &AtomicBool) -> Result<()> {
        if signal.load(Ordering::Acquire) {
            Err(Error::Retired)
        } else {
            Ok(())
        }
    }
    fn module_error(error: module::Error) -> Error {
        match error {
            module::Error::Cancelled => Error::Retired,
            module::Error::Conflict => Error::Conflict,
            module::Error::Native => Error::Native,
        }
    }
    fn read_original_initial(
        runtime: &RuntimeRead,
        context: &Context,
        initial: &InitialRead<WindowsNativeCarrierReceiptStore<NativeSessionFiles>>,
    ) -> Result<Vec<u8>> {
        initial.inspect_initial(context, |journal, original| {
            runtime.verify_same_session_files(context, journal.original_files(context)?)?;
            let bytes = read_preparing(runtime, context)?;
            if original.encode()? != bytes {
                return Err(Error::Conflict);
            }
            runtime.verify_same_session_files(context, journal.original_files(context)?)?;
            Ok(bytes)
        })
    }
    fn read_preparing(runtime: &RuntimeRead, context: &Context) -> Result<Vec<u8>> {
        runtime.verify(context)?;
        if !runtime.fresh(context)? {
            return Err(Error::Retired);
        }
        let bytes = runtime.record(context, RecordKind::NativeCarrierReceipts)?;
        let record = receipts::Record::decode(&bytes)?;
        if record.context != *context
            || record.phase != receipts::Phase::Preparing
            || record
                .keys
                .iter()
                .any(|key| key.phase != KeyPhase::Unstarted)
        {
            return Err(Error::Conflict);
        }
        runtime.verify(context)?;
        if !runtime.fresh(context)?
            || runtime.record(context, RecordKind::NativeCarrierReceipts)? != bytes
        {
            return Err(Error::Conflict);
        }
        Ok(bytes)
    }
    fn validate_requested(context: &Context, record: &PairRecord, logical: &str) -> Result<()> {
        // Run the ACTUAL renderer/parser here, not a hand-built PairConfiguration
        // or a caller's prevalidated bit. Secret rendering never enters the slot.
        let rendered =
            crate::redundancy::pair_configuration(logical).map_err(|_| Error::Invalid)?;
        record.validate().map_err(|_| Error::Invalid)?;
        let pair::Operation::Start(slot) = record.operation.ok_or(Error::Conflict)? else {
            return Err(Error::Conflict);
        };
        let index = if slot == nelomai_client_tunnel::redundancy::Slot::A {
            0
        } else {
            1
        };
        let prepared = record.members[index].as_ref().ok_or(Error::Conflict)?;
        let digest: [u8; 32] = Sha256::digest(rendered.native.as_bytes()).into();
        if record.phase != pair::Phase::Starting
            || record.pending != Some(pair::Effect::CarrierReady)
            || record.scope != context.intent.scope
            || record.provenance != context.provenance
            || record.addresses != context.intent.addresses
            || record.addresses != rendered.addresses
            || record.dns != rendered.dns
            || record.options.is_none()
            || record.stop_stage != 0
            || record.carrier.is_some()
            || record.active.is_some()
            || record.network.is_some()
            || record.pending_guard.is_some()
            || record.members[1 - index].is_some()
            || record.guard
                != crate::member_carrier_guard::Model::empty(record.scope.clone())
                    .map_err(|_| Error::Invalid)?
            || prepared.owner.phase != crate::member_owner::Phase::Prepared
            || prepared.owner.proof.is_some()
            || prepared.owner.retired_proof.is_some()
            || prepared.owner.previous_config_sha256.is_some()
            || prepared.owner.intent.config_sha256 != digest
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "member_carrier_bootstrap_tests.rs"]
mod tests;
