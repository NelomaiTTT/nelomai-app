//! Explicit terminal release only; no Drop-on-unknown authority.
#![allow(dead_code)]
use crate::{member_carrier_native_ownership::Context, member_carrier_pair as pair};
use std::{
    cell::{Cell, RefCell},
    io,
};
fn conflict() -> io::Error {
    io::Error::other("carrier_terminal_release_conflict")
}
pub(crate) fn compare_terminal(context: &Context, record: &pair::Record) -> io::Result<()> {
    crate::member_carrier_native_ownership::validate_context(context).map_err(|_| conflict())?;
    record.validate()?;
    if record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || record.options.is_none()
        || record.phase != pair::Phase::Stopped
        || record.stop_stage != 12
        || record.carrier.is_some()
        || record.members.iter().any(Option::is_some)
        || record.active.is_some()
        || record.operation.is_some()
        || record.pending.is_some()
        || record.pending_guard.is_some()
        || record.guard
            != crate::member_carrier_guard::Model::empty(record.scope.clone())
                .map_err(|_| conflict())?
        || record
            .network
            .as_ref()
            .is_some_and(|n| n.pending.is_some() || n.current != n.baseline)
    {
        return Err(conflict());
    }
    Ok(())
}
/// Own originals before checks. Unknown Drop intentionally retains them.
struct ResourceSlot<T> {
    value: RefCell<Option<T>>,
    attempted: Cell<bool>,
    tainted: Cell<bool>,
}
impl<T> ResourceSlot<T> {
    fn new(value: T) -> Self {
        Self {
            value: RefCell::new(Some(value)),
            attempted: Cell::new(false),
            tainted: Cell::new(false),
        }
    }
    fn release(&self, check: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        if self.attempted.replace(true) {
            self.tainted.set(true);
            return Err(conflict());
        }
        check()?;
        if self.tainted.get() {
            return Err(conflict());
        }
        let value = self
            .value
            .try_borrow_mut()
            .map_err(|_| conflict())?
            .take()
            .ok_or_else(conflict)?;
        drop(value);
        Ok(())
    }
}
impl<T> Drop for ResourceSlot<T> {
    fn drop(&mut self) {
        if let Some(value) = self.value.get_mut().take() {
            std::mem::forget(value);
        }
    }
}

struct PreparationState {
    attempted: Cell<bool>,
    tainted: Cell<bool>,
}
struct PreparationAttempt<'a> {
    state: &'a PreparationState,
    succeeded: bool,
}
impl PreparationState {
    fn new() -> Self {
        Self {
            attempted: Cell::new(false),
            tainted: Cell::new(false),
        }
    }
    fn begin(&self) -> io::Result<PreparationAttempt<'_>> {
        if self.attempted.replace(true) || self.tainted.get() {
            self.tainted.set(true);
            return Err(conflict());
        }
        Ok(PreparationAttempt {
            state: self,
            succeeded: false,
        })
    }
}
impl PreparationAttempt<'_> {
    fn finish(mut self) -> io::Result<()> {
        if self.state.tainted.get() {
            return Err(conflict());
        }
        self.succeeded = true;
        Ok(())
    }
}
impl Drop for PreparationAttempt<'_> {
    fn drop(&mut self) {
        if !self.succeeded {
            self.state.tainted.set(true);
        }
    }
}

pub(crate) struct TerminalCallState {
    attempt: PreparationState,
    completed: Cell<bool>,
}
impl TerminalCallState {
    pub(crate) fn new() -> Self {
        Self {
            attempt: PreparationState::new(),
            completed: Cell::new(false),
        }
    }
    pub(crate) fn run(&self, call: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        let attempt = self.attempt.begin()?;
        call()?;
        attempt.finish()?;
        self.completed.set(true);
        Ok(())
    }
    pub(crate) fn verify(&self) -> io::Result<()> {
        if !self.completed.get() || self.attempt.tainted.get() {
            return Err(conflict());
        }
        Ok(())
    }
}

// A reader returning Ok without ever entering its actual joined callback is a
// lost factual ACK, not permission. Private protocol marker, never a capability.
struct JoinedAck(Cell<bool>);
impl JoinedAck {
    fn new() -> Self {
        Self(Cell::new(false))
    }
    fn acknowledge(&self) {
        self.0.set(true);
    }
    fn verify(&self) -> io::Result<()> {
        if !self.0.get() {
            return Err(conflict());
        }
        Ok(())
    }
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::windows::{
        member_carrier_guard::Bindings,
        member_carrier_key_authority::RuntimeRead,
        member_carrier_members::ClosedMemberBinding,
        member_carrier_module::native::{NativeModuleReleased, OriginalImage},
        member_carrier_pair_store::native_store::NativePairIntentRead,
        member_carrier_runtime::native::{NativeSourceRead, RetiredCarrierRead},
        member_native_deadline::NativeDeadline,
    };
    use std::{cell::Ref, mem::ManuallyDrop, rc::Rc};

    /// # Safety
    /// Implementations must authenticate the SAME actual `resources`: all
    /// original native kernel references released, canonical probe ports retired,
    /// network/routes/DNS restored by their actual ACKs (including missed ACKs),
    /// all original rows stopped/restored, all 48 WFP keys empty and sessions
    /// closed, and restored/removed registry keys. The supplied retired bracket
    /// authenticates closed C/member history and full SDK absence, not these
    /// resource permissions. No Boolean/JSON/lookup-only implementation is sound.
    /// Do not recursively borrow Pair, Source or Retired; their brackets are held.
    /// T, G and their canonical retained originals must be fully closed/disarmed:
    /// destructors must not call DLL exports, repeat native close/unload, probe
    /// historical interfaces, or unwind. Phase/absence metadata alone does NOT
    /// prove those destructor prerequisites. Keep all histories through the final
    /// Pair/Calling postflight; only then may their original owners be dropped.
    pub(crate) unsafe trait NativeTerminalResourceGate<T> {
        /// Called ONLY by this root inside the concrete retired terminal reader.
        /// Resource samplers use inspect_terminal_history_in_bracket, never
        /// reenter the retired reader or resurrect the old Closing/live channel.
        fn authorize_in_retired(
            &self,
            resources: &T,
            context: &Context,
            stopped: &pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &Bindings,
            history: &[ClosedMemberBinding],
        ) -> io::Result<()>;
    }

    struct Pins {
        context: Context,
        runtime: RuntimeRead,
        source: Option<Rc<NativeSourceRead>>,
        retired: Rc<RetiredCarrierRead>,
        stopped: Rc<NativePairIntentRead>,
        expected: pair::Record,
        image: Rc<OriginalImage>,
        supervisor: Rc<NativeDeadline>,
    }
    /// Caller retains this root BEFORE any fallible terminal authentication.
    /// Never returns unique originals solely through Result. No automatic release
    /// of unknown resources or original provenance on Drop. No strong back edge
    /// to this root may be stored in T/G; use actual weak resource read pins.
    /// T must OWN the canonical originals, not only borrow a graph that can be
    /// dropped independently. G must authenticate those exact original owners.
    pub(crate) struct NativeTerminalReleaseRoot<T, G: NativeTerminalResourceGate<T>> {
        pins: ManuallyDrop<Pins>,
        gate: ManuallyDrop<G>,
        resources: ResourceSlot<T>,
        preparation: PreparationState,
        terminal_call: TerminalCallState,
        released: Cell<bool>,
    }
    /// Sealed one-shot permission. Only prepare can mint it; no data constructor.
    /// Carries the very root with all original provenance through unload.
    pub(crate) struct NativeTerminalPermit<T, G: NativeTerminalResourceGate<T>> {
        root: Rc<NativeTerminalReleaseRoot<T, G>>,
        consumed: Cell<bool>,
    }
    impl<T, G: NativeTerminalResourceGate<T>> NativeTerminalReleaseRoot<T, G> {
        #[allow(clippy::too_many_arguments)]
        pub(crate) fn new(
            context: Context,
            runtime: RuntimeRead,
            source: Rc<NativeSourceRead>,
            retired: Rc<RetiredCarrierRead>,
            stopped: Rc<NativePairIntentRead>,
            expected: pair::Record,
            image: Rc<OriginalImage>,
            supervisor: Rc<NativeDeadline>,
            resources: T,
            gate: G,
        ) -> Rc<Self> {
            Rc::new(Self {
                pins: ManuallyDrop::new(Pins {
                    context,
                    runtime,
                    source: Some(source),
                    retired,
                    stopped,
                    expected,
                    image,
                    supervisor,
                }),
                gate: ManuallyDrop::new(gate),
                resources: ResourceSlot::new(resources),
                preparation: PreparationState::new(),
                terminal_call: TerminalCallState::new(),
                released: Cell::new(false),
            })
        }
        /// Published creator identity without Ready Source publication. The
        /// mandatory actual G must authenticate its SAME privately retained
        /// Retired/RowOwner/Runtime/image origins and pregraph attempt ledger.
        /// This is not a None/absence lane: full native terminal Retired reads
        /// and all original resource/destructor ACKs remain hard-wired below.
        #[allow(clippy::too_many_arguments)]
        pub(crate) fn new_prepublication(
            context: Context,
            runtime: RuntimeRead,
            retired: Rc<RetiredCarrierRead>,
            stopped: Rc<NativePairIntentRead>,
            expected: pair::Record,
            image: Rc<OriginalImage>,
            supervisor: Rc<NativeDeadline>,
            resources: T,
            gate: G,
        ) -> Rc<Self> {
            Rc::new(Self {
                pins: ManuallyDrop::new(Pins {
                    context,
                    runtime,
                    source: None,
                    retired,
                    stopped,
                    expected,
                    image,
                    supervisor,
                }),
                gate: ManuallyDrop::new(gate),
                resources: ResourceSlot::new(resources),
                preparation: PreparationState::new(),
                terminal_call: TerminalCallState::new(),
                released: Cell::new(false),
            })
        }
        pub(crate) fn retained_resources(&self) -> io::Result<Ref<'_, T>> {
            let original = self.resources.value.try_borrow().map_err(|_| conflict())?;
            Ref::filter_map(original, Option::as_ref).map_err(|_| conflict())
        }
        fn original_continuity(&self) -> io::Result<()> {
            let p = &self.pins;
            if self.preparation.tainted.get()
                || self.terminal_call.attempt.tainted.get()
                || !p.stopped.matches_runtime(&p.runtime)
                || p.source.as_ref().is_some_and(|source| {
                    !p.retired.matches_source_origin(source)
                        || source.network_scope() != &p.context.intent.scope
                })
                || !p.image.matches_runtime(&p.runtime)
            {
                return Err(conflict());
            }
            // The original supervisor outlives Calling. A revoked forward pin
            // cannot authenticate idle disposition after successful cleanup.
            // This factual gate authenticates the SAME runtime/lease without
            // minting a pin or granting an effect outside cleanup Calling.
            p.supervisor
                .verify_cleanup_runtime_entry(&p.runtime, &p.context)
                .map_err(io::Error::other)?;
            // Does not query the image or resolve an export. Safe also AFTER
            // unloading; same real source/runtime/serialized lock still held.
            p.image
                .verify_terminal_runtime(&p.runtime)
                .map_err(|_| conflict())
        }
        fn continuity(&self) -> io::Result<()> {
            self.original_continuity()?;
            let p = &self.pins;
            // Mint only inside this original supervisor's actual Calling.
            // Construction and final ownership disposal require no read pin.
            let deadline = p.supervisor.read_pin().map_err(io::Error::other)?;
            deadline
                .verify_runtime(&p.supervisor, &p.runtime, &p.context)
                .map_err(io::Error::other)?;
            deadline
                .verify_call(&p.supervisor, &p.context)
                .map_err(io::Error::other)
        }
        fn current(&self) -> io::Result<()> {
            self.continuity()?;
            let p = &self.pins;
            p.stopped.inspect(&p.runtime, &p.supervisor, |actual| {
                compare_terminal(&p.context, actual)?;
                if actual != &p.expected {
                    return Err(conflict());
                }
                self.continuity()
            })?;
            self.continuity()
        }
        fn full_check(&self) -> io::Result<()> {
            self.continuity()?;
            let p = &self.pins;
            p.image.verify_runtime(&p.runtime).map_err(|_| conflict())?;
            p.stopped.inspect(&p.runtime, &p.supervisor, |actual| {
                compare_terminal(&p.context, actual)?;
                if actual != &p.expected {
                    return Err(conflict());
                }
                let resources = self.retained_resources()?;
                let joined = JoinedAck::new();
                // Hard-wired actual opaque terminal read, not an overridable G
                // inspector. Its full-empty SDK/history before-after bracket
                // must return successfully before prepare/unload can proceed.
                p.retired
                    .inspect_terminal_bindings_and_history(|bindings, history| {
                        if bindings.scope != p.context.intent.scope
                            || bindings.carrier.as_ref().is_none_or(|c| {
                                c.identity.scope != p.context.intent.scope
                                    || c.identity.proof.guid != p.context.bindings[0].guid
                                    || c.sources
                                        != p.context
                                            .intent
                                            .addresses
                                            .iter()
                                            .map(|a| a.addr())
                                            .collect::<Vec<_>>()
                            })
                        {
                            return Err(crate::windows::member_carrier_wintun::Error::Conflict);
                        }
                        for original in history {
                            original.comparison_provider(&p.context).map_err(|_| {
                                crate::windows::member_carrier_wintun::Error::Conflict
                            })?;
                        }
                        self.gate
                            .authorize_in_retired(
                                &resources, &p.context, actual, &p.retired, bindings, history,
                            )
                            .map_err(|_| crate::windows::member_carrier_wintun::Error::Conflict)?;
                        joined.acknowledge();
                        Ok(())
                    })
                    .map_err(|_| conflict())?;
                joined.verify()?;
                self.continuity()
            })?;
            p.image.verify_runtime(&p.runtime).map_err(|_| conflict())?;
            self.current()
        }
        pub(crate) fn prepare(self: &Rc<Self>) -> io::Result<NativeTerminalPermit<T, G>> {
            let attempt = self.preparation.begin()?;
            self.full_check()?;
            attempt.finish()?;
            Ok(NativeTerminalPermit {
                root: self.clone(),
                consumed: Cell::new(false),
            })
        }
        /// Caller supplies the SAME original loaded module and an EMPTY retained
        /// ACK slot, both rooted outside this call. The sealed native ACK is put
        /// in that slot BEFORE the actual supervisor's fallible postflight. No
        /// graph destruction occurs in Calling or on Err/unwind. Never nest this
        /// method inside another supervised call.
        pub(crate) fn unload_in_terminal_call(
            self: &Rc<Self>,
            module: &mut crate::windows::member_carrier_module::native::LoadedWintun,
            retained_ack: &mut Option<NativeModuleReleased<T, G>>,
        ) -> io::Result<()> {
            self.terminal_call.run(|| {
                if retained_ack.is_some() {
                    return Err(conflict());
                }
                let p = &self.pins;
                p.supervisor
                    .run_terminal_cleanup(&p.context, &p.stopped, &p.expected, || {
                        let permit = self
                            .prepare()
                            .map_err(|_| crate::member_carrier::CarrierError::Conflict)?;
                        module
                            .release_terminal_into(permit, retained_ack)
                            .map_err(|_| crate::member_carrier::CarrierError::Conflict)?;
                        Ok(())
                    })
                    .map_err(|_| conflict())
            })
        }
        fn after_terminal_call(&self) -> io::Result<()> {
            // Only our successful actual run_terminal_cleanup can set this;
            // an idle Runtime, copied receipt or inner native ACK cannot.
            self.terminal_call.verify()?;
            self.original_continuity()?;
            let p = &self.pins;
            compare_terminal(&p.context, &p.expected)?;
            p.stopped
                .verify_terminal_entry(&p.runtime, &p.context, &p.expected)?;
            self.original_continuity()
        }
        /// Requires SAME module ACK AND this root's whole terminal Calling has
        /// returned successfully. Final idle checks are protected record/runtime/
        /// source/serialized reads ONLY, not SDK reads or effect permission.
        pub(crate) fn release_resources(&self, ack: &NativeModuleReleased<T, G>) -> io::Result<()> {
            self.resources.release(|| {
                if !ack.matches_root(self) {
                    return Err(conflict());
                }
                self.after_terminal_call()
            })?;
            self.released.set(true);
            Ok(())
        }
        /// Authenticated final-disposal check AFTER resource/actor release.
        /// An inner native return, copied state, or idle Runtime is insufficient.
        pub(crate) fn verify_released_original(
            &self,
            ack: &NativeModuleReleased<T, G>,
        ) -> io::Result<()> {
            if !self.released.get()
                || !ack.matches_root(self)
                || self
                    .resources
                    .value
                    .try_borrow()
                    .map_err(|_| conflict())?
                    .is_some()
            {
                return Err(conflict());
            }
            self.after_terminal_call()
        }
        /// Only the original supervisor may acknowledge its eventual final
        /// Drop. SAME module ACK + actual resource disposal + whole supervised
        /// postflight precede this bookkeeping; no copied-state grant.
        pub(crate) fn verify_supervisor_terminal_drop(
            &self,
            supervisor: &crate::windows::member_native_deadline::NativeDeadline,
            ack: &NativeModuleReleased<T, G>,
        ) -> io::Result<()> {
            if !std::ptr::eq(supervisor, self.pins.supervisor.as_ref()) {
                return Err(conflict());
            }
            self.verify_released_original(ack)
        }
        pub(crate) fn allow_original_supervisor_drop(
            &self,
            ack: &NativeModuleReleased<T, G>,
        ) -> io::Result<()> {
            self.pins
                .supervisor
                .allow_terminal_drop(self, ack)
                .map_err(|_| conflict())
        }
    }
    impl<T, G: NativeTerminalResourceGate<T>> Drop for NativeTerminalReleaseRoot<T, G> {
        fn drop(&mut self) {
            if self.released.get() {
                // SAFETY: these fields are dropped once, ONLY after actual
                // native unload ACK + postflight + authenticated resource Drop.
                unsafe {
                    ManuallyDrop::drop(&mut self.gate);
                    ManuallyDrop::drop(&mut self.pins);
                }
            }
            // Otherwise intentionally retain exact provenance/gate to process
            // exit, independently of ResourceSlot's no-Drop-on-unknown rule.
        }
    }
    struct TerminalAttempt<'a> {
        tainted: &'a Cell<bool>,
        succeeded: bool,
    }
    impl Drop for TerminalAttempt<'_> {
        fn drop(&mut self) {
            if !self.succeeded {
                self.tainted.set(true);
            }
        }
    }
    impl<T, G: NativeTerminalResourceGate<T>> NativeTerminalPermit<T, G> {
        pub(crate) fn original_image(&self) -> &OriginalImage {
            &self.root.pins.image
        }
        pub(crate) fn pre_unload(&self) -> io::Result<()> {
            if self.consumed.replace(true) {
                self.root.preparation.tainted.set(true);
                return Err(conflict());
            }
            let mut attempt = TerminalAttempt {
                tainted: &self.root.preparation.tainted,
                succeeded: false,
            };
            self.root.full_check()?;
            attempt.succeeded = true;
            Ok(())
        }
        pub(crate) fn post_unload(&self) -> io::Result<()> {
            let mut attempt = TerminalAttempt {
                tainted: &self.root.preparation.tainted,
                succeeded: false,
            };
            self.root.current()?;
            attempt.succeeded = true;
            Ok(())
        }
        pub(crate) fn matches_root(&self, root: &NativeTerminalReleaseRoot<T, G>) -> bool {
            std::ptr::eq(self.root.as_ref(), root) && self.consumed.get()
        }
    }
    #[cfg(test)]
    fn actual_terminal_api_requires_original_root_and_native_module_ack<
        T,
        G: NativeTerminalResourceGate<T>,
    >(
        root: &Rc<NativeTerminalReleaseRoot<T, G>>,
        module: &mut crate::windows::member_carrier_module::native::LoadedWintun,
        retained_ack: &mut Option<NativeModuleReleased<T, G>>,
    ) -> io::Result<()> {
        // Type-check the real native path, never executed on the host, no
        // fabricated NativePair/Retired/Runtime/Calling/G/LoadedWintun inputs.
        root.unload_in_terminal_call(module, retained_ack)?;
        root.release_resources(retained_ack.as_ref().ok_or_else(conflict)?)
    }
}
#[cfg(test)]
#[path = "member_carrier_terminal_release_tests.rs"]
mod tests;
