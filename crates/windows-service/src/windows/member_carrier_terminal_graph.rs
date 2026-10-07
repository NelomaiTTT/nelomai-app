//! Canonical terminal ownership cut. Factory OFF.
//! Capture completion is NOT native cleanup, disarm, unload or destructor ACK.
#![allow(dead_code)]
#[cfg(windows)]
use crate::windows::{
    member_carrier_assembly::TerminalResources, member_carrier_terminal_release::TerminalCallState,
};
#[cfg(not(windows))]
use crate::{
    member_carrier_assembly::TerminalResources, member_carrier_terminal_release::TerminalCallState,
};
use std::io;
fn conflict() -> io::Error {
    io::Error::other("canonical_terminal_graph_conflict")
}
/// Unknown Drop retains inputs AND any constructed root. No owning input is
/// returned solely through Result; the external root is set before postflight.
struct RetainedReleaseInputs<I, R> {
    inputs: TerminalResources<I>,
    root: TerminalResources<Option<std::rc::Rc<R>>>,
    call: std::rc::Rc<TerminalCallState>,
    release_attempted: bool,
}
impl<I, R> RetainedReleaseInputs<I, R> {
    fn new(inputs: I) -> Self {
        Self {
            inputs: TerminalResources::new(inputs),
            root: TerminalResources::new(None),
            call: std::rc::Rc::new(TerminalCallState::new()),
            release_attempted: false,
        }
    }
    fn construct_into(
        &mut self,
        external: &mut Option<std::rc::Rc<R>>,
        construct: impl FnOnce(&mut I, &mut Option<std::rc::Rc<R>>) -> io::Result<()>,
        postflight: impl FnOnce(&std::rc::Rc<R>) -> io::Result<()>,
    ) -> io::Result<()> {
        let call = self.call.clone();
        call.run(|| {
            if external.is_some() || self.root.retained().is_some() {
                return Err(conflict());
            }
            construct(self.inputs.retained_mut(), self.root.retained_mut())?;
            let root = self.root.retained().as_ref().ok_or_else(conflict)?;
            *external = Some(root.clone());
            postflight(root)
        })
    }
    /// Native caller supplies the actual released-root/opaque ACK check. This
    /// only disposes aliases after that check; it cannot mint a release proof.
    fn release_with(
        &mut self,
        original: &std::rc::Rc<R>,
        verify: impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        if std::mem::replace(&mut self.release_attempted, true) {
            return Err(conflict());
        }
        let retained = self.root.retained().as_ref().ok_or_else(conflict)?;
        if !std::rc::Rc::ptr_eq(retained, original) {
            return Err(conflict());
        }
        verify()?;
        self.inputs.release_original_with(|_| verify())?;
        self.root.release_original_with(|root| {
            if root
                .as_ref()
                .is_none_or(|r| !std::rc::Rc::ptr_eq(r, original))
            {
                return Err(conflict());
            }
            verify()
        })
    }
}
/// Both owning destinations exist before any external drain/separation/check.
/// Completion is a cut ACK only, never a native absence/destructor grant.
struct PregraphOwnershipCut<C, M> {
    resources: TerminalResources<C>,
    modules: TerminalResources<M>,
    completed: std::rc::Rc<TerminalCallState>,
}
impl<C, M> PregraphOwnershipCut<C, M> {
    fn new(resources: C, modules: M) -> Self {
        Self {
            resources: TerminalResources::new(resources),
            modules: TerminalResources::new(modules),
            completed: std::rc::Rc::new(TerminalCallState::new()),
        }
    }
    fn capture(
        &mut self,
        drain: impl FnOnce(&mut C, &mut M) -> io::Result<()>,
        separate: impl FnOnce(&mut C, &mut M) -> io::Result<()>,
        verify: impl FnOnce(&C, &M, &TerminalCallState) -> io::Result<()>,
    ) -> io::Result<()> {
        let completed = self.completed.clone();
        completed.run(|| {
            drain(self.resources.retained_mut(), self.modules.retained_mut())?;
            separate(self.resources.retained_mut(), self.modules.retained_mut())?;
            verify(
                self.resources.retained(),
                self.modules.retained(),
                &completed,
            )
        })
    }
}
// Retention only: T's actual issuer is mandatory at the native caller. This
// cannot create a receipt, prove its meaning or complete an enclosing call.
fn retain_same_receipt<T>(
    destination: &std::cell::RefCell<Option<std::rc::Rc<T>>>,
    original: std::rc::Rc<T>,
) -> io::Result<()> {
    let mut retained = destination.try_borrow_mut().map_err(|_| conflict())?;
    if retained
        .as_ref()
        .is_some_and(|first| !std::rc::Rc::ptr_eq(first, &original))
    {
        return Err(conflict());
    }
    if retained.is_none() {
        *retained = Some(original);
    }
    Ok(())
}

// Origin selection only. This never constructs a close/unload ACK or grants
// permission from equal comparison data.
fn unique_originals<T>(originals: impl IntoIterator<Item = std::rc::Rc<T>>) -> Vec<std::rc::Rc<T>> {
    let mut selected = Vec::new();
    for original in originals {
        if !selected
            .iter()
            .any(|retained| std::rc::Rc::ptr_eq(retained, &original))
        {
            selected.push(original);
        }
    }
    selected
}

// Factual owner selection only. A missing original still needs the actual
// private Never ledger; two owning controllers can never be hidden by choosing
// the first or by equal stopped data. No owner is moved or disposed here.
fn single_current_original<'a, T: 'a>(
    originals: impl IntoIterator<Item = &'a T>,
) -> io::Result<Option<&'a T>> {
    let mut originals = originals.into_iter();
    let selected = originals.next();
    if originals.next().is_some() {
        return Err(conflict());
    }
    Ok(selected)
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::{
        member_carrier_native_ownership::Context,
        member_carrier_pair as pair,
        windows::{
            member_carrier_assembly::native::{
                NativeAssemblyAssets, NativeAssemblySlot, NativeAssemblyTerminalResources,
            },
            member_carrier_bootstrap::native::{
                BootstrapAssets, NativeBootstrapSlot, NativeBootstrapTerminalModule,
                NativeBootstrapTerminalParts,
            },
            member_carrier_coordinator::native::CarrierReadyGate,
            member_carrier_guard::{
                Bindings, NativeGuardTerminalClose, NativeGuardTerminalFence,
                NativeGuardTerminalInput,
            },
            member_carrier_members::ClosedMemberBinding,
            member_carrier_pair_io::native::{
                self as actor, NativeActorCanonicalCut, NativeActorCanonicalTerminalResources,
                NativeActorInputs, NativeActorLocalResources, NativeActorTerminalCut,
                NativeActorTerminalGate, NativeActorTerminalGraph, NativeActorTerminalResources,
            },
            member_carrier_ready::native::{NativeCarrierRoot, NativeCarrierTerminalResources},
            member_carrier_runtime::native::{
                NativeConstructionSlot, NativeResourceRowsRead, RetiredCarrierRead,
            },
            member_carrier_startup::native::{
                NativeGraphTerminalResources, TerminalStartupRaw, TerminalStartupResources,
            },
            member_carrier_terminal_release::native::NativeTerminalResourceGate,
        },
    };
    use std::{
        cell::RefCell,
        rc::{Rc, Weak},
    };

    /// These are OUTSIDE resource T. No release root, module ACK or permit is
    /// retained here. Unknown abandonment retains every exact original.
    pub(crate) struct NativeTerminalModuleOriginals<'a> {
        constructions: Vec<NativeConstructionSlot<'a, CarrierReadyGate>>,
        assembly_assets: Vec<NativeAssemblyAssets>,
        bootstrap_assets: Vec<BootstrapAssets>,
        bootstraps: Vec<NativeBootstrapSlot>,
        bootstrap_cuts: Vec<Rc<RefCell<TerminalResources<NativeBootstrapTerminalParts>>>>,
        bootstrap_modules: Vec<NativeBootstrapTerminalModule>,
        carrier_shells: Vec<NativeCarrierRoot<'a>>,
        assembly_shells: Vec<NativeAssemblySlot>,
        startup_shells: Vec<Rc<RefCell<Box<dyn actor::NativeStartup<'a> + 'a>>>>,
    }
    impl<'a> NativeTerminalModuleOriginals<'a> {
        fn empty() -> Self {
            Self {
                constructions: Vec::new(),
                assembly_assets: Vec::new(),
                bootstrap_assets: Vec::new(),
                bootstraps: Vec::new(),
                bootstrap_cuts: Vec::new(),
                bootstrap_modules: Vec::new(),
                carrier_shells: Vec::new(),
                assembly_shells: Vec::new(),
                startup_shells: Vec::new(),
            }
        }
        /// Counts actual retained owning loader slots, never image aliases.
        pub(crate) fn module_count(&self) -> usize {
            // Unknown/partial bootstrap load returns may hide another owning
            // loader. Never advertise one module by overlooking that obligation.
            if self.verify_bootstrap_dispositions().is_err() {
                return usize::MAX;
            }
            self.constructions
                .len()
                .checked_add(self.assembly_assets.len())
                .and_then(|n| n.checked_add(self.bootstrap_assets.len()))
                .unwrap_or(usize::MAX)
        }
        fn verify_bootstrap_dispositions(&self) -> io::Result<()> {
            if self.bootstraps.len() != self.bootstrap_cuts.len()
                || self.bootstraps.len() != self.bootstrap_modules.len()
            {
                return Err(conflict());
            }
            for ((shell, raw), module) in self
                .bootstraps
                .iter()
                .zip(&self.bootstrap_cuts)
                .zip(&self.bootstrap_modules)
            {
                let raw = raw.try_borrow().map_err(|_| conflict())?;
                let raw = raw.retained();
                shell
                    .verify_original_terminal_transfer(raw)
                    .map_err(|_| conflict())?;
                raw.verify_original_module_transfer(module)
                    .map_err(|_| conflict())?;
                if raw.attempt_facts() != (true, true, true, true)
                    || raw.registry.is_some()
                    || raw.keys.is_some()
                    || raw.original_inputs().is_none()
                {
                    return Err(conflict());
                }
            }
            Ok(())
        }
        /// Borrows the SAME original loader; no HMODULE reconstruction. Caller
        /// selects a retained construction by ordinal, not by equal metadata.
        /// The terminal permit still authenticates exact OriginalImage/module.
        /// Gate must not recursively borrow this construction/authority.
        pub(crate) fn with_original_loaded_module(
            &self,
            ordinal: usize,
            call: impl FnOnce(
                &mut crate::windows::member_carrier_module::native::LoadedWintun,
            ) -> io::Result<()>,
        ) -> io::Result<()> {
            self.constructions
                .get(ordinal)
                .ok_or_else(conflict)?
                .with_original_loaded_module_for_terminal(call)
        }
    }

    /// Final authenticated disposal of the OUTSIDE-T module container. No
    /// default callback or permission from an inner native return alone.
    pub(crate) fn release_original_modules_with_ack<'a, T, G: NativeTerminalResourceGate<T>>(
        container: &mut TerminalResources<NativeTerminalModuleOriginals<'a>>,
        root: &Rc<
            crate::windows::member_carrier_terminal_release::native::NativeTerminalReleaseRoot<
                T,
                G,
            >,
        >,
        ack: &crate::windows::member_carrier_module::native::NativeModuleReleased<T, G>,
    ) -> io::Result<()> {
        container.release_original_with(|originals| {
            root.verify_released_original(ack)?;
            if originals.module_count() != 1 || originals.constructions.len() != 1 {
                return Err(conflict());
            }
            originals.verify_bootstrap_dispositions()?;
            originals.with_original_loaded_module(0, |module| {
                module
                    .verify_terminal_disposition(ack)
                    .map_err(|_| conflict())
            })?;
            root.verify_released_original(ack)?;
            for (shell, raw) in originals.bootstraps.iter().zip(&originals.bootstrap_cuts) {
                raw.try_borrow_mut()
                    .map_err(|_| conflict())?
                    .release_original_with(|raw| {
                        root.verify_released_original(ack)?;
                        shell
                            .verify_original_terminal_transfer(raw)
                            .map_err(|_| conflict())
                    })?;
            }
            Ok(())
        })
    }

    /// ALL remaining exact fields from one actual input after Ready/Assembly
    /// cuts. No owning input is reconstructed from metadata on an error.
    struct NativeInputTerminalRaw<'a> {
        // Present ONLY during the actual partial cut; G forbids this field.
        original: Option<Box<NativeActorInputs<'a>>>,
        metadata: Option<NativeInputTerminalPins>,
        graph: Option<NativeGraphTerminalResources>,
        controllers: [Option<actor::Controller>; 2],
        carrier: Option<NativeCarrierTerminalResources<'a>>,
        assembly: Option<NativeAssemblyTerminalResources>,
    }
    struct NativeInputTerminalPins {
        context: Context,
        runtime: Rc<crate::windows::member_carrier_key_authority::RuntimeRead>,
        lock: RefCell<crate::windows::member_carrier_key_authority::KeyLock>,
        lock_pin: crate::windows::member_carrier_key_authority::KeyLockPin,
        files: crate::windows::member_session::NativeSessionFiles,
        store: Rc<
            RefCell<
                crate::windows::member_carrier_pair_store::native_store::NativeCarrierPairStore,
            >,
        >,
        pair: Rc<crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead>,
        expected: pair::Record,
        pins: crate::windows::member_carrier_ready::native::NativeCarrierPins,
        member_source: Rc<crate::windows::member_carrier_payload::native::MemberSource>,
        _never_effects:
            Rc<crate::windows::member_carrier_member_controller::native::NativeNeverMemberEffects>,
    }
    type OriginalGuardClose = (Rc<RefCell<actor::Guard>>, Rc<NativeGuardTerminalClose>);
    type OriginalKeyCloses = [Option<Rc<crate::windows::member_carrier_keys::KeyHandleClosed>>; 3];

    pub(crate) struct NativeCanonicalTerminalResources<'a> {
        locals: Rc<NativeActorLocalResources>,
        rows: Rc<NativeResourceRowsRead>,
        probes: Rc<actor::ProbeRead>,
        generations_pending: actor::NativeMemberGenerationTerminalResources,
        generations: Option<Rc<actor::NativeMemberGenerationTerminalCut>>,
        bootstrap_cuts: Vec<Rc<RefCell<TerminalResources<NativeBootstrapTerminalParts>>>>,
        startup: Option<TerminalStartupRaw<'a>>,
        inputs: Vec<NativeInputTerminalRaw<'a>>,
        complete: Rc<TerminalCallState>,
        published: Rc<TerminalCallState>,
        guard_close: Rc<TerminalCallState>,
        guard_call: Rc<TerminalCallState>,
        row_transfer_call: Rc<TerminalCallState>,
        key_call: Rc<TerminalCallState>,
        key_closes: RefCell<Vec<OriginalKeyCloses>>,
        adapter_call: Rc<TerminalCallState>,
        adapter_reference: RefCell<
            Option<
                Rc<crate::windows::member_carrier_wintun::native::OriginalAdapterModuleReleased>,
            >,
        >,
        // Exact Guard origins, not a model/engine number. Each actual receipt is
        // retained here by the close callback BEFORE external postflight.
        guards: RefCell<Vec<OriginalGuardClose>>,
        components: Vec<
            Rc<crate::windows::member_carrier_wintun::native::NativeCarrierComponentsTerminalRead>,
        >,
        terminal_pair: Option<
            Rc<crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead>,
        >,
        terminal_record: Option<pair::Record>,
    }

    /// Caller creates and retains this BEFORE touching either actor cut.
    /// Partial inputs remain rooted here even if a later Source/module/graph
    /// borrow fails; successful capture never disarms their unknown Drops.
    pub(crate) struct NativeCanonicalTerminalCapture<'a> {
        canonical: TerminalResources<NativeCanonicalTerminalResources<'a>>,
        modules: Rc<RefCell<TerminalResources<NativeTerminalModuleOriginals<'a>>>>,
        incoming: TerminalResources<Vec<Box<NativeActorInputs<'a>>>>,
        startup_output: TerminalStartupResources<'a>,
        complete: Rc<TerminalCallState>,
        published: Rc<TerminalCallState>,
    }
    pub(crate) struct NativeCanonicalTerminalGate<'a> {
        locals: Weak<NativeActorLocalResources>,
        rows: Weak<NativeResourceRowsRead>,
        probes: Weak<actor::ProbeRead>,
        modules: Weak<RefCell<TerminalResources<NativeTerminalModuleOriginals<'a>>>>,
        complete: Weak<TerminalCallState>,
        published: Weak<TerminalCallState>,
    }
    pub(crate) type CanonicalActorT<'a> = NativeActorTerminalResources<
        NativeCanonicalTerminalResources<'a>,
        NativeCanonicalTerminalGate<'a>,
    >;
    pub(crate) type CanonicalActorG<'a> = NativeActorTerminalGate<
        NativeCanonicalTerminalResources<'a>,
        NativeCanonicalTerminalGate<'a>,
    >;
    pub(crate) type NativeCanonicalTerminalRelease<'a> = actor::NativeActorTerminalRelease<
        NativeCanonicalTerminalResources<'a>,
        NativeCanonicalTerminalGate<'a>,
    >;
    pub(crate) type NativeCanonicalTerminalAck<'a> = actor::NativeActorTerminalAck<
        NativeCanonicalTerminalResources<'a>,
        NativeCanonicalTerminalGate<'a>,
    >;
    /// Factual aliases of existing opaque originals, not permission. Obtain
    /// before publication and retain independently of C/release root. Native
    /// Calling, Pair durable ACK, full terminal Retired SDK and G remain required.
    pub(crate) struct NativeCanonicalTerminalPins {
        _original_getter: (),
        pub(crate) context: Context,
        pub(crate) runtime: Rc<crate::windows::member_carrier_key_authority::RuntimeRead>,
        pub(crate) source: Rc<crate::windows::member_carrier_runtime::native::NativeSourceRead>,
        pub(crate) retired: Rc<RetiredCarrierRead>,
        pub(crate) stopped:
            Rc<crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead>,
        pub(crate) expected: pair::Record,
        pub(crate) image: Rc<crate::windows::member_carrier_module::native::OriginalImage>,
        pub(crate) supervisor: Rc<crate::windows::member_native_deadline::NativeDeadline>,
    }

    /// Distinct attempted-C owning lane. No full-graph Rows/Probe pins are
    /// constructed, and no failed native branch can be converted into Never.
    pub(crate) struct NativePregraphTerminalResources<'a> {
        startup: Option<TerminalStartupRaw<'a>>,
        local: Rc<NativeActorTerminalCut<'a>>,
        pair: Option<
            Rc<crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead>,
        >,
        record: Option<pair::Record>,
        components: Vec<
            Rc<crate::windows::member_carrier_wintun::native::NativeCarrierComponentsTerminalRead>,
        >,
        bootstrap_cuts: Vec<Rc<RefCell<TerminalResources<NativeBootstrapTerminalParts>>>>,
        completed: Rc<TerminalCallState>,
        keys_call: TerminalCallState,
        key_closes: RefCell<OriginalKeyCloses>,
        adapter_call: TerminalCallState,
        adapter: RefCell<
            Option<
                Rc<crate::windows::member_carrier_wintun::native::OriginalAdapterModuleReleased>,
            >,
        >,
    }
    pub(crate) struct NativePregraphTerminalGate<'a> {
        local: Weak<NativeActorTerminalCut<'a>>,
        completed: Weak<TerminalCallState>,
        modules: Weak<RefCell<TerminalResources<NativeTerminalModuleOriginals<'a>>>>,
    }
    pub(crate) type NativePregraphTerminalRelease<'a> =
        crate::windows::member_carrier_terminal_release::native::NativeTerminalReleaseRoot<
            NativePregraphTerminalResources<'a>,
            NativePregraphTerminalGate<'a>,
        >;
    pub(crate) type NativePregraphTerminalAck<'a> =
        crate::windows::member_carrier_module::native::NativeModuleReleased<
            NativePregraphTerminalResources<'a>,
            NativePregraphTerminalGate<'a>,
        >;
    pub(crate) struct NativePregraphTerminalPins {
        pub(crate) context: Context,
        pub(crate) runtime: Rc<crate::windows::member_carrier_key_authority::RuntimeRead>,
        pub(crate) source:
            Option<Rc<crate::windows::member_carrier_runtime::native::NativeSourceRead>>,
        pub(crate) retired: Rc<RetiredCarrierRead>,
        pub(crate) stopped:
            Rc<crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead>,
        pub(crate) expected: pair::Record,
        pub(crate) image: Rc<crate::windows::member_carrier_module::native::OriginalImage>,
        pub(crate) supervisor: Rc<crate::windows::member_native_deadline::NativeDeadline>,
    }
    pub(crate) struct NativePregraphTerminalCapture<'a> {
        cut: PregraphOwnershipCut<
            NativePregraphTerminalResources<'a>,
            Rc<RefCell<TerminalResources<NativeTerminalModuleOriginals<'a>>>>,
        >,
        incoming: TerminalStartupResources<'a>,
        publication: TerminalCallState,
    }
    impl<'a> NativePregraphTerminalCapture<'a> {
        pub(crate) fn new(local: Rc<NativeActorTerminalCut<'a>>) -> Self {
            let completed = Rc::new(TerminalCallState::new());
            Self {
                cut: PregraphOwnershipCut::new(
                    NativePregraphTerminalResources {
                        startup: None,
                        local,
                        pair: None,
                        record: None,
                        components: Vec::new(),
                        bootstrap_cuts: Vec::new(),
                        completed,
                        keys_call: TerminalCallState::new(),
                        key_closes: RefCell::new([None, None, None]),
                        adapter_call: TerminalCallState::new(),
                        adapter: RefCell::new(None),
                    },
                    Rc::new(RefCell::new(TerminalResources::new(
                        NativeTerminalModuleOriginals::empty(),
                    ))),
                ),
                incoming: TerminalStartupResources::empty(),
                publication: TerminalCallState::new(),
            }
        }
        /// Register this object BEFORE calling. Every moved/rejected original
        /// stays in the two retained destinations on error/unwind. This method
        /// is never used as a fallback from failed full graph capture.
        pub(crate) fn capture(
            &mut self,
            canonical: &Rc<NativeActorCanonicalCut<'a>>,
        ) -> io::Result<()> {
            let incoming = &mut self.incoming;
            self.cut.capture(
                |c, modules| {
                    // Retain exact Pair and original wrapper BEFORE any drain.
                    unsafe {
                        canonical.with_originals_mut(|original| {
                            c.pair = Some(original.terminal_pair.clone());
                            c.record = Some(original.terminal_record.clone());
                            if original.roots.is_some() {
                                return Err(conflict());
                            }
                            Ok(())
                        })?;
                    }
                    canonical.drain_startup_into(incoming)?;
                    incoming
                        .transfer_original_into(&mut c.startup)
                        .map_err(|_| conflict())?;
                    let startup = c.startup.as_ref().ok_or_else(conflict)?;
                    startup
                        .verify_pregraph_original_cut()
                        .map_err(|_| conflict())?;
                    // Root the SAME drained Box/Rc outside resource T. No authority
                    // is reconstructed from empty fields or module ordinals.
                    unsafe {
                        canonical.with_originals_mut(|original| {
                            let shell = original.startup.take().ok_or_else(conflict)?;
                            modules
                                .try_borrow_mut()
                                .map_err(|_| conflict())?
                                .retained_mut()
                                .startup_shells
                                .push(shell);
                            Ok(())
                        })?;
                    }
                    Ok(())
                },
                |c, modules| {
                    let raw = c.startup.as_mut().ok_or_else(conflict)?;
                    *c.key_closes.get_mut() = std::mem::take(&mut raw.terminal_key_closes);
                    let mut modules = modules.try_borrow_mut().map_err(|_| conflict())?;
                    let modules = modules.retained_mut();
                    separate_modules(raw.carrier.as_mut(), raw.assembly.as_mut(), modules)?;
                    for bootstrap in &mut modules.bootstraps {
                        let output = Rc::new(RefCell::new(TerminalResources::new(
                            NativeBootstrapTerminalParts::empty(),
                        )));
                        c.bootstrap_cuts.push(output.clone());
                        modules.bootstrap_cuts.push(output.clone());
                        let mut output = output.try_borrow_mut().map_err(|_| conflict())?;
                        bootstrap
                            .drain_terminal_into(&mut output)
                            .map_err(|_| conflict())?;
                        bootstrap
                            .verify_original_terminal_transfer(output.retained())
                            .map_err(|_| conflict())?;
                        let mut retained = TerminalResources::new(Vec::new());
                        output
                            .retained_mut()
                            .transfer_loaded_module_into(&mut retained, |v| v, |_| Ok(()))
                            .map_err(|_| conflict())?;
                        let mut originals = None;
                        retained
                            .transfer_original_into(&mut originals)
                            .map_err(|_| conflict())?;
                        modules
                            .bootstrap_modules
                            .extend(originals.ok_or_else(conflict)?);
                        output
                            .retained()
                            .verify_original_module_transfer(
                                modules.bootstrap_modules.last().ok_or_else(conflict)?,
                            )
                            .map_err(|_| conflict())?;
                    }
                    // Exactly the actual successful C construction, not a full
                    // module-count fallback for zero/unknown/partial constructors.
                    if modules.constructions.len() != 1
                        || !modules.assembly_assets.is_empty()
                        || !modules.bootstrap_assets.is_empty()
                    {
                        return Err(conflict());
                    }
                    let parts = modules.constructions[0].retained_parts();
                    let (carrier, _) = parts.components.as_ref().ok_or_else(conflict)?;
                    c.components.push(carrier.terminal_components_read());
                    carrier
                        .verify_terminal_components()
                        .map_err(|_| conflict())?;
                    modules.verify_bootstrap_dispositions()
                },
                |c, modules, _| {
                    c.startup
                        .as_ref()
                        .ok_or_else(conflict)?
                        .verify_pregraph_original_cut()
                        .map_err(|_| conflict())?;
                    if c.components.len() != 1
                        || modules
                            .try_borrow()
                            .map_err(|_| conflict())?
                            .retained()
                            .module_count()
                            != 1
                    {
                        return Err(conflict());
                    }
                    Ok(())
                },
            )?;
            self.cut
                .resources
                .retained()
                .completed
                .run(|| self.cut.completed.verify())
        }
        pub(crate) fn module_originals(
            &self,
        ) -> Rc<RefCell<TerminalResources<NativeTerminalModuleOriginals<'a>>>> {
            self.cut.modules.retained().clone()
        }
        pub(crate) fn terminal_original_pins(&self) -> io::Result<NativePregraphTerminalPins> {
            self.cut.completed.verify()?;
            let c = self.cut.resources.retained();
            c.completed.verify()?;
            let raw = c.startup.as_ref().ok_or_else(conflict)?;
            raw.verify_pregraph_original_cut().map_err(|_| conflict())?;
            let startup = raw.startup.as_ref().ok_or_else(conflict)?;
            let carrier = raw.carrier.as_ref().ok_or_else(conflict)?;
            let meta = carrier.meta.as_ref().ok_or_else(conflict)?;
            let retired = carrier
                .lifecycle
                .as_ref()
                .ok_or_else(conflict)?
                .retired_pin()
                .map_err(|_| conflict())?;
            let stopped = c.pair.as_ref().ok_or_else(conflict)?;
            let expected = c.record.as_ref().ok_or_else(conflict)?;
            crate::windows::member_carrier_terminal_release::compare_terminal(
                &startup.context,
                expected,
            )?;
            if meta.scope.context != startup.context
                || !meta.runtime.same_original_runtime(&startup.runtime)
                || !meta.pair.same_store_origin(stopped)
                || !Rc::ptr_eq(&meta.supervisor, &startup.supervisor)
                || carrier
                    .source
                    .as_ref()
                    .is_some_and(|s| !retired.matches_source_origin(s))
            {
                return Err(conflict());
            }
            Ok(NativePregraphTerminalPins {
                context: startup.context.clone(),
                runtime: startup.runtime.clone(),
                source: carrier.source.clone(),
                retired,
                stopped: stopped.clone(),
                expected: expected.clone(),
                image: Rc::new(meta.image.read_pin().map_err(|_| conflict())?),
                supervisor: startup.supervisor.clone(),
            })
        }
        pub(crate) fn close_original_resources(
            &self,
            pins: &NativePregraphTerminalPins,
        ) -> io::Result<()> {
            let c = self.cut.resources.retained();
            verify_pregraph_pins(c, pins)?;
            c.keys_call.run(|| pins.supervisor.run_terminal_cleanup(&pins.context, &pins.stopped, &pins.expected, || {
                pins.stopped.inspect(&pins.runtime, &pins.supervisor, |record| {
                    if record != &pins.expected { return Err(conflict()); }
                    pins.retired.inspect_terminal_bindings_and_history(|bindings, history| {
                        verify_pregraph_resource_facts(c, &pins.context, record, &pins.retired, bindings, history).map_err(|_| native_wintun_conflict())?;
                        let raw = c.startup.as_ref().ok_or_else(native_wintun_conflict)?;
                        let assembly = raw.assembly.as_ref().ok_or_else(native_wintun_conflict)?;
                        let fence = PregraphOriginalKeyFence { c, pins, bindings, history };
                        {
                        let mut held_lock = raw.lock.try_borrow_mut().map_err(|_| native_wintun_conflict())?;
                        let lock = held_lock.as_mut().ok_or_else(native_wintun_conflict)?;
                        assembly.with_terminal_original_key_owner(|owner| owner.with_terminal_original_keys(lock, |_, keys, _| {
                            for (slot, key) in keys.into_iter().enumerate() {
                                if let Some(key) = key {
                                    if let Some(ack) = c.key_closes.try_borrow().map_err(|_| crate::member_carrier::CarrierError::Conflict)?[slot].as_ref() {
                                        crate::windows::member_carrier_keys::verify_terminal_original_key_closed(key, ack)?;
                                        continue;
                                    }
                                    crate::windows::member_carrier_keys::close_terminal_original_key(key, &fence, |ack| {
                                        let mut retained = c.key_closes.try_borrow_mut().map_err(|_| crate::member_carrier::CarrierError::Conflict)?;
                                        if retained[slot].is_some() { return Err(crate::member_carrier::CarrierError::Conflict); }
                                        retained[slot] = Some(ack); Ok(())
                                    })?;
                                }
                            }
                            Ok(())
                        })).map_err(|_| native_wintun_conflict())?;
                        }
                        verify_pregraph_key_originals(c).map_err(|_| native_wintun_conflict())
                    }).map_err(|_| conflict())
                }).map_err(|_| crate::member_carrier::CarrierError::Conflict)
            }).map_err(|_| conflict()))?;
            c.adapter_call.run(|| {
                pins.supervisor
                    .run_terminal_cleanup(&pins.context, &pins.stopped, &pins.expected, || {
                        pins.stopped
                            .inspect(&pins.runtime, &pins.supervisor, |record| {
                                if record != &pins.expected {
                                    return Err(conflict());
                                }
                                pins.retired
                                    .inspect_terminal_bindings_and_history(|bindings, history| {
                                        verify_pregraph_resource_facts(
                                            c,
                                            &pins.context,
                                            record,
                                            &pins.retired,
                                            bindings,
                                            history,
                                        )
                                        .map_err(|_| native_wintun_conflict())?;
                                        pins.retired
                                            .release_adapter_reference_in_terminal_bracket(
                                                &pins.stopped,
                                                record,
                                                |ack| {
                                                    retain_same_receipt(&c.adapter, ack)
                                                        .map_err(|_| native_wintun_conflict())
                                                },
                                            )?;
                                        Ok(())
                                    })
                                    .map_err(|_| conflict())
                            })
                            .map_err(|_| crate::member_carrier::CarrierError::Conflict)
                    })
                    .map_err(|_| conflict())
            })
        }
        pub(crate) fn publish_into(
            &mut self,
            resources: &mut Option<TerminalResources<NativePregraphTerminalResources<'a>>>,
            gate: &mut Option<NativePregraphTerminalGate<'a>>,
        ) -> io::Result<()> {
            self.publication.run(|| {
                if resources.is_some() || gate.is_some() {
                    return Err(conflict());
                }
                let c = self.cut.resources.retained();
                c.completed.verify()?;
                c.keys_call.verify()?;
                c.adapter_call.verify()?;
                let g = NativePregraphTerminalGate {
                    local: Rc::downgrade(&c.local),
                    completed: Rc::downgrade(&c.completed),
                    modules: Rc::downgrade(self.cut.modules.retained()),
                };
                // Transfer an owning retention wrapper, not an owning Result.
                let mut retained = TerminalResources::new(None);
                self.cut
                    .resources
                    .transfer_original_into(retained.retained_mut())
                    .map_err(|_| conflict())?;
                let mut original = None;
                retained
                    .transfer_original_into(&mut original)
                    .map_err(|_| conflict())?;
                *resources = Some(TerminalResources::new(
                    original.flatten().ok_or_else(conflict)?,
                ));
                *gate = Some(g);
                Ok(())
            })
        }
    }

    fn native_wintun_conflict() -> crate::windows::member_carrier_wintun::Error {
        crate::windows::member_carrier_wintun::Error::Conflict
    }
    fn verify_pregraph_pins(
        c: &NativePregraphTerminalResources<'_>,
        pins: &NativePregraphTerminalPins,
    ) -> io::Result<()> {
        c.completed.verify()?;
        let raw = c.startup.as_ref().ok_or_else(conflict)?;
        let startup = raw.startup.as_ref().ok_or_else(conflict)?;
        let carrier = raw.carrier.as_ref().ok_or_else(conflict)?;
        let meta = carrier.meta.as_ref().ok_or_else(conflict)?;
        let retired = carrier
            .lifecycle
            .as_ref()
            .ok_or_else(conflict)?
            .retired_pin()
            .map_err(|_| conflict())?;
        if startup.context != pins.context
            || !Rc::ptr_eq(&startup.runtime, &pins.runtime)
            || !Rc::ptr_eq(&startup.supervisor, &pins.supervisor)
            || !Rc::ptr_eq(&retired, &pins.retired)
            || c.pair
                .as_ref()
                .is_none_or(|p| !Rc::ptr_eq(p, &pins.stopped))
            || c.record.as_ref() != Some(&pins.expected)
            || !meta.runtime.same_original_runtime(&pins.runtime)
            || !meta.image.matches_runtime(&pins.runtime)
            || !pins.image.matches_runtime(&pins.runtime)
            || match (&carrier.source, &pins.source) {
                (Some(a), Some(b)) => !Rc::ptr_eq(a, b),
                (None, None) => false,
                _ => true,
            }
        {
            return Err(conflict());
        }
        Ok(())
    }
    fn verify_pregraph_resource_facts(
        c: &NativePregraphTerminalResources<'_>,
        context: &Context,
        stopped: &pair::Record,
        retired: &RetiredCarrierRead,
        bindings: &Bindings,
        history: &[ClosedMemberBinding],
    ) -> io::Result<()> {
        c.completed.verify()?;
        let raw = c.startup.as_ref().ok_or_else(conflict)?;
        raw.verify_pregraph_original_cut().map_err(|_| conflict())?;
        let startup = raw.startup.as_ref().ok_or_else(conflict)?;
        let carrier = raw.carrier.as_ref().ok_or_else(conflict)?;
        let meta = carrier.meta.as_ref().ok_or_else(conflict)?;
        let pair = c.pair.as_ref().ok_or_else(conflict)?;
        if startup.context != *context
            || c.record.as_ref() != Some(stopped)
            || !meta.runtime.same_original_runtime(&startup.runtime)
            || !meta.pair.same_store_origin(pair)
            || !Rc::ptr_eq(&meta.supervisor, &startup.supervisor)
            || !history.is_empty()
        {
            return Err(conflict());
        }
        crate::windows::member_carrier_terminal_release::compare_terminal(context, stopped)?;
        pair.verify_terminal_bracket(&startup.runtime, &startup.supervisor, context, stopped)?;
        carrier
            .verify_pregraph_original_rows(context, retired, bindings)
            .map_err(|_| conflict())?;
        raw.never_effects
            .as_ref()
            .ok_or_else(conflict)?
            .verify_terminal_original_roots(
                &raw.prepared,
                [None, None],
                raw.retired_members.as_deref().ok_or_else(conflict)?,
                &startup.runtime,
                context,
                stopped,
                history,
            )
            .map_err(|_| conflict())?;
        // Private no-graph lineage above is mandatory; these protected absence
        // observations are factual additional checks, never Option permission.
        if startup
            .runtime
            .optional_records(
                context,
                &[
                    crate::windows::member_session::RecordKind::CarrierGuard,
                    crate::windows::member_session::RecordKind::Network,
                    crate::windows::member_session::RecordKind::MemberARows,
                    crate::windows::member_session::RecordKind::MemberBRows,
                ],
            )
            .map_err(|_| conflict())?
            .iter()
            .any(Option::is_some)
        {
            return Err(conflict());
        }
        if c.components.len() != 1 {
            return Err(conflict());
        }
        let mut wfp =
            crate::windows::member_carrier_guard::ScopedGuardAbsence::open(stopped.scope.clone())
                .map_err(|_| conflict())?;
        let first = wfp.read_snapshot(&stopped.scope).map_err(|_| conflict())?;
        if first != stopped.guard.expected
            || !first.filters.is_empty()
            || first.sublayer.is_some()
            || wfp.read_snapshot(&stopped.scope).map_err(|_| conflict())? != first
        {
            return Err(conflict());
        }
        // Mandatory concrete actor supplier: SAME actual local ledger, not
        // inferred missing rows/probes, a JSON shape or a permissive callback.
        c.local
            .verify_pregraph_terminal_in_retired(context, stopped, retired, bindings, history)?;
        pair.verify_terminal_bracket(&startup.runtime, &startup.supervisor, context, stopped)
    }
    fn verify_pregraph_key_originals(c: &NativePregraphTerminalResources<'_>) -> io::Result<()> {
        let raw = c.startup.as_ref().ok_or_else(conflict)?;
        let startup = raw.startup.as_ref().ok_or_else(conflict)?;
        let mut held_lock = raw.lock.try_borrow_mut().map_err(|_| conflict())?;
        let lock = held_lock.as_mut().ok_or_else(conflict)?;
        if !startup.runtime.matches_lock(lock) {
            return Err(conflict());
        }
        let receipts = c.key_closes.try_borrow().map_err(|_| conflict())?;
        raw.assembly.as_ref().ok_or_else(conflict)?.with_terminal_original_key_owner(|owner| {
            owner.with_terminal_original_key_reads(lock, |_, keys| {
                for (slot, key) in keys.into_iter().enumerate() {
                    match (key, receipts[slot].as_ref()) {
                        (Some(key),Some(ack)) => crate::windows::member_carrier_keys::verify_terminal_original_key_closed(key,ack)?,
                        (None,None) => (), // original owner's authenticated lineage, not lookup absence
                        _ => return Err(crate::member_carrier::CarrierError::Conflict),
                    }
                }
                Ok(())
            })
        }).map_err(|_| conflict())
    }

    /// Handle-close and restored-value ACKs cover neither key-root deletion
    /// nor disposal of that original obligation. This is a separate final G
    /// prerequisite, not a pre-close permission or a path-absence substitute.
    fn require_pregraph_key_roots_disposed(
        c: &NativePregraphTerminalResources<'_>,
    ) -> io::Result<()> {
        let raw = c.startup.as_ref().ok_or_else(conflict)?;
        let startup = raw.startup.as_ref().ok_or_else(conflict)?;
        let mut held_lock = raw.lock.try_borrow_mut().map_err(|_| conflict())?;
        let lock = held_lock.as_mut().ok_or_else(conflict)?;
        if !startup.runtime.matches_lock(lock) {
            return Err(conflict());
        }
        raw.assembly
            .as_ref()
            .ok_or_else(conflict)?
            .with_terminal_original_key_owner(|owner| {
                owner.with_terminal_original_key_reads(lock, |_, keys| {
                    for original in keys.into_iter().flatten() {
                        let obligation =
                            crate::windows::member_carrier_keys::terminal_original_key_obligation(
                                original,
                            );
                        obligation.verify_original(original)?;
                        obligation.require_root_absent()?;
                    }
                    Ok(())
                })
            })
            .map_err(|_| conflict())
    }
    struct PregraphOriginalKeyFence<'a, 'b> {
        c: &'b NativePregraphTerminalResources<'a>,
        pins: &'b NativePregraphTerminalPins,
        bindings: &'b Bindings,
        history: &'b [ClosedMemberBinding],
    }
    unsafe impl crate::windows::member_carrier_keys::NativeKeyTerminalFence
        for PregraphOriginalKeyFence<'_, '_>
    {
        fn verify_original_terminal(
            &self,
            context: &Context,
            binding: &crate::member_carrier_native_ownership::Binding,
        ) -> crate::member_carrier::Result<()> {
            if context != &self.pins.context
                || context.bindings.get(binding.role as usize) != Some(binding)
            {
                return Err(crate::member_carrier::CarrierError::Conflict);
            }
            verify_pregraph_resource_facts(
                self.c,
                context,
                &self.pins.expected,
                &self.pins.retired,
                self.bindings,
                self.history,
            )
            .map_err(|_| crate::member_carrier::CarrierError::Conflict)
        }
    }
    impl<'a> NativePregraphTerminalResources<'a> {
        /// Factual SAME actor cut only. Actor release must additionally verify
        /// actual module/root ACK and successful whole terminal postflight.
        pub(crate) fn original_local_cut(&self) -> &Rc<NativeActorTerminalCut<'a>> {
            &self.local
        }
    }
    struct PregraphReleaseInputs<'a> {
        resources: TerminalResources<NativePregraphTerminalResources<'a>>,
        pins: Option<NativePregraphTerminalPins>,
        gate: Option<NativePregraphTerminalGate<'a>>,
        extracted: Option<NativePregraphTerminalResources<'a>>,
    }
    pub(crate) struct NativePregraphReleaseSlot<'a> {
        retained:
            RetainedReleaseInputs<PregraphReleaseInputs<'a>, NativePregraphTerminalRelease<'a>>,
    }
    impl<'a> NativePregraphReleaseSlot<'a> {
        /// Caller MUST retain this slot before calling construct_into. This
        /// infallible registration owns T, G and every original pin even if the
        /// first alias read errors/unwinds. LoadedWintun stays outside T.
        pub(crate) fn new(
            resources: TerminalResources<NativePregraphTerminalResources<'a>>,
            pins: NativePregraphTerminalPins,
            gate: NativePregraphTerminalGate<'a>,
        ) -> Self {
            Self {
                retained: RetainedReleaseInputs::new(PregraphReleaseInputs {
                    resources,
                    pins: Some(pins),
                    gate: Some(gate),
                    extracted: None,
                }),
            }
        }
        pub(crate) fn construct_into(
            &mut self,
            root: &mut Option<Rc<NativePregraphTerminalRelease<'a>>>,
        ) -> io::Result<()> {
            self.retained.construct_into(
                root,
                |inputs, retained_root| {
                    let pins = inputs.pins.as_ref().ok_or_else(conflict)?;
                    verify_pregraph_pins(inputs.resources.retained(), pins)?;
                    let runtime = pins.runtime.read_pin().map_err(|_| conflict())?;
                    inputs
                        .resources
                        .transfer_original_into(&mut inputs.extracted)
                        .map_err(|_| conflict())?;
                    // Everything below is infallible ownership movement into the root.
                    let original = inputs
                        .extracted
                        .take()
                        .expect("same transferred pregraph resources");
                    let pins = inputs.pins.take().expect("retained pregraph pins");
                    let gate = inputs.gate.take().expect("retained pregraph gate");
                    // Both branches own the SAME original C history. None here means
                    // Ready never published Source, NOT no C or native absence.
                    *retained_root = Some(match pins.source {
                        Some(source) => NativePregraphTerminalRelease::new(
                            pins.context,
                            runtime,
                            source,
                            pins.retired,
                            pins.stopped,
                            pins.expected,
                            pins.image,
                            pins.supervisor,
                            original,
                            gate,
                        ),
                        None => NativePregraphTerminalRelease::new_prepublication(
                            pins.context,
                            runtime,
                            pins.retired,
                            pins.stopped,
                            pins.expected,
                            pins.image,
                            pins.supervisor,
                            original,
                            gate,
                        ),
                    });
                    Ok(())
                },
                |root| {
                    root.retained_resources()?;
                    Ok(())
                },
            )
        }
        /// AFTER actual whole module/root/actor release and module-container
        /// disposal. Clears this slot's root alias so the old serialized lease
        /// cannot be retained by the unknown-Drop wrapper on a known success.
        pub(crate) fn release_with_ack(
            &mut self,
            root: &Rc<NativePregraphTerminalRelease<'a>>,
            ack: &NativePregraphTerminalAck<'a>,
        ) -> io::Result<()> {
            if self.retained.release_attempted {
                return Err(conflict());
            }
            let inputs = self.retained.inputs.retained();
            if inputs.pins.is_some() || inputs.gate.is_some() || inputs.extracted.is_some() {
                self.retained.release_attempted = true;
                return Err(conflict());
            }
            self.retained
                .release_with(root, || root.verify_released_original(ack))
        }
    }
    // SAFETY: owns the SAME private Startup/graph/Ready/Rows/key originals and
    // concrete local cut; modules are outside T. No optional data grants release.
    unsafe impl<'a> NativeTerminalResourceGate<NativePregraphTerminalResources<'a>>
        for NativePregraphTerminalGate<'a>
    {
        fn authorize_in_retired(
            &self,
            c: &NativePregraphTerminalResources<'a>,
            context: &Context,
            stopped: &pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &Bindings,
            history: &[ClosedMemberBinding],
        ) -> io::Result<()> {
            let complete = self.completed.upgrade().ok_or_else(conflict)?;
            if !Rc::ptr_eq(&complete, &c.completed)
                || !Rc::ptr_eq(&self.local.upgrade().ok_or_else(conflict)?, &c.local)
            {
                return Err(conflict());
            }
            let _modules = self.modules.upgrade().ok_or_else(conflict)?;
            complete.verify()?;
            c.keys_call.verify()?;
            c.adapter_call.verify()?;
            verify_pregraph_resource_facts(c, context, stopped, retired, bindings, history)?;
            verify_pregraph_key_originals(c)?;
            require_pregraph_key_roots_disposed(c)?;
            let adapter = c.adapter.try_borrow().map_err(|_| conflict())?;
            retired
                .verify_adapter_reference_in_terminal_bracket(
                    c.pair.as_ref().ok_or_else(conflict)?,
                    stopped,
                    adapter.as_ref().ok_or_else(conflict)?,
                )
                .map_err(|_| conflict())?;
            c.components[0].verify_released().map_err(|_| conflict())?;
            for raw in &c.bootstrap_cuts {
                let raw = raw.try_borrow().map_err(|_| conflict())?;
                if raw.retained().attempt_facts() != (true, true, true, true)
                    || raw.retained().registry.is_some()
                    || raw.retained().keys.is_some()
                    || raw.retained().original_inputs().is_none()
                {
                    return Err(conflict());
                }
            }
            verify_pregraph_resource_facts(c, context, stopped, retired, bindings, history)
        }
    }

    impl<'a> NativeCanonicalTerminalCapture<'a> {
        pub(crate) fn new(
            locals: Rc<NativeActorLocalResources>,
            rows: Rc<NativeResourceRowsRead>,
            probes: Rc<actor::ProbeRead>,
        ) -> Self {
            // No getter, comparison, callback or fallible native boundary before
            // the actual inputs are owned by their destination.
            let complete = Rc::new(TerminalCallState::new());
            let published = Rc::new(TerminalCallState::new());
            Self {
                canonical: TerminalResources::new(NativeCanonicalTerminalResources {
                    locals,
                    rows,
                    probes,
                    generations_pending: TerminalResources::new(None),
                    generations: None,
                    bootstrap_cuts: Vec::new(),
                    startup: None,
                    inputs: Vec::new(),
                    complete: complete.clone(),
                    published: published.clone(),
                    guard_close: Rc::new(TerminalCallState::new()),
                    guard_call: Rc::new(TerminalCallState::new()),
                    row_transfer_call: Rc::new(TerminalCallState::new()),
                    key_call: Rc::new(TerminalCallState::new()),
                    key_closes: RefCell::new(Vec::new()),
                    adapter_call: Rc::new(TerminalCallState::new()),
                    adapter_reference: RefCell::new(None),
                    guards: RefCell::new(Vec::new()),
                    components: Vec::new(),
                    terminal_pair: None,
                    terminal_record: None,
                }),
                modules: Rc::new(RefCell::new(TerminalResources::new(
                    NativeTerminalModuleOriginals::empty(),
                ))),
                incoming: TerminalResources::new(Vec::new()),
                startup_output: TerminalStartupResources::empty(),
                complete,
                published,
            }
        }
        pub(crate) fn module_originals(
            &self,
        ) -> Rc<RefCell<TerminalResources<NativeTerminalModuleOriginals<'a>>>> {
            self.modules.clone()
        }
        /// No minting/readback from metadata, no image/SDK/Source/native query.
        /// Uses the SAME retained canonical input, SAME selected terminal Pair
        /// and already registered actual C Close reader. Not a new lease/grant.
        pub(crate) fn terminal_original_pins(&self) -> io::Result<NativeCanonicalTerminalPins> {
            self.complete.verify()?;
            let c = self.canonical.retained();
            let input = c.inputs.first().ok_or_else(conflict)?;
            let actual = input.metadata.as_ref().ok_or_else(conflict)?;
            let carrier = input.carrier.as_ref().ok_or_else(conflict)?;
            let retired = carrier
                .lifecycle
                .as_ref()
                .ok_or_else(conflict)?
                .retired_pin()
                .map_err(|_| conflict())?;
            let stopped = c.terminal_pair.as_ref().ok_or_else(conflict)?;
            let expected = c.terminal_record.as_ref().ok_or_else(conflict)?;
            if !actual.pair.same_store_origin(stopped)
                || !retired.matches_source_origin(&actual.pins.source)
            {
                return Err(conflict());
            }
            crate::windows::member_carrier_terminal_release::compare_terminal(
                &actual.context,
                expected,
            )?;
            Ok(NativeCanonicalTerminalPins {
                _original_getter: (),
                context: actual.context.clone(),
                runtime: actual.runtime.clone(),
                source: actual.pins.source.clone(),
                retired,
                stopped: stopped.clone(),
                expected: expected.clone(),
                image: input
                    .graph
                    .as_ref()
                    .ok_or_else(conflict)?
                    .image
                    .as_ref()
                    .ok_or_else(conflict)?
                    .clone(),
                supervisor: actual.pins.supervisor.clone(),
            })
        }
        pub(crate) fn capture(
            &mut self,
            actual: &Rc<NativeActorTerminalCut<'a>>,
            canonical: &Rc<NativeActorCanonicalCut<'a>>,
        ) -> io::Result<()> {
            let complete = self.complete.clone();
            complete.run(|| {
                // SAFETY: this SAME retained incoming destination is outside T;
                // each original is kept through partial cut failure and cannot
                // be dropped or replaced while module/destructor proof unknown.
                unsafe {
                    actual.retain_rejected_inputs_into(self.incoming.retained_mut())?;
                }
                // SAFETY: exact originals are moved into caller retention, never
                // returned uniquely through Result. Module cut precedes G.
                unsafe {
                    canonical.with_originals_mut(|originals| {
                        let c = self.canonical.retained_mut();
                        c.terminal_pair = Some(originals.terminal_pair.clone());
                        c.terminal_record = Some(originals.terminal_record.clone());
                        if let Some(input) = originals.roots.take() {
                            self.incoming.retained_mut().push(input);
                        }
                        Ok(())
                    })?;
                }
                if !Rc::ptr_eq(&actual.local_resources(), &self.canonical.retained().locals) {
                    return Err(conflict());
                }
                let c = self.canonical.retained_mut();
                c.locals
                    .drain_member_generation_roots_into(&mut c.generations_pending, |_| Ok(()))?;
                let mut original = None;
                c.generations_pending
                    .transfer_original_into(&mut original)
                    .map_err(|_| conflict())?;
                // No fallible boundary between extraction and raw C retention;
                // the emptied retention wrapper has no unknown-history Drop.
                c.generations = original.flatten();
                canonical.drain_startup_into(&mut self.startup_output)?;
                self.startup_output
                    .transfer_original_into(&mut self.canonical.retained_mut().startup)
                    .map_err(|_| conflict())?;
                {
                    let raw = self
                        .canonical
                        .retained_mut()
                        .startup
                        .as_mut()
                        .ok_or_else(conflict)?;
                    let mut modules = self.modules.try_borrow_mut().map_err(|_| conflict())?;
                    separate_modules(
                        raw.carrier.as_mut(),
                        raw.assembly.as_mut(),
                        modules.retained_mut(),
                    )?;
                }
                // Each input is rooted in C BEFORE its fallible drain. Capture
                // failure leaves both the partially moved raw and original input
                // retained, never an owning Result or an absent-looking graph.
                while let Some(input) = self.incoming.retained_mut().pop() {
                    self.canonical
                        .retained_mut()
                        .inputs
                        .push(NativeInputTerminalRaw {
                            original: Some(input),
                            metadata: None,
                            graph: None,
                            controllers: [None, None],
                            carrier: None,
                            assembly: None,
                        });
                    let raw = self
                        .canonical
                        .retained_mut()
                        .inputs
                        .last_mut()
                        .ok_or_else(conflict)?;
                    let original = raw.original.as_mut().ok_or_else(conflict)?;
                    original
                        .carrier
                        .drain_terminal_into(&mut raw.carrier)
                        .map_err(|_| conflict())?;
                    original
                        .assembly
                        .drain_terminal_into(&mut raw.assembly)
                        .map_err(|_| conflict())?;
                    original
                        .carrier
                        .verify_terminal_drained_into(raw.carrier.as_ref().ok_or_else(conflict)?)
                        .map_err(|_| conflict())?;
                    original
                        .assembly
                        .verify_terminal_drained_into(raw.assembly.as_ref().ok_or_else(conflict)?)
                        .map_err(|_| conflict())?;
                    let mut modules = self.modules.try_borrow_mut().map_err(|_| conflict())?;
                    separate_modules(
                        raw.carrier.as_mut(),
                        raw.assembly.as_mut(),
                        modules.retained_mut(),
                    )?;
                    finish_input_cut(raw, modules.retained_mut());
                }
                verify_module_separation(self.canonical.retained())?;
                {
                    let mut modules = self.modules.try_borrow_mut().map_err(|_| conflict())?;
                    let modules = modules.retained_mut();
                    for bootstrap in &mut modules.bootstraps {
                        // Root every raw output BEFORE the first fallible drain.
                        let raw = Rc::new(RefCell::new(TerminalResources::new(
                            NativeBootstrapTerminalParts::empty(),
                        )));
                        self.canonical
                            .retained_mut()
                            .bootstrap_cuts
                            .push(raw.clone());
                        modules.bootstrap_cuts.push(raw.clone());
                        let mut raw = raw.try_borrow_mut().map_err(|_| conflict())?;
                        bootstrap
                            .drain_terminal_into(&mut raw)
                            .map_err(|_| conflict())?;
                        bootstrap
                            .verify_original_terminal_transfer(raw.retained())
                            .map_err(|_| conflict())?;
                        let (_, _, _, transferred) = raw.retained().attempt_facts();
                        if !transferred {
                            return Err(conflict());
                        }
                        // Actual bootstrap transferred its original loader to
                        // Assembly; this is not an empty Option inference.
                        let mut destination = TerminalResources::new(Vec::new());
                        raw.retained_mut()
                            .transfer_loaded_module_into(&mut destination, |v| v, |_| Ok(()))
                            .map_err(|_| conflict())?;
                        // No checks between transfer and outside-T rooting.
                        let mut moved = None;
                        destination
                            .transfer_original_into(&mut moved)
                            .map_err(|_| conflict())?;
                        modules
                            .bootstrap_modules
                            .extend(moved.ok_or_else(conflict)?);
                        raw.retained()
                            .verify_original_module_transfer(
                                modules.bootstrap_modules.last().ok_or_else(conflict)?,
                            )
                            .map_err(|_| conflict())?;
                    }
                    modules.verify_bootstrap_dispositions()?;
                }
                // Pure reads from SAME owning components, before any loader
                // borrow. Retain first; failed verification leaves every pin in C.
                let mut modules = self.modules.try_borrow_mut().map_err(|_| conflict())?;
                for construction in &mut modules.retained_mut().constructions {
                    let parts = construction.retained_parts();
                    let (carrier, _) = parts.components.as_ref().ok_or_else(conflict)?;
                    self.canonical
                        .retained_mut()
                        .components
                        .push(carrier.terminal_components_read());
                    carrier
                        .verify_terminal_components()
                        .map_err(|_| conflict())?;
                }
                if self.canonical.retained().components.is_empty() {
                    return Err(conflict());
                }
                Ok(())
            })
        }
        /// Whole supervised close; call OUTSIDE Calling. The output root exists
        /// before external Runtime/Retired/SDK boundaries. Inner close ACKs do
        /// not complete this state on a later Retired or supervisor failure.
        pub(crate) fn close_guards(
            &mut self,
            pins: &NativeCanonicalTerminalPins,
        ) -> io::Result<()> {
            let original = self.terminal_original_pins()?;
            if original.context != pins.context
                || original.expected != pins.expected
                || !Rc::ptr_eq(&original.runtime, &pins.runtime)
                || !Rc::ptr_eq(&original.source, &pins.source)
                || !Rc::ptr_eq(&original.retired, &pins.retired)
                || !Rc::ptr_eq(&original.stopped, &pins.stopped)
                || !Rc::ptr_eq(&original.image, &pins.image)
                || !Rc::ptr_eq(&original.supervisor, &pins.supervisor)
            {
                return Err(conflict());
            }
            self.drain_stopped_row_captures(pins)?;
            let whole = self.canonical.retained().guard_call.clone();
            whole.run(|| {
                pins.supervisor
                    .run_terminal_cleanup(&pins.context, &pins.stopped, &pins.expected, || {
                        pins.stopped
                            .inspect(&pins.runtime, &pins.supervisor, |actual| {
                                if actual != &pins.expected {
                                    return Err(conflict());
                                }
                                pins.retired
                                    .inspect_terminal_bindings_and_history(|bindings, history| {
                                        self.close_guards_in_terminal_bracket(
                                            &pins.stopped,
                                            &pins.expected,
                                            &pins.retired,
                                            bindings,
                                            history,
                                        )
                                        .map_err(|_| {
                                            crate::windows::member_carrier_wintun::Error::Conflict
                                        })
                                    })
                                    .map_err(|_| conflict())
                            })
                            .map_err(|_| crate::member_carrier::CarrierError::Conflict)
                    })
                    .map_err(|_| conflict())
            })
        }
        fn drain_stopped_row_captures(
            &mut self,
            pins: &NativeCanonicalTerminalPins,
        ) -> io::Result<()> {
            let c = self.canonical.retained_mut();
            let completed = c.row_transfer_call.clone();
            completed.run(|| {
                pins.supervisor.run_terminal_cleanup(&pins.context, &pins.stopped, &pins.expected, || {
                    pins.stopped.inspect(&pins.runtime, &pins.supervisor, |actual| {
                        if actual != &pins.expected { return Err(conflict()); }
                        pins.retired.inspect_terminal_bindings_and_history(|bindings, _| {
                            let rows = c.rows.clone();
                            rows.inspect_retired_in_bracket(&pins.retired, bindings, |facts| {
                                if let Some(carrier) = c.startup.as_mut().and_then(|s| s.carrier.as_mut()) {
                                    carrier.drain_stopped_partial_rows_in_retired(&pins.retired, &rows, facts, &pins.context).map_err(|_| crate::windows::member_carrier_wintun::Error::Conflict)?;
                                }
                                for input in &mut c.inputs {
                                    input.carrier.as_mut().ok_or(crate::windows::member_carrier_wintun::Error::Conflict)?
                                        .drain_stopped_partial_rows_in_retired(&pins.retired, &rows, facts, &pins.context)
                                        .map_err(|_| crate::windows::member_carrier_wintun::Error::Conflict)?;
                                }
                                Ok(())
                            })
                        }).map_err(|_| conflict())
                    }).map_err(|_| crate::member_carrier::CarrierError::Conflict)
                }).map_err(|_| conflict())
            })
        }
        /// Close SAME retained NEW-HKEYs after whole Guard close. Call outside
        /// Calling; partial native ACKs stay in C even when any postflight fails.
        /// No key owner or mutable original lock is returned through Result.
        pub(crate) fn close_key_handles(
            &self,
            pins: &NativeCanonicalTerminalPins,
        ) -> io::Result<()> {
            let original = self.terminal_original_pins()?;
            if original.context != pins.context
                || original.expected != pins.expected
                || !Rc::ptr_eq(&original.runtime, &pins.runtime)
                || !Rc::ptr_eq(&original.source, &pins.source)
                || !Rc::ptr_eq(&original.retired, &pins.retired)
                || !Rc::ptr_eq(&original.stopped, &pins.stopped)
                || !Rc::ptr_eq(&original.image, &pins.image)
                || !Rc::ptr_eq(&original.supervisor, &pins.supervisor)
            {
                return Err(conflict());
            }
            let c = self.canonical.retained();
            c.guard_call.verify()?;
            if c.terminal_pair
                .as_ref()
                .is_none_or(|p| !Rc::ptr_eq(p, &pins.stopped))
                || c.terminal_record.as_ref() != Some(&pins.expected)
            {
                return Err(conflict());
            }
            c.key_call.run(|| {
                pins.supervisor.run_terminal_cleanup(
                    &pins.context, &pins.stopped, &pins.expected, || {
                        pins.stopped.inspect(&pins.runtime, &pins.supervisor, |actual| {
                            if actual != &pins.expected { return Err(conflict()); }
                            pins.retired.inspect_terminal_bindings_and_history(|bindings, history| {
                                let fence = CanonicalKeyFence { canonical: c, pins, bindings, history };
                                for (index, input) in c.inputs.iter().enumerate() {
                                    let metadata = input.metadata.as_ref().ok_or(
                                        crate::windows::member_carrier_wintun::Error::Conflict)?;
                                    if metadata.context != pins.context
                                        || !metadata.runtime.same_original_runtime(&pins.runtime)
                                        || !metadata.pair.same_store_origin(&pins.stopped)
                                    { return Err(crate::windows::member_carrier_wintun::Error::Conflict); }
                                    // Allocate the retained ACK destination BEFORE owner validation
                                    // or any RegCloseKey. Index only selects this immutable C slot;
                                    // G must still verify SAME actual key/close receipt identities.
                                    if c.key_closes.try_borrow().map_err(|_| {
                                        crate::windows::member_carrier_wintun::Error::Conflict
                                    })?.len() != index {
                                        return Err(crate::windows::member_carrier_wintun::Error::Conflict);
                                    }
                                    c.key_closes.try_borrow_mut().map_err(|_| {
                                        crate::windows::member_carrier_wintun::Error::Conflict
                                    })?.push([None, None, None]);
                                    let mut lock = metadata.lock.try_borrow_mut().map_err(|_| {
                                        crate::windows::member_carrier_wintun::Error::Conflict
                                    })?;
                                    let assembly = input.assembly.as_ref().ok_or(
                                        crate::windows::member_carrier_wintun::Error::Conflict)?;
                                    assembly.with_terminal_original_key_owner(|owner| {
                                        owner.with_terminal_original_keys(&mut lock, |_, keys, _| {
                                            for (slot, original) in keys.into_iter().enumerate() {
                                                if let Some(original) = original {
                                                    crate::windows::member_carrier_keys::close_terminal_original_key(
                                                        original, &fence, |ack| {
                                                            let mut retained = c.key_closes.try_borrow_mut()
                                                                .map_err(|_| crate::member_carrier::CarrierError::Conflict)?;
                                                            let dest = &mut retained[index][slot];
                                                            if dest.is_some() { return Err(crate::member_carrier::CarrierError::Conflict); }
                                                            *dest = Some(ack);
                                                            Ok(())
                                                        })?;
                                                }
                                            }
                                            Ok(())
                                        })
                                    }).map_err(|_| crate::windows::member_carrier_wintun::Error::Conflict)?;
                                }
                                // Reauthenticate ALL actual close receipts after the mutable
                                // owner/lock borrows end, before Retired/Pair/supervisor postflight.
                                // This read lane never queries an already-closed HKEY.
                                verify_terminal_key_originals(c)
                                    .map_err(|_| crate::windows::member_carrier_wintun::Error::Conflict)
                            }).map_err(|_| conflict())
                        }).map_err(|_| crate::member_carrier::CarrierError::Conflict)
                    }).map_err(|_| conflict())
            })
        }
        /// Release ONLY this original closed C adapter's extra DLL reference.
        /// Whole supervised success is separate from the factual native ACK.
        /// No loader unload, owner disarm or resource Drop permission here.
        pub(crate) fn release_adapter_reference(
            &self,
            pins: &NativeCanonicalTerminalPins,
        ) -> io::Result<()> {
            let original = self.terminal_original_pins()?;
            if original.context != pins.context
                || original.expected != pins.expected
                || !Rc::ptr_eq(&original.runtime, &pins.runtime)
                || !Rc::ptr_eq(&original.source, &pins.source)
                || !Rc::ptr_eq(&original.retired, &pins.retired)
                || !Rc::ptr_eq(&original.stopped, &pins.stopped)
                || !Rc::ptr_eq(&original.image, &pins.image)
                || !Rc::ptr_eq(&original.supervisor, &pins.supervisor)
            {
                return Err(conflict());
            }
            let c = self.canonical.retained();
            c.key_call.verify()?;
            c.adapter_call.run(|| {
                pins.supervisor.run_terminal_cleanup(
                    &pins.context, &pins.stopped, &pins.expected, || {
                        pins.stopped.inspect(&pins.runtime, &pins.supervisor, |actual| {
                            if actual != &pins.expected { return Err(conflict()); }
                            pins.retired.inspect_terminal_bindings_and_history(|bindings, history| {
                                let check = || {
                                    verify_terminal_key_receipts(c)?;
                                    verify_terminal_guard_receipts(c, &pins.stopped, actual, &pins.retired, bindings)?;
                                    verify_terminal_resource_facts(c, &pins.context, actual, &pins.retired, bindings, history)
                                };
                                check().map_err(|_| crate::windows::member_carrier_wintun::Error::Conflict)?;
                                pins.retired.release_adapter_reference_in_terminal_bracket(
                                    &pins.stopped, actual, |ack| {
                                        // ONLY retain: Runtime still has its mutable receipt-slot
                                        // borrow here. Never call G/Pair/Source/Retired recursively.
                                        retain_same_receipt(&c.adapter_reference, ack)
                                            .map_err(|_| crate::windows::member_carrier_wintun::Error::Conflict)
                                    })?;
                                // The Runtime's mutable receipt-slot borrow has ended. Factual
                                // returned ACK still needs SAME-original verification and all
                                // independent resource postflight before whole-call completion.
                                let retained = c.adapter_reference.try_borrow()
                                    .map_err(|_| crate::windows::member_carrier_wintun::Error::Conflict)?;
                                pins.retired.verify_adapter_reference_in_terminal_bracket(
                                    &pins.stopped, actual, retained.as_ref().ok_or(
                                        crate::windows::member_carrier_wintun::Error::Conflict)?)?;
                                check().map_err(|_| crate::windows::member_carrier_wintun::Error::Conflict)
                            }).map_err(|_| conflict())
                        }).map_err(|_| crate::member_carrier::CarrierError::Conflict)
                    }).map_err(|_| conflict())
            })
        }
        /// Execute inside SAME run_terminal_cleanup + terminal Retired SDK
        /// lease under the authenticated outer Pair read frame. This function
        /// never reenters Pair.inspect or a Guard transaction. No nested Calling.
        /// All Graph aliases are selected by Rc origin BEFORE any close; each
        /// engine is closed ONCE. Failure/unwind retains real partial ACKs in C
        /// and permanently prevents publication/release preparation.
        fn close_guards_in_terminal_bracket(
            &mut self,
            pair: &Rc<
                crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead,
            >,
            stopped: &pair::Record,
            retired: &Rc<RetiredCarrierRead>,
            bindings: &Bindings,
            history: &[ClosedMemberBinding],
        ) -> io::Result<()> {
            let c = self.canonical.retained();
            c.complete.verify()?;
            if c.terminal_pair
                .as_ref()
                .is_none_or(|actual| !Rc::ptr_eq(actual, pair))
                || c.terminal_record.as_ref() != Some(stopped)
            {
                return Err(conflict());
            }
            let context = &c
                .startup
                .as_ref()
                .ok_or_else(conflict)?
                .startup
                .as_ref()
                .ok_or_else(conflict)?
                .context;
            let fence = CanonicalEngineFence {
                canonical: c,
                context,
                pair,
                stopped,
                retired,
                bindings,
                history,
            };
            c.guard_close.run(|| {
                verify_terminal_resource_facts(c, context, stopped, retired, bindings, history)?;
                for input in &c.inputs {
                    if !input
                        .metadata
                        .as_ref()
                        .ok_or_else(conflict)?
                        .pair
                        .same_store_origin(pair)
                    {
                        return Err(conflict());
                    }
                }
                for guard in c.guard_originals()? {
                    let mut original = guard.try_borrow_mut().map_err(|_| conflict())?;
                    original
                        .close_engines_in_terminal_bracket(
                            NativeGuardTerminalInput {
                                pair,
                                stopped,
                                retired,
                                bindings,
                            },
                            &fence,
                            |ack| {
                                let mut roots =
                                    c.guards.try_borrow_mut().map_err(|_| native_conflict())?;
                                // No equal-data replacement or retry after partial
                                // close. Actual origin registry was deduplicated above.
                                if roots.iter().any(|(held, _)| Rc::ptr_eq(held, &guard)) {
                                    return Err(native_conflict());
                                }
                                roots.push((guard.clone(), ack));
                                Ok(())
                            },
                        )
                        .map_err(|_| conflict())?;
                }
                verify_terminal_guard_receipts(c, pair, stopped, retired, bindings)?;
                verify_terminal_resource_facts(c, context, stopped, retired, bindings, history)
            })
        }
        /// Real actor T/G handoff. Destination must be retained by caller BEFORE
        /// invoking this method. Modules/capture owner remain independently held.
        /// No release root or ACK is stored in C/G, and G's edges are Weak.
        pub(crate) fn publish_actor_into(
            &mut self,
            resources: &mut Option<TerminalResources<CanonicalActorT<'a>>>,
            gate: &mut Option<CanonicalActorG<'a>>,
        ) -> io::Result<()> {
            let publication = self.published.clone();
            publication.run(|| {
                if resources.is_some() || gate.is_some() {
                    return Err(conflict());
                }
                self.canonical.retained().complete.verify()?;
                self.canonical.retained().guard_close.verify()?;
                self.canonical.retained().guard_call.verify()?;
                self.canonical.retained().key_call.verify()?;
                self.canonical.retained().adapter_call.verify()?;
                verify_module_separation(self.canonical.retained())?;
                let c = self.canonical.retained();
                let g = NativeCanonicalTerminalGate {
                    locals: Rc::downgrade(&c.locals),
                    rows: Rc::downgrade(&c.rows),
                    probes: Rc::downgrade(&c.probes),
                    modules: Rc::downgrade(&self.modules),
                    complete: Rc::downgrade(&c.complete),
                    published: Rc::downgrade(&c.published),
                };
                let locals = c.locals.clone();
                let mut retained = TerminalResources::new(None);
                self.canonical
                    .transfer_original_into(retained.retained_mut())
                    .map_err(|_| conflict())?;
                // This temporary destination itself retains unknown C on any unwind.
                // Extraction and actual T registration contain no fallible call.
                let mut actual = None;
                retained
                    .transfer_original_into(&mut actual)
                    .map_err(|_| conflict())?;
                let c = actual.flatten().ok_or_else(conflict)?;
                let (t, g) = NativeActorTerminalResources::original(locals, c, g);
                *resources = Some(TerminalResources::new(t));
                *gate = Some(g);
                Ok(())
            })
        }
    }

    fn finish_input_cut<'a>(
        raw: &mut NativeInputTerminalRaw<'a>,
        modules: &mut NativeTerminalModuleOriginals<'a>,
    ) {
        // No fallible call after take: each actual field is immediately rooted
        // in C or the separate original module/shell destination.
        let NativeActorInputs {
            context,
            runtime,
            lock,
            files,
            store,
            pair,
            expected,
            carrier,
            assembly,
            pins,
            originals,
            image,
            member_source,
            never_effects,
            members,
            rows,
            guard,
            attestor,
            guard_resources,
            lifecycle,
            lifecycle_gate,
            probes,
            probe_read,
            probe_state,
            network_read,
            baseline,
            network_gate,
            network_owner,
            network_ack,
            controllers,
            member_gates,
        } = *raw
            .original
            .take()
            .expect("rooted input drained before split");
        modules.carrier_shells.push(carrier);
        modules.assembly_shells.push(assembly);
        raw.metadata = Some(NativeInputTerminalPins {
            context,
            runtime,
            lock_pin: lock.pin(),
            lock: RefCell::new(lock),
            files,
            store,
            pair,
            expected,
            pins,
            member_source,
            _never_effects: never_effects,
        });
        raw.controllers = controllers;
        let mut graph = NativeGraphTerminalResources::default();
        // Full actor input cannot mint the private pregraph transfer origin.
        graph.construction_attempted = true;
        graph.members = Some(members);
        graph.image = Some(image);
        graph.originals = Some(originals);
        graph.rows = Some(rows);
        graph.guard = Some(guard);
        graph.attestor = Some(attestor);
        graph.guard_resources = Some(guard_resources);
        graph.lifecycle = Some(lifecycle);
        graph.lifecycle_gate = lifecycle_gate;
        graph.probes = Some(probes);
        graph.probe_read = Some(probe_read);
        graph.probe_state = Some(probe_state);
        graph.network_read = Some(network_read);
        graph.baseline = Some(baseline);
        graph.network_gate = Some(network_gate);
        graph.network_owner = Some(network_owner);
        graph.network_ack = Some(network_ack);
        graph.member_gates = member_gates;
        raw.graph = Some(graph);
    }

    fn separate_modules<'a>(
        carrier: Option<&mut NativeCarrierTerminalResources<'a>>,
        assembly: Option<&mut NativeAssemblyTerminalResources>,
        modules: &mut NativeTerminalModuleOriginals<'a>,
    ) -> io::Result<()> {
        if let Some(carrier) = carrier {
            if let Some(construction) = carrier.construction.take() {
                modules.constructions.push(construction);
            }
        }
        if let Some(assembly) = assembly {
            if let Some(incoming) = assembly.incoming.take() {
                modules.bootstrap_assets.push(incoming);
            }
            if let Some(parts) = assembly.parts.as_mut() {
                if let Some(assets) = parts.assets.get_mut().take() {
                    modules.assembly_assets.push(assets);
                }
                if let Some(bootstrap) = parts.bootstrap.take() {
                    modules.bootstraps.push(bootstrap);
                }
            }
        }
        Ok(())
    }
    fn verify_module_separation(c: &NativeCanonicalTerminalResources<'_>) -> io::Result<()> {
        let verify = |carrier: Option<&NativeCarrierTerminalResources<'_>>,
                      assembly: Option<&NativeAssemblyTerminalResources>| {
            if carrier.is_some_and(|r| r.construction.is_some())
                || assembly.is_some_and(|r| r.incoming.is_some())
            {
                return Err(conflict());
            }
            if let Some(parts) = assembly.and_then(|r| r.parts.as_ref()) {
                if parts.bootstrap.is_some()
                    || parts.assets.try_borrow().map_err(|_| conflict())?.is_some()
                {
                    return Err(conflict());
                }
            }
            Ok(())
        };
        let startup = c.startup.as_ref().ok_or_else(conflict)?;
        verify(startup.carrier.as_ref(), startup.assembly.as_ref())?;
        for input in &c.inputs {
            if input.original.is_some() || input.metadata.is_none() || input.graph.is_none() {
                return Err(conflict());
            }
            verify(input.carrier.as_ref(), input.assembly.as_ref())?;
        }
        Ok(())
    }

    fn native_conflict() -> crate::member_carrier_guard::GuardError {
        crate::member_carrier_guard::GuardError::Conflict
    }
    impl NativeCanonicalTerminalResources<'_> {
        fn guard_originals(&self) -> io::Result<Vec<Rc<RefCell<actor::Guard>>>> {
            let mut originals = Vec::new();
            let startup = self.startup.as_ref().ok_or_else(conflict)?;
            if let Some(graph) = &startup.graph {
                if let Some(original) = &graph.guard {
                    originals.push(original.clone());
                } else if let Some(transfer) = &graph.input_transfer {
                    originals.push(transfer.guard.clone());
                } else {
                    return Err(conflict());
                }
            }
            for input in &self.inputs {
                originals.push(
                    input
                        .graph
                        .as_ref()
                        .ok_or_else(conflict)?
                        .guard
                        .as_ref()
                        .ok_or_else(conflict)?
                        .clone(),
                );
            }
            let selected = unique_originals(originals);
            if selected.is_empty() {
                return Err(conflict());
            }
            Ok(selected)
        }
    }
    struct CanonicalKeyFence<'a, 'r> {
        canonical: &'r NativeCanonicalTerminalResources<'a>,
        pins: &'r NativeCanonicalTerminalPins,
        bindings: &'r Bindings,
        history: &'r [ClosedMemberBinding],
    }
    // SAFETY: only actual NativeOwnership selects its retained NEW-key ACKs.
    // The original Pair frame/Retired SDK lease/Calling are held outside this
    // fence. Actual closed Guard receipts and independent resource checks are
    // mandatory before/after each native close; never query a closed HKEY.
    unsafe impl crate::windows::member_carrier_keys::NativeKeyTerminalFence
        for CanonicalKeyFence<'_, '_>
    {
        fn verify_original_terminal(
            &self,
            context: &Context,
            binding: &crate::member_carrier_native_ownership::Binding,
        ) -> crate::member_carrier::Result<()> {
            let check = || -> io::Result<()> {
                if context != &self.pins.context
                    || context.bindings.get(binding.role as usize) != Some(binding)
                {
                    return Err(conflict());
                }
                self.pins.stopped.verify_terminal_bracket(
                    &self.pins.runtime,
                    &self.pins.supervisor,
                    context,
                    &self.pins.expected,
                )?;
                verify_terminal_guard_receipts(
                    self.canonical,
                    &self.pins.stopped,
                    &self.pins.expected,
                    &self.pins.retired,
                    self.bindings,
                )?;
                verify_terminal_resource_facts(
                    self.canonical,
                    context,
                    &self.pins.expected,
                    &self.pins.retired,
                    self.bindings,
                    self.history,
                )?;
                self.pins.stopped.verify_terminal_bracket(
                    &self.pins.runtime,
                    &self.pins.supervisor,
                    context,
                    &self.pins.expected,
                )
            };
            check().map_err(|_| crate::member_carrier::CarrierError::Conflict)
        }
    }

    fn verify_terminal_key_receipts(c: &NativeCanonicalTerminalResources<'_>) -> io::Result<()> {
        c.key_call.verify()?;
        verify_terminal_key_originals(c)
    }
    // SAME factual verifier used before whole-call completion and by final G.
    // It cannot complete key_call or authorize release on its own.
    fn verify_terminal_key_originals(c: &NativeCanonicalTerminalResources<'_>) -> io::Result<()> {
        let retained = c.key_closes.try_borrow().map_err(|_| conflict())?;
        if retained.len() != c.inputs.len() || c.inputs.is_empty() {
            return Err(conflict());
        }
        for (index, input) in c.inputs.iter().enumerate() {
            let metadata = input.metadata.as_ref().ok_or_else(conflict)?;
            let mut lock = metadata.lock.try_borrow_mut().map_err(|_| conflict())?;
            if !metadata.runtime.matches_lock(&lock) {
                return Err(conflict());
            }
            input.assembly.as_ref().ok_or_else(conflict)?
                .with_terminal_original_key_owner(|owner| {
                    owner.with_terminal_original_key_reads(&mut lock, |_, keys| {
                        for (slot, key) in keys.into_iter().enumerate() {
                            match (key, &retained[index][slot]) {
                                (Some(original), Some(ack)) => {
                                    crate::windows::member_carrier_keys::verify_terminal_original_key_closed(original, ack)?;
                                }
                                (None, None) => { /* actual owner independently authenticated its zero-key ledger */ }
                                _ => return Err(crate::member_carrier::CarrierError::Conflict),
                            }
                        }
                        Ok(())
                    })
                }).map_err(|_| conflict())?;
        }
        Ok(())
    }

    /// Exact original CREATED_NEW obligations must be independently disposed.
    /// Never infer this from APIPA restoration, HKEY close, absent NIC or a
    /// matching registry name. Missing native delete/commit authority denies G.
    fn require_terminal_key_roots_disposed(
        c: &NativeCanonicalTerminalResources<'_>,
    ) -> io::Result<()> {
        if c.inputs.is_empty() {
            return Err(conflict());
        }
        for input in &c.inputs {
            let metadata = input.metadata.as_ref().ok_or_else(conflict)?;
            let mut lock = metadata.lock.try_borrow_mut().map_err(|_| conflict())?;
            if !metadata.runtime.matches_lock(&lock) {
                return Err(conflict());
            }
            input.assembly
                .as_ref()
                .ok_or_else(conflict)?
                .with_terminal_original_key_owner(|owner| {
                    owner.with_terminal_original_key_reads(&mut lock, |_, keys| {
                        for original in keys.into_iter().flatten() {
                            let obligation = crate::windows::member_carrier_keys::terminal_original_key_obligation(original);
                            obligation.verify_original(original)?;
                            obligation.require_root_absent()?;
                        }
                        Ok(())
                    })
                })
                .map_err(|_| conflict())?;
        }
        Ok(())
    }

    struct CanonicalEngineFence<'a, 'r> {
        canonical: &'r NativeCanonicalTerminalResources<'a>,
        context: &'r Context,
        pair: &'r Rc<crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead>,
        stopped: &'r pair::Record,
        retired: &'r Rc<RetiredCarrierRead>,
        bindings: &'r Bindings,
        history: &'r [ClosedMemberBinding],
    }
    // SAFETY: actual resource SDK/protected/original checks are reused without
    // entering Guard, Pair, Source or Retired. Engine closure is deliberately
    // not a prerequisite for its own close. It is mandatory for later unload.
    unsafe impl NativeGuardTerminalFence for CanonicalEngineFence<'_, '_> {
        fn verify_terminal_resources(
            &self,
            original: &NativeGuardTerminalClose,
            bindings: &Bindings,
            observed_wfp: &crate::member_carrier_guard::Snapshot,
        ) -> crate::member_carrier_guard::Result<()> {
            if !Rc::ptr_eq(original.original_pair(), self.pair)
                || !Rc::ptr_eq(original.original_retired(), self.retired)
                || original.expected_stopped() != self.stopped
                || bindings != self.bindings
                || *observed_wfp
                    != crate::member_carrier_guard::Model::empty(self.stopped.scope.clone())?
                        .expected
            {
                return Err(native_conflict());
            }
            verify_terminal_resource_facts(
                self.canonical,
                self.context,
                self.stopped,
                self.retired,
                bindings,
                self.history,
            )
            .map_err(|_| native_conflict())
        }
    }
    fn verify_terminal_guard_receipts(
        c: &NativeCanonicalTerminalResources<'_>,
        pair: &Rc<crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead>,
        stopped: &pair::Record,
        retired: &Rc<RetiredCarrierRead>,
        bindings: &Bindings,
    ) -> io::Result<()> {
        let selected = c.guard_originals()?;
        let receipts = c.guards.try_borrow().map_err(|_| conflict())?;
        if selected.len() != receipts.len() {
            return Err(conflict());
        }
        for guard in selected {
            let (_, ack) = receipts
                .iter()
                .find(|(original, _)| Rc::ptr_eq(original, &guard))
                .ok_or_else(conflict)?;
            if !Rc::ptr_eq(ack.original_pair(), pair)
                || !Rc::ptr_eq(ack.original_retired(), retired)
                || ack.expected_stopped() != stopped
            {
                return Err(conflict());
            }
            guard
                .try_borrow_mut()
                .map_err(|_| conflict())?
                .verify_terminal_closed_in_retired_bracket(ack, bindings)
                .map_err(|_| conflict())?;
        }
        Ok(())
    }
    fn verify_terminal_resource_facts(
        c: &NativeCanonicalTerminalResources<'_>,
        context: &Context,
        stopped: &pair::Record,
        retired: &RetiredCarrierRead,
        bindings: &Bindings,
        history: &[ClosedMemberBinding],
    ) -> io::Result<()> {
        verify_module_separation(c)?;
        crate::windows::member_carrier_terminal_release::compare_terminal(context, stopped)?;
        if bindings.scope != context.intent.scope {
            return Err(conflict());
        }
        retired
            .inspect_terminal_history_in_bracket(|actual| {
                if actual != history {
                    return Err(crate::windows::member_carrier_wintun::Error::Conflict);
                }
                Ok(())
            })
            .map_err(|_| conflict())?;
        for original in history {
            original
                .comparison_provider(context)
                .map_err(|_| conflict())?;
        }
        c.locals.verify_retired_probe_origins(&c.probes)?;
        c.probes.inspect_retired().map_err(|_| conflict())?;
        let facts = c
            .rows
            .inspect_retired_in_bracket(retired, bindings, |facts| Ok(facts.clone()))
            .map_err(|_| conflict())?;
        let startup = c.startup.as_ref().ok_or_else(conflict)?;
        let pins = startup.startup.as_ref().ok_or_else(conflict)?;
        if pins.context != *context || c.terminal_record.as_ref() != Some(stopped) {
            return Err(conflict());
        }
        let pair = c.terminal_pair.as_ref().ok_or_else(conflict)?;
        let startup_lock = startup.lock.try_borrow().map_err(|_| conflict())?;
        if let Some(lock) = startup_lock.as_ref() {
            if !pins.runtime.matches_lock(lock) {
                return Err(conflict());
            }
        } else {
            // The actual first actor move took this lock. Nil is not proof:
            // require its private retained transfer origin and SAME actual
            // input runtime/store/Pair/lock, including failed input retention.
            let transfer = startup
                .graph
                .as_ref()
                .ok_or_else(conflict)?
                .input_transfer
                .as_ref()
                .ok_or_else(conflict)?;
            if !transfer.pair.same_store_origin(pair)
                || !Rc::ptr_eq(&transfer.rows, &c.rows)
                || !Rc::ptr_eq(&transfer.probes, &c.probes)
            {
                return Err(conflict());
            }
            let matching = c.inputs.iter().any(|raw| {
                let (Some(input), Some(graph)) = (&raw.metadata, &raw.graph) else {
                    return false;
                };
                Rc::ptr_eq(&input.pair, &transfer.pair)
                    && pins.runtime.same_original_runtime(&input.runtime)
                    && Rc::ptr_eq(&pins.store, &input.store)
                    && Rc::ptr_eq(&pins.member_source, &input.member_source)
                    && pins.runtime.matches_pin(&input.lock_pin)
                    && graph
                        .guard
                        .as_ref()
                        .is_some_and(|g| Rc::ptr_eq(g, &transfer.guard))
                    && graph
                        .network_ack
                        .as_ref()
                        .is_some_and(|n| n.same_original(&transfer.network))
            });
            if !matching {
                return Err(conflict());
            }
        }
        drop(startup_lock);
        if let Some(ready) = startup.carrier.as_ref() {
            ready.verify_terminal_row_original(&c.rows, &facts, context)?;
        }
        for raw in &c.inputs {
            let input = raw.metadata.as_ref().ok_or_else(conflict)?;
            let graph = raw.graph.as_ref().ok_or_else(conflict)?;
            if input.context != *context
                || !input.pair.same_store_origin(pair)
                || !pins.runtime.same_original_runtime(&input.runtime)
                || !Rc::ptr_eq(graph.rows.as_ref().ok_or_else(conflict)?, &c.rows)
                || !Rc::ptr_eq(graph.probe_read.as_ref().ok_or_else(conflict)?, &c.probes)
                || !retired.matches_source_origin(&input.pins.source)
                || !input.runtime.matches_pin(&input.lock_pin)
            {
                return Err(conflict());
            }
            raw.carrier
                .as_ref()
                .ok_or_else(conflict)?
                .verify_terminal_row_original(&c.rows, &facts, context)?;
            graph
                .image
                .as_ref()
                .ok_or_else(conflict)?
                .verify_terminal_runtime(&input.runtime)
                .map_err(|_| conflict())?;
            let ack = graph
                .network_owner
                .as_ref()
                .ok_or_else(conflict)?
                .read_pin();
            if !ack.same_original(graph.network_ack.as_ref().ok_or_else(conflict)?)
                || !ack.matches_origin(
                    &input.pins.source,
                    graph.network_gate.as_ref().ok_or_else(conflict)?,
                )
            {
                return Err(conflict());
            }
            graph
                .network_gate
                .as_ref()
                .ok_or_else(conflict)?
                .verify_full_empty_in_retired_bracket(
                    stopped,
                    retired,
                    bindings,
                    graph.baseline.as_ref().ok_or_else(conflict)?,
                    graph.network_read.as_ref().ok_or_else(conflict)?,
                )?;
        }
        c.locals.verify_retired_probe_origins(&c.probes)?;
        retired
            .inspect_terminal_history_in_bracket(|actual| {
                if actual != history {
                    return Err(crate::windows::member_carrier_wintun::Error::Conflict);
                }
                Ok(())
            })
            .map_err(|_| conflict())?;

        Ok(())
    }

    // This is a concrete owning-destructor check, not another effect gate or a
    // default success. The enclosing G already holds the actual Stopped Pair
    // frame, Calling, Retired full-SDK/history bracket and resource close ACKs.
    // Do NOT reborrow the loader's NativeAuthority or query a historical NIC.
    fn verify_inert_terminal_destructors(
        c: &NativeCanonicalTerminalResources<'_>,
        context: &Context,
        stopped: &pair::Record,
        history: &[ClosedMemberBinding],
    ) -> io::Result<()> {
        verify_module_separation(c)?;
        let startup = c.startup.as_ref().ok_or_else(conflict)?;
        let pins = startup.startup.as_ref().ok_or_else(conflict)?;
        let controllers = [
            single_current_original(
                c.inputs
                    .iter()
                    .filter_map(|raw| raw.controllers[0].as_ref()),
            )?,
            single_current_original(
                c.inputs
                    .iter()
                    .filter_map(|raw| raw.controllers[1].as_ref()),
            )?,
        ];
        // The SAME original ledger checks every current and historical owning
        // root, including unused slots. None or empty copied history cannot
        // substitute for its private no-Start/close-registration lineage.
        startup
            .never_effects
            .as_ref()
            .ok_or_else(conflict)?
            .verify_terminal_original_roots(
                &startup.prepared,
                controllers,
                startup.retired_members.as_deref().ok_or_else(conflict)?,
                &pins.runtime,
                context,
                stopped,
                history,
            )
            .map_err(|_| conflict())?;
        for raw in &c.inputs {
            let graph = raw.graph.as_ref().ok_or_else(conflict)?;
            let input = raw.metadata.as_ref().ok_or_else(conflict)?;
            let inventory = graph.probes.as_ref().ok_or_else(conflict)?.read_pin();
            if !inventory.same_inventory(graph.probe_read.as_ref().ok_or_else(conflict)?)
                || !inventory.same_inventory(&c.probes)
            {
                return Err(conflict());
            }
            inventory
                .matches_caps(
                    &input.pins.source,
                    graph.guard.as_ref().ok_or_else(conflict)?,
                    &graph.probe_state.as_ref().ok_or_else(conflict)?.gate(),
                )
                .map_err(|_| conflict())?;
            // Actual canonical held sockets must have their own base/clone
            // close ACKs before their otherwise retaining Drop becomes inert.
            inventory.inspect_retired().map_err(|_| conflict())?;
        }
        Ok(())
    }

    // SAFETY: C retains exact local Rc and ALL moved canonical inputs. Nothing
    // may be released until the mandatory gate verifies native/destructor ACKs
    // and each actual private member-owner ledger authenticates its disposition.
    unsafe impl NativeActorTerminalGraph for NativeCanonicalTerminalResources<'_> {
        fn actor_local_resources(&self) -> &Rc<NativeActorLocalResources> {
            &self.locals
        }
    }
    unsafe impl NativeActorCanonicalTerminalResources for NativeCanonicalTerminalResources<'_> {
        fn actor_rows(&self) -> &Rc<NativeResourceRowsRead> {
            &self.rows
        }
        fn actor_probes(&self) -> &Rc<actor::ProbeRead> {
            &self.probes
        }
        fn actor_member_generation_roots(
            &self,
        ) -> io::Result<Rc<actor::NativeMemberGenerationTerminalCut>> {
            let original = self.generations.as_ref().ok_or_else(conflict)?.clone();
            self.locals.verify_member_generation_transfer(&original)?;
            Ok(original)
        }
    }
    // SAFETY: cannot grant unload while any destructor/referenced-module or
    // terminal network/WFP proof is missing. Original runtime/Retired/resource
    // reads below are factual, not reconstructed owners or generic allows.
    unsafe impl NativeTerminalResourceGate<NativeCanonicalTerminalResources<'_>>
        for NativeCanonicalTerminalGate<'_>
    {
        fn authorize_in_retired(
            &self,
            c: &NativeCanonicalTerminalResources<'_>,
            context: &Context,
            stopped: &pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &Bindings,
            history: &[ClosedMemberBinding],
        ) -> io::Result<()> {
            let complete = self.complete.upgrade().ok_or_else(conflict)?;
            complete.verify()?;
            let published = self.published.upgrade().ok_or_else(conflict)?;
            published.verify()?;
            if !Rc::ptr_eq(&complete, &c.complete)
                || !Rc::ptr_eq(&published, &c.published)
                || !Rc::ptr_eq(&self.locals.upgrade().ok_or_else(conflict)?, &c.locals)
                || !Rc::ptr_eq(&self.rows.upgrade().ok_or_else(conflict)?, &c.rows)
                || !Rc::ptr_eq(&self.probes.upgrade().ok_or_else(conflict)?, &c.probes)
            {
                return Err(conflict());
            }
            // Presence of the actual independently owned module container is
            // required, but is NOT a module ACK. Do not reborrow its authority
            // while original LoadedWintun is borrowed by terminal unload.
            let _modules = self.modules.upgrade().ok_or_else(conflict)?;
            for raw in &c.bootstrap_cuts {
                let raw = raw.try_borrow().map_err(|_| conflict())?;
                let raw = raw.retained();
                if raw.attempt_facts() != (true, true, true, true)
                    || raw.registry.is_some()
                    || raw.keys.is_some()
                {
                    return Err(conflict());
                }
                let input = raw.original_inputs().ok_or_else(conflict)?;
                let pins = c
                    .startup
                    .as_ref()
                    .ok_or_else(conflict)?
                    .startup
                    .as_ref()
                    .ok_or_else(conflict)?;
                if input.context != context
                    || !input
                        .original_intent
                        .same_store_origin(c.terminal_pair.as_ref().ok_or_else(conflict)?)
                    || !input.runtime.same_original_runtime(&pins.runtime)
                {
                    return Err(conflict());
                }
            }
            verify_terminal_resource_facts(c, context, stopped, retired, bindings, history)?;
            c.guard_close.verify()?;
            c.guard_call.verify()?;
            c.row_transfer_call.verify()?;
            verify_terminal_key_receipts(c)?;
            require_terminal_key_roots_disposed(c)?;
            c.adapter_call.verify()?;
            let adapter_reference = c.adapter_reference.try_borrow().map_err(|_| conflict())?;
            retired
                .verify_adapter_reference_in_terminal_bracket(
                    c.terminal_pair.as_ref().ok_or_else(conflict)?,
                    stopped,
                    adapter_reference.as_ref().ok_or_else(conflict)?,
                )
                .map_err(|_| conflict())?;
            if c.components.is_empty() {
                return Err(conflict());
            }
            for original in &c.components {
                original.verify_released().map_err(|_| conflict())?;
            }
            let receipts = c.guards.try_borrow().map_err(|_| conflict())?;
            let selected = c.guard_originals()?;
            if receipts.len() != selected.len() {
                return Err(conflict());
            }
            for guard in selected {
                let (_, ack) = receipts
                    .iter()
                    .find(|(original, _)| Rc::ptr_eq(original, &guard))
                    .ok_or_else(conflict)?;
                if ack.expected_stopped() != stopped
                    || !std::ptr::eq(ack.original_retired().as_ref(), retired)
                {
                    return Err(conflict());
                }
                guard
                    .try_borrow_mut()
                    .map_err(|_| conflict())?
                    .verify_terminal_closed_in_retired_bracket(ack, bindings)
                    .map_err(|_| conflict())?;
            }
            verify_terminal_resource_facts(c, context, stopped, retired, bindings, history)?;
            verify_inert_terminal_destructors(c, context, stopped, history)
        }
    }
}
#[cfg(test)]
#[path = "member_carrier_terminal_graph_tests.rs"]
mod tests;
