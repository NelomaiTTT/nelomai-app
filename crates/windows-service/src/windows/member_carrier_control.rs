//! Actual native terminal composition used by the retained production factory.
//! Pending original layouts remain owned; observations never grant disposal.
#![allow(dead_code)]

use crate::{
    member_carrier_control::CarrierPairFinalizer,
    member_carrier_pair::{CarrierNativePair, CarrierPairTerminalHandoff},
    windows::{
        member_carrier_assembly::TerminalResources,
        member_carrier_pair_io::native::{
            NativeActorCanonicalCut, NativeActorRootHandoff, NativeActorTerminalBranch,
            NativeActorTerminalCut, NativeActorTerminalSelection, NativeCarrierPairIo,
            NativePairJournal,
        },
        member_carrier_startup::NativeAttemptedTerminalLayout,
        member_carrier_terminal_graph::native::{
            self as terminal, CanonicalActorG, CanonicalActorT, NativeCanonicalTerminalAck,
            NativeCanonicalTerminalCapture, NativeCanonicalTerminalPins,
            NativeCanonicalTerminalRelease, NativePregraphReleaseSlot, NativePregraphTerminalAck,
            NativePregraphTerminalCapture, NativePregraphTerminalGate, NativePregraphTerminalPins,
            NativePregraphTerminalRelease, NativePregraphTerminalResources,
            NativeTerminalModuleOriginals,
        },
    },
};
use nelomai_client_tunnel::redundancy::SessionScope;
use std::{cell::RefCell, io, rc::Rc};

type OriginalPair<'a> = CarrierNativePair<NativeCarrierPairIo<'a>, NativePairJournal>;
type CoordinatorCut<'a> = CarrierPairTerminalHandoff<NativeCarrierPairIo<'a>, NativePairJournal>;

/// Every native owning output has a caller-retained destination BEFORE its
/// first fallible boundary. No T/G edge points back to this finisher/root/ACK.
pub(crate) struct NativeCarrierPairFinalizer<'a> {
    scope: Option<SessionScope>,
    coordinator: Option<Rc<CoordinatorCut<'a>>>,
    actor: Option<Rc<NativeActorRootHandoff<'a>>>,
    selection: Option<Rc<NativeActorTerminalSelection<'a>>>,
    branch: Option<NativeActorTerminalBranch<'a>>,
    locals: Option<Rc<NativeActorTerminalCut<'a>>>,
    canonical: Option<Rc<NativeActorCanonicalCut<'a>>>,
    // Large retained raw aggregates live on the heap, not in every cold
    // factory/SessionControl stack frame. Boxing changes no original identity
    // or release order; each owning slot still exists before fallible capture.
    capture: Option<Box<NativeCanonicalTerminalCapture<'a>>>,
    pins: Option<NativeCanonicalTerminalPins>,
    modules: Option<Rc<RefCell<TerminalResources<NativeTerminalModuleOriginals<'a>>>>>,
    resources: Option<TerminalResources<CanonicalActorT<'a>>>,
    gate: Option<CanonicalActorG<'a>>,
    release: Option<Rc<NativeCanonicalTerminalRelease<'a>>>,
    ack: Option<NativeCanonicalTerminalAck<'a>>,
    attempted_layout: Option<NativeAttemptedTerminalLayout>,
    pregraph_capture: Option<Box<NativePregraphTerminalCapture<'a>>>,
    pregraph_pins: Option<NativePregraphTerminalPins>,
    pregraph_resources: Box<Option<TerminalResources<NativePregraphTerminalResources<'a>>>>,
    pregraph_gate: Option<NativePregraphTerminalGate<'a>>,
    pregraph_slot: Option<Box<NativePregraphReleaseSlot<'a>>>,
    pregraph_release: Option<Rc<NativePregraphTerminalRelease<'a>>>,
    pregraph_ack: Option<NativePregraphTerminalAck<'a>>,
    pregraph_captured: bool,
    pregraph_closed: bool,
    pregraph_published: bool,
    locals_captured: bool,
    canonical_captured: bool,
    capture_complete: bool,
    guards_closed: bool,
    keys_closed: bool,
    adapter_released: bool,
    published: bool,
    actor_released: bool,
    completed: bool,
    completed_initial_noc: bool,
}
fn conflict() -> io::Error {
    io::Error::other("native_carrier_terminal_original_or_pending")
}
impl<'a> NativeCarrierPairFinalizer<'a> {
    pub(crate) fn new() -> Self {
        Self {
            scope: None,
            coordinator: None,
            actor: None,
            selection: None,
            branch: None,
            locals: None,
            canonical: None,
            capture: None,
            pins: None,
            modules: None,
            resources: None,
            gate: None,
            release: None,
            ack: None,
            attempted_layout: None,
            pregraph_capture: None,
            pregraph_pins: None,
            pregraph_resources: Box::new(None),
            pregraph_gate: None,
            pregraph_slot: None,
            pregraph_release: None,
            pregraph_ack: None,
            pregraph_captured: false,
            pregraph_closed: false,
            pregraph_published: false,
            locals_captured: false,
            canonical_captured: false,
            capture_complete: false,
            guards_closed: false,
            keys_closed: false,
            adapter_released: false,
            published: false,
            actor_released: false,
            completed: false,
            completed_initial_noc: false,
        }
    }
    /// Scheduling distinction only, after this SAME finalizer acknowledged
    /// native retirement. Initial DATA retirement still needs its opaque root.
    pub(crate) fn completed_initial_noc(&self, pre_pair_initial: bool) -> io::Result<bool> {
        if pre_pair_initial {
            self.verify_unused_before_pair()?;
            return Ok(true);
        }
        if !self.completed {
            return Err(conflict());
        }
        Ok(self.completed_initial_noc)
    }
    /// Pure branch check only. A before-Pair disposition has its OWN original
    /// authority and must not consume or downgrade a used Pair finalizer.
    fn verify_unused_before_pair(&self) -> io::Result<()> {
        macro_rules! absent { ($($field:ident),*) => { $(
            if self.$field.is_some() { return Err(conflict()); }
        )* }; }
        absent!(
            scope,
            coordinator,
            actor,
            selection,
            branch,
            locals,
            canonical,
            capture,
            pins,
            modules,
            resources,
            gate,
            release,
            ack,
            attempted_layout,
            pregraph_capture,
            pregraph_pins,
            pregraph_resources,
            pregraph_gate,
            pregraph_slot,
            pregraph_release,
            pregraph_ack
        );
        if self.pregraph_captured
            || self.pregraph_closed
            || self.pregraph_published
            || self.locals_captured
            || self.canonical_captured
            || self.capture_complete
            || self.guards_closed
            || self.keys_closed
            || self.adapter_released
            || self.published
            || self.actor_released
            || self.completed
            || self.completed_initial_noc
        {
            return Err(conflict());
        }
        Ok(())
    }
    /// Original private layout must be selected BEFORE any full capture. This
    /// lane never consumes full-capture errors as a no-C/pregraph fallback.
    fn finish_pregraph(
        &mut self,
        actor: &Rc<NativeActorRootHandoff<'a>>,
        scope: &SessionScope,
    ) -> io::Result<()> {
        if self.attempted_layout != Some(NativeAttemptedTerminalLayout::PublishedCarrierPregraph) {
            return Err(conflict());
        }
        if !self.actor_released {
            if self.pregraph_capture.is_none() {
                self.pregraph_capture = Some(Box::new(NativePregraphTerminalCapture::new(
                    self.locals.as_ref().ok_or_else(conflict)?.clone(),
                )));
            }
            let capture = self.pregraph_capture.as_mut().ok_or_else(conflict)?;
            if !self.pregraph_captured {
                capture.capture(self.canonical.as_ref().ok_or_else(conflict)?)?;
                self.pregraph_captured = true;
            }
            if self.modules.is_none() {
                self.modules = Some(capture.module_originals());
            }
            if self.pregraph_slot.is_none() {
                if self.pregraph_pins.is_none() {
                    self.pregraph_pins = Some(capture.terminal_original_pins()?);
                }
                let pins = self.pregraph_pins.as_ref().ok_or_else(conflict)?;
                let (stopped, record) = actor.readback_terminal(scope)?;
                if pins.expected.scope != *scope
                    || !Rc::ptr_eq(&pins.stopped, &stopped)
                    || pins.expected != record
                {
                    return Err(conflict());
                }
                if !self.pregraph_closed {
                    capture.close_original_resources(pins)?;
                    self.pregraph_closed = true;
                }
                if !self.pregraph_published {
                    capture.publish_into(&mut self.pregraph_resources, &mut self.pregraph_gate)?;
                    self.pregraph_published = true;
                }
                if self.pregraph_resources.is_none() || self.pregraph_gate.is_none() {
                    return Err(conflict());
                }
                // Infallible owning registration BEFORE any fallible root
                // construction. Slot retains all actual T/G/pins on failure.
                self.pregraph_slot = Some(Box::new(NativePregraphReleaseSlot::new(
                    self.pregraph_resources.take().expect("retained pregraph T"),
                    self.pregraph_pins.take().expect("retained original pins"),
                    self.pregraph_gate.take().expect("retained pregraph G"),
                )));
            }
            if self.pregraph_release.is_none() {
                self.pregraph_slot
                    .as_mut()
                    .ok_or_else(conflict)?
                    .construct_into(&mut self.pregraph_release)?;
            }
            let modules = self.modules.as_ref().ok_or_else(conflict)?.clone();
            let modules = modules.try_borrow().map_err(|_| conflict())?;
            if modules.retained().module_count() != 1 {
                return Err(conflict());
            }
            modules
                .retained()
                .with_original_loaded_module(0, |module| {
                    actor.unload_and_release_pregraph(
                        module,
                        self.pregraph_release.as_ref().ok_or_else(conflict)?,
                        &mut self.pregraph_ack,
                        &mut self.locals,
                        &mut self.canonical,
                    )
                })?;
            self.actor_released = true;
        }
        {
            let modules = self.modules.as_ref().ok_or_else(conflict)?.clone();
            let mut modules = modules.try_borrow_mut().map_err(|_| conflict())?;
            terminal::release_original_modules_with_ack(
                &mut modules,
                self.pregraph_release.as_ref().ok_or_else(conflict)?,
                self.pregraph_ack.as_ref().ok_or_else(conflict)?,
            )?;
        }
        self.pregraph_slot
            .as_mut()
            .ok_or_else(conflict)?
            .release_with_ack(
                self.pregraph_release.as_ref().ok_or_else(conflict)?,
                self.pregraph_ack.as_ref().ok_or_else(conflict)?,
            )?;
        self.pregraph_release
            .as_ref()
            .ok_or_else(conflict)?
            .allow_original_supervisor_drop(self.pregraph_ack.as_ref().ok_or_else(conflict)?)?;
        self.coordinator.take();
        self.actor.take();
        self.branch.take();
        self.selection.take();
        self.pregraph_capture.take();
        self.pregraph_slot.take();
        self.pregraph_ack.take();
        self.pregraph_release.take();
        self.modules.take();
        self.completed = true;
        Ok(())
    }
}

#[cfg(test)]
#[test]
fn actual_initial_completion_selector_requires_unused_pair_finalizer() {
    assert!(
        std::mem::size_of::<NativeCarrierPairFinalizer<'_>>() <= 16 * 1024,
        "cold factory control must not embed terminal raw aggregates on the stack"
    );
    let mut original = NativeCarrierPairFinalizer::new();
    // This boolean is scheduling from the separate original native outcome,
    // not authority from Pair absence or a Stopped snapshot.
    assert!(original.completed_initial_noc(true).unwrap());
    assert!(original.completed_initial_noc(false).is_err());
    let flags: [fn(&mut NativeCarrierPairFinalizer<'_>); 13] = [
        |f| f.pregraph_captured = true,
        |f| f.pregraph_closed = true,
        |f| f.pregraph_published = true,
        |f| f.locals_captured = true,
        |f| f.canonical_captured = true,
        |f| f.capture_complete = true,
        |f| f.guards_closed = true,
        |f| f.keys_closed = true,
        |f| f.adapter_released = true,
        |f| f.published = true,
        |f| f.actor_released = true,
        |f| f.completed = true,
        |f| f.completed_initial_noc = true,
    ];
    for mark_used in flags {
        let mut used = NativeCarrierPairFinalizer::new();
        mark_used(&mut used);
        assert!(used.completed_initial_noc(true).is_err());
    }
    original.scope = Some(SessionScope {
        runtime: nelomai_contracts::RuntimeSlot::Stable,
        runtime_generation: 2,
        session_id: "11111111-1111-4111-8111-111111111111".into(),
        connection_generation: 3,
    });
    assert!(original.completed_initial_noc(true).is_err());
    let mut pair = NativeCarrierPairFinalizer::new();
    pair.completed = true;
    assert!(!pair.completed_initial_noc(false).unwrap());
    pair.completed_initial_noc = true;
    assert!(pair.completed_initial_noc(false).unwrap());
    assert!(pair.completed_initial_noc(true).is_err());
}
impl<'a> CarrierPairFinalizer<NativeCarrierPairIo<'a>, NativePairJournal>
    for NativeCarrierPairFinalizer<'a>
{
    fn finish(
        &mut self,
        original: &mut Option<OriginalPair<'a>>,
        scope: &SessionScope,
    ) -> io::Result<()> {
        if self.scope.as_ref().is_some_and(|actual| actual != scope) {
            return Err(conflict());
        }
        if self.completed {
            return if original.is_none() {
                Ok(())
            } else {
                Err(conflict())
            };
        }
        if self.scope.is_none() {
            self.scope = Some(scope.clone());
        }
        if self.actor.is_none() {
            NativeCarrierPairIo::capture_coordinator_into(
                original,
                &mut self.coordinator,
                &mut self.actor,
                scope,
                |_| Ok(()), // owning registration only; native barriers run inside capture
            )?;
        }
        if original.is_some() {
            return Err(conflict());
        }
        let actor = self.actor.as_ref().ok_or_else(conflict)?.clone();
        if crate::member_carrier_control::continue_pregraph_terminal(
            self.attempted_layout == Some(NativeAttemptedTerminalLayout::PublishedCarrierPregraph),
            self.actor_released,
        ) {
            return self.finish_pregraph(&actor, scope);
        }
        if !self.actor_released {
            let (stopped, record) = actor.readback_terminal(scope)?;
            if self.branch.is_none() {
                actor.select_terminal_branch(&stopped, &record, &mut self.selection)?;
                self.branch = Some(actor.sealed_terminal_branch(
                    &stopped,
                    &record,
                    self.selection.as_ref().ok_or_else(conflict)?,
                )?);
            }
            if self.attempted_layout.is_none() {
                if let Some(NativeActorTerminalBranch::NativeAttempted(witness)) =
                    self.branch.as_ref()
                {
                    self.attempted_layout =
                        Some(actor.attempted_terminal_layout(&stopped, &record, witness)?);
                }
            }
            let attempted = match self.branch.as_ref() {
                Some(NativeActorTerminalBranch::NativeAttempted(witness)) => Some(witness.clone()),
                _ => None,
            };
            crate::member_carrier_control::capture_terminal_originals_for_layout(
                self.attempted_layout == Some(NativeAttemptedTerminalLayout::OtherAttempted),
                || {
                    actor.release_module_only_terminal(
                        &stopped,
                        &record,
                        attempted.as_ref().ok_or_else(conflict)?,
                    )
                },
                || {
                    if !self.locals_captured {
                        if self.attempted_layout
                            == Some(NativeAttemptedTerminalLayout::OtherAttempted)
                        {
                            actor.capture_module_only_locals(
                                &stopped,
                                &record,
                                &mut self.locals,
                            )?;
                        } else {
                            actor.capture_locals(
                                &stopped,
                                &record,
                                &mut self.locals,
                                |_| Ok(()),
                            )?;
                        }
                        self.locals_captured = true;
                    }
                    if !self.canonical_captured {
                        actor.capture_canonical_inputs(
                            &stopped,
                            &record,
                            &mut self.canonical,
                            |_| Ok(()),
                        )?;
                        self.canonical_captured = true;
                    }
                    Ok(())
                },
            )?;
            if let Some(NativeActorTerminalBranch::ZeroEffect(outcome)) = self.branch.as_ref() {
                // Actual private Never/whole native inventory proof, NOT empty
                // actor fields or failed attempted cleanup. No synthetic C,
                // module reference, Source or FreeLibrary ACK in this lane.
                actor.dispose_zero_effect_terminal(
                    outcome,
                    &mut self.locals,
                    &mut self.canonical,
                )?;
                self.actor_released = true;
                self.branch.take();
                self.selection.take();
                self.coordinator.take();
                self.actor.take();
                self.completed_initial_noc = true;
                self.completed = true;
                return Ok(());
            }
            if !matches!(
                self.branch,
                Some(NativeActorTerminalBranch::NativeAttempted(_))
            ) {
                return Err(conflict());
            }
            match self.attempted_layout.ok_or_else(conflict)? {
                NativeAttemptedTerminalLayout::PublishedCarrierPregraph => {
                    return self.finish_pregraph(&actor, scope);
                }
                NativeAttemptedTerminalLayout::GraphAttempted => {}
                NativeAttemptedTerminalLayout::OtherAttempted => {
                    // The scheduling discriminator grants nothing. Actual
                    // Startup already verified the SAME completed own-loader
                    // release; this disposer joins canonical ownership + DATA.
                    // Constructor/failed/unknown loads never reach success here.
                    actor.dispose_module_only_terminal(
                        &stopped,
                        &record,
                        attempted.as_ref().ok_or_else(conflict)?,
                        &mut self.locals,
                        &mut self.canonical,
                    )?;
                    self.actor_released = true;
                    self.branch.take();
                    self.selection.take();
                    self.coordinator.take();
                    self.actor.take();
                    // Select original initialized-J DATA retirement, not Never.
                    self.completed_initial_noc = true;
                    self.completed = true;
                    return Ok(());
                }
            }
            let local = self.locals.as_ref().ok_or_else(conflict)?;
            if self.capture.is_none() {
                let (rows, probes) = local.local_resources().terminal_capture_originals()?;
                self.capture = Some(Box::new(NativeCanonicalTerminalCapture::new(
                    local.local_resources(),
                    rows,
                    probes,
                )));
            }
            let capture = self.capture.as_mut().ok_or_else(conflict)?;
            if !self.capture_complete {
                capture.capture(local, self.canonical.as_ref().ok_or_else(conflict)?)?;
                self.capture_complete = true;
            }
            if self.pins.is_none() {
                self.pins = Some(capture.terminal_original_pins()?);
            }
            if self.modules.is_none() {
                self.modules = Some(capture.module_originals());
            }
            let pins = self.pins.as_ref().ok_or_else(conflict)?;
            if pins.expected.scope != *scope
                || !Rc::ptr_eq(&pins.stopped, &stopped)
                || pins.expected != record
            {
                return Err(conflict());
            }
            if !self.guards_closed {
                capture.close_guards(pins)?;
                self.guards_closed = true;
            }
            if !self.keys_closed {
                capture.close_key_handles(pins)?;
                self.keys_closed = true;
            }
            if !self.adapter_released {
                capture.release_adapter_reference(pins)?;
                self.adapter_released = true;
            }
            if !self.published {
                capture.publish_actor_into(&mut self.resources, &mut self.gate)?;
                self.published = true;
            }
            if self.release.is_none() {
                // All fallible reads precede extraction of the actual T/G.
                let runtime = pins.runtime.read_pin().map_err(|_| conflict())?;
                let deadline = pins.supervisor.read_pin().map_err(|_| conflict())?;
                if self.resources.is_none() || self.gate.is_none() {
                    return Err(conflict());
                }
                let resources = self.resources.take().expect("retained actual native T");
                let gate = self.gate.take().expect("retained actual native G");
                self.release = Some(resources.into_terminal_root(
                    pins.context.clone(),
                    runtime,
                    pins.source.clone(),
                    pins.retired.clone(),
                    pins.stopped.clone(),
                    pins.expected.clone(),
                    pins.image.clone(),
                    pins.supervisor.clone(),
                    deadline,
                    gate,
                ));
            }
            let modules = self.modules.as_ref().ok_or_else(conflict)?.clone();
            let modules = modules.try_borrow().map_err(|_| conflict())?;
            if modules.retained().module_count() != 1 {
                // Multiple original loader references need individually matched
                // actual ACKs; one unload must never authorize dropping all.
                return Err(conflict());
            }
            modules
                .retained()
                .with_original_loaded_module(0, |module| {
                    actor.unload_and_release(
                        module,
                        self.release.as_ref().ok_or_else(conflict)?,
                        &mut self.ack,
                        &mut self.locals,
                        &mut self.canonical,
                    )
                })?;
            self.actor_released = true;
        }
        let modules = self.modules.as_ref().ok_or_else(conflict)?.clone();
        let mut modules = modules.try_borrow_mut().map_err(|_| conflict())?;
        terminal::release_original_modules_with_ack(
            &mut modules,
            self.release.as_ref().ok_or_else(conflict)?,
            self.ack.as_ref().ok_or_else(conflict)?,
        )?;
        self.release
            .as_ref()
            .ok_or_else(conflict)?
            .allow_original_supervisor_drop(self.ack.as_ref().ok_or_else(conflict)?)?;
        // Every remaining alias is now covered by the SAME whole native ACK,
        // G and completed resource release. Dispose them BEFORE SessionStopped;
        // retaining Runtime/Calling/key-lock aliases until a later new Start
        // would incorrectly keep the old serialized lease alive across WARM.
        self.coordinator.take();
        self.actor.take();
        self.branch.take();
        self.selection.take();
        self.capture.take();
        self.pins.take();
        self.ack.take();
        self.release.take();
        self.modules.take();
        self.completed = true;
        Ok(())
    }
}

impl<'a> CarrierPairFinalizer<NativeCarrierPairIo<'a>, NativePairJournal>
    for Rc<RefCell<NativeCarrierPairFinalizer<'a>>>
{
    fn finish(
        &mut self,
        original: &mut Option<OriginalPair<'a>>,
        scope: &SessionScope,
    ) -> io::Result<()> {
        self.try_borrow_mut()
            .map_err(|_| conflict())?
            .finish(original, scope)
    }
}

#[cfg(test)]
#[allow(dead_code)]
fn actual_native_finalizer_consumes_the_same_coordinator_and_terminal_provider(
    original: crate::member_carrier_pair::CarrierNativePair<
        crate::windows::member_carrier_pair_io::native::NativeCarrierPairIo<'static>,
        crate::windows::member_carrier_pair_io::native::NativePairJournal,
    >,
    scope: &nelomai_client_tunnel::redundancy::SessionScope,
) -> std::io::Result<()> {
    // Compile-only actual Windows type join. No fake provider or SDK receipt;
    // this is NOT a native-execution or successful terminal acceptance test.
    use nelomai_client_tunnel::redundancy::driver::NativePair;
    let mut control = crate::member_carrier_control::CarrierPairControl::new(
        original,
        NativeCarrierPairFinalizer::new(),
    );
    control.close(scope)
}
