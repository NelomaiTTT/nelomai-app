//! Serialized product-facing carrier control; native terminal completion is a
//! separate mandatory provider boundary, not the coordinator's Stopped record.
#![allow(dead_code)]
use crate::member_carrier_pair::{CarrierNativePair, CarrierPairIo, PairJournal};
use nelomai_client_tunnel::{
    redundancy::{
        control::PairControl, driver::NativePair, evidence::NativeHealthSample, protocol::Member,
        SessionScope, Slot,
    },
    DesktopTunnelOptions, TunnelMetrics,
};
use std::io;

/// The concrete native provider owns every actual terminal output BEFORE
/// fallible handoff, closes/disarms originals in authenticated native brackets,
/// and returns success only after actual module ACK and whole resource release.
/// No default implementation or permission from matching phase/JSON exists.
pub(crate) trait CarrierPairFinalizer<I: CarrierPairIo, J: PairJournal> {
    fn finish(
        &mut self,
        original: &mut Option<CarrierNativePair<I, J>>,
        scope: &SessionScope,
    ) -> io::Result<()>;
}
/// Caller-retained startup composition. It writes the same original Pair into
/// `destination` before fallible Fresh publication. Partial startup owners stay
/// in this provider; an error is never an owning Result or ordinary fallback.
pub(crate) trait CarrierPairPreparation<I: CarrierPairIo, J: PairJournal> {
    fn prepare_retained_into(
        &mut self,
        destination: &mut Option<CarrierNativePair<I, J>>,
    ) -> io::Result<()>;
    /// Select cleanup through the SAME retained cold owner when no Pair was
    /// constructed. Success acknowledges storage selection only; it cannot
    /// replace the native finalizer's whole disposition or DATA retirement.
    fn begin_cleanup_before_pair(&mut self, _scope: &SessionScope) -> io::Result<()> {
        Err(conflict())
    }
    /// Separate whole native/owning completion, never storage handoff alone.
    /// The provider must retain its SAME typed disposition outcome for the
    /// session store's subsequent initial-DATA retirement.
    fn finish_cleanup_before_pair(&mut self, _scope: &SessionScope) -> io::Result<()> {
        Err(conflict())
    }
}
pub(crate) struct CarrierPairControl<I: CarrierPairIo, J: PairJournal, F> {
    pair: Option<CarrierNativePair<I, J>>,
    preparation: Option<Box<dyn CarrierPairPreparation<I, J>>>,
    preparation_attempted: bool,
    preparation_completed: bool,
    scope: SessionScope,
    finalizer: F,
    closing: bool,
    completed: bool,
}
fn conflict() -> io::Error {
    io::Error::other("carrier_terminal_completion_pending")
}

#[cfg(test)]
#[test]
fn completed_original_module_release_precedes_canonical_cut() {
    use std::cell::Cell;
    for lost_ack in [false, true] {
        let events = std::cell::RefCell::new(Vec::new());
        let retained = Cell::new(true);
        let result = capture_terminal_originals_for_layout(
            true,
            || {
                assert!(retained.get());
                events.borrow_mut().push("original-release-whole");
                if lost_ack {
                    Err(conflict())
                } else {
                    Ok(())
                }
            },
            || {
                events.borrow_mut().push("canonical-cut");
                retained.set(false);
                Ok(())
            },
        );
        assert_eq!(result.is_ok(), !lost_ack);
        assert_eq!(retained.get(), lost_ack);
        assert_eq!(
            *events.borrow(),
            if lost_ack {
                vec!["original-release-whole"]
            } else {
                vec!["original-release-whole", "canonical-cut"]
            }
        );
    }
}
/// Dispatch only: this conveys no native release or absence authority.
/// A selected pregraph lane stays selected after the actor's release; its
/// retained module container and release slot still require their own checks.
pub(crate) fn continue_pregraph_terminal(selected_pregraph: bool, _actor_released: bool) -> bool {
    selected_pregraph
}

/// Terminal scheduling only, not resource/disposal authority. An unconstructed
/// attempted layout needs the actual original release AND whole postflight
/// BEFORE any cut. The concrete native callback verifies its typed ACK; a
/// successful factual read cannot satisfy that callback's contract.
pub(crate) fn capture_terminal_originals_for_layout(
    pending_layout: bool,
    release_original_and_verify_whole: impl FnOnce() -> io::Result<()>,
    capture: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    if pending_layout {
        release_original_and_verify_whole()?;
    }
    capture()
}

#[cfg(test)]
#[test]
fn unacknowledged_terminal_release_keeps_startup_intact() {
    use std::cell::Cell;
    let drained = Cell::new(false);
    let observed = Cell::new(false);
    assert!(capture_terminal_originals_for_layout(
        true,
        || {
            assert!(
                !drained.get(),
                "original Startup must precede any raw handoff"
            );
            observed.set(true);
            Err(conflict()) // factual observation is not the actual release ACK
        },
        || {
            drained.set(true);
            Ok(())
        }
    )
    .is_err());
    assert!(observed.get());
    assert!(!drained.get());
}

#[cfg(test)]
#[test]
fn pending_terminal_errors_never_drain_or_fall_back_to_full_capture() {
    use std::cell::Cell;
    for unwind in [false, true] {
        let captures = Cell::new(0);
        let observations = Cell::new(0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            capture_terminal_originals_for_layout(
                true,
                || {
                    observations.set(observations.get() + 1);
                    if unwind {
                        panic!("bounded_read_unknown");
                    }
                    Err(conflict())
                },
                || {
                    captures.set(captures.get() + 1);
                    Ok(())
                },
            )
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert_eq!(observations.get(), 1);
        assert_eq!(captures.get(), 0);
    }
}

#[cfg(test)]
#[test]
fn acknowledged_terminal_layout_capture_failure_never_selects_pending_reader() {
    use std::cell::Cell;
    for fail in [false, true] {
        let captures = Cell::new(0);
        let result = capture_terminal_originals_for_layout(
            false,
            || panic!("known layout may not select another authority"),
            || {
                captures.set(captures.get() + 1);
                if fail {
                    Err(conflict())
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(result.is_ok(), !fail);
        assert_eq!(captures.get(), 1);
    }
}

#[cfg(test)]
#[test]
fn pregraph_continuation_survives_actor_release_without_selecting_other_lanes() {
    assert!(continue_pregraph_terminal(true, false));
    assert!(continue_pregraph_terminal(true, true));
    assert!(!continue_pregraph_terminal(false, false));
    assert!(!continue_pregraph_terminal(false, true));
}

impl<I: CarrierPairIo, J: PairJournal, F: CarrierPairFinalizer<I, J>> CarrierPairControl<I, J, F> {
    pub(crate) fn new(pair: CarrierNativePair<I, J>, finalizer: F) -> Self {
        let scope = pair.snapshot().scope.clone();
        Self {
            pair: Some(pair),
            preparation: None,
            preparation_attempted: true,
            preparation_completed: true,
            scope,
            finalizer,
            closing: false,
            completed: false,
        }
    }
    pub(crate) fn from_preparation(
        scope: SessionScope,
        preparation: Box<dyn CarrierPairPreparation<I, J>>,
        finalizer: F,
    ) -> Self {
        Self {
            pair: None,
            preparation: Some(preparation),
            preparation_attempted: false,
            preparation_completed: false,
            scope,
            finalizer,
            closing: false,
            completed: false,
        }
    }
    fn live(&self) -> io::Result<&CarrierNativePair<I, J>> {
        if self.closing || self.completed || !self.preparation_completed {
            return Err(conflict());
        }
        self.pair.as_ref().ok_or_else(conflict)
    }
    fn live_mut(&mut self) -> io::Result<&mut CarrierNativePair<I, J>> {
        if self.closing || self.completed || !self.preparation_completed {
            return Err(conflict());
        }
        self.pair.as_mut().ok_or_else(conflict)
    }
    fn initialize(&mut self) -> io::Result<()> {
        if self.preparation_completed {
            return Ok(());
        }
        if self.preparation_attempted {
            return Err(conflict());
        }
        self.preparation_attempted = true; // before native/CAS/unwind; never replay Startup
        self.preparation
            .as_mut()
            .ok_or_else(conflict)?
            .prepare_retained_into(&mut self.pair)?;
        let pair = self.pair.as_ref().ok_or_else(conflict)?;
        if pair.snapshot().scope != self.scope {
            return Err(conflict());
        }
        self.preparation_completed = true;
        Ok(())
    }
}
impl<I: CarrierPairIo, J: PairJournal, F: CarrierPairFinalizer<I, J>> NativePair
    for CarrierPairControl<I, J, F>
{
    type Socket = I::Socket;
    fn check_integrity(&mut self) -> io::Result<()> {
        self.live_mut()?.check_integrity()
    }
    fn sample(&mut self, slot: Slot) -> Option<NativeHealthSample> {
        self.live_mut().ok()?.sample(slot)
    }
    fn open_probe(&mut self, slot: Slot) -> io::Result<(Self::Socket, String)> {
        self.live_mut()?.open_probe(slot)
    }
    fn select_active(&mut self, scope: &SessionScope, slot: Slot) -> io::Result<()> {
        self.live_mut()?.select_active(scope, slot)
    }
    fn close(&mut self, scope: &SessionScope) -> io::Result<()> {
        if *scope != self.scope {
            return Err(conflict());
        }
        if self.completed {
            return Ok(());
        }
        // Latch BEFORE any native or provider boundary, including an unwind.
        // Retry is scoped cleanup only; no method can reopen forward activity.
        self.closing = true;
        if !self.preparation_attempted {
            // Direct native users without SessionControl still need their
            // cold owner. Product prepares it before Starting publication.
            let _ = self.initialize();
        }
        if self.pair.is_none() && !self.preparation_completed {
            self.preparation
                .as_mut()
                .ok_or_else(conflict)?
                .begin_cleanup_before_pair(scope)?;
            // Storage selection is not disposition. Only the SAME provider's
            // separately authenticated pre-Pair whole disposal may complete;
            // the session store still requires its original DATA retirement.
            self.preparation
                .as_mut()
                .ok_or_else(conflict)?
                .finish_cleanup_before_pair(scope)?;
            self.completed = true;
            return Ok(());
        }
        if let Some(original) = self.pair.as_mut() {
            original.close(scope)?;
        }
        self.finalizer.finish(&mut self.pair, scope)?;
        if self.pair.is_some() {
            return Err(conflict());
        }
        // Only the concrete finisher's whole terminal release may reach here.
        // This local state never constructs an SDK/module/ownership receipt.
        self.completed = true;
        Ok(())
    }
}
impl<I: CarrierPairIo, J: PairJournal, F: CarrierPairFinalizer<I, J>> PairControl
    for CarrierPairControl<I, J, F>
{
    fn prepare_session(&mut self, scope: &SessionScope) -> io::Result<()> {
        if *scope != self.scope || self.closing || self.completed {
            return Err(conflict());
        }
        self.initialize()
    }
    fn complete_start(&mut self, scope: &SessionScope) -> io::Result<()> {
        self.live_mut()?.complete_start(scope)
    }
    fn complete_rebind(&mut self, scope: &SessionScope) -> io::Result<()> {
        self.live_mut()?.complete_rebind(scope)
    }
    fn metrics(&self, slot: Slot) -> io::Result<TunnelMetrics> {
        self.live()?.metrics(slot)
    }
    fn physical_network_fingerprint(&self) -> io::Result<String> {
        self.live()?.physical_network_fingerprint()
    }
    fn start_primary(
        &mut self,
        scope: &SessionScope,
        member: &Member,
        options: &DesktopTunnelOptions,
    ) -> io::Result<()> {
        if *scope != self.scope || self.closing || self.completed {
            return Err(conflict());
        }
        self.initialize()?;
        self.live_mut()?.start_primary(scope, member, options)
    }
    fn attach(&mut self, scope: &SessionScope, member: &Member) -> io::Result<()> {
        self.live_mut()?.attach(scope, member)
    }
    fn remove_standby(&mut self, scope: &SessionScope, slot: Slot) -> io::Result<()> {
        self.live_mut()?.remove_standby(scope, slot)
    }
    fn rebind_pair(&mut self, scope: &SessionScope) -> io::Result<bool> {
        self.live_mut()?.rebind_pair(scope)
    }
    fn cleanup_pending(&self) -> bool {
        if self.completed {
            false
        } else if self.closing {
            true
        } else {
            self.pair.as_ref().is_none_or(PairControl::cleanup_pending)
        }
    }
}

#[cfg(test)]
mod pre_pair_tests {
    use super::*;
    use crate::member_carrier_pair::tests::{
        ConstructionDisk, ConstructionFault, Io, StartupTransferFixture,
    };
    use std::{
        cell::{Cell, RefCell},
        panic::{catch_unwind, AssertUnwindSafe},
        rc::Rc,
    };

    #[derive(Clone, Copy, Debug)]
    enum Failure {
        Error,
        Unwind,
    }
    struct Preparation {
        original: Rc<RefCell<StartupTransferFixture>>,
        prepare_failure: Failure,
        cleanup_failure: Option<Failure>,
        preparations: Rc<Cell<usize>>,
        cleanups: Rc<Cell<usize>>,
    }
    impl CarrierPairPreparation<Io, ConstructionDisk> for Preparation {
        fn prepare_retained_into(
            &mut self,
            destination: &mut Option<CarrierNativePair<Io, ConstructionDisk>>,
        ) -> io::Result<()> {
            assert!(destination.is_none());
            // The existing fixture retains the actual cold original; none of
            // these OS-boundary failures may publish a replacement Pair.
            self.original.borrow().assert_untouched();
            self.preparations.set(self.preparations.get() + 1);
            match self.prepare_failure {
                Failure::Error => Err(conflict()),
                Failure::Unwind => panic!("cold publication interrupted"),
            }
        }
        fn begin_cleanup_before_pair(&mut self, scope: &SessionScope) -> io::Result<()> {
            let original = self.original.borrow();
            original.assert_untouched();
            assert_eq!(&original.startup.as_ref().unwrap().scope, scope);
            self.cleanups.set(self.cleanups.get() + 1);
            match self.cleanup_failure {
                Some(Failure::Error) => Err(conflict()),
                Some(Failure::Unwind) => panic!("cleanup selection interrupted"),
                None => Ok(()), // storage selection alone is not native disposal
            }
        }
    }
    struct NoPairFinalizer;
    impl CarrierPairFinalizer<Io, ConstructionDisk> for NoPairFinalizer {
        fn finish(
            &mut self,
            _: &mut Option<CarrierNativePair<Io, ConstructionDisk>>,
            _: &SessionScope,
        ) -> io::Result<()> {
            panic!("Pair finalization cannot adopt a before-Pair owner")
        }
    }

    struct TerminalPreparation {
        cold: Preparation,
        dispositions: Rc<Cell<usize>>,
        acknowledged: bool,
    }
    impl CarrierPairPreparation<Io, ConstructionDisk> for TerminalPreparation {
        fn prepare_retained_into(
            &mut self,
            destination: &mut Option<CarrierNativePair<Io, ConstructionDisk>>,
        ) -> io::Result<()> {
            self.cold.prepare_retained_into(destination)
        }
        fn begin_cleanup_before_pair(&mut self, scope: &SessionScope) -> io::Result<()> {
            self.cold.begin_cleanup_before_pair(scope)
        }
        fn finish_cleanup_before_pair(&mut self, scope: &SessionScope) -> io::Result<()> {
            self.cold.original.borrow().assert_untouched();
            assert_eq!(
                &self.cold.original.borrow().startup.as_ref().unwrap().scope,
                scope
            );
            self.dispositions.set(self.dispositions.get() + 1);
            if self.acknowledged {
                Ok(())
            } else {
                Err(conflict())
            }
        }
    }
    #[test]
    fn pre_pair_stop_requires_separate_actual_disposition_then_is_idempotent() {
        for acknowledged in [false, true] {
            let original = Rc::new(RefCell::new(StartupTransferFixture::new(
                ConstructionFault::None,
            )));
            let scope = original.borrow().startup.as_ref().unwrap().scope.clone();
            let preparations = Rc::new(Cell::new(0));
            let cleanups = Rc::new(Cell::new(0));
            let dispositions = Rc::new(Cell::new(0));
            let mut control = CarrierPairControl::from_preparation(
                scope.clone(),
                Box::new(TerminalPreparation {
                    cold: Preparation {
                        original,
                        prepare_failure: Failure::Error,
                        cleanup_failure: None,
                        preparations: preparations.clone(),
                        cleanups: cleanups.clone(),
                    },
                    dispositions: dispositions.clone(),
                    acknowledged,
                }),
                NoPairFinalizer,
            );
            assert!(control.prepare_session(&scope).is_err());
            assert_eq!(control.close(&scope).is_ok(), acknowledged);
            assert_eq!(
                dispositions.get(),
                1,
                "original disposition consumer skipped"
            );
            assert_eq!(control.cleanup_pending(), !acknowledged);
            assert!(control.prepare_session(&scope).is_err());
            if acknowledged {
                control.close(&scope).unwrap();
                assert_eq!(
                    dispositions.get(),
                    1,
                    "acknowledged native disposal must not repeat"
                );
                assert_eq!(cleanups.get(), 1);
            }
            assert_eq!(preparations.get(), 1);
        }
    }

    // Break: skip the retained provider after Err/unwind, replay preparation,
    // use a foreign scope, or turn cleanup selection into terminal success.
    #[test]
    fn failed_pre_pair_preparation_reaches_same_cleanup_owner_without_terminal_permission() {
        for preparation_failure in [Failure::Error, Failure::Unwind] {
            for cleanup_failure in [None, Some(Failure::Error), Some(Failure::Unwind)] {
                let original = Rc::new(RefCell::new(StartupTransferFixture::new(
                    ConstructionFault::None,
                )));
                let scope = original.borrow().startup.as_ref().unwrap().scope.clone();
                let preparations = Rc::new(Cell::new(0));
                let cleanups = Rc::new(Cell::new(0));
                let mut control = CarrierPairControl::from_preparation(
                    scope.clone(),
                    Box::new(Preparation {
                        original: original.clone(),
                        prepare_failure: preparation_failure,
                        cleanup_failure,
                        preparations: preparations.clone(),
                        cleanups: cleanups.clone(),
                    }),
                    NoPairFinalizer,
                );
                let result = catch_unwind(AssertUnwindSafe(|| control.prepare_session(&scope)));
                assert!(!matches!(result, Ok(Ok(()))));
                let mut foreign = scope.clone();
                foreign.connection_generation += 1;
                assert!(control.close(&foreign).is_err());
                assert_eq!(cleanups.get(), 0);
                let result = catch_unwind(AssertUnwindSafe(|| control.close(&scope)));
                assert!(!matches!(result, Ok(Ok(()))));
                assert_eq!(cleanups.get(), 1, "retained cleanup provider was skipped");
                assert!(control.cleanup_pending());
                assert!(control.prepare_session(&scope).is_err());
                assert!(control.check_integrity().is_err());
                assert_eq!(preparations.get(), 1);
                original.borrow().assert_untouched();
            }
        }
    }

    #[test]
    fn session_control_keeps_pre_pair_original_on_failed_prepare_and_scoped_stop() {
        use nelomai_client_tunnel::{
            redundancy::{
                control::SessionControl,
                driver::SessionStore,
                protocol::Command,
                session::{SessionPhase, SessionSnapshot},
            },
            TunnelConfiguration,
        };
        struct Store {
            scope: SessionScope,
            records: Rc<RefCell<Vec<SessionSnapshot>>>,
            completion: crate::member_pair::InitialDataCompletionState,
            dispositions: Rc<Cell<usize>>,
            acknowledged: bool,
            terminal_events: Rc<RefCell<Vec<&'static str>>>,
        }
        impl SessionStore for Store {
            fn save(&mut self, snapshot: &SessionSnapshot) -> io::Result<()> {
                // Actual product completion scheduler. Only the OS/native
                // outcome and private-file effects are external doubles here.
                self.completion.save(
                    &self.scope,
                    snapshot,
                    |s| {
                        self.records.borrow_mut().push(s.clone());
                        Ok(())
                    },
                    || {
                        assert!(self.acknowledged && self.dispositions.get() == 1);
                        self.terminal_events.borrow_mut().push("retire-original");
                        Ok(())
                    },
                    |_| {
                        self.terminal_events.borrow_mut().push("complete-files");
                        Ok(())
                    },
                    || {
                        self.terminal_events.borrow_mut().push("release-original");
                        Ok(())
                    },
                )
            }
        }
        for (failure, acknowledged) in [
            (Failure::Error, false),
            (Failure::Unwind, false),
            (Failure::Error, true),
            (Failure::Unwind, true),
        ] {
            let original = Rc::new(RefCell::new(StartupTransferFixture::new(
                ConstructionFault::None,
            )));
            let scope = original.borrow().startup.as_ref().unwrap().scope.clone();
            let preparations = Rc::new(Cell::new(0));
            let cleanups = Rc::new(Cell::new(0));
            let dispositions = Rc::new(Cell::new(0));
            let records = Rc::new(RefCell::new(Vec::new()));
            let terminal_events = Rc::new(RefCell::new(Vec::new()));
            let command = Command::Start {
                scope: scope.clone(),
                primary: Member {
                    slot: Slot::A,
                    lease_id: "22222222-2222-4222-8222-222222222222".into(),
                    configuration: TunnelConfiguration::new("software fixture".into()),
                    probe: nelomai_contracts::RedundantHealthProbe {
                        kind: nelomai_contracts::HealthProbeKind::DnsA,
                        target_ipv4: "192.0.2.11".parse().unwrap(),
                        query_name: "example.com".into(),
                        timeout_ms: 2000,
                    },
                },
                role_generation: 1,
                membership_generation: 1,
                warm_stop_v1: true,
                options: DesktopTunnelOptions::default(),
            };
            let mut native = Some(CarrierPairControl::from_preparation(
                scope.clone(),
                Box::new(TerminalPreparation {
                    cold: Preparation {
                        original: original.clone(),
                        prepare_failure: failure,
                        cleanup_failure: None,
                        preparations: preparations.clone(),
                        cleanups: cleanups.clone(),
                    },
                    dispositions: dispositions.clone(),
                    acknowledged,
                }),
                NoPairFinalizer,
            ));
            let mut store = Some(Store {
                scope: scope.clone(),
                records: records.clone(),
                completion: Default::default(),
                dispositions: dispositions.clone(),
                acknowledged,
                terminal_events: terminal_events.clone(),
            });
            let mut retained = None;
            let prepared = catch_unwind(AssertUnwindSafe(|| {
                SessionControl::prepare_retained_into(
                    &mut retained,
                    scope.runtime,
                    &command,
                    &mut native,
                    &mut store,
                    0,
                )
            }));
            assert!(!matches!(prepared, Ok(Ok(()))));
            assert!(native.is_none() && store.is_none());
            assert!(
                records.borrow().is_empty(),
                "preparation precedes Session publication"
            );
            let session = retained.as_mut().expect("same SessionControl owns cleanup");
            let mut foreign = scope.clone();
            foreign.connection_generation += 1;
            assert!(session
                .execute(Command::Stop { scope: foreign }, 1)
                .is_err());
            assert_eq!(cleanups.get(), 0);
            assert_eq!(
                session
                    .execute(
                        Command::Stop {
                            scope: scope.clone()
                        },
                        2
                    )
                    .is_ok(),
                acknowledged
            );
            assert_eq!(cleanups.get(), 1);
            assert_eq!(dispositions.get(), 1);
            assert_eq!(
                session.snapshot().session.phase,
                if acknowledged {
                    SessionPhase::Stopped
                } else {
                    SessionPhase::Stopping
                }
            );
            assert_eq!(session.snapshot().cleanup_pending, !acknowledged);
            assert!(
                !records.borrow().is_empty(),
                "actual Stopping save precedes cleanup"
            );
            let phases: Vec<_> = records.borrow().iter().map(|s| s.phase).collect();
            assert_eq!(
                phases,
                if acknowledged {
                    vec![SessionPhase::Stopping, SessionPhase::Stopped]
                } else {
                    vec![SessionPhase::Stopping, SessionPhase::Stopping]
                }
            );
            assert!(session.execute(command, 3).is_err());
            assert_eq!(
                session.execute(Command::Stop { scope }, 4).is_ok(),
                acknowledged
            );
            assert_eq!(preparations.get(), 1);
            assert_eq!(cleanups.get(), if acknowledged { 1 } else { 2 });
            assert_eq!(dispositions.get(), if acknowledged { 1 } else { 2 });
            if acknowledged {
                assert_eq!(
                    records.borrow().len(),
                    2,
                    "repeat Stop must not replay retirement"
                );
            }
            assert_eq!(
                *terminal_events.borrow(),
                if acknowledged {
                    vec!["retire-original", "complete-files", "release-original"]
                } else {
                    vec![]
                }
            );
            original.borrow().assert_untouched();
        }
    }
}
