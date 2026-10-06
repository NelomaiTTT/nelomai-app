//! Full resource join for the actual split-engine native guard transaction.
//! Comparison helpers grant no native permission; factory remains off.
#![allow(dead_code)]
use crate::{
    member_carrier_guard as policy,
    member_guard::{GuardError, Result},
};

// Adding deny-only bases can precede the new member's route plan. Removing an
// existing base is different: its exact stopped original must be proven first.
fn compare_additive_base(expected: &policy::Model, desired: &policy::Model) -> Result<()> {
    expected.validate()?;
    desired.validate()?;
    if expected.scope != desired.scope
        || expected.permits
        || desired.permits
        || !desired.installed
        || (expected.installed && expected.carrier != desired.carrier)
        || expected
            .members
            .iter()
            .zip(&desired.members)
            .any(|(old, new)| {
                old.as_ref()
                    .is_some_and(|old| new.as_ref().is_none_or(|new| new.identity != old.identity))
            })
    {
        return Err(GuardError::Conflict);
    }
    Ok(())
}

/// Comparison only; native G must additionally authenticate the exact current
/// Retire operation and SAME original closed target/row/probe/network receipts.
fn compare_retirement_base(
    expected: &policy::Model,
    desired: &policy::Model,
    retired: nelomai_client_tunnel::redundancy::Slot,
    closed: &policy::Identity,
) -> Result<()> {
    use nelomai_client_tunnel::redundancy::Slot;
    expected.validate()?;
    desired.validate()?;
    let index = if retired == Slot::A { 0 } else { 1 };
    if expected.scope != desired.scope
        || expected.permits
        || desired.permits
        || !expected.installed
        || !desired.installed
        || expected.active.is_some()
        || desired.active.is_some()
        || expected.carrier != desired.carrier
        || expected.carrier.is_none()
        || expected.assigned_sublayer_weight.is_none()
        || expected.assigned_sublayer_weight != desired.assigned_sublayer_weight
        || expected.members[index]
            .as_ref()
            .is_none_or(|m| m.identity != *closed)
        || desired.members[index].is_some()
        || expected.members[1 - index].is_none()
        || expected.members[1 - index] != desired.members[1 - index]
    {
        return Err(GuardError::Conflict);
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::windows::{
        member_carrier_guard::{Bindings, WindowBindingAttestor},
        member_carrier_guard_attestor::{native::NativeGuardGate, ExchangeEdge},
        member_carrier_key_authority::RuntimeRead,
        member_carrier_network::native::NativeNetworkRead,
        member_carrier_network_gate::native::NativeNetworkGate,
        member_carrier_original_read::OriginalRead,
        member_carrier_pair_store::native_store::NativePairIntentRead,
        member_carrier_probe_gate::native::NativeProbeResourceState,
        member_carrier_runtime::native::{
            NativeBindingsWindow, NativeClosingRead, NativeResourceRowsRead, NativeSourceRead,
            RetiredCarrierRead,
        },
        member_native_deadline::{NativeDeadline, NativeDeadlineReadPin},
    };
    use crate::{member_carrier_native_ownership::Context, member_carrier_pair as pair};
    use policy::SessionKind;
    use std::{
        cell::{Cell, RefCell},
        io,
        rc::Rc,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };

    fn denied<E>(_: E) -> GuardError {
        GuardError::Conflict
    }
    fn io_denied<E>(_: E) -> io::Error {
        io::Error::other("carrier_guard_resource_conflict")
    }
    fn native_denied<E>(_: E) -> crate::windows::member_carrier_wintun::Error {
        crate::windows::member_carrier_wintun::Error::Conflict
    }
    // These registrations are deliberately non-owning. Each real owner can
    // retain this G through its authority; actor roots MUST retain owners first.
    struct Original<T> {
        attempted: Cell<bool>,
        pin: RefCell<Option<OriginalRead<T>>>,
    }
    impl<T> Original<T> {
        fn new() -> Self {
            Self {
                attempted: Cell::new(false),
                pin: RefCell::new(None),
            }
        }
        fn retain(&self, original: &Rc<T>, revoked: &Cell<bool>, cleanup: bool) -> Result<()> {
            if self.attempted.replace(true) {
                revoked.set(true);
                return Err(GuardError::Conflict);
            }
            *self.pin.try_borrow_mut().map_err(|_| {
                revoked.set(true);
                GuardError::Conflict
            })? = Some(OriginalRead::from_retained(original));
            if revoked.get() && !cleanup {
                return Err(GuardError::Conflict);
            }
            Ok(())
        }
        fn read(&self) -> Result<Rc<T>> {
            self.pin
                .try_borrow()
                .map_err(denied)?
                .as_ref()
                .and_then(OriginalRead::upgrade)
                .ok_or(GuardError::Conflict)
        }
    }
    struct Selected {
        pin: Rc<NativePairIntentRead>,
        record: pair::Record,
    }
    struct Shared<A: WindowBindingAttestor> {
        context: Context,
        runtime: RuntimeRead,
        source: OriginalRead<NativeSourceRead>,
        supervisor: Rc<NativeDeadline>,
        deadline: NativeDeadlineReadPin,
        cancelled: Arc<AtomicBool>,
        selected: RefCell<Option<Selected>>,
        revoked: Cell<bool>,
        rows: Original<NativeResourceRowsRead>,
        network_read: Original<NativeNetworkRead>,
        network: Original<NativeNetworkGate<A>>,
        probes: Original<NativeProbeResourceState<A>>,
        closing: Original<NativeClosingRead>,
        retired: Original<RetiredCarrierRead>,
    }
    pub(crate) struct NativeResourceGuardGate<A: WindowBindingAttestor> {
        shared: Rc<Shared<A>>,
    }
    /// Actor-only registration/selection handle. None of these methods mint an
    /// SDK ACK or grant permits; actual G joins every owner again at each edge.
    pub(crate) struct NativeGuardResourceSelection<A: WindowBindingAttestor> {
        shared: Rc<Shared<A>>,
    }
    impl<A: WindowBindingAttestor> NativeResourceGuardGate<A> {
        #[allow(clippy::too_many_arguments)]
        pub(crate) fn new(
            context: Context,
            runtime: RuntimeRead,
            source: &Rc<NativeSourceRead>,
            supervisor: Rc<NativeDeadline>,
            deadline: NativeDeadlineReadPin,
            cancelled: Arc<AtomicBool>,
        ) -> (Self, NativeGuardResourceSelection<A>) {
            let shared = Rc::new(Shared {
                context,
                runtime,
                source: OriginalRead::from_retained(source),
                supervisor,
                deadline,
                cancelled,
                selected: RefCell::new(None),
                revoked: Cell::new(false),
                rows: Original::new(),
                network_read: Original::new(),
                network: Original::new(),
                probes: Original::new(),
                closing: Original::new(),
                retired: Original::new(),
            });
            (
                Self {
                    shared: shared.clone(),
                },
                NativeGuardResourceSelection { shared },
            )
        }
    }
    impl<A: WindowBindingAttestor> NativeGuardResourceSelection<A> {
        pub(crate) fn retain_rows(&self, original: &Rc<NativeResourceRowsRead>) -> Result<()> {
            self.shared
                .rows
                .retain(original, &self.shared.revoked, false)
        }
        pub(crate) fn retain_network_read(&self, original: &Rc<NativeNetworkRead>) -> Result<()> {
            self.shared
                .network_read
                .retain(original, &self.shared.revoked, false)
        }
        pub(crate) fn retain_network(&self, original: &Rc<NativeNetworkGate<A>>) -> Result<()> {
            self.shared
                .network
                .retain(original, &self.shared.revoked, false)
        }
        pub(crate) fn retain_probes(
            &self,
            original: &Rc<NativeProbeResourceState<A>>,
        ) -> Result<()> {
            self.shared
                .probes
                .retain(original, &self.shared.revoked, false)
        }
        pub(crate) fn retain_closing(&self, original: &Rc<NativeClosingRead>) -> Result<()> {
            self.shared
                .closing
                .retain(original, &self.shared.revoked, true)
        }
        pub(crate) fn retain_retired(&self, original: &Rc<RetiredCarrierRead>) -> Result<()> {
            self.shared
                .retired
                .retain(original, &self.shared.revoked, true)
        }
        /// Select outside Guard's native transaction/Pair borrow. Current
        /// protected CAS ACK is inspected under actual Calling; old/equal-value
        /// replacement and any Closing->forward revival deny permanently.
        pub(crate) fn select(
            &self,
            pin: Rc<NativePairIntentRead>,
            record: pair::Record,
        ) -> Result<()> {
            let result = (|| {
                let mut selected = self.shared.selected.try_borrow_mut().map_err(denied)?;
                if selected.as_ref().is_some_and(|old| {
                    record.revision < old.record.revision
                        || (record.revision == old.record.revision
                            && (record != old.record || !Rc::ptr_eq(&pin, &old.pin)))
                        || (old.record.phase == pair::Phase::Closing
                            && record.phase != pair::Phase::Closing)
                }) {
                    return Err(GuardError::Conflict);
                }
                self.shared.continuity(&record, &pin)?;
                pin.inspect(&self.shared.runtime, &self.shared.supervisor, |actual| {
                    if actual != &record {
                        return Err(io_denied(()));
                    }
                    self.shared.continuity(actual, &pin).map_err(io_denied)
                })
                .map_err(denied)?;
                *selected = Some(Selected { pin, record });
                Ok(())
            })();
            if result.is_err() {
                self.shared.revoked.set(true);
            }
            result
        }
    }
    impl<A: WindowBindingAttestor> Shared<A> {
        fn retired_standby(
            &self,
            record: &pair::Record,
            expected: &policy::Model,
            desired: &policy::Model,
            window: &NativeBindingsWindow<'_>,
        ) -> Result<usize> {
            use nelomai_client_tunnel::redundancy::Slot;
            use nelomai_contracts::dispatcher::TunnelSlot;
            let pair::Operation::Retire(target) = record.operation.ok_or(GuardError::Conflict)?
            else {
                return Err(GuardError::Conflict);
            };
            let index = if target == Slot::A { 0 } else { 1 };
            let closed = window
                .closed_member(if index == 0 {
                    TunnelSlot::A
                } else {
                    TunnelSlot::B
                })
                .ok_or(GuardError::Conflict)?;
            let member = record.members[index].as_ref().ok_or(GuardError::Conflict)?;
            let identity = policy::Identity {
                scope: closed.intent.scope.clone(),
                proof: closed.proof.interface,
            };
            if record.phase != pair::Phase::Running
                || record.pending != Some(pair::Effect::Guard)
                || record.stop_stage != 0
                || record.active != Some(if index == 0 { Slot::B } else { Slot::A })
                || member.owner.intent != closed.intent
                || member.owner.proof != Some(closed.proof)
                || record.network.as_ref().is_none_or(|n| {
                    n.pending.is_some()
                        || n.current
                            .routes
                            .iter()
                            .any(|route| route.interface == closed.proof.interface.index)
                })
            {
                return Err(GuardError::Conflict);
            }
            compare_retirement_base(expected, desired, target, &identity)?;
            Ok(index)
        }
        fn continuity(&self, record: &pair::Record, pin: &NativePairIntentRead) -> Result<()> {
            record.validate().map_err(denied)?;
            let cleanup = record.phase == pair::Phase::Closing;
            if record.scope != self.context.intent.scope
                || record.provenance != self.context.provenance
                || record.addresses != self.context.intent.addresses
                || !pin.matches_runtime(&self.runtime)
                || !matches!(
                    record.phase,
                    pair::Phase::Starting | pair::Phase::Running | pair::Phase::Closing
                )
                || (!cleanup
                    && (self.revoked.get()
                        || self.cancelled.load(Ordering::Acquire)
                        || self.closing.attempted.get()
                        || self.retired.attempted.get()))
            {
                return Err(GuardError::Conflict);
            }
            self.deadline
                .verify_runtime_call(&self.supervisor, &self.runtime, &self.context)
                .map_err(denied)?;
            Ok(())
        }
        fn original_window(
            &self,
            record: &pair::Record,
            window: &NativeBindingsWindow<'_>,
        ) -> Result<()> {
            let selected = self.selected.try_borrow().map_err(denied)?;
            let selected = selected.as_ref().ok_or(GuardError::Conflict)?;
            if &selected.record != record || !window.matches_runtime(&self.runtime) {
                return Err(GuardError::Conflict);
            }
            self.continuity(record, &selected.pin)?;
            let source = self.source.upgrade().ok_or(GuardError::Conflict)?;
            if record.phase == pair::Phase::Closing {
                let closing = self.closing.read()?;
                if !closing.matches_source_origin(&source) || !window.matches_closing(&closing) {
                    return Err(GuardError::Conflict);
                }
            } else if !window.matches_source(&source) {
                return Err(GuardError::Conflict);
            }
            Ok(())
        }
    }
    // Safety: actual GuardAttestor holds the selected Pair/Calling and locked
    // WFP read through this entire readonly resource join. Every input is an
    // original native owner read, no successful G double/metadata adoption.
    unsafe impl<A: WindowBindingAttestor> NativeGuardGate for NativeResourceGuardGate<A> {
        fn verify_original_window(
            &self,
            runtime: &RuntimeRead,
            context: &Context,
            record: &pair::Record,
            window: &NativeBindingsWindow<'_>,
        ) -> Result<()> {
            if context != &self.shared.context
                || !runtime.same_original_runtime(&self.shared.runtime)
            {
                return Err(GuardError::Conflict);
            }
            self.shared.original_window(record, window)
        }
        fn authorize(
            &mut self,
            record: &pair::Record,
            kind: SessionKind,
            edge: ExchangeEdge,
            expected: &policy::Model,
            desired: &policy::Model,
            window: &NativeBindingsWindow<'_>,
        ) -> Result<()> {
            let result = (|| {
                self.shared.original_window(record, window)?;
                match edge {
                    ExchangeEdge::Withdraw
                        if kind == SessionKind::DynamicPermits && !desired.permits =>
                    {
                        // Withdrawing own permits must remain possible after a
                        // partial row/route failure. No new allow or base delete.
                    }
                    ExchangeEdge::Base if kind == SessionKind::StaticBase => {
                        let retired = if compare_additive_base(expected, desired).is_ok() {
                            None
                        } else {
                            Some(
                                self.shared
                                    .retired_standby(record, expected, desired, window)?,
                            )
                        };
                        self.shared
                            .rows
                            .read()?
                            .inspect_in_window(window, |facts| {
                                for (i, fact) in facts.rows.iter().enumerate() {
                                    let Some(fact) = fact else {
                                        continue;
                                    };
                                    let Some(actual) = fact.observed.as_ref() else {
                                        // SAME original Source window attests the closed
                                        // target; row sampler authenticates its exact
                                        // Stopped ACK without querying a historical NIC.
                                        if retired != Some(i.saturating_sub(1))
                                            || i == 0
                                            || fact.acknowledged.phase
                                                != crate::member_carrier_rows::Phase::Stopped
                                            || fact.acknowledged.pending.is_some()
                                            || fact.acknowledged.current
                                                != fact.acknowledged.baseline
                                            || fact.acknowledged.current.address.is_some()
                                        {
                                            return Err(native_denied(()));
                                        }
                                        continue;
                                    };
                                    let base = &fact.acknowledged.baseline.interface.policy;
                                    let mut weak = base.clone();
                                    weak.weak_host_send = true;
                                    weak.weak_host_receive = true;
                                    if actual.interface.policy != *base
                                        && (record.network.is_none()
                                            || actual.interface.policy != weak)
                                    {
                                        return Err(native_denied(()));
                                    }
                                }
                                Ok(())
                            })
                            .map_err(denied)?;
                        if record.network.is_some() {
                            self.shared
                                .network
                                .read()?
                                .verify_ack_for_static_base(record, window)
                                .map_err(denied)?;
                        } else {
                            self.shared
                                .network_read
                                .read()?
                                .inspect_in_window(window, |facts| {
                                    if facts.protected_record.is_some()
                                        || !facts.routes.current.is_empty()
                                        || facts.routes.pending.is_some()
                                        || facts.routes.active.is_some()
                                        || facts.routes.pending_active.is_some()
                                        || facts.routes.stopping
                                    {
                                        return Err(io_denied(()));
                                    }
                                    window
                                        .bindings()
                                        .carrier
                                        .as_ref()
                                        .ok_or_else(|| io_denied(()))?;
                                    Ok(())
                                })
                                .map_err(denied)?;
                        }
                        self.shared
                            .probes
                            .read()?
                            .verify_guard_resources(record, window, desired)?;
                    }
                    ExchangeEdge::Install
                        if kind == SessionKind::DynamicPermits && desired.permits =>
                    {
                        self.shared
                            .network
                            .read()?
                            .verify_guard_resources(record, window)
                            .map_err(denied)?;
                        self.shared
                            .probes
                            .read()?
                            .verify_guard_resources(record, window, desired)?;
                    }
                    _ => return Err(GuardError::Conflict),
                }
                self.shared.original_window(record, window)
            })();
            if result.is_err() {
                self.shared.revoked.set(true);
            }
            result
        }
        fn authorize_base_removal(
            &mut self,
            record: &pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &Bindings,
            expected: &policy::Model,
            desired: &policy::Model,
        ) -> Result<()> {
            let result = (|| {
                let selected = self.shared.selected.try_borrow().map_err(denied)?;
                let selected = selected.as_ref().ok_or(GuardError::Conflict)?;
                self.shared.continuity(record, &selected.pin)?;
                let original = self.shared.retired.read()?;
                let source = self.shared.source.upgrade().ok_or(GuardError::Conflict)?;
                if &selected.record != record
                    || !std::ptr::eq(original.as_ref(), retired)
                    || !retired.matches_source_origin(&source)
                    || bindings.scope != record.scope
                    || record.phase != pair::Phase::Closing
                    || record.stop_stage != 10
                    || record.pending != Some(pair::Effect::Guard)
                    || record.active.is_some()
                    || record.operation.is_some()
                    || expected.permits
                    || *desired != policy::Model::empty(record.scope.clone())?
                {
                    return Err(GuardError::Conflict);
                }
                self.shared
                    .rows
                    .read()?
                    .inspect_retired_in_bracket(retired, bindings, |_| Ok(()))
                    .map_err(denied)?;
                self.shared
                    .probes
                    .read()?
                    .verify_retired_guard_resources(record, retired, bindings)?;
                self.shared
                    .network
                    .read()?
                    .verify_retired_guard_resources(record, retired, bindings)
                    .map_err(denied)?;
                self.shared.continuity(record, &selected.pin)
            })();
            if result.is_err() {
                self.shared.revoked.set(true);
            }
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::member_owner::InterfaceProof;
    use nelomai_client_tunnel::redundancy::SessionScope;
    use nelomai_contracts::RuntimeSlot;

    fn base(two: bool) -> policy::Model {
        let scope = SessionScope {
            runtime: RuntimeSlot::Stable,
            runtime_generation: 1,
            session_id: "11111111-1111-4111-8111-111111111111".into(),
            connection_generation: 1,
        };
        let identity = |n| policy::Identity {
            scope: scope.clone(),
            proof: InterfaceProof {
                index: n,
                luid: n as u64 + 100,
                guid: [n as u8; 16],
            },
        };
        policy::Model::new(
            scope.clone(),
            policy::Carrier {
                identity: identity(1),
                sources: vec!["10.7.0.2".parse().unwrap()],
            },
            [
                Some(policy::Member {
                    identity: identity(2),
                    probes: vec![],
                }),
                two.then(|| policy::Member {
                    identity: identity(3),
                    probes: vec![],
                }),
            ],
            None,
        )
        .unwrap()
        .without_permits()
        .unwrap()
    }
    #[test]
    fn additive_base_accepts_initial_and_reserve_but_never_drops_an_existing_deny() {
        let one = base(false);
        let empty = policy::Model::empty(one.scope.clone()).unwrap();
        let two = base(true);
        assert!(compare_additive_base(&empty, &one).is_ok());
        assert!(compare_additive_base(&one, &two).is_ok());
        assert!(compare_additive_base(&two, &one).is_err());
        assert!(compare_additive_base(&one, &empty).is_err());
        let mut foreign = two.clone();
        foreign.members[0].as_mut().unwrap().identity.proof.guid = [19; 16];
        let foreign = policy::Model::new(
            foreign.scope.clone(),
            foreign.carrier.clone().unwrap(),
            foreign.members,
            None,
        )
        .unwrap()
        .without_permits()
        .unwrap();
        assert!(compare_additive_base(&one, &foreign).is_err());
        assert!(compare_additive_base(
            &one,
            &policy::Model::new(
                two.scope.clone(),
                two.carrier.clone().unwrap(),
                two.members,
                None
            )
            .unwrap()
        )
        .is_err());
    }
    #[test]
    fn retirement_removes_only_exact_closed_standby_base_and_keeps_original_priority() {
        use nelomai_client_tunnel::redundancy::Slot;
        let mut snapshot = base(true).expected;
        snapshot.sublayer.as_mut().unwrap().weight = 41;
        let expected = base(true)
            .readback_after(
                &policy::Model::empty(snapshot.scope.clone()).unwrap(),
                &snapshot,
            )
            .unwrap();
        let desired = base(false).inherit_sublayer_weight(&expected).unwrap();
        let closed = expected.members[1].as_ref().unwrap().identity.clone();
        compare_retirement_base(&expected, &desired, Slot::B, &closed).unwrap();
        assert!(compare_additive_base(&expected, &desired).is_err());
        for fault in 0..7 {
            let mut wrong = desired.clone();
            let mut identity = closed.clone();
            let mut target = Slot::B;
            match fault {
                0 => target = Slot::A,
                1 => identity.proof.index += 1,
                2 => identity.scope.connection_generation += 1,
                3 => wrong = policy::Model::empty(expected.scope.clone()).unwrap(),
                4 => wrong = expected.clone(),
                5 => wrong.assigned_sublayer_weight = Some(42),
                _ => wrong = base(false),
            }
            assert!(
                compare_retirement_base(&expected, &wrong, target, &identity).is_err(),
                "fault {fault}"
            );
        }
    }
}
