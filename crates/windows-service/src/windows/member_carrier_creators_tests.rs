use super::*;
use crate::member_carrier::{Intent, Provenance};
use nelomai_client_tunnel::redundancy::SessionScope;
use nelomai_contracts::{dispatcher::EngineIdentity, RuntimeSlot};

fn context() -> Context {
    Context {
        intent: Intent { scope: SessionScope { runtime: RuntimeSlot::Stable, runtime_generation: 2,
            session_id: "11111111-1111-4111-8111-111111111111".into(), connection_generation: 3 },
            addresses: vec!["10.7.0.2/32".parse().unwrap()] },
        provenance: Provenance { boot_id: [8;16], network_epoch: 7, runtime: EngineIdentity {
            slot: RuntimeSlot::Stable, runtime_version: "0.3.3".into(), container_version: "0.3.3".into(),
            runtime_contract_version: 1, manifest_sha256: "a".repeat(64) } },
        bindings: [
            Binding { role: Role::RoleCarrier, guid: [1;16], name: "carrier-c".into(), registry_path: r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{01010101-0101-0101-0101-010101010101}".into() },
            Binding { role: Role::MemberA, guid: [2;16], name: "member-a".into(), registry_path: r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{02020202-0202-0202-0202-020202020202}".into() },
            Binding { role: Role::MemberB, guid: [3;16], name: "member-b".into(), registry_path: r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{03030303-0303-0303-0303-030303030303}".into() },
        ] }
}
fn scope(i: usize) -> Scope {
    let c = context();
    Scope {
        binding: c.bindings[i].clone(),
        context: c,
        generation: (i + 10) as u64,
    }
}
#[derive(Default)]
struct Log {
    reads: Cell<usize>,
    close_checks: Cell<usize>,
    closes: Cell<usize>,
    drops: Cell<usize>,
    fail_read: Cell<bool>,
    fail_close_check: Cell<bool>,
    on_read: RefCell<Option<Box<dyn Fn()>>>,
}
struct Native {
    facts: RefCell<Observation<String>>,
    log: Rc<Log>,
    identity: Rc<()>,
}
struct Receipt {
    identity: Rc<()>,
}
impl Drop for Native {
    fn drop(&mut self) {
        self.log.drops.set(self.log.drops.get() + 1);
    }
}
// Boundary double owns a unique acknowledgement marker. No lookup/adoption
// helper exists; inspect uses the retained object's full facts and live faults.
unsafe impl OriginalNative for Native {
    type Provider = String;
    type CloseReceipt = Receipt;
    type Universe = Universe;
    fn original_identity(&self, _: &Scope) -> Result<OriginalIdentity> {
        self.log.reads.set(self.log.reads.get() + 1);
        if let Some(f) = self.log.on_read.borrow().as_ref() {
            f();
        }
        if self.log.fail_read.get() {
            return Err(Error::Native);
        }
        let f = self.facts.borrow();
        Ok(OriginalIdentity {
            scope: f.scope.clone(),
            identity: f.identity.clone(),
        })
    }
    fn verify_close_receipt(&self, _: &Scope, r: &Receipt) -> Result<()> {
        self.log.close_checks.set(self.log.close_checks.get() + 1);
        if self.log.fail_close_check.get()
            || self.log.closes.get() != 1
            || !Rc::ptr_eq(&self.identity, &r.identity)
        {
            return Err(Error::Native);
        }
        Ok(())
    }
}
struct Universe {
    calls: RefCell<Vec<usize>>,
    absent: RefCell<Vec<Option<Binding>>>,
    provider: RefCell<String>,
    extra: Cell<bool>,
    missing: Cell<bool>,
    wrong_runtime: Cell<bool>,
    fault: Cell<u8>,
    on_inspect: RefCell<Option<Box<dyn Fn()>>>,
}
impl Universe {
    fn new() -> Self {
        Self {
            calls: RefCell::new(vec![]),
            absent: RefCell::new(vec![]),
            provider: RefCell::new("actual-original-provider".into()),
            extra: Cell::new(false),
            missing: Cell::new(false),
            wrong_runtime: Cell::new(false),
            fault: Cell::new(0),
            on_inspect: RefCell::new(None),
        }
    }
}
unsafe impl NativeUniverse<Native> for Universe {
    fn inspect_universe(
        &self,
        c: &Context,
        ids: &[OriginalIdentity],
        absent: Option<&Binding>,
    ) -> Result<UniverseObservation<String>> {
        self.calls.borrow_mut().push(ids.len());
        self.absent.borrow_mut().push(absent.cloned());
        if absent.is_some_and(|binding| {
            !c.bindings.contains(binding)
                || ids.iter().any(|id| {
                    id.identity.guid == binding.guid
                        || id.identity.name.eq_ignore_ascii_case(&binding.name)
                })
        }) {
            return Err(Error::Conflict);
        }
        if let Some(f) = self.on_inspect.borrow().as_ref() {
            f();
        }
        if self.fault.get() == 1 {
            return Err(Error::Native);
        }
        let mut originals = ids
            .iter()
            .map(|id| Observation {
                scope: id.scope.clone(),
                identity: id.identity.clone(),
                provider: self.provider.borrow().clone(),
            })
            .collect::<Vec<_>>();
        if self.extra.get() {
            originals.push(Observation {
                scope: scope(2),
                identity: native(&scope(2)).0.facts.borrow().identity.clone(),
                provider: "foreign".into(),
            });
        }
        if self.missing.get() {
            originals.pop();
        }
        let mut context = c.clone();
        if self.wrong_runtime.get() {
            context.provenance.network_epoch += 1;
        }
        match self.fault.get() {
            2 => originals[0].scope.generation += 1,
            3 => originals[0].identity.description.push('x'),
            4 => originals[1] = originals[0].clone(),
            5 => originals.reverse(),
            _ => (),
        }
        Ok(UniverseObservation { context, originals })
    }
}
impl Native {
    fn native_close(&self) -> Receipt {
        assert_eq!(
            self.log.closes.get(),
            0,
            "original close is consumed only once"
        );
        self.log.closes.set(1);
        Receipt {
            identity: self.identity.clone(),
        }
    }
}
fn native(s: &Scope) -> (Native, Rc<Log>) {
    let log = Rc::new(Log::default());
    (
        Native {
            facts: RefCell::new(Observation {
                scope: s.clone(),
                identity: Identity {
                    guid: s.binding.guid,
                    luid: (53 << 48) | ((s.generation + 1) << 24),
                    index: s.generation as u32 + 1,
                    name: s.binding.name.clone(),
                    description: "Nelomai Tunnel".into(),
                    if_type: 53,
                    tunnel_type: 0,
                },
                provider: "actual-original-provider".into(),
            }),
            log: log.clone(),
            identity: Rc::new(()),
        },
        log,
    )
}
struct Absent {
    calls: usize,
    fail: bool,
    found: bool,
    wrong: bool,
}
unsafe impl NativeAbsence for Absent {
    fn inspect_absence(&mut self, s: &Scope) -> Result<AbsenceFacts> {
        self.calls += 1;
        if self.fail {
            return Err(Error::Native);
        }
        let mut observed = s.clone();
        if self.wrong {
            observed.generation += 1;
        }
        Ok(AbsenceFacts {
            scope: observed,
            matches: if self.found {
                vec![native(s).0.facts.borrow().identity.clone()]
            } else {
                vec![]
            },
        })
    }
}
fn absent() -> Absent {
    Absent {
        calls: 0,
        fail: false,
        found: false,
        wrong: false,
    }
}
fn registry() -> (Producer<Native>, Observer<Native>) {
    Producer::intent(context(), Universe::new()).unwrap()
}
fn live(i: usize) -> (Producer<Native>, Observer<Native>, Rc<Log>) {
    let (mut p, o) = registry();
    let s = scope(i);
    p.confirm_empty(s.clone(), &mut absent()).unwrap();
    let begin = p.begin(s.clone()).unwrap();
    let (n, l) = native(&s);
    let ack = unsafe { begin.acknowledge_original(n) }.unwrap();
    p.publish(ack).unwrap();
    (p, o, l)
}

#[test]
fn carrier_identity_callback_retains_actual_original_without_recursive_universe() {
    let (producer, observer, log) = live(0);
    let calls = producer.original_universe().calls.borrow().len();
    producer
        .original_universe()
        .on_inspect
        .replace(Some(Box::new(|| {
            panic!("identity callback must not recurse integrated member inventory");
        })));
    let reads = log.reads.get();
    observer
        .inspect_live_carrier_identity(&scope(0), |actual| {
            assert_eq!(actual.scope, scope(0));
            assert_eq!(actual.identity.guid, scope(0).binding.guid);
            assert_eq!(log.reads.get(), reads + 1);
            Ok(())
        })
        .unwrap();
    assert_eq!(log.reads.get(), reads + 2);
    assert_eq!(producer.original_universe().calls.borrow().len(), calls);
    assert_eq!(log.closes.get(), 0);
    assert_eq!(log.drops.get(), 0);
}

#[test]
fn carrier_identity_callback_denies_nonoriginal_drift_reentry_error_and_unwind() {
    for fault in 0..6 {
        let (_producer, observer, log) = live(0);
        let entered = Cell::new(false);
        let mut expected = scope(0);
        if fault == 0 {
            expected.generation += 1;
        }
        if fault == 1 {
            log.fail_read.set(true);
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            observer.inspect_live_carrier_identity(&expected, |_| {
                entered.set(true);
                match fault {
                    2 => {
                        log.fail_read.set(true);
                        Ok(())
                    }
                    3 => Err(Error::Native),
                    4 => panic!("original identity callback unwind"),
                    5 => {
                        assert!(observer.observe(&scope(0)).is_err());
                        Ok(())
                    }
                    _ => Ok(()),
                }
            })
        }));
        if fault == 4 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert_eq!(entered.get(), fault >= 2);
        assert!(observer
            .inspect_live_carrier_identity(&scope(0), |_| Ok(()))
            .is_err());
        assert_eq!(log.closes.get(), 0);
    }
    let (_producer, observer) = registry();
    assert!(observer
        .inspect_live_carrier_identity(&scope(0), |_| -> Result<()> { panic!("uncreated") })
        .is_err());
    let (_producer, observer, _) = live(1);
    assert!(observer
        .inspect_live_carrier_identity(&scope(1), |_| -> Result<()> { panic!("member") })
        .is_err());
}

#[test]
fn carrier_identity_callback_rejects_actual_handle_drift_before_and_after_consumer() {
    for after_callback in [false, true] {
        for fault in 0..7 {
            let (producer, observer, log) = live(0);
            // SAME original boundary object; never constructing an ACK from the
            // replacement values. Simulate factual outside drift in its query.
            let original = producer.shared.retained(0).unwrap();
            let captured = original.facts.borrow().clone();
            let change = || {
                let mut facts = original.facts.borrow_mut();
                match fault {
                    0 => facts.scope.generation += 1,
                    1 => facts.identity.guid[0] ^= 1,
                    2 => facts.identity.index += 1,
                    3 => facts.identity.luid += 1,
                    4 => facts.identity.description.push('x'),
                    5 => facts.identity.name.push('x'),
                    _ => facts.identity.if_type += 1,
                }
            };
            if !after_callback {
                change();
            }
            let called = Cell::new(false);
            assert!(
                observer
                    .inspect_live_carrier_identity(&scope(0), |_| {
                        called.set(true);
                        if after_callback {
                            change();
                        }
                        Ok(())
                    })
                    .is_err(),
                "after={after_callback}, fault={fault}"
            );
            assert_eq!(called.get(), after_callback);
            *original.facts.borrow_mut() = captured;
            assert!(observer
                .inspect_live_carrier_identity(&scope(0), |_| Ok(()))
                .is_err());
            assert_eq!(log.closes.get(), 0);
            assert_eq!(log.drops.get(), 0);
        }
    }
}

#[test]
fn never_attempted_key_preparation_requires_full_native_universe_and_cannot_begin() {
    let (mut producer, observer) = registry();
    assert_eq!(
        observer.assert_never_attempted(&context(), &scope(0).binding),
        Ok(UniverseObservation {
            context: context(),
            originals: vec![],
        })
    );
    assert_eq!(&*observer.shared.universe.calls.borrow(), &[0]);
    assert_eq!(
        &*observer.shared.universe.absent.borrow(),
        &[Some(scope(0).binding)]
    );
    assert_eq!(
        observer.assert_absent(&context(), &scope(0).binding),
        Err(Error::Pending)
    );
    assert!(producer.begin(scope(0)).is_err());
    producer.confirm_empty(scope(0), &mut absent()).unwrap();
    assert!(observer
        .assert_never_attempted(&context(), &scope(0).binding)
        .is_err());
    let attempt = producer.begin(scope(0)).unwrap();
    assert!(observer
        .assert_never_attempted(&context(), &scope(0).binding)
        .is_err());
    drop(attempt); // lost/ambiguous ACK cannot be turned back into fresh intent.
    assert!(observer
        .assert_never_attempted(&context(), &scope(0).binding)
        .is_err());

    // The full census is DATA, including actual originals of OTHER roles.
    // Returning it must neither manufacture target absence nor rearm Intent.
    let (mut producer, observer, log) = live(0);
    let expected = observer.observe_all(&context()).unwrap();
    assert_eq!(expected.originals.len(), 1);
    let reads = log.reads.get();
    assert_eq!(
        observer.assert_never_attempted(&context(), &scope(1).binding),
        Ok(expected)
    );
    assert!(log.reads.get() > reads);
    assert_eq!(observer.snapshot(&context()).unwrap()[1], State::Intent);
    assert!(producer.begin(scope(1)).is_err());
    assert_eq!(log.closes.get(), 0);
    assert_eq!(log.drops.get(), 0);
}

#[test]
fn safe_context_only_constructs_intents_not_absence_or_originals() {
    let (mut p, o) = registry();
    assert_eq!(o.snapshot(&context()).unwrap(), [State::Intent; 3]);
    assert_eq!(
        o.assert_absent(&context(), &scope(0).binding),
        Err(Error::Pending)
    );
    assert_eq!(o.observe(&scope(0)), Err(Error::Pending));
    assert!(p.begin(scope(0)).is_err());
}

#[test]
fn registry_composition_matches_retained_original_not_equal_imported_context() {
    let (p, o) = registry();
    let alias = p.observer();
    let (_, foreign) = registry();
    assert_eq!(o.context(), foreign.context());
    assert!(o.same_original_registry(&alias));
    assert!(alias.same_original_registry(&o));
    assert!(!o.same_original_registry(&foreign));
    assert!(!foreign.same_original_registry(&alias));
    // Pointer equality itself supplies no fresh/native absence permission.
    assert!(alias.assert_absent(&context(), &scope(0).binding).is_err());
    drop(p);
    assert!(o.same_original_registry(&alias));
    assert!(alias.observe(&scope(0)).is_err());
}
#[test]
fn unattempted_preparation_rejects_native_extra_error_or_changed_context_and_poison_sticks() {
    for fault in 0..3 {
        let (_producer, observer) = registry();
        match fault {
            0 => observer.shared.universe.extra.set(true),
            1 => observer.shared.universe.fault.set(1),
            _ => observer.shared.universe.wrong_runtime.set(true),
        }
        assert!(observer
            .assert_never_attempted(&context(), &scope(0).binding)
            .is_err());
        assert_eq!(&*observer.shared.universe.calls.borrow(), &[0]);
        observer.shared.universe.extra.set(false);
        observer.shared.universe.fault.set(0);
        observer.shared.universe.wrong_runtime.set(false);
        assert!(observer
            .assert_never_attempted(&context(), &scope(0).binding)
            .is_err());
        assert_eq!(&*observer.shared.universe.calls.borrow(), &[0]);
    }
}
#[test]
fn cleanup_universe_reads_exact_originals_after_poison_without_forward_rearming() {
    let (mut p, o, log) = live(0);
    // Deliberate foreign request poisons forward permission, not retained raw
    // original facts. No lookup/adoption or destructive effect in this query.
    let mut wrong = scope(0);
    wrong.generation += 1;
    assert!(p.retire(&wrong).is_err());
    let observed = o.observe_all_for_cleanup(&context()).unwrap();
    assert_eq!(observed.originals.len(), 1);
    assert_eq!(observed.originals[0].scope, scope(0));
    assert!(o.observe_all(&context()).is_err());
    assert_eq!(log.closes.get(), 0);
    assert!(p.begin(scope(1)).is_err());
    let retiring = p.retire(&scope(0)).unwrap();
    assert_eq!(
        o.observe_all_for_cleanup(&context())
            .unwrap()
            .originals
            .len(),
        1
    );
    let receipt = retiring.original().native_close();
    let ack = retiring.acknowledge_closed(receipt).unwrap();
    assert!(o
        .observe_all_for_cleanup(&context())
        .unwrap()
        .originals
        .is_empty());
    p.complete_close(ack, &mut absent()).unwrap();
    assert!(o
        .observe_all_for_cleanup(&context())
        .unwrap()
        .originals
        .is_empty());
    assert!(o.observe_all(&context()).is_err());
    assert_eq!(log.closes.get(), 1);
}

#[test]
fn cleanup_universe_denies_lost_ack_and_changed_native_facts_without_hiding_extra_devices() {
    let (mut p, o) = registry();
    p.confirm_empty(scope(0), &mut absent()).unwrap();
    drop(p.begin(scope(0)).unwrap());
    assert!(o.observe_all_for_cleanup(&context()).is_err());
    assert!(o.shared.universe.calls.borrow().is_empty());
    for fault in 0..3 {
        let (mut p, o, log) = live(0);
        let mut wrong = scope(0);
        wrong.generation += 1;
        assert!(p.retire(&wrong).is_err());
        match fault {
            0 => o.shared.universe.extra.set(true),
            1 => log.fail_read.set(true),
            _ => *o.shared.universe.provider.borrow_mut() = "changed".into(),
        }
        assert!(o.observe_all_for_cleanup(&context()).is_err());
        assert!(o.observe_all(&context()).is_err());
        assert_eq!(log.closes.get(), 0);
    }
}

#[test]
fn pending_native_create_without_ack_cannot_be_observed_as_an_empty_universe() {
    let (mut p, o) = registry();
    p.confirm_empty(scope(0), &mut absent()).unwrap();
    let begun = p.begin(scope(0)).unwrap();
    assert!(o.observe_all(&context()).is_err());
    assert!(o.shared.universe.calls.borrow().is_empty());
    // A late actual native ACK must still retain the original for cleanup;
    // denial of forward proof is not permission to discard that resource.
    let (n, log) = native(&scope(0));
    assert!(unsafe { begun.acknowledge_original(n) }.is_err());
    assert_eq!(log.drops.get(), 0);
    assert!(p.retire(&scope(0)).is_ok());
}

#[test]
fn key_cleanup_no_ack_facts_do_not_rearm_or_hide_pending_originals() {
    let (mut producer, observer) = registry();
    assert_eq!(
        observer.assert_no_creator_for_key_cleanup(&context(), &scope(0).binding),
        Ok(())
    );
    producer.confirm_empty(scope(0), &mut absent()).unwrap();
    assert_eq!(
        observer.assert_no_creator_for_key_cleanup(&context(), &scope(0).binding),
        Ok(())
    );
    let attempt = producer.begin(scope(0)).unwrap();
    assert!(observer
        .assert_no_creator_for_key_cleanup(&context(), &scope(0).binding)
        .is_err());
    drop(attempt);
    assert!(observer
        .assert_no_creator_for_key_cleanup(&context(), &scope(0).binding)
        .is_err());
    // Unattempted B is factual only after A poisoned the owner; never revives
    // begin/forward permission, and caller must query ALL native absence.
    assert_eq!(
        observer.assert_no_creator_for_key_cleanup(&context(), &scope(1).binding),
        Ok(())
    );
    assert!(producer.confirm_empty(scope(1), &mut absent()).is_err());
    let (_producer, observer, _) = live(0);
    assert!(observer
        .assert_no_creator_for_key_cleanup(&context(), &scope(0).binding)
        .is_err());
}
#[test]
fn actual_empty_then_unique_new_ack_publishes_all_three_disjoint_originals() {
    let (mut p, o) = registry();
    for i in 0..3 {
        let s = scope(i);
        p.confirm_empty(s.clone(), &mut absent()).unwrap();
        assert!(o.assert_absent(&context(), &s.binding).is_ok());
        let b = p.begin(s.clone()).unwrap();
        assert!(o.assert_absent(&context(), &s.binding).is_err());
        let (n, _) = native(&s);
        let ack = unsafe { b.acknowledge_original(n) }.unwrap();
        assert!(o.observe(&s).is_err());
        p.publish(ack).unwrap();
        assert_eq!(o.observe(&s).unwrap().identity.guid, [(i + 1) as u8; 16]);
    }
    assert_eq!(o.snapshot(&context()).unwrap(), [State::Live; 3]);
}
#[test]
fn native_receipt_context_validation_rejects_malformed_or_overlapping_scope() {
    for field in 0..8 {
        let mut c = context();
        match field {
            0 => c.bindings[1].guid = c.bindings[0].guid,
            1 => c.bindings[1].name = "CARRIER-C".into(),
            2 => c.bindings[0].role = Role::MemberA,
            3 => c.bindings[2].registry_path.push('x'),
            4 => c.provenance.boot_id = [0; 16],
            5 => c.provenance.runtime.slot = RuntimeSlot::Latest,
            6 => c.intent.scope.connection_generation = 0,
            _ => c.intent.addresses.clear(),
        }
        assert!(Producer::<Native>::intent(c, Universe::new()).is_err());
    }
}
#[test]
fn original_ack_loss_and_dropped_published_ack_never_rearm_or_report_empty() {
    for acknowledge in [false, true] {
        let (mut p, o) = registry();
        let s = scope(0);
        p.confirm_empty(s.clone(), &mut absent()).unwrap();
        let b = p.begin(s.clone()).unwrap();
        if acknowledge {
            let (n, l) = native(&s);
            drop(unsafe { b.acknowledge_original(n) }.unwrap());
            assert_eq!(l.drops.get(), 0);
        } else {
            drop(b);
        }
        assert_eq!(o.snapshot(&context()).unwrap()[0], State::Ambiguous);
        assert!(o.assert_absent(&context(), &s.binding).is_err());
        assert!(p.begin(s.clone()).is_err());
        assert!(p.confirm_empty(s, &mut absent()).is_err());
    }
}
#[test]
fn wrong_registry_context_binding_generation_and_provider_cannot_publish() {
    for field in 0..5 {
        let (mut p, o) = registry();
        let s = scope(0);
        p.confirm_empty(s.clone(), &mut absent()).unwrap();
        let b = p.begin(s.clone()).unwrap();
        let (n, l) = native(&s);
        match field {
            0 => {
                n.facts
                    .borrow_mut()
                    .scope
                    .context
                    .provenance
                    .runtime
                    .runtime_version = "wrong".into()
            }
            1 => n.facts.borrow_mut().scope.binding = scope(1).binding,
            2 => n.facts.borrow_mut().scope.generation += 1,
            3 => n.facts.borrow_mut().identity.guid = [9; 16],
            _ => l.fail_read.set(true),
        }
        let ack = unsafe { b.acknowledge_original(n) }.unwrap();
        assert!(p.publish(ack).is_err());
        assert!(o.observe(&s).is_err());
        assert_eq!(l.drops.get(), 0);
        assert!(
            p.retire(&s).is_ok(),
            "same retained original remains available for cleanup"
        );
    }
}
#[test]
fn observer_queries_original_while_outer_producer_is_mutably_borrowed() {
    let (mut p, o, _) = live(0);
    fn inside_outer_mutable_borrow(_: &mut Producer<Native>, o: &Observer<Native>) {
        assert_eq!(o.observe(&scope(0)).unwrap().identity.index, 11);
    }
    inside_outer_mutable_borrow(&mut p, &o.clone());
}
#[test]
fn wrong_scope_or_native_query_error_poison_all_forward_queries_but_keep_original_cleanup() {
    for wrong in [false, true] {
        let (mut p, o, l) = live(0);
        let mut s = scope(0);
        if wrong {
            s.context.provenance.network_epoch += 1;
        } else {
            l.fail_read.set(true);
        }
        assert!(o.observe(&s).is_err());
        let reads = l.reads.get();
        assert!(o.observe(&scope(0)).is_err());
        assert_eq!(l.reads.get(), reads);
        assert!(p.begin(scope(1)).is_err());
        let mut a = absent();
        assert!(p.confirm_empty(scope(1), &mut a).is_err());
        assert_eq!(a.calls, 0);
        let retirement = p.retire(&scope(0)).unwrap();
        let receipt = retirement.original().native_close();
        let ack = retirement.acknowledge_closed(receipt).unwrap();
        p.complete_close(ack, &mut absent()).unwrap();
        assert_eq!(l.closes.get(), 1);
        assert_eq!(l.reads.get(), reads);
    }
}
#[test]
fn same_native_close_receipt_and_independent_absence_are_both_required() {
    let (mut p, o, l) = live(0);
    let r = p.retire(&scope(0)).unwrap();
    assert_eq!(o.snapshot(&context()).unwrap()[0], State::Retiring);
    let receipt = r.original().native_close();
    let ack = r.acknowledge_closed(receipt).unwrap();
    let released = p.complete_close(ack, &mut absent()).unwrap();
    assert_eq!(o.snapshot(&context()).unwrap()[0], State::Closed);
    assert!(o.assert_absent(&context(), &scope(0).binding).is_ok());
    assert!(o.observe(&scope(0)).is_err());
    assert_eq!(l.drops.get(), 0);
    drop(released);
    assert_eq!(l.drops.get(), 1);
    assert_eq!(l.closes.get(), 1);
    assert!(p.begin(scope(0)).is_err());
}

fn released_live() -> (
    Producer<Native>,
    Observer<Native>,
    Released<Native>,
    Rc<Log>,
) {
    let (mut p, o, log) = live(0);
    let r = p.retire(&scope(0)).unwrap();
    let receipt = r.original().native_close();
    let ack = r.acknowledge_closed(receipt).unwrap();
    let released = p.complete_close(ack, &mut absent()).unwrap();
    (p, o, released, log)
}

#[test]
fn retired_history_keeps_actual_captured_identity_and_never_reopens_native() {
    let (mut p, o, released, log) = released_live();
    let reader = released.read_pin().unwrap();
    let reads = log.reads.get();
    let checks = log.close_checks.get();
    let mut query = absent();
    let observed = reader.observe(&mut query).unwrap();
    assert_eq!(observed.captured().scope, scope(0));
    assert_eq!(
        observed.captured().identity,
        native(&scope(0)).0.facts.borrow().identity
    );
    assert_eq!(observed.captured().provider, "actual-original-provider");
    assert_eq!(query.calls, 1);
    assert_eq!(
        log.reads.get(),
        reads,
        "closed raw interface is never queried as live"
    );
    assert_eq!(log.close_checks.get(), checks + 2);
    assert!(o.observe(&scope(0)).is_err());
    assert!(p.begin(scope(0)).is_err());
    drop(released);
    assert_eq!(
        log.drops.get(),
        0,
        "independent reader retains the SAME original pins"
    );
    assert!(reader.observe(&mut absent()).is_ok());
    drop(reader);
    assert_eq!(log.drops.get(), 1);
    assert_eq!(log.closes.get(), 1);
}

#[test]
fn retired_original_cut_requires_this_readers_full_outer_bracket() {
    let (_p, _o, released, log) = released_live();
    let reader = released.read_pin().unwrap();
    let sibling = released.read_pin().unwrap();
    let raw_reads = log.reads.get();
    let calls = Cell::new(0);
    assert!(reader
        .with_original_closed_in_bracket(|_, _| {
            calls.set(calls.get() + 1);
            Ok(())
        })
        .is_err());
    reader
        .inspect(&mut absent(), |_| {
            assert!(sibling
                .with_original_closed_in_bracket(|_, _| {
                    calls.set(calls.get() + 1);
                    Ok(())
                })
                .is_err());
            reader.with_original_closed_in_bracket(|original, receipt| {
                original.verify_close_receipt(&scope(0), receipt)?;
                assert!(Rc::ptr_eq(
                    &original.identity,
                    &released.original().identity
                ));
                calls.set(calls.get() + 1);
                Ok(())
            })
        })
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(log.reads.get(), raw_reads, "no closed SDK handle query");
    assert!(reader
        .with_original_closed_in_bracket(|_, _| Ok(()))
        .is_err());
    assert_eq!(log.closes.get(), 1);
}

#[test]
fn retired_original_cut_unwind_and_caught_nested_fault_cannot_escape_bracket() {
    for unwind in [false, true] {
        let (p, _o, released, log) = released_live();
        let reader = released.read_pin().unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            reader.inspect(&mut absent(), |_| {
                reader.with_original_closed_in_bracket(|_, _| {
                    if unwind {
                        panic!("original reference boundary");
                    }
                    assert!(p.observer().observe_all_for_cleanup(&context()).is_err());
                    Ok(())
                })
            })
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert!(!p.shared.busy.get());
        assert!(reader
            .with_original_closed_in_bracket(|_, _| Ok(()))
            .is_err());
        assert_eq!(log.closes.get(), 1);
        reader
            .inspect(&mut absent(), |_| {
                reader.with_original_closed_in_bracket(|n, r| n.verify_close_receipt(&scope(0), r))
            })
            .unwrap();
    }
}

#[test]
fn retired_original_cut_caught_callback_failure_invalidates_outer_success() {
    let (_p, _o, released, log) = released_live();
    let reader = released.read_pin().unwrap();
    let result = reader.inspect(&mut absent(), |_| {
        let failed: Result<()> = reader.with_original_closed_in_bracket(|_, _| Err(Error::Native));
        assert_eq!(failed, Err(Error::Native));
        Ok(()) // a caller must not hide a failed original-reference operation
    });
    assert!(result.is_err());
    assert_eq!(log.closes.get(), 1);
    reader
        .inspect(&mut absent(), |_| {
            reader.with_original_closed_in_bracket(|n, r| n.verify_close_receipt(&scope(0), r))
        })
        .unwrap();
}

#[test]
fn retired_original_cut_fault_counter_exhaustion_cannot_hide_reentry() {
    let (p, _o, released, log) = released_live();
    let reader = released.read_pin().unwrap();
    p.shared.faults.set(u64::MAX - 1);
    let result = reader.inspect(&mut absent(), |_| {
        reader.with_original_closed_in_bracket(|_, _| {
            assert!(p.observer().observe_all_for_cleanup(&context()).is_err());
            Ok(())
        })
    });
    assert!(
        result.is_err(),
        "counter exhaustion must not conceal an inner fault"
    );
    assert_eq!(log.closes.get(), 1);
    assert!(reader.observe(&mut absent()).is_err());
}

#[test]
fn retired_history_requires_fresh_full_universe_absence_and_exact_close_receipt() {
    for fault in 0..6 {
        let (p, _o, released, log) = released_live();
        let reader = released.read_pin().unwrap();
        let mut query = absent();
        match fault {
            0 => query.fail = true,
            1 => query.found = true,
            2 => query.wrong = true,
            3 => p.shared.universe.extra.set(true),
            4 => p.shared.universe.wrong_runtime.set(true),
            _ => log.fail_close_check.set(true),
        }
        assert!(reader.observe(&mut query).is_err());
        assert!(p.shared.poisoned.get());
        assert_eq!(log.closes.get(), 1);
        assert!(p.observer().observe_all(&context()).is_err());
        // Cleanup may re-query the SAME original receipt after a transient
        // failure. It never grants a new live create or suppresses obligations.
        p.shared.universe.extra.set(false);
        p.shared.universe.wrong_runtime.set(false);
        log.fail_close_check.set(false);
        assert!(reader.observe(&mut absent()).is_ok());
    }
}

#[test]
fn retired_history_ignored_reentrant_full_query_and_unwind_cannot_publish_success() {
    for unwind in [false, true] {
        let (p, _o, released, log) = released_live();
        let reader = released.read_pin().unwrap();
        let observer = p.observer();
        *p.shared.universe.on_inspect.borrow_mut() = Some(Box::new(move || {
            if unwind {
                panic!("closed full provider boundary");
            }
            assert!(observer.observe_all_for_cleanup(&context()).is_err());
        }));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            reader.observe(&mut absent())
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert!(p.shared.poisoned.get());
        assert!(!p.shared.busy.get());
        assert_eq!(log.closes.get(), 1);
        *p.shared.universe.on_inspect.borrow_mut() = None;
        assert!(reader.observe(&mut absent()).is_ok());
        assert!(p.observer().observe_all(&context()).is_err());
    }
}

#[test]
fn acknowledged_but_never_captured_original_cannot_invent_retired_binding_history() {
    let (mut p, _o) = registry();
    p.confirm_empty(scope(0), &mut absent()).unwrap();
    let begin = p.begin(scope(0)).unwrap();
    let (n, log) = native(&scope(0));
    drop(unsafe { begin.acknowledge_original(n) }.unwrap());
    let r = p.retire(&scope(0)).unwrap();
    let receipt = r.original().native_close();
    let ack = r.acknowledge_closed(receipt).unwrap();
    let released = p.complete_close(ack, &mut absent()).unwrap();
    assert!(released.read_pin().is_err());
    assert_eq!(log.reads.get(), 0);
    assert_eq!(log.closes.get(), 1);
}

fn released_before_publication() -> (Producer<Native>, Released<Native>, Rc<Log>) {
    let (mut p, _) = registry();
    p.confirm_empty(scope(0), &mut absent()).unwrap();
    let begin = p.begin(scope(0)).unwrap();
    let (original, log) = native(&scope(0));
    let ack = unsafe { begin.acknowledge_original(original) }.unwrap();
    p.shared.universe.fault.set(1);
    assert!(p.publish(ack).is_err());
    p.shared.universe.fault.set(0);
    let retirement = p.retire(&scope(0)).unwrap();
    let close = retirement.original().native_close();
    let ack = retirement.acknowledge_closed(close).unwrap();
    let released = p.complete_close(ack, &mut absent()).unwrap();
    (p, released, log)
}

#[test]
fn unpublished_closed_original_brackets_cleanup_without_inventing_published_identity() {
    let (mut p, released, log) = released_before_publication();
    assert!(released.read_pin().is_err());
    let reader = released.read_unpublished_closed_pin().unwrap();
    let reads = log.reads.get();
    let checks = log.close_checks.get();
    let mut query = absent();
    assert_eq!(reader.inspect(&scope(0), &mut query, || Ok(47)), Ok(47));
    assert_eq!(query.calls, 2);
    assert_eq!(log.close_checks.get(), checks + 4);
    assert_eq!(
        log.reads.get(),
        reads,
        "never query a closed raw NIC as live"
    );
    assert!(p.begin(scope(0)).is_err());
    drop(released);
    assert_eq!(
        log.drops.get(),
        0,
        "reader retains actual create/close pins"
    );
    assert!(reader.inspect(&scope(0), &mut absent(), || Ok(())).is_ok());
    drop(reader);
    assert_eq!(log.drops.get(), 1);
    assert_eq!(log.closes.get(), 1);
    let (_, _, published, _) = released_live();
    assert!(published.read_unpublished_closed_pin().is_err());
}

#[test]
fn closed_read_selection_never_falls_back_after_published_history_failure() {
    let (_p, released, _) = released_before_publication();
    assert!(matches!(
        released.cleanup_read_pin(),
        Ok(ClosedRead::Unpublished(_))
    ));
    let (_p, _, mut published, _) = released_live();
    assert!(matches!(
        published.cleanup_read_pin(),
        Ok(ClosedRead::Published(_))
    ));
    published.captured = None;
    assert!(published.cleanup_read_pin().is_err());
    let (_p, mut unpublished, _) = released_before_publication();
    unpublished.captured = Some(native(&scope(0)).0.facts.borrow().clone());
    assert!(unpublished.cleanup_read_pin().is_err());
}

#[test]
fn unpublished_closed_original_denies_foreign_scope_native_faults_and_missing_owner() {
    for fault in 0..7 {
        let (p, released, log) = released_before_publication();
        let reader = released.read_unpublished_closed_pin().unwrap();
        let mut expected = scope(0);
        let mut query = absent();
        match fault {
            0 => expected.generation += 1,
            1 => query.fail = true,
            2 => query.found = true,
            3 => query.wrong = true,
            4 => p.shared.universe.extra.set(true),
            5 => p.shared.universe.wrong_runtime.set(true),
            _ => log.fail_close_check.set(true),
        }
        let called = Cell::new(false);
        assert!(reader
            .inspect(&expected, &mut query, || {
                called.set(true);
                Ok(())
            })
            .is_err());
        assert!(!called.get());
        assert_eq!(log.closes.get(), 1);
        assert_eq!(log.drops.get(), 0);
        assert!(p.observer().observe_all(&context()).is_err());
    }
    let (p, released, _) = released_before_publication();
    let reader = released.read_unpublished_closed_pin().unwrap();
    drop(p);
    assert!(reader.inspect(&scope(0), &mut absent(), || Ok(())).is_err());
}

#[test]
fn unpublished_closed_original_retains_pins_on_callback_fault_unwind_reentry_or_drift() {
    for fault in 0..5 {
        let (p, released, log) = released_before_publication();
        let reader = released.read_unpublished_closed_pin().unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            reader.inspect(&scope(0), &mut absent(), || {
                match fault {
                    0 => return Err(Error::Native),
                    1 => panic!("prepublication cleanup boundary"),
                    2 => assert!(reader.inspect(&scope(0), &mut absent(), || Ok(())).is_err()),
                    3 => p.shared.universe.extra.set(true),
                    _ => log.fail_close_check.set(true),
                }
                Ok(())
            })
        }));
        if fault == 1 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert!(p.shared.poisoned.get());
        assert!(!p.shared.busy.get());
        assert_eq!(log.closes.get(), 1);
        assert_eq!(log.drops.get(), 0);
        p.shared.universe.extra.set(false);
        log.fail_close_check.set(false);
        assert!(reader.inspect(&scope(0), &mut absent(), || Ok(())).is_ok());
    }
}

#[test]
fn retired_history_requires_current_original_producer_and_no_other_live_native() {
    let (mut p, _o, released, log) = released_live();
    let reader = released.read_pin().unwrap();
    p.confirm_empty(scope(1), &mut absent()).unwrap();
    let begin = p.begin(scope(1)).unwrap();
    let (member, _member_log) = native(&scope(1));
    let ack = unsafe { begin.acknowledge_original(member) }.unwrap();
    p.publish(ack).unwrap();
    assert!(reader.observe(&mut absent()).is_err());
    assert_eq!(log.closes.get(), 1);
    // Forward stays revoked. Only SAME actual acknowledged cleanup can remove
    // the live obstruction; do not turn a journal-only Closed into absence.
    let r = p.retire(&scope(1)).unwrap();
    let receipt = r.original().native_close();
    let ack = r.acknowledge_closed(receipt).unwrap();
    let _member_released = p.complete_close(ack, &mut absent()).unwrap();
    assert!(reader.observe(&mut absent()).is_ok());
    drop(p);
    assert!(reader.observe(&mut absent()).is_err());
}

#[test]
fn retired_history_detects_absence_callback_reentry_before_after_receipt() {
    struct RecursiveAbsence {
        observer: Observer<Native>,
    }
    unsafe impl NativeAbsence for RecursiveAbsence {
        fn inspect_absence(&mut self, s: &Scope) -> Result<AbsenceFacts> {
            assert!(self.observer.observe_all_for_cleanup(&context()).is_err());
            Ok(AbsenceFacts {
                scope: s.clone(),
                matches: vec![],
            })
        }
    }
    let (p, _o, released, log) = released_live();
    let reader = released.read_pin().unwrap();
    let checks = log.close_checks.get();
    let mut query = RecursiveAbsence {
        observer: p.observer(),
    };
    assert!(reader.observe(&mut query).is_err());
    assert_eq!(
        log.close_checks.get(),
        checks + 1,
        "stop immediately after ignored reentry"
    );
    assert!(p.shared.poisoned.get());
    assert!(reader.observe(&mut absent()).is_ok());
}

#[test]
fn successful_retired_read_revokes_all_forward_original_queries_and_new_attempts() {
    let (mut p, o, released, _log) = released_live();
    let reader = released.read_pin().unwrap();
    assert!(reader.observe(&mut absent()).is_ok());
    assert!(o.observe_all(&context()).is_err());
    assert!(p.confirm_empty(scope(1), &mut absent()).is_err());
    assert!(
        reader.observe(&mut absent()).is_ok(),
        "same opaque cleanup facts remain queryable"
    );
}

#[test]
fn retired_inspection_brackets_callback_with_full_absence_without_live_adoption() {
    let (p, _o, released, log) = released_live();
    let reader = released.read_pin().unwrap();
    let mut query = absent();
    let reads = log.reads.get();
    let result = reader
        .inspect(&mut query, |facts| {
            assert_eq!(facts.captured().scope, scope(0));
            assert!(p.shared.busy.get());
            Ok(47)
        })
        .unwrap();
    assert_eq!(result, 47);
    assert_eq!(query.calls, 2);
    assert_eq!(log.reads.get(), reads);
    assert_eq!(log.closes.get(), 1);
}

#[test]
fn retired_inspection_denies_callback_errors_unwind_reentry_and_changed_after_facts() {
    for fault in 0..5 {
        let (p, _o, released, log) = released_live();
        let reader = released.read_pin().unwrap();
        let mut query = absent();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            reader.inspect(&mut query, |_| {
                match fault {
                    0 => return Err(Error::Native),
                    1 => panic!("WFP read boundary"),
                    2 => {
                        assert!(reader.observe(&mut absent()).is_err());
                    }
                    3 => p.shared.universe.extra.set(true),
                    _ => log.fail_close_check.set(true),
                }
                Ok(())
            })
        }));
        if fault == 1 {
            assert!(outcome.is_err());
        } else {
            assert!(outcome.unwrap().is_err());
        }
        assert!(p.shared.poisoned.get());
        assert!(!p.shared.busy.get());
        assert_eq!(log.closes.get(), 1);
        p.shared.universe.extra.set(false);
        log.fail_close_check.set(false);
        assert!(reader.observe(&mut absent()).is_ok());
    }
}
#[test]
fn foreign_close_receipt_failure_or_absence_failure_retains_same_original_without_reclose() {
    for failure in 0..4 {
        let (mut p, o, l) = live(0);
        let r = p.retire(&scope(0)).unwrap();
        let mut receipt = r.original().native_close();
        if failure == 0 {
            receipt.identity = Rc::new(());
        }
        let result = r.acknowledge_closed(receipt);
        if failure == 0 {
            assert!(result.is_err());
        } else {
            let ack = result.unwrap();
            let mut a = absent();
            match failure {
                1 => a.fail = true,
                2 => a.found = true,
                _ => a.wrong = true,
            };
            assert!(p.complete_close(ack, &mut a).is_err());
        }
        assert_eq!(o.snapshot(&context()).unwrap()[0], State::Retiring);
        assert!(o.assert_absent(&context(), &scope(0).binding).is_err());
        assert_eq!(l.drops.get(), 0);
        assert_eq!(l.closes.get(), 1);
        assert!(p.retire(&scope(0)).is_err());
    }
}
#[test]
fn dropping_live_producer_keeps_tombstone_and_original_pins_without_native_drop() {
    let (p, o, l) = live(0);
    drop(p);
    assert!(o.assert_absent(&context(), &scope(0).binding).is_err());
    assert!(o.observe(&scope(0)).is_err());
    assert_eq!(l.closes.get(), 0);
    assert_eq!(l.drops.get(), 0);
    drop(o);
    assert_eq!(
        l.drops.get(),
        0,
        "unresolved original pins are deliberately retained"
    );
}
#[test]
fn recursive_observer_query_denies_without_refcell_panic_and_poison_blocks_outer_success() {
    let (mut p, o, l) = live(0);
    let reentrant = o.clone();
    *l.on_read.borrow_mut() = Some(Box::new(move || {
        assert!(reentrant.observe(&scope(0)).is_err());
    }));
    assert!(o.observe(&scope(0)).is_err());
    let reads = l.reads.get();
    *l.on_read.borrow_mut() = None;
    assert!(o.observe(&scope(0)).is_err());
    assert_eq!(l.reads.get(), reads);
    let r = p.retire(&scope(0)).unwrap();
    let receipt = r.original().native_close();
    let ack = r.acknowledge_closed(receipt).unwrap();
    p.complete_close(ack, &mut absent()).unwrap();
}

#[test]
fn poisoned_cleanup_closure_remains_a_fact_without_reviving_forward_permission() {
    let (mut p, o, l) = live(0);
    l.fail_read.set(true);
    assert!(o.observe(&scope(0)).is_err());
    assert!(o
        .assert_closed_for_cleanup(&context(), &scope(0).binding)
        .is_err());
    let r = p.retire(&scope(0)).unwrap();
    let receipt = r.original().native_close();
    let ack = r.acknowledge_closed(receipt).unwrap();
    let released = p.complete_close(ack, &mut absent()).unwrap();
    assert!(o
        .assert_closed_for_cleanup(&context(), &scope(0).binding)
        .is_ok());
    assert!(o.assert_absent(&context(), &scope(0).binding).is_err());
    assert!(p.begin(scope(1)).is_err());
    assert_eq!(released.scope(), &scope(0));
    assert!(released
        .original()
        .verify_close_receipt(released.scope(), released.receipt())
        .is_ok());
}
#[test]
fn stale_retirement_generation_poison_denies_every_other_forward_scope() {
    let (mut p, o, _) = live(0);
    let mut wrong = scope(0);
    wrong.generation += 1;
    assert!(p.retire(&wrong).is_err());
    let mut a = absent();
    assert!(p.confirm_empty(scope(1), &mut a).is_err());
    assert_eq!(a.calls, 0);
    assert!(o.observe(&scope(0)).is_err());
    assert!(p.retire(&scope(0)).is_ok());
}
#[test]
fn changed_original_identity_or_provider_never_becomes_replacement_ownership() {
    for field in 0..8 {
        let (mut p, o, l) = live(0);
        let native = p.shared.retained(0).unwrap();
        let mut facts = native.facts.borrow_mut();
        match field {
            0 => facts.identity.guid[15] ^= 1,
            1 => facts.identity.luid += 1 << 24,
            2 => facts.identity.index += 1,
            3 => facts.identity.name.push('x'),
            4 => facts.identity.description.push('x'),
            5 => facts.identity.if_type = 6,
            6 => facts.identity.tunnel_type = 1,
            _ => *p.shared.universe.provider.borrow_mut() = "replacement-provider".into(),
        };
        drop(facts);
        assert!(o.observe(&scope(0)).is_err());
        let reads = l.reads.get();
        assert!(o.observe(&scope(0)).is_err());
        assert_eq!(l.reads.get(), reads);
        assert!(p.retire(&scope(0)).is_ok());
        assert_eq!(l.drops.get(), 0);
    }
}

#[test]
fn one_native_provider_query_covers_c_and_both_actual_awg_originals_together() {
    let (mut p, o) = registry();
    let mut logs = vec![];
    for i in 0..3 {
        let s = scope(i);
        p.confirm_empty(s.clone(), &mut absent()).unwrap();
        let b = p.begin(s.clone()).unwrap();
        let (n, l) = native(&s);
        let ack = unsafe { b.acknowledge_original(n) }.unwrap();
        p.publish(ack).unwrap();
        logs.push(l);
    }
    assert_eq!(*p.shared.universe.calls.borrow(), [1, 2, 3]);
    let all = o.observe_all(&context()).unwrap();
    assert_eq!(all.originals.len(), 3);
    assert_eq!(*p.shared.universe.calls.borrow(), [1, 2, 3, 3]);
    assert_eq!(
        all.originals
            .iter()
            .map(|f| f.scope.binding.role)
            .collect::<Vec<_>>(),
        [Role::RoleCarrier, Role::MemberA, Role::MemberB]
    );
    assert!(logs.iter().all(|l| l.reads.get() > 0));
}
#[test]
fn full_universe_unknown_extra_missing_or_changed_runtime_never_filters_to_owned_success() {
    for field in 0..3 {
        let (p, o, l) = live(0);
        match field {
            0 => p.shared.universe.extra.set(true),
            1 => p.shared.universe.missing.set(true),
            _ => p.shared.universe.wrong_runtime.set(true),
        };
        assert!(o.observe_all(&context()).is_err());
        let count = p.shared.universe.calls.borrow().len();
        let reads = l.reads.get();
        assert!(o.observe_all(&context()).is_err());
        assert_eq!(p.shared.universe.calls.borrow().len(), count);
        assert_eq!(l.reads.get(), reads);
    }
}
#[test]
fn same_context_different_registry_and_reused_create_ack_tokens_are_rejected() {
    let (mut p, o) = registry();
    let (mut other, _) = registry();
    let s = scope(0);
    p.confirm_empty(s.clone(), &mut absent()).unwrap();
    let begin = p.begin(s.clone()).unwrap();
    let (n, l) = native(&s);
    let ack = unsafe { begin.acknowledge_original(n) }.unwrap();
    assert!(other.publish(ack).is_err());
    assert_eq!(l.reads.get(), 0);
    assert!(o.observe(&s).is_err());
    assert!(p.retire(&s).is_ok());
    let (mut p, _) = registry();
    p.confirm_empty(s.clone(), &mut absent()).unwrap();
    let begin = p.begin(s.clone()).unwrap();
    let (n, l) = native(&s);
    let ack = unsafe { begin.acknowledge_original(n) }.unwrap();
    // Private test instrumentation attacks the token identity; there is no
    // public constructor or Clone operation which could do this safely.
    let replay = NewCreate {
        shared: ack.shared.clone(),
        attempt: ack.attempt.clone(),
        completed: false,
    };
    p.publish(ack).unwrap();
    assert!(p.publish(replay).is_err());
    assert_eq!(l.reads.get(), 2);
}
#[test]
fn partial_attempt_poison_still_retains_late_actual_ack_for_exact_original_cleanup() {
    let (mut p, o) = registry();
    p.confirm_empty(scope(0), &mut absent()).unwrap();
    p.confirm_empty(scope(1), &mut absent()).unwrap();
    let original = p.begin(scope(0)).unwrap();
    drop(p.begin(scope(1)).unwrap());
    let (n, l) = native(&scope(0));
    assert!(unsafe { original.acknowledge_original(n) }.is_err());
    assert_eq!(l.reads.get(), 0);
    assert_eq!(l.drops.get(), 0);
    assert!(o.assert_absent(&context(), &scope(1).binding).is_err());
    assert!(p.retire(&scope(1)).is_err());
    let r = p.retire(&scope(0)).unwrap();
    let receipt = r.original().native_close();
    let ack = r.acknowledge_closed(receipt).unwrap();
    p.complete_close(ack, &mut absent()).unwrap();
    assert_eq!(l.closes.get(), 1);
}
#[test]
fn native_read_unwind_poison_keeps_captured_original_and_cannot_resume_forward_queries() {
    let (mut p, o) = registry();
    p.confirm_empty(scope(0), &mut absent()).unwrap();
    let b = p.begin(scope(0)).unwrap();
    let (n, l) = native(&scope(0));
    *l.on_read.borrow_mut() = Some(Box::new(|| panic!("native boundary unwind")));
    let ack = unsafe { b.acknowledge_original(n) }.unwrap();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| p.publish(ack))).is_err());
    let reads = l.reads.get();
    assert!(o.observe(&scope(0)).is_err());
    assert_eq!(l.reads.get(), reads);
    assert_eq!(l.drops.get(), 0);
    *l.on_read.borrow_mut() = None;
    let r = p.retire(&scope(0)).unwrap();
    let receipt = r.original().native_close();
    let ack = r.acknowledge_closed(receipt).unwrap();
    p.complete_close(ack, &mut absent()).unwrap();
}
#[test]
fn lost_completion_can_retry_fresh_absence_with_same_receipt_but_never_repeat_close() {
    let (mut p, o, l) = live(0);
    let r = p.retire(&scope(0)).unwrap();
    let receipt = r.original().native_close();
    drop(r.acknowledge_closed(receipt).unwrap());
    let retry = p.resume_close(&scope(0)).unwrap();
    let replay = CloseAck {
        shared: retry.shared.clone(),
        attempt: retry.attempt.clone(),
        nonce: retry.nonce.clone(),
        completed: false,
    };
    drop(retry);
    let fresh = p.resume_close(&scope(0)).unwrap();
    let mut a = absent();
    assert!(p.complete_close(replay, &mut a).is_err());
    assert_eq!(a.calls, 0);
    p.complete_close(fresh, &mut a).unwrap();
    assert_eq!(a.calls, 1);
    assert_eq!(l.closes.get(), 1);
    assert_eq!(l.reads.get(), 2);
    assert_eq!(o.snapshot(&context()).unwrap()[0], State::Closed);
    assert!(p.resume_close(&scope(0)).is_err());
}
#[test]
fn dropping_retirement_without_close_receipt_never_fabricates_completion_or_reissues_close() {
    let (mut p, o, l) = live(0);
    drop(p.retire(&scope(0)).unwrap());
    assert!(p.retire(&scope(0)).is_err());
    assert!(p.resume_close(&scope(0)).is_err());
    assert!(o.assert_absent(&context(), &scope(0).binding).is_err());
    assert_eq!(l.closes.get(), 0);
    assert_eq!(l.drops.get(), 0);
}

#[test]
fn whole_provider_waits_for_every_original_and_fences_every_full_identity_afterwards() {
    let (mut p, o) = registry();
    let mut logs = vec![];
    for i in 0..3 {
        let s = scope(i);
        p.confirm_empty(s.clone(), &mut absent()).unwrap();
        let b = p.begin(s.clone()).unwrap();
        let (n, l) = native(&s);
        p.publish(unsafe { b.acknowledge_original(n) }.unwrap())
            .unwrap();
        logs.push(l);
    }
    let before = logs.iter().map(|l| l.reads.get()).collect::<Vec<_>>();
    let captured = logs.clone();
    let expected = before.clone();
    *p.shared.universe.on_inspect.borrow_mut() = Some(Box::new(move || {
        for (l, count) in captured.iter().zip(&expected) {
            assert_eq!(
                l.reads.get(),
                count + 1,
                "all original raw identities precede provider"
            );
        }
    }));
    o.observe_all(&context()).unwrap();
    for (l, count) in logs.iter().zip(&before) {
        assert_eq!(l.reads.get(), count + 2);
    }
    *p.shared.universe.on_inspect.borrow_mut() = None;
    let n = p.shared.retained(2).unwrap();
    *p.shared.universe.on_inspect.borrow_mut() =
        Some(Box::new(move || n.facts.borrow_mut().identity.index += 1));
    assert_eq!(o.observe_all(&context()), Err(Error::Changed));
    let calls = p.shared.universe.calls.borrow().len();
    assert!(o.observe_all(&context()).is_err());
    assert_eq!(p.shared.universe.calls.borrow().len(), calls);
}
#[test]
fn complete_actual_mib_description_including_windows_numeric_suffix_is_preserved() {
    let (mut p, o) = registry();
    let mut originals = vec![];
    for i in 0..2 {
        let s = scope(i);
        p.confirm_empty(s.clone(), &mut absent()).unwrap();
        let b = p.begin(s.clone()).unwrap();
        let (n, _) = native(&s);
        let description = if i == 0 {
            "Nelomai Tunnel"
        } else {
            "Nelomai Tunnel #2"
        };
        n.facts.borrow_mut().identity.description = description.into();
        p.publish(unsafe { b.acknowledge_original(n) }.unwrap())
            .unwrap();
        originals.push(description);
    }
    let all = o.observe_all(&context()).unwrap();
    assert_eq!(
        all.originals
            .iter()
            .map(|o| o.identity.description.as_str())
            .collect::<Vec<_>>(),
        originals
    );
    p.shared
        .retained(1)
        .unwrap()
        .facts
        .borrow_mut()
        .identity
        .description = "Nelomai Tunnel".into();
    assert_eq!(o.observe_all(&context()), Err(Error::Changed));
}
#[test]
fn whole_provider_error_duplicate_scope_or_fabricated_identity_denies_and_retains_actuals() {
    for fault in 1..5 {
        let (mut p, o, _) = live(0);
        let s = scope(1);
        p.confirm_empty(s.clone(), &mut absent()).unwrap();
        let b = p.begin(s.clone()).unwrap();
        let (n, l) = native(&s);
        p.publish(unsafe { b.acknowledge_original(n) }.unwrap())
            .unwrap();
        p.shared.universe.fault.set(fault);
        assert!(o.observe_all(&context()).is_err());
        let calls = p.shared.universe.calls.borrow().len();
        let reads = l.reads.get();
        assert!(o.observe_all(&context()).is_err());
        assert_eq!(p.shared.universe.calls.borrow().len(), calls);
        assert_eq!(l.reads.get(), reads);
        assert!(p.retire(&scope(0)).is_ok());
        assert!(p.retire(&scope(1)).is_ok());
        assert_eq!(l.drops.get(), 0);
    }
}
#[test]
fn duplicate_raw_index_or_luid_fails_before_any_provider_query() {
    for duplicate_luid in [false, true] {
        let (mut p, o, _) = live(0);
        let s = scope(1);
        p.confirm_empty(s.clone(), &mut absent()).unwrap();
        let b = p.begin(s.clone()).unwrap();
        let (n, l) = native(&s);
        let first = p.shared.retained(0).unwrap();
        if duplicate_luid {
            n.facts.borrow_mut().identity.luid = first.facts.borrow().identity.luid;
        } else {
            n.facts.borrow_mut().identity.index = first.facts.borrow().identity.index;
        }
        let calls = p.shared.universe.calls.borrow().len();
        let ack = unsafe { b.acknowledge_original(n) }.unwrap();
        assert!(p.publish(ack).is_err());
        assert_eq!(p.shared.universe.calls.borrow().len(), calls);
        assert!(o.observe_all(&context()).is_err());
        assert_eq!(l.drops.get(), 0);
        assert!(p.retire(&s).is_ok());
    }
}
#[test]
fn recursive_original_or_provider_callback_stops_queries_immediately_on_poison() {
    for in_provider in [false, true] {
        let (mut p, o, l) = live(0);
        let observer = o.clone();
        let reads = l.reads.get();
        let calls = p.shared.universe.calls.borrow().len();
        let callback = Box::new(move || assert!(observer.observe_all(&context()).is_err()));
        if in_provider {
            *p.shared.universe.on_inspect.borrow_mut() = Some(callback);
        } else {
            *l.on_read.borrow_mut() = Some(callback);
        }
        assert!(o.observe_all(&context()).is_err());
        assert_eq!(
            l.reads.get(),
            reads + 1,
            "no after-fence callback after poison"
        );
        assert_eq!(
            p.shared.universe.calls.borrow().len(),
            calls + usize::from(in_provider)
        );
        *p.shared.universe.on_inspect.borrow_mut() = None;
        *l.on_read.borrow_mut() = None;
        let r = p.retire(&scope(0)).unwrap();
        let receipt = r.original().native_close();
        let ack = r.acknowledge_closed(receipt).unwrap();
        p.complete_close(ack, &mut absent()).unwrap();
    }
}
#[test]
fn all_universe_query_still_checks_empty_input_and_never_turns_intent_into_absence() {
    let (p, o) = registry();
    assert!(o.observe_all(&context()).unwrap().originals.is_empty());
    assert_eq!(*p.shared.universe.calls.borrow(), [0]);
    assert!(o.assert_absent(&context(), &scope(0).binding).is_err());
    p.shared.universe.extra.set(true);
    assert!(o.observe_all(&context()).is_err());
    assert_eq!(o.snapshot(&context()).unwrap(), [State::Ambiguous; 3]);
}
#[test]
fn initial_raw_identity_rejects_non_wintun_type_tunnel_zero_or_unbounded_description() {
    for field in 0..7 {
        let (mut p, o) = registry();
        let s = scope(0);
        p.confirm_empty(s.clone(), &mut absent()).unwrap();
        let b = p.begin(s.clone()).unwrap();
        let (n, l) = native(&s);
        match field {
            0 => n.facts.borrow_mut().identity.if_type = 6,
            1 => n.facts.borrow_mut().identity.tunnel_type = 1,
            2 => n.facts.borrow_mut().identity.luid = 0,
            3 => n.facts.borrow_mut().identity.index = 0,
            4 => n.facts.borrow_mut().identity.description.clear(),
            5 => n.facts.borrow_mut().identity.description = "a".repeat(257),
            _ => n.facts.borrow_mut().identity.description.push('\0'),
        }
        assert!(p
            .publish(unsafe { b.acknowledge_original(n) }.unwrap())
            .is_err());
        assert!(p.shared.universe.calls.borrow().is_empty());
        assert!(o.observe_all(&context()).is_err());
        assert_eq!(l.drops.get(), 0);
        assert!(p.retire(&s).is_ok());
    }
}
