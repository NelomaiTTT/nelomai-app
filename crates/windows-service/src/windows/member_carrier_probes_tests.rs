use super::*;
use std::{cell::Cell, rc::Rc};

#[test]
fn canonical_slot_projection_preserves_actual_original_even_with_equal_metadata() {
    let mut inventory = Canonical::new();
    let a = Rc::new(19);
    let b = Rc::new(19);
    inventory.begin(Slot::B, b.clone()).unwrap();
    let first = inventory.by_slot();
    assert!(first[0].is_none());
    assert!(Rc::ptr_eq(first[1].unwrap(), &b));
    inventory.begin(Slot::A, a.clone()).unwrap();
    inventory.publish(Slot::B).unwrap();
    let both = inventory.by_slot();
    assert!(Rc::ptr_eq(both[0].unwrap(), &a));
    assert!(Rc::ptr_eq(both[1].unwrap(), &b));
    assert!(!Rc::ptr_eq(both[0].unwrap(), both[1].unwrap()));
}

struct Socket {
    closed: Rc<Cell<usize>>,
    dropped: Rc<Cell<usize>>,
    fail: Rc<Cell<bool>>,
}
impl SocketOwner for Socket {
    fn clone_held(&self) -> Result<Self> {
        Ok(Self {
            closed: self.closed.clone(),
            dropped: self.dropped.clone(),
            fail: self.fail.clone(),
        })
    }
    fn close_checked(&mut self) -> Result<()> {
        if self.fail.get() {
            return Err(GuardError::RemovalUnconfirmed);
        }
        self.closed.set(self.closed.get() + 1);
        Ok(())
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        self.dropped.set(self.dropped.get() + 1);
    }
}
struct Cap(Rc<Cell<usize>>);
impl Drop for Cap {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}
fn held() -> Held<Socket, Cap> {
    Held::new(
        Socket {
            closed: Rc::new(Cell::new(0)),
            dropped: Rc::new(Cell::new(0)),
            fail: Rc::new(Cell::new(false)),
        },
        Cap(Rc::new(Cell::new(0))),
    )
}

#[test]
fn a_live_clone_prevents_last_original_handle_release() {
    let mut h = held();
    let closed = h.socket.as_ref().unwrap().closed.clone();
    let id = h.clone_held().unwrap();
    assert!(matches!(
        h.release_after_withdrawal(),
        Err(GuardError::RemovalUnconfirmed)
    ));
    assert_eq!(closed.get(), 0);
    assert!(h.socket.is_some());
    h.retire_clone(id).unwrap();
    h.release_after_withdrawal().unwrap();
    assert_eq!(closed.get(), 2);
}

#[test]
fn failed_clone_close_remains_owned_until_ack_and_original_stays_held() {
    let mut h = held();
    let fail = h.socket.as_ref().unwrap().fail.clone();
    let closed = h.socket.as_ref().unwrap().closed.clone();
    let dropped = h.socket.as_ref().unwrap().dropped.clone();
    let id = h.clone_held().unwrap();
    fail.set(true);
    assert!(h.retire_clone(id).is_err());
    assert_eq!(closed.get(), 0);
    assert_eq!(dropped.get(), 0);
    assert!(h.release_after_withdrawal().is_err());
    fail.set(false);
    h.retire_orphans_after_withdrawal().unwrap();
    h.release_after_withdrawal().unwrap();
    assert_eq!(closed.get(), 2);
    assert_eq!(dropped.get(), 2);
}

#[test]
fn clone_failure_and_forward_revocation_never_release_original() {
    let mut h = held();
    let dropped = h.socket.as_ref().unwrap().dropped.clone();
    h.revoked = true;
    assert!(h.clone_held().is_err());
    assert!(h.socket.is_some());
    // Factual cleanup can still release an already-revoked owner, after proof.
    h.release_after_withdrawal().unwrap();
    assert_eq!(dropped.get(), 1);
    assert!(h.release_after_withdrawal().is_err());
}

#[test]
fn original_close_failure_retains_original_and_caps_for_cleanup_retry() {
    let mut h = held();
    let fail = h.socket.as_ref().unwrap().fail.clone();
    let closed = h.socket.as_ref().unwrap().closed.clone();
    let caps = h.caps.as_ref().unwrap().0.clone();
    fail.set(true);
    assert!(h.release_after_withdrawal().is_err());
    assert_eq!(closed.get(), 0);
    assert!(h.socket.is_some());
    assert_eq!(caps.get(), 0);
    fail.set(false);
    h.release_after_withdrawal().unwrap();
    assert_eq!(closed.get(), 1);
    drop(h);
    assert_eq!(caps.get(), 1);
}

#[test]
fn ignored_nested_read_cannot_complete_an_already_failed_cleanup_call() {
    let serial = Serial::default();
    serial.failed.set(true);
    let call = serial.call(true).unwrap();
    assert!(serial.call(false).is_err());
    assert!(call.finish().is_err());
}

#[test]
fn unwind_retires_forward_calls_but_factual_cleanup_can_retry() {
    let serial = Serial::default();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _call = serial.call(false).unwrap();
        panic!("test callback unwind");
    }))
    .is_err());
    assert!(serial.call(false).is_err());
    serial.call(true).unwrap().finish().unwrap();
    assert!(serial.call(false).is_err());
}

#[test]
fn failed_orphan_close_on_drop_retains_every_native_handle() {
    let mut h = held();
    let dropped = h.socket.as_ref().unwrap().dropped.clone();
    let caps = h.caps.as_ref().unwrap().0.clone();
    let fail = h.socket.as_ref().unwrap().fail.clone();
    let id = h.clone_held().unwrap();
    fail.set(true);
    assert!(h.retire_clone(id).is_err());
    drop(h);
    assert_eq!(dropped.get(), 0);
    assert_eq!(caps.get(), 0);
}

fn facts() -> Facts {
    use crate::member_owner::InterfaceProof;
    let scope = SessionScope {
        runtime: nelomai_contracts::RuntimeSlot::Stable,
        runtime_generation: 7,
        session_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
        connection_generation: 9,
    };
    let identity = |index| Identity {
        scope: scope.clone(),
        proof: InterfaceProof {
            index,
            luid: index as u64 * 100,
            guid: [index as u8; 16],
        },
    };
    Facts {
        scope: scope.clone(),
        carrier: Some(Carrier {
            identity: identity(33),
            sources: vec!["10.8.0.2".parse().unwrap()],
        }),
        egress: [Some(identity(11)), Some(identity(22))],
    }
}

#[test]
fn joined_tuple_reads_original_socket_only_after_exact_source_and_egress_match() {
    let b = facts();
    let expected = Expected::from_facts(&b, Slot::B, Ipv4Addr::new(9, 9, 9, 9)).unwrap();
    let tuple = ProbeTuple {
        source: expected.source.into(),
        source_port: 49152,
        target: expected.target.into(),
        target_port: 53,
        protocol: 17,
    };
    let reads = Cell::new(0);
    assert_eq!(
        expected
            .read_tuple(&b, &tuple, || {
                reads.set(reads.get() + 1);
                Ok(tuple.clone())
            })
            .unwrap(),
        tuple
    );
    assert_eq!(reads.get(), 1);
    // Exact original source/selected egress comparison is required here; the
    // real NativeBindingsWindow independently brackets ALL sibling SDK facts.
    let mut foreign = b.clone();
    foreign.egress[1].as_mut().unwrap().proof.guid[0] ^= 1;
    assert!(expected
        .read_tuple(&foreign, &tuple, || {
            reads.set(reads.get() + 1);
            Ok(tuple.clone())
        })
        .is_err());
    assert_eq!(reads.get(), 1);
    let mut drift = tuple.clone();
    drift.source_port += 1;
    assert!(expected.read_tuple(&b, &tuple, || Ok(drift)).is_err());
    assert!(expected
        .read_tuple(&b, &tuple, || Err(GuardError::Conflict))
        .is_err());
}

#[test]
fn same_numeric_index_with_different_guid_and_luid_is_never_a_source_egress_pair() {
    let mut b = facts();
    b.egress[0].as_mut().unwrap().proof.index = 33;
    assert!(Expected::from_facts(&b, Slot::A, Ipv4Addr::new(9, 9, 9, 9)).is_err());
}

#[test]
fn unknown_guard_snapshot_version_is_not_allow_absence() {
    use crate::member_carrier_guard::{Member, Model};
    let b = facts();
    let model = Model::new(
        b.scope.clone(),
        b.carrier.clone().unwrap(),
        b.egress.clone().map(|i| {
            i.map(|identity| Member {
                identity,
                probes: vec![],
            })
        }),
        None,
    )
    .unwrap()
    .without_permits()
    .unwrap();
    let mut snapshot = model.expected;
    snapshot.version = 99;
    assert!(snapshot_matches(&b, &snapshot, true).is_err());
}

#[test]
fn actual_source_and_selected_egress_are_distinct_and_rebound_facts_deny() {
    let b = facts();
    let target = Ipv4Addr::new(9, 9, 9, 9);
    let expected = Expected::from_facts(&b, Slot::B, target).unwrap();
    assert_eq!(expected.source, Ipv4Addr::new(10, 8, 0, 2));
    assert_eq!(expected.carrier.identity.proof.index, 33);
    assert_eq!(expected.egress.proof.index, 22);
    for case in 0..14 {
        let mut changed = b.clone();
        match case {
            0 => changed.scope.connection_generation += 1,
            1 => changed.scope.runtime_generation += 1,
            2 => changed.carrier.as_mut().unwrap().identity.proof.guid[0] ^= 1,
            3 => changed.carrier.as_mut().unwrap().identity.proof.luid += 1,
            4 => changed.carrier.as_mut().unwrap().identity.proof.index += 1,
            5 => changed.carrier.as_mut().unwrap().sources = vec!["10.8.0.3".parse().unwrap()],
            6 => changed.egress[1].as_mut().unwrap().proof.guid[0] ^= 1,
            7 => changed.egress[1].as_mut().unwrap().proof.luid += 1,
            8 => changed.egress[1].as_mut().unwrap().proof.index += 1,
            9 => changed.egress[1] = None,
            10 => changed.carrier = None,
            11 => {
                changed.egress[1].as_mut().unwrap().scope.session_id =
                    "ffffffff-ffff-ffff-ffff-ffffffffffff".into()
            }
            12 => changed
                .carrier
                .as_mut()
                .unwrap()
                .sources
                .push("fd00::2".parse().unwrap()),
            13 => changed.egress[0].as_mut().unwrap().proof.index = 22,
            _ => unreachable!(),
        }
        assert!(expected.matches_facts(&changed).is_err(), "case {case}");
    }
    for target in [
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::BROADCAST,
        Ipv4Addr::new(224, 0, 0, 1),
    ] {
        assert!(Expected::from_facts(&b, Slot::A, target).is_err());
    }
}

#[test]
fn attaching_independent_other_member_does_not_recreate_or_rebind_original_probe() {
    let mut before = facts();
    before.egress[1] = None;
    let expected = Expected::from_facts(&before, Slot::A, Ipv4Addr::new(9, 9, 9, 9)).unwrap();
    expected.matches_facts(&facts()).unwrap();
}

#[test]
fn even_an_unrelated_remaining_allow_prevents_exclusive_port_release() {
    use crate::member_carrier_guard::{Member, Model};
    let b = facts();
    let model = Model::new(
        b.scope.clone(),
        b.carrier.clone().unwrap(),
        b.egress.clone().map(|i| {
            i.map(|identity| Member {
                identity,
                probes: vec![],
            })
        }),
        Some(Slot::A),
    )
    .unwrap();
    assert!(snapshot_matches(&b, &model.expected, true).is_err());
    let clean = model.without_permits().unwrap().expected;
    snapshot_matches(&b, &clean, true).unwrap();
    for case in 0..5 {
        let mut snapshot = clean.clone();
        match case {
            0 => snapshot.filters.last_mut().unwrap().action = Action::Permit,
            1 => snapshot.scope.connection_generation += 1,
            2 => snapshot.carrier.as_mut().unwrap().identity.proof.luid += 1,
            3 => snapshot.egress[1].as_mut().unwrap().proof.guid[0] ^= 1,
            4 => snapshot.egress[0] = None,
            _ => unreachable!(),
        }
        assert!(
            snapshot_matches(&b, &snapshot, true).is_err(),
            "case {case}"
        );
    }
}

#[test]
fn a_dropped_lease_can_be_marked_orphan_without_borrowing_the_socket_map() {
    let cell = std::cell::RefCell::new(held());
    let id = cell.borrow_mut().clone_held().unwrap();
    let live = cell.borrow().clones.get(&id).unwrap().live.clone();
    let borrowed = cell.borrow_mut();
    live.set(false);
    assert!(cell.try_borrow_mut().is_err());
    drop(borrowed);
    let mut h = cell.borrow_mut();
    assert!(h.release_after_withdrawal().is_err());
    h.retire_orphans_after_withdrawal().unwrap();
    h.release_after_withdrawal().unwrap();
}

#[test]
fn unchecked_drop_retains_original_socket_and_source_guard_caps() {
    let h = held();
    let dropped = h.socket.as_ref().unwrap().dropped.clone();
    let caps = h.caps.as_ref().unwrap().0.clone();
    drop(h);
    assert_eq!(dropped.get(), 0);
    assert_eq!(caps.get(), 0);
}

#[test]
fn failed_publication_keeps_an_original_cleanup_object_retrievable_without_restart() {
    // Kernel-boundary double only; real Held close/retention policy is exercised.
    let original = Rc::new(std::cell::RefCell::new(held()));
    let weak = Rc::downgrade(&original);
    let closed = original.borrow().socket.as_ref().unwrap().closed.clone();
    let mut inventory = Canonical::new();
    inventory.begin(Slot::A, original.clone()).unwrap();
    let publication: Result<()> = Err(GuardError::Conflict);
    assert!(publication.is_err());
    drop(original); // caller received no owner after the failed postflight.
    let recovered = weak
        .upgrade()
        .expect("original ACK must remain retrievable");
    recovered.borrow_mut().release_after_withdrawal().unwrap();
    assert_eq!(closed.get(), 1);
    assert_eq!(inventory.unpublished().count(), 1);
    assert!(inventory
        .begin(Slot::A, Rc::new(std::cell::RefCell::new(held())))
        .is_err());
}

#[test]
fn canonical_entry_exists_before_ack_and_survives_readback_unwind() {
    let original = Rc::new(std::cell::RefCell::new(Held::<Socket, Cap>::pending()));
    let mut inventory = Canonical::new();
    inventory.begin(Slot::B, original.clone()).unwrap();
    assert!(original.borrow().retired().is_err()); // no ACK != retired original.
    let counters = held();
    let closed = counters.socket.as_ref().unwrap().closed.clone();
    let dropped = counters.socket.as_ref().unwrap().dropped.clone();
    let caps = counters.caps.as_ref().unwrap().0.clone();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        *original.borrow_mut() = counters; // actual ACK retained before readback.
        panic!("fallible socket readback / Source postflight");
    }))
    .is_err());
    drop(original);
    assert_eq!(closed.get(), 0);
    assert_eq!(dropped.get(), 0);
    assert_eq!(caps.get(), 0);
    assert!(inventory
        .begin(Slot::B, Rc::new(std::cell::RefCell::new(held())))
        .is_err());
    let retained = inventory.unpublished().next().unwrap();
    retained.borrow_mut().release_after_withdrawal().unwrap();
    retained.borrow().retired().unwrap();
    assert_eq!(closed.get(), 1);
}

#[test]
fn reserved_pre_ack_failure_and_closed_success_never_allow_a_second_open() {
    let mut inventory = Canonical::new();
    inventory
        .begin(
            Slot::A,
            Rc::new(std::cell::RefCell::new(Held::<Socket, Cap>::pending())),
        )
        .unwrap();
    assert!(inventory
        .begin(Slot::A, Rc::new(std::cell::RefCell::new(held())))
        .is_err());
    let original = Rc::new(std::cell::RefCell::new(held()));
    inventory.begin(Slot::B, original.clone()).unwrap();
    inventory.publish(Slot::B).unwrap();
    original.borrow_mut().release_after_withdrawal().unwrap();
    assert!(inventory
        .begin(Slot::B, Rc::new(std::cell::RefCell::new(held())))
        .is_err());
    assert!(inventory.publish(Slot::B).is_err());
    assert_eq!(inventory.all().count(), 2);
    assert_eq!(inventory.unpublished().count(), 1);
}

#[test]
fn retirement_witness_requires_actual_clone_and_original_close_acks() {
    let mut original = held();
    let id = original.clone_held().unwrap();
    let fail = original.socket.as_ref().unwrap().fail.clone();
    let closed = original.socket.as_ref().unwrap().closed.clone();
    original.revoked = true; // lifecycle/request revocation is NOT a close ACK.
    assert!(original.retired().is_err());
    assert!(original.release_after_withdrawal().is_err());
    assert!(original.retired().is_err());
    original.retire_clone(id).unwrap();
    fail.set(true);
    assert!(original.release_after_withdrawal().is_err());
    assert!(original.retired().is_err());
    assert_eq!(closed.get(), 1); // clone only.
    fail.set(false);
    original.release_after_withdrawal().unwrap();
    original.retired().unwrap();
    assert_eq!(closed.get(), 2);
    assert!(original.clone_held().is_err());
}

#[test]
fn canonical_cleanup_retains_partial_failure_and_published_originals() {
    let first = Rc::new(std::cell::RefCell::new(held()));
    let second = Rc::new(std::cell::RefCell::new(held()));
    let fail = second.borrow().socket.as_ref().unwrap().fail.clone();
    let mut inventory = Canonical::new();
    inventory.begin(Slot::A, first.clone()).unwrap();
    inventory.begin(Slot::B, second.clone()).unwrap();
    inventory.publish(Slot::A).unwrap();
    fail.set(true);
    first.borrow_mut().release_after_withdrawal().unwrap();
    assert!(second.borrow_mut().release_after_withdrawal().is_err());
    drop(first);
    drop(second);
    let originals: Vec<_> = inventory.all().collect();
    originals[0].borrow().retired().unwrap();
    assert!(originals[1].borrow().retired().is_err());
    fail.set(false);
    originals[1]
        .borrow_mut()
        .release_after_withdrawal()
        .unwrap();
    for original in inventory.all() {
        original.borrow().retired().unwrap();
    }
    assert_eq!(inventory.unpublished().count(), 1);
}

#[test]
fn dropping_inventory_does_not_close_unpublished_ack_or_source_caps() {
    let original = Rc::new(std::cell::RefCell::new(held()));
    let dropped = original.borrow().socket.as_ref().unwrap().dropped.clone();
    let caps = original.borrow().caps.as_ref().unwrap().0.clone();
    let mut inventory = Canonical::new();
    inventory.begin(Slot::A, original.clone()).unwrap();
    drop(original);
    drop(inventory);
    assert_eq!(dropped.get(), 0);
    assert_eq!(caps.get(), 0);
}

#[test]
fn new_port_requires_no_any_permits_in_each_independent_open_read() {
    use crate::member_carrier_guard::{Member, Model};
    let b = facts();
    let clean = Model::new(
        b.scope.clone(),
        b.carrier.clone().unwrap(),
        b.egress.clone().map(|i| {
            i.map(|identity| Member {
                identity,
                probes: vec![],
            })
        }),
        None,
    )
    .unwrap()
    .without_permits()
    .unwrap()
    .expected;
    let mut dirty = clean.clone();
    dirty.filters.last_mut().unwrap().action = Action::Permit;
    open_snapshot(&b, &clean).unwrap();
    // Any permit (including unrelated member/tuple) must deny BEFORE or AFTER.
    assert!(open_snapshot(&b, &dirty).is_err());
    open_snapshot(&b, &clean).unwrap();
    assert!(open_snapshot(&b, &dirty).is_err());
}
