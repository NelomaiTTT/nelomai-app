use super::*;

// Break: a failed published-reader read is treated as unpublished, or an
// ambiguous pair of actual close roots is accepted. No facts mint a reader.
#[test]
fn closed_original_selection_has_no_error_fallback() {
    let published = Rc::new(1_u8);
    let unpublished = Rc::new(2_u8);
    match select_closed_original(
        Ok(published.clone()),
        Err::<Rc<u8>, _>(CarrierError::Pending),
    )
    .unwrap()
    {
        ClosedOriginal::Published(p) => assert!(Rc::ptr_eq(&p, &published)),
        _ => panic!("changed original close channel"),
    }
    match select_closed_original(
        Err::<Rc<u8>, _>(CarrierError::Pending),
        Ok(unpublished.clone()),
    )
    .unwrap()
    {
        ClosedOriginal::Unpublished(p) => assert!(Rc::ptr_eq(&p, &unpublished)),
        _ => panic!("changed original close channel"),
    }
    for error in [
        CarrierError::Conflict,
        CarrierError::Retired,
        CarrierError::Native,
        CarrierError::Journal,
    ] {
        assert!(select_closed_original(Err::<Rc<u8>, _>(error), Ok(unpublished.clone())).is_err());
        assert!(select_closed_original(Ok(published.clone()), Err::<Rc<u8>, _>(error)).is_err());
    }
    assert!(select_closed_original(Ok(published), Ok(unpublished)).is_err());
    assert!(select_closed_original(
        Err::<Rc<u8>, _>(CarrierError::Pending),
        Err::<Rc<u8>, _>(CarrierError::Pending)
    )
    .is_err());
}

// Ownership protocol only: production callbacks below are the actual Rows
// stopped-transfer verifier. Any failed boundary keeps ALL originals rooted;
// empty shells may be removed only after the original supplier verifies them.
#[test]
fn stopped_partial_transfer_retains_every_cut_before_postflight() {
    struct Owned(Rc<Cell<usize>>);
    impl Drop for Owned {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    for failure in 0..4 {
        for unwind in [false, true] {
            let drops = Rc::new(Cell::new(0));
            let mut partial = Some(Some(Owned(drops.clone())));
            let mut stopped: Option<Option<Owned>> = None;
            let mut owner = None;
            let result = catch_unwind(AssertUnwindSafe(|| {
                let fault = |stage| -> Result<()> {
                    if failure == stage {
                        if unwind {
                            panic!("original row cut postflight");
                        }
                        return Err(CarrierError::Journal);
                    }
                    Ok(())
                };
                transfer_stopped_capture_into(
                    &mut partial,
                    &mut stopped,
                    &mut owner,
                    |p, s| {
                        *s = Some(p.take());
                        fault(0)
                    },
                    |p, s| {
                        assert!(p.is_none());
                        assert!(s.is_some());
                        fault(1)
                    },
                    |s, o| {
                        *o = s.take();
                        fault(2)
                    },
                    |p, s, _o| {
                        assert!(p.is_none());
                        assert!(s.is_none());
                        fault(3)
                    },
                )
            }));
            if unwind {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap(), Err(CarrierError::Journal));
            }
            assert!(partial.is_some());
            assert!(stopped.is_some());
            assert_eq!(drops.get(), 0);
            assert_eq!(
                usize::from(partial.as_ref().unwrap().is_some())
                    + usize::from(stopped.as_ref().unwrap().is_some())
                    + usize::from(owner.is_some()),
                1
            );
            drop((partial, stopped, owner));
            assert_eq!(drops.get(), 1);
        }
    }
    let drops = Rc::new(Cell::new(0));
    let mut partial = Some(Some(Owned(drops.clone())));
    let mut stopped = None;
    let mut owner = None;
    transfer_stopped_capture_into(
        &mut partial,
        &mut stopped,
        &mut owner,
        |p, s| {
            *s = Some(p.take());
            Ok(())
        },
        |p, s| {
            if p.is_none() && s.is_some() {
                Ok(())
            } else {
                Err(CarrierError::Conflict)
            }
        },
        |s, o| {
            *o = s.take();
            Ok(())
        },
        |p, s, _| {
            if p.is_none() && s.is_none() {
                Ok(())
            } else {
                Err(CarrierError::Conflict)
            }
        },
    )
    .unwrap();
    assert!(partial.is_none());
    assert!(stopped.is_none());
    assert!(owner.is_some());
    assert_eq!(drops.get(), 0);
    assert!(transfer_stopped_capture_into(
        &mut partial,
        &mut stopped,
        &mut owner,
        |_, _| panic!("duplicate cut"),
        |_, _| panic!("duplicate verification"),
        |_, _| panic!("duplicate owner move"),
        |_, _, _| panic!("duplicate postflight")
    )
    .is_err());
    drop(owner);
    assert_eq!(drops.get(), 1);
}
#[cfg(not(windows))]
use crate::member_carrier_coordinator::OriginalReadCapture;
#[cfg(windows)]
use crate::windows::member_carrier_coordinator::OriginalReadCapture;
use std::{
    cell::RefCell,
    panic::{catch_unwind, AssertUnwindSafe},
};

const STEPS: [ReadyStep; 8] = [
    ReadyStep::Construct,
    ReadyStep::Create,
    ReadyStep::Session,
    ReadyStep::CaptureRows,
    ReadyStep::Address,
    ReadyStep::Readiness,
    ReadyStep::Drain,
    ReadyStep::PublishSource,
];

// Break: a completed transfer leaves an unknown-retaining shell, or drops
// the actual owner across a later postflight error/unwind.
#[test]
fn completed_capture_transfer_roots_owner_and_disposes_only_successful_empty_shell() {
    struct Capture(Option<Rc<Cell<usize>>>, Rc<Cell<usize>>);
    impl Drop for Capture {
        fn drop(&mut self) {
            assert!(
                self.0.is_none(),
                "only actual completed transfer can drop shell"
            );
            self.1.set(self.1.get() + 1);
        }
    }
    for unwind in [false, true] {
        let shell_drops = Rc::new(Cell::new(0));
        let original = Rc::new(Cell::new(92));
        let mut capture = Some(Capture(Some(original.clone()), shell_drops.clone()));
        let mut owner = None;
        let result = catch_unwind(AssertUnwindSafe(|| {
            transfer_completed_capture_into(
                &mut capture,
                &mut owner,
                |actual| actual.0.take().ok_or(CarrierError::Pending),
                |actual| {
                    assert!(Rc::ptr_eq(actual, &original));
                    assert_eq!(
                        shell_drops.get(),
                        1,
                        "empty shell dropped before postflight"
                    );
                    if unwind {
                        panic!("post transfer native check");
                    }
                    Err(CarrierError::Conflict)
                },
            )
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(capture.is_none());
        assert!(Rc::ptr_eq(owner.as_ref().unwrap(), &original));
        assert!(transfer_completed_capture_into(
            &mut capture,
            &mut owner,
            |_| panic!("no second owning transfer"),
            |_| Ok(())
        )
        .is_err());
    }
}

#[test]
fn completed_capture_transfer_failure_keeps_original_capture_and_never_posts() {
    for unwind in [false, true] {
        let original = Rc::new(Cell::new(37));
        let mut capture = Some(original.clone());
        let mut owner: Option<Rc<Cell<usize>>> = None;
        let result = catch_unwind(AssertUnwindSafe(|| {
            transfer_completed_capture_into(
                &mut capture,
                &mut owner,
                |_| {
                    if unwind {
                        panic!("capture remains unknown");
                    }
                    Err(CarrierError::Pending)
                },
                |_| panic!("unknown transfer cannot post"),
            )
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(Rc::ptr_eq(capture.as_ref().unwrap(), &original));
        assert!(owner.is_none());
    }
}

// Break: failed capture remains caller-rooted, but cleanup cannot borrow its
// actual original owner; or cleanup takes/drops it across Err/unwind.
#[test]
fn cleanup_borrows_original_partial_capture_without_taking_or_dropping_it() {
    struct Resource {
        identity: u64,
        drops: Rc<Cell<usize>>,
    }
    impl Drop for Resource {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }
    for unwind in [false, true] {
        let drops = Rc::new(Cell::new(0));
        let mut root = None;
        let mut partial = Some(Resource {
            identity: 91,
            drops: drops.clone(),
        });
        let result = catch_unwind(AssertUnwindSafe(|| {
            with_retained_or_partial(&mut root, &mut partial, Ok, |owner| {
                assert_eq!(owner.identity, 91);
                owner.identity = 92;
                if unwind {
                    panic!("partial original cleanup postflight");
                }
                Err::<(), _>(CarrierError::Journal)
            })
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), Err(CarrierError::Journal));
        }
        assert!(root.is_none());
        assert_eq!(partial.as_ref().unwrap().identity, 92);
        assert_eq!(drops.get(), 0);
        drop(partial);
        assert_eq!(drops.get(), 1);
    }
    let mut root = Some(7u64);
    let mut partial = Some(9u64);
    with_retained_or_partial(
        &mut root,
        &mut partial,
        |_| panic!("canonical owner already retained"),
        |owner| {
            assert_eq!(*owner, 7);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!((root, partial), (Some(7), Some(9)));

    let mut root = None::<u64>;
    let mut missing = None::<u64>;
    assert_eq!(
        with_retained_or_partial(&mut root, &mut missing, Ok, |_| {
            panic!("missing original cannot reach cleanup")
        }),
        Err::<(), _>(CarrierError::Pending)
    );
    let mut rejected = Some(9u64);
    assert_eq!(
        with_retained_or_partial(
            &mut root,
            &mut rejected,
            |_| Err(CarrierError::Conflict),
            |_| panic!("failed partial-owner validation cannot reach cleanup"),
        ),
        Err::<(), _>(CarrierError::Conflict)
    );
    assert_eq!((root, rejected), (None, Some(9)));
}

// Break: canonical cleanup is entered before the actual issuer is journal-
// rooted, or error/unwind allows reconciliation to proceed anyway.
#[test]
fn created_cleanup_retains_issuer_before_handoff_and_denies_later_calls_on_failure() {
    for failure in 0..3 {
        for unwind in [false, true] {
            let mut trace = Vec::<u8>::new();
            let result = catch_unwind(AssertUnwindSafe(|| {
                created_cleanup_sequence(
                    &mut trace,
                    |trace| {
                        trace.push(1);
                        if failure == 0 {
                            if unwind {
                                panic!("issuer retention");
                            }
                            return Err(CarrierError::Conflict);
                        }
                        Ok(())
                    },
                    |trace| {
                        trace.push(2);
                        if failure == 1 {
                            if unwind {
                                panic!("cleanup handoff");
                            }
                            return Err(CarrierError::Journal);
                        }
                        Ok(())
                    },
                    |trace| {
                        trace.push(3);
                        if unwind {
                            panic!("sealed receipt reconciliation");
                        }
                        Err(CarrierError::Journal)
                    },
                )
            }));
            if unwind {
                assert!(result.is_err());
            } else {
                assert!(result.unwrap().is_err());
            }
            assert_eq!(trace, [&[1u8][..], &[1, 2][..], &[1, 2, 3][..]][failure]);
        }
    }
}

fn literal_carrier_rows_fixture() -> crate::member_carrier_rows::Record {
    use crate::member_carrier_rows as r;
    let ctx = context();
    let key = r::RowKey { luid: 90, index: 7 };
    let baseline = r::Snapshot {
        interface: r::InterfaceRow {
            key,
            policy: r::InterfacePolicy {
                advertising: false,
                forwarding: false,
                weak_host_send: false,
                weak_host_receive: false,
                automatic_metric: true,
                neighbor_unreachability: true,
                managed_address_configuration: false,
                other_stateful_configuration: false,
                advertise_default_route: false,
                router_discovery: 0,
                dad_transmits: 1,
                base_reachable_time: 30000,
                retransmit_time: 1000,
                path_mtu_discovery_timeout: 0,
                link_local_behavior: 0,
                link_local_timeout: 0,
                zone_indices: [0; 16],
                site_prefix_length: 0,
                metric: 5,
                mtu: 1420,
                disable_default_routes: true,
            },
            observed: r::InterfaceObserved {
                max_reassembly_size: 0,
                interface_identifier: 0,
                min_router_advertisement_interval: 0,
                max_router_advertisement_interval: 0,
                connected: true,
                supports_wake_up_patterns: false,
                supports_neighbor_discovery: true,
                supports_router_discovery: true,
                reachable_time: 30000,
                transmit_offload: 0,
                receive_offload: 0,
            },
        },
        address: None,
    };
    r::Record {
        version: 1,
        domain: "carrier-native-ipv4-rows-v1".into(),
        binding: r::Binding {
            scope: ctx.intent.scope.clone(),
            boot_id: ctx.provenance.boot_id,
            runtime: ctx.provenance.runtime.clone(),
            network_epoch: ctx.provenance.network_epoch,
            role: r::Role::Carrier,
            guid: ctx.bindings[0].guid,
            name: ctx.bindings[0].name.clone(),
            key,
            address: [10, 7, 0, 2],
        },
        revision: 2,
        phase: r::Phase::Captured,
        baseline: baseline.clone(),
        current: baseline.clone(),
        pending: None,
        creation: None,
    }
}

// Missing SDK confirmation is a request for the sealed owner's check, not
// adoption of an SDK ACK from pending metadata. Skipping it strands a genuine
// retained Create receipt; applying it to already-ACKed/foreign rows is wrong.
#[test]
fn special_created_cleanup_is_only_selected_for_original_unconfirmed_create_ack() {
    use crate::member_carrier_rows as r;
    let mut ack = literal_carrier_rows_fixture();
    let key = ack.binding.key;
    let baseline = ack.baseline.clone();
    assert!(!needs_created_cleanup(&ack).unwrap());
    let policy = r::AddressPolicy {
        address: [10, 7, 0, 2],
        prefix_origin: 1,
        suffix_origin: 1,
        valid_lifetime: u32::MAX,
        preferred_lifetime: u32::MAX,
        on_link_prefix_length: 32,
        skip_as_source: false,
    };
    ack.pending = Some(r::Pending {
        before: baseline.clone(),
        target: r::Target::Create(policy.clone()),
    });
    assert!(needs_created_cleanup(&ack).unwrap()); // NEVER an SDK receipt/effect grant
    let mut malformed = ack.clone();
    malformed.domain = "foreign".into();
    assert!(needs_created_cleanup(&malformed).is_err());
    let mut foreign = ack.clone();
    foreign.binding.role = r::Role::MemberA;
    assert!(needs_created_cleanup(&foreign).is_err());
    ack.pending = None;
    let created = r::AddressRow {
        key,
        policy,
        observed: r::AddressObserved {
            dad_state: 4,
            scope_id: 0,
            creation_timestamp: 100,
        },
    };
    ack.current.address = Some(created.clone());
    ack.creation = Some(created);
    assert!(!needs_created_cleanup(&ack).unwrap());
    ack.phase = r::Phase::Stopped;
    ack.current = baseline;
    assert!(!needs_created_cleanup(&ack).unwrap());
}

// Break: a stopped copy, wrong protected payload, wrong birth, role or old NIC
// policy is accepted for source-independent C disposal. Comparison success is
// never an ACK; native use also authenticates the actual row pin + Retired SDK.
#[test]
fn pregraph_stopped_row_comparison_requires_exact_original_ack_and_full_policy() {
    let context = context();
    let proof = crate::member_owner::InterfaceProof {
        guid: context.bindings[0].guid,
        index: 7,
        luid: 90,
    };
    let mut ack = literal_carrier_rows_fixture();
    ack.phase = crate::member_carrier_rows::Phase::Stopped;
    compare_pregraph_stopped_rows(&context, proof, &ack.binding, &ack, &ack).unwrap();
    for fault in 0..9 {
        let mut protected = ack.clone();
        let mut actual_binding = ack.binding.clone();
        let mut original = proof;
        match fault {
            0 => protected.revision += 1,
            1 => actual_binding.role = crate::member_carrier_rows::Role::MemberA,
            2 => actual_binding.network_epoch += 1,
            3 => actual_binding.address = [10, 7, 0, 3],
            4 => protected.phase = crate::member_carrier_rows::Phase::Captured,
            5 => protected.current.interface.policy.weak_host_send = true,
            6 => protected.baseline.interface.policy.forwarding = true,
            7 => original.luid += 1,
            _ => actual_binding.name = "foreign-carrier".into(),
        }
        assert!(
            compare_pregraph_stopped_rows(&context, original, &actual_binding, &ack, &protected)
                .is_err(),
            "fault {fault}"
        );
    }
}

// Break: construction keeps the slot only in a local/returned Result, so a
// failed/unwound capture loses the caller's exact cleanup destination.
#[test]
fn capture_slot_is_rooted_before_capture_error_unwind_and_duplicate_denial() {
    struct Resource(Rc<Cell<usize>>);
    impl Drop for Resource {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    for unwind in [false, true] {
        let drops = Rc::new(Cell::new(0));
        let mut root = None;
        let result = catch_unwind(AssertUnwindSafe(|| {
            capture_in_retained_slot(
                &mut root,
                || Resource(drops.clone()),
                |_| {
                    if unwind {
                        panic!("first capture CAS postflight");
                    }
                    Err(CarrierError::Journal)
                },
            )
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), Err(CarrierError::Journal));
        }
        assert!(root.is_some());
        assert_eq!(drops.get(), 0);
        assert_eq!(
            capture_in_retained_slot(
                &mut root,
                || panic!("duplicate constructor"),
                |_| panic!("duplicate capture")
            ),
            Err(CarrierError::Retired)
        );
        assert_eq!(drops.get(), 0);
        drop(root);
        assert_eq!(drops.get(), 1);
    }
}

// Break: a retained owner's SAME-original validation is bypassed and cleanup
// is called on a missing/equal-looking replacement. This is root ordering,
// not an invented SDK creation receipt or a native effect permission.
#[test]
fn retained_rows_cleanup_requires_original_validation_before_borrowed_call() {
    let mut owner = Some(7u64);
    let mut invoked = false;
    let result = with_retained_owner(
        &mut owner,
        |_| Err(CarrierError::Conflict),
        |_| {
            invoked = true;
            Ok(())
        },
    );
    assert_eq!(result, Err(CarrierError::Conflict));
    assert!(!invoked);
    assert_eq!(owner, Some(7));
    let mut absent = None::<u64>;
    assert_eq!(
        with_retained_owner(
            &mut absent,
            |_| panic!("missing original validated"),
            |_| panic!("missing owner cleanup")
        ),
        Err::<(), _>(CarrierError::Pending)
    );
}

// Break: failure/unwind after the Address boundary drops the rooted original,
// or a cleanup call transfers its only owner through Result. Production uses
// an actual RowOwner/private receipt; this fixture tracks ownership, not ACKs.
#[test]
fn retained_address_failure_and_cleanup_keep_original_until_explicit_root_drop() {
    struct Owned(std::rc::Rc<std::cell::Cell<usize>>);
    impl Drop for Owned {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    for unwind in [false, true] {
        let drops = Rc::new(Cell::new(0));
        let mut root = Some(Owned(drops.clone()));
        let result = catch_unwind(AssertUnwindSafe(|| {
            with_retained_owner(
                &mut root,
                |_| Ok(()),
                |_| {
                    if unwind {
                        panic!("durable confirmation postflight");
                    }
                    Err::<(), _>(CarrierError::Journal)
                },
            )
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), Err(CarrierError::Journal));
        }
        assert_eq!(drops.get(), 0);
        assert!(root.is_some());
        with_retained_owner(&mut root, |_| Ok(()), |_| Ok(())).unwrap();
        assert_eq!(drops.get(), 0);
        assert!(catch_unwind(AssertUnwindSafe(|| with_retained_owner(
            &mut root,
            |_| panic!("private original validation postflight"),
            |_| -> Result<()> { panic!("validation unwind cannot enter owner call") },
        )))
        .is_err());
        assert!(root.is_some());
        assert_eq!(drops.get(), 0);
        drop(root);
        assert_eq!(drops.get(), 1);
    }
}

#[test]
fn carrier_root_retains_actual_capture_original_before_postflight_error_or_unwind() {
    for unwind in [false, true] {
        let actual = Rc::new(());
        let mut root = None;
        let result = catch_unwind(AssertUnwindSafe(|| {
            retain_before_postflight(&mut root, actual.clone(), |retained| {
                assert!(Rc::ptr_eq(retained, &actual));
                if unwind {
                    panic!("capture return postflight unwound");
                }
                Err(CarrierError::Native)
            })
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), Err(CarrierError::Native));
        }
        assert!(Rc::ptr_eq(root.as_ref().unwrap(), &actual));
    }
}

#[test]
fn carrier_root_retained_row_ack_cannot_be_replaced_by_equal_looking_original() {
    let actual = Rc::new(7u64);
    let foreign = Rc::new(7u64);
    let mut root = None;
    retain_before_postflight(&mut root, actual.clone(), |_| Ok(())).unwrap();
    assert!(retain_before_postflight(&mut root, foreign.clone(), |_| Ok(())).is_err());
    assert!(Rc::ptr_eq(root.as_ref().unwrap(), &actual));
    assert!(!Rc::ptr_eq(root.as_ref().unwrap(), &foreign));
}

#[test]
fn closing_capture_roots_original_before_native_postflight_error_or_unwind() {
    for unwind in [false, true] {
        let original = Rc::new(());
        let signal = Rc::new(Cell::new(false));
        let root = OriginalReadCapture::new(signal.clone());
        let mut actual_gate_weak = None;
        let mut attempted = false;
        let result = catch_unwind(AssertUnwindSafe(|| {
            begin_original_capture(&mut attempted)?;
            // The native constructor is the unexecuted external boundary.
            // Its callback exercises the REAL Root capture/weak handoff code;
            // importantly postflight occurs AFTER the callback, not return.
            root.capture(original.clone(), |pin| {
                assert!(Rc::ptr_eq(&root.pin()?, &original));
                actual_gate_weak = Some(Rc::downgrade(pin));
                Ok(())
            })?;
            assert!(Rc::ptr_eq(
                &actual_gate_weak.as_ref().unwrap().upgrade().unwrap(),
                &original
            ));
            if unwind {
                panic!("native Closing constructor postflight unwound");
            }
            Err::<(), _>(CarrierError::Native)
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), Err(CarrierError::Native));
        }
        assert!(attempted);
        assert!(
            begin_original_capture(&mut attempted).is_err(),
            "no second capture or registration"
        );
        assert!(Rc::ptr_eq(&root.pin().unwrap(), &original));
        root.confirm(&original).unwrap();
        assert!(signal.get(), "receipt facts do not revive forward");
    }
}

#[test]
fn closing_capture_missing_callback_never_invents_pin_or_retries_constructor() {
    let root = OriginalReadCapture::<()>::new(Rc::new(Cell::new(false)));
    let mut attempted = false;
    let result = (|| {
        begin_original_capture(&mut attempted)?;
        // Actual runtime/constructor failed BEFORE it issued an opaque pin.
        Err::<(), _>(CarrierError::Native)
    })();
    assert_eq!(result, Err(CarrierError::Native));
    assert!(root.pin().is_err());
    assert!(root.require_registered().is_err());
    assert!(begin_original_capture(&mut attempted).is_err());
    assert!(
        root.pin().is_err(),
        "metadata alone cannot synthesize Closing"
    );
}

fn full_cleanup_fixture() -> (
    crate::member_carrier_native_ownership::Context,
    crate::member_carrier_pair::Record,
    crate::member_owner::InterfaceProof,
) {
    use crate::{
        member_carrier_guard as g, member_carrier_pair as p, member_owner::InterfaceProof,
    };
    let context = context();
    let proof = InterfaceProof {
        index: 7,
        luid: 90,
        guid: [1; 16],
    };
    let guard = g::Model::new(
        context.intent.scope.clone(),
        g::Carrier {
            identity: g::Identity {
                scope: context.intent.scope.clone(),
                proof,
            },
            sources: vec!["10.7.0.2".parse().unwrap()],
        },
        [
            Some(g::Member {
                identity: g::Identity {
                    scope: context.intent.scope.clone(),
                    proof: InterfaceProof {
                        index: 8,
                        luid: 91,
                        guid: [2; 16],
                    },
                },
                probes: vec![],
            }),
            None,
        ],
        None,
    )
    .unwrap()
    .without_permits()
    .unwrap();
    let member = p::MemberState {
        owner: crate::member_owner::Record {
            intent: crate::member_owner::Intent {
                scope: context.intent.scope.clone(),
                slot: nelomai_contracts::dispatcher::TunnelSlot::A,
                transport: nelomai_client_tunnel::TunnelTransport::WireGuard,
                engine: crate::test_engine_path("engine.exe"),
                config_sha256: [4; 32],
            },
            phase: crate::member_owner::Phase::Stopping,
            proof: Some(crate::member_owner::NativeProof {
                process: crate::member_owner::ProcessProof {
                    pid: 40,
                    creation_time: 50,
                },
                interface: guard.members[0].as_ref().unwrap().identity.proof,
            }),
            retired_proof: None,
            previous_config_sha256: None,
        },
        lease_id: "22222222-2222-4222-8222-222222222222".into(),
        probe: nelomai_contracts::RedundantHealthProbe {
            kind: nelomai_contracts::HealthProbeKind::DnsA,
            target_ipv4: "1.1.1.1".parse().unwrap(),
            query_name: "example.com".into(),
            timeout_ms: 2000,
        },
        endpoint: "192.0.2.1".parse().unwrap(),
        allowed: vec!["0.0.0.0/0".parse().unwrap()],
        peer: [5; 32],
    };
    let pair = p::Record {
        version: 2,
        scope: context.intent.scope.clone(),
        provenance: context.provenance.clone(),
        revision: 20,
        phase: p::Phase::Closing,
        addresses: context.intent.addresses.clone(),
        dns: vec![],
        carrier: Some(proof),
        members: [Some(member), None],
        active: None,
        options: Some(nelomai_client_tunnel::DesktopTunnelOptions::default()),
        guard,
        pending_guard: None,
        pending: Some(p::Effect::CarrierAddressDelete),
        network: Some(p::NetworkState {
            baseline: p::NetworkSnapshot {
                routes: vec![],
                dns: None,
            },
            current: p::NetworkSnapshot {
                routes: vec![],
                dns: None,
            },
            pending: None,
        }),
        stop_stage: 6,
        operation: None,
    };
    (context, pair, proof)
}

#[test]
fn full_carrier_stop_keeps_base_model_for_mandatory_gate_and_requires_current_stage() {
    use crate::member_carrier_pair as p;
    let (context, mut pair, proof) = full_cleanup_fixture();
    for (stage, effect, boundary) in [
        (6, p::Effect::CarrierAddressDelete, StopStep::Address),
        (7, p::Effect::CarrierSessionEnd, StopStep::Session),
        (8, p::Effect::CarrierClose, StopStep::Handle),
    ] {
        pair.stop_stage = stage;
        pair.pending = Some(effect);
        pair.validate().unwrap();
        assert_eq!(
            full_stop_boundary(&context, &pair, Some(proof)).unwrap(),
            boundary
        );
        assert!(
            stop_boundary(&context, &pair, Some(proof)).is_err(),
            "narrow bootstrap cannot authorize full base model"
        );
        let mut stale = pair.clone();
        stale.stop_stage += 1;
        assert!(full_stop_boundary(&context, &stale, Some(proof)).is_err());
    }
    assert!(full_stop_boundary(&context, &pair, None).is_err());
    let mut foreign = proof;
    foreign.luid += 1;
    assert!(full_stop_boundary(&context, &pair, Some(foreign)).is_err());
}

// Break: a known original C closed before CarrierReady publication is refused
// solely because Pair.C is absent, or that exception spreads to foreign/live
// frames. Pure facts only: the native consumer also requires SAME CloseACK.
#[test]
fn prepublication_terminal_frame_keeps_original_c_without_pair_adoption() {
    use crate::{member_carrier_guard as g, member_carrier_pair as p};
    let (context, mut record, proof) = full_cleanup_fixture();
    record.carrier = None;
    record.members = [None, None];
    record.network = None;
    record.guard = g::Model::empty(record.scope.clone()).unwrap();
    record.stop_stage = 12;
    record.pending = Some(p::Effect::FullEmpty);
    record.validate().unwrap();
    compare_prepublication_terminal_frame(&context, &record, proof).unwrap();
    for fault in 0..8 {
        let mut wrong = record.clone();
        let mut original = proof;
        match fault {
            0 => wrong.phase = p::Phase::Stopped,
            1 => wrong.pending = Some(p::Effect::Guard),
            2 => wrong.stop_stage = 9,
            3 => wrong.addresses.clear(),
            4 => wrong.provenance.network_epoch += 1,
            5 => original.index = 0,
            6 => original.guid = [8; 16],
            _ => wrong.carrier = Some(crate::member_owner::InterfaceProof { luid: 91, ..proof }),
        }
        assert!(
            compare_prepublication_terminal_frame(&context, &wrong, original).is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn raw_unpublished_terminal_frame_never_acquires_a_carrier_identity() {
    use crate::member_carrier_pair as p;
    let (context, mut record, proof) = full_cleanup_fixture();
    record.stop_stage = 12;
    record.pending = Some(p::Effect::FullEmpty);
    record.guard = crate::member_carrier_guard::Model::empty(record.scope.clone()).unwrap();
    record.network = None;
    record.members = [None, None];
    record.carrier = None;
    compare_prepublication_terminal_origin(&context, &record, None).unwrap();
    record.carrier = Some(proof);
    assert!(compare_prepublication_terminal_origin(&context, &record, None).is_err());
    // Published identity is still legal ONLY in its separate original channel.
    compare_prepublication_terminal_origin(&context, &record, Some(proof)).unwrap();
}

// Closing9/10 must inspect an actually closed pregraph C without requiring
// Closing12 key restoration. These comparison facts grant no native authority.
#[test]
fn pregraph_native_empty_is_disjoint_from_terminal_key_restoration() {
    use crate::{member_carrier_guard as g, member_carrier_pair as p};
    let (context, mut record, proof) = full_cleanup_fixture();
    record.carrier = None;
    record.members = [None, None];
    record.network = None;
    record.guard = g::Model::empty(record.scope.clone()).unwrap();
    for (stage, effect) in [(9, p::Effect::NativeEmpty), (10, p::Effect::Guard)] {
        record.stop_stage = stage;
        record.pending = Some(effect);
        compare_pregraph_native_empty_frame(&context, &record, proof).unwrap();
        assert!(compare_prepublication_terminal_frame(&context, &record, proof).is_err());
        for fault in 0..7 {
            let mut bad = record.clone();
            let mut original = proof;
            match fault {
                0 => bad.pending = Some(p::Effect::FullEmpty),
                1 => bad.stop_stage = 12,
                2 => bad.phase = p::Phase::Stopped,
                3 => bad.addresses.clear(),
                4 => original.luid = 0,
                5 => original.guid = [8; 16],
                _ => bad.carrier = Some(crate::member_owner::InterfaceProof { index: 99, ..proof }),
            }
            assert!(compare_pregraph_native_empty_frame(&context, &bad, original).is_err());
        }
    }
    record.stop_stage = 12;
    record.pending = Some(p::Effect::FullEmpty);
    assert!(compare_pregraph_native_empty_frame(&context, &record, proof).is_err());
    compare_prepublication_terminal_frame(&context, &record, proof).unwrap();
}

// Break: early original C cleanup is routed through a later NativeEmpty or
// terminal-key channel. The actual native caller must STILL supply the SAME
// original C/rows/Calling/full SDK bracket; these are comparison facts only.
#[test]
fn pregraph_closing_facts_have_exact_early_frames_not_terminal_permissions() {
    use crate::{member_carrier_guard as g, member_carrier_pair as p};
    use nelomai_client_tunnel::redundancy::Slot;
    let (context, mut record, proof) = full_cleanup_fixture();
    record.members = [None, None];
    record.network = None;
    record.guard = g::Model::empty(record.scope.clone()).unwrap();
    for (stage, effect) in [
        (0, p::Effect::Guard),
        (1, p::Effect::ReleaseProbes),
        (2, p::Effect::RestoreNetwork),
        (3, p::Effect::RestoreWeak),
        (4, p::Effect::MemberStop(Slot::A)),
        (5, p::Effect::MemberStop(Slot::B)),
        (6, p::Effect::CarrierAddressDelete),
        (7, p::Effect::CarrierSessionEnd),
        (8, p::Effect::CarrierClose),
    ] {
        record.stop_stage = stage;
        record.pending = Some(effect);
        compare_pregraph_closing_frame(&context, &record, proof).unwrap();
        assert!(compare_pregraph_native_empty_frame(&context, &record, proof).is_err());
        for fault in 0..9 {
            let mut wrong = record.clone();
            let mut original = proof;
            match fault {
                0 => wrong.pending = None,
                1 => wrong.pending = Some(p::Effect::FullEmpty),
                2 => wrong.carrier = None,
                3 => original.luid += 1,
                4 => wrong.provenance.network_epoch += 1,
                5 => wrong.phase = p::Phase::Stopped,
                6 => wrong.addresses.clear(),
                7 => wrong.options = None,
                _ => wrong.active = Some(Slot::A),
            }
            assert!(compare_pregraph_closing_frame(&context, &wrong, original).is_err());
        }
    }
    for (stage, effect) in [
        (9, p::Effect::NativeEmpty),
        (10, p::Effect::Guard),
        (11, p::Effect::RestoreKeys),
        (12, p::Effect::FullEmpty),
    ] {
        record.stop_stage = stage;
        record.pending = Some(effect);
        assert!(compare_pregraph_closing_frame(&context, &record, proof).is_err());
    }
}

#[test]
fn pregraph_key_restore_read_uses_actual_stage11_not_projected_full_empty() {
    use crate::{member_carrier_guard as g, member_carrier_pair as p};
    let (context, mut record, proof) = full_cleanup_fixture();
    record.members = [None, None];
    record.network = None;
    record.guard = g::Model::empty(record.scope.clone()).unwrap();
    record.stop_stage = 11;
    record.pending = Some(p::Effect::RestoreKeys);
    compare_pregraph_key_restore_frame(&context, &record, proof).unwrap();
    for fault in 0..9 {
        let mut wrong = record.clone();
        let mut origin = proof;
        match fault {
            0 => wrong.pending = None,
            1 => wrong.pending = Some(p::Effect::FullEmpty),
            2 => wrong.stop_stage = 12,
            3 => wrong.stop_stage = 10,
            4 => wrong.carrier = None,
            5 => wrong.phase = p::Phase::Stopped,
            6 => origin.luid += 1,
            7 => wrong.options = None,
            _ => wrong.provenance.network_epoch += 1,
        }
        assert!(compare_pregraph_key_restore_frame(&context, &wrong, origin).is_err());
    }
}

// Actual Pair.begin and Pair.finish BOTH call attest_effect at Closing11.
// Terminal-only selection rejects the pre-effect Disabled original keys.
#[test]
fn key_restore_attestation_selects_before_and_after_actual_native_receipt() {
    use crate::{member_carrier_native_ownership as n, member_carrier_pair as p};
    let (context, mut record, _) = full_cleanup_fixture();
    record.stop_stage = 11;
    record.pending = Some(p::Effect::RestoreKeys);
    record.guard = crate::member_carrier_guard::Model::empty(record.scope.clone()).unwrap();
    let mut native = n::Record {
        version: 2,
        context: context.clone(),
        generation: 7,
        phase: n::Phase::Closing,
        native_rows: n::FullNativeRows::Unbound,
        keys: std::array::from_fn(|i| n::KeyReceipt {
            role: context.bindings[i].role,
            phase: n::KeyPhase::Disabled,
            new_key_ack: true,
            baseline: n::Value::Absent,
            current: n::Value::DwordZero,
            pending: None,
        }),
    };
    assert!(!key_restore_read_is_terminal(&context, &record, &native).unwrap());
    native.phase = n::Phase::Stopped;
    for key in &mut native.keys {
        key.phase = n::KeyPhase::Clean;
        key.current = n::Value::Absent;
    }
    assert!(key_restore_read_is_terminal(&context, &record, &native).unwrap());
    for fault in 0..10 {
        let mut wrong = record.clone();
        let mut observed = native.clone();
        match fault {
            0 => wrong.stop_stage = 12,
            1 => wrong.pending = None,
            2 => wrong.pending = Some(p::Effect::FullEmpty),
            3 => wrong.phase = p::Phase::Stopped,
            4 => wrong.carrier = None,
            5 => observed.context.provenance.network_epoch += 1,
            6 => observed.phase = n::Phase::Preparing,
            7 => observed.keys[1].phase = n::KeyPhase::Captured,
            8 => observed.generation = 0,
            _ => {
                observed.phase = n::Phase::Closing;
                observed.keys[0].phase = n::KeyPhase::Clean;
            }
        }
        assert!(
            key_restore_read_is_terminal(&context, &wrong, &observed).is_err(),
            "fault {fault}"
        );
    }
}

// Break: genuine Stopped is routed as Closing12, or a stopped row/frame grants
// permission without its original SDK reader. This is a strict comparison only.
#[test]
fn pregraph_stopped_frame_is_not_a_closing_projection() {
    use crate::{member_carrier_guard as g, member_carrier_pair as p};
    let (context, mut stopped, proof) = full_cleanup_fixture();
    stopped.phase = p::Phase::Stopped;
    stopped.stop_stage = 12;
    stopped.pending = None;
    stopped.carrier = None;
    stopped.members = [None, None];
    stopped.network = None;
    stopped.guard = g::Model::empty(stopped.scope.clone()).unwrap();
    compare_pregraph_stopped_frame(&context, &stopped, proof).unwrap();
    assert!(compare_prepublication_terminal_frame(&context, &stopped, proof).is_err());
    for fault in 0..7 {
        let mut wrong = stopped.clone();
        let mut original = proof;
        match fault {
            0 => {
                wrong.phase = p::Phase::Closing;
                wrong.pending = Some(p::Effect::FullEmpty);
            }
            1 => wrong.stop_stage = 9,
            2 => wrong.addresses.clear(),
            3 => wrong.carrier = Some(proof),
            4 => wrong.provenance.network_epoch += 1,
            5 => original.guid = [9; 16],
            _ => original.luid = 0,
        }
        assert!(
            compare_pregraph_stopped_frame(&context, &wrong, original).is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn full_carrier_stage3_restore_is_interface_only_before_member_stop() {
    use crate::{member_carrier_pair as p, member_owner as o};
    let (context, mut pair, proof) = full_cleanup_fixture();
    pair.stop_stage = 3;
    pair.pending = Some(p::Effect::RestoreWeak);
    pair.members[0].as_mut().unwrap().owner.phase = o::Phase::Running;
    pair.validate().unwrap();
    full_interface_cleanup_boundary(&context, &pair, Some(proof)).unwrap();
    assert!(full_stop_boundary(&context, &pair, Some(proof)).is_err());
    for fault in 0..9 {
        let mut wrong = pair.clone();
        let mut original = Some(proof);
        match fault {
            0 => wrong.stop_stage = 6,
            1 => wrong.pending = Some(p::Effect::CarrierAddressDelete),
            2 => wrong.scope.connection_generation += 1,
            3 => wrong.provenance.boot_id = [9; 16],
            4 => wrong.addresses = vec!["10.7.0.3/32".parse().unwrap()],
            5 => original.as_mut().unwrap().luid += 1,
            6 => original = None,
            7 => wrong.carrier = None,
            _ => {
                wrong.network.as_mut().unwrap().pending = Some(p::NetworkSnapshot {
                    routes: vec![],
                    dns: None,
                })
            }
        }
        assert!(
            full_interface_cleanup_boundary(&context, &wrong, original).is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn original_pins_are_not_published_before_whole_call_ack_or_after_revocation() {
    let run = ReadyRun::new();
    assert!(run.published(true).is_err());
    let mut calls = 0;
    run.execute_in(
        &mut |call| {
            calls += 1;
            call()
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(calls, STEPS.len());
    assert!(run.published(false).is_err());
    run.published(true).unwrap();
    assert!(run.execute(|_| Ok(())).is_err());
    assert!(run.published(true).is_err());
    let failed = ReadyRun::new();
    assert!(failed.execute(|_| Err(CarrierError::Native)).is_err());
    assert!(failed.published(true).is_err());
}

// Break: cold original C Closing3 is rejected because Source/full G was never
// published, or the interface-only intent is accepted with another effect.
// Actual owner/NEW cleanup ACK/SDK proof remain mandatory at the native call.
#[test]
fn cold_carrier_interface_restore_uses_exact_current_stage_without_source_adoption() {
    use crate::{member_carrier_guard as g, member_carrier_pair as p};
    let (context, mut pair, proof) = full_cleanup_fixture();
    pair.guard = g::Model::empty(pair.scope.clone()).unwrap();
    pair.members = [None, None];
    pair.network = None;
    pair.carrier = None; // known C exists, Ready publication did not complete
    pair.stop_stage = 3;
    pair.pending = Some(p::Effect::RestoreWeak);
    assert_eq!(
        stop_boundary(&context, &pair, Some(proof)),
        Ok(StopStep::Interface)
    );
    for fault in 0..6 {
        let mut wrong = pair.clone();
        let mut original = Some(proof);
        match fault {
            0 => wrong.pending = None,
            1 => wrong.pending = Some(p::Effect::CarrierAddressDelete),
            2 => wrong.stop_stage = 4,
            3 => wrong.provenance.boot_id[0] ^= 1,
            4 => original = None,
            5 => wrong.carrier = Some(crate::member_owner::InterfaceProof { luid: 91, ..proof }),
            _ => unreachable!(),
        }
        assert!(
            stop_boundary(&context, &wrong, original).is_err(),
            "fault {fault}"
        );
    }
}

fn context() -> crate::member_carrier_native_ownership::Context {
    use crate::member_carrier::{Intent, Provenance};
    use crate::member_carrier_native_ownership::{Binding, Context, Role};
    use nelomai_client_tunnel::redundancy::SessionScope;
    use nelomai_contracts::{dispatcher::EngineIdentity, RuntimeSlot};
    Context {
        intent: Intent {
            scope: SessionScope {
                runtime: RuntimeSlot::Stable,
                runtime_generation: 2,
                session_id: "11111111-1111-4111-8111-111111111111".into(),
                connection_generation: 3,
            },
            addresses: vec!["10.7.0.2/32".parse().unwrap()],
        },
        provenance: Provenance {
            boot_id: [8; 16],
            network_epoch: 7,
            runtime: EngineIdentity {
                slot: RuntimeSlot::Stable,
                runtime_version: "0.3.3".into(),
                container_version: "0.3.3".into(),
                runtime_contract_version: 1,
                manifest_sha256: "a".repeat(64),
            },
        },
        bindings: std::array::from_fn(|i| {
            let b = (i + 1) as u8;
            Binding {
                role: [Role::RoleCarrier, Role::MemberA, Role::MemberB][i],
                guid: [b; 16],
                name: ["carrier-c", "member-a", "member-b"][i].into(),
                registry_path: format!(
                    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{{b:02X}{b:02X}{b:02X}{b:02X}-{b:02X}{b:02X}-{b:02X}{b:02X}-{b:02X}{b:02X}-{b:02X}{b:02X}{b:02X}{b:02X}{b:02X}{b:02X}}}"
                ),
            }
        }),
    }
}

#[test]
fn creation_policy_uses_only_the_validated_single_ipv4_host_address() {
    let mut context = context();
    let policy = creation_policy(&context).unwrap();
    assert_eq!(policy.address, [10, 7, 0, 2]);
    assert_eq!((policy.prefix_origin, policy.suffix_origin), (1, 1));
    assert_eq!(
        (policy.valid_lifetime, policy.preferred_lifetime),
        (u32::MAX, u32::MAX)
    );
    assert_eq!(policy.on_link_prefix_length, 32);
    assert!(!policy.skip_as_source);
    for address in ["10.7.0.2/24", "::1/128", "0.0.0.0/32", "127.0.0.1/32"] {
        context.intent.addresses = vec![address.parse().unwrap()];
        assert!(creation_policy(&context).is_err(), "{address}");
    }
    context.intent.addresses = vec![
        "10.7.0.2/32".parse().unwrap(),
        "10.7.0.3/32".parse().unwrap(),
    ];
    assert!(creation_policy(&context).is_err());
}

#[test]
fn source_publication_is_last_after_all_native_creation_and_ready_boundaries() {
    let run = ReadyRun::new();
    let mut seen = vec![];
    run.execute(|step| {
        seen.push(step);
        Ok(())
    })
    .unwrap();
    assert_eq!(seen, STEPS);
    assert!(!run.revoked.get());
    let mut repeated = false;
    assert!(run
        .execute(|_| {
            repeated = true;
            Ok(())
        })
        .is_err());
    assert!(!repeated);
    assert!(run.revoked.get());
}

#[test]
fn c_stop_boundaries_are_separate_current_effects_and_cannot_authorize_end_from_close() {
    use crate::{
        member_carrier_guard as g, member_carrier_pair as p, member_owner::InterfaceProof,
    };
    let context = context();
    let proof = InterfaceProof {
        index: 7,
        luid: 90,
        guid: [1; 16],
    };
    let mut pair = p::Record {
        version: 2,
        scope: context.intent.scope.clone(),
        provenance: context.provenance.clone(),
        revision: 20,
        phase: p::Phase::Closing,
        addresses: context.intent.addresses.clone(),
        dns: vec![],
        carrier: Some(proof),
        members: [None, None],
        active: None,
        options: Some(nelomai_client_tunnel::DesktopTunnelOptions::default()),
        guard: g::Model::empty(context.intent.scope.clone()).unwrap(),
        pending_guard: None,
        pending: Some(p::Effect::CarrierAddressDelete),
        network: None,
        stop_stage: 6,
        operation: None,
    };
    for (stage, effect, expected) in [
        (6, p::Effect::CarrierAddressDelete, StopStep::Address),
        (7, p::Effect::CarrierSessionEnd, StopStep::Session),
        (8, p::Effect::CarrierClose, StopStep::Handle),
    ] {
        pair.stop_stage = stage;
        pair.pending = Some(effect);
        pair.validate().unwrap();
        assert_eq!(
            stop_boundary(&context, &pair, Some(proof)).unwrap(),
            expected
        );
        for wrong in [
            p::Effect::CarrierAddressDelete,
            p::Effect::CarrierSessionEnd,
            p::Effect::CarrierClose,
        ] {
            if wrong != effect {
                let mut changed = pair.clone();
                changed.pending = Some(wrong);
                assert!(stop_boundary(&context, &changed, Some(proof)).is_err());
            }
        }
    }
    for fault in 0..9 {
        let mut changed = pair.clone();
        let mut original = proof;
        match fault {
            0 => changed.provenance.network_epoch += 1,
            1 => changed.scope.connection_generation += 1,
            2 => changed.addresses = vec!["10.7.0.3/32".parse().unwrap()],
            3 => changed.phase = p::Phase::Starting,
            4 => {
                changed.operation = Some(p::Operation::Start(
                    nelomai_client_tunnel::redundancy::Slot::A,
                ))
            }
            5 => changed.active = Some(nelomai_client_tunnel::redundancy::Slot::A),
            6 => original.luid += 1,
            7 => changed.stop_stage = 9,
            8 => original.guid = [9; 16],
            _ => unreachable!(),
        }
        assert!(
            stop_boundary(&context, &changed, Some(original)).is_err(),
            "{fault}"
        );
    }
    // Partial CarrierReady may have created C before publication to Pair. This
    // comparison is allowed ONLY with the independently retained actual owner;
    // the native gate still requires that opaque original and full SDK checks.
    pair.carrier = None;
    assert_eq!(
        stop_boundary(&context, &pair, Some(proof)).unwrap(),
        StopStep::Handle
    );
    assert!(stop_boundary(&context, &pair, None).is_err());
}

#[test]
fn every_failed_native_boundary_prevents_later_effects_and_new_attempt() {
    for failed in 1..=STEPS.len() {
        for unwind in [false, true] {
            let run = ReadyRun::new();
            let mut calls = 0;
            let mut seen = vec![];
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run.execute_in(
                    &mut |call| {
                        calls += 1;
                        call()?;
                        if calls == failed {
                            if unwind {
                                panic!("original C native postflight");
                            }
                            return Err(CarrierError::Pending);
                        }
                        Ok(())
                    },
                    |step| {
                        seen.push(step);
                        Ok(())
                    },
                )
            }));
            assert!(result.is_err() || result.unwrap().is_err());
            assert_eq!(seen, STEPS[..failed]);
            assert!(run.revoked.get());
            assert!(run.published(true).is_err());
            assert!(run.execute(|_| panic!("C retry after postflight")).is_err());
        }
    }
    for failed in 0..STEPS.len() {
        let run = ReadyRun::new();
        let mut seen = vec![];
        assert!(run
            .execute(|step| {
                seen.push(step);
                if step == STEPS[failed] {
                    Err(CarrierError::Native)
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert_eq!(seen, STEPS[..=failed]);
        assert!(run.revoked.get());
        let mut repeated = false;
        assert!(run
            .execute(|_| {
                repeated = true;
                Ok(())
            })
            .is_err());
        assert!(!repeated);
    }
}

#[test]
fn caught_reentry_cannot_publish_a_source_from_the_outer_attempt() {
    let run = ReadyRun::new();
    let seen = RefCell::new(vec![]);
    assert!(run
        .execute(|step| {
            seen.borrow_mut().push(step);
            if step == ReadyStep::Create {
                assert!(run.execute(|_| Ok(())).is_err());
            }
            Ok(())
        })
        .is_err());
    assert_eq!(*seen.borrow(), [ReadyStep::Construct, ReadyStep::Create]);
    assert!(run.revoked.get());
}

#[test]
fn unwind_retains_the_callers_partial_objects_and_irreversibly_retires_run() {
    let run = ReadyRun::new();
    let retained = RefCell::new(vec![]);
    assert!(catch_unwind(AssertUnwindSafe(|| run.execute(|step| {
        retained.borrow_mut().push(step);
        if step == ReadyStep::Address {
            panic!("native postflight");
        }
        Ok(())
    })))
    .is_err());
    assert_eq!(*retained.borrow(), STEPS[..=4]);
    assert!(run.revoked.get());
    assert!(run.execute(|_| Ok(())).is_err());
}
