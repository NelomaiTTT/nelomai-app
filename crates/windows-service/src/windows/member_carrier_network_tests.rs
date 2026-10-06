use super::*;
use crate::{member_carrier_guard::Identity, member_owner::InterfaceProof};
use nelomai_client_tunnel::redundancy::SessionScope;
use nelomai_contracts::RuntimeSlot;

#[test]
fn full_empty_record_join_preserves_original_history_and_brackets_exact_bytes() {
    // Break: reset the live reader's history, or move private IO outside the
    // terminal lease. These are pure IO boundaries, not fake native grants.
    let original = std::rc::Rc::new(NetworkRecordHistory::default());
    original
        .inspect(|| Ok(Some(vec![7, 9])), |_| Ok(()))
        .unwrap();
    let terminal = original.clone();
    let order = std::cell::RefCell::new(Vec::new());
    let facts = terminal
        .inspect_terminal_record(
            || {
                order.borrow_mut().push("terminal");
                Ok(())
            },
            || {
                order.borrow_mut().push("private");
                Ok(Some(vec![7, 9]))
            },
            |bytes| {
                order.borrow_mut().push("inspect");
                Ok(bytes)
            },
        )
        .unwrap();
    assert_eq!(facts, Some(vec![7, 9]));
    assert_eq!(
        *order.borrow(),
        ["terminal", "private", "inspect", "private", "terminal"]
    );
    assert!(terminal
        .inspect_terminal_record(
            || Ok(()),
            || Ok(None),
            |_| -> io::Result<()> { panic!("original observed record cannot become absent") },
        )
        .is_err());
}

#[test]
fn full_empty_record_join_requires_terminal_preflight_and_postflight_even_on_error() {
    // Break: skip either terminal lease check or skip postflight on callbackErr.
    let history = NetworkRecordHistory::default();
    let denied = history.inspect_terminal_record(
        || Err(io::Error::other("not_terminal")),
        || panic!("no private IO before the actual terminal lease"),
        |_| Ok(()),
    );
    assert_eq!(denied.unwrap_err().to_string(), "not_terminal");

    for callback_fails in [false, true] {
        let leases = std::cell::Cell::new(0);
        let result = history.inspect_terminal_record(
            || {
                leases.set(leases.get() + 1);
                if leases.get() == 2 {
                    Err(io::Error::other("terminal_changed"))
                } else {
                    Ok(())
                }
            },
            || Ok(Some(vec![5])),
            |_| {
                if callback_fails {
                    Err(io::Error::other("callback"))
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(result.unwrap_err().to_string(), "terminal_changed");
        assert_eq!(leases.get(), 2);
    }
    assert!(history.inspect(|| Ok(None), |_| Ok(())).is_err());
}

#[test]
fn full_empty_record_join_retains_history_on_private_postread_loss_and_callback_error() {
    // Break: a failed private postread or callback hides the already observed
    // original record, or returns callback success despite lost postread.
    for lost_postread in [false, true] {
        let history = NetworkRecordHistory::default();
        let reads = std::cell::Cell::new(0);
        let leases = std::cell::Cell::new(0);
        let result = history.inspect_terminal_record(
            || {
                leases.set(leases.get() + 1);
                Ok(())
            },
            || {
                reads.set(reads.get() + 1);
                if lost_postread && reads.get() == 2 {
                    Err(io::Error::other("private_read_lost"))
                } else {
                    Ok(Some(vec![6]))
                }
            },
            |_| Err::<(), _>(io::Error::other("callback")),
        );
        assert_eq!(
            result.unwrap_err().to_string(),
            if lost_postread {
                "private_read_lost"
            } else {
                "callback"
            }
        );
        assert_eq!(reads.get(), 2);
        assert_eq!(leases.get(), 2);
        assert!(history.inspect(|| Ok(None), |_| Ok(())).is_err());
    }
}

#[test]
fn full_empty_record_join_unwind_keeps_seen_record_and_cannot_import_absence() {
    // Break: publish observed history only after the fallible callback.
    let history = std::rc::Rc::new(NetworkRecordHistory::default());
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        history.inspect_terminal_record(
            || Ok(()),
            || Ok(Some(vec![8])),
            |_| -> io::Result<()> { panic!("consumer unwound") },
        )
    }));
    assert!(panic.is_err());
    assert!(history
        .clone()
        .inspect_terminal_record(
            || Ok(()),
            || Ok(None),
            |_| -> io::Result<()> { panic!("unwind must not forget the original observed record") },
        )
        .is_err());
}

#[test]
fn network_record_history_survives_cleanup_handoff_and_reads_after_callback_error() {
    let original = std::rc::Rc::new(NetworkRecordHistory::default());
    let cleanup = original.clone();
    let reads = std::cell::Cell::new(0);
    original
        .inspect(
            || {
                reads.set(reads.get() + 1);
                Ok(Some(vec![7, 9]))
            },
            |record| {
                assert_eq!(record, Some(vec![7, 9]));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(reads.get(), 2);
    assert!(cleanup.inspect(|| Ok(None), |_| Ok(())).is_err());

    let fresh = NetworkRecordHistory::default();
    let reads = std::cell::Cell::new(0);
    let err = fresh
        .inspect(
            || {
                reads.set(reads.get() + 1);
                Ok(Some(vec![1]))
            },
            |_| Err::<(), _>(io::Error::other("callback")),
        )
        .unwrap_err();
    assert_eq!(err.to_string(), "callback");
    assert_eq!(reads.get(), 2);
    assert!(fresh.inspect(|| Ok(None), |_| Ok(())).is_err());
}

#[test]
fn network_record_history_rejects_changed_postread_and_never_revives_absence() {
    let original = NetworkRecordHistory::default();
    assert!(original.inspect(|| Ok(None), |_| Ok(())).is_ok());
    let n = std::cell::Cell::new(0);
    assert!(original
        .inspect(
            || {
                n.set(n.get() + 1);
                Ok(Some(vec![n.get()]))
            },
            |_| Ok(())
        )
        .is_err());
    assert_eq!(n.get(), 2);
    assert!(original.inspect(|| Ok(None), |_| Ok(())).is_err());
    assert!(original.inspect(|| Ok(Some(vec![4])), |_| Ok(())).is_ok());
}

#[test]
fn joined_native_network_sampler_rechecks_after_callback_including_error_and_denies_drift() {
    // Break: return cached network/DNS facts or skip the second native sample.
    let reads = std::cell::Cell::new(0);
    let actual = checked_samples(
        || {
            reads.set(reads.get() + 1);
            Ok(41u32)
        },
        |facts| Ok(*facts + 1),
    )
    .unwrap();
    assert_eq!(actual, 42);
    assert_eq!(reads.get(), 2);
    let reads = std::cell::Cell::new(0);
    assert!(checked_samples(
        || {
            reads.set(reads.get() + 1);
            Ok(reads.get())
        },
        |_| Ok(())
    )
    .is_err());
    assert_eq!(reads.get(), 2);
    let reads = std::cell::Cell::new(0);
    let result = checked_samples(
        || {
            reads.set(reads.get() + 1);
            Ok(41u32)
        },
        |_| Err::<(), _>(io::Error::other("callback")),
    );
    assert_eq!(result.unwrap_err().to_string(), "callback");
    assert_eq!(reads.get(), 2);
}

fn sources() -> Sources {
    let scope = SessionScope {
        runtime: RuntimeSlot::Stable,
        runtime_generation: 7,
        session_id: "11111111-1111-4111-8111-111111111111".into(),
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
    Sources {
        carrier: Carrier {
            identity: identity(33),
            sources: vec!["10.7.0.2".parse().unwrap()],
        },
        members: [Some(identity(11)), Some(identity(12))],
    }
}
fn route(index: u32) -> RouteValue {
    RouteValue {
        destination: "9.9.9.9/32".parse().unwrap(),
        scope: RouteScope::WindowsInterface(index),
        interface: index,
        gateway: None,
        metric: 1,
    }
}
fn journal(current: Vec<RouteValue>, pending: Option<Vec<RouteValue>>) -> NetworkJournal {
    let entries = |values: Vec<RouteValue>| {
        values.into_iter().map(|current|
        serde_json::json!({"original":null,"current":NetworkValue::Route(current)})).collect::<Vec<_>>()
    };
    serde_json::from_value(
        serde_json::json!({"owned":entries(current),"active":"A","stopping":false,
        "pending":pending.map(|values|serde_json::json!({"target":entries(values),"active":"B"}))}),
    )
    .unwrap()
}
fn row(index: u32) -> Row {
    Row::static_route(
        route(index),
        NativeProof {
            index,
            luid: index as u64 * 100,
        },
    )
}

#[test]
fn network_facts_keep_committed_and_pending_values_separate_and_report_native_rows() {
    let mut c_only = sources();
    c_only.members = [None, None];
    let empty = serde_json::from_value(serde_json::json!({
        "owned": [], "active": null, "stopping": false, "pending": null
    }))
    .unwrap();
    let baseline = compare_routes(&c_only, &empty, &[], &[row(33)]).unwrap();
    assert!(baseline.current.is_empty());
    assert!(baseline.pending.is_none());
    assert_eq!(baseline.active, None);
    let s = sources();
    let mut target = route(11);
    target.metric = 90;
    let j = journal(vec![route(11)], Some(vec![target.clone(), route(12)]));
    let seen = vec![row(11), row(12), row(33)];
    let f = compare_routes(&s, &j, &[], &seen).unwrap();
    assert_eq!(f.current[0].expected, route(11));
    assert_eq!(f.pending.as_ref().unwrap()[0].expected, target);
    assert_eq!(f.current[0].actual, Some(row(11)));
    assert_eq!(f.pending.as_ref().unwrap()[0].actual, Some(row(11)));
    assert_eq!(f.active, Some(nelomai_client_tunnel::redundancy::Slot::A));
    // Incidental kernel routes on the live C/A/B interfaces are outside the
    // journal-owned keys and must not change the facts used by postflight.
    let mut incidental = seen.clone();
    for index in [33, 11, 12] {
        let mut native = row(index);
        native.route.destination = "224.0.0.0/4".parse().unwrap();
        native.protocol = 2;
        native.origin = 1;
        native.flags = [0, 1, 0, 0];
        incidental.push(native);
    }
    assert_eq!(compare_routes(&s, &j, &[], &incidental).unwrap(), f);
    // The read returns exact facts, NOT a fabricated successful transition.
    assert_ne!(
        f.pending.as_ref().unwrap()[0]
            .actual
            .as_ref()
            .unwrap()
            .route,
        target
    );
}

#[test]
fn network_facts_never_infer_egress_ownership_from_a_matching_native_route() {
    for fault in 0..6 {
        let mut s = sources();
        let mut expected = route(11);
        match fault {
            0 => expected = route(33),
            1 => s.members[0] = None,
            2 => expected.scope = RouteScope::Global,
            3 => s.members[0].as_mut().unwrap().scope.runtime_generation += 1,
            4 => s.members[0].as_mut().unwrap().proof = s.carrier.identity.proof,
            _ => s.members[1].as_mut().unwrap().proof = s.members[0].as_ref().unwrap().proof,
        }
        let j = journal(vec![expected], None);
        assert!(
            compare_routes(&s, &j, &[], &[row(11), row(33)]).is_err(),
            "fault={fault}"
        );
    }
}

#[test]
fn network_facts_preserve_drift_and_absence_but_reject_native_duplicates() {
    let s = sources();
    let j = journal(vec![route(11)], None);
    assert!(compare_routes(&s, &j, &[], &[]).unwrap().current[0]
        .actual
        .is_none());
    for fault in 0..5 {
        let mut changed = row(11);
        match fault {
            0 => changed.luid += 1,
            1 => changed.route.metric += 1,
            2 => changed.protocol += 1,
            3 => changed.flags[0] = 1,
            _ => changed.valid_lifetime -= 1,
        }
        let facts = compare_routes(&s, &j, &[], &[changed.clone()]).unwrap();
        assert_eq!(facts.current[0].actual, Some(changed));
        assert_ne!(facts.current[0].actual, Some(row(11)));
    }
    assert!(compare_routes(&s, &j, &[], &[row(11), row(11)]).is_err());
    let mut foreign = row(11);
    foreign.route.gateway = Some("192.0.2.1".parse().unwrap());
    assert!(compare_routes(&s, &j, &[], &[row(11), foreign]).is_err());
}

#[test]
fn network_facts_reject_nonroute_values_and_invalid_pending_even_with_empty_current() {
    let s = sources();
    let invalid: NetworkJournal = serde_json::from_value(serde_json::json!({
        "owned":[],"active":null,"stopping":false,"pending":{"active":"B","target":[{
            "original":null,"current":{"Route":{"destination":"9.9.9.9/32","scope":{"WindowsInterface":11},
                "interface":0,"gateway":null,"metric":1}}
        }]}
    })).unwrap();
    assert!(compare_routes(&s, &invalid, &[], &[]).is_err());
    let dns: NetworkJournal = serde_json::from_value(serde_json::json!({
        "owned":[{"original":null,"current":{"Dns":{"service":"global","servers":["9.9.9.9"]}}}],
        "active":null,"pending":null,"stopping":false
    }))
    .unwrap();
    assert!(compare_routes(&s, &dns, &[], &[]).is_err());
}
