use super::*;
use crate::{
    member_carrier::{Intent, Provenance},
    member_carrier_native_ownership::{Binding, Role},
    member_owner as owner,
    member_physical::{InterfaceRecord, PhysicalProof},
};
use nelomai_client_tunnel::{DesktopTunnelOptions, TunnelTransport};
use nelomai_contracts::{
    dispatcher::{EngineIdentity, TunnelSlot},
    RuntimeSlot,
};

#[test]
fn physical_capture_preserves_full_sdk_path_and_rejects_competing_same_key() {
    let path = PhysicalRoute {
        proof: PhysicalProof {
            identity: InterfaceIdentity {
                index: 7,
                luid: 8,
                guid: [9; 16],
            },
            family: Family::V4,
            metric: 17,
        },
        row: Row {
            route: RouteValue {
                destination: "0.0.0.0/0".parse().unwrap(),
                gateway: Some("192.0.2.1".parse().unwrap()),
                interface: 7,
                metric: 23,
                scope: RouteScope::WindowsInterface(7),
            },
            luid: 8,
            protocol: 3,
            origin: 0,
            site_prefix_length: 0,
            valid_lifetime: u32::MAX,
            preferred_lifetime: u32::MAX,
            flags: [0, 0, 1, 0],
        },
    };
    let leases = physical_plan_leases(&[path.clone(), path.clone()]).unwrap();
    assert_eq!(
        leases,
        vec![PhysicalLease {
            interface: 7,
            luid: 8,
            guid: [9; 16],
            ipv6: false,
            interface_metric: 17,
            route: RouteValue {
                destination: "0.0.0.0/0".parse().unwrap(),
                gateway: Some("192.0.2.1".parse().unwrap()),
                interface: 7,
                metric: 23,
                scope: RouteScope::WindowsInterface(7)
            },
            protocol: 3,
            origin: 0,
            site_prefix_length: 0,
            valid_lifetime: u32::MAX,
            preferred_lifetime: u32::MAX,
            flags: [0, 0, 1, 0],
        }]
    );
    for field in 0..7 {
        let mut competing = path.clone();
        match field {
            0 => competing.proof.identity.guid = [4; 16],
            1 => competing.proof.metric += 1,
            2 => competing.row.route.gateway = Some("192.0.2.2".parse().unwrap()),
            3 => competing.row.protocol += 1,
            4 => competing.row.valid_lifetime -= 1,
            5 => competing.row.flags[0] = 1,
            _ => competing.row.origin += 1,
        }
        assert!(physical_plan_leases(&[path.clone(), competing]).is_err());
    }
    let mut wrong_luid = path;
    wrong_luid.row.luid += 1;
    assert!(physical_plan_leases(&[wrong_luid]).is_err());
}

// Break: requiring a fabricated first Network pending value to construct a
// factual gate before WeakRows, or promoting that metadata to effect authority.
#[test]
fn pre_network_root_accepts_bootstrap_pair_but_not_effect_or_restored_metadata() {
    let (c, mut r) = fixture();
    r.network = None;
    r.pending = Some(pair::Effect::WeakRows);
    assert!(compare_pre_network_record(&c, &r).is_ok());
    assert!(compare_stage(&c, &r, false).is_err());
    for pending in [
        pair::Effect::CarrierReady,
        pair::Effect::MemberStart(Slot::A),
    ] {
        r.pending = Some(pending);
        assert!(compare_pre_network_record(&c, &r).is_ok());
    }
    r.pending = Some(pair::Effect::Network);
    assert!(compare_pre_network_record(&c, &r).is_err());
    let (_, network) = fixture();
    r = network;
    assert!(compare_pre_network_record(&c, &r).is_err());
    r.network = None;
    r.phase = pair::Phase::Closing;
    r.operation = None;
    r.stop_stage = 2;
    r.active = None;
    r.pending = Some(pair::Effect::RestoreNetwork);
    assert!(compare_pre_network_record(&c, &r).is_err());
}

// Break: first real store span is rejected because old Network was None, or
// that exception permits later baseline replacement/Closing-first exchange.
#[test]
fn first_network_selection_requires_real_effect_record_and_keeps_later_baseline() {
    let (c, next) = fixture();
    let mut old = next.clone();
    old.network = None;
    old.pending = Some(pair::Effect::WeakRows);
    old.revision -= 1;
    assert!(compare_network_selection_records(&c, &old, &next).is_ok());
    let mut missing = next.clone();
    missing.network = None;
    assert!(compare_network_selection_records(&c, &old, &missing).is_err());
    let (c2, closing, _) = lifecycle_fixture(3);
    assert!(compare_network_selection_records(&c2, &old, &closing).is_err());
    let mut later = next.clone();
    later.revision += 1;
    later
        .network
        .as_mut()
        .unwrap()
        .baseline
        .dns
        .as_mut()
        .unwrap()
        .settings
        .domain = Some("foreign".into());
    assert!(compare_network_selection_records(&c, &next, &later).is_err());
    later = next.clone();
    later.revision += 1;
    assert!(compare_network_selection_records(&c, &next, &later).is_ok());
}

// Break: bootstrap context mismatch or an already-published network baseline
// becomes the successful read-only absence needed to mint a fresh original.
#[test]
fn pre_network_root_does_not_accept_foreign_scope_or_existing_baseline() {
    let (c, mut r) = fixture();
    r.network = None;
    r.pending = Some(pair::Effect::WeakRows);
    let mut wrong = c.clone();
    wrong.provenance.network_epoch += 1;
    assert!(compare_pre_network_record(&wrong, &r).is_err());
    let (_, n) = fixture();
    r.network = n.network;
    assert!(compare_pre_network_record(&c, &r).is_err());
    // Even a complete restored actual snapshot is not bootstrap absence.
    let n = r.network.as_mut().unwrap();
    n.current = n.baseline.clone();
    n.pending = None;
    assert!(compare_pre_network_record(&c, &r).is_err());
}

// Break: a postflight compares only the last route key and loses an unknown
// attempt, IO outcome, SDK row metadata or original DNS history entry.
#[test]
fn lifecycle_ack_postflight_compares_full_retained_io_history() {
    let (_, _, baseline) = lifecycle_fixture(7);
    let row = Row::static_route(
        route("192.0.2.11/32", 20, 10, Some("192.0.2.1")),
        NativeProof {
            index: 20,
            luid: 200,
        },
    );
    let before = (
        vec![RouteAttempt {
            row,
            deleting: true,
            acknowledged: true,
        }],
        vec![baseline],
    );
    assert!(same_network_ack_reads(&before, &before.clone()));
    let mut changed = before.clone();
    changed.0[0].acknowledged = false;
    assert!(!same_network_ack_reads(&before, &changed));
    changed = before.clone();
    changed.0[0].row.valid_lifetime -= 1;
    assert!(!same_network_ack_reads(&before, &changed));
    changed = before.clone();
    changed.0.push(changed.0[0].clone());
    assert!(!same_network_ack_reads(&before, &changed));
    changed = before.clone();
    changed.1[0].settings.domain = Some("foreign".into());
    assert!(!same_network_ack_reads(&before, &changed));
}

fn lifecycle_fixture(stage: u8) -> (Context, pair::Record, dns::Snapshot) {
    let (context, mut record) = fixture();
    let baseline = record
        .network
        .as_ref()
        .unwrap()
        .baseline
        .dns
        .clone()
        .unwrap();
    let network = record.network.as_mut().unwrap();
    network.current = network.baseline.clone();
    network.pending = None;
    record.phase = pair::Phase::Closing;
    record.operation = None;
    record.active = None;
    record.stop_stage = stage;
    record.pending = Some(match stage {
        3 => pair::Effect::RestoreWeak,
        6 => pair::Effect::CarrierAddressDelete,
        7 => pair::Effect::CarrierSessionEnd,
        _ => pair::Effect::CarrierClose,
    });
    record.validate().unwrap();
    (context, record, baseline)
}
fn native_empty_fixture(stage: u8) -> (Context, pair::Record, dns::Snapshot) {
    let (context, mut record, baseline) = lifecycle_fixture(8);
    record.stop_stage = stage;
    record.pending = Some(if stage == 9 {
        pair::Effect::NativeEmpty
    } else {
        pair::Effect::Guard
    });
    record.validate().unwrap();
    (context, record, baseline)
}

#[test]
fn full_empty_network_comparison_requires_exact_closing_or_terminal_channel() {
    let (context, mut record, baseline) = native_empty_fixture(10);
    record.stop_stage = 12;
    record.pending = Some(pair::Effect::FullEmpty);
    record.guard = policy::Model::empty(record.scope.clone()).unwrap();
    for terminal in [false, true] {
        let mut full = record.clone();
        if terminal {
            full.phase = pair::Phase::Stopped;
            full.pending = None;
            full.carrier = None;
            full.members = [None, None];
        }
        compare_full_empty_resource_stage(&context, &full, &baseline).unwrap();
        assert!(compare_native_empty_resource_stage(&context, &full, &baseline).is_err());
        for fault in 0..10 {
            let mut bad = full.clone();
            let mut captured = baseline.clone();
            match fault {
                0 => bad.stop_stage = 10,
                1 => bad.pending = Some(pair::Effect::NativeEmpty),
                2 => {
                    bad.pending_guard =
                        Some(policy::ExchangePlan::new(&record.guard, &record.guard).unwrap())
                }
                3 => bad.guard = native_empty_fixture(10).1.guard,
                4 => bad.provenance.network_epoch += 1,
                5 => captured.interface.luid += 1,
                6 => {
                    bad.network.as_mut().unwrap().pending =
                        Some(bad.network.as_ref().unwrap().baseline.clone())
                }
                7 => bad.active = Some(Slot::A),
                8 => {
                    bad.phase = pair::Phase::Running;
                    bad.stop_stage = 0;
                }
                _ => {
                    if terminal {
                        bad.carrier = record.carrier;
                    } else {
                        bad.carrier = None;
                    }
                }
            }
            assert!(
                compare_full_empty_resource_stage(&context, &bad, &captured).is_err(),
                "terminal {terminal}, fault {fault}"
            );
        }
    }
}

#[test]
fn restored_keys_network_facts_do_not_require_future_full_empty_or_skip_baseline() {
    let (context, mut record, baseline) = native_empty_fixture(10);
    record.stop_stage = 11;
    record.pending = Some(pair::Effect::RestoreKeys);
    record.guard = policy::Model::empty(record.scope.clone()).unwrap();
    compare_restored_keys_resource_stage(&context, &record, &baseline).unwrap();
    assert!(compare_full_empty_resource_stage(&context, &record, &baseline).is_err());
    for fault in 0..8 {
        let mut wrong = record.clone();
        let mut original = baseline.clone();
        match fault {
            0 => wrong.stop_stage = 12,
            1 => wrong.pending = Some(pair::Effect::FullEmpty),
            2 => wrong.pending = None,
            3 => wrong.phase = pair::Phase::Stopped,
            4 => wrong.carrier = None,
            5 => original.interface.luid += 1,
            6 => {
                wrong.network.as_mut().unwrap().pending =
                    Some(wrong.network.as_ref().unwrap().baseline.clone())
            }
            _ => wrong.provenance.network_epoch += 1,
        }
        assert!(compare_restored_keys_resource_stage(&context, &wrong, &original).is_err());
    }
}

#[test]
fn full_empty_network_journal_still_requires_every_original_restore_ack() {
    let (context, mut record, baseline) = native_empty_fixture(10);
    record.stop_stage = 12;
    record.pending = Some(pair::Effect::FullEmpty);
    record.guard = policy::Model::empty(record.scope.clone()).unwrap();
    for terminal in [false, true] {
        let mut full = record.clone();
        if terminal {
            full.phase = pair::Phase::Stopped;
            full.pending = None;
            full.carrier = None;
            full.members = [None, None];
        }
        compare_full_empty_resource_journals(
            &context,
            &full,
            &baseline,
            Some(&NetworkJournal::default()),
            None,
            &[],
            1,
            std::slice::from_ref(&baseline),
        )
        .unwrap();
        assert!(compare_full_empty_resource_journals(
            &context,
            &full,
            &baseline,
            None,
            None,
            &[],
            1,
            std::slice::from_ref(&baseline)
        )
        .is_err());
        assert!(compare_full_empty_resource_journals(
            &context,
            &full,
            &baseline,
            Some(&NetworkJournal::default()),
            None,
            &[],
            2,
            std::slice::from_ref(&baseline)
        )
        .is_err());
        let mut foreign = baseline.clone();
        foreign.settings.domain = Some("foreign".into());
        assert!(compare_full_empty_resource_journals(
            &context,
            &full,
            &baseline,
            Some(&NetworkJournal::default()),
            None,
            &[],
            1,
            &[foreign]
        )
        .is_err());
    }
}

#[test]
fn restored_keys_network_journal_requires_every_original_restore_ack() {
    let (context, mut record, baseline) = native_empty_fixture(10);
    record.stop_stage = 11;
    record.pending = Some(pair::Effect::RestoreKeys);
    record.guard = policy::Model::empty(record.scope.clone()).unwrap();
    let route = RouteAttempt {
        row: Row::static_route(
            route("192.0.2.11/32", 20, 10, Some("192.0.2.1")),
            NativeProof {
                index: 20,
                luid: 200,
            },
        ),
        deleting: true,
        acknowledged: true,
    };
    for fault in 0..8 {
        let mut restored = NetworkJournal::default();
        let mut original_dns = baseline.clone();
        let mut ack = route.clone();
        let mut journal_present = true;
        let mut dns_attempts = 1;
        match fault {
            0 => (),
            1 => journal_present = false,
            2 => dns_attempts = 2,
            3 => original_dns.settings.domain = Some("foreign".into()),
            4 => ack.acknowledged = false,
            5 => ack.deleting = false,
            6 => restored = journal(&[], Some(&[route.row.route.clone()]), false),
            _ => restored = journal(&[route.row.route.clone()], None, false),
        }
        assert_eq!(
            compare_restored_keys_resource_journals(
                &context,
                &record,
                &baseline,
                journal_present.then_some(&restored),
                None,
                &[ack],
                dns_attempts,
                &[original_dns],
            )
            .is_ok(),
            fault == 0,
            "fault {fault}"
        );
    }
}

// Break: project a Closing9/10 readonly request into stage8, or accept ANY
// Closing channel/record. Native closure comes from original typed history,
// not rewriting Pair's retained member proofs while static bases remain.
#[test]
fn native_empty_network_read_requires_exact_nine_or_ten_and_closed_record_facts() {
    for stage in [9, 10] {
        let (context, record, baseline) = native_empty_fixture(stage);
        assert!(compare_native_empty_resource_stage(&context, &record, &baseline).is_ok());
        assert!(compare_lifecycle_resource_stage(&context, &record, &baseline, true).is_err());
        for mutation in 0..8 {
            let mut changed = record.clone();
            match mutation {
                0 => {
                    changed.stop_stage = 8;
                    changed.pending = Some(pair::Effect::CarrierClose);
                }
                1 => changed.pending = Some(pair::Effect::RestoreNetwork),
                2 => changed.pending = None,
                3 => changed.provenance.network_epoch += 1,
                4 => changed.guard.permits = true,
                5 => changed.guard.assigned_sublayer_weight = None,
                6 => {
                    changed.network.as_mut().unwrap().pending =
                        Some(changed.network.as_ref().unwrap().baseline.clone())
                }
                _ => changed.carrier.as_mut().unwrap().guid = [99; 16],
            }
            assert!(
                compare_native_empty_resource_stage(&context, &changed, &baseline).is_err(),
                "stage={stage},mutation={mutation}"
            );
        }
        let mut foreign = baseline.clone();
        foreign.interface.luid += 1;
        assert!(compare_native_empty_resource_stage(&context, &record, &foreign).is_err());
    }
}

// Break: treat baseline JSON/empty ACK list as restored after unknown IO, or
// erase original route/child obligations when the protected journal vanishes.
#[test]
fn native_empty_network_read_requires_whole_restored_journals_and_actual_io_history() {
    for stage in [9, 10] {
        let (context, record, baseline) = native_empty_fixture(stage);
        let journal = NetworkJournal::default();
        assert!(compare_native_empty_resource_journals(
            &context,
            &record,
            &baseline,
            Some(&journal),
            None,
            &[],
            1,
            &[baseline.clone()]
        )
        .is_ok());
        let mut partial = record.clone();
        partial.network = None;
        assert!(compare_native_empty_resource_journals(
            &context,
            &partial,
            &baseline,
            None,
            None,
            &[],
            0,
            &[]
        )
        .is_ok());
        assert!(compare_native_empty_resource_journals(
            &context,
            &partial,
            &baseline,
            None,
            None,
            &[],
            1,
            &[baseline.clone()]
        )
        .is_err());
        assert!(compare_native_empty_resource_journals(
            &context,
            &record,
            &baseline,
            Some(&journal),
            None,
            &[],
            1,
            &[]
        )
        .is_err());
        let mut foreign = baseline.clone();
        foreign.settings.domain = Some("foreign".into());
        assert!(compare_native_empty_resource_journals(
            &context,
            &record,
            &baseline,
            Some(&journal),
            None,
            &[],
            1,
            &[foreign]
        )
        .is_err());
        let child = crate::member_pair::DnsRecord {
            baseline: baseline.clone(),
            current: baseline.clone(),
            pending: None,
        };
        assert!(compare_native_empty_resource_journals(
            &context,
            &record,
            &baseline,
            Some(&journal),
            Some(&child),
            &[],
            0,
            &[]
        )
        .is_err());
        let attempt = RouteAttempt {
            row: Row::static_route(
                route("192.0.2.11/32", 20, 10, Some("192.0.2.1")),
                NativeProof {
                    index: 20,
                    luid: 200,
                },
            ),
            deleting: true,
            acknowledged: true,
        };
        assert!(compare_native_empty_resource_journals(
            &context,
            &record,
            &baseline,
            Some(&journal),
            None,
            &[attempt.clone()],
            1,
            &[baseline.clone()]
        )
        .is_ok());
        assert!(compare_native_empty_resource_journals(
            &context,
            &record,
            &baseline,
            None,
            None,
            &[attempt.clone()],
            1,
            &[baseline.clone()]
        )
        .is_err());
        let unknown = RouteAttempt {
            acknowledged: false,
            ..attempt
        };
        assert!(compare_native_empty_resource_journals(
            &context,
            &record,
            &baseline,
            Some(&journal),
            None,
            &[unknown],
            1,
            std::slice::from_ref(&baseline)
        )
        .is_err());
    }
}

// Break: a journaled removal or an already-ACKed empty Guard cannot finish a
// stage10 retry, or the same exception silently permits stage9/base removal.
#[test]
fn native_empty_network_read_stage_ten_retry_is_not_a_stage_nine_removal_grant() {
    let (context, mut record, baseline) = native_empty_fixture(10);
    let empty = policy::Model::empty(record.scope.clone()).unwrap();
    record.pending_guard = Some(policy::ExchangePlan::new(&record.guard, &empty).unwrap());
    record.validate().unwrap();
    assert!(compare_native_empty_resource_stage(&context, &record, &baseline).is_ok());
    let mut nine = record.clone();
    nine.stop_stage = 9;
    nine.pending = Some(pair::Effect::NativeEmpty);
    assert!(compare_native_empty_resource_stage(&context, &nine, &baseline).is_err());
    record.pending_guard = None;
    record.guard = empty;
    record.validate().unwrap();
    assert!(compare_native_empty_resource_stage(&context, &record, &baseline).is_ok());
    nine = record;
    nine.stop_stage = 9;
    nine.pending = Some(pair::Effect::NativeEmpty);
    assert!(compare_native_empty_resource_stage(&context, &nine, &baseline).is_err());

    for stage in [9, 10] {
        let (c, mut prebase, b) = native_empty_fixture(stage);
        let retained_guard = prebase.guard.clone();
        prebase.guard = policy::Model::empty(prebase.scope.clone()).unwrap();
        prebase.network = None;
        prebase.validate().unwrap();
        assert!(compare_native_empty_resource_stage(&c, &prebase, &b).is_ok());
        let mut wrong = prebase.clone();
        if stage == 9 {
            wrong.network = nine.network.clone();
            assert!(compare_native_empty_resource_stage(&c, &wrong, &b).is_err());
            wrong = prebase.clone();
        }
        wrong.pending_guard = Some(policy::ExchangePlan::new(&wrong.guard, &wrong.guard).unwrap());
        assert!(compare_native_empty_resource_stage(&c, &wrong, &b).is_err());
        wrong = prebase.clone();
        wrong.guard.expected.filters = retained_guard.expected.filters.clone();
        assert!(compare_native_empty_resource_stage(&c, &wrong, &b).is_err());
        wrong = prebase.clone();
        wrong.stop_stage = 8;
        wrong.pending = Some(pair::Effect::CarrierClose);
        assert!(compare_native_empty_resource_stage(&c, &wrong, &b).is_err());
    }
}

// Break: lifecycle read facade widens stage2 restore or stage10 base removal.
#[test]
fn lifecycle_network_resources_require_exact_three_six_seven_eight() {
    for stage in [3, 6, 7, 8] {
        let (c, r, b) = lifecycle_fixture(stage);
        assert!(compare_lifecycle_resource_stage(&c, &r, &b, stage == 8).is_ok());
        let mut wrong = r.clone();
        wrong.pending = Some(pair::Effect::RestoreNetwork);
        assert!(compare_lifecycle_resource_stage(&c, &wrong, &b, stage == 8).is_err());
        assert!(compare_lifecycle_resource_stage(&c, &r, &b, stage != 8).is_ok() == (stage == 8));
        let mut prebase = r.clone();
        prebase.guard = policy::Model::empty(prebase.scope.clone()).unwrap();
        prebase.network = None;
        prebase.validate().unwrap();
        assert_eq!(
            compare_lifecycle_resource_stage(&c, &prebase, &b, stage == 8).is_ok(),
            stage != 3
        );
        if stage != 3 {
            let mut wrong = prebase.clone();
            wrong.network = r.network.clone();
            assert!(compare_lifecycle_resource_stage(&c, &wrong, &b, stage == 8).is_err());
            wrong = prebase.clone();
            wrong.pending_guard =
                Some(policy::ExchangePlan::new(&wrong.guard, &wrong.guard).unwrap());
            assert!(compare_lifecycle_resource_stage(&c, &wrong, &b, stage == 8).is_err());
            wrong = prebase.clone();
            wrong.guard.expected.filters = r.guard.expected.filters.clone();
            assert!(compare_lifecycle_resource_stage(&c, &wrong, &b, stage == 8).is_err());
            wrong = prebase;
            wrong.stop_stage = 10;
            wrong.pending = Some(pair::Effect::Guard);
            assert!(compare_lifecycle_resource_stage(&c, &wrong, &b, stage == 8).is_err());
        }
    }
    let (c, mut r, b) = lifecycle_fixture(8);
    r.stop_stage = 10;
    r.pending = Some(pair::Effect::Guard);
    assert!(compare_lifecycle_resource_stage(&c, &r, &b, true).is_err());
}

// Break: baseline metadata or empty successful ACK vector is mistaken for
// never-exchanged when the real SDK attempt registry contains an unknown call.
#[test]
fn lifecycle_dns_requires_actual_attempt_history_and_exact_final_sdk_ack() {
    let (c, r, b) = lifecycle_fixture(3);
    assert!(compare_lifecycle_resource_journals(
        &c,
        &r,
        &b,
        Some(&NetworkJournal::default()),
        None,
        &[],
        0,
        &[]
    )
    .is_ok());
    assert!(compare_lifecycle_resource_journals(
        &c,
        &r,
        &b,
        Some(&NetworkJournal::default()),
        None,
        &[],
        1,
        &[]
    )
    .is_err());
    let applied = b.with_servers(&r.dns).unwrap();
    assert!(compare_lifecycle_resource_journals(
        &c,
        &r,
        &b,
        Some(&NetworkJournal::default()),
        None,
        &[],
        1,
        &[applied.clone()]
    )
    .is_err());
    assert!(compare_lifecycle_resource_journals(
        &c,
        &r,
        &b,
        Some(&NetworkJournal::default()),
        None,
        &[],
        2,
        &[applied, b.clone()]
    )
    .is_ok());
    let mut foreign = b.clone();
    foreign.settings.domain = Some("foreign".into());
    assert!(compare_lifecycle_resource_journals(
        &c,
        &r,
        &b,
        Some(&NetworkJournal::default()),
        None,
        &[],
        1,
        &[foreign]
    )
    .is_err());
}

// Break: missing child/protected record is treated as complete after actual
// IO; or a retained child is ignored when its whole-Pair baseline looks right.
#[test]
fn lifecycle_initial_no_record_does_not_erase_actual_network_obligations() {
    let (c, mut r, b) = lifecycle_fixture(3);
    r.network = None;
    assert!(compare_lifecycle_resource_journals(&c, &r, &b, None, None, &[], 0, &[]).is_ok());
    let child = crate::member_pair::DnsRecord {
        baseline: b.clone(),
        current: b.clone(),
        pending: None,
    };
    assert!(
        compare_lifecycle_resource_journals(&c, &r, &b, None, Some(&child), &[], 0, &[]).is_err()
    );
    assert!(
        compare_lifecycle_resource_journals(&c, &r, &b, None, None, &[], 1, &[b.clone()]).is_err()
    );
    let row = Row::static_route(
        route("192.0.2.11/32", 20, 10, Some("192.0.2.1")),
        NativeProof {
            index: 20,
            luid: 200,
        },
    );
    let attempt = RouteAttempt {
        row,
        deleting: true,
        acknowledged: true,
    };
    assert!(
        compare_lifecycle_resource_journals(&c, &r, &b, None, None, &[attempt], 0, &[]).is_err()
    );
}

// Break: native lookup equality or last unknown IO replaces the retained
// successful Delete ACK, including physical endpoint routes and IPv6 leftovers.
#[test]
fn lifecycle_full_route_table_requires_delete_ack_and_all_original_absence() {
    let (_, r, _) = lifecycle_fixture(7);
    let proofs = [
        r.carrier,
        r.members[0]
            .as_ref()
            .unwrap()
            .owner
            .proof
            .map(|p| p.interface),
        None,
    ];
    let endpoint = Row::static_route(
        route("192.0.2.11/32", 20, 10, Some("192.0.2.1")),
        NativeProof {
            index: 20,
            luid: 200,
        },
    );
    let ack = RouteAttempt {
        row: endpoint.clone(),
        deleting: true,
        acknowledged: true,
    };
    assert!(compare_lifecycle_route_table(&r, proofs, &[ack.clone()], &[], false).is_ok());
    assert!(compare_lifecycle_route_table(&r, proofs, &[ack.clone()], &[endpoint], false).is_err());
    let mut unknown = ack;
    unknown.acknowledged = false;
    assert!(compare_lifecycle_route_table(&r, proofs, &[unknown], &[], false).is_err());
    let a = proofs[1].unwrap();
    let old = Row::static_route(
        route("::/0", a.index, 0, None),
        NativeProof {
            index: a.index,
            luid: a.luid,
        },
    );
    assert!(compare_lifecycle_route_table(&r, proofs, &[], &[old], false).is_err());
    let (_, before_stop, _) = lifecycle_fixture(3);
    let mut incidental = Row::static_route(
        route("224.0.0.0/4", a.index, 0, None),
        NativeProof {
            index: a.index,
            luid: a.luid,
        },
    );
    incidental.protocol = 2;
    incidental.origin = 1;
    incidental.flags = [0, 1, 0, 0];
    assert!(
        compare_lifecycle_route_table(&before_stop, proofs, &[], &[incidental.clone()], true)
            .is_ok()
    );
    for stage in [6, 7, 8] {
        let (_, after_stop, _) = lifecycle_fixture(stage);
        assert!(compare_lifecycle_route_table(
            &after_stop,
            proofs,
            &[],
            &[incidental.clone()],
            true
        )
        .is_err());
    }
    let mut alias = incidental.clone();
    alias.luid += 1;
    assert!(compare_lifecycle_route_table(&before_stop, proofs, &[], &[alias], true).is_err());
    let owned_delete = RouteAttempt {
        row: incidental.clone(),
        deleting: true,
        acknowledged: true,
    };
    assert!(compare_lifecycle_route_table(
        &before_stop,
        proofs,
        &[owned_delete],
        &[incidental],
        true
    )
    .is_err());
}

// Break: treating kernel routes on live C as app-owned leftovers, or retaining them after native close.
#[test]
fn lifecycle_live_carrier_routes_end_only_after_native_close() {
    for stage in [3, 6, 7, 8] {
        let (_, r, _) = lifecycle_fixture(stage);
        let c = r.carrier.unwrap();
        let proofs = [
            Some(c),
            r.members[0]
                .as_ref()
                .unwrap()
                .owner
                .proof
                .map(|p| p.interface),
            None,
        ];
        let incidental_carrier = ["10.7.0.2/32", "224.0.0.0/4"]
            .into_iter()
            .enumerate()
            .map(|(i, destination)| {
                let mut row = Row::static_route(
                    route(destination, c.index, 0, None),
                    NativeProof {
                        index: c.index,
                        luid: c.luid,
                    },
                );
                row.protocol = 2;
                row.origin = if i == 1 { 1 } else { 0 };
                row.flags = if i == 0 { [1, 1, 0, 0] } else { [0, 1, 0, 0] };
                row
            })
            .collect::<Vec<_>>();
        assert!(compare_lifecycle_route_table(&r, proofs, &[], &incidental_carrier, true).is_ok());
        assert!(
            compare_lifecycle_route_table(&r, proofs, &[], &incidental_carrier, false).is_err()
        );
        for index_only in [false, true] {
            let mut alias = incidental_carrier[0].clone();
            if index_only {
                alias.luid += 1;
            } else {
                alias.route.interface += 1;
                alias.route.scope = RouteScope::WindowsInterface(alias.route.interface);
            }
            assert!(compare_lifecycle_route_table(&r, proofs, &[], &[alias], true).is_err());
        }
    }
}

fn fixture() -> (Context, pair::Record) {
    let scope = nelomai_client_tunnel::redundancy::SessionScope {
        runtime: RuntimeSlot::Stable,
        runtime_generation: 2,
        session_id: "11111111-1111-4111-8111-111111111111".into(),
        connection_generation: 3,
    };
    let provenance = Provenance {
        boot_id: [8; 16],
        network_epoch: 7,
        runtime: EngineIdentity {
            slot: RuntimeSlot::Stable,
            runtime_version: "0.3.3".into(),
            container_version: "0.3.3".into(),
            runtime_contract_version: 1,
            manifest_sha256: "a".repeat(64),
        },
    };
    let context = Context {
        intent: Intent {
            scope: scope.clone(),
            addresses: vec!["10.7.0.2/32".parse().unwrap()],
        },
        provenance: provenance.clone(),
        bindings: std::array::from_fn(|i| {
            Binding {
            role: [Role::RoleCarrier,Role::MemberA,Role::MemberB][i], guid: [(i+1) as u8;16],
            name: ["carrier-c","member-a","member-b"][i].into(),
            registry_path: [r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{01010101-0101-0101-0101-010101010101}",
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{02020202-0202-0202-0202-020202020202}",
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{03030303-0303-0303-0303-030303030303}"][i].into(),
        }
        }),
    };
    let c = owner::InterfaceProof {
        index: 7,
        luid: 90,
        guid: [1; 16],
    };
    let a = owner::InterfaceProof {
        index: 8,
        luid: 91,
        guid: [2; 16],
    };
    let member = pair::MemberState {
        owner: owner::Record {
            intent: owner::Intent {
                scope: scope.clone(),
                slot: TunnelSlot::A,
                transport: TunnelTransport::WireGuard,
                engine: crate::test_engine_path("wireguard.exe"),
                config_sha256: [4; 32],
            },
            phase: owner::Phase::Running,
            proof: Some(owner::NativeProof {
                interface: a,
                process: owner::ProcessProof {
                    pid: 50,
                    creation_time: 100,
                },
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
        endpoint: "192.0.2.11".parse().unwrap(),
        allowed: vec!["0.0.0.0/0".parse().unwrap()],
        peer: [3; 32],
    };
    let base = policy::Model::new(
        scope.clone(),
        policy::Carrier {
            identity: policy::Identity {
                scope: scope.clone(),
                proof: c,
            },
            sources: vec!["10.7.0.2".parse().unwrap()],
        },
        [
            Some(policy::Member {
                identity: policy::Identity {
                    scope: scope.clone(),
                    proof: a,
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
    let mut captured = base.expected.clone();
    captured.sublayer.as_mut().unwrap().weight = 41;
    let base = base
        .readback_after(&policy::Model::empty(scope.clone()).unwrap(), &captured)
        .unwrap();
    let dns = dns::Snapshot {
        interface: dns::OwnedInterface {
            scope: scope.clone(),
            guid: c.guid,
            luid: c.luid,
            index: c.index,
        },
        settings: dns::Settings {
            version: 1,
            flags: 0,
            domain: None,
            name_server: None,
            search_list: None,
            registration_enabled: 0,
            register_adapter_name: 0,
            enable_llmnr: 0,
            query_adapter_name: 0,
            profile_name_server: None,
        },
    };
    let baseline = pair::NetworkSnapshot {
        routes: vec![],
        dns: Some(dns.clone()),
    };
    let target = pair::NetworkSnapshot {
        routes: vec![
            route("0.0.0.0/1", 8, 0, None),
            route("128.0.0.0/1", 8, 0, None),
            route("1.1.1.1/32", 8, 1, None),
            route("192.0.2.11/32", 20, 10, Some("192.0.2.1")),
        ],
        dns: Some(dns.with_servers(&["1.1.1.1".parse().unwrap()]).unwrap()),
    };
    let r = pair::Record {
        version: 2,
        scope,
        provenance,
        revision: 10,
        phase: pair::Phase::Starting,
        addresses: context.intent.addresses.clone(),
        dns: vec!["1.1.1.1".parse().unwrap()],
        carrier: Some(c),
        members: [Some(member), None],
        active: None,
        options: Some(DesktopTunnelOptions::default()),
        guard: base,
        pending_guard: None,
        pending: Some(pair::Effect::Network),
        network: Some(pair::NetworkState {
            baseline: baseline.clone(),
            current: baseline,
            pending: Some(target),
        }),
        stop_stage: 0,
        operation: Some(pair::Operation::Start(Slot::A)),
    };
    r.validate().unwrap();
    (context, r)
}
fn route(dst: &str, index: u32, metric: u32, gateway: Option<&str>) -> RouteValue {
    RouteValue {
        destination: dst.parse().unwrap(),
        interface: index,
        scope: RouteScope::WindowsInterface(index),
        metric,
        gateway: gateway.map(|s| s.parse().unwrap()),
    }
}
fn physical() -> PhysicalSnapshot {
    let row = Row::static_route(
        route("0.0.0.0/0", 20, 10, Some("192.0.2.1")),
        NativeProof {
            index: 20,
            luid: 200,
        },
    );
    PhysicalSnapshot::new(
        vec![row],
        vec![InterfaceRecord {
            proof: PhysicalProof {
                identity: InterfaceIdentity {
                    index: 20,
                    luid: 200,
                    guid: [20; 16],
                },
                family: Family::V4,
                metric: 5,
            },
            alias: "Ethernet".into(),
            if_type: 6,
            tunnel_type: 0,
            oper_status: 1,
            status_flags: 1,
        }],
        &[],
    )
    .unwrap()
}

fn guard_resource_fixture() -> (Context, pair::Record, NetworkJournal) {
    let (context, mut record) = fixture();
    let n = record.network.as_mut().unwrap();
    n.current = n.pending.take().unwrap();
    record.revision += 1;
    record.pending = Some(pair::Effect::Guard);
    let desired = policy::Model::new(
        record.scope.clone(),
        record.guard.carrier.clone().unwrap(),
        record.guard.members.clone(),
        Some(Slot::A),
    )
    .unwrap()
    .inherit_sublayer_weight(&record.guard)
    .unwrap();
    record.pending_guard = Some(policy::ExchangePlan::new(&record.guard, &desired).unwrap());
    // Install is the third split boundary, AFTER the actual deny-only base
    // has advanced to the desired active identity. The old base is not an ACK
    // of this intermediate boundary.
    record.guard = record.pending_guard.as_ref().unwrap().base.clone();
    let mut child = journal(
        &record.network.as_ref().unwrap().current.routes,
        None,
        false,
    );
    // Literal stable active slot; only test comparison bytes, not a native ACK.
    let mut value = serde_json::to_value(&child).unwrap();
    value["active"] = serde_json::json!("A");
    child = serde_json::from_value(value).unwrap();
    record.validate().unwrap();
    (context, record, child)
}

// Break: using a Network pending target, Closing, or a non-Install Guard plan as stable permit resources.
#[test]
fn guard_resources_require_guard_install_and_stable_network() {
    let (context, record, _) = guard_resource_fixture();
    assert_eq!(
        compare_guard_resource_stage(&context, &record).unwrap(),
        Slot::A
    );
    let mut drift = record.clone();
    let target = drift.network.as_ref().unwrap().current.clone();
    drift.network.as_mut().unwrap().pending = Some(target);
    assert!(compare_guard_resource_stage(&context, &drift).is_err());
    drift = record.clone();
    drift.pending = Some(pair::Effect::Network);
    assert!(compare_guard_resource_stage(&context, &drift).is_err());
    drift = record.clone();
    drift.pending_guard = None;
    assert!(compare_guard_resource_stage(&context, &drift).is_err());
    drift = record.clone();
    drift.phase = pair::Phase::Closing;
    drift.operation = None;
    drift.active = None;
    assert!(compare_guard_resource_stage(&context, &drift).is_err());
}

// Break: accepting stable JSON/native equality as an ACK, or unfinished child network/DNS journals.
#[test]
fn guard_resources_require_complete_committed_child_and_native_dns_ack() {
    let (_, record, child) = guard_resource_fixture();
    let n = record.network.as_ref().unwrap();
    let actual_dns = n.current.dns.as_ref().unwrap();
    let dns_child = crate::member_pair::DnsRecord {
        baseline: n.baseline.dns.clone().unwrap(),
        current: actual_dns.clone(),
        pending: None,
    };
    assert!(compare_guard_resource_journals(
        &record,
        &child,
        Some(&dns_child),
        actual_dns,
        &[actual_dns.clone()]
    )
    .is_ok());
    assert!(
        compare_guard_resource_journals(&record, &child, Some(&dns_child), actual_dns, &[])
            .is_err()
    );
    let pending = journal(&n.current.routes, Some(&n.current.routes), false);
    assert!(compare_guard_resource_journals(
        &record,
        &pending,
        Some(&dns_child),
        actual_dns,
        &[actual_dns.clone()]
    )
    .is_err());
    let mut incomplete = dns_child.clone();
    incomplete.pending = Some(actual_dns.clone());
    assert!(compare_guard_resource_journals(
        &record,
        &child,
        Some(&incomplete),
        actual_dns,
        &[actual_dns.clone()]
    )
    .is_err());
    assert!(compare_guard_resource_journals(
        &record,
        &child,
        None,
        actual_dns,
        &[actual_dns.clone()]
    )
    .is_err());
    let mut wrong = actual_dns.clone();
    wrong.settings.enable_llmnr ^= 1;
    assert!(compare_guard_resource_journals(
        &record,
        &child,
        Some(&dns_child),
        &wrong,
        &[wrong.clone()]
    )
    .is_err());
}

// Break: using the former Network target instead of recomputing stable routes and complete DNS metadata.
#[test]
fn guard_resources_recompute_exact_stable_routes_and_dns() {
    let (_, record, _) = guard_resource_fixture();
    let plan = compute_plan(
        &record,
        Slot::A,
        &physical(),
        &[InterfaceMetric {
            interface: 8,
            ipv6: false,
            metric: 5,
        }],
    )
    .unwrap();
    assert!(compare_guard_resource_plan(&record, &plan).is_ok());
    let mut drift = record.clone();
    drift.network.as_mut().unwrap().current.routes[0].metric += 1;
    assert!(compare_guard_resource_plan(&drift, &plan).is_err());
    drift = record.clone();
    drift
        .network
        .as_mut()
        .unwrap()
        .current
        .dns
        .as_mut()
        .unwrap()
        .settings
        .enable_llmnr = 1;
    assert!(compare_guard_resource_plan(&drift, &plan).is_err());
}

fn retired_resource_fixture() -> (Context, pair::Record) {
    let (context, mut record) = fixture();
    record.phase = pair::Phase::Closing;
    record.operation = None;
    record.active = None;
    record.stop_stage = 10;
    record.pending = Some(pair::Effect::Guard);
    record.network.as_mut().unwrap().pending = None;
    record.pending_guard = Some(
        policy::ExchangePlan::new(
            &record.guard,
            &policy::Model::empty(record.scope.clone()).unwrap(),
        )
        .unwrap(),
    );
    record.validate().unwrap();
    (context, record)
}

// Break: interpreting closed NICs or matching DNS baseline data as successful network restoration.
#[test]
fn retired_resources_require_stage_ten_restored_children_and_actual_baseline_ack() {
    let (context, record) = retired_resource_fixture();
    let baseline = record
        .network
        .as_ref()
        .unwrap()
        .baseline
        .dns
        .as_ref()
        .unwrap();
    let empty = NetworkJournal::default();
    assert!(compare_retired_resource_journals(
        &context,
        &record,
        &empty,
        false,
        &[baseline.clone()]
    )
    .is_ok());
    assert!(compare_retired_resource_journals(&context, &record, &empty, false, &[]).is_err());
    assert!(compare_retired_resource_journals(
        &context,
        &record,
        &empty,
        true,
        &[baseline.clone()]
    )
    .is_err());
    let mut drift = record.clone();
    drift.stop_stage = 9;
    assert!(compare_retired_resource_journals(
        &context,
        &drift,
        &empty,
        false,
        &[baseline.clone()]
    )
    .is_err());
    let mut drift = record.clone();
    drift
        .network
        .as_mut()
        .unwrap()
        .current
        .dns
        .as_mut()
        .unwrap()
        .settings
        .enable_llmnr = 1;
    assert!(compare_retired_resource_journals(
        &context,
        &drift,
        &empty,
        false,
        &[baseline.clone()]
    )
    .is_err());
}

// Break: using SDK absence to erase an unknown IO outcome or overlooking physical endpoint bypass leftovers.
#[test]
fn retired_route_reads_require_actual_delete_ack_and_full_table_absence() {
    let (_, record) = retired_resource_fixture();
    let bypass = Row::static_route(
        route("192.0.2.11/32", 20, 10, Some("192.0.2.1")),
        NativeProof {
            index: 20,
            luid: 200,
        },
    );
    let ack = RouteAttempt {
        row: bypass.clone(),
        deleting: true,
        acknowledged: true,
    };
    assert!(compare_retired_route_reads(&record, &[ack.clone()], &[]).is_ok());
    assert!(compare_retired_route_reads(&record, &[ack.clone()], &[bypass.clone()]).is_err());
    let unknown = RouteAttempt {
        acknowledged: false,
        ..ack.clone()
    };
    assert!(compare_retired_route_reads(&record, &[unknown], &[]).is_err());
    let held = RouteAttempt {
        deleting: false,
        ..ack
    };
    assert!(compare_retired_route_reads(&record, &[held], &[]).is_err());
    let c_row = Row::static_route(
        route("10.7.0.2/32", 7, 256, None),
        NativeProof { index: 7, luid: 90 },
    );
    assert!(compare_retired_route_reads(&record, &[], &[c_row]).is_err());
    let a_row = Row::static_route(
        route("0.0.0.0/1", 8, 0, None),
        NativeProof { index: 8, luid: 91 },
    );
    assert!(compare_retired_route_reads(&record, &[], &[a_row]).is_err());
}

// Break: recomputing future Attach/B routes at additive DENY-only Base instead of checking the held old network.
#[test]
fn static_base_checks_stable_network_without_future_operation_plan() {
    let (context, mut record, child) = guard_resource_fixture();
    record.phase = pair::Phase::Running;
    record.active = Some(Slot::A);
    record.operation = Some(pair::Operation::Attach(Slot::B));
    assert!(compare_static_base_resource_stage(&context, &record).is_ok());
    let n = record.network.as_ref().unwrap();
    let dns = n.current.dns.as_ref().unwrap();
    let dns_child = crate::member_pair::DnsRecord {
        baseline: n.baseline.dns.clone().unwrap(),
        current: dns.clone(),
        pending: None,
    };
    assert!(compare_guard_resource_journals(
        &record,
        &child,
        Some(&dns_child),
        dns,
        &[dns.clone()]
    )
    .is_ok());
    let mut drift = record.clone();
    let current = n.current.clone();
    drift.network.as_mut().unwrap().pending = Some(current);
    assert!(compare_static_base_resource_stage(&context, &drift).is_err());

    let mut first = record.clone();
    let base = policy::Model::new(
        first.scope.clone(),
        first.guard.carrier.clone().unwrap(),
        first.guard.members.clone(),
        None,
    )
    .unwrap()
    .without_permits()
    .unwrap();
    first.phase = pair::Phase::Starting;
    first.operation = Some(pair::Operation::Start(Slot::A));
    first.active = None;
    first.network = None;
    first.guard = policy::Model::empty(first.scope.clone()).unwrap();
    first.pending_guard = Some(policy::ExchangePlan::new(&first.guard, &base).unwrap());
    first.validate().unwrap();
    assert!(compare_static_base_resource_stage(&context, &first).is_ok());
}

// Break: accepting RestoreNetwork outside exactly Closing stage 2, or live use through Closing.
#[test]
fn exact_network_stage_selects_only_source_or_stage_two_closing() {
    let (c, r) = fixture();
    assert_eq!(compare_stage(&c, &r, false).unwrap(), Channel::Source);
    let mut stop = r.clone();
    stop.phase = pair::Phase::Closing;
    stop.active = None;
    stop.operation = None;
    stop.stop_stage = 2;
    stop.pending = Some(pair::Effect::RestoreNetwork);
    let n = stop.network.as_mut().unwrap();
    n.pending = Some(n.baseline.clone());
    assert_eq!(compare_stage(&c, &stop, true).unwrap(), Channel::Closing);
    assert!(compare_stage(&c, &stop, false).is_err());
    assert!(compare_stage(&c, &r, true).is_err());
    for stage in [0, 1, 3, 4, 7, 9, 10, 12] {
        let mut wrong = stop.clone();
        wrong.stop_stage = stage;
        assert!(compare_stage(&c, &wrong, true).is_err());
    }
    for effect in [
        pair::Effect::Guard,
        pair::Effect::WeakRows,
        pair::Effect::Data(Slot::A),
    ] {
        let mut wrong = r.clone();
        wrong.pending = Some(effect);
        assert!(compare_stage(&c, &wrong, false).is_err());
    }
}
// Break: accepting caller/default Guard, a surviving standby permit, or requested instead of captured priority.
#[test]
fn guard_requires_actual_complete_base_snapshot_and_captured_weight() {
    let (_, r) = fixture();
    assert!(compare_guard(&r, &r.guard.expected).is_ok());
    let mut missing = r.guard.expected.clone();
    missing.filters.pop();
    assert!(compare_guard(&r, &missing).is_err());
    let mut priority = r.guard.expected.clone();
    priority.sublayer.as_mut().unwrap().weight = 65534;
    assert!(compare_guard(&r, &priority).is_err());
    let mut allow = r.guard.expected.clone();
    allow.filters[0].action = policy::Action::Permit;
    assert!(compare_guard(&r, &allow).is_err());
    let empty = policy::Model::empty(r.scope.clone()).unwrap();
    assert!(compare_guard(&r, &empty.expected).is_err());
}
// Break: computing authorization from a subset, numeric member index, endpoint guess or altered DNS settings.
#[test]
fn computed_plan_requires_exact_routes_endpoints_options_and_dns_metadata() {
    let (_, r) = fixture();
    let metrics = [InterfaceMetric {
        interface: 8,
        ipv6: false,
        metric: 5,
    }];
    let computed = compute_plan(&r, Slot::A, &physical(), &metrics).unwrap();
    assert!(compare_desired(&r, &computed).is_ok());
    for fault in 0..7 {
        let mut wrong = r.clone();
        let n = wrong.network.as_mut().unwrap();
        let target = n.pending.as_mut().unwrap();
        match fault {
            0 => {
                target.routes.pop();
            }
            1 => target.routes[0].interface = 7,
            2 => target.routes[0].metric = 9,
            3 => target.routes[3].gateway = Some("192.0.2.2".parse().unwrap()),
            4 => target.dns.as_mut().unwrap().settings.enable_llmnr = 1,
            5 => target.routes.push(target.routes[0].clone()),
            _ => target.routes[3].destination = "192.0.2.22/32".parse().unwrap(),
        }
        assert!(compare_desired(&wrong, &computed).is_err(), "fault {fault}");
    }
    let mut changed = r.clone();
    changed.members[0].as_mut().unwrap().endpoint = "198.51.100.12".parse().unwrap();
    let recomputed = compute_plan(&changed, Slot::A, &physical(), &metrics).unwrap();
    assert!(compare_desired(&changed, &recomputed).is_err());
    let mut split = r.clone();
    let o = split.options.as_mut().unwrap();
    o.policy_hash = Some("policy".into());
    o.excluded_ipv4_cidrs = vec!["198.51.100.0/24".into()];
    let recomputed = compute_plan(&split, Slot::A, &physical(), &metrics).unwrap();
    assert!(compare_desired(&split, &recomputed).is_err());
    split.options.as_mut().unwrap().excluded_ipv4_cidrs = vec!["0.0.0.0/1".into()];
    // An exclusion covering the independently reserved probe has no accepted
    // route plan here. Reject it rather than use a partial/default plan.
    assert!(compute_plan(&split, Slot::A, &physical(), &metrics).is_err());
}
// Break: treating equal row lookup as the ACK of a prior effect or suppressing unknown SDK outcome.
#[test]
fn route_ack_requires_retained_success_and_all_native_metadata() {
    let row = Row::static_route(
        route("1.1.1.1/32", 8, 1, None),
        NativeProof { index: 8, luid: 91 },
    );
    assert!(compare_route_ack(&[], &row).is_err());
    let mut attempts = vec![RouteAttempt {
        row: row.clone(),
        deleting: false,
        acknowledged: false,
    }];
    assert!(compare_route_ack(&attempts, &row).is_err());
    attempts[0].acknowledged = true;
    assert!(compare_route_ack(&attempts, &row).is_ok());
    for fault in 0..8 {
        let mut foreign = row.clone();
        match fault {
            0 => foreign.luid += 1,
            1 => foreign.protocol += 1,
            2 => foreign.origin += 1,
            3 => foreign.site_prefix_length = 1,
            4 => foreign.valid_lifetime -= 1,
            5 => foreign.preferred_lifetime -= 1,
            6 => foreign.flags[0] = 1,
            _ => foreign.route.metric += 1,
        }
        assert!(compare_route_ack(&attempts, &foreign).is_err());
    }
    attempts.push(RouteAttempt {
        row: row.clone(),
        deleting: true,
        acknowledged: true,
    });
    assert!(compare_route_ack(&attempts, &row).is_err());
}
// Break: reading post-effect DNS equals pending JSON without requiring the actual SAME-owner native ACK.
#[test]
fn dns_before_or_after_coverage_never_converts_target_equality_to_ack() {
    let (_, r) = fixture();
    let n = r.network.as_ref().unwrap();
    let before = n.current.dns.as_ref().unwrap();
    let after = n.pending.as_ref().unwrap().dns.as_ref().unwrap();
    assert!(compare_dns_read(&r, before, &[]).is_ok());
    assert!(compare_dns_read(&r, after, &[]).is_err());
    assert!(compare_dns_read(&r, after, std::slice::from_ref(after)).is_ok());
    let mut foreign = after.clone();
    foreign.settings.search_list = Some("foreign.example".into());
    assert!(compare_dns_read(&r, &foreign, std::slice::from_ref(after)).is_err());
}
// Break: reentry/unwind/caught nested errors restore forward authorization or erase an outstanding cleanup obligation.
#[test]
fn gate_fence_is_sticky_on_nested_denial_and_unwind() {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    let fence = GateFence::default();
    assert!(fence
        .run(false, || {
            let _ = fence.run(false, || Ok(()));
            Ok(())
        })
        .is_err());
    assert!(fence.run(false, || Ok(())).is_err());
    assert!(fence.run(true, || Ok(())).is_ok());
    let fence = GateFence::default();
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _ = fence.run(false, || -> io::Result<()> { panic!("native read unwind") });
    }));
    assert!(fence.run(false, || Ok(())).is_err());
    assert!(fence.run(true, || Ok(())).is_ok());
}

fn journal(
    current: &[RouteValue],
    pending: Option<&[RouteValue]>,
    stopping: bool,
) -> NetworkJournal {
    // Comparison bytes only; never imported into the concrete owner or G.
    let entries = |routes: &[RouteValue]| {
        routes
            .iter()
            .map(|r| {
                serde_json::json!({"original":null,
        "current":NetworkValue::Route(r.clone())})
            })
            .collect::<Vec<_>>()
    };
    serde_json::from_value(serde_json::json!({"owned":entries(current),"active":null,
        "pending":pending.map(|r|serde_json::json!({"target":entries(r),"active":"A"})),"stopping":stopping})).unwrap()
}
// Break: authorizing a route effect before the exact protected child pending plan exists.
#[test]
fn route_effect_requires_exact_pending_plan_and_actual_before_row() {
    let (_, r) = fixture();
    let routes = &r.network.as_ref().unwrap().pending.as_ref().unwrap().routes;
    let row = Row::static_route(routes[2].clone(), NativeProof { index: 8, luid: 91 });
    let pending = journal(&[], Some(routes), false);
    let fresh = journal(&[], None, false);
    assert!(compare_route_effect(
        &r,
        &fresh,
        &[],
        &[],
        &row,
        RouteEffect::Create,
        NativeProof { index: 8, luid: 91 }
    )
    .is_err());
    assert!(compare_route_effect(
        &r,
        &pending,
        &[],
        &[],
        &row,
        RouteEffect::Create,
        NativeProof { index: 8, luid: 91 }
    )
    .is_ok());
    assert!(compare_route_effect(
        &r,
        &pending,
        &[],
        std::slice::from_ref(&row),
        &row,
        RouteEffect::Create,
        NativeProof { index: 8, luid: 91 }
    )
    .is_err());
    let unknown = [RouteAttempt {
        row: row.clone(),
        deleting: false,
        acknowledged: false,
    }];
    assert!(compare_route_effect(
        &r,
        &pending,
        &unknown,
        &[],
        &row,
        RouteEffect::Create,
        NativeProof { index: 8, luid: 91 }
    )
    .is_err());
    let mut wrong = row.clone();
    wrong.flags[2] = 1;
    assert!(compare_route_effect(
        &r,
        &pending,
        &[],
        &[],
        &wrong,
        RouteEffect::Create,
        NativeProof { index: 8, luid: 91 }
    )
    .is_err());
}
// Break: deleting foreign or unacknowledged routes during cleanup, or creating an unplanned route.
#[test]
fn route_delete_needs_same_owner_sdk_ack_even_when_native_equals_journal() {
    let (_, mut r) = fixture();
    let old = r
        .network
        .as_ref()
        .unwrap()
        .pending
        .as_ref()
        .unwrap()
        .clone();
    r.phase = pair::Phase::Closing;
    r.operation = None;
    r.stop_stage = 2;
    r.pending = Some(pair::Effect::RestoreNetwork);
    r.network.as_mut().unwrap().current = old.clone();
    let baseline = r.network.as_ref().unwrap().baseline.clone();
    r.network.as_mut().unwrap().pending = Some(baseline);
    let mut pending = journal(&old.routes, Some(&[]), true);
    let mut bytes = serde_json::to_value(&pending).unwrap();
    bytes["pending"]["active"] = serde_json::Value::Null;
    pending = serde_json::from_value(bytes).unwrap();
    let row = Row::static_route(old.routes[2].clone(), NativeProof { index: 8, luid: 91 });
    let actual = [row.clone()];
    assert!(compare_route_effect(
        &r,
        &pending,
        &[],
        &actual,
        &row,
        RouteEffect::Delete,
        NativeProof { index: 8, luid: 91 }
    )
    .is_err());
    let ack = [RouteAttempt {
        row: row.clone(),
        deleting: false,
        acknowledged: true,
    }];
    assert!(compare_route_effect(
        &r,
        &pending,
        &ack,
        &actual,
        &row,
        RouteEffect::Delete,
        NativeProof { index: 8, luid: 91 }
    )
    .is_ok());
    let mut foreign = actual.clone();
    foreign[0].origin = 1;
    assert!(compare_route_effect(
        &r,
        &pending,
        &ack,
        &foreign,
        &row,
        RouteEffect::Delete,
        NativeProof { index: 8, luid: 91 }
    )
    .is_err());
    assert!(compare_route_effect(
        &r,
        &pending,
        &ack,
        &actual,
        &row,
        RouteEffect::Create,
        NativeProof { index: 8, luid: 91 }
    )
    .is_err());
}
// Break: truncating a pending journal, selecting wrong active slot or importing a preexisting original route.
#[test]
fn child_journal_covers_whole_plan_without_adoption() {
    let (_, r) = fixture();
    let target = &r.network.as_ref().unwrap().pending.as_ref().unwrap().routes;
    assert!(compare_journal(&r, &journal(&[], Some(target), false), false).is_ok());
    assert!(compare_journal(&r, &journal(&[], Some(&target[..3]), false), false).is_err());
    let base = serde_json::to_value(journal(&[], Some(target), false)).unwrap();
    for fault in 0..4 {
        let mut value = base.clone();
        match fault {
            0 => value["pending"]["active"] = serde_json::json!("B"),
            1 => value["stopping"] = serde_json::json!(true),
            2 => {
                value["pending"]["target"][0]["original"] =
                    value["pending"]["target"][0]["current"].clone()
            }
            _ => value["pending"]["target"][0]["current"] = serde_json::json!({"LinkDnsRoute":8}),
        }
        let bad = serde_json::from_value(value).unwrap();
        assert!(compare_journal(&r, &bad, false).is_err());
    }
}
// Break: treating protected before/after routes as proof that native effects succeeded.
#[test]
fn route_reads_require_every_present_key_ack_and_reject_extra_member_rows() {
    let (_, r) = fixture();
    let target = &r.network.as_ref().unwrap().pending.as_ref().unwrap().routes;
    let pending = journal(&[], Some(target), false);
    let row = Row::static_route(target[2].clone(), NativeProof { index: 8, luid: 91 });
    assert!(compare_route_reads(&r, &pending, &[], std::slice::from_ref(&row)).is_err());
    let ack = [RouteAttempt {
        row: row.clone(),
        deleting: false,
        acknowledged: true,
    }];
    assert!(compare_route_reads(&r, &pending, &ack, std::slice::from_ref(&row)).is_ok());
    let mut rows = vec![row.clone(), row.clone()];
    assert!(compare_route_reads(&r, &pending, &ack, &rows).is_err());
    rows[1].route.destination = "203.0.113.7/32".parse().unwrap();
    assert!(compare_route_reads(&r, &pending, &ack, &rows).is_err());
}

fn resource_records(c: &Context, r: &pair::Record) -> [Option<rows::Record>; 3] {
    let proofs = [
        r.carrier,
        r.members[0]
            .as_ref()
            .and_then(|m| m.owner.proof.map(|p| p.interface)),
        r.members[1]
            .as_ref()
            .and_then(|m| m.owner.proof.map(|p| p.interface)),
    ];
    std::array::from_fn(|i| {
        proofs[i].map(|p| {
            let key = rows::RowKey {
                index: p.index,
                luid: p.luid,
            };
            let baseline = rows::Snapshot {
                interface: rows::InterfaceRow {
                    key,
                    policy: rows::InterfacePolicy {
                        advertising: false,
                        forwarding: false,
                        weak_host_send: false,
                        weak_host_receive: false,
                        automatic_metric: false,
                        neighbor_unreachability: true,
                        managed_address_configuration: false,
                        other_stateful_configuration: false,
                        advertise_default_route: false,
                        router_discovery: 0,
                        dad_transmits: 1,
                        base_reachable_time: 30000,
                        retransmit_time: 1000,
                        path_mtu_discovery_timeout: 600000,
                        link_local_behavior: 0,
                        link_local_timeout: 0,
                        zone_indices: [0; 16],
                        site_prefix_length: 0,
                        metric: 5,
                        mtu: 1420,
                        disable_default_routes: true,
                    },
                    observed: rows::InterfaceObserved {
                        max_reassembly_size: 0,
                        interface_identifier: 0,
                        min_router_advertisement_interval: 200,
                        max_router_advertisement_interval: 600,
                        connected: true,
                        supports_wake_up_patterns: false,
                        supports_neighbor_discovery: true,
                        supports_router_discovery: true,
                        reachable_time: 27000,
                        transmit_offload: 0,
                        receive_offload: 0,
                    },
                },
                address: None,
            };
            let mut current = baseline.clone();
            current.interface.policy.weak_host_send = true;
            current.interface.policy.weak_host_receive = true;
            let address = (i == 0).then_some(rows::AddressRow {
                key,
                policy: rows::AddressPolicy {
                    address: [10, 7, 0, 2],
                    prefix_origin: 1,
                    suffix_origin: 1,
                    valid_lifetime: u32::MAX,
                    preferred_lifetime: u32::MAX,
                    on_link_prefix_length: 32,
                    skip_as_source: false,
                },
                observed: rows::AddressObserved {
                    dad_state: 4,
                    scope_id: 0,
                    creation_timestamp: 123456789,
                },
            });
            current.address = address.clone();
            let saved = rows::Record {
                version: 1,
                domain: rows::DOMAIN.into(),
                binding: rows::Binding {
                    scope: r.scope.clone(),
                    boot_id: c.provenance.boot_id,
                    runtime: c.provenance.runtime.clone(),
                    network_epoch: c.provenance.network_epoch,
                    role: [
                        rows::Role::Carrier,
                        rows::Role::MemberA,
                        rows::Role::MemberB,
                    ][i],
                    guid: p.guid,
                    name: c.bindings[i].name.clone(),
                    key,
                    address: [10, 7, 0, 2],
                },
                revision: 5,
                phase: rows::Phase::Captured,
                baseline,
                current,
                pending: None,
                creation: address,
            };
            saved.validate().unwrap();
            saved
        })
    })
}
fn resource_facts(records: &[Option<rows::Record>; 3]) -> ResourceRows<'_> {
    records
        .each_ref()
        .map(|r| r.as_ref().map(|r| (&r.binding, r, &r.current)))
}

fn normal_retire_fixture() -> (
    Context,
    pair::Record,
    pair::Record,
    [Option<rows::Record>; 3],
    carrier_members::ClosedMemberBinding,
) {
    let (context, mut selected) = fixture();
    let mut b = selected.members[0].clone().unwrap();
    b.owner.intent.slot = TunnelSlot::B;
    b.owner.intent.config_sha256 = [5; 32];
    let proof = b.owner.proof.as_mut().unwrap();
    proof.interface = owner::InterfaceProof {
        index: 9,
        luid: 92,
        guid: [3; 16],
    };
    proof.process.pid = 51;
    proof.process.creation_time = 101;
    b.lease_id = "33333333-3333-4333-8333-333333333333".into();
    b.endpoint = "192.0.2.12".parse().unwrap();
    selected.members[1] = Some(b);
    selected.phase = pair::Phase::Running;
    selected.operation = Some(pair::Operation::Retire(Slot::A));
    selected.active = Some(Slot::B);
    selected.guard = policy::Model::new(
        selected.scope.clone(),
        selected.guard.carrier.clone().unwrap(),
        [
            selected.guard.members[0].clone(),
            Some(policy::Member {
                identity: policy::Identity {
                    scope: selected.scope.clone(),
                    proof: selected.members[1]
                        .as_ref()
                        .unwrap()
                        .owner
                        .proof
                        .unwrap()
                        .interface,
                },
                probes: vec![],
            }),
        ],
        None,
    )
    .unwrap()
    .inherit_sublayer_weight(&selected.guard)
    .unwrap();
    selected
        .network
        .as_mut()
        .unwrap()
        .pending
        .as_mut()
        .unwrap()
        .routes = vec![route("0.0.0.0/0", 9, 10, None)];
    selected.validate().unwrap();
    let mut rows = resource_records(&context, &selected);
    let a = rows[1].as_mut().unwrap();
    a.current = a.baseline.clone();
    a.phase = rows::Phase::Stopped;
    let closed = carrier_members::ClosedMemberBinding {
        intent: selected.members[0].as_ref().unwrap().owner.intent.clone(),
        proof: selected.members[0].as_ref().unwrap().owner.proof.unwrap(),
    };
    let mut current = selected.clone();
    current.revision += 5;
    current.pending = Some(pair::Effect::Guard);
    current.network.as_mut().unwrap().current =
        current.network.as_mut().unwrap().pending.take().unwrap();
    current.members[0] = None;
    let base = policy::Model::new(
        current.scope.clone(),
        current.guard.carrier.clone().unwrap(),
        [None, current.guard.members[1].clone()],
        None,
    )
    .unwrap()
    .inherit_sublayer_weight(&current.guard)
    .unwrap();
    let desired = policy::Model::new(
        current.scope.clone(),
        base.carrier.clone().unwrap(),
        base.members.clone(),
        Some(Slot::B),
    )
    .unwrap()
    .inherit_sublayer_weight(&base)
    .unwrap();
    current.pending_guard = Some(policy::ExchangePlan::new(&base, &desired).unwrap());
    current.guard = current.pending_guard.as_ref().unwrap().base.clone();
    current.validate().unwrap();
    (context, selected, current, rows, closed)
}

// Break: after native Stop, Pair target still Running or removed is accepted
// from observedNone alone, or its historical metric enters the surviving plan.
#[test]
fn normal_retire_guard_rows_require_typed_original_stopped_history() {
    let (c, old, mut r, resources, closed) = normal_retire_fixture();
    let data = resources.each_ref().map(|row| {
        row.as_ref().map(|row| {
            (
                &row.binding,
                row,
                (row.binding.role != rows::Role::MemberA).then_some(&row.current),
            )
        })
    });
    let metrics = compare_guard_resource_rows(&c, &r, data, [Some(&closed), None]).unwrap();
    assert_eq!(metrics.len(), 1);
    assert_eq!(metrics[0].interface, 9);
    assert!(compare_guard_resource_rows(&c, &r, data, [None, None]).is_err());
    r.members[0] = old.members[0].clone();
    assert_eq!(
        compare_guard_resource_rows(&c, &r, data, [Some(&closed), None]).unwrap()[0].interface,
        9
    );
    let mut wrong = closed.clone();
    wrong.proof.process.creation_time += 1;
    assert!(compare_guard_resource_rows(&c, &r, data, [Some(&wrong), None]).is_err());
    assert!(compare_guard_resource_rows(&c, &old, data, [Some(&closed), None]).is_err());
    let mut bad = resources.clone();
    bad[1].as_mut().unwrap().phase = rows::Phase::Captured;
    let bad_data = bad.each_ref().map(|row| {
        row.as_ref().map(|row| {
            (
                &row.binding,
                row,
                (row.binding.role != rows::Role::MemberA).then_some(&row.current),
            )
        })
    });
    assert!(compare_guard_resource_rows(&c, &r, bad_data, [Some(&closed), None]).is_err());
    bad = resources.clone();
    bad[1].as_mut().unwrap().current.interface.policy.metric += 1;
    let bad_data = bad.each_ref().map(|row| {
        row.as_ref().map(|row| {
            (
                &row.binding,
                row,
                (row.binding.role != rows::Role::MemberA).then_some(&row.current),
            )
        })
    });
    assert!(compare_guard_resource_rows(&c, &r, bad_data, [Some(&closed), None]).is_err());
}

// Break: Retire lineage becomes arbitrary membership removal/replacement or
// accepts another current network instead of the original committed target.
#[test]
fn normal_retire_lineage_only_removes_exact_target_and_preserves_network() {
    let (_, old, r, _, _) = normal_retire_fixture();
    assert_eq!(
        compare_guard_member_lineage(&old, &r).unwrap(),
        Some(Slot::A)
    );
    let mut before = r.clone();
    before.members = old.members.clone();
    assert_eq!(compare_guard_member_lineage(&old, &before).unwrap(), None);
    for change in 0..5 {
        let mut wrong = r.clone();
        match change {
            0 => wrong.operation = Some(pair::Operation::Retire(Slot::B)),
            1 => wrong.members[1] = None,
            2 => wrong.members[1].as_mut().unwrap().peer = [8; 32],
            3 => wrong.network.as_mut().unwrap().current.routes[0].metric += 1,
            _ => wrong.network.as_mut().unwrap().current.routes.push(route(
                "1.1.1.1/32",
                8,
                10,
                None,
            )),
        }
        assert!(
            compare_guard_member_lineage(&old, &wrong).is_err(),
            "change {change}"
        );
    }
}
// Break: authorizing from Source identities without exact original protected row ACK/SDK values.
#[test]
fn resource_rows_require_ready_c_addressless_members_and_exact_weak_delta() {
    let (c, r) = fixture();
    let resources = resource_records(&c, &r);
    let metrics = compare_resource_rows(&c, &r, resource_facts(&resources)).unwrap();
    assert_eq!(metrics.len(), 1);
    assert_eq!(metrics[0].interface, 8);
    assert_eq!(metrics[0].metric, 5);
    for fault in 0..9 {
        let mut wrong = resources.clone();
        let carrier = wrong[0].as_mut().unwrap();
        match fault {
            0 => carrier.current.address.as_mut().unwrap().observed.dad_state = 1,
            1 => {
                carrier
                    .current
                    .address
                    .as_mut()
                    .unwrap()
                    .observed
                    .creation_timestamp += 1
            }
            2 => carrier.current.interface.policy.weak_host_send = false,
            3 => carrier.current.interface.policy.forwarding = true,
            4 => carrier.current.interface.policy.mtu += 1,
            5 => carrier.binding.guid = [9; 16],
            6 => {
                carrier.pending = Some(rows::Pending {
                    before: carrier.current.clone(),
                    target: rows::Target::Interface(carrier.current.interface.policy.clone()),
                })
            }
            7 => wrong[1] = None,
            _ => carrier.creation = None,
        }
        assert!(
            compare_resource_rows(&c, &r, resource_facts(&wrong)).is_err(),
            "fault {fault}"
        );
    }
    let mut actual = resources[0].as_ref().unwrap().current.clone();
    actual.interface.policy.metric += 1;
    let carrier = resources[0].as_ref().unwrap();
    let member = resources[1].as_ref().unwrap();
    assert!(compare_resource_rows(
        &c,
        &r,
        [
            Some((&carrier.binding, carrier, &actual)),
            Some((&member.binding, member, &member.current)),
            None
        ]
    )
    .is_err());
}
// Break: permitting DNS SDK writes before the exact child pending state and actual current snapshot are covered.
#[test]
fn dns_effect_requires_exact_child_pending_full_before_and_target() {
    let (_, r) = fixture();
    let n = r.network.as_ref().unwrap();
    let before = n.current.dns.as_ref().unwrap();
    let desired = n.pending.as_ref().unwrap().dns.as_ref().unwrap();
    let child = crate::member_pair::DnsRecord {
        baseline: before.clone(),
        current: before.clone(),
        pending: Some(desired.clone()),
    };
    assert!(compare_dns_effect(&r, Some(&child), before, desired, before, &[]).is_ok());
    assert!(compare_dns_effect(&r, None, before, desired, before, &[]).is_err());
    let mut wrong = child.clone();
    wrong.pending = None;
    assert!(compare_dns_effect(&r, Some(&wrong), before, desired, before, &[]).is_err());
    let mut wrong = before.clone();
    wrong.settings.registration_enabled = 1;
    assert!(compare_dns_effect(&r, Some(&child), &wrong, desired, &wrong, &[]).is_err());
    assert!(compare_dns_effect(&r, Some(&child), before, desired, desired, &[]).is_err());
}

// Break: allowing a metric Set from a foreign/missing native row or using Set to change a gateway.
#[test]
fn metric_set_requires_same_original_ack_and_gateway() {
    let (_, mut r) = fixture();
    let after = r
        .network
        .as_ref()
        .unwrap()
        .pending
        .as_ref()
        .unwrap()
        .routes
        .clone();
    let mut before = after.clone();
    before[2].metric = 100;
    r.network.as_mut().unwrap().current.routes = before.clone();
    let pending = journal(&before, Some(&after), false);
    let proof = NativeProof { index: 8, luid: 91 };
    let old = Row::static_route(before[2].clone(), proof);
    let new = Row::static_route(after[2].clone(), proof);
    let ack = [RouteAttempt {
        row: old.clone(),
        deleting: false,
        acknowledged: true,
    }];
    assert!(compare_route_effect(
        &r,
        &pending,
        &ack,
        std::slice::from_ref(&old),
        &new,
        RouteEffect::Set,
        proof
    )
    .is_ok());
    assert!(compare_route_effect(&r, &pending, &ack, &[], &new, RouteEffect::Set, proof).is_err());
    let mut wrong = new.clone();
    wrong.route.gateway = Some("192.0.2.1".parse().unwrap());
    assert!(compare_route_effect(
        &r,
        &pending,
        &ack,
        std::slice::from_ref(&old),
        &wrong,
        RouteEffect::Set,
        proof
    )
    .is_err());
    let mut unknown = ack.clone();
    unknown[0].acknowledged = false;
    assert!(compare_route_effect(
        &r,
        &pending,
        &unknown,
        std::slice::from_ref(&old),
        &new,
        RouteEffect::Set,
        proof
    )
    .is_err());
}
