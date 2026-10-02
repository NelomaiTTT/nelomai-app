use super::{compare, Stage};
use crate::member_carrier_rows::*;
use nelomai_client_tunnel::redundancy::SessionScope;
use nelomai_contracts::{dispatcher::EngineIdentity, RuntimeSlot};

// Hand-derived complete portable rows. No decoder, kernel, ACK, or default mock.
fn captured() -> Record {
    let baseline = Snapshot {
        interface: InterfaceRow {
            key: RowKey {
                luid: 3300,
                index: 33,
            },
            policy: InterfacePolicy {
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
                metric: 42,
                mtu: 1420,
                disable_default_routes: true,
            },
            observed: InterfaceObserved {
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
    Record {
        version: 1,
        domain: "carrier-native-ipv4-rows-v1".into(),
        binding: Binding {
            scope: SessionScope {
                runtime: RuntimeSlot::Stable,
                runtime_generation: 1,
                session_id: "11111111-1111-4111-8111-111111111111".into(),
                connection_generation: 2,
            },
            boot_id: [7; 16],
            runtime: EngineIdentity {
                slot: RuntimeSlot::Stable,
                runtime_version: "1.0.0".into(),
                runtime_contract_version: 1,
                container_version: "1.0.0".into(),
                manifest_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .into(),
            },
            network_epoch: 1,
            role: Role::Carrier,
            guid: [3; 16],
            name: "owned-C".into(),
            key: RowKey {
                luid: 3300,
                index: 33,
            },
            address: [10, 77, 0, 2],
        },
        revision: 1,
        phase: Phase::Captured,
        current: baseline.clone(),
        baseline,
        pending: None,
        creation: None,
    }
}

fn created_address() -> AddressRow {
    AddressRow {
        key: RowKey {
            luid: 3300,
            index: 33,
        },
        policy: AddressPolicy {
            address: [10, 77, 0, 2],
            prefix_origin: 1,
            suffix_origin: 1,
            valid_lifetime: 4294967295,
            preferred_lifetime: 4294967295,
            on_link_prefix_length: 32,
            skip_as_source: false,
        },
        observed: AddressObserved {
            dad_state: 1,
            scope_id: 0,
            creation_timestamp: 123456789,
        },
    }
}

fn owned() -> Record {
    let mut saved = captured();
    saved.revision = 3;
    saved.current.address = Some(created_address());
    saved.creation = Some(created_address());
    saved
}

fn deleting() -> Record {
    let mut saved = owned();
    saved.phase = Phase::Closing;
    saved.revision = 5;
    saved.pending = Some(Pending {
        before: saved.current.clone(),
        target: Target::Delete,
    });
    saved
}

fn stopped() -> Record {
    let mut saved = owned();
    saved.phase = Phase::Stopped;
    saved.revision = 7;
    saved.current.address = None;
    saved
}

fn accepts(saved: &Record, actual: &Snapshot, stage: Stage) {
    assert_eq!(compare(&saved.binding, saved, actual, stage), Ok(()));
}

fn denies(saved: &Record, actual: &Snapshot, stage: Stage) {
    assert!(compare(&saved.binding, saved, actual, stage).is_err());
}

// Break: refusing a valid phase or treating readonly observations as policy drift.
#[test]
fn observe_accepts_exact_current_in_all_three_phases_and_readonly_changes() {
    for saved in [captured(), owned(), deleting(), stopped()] {
        accepts(&saved, &saved.current, Stage::Observe);
        let mut actual = saved.current.clone();
        actual.interface.observed.connected = false;
        actual.interface.observed.reachable_time = 31415;
        actual.interface.observed.supports_wake_up_patterns = true;
        actual.interface.observed.transmit_offload = 1;
        if let Some(address) = &mut actual.address {
            address.observed.dad_state = 4;
        }
        accepts(&saved, &actual, Stage::Observe);
    }
}

// Break: allowing member rows into this carrier-only gate.
#[test]
fn rejects_non_carrier_even_with_an_exact_valid_saved_binding() {
    for role in [Role::MemberA, Role::MemberB] {
        let mut saved = captured();
        saved.binding.role = role;
        assert_eq!(saved.validate(), Ok(()));
        denies(&saved, &saved.current, Stage::Observe);
    }
}

// Break: comparing a subset of the runtime/session/native binding.
#[test]
fn rejects_every_foreign_binding_dimension() {
    let saved = captured();
    let mutations: &[fn(&mut Binding)] = &[
        |b| b.scope.runtime_generation += 1,
        |b| b.scope.connection_generation += 1,
        |b| b.scope.session_id = "22222222-2222-4222-8222-222222222222".into(),
        |b| b.boot_id[0] = 8,
        |b| b.runtime.runtime_version = "2.0.0".into(),
        |b| b.runtime.container_version = "2.0.0".into(),
        |b| b.runtime.runtime_contract_version = 2,
        |b| b.runtime.manifest_sha256 = "b".repeat(64),
        |b| b.network_epoch = 2,
        |b| b.role = Role::MemberA,
        |b| b.guid[0] = 4,
        |b| b.name = "foreign-C".into(),
        |b| b.key.luid = 3400,
        |b| b.key.index = 34,
        |b| b.address[3] = 3,
    ];
    for (case, mutate) in mutations.iter().enumerate() {
        let mut binding = saved.binding.clone();
        mutate(&mut binding);
        assert!(
            compare(&binding, &saved, &saved.current, Stage::Observe).is_err(),
            "binding case {case}"
        );
    }
}

// Break: skipping full saved.validate because selected fields look plausible.
#[test]
fn rejects_invalid_saved_records_instead_of_only_checking_policy() {
    let mutations: &[fn(&mut Record)] = &[
        |s| s.version = 2,
        |s| s.domain = "foreign".into(),
        |s| s.revision = 0,
        |s| s.binding.name.clear(),
        |s| s.binding.scope.runtime_generation = 0,
        |s| s.baseline.interface.key.index = 34,
        |s| s.baseline.interface.observed.interface_identifier = 1,
        |s| s.current.interface.observed.max_reassembly_size = 1,
        |s| s.baseline.address = Some(created_address()),
        |s| s.creation.as_mut().unwrap().observed.creation_timestamp = 0,
        |s| s.creation.as_mut().unwrap().policy.on_link_prefix_length = 24,
        |s| s.creation.as_mut().unwrap().observed.dad_state = 5,
        |s| s.creation.as_mut().unwrap().observed.scope_id = 1,
        |s| {
            s.current
                .address
                .as_mut()
                .unwrap()
                .observed
                .creation_timestamp += 1
        },
    ];
    for (case, mutate) in mutations.iter().enumerate() {
        let mut saved = owned();
        mutate(&mut saved);
        assert!(
            compare(&saved.binding, &saved, &saved.current, Stage::Observe).is_err(),
            "saved case {case}"
        );
    }
}

// Break: relying on same_owned while ignoring unsupported/foreign actual fields.
#[test]
fn rejects_invalid_or_foreign_actual_rows() {
    let saved = owned();
    let mutations: &[fn(&mut Snapshot)] = &[
        |a| a.interface.key.index = 34,
        |a| a.interface.key.luid = 3400,
        |a| a.interface.observed.max_reassembly_size = 1,
        |a| a.interface.observed.interface_identifier = 1,
        |a| a.interface.policy.router_discovery = 3,
        |a| a.interface.policy.link_local_behavior = 3,
        |a| a.interface.policy.mtu = 67,
        |a| a.address.as_mut().unwrap().key.index = 34,
        |a| a.address.as_mut().unwrap().key.luid = 0,
        |a| a.address.as_mut().unwrap().policy.address[3] = 3,
        |a| a.address.as_mut().unwrap().policy.suffix_origin = 6,
        |a| a.address.as_mut().unwrap().observed.dad_state = 5,
        |a| a.address.as_mut().unwrap().observed.creation_timestamp = -1,
    ];
    for (case, mutate) in mutations.iter().enumerate() {
        let mut actual = saved.current.clone();
        mutate(&mut actual);
        assert!(
            compare(&saved.binding, &saved, &actual, Stage::Observe).is_err(),
            "actual case {case}"
        );
    }
}

// Break: accepting even matching weak/forwarding/advertising baseline policy.
#[test]
fn rejects_each_forbidden_c_only_flag_even_when_all_policies_match() {
    let mutations: &[fn(&mut InterfacePolicy)] = &[
        |p| p.weak_host_send = true,
        |p| p.weak_host_receive = true,
        |p| p.forwarding = true,
        |p| p.advertising = true,
    ];
    for mutate in mutations {
        for (mut saved, stage) in [
            (owned(), Stage::Observe),
            (deleting(), Stage::Delete),
            (stopped(), Stage::Stopped),
        ] {
            mutate(&mut saved.baseline.interface.policy);
            mutate(&mut saved.current.interface.policy);
            if let Some(p) = &mut saved.pending {
                mutate(&mut p.before.interface.policy);
            }
            assert_eq!(saved.validate(), Ok(()));
            denies(&saved, &saved.current, stage);
        }
    }
}

// Break: treating portable weak-host ownership as permission for the C-only path.
#[test]
fn rejects_saved_current_weak_drift_even_when_actual_matches_current() {
    for send in [true, false] {
        let mut saved = owned();
        if send {
            saved.current.interface.policy.weak_host_send = true;
        } else {
            saved.current.interface.policy.weak_host_receive = true;
        }
        assert_eq!(saved.validate(), Ok(()));
        denies(&saved, &saved.current, Stage::Observe);
    }
}

// Break: omitting any writable field from the full interface-policy CAS.
#[test]
fn rejects_every_actual_interface_policy_drift() {
    let mutations: &[fn(&mut InterfacePolicy)] = &[
        |p| p.advertising = true,
        |p| p.forwarding = true,
        |p| p.weak_host_send = true,
        |p| p.weak_host_receive = true,
        |p| p.automatic_metric = true,
        |p| p.neighbor_unreachability = false,
        |p| p.managed_address_configuration = true,
        |p| p.other_stateful_configuration = true,
        |p| p.advertise_default_route = true,
        |p| p.router_discovery = 1,
        |p| p.dad_transmits = 2,
        |p| p.base_reachable_time += 1,
        |p| p.retransmit_time += 1,
        |p| p.path_mtu_discovery_timeout += 1,
        |p| p.link_local_behavior = 1,
        |p| p.link_local_timeout = 1,
        |p| p.zone_indices[15] = 33,
        |p| p.site_prefix_length = 1,
        |p| p.metric = 43,
        |p| p.mtu = 1500,
        |p| p.disable_default_routes = false,
    ];
    for (case, mutate) in mutations.iter().enumerate() {
        for (saved, stage) in [
            (owned(), Stage::Observe),
            (deleting(), Stage::Delete),
            (stopped(), Stage::Stopped),
        ] {
            let mut actual = saved.current.clone();
            mutate(&mut actual.interface.policy);
            assert!(
                compare(&saved.binding, &saved, &actual, stage).is_err(),
                "policy case {case}, {stage:?}"
            );
        }
    }
}

// Break: confusing a preferred replacement/policy drift with the original creation.
#[test]
fn preferred_dad_does_not_bypass_exact_address_policy_scope_or_creation_stamp() {
    let saved = owned();
    let mutations: &[fn(&mut AddressRow)] = &[
        |a| a.policy.prefix_origin = 2,
        |a| a.policy.suffix_origin = 2,
        |a| a.policy.valid_lifetime = 1000,
        |a| a.policy.preferred_lifetime = 1000,
        |a| a.policy.on_link_prefix_length = 24,
        |a| a.policy.skip_as_source = true,
        |a| a.observed.scope_id = 1,
        |a| a.observed.creation_timestamp += 1,
    ];
    for mutate in mutations {
        let mut actual = saved.current.clone();
        let address = actual.address.as_mut().unwrap();
        address.observed.dad_state = 4;
        mutate(address);
        denies(&saved, &actual, Stage::Observe);
    }
    for dad_state in [0, 1, 2, 3, 4] {
        let mut actual = saved.current.clone();
        actual.address.as_mut().unwrap().observed.dad_state = dad_state;
        accepts(&saved, &actual, Stage::Observe); // No readiness result is issued.
    }
}

// Break: adopting a matching address without recorded creation history.
#[test]
fn rejects_unrecorded_or_unexpected_current_address_and_absence() {
    let saved = captured();
    let mut actual = saved.current.clone();
    actual.address = Some(created_address());
    denies(&saved, &actual, Stage::Observe);
    let mut saved = owned();
    let actual = saved.current.clone();
    saved.creation = None;
    denies(&saved, &actual, Stage::Observe);
    let saved = owned();
    let mut actual = saved.current.clone();
    actual.address = None;
    denies(&saved, &actual, Stage::Observe);
}

// Break: admitting pending interface changes instead of exact baseline policy.
#[test]
fn interface_pending_only_accepts_exact_baseline_without_weak_delta() {
    for phase in [Phase::Captured, Phase::Closing] {
        let mut saved = owned();
        saved.phase = phase;
        saved.pending = Some(Pending {
            before: saved.current.clone(),
            target: Target::Interface(saved.baseline.interface.policy.clone()),
        });
        accepts(&saved, &saved.current, Stage::Observe);
        denies(&saved, &saved.current, Stage::Delete);
        let mut target = saved.baseline.interface.policy.clone();
        target.weak_host_send = true;
        saved.pending.as_mut().unwrap().target = Target::Interface(target);
        denies(&saved, &saved.current, Stage::Observe);
    }
    let mut saved = owned();
    saved.phase = Phase::Closing;
    saved.current.interface.policy.weak_host_receive = true;
    saved.pending = Some(Pending {
        before: saved.current.clone(),
        target: Target::Interface(saved.baseline.interface.policy.clone()),
    });
    assert_eq!(saved.validate(), Ok(()));
    let mut actual = saved.current.clone();
    actual.interface.policy.weak_host_receive = false;
    denies(&saved, &actual, Stage::Observe);
}

// Break: checking pending.before with same_owned instead of complete saved validation.
#[test]
fn rejects_pending_before_drift_even_in_readonly_metadata() {
    let mut saved = deleting();
    saved
        .pending
        .as_mut()
        .unwrap()
        .before
        .interface
        .observed
        .reachable_time += 1;
    denies(&saved, &saved.current, Stage::Observe);
    denies(&saved, &saved.current, Stage::Delete);
}

// Break: losing either side of exact pending-delete reconciliation.
#[test]
fn delete_pending_accepts_only_original_before_or_address_absence() {
    let saved = deleting();
    accepts(&saved, &saved.current, Stage::Observe);
    accepts(&saved, &saved.current, Stage::Delete);
    let mut actual = saved.current.clone();
    actual.address = None;
    accepts(&saved, &actual, Stage::Observe);
    accepts(&saved, &actual, Stage::Delete);
    for mutate in [
        (|a: &mut AddressRow| a.observed.creation_timestamp += 1) as fn(&mut AddressRow),
        |a| a.observed.scope_id = 1,
        |a| a.policy.skip_as_source = true,
    ] {
        let mut actual = saved.current.clone();
        mutate(actual.address.as_mut().unwrap());
        denies(&saved, &actual, Stage::Observe);
        denies(&saved, &actual, Stage::Delete);
    }
}

// Break: letting arbitrary policy JSON or a wrong phase/target authorize deletion.
#[test]
fn delete_stage_requires_closing_delete_intent_and_original_creation() {
    for saved in [captured(), owned(), stopped()] {
        denies(&saved, &saved.current, Stage::Delete);
    }
    let mutations: &[fn(&mut Record)] = &[
        |s| s.phase = Phase::Captured,
        |s| s.phase = Phase::Stopped,
        |s| s.creation = None,
        |s| s.pending = None,
        |s| {
            s.pending.as_mut().unwrap().target =
                Target::Interface(s.baseline.interface.policy.clone())
        },
        |s| s.pending.as_mut().unwrap().target = Target::Create(created_address().policy),
        |s| {
            s.current.address = None;
            s.pending.as_mut().unwrap().before.address = None;
        },
        |s| s.creation.as_mut().unwrap().observed.creation_timestamp += 1,
        |s| {
            s.pending
                .as_mut()
                .unwrap()
                .before
                .address
                .as_mut()
                .unwrap()
                .observed
                .scope_id = 1
        },
    ];
    for (case, mutate) in mutations.iter().enumerate() {
        let mut saved = deleting();
        mutate(&mut saved);
        let mut absent = saved.current.clone();
        absent.address = None;
        assert!(
            compare(&saved.binding, &saved, &saved.current, Stage::Delete).is_err(),
            "delete case {case}"
        );
        denies(&saved, &absent, Stage::Delete);
    }
}

// Break: granting delete/adopting creation from an observed pending-create policy.
#[test]
fn pending_create_observes_facts_without_adopting_creation_or_allowing_delete() {
    for phase in [Phase::Captured, Phase::Closing] {
        let mut saved = captured();
        saved.phase = phase;
        saved.pending = Some(Pending {
            before: saved.current.clone(),
            target: Target::Create(created_address().policy),
        });
        let original = saved.clone();
        accepts(&saved, &saved.current, Stage::Observe);
        let mut actual = saved.current.clone();
        actual.address = Some(created_address());
        accepts(&saved, &actual, Stage::Observe);
        denies(&saved, &actual, Stage::Delete);
        denies(&saved, &saved.current, Stage::Delete);
        assert_eq!(saved, original);
        actual.address.as_mut().unwrap().observed.creation_timestamp = 0;
        denies(&saved, &actual, Stage::Observe);
        actual.address = Some(created_address());
        actual.address.as_mut().unwrap().policy.skip_as_source = true;
        denies(&saved, &actual, Stage::Observe);
        saved.pending.as_mut().unwrap().target = Target::Create(AddressPolicy {
            address: [10, 77, 0, 3],
            ..created_address().policy
        });
        denies(&saved, &saved.current, Stage::Observe);
    }
}

// Break: requiring removal of history, or treating closing/dirty rows as stopped.
#[test]
fn stopped_stage_requires_empty_restored_rows_but_retains_creation_history() {
    let saved = stopped();
    accepts(&saved, &saved.current, Stage::Stopped);
    let mut no_history = saved.clone();
    no_history.creation = None;
    accepts(&no_history, &no_history.current, Stage::Stopped);
    for phase in [Phase::Captured, Phase::Closing] {
        let mut saved = captured();
        saved.phase = phase;
        denies(&saved, &saved.current, Stage::Stopped);
    }
    let mut present = saved.current.clone();
    present.address = Some(created_address());
    denies(&saved, &present, Stage::Stopped);
    let mutations: &[fn(&mut Record)] = &[
        |s| s.current.address = Some(created_address()),
        |s| s.current.interface.policy.weak_host_send = true,
        |s| {
            s.pending = Some(Pending {
                before: s.current.clone(),
                target: Target::Interface(s.baseline.interface.policy.clone()),
            })
        },
    ];
    for mutate in mutations {
        let mut bad = saved.clone();
        mutate(&mut bad);
        denies(&bad, &bad.current, Stage::Stopped);
        denies(&bad, &bad.current, Stage::Observe);
    }
}
