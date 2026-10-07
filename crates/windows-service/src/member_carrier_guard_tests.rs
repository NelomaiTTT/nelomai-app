use super::*;
use nelomai_contracts::RuntimeSlot;

fn scope() -> SessionScope {
    SessionScope {
        runtime: RuntimeSlot::Stable,
        runtime_generation: 1,
        session_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
        connection_generation: 2,
    }
}
fn identity(index: u32) -> Identity {
    Identity {
        scope: scope(),
        proof: InterfaceProof {
            index,
            luid: u64::from(index) * 100,
            guid: [index as u8; 16],
        },
    }
}
fn carrier() -> Carrier {
    Carrier {
        identity: identity(33),
        sources: vec!["10.8.0.2".parse().unwrap(), "fd00::2".parse().unwrap()],
    }
}
fn member(index: u32) -> Member {
    Member {
        identity: identity(index),
        probes: vec![
            ProbeTuple {
                source: "10.8.0.2".parse().unwrap(),
                source_port: 40123 + index as u16,
                target: "1.1.1.1".parse().unwrap(),
                target_port: 53,
                protocol: 17,
            },
            ProbeTuple {
                source: "fd00::2".parse().unwrap(),
                source_port: 40124 + index as u16,
                target: "2606:4700:4700::1111".parse().unwrap(),
                target_port: 53,
                protocol: 17,
            },
        ],
    }
}
fn pair(active: Option<Slot>) -> Model {
    Model::new(
        scope(),
        carrier(),
        [Some(member(11)), Some(member(22))],
        active,
    )
    .unwrap()
}
fn permit(model: &Model, layer: Layer, source: &str, egress: u32) -> Filter {
    let source: IpAddr = source.parse().unwrap();
    model.expected.filters.iter().find(|f| f.action == Action::Permit && f.layer == layer
        && f.conditions.contains(&Condition::SourceAddress(source))
        && f.conditions.iter().any(|c| matches!(c, Condition::EgressIndex(i) | Condition::DestinationIndex(i) | Condition::NextHopIndex(i) if *i == egress))).unwrap().clone()
}

#[test]
fn standby_requires_exact_carrier_and_egress_at_all_four_layers_both_families() {
    let model = pair(Some(Slot::A));
    assert_eq!(model.expected.filters.len(), 32);
    for (layers, source, target, port) in [
        (
            [
                Layer::TransportV4,
                Layer::PacketV4,
                Layer::ForwardV4,
                Layer::AleConnectV4,
            ],
            "10.8.0.2",
            "1.1.1.1",
            40145,
        ),
        (
            [
                Layer::TransportV6,
                Layer::PacketV6,
                Layer::ForwardV6,
                Layer::AleConnectV6,
            ],
            "fd00::2",
            "2606:4700:4700::1111",
            40146,
        ),
    ] {
        use Condition::*;
        let source = source.parse().unwrap();
        let target = target.parse().unwrap();
        let want = [
            vec![
                EgressIndex(22),
                LocalInterface(3300),
                SourceAddress(source),
                DestinationAddress(target),
                LocalPort(port),
                RemotePort(53),
                Protocol(17),
                NoneSetFlags(0x10),
            ],
            vec![
                EgressIndex(22),
                LocalInterface(2200),
                SourceAddress(source),
                DestinationAddress(target),
            ],
            vec![
                DestinationIndex(22),
                DestinationLuid(2200),
                SourceIndex(33),
                SourceLuid(3300),
                SourceAddress(source),
                DestinationAddress(target),
                AllSetFlags(0x40000),
            ],
            vec![
                LocalInterface(3300),
                NextHopIndex(22),
                NextHopLuid(2200),
                SourceAddress(source),
                DestinationAddress(target),
                LocalPort(port),
                RemotePort(53),
                Protocol(17),
            ],
        ];
        for (i, layer) in layers.into_iter().enumerate() {
            let filter = permit(&model, layer, &source.to_string(), 22);
            assert_eq!(filter.conditions, want[i]);
            assert_eq!(filter.flags, 0);
            assert_eq!(filter.weight, 2);
        }
    }
}
#[test]
fn active_data_is_dynamic_source_restricted_and_never_grants_standby_general_data() {
    use Condition::*;
    let model = pair(Some(Slot::A));
    let source = "10.8.0.2".parse().unwrap();
    assert_eq!(
        permit(&model, Layer::TransportV4, "10.8.0.2", 11).conditions,
        vec![
            EgressIndex(11),
            LocalInterface(3300),
            SourceAddress(source),
            NoneSetFlags(0x10)
        ]
    );
    assert_eq!(
        permit(&model, Layer::ForwardV4, "10.8.0.2", 11).conditions,
        vec![
            DestinationIndex(11),
            DestinationLuid(1100),
            SourceIndex(33),
            SourceLuid(3300),
            SourceAddress(source),
            AllSetFlags(0x40000)
        ]
    );
    let base = model.without_permits().unwrap();
    assert_eq!(base.expected.filters.len(), 16);
    assert!(base
        .expected
        .filters
        .iter()
        .all(|f| f.action == Action::Block && f.weight == 1 && f.flags == 0));
    for egress in [11, 22] {
        for layer in [
            Layer::TransportV4,
            Layer::TransportV6,
            Layer::PacketV4,
            Layer::PacketV6,
            Layer::ForwardV4,
            Layer::ForwardV6,
            Layer::AleConnectV4,
            Layer::AleConnectV6,
        ] {
            assert!(base.expected.filters.iter().any(|f| f.layer == layer && f.conditions.iter().any(|c| matches!(c, EgressIndex(i) | DestinationIndex(i) | NextHopIndex(i) if *i == egress))));
        }
    }
}
#[test]
fn malformed_sources_tuples_scopes_and_reused_identity_components_are_denied() {
    pair(None).validate().unwrap();
    for case in 0..15 {
        let mut c = carrier();
        let mut members = [Some(member(11)), Some(member(22))];
        match case {
            0 => c.sources.clear(),
            1 => c.sources.push(c.sources[0]),
            2 => c.sources[0] = "0.0.0.0".parse().unwrap(),
            3 => c.identity.scope.connection_generation += 1,
            4 => c.identity.proof.guid = [0; 16],
            5 => members[1].as_mut().unwrap().identity.proof.index = 11,
            6 => members[1].as_mut().unwrap().identity.proof.luid = 3300,
            7 => members[1].as_mut().unwrap().identity.proof.guid = [11; 16],
            8 => members[1].as_mut().unwrap().probes[0].source_port = 0,
            9 => members[1].as_mut().unwrap().probes[0].target_port = 54,
            10 => members[1].as_mut().unwrap().probes[0].protocol = 6,
            11 => members[1].as_mut().unwrap().probes[0].source = "10.8.0.3".parse().unwrap(),
            12 => members[1].as_mut().unwrap().probes[0].target = "fd00::3".parse().unwrap(),
            13 => {
                let probe = members[1].as_ref().unwrap().probes[0].clone();
                members[1].as_mut().unwrap().probes.push(probe);
            }
            _ => {
                members[1]
                    .as_mut()
                    .unwrap()
                    .identity
                    .scope
                    .runtime_generation += 1
            }
        }
        assert!(
            Model::new(scope(), c, members, Some(Slot::A)).is_err(),
            "case {case}"
        );
    }
}
#[test]
fn new_key_universe_is_full_scope_deterministic_and_disjoint_from_legacy() {
    let keys = resource_keys(&scope()).unwrap();
    let old = crate::member_guard::resource_keys(&scope()).unwrap();
    let repeated = resource_keys(&scope()).unwrap();
    assert_eq!(keys.filters, repeated.filters);
    assert_eq!(keys.sublayer, repeated.sublayer);
    let all: Vec<_> = std::iter::once(keys.sublayer).chain(keys.filters).collect();
    let unique: std::collections::BTreeSet<_> = all.iter().copied().collect();
    assert_eq!(unique.len(), 49);
    for key in all {
        assert_ne!(key, old.sublayer);
        assert!(!old.filters.contains(&key));
    }
    for case in 0..4 {
        let mut s = scope();
        match case {
            0 => s.runtime = RuntimeSlot::Latest,
            1 => s.runtime_generation += 1,
            2 => s.session_id = "11234567-89ab-cdef-0123-456789abcdef".into(),
            _ => s.connection_generation += 1,
        }
        let changed = resource_keys(&s).unwrap();
        assert_ne!(keys.sublayer, changed.sublayer);
        assert!(changed.filters.iter().all(|k| !keys.filters.contains(k)));
    }
}
#[test]
fn assigned_priority_is_captured_once_and_later_drift_or_extra_objects_reject() {
    let empty = Model::empty(scope()).unwrap();
    let base = pair(Some(Slot::A)).without_permits().unwrap();
    assert_eq!(base.expected.sublayer.as_ref().unwrap().weight, 65534);
    let mut native = base.expected.clone();
    native.sublayer.as_mut().unwrap().weight = 65531;
    let captured = base.readback_after(&empty, &native).unwrap();
    assert_eq!(captured.assigned_sublayer_weight, Some(65531));
    captured.validate().unwrap();
    let desired = pair(Some(Slot::B))
        .inherit_sublayer_weight(&captured)
        .unwrap();
    assert_eq!(desired.expected.sublayer.as_ref().unwrap().weight, 65531);
    let mut drift = desired.expected.clone();
    drift.sublayer.as_mut().unwrap().weight -= 1;
    assert!(desired.readback_after(&captured, &drift).is_err());
    native.filters.push(native.filters[0].clone());
    assert!(base.readback_after(&empty, &native).is_err());
}
#[test]
fn serialized_model_recomputes_exact_snapshot_and_never_accepts_legacy_or_unknowns() {
    let model = pair(Some(Slot::A));
    let encoded = serde_json::to_value(&model).unwrap();
    assert_eq!(
        serde_json::from_value::<Model>(encoded.clone()).unwrap(),
        model
    );
    let legacy = crate::member_guard::Model::empty(scope()).unwrap();
    assert!(serde_json::from_value::<Model>(serde_json::to_value(legacy).unwrap()).is_err());
    for case in 0..12 {
        let mut value = encoded.clone();
        match case {
            0 => value["version"] = 99.into(),
            1 => value["expected"]["version"] = 99.into(),
            2 => value["extra"] = true.into(),
            3 => value["expected"]["filters"][0]["layer"] = "Unknown".into(),
            4 => value["expected"]["filters"][0]["flags"] = 128.into(),
            5 => value["expected"]["filters"][0]["weight"] = 99.into(),
            6 => {
                value["expected"]["filters"][0]["conditions"] = serde_json::json!([{"Unknown": 1}])
            }
            7 => value["carrier"]["identity"]["proof"]["guid"][0] = 44.into(),
            8 => value["members"][0]["identity"]["proof"]["index"] = 44.into(),
            9 => value["members"][1]["probes"][0]["source_port"] = 50000.into(),
            10 => value["expected"]["filters"][0]["key"][0] = 0.into(),
            _ => value["carrier"] = serde_json::Value::Null,
        }
        assert!(
            serde_json::from_value::<Model>(value).is_err(),
            "case {case}"
        );
    }
}

fn installed(active: Option<Slot>) -> Model {
    let desired = pair(active);
    let mut native = desired.expected.clone();
    native.sublayer.as_mut().unwrap().weight = 65531;
    desired
        .readback_after(&Model::empty(scope()).unwrap(), &native)
        .unwrap()
}
#[test]
fn split_boundary_rejects_wrong_session_writes_and_tampered_journal_states() {
    let before = installed(Some(Slot::A));
    let desired = pair(Some(Slot::B))
        .inherit_sublayer_weight(&before)
        .unwrap();
    let plan = ExchangePlan::new(&before, &desired).unwrap();
    plan.validate().unwrap();
    assert!(
        validate_session_exchange(&scope(), &before, &desired, SessionKind::StaticBase).is_err()
    );
    assert!(validate_session_exchange(
        &scope(),
        &before.without_permits().unwrap(),
        &Model::empty(scope()).unwrap(),
        SessionKind::DynamicPermits
    )
    .is_err());
    let encoded = serde_json::to_value(&plan).unwrap();
    assert_eq!(
        serde_json::from_value::<ExchangePlan>(encoded.clone()).unwrap(),
        plan
    );
    for field in ["withdrawn", "base"] {
        let mut bad = encoded.clone();
        bad[field] = encoded["desired"].clone();
        assert!(serde_json::from_value::<ExchangePlan>(bad).is_err());
    }
    let mut foreign = desired.clone();
    foreign.carrier.as_mut().unwrap().identity.proof.guid[0] ^= 1;
    foreign.expected.carrier = foreign.carrier.clone();
    foreign.validate().unwrap();
    assert!(ExchangePlan::new(&before, &foreign).is_err());
}
#[test]
fn active_data_requires_exact_four_layer_carrier_ownership_in_both_families() {
    use Condition::*;
    let model = pair(Some(Slot::B));
    for (source, layers) in [
        (
            "10.8.0.2",
            [
                Layer::TransportV4,
                Layer::PacketV4,
                Layer::ForwardV4,
                Layer::AleConnectV4,
            ],
        ),
        (
            "fd00::2",
            [
                Layer::TransportV6,
                Layer::PacketV6,
                Layer::ForwardV6,
                Layer::AleConnectV6,
            ],
        ),
    ] {
        let ip = source.parse().unwrap();
        let expected = [
            vec![
                EgressIndex(22),
                LocalInterface(3300),
                SourceAddress(ip),
                NoneSetFlags(0x10),
            ],
            vec![EgressIndex(22), LocalInterface(2200), SourceAddress(ip)],
            vec![
                DestinationIndex(22),
                DestinationLuid(2200),
                SourceIndex(33),
                SourceLuid(3300),
                SourceAddress(ip),
                AllSetFlags(0x40000),
            ],
            vec![
                LocalInterface(3300),
                NextHopIndex(22),
                NextHopLuid(2200),
                SourceAddress(ip),
            ],
        ];
        for (i, layer) in layers.into_iter().enumerate() {
            assert_eq!(permit(&model, layer, source, 22).conditions, expected[i]);
            assert!(permit(&model, layer, source, 11)
                .conditions
                .iter()
                .any(|c| matches!(c, DestinationAddress(_))));
        }
    }
}
#[test]
fn no_carrier_inference_and_no_unsupported_family_or_duplicate_exclusive_bind() {
    assert!(Model::new(scope(), carrier(), [None, None], None).is_err());
    let model = pair(Some(Slot::A));
    let mut missing = serde_json::to_value(&model).unwrap();
    missing.as_object_mut().unwrap().remove("carrier");
    assert!(serde_json::from_value::<Model>(missing).is_err());
    for bad in [
        "127.0.0.1",
        "169.254.1.2",
        "224.0.0.1",
        "fe80::1",
        "::ffff:10.8.0.2",
        "::",
        "ff00::1",
    ] {
        let mut c = carrier();
        c.sources = vec![bad.parse().unwrap()];
        assert!(Model::new(scope(), c, [Some(member(11)), None], Some(Slot::A)).is_err());
    }
    let mut b = member(22);
    b.probes[0].source_port = 40134;
    assert!(Model::new(
        scope(),
        carrier(),
        [Some(member(11)), Some(b)],
        Some(Slot::A)
    )
    .is_err());
    assert!(Model::new(scope(), carrier(), [Some(member(11)), None], Some(Slot::B)).is_err());
    let mut c = carrier();
    c.sources.push("10.8.0.3".parse().unwrap());
    assert!(Model::new(scope(), c, [Some(member(11)), None], Some(Slot::A)).is_err());
}
