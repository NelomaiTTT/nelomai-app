use super::*;
use nelomai_contracts::RuntimeSlot;

fn intent() -> Intent {
    Intent {
        scope: SessionScope {
            runtime: RuntimeSlot::Stable,
            runtime_generation: 2,
            session_id: "11111111-1111-4111-8111-111111111111".into(),
            connection_generation: 3,
        },
        addresses: vec!["10.7.0.2/32".parse().unwrap()],
    }
}
fn provenance() -> Provenance {
    Provenance {
        boot_id: [8; 16],
        network_epoch: 1,
        runtime: EngineIdentity {
            slot: RuntimeSlot::Stable,
            runtime_version: "0.3.3".into(),
            container_version: "0.3.3".into(),
            runtime_contract_version: 1,
            manifest_sha256: "a".repeat(64),
        },
    }
}
fn baseline() -> [RowValue; 2] {
    [
        RowValue::Address(None),
        RowValue::WeakHost(WeakHostRow {
            send: false,
            receive: false,
        }),
    ]
}
fn desired() -> [RowValue; 2] {
    [
        RowValue::Address(Some(AddressRow {
            address: "10.7.0.2/32".parse().unwrap(),
            skip_as_source: false,
            preferred_lifetime: u32::MAX,
            valid_lifetime: u32::MAX,
        })),
        RowValue::WeakHost(WeakHostRow {
            send: true,
            receive: true,
        }),
    ]
}
fn configured() -> Record {
    Record {
        version: VERSION,
        intent: intent(),
        provenance: provenance(),
        generation: 7,
        phase: Phase::Configured,
        proof: Some(InterfaceProof {
            index: 40,
            luid: 50,
            guid: carrier_key(&intent().scope).unwrap().guid,
        }),
        rows: Some(std::array::from_fn(|i| RowState {
            baseline: baseline()[i].clone(),
            current: desired()[i].clone(),
            pending: None,
        })),
    }
}
#[test]
fn rejected_intents_and_provenance_fail_record_validation() {
    for kind in 0..16 {
        let mut i = intent();
        let mut p = provenance();
        match kind {
            0 => i.scope.runtime_generation = 0,
            1 => i.scope.connection_generation = 0,
            2 => i.scope.session_id = "not-a-session".into(),
            3 => i.addresses.clear(),
            4 => i.addresses.push(i.addresses[0]),
            5 => i.addresses[0] = "2001:db8::2/128".parse().unwrap(),
            6 => i.addresses[0] = "10.7.0.2/24".parse().unwrap(),
            7 => i.addresses[0] = "127.0.0.1/32".parse().unwrap(),
            8 => i.addresses[0] = "169.254.0.2/32".parse().unwrap(),
            9 => p.boot_id = [0; 16],
            10 => p.network_epoch = 0,
            11 => p.runtime.slot = RuntimeSlot::Latest,
            12 => p.runtime.runtime_contract_version = 0,
            13 => p.runtime.manifest_sha256 = "G".repeat(64),
            14 => p.runtime.container_version = "\n".into(),
            _ => p.runtime.runtime_version.clear(),
        }
        let record = Record {
            intent: i,
            provenance: p,
            ..configured()
        };
        assert_eq!(
            validate_record_shape(&record),
            Err(CarrierError::Invalid),
            "case {kind}"
        );
    }
}
#[test]
fn full_scope_carrier_keys_are_deterministic_and_disjoint() {
    let i = intent();
    let key = carrier_key(&i.scope).unwrap();
    assert!(key.name.starts_with("nelomai-carrier-"));
    assert_ne!(key.guid, [0; 16]);
    assert_eq!(carrier_key(&i.scope).unwrap(), key);
    for kind in 0..4 {
        let mut scope = i.scope.clone();
        match kind {
            0 => scope.runtime = RuntimeSlot::Latest,
            1 => scope.runtime_generation += 1,
            2 => scope.connection_generation += 1,
            _ => scope.session_id = "22222222-2222-4222-8222-222222222222".into(),
        }
        let other = carrier_key(&scope).unwrap();
        assert_ne!(other.guid, key.guid);
        assert_ne!(other.name, key.name);
    }
}
#[test]
fn unknown_versions_fields_and_invalid_phase_proof_rows_are_rejected() {
    let original = configured();
    assert_eq!(validate_record_shape(&original), Ok(()));
    let mut unknown_version = serde_json::to_value(&original).unwrap();
    unknown_version["version"] = 99.into();
    assert!(serde_json::from_value::<Record>(unknown_version).is_err());
    for kind in 0..11 {
        let mut record = original.clone();
        match kind {
            0 => record.version += 1,
            1 => record.generation = 0,
            2 => record.proof = None,
            3 => record.phase = Phase::Prepared,
            4 => record.rows = None,
            5 => record.proof.as_mut().unwrap().guid = [9; 16],
            6 => record.proof.as_mut().unwrap().index = 0,
            7 => record.rows.as_mut().unwrap()[0].baseline = desired()[0].clone(),
            8 => record.rows.as_mut().unwrap()[1].pending = Some(baseline()[1].clone()),
            9 => record.rows.as_mut().unwrap()[1].current = baseline()[0].clone(),
            _ => record.rows.as_mut().unwrap()[0].current = baseline()[0].clone(),
        }
        assert_eq!(
            validate_record_shape(&record),
            Err(CarrierError::Invalid),
            "case {kind}"
        );
    }
    for location in [
        "root",
        "intent",
        "scope",
        "provenance",
        "runtime",
        "proof",
        "row",
        "address",
        "weak",
    ] {
        let mut value = serde_json::to_value(&original).unwrap();
        let target = match location {
            "root" => &mut value,
            "intent" => &mut value["intent"],
            "scope" => &mut value["intent"]["scope"],
            "provenance" => &mut value["provenance"],
            "runtime" => &mut value["provenance"]["runtime"],
            "proof" => &mut value["proof"],
            "row" => &mut value["rows"][0],
            "address" => &mut value["rows"][0]["current"]["Address"],
            _ => &mut value["rows"][1]["current"]["WeakHost"],
        };
        target
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), true.into());
        assert!(
            serde_json::from_value::<Record>(value).is_err(),
            "{location}"
        );
    }
}
#[test]
fn invalid_pending_shapes_fail_record_validation() {
    let original = configured();
    for kind in 0..3 {
        let mut changed = original.clone();
        changed.phase = Phase::Closing;
        match kind {
            0 => {
                for row in changed.rows.as_mut().unwrap() {
                    row.pending = Some(row.baseline.clone());
                }
            }
            1 => changed.rows.as_mut().unwrap()[0].pending = Some(desired()[1].clone()),
            _ => changed.rows.as_mut().unwrap()[0].pending = Some(desired()[0].clone()),
        }
        assert_eq!(
            validate_record_shape(&changed),
            Err(CarrierError::Invalid),
            "case {kind}"
        );
    }
}
