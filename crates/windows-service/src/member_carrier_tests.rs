use super::*;
use nelomai_contracts::RuntimeSlot;
use std::{cell::RefCell, collections::VecDeque, rc::Rc};

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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ack {
    Fail,
    Lost,
    Foreign,
    FalseSuccess,
    ReadFailure,
}
struct State {
    record: Option<Record>,
    observed: Observation,
    events: Vec<String>,
    saves: usize,
    fail_save: Option<(usize, Ack)>,
    fail_effect: Option<(&'static str, bool)>,
    dads: VecDeque<DadState>,
    fail_inspect: bool,
    inspections: usize,
    fail_inspect_number: Option<usize>,
    reuse_on_inspect: Option<usize>,
    unacknowledged_row: bool,
    create_baseline: [RowValue; 2],
    corrupt_capture: bool,
    race_effect: Option<&'static str>,
    change_on_configured: bool,
    fail_loads: usize,
}
type Shared = Rc<RefCell<State>>;
struct Disk(Shared);
struct Io(Shared);
impl CarrierJournal for Disk {
    fn load(&mut self, _: &CarrierKey) -> Result<Option<Record>> {
        let mut s = self.0.borrow_mut();
        if s.fail_loads > 0 {
            s.fail_loads -= 1;
            return Err(CarrierError::Journal);
        }
        Ok(s.record.clone())
    }
    fn compare_exchange(
        &mut self,
        _: &CarrierKey,
        expected: Option<&Record>,
        desired: &Record,
    ) -> Result<()> {
        let mut s = self.0.borrow_mut();
        if s.record.as_ref() != expected {
            return Err(CarrierError::Conflict);
        }
        s.saves += 1;
        s.events
            .push(format!("save:{:?}:{}", desired.phase, desired.generation));
        let failure = s.fail_save.filter(|(n, _)| *n == s.saves).map(|(_, a)| a);
        if failure == Some(Ack::Fail) {
            return Err(CarrierError::Journal);
        }
        if failure == Some(Ack::FalseSuccess) {
            return Ok(());
        }
        s.record = Some(desired.clone());
        if failure == Some(Ack::ReadFailure) {
            s.fail_loads = 1;
        }
        if desired.phase == Phase::Configured && s.change_on_configured {
            s.observed.rows.as_mut().unwrap()[1] = baseline()[1].clone();
        }
        if failure == Some(Ack::Foreign) {
            s.record
                .as_mut()
                .unwrap()
                .intent
                .scope
                .connection_generation += 1;
        }
        if failure.is_some() {
            Err(CarrierError::Journal)
        } else {
            Ok(())
        }
    }
}
impl CarrierIo for Io {
    fn inspect(
        &mut self,
        _: &Intent,
        _: &CarrierKey,
        _: Option<&InterfaceProof>,
    ) -> Result<Observation> {
        let mut s = self.0.borrow_mut();
        s.events.push("inspect".into());
        s.inspections += 1;
        if s.fail_inspect || s.fail_inspect_number == Some(s.inspections) {
            return Err(CarrierError::Native);
        }
        if s.reuse_on_inspect == Some(s.inspections) {
            if let Some(proof) = &mut s.observed.by_name {
                proof.luid += 1;
            }
        }
        if s.observed.by_name.is_some() && s.observed.rows == Some(desired()) {
            if let Some(dad) = s.dads.pop_front() {
                s.observed.dad = Some(dad);
            }
        }
        Ok(s.observed.clone())
    }
    fn create_fresh(
        &mut self,
        prepared: &Record,
        key: &CarrierKey,
        expected: &Observation,
    ) -> Result<Captured> {
        let mut s = self.0.borrow_mut();
        assert_eq!(s.record.as_ref(), Some(prepared));
        assert_eq!(s.observed.provenance, prepared.provenance);
        assert_eq!(&s.observed, expected);
        assert!(s.observed.by_name.is_none() && s.observed.by_guid.is_none());
        assert_eq!(s.record.as_ref().unwrap().phase, Phase::Prepared);
        s.events.push("create".into());
        if s.fail_effect == Some(("create", false)) {
            return Err(CarrierError::Native);
        }
        let proof = InterfaceProof {
            index: 40,
            luid: 50,
            guid: key.guid,
        };
        s.observed.by_name = Some(proof);
        s.observed.by_guid = Some(proof);
        s.observed.retained = vec![proof];
        s.observed.rows = Some(s.create_baseline.clone());
        s.observed.dad = None;
        if s.fail_effect == Some(("create", true)) {
            return Err(CarrierError::Native);
        }
        Ok(Captured {
            proof: if s.corrupt_capture {
                InterfaceProof { index: 0, ..proof }
            } else {
                proof
            },
            baseline: s.create_baseline.clone(),
        })
    }
    fn compare_exchange_row(
        &mut self,
        pending: &Record,
        kind: RowKind,
        expected: &RowValue,
        desired: &RowValue,
    ) -> Result<()> {
        let mut s = self.0.borrow_mut();
        assert_eq!(s.record.as_ref(), Some(pending));
        assert_eq!(s.observed.provenance, pending.provenance);
        let proof = &pending.proof.unwrap();
        assert_eq!(s.observed.by_name, Some(*proof));
        assert_eq!(s.observed.by_guid, Some(*proof));
        let index = match kind {
            RowKind::Address => 0,
            RowKind::WeakHost => 1,
        };
        let event = match (kind, desired) {
            (RowKind::Address, RowValue::Address(None)) => "restore_address",
            (RowKind::Address, _) => "address",
            (RowKind::WeakHost, _) if desired == &s.create_baseline[1] => "restore_weak",
            _ => "weak",
        };
        assert_eq!(&s.observed.rows.as_ref().unwrap()[index], expected);
        assert_eq!(s.record.as_ref().unwrap().proof, Some(*proof));
        assert_eq!(
            s.record.as_ref().unwrap().rows.as_ref().unwrap()[index]
                .pending
                .as_ref(),
            Some(desired)
        );
        s.events.push(event.into());
        if s.race_effect == Some(event) {
            s.observed.provenance.network_epoch += 1;
            return Err(CarrierError::Conflict);
        }
        if s.fail_effect == Some((event, false)) {
            return Err(CarrierError::Native);
        }
        if s.unacknowledged_row {
            return Ok(());
        }
        s.observed.rows.as_mut().unwrap()[index] = desired.clone();
        if index == 0 {
            s.observed.dad = if matches!(desired, RowValue::Address(Some(_))) {
                Some(DadState::Preferred)
            } else {
                None
            };
        }
        if s.fail_effect == Some((event, true)) {
            Err(CarrierError::Native)
        } else {
            Ok(())
        }
    }
    fn close(&mut self, closing: &Record, budget_ms: u64) -> Result<()> {
        let mut s = self.0.borrow_mut();
        assert_eq!(s.record.as_ref(), Some(closing));
        assert_eq!(s.observed.provenance, closing.provenance);
        let proof = &closing.proof.unwrap();
        assert_eq!(budget_ms, 5000);
        assert_eq!(s.observed.by_name, Some(*proof));
        assert_eq!(s.observed.rows, Some(s.create_baseline.clone()));
        assert_eq!(s.record.as_ref().unwrap().phase, Phase::Closing);
        s.events.push("close".into());
        if s.race_effect == Some("close") {
            s.observed.by_name.as_mut().unwrap().luid += 1;
            return Err(CarrierError::Conflict);
        }
        if s.fail_effect == Some(("close", false)) {
            return Err(CarrierError::Native);
        }
        s.observed.by_name = None;
        s.observed.by_guid = None;
        s.observed.retained.clear();
        s.observed.rows = None;
        s.observed.dad = None;
        if s.fail_effect == Some(("close", true)) {
            Err(CarrierError::Native)
        } else {
            Ok(())
        }
    }
}
fn fixture() -> (Shared, CarrierOwner<Disk, Io>) {
    let s = Rc::new(RefCell::new(State {
        record: None,
        observed: Observation {
            provenance: provenance(),
            by_name: None,
            by_guid: None,
            retained: vec![],
            rows: None,
            dad: None,
        },
        events: vec![],
        saves: 0,
        fail_save: None,
        fail_effect: None,
        dads: VecDeque::new(),
        fail_inspect: false,
        inspections: 0,
        fail_inspect_number: None,
        reuse_on_inspect: None,
        unacknowledged_row: false,
        create_baseline: baseline(),
        corrupt_capture: false,
        race_effect: None,
        change_on_configured: false,
        fail_loads: 0,
    }));
    let owner = CarrierOwner::new(intent(), provenance(), Disk(s.clone()), Io(s.clone())).unwrap();
    (s, owner)
}
fn saved(s: &Shared) -> Record {
    s.borrow().record.clone().unwrap()
}
fn effects(s: &Shared) -> Vec<String> {
    s.borrow()
        .events
        .iter()
        .filter(|s| !s.starts_with("save:") && *s != "inspect")
        .cloned()
        .collect()
}

// Catches publishing configuration before write-ahead proof/rows/readiness.
#[test]
fn preparation_orders_durable_creation_identity_rows_and_readiness() {
    let (s, mut o) = fixture();
    let result = o.prepare(100).unwrap();
    let record = saved(&s);
    assert_eq!(result, Readiness::Ready(record.proof.unwrap()));
    assert_eq!(record.phase, Phase::Configured);
    assert_eq!(effects(&s), ["create", "weak", "address"]);
    for row in record.rows.unwrap() {
        assert!(row.pending.is_none());
    }
    let events = &s.borrow().events;
    assert!(
        events
            .iter()
            .position(|e| e.starts_with("save:Prepared"))
            .unwrap()
            < events.iter().position(|e| e == "create").unwrap()
    );
    assert!(
        events
            .iter()
            .position(|e| e.starts_with("save:Created"))
            .unwrap()
            < events.iter().position(|e| e == "address").unwrap()
    );
}
#[test]
fn tentative_is_bounded_and_never_published_early() {
    let (s, mut o) = fixture();
    s.borrow_mut().dads = VecDeque::from([DadState::Tentative; 16]);
    assert_eq!(o.prepare(100), Ok(Readiness::Tentative));
    assert_eq!(saved(&s).phase, Phase::Created);
    assert_eq!(o.poll_ready(5099), Ok(Readiness::Tentative));
    assert_eq!(o.poll_ready(5100), Err(CarrierError::Deadline));
    assert_eq!(saved(&s).phase, Phase::Created);
}
#[test]
fn stop_restores_exact_rows_then_closes_and_is_idempotent() {
    let (s, mut o) = fixture();
    o.prepare(0).unwrap();
    let record = o.stop(&saved(&s)).unwrap();
    assert_eq!(record.phase, Phase::Stopped);
    assert_eq!(
        effects(&s),
        [
            "create",
            "weak",
            "address",
            "restore_address",
            "restore_weak",
            "close"
        ]
    );
    let before = effects(&s);
    assert_eq!(o.stop(&record).unwrap(), record);
    assert_eq!(effects(&s), before);
}

#[test]
fn rejected_intents_and_provenance_cannot_reach_native_effects() {
    for kind in 0..16 {
        let (s, _) = fixture();
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
        assert!(
            CarrierOwner::new(i, p, Disk(s.clone()), Io(s.clone())).is_err(),
            "case {kind}"
        );
        assert!(s.borrow().events.is_empty());
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
fn same_name_guid_or_retained_identity_conflicts_never_create() {
    for kind in 0..3 {
        let (s, mut o) = fixture();
        let proof = InterfaceProof {
            index: 40,
            luid: 50,
            guid: [9; 16],
        };
        match kind {
            0 => s.borrow_mut().observed.by_name = Some(proof),
            1 => s.borrow_mut().observed.by_guid = Some(proof),
            _ => s.borrow_mut().observed.retained = vec![proof],
        }
        assert_eq!(o.prepare(0), Err(CarrierError::Conflict));
        assert!(effects(&s).is_empty());
    }
}
#[test]
fn index_luid_guid_reuse_cannot_configure_poll_or_close() {
    for kind in 0..5 {
        let (s, mut o) = fixture();
        s.borrow_mut().dads = VecDeque::from([DadState::Tentative; 16]);
        assert_eq!(o.prepare(0), Ok(Readiness::Tentative));
        let original = saved(&s);
        {
            let mut st = s.borrow_mut();
            match kind {
                0 => st.observed.by_name.as_mut().unwrap().index += 1,
                1 => st.observed.by_guid.as_mut().unwrap().luid += 1,
                2 => st.observed.retained[0].guid = [9; 16],
                3 => st.observed.by_name = None,
                _ => st.observed.retained.clear(),
            }
        }
        let before = effects(&s);
        assert_eq!(o.poll_ready(1), Err(CarrierError::Conflict));
        assert_eq!(o.stop(&original), Err(CarrierError::Conflict));
        assert_eq!(effects(&s), before);
    }
}
#[test]
fn only_tentative_may_wait_and_failed_readiness_cannot_resume() {
    for dad in [DadState::Duplicate, DadState::Deprecated] {
        let (s, mut o) = fixture();
        s.borrow_mut().dads = VecDeque::from([dad; 16]);
        assert!(o.prepare(0).is_err());
        assert_eq!(saved(&s).phase, Phase::Created);
        s.borrow_mut().dads.clear();
        s.borrow_mut().observed.dad = Some(DadState::Preferred);
        assert!(o.poll_ready(1).is_err());
        o.stop(&saved(&s)).unwrap();
    }
}
#[test]
fn readiness_uses_explicit_monotone_deadline_and_fresh_preferred_rows() {
    let (s, mut o) = fixture();
    s.borrow_mut().dads = VecDeque::from([DadState::Tentative; 16]);
    o.prepare(100).unwrap();
    assert_eq!(o.poll_ready(99), Err(CarrierError::Invalid));
    let (s, mut o) = fixture();
    s.borrow_mut().dads = VecDeque::from([DadState::Tentative; 16]);
    o.prepare(100).unwrap();
    s.borrow_mut().dads.clear();
    s.borrow_mut().observed.dad = Some(DadState::Preferred);
    assert!(matches!(o.poll_ready(5099), Ok(Readiness::Ready(_))));
    s.borrow_mut().observed.rows.as_mut().unwrap()[1] = baseline()[1].clone();
    assert_eq!(o.poll_ready(5100), Err(CarrierError::Conflict));
}
#[test]
fn stale_scope_boot_runtime_and_epoch_reject_before_effects() {
    for kind in 0..8 {
        let (s, mut o) = fixture();
        o.prepare(0).unwrap();
        let original = saved(&s);
        let mut i = intent();
        let mut p = provenance();
        match kind {
            0 => i.scope.runtime_generation += 1,
            1 => i.scope.connection_generation += 1,
            2 => i.scope.session_id = "22222222-2222-4222-8222-222222222222".into(),
            3 => {
                i.scope.runtime = RuntimeSlot::Latest;
                p.runtime.slot = RuntimeSlot::Latest;
            }
            4 => p.boot_id = [9; 16],
            5 => p.runtime.manifest_sha256 = "b".repeat(64),
            6 => p.runtime.runtime_version = "0.3.4".into(),
            _ => p.network_epoch += 1,
        }
        let before = effects(&s);
        assert!(CarrierOwner::recover_for_cleanup(
            i,
            p,
            original.clone(),
            Disk(s.clone()),
            Io(s.clone())
        )
        .is_err());
        assert_eq!(effects(&s), before);
        s.borrow_mut().observed.provenance.boot_id = [9; 16];
        assert_eq!(o.stop(&original), Err(CarrierError::Conflict));
        assert_eq!(effects(&s), before);
    }
}
#[test]
fn stale_record_generation_and_foreign_journal_never_overwrite() {
    let (s, mut o) = fixture();
    o.prepare(0).unwrap();
    let original = saved(&s);
    s.borrow_mut().record.as_mut().unwrap().generation += 1;
    let before = effects(&s);
    assert_eq!(o.stop(&original), Err(CarrierError::Conflict));
    assert_eq!(effects(&s), before);
}
#[test]
fn ambiguous_create_ack_retains_prepared_without_adoption_or_deletion() {
    let (s, mut o) = fixture();
    s.borrow_mut().fail_effect = Some(("create", true));
    assert!(o.prepare(0).is_err());
    let record = saved(&s);
    assert_eq!(record.phase, Phase::Prepared);
    assert!(record.proof.is_none());
    assert!(s.borrow().observed.by_name.is_some());
    let mut recovery = CarrierOwner::recover_for_cleanup(
        intent(),
        provenance(),
        record.clone(),
        Disk(s.clone()),
        Io(s.clone()),
    )
    .unwrap();
    assert_eq!(recovery.prepare(1), Err(CarrierError::Retired));
    assert!(recovery.stop(&record).is_err());
    assert_eq!(effects(&s), ["create"]);
    assert_eq!(saved(&s).proof, None);
}
#[test]
fn failed_create_without_effect_can_retire_only_after_proven_absence() {
    let (s, mut o) = fixture();
    s.borrow_mut().fail_effect = Some(("create", false));
    assert!(o.prepare(0).is_err());
    let record = o.stop(&saved(&s)).unwrap();
    assert_eq!(record.phase, Phase::Stopped);
    assert_eq!(effects(&s), ["create"]);
}
#[test]
fn changed_address_or_weakhost_is_retained_without_close() {
    for kind in 0..2 {
        let (s, mut o) = fixture();
        o.prepare(0).unwrap();
        {
            let mut st = s.borrow_mut();
            let rows = st.observed.rows.as_mut().unwrap();
            rows[kind] = if kind == 0 {
                RowValue::Address(Some(AddressRow {
                    preferred_lifetime: 10,
                    ..match desired()[0].clone() {
                        RowValue::Address(Some(a)) => a,
                        _ => unreachable!(),
                    }
                }))
            } else {
                RowValue::WeakHost(WeakHostRow {
                    send: true,
                    receive: false,
                })
            };
        }
        let changed = s.borrow().observed.rows.clone();
        assert!(o.stop(&saved(&s)).is_err());
        assert_eq!(s.borrow().observed.rows, changed);
        assert!(!effects(&s).contains(&"close".to_string()));
        assert_ne!(saved(&s).phase, Phase::Stopped);
    }
}
#[test]
fn every_prepare_journal_transition_handles_committed_and_uncommitted_lost_ack() {
    for number in 1..=7 {
        for ack in [Ack::Fail, Ack::Lost, Ack::Foreign] {
            let (s, mut o) = fixture();
            s.borrow_mut().fail_save = Some((number, ack));
            let result = o.prepare(0);
            if ack == Ack::Lost {
                assert!(matches!(result, Ok(Readiness::Ready(_))), "save {number}");
            } else {
                assert!(result.is_err(), "save {number}");
                if number == 1 {
                    assert!(effects(&s).is_empty());
                }
                if number == 2 {
                    assert_eq!(effects(&s), ["create"]);
                }
                if ack == Ack::Foreign {
                    assert_eq!(saved(&s).intent.scope.connection_generation, 4);
                } else if let Some(record) = o.snapshot().unwrap() {
                    s.borrow_mut().fail_save = None;
                    if number == 2 {
                        assert!(o.stop(&record).is_err());
                    } else {
                        assert_eq!(o.stop(&record).unwrap().phase, Phase::Stopped);
                    }
                }
            }
        }
    }
}
#[test]
fn every_partial_configure_restore_and_close_keeps_cleanup_retryable() {
    for event in [
        "weak",
        "address",
        "restore_address",
        "restore_weak",
        "close",
    ] {
        for applied in [false, true] {
            let (s, mut o) = fixture();
            if event.starts_with("restore") || event == "close" {
                o.prepare(0).unwrap();
                s.borrow_mut().fail_effect = Some((event, applied));
                assert!(o.stop(&saved(&s)).is_err(), "{event}/{applied}");
            } else {
                s.borrow_mut().fail_effect = Some((event, applied));
                assert!(o.prepare(0).is_err());
            }
            let record = saved(&s);
            assert_ne!(record.phase, Phase::Stopped);
            s.borrow_mut().fail_effect = None;
            let mut recovery = CarrierOwner::recover_for_cleanup(
                intent(),
                provenance(),
                record.clone(),
                Disk(s.clone()),
                Io(s.clone()),
            )
            .unwrap();
            assert_eq!(recovery.prepare(0), Err(CarrierError::Retired));
            assert_eq!(recovery.poll_ready(0), Err(CarrierError::Retired));
            assert_eq!(
                recovery.stop(&record).unwrap().phase,
                Phase::Stopped,
                "{event}/{applied}"
            );
        }
    }
}
#[test]
fn every_cleanup_journal_transition_retains_durable_obligation() {
    for number in 8..=13 {
        for ack in [Ack::Fail, Ack::Lost, Ack::Foreign] {
            let (s, mut o) = fixture();
            o.prepare(0).unwrap();
            s.borrow_mut().fail_save = Some((number, ack));
            let result = o.stop(&saved(&s));
            if ack == Ack::Lost {
                assert_eq!(result.unwrap().phase, Phase::Stopped, "save {number}");
            } else {
                assert!(result.is_err(), "save {number}");
                if ack == Ack::Foreign {
                    assert_eq!(saved(&s).intent.scope.connection_generation, 4);
                } else {
                    assert_ne!(saved(&s).phase, Phase::Stopped);
                    s.borrow_mut().fail_save = None;
                    assert_eq!(
                        o.stop(&saved(&s)).unwrap().phase,
                        Phase::Stopped,
                        "save {number}"
                    );
                }
            }
        }
    }
}
#[test]
fn no_native_ack_substitutes_for_exact_row_readback() {
    let (s, mut o) = fixture();
    s.borrow_mut().unacknowledged_row = true;
    assert!(o.prepare(0).is_err());
    let record = saved(&s);
    assert_eq!(record.phase, Phase::Created);
    assert!(record.rows.as_ref().unwrap()[1].pending.is_some());
    s.borrow_mut().unacknowledged_row = false;
    o.stop(&record).unwrap();
}
#[test]
fn unknown_versions_fields_and_invalid_phase_proof_rows_are_rejected() {
    let (s, mut o) = fixture();
    o.prepare(0).unwrap();
    let original = saved(&s);
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
        s.borrow_mut().record = Some(record.clone());
        let before = effects(&s);
        assert!(
            CarrierOwner::recover_for_cleanup(
                intent(),
                provenance(),
                record,
                Disk(s.clone()),
                Io(s.clone())
            )
            .is_err(),
            "case {kind}"
        );
        assert_eq!(effects(&s), before);
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
fn inspect_errors_and_identity_changes_at_each_prepare_read_cannot_publish() {
    let (s, mut o) = fixture();
    o.prepare(0).unwrap();
    let count = s.borrow().inspections;
    for n in 1..=count {
        let (s, mut o) = fixture();
        s.borrow_mut().fail_inspect_number = Some(n);
        assert!(o.prepare(0).is_err(), "inspect {n}");
        // A failure after the Configured CAS may leave that phase durable, but
        // prepare returned no usable proof and exact cleanup is still retained.
        s.borrow_mut().fail_inspect_number = None;
        if let Some(record) = o.snapshot().unwrap() {
            assert_eq!(o.stop(&record).unwrap().phase, Phase::Stopped);
        }
    }
    for n in 3..=count {
        let (s, mut o) = fixture();
        s.borrow_mut().reuse_on_inspect = Some(n);
        assert!(o.prepare(0).is_err(), "reuse {n}");
        assert!(!effects(&s).contains(&"close".into()));
    }
}

#[test]
fn polling_cannot_adopt_a_changed_durable_generation_or_proof() {
    for kind in 0..3 {
        let (s, mut o) = fixture();
        s.borrow_mut().dads = VecDeque::from([DadState::Tentative; 16]);
        o.prepare(0).unwrap();
        {
            let mut st = s.borrow_mut();
            match kind {
                0 => st.record.as_mut().unwrap().generation += 1,
                1 => {
                    let record = st.record.as_mut().unwrap();
                    record.proof.as_mut().unwrap().luid += 1;
                    let proof = record.proof.unwrap();
                    st.observed.by_name = Some(proof);
                    st.observed.by_guid = Some(proof);
                    st.observed.retained = vec![proof];
                }
                _ => st.record.as_mut().unwrap().phase = Phase::Configured,
            }
            st.dads.clear();
            st.observed.dad = Some(DadState::Preferred);
        }
        let before = saved(&s);
        assert_eq!(o.poll_ready(1), Err(CarrierError::Conflict));
        assert_eq!(saved(&s), before);
    }
}
#[test]
fn nondefault_captured_weakhost_baselines_are_restored_exactly() {
    for baseline_weak in [
        WeakHostRow {
            send: true,
            receive: false,
        },
        WeakHostRow {
            send: true,
            receive: true,
        },
    ] {
        let (s, mut o) = fixture();
        s.borrow_mut().create_baseline[1] = RowValue::WeakHost(baseline_weak);
        o.prepare(0).unwrap();
        let record = o.stop(&saved(&s)).unwrap();
        assert_eq!(
            record.rows.as_ref().unwrap()[1].current,
            RowValue::WeakHost(baseline_weak)
        );
        assert_eq!(record.phase, Phase::Stopped);
        assert_eq!(
            effects(&s).iter().filter(|e| *e == "weak").count(),
            usize::from(!baseline_weak.receive)
        );
    }
}
#[test]
fn invalid_captured_identity_or_nonempty_address_baseline_grants_no_row_authority() {
    for kind in 0..2 {
        let (s, mut o) = fixture();
        if kind == 0 {
            s.borrow_mut().corrupt_capture = true;
        } else {
            s.borrow_mut().create_baseline[0] = desired()[0].clone();
        }
        assert_eq!(o.prepare(0), Err(CarrierError::Invalid));
        let record = saved(&s);
        assert_eq!(record.phase, Phase::Prepared);
        assert!(record.proof.is_none());
        assert!(o.stop(&record).is_err());
        assert_eq!(effects(&s), ["create"]);
    }
}
#[test]
fn native_reattestation_races_retain_obligations_without_blind_retry() {
    for event in ["weak", "address", "restore_address", "close"] {
        let (s, mut o) = fixture();
        if event == "close" || event.starts_with("restore") {
            o.prepare(0).unwrap();
            s.borrow_mut().race_effect = Some(event);
            assert_eq!(o.stop(&saved(&s)), Err(CarrierError::Conflict));
        } else {
            s.borrow_mut().race_effect = Some(event);
            assert_eq!(o.prepare(0), Err(CarrierError::Conflict));
        }
        let record = saved(&s);
        assert_ne!(record.phase, Phase::Stopped);
        let before = effects(&s);
        assert!(o.stop(&record).is_err());
        assert_eq!(effects(&s), before);
    }
}
#[test]
fn every_cleanup_inspection_failure_retains_a_retryable_record() {
    let (s, mut o) = fixture();
    o.prepare(0).unwrap();
    let start = s.borrow().inspections;
    o.stop(&saved(&s)).unwrap();
    let end = s.borrow().inspections;
    for n in start + 1..=end {
        let (s, mut o) = fixture();
        o.prepare(0).unwrap();
        s.borrow_mut().fail_inspect_number = Some(n);
        assert!(o.stop(&saved(&s)).is_err(), "inspect {n}");
        assert_ne!(saved(&s).phase, Phase::Stopped);
        s.borrow_mut().fail_inspect_number = None;
        assert_eq!(
            o.stop(&saved(&s)).unwrap().phase,
            Phase::Stopped,
            "inspect {n}"
        );
    }
}
#[test]
fn revision_overflow_rejects_before_closing_or_mutating() {
    let (s, mut o) = fixture();
    o.prepare(0).unwrap();
    {
        let mut st = s.borrow_mut();
        let record = st.record.as_mut().unwrap();
        record.generation = u64::MAX;
        record.phase = Phase::Closing;
        for row in record.rows.as_mut().unwrap() {
            row.current = row.baseline.clone();
        }
        st.observed.rows = Some(baseline());
        st.observed.dad = None;
    }
    let before = effects(&s);
    assert_eq!(o.stop(&saved(&s)), Err(CarrierError::Invalid));
    assert_eq!(effects(&s), before);
}
#[test]
fn publication_rechecks_rows_after_configured_journal_ack() {
    let (s, mut o) = fixture();
    s.borrow_mut().change_on_configured = true;
    assert_eq!(o.prepare(0), Err(CarrierError::Conflict));
    assert_eq!(saved(&s).phase, Phase::Configured);
    assert_eq!(o.poll_ready(1), Err(CarrierError::Retired));
}

#[test]
fn false_journal_success_or_unreadable_ack_cannot_authorize_effects() {
    for number in 1..=13 {
        for ack in [Ack::FalseSuccess, Ack::ReadFailure] {
            let (s, mut o) = fixture();
            if number <= 7 {
                s.borrow_mut().fail_save = Some((number, ack));
                assert!(o.prepare(0).is_err(), "save {number}/{ack:?}");
                if number == 1 {
                    assert!(effects(&s).is_empty());
                }
                if number == 2 {
                    assert_eq!(effects(&s), ["create"]);
                }
                if number == 3 {
                    assert_eq!(effects(&s), ["create"]);
                }
                if number == 5 {
                    assert_eq!(effects(&s), ["create", "weak"]);
                }
            } else {
                o.prepare(0).unwrap();
                s.borrow_mut().fail_save = Some((number, ack));
                assert!(o.stop(&saved(&s)).is_err(), "save {number}/{ack:?}");
            }
            if let Some(record) = o.snapshot().unwrap() {
                s.borrow_mut().fail_save = None;
                if number == 2 && ack == Ack::FalseSuccess {
                    assert!(o.stop(&record).is_err());
                } else {
                    assert_eq!(
                        o.stop(&record).unwrap().phase,
                        Phase::Stopped,
                        "save {number}/{ack:?}"
                    );
                }
            }
        }
    }
}
#[test]
fn readiness_api_error_is_fail_stop_and_recovery_is_cleanup_only() {
    let (s, mut o) = fixture();
    s.borrow_mut().dads = VecDeque::from([DadState::Tentative; 16]);
    o.prepare(0).unwrap();
    s.borrow_mut().fail_inspect = true;
    assert_eq!(o.poll_ready(1), Err(CarrierError::Native));
    s.borrow_mut().fail_inspect = false;
    assert_eq!(o.poll_ready(2), Err(CarrierError::Retired));
    let record = saved(&s);
    let mut recovered = CarrierOwner::recover_for_cleanup(
        intent(),
        provenance(),
        record.clone(),
        Disk(s.clone()),
        Io(s.clone()),
    )
    .unwrap();
    assert_eq!(recovered.poll_ready(2), Err(CarrierError::Retired));
    assert_eq!(recovered.stop(&record).unwrap().phase, Phase::Stopped);
}
#[test]
fn completed_scope_never_creates_again_and_reappearance_is_not_idempotent_success() {
    let (s, mut o) = fixture();
    o.prepare(0).unwrap();
    let record = o.stop(&saved(&s)).unwrap();
    let mut fresh =
        CarrierOwner::new(intent(), provenance(), Disk(s.clone()), Io(s.clone())).unwrap();
    let before = effects(&s);
    assert_eq!(fresh.prepare(1), Err(CarrierError::Retired));
    s.borrow_mut().observed.by_guid = record.proof;
    assert_eq!(o.stop(&record), Err(CarrierError::Conflict));
    assert_eq!(effects(&s), before);
}
#[test]
fn invalid_pending_shapes_and_changed_durable_baselines_reject_before_effects() {
    let (s, mut o) = fixture();
    o.prepare(0).unwrap();
    let original = saved(&s);
    for kind in 0..4 {
        let mut changed = original.clone();
        changed.phase = Phase::Closing;
        match kind {
            0 => {
                for row in changed.rows.as_mut().unwrap() {
                    row.pending = Some(row.baseline.clone());
                }
            }
            1 => changed.rows.as_mut().unwrap()[0].pending = Some(desired()[1].clone()),
            2 => changed.rows.as_mut().unwrap()[0].pending = Some(desired()[0].clone()),
            _ => {
                changed.rows.as_mut().unwrap()[1].baseline = RowValue::WeakHost(WeakHostRow {
                    send: true,
                    receive: false,
                })
            }
        }
        s.borrow_mut().record = Some(changed.clone());
        let before = effects(&s);
        if kind < 3 {
            assert!(CarrierOwner::recover_for_cleanup(
                intent(),
                provenance(),
                changed,
                Disk(s.clone()),
                Io(s.clone())
            )
            .is_err());
        }
        assert!(o.stop(&original).is_err());
        assert_eq!(effects(&s), before);
    }
}
