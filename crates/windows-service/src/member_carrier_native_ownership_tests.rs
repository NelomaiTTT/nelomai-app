use super::*;
use nelomai_client_tunnel::redundancy::SessionScope;
use nelomai_contracts::{dispatcher::EngineIdentity, RuntimeSlot};
use std::{cell::RefCell, collections::VecDeque, fs, io::Write, path::PathBuf, rc::Rc};

fn context() -> Context {
    Context {
        intent: Intent { scope: SessionScope { runtime: RuntimeSlot::Stable,
            runtime_generation: 2, session_id: "11111111-1111-4111-8111-111111111111".into(),
            connection_generation: 3 }, addresses: vec!["10.7.0.2/32".parse().unwrap()] },
        provenance: Provenance { boot_id: [8; 16], network_epoch: 7,
            runtime: EngineIdentity { slot: RuntimeSlot::Stable, runtime_version: "0.3.3".into(),
                container_version: "0.3.3".into(), runtime_contract_version: 1, manifest_sha256: "a".repeat(64) } },
        bindings: [
            Binding { role: Role::RoleCarrier, guid: [1; 16], name: "carrier-c".into(), registry_path: r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{01010101-0101-0101-0101-010101010101}".into() },
            Binding { role: Role::MemberA, guid: [2; 16], name: "member-a".into(), registry_path: r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{02020202-0202-0202-0202-020202020202}".into() },
            Binding { role: Role::MemberB, guid: [3; 16], name: "member-b".into(), registry_path: r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{03030303-0303-0303-0303-030303030303}".into() },
        ],
    }
}

#[test]
fn retiring_and_reattaching_member_key_keeps_live_carrier_and_original_new_key() {
    let (mut owner, state, mut lock) = setup();
    let original = prepare_all(&mut owner, &mut lock);
    for role in [Role::RoleCarrier, Role::MemberA, Role::MemberB] {
        owner.before_adapter_create(role, &mut lock).unwrap();
    }
    state.borrow_mut().nic_absent[0] = false;
    state.borrow_mut().nic_absent[1] = false;
    let before_keys = state.borrow().keys;
    let mut retirement = None;
    let restored = owner
        .restore_member_key(&original, Role::MemberB, &mut retirement, &mut lock)
        .unwrap();
    assert_eq!(restored.phase, Phase::Preparing);
    assert_eq!(restored.keys[0], original.keys[0]);
    assert_eq!(restored.keys[1], original.keys[1]);
    assert_eq!(restored.keys[2].phase, KeyPhase::Captured);
    assert!(restored.keys[2].new_key_ack);
    assert_eq!(state.borrow().values[2], NativeValue::Absent);
    let token = retirement.unwrap();
    let disabled = owner
        .redisable_member_key(&restored, Role::MemberB, &token, &mut lock)
        .unwrap();
    assert_eq!(disabled.keys[2].phase, KeyPhase::Disabled);
    owner
        .before_adapter_create(Role::MemberB, &mut lock)
        .unwrap();
    assert!(owner
        .before_adapter_create(Role::MemberB, &mut lock)
        .is_err());
    assert_eq!(state.borrow().keys, before_keys);
    assert_eq!(
        state
            .borrow()
            .events
            .iter()
            .filter(|e| e.starts_with("create:"))
            .count(),
        3
    );
}

#[test]
fn member_key_cycle_refuses_live_foreign_stale_or_cleanup_authority() {
    for fault in 0..6 {
        let (mut owner, state, mut lock) = setup();
        let original = prepare_all(&mut owner, &mut lock);
        owner
            .before_adapter_create(Role::MemberB, &mut lock)
            .unwrap();
        let mut expected = original.clone();
        match fault {
            0 => state.borrow_mut().nic_absent[2] = false,
            1 => state.borrow_mut().keys[2] = Some(99),
            2 => state.borrow_mut().values[2] = NativeValue::Dword(99),
            3 => expected.generation -= 1,
            4 => lock.held = false,
            _ => {
                owner.begin_cleanup(&original, &mut lock).unwrap();
            }
        }
        let before = state.borrow().events.clone();
        let mut token = None;
        assert!(owner
            .restore_member_key(&expected, Role::MemberB, &mut token, &mut lock)
            .is_err());
        assert!(token.is_none());
        assert_eq!(state.borrow().events, before, "fault {fault}");
    }
}

#[test]
fn equal_looking_foreign_retirement_and_recovery_never_rearm_original_key() {
    let (mut owner, _, mut lock) = setup();
    let record = prepare_all(&mut owner, &mut lock);
    owner
        .before_adapter_create(Role::MemberB, &mut lock)
        .unwrap();
    let mut token = None;
    let restored = owner
        .restore_member_key(&record, Role::MemberB, &mut token, &mut lock)
        .unwrap();
    let (mut foreign, state, mut foreign_lock) = setup();
    let record = prepare_all(&mut foreign, &mut foreign_lock);
    foreign
        .before_adapter_create(Role::MemberB, &mut foreign_lock)
        .unwrap();
    let mut foreign_token = None;
    let foreign_record = foreign
        .restore_member_key(
            &record,
            Role::MemberB,
            &mut foreign_token,
            &mut foreign_lock,
        )
        .unwrap();
    assert_eq!(restored, foreign_record);
    let before = state.borrow().events.clone();
    assert!(foreign
        .redisable_member_key(
            &foreign_record,
            Role::MemberB,
            token.as_ref().unwrap(),
            &mut foreign_lock
        )
        .is_err());
    assert_eq!(state.borrow().events, before);
    let retained = foreign.into_retained();
    let mut recovered = NativeOwnership::recover(
        context(),
        foreign_record.clone(),
        Disk(state.clone()),
        Io(state.clone()),
        Some(retained),
    )
    .unwrap();
    assert!(recovered
        .redisable_member_key(
            &foreign_record,
            Role::MemberB,
            foreign_token.as_ref().unwrap(),
            &mut foreign_lock
        )
        .is_err());
    assert_eq!(state.borrow().events, before);
}

#[test]
fn carrier_create_stage_is_exact_disabled_current_generation_not_live_authority() {
    let (mut owner, _, mut lock) = setup();
    let record = prepare_all(&mut owner, &mut lock);
    let expected = context();
    let binding = &expected.bindings[0];
    assert_eq!(
        validate_carrier_create_stage(&record, &expected, binding, record.generation),
        Ok(())
    );
    assert!(validate_carrier_create_stage(&record, &expected, binding, 0).is_err());
    assert!(
        validate_carrier_create_stage(&record, &expected, binding, record.generation + 1).is_err()
    );
    assert!(validate_carrier_create_stage(
        &record,
        &expected,
        &expected.bindings[1],
        record.generation
    )
    .is_err());
    let mut changed_context = expected.clone();
    changed_context.provenance.network_epoch += 1;
    assert!(
        validate_carrier_create_stage(&record, &changed_context, binding, record.generation)
            .is_err()
    );
    let mut changed_binding = binding.clone();
    changed_binding.name.push_str("-foreign");
    assert!(
        validate_carrier_create_stage(&record, &expected, &changed_binding, record.generation)
            .is_err()
    );
    for phase in [Phase::Closing, Phase::Stopped] {
        let mut changed = record.clone();
        changed.phase = phase;
        assert!(
            validate_carrier_create_stage(&changed, &expected, binding, record.generation).is_err()
        );
    }
    for phase in [
        KeyPhase::Unstarted,
        KeyPhase::CreatePending,
        KeyPhase::Captured,
        KeyPhase::DisablePending,
        KeyPhase::RestorePending,
        KeyPhase::Clean,
    ] {
        let mut changed = record.clone();
        changed.keys[0].phase = phase;
        assert!(
            validate_carrier_create_stage(&changed, &expected, binding, record.generation).is_err()
        );
    }
    let mut no_ack = record.clone();
    no_ack.keys[0].new_key_ack = false;
    assert!(validate_carrier_create_stage(&no_ack, &expected, binding, record.generation).is_err());
    let mut no_disabled_value = record.clone();
    no_disabled_value.keys[0].current = Value::Absent;
    assert!(validate_carrier_create_stage(
        &no_disabled_value,
        &expected,
        binding,
        record.generation
    )
    .is_err());
    let mut pending = record.clone();
    pending.keys[0].pending = Some(Value::DwordZero);
    assert!(
        validate_carrier_create_stage(&pending, &expected, binding, record.generation).is_err()
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ack {
    Success,
    Fail,
    Lost,
    FalseSuccess,
    Foreign,
    Unreadable,
}
#[derive(Debug, Eq, PartialEq)]
struct FakeRetainedKey(u64); // Native boundary only; production never persists this.
struct Lock {
    held: bool,
}
struct State {
    _directory: tempfile::TempDir,
    file: PathBuf,
    events: Vec<String>,
    saves: usize,
    save_fault: Option<(usize, Ack)>,
    read_failure: bool,
    keys: [Option<u64>; 3],
    values: [NativeValue; 3],
    nic_absent: [bool; 3],
    create_ack: Ack,
    effect_fault: Option<(Value, Ack)>,
    inspection_count: usize,
    inspect_failure: Option<usize>,
    stale_challenge: bool,
    stale_generation: bool,
    wrong_context: bool,
    wrong_binding: bool,
    lie_owned_without_token: bool,
    history: Vec<NativeFacts>,
    replay: VecDeque<NativeFacts>,
}
type Shared = Rc<RefCell<State>>;
struct Disk(Shared);
struct Io(Shared);
type Owner = NativeOwnership<Disk, Io>;

// Real bounded JSON decode and fsync/rename/reread on host temporary storage.
// Faults are injected at the journal ACK boundary; this is NOT the protected
// Windows SessionFiles implementation or a claim about its authentication.
fn read_record(s: &State) -> Result<Option<Record>> {
    match fs::read(&s.file) {
        Ok(bytes) if bytes.len() <= MAX_RECORD_BYTES => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| Error::Journal),
        Ok(_) => Err(Error::Journal),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(Error::Journal),
    }
}
fn write_record(s: &State, record: &Record) {
    let bytes = serde_json::to_vec(record).unwrap();
    assert!(bytes.len() <= MAX_RECORD_BYTES);
    let mut file = tempfile::NamedTempFile::new_in(s.file.parent().unwrap()).unwrap();
    file.write_all(&bytes).unwrap();
    file.as_file().sync_all().unwrap();
    file.persist(&s.file).unwrap();
    // Real directory durability on this Unix host; no assertion that opening
    // a directory through std::fs supplies Windows protected-file authority.
    #[cfg(unix)]
    fs::File::open(s.file.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}
impl NativeJournal for Disk {
    fn load(&mut self, context: &Context) -> Result<Option<Record>> {
        let mut s = self.0.borrow_mut();
        if s.read_failure {
            s.read_failure = false;
            return Err(Error::Journal);
        }
        let record = read_record(&s)?;
        if record.as_ref().is_some_and(|r| &r.context != context) {
            return Err(Error::Conflict);
        }
        Ok(record)
    }
    fn compare_exchange(
        &mut self,
        context: &Context,
        old: Option<&Record>,
        next: &Record,
    ) -> Result<()> {
        let mut s = self.0.borrow_mut();
        assert_eq!(context, &next.context);
        if read_record(&s)?.as_ref() != old {
            return Err(Error::Conflict);
        }
        validate_transition(old, next, false)?;
        s.saves += 1;
        s.events.push(format!(
            "journal:{}:{:?}",
            next.generation, next.keys[0].phase
        ));
        let fault = s.save_fault.filter(|(n, _)| *n == s.saves).map(|(_, a)| a);
        if fault == Some(Ack::Fail) {
            return Err(Error::Journal);
        }
        if fault == Some(Ack::FalseSuccess) {
            return Ok(());
        }
        if fault == Some(Ack::Foreign) {
            let mut foreign = next.clone();
            foreign.generation += 100;
            write_record(&s, &foreign);
            return Err(Error::Journal);
        }
        write_record(&s, next);
        if fault == Some(Ack::Unreadable) {
            s.read_failure = true;
        }
        if fault == Some(Ack::Lost) {
            Err(Error::Journal)
        } else {
            Ok(())
        }
    }
}
fn native_matches(
    s: &State,
    binding: &Binding,
    ack: Option<&NewKeyAck<FakeRetainedKey>>,
) -> KeyPresence {
    match s.keys[binding.role.index()] {
        None => KeyPresence::Absent,
        Some(id) if ack.is_some_and(|a| a.retained_handle().0 == id) => {
            KeyPresence::ExactRetainedNewKey
        }
        Some(_) => KeyPresence::Foreign,
    }
}
impl NativeKeyIo for Io {
    type Key = FakeRetainedKey;
    type MutationLock = Lock;
    fn assert_serialized_lock(&mut self, lock: &mut Lock, _: &Context) -> Result<()> {
        if lock.held {
            Ok(())
        } else {
            Err(Error::Conflict)
        }
    }
    fn inspect(
        &mut self,
        lock: &mut Lock,
        record: &Record,
        binding: &Binding,
        ack: Option<&NewKeyAck<FakeRetainedKey>>,
        challenge: u64,
    ) -> Result<NativeFacts> {
        self.assert_serialized_lock(lock, &record.context)?;
        let mut s = self.0.borrow_mut();
        s.inspection_count += 1;
        if s.inspect_failure == Some(s.inspection_count) {
            return Err(Error::Native);
        }
        if let Some(replayed) = s.replay.pop_front() {
            return Ok(replayed);
        }
        let mut supplied_context = context();
        if s.wrong_context {
            supplied_context.provenance.boot_id = [9; 16];
        }
        let mut supplied_binding = context().bindings[binding.role.index()].clone();
        if s.wrong_binding {
            supplied_binding.name = "foreign".into();
        }
        let facts = NativeFacts {
            context: supplied_context,
            binding: supplied_binding,
            generation: if s.stale_generation {
                record.generation - 1
            } else {
                record.generation
            },
            challenge: if s.stale_challenge {
                challenge - 1
            } else {
                challenge
            },
            key: if s.lie_owned_without_token {
                KeyPresence::ExactRetainedNewKey
            } else {
                native_matches(&s, binding, ack)
            },
            value: s.values[binding.role.index()].clone(),
            name_absent: s.nic_absent[binding.role.index()],
            guid_absent: s.nic_absent[binding.role.index()],
            retained_nic_absent: s.nic_absent[binding.role.index()],
        };
        s.history.push(copy_facts(&facts));
        Ok(facts)
    }
    fn create_new_key(
        &mut self,
        lock: &mut Lock,
        pending: &Record,
        binding: &Binding,
        facts: &NativeFacts,
    ) -> Result<NewKeyAck<FakeRetainedKey>> {
        self.assert_serialized_lock(lock, &pending.context)?;
        let mut s = self.0.borrow_mut();
        assert_eq!(
            read_record(&s)?.as_ref(),
            Some(pending),
            "durable before effect"
        );
        assert_eq!(
            pending.keys[binding.role.index()].phase,
            KeyPhase::CreatePending
        );
        assert_eq!(facts.key, KeyPresence::Absent);
        let i = binding.role.index();
        if s.keys[i].is_some() || s.values[i] != NativeValue::Absent || !s.nic_absent[i] {
            return Err(Error::Conflict);
        }
        s.events.push(format!("create:{i}"));
        if s.create_ack == Ack::Fail {
            return Err(Error::Native);
        }
        s.keys[i] = Some(10 + i as u64);
        if s.create_ack == Ack::Lost {
            return Err(Error::Pending);
        }
        NewKeyAck::from_native_created_new_key(
            if s.create_ack == Ack::Foreign { 2 } else { 1 },
            FakeRetainedKey(10 + i as u64),
        )
    }
    fn compare_exchange_value(
        &mut self,
        lock: &mut Lock,
        pending: &Record,
        binding: &Binding,
        ack: &NewKeyAck<FakeRetainedKey>,
        facts: &NativeFacts,
        mutation: ValueCas,
    ) -> Result<()> {
        let ValueCas {
            expected,
            desired,
            value_name,
        } = mutation;
        self.assert_serialized_lock(lock, &pending.context)?;
        let mut s = self.0.borrow_mut();
        assert_eq!(
            read_record(&s)?.as_ref(),
            Some(pending),
            "durable before value CAS"
        );
        assert_eq!(pending.keys[binding.role.index()].pending, Some(desired));
        assert_eq!(value_name, "IPAutoconfigurationEnabled");
        assert_eq!(facts.key, KeyPresence::ExactRetainedNewKey);
        let i = binding.role.index();
        if native_matches(&s, binding, Some(ack)) != KeyPresence::ExactRetainedNewKey
            || s.values[i] != native_value(expected)
            || !s.nic_absent[i]
        {
            return Err(Error::Conflict);
        }
        s.events.push(format!("value:{i}:{desired:?}"));
        let fault = s
            .effect_fault
            .filter(|(value, _)| *value == desired)
            .map(|(_, ack)| ack);
        if fault == Some(Ack::Fail) {
            return Err(Error::Native);
        }
        if fault == Some(Ack::FalseSuccess) {
            return Ok(());
        }
        s.values[i] = native_value(desired);
        if fault == Some(Ack::Foreign) {
            s.values[i] = NativeValue::Dword(9);
        }
        if fault == Some(Ack::Lost) {
            Err(Error::Native)
        } else {
            Ok(())
        }
    }
}
fn native_value(value: Value) -> NativeValue {
    match value {
        Value::Absent => NativeValue::Absent,
        Value::DwordZero => NativeValue::Dword(0),
    }
}
fn setup() -> (Owner, Shared, Lock) {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("receipt.json");
    let shared = Rc::new(RefCell::new(State {
        _directory: directory,
        file,
        events: vec![],
        saves: 0,
        save_fault: None,
        read_failure: false,
        keys: [None; 3],
        values: std::array::from_fn(|_| NativeValue::Absent),
        nic_absent: [true; 3],
        create_ack: Ack::Success,
        effect_fault: None,
        inspection_count: 0,
        inspect_failure: None,
        stale_challenge: false,
        stale_generation: false,
        wrong_context: false,
        wrong_binding: false,
        lie_owned_without_token: false,
        history: vec![],
        replay: VecDeque::new(),
    }));
    let owner = NativeOwnership::new(context(), Disk(shared.clone()), Io(shared.clone())).unwrap();
    (owner, shared, Lock { held: true })
}
fn prepare_all(owner: &mut Owner, lock: &mut Lock) -> Record {
    owner.prepare_role(Role::RoleCarrier, lock).unwrap();
    owner.prepare_role(Role::MemberA, lock).unwrap();
    owner.prepare_role(Role::MemberB, lock).unwrap()
}
fn reopen(
    shared: &Shared,
    saved: Record,
    retained: Option<RetainedKeys<FakeRetainedKey>>,
) -> Result<Owner> {
    NativeOwnership::recover(
        context(),
        saved,
        Disk(shared.clone()),
        Io(shared.clone()),
        retained,
    )
}
fn copy_facts(f: &NativeFacts) -> NativeFacts {
    NativeFacts {
        context: f.context.clone(),
        binding: f.binding.clone(),
        generation: f.generation,
        challenge: f.challenge,
        key: f.key,
        value: f.value.clone(),
        name_absent: f.name_absent,
        guid_absent: f.guid_absent,
        retained_nic_absent: f.retained_nic_absent,
    }
}

#[test]
fn registry_is_journaled_before_each_effect_and_exactly_disabled_before_creation() {
    let (mut owner, shared, mut lock) = setup();
    let mut steps = 0;
    owner
        .prepare_role_in(Role::RoleCarrier, &mut lock, |call| {
            steps += 1;
            let before = shared.borrow().inspection_count;
            call()?;
            assert!(shared.borrow().inspection_count - before <= 1,
                "a supervised preparation call must not combine independent complete owner censuses");
            Ok(())
        })
        .unwrap();
    assert_eq!(steps, 9);
    owner.prepare_role(Role::MemberA, &mut lock).unwrap();
    let record = owner.prepare_role(Role::MemberB, &mut lock).unwrap();
    assert_eq!(record.version, 2);
    assert_eq!(record.generation, 13);
    assert!(record.keys.iter().all(|k| k.phase == KeyPhase::Disabled
        && k.current == Value::DwordZero
        && k.pending.is_none()));
    assert_eq!(record.native_rows, FullNativeRows::Unbound);
    assert_eq!(
        &shared.borrow().events[..7],
        [
            "journal:1:Unstarted",
            "journal:2:CreatePending",
            "create:0",
            "journal:3:Captured",
            "journal:4:DisablePending",
            "value:0:DwordZero",
            "journal:5:Disabled"
        ]
    );
    let receipt = owner
        .before_adapter_create(Role::RoleCarrier, &mut lock)
        .unwrap();
    assert_eq!(receipt.binding.guid, [1; 16]);
    assert_eq!(receipt.record, &record);
    assert_eq!(receipt.new_key_ack.retained_handle().0, 10);
    assert!(
        owner
            .before_adapter_create(Role::RoleCarrier, &mut lock)
            .is_err(),
        "single-use prerequisite"
    );
    for repeat in [false, true] {
        let (mut owner, shared, mut lock) = setup();
        assert!(owner
            .prepare_role_in(Role::RoleCarrier, &mut lock, |call| {
                if repeat {
                    call()?;
                    call()
                } else {
                    Ok(()) // Missing callback is not a completed native step.
                }
            })
            .is_err());
        assert!(shared.borrow().keys.iter().all(Option::is_none));
        assert!(owner.prepare_role(Role::RoleCarrier, &mut lock).is_err());
    }
}
#[test]
fn cleanup_restores_only_owned_values_after_nic_absence_and_never_deletes_keys() {
    let (mut owner, shared, mut lock) = setup();
    let record = prepare_all(&mut owner, &mut lock);
    let mut calls = 0;
    let stopped = owner
        .cleanup_in(&record, &mut lock, |call| {
            calls += 1;
            let before = shared.borrow().inspection_count;
            call()?;
            assert!(
                shared.borrow().inspection_count - before <= 1,
                "cleanup must independently supervise each complete owner census"
            );
            Ok(())
        })
        .unwrap();
    assert_eq!(stopped.phase, Phase::Stopped);
    assert!(stopped
        .keys
        .iter()
        .all(|k| k.current == Value::Absent && k.pending.is_none()));
    assert_eq!(shared.borrow().keys, [Some(10), Some(11), Some(12)]);
    assert_eq!(
        shared.borrow().values,
        [
            NativeValue::Absent,
            NativeValue::Absent,
            NativeValue::Absent
        ]
    );
    let effects = shared.borrow().events.len();
    assert_eq!(owner.cleanup(&stopped, &mut lock), Ok(stopped));
    assert_eq!(shared.borrow().events.len(), effects);
    for failed_call in 1..=calls {
        for unwind in [false, true] {
            let (mut owner, shared, mut lock) = setup();
            let record = prepare_all(&mut owner, &mut lock);
            let mut current_call = 0;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                owner.cleanup_in(&record, &mut lock, |call| {
                    current_call += 1;
                    call()?;
                    if current_call == failed_call {
                        if unwind {
                            panic!("cleanup original postflight");
                        }
                        return Err(Error::Pending);
                    }
                    Ok(())
                })
            }));
            assert!(result.is_err() || result.unwrap().is_err());
            assert_eq!(current_call, failed_call);
            let actual = owner.snapshot().unwrap().unwrap();
            assert_eq!(owner.current.as_ref(), Some(&actual));
            for (index, original) in owner.retained.keys.iter().enumerate() {
                assert_eq!(
                    original.as_ref().unwrap().ack.retained_handle().0,
                    10 + index as u64
                );
            }
            assert!(owner
                .before_adapter_create(Role::RoleCarrier, &mut lock)
                .is_err());
            let stopped = owner.cleanup(&actual, &mut lock).unwrap();
            assert_eq!(stopped.phase, Phase::Stopped);
            assert_eq!(shared.borrow().keys, [Some(10), Some(11), Some(12)]);
            assert_eq!(
                shared
                    .borrow()
                    .events
                    .iter()
                    .filter(|event| event.ends_with(":Absent"))
                    .count(),
                3,
                "accepted native value restoration is not repeated after postflight {failed_call}"
            );
        }
    }
}

#[test]
fn terminal_key_ack_read_uses_same_originals_without_querying_closed_handles() {
    // Break: terminal selection/final G queries a released HKEY or reads keys
    // without the original Stopped journal, retained ledger and current lock.
    let (mut owner, state, mut lock) = setup();
    let record = prepare_all(&mut owner, &mut lock);
    assert!(owner
        .with_terminal_original_key_reads(&mut lock, |_, _| -> Result<()> {
            panic!("terminal callback before actual cleanup")
        })
        .is_err());
    let stopped = owner.cleanup(&record, &mut lock).unwrap();
    let reads = state.borrow().inspection_count;
    let effects = state.borrow().events.len();
    state.borrow_mut().inspect_failure = Some(reads + 1);
    let originals = owner
        .with_terminal_original_key_reads(&mut lock, |record, keys| {
            assert_eq!(record.phase, Phase::Stopped);
            Ok(keys.map(|key| key.map(|key| key.retained_handle().0)))
        })
        .unwrap();
    assert_eq!(originals, [Some(10), Some(11), Some(12)]);
    assert_eq!(state.borrow().inspection_count, reads);
    assert_eq!(state.borrow().events.len(), effects);
    assert!(owner.prepare_role(Role::MemberA, &mut lock).is_err());
    assert_eq!(owner.snapshot().unwrap(), Some(stopped));
    lock.held = false;
    assert!(owner
        .with_terminal_original_key_reads(&mut lock, |_, _| -> Result<()> {
            panic!("terminal key ACK read ignored original serialized lock")
        })
        .is_err());
    for fault in 0..3 {
        let (mut owner, state, mut lock) = setup();
        let record = prepare_all(&mut owner, &mut lock);
        let stopped = owner.cleanup(&record, &mut lock).unwrap();
        match fault {
            0 => owner.retained.keys[1] = None,
            1 => {
                owner.retained.keys[1].as_mut().unwrap().binding = owner.context.bindings[0].clone()
            }
            _ => {}
        }
        let entered = Cell::new(false);
        let result = owner.with_terminal_original_key_reads(&mut lock, |_, _| {
            entered.set(true);
            let mut changed = stopped.clone();
            changed.generation += 1;
            write_record(&state.borrow(), &changed);
            Ok(())
        });
        assert!(result.is_err(), "fault {fault}");
        assert_eq!(entered.get(), fault == 2);
    }
}

#[test]
fn begin_cleanup_publishes_only_closing_while_live_nics_and_keys_remain_owned() {
    let (mut owner, shared, mut lock) = setup();
    let before = owner.prepare_role(Role::RoleCarrier, &mut lock).unwrap();
    {
        let mut state = shared.borrow_mut();
        state.nic_absent[0] = false;
        state.events.clear();
    }
    let closing = owner.begin_cleanup(&before, &mut lock).unwrap();
    assert_eq!(closing.phase, Phase::Closing);
    assert_eq!(closing.generation, before.generation + 1);
    assert_eq!(closing.keys, before.keys);
    assert_eq!(closing.native_rows, before.native_rows);
    assert_eq!(owner.snapshot().unwrap(), Some(closing.clone()));
    assert_eq!(shared.borrow().values[0], NativeValue::Dword(0));
    assert_eq!(
        shared.borrow().events.len(),
        1,
        "only protected journal publication"
    );
    assert!(shared.borrow().events[0].starts_with("journal:"));
    assert_eq!(
        owner.begin_cleanup(&closing, &mut lock),
        Ok(closing.clone())
    );
    assert_eq!(
        shared.borrow().events.len(),
        1,
        "no duplicate publication/effects"
    );
    assert_eq!(
        owner.prepare_role(Role::MemberA, &mut lock),
        Err(Error::Retired)
    );
    assert!(
        owner.cleanup(&closing, &mut lock).is_err(),
        "live NIC still forbids key restore"
    );
    shared.borrow_mut().nic_absent[0] = true;
    assert_eq!(
        owner.cleanup(&closing, &mut lock).unwrap().phase,
        Phase::Stopped
    );
}

#[test]
fn begin_cleanup_wrong_lock_or_record_irreversibly_denies_forward_without_effects() {
    for wrong_lock in [false, true] {
        let (mut owner, shared, mut lock) = setup();
        let before = owner.prepare_role(Role::RoleCarrier, &mut lock).unwrap();
        shared.borrow_mut().events.clear();
        let mut expected = before.clone();
        if wrong_lock {
            lock.held = false;
        } else {
            expected.generation += 1;
        }
        assert!(owner.begin_cleanup(&expected, &mut lock).is_err());
        lock.held = true;
        assert_eq!(
            owner.prepare_role(Role::MemberA, &mut lock),
            Err(Error::Retired)
        );
        assert_eq!(owner.snapshot().unwrap(), Some(before.clone()));
        assert!(shared.borrow().events.is_empty());
        assert_eq!(shared.borrow().values[0], NativeValue::Dword(0));
        // A later exact cleanup can still publish intent; no failed request
        // implies native absence or erases the original retained key.
        assert_eq!(
            owner.begin_cleanup(&before, &mut lock).unwrap().phase,
            Phase::Closing
        );
    }
}
#[test]
fn begin_cleanup_journal_fault_never_restores_keys_or_revives_forward() {
    for fault in [
        Ack::Fail,
        Ack::Lost,
        Ack::FalseSuccess,
        Ack::Unreadable,
        Ack::Foreign,
    ] {
        let (mut owner, shared, mut lock) = setup();
        let before = owner.prepare_role(Role::RoleCarrier, &mut lock).unwrap();
        {
            let mut state = shared.borrow_mut();
            state.nic_absent[0] = false;
            state.events.clear();
            state.save_fault = Some((state.saves + 1, fault));
        }
        let result = owner.begin_cleanup(&before, &mut lock);
        if fault == Ack::Lost {
            let closing = result.unwrap();
            assert_eq!(closing.phase, Phase::Closing);
            assert_eq!(owner.snapshot().unwrap(), Some(closing));
        } else {
            assert!(result.is_err(), "{fault:?}");
        }
        assert_eq!(
            owner.prepare_role(Role::MemberA, &mut lock),
            Err(Error::Retired)
        );
        assert!(owner
            .before_adapter_create(Role::RoleCarrier, &mut lock)
            .is_err());
        let state = shared.borrow();
        assert_eq!(state.values[0], NativeValue::Dword(0));
        assert_eq!(state.keys[0], Some(10));
        assert_eq!(state.events.len(), 1, "publication only, {fault:?}");
        assert!(state.events[0].starts_with("journal:"));
    }
}
#[test]
fn foreign_existing_key_value_or_nic_blocks_precreation() {
    for kind in 0..4 {
        let (mut owner, shared, mut lock) = setup();
        {
            let mut s = shared.borrow_mut();
            match kind {
                0 => s.keys[0] = Some(99),
                1 => s.values[0] = NativeValue::Dword(0),
                2 => {
                    s.values[0] = NativeValue::Other {
                        kind: 1,
                        bytes: vec![0, 0, 0, 0],
                    }
                }
                _ => s.nic_absent[0] = false,
            }
        }
        assert!(owner.prepare_role(Role::RoleCarrier, &mut lock).is_err());
        assert!(shared
            .borrow()
            .events
            .iter()
            .all(|e| !e.starts_with("create:") && !e.starts_with("value:")));
    }
}
#[test]
fn lost_or_existing_key_create_ack_never_grants_adoption_restore_or_retry() {
    for ack in [Ack::Lost, Ack::Foreign, Ack::Fail] {
        let (mut owner, shared, mut lock) = setup();
        shared.borrow_mut().create_ack = ack;
        assert!(owner.prepare_role(Role::RoleCarrier, &mut lock).is_err());
        let saved = owner.snapshot().unwrap().unwrap();
        assert_eq!(saved.keys[0].phase, KeyPhase::CreatePending);
        assert!(!saved.keys[0].new_key_ack);
        assert!(owner.prepare_role(Role::RoleCarrier, &mut lock).is_err());
        let retained = owner.into_retained();
        let mut recovered = reopen(&shared, saved.clone(), Some(retained)).unwrap();
        assert!(recovered.cleanup(&saved, &mut lock).is_err());
        assert_eq!(shared.borrow().values[0], NativeValue::Absent);
        assert!(shared
            .borrow()
            .events
            .iter()
            .all(|e| !e.starts_with("value:")));
    }
}
#[test]
fn recovery_without_live_ack_is_cleanup_only_and_cannot_adopt_json_authority() {
    let (mut owner, shared, mut lock) = setup();
    let record = prepare_all(&mut owner, &mut lock);
    drop(owner);
    let mut recovered = reopen(&shared, record.clone(), None).unwrap();
    assert!(recovered
        .before_adapter_create(Role::RoleCarrier, &mut lock)
        .is_err());
    assert!(recovered.prepare_role(Role::MemberA, &mut lock).is_err());
    assert!(recovered.cleanup(&record, &mut lock).is_err());
    assert_eq!(shared.borrow().values[0], NativeValue::Dword(0));
}
#[test]
fn explicitly_transferred_retained_ack_allows_cleanup_but_never_creation() {
    let (mut owner, shared, mut lock) = setup();
    let record = prepare_all(&mut owner, &mut lock);
    let mut recovered = reopen(&shared, record.clone(), Some(owner.into_retained())).unwrap();
    assert!(recovered
        .before_adapter_create(Role::MemberB, &mut lock)
        .is_err());
    assert!(recovered.prepare_role(Role::MemberB, &mut lock).is_err());
    assert_eq!(
        recovered.cleanup(&record, &mut lock).unwrap().phase,
        Phase::Stopped
    );
}
#[test]
fn value_lost_ack_is_resolved_only_by_exact_readback() {
    let (mut owner, shared, mut lock) = setup();
    shared.borrow_mut().effect_fault = Some((Value::DwordZero, Ack::Lost));
    let record = owner.prepare_role(Role::RoleCarrier, &mut lock).unwrap();
    assert_eq!(record.keys[0].phase, KeyPhase::Disabled);
    shared.borrow_mut().effect_fault = Some((Value::Absent, Ack::Lost));
    assert_eq!(
        owner.cleanup(&record, &mut lock).unwrap().phase,
        Phase::Stopped
    );
}
#[test]
fn false_success_write_or_wrong_type_preserves_pending_cleanup() {
    for fault in [Ack::FalseSuccess, Ack::Fail, Ack::Foreign] {
        let (mut owner, shared, mut lock) = setup();
        shared.borrow_mut().effect_fault = Some((Value::DwordZero, fault));
        assert!(owner.prepare_role(Role::RoleCarrier, &mut lock).is_err());
        let saved = owner.snapshot().unwrap().unwrap();
        assert_eq!(saved.keys[0].phase, KeyPhase::DisablePending);
        assert_eq!(saved.keys[0].pending, Some(Value::DwordZero));
        assert!(owner
            .before_adapter_create(Role::RoleCarrier, &mut lock)
            .is_err());
    }
}
#[test]
fn partial_restore_retains_exact_pending_and_can_finish_after_fresh_attestation() {
    let (mut owner, shared, mut lock) = setup();
    let saved = prepare_all(&mut owner, &mut lock);
    shared.borrow_mut().effect_fault = Some((Value::Absent, Ack::FalseSuccess));
    assert!(owner.cleanup(&saved, &mut lock).is_err());
    let partial = owner.snapshot().unwrap().unwrap();
    assert_eq!(partial.phase, Phase::Closing);
    assert_eq!(partial.keys[0].phase, KeyPhase::RestorePending);
    assert_eq!(partial.keys[0].pending, Some(Value::Absent));
    shared.borrow_mut().effect_fault = None;
    let mut recovery = reopen(&shared, partial.clone(), Some(owner.into_retained())).unwrap();
    assert_eq!(
        recovery.cleanup(&partial, &mut lock).unwrap().phase,
        Phase::Stopped
    );

    let (mut owner, shared, mut lock) = setup();
    let saved = prepare_all(&mut owner, &mut lock);
    assert!(owner
        .cleanup_in(&saved, &mut lock, |call| {
            call()?;
            if read_record(&shared.borrow())?.is_some_and(|r| {
                r.phase == Phase::Closing
                    && r.keys[0].phase == KeyPhase::Clean
                    && r.keys[1].phase == KeyPhase::Disabled
            }) {
                return Err(Error::Pending);
            }
            Ok(())
        })
        .is_err());
    let partial = owner.snapshot().unwrap().unwrap();
    assert_eq!(partial.phase, Phase::Closing);
    assert_eq!(partial.keys[0].phase, KeyPhase::Clean);
    assert_eq!(partial.keys[1].phase, KeyPhase::Disabled);
    assert!(owner
        .before_adapter_create(Role::RoleCarrier, &mut lock)
        .is_err());
    assert_eq!(
        owner.cleanup(&partial, &mut lock).unwrap().phase,
        Phase::Stopped
    );
    assert_eq!(
        shared
            .borrow()
            .events
            .iter()
            .filter(|e| e.ends_with(":Absent"))
            .count(),
        3
    );
}
#[test]
fn stale_native_proof_scope_binding_generation_and_challenge_fail_closed() {
    for kind in 0..4 {
        let (mut owner, shared, mut lock) = setup();
        let saved = prepare_all(&mut owner, &mut lock);
        {
            let mut s = shared.borrow_mut();
            match kind {
                0 => s.wrong_context = true,
                1 => s.wrong_binding = true,
                2 => s.stale_generation = true,
                _ => s.stale_challenge = true,
            }
        }
        assert!(owner
            .before_adapter_create(Role::RoleCarrier, &mut lock)
            .is_err());
        assert!(owner.cleanup(&saved, &mut lock).is_err());
        assert_eq!(shared.borrow().values[0], NativeValue::Dword(0));
    }
}
#[test]
fn replaced_key_foreign_value_and_present_nic_prevent_restoration() {
    for kind in 0..4 {
        let (mut owner, shared, mut lock) = setup();
        let record = prepare_all(&mut owner, &mut lock);
        {
            let mut s = shared.borrow_mut();
            match kind {
                0 => s.keys[0] = Some(999),
                1 => s.values[0] = NativeValue::Dword(1),
                2 => {
                    s.values[0] = NativeValue::Other {
                        kind: 3,
                        bytes: vec![0; 4],
                    }
                }
                _ => s.nic_absent[0] = false,
            }
        }
        assert!(owner.cleanup(&record, &mut lock).is_err());
        assert!(shared
            .borrow()
            .events
            .iter()
            .all(|e| !e.ends_with(":Absent")));
    }
}
#[test]
fn invalid_role_collisions_and_exact_registry_binding_reject_before_effects() {
    for kind in 0..6 {
        let (_, shared, _) = setup();
        let mut c = context();
        match kind {
            0 => c.bindings[1].guid = c.bindings[0].guid,
            1 => c.bindings[1].name = "CARRIER-C".into(),
            2 => c.bindings[1].role = Role::MemberB,
            3 => c.bindings[0].registry_path.push_str("\\Other"),
            4 => c.provenance.boot_id = [0; 16],
            _ => c.intent.scope.connection_generation = 0,
        }
        assert!(NativeOwnership::new(c, Disk(shared.clone()), Io(shared.clone())).is_err());
        assert!(shared.borrow().events.is_empty());
    }
}
#[test]
fn lock_is_mandatory_before_journal_and_native_mutations() {
    let (mut owner, shared, mut lock) = setup();
    lock.held = false;
    assert!(owner.prepare_role(Role::RoleCarrier, &mut lock).is_err());
    assert!(shared.borrow().events.is_empty());
    lock.held = true;
    let saved = prepare_all(&mut owner, &mut lock);
    lock.held = false;
    let count = shared.borrow().events.len();
    assert!(owner.cleanup(&saved, &mut lock).is_err());
    assert_eq!(shared.borrow().events.len(), count);
}
#[test]
fn journal_lost_ack_needs_exact_durable_readback_at_every_prepare_revision() {
    for revision in 1..=13 {
        let (mut owner, shared, mut lock) = setup();
        shared.borrow_mut().save_fault = Some((revision, Ack::Lost));
        assert_eq!(prepare_all(&mut owner, &mut lock).generation, 13);
    }
}
#[test]
fn journal_false_success_uncommitted_foreign_or_unreadable_ack_never_allows_next_effect() {
    for revision in 1..=13 {
        for fault in [Ack::Fail, Ack::FalseSuccess, Ack::Foreign, Ack::Unreadable] {
            let (mut owner, shared, mut lock) = setup();
            shared.borrow_mut().save_fault = Some((revision, fault));
            let mut failed = false;
            for role in [Role::RoleCarrier, Role::MemberA, Role::MemberB] {
                if owner.prepare_role(role, &mut lock).is_err() {
                    failed = true;
                    break;
                }
            }
            assert!(failed, "revision {revision}, {fault:?}");
            assert!(owner
                .before_adapter_create(Role::RoleCarrier, &mut lock)
                .is_err());
            let s = shared.borrow();
            match revision {
                1 | 2 => assert!(s.events.iter().all(|e| e != "create:0")),
                6 => assert!(s.events.iter().all(|e| e != "create:1")),
                10 => assert!(s.events.iter().all(|e| e != "create:2")),
                _ => {}
            }
            match revision {
                1..=4 => assert!(s.events.iter().all(|e| e != "value:0:DwordZero")),
                6..=8 => assert!(s.events.iter().all(|e| e != "value:1:DwordZero")),
                10..=12 => assert!(s.events.iter().all(|e| e != "value:2:DwordZero")),
                _ => {}
            }
        }
    }
}

#[test]
fn bounded_v2_decode_reconstructs_semantics_and_rejects_unbound_native_row_versions() {
    let (mut owner, _, mut lock) = setup();
    let record = prepare_all(&mut owner, &mut lock);
    let bytes = serde_json::to_vec(&record).unwrap();
    assert_eq!(Record::decode(&bytes), Ok(record.clone()));
    assert_eq!(record.encode().unwrap(), bytes);
    for field in [
        "version",
        "generation",
        "baseline",
        "pending",
        "phase",
        "native_rows",
        "ack",
        "extra",
        "intent",
        "binding",
        "runtime",
        "scope",
        "receipt",
    ] {
        let mut wire = serde_json::to_value(&record).unwrap();
        match field {
            "version" => wire["version"] = 1.into(),
            "generation" => wire["generation"] = 0.into(),
            "baseline" => wire["keys"][0]["baseline"] = "DwordZero".into(),
            "pending" => wire["keys"][0]["pending"] = "Absent".into(),
            "phase" => wire["phase"] = "Stopped".into(),
            "native_rows" => wire["native_rows"] = serde_json::json!({"V2": {"bytes": [0, 1]}}),
            "ack" => wire["keys"][0]["new_key_ack"] = false.into(),
            "intent" => wire["context"]["intent"]["extra"] = 1.into(),
            "binding" => wire["context"]["bindings"][0]["handle"] = 1.into(),
            "runtime" => wire["context"]["provenance"]["runtime"]["extra"] = 1.into(),
            "scope" => wire["context"]["intent"]["scope"]["extra"] = 1.into(),
            "receipt" => wire["keys"][0]["extra"] = 1.into(),
            _ => wire["extra"] = 1.into(),
        }
        let altered = serde_json::to_vec(&wire).unwrap();
        assert!(Record::decode(&altered).is_err(), "{field}");
        assert!(
            serde_json::from_slice::<Record>(&altered).is_err(),
            "strict direct reconstruction {field}"
        );
    }
    let mut padded = vec![b' '; MAX_RECORD_BYTES];
    padded.extend(bytes);
    assert!(Record::decode(&padded).is_err());
}
#[test]
fn a_cached_native_proof_from_a_prior_cleanup_owner_is_never_fresh() {
    let (mut owner, shared, mut lock) = setup();
    let prepared = prepare_all(&mut owner, &mut lock);
    let stopped = owner.cleanup(&prepared, &mut lock).unwrap();
    let mut first = reopen(&shared, stopped.clone(), Some(owner.into_retained())).unwrap();
    shared.borrow_mut().history.clear();
    assert_eq!(first.cleanup(&stopped, &mut lock), Ok(stopped.clone()));
    {
        let mut s = shared.borrow_mut();
        s.replay = std::mem::take(&mut s.history).into();
        s.values[0] = NativeValue::Dword(99);
    }
    let mut second = reopen(&shared, stopped.clone(), Some(first.into_retained())).unwrap();
    assert!(
        second.cleanup(&stopped, &mut lock).is_err(),
        "old proof cannot conceal changed value"
    );
}
#[test]
fn cleanup_lost_ack_recovers_each_revision_without_repeating_accepted_effects() {
    for revision in 14..=21 {
        let (mut owner, shared, mut lock) = setup();
        let saved = prepare_all(&mut owner, &mut lock);
        shared.borrow_mut().save_fault = Some((revision, Ack::Lost));
        let stopped = owner.cleanup(&saved, &mut lock).unwrap();
        assert_eq!(stopped.phase, Phase::Stopped);
        assert_eq!(
            shared
                .borrow()
                .events
                .iter()
                .filter(|e| e.ends_with(":Absent"))
                .count(),
            3
        );
    }
}
#[test]
fn crash_at_every_prepare_revision_cannot_enable_creation_or_manufacture_handle_authority() {
    // A whole native step may return its real NEW ACK and then lose timing /
    // authentication postflight. The SAME owner must retain it on Err/unwind.
    for failed_step in 1..=9 {
        for unwind in [false, true] {
            let (mut owner, shared, mut lock) = setup();
            let mut calls = 0;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                owner.prepare_role_in(Role::RoleCarrier, &mut lock, |call| {
                    calls += 1;
                    call()?;
                    if calls == failed_step {
                        if unwind {
                            panic!("native preparation postflight unwind");
                        }
                        return Err(Error::Pending);
                    }
                    Ok(())
                })
            }));
            assert!(result.is_err() || result.unwrap().is_err());
            assert_eq!(calls, failed_step);
            let saved = owner.snapshot().unwrap().unwrap();
            assert_eq!(owner.current.as_ref(), Some(&saved));
            let held = owner.retained.keys[0].as_ref();
            assert_eq!(held.is_some(), failed_step >= 4);
            if let Some(held) = held {
                assert_eq!(held.ack.retained_handle().0, 10);
                assert_eq!(shared.borrow().keys[0], Some(10));
            }
            assert!(owner
                .before_adapter_create(Role::RoleCarrier, &mut lock)
                .is_err());
            assert!(owner.prepare_role(Role::MemberA, &mut lock).is_err());
            assert_eq!(owner.retained.keys[0].is_some(), failed_step >= 4);
        }
    }
    for revision in 1..=13 {
        let (mut owner, shared, mut lock) = setup();
        shared.borrow_mut().save_fault = Some((revision, Ack::Unreadable));
        for role in [Role::RoleCarrier, Role::MemberA, Role::MemberB] {
            if owner.prepare_role(role, &mut lock).is_err() {
                break;
            }
        }
        let saved = owner.snapshot().unwrap().unwrap();
        drop(owner);
        let mut recovered = reopen(&shared, saved.clone(), None).unwrap();
        assert!(recovered
            .prepare_role(Role::RoleCarrier, &mut lock)
            .is_err());
        assert!(recovered
            .before_adapter_create(Role::RoleCarrier, &mut lock)
            .is_err());
        let prior = shared.borrow().values.clone();
        let result = recovered.cleanup(&saved, &mut lock);
        if revision == 1 {
            assert_eq!(result.unwrap().phase, Phase::Stopped);
        } else {
            assert!(result.is_err(), "revision {revision}");
        }
        assert_eq!(shared.borrow().values, prior);
    }
}
#[test]
fn prepared_cleanup_never_changes_provenance_or_revision_and_rejects_foreign_durable_records() {
    for kind in 0..8 {
        let (mut owner, shared, mut lock) = setup();
        let saved = prepare_all(&mut owner, &mut lock);
        let mut altered = saved.clone();
        match kind {
            0 => altered.context.provenance.boot_id = [9; 16],
            1 => altered.context.provenance.network_epoch += 1,
            2 => altered.context.provenance.runtime.manifest_sha256 = "b".repeat(64),
            3 => altered.context.intent.scope.runtime_generation += 1,
            4 => altered.context.intent.scope.connection_generation += 1,
            5 => {
                altered.context.intent.scope.session_id =
                    "22222222-2222-4222-8222-222222222222".into()
            }
            6 => altered.generation += 1,
            _ => altered.context.bindings[0].name = "replacement".into(),
        }
        assert!(owner.cleanup(&altered, &mut lock).is_err());
        assert!(reopen(&shared, altered, None).is_err());
        assert_eq!(shared.borrow().values[0], NativeValue::Dword(0));
    }
}
#[test]
fn transition_firewall_cannot_capture_or_disable_from_cleanup_or_change_baseline() {
    let c = context();
    let first = initial(&c);
    let mut pending = next(&first).unwrap();
    pending.keys[0].phase = KeyPhase::CreatePending;
    assert!(validate_transition(Some(&first), &pending, false).is_ok());
    assert!(validate_transition(Some(&first), &pending, true).is_err());
    let mut captured = next(&pending).unwrap();
    captured.keys[0].phase = KeyPhase::Captured;
    captured.keys[0].new_key_ack = true;
    assert!(validate_transition(Some(&pending), &captured, true).is_err());
    captured.generation += 1;
    assert!(validate_transition(Some(&pending), &captured, false).is_err());
    let mut corrupt = first.clone();
    corrupt.keys[0].baseline = Value::DwordZero;
    assert!(validate_transition(None, &corrupt, false).is_err());
    assert!(validate_transition(None, &first, true).is_err());
}
#[test]
fn every_native_inspection_failure_retains_obligations_without_adapter_creation_authority() {
    let (mut owner, shared, mut lock) = setup();
    let record = prepare_all(&mut owner, &mut lock);
    let prepare_reads = shared.borrow().inspection_count;
    let _ = owner.cleanup(&record, &mut lock).unwrap();
    let total_reads = shared.borrow().inspection_count;
    for at in 1..=total_reads {
        let (mut owner, shared, mut lock) = setup();
        shared.borrow_mut().inspect_failure = Some(at);
        let mut result = Ok(None);
        for role in [Role::RoleCarrier, Role::MemberA, Role::MemberB] {
            result = owner.prepare_role(role, &mut lock).map(Some);
            if result.is_err() {
                break;
            }
        }
        if at <= prepare_reads {
            assert!(result.is_err(), "prepare read {at}");
        } else {
            assert!(
                owner.cleanup(&result.unwrap().unwrap(), &mut lock).is_err(),
                "cleanup read {at}"
            );
        }
        let durable = owner.snapshot().unwrap().unwrap();
        assert!(owner
            .before_adapter_create(Role::RoleCarrier, &mut lock)
            .is_err());
        assert!(durable.generation > 0);
    }
}

#[test]
fn exhausted_revision_cannot_apply_a_restore_that_cannot_be_confirmed_durably() {
    let (mut owner, shared, mut lock) = setup();
    let record = prepare_all(&mut owner, &mut lock);
    shared.borrow_mut().effect_fault = Some((Value::Absent, Ack::Fail));
    assert!(owner.cleanup(&record, &mut lock).is_err());
    let mut partial = owner.snapshot().unwrap().unwrap();
    partial.generation = u64::MAX;
    {
        let s = shared.borrow();
        write_record(&s, &partial);
    }
    shared.borrow_mut().effect_fault = None;
    let mut recovered = reopen(&shared, partial.clone(), Some(owner.into_retained())).unwrap();
    let before = shared.borrow().events.len();
    assert!(recovered.cleanup(&partial, &mut lock).is_err());
    assert_eq!(
        shared.borrow().values[0],
        NativeValue::Dword(0),
        "no native restore on exhausted revision"
    );
    assert_eq!(shared.borrow().events.len(), before);
}
#[test]
fn every_cleanup_journal_fault_keeps_durable_cleanup_recoverable_with_original_live_tokens() {
    for revision in 14..=21 {
        for fault in [Ack::Fail, Ack::FalseSuccess, Ack::Unreadable] {
            let (mut owner, shared, mut lock) = setup();
            let prepared = prepare_all(&mut owner, &mut lock);
            shared.borrow_mut().save_fault = Some((revision, fault));
            assert!(
                owner.cleanup(&prepared, &mut lock).is_err(),
                "{revision} {fault:?}"
            );
            let saved = owner.snapshot().unwrap().unwrap();
            assert!(owner
                .before_adapter_create(Role::RoleCarrier, &mut lock)
                .is_err());
            shared.borrow_mut().save_fault = None;
            let mut recovered =
                reopen(&shared, saved.clone(), Some(owner.into_retained())).unwrap();
            assert_eq!(
                recovered.cleanup(&saved, &mut lock).unwrap().phase,
                Phase::Stopped
            );
            assert_eq!(
                shared
                    .borrow()
                    .events
                    .iter()
                    .filter(|e| e.ends_with(":Absent"))
                    .count(),
                3
            );
        }
    }
}
#[test]
fn terminal_record_does_not_conceal_nic_value_or_key_reappearance() {
    for kind in 0..3 {
        let (mut owner, shared, mut lock) = setup();
        let saved = prepare_all(&mut owner, &mut lock);
        let stopped = owner.cleanup(&saved, &mut lock).unwrap();
        {
            let mut s = shared.borrow_mut();
            match kind {
                0 => s.nic_absent[0] = false,
                1 => s.values[0] = NativeValue::Dword(0),
                _ => s.keys[0] = Some(999),
            }
        }
        let count = shared.borrow().events.len();
        assert!(owner.cleanup(&stopped, &mut lock).is_err());
        assert_eq!(shared.borrow().events.len(), count);
    }
}
#[test]
fn process_crash_with_pending_restore_never_reconstructs_ack_from_path_or_record() {
    let (mut owner, shared, mut lock) = setup();
    let saved = prepare_all(&mut owner, &mut lock);
    shared.borrow_mut().save_fault = Some((16, Ack::Unreadable)); // Restore applied, confirmation ACK not observable.
    assert!(owner.cleanup(&saved, &mut lock).is_err());
    let saved = owner.snapshot().unwrap().unwrap();
    drop(owner);
    shared.borrow_mut().save_fault = None;
    let before = shared.borrow().events.len();
    let mut recovered = reopen(&shared, saved.clone(), None).unwrap();
    assert!(recovered.cleanup(&saved, &mut lock).is_err());
    assert_eq!(shared.borrow().events.len(), before);
    assert_eq!(shared.borrow().values[1], NativeValue::Dword(0));
}
#[test]
fn native_ack_constructor_rejects_every_non_created_disposition() {
    for disposition in [0, 2, 3, u32::MAX] {
        assert!(NewKeyAck::from_native_created_new_key(disposition, FakeRetainedKey(88)).is_err());
    }
    let ack = NewKeyAck::from_native_created_new_key(1, FakeRetainedKey(88)).unwrap();
    assert_eq!(ack.retained_handle().0, 88);
}

#[test]
fn precreation_handoff_retains_the_callers_serialized_mutation_lock() {
    let (mut owner, _, mut lock) = setup();
    owner.prepare_role(Role::RoleCarrier, &mut lock).unwrap();
    let mut calls = 0;
    let receipt = owner
        .before_adapter_create_in(Role::RoleCarrier, &mut lock, &mut |call| {
            calls += 1;
            call()
        })
        .unwrap();
    assert!(receipt.mutation_lock.held);
    assert_eq!(calls, 1);
    for unwind in [false, true] {
        let (mut owner, state, mut lock) = setup();
        owner.prepare_role(Role::RoleCarrier, &mut lock).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner
                .before_adapter_create_in(Role::RoleCarrier, &mut lock, &mut |call| {
                    call()?;
                    if unwind {
                        panic!("original precreation postflight");
                    }
                    Err(Error::Pending)
                })
                .map(|_| ())
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert_eq!(
            owner.retained.keys[0]
                .as_ref()
                .unwrap()
                .ack
                .retained_handle()
                .0,
            10
        );
        assert_eq!(state.borrow().keys[0], Some(10));
        assert!(owner.prepare_role(Role::MemberA, &mut lock).is_err());
    }
}

#[test]
fn a_boundary_ownership_label_cannot_replace_the_original_retained_ack_token() {
    let (mut owner, shared, mut lock) = setup();
    let prepared = prepare_all(&mut owner, &mut lock);
    let stopped = owner.cleanup(&prepared, &mut lock).unwrap();
    drop(owner);
    shared.borrow_mut().lie_owned_without_token = true;
    let mut recovered = reopen(&shared, stopped.clone(), None).unwrap();
    assert!(
        recovered.cleanup(&stopped, &mut lock).is_err(),
        "native label plus JSON is not a retained handle"
    );
}

// Initialization tests use real host-file CAS and an actual retained MutexGuard.
// Only external registry/SDK effects are replaced by the existing Io boundary.
mod initialization {
    use super::*;
    use crate::member_serialized_lease::{ReadPin, SerializedLease};
    use std::{
        cell::Cell,
        panic::{catch_unwind, AssertUnwindSafe},
        sync::Mutex,
    };

    struct PinDrop(Rc<Cell<usize>>);
    impl Drop for PinDrop {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    struct Journal<'a> {
        disk: Disk,
        lease: ReadPin<'a, ()>,
        original: Rc<()>,
        _drop: PinDrop,
        panic_cas: bool,
        panic_after_cas: bool,
        panic_read: bool,
        loads: usize,
        on_load: Option<Box<dyn FnMut()>>,
    }
    impl NativeJournal for Journal<'_> {
        fn load(&mut self, c: &Context) -> Result<Option<Record>> {
            self.loads += 1;
            if let Some(mut callback) = self.on_load.take() {
                callback();
            }
            if self.panic_read {
                panic!("initial read unwind");
            }
            self.disk.load(c)
        }
        fn compare_exchange(
            &mut self,
            c: &Context,
            old: Option<&Record>,
            next: &Record,
        ) -> Result<()> {
            if next.generation == 1 {
                assert!(old.is_none(), "initial CAS must expect exact None");
            }
            if self.panic_cas {
                panic!("initial CAS unwind");
            }
            self.disk.compare_exchange(c, old, next)?;
            if self.panic_after_cas {
                panic!("committed initial CAS unwind");
            }
            Ok(())
        }
    }
    struct Keys<'a> {
        io: Io,
        lease: ReadPin<'a, ()>,
        original: Rc<()>,
        _drop: PinDrop,
        panic_attach: bool,
        attachment_checks: usize,
        on_second_attachment: Option<Box<dyn FnMut()>>,
    }
    impl NativeKeyIo for Keys<'_> {
        type Key = FakeRetainedKey;
        type MutationLock = SerializedLease<'static, ()>;
        fn assert_serialized_lock(
            &mut self,
            lock: &mut Self::MutationLock,
            _: &Context,
        ) -> Result<()> {
            if self.lease.matches(&lock.pin()) {
                Ok(())
            } else {
                Err(Error::Conflict)
            }
        }
        fn inspect(
            &mut self,
            lock: &mut Self::MutationLock,
            r: &Record,
            b: &Binding,
            ack: Option<&NewKeyAck<Self::Key>>,
            challenge: u64,
        ) -> Result<NativeFacts> {
            self.assert_serialized_lock(lock, &r.context)?;
            self.io
                .inspect(&mut Lock { held: true }, r, b, ack, challenge)
        }
        fn create_new_key(
            &mut self,
            lock: &mut Self::MutationLock,
            r: &Record,
            b: &Binding,
            f: &NativeFacts,
        ) -> Result<NewKeyAck<Self::Key>> {
            self.assert_serialized_lock(lock, &r.context)?;
            self.io.create_new_key(&mut Lock { held: true }, r, b, f)
        }
        fn compare_exchange_value(
            &mut self,
            lock: &mut Self::MutationLock,
            r: &Record,
            b: &Binding,
            ack: &NewKeyAck<Self::Key>,
            f: &NativeFacts,
            v: ValueCas,
        ) -> Result<()> {
            self.assert_serialized_lock(lock, &r.context)?;
            self.io
                .compare_exchange_value(&mut Lock { held: true }, r, b, ack, f, v)
        }
    }
    impl NativeKeyAttachment<Journal<'_>> for Keys<'_> {
        fn assert_original_journal_lock(
            &mut self,
            journal: &Journal<'_>,
            lock: &mut Self::MutationLock,
            c: &Context,
        ) -> Result<()> {
            if self.panic_attach {
                panic!("attachment check unwind");
            }
            self.assert_serialized_lock(lock, c)?;
            if !Rc::ptr_eq(&journal.original, &self.original) || !journal.lease.matches(&self.lease)
            {
                return Err(Error::Conflict);
            }
            self.attachment_checks += 1;
            if self.attachment_checks == 2 {
                if let Some(mut callback) = self.on_second_attachment.take() {
                    callback();
                }
            }
            Ok(())
        }
    }
    type Pending = PendingNativeOwnership<Journal<'static>>;
    type Attached = NativeOwnership<InitializedJournal<Journal<'static>>, Keys<'static>>;
    struct Fixture {
        shared: Shared,
        mutex: &'static Mutex<()>,
        lock: SerializedLease<'static, ()>,
        journal: Journal<'static>,
        journal_drops: Rc<Cell<usize>>,
        key_drops: Rc<Cell<usize>>,
    }
    impl Fixture {
        fn new() -> Self {
            let (_, shared, _) = setup();
            let mutex = Box::leak(Box::new(Mutex::new(())));
            let lock = SerializedLease::new((), mutex.try_lock().unwrap());
            let journal_drops = Rc::new(Cell::new(0));
            Self {
                journal: Journal {
                    disk: Disk(shared.clone()),
                    lease: lock.pin(),
                    original: Rc::new(()),
                    _drop: PinDrop(journal_drops.clone()),
                    panic_cas: false,
                    panic_after_cas: false,
                    panic_read: false,
                    loads: 0,
                    on_load: None,
                },
                shared,
                mutex,
                lock,
                journal_drops,
                key_drops: Rc::new(Cell::new(0)),
            }
        }
        // Created only after initialize in the positive test: no placeholder SDK
        // authority, registry handle, or Keys object exists during publication.
        fn keys(&self) -> Keys<'static> {
            Keys {
                io: Io(self.shared.clone()),
                lease: self.lock.pin(),
                original: self.journal.original.clone(),
                _drop: PinDrop(self.key_drops.clone()),
                panic_attach: false,
                attachment_checks: 0,
                on_second_attachment: None,
            }
        }
    }
    fn no_native(shared: &Shared) {
        let s = shared.borrow();
        assert_eq!(s.inspection_count, 0);
        assert_eq!(s.keys, [None; 3]);
        assert_eq!(
            s.values,
            [
                NativeValue::Absent,
                NativeValue::Absent,
                NativeValue::Absent
            ]
        );
        assert!(s.events.iter().all(|event| event.starts_with("journal:")));
    }

    // Break caught: requiring Keys/SDK or not publishing generation1 Unstarted
    // before bootstrap; forgetting current would attempt a second initial CAS.
    #[test]
    fn initializes_before_keys_and_attaches_original_receipt_and_ack() {
        let f = Fixture::new();
        let original = f.journal.original.clone();
        let lease = f.journal.lease.read_pin();
        let mut pending = Some(Pending::new(context(), f.journal));
        let r = pending.as_mut().unwrap().initialize().unwrap().clone();
        assert_eq!(r.generation, 1);
        assert_eq!(r.version, 2);
        assert_eq!(r.phase, Phase::Preparing);
        assert_eq!(r.context, context());
        for (key, role) in r
            .keys
            .iter()
            .zip([Role::RoleCarrier, Role::MemberA, Role::MemberB])
        {
            assert_eq!(
                key,
                &KeyReceipt {
                    role,
                    phase: KeyPhase::Unstarted,
                    new_key_ack: false,
                    baseline: Value::Absent,
                    current: Value::Absent,
                    pending: None
                }
            );
        }
        assert_eq!(r.native_rows, FullNativeRows::Unbound);
        no_native(&f.shared);
        assert_eq!(pending.as_mut().unwrap().verify_initial().unwrap(), r);
        assert_eq!(f.shared.borrow().saves, 1, "verification is READ only");
        let mut keys = Some(Keys {
            io: Io(f.shared.clone()),
            lease,
            original,
            _drop: PinDrop(f.key_drops.clone()),
            panic_attach: false,
            attachment_checks: 0,
            on_second_attachment: None,
        });
        let keys_lease = keys.as_ref().unwrap().lease.read_pin();
        let mut owner: Option<Attached> = None;
        let mut lock = f.lock;
        Pending::attach(&mut pending, &mut keys, &mut owner, &mut lock).unwrap();
        assert!(pending.is_none());
        assert!(keys.is_none());
        let owner = owner.as_mut().unwrap();
        assert_eq!(owner.current.as_ref(), Some(&r));
        no_native(&f.shared);
        let prepared = owner.prepare_role(Role::RoleCarrier, &mut lock).unwrap();
        assert_eq!(prepared.generation, 5);
        assert_eq!(prepared.keys[0].phase, KeyPhase::Disabled);
        let receipt = owner
            .before_adapter_create(Role::RoleCarrier, &mut lock)
            .unwrap();
        assert_eq!(receipt.new_key_ack.retained_handle().0, 10);
        assert!(receipt.mutation_lock.matches(&keys_lease));
        assert_eq!(f.journal_drops.get(), 0);
        assert_eq!(f.key_drops.get(), 0);
        assert_eq!(f.shared.borrow().saves, 5);
    }

    // Break caught: accepting a lost/false ACK or rearming after a failed CAS.
    #[test]
    fn failed_initial_ack_is_fenced_even_when_exact_json_was_committed() {
        for fault in [
            Ack::Fail,
            Ack::Lost,
            Ack::FalseSuccess,
            Ack::Foreign,
            Ack::Unreadable,
        ] {
            let f = Fixture::new();
            let mut keys = Some(f.keys());
            f.shared.borrow_mut().save_fault = Some((1, fault));
            let mut pending = Some(Pending::new(context(), f.journal));
            assert!(pending.as_mut().unwrap().initialize().is_err(), "{fault:?}");
            f.shared.borrow_mut().save_fault = None;
            assert_eq!(pending.as_mut().unwrap().initialize(), Err(Error::Retired));
            assert!(pending.as_mut().unwrap().verify_initial().is_err());
            let mut owner: Option<Attached> = None;
            let mut lock = f.lock;
            assert!(Pending::attach(&mut pending, &mut keys, &mut owner, &mut lock).is_err());
            assert!(pending.is_some() && keys.is_some() && owner.is_none());
            assert_eq!(f.journal_drops.get(), 0);
            assert_eq!(f.key_drops.get(), 0);
            assert_eq!(f.shared.borrow().saves, 1, "{fault:?}");
            no_native(&f.shared);
        }
    }

    // Break caught: treating matching saved JSON or absent/unreadable storage as
    // a successful initialization, or fencing only after the first load.
    #[test]
    fn preexisting_equal_record_and_initial_read_error_cannot_initialize() {
        for existing in [false, true] {
            let f = Fixture::new();
            if existing {
                write_record(&f.shared.borrow(), &initial(&context()));
            } else {
                f.shared.borrow_mut().read_failure = true;
            }
            let mut pending = Pending::new(context(), f.journal);
            assert!(pending.initialize().is_err());
            if existing {
                fs::remove_file(&f.shared.borrow().file).unwrap();
            }
            assert_eq!(pending.initialize(), Err(Error::Retired));
            assert!(pending.verify_initial().is_err());
            assert_eq!(f.shared.borrow().saves, 0);
            no_native(&f.shared);
            assert_eq!(f.journal_drops.get(), 0);
        }
    }

    // Break caught: initializing twice after success, or treating factual
    // verification as a permission that writes/republishes the initial record.
    #[test]
    fn successful_initialization_is_one_attempt_and_verification_checks_original_store() {
        let f = Fixture::new();
        let mut pending = Pending::new(context(), f.journal);
        let r = pending.initialize().unwrap().clone();
        assert_eq!(pending.initialize(), Err(Error::Retired));
        assert_eq!(pending.verify_initial().unwrap(), r);
        let mut foreign = r;
        foreign.generation = 2;
        write_record(&f.shared.borrow(), &foreign);
        assert!(pending.verify_initial().is_err());
        assert_eq!(f.shared.borrow().saves, 1);
        no_native(&f.shared);
    }

    // Break caught: setting attempted after a fallible/unwinding load or CAS.
    #[test]
    fn initialization_unwind_keeps_original_pin_and_permanent_attempt_fence() {
        for during_read in [false, true] {
            let mut f = Fixture::new();
            f.journal.panic_read = during_read;
            f.journal.panic_cas = !during_read;
            let mut pending = Pending::new(context(), f.journal);
            assert!(catch_unwind(AssertUnwindSafe(|| {
                let _ = pending.initialize();
            }))
            .is_err());
            assert_eq!(pending.initialize(), Err(Error::Retired));
            assert!(pending.verify_initial().is_err());
            assert_eq!(f.journal_drops.get(), 0);
            no_native(&f.shared);
        }
    }

    // Break caught: moving the journal/IO into a fallible return or dropping
    // them on failure; checking only equal context or a held-lock flag.
    #[test]
    fn changed_journal_lock_and_equal_foreign_runtime_deny_attach_without_rearm() {
        for kind in 0..4 {
            let f = Fixture::new();
            let mut keys = Some(f.keys());
            let mut lock = f.lock;
            let mut pending = Some(Pending::new(context(), f.journal));
            let r = pending.as_mut().unwrap().initialize().unwrap().clone();
            let original_runtime = keys.as_ref().unwrap().original.clone();
            let mut original_lock = None;
            match kind {
                0 => {
                    let mut changed = r.clone();
                    changed.generation = 2;
                    write_record(&f.shared.borrow(), &changed);
                }
                1 => {
                    f.shared.borrow_mut().read_failure = true;
                }
                2 => {
                    let m = Box::leak(Box::new(Mutex::new(())));
                    original_lock = Some(std::mem::replace(
                        &mut lock,
                        SerializedLease::new((), m.try_lock().unwrap()),
                    ));
                }
                _ => {
                    keys.as_mut().unwrap().original = Rc::new(());
                }
            }
            let mut owner: Option<Attached> = None;
            assert!(
                Pending::attach(&mut pending, &mut keys, &mut owner, &mut lock).is_err(),
                "{kind}"
            );
            assert!(pending.is_some() && keys.is_some() && owner.is_none());
            assert_eq!(f.journal_drops.get(), 0);
            assert_eq!(f.key_drops.get(), 0);
            write_record(&f.shared.borrow(), &r);
            if let Some(original) = original_lock {
                lock = original;
            }
            keys.as_mut().unwrap().original = original_runtime;
            // Repairing facts cannot rearm this original pending owner.
            assert_eq!(
                Pending::attach(&mut pending, &mut keys, &mut owner, &mut lock),
                Err(Error::Retired)
            );
            assert_eq!(pending.as_mut().unwrap().initialize(), Err(Error::Retired));
            no_native(&f.shared);
        }
    }

    // Break caught: losing an original pin across unwinding attachment checks.
    #[test]
    fn attachment_unwind_retains_both_slots_and_denies_retry() {
        let f = Fixture::new();
        let mut keys = Some(f.keys());
        keys.as_mut().unwrap().panic_attach = true;
        let mut lock = f.lock;
        let mut pending = Some(Pending::new(context(), f.journal));
        pending.as_mut().unwrap().initialize().unwrap();
        let mut owner: Option<Attached> = None;
        assert!(catch_unwind(AssertUnwindSafe(|| {
            let _ = Pending::attach(&mut pending, &mut keys, &mut owner, &mut lock);
        }))
        .is_err());
        assert!(pending.is_some() && keys.is_some() && owner.is_none());
        assert_eq!(f.journal_drops.get(), 0);
        assert_eq!(f.key_drops.get(), 0);
        keys.as_mut().unwrap().panic_attach = false;
        assert_eq!(
            Pending::attach(&mut pending, &mut keys, &mut owner, &mut lock),
            Err(Error::Retired)
        );
        no_native(&f.shared);
    }

    // Break caught: returning detached JSON instead of retaining original
    // journal/runtime, or switching to an equal imported journal at attachment.
    #[test]
    fn initial_read_pin_keeps_original_journal_alive_across_attach_and_pending_drop() {
        let f = Fixture::new();
        let mut keys = Some(f.keys());
        let mut lock = f.lock;
        let mut pending = Some(Pending::new(context(), f.journal));
        pending.as_mut().unwrap().initialize().unwrap();
        let read = pending.as_ref().unwrap().read_pin().unwrap();
        let r = read.verify(&context()).unwrap();
        let mut owner: Option<Attached> = None;
        Pending::attach(&mut pending, &mut keys, &mut owner, &mut lock).unwrap();
        assert_eq!(read.verify(&context()), Ok(r.clone()));
        drop(owner);
        drop(lock);
        assert_eq!(f.journal_drops.get(), 0, "pin retains original journal");
        assert!(
            f.mutex.try_lock().is_err(),
            "original journal pin retains real serialized guard"
        );
        assert_eq!(read.verify(&context()), Ok(r.clone()));
        let mut changed = r;
        changed.generation = 2;
        write_record(&f.shared.borrow(), &changed);
        assert!(
            read.verify(&context()).is_err(),
            "fresh original journal read"
        );
        drop(read);
        assert_eq!(f.journal_drops.get(), 1);
        assert!(f.mutex.try_lock().is_ok());
        no_native(&f.shared);
    }

    // Break caught: factual pin verification substituting a caller Context,
    // ignoring unreadable storage, or repairing health by matching JSON later.
    #[test]
    fn initial_read_denial_is_sticky_and_blocks_attachment() {
        for kind in 0..3 {
            let f = Fixture::new();
            let mut keys = Some(f.keys());
            let mut lock = f.lock;
            let mut pending = Some(Pending::new(context(), f.journal));
            let r = pending.as_mut().unwrap().initialize().unwrap().clone();
            let read = pending.as_ref().unwrap().read_pin().unwrap();
            let mut c = context();
            match kind {
                0 => c.provenance.network_epoch += 1,
                1 => f.shared.borrow_mut().read_failure = true,
                _ => {
                    let mut changed = r.clone();
                    changed.generation = 2;
                    write_record(&f.shared.borrow(), &changed);
                }
            }
            assert!(read.verify(&c).is_err());
            write_record(&f.shared.borrow(), &r);
            assert!(read.verify(&context()).is_err());
            let mut owner: Option<Attached> = None;
            assert!(Pending::attach(&mut pending, &mut keys, &mut owner, &mut lock).is_err());
            assert!(pending.is_some() && keys.is_some() && owner.is_none());
            assert_eq!(f.journal_drops.get(), 0);
            assert_eq!(f.key_drops.get(), 0);
            no_native(&f.shared);
        }
    }

    // Break caught: RefCell reentry panicking or outer success hiding the
    // sticky busy failure. Callback performs only a nested factual read.
    #[test]
    fn reentrant_initial_read_poison_is_visible_to_outer_read_and_attach() {
        let f = Fixture::new();
        let mut keys = Some(f.keys());
        let mut lock = f.lock;
        let mut pending = Some(Pending::new(context(), f.journal));
        pending.as_mut().unwrap().initialize().unwrap();
        let read = pending.as_ref().unwrap().read_pin().unwrap();
        let nested = pending.as_ref().unwrap().read_pin().unwrap();
        pending
            .as_ref()
            .unwrap()
            .journal
            .shared
            .borrow_mut()
            .journal
            .on_load = Some(Box::new(move || {
            assert!(nested.verify(&context()).is_err());
        }));
        assert!(read.verify(&context()).is_err());
        assert!(read.verify(&context()).is_err());
        let mut owner: Option<Attached> = None;
        assert!(Pending::attach(&mut pending, &mut keys, &mut owner, &mut lock).is_err());
        assert!(pending.is_some() && keys.is_some() && owner.is_none());
        no_native(&f.shared);
    }

    // Break caught: clearing health on an original adapter's read unwind.
    #[test]
    fn initial_read_unwind_retains_original_and_sticky_health() {
        let f = Fixture::new();
        let mut pending = Pending::new(context(), f.journal);
        pending.initialize().unwrap();
        let read = pending.read_pin().unwrap();
        pending.journal.shared.borrow_mut().journal.panic_read = true;
        assert!(catch_unwind(AssertUnwindSafe(|| {
            let _ = read.verify(&context());
        }))
        .is_err());
        pending.journal.shared.borrow_mut().journal.panic_read = false;
        assert!(read.verify(&context()).is_err());
        assert!(pending.read_pin().is_err());
        assert_eq!(f.journal_drops.get(), 0);
        no_native(&f.shared);
    }

    // Break caught: caching comparison data, passing an imported/equal J,
    // ignoring backend callback denial or ignoring journal drift in callback.
    #[test]
    fn inspect_initial_checks_original_backend_and_revalidates_after_callback() {
        for kind in 0..3 {
            let f = Fixture::new();
            let identity = f.journal.original.clone();
            let mut pending = Pending::new(context(), f.journal);
            let r = pending.initialize().unwrap();
            let read = pending.read_pin().unwrap();
            let result = read.inspect_initial(&context(), |j, record| {
                assert!(Rc::ptr_eq(&identity, &j.original));
                assert_eq!(record, &r);
                match kind {
                    0 => Ok(17),
                    1 => Err(Error::Conflict),
                    _ => {
                        let mut foreign = r.clone();
                        foreign.generation = 2;
                        write_record(&f.shared.borrow(), &foreign);
                        Ok(17)
                    }
                }
            });
            if kind == 0 {
                assert_eq!(result, Ok(17));
            } else {
                assert!(result.is_err());
                write_record(&f.shared.borrow(), &r);
                assert!(read.verify(&context()).is_err());
            }
            no_native(&f.shared);
        }
    }

    #[test]
    fn original_initial_cleanup_handoff_is_repeatable_but_forward_never_rearms() {
        let f = Fixture::new();
        let identity = f.journal.original.clone();
        let mut pending = Pending::new(context(), f.journal);
        let acknowledged = pending.initialize().unwrap();
        let read = pending.read_pin().unwrap();
        // Boundary double starts without a usable forward view. Only the
        // SAME journal's SDK-free cleanup handoff restores readonly storage.
        pending.journal.shared.borrow_mut().journal.panic_read = true;
        assert_eq!(
            read.inspect_original_initial_cleanup(&context(), |j, record| {
                assert!(Rc::ptr_eq(&identity, &j.original));
                assert_eq!(record, &acknowledged);
                assert_eq!(read.verify(&context()), Err(Error::Retired));
                j.panic_read = false;
                Ok(17)
            }),
            Ok(17)
        );
        assert_eq!(read.verify(&context()), Err(Error::Retired));
        assert_eq!(
            read.inspect_original_initial_cleanup(&context(), |_, record| {
                assert_eq!(record, &acknowledged);
                Ok(23)
            }),
            Ok(23)
        );
        assert!(pending.read_pin().is_err());
        assert_eq!(f.shared.borrow().saves, 1);
        no_native(&f.shared);
    }

    #[test]
    fn original_initial_cleanup_error_drift_unwind_and_reentry_keep_original_and_sticky_denial() {
        for fault in 0..5 {
            let f = Fixture::new();
            let mut pending = Pending::new(context(), f.journal);
            let acknowledged = pending.initialize().unwrap();
            let read = pending.read_pin().unwrap();
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                read.inspect_original_initial_cleanup(&context(), |_, record| {
                    assert_eq!(record, &acknowledged);
                    match fault {
                        0 => Err(Error::Conflict),
                        1 => {
                            let mut changed = record.clone();
                            changed.generation += 1;
                            write_record(&f.shared.borrow(), &changed);
                            Ok(())
                        }
                        2 => panic!("cleanup view handoff unwind"),
                        3 => {
                            // Swallowing the nested conflict must still revoke
                            // the outer original operation and future retries.
                            assert!(read
                                .inspect_original_initial_cleanup(&context(), |_, _| Ok(()))
                                .is_err());
                            Ok(())
                        }
                        _ => {
                            f.shared.borrow_mut().read_failure = true;
                            Ok(())
                        }
                    }
                })
            }));
            assert!(outcome.is_err() || outcome.unwrap().is_err());
            write_record(&f.shared.borrow(), &acknowledged);
            f.shared.borrow_mut().read_failure = false;
            let called = Cell::new(false);
            assert!(read
                .inspect_original_initial_cleanup(&context(), |_, _| {
                    called.set(true);
                    Ok(())
                })
                .is_err());
            assert!(!called.get());
            assert!(read.verify(&context()).is_err());
            assert_eq!(f.journal_drops.get(), 0);
            no_native(&f.shared);
        }
    }

    #[test]
    fn original_initial_cleanup_foreign_context_denies_before_handoff() {
        let f = Fixture::new();
        let mut pending = Pending::new(context(), f.journal);
        pending.initialize().unwrap();
        let read = pending.read_pin().unwrap();
        let mut foreign = context();
        foreign.intent.scope.connection_generation += 1;
        let called = Cell::new(false);
        assert!(read
            .inspect_original_initial_cleanup(&foreign, |_, _| {
                called.set(true);
                Ok(())
            })
            .is_err());
        assert!(!called.get());
        assert!(read
            .inspect_original_initial_cleanup(&context(), |_, _| Ok(()))
            .is_err());
        no_native(&f.shared);
    }

    #[test]
    fn original_initial_cleanup_blocks_attachment_and_journal_advance_without_effects() {
        let f = Fixture::new();
        let mut keys = Some(f.keys());
        let mut lock = f.lock;
        let mut pending = Some(Pending::new(context(), f.journal));
        let acknowledged = pending.as_mut().unwrap().initialize().unwrap();
        let read = pending.as_ref().unwrap().read_pin().unwrap();
        read.inspect_original_initial_cleanup(&context(), |_, _| Ok(()))
            .unwrap();
        let mut advanced = acknowledged.clone();
        advanced.generation += 1;
        assert_eq!(
            pending.as_mut().unwrap().journal.compare_exchange(
                &context(),
                Some(&acknowledged),
                &advanced
            ),
            Err(Error::Retired)
        );
        let mut owner: Option<Attached> = None;
        assert_eq!(
            Pending::attach(&mut pending, &mut keys, &mut owner, &mut lock),
            Err(Error::Retired)
        );
        assert!(pending.is_some() && keys.is_some() && owner.is_none());
        assert_eq!(keys.as_ref().unwrap().attachment_checks, 0);
        assert_eq!(f.journal_drops.get(), 0);
        assert_eq!(f.key_drops.get(), 0);
        assert_eq!(f.shared.borrow().saves, 1);
        // Forbidden forward operations do not manufacture a second cleanup
        // authority or revoke the still-original, read-only cleanup view.
        read.inspect_original_initial_cleanup(&context(), |_, r| {
            assert_eq!(r, &acknowledged);
            Ok(())
        })
        .unwrap();
        no_native(&f.shared);
    }

    #[test]
    fn original_initial_cleanup_cannot_relabel_real_key_advancement() {
        let f = Fixture::new();
        let mut keys = Some(f.keys());
        let mut lock = f.lock;
        let mut pending = Some(Pending::new(context(), f.journal));
        pending.as_mut().unwrap().initialize().unwrap();
        let read = pending.as_ref().unwrap().read_pin().unwrap();
        let mut owner: Option<Attached> = None;
        Pending::attach(&mut pending, &mut keys, &mut owner, &mut lock).unwrap();
        let owner = owner.as_mut().unwrap();
        let prepared = owner.prepare_role(Role::RoleCarrier, &mut lock).unwrap();
        let called = Cell::new(false);
        assert_eq!(
            read.inspect_original_initial_cleanup(&context(), |_, _| {
                called.set(true);
                Ok(())
            }),
            Err(Error::Retired)
        );
        assert!(!called.get());
        // A rejected no-C fallback must not poison legitimate key restoration.
        let stopped = owner.cleanup(&prepared, &mut lock).unwrap();
        assert_eq!(stopped.phase, Phase::Stopped);
    }

    #[test]
    fn original_initial_cleanup_requires_retained_ack_even_if_disk_matches() {
        for lost_ack in [false, true] {
            let f = Fixture::new();
            let mut pending = Pending::new(context(), f.journal);
            if lost_ack {
                pending.journal.shared.borrow_mut().journal.panic_after_cas = true;
                assert!(catch_unwind(AssertUnwindSafe(|| pending.initialize())).is_err());
            } else {
                write_record(&f.shared.borrow(), &initial(&context()));
            }
            // This private fixture probes the supplier's internal invariant;
            // the production read_pin constructor cannot issue this capability.
            assert!(pending.read_pin().is_err());
            let read = InitialRead {
                shared: pending.journal.shared.clone(),
                health: pending.journal.health.clone(),
            };
            let called = Cell::new(false);
            assert!(read
                .inspect_original_initial_cleanup(&context(), |_, _| {
                    called.set(true);
                    Ok(())
                })
                .is_err());
            assert!(!called.get());
            assert_eq!(f.journal_drops.get(), 0);
            no_native(&f.shared);
        }
    }

    #[test]
    fn original_initial_retirement_is_once_and_does_not_read_retired_active_journal() {
        let f = Fixture::new();
        let original = f.journal.original.clone();
        let mut pending = Pending::new(context(), f.journal);
        let acknowledged = pending.initialize().unwrap();
        let read = pending.read_pin().unwrap();
        let called = Cell::new(0);
        assert!(
            read.retire_original_initial_data(&context(), |_, _| {
                called.set(called.get() + 1);
                Ok(())
            })
            .is_err(),
            "no retirement before actual cleanup selection"
        );
        assert_eq!(called.get(), 0);
        read.inspect_original_initial_cleanup(&context(), |_, _| Ok(()))
            .unwrap();
        assert_eq!(
            read.retire_original_initial_data(&context(), |j, r| {
                assert!(Rc::ptr_eq(&original, &j.original));
                assert_eq!(r, &acknowledged);
                called.set(called.get() + 1);
                // Boundary double: after actual storage retirement the old active
                // journal is unusable. A postflight active read would unwind.
                j.panic_read = true;
                Ok(37)
            }),
            Ok(37)
        );
        assert_eq!(called.get(), 1);
        assert_eq!(pending.journal.load(&context()), Err(Error::Retired));
        assert!(read.verify(&context()).is_err());
        assert!(read
            .inspect_original_initial_cleanup::<()>(&context(), |_, _| {
                panic!("retired cleanup must not reenter the journal")
            })
            .is_err());
        assert!(read
            .retire_original_initial_data::<()>(&context(), |_, _| {
                panic!("retirement effect must not repeat")
            })
            .is_err());
        assert_eq!(f.journal_drops.get(), 0);
        assert_eq!(f.shared.borrow().saves, 1);
        no_native(&f.shared);
    }

    #[test]
    fn original_initial_retirement_error_unwind_drift_and_swallowed_reentry_never_rearm() {
        for fault in 0..5 {
            let f = Fixture::new();
            let mut pending = Pending::new(context(), f.journal);
            let acknowledged = pending.initialize().unwrap();
            let read = pending.read_pin().unwrap();
            read.inspect_original_initial_cleanup(&context(), |_, _| Ok(()))
                .unwrap();
            if fault == 3 {
                let mut changed = acknowledged.clone();
                changed.generation += 1;
                write_record(&f.shared.borrow(), &changed);
            }
            let called = Cell::new(false);
            let mut supplied = context();
            if fault == 4 {
                supplied.provenance.network_epoch += 1;
            }
            let result = catch_unwind(AssertUnwindSafe(|| {
                read.retire_original_initial_data(&supplied, |_, _| {
                    called.set(true);
                    match fault {
                        0 => Err(Error::Journal),
                        1 => panic!("retirement callback lost ACK"),
                        2 => {
                            assert!(read
                                .retire_original_initial_data(&context(), |_, _| Ok(()))
                                .is_err());
                            Ok(())
                        }
                        _ => panic!("preflight must reject drift or foreign context"),
                    }
                })
            }));
            assert!(result.is_err() || result.unwrap().is_err());
            assert_eq!(called.get(), fault < 3);
            write_record(&f.shared.borrow(), &acknowledged);
            assert!(read
                .retire_original_initial_data::<()>(&context(), |_, _| {
                    panic!("repair must not rearm retirement")
                })
                .is_err());
            assert_eq!(pending.journal.load(&context()), Err(Error::Retired));
            assert_eq!(f.journal_drops.get(), 0);
            no_native(&f.shared);
        }
    }

    // Break caught: issuing a pin from cached successful metadata after the
    // original protected store has become unreadable.
    #[test]
    fn read_pin_requires_fresh_original_initial_read() {
        let f = Fixture::new();
        let mut pending = Pending::new(context(), f.journal);
        pending.initialize().unwrap();
        f.shared.borrow_mut().read_failure = true;
        assert!(pending.read_pin().is_err());
        assert!(
            pending.read_pin().is_err(),
            "matching data cannot repair health"
        );
        no_native(&f.shared);
    }

    // Break caught: permitting another bootstrap after key advance, or stale
    // initial callbacks poisoning ordinary retained-key preparation/cleanup.
    #[test]
    fn key_advance_retires_initial_read_without_poisoning_key_lifecycle() {
        let f = Fixture::new();
        let mut keys = Some(f.keys());
        let mut lock = f.lock;
        let mut pending = Some(Pending::new(context(), f.journal));
        pending.as_mut().unwrap().initialize().unwrap();
        let read = pending.as_ref().unwrap().read_pin().unwrap();
        let mut owner: Option<Attached> = None;
        Pending::attach(&mut pending, &mut keys, &mut owner, &mut lock).unwrap();
        let owner = owner.as_mut().unwrap();
        owner.prepare_role(Role::RoleCarrier, &mut lock).unwrap();
        assert!(read.verify(&context()).is_err());
        owner.prepare_role(Role::MemberA, &mut lock).unwrap();
        let prepared = owner.prepare_role(Role::MemberB, &mut lock).unwrap();
        assert_eq!(prepared.generation, 13);
        assert_eq!(
            read.inspect_initial(&context(), |_, _| Ok(())),
            Err(Error::Retired)
        );
        assert_eq!(
            owner.cleanup(&prepared, &mut lock).unwrap().phase,
            Phase::Stopped
        );
    }

    // Break caught: adopting committed JSON after an original CAS unwinds
    // without delivering its ACK, or dropping original J while unwinding.
    #[test]
    fn committed_cas_unwind_never_mints_initial_receipt() {
        let mut f = Fixture::new();
        f.journal.panic_after_cas = true;
        let mut pending = Pending::new(context(), f.journal);
        assert!(catch_unwind(AssertUnwindSafe(|| {
            let _ = pending.initialize();
        }))
        .is_err());
        assert_eq!(
            read_record(&f.shared.borrow()).unwrap().unwrap().generation,
            1
        );
        assert_eq!(pending.initialize(), Err(Error::Retired));
        assert!(pending.read_pin().is_err());
        assert!(pending.verify_initial().is_err());
        assert_eq!(f.journal_drops.get(), 0);
        assert_eq!(f.shared.borrow().saves, 1);
        no_native(&f.shared);
    }

    // Break caught: moving originals before checking output occupancy/missing
    // IO, silently overwriting an existing owner, or retrying repaired slots.
    #[test]
    fn attachment_keeps_occupied_output_and_missing_io_originals() {
        let first = Fixture::new();
        let mut first_keys = Some(first.keys());
        let mut first_lock = first.lock;
        let mut first_pending = Some(Pending::new(context(), first.journal));
        let first_record = first_pending.as_mut().unwrap().initialize().unwrap();
        let mut occupied: Option<Attached> = None;
        Pending::attach(
            &mut first_pending,
            &mut first_keys,
            &mut occupied,
            &mut first_lock,
        )
        .unwrap();
        for output_occupied in [false, true] {
            let f = Fixture::new();
            let mut held_keys = Some(f.keys());
            let mut io = if output_occupied {
                held_keys.take()
            } else {
                None
            };
            let mut lock = f.lock;
            let mut pending = Some(Pending::new(context(), f.journal));
            pending.as_mut().unwrap().initialize().unwrap();
            let mut owner = if output_occupied {
                occupied.take()
            } else {
                None
            };
            assert!(Pending::attach(&mut pending, &mut io, &mut owner, &mut lock).is_err());
            assert!(pending.is_some());
            if output_occupied {
                assert!(io.is_some());
                assert_eq!(
                    owner.as_ref().unwrap().current.as_ref(),
                    Some(&first_record)
                );
                occupied = owner.take();
            } else {
                io = held_keys.take();
            }
            assert_eq!(
                Pending::attach(&mut pending, &mut io, &mut owner, &mut lock),
                Err(Error::Retired)
            );
            assert_eq!(f.journal_drops.get(), 0);
            assert_eq!(f.key_drops.get(), 0);
            no_native(&f.shared);
        }
        assert_eq!(first.journal_drops.get(), 0);
        assert_eq!(first.key_drops.get(), 0);
    }

    // Break caught: trusting the earlier receipt when the final factual
    // backend/lock callback races with protected journal replacement. The
    // callback verifies the same actual lease and returns Ok after replacement.
    #[test]
    fn final_attachment_callback_journal_race_retains_slots_and_sticky_denial() {
        let f = Fixture::new();
        let mut keys = Some(f.keys());
        let mut lock = f.lock;
        let mut pending = Some(Pending::new(context(), f.journal));
        let initial_record = pending.as_mut().unwrap().initialize().unwrap();
        let read = pending.as_ref().unwrap().read_pin().unwrap();
        let shared = f.shared.clone();
        let mut replacement = initial_record.clone();
        replacement.generation = 2;
        keys.as_mut().unwrap().on_second_attachment = Some(Box::new(move || {
            write_record(&shared.borrow(), &replacement);
        }));
        let mut owner: Option<Attached> = None;
        assert!(Pending::attach(&mut pending, &mut keys, &mut owner, &mut lock).is_err());
        assert!(pending.is_some() && keys.is_some() && owner.is_none());
        assert_eq!(f.journal_drops.get(), 0);
        assert_eq!(f.key_drops.get(), 0);
        no_native(&f.shared);
        write_record(&f.shared.borrow(), &initial_record);
        assert!(
            read.verify(&context()).is_err(),
            "health remains fenced after repair"
        );
        assert_eq!(
            Pending::attach(&mut pending, &mut keys, &mut owner, &mut lock),
            Err(Error::Retired)
        );
        assert!(pending.is_some() && keys.is_some() && owner.is_none());
        assert_eq!(pending.as_mut().unwrap().initialize(), Err(Error::Retired));
        no_native(&f.shared);
    }
}
