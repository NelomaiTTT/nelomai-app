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
    let record = prepare_all(&mut owner, &mut lock);
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
}
#[test]
fn cleanup_restores_only_owned_values_after_nic_absence_and_never_deletes_keys() {
    let (mut owner, shared, mut lock) = setup();
    let record = prepare_all(&mut owner, &mut lock);
    let stopped = owner.cleanup(&record, &mut lock).unwrap();
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
    let receipt = owner
        .before_adapter_create(Role::RoleCarrier, &mut lock)
        .unwrap();
    assert!(receipt.mutation_lock.held);
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
