use super::*;
use native_receipt::{
    Binding, Context, FullNativeRows, KeyPhase, KeyReceipt, Phase, Record, Role, Value,
};
use nelomai_client_tunnel::redundancy::{
    session::{SessionPhase, SessionState},
    Slot,
};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

const FILE: PrivateFile = PrivateFile::NativeCarrierReceipts;
const KIND: RecordKind = RecordKind::NativeCarrierReceipts;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    Fail,
    Lost,
    FalseSuccess,
    Unreadable,
    Foreign,
    EquivalentLost,
}
#[derive(Default)]
struct State {
    bytes: BTreeMap<PrivateFile, Vec<u8>>,
    writes: usize,
    receipt_attempts: usize,
    fault: Option<Fault>,
    fail_read: Option<PrivateFile>,
    race: Option<Vec<u8>>,
    meta_fault: Option<(PrivateFile, Fault)>,
    reads: Vec<PrivateFile>,
    transaction_fault: Option<bool>,
    after_transaction: Option<Box<dyn FnOnce()>>,
}
#[derive(Clone, Default)]
struct Disk(Rc<RefCell<State>>);
impl PrivateRecords for Disk {
    fn read(&mut self, file: PrivateFile) -> io::Result<Option<Vec<u8>>> {
        let mut state = self.0.borrow_mut();
        state.reads.push(file);
        if state.fail_read == Some(file) {
            return Err(io::Error::other("SECRET unreadable"));
        }
        Ok(state.bytes.get(&file).cloned())
    }
    fn compare_exchange(
        &mut self,
        file: PrivateFile,
        expected: Option<&[u8]>,
        desired: &[u8],
    ) -> io::Result<()> {
        let mut state = self.0.borrow_mut();
        if file == FILE {
            state.receipt_attempts += 1;
            if let Some(race) = state.race.take() {
                state.bytes.insert(file, race);
            }
        }
        if state.bytes.get(&file).map(Vec::as_slice) != expected
            || desired.len() > file.limit()
            || state
                .bytes
                .get(&file)
                .is_some_and(|b| b.len() > file.limit())
        {
            return Err(io::Error::other("SECRET exact CAS"));
        }
        let fault = if file == FILE {
            state.fault.take()
        } else if state.meta_fault.is_some_and(|(target, _)| target == file) {
            state.meta_fault.take().map(|(_, fault)| fault)
        } else {
            None
        };
        if fault == Some(Fault::Fail) {
            return Err(io::Error::other("SECRET uncommitted"));
        }
        if fault == Some(Fault::FalseSuccess) {
            return Ok(());
        }
        let mut bytes = desired.to_vec();
        if fault == Some(Fault::Foreign) {
            let mut outer: SavedRecord = serde_json::from_slice(&bytes).unwrap();
            let mut record = Record::decode(outer.data.as_bytes()).unwrap();
            record.generation += 100;
            outer.data = String::from_utf8(record.encode().unwrap()).unwrap();
            bytes = serde_json::to_vec(&outer).unwrap();
        }
        if fault == Some(Fault::EquivalentLost) {
            let mut outer: SavedRecord = serde_json::from_slice(&bytes).unwrap();
            let record = Record::decode(outer.data.as_bytes()).unwrap();
            outer.data = serde_json::to_string_pretty(&record).unwrap();
            bytes = serde_json::to_vec(&outer).unwrap();
        }
        state.bytes.insert(file, bytes);
        state.writes += 1;
        if fault == Some(Fault::Unreadable) {
            state.fail_read = Some(file);
        }
        if matches!(fault, Some(Fault::Lost | Fault::EquivalentLost)) {
            Err(io::Error::other("SECRET committed lost ACK"))
        } else {
            Ok(())
        }
    }
}
impl SessionFileIo for Disk {
    fn transaction<T>(
        &mut self,
        action: impl FnOnce(&mut dyn PrivateRecords) -> io::Result<T>,
    ) -> io::Result<T> {
        let fault = self.0.borrow_mut().transaction_fault.take();
        let result = action(self);
        let after = self.0.borrow_mut().after_transaction.take();
        if let Some(after) = after {
            after();
        }
        match fault {
            Some(true) => panic!("protected initial cleanup postflight"),
            Some(false) => Err(io::Error::other("protected initial cleanup postflight")),
            None => result,
        }
    }
}
fn scope() -> SessionScope {
    SessionScope {
        runtime: RuntimeSlot::Stable,
        runtime_generation: 1,
        session_id: "11111111-1111-4111-8111-111111111111".into(),
        connection_generation: 2,
    }
}
fn runtime() -> EngineIdentity {
    EngineIdentity {
        slot: RuntimeSlot::Stable,
        runtime_version: "1.0.0".into(),
        runtime_contract_version: 1,
        container_version: "1.0.0".into(),
        manifest_sha256: "a".repeat(64),
    }
}
fn context() -> Context {
    Context { intent: carrier::Intent { scope: scope(), addresses: vec!["10.7.0.2/32".parse().unwrap()] },
        provenance: carrier::Provenance { boot_id: [7; 16], runtime: runtime(), network_epoch: 1 },
        bindings: [
            Binding { role: Role::RoleCarrier, guid: [1; 16], name: "carrier-c".into(), registry_path: r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{01010101-0101-0101-0101-010101010101}".into() },
            Binding { role: Role::MemberA, guid: [2; 16], name: "member-a".into(), registry_path: r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{02020202-0202-0202-0202-020202020202}".into() },
            Binding { role: Role::MemberB, guid: [3; 16], name: "member-b".into(), registry_path: r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{03030303-0303-0303-0303-030303030303}".into() },
        ] }
}
fn initial(context: &Context) -> Record {
    Record {
        version: 2,
        context: context.clone(),
        generation: 1,
        phase: Phase::Preparing,
        keys: [Role::RoleCarrier, Role::MemberA, Role::MemberB].map(|role| KeyReceipt {
            role,
            phase: KeyPhase::Unstarted,
            new_key_ack: false,
            baseline: Value::Absent,
            current: Value::Absent,
            pending: None,
        }),
        native_rows: FullNativeRows::Unbound,
    }
}
fn next(record: &Record) -> Record {
    let mut r = record.clone();
    r.generation += 1;
    r
}

// Break: genuine initial journals cannot enter the SDK-free cleanup view, or
// equal/reopened DATA manufactures their successful initialization ACK.
#[test]
fn original_initial_cleanup_retains_unborn_and_birth_bound_journal_without_writes() {
    for bound in [false, true] {
        let (disk, mut files) = fixture();
        let c = context();
        let mut journal = open(&files);
        let record = initial(&c);
        save(&mut journal, None, &record);
        let execution = if bound {
            WindowsSessionStore::open(files.clone(), scope(), RecordKind::Session)
                .unwrap()
                .0
                .save(
                    &SessionState::new(scope(), Slot::A, 0, 0)
                        .unwrap()
                        .snapshot(),
                )
                .unwrap();
            let history = files.session_ack_root(&scope()).unwrap();
            let ack = history.acknowledgements().unwrap().last().unwrap().clone();
            let root = history.bind_native_birth(&c, &ack).unwrap();
            journal
                .bind_original_native_view(files.native_birth_view(&root).unwrap())
                .unwrap();
            Some(root)
        } else {
            None
        };
        let canonical = match &execution {
            Some(root) => root.native_cleanup_view(&files).unwrap().into_files(),
            None => files.recovery_view(RuntimeSlot::Stable).unwrap().unwrap().0,
        };
        let before = disk.0.borrow().bytes.clone();
        journal
            .enter_original_initial_cleanup(canonical.clone())
            .unwrap();
        journal
            .enter_original_initial_cleanup(canonical.clone())
            .unwrap();
        assert_eq!(journal.load(&c).unwrap(), Some(record.clone()));
        assert_eq!(disk.0.borrow().bytes, before);
        assert_eq!(journal.initial_ack.as_ref(), Some(&record));
        assert!(journal.original_files(&c).is_err());
        let mut forward = next(&record);
        forward.keys[0].phase = KeyPhase::CreatePending;
        assert!(journal
            .compare_exchange(&c, Some(&record), &forward)
            .is_err());
        let mut reopened = open(&files);
        assert!(reopened.enter_original_initial_cleanup(canonical).is_err());
    }
}

#[test]
fn original_initial_cleanup_denies_reopened_lost_ack_foreign_and_forward_views() {
    for fault in 0..5 {
        let (disk, mut files) = fixture();
        let c = context();
        let mut journal = open(&files);
        let record = initial(&c);
        if fault == 0 {
            let mut foreign_journal = open(&files);
            save(&mut foreign_journal, None, &record);
        } else if fault == 1 {
            disk.0.borrow_mut().fault = Some(Fault::Lost);
            assert!(journal.compare_exchange(&c, None, &record).is_err());
        } else {
            save(&mut journal, None, &record);
        }
        let valid = files.recovery_view(RuntimeSlot::Stable).unwrap().unwrap().0;
        let candidate = match fault {
            2 => files.clone(),
            3 => {
                let (_, mut other) = fixture();
                save(&mut open(&other), None, &record);
                other.recovery_view(RuntimeSlot::Stable).unwrap().unwrap().0
            }
            4 => {
                let mut other =
                    ProtectedSessionFiles::new(disk.clone(), runtime(), [7; 16]).unwrap();
                other.recovery_view(RuntimeSlot::Stable).unwrap().unwrap().0
            }
            _ => valid.clone(),
        };
        let before = disk.0.borrow().bytes.clone();
        assert!(journal.enter_original_initial_cleanup(candidate).is_err());
        assert!(journal.initial_cleanup_files.is_some()); // retained even on denial
        assert!(journal.enter_original_initial_cleanup(valid).is_err());
        assert!(journal.load(&c).is_err());
        assert_eq!(disk.0.borrow().bytes, before);
    }
}

#[test]
fn original_initial_cleanup_error_unwind_or_replacement_keeps_selected_view_and_fence() {
    for fault in 0..3 {
        let (disk, mut files) = fixture();
        let c = context();
        let mut journal = open(&files);
        let record = initial(&c);
        save(&mut journal, None, &record);
        let canonical = files.recovery_view(RuntimeSlot::Stable).unwrap().unwrap().0;
        if fault < 2 {
            disk.0.borrow_mut().transaction_fault = Some(fault == 1);
        } else {
            inject(&disk, &next(&record));
        }
        let before = disk.0.borrow().bytes.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            journal.enter_original_initial_cleanup(canonical.clone())
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(journal
            .initial_cleanup_files
            .as_ref()
            .unwrap()
            .same_original_backend(&canonical));
        assert_eq!(journal.initial_ack.as_ref(), Some(&record));
        assert!(journal.enter_original_initial_cleanup(canonical).is_err());
        assert!(journal.load(&c).is_err());
        assert_eq!(disk.0.borrow().bytes, before);
    }
}

fn noc_terminal_fixture_bound(
    bound: bool,
) -> (
    Disk,
    ProtectedSessionFiles<Disk>,
    Store,
    Option<epoch::ExecutionRoot<Disk>>,
) {
    let (disk, mut files) = fixture();
    let c = context();
    let mut journal = open(&files);
    save(&mut journal, None, &initial(&c));
    let execution = if bound {
        WindowsSessionStore::open(files.clone(), scope(), RecordKind::Session)
            .unwrap()
            .0
            .save(
                &SessionState::new(scope(), Slot::A, 0, 0)
                    .unwrap()
                    .snapshot(),
            )
            .unwrap();
        let history = files.session_ack_root(&scope()).unwrap();
        let root = history
            .bind_native_birth(&c, history.acknowledgements().unwrap().last().unwrap())
            .unwrap();
        journal
            .bind_original_native_view(files.native_birth_view(&root).unwrap())
            .unwrap();
        Some(root)
    } else {
        None
    };
    let mut session = SessionState::new(scope(), Slot::A, 0, 0)
        .unwrap()
        .snapshot();
    session.phase = SessionPhase::Stopped;
    WindowsSessionStore::open(files.clone(), scope(), RecordKind::Session)
        .unwrap()
        .0
        .save(&session)
        .unwrap();
    // Protected terminal Pair comparison DATA. Native NoC completion itself is
    // doubled ONLY at the mandatory unsafe boundary below, never by this JSON.
    let pair = crate::member_carrier_pair::Record {
        version: 2,
        scope: scope(),
        provenance: c.provenance.clone(),
        revision: 20,
        phase: crate::member_carrier_pair::Phase::Stopped,
        addresses: vec![],
        dns: vec![],
        carrier: None,
        members: [None, None],
        active: None,
        options: None,
        guard: crate::member_carrier_guard::Model::empty(scope()).unwrap(),
        pending_guard: None,
        pending: None,
        network: None,
        stop_stage: 12,
        operation: None,
    };
    let payload = carrier_pair_store::encode_carrier_payload(&pair).unwrap();
    let saved = SavedRecord {
        version: PRIVATE_VERSION,
        identity: SessionIdentity {
            boot_id: [7; 16],
            runtime: runtime(),
            scope: scope(),
        },
        kind: RecordKind::Pair,
        network_epoch: 1,
        data: String::from_utf8(payload).unwrap(),
    };
    disk.0
        .borrow_mut()
        .bytes
        .insert(PrivateFile::Pair, serde_json::to_vec(&saved).unwrap());
    let canonical = match &execution {
        Some(root) => root.native_cleanup_view(&files).unwrap().into_files(),
        None => files.recovery_view(RuntimeSlot::Stable).unwrap().unwrap().0,
    };
    journal.enter_original_initial_cleanup(canonical).unwrap();
    (disk, files, journal, execution)
}
fn noc_terminal_fixture() -> (Disk, ProtectedSessionFiles<Disk>, Store) {
    let (disk, files, journal, _) = noc_terminal_fixture_bound(false);
    (disk, files, journal)
}
struct CompletedNoC {
    original: InitialNativeDataRead,
    completed: bool,
    attempted: std::cell::Cell<bool>,
    failed: std::cell::Cell<bool>,
    fail_at: usize,
    reenter_at: usize,
    panic_at: usize,
    checks: std::cell::Cell<usize>,
}
impl CompletedNoC {
    fn new(original: InitialNativeDataRead) -> Self {
        Self {
            original,
            completed: true,
            attempted: std::cell::Cell::new(false),
            failed: std::cell::Cell::new(false),
            fail_at: 0,
            reenter_at: 0,
            panic_at: 0,
            checks: std::cell::Cell::new(0),
        }
    }
}
// SAFETY: explicit host double ONLY of native completed NoC issuer. Real
// ProtectedSessionFiles, exact private transaction, initial CAS/ACK and reader
// identity are exercised, not an alternate successful journal/provider.
unsafe impl OriginalInitialNativeDataRetirement for CompletedNoC {
    fn begin_retirement(&self, original: &InitialNativeDataRead) -> io::Result<()> {
        if self.attempted.replace(true) || !self.completed || !self.original.same_original(original)
        {
            self.failed.set(true);
            return Err(failed());
        }
        Ok(())
    }
    fn verify_retirement(
        &self,
        original: &InitialNativeDataRead,
        _current: &ProtectedRecoveryRecords,
    ) -> io::Result<()> {
        self.checks.set(self.checks.get() + 1);
        if self.reenter_at == self.checks.get() {
            assert!(self.begin_retirement(original).is_err()); // deliberately swallowed
        }
        assert_ne!(
            self.panic_at,
            self.checks.get(),
            "original NoC issuer unwind"
        );
        if !self.completed
            || self.failed.get()
            || !self.original.same_original(original)
            || self.fail_at == self.checks.get()
        {
            return Err(failed());
        }
        Ok(())
    }
    fn fail_retirement(&self) {
        self.failed.set(true);
    }
}

struct CompletedBeforePair(CompletedNoC);
// SAFETY: external completed-native boundary double only. The real original
// private journal, transaction, ACKs and storage completion are not replaced.
unsafe impl OriginalInitialNativeDataRetirement for CompletedBeforePair {
    fn begin_retirement(&self, original: &InitialNativeDataRead) -> io::Result<()> {
        self.0.begin_retirement(original)
    }
    fn verify_retirement(
        &self,
        original: &InitialNativeDataRead,
        current: &ProtectedRecoveryRecords,
    ) -> io::Result<()> {
        self.0.verify_retirement(original, current)?;
        self.verify_absent_pair(original, current)
    }
    fn verify_absent_pair(
        &self,
        original: &InitialNativeDataRead,
        current: &ProtectedRecoveryRecords,
    ) -> io::Result<()> {
        if !self.0.completed
            || self.0.failed.get()
            || !self.0.original.same_original(original)
            || current.scope != original.acknowledged().context.intent.scope
            || current
                .records
                .iter()
                .find(|(k, _)| *k == RecordKind::Pair)
                .is_none_or(|(_, raw)| raw.is_some())
        {
            return Err(failed());
        }
        Ok(())
    }
    fn fail_retirement(&self) {
        self.0.fail_retirement();
    }
}

#[test]
fn before_pair_initial_retirement_requires_separate_original_outcome_and_releases_real_store() {
    for bound in [false, true] {
        let (disk, mut files, mut journal, held_execution) = noc_terminal_fixture_bound(bound);
        // External private-file fixture: this original never published Pair.
        disk.0.borrow_mut().bytes.remove(&PrivateFile::Pair);
        let pin = journal.original_initial_data_read().unwrap();
        let proof = CompletedBeforePair(CompletedNoC::new(pin.clone()));
        let before = disk.0.borrow().bytes.clone();
        let retained = RefCell::new(None);
        let ack = journal
            .retire_original_initial_data(&proof, |ack| {
                *retained.borrow_mut() = Some(ack);
                Ok(())
            })
            .unwrap();
        assert!(ack.matches_original(&pin));
        assert!(Rc::ptr_eq(&ack, retained.borrow().as_ref().unwrap()));
        for kind in RecordKind::OWNED {
            assert_eq!(
                disk.0.borrow().bytes.get(&kind.file()),
                before.get(&kind.file())
            );
        }
        assert!(!disk.0.borrow().bytes.contains_key(&PrivateFile::Pair));
        files.complete(&scope()).unwrap();
        let mut next_scope = scope();
        next_scope.connection_generation += 1;
        files.claim(&next_scope).unwrap();
        assert!(files.read(&next_scope, KIND).unwrap().is_none());
        assert!(journal
            .retire_original_initial_data(&proof, |_| Ok(()))
            .is_err());
        drop(held_execution);
    }
}

#[test]
fn before_pair_retirement_rejects_default_pair_issuer_and_preserves_lost_storage_ack() {
    let (disk, _, mut journal) = noc_terminal_fixture();
    disk.0.borrow_mut().bytes.remove(&PrivateFile::Pair);
    let proof = CompletedNoC::new(journal.original_initial_data_read().unwrap());
    let before = disk.0.borrow().bytes.clone();
    assert!(journal
        .retire_original_initial_data(&proof, |_| Ok(()))
        .is_err());
    assert_eq!(disk.0.borrow().bytes, before);
    for target in [completed_file(&scope()).unwrap(), PrivateFile::Index] {
        for fault in [
            Fault::Fail,
            Fault::Lost,
            Fault::FalseSuccess,
            Fault::Unreadable,
        ] {
            let (disk, _, mut journal) = noc_terminal_fixture();
            disk.0.borrow_mut().bytes.remove(&PrivateFile::Pair);
            let pin = journal.original_initial_data_read().unwrap();
            let proof = CompletedBeforePair(CompletedNoC::new(pin));
            let native = disk.0.borrow().bytes[&FILE].clone();
            disk.0.borrow_mut().meta_fault = Some((target, fault));
            assert!(journal
                .retire_original_initial_data(&proof, |_| Ok(()))
                .is_err());
            assert!(journal.initial_retirement_ack.is_none());
            assert_eq!(disk.0.borrow().bytes[&FILE], native);
            assert!(proof.0.failed.get());
            assert!(journal
                .retire_original_initial_data(&proof, |_| Ok(()))
                .is_err());
        }
    }
}

#[test]
fn original_initial_data_retirement_preserves_preparing_and_permanent_replay_history() {
    let (disk, mut files, mut journal) = noc_terminal_fixture();
    let pin = journal.original_initial_data_read().unwrap();
    let proof = CompletedNoC::new(pin.clone());
    let old = disk.0.borrow().bytes.clone();
    let retained = RefCell::new(None);
    let ack = journal
        .retire_original_initial_data(&proof, |ack| {
            *retained.borrow_mut() = Some(ack);
            Ok(())
        })
        .unwrap();
    assert!(ack.matches_original(&pin));
    assert!(Rc::ptr_eq(&ack, retained.borrow().as_ref().unwrap()));
    for kind in RecordKind::OWNED {
        assert_eq!(
            disk.0.borrow().bytes.get(&kind.file()),
            old.get(&kind.file())
        );
    }
    assert_eq!(pin.acknowledged().phase, Phase::Preparing);
    let saved = parse_record(KIND, &old[&FILE]).unwrap();
    assert!(require_stopped_native(&saved).is_err()); // ordinary rule UNCHANGED
    files.complete(&scope()).unwrap(); // exact already-retired acknowledgement
    assert!(files.claim(&scope()).is_err());
    let mut next = scope();
    next.connection_generation += 1;
    files.claim(&next).unwrap();
    assert!(files.read(&next, KIND).unwrap().is_none()); // old DATA is not ownership
    assert!(journal
        .retire_original_initial_data(&proof, |_| Ok(()))
        .is_err());
}

#[test]
fn original_initial_data_retirement_bound_cleanup_requires_actual_live_registered_root() {
    let (disk, mut files, mut journal, root) = noc_terminal_fixture_bound(true);
    let root = root.unwrap();
    let original = journal.original_initial_data_read().unwrap();
    let proof = CompletedNoC::new(original.clone());
    let bytes = disk.0.borrow().bytes[&FILE].clone();
    journal
        .retire_original_initial_data(&proof, |_| Ok(()))
        .unwrap();
    assert_eq!(disk.0.borrow().bytes[&FILE], bytes);
    assert!(files.native_birth_view(&root).is_err()); // cleanup never re-arms
    files.complete(&scope()).unwrap();

    let (_, _, mut journal, root) = noc_terminal_fixture_bound(true);
    let proof = CompletedNoC::new(journal.original_initial_data_read().unwrap());
    drop(root); // registered Weak alone must not authenticate private cleanup
    assert!(journal
        .retire_original_initial_data(&proof, |_| Ok(()))
        .is_err());
    assert!(journal.initial_retirement_ack.is_none());
}

#[test]
fn original_initial_data_retirement_missing_or_foreign_completed_outcome_never_writes() {
    for foreign in [false, true] {
        let (disk, _, mut journal) = noc_terminal_fixture();
        let (_, _, other) = noc_terminal_fixture();
        let pin = if foreign {
            other.original_initial_data_read().unwrap()
        } else {
            journal.original_initial_data_read().unwrap()
        };
        let mut proof = CompletedNoC::new(pin);
        proof.completed = foreign;
        let before = disk.0.borrow().bytes.clone();
        assert!(journal
            .retire_original_initial_data(&proof, |_| Ok(()))
            .is_err());
        assert_eq!(disk.0.borrow().bytes, before);
        assert!(journal.initial_retirement_ack.is_none());
        assert!(journal
            .retire_original_initial_data(&proof, |_| Ok(()))
            .is_err());
    }
}

#[test]
fn original_initial_data_retirement_without_explicit_cleanup_fences_original_forward_journal() {
    let (disk, files) = fixture();
    let mut journal = open(&files);
    let record = initial(&context());
    save(&mut journal, None, &record);
    let proof = CompletedNoC::new(journal.original_initial_data_read().unwrap());
    let before = disk.0.borrow().bytes.clone();
    assert!(journal
        .retire_original_initial_data(&proof, |_| Ok(()))
        .is_err());
    let mut desired = next(&record);
    desired.keys[0].phase = KeyPhase::CreatePending;
    assert!(journal
        .compare_exchange(&context(), Some(&record), &desired)
        .is_err());
    assert_eq!(disk.0.borrow().bytes, before);
}

#[test]
fn original_initial_data_retirement_lost_marker_or_index_ack_is_not_imported() {
    for target in [completed_file(&scope()).unwrap(), PrivateFile::Index] {
        for fault in [
            Fault::Fail,
            Fault::Lost,
            Fault::FalseSuccess,
            Fault::Unreadable,
        ] {
            let (disk, _, mut journal) = noc_terminal_fixture();
            let pin = journal.original_initial_data_read().unwrap();
            let proof = CompletedNoC::new(pin);
            let original = disk.0.borrow().bytes[&FILE].clone();
            disk.0.borrow_mut().meta_fault = Some((target, fault));
            assert!(journal
                .retire_original_initial_data(&proof, |_| Ok(()))
                .is_err());
            assert!(journal.initial_retirement_ack.is_none());
            assert_eq!(disk.0.borrow().bytes[&FILE], original);
            assert!(journal
                .retire_original_initial_data(&proof, |_| Ok(()))
                .is_err());
            assert!(proof.failed.get());
        }
    }
}

#[test]
fn original_initial_data_retirement_retains_real_ack_before_postflight_error_or_unwind() {
    for fault in 0..3 {
        let (disk, _, mut journal) = noc_terminal_fixture();
        let pin = journal.original_initial_data_read().unwrap();
        let mut proof = CompletedNoC::new(pin.clone());
        if fault == 2 {
            proof.fail_at = 4;
        }
        let retained = RefCell::new(None);
        let original = disk.0.borrow().bytes[&FILE].clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            journal.retire_original_initial_data(&proof, |ack| {
                *retained.borrow_mut() = Some(ack);
                match fault {
                    0 => Err(failed()),
                    1 => panic!("NoC ACK publication unwind"),
                    _ => Ok(()),
                }
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        let actual = journal.initial_retirement_ack.as_ref().unwrap();
        assert!(actual.matches_original(&pin));
        assert!(Rc::ptr_eq(actual, retained.borrow().as_ref().unwrap()));
        assert_eq!(disk.0.borrow().bytes[&FILE], original);
        assert!(journal
            .retire_original_initial_data(&proof, |_| Ok(()))
            .is_err());
        assert!(proof.failed.get());
    }
}

#[test]
fn original_initial_data_retirement_changed_records_pending_keys_or_nonterminal_session_deny() {
    for fault in 0..4 {
        let (disk, _, mut journal) = noc_terminal_fixture();
        let pin = journal.original_initial_data_read().unwrap();
        let proof = CompletedNoC::new(pin);
        match fault {
            0 => {
                let mut changed = next(&initial(&context()));
                changed.keys[0].phase = KeyPhase::CreatePending;
                inject(&disk, &changed);
            }
            1 => {
                let raw = disk.0.borrow().bytes[&PrivateFile::Session].clone();
                let mut saved = parse_record(RecordKind::Session, &raw).unwrap();
                let mut session: SessionSnapshot = decode(&scope(), saved.data.as_bytes()).unwrap();
                session.phase = SessionPhase::Stopping;
                saved.data = serde_json::to_string(&Envelope {
                    version: 1,
                    scope: scope(),
                    payload: session,
                })
                .unwrap();
                disk.0
                    .borrow_mut()
                    .bytes
                    .insert(PrivateFile::Session, serde_json::to_vec(&saved).unwrap());
            }
            2 => {
                disk.0.borrow_mut().bytes.remove(&PrivateFile::Pair);
            }
            _ => {
                let other = disk.clone();
                disk.0.borrow_mut().after_transaction = Some(Box::new(move || {
                    // SAME typed bytes but a different exact canonical envelope,
                    // after the initial private frame completed: must not adopt.
                    let raw = other.0.borrow().bytes[&PrivateFile::Pair].clone();
                    let saved: SavedRecord = serde_json::from_slice(&raw).unwrap();
                    other.0.borrow_mut().bytes.insert(
                        PrivateFile::Pair,
                        serde_json::to_vec_pretty(&saved).unwrap(),
                    );
                }));
            }
        }
        let receipt = disk.0.borrow().bytes[&FILE].clone();
        assert!(journal
            .retire_original_initial_data(&proof, |_| Ok(()))
            .is_err());
        assert!(journal.initial_retirement_ack.is_none());
        assert!(!disk
            .0
            .borrow()
            .bytes
            .contains_key(&completed_file(&scope()).unwrap()));
        assert_eq!(disk.0.borrow().bytes[&FILE], receipt);
        assert!(proof.failed.get());
    }
}

#[test]
fn original_initial_data_retirement_swallowed_reentry_and_issuer_unwind_remain_sticky() {
    for at in [1, 4] {
        for unwind in [false, true] {
            let (disk, _, mut journal) = noc_terminal_fixture();
            let pin = journal.original_initial_data_read().unwrap();
            let mut proof = CompletedNoC::new(pin);
            if unwind {
                proof.panic_at = at;
            } else {
                proof.reenter_at = at;
            }
            let before = disk.0.borrow().bytes[&FILE].clone();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                journal.retire_original_initial_data(&proof, |_| Ok(()))
            }));
            assert!(result.is_err() || result.unwrap().is_err());
            assert_eq!(journal.initial_retirement_ack.is_some(), at == 4);
            assert!(proof.failed.get());
            assert!(journal
                .retire_original_initial_data(&proof, |_| Ok(()))
                .is_err());
            assert_eq!(disk.0.borrow().bytes[&FILE], before);
        }
    }
}
fn sequence() -> Vec<Record> {
    let mut record = initial(&context());
    let mut records = vec![record.clone()];
    for i in 0..3 {
        record = next(&record);
        record.keys[i].phase = KeyPhase::CreatePending;
        records.push(record.clone());
        record = next(&record);
        record.keys[i].phase = KeyPhase::Captured;
        record.keys[i].new_key_ack = true;
        records.push(record.clone());
        record = next(&record);
        record.keys[i].phase = KeyPhase::DisablePending;
        record.keys[i].pending = Some(Value::DwordZero);
        records.push(record.clone());
        record = next(&record);
        record.keys[i].phase = KeyPhase::Disabled;
        record.keys[i].current = Value::DwordZero;
        record.keys[i].pending = None;
        records.push(record.clone());
    }
    record = next(&record);
    record.phase = Phase::Closing;
    records.push(record.clone());
    for i in 0..3 {
        record = next(&record);
        record.keys[i].phase = KeyPhase::RestorePending;
        record.keys[i].pending = Some(Value::Absent);
        records.push(record.clone());
        record = next(&record);
        record.keys[i].phase = KeyPhase::Clean;
        record.keys[i].current = Value::Absent;
        record.keys[i].pending = None;
        records.push(record.clone());
    }
    record = next(&record);
    record.phase = Phase::Stopped;
    records.push(record);
    records
}
fn files(disk: &Disk) -> ProtectedSessionFiles<Disk> {
    ProtectedSessionFiles::new(disk.clone(), runtime(), [7; 16]).unwrap()
}
fn fixture() -> (Disk, ProtectedSessionFiles<Disk>) {
    let disk = Disk::default();
    let mut f = files(&disk);
    f.claim(&scope()).unwrap();
    (disk, f)
}
type Store = WindowsNativeCarrierReceiptStore<ProtectedSessionFiles<Disk>>;
fn open(f: &ProtectedSessionFiles<Disk>) -> Store {
    WindowsNativeCarrierReceiptStore::open(f.clone(), context())
        .unwrap()
        .0
}

#[test]
fn initial_attachment_exposes_only_original_live_store_backend() {
    let (disk, f) = fixture();
    let mut store = open(&f);
    assert!(store
        .original_files(&context())
        .unwrap()
        .same_original_backend(&f));
    save(&mut store, None, &initial(&context()));
    assert!(store
        .original_files(&context())
        .unwrap()
        .same_original_backend(&f));
    let mut foreign = context();
    foreign.provenance.network_epoch += 1;
    assert!(store.original_files(&foreign).is_err());
    assert!(
        open(&f).original_files(&context()).is_err(),
        "a reopened equal initial journal is cleanup-only"
    );
    disk.0.borrow_mut().fault = Some(Fault::Lost);
    let mut pending = next(&initial(&context()));
    pending.keys[0].phase = KeyPhase::CreatePending;
    assert!(store
        .compare_exchange(&context(), Some(&initial(&context())), &pending)
        .is_err());
    assert!(
        store.original_files(&context()).is_err(),
        "lost fresh CAS revokes original backend attachment"
    );
}
fn save(store: &mut Store, old: Option<&Record>, desired: &Record) {
    store
        .compare_exchange(&desired.context, old, desired)
        .unwrap();
}
fn inject(disk: &Disk, record: &Record) {
    let outer = SavedRecord {
        version: PRIVATE_VERSION,
        identity: SessionIdentity {
            boot_id: record.context.provenance.boot_id,
            runtime: record.context.provenance.runtime.clone(),
            scope: record.context.intent.scope.clone(),
        },
        kind: KIND,
        network_epoch: record.context.provenance.network_epoch,
        data: String::from_utf8(record.encode().unwrap()).unwrap(),
    };
    disk.0
        .borrow_mut()
        .bytes
        .insert(FILE, serde_json::to_vec(&outer).unwrap());
}
fn clean_legacy(f: &mut ProtectedSessionFiles<Disk>) {
    clean_scope(f, &scope());
}
fn clean_scope(f: &mut ProtectedSessionFiles<Disk>, own: &SessionScope) {
    let mut session = SessionState::new(own.clone(), Slot::A, 0, 0)
        .unwrap()
        .snapshot();
    session.phase = SessionPhase::Stopped;
    WindowsSessionStore::open(f.clone(), own.clone(), RecordKind::Session)
        .unwrap()
        .0
        .save(&session)
        .unwrap();
    let pair = PairRecord {
        scope: own.clone(),
        members: [None, None],
        active: None,
        guard: crate::member_guard::Model::empty(own.clone()).unwrap(),
        pending_guard: None,
        dns: [None, None],
        options: None,
        closing: false,
    };
    WindowsPairStore::open(f.clone(), own.clone(), RecordKind::Pair)
        .unwrap()
        .0
        .save(&pair)
        .unwrap();
}

#[test]
fn native_receipts_use_a_distinct_fixed_bounded_namespace() {
    assert_eq!(
        FILE.name(),
        "nelomai-redundant-native-carrier-receipts.json"
    );
    assert_eq!(FILE.limit(), 65_536);
    assert_ne!(FILE, PrivateFile::Carrier);
    let (disk, f) = fixture();
    let mut store = open(&f);
    let r = initial(&context());
    save(&mut store, None, &r);
    assert!(!disk.0.borrow().bytes.contains_key(&PrivateFile::Carrier));
    assert_eq!(
        f.clone().read(&scope(), KIND).unwrap(),
        Some(r.encode().unwrap())
    );
}
#[test]
fn real_protected_native_journal_runs_all_twenty_one_receipt_revisions() {
    let (disk, mut f) = fixture();
    let mut store = open(&f);
    let records = sequence();
    for (i, record) in records.iter().enumerate() {
        let old = i.checked_sub(1).map(|i| &records[i]);
        save(&mut store, old, record);
        assert_eq!(store.load(&context()).unwrap().as_ref(), Some(record));
    }
    clean_legacy(&mut f);
    f.complete(&scope()).unwrap();
    assert!(f.scopes(RuntimeSlot::Stable).unwrap().is_empty());
    assert!(disk.0.borrow().bytes.contains_key(&FILE));
    assert!(f.claim(&scope()).is_err());
}
#[test]
fn reopened_records_are_cleanup_only_even_with_original_fresh_files_clone() {
    let (_, f) = fixture();
    let mut live = open(&f);
    let records = sequence();
    save(&mut live, None, &records[0]);
    let mut reopened = open(&f);
    assert!(reopened
        .compare_exchange(&context(), Some(&records[0]), &records[1])
        .is_err());
    let mut closing = next(&records[0]);
    closing.phase = Phase::Closing;
    save(&mut reopened, Some(&records[0]), &closing);
}
#[test]
fn every_fresh_ack_fault_revokes_load_and_reopens_only_for_cleanup() {
    for at in 0usize..21 {
        for fault in [
            Fault::Fail,
            Fault::Lost,
            Fault::FalseSuccess,
            Fault::Unreadable,
            Fault::Foreign,
        ] {
            let (disk, f) = fixture();
            let mut store = open(&f);
            let records = sequence();
            for i in 0..at {
                save(
                    &mut store,
                    i.checked_sub(1).map(|n| &records[n]),
                    &records[i],
                );
            }
            disk.0.borrow_mut().fault = Some(fault);
            let old = at.checked_sub(1).map(|i| &records[i]);
            assert!(
                store
                    .compare_exchange(&context(), old, &records[at])
                    .is_err(),
                "{at} {fault:?}"
            );
            disk.0.borrow_mut().fail_read = None;
            assert!(store.load(&context()).is_err(), "revoked {at} {fault:?}");
            let (mut recovery, saved) =
                WindowsNativeCarrierReceiptStore::open(f.clone(), context()).unwrap();
            assert!(recovery.cleanup_only);
            if fault != Fault::Foreign {
                assert_eq!(
                    saved.as_ref(),
                    if matches!(fault, Fault::Lost | Fault::Unreadable) {
                        Some(&records[at])
                    } else {
                        old
                    }
                );
            }
            if saved.is_none() {
                assert!(recovery
                    .compare_exchange(&context(), None, &records[0])
                    .is_err());
            } else if saved.as_ref().unwrap().phase == Phase::Preparing {
                let mut denied = next(saved.as_ref().unwrap());
                denied.keys[0].phase = KeyPhase::CreatePending;
                assert!(recovery
                    .compare_exchange(&context(), saved.as_ref(), &denied)
                    .is_err());
            }
        }
    }
}
#[test]
fn an_empty_unconfirmed_fresh_write_revokes_the_shared_protected_fresh_permission() {
    for fault in [Fault::Fail, Fault::FalseSuccess] {
        let (disk, f) = fixture();
        let mut live = open(&f);
        let r = initial(&context());
        disk.0.borrow_mut().fault = Some(fault);
        assert!(live.compare_exchange(&context(), None, &r).is_err());
        let (mut reopened, saved) =
            WindowsNativeCarrierReceiptStore::open(f.clone(), context()).unwrap();
        assert!(saved.is_none());
        assert!(reopened.cleanup_only);
        assert!(reopened.compare_exchange(&context(), None, &r).is_err());
    }
}
#[test]
fn a_cleanup_lost_ack_resolves_exact_durable_readback_without_live_permission() {
    for at in 13usize..21 {
        let (disk, f) = fixture();
        let records = sequence();
        let mut live = open(&f);
        for i in 0..at {
            save(
                &mut live,
                i.checked_sub(1).map(|n| &records[n]),
                &records[i],
            );
        }
        let mut cleanup = open(&f);
        disk.0.borrow_mut().fault = Some(Fault::Lost);
        save(&mut cleanup, Some(&records[at - 1]), &records[at]);
        assert_eq!(cleanup.load(&context()).unwrap(), Some(records[at].clone()));
        assert!(cleanup.cleanup_only);
    }
}
#[test]
fn cleanup_only_raw_boundary_cannot_capture_or_disable_from_old_records() {
    for at in 0..12 {
        let (disk, _) = fixture();
        let records = sequence();
        inject(&disk, &records[at]);
        let mut reopened = files(&disk);
        assert!(reopened
            .compare_exchange(
                &scope(),
                KIND,
                Some(&records[at].encode().unwrap()),
                &records[at + 1].encode().unwrap()
            )
            .is_err());
    }
}
#[test]
fn every_nonterminal_receipt_blocks_completion_and_empty_completion() {
    for r in sequence().into_iter().take(20) {
        let (disk, mut f) = fixture();
        clean_legacy(&mut f);
        inject(&disk, &r);
        assert!(
            f.complete(&scope()).is_err(),
            "{:?} {}",
            r.phase,
            r.generation
        );
        assert!(f.complete_empty(&scope()).is_err());
        assert!(!disk
            .0
            .borrow()
            .bytes
            .contains_key(&completed_file(&scope()).unwrap()));
    }
}
#[test]
fn stopped_receipt_is_not_an_empty_crash_gap_but_allows_full_completion() {
    let (disk, mut f) = fixture();
    clean_legacy(&mut f);
    inject(&disk, sequence().last().unwrap());
    assert!(f.complete_empty(&scope()).is_err());
    f.complete(&scope()).unwrap();
    assert!(disk.0.borrow().bytes.contains_key(&FILE));
}
#[test]
fn orphan_native_receipt_cannot_be_ignored_by_enumeration_or_new_claim() {
    let disk = Disk::default();
    inject(&disk, &initial(&context()));
    let mut f = files(&disk);
    assert!(f.scopes(RuntimeSlot::Stable).is_err());
    assert!(f.claim(&scope()).is_err());
    assert!(f.recovery_view(RuntimeSlot::Stable).is_err());
}
#[test]
fn active_corrupt_receipts_block_enumeration_recovery_and_completion() {
    for bytes in [b"SECRET invalid JSON".to_vec(), vec![b' '; 65_537]] {
        let (disk, mut f) = fixture();
        clean_legacy(&mut f);
        disk.0.borrow_mut().bytes.insert(FILE, bytes.clone());
        assert!(f.scopes(RuntimeSlot::Stable).is_err());
        assert!(f.recovery_view(RuntimeSlot::Stable).is_err());
        assert!(f.complete(&scope()).is_err());
        assert!(f.complete_empty(&scope()).is_err());
        assert_eq!(disk.0.borrow().bytes[&FILE], bytes);
    }
}
#[test]
fn full_context_is_independent_and_exact_not_copied_from_record_metadata() {
    for field in 0..8 {
        let (disk, f) = fixture();
        let mut live = open(&f);
        let r = initial(&context());
        save(&mut live, None, &r);
        let mut wrong = context();
        match field {
            0 => wrong.intent.scope.connection_generation += 1,
            1 => wrong.provenance.boot_id = [9; 16],
            2 => wrong.provenance.runtime.manifest_sha256 = "b".repeat(64),
            3 => wrong.provenance.network_epoch += 1,
            4 => wrong.bindings[0].name = "foreign-c".into(),
            5 => wrong.bindings.swap(1, 2),
            6 => wrong.intent.addresses = vec!["10.7.0.3/32".parse().unwrap()],
            _ => wrong.intent.scope.runtime_generation += 1,
        }
        assert!(live.load(&wrong).is_err());
        assert!(WindowsNativeCarrierReceiptStore::open(f.clone(), wrong).is_err());
        assert_eq!(disk.0.borrow().writes, 2); // protected index + receipt only
    }
}
#[test]
fn live_epoch_changes_require_cleanup_reopen_and_never_migrate_receipt_epoch() {
    let (disk, f) = fixture();
    let mut store = open(&f);
    let r = initial(&context());
    save(&mut store, None, &r);
    let mut state = SessionState::new(scope(), Slot::A, 0, 0)
        .unwrap()
        .snapshot();
    state.network_epoch = 2;
    WindowsSessionStore::open(f.clone(), scope(), RecordKind::Session)
        .unwrap()
        .0
        .save(&state)
        .unwrap();
    assert!(store.load(&context()).is_err());
    let mut cleanup = open(&f);
    let mut closing = next(&r);
    closing.phase = Phase::Closing;
    save(&mut cleanup, Some(&r), &closing);
    let saved: SavedRecord = serde_json::from_slice(&disk.0.borrow().bytes[&FILE]).unwrap();
    assert_eq!(saved.network_epoch, 1);
    assert_eq!(
        Record::decode(saved.data.as_bytes())
            .unwrap()
            .context
            .provenance
            .network_epoch,
        1
    );
}
#[test]
fn noncanonical_expected_bytes_are_used_exactly_without_reserializing_old_json() {
    let (disk, f) = fixture();
    let r = initial(&context());
    inject(&disk, &r);
    {
        let mut state = disk.0.borrow_mut();
        let mut saved: SavedRecord = serde_json::from_slice(&state.bytes[&FILE]).unwrap();
        saved.data = serde_json::to_string_pretty(&r).unwrap();
        state
            .bytes
            .insert(FILE, serde_json::to_vec_pretty(&saved).unwrap());
    }
    let mut store = open(&f);
    let mut closing = next(&r);
    closing.phase = Phase::Closing;
    save(&mut store, Some(&r), &closing);
    assert_eq!(store.load(&context()).unwrap(), Some(closing));
}
#[test]
fn replacement_between_snapshot_and_private_cas_is_never_overwritten() {
    let (disk, f) = fixture();
    let mut store = open(&f);
    let records = sequence();
    save(&mut store, None, &records[0]);
    let original = disk.0.borrow().bytes[&FILE].clone();
    inject(&disk, &records[1]);
    let replacement = disk.0.borrow().bytes[&FILE].clone();
    disk.0.borrow_mut().bytes.insert(FILE, original);
    disk.0.borrow_mut().race = Some(replacement.clone());
    assert!(store
        .compare_exchange(&context(), Some(&records[0]), &records[1])
        .is_err());
    assert!(store.load(&context()).is_err());
    assert_eq!(disk.0.borrow().bytes[&FILE], replacement);
}

#[test]
fn falsely_acknowledged_empty_completion_cannot_release_without_a_permanent_marker() {
    let (disk, mut f) = fixture();
    disk.0.borrow_mut().meta_fault = Some((completed_file(&scope()).unwrap(), Fault::FalseSuccess));
    assert!(f.complete_empty(&scope()).is_err());
    let (_, index) = load_index(&mut disk.clone()).unwrap();
    assert_eq!(index.active.unwrap().scope, scope());
    assert!(!disk
        .0
        .borrow()
        .bytes
        .contains_key(&completed_file(&scope()).unwrap()));
}

#[test]
fn falsely_acknowledged_completion_index_is_not_reported_as_retired() {
    let (disk, mut f) = fixture();
    clean_legacy(&mut f);
    inject(&disk, sequence().last().unwrap());
    disk.0.borrow_mut().meta_fault = Some((PrivateFile::Index, Fault::FalseSuccess));
    assert!(f.complete(&scope()).is_err());
    assert_eq!(f.scopes(RuntimeSlot::Stable).unwrap(), vec![scope()]);
}

#[test]
fn falsely_acknowledged_claim_does_not_acquire_fresh_permission() {
    let disk = Disk::default();
    let mut f = files(&disk);
    disk.0.borrow_mut().meta_fault = Some((PrivateFile::Index, Fault::FalseSuccess));
    assert!(f.claim(&scope()).is_err());
    assert!(f.backend.lock().unwrap().fresh.is_none());
}

fn cleanup_edges() -> Vec<(Record, Record)> {
    let records = sequence();
    let mut edges: Vec<_> = (12..20)
        .map(|i| (records[i].clone(), records[i + 1].clone()))
        .collect();
    // Every preparation crash point can fence to Closing; CreatePending is
    // deliberately not erasable after an ambiguous native create.
    for record in records.iter().take(12) {
        let mut closing = next(record);
        closing.phase = Phase::Closing;
        edges.push((record.clone(), closing));
    }
    for role in 0..3 {
        for (from, to) in [
            (KeyPhase::Unstarted, KeyPhase::Clean),
            (KeyPhase::Captured, KeyPhase::Clean),
            (KeyPhase::DisablePending, KeyPhase::Captured),
            (KeyPhase::DisablePending, KeyPhase::Disabled),
            (KeyPhase::Disabled, KeyPhase::RestorePending),
            (KeyPhase::RestorePending, KeyPhase::Clean),
        ] {
            let mut old = initial(&context());
            old.phase = Phase::Closing;
            old.generation = 100;
            let receipt = |phase| KeyReceipt {
                role: old.keys[role].role,
                phase,
                new_key_ack: from != KeyPhase::Unstarted,
                baseline: Value::Absent,
                current: if matches!(phase, KeyPhase::Disabled | KeyPhase::RestorePending) {
                    Value::DwordZero
                } else {
                    Value::Absent
                },
                pending: match phase {
                    KeyPhase::DisablePending => Some(Value::DwordZero),
                    KeyPhase::RestorePending => Some(Value::Absent),
                    _ => None,
                },
            };
            let before = receipt(from);
            let after = receipt(to);
            old.keys[role] = before;
            let mut desired = next(&old);
            desired.keys[role] = after;
            edges.push((old, desired));
        }
    }
    edges
}

#[test]
fn every_allowed_cleanup_mutation_uses_real_protected_cas_with_the_full_fault_matrix() {
    for (old, desired) in cleanup_edges() {
        native_receipt::validate_transition(Some(&old), &desired, true).unwrap();
        for fault in [
            None,
            Some(Fault::Fail),
            Some(Fault::Lost),
            Some(Fault::FalseSuccess),
            Some(Fault::Unreadable),
            Some(Fault::Foreign),
            Some(Fault::EquivalentLost),
        ] {
            let (disk, f) = fixture();
            inject(&disk, &old);
            let mut store = open(&f);
            disk.0.borrow_mut().fault = fault;
            let result = store.compare_exchange(&context(), Some(&old), &desired);
            assert_eq!(
                result.is_ok(),
                matches!(fault, None | Some(Fault::Lost)),
                "{:?}->{:?} {fault:?}",
                old.keys,
                desired.keys
            );
            disk.0.borrow_mut().fail_read = None;
            let actual = store.load(&context()).unwrap().unwrap();
            if matches!(fault, Some(Fault::Fail | Fault::FalseSuccess)) {
                assert_eq!(actual, old);
            } else if fault != Some(Fault::Foreign) {
                assert_eq!(actual, desired);
            }
            assert!(store.cleanup_only);
        }
    }
}

#[test]
fn captured_pending_and_ambiguous_create_cleanup_never_synthesize_a_new_ack() {
    for role in 0..3 {
        let (disk, f) = fixture();
        let mut pending = initial(&context());
        pending.phase = Phase::Closing;
        pending.keys[role].phase = KeyPhase::CreatePending;
        inject(&disk, &pending);
        let mut store = open(&f);
        for phase in [KeyPhase::Captured, KeyPhase::Clean, KeyPhase::Unstarted] {
            let mut forged = next(&pending);
            forged.keys[role].phase = phase;
            forged.keys[role].new_key_ack = phase == KeyPhase::Captured;
            assert!(store
                .compare_exchange(&context(), Some(&pending), &forged)
                .is_err());
        }
        assert_eq!(store.load(&context()).unwrap(), Some(pending));
        assert_eq!(disk.0.borrow().receipt_attempts, 0);
    }
}

#[test]
fn cleanup_idempotence_does_not_reenable_creation_or_return_native_proof() {
    for record in sequence() {
        let (disk, f) = fixture();
        inject(&disk, &record);
        let mut store = open(&f);
        save(&mut store, Some(&record), &record);
        assert!(store.cleanup_only);
        assert_eq!(store.load(&context()).unwrap(), Some(record));
    }
}

fn corrupt_bytes(outer: bool, pointer: &str, replacement: serde_json::Value) -> Vec<u8> {
    let disk = Disk::default();
    inject(&disk, &initial(&context()));
    let mut saved: SavedRecord = serde_json::from_slice(&disk.0.borrow().bytes[&FILE]).unwrap();
    if outer {
        let mut value = serde_json::to_value(saved).unwrap();
        *value.pointer_mut(pointer).unwrap() = replacement;
        serde_json::to_vec(&value).unwrap()
    } else {
        let mut value: serde_json::Value = serde_json::from_str(&saved.data).unwrap();
        *value.pointer_mut(pointer).unwrap() = replacement;
        saved.data = serde_json::to_string(&value).unwrap();
        serde_json::to_vec(&saved).unwrap()
    }
}

#[test]
fn strict_outer_and_inner_reconstruction_rejects_corrupt_foreign_and_future_receipts_everywhere() {
    use serde_json::json;
    let changes = [
        (true, "/version", json!(1)),
        (true, "/kind", json!("Carrier")),
        (true, "/network_epoch", json!(0)),
        (true, "/network_epoch", json!(2)),
        (true, "/identity/scope/connection_generation", json!(99)),
        (true, "/identity/scope/runtime_generation", json!(99)),
        (true, "/identity/boot_id", json!(vec![9; 16])),
        (
            true,
            "/identity/runtime/manifest_sha256",
            json!("b".repeat(64)),
        ),
        (false, "/version", json!(1)),
        (false, "/version", json!(3)),
        (false, "/generation", json!(0)),
        (false, "/phase", json!("Stopped")),
        (
            false,
            "/context/intent/scope/session_id",
            json!("22222222-2222-4222-8222-222222222222"),
        ),
        (false, "/context/provenance/boot_id", json!(vec![9; 16])),
        (
            false,
            "/context/provenance/runtime/runtime_version",
            json!("2.0.0"),
        ),
        (false, "/context/provenance/network_epoch", json!(2)),
        (false, "/context/bindings/0/guid", json!(vec![0; 16])),
        (false, "/context/bindings/0/registry_path", json!("foreign")),
        (false, "/context/bindings/1/name", json!("CARRIER-C")),
        (false, "/context/bindings/1/role", json!("RoleCarrier")),
        (false, "/keys/0/new_key_ack", json!(true)),
        (false, "/keys/0/current", json!("DwordZero")),
        (false, "/keys/0/pending", json!("DwordZero")),
        (false, "/keys/0/baseline", json!("DwordZero")),
        (false, "/native_rows", json!("Bound")),
    ];
    for (outer, pointer, replacement) in changes {
        let (disk, mut f) = fixture();
        clean_legacy(&mut f);
        let corrupt = corrupt_bytes(outer, pointer, replacement);
        disk.0.borrow_mut().bytes.insert(FILE, corrupt.clone());
        let writes = disk.0.borrow().writes;
        assert!(f.read(&scope(), KIND).is_err(), "{pointer}");
        assert!(
            WindowsNativeCarrierReceiptStore::open(f.clone(), context()).is_err(),
            "{pointer}"
        );
        assert!(f.scopes(RuntimeSlot::Stable).is_err(), "{pointer}");
        assert!(f.recovery_view(RuntimeSlot::Stable).is_err(), "{pointer}");
        assert!(f.complete(&scope()).is_err(), "{pointer}");
        assert!(f.complete_empty(&scope()).is_err(), "{pointer}");
        assert_eq!(disk.0.borrow().bytes[&FILE], corrupt);
        assert_eq!(disk.0.borrow().writes, writes);
    }
}

#[test]
fn unknown_fields_at_each_receipt_layer_and_v1_envelopes_are_rejected_not_migrated() {
    for pointer in [
        "",
        "/context",
        "/context/intent",
        "/context/provenance",
        "/context/provenance/runtime",
        "/context/intent/scope",
        "/context/bindings/0",
        "/keys/0",
    ] {
        let (disk, f) = fixture();
        inject(&disk, &initial(&context()));
        let mut saved: SavedRecord = serde_json::from_slice(&disk.0.borrow().bytes[&FILE]).unwrap();
        let mut inner: serde_json::Value = serde_json::from_str(&saved.data).unwrap();
        inner
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unsupported".into(), serde_json::json!(true));
        saved.data = serde_json::to_string(&inner).unwrap();
        disk.0
            .borrow_mut()
            .bytes
            .insert(FILE, serde_json::to_vec(&saved).unwrap());
        assert!(
            WindowsNativeCarrierReceiptStore::open(f, context()).is_err(),
            "{pointer}"
        );
    }
    let (disk, mut f) = fixture();
    inject(&disk, &initial(&context()));
    let mut outer: serde_json::Value =
        serde_json::from_slice(&disk.0.borrow().bytes[&FILE]).unwrap();
    outer
        .as_object_mut()
        .unwrap()
        .insert("unsupported".into(), serde_json::json!(true));
    disk.0
        .borrow_mut()
        .bytes
        .insert(FILE, serde_json::to_vec(&outer).unwrap());
    assert!(f.read(&scope(), KIND).is_err());
    let v1 = serde_json::to_vec(&Envelope {
        version: 1,
        scope: scope(),
        payload: initial(&context()),
    })
    .unwrap();
    assert!(f.compare_exchange(&scope(), KIND, None, &v1).is_err());
}

#[test]
fn payload_and_entire_protected_envelope_have_independent_size_bounds() {
    let (disk, mut f) = fixture();
    inject(&disk, &initial(&context()));
    let original = disk.0.borrow().bytes[&FILE].clone();
    let mut bounded = original.clone();
    bounded.resize(FILE.limit(), b' ');
    disk.0.borrow_mut().bytes.insert(FILE, bounded.clone());
    assert!(open(&f).load(&context()).unwrap().is_some());
    bounded.push(b' ');
    disk.0.borrow_mut().bytes.insert(FILE, bounded);
    assert!(f.read(&scope(), KIND).is_err());
    disk.0.borrow_mut().bytes.remove(&FILE);
    let mut payload = initial(&context()).encode().unwrap();
    payload.resize(FILE.limit(), b' ');
    assert!(Record::decode(&payload).is_ok());
    assert!(f.compare_exchange(&scope(), KIND, None, &payload).is_err()); // outer wrapper would exceed 64KiB
    payload.push(b' ');
    assert!(f.compare_exchange(&scope(), KIND, None, &payload).is_err());
    assert!(!disk.0.borrow().bytes.contains_key(&FILE));
}

#[test]
fn raw_protected_cas_authenticates_full_context_revision_and_claim_independently() {
    let (disk, mut f) = fixture();
    let records = sequence();
    f.compare_exchange(&scope(), KIND, None, &records[0].encode().unwrap())
        .unwrap();
    for field in 0..7 {
        let mut desired = records[1].clone();
        match field {
            0 => desired.context.intent.scope.connection_generation += 1,
            1 => desired.context.provenance.boot_id = [9; 16],
            2 => desired.context.provenance.runtime.manifest_sha256 = "b".repeat(64),
            3 => desired.context.provenance.network_epoch = 2,
            4 => desired.context.bindings[0].name = "other-carrier".into(),
            5 => desired.generation += 1,
            _ => desired.context.intent.addresses = vec!["10.7.0.3/32".parse().unwrap()],
        }
        assert!(f
            .compare_exchange(
                &scope(),
                KIND,
                Some(&records[0].encode().unwrap()),
                &desired.encode().unwrap()
            )
            .is_err());
    }
    assert_eq!(disk.0.borrow().receipt_attempts, 1);
    assert!(f
        .compare_exchange(
            &scope(),
            KIND,
            Some(b"not exact bytes"),
            &records[1].encode().unwrap()
        )
        .is_err());
    let mut no_claim = files(&Disk::default());
    assert!(no_claim
        .compare_exchange(&scope(), KIND, None, &records[0].encode().unwrap())
        .is_err());
}

#[test]
fn lost_claim_ack_is_cleanup_only_and_a_new_claim_never_replays_an_active_scope() {
    let disk = Disk::default();
    let mut f = files(&disk);
    disk.0.borrow_mut().meta_fault = Some((PrivateFile::Index, Fault::Lost));
    assert!(f.claim(&scope()).is_err());
    let (mut store, saved) = WindowsNativeCarrierReceiptStore::open(f.clone(), context()).unwrap();
    assert!(saved.is_none());
    assert!(store.cleanup_only);
    assert!(store
        .compare_exchange(&context(), None, &initial(&context()))
        .is_err());
    assert!(f.claim(&scope()).is_err());
    f.complete_empty(&scope()).unwrap();
    assert!(files(&disk).claim(&scope()).is_err());
}

#[test]
fn completion_marker_and_index_ack_faults_retain_obligations_and_never_restore_fresh_access() {
    for target in [completed_file(&scope()).unwrap(), PrivateFile::Index] {
        for fault in [
            Fault::Fail,
            Fault::Lost,
            Fault::FalseSuccess,
            Fault::Unreadable,
        ] {
            let (disk, mut f) = fixture();
            clean_legacy(&mut f);
            inject(&disk, sequence().last().unwrap());
            disk.0.borrow_mut().meta_fault = Some((target, fault));
            assert!(f.complete(&scope()).is_err(), "{target:?} {fault:?}");
            disk.0.borrow_mut().fail_read = None;
            assert!(!f.carrier_access(&scope()).is_ok_and(|access| access.fresh));
            assert!(files(&disk).claim(&scope()).is_err());
            f.complete(&scope()).unwrap();
            assert!(f.scopes(RuntimeSlot::Stable).unwrap().is_empty());
            assert!(disk.0.borrow().bytes.contains_key(&FILE));
        }
    }
}

#[test]
fn previous_boot_recovery_retains_original_provenance_and_is_always_cleanup_only() {
    let (disk, _) = fixture();
    let record = sequence()[2].clone();
    inject(&disk, &record);
    let mut today = ProtectedSessionFiles::new(disk.clone(), runtime(), [8; 16]).unwrap();
    assert!(today.scopes(RuntimeSlot::Stable).is_err());
    assert!(WindowsNativeCarrierReceiptStore::open(today.clone(), context()).is_err());
    let (retained, changed) = today.recovery_view(RuntimeSlot::Stable).unwrap().unwrap();
    assert!(changed);
    let mut cleanup = open(&retained);
    let mut closing = next(&record);
    closing.phase = Phase::Closing;
    save(&mut cleanup, Some(&record), &closing);
    assert_eq!(
        cleanup
            .load(&context())
            .unwrap()
            .unwrap()
            .context
            .provenance
            .boot_id,
        [7; 16]
    );
    let mut wrong = context();
    wrong.provenance.boot_id = [8; 16];
    assert!(WindowsNativeCarrierReceiptStore::open(retained.clone(), wrong).is_err());
    assert!(retained.clone().claim(&scope()).is_err());
    assert!(retained
        .clone()
        .completed_in_previous_boot(&scope())
        .is_err()); // active != completed
}

#[test]
fn retired_nonterminal_corrupt_or_unmarked_receipts_are_never_hidden_from_a_new_scope() {
    for case in 0..4 {
        let (disk, mut f) = fixture();
        clean_legacy(&mut f);
        inject(&disk, sequence().last().unwrap());
        f.complete(&scope()).unwrap();
        match case {
            0 => inject(&disk, &initial(&context())),
            1 => {
                disk.0
                    .borrow_mut()
                    .bytes
                    .insert(FILE, b"unknown corrupt obligation".to_vec());
            }
            2 => {
                disk.0
                    .borrow_mut()
                    .bytes
                    .remove(&completed_file(&scope()).unwrap());
            }
            _ => {
                let mut foreign = sequence().last().unwrap().clone();
                foreign.context.intent.scope.connection_generation += 1;
                inject(&disk, &foreign);
            }
        }
        let mut new_scope = scope();
        new_scope.connection_generation += 10;
        assert!(f.scopes(RuntimeSlot::Stable).is_err());
        assert!(f.recovery_view(RuntimeSlot::Stable).is_err());
        assert!(f.claim(&new_scope).is_err());
        assert!(f.complete(&scope()).is_err());
    }
}

#[test]
fn all_ten_fixed_record_owners_survive_retirement_and_partial_overwrite_without_replay() {
    let disk = Disk::default();
    let mut identities = vec![];
    for (i, kind) in RecordKind::OWNED.into_iter().enumerate() {
        let local = Disk::default();
        let mut f = files(&local);
        let mut own = scope();
        own.connection_generation += i as u64;
        f.claim(&own).unwrap();
        if kind == RecordKind::NativeCreator {
            let mut context = context();
            context.intent.scope = own.clone();
            let creator = CreatorRecord::decode(
                &serde_json::to_vec(&serde_json::json!({
                    "version":1,"context":context,"process":{"pid":256,"creation_time":500}
                }))
                .unwrap(),
            )
            .unwrap();
            WindowsNativeCreatorStore::open(f.clone(), context)
                .unwrap()
                .publish(&creator)
                .unwrap();
        }
        clean_scope(&mut f, &own);
        if kind == RecordKind::Network {
            WindowsNetworkStore::open(f.clone(), own.clone(), kind)
                .unwrap()
                .0
                .save(&NetworkJournal::default())
                .unwrap();
        }
        if kind == RecordKind::Carrier {
            let mut record = carrier::Record {
                version: 1,
                intent: context().intent,
                provenance: context().provenance,
                generation: 1,
                phase: carrier::Phase::Prepared,
                proof: None,
                rows: None,
            };
            record.intent.scope = own.clone();
            let key = carrier::carrier_key(&own).unwrap();
            let mut store = WindowsCarrierStore::open(f.clone(), own.clone()).unwrap().0;
            store.compare_exchange(&key, None, &record).unwrap();
            for phase in [carrier::Phase::Closing, carrier::Phase::Stopped] {
                let mut desired = record.clone();
                desired.generation += 1;
                desired.phase = phase;
                store
                    .compare_exchange(&key, Some(&record), &desired)
                    .unwrap();
                record = desired;
            }
        }
        if kind == KIND {
            let mut context = context();
            context.intent.scope = own.clone();
            let mut store = WindowsNativeCarrierReceiptStore::open(f.clone(), context.clone())
                .unwrap()
                .0;
            let mut previous = None;
            for mut record in sequence() {
                record.context = context.clone();
                store
                    .compare_exchange(&context, previous.as_ref(), &record)
                    .unwrap();
                previous = Some(record);
            }
        }
        if kind == RecordKind::CarrierGuard {
            let mut context = context();
            context.intent.scope = own.clone();
            let (mut guard, old) = WindowsCarrierGuardStore::open(f.clone(), context).unwrap();
            assert!(old.is_none());
            guard.initialize().unwrap();
        }
        let row_role = match kind {
            RecordKind::CarrierRows => Some(rows::Role::Carrier),
            RecordKind::MemberARows => Some(rows::Role::MemberA),
            RecordKind::MemberBRows => Some(rows::Role::MemberB),
            _ => None,
        };
        if let Some(role) = row_role {
            use rows::Journal;
            let key = rows::RowKey {
                luid: 3000 + i as u64,
                index: 30 + i as u32,
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
                        dad_transmits: 3,
                        base_reachable_time: 30000,
                        retransmit_time: 1000,
                        path_mtu_discovery_timeout: 600000,
                        link_local_behavior: 0,
                        link_local_timeout: 6500,
                        zone_indices: [0; 16],
                        site_prefix_length: 0,
                        metric: 19,
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
                        supports_router_discovery: false,
                        reachable_time: 45678,
                        transmit_offload: 0,
                        receive_offload: 0,
                    },
                },
                address: None,
            };
            let mut record = rows::Record {
                version: 1,
                domain: "carrier-native-ipv4-rows-v1".into(),
                binding: rows::Binding {
                    scope: own.clone(),
                    boot_id: [7; 16],
                    runtime: runtime(),
                    network_epoch: 1,
                    role,
                    guid: [i as u8 + 1; 16],
                    name: format!("owned-row-{i}"),
                    key,
                    address: [10, 7, 0, 2],
                },
                revision: 1,
                phase: rows::Phase::Captured,
                current: baseline.clone(),
                baseline,
                pending: None,
                creation: None,
            };
            let mut store = WindowsCarrierRowsStore::open(f.clone(), record.binding.clone())
                .unwrap()
                .0;
            store
                .compare_exchange(&record.binding, None, &record)
                .unwrap();
            for phase in [rows::Phase::Closing, rows::Phase::Stopped] {
                let mut desired = record.clone();
                desired.revision += 1;
                desired.phase = phase;
                store
                    .compare_exchange(&record.binding, Some(&record), &desired)
                    .unwrap();
                record = desired;
            }
        }
        f.complete(&own).unwrap();
        let identity = SessionIdentity {
            boot_id: [7; 16],
            runtime: runtime(),
            scope: own.clone(),
        };
        identities.push(identity);
        let local = local.0.borrow();
        let mut group = disk.0.borrow_mut();
        group
            .bytes
            .insert(kind.file(), local.bytes[&kind.file()].clone());
        let marker = completed_file(&own).unwrap();
        group.bytes.insert(marker, local.bytes[&marker].clone());
    }
    disk.0.borrow_mut().bytes.insert(
        PrivateFile::Index,
        serde_json::to_vec(&SessionIndex {
            version: PRIVATE_VERSION,
            active: None,
            completed: identities.clone(),
        })
        .unwrap(),
    );
    let mut f = files(&disk);
    assert!(f.scopes(RuntimeSlot::Stable).unwrap().is_empty());
    let reads = disk.0.borrow().reads.clone();
    for kind in RecordKind::OWNED {
        assert!(reads.contains(&kind.file()));
    }
    let mut own = scope();
    own.connection_generation = 99;
    f.claim(&own).unwrap();
    for kind in RecordKind::OWNED {
        assert!(f.read(&own, kind).unwrap().is_none());
    }
    let mut context = context();
    context.intent.scope = own.clone();
    let (mut store, saved) =
        WindowsNativeCarrierReceiptStore::open(f.clone(), context.clone()).unwrap();
    assert!(saved.is_none());
    assert!(!store.cleanup_only);
    clean_scope(&mut f, &own); // closed owners are now only partially represented
    for (i, mut record) in sequence().into_iter().enumerate() {
        record.context = context.clone();
        let old = store.load(&context).unwrap();
        assert_eq!(old.is_none(), i == 0);
        store
            .compare_exchange(&context, old.as_ref(), &record)
            .unwrap();
    }
    f.complete(&own).unwrap();
    let (_, index) = load_index(&mut disk.clone()).unwrap();
    assert_eq!(index.completed.len(), RecordKind::OWNED.len() - 2);
    assert!(index.completed.contains(identities.last().unwrap())); // immutable Creator DATA survives partial overwrite
    for id in &identities {
        assert!(f.claim(&id.scope).is_err());
    } // compacted identities still permanently fenced
    let mut next = own.clone();
    next.connection_generation += 1;
    f.claim(&next).unwrap();
    f.complete_empty(&next).unwrap();
    for id in &identities {
        assert!(f.claim(&id.scope).is_err());
    }
    let mut today = ProtectedSessionFiles::new(disk, runtime(), [8; 16]).unwrap();
    for id in identities {
        assert!(today.completed_in_previous_boot(&id.scope).unwrap());
    }
}

#[test]
fn independently_fresh_empty_claim_cannot_use_a_stale_epoch_or_invalid_binding_template() {
    let (disk, f) = fixture();
    let mut session = SessionState::new(scope(), Slot::A, 0, 0)
        .unwrap()
        .snapshot();
    session.network_epoch = 2;
    WindowsSessionStore::open(f.clone(), scope(), RecordKind::Session)
        .unwrap()
        .0
        .save(&session)
        .unwrap();
    assert!(WindowsNativeCarrierReceiptStore::open(f.clone(), context()).is_err());
    let mut fresh_context = context();
    fresh_context.provenance.network_epoch = 2;
    let (mut store, saved) =
        WindowsNativeCarrierReceiptStore::open(f.clone(), fresh_context.clone()).unwrap();
    assert!(saved.is_none());
    assert!(!store.cleanup_only);
    store
        .compare_exchange(&fresh_context, None, &initial(&fresh_context))
        .unwrap();
    for field in 0..4 {
        let mut bad = fresh_context.clone();
        match field {
            0 => bad.bindings[1].name = "CARRIER-C".into(),
            1 => bad.bindings[1].guid = bad.bindings[0].guid,
            2 => bad.bindings[0].registry_path = "untrusted-path".into(),
            _ => bad.bindings.swap(0, 1),
        }
        assert!(WindowsNativeCarrierReceiptStore::open(f.clone(), bad).is_err());
    }
    assert_eq!(disk.0.borrow().receipt_attempts, 1);
}

#[test]
fn revoked_live_instances_stay_revoked_after_cleanup_reconciliation_and_disk_reopen() {
    let (disk, f) = fixture();
    let mut store = open(&f);
    let records = sequence();
    save(&mut store, None, &records[0]);
    disk.0.borrow_mut().fault = Some(Fault::Lost);
    assert!(store
        .compare_exchange(&context(), Some(&records[0]), &records[1])
        .is_err());
    let mut recovery = open(&files(&disk));
    let mut closing = next(&records[1]);
    closing.phase = Phase::Closing;
    save(&mut recovery, Some(&records[1]), &closing);
    assert!(store.load(&context()).is_err());
    assert!(store
        .compare_exchange(&context(), Some(&closing), &closing)
        .is_err());
    assert!(f
        .clone()
        .compare_exchange(
            &scope(),
            KIND,
            Some(&closing.encode().unwrap()),
            &records[2].encode().unwrap()
        )
        .is_err());
}

#[test]
fn valid_but_foreign_caller_guid_path_name_and_runtime_bindings_are_never_adopted() {
    for field in 0..6 {
        let (disk, f) = fixture();
        inject(&disk, &initial(&context()));
        let mut wrong = context();
        match field {
            0 => {
                wrong.bindings[0].guid = [4; 16];
                wrong.bindings[0].registry_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{04040404-0404-0404-0404-040404040404}".into();
            }
            1 => wrong.bindings[0].name = "CARRIER-C".into(), // exact caller spelling, not just uniqueness
            2 => wrong.intent.scope.session_id = "22222222-2222-4222-8222-222222222222".into(),
            3 => wrong.provenance.runtime.runtime_contract_version += 1,
            4 => wrong.provenance.runtime.container_version = "2.0.0".into(),
            _ => wrong.provenance.runtime.runtime_version = "2.0.0".into(),
        }
        validate_native_context(&wrong).unwrap();
        assert!(WindowsNativeCarrierReceiptStore::open(f, wrong).is_err());
        assert_eq!(disk.0.borrow().receipt_attempts, 0);
    }
}

#[test]
fn exhausted_revisions_and_two_simultaneous_mutations_never_reach_private_io() {
    let (disk, f) = fixture();
    let mut old = initial(&context());
    old.generation = u64::MAX;
    inject(&disk, &old);
    let mut store = open(&f);
    let mut wrapped = old.clone();
    wrapped.generation = 1;
    wrapped.phase = Phase::Closing;
    assert!(store
        .compare_exchange(&context(), Some(&old), &wrapped)
        .is_err());
    let mut closing = initial(&context());
    closing.phase = Phase::Closing;
    inject(&disk, &closing);
    let mut store = open(&f);
    let mut two = next(&closing);
    two.keys[0].phase = KeyPhase::Clean;
    two.keys[1].phase = KeyPhase::Clean;
    assert!(store
        .compare_exchange(&context(), Some(&closing), &two)
        .is_err());
    assert_eq!(disk.0.borrow().receipt_attempts, 0);
}
