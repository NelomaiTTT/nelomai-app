use super::*;
use crate::member_carrier::{
    self as carrier, CarrierJournal, Phase, Record, RowState, RowValue, WeakHostRow,
};
use crate::member_owner::InterfaceProof;
use nelomai_client_tunnel::redundancy::{
    session::{SessionPhase, SessionState},
    Slot,
};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

#[derive(Clone, Default)]
struct Disk(Rc<RefCell<DiskState>>);
#[derive(Default)]
struct DiskState {
    bytes: BTreeMap<PrivateFile, Vec<u8>>,
    writes: usize,
    reads: usize,
    fail: Option<PrivateFile>,
    lose_ack: Option<PrivateFile>,
    fail_read: Option<PrivateFile>,
    fail_read_after_write: bool,
    false_ack: bool,
    replace_before_cas: Option<Vec<u8>>,
}
impl PrivateRecords for Disk {
    fn read(&mut self, file: PrivateFile) -> io::Result<Option<Vec<u8>>> {
        let mut s = self.0.borrow_mut();
        s.reads += 1;
        if s.fail_read == Some(file) {
            return Err(io::Error::other("SECRET read failure"));
        }
        Ok(s.bytes.get(&file).cloned())
    }
    fn compare_exchange(
        &mut self,
        file: PrivateFile,
        expected: Option<&[u8]>,
        desired: &[u8],
    ) -> io::Result<()> {
        let mut s = self.0.borrow_mut();
        if file == PrivateFile::Carrier {
            if let Some(bytes) = s.replace_before_cas.take() {
                s.bytes.insert(file, bytes);
            }
        }
        if s.fail == Some(file)
            || desired.len() > file.limit()
            || s.bytes.get(&file).is_some_and(|b| b.len() > file.limit())
            || s.bytes.get(&file).map(Vec::as_slice) != expected
        {
            return Err(io::Error::other("SECRET CAS failure"));
        }
        if file == PrivateFile::Carrier && s.false_ack {
            s.false_ack = false;
            return Ok(());
        }
        s.bytes.insert(file, desired.to_vec());
        s.writes += 1;
        if file == PrivateFile::Carrier && s.fail_read_after_write {
            s.fail_read_after_write = false;
            s.fail_read = Some(file);
        }
        if s.lose_ack == Some(file) {
            s.lose_ack = None;
            return Err(io::Error::other("SECRET lost acknowledgement"));
        }
        Ok(())
    }
}
impl SessionFileIo for Disk {
    fn transaction<T>(
        &mut self,
        action: impl FnOnce(&mut dyn PrivateRecords) -> io::Result<T>,
    ) -> io::Result<T> {
        action(self)
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
fn files(disk: &Disk) -> ProtectedSessionFiles<Disk> {
    ProtectedSessionFiles::new(disk.clone(), runtime(), [7; 16]).unwrap()
}
fn prepared() -> Record {
    Record {
        version: 1,
        intent: carrier::Intent {
            scope: scope(),
            addresses: vec!["10.7.0.2/32".parse().unwrap()],
        },
        provenance: carrier::Provenance {
            boot_id: [7; 16],
            runtime: runtime(),
            network_epoch: 1,
        },
        generation: 1,
        phase: Phase::Prepared,
        proof: None,
        rows: None,
    }
}
fn advance(old: &Record, phase: Phase) -> Record {
    let mut next = old.clone();
    next.generation += 1;
    next.phase = phase;
    next
}
fn created(old: &Record) -> Record {
    let mut r = advance(old, Phase::Created);
    r.proof = Some(InterfaceProof {
        index: 40,
        luid: 50,
        guid: carrier::carrier_key(&r.intent.scope).unwrap().guid,
    });
    r.rows = Some(
        [
            RowValue::Address(None),
            RowValue::WeakHost(WeakHostRow {
                send: false,
                receive: false,
            }),
        ]
        .map(|baseline| RowState {
            current: baseline.clone(),
            baseline,
            pending: None,
        }),
    );
    r
}
fn goal() -> [RowValue; 2] {
    [
        RowValue::Address(Some(carrier::AddressRow {
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
fn payload(r: &Record) -> Vec<u8> {
    serde_json::to_vec(&Envelope {
        version: 1,
        scope: r.intent.scope.clone(),
        payload: r,
    })
    .unwrap()
}
fn inject(disk: &Disk, r: &Record) {
    let raw = serde_json::to_vec(&SavedRecord {
        version: PRIVATE_VERSION,
        identity: SessionIdentity {
            boot_id: [7; 16],
            runtime: runtime(),
            scope: r.intent.scope.clone(),
        },
        kind: RecordKind::Carrier,
        network_epoch: r.provenance.network_epoch,
        data: String::from_utf8(payload(r)).unwrap(),
    })
    .unwrap();
    disk.0.borrow_mut().bytes.insert(PrivateFile::Carrier, raw);
}
fn clean_legacy(f: &mut ProtectedSessionFiles<Disk>, scope: &SessionScope) {
    let mut state = SessionState::new(scope.clone(), Slot::A, 1, 1)
        .unwrap()
        .snapshot();
    state.phase = SessionPhase::Stopped;
    let (mut store, _) =
        WindowsSessionStore::open(f.clone(), scope.clone(), RecordKind::Session).unwrap();
    store.save(&state).unwrap();
    let pair = PairRecord {
        scope: scope.clone(),
        members: [None, None],
        active: None,
        guard: crate::member_guard::Model::empty(scope.clone()).unwrap(),
        pending_guard: None,
        dns: [None, None],
        options: None,
        closing: false,
    };
    let (mut store, _) =
        WindowsPairStore::open(f.clone(), scope.clone(), RecordKind::Pair).unwrap();
    store.save(&pair).unwrap();
}
fn fixture() -> (Disk, ProtectedSessionFiles<Disk>) {
    let d = Disk::default();
    let mut f = files(&d);
    f.claim(&scope()).unwrap();
    (d, f)
}
type Store = WindowsCarrierStore<ProtectedSessionFiles<Disk>>;
fn open(f: &ProtectedSessionFiles<Disk>) -> Store {
    WindowsCarrierStore::open(f.clone(), scope()).unwrap().0
}
fn key() -> carrier::CarrierKey {
    carrier::carrier_key(&scope()).unwrap()
}
fn save(store: &mut Store, old: Option<&Record>, next: &Record) {
    store.compare_exchange(&key(), old, next).unwrap();
}
fn configure(store: &mut Store) -> Record {
    let p = prepared();
    save(store, None, &p);
    let mut r = created(&p);
    save(store, Some(&p), &r);
    for index in [1, 0] {
        let mut pending = advance(&r, Phase::Created);
        pending.rows.as_mut().unwrap()[index].pending = Some(goal()[index].clone());
        save(store, Some(&r), &pending);
        let mut confirmed = advance(&pending, Phase::Created);
        let row = &mut confirmed.rows.as_mut().unwrap()[index];
        row.current = row.pending.take().unwrap();
        save(store, Some(&pending), &confirmed);
        r = confirmed;
    }
    let ready = advance(&r, Phase::Configured);
    save(store, Some(&r), &ready);
    ready
}
fn cleanup(store: &mut Store, r: &Record) -> Record {
    if r.phase == Phase::Stopped {
        return r.clone();
    }
    let mut closing = if r.phase == Phase::Closing {
        r.clone()
    } else {
        let closing = advance(r, Phase::Closing);
        save(store, Some(r), &closing);
        closing
    };
    if closing.rows.is_some() {
        for i in [0, 1] {
            if closing.rows.as_ref().unwrap()[i].pending.is_some() {
                let mut confirmed = advance(&closing, Phase::Closing);
                confirmed.rows.as_mut().unwrap()[i].pending = None;
                save(store, Some(&closing), &confirmed);
                closing = confirmed;
            }
            if closing.rows.as_ref().unwrap()[i].current
                != closing.rows.as_ref().unwrap()[i].baseline
            {
                let mut pending = advance(&closing, Phase::Closing);
                let row = &mut pending.rows.as_mut().unwrap()[i];
                row.pending = Some(row.baseline.clone());
                save(store, Some(&closing), &pending);
                let mut confirmed = advance(&pending, Phase::Closing);
                let row = &mut confirmed.rows.as_mut().unwrap()[i];
                row.current = row.pending.take().unwrap();
                save(store, Some(&pending), &confirmed);
                closing = confirmed;
            }
        }
    }
    let stopped = advance(&closing, Phase::Stopped);
    save(store, Some(&closing), &stopped);
    stopped
}

#[test]
fn four_fixed_record_owners_remain_exactly_marked_bounded_and_retained() {
    let d = Disk::default();
    let mut identities = Vec::new();
    for (number, kind) in RecordKind::ALL.into_iter().enumerate() {
        let local = Disk::default();
        let mut f = files(&local);
        let mut s = scope();
        s.connection_generation += number as u64;
        f.claim(&s).unwrap();
        clean_legacy(&mut f, &s);
        if kind == RecordKind::Network {
            let (mut store, _) = WindowsNetworkStore::open(f.clone(), s.clone(), kind).unwrap();
            store.save(&NetworkJournal::default()).unwrap();
        }
        if kind == RecordKind::Carrier {
            let (mut store, _) = WindowsCarrierStore::open(f.clone(), s.clone()).unwrap();
            let k = carrier::carrier_key(&s).unwrap();
            let mut p = prepared();
            p.intent.scope = s.clone();
            store.compare_exchange(&k, None, &p).unwrap();
            let closing = advance(&p, Phase::Closing);
            store.compare_exchange(&k, Some(&p), &closing).unwrap();
            store
                .compare_exchange(&k, Some(&closing), &advance(&closing, Phase::Stopped))
                .unwrap();
        }
        f.complete(&s).unwrap();
        let id = SessionIdentity {
            boot_id: [7; 16],
            runtime: runtime(),
            scope: s.clone(),
        };
        identities.push(id);
        let bytes = local.0.borrow();
        let marker = completed_file(&s).unwrap();
        let mut saved = d.0.borrow_mut();
        saved
            .bytes
            .insert(kind.file(), bytes.bytes[&kind.file()].clone());
        saved.bytes.insert(marker, bytes.bytes[&marker].clone());
    }
    let index = SessionIndex {
        version: PRIVATE_VERSION,
        active: None,
        completed: identities.clone(),
    };
    d.0.borrow_mut()
        .bytes
        .insert(PrivateFile::Index, serde_json::to_vec(&index).unwrap());
    let mut f = files(&d);
    assert!(f.scopes(RuntimeSlot::Stable).unwrap().is_empty());
    let mut next = scope();
    next.connection_generation = 99;
    f.claim(&next).unwrap();
    for kind in RecordKind::ALL {
        assert!(f.read(&next, kind).unwrap().is_none());
    }
    f.complete_empty(&next).unwrap();
    let retained: SessionIndex =
        serde_json::from_slice(&d.0.borrow().bytes[&PrivateFile::Index]).unwrap();
    assert!(retained.active.is_none());
    assert!(retained.completed == identities);
    let valid_bytes = d.0.borrow().bytes.clone();
    let mut overflow = retained;
    overflow.completed.push(SessionIdentity {
        boot_id: [7; 16],
        runtime: runtime(),
        scope: next.clone(),
    });
    d.0.borrow_mut()
        .bytes
        .insert(PrivateFile::Index, serde_json::to_vec(&overflow).unwrap());
    assert!(files(&d).scopes(RuntimeSlot::Stable).is_err());
    d.0.borrow_mut().bytes = valid_bytes;
    let carrier_marker = completed_file(&identities[3].scope).unwrap();
    d.0.borrow_mut().bytes.remove(&carrier_marker);
    assert!(files(&d).scopes(RuntimeSlot::Stable).is_err());
    assert!(files(&d).claim(&next).is_err());
}
#[test]
fn concurrent_changed_private_record_is_never_overwritten_or_treated_as_ack() {
    let (d, f) = fixture();
    let mut store = open(&f);
    let p = prepared();
    save(&mut store, None, &p);
    let mut changed = advance(&p, Phase::Closing);
    changed.generation += 1;
    inject(&d, &changed);
    let changed_bytes = d.0.borrow().bytes[&PrivateFile::Carrier].clone();
    inject(&d, &p);
    d.0.borrow_mut().replace_before_cas = Some(changed_bytes.clone());
    assert!(store
        .compare_exchange(&key(), Some(&p), &created(&p))
        .is_err());
    assert!(store.load(&key()).is_err());
    assert_eq!(d.0.borrow().bytes[&PrivateFile::Carrier], changed_bytes);
    let (mut recovery, saved) = WindowsCarrierStore::open(files(&d), scope()).unwrap();
    assert_eq!(saved, Some(changed.clone()));
    assert_eq!(cleanup(&mut recovery, &changed).phase, Phase::Stopped);
}
#[test]
fn uncertain_post_cas_confirmation_revokes_live_store_until_cleanup_reopen() {
    for unreadable in [false, true] {
        let (d, f) = fixture();
        let mut store = open(&f);
        if unreadable {
            d.0.borrow_mut().fail_read_after_write = true;
        } else {
            d.0.borrow_mut().false_ack = true;
        }
        let p = prepared();
        assert!(store.compare_exchange(&key(), None, &p).is_err());
        d.0.borrow_mut().fail_read = None;
        assert!(
            store.load(&key()).is_err(),
            "uncertain CAS must not restore fresh authority"
        );
        assert!(store.compare_exchange(&key(), None, &p).is_err());
        let (mut reopened, record) = WindowsCarrierStore::open(files(&d), scope()).unwrap();
        assert_eq!(record, unreadable.then_some(p.clone()));
        if let Some(record) = record {
            assert_eq!(cleanup(&mut reopened, &record).phase, Phase::Stopped);
        } else {
            assert!(reopened.compare_exchange(&key(), None, &p).is_err());
        }
    }
}
#[test]
fn lost_ack_at_each_carrier_commit_keeps_exact_obligation_and_blocks_live_instance() {
    for number in 1..=13 {
        for committed in [false, true] {
            let (d, f) = fixture();
            let mut store = open(&f);
            // Derive the ordered real lifecycle's payloads without touching disk.
            let p = prepared();
            let c = created(&p);
            let mut sequence = vec![p, c.clone()];
            let mut r = c;
            for i in [1, 0] {
                let mut pending = advance(&r, Phase::Created);
                pending.rows.as_mut().unwrap()[i].pending = Some(goal()[i].clone());
                let mut confirmed = advance(&pending, Phase::Created);
                let row = &mut confirmed.rows.as_mut().unwrap()[i];
                row.current = row.pending.take().unwrap();
                sequence.extend([pending, confirmed.clone()]);
                r = confirmed;
            }
            r = advance(&r, Phase::Configured);
            sequence.push(r.clone());
            r = advance(&r, Phase::Closing);
            sequence.push(r.clone());
            for i in [0, 1] {
                let mut pending = advance(&r, Phase::Closing);
                let row = &mut pending.rows.as_mut().unwrap()[i];
                row.pending = Some(row.baseline.clone());
                let mut confirmed = advance(&pending, Phase::Closing);
                let row = &mut confirmed.rows.as_mut().unwrap()[i];
                row.current = row.pending.take().unwrap();
                sequence.extend([pending, confirmed.clone()]);
                r = confirmed;
            }
            sequence.push(advance(&r, Phase::Stopped));
            for (i, next) in sequence.iter().enumerate() {
                let old = i.checked_sub(1).map(|i| &sequence[i]);
                if i + 1 == number {
                    if committed {
                        d.0.borrow_mut().lose_ack = Some(PrivateFile::Carrier);
                    } else {
                        d.0.borrow_mut().fail = Some(PrivateFile::Carrier);
                    }
                    assert!(store.compare_exchange(&key(), old, next).is_err());
                    assert!(store.load(&key()).is_err());
                    d.0.borrow_mut().fail = None;
                    let (mut reopened, saved) =
                        WindowsCarrierStore::open(files(&d), scope()).unwrap();
                    assert_eq!(
                        saved.as_ref(),
                        if committed { Some(next) } else { old },
                        "commit {number}/{committed}"
                    );
                    if let Some(saved) = saved {
                        assert_eq!(cleanup(&mut reopened, &saved).phase, Phase::Stopped);
                    } else {
                        assert!(reopened
                            .compare_exchange(&key(), None, &prepared())
                            .is_err());
                    }
                    break;
                }
                save(&mut store, old, next);
            }
        }
    }
}
#[test]
fn cleanup_lost_ack_is_reread_exactly_without_resuming_or_losing_pending_rows() {
    let (d, f) = fixture();
    let mut live = open(&f);
    let ready = configure(&mut live);
    let mut recovered = open(&files(&d));
    let closing = advance(&ready, Phase::Closing);
    d.0.borrow_mut().lose_ack = Some(PrivateFile::Carrier);
    save(&mut recovered, Some(&ready), &closing);
    let mut pending = advance(&closing, Phase::Closing);
    let row = &mut pending.rows.as_mut().unwrap()[0];
    row.pending = Some(row.baseline.clone());
    d.0.borrow_mut().lose_ack = Some(PrivateFile::Carrier);
    save(&mut recovered, Some(&closing), &pending);
    assert_eq!(recovered.load(&key()).unwrap(), Some(pending.clone()));
    assert!(recovered
        .compare_exchange(
            &key(),
            Some(&pending),
            &advance(&pending, Phase::Configured)
        )
        .is_err());
    assert_eq!(cleanup(&mut recovered, &pending).phase, Phase::Stopped);
}
#[test]
fn cleanup_can_confirm_either_exact_current_or_exact_pending_but_cannot_invent_rows() {
    for applied in [false, true] {
        let (d, f) = fixture();
        let mut live = open(&f);
        let p = prepared();
        save(&mut live, None, &p);
        let c = created(&p);
        save(&mut live, Some(&p), &c);
        let mut pending = advance(&c, Phase::Created);
        pending.rows.as_mut().unwrap()[1].pending = Some(goal()[1].clone());
        save(&mut live, Some(&c), &pending);
        let mut recovered = open(&files(&d));
        let closing = advance(&pending, Phase::Closing);
        save(&mut recovered, Some(&pending), &closing);
        let mut confirmed = advance(&closing, Phase::Closing);
        let row = &mut confirmed.rows.as_mut().unwrap()[1];
        if applied {
            row.current = row.pending.clone().unwrap();
        }
        row.pending = None;
        save(&mut recovered, Some(&closing), &confirmed);
        assert_eq!(cleanup(&mut recovered, &confirmed).phase, Phase::Stopped);
    }
}
#[test]
fn epoch_advancement_cannot_migrate_live_carrier_but_cleanup_preserves_retained_epoch() {
    let (d, f) = fixture();
    let mut live = open(&f);
    let ready = configure(&mut live);
    let (mut session, _) =
        WindowsSessionStore::open(f.clone(), scope(), RecordKind::Session).unwrap();
    let mut state = SessionState::new(scope(), Slot::A, 1, 1)
        .unwrap()
        .snapshot();
    state.network_epoch = 2;
    session.save(&state).unwrap();
    let before = d.0.borrow().bytes[&PrivateFile::Carrier].clone();
    assert_eq!(
        live.compare_exchange(&key(), Some(&ready), &ready),
        Err(carrier::CarrierError::Conflict)
    );
    assert_eq!(d.0.borrow().bytes[&PrivateFile::Carrier], before);
    let mut recovery = open(&files(&d));
    let stopped = cleanup(&mut recovery, &ready);
    assert_eq!(stopped.provenance.network_epoch, 1);
    let raw: SavedRecord =
        serde_json::from_slice(&d.0.borrow().bytes[&PrivateFile::Carrier]).unwrap();
    assert_eq!(raw.network_epoch, 1);
}
#[test]
fn normal_stale_boot_runtime_scope_views_are_denied_and_explicit_view_is_cleanup_only() {
    let (d, f) = fixture();
    let mut live = open(&f);
    let ready = configure(&mut live);
    let before = d.0.borrow().bytes.clone();
    let mut changed_runtime = runtime();
    changed_runtime.manifest_sha256 = "b".repeat(64);
    for boot in [[7; 16], [8; 16]] {
        let mut changed =
            ProtectedSessionFiles::new(d.clone(), changed_runtime.clone(), boot).unwrap();
        assert!(WindowsCarrierStore::open(changed.clone(), scope()).is_err());
        let (view, reboot) = changed.recovery_view(RuntimeSlot::Stable).unwrap().unwrap();
        assert_eq!(reboot, boot != [7; 16]);
        let (mut store, record) = WindowsCarrierStore::open(view, scope()).unwrap();
        assert_eq!(record, Some(ready.clone()));
        assert!(store
            .compare_exchange(&key(), Some(&ready), &advance(&ready, Phase::Configured))
            .is_err());
    }
    let mut foreign = scope();
    foreign.connection_generation += 1;
    assert!(WindowsCarrierStore::open(f.clone(), foreign).is_err());
    assert_eq!(d.0.borrow().bytes, before);
}
#[test]
fn carrier_envelope_bound_and_private_read_errors_never_clear_claim_or_records() {
    let (d, mut f) = fixture();
    clean_legacy(&mut f, &scope());
    d.0.borrow_mut()
        .bytes
        .insert(PrivateFile::Carrier, vec![b' '; 64 * 1024 + 1]);
    let before = d.0.borrow().bytes.clone();
    assert!(f.read(&scope(), RecordKind::Carrier).is_err());
    assert!(f.complete(&scope()).is_err());
    assert!(f.complete_empty(&scope()).is_err());
    assert_eq!(d.0.borrow().bytes, before);
    inject(&d, &prepared());
    d.0.borrow_mut().fail_read = Some(PrivateFile::Carrier);
    let error = f.read(&scope(), RecordKind::Carrier).unwrap_err();
    assert!(!error.to_string().contains("SECRET"));
    assert!(WindowsCarrierStore::open(f.clone(), scope()).is_err());
    assert!(f.complete(&scope()).is_err());
}
#[test]
fn carrier_storage_never_trusts_bare_json_without_authenticated_session_access() {
    #[derive(Clone)]
    struct BareJson;
    impl SessionFiles for BareJson {
        fn scopes(&mut self, _: RuntimeSlot) -> io::Result<Vec<SessionScope>> {
            Ok(vec![scope()])
        }
        fn claim(&mut self, _: &SessionScope) -> io::Result<()> {
            Ok(())
        }
        fn read(&mut self, _: &SessionScope, _: RecordKind) -> io::Result<Option<Vec<u8>>> {
            panic!("unauthenticated JSON must not be read")
        }
        fn compare_exchange(
            &mut self,
            _: &SessionScope,
            _: RecordKind,
            _: Option<&[u8]>,
            _: &[u8],
        ) -> io::Result<()> {
            panic!("unauthenticated mutation")
        }
    }
    assert!(WindowsCarrierStore::open(BareJson, scope()).is_err());
}
#[test]
fn completed_marker_does_not_authorize_live_carrier_retirement_or_overwrite() {
    let (d, mut f) = fixture();
    let mut live = open(&f);
    let ready = configure(&mut live);
    let stopped = cleanup(&mut live, &ready);
    clean_legacy(&mut f, &scope());
    f.complete(&scope()).unwrap();
    inject(&d, &ready);
    let before = d.0.borrow().bytes.clone();
    let mut next = scope();
    next.connection_generation += 1;
    assert!(files(&d).scopes(RuntimeSlot::Stable).is_err());
    assert!(files(&d).claim(&next).is_err());
    assert!(f.complete(&scope()).is_err());
    assert_eq!(d.0.borrow().bytes, before);
    inject(&d, &stopped);
    f.claim(&next).unwrap();
    inject(&d, &ready);
    assert!(f.read(&next, RecordKind::Carrier).is_err());
    assert!(f.complete_empty(&next).is_err());
}

#[test]
fn carrier_store_fresh_lifecycle_and_exact_completion_include_carrier() {
    let (d, mut f) = fixture();
    let mut store = open(&f);
    let ready = configure(&mut store);
    assert_eq!(store.load(&key()).unwrap(), Some(ready.clone()));
    let raw: SavedRecord =
        serde_json::from_slice(&d.0.borrow().bytes[&PrivateFile::Carrier]).unwrap();
    assert_eq!(raw.identity.boot_id, [7; 16]);
    assert_eq!(raw.identity.runtime, runtime());
    assert_eq!(raw.network_epoch, 1);
    clean_legacy(&mut f, &scope());
    assert!(f.complete(&scope()).is_err());
    let mut recovered = open(&files(&d));
    let stopped = cleanup(&mut recovered, &ready);
    assert_eq!(stopped.phase, Phase::Stopped);
    assert_eq!(stopped.proof, ready.proof);
    f.complete(&scope()).unwrap();
    f.complete(&scope()).unwrap();
    assert!(files(&d).claim(&scope()).is_err());
}
#[test]
fn every_present_nonstopped_or_invalid_carrier_prevents_completion() {
    for kind in 0..9 {
        let (d, mut f) = fixture();
        clean_legacy(&mut f, &scope());
        let p = prepared();
        let c = created(&p);
        let mut r = match kind {
            0 => p,
            _ => c,
        };
        match kind {
            2 => {
                r.phase = Phase::Configured;
                for (i, row) in r.rows.as_mut().unwrap().iter_mut().enumerate() {
                    row.current = goal()[i].clone();
                }
            }
            3 => r.phase = Phase::Closing,
            4 => {
                r.phase = Phase::Stopped;
                r.rows.as_mut().unwrap()[0].pending = Some(goal()[0].clone());
            }
            5 => {
                r.phase = Phase::Stopped;
                r.rows.as_mut().unwrap()[0].current = goal()[0].clone();
            }
            6 => {
                r.phase = Phase::Stopped;
                r.version = 99;
            }
            7 => {
                r.phase = Phase::Stopped;
                r.provenance.network_epoch = 2;
            }
            8 => {
                r.phase = Phase::Stopped;
                r.provenance.boot_id = [8; 16];
            }
            _ => {}
        }
        inject(&d, &r);
        let before = d.0.borrow().bytes.clone();
        assert!(f.complete(&scope()).is_err(), "case {kind}");
        assert_eq!(d.0.borrow().bytes, before);
        assert!(!d
            .0
            .borrow()
            .bytes
            .contains_key(&completed_file(&scope()).unwrap()));
    }
}
#[test]
fn complete_empty_rejects_carrier_even_without_other_payloads() {
    for terminal in [false, true] {
        let (d, mut f) = fixture();
        let mut r = prepared();
        if terminal {
            r.phase = Phase::Stopped;
            r.generation = 3;
        }
        inject(&d, &r);
        let before = d.0.borrow().bytes.clone();
        assert!(f.complete_empty(&scope()).is_err());
        assert_eq!(d.0.borrow().bytes, before);
    }
}
#[test]
fn orphan_carrier_blocks_scopes_recovery_and_new_claim() {
    let (d, _) = fixture();
    inject(&d, &prepared());
    d.0.borrow_mut().bytes.remove(&PrivateFile::Index);
    let before = d.0.borrow().bytes.clone();
    let mut f = files(&d);
    assert!(f.scopes(RuntimeSlot::Stable).is_err());
    assert!(f.recovery_view(RuntimeSlot::Stable).is_err());
    assert!(f.claim(&scope()).is_err());
    assert_eq!(d.0.borrow().bytes, before);
}
#[test]
fn carrier_payload_provenance_is_authenticated_by_protected_envelope() {
    for kind in 0..8 {
        let (d, mut f) = fixture();
        let mut p = prepared();
        match kind {
            0 => p.provenance.boot_id = [8; 16],
            1 => p.provenance.runtime.manifest_sha256 = "b".repeat(64),
            2 => p.provenance.runtime.runtime_version = "other".into(),
            3 => p.provenance.network_epoch = 2,
            4 => p.intent.scope.connection_generation += 1,
            5 => p.version = 99,
            6 => p.provenance.runtime.slot = RuntimeSlot::Latest,
            _ => p.provenance.network_epoch = 0,
        }
        assert!(
            f.compare_exchange(&scope(), RecordKind::Carrier, None, &payload(&p))
                .is_err(),
            "case {kind}"
        );
        assert!(!d.0.borrow().bytes.contains_key(&PrivateFile::Carrier));
    }
}
#[test]
fn carrier_fresh_creation_requires_claim_and_cannot_be_replayed_from_recovery() {
    let d = Disk::default();
    assert!(WindowsCarrierStore::open(files(&d), scope()).is_err());
    let (d, f) = fixture();
    let mut reopened = open(&files(&d));
    assert!(reopened
        .compare_exchange(&key(), None, &prepared())
        .is_err());
    let mut original = open(&f);
    save(&mut original, None, &prepared());
    let mut recovered = open(&f);
    assert!(recovered
        .compare_exchange(&key(), Some(&prepared()), &created(&prepared()))
        .is_err());
}
#[test]
fn carrier_unknown_fields_versions_scope_and_saved_epoch_reject_read_and_completion() {
    for kind in 0..15 {
        let (d, mut f) = fixture();
        clean_legacy(&mut f, &scope());
        let mut stopped = created(&prepared());
        stopped.phase = Phase::Stopped;
        inject(&d, &stopped);
        let raw = d.0.borrow().bytes[&PrivateFile::Carrier].clone();
        let mut saved: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let mut data: serde_json::Value =
            serde_json::from_str(saved["data"].as_str().unwrap()).unwrap();
        match kind {
            0 => {
                saved["extra"] = true.into();
            }
            1 => saved["version"] = 99.into(),
            2 => data["version"] = 99.into(),
            3 => data["payload"]["version"] = 99.into(),
            4 => data["payload"]["extra"] = true.into(),
            5 => data["scope"]["connection_generation"] = 9.into(),
            6 => saved["network_epoch"] = 2.into(),
            7 => data["payload"]["provenance"]["network_epoch"] = 2.into(),
            8 => saved["kind"] = "Pair".into(),
            9 => data["payload"]["provenance"]["runtime"]["extra"] = true.into(),
            10 => data["payload"]["intent"]["extra"] = true.into(),
            11 => data["payload"]["rows"][0]["extra"] = true.into(),
            12 => data["payload"]["phase"] = "Unknown".into(),
            13 => data["payload"]["rows"][1]["pending"] = serde_json::json!({"Unknown": {}}),
            _ => data["extra"] = true.into(),
        }
        saved["data"] = serde_json::to_string(&data).unwrap().into();
        d.0.borrow_mut()
            .bytes
            .insert(PrivateFile::Carrier, serde_json::to_vec(&saved).unwrap());
        let before = d.0.borrow().bytes.clone();
        assert!(
            f.read(&scope(), RecordKind::Carrier).is_err(),
            "read {kind}"
        );
        assert!(WindowsCarrierStore::open(f.clone(), scope()).is_err());
        assert!(f.complete(&scope()).is_err());
        assert_eq!(d.0.borrow().bytes, before);
    }
}
#[test]
fn foreign_key_and_stale_exact_cas_never_replace_current_record() {
    let (d, f) = fixture();
    let mut store = open(&f);
    let p = prepared();
    save(&mut store, None, &p);
    for kind in 0..3 {
        let mut foreign = key();
        match kind {
            0 => foreign.name.push('x'),
            1 => foreign.guid[0] ^= 1,
            _ => {
                let mut s = scope();
                s.connection_generation += 1;
                foreign = carrier::carrier_key(&s).unwrap();
            }
        }
        let before = d.0.borrow().bytes.clone();
        assert!(store.load(&foreign).is_err());
        assert!(store
            .compare_exchange(&foreign, Some(&p), &created(&p))
            .is_err());
        assert_eq!(d.0.borrow().bytes, before);
    }
    let c = created(&p);
    save(&mut store, Some(&p), &c);
    let before = d.0.borrow().bytes.clone();
    assert!(store.compare_exchange(&key(), Some(&p), &c).is_err());
    assert_eq!(d.0.borrow().bytes, before);
}
#[test]
fn recovery_store_independently_rejects_resume_proof_baseline_and_intent_changes() {
    for kind in 0..10 {
        let (d, f) = fixture();
        let mut original = open(&f);
        let ready = configure(&mut original);
        let mut recovered = open(&files(&d));
        let mut next = advance(&ready, Phase::Closing);
        match kind {
            0 => next.phase = Phase::Created,
            1 => next.phase = Phase::Configured,
            2 => next.proof.as_mut().unwrap().luid += 1,
            3 => {
                next.proof = None;
                next.rows = None;
            }
            4 => {
                next.rows.as_mut().unwrap()[1].baseline = RowValue::WeakHost(WeakHostRow {
                    send: true,
                    receive: false,
                })
            }
            5 => next.intent.addresses[0] = "10.7.0.3/32".parse().unwrap(),
            6 => next.provenance.network_epoch += 1,
            7 => next.generation = ready.generation,
            8 => next.generation += 1,
            _ => next.rows.as_mut().unwrap()[0].current = RowValue::Address(None),
        }
        let before = d.0.borrow().bytes.clone();
        assert!(
            recovered
                .compare_exchange(&key(), Some(&ready), &next)
                .is_err(),
            "case {kind}"
        );
        assert_eq!(d.0.borrow().bytes, before);
    }
}
#[test]
fn raw_session_boundary_independently_rejects_recovery_resume() {
    let (d, f) = fixture();
    let mut store = open(&f);
    let ready = configure(&mut store);
    let mut reopened = files(&d);
    assert!(reopened
        .compare_exchange(
            &scope(),
            RecordKind::Carrier,
            Some(&payload(&ready)),
            &payload(&advance(&ready, Phase::Configured))
        )
        .is_err());
    let closing = advance(&ready, Phase::Closing);
    reopened
        .compare_exchange(
            &scope(),
            RecordKind::Carrier,
            Some(&payload(&ready)),
            &payload(&closing),
        )
        .unwrap();
}
#[test]
fn carrier_lost_ack_preserves_durable_pending_and_allows_only_cleanup_reopen() {
    for committed in [false, true] {
        let (d, f) = fixture();
        let mut store = open(&f);
        let p = prepared();
        save(&mut store, None, &p);
        let c = created(&p);
        save(&mut store, Some(&p), &c);
        let mut pending = advance(&c, Phase::Created);
        pending.rows.as_mut().unwrap()[1].pending = Some(goal()[1].clone());
        if committed {
            d.0.borrow_mut().lose_ack = Some(PrivateFile::Carrier);
        } else {
            d.0.borrow_mut().fail = Some(PrivateFile::Carrier);
        }
        assert!(store.compare_exchange(&key(), Some(&c), &pending).is_err());
        d.0.borrow_mut().fail = None;
        let (mut recovered, saved) = WindowsCarrierStore::open(files(&d), scope()).unwrap();
        let saved = saved.unwrap();
        assert_eq!(
            saved,
            if committed {
                pending.clone()
            } else {
                c.clone()
            }
        );
        assert!(recovered
            .compare_exchange(&key(), Some(&saved), &advance(&saved, Phase::Created))
            .is_err());
        let closing = advance(&saved, Phase::Closing);
        save(&mut recovered, Some(&saved), &closing);
        let mut cleared = advance(&closing, Phase::Closing);
        cleared.rows.as_mut().unwrap()[1].pending = None;
        if committed {
            save(&mut recovered, Some(&closing), &cleared);
        }
    }
}
#[test]
fn legacy_missing_carrier_and_terminal_carrier_remain_cleanup_compatible() {
    let (d, mut f) = fixture();
    clean_legacy(&mut f, &scope());
    f.complete(&scope()).unwrap();
    assert!(!d.0.borrow().bytes.contains_key(&PrivateFile::Carrier));
    let (d, mut f) = fixture();
    let mut store = open(&f);
    let ready = configure(&mut store);
    cleanup(&mut store, &ready);
    clean_legacy(&mut f, &scope());
    f.complete(&scope()).unwrap();
    let mut next_scope = scope();
    next_scope.connection_generation += 1;
    f.claim(&next_scope).unwrap();
    assert!(f.read(&next_scope, RecordKind::Carrier).unwrap().is_none());
    let before = d.0.borrow().bytes[&PrivateFile::Carrier].clone();
    f.complete_empty(&next_scope).unwrap();
    assert_eq!(d.0.borrow().bytes[&PrivateFile::Carrier], before);
    let index: SessionIndex =
        serde_json::from_slice(&d.0.borrow().bytes[&PrivateFile::Index]).unwrap();
    assert!(index.completed.iter().any(|id| id.scope == scope()));
}
