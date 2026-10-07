//! Real protected SessionFiles boundary with only private disk IO substituted.
#[cfg(windows)]
use super::super::member_files::{PrivateFile, PrivateRecords, SessionFileIo};
#[cfg(windows)]
use super::super::member_session::{ProtectedSessionFiles, WindowsSessionStore};
use super::*;
use crate::member_carrier::{Intent, Provenance};
use crate::member_carrier_native_ownership::{Binding, Context, Role};
use crate::member_carrier_pair::PairJournal;
use crate::member_carrier_pair::{Phase, Record};
#[cfg(not(windows))]
use crate::member_files::{PrivateFile, PrivateRecords, SessionFileIo};
#[cfg(not(windows))]
use crate::member_session::{ProtectedSessionFiles, WindowsSessionStore};
use nelomai_client_tunnel::redundancy::SessionScope;
use nelomai_contracts::{dispatcher::EngineIdentity, RuntimeSlot};
use std::{cell::RefCell, collections::BTreeMap, io, rc::Rc};

#[derive(Clone, Default)]
struct Disk(Rc<RefCell<DiskState>>);
#[derive(Default)]
struct DiskState {
    bytes: BTreeMap<PrivateFile, Vec<u8>>,
    fault: u8,
    unreadable: bool,
    writes: usize,
}
impl PrivateRecords for Disk {
    fn read(&mut self, file: PrivateFile) -> io::Result<Option<Vec<u8>>> {
        let d = self.0.borrow();
        if file == PrivateFile::Pair && d.unreadable {
            return Err(io::Error::other("private_pair_unreadable"));
        }
        Ok(d.bytes.get(&file).cloned())
    }
    fn compare_exchange(
        &mut self,
        file: PrivateFile,
        expected: Option<&[u8]>,
        desired: &[u8],
    ) -> io::Result<()> {
        let mut d = self.0.borrow_mut();
        if d.bytes.get(&file).map(Vec::as_slice) != expected {
            return Err(io::Error::other("disk_conflict"));
        }
        let fault = if file == PrivateFile::Pair {
            d.writes += 1;
            std::mem::take(&mut d.fault)
        } else {
            0
        };
        if fault == 1 {
            return Err(io::Error::other("private_before_write"));
        }
        if fault == 3 {
            return Ok(());
        }
        let mut bytes = desired.to_vec();
        if fault == 5 {
            let mut saved: serde_json::Value = serde_json::from_slice(desired).unwrap();
            saved["data"] = format!("{} ", saved["data"].as_str().unwrap()).into();
            bytes = serde_json::to_vec(&saved).unwrap();
        }
        d.bytes.insert(file, bytes);
        if fault == 4 {
            d.unreadable = true;
        }
        if fault == 2 {
            return Err(io::Error::other("private_commit_lost_ack"));
        }
        Ok(())
    }
}
impl SessionFileIo for Disk {
    fn transaction<T>(
        &mut self,
        f: impl FnOnce(&mut dyn PrivateRecords) -> io::Result<T>,
    ) -> io::Result<T> {
        f(self)
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
fn context() -> Context {
    Context {
        intent: Intent { scope: scope(), addresses: vec!["10.7.0.2/32".parse().unwrap()] },
        provenance: Provenance { boot_id: [7;16], runtime: EngineIdentity { slot: RuntimeSlot::Stable, runtime_version: "1.0.0".into(), runtime_contract_version: 1, container_version: "1.0.0".into(), manifest_sha256: "a".repeat(64) }, network_epoch: 1 },
        bindings: [Role::RoleCarrier, Role::MemberA, Role::MemberB].map(|role| {
            let n = match role { Role::RoleCarrier => 1, Role::MemberA => 2, Role::MemberB => 3 };
            let b = format!("{n:02x}");
            Binding { role, guid: [n;16], name: format!("pair-store-{n}"), registry_path: format!(r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{{}-{}-{}-{}-{}}}", b.repeat(4), b.repeat(2), b.repeat(2), b.repeat(2), b.repeat(6)) }
        }),
    }
}
fn fresh() -> Record {
    Record {
        version: 2,
        scope: scope(),
        provenance: context().provenance,
        revision: 1,
        phase: Phase::Fresh,
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
        stop_stage: 0,
        operation: None,
    }
}
fn pair_bytes(record: &Record) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"version":1,"scope":scope(),"payload":record})).unwrap()
}
fn files() -> (Disk, ProtectedSessionFiles<Disk>) {
    let d = Disk::default();
    let f = ProtectedSessionFiles::new(d.clone(), context().provenance.runtime, [7; 16]).unwrap();
    (d, f)
}

/// Desired MAIN integration contract. This must be RED while the actual raw
/// Pair validator is v1-only; never bypass it with a fake successful validator.
#[test]
fn original_closing_ack_covers_only_exact_sequential_cleanup_stage() {
    use nelomai_client_tunnel::redundancy::Slot;
    // Break: cleanup entry accepts merely Closing, wrong stage or a live effect.
    let effects = [
        pair::Effect::Guard,
        pair::Effect::ReleaseProbes,
        pair::Effect::RestoreNetwork,
        pair::Effect::RestoreWeak,
        pair::Effect::MemberStop(Slot::A),
        pair::Effect::MemberStop(Slot::B),
        pair::Effect::CarrierAddressDelete,
        pair::Effect::CarrierSessionEnd,
        pair::Effect::CarrierClose,
        pair::Effect::NativeEmpty,
        pair::Effect::Guard,
        pair::Effect::RestoreKeys,
        pair::Effect::FullEmpty,
    ];
    let f = fixture();
    let (mut store, _) = WindowsCarrierPairStore::open(f.files.clone(), context()).unwrap();
    store.compare_exchange(None, &fresh()).unwrap();
    let mut current = fresh();
    for (stage, effect) in effects.iter().enumerate() {
        let mut next = closing(&current);
        next.stop_stage = stage as u8;
        next.pending = Some(*effect);
        store.compare_exchange(Some(&current), &next).unwrap();
        let intent = store.record_intent(&next).unwrap();
        let writes = f.disk.0.borrow().writes;
        intent.cleanup().unwrap();
        assert_eq!(f.disk.0.borrow().writes, writes);
        for bad_effect in [
            pair::Effect::Data(Slot::A),
            pair::Effect::CarrierReady,
            pair::Effect::Network,
            pair::Effect::HoldProbe(Slot::B),
        ] {
            let mut bad = next.clone();
            bad.pending = Some(bad_effect);
            let comparison = RecordIntent {
                origin: std::rc::Rc::new(()),
                raw: encode_carrier_payload(&bad).unwrap(),
                record: bad,
            };
            assert!(comparison.cleanup().is_err());
        }
        let mut wrong = next.clone();
        wrong.stop_stage = if stage == 12 { 0 } else { stage as u8 + 1 };
        assert!(RecordIntent {
            origin: std::rc::Rc::new(()),
            raw: encode_carrier_payload(&wrong).unwrap(),
            record: wrong
        }
        .cleanup()
        .is_err());
        let mut wrong = next.clone();
        wrong.phase = Phase::Starting;
        assert!(RecordIntent {
            origin: std::rc::Rc::new(()),
            raw: encode_carrier_payload(&wrong).unwrap(),
            record: wrong
        }
        .cleanup()
        .is_err());
        let mut wrong = next.clone();
        wrong.pending = None;
        assert!(RecordIntent {
            origin: std::rc::Rc::new(()),
            raw: encode_carrier_payload(&wrong).unwrap(),
            record: wrong
        }
        .cleanup()
        .is_err());
        let mut wrong = next.clone();
        wrong.operation = Some(pair::Operation::Start(Slot::A));
        assert!(RecordIntent {
            origin: std::rc::Rc::new(()),
            raw: encode_carrier_payload(&wrong).unwrap(),
            record: wrong
        }
        .cleanup()
        .is_err());
        current = next;
    }
    let (mut reopened, _) = WindowsCarrierPairStore::open(f.files, context()).unwrap();
    assert!(reopened.record_intent(&current).is_err());
}

#[test]
fn actual_protected_pair_boundary_accepts_authenticated_v2_fresh() {
    let (_, mut f) = files();
    f.claim(&scope()).unwrap();
    let bytes = pair_bytes(&fresh());
    f.compare_exchange(&scope(), RecordKind::Pair, None, &bytes)
        .unwrap();
    assert_eq!(f.read(&scope(), RecordKind::Pair).unwrap(), Some(bytes));
    assert!(f.complete_empty(&scope()).is_err());
}

#[derive(Clone)]
struct Fixture {
    files: ProtectedSessionFiles<Disk>,
    disk: Disk,
}
fn fixture() -> Fixture {
    let (disk, mut f) = files();
    f.claim(&scope()).unwrap();
    Fixture { files: f, disk }
}
fn closing(old: &Record) -> Record {
    let mut r = old.clone();
    r.revision += 1;
    r.phase = Phase::Closing;
    r.active = None;
    r.operation = None;
    r.pending = None;
    r
}

fn cleanup_effects() -> [pair::Effect; 13] {
    use nelomai_client_tunnel::redundancy::Slot;
    [
        pair::Effect::Guard,
        pair::Effect::ReleaseProbes,
        pair::Effect::RestoreNetwork,
        pair::Effect::RestoreWeak,
        pair::Effect::MemberStop(Slot::A),
        pair::Effect::MemberStop(Slot::B),
        pair::Effect::CarrierAddressDelete,
        pair::Effect::CarrierSessionEnd,
        pair::Effect::CarrierClose,
        pair::Effect::NativeEmpty,
        pair::Effect::Guard,
        pair::Effect::RestoreKeys,
        pair::Effect::FullEmpty,
    ]
}

fn cleanup_window(
    stage: u8,
) -> (
    Fixture,
    WindowsCarrierPairStore<ProtectedSessionFiles<Disk>>,
    Record,
) {
    let f = fixture();
    let (mut store, _) = WindowsCarrierPairStore::open(f.files.clone(), context()).unwrap();
    let mut record = fresh();
    store.compare_exchange(None, &record).unwrap();
    for current_stage in 0..=stage {
        let mut next = closing(&record);
        next.stop_stage = current_stage;
        next.pending = Some(cleanup_effects()[current_stage as usize]);
        store.compare_exchange(Some(&record), &next).unwrap();
        record = next;
    }
    (f, store, record)
}

#[test]
fn cleanup_effect_read_returns_exact_acknowledged_stage_without_any_publication() {
    // Break: deny all cleanup reads, skip the callback, substitute a record, or
    // mutate storage/revision while reading the original Closing publication.
    for stage in 0..=12 {
        let (f, mut store, record) = cleanup_window(stage);
        let intent = store.record_intent(&record).unwrap();
        let before = f.disk.0.borrow().bytes.clone();
        let writes = f.disk.0.borrow().writes;
        let result = intent
            .inspect_cleanup_effect(&record, stage, |actual| {
                assert!(actual == &record);
                assert_eq!(actual.pending, Some(cleanup_effects()[stage as usize]));
                Ok((actual.revision, actual.stop_stage))
            })
            .unwrap();
        assert_eq!(result, (stage as u64 + 2, stage));
        assert_eq!(f.disk.0.borrow().bytes, before);
        assert_eq!(f.disk.0.borrow().writes, writes);
        assert!(store.load(&scope()).unwrap() == Some(record));
    }
}

#[test]
fn exact_original_terminal_ack_is_readonly_and_never_a_closing_effect_ack() {
    let (f, mut store, current) = cleanup_window(12);
    let mut stopped = current.clone();
    stopped.revision += 1;
    stopped.phase = Phase::Stopped;
    stopped.pending = None;
    stopped.carrier = None;
    stopped.members = [None, None];
    stopped.active = None;
    stopped.pending_guard = None;
    store.compare_exchange(Some(&current), &stopped).unwrap();
    let intent = store.record_intent(&stopped).unwrap();
    let writes = f.disk.0.borrow().writes;
    let bytes = f.disk.0.borrow().bytes.clone();
    intent.terminal_entry(&stopped).unwrap();
    assert_eq!(writes, f.disk.0.borrow().writes);
    assert_eq!(bytes, f.disk.0.borrow().bytes);
    assert!(intent.cleanup().is_err());
    assert!(intent.effect(&stopped, pair::Effect::FullEmpty).is_err());
    let mut foreign = stopped.clone();
    foreign.revision += 1;
    assert!(intent.terminal_entry(&foreign).is_err());
    let current_intent = RecordIntent {
        origin: std::rc::Rc::new(()),
        raw: encode_carrier_payload(&current).unwrap(),
        record: current,
    };
    assert!(current_intent.terminal_entry(&stopped).is_err());
}

#[test]
fn terminal_read_accepts_later_ack_only_from_same_original_store() {
    // Break: comparing pin addresses rejects a later ACK from the actual store;
    // comparing equal record bytes adopts an independently reopened writer.
    let (f, mut store, current) = cleanup_window(12);
    let closing_ack = store.record_intent(&current).unwrap();
    let mut stopped = current.clone();
    stopped.revision += 1;
    stopped.phase = Phase::Stopped;
    stopped.pending = None;
    store.compare_exchange(Some(&current), &stopped).unwrap();
    let terminal = store.record_intent(&stopped).unwrap();
    assert!(terminal.same_store_origin(&closing_ack));
    assert!(!std::ptr::eq(&terminal, &closing_ack));
    let (reopened, _) = WindowsCarrierPairStore::open(f.files, context()).unwrap();
    let foreign = RecordIntent {
        origin: reopened.origin.clone(),
        raw: terminal.raw.clone(),
        record: stopped,
    };
    assert!(!terminal.same_store_origin(&foreign));
}

#[test]
fn terminal_read_frame_is_nonreentrant_and_exists_only_inside_actual_outer_read() {
    // Break: allowing terminal bracket reads outside inspect or recursively
    // entering the Pair mutex; neither busy alone nor equal records is a frame.
    let (_, mut store, current) = cleanup_window(12);
    let intent = store.record_intent(&current).unwrap();
    let busy = Cell::new(false);
    let revoked = Cell::new(false);
    let slot = RefCell::new(None);
    assert!(PairReadFrame::inspect(&slot, &busy, &revoked, |_: &RecordIntent| Ok(())).is_err());
    let mut call = PairIntentCall::begin(&busy, &revoked).unwrap();
    // A pre-entry call's busy flag alone is not an authenticated read frame.
    assert!(PairReadFrame::inspect(&slot, &busy, &revoked, |_: &RecordIntent| Ok(())).is_err());
    let frame = PairReadFrame::enter(&slot, intent).unwrap();
    let read = PairReadFrame::inspect(&slot, &busy, &revoked, |original| {
        Ok((original.record.revision, original.record.stop_stage))
    })
    .unwrap();
    assert_eq!(read, (14, 12));
    assert!(PairReadFrame::enter(&slot, store.record_intent(&current).unwrap()).is_err());
    drop(frame);
    assert!(PairReadFrame::inspect(&slot, &busy, &revoked, |_: &RecordIntent| Ok(())).is_err());
    call.completed = true;
    drop(call);
    assert!(!busy.get());
    assert!(!revoked.get());
}

#[test]
fn terminal_read_frame_revocation_and_unwind_cannot_reopen_bracket() {
    // Break: retaining an active frame after callback unwind or accepting it
    // after a caught outer Pair reentry permanently revoked the original read.
    for unwind in [false, true] {
        let (_, mut store, current) = cleanup_window(12);
        let intent = store.record_intent(&current).unwrap();
        let busy = Cell::new(false);
        let revoked = Cell::new(false);
        let slot = RefCell::new(None);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _call = PairIntentCall::begin(&busy, &revoked).unwrap();
            let _frame = PairReadFrame::enter(&slot, intent).unwrap();
            if unwind {
                panic!("outer_pair_read_unwind");
            }
            assert!(PairIntentCall::begin(&busy, &revoked).is_err());
            assert!(
                PairReadFrame::inspect(&slot, &busy, &revoked, |_: &RecordIntent| Ok(())).is_err()
            );
        }));
        assert_eq!(outcome.is_err(), unwind);
        assert!(slot.borrow().is_none());
        assert!(!busy.get());
        assert!(revoked.get());
        assert!(PairReadFrame::inspect(&slot, &busy, &revoked, |_: &RecordIntent| Ok(())).is_err());
    }
}

#[test]
fn explicit_cleanup_store_entry_is_readonly_sticky_and_rejects_fresh_publication() {
    let f = fixture();
    let (mut store, _) = WindowsCarrierPairStore::open(f.files.clone(), context()).unwrap();
    let record = fresh();
    store.compare_exchange(None, &record).unwrap();
    let before = f.disk.0.borrow().bytes.clone();
    let writes = f.disk.0.borrow().writes;
    store.begin_cleanup(&scope()).unwrap();
    assert!(store.cleanup_only);
    assert_eq!(f.disk.0.borrow().bytes, before);
    assert_eq!(f.disk.0.borrow().writes, writes);
    assert!(store.load(&scope()).unwrap() == Some(record.clone()));
    let mut forward = record.clone();
    forward.revision += 1;
    assert!(store.compare_exchange(Some(&record), &forward).is_err());
    assert!(store.cleanup_only);
    let closing = closing(&record);
    store.compare_exchange(Some(&record), &closing).unwrap();
    store.begin_cleanup(&scope()).unwrap();
    assert!(store.load(&scope()).unwrap() == Some(closing));
}

#[test]
fn foreign_cleanup_storage_entry_cannot_revoke_original_store() {
    let f = fixture();
    let (mut store, _) = WindowsCarrierPairStore::open(f.files.clone(), context()).unwrap();
    let mut foreign = scope();
    foreign.connection_generation += 1;
    assert!(store.begin_cleanup(&foreign).is_err());
    assert!(!store.cleanup_only);
    store.compare_exchange(None, &fresh()).unwrap();
}

#[test]
fn original_birth_cleanup_view_keeps_same_writer_ack_after_session_epoch_changes() {
    use nelomai_client_tunnel::redundancy::{session::SessionState, Slot};
    let mut f = fixture();
    let session = SessionState::new(scope(), Slot::A, 1, 1)
        .unwrap()
        .snapshot();
    let payload = |session: &SessionSnapshot| {
        serde_json::to_vec(&Envelope {
            version: 1,
            scope: scope(),
            payload: session,
        })
        .unwrap()
    };
    let original = f.files.session_ack_root(&scope()).unwrap();
    f.files
        .compare_exchange(&scope(), RecordKind::Session, None, &payload(&session))
        .unwrap();
    let ack = original.inspect(|facts| Ok(facts.ack.clone())).unwrap();
    let execution = original.bind_native_birth(&context(), &ack).unwrap();
    let native_view = f.files.native_birth_view(&execution).unwrap();
    let (mut store, _) = WindowsCarrierPairStore::open(native_view, context()).unwrap();
    let record = fresh();
    store.compare_exchange(None, &record).unwrap();
    let writer = store.origin.clone();
    let old_ack = store.record_intent(&record).unwrap();
    let mut next = session.clone();
    next.network_epoch = 2;
    f.files
        .compare_exchange(
            &scope(),
            RecordKind::Session,
            Some(&payload(&session)),
            &payload(&next),
        )
        .unwrap();
    assert!(store.load(&scope()).is_err());
    // Actual Runtime supplies this exact original-root typed view at explicit
    // Stop. The real store must keep it through recovery refresh and CAS; no
    // replacement writer, equal JSON or post-read success can mint the ACK.
    store.files = execution
        .native_cleanup_view(&f.files)
        .unwrap()
        .into_files();
    store.begin_cleanup(&scope()).unwrap();
    assert!(Rc::ptr_eq(&writer, &store.origin));
    store.verify_original_intent(&old_ack, &record).unwrap();
    assert_eq!(
        store
            .files
            .native_carrier_access(&scope())
            .unwrap()
            .provenance()
            .network_epoch,
        1
    );
    let closing = closing(&record);
    store.compare_exchange(Some(&record), &closing).unwrap();
    let ack = store.record_intent(&closing).unwrap();
    assert!(
        ack.cleanup().is_err(),
        "storage-only Closing is not an SDK effect window"
    );
    let mut guard_window = closing.clone();
    guard_window.revision += 1;
    guard_window.pending = Some(pair::Effect::Guard);
    store
        .compare_exchange(Some(&closing), &guard_window)
        .unwrap();
    store
        .record_intent(&guard_window)
        .unwrap()
        .cleanup()
        .unwrap();
    assert!(store.load(&scope()).unwrap() == Some(guard_window));
    assert!(execution.current_lease().is_err());
}

#[test]
fn original_native_pair_writer_uses_explicit_execution_two_three_without_birth_rewrite() {
    use nelomai_client_tunnel::redundancy::{
        session::{SessionPhase, SessionState},
        Slot,
    };
    let mut f = fixture();
    let session = SessionState::new(scope(), Slot::A, 1, 1)
        .unwrap()
        .snapshot();
    let payload = |session: &SessionSnapshot| {
        serde_json::to_vec(&Envelope {
            version: 1,
            scope: scope(),
            payload: session,
        })
        .unwrap()
    };
    let original = f.files.session_ack_root(&scope()).unwrap();
    f.files
        .compare_exchange(&scope(), RecordKind::Session, None, &payload(&session))
        .unwrap();
    let current_ack = || original.inspect(|facts| Ok(facts.ack.clone())).unwrap();
    let execution = original
        .bind_native_birth(&context(), &current_ack())
        .unwrap();
    let birth = execution.current_lease().unwrap();
    let view = f.files.native_birth_view(&execution).unwrap();
    let (mut store, _) = WindowsCarrierPairStore::open(view, context()).unwrap();
    let mut record = fresh();
    store.compare_exchange(None, &record).unwrap();
    let mut before = session.clone();
    before.phase = SessionPhase::Running;
    before.installed[0] = true;
    before.committed[0] = true;
    f.files
        .compare_exchange(
            &scope(),
            RecordKind::Session,
            Some(&payload(&session)),
            &payload(&before),
        )
        .unwrap();
    let mut lease = execution.select_running(&birth, &current_ack()).unwrap();
    for epoch in [2, 3] {
        let mut next = before.clone();
        next.network_epoch = epoch;
        f.files
            .compare_exchange(
                &scope(),
                RecordKind::Session,
                Some(&payload(&before)),
                &payload(&next),
            )
            .unwrap();
        // Storage selection is explicit; no SDK readiness is asserted here.
        lease = if epoch == 2 {
            execution.renew_for_rebind(&lease, &current_ack()).unwrap()
        } else {
            execution.complete_rebind(&lease, &current_ack()).unwrap()
        };
        assert!(store.load(&scope()).unwrap() == Some(record.clone()));
        let mut desired = record.clone();
        desired.revision += 1;
        store.compare_exchange(Some(&record), &desired).unwrap();
        assert_eq!(desired.provenance.network_epoch, 1);
        assert!(!store.cleanup_only);
        record = desired;
        before = next;
    }
}

#[test]
fn cleanup_effect_read_rejects_equal_effect_at_other_stage_and_foreign_expected_record() {
    // Break: accept Guard stage 0 as stage 10, or accept caller data sharing
    // only scope/revision/pending rather than the entire acknowledged record.
    for stage in 0..=12 {
        let (_, mut store, record) = cleanup_window(stage);
        let intent = store.record_intent(&record).unwrap();
        for requested_stage in [
            stage.saturating_add(1),
            13,
            255,
            if stage == 0 { 10 } else { 0 },
        ] {
            let called = std::cell::Cell::new(false);
            assert!(intent
                .inspect_cleanup_effect(&record, requested_stage, |_| {
                    called.set(true);
                    Ok(())
                })
                .is_err());
            assert!(!called.get());
        }
        for case in 0..6 {
            let mut foreign = record.clone();
            match case {
                0 => foreign.revision += 1,
                1 => foreign.scope.connection_generation += 1,
                2 => foreign.provenance.network_epoch += 1,
                3 => foreign.dns = vec!["9.9.9.9".parse().unwrap()],
                4 => foreign.stop_stage = if stage == 0 { 10 } else { 0 },
                _ => foreign.pending = None,
            }
            assert!(
                intent
                    .inspect_cleanup_effect(&foreign, stage, |_| -> io::Result<()> {
                        panic!("foreign expected record reached cleanup read")
                    })
                    .is_err(),
                "stage {stage}, case {case}"
            );
        }
    }
}

#[test]
fn cleanup_effect_read_requires_cleanup_mapping_and_never_accepts_forward_intent() {
    // Break: check pending equality alone, or check merely Closing without the
    // precise stage/effect map from the actual CarrierPair stop sequence.
    for stage in 0..=12 {
        let (_, mut store, record) = cleanup_window(stage);
        let mut bad = closing(&record);
        bad.pending = Some(pair::Effect::Network);
        store.compare_exchange(Some(&record), &bad).unwrap();
        let intent = store.record_intent(&bad).unwrap();
        assert!(intent
            .inspect_cleanup_effect(&bad, stage, |_| -> io::Result<()> {
                panic!("forward effect reached cleanup read")
            })
            .is_err());
    }
    let f = fixture();
    let (mut store, _) = WindowsCarrierPairStore::open(f.files, context()).unwrap();
    store.compare_exchange(None, &fresh()).unwrap();
    let (pending, _) = pending_network_record(&fresh());
    store.compare_exchange(Some(&fresh()), &pending).unwrap();
    let intent = store.record_intent(&pending).unwrap();
    assert!(intent
        .inspect_cleanup_effect(&pending, 0, |_| -> io::Result<()> {
            panic!("live publication reached cleanup read")
        })
        .is_err());
}

#[test]
fn cleanup_effect_read_propagates_read_error_and_callback_unwind() {
    // Break: discard an independent reader's failure or manufacture a success
    // result when the callback did not return an authenticated observation.
    let (_, mut store, record) = cleanup_window(9);
    let intent = store.record_intent(&record).unwrap();
    let err = intent
        .inspect_cleanup_effect(&record, 9, |_| {
            Err::<(), _>(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "independent_read_denied",
            ))
        })
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(err.to_string(), "independent_read_denied");
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        intent.inspect_cleanup_effect(&record, 9, |_| -> io::Result<()> {
            panic!("independent_read_unwind")
        })
    }))
    .is_err());
}

#[test]
fn cleanup_effect_read_cannot_mint_from_failed_ack_unreadable_storage_or_new_store() {
    // Break: convert known committed bytes into an original returned ACK or
    // adopt an equal protected record through a reopened owner.
    for fault in [1, 2, 3, 4, 5] {
        let (f, mut store, record) = cleanup_window(8);
        let mut next = closing(&record);
        next.stop_stage = 9;
        next.pending = Some(pair::Effect::NativeEmpty);
        f.disk.0.borrow_mut().fault = fault;
        assert!(store.compare_exchange(Some(&record), &next).is_err());
        assert!(store.record_intent(&next).is_err(), "fault {fault}");
    }
    let (f, mut store, record) = cleanup_window(9);
    let (mut reopened, _) = WindowsCarrierPairStore::open(f.files.clone(), context()).unwrap();
    assert!(reopened.record_intent(&record).is_err());
    f.disk.0.borrow_mut().unreadable = true;
    assert!(store.record_intent(&record).is_err());
    f.disk.0.borrow_mut().unreadable = false;
    // Revocation never reconstitutes a new publication ACK on the reopened store.
    assert!(reopened.record_intent(&record).is_err());
}

#[test]
fn cleanup_effect_read_cannot_mint_after_acknowledged_stage_or_raw_bytes_drift() {
    // Break: mint the previous read window after another protected CAS, or
    // tolerate equal parsed JSON when the exact authenticated bytes changed.
    let (f, mut store, record) = cleanup_window(0);
    let mut next = closing(&record);
    next.stop_stage = 1;
    next.pending = Some(pair::Effect::ReleaseProbes);
    store.compare_exchange(Some(&record), &next).unwrap();
    assert!(store.record_intent(&record).is_err());
    let raw = f
        .disk
        .0
        .borrow()
        .bytes
        .get(&PrivateFile::Pair)
        .unwrap()
        .clone();
    let mut protected: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    protected["data"] = format!("{} ", protected["data"].as_str().unwrap()).into();
    f.disk
        .0
        .borrow_mut()
        .bytes
        .insert(PrivateFile::Pair, serde_json::to_vec(&protected).unwrap());
    assert!(store.record_intent(&next).is_err());
}

#[test]
fn cleanup_effect_read_pin_rechecks_current_protected_bytes_after_mint() {
    // Break: a previously minted native read uses its cached ACK after actual
    // protected storage advances, becomes unreadable, or changes exact bytes.
    let (f, mut store, record) = cleanup_window(0);
    let intent = store.record_intent(&record).unwrap();
    intent.verify_files(&mut f.files.clone()).unwrap();
    let mut next = closing(&record);
    next.stop_stage = 1;
    next.pending = Some(pair::Effect::ReleaseProbes);
    store.compare_exchange(Some(&record), &next).unwrap();
    assert!(intent.verify_files(&mut f.files.clone()).is_err());

    let (f, mut store, record) = cleanup_window(9);
    let intent = store.record_intent(&record).unwrap();
    f.disk.0.borrow_mut().unreadable = true;
    assert!(intent.verify_files(&mut f.files.clone()).is_err());
    f.disk.0.borrow_mut().unreadable = false;
    intent.verify_files(&mut f.files.clone()).unwrap();
    let raw = f.disk.0.borrow().bytes[&PrivateFile::Pair].clone();
    let mut protected: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    protected["data"] = format!("{} ", protected["data"].as_str().unwrap()).into();
    f.disk
        .0
        .borrow_mut()
        .bytes
        .insert(PrivateFile::Pair, serde_json::to_vec(&protected).unwrap());
    assert!(intent.verify_files(&mut f.files.clone()).is_err());
}

#[test]
fn cleanup_effect_read_call_guard_releases_serialization_and_revokes_error_or_unwind() {
    // Break: failed/unwound native inspection resets health and permits a later
    // read, or the outer busy lease is released by a reentrant attempt.
    for unwind in [false, true] {
        let busy = Cell::new(false);
        let revoked = Cell::new(false);
        let (_, mut store, record) = cleanup_window(9);
        let intent = store.record_intent(&record).unwrap();
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> io::Result<()> {
                let _call = PairIntentCall::begin(&busy, &revoked)?;
                intent.inspect_cleanup_effect(&record, 9, |_| {
                    if unwind {
                        panic!("guarded_read_unwind");
                    }
                    Err(io::Error::other("guarded_read_error"))
                })
            }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert!(revoked.get());
        assert!(!busy.get());
        assert!(PairIntentCall::begin(&busy, &revoked).is_err());
        assert!(!busy.get());
    }
    let busy = Cell::new(false);
    let revoked = Cell::new(false);
    let call = PairIntentCall::begin(&busy, &revoked).unwrap();
    assert!(PairIntentCall::begin(&busy, &revoked).is_err());
    assert!(busy.get());
    assert!(revoked.get());
    drop(call);
    assert!(!busy.get());
    assert!(PairIntentCall::begin(&busy, &revoked).is_err());
}

#[test]
fn cleanup_effect_read_call_guard_releases_success_without_revoking_original_pin() {
    // Break: successful read permanently revokes the original Pair pin or
    // leaves busy set, preventing later facts in the same acknowledged stage.
    let busy = Cell::new(false);
    let revoked = Cell::new(false);
    let (_, mut store, record) = cleanup_window(10);
    let intent = store.record_intent(&record).unwrap();
    for _ in 0..2 {
        let mut call = PairIntentCall::begin(&busy, &revoked).unwrap();
        let stage = intent
            .inspect_cleanup_effect(&record, 10, |r| Ok(r.stop_stage))
            .unwrap();
        assert_eq!(stage, 10);
        call.completed = true;
        drop(call);
        assert!(!busy.get());
        assert!(!revoked.get());
    }
}
fn legacy_bytes() -> Vec<u8> {
    let p = crate::member_pair::PairRecord {
        scope: scope(),
        members: [None, None],
        active: None,
        guard: crate::member_guard::Model::empty(scope()).unwrap(),
        pending_guard: None,
        dns: [None, None],
        options: None,
        closing: false,
    };
    serde_json::to_vec(&serde_json::json!({"version":1,"scope":scope(),"payload":p})).unwrap()
}

#[test]
fn protected_strict_payload_dispatch_keeps_legacy_cleanup_separate() {
    assert!(matches!(
        decode_pair_payload(&scope(), &pair_bytes(&fresh())).unwrap(),
        crate::member_carrier_pair::CleanupRecord::Carrier(_)
    ));
    assert!(matches!(
        decode_pair_payload(&scope(), &legacy_bytes()).unwrap(),
        crate::member_carrier_pair::CleanupRecord::Legacy(_)
    ));
}
#[test]
fn protected_fresh_is_from_authenticated_claim_not_empty_json() {
    let (_, f) = files();
    assert!(WindowsCarrierPairStore::open(f, context()).is_err());
    let f = fixture();
    let (mut store, saved) = WindowsCarrierPairStore::open(f.files.clone(), context()).unwrap();
    assert!(saved.is_none());
    store.compare_exchange(None, &fresh()).unwrap();
    assert_eq!(store.load(&scope()).unwrap().unwrap().revision, 1);
    assert_eq!(f.disk.0.borrow().writes, 1);
    let (mut reopened, saved) = WindowsCarrierPairStore::open(f.files, context()).unwrap();
    assert!(matches!(
        saved,
        Some(crate::member_carrier_pair::CleanupRecord::Carrier(_))
    ));
    assert!(reopened.compare_exchange(Some(&fresh()), &fresh()).is_err());
    reopened
        .compare_exchange(Some(&fresh()), &closing(&fresh()))
        .unwrap();
    assert_eq!(
        reopened.load(&scope()).unwrap().unwrap().phase,
        Phase::Closing
    );
}
#[test]
fn protected_lost_ack_never_resumes_and_cleanup_reads_exact_committed_record() {
    let f = fixture();
    let (mut store, _) = WindowsCarrierPairStore::open(f.files.clone(), context()).unwrap();
    f.disk.0.borrow_mut().fault = 2;
    assert!(store.compare_exchange(None, &fresh()).is_err());
    assert!(!f
        .files
        .clone()
        .native_carrier_access(&scope())
        .unwrap()
        .is_fresh());
    let actual = store.load(&scope()).unwrap().unwrap();
    let mut live = actual.clone();
    live.revision += 1;
    assert!(store.compare_exchange(Some(&actual), &live).is_err());
    store
        .compare_exchange(Some(&actual), &closing(&actual))
        .unwrap();
    assert_eq!(store.load(&scope()).unwrap().unwrap().phase, Phase::Closing);
}

#[test]
fn protected_original_ack_receipt_is_retained_across_later_fallible_native_pin_checks() {
    let f = fixture();
    let (mut store, _) = WindowsCarrierPairStore::open(f.files, context()).unwrap();
    store.compare_exchange(None, &fresh()).unwrap();
    // Native specialization can fail its independent RuntimeRead AFTER this
    // return. The original typed ACK must already remain retained, not recreated
    // later from independently equal protected bytes.
    store.restrict_to_cleanup();
    let receipt = store
        .receipt
        .as_ref()
        .expect("original publication ACK retained");
    assert!(matches!(receipt.ack, PublicationAck::Acknowledged));
    assert_eq!(receipt.desired.phase, Phase::Fresh);
    assert_eq!(receipt.desired.revision, 1);
    assert_eq!(store.load(&scope()).unwrap().unwrap().phase, Phase::Fresh);
}
#[test]
fn protected_exact_desired_readback_never_allows_rollback_to_before_after_lost_ack() {
    let f = fixture();
    let (mut store, _) = WindowsCarrierPairStore::open(f.files.clone(), context()).unwrap();
    f.disk.0.borrow_mut().fault = 2;
    assert!(store.compare_exchange(None, &fresh()).is_err());
    assert_eq!(store.load(&scope()).unwrap().unwrap().revision, 1);
    f.disk.0.borrow_mut().bytes.remove(&PrivateFile::Pair);
    assert!(
        store.load(&scope()).is_err(),
        "confirmed durable record cannot disappear into fresh absence"
    );
}

#[test]
fn protected_unknown_versions_fields_duplicates_and_foreign_envelopes_never_dispatch_as_legacy() {
    for case in 0..9 {
        let mut value: serde_json::Value = serde_json::from_slice(&pair_bytes(&fresh())).unwrap();
        match case {
            0 => value["version"] = 2.into(),
            1 => value["payload"]["version"] = 99.into(),
            2 => value["payload"]["version"] = 1.into(),
            3 => value["extra"] = true.into(),
            4 => value["payload"]["extra"] = true.into(),
            5 => value["scope"]["connection_generation"] = 3.into(),
            6 => value["payload"]["scope"]["connection_generation"] = 3.into(),
            7 => value["payload"]["version"] = serde_json::Value::Null,
            _ => value["payload"]["revision"] = 0.into(),
        }
        assert!(
            decode_pair_payload(&scope(), &serde_json::to_vec(&value).unwrap()).is_err(),
            "case {case}"
        );
    }
    let bytes = String::from_utf8(pair_bytes(&fresh())).unwrap();
    let duplicated = bytes.replacen("\"revision\":1", "\"revision\":1,\"revision\":2", 1);
    assert!(decode_pair_payload(&scope(), duplicated.as_bytes()).is_err());
    let duplicated = bytes.replacen("\"version\":2", "\"version\":99,\"version\":2", 1);
    assert!(decode_pair_payload(&scope(), duplicated.as_bytes()).is_err());
    assert!(decode_pair_payload(&scope(), &vec![b' '; 65_536 + 1025]).is_err());
}
#[test]
fn protected_every_publication_failure_keeps_original_receipt_and_claim_cleanup_only() {
    for fault in 1..=5 {
        let f = fixture();
        let (mut store, _) = WindowsCarrierPairStore::open(f.files.clone(), context()).unwrap();
        f.disk.0.borrow_mut().fault = fault;
        assert!(
            store.compare_exchange(None, &fresh()).is_err(),
            "fault {fault}"
        );
        assert!(store.receipt.is_some());
        assert!(!f
            .files
            .clone()
            .native_carrier_access(&scope())
            .unwrap()
            .is_fresh());
        f.disk.0.borrow_mut().unreadable = false;
        let actual = store.load(&scope());
        if fault == 5 {
            assert!(
                actual.is_err(),
                "same JSON but nonexact bytes cannot classify desired"
            );
        } else if matches!(fault, 2 | 4) {
            let record = actual.unwrap().unwrap();
            let mut live = record.clone();
            live.revision += 1;
            assert!(store.compare_exchange(Some(&record), &live).is_err());
            store
                .compare_exchange(Some(&record), &closing(&record))
                .unwrap();
        } else {
            assert!(actual.unwrap().is_none());
            assert!(
                store.compare_exchange(None, &fresh()).is_err(),
                "cannot reinitialize fresh after failed ACK"
            );
        }
    }
}
#[test]
fn protected_cleanup_cas_partial_or_lost_ack_is_retryable_only_from_exact_known_state() {
    for fault in 1..=5 {
        let f = fixture();
        let (mut store, _) = WindowsCarrierPairStore::open(f.files.clone(), context()).unwrap();
        store.compare_exchange(None, &fresh()).unwrap();
        let (mut recovered, _) = WindowsCarrierPairStore::open(f.files.clone(), context()).unwrap();
        let desired = closing(&fresh());
        f.disk.0.borrow_mut().fault = fault;
        assert!(recovered
            .compare_exchange(Some(&fresh()), &desired)
            .is_err());
        f.disk.0.borrow_mut().unreadable = false;
        if fault == 5 {
            assert!(recovered.load(&scope()).is_err());
            continue;
        }
        let current = recovered.load(&scope()).unwrap().unwrap();
        let next = closing(&current);
        recovered.compare_exchange(Some(&current), &next).unwrap();
        assert_eq!(
            recovered.load(&scope()).unwrap().unwrap().phase,
            Phase::Closing
        );
        assert_eq!(
            recovered.load(&scope()).unwrap().unwrap().revision,
            if matches!(fault, 2 | 4) { 3 } else { 2 }
        );
    }
}
#[test]
fn protected_foreign_context_scope_boot_runtime_and_epoch_never_gain_write_authority() {
    for case in 0..5 {
        let f = fixture();
        let mut c = context();
        match case {
            0 => c.intent.scope.connection_generation += 1,
            1 => c.provenance.boot_id = [8; 16],
            2 => c.provenance.runtime.manifest_sha256 = "b".repeat(64),
            3 => c.provenance.network_epoch += 1,
            _ => c.provenance.runtime.runtime_version = "9.0.0".into(),
        }
        assert!(
            WindowsCarrierPairStore::open(f.files.clone(), c).is_err(),
            "case {case}"
        );
        assert_eq!(f.disk.0.borrow().writes, 0);
    }
}
#[test]
fn protected_revision_replay_wrong_expected_and_terminal_reopen_are_nonmutating() {
    let f = fixture();
    let (mut store, _) = WindowsCarrierPairStore::open(f.files.clone(), context()).unwrap();
    store.compare_exchange(None, &fresh()).unwrap();
    assert!(store.compare_exchange(None, &closing(&fresh())).is_err());
    let before = f.disk.0.borrow().writes;
    assert!(store.compare_exchange(Some(&fresh()), &fresh()).is_err());
    assert_eq!(f.disk.0.borrow().writes, before);
    let mut current = closing(&fresh());
    store.compare_exchange(Some(&fresh()), &current).unwrap();
    for stage in 1..=12 {
        let mut next = current.clone();
        next.revision += 1;
        next.stop_stage = stage;
        store.compare_exchange(Some(&current), &next).unwrap();
        current = next;
    }
    let mut terminal = current.clone();
    terminal.revision += 1;
    terminal.phase = Phase::Stopped;
    store.compare_exchange(Some(&current), &terminal).unwrap();
    assert!(require_terminal_pair(&scope(), &encode_carrier_payload(&terminal).unwrap()).is_ok());
    assert!(require_terminal_pair(&scope(), &pair_bytes(&fresh())).is_err());
    let (mut reopened, saved) = WindowsCarrierPairStore::open(f.files.clone(), context()).unwrap();
    assert!(matches!(saved, Some(CleanupRecord::Carrier(_))));
    let mut forbidden = terminal.clone();
    forbidden.revision += 1;
    forbidden.phase = Phase::Fresh;
    assert!(reopened
        .compare_exchange(Some(&terminal), &forbidden)
        .is_err());
    // PairJournal never calls complete. Claim is still active after terminal:
    // main must independently gate actual native EMPTY and Session completion.
    assert_eq!(
        f.files.clone().scopes(RuntimeSlot::Stable).unwrap(),
        vec![scope()]
    );
}
#[test]
fn protected_preloaded_legacy_is_cleanup_dispatch_only_and_never_a_carrier_journal() {
    let f = fixture();
    #[cfg(windows)]
    use super::super::member_session::WindowsPairStore;
    use crate::member_pair::PairStore;
    #[cfg(not(windows))]
    use crate::member_session::WindowsPairStore;
    let legacy: crate::member_pair::PairRecord = envelope(&scope(), &legacy_bytes()).unwrap();
    let (mut legacy_store, _) =
        WindowsPairStore::open(f.files.clone(), scope(), RecordKind::Pair).unwrap();
    legacy_store.save(&legacy).unwrap();
    let (mut store, saved) = WindowsCarrierPairStore::open(f.files.clone(), context()).unwrap();
    assert!(matches!(saved, Some(CleanupRecord::Legacy(_))));
    assert!(store.load(&scope()).is_err());
    assert!(store.compare_exchange(None, &fresh()).is_err());
    assert_eq!(f.disk.0.borrow().writes, 1);
    assert!(require_terminal_pair(&scope(), &legacy_bytes()).is_ok());
}
#[test]
fn protected_drop_does_not_claim_complete_delete_or_publish() {
    let f = fixture();
    let (mut store, _) = WindowsCarrierPairStore::open(f.files.clone(), context()).unwrap();
    store.compare_exchange(None, &fresh()).unwrap();
    let before = f.disk.0.borrow().bytes.clone();
    let writes = f.disk.0.borrow().writes;
    drop(store);
    assert_eq!(f.disk.0.borrow().bytes, before);
    assert_eq!(f.disk.0.borrow().writes, writes);
    assert_eq!(
        f.files.clone().scopes(RuntimeSlot::Stable).unwrap(),
        vec![scope()]
    );
}
#[test]
fn protected_retained_epoch_is_cleanup_only_not_current_live_freshness() {
    use nelomai_client_tunnel::redundancy::{driver::SessionStore, session::SessionState, Slot};
    let f = fixture();
    let (mut store, _) = WindowsCarrierPairStore::open(f.files.clone(), context()).unwrap();
    store.compare_exchange(None, &fresh()).unwrap();
    let mut s = SessionState::new(scope(), Slot::A, 1, 1)
        .unwrap()
        .snapshot();
    s.network_epoch = 2;
    let (mut session, _) =
        WindowsSessionStore::open(f.files.clone(), scope(), RecordKind::Session).unwrap();
    session.save(&s).unwrap();
    assert!(
        store.load(&scope()).is_err(),
        "old live store cannot ignore new native epoch"
    );
    let (mut recovered, _) = WindowsCarrierPairStore::open(f.files.clone(), context()).unwrap();
    recovered
        .compare_exchange(Some(&fresh()), &closing(&fresh()))
        .unwrap();
    assert_eq!(
        recovered
            .load(&scope())
            .unwrap()
            .unwrap()
            .provenance
            .network_epoch,
        1
    );
    let mut current_context = context();
    current_context.provenance.network_epoch = 2;
    assert!(
        WindowsCarrierPairStore::open(f.files, current_context).is_err(),
        "cannot migrate retained ownership to new epoch"
    );
}

fn pending_network_record(before: &Record) -> (Record, crate::member_pair::DnsRecord) {
    use crate::member_carrier_pair::{Effect, NetworkSnapshot, NetworkState, Operation};
    let mut r = before.clone();
    r.revision += 1;
    r.phase = Phase::Starting;
    r.addresses = context().intent.addresses;
    r.options = Some(nelomai_client_tunnel::DesktopTunnelOptions::default());
    r.operation = Some(Operation::Start(nelomai_client_tunnel::redundancy::Slot::A));
    r.carrier = Some(crate::member_owner::InterfaceProof {
        index: 13,
        luid: 12,
        guid: [1; 16],
    });
    r.pending = Some(Effect::Network);
    let baseline = crate::member_dns::Snapshot {
        interface: crate::member_dns::OwnedInterface {
            scope: scope(),
            guid: [1; 16],
            luid: 12,
            index: 13,
        },
        settings: crate::member_dns::Settings {
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
    let target = baseline
        .with_servers(&["8.8.8.8".parse().unwrap()])
        .unwrap();
    r.dns = vec!["8.8.8.8".parse().unwrap()];
    r.network = Some(NetworkState {
        baseline: NetworkSnapshot {
            routes: vec![],
            dns: Some(baseline.clone()),
        },
        current: NetworkSnapshot {
            routes: vec![],
            dns: Some(baseline.clone()),
        },
        pending: Some(NetworkSnapshot {
            routes: vec![],
            dns: Some(target),
        }),
    });
    (
        r,
        crate::member_pair::DnsRecord {
            baseline: baseline.clone(),
            current: baseline,
            pending: None,
        },
    )
}
#[test]
fn original_forward_entry_requires_exact_current_pending_operation_before_supervision() {
    // Break: the supervisor enters from a request/equal reopen, or Closing is
    // accepted through the live channel instead of its exact cleanup stage.
    let f = fixture();
    let (mut store, _) = WindowsCarrierPairStore::open(f.files.clone(), context()).unwrap();
    store.compare_exchange(None, &fresh()).unwrap();
    let (pending, _) = pending_network_record(&fresh());
    store.compare_exchange(Some(&fresh()), &pending).unwrap();
    let intent = store.record_intent(&pending).unwrap();
    let writes = f.disk.0.borrow().writes;
    intent
        .forward_entry(&pending, pair::Effect::Network)
        .unwrap();
    assert_eq!(f.disk.0.borrow().writes, writes, "entry is read-only");
    assert!(intent
        .forward_entry(&pending, pair::Effect::CarrierReady)
        .is_err());
    let mut foreign = pending.clone();
    foreign.revision += 1;
    assert!(intent
        .forward_entry(&foreign, pair::Effect::Network)
        .is_err());
    for case in 0..4 {
        let mut bad = pending.clone();
        match case {
            0 => {
                bad.phase = Phase::Closing;
                bad.active = None;
                bad.operation = None;
            }
            1 => bad.operation = None,
            2 => bad.pending = None,
            _ => bad.stop_stage = 1,
        }
        let comparison = RecordIntent {
            origin: std::rc::Rc::new(()),
            raw: encode_carrier_payload(&bad).unwrap(),
            record: bad.clone(),
        };
        assert!(
            comparison
                .forward_entry(&bad, pair::Effect::Network)
                .is_err(),
            "case {case}"
        );
    }
    let (mut reopened, _) = WindowsCarrierPairStore::open(f.files, context()).unwrap();
    assert!(reopened.record_intent(&pending).is_err());
}

#[test]
fn dns_subjournal_is_covered_by_acknowledged_whole_pair_intent_without_revision_writes() {
    let f = fixture();
    let (mut store, _) = WindowsCarrierPairStore::open(f.files.clone(), context()).unwrap();
    store.compare_exchange(None, &fresh()).unwrap();
    let (pending, initial) = pending_network_record(&fresh());
    store.compare_exchange(Some(&fresh()), &pending).unwrap();
    let span = store.network_intent(&pending).unwrap();
    let before = f.disk.0.borrow().bytes.clone();
    let writes = f.disk.0.borrow().writes;
    span.dns_transition(false, None, Some(&initial), None)
        .unwrap();
    let target = pending
        .network
        .as_ref()
        .unwrap()
        .pending
        .as_ref()
        .unwrap()
        .dns
        .clone()
        .unwrap();
    let mut preparing = initial.clone();
    preparing.pending = Some(target.clone());
    span.dns_transition(false, Some(&initial), Some(&preparing), None)
        .unwrap();
    let mut applied = preparing.clone();
    applied.current = target.clone();
    applied.pending = None;
    span.dns_transition(false, Some(&preparing), Some(&applied), Some(&target))
        .unwrap();
    assert_eq!(f.disk.0.borrow().bytes, before);
    assert_eq!(f.disk.0.borrow().writes, writes);
    assert_eq!(
        store.load(&scope()).unwrap().unwrap().revision,
        pending.revision
    );
}

#[test]
fn network_intent_read_requires_exact_acknowledged_current_whole_record() {
    let f = fixture();
    let (mut store, _) = WindowsCarrierPairStore::open(f.files.clone(), context()).unwrap();
    store.compare_exchange(None, &fresh()).unwrap();
    let (pending, _) = pending_network_record(&fresh());
    store.compare_exchange(Some(&fresh()), &pending).unwrap();
    let span = store.network_intent(&pending).unwrap();
    let called = std::cell::Cell::new(false);
    assert_eq!(
        span.inspect_record(&pending, |actual| {
            called.set(true);
            Ok(actual.revision)
        })
        .unwrap(),
        pending.revision
    );
    assert!(called.get());
    let mut changed = pending.clone();
    changed.revision += 1;
    called.set(false);
    assert!(span
        .inspect_record(&changed, |_| {
            called.set(true);
            Ok(())
        })
        .is_err());
    assert!(!called.get());
    let mut corrupted = span;
    corrupted.raw.push(0);
    assert!(corrupted
        .inspect_record(&pending, |_| {
            called.set(true);
            Ok(())
        })
        .is_err());
    assert!(!called.get());
}
#[test]
fn whole_operation_read_requires_original_publication_ack_and_exact_pending_effect() {
    let f = fixture();
    let (mut store, _) = WindowsCarrierPairStore::open(f.files.clone(), context()).unwrap();
    store.compare_exchange(None, &fresh()).unwrap();
    let (pending, _) = pending_network_record(&fresh());
    store.compare_exchange(Some(&fresh()), &pending).unwrap();
    let before = f.disk.0.borrow().bytes.clone();
    let writes = f.disk.0.borrow().writes;
    let intent = store.record_intent(&pending).unwrap();
    intent.effect(&pending, pair::Effect::Network).unwrap();
    assert!(intent.effect(&pending, pair::Effect::CarrierClose).is_err());
    assert!(intent
        .effect(
            &pending,
            pair::Effect::HoldProbe(nelomai_client_tunnel::redundancy::Slot::B)
        )
        .is_err());
    let mut foreign = pending.clone();
    foreign.revision += 1;
    assert!(intent.effect(&foreign, pair::Effect::Network).is_err());
    assert_eq!(f.disk.0.borrow().bytes, before);
    assert_eq!(f.disk.0.borrow().writes, writes);
    let (mut reopened, _) = WindowsCarrierPairStore::open(f.files, context()).unwrap();
    assert!(reopened.record_intent(&pending).is_err());
}

#[test]
fn bootstrap_whole_call_requires_same_store_original_not_equal_published_bytes() {
    let first = fixture();
    let other = fixture();
    let (mut actual, _) = WindowsCarrierPairStore::open(first.files.clone(), context()).unwrap();
    let (mut equal, _) = WindowsCarrierPairStore::open(other.files.clone(), context()).unwrap();
    for store in [&mut actual, &mut equal] {
        store.compare_exchange(None, &fresh()).unwrap();
    }
    let (pending, _) = pending_network_record(&fresh());
    for store in [&mut actual, &mut equal] {
        store.compare_exchange(Some(&fresh()), &pending).unwrap();
    }
    let original = actual.record_intent(&pending).unwrap();
    actual.verify_original_intent(&original, &pending).unwrap();
    let writes = other.disk.0.borrow().writes;
    assert!(
        equal.verify_original_intent(&original, &pending).is_err(),
        "equal independently acknowledged bytes are not SAME originating store"
    );
    assert_eq!(other.disk.0.borrow().writes, writes);
}
#[test]
fn whole_operation_read_never_adopts_committed_bytes_after_lost_ack() {
    for fault in [1, 2, 3, 4, 5] {
        let f = fixture();
        let (mut store, _) = WindowsCarrierPairStore::open(f.files.clone(), context()).unwrap();
        store.compare_exchange(None, &fresh()).unwrap();
        let (pending, _) = pending_network_record(&fresh());
        f.disk.0.borrow_mut().fault = fault;
        assert!(store.compare_exchange(Some(&fresh()), &pending).is_err());
        assert!(store.record_intent(&pending).is_err(), "{fault}");
    }
}
#[test]
fn master_dns_intent_rejects_wrong_phase_metadata_target_ack_and_live_removal() {
    let f = fixture();
    let (mut store, _) = WindowsCarrierPairStore::open(f.files, context()).unwrap();
    store.compare_exchange(None, &fresh()).unwrap();
    assert!(store.network_intent(&fresh()).is_err());
    let (pending, initial) = pending_network_record(&fresh());
    store.compare_exchange(Some(&fresh()), &pending).unwrap();
    let span = store.network_intent(&pending).unwrap();
    let target = pending
        .network
        .as_ref()
        .unwrap()
        .pending
        .as_ref()
        .unwrap()
        .dns
        .clone()
        .unwrap();
    let mut preparing = initial.clone();
    preparing.pending = Some(target.clone());
    let mut applied = preparing.clone();
    applied.current = target.clone();
    applied.pending = None;
    assert!(span
        .dns_transition(false, Some(&preparing), Some(&applied), None)
        .is_err());
    assert!(span
        .dns_transition(
            false,
            Some(&preparing),
            Some(&applied),
            Some(&initial.current)
        )
        .is_err());
    assert!(span
        .dns_transition(false, Some(&initial), None, Some(&initial.current))
        .is_err());
    assert!(span
        .dns_transition(true, None, Some(&initial), None)
        .is_err());
    for case in 0..4 {
        let mut bad = preparing.clone();
        match case {
            0 => bad.baseline.interface.luid += 1,
            1 => bad.pending.as_mut().unwrap().settings.name_server = Some("9.9.9.9".into()),
            2 => bad.pending.as_mut().unwrap().settings.flags = 2,
            _ => bad.current.interface.guid = [8; 16],
        }
        assert!(
            span.dns_transition(false, Some(&initial), Some(&bad), None)
                .is_err(),
            "{case}"
        );
    }
    let mut bad_span = NetworkIntent {
        raw: span.raw.clone(),
        record: span.record.clone(),
    };
    bad_span.record.revision += 1;
    assert!(bad_span
        .dns_transition(false, None, Some(&initial), None)
        .is_err());
}
#[test]
fn whole_pair_ack_loss_or_equal_reopen_never_mints_a_dns_intent() {
    let f = fixture();
    let (mut store, _) = WindowsCarrierPairStore::open(f.files.clone(), context()).unwrap();
    store.compare_exchange(None, &fresh()).unwrap();
    let (pending, _) = pending_network_record(&fresh());
    f.disk.0.borrow_mut().fault = 2;
    assert!(store.compare_exchange(Some(&fresh()), &pending).is_err());
    assert!(store.load(&scope()).unwrap().unwrap() == pending);
    assert!(store.network_intent(&pending).is_err());
    let (mut reopened, _) = WindowsCarrierPairStore::open(f.files, context()).unwrap();
    assert!(reopened.network_intent(&pending).is_err());
}
#[test]
fn cleanup_dns_span_restores_only_exact_baseline_then_accepts_acknowledged_retirement() {
    let f = fixture();
    let (mut store, _) = WindowsCarrierPairStore::open(f.files, context()).unwrap();
    store.compare_exchange(None, &fresh()).unwrap();
    let (pending, initial) = pending_network_record(&fresh());
    store.compare_exchange(Some(&fresh()), &pending).unwrap();
    let target = pending
        .network
        .as_ref()
        .unwrap()
        .pending
        .as_ref()
        .unwrap()
        .dns
        .clone()
        .unwrap();
    let mut current = closing(&pending);
    current.pending = Some(pair::Effect::RestoreNetwork);
    current.network.as_mut().unwrap().current.dns = Some(target.clone());
    current.network.as_mut().unwrap().pending =
        Some(current.network.as_ref().unwrap().baseline.clone());
    store.compare_exchange(Some(&pending), &current).unwrap();
    for stage in 1..=2 {
        let mut next = current.clone();
        next.revision += 1;
        next.stop_stage = stage;
        store.compare_exchange(Some(&current), &next).unwrap();
        current = next;
    }
    let span = store.network_intent(&current).unwrap();
    let mut old = initial.clone();
    old.current = target;
    let mut restoring = old.clone();
    restoring.pending = Some(initial.baseline.clone());
    span.dns_transition(true, Some(&old), Some(&restoring), None)
        .unwrap();
    span.dns_transition(
        true,
        Some(&restoring),
        Some(&initial),
        Some(&initial.baseline),
    )
    .unwrap();
    span.dns_transition(
        true,
        Some(&initial),
        Some(&initial),
        Some(&initial.baseline),
    )
    .unwrap();
    assert!(span
        .dns_transition(true, Some(&initial), Some(&initial), None)
        .is_err());
    assert!(span
        .dns_transition(
            false,
            Some(&initial),
            Some(&initial),
            Some(&initial.baseline)
        )
        .is_err());
    assert!(span
        .dns_transition(true, Some(&old), Some(&old), Some(&initial.baseline))
        .is_err());
    span.dns_transition(true, Some(&initial), None, Some(&initial.baseline))
        .unwrap();
    assert!(span
        .dns_transition(true, Some(&old), None, Some(&initial.baseline))
        .is_err());
}
