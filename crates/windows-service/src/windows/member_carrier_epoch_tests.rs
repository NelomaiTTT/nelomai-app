use super::super::{EngineIdentity, PrivateFile, PrivateRecords, SessionFileIo, SessionFiles};
use super::*;
use nelomai_client_tunnel::redundancy::{
    session::{SessionPhase, SessionState},
    Slot,
};
use nelomai_contracts::RuntimeSlot;
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

#[derive(Clone, Default)]
struct Disk(Rc<RefCell<DiskState>>);
#[derive(Default)]
struct DiskState {
    bytes: BTreeMap<PrivateFile, Vec<u8>>,
    lost_ack: bool,
    fail_after: bool,
    after: Option<Box<dyn FnOnce()>>,
    lost_file: Option<PrivateFile>,
    false_file: Option<PrivateFile>,
    reads: BTreeMap<PrivateFile, usize>,
    transactions: usize,
    fail_read: Option<PrivateFile>,
}
impl PrivateRecords for Disk {
    fn read(&mut self, file: PrivateFile) -> io::Result<Option<Vec<u8>>> {
        let mut disk = self.0.borrow_mut();
        *disk.reads.entry(file).or_default() += 1;
        if disk.fail_read == Some(file) {
            return Err(conflict());
        }
        Ok(disk.bytes.get(&file).cloned())
    }
    fn compare_exchange(
        &mut self,
        file: PrivateFile,
        expected: Option<&[u8]>,
        desired: &[u8],
    ) -> io::Result<()> {
        let mut d = self.0.borrow_mut();
        if d.bytes.get(&file).map(Vec::as_slice) != expected {
            return Err(conflict());
        }
        if d.false_file == Some(file) {
            d.false_file = None;
            return Ok(());
        }
        d.bytes.insert(file, desired.to_vec());
        if (file == PrivateFile::Session && d.lost_ack) || d.lost_file == Some(file) {
            d.lost_ack = false;
            d.lost_file = None;
            return Err(conflict());
        }
        Ok(())
    }
}
impl SessionFileIo for Disk {
    fn transaction<T>(
        &mut self,
        f: impl FnOnce(&mut dyn PrivateRecords) -> io::Result<T>,
    ) -> io::Result<T> {
        self.0.borrow_mut().transactions += 1;
        let result = f(self);
        let after = self.0.borrow_mut().after.take();
        if let Some(after) = after {
            after();
        }
        if self.0.borrow_mut().fail_after {
            self.0.borrow_mut().fail_after = false;
            return Err(conflict());
        }
        result
    }
}
fn scope() -> SessionScope {
    SessionScope {
        runtime: RuntimeSlot::Stable,
        runtime_generation: 1,
        connection_generation: 2,
        session_id: "11111111-1111-4111-8111-111111111111".into(),
    }
}
fn files(d: &Disk) -> ProtectedSessionFiles<Disk> {
    ProtectedSessionFiles::new(
        d.clone(),
        EngineIdentity {
            slot: RuntimeSlot::Stable,
            runtime_version: "1.0.0".into(),
            runtime_contract_version: 1,
            container_version: "1.0.0".into(),
            manifest_sha256: "a".repeat(64),
        },
        [7; 16],
    )
    .unwrap()
}
fn initial() -> SessionSnapshot {
    SessionState::new(scope(), Slot::A, 1, 1)
        .unwrap()
        .snapshot()
}
fn payload(s: &SessionSnapshot) -> Vec<u8> {
    serde_json::to_vec(&super::super::Envelope {
        version: 1,
        scope: s.scope.clone(),
        payload: s,
    })
    .unwrap()
}
fn write(
    f: &mut ProtectedSessionFiles<Disk>,
    old: Option<&SessionSnapshot>,
    next: &SessionSnapshot,
) -> io::Result<()> {
    let old = old.map(payload);
    f.compare_exchange(
        &next.scope,
        RecordKind::Session,
        old.as_deref(),
        &payload(next),
    )
}

#[test]
fn actual_claim_and_starting_running_epoch_two_three_keep_birth_fixed() {
    let d = Disk::default();
    let mut f = files(&d);
    assert!(f.session_ack_root(&scope()).is_err());
    f.claim(&scope()).unwrap();
    let root = f.session_ack_root(&scope()).unwrap();
    // Missing Session is never epoch1 ACK and failure is deliberately sticky.
    assert!(root.inspect(|_| Ok(())).is_err());
    // A separate original claim demonstrates the successful trace.
    let d = Disk::default();
    let mut f = files(&d);
    f.claim(&scope()).unwrap();
    let root = f.session_ack_root(&scope()).unwrap();
    let mut before = initial();
    write(&mut f, None, &before).unwrap();
    let first = root
        .inspect(|facts| {
            assert_eq!(facts.birth.network_epoch(), 1);
            assert_eq!(facts.execution.value(), 1);
            Ok(facts.ack.clone())
        })
        .unwrap();
    for (epoch, phase) in [
        (1, SessionPhase::Running),
        (2, SessionPhase::Running),
        (3, SessionPhase::Running),
    ] {
        let mut next = before.clone();
        next.phase = phase;
        next.network_epoch = epoch;
        next.local_revision += 1;
        next.installed[0] = true;
        next.committed[0] = true;
        write(&mut f, Some(&before), &next).unwrap();
        root.inspect(|facts| {
            assert_eq!(facts.birth.network_epoch(), 1);
            assert_eq!(facts.birth.scope(), &scope());
            assert_eq!(facts.execution.value(), epoch);
            assert_eq!(facts.session, &next);
            assert!(!facts.ack.same_original(&first));
            Ok(())
        })
        .unwrap();
        before = next;
    }
    assert_eq!(root.acknowledgements().unwrap().len(), 4);
    assert!(root.matches_origin(&f));
    assert!(f.session_ack_root(&scope()).unwrap().matches_origin(&f));
}

#[test]
fn equal_backend_data_and_recovery_alias_cannot_mint_original_ack() {
    let d = Disk::default();
    let mut f = files(&d);
    f.claim(&scope()).unwrap();
    let root = f.session_ack_root(&scope()).unwrap();
    write(&mut f, None, &initial()).unwrap();
    assert!(root.matches_origin(&f));
    assert!(!root.matches_origin(&files(&d)));
    assert!(files(&d).session_ack_root(&scope()).is_err());
    let (view, _) = f.recovery_view(RuntimeSlot::Stable).unwrap().unwrap();
    assert!(view.session_ack_root(&scope()).is_err());
}

#[test]
fn actual_cas_ack_is_retained_before_outer_error_and_callback() {
    let d = Disk::default();
    let mut f = files(&d);
    f.claim(&scope()).unwrap();
    let root = f.session_ack_root(&scope()).unwrap();
    let observed = Rc::new(RefCell::new(0));
    let out = observed.clone();
    let original = root.clone();
    d.0.borrow_mut().after = Some(Box::new(move || {
        *out.borrow_mut() = original.acknowledgements().unwrap().len()
    }));
    d.0.borrow_mut().fail_after = true;
    assert!(write(&mut f, None, &initial()).is_err());
    assert_eq!(*observed.borrow(), 1);
    assert_eq!(root.acknowledgements().unwrap().len(), 1);
    assert!(root.inspect(|_| Ok(())).is_err());
}

#[test]
fn lost_actual_session_cas_ack_never_imports_matching_private_bytes() {
    let d = Disk::default();
    let mut f = files(&d);
    f.claim(&scope()).unwrap();
    let root = f.session_ack_root(&scope()).unwrap();
    d.0.borrow_mut().lost_ack = true;
    assert!(write(&mut f, None, &initial()).is_err());
    assert!(d.0.borrow().bytes.contains_key(&PrivateFile::Session));
    assert!(root.acknowledgements().unwrap().is_empty());
    assert!(root.inspect(|_| Ok(())).is_err());
    assert!(f.session_ack_root(&scope()).is_err());
}

#[test]
fn current_replacement_missing_session_and_callback_drift_are_sticky() {
    for kind in 0..3 {
        let d = Disk::default();
        let mut f = files(&d);
        f.claim(&scope()).unwrap();
        let root = f.session_ack_root(&scope()).unwrap();
        write(&mut f, None, &initial()).unwrap();
        let raw =
            d.0.borrow()
                .bytes
                .get(&PrivateFile::Session)
                .unwrap()
                .clone();
        if kind == 0 {
            d.0.borrow_mut().bytes.remove(&PrivateFile::Session);
        }
        if kind == 1 {
            let mut replaced: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            let mut session = initial();
            session.local_revision += 1;
            replaced["data"] =
                serde_json::Value::String(String::from_utf8(payload(&session)).unwrap());
            d.0.borrow_mut()
                .bytes
                .insert(PrivateFile::Session, serde_json::to_vec(&replaced).unwrap());
        }
        assert!(root
            .inspect(|_| {
                if kind == 2 {
                    d.0.borrow_mut().bytes.remove(&PrivateFile::Session);
                }
                Ok(())
            })
            .is_err());
        d.0.borrow_mut().bytes.insert(PrivateFile::Session, raw);
        assert!(root.inspect(|_| Ok(())).is_err());
        assert_eq!(root.acknowledgements().unwrap().len(), 1);
    }
}

#[test]
fn caught_read_or_session_write_reentry_revokes_original_without_deadlock() {
    for writing in [false, true] {
        let d = Disk::default();
        let mut f = files(&d);
        f.claim(&scope()).unwrap();
        let root = f.session_ack_root(&scope()).unwrap();
        write(&mut f, None, &initial()).unwrap();
        assert!(root
            .inspect(|_| {
                if writing {
                    let mut next = initial();
                    next.phase = SessionPhase::Running;
                    next.installed[0] = true;
                    next.committed[0] = true;
                    assert!(write(&mut f, Some(&initial()), &next).is_err());
                } else {
                    assert!(root.inspect(|_| Ok(())).is_err());
                }
                Ok(())
            })
            .is_err());
        assert!(root.inspect(|_| Ok(())).is_err());
        assert_eq!(root.acknowledgements().unwrap().len(), 1);
    }
}

#[test]
fn unwind_does_not_refresh_or_manufacture_epoch() {
    let d = Disk::default();
    let mut f = files(&d);
    f.claim(&scope()).unwrap();
    let root = f.session_ack_root(&scope()).unwrap();
    write(&mut f, None, &initial()).unwrap();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || root.inspect::<()>(|_| panic!("callback"))
    ))
    .is_err());
    assert!(root.inspect(|_| Ok(())).is_err());
}

#[test]
fn revoked_root_getter_cannot_refresh_from_restored_equal_session_bytes() {
    let d = Disk::default();
    let mut f = files(&d);
    f.claim(&scope()).unwrap();
    let root = f.session_ack_root(&scope()).unwrap();
    write(&mut f, None, &initial()).unwrap();
    let raw =
        d.0.borrow_mut()
            .bytes
            .remove(&PrivateFile::Session)
            .unwrap();
    assert!(root.inspect(|_| Ok(())).is_err());
    d.0.borrow_mut().bytes.insert(PrivateFile::Session, raw);
    assert!(f.session_ack_root(&scope()).is_err());
    assert!(root.inspect(|_| Ok(())).is_err());
}

#[test]
fn completed_claim_and_next_claim_have_distinct_original_histories() {
    let d = Disk::default();
    let mut f = files(&d);
    f.claim(&scope()).unwrap();
    let old = f.session_ack_root(&scope()).unwrap();
    let starting = initial();
    write(&mut f, None, &starting).unwrap();
    let old_ack = old.inspect(|facts| Ok(facts.ack.clone())).unwrap();
    let mut stopped = starting.clone();
    stopped.phase = SessionPhase::Stopped;
    stopped.local_revision += 1;
    write(&mut f, Some(&starting), &stopped).unwrap();
    let pair = crate::member_pair::PairRecord {
        scope: scope(),
        members: [None, None],
        active: None,
        guard: crate::member_guard::Model::empty(scope()).unwrap(),
        pending_guard: None,
        dns: [None, None],
        options: None,
        closing: false,
    };
    let bytes = serde_json::to_vec(&super::super::Envelope {
        version: 1,
        scope: scope(),
        payload: pair,
    })
    .unwrap();
    f.compare_exchange(&scope(), RecordKind::Pair, None, &bytes)
        .unwrap();
    f.complete(&scope()).unwrap();
    assert!(old.inspect(|_| Ok(())).is_err());
    let mut next_scope = scope();
    next_scope.connection_generation += 1;
    f.claim(&next_scope).unwrap();
    let new = f.session_ack_root(&next_scope).unwrap();
    assert!(!old.matches_origin(&f));
    assert!(new.matches_origin(&f));
    assert!(old.inspect(|_| Ok(())).is_err());
    let mut next = initial();
    next.scope = next_scope;
    write(&mut f, None, &next).unwrap();
    new.inspect(|facts| {
        assert_eq!(facts.birth.network_epoch(), 1);
        assert!(!facts.ack.same_original(&old_ack));
        Ok(())
    })
    .unwrap();
}

#[test]
fn actual_scope_mismatch_and_bare_session_read_reentry_deny_without_refresh() {
    for mismatch in [false, true] {
        let d = Disk::default();
        let mut f = files(&d);
        f.claim(&scope()).unwrap();
        let root = f.session_ack_root(&scope()).unwrap();
        write(&mut f, None, &initial()).unwrap();
        if mismatch {
            let mut wrong = scope();
            wrong.connection_generation += 1;
            assert!(f.session_ack_root(&wrong).is_err());
        } else {
            assert!(root
                .inspect(|_| {
                    assert!(f.read(&scope(), RecordKind::Session).is_err());
                    Ok(())
                })
                .is_err());
        }
        assert!(root.inspect(|_| Ok(())).is_err());
    }
}

#[test]
fn birth_context_epoch_one_cannot_be_replaced_by_execution_epoch_two() {
    use crate::member_carrier::{Intent, Provenance};
    use crate::member_carrier_native_ownership::{Binding, Context, Role};
    let d = Disk::default();
    let mut f = files(&d);
    f.claim(&scope()).unwrap();
    let root = f.session_ack_root(&scope()).unwrap();
    let before = initial();
    write(&mut f, None, &before).unwrap();
    let mut next = before.clone();
    next.network_epoch = 2;
    next.local_revision += 1;
    write(&mut f, Some(&before), &next).unwrap();
    let mut context = Context {
        intent: Intent {
            scope: scope(),
            addresses: vec![],
        },
        provenance: Provenance {
            boot_id: [7; 16],
            runtime: f.runtime.clone(),
            network_epoch: 1,
        },
        bindings: std::array::from_fn(|i| Binding {
            role: [Role::RoleCarrier, Role::MemberA, Role::MemberB][i],
            guid: [i as u8 + 1; 16],
            name: "literal".into(),
            registry_path: "literal".into(),
        }),
    };
    root.inspect(|facts| {
        assert_eq!(facts.execution.value(), 2);
        assert!(facts.birth.matches_context(&context));
        context.provenance.network_epoch = 2;
        assert!(!facts.birth.matches_context(&context));
        assert_eq!(facts.birth.network_epoch(), 1);
        Ok(())
    })
    .unwrap();
}

#[test]
fn actual_protected_session_ack_history_bound_fences_read_without_changing_legacy_write() {
    let d = Disk::default();
    let mut f = files(&d);
    f.claim(&scope()).unwrap();
    let root = f.session_ack_root(&scope()).unwrap();
    let mut before = initial();
    write(&mut f, None, &before).unwrap();
    for _ in 1..MAX_ACKS {
        let mut next = before.clone();
        next.local_revision += 1;
        write(&mut f, Some(&before), &next).unwrap();
        before = next;
    }
    assert_eq!(root.acknowledgements().unwrap().len(), MAX_ACKS);
    root.inspect(|_| Ok(())).unwrap();
    let mut next = before.clone();
    next.local_revision += 1;
    write(&mut f, Some(&before), &next).unwrap();
    assert_eq!(root.acknowledgements().unwrap().len(), MAX_ACKS);
    assert!(root.inspect(|_| Ok(())).is_err());
    assert!(f.session_ack_root(&scope()).is_err());
    assert_eq!(
        f.read(&scope(), RecordKind::Session).unwrap().unwrap(),
        payload(&next)
    );
}

fn native_context(
    f: &ProtectedSessionFiles<Disk>,
) -> crate::member_carrier_native_ownership::Context {
    use crate::member_carrier_native_ownership::{Binding, Context, Role};
    Context {
        intent: crate::member_carrier::Intent { scope: scope(), addresses: vec!["10.7.0.2/32".parse().unwrap()] },
        provenance: crate::member_carrier::Provenance { boot_id: [7;16], runtime: f.runtime.clone(), network_epoch: 1 },
        bindings: [Role::RoleCarrier,Role::MemberA,Role::MemberB].map(|role| {
            let (id,name) = match role { Role::RoleCarrier => (1,"carrier-c"),Role::MemberA => (2,"member-a"),Role::MemberB => (3,"member-b") };
            Binding { role, guid:[id;16], name:name.into(), registry_path:format!(r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{{id:02x}{id:02x}{id:02x}{id:02x}-{id:02x}{id:02x}-{id:02x}{id:02x}-{id:02x}{id:02x}-{id:02x}{id:02x}{id:02x}{id:02x}{id:02x}{id:02x}}}") }
        }),
    }
}
fn native_record(
    context: &crate::member_carrier_native_ownership::Context,
) -> crate::member_carrier_native_ownership::Record {
    use crate::member_carrier_native_ownership as n;
    n::Record {
        version: 2,
        context: context.clone(),
        generation: 1,
        phase: n::Phase::Preparing,
        keys: [n::Role::RoleCarrier, n::Role::MemberA, n::Role::MemberB].map(|role| {
            n::KeyReceipt {
                role,
                phase: n::KeyPhase::Unstarted,
                new_key_ack: false,
                baseline: n::Value::Absent,
                current: n::Value::Absent,
                pending: None,
            }
        }),
        native_rows: n::FullNativeRows::Unbound,
    }
}
fn ack(root: &SessionAckRoot<Disk>) -> SessionWriteAck {
    root.acknowledgements().unwrap().last().unwrap().clone()
}
fn bound_start() -> (
    Disk,
    ProtectedSessionFiles<Disk>,
    SessionAckRoot<Disk>,
    ExecutionRoot<Disk>,
    Arc<ExecutionLease>,
    SessionSnapshot,
) {
    let d = Disk::default();
    let mut f = files(&d);
    f.claim(&scope()).unwrap();
    let root = f.session_ack_root(&scope()).unwrap();
    let s = initial();
    write(&mut f, None, &s).unwrap();
    let execution = root
        .bind_native_birth(&native_context(&f), &ack(&root))
        .unwrap();
    let lease = execution.current_lease().unwrap();
    (d, f, root, execution, lease, s)
}
fn running(f: &mut ProtectedSessionFiles<Disk>, s: &SessionSnapshot) -> SessionSnapshot {
    let mut r = s.clone();
    r.phase = SessionPhase::Running;
    r.installed[0] = true;
    r.committed[0] = true;
    write(f, Some(s), &r).unwrap();
    r
}

// Removing explicit selection or substituting current file epoch for its
// original lease must fail this real protected-native-record CAS test.
#[test]
fn native_birth_storage_explicit_two_rebinds_keep_birth_and_invalidate_old_leases() {
    let (d, mut f, root, execution, birth, s) = bound_start();
    let context = native_context(&f);
    let mut view = f.native_birth_view(&execution).unwrap();
    let mut r = native_record(&context);
    let mut raw = r.encode().unwrap();
    view.compare_exchange(&scope(), RecordKind::NativeCarrierReceipts, None, &raw)
        .unwrap();
    let mut s = running(&mut f, &s);
    assert_eq!(execution.verify_current(&birth).unwrap().session, s);
    let mut lease = execution.select_running(&birth, &ack(&root)).unwrap();
    for next_epoch in [2, 3, 4, 5] {
        let mut next = s.clone();
        next.network_epoch = next_epoch;
        write(&mut f, Some(&s), &next).unwrap();
        assert!(view.native_carrier_access(&scope()).is_err()); // No implicit ACK adoption.
        let old = lease.clone();
        lease = if next_epoch % 2 == 0 {
            execution.renew_for_rebind(&old, &ack(&root)).unwrap()
        } else {
            execution.complete_rebind(&old, &ack(&root)).unwrap()
        };
        assert!(execution.verify_current(&old).is_err());
        let facts = execution.verify_current(&lease).unwrap();
        assert_eq!(facts.context, context);
        assert_eq!(facts.session, next);
        assert_eq!(facts.execution.value(), next_epoch);
        assert_eq!(
            view.native_carrier_access(&scope())
                .unwrap()
                .provenance
                .network_epoch,
            1
        );
        use crate::member_carrier_native_ownership::{KeyPhase, Value};
        r.generation += 1;
        match next_epoch {
            2 => r.keys[0].phase = KeyPhase::CreatePending,
            3 => {
                r.keys[0].phase = KeyPhase::Captured;
                r.keys[0].new_key_ack = true;
            }
            4 => {
                r.keys[0].phase = KeyPhase::DisablePending;
                r.keys[0].pending = Some(Value::DwordZero);
            }
            _ => {
                r.keys[0].phase = KeyPhase::Disabled;
                r.keys[0].current = Value::DwordZero;
                r.keys[0].pending = None;
            }
        }
        let bytes = r.encode().unwrap();
        view.compare_exchange(
            &scope(),
            RecordKind::NativeCarrierReceipts,
            Some(&raw),
            &bytes,
        )
        .unwrap();
        raw = bytes;
        s = next;
    }
    let saved: super::super::SavedRecord = serde_json::from_slice(
        d.0.borrow()
            .bytes
            .get(&PrivateFile::NativeCarrierReceipts)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(saved.network_epoch, 1);
    assert_eq!(r.context.provenance.network_epoch, 1);
    assert!(f
        .native_birth_view(&execution)
        .unwrap()
        .same_original_backend(&f));
}

#[test]
fn native_birth_bind_is_once_original_starting_not_running_or_foreign_ack() {
    let (_, mut f, root, execution, lease, s) = bound_start();
    assert!(root
        .bind_native_birth(&native_context(&f), &ack(&root))
        .is_err());
    let (_, foreign, foreign_root, _, _, _) = bound_start();
    assert!(foreign.native_birth_view(&execution).is_err());
    assert!(execution
        .select_running(&lease, &ack(&foreign_root))
        .is_err());
    let _ = running(&mut f, &s);
    assert!(root
        .bind_native_birth(&native_context(&f), &ack(&root))
        .is_err());
}

fn bound_running() -> (
    Disk,
    ProtectedSessionFiles<Disk>,
    SessionAckRoot<Disk>,
    ExecutionRoot<Disk>,
    Arc<ExecutionLease>,
    SessionSnapshot,
) {
    let (d, mut f, root, execution, birth, s) = bound_start();
    let s = running(&mut f, &s);
    let lease = execution.select_running(&birth, &ack(&root)).unwrap();
    (d, f, root, execution, lease, s)
}
fn epoch_two() -> (
    Disk,
    ProtectedSessionFiles<Disk>,
    SessionAckRoot<Disk>,
    ExecutionRoot<Disk>,
    Arc<ExecutionLease>,
    SessionSnapshot,
) {
    let (d, mut f, root, execution, old, s) = bound_running();
    let mut next = s.clone();
    next.network_epoch = 2;
    write(&mut f, Some(&s), &next).unwrap();
    let lease = execution.renew_for_rebind(&old, &ack(&root)).unwrap();
    (d, f, root, execution, lease, next)
}

#[test]
fn native_birth_renew_rejects_skips_changed_session_fields_and_wrong_completion_stage() {
    for mutation in 0..9 {
        let (_, mut f, root, execution, lease, s) = bound_running();
        let mut next = s.clone();
        next.network_epoch = 2;
        match mutation {
            0 => next.network_epoch = 3,
            1 => next.network_epoch = u64::MAX,
            2 => next.local_revision += 1,
            3 => next.role_generation += 1,
            4 => next.membership_generation += 1,
            5 => {
                next.active = Slot::B;
                next.installed[1] = true;
                next.committed[1] = true;
            }
            6 => next.role_confirmed = false,
            7 => next.phase = SessionPhase::Stopping,
            _ => {
                next.installed[1] = true;
                next.committed[1] = true;
            }
        }
        write(&mut f, Some(&s), &next).unwrap();
        assert!(
            execution.renew_for_rebind(&lease, &ack(&root)).is_err(),
            "mutation {mutation}"
        );
    }
    let (_, mut f, root, execution, lease, s) = bound_running();
    let mut next = s.clone();
    next.network_epoch = 2;
    write(&mut f, Some(&s), &next).unwrap();
    assert!(execution.complete_rebind(&lease, &ack(&root)).is_err());
    let (_, mut f, root, execution, lease, s) = epoch_two();
    let mut next = s.clone();
    next.network_epoch = 3;
    write(&mut f, Some(&s), &next).unwrap();
    assert!(execution.renew_for_rebind(&lease, &ack(&root)).is_err());
}

#[test]
fn native_birth_selection_is_retained_before_failed_postflight_and_never_refreshed() {
    let (d, mut f, root, execution, lease, s) = bound_running();
    let mut next = s.clone();
    next.network_epoch = 2;
    write(&mut f, Some(&s), &next).unwrap();
    let next_ack = ack(&root);
    let execution = Rc::new(execution);
    let retained = Rc::new(RefCell::new(None));
    let observed = retained.clone();
    let original = execution.clone();
    d.0.borrow_mut().after = Some(Box::new(move || {
        *observed.borrow_mut() = Some(original.current_lease().unwrap());
    }));
    d.0.borrow_mut().fail_after = true;
    assert!(execution.renew_for_rebind(&lease, &next_ack).is_err());
    let selected = retained.borrow().clone().unwrap();
    assert!(selected.ack.same_original(&next_ack));
    assert!(execution.verify_current(&selected).is_err());
    assert!(execution.current_lease().is_err());
    assert!(f.native_birth_view(&execution).is_err());
    assert!(root
        .bind_native_birth(&native_context(&f), &next_ack)
        .is_err());
}

#[test]
fn native_birth_view_does_not_write_session_network_legacy_or_follow_dead_root() {
    let (_, mut f, _, execution, lease, s) = bound_start();
    let mut view = f.native_birth_view(&execution).unwrap();
    assert!(view.read(&scope(), RecordKind::Network).is_err());
    assert!(
        super::super::ProtectedStore::<_, super::super::NativeNetworkRecord>::open(
            view.clone(),
            scope(),
            RecordKind::Network,
        )
        .is_err()
    );
    assert!(f.read(&scope(), RecordKind::Network).unwrap().is_none());
    let (mut common, saved) =
        super::super::ProtectedStore::open(f.clone(), scope(), RecordKind::Network).unwrap();
    assert!(saved.is_none());
    common
        .save_value(&super::super::NativeNetworkRecord::default())
        .unwrap();
    let saved = f.read(&scope(), RecordKind::Network).unwrap().unwrap();
    assert_eq!(common.expected.as_ref(), Some(&saved));
    super::super::NativeNetworkRecord::read_comparison(&scope(), &saved).unwrap();
    execution.verify_current(&lease).unwrap();
    assert!(view.read(&scope(), RecordKind::Network).is_err());
    let mut cleanup = execution.native_cleanup_view(&f).unwrap().into_files();
    assert!(cleanup.read(&scope(), RecordKind::Network).is_err());

    // A durable lost ACK through the common view does not advance this store's
    // expected bytes or become a successful publication under the retained birth.
    let (disk, mut original, _, loss_execution, loss_lease, _) = bound_start();
    let (mut lost, existing) =
        super::super::ProtectedStore::open(original.clone(), scope(), RecordKind::Network).unwrap();
    assert!(existing.is_none());
    disk.0.borrow_mut().lost_file = Some(PrivateFile::Network);
    assert!(lost
        .save_value(&super::super::NativeNetworkRecord::default())
        .is_err());
    assert!(original
        .read(&scope(), RecordKind::Network)
        .unwrap()
        .is_some());
    assert!(lost.expected.is_none());
    assert!(lost
        .save_value(&super::super::NativeNetworkRecord::default())
        .is_err());
    assert!(lost.expected.is_none());
    assert!(loss_execution.verify_current(&loss_lease).is_err());
    assert!(view.claim(&scope()).is_err());
    assert!(view.complete(&scope()).is_err());
    assert!(write(&mut view, Some(&s), &s).is_err());
    let network = serde_json::to_vec(&super::super::Envelope {
        version: 1,
        scope: scope(),
        payload: super::super::NativeNetworkRecord::default(),
    })
    .unwrap();
    assert!(view
        .compare_exchange(&scope(), RecordKind::Network, None, &network)
        .is_err());
    assert!(cleanup
        .compare_exchange(&scope(), RecordKind::Network, Some(&saved), &network)
        .is_err());
    assert_eq!(f.read(&scope(), RecordKind::Network).unwrap(), Some(saved));
    let legacy = crate::member_pair::PairRecord {
        scope: scope(),
        members: [None, None],
        active: None,
        guard: crate::member_guard::Model::empty(scope()).unwrap(),
        pending_guard: None,
        dns: [None, None],
        options: None,
        closing: false,
    };
    let legacy = serde_json::to_vec(&super::super::Envelope {
        version: 1,
        scope: scope(),
        payload: legacy,
    })
    .unwrap();
    assert!(view
        .compare_exchange(&scope(), RecordKind::Pair, None, &legacy)
        .is_err());
    drop(execution);
    assert!(view.native_carrier_access(&scope()).is_err());
    assert!(lease.origin.upgrade().is_none());
}

#[test]
fn native_birth_record_false_success_lost_ack_and_outer_drift_fence_original() {
    for fault in 0..4 {
        let (d, f, root, execution, lease, _) = epoch_two();
        let mut view = f.native_birth_view(&execution).unwrap();
        let bytes = native_record(&native_context(&f)).encode().unwrap();
        match fault {
            0 => d.0.borrow_mut().false_file = Some(PrivateFile::NativeCarrierReceipts),
            1 => d.0.borrow_mut().lost_file = Some(PrivateFile::NativeCarrierReceipts),
            2 => {
                let disk = d.clone();
                d.0.borrow_mut().after = Some(Box::new(move || {
                    disk.0.borrow_mut().bytes.remove(&PrivateFile::Session);
                }));
            }
            _ => d.0.borrow_mut().fail_after = true,
        }
        assert!(view
            .compare_exchange(&scope(), RecordKind::NativeCarrierReceipts, None, &bytes)
            .is_err());
        assert!(execution.verify_current(&lease).is_err());
        assert!(root.inspect(|_| Ok(())).is_err());
    }
}

#[test]
fn native_birth_execution_read_releases_private_lock_and_cannot_keep_root_alive() {
    let (_, mut f, _, execution, lease, _) = bound_running();
    let facts = execution.verify_current(&lease).unwrap();
    // This real Session read after return would deadlock/fence if locks leaked.
    assert_eq!(
        f.read(&scope(), RecordKind::Session).unwrap().unwrap(),
        payload(&facts.session)
    );
    drop(execution);
    assert!(lease.origin.upgrade().is_none());
}

fn rows_record(
    context: &crate::member_carrier_native_ownership::Context,
    role: crate::member_carrier_rows::Role,
) -> crate::member_carrier_rows::Record {
    use crate::member_carrier_rows as r;
    let i = match role {
        r::Role::Carrier => 0,
        r::Role::MemberA => 1,
        r::Role::MemberB => 2,
    };
    let key = r::RowKey {
        luid: 1000 + i as u64,
        index: 100 + i as u32,
    };
    let b = r::Binding {
        scope: scope(),
        boot_id: [7; 16],
        runtime: context.provenance.runtime.clone(),
        network_epoch: 1,
        role,
        guid: context.bindings[i].guid,
        name: context.bindings[i].name.clone(),
        key,
        address: [10, 7, 0, 2],
    };
    let s = r::Snapshot {
        interface: r::InterfaceRow {
            key,
            policy: r::InterfacePolicy {
                advertising: false,
                forwarding: false,
                weak_host_send: false,
                weak_host_receive: false,
                automatic_metric: false,
                neighbor_unreachability: true,
                managed_address_configuration: false,
                other_stateful_configuration: true,
                advertise_default_route: false,
                router_discovery: 0,
                dad_transmits: 3,
                base_reachable_time: 30000,
                retransmit_time: 1000,
                path_mtu_discovery_timeout: 600000,
                link_local_behavior: 0,
                link_local_timeout: 6500,
                zone_indices: [17; 16],
                metric: 19,
                mtu: 1420,
                disable_default_routes: true,
            },
            observed: r::InterfaceObserved {
                site_prefix_length: 0,
                max_reassembly_size: 0,
                interface_identifier: 0,
                min_router_advertisement_interval: 200,
                max_router_advertisement_interval: 600,
                connected: true,
                supports_wake_up_patterns: false,
                supports_neighbor_discovery: true,
                supports_router_discovery: false,
                reachable_time: 45678,
                transmit_offload: 0xa5,
                receive_offload: 0x5a,
            },
        },
        address: None,
    };
    r::Record {
        version: 1,
        domain: r::DOMAIN.into(),
        binding: b,
        revision: 1,
        phase: r::Phase::Captured,
        baseline: s.clone(),
        current: s,
        pending: None,
        creation: None,
    }
}
fn native_payloads(
    context: &crate::member_carrier_native_ownership::Context,
) -> Vec<(RecordKind, Vec<u8>)> {
    use super::super::{CarrierGuardRecord, Envelope};
    let pair = crate::member_carrier_pair::Record {
        version: 2,
        scope: scope(),
        provenance: context.provenance.clone(),
        revision: 1,
        phase: crate::member_carrier_pair::Phase::Fresh,
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
    };
    let carrier = crate::member_carrier::Record {
        version: 1,
        intent: context.intent.clone(),
        provenance: context.provenance.clone(),
        generation: 1,
        phase: crate::member_carrier::Phase::Prepared,
        proof: None,
        rows: None,
    };
    let guard = CarrierGuardRecord {
        version: 2,
        context: context.clone(),
        revision: 1,
        current: crate::member_carrier_guard::Model::empty(scope()).unwrap(),
        pending: None,
    };
    let mut values = vec![
        (
            RecordKind::Pair,
            serde_json::to_vec(&Envelope {
                version: 1,
                scope: scope(),
                payload: pair,
            })
            .unwrap(),
        ),
        (
            RecordKind::Carrier,
            serde_json::to_vec(&Envelope {
                version: 1,
                scope: scope(),
                payload: carrier,
            })
            .unwrap(),
        ),
        (RecordKind::CarrierGuard, guard.encode().unwrap()),
        (
            RecordKind::NativeCarrierReceipts,
            native_record(context).encode().unwrap(),
        ),
    ];
    for (kind, role) in [
        (
            RecordKind::CarrierRows,
            crate::member_carrier_rows::Role::Carrier,
        ),
        (
            RecordKind::MemberARows,
            crate::member_carrier_rows::Role::MemberA,
        ),
        (
            RecordKind::MemberBRows,
            crate::member_carrier_rows::Role::MemberB,
        ),
    ] {
        values.push((kind, rows_record(context, role).encode().unwrap()));
    }
    values
}

#[test]
fn native_birth_all_typed_initial_cas_join_selected_ack_without_rewriting_birth() {
    for i in 0..7 {
        let (d, f, _, execution, lease, _) = epoch_two();
        let context = native_context(&f);
        let (kind, bytes) = native_payloads(&context).remove(i);
        // Exact-context birth storage succeeds only through the selected view.
        let mut view = f.native_birth_view(&execution).unwrap();
        view.compare_exchange(&scope(), kind, None, &bytes).unwrap();
        assert_eq!(view.read(&scope(), kind).unwrap().unwrap(), bytes);
        let saved: super::super::SavedRecord =
            serde_json::from_slice(d.0.borrow().bytes.get(&kind.file()).unwrap()).unwrap();
        assert_eq!(saved.network_epoch, 1);
        execution.verify_current(&lease).unwrap();
        // Ordinary fresh files still require current epoch for initial records.
        let (_, mut other, _, _, _, _) = epoch_two();
        assert!(
            other
                .compare_exchange(&scope(), kind, None, &bytes)
                .is_err(),
            "{kind:?}"
        );
    }
}

#[test]
fn native_birth_all_typed_context_substitution_is_denied_before_private_cas() {
    for i in 0..7 {
        let (d, f, _, execution, _, _) = epoch_two();
        let mut context = native_context(&f);
        // Same authenticated birth scope/provenance, but different selected C
        // intent/bindings. Byte-valid records must not replace this selection.
        context.intent.addresses = vec!["10.7.0.3/32".parse().unwrap()];
        context.bindings[0].name = "other-c".into();
        context.bindings[1].name = "other-a".into();
        context.bindings[2].name = "other-b".into();
        let (kind, mut bytes) = native_payloads(&context).remove(i);
        if kind == RecordKind::Pair {
            // A Fresh pair has no addresses yet; provenance must remain exact.
            let mut p = super::super::carrier_pair_payload(&scope(), &bytes)
                .unwrap()
                .unwrap();
            p.provenance.network_epoch = 2;
            bytes = serde_json::to_vec(&super::super::Envelope {
                version: 1,
                scope: scope(),
                payload: p,
            })
            .unwrap();
        }
        let mut view = f.native_birth_view(&execution).unwrap();
        assert!(
            view.compare_exchange(&scope(), kind, None, &bytes).is_err(),
            "{kind:?}"
        );
        assert!(!d.0.borrow().bytes.contains_key(&kind.file()));
    }
}

#[test]
fn native_birth_same_epoch_actual_lifecycle_acks_keep_selected_lease_not_native_permissions() {
    let (_, mut f, root, execution, lease, s) = bound_running();
    let mut view = f.native_birth_view(&execution).unwrap();
    let mut alias = view.clone();
    let mut before = s;
    let context = native_context(&f);
    let initial = native_record(&context).encode().unwrap();
    view.compare_exchange(&scope(), RecordKind::NativeCarrierReceipts, None, &initial)
        .unwrap();
    for step in 0..4 {
        let mut next = before.clone();
        next.local_revision += 1;
        match step {
            0 => {
                next.installed[1] = true;
                next.committed[1] = true;
                next.membership_generation += 1;
            }
            1 => {
                next.active = Slot::B;
                next.role_generation += 1;
            }
            2 => {
                next.phase = SessionPhase::Stopping;
                next.role_confirmed = false;
            }
            _ => {
                next.phase = SessionPhase::Stopped;
                next.installed = [false, false];
                next.committed = [false, false];
            }
        }
        write(&mut f, Some(&before), &next).unwrap();
        let facts = execution.verify_current(&lease).unwrap();
        assert_eq!(facts.session, next);
        assert!(facts.ack.same_original(&ack(&root)));
        assert!(Arc::ptr_eq(&execution.current_lease().unwrap(), &lease));
        assert_eq!(
            view.native_carrier_access(&scope())
                .unwrap()
                .provenance
                .network_epoch,
            1
        );
        assert_eq!(
            alias
                .native_carrier_access(&scope())
                .unwrap()
                .provenance
                .network_epoch,
            1
        );
        if step == 2 {
            let mut closing = native_record(&context);
            closing.generation += 1;
            closing.phase = crate::member_carrier_native_ownership::Phase::Closing;
            view.compare_exchange(
                &scope(),
                RecordKind::NativeCarrierReceipts,
                Some(&initial),
                &closing.encode().unwrap(),
            )
            .unwrap();
        }
        before = next;
    }
}

#[test]
fn native_birth_renew_compares_last_actual_same_epoch_ack_after_attach_not_original_anchor() {
    let (_, mut f, root, execution, lease, s) = bound_running();
    let mut attached = s.clone();
    attached.installed[1] = true;
    attached.committed[1] = true;
    attached.local_revision += 1;
    attached.membership_generation += 1;
    write(&mut f, Some(&s), &attached).unwrap();
    let mut next = attached.clone();
    next.network_epoch = 2;
    write(&mut f, Some(&attached), &next).unwrap();
    let renewed = execution.renew_for_rebind(&lease, &ack(&root)).unwrap();
    assert_eq!(execution.verify_current(&renewed).unwrap().session, next);
    assert!(execution.verify_current(&lease).is_err());
}

#[test]
fn native_birth_execution_origin_comparison_accepts_alias_not_recovery_or_equal_backend() {
    let (d, mut f, root, execution, _, _) = bound_start();
    let view = f.native_birth_view(&execution).unwrap();
    assert!(execution.matches_origin(&f));
    assert!(execution.matches_origin(&f.clone()));
    assert!(execution.matches_origin(&view));
    assert!(execution.matches_birth_context(&native_context(&f)));
    assert!(!execution.matches_origin(&files(&d)));
    let (recovery, _) = f.recovery_view(RuntimeSlot::Stable).unwrap().unwrap();
    assert!(!execution.matches_origin(&recovery));
    assert!(recovery.native_birth_view(&execution).is_err());
    // Dropping the actor root does not let retained file data recreate it.
    drop(view);
    drop(execution);
    assert!(root
        .bind_native_birth(&native_context(&f), &ack(&root))
        .is_err());
}

#[test]
fn native_birth_completion_cannot_use_older_running_ack_after_common_stop() {
    let (_, mut f, root, execution, lease, s) = epoch_two();
    let mut completed = s.clone();
    completed.network_epoch = 3;
    write(&mut f, Some(&s), &completed).unwrap();
    let completion_ack = ack(&root);
    let mut stopping = completed.clone();
    stopping.phase = SessionPhase::Stopping;
    stopping.local_revision += 1;
    write(&mut f, Some(&completed), &stopping).unwrap();
    assert!(execution.complete_rebind(&lease, &completion_ack).is_err());
}

#[test]
fn native_birth_view_identity_requires_original_bound_state_even_after_cleanup_revocation() {
    let (d, mut files, _, execution, lease, _) = bound_start();
    let view = files.native_birth_view(&execution).unwrap();
    assert!(execution.matches_native_view(&view));
    assert!(execution.matches_native_view(&view.clone()));
    assert!(!execution.matches_native_view(&files));
    assert!(!execution.matches_native_view(&super::tests::files(&d)));
    let (recovery, _) = files.recovery_view(RuntimeSlot::Stable).unwrap().unwrap();
    assert!(!execution.matches_native_view(&recovery));
    let (_, _, _, foreign, _, _) = bound_start();
    assert!(!foreign.matches_native_view(&view));
    let cleanup_cap = execution.native_cleanup_view(&files).unwrap();
    let cleanup = cleanup_cap.into_files();
    assert!(execution.matches_native_view(&cleanup));
    assert!(execution.matches_native_view(&cleanup.clone()));
    assert!(execution.matches_native_view(&view));
    assert!(!execution.matches_origin(&cleanup));
    assert!(!foreign.matches_native_view(&cleanup));
    assert!(execution.verify_current(&lease).is_err());
    let mut changed = cleanup.clone();
    changed.boot = [8; 16];
    assert!(!execution.matches_native_view(&changed));
    let mut unbound = cleanup.clone();
    unbound.native_execution = None;
    assert!(!execution.matches_native_view(&unbound));
    let mut mismatched = cleanup;
    mismatched.native_cleanup = false;
    assert!(!execution.matches_native_view(&mismatched));
}

#[test]
fn actual_carrier_access_birth_fact_failed_postflight_fences_all_registered_siblings() {
    let (_, files, _, execution, _, _) = bound_running();
    let context = native_context(&files);
    let mut view = files.native_birth_view(&execution).unwrap();
    let bytes = native_record(&context).encode().unwrap();
    view.compare_exchange(&scope(), RecordKind::NativeCarrierReceipts, None, &bytes)
        .unwrap();
    let kinds = [
        RecordKind::Session,
        RecordKind::NativeCarrierReceipts,
        RecordKind::MemberARows,
    ];
    let expected = kinds
        .map(|kind| view.read(&scope(), kind).unwrap())
        .to_vec();
    assert!(view
        .native_records(&context, &[RecordKind::Network])
        .is_err());
    let (access, records) = view.native_records(&context, &kinds).unwrap();
    access.require_native_context(&context).unwrap();
    assert!(access.is_registered_native_birth_view());
    assert!(access.is_fresh());
    assert_eq!(records, expected);
    assert!(view.native_records(&context, &[]).unwrap().1.is_empty());
    let mut cleanup = execution.native_cleanup_view(&files).unwrap().into_files();
    let (access, records) = cleanup.native_records(&context, &kinds).unwrap();
    assert!(access.is_registered_native_birth_view());
    assert!(!access.is_fresh());
    assert_eq!(records, expected);

    for batch in [false, true] {
        let (disk, files, _, execution, _, _) = bound_running();
        let context = native_context(&files);
        let mut view = files.native_birth_view(&execution).unwrap();
        let bytes = native_record(&context).encode().unwrap();
        view.compare_exchange(&scope(), RecordKind::NativeCarrierReceipts, None, &bytes)
            .unwrap();
        disk.0.borrow_mut().reads.clear();
        disk.0.borrow_mut().transactions = 0;
        if batch {
            view.native_records(&context, &kinds).unwrap();
        } else {
            view.read(&scope(), RecordKind::Session).unwrap();
        }
        let disk = disk.0.borrow();
        // Two mandatory original ACK brackets plus the selected record/epoch
        // reads, with no third Session/index verification inside transaction one.
        assert_eq!(disk.transactions, 2);
        assert_eq!(disk.reads[&PrivateFile::Index], 3);
        assert_eq!(disk.reads[&PrivateFile::Session], if batch { 4 } else { 3 });
    }
    for batch in [false, true] {
        for fault in 0..4 {
            let (disk, files, root, execution, lease, _) = bound_running();
            let context = native_context(&files);
            let mut view = files.native_birth_view(&execution).unwrap();
            let original = disk.0.borrow().bytes.clone();
            let changed = disk.clone();
            disk.0.borrow_mut().after = Some(Box::new(move || match fault {
                0 => {
                    changed.0.borrow_mut().bytes.remove(&PrivateFile::Index);
                }
                1 => {
                    let mut disk = changed.0.borrow_mut();
                    let mut record: super::super::SavedRecord =
                        serde_json::from_slice(&disk.bytes[&PrivateFile::Session]).unwrap();
                    let mut session: super::super::Envelope<SessionSnapshot> =
                        serde_json::from_str(&record.data).unwrap();
                    session.payload.local_revision += 1;
                    record.data = serde_json::to_string(&session).unwrap();
                    disk.bytes
                        .insert(PrivateFile::Session, serde_json::to_vec(&record).unwrap());
                }
                2 => changed.0.borrow_mut().fail_read = Some(PrivateFile::Session),
                _ => panic!("selected read directory postflight"),
            }));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if batch {
                    view.native_records(&context, &kinds).map(|_| ())
                } else {
                    view.read(&scope(), RecordKind::Session).map(|_| ())
                }
            }));
            if fault == 3 {
                assert!(result.is_err());
            } else {
                assert!(result.unwrap().is_err());
            }
            // Restoring equal private bytes must not refresh the original roots.
            disk.0.borrow_mut().bytes = original;
            disk.0.borrow_mut().fail_read = None;
            assert!(view.native_carrier_access(&scope()).is_err());
            assert!(execution.verify_current(&lease).is_err());
            assert!(root.inspect(|_| Ok(())).is_err());
        }
    }

    for fault in 0..5 {
        let (disk, mut files, root, execution, lease, session) = bound_running();
        let mut context = native_context(&files);
        let mut view = files.native_birth_view(&execution).unwrap();
        let bytes = native_record(&context).encode().unwrap();
        view.compare_exchange(&scope(), RecordKind::NativeCarrierReceipts, None, &bytes)
            .unwrap();
        match fault {
            0 => context.bindings[0].name.push_str("-foreign"),
            1 => {
                let mut next = session.clone();
                next.network_epoch += 1;
                write(&mut files, Some(&session), &next).unwrap();
            }
            2 => {
                let wrong = disk.0.borrow().bytes[&PrivateFile::Session].clone();
                disk.0
                    .borrow_mut()
                    .bytes
                    .insert(PrivateFile::NativeCarrierReceipts, wrong);
            }
            3 => disk.0.borrow_mut().fail_after = true,
            _ => disk.0.borrow_mut().after = Some(Box::new(|| panic!("batch postflight"))),
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            view.native_records(&context, &kinds)
        }));
        if fault == 4 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert!(view.native_carrier_access(&scope()).is_err());
        assert!(execution.verify_current(&lease).is_err());
        if fault == 1 {
            // A stale selected lease is denied before a storage flight starts;
            // the original factual ACK history still records the actual epoch.
            root.inspect(|facts| {
                assert_eq!(facts.execution.value(), 2);
                Ok(())
            })
            .unwrap();
        } else {
            assert!(root.inspect(|_| Ok(())).is_err());
        }
    }

    let (disk, mut files, _, _, _, _) = bound_running();
    let context = native_context(&files);
    let changed = disk.clone();
    disk.0.borrow_mut().after = Some(Box::new(move || {
        changed.0.borrow_mut().bytes.remove(&PrivateFile::Index);
    }));
    assert!(files
        .native_records(&context, &[RecordKind::Session])
        .is_err());

    for reentry in [false, true] {
        let (disk, mut files, root, execution, lease, _) = bound_running();
        let mut view = files.native_birth_view(&execution).unwrap();
        let mut sibling = view.clone();
        let mut callback_sibling = sibling.clone();
        let ack_count = root.acknowledgements().unwrap().len();
        if reentry {
            disk.0.borrow_mut().after = Some(Box::new(move || {
                assert!(callback_sibling.native_carrier_access(&scope()).is_err());
            }));
        } else {
            disk.0.borrow_mut().fail_after = true;
        }
        assert!(view.native_carrier_access(&scope()).is_err());
        assert!(sibling.native_carrier_access(&scope()).is_err());
        assert!(execution.verify_current(&lease).is_err());
        assert!(files.session_ack_root(&scope()).is_err());
        assert_eq!(root.acknowledgements().unwrap().len(), ack_count);
        // Explicit owned cleanup is distinguishable from a forward refresh.
        let mut cleanup = execution.native_cleanup_view(&files).unwrap().into_files();
        let access = cleanup.native_carrier_access(&scope()).unwrap();
        assert!(access.is_registered_native_birth_view());
        assert!(!access.is_fresh());
        assert!(view.native_carrier_access(&scope()).is_err());
        assert!(!files
            .native_carrier_access(&scope())
            .unwrap()
            .is_registered_native_birth_view());
    }
}

#[test]
fn actual_carrier_access_birth_view_fact_distinguishes_selected_native_flight_from_legacy() {
    let (disk, mut files, root, execution, lease, session) = bound_running();
    let context = native_context(&files);
    let ordinary = files.native_carrier_access(&scope()).unwrap();
    assert!(!ordinary.is_registered_native_birth_view());
    ordinary.require_native_context(&context).unwrap();
    let (mut legacy, _) = files.recovery_view(RuntimeSlot::Stable).unwrap().unwrap();
    assert!(!legacy
        .native_carrier_access(&scope())
        .unwrap()
        .is_registered_native_birth_view());
    let mut native = files.native_birth_view(&execution).unwrap();
    assert!(native
        .native_carrier_access(&scope())
        .unwrap()
        .is_registered_native_birth_view());
    let mut next = session.clone();
    next.network_epoch = 2;
    write(&mut files, Some(&session), &next).unwrap();
    assert!(native.native_carrier_access(&scope()).is_err());
    let renewed = execution.renew_for_rebind(&lease, &ack(&root)).unwrap();
    let selected = native.native_carrier_access(&scope()).unwrap();
    assert!(selected.is_registered_native_birth_view());
    assert!(selected.is_fresh());
    assert_eq!(selected.provenance().network_epoch, 1);
    selected.require_native_context(&context).unwrap();
    let ordinary = files.native_carrier_access(&scope()).unwrap();
    assert!(!ordinary.is_registered_native_birth_view());
    assert_eq!(ordinary.provenance().network_epoch, 2);
    let mut reopened = super::tests::files(&disk);
    assert!(!reopened
        .native_carrier_access(&scope())
        .unwrap()
        .is_registered_native_birth_view());
    let mut cleanup = execution.native_cleanup_view(&files).unwrap().into_files();
    let cleanup_fact = cleanup.native_carrier_access(&scope()).unwrap();
    assert!(cleanup_fact.is_registered_native_birth_view());
    assert!(!cleanup_fact.is_fresh());
    assert_eq!(cleanup_fact.provenance().network_epoch, 1);
    let (mut recovered, changed) = cleanup.recovery_view(RuntimeSlot::Stable).unwrap().unwrap();
    assert!(!changed);
    assert!(recovered
        .native_carrier_access(&scope())
        .unwrap()
        .is_registered_native_birth_view());
    assert!(execution.verify_current(&renewed).is_err());
    drop(execution);
    assert!(native.native_carrier_access(&scope()).is_err());
    assert!(recovered.native_carrier_access(&scope()).is_err());
}

#[test]
fn native_birth_cleanup_recovery_preserves_original_binding_and_birth_epoch_without_fallback() {
    let (disk, mut files, _, execution, lease, session) = bound_running();
    let mut next = session.clone();
    next.network_epoch = 2;
    disk.0.borrow_mut().lost_ack = true;
    assert!(write(&mut files, Some(&session), &next).is_err());
    let mut cleanup = execution.native_cleanup_view(&files).unwrap().into_files();
    let (mut recovered, changed) = cleanup.recovery_view(RuntimeSlot::Stable).unwrap().unwrap();
    assert!(!changed);
    assert!(execution.matches_native_view(&recovered));
    assert_eq!(
        recovered
            .native_carrier_access(&scope())
            .unwrap()
            .provenance
            .network_epoch,
        1
    );
    assert!(!recovered
        .native_carrier_access(&scope())
        .unwrap()
        .is_fresh());
    assert!(execution.verify_current(&lease).is_err());
    assert!(recovered.claim(&scope()).is_err());
    assert!(recovered.recovery_view(RuntimeSlot::Latest).is_err());
    disk.0.borrow_mut().bytes.remove(&PrivateFile::Index);
    assert!(cleanup.recovery_view(RuntimeSlot::Stable).is_err());
    drop(execution);
    assert!(recovered.recovery_view(RuntimeSlot::Stable).is_err());
}

#[test]
fn native_birth_cleanup_can_publish_first_closing_for_exact_empty_v2_claim_not_foreign_addresses() {
    let (_, files, _, execution, _, _) = bound_start();
    let context = native_context(&files);
    let bytes = native_payloads(&context)
        .into_iter()
        .find(|(kind, _)| *kind == RecordKind::Pair)
        .unwrap()
        .1;
    let mut forward = files.native_birth_view(&execution).unwrap();
    forward
        .compare_exchange(&scope(), RecordKind::Pair, None, &bytes)
        .unwrap();
    let mut cleanup = execution.native_cleanup_view(&files).unwrap().into_files();
    let envelope: super::super::Envelope<crate::member_carrier_pair::Record> =
        serde_json::from_slice(&bytes).unwrap();
    let mut closing = envelope.payload;
    closing.revision += 1;
    closing.phase = crate::member_carrier_pair::Phase::Closing;
    let mut foreign = closing.clone();
    foreign.addresses = vec!["192.0.2.99/32".parse().unwrap()];
    let foreign = serde_json::to_vec(&super::super::Envelope {
        version: 1,
        scope: scope(),
        payload: foreign,
    })
    .unwrap();
    assert!(cleanup
        .compare_exchange(&scope(), RecordKind::Pair, Some(&bytes), &foreign)
        .is_err());
    let closing_bytes = serde_json::to_vec(&super::super::Envelope {
        version: 1,
        scope: scope(),
        payload: &closing,
    })
    .unwrap();
    cleanup
        .compare_exchange(&scope(), RecordKind::Pair, Some(&bytes), &closing_bytes)
        .unwrap();
    assert_eq!(
        cleanup.read(&scope(), RecordKind::Pair).unwrap().unwrap(),
        closing_bytes
    );
}

#[test]
fn native_birth_cleanup_never_exposes_unbound_network_absence_as_restored_fact() {
    let (_, files, _, execution, _, _) = bound_start();
    let mut cleanup = execution.native_cleanup_view(&files).unwrap().into_files();
    assert!(cleanup.read(&scope(), RecordKind::Network).is_err());
}

#[test]
fn native_birth_cleanup_whole_private_bracket_denies_drift_caught_reentry_and_unwind() {
    for fault in 0..3 {
        let (disk, files, _, execution, lease, session) = bound_start();
        let mut cleanup = execution.native_cleanup_view(&files).unwrap().into_files();
        let mut alias = cleanup.clone();
        let changed = disk.clone();
        disk.0.borrow_mut().after = Some(Box::new(move || match fault {
            0 => {
                let mut disk = changed.0.borrow_mut();
                let mut record: super::super::SavedRecord =
                    serde_json::from_slice(disk.bytes.get(&PrivateFile::Session).unwrap()).unwrap();
                let mut next = session;
                next.network_epoch = 2;
                record.network_epoch = 2;
                record.data = String::from_utf8(payload(&next)).unwrap();
                disk.bytes
                    .insert(PrivateFile::Session, serde_json::to_vec(&record).unwrap());
            }
            1 => assert!(alias.native_carrier_access(&scope()).is_err()),
            _ => panic!("cleanup private postflight unwind"),
        }));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            cleanup.native_carrier_access(&scope())
        }));
        if fault == 2 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert!(execution.verify_current(&lease).is_err());
        // A completed later cleanup fact bracket is not a forward refresh.
        if fault == 2 {
            // The original protected backend mutex is poisoned by unwind.
            // No cleanup facet may manufacture a replacement backend.
            assert!(cleanup.native_carrier_access(&scope()).is_err());
        } else {
            assert!(!cleanup.native_carrier_access(&scope()).unwrap().is_fresh());
        }
        assert!(execution.current_lease().is_err());
    }
}

#[test]
fn native_birth_cleanup_after_uncertain_session_ack_reads_owned_context_and_only_cleans() {
    for outer_lost in [false, true] {
        let (d, mut f, root, execution, lease, s) = bound_running();
        let context = native_context(&f);
        let record = native_record(&context);
        let bytes = record.encode().unwrap();
        let mut forward = f.native_birth_view(&execution).unwrap();
        forward
            .compare_exchange(&scope(), RecordKind::NativeCarrierReceipts, None, &bytes)
            .unwrap();
        let fresh_pair = native_payloads(&context)
            .into_iter()
            .find(|(kind, _)| *kind == RecordKind::Pair)
            .unwrap()
            .1;
        forward
            .compare_exchange(&scope(), RecordKind::Pair, None, &fresh_pair)
            .unwrap();
        let envelope: super::super::Envelope<crate::member_carrier_pair::Record> =
            serde_json::from_slice(&fresh_pair).unwrap();
        let mut starting_pair = envelope.payload;
        starting_pair.revision += 1;
        starting_pair.phase = crate::member_carrier_pair::Phase::Starting;
        starting_pair.addresses = context.intent.addresses.clone();
        let starting_bytes = serde_json::to_vec(&super::super::Envelope {
            version: 1,
            scope: scope(),
            payload: &starting_pair,
        })
        .unwrap();
        forward
            .compare_exchange(
                &scope(),
                RecordKind::Pair,
                Some(&fresh_pair),
                &starting_bytes,
            )
            .unwrap();
        let mut next = s.clone();
        next.network_epoch = 2;
        if outer_lost {
            d.0.borrow_mut().fail_after = true;
        } else {
            d.0.borrow_mut().lost_ack = true;
        }
        assert!(write(&mut f, Some(&s), &next).is_err());
        assert!(execution.verify_current(&lease).is_err());
        assert!(forward.native_carrier_access(&scope()).is_err());
        let mut cleanup = execution.native_cleanup_view(&f).unwrap().into_files();
        let facts = cleanup.native_carrier_access(&scope()).unwrap();
        assert!(!facts.is_fresh());
        assert_eq!(facts.provenance, context.provenance);
        assert_eq!(
            cleanup
                .read(&scope(), RecordKind::Session)
                .unwrap()
                .unwrap(),
            payload(&next)
        );
        assert_eq!(
            cleanup
                .read(&scope(), RecordKind::NativeCarrierReceipts)
                .unwrap()
                .unwrap(),
            bytes
        );
        assert!(execution.verify_current(&lease).is_err());
        assert!(root.inspect(|_| Ok(())).is_err());
        assert_eq!(
            cleanup.read(&scope(), RecordKind::Pair).unwrap().unwrap(),
            starting_bytes
        );
        let mut closing_pair = starting_pair;
        closing_pair.revision += 1;
        closing_pair.phase = crate::member_carrier_pair::Phase::Closing;
        let closing_bytes = serde_json::to_vec(&super::super::Envelope {
            version: 1,
            scope: scope(),
            payload: &closing_pair,
        })
        .unwrap();
        cleanup
            .compare_exchange(
                &scope(),
                RecordKind::Pair,
                Some(&starting_bytes),
                &closing_bytes,
            )
            .unwrap();
        for (kind, bytes) in native_payloads(&context) {
            if kind != RecordKind::NativeCarrierReceipts {
                assert!(
                    cleanup
                        .compare_exchange(&scope(), kind, None, &bytes)
                        .is_err(),
                    "{kind:?}"
                );
            }
        }
        let mut closing = record.clone();
        closing.generation += 1;
        closing.phase = crate::member_carrier_native_ownership::Phase::Closing;
        cleanup
            .compare_exchange(
                &scope(),
                RecordKind::NativeCarrierReceipts,
                Some(&bytes),
                &closing.encode().unwrap(),
            )
            .unwrap();
        assert!(write(&mut cleanup, Some(&next), &next).is_err());
        assert!(cleanup.claim(&scope()).is_err());
        assert!(cleanup.complete(&scope()).is_err());
        assert!(execution.renew_for_rebind(&lease, &ack(&root)).is_err());
    }
}

#[test]
fn native_birth_cleanup_facet_denies_other_backend_context_successor_claim_and_dead_root() {
    let (d, mut f, _, execution, _, s) = bound_start();
    assert!(execution.native_cleanup_view(&files(&d)).is_err());
    let mut cleanup = execution.native_cleanup_view(&f).unwrap().into_files();
    assert!(!cleanup.native_carrier_access(&scope()).unwrap().is_fresh());
    let mut alias = f.clone();
    alias.boot = [8; 16];
    assert!(execution.native_cleanup_view(&alias).is_err());
    // A different active private claim may never become cleanup authority.
    let mut index: super::super::SessionIndex =
        serde_json::from_slice(d.0.borrow().bytes.get(&PrivateFile::Index).unwrap()).unwrap();
    index.active.as_mut().unwrap().scope.connection_generation += 1;
    d.0.borrow_mut()
        .bytes
        .insert(PrivateFile::Index, serde_json::to_vec(&index).unwrap());
    assert!(cleanup.native_carrier_access(&scope()).is_err());
    drop(execution);
    assert!(cleanup.read(&scope(), RecordKind::Session).is_err());
    // No Session write was used to grant a successor or resume the old epoch.
    assert!(f
        .read(&index.active.unwrap().scope, RecordKind::Session)
        .is_err());
    let _ = s;
}

#[test]
fn native_birth_reentry_and_unwind_during_publication_fence_retained_selection() {
    for panic in [false, true] {
        let (d, mut f, root, execution, lease, s) = bound_running();
        let execution = Rc::new(execution);
        let mut next = s.clone();
        next.network_epoch = 2;
        write(&mut f, Some(&s), &next).unwrap();
        let original = execution.clone();
        let next_ack = ack(&root);
        let a = next_ack.clone();
        d.0.borrow_mut().after = Some(Box::new(move || {
            let selected = original.current_lease().unwrap();
            assert!(selected.ack.same_original(&a));
            if panic {
                panic!("execution postflight unwind");
            }
            assert!(original.verify_current(&selected).is_err());
        }));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            execution.renew_for_rebind(&lease, &next_ack)
        }));
        if panic {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert!(execution.current_lease().is_err());
        assert!(root.inspect(|_| Ok(())).is_err());
    }
}
