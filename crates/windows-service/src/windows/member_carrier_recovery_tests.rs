#[cfg(windows)]
use super::super::{
    member_files::{PrivateFile, PrivateRecords},
    member_session::{
        SessionFiles, WindowsNativeCarrierReceiptStore, WindowsNativeCreatorStore,
        WindowsSessionStore,
    },
};
use super::*;
use crate::{
    member_carrier::{Intent, Provenance},
    member_carrier_native_ownership as keys,
};
#[cfg(not(windows))]
use crate::{
    member_files::{PrivateFile, PrivateRecords},
    member_session::{
        SessionFiles, WindowsNativeCarrierReceiptStore, WindowsNativeCreatorStore,
        WindowsSessionStore,
    },
};
use nelomai_client_tunnel::redundancy::{
    driver::SessionStore, session::SessionState, SessionScope, Slot,
};
use nelomai_contracts::dispatcher::EngineIdentity;
use std::collections::BTreeMap;
#[derive(Clone, Default)]
struct Disk(Rc<RefCell<BTreeMap<PrivateFile, Vec<u8>>>>);
impl PrivateRecords for Disk {
    fn read(&mut self, file: PrivateFile) -> io::Result<Option<Vec<u8>>> {
        Ok(self.0.borrow().get(&file).cloned())
    }
    fn compare_exchange(
        &mut self,
        file: PrivateFile,
        expected: Option<&[u8]>,
        desired: &[u8],
    ) -> io::Result<()> {
        let mut d = self.0.borrow_mut();
        if d.get(&file).map(Vec::as_slice) != expected {
            return Err(conflict());
        }
        d.insert(file, desired.to_vec());
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
/// Only private OS reads are faulted; protected identity, envelope, whole
/// transaction and recovery-selection algorithms remain the actual code.
#[derive(Clone)]
struct PostflightFaultDisk {
    disk: Disk,
    index_reads: Rc<Cell<usize>>,
    unwind: bool,
}
impl PrivateRecords for PostflightFaultDisk {
    fn read(&mut self, file: PrivateFile) -> io::Result<Option<Vec<u8>>> {
        if file == PrivateFile::Index {
            let count = self.index_reads.get() + 1;
            self.index_reads.set(count);
            if count == 2 {
                if self.unwind {
                    panic!("actual private postflight read unwound");
                }
                return Err(io::Error::other("actual_private_postflight_read_fault"));
            }
        }
        self.disk.read(file)
    }
    fn compare_exchange(
        &mut self,
        file: PrivateFile,
        expected: Option<&[u8]>,
        desired: &[u8],
    ) -> io::Result<()> {
        self.disk.compare_exchange(file, expected, desired)
    }
}
impl SessionFileIo for PostflightFaultDisk {
    fn transaction<T>(
        &mut self,
        f: impl FnOnce(&mut dyn PrivateRecords) -> io::Result<T>,
    ) -> io::Result<T> {
        f(self)
    }
}
fn context() -> Context {
    let scope = SessionScope {
        runtime: RuntimeSlot::Stable,
        runtime_generation: 1,
        session_id: "11111111-1111-4111-8111-111111111111".into(),
        connection_generation: 2,
    };
    Context {
        intent: Intent { scope, addresses: vec!["10.7.0.2/32".parse().unwrap()] },
        provenance: Provenance { boot_id: [7;16], runtime: EngineIdentity { slot: RuntimeSlot::Stable, runtime_version: "1.0.0".into(), runtime_contract_version: 1, container_version: "1.0.0".into(), manifest_sha256: "a".repeat(64) }, network_epoch: 1 },
        bindings: [keys::Role::RoleCarrier, keys::Role::MemberA, keys::Role::MemberB].map(|role| {
            let n = match role { keys::Role::RoleCarrier => 1, keys::Role::MemberA => 2, keys::Role::MemberB => 3 };
            let hex = format!("{n:02x}");
            keys::Binding { role, guid: [n;16], name: format!("recovery-{n}"), registry_path: format!(r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{{}-{}-{}-{}-{}}}", hex.repeat(4), hex.repeat(2), hex.repeat(2), hex.repeat(2), hex.repeat(6)) }
        }),
    }
}
fn basic_fixture() -> (Disk, ProtectedSessionFiles<Disk>, Context) {
    let disk = Disk::default();
    let (files, c) = initial_files(disk.clone());
    (disk, files, c)
}
fn initial_files<I: SessionFileIo>(disk: I) -> (ProtectedSessionFiles<I>, Context) {
    let c = context();
    let mut files =
        ProtectedSessionFiles::new(disk, c.provenance.runtime.clone(), c.provenance.boot_id)
            .unwrap();
    files.claim(&c.intent.scope).unwrap();
    let mut session =
        WindowsSessionStore::open(files.clone(), c.intent.scope.clone(), RecordKind::Session)
            .unwrap()
            .0;
    session
        .save(
            &SessionState::new(c.intent.scope.clone(), Slot::A, 0, 0)
                .unwrap()
                .snapshot(),
        )
        .unwrap();
    (files, c)
}

#[test]
fn bootstrap_context_original_journal_binds_birth_view_without_reopening_or_sdk_ack() {
    use keys::NativeJournal;
    let (_, files, c) = basic_fixture();
    let history = files.session_ack_root(&c.intent.scope).unwrap();
    let starting = history.acknowledgements().unwrap().last().unwrap().clone();
    let execution = history.bind_native_birth(&c, &starting).unwrap();
    let lease = execution.current_lease().unwrap();
    let journal = WindowsNativeCarrierReceiptStore::open(files.clone(), c.clone())
        .unwrap()
        .0;
    let mut pending = keys::PendingNativeOwnership::new(c.clone(), journal);
    let first = pending.initialize().unwrap();
    let original = pending.read_pin().unwrap();
    let view = files.native_birth_view(&execution).unwrap();
    original
        .inspect_initial(&c, |journal, _| {
            journal
                .bind_original_native_view(view)
                .map_err(|_| crate::member_carrier::CarrierError::Journal)
        })
        .unwrap();
    assert!(first
        .keys
        .iter()
        .all(|k| !k.new_key_ack && k.phase == keys::KeyPhase::Unstarted));
    assert_eq!(first.native_rows, keys::FullNativeRows::Unbound);
    let (mut common, current) =
        WindowsSessionStore::open(files.clone(), c.intent.scope.clone(), RecordKind::Session)
            .unwrap();
    let mut running = current.unwrap();
    running.phase = nelomai_client_tunnel::redundancy::session::SessionPhase::Running;
    running.installed[0] = true;
    running.committed[0] = true;
    common.save(&running).unwrap();
    let current_ack = || history.acknowledgements().unwrap().last().unwrap().clone();
    let running_lease = execution.select_running(&lease, &current_ack()).unwrap();
    running.network_epoch = 2;
    common.save(&running).unwrap();
    let renewed = execution
        .renew_for_rebind(&running_lease, &current_ack())
        .unwrap();
    running.network_epoch = 3;
    common.save(&running).unwrap();
    let _completed = execution.complete_rebind(&renewed, &current_ack()).unwrap();
    original
        .inspect_initial(&c, |_, record| {
            assert_eq!(record, &first);
            Ok(())
        })
        .unwrap();
    let mut reopened = WindowsNativeCarrierReceiptStore::open(
        files.native_birth_view(&execution).unwrap(),
        c.clone(),
    )
    .unwrap()
    .0;
    assert_eq!(reopened.load(&c).unwrap(), Some(first.clone()));
    let mut next = first.clone();
    next.generation += 1;
    next.keys[0].phase = keys::KeyPhase::CreatePending;
    assert!(reopened.compare_exchange(&c, Some(&first), &next).is_err());
}

#[test]
fn bootstrap_context_binding_denies_unbound_foreign_cleanup_and_late_key_attempts() {
    use keys::NativeJournal;
    for invalid in 0..4 {
        let (_, files, c) = basic_fixture();
        let history = files.session_ack_root(&c.intent.scope).unwrap();
        let starting = history.acknowledgements().unwrap().last().unwrap().clone();
        let execution = history.bind_native_birth(&c, &starting).unwrap();
        let mut journal = WindowsNativeCarrierReceiptStore::open(files.clone(), c.clone())
            .unwrap()
            .0;
        let (_, _, _, mut first) = fixture();
        first.generation = 1;
        first.keys[0].phase = keys::KeyPhase::Unstarted;
        journal.compare_exchange(&c, None, &first).unwrap();
        let (_, foreign, _) = basic_fixture();
        let foreign_history = foreign.session_ack_root(&c.intent.scope).unwrap();
        let foreign_starting = foreign_history
            .acknowledgements()
            .unwrap()
            .last()
            .unwrap()
            .clone();
        let foreign_execution = foreign_history
            .bind_native_birth(&c, &foreign_starting)
            .unwrap();
        let candidate = match invalid {
            0 => files.clone(),
            1 => foreign.native_birth_view(&foreign_execution).unwrap(),
            2 => execution.native_cleanup_view(&files).unwrap().into_files(),
            _ => {
                let mut pending = first.clone();
                pending.generation = 2;
                pending.keys[0].phase = keys::KeyPhase::CreatePending;
                journal
                    .compare_exchange(&c, Some(&first), &pending)
                    .unwrap();
                files.native_birth_view(&execution).unwrap()
            }
        };
        assert!(journal.bind_original_native_view(candidate).is_err());
        assert!(journal.load(&c).is_err());
        // A fresh-looking repair cannot resume this original failed handoff.
        if let Ok(valid) = files.native_birth_view(&execution) {
            assert!(journal.bind_original_native_view(valid).is_err());
        }
    }
}

#[test]
fn bootstrap_context_initial_data_survives_crash_before_pair_and_never_fabricates_receipts() {
    let (disk, files, c) = basic_fixture();
    let journal = WindowsNativeCarrierReceiptStore::open(files, c.clone())
        .unwrap()
        .0;
    let mut slot = keys::PendingNativeOwnership::new(c.clone(), journal);
    let initial = slot.initialize().unwrap();
    assert_eq!(initial.generation, 1);
    assert!(initial
        .keys
        .iter()
        .all(|k| k.phase == keys::KeyPhase::Unstarted && !k.new_key_ack));
    assert_eq!(initial.native_rows, keys::FullNativeRows::Unbound);
    let old_bytes = disk
        .0
        .borrow()
        .get(&PrivateFile::NativeCarrierReceipts)
        .unwrap()
        .clone();
    assert!(!disk.0.borrow().contains_key(&PrivateFile::Pair));
    assert!(!disk.0.borrow().contains_key(&PrivateFile::CarrierGuard));
    drop(slot); // no retained SDK/creator owner is reconstructed in the cold process
    let cold =
        ProtectedSessionFiles::new(disk.clone(), c.provenance.runtime.clone(), [9; 16]).unwrap();
    let root = ProtectedRecoveryRoot::new(cold);
    root.initialize(RuntimeSlot::Stable).unwrap();
    let facts = root.retained_facts().unwrap();
    assert_eq!(facts.context.as_ref(), Some(&c));
    assert_eq!(facts.layout, RecoveryLayout::NativeCarrier);
    root.retire_cold_empty(cold_inventory()).unwrap(); // OS boundary double, not native hardware acceptance
    assert_eq!(
        disk.0.borrow().get(&PrivateFile::NativeCarrierReceipts),
        Some(&old_bytes)
    );
    assert!(!disk.0.borrow().contains_key(&PrivateFile::Pair));
    assert!(!disk.0.borrow().contains_key(&PrivateFile::CarrierGuard));
}

#[test]
fn bootstrap_context_claim_only_before_session_or_pair_retains_real_context_and_missing_session() {
    let disk = Disk::default();
    let c = context();
    let mut files = ProtectedSessionFiles::new(
        disk.clone(),
        c.provenance.runtime.clone(),
        c.provenance.boot_id,
    )
    .unwrap();
    files.claim(&c.intent.scope).unwrap();
    let journal = WindowsNativeCarrierReceiptStore::open(files.clone(), c.clone())
        .unwrap()
        .0;
    let mut slot = keys::PendingNativeOwnership::new(c.clone(), journal);
    let record = slot.initialize().unwrap();
    assert_eq!(record.context, c);
    assert_eq!(record.context.provenance.network_epoch, 1);
    assert!(record
        .keys
        .iter()
        .all(|k| !k.new_key_ack && k.phase == keys::KeyPhase::Unstarted));
    for absent in [
        PrivateFile::Session,
        PrivateFile::Pair,
        PrivateFile::Carrier,
        PrivateFile::CarrierGuard,
    ] {
        assert!(!disk.0.borrow().contains_key(&absent));
    }
    assert!(files
        .session_ack_root(&c.intent.scope)
        .unwrap()
        .acknowledgements()
        .unwrap()
        .is_empty());
    drop(slot);
    let old = disk
        .0
        .borrow()
        .get(&PrivateFile::NativeCarrierReceipts)
        .unwrap()
        .clone();
    let cold =
        ProtectedSessionFiles::new(disk.clone(), c.provenance.runtime.clone(), [9; 16]).unwrap();
    let root = ProtectedRecoveryRoot::new(cold);
    root.initialize(RuntimeSlot::Stable).unwrap();
    let facts = root.retained_facts().unwrap();
    assert_eq!(facts.context.as_ref(), Some(&c));
    assert_eq!(facts.layout, RecoveryLayout::NativeCarrier);
    assert!(facts
        .requirements
        .contains(&RecoveryRequirement::MissingSession));
    root.retire_cold_empty(cold_inventory()).unwrap();
    assert_eq!(
        disk.0.borrow().get(&PrivateFile::NativeCarrierReceipts),
        Some(&old)
    );
    assert!(!disk.0.borrow().contains_key(&PrivateFile::Session));
    assert!(!disk.0.borrow().contains_key(&PrivateFile::Pair));
}

#[test]
fn bootstrap_context_equal_external_publication_is_not_this_journals_initial_ack() {
    use keys::NativeJournal;
    let (_, mut files, c) = basic_fixture();
    let history = files.session_ack_root(&c.intent.scope).unwrap();
    let ack = history.acknowledgements().unwrap().last().unwrap().clone();
    let execution = history.bind_native_birth(&c, &ack).unwrap();
    let mut journal = WindowsNativeCarrierReceiptStore::open(files.clone(), c.clone())
        .unwrap()
        .0;
    let (_, _, _, mut equal) = fixture();
    equal.generation = 1;
    equal.keys[0].phase = keys::KeyPhase::Unstarted;
    files
        .compare_exchange(
            &c.intent.scope,
            RecordKind::NativeCarrierReceipts,
            None,
            &equal.encode().unwrap(),
        )
        .unwrap();
    assert!(journal
        .bind_original_native_view(files.native_birth_view(&execution).unwrap())
        .is_err());
    assert!(journal.load(&c).is_err());
}

#[derive(Clone, Default)]
struct BootstrapFaultDisk {
    disk: Disk,
    receipt_reads: Rc<Cell<usize>>,
    fail_read: Rc<Cell<Option<(usize, bool)>>>,
    lost_initial_ack: Rc<Cell<bool>>,
}
impl PrivateRecords for BootstrapFaultDisk {
    fn read(&mut self, kind: PrivateFile) -> io::Result<Option<Vec<u8>>> {
        if kind == PrivateFile::NativeCarrierReceipts {
            let n = self.receipt_reads.get() + 1;
            self.receipt_reads.set(n);
            if let Some((at, unwind)) = self.fail_read.get() {
                if n == at {
                    self.fail_read.set(None);
                    if unwind {
                        panic!("private bootstrap receipt read unwound");
                    }
                    return Err(io::Error::other("private_bootstrap_receipt_read_fault"));
                }
            }
        }
        self.disk.read(kind)
    }
    fn compare_exchange(
        &mut self,
        kind: PrivateFile,
        expected: Option<&[u8]>,
        desired: &[u8],
    ) -> io::Result<()> {
        self.disk.compare_exchange(kind, expected, desired)?;
        if kind == PrivateFile::NativeCarrierReceipts && self.lost_initial_ack.replace(false) {
            return Err(io::Error::other("private_initial_receipt_ack_lost"));
        }
        Ok(())
    }
}
impl SessionFileIo for BootstrapFaultDisk {
    fn transaction<T>(
        &mut self,
        action: impl FnOnce(&mut dyn PrivateRecords) -> io::Result<T>,
    ) -> io::Result<T> {
        action(self)
    }
}

#[test]
fn bootstrap_context_lost_initial_cas_ack_never_becomes_bindable_from_equal_bytes() {
    let disk = BootstrapFaultDisk::default();
    let (files, c) = initial_files(disk.clone());
    let history = files.session_ack_root(&c.intent.scope).unwrap();
    let ack = history.acknowledgements().unwrap().last().unwrap().clone();
    let execution = history.bind_native_birth(&c, &ack).unwrap();
    let canonical = files.native_birth_view(&execution).unwrap();
    let journal = WindowsNativeCarrierReceiptStore::open(files, c.clone())
        .unwrap()
        .0;
    let mut pending = keys::PendingNativeOwnership::new(c.clone(), journal);
    disk.lost_initial_ack.set(true);
    assert!(pending.initialize().is_err());
    assert!(disk
        .disk
        .0
        .borrow()
        .contains_key(&PrivateFile::NativeCarrierReceipts));
    assert!(pending.read_pin().is_err());
    assert!(pending.initialize().is_err());
    // Reopening durable matching bytes is cleanup-only, never the lost initial ACK.
    let mut bound = canonical;
    assert!(!bound
        .native_carrier_access(&c.intent.scope)
        .is_ok_and(|access| access.is_fresh()));
}

#[test]
fn bootstrap_context_each_private_bind_read_error_or_unwind_permanently_fences_original() {
    // Calibrate only the actual private-IO fault positions; assertions concern
    // real journal fencing, not a test-double callback's success policy.
    let mut reads = None;
    for fault in 0..=128 {
        if reads.is_some_and(|n| fault > n) {
            break;
        }
        for unwind in [false, true] {
            if fault == 0 && unwind {
                continue;
            }
            let disk = BootstrapFaultDisk::default();
            let (files, c) = initial_files(disk.clone());
            let history = files.session_ack_root(&c.intent.scope).unwrap();
            let ack = history.acknowledgements().unwrap().last().unwrap().clone();
            let execution = history.bind_native_birth(&c, &ack).unwrap();
            let journal = WindowsNativeCarrierReceiptStore::open(files.clone(), c.clone())
                .unwrap()
                .0;
            let mut pending = keys::PendingNativeOwnership::new(c.clone(), journal);
            pending.initialize().unwrap();
            let original = pending.read_pin().unwrap();
            let canonical = files.native_birth_view(&execution).unwrap();
            disk.receipt_reads.set(0);
            if fault != 0 {
                disk.fail_read.set(Some((fault, unwind)));
            }
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                original.inspect_initial(&c, |journal, _| {
                    journal
                        .bind_original_native_view(canonical)
                        .map_err(|_| crate::member_carrier::CarrierError::Journal)
                })
            }));
            if fault == 0 {
                result.unwrap().unwrap();
                reads = Some(disk.receipt_reads.get());
                assert!(reads.unwrap() <= 128);
            } else {
                assert!(result.is_err() || result.unwrap().is_err());
                assert!(original.verify(&c).is_err());
                assert!(pending.initialize().is_err());
            }
        }
    }
}
fn fixture() -> (Disk, ProtectedSessionFiles<Disk>, Context, keys::Record) {
    let (disk, files, c) = basic_fixture();
    let mut journal = WindowsNativeCarrierReceiptStore::open(files.clone(), c.clone())
        .unwrap()
        .0;
    let first = keys::Record {
        version: 2,
        context: c.clone(),
        generation: 1,
        phase: keys::Phase::Preparing,
        keys: [
            keys::Role::RoleCarrier,
            keys::Role::MemberA,
            keys::Role::MemberB,
        ]
        .map(|role| keys::KeyReceipt {
            role,
            phase: keys::KeyPhase::Unstarted,
            new_key_ack: false,
            baseline: keys::Value::Absent,
            current: keys::Value::Absent,
            pending: None,
        }),
        native_rows: keys::FullNativeRows::Unbound,
    };
    use keys::NativeJournal;
    journal.compare_exchange(&c, None, &first).unwrap();
    let mut pending = first.clone();
    pending.generation = 2;
    pending.keys[0].phase = keys::KeyPhase::CreatePending;
    journal
        .compare_exchange(&c, Some(&first), &pending)
        .unwrap();
    (disk, files, c, pending)
}
fn publish_legacy_pair(files: &mut ProtectedSessionFiles<Disk>, c: &Context) {
    let legacy = crate::member_pair::PairRecord {
        scope: c.intent.scope.clone(),
        members: [None, None],
        active: None,
        guard: crate::member_guard::Model::empty(c.intent.scope.clone()).unwrap(),
        pending_guard: None,
        dns: [None, None],
        options: None,
        closing: false,
    };
    let bytes = serde_json::to_vec(
        &serde_json::json!({"version":1,"scope":c.intent.scope,"payload":legacy}),
    )
    .unwrap();
    files
        .compare_exchange(&c.intent.scope, RecordKind::Pair, None, &bytes)
        .unwrap();
}
#[test]
fn recovery_factory_layout_preserves_legacy_branch_only_without_native_sidecars() {
    // Break: select legacy after finding a partial native receipt, or deny the
    // existing legacy layout merely because native discovery was added.
    let (disk, mut files, c) = basic_fixture();
    publish_legacy_pair(&mut files, &c);
    let before = disk.0.borrow().clone();
    let root = ProtectedRecoveryRoot::new(files);
    root.initialize(RuntimeSlot::Stable).unwrap();
    root.inspect(|facts| {
        assert_eq!(facts.layout, RecoveryLayout::LegacyOnly);
        assert!(facts.payload(RecordKind::Pair).is_some());
        assert!(facts.pair.is_none());
        assert!(!facts
            .requirements
            .contains(&RecoveryRequirement::MissingPair));
        Ok(())
    })
    .unwrap();
    assert_eq!(*disk.0.borrow(), before);
    let (disk, mut files, c, _) = fixture();
    publish_legacy_pair(&mut files, &c);
    let before = disk.0.borrow().clone();
    let root = ProtectedRecoveryRoot::new(files);
    assert!(root.initialize(RuntimeSlot::Stable).is_err());
    assert_eq!(*disk.0.borrow(), before);
}
#[test]
fn recovery_retains_actual_pending_creation_without_missing_pair_empty_adoption() {
    // Break: discard a partial native receipt because logical Pair publication
    // never happened, or turn its CreatePending bytes into a live native ACK.
    let (disk, files, c, _) = fixture();
    let before = disk.0.borrow().clone();
    let root = ProtectedRecoveryRoot::new(files);
    assert!(root.initialize(RuntimeSlot::Stable).unwrap());
    assert_eq!(
        root.facts.borrow().as_ref().unwrap().context.as_ref(),
        Some(&c)
    );
    assert_eq!(*disk.0.borrow(), before);
}
#[test]
fn recovery_unknown_create_reports_original_requirement_not_a_key_delete_grant() {
    let (disk, files, _, pending) = fixture();
    let before = disk.0.borrow().clone();
    let root = ProtectedRecoveryRoot::new(files);
    root.initialize(RuntimeSlot::Stable).unwrap();
    root.inspect(|facts| {
        assert_eq!(facts.keys.as_ref().unwrap(), &pending);
        assert!(facts
            .requirements
            .contains(&RecoveryRequirement::UnknownKeyCreate(
                keys::Role::RoleCarrier
            )));
        assert!(facts
            .requirements
            .contains(&RecoveryRequirement::MissingPair));
        Ok(())
    })
    .unwrap();
    assert_eq!(*disk.0.borrow(), before);
}

#[test]
fn recovery_preserves_pending_network_and_physical_obligations_without_empty_defaults() {
    // Break: decode only NetworkJournal and discard physical baselines, or
    // normalize a pending transition to an empty/restored network.
    let (disk, mut files, c, _) = fixture();
    let physical = serde_json::json!({
        "interface": 27, "luid": 29, "guid": vec![6; 16], "ipv6": false,
        "interface_metric": 41,
        "route": {"destination": "0.0.0.0/0", "scope": "Global",
            "interface": 27, "gateway": "192.0.2.1", "metric": 43},
        "protocol": 3, "origin": 0, "site_prefix_length": 0,
        "valid_lifetime": 4294967295u32, "preferred_lifetime": 4294967295u32,
        "flags": [0, 1, 0, 0]
    });
    let payload = serde_json::json!({
        "version": 1, "scope": c.intent.scope,
        "payload": {"journal": {"owned": [], "active": null,
            "pending": {"target": [], "active": null}, "stopping": true},
            "physical": [physical]}
    });
    let expected = serde_json::to_vec(&payload).unwrap();
    files
        .compare_exchange(&c.intent.scope, RecordKind::Network, None, &expected)
        .unwrap();
    let before = disk.0.borrow().clone();
    let root = ProtectedRecoveryRoot::new(files);
    root.initialize(RuntimeSlot::Stable).unwrap();
    root.inspect(|facts| {
        assert_eq!(
            facts.payload(RecordKind::Network),
            Some(expected.as_slice())
        );
        assert!(facts
            .requirements
            .contains(&RecoveryRequirement::OriginalNetwork));
        let network = facts.network_obligation()?.unwrap();
        let actual = serde_json::to_value(network).unwrap();
        assert_eq!(actual["physical"][0], physical);
        assert_eq!(
            actual["journal"]["pending"],
            payload["payload"]["journal"]["pending"]
        );
        assert_eq!(actual["journal"]["stopping"], true);
        Ok(())
    })
    .unwrap();
    assert_eq!(*disk.0.borrow(), before);
}

#[test]
fn cold_retirement_keeps_exact_pending_network_and_physical_baseline_history() {
    let (disk, mut files, c, _) = fixture();
    let payload = serde_json::json!({
        "version": 1, "scope": c.intent.scope,
        "payload": {"journal": {"owned": [], "active": null,
            "pending": {"target": [], "active": null}, "stopping": true},
            "physical": [{"interface": 27, "luid": 29, "guid": vec![6;16],
                "ipv6": false, "interface_metric": 41,
                "route": {"destination": "0.0.0.0/0", "scope": "Global",
                    "interface": 27, "gateway": "192.0.2.1", "metric": 43},
                "protocol": 3, "origin": 0, "site_prefix_length": 0,
                "valid_lifetime": 4294967295u32, "preferred_lifetime": 4294967295u32,
                "flags": [0,1,0,0]}]}
    });
    let bytes = serde_json::to_vec(&payload).unwrap();
    files
        .compare_exchange(&c.intent.scope, RecordKind::Network, None, &bytes)
        .unwrap();
    let before = disk.0.borrow().clone();
    let files = ProtectedSessionFiles::new(disk.clone(), c.provenance.runtime, [9; 16]).unwrap();
    let root = ProtectedRecoveryRoot::new(files);
    root.initialize(RuntimeSlot::Stable).unwrap();
    let expected = root
        .retained_facts()
        .unwrap()
        .network_obligation()
        .unwrap()
        .unwrap();
    root.retire_cold_empty(cold_inventory()).unwrap();
    assert_eq!(
        root.retained_facts().unwrap().payload(RecordKind::Network),
        Some(bytes.as_slice())
    );
    assert_eq!(
        serde_json::to_value(root.retained_facts().unwrap().network_obligation().unwrap()).unwrap(),
        serde_json::to_value(Some(expected)).unwrap()
    );
    for (file, bytes) in before {
        if file != PrivateFile::Index {
            assert_eq!(disk.0.borrow().get(&file), Some(&bytes));
        }
    }
}
#[test]
fn recovery_reentry_and_callback_faults_revoke_reads_but_preserve_original_history() {
    for case in 0..3 {
        let (disk, files, _, _) = fixture();
        let before = disk.0.borrow().clone();
        let root = ProtectedRecoveryRoot::new(files);
        root.initialize(RuntimeSlot::Stable).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            root.inspect(|_| {
                if case == 0 {
                    assert!(root.inspect(|_| Ok(())).is_err());
                    Ok(())
                } else if case == 1 {
                    Err(conflict())
                } else {
                    panic!("recovery comparison unwound");
                }
            })
        }));
        if case == 2 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert!(root.inspect(|_| Ok(())).is_err());
        assert!(root.retained_facts().unwrap().keys.is_some());
        assert_eq!(*disk.0.borrow(), before);
    }
}
#[test]
fn recovery_changed_boot_remains_explicit_and_never_changes_retained_context() {
    let (disk, _, c, _) = fixture();
    let caller =
        ProtectedSessionFiles::new(disk.clone(), c.provenance.runtime.clone(), [8; 16]).unwrap();
    let before = disk.0.borrow().clone();
    let root = ProtectedRecoveryRoot::new(caller);
    root.initialize(RuntimeSlot::Stable).unwrap();
    root.inspect(|facts| {
        assert!(facts.changed_boot);
        assert_eq!(facts.context.as_ref(), Some(&c));
        assert!(facts
            .requirements
            .contains(&RecoveryRequirement::ChangedBootNativeEmpty));
        Ok(())
    })
    .unwrap();
    assert_eq!(*disk.0.borrow(), before);
}

#[test]
fn recovery_current_private_replacement_is_not_a_refresh_or_completion() {
    for file in [
        PrivateFile::Index,
        PrivateFile::Session,
        PrivateFile::NativeCarrierReceipts,
    ] {
        let (disk, files, _, _) = fixture();
        let root = ProtectedRecoveryRoot::new(files);
        root.initialize(RuntimeSlot::Stable).unwrap();
        assert!(root
            .inspect(|_| {
                // Even identical parsed JSON with changed canonical private bytes
                // is not this selection. Original records/claim remain untouched.
                disk.0.borrow_mut().get_mut(&file).unwrap().push(b' ');
                Ok(())
            })
            .is_err());
        assert!(root.inspect(|_| Ok(())).is_err());
        assert!(root.retained_facts().unwrap().keys.is_some());
        assert!(!disk
            .0
            .borrow()
            .keys()
            .any(|f| matches!(f, PrivateFile::Completed(_))));
    }
}

#[test]
fn recovery_absent_session_unknown_version_and_removed_native_sidecar_fail_closed() {
    for case in 0..3 {
        let (disk, files, _, _) = fixture();
        if case == 0 {
            disk.0.borrow_mut().remove(&PrivateFile::Session);
        }
        if case == 1 {
            let mut d = disk.0.borrow_mut();
            let raw = d.get_mut(&PrivateFile::NativeCarrierReceipts).unwrap();
            let mut envelope: serde_json::Value = serde_json::from_slice(raw).unwrap();
            let mut payload: serde_json::Value =
                serde_json::from_str(envelope["data"].as_str().unwrap()).unwrap();
            payload["version"] = 99.into();
            envelope["data"] = serde_json::to_string(&payload).unwrap().into();
            *raw = serde_json::to_vec(&envelope).unwrap();
        }
        let root = ProtectedRecoveryRoot::new(files);
        if case == 2 {
            root.initialize(RuntimeSlot::Stable).unwrap();
            disk.0
                .borrow_mut()
                .remove(&PrivateFile::NativeCarrierReceipts);
            assert!(root.inspect(|_| Ok(())).is_err());
        } else if case == 0 {
            root.initialize(RuntimeSlot::Stable).unwrap();
            root.inspect(|facts| {
                assert!(facts
                    .requirements
                    .contains(&RecoveryRequirement::MissingSession));
                assert!(facts.keys.is_some());
                Ok(())
            })
            .unwrap();
        } else {
            assert!(root.initialize(RuntimeSlot::Stable).is_err());
        }
        assert!(!disk
            .0
            .borrow()
            .keys()
            .any(|f| matches!(f, PrivateFile::Completed(_))));
    }
}

#[test]
fn recovery_same_epoch_session_updates_cannot_auto_refresh_frozen_records() {
    let (disk, files, c, _) = fixture();
    let mut session =
        WindowsSessionStore::open(files.clone(), c.intent.scope.clone(), RecordKind::Session)
            .unwrap()
            .0;
    let root = ProtectedRecoveryRoot::new(files);
    root.initialize(RuntimeSlot::Stable).unwrap();
    let mut state = SessionState::new(c.intent.scope.clone(), Slot::A, 0, 0).unwrap();
    state.begin_stop(&c.intent.scope).unwrap();
    session.save(&state.snapshot()).unwrap();
    assert!(root.inspect(|_| Ok(())).is_err());
    assert!(root
        .retained_facts()
        .unwrap()
        .payload(RecordKind::Session)
        .is_some());
    assert!(!disk
        .0
        .borrow()
        .keys()
        .any(|f| matches!(f, PrivateFile::Completed(_))));
}

#[test]
fn recovery_read_root_is_once_attempted_and_no_active_claim_is_not_native_empty() {
    let disk = Disk::default();
    let c = context();
    let files =
        ProtectedSessionFiles::new(disk.clone(), c.provenance.runtime, c.provenance.boot_id)
            .unwrap();
    let root = ProtectedRecoveryRoot::new(files);
    assert!(!root.initialize(RuntimeSlot::Stable).unwrap());
    assert!(root.inspect(|_| Ok(())).is_err());
    assert!(root.initialize(RuntimeSlot::Stable).is_err());
    assert!(disk.0.borrow().is_empty());
}

#[test]
fn recovery_initial_postflight_fault_and_unwind_retain_sample_before_denial() {
    // Break: construct an obligation root only after private postflight, or
    // retry initialization/readback as a successful acknowledgement.
    for unwind in [false, true] {
        let (disk, _, c, pending) = fixture();
        let before = disk.0.borrow().clone();
        let fault = PostflightFaultDisk {
            disk: disk.clone(),
            index_reads: Rc::new(Cell::new(0)),
            unwind,
        };
        let files =
            ProtectedSessionFiles::new(fault, c.provenance.runtime, c.provenance.boot_id).unwrap();
        let root = ProtectedRecoveryRoot::new(files);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            root.initialize(RuntimeSlot::Stable)
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert_eq!(root.retained_facts().unwrap().keys.as_ref(), Some(&pending));
        assert!(root.inspect(|_| Ok(())).is_err());
        assert!(root.initialize(RuntimeSlot::Stable).is_err());
        assert_eq!(*disk.0.borrow(), before);
    }
}

// Explicit OS-inventory boundary double only. The protected claim, opaque proof
// protocol, exact snapshot fence and atomic index CAS are production code.
struct ColdInventory {
    before: [u8; 8],
    after: [u8; 8],
    entered: Cell<usize>,
    omit: bool,
}
unsafe impl NativeColdEmptyInventory for ColdInventory {
    fn inspect_empty(
        &self,
        facts: &RecoveryFacts,
        call: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        assert_eq!(facts.context.as_ref().unwrap().provenance.boot_id, [7; 16]);
        let check = |statuses: &[u8; 8]| {
            // SCM/mixed NIC/addresses/interfaces/routes/registry/BFE/DNS+physical.
            // 0 = complete EMPTY; present/unknown/partial/read-error never EMPTY.
            if statuses.iter().any(|v| *v != 0) {
                Err(conflict())
            } else {
                Ok(())
            }
        };
        check(&self.before)?;
        if !self.omit {
            self.entered.set(self.entered.get() + 1);
            call()?;
        }
        check(&self.after)
    }
}
fn cold_inventory() -> Rc<ColdInventory> {
    Rc::new(ColdInventory {
        before: [0; 8],
        after: [0; 8],
        entered: Cell::new(0),
        omit: false,
    })
}
fn cold_fixture() -> (Disk, ProtectedSessionFiles<Disk>, Context) {
    let (disk, _, context, _) = fixture();
    let cold =
        ProtectedSessionFiles::new(disk.clone(), context.provenance.runtime.clone(), [9; 16])
            .unwrap();
    (disk, cold, context)
}
#[test]
fn cold_empty_retires_original_claim_preserves_pending_bytes_and_permanent_replay_fence() {
    // Break: demand fabricated Stopped records, rewrite pending receipts, skip
    // native proof, or allow the retired scope to be reclaimed.
    let (disk, files, c) = cold_fixture();
    let original = disk.0.borrow().clone();
    let mut caller_files = files.clone();
    let root = ProtectedRecoveryRoot::new(files);
    root.initialize(RuntimeSlot::Stable).unwrap();
    let inventory = cold_inventory();
    let ack = root.retire_cold_empty(inventory.clone()).unwrap();
    assert_eq!(ack.scope(), &c.intent.scope);
    assert_eq!(inventory.entered.get(), 2);
    for (file, bytes) in &original {
        if *file != PrivateFile::Index {
            assert_eq!(disk.0.borrow().get(file), Some(bytes));
        }
    }
    assert!(caller_files.claim(&c.intent.scope).is_err());
    assert!(caller_files.scopes(RuntimeSlot::Stable).unwrap().is_empty());
    assert!(root.retire_cold_empty(cold_inventory()).is_err());
    let mut next = c.intent.scope.clone();
    next.connection_generation += 1;
    caller_files.claim(&next).unwrap();
    assert!(caller_files
        .read(&next, RecordKind::NativeCarrierReceipts)
        .unwrap()
        .is_none());
    assert_eq!(
        disk.0.borrow()[&PrivateFile::NativeCarrierReceipts],
        original[&PrivateFile::NativeCarrierReceipts]
    );
}

#[test]
fn cold_empty_denies_each_present_unknown_partial_native_family_and_missing_callback() {
    for family in 0..8 {
        for status in [1, 2, 3, 4] {
            let (disk, files, _) = cold_fixture();
            let original = disk.0.borrow().clone();
            let root = ProtectedRecoveryRoot::new(files);
            root.initialize(RuntimeSlot::Stable).unwrap();
            let mut before = [0; 8];
            before[family] = status;
            let inventory = Rc::new(ColdInventory {
                before,
                after: [0; 8],
                entered: Cell::new(0),
                omit: false,
            });
            assert!(root.retire_cold_empty(inventory).is_err());
            assert_eq!(*disk.0.borrow(), original);
            assert!(root.retained_facts().unwrap().keys.is_some());
            assert!(root.retire_cold_empty(cold_inventory()).is_err());
        }
    }
    let (disk, files, _) = cold_fixture();
    let original = disk.0.borrow().clone();
    let root = ProtectedRecoveryRoot::new(files);
    root.initialize(RuntimeSlot::Stable).unwrap();
    assert!(root
        .retire_cold_empty(Rc::new(ColdInventory {
            before: [0; 8],
            after: [0; 8],
            entered: Cell::new(0),
            omit: true
        }))
        .is_err());
    assert_eq!(*disk.0.borrow(), original);
}

struct HookInventory {
    hook: RefCell<Box<dyn FnMut(usize) -> io::Result<()>>>,
    calls: Cell<usize>,
    repeat: bool,
}
unsafe impl NativeColdEmptyInventory for HookInventory {
    fn inspect_empty(
        &self,
        _: &RecoveryFacts,
        callback: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        let n = self.calls.get() + 1;
        self.calls.set(n);
        (self.hook.borrow_mut())(n)?; // explicit OS boundary fault/mutation
        callback()?;
        if self.repeat {
            let _ = callback();
        } // deliberately swallowed duplicate
        if n == 2 {
            (self.hook.borrow_mut())(3)?;
        }
        Ok(())
    }
}
#[test]
fn cold_empty_fences_reentry_duplicate_callbacks_foreign_backend_and_current_replacement() {
    for failure in 0..4 {
        let (disk, files, c) = cold_fixture();
        let original = disk.0.borrow().clone();
        let root = Rc::new(ProtectedRecoveryRoot::new(files));
        root.initialize(RuntimeSlot::Stable).unwrap();
        let weak = Rc::downgrade(&root);
        let changed = disk.clone();
        let inventory = Rc::new(HookInventory {
            calls: Cell::new(0),
            repeat: failure == 3,
            hook: RefCell::new(Box::new(move |n| {
                if n == 1 {
                    let root = weak.upgrade().unwrap();
                    match failure {
                        0 => {
                            assert!(root.inspect(|_| Ok(())).is_err());
                        }
                        1 => {
                            changed
                                .0
                                .borrow_mut()
                                .get_mut(&PrivateFile::NativeCarrierReceipts)
                                .unwrap()
                                .push(b' ');
                        }
                        2 => {
                            *root.files.borrow_mut() = ProtectedSessionFiles::new(
                                changed.clone(),
                                c.provenance.runtime.clone(),
                                [9; 16],
                            )
                            .unwrap();
                        }
                        _ => {}
                    }
                }
                Ok(())
            })),
        });
        assert!(root.retire_cold_empty(inventory).is_err());
        assert!(root.retained_cold_retirement_ack().unwrap().is_none());
        assert!(root.retire_cold_empty(cold_inventory()).is_err());
        assert!(!disk
            .0
            .borrow()
            .keys()
            .any(|k| matches!(k, PrivateFile::Completed(_))));
        if failure != 1 {
            assert_eq!(*disk.0.borrow(), original);
        }
    }
}
#[derive(Clone, Copy, Default, PartialEq)]
enum ColdFault {
    #[default]
    None,
    MarkerLost,
    MarkerFalse,
    IndexLost,
    IndexFalse,
    MarkerRead,
    IndexRead,
    PostRead,
    PostUnwind,
}
#[derive(Clone)]
struct ColdFaultDisk {
    disk: Disk,
    fault: Rc<Cell<ColdFault>>,
}
impl PrivateRecords for ColdFaultDisk {
    fn read(&mut self, file: PrivateFile) -> io::Result<Option<Vec<u8>>> {
        let bytes = self.disk.read(file)?;
        let fault = self.fault.get();
        let retired = self
            .disk
            .0
            .borrow()
            .get(&PrivateFile::Index)
            .is_some_and(|b| {
                serde_json::from_slice::<serde_json::Value>(b).unwrap()["active"].is_null()
            });
        let fail = (fault == ColdFault::MarkerRead
            && matches!(file, PrivateFile::Completed(_))
            && bytes.is_some())
            || (fault == ColdFault::IndexRead && file == PrivateFile::Index && retired)
            || (matches!(fault, ColdFault::PostRead | ColdFault::PostUnwind)
                && file == PrivateFile::NativeCarrierReceipts
                && retired);
        if fail {
            self.fault.set(ColdFault::None);
            if fault == ColdFault::PostUnwind {
                panic!("actual cold private postflight unwind");
            }
            return Err(conflict());
        }
        Ok(bytes)
    }
    fn compare_exchange(
        &mut self,
        file: PrivateFile,
        expected: Option<&[u8]>,
        desired: &[u8],
    ) -> io::Result<()> {
        let fault = self.fault.get();
        let selected = (matches!(fault, ColdFault::MarkerLost | ColdFault::MarkerFalse)
            && matches!(file, PrivateFile::Completed(_)))
            || (matches!(fault, ColdFault::IndexLost | ColdFault::IndexFalse)
                && file == PrivateFile::Index);
        if selected {
            self.fault.set(ColdFault::None);
        }
        if selected && matches!(fault, ColdFault::MarkerFalse | ColdFault::IndexFalse) {
            return Ok(());
        }
        self.disk.compare_exchange(file, expected, desired)?;
        if selected {
            Err(conflict())
        } else {
            Ok(())
        }
    }
}
impl SessionFileIo for ColdFaultDisk {
    fn transaction<T>(
        &mut self,
        callback: impl FnOnce(&mut dyn PrivateRecords) -> io::Result<T>,
    ) -> io::Result<T> {
        callback(self)
    }
}
#[test]
fn cold_retirement_cas_faults_never_import_success_and_postflight_keeps_actual_ack() {
    for fault in [
        ColdFault::MarkerLost,
        ColdFault::MarkerFalse,
        ColdFault::IndexLost,
        ColdFault::IndexFalse,
        ColdFault::MarkerRead,
        ColdFault::IndexRead,
        ColdFault::PostRead,
        ColdFault::PostUnwind,
    ] {
        let (disk, _, c) = cold_fixture();
        let original = disk.0.borrow().clone();
        let mode = Rc::new(Cell::new(ColdFault::None));
        let files = ProtectedSessionFiles::new(
            ColdFaultDisk {
                disk: disk.clone(),
                fault: mode.clone(),
            },
            c.provenance.runtime,
            [9; 16],
        )
        .unwrap();
        let root = ProtectedRecoveryRoot::new(files);
        root.initialize(RuntimeSlot::Stable).unwrap();
        mode.set(fault);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            root.retire_cold_empty(cold_inventory())
        }));
        if fault == ColdFault::PostUnwind {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        let retained = root.retained_cold_retirement_ack().unwrap();
        assert_eq!(
            retained.is_some(),
            matches!(fault, ColdFault::PostRead | ColdFault::PostUnwind)
        );
        assert!(root.retire_cold_empty(cold_inventory()).is_err());
        assert!(root.retained_facts().unwrap().keys.is_some());
        for (file, bytes) in &original {
            if *file != PrivateFile::Index {
                assert_eq!(disk.0.borrow().get(file), Some(bytes));
            }
        }
    }
}

#[test]
fn cold_native_postflight_fault_retains_original_ack_without_returning_empty_success() {
    let (disk, files, _) = cold_fixture();
    let original = disk.0.borrow().clone();
    let root = ProtectedRecoveryRoot::new(files);
    root.initialize(RuntimeSlot::Stable).unwrap();
    let inventory = Rc::new(HookInventory {
        calls: Cell::new(0),
        repeat: false,
        hook: RefCell::new(Box::new(|n| if n == 3 { Err(conflict()) } else { Ok(()) })),
    });
    assert!(root.retire_cold_empty(inventory).is_err());
    assert!(root.retained_cold_retirement_ack().unwrap().is_some());
    for (file, bytes) in original {
        if file != PrivateFile::Index {
            assert_eq!(disk.0.borrow().get(&file), Some(&bytes));
        }
    }
}

#[test]
fn cold_empty_missing_context_and_legacy_layout_never_retire_a_claim() {
    for legacy in [false, true] {
        let (disk, mut files, c) = basic_fixture();
        if legacy {
            publish_legacy_pair(&mut files, &c);
        } else {
            let record = pair::Record {
                version: 2,
                scope: c.intent.scope.clone(),
                provenance: c.provenance.clone(),
                revision: 1,
                phase: pair::Phase::Fresh,
                addresses: vec![],
                dns: vec![],
                carrier: None,
                members: [None, None],
                active: None,
                options: None,
                guard: crate::member_carrier_guard::Model::empty(c.intent.scope.clone()).unwrap(),
                pending_guard: None,
                pending: None,
                network: None,
                stop_stage: 0,
                operation: None,
            };
            files
                .compare_exchange(
                    &c.intent.scope,
                    RecordKind::Pair,
                    None,
                    &pair_store::encode_carrier_payload(&record).unwrap(),
                )
                .unwrap();
        }
        let files =
            ProtectedSessionFiles::new(disk.clone(), c.provenance.runtime, [9; 16]).unwrap();
        let before = disk.0.borrow().clone();
        let root = ProtectedRecoveryRoot::new(files);
        root.initialize(RuntimeSlot::Stable).unwrap();
        assert!(root.retained_facts().unwrap().context.is_none());
        let scanner = cold_inventory();
        assert!(root.retire_cold_empty(scanner.clone()).is_err());
        assert_eq!(scanner.entered.get(), 0);
        assert_eq!(*disk.0.borrow(), before);
    }
}

#[test]
fn cold_retirement_marker_authenticates_preserved_payloads_not_terminal_json() {
    for missing in [false, true] {
        let (disk, files, c) = cold_fixture();
        let mut caller = files.clone();
        let root = ProtectedRecoveryRoot::new(files);
        root.initialize(RuntimeSlot::Stable).unwrap();
        root.retire_cold_empty(cold_inventory()).unwrap();
        // Same parsed receipt is NOT the committed retirement's exact payload.
        if missing {
            disk.0
                .borrow_mut()
                .remove(&PrivateFile::NativeCarrierReceipts);
        } else {
            disk.0
                .borrow_mut()
                .get_mut(&PrivateFile::NativeCarrierReceipts)
                .unwrap()
                .push(b' ');
        }
        assert!(caller.scopes(RuntimeSlot::Stable).is_err());
        let mut next = c.intent.scope;
        next.connection_generation += 1;
        assert!(caller.claim(&next).is_err());
    }
}

#[test]
fn cold_marker_lost_ack_requires_a_new_original_empty_proof_not_readback_adoption() {
    let (disk, _, c) = cold_fixture();
    let mode = Rc::new(Cell::new(ColdFault::None));
    let files = ProtectedSessionFiles::new(
        ColdFaultDisk {
            disk: disk.clone(),
            fault: mode.clone(),
        },
        c.provenance.runtime,
        [9; 16],
    )
    .unwrap();
    let root = ProtectedRecoveryRoot::new(files.clone());
    root.initialize(RuntimeSlot::Stable).unwrap();
    let old_index = disk.0.borrow()[&PrivateFile::Index].clone();
    mode.set(ColdFault::MarkerLost);
    assert!(root.retire_cold_empty(cold_inventory()).is_err());
    assert!(root.retained_cold_retirement_ack().unwrap().is_none());
    assert_eq!(disk.0.borrow()[&PrivateFile::Index], old_index);
    assert!(root.retire_cold_empty(cold_inventory()).is_err());
    let retry = ProtectedRecoveryRoot::new(files);
    retry.initialize(RuntimeSlot::Stable).unwrap();
    let scanner = cold_inventory();
    retry.retire_cold_empty(scanner.clone()).unwrap();
    assert_eq!(scanner.entered.get(), 2); // marker alone never substitutes for SDK proof
    assert!(retry.retained_cold_retirement_ack().unwrap().is_some());
}

#[test]
fn cold_empty_both_native_bracket_failures_and_unwinds_remain_sticky() {
    for phase in [1, 2, 3] {
        for unwind in [false, true] {
            let (disk, files, _) = cold_fixture();
            let before = disk.0.borrow().clone();
            let root = ProtectedRecoveryRoot::new(files);
            root.initialize(RuntimeSlot::Stable).unwrap();
            let scanner = Rc::new(HookInventory {
                calls: Cell::new(0),
                repeat: false,
                hook: RefCell::new(Box::new(move |n| {
                    if n != phase {
                        return Ok(());
                    }
                    if unwind {
                        panic!("actual independent cold inventory unwind");
                    }
                    Err(conflict())
                })),
            });
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                root.retire_cold_empty(scanner)
            }));
            if unwind {
                assert!(result.is_err());
            } else {
                assert!(result.unwrap().is_err());
            }
            assert_eq!(
                root.retained_cold_retirement_ack().unwrap().is_some(),
                phase == 3
            );
            assert!(root.retire_cold_empty(cold_inventory()).is_err());
            for (file, bytes) in &before {
                if phase != 3 || *file != PrivateFile::Index {
                    assert_eq!(disk.0.borrow().get(file), Some(bytes));
                }
            }
        }
    }
}

struct SwallowedCallbackFault {
    disk: Disk,
    calls: Cell<usize>,
}
unsafe impl NativeColdEmptyInventory for SwallowedCallbackFault {
    fn inspect_empty(
        &self,
        _: &RecoveryFacts,
        callback: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        let n = self.calls.get() + 1;
        self.calls.set(n);
        if n != 1 {
            return callback();
        }
        let old = self.disk.0.borrow()[&PrivateFile::NativeCarrierReceipts].clone();
        self.disk
            .0
            .borrow_mut()
            .get_mut(&PrivateFile::NativeCarrierReceipts)
            .unwrap()
            .push(b' ');
        assert!(callback().is_err());
        self.disk
            .0
            .borrow_mut()
            .insert(PrivateFile::NativeCarrierReceipts, old);
        Ok(()) // erroneous scanner cannot turn a caught protected fault into proof
    }
}
#[test]
fn cold_empty_caught_callback_failure_cannot_refresh_original_selection() {
    let (disk, files, _) = cold_fixture();
    let before = disk.0.borrow().clone();
    let root = ProtectedRecoveryRoot::new(files);
    root.initialize(RuntimeSlot::Stable).unwrap();
    assert!(root
        .retire_cold_empty(Rc::new(SwallowedCallbackFault {
            disk: disk.clone(),
            calls: Cell::new(0)
        }))
        .is_err());
    assert!(root.retained_cold_retirement_ack().unwrap().is_none());
    assert_eq!(*disk.0.borrow(), before);
}

struct DuplicateRetirementCallback(Cell<usize>);
unsafe impl NativeColdEmptyInventory for DuplicateRetirementCallback {
    fn inspect_empty(
        &self,
        _: &RecoveryFacts,
        callback: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        let count = self.0.get() + 1;
        self.0.set(count);
        callback()?;
        if count == 2 {
            assert!(callback().is_err());
        }
        Ok(()) // caught duplication after real commit must still deny success
    }
}
#[test]
fn cold_duplicate_after_actual_retirement_keeps_ack_history_but_denies_success() {
    let (disk, files, c) = cold_fixture();
    let before = disk.0.borrow().clone();
    let root = ProtectedRecoveryRoot::new(files);
    root.initialize(RuntimeSlot::Stable).unwrap();
    assert!(root
        .retire_cold_empty(Rc::new(DuplicateRetirementCallback(Cell::new(0))))
        .is_err());
    assert_eq!(
        root.retained_cold_retirement_ack()
            .unwrap()
            .unwrap()
            .scope(),
        &c.intent.scope
    );
    assert!(root.retire_cold_empty(cold_inventory()).is_err());
    for (file, bytes) in before {
        if file != PrivateFile::Index {
            assert_eq!(disk.0.borrow().get(&file), Some(&bytes));
        }
    }
}

fn canonical_context() -> (Context, [std::path::PathBuf; 2]) {
    let mut c = context();
    // Fixed trusted basenames: platform spelling is only query DATA here.
    let paths = ["nelomai-a.conf", "nelomai-b.conf"].map(|name| std::env::temp_dir().join(name));
    let carrier = crate::member_carrier::carrier_key(&c.intent.scope).unwrap();
    let text: String = carrier
        .guid
        .iter()
        .enumerate()
        .map(|(i, b)| {
            format!(
                "{}{b:02x}",
                if matches!(i, 4 | 6 | 8 | 10) { "-" } else { "" }
            )
        })
        .collect();
    c.bindings[0] = keys::Binding {
        role: keys::Role::RoleCarrier,
        guid: carrier.guid,
        name: carrier.name,
        registry_path: format!(
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{{text}}}"
        ),
    };
    for (i, slot) in [
        nelomai_contracts::dispatcher::TunnelSlot::A,
        nelomai_contracts::dispatcher::TunnelSlot::B,
    ]
    .into_iter()
    .enumerate()
    {
        c.bindings[i + 1] = crate::member_native_guid::member_binding(
            crate::member_native_guid::ProviderPath::WireGuardSignedDll,
            crate::member_native_guid::WG_SOURCE_REVISION,
            slot,
            &paths[i],
            crate::redundancy::slot_service_name(
                slot,
                nelomai_client_tunnel::TunnelTransport::WireGuard,
            ),
        )
        .unwrap();
    }
    (c, paths)
}
#[test]
fn cold_scanner_namespace_covers_both_transports_and_rejects_saved_aliases() {
    // Break: trust saved Context as the entire namespace, omit AWG, or repair
    // a foreign GUID/name/config basename into a canonical identity.
    let (c, paths) = canonical_context();
    let all = cold_namespace(&c, [&paths[0], &paths[1]]).unwrap();
    let names: Vec<_> = all.iter().map(|b| b.name.as_str()).collect();
    assert!(names.contains(&"nelomai-a"));
    assert!(names.contains(&"nelomai-b"));
    assert!(names.contains(&"NelomaiAmneziaWg3A"));
    assert!(names.contains(&"NelomaiAmneziaWg3B"));
    assert_eq!(all.len(), 5);
    for changed in 0..3 {
        let mut foreign = c.clone();
        if changed == 0 {
            foreign.bindings[0].name.push('x');
        }
        if changed == 1 {
            foreign.bindings[1].guid[0] ^= 1;
        }
        if changed == 2 {
            foreign.bindings[2].registry_path.push('x');
        }
        assert!(cold_namespace(&foreign, [&paths[0], &paths[1]]).is_err());
    }
    let bad = paths[0].with_file_name("foreign.conf");
    assert!(cold_namespace(&c, [&bad, &paths[1]]).is_err());
}
#[test]
fn cold_scanner_network_comparison_denies_present_route_without_old_index_io() {
    // Break: ignore the protected pending route, compare only metrics, or use
    // a default empty SDK model instead of the supplied fresh full table.
    use nelomai_client_tunnel::redundancy::network::{RouteScope, RouteValue};
    let (disk, mut files, c, _) = fixture();
    let route = RouteValue {
        destination: "198.51.100.10/32".parse().unwrap(),
        scope: RouteScope::WindowsInterface(27),
        interface: 27,
        gateway: Some("192.0.2.1".parse().unwrap()),
        metric: 7,
    };
    let payload = serde_json::json!({"version":1,"scope":c.intent.scope,
        "payload":{"journal":{"owned":[],"active":null,"pending":{"target":[
            {"original":null,"current":{"Route":route}}],"active":null},"stopping":true},"physical":[]}});
    files
        .compare_exchange(
            &c.intent.scope,
            RecordKind::Network,
            None,
            &serde_json::to_vec(&payload).unwrap(),
        )
        .unwrap();
    let before = disk.0.borrow().clone();
    let root = ProtectedRecoveryRoot::new(files);
    root.initialize(RuntimeSlot::Stable).unwrap();
    let facts = root.retained_facts().unwrap();
    let empty = crate::member_physical::PhysicalSnapshot::new(vec![], vec![], &[]).unwrap();
    cold_network_rows(&facts, &empty).unwrap();
    let mut foreign_metric = route.clone();
    foreign_metric.metric = 999;
    let present = crate::member_routes::Row::static_route(
        foreign_metric,
        crate::member_routes::NativeProof {
            index: 27,
            luid: 29,
        },
    );
    let identity = crate::member_physical::InterfaceIdentity {
        index: 27,
        luid: 29,
        guid: [6; 16],
    };
    let interface = crate::member_physical::InterfaceRecord {
        proof: crate::member_physical::PhysicalProof {
            identity,
            family: crate::member_physical::Family::V4,
            metric: 41,
        },
        alias: "Ethernet".into(),
        if_type: 6,
        tunnel_type: 0,
        oper_status: 1,
        status_flags: 1,
    };
    let table =
        crate::member_physical::PhysicalSnapshot::new(vec![present], vec![interface], &[]).unwrap();
    assert!(cold_network_rows(&facts, &table).is_err());
    assert_eq!(*disk.0.borrow(), before);
}

#[test]
fn cold_scanner_full_tables_reject_orphans_unknown_families_and_foreign_vip() {
    // Break: treat incomplete tables as EMPTY, assume old numeric indices still
    // identify C, or ignore an owned VIP present on a different physical NIC.
    let (c, paths) = canonical_context();
    let targets = cold_namespace(&c, [&paths[0], &paths[1]]).unwrap();
    let physical = crate::member_physical::InterfaceIdentity {
        index: 27,
        luid: 29,
        guid: [6; 16],
    };
    let ips = [(2, 27, 29), (23, 27, 29)];
    cold_mib_empty(&c, &targets, &[physical], &ips, &[]).unwrap();
    for binding in &targets {
        let own = crate::member_physical::InterfaceIdentity {
            guid: binding.guid,
            ..physical
        };
        assert!(cold_mib_empty(&c, &targets, &[own], &ips, &[]).is_err());
    }
    for bad in [(0, 27, 29), (2, 999, 29), (2, 27, 999)] {
        assert!(cold_mib_empty(&c, &targets, &[physical], &[bad], &[]).is_err());
    }
    assert!(cold_mib_empty(&c, &targets, &[physical, physical], &ips, &[]).is_err());
    assert!(cold_mib_empty(
        &c,
        &targets,
        &[physical],
        &ips,
        &[(27, 29, "10.7.0.2".parse().unwrap())]
    )
    .is_err());
    assert!(cold_mib_empty(
        &c,
        &targets,
        &[physical],
        &ips,
        &[(999, 29, "192.0.2.10".parse().unwrap())]
    )
    .is_err());
    cold_mib_empty(
        &c,
        &targets,
        &[physical],
        &ips,
        &[(27, 29, "192.0.2.10".parse().unwrap())],
    )
    .unwrap();
}

#[test]
fn cold_scanner_member_journals_are_obligations_not_original_process_ack() {
    use crate::member_owner::{Intent, InterfaceProof, NativeProof, Phase, ProcessProof, Record};
    use nelomai_contracts::dispatcher::TunnelSlot;
    let (c, paths) = canonical_context();
    let targets = cold_namespace(&c, [&paths[0], &paths[1]]).unwrap();
    let engine_path = std::env::temp_dir().join("protected-engine.exe");
    let engine = engine_path.as_path();
    let record = Record {
        intent: Intent {
            scope: c.intent.scope.clone(),
            slot: TunnelSlot::A,
            transport: nelomai_client_tunnel::TunnelTransport::WireGuard,
            engine: engine.to_owned(),
            config_sha256: [4; 32],
        },
        phase: Phase::Running,
        proof: Some(NativeProof {
            process: ProcessProof {
                pid: 12,
                creation_time: 34,
            },
            interface: InterfaceProof {
                index: 17,
                luid: 19,
                guid: c.bindings[1].guid,
            },
        }),
        retired_proof: None,
        previous_config_sha256: None,
    };
    let bytes = serde_json::to_vec(&record).unwrap();
    assert_eq!(
        cold_member_record(&bytes, TunnelSlot::A, &c, engine, &targets).unwrap(),
        record
    );
    // Running data remains Running data; only the independent scanner may
    // prove absence. No JSON-to-Stopped receipt or original creator pin.
    for mutation in 0..8 {
        let mut bad = record.clone();
        match mutation {
            0 => bad.intent.slot = TunnelSlot::B,
            1 => bad.intent.scope.connection_generation += 1,
            2 => bad.intent.engine = "foreign.exe".into(),
            3 => bad.proof = None,
            4 => bad.proof.as_mut().unwrap().process.pid = 0,
            5 => bad.proof.as_mut().unwrap().interface.luid = 0,
            6 => bad.proof.as_mut().unwrap().interface.guid = [99; 16],
            _ => bad.previous_config_sha256 = Some([9; 32]),
        }
        assert!(cold_member_record(
            &serde_json::to_vec(&bad).unwrap(),
            TunnelSlot::A,
            &c,
            engine,
            &targets
        )
        .is_err());
    }
}

#[test]
fn cold_scanner_uses_original_state_backend_not_distinct_install_root() {
    let root = std::env::temp_dir();
    let install = root.join("ProgramFiles/Nelomai/privileged");
    let state = root.join("ProgramData/Nelomai/Tunnel");
    let paths = [state.join("nelomai-a.conf"), state.join("nelomai-b.conf")];
    assert_ne!(install, state);
    cold_state_paths(&state, &state, [&paths[0], &paths[1]]).unwrap();
    assert!(cold_state_paths(&state, &install, [&paths[0], &paths[1]]).is_err());
    let wrong = [
        install.join("nelomai-a.conf"),
        install.join("nelomai-b.conf"),
    ];
    assert!(cold_state_paths(&state, &state, [&wrong[0], &wrong[1]]).is_err());
    assert!(cold_state_paths(&state, &state, [&paths[1], &paths[0]]).is_err());
}

#[test]
fn cold_scanner_retained_stopped_slot_can_be_fresh_predecessor_not_running_adoption() {
    use crate::member_owner::{Intent, Phase, Record};
    use nelomai_contracts::dispatcher::TunnelSlot;
    let (c, paths) = canonical_context();
    let targets = cold_namespace(&c, [&paths[0], &paths[1]]).unwrap();
    let engine = std::env::temp_dir().join("old-signed-engine.exe");
    let mut old_scope = c.intent.scope.clone();
    old_scope.connection_generation -= 1;
    let old = Record {
        intent: Intent {
            scope: old_scope,
            slot: TunnelSlot::A,
            transport: nelomai_client_tunnel::TunnelTransport::WireGuard,
            engine: engine.clone(),
            config_sha256: [1; 32],
        },
        phase: Phase::Stopped,
        proof: None,
        retired_proof: None,
        previous_config_sha256: None,
    };
    let current_engine = std::env::temp_dir().join("current-signed-engine.exe");
    let parsed = cold_member_record(
        &serde_json::to_vec(&old).unwrap(),
        TunnelSlot::A,
        &c,
        &current_engine,
        &targets,
    )
    .unwrap();
    assert_eq!(parsed, old); // never relabel terminal or mint an old SCM ACK
    let new_intent = Intent {
        scope: c.intent.scope.clone(),
        engine: current_engine.clone(),
        ..old.intent.clone()
    };
    crate::member_owner::validate_prior_stopped(&new_intent, &parsed).unwrap();
    let mut running = old.clone();
    running.phase = Phase::Stopping;
    assert!(cold_member_record(
        &serde_json::to_vec(&running).unwrap(),
        TunnelSlot::A,
        &c,
        &current_engine,
        &targets
    )
    .is_err());
    assert!(crate::member_owner::validate_prior_stopped(&new_intent, &running).is_err());
}

#[test]
fn cold_scanner_stopped_other_transport_retired_proof_remains_an_absence_obligation() {
    use crate::member_owner::{Intent, InterfaceProof, NativeProof, Phase, ProcessProof, Record};
    use nelomai_contracts::dispatcher::TunnelSlot;
    let (c, paths) = canonical_context();
    let targets = cold_namespace(&c, [&paths[0], &paths[1]]).unwrap();
    let engine = std::env::temp_dir().join("old-signed-engine.exe");
    let mut old_scope = c.intent.scope.clone();
    old_scope.connection_generation -= 1;
    let mut old = Record {
        intent: Intent {
            scope: old_scope,
            slot: TunnelSlot::A,
            transport: nelomai_client_tunnel::TunnelTransport::AmneziaWg3,
            engine: engine.clone(),
            config_sha256: [1; 32],
        },
        phase: Phase::Stopped,
        proof: None,
        retired_proof: Some(NativeProof {
            process: ProcessProof {
                pid: 12,
                creation_time: 34,
            },
            interface: InterfaceProof {
                index: 17,
                luid: 19,
                guid: targets[2].guid,
            },
        }),
        previous_config_sha256: None,
    };
    assert_ne!(targets[2].guid, c.bindings[1].guid);
    let parsed = cold_member_record(
        &serde_json::to_vec(&old).unwrap(),
        TunnelSlot::A,
        &c,
        &engine,
        &targets,
    )
    .unwrap();
    assert_eq!(parsed.retired_proof, old.retired_proof);
    let next = Intent {
        scope: c.intent.scope.clone(),
        transport: nelomai_client_tunnel::TunnelTransport::WireGuard,
        ..old.intent.clone()
    };
    crate::member_owner::validate_prior_stopped(&next, &parsed).unwrap();
    for foreign in [targets[3].guid, targets[4].guid, [99; 16]] {
        old.retired_proof.as_mut().unwrap().interface.guid = foreign;
        assert!(cold_member_record(
            &serde_json::to_vec(&old).unwrap(),
            TunnelSlot::A,
            &c,
            &engine,
            &targets
        )
        .is_err());
    }
}

#[test]
fn non_wfp_read_requires_real_changed_boot_and_original_guard_data_not_member_pid() {
    let (_, files, _) = cold_fixture();
    let root = ProtectedRecoveryRoot::new(files);
    root.initialize(RuntimeSlot::Stable).unwrap();
    let mut facts = (*root.retained_facts().unwrap()).clone();
    // A real protected Guard fixture is required, not synthesized by the reader.
    assert!(require_non_wfp_recovery(&facts).is_err());
    facts.changed_boot = false;
    assert!(require_non_wfp_recovery(&facts).is_err());
}

#[test]
fn non_wfp_read_changed_boot_preserves_actual_protected_guard_without_empty_projection() {
    let (disk, mut files, c, _) = fixture();
    let record = CarrierGuardRecord {
        version: 2,
        context: c.clone(),
        revision: 1,
        current: crate::member_carrier_guard::Model::empty(c.intent.scope.clone()).unwrap(),
        pending: None,
    };
    files
        .compare_exchange(
            &c.intent.scope,
            RecordKind::CarrierGuard,
            None,
            &record.encode().unwrap(),
        )
        .unwrap();
    let raw = disk
        .0
        .borrow()
        .get(&PrivateFile::CarrierGuard)
        .unwrap()
        .clone();
    let cold =
        ProtectedSessionFiles::new(disk.clone(), c.provenance.runtime.clone(), [9; 16]).unwrap();
    let root = ProtectedRecoveryRoot::new(cold);
    root.initialize(RuntimeSlot::Stable).unwrap();
    root.inspect(|facts| {
        require_non_wfp_recovery(facts)?;
        assert_eq!(facts.guard.as_ref(), Some(&record));
        Ok(())
    })
    .unwrap();
    assert_eq!(disk.0.borrow().get(&PrivateFile::CarrierGuard), Some(&raw));
    let mut same_boot = (*root.retained_facts().unwrap()).clone();
    same_boot.changed_boot = false;
    assert!(require_non_wfp_recovery(&same_boot).is_err());
}

#[test]
fn creator_store_claim_only_is_immutable_and_recovered_as_native_context_data() {
    let disk = Disk::default();
    let c = context();
    let mut files = ProtectedSessionFiles::new(
        disk.clone(),
        c.provenance.runtime.clone(),
        c.provenance.boot_id,
    )
    .unwrap();
    files.claim(&c.intent.scope).unwrap();
    let creator = CreatorRecord::decode(
        &serde_json::to_vec(&serde_json::json!({
            "version":1, "context":c, "process":{"pid":256,"creation_time":500}
        }))
        .unwrap(),
    )
    .unwrap(); // explicit kernel DATA at private-IO boundary, no native capture/ACK double
    let mut store = WindowsNativeCreatorStore::open(files.clone(), c.clone()).unwrap();
    store.publish(&creator).unwrap();
    assert!(store.publish(&creator).is_err());
    let raw = disk
        .0
        .borrow()
        .get(&PrivateFile::NativeCreator)
        .unwrap()
        .clone();
    assert!(!disk.0.borrow().contains_key(&PrivateFile::Session));
    assert!(!disk.0.borrow().contains_key(&PrivateFile::Pair));
    assert!(WindowsNativeCreatorStore::open(files, c.clone()).is_err());
    let cold =
        ProtectedSessionFiles::new(disk.clone(), c.provenance.runtime.clone(), [9; 16]).unwrap();
    let root = ProtectedRecoveryRoot::new(cold);
    root.initialize(RuntimeSlot::Stable).unwrap();
    let facts = root.retained_facts().unwrap();
    assert_eq!(facts.layout, RecoveryLayout::NativeCarrier);
    assert_eq!(facts.context.as_ref(), Some(&c));
    assert_eq!(facts.creator.as_ref(), Some(&creator));
    assert!(facts
        .requirements
        .contains(&RecoveryRequirement::MissingSession));
    root.retire_cold_empty(cold_inventory()).unwrap();
    assert_eq!(disk.0.borrow().get(&PrivateFile::NativeCreator), Some(&raw));
}

fn creator_data(c: &Context) -> CreatorRecord {
    CreatorRecord::decode(
        &serde_json::to_vec(&serde_json::json!({
            "version":1,"context":c,"process":{"pid":256,"creation_time":500}
        }))
        .unwrap(),
    )
    .unwrap()
}
#[derive(Clone, Default)]
struct CreatorFaultDisk {
    disk: Disk,
    mode: Rc<Cell<u8>>,
}
impl PrivateRecords for CreatorFaultDisk {
    fn read(&mut self, file: PrivateFile) -> io::Result<Option<Vec<u8>>> {
        if file == PrivateFile::NativeCreator && self.disk.0.borrow().contains_key(&file) {
            match self.mode.get() {
                3 => {
                    self.mode.set(0);
                    return Err(conflict());
                }
                4 => {
                    self.mode.set(0);
                    panic!("creator private readback unwind");
                }
                _ => {}
            }
        }
        self.disk.read(file)
    }
    fn compare_exchange(
        &mut self,
        file: PrivateFile,
        old: Option<&[u8]>,
        new: &[u8],
    ) -> io::Result<()> {
        if file == PrivateFile::NativeCreator && self.mode.get() == 2 {
            self.mode.set(0);
            return Ok(()); // explicit private-OS false ACK, must require readback
        }
        self.disk.compare_exchange(file, old, new)?;
        if file == PrivateFile::NativeCreator {
            if self.mode.get() == 1 {
                self.mode.set(0);
                return Err(conflict());
            }
            if self.mode.get() == 5 {
                self.mode.set(0);
                let mut raw: serde_json::Value = serde_json::from_slice(
                    self.disk.0.borrow().get(&PrivateFile::Session).unwrap(),
                )
                .unwrap();
                let mut session: serde_json::Value =
                    serde_json::from_str(raw["data"].as_str().unwrap()).unwrap();
                let revision = session["payload"]["local_revision"].as_u64().unwrap();
                session["payload"]["local_revision"] = serde_json::json!(revision + 1);
                raw["data"] = serde_json::Value::String(serde_json::to_string(&session).unwrap());
                self.disk
                    .0
                    .borrow_mut()
                    .insert(PrivateFile::Session, serde_json::to_vec(&raw).unwrap());
            }
        }
        Ok(())
    }
}
impl SessionFileIo for CreatorFaultDisk {
    fn transaction<T>(
        &mut self,
        f: impl FnOnce(&mut dyn PrivateRecords) -> io::Result<T>,
    ) -> io::Result<T> {
        f(self)
    }
}

#[test]
fn creator_initial_cas_faults_never_adopt_matching_data_or_retry() {
    for fault in 1..=4 {
        let disk = CreatorFaultDisk::default();
        let (files, c) = initial_files(disk.clone());
        let data = creator_data(&c);
        let mut store = WindowsNativeCreatorStore::open(files.clone(), c.clone()).unwrap();
        disk.mode.set(fault);
        if fault == 4 {
            assert!(std::panic::catch_unwind(
                std::panic::AssertUnwindSafe(|| store.publish(&data))
            )
            .is_err());
        } else {
            assert!(store.publish(&data).is_err(), "fault {fault}");
        }
        assert!(store.publish(&data).is_err());
        if fault != 2 {
            assert!(WindowsNativeCreatorStore::open(files, c).is_err());
        }
    }
}

#[test]
fn creator_cas_requires_unchanged_starting_phase_through_private_postflight() {
    let disk = CreatorFaultDisk::default();
    let (files, c) = initial_files(disk.clone());
    let mut store = WindowsNativeCreatorStore::open(files, c.clone()).unwrap();
    disk.mode.set(5);
    assert!(store.publish(&creator_data(&c)).is_err());
    assert!(disk
        .disk
        .0
        .borrow()
        .contains_key(&PrivateFile::NativeCreator));
}

#[test]
fn creator_raw_writer_denies_replacement_foreign_context_and_late_native_publication() {
    let (_, mut files, c) = basic_fixture();
    let mut foreign = c.clone();
    foreign.provenance.boot_id = [4; 16];
    assert!(files
        .compare_exchange(
            &c.intent.scope,
            RecordKind::NativeCreator,
            None,
            &creator_data(&foreign).encode().unwrap()
        )
        .is_err());
    let (_, mut files, c) = basic_fixture(); // failed foreign attempt fences original forward backend
    let data = creator_data(&c).encode().unwrap();
    files
        .compare_exchange(&c.intent.scope, RecordKind::NativeCreator, None, &data)
        .unwrap();
    assert!(files
        .compare_exchange(
            &c.intent.scope,
            RecordKind::NativeCreator,
            Some(&data),
            &data
        )
        .is_err());
    let (_, mut files, c) = basic_fixture();
    let (_, _, _, mut receipt) = fixture();
    receipt.generation = 1;
    receipt.keys[0].phase = keys::KeyPhase::Unstarted;
    files
        .compare_exchange(
            &c.intent.scope,
            RecordKind::NativeCarrierReceipts,
            None,
            &receipt.encode().unwrap(),
        )
        .unwrap();
    assert!(files
        .compare_exchange(&c.intent.scope, RecordKind::NativeCreator, None, &data)
        .is_err());
}

#[test]
fn cold_old_nine_record_marker_remains_readable_but_cannot_hide_same_claim_creator() {
    for hidden_creator in [false, true] {
        let (disk, files, c) = cold_fixture();
        let root = ProtectedRecoveryRoot::new(files);
        root.initialize(RuntimeSlot::Stable).unwrap();
        root.retire_cold_empty(cold_inventory()).unwrap();
        let marker = *disk
            .0
            .borrow()
            .keys()
            .find(|f| matches!(f, PrivateFile::Completed(_)))
            .unwrap();
        let mut saved: serde_json::Value =
            serde_json::from_slice(disk.0.borrow().get(&marker).unwrap()).unwrap();
        let records = saved["cold_empty"]["records"].as_array_mut().unwrap();
        assert_eq!(records.len(), 10);
        assert_eq!(records.pop().unwrap()[1], serde_json::Value::Null);
        disk.0
            .borrow_mut()
            .insert(marker, serde_json::to_vec(&saved).unwrap());
        if hidden_creator {
            let mut raw: serde_json::Value = serde_json::from_slice(
                disk.0
                    .borrow()
                    .get(&PrivateFile::NativeCarrierReceipts)
                    .unwrap(),
            )
            .unwrap();
            raw["kind"] = serde_json::json!("NativeCreator");
            raw["data"] = serde_json::Value::String(
                String::from_utf8(creator_data(&c).encode().unwrap()).unwrap(),
            );
            disk.0.borrow_mut().insert(
                PrivateFile::NativeCreator,
                serde_json::to_vec(&raw).unwrap(),
            );
        }
        let mut next = c.intent.scope.clone();
        next.session_id = "22222222-2222-4222-8222-222222222222".into();
        let mut fresh = ProtectedSessionFiles::new(disk, c.provenance.runtime, [9; 16]).unwrap();
        assert_eq!(fresh.claim(&next).is_ok(), !hidden_creator);
    }
}

#[test]
fn cold_member_storage_disposition_preserves_exact_intent_not_native_stop_ack() {
    #[cfg(windows)]
    use super::super::member_files::cold_member_retirement_payload;
    #[cfg(not(windows))]
    use crate::member_files::cold_member_retirement_payload;
    use crate::member_owner::{Intent, InterfaceProof, NativeProof, Phase, ProcessProof, Record};
    use nelomai_contracts::dispatcher::TunnelSlot;
    let (c, paths) = canonical_context();
    let targets = cold_namespace(&c, [&paths[0], &paths[1]]).unwrap();
    for phase in [Phase::Running, Phase::Stopping, Phase::Stopped] {
        let old = Record {
            intent: Intent {
                scope: c.intent.scope.clone(),
                slot: TunnelSlot::A,
                transport: nelomai_client_tunnel::TunnelTransport::WireGuard,
                engine: r"C:\Program Files\Nelomai\privileged\engine.exe".into(),
                config_sha256: [3; 32],
            },
            phase,
            proof: if phase == Phase::Stopped {
                None
            } else {
                Some(NativeProof {
                    process: ProcessProof {
                        pid: 300,
                        creation_time: 99,
                    },
                    interface: InterfaceProof {
                        index: 17,
                        luid: 21,
                        guid: targets[1].guid,
                    },
                })
            },
            retired_proof: Some(NativeProof {
                process: ProcessProof {
                    pid: 301,
                    creation_time: 98,
                },
                interface: InterfaceProof {
                    index: 18,
                    luid: 22,
                    guid: targets[2].guid,
                },
            }),
            previous_config_sha256: None,
        };
        let raw = serde_json::to_vec(&old).unwrap();
        let next: Record =
            serde_json::from_slice(&cold_member_retirement_payload(TunnelSlot::A, &raw).unwrap())
                .unwrap();
        assert_eq!(next.intent, old.intent);
        assert_eq!(next.phase, Phase::Stopped);
        assert!(next.proof.is_none() && next.retired_proof.is_none());
        assert_eq!(serde_json::from_slice::<Record>(&raw).unwrap(), old);
        assert!(cold_member_retirement_payload(TunnelSlot::B, &raw).is_err());
    }
}

#[test]
fn creator_data_remains_exact_birth_one_in_original_execution_two_and_three() {
    let (disk, files, c) = basic_fixture();
    let data = creator_data(&c);
    WindowsNativeCreatorStore::open(files.clone(), c.clone())
        .unwrap()
        .publish(&data)
        .unwrap();
    let raw = disk
        .0
        .borrow()
        .get(&PrivateFile::NativeCreator)
        .unwrap()
        .clone();
    let history = files.session_ack_root(&c.intent.scope).unwrap();
    let starting = history.acknowledgements().unwrap().last().unwrap().clone();
    let root = history.bind_native_birth(&c, &starting).unwrap();
    let birth = root.current_lease().unwrap();
    let mut view = files.native_birth_view(&root).unwrap();
    let (mut common, session) =
        WindowsSessionStore::open(files.clone(), c.intent.scope.clone(), RecordKind::Session)
            .unwrap();
    let mut session = session.unwrap();
    session.phase = nelomai_client_tunnel::redundancy::session::SessionPhase::Running;
    session.installed[0] = true;
    session.committed[0] = true;
    common.save(&session).unwrap();
    let current = || history.acknowledgements().unwrap().last().unwrap().clone();
    let running = root.select_running(&birth, &current()).unwrap();
    session.network_epoch = 2;
    common.save(&session).unwrap();
    let renewed = root.renew_for_rebind(&running, &current()).unwrap();
    assert_eq!(
        view.read(&c.intent.scope, RecordKind::NativeCreator)
            .unwrap(),
        Some(data.encode().unwrap())
    );
    session.network_epoch = 3;
    common.save(&session).unwrap();
    root.complete_rebind(&renewed, &current()).unwrap();
    assert_eq!(
        view.read(&c.intent.scope, RecordKind::NativeCreator)
            .unwrap(),
        Some(data.encode().unwrap())
    );
    assert_eq!(disk.0.borrow().get(&PrivateFile::NativeCreator), Some(&raw));
}
