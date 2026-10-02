use super::*;

// The write returning successfully is a historical fact even when the SAME
// publication's postflight fails. Neither fact is read authorization alone.
#[test]
fn original_publication_retains_write_ack_before_failed_postflight() {
    for unwind in [false, true] {
        let state = CreatorPublication::new();
        let checks = Cell::new(0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            state.run(
                || {
                    checks.set(checks.get() + 1);
                    if checks.get() == 2 {
                        if unwind {
                            panic!("original publication postflight");
                        }
                        return Err(conflict());
                    }
                    Ok(())
                },
                || Ok(()),
            )
        }));
        assert!(!matches!(result, Ok(Ok(()))));
        assert_eq!(
            state.receipt(),
            CreatorPublicationReceipt::WriteAcknowledged
        );
        assert!(state.run(|| Ok(()), || Ok(())).is_err());
        assert_eq!(
            state.receipt(),
            CreatorPublicationReceipt::WriteAcknowledged
        );
    }
}

#[test]
fn original_publication_receipt_distinguishes_missing_and_returned_ack() {
    let state = CreatorPublication::new();
    assert_eq!(state.receipt(), CreatorPublicationReceipt::Unattempted);
    assert!(state
        .run(|| Ok(()), || -> io::Result<()> { Err(conflict()) })
        .is_err());
    assert_eq!(
        state.receipt(),
        CreatorPublicationReceipt::AttemptedUnacknowledged
    );

    let complete = CreatorPublication::new();
    complete.run(|| Ok(()), || Ok(())).unwrap();
    assert_eq!(complete.receipt(), CreatorPublicationReceipt::Completed);
}

fn captured() -> OriginalCreator<()> {
    OriginalCreator::new(
        std::rc::Rc::new(()),
        CreatorRecord {
            version: 1,
            context: context(),
            process: ProcessProof {
                pid: 256,
                creation_time: 500,
            },
        },
    )
    .unwrap()
}

fn verify(capture: &OriginalCreator<()>) -> io::Result<()> {
    capture.verify_published_read(
        capture.runtime.as_ref(),
        &capture.record.context,
        &capture.bytes,
        || Ok(capture.record.process),
    )
}

#[test]
fn completed_original_creator_allows_repeated_read_without_republication() {
    let original = captured();
    let writes = Cell::new(0);
    original
        .publication
        .run(
            || Ok(()),
            || {
                writes.set(writes.get() + 1);
                Ok(())
            },
        )
        .unwrap();
    for _ in 0..3 {
        verify(&original).unwrap();
    }
    let same_runtime = original.runtime.clone();
    original
        .verify_published_read(
            same_runtime.as_ref(),
            &original.record.context,
            &original.bytes,
            || Ok(original.record.process),
        )
        .unwrap();
    assert_eq!(writes.get(), 1);
    assert_eq!(
        original.publication.receipt(),
        CreatorPublicationReceipt::Completed
    );
}

#[test]
fn equal_published_bytes_cannot_supply_missing_original_publication() {
    for fault in 0..4 {
        let original = captured();
        // These bytes exist independently of ACK. A lost write ACK cannot be
        // imported by inspecting even the exact original encoded record.
        let external = original.bytes.clone();
        if fault != 0 {
            let checks = Cell::new(0);
            assert!(
                original
                    .publication
                    .run(
                        || {
                            checks.set(checks.get() + 1);
                            if fault == 2 && checks.get() == 2 {
                                Err(conflict())
                            } else {
                                Ok(())
                            }
                        },
                        || if fault == 1 { Err(conflict()) } else { Ok(()) },
                    )
                    .is_err()
                    || fault == 3
            );
        }
        let result = original.verify_published_read(
            original.runtime.as_ref(),
            &original.record.context,
            &external,
            || Ok(original.record.process),
        );
        assert_eq!(result.is_ok(), fault == 3);
    }
}

#[test]
fn creator_read_rejects_equal_foreign_runtime_and_original_capsule() {
    let original = captured();
    original.publication.run(|| Ok(()), || Ok(())).unwrap();
    let foreign = captured();
    assert_eq!(foreign.bytes, original.bytes);
    assert!(original
        .verify_published_read(
            foreign.runtime.as_ref(),
            &original.record.context,
            &original.bytes,
            || Ok(original.record.process)
        )
        .is_err());
    assert!(verify(&original).is_err());
    // The foreign capsule cannot acquire this original's completed history.
    assert!(foreign
        .verify_published_read(
            foreign.runtime.as_ref(),
            &foreign.record.context,
            &original.bytes,
            || Ok(original.record.process)
        )
        .is_err());
}

#[test]
fn creator_read_requires_exact_birth_context_and_original_canonical_bytes() {
    for fault in 0..9 {
        let original = captured();
        original.publication.run(|| Ok(()), || Ok(())).unwrap();
        let mut context = original.record.context.clone();
        let mut bytes = original.bytes.clone();
        match fault {
            0 => context.provenance.network_epoch += 1,
            1 => context.intent.scope.connection_generation += 1,
            2 => bytes.clear(),
            3 => bytes.push(b' '), // Semantically equal JSON is NOT original bytes.
            4 => {
                let mut replacement = original.record.clone();
                replacement.process.creation_time += 1;
                bytes = replacement.encode().unwrap();
            }
            5 => context.provenance.boot_id[0] += 1,
            6 => context.provenance.runtime.runtime_version = "2.0.0".into(),
            7 => context.bindings[0].name.push_str("-foreign"),
            8 => context.bindings[1].guid[0] += 1,
            _ => unreachable!(),
        }
        assert!(original
            .verify_published_read(original.runtime.as_ref(), &context, &bytes, || Ok(original
                .record
                .process))
            .is_err());
        assert!(
            verify(&original).is_err(),
            "replacement cannot repair a denied read"
        );
    }
}

#[test]
fn creator_read_requires_current_kernel_pid_and_birth_before_and_after() {
    for postflight in [false, true] {
        for field in 0..3 {
            let original = captured();
            original.publication.run(|| Ok(()), || Ok(())).unwrap();
            let checks = Cell::new(0);
            assert!(original
                .verify_published_read(
                    original.runtime.as_ref(),
                    &original.record.context,
                    &original.bytes,
                    || {
                        checks.set(checks.get() + 1);
                        if !postflight || checks.get() == 2 {
                            let mut process = original.record.process;
                            match field {
                                0 => process.pid += 1,
                                1 => process.creation_time += 1,
                                2 => return Err(conflict()),
                                _ => unreachable!(),
                            }
                            return Ok(process);
                        }
                        Ok(original.record.process)
                    }
                )
                .is_err());
            assert_eq!(checks.get(), if postflight { 2 } else { 1 });
            assert!(verify(&original).is_err());
        }
    }
}

#[test]
fn creator_read_error_unwind_and_swallowed_reentry_are_sticky() {
    for fault in 0..6 {
        let original = captured();
        original.publication.run(|| Ok(()), || Ok(())).unwrap();
        let checks = Cell::new(0);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            original.verify_published_read(
                original.runtime.as_ref(),
                &original.record.context,
                &original.bytes,
                || {
                    checks.set(checks.get() + 1);
                    match (fault, checks.get()) {
                        (0, 1) | (1, 2) => return Err(conflict()),
                        (2, 1) | (3, 2) => panic!("original kernel observation unwind"),
                        (4, 1) => assert!(verify(&original).is_err()),
                        (5, 2) => assert!(original.publication.run(|| Ok(()), || Ok(())).is_err()),
                        _ => (),
                    }
                    Ok(original.record.process)
                },
            )
        }));
        assert!(!matches!(outcome, Ok(Ok(()))));
        assert!(verify(&original).is_err());
        assert_eq!(
            original.publication.receipt(),
            CreatorPublicationReceipt::Completed
        );
    }
}

#[test]
fn read_reentry_during_publication_denies_both_but_retains_returned_write_fact() {
    let original = captured();
    assert!(original
        .publication
        .run(
            || Ok(()),
            || {
                assert!(verify(&original).is_err());
                Ok(())
            }
        )
        .is_err());
    assert_eq!(
        original.publication.receipt(),
        CreatorPublicationReceipt::WriteAcknowledged
    );
    assert!(verify(&original).is_err());
}

#[test]
fn swallowed_read_reentry_in_publish_preflight_never_reaches_private_write() {
    let original = captured();
    let writes = Cell::new(0);
    assert!(original
        .publication
        .run(
            || {
                assert!(verify(&original).is_err());
                Ok(())
            },
            || {
                writes.set(writes.get() + 1);
                Ok(())
            },
        )
        .is_err());
    assert_eq!(writes.get(), 0);
    assert_eq!(
        original.publication.receipt(),
        CreatorPublicationReceipt::AttemptedUnacknowledged
    );
}

#[test]
fn read_before_publication_permanently_denies_later_write_without_kernel_io() {
    let original = captured();
    assert!(original
        .verify_published_read(
            original.runtime.as_ref(),
            &original.record.context,
            &original.bytes,
            || panic!("missing publication must deny before kernel query"),
        )
        .is_err());
    assert!(original
        .publication
        .run(
            || panic!("read denial cannot be repaired by publication preflight"),
            || -> io::Result<()> { panic!("read denial cannot be repaired by private write") },
        )
        .is_err());
    assert_eq!(
        original.publication.receipt(),
        CreatorPublicationReceipt::Unattempted
    );
}

#[cfg(windows)]
use crate::windows::{member_files as files, member_session as session};
#[cfg(not(windows))]
use crate::{member_files as files, member_session as session};

// External private-file IO only. Every claim, envelope, transaction, original
// CAS/readback and immutable Creator parser below is the production adapter.
#[derive(Clone, Copy)]
enum DiskFault {
    LostAck,
    FalseAck,
    ReadbackError,
    Unwind,
    TransactionPostflight,
}
#[derive(Default)]
struct DiskState {
    records: std::collections::BTreeMap<files::PrivateFile, Vec<u8>>,
    fault: Option<DiskFault>,
    creator_read_error: bool,
    transaction_error: bool,
    creator_writes: usize,
}
#[derive(Clone, Default)]
struct Disk(std::rc::Rc<std::cell::RefCell<DiskState>>);
impl files::PrivateRecords for Disk {
    fn read(&mut self, file: files::PrivateFile) -> io::Result<Option<Vec<u8>>> {
        let state = self.0.borrow();
        if file == files::PrivateFile::NativeCreator && state.creator_read_error {
            return Err(io::Error::other("private Creator readback"));
        }
        Ok(state.records.get(&file).cloned())
    }
    fn compare_exchange(
        &mut self,
        file: files::PrivateFile,
        expected: Option<&[u8]>,
        desired: &[u8],
    ) -> io::Result<()> {
        let mut state = self.0.borrow_mut();
        if state.records.get(&file).map(Vec::as_slice) != expected || desired.len() > file.limit() {
            return Err(io::Error::other("private exact CAS"));
        }
        let fault = if file == files::PrivateFile::NativeCreator {
            state.creator_writes += 1;
            state.fault.take()
        } else {
            None
        };
        if matches!(fault, Some(DiskFault::FalseAck)) {
            return Ok(());
        }
        state.records.insert(file, desired.to_vec());
        match fault {
            Some(DiskFault::LostAck) => Err(io::Error::other("durable write lost ACK")),
            Some(DiskFault::ReadbackError) => {
                state.creator_read_error = true;
                Ok(())
            }
            Some(DiskFault::Unwind) => panic!("durable private write unwind"),
            Some(DiskFault::TransactionPostflight) => {
                state.transaction_error = true;
                Ok(())
            }
            _ => Ok(()),
        }
    }
}
impl files::SessionFileIo for Disk {
    fn transaction<T>(
        &mut self,
        action: impl FnOnce(&mut dyn files::PrivateRecords) -> io::Result<T>,
    ) -> io::Result<T> {
        let value = action(self)?;
        if self.0.borrow().transaction_error {
            return Err(io::Error::other("private transaction postflight"));
        }
        Ok(value)
    }
}
fn protected_files(original: &OriginalCreator<()>) -> (Disk, session::ProtectedSessionFiles<Disk>) {
    use session::SessionFiles;
    let disk = Disk::default();
    let mut files = session::ProtectedSessionFiles::new(
        disk.clone(),
        original.record.context.provenance.runtime.clone(),
        [7; 16],
    )
    .unwrap();
    files.claim(&original.record.context.intent.scope).unwrap();
    (disk, files)
}

#[test]
fn actual_protected_claim_only_creator_publication_survives_forward_revocation_for_read() {
    use session::SessionFiles;
    let original = captured();
    let (disk, mut files) = protected_files(&original);
    let context = &original.record.context;
    assert!(files
        .read(&context.intent.scope, session::RecordKind::Session)
        .unwrap()
        .is_none());
    let mut store =
        session::WindowsNativeCreatorStore::open(files.clone(), context.clone()).unwrap();
    original
        .publication
        .run(|| Ok(()), || store.publish(&original.record))
        .unwrap();
    files
        .revoke_native_carrier_access(&context.intent.scope)
        .unwrap();
    assert!(!files
        .native_carrier_access(&context.intent.scope)
        .unwrap()
        .is_fresh());
    let observed = files
        .read(&context.intent.scope, session::RecordKind::NativeCreator)
        .unwrap()
        .unwrap();
    original
        .verify_published_read(original.runtime.as_ref(), context, &observed, || {
            Ok(original.record.process)
        })
        .unwrap();
    assert!(store.publish(&original.record).is_err());
    assert_eq!(disk.0.borrow().creator_writes, 1);
    verify(&original).unwrap();
    assert!(
        !files
            .native_carrier_access(&context.intent.scope)
            .unwrap()
            .is_fresh(),
        "read cannot revive forward storage"
    );
}

#[test]
fn actual_protected_lost_false_ack_readback_and_unwind_cannot_mint_publication() {
    for fault in [
        DiskFault::LostAck,
        DiskFault::FalseAck,
        DiskFault::ReadbackError,
        DiskFault::Unwind,
        DiskFault::TransactionPostflight,
    ] {
        let original = captured();
        let (disk, files) = protected_files(&original);
        let mut store =
            session::WindowsNativeCreatorStore::open(files, original.record.context.clone())
                .unwrap();
        disk.0.borrow_mut().fault = Some(fault);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            original
                .publication
                .run(|| Ok(()), || store.publish(&original.record))
        }));
        assert!(!matches!(outcome, Ok(Ok(()))));
        assert_eq!(
            original.publication.receipt(),
            CreatorPublicationReceipt::AttemptedUnacknowledged
        );
        // A false ACK may leave no file; other faults can leave exact durable
        // bytes. Neither observable state is the capsule's returned ACK.
        assert!(verify(&original).is_err());
        assert!(store.publish(&original.record).is_err());
        assert_eq!(disk.0.borrow().creator_writes, 1);
    }
}

#[test]
fn actual_protected_returned_write_then_capsule_postflight_error_retains_ack_only() {
    use session::SessionFiles;
    let original = captured();
    let (_disk, mut files) = protected_files(&original);
    let mut store =
        session::WindowsNativeCreatorStore::open(files.clone(), original.record.context.clone())
            .unwrap();
    let checks = Cell::new(0);
    assert!(original
        .publication
        .run(
            || {
                checks.set(checks.get() + 1);
                if checks.get() == 2 {
                    Err(conflict())
                } else {
                    Ok(())
                }
            },
            || store.publish(&original.record)
        )
        .is_err());
    let observed = files
        .read(
            &original.record.context.intent.scope,
            session::RecordKind::NativeCreator,
        )
        .unwrap()
        .unwrap();
    assert_eq!(observed, original.bytes);
    assert_eq!(
        original.publication.receipt(),
        CreatorPublicationReceipt::WriteAcknowledged
    );
    assert!(original
        .verify_published_read(
            original.runtime.as_ref(),
            &original.record.context,
            &observed,
            || Ok(original.record.process)
        )
        .is_err());
}

#[test]
fn actual_protected_current_creator_replacement_denies_without_json_ack_adoption() {
    use session::SessionFiles;
    let original = captured();
    let (disk, mut files) = protected_files(&original);
    let context = &original.record.context;
    let mut store =
        session::WindowsNativeCreatorStore::open(files.clone(), context.clone()).unwrap();
    original
        .publication
        .run(|| Ok(()), || store.publish(&original.record))
        .unwrap();
    let old = disk.0.borrow().records[&files::PrivateFile::NativeCreator].clone();
    let mut outer: serde_json::Value = serde_json::from_slice(&old).unwrap();
    let mut replacement = original.record.clone();
    replacement.process.creation_time += 1;
    outer["data"] = serde_json::json!(String::from_utf8(replacement.encode().unwrap()).unwrap());
    disk.0.borrow_mut().records.insert(
        files::PrivateFile::NativeCreator,
        serde_json::to_vec(&outer).unwrap(),
    );
    // Raw protected authentication can validly return comparison DATA. It is
    // not the original capsule ACK, even with equal scope/runtime/birth context.
    let observed = files
        .read(&context.intent.scope, session::RecordKind::NativeCreator)
        .unwrap()
        .unwrap();
    assert_eq!(CreatorRecord::decode(&observed).unwrap(), replacement);
    assert!(original
        .verify_published_read(original.runtime.as_ref(), context, &observed, || {
            Ok(original.record.process)
        })
        .is_err());
    disk.0
        .borrow_mut()
        .records
        .insert(files::PrivateFile::NativeCreator, old);
    assert!(
        verify(&original).is_err(),
        "restoring bytes cannot restore read authority"
    );
    assert_eq!(disk.0.borrow().creator_writes, 1);
}

// Break: swallowed reentry, failed private CAS or postflight and unwind allow
// a second creator record publication or return a fabricated first-write ACK.
#[test]
fn original_creator_publication_is_one_shot_and_failure_sticky() {
    use std::cell::Cell;
    for fault in 0..5 {
        let state = CreatorPublication::new();
        let checks = Cell::new(0);
        let writes = Cell::new(0);
        let check = || -> io::Result<()> {
            checks.set(checks.get() + 1);
            if fault == 0 && checks.get() == 1 || fault == 2 && checks.get() == 2 {
                return Err(conflict());
            }
            Ok(())
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            state.run(check, || -> io::Result<()> {
                writes.set(writes.get() + 1);
                match fault {
                    1 => Err(conflict()),
                    3 => panic!("creator private CAS acknowledgement unwind"),
                    4 => {
                        assert!(state.run(|| Ok(()), || Ok(())).is_err());
                        Ok(())
                    }
                    _ => Ok(()),
                }
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        let before = writes.get();
        assert!(state
            .run(
                || Ok(()),
                || {
                    writes.set(writes.get() + 1);
                    Ok(())
                }
            )
            .is_err());
        assert_eq!(writes.get(), before);
        assert_eq!(before, if fault == 0 { 0 } else { 1 });
    }
    let state = CreatorPublication::new();
    state.run(|| Ok(()), || Ok(())).unwrap();
    assert!(state.run(|| Ok(()), || Ok(())).is_err());
}

fn context() -> Context {
    use crate::{
        member_carrier::{Intent, Provenance},
        member_carrier_native_ownership::{Binding, Role},
    };
    use nelomai_client_tunnel::redundancy::SessionScope;
    use nelomai_contracts::{dispatcher::EngineIdentity, RuntimeSlot};
    let scope = SessionScope {
        runtime: RuntimeSlot::Stable,
        runtime_generation: 1,
        session_id: "11111111-1111-4111-8111-111111111111".into(),
        connection_generation: 2,
    };
    Context {
        intent: Intent { scope, addresses: vec!["10.7.0.2/32".parse().unwrap()] },
        provenance: Provenance { boot_id: [7;16], runtime: EngineIdentity {
            slot: RuntimeSlot::Stable, runtime_version: "1.0.0".into(), runtime_contract_version: 1,
            container_version: "1.0.0".into(), manifest_sha256: "a".repeat(64) }, network_epoch: 1 },
        bindings: [Role::RoleCarrier, Role::MemberA, Role::MemberB].map(|role| {
            let n = match role { Role::RoleCarrier => 1, Role::MemberA => 2, Role::MemberB => 3 };
            let hex = format!("{n:02x}");
            Binding { role, guid: [n;16], name: format!("creator-data-{n}"), registry_path: format!(
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{{}-{}-{}-{}-{}}}",
                hex.repeat(4), hex.repeat(2), hex.repeat(2), hex.repeat(2), hex.repeat(6)) }
        }),
    }
}

// Break: absent/malformed/foreign/oversize process DATA can be admitted as
// original creator authority during a native cleanup branch.
#[test]
fn creator_record_codec_is_bounded_strict_and_context_bound() {
    let context = context();
    let record = CreatorRecord {
        version: 1,
        context: context.clone(),
        process: ProcessProof {
            pid: 256,
            creation_time: 500,
        },
    };
    let encoded = record.encode().unwrap();
    assert_eq!(CreatorRecord::decode(&encoded).unwrap(), record);
    record.require_context(&context).unwrap();
    let mut foreign = context.clone();
    foreign.provenance.network_epoch += 1;
    assert!(record.require_context(&foreign).is_err());
    assert!(CreatorRecord::decode(&vec![b' '; MAX_BYTES + 1]).is_err());
    for field in ["context", "process", "version"] {
        let mut raw = serde_json::to_value(&record).unwrap();
        raw.as_object_mut().unwrap().remove(field);
        assert!(CreatorRecord::decode(&serde_json::to_vec(&raw).unwrap()).is_err());
    }
    for (key, value) in [
        ("version", serde_json::json!(2)),
        ("foreign", serde_json::json!(true)),
    ] {
        let mut raw = serde_json::to_value(&record).unwrap();
        raw[key] = value;
        assert!(serde_json::from_value::<CreatorRecord>(raw.clone()).is_err());
        assert!(CreatorRecord::decode(&serde_json::to_vec(&raw).unwrap()).is_err());
    }
    for process in [
        ProcessProof {
            pid: 4,
            ..record.process
        },
        ProcessProof {
            creation_time: 0,
            ..record.process
        },
    ] {
        let bad = CreatorRecord {
            process,
            ..record.clone()
        };
        assert!(bad.encode().is_err());
    }
}

// Break: matching current PID (including an exited/reused process) is treated
// as original creator death without checking creation-time and API outcome.
#[test]
fn same_boot_death_requires_exact_process_lifetime_observation() {
    let original = ProcessProof {
        pid: 256,
        creation_time: 500,
    };
    assert!(require_creator_dead(original, ProcessObservation::Absent).is_ok());
    assert!(require_creator_dead(original, ProcessObservation::Exited(original)).is_ok());
    assert!(require_creator_dead(original, ProcessObservation::Running(original)).is_err());
    for exited in [false, true] {
        for time in [499, 501] {
            let other = ProcessProof {
                creation_time: time,
                ..original
            };
            let observation = if exited {
                ProcessObservation::Exited(other)
            } else {
                ProcessObservation::Running(other)
            };
            assert_eq!(
                require_creator_dead(original, observation).is_ok(),
                time > 500
            );
        }
        let foreign = ProcessProof {
            pid: 260,
            ..original
        };
        let observation = if exited {
            ProcessObservation::Exited(foreign)
        } else {
            ProcessObservation::Running(foreign)
        };
        assert!(require_creator_dead(original, observation).is_err());
    }
    assert!(require_creator_dead(original, ProcessObservation::Unreadable).is_err());
    for invalid in [
        ProcessProof { pid: 0, ..original },
        ProcessProof { pid: 4, ..original },
        ProcessProof {
            creation_time: 0,
            ..original
        },
    ] {
        assert!(require_creator_dead(invalid, ProcessObservation::Absent).is_err());
    }
}
