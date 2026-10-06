//! Synthetic protected-IO tests: no native WFP execution or authority.
use super::*;
use crate::member_carrier_guard as guard;
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

#[derive(Clone, Default)]
struct Disk(Rc<RefCell<State>>);
#[derive(Default)]
struct State {
    bytes: BTreeMap<PrivateFile, Vec<u8>>,
    fault: u8,
    unreadable: bool,
    fail_read: Option<PrivateFile>,
}
impl PrivateRecords for Disk {
    fn read(&mut self, file: PrivateFile) -> io::Result<Option<Vec<u8>>> {
        let d = self.0.borrow();
        if d.fail_read == Some(file) || (d.unreadable && file.name().contains("carrier-guard")) {
            return Err(failed());
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
            return Err(failed());
        }
        let fault = if file.name().contains("carrier-guard") {
            std::mem::take(&mut d.fault)
        } else {
            0
        };
        if fault == 1 {
            return Err(failed());
        }
        if fault == 3 {
            return Ok(());
        }
        d.bytes.insert(
            file,
            if fault == 4 {
                desired[..desired.len() / 2].to_vec()
            } else {
                desired.to_vec()
            },
        );
        if fault == 6 {
            let mut session = nelomai_client_tunnel::redundancy::session::SessionState::new(
                scope(),
                nelomai_client_tunnel::redundancy::Slot::A,
                1,
                1,
            )
            .unwrap()
            .snapshot();
            session.network_epoch = 2;
            let saved = SavedRecord {
                version: PRIVATE_VERSION,
                identity: SessionIdentity {
                    boot_id: [7; 16],
                    runtime: context().provenance.runtime,
                    scope: scope(),
                },
                kind: RecordKind::Session,
                network_epoch: 2,
                data: String::from_utf8(
                    serde_json::to_vec(&Envelope {
                        version: 1,
                        scope: scope(),
                        payload: session,
                    })
                    .unwrap(),
                )
                .unwrap(),
            };
            d.bytes
                .insert(PrivateFile::Session, serde_json::to_vec(&saved).unwrap());
        }
        if fault == 5 {
            d.unreadable = true;
        }
        if fault == 7 {
            let mut raw: serde_json::Value = serde_json::from_slice(&d.bytes[&file]).unwrap();
            raw["network_epoch"] = 2.into();
            d.bytes.insert(file, serde_json::to_vec(&raw).unwrap());
        }
        if fault == 8 {
            d.bytes.get_mut(&file).unwrap().push(b' ');
        }
        if fault == 2 {
            return Err(failed());
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
fn context() -> native_receipt::Context {
    let runtime = nelomai_contracts::dispatcher::EngineIdentity {
        slot: RuntimeSlot::Stable,
        runtime_version: "1.0.0".into(),
        runtime_contract_version: 1,
        container_version: "1.0.0".into(),
        manifest_sha256: "a".repeat(64),
    };
    native_receipt::Context { intent: carrier::Intent { scope: scope(), addresses: vec!["10.7.0.2/32".parse().unwrap()] }, provenance: carrier::Provenance { boot_id: [7;16], runtime, network_epoch: 1 }, bindings: [native_receipt::Role::RoleCarrier,native_receipt::Role::MemberA,native_receipt::Role::MemberB].map(|role| {
        let n = match role { native_receipt::Role::RoleCarrier => 1, native_receipt::Role::MemberA => 2, native_receipt::Role::MemberB => 3 };
        let byte = format!("{n:02x}");
        native_receipt::Binding { role, guid: [n;16], name: format!("guard-{n}"), registry_path: format!(r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{{}-{}-{}-{}-{}}}", byte.repeat(4),byte.repeat(2),byte.repeat(2),byte.repeat(2),byte.repeat(6)) }
    }) }
}
fn fixture() -> (Disk, ProtectedSessionFiles<Disk>) {
    let d = Disk::default();
    let mut f =
        ProtectedSessionFiles::new(d.clone(), context().provenance.runtime, [7; 16]).unwrap();
    f.claim(&scope()).unwrap();
    (d, f)
}
fn kind() -> RecordKind {
    serde_json::from_str("\"CarrierGuard\"").expect("protected v2 namespace must exist")
}
fn initial_bytes() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"version":2,"context":context(),"revision":1,"current":guard::Model::empty(scope()).unwrap(),"pending":null})).unwrap()
}
fn installed() -> guard::Model {
    let identity = |n| guard::Identity {
        scope: scope(),
        proof: crate::member_owner::InterfaceProof {
            index: n as u32,
            luid: n as u64 + 100,
            guid: [n; 16],
        },
    };
    guard::Model::new(
        scope(),
        guard::Carrier {
            identity: identity(1),
            sources: vec!["10.7.0.2".parse().unwrap()],
        },
        [
            Some(guard::Member {
                identity: identity(2),
                probes: vec![],
            }),
            Some(guard::Member {
                identity: identity(3),
                probes: vec![],
            }),
        ],
        Some(nelomai_client_tunnel::redundancy::Slot::A),
    )
    .unwrap()
}

#[test]
fn guard_fresh_initial_is_durable_and_full_inventory_blocks_empty_completion() {
    let (_, mut f) = fixture();
    let bytes = initial_bytes();
    f.compare_exchange(&scope(), kind(), None, &bytes).unwrap();
    assert_eq!(f.read(&scope(), kind()).unwrap(), Some(bytes));
    assert!(f.complete_empty(&scope()).is_err());
}
#[test]
fn guard_raw_boundary_denies_noninitial_revision_foreign_context_and_schema() {
    for case in 0..6 {
        let (_, mut f) = fixture();
        let mut value: serde_json::Value = serde_json::from_slice(&initial_bytes()).unwrap();
        match case {
            0 => value["version"] = 1.into(),
            1 => value["revision"] = 2.into(),
            2 => value["context"]["provenance"]["boot_id"][0] = 8.into(),
            3 => value["context"]["provenance"]["network_epoch"] = 2.into(),
            4 => value["extra"] = true.into(),
            _ => value["current"] = serde_json::to_value(installed()).unwrap(),
        }
        assert!(
            f.compare_exchange(&scope(), kind(), None, &serde_json::to_vec(&value).unwrap())
                .is_err(),
            "case {case}"
        );
        assert!(!f.native_carrier_access(&scope()).unwrap().is_fresh());
    }
}
#[test]
fn guard_raw_boundary_requires_monotonic_revision_exact_current_and_pending_plan() {
    for case in 0..5 {
        let (_, mut f) = fixture();
        let old = initial_bytes();
        f.compare_exchange(&scope(), kind(), None, &old).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&old).unwrap();
        value["revision"] = 2.into();
        value["pending"] = serde_json::to_value(
            guard::ExchangePlan::new(&guard::Model::empty(scope()).unwrap(), &installed()).unwrap(),
        )
        .unwrap();
        match case {
            0 => value["revision"] = 1.into(),
            1 => value["revision"] = 3.into(),
            2 => value["current"] = serde_json::to_value(installed()).unwrap(),
            3 => value["context"]["bindings"][0]["name"] = "changed".into(),
            _ => value["pending"]["desired"]["carrier"]["identity"]["proof"]["guid"][0] = 9.into(),
        }
        assert!(
            f.compare_exchange(
                &scope(),
                kind(),
                Some(&old),
                &serde_json::to_vec(&value).unwrap()
            )
            .is_err(),
            "case {case}"
        );
    }
}
#[test]
fn guard_cleanup_raw_cannot_create_or_rearm() {
    let (_, mut f) = fixture();
    let (mut cleanup, _) = f.recovery_view(RuntimeSlot::Stable).unwrap().unwrap();
    assert!(cleanup
        .compare_exchange(&scope(), kind(), None, &initial_bytes())
        .is_err());
    // A separate fresh claim is required after the denied raw write revoked it.
    let (_, mut f) = fixture();
    let old = initial_bytes();
    f.compare_exchange(&scope(), kind(), None, &old).unwrap();
    let (mut cleanup, _) = f.recovery_view(RuntimeSlot::Stable).unwrap().unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&old).unwrap();
    value["revision"] = 2.into();
    value["pending"] = serde_json::to_value(
        guard::ExchangePlan::new(&guard::Model::empty(scope()).unwrap(), &installed()).unwrap(),
    )
    .unwrap();
    assert!(cleanup
        .compare_exchange(
            &scope(),
            kind(),
            Some(&old),
            &serde_json::to_vec(&value).unwrap()
        )
        .is_err());
}

fn stored() -> (Disk, ProtectedSessionFiles<Disk>) {
    let (disk, mut files) = fixture();
    files
        .compare_exchange(&scope(), kind(), None, &initial_bytes())
        .unwrap();
    (disk, files)
}
fn plan() -> guard::ExchangePlan {
    guard::ExchangePlan::new(&guard::Model::empty(scope()).unwrap(), &installed()).unwrap()
}
fn captured(mut plan: guard::ExchangePlan) -> guard::ExchangePlan {
    let mut base = plan.base.expected.clone();
    base.sublayer.as_mut().unwrap().weight = 65000;
    plan.base = plan.base.readback_after(&plan.expected, &base).unwrap();
    let mut desired = plan.desired.expected.clone();
    desired.sublayer.as_mut().unwrap().weight = 65000;
    plan.desired = plan
        .desired
        .readback_after(&plan.expected, &desired)
        .unwrap();
    plan.captured_sublayer_weight = Some(65000);
    plan.validate().unwrap();
    plan
}

#[test]
fn guard_every_unconfirmed_write_revokes_shared_fresh_even_when_file_missing() {
    for fault in [1, 2, 3, 4, 5, 7, 8] {
        let (disk, mut files) = fixture();
        disk.0.borrow_mut().fault = fault;
        assert!(
            files
                .compare_exchange(&scope(), kind(), None, &initial_bytes())
                .is_err(),
            "fault {fault}"
        );
        assert!(!files.native_carrier_access(&scope()).unwrap().is_fresh());
        disk.0.borrow_mut().unreadable = false;
        assert!(files
            .compare_exchange(&scope(), kind(), None, &initial_bytes())
            .is_err());
    }
}

#[test]
fn guard_raw_fresh_cas_also_rechecks_epoch_after_ack() {
    let (disk, mut files) = fixture();
    disk.0.borrow_mut().fault = 6;
    assert!(files
        .compare_exchange(&scope(), kind(), None, &initial_bytes())
        .is_err());
    assert!(!files.native_carrier_access(&scope()).unwrap().is_fresh());
}
#[test]
fn guard_stale_epoch_boot_runtime_binding_and_scope_deny_legacy_write() {
    for case in 0..5 {
        let (_, mut files) = stored();
        let raw = files.read(&scope(), kind()).unwrap().unwrap();
        let mut next = CarrierGuardRecord::decode(&raw).unwrap();
        next.revision += 1;
        next.pending = Some(plan());
        match case {
            0 => next.context.provenance.network_epoch = 2,
            1 => next.context.provenance.boot_id[0] = 8,
            2 => next.context.provenance.runtime.manifest_sha256 = "b".repeat(64),
            3 => next.context.bindings[0].name = "foreign".into(),
            _ => next.context.intent.scope.connection_generation += 1,
        }
        assert!(
            files
                .compare_exchange(
                    &scope(),
                    kind(),
                    Some(&raw),
                    &serde_json::to_vec(&next).unwrap()
                )
                .is_err(),
            "case {case}"
        );
        assert!(!files.native_carrier_access(&scope()).unwrap().is_fresh());
    }
}
#[test]
fn guard_oversize_schema_and_exact_raw_cas_conflicts_revoke() {
    for case in 0..4 {
        let (_, mut files) = stored();
        let raw = files.read(&scope(), kind()).unwrap().unwrap();
        let mut next = CarrierGuardRecord::decode(&raw).unwrap();
        next.revision += 1;
        next.pending = Some(plan());
        let bytes = match case {
            0 => vec![b' '; 65537],
            2 => {
                let mut value = serde_json::to_value(&next).unwrap();
                value["extra"] = true.into();
                serde_json::to_vec(&value).unwrap()
            }
            _ => next.encode().unwrap(),
        };
        if case == 3 {
            files
                .compare_exchange(&scope(), kind(), Some(&raw), &bytes)
                .unwrap();
        }
        let expected = if case == 1 {
            b"foreign".as_slice()
        } else {
            raw.as_slice()
        };
        assert!(files
            .compare_exchange(&scope(), kind(), Some(expected), &bytes)
            .is_err());
        assert!(!files.native_carrier_access(&scope()).unwrap().is_fresh());
    }
}
fn terminal_legacy(files: &mut ProtectedSessionFiles<Disk>) {
    let mut snapshot = nelomai_client_tunnel::redundancy::session::SessionState::new(
        scope(),
        nelomai_client_tunnel::redundancy::Slot::A,
        1,
        1,
    )
    .unwrap()
    .snapshot();
    snapshot.phase = nelomai_client_tunnel::redundancy::session::SessionPhase::Stopped;
    WindowsSessionStore::open(files.clone(), scope(), RecordKind::Session)
        .unwrap()
        .0
        .save(&snapshot)
        .unwrap();
    let pair = PairRecord {
        scope: scope(),
        members: [None, None],
        active: None,
        guard: crate::member_guard::Model::empty(scope()).unwrap(),
        pending_guard: None,
        dns: [None, None],
        options: None,
        closing: false,
    };
    WindowsPairStore::open(files.clone(), scope(), RecordKind::Pair)
        .unwrap()
        .0
        .save(&pair)
        .unwrap();
}
#[test]
fn guard_completion_requires_exact_no_keys_no_permits_no_pending_terminal() {
    for mode in 0..3 {
        let (disk, mut files) = stored();
        terminal_legacy(&mut files);
        let mut raw = files.read(&scope(), kind()).unwrap().unwrap();
        let mut next = CarrierGuardRecord::decode(&raw).unwrap();
        next.revision += 1;
        next.pending = Some(plan());
        let bytes = next.encode().unwrap();
        files
            .compare_exchange(&scope(), kind(), Some(&raw), &bytes)
            .unwrap();
        raw = bytes;
        let bound = captured(plan());
        next.revision += 1;
        next.pending = Some(bound.clone());
        let bytes = next.encode().unwrap();
        files
            .compare_exchange(&scope(), kind(), Some(&raw), &bytes)
            .unwrap();
        raw = bytes;
        let (mut cleanup, _) = files.recovery_view(RuntimeSlot::Stable).unwrap().unwrap();
        if mode != 0 {
            next.revision += 1;
            next.pending = None;
            next.current = if mode == 1 {
                bound.desired.clone()
            } else {
                bound.base.clone()
            };
            let bytes = next.encode().unwrap();
            if mode == 1 {
                files
                    .compare_exchange(&scope(), kind(), Some(&raw), &bytes)
                    .unwrap();
            } else {
                cleanup
                    .compare_exchange(&scope(), kind(), Some(&raw), &bytes)
                    .unwrap();
            }
            raw = bytes;
        }
        assert!(files.complete(&scope()).is_err());
        assert!(!disk
            .0
            .borrow()
            .bytes
            .contains_key(&completed_file(&scope()).unwrap()));
        if mode == 0 {
            next.revision += 1;
            next.pending = None;
            next.current = bound.base.clone();
            let bytes = next.encode().unwrap();
            cleanup
                .compare_exchange(&scope(), kind(), Some(&raw), &bytes)
                .unwrap();
            raw = bytes;
        }
        let empty = guard::Model::empty(scope()).unwrap();
        next.revision += 1;
        next.pending = Some(guard::ExchangePlan::new(&next.current, &empty).unwrap());
        let bytes = next.encode().unwrap();
        cleanup
            .compare_exchange(&scope(), kind(), Some(&raw), &bytes)
            .unwrap();
        raw = bytes;
        next.revision += 1;
        next.current = empty;
        next.pending = None;
        cleanup
            .compare_exchange(&scope(), kind(), Some(&raw), &next.encode().unwrap())
            .unwrap();
        files.complete(&scope()).unwrap();
        assert!(files.scopes(RuntimeSlot::Stable).unwrap().is_empty());
        let mut next_scope = scope();
        next_scope.connection_generation += 1;
        files.claim(&next_scope).unwrap();
        assert!(files.read(&next_scope, kind()).unwrap().is_none());
    }
}
#[test]
fn guard_namespace_read_errors_deny_claim_recovery_complete_and_empty_paths() {
    let d = Disk::default();
    let mut files =
        ProtectedSessionFiles::new(d.clone(), context().provenance.runtime, [7; 16]).unwrap();
    d.0.borrow_mut().fail_read = Some(kind().file());
    assert!(files.claim(&scope()).is_err());
    for path in 0..4 {
        let (d, mut files) = stored();
        terminal_legacy(&mut files);
        d.0.borrow_mut().fail_read = Some(kind().file());
        let denied = match path {
            0 => files.recovery_view(RuntimeSlot::Stable).is_err(),
            1 => files.scopes(RuntimeSlot::Stable).is_err(),
            2 => files.complete(&scope()).is_err(),
            _ => files.complete_empty(&scope()).is_err(),
        };
        assert!(denied, "path {path}");
    }
}

#[test]
fn guard_retired_pending_or_installed_record_cannot_become_absence_or_new_claim() {
    for mode in 0..3 {
        let (disk, mut files) = stored();
        terminal_legacy(&mut files);
        files.complete(&scope()).unwrap();
        let mut saved: SavedRecord =
            serde_json::from_slice(&disk.0.borrow().bytes[&kind().file()]).unwrap();
        let mut record = CarrierGuardRecord::decode(saved.data.as_bytes()).unwrap();
        if mode == 0 {
            record.pending = Some(plan());
        }
        if mode == 1 {
            record.current = captured(plan()).base;
        }
        if mode == 2 {
            record.current = captured(plan()).desired;
        }
        saved.data = String::from_utf8(record.encode().unwrap()).unwrap();
        disk.0
            .borrow_mut()
            .bytes
            .insert(kind().file(), serde_json::to_vec(&saved).unwrap());
        assert!(files.scopes(RuntimeSlot::Stable).is_err());
        assert!(files.complete(&scope()).is_err());
        let mut next = scope();
        next.connection_generation += 1;
        assert!(files.claim(&next).is_err());
    }
}
#[test]
fn guard_read_rejects_malformed_foreign_extra_and_versioned_retained_bytes() {
    for case in 0..6 {
        let (disk, mut files) = stored();
        let mut saved: SavedRecord =
            serde_json::from_slice(&disk.0.borrow().bytes[&kind().file()]).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&saved.data).unwrap();
        match case {
            0 => value["version"] = 1.into(),
            1 => value["extra"] = true.into(),
            2 => value["context"]["extra"] = true.into(),
            3 => value["context"]["bindings"][0]["name"] = "".into(),
            4 => {
                value["context"]["provenance"]["runtime"]["manifest_sha256"] = "b".repeat(64).into()
            }
            _ => value["current"]["expected"]["filters"] = serde_json::json!([{}]),
        }
        saved.data = serde_json::to_string(&value).unwrap();
        disk.0
            .borrow_mut()
            .bytes
            .insert(kind().file(), serde_json::to_vec(&saved).unwrap());
        assert!(files.read(&scope(), kind()).is_err(), "case {case}");
    }
}
#[test]
fn guard_json_cannot_supply_storage_permission_or_fresh_claim() {
    let disk = Disk::default();
    let mut unclaimed =
        ProtectedSessionFiles::new(disk, context().provenance.runtime, [7; 16]).unwrap();
    assert!(unclaimed
        .compare_exchange(&scope(), kind(), None, &initial_bytes())
        .is_err());
    let (_, mut files) = fixture();
    files.revoke_native_carrier_access(&scope()).unwrap();
    assert!(files
        .compare_exchange(&scope(), kind(), None, &initial_bytes())
        .is_err());
    assert!(files.read(&scope(), kind()).unwrap().is_none());
}

#[test]
fn guard_direct_deserialization_is_strict_v2_not_only_the_io_decoder() {
    for case in 0..3 {
        let mut value: serde_json::Value = serde_json::from_slice(&initial_bytes()).unwrap();
        match case {
            0 => value["version"] = 1.into(),
            1 => value["revision"] = 0.into(),
            _ => {
                value["pending"] = serde_json::to_value(
                    guard::ExchangePlan::new(&installed(), &installed().without_permits().unwrap())
                        .unwrap(),
                )
                .unwrap()
            }
        }
        assert!(
            serde_json::from_value::<CarrierGuardRecord>(value).is_err(),
            "case {case}"
        );
    }
}
#[test]
fn guard_revision_overflow_has_no_write_and_revokes_fresh_claim() {
    let (disk, mut files) = stored();
    let mut saved: SavedRecord =
        serde_json::from_slice(&disk.0.borrow().bytes[&kind().file()]).unwrap();
    let mut record = CarrierGuardRecord::decode(saved.data.as_bytes()).unwrap();
    record.revision = u64::MAX;
    saved.data = String::from_utf8(record.encode().unwrap()).unwrap();
    let raw = serde_json::to_vec(&saved).unwrap();
    disk.0.borrow_mut().bytes.insert(kind().file(), raw.clone());
    record.pending = Some(plan());
    let bytes = record.encode().unwrap();
    assert!(files
        .compare_exchange(&scope(), kind(), Some(saved.data.as_bytes()), &bytes)
        .is_err());
    assert_eq!(disk.0.borrow().bytes[&kind().file()], raw);
    assert!(!files.native_carrier_access(&scope()).unwrap().is_fresh());
}
