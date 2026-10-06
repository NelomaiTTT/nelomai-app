use super::*;
use crate::member_carrier_rows::{self as rows, *};
use nelomai_client_tunnel::redundancy::{
    session::{SessionPhase, SessionState},
    Slot,
};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    rc::Rc,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Fail,
    Lost,
    False,
    Unreadable,
    Foreign,
    Equivalent,
    Panic,
}
#[derive(Default)]
struct State {
    bytes: BTreeMap<PrivateFile, Vec<u8>>,
    fault: Option<Fault>,
    unreadable: Option<PrivateFile>,
    race: Option<Vec<u8>>,
    attempts: usize,
    reads: usize,
    pair_race: Option<Vec<u8>>,
    fail_after: bool,
}
#[derive(Clone, Default)]
struct Disk(Rc<RefCell<State>>);
impl PrivateRecords for Disk {
    fn read(&mut self, file: PrivateFile) -> io::Result<Option<Vec<u8>>> {
        let mut s = self.0.borrow_mut();
        s.reads += 1;
        if s.unreadable == Some(file) {
            return Err(io::Error::other("SECRET read"));
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
        let row = matches!(
            file,
            PrivateFile::CarrierRows | PrivateFile::MemberARows | PrivateFile::MemberBRows
        );
        if row {
            s.attempts += 1;
            if let Some(race) = s.race.take() {
                s.bytes.insert(file, race);
            }
            if let Some(pair) = s.pair_race.take() {
                s.bytes.insert(PrivateFile::Pair, pair);
            }
        }
        if s.bytes.get(&file).map(Vec::as_slice) != expected || desired.len() > file.limit() {
            return Err(io::Error::other("SECRET CAS"));
        }
        let fault = if row { s.fault.take() } else { None };
        if fault == Some(Fault::Fail) {
            return Err(io::Error::other("SECRET uncommitted"));
        }
        if fault == Some(Fault::False) {
            return Ok(());
        }
        let mut raw = desired.to_vec();
        if matches!(fault, Some(Fault::Foreign | Fault::Equivalent)) {
            let mut outer: SavedRecord = serde_json::from_slice(&raw).unwrap();
            let mut record = Record::decode(outer.data.as_bytes()).unwrap();
            if fault == Some(Fault::Foreign) {
                record.revision += 100;
                outer.data = String::from_utf8(record.encode().unwrap()).unwrap();
            } else {
                outer.data = serde_json::to_string_pretty(&record).unwrap();
            }
            raw = serde_json::to_vec(&outer).unwrap();
        }
        s.bytes.insert(file, raw);
        if fault == Some(Fault::Panic) {
            panic!("private row CAS unwind");
        }
        if fault == Some(Fault::Unreadable) {
            s.unreadable = Some(file);
        }
        if matches!(fault, Some(Fault::Lost | Fault::Equivalent)) {
            Err(io::Error::other("SECRET lost"))
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
        let result = action(self);
        if std::mem::take(&mut self.0.borrow_mut().fail_after) {
            return Err(io::Error::other("private postflight"));
        }
        result
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
fn binding(role: Role) -> Binding {
    let n = match role {
        Role::Carrier => 1,
        Role::MemberA => 2,
        Role::MemberB => 3,
    };
    Binding {
        scope: scope(),
        boot_id: [7; 16],
        runtime: runtime(),
        network_epoch: 1,
        role,
        guid: [n as u8; 16],
        name: format!("owned-{n}"),
        key: RowKey {
            luid: 3000 + n,
            index: 30 + n as u32,
        },
        address: [10, 7, 0, 2],
    }
}
fn initial(role: Role) -> Record {
    let b = binding(role);
    let policy = InterfacePolicy {
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
    };
    let observed = InterfaceObserved {
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
    };
    let baseline = Snapshot {
        interface: InterfaceRow {
            key: b.key,
            policy,
            observed,
        },
        address: None,
    };
    Record {
        version: 1,
        domain: "carrier-native-ipv4-rows-v1".into(),
        binding: b,
        revision: 1,
        phase: Phase::Captured,
        current: baseline.clone(),
        baseline,
        pending: None,
        creation: None,
    }
}
fn bump(r: &Record) -> Record {
    let mut n = r.clone();
    n.revision += 1;
    n
}
fn sequence(role: Role) -> Vec<Record> {
    let mut r = initial(role);
    let mut seq = vec![r.clone()];
    let mut weak = r.current.interface.policy.clone();
    weak.weak_host_send = true;
    weak.weak_host_receive = true;
    r = bump(&r);
    r.pending = Some(Pending {
        before: r.current.clone(),
        target: Target::Interface(weak.clone()),
    });
    seq.push(r.clone());
    r = bump(&r);
    r.current.interface.policy = weak;
    r.current.interface.observed.reachable_time += 1;
    r.pending = None;
    seq.push(r.clone());
    if role == Role::Carrier {
        let p = AddressPolicy {
            address: r.binding.address,
            prefix_origin: 1,
            suffix_origin: 1,
            valid_lifetime: u32::MAX,
            preferred_lifetime: u32::MAX,
            on_link_prefix_length: 32,
            skip_as_source: false,
        };
        r = bump(&r);
        r.pending = Some(Pending {
            before: r.current.clone(),
            target: Target::Create(p.clone()),
        });
        seq.push(r.clone());
        r = bump(&r);
        let a = AddressRow {
            key: r.binding.key,
            policy: p,
            observed: AddressObserved {
                dad_state: 4,
                scope_id: 0,
                creation_timestamp: 123456789,
            },
        };
        r.current.address = Some(a.clone());
        r.creation = Some(a);
        r.pending = None;
        seq.push(r.clone());
    }
    r = bump(&r);
    r.phase = Phase::Closing;
    seq.push(r.clone());
    r = bump(&r);
    r.pending = Some(Pending {
        before: r.current.clone(),
        target: Target::Interface(r.baseline.interface.policy.clone()),
    });
    seq.push(r.clone());
    r = bump(&r);
    r.current.interface.policy = r.baseline.interface.policy.clone();
    r.pending = None;
    seq.push(r.clone());
    if role == Role::Carrier {
        r = bump(&r);
        r.pending = Some(Pending {
            before: r.current.clone(),
            target: Target::Delete,
        });
        seq.push(r.clone());
        r = bump(&r);
        r.current.address = None;
        r.pending = None;
        seq.push(r.clone());
    }
    r = bump(&r);
    r.phase = Phase::Stopped;
    seq.push(r);
    seq
}
fn files(d: &Disk) -> ProtectedSessionFiles<Disk> {
    ProtectedSessionFiles::new(d.clone(), runtime(), [7; 16]).unwrap()
}
fn claimed(d: &Disk) -> ProtectedSessionFiles<Disk> {
    let mut f = files(d);
    f.claim(&scope()).unwrap();
    f
}
fn publish(f: &mut ProtectedSessionFiles<Disk>, records: &[Record]) {
    let (mut store, old) =
        WindowsCarrierRowsStore::open(f.clone(), records[0].binding.clone()).unwrap();
    assert!(old.is_none());
    let mut previous = None;
    for r in records {
        store
            .compare_exchange(&r.binding, previous.as_ref(), r)
            .unwrap();
        assert_eq!(store.load(&r.binding).unwrap().as_ref(), Some(r));
        previous = Some(r.clone());
    }
}
fn close_legacy(f: &mut ProtectedSessionFiles<Disk>) {
    let mut s = SessionState::new(scope(), Slot::A, 0, 0)
        .unwrap()
        .snapshot();
    s.phase = SessionPhase::Stopped;
    let (mut store, _) =
        WindowsSessionStore::open(f.clone(), scope(), RecordKind::Session).unwrap();
    store.save(&s).unwrap();
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
    let (mut p, _) = WindowsPairStore::open(f.clone(), scope(), RecordKind::Pair).unwrap();
    p.save(&pair).unwrap();
}

// Explicit double of Main's unsafe native receipt/root boundary ONLY. All
// private identity, envelope, epoch, CAS and row validation below remain real.
struct GenerationBoundary {
    old: Vec<u8>,
    next: Vec<u8>,
    kind: RecordKind,
    begun: Cell<usize>,
    verified: Cell<usize>,
    disk: Disk,
    reads_before: Cell<usize>,
    reject: Cell<bool>,
    original_files: ProtectedSessionFiles<Disk>,
    pair: Vec<u8>,
    completed_capture: Cell<bool>,
}
impl GenerationBoundary {
    fn new(
        disk: &Disk,
        original_files: &ProtectedSessionFiles<Disk>,
        old: &Record,
        next: &Record,
    ) -> Rc<Self> {
        Rc::new(Self {
            old: old.encode().unwrap(),
            next: next.encode().unwrap(),
            kind: rows_kind(next.binding.role),
            begun: Cell::new(0),
            verified: Cell::new(0),
            disk: disk.clone(),
            reads_before: Cell::new(disk.0.borrow().reads),
            reject: Cell::new(false),
            completed_capture: Cell::new(false),
            original_files: original_files.clone(),
            pair: serde_json::from_slice::<SavedRecord>(&disk.0.borrow().bytes[&PrivateFile::Pair])
                .unwrap()
                .data
                .into_bytes(),
        })
    }
}
// SAFETY: test-only boundary models a once-consumed original token bound to
// these exact payloads. Verification does not call SDK or the Session backend.
unsafe impl OriginalRowGenerationWrite for GenerationBoundary {
    fn begin_write(&self, _: &SessionScope, _: RecordKind, _: &[u8], _: &[u8]) -> io::Result<()> {
        let before = self.begun.replace(self.begun.get() + 1);
        if before != 0 || self.disk.0.borrow().reads != self.reads_before.get() {
            return Err(io::Error::other("generation begin"));
        }
        Ok(())
    }
    fn verify_backend(&self, origin: &OriginalSessionFilesIdentity) -> io::Result<()> {
        if origin.same_original(&self.original_files.read_identity()) {
            Ok(())
        } else {
            Err(io::Error::other("foreign backend"))
        }
    }
    fn verify_storage_backend(&self, origin: &OriginalSessionFilesIdentity) -> io::Result<()> {
        self.verify_backend(origin)
    }
    fn verify_completed_storage_backend(
        &self,
        origin: &OriginalSessionFilesIdentity,
    ) -> io::Result<()> {
        if !self.completed_capture.get() {
            return Err(io::Error::other("capture not completed"));
        }
        self.verify_backend(origin)
    }
    fn verify_cleanup_storage_backend(
        &self,
        origin: &OriginalSessionFilesIdentity,
    ) -> io::Result<()> {
        self.verify_completed_storage_backend(origin)
    }
    fn fail_write(&self) {
        self.reject.set(true);
    }
    fn verify_pair(&self, pair: &[u8]) -> io::Result<()> {
        if pair == self.pair && !self.reject.get() {
            Ok(())
        } else {
            Err(io::Error::other("stale Pair"))
        }
    }
    fn verify_write(
        &self,
        selected_scope: &SessionScope,
        kind: RecordKind,
        old: &[u8],
        next: &[u8],
    ) -> io::Result<()> {
        self.verified.set(self.verified.get() + 1);
        if self.begun.get() != 1
            || self.reject.get()
            || *selected_scope != scope()
            || kind != self.kind
            || old != self.old
            || next != self.next
        {
            return Err(io::Error::other("generation receipt"));
        }
        Ok(())
    }
}
fn generation_fixture(role: Role) -> (Disk, ProtectedSessionFiles<Disk>, Record, Record) {
    let d = Disk::default();
    let mut f = claimed(&d);
    let seq = sequence(role);
    publish(&mut f, &seq);
    let old = seq.last().unwrap().clone();
    let mut next = initial(role);
    next.binding.key.index += 100;
    next.binding.key.luid += 1000;
    next.baseline.interface.key = next.binding.key;
    next.current = next.baseline.clone();
    inject_generation_pair(&d, &next);
    (d, f, old, next)
}
fn inject_generation_pair(d: &Disk, next: &Record) {
    use crate::{
        member_carrier_guard as guard, member_carrier_pair as pair, member_owner as owner,
    };
    use nelomai_contracts::dispatcher::TunnelSlot;
    let c = binding(Role::Carrier);
    let carrier = owner::InterfaceProof {
        index: c.key.index,
        luid: c.key.luid,
        guid: c.guid,
    };
    let members = [Role::MemberA, Role::MemberB].map(|role| {
        let b = if role == next.binding.role {
            next.binding.clone()
        } else {
            binding(role)
        };
        let slot = if role == Role::MemberA {
            TunnelSlot::A
        } else {
            TunnelSlot::B
        };
        Some(pair::MemberState {
            owner: owner::Record {
                intent: owner::Intent {
                    scope: scope(),
                    slot,
                    transport: nelomai_client_tunnel::TunnelTransport::WireGuard,
                    engine: crate::test_engine_path("wireguard.exe"),
                    config_sha256: [4; 32],
                },
                phase: owner::Phase::Running,
                proof: Some(owner::NativeProof {
                    interface: owner::InterfaceProof {
                        index: b.key.index,
                        luid: b.key.luid,
                        guid: b.guid,
                    },
                    process: owner::ProcessProof {
                        pid: b.key.index,
                        creation_time: 100,
                    },
                }),
                retired_proof: None,
                previous_config_sha256: None,
            },
            lease_id: if role == Role::MemberA {
                "22222222-2222-4222-8222-222222222222"
            } else {
                "33333333-3333-4333-8333-333333333333"
            }
            .into(),
            probe: nelomai_contracts::RedundantHealthProbe {
                kind: nelomai_contracts::HealthProbeKind::DnsA,
                target_ipv4: "1.1.1.1".parse().unwrap(),
                query_name: "example.com".into(),
                timeout_ms: 2000,
            },
            endpoint: if role == Role::MemberA {
                "192.0.2.11"
            } else {
                "192.0.2.12"
            }
            .parse()
            .unwrap(),
            allowed: vec!["0.0.0.0/0".parse().unwrap()],
            peer: [3; 32],
        })
    });
    let base = guard::Model::new(
        scope(),
        guard::Carrier {
            identity: guard::Identity {
                scope: scope(),
                proof: carrier,
            },
            sources: vec!["10.7.0.2".parse().unwrap()],
        },
        members.clone().map(|m| {
            m.map(|m| guard::Member {
                identity: guard::Identity {
                    scope: scope(),
                    proof: m.owner.proof.unwrap().interface,
                },
                probes: vec![],
            })
        }),
        None,
    )
    .unwrap()
    .without_permits()
    .unwrap();
    let mut actual = base.expected.clone();
    actual.sublayer.as_mut().unwrap().weight = 41;
    let base = base
        .readback_after(&guard::Model::empty(scope()).unwrap(), &actual)
        .unwrap();
    let target = if next.binding.role == Role::MemberA {
        Slot::A
    } else {
        Slot::B
    };
    let record = pair::Record {
        version: 2,
        scope: scope(),
        provenance: carrier::Provenance {
            boot_id: [7; 16],
            runtime: runtime(),
            network_epoch: 1,
        },
        revision: 10,
        phase: pair::Phase::Running,
        addresses: vec!["10.7.0.2/32".parse().unwrap()],
        dns: vec!["1.1.1.1".parse().unwrap()],
        carrier: Some(carrier),
        members,
        active: Some(if target == Slot::A { Slot::B } else { Slot::A }),
        options: Some(nelomai_client_tunnel::DesktopTunnelOptions::default()),
        guard: base,
        pending_guard: None,
        pending: Some(pair::Effect::WeakRows),
        network: None,
        stop_stage: 0,
        operation: Some(pair::Operation::Attach(target)),
    };
    record.validate().unwrap();
    let saved = SavedRecord {
        version: PRIVATE_VERSION,
        identity: SessionIdentity {
            boot_id: [7; 16],
            runtime: runtime(),
            scope: scope(),
        },
        kind: RecordKind::Pair,
        network_epoch: 1,
        data: String::from_utf8(carrier_pair_store::encode_carrier_payload(&record).unwrap())
            .unwrap(),
    };
    d.0.borrow_mut()
        .bytes
        .insert(PrivateFile::Pair, serde_json::to_vec(&saved).unwrap());
}

// Break: ordinary CAS silently reopens Stopped, or the typed path never checks
// the actual original native token and exact protected stopped payload.
#[test]
fn generation_raw_original_token_replaces_stopped_payload_without_relaxing_normal_cas() {
    for role in [Role::MemberA, Role::MemberB] {
        let (d, mut f, old, next) = generation_fixture(role);
        let token = GenerationBoundary::new(&d, &f, &old, &next);
        f.compare_exchange_row_generation(
            &scope(),
            rows_kind(role),
            &token.old,
            &token.next,
            token.as_ref(),
        )
        .unwrap();
        assert_eq!(
            Record::decode(&f.read(&scope(), rows_kind(role)).unwrap().unwrap()).unwrap(),
            next
        );
        assert_eq!(token.begun.get(), 1);
        assert!(token.verified.get() >= 2);
        let (_, mut ordinary, old, next) = generation_fixture(role);
        assert!(ordinary
            .compare_exchange(
                &scope(),
                rows_kind(role),
                Some(&old.encode().unwrap()),
                &next.encode().unwrap()
            )
            .is_err());
    }
}

// Break: token grants a foreign role/carrier, altered birth identity or pending
// generation, despite private schema validation still accepting those bytes.
#[test]
fn generation_raw_rejects_nonmember_or_changed_immutable_identity_and_unknown_token() {
    for field in 0..12 {
        let role = if field == 0 {
            Role::Carrier
        } else {
            Role::MemberA
        };
        let (d, mut f, old, mut next) = generation_fixture(role);
        match field {
            1 => next.binding.guid = [99; 16],
            2 => next.binding.name = "replacement".into(),
            3 => next.binding.network_epoch += 1,
            4 => next.binding.boot_id = [88; 16],
            5 => next.binding.address = [10, 7, 0, 3],
            6 => next.revision = 2,
            7 => next.phase = Phase::Closing,
            8 => next.current.interface.observed.reachable_time += 1,
            9 => {
                next.binding.role = Role::MemberB;
            }
            10 => {
                next.binding.runtime.runtime_version = "2.0.0".into();
            }
            _ => {}
        }
        let token = GenerationBoundary::new(&d, &f, &old, &next);
        if field == 11 {
            token.reject.set(true);
        }
        let before = d.0.borrow().attempts;
        assert!(
            f.compare_exchange_row_generation(
                &scope(),
                rows_kind(role),
                &token.old,
                &token.next,
                token.as_ref()
            )
            .is_err(),
            "field={field}"
        );
        assert_eq!(d.0.borrow().attempts, before, "field={field}");
    }
}

// Break: a failed first typed CAS is adopted from matching readback or token
// reuse succeeds after lost/unreadable/false/foreign/equivalent private writes.
#[test]
fn generation_raw_lost_ack_never_refreshes_original_fresh_permission_or_reuses_token() {
    for fault in [
        Fault::Fail,
        Fault::Lost,
        Fault::False,
        Fault::Unreadable,
        Fault::Foreign,
        Fault::Equivalent,
    ] {
        let (d, mut f, old, next) = generation_fixture(Role::MemberA);
        let token = GenerationBoundary::new(&d, &f, &old, &next);
        d.0.borrow_mut().fault = Some(fault);
        let before = d.0.borrow().attempts;
        assert!(
            f.compare_exchange_row_generation(
                &scope(),
                RecordKind::MemberARows,
                &token.old,
                &token.next,
                token.as_ref()
            )
            .is_err(),
            "{fault:?}"
        );
        assert_eq!(d.0.borrow().attempts, before + 1);
        d.0.borrow_mut().unreadable = None;
        assert!(!f.native_carrier_access(&scope()).unwrap().is_fresh());
        assert!(f
            .compare_exchange_row_generation(
                &scope(),
                RecordKind::MemberARows,
                &token.old,
                &token.next,
                token.as_ref()
            )
            .is_err());
        assert_eq!(d.0.borrow().attempts, before + 1);
    }
}

// Break: a different Backend over equal disk/JSON inherits the token, or a
// current Pair change bypasses its captured original pending-WeakRows ACK.
#[test]
fn generation_raw_foreign_backend_and_stale_pair_never_write() {
    for stale_pair in [false, true] {
        let (d, mut f, old, next) = generation_fixture(Role::MemberA);
        let token = GenerationBoundary::new(&d, &f, &old, &next);
        if stale_pair {
            let mut saved: SavedRecord =
                serde_json::from_slice(&d.0.borrow().bytes[&PrivateFile::Pair]).unwrap();
            let mut p = carrier_pair_payload(&scope(), saved.data.as_bytes())
                .unwrap()
                .unwrap();
            p.revision += 1;
            saved.data =
                String::from_utf8(carrier_pair_store::encode_carrier_payload(&p).unwrap()).unwrap();
            d.0.borrow_mut()
                .bytes
                .insert(PrivateFile::Pair, serde_json::to_vec(&saved).unwrap());
        } else {
            f = files(&d);
        }
        let attempts = d.0.borrow().attempts;
        assert!(f
            .compare_exchange_row_generation(
                &scope(),
                RecordKind::MemberARows,
                &token.old,
                &token.next,
                token.as_ref()
            )
            .is_err());
        assert_eq!(d.0.borrow().attempts, attempts);
        assert!(token.reject.get());
    }
}

// Break: the logical hole is exposed over replacement bytes, or the first
// generation CAS serializes old data instead of using the retained exact bytes.
#[test]
fn generation_adapter_loads_none_only_until_actual_first_cas_then_uses_normal_transitions() {
    let (d, f, old, next) = generation_fixture(Role::MemberA);
    let token = GenerationBoundary::new(&d, &f, &old, &next);
    let mut store = WindowsCarrierRowsStore::open_generation(
        f.clone(),
        next.binding.clone(),
        token.old.clone(),
        token.clone(),
    );
    assert!(store.load(&next.binding).unwrap().is_none());
    assert_eq!(
        f.clone().read(&scope(), RecordKind::MemberARows).unwrap(),
        Some(token.old.clone())
    );
    token.reads_before.set(d.0.borrow().reads);
    store.compare_exchange(&next.binding, None, &next).unwrap();
    assert_eq!(store.load(&next.binding).unwrap(), Some(next.clone()));
    token.completed_capture.set(true); // explicit test-only full native boundary
    let mut pending = bump(&next);
    let mut weak = next.current.interface.policy.clone();
    weak.weak_host_send = true;
    weak.weak_host_receive = true;
    pending.pending = Some(Pending {
        before: next.current.clone(),
        target: Target::Interface(weak),
    });
    store
        .compare_exchange(&next.binding, Some(&next), &pending)
        .unwrap();
    assert_eq!(store.load(&next.binding).unwrap(), Some(pending));
    assert_eq!(token.begun.get(), 1);
}

// Break: constructor/load treats an equal-looking new captured file as its
// own ACK after lost CAS, or a failed holder can retry/resume via readback.
#[test]
fn generation_adapter_never_adopts_lost_first_ack_or_changed_old_payload() {
    for lost in [false, true] {
        let (d, f, old, next) = generation_fixture(Role::MemberB);
        let token = GenerationBoundary::new(&d, &f, &old, &next);
        let mut store = WindowsCarrierRowsStore::open_generation(
            f.clone(),
            next.binding.clone(),
            token.old.clone(),
            token.clone(),
        );
        if lost {
            d.0.borrow_mut().fault = Some(Fault::Lost);
            assert!(store.compare_exchange(&next.binding, None, &next).is_err());
        } else {
            inject(&d, &next);
            assert!(store.load(&next.binding).is_err());
        }
        let attempts = d.0.borrow().attempts;
        assert!(store.load(&next.binding).is_err());
        assert!(store.compare_exchange(&next.binding, None, &next).is_err());
        assert_eq!(d.0.borrow().attempts, attempts);
    }
}

#[test]
fn generation_identity_keeps_protected_files_send_without_global_rc_tokens() {
    fn require_send<T: Send>() {}
    require_send::<ProtectedSessionFiles<()>>();
}

// Only external SCM/process/config/journal operations are doubled here. The
// original live registration, successful rebind ACK and Stop receipt are all
// issued by the actual MemberOwner/RetainedMember/RetainedMemberOrigin code.
use crate::{member_original as original, member_owner as member};
#[derive(Default)]
struct GenerationMemberState {
    record: Option<member::Record>,
    digest: Option<[u8; 32]>,
    service: Option<Rc<()>>,
    running: bool,
    process: u32,
}
#[derive(Clone)]
struct GenerationMemberDisk(Rc<RefCell<GenerationMemberState>>);
impl member::Journal for GenerationMemberDisk {
    fn load(
        &mut self,
        _: nelomai_contracts::dispatcher::TunnelSlot,
    ) -> member::Result<Option<member::Record>> {
        Ok(self.0.borrow().record.clone())
    }
    fn compare_exchange(
        &mut self,
        _: nelomai_contracts::dispatcher::TunnelSlot,
        expected: Option<&member::Record>,
        desired: &member::Record,
    ) -> member::Result<()> {
        let mut state = self.0.borrow_mut();
        if state.record.as_ref() != expected {
            return Err(member::OwnerError::Conflict);
        }
        state.record = Some(desired.clone());
        Ok(())
    }
}
struct GenerationMemberNative {
    state: Rc<RefCell<GenerationMemberState>>,
    interface: member::InterfaceProof,
}
impl GenerationMemberNative {
    fn observation(&self, retained: Option<&member::NativeProof>) -> member::Observation {
        let s = self.state.borrow();
        member::Observation {
            config_sha256: s.digest,
            service: s.service.as_ref().map(|_| member::ServiceObservation {
                exact_spec: true,
                process: s.running.then_some(member::ProcessProof {
                    pid: s.process,
                    creation_time: u64::from(s.process) + 100,
                }),
            }),
            alternative_service_present: false,
            interface: s.running.then_some(self.interface),
            retained_interfaces: if s.running && retained.is_some() {
                vec![self.interface]
            } else {
                vec![]
            },
        }
    }
}
impl member::OriginalMemberNative for GenerationMemberNative {
    type Service = Rc<()>;
    type Process = member::ProcessProof;
    fn create(&mut self, _: &member::Intent) -> member::Result<Self::Service> {
        let service = Rc::new(());
        self.state.borrow_mut().service = Some(service.clone());
        Ok(service)
    }
    fn finish_created(&mut self, _: &Self::Service) -> member::Result<()> {
        self.state.borrow_mut().running = true;
        self.state.borrow_mut().process = 50;
        Ok(())
    }
    fn running_pid(&mut self, _: &Self::Service) -> member::Result<u32> {
        let s = self.state.borrow();
        Ok(if s.running { s.process } else { 0 })
    }
    fn pin_process(&mut self, pid: u32) -> member::Result<Self::Process> {
        Ok(member::ProcessProof {
            pid,
            creation_time: u64::from(pid) + 100,
        })
    }
    fn query_process(
        &mut self,
        process: &Self::Process,
    ) -> member::Result<(member::ProcessProof, u32)> {
        let s = self.state.borrow();
        Ok((
            *process,
            if s.running && s.process == process.pid {
                259
            } else {
                0
            },
        ))
    }
    fn observe(
        &mut self,
        service: &Self::Service,
        _: &member::Intent,
        retained: Option<&member::NativeProof>,
    ) -> member::Result<member::OriginalMemberFacts> {
        let s = self.state.borrow();
        if s.service
            .as_ref()
            .is_none_or(|own| !Rc::ptr_eq(own, service))
        {
            return Err(member::OwnerError::Conflict);
        }
        Ok(member::OriginalMemberFacts {
            exact_spec: true,
            pid: if s.running { s.process } else { 0 },
            alternative_service_present: false,
            interface: s.running.then_some(self.interface),
            retained_interfaces: if s.running && retained.is_some() {
                vec![self.interface]
            } else {
                vec![]
            },
        })
    }
    fn observe_cleanup(
        &mut self,
        _: &Self::Service,
        _: &member::Intent,
        retained: Option<&member::NativeProof>,
    ) -> member::Result<member::Observation> {
        Ok(self.observation(retained))
    }
    fn stop(&mut self, _: &Self::Service) -> member::Result<()> {
        self.state.borrow_mut().running = false;
        Ok(())
    }
    fn start_existing(&mut self, _: &Self::Service) -> member::Result<()> {
        let mut s = self.state.borrow_mut();
        s.process += 1;
        s.running = true;
        Ok(())
    }
    fn delete(&mut self, _: &Self::Service) -> member::Result<()> {
        self.state.borrow_mut().service = None;
        Ok(())
    }
}
struct GenerationMemberIo {
    origin: member::RetainedMemberOrigin<Rc<()>, member::ProcessProof>,
    native: GenerationMemberNative,
}
impl member::MemberIo for GenerationMemberIo {
    fn inspect(
        &mut self,
        _: &member::Intent,
        retained: Option<&member::NativeProof>,
    ) -> member::Result<member::Observation> {
        Ok(self.native.observation(retained))
    }
    fn inspect_original(
        &mut self,
        intent: &member::Intent,
        retained: &member::NativeProof,
    ) -> member::Result<member::Observation> {
        let digest = self.native.state.borrow().digest;
        self.origin
            .inspect_original(&mut self.native, intent, retained, || Ok(digest))
    }
    fn inspect_original_for_cleanup(
        &mut self,
        intent: &member::Intent,
        retained: &member::NativeProof,
    ) -> member::Result<member::Observation> {
        let digest = self.native.state.borrow().digest;
        self.origin
            .inspect_original_for_cleanup(&mut self.native, intent, retained, || Ok(digest))
    }
    fn revoke_original(&mut self) {
        self.origin.revoke();
    }
    fn write_private_config(
        &mut self,
        intent: &member::Intent,
        expected: Option<[u8; 32]>,
        _: &str,
    ) -> member::Result<()> {
        let mut s = self.native.state.borrow_mut();
        if s.digest != expected {
            return Err(member::OwnerError::Conflict);
        }
        s.digest = Some(intent.config_sha256);
        Ok(())
    }
    fn start_fresh(
        &mut self,
        intent: &member::Intent,
        _: Option<&member::NativeProof>,
    ) -> member::Result<()> {
        self.origin.start(&mut self.native, intent)
    }
    fn stop_slot(
        &mut self,
        intent: &member::Intent,
        retained: Option<&member::NativeProof>,
        expected: &member::Observation,
    ) -> member::Result<()> {
        self.origin
            .stop_delete(&mut self.native, intent, retained, expected)
    }
    fn rebind(
        &mut self,
        _: &member::Intent,
        _: &member::NativeProof,
        _: &member::Observation,
    ) -> member::Result<()> {
        Err(member::OwnerError::Native)
    }
}
impl member::OriginalMemberRebindIo for GenerationMemberIo {
    fn rebind_original(
        &mut self,
        intent: &member::Intent,
        old: &member::NativeProof,
    ) -> member::Result<Rc<member::OriginalRebindAck>> {
        let digest = self.native.state.borrow().digest;
        self.origin
            .rebind_original(&mut self.native, intent, old, || Ok(digest))
    }
    fn read_rebound_original(
        &mut self,
        ack: &Rc<member::OriginalRebindAck>,
    ) -> member::Result<member::NativeProof> {
        let digest = self.native.state.borrow().digest;
        self.origin
            .read_rebound_original(&mut self.native, ack, || Ok(digest))
    }
}
type GenerationMember = original::RetainedMember<GenerationMemberDisk, GenerationMemberIo>;
fn generation_member(
    next: &Record,
) -> (
    GenerationMember,
    member::Record,
    original::OriginalMemberRegistration<GenerationMemberDisk, GenerationMemberIo>,
) {
    let state = Rc::new(RefCell::new(GenerationMemberState::default()));
    let io = GenerationMemberIo {
        origin: member::RetainedMemberOrigin::empty(),
        native: GenerationMemberNative {
            state: state.clone(),
            interface: member::InterfaceProof {
                index: next.binding.key.index,
                luid: next.binding.key.luid,
                guid: next.binding.guid,
            },
        },
    };
    let owner = member::MemberOwner::from_trusted_engine(
        scope(),
        nelomai_contracts::dispatcher::TunnelSlot::A,
        nelomai_client_tunnel::TunnelTransport::WireGuard,
        crate::test_engine_path("engine.exe"),
        "[Interface]\nPrivateKey = PRIVATE-TEST-KEY\nDNS = 9.9.9.9\n[Peer]\nPublicKey = test\n",
        GenerationMemberDisk(state),
        io,
    )
    .unwrap();
    let mut member = original::RetainedMember::new(owner);
    let running = member.start_with_prior(None).unwrap();
    let registration = member.original_read().unwrap().registration().unwrap();
    (member, running, registration)
}
struct GenerationLifecycleBoundary {
    base: Rc<GenerationBoundary>,
    started: original::OriginalMemberRegistration<GenerationMemberDisk, GenerationMemberIo>,
    // Test-only native full-postflight boundary. Never a production grant.
    completed_capture: RefCell<Option<Rc<Record>>>,
}

// Explicit unsafe native-boundary double only. A successful initial protected
// CAS/read pin is retained independently of full native completion. The cleanup
// parent is captured ONLY from the actual bound ExecutionRoot cleanup view.
struct PartialCaptureCleanupBoundary {
    initial: GenerationLifecycleBoundary,
    captured: RefCell<Option<Rc<Record>>>,
    closing_parent: RefCell<Option<OriginalSessionFilesIdentity>>,
    cleanup_calls: Cell<usize>,
    fault: Cell<Option<(usize, bool)>>,
}
impl PartialCaptureCleanupBoundary {
    fn new(
        disk: &Disk,
        files: &ProtectedSessionFiles<Disk>,
        old: &Record,
        next: &Record,
        started: original::OriginalMemberRegistration<GenerationMemberDisk, GenerationMemberIo>,
    ) -> Rc<Self> {
        Rc::new(Self {
            initial: GenerationLifecycleBoundary {
                base: GenerationBoundary::new(disk, files, old, next),
                started,
                completed_capture: RefCell::new(None),
            },
            captured: RefCell::new(None),
            closing_parent: RefCell::new(None),
            cleanup_calls: Cell::new(0),
            fault: Cell::new(None),
        })
    }
}
// SAFETY: host-only native boundary; initial one-shot/live verification remains
// unchanged, cleanup verifies retained exact ACK pin and actual parent's identity
// purely. It never queries native SDK or calls back into protected files.
unsafe impl OriginalRowGenerationWrite for PartialCaptureCleanupBoundary {
    fn begin_write(
        &self,
        s: &SessionScope,
        k: RecordKind,
        old: &[u8],
        new: &[u8],
    ) -> io::Result<()> {
        self.initial.begin_write(s, k, old, new)
    }
    fn verify_backend(&self, origin: &OriginalSessionFilesIdentity) -> io::Result<()> {
        self.initial.verify_backend(origin)
    }
    fn verify_storage_backend(&self, origin: &OriginalSessionFilesIdentity) -> io::Result<()> {
        self.initial.verify_storage_backend(origin)
    }
    fn verify_completed_storage_backend(
        &self,
        origin: &OriginalSessionFilesIdentity,
    ) -> io::Result<()> {
        self.initial.verify_completed_storage_backend(origin)
    }
    fn verify_cleanup_storage_backend(
        &self,
        origin: &OriginalSessionFilesIdentity,
    ) -> io::Result<()> {
        let call = self.cleanup_calls.get() + 1;
        self.cleanup_calls.set(call);
        if let Some((at, unwind)) = self.fault.get() {
            if call == at {
                if unwind {
                    panic!("original cleanup callback unwind");
                }
                return Err(io::Error::other("original cleanup callback error"));
            }
        }
        let parent = self.closing_parent.borrow();
        let captured = self.captured.borrow();
        if parent.as_ref().is_none_or(|p| !p.same_original(origin))
            || captured
                .as_ref()
                .is_none_or(|p| p.encode().unwrap() != self.initial.base.next)
        {
            return Err(io::Error::other("no original Closing capture pin"));
        }
        self.initial.base.verify_backend(origin)
    }
    fn verify_pair(&self, bytes: &[u8]) -> io::Result<()> {
        self.initial.verify_pair(bytes)
    }
    fn verify_write(
        &self,
        s: &SessionScope,
        k: RecordKind,
        old: &[u8],
        new: &[u8],
    ) -> io::Result<()> {
        self.initial.verify_write(s, k, old, new)
    }
    fn fail_write(&self) {
        self.initial.fail_write();
    }
}

// Break: full completion is demanded for an actual retained initial Captured
// ACK after native postflight failure, making original Closing cleanup impossible.
#[test]
fn generation_partial_captured_ack_enters_bound_closing_cleanup_without_full_completion() {
    let (disk, original, old, next) = generation_fixture(Role::MemberA);
    let (root, view) = generation_execution_view(&original);
    let (_member, _record, started) = generation_member(&next);
    let token = PartialCaptureCleanupBoundary::new(&disk, &view, &old, &next, started);
    let mut journal = WindowsCarrierRowsStore::open_generation(
        view,
        next.binding.clone(),
        token.initial.base.old.clone(),
        token.clone(),
    );
    journal
        .compare_exchange(&next.binding, None, &next)
        .unwrap();
    *token.captured.borrow_mut() = Some(Rc::new(journal.load(&next.binding).unwrap().unwrap()));
    let cleanup = root.native_cleanup_view(&original).unwrap().into_files();
    *token.closing_parent.borrow_mut() = Some(cleanup.read_identity());
    token.fail_write(); // initial forward/native postflight failed, pin retained
    assert!(token
        .verify_completed_storage_backend(&cleanup.read_identity())
        .is_err());
    journal.enter_cleanup(cleanup).unwrap();
    assert_eq!(journal.load(&next.binding).unwrap(), Some(next.clone()));
    let mut forward = bump(&next);
    let mut weak = next.current.interface.policy.clone();
    weak.weak_host_send = true;
    weak.weak_host_receive = true;
    forward.pending = Some(Pending {
        before: next.current.clone(),
        target: Target::Interface(weak),
    });
    let attempts = disk.0.borrow().attempts;
    assert!(journal
        .compare_exchange(&next.binding, Some(&next), &forward)
        .is_err());
    assert_eq!(disk.0.borrow().attempts, attempts);
    assert_eq!(journal.load(&next.binding).unwrap(), Some(next.clone()));
    let mut closing = bump(&next);
    closing.phase = Phase::Closing;
    journal
        .compare_exchange(&next.binding, Some(&next), &closing)
        .unwrap();
    let mut stopped = bump(&closing);
    stopped.phase = Phase::Stopped;
    journal
        .compare_exchange(&next.binding, Some(&closing), &stopped)
        .unwrap();
    assert_eq!(journal.load(&next.binding).unwrap(), Some(stopped));
    let mut reader = token.initial.base.original_files.clone();
    assert!(reader
        .read_completed_row_generation(&scope(), RecordKind::MemberARows, token.as_ref())
        .is_err());
    assert!(root.current_lease().is_err());
}

// Break: equal foreign/live cleanup files bypass the original parent, or a
// successfully latched handoff keeps working after its original Closing expires.
#[test]
fn generation_partial_cleanup_requires_actual_parent_and_current_cleanup_capability() {
    let (disk, original, old, next) = generation_fixture(Role::MemberB);
    let (root, view) = generation_execution_view(&original);
    let (_member, _record, started) = generation_member(&next);
    let token = PartialCaptureCleanupBoundary::new(&disk, &view, &old, &next, started);
    let mut journal = WindowsCarrierRowsStore::open_generation(
        view.clone(),
        next.binding.clone(),
        token.initial.base.old.clone(),
        token.clone(),
    );
    journal
        .compare_exchange(&next.binding, None, &next)
        .unwrap();
    *token.captured.borrow_mut() = Some(Rc::new(journal.load(&next.binding).unwrap().unwrap()));
    let cleanup = root.native_cleanup_view(&original).unwrap().into_files();
    *token.closing_parent.borrow_mut() = Some(cleanup.read_identity());
    token.fail_write();
    let (_foreign_disk, foreign, _, _) = generation_fixture(Role::MemberB);
    let (foreign_root, _) = generation_execution_view(&foreign);
    for wrong in [
        view,
        foreign_root
            .native_cleanup_view(&foreign)
            .unwrap()
            .into_files(),
    ] {
        assert!(journal.enter_cleanup(wrong).is_err());
        assert!(journal.load(&next.binding).is_err());
    }
    journal.enter_cleanup(cleanup).unwrap();
    assert_eq!(journal.load(&next.binding).unwrap(), Some(next.clone()));
    token.closing_parent.borrow_mut().take(); // dropped actual native-boundary Closing
    let attempts = disk.0.borrow().attempts;
    assert!(journal.load(&next.binding).is_err());
    let mut closing = bump(&next);
    closing.phase = Phase::Closing;
    assert!(journal
        .compare_exchange(&next.binding, Some(&next), &closing)
        .is_err());
    assert_eq!(disk.0.borrow().attempts, attempts);
}

// Break: a typed epoch cleanup view and matching row metadata replace the
// separately mandatory retained native Captured ACK pin or bound Closing.
#[test]
fn generation_partial_cleanup_denies_missing_native_pin_or_closing_despite_typed_files() {
    for missing_pin in [true, false] {
        let (disk, original, old, next) = generation_fixture(Role::MemberA);
        let (root, view) = generation_execution_view(&original);
        let (_member, _record, started) = generation_member(&next);
        let token = PartialCaptureCleanupBoundary::new(&disk, &view, &old, &next, started);
        let mut journal = WindowsCarrierRowsStore::open_generation(
            view,
            next.binding.clone(),
            token.initial.base.old.clone(),
            token.clone(),
        );
        journal
            .compare_exchange(&next.binding, None, &next)
            .unwrap();
        let pin = Rc::new(journal.load(&next.binding).unwrap().unwrap());
        let cleanup = root.native_cleanup_view(&original).unwrap().into_files();
        if missing_pin {
            *token.closing_parent.borrow_mut() = Some(cleanup.read_identity());
        } else {
            *token.captured.borrow_mut() = Some(pin);
        }
        token.fail_write();
        let attempts = disk.0.borrow().attempts;
        assert!(journal.enter_cleanup(cleanup).is_err());
        assert!(journal.load(&next.binding).is_err());
        assert!(journal.first_acknowledged && !journal.inner.cleanup_handoff);
        assert_eq!(disk.0.borrow().attempts, attempts);
    }
}

// Break: partial cleanup's failed/lost ordinary CAS falls back to completed-only
// reads, losing the actual original owner's durable obligation and cleanup retry.
#[test]
fn generation_partial_cleanup_failed_cas_rereads_same_typed_parent_without_completion() {
    for fault in [Fault::Fail, Fault::Lost] {
        let (disk, original, old, next) = generation_fixture(Role::MemberA);
        let (root, view) = generation_execution_view(&original);
        let (_member, _record, started) = generation_member(&next);
        let token = PartialCaptureCleanupBoundary::new(&disk, &view, &old, &next, started);
        let mut journal = WindowsCarrierRowsStore::open_generation(
            view,
            next.binding.clone(),
            token.initial.base.old.clone(),
            token.clone(),
        );
        journal
            .compare_exchange(&next.binding, None, &next)
            .unwrap();
        *token.captured.borrow_mut() = Some(Rc::new(journal.load(&next.binding).unwrap().unwrap()));
        let cleanup = root.native_cleanup_view(&original).unwrap().into_files();
        *token.closing_parent.borrow_mut() = Some(cleanup.read_identity());
        token.fail_write();
        journal.enter_cleanup(cleanup).unwrap();
        let mut closing = bump(&next);
        closing.phase = Phase::Closing;
        disk.0.borrow_mut().fault = Some(fault);
        assert!(journal
            .compare_exchange(&next.binding, Some(&next), &closing)
            .is_err());
        let actual = if fault == Fault::Lost {
            &closing
        } else {
            &next
        };
        assert_eq!(journal.load(&next.binding).unwrap().as_ref(), Some(actual));
        journal
            .compare_exchange(&next.binding, Some(actual), &closing)
            .unwrap();
        assert!(journal.inner.revoked && journal.inner.cleanup_handoff);
        assert!(token.initial.completed_capture.borrow().is_none());
        let mut reader = token.initial.base.original_files.clone();
        assert!(reader
            .read_completed_row_generation(&scope(), RecordKind::MemberARows, token.as_ref())
            .is_err());
        assert!(root.current_lease().is_err());
    }
}

// Break: callback Err/unwind before or after the private bracket publishes the
// partial cleanup channel despite missing genuine original Closing proof.
#[test]
fn generation_partial_cleanup_callback_error_and_unwind_never_publish_handoff() {
    for at in [1, 2] {
        for unwind in [false, true] {
            let (disk, original, old, next) = generation_fixture(Role::MemberA);
            let (root, view) = generation_execution_view(&original);
            let (_member, _record, started) = generation_member(&next);
            let token = PartialCaptureCleanupBoundary::new(&disk, &view, &old, &next, started);
            let mut journal = WindowsCarrierRowsStore::open_generation(
                view,
                next.binding.clone(),
                token.initial.base.old.clone(),
                token.clone(),
            );
            journal
                .compare_exchange(&next.binding, None, &next)
                .unwrap();
            *token.captured.borrow_mut() =
                Some(Rc::new(journal.load(&next.binding).unwrap().unwrap()));
            let cleanup = root.native_cleanup_view(&original).unwrap().into_files();
            *token.closing_parent.borrow_mut() = Some(cleanup.read_identity());
            token.fail_write();
            token.fault.set(Some((at, unwind)));
            let attempts = disk.0.borrow().attempts;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                journal.enter_cleanup(cleanup)
            }));
            if unwind {
                assert!(result.is_err());
            } else {
                assert!(result.unwrap().is_err());
            }
            assert!(journal.cleanup_attempted && !journal.inner.cleanup_handoff);
            assert!(journal.load(&next.binding).is_err());
            assert_eq!(disk.0.borrow().attempts, attempts);
            token.fault.set(None);
            journal
                .enter_cleanup(root.native_cleanup_view(&original).unwrap().into_files())
                .unwrap();
            assert_eq!(journal.load(&next.binding).unwrap(), Some(next.clone()));
            assert!(root.current_lease().is_err());
        }
    }
}

// Break: committed-looking initial Captured bytes after lost ACK/unwind become
// an original cleanup pin despite no successful first CAS acknowledgement.
#[test]
fn generation_partial_cleanup_never_imports_unknown_initial_capture_ack() {
    for fault in [Fault::Fail, Fault::Lost, Fault::Panic] {
        let (disk, original, old, next) = generation_fixture(Role::MemberA);
        let (root, view) = generation_execution_view(&original);
        let (_member, _record, started) = generation_member(&next);
        let token = PartialCaptureCleanupBoundary::new(&disk, &view, &old, &next, started);
        let mut journal = WindowsCarrierRowsStore::open_generation(
            view,
            next.binding.clone(),
            token.initial.base.old.clone(),
            token.clone(),
        );
        disk.0.borrow_mut().fault = Some(fault);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            journal.compare_exchange(&next.binding, None, &next)
        }));
        if fault == Fault::Panic {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert!(!journal.first_acknowledged);
        match root.native_cleanup_view(&original) {
            Ok(cleanup) => {
                let cleanup = cleanup.into_files();
                *token.closing_parent.borrow_mut() = Some(cleanup.read_identity());
                assert!(journal.enter_cleanup(cleanup).is_err());
            }
            Err(_) => {
                // Real backend transaction unwind poisons the private boundary;
                // even typed cleanup construction must deny, not import bytes.
                assert_eq!(fault, Fault::Panic);
            }
        }
        assert_eq!(token.cleanup_calls.get(), 0); // first ACK boundary denied before callback/IO
        assert!(journal.load(&next.binding).is_err());
        assert!(token.captured.borrow().is_none());
        let attempts = disk.0.borrow().attempts;
        assert!(journal
            .compare_exchange(&next.binding, None, &next)
            .is_err());
        assert_eq!(disk.0.borrow().attempts, attempts);
    }
}
impl GenerationLifecycleBoundary {
    fn live(&self) -> io::Result<()> {
        if self.base.reject.get() {
            return Err(io::Error::other("capture forward revoked"));
        }
        self.started
            .verify_current()
            .map_err(|_| io::Error::other("started registration retired"))
    }
}
// SAFETY: test-only original native boundary; callbacks are pure, and initial
// writes always require the actual still-current original Started registration.
unsafe impl OriginalRowGenerationWrite for GenerationLifecycleBoundary {
    fn begin_write(
        &self,
        s: &SessionScope,
        k: RecordKind,
        old: &[u8],
        new: &[u8],
    ) -> io::Result<()> {
        self.live()?;
        self.base.begin_write(s, k, old, new)
    }
    fn verify_backend(&self, origin: &OriginalSessionFilesIdentity) -> io::Result<()> {
        self.live()?;
        self.base.verify_backend(origin)
    }
    fn verify_pair(&self, bytes: &[u8]) -> io::Result<()> {
        self.live()?;
        self.base.verify_pair(bytes)
    }
    fn verify_write(
        &self,
        s: &SessionScope,
        k: RecordKind,
        old: &[u8],
        new: &[u8],
    ) -> io::Result<()> {
        self.live()?;
        self.base.verify_write(s, k, old, new)
    }
    fn verify_storage_backend(&self, origin: &OriginalSessionFilesIdentity) -> io::Result<()> {
        if self.completed_capture.borrow().is_none() {
            self.live()?;
            if self.base.reject.get() {
                return Err(io::Error::other("capture revoked"));
            }
        }
        // Analogous to Main's actual completed registered-pin branch: pure
        // original storage history survives forward selection revocation.
        // Initial begin/verify_backend/verify_write above remain strict.
        self.base.verify_backend(origin)
    }
    fn verify_completed_storage_backend(
        &self,
        origin: &OriginalSessionFilesIdentity,
    ) -> io::Result<()> {
        if self.completed_capture.borrow().is_none() {
            return Err(io::Error::other("capture not completed"));
        }
        self.verify_storage_backend(origin)
    }
    fn verify_cleanup_storage_backend(
        &self,
        origin: &OriginalSessionFilesIdentity,
    ) -> io::Result<()> {
        self.verify_completed_storage_backend(origin)
    }
    fn fail_write(&self) {
        self.base.fail_write();
    }
}

// Break: ordinary journal reads/CAS still require a live initial Started pin
// after an acknowledged capture, original rebind or original Stop receipt.
#[test]
fn generation_completed_capture_continues_after_actual_member_rebind_and_stop() {
    let (d, mut f, old, next) = generation_fixture(Role::MemberA);
    let (mut member, running, started) = generation_member(&next);
    let token = Rc::new(GenerationLifecycleBoundary {
        base: GenerationBoundary::new(&d, &f, &old, &next),
        started,
        completed_capture: RefCell::new(None),
    });
    let mut store = WindowsCarrierRowsStore::open_generation(
        f.clone(),
        next.binding.clone(),
        token.base.old.clone(),
        token.clone(),
    );
    store.compare_exchange(&next.binding, None, &next).unwrap();
    // A successful raw ACK/readback alone is NOT Main's native completion.
    token.live().unwrap();
    *token.completed_capture.borrow_mut() =
        Some(Rc::new(store.load(&next.binding).unwrap().unwrap()));
    let (rebound, receipt, replacement) = member.rebind_original(&running).unwrap();
    member.verify_rebind_receipt(&receipt).unwrap();
    replacement
        .registration()
        .unwrap()
        .verify_current()
        .unwrap();
    assert_ne!(
        running.proof.unwrap().process,
        rebound.proof.unwrap().process
    );
    assert!(token.started.verify_current().is_err());
    assert_eq!(store.load(&next.binding).unwrap(), Some(next.clone()));
    let mut pending = bump(&next);
    let mut weak = next.current.interface.policy.clone();
    weak.weak_host_send = true;
    weak.weak_host_receive = true;
    pending.pending = Some(Pending {
        before: next.current.clone(),
        target: Target::Interface(weak.clone()),
    });
    store
        .compare_exchange(&next.binding, Some(&next), &pending)
        .unwrap();
    let mut current = bump(&pending);
    current.current.interface.policy = weak;
    current.pending = None;
    store
        .compare_exchange(&next.binding, Some(&pending), &current)
        .unwrap();
    // Closing storage/RestoreWeak precedes MemberStop in the actual lifecycle.
    // A live replacement registration does not keep forward storage fresh.
    replacement
        .registration()
        .unwrap()
        .verify_current()
        .unwrap();
    f.revoke_native_carrier_access(&scope()).unwrap();
    assert_eq!(store.load(&next.binding).unwrap(), Some(current.clone()));
    let mut closing = bump(&current);
    closing.phase = Phase::Closing;
    store
        .compare_exchange(&next.binding, Some(&current), &closing)
        .unwrap();
    let mut restore = bump(&closing);
    restore.pending = Some(Pending {
        before: closing.current.clone(),
        target: Target::Interface(closing.baseline.interface.policy.clone()),
    });
    store
        .compare_exchange(&next.binding, Some(&closing), &restore)
        .unwrap();
    let mut restored = bump(&restore);
    restored.current.interface.policy = restored.baseline.interface.policy.clone();
    restored.pending = None;
    store
        .compare_exchange(&next.binding, Some(&restore), &restored)
        .unwrap();
    let mut rows_stopped = bump(&restored);
    rows_stopped.phase = Phase::Stopped;
    store
        .compare_exchange(&next.binding, Some(&restored), &rows_stopped)
        .unwrap();
    assert_eq!(store.load(&next.binding).unwrap(), Some(rows_stopped));
    let (stopped, receipt) = member.stop(&rebound).unwrap();
    member.verify_closed(&receipt).unwrap();
    assert_eq!(stopped.phase, member::Phase::Stopped);
    assert!(replacement.registration().is_err());
    assert_eq!(
        store.load(&next.binding).unwrap().unwrap().phase,
        Phase::Stopped
    );
    assert_eq!(token.base.begun.get(), 1);
    assert!(token
        .begin_write(
            &scope(),
            RecordKind::MemberARows,
            &token.base.old,
            &token.base.next
        )
        .is_err());
}

// Break: retirement permits the first generation write, or a raw ACK alone
// bypasses Main's not-yet-completed native capture postflight.
#[test]
fn generation_uncompleted_capture_denies_actual_started_retirement() {
    for captured in [false, true] {
        let (d, f, old, next) = generation_fixture(Role::MemberA);
        let (mut member, running, started) = generation_member(&next);
        let token = Rc::new(GenerationLifecycleBoundary {
            base: GenerationBoundary::new(&d, &f, &old, &next),
            started,
            completed_capture: RefCell::new(None),
        });
        let mut store = WindowsCarrierRowsStore::open_generation(
            f.clone(),
            next.binding.clone(),
            token.base.old.clone(),
            token.clone(),
        );
        if captured {
            store.compare_exchange(&next.binding, None, &next).unwrap();
        } else {
            // Historical completion cannot make an unacknowledged holder
            // choose continuation permission for its first generation CAS.
            *token.completed_capture.borrow_mut() = Some(Rc::new(next.clone()));
        }
        let (_, receipt) = member.stop(&running).unwrap();
        member.verify_closed(&receipt).unwrap();
        let attempts = d.0.borrow().attempts;
        assert!(store.load(&next.binding).is_err());
        assert!(store.compare_exchange(&next.binding, None, &next).is_err());
        assert_eq!(d.0.borrow().attempts, attempts);
    }
}

// Break: only compare current Pair before CAS, or skip outer private-file
// postflight while returning a successful generation ACK from equal readback.
#[test]
fn generation_raw_pair_drift_after_cas_and_outer_transaction_failure_are_sticky() {
    for drift in [false, true] {
        let (d, mut f, old, next) = generation_fixture(Role::MemberA);
        let token = GenerationBoundary::new(&d, &f, &old, &next);
        if drift {
            let mut pair: SavedRecord =
                serde_json::from_slice(&d.0.borrow().bytes[&PrivateFile::Pair]).unwrap();
            pair.data.push(' '); // valid equivalent payload, NOT same original bytes
            d.0.borrow_mut().pair_race = Some(serde_json::to_vec(&pair).unwrap());
        } else {
            d.0.borrow_mut().fail_after = true;
        }
        let attempts = d.0.borrow().attempts;
        assert!(f
            .compare_exchange_row_generation(
                &scope(),
                RecordKind::MemberARows,
                &token.old,
                &token.next,
                token.as_ref()
            )
            .is_err());
        assert_eq!(d.0.borrow().attempts, attempts + 1);
        assert!(token.reject.get());
        assert!(!f.native_carrier_access(&scope()).unwrap().is_fresh());
    }
}

// Break: an unwound raw write leaves the local holder/token resumable even
// though the private file already contains the exact requested captured bytes.
#[test]
fn generation_adapter_unwind_retains_bytes_and_irrevocably_denies_readback_adoption() {
    let (d, f, old, next) = generation_fixture(Role::MemberA);
    let token = GenerationBoundary::new(&d, &f, &old, &next);
    let mut store = WindowsCarrierRowsStore::open_generation(
        f.clone(),
        next.binding.clone(),
        token.old.clone(),
        token.clone(),
    );
    d.0.borrow_mut().fault = Some(Fault::Panic);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| store.compare_exchange(
            &next.binding,
            None,
            &next
        )))
        .is_err()
    );
    assert!(token.reject.get());
    assert_eq!(token.begun.get(), 1);
    let saved: SavedRecord =
        serde_json::from_slice(&d.0.borrow().bytes[&PrivateFile::MemberARows]).unwrap();
    assert_eq!(saved.data.as_bytes(), token.next);
    let attempts = d.0.borrow().attempts;
    assert!(store.load(&next.binding).is_err());
    assert!(store.compare_exchange(&next.binding, None, &next).is_err());
    assert_eq!(d.0.borrow().attempts, attempts);
}

// Break: explicit selected execution2 rewrites birth1 row identity/envelope,
// or binding1 is accepted on ordinary/unselected files by a generic epoch waiver.
#[test]
fn generation_bound_execution_two_preserves_birth_and_original_root_storage() {
    use crate::member_carrier_native_ownership::{
        Binding as NativeBinding, Context, Role as NativeRole,
    };
    let (d, mut f, old, next) = generation_fixture(Role::MemberA);
    let mut s = SessionState::new(scope(), Slot::A, 0, 0)
        .unwrap()
        .snapshot();
    let mut session = WindowsSessionStore::open(f.clone(), scope(), RecordKind::Session)
        .unwrap()
        .0;
    session.save(&s).unwrap();
    let root = f.session_ack_root(&scope()).unwrap();
    let context = Context {
        intent: carrier::Intent {
            scope: scope(),
            addresses: vec!["10.7.0.2/32".parse().unwrap()],
        },
        provenance: carrier::Provenance {
            boot_id: [7; 16],
            runtime: runtime(),
            network_epoch: 1,
        },
        bindings: std::array::from_fn(|i| {
            let b = binding([Role::Carrier, Role::MemberA, Role::MemberB][i]);
            let n = i + 1;
            let hex = format!("{n:02x}");
            NativeBinding {
                role: [
                    NativeRole::RoleCarrier,
                    NativeRole::MemberA,
                    NativeRole::MemberB,
                ][i],
                guid: b.guid,
                name: b.name,
                registry_path: format!(
                    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{{}-{}-{}-{}-{}}}",
                    hex.repeat(4),
                    hex.repeat(2),
                    hex.repeat(2),
                    hex.repeat(2),
                    hex.repeat(6)
                ),
            }
        }),
    };
    let ack = root.inspect(|facts| Ok(facts.ack.clone())).unwrap();
    let execution = root.bind_native_birth(&context, &ack).unwrap();
    // Canonical files are retained at the actual Starting birth ACK, before
    // later Session writes. This SAME view follows only explicit selections;
    // it is not recreated from the current epoch or a later file snapshot.
    let view = f.native_birth_view(&execution).unwrap();
    let birth = execution.current_lease().unwrap();
    s.phase = SessionPhase::Running;
    s.installed[0] = true;
    s.committed[0] = true;
    s.local_revision += 1;
    session.save(&s).unwrap();
    let ack = root.inspect(|facts| Ok(facts.ack.clone())).unwrap();
    let running = execution.select_running(&birth, &ack).unwrap();
    s.network_epoch = 2;
    session.save(&s).unwrap();
    let ack = root.inspect(|facts| Ok(facts.ack.clone())).unwrap();
    let _renewed = execution.renew_for_rebind(&running, &ack).unwrap();
    assert!(!view.read_identity().same_original(&f.read_identity())); // bound root is also exact
    let token = GenerationBoundary::new(&d, &view, &old, &next);
    let mut store = WindowsCarrierRowsStore::open_generation(
        view,
        next.binding.clone(),
        token.old.clone(),
        token.clone(),
    );
    assert!(store.load(&next.binding).unwrap().is_none());
    token.reads_before.set(d.0.borrow().reads);
    store.compare_exchange(&next.binding, None, &next).unwrap();
    assert_eq!(store.load(&next.binding).unwrap(), Some(next));
    let saved: SavedRecord =
        serde_json::from_slice(&d.0.borrow().bytes[&PrivateFile::MemberARows]).unwrap();
    assert_eq!(saved.network_epoch, 1);
    // Explicit renewal did not make unbound older-epoch generation legal.
    let token = GenerationBoundary::new(&d, &f, &old, &initial(Role::MemberA));
    assert!(f
        .compare_exchange_row_generation(
            &scope(),
            RecordKind::MemberARows,
            &token.old,
            &token.next,
            token.as_ref()
        )
        .is_err());
}
#[test]
fn rows_full_metadata_survives_actual_protected_three_role_journals() {
    let d = Disk::default();
    let mut f = claimed(&d);
    for role in [Role::Carrier, Role::MemberA, Role::MemberB] {
        let seq = sequence(role);
        publish(&mut f, &seq);
        let raw = d.0.borrow().bytes[&rows_file(role)].clone();
        let saved: SavedRecord = serde_json::from_slice(&raw).unwrap();
        assert_eq!(saved.network_epoch, 1);
        assert_eq!(
            Record::decode(saved.data.as_bytes()).unwrap(),
            *seq.last().unwrap()
        );
    }
    close_legacy(&mut f);
    f.complete(&scope()).unwrap();
    assert!(files(&d).claim(&scope()).is_err());
}
#[test]
fn rows_transition_firewall_rejects_unjournaled_two_effects_and_cleanup_create() {
    let seq = sequence(Role::Carrier);
    let mut n = bump(&seq[0]);
    n.current.interface.policy.weak_host_send = true;
    assert!(rows::validate_transition(Some(&seq[0]), &n, false).is_err());
    assert!(rows::validate_transition(Some(&seq[3]), &seq[4], true).is_err());
    assert!(rows::validate_transition(None, &seq[0], true).is_err());
    for (i, r) in seq.iter().enumerate() {
        rows::validate_transition(i.checked_sub(1).map(|j| &seq[j]), r, false).unwrap();
    }
}
#[test]
fn rows_all_present_nonstopped_roles_block_completion_and_empty() {
    for role in [Role::Carrier, Role::MemberA, Role::MemberB] {
        let seq = sequence(role);
        for stop in 1..seq.len() {
            let d = Disk::default();
            let mut f = claimed(&d);
            publish(&mut f, &seq[..stop]);
            close_legacy(&mut f);
            assert!(f.complete(&scope()).is_err());
            assert!(f.complete_empty(&scope()).is_err());
        }
        let d = Disk::default();
        let mut f = claimed(&d);
        publish(&mut f, &seq);
        assert!(f.complete_empty(&scope()).is_err());
        close_legacy(&mut f);
        f.complete(&scope()).unwrap();
    }
}
#[test]
fn rows_each_fresh_revision_ack_fault_revokes_live_shared_and_absent_reopen() {
    for role in [Role::Carrier, Role::MemberA, Role::MemberB] {
        let seq = sequence(role);
        for i in 0..seq.len() {
            for fault in [
                Fault::Fail,
                Fault::Lost,
                Fault::False,
                Fault::Unreadable,
                Fault::Foreign,
                Fault::Equivalent,
            ] {
                let d = Disk::default();
                let f = claimed(&d);
                let (mut store, _) =
                    WindowsCarrierRowsStore::open(f.clone(), binding(role)).unwrap();
                for j in 0..i {
                    store
                        .compare_exchange(
                            &binding(role),
                            j.checked_sub(1).map(|k| &seq[k]),
                            &seq[j],
                        )
                        .unwrap();
                }
                d.0.borrow_mut().fault = Some(fault);
                assert!(
                    store
                        .compare_exchange(
                            &binding(role),
                            i.checked_sub(1).map(|j| &seq[j]),
                            &seq[i]
                        )
                        .is_err(),
                    "{role:?}/{i}/{fault:?}"
                );
                assert!(store.load(&binding(role)).is_err());
                d.0.borrow_mut().unreadable = None;
                assert!(!f.clone().native_carrier_access(&scope()).unwrap().fresh);
                if let Ok((mut cleanup, current)) =
                    WindowsCarrierRowsStore::open(f.clone(), binding(role))
                {
                    if current.is_none() {
                        assert!(cleanup
                            .compare_exchange(&binding(role), None, &seq[0])
                            .is_err());
                    } else if i < 3 {
                        let old = current.unwrap();
                        let mut start = bump(&old);
                        start.pending = Some(Pending {
                            before: old.current.clone(),
                            target: Target::Interface(seq[2].current.interface.policy.clone()),
                        });
                        assert!(cleanup
                            .compare_exchange(&binding(role), Some(&old), &start)
                            .is_err());
                    }
                }
            }
        }
    }
}

// Break: historical storage origin adopts a later normal row CAS's lost ACK
// and reopens the holder merely because desired private bytes were committed.
#[test]
fn generation_completed_capture_normal_cas_lost_ack_stays_revoked() {
    let (d, mut f, old, next) = generation_fixture(Role::MemberA);
    let (_member, _running, started) = generation_member(&next);
    let token = Rc::new(GenerationLifecycleBoundary {
        base: GenerationBoundary::new(&d, &f, &old, &next),
        started,
        completed_capture: RefCell::new(None),
    });
    let mut store = WindowsCarrierRowsStore::open_generation(
        f.clone(),
        next.binding.clone(),
        token.base.old.clone(),
        token.clone(),
    );
    store.compare_exchange(&next.binding, None, &next).unwrap();
    *token.completed_capture.borrow_mut() =
        Some(Rc::new(store.load(&next.binding).unwrap().unwrap()));
    let mut pending = bump(&next);
    let mut weak = next.current.interface.policy.clone();
    weak.weak_host_send = true;
    weak.weak_host_receive = true;
    pending.pending = Some(Pending {
        before: next.current.clone(),
        target: Target::Interface(weak),
    });
    d.0.borrow_mut().fault = Some(Fault::Lost);
    assert!(store
        .compare_exchange(&next.binding, Some(&next), &pending)
        .is_err());
    assert!(!f.native_carrier_access(&scope()).unwrap().is_fresh());
    assert_eq!(
        f.read(&scope(), RecordKind::MemberARows).unwrap(),
        Some(pending.encode().unwrap())
    );
    let attempts = d.0.borrow().attempts;
    // Completed history permits factual cleanup readback, not forward rearm.
    assert_eq!(store.load(&next.binding).unwrap(), Some(pending.clone()));
    assert!(store
        .compare_exchange(&next.binding, Some(&next), &pending)
        .is_err());
    assert_eq!(d.0.borrow().attempts, attempts);
    assert_eq!(token.base.begun.get(), 1);
}

fn generation_execution_view(
    files: &ProtectedSessionFiles<Disk>,
) -> (epoch::ExecutionRoot<Disk>, ProtectedSessionFiles<Disk>) {
    rows_execution_view(files, true)
}

fn rows_execution_view(
    files: &ProtectedSessionFiles<Disk>,
    renew: bool,
) -> (epoch::ExecutionRoot<Disk>, ProtectedSessionFiles<Disk>) {
    use crate::member_carrier_native_ownership::{
        Binding as NativeBinding, Context, Role as NativeRole,
    };
    let mut s = SessionState::new(scope(), Slot::A, 0, 0)
        .unwrap()
        .snapshot();
    let mut writer = WindowsSessionStore::open(files.clone(), scope(), RecordKind::Session)
        .unwrap()
        .0;
    writer.save(&s).unwrap();
    let origin = files.session_ack_root(&scope()).unwrap();
    let context = Context {
        intent: carrier::Intent {
            scope: scope(),
            addresses: vec!["10.7.0.2/32".parse().unwrap()],
        },
        provenance: carrier::Provenance {
            boot_id: [7; 16],
            runtime: runtime(),
            network_epoch: 1,
        },
        bindings: std::array::from_fn(|i| {
            let b = binding([Role::Carrier, Role::MemberA, Role::MemberB][i]);
            let hex = format!("{:02x}", i + 1);
            NativeBinding {
                role: [
                    NativeRole::RoleCarrier,
                    NativeRole::MemberA,
                    NativeRole::MemberB,
                ][i],
                guid: b.guid,
                name: b.name,
                registry_path: format!(
                    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{{}-{}-{}-{}-{}}}",
                    hex.repeat(4),
                    hex.repeat(2),
                    hex.repeat(2),
                    hex.repeat(2),
                    hex.repeat(6)
                ),
            }
        }),
    };
    let ack = origin.inspect(|facts| Ok(facts.ack.clone())).unwrap();
    let root = origin.bind_native_birth(&context, &ack).unwrap();
    let view = files.native_birth_view(&root).unwrap();
    let birth = root.current_lease().unwrap();
    s.phase = SessionPhase::Running;
    s.installed[0] = true;
    s.committed[0] = true;
    s.local_revision += 1;
    writer.save(&s).unwrap();
    let ack = origin.inspect(|facts| Ok(facts.ack.clone())).unwrap();
    let running = root.select_running(&birth, &ack).unwrap();
    if renew {
        s.network_epoch = 2;
        writer.save(&s).unwrap();
        let ack = origin.inspect(|facts| Ok(facts.ack.clone())).unwrap();
        root.renew_for_rebind(&running, &ack).unwrap();
    }
    (root, view)
}

// Break: bound startup journals depend forever on the live execution flight;
// explicit SAME-root cleanup cannot restore their original rows after revoke.
#[test]
fn normal_bound_rows_enter_original_cleanup_after_execution_revocation() {
    for role in [Role::Carrier, Role::MemberA, Role::MemberB] {
        let disk = Disk::default();
        let mut original = files(&disk);
        original.claim(&scope()).unwrap();
        let (root, view) = rows_execution_view(&original, false);
        let records = sequence(role);
        let b = records[0].binding.clone();
        let (mut journal, none) = WindowsCarrierRowsStore::open(view, b.clone()).unwrap();
        assert!(none.is_none());
        journal.compare_exchange(&b, None, &records[0]).unwrap();
        journal
            .compare_exchange(&b, Some(&records[0]), &records[1])
            .unwrap();
        journal
            .compare_exchange(&b, Some(&records[1]), &records[2])
            .unwrap();
        let cleanup = root.native_cleanup_view(&original).unwrap().into_files();
        assert!(journal.load(&b).is_err());
        journal.enter_cleanup(cleanup).unwrap();
        assert_eq!(journal.load(&b).unwrap(), Some(records[2].clone()));
        let mut closing = bump(&records[2]);
        closing.phase = Phase::Closing;
        journal
            .compare_exchange(&b, Some(&records[2]), &closing)
            .unwrap();
        let mut pending = bump(&closing);
        pending.pending = Some(Pending {
            before: closing.current.clone(),
            target: Target::Interface(closing.baseline.interface.policy.clone()),
        });
        journal
            .compare_exchange(&b, Some(&closing), &pending)
            .unwrap();
        let mut restored = bump(&pending);
        restored.current.interface.policy = restored.baseline.interface.policy.clone();
        restored.pending = None;
        journal
            .compare_exchange(&b, Some(&pending), &restored)
            .unwrap();
        let mut stopped = bump(&restored);
        stopped.phase = Phase::Stopped;
        journal
            .compare_exchange(&b, Some(&restored), &stopped)
            .unwrap();
        assert_eq!(journal.load(&b).unwrap(), Some(stopped.clone()));
        assert!(root.current_lease().is_err());
        let mut resume = bump(&stopped);
        resume.phase = Phase::Captured;
        let attempts = disk.0.borrow().attempts;
        assert!(journal
            .compare_exchange(&b, Some(&stopped), &resume)
            .is_err());
        assert_eq!(disk.0.borrow().attempts, attempts);
    }
}

// Break: same-looking files, unbound recovery, or a live view can rearm the
// original holder without the explicit typed SAME execution-root cleanup.
#[test]
fn normal_bound_rows_cleanup_rejects_foreign_unbound_live_and_missing_original_row() {
    for wrong in 0..5 {
        let disk = Disk::default();
        let mut original = files(&disk);
        original.claim(&scope()).unwrap();
        let (root, view) = rows_execution_view(&original, false);
        let row = initial(Role::MemberA);
        let (mut journal, _) =
            WindowsCarrierRowsStore::open(view.clone(), row.binding.clone()).unwrap();
        journal.compare_exchange(&row.binding, None, &row).unwrap();
        let foreign_disk = Disk::default();
        let mut foreign = files(&foreign_disk);
        foreign.claim(&scope()).unwrap();
        let (foreign_root, _) = rows_execution_view(&foreign, false);
        let candidate = match wrong {
            0 => view, // still fresh live, not typed cleanup
            1 => original.recovery_view(scope().runtime).unwrap().unwrap().0,
            2 => foreign_root
                .native_cleanup_view(&foreign)
                .unwrap()
                .into_files(),
            _ => root.native_cleanup_view(&original).unwrap().into_files(),
        };
        if wrong == 3 {
            disk.0.borrow_mut().bytes.remove(&PrivateFile::MemberARows);
        }
        if wrong == 4 {
            disk.0.borrow_mut().unreadable = Some(PrivateFile::MemberARows);
        }
        let attempts = disk.0.borrow().attempts;
        assert!(journal.enter_cleanup(candidate).is_err());
        assert!(journal.load(&row.binding).is_err());
        assert!(journal
            .compare_exchange(&row.binding, Some(&row), &bump(&row))
            .is_err());
        assert_eq!(disk.0.borrow().attempts, attempts);
        assert!(journal.revoked && journal.cleanup_only && !journal.cleanup_handoff);
    }
}

// Break: a failed/lost ordinary initial-owner CAS makes its exact durable
// obligation inaccessible even after explicit original cleanup handoff.
#[test]
fn normal_bound_rows_failed_write_enters_cleanup_without_new_owner_or_forward_retry() {
    for fault in [Fault::Fail, Fault::Lost] {
        let disk = Disk::default();
        let mut original = files(&disk);
        original.claim(&scope()).unwrap();
        let (root, view) = rows_execution_view(&original, false);
        let records = sequence(Role::MemberB);
        let b = records[0].binding.clone();
        let (mut journal, _) = WindowsCarrierRowsStore::open(view, b.clone()).unwrap();
        journal.compare_exchange(&b, None, &records[0]).unwrap();
        disk.0.borrow_mut().fault = Some(fault);
        assert!(journal
            .compare_exchange(&b, Some(&records[0]), &records[1])
            .is_err());
        assert!(journal.load(&b).is_err());
        journal
            .enter_cleanup(root.native_cleanup_view(&original).unwrap().into_files())
            .unwrap();
        let actual = if fault == Fault::Lost {
            &records[1]
        } else {
            &records[0]
        };
        assert_eq!(journal.load(&b).unwrap().as_ref(), Some(actual));
        assert!(journal.revoked); // native/forward latch never cleared
        let attempts = disk.0.borrow().attempts;
        // A lost ACK already stored records[1]; its exact idempotent reread is
        // not a weak-host grant. Reject the actual forward mutation instead.
        let forward = if fault == Fault::Lost {
            &records[2]
        } else {
            &records[1]
        };
        assert!(journal.compare_exchange(&b, Some(actual), forward).is_err());
        assert_eq!(disk.0.borrow().attempts, attempts);
        let mut closing = bump(actual);
        closing.phase = Phase::Closing;
        closing.pending = None; // exact actual-before baseline; cancels pending weak grant
        journal
            .compare_exchange(&b, Some(actual), &closing)
            .unwrap();
        let mut stopped = bump(&closing);
        stopped.phase = Phase::Stopped;
        journal
            .compare_exchange(&b, Some(&closing), &stopped)
            .unwrap();
        assert_eq!(journal.load(&b).unwrap(), Some(stopped));
        assert!(root.current_lease().is_err());
    }
}

// Break: normal cleanup reconstructs a current-epoch binding instead of keeping
// the original birth1 row journal after explicit execution renewal to2.
#[test]
fn normal_bound_rows_cleanup_preserves_birth_after_actual_session_epoch_renewal() {
    let disk = Disk::default();
    let mut original = files(&disk);
    original.claim(&scope()).unwrap();
    let (root, view) = rows_execution_view(&original, false);
    let row = initial(Role::Carrier);
    let (mut journal, _) = WindowsCarrierRowsStore::open(view, row.binding.clone()).unwrap();
    journal.compare_exchange(&row.binding, None, &row).unwrap();
    let (mut writer, current) =
        WindowsSessionStore::open(original.clone(), scope(), RecordKind::Session).unwrap();
    let mut session = current.unwrap();
    let before = root.current_lease().unwrap();
    session.network_epoch = 2;
    writer.save(&session).unwrap();
    let origin = original.session_ack_root(&scope()).unwrap();
    let ack = origin.inspect(|facts| Ok(facts.ack.clone())).unwrap();
    root.renew_for_rebind(&before, &ack).unwrap();
    journal
        .enter_cleanup(root.native_cleanup_view(&original).unwrap().into_files())
        .unwrap();
    assert_eq!(journal.load(&row.binding).unwrap(), Some(row.clone()));
    let mut closing = bump(&row);
    closing.phase = Phase::Closing;
    journal
        .compare_exchange(&row.binding, Some(&row), &closing)
        .unwrap();
    let saved: SavedRecord =
        serde_json::from_slice(&disk.0.borrow().bytes[&PrivateFile::CarrierRows]).unwrap();
    assert_eq!(saved.network_epoch, 1);
    assert_eq!(
        Record::decode(saved.data.as_bytes())
            .unwrap()
            .binding
            .network_epoch,
        1
    );
    assert!(root.current_lease().is_err());
}

// Break: pointer-only matching admits cleanup when its strong original root
// has expired; or failed postflight accidentally enables the holder.
#[test]
fn normal_bound_rows_cleanup_requires_live_original_root_and_successful_private_bracket() {
    for expired in [true, false] {
        let disk = Disk::default();
        let mut original = files(&disk);
        original.claim(&scope()).unwrap();
        let (root, view) = rows_execution_view(&original, false);
        let row = initial(Role::MemberA);
        let (mut journal, _) = WindowsCarrierRowsStore::open(view, row.binding.clone()).unwrap();
        journal.compare_exchange(&row.binding, None, &row).unwrap();
        let cleanup = root.native_cleanup_view(&original).unwrap().into_files();
        if expired {
            drop(root);
        } else {
            disk.0.borrow_mut().fail_after = true;
        }
        assert!(journal.enter_cleanup(cleanup).is_err());
        assert!(journal.load(&row.binding).is_err());
        assert!(!journal.cleanup_handoff);
    }
}

// Break: an unconfirmed Interface outcome can only persist as Captured, or
// exact before/after resolution loses original pending bytes during bound cleanup.
// Existing firewall behavior is characterized here; no new native grant.
#[test]
fn normal_bound_pending_interface_readback_failure_resolves_only_as_closing() {
    for role in [Role::Carrier, Role::MemberA, Role::MemberB] {
        for after in [false, true] {
            let disk = Disk::default();
            let mut original = files(&disk);
            original.claim(&scope()).unwrap();
            let (root, view) = rows_execution_view(&original, false);
            let records = sequence(role);
            let binding = records[0].binding.clone();
            let (mut journal, _) = WindowsCarrierRowsStore::open(view, binding.clone()).unwrap();
            journal
                .compare_exchange(&binding, None, &records[0])
                .unwrap();
            journal
                .compare_exchange(&binding, Some(&records[0]), &records[1])
                .unwrap();
            // A false private ACK leaves the original pending bytes unchanged;
            // actual native before/after outcome is Main RowOwner's separate proof.
            disk.0.borrow_mut().fault = Some(Fault::False);
            assert!(journal
                .compare_exchange(&binding, Some(&records[1]), &records[2])
                .is_err());
            let mut cleanup = root.native_cleanup_view(&original).unwrap().into_files();
            assert!(!cleanup.native_carrier_access(&scope()).unwrap().is_fresh());
            journal.enter_cleanup(cleanup).unwrap();
            assert_eq!(journal.load(&binding).unwrap(), Some(records[1].clone()));
            let mut resolved = bump(&records[1]);
            resolved.pending = None;
            resolved.current = if after {
                records[2].current.clone()
            } else {
                records[1].current.clone()
            };
            let attempts = disk.0.borrow().attempts;
            assert!(journal
                .compare_exchange(&binding, Some(&records[1]), &resolved)
                .is_err());
            assert_eq!(disk.0.borrow().attempts, attempts); // Captured confirmation cannot resume
            resolved.phase = Phase::Closing;
            journal
                .compare_exchange(&binding, Some(&records[1]), &resolved)
                .unwrap();
            assert_eq!(journal.load(&binding).unwrap(), Some(resolved.clone()));
            let mut pending = bump(&resolved);
            pending.pending = Some(Pending {
                before: resolved.current.clone(),
                target: Target::Interface(resolved.baseline.interface.policy.clone()),
            });
            journal
                .compare_exchange(&binding, Some(&resolved), &pending)
                .unwrap();
            let mut restored = bump(&pending);
            restored.pending = None;
            restored.current.interface.policy = restored.baseline.interface.policy.clone();
            journal
                .compare_exchange(&binding, Some(&pending), &restored)
                .unwrap();
            let mut stopped = bump(&restored);
            stopped.phase = Phase::Stopped;
            journal
                .compare_exchange(&binding, Some(&restored), &stopped)
                .unwrap();
            assert!(journal.revoked && journal.cleanup_only && journal.cleanup_handoff);
            assert!(root.current_lease().is_err());
            let saved: SavedRecord =
                serde_json::from_slice(&disk.0.borrow().bytes[&rows_file(role)]).unwrap();
            assert_eq!(saved.network_epoch, 1);
            assert_eq!(Record::decode(saved.data.as_bytes()).unwrap(), stopped);
        }
    }
}

// Break: cleanup confirmation may adopt a foreign outcome, new baseline/binding,
// or changed protected record rather than exact original pending before/target.
#[test]
fn normal_bound_pending_interface_cleanup_denies_foreign_outcome_and_original_byte_drift() {
    for wrong in 0..5 {
        let disk = Disk::default();
        let mut original = files(&disk);
        original.claim(&scope()).unwrap();
        let (root, view) = rows_execution_view(&original, false);
        let records = sequence(Role::MemberA);
        let binding = records[0].binding.clone();
        let (mut journal, _) = WindowsCarrierRowsStore::open(view, binding.clone()).unwrap();
        journal
            .compare_exchange(&binding, None, &records[0])
            .unwrap();
        journal
            .compare_exchange(&binding, Some(&records[0]), &records[1])
            .unwrap();
        journal
            .enter_cleanup(root.native_cleanup_view(&original).unwrap().into_files())
            .unwrap();
        let mut resolved = bump(&records[1]);
        resolved.phase = Phase::Closing;
        resolved.pending = None;
        match wrong {
            0 => resolved.current.interface.policy.metric += 1,
            1 => resolved.binding.key.index += 1,
            2 => resolved.baseline.interface.policy.metric += 1,
            3 => resolved.binding.guid = [99; 16],
            _ => {
                let mut replacement = records[1].clone();
                replacement.revision += 10;
                inject(&disk, &replacement); // external private CAS race, not an original ACK
            }
        }
        let bytes_before = disk.0.borrow().bytes[&PrivateFile::MemberARows].clone();
        let attempts = disk.0.borrow().attempts;
        assert!(journal
            .compare_exchange(&binding, Some(&records[1]), &resolved)
            .is_err());
        assert_eq!(disk.0.borrow().attempts, attempts);
        assert_eq!(
            disk.0.borrow().bytes[&PrivateFile::MemberARows],
            bytes_before
        );
        assert!(root.current_lease().is_err());
    }
}

// Break: a failed explicit generation handoff opens reads/writes merely because
// cleanup_only was latched, without the actual SAME-root typed cleanup bracket.
#[test]
fn generation_failed_bound_cleanup_handoff_stays_closed_until_actual_typed_parent_validates() {
    for wrong in 0..3 {
        let (disk, original, old, next) = generation_fixture(Role::MemberA);
        let (root, mut view) = generation_execution_view(&original);
        let (_member, _running, started) = generation_member(&next);
        let token = Rc::new(GenerationLifecycleBoundary {
            base: GenerationBoundary::new(&disk, &view, &old, &next),
            started,
            completed_capture: RefCell::new(None),
        });
        let mut journal = WindowsCarrierRowsStore::open_generation(
            view.clone(),
            next.binding.clone(),
            token.base.old.clone(),
            token.clone(),
        );
        journal
            .compare_exchange(&next.binding, None, &next)
            .unwrap();
        *token.completed_capture.borrow_mut() =
            Some(Rc::new(journal.load(&next.binding).unwrap().unwrap()));
        let candidate = match wrong {
            0 => view.clone(), // registered live birth view, NOT cleanup
            1 => {
                original
                    .clone()
                    .recovery_view(scope().runtime)
                    .unwrap()
                    .unwrap()
                    .0
            }
            _ => {
                let cleanup = root.native_cleanup_view(&original).unwrap().into_files();
                disk.0.borrow_mut().fail_after = true;
                cleanup
            }
        };
        assert!(journal.enter_cleanup(candidate).is_err());
        let attempts = disk.0.borrow().attempts;
        assert!(journal.load(&next.binding).is_err());
        let mut closing = bump(&next);
        closing.phase = Phase::Closing;
        assert!(journal
            .compare_exchange(&next.binding, Some(&next), &closing)
            .is_err());
        assert_eq!(disk.0.borrow().attempts, attempts);
        // Retry only the typed storage handoff, never the initial capture grant.
        journal
            .enter_cleanup(root.native_cleanup_view(&original).unwrap().into_files())
            .unwrap();
        assert_eq!(journal.load(&next.binding).unwrap(), Some(next.clone()));
        journal
            .compare_exchange(&next.binding, Some(&next), &closing)
            .unwrap();
        assert!(root.current_lease().is_err());
        assert!(token.verify_backend(&view.read_identity()).is_err());
        assert!(!view
            .native_carrier_access(&scope())
            .is_ok_and(|a| a.is_fresh()));
    }
}

// Break: raw first ACK is mistaken for full native completion and authorizes
// subsequent WeakRows writes before its original completed pin exists.
#[test]
fn generation_raw_ack_without_full_completion_denies_ordinary_write() {
    let (d, f, old, next) = generation_fixture(Role::MemberA);
    let (_member, _running, started) = generation_member(&next);
    let token = Rc::new(GenerationLifecycleBoundary {
        base: GenerationBoundary::new(&d, &f, &old, &next),
        started,
        completed_capture: RefCell::new(None),
    });
    let mut store = WindowsCarrierRowsStore::open_generation(
        f,
        next.binding.clone(),
        token.base.old.clone(),
        token.clone(),
    );
    store.compare_exchange(&next.binding, None, &next).unwrap();
    assert_eq!(store.load(&next.binding).unwrap(), Some(next.clone()));
    let mut pending = bump(&next);
    let mut weak = next.current.interface.policy.clone();
    weak.weak_host_send = true;
    weak.weak_host_receive = true;
    pending.pending = Some(Pending {
        before: next.current.clone(),
        target: Target::Interface(weak),
    });
    let attempts = d.0.borrow().attempts;
    assert!(store
        .compare_exchange(&next.binding, Some(&next), &pending)
        .is_err());
    assert_eq!(d.0.borrow().attempts, attempts);
    assert!(store.load(&next.binding).is_err());
}

// Break: completed ordinary cleanup CAS errors prohibit the exact journal.load
// used by actual OwnedRows.persist to retain durable cleanup obligations.
#[test]
fn generation_completed_typed_cleanup_rereads_and_retries_failed_or_lost_ordinary_cas() {
    for fault in [Fault::Fail, Fault::Lost] {
        let (d, original, old, next) = generation_fixture(Role::MemberA);
        let (root, view) = generation_execution_view(&original);
        let (_member, _running, started) = generation_member(&next);
        let token = Rc::new(GenerationLifecycleBoundary {
            base: GenerationBoundary::new(&d, &view, &old, &next),
            started,
            completed_capture: RefCell::new(None),
        });
        let mut store = WindowsCarrierRowsStore::open_generation(
            view,
            next.binding.clone(),
            token.base.old.clone(),
            token.clone(),
        );
        store.compare_exchange(&next.binding, None, &next).unwrap();
        *token.completed_capture.borrow_mut() =
            Some(Rc::new(store.load(&next.binding).unwrap().unwrap()));
        let mut pending = bump(&next);
        let mut weak = next.current.interface.policy.clone();
        weak.weak_host_send = true;
        weak.weak_host_receive = true;
        pending.pending = Some(Pending {
            before: next.current.clone(),
            target: Target::Interface(weak.clone()),
        });
        store
            .compare_exchange(&next.binding, Some(&next), &pending)
            .unwrap();
        let mut current = bump(&pending);
        current.current.interface.policy = weak;
        current.pending = None;
        store
            .compare_exchange(&next.binding, Some(&pending), &current)
            .unwrap();
        let cleanup = root.native_cleanup_view(&original).unwrap().into_files();
        let cleanup_origin = cleanup.read_identity();
        assert!(root.matches_native_view(&cleanup));
        store.enter_cleanup(cleanup).unwrap();
        let mut closing = bump(&current);
        closing.phase = Phase::Closing;
        d.0.borrow_mut().fault = Some(fault);
        assert!(store
            .compare_exchange(&next.binding, Some(&current), &closing)
            .is_err());
        let actual = if fault == Fault::Lost {
            closing.clone()
        } else {
            current.clone()
        };
        assert_eq!(store.load(&next.binding).unwrap(), Some(actual.clone()));
        token
            .verify_completed_storage_backend(&cleanup_origin)
            .unwrap();
        assert!(token.verify_backend(&cleanup_origin).is_err());
        store
            .compare_exchange(&next.binding, Some(&actual), &closing)
            .unwrap();
        let mut restore = bump(&closing);
        restore.pending = Some(Pending {
            before: closing.current.clone(),
            target: Target::Interface(closing.baseline.interface.policy.clone()),
        });
        store
            .compare_exchange(&next.binding, Some(&closing), &restore)
            .unwrap();
        let mut restored = bump(&restore);
        restored.current.interface.policy = restored.baseline.interface.policy.clone();
        restored.pending = None;
        store
            .compare_exchange(&next.binding, Some(&restore), &restored)
            .unwrap();
        let mut stopped = bump(&restored);
        stopped.phase = Phase::Stopped;
        store
            .compare_exchange(&next.binding, Some(&restored), &stopped)
            .unwrap();
        assert_eq!(store.load(&next.binding).unwrap(), Some(stopped));
        let saved: SavedRecord =
            serde_json::from_slice(&d.0.borrow().bytes[&PrivateFile::MemberARows]).unwrap();
        assert_eq!(saved.network_epoch, 1);
        assert!(root.current_lease().is_err()); // no forward selection rearmed
        assert!(token
            .begin_write(
                &scope(),
                RecordKind::MemberARows,
                &token.base.old,
                &token.base.next
            )
            .is_err());
    }
}

// Break: typed cleanup handoff adopts failed initial capture from matching
// committed bytes, or accepts an equivalent foreign backend/root.
#[test]
fn generation_incomplete_failed_capture_never_enters_typed_cleanup() {
    for fault in [Fault::Fail, Fault::Lost] {
        let (d, original, old, next) = generation_fixture(Role::MemberA);
        let (root, view) = generation_execution_view(&original);
        let (_member, _running, started) = generation_member(&next);
        let token = Rc::new(GenerationLifecycleBoundary {
            base: GenerationBoundary::new(&d, &view, &old, &next),
            started,
            completed_capture: RefCell::new(None),
        });
        let mut store = WindowsCarrierRowsStore::open_generation(
            view,
            next.binding.clone(),
            token.base.old.clone(),
            token.clone(),
        );
        d.0.borrow_mut().fault = Some(fault);
        assert!(store.compare_exchange(&next.binding, None, &next).is_err());
        assert!(store
            .enter_cleanup(root.native_cleanup_view(&original).unwrap().into_files())
            .is_err());
        assert!(store.load(&next.binding).is_err());
        assert!(token
            .verify_completed_storage_backend(&token.base.original_files.read_identity())
            .is_err());
    }
}

// Break: a live bound files clone cannot provide immediate factual obligation
// readback after its actual epoch flight is revoked by an ordinary lost ACK.
#[test]
fn generation_bound_forward_failure_rereads_obligation_but_requires_explicit_cleanup_for_writes() {
    let (d, original, old, next) = generation_fixture(Role::MemberA);
    let (root, view) = generation_execution_view(&original);
    let (_member, _running, started) = generation_member(&next);
    let token = Rc::new(GenerationLifecycleBoundary {
        base: GenerationBoundary::new(&d, &view, &old, &next),
        started,
        completed_capture: RefCell::new(None),
    });
    let mut store = WindowsCarrierRowsStore::open_generation(
        view,
        next.binding.clone(),
        token.base.old.clone(),
        token.clone(),
    );
    store.compare_exchange(&next.binding, None, &next).unwrap();
    *token.completed_capture.borrow_mut() =
        Some(Rc::new(store.load(&next.binding).unwrap().unwrap()));
    let mut pending = bump(&next);
    let mut weak = next.current.interface.policy.clone();
    weak.weak_host_send = true;
    weak.weak_host_receive = true;
    pending.pending = Some(Pending {
        before: next.current.clone(),
        target: Target::Interface(weak),
    });
    d.0.borrow_mut().fault = Some(Fault::Lost);
    assert!(store
        .compare_exchange(&next.binding, Some(&next), &pending)
        .is_err());
    assert!(root.current_lease().is_err());
    assert_eq!(store.load(&next.binding).unwrap(), Some(pending.clone()));
    assert!(root.current_lease().is_err());
    assert!(store.inner.revoked && store.inner.cleanup_only);
    // Reconcile the pending mutation's actual before policy for cleanup only.
    // The storage observation does not claim a successful native/row ACK.
    let mut closing = bump(&pending);
    closing.phase = Phase::Closing;
    closing.pending = None;
    let attempts = d.0.borrow().attempts;
    assert!(store
        .compare_exchange(&next.binding, Some(&pending), &closing)
        .is_err());
    assert_eq!(d.0.borrow().attempts, attempts);
    assert_eq!(store.load(&next.binding).unwrap(), Some(pending.clone()));
    store
        .enter_cleanup(root.native_cleanup_view(&original).unwrap().into_files())
        .unwrap();
    store
        .compare_exchange(&next.binding, Some(&pending), &closing)
        .unwrap();
    let mut stopped = bump(&closing);
    stopped.phase = Phase::Stopped;
    store
        .compare_exchange(&next.binding, Some(&closing), &stopped)
        .unwrap();
    assert_eq!(store.load(&next.binding).unwrap(), Some(stopped));
    assert!(store.inner.revoked);
    assert!(root.current_lease().is_err());
    assert!(token
        .begin_write(
            &scope(),
            RecordKind::MemberARows,
            &token.base.old,
            &token.base.next
        )
        .is_err());
}

// Break: the completed obligation read becomes a generic cleanup-files export,
// reads non-row namespaces, adopts foreign origins, or survives a dead root.
#[test]
fn generation_completed_obligation_read_is_fixed_member_readonly_and_same_original_root() {
    let (d, original, old, next) = generation_fixture(Role::MemberA);
    let (root, mut view) = generation_execution_view(&original);
    let (_member, _running, started) = generation_member(&next);
    let token = Rc::new(GenerationLifecycleBoundary {
        base: GenerationBoundary::new(&d, &view, &old, &next),
        started,
        completed_capture: RefCell::new(None),
    });
    let mut store = WindowsCarrierRowsStore::open_generation(
        view.clone(),
        next.binding.clone(),
        token.base.old.clone(),
        token.clone(),
    );
    store.compare_exchange(&next.binding, None, &next).unwrap();
    *token.completed_capture.borrow_mut() =
        Some(Rc::new(store.load(&next.binding).unwrap().unwrap()));
    let writes = d.0.borrow().attempts;
    let (access, bytes) = view
        .read_completed_row_generation(&scope(), RecordKind::MemberARows, token.as_ref())
        .unwrap();
    assert!(!access.is_fresh());
    assert!(access.is_registered_native_birth_view());
    assert_eq!(bytes, Some(next.encode().unwrap()));
    assert_eq!(d.0.borrow().attempts, writes);
    assert!(root.current_lease().is_ok()); // a readonly fact does not publish Runtime cleanup
    for kind in [
        RecordKind::Session,
        RecordKind::Pair,
        RecordKind::Network,
        RecordKind::Carrier,
        RecordKind::CarrierGuard,
        RecordKind::NativeCarrierReceipts,
        RecordKind::CarrierRows,
    ] {
        assert!(view
            .read_completed_row_generation(&scope(), kind, token.as_ref())
            .is_err());
    }
    assert!(files(&d)
        .read_completed_row_generation(&scope(), RecordKind::MemberARows, token.as_ref())
        .is_err());
    let mut foreign_scope = scope();
    foreign_scope.connection_generation += 1;
    assert!(view
        .read_completed_row_generation(&foreign_scope, RecordKind::MemberARows, token.as_ref())
        .is_err());
    drop(root);
    assert!(view
        .read_completed_row_generation(&scope(), RecordKind::MemberARows, token.as_ref())
        .is_err());
}

fn inject(d: &Disk, r: &Record) {
    let saved = SavedRecord {
        version: PRIVATE_VERSION,
        identity: SessionIdentity {
            boot_id: r.binding.boot_id,
            runtime: r.binding.runtime.clone(),
            scope: r.binding.scope.clone(),
        },
        kind: rows_kind(r.binding.role),
        network_epoch: r.binding.network_epoch,
        data: String::from_utf8(r.encode().unwrap()).unwrap(),
    };
    d.0.borrow_mut().bytes.insert(
        rows_file(r.binding.role),
        serde_json::to_vec(&saved).unwrap(),
    );
}
#[test]
fn rows_cleanup_open_downgrades_its_raw_files_not_the_other_live_reader() {
    let d = Disk::default();
    let mut f = claimed(&d);
    let r = initial(Role::Carrier);
    publish(&mut f, &[r.clone()]);
    let (mut cleanup, _) = WindowsCarrierRowsStore::open(f.clone(), r.binding.clone()).unwrap();
    assert!(!cleanup.files.native_carrier_access(&scope()).unwrap().fresh);
    assert!(f.native_carrier_access(&scope()).unwrap().fresh);
    let desired = &sequence(Role::Carrier)[1];
    assert!(cleanup
        .files
        .compare_exchange(
            &scope(),
            rows_kind(Role::Carrier),
            Some(&r.encode().unwrap()),
            &desired.encode().unwrap()
        )
        .is_err());
    assert!(!f.native_carrier_access(&scope()).unwrap().fresh);
}
#[test]
fn rows_invalid_preflight_cas_revokes_shared_claim_without_writing() {
    for fault in 0..4 {
        let d = Disk::default();
        let f = claimed(&d);
        let r = initial(Role::Carrier);
        let (mut store, _) = WindowsCarrierRowsStore::open(f.clone(), r.binding.clone()).unwrap();
        let mut desired = r.clone();
        let mut caller = r.binding.clone();
        match fault {
            0 => desired.domain = "unknown".into(),
            1 => desired.binding.name = "foreign".into(),
            2 => caller.guid = [99; 16],
            _ => desired.revision = 99,
        };
        assert!(store.compare_exchange(&caller, None, &desired).is_err());
        assert!(store.load(&r.binding).is_err());
        assert_eq!(d.0.borrow().attempts, 0);
        assert!(!f.clone().native_carrier_access(&scope()).unwrap().fresh);
        let (mut reopened, old) = WindowsCarrierRowsStore::open(f, r.binding.clone()).unwrap();
        assert!(old.is_none());
        assert!(reopened.compare_exchange(&r.binding, None, &r).is_err());
    }
}
#[test]
fn rows_raw_cleanup_cannot_resume_capture_new_history_or_erase_pending() {
    let seq = sequence(Role::Carrier);
    for (old, next) in [(&seq[0], &seq[1]), (&seq[3], &seq[4]), (&seq[4], &seq[5])] {
        let d = Disk::default();
        let mut f = claimed(&d);
        inject(&d, old);
        let mut v = f.recovery_view(RuntimeSlot::Stable).unwrap().unwrap().0;
        let allowed = next.phase == Phase::Closing;
        assert_eq!(
            v.compare_exchange(
                &scope(),
                rows_kind(Role::Carrier),
                Some(&old.encode().unwrap()),
                &next.encode().unwrap()
            )
            .is_ok(),
            allowed
        );
    }
}
#[test]
fn rows_cleanup_all_noncreate_pending_confirmations_and_ack_faults() {
    for role in [Role::Carrier, Role::MemberA, Role::MemberB] {
        let seq = sequence(role);
        let mut pairs = Vec::new();
        for old in &seq {
            if old.phase == Phase::Stopped {
                continue;
            }
            if old
                .pending
                .as_ref()
                .is_some_and(|p| matches!(p.target, Target::Create(_)))
            {
                continue;
            }
            let mut fence = bump(old);
            fence.phase = Phase::Closing;
            if let Some(p) = &old.pending {
                fence.pending = None;
                match &p.target {
                    Target::Interface(target) => fence.current.interface.policy = target.clone(),
                    Target::Delete => fence.current.address = None,
                    Target::Create(_) => unreachable!(),
                }
            }
            if old.phase == Phase::Captured || old.pending.is_some() {
                pairs.push((old.clone(), fence));
            }
        }
        for pair in seq.windows(2) {
            if pair[0].phase == Phase::Closing {
                pairs.push((pair[0].clone(), pair[1].clone()));
            }
        }
        for (old, next) in pairs {
            rows::validate_transition(Some(&old), &next, true).unwrap();
            for fault in [
                None,
                Some(Fault::Fail),
                Some(Fault::Lost),
                Some(Fault::False),
                Some(Fault::Unreadable),
                Some(Fault::Foreign),
                Some(Fault::Equivalent),
            ] {
                let d = Disk::default();
                let f = claimed(&d);
                inject(&d, &old);
                let (mut store, loaded) =
                    WindowsCarrierRowsStore::open(f, old.binding.clone()).unwrap();
                assert_eq!(loaded, Some(old.clone()));
                d.0.borrow_mut().fault = fault;
                let ok = store
                    .compare_exchange(&old.binding, Some(&old), &next)
                    .is_ok();
                assert_eq!(
                    ok,
                    matches!(fault, None | Some(Fault::Lost)),
                    "{role:?} revision{} {fault:?}",
                    old.revision
                );
                d.0.borrow_mut().unreadable = None;
                let current = store.load(&old.binding);
                if matches!(fault, None | Some(Fault::Lost | Fault::Unreadable)) {
                    assert_eq!(current.unwrap(), Some(next.clone()));
                }
            }
        }
    }
}
#[test]
fn rows_inventory_corruption_orphan_and_future_epoch_blocks_all_claim_paths() {
    for role in [Role::Carrier, Role::MemberA, Role::MemberB] {
        for corrupt in 0..5 {
            let d = Disk::default();
            let mut f = claimed(&d);
            let mut r = initial(role);
            if corrupt == 0 {
                r.binding.network_epoch = 2;
            }
            inject(&d, &r);
            if corrupt > 0 {
                let raw = d.0.borrow().bytes[&rows_file(role)].clone();
                let mut outer: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                match corrupt {
                    1 => outer["data"] = "{}".into(),
                    2 => outer["identity"]["boot_id"] = serde_json::to_value([8u8; 16]).unwrap(),
                    3 => outer["network_epoch"] = 2.into(),
                    _ => outer["kind"] = "Session".into(),
                };
                d.0.borrow_mut()
                    .bytes
                    .insert(rows_file(role), serde_json::to_vec(&outer).unwrap());
            }
            assert!(f.scopes(RuntimeSlot::Stable).is_err());
            assert!(f.recovery_view(RuntimeSlot::Stable).is_err());
            assert!(f.complete_empty(&scope()).is_err());
            assert!(f.complete(&scope()).is_err());
            d.0.borrow_mut().bytes.remove(&PrivateFile::Index);
            assert!(files(&d).claim(&scope()).is_err());
        }
    }
}
#[test]
fn rows_full_binding_caller_is_independent_and_cannot_be_copied_from_foreign_json() {
    let cases: [fn(&mut Binding); 12] = [
        |b| b.boot_id = [8; 16],
        |b| b.runtime.runtime_version = "2".into(),
        |b| b.runtime.container_version = "2".into(),
        |b| b.runtime.manifest_sha256 = "b".repeat(64),
        |b| b.runtime.runtime_contract_version = 2,
        |b| b.scope.runtime_generation += 1,
        |b| b.scope.connection_generation += 1,
        |b| b.name = "foreign".into(),
        |b| b.guid = [9; 16],
        |b| b.key.index += 1,
        |b| b.key.luid += 1,
        |b| b.address[3] += 1,
    ];
    for change in cases {
        let d = Disk::default();
        let mut f = claimed(&d);
        let r = initial(Role::Carrier);
        publish(&mut f, &[r.clone()]);
        let mut b = r.binding;
        change(&mut b);
        assert!(WindowsCarrierRowsStore::open(f, b).is_err());
    }
}
#[test]
fn rows_payload_and_envelope_epoch_context_are_authenticated_independently() {
    for role in [Role::Carrier, Role::MemberA, Role::MemberB] {
        for change in 0..6 {
            let d = Disk::default();
            let mut f = claimed(&d);
            let r = initial(role);
            inject(&d, &r);
            let raw = d.0.borrow().bytes[&rows_file(role)].clone();
            let mut saved: SavedRecord = serde_json::from_slice(&raw).unwrap();
            let mut inner = Record::decode(saved.data.as_bytes()).unwrap();
            match change {
                0 => inner.binding.boot_id = [8; 16],
                1 => inner.binding.runtime.runtime_version = "2".into(),
                2 => inner.binding.network_epoch = 2,
                3 => saved.network_epoch = 2,
                4 => inner.binding.scope.connection_generation += 1,
                _ => {
                    inner.binding.role = if role == Role::Carrier {
                        Role::MemberA
                    } else {
                        Role::Carrier
                    }
                }
            };
            saved.data = String::from_utf8(inner.encode().unwrap()).unwrap();
            d.0.borrow_mut()
                .bytes
                .insert(rows_file(role), serde_json::to_vec(&saved).unwrap());
            assert!(f.read(&scope(), rows_kind(role)).is_err());
            assert!(f.scopes(RuntimeSlot::Stable).is_err());
        }
    }
}
#[test]
fn rows_strict_unknown_nested_fields_required_nullable_and_versions() {
    let r = sequence(Role::Carrier)[3].clone();
    let base = serde_json::to_value(&r).unwrap();
    for path in [
        "",
        "/binding",
        "/binding/scope",
        "/binding/runtime",
        "/baseline",
        "/baseline/interface",
        "/baseline/interface/key",
        "/baseline/interface/policy",
        "/baseline/interface/observed",
        "/current",
        "/pending",
        "/pending/before",
        "/pending/target/value",
    ] {
        let mut v = base.clone();
        let target = if path.is_empty() {
            &mut v
        } else {
            v.pointer_mut(path).unwrap()
        };
        target
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), true.into());
        assert!(
            Record::decode(&serde_json::to_vec(&v).unwrap()).is_err(),
            "{path}"
        );
    }
    for path in ["pending", "creation"] {
        let mut v = base.clone();
        v.as_object_mut().unwrap().remove(path);
        assert!(Record::decode(&serde_json::to_vec(&v).unwrap()).is_err());
    }
    for version in [0, 2, u32::MAX] {
        let mut v = base.clone();
        v["version"] = version.into();
        assert!(Record::decode(&serde_json::to_vec(&v).unwrap()).is_err());
    }
    for key in ["baseline", "current"] {
        let mut v = base.clone();
        v[key].as_object_mut().unwrap().remove("address");
        assert!(Record::decode(&serde_json::to_vec(&v).unwrap()).is_err());
    }
}
#[test]
fn rows_transition_immutables_pending_and_terminal_matrix() {
    let seq = sequence(Role::Carrier);
    for i in 1..seq.len() {
        let old = &seq[i - 1];
        let good = &seq[i];
        rows::validate_transition(Some(old), good, false).unwrap();
        let mut variants = Vec::new();
        let mut n = good.clone();
        n.revision += 1;
        variants.push(n);
        let mut n = good.clone();
        n.baseline.interface.observed.reachable_time += 1;
        variants.push(n);
        let mut n = good.clone();
        n.binding.guid = [77; 16];
        variants.push(n);
        let mut n = good.clone();
        n.current.interface.policy.metric += 1;
        variants.push(n);
        for bad in variants {
            assert!(rows::validate_transition(Some(old), &bad, false).is_err());
        }
    }
    for r in &seq {
        rows::validate_transition(Some(r), r, true).unwrap();
    }
    let stopped = seq.last().unwrap();
    let changed = bump(stopped);
    assert!(rows::validate_transition(Some(stopped), &changed, true).is_err());
    let mut nointent = bump(&seq[0]);
    nointent.creation = seq[4].creation.clone();
    nointent.current.address = seq[4].current.address.clone();
    assert!(rows::validate_transition(Some(&seq[0]), &nointent, false).is_err());
    let mut twoeffects = seq[4].clone();
    twoeffects.current.interface.policy.weak_host_send = false;
    assert!(rows::validate_transition(Some(&seq[3]), &twoeffects, false).is_err());
}
#[test]
fn rows_initial_and_outer_bounds_fail_before_effect_and_shared_access_is_revoked() {
    let d = Disk::default();
    let f = claimed(&d);
    let mut r = initial(Role::Carrier);
    r.binding.runtime.runtime_version = "x".repeat(70000);
    let (mut store, _) = WindowsCarrierRowsStore::open(f.clone(), binding(Role::Carrier)).unwrap();
    assert!(store
        .compare_exchange(&binding(Role::Carrier), None, &r)
        .is_err());
    assert_eq!(d.0.borrow().attempts, 0);
    assert!(!f.clone().native_carrier_access(&scope()).unwrap().fresh);
    for role in [Role::Carrier, Role::MemberA, Role::MemberB] {
        assert_eq!(rows_file(role).limit(), 65536);
    }
}
#[test]
fn rows_exact_old_noncanonical_bytes_and_changed_private_cas() {
    for race in [false, true] {
        let d = Disk::default();
        let f = claimed(&d);
        let r = initial(Role::Carrier);
        inject(&d, &r);
        let raw = d.0.borrow().bytes[&rows_file(Role::Carrier)].clone();
        let mut outer: SavedRecord = serde_json::from_slice(&raw).unwrap();
        outer.data = serde_json::to_string_pretty(&r).unwrap();
        let old = serde_json::to_vec_pretty(&outer).unwrap();
        d.0.borrow_mut().bytes.insert(rows_file(Role::Carrier), old);
        let (mut store, _) = WindowsCarrierRowsStore::open(f.clone(), r.binding.clone()).unwrap();
        let mut close = bump(&r);
        close.phase = Phase::Closing;
        if race {
            let mut replacement = outer;
            replacement.data = serde_json::to_string(&bump(&r)).unwrap();
            d.0.borrow_mut().race = Some(serde_json::to_vec(&replacement).unwrap());
        }
        assert_eq!(
            store.compare_exchange(&r.binding, Some(&r), &close).is_ok(),
            !race
        );
    }
}
#[test]
fn rows_cross_role_guid_name_luid_index_aliases_reject_without_overwrite() {
    for change in 0..4 {
        let d = Disk::default();
        let mut f = claimed(&d);
        let a = initial(Role::Carrier);
        publish(&mut f, &[a.clone()]);
        let mut b = initial(Role::MemberA);
        match change {
            0 => b.binding.guid = a.binding.guid,
            1 => b.binding.name = a.binding.name.to_uppercase(),
            2 => {
                b.binding.key.luid = a.binding.key.luid;
                b.baseline.interface.key = b.binding.key;
                b.current = b.baseline.clone();
            }
            _ => {
                b.binding.key.index = a.binding.key.index;
                b.baseline.interface.key = b.binding.key;
                b.current = b.baseline.clone();
            }
        }
        let (mut store, _) = WindowsCarrierRowsStore::open(f, b.binding.clone()).unwrap();
        assert!(store.compare_exchange(&b.binding, None, &b).is_err());
        assert!(!d.0.borrow().bytes.contains_key(&rows_file(Role::MemberA)));
    }
}

#[test]
fn rows_whole_envelope_bound_and_raw_false_ack_are_not_inner_codec_success() {
    for role in [Role::Carrier, Role::MemberA, Role::MemberB] {
        let d = Disk::default();
        let mut f = claimed(&d);
        let r = initial(role);
        let mut bytes = r.encode().unwrap();
        bytes.resize(65400, b' ');
        assert!(Record::decode(&bytes).is_ok());
        assert!(f
            .compare_exchange(&scope(), rows_kind(role), None, &bytes)
            .is_err());
        assert_eq!(d.0.borrow().attempts, 0);
        assert!(!f.native_carrier_access(&scope()).unwrap().fresh);
        let d = Disk::default();
        let mut f = claimed(&d);
        d.0.borrow_mut().fault = Some(Fault::False);
        assert!(f
            .compare_exchange(&scope(), rows_kind(role), None, &r.encode().unwrap())
            .is_err());
        assert!(!f.native_carrier_access(&scope()).unwrap().fresh);
        assert!(f.complete_empty(&scope()).is_ok()); // trusted absence call; no row bytes exist
    }
}
#[test]
fn rows_epoch_advance_forces_live_failure_but_cleanup_retains_original_context() {
    let d = Disk::default();
    let mut f = claimed(&d);
    let seq = sequence(Role::Carrier);
    let (mut live, _) = WindowsCarrierRowsStore::open(f.clone(), binding(Role::Carrier)).unwrap();
    live.compare_exchange(&binding(Role::Carrier), None, &seq[0])
        .unwrap();
    let mut s = SessionState::new(scope(), Slot::A, 0, 0)
        .unwrap()
        .snapshot();
    s.network_epoch = 2;
    WindowsSessionStore::open(f.clone(), scope(), RecordKind::Session)
        .unwrap()
        .0
        .save(&s)
        .unwrap();
    assert!(live.load(&binding(Role::Carrier)).is_err());
    assert!(live
        .compare_exchange(&binding(Role::Carrier), Some(&seq[0]), &seq[1])
        .is_err());
    let (mut cleanup, _) =
        WindowsCarrierRowsStore::open(f.clone(), binding(Role::Carrier)).unwrap();
    let mut closing = bump(&seq[0]);
    closing.phase = Phase::Closing;
    cleanup
        .compare_exchange(&binding(Role::Carrier), Some(&seq[0]), &closing)
        .unwrap();
    let mut stopped = bump(&closing);
    stopped.phase = Phase::Stopped;
    cleanup
        .compare_exchange(&binding(Role::Carrier), Some(&closing), &stopped)
        .unwrap();
    let raw = d.0.borrow().bytes[&rows_file(Role::Carrier)].clone();
    let saved: SavedRecord = serde_json::from_slice(&raw).unwrap();
    assert_eq!(saved.network_epoch, 1);
    s.phase = SessionPhase::Stopped;
    WindowsSessionStore::open(f.clone(), scope(), RecordKind::Session)
        .unwrap()
        .0
        .save(&s)
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
    WindowsPairStore::open(f.clone(), scope(), RecordKind::Pair)
        .unwrap()
        .0
        .save(&pair)
        .unwrap();
    f.complete(&scope()).unwrap();
}
#[test]
fn rows_previous_boot_runtime_cleanup_uses_only_retained_authenticated_identity() {
    let d = Disk::default();
    let mut f = claimed(&d);
    let r = initial(Role::Carrier);
    publish(&mut f, &[r.clone()]);
    let mut new_runtime = runtime();
    new_runtime.runtime_version = "2".into();
    let mut reboot = ProtectedSessionFiles::new(d.clone(), new_runtime, [8; 16]).unwrap();
    assert!(WindowsCarrierRowsStore::open(reboot.clone(), r.binding.clone()).is_err());
    let (view, changed) = reboot.recovery_view(RuntimeSlot::Stable).unwrap().unwrap();
    assert!(changed);
    let (mut cleanup, _) = WindowsCarrierRowsStore::open(view, r.binding.clone()).unwrap();
    let mut closing = bump(&r);
    closing.phase = Phase::Closing;
    cleanup
        .compare_exchange(&r.binding, Some(&r), &closing)
        .unwrap();
    let mut invented = r.binding.clone();
    invented.boot_id = [8; 16];
    assert!(cleanup.load(&invented).is_err());
}
#[test]
fn rows_missing_legacy_compatible_partial_inventory_and_reappearance_not_completion() {
    let d = Disk::default();
    let mut f = claimed(&d);
    close_legacy(&mut f);
    f.complete(&scope()).unwrap();
    for role in [Role::Carrier, Role::MemberA, Role::MemberB] {
        let d = Disk::default();
        let mut f = claimed(&d);
        publish(&mut f, &sequence(role));
        close_legacy(&mut f);
        f.complete(&scope()).unwrap();
        assert!(f.complete(&scope()).is_ok());
        inject(&d, &initial(role)); // terminal identity alone cannot hide a revived obligation
        assert!(f.complete(&scope()).is_err());
        assert!(f.scopes(RuntimeSlot::Stable).is_err());
        let mut other = scope();
        other.connection_generation += 1;
        assert!(f.claim(&other).is_err());
    }
}
#[test]
fn rows_no_pending_intent_can_be_replaced_or_unconfirmed_create_erased() {
    let seq = sequence(Role::Carrier);
    let old = &seq[3];
    let mut erased = bump(old);
    erased.pending = None;
    assert!(rows::validate_transition(Some(old), &erased, false).is_err());
    assert!(rows::validate_transition(Some(old), &erased, true).is_err());
    let mut closing = bump(old);
    closing.phase = Phase::Closing;
    rows::validate_transition(Some(old), &closing, true).unwrap();
    let mut erase = bump(&closing);
    erase.pending = None;
    assert!(rows::validate_transition(Some(&closing), &erase, true).is_err());
    let mut replacement = bump(&seq[1]);
    replacement.pending.as_mut().unwrap().target = seq[3].pending.as_ref().unwrap().target.clone();
    // replace an existing weak intent with another intent, no native confirmation
    assert!(rows::validate_transition(Some(&seq[1]), &replacement, false).is_err());
}

fn empty_pair(own: &SessionScope) -> PairRecord {
    PairRecord {
        scope: own.clone(),
        members: [None, None],
        active: None,
        guard: crate::member_guard::Model::empty(own.clone()).unwrap(),
        pending_guard: None,
        dns: [None, None],
        options: None,
        closing: false,
    }
}
fn terminal_payload(kind: RecordKind, own: &SessionScope) -> Vec<u8> {
    if let Some(role) = kind.row_role() {
        let mut r = initial(role);
        r.binding.scope = own.clone();
        r.revision = 3;
        r.phase = Phase::Stopped;
        return r.encode().unwrap();
    }
    match kind {
        RecordKind::Session => {
            let mut s = SessionState::new(own.clone(), Slot::A, 0, 0)
                .unwrap()
                .snapshot();
            s.phase = SessionPhase::Stopped;
            serde_json::to_vec(&Envelope {
                version: 1,
                scope: own.clone(),
                payload: s,
            })
            .unwrap()
        }
        RecordKind::Pair => serde_json::to_vec(&Envelope {
            version: 1,
            scope: own.clone(),
            payload: empty_pair(own),
        })
        .unwrap(),
        RecordKind::Network => serde_json::to_vec(&Envelope {
            version: 1,
            scope: own.clone(),
            payload: NetworkJournal::default(),
        })
        .unwrap(),
        RecordKind::Carrier => serde_json::to_vec(&Envelope {
            version: 1,
            scope: own.clone(),
            payload: carrier::Record {
                version: 1,
                intent: carrier::Intent {
                    scope: own.clone(),
                    addresses: vec!["10.7.0.2/32".parse().unwrap()],
                },
                provenance: carrier::Provenance {
                    boot_id: [7; 16],
                    runtime: runtime(),
                    network_epoch: 1,
                },
                generation: 3,
                phase: carrier::Phase::Stopped,
                proof: None,
                rows: None,
            },
        })
        .unwrap(),
        RecordKind::NativeCarrierReceipts => {
            let roles = [
                native_receipt::Role::RoleCarrier,
                native_receipt::Role::MemberA,
                native_receipt::Role::MemberB,
            ];
            let record=native_receipt::Record{version:2,context:native_receipt::Context{intent:carrier::Intent{scope:own.clone(),addresses:vec!["10.7.0.2/32".parse().unwrap()]},provenance:carrier::Provenance{boot_id:[7;16],runtime:runtime(),network_epoch:1},bindings:roles.map(|role|{
    let (n,name)=match role{native_receipt::Role::RoleCarrier=>(1,"c"),native_receipt::Role::MemberA=>(2,"a"),native_receipt::Role::MemberB=>(3,"b")};
    let byte=format!("{n:02x}");let guid=format!("{}-{}-{}-{}-{}",byte.repeat(4),byte.repeat(2),byte.repeat(2),byte.repeat(2),byte.repeat(6));
    native_receipt::Binding{role,guid:[n;16],name:name.into(),registry_path:format!(r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{{guid}}}")}
   })},generation:3,phase:native_receipt::Phase::Stopped,keys:roles.map(|role|native_receipt::KeyReceipt{role,phase:native_receipt::KeyPhase::Clean,new_key_ack:false,baseline:native_receipt::Value::Absent,current:native_receipt::Value::Absent,pending:None}),native_rows:native_receipt::FullNativeRows::Unbound};
            record.encode().unwrap()
        }
        RecordKind::CarrierGuard => {
            let native = native_receipt::Record::decode(&terminal_payload(
                RecordKind::NativeCarrierReceipts,
                own,
            ))
            .unwrap();
            CarrierGuardRecord {
                version: 2,
                context: native.context,
                revision: 1,
                current: carrier_guard::Model::empty(own.clone()).unwrap(),
                pending: None,
            }
            .encode()
            .unwrap()
        }
        RecordKind::NativeCreator => {
            let native = native_receipt::Record::decode(&terminal_payload(
                RecordKind::NativeCarrierReceipts,
                own,
            ))
            .unwrap();
            CreatorRecord::decode(
                &serde_json::to_vec(&serde_json::json!({
                    "version":1,"context":native.context,"process":{"pid":256,"creation_time":500}
                }))
                .unwrap(),
            )
            .unwrap()
            .encode()
            .unwrap()
        }
        _ => unreachable!(),
    }
}
#[test]
fn rows_all_ten_physical_namespaces_have_bounded_retired_owners_and_partial_rewrite() {
    let d = Disk::default();
    let mut identities = Vec::new();
    let mut names = std::collections::HashSet::new();
    for (i, kind) in RecordKind::OWNED.iter().copied().enumerate() {
        assert!(names.insert(kind.file().name()));
        let mut own = scope();
        own.connection_generation = i as u64 + 10;
        let identity = SessionIdentity {
            boot_id: [7; 16],
            runtime: runtime(),
            scope: own.clone(),
        };
        let saved = SavedRecord {
            version: PRIVATE_VERSION,
            identity: identity.clone(),
            kind,
            network_epoch: 1,
            data: String::from_utf8(terminal_payload(kind, &own)).unwrap(),
        };
        let raw = serde_json::to_vec(&saved).unwrap();
        parse_record(kind, &raw).unwrap();
        d.0.borrow_mut().bytes.insert(kind.file(), raw);
        d.0.borrow_mut().bytes.insert(
            completed_file(&own).unwrap(),
            serde_json::to_vec(&CompletedRecord {
                version: PRIVATE_VERSION,
                identity: identity.clone(),
            })
            .unwrap(),
        );
        identities.push(identity);
    }
    assert_eq!(names.len(), 10);
    d.0.borrow_mut().bytes.insert(
        PrivateFile::Index,
        serde_json::to_vec(&SessionIndex {
            version: PRIVATE_VERSION,
            active: None,
            completed: identities.clone(),
        })
        .unwrap(),
    );
    let mut f = files(&d);
    assert!(f.scopes(RuntimeSlot::Stable).unwrap().is_empty());
    f.claim(&scope()).unwrap();
    let mut records = sequence(Role::Carrier);
    publish(&mut f, &records);
    let own_member = initial(Role::MemberA);
    publish(&mut f, &[own_member]); // retain a nonterminal role until later cleanup
    assert!(f.complete_empty(&scope()).is_err());
    close_legacy(&mut f);
    assert!(f.complete(&scope()).is_err());
    let mut member = initial(Role::MemberA);
    let (mut cleanup, _) =
        WindowsCarrierRowsStore::open(f.clone(), member.binding.clone()).unwrap();
    let old = member.clone();
    member.revision += 1;
    member.phase = Phase::Closing;
    cleanup
        .compare_exchange(&member.binding, Some(&old), &member)
        .unwrap();
    let old = member.clone();
    member.revision += 1;
    member.phase = Phase::Stopped;
    cleanup
        .compare_exchange(&member.binding, Some(&old), &member)
        .unwrap();
    f.complete(&scope()).unwrap();
    for id in &identities {
        assert!(f.claim(&id.scope).is_err());
    }
    assert!(f.complete(&scope()).is_ok());
    // Explicit retired corruption cannot be hidden by a valid permanent marker.
    records.last_mut().unwrap().phase = Phase::Closing;
    inject(&d, records.last().unwrap());
    assert!(f.scopes(RuntimeSlot::Stable).is_err());
}

#[test]
fn carrier_access_exact_storage_context_rejects_each_provenance_mismatch() {
    let d = Disk::default();
    let mut f = claimed(&d);
    let raw = terminal_payload(RecordKind::NativeCarrierReceipts, &scope());
    let context = native_receipt::Record::decode(&raw).unwrap().context;
    let access = f.native_carrier_access(&scope()).unwrap();
    access.require_native_context(&context).unwrap();
    assert!(access.is_fresh());
    for change in 0..9 {
        let mut bad = context.clone();
        match change {
            0 => bad.intent.scope.connection_generation += 1,
            1 => bad.intent.scope.runtime_generation += 1,
            2 => bad.provenance.boot_id = [8; 16],
            3 => bad.provenance.runtime.runtime_version = "2".into(),
            4 => bad.provenance.runtime.container_version = "2".into(),
            5 => bad.provenance.runtime.runtime_contract_version += 1,
            6 => bad.provenance.runtime.manifest_sha256 = "b".repeat(64),
            7 => bad.provenance.network_epoch += 1,
            _ => bad.intent.scope.runtime = RuntimeSlot::Latest,
        };
        assert!(access.require_native_context(&bad).is_err());
    }
    let view = f.recovery_view(RuntimeSlot::Stable).unwrap().unwrap().0;
    let retained = view.clone().native_carrier_access(&scope()).unwrap();
    retained.require_native_context(&context).unwrap();
    assert!(!retained.is_fresh());
    // Storage comparison deliberately cannot attest native GUID/name/ownership.
    let mut not_native = context;
    not_native.bindings[0].name = "foreign".into();
    retained.require_native_context(&not_native).unwrap();
}
#[test]
fn rows_two_fresh_store_cas_race_revokes_winner_without_duplicate_effects() {
    let d = Disk::default();
    let f = claimed(&d);
    let r = initial(Role::Carrier);
    let (mut a, _) = WindowsCarrierRowsStore::open(f.clone(), r.binding.clone()).unwrap();
    let (mut b, _) = WindowsCarrierRowsStore::open(f.clone(), r.binding.clone()).unwrap();
    a.compare_exchange(&r.binding, None, &r).unwrap();
    assert!(b.compare_exchange(&r.binding, None, &r).is_err());
    assert!(a.load(&r.binding).is_err());
    assert_eq!(d.0.borrow().attempts, 1);
}
#[test]
fn rows_raw_schema_error_revokes_all_roles_before_any_private_write() {
    for role in [Role::Carrier, Role::MemberA, Role::MemberB] {
        let d = Disk::default();
        let mut f = claimed(&d);
        assert!(f
            .compare_exchange(&scope(), rows_kind(role), None, b"{}")
            .is_err());
        assert!(!f.native_carrier_access(&scope()).unwrap().is_fresh());
        assert_eq!(d.0.borrow().attempts, 0);
    }
}

#[test]
fn rows_actual_protected_reads_reject_unknown_nullable_schema_and_outer_fields() {
    for role in [Role::Carrier, Role::MemberA, Role::MemberB] {
        for corrupt in 0..11 {
            let d = Disk::default();
            let mut f = claimed(&d);
            let r = initial(role);
            inject(&d, &r);
            let raw = d.0.borrow().bytes[&rows_file(role)].clone();
            let mut outer: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            let mut inner: serde_json::Value =
                serde_json::from_str(outer["data"].as_str().unwrap()).unwrap();
            match corrupt {
                0 => {
                    inner["extra"] = true.into();
                }
                1 => {
                    inner["baseline"]["interface"]["observed"]["extra"] = true.into();
                }
                2 => {
                    inner["current"]["interface"]["policy"]["extra"] = true.into();
                }
                3 => {
                    inner["binding"]["key"]["extra"] = true.into();
                }
                4 => {
                    inner.as_object_mut().unwrap().remove("creation");
                }
                5 => {
                    inner["current"].as_object_mut().unwrap().remove("address");
                }
                6 => {
                    inner["version"] = 2.into();
                }
                7 => {
                    outer["extra"] = true.into();
                }
                8 => {
                    outer["identity"]["extra"] = true.into();
                }
                9 => {
                    outer["version"] = 3.into();
                }
                _ => {
                    inner["baseline"]["interface"]["observed"]["interface_identifier"] =
                        (-1_i64).into();
                }
            }
            outer["data"] = serde_json::to_string(&inner).unwrap().into();
            d.0.borrow_mut()
                .bytes
                .insert(rows_file(role), serde_json::to_vec(&outer).unwrap());
            assert!(WindowsCarrierRowsStore::open(f.clone(), r.binding).is_err());
            assert!(f.read(&scope(), rows_kind(role)).is_err());
            assert!(f.recovery_view(RuntimeSlot::Stable).is_err());
        }
    }
    let r = sequence(Role::Carrier)[4].clone();
    for path in [
        "/creation",
        "/creation/policy",
        "/creation/observed",
        "/creation/key",
        "/current/address",
        "/current/address/policy",
        "/current/address/observed",
    ] {
        let mut v = serde_json::to_value(&r).unwrap();
        v.pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), true.into());
        let d = Disk::default();
        let mut f = claimed(&d);
        inject(&d, &r);
        let raw = d.0.borrow().bytes[&rows_file(Role::Carrier)].clone();
        let mut outer: SavedRecord = serde_json::from_slice(&raw).unwrap();
        outer.data = serde_json::to_string(&v).unwrap();
        d.0.borrow_mut().bytes.insert(
            rows_file(Role::Carrier),
            serde_json::to_vec(&outer).unwrap(),
        );
        assert!(f.read(&scope(), RecordKind::CarrierRows).is_err(), "{path}");
    }
}
