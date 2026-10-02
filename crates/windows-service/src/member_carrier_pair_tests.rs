use super::*;
use crate::member_owner::{Intent, NativeProof, Phase as OwnerPhase, ProcessProof};
use nelomai_client_tunnel::{
    redundancy::{
        evidence::NativeHealthSample,
        network::{RouteScope, RouteValue},
        ProbeDatagram,
    },
    TunnelConfiguration, TunnelMetrics,
};
use nelomai_contracts::{
    dispatcher::{EngineIdentity, TunnelSlot},
    RedundantHealthProbe, RuntimeSlot,
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, rc::Rc};

fn scope() -> SessionScope {
    SessionScope {
        runtime: RuntimeSlot::Stable,
        runtime_generation: 2,
        session_id: "11111111-1111-4111-8111-111111111111".into(),
        connection_generation: 3,
    }
}
fn provenance() -> Provenance {
    Provenance {
        boot_id: [8; 16],
        network_epoch: 1,
        runtime: EngineIdentity {
            slot: RuntimeSlot::Stable,
            runtime_version: "0.3.3".into(),
            container_version: "0.3.3".into(),
            runtime_contract_version: 1,
            manifest_sha256: "a".repeat(64),
        },
    }
}
fn proof(n: u32) -> InterfaceProof {
    InterfaceProof {
        index: n,
        luid: u64::from(n) * 100,
        guid: [n as u8; 16],
    }
}
fn member(slot: Slot) -> Member {
    let key = if slot == Slot::A {
        "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
    } else {
        "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
    };
    Member { slot, lease_id: if slot == Slot::A {"22222222-2222-4222-8222-222222222222"}
        else {"33333333-3333-4333-8333-333333333333"}.into(),
        configuration:TunnelConfiguration::new(format!("[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.7.0.2/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = {key}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.{}:51820\nPersistentKeepalive = 25\n", if slot == Slot::A {11} else {22})),
        probe:RedundantHealthProbe {kind:nelomai_contracts::HealthProbeKind::DnsA,target_ipv4:"1.1.1.1".parse().unwrap(),query_name:"example.com".into(),timeout_ms:2000} }
}
struct State {
    scope: SessionScope,
    disk: Option<Record>,
    guard: guard::Model,
    network: NetworkSnapshot,
    carrier: Option<InterfaceProof>,
    members: [Option<OwnerRecord>; 2],
    weak: bool,
    events: Vec<String>,
    counts: BTreeMap<String, usize>,
    fail: Option<(String, bool)>,
    saves: usize,
    fail_save: Option<(usize, bool)>,
    foreign: bool,
    held: usize,
    released: usize,
    unpublished: usize,
    unacknowledged_create: bool,
    execution_epoch: u64,
    rebind_sealed: bool,
    cleanup_begun: bool,
    require_cleanup_entry: bool,
    probe_replies: bool,
    health_dead: [bool; 2],
    tx: [u64; 2],
    rx: [u64; 2],
}
type Shared = Rc<RefCell<State>>;
struct Disk(Shared);
pub(crate) struct Io(Shared, Option<Box<StartupTransferOwner>>);
// A real MemberOwner constructor is used by the fake native adapter. These
// external boundaries deny access: preparation must not touch journals/native IO.
struct ConstructionOnly;
impl crate::member_owner::Journal for ConstructionOnly {
    fn load(&mut self, _: TunnelSlot) -> crate::member_owner::Result<Option<OwnerRecord>> {
        Err(crate::member_owner::OwnerError::Journal)
    }
    fn compare_exchange(
        &mut self,
        _: TunnelSlot,
        _: Option<&OwnerRecord>,
        _: &OwnerRecord,
    ) -> crate::member_owner::Result<()> {
        Err(crate::member_owner::OwnerError::Journal)
    }
}
impl crate::member_owner::MemberIo for ConstructionOnly {
    fn inspect(
        &mut self,
        _: &Intent,
        _: Option<&NativeProof>,
    ) -> crate::member_owner::Result<crate::member_owner::Observation> {
        Err(crate::member_owner::OwnerError::Native)
    }
    fn inspect_original(
        &mut self,
        _: &Intent,
        _: &NativeProof,
    ) -> crate::member_owner::Result<crate::member_owner::Observation> {
        Err(crate::member_owner::OwnerError::Native)
    }
    fn inspect_original_for_cleanup(
        &mut self,
        _: &Intent,
        _: &NativeProof,
    ) -> crate::member_owner::Result<crate::member_owner::Observation> {
        Err(crate::member_owner::OwnerError::Native)
    }
    fn revoke_original(&mut self) {
        panic!("read-only constructor attempted native revocation")
    }
    fn write_private_config(
        &mut self,
        _: &Intent,
        _: Option<[u8; 32]>,
        _: &str,
    ) -> crate::member_owner::Result<()> {
        Err(crate::member_owner::OwnerError::Native)
    }
    fn start_fresh(
        &mut self,
        _: &Intent,
        _: Option<&NativeProof>,
    ) -> crate::member_owner::Result<()> {
        Err(crate::member_owner::OwnerError::Native)
    }
    fn stop_slot(
        &mut self,
        _: &Intent,
        _: Option<&NativeProof>,
        _: &crate::member_owner::Observation,
    ) -> crate::member_owner::Result<()> {
        Err(crate::member_owner::OwnerError::Native)
    }
    fn rebind(
        &mut self,
        _: &Intent,
        _: &NativeProof,
        _: &crate::member_owner::Observation,
    ) -> crate::member_owner::Result<()> {
        Err(crate::member_owner::OwnerError::Native)
    }
}
pub(crate) struct Socket {
    state: Shared,
    slot: Slot,
    query: Vec<u8>,
    replied: bool,
}
impl Drop for Socket {
    fn drop(&mut self) {
        let mut s = self.state.borrow_mut();
        s.held -= 1;
        s.released += 1;
    }
}
impl ProbeDatagram for Socket {
    fn send(&mut self, packet: &[u8]) -> io::Result<usize> {
        self.query = packet.to_vec();
        self.state.borrow_mut().tx[idx(self.slot)] += 1;
        Ok(packet.len())
    }
    fn receive(&mut self, packet: &mut [u8]) -> io::Result<usize> {
        let mut state = self.state.borrow_mut();
        if !state.probe_replies || state.health_dead[idx(self.slot)] || self.replied {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        // External UDP boundary only: real DNS parser, scheduler, evidence,
        // SessionControl and carrier coordinator consume this scoped reply.
        let mut reply = self.query.clone();
        if reply.len() < 12 {
            return Err(failed());
        }
        reply[2] = 0x81;
        reply[3] = 0x80;
        reply[7] = 1;
        reply.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4]);
        if packet.len() < reply.len() {
            return Err(failed());
        }
        packet[..reply.len()].copy_from_slice(&reply);
        self.replied = true;
        state.rx[idx(self.slot)] += 1;
        Ok(reply.len())
    }
}
impl PairSocket for Socket {
    fn duplicate(&self) -> io::Result<Self> {
        self.state.borrow_mut().held += 1;
        Ok(Self {
            state: self.state.clone(),
            slot: self.slot,
            query: vec![],
            replied: false,
        })
    }
}
impl PairJournal for Disk {
    fn begin_cleanup(&mut self, scope: &SessionScope) -> io::Result<()> {
        if *scope != self.0.borrow().scope {
            return Err(failed());
        }
        self.0.borrow_mut().cleanup_begun = true;
        Io(self.0.clone(), None).effect("cleanup-storage", |_| {})
    }
    fn load(&mut self, _: &SessionScope) -> io::Result<Option<Record>> {
        let state = self.0.borrow();
        if state.require_cleanup_entry && !state.cleanup_begun {
            return Err(failed());
        }
        drop(state);
        Ok(self.0.borrow().disk.clone())
    }
    fn compare_exchange(&mut self, old: Option<&Record>, new: &Record) -> io::Result<()> {
        let mut s = self.0.borrow_mut();
        if s.disk.as_ref() != old {
            return Err(failed());
        }
        s.saves += 1;
        s.events
            .push(format!("save:{:?}:{:?}", new.phase, new.pending));
        let fault = s.fail_save.filter(|(n, _)| *n == s.saves);
        if fault.is_none_or(|(_, lost)| lost) {
            s.disk = Some(new.clone());
        }
        if fault.is_some() {
            s.fail_save = None;
            return Err(failed());
        }
        Ok(())
    }
}
impl Io {
    fn effect(&mut self, name: &str, apply: impl FnOnce(&mut State)) -> io::Result<()> {
        let mut s = self.0.borrow_mut();
        s.events.push(name.into());
        *s.counts.entry(name.into()).or_default() += 1;
        let fault = s.fail.as_ref().filter(|(n, _)| n == name).cloned();
        if fault.as_ref().is_none_or(|(_, lost)| *lost) {
            apply(&mut s)
        }
        if fault.is_some() {
            s.fail = None;
            return Err(failed());
        }
        Ok(())
    }
}
impl CarrierPairIo for Io {
    type Socket = Socket;
    fn select_running_execution(&mut self, record: &Record) -> io::Result<u64> {
        assert_eq!(record.phase, Phase::Running);
        if self
            .0
            .borrow()
            .fail
            .as_ref()
            .is_some_and(|(name, _)| name == "complete-start-unwind")
        {
            panic!("original Running handoff interrupted");
        }
        self.effect("complete-start", |_| {})?;
        Ok(self.0.borrow().execution_epoch)
    }
    fn preflight_fresh(&mut self, r: &Record) -> io::Result<()> {
        self.effect("fresh", |_| {})?;
        let s = self.0.borrow();
        if s.carrier.is_some()
            || s.members.iter().any(Option::is_some)
            || s.guard.expected != r.guard.expected
            || s.foreign
        {
            Err(failed())
        } else {
            Ok(())
        }
    }
    fn attest_effect(&mut self, _: &Record, _: Effect) -> io::Result<()> {
        if self.0.borrow().foreign {
            Err(failed())
        } else {
            Ok(())
        }
    }
    fn create_carrier_ready(&mut self, _: &Record) -> io::Result<InterfaceProof> {
        let result = self.effect("carrier-ready", |s| s.carrier = Some(proof(33)));
        if result.is_err() && self.0.borrow().carrier.is_some() {
            self.0.borrow_mut().unacknowledged_create = true;
        }
        result?;
        Ok(proof(33))
    }
    fn verify_carrier_ready(&mut self, r: &Record) -> io::Result<()> {
        self.effect("ready", |_| {})?;
        if r.carrier != self.0.borrow().carrier || r.carrier.is_none() {
            Err(failed())
        } else {
            Ok(())
        }
    }
    fn prepare_member(&mut self, r: &Record, m: &Member, native: &str) -> io::Result<OwnerRecord> {
        self.effect("prepare-member", |_| {})?;
        assert!(!native.contains("Address"));
        assert!(!native.contains("DNS"));
        assert!(native.contains("Table = off"));
        let slot = if m.slot == Slot::A {
            TunnelSlot::A
        } else {
            TunnelSlot::B
        };
        let owner = crate::member_owner::MemberOwner::from_trusted_carrier_engine(
            &crate::member_carrier::Intent {
                scope: r.scope.clone(),
                addresses: r.addresses.clone(),
            },
            slot,
            nelomai_client_tunnel::detect_configuration_transport(native),
            crate::test_engine_path("engine.exe"),
            m.configuration.expose(),
            ConstructionOnly,
            ConstructionOnly,
        )
        .map_err(|_| failed())?;
        Ok(OwnerRecord {
            intent: owner.intent().clone(),
            phase: OwnerPhase::Prepared,
            proof: None,
            retired_proof: None,
            previous_config_sha256: None,
        })
    }
    fn start_member(&mut self, r: &Record, slot: Slot, native: &str) -> io::Result<OwnerRecord> {
        let mut owner = r.members[idx(slot)].as_ref().unwrap().owner.clone();
        assert_eq!(
            owner.intent.config_sha256,
            <[u8; 32]>::from(Sha256::digest(native.as_bytes()))
        );
        owner.phase = OwnerPhase::Running;
        owner.proof = Some(NativeProof {
            interface: proof(if slot == Slot::A { 11 } else { 22 }),
            process: ProcessProof {
                pid: idx(slot) as u32 + 50,
                creation_time: 100,
            },
        });
        self.effect(&format!("start-{slot:?}"), |s| {
            assert!(s.carrier.is_some());
            s.members[idx(slot)] = Some(owner.clone())
        })?;
        Ok(owner)
    }
    fn verify_member(&mut self, r: &Record, slot: Slot) -> io::Result<()> {
        if self.0.borrow().members[idx(slot)].as_ref()
            != r.members[idx(slot)].as_ref().map(|m| &m.owner)
        {
            Err(failed())
        } else {
            Ok(())
        }
    }
    fn stop_member(&mut self, _: &Record, slot: Slot) -> io::Result<()> {
        self.effect(&format!("stop-{slot:?}"), |s| s.members[idx(slot)] = None)
    }
    fn verify_member_absent(&mut self, _: &Record, slot: Slot) -> io::Result<()> {
        if self.0.borrow().members[idx(slot)].is_some() {
            Err(failed())
        } else {
            Ok(())
        }
    }
    fn guard_snapshot(&mut self, _: &SessionScope) -> io::Result<guard::Snapshot> {
        self.effect("snapshot", |_| {})?;
        Ok(self.0.borrow().guard.expected.clone())
    }
    fn guard_exchange(
        &mut self,
        _: &Record,
        kind: guard::SessionKind,
        before: &guard::Model,
        after: &guard::Model,
    ) -> io::Result<guard::Model> {
        guard::validate_session_exchange(&self.0.borrow().scope, before, after, kind)
            .map_err(|_| failed())?;
        assert_eq!(self.0.borrow().guard, *before);
        let mut actual = after.expected.clone();
        if !before.installed && after.installed {
            actual.sublayer.as_mut().unwrap().weight = 65531;
        }
        let committed = after
            .readback_after(before, &actual)
            .map_err(|_| failed())?;
        let name = match kind {
            guard::SessionKind::StaticBase => "bases",
            guard::SessionKind::DynamicPermits => {
                if after.permits {
                    "allows"
                } else {
                    "withdraw"
                }
            }
        };
        self.effect(name, |s| s.guard = committed.clone())?;
        Ok(committed)
    }
    fn close_dynamic_permits(&mut self, _: &Record) -> io::Result<()> {
        self.effect("close-allows", |s| {
            s.guard = s.guard.without_permits().unwrap()
        })
    }
    fn apply_weak_rows(&mut self, _: &Record) -> io::Result<()> {
        self.effect("weak", |s| {
            assert!(s.guard.installed && !s.guard.permits);
            s.weak = true
        })
    }
    fn restore_weak_rows(&mut self, _: &Record) -> io::Result<()> {
        self.effect("restore-weak", |s| {
            assert!(s.guard.installed || !s.weak);
            assert!(!s.guard.permits);
            s.weak = false
        })
    }
    fn restore_member_weak_rows(&mut self, _: &Record, _: Slot) -> io::Result<()> {
        self.effect("restore-member-weak", |s| {
            assert!(!s.guard.permits && s.guard.installed)
        })
    }
    fn read_network(&mut self, _: &Record) -> io::Result<NetworkSnapshot> {
        self.effect("network-read", |_| {})?;
        Ok(self.0.borrow().network.clone())
    }
    fn plan_network(&mut self, r: &Record, slot: Slot) -> io::Result<NetworkSnapshot> {
        let c = r.carrier.unwrap();
        let e = r.members[idx(slot)]
            .as_ref()
            .unwrap()
            .owner
            .proof
            .unwrap()
            .interface;
        Ok(NetworkSnapshot {
            routes: vec![RouteValue {
                destination: "0.0.0.0/0".parse().unwrap(),
                scope: RouteScope::WindowsInterface(e.index),
                interface: e.index,
                gateway: None,
                metric: 1,
            }],
            dns: Some(crate::member_dns::Snapshot {
                interface: crate::member_dns::OwnedInterface {
                    scope: r.scope.clone(),
                    guid: c.guid,
                    luid: c.luid,
                    index: c.index,
                },
                settings: crate::member_dns::Settings {
                    version: 1,
                    flags: 0,
                    domain: None,
                    name_server: Some("1.1.1.1".into()),
                    search_list: None,
                    registration_enabled: 0,
                    register_adapter_name: 0,
                    enable_llmnr: 0,
                    query_adapter_name: 0,
                    profile_name_server: None,
                },
            }),
        })
    }
    fn exchange_network(
        &mut self,
        _: &Record,
        old: &NetworkSnapshot,
        new: &NetworkSnapshot,
    ) -> io::Result<()> {
        self.effect(
            if new.routes.is_empty() {
                "restore-network"
            } else {
                "network"
            },
            |s| {
                assert_eq!(&s.network, old);
                assert!(!s.guard.permits);
                s.network = new.clone()
            },
        )
    }
    fn plan_retirement_network(&mut self, r: &Record, slot: Slot) -> io::Result<NetworkSnapshot> {
        self.plan_network(r, slot.other())
    }
    fn verify_network_plan(
        &mut self,
        r: &Record,
        active: Slot,
        desired: &NetworkSnapshot,
    ) -> io::Result<()> {
        self.effect("plan-proof", |_| {})?;
        if self.plan_network(r, active)? != *desired {
            return Err(failed());
        }
        Ok(())
    }
    fn verify_network_and_endpoints(&mut self, _: &Record, _: Slot) -> io::Result<()> {
        self.effect("endpoints", |_| {})
    }
    fn hold_probe(&mut self, r: &Record, slot: Slot) -> io::Result<(Socket, guard::ProbeTuple)> {
        let result = self.effect(&format!("hold-{slot:?}"), |s| {
            assert!(s.guard.installed && !s.guard.permits);
            s.held += 1;
            s.unpublished += 1
        });
        result?;
        self.0.borrow_mut().unpublished -= 1;
        Ok((
            Socket {
                state: self.0.clone(),
                slot,
                query: vec![],
                replied: false,
            },
            guard::ProbeTuple {
                source: r.addresses[0].addr(),
                source_port: 40100 + idx(slot) as u16,
                target: r.members[idx(slot)]
                    .as_ref()
                    .unwrap()
                    .probe
                    .target_ipv4
                    .into(),
                target_port: 53,
                protocol: 17,
            },
        ))
    }
    fn verify_held_probe(
        &mut self,
        _: &Record,
        _: Slot,
        _: &Socket,
        _: &guard::ProbeTuple,
    ) -> io::Result<()> {
        self.effect("held-proof", |s| assert!(s.held > 0))
    }
    fn release_probe(&mut self, _: &Record, slot: Slot, socket: Socket) -> io::Result<()> {
        self.effect(&format!("release-{slot:?}"), |s| assert!(!s.guard.permits))?;
        drop(socket);
        Ok(())
    }
    fn release_unpublished_probes(&mut self, _: &Record) -> io::Result<()> {
        let mut s = self.0.borrow_mut();
        assert!(!s.guard.permits);
        s.held -= s.unpublished;
        s.released += s.unpublished;
        s.unpublished = 0;
        Ok(())
    }
    fn verify_target_health(&mut self, _: &Record, _: Slot) -> io::Result<()> {
        self.effect("target-health", |_| {})
    }
    fn verify_data(&mut self, _: &Record, _: Slot) -> io::Result<()> {
        self.effect("data", |s| assert!(s.guard.permits))
    }
    fn delete_carrier_addresses(&mut self, _: &Record) -> io::Result<()> {
        self.effect("address-delete", |_| {})
    }
    fn end_carrier_session(&mut self, _: &Record) -> io::Result<()> {
        self.effect("session-end", |_| {})
    }
    fn close_carrier_handle(&mut self, _: &Record) -> io::Result<()> {
        if self.0.borrow().unacknowledged_create {
            return Err(failed());
        }
        self.effect("carrier-close", |s| s.carrier = None)
    }
    fn verify_native_empty(&mut self, _: &Record) -> io::Result<()> {
        self.effect("native-empty", |_| {})?;
        let s = self.0.borrow();
        if s.carrier.is_some()
            || s.members.iter().any(Option::is_some)
            || !s.network.routes.is_empty()
            || s.held != 0
            || s.weak
        {
            Err(failed())
        } else {
            Ok(())
        }
    }
    fn restore_owned_keys(&mut self, _: &Record) -> io::Result<()> {
        self.effect("restore-keys", |_| {})
    }
    fn restore_member_keys(&mut self, _: &Record, _: Slot) -> io::Result<()> {
        self.effect("restore-member-keys", |_| {})
    }
    fn verify_full_empty(&mut self, r: &Record) -> io::Result<()> {
        self.effect("full-empty", |_| {})?;
        if self.0.borrow().guard != guard::Model::empty(r.scope.clone()).unwrap() {
            Err(failed())
        } else {
            Ok(())
        }
    }
    fn observe(
        &mut self,
        _: &Record,
        slot: Slot,
    ) -> io::Result<(TunnelMetrics, NativeHealthSample)> {
        self.effect("observe", |_| {})?;
        let state = self.0.borrow();
        let dead = state.health_dead[idx(slot)];
        Ok((
            TunnelMetrics::default(),
            NativeHealthSample {
                admitted: !dead,
                closed: dead,
                handshake_fresh: !dead,
                tx_packets: 3 + state.tx[idx(slot)],
                rx_data_packets: 3 + state.rx[idx(slot)],
            },
        ))
    }
    fn fingerprint(&mut self, _: &Record) -> io::Result<String> {
        self.effect("fingerprint", |_| {})?;
        Ok("a".repeat(64))
    }
    fn begin_rebind_execution(&mut self, _: &Record) -> io::Result<u64> {
        self.effect("execution-begin", |s| s.execution_epoch += 1)?;
        Ok(self.0.borrow().execution_epoch)
    }
    fn seal_rebind_execution(&mut self, _: &Record) -> io::Result<()> {
        self.effect("execution-seal", |s| s.rebind_sealed = true)
    }
    fn complete_rebind_execution(&mut self, _: &Record) -> io::Result<u64> {
        if !self.0.borrow().rebind_sealed {
            return Err(failed());
        }
        self.effect("execution-complete", |s| s.rebind_sealed = false)?;
        Ok(self.0.borrow().execution_epoch)
    }
    fn rebind_member(&mut self, r: &Record, slot: Slot) -> io::Result<OwnerRecord> {
        let mut owner = r.members[idx(slot)].as_ref().unwrap().owner.clone();
        owner.retired_proof = owner.proof;
        owner.proof.as_mut().unwrap().process.creation_time += 1;
        self.effect("rebind", |s| s.members[idx(slot)] = Some(owner.clone()))?;
        Ok(owner)
    }
}
fn fresh_state() -> Shared {
    fresh_state_for(scope())
}
fn fresh_state_for(scope: SessionScope) -> Shared {
    Rc::new(RefCell::new(State {
        scope: scope.clone(),
        disk: None,
        guard: guard::Model::empty(scope).unwrap(),
        network: NetworkSnapshot {
            routes: vec![],
            dns: None,
        },
        carrier: None,
        members: [None, None],
        weak: false,
        events: vec![],
        counts: BTreeMap::new(),
        fail: None,
        saves: 0,
        fail_save: None,
        foreign: false,
        held: 0,
        released: 0,
        unpublished: 0,
        unacknowledged_create: false,
        execution_epoch: 1,
        rebind_sealed: false,
        cleanup_begun: false,
        require_cleanup_entry: false,
        probe_replies: false,
        health_dead: [false; 2],
        tx: [0; 2],
        rx: [0; 2],
    }))
}
fn pair() -> (CarrierNativePair<Io, Disk>, Shared) {
    let s = fresh_state();
    (
        CarrierNativePair::new(scope(), provenance(), Io(s.clone(), None), Disk(s.clone()))
            .unwrap(),
        s,
    )
}

#[test]
fn retained_construction_keeps_both_originals_after_lost_fresh_ack() {
    let shared = fresh_state();
    shared.borrow_mut().fail_save = Some((1, true));
    let mut native = Some(Io(shared.clone(), None));
    let mut journal = Some(Disk(shared.clone()));
    let mut retained = None;
    assert!(CarrierNativePair::new_retained_into(
        &mut retained,
        scope(),
        provenance(),
        &mut native,
        &mut journal,
    )
    .is_err());
    let pair = retained
        .as_mut()
        .expect("full original owner retained on failed Fresh ACK");
    assert!(native.is_none());
    assert!(journal.is_none());
    assert!(Rc::ptr_eq(&pair.io.borrow_mut().0, &shared));
    assert!(Rc::ptr_eq(&pair.journal.borrow_mut().0, &shared));
    assert_eq!(shared.borrow().disk.as_ref().unwrap().phase, Phase::Fresh);
    assert!(pair
        .start(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .is_err());
    assert!(pair.cleanup_pending());
    assert!(
        pair.stop(&scope()).is_err(),
        "equal Fresh DATA cannot repair a missing publication ACK"
    );
    assert!(pair.cleanup_pending());
    assert!(shared.borrow().carrier.is_none());
}

#[test]
fn retained_construction_acknowledged_path_uses_same_ordinary_start() {
    let shared = fresh_state();
    let mut native = Some(Io(shared.clone(), None));
    let mut journal = Some(Disk(shared.clone()));
    let mut retained = None;
    CarrierNativePair::new_retained_into(
        &mut retained,
        scope(),
        provenance(),
        &mut native,
        &mut journal,
    )
    .unwrap();
    let pair = retained.as_mut().unwrap();
    pair.start(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    assert_eq!(pair.snapshot().phase, Phase::Running);
    assert_eq!(shared.borrow().counts.get("carrier-ready"), Some(&1));
    pair.stop(&scope()).unwrap();
    assert!(!pair.cleanup_pending());
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ConstructionFault {
    None,
    LoadError(usize),
    LoadUnwind(usize),
    WriteError(bool),
    WriteUnwind(bool),
    ReadbackAbsent,
    ReadbackForeign,
}
struct ConstructionTrace {
    loads: usize,
    writes: usize,
    drops: usize,
    fault: ConstructionFault,
    on_load: Option<Box<dyn FnMut() -> io::Result<()>>>,
}
pub(crate) struct ConstructionDisk {
    original: Disk,
    trace: Rc<RefCell<ConstructionTrace>>,
}
impl Drop for ConstructionDisk {
    fn drop(&mut self) {
        self.trace.borrow_mut().drops += 1;
    }
}
impl PairJournal for ConstructionDisk {
    fn begin_cleanup(&mut self, scope: &SessionScope) -> io::Result<()> {
        self.original.begin_cleanup(scope)
    }
    fn load(&mut self, scope: &SessionScope) -> io::Result<Option<Record>> {
        let (number, fault, callback) = {
            let mut trace = self.trace.borrow_mut();
            trace.loads += 1;
            (trace.loads, trace.fault, trace.on_load.take())
        };
        if let Some(mut callback) = callback {
            callback()?;
        }
        match fault {
            ConstructionFault::LoadError(n) if n == number => {
                self.trace.borrow_mut().fault = ConstructionFault::None;
                return Err(failed());
            }
            ConstructionFault::LoadUnwind(n) if n == number => {
                self.trace.borrow_mut().fault = ConstructionFault::None;
                panic!("original protected load interrupted");
            }
            ConstructionFault::ReadbackAbsent if number == 2 => {
                self.original.0.borrow_mut().disk = None;
            }
            ConstructionFault::ReadbackForeign if number == 2 => {
                let mut state = self.original.0.borrow_mut();
                state.disk.as_mut().unwrap().scope.connection_generation += 1;
            }
            _ => {}
        }
        self.original.load(scope)
    }
    fn compare_exchange(&mut self, old: Option<&Record>, new: &Record) -> io::Result<()> {
        let fault = {
            let mut trace = self.trace.borrow_mut();
            trace.writes += 1;
            std::mem::replace(&mut trace.fault, ConstructionFault::None)
        };
        match fault {
            ConstructionFault::WriteError(applied) => {
                if applied {
                    self.original.compare_exchange(old, new)?;
                }
                Err(failed())
            }
            ConstructionFault::WriteUnwind(applied) => {
                if applied {
                    self.original.compare_exchange(old, new)?;
                }
                panic!("original Fresh CAS interrupted");
            }
            other => {
                // Preserve faults meant for the second actual read, not CAS.
                self.trace.borrow_mut().fault = other;
                self.original.compare_exchange(old, new)
            }
        }
    }
}
pub(crate) type ConstructionPair = CarrierNativePair<Io, ConstructionDisk>;
// Shared TEST-ONLY external IO fixture. Cold retains the exact owning Startup
// in the existing native boundary; actual Pair construction/lifecycle is not
// stubbed and no native ACK constructor is exposed to Startup tests.
pub(crate) struct StartupTransferOwner {
    pub(crate) scope: SessionScope,
    pub(crate) provenance: Provenance,
    shared: Shared,
    trace: Rc<RefCell<ConstructionTrace>>,
    origin: Rc<()>,
    drops: Rc<Cell<usize>>,
}
impl Drop for StartupTransferOwner {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}
impl StartupTransferOwner {
    pub(crate) fn identity(&self) -> (SessionScope, Provenance) {
        (self.scope.clone(), self.provenance.clone())
    }
    pub(crate) fn cold(self) -> (Io, ConstructionDisk) {
        let shared = self.shared.clone();
        let journal = ConstructionDisk {
            original: Disk(shared.clone()),
            trace: self.trace.clone(),
        };
        (Io(shared, Some(Box::new(self))), journal)
    }
}
pub(crate) struct StartupTransferFixture {
    pub(crate) startup: Option<StartupTransferOwner>,
    pub(crate) io: Option<Io>,
    pub(crate) journal: Option<ConstructionDisk>,
    pub(crate) pair: Option<ConstructionPair>,
    shared: Shared,
    trace: Rc<RefCell<ConstructionTrace>>,
    origin: Rc<()>,
    drops: Rc<Cell<usize>>,
}
impl StartupTransferFixture {
    pub(crate) fn new(fault: ConstructionFault) -> Self {
        let shared = fresh_state();
        let trace = Rc::new(RefCell::new(ConstructionTrace {
            loads: 0,
            writes: 0,
            drops: 0,
            fault,
            on_load: None,
        }));
        let origin = Rc::new(());
        let drops = Rc::new(Cell::new(0));
        Self {
            startup: Some(StartupTransferOwner {
                scope: scope(),
                provenance: provenance(),
                shared: shared.clone(),
                trace: trace.clone(),
                origin: origin.clone(),
                drops: drops.clone(),
            }),
            io: None,
            journal: None,
            pair: None,
            shared,
            trace,
            origin,
            drops,
        }
    }
    pub(crate) fn assert_rooted(&mut self) {
        assert!(self.startup.is_none());
        let io = if let Some(pair) = self.pair.as_ref() {
            assert!(self.io.is_none() && self.journal.is_none());
            pair.io.borrow_mut()
        } else {
            panic!("complete original pair must precede external journal failure")
        };
        let original = io.1.as_ref().expect("same cold Startup owner retained");
        assert!(Rc::ptr_eq(&original.origin, &self.origin));
        assert!(Rc::ptr_eq(&io.0, &original.shared));
        let journal = self.pair.as_ref().unwrap().journal.borrow_mut();
        assert!(Rc::ptr_eq(&journal.trace, &self.trace));
        assert!(Rc::ptr_eq(&journal.original.0, &self.shared));
        assert_eq!(self.drops.get(), 0);
        assert_eq!(self.trace.borrow().drops, 0);
    }
    pub(crate) fn assert_untouched(&self) {
        assert!(Rc::ptr_eq(
            &self.startup.as_ref().unwrap().origin,
            &self.origin
        ));
        assert_eq!(self.drops.get(), 0);
        assert_eq!(self.trace.borrow().loads, 0);
        assert_eq!(self.trace.borrow().writes, 0);
    }
    pub(crate) fn assert_converted_rooted(&self) {
        assert!(self.startup.is_none() && self.pair.is_none());
        let io = self.io.as_ref().unwrap();
        let owner = io.1.as_ref().unwrap();
        assert!(Rc::ptr_eq(&owner.origin, &self.origin));
        assert!(Rc::ptr_eq(
            &self.journal.as_ref().unwrap().trace,
            &self.trace
        ));
        assert_eq!(self.drops.get(), 0);
        assert_eq!(self.trace.borrow().drops, 0);
        assert_eq!(self.trace.borrow().loads, 0);
        assert_eq!(self.trace.borrow().writes, 0);
    }
    pub(crate) fn seed_initial_fresh(&mut self, foreign: bool) {
        let mut data = pair().0.snapshot().clone();
        if foreign {
            data.scope.connection_generation += 1;
        }
        self.shared.borrow_mut().disk = Some(data);
    }
    pub(crate) fn make_native_foreign(&mut self, foreign: bool) {
        self.shared.borrow_mut().foreign = foreign;
    }
    pub(crate) fn fail_cleanup_entry(&mut self, lost: bool) {
        self.shared.borrow_mut().fail = Some(("cleanup-storage".into(), lost));
    }
    pub(crate) fn assert_denied(&mut self) {
        let mut check = RetainedConstruction {
            shared: self.shared.clone(),
            trace: self.trace.clone(),
            pair: self.pair.take(),
            native: None,
            journal: None,
        };
        check.assert_forward_denied();
        self.pair = check.pair.take();
    }
    pub(crate) fn start(&mut self) {
        let pair = self.pair.as_mut().unwrap();
        pair.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
            .unwrap();
        assert_eq!(pair.snapshot().phase, Phase::Running);
        assert_eq!(self.shared.borrow().counts.get("carrier-ready"), Some(&1));
    }
    pub(crate) fn start_stop(&mut self) {
        self.start();
        self.close().unwrap();
        assert!(!self.pair.as_ref().unwrap().cleanup_pending());
    }
    pub(crate) fn close(&mut self) -> io::Result<()> {
        self.pair.as_mut().unwrap().stop(&scope())
    }
}
struct RetainedConstruction {
    shared: Shared,
    trace: Rc<RefCell<ConstructionTrace>>,
    pair: Option<ConstructionPair>,
    native: Option<Io>,
    journal: Option<ConstructionDisk>,
}
impl RetainedConstruction {
    fn new(fault: ConstructionFault) -> Self {
        let shared = fresh_state();
        let trace = Rc::new(RefCell::new(ConstructionTrace {
            loads: 0,
            writes: 0,
            drops: 0,
            fault,
            on_load: None,
        }));
        Self {
            pair: None,
            native: Some(Io(shared.clone(), None)),
            journal: Some(ConstructionDisk {
                original: Disk(shared.clone()),
                trace: trace.clone(),
            }),
            shared,
            trace,
        }
    }
    fn construct(&mut self) -> io::Result<()> {
        ConstructionPair::new_retained_into(
            &mut self.pair,
            scope(),
            provenance(),
            &mut self.native,
            &mut self.journal,
        )
    }
    fn assert_rooted(&mut self) {
        assert!(self.native.is_none());
        assert!(self.journal.is_none());
        let pair = self.pair.as_mut().unwrap();
        assert!(Rc::ptr_eq(&pair.io.borrow_mut().0, &self.shared));
        let journal = pair.journal.borrow_mut();
        assert!(Rc::ptr_eq(&journal.original.0, &self.shared));
        assert!(Rc::ptr_eq(&journal.trace, &self.trace));
        assert_eq!(self.trace.borrow().drops, 0);
    }
    fn assert_forward_denied(&mut self) {
        let events = self.shared.borrow().events.len();
        let loads = self.trace.borrow().loads;
        let pair = self.pair.as_mut().unwrap();
        assert!(pair
            .start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
            .is_err());
        assert!(pair.attach(&scope(), &member(Slot::B)).is_err());
        assert!(pair.remove_standby(&scope(), Slot::B).is_err());
        assert!(pair.select_active(&scope(), Slot::B).is_err());
        assert!(pair.rebind_pair(&scope()).is_err());
        assert!(pair.complete_start(&scope()).is_err());
        assert!(pair.complete_rebind(&scope()).is_err());
        assert!(pair.check_integrity().is_err());
        assert!(pair.sample(Slot::A).is_none());
        assert!(pair.sample(Slot::B).is_none());
        assert!(pair.open_probe(Slot::A).is_err());
        assert!(pair.open_probe(Slot::B).is_err());
        assert!(pair.metrics(Slot::A).is_err());
        assert!(pair.physical_network_fingerprint().is_err());
        assert_eq!(self.shared.borrow().events.len(), events);
        assert_eq!(self.trace.borrow().loads, loads);
    }
}

#[test]
fn retained_construction_faults_and_unwinds_root_before_first_io_and_never_forward() {
    for fault in [
        ConstructionFault::LoadError(1),
        ConstructionFault::LoadUnwind(1),
        ConstructionFault::WriteError(false),
        ConstructionFault::WriteError(true),
        ConstructionFault::WriteUnwind(false),
        ConstructionFault::WriteUnwind(true),
        ConstructionFault::LoadError(2),
        ConstructionFault::LoadUnwind(2),
        ConstructionFault::ReadbackAbsent,
        ConstructionFault::ReadbackForeign,
    ] {
        let mut fixture = RetainedConstruction::new(fault);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fixture.construct()));
        assert!(!matches!(result, Ok(Ok(()))), "{fault:?}");
        fixture.assert_rooted();
        fixture.assert_forward_denied();
        assert!(fixture.pair.as_ref().unwrap().cleanup_pending());
        assert!(fixture.shared.borrow().counts.is_empty());
        if matches!(
            fault,
            ConstructionFault::LoadError(2) | ConstructionFault::LoadUnwind(2)
        ) {
            // A real CAS ACK retained before readback allows only exact Stop.
            fixture.pair.as_mut().unwrap().stop(&scope()).unwrap();
            assert!(!fixture.pair.as_ref().unwrap().cleanup_pending());
            fixture.assert_forward_denied();
        } else {
            assert!(fixture.pair.as_mut().unwrap().stop(&scope()).is_err());
            assert!(fixture.pair.as_ref().unwrap().cleanup_pending());
            assert_ne!(
                fixture.pair.as_ref().unwrap().snapshot().phase,
                Phase::Stopped
            );
        }
        fixture.assert_rooted();
    }
}

#[test]
fn retained_construction_unknown_initial_load_cannot_adopt_later_equal_fresh_or_absence() {
    let fresh_data = pair().0.snapshot().clone();
    for equal_data in [false, true] {
        let mut fixture = RetainedConstruction::new(ConstructionFault::LoadError(1));
        assert!(fixture.construct().is_err());
        fixture.shared.borrow_mut().disk = equal_data.then(|| fresh_data.clone());
        let before = fixture.trace.borrow().loads;
        assert!(fixture.pair.as_mut().unwrap().close(&scope()).is_err());
        assert_eq!(fixture.trace.borrow().loads, before);
        assert_eq!(fixture.trace.borrow().writes, 0);
        fixture.assert_forward_denied();
        assert!(fixture.pair.as_ref().unwrap().cleanup_pending());
    }
}

#[test]
fn retained_construction_nonempty_initial_journal_never_issues_cas_or_adopts() {
    let original = pair().0.snapshot().clone();
    for foreign in [false, true] {
        let mut fixture = RetainedConstruction::new(ConstructionFault::None);
        let mut data = original.clone();
        if foreign {
            data.scope.connection_generation += 1;
        }
        fixture.shared.borrow_mut().disk = Some(data.clone());
        assert!(fixture.construct().is_err());
        fixture.assert_rooted();
        fixture.assert_forward_denied();
        assert!(fixture.pair.as_mut().unwrap().stop(&scope()).is_err());
        assert_eq!(fixture.trace.borrow().writes, 0);
        assert!(fixture.shared.borrow().disk.as_ref() == Some(&data));
        assert!(fixture.shared.borrow().counts.is_empty());
    }
}

#[test]
fn retained_construction_invalid_inputs_are_not_consumed_and_do_no_io() {
    for case in 0..7 {
        let mut fixture = RetainedConstruction::new(ConstructionFault::None);
        let mut scope = scope();
        let mut origin = provenance();
        match case {
            0 => scope.session_id = "not-a-scope".into(),
            1 => scope.connection_generation = 0,
            2 => origin.network_epoch = 0,
            3 => origin.boot_id = [0; 16],
            4 => origin.runtime.slot = RuntimeSlot::Latest,
            5 => fixture.native = None,
            _ => fixture.journal = None,
        }
        let had_native = fixture.native.is_some();
        let had_journal = fixture.journal.is_some();
        assert!(ConstructionPair::new_retained_into(
            &mut fixture.pair,
            scope,
            origin,
            &mut fixture.native,
            &mut fixture.journal,
        )
        .is_err());
        assert!(fixture.pair.is_none());
        assert_eq!(fixture.native.is_some(), had_native);
        assert_eq!(fixture.journal.is_some(), had_journal);
        assert_eq!(fixture.trace.borrow().loads, 0);
        assert_eq!(fixture.trace.borrow().writes, 0);
    }
}

#[test]
fn retained_construction_duplicate_keeps_and_fences_original_incoming_untouched() {
    let mut original = RetainedConstruction::new(ConstructionFault::None);
    original.construct().unwrap();
    original
        .pair
        .as_mut()
        .unwrap()
        .start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    let mut incoming = RetainedConstruction::new(ConstructionFault::None);
    assert!(ConstructionPair::new_retained_into(
        &mut original.pair,
        scope(),
        provenance(),
        &mut incoming.native,
        &mut incoming.journal,
    )
    .is_err());
    original.assert_rooted();
    assert!(incoming.native.is_some());
    assert!(incoming.journal.is_some());
    assert_eq!(incoming.trace.borrow().loads, 0);
    original.assert_forward_denied();
    original.pair.as_mut().unwrap().stop(&scope()).unwrap();
    original.assert_forward_denied();
}

#[test]
fn retained_construction_actor_reentry_cannot_access_owner_and_failed_callback_stays_fenced() {
    let mut fixture = RetainedConstruction::new(ConstructionFault::None);
    let actor = Rc::new(RefCell::new(None::<ConstructionPair>));
    let weak = Rc::downgrade(&actor);
    let trace = fixture.trace.clone();
    fixture.trace.borrow_mut().on_load = Some(Box::new(move || {
        assert_eq!(trace.borrow().writes, 0);
        assert!(weak.upgrade().unwrap().try_borrow_mut().is_err());
        Err(failed())
    }));
    assert!(ConstructionPair::new_retained_into(
        &mut actor.borrow_mut(),
        scope(),
        provenance(),
        &mut fixture.native,
        &mut fixture.journal,
    )
    .is_err());
    fixture.pair = actor.borrow_mut().take();
    fixture.assert_rooted();
    fixture.assert_forward_denied();
    assert_eq!(fixture.trace.borrow().writes, 0);
}

#[test]
fn retained_construction_readback_failure_stop_requires_native_predicates_and_exact_scope() {
    let mut fixture = RetainedConstruction::new(ConstructionFault::LoadError(2));
    assert!(fixture.construct().is_err());
    let mut foreign_scope = scope();
    foreign_scope.connection_generation += 1;
    assert!(fixture.pair.as_mut().unwrap().stop(&foreign_scope).is_err());
    assert!(!fixture.shared.borrow().cleanup_begun);
    fixture.shared.borrow_mut().foreign = true;
    assert!(fixture.pair.as_mut().unwrap().stop(&scope()).is_err());
    assert!(fixture.pair.as_ref().unwrap().cleanup_pending());
    assert_ne!(
        fixture.pair.as_ref().unwrap().snapshot().phase,
        Phase::Stopped
    );
    fixture.shared.borrow_mut().foreign = false;
    fixture.shared.borrow_mut().fail = Some(("full-empty".into(), false));
    assert!(fixture.pair.as_mut().unwrap().stop(&scope()).is_err());
    assert!(fixture.pair.as_ref().unwrap().cleanup_pending());
    fixture.pair.as_mut().unwrap().stop(&scope()).unwrap();
    assert!(!fixture.pair.as_ref().unwrap().cleanup_pending());
    fixture.assert_forward_denied();
}

#[test]
fn retained_construction_abandonment_does_not_implicitly_close_or_write() {
    let mut fixture = RetainedConstruction::new(ConstructionFault::WriteError(true));
    assert!(fixture.construct().is_err());
    let record = fixture.shared.borrow().disk.clone();
    let writes = fixture.trace.borrow().writes;
    drop(fixture.pair.take());
    assert_eq!(fixture.trace.borrow().drops, 1);
    assert_eq!(fixture.trace.borrow().writes, writes);
    assert!(fixture.shared.borrow().disk == record);
    assert!(fixture.shared.borrow().counts.is_empty());
}

#[test]
fn start_readies_c_once_before_addressless_a_and_blocks_before_network_and_ports() {
    let (mut p, s) = pair();
    p.start(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    assert_eq!(p.snapshot().phase, Phase::Running);
    assert_eq!(p.snapshot().active, Some(Slot::A));
    assert_eq!(s.borrow().counts.get("carrier-ready"), Some(&1));
    let events = &s.borrow().events;
    let position = |name: &str| events.iter().position(|e| e == name).unwrap();
    assert!(position("carrier-ready") < position("start-A"));
    assert!(position("bases") < position("weak"));
    assert!(position("weak") < position("network"));
    assert!(position("network") < position("hold-A"));
    assert!(position("hold-A") < position("allows"));
    assert!(position("allows") < position("data"));
}

#[test]
fn stop_explicitly_enters_cleanup_storage_before_reconciling_revoked_forward_reads() {
    let (mut pair, shared) = running();
    shared.borrow_mut().require_cleanup_entry = true;
    pair.stop(&scope()).unwrap();
    assert!(shared.borrow().cleanup_begun);
    assert_eq!(pair.snapshot().phase, Phase::Stopped);
    assert!(!pair.cleanup_pending());
    assert!(pair.check_integrity().is_err());
    pair.stop(&scope()).unwrap();
}

#[test]
fn failed_cleanup_storage_entry_revokes_live_reads_without_native_effects_and_can_retry() {
    for lost in [false, true] {
        let (mut pair, shared) = running();
        let effects_before = shared.borrow().events.len();
        shared.borrow_mut().fail = Some(("cleanup-storage".into(), lost));
        assert!(pair.stop(&scope()).is_err());
        assert_eq!(
            &shared.borrow().events[effects_before..],
            &["cleanup-storage"]
        );
        assert!(pair.cleanup_pending());
        assert!(pair.check_integrity().is_err());
        assert!(pair.open_probe(Slot::A).is_err());
        pair.stop(&scope()).unwrap();
        assert_eq!(pair.snapshot().phase, Phase::Stopped);
        assert!(!pair.cleanup_pending());
    }
}

#[test]
fn foreign_stop_cannot_enter_original_cleanup_storage_or_revoke_live_pair() {
    let (mut pair, shared) = running();
    let mut foreign = scope();
    foreign.connection_generation += 1;
    let before = shared.borrow().events.len();
    assert!(pair.stop(&foreign).is_err());
    assert_eq!(shared.borrow().events.len(), before);
    assert!(!shared.borrow().cleanup_begun);
    pair.check_integrity().unwrap();
}

fn running() -> (CarrierNativePair<Io, Disk>, Shared) {
    let (mut p, s) = pair();
    p.start(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    (p, s)
}

mod terminal_control {
    use super::*;
    use crate::member_carrier_control::{CarrierPairControl, CarrierPairFinalizer};
    use nelomai_client_tunnel::redundancy::{
        driver::{SessionDriver, SessionStore},
        session::{SessionPhase, SessionSnapshot, SessionState},
    };
    struct Finish {
        retained: Option<Rc<CarrierPairTerminalHandoff<Io, Disk>>>,
        originals: Option<(Io, Disk)>,
        calls: Rc<Cell<usize>>,
        fail_once: bool,
        leave_live: bool,
        unwind_once: bool,
    }
    impl CarrierPairFinalizer<Io, Disk> for Finish {
        fn finish(
            &mut self,
            original: &mut Option<CarrierNativePair<Io, Disk>>,
            scope: &SessionScope,
        ) -> io::Result<()> {
            self.calls.set(self.calls.get() + 1);
            if self.leave_live {
                return Ok(());
            }
            if self.retained.is_none() {
                CarrierNativePair::capture_terminal_into(original, &mut self.retained, |_| Ok(()))?;
            }
            if std::mem::take(&mut self.unwind_once) {
                panic!("native_finalizer_after_owning_capture");
            }
            if std::mem::take(&mut self.fail_once) {
                return Err(failed());
            }
            let retained = self.retained.as_ref().unwrap();
            retained.verify_original_terminal(scope)?;
            self.originals = Some(retained.take_originals(scope)?);
            Ok(())
        }
    }
    struct Sessions(Rc<RefCell<Vec<SessionSnapshot>>>);
    impl SessionStore for Sessions {
        fn save(&mut self, snapshot: &SessionSnapshot) -> io::Result<()> {
            self.0.borrow_mut().push(snapshot.clone());
            Ok(())
        }
    }
    type Control = CarrierPairControl<Io, Disk, Finish>;
    fn control(fail_once: bool, leave_live: bool) -> (Control, Shared, Rc<Cell<usize>>) {
        control_with_faults(fail_once, leave_live, false)
    }
    fn control_with_faults(
        fail_once: bool,
        leave_live: bool,
        unwind_once: bool,
    ) -> (Control, Shared, Rc<Cell<usize>>) {
        let (pair, state) = pair();
        let calls = Rc::new(Cell::new(0));
        let mut control = CarrierPairControl::new(
            pair,
            Finish {
                retained: None,
                originals: None,
                calls: calls.clone(),
                fail_once,
                leave_live,
                unwind_once,
            },
        );
        control
            .start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
            .unwrap();
        (control, state, calls)
    }
    struct ColdPreparation {
        state: Shared,
        calls: Rc<Cell<usize>>,
        io: Option<Io>,
        journal: Option<Disk>,
    }
    impl crate::member_carrier_control::CarrierPairPreparation<Io, Disk> for ColdPreparation {
        fn prepare_retained_into(
            &mut self,
            destination: &mut Option<CarrierNativePair<Io, Disk>>,
        ) -> io::Result<()> {
            self.calls.set(self.calls.get() + 1);
            assert!(Rc::ptr_eq(&self.io.as_ref().unwrap().0, &self.state));
            let scope = self.state.borrow().scope.clone();
            CarrierNativePair::new_retained_into(
                destination,
                scope,
                provenance(),
                &mut self.io,
                &mut self.journal,
            )
        }
    }
    fn cold_control() -> (Control, Shared, Rc<Cell<usize>>, Rc<Cell<usize>>) {
        cold_control_for(scope())
    }
    fn cold_control_for(
        scope: SessionScope,
    ) -> (Control, Shared, Rc<Cell<usize>>, Rc<Cell<usize>>) {
        let state = fresh_state_for(scope.clone());
        let prepared = Rc::new(Cell::new(0));
        let finished = Rc::new(Cell::new(0));
        let control = CarrierPairControl::from_preparation(
            scope,
            Box::new(ColdPreparation {
                state: state.clone(),
                calls: prepared.clone(),
                io: Some(Io(state.clone(), None)),
                journal: Some(Disk(state.clone())),
            }),
            Finish {
                retained: None,
                originals: None,
                calls: finished.clone(),
                fail_once: false,
                leave_live: false,
                unwind_once: false,
            },
        );
        (control, state, prepared, finished)
    }
    #[test]
    fn cold_factory_control_publishes_fresh_only_after_actor_owns_preparation() {
        let (mut control, state, prepared, finished) = cold_control();
        assert_eq!(prepared.get(), 0);
        assert!(state.borrow().disk.is_none());
        control
            .start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
            .unwrap();
        assert_eq!(prepared.get(), 1);
        assert_eq!(state.borrow().disk.as_ref().unwrap().phase, Phase::Running);
        assert_eq!(state.borrow().carrier, Some(proof(33)));
        control.close(&scope()).unwrap();
        assert!(!control.cleanup_pending());
        assert_eq!(finished.get(), 1);
        assert!(state.borrow().carrier.is_none());
    }
    mod factory_entry {
        use super::*;
        use crate::{
            member_actor::{CompositeBackend, PairFactory},
            ServiceError, ServiceTunnelBackend, ServiceTunnelState,
        };
        use nelomai_client_tunnel::{
            redundancy::{control::SessionControl, protocol::Command},
            TunnelTransport,
        };
        #[derive(Default)]
        struct Single(Rc<Cell<usize>>);
        impl ServiceTunnelBackend for Single {
            fn start(
                &mut self,
                _: &str,
                _: &DesktopTunnelOptions,
                _: TunnelTransport,
            ) -> Result<ServiceTunnelState, ServiceError> {
                self.0.set(self.0.get() + 1);
                Ok(ServiceTunnelState::Running)
            }
            fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
                self.0.set(self.0.get() + 1);
                Ok(ServiceTunnelState::Stopped)
            }
            fn status(&mut self) -> Result<ServiceTunnelState, ServiceError> {
                Ok(ServiceTunnelState::Stopped)
            }
        }
        #[derive(Default)]
        struct ExternalState {
            worlds: Vec<Shared>,
            prepared: Vec<Rc<Cell<usize>>>,
            finalized: Vec<Rc<Cell<usize>>>,
            sessions: Vec<SessionSnapshot>,
            scopes: Vec<SessionScope>,
            lose_starting_ack: bool,
            fail_native: Option<(String, bool)>,
            fail_fresh_ack: bool,
        }
        struct Factory(Rc<RefCell<ExternalState>>);
        struct Store(Rc<RefCell<ExternalState>>);
        impl SessionStore for Store {
            fn save(&mut self, snapshot: &SessionSnapshot) -> io::Result<()> {
                let mut state = self.0.borrow_mut();
                state.sessions.push(snapshot.clone());
                if snapshot.phase == SessionPhase::Starting
                    && std::mem::take(&mut state.lose_starting_ack)
                {
                    return Err(failed());
                }
                Ok(())
            }
        }
        impl PairFactory for Factory {
            type Native = Control;
            type Store = Store;
            fn recover(&mut self, _: RuntimeSlot) -> Result<(), ServiceError> {
                Ok(())
            }
            fn prepare(
                &mut self,
                runtime: RuntimeSlot,
                command: &Command,
                now: u64,
            ) -> io::Result<SessionControl<Control, Store>> {
                let mut destination = None;
                self.prepare_retained_into(&mut destination, runtime, command, now)?;
                destination.ok_or_else(failed)
            }
            fn prepare_retained_into(
                &mut self,
                destination: &mut Option<SessionControl<Control, Store>>,
                runtime: RuntimeSlot,
                command: &Command,
                now: u64,
            ) -> io::Result<()> {
                command.validate(runtime)?;
                let scope = command.scope().clone();
                let (native, world, prepared, finalized) = cold_control_for(scope.clone());
                {
                    let mut external = self.0.borrow_mut();
                    if external.scopes.contains(&scope) {
                        return Err(failed());
                    }
                    external.scopes.push(scope);
                    world.borrow_mut().fail = external.fail_native.take();
                    if std::mem::take(&mut external.fail_fresh_ack) {
                        world.borrow_mut().fail_save = Some((1, true));
                    }
                    external.worlds.push(world);
                    external.prepared.push(prepared);
                    external.finalized.push(finalized);
                }
                SessionControl::prepare_retained_into(
                    destination,
                    runtime,
                    command,
                    &mut Some(native),
                    &mut Some(Store(self.0.clone())),
                    now,
                )
            }
        }
        fn start(scope: SessionScope) -> Command {
            Command::Start {
                scope,
                primary: member(Slot::A),
                role_generation: 1,
                membership_generation: 1,
                warm_stop_v1: true,
                options: DesktopTunnelOptions::default(),
            }
        }
        type Fixture = (
            CompositeBackend<Single, Factory>,
            Rc<RefCell<ExternalState>>,
            Rc<Cell<usize>>,
        );
        fn setup() -> Fixture {
            let external = Rc::new(RefCell::new(ExternalState::default()));
            let single = Rc::new(Cell::new(0));
            (
                CompositeBackend::new(
                    RuntimeSlot::Stable,
                    Single(single.clone()),
                    Factory(external.clone()),
                )
                .unwrap(),
                external,
                single,
            )
        }
        fn view(
            active: Slot,
            role: u64,
            membership: u64,
            b: &str,
        ) -> nelomai_contracts::RedundantSessionView {
            let a = member(Slot::A).lease_id;
            nelomai_contracts::RedundantSessionView {
                session_id: scope().session_id,
                state: nelomai_contracts::RedundantSessionState::Connected,
                active_lease_id: Some(if active == Slot::A {
                    a.clone()
                } else {
                    b.into()
                }),
                slot_a_lease_id: Some(a),
                slot_b_lease_id: Some(b.into()),
                standby_desired: true,
                role_generation: role,
                membership_generation: membership,
                reason: None,
            }
        }
        fn confirm_role(
            actor: &mut CompositeBackend<Single, Factory>,
            active: Slot,
            generation: u64,
        ) {
            let current = actor.current_redundancy_snapshot().unwrap().session;
            let session = view(
                active,
                generation,
                current.membership_generation,
                &member(Slot::B).lease_id,
            );
            let local_active_lease_id = session.active_lease_id.clone().unwrap();
            actor
                .redundant(Command::ConfirmRole {
                    scope: scope(),
                    expected_revision: current.local_revision,
                    expected_network_epoch: current.network_epoch,
                    response: nelomai_contracts::RedundantRoleResponse {
                        api_version: nelomai_contracts::ApiVersion::V1,
                        request_id: "software-fixture".into(),
                        action: nelomai_contracts::RedundantRoleAction::Accepted,
                        local_active_lease_id,
                        session,
                    },
                })
                .unwrap();
        }
        #[test]
        fn carrier_factory_primary_start_stop_repeat_uses_fresh_session() {
            // Real actor + SessionControl + cold CarrierPairControl/coordinator;
            // only native IO/private storage/terminal SDK ACK are external doubles.
            let (mut actor, external, single) = setup();
            let first = actor.redundant(start(scope())).unwrap();
            assert_eq!(first.session.phase, SessionPhase::Running);
            actor.redundant(Command::Stop { scope: scope() }).unwrap();
            actor.redundant(Command::Stop { scope: scope() }).unwrap();
            let mut next = scope();
            next.session_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into();
            next.connection_generation += 1;
            let second = actor.redundant(start(next.clone())).unwrap();
            assert_eq!(second.session.scope, next);
            actor.redundant(Command::Stop { scope: next }).unwrap();
            let state = external.borrow();
            assert_eq!(state.worlds.len(), 2);
            assert!(state.prepared.iter().all(|calls| calls.get() == 1));
            assert!(state.finalized.iter().all(|calls| calls.get() == 1));
            for world in &state.worlds {
                let native = world.borrow();
                assert_eq!(native.counts.get("carrier-ready"), Some(&1));
                assert!(native.carrier.is_none());
                assert!(native.members.iter().all(Option::is_none));
                assert_eq!(native.network.routes.len(), 0);
                assert!(native.disk.as_ref().unwrap().phase == Phase::Stopped);
            }
            assert_eq!(single.get(), 0);
        }
        #[test]
        fn carrier_factory_partial_start_retains_cleanup_owner() {
            for boundary in [
                "starting",
                "fresh-ack",
                "carrier-ready",
                "start-A",
                "complete-start",
            ] {
                let (mut actor, external, single) = setup();
                {
                    let mut state = external.borrow_mut();
                    if boundary == "starting" {
                        state.lose_starting_ack = true;
                    } else if boundary == "fresh-ack" {
                        state.fail_fresh_ack = true;
                    } else {
                        state.fail_native = Some((boundary.into(), true));
                    }
                }
                assert!(actor.redundant(start(scope())).is_err(), "{boundary}");
                let snapshot = actor.current_redundancy_snapshot().unwrap();
                if !snapshot.cleanup_pending {
                    // SessionControl can already have completed exact Stop
                    // on a failed member/Running publication; no fallback ran.
                    assert_eq!(snapshot.session.phase, SessionPhase::Stopped, "{boundary}");
                }
                assert_eq!(snapshot.session.scope, scope());
                if snapshot.cleanup_pending {
                    assert!(actor
                        .start(
                            "ordinary",
                            &DesktopTunnelOptions::default(),
                            TunnelTransport::WireGuard
                        )
                        .is_err());
                }
                let mut foreign = scope();
                foreign.connection_generation += 1;
                assert!(actor.redundant(Command::Stop { scope: foreign }).is_err());
                let stopped = actor.redundant(Command::Stop { scope: scope() });
                if matches!(boundary, "fresh-ack" | "carrier-ready") {
                    // Unknown original CAS ACK is deliberately not inferred from
                    // matching bytes; same owner remains fenced and Pending.
                    assert!(stopped.is_err());
                    assert!(actor.current_redundancy_snapshot().unwrap().cleanup_pending);
                    assert_eq!(external.borrow().finalized[0].get(), 0);
                } else {
                    assert!(
                        !stopped
                            .unwrap_or_else(|error| panic!(
                                "{boundary}: {error:?}; events={:?}",
                                external.borrow().worlds[0].borrow().events
                            ))
                            .cleanup_pending,
                        "{boundary}"
                    );
                    assert_eq!(external.borrow().finalized[0].get(), 1);
                }
                assert_eq!(single.get(), 0);
            }
        }
        #[test]
        fn carrier_creator_is_rooted_before_lost_starting_ack_and_stopping_window() {
            let (mut actor, external, _) = setup();
            external.borrow_mut().lose_starting_ack = true;
            assert!(actor.redundant(start(scope())).is_err());
            // NativeCreator publication accepts only absent/Starting Session,
            // never Stopping. The original cold composition must already exist.
            assert_eq!(external.borrow().prepared[0].get(), 1);
            actor.redundant(Command::Stop { scope: scope() }).unwrap();
            assert_eq!(external.borrow().prepared[0].get(), 1);
        }
        #[test]
        fn carrier_factory_attach_switch_replace_preserves_carrier() {
            let (mut actor, external, single) = setup();
            let first = actor.redundant(start(scope())).unwrap();
            let world = external.borrow().worlds[0].clone();
            world.borrow_mut().probe_replies = true;
            let c = world.borrow().carrier;
            let attached = actor
                .redundant(Command::Attach {
                    scope: scope(),
                    member: member(Slot::B),
                    expected_revision: first.session.local_revision,
                    expected_network_epoch: first.session.network_epoch,
                    expected_membership_generation: 1,
                    membership_generation: 2,
                })
                .unwrap();
            assert_eq!(attached.session.membership_generation, 2);
            actor.tick(0).unwrap();
            actor.tick(100).unwrap();
            world.borrow_mut().health_dead[0] = true;
            for now in (200..=3500).step_by(100) {
                actor.tick(now).unwrap();
            }
            let switched = actor.current_redundancy_snapshot().unwrap();
            assert_eq!(switched.session.active, Slot::B);
            assert_eq!(world.borrow().disk.as_ref().unwrap().active, Some(Slot::B));
            assert_eq!(world.borrow().carrier, c);
            assert!(
                world.borrow().rx[1] > 0,
                "real evidence reducer consumed fake UDP only"
            );
            confirm_role(&mut actor, Slot::B, 2);
            world.borrow_mut().health_dead = [false, true];
            for now in (3600..=7500).step_by(100) {
                actor.tick(now).unwrap();
            }
            assert_eq!(
                actor.current_redundancy_snapshot().unwrap().session.active,
                Slot::A
            );
            assert_eq!(world.borrow().disk.as_ref().unwrap().active, Some(Slot::A));
            assert_eq!(world.borrow().carrier, c);
            confirm_role(&mut actor, Slot::A, 3);
            world.borrow_mut().health_dead = [false; 2];
            let before = actor.current_redundancy_snapshot().unwrap().session;
            let retired = actor
                .redundant(Command::RetireInactive {
                    scope: scope(),
                    slot: Slot::B,
                    lease_id: member(Slot::B).lease_id,
                    expected_revision: before.local_revision,
                    expected_network_epoch: before.network_epoch,
                    expected_membership_generation: before.membership_generation,
                })
                .unwrap();
            assert!(world.borrow().members[1].is_none());
            let mut replacement = member(Slot::B);
            replacement.lease_id = "44444444-4444-4444-8444-444444444444".into();
            replacement.configuration = TunnelConfiguration::new(
                replacement
                    .configuration
                    .expose()
                    .replace(":51820", ":51821"),
            );
            let new_lease = replacement.lease_id.clone();
            let staged = actor
                .redundant(Command::StageCandidate {
                    scope: scope(),
                    member: replacement,
                    expected_revision: retired.session.local_revision,
                    expected_network_epoch: retired.session.network_epoch,
                    expected_membership_generation: 2,
                })
                .unwrap();
            let effects = world.borrow().events.len();
            assert!(actor
                .redundant(Command::Attach {
                    scope: scope(),
                    member: member(Slot::B),
                    expected_revision: first.session.local_revision,
                    expected_network_epoch: first.session.network_epoch,
                    expected_membership_generation: 1,
                    membership_generation: 2,
                })
                .is_err());
            assert_eq!(
                world.borrow().events.len(),
                effects,
                "stale receipt cannot enter native"
            );
            let replaced = actor
                .redundant(Command::CommitCandidate {
                    scope: scope(),
                    slot: Slot::B,
                    expected_revision: staged.session.local_revision,
                    expected_network_epoch: staged.session.network_epoch,
                    session: view(Slot::A, 3, 3, &new_lease),
                })
                .unwrap();
            assert_eq!(replaced.session.membership_generation, 3);
            assert_eq!(world.borrow().carrier, c);
            assert_eq!(world.borrow().counts.get("carrier-ready"), Some(&1));
            assert_eq!(external.borrow().prepared[0].get(), 1);
            assert_eq!(single.get(), 0);
            actor.redundant(Command::Stop { scope: scope() }).unwrap();
            assert_eq!(external.borrow().finalized[0].get(), 1);
            assert!(world.borrow().carrier.is_none());
        }
        #[test]
        fn carrier_factory_switch_failure_never_publishes_target_or_falls_back() {
            for boundary in [
                "target-health",
                "withdraw",
                "network",
                "endpoints",
                "allows",
                "data",
            ] {
                for lost_ack in [false, true] {
                    let (mut actor, external, single) = setup();
                    let first = actor.redundant(start(scope())).unwrap();
                    actor
                        .redundant(Command::Attach {
                            scope: scope(),
                            member: member(Slot::B),
                            expected_revision: first.session.local_revision,
                            expected_network_epoch: first.session.network_epoch,
                            expected_membership_generation: 1,
                            membership_generation: 2,
                        })
                        .unwrap();
                    let world = external.borrow().worlds[0].clone();
                    world.borrow_mut().probe_replies = true;
                    actor.tick(0).unwrap();
                    actor.tick(100).unwrap();
                    world.borrow_mut().health_dead[0] = true;
                    world.borrow_mut().fail = Some((boundary.into(), lost_ack));
                    let mut failed_tick = false;
                    for now in (200..=3500).step_by(100) {
                        if actor.tick(now).is_err() {
                            failed_tick = true;
                            break;
                        }
                    }
                    assert!(failed_tick, "{boundary} lost={lost_ack}");
                    let stopped = actor.redundant(Command::Stop { scope: scope() }).unwrap();
                    assert_eq!(stopped.session.phase, SessionPhase::Stopped);
                    assert!(!stopped.cleanup_pending);
                    assert!(
                        external
                            .borrow()
                            .sessions
                            .iter()
                            .all(|s| s.active == Slot::A),
                        "no role publication after native failure"
                    );
                    let native = world.borrow();
                    assert!(native.carrier.is_none());
                    assert!(native.members.iter().all(Option::is_none));
                    assert!(!native.guard.permits);
                    assert!(native.network.routes.is_empty());
                    assert_eq!(native.held, 0);
                    assert_eq!(external.borrow().finalized[0].get(), 1);
                    assert_eq!(single.get(), 0);
                }
            }
        }
    }
    #[test]
    fn terminal_control_stopped_coordinator_does_not_publish_session_before_native_finalizer() {
        // Break: returning bare coordinator.stop success publishes SessionStopped
        // despite a still-owned module/graph or failed native terminal handoff.
        let (control, state, calls) = control(true, false);
        let sessions = Rc::new(RefCell::new(Vec::new()));
        let initial = SessionState::new(scope(), Slot::A, 1, 1).unwrap();
        let mut driver =
            SessionDriver::new(initial, control, Sessions(sessions.clone()), 0).unwrap();
        assert!(driver.stop(&scope()).is_err());
        assert_eq!(state.borrow().disk.as_ref().unwrap().phase, Phase::Stopped);
        assert_eq!(driver.state().snapshot().phase, SessionPhase::Stopping);
        assert!(driver.native().cleanup_pending());
        assert!(sessions
            .borrow()
            .iter()
            .all(|r| r.phase != SessionPhase::Stopped));
        assert_eq!(calls.get(), 1);
        driver.stop(&scope()).unwrap();
        assert_eq!(driver.state().snapshot().phase, SessionPhase::Stopped);
        assert!(!driver.native().cleanup_pending());
        assert_eq!(calls.get(), 2);
    }
    #[test]
    fn terminal_control_requires_owning_transfer_not_success_with_original_left_live() {
        let (mut control, state, calls) = control(false, true);
        assert!(control.close(&scope()).is_err());
        assert_eq!(state.borrow().disk.as_ref().unwrap().phase, Phase::Stopped);
        assert!(control.cleanup_pending());
        assert_eq!(calls.get(), 1);
        assert!(control.metrics(Slot::A).is_err());
        assert!(control.attach(&scope(), &member(Slot::B)).is_err());
    }
    #[test]
    fn terminal_control_success_and_repeat_stop_release_once_and_deny_forward() {
        let (mut control, _state, calls) = control(false, false);
        control.close(&scope()).unwrap();
        assert_eq!(calls.get(), 1);
        assert!(!control.cleanup_pending());
        control.close(&scope()).unwrap();
        assert_eq!(calls.get(), 1);
        assert!(control.open_probe(Slot::A).is_err());
        assert!(control.sample(Slot::A).is_none());
        assert!(control
            .start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
            .is_err());
        let mut other = scope();
        other.connection_generation += 1;
        assert!(control.close(&other).is_err());
        assert_eq!(calls.get(), 1);
    }
    #[test]
    fn terminal_control_foreign_stop_cannot_close_original_or_retire_forward() {
        // Break: latching Closing before exact scope validation lets a foreign
        // request stop the real session or silently revoke its working channel.
        let (mut control, state, calls) = control(false, false);
        let before = state.borrow().events.len();
        let mut foreign = scope();
        foreign.connection_generation += 1;
        assert!(control.close(&foreign).is_err());
        assert_eq!(state.borrow().events.len(), before);
        assert_eq!(calls.get(), 0);
        assert!(control.metrics(Slot::A).is_ok());
        control.check_integrity().unwrap();
        control.close(&scope()).unwrap();
        assert_eq!(calls.get(), 1);
    }
    #[test]
    fn terminal_control_native_stop_failure_never_enters_finalizer_or_reopens_forward() {
        // Break: invoking finalizer after incomplete native Stop or allowing
        // another Start between scoped cleanup retries.
        let (mut control, state, calls) = control(false, false);
        state.borrow_mut().fail = Some(("restore-network".into(), false));
        assert!(control.close(&scope()).is_err());
        assert_eq!(calls.get(), 0);
        assert!(control.cleanup_pending());
        assert!(control.metrics(Slot::A).is_err());
        assert!(control.select_active(&scope(), Slot::A).is_err());
        assert!(control.attach(&scope(), &member(Slot::B)).is_err());
        control.close(&scope()).unwrap();
        assert_eq!(calls.get(), 1);
        assert!(!control.cleanup_pending());
    }
    #[test]
    fn terminal_control_unwind_retains_original_handoff_and_cleanup_only_retry() {
        // Break: unwinding after native owning capture loses I/J or clears
        // Closing, allowing SessionStopped/forward before terminal release.
        let (mut control, _state, calls) = control_with_faults(false, false, true);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            control.close(&scope()).unwrap();
        }))
        .is_err());
        assert!(control.cleanup_pending());
        assert!(control.open_probe(Slot::A).is_err());
        assert!(control.complete_start(&scope()).is_err());
        control.close(&scope()).unwrap();
        assert_eq!(calls.get(), 2);
        assert!(!control.cleanup_pending());
    }
}
#[test]
fn terminal_handoff_moves_the_original_io_and_journal_once_without_effects() {
    let (mut pair, shared) = running();
    pair.stop(&scope()).unwrap();
    let before = shared.borrow().events.len();
    let mut source = Some(pair);
    let mut root = None;
    CarrierNativePair::capture_terminal_into(&mut source, &mut root, |_| Ok(())).unwrap();
    assert!(source.is_none());
    let root = root.unwrap();
    assert_eq!(shared.borrow().events.len(), before);
    root.verify_original_terminal(&scope()).unwrap();
    let before = shared.borrow().events.len();
    let (io, journal) = root.take_originals(&scope()).unwrap();
    assert!(Rc::ptr_eq(&io.0, &shared));
    assert!(Rc::ptr_eq(&journal.0, &shared));
    assert!(root.take_originals(&scope()).is_err());
    assert_eq!(shared.borrow().events.len(), before);
    let retained = root.pair.borrow();
    let retained = retained.as_ref().unwrap();
    assert_eq!(retained.record.phase, Phase::Stopped);
    assert!(retained.receipts.carrier.is_some());
    assert!(retained.receipts.members[0].is_some());
}

#[test]
fn terminal_handoff_take_denies_before_post_stopped_original_full_empty_read() {
    let (mut pair, shared) = running();
    pair.stop(&scope()).unwrap();
    let mut source = Some(pair);
    let mut root = None;
    CarrierNativePair::capture_terminal_into(&mut source, &mut root, |_| Ok(())).unwrap();
    let before = shared.borrow().events.len();
    assert!(root.as_ref().unwrap().take_originals(&scope()).is_err());
    assert_eq!(shared.borrow().events.len(), before);
}

#[test]
fn terminal_handoff_failed_original_full_empty_never_transfers_and_retry_rereads() {
    let (mut pair, shared) = running();
    pair.stop(&scope()).unwrap();
    let mut source = Some(pair);
    let mut root = None;
    CarrierNativePair::capture_terminal_into(&mut source, &mut root, |_| Ok(())).unwrap();
    let root = root.unwrap();
    shared.borrow_mut().fail = Some(("full-empty".into(), false));
    let reads = shared.borrow().counts["full-empty"];
    assert!(root.verify_original_terminal(&scope()).is_err());
    assert!(root.take_originals(&scope()).is_err());
    assert_eq!(shared.borrow().counts["full-empty"], reads + 1);
    root.verify_original_terminal(&scope()).unwrap();
    assert_eq!(shared.borrow().counts["full-empty"], reads + 2);
    let before = shared.borrow().events.len();
    assert!(root.verify_original_terminal(&scope()).is_err());
    let _originals = root.take_originals(&scope()).unwrap();
    assert_eq!(shared.borrow().events.len(), before);
}

#[test]
fn terminal_handoff_retains_originals_before_callback_error_or_unwind() {
    for unwind in [false, true] {
        let (mut pair, shared) = running();
        pair.stop(&scope()).unwrap();
        let before = shared.borrow().events.len();
        let mut source = Some(pair);
        let mut root = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            CarrierNativePair::capture_terminal_into(&mut source, &mut root, |_| {
                if unwind {
                    panic!("terminal handoff callback");
                }
                Err(failed())
            })
        }));
        assert!(if unwind {
            result.is_err()
        } else {
            result.unwrap().is_err()
        });
        assert!(source.is_none());
        assert_eq!(shared.borrow().events.len(), before);
        let root = root.unwrap();
        root.verify_original_terminal(&scope()).unwrap();
        let before = shared.borrow().events.len();
        let (io, journal) = root.take_originals(&scope()).unwrap();
        assert!(Rc::ptr_eq(&io.0, &shared));
        assert!(Rc::ptr_eq(&journal.0, &shared));
        assert_eq!(shared.borrow().events.len(), before);
    }
}

#[test]
fn terminal_handoff_rejects_foreign_scope_and_live_or_unacknowledged_owner() {
    for scenario in 0..4 {
        let (mut pair, shared) = running();
        if scenario != 0 {
            pair.stop(&scope()).unwrap();
        }
        let mut selected = scope();
        match scenario {
            1 => selected.connection_generation += 1,
            2 => pair.terminal_ack_pending = true,
            3 => pair.uncertain_write = Some(pair.record.clone()),
            _ => {}
        }
        let before = shared.borrow().events.len();
        let held = shared.borrow().held;
        let mut source = Some(pair);
        let mut root = None;
        CarrierNativePair::capture_terminal_into(&mut source, &mut root, |_| Ok(())).unwrap();
        assert!(root
            .as_ref()
            .unwrap()
            .verify_original_terminal(&selected)
            .is_err());
        assert!(root.as_ref().unwrap().take_originals(&selected).is_err());
        assert!(root.as_ref().unwrap().pair.borrow().is_some());
        assert_eq!(shared.borrow().events.len(), before);
        assert_eq!(shared.borrow().held, held);
    }
}

#[test]
fn terminal_handoff_occupied_destination_preserves_second_original_owner() {
    let (pair, _) = running();
    let mut first = Some(pair);
    let mut root = None;
    CarrierNativePair::capture_terminal_into(&mut first, &mut root, |_| Ok(())).unwrap();
    let (pair, shared) = running();
    let mut second = Some(pair);
    let before = shared.borrow().events.len();
    assert!(
        CarrierNativePair::capture_terminal_into(&mut second, &mut root, |_| {
            panic!("occupied destination must not invoke callback")
        })
        .is_err()
    );
    assert!(second.is_some());
    assert_eq!(shared.borrow().events.len(), before);
    second.as_mut().unwrap().check_integrity().unwrap();
}

#[test]
fn terminal_handoff_releases_inert_history_only_after_originals_transferred() {
    let (mut pair, shared) = running();
    pair.stop(&scope()).unwrap();
    let retained_latch = pair.faulted.clone();
    let before = shared.borrow().events.len();
    let mut source = Some(pair);
    let mut root = None;
    CarrierNativePair::capture_terminal_into(&mut source, &mut root, |_| Ok(())).unwrap();
    let root = root.unwrap();
    assert_eq!(shared.borrow().events.len(), before);
    root.verify_original_terminal(&scope()).unwrap();
    let before = shared.borrow().events.len();
    let _originals = root.take_originals(&scope()).unwrap();
    drop(root);
    assert_eq!(Rc::strong_count(&retained_latch), 1);
    assert_eq!(shared.borrow().events.len(), before);
}

#[test]
fn terminal_handoff_abandonment_keeps_untransferred_originals_and_socket_obligations() {
    let (pair, shared) = running();
    let retained_latch = pair.faulted.clone();
    let before = shared.borrow().events.len();
    let mut source = Some(pair);
    let mut root = None;
    CarrierNativePair::capture_terminal_into(&mut source, &mut root, |_| Ok(())).unwrap();
    assert!(root.as_ref().unwrap().take_originals(&scope()).is_err());
    drop(root);
    assert_eq!(Rc::strong_count(&retained_latch), 2);
    assert_eq!(shared.borrow().held, 1);
    assert_eq!(shared.borrow().events.len(), before);
}
#[test]
fn startup_handoff_selects_running_once_and_rejects_foreign_or_duplicate_calls() {
    let (mut pair, shared) = running();
    let mut foreign = scope();
    foreign.connection_generation += 1;
    assert!(pair.complete_start(&foreign).is_err());
    assert!(!shared.borrow().counts.contains_key("complete-start"));
    pair.complete_start(&scope()).unwrap();
    assert_eq!(shared.borrow().counts.get("complete-start"), Some(&1));
    assert!(pair.complete_start(&scope()).is_err());
    assert_eq!(shared.borrow().counts.get("complete-start"), Some(&1));
    pair.check_integrity().unwrap();
    pair.stop(&scope()).unwrap();
}
#[test]
fn startup_handoff_failure_or_wrong_epoch_cannot_reopen_forward_reads() {
    for fault in 0..3 {
        let (mut pair, shared) = running();
        match fault {
            0 => shared.borrow_mut().fail = Some(("complete-start".into(), false)),
            1 => shared.borrow_mut().fail = Some(("complete-start".into(), true)),
            _ => shared.borrow_mut().execution_epoch += 1,
        }
        assert!(pair.complete_start(&scope()).is_err());
        assert!(pair.check_integrity().is_err());
        assert!(pair.open_probe(Slot::A).is_err());
        assert!(pair.complete_start(&scope()).is_err());
        assert_eq!(shared.borrow().counts.get("complete-start"), Some(&1));
        pair.stop(&scope()).unwrap();
        assert_eq!(pair.snapshot().phase, Phase::Stopped);
    }
}
#[test]
fn startup_handoff_unwind_keeps_original_resources_cleanup_only() {
    let (mut pair, shared) = running();
    shared.borrow_mut().fail = Some(("complete-start-unwind".into(), false));
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || pair.complete_start(&scope())
    ))
    .is_err());
    assert!(pair.check_integrity().is_err());
    assert!(pair.open_probe(Slot::A).is_err());
    shared.borrow_mut().fail = None;
    pair.stop(&scope()).unwrap();
    assert_eq!(pair.snapshot().phase, Phase::Stopped);
}
#[test]
fn actual_member_plan_keeps_endpoint_and_lan_physical_bypasses() {
    use crate::member_plan::{member_route_plan, InterfaceMetric};
    use nelomai_client_tunnel::redundancy::route_plan::MemberRoutes;
    let (p, _) = running();
    let physical = |destination: &str| RouteValue {
        destination: destination.parse().unwrap(),
        scope: RouteScope::WindowsInterface(26),
        interface: 26,
        gateway: Some("192.168.3.1".parse().unwrap()),
        metric: 1,
    };
    let plan = member_route_plan(
        Slot::A,
        &[MemberRoutes {
            slot: Slot::A,
            interface: 11,
            allowed: vec!["0.0.0.0/0".parse().unwrap()],
            probe: "1.1.1.1".parse().unwrap(),
        }],
        &[
            "192.0.2.11/32".parse().unwrap(),
            "192.168.3.0/24".parse().unwrap(),
        ],
        &[physical("192.0.2.11/32"), physical("192.168.3.0/24")],
        &[
            InterfaceMetric {
                interface: 11,
                ipv6: false,
                metric: 5,
            },
            InterfaceMetric {
                interface: 26,
                ipv6: false,
                metric: 10,
            },
        ],
        1,
    )
    .unwrap();
    assert!(plan.routes.iter().any(|r| r.interface == 26));
    let mut snapshot = p.snapshot().network.as_ref().unwrap().current.clone();
    snapshot.routes = plan.routes;
    // This is structural validation ONLY. The required original-native IO
    // boundary must separately authenticate physical leases and the whole plan.
    validate_network(p.snapshot(), &snapshot, true).unwrap();
}
#[test]
fn structural_physical_plan_is_not_native_authority_and_failure_precedes_effect() {
    let (mut p, s) = pair();
    s.borrow_mut().fail = Some(("plan-proof".into(), false));
    assert!(p
        .start(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .is_err());
    assert_eq!(s.borrow().counts.get("plan-proof"), Some(&1));
    assert!(!s.borrow().counts.contains_key("network"));
    assert!(!s.borrow().counts.contains_key("allows"));
    p.stop(&scope()).unwrap();
    assert_eq!(p.snapshot().phase, Phase::Stopped);
}
#[test]
fn physical_plan_still_rejects_carrier_scope_family_and_aliased_keys() {
    let (p, _) = running();
    let original = p.snapshot().network.as_ref().unwrap().current.clone();
    for kind in 0..5 {
        let mut n = original.clone();
        match kind {
            0 => {
                n.routes[0].interface = p.snapshot().carrier.unwrap().index;
            }
            1 => {
                n.routes[0].scope = RouteScope::Global;
            }
            2 => {
                n.routes[0].gateway = Some("2001:db8::1".parse().unwrap());
            }
            3 => {
                n.routes.push(n.routes[0].clone());
            }
            _ => {
                n.routes[0].interface = 0;
            }
        }
        assert!(validate_network(p.snapshot(), &n, true).is_err(), "{kind}");
    }
}
fn attached() -> (CarrierNativePair<Io, Disk>, Shared) {
    let (mut p, s) = running();
    p.attach_member(&scope(), p.fence(), &member(Slot::B))
        .unwrap();
    (p, s)
}
#[test]
fn independent_ab_attach_and_switch_keep_same_c_and_withdraw_before_routes_before_allows() {
    let (mut p, s) = attached();
    let c = p.snapshot().carrier;
    assert_ne!(
        p.snapshot().members[0].as_ref().unwrap().owner.proof,
        p.snapshot().members[1].as_ref().unwrap().owner.proof
    );
    let start = s.borrow().events.len();
    p.switch(&scope(), p.fence(), Slot::B).unwrap();
    assert_eq!(p.snapshot().carrier, c);
    assert_eq!(p.snapshot().active, Some(Slot::B));
    assert_eq!(s.borrow().counts.get("carrier-ready"), Some(&1));
    let events = &s.borrow().events[start..];
    let pos = |name: &str| events.iter().position(|e| e == name).unwrap();
    assert!(pos("withdraw") < pos("network"));
    assert!(pos("network") < pos("allows"));
    assert!(pos("allows") < pos("data"));
}
#[test]
fn stop_closing_first_preserves_bases_until_full_native_absence_then_terminal() {
    let (mut p, s) = attached();
    let start = s.borrow().events.len();
    p.stop(&scope()).unwrap();
    assert_eq!(p.snapshot().phase, Phase::Stopped);
    assert_eq!(s.borrow().held, 0);
    let events = &s.borrow().events[start..];
    assert_eq!(events[0], "cleanup-storage");
    assert!(events[1].starts_with("save:Closing"));
    let pos = |name: &str| events.iter().position(|e| e == name).unwrap();
    assert!(pos("close-allows") < pos("release-A"));
    assert!(pos("release-B") < pos("restore-network"));
    assert!(pos("restore-network") < pos("restore-weak"));
    assert!(pos("restore-weak") < pos("stop-A"));
    assert!(pos("stop-B") < pos("address-delete"));
    assert!(pos("address-delete") < pos("session-end"));
    assert!(pos("session-end") < pos("carrier-close"));
    assert!(pos("carrier-close") < pos("native-empty"));
    assert!(pos("native-empty") < pos("bases"));
    assert!(pos("bases") < pos("restore-keys"));
    assert!(pos("restore-keys") < pos("full-empty"));
}
#[test]
fn sibling_network_mismatch_and_stale_fences_have_no_effects() {
    let (mut p, s) = running();
    let mut b = member(Slot::B);
    b.configuration = TunnelConfiguration::new(
        b.configuration
            .expose()
            .replace("10.7.0.2/32", "10.7.0.3/32"),
    );
    let events = s.borrow().events.len();
    assert!(p.attach_member(&scope(), p.fence(), &b).is_err());
    assert_eq!(s.borrow().events.len(), events);
    let mut fence = p.fence();
    fence.revision -= 1;
    assert!(p.attach_member(&scope(), fence, &member(Slot::B)).is_err());
    assert_eq!(s.borrow().events.len(), events);
}
#[test]
fn partial_start_never_cleanup_and_resume_and_stop_retries_exact_obligation() {
    for name in ["start-A", "weak", "network", "hold-A", "allows", "data"] {
        for lost in [false, true] {
            let (mut p, s) = pair();
            s.borrow_mut().fail = Some((name.into(), lost));
            assert!(
                p.start(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
                    .is_err(),
                "{name} {lost}"
            );
            assert_ne!(p.snapshot().phase, Phase::Running);
            let events = s.borrow().events.len();
            assert!(p
                .start(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
                .is_err());
            assert_eq!(events, s.borrow().events.len());
            p.stop(&scope()).unwrap_or_else(|e| {
                panic!(
                    "start failure {name} lost={lost}: {e}; stage={} events={:?}",
                    p.snapshot().stop_stage,
                    s.borrow().events
                )
            });
            assert_eq!(p.snapshot().phase, Phase::Stopped);
        }
    }
}
#[test]
fn each_stop_partial_or_lost_ack_is_retryable_without_early_terminal() {
    for name in [
        "close-allows",
        "release-A",
        "restore-network",
        "restore-weak",
        "stop-A",
        "stop-B",
        "address-delete",
        "session-end",
        "carrier-close",
        "native-empty",
        "bases",
        "restore-keys",
        "full-empty",
    ] {
        for lost in [false, true] {
            let (mut p, s) = attached();
            s.borrow_mut().fail = Some((name.into(), lost));
            assert!(p.stop(&scope()).is_err(), "{name} {lost}");
            assert_ne!(p.snapshot().phase, Phase::Stopped);
            p.stop(&scope()).unwrap_or_else(|e| {
                panic!(
                    "stop failure {name} lost={lost}: {e}; stage={} events={:?}",
                    p.snapshot().stop_stage,
                    s.borrow().events
                )
            });
            assert_eq!(p.snapshot().phase, Phase::Stopped, "{name} {lost}");
        }
    }
}

#[test]
fn stopping_before_start_retires_claim_without_creating_native_resources() {
    let (mut p, s) = pair();
    p.stop(&scope()).unwrap();
    assert_eq!(p.snapshot().phase, Phase::Stopped);
    assert!(!s.borrow().counts.contains_key("carrier-ready"));
    assert!(!s.borrow().counts.contains_key("start-A"));
}
#[test]
fn all_start_protected_cas_failures_remain_cleanup_only_and_can_retire_acknowledged_effects() {
    let (p, s) = running();
    let saves = s.borrow().saves;
    drop(p);
    for save in 2..=saves {
        for lost in [false, true] {
            let (mut p, s) = pair();
            s.borrow_mut().fail_save = Some((save, lost));
            assert!(
                p.start(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
                    .is_err(),
                "save {save} lost={lost}"
            );
            assert!(p.cleanup_pending());
            let count = s.borrow().events.len();
            assert!(p
                .start(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
                .is_err());
            assert_eq!(s.borrow().events.len(), count);
            p.stop(&scope()).unwrap_or_else(|e| {
                panic!(
                    "start CAS {save} lost={lost}: {e} stage={}",
                    p.snapshot().stop_stage
                )
            });
            assert_eq!(p.snapshot().phase, Phase::Stopped);
        }
    }
}
#[test]
fn switch_partial_or_lost_ack_never_publishes_target_or_resumes() {
    for name in [
        "target-health",
        "withdraw",
        "network",
        "endpoints",
        "allows",
        "data",
    ] {
        for lost in [false, true] {
            let (mut p, s) = attached();
            s.borrow_mut().fail = Some((name.into(), lost));
            assert!(
                p.switch(&scope(), p.fence(), Slot::B).is_err(),
                "{name} {lost}"
            );
            assert_eq!(p.snapshot().active, Some(Slot::A));
            assert!(p.cleanup_pending());
            assert!(p.switch(&scope(), p.fence(), Slot::B).is_err());
            p.stop(&scope()).unwrap();
        }
    }
}
#[test]
fn unacknowledged_native_c_creation_is_never_adopted_or_blindly_deleted() {
    let (mut p, s) = pair();
    s.borrow_mut().fail = Some(("carrier-ready".into(), true));
    assert!(p
        .start(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .is_err());
    assert!(p.snapshot().carrier.is_none());
    assert!(p.stop(&scope()).is_err());
    assert!(s.borrow().carrier.is_some());
    assert!(!s.borrow().counts.contains_key("carrier-close"));
    assert!(p.cleanup_pending());
}
#[test]
fn unknown_version_extra_fields_and_guard_source_mismatch_fail_record_decode() {
    let (p, _) = running();
    let raw = serde_json::to_value(p.snapshot()).unwrap();
    for value in [
        serde_json::json!(1),
        serde_json::json!(3),
        serde_json::json!(0),
    ] {
        let mut bad = raw.clone();
        bad["version"] = value;
        assert!(Record::decode(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    let mut bad = raw.clone();
    bad["foreignAuthority"] = serde_json::json!(true);
    assert!(Record::decode(&serde_json::to_vec(&bad).unwrap()).is_err());
    let mut bad = raw;
    bad["carrier"]["guid"] = serde_json::to_value([44; 16]).unwrap();
    assert!(Record::decode(&serde_json::to_vec(&bad).unwrap()).is_err());
}
#[test]
fn cleanup_only_recovery_cannot_sample_probe_start_attach_switch_or_rebind() {
    let (mut p, s) = running();
    p.stop(&scope()).unwrap();
    let saved = p.snapshot().clone();
    drop(p);
    let mut p = CarrierNativePair::recover_for_cleanup(
        scope(),
        provenance(),
        saved,
        Io(s.clone(), None),
        Disk(s.clone()),
    )
    .unwrap();
    let count = s.borrow().events.len();
    assert!(p.sample(Slot::A).is_none());
    assert!(p.open_probe(Slot::A).is_err());
    assert!(p
        .start(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .is_err());
    assert!(p
        .attach_member(&scope(), p.fence(), &member(Slot::B))
        .is_err());
    assert!(p.switch(&scope(), p.fence(), Slot::B).is_err());
    assert!(p.rebind_pair(&scope()).is_err());
    assert_eq!(s.borrow().events.len(), count);
    p.stop(&scope()).unwrap();
}
#[test]
fn stale_scope_boot_runtime_epoch_and_foreign_native_resources_never_gain_mutation_authority() {
    let (p, s) = running();
    let saved = p.snapshot().clone();
    let mut stale = scope();
    stale.connection_generation += 1;
    assert!(CarrierNativePair::recover_for_cleanup(
        stale,
        provenance(),
        saved.clone(),
        Io(s.clone(), None),
        Disk(s.clone())
    )
    .is_err());
    for change in [0, 1, 2] {
        let mut provenance = provenance();
        match change {
            0 => provenance.boot_id = [9; 16],
            1 => provenance.runtime.manifest_sha256 = "b".repeat(64),
            _ => provenance.network_epoch += 1,
        };
        assert!(CarrierNativePair::recover_for_cleanup(
            scope(),
            provenance,
            saved.clone(),
            Io(s.clone(), None),
            Disk(s.clone())
        )
        .is_err());
    }
    drop(p);
    let (mut p, s) = attached();
    s.borrow_mut().foreign = true;
    let count = s.borrow().counts.clone();
    assert!(p.stop(&scope()).is_err());
    // Explicit private cleanup selection is not a native mutation grant.
    // The foreign SDK state still blocks ALL subsequent effects.
    let mut actual = s.borrow().counts.clone();
    assert_eq!(actual.remove("cleanup-storage"), Some(1));
    assert_eq!(actual, count);
}
#[test]
fn drop_has_no_implicit_native_or_journal_effects_and_does_not_release_authorized_ports() {
    let (p, s) = attached();
    let count = s.borrow().events.len();
    let held = s.borrow().held;
    drop(p);
    assert_eq!(s.borrow().events.len(), count);
    assert_eq!(s.borrow().held, held);
    assert_eq!(s.borrow().released, 0);
}
#[test]
fn failed_withdrawal_readback_keeps_both_ports_and_prevents_network_or_terminal_effects() {
    let (mut p, s) = attached();
    let held = s.borrow().held;
    s.borrow_mut().fail = Some(("snapshot".into(), false));
    assert!(p.stop(&scope()).is_err());
    assert_eq!(s.borrow().held, held);
    assert_eq!(s.borrow().released, 0);
    assert!(p.cleanup_pending());
    p.stop(&scope()).unwrap();
    assert_eq!(p.snapshot().phase, Phase::Stopped);
}

#[test]
fn compatible_rebind_retires_processes_but_keeps_c_and_same_native_interfaces() {
    let (mut p, s) = attached();
    let c = p.snapshot().carrier;
    let old = p.snapshot().members.clone();
    assert!(p.rebind_pair(&scope()).unwrap());
    assert_eq!(p.snapshot().carrier, c);
    for slot in [Slot::A, Slot::B] {
        let owner = &p.snapshot().members[idx(slot)].as_ref().unwrap().owner;
        assert_eq!(
            owner.retired_proof,
            old[idx(slot)].as_ref().unwrap().owner.proof
        );
        assert_ne!(
            owner.proof.unwrap().process,
            owner.retired_proof.unwrap().process
        );
        assert_eq!(
            owner.proof.unwrap().interface,
            owner.retired_proof.unwrap().interface
        );
    }
    assert_eq!(s.borrow().counts.get("carrier-ready"), Some(&1));
    p.stop(&scope()).unwrap();
}

#[test]
fn rebind_execution_fence_advances_without_rewriting_birth_journals() {
    let (mut p, s) = attached();
    let birth = p.snapshot().provenance.clone();
    assert!(p.rebind_pair(&scope()).unwrap());
    // The common owner persists the completion epoch AFTER native rebind.
    s.borrow_mut().execution_epoch = 3;
    p.complete_rebind(&scope()).unwrap();
    p.check_integrity().unwrap();
    assert_eq!(p.fence().network_epoch, 3);
    assert_eq!(p.snapshot().provenance, birth);
    assert_eq!(s.borrow().disk.as_ref().unwrap().provenance, birth);
    assert!(p.rebind_pair(&scope()).unwrap());
    s.borrow_mut().execution_epoch = 5;
    p.complete_rebind(&scope()).unwrap();
    p.check_integrity().unwrap();
    assert_eq!(p.fence().network_epoch, 5);
    assert_eq!(p.snapshot().provenance, birth);
    p.stop(&scope()).unwrap();
}

#[test]
fn unsolicited_or_skipped_execution_ack_cannot_refresh_live_fence() {
    for unexpected in [0, 2, 3, u64::MAX] {
        let (mut p, s) = attached();
        s.borrow_mut().execution_epoch = unexpected;
        assert!(
            p.complete_rebind(&scope()).is_err(),
            "unsolicited epoch {unexpected}"
        );
        assert_eq!(p.fence().network_epoch, 1);
    }
    let (mut p, s) = attached();
    p.rebind_pair(&scope()).unwrap();
    s.borrow_mut().execution_epoch = 4;
    assert!(p.complete_rebind(&scope()).is_err());
    assert!(p.cleanup_pending());
}

#[test]
fn pending_execution_completion_cannot_read_data_and_full_stop_retires_the_fence() {
    let (mut p, _) = attached();
    p.rebind_pair(&scope()).unwrap();
    assert!(p.cleanup_pending());
    assert!(p.check_integrity().is_err());
    assert!(p.sample(Slot::A).is_none());
    assert!(p.open_probe(Slot::B).is_err());
    p.stop(&scope()).unwrap();
    assert!(!p.cleanup_pending());
    p.stop(&scope()).unwrap();
    assert!(!p.cleanup_pending());
}

#[test]
fn failed_or_lost_execution_boundaries_never_resume_live_and_keep_stop_possible() {
    for (boundary, lost) in [
        ("execution-begin", false),
        ("execution-begin", true),
        ("execution-seal", false),
        ("execution-seal", true),
        ("execution-complete", false),
        ("execution-complete", true),
    ] {
        let (mut p, s) = attached();
        let birth = p.snapshot().provenance.clone();
        let original_carrier = p.snapshot().carrier;
        if boundary == "execution-complete" {
            p.rebind_pair(&scope()).unwrap();
            s.borrow_mut().execution_epoch = 3;
            s.borrow_mut().fail = Some((boundary.into(), lost));
            assert!(p.complete_rebind(&scope()).is_err());
        } else {
            s.borrow_mut().fail = Some((boundary.into(), lost));
            assert!(p.rebind_pair(&scope()).is_err());
        }
        assert_eq!(p.snapshot().provenance, birth);
        assert_eq!(p.snapshot().carrier, original_carrier);
        assert!(p.cleanup_pending());
        assert!(p.sample(Slot::A).is_none());
        assert!(p.open_probe(Slot::A).is_err());
        p.stop(&scope()).unwrap();
        assert!(!p.cleanup_pending(), "{boundary} lost={lost}");
    }
}

#[test]
fn pending_execution_completion_does_not_hide_uncertain_cleanup_ack() {
    let (mut p, s) = attached();
    p.rebind_pair(&scope()).unwrap();
    let next_save = s.borrow().saves + 1;
    s.borrow_mut().fail_save = Some((next_save, true));
    assert!(p.stop(&scope()).is_err());
    assert!(p.cleanup_pending());
    p.stop(&scope()).unwrap();
    assert!(!p.cleanup_pending());
    assert!(p.complete_rebind(&scope()).is_err());
}
#[test]
fn targeted_inactive_retirement_then_replacement_keeps_primary_and_c() {
    let (mut p, s) = attached();
    let c = p.snapshot().carrier;
    p.remove_standby(&scope(), Slot::B).unwrap();
    assert_eq!(p.snapshot().carrier, c);
    assert_eq!(p.snapshot().active, Some(Slot::A));
    assert!(p.snapshot().members[1].is_none());
    assert!(p.snapshot().guard.members[1].is_none());
    p.attach_member(&scope(), p.fence(), &member(Slot::B))
        .unwrap();
    assert_eq!(s.borrow().counts.get("carrier-ready"), Some(&1));
    p.stop(&scope()).unwrap();
}

#[test]
fn protected_cas_contract_accepts_exact_revision_transition_and_rejects_replay_or_baseline_replacement(
) {
    let (p, _) = pair();
    let old = p.snapshot().clone();
    let mut desired = old.clone();
    desired.revision += 1;
    desired.phase = Phase::Starting;
    desired.addresses = vec!["10.7.0.2/32".parse().unwrap()];
    desired.options = Some(DesktopTunnelOptions::default());
    desired.operation = Some(Operation::Start(Slot::A));
    validate_transition(Some(&old), &desired).unwrap();
    assert!(validate_transition(Some(&old), &old).is_err());
    let mut replay = desired.clone();
    replay.scope.connection_generation += 1;
    assert!(validate_transition(Some(&old), &replay).is_err());
    let (p, _) = running();
    let old = p.snapshot().clone();
    let mut desired = old.clone();
    desired.revision += 1;
    desired.network.as_mut().unwrap().baseline.routes =
        desired.network.as_ref().unwrap().current.routes.clone();
    assert!(validate_transition(Some(&old), &desired).is_err());
}
#[test]
fn every_stop_journal_partial_or_lost_ack_keeps_completion_pending_until_retry() {
    let (mut p, s) = attached();
    let first = s.borrow().saves;
    p.stop(&scope()).unwrap();
    let last = s.borrow().saves;
    for save in first + 1..=last {
        for lost in [false, true] {
            let (mut p, s) = attached();
            s.borrow_mut().fail_save = Some((save, lost));
            assert!(p.stop(&scope()).is_err(), "save {save} lost={lost}");
            assert!(p.cleanup_pending(), "save {save} lost={lost}");
            p.stop(&scope()).unwrap_or_else(|e| {
                panic!(
                    "stop CAS {save} lost={lost}: {e} stage={}",
                    p.snapshot().stop_stage
                )
            });
            assert_eq!(p.snapshot().phase, Phase::Stopped);
            assert!(!p.cleanup_pending());
        }
    }
}
#[test]
fn warm_last_primary_remains_owned_by_common_session_state_after_local_complete_cleanup() {
    use nelomai_client_tunnel::redundancy::session::SessionState;
    let (mut p, s) = attached();
    let mut state = SessionState::new(scope(), Slot::A, 2, 3).unwrap();
    state.primary_started(&scope()).unwrap();
    let install = state.install_ticket(&scope(), Slot::B).unwrap();
    state.standby_installed(install, 4).unwrap();
    let promotion = state.promotion_ticket(&scope(), Slot::B).unwrap();
    state
        .promote(promotion, || p.select_active(&scope(), Slot::B))
        .unwrap();
    assert!(state.warm_slot().is_none());
    let update = state.role_update().unwrap();
    assert!(state.ack_role(&update, 3));
    state.begin_stop(&scope()).unwrap();
    p.stop(&scope()).unwrap();
    state.stopped(&scope()).unwrap();
    assert_eq!(state.warm_slot(), Some(Slot::B));
    assert!(s.borrow().carrier.is_none());
    assert!(s.borrow().members.iter().all(Option::is_none));
}

#[test]
fn attach_partial_or_lost_ack_fences_the_pair_and_cleanup_keeps_original_c() {
    for name in [
        "withdraw", "start-B", "bases", "weak", "network", "hold-B", "allows", "data",
    ] {
        for lost in [false, true] {
            let (mut p, s) = running();
            let c = p.snapshot().carrier;
            s.borrow_mut().fail = Some((name.into(), lost));
            assert!(
                p.attach_member(&scope(), p.fence(), &member(Slot::B))
                    .is_err(),
                "{name} {lost}"
            );
            assert_eq!(p.snapshot().carrier, c);
            assert!(p.cleanup_pending());
            assert!(p.sample(Slot::A).is_none());
            assert!(p.remove_standby(&scope(), Slot::B).is_err());
            p.stop(&scope())
                .unwrap_or_else(|e| panic!("attach {name} lost={lost}: {e}"));
        }
    }
}
#[test]
fn all_attach_and_switch_cas_failures_keep_a_cleanup_obligation() {
    for switch in [false, true] {
        let (mut p, s) = if switch { attached() } else { running() };
        let first = s.borrow().saves;
        if switch {
            p.switch(&scope(), p.fence(), Slot::B).unwrap()
        } else {
            p.attach_member(&scope(), p.fence(), &member(Slot::B))
                .unwrap()
        }
        let last = s.borrow().saves;
        drop(p);
        for save in first + 1..=last {
            for lost in [false, true] {
                let (mut p, s) = if switch { attached() } else { running() };
                s.borrow_mut().fail_save = Some((save, lost));
                let result = if switch {
                    p.switch(&scope(), p.fence(), Slot::B)
                } else {
                    p.attach_member(&scope(), p.fence(), &member(Slot::B))
                };
                assert!(result.is_err(), "switch={switch} save={save} lost={lost}");
                assert!(p.cleanup_pending());
                p.stop(&scope())
                    .unwrap_or_else(|e| panic!("switch={switch} CAS={save} lost={lost}: {e}"));
            }
        }
    }
}
#[test]
fn lost_original_base_creation_ack_does_not_learn_priority_from_later_snapshot() {
    let (mut p, s) = pair();
    s.borrow_mut().fail = Some(("bases".into(), true));
    assert!(p
        .start(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .is_err());
    assert!(p.snapshot().guard.assigned_sublayer_weight.is_none());
    let bases = s.borrow().counts["bases"];
    assert!(p.stop(&scope()).is_err());
    assert_eq!(s.borrow().counts["bases"], bases);
    assert_eq!(s.borrow().guard.assigned_sublayer_weight, Some(65531));
    assert!(p.cleanup_pending());
}
#[test]
fn rebind_and_retirement_partial_failures_never_recreate_c_or_resume_after_cleanup() {
    for rebind in [false, true] {
        for name in if rebind {
            vec![
                "withdraw",
                "release-A",
                "rebind",
                "network",
                "hold-A",
                "allows",
                "data",
            ]
        } else {
            vec![
                "withdraw",
                "network",
                "restore-member-weak",
                "stop-B",
                "release-B",
                "bases",
                "restore-member-keys",
                "allows",
                "data",
            ]
        } {
            for lost in [false, true] {
                let (mut p, s) = attached();
                let c = p.snapshot().carrier;
                s.borrow_mut().fail = Some((name.into(), lost));
                let result = if rebind {
                    p.rebind_pair(&scope()).map(|_| ())
                } else {
                    p.remove_standby(&scope(), Slot::B)
                };
                assert!(result.is_err(), "rebind={rebind} {name} {lost}");
                assert_eq!(p.snapshot().carrier, c);
                assert!(p.cleanup_pending());
                p.stop(&scope())
                    .unwrap_or_else(|e| panic!("rebind={rebind} {name} lost={lost}: {e}"));
            }
        }
    }
}

#[test]
fn member_capability_or_native_configuration_rejection_precedes_carrier_creation() {
    let (mut p, s) = pair();
    s.borrow_mut().fail = Some(("prepare-member".into(), false));
    assert!(p
        .start(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .is_err());
    assert!(s.borrow().carrier.is_none());
    assert!(!s.borrow().counts.contains_key("carrier-ready"));
}
#[test]
fn terminal_marker_has_no_live_carrier_or_members() {
    let (mut p, _) = attached();
    p.stop(&scope()).unwrap();
    assert!(p.snapshot().carrier.is_none());
    assert!(p.snapshot().members.iter().all(Option::is_none));
}

#[test]
fn explicit_legacy_decoder_produces_only_legacy_cleanup_not_a_carrier_intent() {
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
    let bytes = serde_json::to_vec(&legacy).unwrap();
    assert!(matches!(
        decode_for_cleanup(&bytes, &scope()).unwrap(),
        CleanupRecord::Legacy(_)
    ));
    assert!(Record::decode(&bytes).is_err());
    let (mut p, _) = running();
    let carrier = p.snapshot().encode().unwrap();
    assert!(matches!(
        decode_for_cleanup(&carrier, &scope()).unwrap(),
        CleanupRecord::Carrier(_)
    ));
    let mut bad = serde_json::to_value(p.snapshot()).unwrap();
    bad["version"] = serde_json::json!(99);
    assert!(decode_for_cleanup(&serde_json::to_vec(&bad).unwrap(), &scope()).is_err());
    let mut stale = scope();
    stale.runtime_generation += 1;
    assert!(decode_for_cleanup(&carrier, &stale).is_err());
    p.stop(&scope()).unwrap();
}

#[test]
fn different_native_backends_share_logical_network_without_recreating_c() {
    let (mut p, s) = running();
    let mut b = member(Slot::B);
    b.configuration = TunnelConfiguration::new(b.configuration.expose().replace(
        "[Interface]\n", "[Interface]\nJc = 3\nJmin = 40\nJmax = 70\nHeaderProtectionKey = synthetic-header\nContentPaddingAddition = 1\n"));
    p.attach_member(&scope(), p.fence(), &b).unwrap();
    assert_ne!(
        p.snapshot().members[0]
            .as_ref()
            .unwrap()
            .owner
            .intent
            .transport,
        p.snapshot().members[1]
            .as_ref()
            .unwrap()
            .owner
            .intent
            .transport
    );
    assert_eq!(s.borrow().counts.get("carrier-ready"), Some(&1));
    p.stop(&scope()).unwrap();
}

#[test]
fn every_live_read_failure_irrevocably_fences_forward_operations() {
    for operation in ["metrics", "fingerprint", "open-probe"] {
        let (mut p, s) = running();
        let fault = match operation {
            "metrics" => "observe",
            "fingerprint" => "fingerprint",
            _ => "held-proof",
        };
        s.borrow_mut().fail = Some((fault.into(), false));
        let result = match operation {
            "metrics" => p.metrics(Slot::A).map(|_| ()),
            "fingerprint" => p.physical_network_fingerprint().map(|_| ()),
            _ => p.open_probe(Slot::A).map(|_| ()),
        };
        assert!(result.is_err(), "{operation}");
        assert!(p.cleanup_pending(), "{operation}");
        let before = s.borrow().events.len();
        assert!(p.sample(Slot::A).is_none(), "{operation}");
        assert!(p.metrics(Slot::A).is_err(), "{operation}");
        assert!(p.physical_network_fingerprint().is_err(), "{operation}");
        assert_eq!(s.borrow().events.len(), before, "{operation}");
        p.stop(&scope()).unwrap();
    }
}

#[test]
fn metrics_and_fingerprint_reject_changed_protected_pair_before_native_reads() {
    for fingerprint in [false, true] {
        let (p, s) = running();
        s.borrow_mut().disk.as_mut().unwrap().revision += 1;
        let before = s.borrow().events.len();
        let result = if fingerprint {
            p.physical_network_fingerprint().map(|_| ())
        } else {
            p.metrics(Slot::A).map(|_| ())
        };
        assert!(result.is_err());
        assert!(p.cleanup_pending());
        assert_eq!(s.borrow().events.len(), before);
    }
}

#[test]
fn inactive_retirement_closes_original_probe_before_weak_restore_and_member_stop() {
    let (mut p, s) = attached();
    let before = s.borrow().events.len();
    p.remove_standby(&scope(), Slot::B).unwrap();
    let events = &s.borrow().events[before..];
    let position = |name: &str| events.iter().position(|e| e == name).unwrap();
    assert!(position("release-B") < position("restore-member-weak"));
    assert!(position("release-B") < position("stop-B"));
    assert!(position("withdraw") < position("release-B"));
    assert!(position("release-B") < position("bases"));
}

#[test]
fn swallowed_borrow_failure_revokes_live_reads_without_closing_native_objects() {
    let (mut p, s) = running();
    let borrowed = p.io.borrow_mut();
    assert!(p.metrics(Slot::A).is_err());
    assert!(p.cleanup_pending());
    drop(borrowed);
    let before = s.borrow().events.len();
    assert!(p.sample(Slot::A).is_none());
    assert_eq!(s.borrow().events.len(), before);
    assert_eq!(s.borrow().held, 1);
    p.stop(&scope()).unwrap();
}
