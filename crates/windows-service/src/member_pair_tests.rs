use super::*;
use nelomai_contracts::RuntimeSlot;
use std::{cell::RefCell, rc::Rc};

#[test]
fn verified_dos_engine_accepts_only_its_canonical_prefix_variant() {
    use std::path::Path;
    let dos = Path::new(r"C:\Program Files\Nelomai\engine.exe");
    let canonical = Path::new(r"\\?\C:\Program Files\Nelomai\engine.exe");
    assert!(canonical_engine_matches(dos, canonical));
    assert!(canonical_engine_matches(canonical, canonical));
    for other in [
        r"C:\Program Files\Other\engine.exe",
        r"D:\Program Files\Nelomai\engine.exe",
        r"C:\Program Files\Nelomai\..\Nelomai\engine.exe",
        r"C:\PROGRA~1\Nelomai\engine.exe",
        r"C:\Program Files\Nelomai\engine.exe:stream",
        r"C:Program Files\Nelomai\engine.exe",
        r"\\server\share\engine.exe",
        r"\\.\C:\Program Files\Nelomai\engine.exe",
    ] {
        assert!(
            !canonical_engine_matches(Path::new(other), canonical),
            "{other}"
        );
    }
}

fn scope() -> SessionScope {
    SessionScope {
        runtime: RuntimeSlot::Stable,
        runtime_generation: 2,
        session_id: "11111111-1111-4111-8111-111111111111".into(),
        connection_generation: 3,
    }
}

#[test]
fn empty_claim_requires_absence_of_every_record_and_native_effect() {
    use crate::member_owner::{Observation, ServiceObservation};
    let empty = Observation {
        config_sha256: None,
        service: None,
        alternative_service_present: false,
        interface: None,
        retained_interfaces: vec![],
    };
    let guard = Model::empty(scope()).unwrap().expected;
    let check = |records, observed: Observation| {
        verify_empty_claim(
            &scope(),
            records,
            |_| Ok((None, observed.clone())),
            || Ok(guard.clone()),
        )
    };
    assert!(check([false; 3], empty.clone()).is_ok());
    for index in 0..3 {
        let mut records = [false; 3];
        records[index] = true;
        assert!(check(records, empty.clone()).is_err());
    }
    let mut present = empty.clone();
    present.config_sha256 = Some([1; 32]);
    assert!(check([false; 3], present).is_err());
    let mut present = empty.clone();
    present.service = Some(ServiceObservation {
        exact_spec: true,
        process: None,
    });
    assert!(check([false; 3], present).is_err());
    let mut present = empty.clone();
    present.alternative_service_present = true;
    assert!(check([false; 3], present).is_err());
    let proof = crate::member_owner::InterfaceProof {
        index: 10,
        luid: 20,
        guid: [1; 16],
    };
    let mut present = empty.clone();
    present.interface = Some(proof);
    assert!(check([false; 3], present).is_err());
    let mut present = empty.clone();
    present.retained_interfaces.push(proof);
    assert!(check([false; 3], present).is_err());
    assert!(verify_empty_claim(
        &scope(),
        [false; 3],
        |_| Err(io::ErrorKind::PermissionDenied.into()),
        || Ok(guard.clone())
    )
    .is_err());
    let mut wrong = guard.clone();
    wrong.scope.connection_generation += 1;
    assert!(verify_empty_claim(
        &scope(),
        [false; 3],
        |_| Ok((None, empty.clone())),
        || Ok(wrong.clone())
    )
    .is_err());
    let saved = Io(Rc::new(RefCell::new(State::default())))
        .prepare_member(&scope(), &member(Slot::A))
        .unwrap()
        .owner;
    assert!(verify_empty_claim(
        &scope(),
        [false; 3],
        |_| Ok((Some(saved.clone()), empty.clone())),
        || Ok(guard.clone())
    )
    .is_err());
}

#[test]
fn empty_claim_rechecks_both_slots_and_guard_before_releasing_authority() {
    let empty = crate::member_owner::Observation {
        config_sha256: None,
        service: None,
        alternative_service_present: false,
        interface: None,
        retained_interfaces: vec![],
    };
    let expected = Model::empty(scope()).unwrap().expected;
    let mut slots = vec![];
    assert!(verify_empty_claim(
        &scope(),
        [false; 3],
        |slot| {
            slots.push(slot);
            if slots.len() == 4 {
                return Err(io::ErrorKind::Interrupted.into());
            }
            Ok((None, empty.clone()))
        },
        || Ok(expected.clone())
    )
    .is_err());
    assert_eq!(slots, [Slot::A, Slot::B, Slot::A, Slot::B]);
    let mut reads = 0;
    assert!(verify_empty_claim(
        &scope(),
        [false; 3],
        |_| Ok((None, empty.clone())),
        || {
            reads += 1;
            if reads == 2 {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            Ok(expected.clone())
        }
    )
    .is_err());
    assert_eq!(reads, 2);
}

#[test]
fn empty_new_claim_preserves_proven_stopped_predecessor_configs() {
    let mut old = Io(Rc::new(RefCell::new(State::default())))
        .prepare_member(&scope(), &member(Slot::A))
        .unwrap()
        .owner;
    old.phase = crate::member_owner::Phase::Stopped;
    old.proof = None;
    old.retired_proof = None;
    old.intent.scope.connection_generation -= 1;
    let check = |foreign: bool| {
        verify_empty_claim(
            &scope(),
            [false; 3],
            |slot| {
                let mut record = old.clone();
                record.intent.slot = slot_native(slot);
                let config = if foreign {
                    [99; 32]
                } else {
                    record.intent.config_sha256
                };
                Ok((
                    Some(record),
                    crate::member_owner::Observation {
                        config_sha256: Some(config),
                        service: None,
                        alternative_service_present: false,
                        interface: None,
                        retained_interfaces: vec![],
                    },
                ))
            },
            || Ok(Model::empty(scope()).unwrap().expected),
        )
    };
    assert!(
        check(false).is_ok(),
        "claim-before-Pair-save must not strand a clean predecessor"
    );
    assert!(check(true).is_err());
}

#[test]
fn terminal_completion_follows_durable_stop_and_failed_ack_is_not_success() {
    use nelomai_client_tunnel::redundancy::session::{SessionPhase, SessionState};
    let mut latch = CompletionState::default();
    let mut state = SessionState::new(scope(), Slot::B, 7, 9).unwrap();
    let events = RefCell::new(vec![]);
    latch
        .save(
            &scope(),
            &state.snapshot(),
            |_| {
                events.borrow_mut().push("save");
                Ok(())
            },
            |_| panic!("running cannot complete"),
        )
        .unwrap();
    state.begin_stop(&scope()).unwrap();
    state.stopped(&scope()).unwrap();
    let stopped = state.snapshot();
    let error = latch
        .save(
            &scope(),
            &stopped,
            |_| Err(io::ErrorKind::WriteZero.into()),
            |_| panic!("failed durable Stop cannot complete"),
        )
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    assert!(latch
        .save(
            &scope(),
            &stopped,
            |_| {
                events.borrow_mut().push("save");
                Ok(())
            },
            |_| {
                events.borrow_mut().push("complete_failed");
                Err(io::ErrorKind::Interrupted.into())
            }
        )
        .is_err());
    latch
        .save(
            &scope(),
            &stopped,
            |_| {
                events.borrow_mut().push("save");
                Ok(())
            },
            |bound| {
                assert_eq!(bound, &scope());
                events.borrow_mut().push("complete");
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(
        *events.borrow(),
        ["save", "save", "complete_failed", "save", "complete"]
    );
    latch
        .save(
            &scope(),
            &stopped,
            |_| panic!("duplicate terminal save must be pure"),
            |_| panic!("duplicate completion must be pure"),
        )
        .unwrap();
    let mut other = stopped.clone();
    other.scope.connection_generation += 1;
    assert!(latch
        .save(
            &scope(),
            &other,
            |_| panic!("wrong scope"),
            |_| panic!("wrong scope")
        )
        .is_err());
    other = stopped;
    other.phase = SessionPhase::Running;
    assert!(latch
        .save(
            &scope(),
            &other,
            |_| panic!("terminal cannot resume"),
            |_| panic!("terminal cannot resume")
        )
        .is_err());
}

#[test]
fn cleanup_terminal_record_covers_pair_before_session_gap_without_start_authority() {
    use nelomai_client_tunnel::redundancy::session::{SessionPhase, SessionState};
    let gap = stopped_after_cleanup(&scope(), None).unwrap();
    assert_eq!(gap.phase, SessionPhase::Stopped);
    assert_eq!(gap.installed, [false; 2]);
    assert_eq!(gap.committed, [false; 2]);
    assert!(!gap.role_confirmed);
    assert_eq!(
        (
            gap.network_epoch,
            gap.role_generation,
            gap.membership_generation
        ),
        (1, 0, 0)
    );
    let old = SessionState::new(scope(), Slot::B, 7, 9)
        .unwrap()
        .snapshot();
    let terminal = stopped_after_cleanup(&scope(), Some(old)).unwrap();
    assert_eq!(terminal.phase, SessionPhase::Stopped);
    assert_eq!(terminal.active, Slot::B);
    assert_eq!(
        (terminal.role_generation, terminal.membership_generation),
        (7, 9)
    );
    let mut other = scope();
    other.connection_generation += 1;
    assert!(stopped_after_cleanup(&other, Some(terminal)).is_err());
}
fn member(slot: Slot) -> Member {
    serde_json::from_value(serde_json::json!({"slot":slot,"lease_id":"22222222-2222-4222-8222-222222222222", "configuration":"[Interface]\nPrivateKey = fake\n[Peer]\n", "probe":{"kind":"dns_a","target_ipv4":"10.0.0.1","query_name":"example.com","timeout_ms":2000}})).unwrap()
}
#[derive(Default)]
struct State {
    events: Vec<String>,
    saved: Option<PairRecord>,
    guard: Option<Model>,
    owners: [Option<OwnerRecord>; 2],
    route_active: Option<Slot>,
    routed_members: [bool; 2],
    fail_routes: bool,
    endpoint_lost: bool,
    fail_save: bool,
    lost_pair_save: bool,
    fail_guard: bool,
    fail_guard_read: bool,
    assigned_weight: Option<u16>,
    fail_guard_ack_save: bool,
    guard_observation: Option<crate::member_guard::Snapshot>,
    fail_permit_close: bool,
    fail_save_on_permit_close: bool,
    guard_observation_on_permit_close: Option<crate::member_guard::Snapshot>,
    fail_cleanup_routes: bool,
    owner_saves: usize,
    fail_owner_save: Option<usize>,
    lost_owner_save: Option<usize>,
}
type Shared = Rc<RefCell<State>>;
struct Disk(Shared);
impl PairStore for Disk {
    fn save(&mut self, r: &PairRecord) -> io::Result<()> {
        let mut s = self.0.borrow_mut();
        if s.fail_save {
            return Err(io::ErrorKind::WriteZero.into());
        }
        s.saved = Some(r.clone());
        s.events.push("save".into());
        if s.lost_pair_save {
            s.lost_pair_save = false;
            return Err(io::ErrorKind::Interrupted.into());
        }
        Ok(())
    }
}
struct Socket(Shared);
impl Drop for Socket {
    fn drop(&mut self) {
        self.0.borrow_mut().events.push("socket_drop".into());
    }
}
impl ProbeDatagram for Socket {
    fn send(&mut self, p: &[u8]) -> io::Result<usize> {
        Ok(p.len())
    }
    fn receive(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
    }
}
impl PairSocket for Socket {
    fn duplicate(&self) -> io::Result<Self> {
        Ok(Self(self.0.clone()))
    }
}
struct Io(Shared);
#[test]
fn scoped_endpoint_loss_rejects_health_and_new_probes_but_allows_cleanup() {
    let (mut p, s) = pair();
    p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    p.attach(&scope(), &member(Slot::B)).unwrap();
    s.borrow_mut().endpoint_lost = true;
    assert!(p.sample(Slot::A).is_none());
    assert!(p.open_probe(Slot::A).is_err());
    p.close(&scope()).unwrap();
    assert!(!p.cleanup_pending());
}
#[test]
fn endpoint_failure_during_activation_never_opens_data_permits() {
    let (mut p, s) = pair();
    s.borrow_mut().endpoint_lost = true;
    assert!(p
        .start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .is_err());
    assert!(s.borrow().guard.as_ref().unwrap().active.is_none());
    assert!(p.sample(Slot::A).is_none());
    p.close(&scope()).unwrap();
    assert!(!p.cleanup_pending());
}
impl PairIo for Io {
    type Socket = Socket;
    fn prepare_member(&mut self, scope: &SessionScope, m: &Member) -> io::Result<MemberRecord> {
        let i = m.slot.idx() as u32 + 10;
        Ok(MemberRecord {
            prior_stopped: None,
            owner: OwnerRecord {
                intent: crate::member_owner::Intent {
                    scope: scope.clone(),
                    slot: slot_native(m.slot),
                    transport: nelomai_client_tunnel::TunnelTransport::WireGuard,
                    engine: crate::test_engine_path("engine.exe"),
                    config_sha256: [1; 32],
                },
                phase: crate::member_owner::Phase::Prepared,
                proof: None,
                retired_proof: None,
                previous_config_sha256: None,
            },
            source: format!("10.0.0.{i}").parse().unwrap(),
            endpoint: "192.0.2.1".parse().unwrap(),
            allowed: vec!["0.0.0.0/0".parse().unwrap()],
            dns: vec![],
            probe: m.probe.clone(),
            peer: [2; 32],
            started_epoch_ms: 1,
        })
    }
    fn start(&mut self, m: &MemberRecord) -> io::Result<OwnerRecord> {
        let mut r = m.owner.clone();
        let i = slot_shared(r.intent.slot).idx();
        assert!(self.0.borrow().saved.as_ref().unwrap().members[i].is_some());
        r.phase = crate::member_owner::Phase::Running;
        r.proof = Some(crate::member_owner::NativeProof {
            process: crate::member_owner::ProcessProof {
                pid: i as u32 + 20,
                creation_time: 30,
            },
            interface: crate::member_owner::InterfaceProof {
                index: i as u32 + 10,
                luid: i as u64 + 40,
                guid: [i as u8 + 1; 16],
            },
        });
        self.0.borrow_mut().owners[i] = Some(r.clone());
        Ok(r)
    }
    fn current(&mut self, slot: Slot) -> io::Result<Option<OwnerRecord>> {
        Ok(self.0.borrow().owners[slot.idx()].clone())
    }
    fn verify(&mut self, m: &MemberRecord) -> io::Result<()> {
        if self.0.borrow().owners[slot_shared(m.owner.intent.slot).idx()].as_ref() == Some(&m.owner)
        {
            Ok(())
        } else {
            Err(failed())
        }
    }
    fn confirm_absent(&mut self, m: &MemberRecord) -> io::Result<bool> {
        Ok(
            self.0.borrow().owners[slot_shared(m.owner.intent.slot).idx()]
                .as_ref()
                .is_some_and(|r| {
                    r.phase == crate::member_owner::Phase::Stopped && r.intent == m.owner.intent
                }),
        )
    }
    fn verify_endpoint(&mut self, m: &MemberRecord) -> io::Result<()> {
        self.verify(m)?;
        if self.0.borrow().endpoint_lost {
            Err(failed())
        } else {
            Ok(())
        }
    }
    fn stop(&mut self, m: &MemberRecord) -> io::Result<OwnerRecord> {
        self.verify(m)?;
        let mut r = m.owner.clone();
        r.phase = crate::member_owner::Phase::Stopped;
        r.retired_proof = r.proof.take();
        self.0.borrow_mut().owners[slot_shared(r.intent.slot).idx()] = Some(r.clone());
        self.0.borrow_mut().events.push("stop".into());
        Ok(r)
    }
    fn rebind(&mut self, m: &MemberRecord) -> io::Result<OwnerRecord> {
        self.verify(m)?;
        Ok(m.owner.clone())
    }
    fn observe(&mut self, m: &MemberRecord) -> io::Result<(TunnelMetrics, NativeHealthSample)> {
        self.verify(m)?;
        Ok((
            TunnelMetrics::default(),
            NativeHealthSample {
                admitted: true,
                closed: false,
                handshake_fresh: true,
                tx_packets: 4,
                rx_data_packets: 3,
            },
        ))
    }
    fn fingerprint(&mut self, _: &[Option<MemberRecord>; 2]) -> io::Result<String> {
        Ok("a".repeat(64))
    }
    fn open_base(&mut self, m: &MemberRecord) -> io::Result<(Socket, ProbeTuple)> {
        self.verify(m)?;
        // WinSock connect on IP_UNICAST_IF requires a route on that member,
        // even though bind and interface ownership already succeeded.
        if !self.0.borrow().routed_members[slot_shared(m.owner.intent.slot).idx()] {
            return Err(io::Error::from_raw_os_error(10051));
        }
        Ok((
            Socket(self.0.clone()),
            ProbeTuple {
                source: m.source.into(),
                source_port: 1234,
                target: m.probe.target_ipv4.into(),
                target_port: 53,
                protocol: 17,
            },
        ))
    }
    fn guard_snapshot(&mut self) -> io::Result<crate::member_guard::Snapshot> {
        if self.0.borrow().fail_guard_read {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if let Some(observed) = &self.0.borrow().guard_observation {
            return Ok(observed.clone());
        }
        Ok(self.0.borrow().guard.as_ref().unwrap().expected.clone())
    }
    fn guard_exchange(&mut self, p: &ExchangePlan) -> io::Result<Model> {
        let mut s = self.0.borrow_mut();
        assert!(s.saved.as_ref().unwrap().pending_guard.is_some());
        assert_eq!(s.guard.as_ref().unwrap().expected, p.expected.expected);
        if s.fail_guard {
            return Err(failed());
        }
        s.events.push(format!("guard:{:?}", p.desired.active));
        let mut actual = p.desired.expected.clone();
        if !p.expected.installed && p.desired.installed {
            if let Some(weight) = s.assigned_weight {
                actual.sublayer.as_mut().unwrap().weight = weight;
            }
        }
        let committed = p
            .desired
            .readback_after(&p.expected, &actual)
            .map_err(|_| failed())?;
        s.guard = Some(committed.clone());
        if s.fail_guard_ack_save {
            s.fail_save = true;
        }
        Ok(committed)
    }
    fn close_permits(&mut self) -> io::Result<()> {
        let mut s = self.0.borrow_mut();
        s.events.push("withdraw".into());
        if s.fail_permit_close {
            return Err(failed());
        }
        s.guard = Some(s.guard.as_ref().unwrap().without_probes().unwrap());
        if s.fail_save_on_permit_close {
            s.fail_save = true;
        }
        if let Some(observation) = s.guard_observation_on_permit_close.take() {
            s.guard_observation = Some(observation);
        }
        Ok(())
    }
    fn select_routes(
        &mut self,
        active: Slot,
        members: &[Option<MemberRecord>; 2],
        _: &DesktopTunnelOptions,
    ) -> io::Result<()> {
        let mut s = self.0.borrow_mut();
        assert_eq!(s.guard.as_ref().unwrap().active, None);
        assert!(s.guard.as_ref().unwrap().installed);
        s.events.push(format!("routes:{active:?}"));
        if s.fail_routes {
            s.fail_routes = false;
            return Err(failed());
        }
        s.route_active = Some(active);
        s.routed_members = members.each_ref().map(Option::is_some);
        Ok(())
    }
    fn cleanup_routes(&mut self) -> io::Result<()> {
        let mut s = self.0.borrow_mut();
        s.events.push("routes_clean".into());
        if s.fail_cleanup_routes {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        s.route_active = None;
        s.routed_members = [false; 2];
        Ok(())
    }
    fn read_dns(&mut self, _: &MemberRecord) -> io::Result<DnsSnapshot> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn exchange_dns(&mut self, _: &DnsSnapshot, _: &DnsSnapshot) -> io::Result<()> {
        panic!("unexpected DNS")
    }
}
fn pair() -> (SessionNativePair<Io, Disk>, Shared) {
    let s = Rc::new(RefCell::new(State::default()));
    s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
    let p = SessionNativePair::new(scope(), Io(s.clone()), Disk(s.clone())).unwrap();
    (p, s)
}

#[test]
fn primary_attach_and_rebind_route_before_connecting_probe_sockets() {
    let (mut p, s) = pair();
    p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    p.attach(&scope(), &member(Slot::B)).unwrap();
    assert_eq!(p.record.active, Some(Slot::A));
    assert!(p.sockets.iter().all(Option::is_some));
    p.rebind_pair(&scope()).unwrap();
    assert_eq!(p.record.active, Some(Slot::A));
    assert!(p.sockets.iter().all(Option::is_some));
    p.close(&scope()).unwrap();
    assert!(p.closed);
    assert_eq!(s.borrow().routed_members, [false; 2]);
    assert!(!s.borrow().guard.as_ref().unwrap().installed);
}

#[test]
fn abort_before_dns_activation_never_reads_or_writes_unmodified_dns() {
    let (mut p, s) = pair();
    let m = member(Slot::A);
    let mut prepared = p.io.borrow_mut().prepare_member(&scope(), &m).unwrap();
    prepared.dns = vec!["9.9.9.9".parse().unwrap()];
    p.record.members[0] = Some(prepared.clone());
    p.save().unwrap();
    p.io.borrow_mut().start(&prepared).unwrap();
    p.refresh(Slot::A).unwrap();
    p.fence().unwrap();
    // No DNS baseline or write happened before a probe-socket failure. This
    // fake rejects DNS access; closing must still stop the owned interface.
    p.close(&scope()).unwrap();
    assert!(p.closed);
    assert_eq!(
        s.borrow().owners[0].as_ref().unwrap().phase,
        crate::member_owner::Phase::Stopped
    );
}

#[test]
fn reincarnation_gate_requires_retired_pair_guard_and_network_evidence() {
    let (mut pair, s) = pair();
    pair.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    pair.attach(&scope(), &member(Slot::B)).unwrap();
    let before = s.borrow().saved.clone().unwrap();
    pair.remove_standby(&scope(), Slot::B).unwrap();
    let clean = s.borrow().saved.clone().unwrap();
    let retired = s.borrow().owners[1].clone().unwrap();
    let guard = s.borrow().guard.as_ref().unwrap().expected.clone();
    assert!(verify_retired_slot(&retired, &clean, &[], &guard).is_ok());
    assert!(verify_retired_slot(&retired, &before, &[], &guard).is_err());
    let proof = retired.retired_proof.unwrap();
    let route = nelomai_client_tunnel::redundancy::network::RouteValue {
        destination: "10.0.0.1/32".parse().unwrap(),
        interface: proof.interface.index,
        scope: nelomai_client_tunnel::redundancy::network::RouteScope::WindowsInterface(
            proof.interface.index,
        ),
        gateway: None,
        metric: 0,
    };
    assert!(verify_retired_slot(&retired, &clean, &[route], &guard).is_err());
    assert!(verify_retired_slot(&retired, &clean, &[], &before.guard.expected).is_err());
    let mut foreign = retired.clone();
    foreign.intent.scope.connection_generation += 1;
    assert!(verify_retired_slot(&foreign, &clean, &[], &guard).is_err());
    let mut pending = clean;
    pending.closing = true;
    assert!(verify_retired_slot(&retired, &pending, &[], &guard).is_err());
}
#[test]
fn guard_precedes_inactive_routes_and_promotion_changes_no_owner() {
    let (mut p, s) = pair();
    p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    p.attach(&scope(), &member(Slot::B)).unwrap();
    s.borrow_mut().events.clear();
    p.select_active(&scope(), Slot::B).unwrap();
    let s = s.borrow();
    let events: Vec<_> = s
        .events
        .iter()
        .filter(|e| e.as_str() != "save")
        .cloned()
        .collect();
    assert_eq!(events, vec!["guard:None", "routes:B", "guard:Some(B)"]);
    assert_eq!(s.route_active, Some(Slot::B));
    assert_eq!(
        s.owners[0].as_ref().unwrap().phase,
        crate::member_owner::Phase::Running
    );
}
#[test]
fn failed_switch_rolls_back_routes_under_guard_before_restoring_old_role() {
    let (mut p, s) = pair();
    p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    p.attach(&scope(), &member(Slot::B)).unwrap();
    s.borrow_mut().events.clear();
    s.borrow_mut().fail_routes = true;
    assert!(p.select_active(&scope(), Slot::B).is_err());
    assert_eq!(s.borrow().route_active, Some(Slot::A));
    assert_eq!(s.borrow().guard.as_ref().unwrap().active, Some(Slot::A));
    assert!(!p.cleanup_pending());
}
#[test]
fn close_withdraws_permits_before_socket_drop_and_closes_routes_before_members() {
    let (mut p, s) = pair();
    p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    s.borrow_mut().events.clear();
    p.close(&scope()).unwrap();
    let s = s.borrow();
    let pos = |e: &str| s.events.iter().position(|v| v == e).unwrap();
    assert!(pos("guard:None") < pos("socket_drop"));
    assert!(pos("routes_clean") < pos("stop"));
}
#[test]
fn repeated_verified_close_needs_no_new_journal_or_native_authority() {
    let (mut p, s) = pair();
    p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    p.close(&scope()).unwrap();
    s.borrow_mut().events.clear();
    s.borrow_mut().fail_save = true;
    p.close(&scope()).unwrap();
    assert!(s.borrow().events.is_empty());
}
#[test]
fn rebind_retries_under_existing_fence_after_transient_route_cleanup_failure() {
    let (mut p, s) = pair();
    p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    s.borrow_mut().fail_cleanup_routes = true;
    assert!(p.rebind_pair(&scope()).is_err());
    assert!(p.open_probe(Slot::A).is_err());
    s.borrow_mut().fail_cleanup_routes = false;
    assert!(p.physical_network_fingerprint().is_err());
    assert!(p.rebind_pair(&scope()).is_err());
    p.check_integrity().unwrap();
    assert!(p.rebind_pair(&scope()).unwrap());
    assert!(p.open_probe(Slot::A).is_ok());
}

#[test]
fn fenced_discovery_requires_exact_installed_permit_free_guard() {
    for mutation in 0..6 {
        let (mut p, s) = pair();
        p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
            .unwrap();
        let running = p.record.guard.clone();
        s.borrow_mut().fail_cleanup_routes = true;
        assert!(p.rebind_pair(&scope()).is_err());
        s.borrow_mut().fail_cleanup_routes = false;
        p.check_integrity().unwrap();
        assert!(p.physical_network_fingerprint().is_ok());
        match mutation {
            0 => s.borrow_mut().guard = Some(Model::empty(scope()).unwrap()),
            1 => s.borrow_mut().guard = Some(running.clone()),
            2 => s.borrow_mut().fail_guard_read = true,
            3 => {
                p.record.pending_guard = Some(ExchangePlan::new(&p.record.guard, &running).unwrap())
            }
            4 => {
                // Even exact readback of a model with dynamic probe permits is
                // not an acknowledged blocking fence eligible for recovery.
                p.record.guard = Model::new(scope(), running.members.clone(), None).unwrap();
                s.borrow_mut().guard = Some(p.record.guard.clone());
            }
            _ => {
                p.record.guard = Model::empty(scope()).unwrap();
                s.borrow_mut().guard = Some(p.record.guard.clone());
            }
        }
        s.borrow_mut().events.clear();
        assert!(p.physical_network_fingerprint().is_err());
        assert!(s.borrow().events.is_empty());
    }
}
#[test]
fn scope_mismatch_and_durable_failure_prevent_native_effects() {
    let (mut p, s) = pair();
    let mut wrong = scope();
    wrong.connection_generation += 1;
    assert!(p
        .start_primary(&wrong, &member(Slot::A), &DesktopTunnelOptions::default())
        .is_err());
    s.borrow_mut().fail_save = true;
    assert!(p
        .start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .is_err());
    assert!(s.borrow().owners.iter().all(Option::is_none));
}
#[test]
fn native_parameters_are_literal_bounded_and_reject_duplicate_or_ipv6_dns() {
    let config="[Interface]\nPrivateKey = secret\nAddress = 10.2.0.2/32\nDNS = 9.9.9.9\n[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nEndpoint = 192.0.2.5:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n";
    let p = MemberParameters::parse(config).unwrap();
    assert_eq!(p.peer, [1; 32]);
    assert_eq!(p.source, Ipv4Addr::new(10, 2, 0, 2));
    assert_eq!(p.allowed.len(), 2);
    assert!(MemberParameters::parse(&config.replace("9.9.9.9", "2001:db8::53")).is_err());
    assert!(
        MemberParameters::parse(&config.replace("192.0.2.5:51820", "host.example:51820")).is_err()
    );
    assert!(MemberParameters::parse(&format!("{config}Endpoint = 192.0.2.6:5\n")).is_err());
}
#[test]
fn missing_guard_fences_probe_and_health_even_when_old_route_role_is_running() {
    let (mut p, s) = pair();
    p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
    assert!(p.open_probe(Slot::A).is_err());
    assert!(p.sample(Slot::A).is_none());
}

#[test]
fn native_guard_loss_or_unreadable_snapshot_closes_both_without_gui_and_never_reinstalls() {
    for unreadable in [false, true] {
        let (mut pair, s) = pair();
        pair.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
            .unwrap();
        pair.attach(&scope(), &member(Slot::B)).unwrap();
        s.borrow_mut().events.clear();
        if unreadable {
            s.borrow_mut().fail_guard_read = true;
        } else {
            s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
        }
        assert!(pair.sample(Slot::A).is_none());
        assert!(s
            .borrow()
            .owners
            .iter()
            .flatten()
            .all(|r| r.phase == crate::member_owner::Phase::Stopped));
        assert!(pair.cleanup_pending());
        assert!(pair.sample(Slot::B).is_none());
        assert!(pair.attach(&scope(), &member(Slot::B)).is_err());
        assert!(!s.borrow().events.iter().any(|e| e.starts_with("guard:")));
    }
}
#[test]
fn guard_failure_never_publishes_inactive_routes_or_drops_exclusive_socket() {
    let (mut p, s) = pair();
    p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    s.borrow_mut().events.clear();
    s.borrow_mut().fail_guard = true;
    assert!(p.attach(&scope(), &member(Slot::B)).is_err());
    assert!(p.cleanup_pending());
    assert!(!s.borrow().events.iter().any(|e| e.starts_with("routes:")));
    assert!(!s.borrow().events.iter().any(|e| e == "socket_drop"));
}
#[test]
fn unconfirmed_permit_removal_keeps_exclusive_socket_reserved_on_drop() {
    let (mut p, s) = pair();
    p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    s.borrow_mut().events.clear();
    s.borrow_mut().fail_permit_close = true;
    drop(p);
    assert!(s.borrow().events.contains(&"withdraw".into()));
    assert!(!s.borrow().events.contains(&"socket_drop".into()));
}
#[test]
fn assigned_sublayer_weight_failed_pin_save_cannot_relearn_changed_weight() {
    let (mut p, s) = pair();
    s.borrow_mut().assigned_weight = Some(32771);
    s.borrow_mut().fail_guard_ack_save = true;
    let desired = Model::new(
        scope(),
        [
            Some(crate::member_guard::Member {
                interface: crate::member_guard::Interface {
                    index: 73,
                    luid: 14918723538255872,
                },
                probes: vec![],
            }),
            None,
        ],
        None,
    )
    .unwrap();
    assert!(p.guard(desired).is_err());
    assert!(s.borrow().saved.as_ref().unwrap().pending_guard.is_some());
    assert!(
        p.cleanup_pending(),
        "an unacknowledged pin is still pending work"
    );
    s.borrow_mut().fail_save = false;
    let mut changed = s.borrow().guard.as_ref().unwrap().expected.clone();
    changed.sublayer.as_mut().unwrap().weight = 32772;
    s.borrow_mut().guard_observation = Some(changed);
    assert!(
        p.reconcile_guard().is_err(),
        "a failed durable save must not forget the observed assignment"
    );
}

#[test]
fn assigned_sublayer_weight_survives_roles_and_restart_cleanup() {
    let (mut p, s) = pair();
    s.borrow_mut().assigned_weight = Some(32771);
    p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    p.attach(&scope(), &member(Slot::B)).unwrap();
    p.select_active(&scope(), Slot::B).unwrap();
    let record: PairRecord =
        serde_json::from_slice(&serde_json::to_vec(s.borrow().saved.as_ref().unwrap()).unwrap())
            .unwrap();
    assert_eq!(record.guard.assigned_sublayer_weight, Some(32771));
    assert_eq!(
        record.guard.expected.sublayer.as_ref().unwrap().weight,
        32771
    );
    record.guard.validate().unwrap();
    drop(p);
    let mut recovered =
        SessionNativePair::recover_for_cleanup(scope(), Io(s.clone()), Disk(s.clone()), record)
            .unwrap();
    recovered.close(&scope()).unwrap();
    let saved = s.borrow().saved.clone().unwrap();
    assert!(!saved.guard.installed);
    assert_eq!(saved.guard.assigned_sublayer_weight, None);
    assert!(saved.pending_guard.is_none());
}

#[test]
fn guard_acknowledges_desired_members_even_when_native_snapshot_is_unchanged() {
    let (mut p, _) = pair();
    p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    // Active members have no guard filters. Removing this member from the
    // policy must still acknowledge its new model, even with identical WFP rows.
    let desired = Model::new(scope(), [None, None], None).unwrap();
    p.guard(desired).unwrap();
    assert!(p.record.guard.members.iter().all(Option::is_none));
    assert_eq!(p.record.guard.active, None);
}

#[test]
fn assigned_sublayer_weight_legacy_committed_pending_is_recovered_and_saved() {
    let (mut p, s) = pair();
    let desired = Model::new(
        scope(),
        [
            Some(crate::member_guard::Member {
                interface: crate::member_guard::Interface {
                    index: 73,
                    luid: 14918723538255872,
                },
                probes: vec![],
            }),
            None,
        ],
        None,
    )
    .unwrap();
    p.record.pending_guard = Some(ExchangePlan::new(&p.record.guard, &desired).unwrap());
    p.save().unwrap();
    let legacy = serde_json::to_value(&p.record).unwrap();
    for model in [
        &legacy["guard"],
        &legacy["pending_guard"]["expected"],
        &legacy["pending_guard"]["withdrawn"],
        &legacy["pending_guard"]["base"],
        &legacy["pending_guard"]["desired"],
    ] {
        assert!(model
            .as_object()
            .unwrap()
            .get("assigned_sublayer_weight")
            .is_none());
    }
    let record: PairRecord = serde_json::from_value(legacy).unwrap();
    drop(p);
    let mut actual = desired.expected.clone();
    actual.sublayer.as_mut().unwrap().weight = 32771;
    s.borrow_mut().guard_observation = Some(actual.clone());
    let mut recovered =
        SessionNativePair::recover_for_cleanup(scope(), Io(s.clone()), Disk(s.clone()), record)
            .unwrap();
    recovered.reconcile_guard().unwrap();
    let saved = s.borrow().saved.clone().unwrap();
    assert!(saved.pending_guard.is_none());
    assert_eq!(saved.guard.expected, actual);
    saved.guard.validate().unwrap();
    assert_eq!(saved.guard.assigned_sublayer_weight, Some(32771));
    let pinned: PairRecord = serde_json::from_slice(&serde_json::to_vec(&saved).unwrap()).unwrap();
    let mut forged = pinned.clone();
    forged.pending_guard =
        Some(ExchangePlan::new(&Model::empty(scope()).unwrap(), &desired).unwrap());
    assert!(SessionNativePair::recover_for_cleanup(
        scope(),
        Io(s.clone()),
        Disk(s.clone()),
        forged
    )
    .is_err());
    s.borrow_mut().guard = Some(saved.guard);
    s.borrow_mut().guard_observation = None;
    drop(recovered);
    let mut restarted =
        SessionNativePair::recover_for_cleanup(scope(), Io(s.clone()), Disk(s.clone()), pinned)
            .unwrap();
    let mut changed = actual.clone();
    changed.sublayer.as_mut().unwrap().weight = 32772;
    s.borrow_mut().guard_observation = Some(changed);
    assert!(restarted.reconcile_guard().is_err());
    s.borrow_mut().guard_observation = None;
    restarted.close(&scope()).unwrap();
    let final_record = s.borrow().saved.clone().unwrap();
    assert_eq!(final_record.guard, Model::empty(scope()).unwrap());
    assert!(final_record.pending_guard.is_none());
    assert!(s
        .borrow()
        .guard
        .as_ref()
        .unwrap()
        .expected
        .filters
        .is_empty());
}

#[test]
fn recovery_accepts_only_exact_dynamic_withdrawal_and_is_cleanup_only() {
    let (mut p, s) = pair();
    p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    let record = s.borrow().saved.clone().unwrap();
    drop(p);
    s.borrow_mut().events.clear();
    let mut recovered =
        SessionNativePair::recover_for_cleanup(scope(), Io(s.clone()), Disk(s.clone()), record)
            .unwrap();
    assert!(recovered.sample(Slot::A).is_none());
    assert!(recovered
        .start_primary(&scope(), &member(Slot::B), &DesktopTunnelOptions::default())
        .is_err());
    recovered.close(&scope()).unwrap();
    assert_eq!(s.borrow().route_active, None);
    assert_eq!(
        s.borrow().owners[0].as_ref().unwrap().phase,
        crate::member_owner::Phase::Stopped
    );
}

fn pair_after_failed_guard_ack_stop() -> (SessionNativePair<Io, Disk>, Shared) {
    let (mut p, s) = pair();
    s.borrow_mut().assigned_weight = Some(32771);
    p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    p.attach(&scope(), &member(Slot::B)).unwrap();
    p.fence().unwrap();
    s.borrow_mut().fail_guard_ack_save = true;
    assert!(p.guard(p.model(Some(Slot::A), true).unwrap()).is_err());
    assert!(p.guard_save_pending);
    assert_eq!(
        p.close(&scope()).unwrap_err().kind(),
        io::ErrorKind::WriteZero
    );
    assert!(p.cleanup_pending());
    s.borrow_mut().fail_save = false;
    s.borrow_mut().fail_guard_ack_save = false;
    (p, s)
}

#[test]
fn stop_retry_after_guard_ack_save_failure_completes_without_restart() {
    let (mut p, s) = pair_after_failed_guard_ack_stop();
    p.close(&scope()).unwrap();
    assert!(!p.cleanup_pending());
    assert!(s
        .borrow()
        .saved
        .as_ref()
        .unwrap()
        .members
        .iter()
        .all(Option::is_none));
    assert_eq!(
        s.borrow().saved.as_ref().unwrap().guard,
        Model::empty(scope()).unwrap()
    );
    assert_eq!(s.borrow().route_active, None);
    assert!(s
        .borrow()
        .owners
        .iter()
        .flatten()
        .all(|m| m.phase == crate::member_owner::Phase::Stopped));
    p.close(&scope()).unwrap();
}

#[test]
fn stop_retry_rejects_changed_withdrawn_guard_until_exact_snapshot_returns() {
    let (mut p, s) = pair_after_failed_guard_ack_stop();
    let mut changed = s.borrow().guard.as_ref().unwrap().expected.clone();
    changed.sublayer.as_mut().unwrap().weight = 32772;
    s.borrow_mut().guard_observation = Some(changed);
    s.borrow_mut().events.clear();
    assert!(p.close(&scope()).is_err());
    assert!(p.cleanup_pending());
    assert!(!s.borrow().events.iter().any(|e| e.starts_with("guard:")));
    s.borrow_mut().guard_observation = None;
    p.close(&scope()).unwrap();
    assert!(!p.cleanup_pending());
}

#[test]
fn stop_retry_requires_confirmed_own_dynamic_session_close() {
    let (mut p, s) = pair_after_failed_guard_ack_stop();
    s.borrow_mut().fail_permit_close = true;
    assert!(p.close(&scope()).is_err());
    assert!(p.cleanup_pending());
    s.borrow_mut().fail_permit_close = false;
    p.close(&scope()).unwrap();
    assert!(!p.cleanup_pending());
}

#[test]
fn active_pair_does_not_adopt_exact_dynamic_withdrawal() {
    let (mut p, s) = pair();
    p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    p.attach(&scope(), &member(Slot::B)).unwrap();
    Io(s.clone()).close_permits().unwrap();
    assert!(p.reconcile_guard().is_err());
    assert!(p.open_probe(Slot::A).is_err());
    assert!(p.sample(Slot::A).is_none());
}

#[test]
fn stop_retry_rereads_exact_guard_after_own_session_close() {
    let (mut p, s) = pair_after_failed_guard_ack_stop();
    let mut changed = s.borrow().guard.as_ref().unwrap().expected.clone();
    changed.sublayer.as_mut().unwrap().weight = 32772;
    s.borrow_mut().guard_observation_on_permit_close = Some(changed);
    s.borrow_mut().events.clear();
    assert!(p.close(&scope()).is_err());
    assert!(p.cleanup_pending());
    assert!(!s.borrow().events.iter().any(|e| e.starts_with("guard:")));
    s.borrow_mut().guard_observation = None;
    p.close(&scope()).unwrap();
    assert!(!p.cleanup_pending());
}

#[test]
fn stop_retry_persists_withdrawal_before_further_guard_changes() {
    let (mut p, s) = pair_after_failed_guard_ack_stop();
    s.borrow_mut().fail_save_on_permit_close = true;
    s.borrow_mut().events.clear();
    assert_eq!(
        p.close(&scope()).unwrap_err().kind(),
        io::ErrorKind::WriteZero
    );
    assert!(p.cleanup_pending());
    assert!(p.guard_save_pending);
    assert!(!s.borrow().events.iter().any(|e| e.starts_with("guard:")));
    s.borrow_mut().fail_save_on_permit_close = false;
    s.borrow_mut().fail_save = false;
    p.close(&scope()).unwrap();
    assert!(!p.cleanup_pending());
}

#[test]
fn diagnostics_follow_promoted_active_and_stopping_rejects_reads() {
    let (mut p, s) = pair();
    p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    p.attach(&scope(), &member(Slot::B)).unwrap();
    p.select_active(&scope(), Slot::B).unwrap();
    assert!(p.metrics(Slot::A).is_err());
    assert!(p.metrics(Slot::B).is_ok());
    s.borrow_mut().fail_guard = true;
    assert!(p.close(&scope()).is_err());
    assert!(p.metrics(Slot::B).is_err());
    assert!(p.physical_network_fingerprint().is_err());
}
#[test]
fn disk_failure_stop_still_cuts_both_native_members_and_retains_first_error() {
    let (mut p, s) = pair();
    p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    p.attach(&scope(), &member(Slot::B)).unwrap();
    s.borrow_mut().fail_save = true;
    s.borrow_mut().fail_cleanup_routes = true;
    assert_eq!(
        p.close(&scope()).unwrap_err().kind(),
        io::ErrorKind::WriteZero
    );
    assert!(s
        .borrow()
        .owners
        .iter()
        .flatten()
        .all(|m| m.phase == crate::member_owner::Phase::Stopped));
    assert!(p.cleanup_pending());
    assert!(p.record.members.iter().all(Option::is_some));
}
#[test]
fn route_or_dns_cleanup_error_never_prevents_both_native_stops() {
    for dns in [false, true] {
        let (mut p, s) = pair();
        p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
            .unwrap();
        p.attach(&scope(), &member(Slot::B)).unwrap();
        if dns {
            let m = p.record.members[0].as_mut().unwrap();
            m.dns.push("9.9.9.9".parse().unwrap());
            let interface = m.owner.proof.unwrap().interface;
            let baseline = DnsSnapshot {
                interface: crate::member_dns::OwnedInterface {
                    scope: scope(),
                    guid: interface.guid,
                    luid: interface.luid,
                    index: interface.index,
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
            // Restoration is required only after a baseline was journaled.
            p.record.dns[0] = Some(DnsRecord {
                current: baseline.with_servers(&m.dns).unwrap(),
                baseline,
                pending: None,
            });
        } else {
            s.borrow_mut().fail_cleanup_routes = true;
        }
        assert!(p.close(&scope()).is_err());
        assert!(s
            .borrow()
            .owners
            .iter()
            .flatten()
            .all(|m| m.phase == crate::member_owner::Phase::Stopped));
        assert!(p.cleanup_pending());
        s.borrow_mut().fail_cleanup_routes = false;
        p.close(&scope()).unwrap();
        assert!(!p.cleanup_pending());
    }
}
#[test]
fn failed_reserve_route_cleanup_restores_healthy_primary_and_can_retry() {
    let (mut p, s) = pair();
    p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    p.attach(&scope(), &member(Slot::B)).unwrap();
    s.borrow_mut().fail_routes = true;
    assert!(p.remove_standby(&scope(), Slot::B).is_err());
    assert_eq!(s.borrow().guard.as_ref().unwrap().active, Some(Slot::A));
    assert_eq!(s.borrow().route_active, Some(Slot::A));
    assert!(p.metrics(Slot::A).is_ok());
    p.remove_standby(&scope(), Slot::B).unwrap();
    assert_eq!(
        s.borrow().owners[1].as_ref().unwrap().phase,
        crate::member_owner::Phase::Stopped
    );
    assert!(p.metrics(Slot::A).is_ok());
}

// Real MemberOwner + real SessionNativePair. Only file CAS / SCM / interface
// reads are faked; retained journals and configs survive new owners and pairs.
mod retained_owner_seam {
    use super::*;
    use crate::member_owner::{self as owner, Journal, MemberIo, MemberOwner};
    #[test]
    fn actor_rebind_errors_retry_proven_owners_or_signal_terminal_recovery() {
        use crate::{member_actor::CompositeBackend, ServiceTunnelBackend};
        use nelomai_client_tunnel::redundancy::{protocol::Command, session::SessionPhase};
        let mut failures = Vec::new();
        for (fault, terminal) in [
            ("none", false),
            ("routes", false),
            ("pair_journal", false),
            ("pair_journal_persistent", true),
            ("pair_journal_lost_ack", false),
            ("guard", false),
            ("native_rebind", true),
            ("native_rebind_lost_ack", true),
            ("owner_prepared_save", false),
            ("owner_running_save", true),
            ("owner_running_lost_ack", false),
            ("reserve_prepared_save", false),
            ("reserve_running_save", true),
            ("reserve_running_lost_ack", false),
        ] {
            let s = Rc::new(RefCell::new(State::default()));
            let native = Rc::new(RefCell::new(Native {
                answer_queries: true,
                dns_enabled: true,
                ..Default::default()
            }));
            s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
            let mut actor = CompositeBackend::new(
                RuntimeSlot::Stable,
                NoSingle,
                PhysicalFactory(s.clone(), native.clone()),
            )
            .unwrap();
            actor
                .redundant(Command::Start {
                    scope: scope(),
                    primary: member(Slot::A),
                    role_generation: 0,
                    membership_generation: 0,
                    warm_stop_v1: true,
                    options: DesktopTunnelOptions::default(),
                })
                .unwrap();
            let with_reserve = fault.starts_with("reserve_");
            if with_reserve {
                let snapshot = actor.current_redundancy_snapshot().unwrap();
                let mut reserve = member(Slot::B);
                reserve.lease_id = "33333333-3333-4333-8333-333333333333".into();
                actor
                    .redundant(Command::Attach {
                        scope: scope(),
                        member: reserve,
                        expected_revision: snapshot.session.local_revision,
                        expected_network_epoch: snapshot.session.network_epoch,
                        expected_membership_generation: 0,
                        membership_generation: 0,
                    })
                    .unwrap();
            }
            for now in (0..=2000).step_by(100) {
                actor.tick(now).unwrap();
            }
            assert!(actor.current_redundancy_snapshot().unwrap().primary_ready);
            let owner_saves = s.borrow().owner_saves;
            match fault {
                "routes" => s.borrow_mut().fail_cleanup_routes = true,
                "pair_journal" | "pair_journal_persistent" => s.borrow_mut().fail_save = true,
                "pair_journal_lost_ack" => s.borrow_mut().lost_pair_save = true,
                "guard" => s.borrow_mut().fail_guard = true,
                "native_rebind" => native.borrow_mut().fail_rebind = true,
                "native_rebind_lost_ack" => native.borrow_mut().lost_rebind = true,
                "owner_prepared_save" => s.borrow_mut().fail_owner_save = Some(owner_saves + 1),
                "owner_running_save" => s.borrow_mut().fail_owner_save = Some(owner_saves + 2),
                "owner_running_lost_ack" => s.borrow_mut().lost_owner_save = Some(owner_saves + 2),
                "reserve_prepared_save" => s.borrow_mut().fail_owner_save = Some(owner_saves + 3),
                "reserve_running_save" => s.borrow_mut().fail_owner_save = Some(owner_saves + 4),
                "reserve_running_lost_ack" => {
                    s.borrow_mut().lost_owner_save = Some(owner_saves + 4)
                }
                _ => (),
            }
            let initial = actor.redundant(Command::NetworkChanged { scope: scope() });
            assert_eq!(
                initial.is_err(),
                fault != "none",
                "fault not reached: {fault}"
            );
            if fault == "pair_journal_persistent" {
                assert!(actor.tick(2100).is_err());
                let snapshot = actor.current_redundancy_snapshot().unwrap();
                assert_eq!(snapshot.session.phase, SessionPhase::Stopping);
                assert!(snapshot.stalled && snapshot.cleanup_pending && !snapshot.primary_ready);
                assert_eq!(native.borrow().live, [None, None]);
                s.borrow_mut().fail_save = false;
                // Core's existing exact recovery-stop path can complete the
                // retained cleanup once storage is available; no new Start.
                actor
                    .redundant(Command::PrepareRecoveryStop {
                        scope: scope(),
                        expected_revision: snapshot.session.local_revision,
                        expected_network_epoch: snapshot.session.network_epoch,
                    })
                    .unwrap();
                actor.redundant(Command::Stop { scope: scope() }).unwrap();
            }
            s.borrow_mut().fail_cleanup_routes = false;
            s.borrow_mut().fail_save = false;
            s.borrow_mut().fail_guard = false;
            s.borrow_mut().fail_owner_save = None;
            s.borrow_mut().lost_owner_save = None;
            native.borrow_mut().fail_rebind = false;
            native.borrow_mut().lost_rebind = false;
            for now in (2100..=12000).step_by(100) {
                let _ = actor.tick(now);
            }
            let snapshot = actor.current_redundancy_snapshot().unwrap();
            let expected = if terminal {
                snapshot.session.phase == SessionPhase::Stopped
                    && snapshot.stalled
                    && !snapshot.primary_ready
                    && !snapshot.cleanup_pending
                    && native.borrow().live == [None, None]
                    && s.borrow().guard.as_ref().unwrap() == &Model::empty(scope()).unwrap()
            } else {
                snapshot.session.phase == SessionPhase::Running
                    && !snapshot.stalled
                    && snapshot.primary_ready
                    && !snapshot.cleanup_pending
                    && native.borrow().live[0].is_some()
                    && s.borrow().guard.as_ref().unwrap().active == Some(Slot::A)
            };
            if !expected {
                failures.push(format!("{fault}: {snapshot:?}"));
            }
            assert_eq!(
                native.borrow().starts,
                [1, u64::from(with_reserve)],
                "must not create new native owners: {fault}"
            );
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
    #[test]
    fn rebind_failure_reconciliation_preserves_foreign_member_and_cleanup_journal() {
        for mutation in 0..3 {
            let s = Rc::new(RefCell::new(State::default()));
            let native = Rc::new(RefCell::new(Native::default()));
            s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
            let mut pair = SessionNativePair::new(
                scope(),
                RetainedIo::new(s.clone(), native.clone()),
                Disk(s.clone()),
            )
            .unwrap();
            pair.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
                .unwrap();
            pair.attach(&scope(), &member(Slot::B)).unwrap();
            let retained = pair.record.members[1].as_ref().unwrap().owner.clone();
            s.borrow_mut().fail_cleanup_routes = true;
            assert!(pair.rebind_pair(&scope()).is_err());
            s.borrow_mut().fail_cleanup_routes = false;
            match mutation {
                0 => {
                    native.borrow_mut().live[1]
                        .as_mut()
                        .unwrap()
                        .process
                        .creation_time += 100
                }
                1 => native.borrow_mut().configs[1] = Some([99; 32]),
                _ => {
                    s.borrow_mut().owners[1]
                        .as_mut()
                        .unwrap()
                        .intent
                        .scope
                        .connection_generation += 1
                }
            }
            let foreign = native.borrow().live[1];
            assert!(pair.check_integrity().is_err());
            assert!(pair.cleanup_pending());
            assert_eq!(native.borrow().live, [None, foreign]);
            assert_eq!(pair.record.members[1].as_ref().unwrap().owner, retained);
            assert_eq!(
                s.borrow().saved.as_ref().unwrap().members[1]
                    .as_ref()
                    .unwrap()
                    .owner,
                retained
            );
            assert!(pair.physical_network_fingerprint().is_err());
            assert!(pair.rebind_pair(&scope()).is_err());
            assert_eq!(native.borrow().starts, [1, 1]);
        }
    }
    #[test]
    fn actor_retries_rebind_after_transient_cleanup_failure() {
        use crate::{member_actor::CompositeBackend, ServiceTunnelBackend};
        use nelomai_client_tunnel::redundancy::protocol::Command;
        let s = Rc::new(RefCell::new(State::default()));
        let native = Rc::new(RefCell::new(Native {
            answer_queries: true,
            dns_enabled: true,
            ..Default::default()
        }));
        s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
        let mut actor = CompositeBackend::new(
            RuntimeSlot::Stable,
            NoSingle,
            PhysicalFactory(s.clone(), native.clone()),
        )
        .unwrap();
        actor
            .redundant(Command::Start {
                scope: scope(),
                primary: member(Slot::A),
                role_generation: 0,
                membership_generation: 0,
                warm_stop_v1: true,
                options: DesktopTunnelOptions::default(),
            })
            .unwrap();
        for now in (0..=2000).step_by(100) {
            actor.tick(now).unwrap();
        }
        assert!(actor.current_redundancy_snapshot().unwrap().primary_ready);
        s.borrow_mut().fail_cleanup_routes = true;
        assert!(actor
            .redundant(Command::NetworkChanged { scope: scope() })
            .is_err());
        s.borrow_mut().fail_cleanup_routes = false;
        s.borrow_mut().events.clear();
        for now in (2100..=10000).step_by(100) {
            actor.tick(now).unwrap();
        }
        let final_state = actor.current_redundancy_snapshot().unwrap();
        assert!(native.borrow().live[0].is_some());
        assert!(
            final_state.primary_ready,
            "state={final_state:?}, retry_events={:?}",
            s.borrow().events
        );
        assert!(s.borrow().events.iter().any(|e| e == "routes_clean"));
        assert_eq!(s.borrow().guard.as_ref().unwrap().active, Some(Slot::A));
        assert!(!final_state.cleanup_pending);
        assert_eq!(native.borrow().starts, [1, 0]);
    }
    #[test]
    fn network_change_before_failed_reserve_retirement_recovers_health() {
        use crate::{member_actor::CompositeBackend, ServiceTunnelBackend};
        use nelomai_client_tunnel::redundancy::{protocol::Command, session::SessionPhase};
        // Healthy control, absent SCM, stopped SCM, route failure after owned
        // retirement, and transient failure while retiring the stopped SCM.
        for (crash, stopped_service, failure) in [
            (false, false, 0),
            (true, false, 0),
            (true, true, 0),
            (true, true, 1),
            (true, true, 2),
        ] {
            let s = Rc::new(RefCell::new(State::default()));
            let native = Rc::new(RefCell::new(Native {
                answer_queries: true,
                dns_enabled: true,
                ..Default::default()
            }));
            s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
            let mut actor = CompositeBackend::new(
                RuntimeSlot::Stable,
                NoSingle,
                PhysicalFactory(s.clone(), native.clone()),
            )
            .unwrap();
            actor
                .redundant(Command::Start {
                    scope: scope(),
                    primary: member(Slot::A),
                    role_generation: 0,
                    membership_generation: 0,
                    warm_stop_v1: true,
                    options: DesktopTunnelOptions::default(),
                })
                .unwrap();
            let snapshot = actor.current_redundancy_snapshot().unwrap();
            let mut reserve = member(Slot::B);
            reserve.lease_id = "33333333-3333-4333-8333-333333333333".into();
            actor
                .redundant(Command::Attach {
                    scope: scope(),
                    member: reserve,
                    expected_revision: snapshot.session.local_revision,
                    expected_network_epoch: snapshot.session.network_epoch,
                    expected_membership_generation: 0,
                    membership_generation: 0,
                })
                .unwrap();
            for now in (0..=2000).step_by(100) {
                actor.tick(now).unwrap();
            }
            assert!(actor.current_redundancy_snapshot().unwrap().primary_ready);
            if crash {
                native.borrow_mut().live[1] = None;
                native.borrow_mut().dns[1] = None;
                native.borrow_mut().stopped_service[1] = stopped_service;
            }
            s.borrow_mut().fail_cleanup_routes = failure == 1;
            native.borrow_mut().fail_stopped_cleanup = failure == 2;
            let initial = actor.redundant(Command::NetworkChanged { scope: scope() });
            if failure == 0 {
                initial.unwrap();
            } else {
                assert!(initial.is_err());
                assert!(!actor.current_redundancy_snapshot().unwrap().primary_ready);
                assert_eq!(s.borrow().guard.as_ref().unwrap().active, None);
            }
            s.borrow_mut().fail_cleanup_routes = false;
            native.borrow_mut().fail_stopped_cleanup = false;
            for now in (2100..=10000).step_by(100) {
                actor.tick(now).unwrap();
            }
            let final_state = actor.current_redundancy_snapshot().unwrap();
            assert_eq!(final_state.session.phase, SessionPhase::Running);
            assert!(native.borrow().live[0].is_some());
            assert!(
                final_state.primary_ready,
                "crash={crash}, stopped_service={stopped_service}, failure={failure}, state={final_state:?}"
            );
            assert_eq!(native.borrow().starts, [1, 1]);
            assert_eq!(s.borrow().guard.as_ref().unwrap().active, Some(Slot::A));
            assert!(!final_state.cleanup_pending);
            if crash {
                assert!(final_state.standby_failed);
                assert!(native.borrow().live[1].is_none());
                assert!(!native.borrow().stopped_service[1]);
                assert_eq!(
                    s.borrow().owners[1].as_ref().unwrap().phase,
                    owner::Phase::Stopped
                );
                assert!(s.borrow().saved.as_ref().unwrap().dns[1].is_none());
            }
        }
    }
    #[test]
    fn absent_standby_cleanup_preserves_primary_and_allows_replacement() {
        for stopped_service in [false, true] {
            let s = Rc::new(RefCell::new(State::default()));
            let native = Rc::new(RefCell::new(Native {
                dns_enabled: true,
                ..Default::default()
            }));
            s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
            let mut p = SessionNativePair::new(
                scope(),
                RetainedIo::new(s.clone(), native.clone()),
                Disk(s.clone()),
            )
            .unwrap();
            p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
                .unwrap();
            p.attach(&scope(), &member(Slot::B)).unwrap();
            let primary = native.borrow().live[0];
            native.borrow_mut().live[1] = None;
            native.borrow_mut().dns[1] = None;
            native.borrow_mut().stopped_service[1] = stopped_service;
            s.borrow_mut().events.clear();
            let result = p.remove_standby(&scope(), Slot::B);
            assert_eq!(
                native.borrow().live[0],
                primary,
                "healthy primary stopped: {result:?}"
            );
            result.unwrap();
            assert!(!p.cleanup_pending());
            assert!(p.record.members[1].is_none());
            assert_eq!(p.record.active, Some(Slot::A));
            assert_eq!(s.borrow().route_active, Some(Slot::A));
            assert!(!s.borrow().events.iter().any(|e| e == "dns:B"));
            assert_eq!(
                native.borrow().dns[0]
                    .as_ref()
                    .unwrap()
                    .settings
                    .name_server
                    .as_deref(),
                Some("9.9.9.9")
            );
            let guard = s.borrow().guard.clone().unwrap();
            assert_eq!(guard.active, Some(Slot::A));
            assert!(guard.members[1].is_none());
            let mut replacement = member(Slot::B);
            replacement.lease_id = "33333333-3333-4333-8333-333333333333".into();
            p.attach(&scope(), &replacement).unwrap();
            assert_eq!(native.borrow().starts, [1, 2]);
            assert_eq!(native.borrow().live[0], primary);
        }
    }
    #[test]
    fn rebind_after_primary_crash_skips_retired_member() {
        for stopped_service in [false, true] {
            let s = Rc::new(RefCell::new(State::default()));
            let native = Rc::new(RefCell::new(Native {
                dns_enabled: true,
                ..Default::default()
            }));
            s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
            let mut p = SessionNativePair::new(
                scope(),
                RetainedIo::new(s.clone(), native.clone()),
                Disk(s.clone()),
            )
            .unwrap();
            p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
                .unwrap();
            p.attach(&scope(), &member(Slot::B)).unwrap();
            assert!(p.rebind_pair(&scope()).unwrap(), "control: both live");
            native.borrow_mut().live[0] = None;
            native.borrow_mut().dns[0] = None;
            native.borrow_mut().stopped_service[0] = stopped_service;
            p.select_active(&scope(), Slot::B).unwrap();
            let old_primary = native.borrow().live[1];
            s.borrow_mut().events.clear();
            assert!(p.rebind_pair(&scope()).unwrap());
            assert_eq!(p.record.active, Some(Slot::B));
            assert!(!p.cleanup_pending());
            assert!(native.borrow().live[0].is_none());
            assert_ne!(native.borrow().live[1], old_primary);
            assert_eq!(native.borrow().starts, [1, 1]);
            assert!(p.sockets[0].is_none());
            assert!(p.sockets[1].is_some());
            assert_eq!(s.borrow().guard.as_ref().unwrap().active, Some(Slot::B));
            assert_eq!(s.borrow().route_active, Some(Slot::B));
            assert!(!s.borrow().events.iter().any(|e| e == "dns:A"));
            assert_eq!(
                native.borrow().dns[1]
                    .as_ref()
                    .unwrap()
                    .settings
                    .name_server
                    .as_deref(),
                Some("9.9.9.9")
            );
            p.remove_standby(&scope(), Slot::A).unwrap();
            p.close(&scope()).unwrap();
            assert!(native.borrow().live.iter().all(Option::is_none));
        }
    }
    #[test]
    fn rebind_does_not_ignore_foreign_or_unproven_retired_member() {
        for mutation in 0..4 {
            let s = Rc::new(RefCell::new(State::default()));
            let native = Rc::new(RefCell::new(Native::default()));
            s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
            let mut p = SessionNativePair::new(
                scope(),
                RetainedIo::new(s.clone(), native.clone()),
                Disk(s.clone()),
            )
            .unwrap();
            p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
                .unwrap();
            p.attach(&scope(), &member(Slot::B)).unwrap();
            let old = native.borrow().live[0];
            native.borrow_mut().live[0] = None;
            p.select_active(&scope(), Slot::B).unwrap();
            match mutation {
                0 => native.borrow_mut().live[0] = old,
                1 => native.borrow_mut().configs[0] = Some([99; 32]),
                2 => native.borrow_mut().fail_inspect = true,
                _ => native.borrow_mut().live[1] = None,
            }
            let before = native.borrow().live;
            s.borrow_mut().events.clear();
            assert!(p.rebind_pair(&scope()).is_err());
            assert_eq!(native.borrow().live, before);
            assert!(s.borrow().events.is_empty());
            assert_eq!(native.borrow().starts, [1, 1]);
        }
    }
    #[test]
    fn failed_reserve_retirement_never_forgets_owner_or_deletes_foreign_native() {
        for mutation in 0..5 {
            let s = Rc::new(RefCell::new(State::default()));
            let native = Rc::new(RefCell::new(Native::default()));
            s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
            let mut p = SessionNativePair::new(
                scope(),
                RetainedIo::new(s.clone(), native.clone()),
                Disk(s.clone()),
            )
            .unwrap();
            p.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
                .unwrap();
            p.attach(&scope(), &member(Slot::B)).unwrap();
            let intent = p.record.members[1].as_ref().unwrap().owner.intent.clone();
            native.borrow_mut().live[1] = None;
            native.borrow_mut().stopped_service[1] = true;
            match mutation {
                0 => {
                    let mut foreign = p.record.members[1].as_ref().unwrap().owner.proof.unwrap();
                    foreign.process.creation_time += 99;
                    native.borrow_mut().live[1] = Some(foreign);
                }
                1 => native.borrow_mut().configs[1] = Some([99; 32]),
                2 => native.borrow_mut().fail_inspect = true,
                3 => native.borrow_mut().fail_stopped_cleanup = true,
                _ => s.borrow_mut().fail_save = true,
            }
            let foreign = native.borrow().live[1];
            s.borrow_mut().events.clear();
            assert!(p.remove_standby(&scope(), Slot::B).is_err());
            assert_eq!(native.borrow().live[1], foreign);
            assert_eq!(s.borrow().owners[1].as_ref().unwrap().intent, intent);
            assert!(p.record.members[1].is_some());
            assert!(p.cleanup_pending());
            assert!(!s.borrow().events.iter().any(|e| e == "guard:Some(A)"));
            assert_eq!(native.borrow().starts, [1, 1]);
        }
    }
    #[derive(Default)]
    struct Native {
        configs: [Option<[u8; 32]>; 2],
        live: [Option<owner::NativeProof>; 2],
        stopped_service: [bool; 2],
        answer_queries: bool,
        tx: [u64; 2],
        rx: [u64; 2],
        dns_enabled: bool,
        dns: [Option<DnsSnapshot>; 2],
        starts: [u64; 2],
        fail_config: bool,
        lost_config: bool,
        fail_inspect: bool,
        fail_stopped_cleanup: bool,
        fail_rebind: bool,
        lost_rebind: bool,
    }
    type NativeState = Rc<RefCell<Native>>;
    struct HealthSocket {
        base: Socket,
        native: NativeState,
        slot: Slot,
        query: Vec<u8>,
        replied: bool,
        base_owner: bool,
    }
    impl Drop for HealthSocket {
        fn drop(&mut self) {
            if self.base_owner {
                self.base
                    .0
                    .borrow_mut()
                    .events
                    .push(format!("base_drop:{:?}", self.slot));
            }
        }
    }
    impl ProbeDatagram for HealthSocket {
        fn send(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.query = bytes.to_vec();
            self.native.borrow_mut().tx[self.slot.idx()] += 1;
            Ok(bytes.len())
        }
        fn receive(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let mut native = self.native.borrow_mut();
            if self.replied || !native.answer_queries || native.live[self.slot.idx()].is_none() {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let mut response = self.query.clone();
            response[2] = 0x81;
            response[3] = 0x80;
            response[7] = 1;
            response.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4]);
            bytes[..response.len()].copy_from_slice(&response);
            native.rx[self.slot.idx()] += 1;
            self.replied = true;
            Ok(response.len())
        }
    }
    impl PairSocket for HealthSocket {
        fn duplicate(&self) -> io::Result<Self> {
            Ok(Self {
                base: self.base.duplicate()?,
                native: self.native.clone(),
                slot: self.slot,
                query: Vec::new(),
                replied: false,
                base_owner: false,
            })
        }
    }
    struct JournalIo(Shared);
    impl Journal for JournalIo {
        fn load(&mut self, slot: TunnelSlot) -> owner::Result<Option<OwnerRecord>> {
            Ok(self.0.borrow().owners[slot_shared(slot).idx()].clone())
        }
        fn compare_exchange(
            &mut self,
            slot: TunnelSlot,
            expected: Option<&OwnerRecord>,
            next: &OwnerRecord,
        ) -> owner::Result<()> {
            let mut s = self.0.borrow_mut();
            let i = slot_shared(slot).idx();
            if s.owners[i].as_ref() != expected {
                return Err(owner::OwnerError::Conflict);
            }
            s.owner_saves += 1;
            if s.fail_owner_save == Some(s.owner_saves) {
                return Err(owner::OwnerError::Journal);
            }
            s.owners[i] = Some(next.clone());
            if s.lost_owner_save == Some(s.owner_saves) {
                return Err(owner::OwnerError::Journal);
            }
            Ok(())
        }
    }
    struct NativeIo(NativeState);
    impl MemberIo for NativeIo {
        fn inspect(
            &mut self,
            intent: &owner::Intent,
            retained: Option<&owner::NativeProof>,
        ) -> owner::Result<owner::Observation> {
            let s = self.0.borrow();
            if s.fail_inspect {
                return Err(owner::OwnerError::Native);
            }
            let i = slot_shared(intent.slot).idx();
            let live = s.live[i];
            Ok(owner::Observation {
                config_sha256: s.configs[i],
                service: live
                    .map(|p| owner::ServiceObservation {
                        exact_spec: true,
                        process: Some(p.process),
                    })
                    .or_else(|| {
                        s.stopped_service[i].then_some(owner::ServiceObservation {
                            exact_spec: true,
                            process: None,
                        })
                    }),
                alternative_service_present: false,
                interface: live.map(|p| p.interface),
                retained_interfaces: live
                    .filter(|p| retained.is_some_and(|r| r.interface.index == p.interface.index))
                    .map(|p| vec![p.interface])
                    .unwrap_or_default(),
            })
        }
        fn write_private_config(
            &mut self,
            intent: &owner::Intent,
            expected: Option<[u8; 32]>,
            _: &str,
        ) -> owner::Result<()> {
            let mut s = self.0.borrow_mut();
            let i = slot_shared(intent.slot).idx();
            if s.configs[i] != expected {
                return Err(owner::OwnerError::Conflict);
            }
            if s.fail_config {
                return Err(owner::OwnerError::Native);
            }
            s.configs[i] = Some(intent.config_sha256);
            if s.lost_config {
                return Err(owner::OwnerError::Native);
            }
            Ok(())
        }
        fn start_fresh(
            &mut self,
            intent: &owner::Intent,
            _: Option<&owner::NativeProof>,
        ) -> owner::Result<()> {
            let mut s = self.0.borrow_mut();
            let i = slot_shared(intent.slot).idx();
            assert!(s.live[i].is_none());
            assert_eq!(s.configs[i], Some(intent.config_sha256));
            s.starts[i] += 1;
            s.live[i] = Some(owner::NativeProof {
                process: owner::ProcessProof {
                    pid: 20 + i as u32,
                    creation_time: s.starts[i],
                },
                interface: owner::InterfaceProof {
                    index: 10 + i as u32,
                    luid: 40 + i as u64,
                    guid: [i as u8 + 1; 16],
                },
            });
            if s.dns_enabled {
                let p = s.live[i].unwrap().interface;
                s.dns[i] = Some(DnsSnapshot {
                    interface: crate::member_dns::OwnedInterface {
                        scope: intent.scope.clone(),
                        guid: p.guid,
                        luid: p.luid,
                        index: p.index,
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
                });
            }
            Ok(())
        }
        fn stop_slot(
            &mut self,
            intent: &owner::Intent,
            proof: Option<&owner::NativeProof>,
            expected: &owner::Observation,
        ) -> owner::Result<()> {
            // Match the real adapter's require_same check, including cleanup
            // by the still-live owner of an interrupted Prepared operation.
            // MemberOwner (not this OS fake) decides whether that is allowed.
            if &self.inspect(intent, proof)? != expected {
                return Err(owner::OwnerError::Conflict);
            }
            let mut s = self.0.borrow_mut();
            let i = slot_shared(intent.slot).idx();
            if s.fail_stopped_cleanup && s.live[i].is_none() && s.stopped_service[i] {
                return Err(owner::OwnerError::Native);
            }
            if expected.service.as_ref().and_then(|svc| svc.process) != s.live[i].map(|p| p.process)
                || s.configs[i] != Some(intent.config_sha256)
            {
                return Err(owner::OwnerError::Conflict);
            }
            s.live[i] = None;
            s.stopped_service[i] = false;
            s.dns[i] = None;
            Ok(())
        }
        fn rebind(
            &mut self,
            intent: &owner::Intent,
            proof: &owner::NativeProof,
            _: &owner::Observation,
        ) -> owner::Result<()> {
            let mut state = self.0.borrow_mut();
            if state.fail_rebind {
                return Err(owner::OwnerError::Native);
            }
            let current = state.live[slot_shared(intent.slot).idx()].as_mut().unwrap();
            assert_eq!(current, proof);
            current.process.creation_time += 100;
            current.process.pid += 100;
            if state.lost_rebind {
                return Err(owner::OwnerError::Native);
            }
            Ok(())
        }
    }
    type RealOwner = MemberOwner<JournalIo, NativeIo>;
    struct RetainedIo {
        base: Io,
        native: NativeState,
        owners: [Option<RealOwner>; 2],
    }
    impl RetainedIo {
        fn new(s: Shared, native: NativeState) -> Self {
            Self {
                base: Io(s),
                native,
                owners: [None, None],
            }
        }
        fn owner(&mut self, m: &MemberRecord) -> &mut RealOwner {
            self.owners[slot_shared(m.owner.intent.slot).idx()]
                .as_mut()
                .unwrap()
        }
        fn recover(s: Shared, native: NativeState, record: &PairRecord) -> Self {
            let mut io = Self::new(s.clone(), native.clone());
            for (i, m) in record.members.iter().enumerate() {
                let Some(m) = m else {
                    continue;
                };
                let current = s.borrow().owners[i].clone();
                if matches_unstarted_prior(m, current.as_ref()).unwrap() {
                    continue;
                }
                let saved = current.unwrap();
                io.owners[i] = Some(
                    MemberOwner::recover_for_cleanup(
                        saved.intent.scope.clone(),
                        saved.intent.slot,
                        saved.intent.transport,
                        saved.intent.engine.clone(),
                        saved,
                        JournalIo(s.clone()),
                        NativeIo(native.clone()),
                    )
                    .unwrap(),
                );
            }
            io
        }
    }
    impl PairIo for RetainedIo {
        type Socket = HealthSocket;
        fn prepare_member(&mut self, scope: &SessionScope, m: &Member) -> io::Result<MemberRecord> {
            let i = m.slot.idx();
            if let Some(old) = &mut self.owners[i] {
                let retired = old
                    .snapshot()
                    .map_err(io::Error::other)?
                    .ok_or_else(failed)?;
                let pair = self.base.0.borrow().saved.clone().unwrap();
                verify_retired_slot(&retired, &pair, &[], &self.base.guard_snapshot()?)?;
                if !old.confirm_absent(&retired).map_err(io::Error::other)? {
                    return Err(failed());
                }
            }
            let mut owner = MemberOwner::from_trusted_engine(
                scope.clone(),
                slot_native(m.slot),
                nelomai_client_tunnel::TunnelTransport::WireGuard,
                crate::test_engine_path("engine.exe"),
                m.configuration.expose(),
                JournalIo(self.base.0.clone()),
                NativeIo(self.native.clone()),
            )
            .map_err(io::Error::other)?;
            let mut record = self.base.prepare_member(scope, m)?;
            record.owner.intent = owner.intent().clone();
            record.prior_stopped = owner.prior_stopped().map_err(io::Error::other)?;
            if self.native.borrow().dns_enabled {
                record.dns = vec!["9.9.9.9".parse().unwrap()];
            }
            self.owners[i] = Some(owner);
            Ok(record)
        }
        fn start(&mut self, m: &MemberRecord) -> io::Result<OwnerRecord> {
            self.owner(m)
                .start_with_prior(m.prior_stopped.as_ref())
                .map_err(io::Error::other)
        }
        fn abandon_unstarted(&mut self, m: &MemberRecord) -> io::Result<bool> {
            let current =
                self.base.0.borrow().owners[slot_shared(m.owner.intent.slot).idx()].clone();
            if !matches_unstarted_prior(m, current.as_ref())? {
                return Ok(false);
            }
            if let Some(prior) = current {
                let mut cleanup = MemberOwner::recover_for_cleanup(
                    prior.intent.scope.clone(),
                    prior.intent.slot,
                    prior.intent.transport,
                    prior.intent.engine.clone(),
                    prior.clone(),
                    JournalIo(self.base.0.clone()),
                    NativeIo(self.native.clone()),
                )
                .map_err(io::Error::other)?;
                cleanup.confirm_absent(&prior).map_err(io::Error::other)
            } else {
                let i = slot_shared(m.owner.intent.slot).idx();
                let native = self.native.borrow();
                Ok(native.live[i].is_none() && native.configs[i].is_none())
            }
        }
        fn current(&mut self, slot: Slot) -> io::Result<Option<OwnerRecord>> {
            self.owners[slot.idx()]
                .as_mut()
                .map(|o| o.snapshot().map_err(io::Error::other))
                .transpose()
                .map(Option::flatten)
        }
        fn verify(&mut self, m: &MemberRecord) -> io::Result<()> {
            self.owner(m)
                .verify_live(&m.owner)
                .map_err(io::Error::other)
        }
        fn confirm_absent(&mut self, m: &MemberRecord) -> io::Result<bool> {
            self.owner(m)
                .confirm_absent(&m.owner)
                .map_err(io::Error::other)
        }
        fn verify_endpoint(&mut self, m: &MemberRecord) -> io::Result<()> {
            self.base.verify_endpoint(m)
        }
        fn confirm_inactive_for_discovery(&mut self, m: &MemberRecord) -> io::Result<bool> {
            self.owner(m)
                .confirm_inactive_for_discovery(&m.owner)
                .map_err(io::Error::other)
        }
        fn stop(&mut self, m: &MemberRecord) -> io::Result<OwnerRecord> {
            self.owner(m)
                .stop_best_effort(&m.owner)
                .map_err(io::Error::other)
        }
        fn rebind(&mut self, m: &MemberRecord) -> io::Result<OwnerRecord> {
            self.owner(m).rebind(&m.owner).map_err(io::Error::other)
        }
        fn observe(&mut self, m: &MemberRecord) -> io::Result<(TunnelMetrics, NativeHealthSample)> {
            self.verify(m)?;
            let (metrics, mut sample) = self.base.observe(m)?;
            let native = self.native.borrow();
            let i = slot_shared(m.owner.intent.slot).idx();
            sample.tx_packets = native.tx[i];
            sample.rx_data_packets = native.rx[i];
            Ok((metrics, sample))
        }
        fn fingerprint(&mut self, m: &[Option<MemberRecord>; 2]) -> io::Result<String> {
            self.base.fingerprint(m)
        }
        fn open_base(&mut self, m: &MemberRecord) -> io::Result<(HealthSocket, ProbeTuple)> {
            self.verify(m)?;
            let (base, tuple) = self.base.open_base(m)?;
            Ok((
                HealthSocket {
                    base,
                    native: self.native.clone(),
                    slot: slot_shared(m.owner.intent.slot),
                    query: Vec::new(),
                    replied: false,
                    base_owner: true,
                },
                tuple,
            ))
        }
        fn guard_snapshot(&mut self) -> io::Result<crate::member_guard::Snapshot> {
            self.base.guard_snapshot()
        }
        fn guard_exchange(&mut self, p: &ExchangePlan) -> io::Result<Model> {
            self.base.guard_exchange(p)
        }
        fn close_permits(&mut self) -> io::Result<()> {
            self.base.close_permits()
        }
        fn select_routes(
            &mut self,
            a: Slot,
            m: &[Option<MemberRecord>; 2],
            o: &DesktopTunnelOptions,
        ) -> io::Result<()> {
            let live = live_route_members(self, a, m)?;
            self.base.select_routes(a, &live, o)
        }
        fn cleanup_routes(&mut self) -> io::Result<()> {
            self.base.cleanup_routes()
        }
        fn read_dns(&mut self, m: &MemberRecord) -> io::Result<DnsSnapshot> {
            self.verify(m)?;
            self.native.borrow().dns[slot_shared(m.owner.intent.slot).idx()]
                .clone()
                .ok_or_else(failed)
        }
        fn exchange_dns(&mut self, a: &DnsSnapshot, b: &DnsSnapshot) -> io::Result<()> {
            let m = self
                .base
                .0
                .borrow()
                .saved
                .as_ref()
                .unwrap()
                .members
                .iter()
                .flatten()
                .find(|m| {
                    m.owner
                        .proof
                        .is_some_and(|p| p.interface.index == a.interface.index)
                })
                .cloned()
                .ok_or_else(failed)?;
            self.verify(&m)?;
            let i = slot_shared(m.owner.intent.slot).idx();
            let mut native = self.native.borrow_mut();
            if a.interface != b.interface || native.dns[i].as_ref() != Some(a) {
                return Err(failed());
            }
            native.dns[i] = Some(b.clone());
            self.base
                .0
                .borrow_mut()
                .events
                .push(format!("dns:{:?}", slot_shared(m.owner.intent.slot)));
            Ok(())
        }
    }
    struct SessionDisk;
    impl nelomai_client_tunnel::redundancy::driver::SessionStore for SessionDisk {
        fn save(
            &mut self,
            _: &nelomai_client_tunnel::redundancy::session::SessionSnapshot,
        ) -> io::Result<()> {
            Ok(())
        }
    }
    struct NoSingle;
    impl crate::ServiceTunnelBackend for NoSingle {
        fn start(
            &mut self,
            _: &str,
            _: &DesktopTunnelOptions,
            _: nelomai_client_tunnel::TunnelTransport,
        ) -> Result<crate::ServiceTunnelState, crate::ServiceError> {
            panic!("no legacy fallback")
        }
        fn stop(&mut self) -> Result<crate::ServiceTunnelState, crate::ServiceError> {
            panic!("no legacy fallback")
        }
        fn status(&mut self) -> Result<crate::ServiceTunnelState, crate::ServiceError> {
            Ok(crate::ServiceTunnelState::Stopped)
        }
    }
    struct PhysicalFactory(Shared, NativeState);
    impl crate::member_actor::PairFactory for PhysicalFactory {
        type Native = SessionNativePair<RetainedIo, Disk>;
        type Store = SessionDisk;
        fn recover(&mut self, _: RuntimeSlot) -> Result<(), crate::ServiceError> {
            Ok(())
        }
        fn prepare(
            &mut self,
            runtime: RuntimeSlot,
            command: &nelomai_client_tunnel::redundancy::protocol::Command,
            now: u64,
        ) -> io::Result<
            nelomai_client_tunnel::redundancy::control::SessionControl<Self::Native, Self::Store>,
        > {
            let native = SessionNativePair::new(
                command.scope().clone(),
                RetainedIo::new(self.0.clone(), self.1.clone()),
                Disk(self.0.clone()),
            )?;
            nelomai_client_tunnel::redundancy::control::SessionControl::prepare(
                runtime,
                command,
                native,
                SessionDisk,
                now,
            )
        }
    }
    #[test]
    fn promotion_rejects_unproven_old_member_or_nonlive_selected_member_before_effects() {
        for mutation in 0..5 {
            let s = Rc::new(RefCell::new(State::default()));
            let native = Rc::new(RefCell::new(Native::default()));
            s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
            let mut pair = SessionNativePair::new(
                scope(),
                RetainedIo::new(s.clone(), native.clone()),
                Disk(s.clone()),
            )
            .unwrap();
            pair.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
                .unwrap();
            pair.attach(&scope(), &member(Slot::B)).unwrap();
            match mutation {
                0 => {
                    native.borrow_mut().live[0]
                        .as_mut()
                        .unwrap()
                        .process
                        .creation_time += 100
                }
                1 => native.borrow_mut().live[1] = None,
                2 => native.borrow_mut().live[1].as_mut().unwrap().interface.guid = [99; 16],
                3 => native.borrow_mut().fail_inspect = true,
                _ => {
                    native.borrow_mut().live[0] = None;
                    native.borrow_mut().stopped_service[0] = true;
                    native.borrow_mut().configs[0] = Some([99; 32]);
                }
            }
            s.borrow_mut().events.clear();
            let before = native.borrow().live;
            assert!(pair.select_active(&scope(), Slot::B).is_err());
            assert_eq!(native.borrow().live, before);
            assert_eq!(native.borrow().starts, [1, 1]);
            assert!(s.borrow().events.is_empty());
            assert_eq!(s.borrow().guard.as_ref().unwrap().active, Some(Slot::A));
        }
    }
    #[test]
    fn actor_promotes_healthy_b_after_a_scm_crash_and_retires_only_a() {
        use crate::{member_actor::CompositeBackend, ServiceTunnelBackend};
        use nelomai_client_tunnel::redundancy::{protocol::Command, session::SessionPhase};
        for (stopped_service, cleanup_failure) in
            [(false, 0), (true, 0), (true, 1), (true, 2), (true, 3)]
        {
            let s = Rc::new(RefCell::new(State::default()));
            let native = Rc::new(RefCell::new(Native {
                answer_queries: true,
                dns_enabled: true,
                ..Default::default()
            }));
            s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
            let mut actor = CompositeBackend::new(
                RuntimeSlot::Stable,
                NoSingle,
                PhysicalFactory(s.clone(), native.clone()),
            )
            .unwrap();
            actor
                .redundant(Command::Start {
                    scope: scope(),
                    primary: member(Slot::A),
                    role_generation: 0,
                    membership_generation: 0,
                    warm_stop_v1: true,
                    options: DesktopTunnelOptions::default(),
                })
                .unwrap();
            let snapshot = actor.current_redundancy_snapshot().unwrap();
            let mut reserve = member(Slot::B);
            reserve.lease_id = "33333333-3333-4333-8333-333333333333".into();
            actor
                .redundant(Command::Attach {
                    scope: scope(),
                    member: reserve,
                    expected_revision: snapshot.session.local_revision,
                    expected_network_epoch: snapshot.session.network_epoch,
                    expected_membership_generation: 0,
                    membership_generation: 0,
                })
                .unwrap();
            for now in (0..=2000).step_by(100) {
                actor.tick(now).unwrap();
            }
            assert!(actor.current_redundancy_snapshot().unwrap().primary_ready);
            let b = native.borrow().live[1];
            native.borrow_mut().live[0] = None;
            native.borrow_mut().dns[0] = None;
            native.borrow_mut().stopped_service[0] = stopped_service;
            match cleanup_failure {
                1 => native.borrow_mut().fail_stopped_cleanup = true,
                2 => {
                    let count = s.borrow().owner_saves;
                    s.borrow_mut().fail_owner_save = Some(count + 2);
                }
                3 => {
                    let count = s.borrow().owner_saves;
                    s.borrow_mut().lost_owner_save = Some(count + 2);
                }
                _ => (),
            }
            s.borrow_mut().events.clear();
            let mut failed = false;
            for now in (2100..=12000).step_by(100) {
                if actor.tick(now).is_err() {
                    failed = true;
                    break;
                }
            }
            let result = actor.current_redundancy_snapshot().unwrap();
            if cleanup_failure != 0 {
                assert!(failed, "failed stopped cleanup must reject promotion");
                assert_ne!(result.session.active, Slot::B);
                assert_ne!(result.session.phase, SessionPhase::Running);
                assert_eq!(native.borrow().starts, [1, 1]);
                assert!(!s
                    .borrow()
                    .events
                    .iter()
                    .any(|e| e == "routes:B" || e == "guard:Some(B)"));
                if cleanup_failure == 1 {
                    assert!(result.cleanup_pending);
                    assert!(native.borrow().stopped_service[0]);
                    let retained = s.borrow().owners[0].clone().unwrap();
                    assert_eq!(retained.phase, owner::Phase::Stopping);
                    assert!(retained.proof.is_some());
                }
                continue;
            }
            assert!(!failed);
            assert_eq!(result.session.phase, SessionPhase::Running);
            assert_eq!(result.session.active, Slot::B);
            assert!(result.primary_ready);
            assert!(!result.cleanup_pending);
            assert_eq!(native.borrow().starts, [1, 1]);
            assert_eq!(native.borrow().live[1], b);
            assert!(!native.borrow().stopped_service[0]);
            assert_eq!(
                s.borrow().owners[0].as_ref().unwrap().phase,
                owner::Phase::Stopped
            );
            assert_eq!(s.borrow().route_active, Some(Slot::B));
            let guard = s.borrow().guard.clone().unwrap();
            assert_eq!(guard.active, Some(Slot::B));
            assert!(guard.members[0].is_none());
            assert!(guard.members[1].is_some());
            assert!(s.borrow().saved.as_ref().unwrap().dns[0].is_none());
            assert!(native.borrow().dns[0].is_none());
            assert_eq!(
                native.borrow().dns[1]
                    .as_ref()
                    .unwrap()
                    .settings
                    .name_server
                    .as_deref(),
                Some("9.9.9.9")
            );
            assert!(actor.metrics(false).is_ok());
            assert!(actor.physical_network_fingerprint().is_ok());
            let events = s.borrow().events.clone();
            let fence = events.iter().position(|e| e == "guard:None").unwrap();
            let drop = events.iter().position(|e| e == "base_drop:A").unwrap();
            let routes = events.iter().position(|e| e == "routes:B").unwrap();
            let allow = events.iter().position(|e| e == "guard:Some(B)").unwrap();
            assert!(fence < routes && routes < allow);
            assert!(fence < drop && drop < routes);
            assert!(!events.iter().any(|e| e == "dns:A"));
            // The UI has not removed the retired A yet. A physical-network
            // change must still rebind B and resume autonomous health polling.
            actor
                .redundant(Command::NetworkChanged { scope: scope() })
                .unwrap();
            for now in (12100..=20000).step_by(100) {
                actor.tick(now).unwrap();
            }
            let rebound = actor.current_redundancy_snapshot().unwrap();
            assert_eq!(rebound.session.active, Slot::B);
            assert_eq!(rebound.session.phase, SessionPhase::Running);
            assert!(rebound.primary_ready);
            assert!(!rebound.cleanup_pending);
            assert!(native.borrow().live[0].is_none());
            assert!(native.borrow().live[1].is_some());
            assert_eq!(native.borrow().starts, [1, 1]);
            assert!(actor.metrics(false).is_ok());
        }
    }
    #[test]
    fn physical_poll_keeps_health_running_after_owned_member_disappears_but_rejects_foreign() {
        use crate::{member_actor::CompositeBackend, ServiceTunnelBackend};
        use nelomai_client_tunnel::redundancy::protocol::Command;
        for (stopped_service, foreign) in [(false, false), (true, false), (false, true)] {
            let s = Rc::new(RefCell::new(State::default()));
            let native = Rc::new(RefCell::new(Native::default()));
            s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
            let mut actor = CompositeBackend::new(
                RuntimeSlot::Stable,
                NoSingle,
                PhysicalFactory(s.clone(), native.clone()),
            )
            .unwrap();
            actor
                .redundant(Command::Start {
                    scope: scope(),
                    primary: member(Slot::A),
                    role_generation: 0,
                    membership_generation: 0,
                    warm_stop_v1: true,
                    options: DesktopTunnelOptions::default(),
                })
                .unwrap();
            let state = actor.current_redundancy_snapshot().unwrap().session;
            let mut reserve = member(Slot::B);
            reserve.lease_id = "33333333-3333-4333-8333-333333333333".into();
            actor
                .redundant(Command::Attach {
                    scope: scope(),
                    member: reserve,
                    expected_revision: state.local_revision,
                    expected_network_epoch: state.network_epoch,
                    expected_membership_generation: 0,
                    membership_generation: 0,
                })
                .unwrap();
            actor.tick(0).unwrap();
            let epoch = actor
                .current_redundancy_snapshot()
                .unwrap()
                .session
                .network_epoch;
            if foreign {
                native.borrow_mut().live[0]
                    .as_mut()
                    .unwrap()
                    .process
                    .creation_time += 100;
            } else {
                native.borrow_mut().live[0] = None;
                native.borrow_mut().stopped_service[0] = stopped_service;
            }
            // Poll physical BEFORE any subsequent health sample, exactly as the
            // production actor does. No missing-metrics evidence exists yet.
            for now in (2000..=12000).step_by(500) {
                actor.tick(now).unwrap();
            }
            let result = actor.current_redundancy_snapshot().unwrap();
            if foreign {
                assert!(actor.physical_network_fingerprint().is_err());
                assert!(result.session.network_epoch > epoch);
                assert!(!result.stalled, "invalid discovery must suspend health");
            } else {
                assert_eq!(
                    actor.physical_network_fingerprint().unwrap(),
                    "a".repeat(64)
                );
                assert_eq!(
                    result.session.network_epoch, epoch,
                    "native absence is not a physical network change"
                );
                assert!(result.stalled,"missing samples must reach health after its existing urgent budget; fake DNS deliberately never replies");
            }
            assert_eq!(native.borrow().starts, [1, 1]);
            assert!(native.borrow().live[1].is_some());
            assert_eq!(result.session.active, Slot::A);
        }
    }
    #[test]
    fn physical_fingerprint_accepts_absent_member_not_stale_or_unproven_identity() {
        for slot in [Slot::A, Slot::B] {
            for mutation in 0..5 {
                let s = Rc::new(RefCell::new(State::default()));
                let native = Rc::new(RefCell::new(Native::default()));
                s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
                let mut pair = SessionNativePair::new(
                    scope(),
                    RetainedIo::new(s.clone(), native.clone()),
                    Disk(s.clone()),
                )
                .unwrap();
                pair.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
                    .unwrap();
                pair.attach(&scope(), &member(Slot::B)).unwrap();
                let before = pair.physical_network_fingerprint().unwrap();
                native.borrow_mut().live[slot.idx()] = None;
                match mutation {
                    0 => (),
                    1 => native.borrow_mut().fail_inspect = true,
                    2 => native.borrow_mut().configs[slot.idx()] = Some([99; 32]),
                    3 => {
                        s.borrow_mut().owners[slot.idx()]
                            .as_mut()
                            .unwrap()
                            .intent
                            .scope
                            .connection_generation += 1
                    }
                    _ => {
                        let mut foreign = pair.record.members[slot.idx()]
                            .as_ref()
                            .unwrap()
                            .owner
                            .proof
                            .unwrap();
                        foreign.interface.guid = [99; 16];
                        native.borrow_mut().live[slot.idx()] = Some(foreign);
                    }
                }
                s.borrow_mut().events.clear();
                let fingerprint = pair.physical_network_fingerprint();
                if mutation == 0 {
                    assert_eq!(fingerprint.unwrap(), before);
                } else {
                    assert!(fingerprint.is_err());
                }
                assert!(s.borrow().events.is_empty(), "discovery must be read-only");
                assert_eq!(native.borrow().starts, [1, 1]);
            }
        }
    }
    #[test]
    fn exact_empty_guard_after_native_stop_completes_only_cleanup_and_never_reinstalls() {
        for recovery in [false, true] {
            for pending in [false, true] {
                let s = Rc::new(RefCell::new(State::default()));
                let native = Rc::new(RefCell::new(Native::default()));
                s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
                let mut pair = SessionNativePair::new(
                    scope(),
                    RetainedIo::new(s.clone(), native.clone()),
                    Disk(s.clone()),
                )
                .unwrap();
                pair.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
                    .unwrap();
                pair.attach(&scope(), &member(Slot::B)).unwrap();
                // Retained per-interface DNS must disappear only with proven
                // native absence, never by writing onto a reused interface.
                for i in 0..2 {
                    let m = pair.record.members[i].as_mut().unwrap();
                    let interface = m.owner.proof.unwrap().interface;
                    m.dns = vec!["9.9.9.9".parse().unwrap()];
                    let baseline = DnsSnapshot {
                        interface: crate::member_dns::OwnedInterface {
                            scope: scope(),
                            guid: interface.guid,
                            luid: interface.luid,
                            index: interface.index,
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
                    pair.record.dns[i] = Some(DnsRecord {
                        current: baseline.with_servers(&m.dns).unwrap(),
                        baseline,
                        pending: None,
                    });
                }
                if pending {
                    pair.record.pending_guard = Some(
                        ExchangePlan::new(&pair.record.guard, &pair.model(None, false).unwrap())
                            .unwrap(),
                    );
                }
                pair.save().unwrap();
                s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
                s.borrow_mut().events.clear();
                assert!(
                    pair.check_integrity().is_err(),
                    "first loss must fail-stop, never be adopted"
                );
                assert_eq!(native.borrow().live, [None, None]);
                assert!(s
                    .borrow()
                    .owners
                    .iter()
                    .flatten()
                    .all(|r| r.phase == owner::Phase::Stopped));
                assert!(pair.cleanup_pending());
                if recovery {
                    let record = s.borrow().saved.clone().unwrap();
                    drop(pair);
                    let io = RetainedIo::recover(s.clone(), native.clone(), &record);
                    pair = SessionNativePair::recover_for_cleanup(
                        scope(),
                        io,
                        Disk(s.clone()),
                        record,
                    )
                    .unwrap();
                }
                s.borrow_mut().fail_cleanup_routes = true;
                assert!(
                    pair.close(&scope()).is_err(),
                    "empty guard must not skip route cleanup"
                );
                assert!(pair.cleanup_pending());
                s.borrow_mut().fail_cleanup_routes = false;
                pair.close(&scope()).unwrap();
                assert!(!pair.cleanup_pending());
                let saved = s.borrow().saved.clone().unwrap();
                assert!(saved.members.iter().all(Option::is_none));
                assert!(saved.dns.iter().all(Option::is_none));
                assert!(saved.pending_guard.is_none());
                assert_eq!(saved.guard, Model::empty(scope()).unwrap());
                assert!(
                    !s.borrow().events.iter().any(|e| e.starts_with("guard:")),
                    "cleanup must not reinstall WFP"
                );
                if !recovery {
                    assert!(pair.integrity_fault.is_some());
                    assert!(pair.check_integrity().is_err());
                }
                assert!(pair.sample(Slot::A).is_none());
                assert!(pair.rebind_pair(&scope()).is_err());
                assert!(pair
                    .start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
                    .is_err());
                assert_eq!(native.borrow().starts, [1, 1]);
            }
        }
    }

    #[test]
    fn empty_guard_cleanup_rejects_unknown_foreign_live_and_reused_native_identity() {
        for fault in 0..6 {
            let s = Rc::new(RefCell::new(State::default()));
            let native = Rc::new(RefCell::new(Native::default()));
            s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
            let mut pair = SessionNativePair::new(
                scope(),
                RetainedIo::new(s.clone(), native.clone()),
                Disk(s.clone()),
            )
            .unwrap();
            pair.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
                .unwrap();
            pair.attach(&scope(), &member(Slot::B)).unwrap();
            let original = native.borrow().live[1].unwrap();
            let foreign_filter = pair.record.guard.expected.filters[0].clone();
            s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
            assert!(pair.check_integrity().is_err());
            assert_eq!(native.borrow().live, [None, None]);
            match fault {
                0 => s.borrow_mut().fail_guard_read = true,
                1 => native.borrow_mut().fail_inspect = true,
                2 => {
                    let mut observed = Model::empty(scope()).unwrap().expected;
                    observed.filters.push(foreign_filter);
                    s.borrow_mut().guard_observation = Some(observed);
                }
                3 => native.borrow_mut().live[1] = Some(original),
                4 => {
                    let mut reused = original;
                    reused.process.creation_time += 100;
                    reused.interface.guid = [99; 16];
                    native.borrow_mut().live[1] = Some(reused);
                }
                _ => s.borrow_mut().owners[1] = None,
            }
            let retained = native.borrow().live;
            s.borrow_mut().events.clear();
            assert!(
                pair.close(&scope()).is_err(),
                "fault {fault} must not be treated as exact absence"
            );
            assert!(pair.cleanup_pending());
            assert!(pair.record.members.iter().all(Option::is_some));
            assert_eq!(native.borrow().live, retained);
            assert!(!s.borrow().events.iter().any(|e| e.starts_with("guard:")));
            assert_eq!(native.borrow().starts, [1, 1]);
        }
    }

    #[test]
    fn guard_loss_tick_closes_proven_owner_but_never_stops_reused_foreign_pid() {
        for foreign in [false, true] {
            let s = Rc::new(RefCell::new(State::default()));
            let native = Rc::new(RefCell::new(Native::default()));
            s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
            let mut pair = SessionNativePair::new(
                scope(),
                RetainedIo::new(s.clone(), native.clone()),
                Disk(s.clone()),
            )
            .unwrap();
            pair.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
                .unwrap();
            pair.attach(&scope(), &member(Slot::B)).unwrap();
            if foreign {
                native.borrow_mut().live[1]
                    .as_mut()
                    .unwrap()
                    .process
                    .creation_time += 100;
            }
            let retained_b = native.borrow().live[1];
            s.borrow_mut().fail_guard_read = true;
            // No GUI, health sample, or DNS result is needed for fail-stop.
            assert!(pair.check_integrity().is_err());
            assert!(native.borrow().live[0].is_none());
            assert_eq!(
                native.borrow().live[1],
                if foreign { retained_b } else { None }
            );
            assert!(pair.cleanup_pending());
            // Recovering read access must not clear the fault or start/adopt.
            s.borrow_mut().fail_guard_read = false;
            assert!(pair.check_integrity().is_err());
            assert!(pair.sample(Slot::A).is_none());
            assert!(pair
                .start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
                .is_err());
            assert_eq!(native.borrow().starts, [1, 1]);
            assert_eq!(
                native.borrow().live[1],
                if foreign { retained_b } else { None }
            );
        }
    }
    #[test]
    fn real_owner_pair_retire_b_then_replace_b_keeps_primary_and_retained_files() {
        let s = Rc::new(RefCell::new(State::default()));
        let native = Rc::new(RefCell::new(Native::default()));
        s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
        let mut pair = SessionNativePair::new(
            scope(),
            RetainedIo::new(s.clone(), native.clone()),
            Disk(s.clone()),
        )
        .unwrap();
        pair.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
            .unwrap();
        pair.attach(&scope(), &member(Slot::B)).unwrap();
        let old = s.borrow().owners[1].clone().unwrap();
        pair.remove_standby(&scope(), Slot::B).unwrap();
        assert_eq!(native.borrow().configs[1], Some(old.intent.config_sha256));
        let mut replacement = member(Slot::B);
        replacement.configuration = nelomai_client_tunnel::TunnelConfiguration::new(
            "[Interface]\nPrivateKey = replaced\n[Peer]\n".into(),
        );
        pair.attach(&scope(), &replacement).unwrap();
        assert_eq!(native.borrow().starts, [1, 2]);
        assert_eq!(s.borrow().guard.as_ref().unwrap().active, Some(Slot::A));
        assert!(pair.metrics(Slot::A).is_ok());
        assert_ne!(
            s.borrow().owners[1].as_ref().unwrap().intent.config_sha256,
            old.intent.config_sha256
        );
        pair.close(&scope()).unwrap();
    }
    #[test]
    fn real_owner_pair_stop_then_new_scope_start_reuses_neither_owner_nor_native_proof() {
        let s = Rc::new(RefCell::new(State::default()));
        let native = Rc::new(RefCell::new(Native::default()));
        s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
        let mut first = SessionNativePair::new(
            scope(),
            RetainedIo::new(s.clone(), native.clone()),
            Disk(s.clone()),
        )
        .unwrap();
        first
            .start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
            .unwrap();
        let old = s.borrow().owners[0].clone().unwrap();
        first.close(&scope()).unwrap();
        drop(first);
        assert_eq!(native.borrow().configs[0], Some(old.intent.config_sha256));
        let next = SessionScope {
            connection_generation: 4,
            ..scope()
        };
        s.borrow_mut().guard = Some(Model::empty(next.clone()).unwrap());
        let mut second = SessionNativePair::new(
            next.clone(),
            RetainedIo::new(s.clone(), native.clone()),
            Disk(s.clone()),
        )
        .unwrap();
        second
            .start_primary(&next, &member(Slot::A), &DesktopTunnelOptions::default())
            .unwrap();
        assert_eq!(native.borrow().starts, [2, 0]);
        let current = s.borrow().owners[0].clone().unwrap();
        assert_eq!(current.intent.scope, next);
        assert_ne!(current.proof, old.proof);
        second.close(&next).unwrap();
    }

    #[test]
    fn replacement_failed_or_lost_owner_cas_keeps_exact_prior_and_cleanup_never_restarts() {
        for (fail, lost) in [
            (Some(1), None),
            (None, Some(1)),
            (Some(2), None),
            (None, Some(2)),
            (None, Some(3)),
        ] {
            let s = Rc::new(RefCell::new(State::default()));
            let native = Rc::new(RefCell::new(Native::default()));
            s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
            let mut pair = SessionNativePair::new(
                scope(),
                RetainedIo::new(s.clone(), native.clone()),
                Disk(s.clone()),
            )
            .unwrap();
            pair.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
                .unwrap();
            pair.attach(&scope(), &member(Slot::B)).unwrap();
            pair.remove_standby(&scope(), Slot::B).unwrap();
            let prior = s.borrow().owners[1].clone().unwrap();
            s.borrow_mut().owner_saves = 0;
            s.borrow_mut().fail_owner_save = fail;
            s.borrow_mut().lost_owner_save = lost;
            assert!(pair.attach(&scope(), &member(Slot::B)).is_err());
            assert_eq!(
                s.borrow().saved.as_ref().unwrap().members[1]
                    .as_ref()
                    .unwrap()
                    .prior_stopped,
                Some(prior.clone())
            );
            s.borrow_mut().fail_owner_save = None;
            s.borrow_mut().lost_owner_save = None;
            let starts = native.borrow().starts;
            let saved = s.borrow().saved.clone().unwrap();
            drop(pair);
            let io = RetainedIo::recover(s.clone(), native.clone(), &saved);
            let mut cleanup =
                SessionNativePair::recover_for_cleanup(scope(), io, Disk(s.clone()), saved)
                    .unwrap();
            cleanup.close(&scope()).unwrap();
            assert_eq!(native.borrow().starts, starts);
            assert_eq!(native.borrow().live, [None, None]);
            if fail == Some(1) {
                assert_eq!(s.borrow().owners[1], Some(prior));
            }
        }
    }

    #[test]
    fn pair_and_config_publication_crashes_keep_retained_slot_cleanup_only() {
        for boundary in 0..4 {
            let s = Rc::new(RefCell::new(State::default()));
            let native = Rc::new(RefCell::new(Native::default()));
            s.borrow_mut().guard = Some(Model::empty(scope()).unwrap());
            let mut pair = SessionNativePair::new(
                scope(),
                RetainedIo::new(s.clone(), native.clone()),
                Disk(s.clone()),
            )
            .unwrap();
            pair.start_primary(&scope(), &member(Slot::A), &DesktopTunnelOptions::default())
                .unwrap();
            pair.attach(&scope(), &member(Slot::B)).unwrap();
            pair.remove_standby(&scope(), Slot::B).unwrap();
            let old_config = native.borrow().configs[1];
            match boundary {
                0 => s.borrow_mut().fail_save = true,
                1 => s.borrow_mut().lost_pair_save = true,
                2 => native.borrow_mut().fail_config = true,
                _ => native.borrow_mut().lost_config = true,
            }
            let mut replacement = member(Slot::B);
            replacement.configuration = nelomai_client_tunnel::TunnelConfiguration::new(
                "[Interface]\nPrivateKey = new-secret\n[Peer]\n".into(),
            );
            assert!(pair.attach(&scope(), &replacement).is_err());
            s.borrow_mut().fail_save = false;
            native.borrow_mut().fail_config = false;
            native.borrow_mut().lost_config = false;
            let expected_config = native.borrow().configs[1];
            if boundary < 3 {
                assert_eq!(expected_config, old_config);
            } else {
                assert_ne!(expected_config, old_config);
            }
            let saved = s.borrow().saved.clone().unwrap();
            drop(pair);
            let io = RetainedIo::recover(s.clone(), native.clone(), &saved);
            let mut cleanup =
                SessionNativePair::recover_for_cleanup(scope(), io, Disk(s.clone()), saved)
                    .unwrap();
            cleanup.close(&scope()).unwrap();
            assert_eq!(native.borrow().starts, [1, 1]);
            assert_eq!(native.borrow().live, [None, None]);
            assert_eq!(native.borrow().configs[1], expected_config);
        }
    }
}
