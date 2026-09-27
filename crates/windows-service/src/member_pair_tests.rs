use super::*;
use nelomai_contracts::RuntimeSlot;
use std::{cell::RefCell, rc::Rc};

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
    fail_routes: bool,
    fail_save: bool,
    lost_pair_save: bool,
    fail_guard: bool,
    fail_guard_read: bool,
    guard_observation: Option<crate::member_guard::Snapshot>,
    fail_permit_close: bool,
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
                    engine: "/trusted/engine.exe".into(),
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
    fn guard_exchange(&mut self, p: &ExchangePlan) -> io::Result<()> {
        let mut s = self.0.borrow_mut();
        assert!(s.saved.as_ref().unwrap().pending_guard.is_some());
        assert_eq!(s.guard.as_ref().unwrap().expected, p.expected.expected);
        if s.fail_guard {
            return Err(failed());
        }
        s.events.push(format!("guard:{:?}", p.desired.active));
        s.guard = Some(p.desired.clone());
        Ok(())
    }
    fn close_permits(&mut self) -> io::Result<()> {
        let mut s = self.0.borrow_mut();
        s.events.push("withdraw".into());
        if s.fail_permit_close {
            return Err(failed());
        }
        s.guard = Some(s.guard.as_ref().unwrap().without_probes().unwrap());
        Ok(())
    }
    fn select_routes(
        &mut self,
        active: Slot,
        _: &[Option<MemberRecord>; 2],
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
        Ok(())
    }
    fn cleanup_routes(&mut self) -> io::Result<()> {
        let mut s = self.0.borrow_mut();
        s.events.push("routes_clean".into());
        if s.fail_cleanup_routes {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        s.route_active = None;
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
    assert!(p.rebind_pair(&scope()).unwrap());
    assert!(p.open_probe(Slot::A).is_ok());
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
            p.record.members[0]
                .as_mut()
                .unwrap()
                .dns
                .push("9.9.9.9".parse().unwrap());
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
    #[derive(Default)]
    struct Native {
        configs: [Option<[u8; 32]>; 2],
        live: [Option<owner::NativeProof>; 2],
        starts: [u64; 2],
        fail_config: bool,
        lost_config: bool,
        fail_inspect: bool,
    }
    type NativeState = Rc<RefCell<Native>>;
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
                service: live.map(|p| owner::ServiceObservation {
                    exact_spec: true,
                    process: Some(p.process),
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
            Ok(())
        }
        fn stop_slot(
            &mut self,
            intent: &owner::Intent,
            proof: Option<&owner::NativeProof>,
            _: &owner::Observation,
        ) -> owner::Result<()> {
            let mut s = self.0.borrow_mut();
            let i = slot_shared(intent.slot).idx();
            if s.live[i].as_ref() != proof {
                return Err(owner::OwnerError::Conflict);
            }
            s.live[i] = None;
            Ok(())
        }
        fn rebind(
            &mut self,
            _: &owner::Intent,
            _: &owner::NativeProof,
            _: &owner::Observation,
        ) -> owner::Result<()> {
            Err(owner::OwnerError::Native)
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
        type Socket = Socket;
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
                "/trusted/engine.exe".into(),
                m.configuration.expose(),
                JournalIo(self.base.0.clone()),
                NativeIo(self.native.clone()),
            )
            .map_err(io::Error::other)?;
            let mut record = self.base.prepare_member(scope, m)?;
            record.owner.intent = owner.intent().clone();
            record.prior_stopped = owner.prior_stopped().map_err(io::Error::other)?;
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
            self.base.observe(m)
        }
        fn fingerprint(&mut self, m: &[Option<MemberRecord>; 2]) -> io::Result<String> {
            self.base.fingerprint(m)
        }
        fn open_base(&mut self, m: &MemberRecord) -> io::Result<(Socket, ProbeTuple)> {
            self.verify(m)?;
            self.base.open_base(m)
        }
        fn guard_snapshot(&mut self) -> io::Result<crate::member_guard::Snapshot> {
            self.base.guard_snapshot()
        }
        fn guard_exchange(&mut self, p: &ExchangePlan) -> io::Result<()> {
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
            self.base.select_routes(a, m, o)
        }
        fn cleanup_routes(&mut self) -> io::Result<()> {
            self.base.cleanup_routes()
        }
        fn read_dns(&mut self, m: &MemberRecord) -> io::Result<DnsSnapshot> {
            self.base.read_dns(m)
        }
        fn exchange_dns(&mut self, a: &DnsSnapshot, b: &DnsSnapshot) -> io::Result<()> {
            self.base.exchange_dns(a, b)
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
