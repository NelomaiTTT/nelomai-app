use nelomai_client_tunnel::{redundancy::control::*, DesktopTunnelOptions};
use nelomai_client_tunnel::{
    redundancy::{
        driver::*, evidence::NativeHealthSample, protocol::*, session::*, ProbeDatagram,
        SessionScope, Slot,
    },
    TunnelConfiguration,
};
use nelomai_contracts::*;
use std::{cell::RefCell, io, rc::Rc};

const A: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const B: &str = "bbbbbbbb-0000-4000-8000-000000000002";
const FOREIGN: &str = "cccccccc-0000-4000-8000-000000000003";
fn ix(slot: Slot) -> usize {
    if slot == Slot::A {
        0
    } else {
        1
    }
}
fn scope() -> SessionScope {
    SessionScope {
        runtime: RuntimeSlot::Latest,
        runtime_generation: 10,
        session_id: "11111111-1111-4111-8111-111111111111".into(),
        connection_generation: 7,
    }
}
fn member(slot: Slot) -> Member {
    Member {
        slot,
        lease_id: if slot == Slot::A { A } else { B }.into(),
        configuration: TunnelConfiguration::new("private fake configuration".into()),
        probe: RedundantHealthProbe {
            kind: HealthProbeKind::DnsA,
            target_ipv4: "9.9.9.9".parse().unwrap(),
            query_name: "example.com".into(),
            timeout_ms: 4000,
        },
    }
}
fn start(warm: bool) -> Command {
    Command::Start {
        scope: scope(),
        primary: member(Slot::A),
        role_generation: 0,
        membership_generation: 0,
        warm_stop_v1: warm,
        options: DesktopTunnelOptions::default(),
    }
}
#[derive(Default)]
struct World {
    events: Vec<String>,
    saved: Vec<SessionSnapshot>,
    tx: [u64; 2],
    rx: [u64; 2],
    lost: [bool; 2],
    dead: [bool; 2],
    native: [bool; 2],
    fail_start: bool,
    fail_attach: bool,
    fail_remove: bool,
    fail_close: bool,
    fail_select: bool,
    fail_save: bool,
    lose_save_ack: bool,
    closed_scopes: Vec<SessionScope>,
    fail_rebind: bool,
    validated: bool,
    drops: usize,
    drops_by_slot: [usize; 2],
    removals: Vec<(Slot, SessionSnapshot, [usize; 2])>,
}
struct Socket {
    world: Rc<RefCell<World>>,
    slot: Slot,
    query: Vec<u8>,
    replied: bool,
}
impl Drop for Socket {
    fn drop(&mut self) {
        let mut world = self.world.borrow_mut();
        world.drops += 1;
        world.drops_by_slot[ix(self.slot)] += 1;
    }
}
impl ProbeDatagram for Socket {
    fn send(&mut self, p: &[u8]) -> io::Result<usize> {
        self.query = p.to_vec();
        self.world.borrow_mut().tx[ix(self.slot)] += 1;
        Ok(p.len())
    }
    fn receive(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if self.replied || self.world.borrow().lost[ix(self.slot)] {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let mut reply = self.query.clone();
        reply[2] = 0x81;
        reply[3] = 0x80;
        reply[7] = 1;
        reply.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4]);
        p[..reply.len()].copy_from_slice(&reply);
        self.replied = true;
        self.world.borrow_mut().rx[ix(self.slot)] += 1;
        Ok(reply.len())
    }
}
struct Pair(Rc<RefCell<World>>);
impl NativePair for Pair {
    type Socket = Socket;
    fn sample(&mut self, slot: Slot) -> Option<NativeHealthSample> {
        let world = self.0.borrow();
        let i = ix(slot);
        Some(NativeHealthSample {
            admitted: world.native[i] && !world.dead[i],
            closed: world.dead[i],
            handshake_fresh: !world.dead[i],
            tx_packets: world.tx[i],
            rx_data_packets: world.rx[i],
        })
    }
    fn open_probe(&mut self, slot: Slot) -> io::Result<(Socket, String)> {
        Ok((
            Socket {
                world: self.0.clone(),
                slot,
                query: vec![],
                replied: false,
            },
            "example.com".into(),
        ))
    }
    fn select_active(&mut self, _: &SessionScope, slot: Slot) -> io::Result<()> {
        self.0.borrow_mut().events.push(format!("select {slot:?}"));
        if self.0.borrow().fail_select {
            return Err(io::Error::other("select failed"));
        }
        Ok(())
    }
    fn close(&mut self, scope: &SessionScope) -> io::Result<()> {
        let mut world = self.0.borrow_mut();
        world.events.push("close".into());
        world.closed_scopes.push(scope.clone());
        if world.fail_close {
            return Err(io::Error::other("close failed"));
        }
        world.native = [false; 2];
        Ok(())
    }
}
impl PairControl for Pair {
    fn metrics(&self, slot: Slot) -> io::Result<nelomai_client_tunnel::TunnelMetrics> {
        self.0.borrow_mut().events.push(format!("metrics {slot:?}"));
        Ok(nelomai_client_tunnel::TunnelMetrics {
            received_bytes: if slot == Slot::A { 10 } else { 20 },
            sent_bytes: 3,
            latest_handshake_epoch_millis: None,
            probe_target: None,
        })
    }
    fn physical_network_fingerprint(&self) -> io::Result<String> {
        self.0.borrow_mut().events.push("pair fingerprint".into());
        Ok("ab".repeat(32))
    }
    fn start_primary(
        &mut self,
        _: &SessionScope,
        member: &Member,
        _: &DesktopTunnelOptions,
    ) -> io::Result<()> {
        let mut world = self.0.borrow_mut();
        assert_eq!(world.saved.last().unwrap().phase, SessionPhase::Starting);
        world.events.push(format!("start {:?}", member.slot));
        world.native[ix(member.slot)] = true;
        if world.fail_start {
            Err(io::Error::other("start failed"))
        } else {
            Ok(())
        }
    }
    fn attach(&mut self, _: &SessionScope, member: &Member) -> io::Result<()> {
        let mut world = self.0.borrow_mut();
        world.events.push(format!("attach {:?}", member.slot));
        world.native[ix(member.slot)] = true;
        if world.fail_attach {
            Err(io::Error::other("attach failed"))
        } else {
            Ok(())
        }
    }
    fn remove_standby(&mut self, _: &SessionScope, slot: Slot) -> io::Result<()> {
        let mut world = self.0.borrow_mut();
        world.events.push(format!("remove {slot:?}"));
        let saved = world.saved.last().unwrap().clone();
        let drops = world.drops_by_slot;
        world.removals.push((slot, saved, drops));
        if world.fail_remove {
            return Err(io::Error::other("remove failed"));
        }
        world.native[ix(slot)] = false;
        Ok(())
    }
    fn rebind_pair(&mut self, _: &SessionScope) -> io::Result<bool> {
        let mut world = self.0.borrow_mut();
        let epoch = world.saved.last().unwrap().network_epoch;
        world.events.push(format!("rebind epoch {epoch}"));
        if world.fail_rebind {
            Err(io::Error::other("rebind failed"))
        } else {
            Ok(world.validated)
        }
    }
    fn cleanup_pending(&self) -> bool {
        let w = self.0.borrow();
        w.fail_close && w.native.iter().any(|v| *v)
    }
}
struct Store(Rc<RefCell<World>>);
impl SessionStore for Store {
    fn save(&mut self, state: &SessionSnapshot) -> io::Result<()> {
        let mut world = self.0.borrow_mut();
        world.events.push(format!("save {:?}", state.phase));
        if world.fail_save {
            return Err(io::Error::other("save failed"));
        }
        world.saved.push(state.clone());
        if world.lose_save_ack {
            world.lose_save_ack = false;
            return Err(io::Error::other("save acknowledgement lost"));
        }
        Ok(())
    }
}
type Owner = SessionControl<Pair, Store>;
fn prepared(warm: bool) -> (Owner, Rc<RefCell<World>>) {
    let world = Rc::new(RefCell::new(World::default()));
    let owner = Owner::prepare(
        RuntimeSlot::Latest,
        &start(warm),
        Pair(world.clone()),
        Store(world.clone()),
        0,
    )
    .unwrap();
    (owner, world)
}
fn running() -> (Owner, Rc<RefCell<World>>) {
    let (mut owner, world) = prepared(true);
    owner
        .start_primary(&member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    (owner, world)
}

#[test]
fn locally_retiring_inactive_preserves_server_membership_until_candidate_commit() {
    let (mut owner, world) = running();
    attach(&mut owner, false, 0).unwrap();
    let before = owner.snapshot();
    owner
        .execute(
            Command::RetireInactive {
                scope: scope(),
                slot: Slot::B,
                lease_id: B.into(),
                expected_revision: before.session.local_revision,
                expected_network_epoch: before.session.network_epoch,
                expected_membership_generation: 0,
            },
            1,
        )
        .unwrap();
    let retired = owner.snapshot();
    assert_eq!(retired.leases, [Some(A.into()), None]);
    assert_eq!(retired.current_leases, [Some(A.into()), Some(B.into())]);
    assert_eq!(retired.session.membership_generation, 0);
    assert_eq!(retired.session.installed, [true, false]);
    assert!(world.borrow().native[0]);
    assert!(!world.borrow().native[1]);
    assert!(owner
        .execute(
            Command::RetireInactive {
                scope: scope(),
                slot: Slot::A,
                lease_id: A.into(),
                expected_revision: retired.session.local_revision,
                expected_network_epoch: retired.session.network_epoch,
                expected_membership_generation: 0,
            },
            2
        )
        .is_err());
    let mut replacement = member(Slot::B);
    replacement.lease_id = FOREIGN.into();
    owner
        .execute(
            Command::StageCandidate {
                scope: scope(),
                member: replacement,
                expected_revision: retired.session.local_revision,
                expected_network_epoch: retired.session.network_epoch,
                expected_membership_generation: 0,
            },
            3,
        )
        .unwrap();
    let staged = owner.snapshot();
    assert_eq!(staged.leases[1].as_deref(), Some(FOREIGN));
    assert_eq!(staged.current_leases[1].as_deref(), Some(B));
    assert_eq!(staged.session.committed, [true, false]);
}
#[test]
fn reinstated_current_member_requires_same_membership_and_fresh_probe_before_commit() {
    let (mut owner, _) = running();
    attach(&mut owner, false, 0).unwrap();
    let s = owner.snapshot().session;
    owner
        .execute(
            Command::RetireInactive {
                scope: scope(),
                slot: Slot::B,
                lease_id: B.into(),
                expected_revision: s.local_revision,
                expected_network_epoch: s.network_epoch,
                expected_membership_generation: 0,
            },
            1,
        )
        .unwrap();
    attach(&mut owner, true, 2).unwrap();
    for now in (100..=16000).step_by(100) {
        owner.tick(now).unwrap();
    }
    let snap = owner.snapshot();
    assert!(snap.standby_ready);
    let session = view(&snap, true);
    assert_eq!(session.membership_generation, 0);
    owner
        .execute(
            Command::CommitCandidate {
                scope: scope(),
                slot: Slot::B,
                expected_revision: snap.session.local_revision,
                expected_network_epoch: snap.session.network_epoch,
                session,
            },
            16000,
        )
        .unwrap();
    assert!(owner.snapshot().session.committed[1]);
    assert_eq!(owner.snapshot().session.membership_generation, 0);
}
fn attach(owner: &mut Owner, candidate: bool, now: u64) -> io::Result<Snapshot> {
    let s = owner.snapshot().session;
    let command = if candidate {
        Command::StageCandidate {
            scope: s.scope,
            member: member(s.active.other()),
            expected_revision: s.local_revision,
            expected_network_epoch: s.network_epoch,
            expected_membership_generation: s.membership_generation,
        }
    } else {
        Command::Attach {
            scope: s.scope,
            member: member(s.active.other()),
            expected_revision: s.local_revision,
            expected_network_epoch: s.network_epoch,
            expected_membership_generation: s.membership_generation,
            membership_generation: s.membership_generation,
        }
    };
    owner.execute(command, now)
}
fn view(snapshot: &Snapshot, include_candidate: bool) -> RedundantSessionView {
    let map = |i: usize| {
        if include_candidate || snapshot.session.committed[i] {
            snapshot.leases[i].clone()
        } else {
            None
        }
    };
    RedundantSessionView {
        session_id: snapshot.session.scope.session_id.clone(),
        state: RedundantSessionState::Connected,
        active_lease_id: snapshot.leases[ix(snapshot.session.active)].clone(),
        slot_a_lease_id: map(0),
        slot_b_lease_id: map(1),
        standby_desired: true,
        role_generation: snapshot.session.role_generation,
        membership_generation: snapshot.session.membership_generation,
        reason: None,
    }
}
fn confirm(owner: &mut Owner, response: RedundantRoleResponse, now: u64) -> io::Result<Snapshot> {
    let s = owner.snapshot().session;
    owner.execute(
        Command::ConfirmRole {
            scope: s.scope,
            expected_revision: s.local_revision,
            expected_network_epoch: s.network_epoch,
            response,
        },
        now,
    )
}
fn response(owner: &mut Owner) -> RedundantRoleResponse {
    let snapshot = owner.snapshot();
    let mut session = view(&snapshot, false);
    if !snapshot.session.role_confirmed {
        session.role_generation += 1;
    }
    RedundantRoleResponse {
        api_version: ApiVersion::V1,
        request_id: "fake".into(),
        action: RedundantRoleAction::Acknowledged,
        local_active_lease_id: snapshot.leases[ix(snapshot.session.active)]
            .clone()
            .unwrap(),
        session,
    }
}
fn promote(owner: &mut Owner, world: &Rc<RefCell<World>>) {
    attach(owner, false, 0).unwrap();
    owner.tick(0).unwrap();
    owner.tick(100).unwrap();
    world.borrow_mut().dead[0] = true;
    for now in (200..=3500).step_by(100) {
        owner.tick(now).unwrap();
    }
    assert_eq!(owner.snapshot().session.active, Slot::B);
}

#[test]
fn diagnostics_use_current_promoted_active_and_reject_nonrunning_phases() {
    let (mut owner, world) = prepared(true);
    assert!(owner.metrics().is_err());
    assert!(owner.physical_network_fingerprint().is_err());
    owner
        .start_primary(&member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    assert_eq!(owner.metrics().unwrap().received_bytes, 10);
    assert_eq!(
        owner.physical_network_fingerprint().unwrap(),
        "ab".repeat(32)
    );
    promote(&mut owner, &world);
    assert_eq!(owner.metrics().unwrap().received_bytes, 20);
    owner.execute(prepare_stop(scope()), 10_000).unwrap();
    world.borrow_mut().events.clear();
    assert!(owner.metrics().is_err());
    assert!(owner.physical_network_fingerprint().is_err());
    assert!(world.borrow().events.is_empty());
    owner
        .execute(Command::Stop { scope: scope() }, 10_001)
        .unwrap();
    world.borrow_mut().events.clear();
    assert!(owner.metrics().is_err());
    assert!(owner.physical_network_fingerprint().is_err());
    assert!(world.borrow().events.is_empty());
}

#[test]
fn discovery_invalidation_is_scoped_cancels_queries_and_suspends_health_without_close() {
    let (mut owner, world) = running();
    owner.tick(0).unwrap();
    let before = owner.snapshot();
    let events = world.borrow().events.clone();
    let mut wrong = scope();
    wrong.connection_generation += 1;
    assert!(owner.invalidate_network(&wrong, 100).is_err());
    assert_eq!(owner.snapshot(), before);
    assert_eq!(world.borrow().events, events);
    owner.invalidate_network(&scope(), 100).unwrap();
    assert!(!owner.network_validated());
    assert_eq!(world.borrow().drops, 1);
    assert!(world.borrow().closed_scopes.is_empty());
    let tx = world.borrow().tx;
    owner.tick(200).unwrap();
    owner.tick(10_000).unwrap();
    assert_eq!(world.borrow().tx, tx);
    assert_eq!(
        owner.snapshot().session.network_epoch,
        before.session.network_epoch + 1
    );
    assert!(!owner.snapshot().primary_ready);
}

fn stalled_primary() -> (Owner, Rc<RefCell<World>>) {
    let (mut owner, world) = running();
    world.borrow_mut().dead[0] = true;
    assert!(owner.tick(0).unwrap().stalled);
    (owner, world)
}

fn snapshot_stalled(owner: &mut Owner) -> bool {
    // Exercise the required wire field even before the new contract compiles.
    serde_json::to_value(owner.snapshot()).unwrap()["stalled"] == true
}

#[test]
fn stalled_snapshot_is_sticky_across_status_and_empty_ticks_then_primary_recovery() {
    let (mut owner, world) = stalled_primary();
    assert!(snapshot_stalled(&mut owner));
    for now in [100, 200, 300] {
        assert!(!owner.tick(now).unwrap().stalled);
        let before = world.borrow().events.clone();
        let snapshot = owner
            .execute(Command::Status { scope: scope() }, now)
            .unwrap();
        assert_eq!(serde_json::to_value(snapshot).unwrap()["stalled"], true);
        assert_eq!(world.borrow().events, before);
    }
    world.borrow_mut().dead[0] = false;
    for now in (400..=5000).step_by(100) {
        owner.tick(now).unwrap();
    }
    assert!(owner.snapshot().primary_ready);
    assert!(!snapshot_stalled(&mut owner));
    world.borrow_mut().dead[0] = true;
    assert!(
        owner.tick(5500).unwrap().stalled,
        "recovered primary starts a new loss episode"
    );
    assert!(snapshot_stalled(&mut owner));
    assert!(world.borrow().closed_scopes.is_empty());
}

#[test]
fn stalled_pair_can_switch_to_later_recovered_current_reserve_without_restart() {
    let (mut owner, world) = running();
    attach(&mut owner, false, 0).unwrap();
    world.borrow_mut().dead = [true; 2];
    assert!(owner.tick(0).unwrap().stalled);
    assert!(snapshot_stalled(&mut owner));
    world.borrow_mut().dead[1] = false;
    let mut switches = vec![];
    for now in (100..=10000).step_by(100) {
        if let Some(slot) = owner.tick(now).unwrap().switched {
            switches.push(slot);
        }
    }
    assert_eq!(switches, [Slot::B]);
    assert_eq!(owner.snapshot().session.active, Slot::B);
    assert!(!snapshot_stalled(&mut owner));
    assert!(world.borrow().closed_scopes.is_empty());
}

#[test]
fn stalled_candidate_cannot_promote_or_clear_signal_until_current_commit() {
    let (mut owner, world) = stalled_primary();
    attach(&mut owner, true, 100).unwrap();
    for now in (100..=20000).step_by(100) {
        assert!(owner.tick(now).unwrap().switched.is_none());
    }
    assert!(snapshot_stalled(&mut owner));
    let snapshot = owner.snapshot();
    assert!(snapshot.standby_ready);
    let mut session = view(&snapshot, true);
    session.membership_generation += 1;
    owner
        .execute(
            Command::CommitCandidate {
                scope: scope(),
                slot: Slot::B,
                expected_revision: snapshot.session.local_revision,
                expected_network_epoch: snapshot.session.network_epoch,
                session,
            },
            20000,
        )
        .unwrap();
    assert!(!snapshot_stalled(&mut owner));
    // Commit eligibility is not a fresh failover query; keep the existing
    // background cadence and wait for the next exact post-incident success.
    let mut switches = vec![];
    for now in (20100..=36000).step_by(100) {
        if let Some(slot) = owner.tick(now).unwrap().switched {
            switches.push(slot);
        }
    }
    assert_eq!(switches, [Slot::B]);
    assert!(world.borrow().closed_scopes.is_empty());
}

#[test]
fn stalled_clears_on_current_attach_but_not_failed_or_stale_membership_commands() {
    let (mut owner, world) = stalled_primary();
    world.borrow_mut().fail_attach = true;
    assert!(attach(&mut owner, false, 100).is_err());
    assert!(snapshot_stalled(&mut owner));
    world.borrow_mut().fail_attach = false;
    let state = owner.snapshot().session;
    assert!(owner
        .execute(
            Command::Attach {
                scope: scope(),
                member: member(Slot::B),
                expected_revision: state.local_revision,
                expected_network_epoch: state.network_epoch + 1,
                expected_membership_generation: 0,
                membership_generation: 0,
            },
            100
        )
        .is_err());
    assert!(snapshot_stalled(&mut owner));
    attach(&mut owner, false, 100).unwrap();
    assert!(!snapshot_stalled(&mut owner));
}

#[test]
fn stalled_invalidated_epoch_and_old_probes_do_not_clear_until_new_validation() {
    let (mut owner, world) = stalled_primary();
    let old = owner.snapshot().session;
    owner.invalidate_network(&scope(), 100).unwrap();
    // Old pending success becomes available, but its cancelled query is not evidence.
    world.borrow_mut().dead[0] = false;
    for now in [200, 5000] {
        assert!(!owner.tick(now).unwrap().primary_ready);
    }
    assert!(snapshot_stalled(&mut owner));
    let mut foreign = scope();
    foreign.connection_generation += 1;
    assert!(owner
        .execute(Command::NetworkChanged { scope: foreign }, 5000)
        .is_err());
    assert!(snapshot_stalled(&mut owner));
    assert!(owner
        .execute(
            Command::Attach {
                scope: scope(),
                member: member(Slot::B),
                expected_revision: old.local_revision,
                expected_network_epoch: old.network_epoch,
                expected_membership_generation: 0,
                membership_generation: 0,
            },
            5000
        )
        .is_err());
    assert!(snapshot_stalled(&mut owner));
    for fail in [true, false] {
        world.borrow_mut().fail_rebind = fail;
        let result = owner.execute(Command::NetworkChanged { scope: scope() }, 5000);
        assert_eq!(result.is_err(), fail);
        assert!(snapshot_stalled(&mut owner));
    }
    world.borrow_mut().validated = true;
    owner
        .execute(Command::NetworkChanged { scope: scope() }, 5000)
        .unwrap();
    assert!(!snapshot_stalled(&mut owner));
    assert!(!owner.snapshot().primary_ready);
}

fn recovery_stop(snapshot: &Snapshot) -> Command {
    serde_json::from_value(serde_json::json!({"action":"prepare_recovery_stop",
        "scope":snapshot.session.scope,"expected_revision":snapshot.session.local_revision,
        "expected_network_epoch":snapshot.session.network_epoch}))
    .unwrap()
}

#[test]
fn terminal_promotion_failure_latches_stalled_and_authorizes_exact_cold_retry() {
    for fail_close in [false, true] {
        let (mut owner, world) = running();
        attach(&mut owner, false, 0).unwrap();
        for now in (0..=16000).step_by(100) {
            owner.tick(now).unwrap();
        }
        {
            let mut w = world.borrow_mut();
            w.dead[0] = true;
            w.fail_select = true;
            w.fail_close = fail_close;
        }
        let mut failed = false;
        for now in (16100..=20000).step_by(100) {
            let before = owner.snapshot();
            if owner.tick(now).is_err() {
                assert!(
                    !before.stalled,
                    "the native select failure must create the signal"
                );
                let frozen = owner.snapshot();
                assert_eq!(
                    frozen.session.phase,
                    if fail_close {
                        SessionPhase::Stopping
                    } else {
                        SessionPhase::Stopped
                    }
                );
                assert!(frozen.stalled);
                assert!(!frozen.primary_ready && !frozen.standby_ready);
                assert_eq!(world.borrow().closed_scopes, [scope()]);
                let events = world.borrow().events.clone();
                assert_eq!(owner.execute(recovery_stop(&frozen), now).unwrap(), frozen);
                assert_eq!(world.borrow().events, events, "cold retry is read-only");
                failed = true;
                break;
            }
        }
        assert!(failed, "real healthy reserve must reach native promotion");
    }
    let (mut fresh, _) = running();
    assert!(!fresh.snapshot().stalled);
}

#[test]
fn terminal_failure_signal_excludes_user_stops_startup_and_nonterminal_errors() {
    for prepare in [false, true] {
        for (fail_save, fail_close) in [(false, false), (true, false), (false, true), (true, true)]
        {
            let (mut owner, world) = running();
            world.borrow_mut().fail_save = fail_save;
            world.borrow_mut().fail_close = fail_close;
            let command = if prepare {
                Command::PrepareStop { scope: scope() }
            } else {
                Command::Stop { scope: scope() }
            };
            assert_eq!(
                owner.execute(command, 1).is_err(),
                fail_save || (!prepare && fail_close)
            );
            if prepare {
                let _ = owner.tick(1001);
            }
            assert!(!owner.snapshot().stalled);
            let snapshot = owner.snapshot();
            assert!(owner.execute(recovery_stop(&snapshot), 2).is_err());
        }
    }
    let (mut owner, world) = prepared(false);
    world.borrow_mut().fail_start = true;
    assert!(owner
        .start_primary(&member(Slot::A), &DesktopTunnelOptions::default())
        .is_err());
    assert!(!owner.snapshot().stalled);
    let (mut owner, world) = running();
    let s = owner.snapshot().session;
    assert!(owner
        .execute(
            Command::Attach {
                scope: scope(),
                member: member(Slot::B),
                expected_revision: s.local_revision + 1,
                expected_network_epoch: s.network_epoch,
                expected_membership_generation: 0,
                membership_generation: 0
            },
            1
        )
        .is_err());
    world.borrow_mut().fail_rebind = true;
    assert!(owner
        .execute(Command::NetworkChanged { scope: scope() }, 2)
        .is_err());
    assert_eq!(owner.snapshot().session.phase, SessionPhase::Running);
    assert!(!owner.snapshot().stalled);
}

#[test]
fn terminal_network_invalidation_save_failure_is_recoverable_but_not_a_new_start() {
    let (mut owner, world) = running();
    world.borrow_mut().fail_save = true;
    assert!(owner.invalidate_network(&scope(), 1).is_err());
    let frozen = owner.snapshot();
    assert_eq!(frozen.session.phase, SessionPhase::Stopped);
    assert!(frozen.stalled);
    let events = world.borrow().events.clone();
    assert_eq!(owner.execute(recovery_stop(&frozen), 2).unwrap(), frozen);
    assert_eq!(world.borrow().events, events);
    assert!(owner.execute(start(false), 3).is_err());
}

#[test]
fn recovery_stop_freezes_exact_stalled_pair_and_keeps_existing_close_deadline() {
    let (mut owner, world) = stalled_primary();
    let before = owner.snapshot();
    let frozen = owner.execute(recovery_stop(&before), 100).unwrap();
    assert_eq!(frozen.session.phase, SessionPhase::Stopping);
    assert_eq!(frozen.session.active, Slot::A);
    assert_eq!(
        frozen.session.local_revision,
        before.session.local_revision + 1
    );
    assert!(snapshot_stalled(&mut owner));
    assert_eq!(world.borrow().saved.last(), Some(&frozen.session));
    assert!(world.borrow().closed_scopes.is_empty());
    let events = world.borrow().events.clone();
    assert_eq!(owner.execute(recovery_stop(&frozen), 100).unwrap(), frozen);
    assert_eq!(world.borrow().events, events);
    owner.tick(1099).unwrap();
    assert!(world.borrow().closed_scopes.is_empty());
    owner.tick(1100).unwrap();
    assert_eq!(world.borrow().closed_scopes, [scope()]);
    let stopped = owner.snapshot();
    let events = world.borrow().events.clone();
    assert_eq!(
        owner.execute(recovery_stop(&stopped), 1100).unwrap(),
        stopped
    );
    assert_eq!(world.borrow().events, events);
}

#[test]
fn recovery_stop_stale_scope_revision_epoch_and_healthy_or_unproven_primary_have_no_effects() {
    let (mut owner, world) = stalled_primary();
    let before = owner.snapshot();
    for wrong in 0..4 {
        let mut wire = serde_json::to_value(recovery_stop(&before)).unwrap();
        match wrong {
            0 => wire["scope"]["connection_generation"] = 8.into(),
            1 => wire["expected_revision"] = (before.session.local_revision + 1).into(),
            2 => wire["expected_network_epoch"] = (before.session.network_epoch + 1).into(),
            _ => wire["expected_revision"] = 0.into(),
        }
        let events = world.borrow().events.clone();
        assert!(owner
            .execute(serde_json::from_value(wire).unwrap(), 100)
            .is_err());
        assert_eq!(owner.snapshot(), before);
        assert_eq!(world.borrow().events, events);
    }
    world.borrow_mut().dead[0] = false;
    for now in (100..=5000).step_by(100) {
        owner.tick(now).unwrap();
    }
    assert!(owner.snapshot().primary_ready);
    let healthy = owner.snapshot();
    let events = world.borrow().events.clone();
    assert!(owner.execute(recovery_stop(&healthy), 5000).is_err());
    assert!(owner.execute(recovery_stop(&before), 5000).is_err());
    assert_eq!(owner.snapshot(), healthy);
    assert_eq!(world.borrow().events, events);
    let (mut owner, world) = running();
    let fresh = owner.snapshot();
    let events = world.borrow().events.clone();
    assert!(owner.execute(recovery_stop(&fresh), 0).is_err());
    assert_eq!(world.borrow().events, events);
}

#[test]
fn recovery_stop_cannot_freeze_after_native_failover_or_invalidated_epoch() {
    let (mut owner, world) = running();
    attach(&mut owner, false, 0).unwrap();
    world.borrow_mut().dead = [true; 2];
    assert!(owner.tick(0).unwrap().stalled);
    let stale = owner.snapshot();
    world.borrow_mut().dead[1] = false;
    for now in (100..=10000).step_by(100) {
        owner.tick(now).unwrap();
    }
    assert_eq!(owner.snapshot().session.active, Slot::B);
    let events = world.borrow().events.clone();
    assert!(owner.execute(recovery_stop(&stale), 10000).is_err());
    let current = owner.snapshot();
    assert!(owner.execute(recovery_stop(&current), 10000).is_err());
    assert_eq!(world.borrow().events, events);
    let (mut owner, world) = stalled_primary();
    let old = owner.snapshot();
    owner.invalidate_network(&scope(), 100).unwrap();
    let events = world.borrow().events.clone();
    assert!(owner.execute(recovery_stop(&old), 100).is_err());
    let invalidated = owner.snapshot();
    assert!(
        owner.execute(recovery_stop(&invalidated), 100).is_err(),
        "old loss is not validated evidence in a new epoch"
    );
    assert_eq!(world.borrow().events, events);
    assert!(snapshot_stalled(&mut owner));
}

#[test]
fn recovery_stop_lost_save_ack_closes_exact_pair_and_preserves_stalled_signal() {
    let (mut owner, world) = stalled_primary();
    let before = owner.snapshot();
    world.borrow_mut().lose_save_ack = true;
    assert!(owner.execute(recovery_stop(&before), 100).is_err());
    assert_eq!(world.borrow().closed_scopes, [scope()]);
    assert_eq!(owner.snapshot().session.phase, SessionPhase::Stopped);
    assert!(snapshot_stalled(&mut owner));
    let stopped = owner.snapshot();
    let events = world.borrow().events.clone();
    assert_eq!(
        owner.execute(recovery_stop(&stopped), 100).unwrap(),
        stopped
    );
    assert!(owner.execute(recovery_stop(&before), 100).is_err());
    let mut wrong = recovery_stop(&stopped);
    if let Command::PrepareRecoveryStop { scope, .. } = &mut wrong {
        scope.connection_generation += 1;
    }
    assert!(owner.execute(wrong, 100).is_err());
    assert_eq!(world.borrow().events, events);
}

fn prepare_stop(scope: SessionScope) -> Command {
    serde_json::from_value(serde_json::json!({"action":"prepare_stop", "scope":scope})).unwrap()
}

#[test]
fn prepare_stop_freezes_confirmed_b_without_closing_or_later_promotion() {
    let (mut owner, world) = running();
    promote(&mut owner, &world);
    let ack = response(&mut owner);
    confirm(&mut owner, ack, 3500).unwrap();
    let previous = owner.snapshot().session;
    let frozen = owner.execute(prepare_stop(scope()), 3600).unwrap();
    assert_eq!(frozen.session.phase, SessionPhase::Stopping);
    assert_eq!(frozen.session.active, Slot::B);
    assert_eq!(frozen.session.local_revision, previous.local_revision + 1);
    assert_eq!(world.borrow().saved.last(), Some(&frozen.session));
    assert_eq!(world.borrow().native, [true, true]);
    assert!(world.borrow().closed_scopes.is_empty());
    assert!(!frozen.primary_ready && !frozen.standby_ready);
    assert_eq!(owner.warm_slot(), Some(Slot::B));
    world.borrow_mut().dead = [false, true];
    let sent = world.borrow().tx;
    for now in (3700..=4500).step_by(100) {
        let result = owner.tick(now).unwrap();
        assert_eq!(result.switched, None);
        assert!(!result.primary_ready && !result.standby_ready);
    }
    assert_eq!(world.borrow().tx, sent);
    assert_eq!(owner.snapshot(), frozen);
}

#[test]
fn prepare_stop_retry_keeps_revision_and_original_1000ms_deadline() {
    let (mut owner, world) = running();
    attach(&mut owner, false, 0).unwrap();
    owner.tick(0).unwrap(); // two outstanding sockets must be cancelled
    let frozen = owner.execute(prepare_stop(scope()), 100).unwrap();
    assert_eq!(world.borrow().drops_by_slot, [1, 1]);
    let saves = world.borrow().saved.len();
    assert_eq!(owner.execute(prepare_stop(scope()), 1099).unwrap(), frozen);
    assert_eq!(world.borrow().saved.len(), saves);
    owner.tick(1099).unwrap();
    assert!(world.borrow().closed_scopes.is_empty());
    assert_eq!(world.borrow().native, [true, true]);
    owner.tick(1100).unwrap();
    assert_eq!(world.borrow().closed_scopes, [scope()]);
    assert_eq!(world.borrow().native, [false, false]);
    let stopped = owner.snapshot();
    assert_eq!(stopped.session.phase, SessionPhase::Stopped);
    assert_eq!(
        stopped.session.local_revision,
        frozen.session.local_revision
    );
    owner.tick(1200).unwrap();
    assert_eq!(world.borrow().closed_scopes, [scope()]);
}

#[test]
fn explicit_stop_closes_prepared_pair_immediately() {
    let (mut owner, world) = running();
    let frozen = owner.execute(prepare_stop(scope()), 100).unwrap();
    let stopped = owner
        .execute(Command::Stop { scope: scope() }, 101)
        .unwrap();
    assert_eq!(world.borrow().closed_scopes, [scope()]);
    assert_eq!(stopped.session.phase, SessionPhase::Stopped);
    assert_eq!(
        stopped.session.local_revision,
        frozen.session.local_revision
    );
    owner.tick(1100).unwrap();
    assert_eq!(world.borrow().closed_scopes, [scope()]);
}

#[test]
fn prepare_stop_failed_save_or_lost_ack_still_closes_exact_pair() {
    for lost_ack in [false, true] {
        let (mut owner, world) = running();
        world.borrow_mut().fail_save = !lost_ack;
        world.borrow_mut().lose_save_ack = lost_ack;
        assert!(owner.execute(prepare_stop(scope()), 100).is_err());
        assert_eq!(world.borrow().closed_scopes, [scope()]);
        assert_eq!(world.borrow().native, [false, false]);
        assert_eq!(owner.snapshot().session.phase, SessionPhase::Stopped);
        let events = &world.borrow().events;
        let close = events.iter().position(|e| e == "close").unwrap();
        assert_eq!(events[close - 1], "save Stopping");
    }
}

#[test]
fn prepare_stop_stale_scope_has_no_effects() {
    let (mut owner, world) = running();
    let before = owner.snapshot();
    let events = world.borrow().events.clone();
    let mut stale = scope();
    stale.connection_generation += 1;
    assert!(owner.execute(prepare_stop(stale), 100).is_err());
    assert_eq!(owner.snapshot(), before);
    assert_eq!(world.borrow().events, events);
    owner.tick(1100).unwrap();
    assert_eq!(world.borrow().native, [true, false]);
}

#[test]
fn prepare_stop_never_started_has_no_warm_and_blocks_start_install_and_role_ack() {
    let (mut owner, world) = prepared(true);
    owner.execute(prepare_stop(scope()), 100).unwrap();
    assert_eq!(owner.warm_slot(), None);
    let before = world.borrow().events.clone();
    assert!(owner
        .start_primary(&member(Slot::A), &DesktopTunnelOptions::default())
        .is_err());
    assert!(attach(&mut owner, false, 101).is_err());
    assert_eq!(world.borrow().events, before);
    owner.tick(1100).unwrap();
    assert_eq!(owner.warm_slot(), None);

    let (mut owner, world) = running();
    let ack = response(&mut owner);
    owner.execute(prepare_stop(scope()), 100).unwrap();
    let events = world.borrow().events.clone();
    assert!(confirm(&mut owner, ack, 101).is_err());
    assert!(attach(&mut owner, true, 101).is_err());
    assert!(owner
        .execute(Command::NetworkChanged { scope: scope() }, 101)
        .is_err());
    assert_eq!(world.borrow().events, events);
}

#[test]
fn prepare_stop_deadline_cleanup_failure_retries_on_next_tick() {
    let (mut owner, world) = running();
    owner.execute(prepare_stop(scope()), 100).unwrap();
    world.borrow_mut().fail_close = true;
    assert!(owner.tick(1100).is_err());
    assert_eq!(owner.snapshot().session.phase, SessionPhase::Stopping);
    assert!(owner.snapshot().cleanup_pending);
    world.borrow_mut().fail_close = false;
    owner.tick(1200).unwrap();
    assert_eq!(world.borrow().closed_scopes, [scope(), scope()]);
    assert_eq!(world.borrow().native, [false, false]);
}

#[test]
fn prepare_stop_retry_cannot_acknowledge_an_unsaved_freeze_after_failed_close() {
    let (mut owner, world) = running();
    world.borrow_mut().fail_save = true;
    world.borrow_mut().fail_close = true;
    assert!(owner.execute(prepare_stop(scope()), 100).is_err());
    let revision = owner.snapshot().session.local_revision;
    assert!(owner.execute(prepare_stop(scope()), 101).is_err());
    assert_eq!(owner.snapshot().session.local_revision, revision);
    assert_eq!(world.borrow().closed_scopes, [scope(), scope()]);
    world.borrow_mut().fail_save = false;
    world.borrow_mut().fail_close = false;
    owner.tick(102).unwrap();
    assert_eq!(world.borrow().native, [false, false]);
}

#[test]
fn primary_first_persists_starting_before_native_and_readiness_needs_tick() {
    let (mut owner, world) = prepared(true);
    assert_eq!(world.borrow().events, ["save Starting"]);
    assert_eq!(owner.warm_slot(), None);
    let snapshot = owner
        .start_primary(&member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    assert_eq!(
        world.borrow().events,
        ["save Starting", "start A", "save Running"]
    );
    assert_eq!(snapshot.session.installed, [true, false]);
    assert_eq!(snapshot.session.role_generation, 0);
    assert_eq!(snapshot.session.membership_generation, 0);
    assert!(!snapshot.primary_ready);
    assert!(!owner.tick(0).unwrap().primary_ready);
    assert!(owner.tick(100).unwrap().primary_ready);
    assert!(owner.snapshot().primary_ready);
    assert_eq!(owner.snapshot().leases, [Some(A.into()), None]);
}

#[test]
fn invalid_runtime_duplicate_start_and_wrong_primary_have_no_native_effects() {
    let world = Rc::new(RefCell::new(World::default()));
    assert!(Owner::prepare(
        RuntimeSlot::Stable,
        &start(true),
        Pair(world.clone()),
        Store(world.clone()),
        0
    )
    .is_err());
    assert!(world.borrow().events.is_empty());
    let (mut owner, world) = prepared(true);
    assert!(owner
        .start_primary(&member(Slot::B), &DesktopTunnelOptions::default())
        .is_err());
    assert!(owner.execute(start(true), 0).is_err());
    assert_eq!(world.borrow().events, ["save Starting"]);
}

#[test]
fn failed_start_owner_is_retained_for_cleanup_retry() {
    let (mut owner, world) = prepared(true);
    world.borrow_mut().fail_start = true;
    world.borrow_mut().fail_close = true;
    assert!(owner
        .start_primary(&member(Slot::A), &DesktopTunnelOptions::default())
        .is_err());
    assert!(owner.snapshot().cleanup_pending);
    assert_eq!(owner.warm_slot(), None);
    world.borrow_mut().fail_close = false;
    assert_eq!(
        owner
            .execute(Command::Stop { scope: scope() }, 1)
            .unwrap()
            .session
            .phase,
        SessionPhase::Stopped
    );
    assert!(!owner.snapshot().cleanup_pending);
}

#[test]
fn stale_attach_revision_epoch_membership_scope_and_lease_have_zero_effects() {
    for wrong in 0..6 {
        let (mut owner, world) = running();
        let s = owner.snapshot().session;
        let mut command = Command::Attach {
            scope: scope(),
            member: member(Slot::B),
            expected_revision: s.local_revision,
            expected_network_epoch: s.network_epoch,
            expected_membership_generation: 0,
            membership_generation: 0,
        };
        if let Command::Attach {
            scope,
            member,
            expected_revision,
            expected_network_epoch,
            expected_membership_generation,
            ..
        } = &mut command
        {
            match wrong {
                0 => *expected_revision += 1,
                1 => *expected_network_epoch += 1,
                2 => *expected_membership_generation += 1,
                3 => scope.connection_generation += 1,
                4 => member.slot = Slot::A,
                _ => member.lease_id = A.into(),
            }
        }
        let before = world.borrow().events.clone();
        assert!(owner.execute(command, 10).is_err());
        assert_eq!(world.borrow().events, before);
    }
}

#[test]
fn initial_committed_standby_accepts_membership_zero_and_duplicate_is_fenced() {
    let (mut owner, world) = running();
    let snapshot = attach(&mut owner, false, 0).unwrap();
    assert_eq!(snapshot.session.committed, [true, true]);
    assert_eq!(snapshot.session.membership_generation, 0);
    let before = world.borrow().events.clone();
    assert!(attach(&mut owner, false, 1).is_err());
    assert_eq!(world.borrow().events, before);
}

#[test]
fn failed_standby_removes_only_b_and_keeps_primary_ready() {
    let (mut owner, world) = running();
    owner.tick(0).unwrap();
    owner.tick(100).unwrap();
    world.borrow_mut().fail_attach = true;
    assert!(attach(&mut owner, false, 200).is_err());
    assert_eq!(world.borrow().native, [true, false]);
    assert!(!world.borrow().events.iter().any(|s| s == "close"));
    assert!(world
        .borrow()
        .events
        .ends_with(&["attach B".into(), "remove B".into()]));
    assert_eq!(owner.snapshot().leases, [Some(A.into()), None]);
    assert!(owner.snapshot().primary_ready);
    world.borrow_mut().fail_attach = false;
    attach(&mut owner, false, 300).unwrap();
}

#[test]
fn failed_partial_standby_cleanup_stops_whole_pair_and_remains_retryable() {
    let (mut owner, world) = running();
    {
        let mut w = world.borrow_mut();
        w.fail_attach = true;
        w.fail_remove = true;
        w.fail_close = true;
    }
    assert!(attach(&mut owner, true, 0).is_err());
    assert_eq!(owner.snapshot().session.phase, SessionPhase::Stopping);
    assert!(owner.snapshot().cleanup_pending);
    world.borrow_mut().fail_close = false;
    owner.execute(Command::Stop { scope: scope() }, 1).unwrap();
    assert_eq!(world.borrow().native, [false, false]);
}

#[test]
fn uncommitted_candidate_is_ready_but_cannot_promote_without_exact_panel_commit() {
    let (mut owner, world) = running();
    attach(&mut owner, true, 0).unwrap();
    for now in (0..=16000).step_by(100) {
        owner.tick(now).unwrap();
    }
    assert!(owner.snapshot().standby_ready);
    world.borrow_mut().dead[0] = true;
    for now in (16100..=17000).step_by(100) {
        owner.tick(now).unwrap();
    }
    assert_eq!(owner.snapshot().session.active, Slot::A);
    let snapshot = owner.snapshot();
    let mut session = view(&snapshot, true);
    session.membership_generation = 1;
    let command = Command::CommitCandidate {
        scope: scope(),
        slot: Slot::B,
        expected_revision: snapshot.session.local_revision,
        expected_network_epoch: snapshot.session.network_epoch,
        session,
    };
    owner.execute(command, 17000).unwrap();
    assert_eq!(owner.snapshot().session.committed, [true, true]);
    for now in (17100..=19000).step_by(100) {
        owner.tick(now).unwrap();
    }
    assert_eq!(owner.snapshot().session.active, Slot::B);
}

#[test]
fn candidate_commit_requires_ready_current_epoch_exact_maps_and_next_membership() {
    for wrong in 0..8 {
        let (mut owner, world) = running();
        attach(&mut owner, true, 0).unwrap();
        if wrong != 0 {
            for now in (0..=16000).step_by(100) {
                owner.tick(now).unwrap();
            }
        }
        let snapshot = owner.snapshot();
        let mut session = view(&snapshot, true);
        session.membership_generation = 1;
        let mut revision = snapshot.session.local_revision;
        let mut epoch = snapshot.session.network_epoch;
        match wrong {
            0 => (),
            1 => session.slot_b_lease_id = Some(FOREIGN.into()),
            2 => session.active_lease_id = Some(B.into()),
            3 => session.role_generation += 1,
            4 => session.membership_generation = 2,
            5 => session.state = RedundantSessionState::Stopped,
            6 => revision += 1,
            _ => epoch += 1,
        }
        let before = world.borrow().events.clone();
        assert!(owner
            .execute(
                Command::CommitCandidate {
                    scope: scope(),
                    slot: Slot::B,
                    expected_revision: revision,
                    expected_network_epoch: epoch,
                    session
                },
                16000
            )
            .is_err());
        assert!(!owner.snapshot().session.committed[1]);
        assert_eq!(world.borrow().events, before);
    }
}

#[test]
fn role_ack_rejects_wrong_maps_active_state_generations_and_rebase_without_effects() {
    for wrong in 0..9 {
        let (mut owner, world) = running();
        promote(&mut owner, &world);
        let mut ack = response(&mut owner);
        match wrong {
            0 => ack.session.slot_a_lease_id = Some(FOREIGN.into()),
            1 => ack.session.slot_b_lease_id = None,
            2 => ack.local_active_lease_id = A.into(),
            3 => ack.session.active_lease_id = Some(A.into()),
            4 => ack.session.membership_generation += 1,
            5 => ack.session.role_generation += 1,
            6 => ack.session.state = RedundantSessionState::Allocating,
            7 => ack.action = RedundantRoleAction::Rebase,
            _ => ack.session.session_id = FOREIGN.into(),
        }
        let before = world.borrow().events.clone();
        assert!(confirm(&mut owner, ack, 3500).is_err());
        assert_eq!(world.borrow().events, before);
        assert_eq!(owner.warm_slot(), None);
    }
}

#[test]
fn candidate_is_excluded_from_role_ack_committed_slot_map() {
    let (mut owner, _) = running();
    attach(&mut owner, true, 0).unwrap();
    let mut ack = response(&mut owner);
    ack.session.slot_b_lease_id = Some(B.into());
    assert!(confirm(&mut owner, ack, 0).is_err());
    let ack = response(&mut owner);
    confirm(&mut owner, ack, 0).unwrap();
}

#[test]
fn scripted_failover_network_stop_warm_restart_fences_the_previous_pair() {
    let (mut owner, world) = running();
    owner.tick(0).unwrap();
    owner.tick(100).unwrap();
    assert!(owner.snapshot().primary_ready);
    assert_eq!(world.borrow().native, [true, false]);
    attach(&mut owner, false, 200).unwrap();
    for now in (200..=16000).step_by(100) {
        owner.tick(now).unwrap();
    }
    assert!(owner.snapshot().standby_ready);
    world.borrow_mut().dead[0] = true;
    for now in (16100..=19000).step_by(100) {
        owner.tick(now).unwrap();
    }
    assert_eq!(owner.snapshot().session.active, Slot::B);
    assert!(world.borrow().events.iter().any(|e| e == "select B"));
    let ack = response(&mut owner);
    confirm(&mut owner, ack, 19000).unwrap();
    let old = owner.snapshot();
    world.borrow_mut().validated = true;
    owner
        .execute(Command::NetworkChanged { scope: scope() }, 19100)
        .unwrap();
    assert!(!owner.snapshot().primary_ready);
    assert!(owner.snapshot().session.network_epoch > old.session.network_epoch);
    for now in (19200..=24000).step_by(100) {
        owner.tick(now).unwrap();
    }
    assert!(owner.snapshot().primary_ready);
    assert_eq!(owner.snapshot().session.active, Slot::B);
    let ack = response(&mut owner);
    confirm(&mut owner, ack, 24000).unwrap();
    owner.execute(prepare_stop(scope()), 24100).unwrap();
    owner
        .execute(Command::Stop { scope: scope() }, 24100)
        .unwrap();
    assert_eq!(owner.warm_slot(), Some(Slot::B));
    assert_eq!(world.borrow().native, [false; 2]);
    assert!(!owner.snapshot().cleanup_pending);
    let late_stop = Command::Stop { scope: scope() };

    // Simulate the panel returning the WARM peer as the next primary and a
    // newly issued reserve. No assumption that physical slot B stays primary.
    let mut next_scope = scope();
    next_scope.connection_generation += 1;
    next_scope.session_id = "22222222-2222-4222-8222-222222222222".into();
    let mut primary = member(Slot::A);
    primary.lease_id = B.into();
    let next_start = Command::Start {
        scope: next_scope.clone(),
        primary,
        role_generation: 0,
        membership_generation: 0,
        warm_stop_v1: true,
        options: DesktopTunnelOptions::default(),
    };
    world.borrow_mut().dead = [false; 2];
    let mut next = Owner::prepare(
        RuntimeSlot::Latest,
        &next_start,
        Pair(world.clone()),
        Store(world.clone()),
        25000,
    )
    .unwrap();
    let Command::Start {
        primary, options, ..
    } = &next_start
    else {
        unreachable!()
    };
    next.start_primary(primary, options).unwrap();
    next.tick(25000).unwrap();
    next.tick(25100).unwrap();
    assert!(next.snapshot().primary_ready);
    assert_eq!(next.snapshot().current_leases, [Some(B.into()), None]);
    assert_eq!(world.borrow().native, [true, false]);
    let state = next.snapshot();
    let events = world.borrow().events.clone();
    assert!(next.execute(late_stop, 25100).is_err());
    assert_eq!(next.snapshot(), state);
    assert_eq!(world.borrow().events, events);
    let mut fresh = member(Slot::B);
    fresh.lease_id = FOREIGN.into();
    next.execute(
        Command::Attach {
            scope: next_scope.clone(),
            member: fresh,
            expected_revision: state.session.local_revision,
            expected_network_epoch: state.session.network_epoch,
            expected_membership_generation: 0,
            membership_generation: 0,
        },
        25200,
    )
    .unwrap();
    assert_eq!(
        next.snapshot().current_leases,
        [Some(B.into()), Some(FOREIGN.into())]
    );
    assert_eq!(world.borrow().native, [true; 2]);
    next.execute(
        Command::Stop {
            scope: next_scope.clone(),
        },
        25300,
    )
    .unwrap();
    assert_eq!(world.borrow().closed_scopes, [scope(), next_scope]);
}

#[test]
fn confirmed_last_active_b_is_warm_on_stop_and_equal_ack_is_idempotent() {
    let (mut owner, world) = running();
    promote(&mut owner, &world);
    assert_eq!(owner.warm_slot(), None);
    let ack = response(&mut owner);
    confirm(&mut owner, ack.clone(), 3500).unwrap();
    let before = world.borrow().events.clone();
    confirm(&mut owner, ack.clone(), 3500).unwrap();
    assert_eq!(world.borrow().events, before);
    let mut invalid = ack;
    invalid.session.role_generation += 1;
    assert!(confirm(&mut owner, invalid, 3500).is_err());
    owner
        .execute(Command::Stop { scope: scope() }, 3500)
        .unwrap();
    assert_eq!(owner.warm_slot(), Some(Slot::B));
    assert!(!owner.snapshot().primary_ready);
    assert_eq!(world.borrow().native, [false; 2]);
}

#[test]
fn canonical_a_acknowledged_at_same_generation_after_unreported_a_b_a_flip() {
    let (mut owner, world) = running();
    promote(&mut owner, &world);
    let b_snapshot = owner.snapshot();
    let b_ack = response(&mut owner);
    world.borrow_mut().dead[0] = false;
    for now in (3600..=16000).step_by(100) {
        owner.tick(now).unwrap();
    }
    world.borrow_mut().dead[1] = true;
    for now in (16100..=20000).step_by(100) {
        owner.tick(now).unwrap();
    }
    let unconfirmed = owner.snapshot();
    assert_eq!(unconfirmed.session.active, Slot::A);
    assert!(!unconfirmed.session.role_confirmed);
    assert_eq!(unconfirmed.session.role_generation, 0);
    let mut ack = response(&mut owner);
    ack.session.role_generation = 0;
    let before = world.borrow().events.clone();
    for wrong in 0..6 {
        let mut invalid = ack.clone();
        match wrong {
            0 => invalid.action = RedundantRoleAction::Accepted,
            1 => invalid.action = RedundantRoleAction::Rebase,
            2 => invalid.session.slot_b_lease_id = Some(FOREIGN.into()),
            3 => invalid.local_active_lease_id = B.into(),
            4 => invalid.session.membership_generation += 1,
            _ => invalid.session.role_generation = 2,
        }
        assert!(confirm(&mut owner, invalid, 20000).is_err());
        assert_eq!(owner.snapshot(), unconfirmed);
        assert_eq!(world.borrow().events, before);
    }
    assert!(owner
        .execute(
            Command::ConfirmRole {
                scope: scope(),
                expected_revision: b_snapshot.session.local_revision,
                expected_network_epoch: b_snapshot.session.network_epoch,
                response: b_ack,
            },
            20000
        )
        .is_err());
    let confirmed = confirm(&mut owner, ack, 20000).unwrap();
    assert!(confirmed.session.role_confirmed);
    assert_eq!(confirmed.session.role_generation, 0);
    assert_eq!(owner.warm_slot(), Some(Slot::A));
    assert_eq!(world.borrow().saved.last(), Some(&confirmed.session));
    assert_eq!(
        world
            .borrow()
            .events
            .iter()
            .filter(|e| e.starts_with("select"))
            .cloned()
            .collect::<Vec<_>>(),
        ["select B", "select A"]
    );
}

#[test]
fn lost_role_ack_and_unnegotiated_warm_never_offer_warm_retention() {
    let (mut owner, world) = running();
    promote(&mut owner, &world);
    owner
        .execute(Command::Stop { scope: scope() }, 3500)
        .unwrap();
    assert_eq!(owner.warm_slot(), None);
    let (mut owner, _) = prepared(false);
    owner
        .start_primary(&member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    owner.execute(Command::Stop { scope: scope() }, 0).unwrap();
    assert_eq!(owner.warm_slot(), None);
}

fn flipped_back_unconfirmed() -> (Owner, Rc<RefCell<World>>, Command) {
    let (mut owner, world) = running();
    promote(&mut owner, &world);
    let b = owner.snapshot().session;
    let in_flight_b = Command::ConfirmRole {
        scope: b.scope,
        expected_revision: b.local_revision,
        expected_network_epoch: b.network_epoch,
        response: response(&mut owner),
    };
    world.borrow_mut().dead[0] = false;
    for now in (3600..=16000).step_by(100) {
        owner.tick(now).unwrap();
    }
    world.borrow_mut().dead[1] = true;
    for now in (16100..=20000).step_by(100) {
        owner.tick(now).unwrap();
    }
    assert_eq!(owner.snapshot().session.active, Slot::A);
    assert!(!owner.snapshot().session.role_confirmed);
    (owner, world, in_flight_b)
}

fn rebase(owner: &mut Owner) -> RedundantRoleResponse {
    let snapshot = owner.snapshot();
    let mut result = response(owner);
    result.action = RedundantRoleAction::Rebase;
    result.session.active_lease_id =
        snapshot.current_leases[ix(snapshot.session.active.other())].clone();
    result.session.slot_a_lease_id = snapshot.current_leases[0].clone();
    result.session.slot_b_lease_id = snapshot.current_leases[1].clone();
    result
}

#[test]
fn role_rebase_observes_late_b_ack_without_switching_or_confirming_native_a() {
    for server_state in [
        RedundantSessionState::Connected,
        RedundantSessionState::Degraded,
    ] {
        let (mut owner, world, stale_b) = flipped_back_unconfirmed();
        let before = owner.snapshot();
        assert!(owner.execute(stale_b, 20000).is_err());
        let mut observation = rebase(&mut owner);
        observation.session.state = server_state;
        let events = world.borrow().events.len();
        let drops = world.borrow().drops;
        let observed = confirm(&mut owner, observation.clone(), 20000).unwrap();
        let mut expected = before.clone();
        expected.session.role_generation = 1;
        assert_eq!(observed, expected, "only the observed generation changes");
        assert_eq!(world.borrow().saved.last(), Some(&observed.session));
        assert_eq!(&world.borrow().events[events..], ["save Running"]);
        assert_eq!(world.borrow().drops, drops, "pending health probes survive");
        assert!(owner.network_validated());
        assert_eq!(owner.warm_slot(), None);
        assert!(
            confirm(&mut owner, observation, 20000).is_err(),
            "same-generation Rebase is not a receipt"
        );
        let health = owner.tick(20100).unwrap();
        assert!(
            health.primary_ready,
            "observation must not reset healthy A evidence"
        );
        let mut accepted = response(&mut owner);
        accepted.action = RedundantRoleAction::Accepted;
        assert_eq!(accepted.session.role_generation, 2);
        let confirmed = confirm(&mut owner, accepted, 20100).unwrap();
        assert_eq!(confirmed.session.role_generation, 2);
        assert!(confirmed.session.role_confirmed);
        assert_eq!(owner.warm_slot(), Some(Slot::A));
        assert_eq!(
            world
                .borrow()
                .events
                .iter()
                .filter(|e| e.starts_with("select"))
                .cloned()
                .collect::<Vec<_>>(),
            ["select B", "select A"]
        );
    }
}

#[test]
fn role_rebase_rejects_wrong_current_map_active_generation_membership_and_state() {
    let (mut owner, world, _) = flipped_back_unconfirmed();
    let valid = rebase(&mut owner);
    let before = owner.snapshot();
    let events = world.borrow().events.clone();
    for wrong in 0..12 {
        let mut invalid = valid.clone();
        match wrong {
            0 => invalid.local_active_lease_id = B.into(),
            1 => invalid.session.active_lease_id = Some(A.into()),
            2 => invalid.session.active_lease_id = Some(FOREIGN.into()),
            3 => invalid.session.active_lease_id = None,
            4 => invalid.session.slot_a_lease_id = Some(FOREIGN.into()),
            5 => invalid.session.slot_b_lease_id = None,
            6 => invalid.session.role_generation = 0,
            7 => invalid.session.role_generation = 2,
            8 => invalid.session.role_generation = i64::MAX as u64 + 1,
            9 => invalid.session.membership_generation += 1,
            10 => invalid.session.state = RedundantSessionState::Allocating,
            _ => invalid.session.session_id = FOREIGN.into(),
        }
        assert!(confirm(&mut owner, invalid, 20000).is_err(), "case {wrong}");
        assert_eq!(owner.snapshot(), before);
        assert_eq!(world.borrow().events, events);
    }
    // Prove the rejection cases differ from an otherwise consumable observation.
    assert!(confirm(&mut owner, valid, 20000).is_ok());
}

#[test]
fn role_rebase_is_fenced_by_scope_revision_epoch_confirmed_role_and_stop() {
    let (mut owner, world, _) = flipped_back_unconfirmed();
    let response = rebase(&mut owner);
    let before = owner.snapshot();
    let events = world.borrow().events.clone();
    for wrong in 0..3 {
        let mut scope = scope();
        if wrong == 0 {
            scope.connection_generation += 1;
        }
        assert!(owner
            .execute(
                Command::ConfirmRole {
                    scope,
                    expected_revision: before.session.local_revision - u64::from(wrong == 1),
                    expected_network_epoch: before.session.network_epoch + u64::from(wrong == 2),
                    response: response.clone(),
                },
                20000
            )
            .is_err());
        assert_eq!(owner.snapshot(), before);
        assert_eq!(world.borrow().events, events);
    }
    let accepted = self::response(&mut owner);
    confirm(&mut owner, accepted, 20000).unwrap();
    let confirmed = owner.snapshot();
    let events = world.borrow().events.clone();
    let response = rebase(&mut owner);
    assert!(confirm(&mut owner, response.clone(), 20000).is_err());
    assert_eq!(owner.snapshot(), confirmed);
    assert_eq!(world.borrow().events, events);
    owner
        .execute(Command::PrepareStop { scope: scope() }, 20000)
        .unwrap();
    let frozen = owner.snapshot();
    let events = world.borrow().events.clone();
    assert!(confirm(&mut owner, response.clone(), 20000).is_err());
    assert_eq!(owner.snapshot(), frozen);
    assert_eq!(world.borrow().events, events);
    owner
        .execute(Command::Stop { scope: scope() }, 20000)
        .unwrap();
    let stopped = owner.snapshot();
    let events = world.borrow().events.clone();
    assert!(confirm(&mut owner, response, 20000).is_err());
    assert_eq!(owner.snapshot(), stopped);
    assert_eq!(world.borrow().events, events);
}

#[test]
fn role_rebase_failed_save_or_lost_ack_closes_pair_without_publishing_observation() {
    for lost_ack in [false, true] {
        for fail_close in [false, true] {
            let (mut owner, world, _) = flipped_back_unconfirmed();
            let observation = rebase(&mut owner);
            let saves = world.borrow().saved.len();
            world.borrow_mut().fail_save = !lost_ack;
            world.borrow_mut().lose_save_ack = lost_ack;
            world.borrow_mut().fail_close = fail_close;
            assert!(confirm(&mut owner, observation, 20000).is_err());
            let after = owner.snapshot();
            assert_eq!(after.session.role_generation, 0);
            assert_eq!(after.session.active, Slot::A);
            assert!(!after.session.role_confirmed);
            assert_eq!(
                after.session.phase,
                if fail_close {
                    SessionPhase::Stopping
                } else {
                    SessionPhase::Stopped
                }
            );
            assert!(
                after.stalled,
                "command-internal terminal stop must be recoverable"
            );
            assert_eq!(owner.execute(recovery_stop(&after), 20000).unwrap(), after);
            assert_eq!(world.borrow().closed_scopes, [scope()]);
            assert!(!after.primary_ready && !after.standby_ready);
            assert_eq!(owner.warm_slot(), None);
            if lost_ack {
                let world = world.borrow();
                assert_eq!(world.saved[saves].role_generation, 1);
                assert!(!world.saved[saves].role_confirmed);
                assert_eq!(world.saved[saves].phase, SessionPhase::Running);
            }
            world.borrow_mut().fail_save = false;
            world.borrow_mut().fail_close = false;
            owner
                .execute(Command::Stop { scope: scope() }, 20000)
                .unwrap();
            assert_eq!(world.borrow().native, [false; 2]);
        }
    }
}

#[test]
fn old_stop_cannot_stop_a_new_connection_owner() {
    let world = Rc::new(RefCell::new(World::default()));
    let mut command = start(true);
    if let Command::Start { scope, .. } = &mut command {
        scope.connection_generation += 1;
    }
    let mut owner = Owner::prepare(
        RuntimeSlot::Latest,
        &command,
        Pair(world.clone()),
        Store(world.clone()),
        0,
    )
    .unwrap();
    owner
        .start_primary(&member(Slot::A), &DesktopTunnelOptions::default())
        .unwrap();
    let before = world.borrow().events.clone();
    assert!(owner.execute(Command::Stop { scope: scope() }, 1).is_err());
    assert_eq!(world.borrow().events, before);
    assert_eq!(world.borrow().native, [true, false]);
}

#[test]
fn network_change_fences_old_callbacks_before_rebind_and_failure_stays_suspended() {
    for failure in [false, true] {
        let (mut owner, world) = running();
        attach(&mut owner, true, 0).unwrap();
        owner.tick(0).unwrap();
        owner.tick(100).unwrap();
        let old = owner.snapshot();
        let mut session = view(&old, true);
        session.membership_generation = 1;
        world.borrow_mut().fail_rebind = failure;
        let result = owner.execute(Command::NetworkChanged { scope: scope() }, 200);
        assert_eq!(result.is_err(), failure);
        assert!(!owner.snapshot().primary_ready);
        assert!(!owner.snapshot().standby_ready);
        assert!(owner.snapshot().session.network_epoch > old.session.network_epoch);
        assert!(world.borrow().events.iter().any(|e| e == "rebind epoch 2"));
        assert!(owner
            .execute(
                Command::CommitCandidate {
                    scope: scope(),
                    slot: Slot::B,
                    expected_revision: old.session.local_revision,
                    expected_network_epoch: old.session.network_epoch,
                    session
                },
                300
            )
            .is_err());
        world.borrow_mut().dead[0] = true;
        for now in (300..=9000).step_by(100) {
            assert!(!owner.tick(now).unwrap().primary_ready);
        }
        assert!(!world
            .borrow()
            .events
            .iter()
            .any(|e| e.starts_with("select")));
    }
}

#[test]
fn validated_network_rebind_advances_epoch_twice_and_requires_fresh_evidence() {
    let (mut owner, world) = running();
    owner.tick(0).unwrap();
    owner.tick(100).unwrap();
    world.borrow_mut().validated = true;
    let snapshot = owner
        .execute(Command::NetworkChanged { scope: scope() }, 200)
        .unwrap();
    assert_eq!(snapshot.session.network_epoch, 3);
    assert!(!snapshot.primary_ready);
    for now in (300..=5000).step_by(100) {
        owner.tick(now).unwrap();
    }
    assert!(owner.snapshot().primary_ready);
}

#[test]
fn stop_disables_native_even_when_snapshot_store_fails() {
    let (mut owner, world) = running();
    world.borrow_mut().fail_save = true;
    assert!(owner.execute(Command::Stop { scope: scope() }, 1).is_err());
    assert_eq!(world.borrow().native, [false; 2]);
    assert_eq!(owner.snapshot().session.phase, SessionPhase::Stopped);
}

#[test]
fn explicit_constructor_validates_initial_lease_scope_and_never_starts_on_drop() {
    for wrong in 0..5 {
        let world = Rc::new(RefCell::new(World::default()));
        let mut state = SessionState::new(scope(), Slot::A, 0, 0).unwrap();
        let mut leases = [Some(A.into()), None];
        let mut runtime = RuntimeSlot::Latest;
        match wrong {
            0 => runtime = RuntimeSlot::Stable,
            1 => leases[0] = None,
            2 => leases[1] = Some(B.into()),
            3 => leases[0] = Some("invalid".into()),
            _ => state.primary_started(&scope()).unwrap(),
        }
        assert!(Owner::new(
            runtime,
            state,
            leases,
            true,
            Pair(world.clone()),
            Store(world.clone()),
            0
        )
        .is_err());
        assert!(world.borrow().events.is_empty());
    }
    let world = Rc::new(RefCell::new(World::default()));
    let state = SessionState::new(scope(), Slot::B, 0, 0).unwrap();
    let owner = Owner::new(
        RuntimeSlot::Latest,
        state,
        [None, Some(B.into())],
        true,
        Pair(world.clone()),
        Store(world.clone()),
        0,
    )
    .unwrap();
    drop(owner);
    assert_eq!(world.borrow().events, ["save Starting"]);
}

#[test]
fn initial_store_failure_cannot_start_native_pair() {
    let world = Rc::new(RefCell::new(World {
        fail_save: true,
        ..Default::default()
    }));
    assert!(Owner::prepare(
        RuntimeSlot::Latest,
        &start(true),
        Pair(world.clone()),
        Store(world.clone()),
        0
    )
    .is_err());
    assert!(!world.borrow().events.iter().any(|e| e.starts_with("start")));
    assert_eq!(world.borrow().native, [false; 2]);
}

#[test]
fn attach_metadata_failure_clears_readiness_and_keeps_failed_cleanup_owner() {
    for candidate in [false, true] {
        let (mut owner, world) = running();
        owner.tick(0).unwrap();
        owner.tick(100).unwrap();
        assert!(owner.snapshot().primary_ready);
        {
            let mut state = world.borrow_mut();
            state.fail_save = true;
            state.fail_close = true;
        }
        assert!(attach(&mut owner, candidate, 200).is_err());
        let snapshot = owner.snapshot();
        assert!(!snapshot.primary_ready);
        assert!(!snapshot.standby_ready);
        assert!(snapshot.cleanup_pending);
        assert_eq!(snapshot.session.phase, SessionPhase::Stopping);
        {
            let mut state = world.borrow_mut();
            state.fail_save = false;
            state.fail_close = false;
        }
        owner
            .execute(Command::Stop { scope: scope() }, 300)
            .unwrap();
        assert_eq!(world.borrow().native, [false; 2]);
        assert!(!owner.snapshot().cleanup_pending);
    }
}

#[test]
fn candidate_commit_rechecks_readiness_instead_of_reusing_a_stale_ready_bit() {
    let (mut owner, world) = running();
    attach(&mut owner, true, 0).unwrap();
    for now in (0..=16000).step_by(100) {
        owner.tick(now).unwrap();
    }
    assert!(owner.snapshot().standby_ready);
    let snapshot = owner.snapshot();
    let mut session = view(&snapshot, true);
    session.membership_generation = 1;
    world.borrow_mut().dead[1] = true;
    assert!(owner
        .execute(
            Command::CommitCandidate {
                scope: scope(),
                slot: Slot::B,
                expected_revision: snapshot.session.local_revision,
                expected_network_epoch: snapshot.session.network_epoch,
                session,
            },
            17000
        )
        .is_err());
    assert!(!owner.snapshot().standby_ready);
    assert!(!owner.snapshot().session.committed[1]);
}

#[test]
fn old_role_ack_epoch_cannot_confirm_after_network_rebind() {
    let (mut owner, world) = running();
    promote(&mut owner, &world);
    let snapshot = owner.snapshot();
    let ack = response(&mut owner);
    owner
        .execute(Command::NetworkChanged { scope: scope() }, 3600)
        .unwrap();
    let before = world.borrow().events.clone();
    assert!(owner
        .execute(
            Command::ConfirmRole {
                scope: scope(),
                expected_revision: snapshot.session.local_revision,
                expected_network_epoch: snapshot.session.network_epoch,
                response: ack,
            },
            3600
        )
        .is_err());
    assert_eq!(world.borrow().events, before);
    assert_eq!(owner.warm_slot(), None);
}

fn remove_command(snapshot: &Snapshot) -> Command {
    serde_json::from_value(serde_json::json!({
        "action": "remove_standby", "scope": snapshot.session.scope,
        "slot": snapshot.session.active.other(),
        "lease_id": snapshot.leases[ix(snapshot.session.active.other())],
        "expected_revision": snapshot.session.local_revision,
        "expected_network_epoch": snapshot.session.network_epoch,
        "expected_membership_generation": snapshot.session.membership_generation,
    }))
    .unwrap()
}

#[test]
fn failed_candidate_commit_can_remove_b_and_stage_new_b_without_stopping_a() {
    let (mut owner, world) = running();
    attach(&mut owner, true, 0).unwrap();
    for now in (0..=16000).step_by(100) {
        owner.tick(now).unwrap();
    }
    let before = owner.snapshot();
    let mut rejected = view(&before, true);
    rejected.membership_generation = 1;
    rejected.active_lease_id = Some(B.into());
    assert!(owner
        .execute(
            Command::CommitCandidate {
                scope: scope(),
                slot: Slot::B,
                expected_revision: before.session.local_revision,
                expected_network_epoch: before.session.network_epoch,
                session: rejected,
            },
            16000
        )
        .is_err());
    let removed = owner.execute(remove_command(&before), 16000).unwrap();
    assert_eq!(removed.session.installed, [true, false]);
    assert_eq!(removed.session.committed, [true, false]);
    assert_eq!(removed.leases, [Some(A.into()), None]);
    assert!(removed.primary_ready);
    assert!(!removed.standby_ready);
    assert_eq!(
        removed.session.local_revision,
        before.session.local_revision + 1
    );
    assert_eq!(
        removed.session.membership_generation,
        before.session.membership_generation
    );
    assert_eq!(world.borrow().native, [true, false]);
    let mut replacement = member(Slot::B);
    replacement.lease_id = FOREIGN.into();
    owner
        .execute(
            Command::StageCandidate {
                scope: scope(),
                member: replacement,
                expected_revision: removed.session.local_revision,
                expected_network_epoch: removed.session.network_epoch,
                expected_membership_generation: removed.session.membership_generation,
            },
            16100,
        )
        .unwrap();
    assert_eq!(world.borrow().native, [true, true]);
    assert_eq!(
        owner.snapshot().leases,
        [Some(A.into()), Some(FOREIGN.into())]
    );
    assert!(!owner.snapshot().session.committed[1]);
    let events = world.borrow().events.clone();
    assert!(owner.execute(remove_command(&before), 16200).is_err());
    assert_eq!(world.borrow().events, events);
    assert!(!events.iter().any(|e| e == "close"));
}

#[test]
fn candidate_probe_is_cancelled_and_removal_persisted_before_native_cleanup() {
    let (mut owner, world) = running();
    attach(&mut owner, true, 0).unwrap();
    owner.tick(0).unwrap();
    assert_eq!(world.borrow().tx, [1, 1]);
    let before = owner.snapshot();
    owner.execute(remove_command(&before), 1).unwrap();
    let state = world.borrow();
    let (slot, saved, drops) = state.removals.last().unwrap();
    assert_eq!(*slot, Slot::B);
    assert_eq!(saved.phase, SessionPhase::Running);
    assert_eq!(saved.installed, [true, false]);
    assert_eq!(saved.local_revision, before.session.local_revision + 1);
    assert_eq!(
        *drops,
        [0, 1],
        "only B's outstanding probe is cancelled before removal"
    );
    assert!(state
        .events
        .ends_with(&["save Running".into(), "remove B".into()]));
    drop(state);
    assert!(owner.tick(100).unwrap().primary_ready);
    assert_eq!(world.borrow().tx[1], 1);
    attach(&mut owner, true, 200).unwrap();
    assert!(!owner.tick(200).unwrap().standby_ready);
    assert_eq!(world.borrow().tx[1], 2);
}

#[test]
fn stale_active_wrong_lease_and_current_standby_removal_have_no_effects() {
    for wrong in 0..8 {
        let (mut owner, world) = running();
        attach(&mut owner, wrong != 7, 0).unwrap();
        owner.tick(0).unwrap();
        let before = owner.snapshot();
        let mut wire = serde_json::to_value(remove_command(&before)).unwrap();
        match wrong {
            0 => wire["expected_revision"] = serde_json::json!(before.session.local_revision + 1),
            1 => {
                wire["expected_network_epoch"] = serde_json::json!(before.session.network_epoch + 1)
            }
            2 => wire["expected_membership_generation"] = serde_json::json!(1),
            3 => wire["lease_id"] = serde_json::json!(FOREIGN),
            4 => {
                wire["slot"] = serde_json::json!("A");
                wire["lease_id"] = serde_json::json!(A);
            }
            5 => wire["scope"]["connection_generation"] = serde_json::json!(8),
            6 => wire["lease_id"] = serde_json::json!("invalid"),
            _ => (),
        }
        let events = world.borrow().events.clone();
        let drops = world.borrow().drops;
        assert!(owner
            .execute(serde_json::from_value(wire).unwrap(), 1)
            .is_err());
        assert_eq!(world.borrow().events, events);
        assert_eq!(world.borrow().drops, drops);
        assert_eq!(owner.snapshot(), before);
        assert_eq!(world.borrow().native, [true, true]);
    }
}

#[test]
fn ambiguous_candidate_removal_retains_lease_and_fences_pair_for_cleanup() {
    for journal_failure in [false, true] {
        let (mut owner, world) = running();
        attach(&mut owner, true, 0).unwrap();
        owner.tick(0).unwrap();
        let before = owner.snapshot();
        {
            let mut state = world.borrow_mut();
            state.fail_save = journal_failure;
            state.fail_remove = !journal_failure;
            state.fail_close = true;
        }
        assert!(owner.execute(remove_command(&before), 1).is_err());
        let frozen = owner.snapshot();
        assert!(frozen.stalled);
        assert_eq!(owner.execute(recovery_stop(&frozen), 1).unwrap(), frozen);
        let failed = owner.snapshot();
        assert_eq!(failed.leases[1].as_deref(), Some(B));
        assert_eq!(failed.session.phase, SessionPhase::Stopping);
        assert!(failed.cleanup_pending);
        assert!(!failed.primary_ready && !failed.standby_ready);
        assert_eq!(world.borrow().removals.is_empty(), journal_failure);
        assert!(world.borrow().events.iter().any(|event| event == "close"));
        assert!(attach(&mut owner, true, 2).is_err());
        {
            let mut state = world.borrow_mut();
            state.fail_save = false;
            state.fail_remove = false;
            state.fail_close = false;
        }
        owner.execute(Command::Stop { scope: scope() }, 3).unwrap();
        assert_eq!(world.borrow().native, [false; 2]);
        assert!(!owner.snapshot().cleanup_pending);
    }
}
