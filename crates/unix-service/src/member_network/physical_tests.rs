// Compose the real actor, shared health driver, Unix member ownership and route
// CAS. Only native I/O, time, DNS datagrams and persistence are fake.
use super::*;
use crate::member_network::actor::{CompositeBackend, PairFactory};
use nelomai_client_tunnel::redundancy::{
    control::SessionControl,
    protocol::{Command, Snapshot},
    ProbeDatagram,
};

struct Socket {
    state: Rc<RefCell<State>>,
    slot: Slot,
    query: Option<Vec<u8>>,
}
impl ProbeDatagram for Socket {
    fn send(&mut self, packet: &[u8]) -> io::Result<usize> {
        self.query = Some(packet.to_vec());
        self.state.borrow_mut().probe_tx[usize::from(self.slot == Slot::B)] += 1;
        Ok(packet.len())
    }
    fn receive(&mut self, packet: &mut [u8]) -> io::Result<usize> {
        let mut state = self.state.borrow_mut();
        let native_slot = if self.slot == Slot::A {
            TunnelSlot::A
        } else {
            TunnelSlot::B
        };
        if state.absent_slot == Some(native_slot)
            || state.bad_identity_slot == Some(native_slot)
            || state.bad_identity
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let mut response = self.query.take().ok_or(io::ErrorKind::WouldBlock)?;
        response[2] = 0x81;
        response[3] = 0x80;
        response[7] = 1;
        response.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4]);
        packet[..response.len()].copy_from_slice(&response);
        state.probe_rx[usize::from(self.slot == Slot::B)] += 1;
        Ok(response.len())
    }
}
struct Native {
    pair: Pair,
    state: Rc<RefCell<State>>,
}
impl NativePair for Native {
    type Socket = Socket;
    fn sample(&mut self, slot: Slot) -> Option<NativeHealthSample> {
        self.pair.sample_at(slot, NOW)
    }
    fn open_probe(&mut self, slot: Slot) -> io::Result<(Socket, String)> {
        self.pair.open_probe_with(slot, |_, _, _| {
            Ok(Socket {
                state: self.state.clone(),
                slot,
                query: None,
            })
        })
    }
    fn select_active(&mut self, scope: &SessionScope, slot: Slot) -> io::Result<()> {
        self.pair.select_active(scope, slot)
    }
    fn close(&mut self, scope: &SessionScope) -> io::Result<()> {
        self.pair.close(scope)
    }
}
impl PairControl for Native {
    fn physical_network_fingerprint(&self) -> io::Result<String> {
        self.pair.physical_network_fingerprint()
    }
    fn start_primary(
        &mut self,
        scope: &SessionScope,
        member: &Member,
        options: &DesktopTunnelOptions,
    ) -> io::Result<()> {
        self.pair.start_primary(scope, member, options)
    }
    fn attach(&mut self, scope: &SessionScope, member: &Member) -> io::Result<()> {
        self.pair.attach(scope, member)
    }
    fn remove_standby(&mut self, scope: &SessionScope, slot: Slot) -> io::Result<()> {
        self.pair.remove_standby(scope, slot)
    }
    fn rebind_pair(&mut self, scope: &SessionScope) -> io::Result<bool> {
        self.pair.rebind_pair(scope)
    }
    fn cleanup_pending(&self) -> bool {
        self.pair.cleanup_pending()
    }
}
struct SessionJournal;
impl SessionStore for SessionJournal {
    fn save(&mut self, _: &SessionSnapshot) -> io::Result<()> {
        Ok(())
    }
}
struct Factory(Option<Native>);
impl PairFactory for Factory {
    type Native = Native;
    type Store = SessionJournal;
    fn recover(&mut self) -> Result<(), ServiceError> {
        Ok(())
    }
    fn prepare(
        &mut self,
        command: &Command,
        now: u64,
    ) -> io::Result<SessionControl<Native, SessionJournal>> {
        SessionControl::prepare(
            RuntimeSlot::Latest,
            command,
            self.0.take().unwrap(),
            SessionJournal,
            now,
        )
    }
}
struct Single;
impl ServiceTunnelBackend for Single {
    fn start(
        &mut self,
        _: &ParsedConfiguration,
        _: &DesktopTunnelOptions,
    ) -> Result<ServiceTunnelState, ServiceError> {
        panic!("must not start single backend")
    }
    fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        panic!("must not stop single backend")
    }
    fn status(&self) -> Result<ServiceTunnelState, ServiceError> {
        Ok(ServiceTunnelState::Stopped)
    }
}
type Actor = CompositeBackend<Single, Factory>;
fn snapshot(actor: &Actor) -> Snapshot {
    actor.current_redundancy_snapshot().unwrap()
}
fn ready_pair() -> (Actor, Rc<RefCell<State>>) {
    let (pair, state) = unstarted();
    state.borrow_mut().handshake = Some(NOW - 1000);
    let mut actor = Actor::new(
        RuntimeSlot::Latest,
        Single,
        Factory(Some(Native {
            pair,
            state: state.clone(),
        })),
    )
    .unwrap();
    actor
        .redundant(Command::Start {
            scope: scope(),
            primary: command_member(Slot::A),
            role_generation: 1,
            membership_generation: 1,
            warm_stop_v1: true,
            options: DesktopTunnelOptions::default(),
        })
        .unwrap();
    actor.tick(0).unwrap();
    actor.tick(100).unwrap();
    let s = snapshot(&actor).session;
    actor
        .redundant(Command::Attach {
            scope: scope(),
            member: command_member(Slot::B),
            expected_revision: s.local_revision,
            expected_network_epoch: s.network_epoch,
            expected_membership_generation: s.membership_generation,
            membership_generation: s.membership_generation,
        })
        .unwrap();
    // Real standby readiness requires three probes and 15 seconds of stability.
    for now in (200..=19900).step_by(100) {
        actor.tick(now).unwrap();
    }
    let ready = snapshot(&actor);
    assert!(ready.primary_ready && ready.standby_ready, "{ready:?}");
    state.borrow_mut().calls.clear();
    (actor, state)
}

#[test]
fn absent_active_with_valid_physical_network_promotes_healthy_standby() {
    let (mut actor, state) = ready_pair();
    let epoch = snapshot(&actor).session.network_epoch;
    state.borrow_mut().absent_slot = Some(TunnelSlot::A);
    for now in (20000..=32000).step_by(100) {
        actor.tick(now).unwrap();
    }
    let after = snapshot(&actor);
    assert_eq!(
        after.session.network_epoch, epoch,
        "member loss is not physical network loss"
    );
    assert_eq!(after.session.active, Slot::B);
    assert!(after.primary_ready);
    assert!(state.borrow().calls.contains(&"write network"));
    assert!(!state.borrow().calls.contains(&"resolve"));
    assert!(state.borrow().stopped_slots.is_empty());
}

#[test]
fn absent_standby_is_reported_and_can_be_replaced_without_suspending_active() {
    let (mut actor, state) = ready_pair();
    let epoch = snapshot(&actor).session.network_epoch;
    state.borrow_mut().absent_slot = Some(TunnelSlot::B);
    for now in (20000..=32000).step_by(100) {
        actor.tick(now).unwrap();
    }
    let after = snapshot(&actor);
    assert_eq!(after.session.network_epoch, epoch);
    assert_eq!(after.session.active, Slot::A);
    assert!(
        after.primary_ready && after.standby_failed && !after.standby_ready,
        "{after:?}"
    );
    actor
        .redundant(Command::RetireInactive {
            scope: scope(),
            slot: Slot::B,
            lease_id: command_member(Slot::B).lease_id,
            expected_revision: after.session.local_revision,
            expected_network_epoch: epoch,
            expected_membership_generation: after.session.membership_generation,
        })
        .unwrap();
    let s = snapshot(&actor).session;
    let mut replacement = command_member(Slot::B);
    replacement.lease_id = "72cc17e2-0000-4000-8000-000000000004".into();
    actor
        .redundant(Command::StageCandidate {
            scope: scope(),
            member: replacement,
            expected_revision: s.local_revision,
            expected_network_epoch: epoch,
            expected_membership_generation: s.membership_generation,
        })
        .unwrap();
    for now in (32100..=50000).step_by(100) {
        actor.tick(now).unwrap();
    }
    let after = snapshot(&actor);
    assert_eq!(after.session.active, Slot::A);
    assert_eq!(after.session.network_epoch, epoch);
    assert!(after.primary_ready && after.standby_ready, "{after:?}");
    assert_eq!(state.borrow().stopped_slots, [TunnelSlot::B]);
}

#[test]
fn actual_physical_discovery_failure_still_suspends_health_and_promotion() {
    let (mut actor, state) = ready_pair();
    let epoch = snapshot(&actor).session.network_epoch;
    let probes = state.borrow().probe_tx;
    let routes = state.borrow().values.clone();
    state.borrow_mut().absent_slot = Some(TunnelSlot::A);
    state.borrow_mut().fail_fingerprint = true;
    for now in (20000..=32000).step_by(100) {
        actor.tick(now).unwrap();
    }
    let after = snapshot(&actor);
    assert!(after.session.network_epoch > epoch);
    assert_eq!(after.session.active, Slot::A);
    assert!(!after.primary_ready && !after.standby_ready);
    assert_eq!(state.borrow().probe_tx, probes);
    assert_eq!(state.borrow().values, routes);
    assert!(!state.borrow().calls.contains(&"resolve"));
}

#[test]
fn valid_physical_network_does_not_authorize_promotion_of_foreign_standby() {
    let (mut actor, state) = ready_pair();
    let epoch = snapshot(&actor).session.network_epoch;
    let routes = state.borrow().values.clone();
    let probes = state.borrow().probe_tx;
    state.borrow_mut().absent_slot = Some(TunnelSlot::A);
    state.borrow_mut().bad_identity_slot = Some(TunnelSlot::B);
    for now in (20000..=32000).step_by(100) {
        actor.tick(now).unwrap();
    }
    let after = snapshot(&actor);
    assert_eq!(after.session.network_epoch, epoch);
    assert_eq!(after.session.active, Slot::A);
    assert!(!after.primary_ready && !after.standby_ready);
    assert!(after.standby_failed);
    assert_eq!(state.borrow().values, routes);
    assert_eq!(state.borrow().probe_tx, probes);
    assert!(!state.borrow().calls.contains(&"write network"));
    assert!(state.borrow().stopped_slots.is_empty());
}

#[test]
fn physical_discovery_keeps_member_lifecycle_fences() {
    let (pair, state) = unstarted();
    assert!(pair
        .network
        .members()
        .physical_network_fingerprint(&scope(), Slot::A)
        .is_err());
    assert!(state.borrow().calls.is_empty());
    let (mut pair, state) = setup();
    assert!(pair
        .network
        .members()
        .physical_network_fingerprint(&scope(), Slot::B)
        .is_err());
    assert!(state.borrow().calls.is_empty());
    NativePair::close(&mut pair, &scope()).unwrap();
    state.borrow_mut().calls.clear();
    assert!(pair
        .network
        .members()
        .physical_network_fingerprint(&scope(), Slot::A)
        .is_err());
    assert!(state.borrow().calls.is_empty());
}
