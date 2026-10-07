use nelomai_client_tunnel::redundancy::{
    driver::*, evidence::NativeHealthSample, session::*, ProbeDatagram, SessionScope, Slot,
};
use nelomai_contracts::RuntimeSlot;
use std::{cell::RefCell, io, rc::Rc};

#[derive(Default)]
struct World {
    tx: [u64; 2],
    rx: [u64; 2],
    lost: [bool; 2],
    dead: [bool; 2],
    selects: Vec<Slot>,
    closed: usize,
    drops: usize,
    save_error: bool,
    switch_error: bool,
    integrity_error: bool,
    native_drops: usize,
    store_drops: usize,
    saves: Vec<SessionSnapshot>,
    lost_save_ack: bool,
    panic_save: bool,
    close_error: bool,
}
fn ix(s: Slot) -> usize {
    if s == Slot::A {
        0
    } else {
        1
    }
}
struct Socket {
    world: Rc<RefCell<World>>,
    slot: Slot,
    query: Vec<u8>,
    replied: bool,
}
impl Drop for Socket {
    fn drop(&mut self) {
        self.world.borrow_mut().drops += 1;
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
        let mut r = self.query.clone();
        r[2] = 0x81;
        r[3] = 0x80;
        r[7] = 1;
        r.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4]);
        p[..r.len()].copy_from_slice(&r);
        self.replied = true;
        self.world.borrow_mut().rx[ix(self.slot)] += 1;
        Ok(r.len())
    }
}
struct Pair(Rc<RefCell<World>>);
impl Drop for Pair {
    fn drop(&mut self) {
        self.0.borrow_mut().native_drops += 1;
    }
}
impl NativePair for Pair {
    type Socket = Socket;
    fn check_integrity(&mut self) -> io::Result<()> {
        if self.0.borrow().integrity_error {
            Err(io::ErrorKind::PermissionDenied.into())
        } else {
            Ok(())
        }
    }
    fn sample(&mut self, slot: Slot) -> Option<NativeHealthSample> {
        let w = self.0.borrow();
        let i = ix(slot);
        Some(NativeHealthSample {
            admitted: !w.dead[i],
            closed: w.dead[i],
            handshake_fresh: !w.dead[i],
            tx_packets: w.tx[i],
            rx_data_packets: w.rx[i],
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
        if self.0.borrow().switch_error {
            return Err(io::Error::other("switch"));
        }
        self.0.borrow_mut().selects.push(slot);
        Ok(())
    }
    fn close(&mut self, _: &SessionScope) -> io::Result<()> {
        self.0.borrow_mut().closed += 1;
        if self.0.borrow().close_error {
            Err(io::Error::other("original close unacknowledged"))
        } else {
            Ok(())
        }
    }
}
struct Store(Rc<RefCell<World>>);
impl Drop for Store {
    fn drop(&mut self) {
        self.0.borrow_mut().store_drops += 1;
    }
}
impl SessionStore for Store {
    fn save(&mut self, snapshot: &SessionSnapshot) -> io::Result<()> {
        if self.0.borrow().save_error {
            Err(io::Error::other("disk"))
        } else {
            self.0.borrow_mut().saves.push(snapshot.clone());
            assert!(!self.0.borrow().panic_save, "original save unwind");
            if self.0.borrow().lost_save_ack {
                return Err(io::Error::other("original write ACK lost"));
            }
            Ok(())
        }
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

#[test]
fn retained_driver_starting_save_error_lost_ack_and_unwind_keep_same_cleanup_owner() {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    for fault in 0..3 {
        let world = Rc::new(RefCell::new(World::default()));
        {
            let mut w = world.borrow_mut();
            w.save_error = fault == 0;
            w.lost_save_ack = fault == 1;
            w.panic_save = fault == 2;
        }
        let mut native = Some(Pair(world.clone()));
        let mut store = Some(Store(world.clone()));
        let mut retained = None;
        let result = catch_unwind(AssertUnwindSafe(|| {
            SessionDriver::prepare_retained_into(
                &mut retained,
                SessionState::new(scope(), Slot::A, 1, 1).unwrap(),
                &mut native,
                &mut store,
                0,
            )
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(native.is_none() && store.is_none());
        let owner = retained.as_mut().expect("lost same retained owner");
        assert_eq!(owner.state().snapshot().scope, scope());
        assert_eq!(owner.state().snapshot().phase, SessionPhase::Starting);
        assert_eq!(world.borrow().native_drops, 0);
        assert_eq!(world.borrow().store_drops, 0);
        assert_eq!(world.borrow().closed, 0, "preparation cannot auto-close");
        assert!(!owner.network_validated());
        assert!(owner
            .start_primary(
                &scope(),
                |_| panic!("native Start"),
                |_| { panic!("Start completion") }
            )
            .is_err());
        assert!(owner.network_changed(&scope(), 1, true).is_err());
        assert!(owner.tick(0).is_err());
        assert!(!owner.recovery_stop_eligible(0));
        assert!(catch_unwind(AssertUnwindSafe(|| {
            owner.native_mut();
        }))
        .is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| {
            owner.native();
        }))
        .is_err());
        {
            let mut w = world.borrow_mut();
            w.save_error = false;
            w.lost_save_ack = false;
            w.panic_save = false;
            w.close_error = true;
        }
        assert!(owner.stop(&scope()).is_err());
        assert_eq!(owner.state().snapshot().phase, SessionPhase::Stopping);
        world.borrow_mut().close_error = false;
        owner.stop(&scope()).unwrap();
        assert_eq!(owner.state().snapshot().phase, SessionPhase::Stopped);
        assert!(owner.network_changed(&scope(), 2, true).is_err());
        assert!(owner.tick(2).is_err());
        assert_eq!(world.borrow().closed, 2);
        assert!(world
            .borrow()
            .saves
            .iter()
            .skip(1)
            .all(|s| s.phase != SessionPhase::Starting));
        drop(retained);
        assert_eq!(world.borrow().native_drops, 1);
        assert_eq!(world.borrow().store_drops, 1);
    }
}

#[test]
fn retained_driver_rejects_nonstarting_and_missing_inputs_before_any_io() {
    for fault in 0..3 {
        let world = Rc::new(RefCell::new(World::default()));
        let mut native = (fault != 1).then(|| Pair(world.clone()));
        let mut store = (fault != 2).then(|| Store(world.clone()));
        let mut state = SessionState::new(scope(), Slot::A, 1, 1).unwrap();
        if fault == 0 {
            state.primary_started(&scope()).unwrap();
        }
        let mut destination = None;
        assert!(SessionDriver::prepare_retained_into(
            &mut destination,
            state,
            &mut native,
            &mut store,
            0
        )
        .is_err());
        assert!(destination.is_none());
        assert_eq!(native.is_some(), fault != 1);
        assert_eq!(store.is_some(), fault != 2);
        assert!(world.borrow().saves.is_empty());
        assert_eq!(world.borrow().closed, 0);
        assert_eq!(world.borrow().native_drops, 0);
        assert_eq!(world.borrow().store_drops, 0);
    }
}

#[test]
fn retained_driver_duplicate_preparation_cannot_select_new_scope_or_recover_forward() {
    let world = Rc::new(RefCell::new(World::default()));
    let mut native = Some(Pair(world.clone()));
    let mut store = Some(Store(world.clone()));
    let mut retained = None;
    SessionDriver::prepare_retained_into(
        &mut retained,
        SessionState::new(scope(), Slot::B, 1, 1).unwrap(),
        &mut native,
        &mut store,
        0,
    )
    .unwrap();
    assert_eq!(world.borrow().saves.len(), 1);
    assert!(retained.as_ref().unwrap().network_validated());
    let mut foreign_scope = scope();
    foreign_scope.connection_generation += 1;
    let foreign = Rc::new(RefCell::new(World::default()));
    let mut other_native = Some(Pair(foreign.clone()));
    let mut other_store = Some(Store(foreign.clone()));
    assert!(SessionDriver::prepare_retained_into(
        &mut retained,
        SessionState::new(foreign_scope.clone(), Slot::A, 1, 1).unwrap(),
        &mut other_native,
        &mut other_store,
        0
    )
    .is_err());
    let original = retained.as_mut().unwrap();
    assert_eq!(original.state().snapshot().scope, scope());
    assert_eq!(original.state().snapshot().active, Slot::B);
    assert!(original.stop(&foreign_scope).is_err());
    assert_eq!(world.borrow().closed, 0);
    assert!(other_native.is_some() && other_store.is_some());
    assert!(foreign.borrow().saves.is_empty());
    original.stop(&scope()).unwrap();
    assert_eq!(world.borrow().closed, 1);
    assert!(!original.network_validated());
    assert!(original.tick(0).is_err());
}
fn setup() -> (SessionDriver<Pair, Store>, Rc<RefCell<World>>) {
    let w = Rc::new(RefCell::new(World::default()));
    let mut s = SessionState::new(scope(), Slot::A, 1, 1).unwrap();
    s.primary_started(&scope()).unwrap();
    (
        SessionDriver::new(s, Pair(w.clone()), Store(w.clone()), 0).unwrap(),
        w,
    )
}
fn standby(d: &mut SessionDriver<Pair, Store>, now: u64) {
    let t = d.state().install_ticket(&scope(), Slot::B).unwrap();
    d.standby_installed(t, 2, now).unwrap();
}

#[test]
fn helper_proves_primary_before_standby_exists() {
    let (mut d, _) = setup();
    assert!(!d.tick(0).unwrap().primary_ready);
    assert!(d.tick(100).unwrap().primary_ready);
}

#[test]
fn native_integrity_failure_closes_even_while_network_health_is_suspended() {
    let (mut d, w) = setup();
    standby(&mut d, 0);
    d.tick(0).unwrap();
    d.network_changed(&scope(), 100, false).unwrap();
    w.borrow_mut().integrity_error = true;
    assert_eq!(
        d.tick(200).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(w.borrow().closed, 1);
    assert_eq!(d.state().snapshot().phase, SessionPhase::Stopped);
    assert!(w.borrow().selects.is_empty());
    let probes = w.borrow().tx;
    d.tick(1000).unwrap();
    assert_eq!(w.borrow().closed, 1);
    assert_eq!(w.borrow().tx, probes);
}

#[test]
fn recovery_stop_evidence_guard_is_readonly_and_fences_healthy_invalidated_and_old_clock() {
    let (mut d, w) = setup();
    d.tick(0).unwrap();
    d.tick(100).unwrap();
    assert!(!d.recovery_stop_eligible(100));
    w.borrow_mut().dead[0] = true;
    assert!(d.tick(500).unwrap().stalled);
    let effects = (w.borrow().tx, w.borrow().drops, w.borrow().closed);
    assert!(d.recovery_stop_eligible(500));
    assert!(!d.recovery_stop_eligible(499));
    assert_eq!(
        (w.borrow().tx, w.borrow().drops, w.borrow().closed),
        effects
    );
    d.network_changed(&scope(), 600, false).unwrap();
    assert!(!d.recovery_stop_eligible(10000));
    d.stop(&scope()).unwrap();
    assert!(!d.recovery_stop_eligible(10000));
}

#[test]
fn recovery_stop_evidence_guard_rejects_fresh_usable_current_reserve_not_candidate() {
    let (mut d, w) = setup();
    d.tick(0).unwrap();
    d.tick(100).unwrap();
    let ticket = d.state().install_ticket(&scope(), Slot::B).unwrap();
    d.candidate_installed(ticket, 200).unwrap();
    for now in (200..=16000).step_by(100) {
        d.tick(now).unwrap();
    }
    w.borrow_mut().dead[0] = true;
    for now in (16100..=18200).step_by(100) {
        d.tick(now).unwrap();
    }
    assert!(
        d.recovery_stop_eligible(18200),
        "uncommitted candidate cannot protect user traffic"
    );
    let s = d.state().snapshot();
    d.commit_candidate(&scope(), Slot::B, s.local_revision, s.network_epoch, 1, 2)
        .unwrap();
    let effects = (w.borrow().tx, w.borrow().drops, w.borrow().closed);
    assert!(
        !d.recovery_stop_eligible(18200),
        "CURRENT reserve has fresh usable proof before next health tick"
    );
    assert_eq!(
        (w.borrow().tx, w.borrow().drops, w.borrow().closed),
        effects
    );
    assert!(w.borrow().selects.is_empty());
}

#[test]
fn helper_failover_runs_without_any_ui_or_panel_callback() {
    let (mut d, w) = setup();
    d.tick(0).unwrap();
    d.tick(100).unwrap();
    standby(&mut d, 200);
    d.tick(200).unwrap();
    d.tick(300).unwrap();
    w.borrow_mut().lost[0] = true;
    for now in (400..=8500).step_by(100) {
        d.tick(now).unwrap();
    }
    assert_eq!(w.borrow().selects, vec![Slot::B]);
    assert_eq!(d.state().snapshot().active, Slot::B);
    assert!(d.state().role_update().is_some());
}

#[test]
fn stale_standby_success_cannot_promote_after_network_epoch() {
    let (mut d, w) = setup();
    standby(&mut d, 0);
    d.tick(0).unwrap();
    d.tick(100).unwrap();
    d.network_changed(&scope(), 200, false).unwrap();
    w.borrow_mut().dead[0] = true;
    w.borrow_mut().lost[1] = true;
    for now in (300..=9000).step_by(100) {
        d.tick(now).unwrap();
    }
    assert!(w.borrow().selects.is_empty());
    assert!(!d.tick(9100).unwrap().primary_ready);
}

#[test]
fn stop_drops_probes_and_disables_members_even_if_journal_is_unwritable() {
    let (mut d, w) = setup();
    standby(&mut d, 0);
    d.tick(0).unwrap();
    w.borrow_mut().save_error = true;
    assert!(d.stop(&scope()).is_err());
    assert_eq!(w.borrow().closed, 1);
    assert_eq!(w.borrow().drops, 2);
    assert_eq!(d.state().snapshot().phase, SessionPhase::Stopped);
    d.tick(100).unwrap();
    assert_eq!(w.borrow().tx, [1, 1]);

    let (mut pending, w) = setup();
    w.borrow_mut().close_error = true;
    assert!(pending.stop(&scope()).is_err());
    for now in [100, 200, 300] {
        let tick = pending.tick(now).unwrap();
        assert!(!tick.primary_ready && !tick.standby_ready);
        assert_eq!(pending.state().snapshot().phase, SessionPhase::Stopping);
        assert_eq!((w.borrow().native_drops, w.borrow().store_drops), (0, 0));
    }
    assert!(
        pending.tick(250).is_err(),
        "backward clock still propagates"
    );
    w.borrow_mut().close_error = false;
    let tick = pending.tick(400).unwrap();
    assert!(!tick.primary_ready && !tick.standby_ready);
    assert_eq!(pending.state().snapshot().phase, SessionPhase::Stopped);

    let (mut pending, w) = setup();
    w.borrow_mut().close_error = true;
    assert!(pending.stop(&scope()).is_err());
    w.borrow_mut().close_error = false;
    w.borrow_mut().lost_save_ack = true;
    assert!(
        pending.tick(100).is_err(),
        "Stopped with lost final save ACK propagates"
    );
    assert_eq!(pending.state().snapshot().phase, SessionPhase::Stopped);

    let (mut running, w) = setup();
    w.borrow_mut().integrity_error = true;
    w.borrow_mut().close_error = true;
    assert!(
        running.tick(1000).is_err(),
        "first Running-to-Stopping close error propagates"
    );
    assert_eq!(running.state().snapshot().phase, SessionPhase::Stopping);
}

#[test]
fn failed_switch_never_publishes_b_or_its_server_role() {
    let (mut d, w) = setup();
    standby(&mut d, 0);
    d.tick(0).unwrap();
    d.tick(100).unwrap();
    w.borrow_mut().switch_error = true;
    w.borrow_mut().dead[0] = true;
    for now in (200..=3500).step_by(100) {
        let _ = d.tick(now);
    }
    assert_ne!(d.state().snapshot().active, Slot::B);
    assert!(d.state().role_update().is_none());
}

#[test]
fn backward_clock_fences_pending_probes_instead_of_reusing_health() {
    let (mut d, w) = setup();
    d.tick(100).unwrap();
    assert!(d.tick(50).is_err());
    assert_eq!(w.borrow().closed, 1);
}

#[test]
fn hard_failure_does_not_launch_reserve_ticket_cancelled_in_same_tick() {
    let (mut d, w) = setup();
    standby(&mut d, 0);
    w.borrow_mut().dead[0] = true;
    d.tick(0).unwrap();
    assert_eq!(
        w.borrow().tx[1],
        0,
        "normal B probe was cancelled by urgent episode"
    );
    d.tick(1000).unwrap();
    assert_eq!(w.borrow().tx[1], 1, "only new urgent B probe can send");
}

#[test]
fn primary_native_start_is_owned_before_effect_and_failure_remains_stoppable() {
    let w = Rc::new(RefCell::new(World::default()));
    let s = SessionState::new(scope(), Slot::A, 1, 1).unwrap();
    let mut d = SessionDriver::new(s, Pair(w.clone()), Store(w.clone()), 0).unwrap();
    assert!(!d.tick(0).unwrap().primary_ready);
    assert_eq!(w.borrow().tx, [0, 0]);
    assert!(d
        .start_primary(
            &scope(),
            |_| Err(io::Error::other("native partial failure")),
            |_| panic!("no completion after failed native Start")
        )
        .is_err());
    assert_eq!(d.state().snapshot().phase, SessionPhase::Stopped);
    assert_eq!(d.state().warm_slot(), None);
    assert_eq!(w.borrow().closed, 1);
    assert!(d
        .start_primary(
            &scope(),
            |_| panic!("late Start after Stop"),
            |_| panic!("no late completion")
        )
        .is_err());
}

#[test]
fn primary_start_success_is_not_yet_data_plane_ready() {
    let w = Rc::new(RefCell::new(World::default()));
    let s = SessionState::new(scope(), Slot::A, 1, 1).unwrap();
    let mut d = SessionDriver::new(s, Pair(w.clone()), Store(w.clone()), 0).unwrap();
    d.start_primary(&scope(), |_| Ok(()), |_| Ok(())).unwrap();
    assert!(!d.tick(0).unwrap().primary_ready);
    assert!(d.tick(100).unwrap().primary_ready);
}

#[test]
fn healthy_candidate_is_probed_but_cannot_receive_user_traffic_until_commit() {
    let (mut d, w) = setup();
    d.tick(0).unwrap();
    d.tick(100).unwrap();
    let ticket = d.state().install_ticket(&scope(), Slot::B).unwrap();
    d.candidate_installed(ticket, 200).unwrap();
    let mut ready = false;
    for now in (200..=16000).step_by(100) {
        ready = d.tick(now).unwrap().standby_ready;
    }
    assert!(ready);
    w.borrow_mut().dead[0] = true;
    for now in (16100..=18100).step_by(100) {
        d.tick(now).unwrap();
    }
    assert!(w.borrow().selects.is_empty());
    let snapshot = d.state().snapshot();
    d.commit_candidate(
        &scope(),
        Slot::B,
        snapshot.local_revision,
        snapshot.network_epoch,
        1,
        2,
    )
    .unwrap();
    for now in (18200..=22000).step_by(100) {
        d.tick(now).unwrap();
    }
    assert_eq!(w.borrow().selects, vec![Slot::B]);
}

#[test]
fn role_ack_disk_failure_cannot_leave_a_false_warm_claim() {
    let (mut d, w) = setup();
    standby(&mut d, 0);
    d.tick(0).unwrap();
    d.tick(100).unwrap();
    w.borrow_mut().dead[0] = true;
    for now in (200..=3500).step_by(100) {
        d.tick(now).unwrap();
    }
    let update = d.state().role_update().unwrap();
    w.borrow_mut().save_error = true;
    assert!(d.confirm_role(&update, 2).is_err());
    assert_eq!(d.state().warm_slot(), None);
    assert_eq!(d.state().snapshot().phase, SessionPhase::Stopped);
}

#[test]
fn prepare_stop_fences_outstanding_install_tickets_without_native_close() {
    let (mut d, w) = setup();
    let ticket = d.state().install_ticket(&scope(), Slot::B).unwrap();
    d.prepare_stop(&scope(), 100).unwrap();
    let frozen = d.state().snapshot();
    assert!(d.standby_installed(ticket.clone(), 2, 101).is_err());
    assert!(d.candidate_installed(ticket, 101).is_err());
    assert!(d
        .start_primary(
            &scope(),
            |_| panic!("frozen Start must not execute"),
            |_| panic!("no frozen completion")
        )
        .is_err());
    assert_eq!(d.state().snapshot(), frozen);
    assert_eq!(w.borrow().closed, 0);
    d.tick(1100).unwrap();
    assert_eq!(w.borrow().closed, 1);
}

#[test]
fn prepare_stop_cannot_confirm_an_outstanding_role_ack() {
    let (mut d, w) = setup();
    standby(&mut d, 0);
    d.tick(0).unwrap();
    d.tick(100).unwrap();
    w.borrow_mut().dead[0] = true;
    for now in (200..=3500).step_by(100) {
        d.tick(now).unwrap();
    }
    let update = d.state().role_update().unwrap();
    d.prepare_stop(&scope(), 3600).unwrap();
    assert!(d.confirm_role(&update, 2).is_err());
    assert_eq!(d.state().snapshot().active, Slot::B);
    assert_eq!(d.state().warm_slot(), None);
    assert_eq!(w.borrow().closed, 0);
    d.tick(4600).unwrap();
    assert_eq!(w.borrow().closed, 1);
}

#[test]
fn prepare_stop_validates_scope_before_clock_and_closes_on_unbounded_deadline() {
    let (mut d, w) = setup();
    d.tick(100).unwrap();
    let before = d.state().snapshot();
    let mut stale = scope();
    stale.connection_generation += 1;
    assert!(d.prepare_stop(&stale, 0).is_err());
    assert_eq!(d.state().snapshot(), before);
    assert_eq!(w.borrow().closed, 0);
    assert!(d.prepare_stop(&scope(), u64::MAX).is_err());
    assert_eq!(d.state().snapshot().phase, SessionPhase::Stopped);
    assert_eq!(w.borrow().closed, 1);
}
