use super::*;
use crate::member_owner::{
    InterfaceProof, Journal, MemberIo, MemberOwner, NativeProof, Observation, OwnerError, Phase,
    ProcessProof, Record, Result, ServiceObservation,
};
use nelomai_client_tunnel::{redundancy::SessionScope, TunnelTransport};
use nelomai_contracts::{dispatcher::TunnelSlot, RuntimeSlot};
use std::{cell::RefCell, rc::Rc};

const CONFIG: &str =
    "[Interface]\nPrivateKey = PRIVATE-TEST-KEY\nDNS = 9.9.9.9\n[Peer]\nPublicKey = test\n";

#[test]
fn terminal_unstarted_registration_requires_same_actual_pending_without_io() {
    let state = State::default();
    let mut member = RetainedMember::new(owner(&state));
    let pending = member.pending_read().unwrap();
    let foreign = RetainedMember::new(owner(&State::default()));
    let foreign_pending = foreign.pending_read().unwrap();
    state.borrow_mut().on_load = Some(Rc::new(|| panic!("terminal facts must not read storage")));
    assert_eq!(
        member
            .verify_terminal_unstarted_registration(&pending)
            .unwrap(),
        pending.intent
    );
    assert!(member
        .verify_terminal_unstarted_registration(&foreign_pending)
        .is_err());
    for fault in 0..3 {
        let mut changed = pending.read_pin();
        match fault {
            0 => changed.intent.scope.connection_generation += 1,
            1 => changed.intent.slot = TunnelSlot::B,
            _ => changed.generation += 1,
        }
        assert!(member
            .verify_terminal_unstarted_registration(&changed)
            .is_err());
    }
    state.borrow_mut().on_load = None;
    state.borrow_mut().lost_start_ack = true;
    assert!(member.start().is_err());
    assert!(member
        .verify_terminal_unstarted_registration(&pending)
        .is_err());
}

#[test]
fn unstarted_native_cleanup_denies_stale_pending_generation_before_any_read() {
    let state = State::default();
    let member = RetainedMember::new(owner(&state));
    let mut pending = member.pending_read().unwrap();
    pending.generation += 1;
    assert!(pending.read_unstarted_for_cleanup().is_err());
    assert_eq!(state.borrow().starts, 0);
    assert_eq!(state.borrow().config_writes, 0);
}

#[test]
fn terminal_registration_after_actual_native_rebind_requires_current_original_generation() {
    for slot in [TunnelSlot::A, TunnelSlot::B] {
        for transport in [TunnelTransport::WireGuard, TunnelTransport::AmneziaWg3] {
            let mut original = crate::member_original::rebind_test_support::start_original(
                owner(&State::default()).intent().scope.clone(),
                slot,
                transport,
                crate::test_engine_path("engine.exe"),
                native(),
            )
            .unwrap();
            let (running, rebound, reader) =
                original.member.rebind_original(&original.running).unwrap();
            let pending = original.member.pending_rebind_read(&rebound).unwrap();
            rebound
                .verify_retired_original_read(&original.reader)
                .unwrap();
            rebound.verify_replacement_original_read(&reader).unwrap();
            let (stopped, closed) = original.member.stop(&running).unwrap();
            let before = original.control.counts();
            assert_eq!(
                original
                    .member
                    .verify_terminal_closed_registration(&pending, &closed)
                    .unwrap(),
                stopped
            );
            assert!(original
                .member
                .verify_terminal_closed_registration(&original.pending, &closed)
                .is_err());
            assert!(original
                .member
                .verify_terminal_unstarted_registration(&pending)
                .is_err());
            assert_eq!(original.control.counts(), before);
        }
    }
}

#[test]
fn terminal_closed_registration_authenticates_actual_ack_without_old_file_or_sdk_reads() {
    let state = State::default();
    let mut member = RetainedMember::new(owner(&state));
    let pending = member.pending_read().unwrap();
    let running = member.start().unwrap();
    let (stopped, closed) = member.stop(&running).unwrap();
    let foreign_state = State::default();
    let mut foreign = RetainedMember::new(owner(&foreign_state));
    let foreign_pending = foreign.pending_read().unwrap();
    let foreign_running = foreign.start().unwrap();
    let (_, foreign_closed) = foreign.stop(&foreign_running).unwrap();
    // Next generation may have rewritten the original journal. This method is
    // inert-destructor registration, never a fresh native absence observation.
    state.borrow_mut().record = None;
    state.borrow_mut().fail_absence = true;
    state.borrow_mut().on_load = Some(Rc::new(|| panic!("historical file lookup forbidden")));
    assert_eq!(
        member
            .verify_terminal_closed_registration(&pending, &closed)
            .unwrap(),
        stopped
    );
    assert!(member
        .verify_terminal_closed_registration(&foreign_pending, &closed)
        .is_err());
    assert!(member
        .verify_terminal_closed_registration(&pending, &foreign_closed)
        .is_err());
    assert!(member
        .verify_terminal_unstarted_registration(&pending)
        .is_err());
}

fn readonly_profile_owner(state: &State) -> MemberOwner<Disk, Io> {
    let config = "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n";
    MemberOwner::from_trusted_engine(
        owner(state).intent().scope.clone(),
        TunnelSlot::B,
        TunnelTransport::WireGuard,
        crate::test_engine_path("engine.exe"),
        config,
        Disk(state.clone()),
        Io(state.clone()),
    )
    .unwrap()
}

#[test]
fn actual_retained_owner_keeps_readonly_profile_before_start_without_effects() {
    let state = Rc::new(RefCell::new(BoundaryState::default()));
    let retained = RetainedMember::new(readonly_profile_owner(&state));
    assert!(retained.verify_readonly_native_profile().is_err());
    retained.prepare_readonly_native_profile().unwrap();
    retained.verify_readonly_native_profile().unwrap();
    assert_eq!(state.borrow().journal_writes, 0);
    assert_eq!(state.borrow().config_writes, 0);
    assert_eq!(state.borrow().starts, 0);
    assert_eq!(state.borrow().stops, 0);
    // No Source/SDK/Journals are re-entered from this original comparison.
    state.borrow_mut().on_load = Some(Rc::new(|| panic!("readonly parser cannot query journal")));
    retained.verify_readonly_native_profile().unwrap();
    let pending = retained.pending_read().unwrap();
    let io_drops = state.borrow().io_drops;
    drop(retained);
    assert_eq!(state.borrow().io_drops, io_drops);
    drop(pending);
    assert_eq!(state.borrow().io_drops, io_drops + 1);
}

#[test]
fn actual_closed_owner_retains_parser_fact_without_resurrecting_live_authority() {
    let state = Rc::new(RefCell::new(BoundaryState::default()));
    let mut retained = RetainedMember::new(readonly_profile_owner(&state));
    retained.prepare_readonly_native_profile().unwrap();
    let running = retained.start_with_prior(None).unwrap();
    let mut reader = retained.original_read().unwrap();
    let (_, closed) = retained.stop(&running).unwrap();
    retained.verify_closed(&closed).unwrap();
    assert!(reader.read().is_err());
    state.borrow_mut().on_load = Some(Rc::new(|| {
        panic!("parser fact cannot read post-stop files")
    }));
    retained.verify_readonly_native_profile().unwrap();
    assert!(retained.prepare_readonly_native_profile().is_err());
    assert_eq!(state.borrow().starts, 1);
    assert_eq!(state.borrow().stops, 1);
}
fn native() -> NativeProof {
    NativeProof {
        process: ProcessProof {
            pid: 20,
            creation_time: 30,
        },
        interface: InterfaceProof {
            index: 40,
            luid: 50,
            guid: [6; 16],
        },
    }
}
#[derive(Default)]
struct BoundaryState {
    record: Option<Record>,
    digest: Option<[u8; 32]>,
    running: bool,
    original: bool,
    original_created: bool,
    on_original: Option<Rc<dyn Fn()>>,
    observed: Option<NativeProof>,
    starts: usize,
    stops: usize,
    fail_stop_save: bool,
    lost_stop_ack: bool,
    fail_absence: bool,
    panic_absence: bool,
    fail_original: bool,
    panic_original: bool,
    io_drops: usize,
    lost_start_ack: bool,
    panic_start_ack: bool,
    journal_writes: usize,
    config_writes: usize,
    on_load: Option<Rc<dyn Fn()>>,
}
type State = Rc<RefCell<BoundaryState>>;
struct Disk(State);
struct Io(State);
impl Drop for Io {
    fn drop(&mut self) {
        self.0.borrow_mut().io_drops += 1;
    }
}
impl Journal for Disk {
    fn load(&mut self, _: TunnelSlot) -> Result<Option<Record>> {
        let hook = self.0.borrow().on_load.clone();
        if let Some(hook) = hook {
            hook();
        }
        Ok(self.0.borrow().record.clone())
    }
    fn compare_exchange(
        &mut self,
        _: TunnelSlot,
        expected: Option<&Record>,
        desired: &Record,
    ) -> Result<()> {
        let mut state = self.0.borrow_mut();
        if state.record.as_ref() != expected {
            return Err(OwnerError::Conflict);
        }
        if desired.phase == Phase::Stopped && state.fail_stop_save {
            return Err(OwnerError::Journal);
        }
        state.record = Some(desired.clone());
        state.journal_writes += 1;
        if desired.phase == Phase::Stopped && state.lost_stop_ack {
            return Err(OwnerError::Journal);
        }
        Ok(())
    }
}
impl MemberIo for Io {
    fn inspect(
        &mut self,
        _: &crate::member_owner::Intent,
        retained: Option<&NativeProof>,
    ) -> Result<Observation> {
        let state = self.0.borrow();
        let observed = state.observed.unwrap_or_else(native);
        assert!(
            state.running || !state.panic_absence,
            "OS absence read unwind"
        );
        if !state.running && state.fail_absence {
            return Err(OwnerError::Native);
        }
        Ok(Observation {
            config_sha256: state.digest,
            service: state.running.then_some(ServiceObservation {
                exact_spec: true,
                process: Some(observed.process),
            }),
            alternative_service_present: false,
            interface: state.running.then_some(observed.interface),
            retained_interfaces: if state.running && retained.is_some() {
                vec![observed.interface]
            } else {
                vec![]
            },
        })
    }
    fn inspect_original(
        &mut self,
        intent: &crate::member_owner::Intent,
        proof: &NativeProof,
    ) -> Result<Observation> {
        let state = self.0.borrow();
        assert!(!state.panic_original, "OS original read unwind");
        if !state.original || !state.original_created || state.fail_original {
            return Err(OwnerError::Native);
        }
        let hook = state.on_original.clone();
        drop(state);
        if let Some(hook) = hook {
            hook();
        }
        self.inspect(intent, Some(proof))
    }
    fn inspect_original_for_cleanup(
        &mut self,
        intent: &crate::member_owner::Intent,
        proof: &NativeProof,
    ) -> Result<Observation> {
        let state = self.0.borrow();
        assert!(!state.panic_original, "OS cleanup original read unwind");
        if !state.original_created || state.fail_original {
            return Err(OwnerError::Native);
        }
        let hook = state.on_original.clone();
        drop(state);
        if let Some(hook) = hook {
            hook();
        }
        self.inspect(intent, Some(proof))
    }
    fn revoke_original(&mut self) {
        self.0.borrow_mut().original = false;
    }
    fn write_private_config(
        &mut self,
        intent: &crate::member_owner::Intent,
        expected: Option<[u8; 32]>,
        _: &str,
    ) -> Result<()> {
        let mut state = self.0.borrow_mut();
        if state.digest != expected {
            return Err(OwnerError::Conflict);
        }
        state.digest = Some(intent.config_sha256);
        state.config_writes += 1;
        Ok(())
    }
    fn start_fresh(
        &mut self,
        _: &crate::member_owner::Intent,
        _: Option<&NativeProof>,
    ) -> Result<()> {
        let mut state = self.0.borrow_mut();
        state.starts += 1;
        state.running = true;
        state.original = true;
        state.original_created = true;
        assert!(!state.panic_start_ack, "native Start ACK unwind");
        if state.lost_start_ack {
            return Err(OwnerError::Native);
        }
        Ok(())
    }
    fn stop_slot(
        &mut self,
        _: &crate::member_owner::Intent,
        _: Option<&NativeProof>,
        _: &Observation,
    ) -> Result<()> {
        let mut state = self.0.borrow_mut();
        state.stops += 1;
        state.running = false;
        state.original = false;
        state.original_created = false;
        Ok(())
    }
    fn rebind(
        &mut self,
        _: &crate::member_owner::Intent,
        _: &NativeProof,
        _: &Observation,
    ) -> Result<()> {
        Err(OwnerError::Native)
    }
}
fn owner(state: &State) -> MemberOwner<Disk, Io> {
    MemberOwner::from_trusted_engine(
        SessionScope {
            runtime: RuntimeSlot::Stable,
            runtime_generation: 2,
            session_id: "11111111-1111-4111-8111-111111111111".into(),
            connection_generation: 3,
        },
        TunnelSlot::A,
        TunnelTransport::WireGuard,
        crate::test_engine_path("engine.exe"),
        CONFIG,
        Disk(state.clone()),
        Io(state.clone()),
    )
    .unwrap()
}

#[test]
fn independent_reader_retains_the_actual_owner_and_files_after_controller_drop() {
    let state = State::default();
    let mut controller = RetainedMember::new(owner(&state));
    let running = controller.start().unwrap();
    let mut read = controller.original_read().unwrap();
    drop(controller);
    assert_eq!(state.borrow().io_drops, 0);
    assert_eq!(read.read().unwrap(), (running.intent, native()));
    drop(read);
    assert_eq!(state.borrow().io_drops, 1);
    assert_eq!(state.borrow().stops, 0); // No Stop/Delete in retention Drop.
}

#[test]
fn started_registration_purely_matches_exact_original_without_reading_private_files() {
    let state = State::default();
    let mut controller = RetainedMember::new(owner(&state));
    let pending = controller.pending_read().unwrap();
    controller.start().unwrap();
    let read = controller.original_read().unwrap();
    let registration = read.registration().unwrap();
    let second = controller.original_read().unwrap();
    state.borrow_mut().on_load = Some(Rc::new(|| panic!("registration queried private file")));
    registration.verify_original_read(&second).unwrap();
    registration.verify_pending_read(&pending).unwrap();
    assert_eq!(registration.proof(), native());
    let foreign_state = State::default();
    let mut foreign = RetainedMember::new(owner(&foreign_state));
    let foreign_pending = foreign.pending_read().unwrap();
    foreign.start().unwrap();
    let foreign_read = foreign.original_read().unwrap();
    assert!(registration.verify_original_read(&foreign_read).is_err());
    assert!(registration.verify_pending_read(&foreign_pending).is_err());
}

#[test]
fn started_registration_denies_wrong_scope_proof_generation_and_closed_original() {
    let state = State::default();
    let mut controller = RetainedMember::new(owner(&state));
    let running = controller.start().unwrap();
    let read = controller.original_read().unwrap();
    let registration = read.registration().unwrap();
    for fault in 0..3 {
        let mut changed = controller.original_read().unwrap();
        match fault {
            0 => changed.intent.scope.connection_generation += 1,
            1 => changed.proof.process.creation_time += 1,
            _ => changed.generation += 1,
        }
        assert!(registration.verify_original_read(&changed).is_err());
    }
    controller.stop(&running).unwrap();
    assert!(registration.verify_original_read(&read).is_err());
    assert!(read.registration().is_err());
}

#[test]
fn started_registration_retains_actual_io_without_implicit_stop_after_controller_drop() {
    let state = State::default();
    let mut controller = RetainedMember::new(owner(&state));
    controller.start().unwrap();
    let reader = controller.original_read().unwrap();
    let registration = reader.registration().unwrap();
    drop(controller);
    drop(reader);
    assert_eq!(state.borrow().io_drops, 0);
    assert_eq!(state.borrow().stops, 0);
    registration.verify_current().unwrap(); // Identity only, not SDK/absence.
    drop(registration);
    assert_eq!(state.borrow().io_drops, 1);
    assert_eq!(state.borrow().stops, 0);
}

// Break: returning absent from an unstarted flag without reading this owner's
// actual private predecessor/native absence, or publishing a synthetic Stop.
#[test]
fn unstarted_cleanup_reads_actual_private_owner_without_any_publication_or_native_effect() {
    let state = State::default();
    let mut controller = RetainedMember::new(owner(&state));
    let mut pending = controller.pending_read().unwrap();
    let intent = pending.intent().clone();
    assert_eq!(
        pending.read_unstarted_for_cleanup().unwrap(),
        (intent.clone(), None)
    );
    assert_eq!(
        pending.read_unstarted_for_cleanup().unwrap(),
        (intent, None)
    );
    assert!(controller.start().is_err()); // Closing never rearms forwarding.
    let s = state.borrow();
    assert_eq!(
        (s.journal_writes, s.config_writes, s.starts, s.stops),
        (0, 0, 0, 0)
    );
    assert!(s.record.is_none());
}

#[test]
fn unstarted_cleanup_denies_lost_start_ack_and_foreign_pending_intent() {
    let state = State::default();
    let controller = RetainedMember::new(owner(&state));
    let mut pending = controller.pending_read().unwrap();
    pending.intent.scope.connection_generation += 1;
    assert!(pending.read_unstarted_for_cleanup().is_err());
    let state = State::default();
    let mut controller = RetainedMember::new(owner(&state));
    let mut pending = controller.pending_read().unwrap();
    state.borrow_mut().lost_start_ack = true;
    assert!(controller.start().is_err());
    state.borrow_mut().running = false; // Disappearance cannot erase attempt.
    assert!(pending.read_unstarted_for_cleanup().is_err());
}

#[test]
fn unstarted_cleanup_error_and_unwind_retain_owner_without_synthetic_stop() {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    for unwind in [false, true] {
        let state = State::default();
        let controller = RetainedMember::new(owner(&state));
        let mut pending = controller.pending_read().unwrap();
        state.borrow_mut().fail_absence = !unwind;
        state.borrow_mut().panic_absence = unwind;
        if unwind {
            assert!(
                catch_unwind(AssertUnwindSafe(|| pending.read_unstarted_for_cleanup())).is_err()
            );
        } else {
            assert!(pending.read_unstarted_for_cleanup().is_err());
        }
        drop(controller);
        assert_eq!(state.borrow().io_drops, 0);
        assert_eq!(state.borrow().journal_writes, 0);
        assert_eq!(state.borrow().stops, 0);
        drop(pending);
        assert_eq!(state.borrow().io_drops, 1);
    }
}

#[test]
fn pending_owner_pin_closes_without_ever_creating_a_running_reader() {
    let state = State::default();
    let mut controller = RetainedMember::new(owner(&state));
    let mut pending = controller.pending_read().unwrap();
    assert_eq!(pending.read_preparing().unwrap().1, None);
    let running = controller.start().unwrap();
    state.borrow_mut().fail_original = true;
    assert!(controller.original_read().is_err());
    state.borrow_mut().fail_original = false;
    let (stopped, receipt) = controller.stop(&running).unwrap();
    controller.verify_closed(&receipt).unwrap();
    assert_eq!(pending.read_closed(&receipt).unwrap(), stopped);
    assert!(pending.read_preparing().is_err());
    drop(controller);
    assert_eq!(state.borrow().io_drops, 0);
    pending.read_closed(&receipt).unwrap();
    drop(pending);
    drop(receipt);
    assert_eq!(state.borrow().io_drops, 1);
}

#[test]
fn pending_owner_pin_rejects_equal_foreign_closed_receipt_and_native_unknown() {
    let a = State::default();
    let b = State::default();
    let mut first = RetainedMember::new(owner(&a));
    let mut second = RetainedMember::new(owner(&b));
    let mut pending = first.pending_read().unwrap();
    let ar = first.start().unwrap();
    let br = second.start().unwrap();
    assert_eq!(ar, br);
    let (_, foreign) = second.stop(&br).unwrap();
    assert!(pending.read_closed(&foreign).is_err());
    let (stopped, exact) = first.stop(&ar).unwrap();
    assert_eq!(pending.read_closed(&exact).unwrap(), stopped);
    a.borrow_mut().fail_absence = true;
    assert!(pending.read_closed(&exact).is_err());
    assert!(first.verify_closed(&exact).is_err());
    a.borrow_mut().fail_absence = false;
    pending.read_closed(&exact).unwrap();
}

#[test]
fn pending_stop_receipt_for_native_start_error_never_fabricates_running_proof() {
    for unwind in [false, true] {
        let state = State::default();
        let mut controller = RetainedMember::new(owner(&state));
        let mut pending = controller.pending_read().unwrap();
        state.borrow_mut().lost_start_ack = !unwind;
        state.borrow_mut().panic_start_ack = unwind;
        let start = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| controller.start()));
        if unwind {
            assert!(start.is_err());
        } else {
            assert!(start.unwrap().is_err());
        }
        assert!(state.borrow().running);
        let actual = controller.snapshot().unwrap().unwrap();
        assert_eq!(actual.phase, Phase::Prepared);
        assert!(actual.proof.is_none());
        assert!(controller.original_read().is_err());
        assert_eq!(pending.read_for_cleanup(), Err(OwnerError::Pending));
        let (stopped, receipt) = controller.stop(&actual).unwrap();
        assert!(stopped.retired_proof.is_none());
        controller.verify_closed(&receipt).unwrap();
        assert_eq!(pending.read_closed(&receipt).unwrap(), stopped);
        assert_eq!(pending.read_closed_proof(&receipt).unwrap(), None);
        assert_eq!(state.borrow().stops, 1);
        assert!(controller.start().is_err());
    }
}

#[test]
fn pending_closed_proof_comes_only_from_same_original_stop_attempt_not_equal_receipt() {
    let state = State::default();
    let other_state = State::default();
    let mut member = RetainedMember::new(owner(&state));
    let mut other = RetainedMember::new(owner(&other_state));
    let mut pending = member.pending_read().unwrap();
    let running = member.start().unwrap();
    let foreign_running = other.start().unwrap();
    let (_, foreign) = other.stop(&foreign_running).unwrap();
    assert!(pending.read_closed_proof(&foreign).is_err());
    let (_, receipt) = member.stop(&running).unwrap();
    assert_eq!(
        pending.read_closed_proof(&receipt).unwrap(),
        Some((running.intent, native()))
    );
}

#[test]
fn pending_closed_proof_never_promotes_previous_incarnations_retired_proof() {
    let state = State::default();
    let mut previous = RetainedMember::new(owner(&state));
    let running = previous.start().unwrap();
    let (old, _) = previous.stop(&running).unwrap();
    assert_eq!(old.retired_proof, Some(native()));
    let mut current = RetainedMember::new(owner(&state));
    let mut pending = current.pending_read().unwrap();
    state.borrow_mut().lost_start_ack = true;
    assert!(current.start_with_prior(Some(&old)).is_err());
    let actual = current.snapshot().unwrap().unwrap();
    assert_eq!(actual.phase, Phase::Prepared);
    assert!(actual.proof.is_none());
    let (stopped, receipt) = current.stop(&actual).unwrap();
    assert_eq!(stopped.retired_proof, old.retired_proof);
    assert_eq!(pending.read_closed_proof(&receipt).unwrap(), None);
}

#[test]
fn pending_forward_read_denies_caught_same_owner_reentry_and_never_rearms() {
    let state = State::default();
    let mut controller = RetainedMember::new(owner(&state));
    let mut outer = controller.pending_read().unwrap();
    let nested = Rc::new(RefCell::new(outer.read_pin()));
    controller.start().unwrap();
    let calls = Rc::new(Cell::new(0));
    let nested_calls = calls.clone();
    state.borrow_mut().on_original = Some(Rc::new(move || {
        nested_calls.set(nested_calls.get() + 1);
        assert!(nested.borrow_mut().read_preparing().is_err());
    }));
    assert!(outer.read_preparing().is_err());
    assert!(calls.get() > 0);
    state.borrow_mut().on_original = None;
    assert!(outer.read_preparing().is_err());
    assert!(outer.read_for_cleanup().is_ok());
    assert!(controller.original_read().is_err());
}

#[test]
fn equal_existing_journal_and_native_facts_cannot_seed_another_original_reader() {
    let state = State::default();
    let mut first = RetainedMember::new(owner(&state));
    first.start().unwrap();
    let mut original = first.original_read().unwrap();
    let mut second = RetainedMember::new(owner(&state));
    assert!(second.original_read().is_err());
    // The second native boundary's revocation is local in production. Restore
    // this shared OS fake flag; no actual original owner record was changed.
    state.borrow_mut().original = true;
    assert!(original.read().is_ok());
    assert_eq!(state.borrow().starts, 1);
}

#[test]
fn stop_receipt_follows_exact_native_absence_and_durable_stop_not_a_native_request() {
    let state = State::default();
    let mut controller = RetainedMember::new(owner(&state));
    let running = controller.start().unwrap();
    let mut reader = controller.original_read().unwrap();
    state.borrow_mut().fail_stop_save = true;
    assert!(controller.stop(&running).is_err());
    assert_eq!(state.borrow().stops, 1);
    assert!(!state.borrow().running);
    assert!(reader.read().is_err());
    let closing = controller.snapshot().unwrap().unwrap();
    state.borrow_mut().fail_stop_save = false;
    let (stopped, receipt) = controller.stop(&closing).unwrap();
    assert_eq!(stopped.phase, Phase::Stopped);
    reader.verify_closed(&receipt).unwrap();
    assert_eq!(state.borrow().stops, 1); // No duplicate native delete on retry.
    assert!(controller.stop(&stopped).is_err()); // Receipt cannot be reissued.
    assert!(reader.read().is_err());
}

#[test]
fn foreign_closure_receipt_cannot_retire_an_equal_reader() {
    let a = State::default();
    let b = State::default();
    let mut first = RetainedMember::new(owner(&a));
    let mut second = RetainedMember::new(owner(&b));
    let a_running = first.start().unwrap();
    let b_running = second.start().unwrap();
    assert_eq!(a_running, b_running); // Equal DATA deliberately.
    let mut reader = first.original_read().unwrap();
    let (_, foreign) = second.stop(&b_running).unwrap();
    assert!(reader.verify_closed(&foreign).is_err());
    assert!(reader.read().is_err()); // Failed closure verification revokes forward.
}

#[test]
fn native_read_error_and_unwind_irreversibly_revoke_all_readers() {
    for unwind in [false, true] {
        let state = State::default();
        let mut controller = RetainedMember::new(owner(&state));
        let running = controller.start().unwrap();
        let mut first = controller.original_read().unwrap();
        let mut second = controller.original_read().unwrap();
        state.borrow_mut().fail_original = !unwind;
        state.borrow_mut().panic_original = unwind;
        let attempted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| first.read()));
        if unwind {
            assert!(attempted.is_err());
        } else {
            assert!(attempted.unwrap().is_err());
        }
        state.borrow_mut().fail_original = false;
        state.borrow_mut().panic_original = false;
        state.borrow_mut().original = true; // Changed OS cannot rearm SAME owner.
        assert!(second.read().is_err());
        let (_, receipt) = controller.stop(&running).unwrap();
        second.verify_closed(&receipt).unwrap();
    }
}

#[test]
fn journal_drift_and_caught_reentrant_read_cannot_become_fresh_permission() {
    let state = State::default();
    let mut controller = RetainedMember::new(owner(&state));
    let running = controller.start().unwrap();
    let mut reader = controller.original_read().unwrap();
    state
        .borrow_mut()
        .record
        .as_mut()
        .unwrap()
        .intent
        .scope
        .connection_generation += 1;
    assert!(reader.read().is_err());
    state.borrow_mut().record = Some(running.clone());
    assert!(reader.read().is_err());

    let state = State::default();
    let mut controller = RetainedMember::new(owner(&state));
    controller.start().unwrap();
    let mut reader = controller.original_read().unwrap();
    let held = controller.shared.owner.borrow_mut();
    assert!(reader.read().is_err());
    drop(held);
    assert!(controller.original_read().is_err());
    assert!(reader.read().is_err());
}

#[test]
fn lost_terminal_ack_can_be_read_back_by_same_controller_without_second_native_stop() {
    let state = State::default();
    let mut controller = RetainedMember::new(owner(&state));
    let running = controller.start().unwrap();
    let mut reader = controller.original_read().unwrap();
    state.borrow_mut().lost_stop_ack = true;
    assert!(controller.stop(&running).is_err());
    let stopped = controller.snapshot().unwrap().unwrap();
    assert_eq!(stopped.phase, Phase::Stopped);
    state.borrow_mut().lost_stop_ack = false;
    let (_, receipt) = controller.stop(&stopped).unwrap();
    reader.verify_closed(&receipt).unwrap();
    assert_eq!(state.borrow().stops, 1);
}

#[test]
fn completion_is_fresh_and_foreign_terminal_record_never_manufactures_receipt() {
    let state = State::default();
    let mut controller = RetainedMember::new(owner(&state));
    let running = controller.start().unwrap();
    let mut reader = controller.original_read().unwrap();
    let (stopped, receipt) = controller.stop(&running).unwrap();
    state.borrow_mut().fail_absence = true;
    assert!(reader.verify_closed(&receipt).is_err());
    state.borrow_mut().fail_absence = false;
    reader.verify_closed(&receipt).unwrap();
    let mut recovered = RetainedMember::new(owner(&state));
    assert!(recovered.stop(&stopped).is_err());
    assert_eq!(state.borrow().stops, 1);
}

#[test]
fn closed_history_requires_exact_actual_receipt_and_retains_same_io_after_stop() {
    let state = State::default();
    let mut controller = RetainedMember::new(owner(&state));
    let running = controller.start().unwrap();
    let mut reader = controller.original_read().unwrap();
    let (stopped, receipt) = controller.stop(&running).unwrap();
    drop(controller);
    assert_eq!(state.borrow().io_drops, 0);
    assert_eq!(stopped.proof, None);
    assert_eq!(
        reader.read_closed_history(&receipt).unwrap(),
        (running.intent, native())
    );
    assert!(reader.read().is_err());
    drop(reader);
    assert_eq!(state.borrow().io_drops, 0); // Receipt also retains the SAME IO.
    drop(receipt);
    assert_eq!(state.borrow().io_drops, 1);
    assert_eq!(state.borrow().starts, 1);
    assert_eq!(state.borrow().stops, 1);
}

#[test]
fn equal_foreign_receipt_never_returns_closed_history_or_preserves_live_permission() {
    let a = State::default();
    let b = State::default();
    let mut first = RetainedMember::new(owner(&a));
    let mut second = RetainedMember::new(owner(&b));
    let running = first.start().unwrap();
    let foreign_running = second.start().unwrap();
    assert_eq!(running, foreign_running);
    let mut reader = first.original_read().unwrap();
    let (_, foreign) = second.stop(&foreign_running).unwrap();
    assert!(reader.read_closed_history(&foreign).is_err());
    assert!(reader.read().is_err());
    assert!(first.original_read().is_err());
    let (_, exact) = first.stop(&running).unwrap();
    assert_eq!(
        reader.read_closed_history(&exact).unwrap(),
        (running.intent, native())
    );
    assert!(reader.read().is_err());
}

#[test]
fn closed_history_rechecks_durable_stop_and_native_absence_on_every_read() {
    for fault in 0..3 {
        let state = State::default();
        let mut controller = RetainedMember::new(owner(&state));
        let running = controller.start().unwrap();
        let mut reader = controller.original_read().unwrap();
        let (stopped, receipt) = controller.stop(&running).unwrap();
        reader.read_closed_history(&receipt).unwrap();
        match fault {
            0 => state.borrow_mut().record = Some(running.clone()),
            1 => state.borrow_mut().fail_absence = true,
            _ => state.borrow_mut().running = true,
        }
        assert!(
            reader.read_closed_history(&receipt).is_err(),
            "fault {fault}"
        );
        state.borrow_mut().record = Some(stopped);
        state.borrow_mut().fail_absence = false;
        state.borrow_mut().running = false;
        assert_eq!(
            reader.read_closed_history(&receipt).unwrap(),
            (running.intent, native())
        );
        assert!(reader.read().is_err());
        assert!(controller.start().is_err());
    }
}

#[test]
fn sealed_generation_preserves_only_original_history_after_private_journal_reuse() {
    let state = State::default();
    let mut controller = RetainedMember::new(owner(&state));
    let running = controller.start().unwrap();
    let mut reader = controller.original_read().unwrap();
    let pending = PendingMemberRead {
        shared: controller.shared.clone(),
        intent: running.intent.clone(),
        generation: controller.shared.read_generation.get(),
    };
    let (stopped, receipt) = controller.stop(&running).unwrap();
    let receipt = Rc::new(receipt);
    let sealed = controller.seal_closed_generation(&receipt).unwrap();
    assert!(Rc::ptr_eq(
        &sealed,
        &controller.seal_closed_generation(&receipt).unwrap()
    ));
    sealed.verify_live_reader(&reader).unwrap();
    sealed.verify_pending_reader(&pending).unwrap();

    // A later owner may reuse private storage only after Main's independently
    // authorized SDK/inventory/row/key retirement. The seal itself grants none.
    state.borrow_mut().record = Some(running.clone());
    state.borrow_mut().running = true;
    assert!(reader.read_closed_history(&receipt).is_err());
    assert!(controller.verify_closed(&receipt).is_err());
    assert!(reader.read().is_err());
    assert_eq!(
        sealed.read_history(&receipt).unwrap(),
        (stopped.intent, Some(native()))
    );
    drop(controller);
    drop(reader);
    drop(pending);
    drop(receipt);
    assert_eq!(state.borrow().io_drops, 0);
    drop(sealed);
    assert_eq!(state.borrow().io_drops, 1);
    assert_eq!(state.borrow().starts, 1);
    assert_eq!(state.borrow().stops, 1);
}

#[test]
fn retired_original_reader_comparison_never_queries_reused_private_files() {
    let state = State::default();
    let mut controller = RetainedMember::new(owner(&state));
    let running = controller.start().unwrap();
    let reader = controller.original_read().unwrap();
    let (stopped, receipt) = controller.stop(&running).unwrap();
    let receipt = Rc::new(receipt);
    let seal = controller.seal_closed_generation(&receipt).unwrap();
    state.borrow_mut().record = Some(running);
    state.borrow_mut().running = true;
    state.borrow_mut().on_load = Some(Rc::new(|| panic!("old generation journal queried")));
    seal.verify_retired_original_read(&reader, &receipt, &stopped)
        .unwrap();
    assert_eq!(state.borrow().starts, 1);
    assert_eq!(state.borrow().stops, 1);
    state.borrow_mut().on_load = None;
}

#[test]
fn retired_original_reader_comparison_denies_foreign_rc_scope_proof_and_record() {
    let state = State::default();
    let foreign = State::default();
    let mut controller = RetainedMember::new(owner(&state));
    let mut other = RetainedMember::new(owner(&foreign));
    let running = controller.start().unwrap();
    let other_running = other.start().unwrap();
    let reader = controller.original_read().unwrap();
    let other_reader = other.original_read().unwrap();
    let (stopped, receipt) = controller.stop(&running).unwrap();
    let (_, other_receipt) = other.stop(&other_running).unwrap();
    let receipt = Rc::new(receipt);
    let seal = controller.seal_closed_generation(&receipt).unwrap();
    assert!(seal
        .verify_retired_original_read(&other_reader, &receipt, &stopped)
        .is_err());
    assert!(seal
        .verify_retired_original_read(&reader, &Rc::new(other_receipt), &stopped)
        .is_err());
    for fault in 0..3 {
        let mut wrong = stopped.clone();
        match fault {
            0 => wrong.intent.scope.connection_generation += 1,
            1 => wrong.retired_proof.as_mut().unwrap().process.creation_time += 1,
            _ => wrong.intent.config_sha256 = [4; 32],
        }
        assert!(seal
            .verify_retired_original_read(&reader, &receipt, &wrong)
            .is_err());
    }
    seal.verify_retired_original_read(&reader, &receipt, &stopped)
        .unwrap();
}

#[test]
fn sealed_generation_rejects_foreign_equal_ack_and_reader_without_new_effects() {
    let state = State::default();
    let foreign = State::default();
    let mut controller = RetainedMember::new(owner(&state));
    let mut other = RetainedMember::new(owner(&foreign));
    let running = controller.start().unwrap();
    let other_running = other.start().unwrap();
    assert_eq!(running, other_running);
    let other_reader = other.original_read().unwrap();
    let other_pending = PendingMemberRead {
        shared: other.shared.clone(),
        intent: running.intent.clone(),
        generation: other.shared.read_generation.get(),
    };
    let (_, receipt) = controller.stop(&running).unwrap();
    let (_, other_receipt) = other.stop(&other_running).unwrap();
    let receipt = Rc::new(receipt);
    let other_receipt = Rc::new(other_receipt);
    assert!(controller.seal_closed_generation(&other_receipt).is_err());
    let sealed = controller.seal_closed_generation(&receipt).unwrap();
    let equal_rc = Rc::new(ClosedMemberReceipt {
        shared: controller.shared.clone(),
        stopped: receipt.stopped.clone(),
        generation: receipt.generation,
    });
    assert!(sealed.read_history(&other_receipt).is_err());
    assert!(sealed.read_history(&equal_rc).is_err());
    assert!(controller.seal_closed_generation(&equal_rc).is_err());
    assert!(sealed.verify_live_reader(&other_reader).is_err());
    assert!(sealed.verify_pending_reader(&other_pending).is_err());
    let mut wrong_scope = running.intent.clone();
    wrong_scope.scope.connection_generation += 1;
    let wrong_pending = PendingMemberRead {
        shared: controller.shared.clone(),
        intent: wrong_scope,
        generation: controller.shared.read_generation.get(),
    };
    assert!(sealed.verify_pending_reader(&wrong_pending).is_err());
    assert!(sealed.read_history(&receipt).is_ok());
    assert_eq!(state.borrow().starts, 1);
    assert_eq!(state.borrow().stops, 1);
    assert_eq!(state.borrow().config_writes, 1);
}

#[test]
fn sealed_generation_failed_or_unwound_postflight_roots_original_before_retry() {
    for unwind in [false, true] {
        let state = State::default();
        let mut controller = RetainedMember::new(owner(&state));
        let running = controller.start().unwrap();
        let (_, receipt) = controller.stop(&running).unwrap();
        let receipt = Rc::new(receipt);
        let weak = Rc::downgrade(&controller.shared);
        let hook_state = Rc::downgrade(&state);
        state.borrow_mut().on_load = Some(Rc::new(move || {
            let shared = weak.upgrade().unwrap();
            if shared.sealed_generation.borrow().is_some() {
                let state = hook_state.upgrade().unwrap();
                state.borrow_mut().fail_absence = !unwind;
                state.borrow_mut().panic_absence = unwind;
            }
        }));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            controller.seal_closed_generation(&receipt)
        }));
        assert!(if unwind {
            result.is_err()
        } else {
            result.unwrap().is_err()
        });
        let rooted = controller
            .shared
            .sealed_generation
            .borrow()
            .as_ref()
            .unwrap()
            .upgrade()
            .unwrap();
        assert!(rooted.read_history(&receipt).is_err());
        assert_eq!(state.borrow().io_drops, 0);
        state.borrow_mut().on_load = None;
        state.borrow_mut().fail_absence = false;
        state.borrow_mut().panic_absence = false;
        let retry = controller.seal_closed_generation(&receipt).unwrap();
        assert!(Rc::ptr_eq(&rooted, &retry));
        assert!(retry.read_history(&receipt).is_ok());
        drop(controller);
        drop(receipt);
        drop(rooted);
        assert_eq!(state.borrow().io_drops, 0);
        drop(retry);
        assert_eq!(state.borrow().io_drops, 1);
        assert_eq!(state.borrow().stops, 1);
    }
}

#[test]
fn sealed_generation_unknown_current_absence_cannot_publish_history() {
    for live in [false, true] {
        let state = State::default();
        let mut controller = RetainedMember::new(owner(&state));
        let running = controller.start().unwrap();
        let (_, receipt) = controller.stop(&running).unwrap();
        let receipt = Rc::new(receipt);
        state.borrow_mut().running = live;
        state.borrow_mut().fail_absence = !live;
        assert!(controller.seal_closed_generation(&receipt).is_err());
        assert!(controller.shared.sealed_generation.borrow().is_none());
        state.borrow_mut().running = false;
        state.borrow_mut().fail_absence = false;
        controller.seal_closed_generation(&receipt).unwrap();
        assert_eq!(state.borrow().stops, 1);
    }
}

#[test]
fn closure_unwind_and_reentrant_owner_borrow_revoke_forward_without_losing_history() {
    for unwind in [false, true] {
        let state = State::default();
        let mut controller = RetainedMember::new(owner(&state));
        let running = controller.start().unwrap();
        let mut reader = controller.original_read().unwrap();
        let (_, receipt) = controller.stop(&running).unwrap();
        if unwind {
            state.borrow_mut().panic_absence = true;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                reader.read_closed_history(&receipt)
            }));
            assert!(result.is_err());
            state.borrow_mut().panic_absence = false;
        } else {
            let held = controller.shared.owner.borrow_mut();
            assert!(reader.read_closed_history(&receipt).is_err());
            drop(held);
        }
        reader.read_closed_history(&receipt).unwrap();
        assert!(reader.read().is_err());
        assert!(controller.original_read().is_err());
    }
}

#[test]
fn cleanup_reads_actual_still_running_owner_and_irrevocably_retires_forward() {
    let state = State::default();
    let mut controller = RetainedMember::new(owner(&state));
    let running = controller.start().unwrap();
    let mut reader = controller.original_read().unwrap();
    let mut sibling = controller.original_read().unwrap();
    assert_eq!(
        reader.read_for_cleanup().unwrap(),
        (running.intent.clone(), native())
    );
    assert!(sibling.read().is_err());
    assert!(controller.original_read().is_err());
    assert!(controller.start().is_err());
    assert_eq!(
        reader.read_for_cleanup().unwrap(),
        (running.intent.clone(), native())
    );
    assert_eq!(state.borrow().starts, 1);
    assert_eq!(state.borrow().stops, 0);
    let (_, receipt) = controller.stop(&running).unwrap();
    assert!(reader.read_for_cleanup().is_err());
    assert_eq!(
        reader.read_closed_history(&receipt).unwrap(),
        (running.intent, native())
    );
}

#[test]
fn cleanup_after_failed_forward_read_observes_same_original_without_rearming() {
    let state = State::default();
    let mut controller = RetainedMember::new(owner(&state));
    let running = controller.start().unwrap();
    let mut reader = controller.original_read().unwrap();
    state.borrow_mut().fail_original = true;
    assert!(reader.read().is_err());
    state.borrow_mut().fail_original = false;
    assert_eq!(
        reader.read_for_cleanup().unwrap(),
        (running.intent, native())
    );
    assert!(reader.read().is_err());
    assert!(controller.original_read().is_err());
    assert_eq!(state.borrow().starts, 1);
    assert_eq!(state.borrow().stops, 0);
}

#[test]
fn cleanup_denies_ignored_reentry_through_an_independent_same_owner_reader() {
    for forward in [false, true] {
        let state = State::default();
        let mut controller = RetainedMember::new(owner(&state));
        controller.start().unwrap();
        let mut outer = controller.original_read().unwrap();
        let nested = Rc::new(RefCell::new(controller.original_read().unwrap()));
        let entered = Rc::new(Cell::new(0));
        let nested_pin = nested.clone();
        let nested_entered = entered.clone();
        state.borrow_mut().on_original = Some(Rc::new(move || {
            nested_entered.set(nested_entered.get() + 1);
            let result = if forward {
                nested_pin.borrow_mut().read()
            } else {
                nested_pin.borrow_mut().read_for_cleanup()
            };
            assert!(result.is_err()); // Caught by the hostile native boundary.
        }));
        assert!(outer.read_for_cleanup().is_err());
        assert!(entered.get() > 0);
        state.borrow_mut().on_original = None;
        assert!(outer.read_for_cleanup().is_ok());
        assert!(outer.read().is_err());
        assert!(nested.borrow_mut().read().is_err());
        assert!(controller.original_read().is_err());
        assert_eq!(state.borrow().stops, 0);
    }
}

#[test]
fn cleanup_denies_reused_process_interface_or_lost_actual_original_owner() {
    for fault in 0..5 {
        let state = State::default();
        let mut controller = RetainedMember::new(owner(&state));
        controller.start().unwrap();
        let mut reader = controller.original_read().unwrap();
        let mut seen = native();
        match fault {
            0 => seen.process.creation_time += 1,
            1 => seen.interface.guid = [9; 16],
            2 => seen.interface.luid += 1,
            3 => seen.interface.index += 1,
            _ => state.borrow_mut().original_created = false,
        }
        state.borrow_mut().observed = Some(seen);
        assert!(reader.read_for_cleanup().is_err(), "fault {fault}");
        assert!(reader.read().is_err());
        assert!(controller.original_read().is_err());
        assert_eq!(state.borrow().stops, 0);
    }
}

#[test]
fn cleanup_read_denies_durable_drift_error_unwind_and_owner_reentry_without_rearming() {
    for fault in 0..4 {
        let state = State::default();
        let mut controller = RetainedMember::new(owner(&state));
        let running = controller.start().unwrap();
        let mut reader = controller.original_read().unwrap();
        match fault {
            0 => state.borrow_mut().record = None,
            1 => state.borrow_mut().fail_original = true,
            2 => state.borrow_mut().panic_original = true,
            _ => {}
        }
        let held = (fault == 3).then(|| controller.shared.owner.borrow_mut());
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| reader.read_for_cleanup()));
        if fault == 2 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err(), "fault {fault}");
        }
        drop(held);
        state.borrow_mut().record = Some(running);
        state.borrow_mut().fail_original = false;
        state.borrow_mut().panic_original = false;
        assert!(reader.read_for_cleanup().is_ok(), "factual retry {fault}");
        assert!(reader.read().is_err());
        assert!(controller.original_read().is_err());
        assert_eq!(state.borrow().stops, 0);
    }
}
