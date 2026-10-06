// Host lifecycle harness integrated with the actual service crate modules.
// Native metadata checks include the actual service root and its main-owned
// Wintun declaration exactly once, never substitute receipt/owner types.
#[cfg(windows)]
include!("../lib.rs");
#[cfg(not(windows))]
#[path = "member_carrier_wintun.rs"]
mod subject;
#[cfg(all(test, not(windows)))]
mod tests {
    use super::subject;
    use super::subject::*;

    // Break: discarding the actual reference ACK on postflight Err/unwind,
    // repeating an effect after a lost return, or accepting a suppressed reentry.
    #[test]
    fn closed_reference_release_retains_returned_ack_before_fault_and_is_once() {
        for unwind in [false, true] {
            let state = ClosedReferenceRelease::new();
            let effects = std::cell::Cell::new(0);
            let retained = std::cell::Cell::new(false);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                state.run(
                    || Ok(()),
                    || {
                        effects.set(effects.get() + 1);
                        Ok(())
                    },
                    || {
                        assert!(state.acknowledged());
                        retained.set(true);
                        if unwind {
                            panic!("reference ACK postflight");
                        }
                        Err(Error::Conflict)
                    },
                )
            }));
            assert!(result.is_err() || result.unwrap().is_err());
            assert_eq!(effects.get(), 1);
            assert!(retained.get());
            assert!(state.acknowledged());
            assert!(state
                .run(
                    || panic!("duplicate check"),
                    || panic!("duplicate effect"),
                    || Ok(())
                )
                .is_err());
            assert_eq!(effects.get(), 1);
        }
    }

    #[test]
    fn closed_reference_failed_or_unwound_effect_never_becomes_an_ack() {
        for unwind in [false, true] {
            let state = ClosedReferenceRelease::new();
            let effects = std::cell::Cell::new(0);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                state.run(
                    || Ok(()),
                    || {
                        effects.set(effects.get() + 1);
                        if unwind {
                            panic!("native reference return lost");
                        }
                        Err(Error::Native)
                    },
                    || panic!("must not mint ACK"),
                )
            }));
            assert!(result.is_err() || result.unwrap().is_err());
            assert!(!state.acknowledged());
            assert!(state.was_attempted());
            assert!(state
                .run(|| Ok(()), || panic!("must not repeat"), || Ok(()))
                .is_err());
            assert_eq!(effects.get(), 1);
        }
    }

    #[test]
    fn closed_reference_reentry_caught_by_callback_still_denies_effect() {
        let state = ClosedReferenceRelease::new();
        assert!(state
            .run(
                || {
                    assert!(state
                        .run(|| Ok(()), || panic!("recursive effect"), || Ok(()))
                        .is_err());
                    Ok(())
                },
                || panic!("tainted effect"),
                || Ok(())
            )
            .is_err());
        assert!(!state.acknowledged());
    }

    use std::{cell::RefCell, collections::VecDeque, rc::Rc, sync::atomic::AtomicBool};
    #[derive(Clone, Debug)]
    struct FullRow {
        identity: Identity,
        counters: [u64; 20],
        status: [u32; 10],
        raw_metadata: [u8; 64],
    }
    struct Handle(u32);
    struct TestPrerequisite;
    #[derive(Default)]
    struct State {
        calls: Vec<String>,
        fail: Option<&'static str>,
        version: Option<u32>,
        present: bool,
        foreign: bool,
        row: Option<FullRow>,
        packets: VecDeque<(u32, u32)>,
        clock: u64,
        released: Vec<u32>,
        closed: u32,
        ended: u32,
        reappear: bool,
        drift: bool,
        eof: bool,
        fail_stage: Option<Stage>,
        end_duration: u64,
        close_duration: u64,
        fail_after_receive: bool,
        fail_after_start: bool,
        index_identity: Option<Identity>,
        initial_description: Option<String>,
        observed_stages: Vec<Stage>,
        call_resources_held: bool,
        panic_end: bool,
        panic_start: bool,
        fail_after_end: bool,
        end_pin: Option<SessionEndRead>,
        cancel_at_stage: Option<(Stage, Rc<AtomicBool>)>,
        cancel_after_end: Option<Rc<AtomicBool>>,
    }
    #[derive(Clone)]
    struct Native(Rc<RefCell<State>>);
    fn binding() -> Binding {
        Binding {
            guid: [1; 16],
            name: "carrier-only".into(),
            tunnel_type: "Nelomai carrier".into(),
        }
    }
    fn row() -> FullRow {
        FullRow {
            identity: Identity {
                guid: [1; 16],
                luid: 77,
                index: 7,
                name: "carrier-only".into(),
                description: "Nelomai carrier Tunnel".into(),
                if_type: 53,
                tunnel_type: 0,
            },
            counters: [4; 20],
            status: [5; 10],
            raw_metadata: [6; 64],
        }
    }
    impl Native {
        fn call(&self, call: &'static str) -> Result<()> {
            let mut s = self.0.borrow_mut();
            s.calls.push(call.into());
            if s.fail == Some(call) {
                Err(Error::Native)
            } else {
                Ok(())
            }
        }
    }
    impl Kernel for Native {
        type Adapter = Handle;
        type Session = Handle;
        type Packet = Handle;
        type Row = FullRow;
        type Key = ();
        type MutationLock = ();
        type Prerequisite<'p> = TestPrerequisite;
        fn verify(&mut self, _: &Binding, stage: Stage) -> Result<()> {
            // Native installation resources acquired at an effect seam must
            // remain held through the call, not through the session lifetime.
            if matches!(
                stage,
                Stage::BeforeCreate | Stage::BeforeSession | Stage::BeforeEnd | Stage::BeforeClose
            ) {
                self.0.borrow_mut().call_resources_held = true;
            }
            self.call("verify")?;
            self.0.borrow_mut().calls.push(format!("{stage:?}"));
            if let Some((at, cancel)) = &self.0.borrow().cancel_at_stage {
                if *at == stage {
                    cancel.store(true, std::sync::atomic::Ordering::Release);
                }
            }
            if self.0.borrow().fail_stage == Some(stage) {
                return Err(Error::Conflict);
            }
            Ok(())
        }
        fn driver_version(&mut self) -> Result<Option<u32>> {
            self.call("version")?;
            Ok(self.0.borrow().version)
        }
        fn absent(&mut self, _: &Binding) -> Result<()> {
            self.call("absence")?;
            if self.0.borrow().present || self.0.borrow().foreign {
                Err(Error::Conflict)
            } else {
                Ok(())
            }
        }
        fn create<'p>(&mut self, _: &Binding, _: TestPrerequisite) -> Result<Handle>
        where
            Self::Key: 'p,
            Self::MutationLock: 'p,
        {
            assert!(self.0.borrow().call_resources_held);
            self.call("create")?;
            let mut s = self.0.borrow_mut();
            s.present = true;
            s.row = Some(row());
            if let Some(description) = s.initial_description.clone() {
                s.row.as_mut().unwrap().identity.description = description;
            }
            s.version = Some(14);
            Ok(Handle(1))
        }
        fn luid(&mut self, handle: &Handle) -> Result<u64> {
            assert_eq!(handle.0, 1);
            self.call("luid")?;
            Ok(if self.0.borrow().drift { 88 } else { 77 })
        }
        fn row_luid(&mut self, _: u64) -> Result<FullRow> {
            self.call("row_luid")?;
            Ok(self.0.borrow().row.clone().unwrap())
        }
        fn row_index(&mut self, _: u32) -> Result<FullRow> {
            self.call("row_index")?;
            let state = self.0.borrow();
            let mut row = state.row.clone().unwrap();
            if let Some(identity) = &state.index_identity {
                row.identity = identity.clone();
            }
            Ok(row)
        }
        fn identity(&self, row: &FullRow) -> Result<Identity> {
            Ok(row.identity.clone())
        }
        fn attest(&mut self, _: &Binding, _: &Identity, stage: Stage) -> Result<()> {
            self.0.borrow_mut().observed_stages.push(stage);
            self.call("provider")
        }
        fn start(&mut self, adapter: &Handle, capacity: u32) -> Result<Handle> {
            assert!(self.0.borrow().call_resources_held);
            assert_eq!(adapter.0, 1);
            assert_eq!(capacity, 0x20000);
            self.call("start")?;
            assert!(!self.0.borrow().panic_start, "unknown start return");
            if self.0.borrow().fail_after_start {
                self.0.borrow_mut().fail = Some("row_luid");
            }
            Ok(Handle(2))
        }
        fn receive(&mut self, session: &Handle) -> Result<Receive<Handle>> {
            assert_eq!(session.0, 2);
            self.call("receive")?;
            let mut s = self.0.borrow_mut();
            s.clock += 1;
            if s.fail_after_receive {
                s.fail = Some("row_luid");
            }
            Ok(if s.eof {
                Receive::Eof
            } else if let Some((id, size)) = s.packets.pop_front() {
                Receive::Packet(Handle(id), size)
            } else {
                Receive::Empty
            })
        }
        fn release(&mut self, session: &Handle, packet: Handle) {
            assert_eq!(session.0, 2);
            let mut s = self.0.borrow_mut();
            s.calls.push("release".into());
            s.released.push(packet.0);
        }
        fn wait(&mut self, _: &Handle, ms: u32) -> Result<()> {
            assert!(ms <= 50);
            self.call("wait")?;
            self.0.borrow_mut().clock += u64::from(ms);
            Ok(())
        }
        fn now_ms(&self) -> u64 {
            self.0.borrow().clock
        }
        fn end(&mut self, session: Handle) {
            assert!(self.0.borrow().call_resources_held);
            assert_eq!(session.0, 2);
            let mut s = self.0.borrow_mut();
            s.calls.push("end".into());
            s.ended += 1;
            s.clock += s.end_duration;
            if let Some(pin) = &s.end_pin {
                assert!(matches!(pin.acknowledged(), Err(Error::Pending)));
            }
            if let Some(cancel) = &s.cancel_after_end {
                cancel.store(true, std::sync::atomic::Ordering::Release);
            }
            if s.fail_after_end {
                s.fail = Some("row_luid");
            }
            assert!(!s.panic_end, "unknown end return");
        }
        fn close(&mut self, adapter: Handle) {
            assert!(self.0.borrow().call_resources_held);
            assert_eq!(adapter.0, 1);
            let mut s = self.0.borrow_mut();
            s.calls.push("close".into());
            s.closed += 1;
            s.clock += s.close_duration;
            s.present = s.reappear;
        }
        fn release_module(&mut self) -> Result<()> {
            self.call("unpin_module")
        }
        fn release_call_resources(&mut self) {
            self.0.borrow_mut().call_resources_held = false;
        }
    }
    fn setup() -> (Native, Carrier<Native>) {
        let n = Native(Rc::new(RefCell::new(State::default())));
        let c = Carrier::new(n.clone(), binding()).unwrap();
        (n, c)
    }
    trait Cleanup {
        fn close(&mut self) -> Result<()>;
    }
    impl Cleanup for Carrier<Native> {
        fn close(&mut self) -> Result<()> {
            self.close_original(&AtomicBool::new(false))
        }
    }

    #[test]
    fn acknowledged_end_retry_requires_fresh_authority_and_original_observation() {
        // Break: an old VOID ACK bypasses a changed pending intent or native identity.
        for authority_denied in [false, true] {
            let (n, mut c) = setup();
            c.create(TestPrerequisite).unwrap();
            c.start().unwrap();
            let pin = c.session_end_read();
            c.end_session(&AtomicBool::new(false)).unwrap();
            let ack = pin.acknowledged().unwrap();
            if authority_denied {
                n.0.borrow_mut().fail_stage = Some(Stage::BeforeEnd);
            } else {
                n.0.borrow_mut().drift = true;
            }
            assert_eq!(c.end_session(&AtomicBool::new(false)), Err(Error::Conflict));
            pin.verify_acknowledged(&ack).unwrap(); // retained fact, not fresh permission
            assert_eq!(n.0.borrow().ended, 1);
            assert_eq!(n.0.borrow().closed, 0);
            assert!(!n.0.borrow().call_resources_held);
        }
    }

    #[test]
    fn original_session_state_pin_distinguishes_live_unknown_and_consumed_outcomes() {
        let (n, mut c) = setup();
        let pin = c.session_end_read();
        let alias = pin.read_pin();
        pin.verify_never_started().unwrap();
        alias.verify_no_live_session().unwrap();
        assert_eq!(pin.verify_endable(), Err(Error::Pending));
        c.create(TestPrerequisite).unwrap();
        c.start().unwrap();
        assert_eq!(pin.verify_never_started(), Err(Error::Pending));
        assert_eq!(alias.verify_no_live_session(), Err(Error::Pending));
        pin.verify_endable().unwrap();
        c.end_session(&AtomicBool::new(false)).unwrap();
        alias.verify_no_live_session().unwrap();
        pin.verify_endable().unwrap();
        assert_eq!(pin.verify_never_started(), Err(Error::Pending));
        let ack = pin.acknowledged().unwrap();
        alias.verify_acknowledged(&ack).unwrap();
        c.close().unwrap();
        pin.verify_no_live_session().unwrap();
        assert_eq!(n.0.borrow().ended, 1);
        assert_eq!(n.0.borrow().closed, 1);
    }

    #[test]
    fn registered_original_session_tracks_its_actual_carrier_and_rejects_replacement() {
        let (_, mut c) = setup();
        let (_, mut foreign) = setup();
        let mut read = OriginalSessionRead::new();
        assert_eq!(read.no_live_session(), Err(Error::Pending));
        read.retain(c.session_end_read());
        read.no_live_session().unwrap();
        assert_eq!(read.endable(), Err(Error::Pending));
        c.create(TestPrerequisite).unwrap();
        c.start().unwrap();
        read.endable().unwrap();
        assert_eq!(read.no_live_session(), Err(Error::Pending));
        foreign.create(TestPrerequisite).unwrap();
        foreign.start().unwrap();
        foreign.end_session(&AtomicBool::new(false)).unwrap();
        // A foreign equal identity with a real end ACK cannot replace ours.
        read.retain(foreign.session_end_read());
        assert_eq!(read.no_live_session(), Err(Error::Pending));
        assert_eq!(read.endable(), Err(Error::Pending));
        c.end_session(&AtomicBool::new(false)).unwrap();
        assert_eq!(read.no_live_session(), Err(Error::Pending)); // sticky invalid
    }
    #[test]
    fn upgraded_gate_retains_same_live_bootstrap_session_without_restarting_or_adopting() {
        let (n, mut carrier) = setup();
        carrier.create(TestPrerequisite).unwrap();
        carrier.start().unwrap();
        let original = carrier.session_end_read();
        let mut gate = OriginalSessionRead::new();
        gate.retain_handoff(original.read_pin());
        gate.live().unwrap();
        assert_eq!(gate.no_live_session(), Err(Error::Pending));
        carrier.end_session(&AtomicBool::new(false)).unwrap();
        gate.endable().unwrap();
        gate.no_live_session().unwrap();
        assert_eq!(gate.live(), Err(Error::Pending));
        let mut ended = OriginalSessionRead::new();
        ended.retain_handoff(original.read_pin());
        ended.endable().unwrap();
        assert_eq!(ended.live(), Err(Error::Pending));
        ended.retain_handoff(original); // even SAME replacement remains denied
        assert_eq!(ended.endable(), Err(Error::Pending));
        let (_, never) = setup();
        let mut unknown = OriginalSessionRead::new();
        unknown.retain_handoff(never.session_end_read());
        assert_eq!(unknown.endable(), Err(Error::Pending));
        assert_eq!(n.0.borrow().ended, 1);
    }

    #[test]
    fn registered_original_session_requires_initial_state_and_stays_bound_after_end() {
        for late in [false, true] {
            let (_, mut c) = setup();
            let mut read = OriginalSessionRead::new();
            if !late {
                read.retain(c.session_end_read());
            }
            c.create(TestPrerequisite).unwrap();
            c.start().unwrap();
            c.end_session(&AtomicBool::new(false)).unwrap();
            if late {
                read.retain(c.session_end_read());
                assert_eq!(read.no_live_session(), Err(Error::Pending));
            } else {
                read.no_live_session().unwrap();
                read.endable().unwrap();
                c.close().unwrap();
                read.no_live_session().unwrap();
            }
        }
    }

    #[test]
    fn original_session_state_pin_never_promotes_unknown_start_or_end_to_absence() {
        for unknown_start in [true, false] {
            let (n, mut c) = setup();
            let pin = c.session_end_read();
            c.create(TestPrerequisite).unwrap();
            if unknown_start {
                n.0.borrow_mut().panic_start = true;
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.start())).is_err()
                );
            } else {
                c.start().unwrap();
                n.0.borrow_mut().panic_end = true;
                assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                    || c.end_session(&AtomicBool::new(false))
                ))
                .is_err());
            }
            assert_eq!(pin.verify_never_started(), Err(Error::Pending));
            assert_eq!(pin.verify_no_live_session(), Err(Error::Pending));
            assert_eq!(pin.verify_endable(), Err(Error::Pending));
            assert!(matches!(pin.acknowledged(), Err(Error::Pending)));
            assert_eq!(n.0.borrow().closed, 0);
        }
    }

    #[test]
    fn foreign_equal_session_without_native_start_cannot_mask_original_live_session() {
        let (_, mut original) = setup();
        let (_, foreign) = setup();
        let pin = original.session_end_read();
        let foreign_pin = foreign.session_end_read();
        original.create(TestPrerequisite).unwrap();
        original.start().unwrap();
        foreign_pin.verify_never_started().unwrap();
        foreign_pin.verify_no_live_session().unwrap();
        assert_eq!(pin.verify_no_live_session(), Err(Error::Pending));
        pin.verify_endable().unwrap();
    }

    #[test]
    fn separate_end_retains_original_adapter_and_module_then_close_never_reends() {
        // Break: authorizing CloseAdapter from the durable EndSession operation.
        let (n, mut c) = setup();
        let pin = c.session_end_read();
        let alias = pin.read_pin();
        c.create(TestPrerequisite).unwrap();
        c.start().unwrap();
        n.0.borrow_mut().end_pin = Some(alias.read_pin());
        n.0.borrow_mut().calls.clear();
        n.0.borrow_mut().observed_stages.clear();
        c.end_session(&AtomicBool::new(false)).unwrap();
        let ack = pin.acknowledged().unwrap();
        alias.verify_acknowledged(&ack).unwrap();
        assert_eq!(c.phase(), Phase::Closing);
        assert_eq!(n.0.borrow().ended, 1);
        assert_eq!(n.0.borrow().closed, 0);
        assert!(n.0.borrow().present);
        assert!(!n
            .0
            .borrow()
            .calls
            .iter()
            .any(|s| s == "unpin_module" || s == "BeforeClose"));
        assert_eq!(n.0.borrow().observed_stages, [Stage::CleanupObserve; 2]);
        assert_eq!(c.captured().unwrap().identity, row().identity);
        assert!(!n.0.borrow().call_resources_held);
        let observations = n.0.borrow().observed_stages.len();
        c.end_session(&AtomicBool::new(false)).unwrap();
        assert_eq!(n.0.borrow().observed_stages.len(), observations + 1);
        assert_eq!(n.0.borrow().ended, 1);
        assert_eq!(n.0.borrow().closed, 0);
        assert_eq!(c.start(), Err(Error::Pending));
        assert_eq!(
            c.drain(&AtomicBool::new(false), 100, 1),
            Err(Error::Pending)
        );
        c.close().unwrap();
        c.close().unwrap();
        pin.verify_acknowledged(&ack).unwrap();
        assert_eq!(n.0.borrow().ended, 1);
        assert_eq!(n.0.borrow().closed, 1);
        assert_eq!(
            n.0.borrow()
                .calls
                .iter()
                .filter(|s| *s == "unpin_module")
                .count(),
            1
        );
    }

    #[test]
    fn separate_slow_end_preserves_ack_and_original_adapter() {
        // Break: a local timer rejects a supervised native return or obscures its ACK.
        let (n, mut c) = setup();
        c.create(TestPrerequisite).unwrap();
        c.start().unwrap();
        let pin = c.session_end_read();
        n.0.borrow_mut().end_duration = 1500;
        c.end_session(&AtomicBool::new(false)).unwrap();
        let ack = pin.acknowledged().unwrap();
        pin.verify_acknowledged(&ack).unwrap();
        assert_eq!(n.0.borrow().ended, 1);
        assert_eq!(n.0.borrow().closed, 0);
        assert!(n.0.borrow().present);
        assert!(!n.0.borrow().call_resources_held);
        assert!(!n.0.borrow().calls.iter().any(|s| s == "unpin_module"));
        c.close().unwrap();
        assert_eq!(n.0.borrow().ended, 1);
        assert_eq!(n.0.borrow().closed, 1);
    }

    #[test]
    fn separate_end_fallible_postflight_or_cancel_cannot_erase_void_ack() {
        for postflight_error in [true, false] {
            let (n, mut c) = setup();
            c.create(TestPrerequisite).unwrap();
            c.start().unwrap();
            let pin = c.session_end_read();
            let cancel = Rc::new(AtomicBool::new(false));
            if postflight_error {
                n.0.borrow_mut().fail_after_end = true;
            } else {
                n.0.borrow_mut().cancel_after_end = Some(cancel.clone());
            }
            assert_eq!(
                c.end_session(&cancel),
                Err(if postflight_error {
                    Error::Native
                } else {
                    Error::Cancelled
                })
            );
            let ack = pin.acknowledged().unwrap();
            pin.verify_acknowledged(&ack).unwrap();
            assert_eq!(n.0.borrow().closed, 0);
            assert!(!n.0.borrow().call_resources_held);
            n.0.borrow_mut().fail = None;
            c.end_session(&AtomicBool::new(false)).unwrap();
            c.close().unwrap();
            assert_eq!(n.0.borrow().ended, 1);
            assert_eq!(n.0.borrow().closed, 1);
        }
    }

    #[test]
    fn separate_end_before_end_denial_and_pre_effect_cancellation_have_no_effects() {
        for mode in 0..4 {
            let (n, mut c) = setup();
            c.create(TestPrerequisite).unwrap();
            c.start().unwrap();
            let pin = c.session_end_read();
            let cancel = Rc::new(AtomicBool::new(mode == 2));
            let expected = match mode {
                0 => {
                    n.0.borrow_mut().fail_stage = Some(Stage::BeforeEnd);
                    Error::Conflict
                }
                1 => {
                    n.0.borrow_mut().fail_stage = Some(Stage::CleanupObserve);
                    Error::Conflict
                }
                _ => Error::Cancelled,
            };
            if mode == 3 {
                n.0.borrow_mut().cancel_at_stage = Some((Stage::BeforeEnd, cancel.clone()));
            }
            assert_eq!(c.end_session(&cancel), Err(expected));
            assert!(matches!(pin.acknowledged(), Err(Error::Pending)));
            assert_eq!(n.0.borrow().ended, 0);
            assert_eq!(n.0.borrow().closed, 0);
            assert!(!n.0.borrow().call_resources_held);
            assert!(!n.0.borrow().calls.iter().any(|s| s == "unpin_module"));
            n.0.borrow_mut().fail_stage = None;
            n.0.borrow_mut().cancel_at_stage = None;
            c.end_session(&AtomicBool::new(false)).unwrap();
            c.close().unwrap();
            assert_eq!(n.0.borrow().ended, 1);
        }
    }

    #[test]
    fn caught_kernel_end_unwind_stays_pending_and_refuses_end_and_close() {
        // Break: session.take() + Closing falsely becomes a successful end ACK.
        for separate in [false, true] {
            let (n, mut c) = setup();
            c.create(TestPrerequisite).unwrap();
            c.start().unwrap();
            let pin = c.session_end_read();
            n.0.borrow_mut().panic_end = true;
            n.0.borrow_mut().end_pin = Some(pin.read_pin());
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if separate {
                    c.end_session(&AtomicBool::new(false))
                } else {
                    c.close()
                }
            }));
            assert!(caught.is_err());
            assert!(!n.0.borrow().call_resources_held);
            assert!(matches!(pin.acknowledged(), Err(Error::Pending)));
            n.0.borrow_mut().panic_end = false;
            assert_eq!(c.end_session(&AtomicBool::new(false)), Err(Error::Pending));
            assert_eq!(c.close(), Err(Error::Pending));
            assert_eq!(n.0.borrow().ended, 1);
            assert_eq!(n.0.borrow().closed, 0);
            assert!(n.0.borrow().present);
            let calls = n.0.borrow().calls.clone();
            drop(c);
            assert!(matches!(pin.acknowledged(), Err(Error::Pending)));
            assert_eq!(n.0.borrow().calls, calls);
        }
    }

    #[test]
    fn foreign_end_ack_cannot_complete_unended_original_or_its_read_alias() {
        // Numeric identities are deliberately equal; only the private Rc agrees.
        let (n, mut c) = setup();
        let (_, mut foreign) = setup();
        for owner in [&mut c, &mut foreign] {
            owner.create(TestPrerequisite).unwrap();
            owner.start().unwrap();
        }
        let pin = c.session_end_read();
        let alias = pin.read_pin();
        let foreign_pin = foreign.session_end_read();
        foreign.end_session(&AtomicBool::new(false)).unwrap();
        let foreign_ack = foreign_pin.acknowledged().unwrap();
        assert_eq!(pin.verify_acknowledged(&foreign_ack), Err(Error::Conflict));
        assert_eq!(
            alias.verify_acknowledged(&foreign_ack),
            Err(Error::Conflict)
        );
        assert!(matches!(pin.acknowledged(), Err(Error::Pending)));
        assert!(matches!(alias.acknowledged(), Err(Error::Pending)));
        assert_eq!(n.0.borrow().ended, 0);
        c.end_session(&AtomicBool::new(false)).unwrap();
        let ack = alias.acknowledged().unwrap();
        assert_eq!(foreign_pin.verify_acknowledged(&ack), Err(Error::Conflict));
        pin.verify_acknowledged(&ack).unwrap();
    }

    #[test]
    fn never_started_partial_bootstrap_closes_without_fabricating_session_end_ack() {
        for created in [false, true] {
            let (n, mut c) = setup();
            let pin = c.session_end_read();
            if created {
                c.create(TestPrerequisite).unwrap();
            }
            assert_eq!(c.end_session(&AtomicBool::new(false)), Err(Error::Pending));
            assert!(matches!(pin.acknowledged(), Err(Error::Pending)));
            c.close().unwrap();
            assert!(matches!(pin.acknowledged(), Err(Error::Pending)));
            assert_eq!(n.0.borrow().ended, 0);
            assert_eq!(n.0.borrow().closed, u32::from(created));
        }
    }

    #[test]
    fn unknown_session_start_cannot_be_treated_as_never_started_cleanup() {
        let (n, mut c) = setup();
        c.create(TestPrerequisite).unwrap();
        n.0.borrow_mut().panic_start = true;
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.start()));
        assert!(caught.is_err());
        assert_eq!(c.close(), Err(Error::Pending));
        assert_eq!(n.0.borrow().closed, 0);
        assert_eq!(n.0.borrow().ended, 0);
        assert!(matches!(
            c.session_end_read().acknowledged(),
            Err(Error::Pending)
        ));
    }

    #[test]
    fn returned_start_failure_without_native_session_preserves_adapter_only_cleanup() {
        // Kernel::start returned Err before starting (native equivalent: NULL),
        // so close must retain its established never-started cleanup behavior.
        let (n, mut c) = setup();
        c.create(TestPrerequisite).unwrap();
        let pin = c.session_end_read();
        n.0.borrow_mut().fail = Some("start");
        assert_eq!(c.start(), Err(Error::Native));
        n.0.borrow_mut().fail = None;
        assert_eq!(c.start(), Err(Error::Pending));
        c.close().unwrap();
        assert_eq!(n.0.borrow().ended, 0);
        assert_eq!(n.0.borrow().closed, 1);
        assert!(matches!(pin.acknowledged(), Err(Error::Pending)));
    }

    #[test]
    fn owned_authority_holder_retains_local_resource_and_delegates_to_same_owner_after_move() {
        // Portable test of the production holder, NOT native authority proof.
        // Losing ownership or delegating to a replacement would break this test.
        struct Resource<'a> {
            pin: Rc<()>,
            calls: &'a std::cell::Cell<u32>,
        }
        let calls = std::cell::Cell::new(0);
        let pin = Rc::new(());
        let weak = Rc::downgrade(&pin);
        let holder = {
            let owner = Resource { pin, calls: &calls };
            subject::AuthorityHolder::Owned(owner)
        };
        let mut moved = holder;
        for expected in [1, 2] {
            let actual = moved.as_mut();
            assert!(Rc::ptr_eq(&actual.pin, &weak.upgrade().unwrap()));
            actual.calls.set(actual.calls.get() + 1);
            assert_eq!(calls.get(), expected);
        }
        assert_eq!(weak.strong_count(), 1);
        drop(moved);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn borrowed_authority_holder_returns_original_borrow_without_consuming_owner() {
        let mut owner = Box::new(41_u32);
        {
            let mut holder = subject::AuthorityHolder::Borrowed(&mut owner);
            **holder.as_mut() += 1;
        }
        assert_eq!(*owner, 42);
    }

    #[test]
    fn boundary_lifecycle_retains_created_handle_and_full_rows_before_session() {
        let (n, mut c) = setup();
        c.create(TestPrerequisite).unwrap();
        assert_eq!(c.phase(), Phase::Created);
        let full = c.captured().unwrap();
        assert_eq!(full.raw_metadata, [6; 64]);
        assert_eq!(full.counters, [4; 20]);
        assert_eq!(full.status, [5; 10]);
        c.start().unwrap();
        assert_eq!(c.phase(), Phase::Session);
        let s = n.0.borrow();
        let calls = &s.calls;
        assert!(
            calls.iter().position(|s| s == "absence").unwrap()
                < calls.iter().position(|s| s == "create").unwrap()
        );
        assert!(
            calls.iter().position(|s| s == "provider").unwrap()
                < calls.iter().position(|s| s == "start").unwrap()
        );
    }

    #[test]
    fn installation_resources_are_released_between_completed_carrier_operations() {
        // Break: retaining Device+Driver locks for the carrier lifetime stalls
        // independent member driver creation in the other process.
        let (n, mut c) = setup();
        c.create(TestPrerequisite).unwrap();
        assert!(!n.0.borrow().call_resources_held);
        c.start().unwrap();
        assert!(!n.0.borrow().call_resources_held);
        assert_eq!(c.phase(), Phase::Session);
        c.close().unwrap();
        assert!(!n.0.borrow().call_resources_held);
        assert_eq!(n.0.borrow().closed, 1);
    }

    #[test]
    fn failed_pre_effect_read_releases_installation_resources_without_closing_original() {
        let (n, mut c) = setup();
        c.create(TestPrerequisite).unwrap();
        n.0.borrow_mut().fail = Some("row_luid");
        assert!(c.start().is_err());
        assert!(!n.0.borrow().call_resources_held);
        assert_eq!(n.0.borrow().closed, 0);
        assert_eq!(n.0.borrow().ended, 0);
        assert_eq!(c.phase(), Phase::Created);
    }

    #[test]
    fn call_resource_bracket_releases_real_lock_on_error_or_unwind_but_keeps_original_pin() {
        // Exercise the production bracket with an actual host mutex/retained
        // resource. This does not pretend to execute a Windows native lease.
        struct Owner<'a> {
            lease: Option<std::sync::MutexGuard<'a, ()>>,
            original: Rc<()>,
        }
        impl subject::CallResources for Owner<'_> {
            fn release_call_resources(&mut self) {
                self.lease.take();
            }
        }
        for unwind in [false, true] {
            let mutex = std::sync::Mutex::new(());
            let original = Rc::new(());
            let weak = Rc::downgrade(&original);
            let mut owner = Owner {
                lease: Some(mutex.lock().unwrap()),
                original,
            };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                subject::with_call_resources(&mut owner, |held| -> Result<()> {
                    assert!(held.lease.is_some());
                    assert!(matches!(
                        mutex.try_lock(),
                        Err(std::sync::TryLockError::WouldBlock)
                    ));
                    if unwind {
                        panic!("uncertain native boundary");
                    }
                    Err(Error::Native)
                })
            }));
            if unwind {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap(), Err(Error::Native));
            }
            assert!(owner.lease.is_none());
            assert!(!matches!(
                mutex.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
            assert!(Rc::ptr_eq(&owner.original, &weak.upgrade().unwrap()));
            drop(owner);
            assert!(weak.upgrade().is_none());
        }
    }
    #[test]
    fn original_duplicate_description_is_captured_whole_and_cannot_drift() {
        let (n, mut c) = setup();
        n.0.borrow_mut().initial_description = Some("Nelomai carrier Tunnel #2".into());
        c.create(TestPrerequisite).unwrap();
        assert_eq!(
            c.captured().unwrap().identity.description,
            "Nelomai carrier Tunnel #2"
        );
        c.start().unwrap();
        n.0.borrow_mut().row.as_mut().unwrap().identity.description =
            "Nelomai carrier Tunnel #3".into();
        assert!(c.reattest().is_err());
    }
    #[test]
    fn independent_foreign_name_or_guid_never_creates_or_adopts() {
        let (n, mut c) = setup();
        n.0.borrow_mut().foreign = true;
        assert_eq!(c.create(TestPrerequisite), Err(Error::Conflict));
        assert!(!n.0.borrow().calls.iter().any(|s| s == "create"));
    }
    #[test]
    fn unsupported_running_driver_is_rejected_before_creation() {
        let (n, mut c) = setup();
        n.0.borrow_mut().version = Some(15);
        assert_eq!(c.create(TestPrerequisite), Err(Error::Unsupported));
        assert_eq!(n.0.borrow().closed, 0);
    }
    #[test]
    fn original_handle_capture_error_retains_effect_and_module_obligations() {
        let (n, mut c) = setup();
        n.0.borrow_mut().fail = Some("row_luid");
        assert!(c.create(TestPrerequisite).is_err());
        assert_eq!(c.phase(), Phase::CreatePending);
        assert!(n.0.borrow().present);
        assert!(!n.0.borrow().calls.iter().any(|s| s == "unpin_module"));
    }
    #[test]
    fn ambiguous_create_failure_is_not_retried_or_adopted() {
        let (n, mut c) = setup();
        n.0.borrow_mut().fail = Some("create");
        assert!(c.create(TestPrerequisite).is_err());
        n.0.borrow_mut().fail = None;
        assert!(c.create(TestPrerequisite).is_err());
        assert_eq!(
            n.0.borrow()
                .calls
                .iter()
                .filter(|s| s.as_str() == "create")
                .count(),
            1
        );
        assert!(c.close().is_err());
    }
    #[test]
    fn receive_drain_releases_every_packet_without_forwarding_and_obeys_packet_bound() {
        let (n, mut c) = setup();
        c.create(TestPrerequisite).unwrap();
        c.start().unwrap();
        n.0.borrow_mut()
            .packets
            .extend([(10, 64), (11, 100), (12, 65)]);
        let r = c.drain(&AtomicBool::new(false), 1000, 2).unwrap();
        assert_eq!(
            r,
            Drain {
                discarded: 2,
                stop: DrainStop::PacketLimit
            }
        );
        assert_eq!(n.0.borrow().released, vec![10, 11]);
        assert_eq!(n.0.borrow().packets.len(), 1);
    }
    #[test]
    fn malformed_packet_is_released_even_when_rejected() {
        let (n, mut c) = setup();
        c.create(TestPrerequisite).unwrap();
        c.start().unwrap();
        n.0.borrow_mut().packets.push_back((10, 0));
        assert_eq!(
            c.drain(&AtomicBool::new(false), 1000, 32),
            Err(Error::Unsupported)
        );
        assert_eq!(n.0.borrow().released, vec![10]);
    }
    #[test]
    fn cancellation_and_deadline_do_not_end_or_close_retained_capabilities() {
        let (n, mut c) = setup();
        c.create(TestPrerequisite).unwrap();
        c.start().unwrap();
        assert_eq!(
            c.drain(&AtomicBool::new(true), 1000, 32).unwrap().stop,
            DrainStop::Cancelled
        );
        assert_eq!(
            c.drain(&AtomicBool::new(false), 100, 32).unwrap().stop,
            DrainStop::Deadline
        );
        assert_eq!(n.0.borrow().ended, 0);
        assert_eq!(n.0.borrow().closed, 0);
    }
    #[test]
    fn native_eof_is_not_readiness_or_permission_to_adopt() {
        let (n, mut c) = setup();
        c.create(TestPrerequisite).unwrap();
        c.start().unwrap();
        n.0.borrow_mut().eof = true;
        assert_eq!(
            c.drain(&AtomicBool::new(false), 1000, 32).unwrap().stop,
            DrainStop::Eof
        );
        assert_eq!(c.start(), Err(Error::Pending));
    }
    #[test]
    fn teardown_consumes_session_then_original_adapter_and_unpins_only_after_absence() {
        let (n, mut c) = setup();
        c.create(TestPrerequisite).unwrap();
        c.start().unwrap();
        c.close().unwrap();
        c.close().unwrap();
        assert_eq!(c.phase(), Phase::Closed);
        let s = n.0.borrow();
        assert_eq!(s.ended, 1);
        assert_eq!(s.closed, 1);
        let calls = &s.calls;
        assert!(
            calls.iter().position(|s| s == "end").unwrap()
                < calls.iter().position(|s| s == "close").unwrap()
        );
        assert_eq!(calls.last().unwrap(), "unpin_module");
    }
    #[test]
    fn post_close_absence_failure_never_reuses_a_consumed_handle() {
        let (n, mut c) = setup();
        c.create(TestPrerequisite).unwrap();
        c.start().unwrap();
        n.0.borrow_mut().reappear = true;
        assert!(c.close().is_err());
        assert_eq!(c.phase(), Phase::ClosePending);
        assert!(c.close().is_err());
        assert_eq!(n.0.borrow().closed, 1);
        assert!(!n.0.borrow().calls.iter().any(|s| s == "unpin_module"));
    }
    #[test]
    fn changed_original_handle_identity_prevents_session_drain_and_destructive_close() {
        let (n, mut c) = setup();
        c.create(TestPrerequisite).unwrap();
        c.start().unwrap();
        n.0.borrow_mut().drift = true;
        assert!(c.reattest().is_err());
        assert!(c.close().is_err());
        assert_eq!(n.0.borrow().ended, 0);
        assert_eq!(n.0.borrow().closed, 0);
    }
    #[test]
    fn invalid_binding_or_unbounded_drain_arguments_never_reach_native_effects() {
        let n = Native(Rc::new(RefCell::new(State::default())));
        let mut b = binding();
        b.guid = [0; 16];
        assert!(Carrier::new(n.clone(), b).is_err());
        let (_, mut c) = setup();
        assert!(c.drain(&AtomicBool::new(false), 1001, 32).is_err());
        assert!(n.0.borrow().calls.is_empty());
    }

    unsafe extern "system" fn export_stub() -> isize {
        0
    }
    #[test]
    fn audited_function_table_requires_all_nine_exports_and_resolves_no_send_or_adoption_api() {
        let mut names = vec![];
        let result = unsafe {
            Functions::resolve(|name| {
                names.push(name.to_str().unwrap().to_owned());
                Some(export_stub)
            })
        };
        assert!(result.is_ok());
        assert_eq!(
            names,
            [
                "WintunCreateAdapter",
                "WintunCloseAdapter",
                "WintunGetAdapterLUID",
                "WintunGetRunningDriverVersion",
                "WintunStartSession",
                "WintunEndSession",
                "WintunGetReadWaitEvent",
                "WintunReceivePacket",
                "WintunReleaseReceivePacket"
            ]
        );
    }
    #[test]
    fn any_missing_audited_export_rejects_the_whole_capability() {
        for missing in [
            "WintunCreateAdapter",
            "WintunCloseAdapter",
            "WintunGetAdapterLUID",
            "WintunGetRunningDriverVersion",
            "WintunStartSession",
            "WintunEndSession",
            "WintunGetReadWaitEvent",
            "WintunReceivePacket",
            "WintunReleaseReceivePacket",
        ] {
            assert!(unsafe {
                Functions::resolve(|name| {
                    if name.to_bytes() == missing.as_bytes() {
                        None
                    } else {
                        Some(export_stub)
                    }
                })
            }
            .is_err());
        }
    }

    #[test]
    fn zero_version_status_requires_file_not_found_not_access_denied_or_false_success() {
        assert_eq!(driver_status(0, 2), Ok(None));
        assert_eq!(driver_status(14, 0), Ok(Some(14)));
        for error in [0, 5, 87, 1168] {
            assert_eq!(driver_status(0, error), Err(Error::Native));
        }
        for version in [1, 13, 15, u32::MAX] {
            assert_eq!(driver_status(version, 0), Err(Error::Unsupported));
        }
    }
    #[test]
    fn independently_authorized_close_does_not_require_revoked_forward_observation() {
        // A current Closing record authorizes only cleanup. Forward Observe
        // must keep failing: clearing that denial to get Stop working is unsafe.
        let (n, mut c) = setup();
        c.create(TestPrerequisite).unwrap();
        c.start().unwrap();
        n.0.borrow_mut().fail_stage = Some(Stage::Observe);
        assert_eq!(c.reattest().map(|_| ()), Err(Error::Conflict));
        n.0.borrow_mut().observed_stages.clear();
        c.close().unwrap();
        assert_eq!(c.phase(), Phase::Closed);
        assert_eq!(n.0.borrow().ended, 1);
        assert_eq!(n.0.borrow().closed, 1);
        assert_eq!(n.0.borrow().observed_stages, [Stage::CleanupObserve; 4]);
        assert_eq!(c.reattest().map(|_| ()), Err(Error::Retired));
    }

    #[test]
    fn cleanup_observation_denial_retains_original_session_and_adapter() {
        let (n, mut c) = setup();
        c.create(TestPrerequisite).unwrap();
        c.start().unwrap();
        n.0.borrow_mut().fail_stage = Some(Stage::CleanupObserve);
        assert_eq!(c.close(), Err(Error::Conflict));
        assert_eq!(n.0.borrow().ended, 0);
        assert_eq!(n.0.borrow().closed, 0);
        assert!(n.0.borrow().present);
        // Cleanup failure must not permit any subsequent forward progress.
        assert_eq!(
            c.drain(&AtomicBool::new(false), 100, 2),
            Err(Error::Pending)
        );
    }

    #[test]
    fn native_drain_fault_is_permanently_cleanup_only_even_after_boundary_recovers() {
        for fault in [
            "verify",
            "luid",
            "row_luid",
            "row_index",
            "provider",
            "receive",
            "wait",
        ] {
            let (n, mut c) = setup();
            c.create(TestPrerequisite).unwrap();
            c.start().unwrap();
            n.0.borrow_mut().fail = Some(fault);
            assert!(c.drain(&AtomicBool::new(false), 100, 2).is_err(), "{fault}");
            n.0.borrow_mut().fail = None;
            assert_eq!(
                c.drain(&AtomicBool::new(false), 100, 2),
                Err(Error::Pending),
                "{fault}"
            );
            c.close().unwrap();
            assert_eq!(n.0.borrow().ended, 1);
            assert_eq!(n.0.borrow().closed, 1);
        }
    }
    #[test]
    fn non_ascii_or_surrounding_whitespace_binding_cannot_bypass_exact_absence_comparison() {
        for name in ["carriér", " carrier", "carrier ", "\tcarrier"] {
            let n = Native(Rc::new(RefCell::new(State::default())));
            let mut b = binding();
            b.name = name.into();
            assert!(Carrier::new(n.clone(), b).is_err(), "{name}");
            assert!(n.0.borrow().calls.is_empty());
        }
    }
    #[test]
    fn failed_dll_unpin_keeps_close_pending_and_never_reuses_original_handles() {
        let (n, mut c) = setup();
        c.create(TestPrerequisite).unwrap();
        c.start().unwrap();
        n.0.borrow_mut().fail = Some("unpin_module");
        assert_eq!(c.close(), Err(Error::Native));
        assert_eq!(c.phase(), Phase::ClosePending);
        assert_eq!(n.0.borrow().ended, 1);
        assert_eq!(n.0.borrow().closed, 1);
        n.0.borrow_mut().fail = None;
        c.close().unwrap();
        assert_eq!(c.phase(), Phase::Closed);
        assert_eq!(n.0.borrow().ended, 1);
        assert_eq!(n.0.borrow().closed, 1);
    }
    #[test]
    fn cancelled_cleanup_preserves_original_capabilities_and_does_not_consume_handles() {
        let (n, mut c) = setup();
        c.create(TestPrerequisite).unwrap();
        c.start().unwrap();
        assert!(c.close_original(&AtomicBool::new(true)).is_err());
        assert_eq!(n.0.borrow().ended, 0);
        assert_eq!(n.0.borrow().closed, 0);
        c.close().unwrap();
    }
    #[test]
    fn full_current_observation_preserves_volatile_metadata_without_overwriting_original_capture() {
        let (n, mut c) = setup();
        c.create(TestPrerequisite).unwrap();
        let mut current = row();
        current.counters = [88; 20];
        current.status = [99; 10];
        current.raw_metadata = [77; 64];
        n.0.borrow_mut().row = Some(current);
        let observed = c.reattest().unwrap();
        assert_eq!(observed.counters, [88; 20]);
        assert_eq!(observed.status, [99; 10]);
        assert_eq!(observed.raw_metadata, [77; 64]);
        assert_eq!(c.captured().unwrap().counters, [4; 20]);
    }
    #[test]
    fn original_observation_failure_cannot_rearm_live_creator_after_native_recovers() {
        for fault in ["verify", "luid", "row_luid", "row_index", "provider"] {
            let (n, mut c) = setup();
            c.create(TestPrerequisite).unwrap();
            c.start().unwrap();
            n.0.borrow_mut().fail = Some(fault);
            assert!(c.reattest().is_err(), "{fault}");
            n.0.borrow_mut().fail = None;
            let calls = n.0.borrow().calls.clone();
            assert!(c.reattest().is_err(), "revocation {fault}");
            assert_eq!(
                n.0.borrow().calls,
                calls,
                "cached creator cannot be rearmed"
            );
            assert_eq!(
                c.drain(&AtomicBool::new(false), 100, 2),
                Err(Error::Pending)
            );
            // Cleanup still uses the SAME original handles and fresh capture,
            // never the revoked live observation or reopening an interface.
            c.close().unwrap();
            assert_eq!(n.0.borrow().closed, 1);
            assert_eq!(n.0.borrow().ended, 1);
        }
    }
    #[test]
    fn each_immutable_identity_drift_and_index_query_disagreement_blocks_destruction() {
        let mut changes = vec![];
        for field in 0..7 {
            let mut identity = row().identity;
            match field {
                0 => identity.guid[0] ^= 1,
                1 => identity.luid += 1,
                2 => identity.index += 1,
                3 => identity.name.push('x'),
                4 => identity.description.push('x'),
                5 => identity.if_type += 1,
                _ => identity.tunnel_type += 1,
            }
            changes.push(identity);
        }
        for identity in changes {
            for index_only in [false, true] {
                let (n, mut c) = setup();
                c.create(TestPrerequisite).unwrap();
                c.start().unwrap();
                if index_only {
                    n.0.borrow_mut().index_identity = Some(identity.clone());
                } else {
                    n.0.borrow_mut().row.as_mut().unwrap().identity = identity.clone();
                }
                assert!(c.reattest().is_err());
                assert!(c.close().is_err());
                assert_eq!(n.0.borrow().ended, 0);
                assert_eq!(n.0.borrow().closed, 0);
            }
        }
    }
    #[test]
    fn post_start_failure_retains_session_for_cleanup_and_prevents_duplicate_start() {
        let (n, mut c) = setup();
        c.create(TestPrerequisite).unwrap();
        n.0.borrow_mut().fail_after_start = true;
        assert!(c.start().is_err());
        assert_eq!(c.phase(), Phase::Session);
        n.0.borrow_mut().fail = None;
        assert_eq!(c.start(), Err(Error::Pending));
        assert_eq!(
            c.drain(&AtomicBool::new(false), 100, 2),
            Err(Error::Pending)
        );
        c.close().unwrap();
        assert_eq!(n.0.borrow().ended, 1);
    }
    #[test]
    fn packet_is_released_before_failed_post_receive_attestation() {
        let (n, mut c) = setup();
        c.create(TestPrerequisite).unwrap();
        c.start().unwrap();
        n.0.borrow_mut().packets.push_back((11, 64));
        n.0.borrow_mut().fail_after_receive = true;
        assert!(c.drain(&AtomicBool::new(false), 100, 2).is_err());
        assert_eq!(n.0.borrow().released, [11]);
        n.0.borrow_mut().fail = None;
        assert_eq!(
            c.drain(&AtomicBool::new(false), 100, 2),
            Err(Error::Pending)
        );
        c.close().unwrap();
    }
    #[test]
    fn every_teardown_authority_stage_retains_correct_remaining_capabilities() {
        for (stage, ended, closed) in [
            (Stage::CleanupObserve, 0, 0),
            (Stage::BeforeEnd, 0, 0),
            (Stage::BeforeClose, 1, 0),
            (Stage::AfterClose, 1, 1),
        ] {
            let (n, mut c) = setup();
            c.create(TestPrerequisite).unwrap();
            c.start().unwrap();
            n.0.borrow_mut().fail_stage = Some(stage);
            assert!(c.close().is_err(), "{stage:?}");
            assert_eq!(n.0.borrow().ended, ended);
            assert_eq!(n.0.borrow().closed, closed);
            assert!(!n.0.borrow().calls.iter().any(|c| c == "unpin_module"));
            n.0.borrow_mut().fail_stage = None;
            c.close().unwrap();
            assert_eq!(n.0.borrow().ended, 1);
            assert_eq!(n.0.borrow().closed, 1);
        }
    }
    #[test]
    fn slow_native_end_or_close_preserves_completion_without_reusing_handles() {
        for after_end in [true, false] {
            let (n, mut c) = setup();
            c.create(TestPrerequisite).unwrap();
            c.start().unwrap();
            if after_end {
                n.0.borrow_mut().end_duration = 1500;
            } else {
                n.0.borrow_mut().close_duration = 1500;
            }
            c.close_original(&AtomicBool::new(false)).unwrap();
            assert_eq!(c.phase(), Phase::Closed);
            assert_eq!(n.0.borrow().ended, 1);
            assert_eq!(n.0.borrow().closed, 1);
            c.close().unwrap();
            assert_eq!(n.0.borrow().ended, 1);
            assert_eq!(n.0.borrow().closed, 1);
        }
    }
    #[test]
    fn unused_module_cleanup_never_creates_or_closes_a_nic() {
        let (n, mut c) = setup();
        n.0.borrow_mut().fail = Some("unpin_module");
        assert!(c.close().is_err());
        assert_eq!(c.phase(), Phase::ClosePending);
        n.0.borrow_mut().fail = None;
        c.close().unwrap();
        assert_eq!(n.0.borrow().ended, 0);
        assert_eq!(n.0.borrow().closed, 0);
        assert!(!n.0.borrow().calls.iter().any(|c| c == "create"));
    }
    #[test]
    fn hardware_filter_or_endpoint_native_role_cannot_be_attested_as_carrier() {
        for flags in 0..=u8::MAX {
            assert_eq!(virtual_role(flags).is_ok(), flags & 0x83 == 0, "{flags:#x}");
        }
    }
    #[test]
    fn dropping_unfinished_carrier_never_infers_authority_or_performs_native_cleanup() {
        let (n, mut c) = setup();
        c.create(TestPrerequisite).unwrap();
        c.start().unwrap();
        let before = n.0.borrow().calls.clone();
        drop(c);
        assert_eq!(n.0.borrow().calls, before);
        assert_eq!(n.0.borrow().ended, 0);
        assert_eq!(n.0.borrow().closed, 0);
    }
}
