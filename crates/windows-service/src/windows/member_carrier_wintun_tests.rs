// Standalone host harness: main owns mod.rs/Cargo integration.
// Native metadata checks include the actual service root and its main-owned
// Wintun declaration exactly once, never substitute receipt/owner types.
#[cfg(windows)]
include!("../lib.rs");
#[cfg(not(windows))]
#[path = "member_carrier_wintun.rs"]
mod subject;
#[cfg(all(test, not(windows)))]
mod tests {
    use super::subject::*;
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
            self.call("verify")?;
            self.0.borrow_mut().calls.push(format!("{stage:?}"));
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
            self.call("create")?;
            let mut s = self.0.borrow_mut();
            s.present = true;
            s.row = Some(row());
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
        fn attest(&mut self, _: &Binding, _: &Identity) -> Result<()> {
            self.call("provider")
        }
        fn start(&mut self, adapter: &Handle, capacity: u32) -> Result<Handle> {
            assert_eq!(adapter.0, 1);
            assert_eq!(capacity, 0x20000);
            self.call("start")?;
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
            assert_eq!(session.0, 2);
            let mut s = self.0.borrow_mut();
            s.calls.push("end".into());
            s.ended += 1;
            s.clock += s.end_duration;
        }
        fn close(&mut self, adapter: Handle) {
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
            self.close_bounded(&AtomicBool::new(false), 1000)
        }
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
        assert!(c.close_bounded(&AtomicBool::new(true), 100).is_err());
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
            (Stage::Observe, 0, 0),
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
    fn exceeded_native_end_or_close_budget_preserves_remaining_obligations_without_reusing_handles()
    {
        for after_end in [true, false] {
            let (n, mut c) = setup();
            c.create(TestPrerequisite).unwrap();
            c.start().unwrap();
            if after_end {
                n.0.borrow_mut().end_duration = 150;
            } else {
                n.0.borrow_mut().close_duration = 150;
            }
            assert_eq!(
                c.close_bounded(&AtomicBool::new(false), 100),
                Err(Error::Deadline)
            );
            assert_eq!(n.0.borrow().ended, 1);
            assert_eq!(n.0.borrow().closed, u32::from(!after_end));
            assert!(!n.0.borrow().calls.iter().any(|c| c == "unpin_module"));
            c.close().unwrap();
            assert_eq!(n.0.borrow().ended, 1);
            assert_eq!(n.0.borrow().closed, 1);
        }
    }
    #[test]
    fn unused_module_cleanup_is_bounded_and_never_creates_or_closes_a_nic() {
        let (n, mut c) = setup();
        assert_eq!(
            c.close_bounded(&AtomicBool::new(false), 0),
            Err(Error::Invalid)
        );
        assert_eq!(
            c.close_bounded(&AtomicBool::new(false), 1001),
            Err(Error::Invalid)
        );
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
