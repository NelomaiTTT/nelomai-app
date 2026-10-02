use super::*;
use crate::{
    member_carrier::{Intent, Provenance},
    member_carrier_native_ownership::{Binding, Role},
};
use nelomai_contracts::{dispatcher::EngineIdentity, RuntimeSlot};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::rc::Rc;
fn terminal() -> (Context, pair::Record) {
    let scope = nelomai_client_tunnel::redundancy::SessionScope {
        runtime: RuntimeSlot::Stable,
        runtime_generation: 2,
        session_id: "11111111-1111-4111-8111-111111111111".into(),
        connection_generation: 3,
    };
    let provenance = Provenance {
        boot_id: [8; 16],
        network_epoch: 7,
        runtime: EngineIdentity {
            slot: RuntimeSlot::Stable,
            runtime_version: "0.3.3".into(),
            container_version: "0.3.3".into(),
            runtime_contract_version: 1,
            manifest_sha256: "a".repeat(64),
        },
    };
    let context = Context {
        intent: Intent {
            scope: scope.clone(),
            addresses: vec!["10.7.0.2/32".parse().unwrap()],
        },
        provenance: provenance.clone(),
        bindings: std::array::from_fn(|i| {
            Binding {
            role:[Role::RoleCarrier,Role::MemberA,Role::MemberB][i],guid:[(i+1) as u8;16],
            name:["carrier-c","member-a","member-b"][i].into(),
            registry_path:[
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{01010101-0101-0101-0101-010101010101}",
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{02020202-0202-0202-0202-020202020202}",
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{03030303-0303-0303-0303-030303030303}"
            ][i].into()
        }
        }),
    };
    let record = pair::Record {
        version: 2,
        scope: scope.clone(),
        provenance,
        revision: 30,
        phase: pair::Phase::Stopped,
        addresses: context.intent.addresses.clone(),
        dns: vec![],
        carrier: None,
        members: [None, None],
        active: None,
        options: Some(nelomai_client_tunnel::DesktopTunnelOptions::default()),
        guard: crate::member_carrier_guard::Model::empty(scope).unwrap(),
        pending_guard: None,
        pending: None,
        network: None,
        stop_stage: 12,
        operation: None,
    };
    record.validate().unwrap();
    (context, record)
}
// Break: accepting Closing/FullEmpty intent or equal-looking foreign terminal
// metadata instead of an exact supported terminal comparison (never a grant).
#[test]
fn exact_stopped_record_is_comparison_only_and_every_partial_or_foreign_terminal_denies() {
    let (context, record) = terminal();
    assert!(compare_terminal(&context, &record).is_ok());
    for fault in 0..9 {
        let mut r = record.clone();
        match fault {
            0 => r.phase = pair::Phase::Closing,
            1 => r.pending = Some(pair::Effect::FullEmpty),
            2 => r.stop_stage = 11,
            3 => r.provenance.boot_id = [9; 16],
            4 => r.provenance.network_epoch += 1,
            5 => r.scope.connection_generation += 1,
            6 => r.addresses = vec!["10.7.0.3/32".parse().unwrap()],
            7 => r.options = None,
            _ => r.operation = Some(pair::Operation::Rebind),
        }
        assert!(compare_terminal(&context, &r).is_err(), "fault {fault}");
    }
}
struct Original(Rc<Cell<usize>>);
impl Drop for Original {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}
// Break: dropping an unknown original, taking it before a failed/unwound check,
// or invoking cleanup again after a failure/lost ACK.
#[test]
fn originals_drop_only_after_one_successful_final_check() {
    let drops = Rc::new(Cell::new(0));
    let slot = ResourceSlot::new(Original(drops.clone()));
    assert_eq!(drops.get(), 0);
    slot.release(|| Ok(())).unwrap();
    assert_eq!(drops.get(), 1);
    assert!(slot.release(|| panic!("duplicate must not run")).is_err());
    drop(slot);
    assert_eq!(drops.get(), 1);
}
#[test]
fn failed_unwound_or_missing_final_ack_retains_original_even_on_drop() {
    for unwind in [false, true] {
        let drops = Rc::new(Cell::new(0));
        let slot = ResourceSlot::new(Original(drops.clone()));
        let result = catch_unwind(AssertUnwindSafe(|| {
            slot.release(|| {
                if unwind {
                    panic!("final check unwind");
                }
                Err(conflict())
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert_eq!(drops.get(), 0);
        assert!(slot.release(|| panic!("unknown must not retry")).is_err());
        drop(slot);
        assert_eq!(drops.get(), 0);
    }
    let drops = Rc::new(Cell::new(0));
    drop(ResourceSlot::new(Original(drops.clone())));
    assert_eq!(drops.get(), 0);
}
#[test]
fn caught_reentry_cannot_allow_outer_resource_drop() {
    let drops = Rc::new(Cell::new(0));
    let slot = ResourceSlot::new(Original(drops.clone()));
    assert!(slot
        .release(|| {
            assert!(slot.release(|| Ok(())).is_err());
            Ok(())
        })
        .is_err());
    assert_eq!(drops.get(), 0);
    drop(slot);
    assert_eq!(drops.get(), 0);
}

#[test]
fn successful_preparation_is_one_shot_and_does_not_drop_any_original() {
    let drops = Rc::new(Cell::new(0));
    let slot = ResourceSlot::new(Original(drops.clone()));
    let state = PreparationState::new();
    state.begin().unwrap().finish().unwrap();
    assert!(!state.tainted.get());
    assert!(state.begin().is_err());
    assert!(state.tainted.get());
    drop(slot);
    assert_eq!(drops.get(), 0);
}
#[test]
fn preparation_failure_unwind_and_caught_reentry_permanently_deny() {
    for fault in 0..3 {
        let state = PreparationState::new();
        let checks = Cell::new(0);
        let drops = Rc::new(Cell::new(0));
        let slot = ResourceSlot::new(Original(drops.clone()));
        let r = catch_unwind(AssertUnwindSafe(|| -> io::Result<()> {
            let attempt = state.begin()?;
            checks.set(checks.get() + 1);
            match fault {
                0 => return Err(conflict()),
                1 => panic!("terminal preparation postflight unwind"),
                _ => assert!(state.begin().is_err()),
            }
            attempt.finish()
        }));
        assert!(r.is_err() || r.unwrap().is_err());
        assert_eq!(checks.get(), 1);
        assert!(state.tainted.get());
        assert!(state.begin().is_err());
        drop(slot);
        assert_eq!(drops.get(), 0);
    }
}

#[test]
fn invalid_original_context_and_nonempty_guard_cannot_match_terminal_data() {
    let (context, record) = terminal();
    for fault in 0..5 {
        let mut c = context.clone();
        match fault {
            0 => c.bindings[0].guid = [0; 16],
            1 => c.bindings[1].registry_path = c.bindings[0].registry_path.clone(),
            2 => c.bindings[1].name = c.bindings[0].name.clone(),
            3 => c.bindings[2].role = Role::RoleCarrier,
            _ => c.intent.scope.runtime_generation += 1,
        }
        assert!(compare_terminal(&c, &record).is_err());
    }
    let mut r = record;
    r.guard.installed = true;
    assert!(compare_terminal(&context, &r).is_err());
}

#[test]
fn joined_reader_success_without_actual_callback_ack_is_not_permission() {
    let unknown = JoinedAck::new();
    assert!(unknown.verify().is_err());
    let completed = JoinedAck::new();
    completed.acknowledge();
    completed.verify().unwrap();
    // Reader/callback Err or unwind remains Err even if the callback returned;
    // production checks its Result BEFORE verifying this private marker.
    let drops = Rc::new(Cell::new(0));
    let slot = ResourceSlot::new(Original(drops.clone()));
    assert!(slot.release(|| unknown.verify()).is_err());
    assert_eq!(drops.get(), 0);
    drop(slot);
    assert_eq!(drops.get(), 0);
}

// Break: treating the inner native ACK as completion before the real outer
// supervisor's postflight, or losing the retained ACK when that postflight errs.
#[test]
fn outer_terminal_postflight_error_keeps_native_ack_and_originals_but_denies_drop() {
    let state = TerminalCallState::new();
    let drops = Rc::new(Cell::new(0));
    let resources = ResourceSlot::new(Original(drops.clone()));
    let mut retained_ack = None;
    assert!(state
        .run(|| {
            retained_ack = Some(7);
            assert!(state.verify().is_err());
            Err(conflict())
        })
        .is_err());
    assert_eq!(retained_ack, Some(7));
    assert!(state.verify().is_err());
    assert!(resources.release(|| state.verify()).is_err());
    assert_eq!(drops.get(), 0);
    assert!(state
        .run(|| panic!("must not retry native unload"))
        .is_err());
    drop(resources);
    assert_eq!(drops.get(), 0);
}

#[test]
fn whole_terminal_call_success_not_inner_ack_opens_once_only_resource_release() {
    let state = TerminalCallState::new();
    let drops = Rc::new(Cell::new(0));
    let resources = ResourceSlot::new(Original(drops.clone()));
    let mut retained_ack = None;
    state
        .run(|| {
            retained_ack = Some(7);
            assert!(state.verify().is_err());
            assert_eq!(drops.get(), 0);
            Ok(())
        })
        .unwrap();
    assert_eq!(retained_ack, Some(7));
    resources.release(|| state.verify()).unwrap();
    assert_eq!(drops.get(), 1);
    assert!(resources.release(|| Ok(())).is_err());
    assert!(state.run(|| panic!("must not retry")).is_err());
    assert!(state.verify().is_err());
}

#[test]
fn outer_terminal_unwind_or_caught_reentry_never_finishes_the_call() {
    for unwind in [true, false] {
        let state = TerminalCallState::new();
        let drops = Rc::new(Cell::new(0));
        let resources = ResourceSlot::new(Original(drops.clone()));
        let mut retained_ack = None;
        let result = catch_unwind(AssertUnwindSafe(|| {
            state.run(|| {
                retained_ack = Some(7);
                if unwind {
                    panic!("outer terminal postflight");
                }
                assert!(state.run(|| Ok(())).is_err());
                Ok(())
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert_eq!(retained_ack, Some(7));
        assert!(state.verify().is_err());
        assert!(resources.release(|| state.verify()).is_err());
        assert_eq!(drops.get(), 0);
        drop(resources);
        assert_eq!(drops.get(), 0);
    }
}
