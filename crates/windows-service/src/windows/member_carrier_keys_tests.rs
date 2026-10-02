// Actual production key module tests, run by Cargo on both host and Windows.
// Only registry effects and the independent native-authority boundary are fake.
use super::*;

#[test]
fn terminal_hkey_native_ack_is_retained_before_postflight_and_never_repeated() {
    // Break: storing close success only after postflight loses a real native
    // ACK, allowing Drop/retry to close an already-released HKEY again.
    let state = KeyHandleClose::new();
    let calls = std::cell::Cell::new(0);
    let retained = RefCell::new(None);
    assert!(state
        .run(
            || Ok(()),
            || {
                calls.set(calls.get() + 1);
                Ok(())
            },
            |ack| {
                *retained.borrow_mut() = Some(ack);
                Ok(())
            },
            || Err(Error::Pending)
        )
        .is_err());
    assert_eq!(calls.get(), 1);
    state
        .verify_ack(retained.borrow().as_ref().unwrap())
        .unwrap();
    assert!(state.was_attempted());
    assert!(state
        .run(
            || Ok(()),
            || {
                calls.set(calls.get() + 1);
                Ok(())
            },
            |_| Ok(()),
            || Ok(())
        )
        .is_err());
    assert_eq!(calls.get(), 1);
    assert!(KeyHandleClose::new()
        .verify_ack(retained.borrow().as_ref().unwrap())
        .is_err());
}

#[test]
fn terminal_hkey_unknown_outcome_retains_original_without_ack_or_drop_retry() {
    for fault in 0..4 {
        let state = KeyHandleClose::new();
        let calls = std::cell::Cell::new(0);
        let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            state.run(
                || {
                    if fault == 0 {
                        Err(Error::Conflict)
                    } else {
                        Ok(())
                    }
                },
                || {
                    calls.set(calls.get() + 1);
                    if fault == 1 {
                        Err(Error::Native)
                    } else if fault == 2 {
                        panic!("native_close_unknown")
                    } else {
                        Ok(())
                    }
                },
                |_| {
                    if fault == 3 {
                        panic!("returned_ack_postflight_unwind")
                    }
                    Ok(())
                },
                || Ok(()),
            )
        }));
        assert!(observed.is_err() || observed.unwrap().is_err());
        assert_eq!(calls.get(), usize::from(fault != 0));
        assert!(state.was_attempted());
        assert_eq!(state.read_ack().is_ok(), fault == 3);
        assert!(state
            .run(
                || Ok(()),
                || {
                    calls.set(calls.get() + 1);
                    Ok(())
                },
                |_| Ok(()),
                || Ok(())
            )
            .is_err());
        assert_eq!(calls.get(), usize::from(fault != 0));
    }
}

#[test]
fn terminal_hkey_caught_reentry_never_completes_outer_release() {
    let state = KeyHandleClose::new();
    let calls = std::cell::Cell::new(0);
    assert!(state
        .run(
            || {
                assert!(state
                    .run(
                        || Ok(()),
                        || {
                            calls.set(calls.get() + 1);
                            Ok(())
                        },
                        |_| Ok(()),
                        || Ok(())
                    )
                    .is_err());
                Ok(())
            },
            || {
                calls.set(calls.get() + 1);
                Ok(())
            },
            |_| Ok(()),
            || Ok(())
        )
        .is_err());
    assert_eq!(calls.get(), 0);
    assert!(state.read_ack().is_err());
}

#[test]
fn live_member_restore_policy_requires_fresh_exact_pending_noncarrier_key() {
    let mut r = pending();
    r.phase = Phase::Preparing;
    r.keys[0].phase = KeyPhase::Disabled;
    r.keys[0].new_key_ack = true;
    r.keys[0].current = Value::DwordZero;
    r.keys[1].phase = KeyPhase::RestorePending;
    r.keys[1].new_key_ack = true;
    r.keys[1].current = Value::DwordZero;
    r.keys[1].pending = Some(Value::Absent);
    let b = r.context.bindings[1].clone();
    let effect = Effect::Value(ValueCas {
        expected: Value::DwordZero,
        desired: Value::Absent,
        value_name: VALUE,
    });
    effect_matches_storage(&r, &b, effect, &r, true).unwrap();
    assert!(effect_matches_storage(&r, &b, effect, &r, false).is_err());
    let mut foreign = r.clone();
    foreign.generation += 1;
    assert!(effect_matches_storage(&r, &b, effect, &foreign, true).is_err());
    let mut carrier = r.clone();
    carrier.keys.swap(0, 1);
    carrier.keys[0].role = receipt::Role::RoleCarrier;
    carrier.keys[1].role = receipt::Role::MemberA;
    assert!(effect_matches_storage(
        &carrier,
        &carrier.context.bindings[0],
        effect,
        &carrier,
        true
    )
    .is_err());
}
use crate::member_carrier::{CarrierError as Error, Result};
use crate::member_carrier_native_ownership::{
    Binding, Context, FullNativeRows, KeyPhase, KeyReceipt, NativeKeyIo, NativeValue, Phase,
    Record, Role, Value, ValueCas,
};
use nelomai_client_tunnel::redundancy::SessionScope;
use nelomai_contracts::{dispatcher::EngineIdentity, RuntimeSlot};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

fn context() -> Context {
    Context {intent:crate::member_carrier::Intent {scope:SessionScope {runtime:RuntimeSlot::Stable,runtime_generation:2,session_id:"11111111-1111-4111-8111-111111111111".into(),connection_generation:3},addresses:vec!["10.7.0.2/32".parse().unwrap()]},
 provenance:crate::member_carrier::Provenance {boot_id:[8;16],network_epoch:7,runtime:EngineIdentity {slot:RuntimeSlot::Stable,runtime_version:"0.3.3".into(),container_version:"0.3.3".into(),runtime_contract_version:1,manifest_sha256:"a".repeat(64)}},
 bindings:[1u8,2,3].map(|id|{let guid=format!("{id:02x}").repeat(4)+"-"+&format!("{id:02x}").repeat(2)+"-"+&format!("{id:02x}").repeat(2)+"-"+&format!("{id:02x}").repeat(2)+"-"+&format!("{id:02x}").repeat(6);Binding {role:[Role::RoleCarrier,Role::MemberA,Role::MemberB][(id-1)as usize],guid:[id;16],name:format!("carrier-{id}"),registry_path:format!("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{{{guid}}}")}})}
}
fn pending() -> Record {
    Record {
        version: 2,
        context: context(),
        generation: 2,
        phase: Phase::Preparing,
        keys: [Role::RoleCarrier, Role::MemberA, Role::MemberB].map(|role| KeyReceipt {
            role,
            phase: if role == Role::RoleCarrier {
                KeyPhase::CreatePending
            } else {
                KeyPhase::Unstarted
            },
            new_key_ack: false,
            baseline: Value::Absent,
            current: Value::Absent,
            pending: None,
        }),
        native_rows: FullNativeRows::Unbound,
    }
}
const NATIVE_PARENT: &str =
    r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces";
#[cfg(not(windows))]
const VALUE: &str = "IPAutoconfigurationEnabled";
#[derive(Default)]
struct State {
    values: BTreeMap<u64, NativeValue>,
    // Independent registry contents: reading/restoring the APIPA value does
    // not prove the key empty, nor authorize deleting any other contents.
    other_values: BTreeMap<(u64, String), NativeValue>,
    subkeys: BTreeMap<(u64, String), ()>,
    names: BTreeMap<u64, String>,
    path: Option<u64>,
    next: u64,
    writes: usize,
    fail_flush: bool,
    force_existing: bool,
    create_result_lost: bool,
    deleted: bool,
    nic: bool,
    lock_valid: bool,
    panic_after_write: bool,
    effect_denied: bool,
    parent_reads: usize,
    value_reads: usize,
    drift_parent_after: Option<usize>,
    drift_value_after: Option<usize>,
    original_info_status: Option<u32>,
    original_info_reads: usize,
}
type Shared = Rc<RefCell<State>>;
struct Kernel(Shared);
struct Authority(Shared);
impl NativeAuthority for Authority {
    type Lock = bool;
    fn verify(&mut self, lock: &mut bool, _: &Context) -> Result<()> {
        if *lock && self.0.borrow().lock_valid {
            Ok(())
        } else {
            Err(Error::Conflict)
        }
    }
    fn authorize_effect(
        &mut self,
        lock: &mut bool,
        pending: &Record,
        _: &Binding,
        _: Effect,
    ) -> Result<()> {
        self.verify(lock, &pending.context)?;
        if self.0.borrow().effect_denied {
            Err(Error::Conflict)
        } else {
            Ok(())
        }
    }
    fn nic_absence(
        &mut self,
        _: &mut bool,
        _: &Context,
        _: &Binding,
    ) -> Result<(bool, bool, bool)> {
        let absent = !self.0.borrow().nic;
        Ok((absent, absent, absent))
    }
}
impl RegistryKernel for Kernel {
    type Handle = u64;
    fn interfaces(&mut self) -> Result<u64> {
        Ok(1)
    }
    fn name(&mut self, h: &u64) -> Result<String> {
        if *h == 1 {
            let mut state = self.0.borrow_mut();
            state.parent_reads += 1;
            if state
                .drift_parent_after
                .is_some_and(|n| state.parent_reads >= n)
            {
                return Ok(format!("{NATIVE_PARENT}\\foreign"));
            }
            return Ok(NATIVE_PARENT.into());
        }
        self.0.borrow().names.get(h).cloned().ok_or(Error::Conflict)
    }
    fn open(&mut self, _: &u64, _: &str) -> Result<Option<u64>> {
        Ok(self.0.borrow().path)
    }
    fn create(&mut self, _: &u64, child: &str) -> Result<(u64, u32)> {
        let mut s = self.0.borrow_mut();
        s.next += 1;
        let h = s.next;
        s.names.insert(h, format!("{NATIVE_PARENT}\\{child}"));
        s.values.insert(h, NativeValue::Absent);
        s.path = Some(h);
        if s.create_result_lost {
            return Err(Error::Pending);
        }
        Ok((h, if s.force_existing { 2 } else { 1 }))
    }
    fn value(&mut self, h: &u64) -> Result<NativeValue> {
        let mut s = self.0.borrow_mut();
        s.value_reads += 1;
        if s.drift_value_after.is_some_and(|n| s.value_reads >= n) {
            return Ok(NativeValue::Dword(1));
        }
        assert!(
            !s.panic_after_write || s.writes == 0,
            "injected native read panic"
        );
        if s.deleted {
            return Err(Error::Conflict);
        }
        s.values.get(h).cloned().ok_or(Error::Conflict)
    }
    fn zero(&mut self, h: &u64) -> Result<()> {
        let mut s = self.0.borrow_mut();
        s.writes += 1;
        s.values.insert(*h, NativeValue::Dword(0));
        Ok(())
    }
    fn delete_value(&mut self, h: &u64) -> Result<()> {
        let mut s = self.0.borrow_mut();
        s.writes += 1;
        s.values.insert(*h, NativeValue::Absent);
        Ok(())
    }
    fn flush(&mut self, _: &u64) -> Result<()> {
        if self.0.borrow().fail_flush {
            Err(Error::Pending)
        } else {
            Ok(())
        }
    }
    fn original_key_info_status(&mut self, h: &u64) -> Result<u32> {
        let mut s = self.0.borrow_mut();
        assert!(
            s.names.contains_key(h),
            "must query actual returned original"
        );
        s.original_info_reads += 1;
        s.original_info_status.ok_or(Error::Pending)
    }
}

#[test]
fn panic_during_effect_confirmation_cannot_rearm_live_key_io() {
    let (mut io, s) = setup();
    let mut r = pending();
    let b = r.context.bindings[0].clone();
    let f = io.inspect(&mut true, &r, &b, None, 1).unwrap();
    let ack = io.create_new_key(&mut true, &r, &b, &f).unwrap();
    r.keys[0].new_key_ack = true;
    r.keys[0].phase = KeyPhase::DisablePending;
    r.keys[0].pending = Some(Value::DwordZero);
    let f = io.inspect(&mut true, &r, &b, Some(&ack), 2).unwrap();
    s.borrow_mut().panic_after_write = true;
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| io.compare_exchange_value(
            &mut true,
            &r,
            &b,
            &ack,
            &f,
            ValueCas {
                expected: Value::Absent,
                desired: Value::DwordZero,
                value_name: VALUE
            }
        )))
        .is_err()
    );
    s.borrow_mut().panic_after_write = false;
    assert!(io.inspect(&mut true, &r, &b, Some(&ack), 3).is_err());
}
fn setup() -> (Keys<Kernel, Authority>, Shared) {
    let shared = Rc::new(RefCell::new(State {
        next: 10,
        lock_valid: true,
        ..Default::default()
    }));
    (
        Keys::new(Kernel(shared.clone()), Authority(shared.clone()), context()),
        shared,
    )
}

#[test]
fn module_precreation_read_uses_same_new_key_ack_and_never_writes() {
    let (mut io, shared) = setup();
    let mut record = pending();
    let binding = record.context.bindings[0].clone();
    let facts = io.inspect(&mut true, &record, &binding, None, 1).unwrap();
    let ack = io
        .create_new_key(&mut true, &record, &binding, &facts)
        .unwrap();
    record.keys[0].new_key_ack = true;
    record.keys[0].phase = KeyPhase::DisablePending;
    record.keys[0].pending = Some(Value::DwordZero);
    let facts = io
        .inspect(&mut true, &record, &binding, Some(&ack), 2)
        .unwrap();
    io.compare_exchange_value(
        &mut true,
        &record,
        &binding,
        &ack,
        &facts,
        ValueCas {
            expected: Value::Absent,
            desired: Value::DwordZero,
            value_name: VALUE,
        },
    )
    .unwrap();
    record.keys[0].phase = KeyPhase::Disabled;
    record.keys[0].current = Value::DwordZero;
    record.keys[0].pending = None;
    let writes = shared.borrow().writes;
    let mut kernel = Kernel(shared.clone());
    assert_eq!(
        reattest_disabled_original_key(&mut kernel, &record, &binding, &ack),
        Ok(())
    );
    assert_eq!(shared.borrow().writes, writes);
    shared.borrow_mut().path = None;
    assert!(reattest_disabled_original_key(&mut kernel, &record, &binding, &ack).is_err());
    shared.borrow_mut().path = Some(11);
    shared.borrow_mut().values.insert(11, NativeValue::Dword(1));
    assert!(reattest_disabled_original_key(&mut kernel, &record, &binding, &ack).is_err());
    shared.borrow_mut().values.insert(11, NativeValue::Dword(0));
    shared.borrow_mut().deleted = true;
    assert!(reattest_disabled_original_key(&mut kernel, &record, &binding, &ack).is_err());
    shared.borrow_mut().deleted = false;
    let mut foreign = binding.clone();
    foreign.name.push_str("-other");
    assert!(reattest_disabled_original_key(&mut kernel, &record, &foreign, &ack).is_err());
    let mut changed = record.clone();
    changed.context.provenance.network_epoch += 1;
    assert!(reattest_disabled_original_key(&mut kernel, &changed, &binding, &ack).is_err());
    let mut pending = record.clone();
    pending.keys[0].pending = Some(Value::DwordZero);
    assert!(reattest_disabled_original_key(&mut kernel, &pending, &binding, &ack).is_err());
    assert_eq!(shared.borrow().writes, writes);
}

#[test]
fn observation_permission_does_not_authorize_native_key_creation() {
    let (mut io, s) = setup();
    let r = pending();
    let b = r.context.bindings[0].clone();
    let f = io.inspect(&mut true, &r, &b, None, 1).unwrap();
    s.borrow_mut().effect_denied = true;
    assert!(io.create_new_key(&mut true, &r, &b, &f).is_err());
    assert!(s.borrow().path.is_none());
}

// Actual Keys create/disable flow. Only the OS registry and independent native
// authority boundaries are replaced; these are not native Windows acceptance.
fn disabled_role(
    role: Role,
) -> (
    Record,
    Binding,
    crate::member_carrier_native_ownership::NewKeyAck<Held<u64>>,
    Shared,
) {
    let (mut io, shared) = setup();
    let mut record = pending();
    let index = match role {
        Role::RoleCarrier => 0,
        Role::MemberA => 1,
        Role::MemberB => 2,
    };
    record.keys[0].phase = KeyPhase::Unstarted;
    record.keys[index].phase = KeyPhase::CreatePending;
    let binding = record.context.bindings[index].clone();
    let facts = io.inspect(&mut true, &record, &binding, None, 1).unwrap();
    let ack = io
        .create_new_key(&mut true, &record, &binding, &facts)
        .unwrap();
    record.keys[index].phase = KeyPhase::DisablePending;
    record.keys[index].new_key_ack = true;
    record.keys[index].pending = Some(Value::DwordZero);
    let facts = io
        .inspect(&mut true, &record, &binding, Some(&ack), 2)
        .unwrap();
    io.compare_exchange_value(
        &mut true,
        &record,
        &binding,
        &ack,
        &facts,
        ValueCas {
            expected: Value::Absent,
            desired: Value::DwordZero,
            value_name: VALUE,
        },
    )
    .unwrap();
    record.keys[index].phase = KeyPhase::Disabled;
    record.keys[index].current = Value::DwordZero;
    record.keys[index].pending = None;
    record.encode().unwrap();
    (record, binding, ack, shared)
}

#[test]
fn member_precreation_reattests_original_disabled_a_and_b_without_writes() {
    for role in [Role::MemberA, Role::MemberB] {
        let (record, binding, ack, shared) = disabled_role(role);
        let writes = shared.borrow().writes;
        let mut kernel = Kernel(shared.clone());
        assert_eq!(
            reattest_disabled_original_member_key(
                &mut kernel,
                &record,
                &record.context,
                &binding,
                record.generation,
                &ack
            ),
            Ok(())
        );
        assert!(reattest_disabled_original_key(&mut kernel, &record, &binding, &ack).is_err());
        assert_eq!(shared.borrow().writes, writes);
    }
}

#[test]
fn member_precreation_never_accepts_carrier_other_role_or_changed_current_record() {
    let (record, binding, ack, shared) = disabled_role(Role::MemberA);
    let mut kernel = Kernel(shared.clone());
    for generation in [0, record.generation + 1] {
        assert!(reattest_disabled_original_member_key(
            &mut kernel,
            &record,
            &record.context,
            &binding,
            generation,
            &ack
        )
        .is_err());
    }
    for index in [0, 2] {
        assert!(reattest_disabled_original_member_key(
            &mut kernel,
            &record,
            &record.context,
            &record.context.bindings[index],
            record.generation,
            &ack
        )
        .is_err());
    }
    for mode in 0..8 {
        let mut changed = record.clone();
        match mode {
            0 => changed.phase = Phase::Closing,
            1 => changed.generation = 0,
            2 => changed.keys[1].new_key_ack = false,
            3 => changed.keys[1].phase = KeyPhase::Captured,
            4 => changed.keys[1].current = Value::Absent,
            5 => changed.keys[1].pending = Some(Value::DwordZero),
            6 => changed.context.provenance.network_epoch += 1,
            _ => changed.context.bindings[1].name.push_str("-foreign"),
        }
        assert!(reattest_disabled_original_member_key(
            &mut kernel,
            &changed,
            &record.context,
            &binding,
            record.generation,
            &ack
        )
        .is_err());
    }
    let (carrier, carrier_binding, carrier_ack, carrier_shared) = disabled_role(Role::RoleCarrier);
    assert!(reattest_disabled_original_member_key(
        &mut Kernel(carrier_shared.clone()),
        &carrier,
        &carrier.context,
        &carrier_binding,
        carrier.generation,
        &carrier_ack
    )
    .is_err());
    assert!(reattest_disabled_original_key(
        &mut Kernel(carrier_shared),
        &carrier,
        &carrier_binding,
        &carrier_ack
    )
    .is_ok());
    assert_eq!(shared.borrow().writes, 1);
}

#[test]
fn member_precreation_requires_original_held_context_names_and_exact_native_value() {
    for role in [Role::MemberA, Role::MemberB] {
        for mode in 0..8 {
            let (record, binding, ack, shared) = disabled_role(role);
            match mode {
                0 => {
                    shared.borrow_mut().path = None;
                }
                1 => {
                    shared.borrow_mut().values.insert(11, NativeValue::Dword(1));
                }
                2 => {
                    shared.borrow_mut().values.insert(
                        11,
                        NativeValue::Other {
                            kind: 1,
                            bytes: vec![0; 4],
                        },
                    );
                }
                3 => {
                    shared
                        .borrow_mut()
                        .names
                        .insert(11, format!("{NATIVE_PARENT}\\renamed"));
                }
                4 => {
                    shared.borrow_mut().deleted = true;
                }
                5 => {
                    let mut state = shared.borrow_mut();
                    state.path = Some(12);
                    state
                        .names
                        .insert(12, format!("{NATIVE_PARENT}\\replacement"));
                    state.values.insert(12, NativeValue::Dword(0));
                }
                6 => {
                    let mut state = shared.borrow_mut();
                    state.path = Some(12);
                    let old_name = state.names.remove(&11).unwrap();
                    state.names.insert(12, old_name);
                    state.values.insert(12, NativeValue::Dword(0));
                }
                _ => {
                    let foreign_context = {
                        let mut c = record.context.clone();
                        c.intent.scope.connection_generation += 1;
                        c
                    };
                    let mut foreign = record.clone();
                    foreign.context = foreign_context.clone();
                    assert!(reattest_disabled_original_member_key(
                        &mut Kernel(shared.clone()),
                        &foreign,
                        &foreign_context,
                        &binding,
                        foreign.generation,
                        &ack
                    )
                    .is_err());
                    continue;
                }
            }
            assert!(reattest_disabled_original_member_key(
                &mut Kernel(shared.clone()),
                &record,
                &record.context,
                &binding,
                record.generation,
                &ack
            )
            .is_err());
            assert_eq!(shared.borrow().writes, 1);
        }
    }
}

#[test]
fn member_precreation_requires_second_parent_and_value_continuity_sample() {
    for role in [Role::MemberA, Role::MemberB] {
        for parent in [true, false] {
            let (record, binding, ack, shared) = disabled_role(role);
            {
                let mut state = shared.borrow_mut();
                state.parent_reads = 0;
                state.value_reads = 0;
                if parent {
                    state.drift_parent_after = Some(3);
                } else {
                    state.drift_value_after = Some(3);
                }
            }
            assert!(reattest_disabled_original_member_key(
                &mut Kernel(shared.clone()),
                &record,
                &record.context,
                &binding,
                record.generation,
                &ack
            )
            .is_err());
            assert_eq!(shared.borrow().writes, 1);
        }
    }
}

#[test]
fn observation_permission_does_not_authorize_native_value_write() {
    let (mut io, s) = setup();
    let mut r = pending();
    let b = r.context.bindings[0].clone();
    let f = io.inspect(&mut true, &r, &b, None, 1).unwrap();
    let ack = io.create_new_key(&mut true, &r, &b, &f).unwrap();
    r.keys[0].new_key_ack = true;
    r.keys[0].phase = KeyPhase::DisablePending;
    r.keys[0].pending = Some(Value::DwordZero);
    let f = io.inspect(&mut true, &r, &b, Some(&ack), 2).unwrap();
    s.borrow_mut().effect_denied = true;
    assert!(io
        .compare_exchange_value(
            &mut true,
            &r,
            &b,
            &ack,
            &f,
            ValueCas {
                expected: Value::Absent,
                desired: Value::DwordZero,
                value_name: VALUE
            }
        )
        .is_err());
    assert_eq!(s.borrow().writes, 0);
    assert_eq!(s.borrow().values.get(&11), Some(&NativeValue::Absent));
}

#[test]
fn reopened_preparing_receipt_cannot_authorize_creation_or_disable() {
    let mut r = pending();
    let b = r.context.bindings[0].clone();
    assert!(effect_matches_storage(&r, &b, Effect::Create, &r, true).is_ok());
    assert!(effect_matches_storage(&r, &b, Effect::Create, &r, false).is_err());
    r.keys[0].new_key_ack = true;
    r.keys[0].phase = KeyPhase::DisablePending;
    r.keys[0].pending = Some(Value::DwordZero);
    let effect = Effect::Value(ValueCas {
        expected: Value::Absent,
        desired: Value::DwordZero,
        value_name: VALUE,
    });
    assert!(effect_matches_storage(&r, &b, effect, &r, true).is_ok());
    assert!(effect_matches_storage(&r, &b, effect, &r, false).is_err());
}

#[test]
fn only_the_exact_persisted_pending_receipt_can_authorize_an_effect() {
    let r = pending();
    let b = r.context.bindings[0].clone();
    for mode in 0..4 {
        let mut actual = r.clone();
        match mode {
            0 => actual.generation += 1,
            1 => actual.context.provenance.network_epoch += 1,
            2 => actual.context.intent.scope.connection_generation += 1,
            _ => actual.keys[0].phase = KeyPhase::Unstarted,
        }
        assert!(effect_matches_storage(&r, &b, Effect::Create, &actual, true).is_err());
    }
    let foreign = r.context.bindings[1].clone();
    assert!(effect_matches_storage(&r, &foreign, Effect::Create, &r, true).is_err());
    let mut unsupported = r.clone();
    unsupported.version = 999;
    assert!(effect_matches_storage(&unsupported, &b, Effect::Create, &unsupported, true).is_err());
}

#[test]
fn cleanup_authorizes_only_exact_owned_value_restoration_not_key_deletion() {
    let mut r = pending();
    let b = r.context.bindings[0].clone();
    r.phase = Phase::Closing;
    r.keys[0].new_key_ack = true;
    r.keys[0].phase = KeyPhase::RestorePending;
    r.keys[0].current = Value::DwordZero;
    r.keys[0].pending = Some(Value::Absent);
    let effect = Effect::Value(ValueCas {
        expected: Value::DwordZero,
        desired: Value::Absent,
        value_name: VALUE,
    });
    assert!(effect_matches_storage(&r, &b, effect, &r, false).is_ok());
    assert!(effect_matches_storage(&r, &b, Effect::Create, &r, true).is_err());
    let wrong = Effect::Value(ValueCas {
        expected: Value::DwordZero,
        desired: Value::Absent,
        value_name: "ForeignValue",
    });
    assert!(effect_matches_storage(&r, &b, wrong, &r, false).is_err());
    r.keys[0].new_key_ack = false;
    assert!(effect_matches_storage(&r, &b, effect, &r, false).is_err());
}
fn name_bytes(name: &str) -> Vec<u8> {
    let b: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut out = (b.len() as u32).to_le_bytes().to_vec();
    out.extend(b);
    out
}
#[test]
fn native_name_decoder_consumes_nonterminated_exact_length() {
    let b = name_bytes(NATIVE_PARENT);
    assert_eq!(decode_name(&b, b.len()).unwrap(), NATIVE_PARENT);
}
#[test]
fn native_name_decoder_rejects_truncation_odd_length_nul_and_surrogate() {
    for b in [
        vec![1, 0, 0, 0, 65],
        vec![2, 0, 0, 0, 0, 0],
        vec![2, 0, 0, 0, 0, 216],
        vec![255; 4096],
    ] {
        assert!(decode_name(&b, b.len()).is_err())
    }
}
#[test]
fn canonical_interfaces_parent_cannot_be_foreign_or_alias() {
    assert!(parent_valid(NATIVE_PARENT));
    assert!(parent_valid(&NATIVE_PARENT.to_lowercase()));
    for p in [
        r"\REGISTRY\USER\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces",
        r"\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
        r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\extra",
    ] {
        assert!(!parent_valid(p));
    }
}
#[test]
fn actual_new_handle_and_exact_raw_value_complete_disable_restore() {
    let (mut io, s) = setup();
    let mut r = pending();
    let binding = r.context.bindings[0].clone();
    let f = io.inspect(&mut true, &r, &binding, None, 1).unwrap();
    let ack = io.create_new_key(&mut true, &r, &binding, &f).unwrap();
    r.generation += 1;
    r.keys[0].new_key_ack = true;
    r.keys[0].phase = KeyPhase::DisablePending;
    r.keys[0].pending = Some(Value::DwordZero);
    let f = io.inspect(&mut true, &r, &binding, Some(&ack), 2).unwrap();
    io.compare_exchange_value(
        &mut true,
        &r,
        &binding,
        &ack,
        &f,
        ValueCas {
            expected: Value::Absent,
            desired: Value::DwordZero,
            value_name: VALUE,
        },
    )
    .unwrap();
    assert_eq!(s.borrow().values.get(&11), Some(&NativeValue::Dword(0)));
    r.phase = Phase::Closing;
    r.generation += 1;
    r.keys[0].phase = KeyPhase::RestorePending;
    r.keys[0].current = Value::DwordZero;
    r.keys[0].pending = Some(Value::Absent);
    let f = io.inspect(&mut true, &r, &binding, Some(&ack), 3).unwrap();
    io.compare_exchange_value(
        &mut true,
        &r,
        &binding,
        &ack,
        &f,
        ValueCas {
            expected: Value::DwordZero,
            desired: Value::Absent,
            value_name: VALUE,
        },
    )
    .unwrap();
    assert_eq!(s.borrow().values.get(&11), Some(&NativeValue::Absent));
    assert_eq!(s.borrow().writes, 2);
}

// SAME actual Keys/authority/kernel and original CREATED_NEW ACK throughout.
// Only external registry/independent authority IO is doubled. No NativeOwner,
// SDK outcome, persisted deletion or terminal grant is supplied by this helper.
struct RestoredOriginal {
    io: Keys<Kernel, Authority>,
    shared: Shared,
    ack: NewKeyAck<Held<u64>>,
    record: Record,
    binding: Binding,
}
fn restore_original_before_nic(
    role: Role,
    before_restore: impl FnOnce(&Shared, u64),
) -> RestoredOriginal {
    let (mut io, shared) = setup();
    let mut record = pending();
    let index = role as usize;
    record.keys[0].phase = KeyPhase::Unstarted;
    record.keys[index].phase = KeyPhase::CreatePending;
    let binding = record.context.bindings[index].clone();
    let facts = io.inspect(&mut true, &record, &binding, None, 1).unwrap();
    let ack = io
        .create_new_key(&mut true, &record, &binding, &facts)
        .unwrap();
    record.keys[index].new_key_ack = true;
    record.keys[index].phase = KeyPhase::DisablePending;
    record.keys[index].pending = Some(Value::DwordZero);
    let facts = io
        .inspect(&mut true, &record, &binding, Some(&ack), 2)
        .unwrap();
    io.compare_exchange_value(
        &mut true,
        &record,
        &binding,
        &ack,
        &facts,
        ValueCas {
            expected: Value::Absent,
            desired: Value::DwordZero,
            value_name: VALUE,
        },
    )
    .unwrap();
    before_restore(&shared, *ack.retained_handle().handle());
    record.phase = Phase::Closing;
    record.keys[index].phase = KeyPhase::RestorePending;
    record.keys[index].current = Value::DwordZero;
    record.keys[index].pending = Some(Value::Absent);
    let facts = io
        .inspect(&mut true, &record, &binding, Some(&ack), 3)
        .unwrap();
    io.compare_exchange_value(
        &mut true,
        &record,
        &binding,
        &ack,
        &facts,
        ValueCas {
            expected: Value::DwordZero,
            desired: Value::Absent,
            value_name: VALUE,
        },
    )
    .unwrap();
    RestoredOriginal {
        io,
        shared,
        ack,
        record,
        binding,
    }
}

#[test]
fn restored_original_before_nic_leaves_key_and_blocks_fresh_start() {
    // Break: treating successful value restore or NIC absence as key absence
    // permits adopting a surviving NON_VOLATILE key at the next precreation.
    for role in [Role::RoleCarrier, Role::MemberA, Role::MemberB] {
        let RestoredOriginal {
            mut io,
            shared,
            ack,
            record,
            binding,
        } = restore_original_before_nic(role, |_, _| {});
        assert!(!shared.borrow().nic);
        assert_eq!(shared.borrow().writes, 2);
        let original = *ack.retained_handle().handle();
        assert_eq!(shared.borrow().path, Some(original));
        assert_eq!(shared.borrow().values[&original], NativeValue::Absent);
        let owned = io
            .inspect(&mut true, &record, &binding, Some(&ack), 4)
            .unwrap();
        assert_eq!(owned.key, KeyPresence::ExactRetainedNewKey);
        assert_eq!(owned.value, NativeValue::Absent);
        let mut fresh = pending();
        fresh.keys[0].phase = KeyPhase::Unstarted;
        fresh.keys[role as usize].phase = KeyPhase::CreatePending;
        let unowned = io.inspect(&mut true, &fresh, &binding, None, 5).unwrap();
        assert_eq!(unowned.key, KeyPresence::Foreign);
        assert!(io
            .create_new_key(&mut true, &fresh, &binding, &unowned)
            .is_err());
        assert_eq!(shared.borrow().path, Some(original));
        assert_eq!(shared.borrow().writes, 2);
    }
}

#[test]
fn apipa_absence_does_not_prove_entire_original_key_empty() {
    // Break: deleting a key from only an absent APIPA value destroys foreign
    // values/subkeys. These are genuine independent external registry rows.
    let RestoredOriginal {
        mut io,
        shared,
        ack,
        record,
        binding,
    } = restore_original_before_nic(Role::RoleCarrier, |shared, original| {
        let mut state = shared.borrow_mut();
        state.other_values.insert(
            (original, "ForeignConfiguration".into()),
            NativeValue::Dword(17),
        );
        state.subkeys.insert((original, "ForeignChild".into()), ());
    });
    let original = *ack.retained_handle().handle();
    let value = (original, "ForeignConfiguration".to_owned());
    let subkey = (original, "ForeignChild".to_owned());
    let facts = io
        .inspect(&mut true, &record, &binding, Some(&ack), 4)
        .unwrap();
    assert_eq!(facts.value, NativeValue::Absent);
    assert_eq!(facts.key, KeyPresence::ExactRetainedNewKey);
    assert_eq!(shared.borrow().other_values[&value], NativeValue::Dword(17));
    assert!(shared.borrow().subkeys.contains_key(&subkey));
    assert_eq!(shared.borrow().writes, 2);
}

// Only external registry handles are doubled. All creation/retention/close
// policy below is the production Keys + KeyHandleClose implementation.
struct DropTrackedHandle {
    id: u64,
    original: std::cell::Cell<bool>,
    close: KeyHandleClose,
    closes: Rc<std::cell::Cell<usize>>,
    close_fault: std::cell::Cell<u8>,
}
impl Drop for DropTrackedHandle {
    fn drop(&mut self) {
        if self.original.get() && !self.close.was_attempted() {
            self.closes.set(self.closes.get() + 1);
        }
    }
}
impl TerminalKeyHandle for DropTrackedHandle {
    fn close_original(
        &self,
        check: impl FnOnce() -> Result<()>,
        retain: impl FnOnce(Rc<KeyHandleClosed>) -> Result<()>,
        post: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.close.run(
            check,
            || {
                self.closes.set(self.closes.get() + 1);
                match self.close_fault.get() {
                    1 => Err(Error::Native),
                    2 => panic!("external_original_close_unknown"),
                    _ => Ok(()),
                }
            },
            retain,
            post,
        )
    }
    fn verify_closed(&self, ack: &Rc<KeyHandleClosed>) -> Result<()> {
        self.close.verify_ack(ack)
    }
}
struct DropTrackedKernel {
    registry: Kernel,
    closes: Rc<std::cell::Cell<usize>>,
    track_created_parent: bool,
}
impl DropTrackedKernel {
    fn wrap(&self, id: u64, original: bool) -> DropTrackedHandle {
        DropTrackedHandle {
            id,
            original: std::cell::Cell::new(original),
            close: KeyHandleClose::new(),
            closes: self.closes.clone(),
            close_fault: std::cell::Cell::new(0),
        }
    }
}
impl RegistryKernel for DropTrackedKernel {
    type Handle = DropTrackedHandle;
    fn interfaces(&mut self) -> Result<Self::Handle> {
        let id = self.registry.interfaces()?;
        Ok(self.wrap(id, false))
    }
    fn name(&mut self, h: &Self::Handle) -> Result<String> {
        if h.close.was_attempted() {
            return Err(Error::Pending);
        }
        self.registry.name(&h.id)
    }
    fn open(&mut self, p: &Self::Handle, child: &str) -> Result<Option<Self::Handle>> {
        if p.close.was_attempted() {
            return Err(Error::Pending);
        }
        Ok(self
            .registry
            .open(&p.id, child)?
            .map(|id| self.wrap(id, false)))
    }
    fn create(&mut self, p: &Self::Handle, child: &str) -> Result<(Self::Handle, u32)> {
        let (id, disposition) = self.registry.create(&p.id, child)?;
        if self.track_created_parent && disposition == 1 {
            p.original.set(true);
        }
        Ok((self.wrap(id, true), disposition))
    }
    fn value(&mut self, h: &Self::Handle) -> Result<NativeValue> {
        if h.close.was_attempted() {
            return Err(Error::Pending);
        }
        self.registry.value(&h.id)
    }
    fn zero(&mut self, h: &Self::Handle) -> Result<()> {
        self.registry.zero(&h.id)
    }
    fn delete_value(&mut self, h: &Self::Handle) -> Result<()> {
        self.registry.delete_value(&h.id)
    }
    fn flush(&mut self, h: &Self::Handle) -> Result<()> {
        self.registry.flush(&h.id)
    }
    fn original_key_info_status(&mut self, h: &Self::Handle) -> Result<u32> {
        if h.close.was_attempted() {
            return Err(Error::Pending);
        }
        self.registry.original_key_info_status(&h.id)
    }
}

#[test]
fn abandoned_created_new_key_cannot_implicitly_close_terminal_obligation() {
    // Break: the owning NEW acknowledgement's ordinary Drop releases its native
    // handle without either terminal disposition or an actual close ACK.
    let (_, shared) = setup();
    let closes = Rc::new(std::cell::Cell::new(0));
    let mut keys = Keys::new(
        DropTrackedKernel {
            registry: Kernel(shared.clone()),
            closes: closes.clone(),
            track_created_parent: false,
        },
        Authority(shared.clone()),
        context(),
    );
    let record = pending();
    let binding = record.context.bindings[0].clone();
    let facts = keys.inspect(&mut true, &record, &binding, None, 1).unwrap();
    let original = keys
        .create_new_key(&mut true, &record, &binding, &facts)
        .unwrap();
    drop(original);
    drop(keys);
    assert_eq!(
        closes.get(),
        0,
        "unknown original must remain retained, not RegCloseKey in Drop"
    );
    assert_eq!(shared.borrow().path, Some(11));
}

#[test]
fn original_created_parent_survives_capture_success_and_failed_postflight() {
    // Break: remembering a parent path instead of the SAME actual parent HKEY
    // closes its native descriptor when capture returns or unwinds. A later
    // reopened name cannot supply original-parent identity for root disposition.
    for fail_flush in [false, true] {
        let (_, shared) = setup();
        let closes = Rc::new(std::cell::Cell::new(0));
        let mut keys = Keys::new(
            DropTrackedKernel {
                registry: Kernel(shared.clone()),
                closes: closes.clone(),
                track_created_parent: true,
            },
            Authority(shared.clone()),
            context(),
        );
        let record = pending();
        let binding = record.context.bindings[0].clone();
        let facts = keys.inspect(&mut true, &record, &binding, None, 1).unwrap();
        shared.borrow_mut().fail_flush = fail_flush;
        let outcome = keys.create_new_key(&mut true, &record, &binding, &facts);
        assert_eq!(outcome.is_err(), fail_flush);
        assert_eq!(
            closes.get(),
            0,
            "actual CREATED_NEW parent must be retained before capture postflight"
        );
        let pin = if let Ok(original) = outcome {
            let pin = terminal_original_key_obligation(&original);
            drop(original);
            pin
        } else {
            keys.pending_original_key_obligation().unwrap()
        };
        assert!(pin.require_root_absent().is_err());
        drop(keys);
        drop(pin);
        assert_eq!(
            closes.get(),
            0,
            "unknown original parent is not Drop authority"
        );
    }
}

#[test]
fn restored_value_keeps_same_owning_key_root_obligation_and_fresh_absence_denies() {
    // Break: promoting successful RegDeleteValue + an empty DWORD read to a
    // root deletion receipt, or reconstructing a pin instead of the original.
    let RestoredOriginal {
        mut io,
        shared,
        ack,
        record,
        binding,
    } = restore_original_before_nic(Role::RoleCarrier, |_, _| {});
    let pin = terminal_original_key_obligation(&ack);
    assert!(Rc::ptr_eq(&pin, &terminal_original_key_obligation(&ack)));
    pin.verify_original(&ack).unwrap();
    assert_eq!(
        pin.classification(),
        KeyRootObligationKind::ValueRestoreObservedRootRetained
    );
    assert!(pin.require_root_absent().is_err());
    let reads = (shared.borrow().parent_reads, shared.borrow().value_reads);
    let _ = pin.classification();
    pin.verify_original(&ack).unwrap();
    assert_eq!(
        reads,
        (shared.borrow().parent_reads, shared.borrow().value_reads)
    );
    let facts = io.inspect(&mut true, &record, &binding, None, 10).unwrap();
    assert_eq!(facts.key, KeyPresence::Foreign);
    assert!(io
        .create_new_key(&mut true, &pending(), &binding, &facts)
        .is_err());
    assert_eq!(shared.borrow().writes, 2);
    drop(ack);
    assert_eq!(
        pin.classification(),
        KeyRootObligationKind::ValueRestoreObservedRootRetained
    );
    assert!(pin.require_root_absent().is_err());
}

// Break: a genuine 1018 original observation cannot be retained; equal lookup
// absence/restored DWORD or a foreign original instead supplies the receipt.
#[test]
fn sdk_deleted_original_observation_roots_status_before_postflight_and_no_disposition() {
    for post_error in [false, true] {
        let mut actual = restore_original_before_nic(Role::RoleCarrier, |_, _| {});
        actual.shared.borrow_mut().original_info_status = Some(1018);
        actual.shared.borrow_mut().path = None;
        let pin = terminal_original_key_obligation(&actual.ack);
        let checks = std::cell::Cell::new(0);
        let result = pin.observe_sdk_deleted(&actual.ack, &mut actual.io.kernel, || {
            checks.set(checks.get() + 1);
            if checks.get() == 2 {
                let held = pin.sdk_deleted_read().expect("retained BEFORE postflight");
                assert_eq!(
                    held.statuses.each_ref().map(|s| s.get()),
                    [Some(1018), Some(1018)]
                );
                if post_error {
                    return Err(Error::Conflict);
                }
            }
            Ok(())
        });
        assert_eq!(result.is_ok(), !post_error);
        assert_eq!(actual.shared.borrow().original_info_reads, 2);
        assert_eq!(checks.get(), 2);
        assert!(pin.sdk_deleted_read().is_ok());
        assert!(
            pin.require_root_absent().is_err(),
            "observation is NOT close/disposition ACK"
        );
        assert!(pin.closed_handle_ack().is_err());
    }
}

#[test]
fn sdk_deleted_cleanup_observation_is_not_a_value_mutation_or_foreign_adoption() {
    let mut actual = restore_original_before_nic(Role::RoleCarrier, |_, _| {});
    actual.shared.borrow_mut().original_info_status = Some(1018);
    actual.shared.borrow_mut().path = None;
    let writes = actual.shared.borrow().writes;
    let facts = actual
        .io
        .inspect(
            &mut true,
            &actual.record,
            &actual.binding,
            Some(&actual.ack),
            91,
        )
        .unwrap();
    assert_eq!(facts.key, KeyPresence::OriginalSdkDeleted);
    assert_eq!(facts.value, NativeValue::Absent);
    assert!(actual
        .io
        .compare_exchange_value(
            &mut true,
            &actual.record,
            &actual.binding,
            &actual.ack,
            &facts,
            ValueCas {
                expected: Value::DwordZero,
                desired: Value::Absent,
                value_name: VALUE
            }
        )
        .is_err());
    assert_eq!(actual.shared.borrow().writes, writes);
    assert!(terminal_original_key_obligation(&actual.ack)
        .require_root_absent()
        .is_err());
}

struct ExactKeyJournal(Rc<RefCell<Option<Record>>>);
impl receipt::NativeJournal for ExactKeyJournal {
    fn load(&mut self, expected: &Context) -> Result<Option<Record>> {
        let saved = self.0.borrow().clone();
        if saved.as_ref().is_some_and(|r| &r.context != expected) {
            return Err(Error::Conflict);
        }
        Ok(saved)
    }
    fn compare_exchange(
        &mut self,
        context: &Context,
        old: Option<&Record>,
        desired: &Record,
    ) -> Result<()> {
        if &desired.context != context || self.0.borrow().as_ref() != old {
            return Err(Error::Journal);
        }
        *self.0.borrow_mut() = Some(desired.clone());
        Ok(())
    }
}

#[test]
fn sdk_deleted_disabled_original_cleanup_preserves_real_owner_cas_and_never_writes_deleted_key() {
    let (io, shared) = setup();
    let journal = Rc::new(RefCell::new(None));
    let mut owner =
        receipt::NativeOwnership::new(context(), ExactKeyJournal(journal.clone()), io).unwrap();
    let disabled = owner.prepare_role(Role::RoleCarrier, &mut true).unwrap();
    assert_eq!(disabled.keys[0].phase, KeyPhase::Disabled);
    assert_eq!(shared.borrow().writes, 1);
    shared.borrow_mut().original_info_status = Some(1018);
    shared.borrow_mut().path = None;
    let stopped = owner.cleanup(&disabled, &mut true).unwrap();
    assert_eq!(stopped.phase, Phase::Stopped);
    assert_eq!(journal.borrow().as_ref(), Some(&stopped));
    assert_eq!(
        shared.borrow().writes,
        1,
        "no DWORD write/delete to deleted original"
    );
    let original = owner
        .with_terminal_original_keys(&mut true, |_, keys, _| {
            Ok(terminal_original_key_obligation(keys[0].unwrap()))
        })
        .unwrap();
    assert!(original.sdk_deleted_read().is_ok());
    assert!(
        original.require_root_absent().is_err(),
        "Clean CAS alone isn't disposition"
    );
    assert!(owner
        .before_adapter_create(Role::RoleCarrier, &mut true)
        .is_err());
}

type TrackedKeyFixture = (
    Keys<DropTrackedKernel, Authority>,
    Shared,
    NewKeyAck<Held<DropTrackedHandle>>,
    Rc<std::cell::Cell<usize>>,
);
fn sdk_deleted_tracked_original() -> TrackedKeyFixture {
    let (_, shared) = setup();
    let closes = Rc::new(std::cell::Cell::new(0));
    let mut io = Keys::new(
        DropTrackedKernel {
            registry: Kernel(shared.clone()),
            closes: closes.clone(),
            track_created_parent: true,
        },
        Authority(shared.clone()),
        context(),
    );
    let record = pending();
    let facts = io
        .inspect(&mut true, &record, &record.context.bindings[0], None, 1)
        .unwrap();
    let ack = io
        .create_new_key(&mut true, &record, &record.context.bindings[0], &facts)
        .unwrap();
    shared.borrow_mut().original_info_status = Some(1018);
    shared.borrow_mut().path = None;
    (io, shared, ack, closes)
}

#[test]
fn sdk_deleted_original_requires_both_actual_close_acks_before_inert_disposition() {
    let (mut io, _, ack, closes) = sdk_deleted_tracked_original();
    let pin = terminal_original_key_obligation(&ack);
    let returned = RefCell::new(None);
    pin.close_sdk_deleted(
        &ack,
        &mut io.kernel,
        || Ok(()),
        |child| {
            *returned.borrow_mut() = Some(child);
            assert!(pin.closed_handle_ack().is_ok());
            assert!(pin.parent_closed.borrow().is_none());
            assert!(pin.require_root_absent().is_err());
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(closes.get(), 2);
    ack.retained_handle()
        .handle()
        .verify_closed(returned.borrow().as_ref().unwrap())
        .unwrap();
    pin.parent_handle()
        .verify_closed(pin.parent_closed.borrow().as_ref().unwrap())
        .unwrap();
    pin.verify_sdk_deleted_read(&pin.sdk_deleted_read().unwrap())
        .unwrap();
    pin.require_root_absent().unwrap();
    assert!(io.kernel.original_key_info_status(pin.handle()).is_err());
    assert!(io
        .kernel
        .open(pin.parent_handle(), &ack.retained_handle().child)
        .is_err());
    drop(ack);
    drop(pin);
    drop(io);
    assert_eq!(closes.get(), 2, "both native wrappers' Drop is inert");
}

#[test]
fn sdk_deleted_terminal_faults_retain_exact_observation_and_native_ack_floor() {
    for fault in 1..=8 {
        for unwind in [false, true] {
            let (mut io, _, ack, closes) = sdk_deleted_tracked_original();
            let pin = terminal_original_key_obligation(&ack);
            let calls = std::cell::Cell::new(0);
            if fault == 7 {
                pin.handle().close_fault.set(if unwind { 2 } else { 1 });
            }
            if fault == 8 {
                pin.parent_handle()
                    .close_fault
                    .set(if unwind { 2 } else { 1 });
            }
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                pin.close_sdk_deleted(
                    &ack,
                    &mut io.kernel,
                    || {
                        calls.set(calls.get() + 1);
                        if calls.get() == fault {
                            if unwind {
                                panic!("original_fence_unwind");
                            }
                            return Err(Error::Conflict);
                        }
                        Ok(())
                    },
                    |_| Ok(()),
                )
            }));
            assert!(result.is_err() || result.unwrap().is_err());
            assert!(pin.require_root_absent().is_err());
            let expected = match fault {
                1..=3 => 0,
                4 | 5 | 7 => 1,
                _ => 2,
            };
            assert_eq!(closes.get(), expected);
            assert_eq!(
                pin.closed_handle_ack().is_ok(),
                matches!(fault, 4 | 5 | 6 | 8)
            );
            assert_eq!(pin.parent_closed.borrow().is_some(), fault == 6);
            assert!(pin
                .close_sdk_deleted(&ack, &mut io.kernel, || Ok(()), |_| Ok(()))
                .is_err());
            drop(ack);
            drop(pin);
            drop(io);
            assert_eq!(closes.get(), expected, "unknown Drop cannot close/retry");
        }
    }
}

#[test]
fn sdk_deleted_caught_reentry_prevents_next_query_or_parent_close() {
    for in_retainer in [false, true] {
        let (mut io, shared, ack, closes) = sdk_deleted_tracked_original();
        let pin = terminal_original_key_obligation(&ack);
        let first = std::cell::Cell::new(true);
        let nested = || {
            let mut kernel = DropTrackedKernel {
                registry: Kernel(shared.clone()),
                closes: closes.clone(),
                track_created_parent: true,
            };
            assert!(pin
                .close_sdk_deleted(&ack, &mut kernel, || Ok(()), |_| Ok(()))
                .is_err());
        };
        assert!(pin
            .close_sdk_deleted(
                &ack,
                &mut io.kernel,
                || {
                    if !in_retainer && first.replace(false) {
                        nested();
                    }
                    Ok(())
                },
                |_| {
                    if in_retainer {
                        nested();
                    }
                    Ok(())
                }
            )
            .is_err());
        assert_eq!(closes.get(), usize::from(in_retainer));
        assert_eq!(
            shared.borrow().original_info_reads,
            if in_retainer { 2 } else { 0 }
        );
        assert!(pin.require_root_absent().is_err());
    }
}

#[test]
fn sdk_deleted_observer_denies_foreign_equal_original_parent_replace_and_non1018() {
    for fault in 0..7 {
        let mut actual = restore_original_before_nic(Role::RoleCarrier, |_, _| {});
        let other = restore_original_before_nic(Role::RoleCarrier, |_, _| {});
        let pin = terminal_original_key_obligation(&actual.ack);
        actual.shared.borrow_mut().path = None;
        actual.shared.borrow_mut().original_info_status = Some(1018);
        match fault {
            0 => actual.shared.borrow_mut().original_info_status = Some(0),
            1 => actual.shared.borrow_mut().original_info_status = Some(2),
            2 => actual.shared.borrow_mut().original_info_status = Some(5),
            3 => actual.shared.borrow_mut().original_info_status = None,
            4 => actual.shared.borrow_mut().path = Some(11),
            5 => actual.shared.borrow_mut().drift_parent_after = Some(0),
            _ => {}
        }
        let original = if fault == 6 { &other.ack } else { &actual.ack };
        assert!(pin
            .observe_sdk_deleted(original, &mut actual.io.kernel, || Ok(()))
            .is_err());
        assert!(pin.require_root_absent().is_err());
        actual.shared.borrow_mut().path = None;
        actual.shared.borrow_mut().original_info_status = Some(1018);
        assert!(
            pin.observe_sdk_deleted(&actual.ack, &mut actual.io.kernel, || Ok(()))
                .is_err(),
            "no rearm after error"
        );
    }
}

#[test]
fn sdk_deleted_read_cannot_import_foreign_equal_original_or_reset_failed_postflight() {
    let mut left = restore_original_before_nic(Role::RoleCarrier, |_, _| {});
    let mut right = restore_original_before_nic(Role::RoleCarrier, |_, _| {});
    for actual in [&mut left, &mut right] {
        actual.shared.borrow_mut().path = None;
        actual.shared.borrow_mut().original_info_status = Some(1018);
        terminal_original_key_obligation(&actual.ack)
            .observe_sdk_deleted(&actual.ack, &mut actual.io.kernel, || Ok(()))
            .unwrap();
    }
    let a = terminal_original_key_obligation(&left.ack);
    let b = terminal_original_key_obligation(&right.ack);
    assert!(a
        .verify_sdk_deleted_read(&b.sdk_deleted_read().unwrap())
        .is_err());
    a.verify_sdk_deleted_read(&a.sdk_deleted_read().unwrap())
        .unwrap();
    let n = std::cell::Cell::new(0);
    assert!(a
        .observe_sdk_deleted(&left.ack, &mut left.io.kernel, || {
            n.set(n.get() + 1);
            if n.get() == 2 {
                return Err(Error::Conflict);
            }
            Ok(())
        })
        .is_err());
    assert!(a
        .verify_sdk_deleted_read(&a.sdk_deleted_read().unwrap())
        .is_err());
}

#[test]
fn sdk_deleted_retainer_error_or_unwind_preserves_child_ack_but_never_closes_parent() {
    for unwind in [false, true] {
        let (mut io, _, ack, closes) = sdk_deleted_tracked_original();
        let pin = terminal_original_key_obligation(&ack);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pin.close_sdk_deleted(
                &ack,
                &mut io.kernel,
                || Ok(()),
                |_| {
                    assert!(pin.closed_handle_ack().is_ok());
                    if unwind {
                        panic!("caller_retainer_unwind");
                    }
                    Err(Error::Conflict)
                },
            )
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(pin.closed_handle_ack().is_ok());
        assert!(pin.parent_closed.borrow().is_none());
        assert!(pin.require_root_absent().is_err());
        drop(ack);
        drop(pin);
        drop(io);
        assert_eq!(closes.get(), 1);
    }
}

#[test]
fn sdk_deleted_observer_closed_original_or_parent_and_caught_read_reentry_deny() {
    for fault in 0..3 {
        let (mut io, shared, ack, closes) = sdk_deleted_tracked_original();
        let pin = terminal_original_key_obligation(&ack);
        if fault < 2 {
            let handle = if fault == 0 {
                pin.handle()
            } else {
                pin.parent_handle()
            };
            handle
                .close_original(|| Ok(()), |_| Ok(()), || Ok(()))
                .unwrap();
        }
        let first = std::cell::Cell::new(true);
        assert!(pin
            .observe_sdk_deleted(&ack, &mut io.kernel, || {
                if fault == 2 && first.replace(false) {
                    let mut nested = DropTrackedKernel {
                        registry: Kernel(shared.clone()),
                        closes: closes.clone(),
                        track_created_parent: true,
                    };
                    assert!(pin
                        .observe_sdk_deleted(&ack, &mut nested, || Ok(()))
                        .is_err());
                }
                Ok(())
            })
            .is_err());
        assert!(pin.require_root_absent().is_err());
        assert_eq!(shared.borrow().original_info_reads, usize::from(fault == 1));
        assert_eq!(closes.get(), usize::from(fault < 2));
    }
}

#[test]
fn sdk_deleted_cleanup_whole_sampler_error_is_sticky_and_preserves_original_receipt() {
    let mut actual = restore_original_before_nic(Role::RoleCarrier, |_, _| {});
    actual.shared.borrow_mut().original_info_status = Some(1018);
    actual.shared.borrow_mut().path = None;
    actual.shared.borrow_mut().lock_valid = false;
    let root = terminal_original_key_obligation(&actual.ack);
    assert!(actual
        .io
        .inspect(
            &mut true,
            &actual.record,
            &actual.binding,
            Some(&actual.ack),
            41
        )
        .is_err());
    actual.shared.borrow_mut().lock_valid = true;
    assert!(actual
        .io
        .inspect(
            &mut true,
            &actual.record,
            &actual.binding,
            Some(&actual.ack),
            42
        )
        .is_err());
    root.verify_original(&actual.ack).unwrap();
    assert!(root.require_root_absent().is_err());
}

#[test]
fn equal_context_foreign_new_ack_cannot_replace_original_key_root_obligation() {
    // Break: authorizing a matching GUID/context/raw handle rather than the
    // original CREATED_NEW invocation's opaque retained Rc.
    let left = restore_original_before_nic(Role::RoleCarrier, |_, _| {});
    let right = restore_original_before_nic(Role::RoleCarrier, |_, _| {});
    assert_eq!(
        left.ack.retained_handle().handle(),
        right.ack.retained_handle().handle()
    );
    let pin = terminal_original_key_obligation(&left.ack);
    assert!(pin.verify_original(&right.ack).is_err());
    assert!(!Rc::ptr_eq(
        &pin,
        &terminal_original_key_obligation(&right.ack)
    ));
    assert!(pin.closed_handle_ack().is_err());
    assert!(pin.require_root_absent().is_err());
}

#[test]
fn lost_or_unwound_value_confirmation_keeps_original_obligation_unknown() {
    // Break: retry/readback rearms a failed value effect, discards its original
    // handle, or creates a key-root absence certificate from current bytes.
    for unwind in [false, true] {
        let (mut io, shared) = setup();
        let mut record = pending();
        let binding = record.context.bindings[0].clone();
        let facts = io.inspect(&mut true, &record, &binding, None, 1).unwrap();
        let ack = io
            .create_new_key(&mut true, &record, &binding, &facts)
            .unwrap();
        let pin = terminal_original_key_obligation(&ack);
        record.keys[0].new_key_ack = true;
        record.keys[0].phase = KeyPhase::DisablePending;
        record.keys[0].pending = Some(Value::DwordZero);
        let facts = io
            .inspect(&mut true, &record, &binding, Some(&ack), 2)
            .unwrap();
        shared.borrow_mut().panic_after_write = unwind;
        shared.borrow_mut().fail_flush = !unwind;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            io.compare_exchange_value(
                &mut true,
                &record,
                &binding,
                &ack,
                &facts,
                ValueCas {
                    expected: Value::Absent,
                    desired: Value::DwordZero,
                    value_name: VALUE,
                },
            )
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        shared.borrow_mut().panic_after_write = false;
        shared.borrow_mut().fail_flush = false;
        assert_eq!(
            pin.classification(),
            KeyRootObligationKind::UncertainOriginalKeyRoot
        );
        pin.verify_original(&ack).unwrap();
        assert!(io
            .inspect(&mut true, &record, &binding, Some(&ack), 3)
            .is_err());
        assert!(pin.require_root_absent().is_err());
        assert_eq!(shared.borrow().writes, 1);
    }
}

#[test]
fn actual_created_ack_before_failed_postflight_keeps_only_unknown_owning_floor() {
    // Break: dropping the real CREATED_NEW handle after capture flush failure,
    // or upgrading its owning obligation to an acknowledged durable receipt.
    let (mut io, shared) = setup();
    let record = pending();
    let binding = record.context.bindings[0].clone();
    let facts = io.inspect(&mut true, &record, &binding, None, 1).unwrap();
    shared.borrow_mut().fail_flush = true;
    assert!(io
        .create_new_key(&mut true, &record, &binding, &facts)
        .is_err());
    let pin = io.pending_original_key_obligation().unwrap();
    assert_eq!(
        pin.classification(),
        KeyRootObligationKind::UncertainOriginalKeyRoot
    );
    assert!(pin.require_root_absent().is_err());
    assert!(pin.closed_handle_ack().is_err());
    assert_eq!(shared.borrow().path, Some(11));
    shared.borrow_mut().fail_flush = false;
    assert!(io
        .create_new_key(&mut true, &record, &binding, &facts)
        .is_err());
    assert!(Rc::ptr_eq(
        &pin,
        &io.pending_original_key_obligation().unwrap()
    ));
}

#[test]
fn unknown_or_existing_native_create_result_cannot_mint_key_obligation() {
    // Break: constructor/adoption from present matching registry bytes when
    // CREATED_NEW's actual returned handle/disposition was not acknowledged.
    for lost in [false, true] {
        let (mut io, shared) = setup();
        let record = pending();
        let binding = record.context.bindings[0].clone();
        let facts = io.inspect(&mut true, &record, &binding, None, 1).unwrap();
        shared.borrow_mut().create_result_lost = lost;
        shared.borrow_mut().force_existing = !lost;
        assert!(io
            .create_new_key(&mut true, &record, &binding, &facts)
            .is_err());
        assert!(shared.borrow().path.is_some());
        assert!(io.pending_original_key_obligation().is_err());
        assert!(io
            .create_new_key(&mut true, &record, &binding, &facts)
            .is_err());
        assert_eq!(shared.borrow().next, 11);
    }
}

#[test]
fn actual_close_ack_is_retained_on_owning_floor_before_failed_or_unwound_postflight() {
    // Break: dropping a closed HKEY again after postflight failure, or promoting
    // its independently captured close ACK to registry-root deletion/absence.
    for unwind in [false, true] {
        let (_, shared) = setup();
        let closes = Rc::new(std::cell::Cell::new(0));
        let mut io = Keys::new(
            DropTrackedKernel {
                registry: Kernel(shared.clone()),
                closes: closes.clone(),
                track_created_parent: true,
            },
            Authority(shared.clone()),
            context(),
        );
        let record = pending();
        let binding = record.context.bindings[0].clone();
        let facts = io.inspect(&mut true, &record, &binding, None, 1).unwrap();
        let ack = io
            .create_new_key(&mut true, &record, &binding, &facts)
            .unwrap();
        let pin = terminal_original_key_obligation(&ack);
        let native = ack.retained_handle().handle();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            native.close.run(
                || Ok(()),
                || {
                    closes.set(closes.get() + 1);
                    Ok(())
                },
                |ack| pin.record_closed_handle_ack(ack, |h, ack| h.close.verify_ack(ack)),
                || {
                    if unwind {
                        panic!("terminal_postflight_unwind")
                    } else {
                        Err(Error::Conflict)
                    }
                },
            )
        }));
        assert!(outcome.is_err() || outcome.unwrap().is_err());
        assert_eq!(
            pin.classification(),
            KeyRootObligationKind::OriginalHandleClosedRootRetained
        );
        native
            .close
            .verify_ack(&pin.closed_handle_ack().unwrap())
            .unwrap();
        assert!(pin.require_root_absent().is_err());
        assert!(!pin.parent_handle().close.was_attempted());
        assert!(native
            .close
            .run(
                || Ok(()),
                || {
                    closes.set(closes.get() + 1);
                    Ok(())
                },
                |_| Ok(()),
                || Ok(())
            )
            .is_err());
        assert_eq!(closes.get(), 1);
        drop(ack);
        drop(pin); // actual acknowledged-close wrapper Drop is inert
        drop(io);
        assert_eq!(closes.get(), 1);
        assert_eq!(shared.borrow().path, Some(11));
    }
}

#[test]
fn foreign_close_ack_does_not_clear_original_key_obligation() {
    // Break: using any equal-looking close receipt to disarm an original handle.
    let original = restore_original_before_nic(Role::RoleCarrier, |_, _| {});
    let pin = terminal_original_key_obligation(&original.ack);
    let own_close = KeyHandleClose::new();
    let foreign_close = KeyHandleClose::new();
    foreign_close
        .run(|| Ok(()), || Ok(()), |_| Ok(()), || Ok(()))
        .unwrap();
    assert!(pin
        .record_closed_handle_ack(foreign_close.read_ack().unwrap(), |_, ack| own_close
            .verify_ack(ack))
        .is_err());
    assert!(pin.closed_handle_ack().is_err());
    assert_eq!(
        pin.classification(),
        KeyRootObligationKind::ValueRestoreObservedRootRetained
    );
    assert!(pin.require_root_absent().is_err());
}

#[test]
fn deleted_or_renamed_handle_and_path_replacement_grant_no_value_effect() {
    for mode in 0..3 {
        let (mut io, s) = setup();
        let mut r = pending();
        let b = r.context.bindings[0].clone();
        let f = io.inspect(&mut true, &r, &b, None, 1).unwrap();
        let ack = io.create_new_key(&mut true, &r, &b, &f).unwrap();
        r.keys[0].new_key_ack = true;
        r.keys[0].phase = KeyPhase::DisablePending;
        r.keys[0].pending = Some(Value::DwordZero);
        {
            let mut state = s.borrow_mut();
            match mode {
                0 => state.deleted = true,
                1 => {
                    state.names.insert(11, format!("{NATIVE_PARENT}\\renamed"));
                }
                _ => {
                    state.path = Some(12);
                    state.names.insert(12, format!("{NATIVE_PARENT}\\foreign"));
                    state.values.insert(12, NativeValue::Absent);
                }
            }
        }
        assert!(io.inspect(&mut true, &r, &b, Some(&ack), 2).is_err());
        assert_eq!(s.borrow().writes, 0);
    }
}
#[test]
fn existing_create_disposition_is_not_adopted() {
    let (mut io, s) = setup();
    s.borrow_mut().force_existing = true;
    let r = pending();
    let b = r.context.bindings[0].clone();
    let f = io.inspect(&mut true, &r, &b, None, 1).unwrap();
    assert!(io.create_new_key(&mut true, &r, &b, &f).is_err());
    assert_eq!(s.borrow().writes, 0);
}
#[test]
fn only_exact_native_dword_can_be_interpreted_as_zero() {
    assert_eq!(
        decode_value(4, &[0, 0, 0, 0]).unwrap(),
        NativeValue::Dword(0)
    );
    assert_eq!(
        decode_value(4, &[1, 0, 0, 0]).unwrap(),
        NativeValue::Dword(1)
    );
    for (kind, b) in [(1, vec![0, 0, 0, 0]), (4, vec![0, 0]), (4, vec![0; 8])] {
        assert_eq!(
            decode_value(kind, &b).unwrap(),
            NativeValue::Other { kind, bytes: b }
        );
    }
    assert!(decode_value(4, &[0; 257]).is_err());
}
#[test]
fn lost_flush_cannot_be_converted_to_live_authority_by_readback() {
    let (mut io, s) = setup();
    let mut r = pending();
    let b = r.context.bindings[0].clone();
    let f = io.inspect(&mut true, &r, &b, None, 1).unwrap();
    let ack = io.create_new_key(&mut true, &r, &b, &f).unwrap();
    r.keys[0].new_key_ack = true;
    r.keys[0].phase = KeyPhase::DisablePending;
    r.keys[0].pending = Some(Value::DwordZero);
    let f = io.inspect(&mut true, &r, &b, Some(&ack), 2).unwrap();
    s.borrow_mut().fail_flush = true;
    assert!(io
        .compare_exchange_value(
            &mut true,
            &r,
            &b,
            &ack,
            &f,
            ValueCas {
                expected: Value::Absent,
                desired: Value::DwordZero,
                value_name: VALUE
            }
        )
        .is_err());
    assert_eq!(s.borrow().writes, 1);
    s.borrow_mut().fail_flush = false;
    assert!(io.inspect(&mut true, &r, &b, Some(&ack), 3).is_err());
}
#[test]
fn actual_lock_native_absence_context_and_pending_value_are_required() {
    for mode in 0..4 {
        let (mut io, s) = setup();
        let mut r = pending();
        let b = r.context.bindings[0].clone();
        let f = io.inspect(&mut true, &r, &b, None, 1).unwrap();
        let ack = io.create_new_key(&mut true, &r, &b, &f).unwrap();
        r.keys[0].new_key_ack = true;
        r.keys[0].phase = KeyPhase::DisablePending;
        r.keys[0].pending = Some(Value::DwordZero);
        let f = io.inspect(&mut true, &r, &b, Some(&ack), 2).unwrap();
        match mode {
            0 => s.borrow_mut().lock_valid = false,
            1 => s.borrow_mut().nic = true,
            2 => r.context.provenance.network_epoch += 1,
            _ => r.keys[0].pending = Some(Value::Absent),
        }
        assert!(io
            .compare_exchange_value(
                &mut true,
                &r,
                &b,
                &ack,
                &f,
                ValueCas {
                    expected: Value::Absent,
                    desired: Value::DwordZero,
                    value_name: VALUE
                }
            )
            .is_err());
        assert_eq!(s.borrow().writes, 0);
    }
}

// OPT-IN external SDK contract measurements ONLY. Never called by production,
// never touch HKLM/Interfaces, never mint a carrier/KEY-delete/module grant.
// A failing measurement retains the exact HKCU test key; no cleanup-by-lookup,
// recursive delete, implicit Drop retry or fallback deletion exists.
#[test]
fn relative_txr_stage_retains_actual_handle_bound_ack_before_failed_postflight() {
    use super::relative_txr_probe::{Capsule, Phase};
    let io = RelativeRegistry::default();
    let native = io.0.clone();
    let mut rooted = None;
    Capsule::capture_into(&mut rooted, io).unwrap();
    let original = rooted.unwrap();
    let binding = original.binding().unwrap();
    let mut stage_ack = None;
    let result = original.stage(
        &binding,
        |ack| {
            stage_ack = Some(ack);
            Ok(())
        },
        || Err(Error::Conflict),
    );
    assert!(result.is_err());
    // Only the external registry syscall is doubled: the capsule must invoke
    // delete on its actual derived handle, root the real ACK, then fail closed.
    assert_eq!(native.borrow().deleted_handles, vec![11]);
    let retained = stage_ack.expect("actual NtDeleteKey stage ACK must survive postflight failure");
    original.verify_ack(Phase::Stage, &retained).unwrap();
    assert!(original.stage(&binding, |_| Ok(()), || Ok(())).is_err());
}

#[derive(Default)]
struct RelativeRegistry(std::rc::Rc<std::cell::RefCell<RelativeRegistryState>>);
#[derive(Default)]
struct RelativeRegistryState {
    deleted_handles: Vec<u64>,
    commits: usize,
    rollbacks: usize,
    closed: Vec<u64>,
    values: u32,
    subkeys: u32,
    fault_stage: u8,
    fault_commit: bool,
    fault_rollback: bool,
    fault_capture: bool,
    captures: usize,
    fault_close: Option<u64>,
    absent: bool,
    drops: usize,
}
// IO boundary only. The real capsule owns capture, origin checks, effect
// latches, ACK retention and sticky failure, not this external registry double.
unsafe impl super::relative_txr_probe::Kernel for RelativeRegistry {
    type Key = u64;
    type Transaction = u64;
    fn create_original(&mut self) -> Result<u64> {
        let mut io = self.0.borrow_mut();
        io.captures += 1;
        if io.fault_capture {
            Err(Error::Native)
        } else {
            Ok(10)
        }
    }
    fn metadata(&mut self, key: &u64) -> Result<super::relative_txr_probe::Metadata> {
        assert!([10, 11].contains(key));
        Ok(super::relative_txr_probe::Metadata {
            name: "HKCU\\Software\\OwnProbe".into(),
            class: "".into(),
            subkeys: self.0.borrow().subkeys,
            values: self.0.borrow().values,
            last_write: (7, 9),
            security: vec![1, 2, 3],
        })
    }
    fn begin(&mut self) -> Result<u64> {
        Ok(20)
    }
    fn derive_empty(&mut self, original: &u64, transaction: &u64) -> Result<u64> {
        assert_eq!((*original, *transaction), (10, 20));
        Ok(11)
    }
    fn delete_derived(&mut self, derived: &u64, transaction: &u64) -> Result<()> {
        assert_eq!((*derived, *transaction), (11, 20));
        self.0.borrow_mut().deleted_handles.push(*derived);
        let fault = self.0.borrow().fault_stage;
        match fault {
            1 => Err(Error::Native),
            2 => panic!("lost stage return"),
            _ => Ok(()),
        }
    }
    fn commit(&mut self, tx: &u64) -> Result<()> {
        assert_eq!(*tx, 20);
        let mut io = self.0.borrow_mut();
        io.commits += 1;
        if io.fault_commit {
            return Err(Error::Native);
        }
        io.absent = true;
        Ok(())
    }
    fn rollback(&mut self, tx: &u64) -> Result<()> {
        assert_eq!(*tx, 20);
        let mut io = self.0.borrow_mut();
        io.rollbacks += 1;
        if io.fault_rollback {
            Err(Error::Native)
        } else {
            Ok(())
        }
    }
    fn close_key(&mut self, key: &u64) -> Result<()> {
        self.close(*key)
    }
    fn close_transaction(&mut self, tx: &u64) -> Result<()> {
        self.close(*tx)
    }
    fn close_parent(&mut self) -> Result<()> {
        self.close(30)
    }
    fn probe_path_absent(&mut self) -> Result<bool> {
        Ok(self.0.borrow().absent)
    }
}
impl RelativeRegistry {
    fn close(&mut self, handle: u64) -> Result<()> {
        let mut io = self.0.borrow_mut();
        io.closed.push(handle);
        if io.fault_close == Some(handle) {
            Err(Error::Native)
        } else {
            Ok(())
        }
    }
}
impl Drop for RelativeRegistry {
    fn drop(&mut self) {
        self.0.borrow_mut().drops += 1;
    }
}

#[test]
fn relative_txr_ack_chain_is_same_original_one_shot_and_close_is_independent() {
    use super::relative_txr_probe::{Capsule, Phase};
    let io = RelativeRegistry::default();
    let native = io.0.clone();
    let mut root = None;
    Capsule::capture_into(&mut root, io).unwrap();
    let c = root.unwrap();
    let binding = c.binding().unwrap();
    assert!(c.commit(|_| Ok(()), || Ok(())).is_err());
    // Invalid ordering irreversibly stalls THIS capsule, not a grant/retry.
    assert!(c.stage(&binding, |_| Ok(()), || Ok(())).is_err());
    assert!(native.borrow().deleted_handles.is_empty());
    drop(c);
    assert_eq!(native.borrow().drops, 0);

    let io = RelativeRegistry::default();
    let native = io.0.clone();
    let mut root = None;
    Capsule::capture_into(&mut root, io).unwrap();
    let c = root.unwrap();
    let binding = c.binding().unwrap();
    let mut stage = None;
    c.stage(
        &binding,
        |ack| {
            stage = Some(ack);
            Ok(())
        },
        || Ok(()),
    )
    .unwrap();
    c.verify_ack(Phase::Stage, &stage.unwrap()).unwrap();
    c.commit(|_| Ok(()), || Ok(())).unwrap();
    assert!(c.measurement_complete().is_err());
    assert!(native.borrow().closed.is_empty());
    for phase in Phase::CLOSES {
        c.close(phase, |_| Ok(()), || Ok(())).unwrap();
    }
    c.measurement_complete().unwrap();
    assert_eq!(native.borrow().closed, vec![11, 10, 20, 30]);
    drop(c);
    assert_eq!(native.borrow().drops, 1);
}

#[test]
fn relative_txr_foreign_equal_binding_or_ack_cannot_replace_actual_capture() {
    use super::relative_txr_probe::{Capsule, Phase};
    let mut left = None;
    let mut right = None;
    let left_io = RelativeRegistry::default();
    let native = left_io.0.clone();
    Capsule::capture_into(&mut left, left_io).unwrap();
    Capsule::capture_into(&mut right, RelativeRegistry::default()).unwrap();
    let (a, b) = (left.unwrap(), right.unwrap());
    let mut ack = None;
    b.stage(
        &b.binding().unwrap(),
        |real| {
            ack = Some(real);
            Ok(())
        },
        || Ok(()),
    )
    .unwrap();
    assert!(a.verify_ack(Phase::Stage, &ack.unwrap()).is_err());
    assert!(a
        .stage(&b.binding().unwrap(), |_| Ok(()), || Ok(()))
        .is_err());
    assert!(native.borrow().deleted_handles.is_empty());
}

#[test]
fn relative_txr_foreign_value_or_subkey_before_stage_denies_without_delete() {
    use super::relative_txr_probe::Capsule;
    for subkey in [false, true] {
        let io = RelativeRegistry::default();
        let native = io.0.clone();
        let mut root = None;
        Capsule::capture_into(&mut root, io).unwrap();
        if subkey {
            native.borrow_mut().subkeys = 1;
        } else {
            native.borrow_mut().values = 1;
        }
        let c = root.unwrap();
        assert!(c
            .stage(&c.binding().unwrap(), |_| Ok(()), || Ok(()))
            .is_err());
        assert!(native.borrow().deleted_handles.is_empty());
        c.rollback(|_| Ok(()), || Ok(())).unwrap();
        assert!(c.measurement_complete().is_err());
    }
}

#[test]
fn relative_txr_lost_or_unwound_stage_return_never_mints_ack_or_retries() {
    use super::relative_txr_probe::{Capsule, Phase};
    for fault in [1, 2] {
        let io = RelativeRegistry::default();
        let native = io.0.clone();
        let mut root = None;
        Capsule::capture_into(&mut root, io).unwrap();
        native.borrow_mut().fault_stage = fault;
        let c = root.unwrap();
        let binding = c.binding().unwrap();
        let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            c.stage(&binding, |_| Ok(()), || Ok(()))
        }));
        assert!(matches!(first, Err(_) | Ok(Err(_))));
        assert!(c.read_ack(Phase::Stage).is_err());
        native.borrow_mut().fault_stage = 0;
        assert!(c.stage(&binding, |_| Ok(()), || Ok(())).is_err());
        assert_eq!(native.borrow().deleted_handles, vec![11]);
        c.rollback(|_| Ok(()), || Ok(())).unwrap();
        assert!(c.commit(|_| Ok(()), || Ok(())).is_err());
    }
}

#[test]
fn relative_txr_commit_ack_survives_callback_unwind_without_whole_measurement() {
    use super::relative_txr_probe::{Capsule, Phase};
    let io = RelativeRegistry::default();
    let native = io.0.clone();
    let mut root = None;
    Capsule::capture_into(&mut root, io).unwrap();
    let c = root.unwrap();
    c.stage(&c.binding().unwrap(), |_| Ok(()), || Ok(()))
        .unwrap();
    let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        c.commit(|_| panic!("caller after real commit"), || Ok(()))
    }));
    assert!(first.is_err());
    c.read_ack(Phase::Commit).unwrap();
    assert!(c.commit(|_| Ok(()), || Ok(())).is_err());
    assert!(c.rollback(|_| Ok(()), || Ok(())).is_err());
    for phase in Phase::CLOSES {
        c.close(phase, |_| Ok(()), || Ok(())).unwrap();
    }
    assert_eq!(native.borrow().commits, 1);
    assert!(c.measurement_complete().is_err());
}

#[test]
fn relative_txr_partial_close_and_caught_reentry_keep_inert_release_denied() {
    use super::relative_txr_probe::{Capsule, Phase};
    let io = RelativeRegistry::default();
    let native = io.0.clone();
    let mut root = None;
    Capsule::capture_into(&mut root, io).unwrap();
    let c = root.unwrap();
    let binding = c.binding().unwrap();
    assert!(c
        .stage(
            &binding,
            |_| {
                assert!(c.stage(&binding, |_| Ok(()), || Ok(())).is_err());
                Ok(())
            },
            || Ok(())
        )
        .is_err());
    c.read_ack(Phase::Stage).unwrap();
    assert!(c.commit(|_| Ok(()), || Ok(())).is_err());
    c.rollback(|_| Ok(()), || Ok(())).unwrap();
    native.borrow_mut().fault_close = Some(10);
    c.close(Phase::CloseDerived, |_| Ok(()), || Ok(())).unwrap();
    assert!(c
        .close(Phase::CloseOriginal, |_| Ok(()), || Ok(()))
        .is_err());
    assert!(c.read_ack(Phase::CloseOriginal).is_err());
    native.borrow_mut().fault_close = None;
    assert!(c
        .close(Phase::CloseOriginal, |_| Ok(()), || Ok(()))
        .is_err());
    assert_eq!(native.borrow().closed, vec![11, 10]);
    drop(c);
    assert_eq!(native.borrow().drops, 0);
}

#[test]
fn relative_txr_unknown_commit_and_rollback_returns_never_become_absence_receipts() {
    use super::relative_txr_probe::{Capsule, Phase};
    let io = RelativeRegistry::default();
    let native = io.0.clone();
    let mut root = None;
    Capsule::capture_into(&mut root, io).unwrap();
    let c = root.unwrap();
    c.stage(&c.binding().unwrap(), |_| Ok(()), || Ok(()))
        .unwrap();
    native.borrow_mut().fault_commit = true;
    assert!(c.commit(|_| Ok(()), || Ok(())).is_err());
    assert!(c.read_ack(Phase::Commit).is_err());
    // A later externally absent observation is NOT a native commit receipt.
    native.borrow_mut().absent = true;
    native.borrow_mut().fault_commit = false;
    assert!(c.commit(|_| Ok(()), || Ok(())).is_err());
    native.borrow_mut().fault_rollback = true;
    assert!(c.rollback(|_| Ok(()), || Ok(())).is_err());
    assert!(c.read_ack(Phase::Rollback).is_err());
    native.borrow_mut().fault_rollback = false;
    assert!(c.rollback(|_| Ok(()), || Ok(())).is_err());
    assert!(c
        .close(Phase::CloseOriginal, |_| Ok(()), || Ok(()))
        .is_err());
    assert!(c.measurement_complete().is_err());
    assert_eq!((native.borrow().commits, native.borrow().rollbacks), (1, 1));
    assert!(native.borrow().closed.is_empty());
    drop(c);
    assert_eq!(native.borrow().drops, 0);
}

#[test]
fn relative_txr_capture_output_is_rooted_before_unknown_return_and_never_replaced() {
    use super::relative_txr_probe::Capsule;
    let io = RelativeRegistry::default();
    let native = io.0.clone();
    native.borrow_mut().fault_capture = true;
    let mut root = None;
    assert!(Capsule::capture_into(&mut root, io).is_err());
    let original = root.as_ref().unwrap().clone();
    assert!(original.binding().is_err());
    let replacement = RelativeRegistry::default();
    let replacement_io = replacement.0.clone();
    assert!(Capsule::capture_into(&mut root, replacement).is_err());
    assert!(std::rc::Rc::ptr_eq(&original, root.as_ref().unwrap()));
    assert_eq!(replacement_io.borrow().captures, 0);
    assert_eq!(native.borrow().captures, 1);
    drop(root);
    drop(original);
    assert_eq!(native.borrow().drops, 0);
}

#[test]
fn relative_txr_caught_early_terminal_read_reentry_cannot_complete_outer_stage() {
    use super::relative_txr_probe::{Capsule, Phase};
    let mut root = None;
    Capsule::capture_into(&mut root, RelativeRegistry::default()).unwrap();
    let c = root.unwrap();
    assert!(c
        .stage(
            &c.binding().unwrap(),
            |_| {
                assert!(c.measurement_complete().is_err()); // no close/commit facts yet
                Ok(()) // swallowing nested failure must not complete outer forward use
            },
            || Ok(())
        )
        .is_err());
    c.read_ack(Phase::Stage).unwrap(); // actual ACK remains only historical fact
    assert!(c.commit(|_| Ok(()), || Ok(())).is_err());
}

#[cfg(windows)]
mod txr_native_measurement {
    use super::super::relative_txr_probe as relative;
    use std::ptr;
    use windows_sys::{
        Wdk::System::Registry::{KeyNameInformation, NtDeleteKey, NtQueryKey},
        Win32::{
            Foundation::{
                CloseHandle, CompareObjectHandles, GetLastError, ERROR_FILE_NOT_FOUND,
                ERROR_TRANSACTIONAL_CONFLICT, FILETIME, HANDLE, NO_ERROR,
            },
            Security::{
                DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            },
            Storage::FileSystem::{CommitTransaction, CreateTransaction, RollbackTransaction},
            System::Registry::*,
        },
    };
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }
    fn name(h: HKEY) -> String {
        let mut bytes = [0u32; super::MAX_NAME / 4];
        let mut n = 0;
        assert_eq!(
            unsafe {
                NtQueryKey(
                    h,
                    KeyNameInformation,
                    bytes.as_mut_ptr().cast(),
                    super::MAX_NAME as u32,
                    &mut n,
                )
            },
            0
        );
        let data = unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast(), super::MAX_NAME) };
        super::decode_name(data, n as usize).unwrap()
    }
    #[derive(Debug, Eq, PartialEq)]
    struct Metadata {
        class: String,
        subkeys: u32,
        values: u32,
        last_write: (u32, u32),
        security: Vec<u8>,
    }
    fn metadata(h: HKEY) -> Metadata {
        let mut class = [0u16; 256];
        let mut len = class.len() as u32;
        let (mut subkeys, mut values) = (0, 0);
        let mut time = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        assert_eq!(
            unsafe {
                RegQueryInfoKeyW(
                    h,
                    class.as_mut_ptr(),
                    &mut len,
                    ptr::null(),
                    &mut subkeys,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut values,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut time,
                )
            },
            NO_ERROR
        );
        assert!((len as usize) < class.len());
        let mut security = [0u32; 1024];
        let mut size = std::mem::size_of_val(&security) as u32;
        assert_eq!(
            unsafe {
                RegGetKeySecurity(
                    h,
                    OWNER_SECURITY_INFORMATION
                        | GROUP_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION,
                    security.as_mut_ptr().cast(),
                    &mut size,
                )
            },
            NO_ERROR
        );
        assert!((size as usize) <= std::mem::size_of_val(&security));
        Metadata {
            class: String::from_utf16(&class[..len as usize]).unwrap(),
            subkeys,
            values,
            last_write: (time.dwLowDateTime, time.dwHighDateTime),
            security: unsafe {
                std::slice::from_raw_parts(security.as_ptr().cast::<u8>(), size as usize)
            }
            .to_vec(),
        }
    }
    // Caller-local owning slots exist before every effect. No native calls in
    // Drop; errors leave these original handles/obligations to the probe caller.
    struct Probe {
        parent: HKEY,
        original: HKEY,
        transactional: HKEY,
        transaction: HANDLE,
        child: Vec<u16>,
        expected: String,
        original_created: bool,
        staged: bool,
        stage_ack: bool,
        commit_attempted: bool,
        commit_ack: bool,
        rollback_ack: bool,
        close_attempted: [bool; 4],
        close_ack: [bool; 4],
    }
    impl Probe {
        fn create() -> Self {
            let mut p = Self::uncreated();
            p.create_native();
            p
        }
        fn uncreated() -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let child = format!("Nelomai-Carrier-TxR-{}-{nonce}", std::process::id());
            let p = Self {
                parent: ptr::null_mut(),
                original: ptr::null_mut(),
                transactional: ptr::null_mut(),
                transaction: ptr::null_mut(),
                child: wide(&child),
                expected: String::new(),
                original_created: false,
                staged: false,
                stage_ack: false,
                commit_attempted: false,
                commit_ack: false,
                rollback_ack: false,
                close_attempted: [false; 4],
                close_ack: [false; 4],
            };
            eprintln!(
                "retained probe target HKCU\\Software\\{child}; failure NEVER deletes/retries it"
            );
            p
        }
        fn create_native(&mut self) {
            assert!(self.original.is_null() && self.parent.is_null());
            assert_eq!(
                unsafe {
                    RegOpenKeyExW(
                        HKEY_CURRENT_USER,
                        wide("Software").as_ptr(),
                        0,
                        KEY_ALL_ACCESS,
                        &mut self.parent,
                    )
                },
                NO_ERROR
            );
            self.expected = format!(
                "{}\\{}",
                name(self.parent),
                String::from_utf16(&self.child[..self.child.len() - 1]).unwrap()
            );
            let mut disposition = 0;
            let rc = unsafe {
                RegCreateKeyExW(
                    self.parent,
                    self.child.as_ptr(),
                    0,
                    ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_ALL_ACCESS,
                    ptr::null(),
                    &mut self.original,
                    &mut disposition,
                )
            };
            self.original_created = rc == NO_ERROR && disposition == REG_CREATED_NEW_KEY;
            assert_eq!(rc, NO_ERROR);
            assert_eq!(
                disposition, REG_CREATED_NEW_KEY,
                "collision/foreign key is never adopted/deleted"
            );
            assert_eq!(name(self.original), self.expected);
            assert_eq!(
                (
                    metadata(self.original).subkeys,
                    metadata(self.original).values
                ),
                (0, 0)
            );
        }
        fn begin(&mut self) {
            assert!(self.transaction.is_null());
            let original_metadata = metadata(self.original);
            assert_eq!(name(self.original), self.expected);
            self.transaction = unsafe {
                CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 5000, ptr::null())
            };
            assert!(!self.transaction.is_null() && self.transaction as isize != -1);
            // Test the user's original-HKEY-derived empty-subkey proposal first.
            assert_eq!(
                unsafe {
                    RegOpenKeyTransactedW(
                        self.original,
                        wide("").as_ptr(),
                        0,
                        KEY_ALL_ACCESS,
                        &mut self.transactional,
                        self.transaction,
                        ptr::null(),
                    )
                },
                NO_ERROR
            );
            assert_ne!(
                unsafe { CompareObjectHandles(self.original, self.transactional) },
                0,
                "original and TxR views MUST be actual SAME underlying object; no name fallback"
            );
            assert_eq!(name(self.transactional), self.expected);
            // No non-transacted original registry read inside the TxR window:
            // whether it would abort the transaction must not be assumed.
            assert_eq!(original_metadata, metadata(self.transactional));
            // Retained-parent/child lookup is independently checked against
            // that SAME original object before considering path-based staging.
            let mut by_child = ptr::null_mut();
            assert_eq!(
                unsafe {
                    RegOpenKeyTransactedW(
                        self.parent,
                        self.child.as_ptr(),
                        0,
                        KEY_ALL_ACCESS,
                        &mut by_child,
                        self.transaction,
                        ptr::null(),
                    )
                },
                NO_ERROR
            );
            assert_ne!(unsafe { CompareObjectHandles(self.original, by_child) }, 0);
            assert_eq!(metadata(by_child), metadata(self.transactional));
            assert_eq!(unsafe { RegCloseKey(by_child) }, NO_ERROR);
        }
        fn stage(&mut self) -> u32 {
            assert!(self.original_created && !self.staged && !self.commit_attempted);
            self.staged = true; // native error is never retried
            let rc = unsafe {
                RegDeleteKeyTransactedW(
                    self.parent,
                    self.child.as_ptr(),
                    0,
                    0,
                    self.transaction,
                    ptr::null(),
                )
            };
            self.stage_ack = rc == NO_ERROR; // factual ACK before caller assertions
            rc
        }
        fn commit(&mut self) -> bool {
            assert!(self.stage_ack && !self.commit_attempted);
            self.commit_attempted = true;
            let rc = unsafe { CommitTransaction(self.transaction) };
            self.commit_ack = rc != 0; // retain actual ACK BEFORE any read/assert
            self.commit_ack
        }
        fn close(&mut self) {
            for (index, raw) in [
                self.transactional,
                self.original,
                self.transaction,
                self.parent,
            ]
            .into_iter()
            .enumerate()
            {
                assert!(!self.close_attempted[index]);
                self.close_attempted[index] = true;
                let ok = if index == 2 {
                    unsafe { CloseHandle(raw) != 0 }
                } else {
                    unsafe { RegCloseKey(raw) == NO_ERROR }
                };
                self.close_ack[index] = ok; // independent real close ACK
                assert!(ok, "close ACK unknown: no retry");
            }
        }
        fn require_absent_after_closed_commit(&self) {
            assert!(self.commit_ack && self.close_ack.iter().all(|a| *a));
            let path = format!(
                "Software\\{}",
                String::from_utf16(&self.child[..self.child.len() - 1]).unwrap()
            );
            let mut observed = ptr::null_mut();
            let rc = unsafe {
                RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    wide(&path).as_ptr(),
                    0,
                    KEY_QUERY_VALUE,
                    &mut observed,
                )
            };
            if !observed.is_null() {
                assert_eq!(unsafe { RegCloseKey(observed) }, NO_ERROR);
            }
            assert_eq!(
                rc, ERROR_FILE_NOT_FOUND,
                "absence is separate from commit/close ACK"
            );
        }
    }

    #[derive(Clone, Copy)]
    enum RelativeRace {
        None,
        Value,
        Subkey,
        Namespace,
    }
    // Separate lane, never a replacement for Probe::begin's required kernel
    // object comparison. All actual native outputs live in these owning slots
    // BEFORE SDK checks/return conversion, including intentionally faulted IO.
    struct RelativeSlots {
        probe: Probe,
        race: RelativeRace,
        race_status: Option<u32>,
        replacement: HKEY,
        replacement_created: bool,
        replacement_metadata: Option<Metadata>,
        extra_subkey: HKEY,
        extra_subkey_created: bool,
        extra_closed: bool,
        stage_status: Option<i32>,
    }
    struct NativeRelativeIo(std::rc::Rc<std::cell::RefCell<RelativeSlots>>);
    fn native_status(status: u32) -> super::Result<()> {
        if status == NO_ERROR {
            Ok(())
        } else {
            Err(super::Error::Native)
        }
    }
    impl RelativeSlots {
        fn race_after_last_empty_read(&mut self) {
            assert!(self.race_status.is_none());
            self.race_status = Some(match self.race {
                RelativeRace::None => NO_ERROR,
                RelativeRace::Value => unsafe {
                    RegSetValueExW(
                        self.probe.original,
                        wide("OwnProbeExternalValue").as_ptr(),
                        0,
                        REG_DWORD,
                        17u32.to_le_bytes().as_ptr(),
                        4,
                    )
                },
                RelativeRace::Subkey => {
                    let mut disposition = 0;
                    let status = unsafe {
                        RegCreateKeyExW(
                            self.probe.original,
                            wide("OwnProbeExternalChild").as_ptr(),
                            0,
                            ptr::null(),
                            REG_OPTION_NON_VOLATILE,
                            KEY_ALL_ACCESS,
                            ptr::null(),
                            &mut self.extra_subkey,
                            &mut disposition,
                        )
                    };
                    self.extra_subkey_created =
                        status == NO_ERROR && disposition == REG_CREATED_NEW_KEY;
                    if status == NO_ERROR {
                        assert_eq!(
                            disposition, REG_CREATED_NEW_KEY,
                            "no foreign subkey adoption"
                        );
                    }
                    status
                }
                RelativeRace::Namespace => {
                    let renamed = format!(
                        "{}-renamed",
                        String::from_utf16(&self.probe.child[..self.probe.child.len() - 1])
                            .unwrap()
                    );
                    let status = unsafe {
                        RegRenameKey(
                            self.probe.parent,
                            self.probe.child.as_ptr(),
                            wide(&renamed).as_ptr(),
                        )
                    };
                    // Record rename result BEFORE the next fallible native call.
                    self.race_status = Some(status);
                    if status == NO_ERROR {
                        let mut disposition = 0;
                        let rc = unsafe {
                            RegCreateKeyExW(
                                self.probe.parent,
                                self.probe.child.as_ptr(),
                                0,
                                ptr::null(),
                                REG_OPTION_NON_VOLATILE,
                                KEY_ALL_ACCESS,
                                ptr::null(),
                                &mut self.replacement,
                                &mut disposition,
                            )
                        };
                        self.replacement_created =
                            rc == NO_ERROR && disposition == REG_CREATED_NEW_KEY;
                        assert_eq!(rc, NO_ERROR);
                        assert_eq!(
                            disposition, REG_CREATED_NEW_KEY,
                            "replacement never adopts an existing path"
                        );
                        assert_eq!(
                            unsafe { CompareObjectHandles(self.probe.original, self.replacement) },
                            0,
                            "replacement must not be original kernel object"
                        );
                        self.replacement_metadata = Some(metadata(self.replacement));
                    }
                    status
                }
            });
            eprintln!(
                "external own-HKCU interleave after LAST empty read: status={:?}",
                self.race_status
            );
        }
    }
    // SAFETY: this test-only adapter creates exclusively its own nonce HKCU
    // child, retains actual native outputs first, derives ONLY by NULL relative
    // subkey from that original HKEY, stages NtDeleteKey on that exact derived
    // HKEY and has no native Drop. TxR semantics remain a measurement, not an
    // assumption or a NativeOwnership issuer.
    unsafe impl relative::Kernel for NativeRelativeIo {
        type Key = HKEY;
        type Transaction = HANDLE;
        fn create_original(&mut self) -> super::Result<HKEY> {
            let mut s = self.0.borrow_mut();
            s.probe.create_native();
            assert!(s.probe.original_created);
            Ok(s.probe.original)
        }
        fn metadata(&mut self, key: &HKEY) -> super::Result<relative::Metadata> {
            let s = self.0.borrow();
            if *key != s.probe.original && *key != s.probe.transactional {
                return Err(super::Error::Conflict);
            }
            let m = metadata(*key);
            Ok(relative::Metadata {
                name: name(*key),
                class: m.class,
                subkeys: m.subkeys,
                values: m.values,
                last_write: m.last_write,
                security: m.security,
            })
        }
        fn begin(&mut self) -> super::Result<HANDLE> {
            let mut s = self.0.borrow_mut();
            assert!(s.probe.transaction.is_null());
            s.probe.transaction = unsafe {
                CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 5000, ptr::null())
            };
            if s.probe.transaction.is_null() || s.probe.transaction as isize == -1 {
                return Err(super::Error::Native);
            }
            Ok(s.probe.transaction)
        }
        fn derive_empty(&mut self, original: &HKEY, tx: &HANDLE) -> super::Result<HKEY> {
            let mut s = self.0.borrow_mut();
            assert_eq!((*original, *tx), (s.probe.original, s.probe.transaction));
            assert!(s.probe.original_created && s.probe.transactional.is_null());
            let status = unsafe {
                RegOpenKeyTransactedW(
                    *original,
                    ptr::null(),
                    0,
                    KEY_ALL_ACCESS,
                    &mut s.probe.transactional,
                    *tx,
                    ptr::null(),
                )
            };
            eprintln!("original-HKEY NULL-relative TxR open status={status}; no namespace lookup or CompareObjectHandles grant");
            native_status(status)?;
            if s.probe.transactional.is_null() || s.probe.transactional == *original {
                // Non-predefined CREATED_NEW original must produce a NEW view
                // handle. Never turn a special/predefined-handle result into
                // two independent aliases/close receipts.
                return Err(super::Error::Conflict);
            }
            Ok(s.probe.transactional)
        }
        fn delete_derived(&mut self, derived: &HKEY, tx: &HANDLE) -> super::Result<()> {
            let mut s = self.0.borrow_mut();
            assert_eq!(
                (*derived, *tx),
                (s.probe.transactional, s.probe.transaction)
            );
            assert!(s.probe.original_created && !s.probe.staged);
            s.probe.staged = true;
            // Intentional EXTERNAL race after capsule's last metadata/empty
            // read, not before it: tests the actual isolation/effect boundary.
            s.race_after_last_empty_read();
            let status = unsafe { NtDeleteKey(*derived) };
            s.stage_status = Some(status);
            s.probe.stage_ack = status == 0;
            eprintln!("handle-bound NtDeleteKey(TxR-derived original) NTSTATUS={status:#x}");
            if status == 0 {
                Ok(())
            } else {
                Err(super::Error::Native)
            }
        }
        fn commit(&mut self, tx: &HANDLE) -> super::Result<()> {
            let mut s = self.0.borrow_mut();
            assert_eq!(*tx, s.probe.transaction);
            if s.probe.commit() {
                eprintln!("actual native commit ACK");
                Ok(())
            } else {
                eprintln!("commit denied Win32={}", unsafe { GetLastError() });
                Err(super::Error::Native)
            }
        }
        fn rollback(&mut self, tx: &HANDLE) -> super::Result<()> {
            let mut s = self.0.borrow_mut();
            assert_eq!(*tx, s.probe.transaction);
            s.probe.rollback_ack = unsafe { RollbackTransaction(*tx) } != 0;
            eprintln!("actual rollback ACK={}", s.probe.rollback_ack);
            if s.probe.rollback_ack {
                Ok(())
            } else {
                Err(super::Error::Native)
            }
        }
        fn close_key(&mut self, key: &HKEY) -> super::Result<()> {
            let mut s = self.0.borrow_mut();
            let index = if *key == s.probe.transactional {
                0
            } else {
                assert_eq!(*key, s.probe.original);
                1
            };
            assert!(!s.probe.close_attempted[index]);
            s.probe.close_attempted[index] = true;
            let rc = unsafe { RegCloseKey(*key) };
            s.probe.close_ack[index] = rc == NO_ERROR;
            eprintln!(
                "RegCloseKey original slot{index} ACK={}",
                s.probe.close_ack[index]
            );
            native_status(rc)
        }
        fn close_transaction(&mut self, tx: &HANDLE) -> super::Result<()> {
            let mut s = self.0.borrow_mut();
            assert_eq!(*tx, s.probe.transaction);
            assert!(!s.probe.close_attempted[2]);
            s.probe.close_attempted[2] = true;
            s.probe.close_ack[2] = unsafe { CloseHandle(*tx) } != 0;
            if s.probe.close_ack[2] {
                Ok(())
            } else {
                Err(super::Error::Native)
            }
        }
        fn close_parent(&mut self) -> super::Result<()> {
            let mut s = self.0.borrow_mut();
            assert!(!s.probe.close_attempted[3]);
            s.probe.close_attempted[3] = true;
            let rc = unsafe { RegCloseKey(s.probe.parent) };
            s.probe.close_ack[3] = rc == NO_ERROR;
            native_status(rc)
        }
        fn probe_path_absent(&mut self) -> super::Result<bool> {
            self.0.borrow().probe.require_absent_after_closed_commit();
            Ok(true)
        }
    }
    fn relative_capture(
        race: RelativeRace,
    ) -> (
        std::rc::Rc<relative::Capsule<NativeRelativeIo>>,
        std::rc::Rc<std::cell::RefCell<RelativeSlots>>,
    ) {
        let slots = std::rc::Rc::new(std::cell::RefCell::new(RelativeSlots {
            probe: Probe::uncreated(),
            race,
            race_status: None,
            replacement: ptr::null_mut(),
            replacement_created: false,
            replacement_metadata: None,
            extra_subkey: ptr::null_mut(),
            extra_subkey_created: false,
            extra_closed: false,
            stage_status: None,
        }));
        let mut root = None;
        relative::Capsule::capture_into(&mut root, NativeRelativeIo(slots.clone())).unwrap();
        (root.unwrap(), slots)
    }
    fn relative_close(c: &relative::Capsule<NativeRelativeIo>) {
        for phase in relative::Phase::CLOSES {
            c.close(phase, |_| Ok(()), || Ok(())).unwrap();
        }
    }
    #[test]
    #[ignore = "Main-only fresh own HKCU: original-relative TxR + handle-bound NtDeleteKey; not production proof"]
    fn relative_txr_native_handle_delete_commit_and_independent_close() {
        let (c, slots) = relative_capture(RelativeRace::None);
        c.stage(&c.binding().unwrap(), |_| Ok(()), || Ok(()))
            .unwrap();
        c.commit(|_| Ok(()), || Ok(())).unwrap();
        assert_eq!(slots.borrow().probe.close_ack, [false; 4]);
        relative_close(&c);
        c.measurement_complete().unwrap();
    }
    fn relative_race_measurement(race: RelativeRace) {
        let (c, slots) = relative_capture(race);
        let stage = c.stage(&c.binding().unwrap(), |_| Ok(()), || Ok(()));
        let status = slots
            .borrow()
            .race_status
            .expect("actual external IO must execute after last empty read");
        if status == NO_ERROR {
            if stage.is_ok() {
                assert!(
                    c.commit(|_| Ok(()), || Ok(())).is_err(),
                    "accepted external change MUST NOT commit original deletion"
                );
            }
            c.rollback(|_| Ok(()), || Ok(())).unwrap();
            let mut s = slots.borrow_mut();
            match race {
                RelativeRace::Value => {
                    let (mut value, mut kind, mut len) = (0u32, 0, 4);
                    assert_eq!(
                        unsafe {
                            RegQueryValueExW(
                                s.probe.original,
                                wide("OwnProbeExternalValue").as_ptr(),
                                ptr::null(),
                                &mut kind,
                                (&mut value as *mut u32).cast(),
                                &mut len,
                            )
                        },
                        NO_ERROR
                    );
                    assert_eq!((kind, len, value), (REG_DWORD, 4, 17));
                }
                RelativeRace::Subkey => {
                    assert!(s.extra_subkey_created);
                    assert_eq!(metadata(s.probe.original).subkeys, 1);
                    assert_eq!(
                        name(s.extra_subkey),
                        format!("{}\\OwnProbeExternalChild", s.probe.expected)
                    );
                    s.extra_closed = unsafe { RegCloseKey(s.extra_subkey) } == NO_ERROR;
                    assert!(s.extra_closed);
                }
                RelativeRace::Namespace => {
                    assert!(s.replacement_created);
                    assert_eq!(
                        name(s.probe.original),
                        format!("{}-renamed", s.probe.expected)
                    );
                    assert_eq!(name(s.replacement), s.probe.expected);
                    assert_eq!(Some(metadata(s.replacement)), s.replacement_metadata);
                    s.extra_closed = unsafe { RegCloseKey(s.replacement) } == NO_ERROR;
                    assert!(s.extra_closed);
                }
                RelativeRace::None => panic!("not a fault measurement"),
            }
            drop(s);
            relative_close(&c);
            assert!(c.measurement_complete().is_err());
            eprintln!("accepted external change preserved after ACTUAL rollback; own probe keys retained, no delete retry");
        } else {
            assert_eq!(
                status, ERROR_TRANSACTIONAL_CONFLICT,
                "unexpected error is not isolation proof"
            );
            if stage.is_ok() {
                c.commit(|_| Ok(()), || Ok(())).unwrap();
                relative_close(&c);
                c.measurement_complete().unwrap();
            } else {
                c.rollback(|_| Ok(()), || Ok(())).unwrap();
                relative_close(&c);
                assert!(c.measurement_complete().is_err());
                eprintln!("external conflict aborted TxR; actual rollback ACK, original own empty probe key retained");
            }
        }
    }
    #[test]
    #[ignore = "Main-only own HKCU: nontransacted value interleave after last empty read"]
    fn relative_txr_native_external_value_after_empty_read_conflicts_or_rolls_back() {
        relative_race_measurement(RelativeRace::Value);
    }
    #[test]
    #[ignore = "Main-only own HKCU: nontransacted subkey interleave after last empty read"]
    fn relative_txr_native_external_subkey_after_empty_read_conflicts_or_rolls_back() {
        relative_race_measurement(RelativeRace::Subkey);
    }
    #[test]
    #[ignore = "Main-only own HKCU: rename/replacement interleave after last empty read"]
    fn relative_txr_native_namespace_after_empty_read_preserves_replacement() {
        relative_race_measurement(RelativeRace::Namespace);
    }

    #[test]
    #[ignore = "Main opt-in only: bounded own HKCU TxR measurement; never production authorization"]
    fn txr_native_same_object_commit_and_independent_close() {
        let mut p = Probe::create();
        // Real precreation value disable/restore; original key is still present.
        let value = wide(super::VALUE);
        assert_eq!(
            unsafe {
                RegSetValueExW(
                    p.original,
                    value.as_ptr(),
                    0,
                    REG_DWORD,
                    0u32.to_le_bytes().as_ptr(),
                    4,
                )
            },
            NO_ERROR
        );
        assert_eq!(
            unsafe { RegDeleteValueW(p.original, value.as_ptr()) },
            NO_ERROR
        );
        assert_eq!(metadata(p.original).values, 0);
        p.begin();
        assert_eq!(
            (
                metadata(p.transactional).subkeys,
                metadata(p.transactional).values
            ),
            (0, 0)
        );
        assert_eq!(p.stage(), NO_ERROR);
        assert!(p.commit(), "commit ACK missing; no absence adoption/retry");
        assert_eq!(
            p.close_ack, [false; 4],
            "delete/commit never closes original aliases implicitly"
        );
        p.close();
        p.require_absent_after_closed_commit();
    }

    #[test]
    #[ignore = "Main opt-in only: bounded own HKCU external-writer/TxR rollback measurement"]
    fn txr_native_external_value_write_conflicts_or_prevents_delete_commit() {
        let mut p = Probe::create();
        p.begin();
        let value = wide("OwnProbeExternalValue");
        let write = unsafe {
            RegSetValueExW(
                p.original,
                value.as_ptr(),
                0,
                REG_DWORD,
                17u32.to_le_bytes().as_ptr(),
                4,
            )
        };
        if write == NO_ERROR {
            let staged = p.stage();
            if staged == NO_ERROR {
                assert!(!p.commit(), "accepted external value was silently deleted");
            }
            p.rollback_ack = unsafe { RollbackTransaction(p.transaction) } != 0;
            assert!(
                p.rollback_ack,
                "rollback unacknowledged: retain all originals"
            );
            let mut actual = 0u32;
            let (mut kind, mut size) = (0, 4);
            assert_eq!(
                unsafe {
                    RegQueryValueExW(
                        p.original,
                        value.as_ptr(),
                        ptr::null(),
                        &mut kind,
                        (&mut actual as *mut u32).cast(),
                        &mut size,
                    )
                },
                NO_ERROR
            );
            assert_eq!((kind, size, actual), (REG_DWORD, 4, 17));
            assert_eq!(name(p.original), p.expected);
            // Retain the fault-test key/value. No second deletion/lookup or
            // cleanup permission is inferred from acknowledged rollback.
            p.close();
            eprintln!("accepted external value preserved; original HKCU test key retained, NOT retried/deleted");
        } else {
            assert_eq!(
                write,
                ERROR_TRANSACTIONAL_CONFLICT,
                "unexpected writer failure is not isolation proof: {}",
                unsafe { GetLastError() }
            );
            assert_eq!(p.stage(), NO_ERROR);
            assert!(p.commit());
            p.close();
            p.require_absent_after_closed_commit();
        }
    }

    #[test]
    #[ignore = "Main opt-in only: bounded own HKCU rename/replacement versus TxR measurement"]
    fn txr_native_namespace_replacement_cannot_commit_original_path_deletion() {
        let mut p = Probe::create();
        p.begin();
        let renamed = format!(
            "{}-renamed",
            String::from_utf16(&p.child[..p.child.len() - 1]).unwrap()
        );
        let rename = unsafe { RegRenameKey(p.parent, p.child.as_ptr(), wide(&renamed).as_ptr()) };
        if rename == NO_ERROR {
            let mut replacement = ptr::null_mut();
            let mut disposition = 0;
            assert_eq!(
                unsafe {
                    RegCreateKeyExW(
                        p.parent,
                        p.child.as_ptr(),
                        0,
                        ptr::null(),
                        REG_OPTION_NON_VOLATILE,
                        KEY_ALL_ACCESS,
                        ptr::null(),
                        &mut replacement,
                        &mut disposition,
                    )
                },
                NO_ERROR
            );
            assert_eq!(
                disposition, REG_CREATED_NEW_KEY,
                "replacement probe never adopts a foreign root"
            );
            assert_eq!(unsafe { CompareObjectHandles(p.original, replacement) }, 0);
            let replacement_before = metadata(replacement);
            let staged = p.stage();
            if staged == NO_ERROR {
                assert!(
                    !p.commit(),
                    "renamed original permitted deleting replacement path"
                );
            }
            p.rollback_ack = unsafe { RollbackTransaction(p.transaction) } != 0;
            assert!(p.rollback_ack, "rollback ACK missing; retain all roots");
            assert_eq!(name(p.original), format!("{}-renamed", p.expected));
            assert_eq!(name(replacement), p.expected);
            assert_eq!(metadata(replacement), replacement_before);
            assert_eq!(unsafe { RegCloseKey(replacement) }, NO_ERROR);
            p.close();
            eprintln!("original renamed/replacement HKCU fault keys preserved; no delete retry/lookup adoption");
        } else {
            assert_eq!(
                rename, ERROR_TRANSACTIONAL_CONFLICT,
                "unexpected rename failure is not isolation proof"
            );
            assert_eq!(p.stage(), NO_ERROR);
            assert!(p.commit());
            p.close();
            p.require_absent_after_closed_commit();
        }
    }
}
