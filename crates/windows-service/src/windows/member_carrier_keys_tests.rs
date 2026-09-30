// Standalone host harness: actual production receipt/identity/CAS logic,
// fake only the registry effects and independent native authority boundary.
#![cfg_attr(not(windows), allow(dead_code))]
#[cfg(not(windows))]
#[path = "../member_carrier.rs"]
mod member_carrier;
#[cfg(not(windows))]
#[path = "../member_carrier_native_ownership.rs"]
mod member_carrier_native_ownership;
#[cfg(not(windows))]
#[path = "../member_owner.rs"]
mod member_owner;
#[cfg(not(windows))]
mod redundancy {
    pub use nelomai_windows_service::redundancy::*;
}
#[cfg(not(windows))]
fn test_engine_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new("/trusted").join(name)
}
#[cfg(not(windows))]
#[path = "member_carrier_keys.rs"]
mod native;
#[cfg(windows)]
use super::*;
use crate::member_carrier::{CarrierError as Error, Result};
use crate::member_carrier_native_ownership::{
    Binding, Context, FullNativeRows, KeyPhase, KeyReceipt, NativeKeyIo, NativeValue, Phase,
    Record, Role, Value, ValueCas,
};
#[cfg(not(windows))]
use native::*;
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
    names: BTreeMap<u64, String>,
    path: Option<u64>,
    next: u64,
    writes: usize,
    fail_flush: bool,
    force_existing: bool,
    deleted: bool,
    nic: bool,
    lock_valid: bool,
    panic_after_write: bool,
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
        Ok((h, if s.force_existing { 2 } else { 1 }))
    }
    fn value(&mut self, h: &u64) -> Result<NativeValue> {
        let s = self.0.borrow();
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
