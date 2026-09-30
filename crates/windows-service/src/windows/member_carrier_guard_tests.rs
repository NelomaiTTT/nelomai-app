// Also a standalone host test crate: compile against the unchanged real portable
// modules and windows-sys ABI types. Native BFE calls are cfg(windows) only.
#![cfg_attr(not(windows), allow(dead_code))]
#[cfg(not(windows))]
#[path = "../member_carrier_guard.rs"]
mod member_carrier_guard;
#[cfg(not(windows))]
#[path = "../member_guard.rs"]
mod member_guard;
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
#[path = "member_carrier_guard.rs"]
mod native;
#[cfg(windows)]
use super::*;
use crate::{
    member_carrier_guard::{
        Action, Carrier, Filter, GuardError, Identity, Key, Layer, Member, Model, ProbeTuple,
        Result, SessionKind, SplitEngines, Sublayer,
    },
    member_owner::InterfaceProof,
};
#[cfg(not(windows))]
use native::*;
use nelomai_client_tunnel::redundancy::{SessionScope, Slot};
use nelomai_contracts::RuntimeSlot;
use std::ptr;
#[cfg(not(windows))]
use windows_sys::{core::GUID, Win32::NetworkManagement::WindowsFilteringPlatform::*};

fn scope() -> SessionScope {
    SessionScope {
        runtime: RuntimeSlot::Stable,
        runtime_generation: 7,
        session_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
        connection_generation: 9,
    }
}
fn identity(index: u32) -> Identity {
    Identity {
        scope: scope(),
        proof: InterfaceProof {
            index,
            luid: index as u64 * 100,
            guid: [index as u8; 16],
        },
    }
}
fn pair(active: Option<Slot>) -> Model {
    Model::new(
        scope(),
        Carrier {
            identity: identity(33),
            sources: vec!["10.8.0.2".parse().unwrap(), "fd00::2".parse().unwrap()],
        },
        [11, 22].map(|i| {
            Some(Member {
                identity: identity(i),
                probes: vec![
                    ProbeTuple {
                        source: "10.8.0.2".parse().unwrap(),
                        source_port: 40123 + i as u16,
                        target: "1.1.1.1".parse().unwrap(),
                        target_port: 53,
                        protocol: 17,
                    },
                    ProbeTuple {
                        source: "fd00::2".parse().unwrap(),
                        source_port: 40124 + i as u16,
                        target: "2606:4700:4700::1111".parse().unwrap(),
                        target_port: 53,
                        protocol: 17,
                    },
                ],
            })
        }),
        active,
    )
    .unwrap()
}
fn returned(filter: &Filter) -> EncodedFilter {
    let mut encoded = EncodedFilter::new(filter).unwrap();
    encoded.raw.filterId = 9001;
    encoded.raw.effectiveWeight = encoded.raw.weight;
    encoded
}
fn permit(layer: Layer) -> Filter {
    pair(None)
        .expected
        .filters
        .into_iter()
        .find(|f| {
            f.layer == layer
                && f.action == Action::Permit
                && f.conditions.iter().any(|c| {
                    matches!(
                        c,
                        crate::member_carrier_guard::Condition::EgressIndex(11)
                            | crate::member_carrier_guard::Condition::DestinationIndex(11)
                            | crate::member_carrier_guard::Condition::NextHopIndex(11)
                    )
                })
        })
        .unwrap()
}

#[test]
fn native_codec_roundtrips_real_full_four_layer_models_and_preserves_ids() {
    for active in [None, Some(Slot::A), Some(Slot::B)] {
        let model = pair(active);
        for filter in &model.expected.filters {
            let encoded = returned(filter);
            let got = unsafe { decode_filter(&encoded.raw, filter.key, filter.sublayer) }.unwrap();
            assert_eq!(got.policy, *filter);
            assert_eq!(got.id, 9001);
        }
    }
}

#[test]
fn native_codec_uses_literal_wfp_layer_fields_types_flags_and_eight_ale_conditions() {
    for (layer, layer_id, local_luid, count) in [
        (
            Layer::TransportV4,
            0x09e61aea_d214_46e2_9b21_b26b0b2f28c8u128,
            3300,
            8,
        ),
        (
            Layer::PacketV4,
            0x1e5c9fae_8a84_4135_a331_950b54229ecd,
            1100,
            4,
        ),
        (
            Layer::ForwardV4,
            0xa82acc24_4ee1_4ee1_b465_fd1d25cb10a4,
            3300,
            7,
        ),
        (
            Layer::AleConnectV4,
            0xc38d57d1_05a7_4c33_904f_7fbceee60e82,
            3300,
            8,
        ),
        (
            Layer::TransportV6,
            0xe1735bde_013f_4655_b351_a49e15762df0,
            3300,
            8,
        ),
        (
            Layer::PacketV6,
            0xa3b3ab6b_3564_488c_9117_f34e82142763,
            1100,
            4,
        ),
        (
            Layer::ForwardV6,
            0x7b964818_19c7_493a_b71f_832c3684d28c,
            3300,
            7,
        ),
        (
            Layer::AleConnectV6,
            0x4a72393b_319f_44bc_84c3_ba54dcb3b6b4,
            3300,
            8,
        ),
    ] {
        let filter = permit(layer);
        let encoded = returned(&filter);
        assert_eq!(key(encoded.raw.layerKey), Key(layer_id.to_be_bytes()));
        assert_eq!(encoded.raw.numFilterConditions, count);
        assert_eq!(
            encoded.raw.flags,
            if matches!(layer, Layer::AleConnectV4 | Layer::AleConnectV6) {
                64
            } else {
                0
            }
        );
        let conditions =
            unsafe { std::slice::from_raw_parts(encoded.raw.filterCondition, count as usize) };
        let local = conditions
            .iter()
            .find(|c| {
                key(c.fieldKey) == Key(0x4cd62a49_59c3_4969_b7f3_bda5d32890a4u128.to_be_bytes())
            })
            .unwrap();
        assert_eq!(local.conditionValue.r#type, 4); // FWP_UINT64 is a pointer, not inline integer.
        assert_eq!(
            unsafe { *local.conditionValue.Anonymous.uint64 },
            local_luid
        );
        if matches!(layer, Layer::ForwardV4 | Layer::ForwardV6) {
            assert!(conditions.iter().any(|c| key(c.fieldKey)
                == Key(0x1076b8a5_6323_4c5e_9810_e8d3fc9e6136u128.to_be_bytes())
                && unsafe { *c.conditionValue.Anonymous.uint64 } == 1100));
            assert!(conditions
                .iter()
                .any(|c| key(c.fieldKey) == key(FWPM_CONDITION_IP_SOURCE_ADDRESS)));
            assert!(conditions
                .iter()
                .any(|c| key(c.fieldKey) == key(FWPM_CONDITION_IP_DESTINATION_ADDRESS)));
        }
        if matches!(
            layer,
            Layer::ForwardV4 | Layer::TransportV4 | Layer::ForwardV6 | Layer::TransportV6
        ) {
            let flags = conditions
                .iter()
                .find(|c| key(c.fieldKey) == key(FWPM_CONDITION_FLAGS))
                .unwrap();
            assert_eq!(
                flags.matchType,
                if matches!(layer, Layer::ForwardV4 | Layer::ForwardV6) {
                    6
                } else {
                    8
                }
            );
            assert_eq!(
                unsafe { flags.conditionValue.Anonymous.uint32 },
                if matches!(layer, Layer::ForwardV4 | Layer::ForwardV6) {
                    0x40000
                } else {
                    0x10
                }
            );
        }
    }
}

#[test]
fn returned_metadata_is_strict_and_unknown_attributes_never_disappear_in_projection() {
    let filter = permit(Layer::AleConnectV6);
    for fault in 0..15 {
        let mut encoded = returned(&filter);
        let mut foreign = GUID::from_u128(42);
        match fault {
            0 => encoded.raw.flags |= 8,
            1 => encoded.raw.providerKey = &mut foreign,
            2 => encoded.raw.providerData.size = 1,
            3 => encoded.raw.providerData.data = ptr::dangling_mut(),
            4 => encoded.raw.reserved = &mut foreign,
            5 => encoded.raw.Anonymous.rawContext = 1,
            6 => encoded.raw.action.r#type = FWP_ACTION_CONTINUE,
            7 => encoded.raw.action.Anonymous.filterType = foreign,
            8 => encoded.raw.numFilterConditions = 9,
            9 => encoded.raw.filterCondition = ptr::null_mut(),
            10 => encoded.raw.weight.r#type = FWP_UINT8,
            11 => encoded.raw.effectiveWeight.r#type = FWP_EMPTY,
            12 => encoded.raw.filterId = 0,
            13 => encoded.raw.subLayerKey = foreign,
            _ => encoded.raw.layerKey = foreign,
        }
        assert!(
            unsafe { decode_filter(&encoded.raw, filter.key, filter.sublayer) }.is_err(),
            "metadata fault {fault}"
        );
    }
}

#[test]
fn native_sublayer_read_preserves_full_assigned_priority_and_rejects_foreign_metadata() {
    let sub = pair(None).expected.sublayer.unwrap();
    let mut name: Vec<_> = NAME.encode_utf16().chain(Some(0)).collect();
    let mut raw = FWPM_SUBLAYER0 {
        subLayerKey: guid(sub.key),
        weight: 65531,
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: ptr::null_mut(),
        },
        ..Default::default()
    };
    let actual = unsafe { decode_sublayer(&raw, sub.key) }.unwrap();
    assert_eq!(actual.weight, 65531);
    raw.flags = 1;
    assert!(unsafe { decode_sublayer(&raw, sub.key) }.is_err());
}

#[test]
fn native_abi_layout_has_x64_sdk_offsets_and_pointer_valued_union_sizes() {
    use std::mem::{align_of, offset_of, size_of};
    // Also evaluated by cargo check --target x86_64-pc-windows-msvc --tests;
    // runtime host assertions alone would not prove the target ABI layout.
    const {
        assert!(size_of::<FWPM_FILTER0>() == 200);
        assert!(align_of::<FWPM_FILTER0>() == 8);
        assert!(offset_of!(FWPM_FILTER0, filterCondition) == 120);
        assert!(offset_of!(FWPM_FILTER0, action) == 128);
        assert!(offset_of!(FWPM_FILTER0, filterId) == 176);
        assert!(offset_of!(FWPM_FILTER0, effectiveWeight) == 184);
        assert!(size_of::<FWPM_FILTER_CONDITION0>() == 40);
        assert!(size_of::<FWP_CONDITION_VALUE0>() == 16);
        assert!(size_of::<FWPM_SUBLAYER0>() == 72);
    }
    assert_eq!(
        (size_of::<FWPM_FILTER0>(), align_of::<FWPM_FILTER0>()),
        (200, 8)
    );
    assert_eq!(offset_of!(FWPM_FILTER0, filterCondition), 120);
    assert_eq!(offset_of!(FWPM_FILTER0, action), 128);
    assert_eq!(offset_of!(FWPM_FILTER0, filterId), 176);
    assert_eq!(offset_of!(FWPM_FILTER0, effectiveWeight), 184);
    assert_eq!(size_of::<FWPM_FILTER_CONDITION0>(), 40);
    assert_eq!(size_of::<FWP_CONDITION_VALUE0>(), 16);
    assert_eq!(size_of::<FWPM_SUBLAYER0>(), 72);
}

#[test]
fn native_forward_and_ale_conjunctions_use_header_literal_identity_fields_not_swapped_aliases() {
    for layer in [
        Layer::ForwardV4,
        Layer::ForwardV6,
        Layer::AleConnectV4,
        Layer::AleConnectV6,
    ] {
        let encoded = returned(&permit(layer));
        let raw = unsafe {
            std::slice::from_raw_parts(
                encoded.raw.filterCondition,
                encoded.raw.numFilterConditions as usize,
            )
        };
        let fields: Vec<_> = if matches!(layer, Layer::ForwardV4 | Layer::ForwardV6) {
            vec![
                (
                    0x35cf6522_4139_45ee_a0d5_67b80949d879u128,
                    FWP_UINT32,
                    11u64,
                ), // destination index
                (0x1076b8a5_6323_4c5e_9810_e8d3fc9e6136, FWP_UINT64, 1100), // destination LUID
                (0x2311334d_c92d_45bf_9496_edf447820e2d, FWP_UINT32, 33),   // source index
                (0x4cd62a49_59c3_4969_b7f3_bda5d32890a4, FWP_UINT64, 3300), // source LUID
            ]
        } else {
            vec![
                (
                    0x138e6888_7ab8_4d65_9ee8_0591bcf6a494u128,
                    FWP_UINT32,
                    11u64,
                ), // next-hop index
                (0x93ae8f5b_7f6f_4719_98c8_14e97429ef04, FWP_UINT64, 1100), // next-hop LUID
                (0x4cd62a49_59c3_4969_b7f3_bda5d32890a4, FWP_UINT64, 3300), // source-holder LUID
                (
                    0x0c1ba1af_5765_453f_af22_a8f791ac775b,
                    FWP_UINT16,
                    if layer == Layer::AleConnectV4 {
                        40134
                    } else {
                        40135
                    },
                ),
                (0xc35a604d_d22b_4e1a_91b4_68f674ee674b, FWP_UINT16, 53),
                (0x3971ef2b_623e_4f9a_8cb1_6e79b806b9a7, FWP_UINT8, 17),
            ]
        };
        for (field, kind, want) in fields {
            let c = raw
                .iter()
                .find(|c| key(c.fieldKey) == Key(field.to_be_bytes()))
                .unwrap();
            assert_eq!(c.matchType, 0);
            assert_eq!(c.conditionValue.r#type, kind);
            let got = unsafe {
                match kind {
                    FWP_UINT8 => c.conditionValue.Anonymous.uint8 as u64,
                    FWP_UINT16 => c.conditionValue.Anonymous.uint16 as u64,
                    FWP_UINT32 => c.conditionValue.Anonymous.uint32 as u64,
                    FWP_UINT64 => *c.conditionValue.Anonymous.uint64,
                    _ => unreachable!(),
                }
            };
            assert_eq!(got, want);
        }
    }
}

use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
#[derive(Clone, Default)]
struct Objects {
    sublayer: Option<Sublayer>,
    filters: BTreeMap<Key, (NativeFilter, SessionKind)>,
}
#[derive(Default)]
struct World {
    objects: Objects,
    staged: Option<Objects>,
    events: Vec<String>,
    lookups: Vec<Key>,
    next_id: u64,
    commit_fault: u8,
    read_fault: bool,
    close_fault: bool,
    abort_fault: bool,
    assigned: u16,
    binding_fault: u8,
    denied: bool,
    closed: [bool; 2],
    panic_authorize: bool,
    partial_add_at: Option<usize>,
    adds: usize,
}
struct Api(Rc<RefCell<World>>);
impl NativeApi for Api {
    fn begin(&mut self, kind: SessionKind, readonly: bool) -> Result<()> {
        let mut w = self.0.borrow_mut();
        assert!(w.staged.is_none());
        if w.closed[usize::from(kind == SessionKind::DynamicPermits)] {
            return Err(GuardError::Conflict);
        }
        w.events.push(format!("begin:{kind:?}:{readonly}"));
        w.staged = Some(w.objects.clone());
        Ok(())
    }
    fn commit(&mut self, kind: SessionKind) -> Result<()> {
        let mut w = self.0.borrow_mut();
        w.events.push(format!("commit:{kind:?}"));
        let fault = std::mem::take(&mut w.commit_fault);
        if fault != 1 && fault != 3 {
            w.objects = w.staged.take().unwrap();
        }
        if fault == 1 || fault == 2 {
            return Err(GuardError::Native(55));
        }
        w.staged = None;
        Ok(())
    }
    fn abort(&mut self, kind: SessionKind) -> Result<()> {
        let mut w = self.0.borrow_mut();
        w.events.push(format!("abort:{kind:?}"));
        let active = w.staged.take().is_some();
        if w.abort_fault || !active {
            Err(GuardError::Native(56))
        } else {
            Ok(())
        }
    }
    fn close(&mut self, kind: SessionKind) -> Result<()> {
        let mut w = self.0.borrow_mut();
        w.events.push(format!("close:{kind:?}"));
        if w.close_fault {
            return Err(GuardError::Native(57));
        }
        w.closed[usize::from(kind == SessionKind::DynamicPermits)] = true;
        if kind == SessionKind::DynamicPermits {
            w.objects.filters.retain(|_, (_, k)| *k != kind);
        }
        Ok(())
    }
    fn sublayer(&mut self, _: SessionKind, key: Key) -> Result<Option<Sublayer>> {
        let mut w = self.0.borrow_mut();
        w.lookups.push(key);
        if w.read_fault {
            return Err(GuardError::Native(58));
        }
        Ok(w.staged.as_ref().unwrap().sublayer.clone())
    }
    fn filter(&mut self, _: SessionKind, key: Key, _: Key) -> Result<Option<NativeFilter>> {
        let mut w = self.0.borrow_mut();
        w.lookups.push(key);
        Ok(w.staged
            .as_ref()
            .unwrap()
            .filters
            .get(&key)
            .map(|(f, _)| f.clone()))
    }
    fn add_sublayer(&mut self, sub: &Sublayer) -> Result<()> {
        let mut w = self.0.borrow_mut();
        w.events.push("add:base".into());
        let weight = w.assigned;
        let state = w.staged.as_mut().unwrap();
        if state.sublayer.is_some() {
            return Err(GuardError::Conflict);
        }
        let mut sub = sub.clone();
        sub.weight = weight;
        state.sublayer = Some(sub);
        Ok(())
    }
    fn delete_sublayer(&mut self, key: Key) -> Result<()> {
        let mut w = self.0.borrow_mut();
        let state = w.staged.as_mut().unwrap();
        if state.sublayer.as_ref().map(|s| s.key) != Some(key) || !state.filters.is_empty() {
            return Err(GuardError::Conflict);
        }
        state.sublayer = None;
        Ok(())
    }
    fn add_filter(&mut self, kind: SessionKind, filter: &Filter) -> Result<u64> {
        let mut w = self.0.borrow_mut();
        w.next_id += 1;
        let id = w.next_id;
        let mut raw = returned(filter);
        raw.raw.filterId = id;
        let actual = unsafe { decode_filter(&raw.raw, filter.key, filter.sublayer) }?;
        let state = w.staged.as_mut().unwrap();
        if state.filters.contains_key(&filter.key) {
            return Err(GuardError::Conflict);
        }
        state.filters.insert(filter.key, (actual, kind));
        w.events.push(format!("add:{kind:?}"));
        w.adds += 1;
        if w.partial_add_at == Some(w.adds) {
            return Err(GuardError::Native(59));
        }
        Ok(id)
    }
    fn delete_filter(&mut self, kind: SessionKind, key: Key) -> Result<()> {
        let mut w = self.0.borrow_mut();
        let state = w.staged.as_mut().unwrap();
        if state.filters.get(&key).map(|(_, k)| *k) != Some(kind) {
            return Err(GuardError::Conflict);
        }
        state.filters.remove(&key);
        w.events.push(format!("delete:{kind:?}"));
        Ok(())
    }
}
struct Attestor(Rc<RefCell<World>>);
impl BindingAttestor for Attestor {
    fn observe(&mut self, s: &SessionScope) -> Result<Bindings> {
        let mut w = self.0.borrow_mut();
        assert!(w.staged.is_some());
        w.events.push("attest".into());
        let model = pair(None);
        let mut c = model.carrier.unwrap();
        let mut e = model.members.map(|m| m.map(|m| m.identity));
        let mut scope = s.clone();
        match w.binding_fault {
            1 => c.identity.proof.guid = [99; 16],
            2 => c.sources = vec!["10.8.0.3".parse().unwrap()],
            3 => e[0].as_mut().unwrap().proof.guid = [98; 16],
            4 => scope.runtime_generation += 1,
            5 => return Err(GuardError::Conflict),
            7 => {
                return Ok(Bindings {
                    scope,
                    carrier: None,
                    egress: e,
                })
            }
            8 => e[0] = None,
            9 => c.identity.scope.connection_generation += 1,
            10 => c.identity.proof.luid += 1,
            11 => c.identity.proof.index = 11,
            12 => e[1].as_mut().unwrap().proof.guid = [97; 16],
            _ => {}
        }
        Ok(Bindings {
            scope,
            carrier: Some(c),
            egress: e,
        })
    }
    fn authorize(&mut self, kind: SessionKind, expected: &Model, desired: &Model) -> Result<()> {
        let mut w = self.0.borrow_mut();
        assert!(w.staged.is_some());
        w.events.push(format!("authorize:{kind:?}"));
        assert!(!w.panic_authorize, "injected authority unwind");
        if w.denied {
            return Err(GuardError::Conflict);
        }
        if desired.permits && !expected.permits {
            assert!(w
                .staged
                .as_ref()
                .unwrap()
                .filters
                .values()
                .all(|(f, _)| f.policy.action == Action::Block));
        }
        Ok(())
    }
}
fn adapter() -> (NativeGuard<Api, Attestor>, Rc<RefCell<World>>) {
    let world = Rc::new(RefCell::new(World {
        assigned: 65531,
        next_id: 100,
        ..Default::default()
    }));
    (
        NativeGuard::fresh(scope(), Api(world.clone()), Attestor(world.clone())).unwrap(),
        world,
    )
}
fn base(guard: &mut NativeGuard<Api, Attestor>) -> Model {
    let empty = Model::empty(scope()).unwrap();
    let desired = pair(Some(Slot::A)).without_permits().unwrap();
    guard
        .exchange(SessionKind::StaticBase, &empty, &desired)
        .unwrap()
}

#[test]
fn adapter_captures_full_creation_priority_and_checks_all_49_keys_with_fresh_attestation() {
    let (mut guard, w) = adapter();
    let model = base(&mut guard);
    assert_eq!(model.assigned_sublayer_weight, Some(65531));
    assert_eq!(guard.snapshot().unwrap(), model.expected);
    let keys = crate::member_carrier_guard::resource_keys(&scope()).unwrap();
    let lookups = w.borrow().lookups.clone();
    for k in std::iter::once(keys.sublayer).chain(keys.filters) {
        assert!(lookups.contains(&k));
    }
    assert_eq!(model.expected.filters.len(), 16);
    let desired = pair(Some(Slot::A)).inherit_sublayer_weight(&model).unwrap();
    let live = guard
        .exchange(SessionKind::DynamicPermits, &model, &desired)
        .unwrap();
    assert_eq!(guard.snapshot().unwrap(), live.expected);
    assert_eq!(live.expected.filters.len(), 32);
}

#[test]
fn adapter_rejects_independent_guid_source_scope_drift_and_current_changed_cas() {
    for fault in 1..=12 {
        let (mut guard, w) = adapter();
        let model = base(&mut guard);
        let desired = pair(Some(Slot::A)).inherit_sublayer_weight(&model).unwrap();
        if fault == 6 {
            w.borrow_mut().objects.sublayer.as_mut().unwrap().weight = 65530;
        } else {
            w.borrow_mut().binding_fault = fault;
        }
        assert!(
            guard
                .exchange(SessionKind::DynamicPermits, &model, &desired)
                .is_err(),
            "fault {fault}"
        );
        assert!(w
            .borrow()
            .objects
            .filters
            .values()
            .all(|(f, _)| f.policy.action == Action::Block));
        assert_eq!(w.borrow().objects.filters.len(), 16);
        assert!(guard
            .exchange(SessionKind::DynamicPermits, &model, &desired)
            .is_err());
    }
}

#[test]
fn adapter_install_errors_lost_ack_false_success_abort_and_read_error_are_cleanup_only() {
    for fault in 0..6 {
        let (mut guard, w) = adapter();
        let model = base(&mut guard);
        let desired = pair(Some(Slot::A)).inherit_sublayer_weight(&model).unwrap();
        {
            let mut w = w.borrow_mut();
            match fault {
                0 => w.commit_fault = 1,
                1 => w.commit_fault = 2,
                2 => w.commit_fault = 3,
                3 => w.read_fault = true,
                4 => {
                    w.denied = true;
                    w.abort_fault = true
                }
                _ => w.denied = true,
            }
        }
        assert!(
            guard
                .exchange(SessionKind::DynamicPermits, &model, &desired)
                .is_err(),
            "fault {fault}"
        );
        assert!(w
            .borrow()
            .objects
            .filters
            .values()
            .all(|(f, _)| f.policy.action == Action::Block));
        assert_eq!(w.borrow().objects.filters.len(), 16);
        let events = w.borrow().events.clone();
        assert!(events.contains(&"close:DynamicPermits".into()));
        assert!(guard
            .exchange(SessionKind::DynamicPermits, &model, &desired)
            .is_err());
    }
}

#[test]
fn adapter_disallows_wrong_session_and_fresh_replay_of_recovered_models_before_effects() {
    let (mut guard, w) = adapter();
    let empty = Model::empty(scope()).unwrap();
    let desired = pair(None);
    assert!(guard
        .exchange(SessionKind::StaticBase, &empty, &desired)
        .is_err());
    assert!(guard
        .exchange(SessionKind::DynamicPermits, &empty, &desired)
        .is_err());
    let (mut guard, w2) = adapter();
    let captured = base(&mut guard);
    let (mut reopened, w3) = adapter();
    assert!(reopened
        .exchange(
            SessionKind::DynamicPermits,
            &captured,
            &pair(Some(Slot::A))
                .inherit_sublayer_weight(&captured)
                .unwrap()
        )
        .is_err());
    assert!(w.borrow().objects.sublayer.is_none());
    assert!(w3.borrow().objects.sublayer.is_none());
    assert_eq!(w2.borrow().objects.filters.len(), 16);
}

#[test]
fn adapter_drop_closes_only_owned_dynamic_first_and_retains_nonpersistent_base() {
    let (mut guard, w) = adapter();
    let model = base(&mut guard);
    let desired = pair(Some(Slot::A)).inherit_sublayer_weight(&model).unwrap();
    guard
        .exchange(SessionKind::DynamicPermits, &model, &desired)
        .unwrap();
    drop(guard);
    let w = w.borrow();
    assert_eq!(w.objects.filters.len(), 16);
    assert!(w.objects.sublayer.is_some());
    assert!(w
        .events
        .ends_with(&["close:DynamicPermits".into(), "close:StaticBase".into()]));
}

#[test]
fn native_sessions_are_separate_nonpersistent_base_and_dynamic_permits_not_shared_lifetime() {
    for (kind, flags) in [
        (SessionKind::StaticBase, 0),
        (SessionKind::DynamicPermits, 1),
    ] {
        let s = session(kind);
        assert_eq!(s.flags, flags);
        assert_eq!(s.txnWaitTimeoutInMSec, 5000);
        assert_eq!(key(s.sessionKey), Key([0; 16]));
        assert!(s.displayData.name.is_null());
        assert!(s.displayData.description.is_null());
        assert_eq!(s.processId, 0);
        assert!(s.sid.is_null());
        assert!(s.username.is_null());
    }
}

#[test]
fn adapter_creation_lost_ack_never_returns_priority_or_resumes_and_retains_exact_cleanup_obligations(
) {
    for fault in [1, 2, 3] {
        let (mut guard, w) = adapter();
        w.borrow_mut().commit_fault = fault;
        let empty = Model::empty(scope()).unwrap();
        let desired = pair(None).without_permits().unwrap();
        assert!(guard
            .exchange(SessionKind::StaticBase, &empty, &desired)
            .is_err());
        assert_eq!(w.borrow().objects.sublayer.is_some(), fault == 2);
        assert!(w
            .borrow()
            .objects
            .filters
            .values()
            .all(|(f, _)| f.policy.action == Action::Block));
        assert!(guard
            .exchange(SessionKind::StaticBase, &empty, &desired)
            .is_err());
        assert!(w.borrow().events.contains(&"close:DynamicPermits".into()));
    }
}

#[test]
fn adapter_foreign_replacement_ids_or_orphan_allow_keys_cannot_be_adopted_or_deleted() {
    for orphan in [false, true] {
        let (mut guard, w) = adapter();
        let model = base(&mut guard);
        let desired = pair(Some(Slot::A)).inherit_sublayer_weight(&model).unwrap();
        let forged = if orphan {
            desired
                .expected
                .filters
                .iter()
                .find(|f| f.action == Action::Permit)
                .unwrap()
                .clone()
        } else {
            model.expected.filters[0].clone()
        };
        w.borrow_mut().objects.filters.insert(
            forged.key,
            (
                NativeFilter {
                    policy: forged.clone(),
                    id: 99999,
                },
                SessionKind::StaticBase,
            ),
        );
        assert!(guard
            .exchange(SessionKind::DynamicPermits, &model, &desired)
            .is_err());
        assert!(w.borrow().objects.filters.contains_key(&forged.key)); // No foreign/static deletion workaround.
        assert!(guard.snapshot().is_err());
    }
}

#[test]
fn native_conditions_reject_duplicate_fields_wrong_family_types_match_masks_and_layer_aliases() {
    for layer in [
        Layer::TransportV4,
        Layer::PacketV6,
        Layer::ForwardV4,
        Layer::AleConnectV6,
    ] {
        let filter = permit(layer);
        for fault in 0..7 {
            let mut encoded = returned(&filter);
            let conditions = unsafe {
                std::slice::from_raw_parts_mut(
                    encoded.raw.filterCondition,
                    encoded.raw.numFilterConditions as usize,
                )
            };
            match fault {
                0 => conditions[1] = conditions[0],
                1 => conditions[0].matchType = FWP_MATCH_NOT_EQUAL,
                2 => conditions[0].conditionValue.r#type = FWP_RANGE_TYPE,
                3 => conditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID,
                4 => encoded.raw.flags ^= 64,
                5 => encoded.raw.filterKey = GUID::from_u128(7),
                _ => {
                    let address = conditions
                        .iter_mut()
                        .find(|c| {
                            key(c.fieldKey)
                                == key(if matches!(layer, Layer::ForwardV4) {
                                    FWPM_CONDITION_IP_SOURCE_ADDRESS
                                } else {
                                    FWPM_CONDITION_IP_LOCAL_ADDRESS
                                })
                        })
                        .unwrap();
                    address.conditionValue.r#type =
                        if matches!(layer, Layer::TransportV4 | Layer::ForwardV4) {
                            FWP_BYTE_ARRAY16_TYPE
                        } else {
                            FWP_UINT32
                        };
                    address.conditionValue.Anonymous = FWP_CONDITION_VALUE0_0 {
                        byteArray16: ptr::null_mut(),
                    };
                }
            }
            assert!(
                unsafe { decode_filter(&encoded.raw, filter.key, filter.sublayer) }.is_err(),
                "{layer:?}/{fault}"
            );
        }
    }
}

#[test]
fn adapter_snapshot_itself_rejects_later_priority_or_owned_policy_drift_without_adoption() {
    for priority in [false, true] {
        let (mut guard, w) = adapter();
        let _ = base(&mut guard);
        if priority {
            w.borrow_mut().objects.sublayer.as_mut().unwrap().weight = 65530;
        } else {
            w.borrow_mut()
                .objects
                .filters
                .values_mut()
                .next()
                .unwrap()
                .0
                .policy
                .conditions[0] = crate::member_carrier_guard::Condition::EgressIndex(99);
        }
        assert!(guard.snapshot().is_err());
        assert_eq!(w.borrow().objects.filters.len(), 16);
    }
}

#[derive(Default)]
struct Journal(Option<crate::member_carrier_guard::ExchangePlan>);
impl crate::member_carrier_guard::ExchangeJournal for Journal {
    fn load(
        &mut self,
        _: &SessionScope,
    ) -> Result<Option<crate::member_carrier_guard::ExchangePlan>> {
        Ok(self.0.clone())
    }
    fn compare_exchange(
        &mut self,
        expected: Option<&crate::member_carrier_guard::ExchangePlan>,
        desired: &crate::member_carrier_guard::ExchangePlan,
    ) -> Result<()> {
        if self.0.as_ref() != expected {
            return Err(GuardError::Conflict);
        }
        self.0 = Some(desired.clone());
        Ok(())
    }
}
struct Authority;
impl crate::member_carrier_guard::Authority for Authority {
    fn before_base(&mut self, _: &Model, _: &Model) -> Result<()> {
        Ok(())
    }
    fn before_install(&mut self, _: &Model) -> Result<()> {
        Ok(())
    }
}
#[test]
fn real_portable_journaled_exchange_role_switch_and_allow_absence_use_native_adapter() {
    use crate::member_carrier_guard::{apply_split, confirm_no_permits, ExchangePlan};
    let (mut guard, w) = adapter();
    let mut journal = Journal::default();
    let empty = Model::empty(scope()).unwrap();
    let plan = ExchangePlan::new(&empty, &pair(Some(Slot::A))).unwrap();
    let token = plan.persist(&mut journal, None).unwrap();
    let a = apply_split(&mut guard, &token, &mut Authority, &mut journal).unwrap();
    assert_eq!(
        journal.0.as_ref().unwrap().captured_sublayer_weight,
        Some(65531)
    );
    let desired = pair(Some(Slot::B)).inherit_sublayer_weight(&a).unwrap();
    let switch = ExchangePlan::new(&a, &desired).unwrap();
    let saved = journal.0.clone();
    let token = switch.persist(&mut journal, saved.as_ref()).unwrap();
    let b = apply_split(&mut guard, &token, &mut Authority, &mut journal).unwrap();
    assert_eq!(b.active, Some(Slot::B));
    assert_eq!(guard.snapshot().unwrap(), b.expected);
    guard.close_permits().unwrap();
    assert_eq!(
        confirm_no_permits(&mut guard, &switch).unwrap().expected,
        b.without_permits().unwrap().expected
    );
    assert_eq!(w.borrow().objects.filters.len(), 16);
    assert!(guard
        .exchange(
            SessionKind::DynamicPermits,
            &b.without_permits().unwrap(),
            &b
        )
        .is_err());
}

#[test]
fn adapter_failed_close_or_foreign_static_allow_keeps_exact_absence_unconfirmed() {
    use crate::member_carrier_guard::{confirm_no_permits, ExchangePlan};
    for foreign in [false, true] {
        let (mut guard, w) = adapter();
        let model = base(&mut guard);
        let desired = pair(Some(Slot::A)).inherit_sublayer_weight(&model).unwrap();
        let live = guard
            .exchange(SessionKind::DynamicPermits, &model, &desired)
            .unwrap();
        let plan = ExchangePlan::new(&live, &live).unwrap();
        if foreign {
            w.borrow_mut()
                .objects
                .filters
                .values_mut()
                .find(|(f, _)| f.policy.action == Action::Permit)
                .unwrap()
                .1 = SessionKind::StaticBase;
        } else {
            w.borrow_mut().close_fault = true;
        }
        let close = guard.close_permits();
        if !foreign {
            assert_eq!(close, Err(GuardError::RemovalUnconfirmed));
        }
        assert!(confirm_no_permits(&mut guard, &plan).is_err());
        assert!(w
            .borrow()
            .objects
            .filters
            .values()
            .any(|(f, _)| f.policy.action == Action::Permit));
    }
}

#[test]
fn adapter_authority_unwind_aborts_closes_only_own_permits_and_poison_fences_resume() {
    let (mut guard, w) = adapter();
    let model = base(&mut guard);
    let desired = pair(Some(Slot::A)).inherit_sublayer_weight(&model).unwrap();
    let live = guard
        .exchange(SessionKind::DynamicPermits, &model, &desired)
        .unwrap();
    w.borrow_mut().panic_authorize = true;
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = guard.exchange(
            SessionKind::DynamicPermits,
            &live,
            &live.without_permits().unwrap(),
        );
    }));
    assert!(panic.is_err());
    assert!(w.borrow().staged.is_none());
    assert!(w
        .borrow()
        .objects
        .filters
        .values()
        .all(|(f, _)| f.policy.action == Action::Block));
    assert_eq!(w.borrow().objects.filters.len(), 16);
    w.borrow_mut().panic_authorize = false;
    assert!(guard
        .exchange(
            SessionKind::DynamicPermits,
            &live,
            &live.without_permits().unwrap()
        )
        .is_err());
}

#[test]
fn adapter_each_partial_add_aborts_atomic_transaction_and_never_returns_partial_policy() {
    for dynamic in [false, true] {
        for failed_add in 1..=16 {
            let (mut guard, w) = adapter();
            let expected = if dynamic {
                base(&mut guard)
            } else {
                Model::empty(scope()).unwrap()
            };
            let desired = if dynamic {
                pair(Some(Slot::A))
                    .inherit_sublayer_weight(&expected)
                    .unwrap()
            } else {
                pair(None).without_permits().unwrap()
            };
            {
                let mut w = w.borrow_mut();
                w.partial_add_at = Some(w.adds + failed_add);
            }
            let kind = if dynamic {
                SessionKind::DynamicPermits
            } else {
                SessionKind::StaticBase
            };
            assert!(
                guard.exchange(kind, &expected, &desired).is_err(),
                "{kind:?}, add {failed_add}"
            );
            assert!(w.borrow().staged.is_none());
            assert_eq!(
                w.borrow().objects.filters.len(),
                if dynamic { 16 } else { 0 }
            );
            assert_eq!(w.borrow().objects.sublayer.is_some(), dynamic);
            assert!(w
                .borrow()
                .objects
                .filters
                .values()
                .all(|(f, _)| f.policy.action == Action::Block));
            assert!(guard.exchange(kind, &expected, &desired).is_err());
        }
    }
}

#[test]
fn adapter_owned_base_removal_requires_mandatory_authority_and_exact_key_only_deletion() {
    for denied in [false, true] {
        let (mut guard, w) = adapter();
        let model = base(&mut guard);
        w.borrow_mut().denied = denied;
        let empty = Model::empty(scope()).unwrap();
        let result = guard.exchange(SessionKind::StaticBase, &model, &empty);
        if denied {
            assert!(result.is_err());
            assert_eq!(w.borrow().objects.filters.len(), 16);
            assert!(w.borrow().objects.sublayer.is_some());
        } else {
            assert_eq!(result.unwrap(), empty);
            assert_eq!(guard.snapshot().unwrap(), empty.expected);
            assert!(w.borrow().objects.filters.is_empty());
            assert!(w.borrow().objects.sublayer.is_none());
        }
    }
}
