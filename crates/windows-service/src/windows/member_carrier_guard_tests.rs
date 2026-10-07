// Child tests on both host and native: same production policies/lifecycle and
// SDK layouts. Only external BFE and native authorization are doubled.
use super::*;
use crate::{
    member_carrier_guard::{
        Action, Carrier, Filter, GuardError, Identity, Key, Layer, Member, Model, ProbeTuple,
        Result, SessionKind, Snapshot, SplitEngines, Sublayer,
    },
    member_owner::InterfaceProof,
};
use nelomai_client_tunnel::redundancy::{SessionScope, Slot};
use nelomai_contracts::RuntimeSlot;
use std::ptr;

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

use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    rc::Rc,
};

mod terminal_engine {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn owner() -> EngineLifetime {
        EngineLifetime::new(SessionKind::StaticBase, 17).unwrap()
    }

    // Break: the terminal lane must not reuse ordinary EngineDrop's retry when
    // the actual close boundary failed or unwound (possibly AFTER native close).
    #[test]
    fn failed_or_unwound_terminal_close_retains_uncertainty_without_drop_retry() {
        for unwind in [false, true] {
            let engine = owner();
            engine.enter_terminal();
            let calls = std::cell::Cell::new(0);
            let result = catch_unwind(AssertUnwindSafe(|| {
                engine.close_terminal(|handle| {
                    assert_eq!(handle, 17);
                    calls.set(calls.get() + 1);
                    if unwind {
                        panic!("close ACK lost by unwind");
                    }
                    Err(GuardError::Native(57))
                })
            }));
            assert!(result.is_err() || result.unwrap().is_err());
            assert!(!engine.drop_requires_close());
            assert!(engine
                .close_terminal(|_| {
                    calls.set(calls.get() + 1);
                    Ok(())
                })
                .is_err());
            assert_eq!(calls.get(), 1);
            assert!(engine.acknowledged().is_err());
        }
    }

    #[test]
    fn actual_ack_is_retained_and_foreign_equal_handle_receipt_is_not_original() {
        let engine = owner();
        let foreign = owner();
        engine.enter_terminal();
        foreign.enter_terminal();
        let original = engine.close_terminal(|_| Ok(())).unwrap();
        let equal = foreign.close_terminal(|_| Ok(())).unwrap();
        assert!(engine.verify_ack(&original).is_ok());
        assert!(engine.verify_ack(&equal).is_err());
        assert!(Rc::ptr_eq(&original, &engine.acknowledged().unwrap()));
        assert!(!engine.drop_requires_close());
    }

    #[test]
    fn swallowed_close_reentry_keeps_real_ack_but_denies_outer_release() {
        let engine = owner();
        engine.enter_terminal();
        let calls = std::cell::Cell::new(0);
        assert!(engine
            .close_terminal(|_| {
                calls.set(calls.get() + 1);
                assert!(engine
                    .close_terminal(|_| {
                        calls.set(calls.get() + 1);
                        Ok(())
                    })
                    .is_err());
                Ok(()) // actual external close succeeded; original receipt retained
            })
            .is_err());
        assert_eq!(calls.get(), 1);
        assert!(engine.acknowledged().is_ok());
        assert!(engine.verify_inert().is_err());
        assert!(!engine.drop_requires_close());
    }

    #[test]
    fn prior_actual_emergency_ack_is_reused_without_second_native_close() {
        let engine = owner();
        engine.close_ordinary(|_| Ok(())).unwrap();
        let original = engine.acknowledged().unwrap();
        engine.enter_terminal();
        let reused = engine
            .close_terminal(|_| panic!("already closed original"))
            .unwrap();
        assert!(Rc::ptr_eq(&original, &reused));
        engine.verify_inert().unwrap();
    }
}

mod terminal_guard {
    use super::*;
    use std::{
        cell::Cell,
        panic::{catch_unwind, AssertUnwindSafe},
    };

    struct TerminalApi {
        inner: Api,
        engines: [EngineLifetime; 2],
        lost: Option<SessionKind>,
    }
    /// External BFE readonly session, distinct from the original closed engine.
    /// Shares SDK objects, NOT the original handle's closed/ownership state.
    struct ObserverApi(Api);
    impl NativeApi for ObserverApi {
        fn begin(&mut self, kind: SessionKind, readonly: bool) -> Result<()> {
            if kind != SessionKind::StaticBase || !readonly {
                return Err(GuardError::Conflict);
            }
            let mut sdk = self.0 .0.borrow_mut();
            assert!(sdk.staged.is_none());
            sdk.events.push("observer:begin:readonly".into());
            sdk.staged = Some(sdk.objects.clone());
            Ok(())
        }
        fn commit(&mut self, k: SessionKind) -> Result<()> {
            self.0.commit(k)
        }
        fn abort(&mut self, k: SessionKind) -> Result<()> {
            self.0.abort(k)
        }
        fn sublayer(&mut self, k: SessionKind, key: Key) -> Result<Option<Sublayer>> {
            self.0.sublayer(k, key)
        }
        fn filter(&mut self, k: SessionKind, key: Key, sub: Key) -> Result<Option<NativeFilter>> {
            self.0.filter(k, key, sub)
        }
        fn close(&mut self, _: SessionKind) -> Result<()> {
            Err(GuardError::Conflict)
        }
        fn arbitration(&mut self, _: SessionKind) -> Result<Vec<ArbitrationFilter>> {
            Err(GuardError::Conflict)
        }
        fn add_sublayer(&mut self, _: &Sublayer) -> Result<()> {
            Err(GuardError::Conflict)
        }
        fn delete_sublayer(&mut self, _: Key) -> Result<()> {
            Err(GuardError::Conflict)
        }
        fn add_filter(&mut self, _: SessionKind, _: &Filter) -> Result<u64> {
            Err(GuardError::Conflict)
        }
        fn delete_filter(&mut self, _: SessionKind, _: Key) -> Result<()> {
            Err(GuardError::Conflict)
        }
    }
    impl NativeApi for TerminalApi {
        fn begin(&mut self, k: SessionKind, r: bool) -> Result<()> {
            self.inner.begin(k, r)
        }
        fn commit(&mut self, k: SessionKind) -> Result<()> {
            self.inner.commit(k)
        }
        fn abort(&mut self, k: SessionKind) -> Result<()> {
            self.inner.abort(k)
        }
        fn close(&mut self, k: SessionKind) -> Result<()> {
            self.engines[usize::from(k == SessionKind::DynamicPermits)]
                .close_ordinary(|_| self.inner.close(k))
        }
        fn sublayer(&mut self, k: SessionKind, key: Key) -> Result<Option<Sublayer>> {
            self.inner.sublayer(k, key)
        }
        fn filter(&mut self, k: SessionKind, key: Key, sub: Key) -> Result<Option<NativeFilter>> {
            self.inner.filter(k, key, sub)
        }
        fn arbitration(&mut self, k: SessionKind) -> Result<Vec<ArbitrationFilter>> {
            self.inner.arbitration(k)
        }
        fn add_sublayer(&mut self, s: &Sublayer) -> Result<()> {
            self.inner.add_sublayer(s)
        }
        fn delete_sublayer(&mut self, k: Key) -> Result<()> {
            self.inner.delete_sublayer(k)
        }
        fn add_filter(&mut self, k: SessionKind, f: &Filter) -> Result<u64> {
            self.inner.add_filter(k, f)
        }
        fn delete_filter(&mut self, k: SessionKind, key: Key) -> Result<()> {
            self.inner.delete_filter(k, key)
        }
    }
    // Only the external BFE boundary is replaced; original engine lifetimes,
    // ACK retention, guard policy/readbacks and irreversible protocol are real.
    unsafe impl TerminalNativeApi for TerminalApi {
        fn enter_terminal_lane(&mut self) {
            for e in &self.engines {
                e.enter_terminal();
            }
        }
        fn engine_origin(&self, k: SessionKind) -> Rc<()> {
            self.engines[usize::from(k == SessionKind::DynamicPermits)].original_origin()
        }
        fn engine_close_ack(&self, k: SessionKind) -> Result<Rc<EngineCloseAck>> {
            self.engines[usize::from(k == SessionKind::DynamicPermits)].acknowledged()
        }
        fn close_terminal_engine(&mut self, k: SessionKind) -> Result<Rc<EngineCloseAck>> {
            self.engines[usize::from(k == SessionKind::DynamicPermits)].close_terminal(|_| {
                self.inner.close(k)?;
                if self.lost == Some(k) {
                    return Err(GuardError::Native(57));
                }
                Ok(())
            })
        }
        fn verify_engine_inert(&self, k: SessionKind, ack: &Rc<EngineCloseAck>) -> Result<()> {
            let e = &self.engines[usize::from(k == SessionKind::DynamicPermits)];
            e.verify_ack(ack)?;
            e.verify_inert()
        }
    }
    type Guard = NativeGuard<TerminalApi, Attestor>;
    fn original(lost: Option<SessionKind>) -> (Guard, Rc<RefCell<World>>) {
        let w = Rc::new(RefCell::new(World::default()));
        let api = TerminalApi {
            inner: Api(w.clone()),
            engines: [
                EngineLifetime::new(SessionKind::StaticBase, 17).unwrap(),
                EngineLifetime::new(SessionKind::DynamicPermits, 19).unwrap(),
            ],
            lost,
        };
        (
            NativeGuard::fresh(scope(), api, Attestor(w.clone())).unwrap(),
            w,
        )
    }
    fn bindings() -> Bindings {
        Bindings {
            service_domains: Vec::new(),
            scope: scope(),
            carrier: None,
            egress: [None, None],
        }
    }

    // Break: actual engine ACKs cannot make final failed/unwound postflight a
    // destructor proof. Both actual receipts must remain factual and rooted.
    #[test]
    fn final_postflight_error_or_unwind_retains_both_acks_without_inert_grant() {
        for unwind in [false, true] {
            let (mut guard, w) = original(None);
            let receipt = guard.begin_terminal_close().unwrap();
            let calls = Cell::new(0);
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                guard.close_terminal_checked(&receipt, &bindings(), || {
                    calls.set(calls.get() + 1);
                    if w.borrow().closed == [true, true] {
                        if unwind {
                            panic!("terminal resource postflight");
                        }
                        return Err(GuardError::Conflict);
                    }
                    Ok(())
                })
            }));
            assert!(outcome.is_err() || outcome.unwrap().is_err());
            assert!(receipt
                .acknowledgements()
                .unwrap()
                .iter()
                .all(Option::is_some));
            assert!(guard.verify_terminal_inert(&receipt).is_err());
            let before = w.borrow().events.clone();
            drop(guard);
            assert_eq!(w.borrow().events, before);
        }
    }

    #[test]
    fn actual_partial_close_lost_ack_never_adopts_closed_flag_or_retries() {
        let (mut guard, w) = original(Some(SessionKind::StaticBase));
        let receipt = guard.begin_terminal_close().unwrap();
        let observed_after_failed_second_close = Cell::new(false);
        // Independent readonly observer at the external BFE boundary: reads
        // real test BFE objects via the production all-key snapshot routine,
        // never the closed guard engine or its modeled/closed flags.
        let mut observer = ScopedGuardAbsence::new(scope(), ObserverApi(Api(w.clone()))).unwrap();
        assert!(guard
            .close_terminal_checked(&receipt, &bindings(), || {
                w.borrow_mut().lookups.clear();
                let actual = observer.read_snapshot(&scope())?;
                assert_eq!(actual, Model::empty(scope()).unwrap().expected);
                if w.borrow().closed == [true, true] {
                    let keys = crate::member_carrier_guard::resource_keys(&scope()).unwrap();
                    assert_eq!(
                        w.borrow().lookups,
                        std::iter::once(keys.sublayer)
                            .chain(keys.filters)
                            .collect::<Vec<_>>()
                    );
                    observed_after_failed_second_close.set(true);
                }
                Ok(())
            })
            .is_err());
        assert!(observed_after_failed_second_close.get());
        assert_eq!(w.borrow().closed, [true, true]); // external operation really ran
        let a = receipt.acknowledgements().unwrap();
        assert!(a[0].is_none());
        assert!(a[1].is_some());
        assert!(guard.verify_terminal_inert(&receipt).is_err());
        let before = w.borrow().events.clone();
        assert!(guard.begin_terminal_close().is_err());
        assert!(guard.snapshot().is_err());
        drop(guard);
        assert_eq!(w.borrow().events, before);
    }

    #[test]
    fn completed_close_requires_same_guard_and_both_actual_engine_origins() {
        let (mut guard, w) = original(None);
        let (mut foreign, _) = original(None);
        let receipt = guard.begin_terminal_close().unwrap();
        guard
            .close_terminal_checked(&receipt, &bindings(), || Ok(()))
            .unwrap();
        guard.verify_terminal_inert(&receipt).unwrap();
        let other = foreign.begin_terminal_close().unwrap();
        foreign
            .close_terminal_checked(&other, &bindings(), || Ok(()))
            .unwrap();
        assert!(guard.verify_terminal_inert(&other).is_err());
        let before = w.borrow().events.clone();
        drop(guard);
        assert_eq!(w.borrow().events, before);
    }

    #[test]
    fn replaced_equal_native_handle_is_not_the_closed_original_engine() {
        let (mut guard, _) = original(None);
        let receipt = guard.begin_terminal_close().unwrap();
        guard
            .close_terminal_checked(&receipt, &bindings(), || Ok(()))
            .unwrap();
        // SAME numerical handle and successful foreign native close cannot
        // replace the opaque engine that actually issued the retained ACK.
        let replacement = EngineLifetime::new(SessionKind::StaticBase, 17).unwrap();
        replacement.enter_terminal();
        replacement.close_terminal(|_| Ok(())).unwrap();
        guard.io.engines[0] = replacement;
        assert!(guard.verify_terminal_inert(&receipt).is_err());
        assert!(receipt
            .acknowledgements()
            .unwrap()
            .iter()
            .all(Option::is_some));
    }

    #[test]
    fn unperformed_close_is_not_an_ack_and_terminal_lane_denies_all_forward_io() {
        let (mut guard, w) = original(None);
        let receipt = guard.begin_terminal_close().unwrap();
        assert!(guard.verify_terminal_inert(&receipt).is_err());
        assert!(receipt
            .acknowledgements()
            .unwrap()
            .iter()
            .all(Option::is_none));
        let before = w.borrow().events.clone();
        assert!(guard.snapshot().is_err());
        assert!(guard.close_permits().is_err());
        let empty = Model::empty(scope()).unwrap();
        assert!(guard
            .exchange(SessionKind::StaticBase, &empty, &empty)
            .is_err());
        assert_eq!(w.borrow().events, before);
        drop(guard);
        assert_eq!(w.borrow().events, before);
    }

    #[test]
    fn same_receipt_is_rooted_before_failed_or_unwound_registration_and_never_replaced() {
        for unwind in [false, true] {
            let (mut guard, w) = original(None);
            let receipt = guard.begin_terminal_close().unwrap();
            let mut destination = None;
            let caller = RefCell::new(None);
            let result = catch_unwind(AssertUnwindSafe(|| {
                retain_terminal_original(&mut destination, &receipt, &receipt, |actual| {
                    assert!(Rc::ptr_eq(&actual, &receipt));
                    *caller.borrow_mut() = Some(actual);
                    if unwind {
                        panic!("caller retained before registration unwind");
                    }
                    Err(GuardError::Conflict)
                })
            }));
            assert!(result.is_err() || result.unwrap().is_err());
            assert!(Rc::ptr_eq(destination.as_ref().unwrap(), &receipt));
            assert!(Rc::ptr_eq(caller.borrow().as_ref().unwrap(), &receipt));
            assert!(receipt
                .acknowledgements()
                .unwrap()
                .iter()
                .all(Option::is_none));
            assert!(guard
                .close_terminal_checked(&receipt, &bindings(), || Ok(()))
                .is_err());
            assert!(guard.verify_terminal_inert(&receipt).is_err());
            let (mut other, _) = original(None);
            let equal = other.begin_terminal_close().unwrap();
            assert!(
                retain_terminal_original(&mut destination, &equal, &equal, |_| panic!(
                    "occupied original"
                ))
                .is_err()
            );
            assert!(Rc::ptr_eq(destination.as_ref().unwrap(), &receipt));
            let before = w.borrow().events.clone();
            drop(guard);
            assert_eq!(w.borrow().events, before);
        }
    }

    #[test]
    fn caller_receipt_is_the_same_actual_root_after_successful_close_and_inert_drop() {
        let (mut guard, w) = original(None);
        let receipt = guard.begin_terminal_close().unwrap();
        let mut destination = None;
        let mut caller = None;
        retain_terminal_original(&mut destination, &receipt, &receipt, |actual| {
            caller = Some(actual);
            Ok(())
        })
        .unwrap();
        guard
            .close_terminal_checked(&receipt, &bindings(), || Ok(()))
            .unwrap();
        let caller = caller.unwrap();
        assert!(Rc::ptr_eq(&caller, &receipt));
        for (left, right) in caller
            .acknowledgements()
            .unwrap()
            .iter()
            .zip(receipt.acknowledgements().unwrap())
        {
            assert!(Rc::ptr_eq(left.as_ref().unwrap(), right.as_ref().unwrap()));
        }
        guard.verify_terminal_inert(&caller).unwrap();
        let before = w.borrow().events.clone();
        drop(guard);
        assert_eq!(w.borrow().events, before);
        assert!(caller
            .acknowledgements()
            .unwrap()
            .iter()
            .all(Option::is_some));
    }

    #[test]
    fn actual_prior_emergency_ack_is_mirrored_before_fallible_terminal_registration() {
        let (mut guard, w) = original(None);
        guard.io.close(SessionKind::DynamicPermits).unwrap();
        let actual = guard
            .io
            .engine_close_ack(SessionKind::DynamicPermits)
            .unwrap();
        let receipt = guard.begin_terminal_close().unwrap();
        let mirrored = receipt.acknowledgements().unwrap();
        assert!(Rc::ptr_eq(mirrored[1].as_ref().unwrap(), &actual));
        assert!(mirrored[0].is_none());
        let mut destination = None;
        assert!(
            retain_terminal_original(&mut destination, &receipt, &receipt, |_| Err(
                GuardError::Conflict
            ))
            .is_err()
        );
        assert!(Rc::ptr_eq(destination.as_ref().unwrap(), &receipt));
        assert!(Rc::ptr_eq(
            receipt.acknowledgements().unwrap()[1].as_ref().unwrap(),
            &actual
        ));
        assert!(guard.verify_terminal_inert(&receipt).is_err());
        let before = w.borrow().events.clone();
        drop(guard);
        assert_eq!(w.borrow().events, before);
    }

    #[test]
    fn foreign_scope_and_surviving_last_key_deny_before_any_engine_close() {
        for foreign in [false, true] {
            let (mut guard, w) = original(None);
            let receipt = guard.begin_terminal_close().unwrap();
            let mut b = bindings();
            if foreign {
                b.scope.connection_generation += 1;
            } else {
                let keys = crate::member_carrier_guard::resource_keys(&scope()).unwrap();
                let mut f = pair(None).expected.filters[0].clone();
                f.key = keys.filters[47];
                w.borrow_mut().objects.filters.insert(
                    f.key,
                    (NativeFilter { policy: f, id: 700 }, SessionKind::StaticBase),
                );
            }
            assert!(guard
                .close_terminal_checked(&receipt, &b, || Ok(()))
                .is_err());
            assert!(w.borrow().events.iter().all(|e| !e.starts_with("close:")));
            assert!(guard.verify_terminal_inert(&receipt).is_err());
        }
    }
}
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
    binding_after_scan: Option<u8>,
    arbitration_fault: bool,
    arbitration_extra: Vec<ArbitrationFilter>,
    denied: bool,
    closed: [bool; 2],
    panic_authorize: bool,
    read_error_authorize: bool,
    locked_fault: u8,
    panic_locked_filter: bool,
    read_filter_error: bool,
    panic_after_locked_read: bool,
    catch_locked_failure: bool,
    locked_snapshots: Vec<Result<Snapshot>>,
    locked_lookups: Vec<Vec<Key>>,
    query_kinds: Vec<SessionKind>,
    partial_add_at: Option<usize>,
    adds: usize,
}
struct Api(Rc<RefCell<World>>);

// These tests exercise the production cold lifecycle; only external BFE and
// authenticated caller inputs are doubled. No original creator ACK is minted.
struct ColdApi(Api);
impl ColdStaticNativeApi for ColdApi {
    fn begin(&mut self, readonly: bool) -> Result<()> {
        self.0.begin(SessionKind::StaticBase, readonly)
    }
    fn read_full(&mut self, scope: &SessionScope) -> Result<ColdWfpFacts> {
        let keys = crate::member_carrier_guard::resource_keys(scope)?;
        let sublayer = self.0.sublayer(SessionKind::StaticBase, keys.sublayer)?;
        let mut filters = Vec::new();
        for k in keys.filters {
            if let Some(f) = self.0.filter(SessionKind::StaticBase, k, keys.sublayer)? {
                filters.push(f);
            }
        }
        if sublayer.is_none() && !filters.is_empty() {
            return Err(GuardError::Conflict);
        }
        Ok(ColdWfpFacts {
            sublayer,
            filters,
            arbitration: self.0.arbitration(SessionKind::StaticBase)?,
        })
    }
    fn delete_original_block(&mut self, original: &NativeFilter) -> Result<()> {
        let now = self.0.filter(
            SessionKind::StaticBase,
            original.policy.key,
            original.policy.sublayer,
        )?;
        if now.as_ref() != Some(original) {
            return Err(GuardError::Conflict);
        }
        self.0
            .delete_filter(SessionKind::StaticBase, original.policy.key)
    }
    fn delete_original_sublayer(&mut self, original: &Sublayer) -> Result<()> {
        if self
            .0
            .sublayer(SessionKind::StaticBase, original.key)?
            .as_ref()
            != Some(original)
        {
            return Err(GuardError::Conflict);
        }
        self.0.delete_sublayer(original.key)
    }
    fn commit(&mut self) -> Result<()> {
        self.0.commit(SessionKind::StaticBase)
    }
    fn abort(&mut self) -> Result<()> {
        self.0.abort(SessionKind::StaticBase)
    }
}
struct ColdAuth {
    policies: RefCell<ColdGuardPolicies>,
    valid: Cell<bool>,
    after_fault: Cell<bool>,
    panic_after: Cell<bool>,
    hook: RefCell<Option<Box<dyn FnOnce()>>>,
}
// SAFETY: test-only external authorization double; no Windows execution.
unsafe impl ColdStaticAuthorization for ColdAuth {
    fn with_cleanup_authority<T>(
        &self,
        s: &SessionScope,
        read: impl FnOnce(&ColdGuardPolicies) -> Result<T>,
    ) -> Result<T> {
        if !self.valid.get() || *s != scope() {
            self.valid.set(false);
            return Err(GuardError::Conflict);
        }
        struct Flight<'a> {
            valid: &'a Cell<bool>,
            done: bool,
        }
        impl Drop for Flight<'_> {
            fn drop(&mut self) {
                if !self.done {
                    self.valid.set(false);
                }
            }
        }
        let mut flight = Flight {
            valid: &self.valid,
            done: false,
        };
        if let Some(hook) = self.hook.borrow_mut().take() {
            hook();
        }
        let result = read(&self.policies.borrow());
        assert!(!self.panic_after.get(), "cold authorizer postflight unwind");
        if self.after_fault.get() || result.is_err() {
            self.valid.set(false);
            return result.and(Err(GuardError::Conflict));
        }
        flight.done = true;
        result
    }
}
type ColdFixture = (
    Rc<ColdStaticCleanup<ColdApi, ColdAuth>>,
    Rc<RefCell<World>>,
    Rc<ColdAuth>,
);
fn cold_policies(
    current: Model,
    pending: Option<crate::member_carrier_guard::ExchangePlan>,
) -> ColdGuardPolicies {
    let protected_record = serde_json::to_vec(&(&current, &pending)).unwrap();
    ColdGuardPolicies {
        current,
        pending,
        protected_record,
    }
}
fn cold_fixture(count: usize) -> ColdFixture {
    let mut model = pair(None).without_permits().unwrap();
    model = model
        .readback_after(&Model::empty(scope()).unwrap(), &model.expected)
        .unwrap();
    let world = Rc::new(RefCell::new(World::default()));
    world.borrow_mut().objects.sublayer = model.expected.sublayer.clone();
    for (i, policy) in model.expected.filters.iter().take(count).enumerate() {
        world.borrow_mut().objects.filters.insert(
            policy.key,
            (
                NativeFilter {
                    policy: policy.clone(),
                    id: 700 + i as u64,
                },
                SessionKind::StaticBase,
            ),
        );
    }
    let auth = Rc::new(ColdAuth {
        policies: RefCell::new(cold_policies(model, None)),
        valid: Cell::new(true),
        after_fault: Cell::new(false),
        panic_after: Cell::new(false),
        hook: RefCell::new(None),
    });
    let root = ColdStaticCleanup::root(scope(), auth.clone());
    root.initialize(|| Ok(ColdApi(Api(world.clone())))).unwrap();
    (root, world, auth)
}
#[test]
fn cold_static_cleanup_removes_exact_captured_partial_blocks_only() {
    let (root, world, _) = cold_fixture(3);
    root.capture().unwrap();
    let captured_ids: Vec<_> = world
        .borrow()
        .objects
        .filters
        .values()
        .map(|(f, _)| f.id)
        .collect();
    assert_eq!(captured_ids, vec![700, 701, 702]);
    root.cleanup().unwrap();
    assert!(world.borrow().objects.filters.is_empty());
    assert!(world.borrow().objects.sublayer.is_none());
    assert_eq!(root.disposition(), (true, true, false));
    assert_eq!(
        world
            .borrow()
            .events
            .iter()
            .filter(|e| e.as_str() == "begin:StaticBase:false")
            .count(),
        1
    );
    assert!(!world
        .borrow()
        .events
        .iter()
        .any(|e| e.contains("DynamicPermits") || e.starts_with("add:")));
}

#[test]
fn cold_static_capture_denies_foreign_extra_permit_unknown_policy_and_reused_ids() {
    for fault in 0..10 {
        let (root, world, _) = cold_fixture(3);
        {
            let mut w = world.borrow_mut();
            let own = w.objects.filters.values().next().unwrap().0.clone();
            let weight = w.objects.sublayer.as_ref().unwrap().weight;
            match fault {
                0 | 1 => w.arbitration_extra.push(ArbitrationFilter {
                    service_domain: None,
                    key: Key([99; 16]),
                    id: 98765,
                    layer: own.policy.layer,
                    sublayer: own.policy.sublayer,
                    sublayer_weight: weight,
                    flags: 0,
                    action: if fault == 0 {
                        FWP_ACTION_BLOCK
                    } else {
                        FWP_ACTION_PERMIT
                    },
                }),
                2 => {
                    w.objects
                        .filters
                        .values_mut()
                        .next()
                        .unwrap()
                        .0
                        .policy
                        .conditions = vec![Condition::EgressIndex(9876)]
                }
                3 => {
                    w.objects
                        .filters
                        .values_mut()
                        .next()
                        .unwrap()
                        .0
                        .policy
                        .action = Action::Permit
                }
                4 => {
                    w.objects
                        .filters
                        .values_mut()
                        .next()
                        .unwrap()
                        .0
                        .policy
                        .flags = FWPM_FILTER_FLAG_PERSISTENT
                }
                5 => w.objects.filters.values_mut().next().unwrap().0.id = 0,
                6 => w.objects.sublayer.as_mut().unwrap().weight -= 1,
                7 => w.objects.sublayer = None,
                8 => {
                    let id = w.objects.filters.values().next().unwrap().0.id;
                    w.objects.filters.values_mut().nth(1).unwrap().0.id = id;
                }
                _ => w.arbitration_extra.push(ArbitrationFilter {
                    service_domain: None,
                    key: Key([98; 16]),
                    id: own.id,
                    layer: own.policy.layer,
                    sublayer: Key([97; 16]),
                    sublayer_weight: 123,
                    flags: 0,
                    action: FWP_ACTION_BLOCK,
                }),
            }
        }
        let before = world.borrow().objects.filters.len();
        assert!(root.capture().is_err(), "fault {fault}");
        assert!(root.cleanup().is_err());
        assert_eq!(world.borrow().objects.filters.len(), before);
        assert!(
            !world
                .borrow()
                .events
                .iter()
                .any(|e| e.starts_with("delete:")),
            "fault {fault}"
        );
        assert_eq!(root.disposition(), (false, false, true));
    }
}

#[test]
fn cold_static_mutation_after_capture_never_deletes_replacement() {
    for id_only in [false, true] {
        let (root, world, _) = cold_fixture(3);
        root.capture().unwrap();
        let mut w = world.borrow_mut();
        let f = &mut w.objects.filters.values_mut().next().unwrap().0;
        if id_only {
            f.id += 555;
        } else {
            f.policy.conditions = vec![Condition::EgressIndex(456)];
        }
        drop(w);
        assert!(root.cleanup().is_err());
        assert_eq!(world.borrow().objects.filters.len(), 3);
        assert!(!world
            .borrow()
            .events
            .iter()
            .any(|e| e.starts_with("delete:")));
    }
}

#[test]
fn cold_static_commit_loss_and_postflight_error_keep_facts_without_success_or_retry() {
    for fault in 0..4 {
        let (root, world, auth) = cold_fixture(3);
        root.capture().unwrap();
        match fault {
            0 => world.borrow_mut().commit_fault = 1, // did not commit
            1 => world.borrow_mut().commit_fault = 2, // committed, lost ACK
            2 => auth.after_fault.set(true),
            _ => auth.panic_after.set(true),
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| root.cleanup()));
        if fault == 3 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert_eq!(world.borrow().objects.filters.is_empty(), fault != 0);
        assert_eq!(root.disposition(), (fault >= 2, false, true));
        let events = world.borrow().events.clone();
        assert!(root.cleanup().is_err());
        assert_eq!(world.borrow().events, events);
    }
}

#[test]
fn cold_static_reentry_swallowed_by_authorizer_permanently_denies_all_effects() {
    let (root, world, auth) = cold_fixture(3);
    root.capture().unwrap();
    let weak = Rc::downgrade(&root);
    *auth.hook.borrow_mut() = Some(Box::new(move || {
        assert!(weak.upgrade().unwrap().cleanup().is_err());
    }));
    assert!(root.cleanup().is_err());
    assert_eq!(world.borrow().objects.filters.len(), 3);
    assert!(!world
        .borrow()
        .events
        .iter()
        .any(|e| e.starts_with("delete:")));
    assert_eq!(root.disposition(), (false, false, true));
}

#[test]
fn cold_static_authorization_callback_failure_is_sticky_in_retained_issuer_itself() {
    let (root, world, _) = cold_fixture(2);
    let result: Result<()> = root.authorized(|_| Err(GuardError::Native(998)));
    assert!(result.is_err());
    assert_eq!(root.disposition(), (false, false, true));
    assert!(root.cleanup().is_err());
    assert!(world.borrow().events.is_empty());
    assert_eq!(world.borrow().objects.filters.len(), 2);
}

#[test]
fn cold_static_root_is_retained_before_open_and_survives_issuer_postflight_loss() {
    let (_, world, auth) = cold_fixture(1);
    let retained = RefCell::new(None);
    auth.after_fault.set(true);
    let result = retain_cold_issuer(
        scope(),
        auth,
        |root| {
            *retained.borrow_mut() = Some(root);
            Ok(())
        },
        || {
            assert!(retained.borrow().is_some());
            Ok(ColdApi(Api(world.clone())))
        },
    );
    assert!(result.is_err());
    let root = retained.borrow().as_ref().unwrap().clone();
    assert!(root.io.borrow().is_some());
    assert!(root.cleanup().is_err());
    assert!(world.borrow().events.is_empty());
}

#[test]
fn cold_static_issuer_rejects_discarded_retention_callback_before_native_open() {
    let (_, world, auth) = cold_fixture(1);
    let opened = Cell::new(false);
    let result = retain_cold_issuer(
        scope(),
        auth,
        |_| Ok(()),
        || {
            opened.set(true);
            Ok(ColdApi(Api(world.clone())))
        },
    );
    assert!(result.is_err());
    assert!(!opened.get());
    assert!(world.borrow().events.is_empty());
    assert_eq!(world.borrow().objects.filters.len(), 1);
}

#[test]
fn cold_static_missing_or_foreign_authority_and_duplicate_capture_never_write() {
    for fault in 0..3 {
        let (root, world, auth) = cold_fixture(2);
        match fault {
            0 => auth.valid.set(false),
            1 => {
                *auth.policies.borrow_mut() = cold_policies(
                    Model::empty(SessionScope {
                        connection_generation: 10,
                        ..scope()
                    })
                    .unwrap(),
                    None,
                )
            }
            _ => {
                root.capture().unwrap();
            }
        }
        assert!(root.capture().is_err());
        assert!(root.cleanup().is_err());
        assert_eq!(world.borrow().objects.filters.len(), 2);
        assert!(!world
            .borrow()
            .events
            .iter()
            .any(|e| e.starts_with("delete:")));
    }
}

#[test]
fn cold_static_pending_prior_and_prospective_base_subsets_are_comparison_only() {
    let (old, world, auth) = cold_fixture(0);
    let expected = pair(None).without_permits().unwrap();
    let expected = expected
        .readback_after(&Model::empty(scope()).unwrap(), &expected.expected)
        .unwrap();
    let mut desired_members = pair(None).members;
    desired_members[1].as_mut().unwrap().identity = identity(44);
    let desired = Model::new(scope(), pair(None).carrier.unwrap(), desired_members, None)
        .unwrap()
        .without_permits()
        .unwrap()
        .inherit_sublayer_weight(&expected)
        .unwrap();
    let pending = crate::member_carrier_guard::ExchangePlan::new(&expected, &desired).unwrap();
    *auth.policies.borrow_mut() = cold_policies(expected.clone(), Some(pending));
    for (i, f) in expected
        .expected
        .filters
        .iter()
        .filter(|f| f.conditions == vec![Condition::EgressIndex(11)])
        .take(2)
        .chain(
            desired
                .expected
                .filters
                .iter()
                .filter(|f| f.conditions == vec![Condition::EgressIndex(44)])
                .take(2),
        )
        .enumerate()
    {
        world.borrow_mut().objects.filters.insert(
            f.key,
            (
                NativeFilter {
                    policy: f.clone(),
                    id: 1200 + i as u64,
                },
                SessionKind::StaticBase,
            ),
        );
    }
    // NEW issuer authenticates the actual pending record, never changes the old
    // original Guard/plan and never imports an old native ID as creator authority.
    drop(old);
    let retained = RefCell::new(None);
    let root = retain_cold_issuer(
        scope(),
        auth,
        |r| {
            *retained.borrow_mut() = Some(r);
            Ok(())
        },
        || Ok(ColdApi(Api(world.clone()))),
    )
    .unwrap();
    root.cleanup().unwrap();
    assert!(world.borrow().objects.filters.is_empty());
    assert_eq!(root.disposition(), (true, true, false));
}

#[test]
fn cold_static_dynamic_block_cannot_be_deleted_through_static_session_or_fallback() {
    let (root, world, _) = cold_fixture(3);
    world
        .borrow_mut()
        .objects
        .filters
        .values_mut()
        .nth(1)
        .unwrap()
        .1 = SessionKind::DynamicPermits;
    // Native policy flags alone do not encode dynamic session ownership. The
    // external SDK's WRONG_SESSION boundary rejects deletion, rolling back ALL
    // earlier staged deletes. No alternate engine is opened/retried.
    root.capture().unwrap();
    assert!(root.cleanup().is_err());
    assert_eq!(world.borrow().objects.filters.len(), 3);
    assert_eq!(root.disposition(), (false, false, true));
    assert!(!world
        .borrow()
        .events
        .iter()
        .any(|e| e.contains("DynamicPermits")));
    assert!(world.borrow().staged.is_none());
}

#[test]
fn cold_static_authority_and_retained_root_failures_never_open_or_mutate() {
    for unwind in [false, true] {
        let (_, world, auth) = cold_fixture(2);
        let retained = RefCell::new(None);
        let opened = Cell::new(false);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            retain_cold_issuer(
                scope(),
                auth,
                |root| {
                    *retained.borrow_mut() = Some(root);
                    assert!(!unwind, "retention callback unwind");
                    Err(GuardError::Conflict)
                },
                || {
                    opened.set(true);
                    Ok(ColdApi(Api(world.clone())))
                },
            )
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert!(!opened.get());
        let root = retained.borrow().as_ref().unwrap().clone();
        assert!(root.cleanup().is_err());
        assert!(world.borrow().events.is_empty());
        assert_eq!(world.borrow().objects.filters.len(), 2);
    }
}

#[test]
fn cold_static_scope_reads_all_48_keys_and_unrelated_layers_objects_remain_untouched() {
    let (root, world, _) = cold_fixture(1);
    world
        .borrow_mut()
        .arbitration_extra
        .push(ArbitrationFilter {
            service_domain: None,
            key: Key([90; 16]),
            id: 12345,
            layer: Layer::AleConnectV6,
            sublayer: Key([91; 16]),
            sublayer_weight: 65535,
            flags: FWPM_FILTER_FLAG_PERSISTENT,
            action: FWP_ACTION_PERMIT,
        });
    root.capture().unwrap();
    let keys = crate::member_carrier_guard::resource_keys(&scope()).unwrap();
    let expected_lookups: Vec<_> = std::iter::once(keys.sublayer).chain(keys.filters).collect();
    assert_eq!(
        world.borrow().lookups,
        [expected_lookups.clone(), expected_lookups].concat()
    );
    root.cleanup().unwrap();
    assert_eq!(world.borrow().arbitration_extra.len(), 1);
    assert_eq!(world.borrow().arbitration_extra[0].id, 12345);
}

#[test]
fn cold_static_equal_model_cannot_hide_changed_protected_context_or_revision() {
    let (root, world, auth) = cold_fixture(2);
    root.capture().unwrap();
    // External private-record boundary changes only context/revision DATA while
    // WFP policies remain equal. There is no metadata-equal new authorization.
    auth.policies.borrow_mut().protected_record.push(9);
    assert!(root.cleanup().is_err());
    assert_eq!(world.borrow().objects.filters.len(), 2);
    assert!(!world
        .borrow()
        .events
        .iter()
        .any(|e| e.starts_with("delete:")));
}

#[test]
fn cold_static_permit_bearing_journal_is_data_but_any_native_permit_denies_cleanup() {
    for native_permit in [false, true] {
        let (_, world, auth) = cold_fixture(3);
        let model = pair(Some(Slot::A));
        let model = model
            .readback_after(&Model::empty(scope()).unwrap(), &model.expected)
            .unwrap();
        if native_permit {
            let permit = model
                .expected
                .filters
                .iter()
                .find(|f| f.action == Action::Permit)
                .unwrap()
                .clone();
            world.borrow_mut().objects.filters.insert(
                permit.key,
                (
                    NativeFilter {
                        policy: permit,
                        id: 7777,
                    },
                    SessionKind::DynamicPermits,
                ),
            );
        }
        *auth.policies.borrow_mut() = cold_policies(model, None);
        let retained = RefCell::new(None);
        let result = retain_cold_issuer(
            scope(),
            auth,
            |r| {
                *retained.borrow_mut() = Some(r);
                Ok(())
            },
            || Ok(ColdApi(Api(world.clone()))),
        );
        if native_permit {
            assert!(result.is_err());
            assert_eq!(world.borrow().objects.filters.len(), 4);
            assert!(!world
                .borrow()
                .events
                .iter()
                .any(|e| e.starts_with("delete:")));
        } else {
            result.unwrap().cleanup().unwrap();
            assert!(world.borrow().objects.filters.is_empty());
        }
    }
}

#[test]
fn cold_static_invalid_pending_plan_or_missing_protected_frame_denies_before_engine_open() {
    for fault in 0..6 {
        let (_, world, auth) = cold_fixture(2);
        let current = pair(None).without_permits().unwrap();
        let current = current
            .readback_after(&Model::empty(scope()).unwrap(), &current.expected)
            .unwrap();
        let desired = Model::empty(scope()).unwrap();
        let mut plan = crate::member_carrier_guard::ExchangePlan::new(&current, &desired).unwrap();
        match fault {
            0 => plan.version = 91,
            1 => plan.expected = desired.clone(),
            2 => plan.withdrawn = desired.clone(),
            3 => plan.base = current.clone(),
            4 => plan.desired = current.clone(),
            _ => {}
        }
        let mut data = cold_policies(current, Some(plan));
        if fault == 5 {
            data.protected_record.clear();
        }
        *auth.policies.borrow_mut() = data;
        let retained = RefCell::new(None);
        let opened = Cell::new(false);
        let result = retain_cold_issuer(
            scope(),
            auth,
            |r| {
                *retained.borrow_mut() = Some(r);
                Ok(())
            },
            || {
                opened.set(true);
                Ok(ColdApi(Api(world.clone())))
            },
        );
        assert!(result.is_err(), "fault {fault}");
        assert!(!opened.get(), "fault {fault}");
        assert!(world.borrow().events.is_empty());
        assert_eq!(world.borrow().objects.filters.len(), 2);
    }
}
#[test]
fn startup_absence_queries_all_native_keys_in_a_readonly_transaction_each_time() {
    let world = Rc::new(RefCell::new(World::default()));
    let mut reader = ScopedGuardAbsence::new(scope(), Api(world.clone())).unwrap();
    let keys = crate::member_carrier_guard::resource_keys(&scope()).unwrap();
    for _ in 0..2 {
        world.borrow_mut().lookups.clear();
        reader.verify(&scope()).unwrap();
        assert_eq!(
            world.borrow().lookups,
            std::iter::once(keys.sublayer)
                .chain(keys.filters)
                .collect::<Vec<_>>()
        );
        assert!(world.borrow().staged.is_none());
    }
    assert_eq!(
        world.borrow().events,
        [
            "begin:StaticBase:true",
            "commit:StaticBase",
            "begin:StaticBase:true",
            "commit:StaticBase"
        ]
    );
    assert_eq!(world.borrow().closed, [false, false]);
}

#[test]
fn terminal_absence_returns_actual_complete_snapshot_and_never_refreshes_failed_reader() {
    let world = Rc::new(RefCell::new(World::default()));
    let mut reader = ScopedGuardAbsence::new(scope(), Api(world.clone())).unwrap();
    let keys = crate::member_carrier_guard::resource_keys(&scope()).unwrap();
    let observed = reader.read_snapshot(&scope()).unwrap();
    assert_eq!(observed, Model::empty(scope()).unwrap().expected);
    assert_eq!(
        world.borrow().lookups,
        std::iter::once(keys.sublayer)
            .chain(keys.filters)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        world.borrow().events,
        ["begin:StaticBase:true", "commit:StaticBase"]
    );
    // Even the last scoped key must be independently queried on a later read.
    let mut f = pair(None).expected.filters[0].clone();
    f.key = keys.filters[47];
    world.borrow_mut().objects.filters.insert(
        f.key,
        (NativeFilter { policy: f, id: 999 }, SessionKind::StaticBase),
    );
    assert!(reader.read_snapshot(&scope()).is_err());
    world.borrow_mut().objects.filters.clear();
    assert!(reader.read_snapshot(&scope()).is_err());
    assert!(reader.verify(&scope()).is_err());
}

#[test]
fn startup_absence_never_adopts_existing_policy_or_rearms_after_uncertainty() {
    for fault in 0..6 {
        let world = Rc::new(RefCell::new(World::default()));
        let mut reader = ScopedGuardAbsence::new(scope(), Api(world.clone())).unwrap();
        let mut expected = scope();
        match fault {
            0 => world.borrow_mut().objects.sublayer = pair(None).expected.sublayer,
            1 => {
                // Orphaned LAST scoped filter must not be hidden by absence of
                // the sublayer or by the coordinator's empty model.
                let keys = crate::member_carrier_guard::resource_keys(&scope()).unwrap();
                let mut f = pair(None).expected.filters[0].clone();
                f.key = keys.filters[47];
                world.borrow_mut().objects.filters.insert(
                    f.key,
                    (
                        NativeFilter {
                            policy: f,
                            id: 9001,
                        },
                        SessionKind::StaticBase,
                    ),
                );
            }
            2 => world.borrow_mut().read_fault = true,
            3 => world.borrow_mut().read_filter_error = true,
            4 => world.borrow_mut().commit_fault = 1,
            5 => expected.connection_generation += 1,
            _ => unreachable!(),
        }
        assert!(reader.verify(&expected).is_err(), "fault {fault}");
        let prior = world.borrow().events.len();
        world.borrow_mut().objects = Objects::default();
        world.borrow_mut().read_fault = false;
        world.borrow_mut().read_filter_error = false;
        world.borrow_mut().commit_fault = 0;
        assert!(
            reader.verify(&scope()).is_err(),
            "must remain retired {fault}"
        );
        assert_eq!(
            world.borrow().events.len(),
            prior,
            "no retry effects {fault}"
        );
        assert!(world
            .borrow()
            .events
            .iter()
            .all(|e| !e.starts_with("add:") && !e.starts_with("delete:")));
    }
}
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
    fn sublayer(&mut self, kind: SessionKind, key: Key) -> Result<Option<Sublayer>> {
        let mut w = self.0.borrow_mut();
        w.lookups.push(key);
        w.query_kinds.push(kind);
        if w.read_fault {
            return Err(GuardError::Native(58));
        }
        Ok(w.staged.as_ref().unwrap().sublayer.clone())
    }
    fn filter(&mut self, kind: SessionKind, key: Key, _: Key) -> Result<Option<NativeFilter>> {
        let mut w = self.0.borrow_mut();
        w.lookups.push(key);
        w.query_kinds.push(kind);
        assert!(!w.panic_locked_filter, "injected locked read unwind");
        if w.read_filter_error {
            return Err(GuardError::Native(60));
        }
        let found = w
            .staged
            .as_ref()
            .unwrap()
            .filters
            .get(&key)
            .map(|(f, _)| f.clone());
        if key == crate::member_carrier_guard::resource_keys(&scope())?.filters[47] {
            if let Some(fault) = w.binding_after_scan.take() {
                w.binding_fault = fault;
            }
        }
        Ok(found)
    }
    fn arbitration(&mut self, kind: SessionKind) -> Result<Vec<ArbitrationFilter>> {
        let mut w = self.0.borrow_mut();
        w.events.push(format!("arbitration:{kind:?}"));
        if w.arbitration_fault {
            return Err(GuardError::Native(61));
        }
        let state = w.staged.as_ref().unwrap();
        let mut filters: Vec<_> = state
            .filters
            .values()
            .map(|(f, _)| ArbitrationFilter {
                service_domain: None,
                key: f.policy.key,
                id: f.id,
                layer: f.policy.layer,
                sublayer: f.policy.sublayer,
                sublayer_weight: state.sublayer.as_ref().unwrap().weight,
                flags: f.policy.flags,
                action: if f.policy.action == Action::Block {
                    FWP_ACTION_BLOCK
                } else {
                    FWP_ACTION_PERMIT
                },
            })
            .collect();
        filters.extend(w.arbitration_extra.clone());
        Ok(filters)
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
        w.events.push("delete:base".into());
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
                    service_domains: Vec::new(),
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
            service_domains: Vec::new(),
            scope,
            carrier: Some(c),
            egress: e,
        })
    }
    fn authorize<N: NativeApi>(
        &mut self,
        kind: SessionKind,
        expected: &Model,
        desired: &Model,
        locked: &mut LockedWfpRead<'_, N>,
    ) -> Result<()> {
        let mut bindings = self.observe(&expected.scope)?;
        let mut w = self.0.borrow_mut();
        assert!(w.staged.is_some());
        w.events.push(format!("authorize:{kind:?}"));
        assert!(!w.panic_authorize, "injected authority unwind");
        if w.denied {
            return Err(GuardError::Conflict);
        }
        if w.read_error_authorize {
            w.read_fault = true;
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
        let fault = w.locked_fault;
        if fault != 0 {
            let state = w.staged.as_mut().unwrap();
            let key = expected.expected.filters[0].key;
            match fault {
                1 => state.filters.get_mut(&key).unwrap().0.id = 99999,
                2 => {
                    state.filters.remove(&key);
                }
                3 => state.filters.get_mut(&key).unwrap().0.policy.weight = 7,
                4 => state
                    .filters
                    .get_mut(&key)
                    .unwrap()
                    .0
                    .policy
                    .conditions
                    .clear(),
                5 => state.sublayer.as_mut().unwrap().weight = 65530,
                6 => {
                    state.sublayer = None;
                }
                7 => {
                    let f = desired
                        .expected
                        .filters
                        .iter()
                        .find(|f| f.action == Action::Permit)
                        .unwrap()
                        .clone();
                    state.filters.insert(
                        f.key,
                        (
                            NativeFilter {
                                policy: f,
                                id: 99999,
                            },
                            SessionKind::StaticBase,
                        ),
                    );
                }
                8 => {
                    let mut other = scope();
                    other.session_id = "11234567-89ab-cdef-0123-456789abcdef".into();
                    state.filters.get_mut(&key).unwrap().0.policy.key =
                        crate::member_carrier_guard::resource_keys(&other)?.filters[0];
                }
                9 => state.filters.get_mut(&key).unwrap().0.id = 0,
                10 => state.filters.get_mut(&key).unwrap().0.policy.sublayer = Key([99; 16]),
                11 => state.sublayer.as_mut().unwrap().key = Key([99; 16]),
                12 => bindings.scope.runtime_generation += 1,
                13 => bindings.carrier.as_mut().unwrap().identity.proof.guid = [99; 16],
                14 => {
                    bindings.carrier.as_mut().unwrap().sources = vec!["10.8.0.3".parse().unwrap()]
                }
                15 => bindings.egress[0].as_mut().unwrap().proof.guid = [98; 16],
                16 => w.panic_locked_filter = true,
                17 => w.read_filter_error = true,
                18 => {
                    let last = crate::member_carrier_guard::resource_keys(&scope())?.filters[47];
                    let f = desired
                        .expected
                        .filters
                        .iter()
                        .find(|f| f.key == last)
                        .unwrap()
                        .clone();
                    state.filters.insert(
                        last,
                        (
                            NativeFilter {
                                policy: f,
                                id: 99999,
                            },
                            SessionKind::StaticBase,
                        ),
                    );
                }
                19 => state.sublayer.as_mut().unwrap().flags = 1,
                20 => state.filters.get_mut(&key).unwrap().0.policy.flags ^= 64,
                21 => bindings.egress[1].as_mut().unwrap().proof.guid = [97; 16],
                _ => unreachable!(),
            }
        }
        let lookup_start = w.lookups.len();
        let catch_failure = w.catch_locked_failure;
        w.events.push("locked:read".into());
        drop(w); // Native reads borrow this same fake boundary, never a Model.
        let actual = if catch_failure {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| locked.snapshot(&bindings)))
                .unwrap_or(Err(GuardError::Conflict))
        } else {
            locked.snapshot(&bindings)
        };
        let mut w = self.0.borrow_mut();
        let lookups = w.lookups[lookup_start..].to_vec();
        w.locked_lookups.push(lookups);
        w.locked_snapshots.push(actual.clone());
        assert!(
            !w.panic_after_locked_read,
            "injected authority unwind after locked read"
        );
        if catch_failure {
            // Deliberately mishandled authority: retry a now-clean read and
            // return success after swallowing the first failure. Guard must
            // still abort rather than turn this into effect permission.
            w.read_fault = false;
            w.panic_locked_filter = false;
            w.read_filter_error = false;
            w.locked_fault = 0;
            drop(w);
            let retry = locked.snapshot(&bindings);
            self.0.borrow_mut().locked_snapshots.push(retry);
            return Ok(());
        }
        actual.map(|_| ())
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
fn permits_require_independent_priority_inventory_before_native_effects() {
    let (mut guard, w) = adapter();
    let model = base(&mut guard);
    let desired = pair(Some(Slot::A)).inherit_sublayer_weight(&model).unwrap();
    w.borrow_mut().events.clear();
    w.borrow_mut().arbitration_fault = true;
    assert!(guard
        .exchange(SessionKind::DynamicPermits, &model, &desired)
        .is_err());
    let world = w.borrow();
    assert!(world.closed[1]);
    assert!(!world
        .events
        .iter()
        .any(|e| e.starts_with("add:") || e.starts_with("delete:")));
    assert_eq!(world.objects.filters.len(), 16);
}

#[test]
fn priority_barrier_rejects_higher_or_equal_hard_permits_and_opaque_callouts() {
    for weight in [65531, 65532, 65535] {
        for action in [
            FWP_ACTION_PERMIT,
            FWP_ACTION_CALLOUT_TERMINATING,
            FWP_ACTION_CALLOUT_UNKNOWN,
            FWP_ACTION_CALLOUT_INSPECTION,
            u32::MAX,
        ] {
            let (mut guard, w) = adapter();
            let model = base(&mut guard);
            let desired = pair(Some(Slot::A)).inherit_sublayer_weight(&model).unwrap();
            w.borrow_mut().events.clear();
            w.borrow_mut().arbitration_extra.push(ArbitrationFilter {
                service_domain: None,
                key: Key([91; 16]),
                id: 9091,
                layer: Layer::AleConnectV4,
                sublayer: Key([92; 16]),
                sublayer_weight: weight,
                flags: FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
                action,
            });
            assert!(
                guard
                    .exchange(SessionKind::DynamicPermits, &model, &desired)
                    .is_err(),
                "weight={weight}, action={action}"
            );
            assert_eq!(w.borrow().objects.filters.len(), 16);
            assert!(!w
                .borrow()
                .events
                .iter()
                .any(|e| e.starts_with("add:") || e.starts_with("delete:")));
            assert!(w.borrow().closed[1]);
        }
    }
}

#[test]
fn priority_barrier_accepts_soft_foreign_policy_without_changing_it() {
    for (weight, flags, action) in [
        (65535, 0, FWP_ACTION_PERMIT),
        (65535, 0, FWP_ACTION_BLOCK),
        (65535, 0, FWP_ACTION_CONTINUE),
        (
            65530,
            FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
            FWP_ACTION_PERMIT,
        ),
        (
            65535,
            FWPM_FILTER_FLAG_DISABLED | FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
            FWP_ACTION_PERMIT,
        ),
    ] {
        let (mut guard, w) = adapter();
        let model = base(&mut guard);
        let desired = pair(Some(Slot::A)).inherit_sublayer_weight(&model).unwrap();
        w.borrow_mut().arbitration_extra.push(ArbitrationFilter {
            service_domain: None,
            key: Key([91; 16]),
            id: 9091,
            layer: Layer::AleConnectV4,
            sublayer: Key([92; 16]),
            sublayer_weight: weight,
            flags,
            action,
        });
        let live = guard
            .exchange(SessionKind::DynamicPermits, &model, &desired)
            .unwrap();
        assert!(live.permits);
        let world = w.borrow();
        assert_eq!(world.arbitration_extra.len(), 1);
        assert_eq!(world.arbitration_extra[0].flags, flags);
        assert_eq!(world.arbitration_extra[0].sublayer_weight, weight);
        assert!(world.events.contains(&"arbitration:DynamicPermits".into()));
    }
}

#[test]
fn priority_inventory_requires_complete_original_ids_layers_flags_and_assigned_priority() {
    let (mut guard, w) = adapter();
    let model = base(&mut guard);
    let mut io = Api(w.clone());
    io.begin(SessionKind::DynamicPermits, false).unwrap();
    let filters = io.arbitration(SessionKind::DynamicPermits).unwrap();
    let ids: BTreeMap<_, _> = filters.iter().map(|f| (f.key, f.id)).collect();
    assert!(validate_arbitration(&scope(), &model.expected, &ids, &filters, &[]).is_ok());
    let domain = crate::member_owner::ServiceDomain {
        app_id: "\\device\\volume\\wireguard.exe\0".encode_utf16().collect(),
        service_sid: [
            vec![1, 6, 0, 0, 0, 0, 0, 5],
            80u32.to_le_bytes().to_vec(),
            vec![7; 20],
        ]
        .concat(),
    };
    let mut service_filters = filters.clone();
    service_filters.push(ArbitrationFilter {
        service_domain: Some(domain.clone()),
        key: Key([91; 16]),
        id: 9091,
        layer: Layer::AleConnectV4,
        sublayer: Key([92; 16]),
        sublayer_weight: u16::MAX,
        flags: FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
        action: FWP_ACTION_PERMIT,
    });
    assert!(validate_arbitration(
        &scope(),
        &model.expected,
        &ids,
        &service_filters,
        &[domain.clone()]
    )
    .is_ok());
    assert!(validate_arbitration(&scope(), &model.expected, &ids, &service_filters, &[]).is_err());
    for fault in 0..4 {
        let mut changed = service_filters.clone();
        let foreign = changed.last_mut().unwrap();
        match fault {
            0 => foreign.service_domain = None,
            1 => foreign.service_domain.as_mut().unwrap().service_sid[31] ^= 1,
            2 => foreign.service_domain.as_mut().unwrap().app_id[1] ^= 1,
            _ => foreign.layer = Layer::ForwardV4,
        }
        assert!(
            validate_arbitration(&scope(), &model.expected, &ids, &changed, &[domain.clone()])
                .is_err()
        );
    }
    for fault in 0..10 {
        let mut changed = filters.clone();
        match fault {
            0 => {
                changed.pop();
            }
            1 => changed.push(changed[0].clone()),
            2 => changed[0].id = 0,
            3 => changed[0].id += 99999,
            4 => changed[0].layer = Layer::AleConnectV6,
            5 => changed[0].flags ^= FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
            6 => changed[0].sublayer_weight += 1,
            7 => changed[0].sublayer = Key([92; 16]),
            8 => changed[0].key = Key([91; 16]),
            _ => changed[0].action = FWP_ACTION_PERMIT,
        }
        assert!(
            validate_arbitration(&scope(), &model.expected, &ids, &changed, &[]).is_err(),
            "fault={fault}"
        );
    }
    io.abort(SessionKind::DynamicPermits).unwrap();
}

#[test]
fn priority_read_failure_never_blocks_independent_permit_withdrawal() {
    let (mut guard, w) = adapter();
    let base = base(&mut guard);
    let desired = pair(Some(Slot::A)).inherit_sublayer_weight(&base).unwrap();
    let live = guard
        .exchange(SessionKind::DynamicPermits, &base, &desired)
        .unwrap();
    w.borrow_mut().arbitration_fault = true;
    w.borrow_mut().events.clear();
    let no_permits = live.without_permits().unwrap();
    guard
        .exchange(SessionKind::DynamicPermits, &live, &no_permits)
        .unwrap();
    assert!(!w
        .borrow()
        .events
        .iter()
        .any(|e| e.starts_with("arbitration:")));
    assert!(w
        .borrow()
        .objects
        .filters
        .values()
        .all(|(f, _)| f.policy.action == Action::Block));
}

#[test]
fn live_readback_rechecks_priority_and_closes_only_own_dynamic_session_on_conflict() {
    let (mut guard, w) = adapter();
    let model = base(&mut guard);
    let desired = pair(Some(Slot::A)).inherit_sublayer_weight(&model).unwrap();
    guard
        .exchange(SessionKind::DynamicPermits, &model, &desired)
        .unwrap();
    w.borrow_mut().arbitration_fault = true;
    assert!(guard.snapshot().is_err());
    assert!(w.borrow().closed[1]);
    assert!(!w.borrow().closed[0]);
    assert_eq!(w.borrow().objects.filters.len(), 16);
}

#[test]
fn snapshot_brackets_the_whole_native_inventory_with_independent_owners() {
    let world = Rc::new(RefCell::new(World::default()));
    let mut io = Api(world.clone());
    let c_only = Bindings {
        service_domains: Vec::new(),
        scope: scope(),
        carrier: pair(None).carrier,
        egress: [None, None],
    };
    io.begin(SessionKind::StaticBase, true).unwrap();
    let observed = read_native_snapshot(
        &mut io,
        &c_only,
        &scope(),
        SessionKind::StaticBase,
        &BTreeMap::new(),
    )
    .unwrap();
    io.commit(SessionKind::StaticBase).unwrap();
    assert_eq!(observed, Model::empty(scope()).unwrap().expected);
    assert_eq!(world.borrow().lookups.len(), 49);
    for fault in 0..12 {
        let mut changed = Bindings {
            service_domains: Vec::new(),
            scope: c_only.scope.clone(),
            carrier: c_only.carrier.clone(),
            egress: c_only.egress.clone(),
        };
        let c = changed.carrier.as_mut().unwrap();
        match fault {
            0 => changed.scope.connection_generation = 0,
            1 => c.identity.scope.runtime_generation += 1,
            2 => c.identity.proof.index = 0,
            3 => c.identity.proof.luid = 0,
            4 => c.identity.proof.guid = [0; 16],
            5 => c.sources.clear(),
            6 => c.sources = vec!["127.0.0.1".parse().unwrap()],
            7 => c.sources = vec!["10.8.0.2".parse().unwrap(), "10.8.0.3".parse().unwrap()],
            8 => c.sources = vec!["fd00::2".parse().unwrap(), "10.8.0.2".parse().unwrap()],
            9 => changed.egress[0] = Some(c.identity.clone()),
            10 => {
                changed.egress = pair(None).members.map(|m| m.map(|m| m.identity));
                changed.carrier = None;
            }
            11 => {
                changed.carrier = None;
                changed.scope.connection_generation = 0;
            }
            _ => unreachable!(),
        }
        assert!(
            validate_bindings(&changed.scope, &changed).is_err(),
            "fault {fault}"
        );
    }
    for installed in [false, true] {
        for fault in [1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12] {
            let (mut guard, w) = adapter();
            if installed {
                base(&mut guard);
            }
            w.borrow_mut().binding_after_scan = Some(fault);
            assert!(
                guard.snapshot().is_err(),
                "installed={installed}, fault={fault}"
            );
            assert!(w.borrow().closed[1]);
            w.borrow_mut().binding_fault = 0;
            let empty = Model::empty(scope()).unwrap();
            assert!(guard
                .exchange(SessionKind::StaticBase, &empty, &pair(None))
                .is_err());
        }
    }
}

#[test]
fn inventory_owner_change_before_write_authorization_never_stages_effects() {
    for fault in [1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12] {
        let (mut guard, w) = adapter();
        w.borrow_mut().binding_after_scan = Some(fault);
        let empty = Model::empty(scope()).unwrap();
        assert!(guard
            .exchange(SessionKind::StaticBase, &empty, &pair(None))
            .is_err());
        assert!(!w
            .borrow()
            .events
            .iter()
            .any(|e| e.starts_with("add:") || e.starts_with("delete:")));
        assert!(!w
            .borrow()
            .events
            .iter()
            .any(|e| e.starts_with("authorize:")));
        assert!(w.borrow().objects.sublayer.is_none());
        assert!(w.borrow().closed[1]);
    }
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

// A read failure during authority must be detected before the first permit add,
// rather than only by the guard's reconstruction after effects have been staged.
#[test]
fn locked_read_error_aborts_before_any_new_native_effects() {
    let (mut guard, w) = adapter();
    let model = base(&mut guard);
    let desired = pair(Some(Slot::A)).inherit_sublayer_weight(&model).unwrap();
    w.borrow_mut().events.clear();
    w.borrow_mut().read_error_authorize = true;
    assert_eq!(
        guard.exchange(SessionKind::DynamicPermits, &model, &desired),
        Err(GuardError::Native(58))
    );
    let world = w.borrow();
    assert!(!world
        .events
        .iter()
        .any(|e| e.starts_with("add:") || e.starts_with("delete:")));
    assert!(world.staged.is_none());
    assert!(world.events.contains(&"abort:DynamicPermits".into()));
    assert!(world.closed[1]);
    assert_eq!(world.objects.filters.len(), 16);
    assert_eq!(
        world.locked_snapshots.last(),
        Some(&Err(GuardError::Native(58)))
    );
}

#[test]
fn locked_filter_query_error_closes_prior_permits_before_any_delete_effect() {
    let (mut guard, w) = adapter();
    let model = base(&mut guard);
    let desired = pair(Some(Slot::A)).inherit_sublayer_weight(&model).unwrap();
    let live = guard
        .exchange(SessionKind::DynamicPermits, &model, &desired)
        .unwrap();
    {
        let mut world = w.borrow_mut();
        world.events.clear();
        world.locked_fault = 17;
    }
    assert_eq!(
        guard.exchange(
            SessionKind::DynamicPermits,
            &live,
            &live.without_permits().unwrap()
        ),
        Err(GuardError::Native(60))
    );
    let world = w.borrow();
    assert_eq!(
        world.locked_snapshots.last(),
        Some(&Err(GuardError::Native(60)))
    );
    assert!(world.staged.is_none());
    assert!(world.closed[1]);
    assert!(!world.closed[0]);
    assert_eq!(world.objects.filters.len(), 16);
    assert!(!world
        .events
        .iter()
        .any(|e| e.starts_with("add:") || e.starts_with("delete:")));
}

#[test]
fn locked_read_failure_caught_by_authority_cannot_be_cleared_by_successful_retry() {
    for fault in [0, 16, 17] {
        let (mut guard, w) = adapter();
        let model = base(&mut guard);
        let desired = pair(Some(Slot::A)).inherit_sublayer_weight(&model).unwrap();
        {
            let mut world = w.borrow_mut();
            world.events.clear();
            world.read_error_authorize = fault == 0;
            world.locked_fault = fault;
            world.catch_locked_failure = true;
        }
        assert_eq!(
            guard.exchange(SessionKind::DynamicPermits, &model, &desired),
            Err(GuardError::Conflict)
        );
        let world = w.borrow();
        assert!(world.locked_snapshots[1].is_err());
        assert_eq!(world.locked_snapshots[2], Ok(model.expected));
        assert!(world.staged.is_none());
        assert!(world.closed[1]);
        assert_eq!(world.objects.filters.len(), 16);
        assert!(!world
            .events
            .iter()
            .any(|e| e.starts_with("add:") || e.starts_with("delete:")));
    }
}

// Copying expected Model data, omitting an inventory key or adopting a returned
// ID would allow these faults to pass the authority window before effects.
#[test]
fn locked_read_rejects_current_changed_missing_foreign_and_extra_scoped_objects_before_effects() {
    for (fault, label) in [
        (1, "foreign replacement ID"),
        (2, "missing owned filter"),
        (3, "changed filter weight"),
        (4, "changed conditions"),
        (5, "changed assigned priority"),
        (6, "missing sublayer"),
        (7, "extra scoped permit ID"),
        (8, "foreign scope key returned for owned key"),
        (9, "zero ID"),
        (10, "foreign filter sublayer"),
        (11, "foreign sublayer key"),
        (12, "comparison scope drift"),
        (13, "comparison carrier GUID drift"),
        (14, "comparison C source drift"),
        (15, "comparison A GUID drift"),
        (18, "extra ID at last scoped key"),
        (19, "changed sublayer flags"),
        (20, "changed filter flags"),
        (21, "comparison B GUID drift"),
    ] {
        let (mut guard, w) = adapter();
        let model = base(&mut guard);
        let desired = pair(Some(Slot::A)).inherit_sublayer_weight(&model).unwrap();
        {
            let mut world = w.borrow_mut();
            world.events.clear();
            world.locked_fault = fault;
        }
        assert_eq!(
            guard.exchange(SessionKind::DynamicPermits, &model, &desired),
            Err(GuardError::Conflict),
            "{label}"
        );
        {
            let world = w.borrow();
            assert_eq!(
                world.locked_snapshots.last(),
                Some(&Err(GuardError::Conflict)),
                "{label}"
            );
            assert!(
                !world
                    .events
                    .iter()
                    .any(|e| e.starts_with("add:") || e.starts_with("delete:")),
                "{label}"
            );
            assert!(world.staged.is_none(), "{label}");
            assert!(world.closed[1], "{label}");
            assert_eq!(world.objects.filters.len(), 16, "{label}");
            assert_eq!(
                world
                    .events
                    .iter()
                    .filter(|e| e.starts_with("begin:"))
                    .count(),
                1,
                "{label}"
            );
        }
        w.borrow_mut().locked_fault = 0;
        assert!(
            guard
                .exchange(SessionKind::DynamicPermits, &model, &desired)
                .is_err(),
            "{label}: terminal write fence"
        );
    }
}

// Exact live ID checks must accept ordinary retained objects, read ALL scoped
// keys and use only the already active engine transaction for every window.
#[test]
fn locked_read_reads_exact_current_native_inventory_in_the_same_transaction() {
    let (mut guard, w) = adapter();
    let model = base(&mut guard);
    let desired = pair(Some(Slot::A)).inherit_sublayer_weight(&model).unwrap();
    w.borrow_mut().events.clear();
    w.borrow_mut().query_kinds.clear();
    let live = guard
        .exchange(SessionKind::DynamicPermits, &model, &desired)
        .unwrap();
    let world = w.borrow();
    assert_eq!(
        world.locked_snapshots[0],
        Ok(Model::empty(scope()).unwrap().expected)
    );
    assert_eq!(world.locked_snapshots[1], Ok(model.expected));
    let keys = crate::member_carrier_guard::resource_keys(&scope()).unwrap();
    let inventory: Vec<_> = std::iter::once(keys.sublayer).chain(keys.filters).collect();
    assert_eq!(inventory.len(), 49);
    assert_eq!(world.locked_lookups, vec![inventory.clone(), inventory]);
    assert!(world.query_kinds[..147]
        .iter()
        .all(|k| *k == SessionKind::DynamicPermits));
    assert!(world.query_kinds[147..]
        .iter()
        .all(|k| *k == SessionKind::StaticBase));
    assert_eq!(world.query_kinds.len(), 196);
    assert_eq!(
        world
            .events
            .iter()
            .filter(|e| e.starts_with("begin:"))
            .count(),
        2
    );
    assert_eq!(live.expected.filters.len(), 32);
    assert_eq!(live.assigned_sublayer_weight, Some(65531));
}

// A caller catching either native-read or authority unwinding must not leave a
// transaction open, retain permits or regain permission to write.
#[test]
fn locked_read_and_authority_unwinds_abort_close_permits_and_fence_resume() {
    for native_read in [false, true] {
        let (mut guard, w) = adapter();
        let model = base(&mut guard);
        let desired = pair(Some(Slot::A)).inherit_sublayer_weight(&model).unwrap();
        let live = guard
            .exchange(SessionKind::DynamicPermits, &model, &desired)
            .unwrap();
        let withdrawn = live.without_permits().unwrap();
        {
            let mut world = w.borrow_mut();
            world.events.clear();
            world.locked_fault = if native_read { 16 } else { 0 };
            world.panic_after_locked_read = !native_read;
        }
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = guard.exchange(SessionKind::DynamicPermits, &live, &withdrawn);
        }))
        .is_err());
        {
            let world = w.borrow();
            assert!(world.staged.is_none());
            assert!(world.events.contains(&"abort:DynamicPermits".into()));
            assert!(world.closed[1]);
            assert!(!world.closed[0]);
            assert_eq!(world.objects.filters.len(), 16);
            assert!(world
                .objects
                .filters
                .values()
                .all(|(f, _)| f.policy.action == Action::Block));
            assert!(!world
                .events
                .iter()
                .any(|e| e.starts_with("add:") || e.starts_with("delete:")));
        }
        {
            let mut world = w.borrow_mut();
            world.locked_fault = 0;
            world.panic_locked_filter = false;
            world.panic_after_locked_read = false;
        }
        assert!(guard
            .exchange(SessionKind::DynamicPermits, &live, &withdrawn)
            .is_err());
    }
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
    // Pinned SDK WireGuard hard permit: app ID plus exactly one service
    // ALLOW/MATCH_FILTER ACE. Any widened/opaque descriptor fails closed.
    let mut app_bytes: Vec<u8> = "\\device\\volume\\wireguard.exe\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let mut descriptor = [
        vec![
            1, 0, 4, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 2, 0, 48, 0, 1, 0, 0, 0,
            0, 0, 40, 0, 1, 0, 0, 0,
        ],
        vec![1, 6, 0, 0, 0, 0, 0, 5],
        80u32.to_le_bytes().to_vec(),
        vec![7; 20],
    ]
    .concat();
    let mut app = FWP_BYTE_BLOB {
        size: app_bytes.len() as u32,
        data: app_bytes.as_mut_ptr(),
    };
    let mut user = FWP_BYTE_BLOB {
        size: descriptor.len() as u32,
        data: descriptor.as_mut_ptr(),
    };
    let mut conditions = [
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: &mut app },
            },
        },
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_USER_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_SECURITY_DESCRIPTOR_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    byteBlob: &mut user,
                },
            },
        },
    ];
    let raw = FWPM_FILTER0 {
        flags: FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
        action: FWPM_ACTION0 {
            r#type: FWP_ACTION_PERMIT,
            ..Default::default()
        },
        numFilterConditions: 2,
        filterCondition: conditions.as_mut_ptr(),
        ..Default::default()
    };
    let exact = service_filter_domain(&raw, Layer::AleConnectV4).unwrap();
    assert_eq!(exact.service_sid, descriptor[36..]);
    assert!(service_filter_domain(&raw, Layer::AleConnectV6).is_some());
    assert!(service_filter_domain(&raw, Layer::ForwardV4).is_none());
    for (offset, byte) in descriptor.clone().into_iter().take(48).enumerate() {
        descriptor[offset] = byte ^ 1;
        assert!(
            service_filter_domain(&raw, Layer::AleConnectV4).is_none(),
            "offset={offset}"
        );
        descriptor[offset] = byte;
    }
    conditions[1].conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
    assert!(service_filter_domain(&raw, Layer::AleConnectV4).is_none());
    conditions[1].conditionValue.r#type = FWP_SECURITY_DESCRIPTOR_TYPE;
    conditions[1].matchType = FWP_MATCH_NOT_EQUAL;
    assert!(service_filter_domain(&raw, Layer::AleConnectV4).is_none());
    conditions[1].matchType = FWP_MATCH_EQUAL;
    conditions[1].fieldKey = FWPM_CONDITION_ALE_APP_ID;
    assert!(service_filter_domain(&raw, Layer::AleConnectV4).is_none());
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

#[test]
fn adapter_failed_close_or_foreign_static_allow_keeps_exact_absence_unconfirmed() {
    for foreign in [false, true] {
        let (mut guard, w) = adapter();
        let model = base(&mut guard);
        let desired = pair(Some(Slot::A)).inherit_sublayer_weight(&model).unwrap();
        guard
            .exchange(SessionKind::DynamicPermits, &model, &desired)
            .unwrap();
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
        assert!(guard.snapshot().is_err());
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

#[test]
fn adapter_retired_base_cleanup_after_rundown_never_revives_forward_writes() {
    for denied in [false, true] {
        let (mut guard, w) = adapter();
        let model = base(&mut guard);
        guard.close_permits().unwrap();
        assert!(guard
            .exchange(SessionKind::StaticBase, &model, &model)
            .is_err());
        w.borrow_mut().denied = denied;
        let result = guard.exchange_retired_base(&model);
        if denied {
            assert!(result.is_err());
            assert_eq!(w.borrow().objects.filters.len(), 16);
        } else {
            let empty = Model::empty(scope()).unwrap();
            assert_eq!(result.unwrap(), empty);
            assert_eq!(guard.snapshot().unwrap(), empty.expected);
            assert!(w.borrow().objects.filters.is_empty());
            assert!(guard
                .exchange(SessionKind::StaticBase, &empty, &model)
                .is_err());
        }
    }
}
