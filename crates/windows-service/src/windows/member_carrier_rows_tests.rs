// Standalone host harness uses the actual windows-sys rows; no IP Helper effects.
#![cfg_attr(not(windows), allow(dead_code))]

// These offsets are checked independently by cached SDK C _Static_asserts
// targeting x86_64-pc-windows-msvc, and again by strict MSVC test compilation.
// Neither native padding nor inactive union bytes are serialized by the codec.
#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(std::mem::size_of::<MIB_UNICASTIPADDRESS_ROW>() == 80);
    assert!(std::mem::align_of::<MIB_UNICASTIPADDRESS_ROW>() == 8);
    assert!(std::mem::size_of::<MIB_IPINTERFACE_ROW>() == 168);
    assert!(std::mem::align_of::<MIB_IPINTERFACE_ROW>() == 8);
    assert!(std::mem::offset_of!(MIB_UNICASTIPADDRESS_ROW, Address) == 0);
    assert!(std::mem::offset_of!(MIB_UNICASTIPADDRESS_ROW, InterfaceLuid) == 32);
    assert!(std::mem::offset_of!(MIB_UNICASTIPADDRESS_ROW, InterfaceIndex) == 40);
    assert!(std::mem::offset_of!(MIB_UNICASTIPADDRESS_ROW, PrefixOrigin) == 44);
    assert!(std::mem::offset_of!(MIB_UNICASTIPADDRESS_ROW, SuffixOrigin) == 48);
    assert!(std::mem::offset_of!(MIB_UNICASTIPADDRESS_ROW, ValidLifetime) == 52);
    assert!(std::mem::offset_of!(MIB_UNICASTIPADDRESS_ROW, PreferredLifetime) == 56);
    assert!(std::mem::offset_of!(MIB_UNICASTIPADDRESS_ROW, OnLinkPrefixLength) == 60);
    assert!(std::mem::offset_of!(MIB_UNICASTIPADDRESS_ROW, SkipAsSource) == 61);
    assert!(std::mem::offset_of!(MIB_UNICASTIPADDRESS_ROW, DadState) == 64);
    assert!(std::mem::offset_of!(MIB_UNICASTIPADDRESS_ROW, ScopeId) == 68);
    assert!(std::mem::offset_of!(MIB_UNICASTIPADDRESS_ROW, CreationTimeStamp) == 72);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, Family) == 0);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, InterfaceLuid) == 8);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, InterfaceIndex) == 16);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, MaxReassemblySize) == 20);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, InterfaceIdentifier) == 24);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, MinRouterAdvertisementInterval) == 32);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, MaxRouterAdvertisementInterval) == 36);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, AdvertisingEnabled) == 40);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, ForwardingEnabled) == 41);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, WeakHostSend) == 42);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, WeakHostReceive) == 43);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, UseAutomaticMetric) == 44);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, UseNeighborUnreachabilityDetection) == 45);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, ManagedAddressConfigurationSupported) == 46);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, OtherStatefulConfigurationSupported) == 47);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, AdvertiseDefaultRoute) == 48);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, RouterDiscoveryBehavior) == 52);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, DadTransmits) == 56);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, BaseReachableTime) == 60);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, RetransmitTime) == 64);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, PathMtuDiscoveryTimeout) == 68);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, LinkLocalAddressBehavior) == 72);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, LinkLocalAddressTimeout) == 76);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, ZoneIndices) == 80);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, SitePrefixLength) == 144);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, Metric) == 148);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, NlMtu) == 152);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, Connected) == 156);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, SupportsWakeUpPatterns) == 157);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, SupportsNeighborDiscovery) == 158);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, SupportsRouterDiscovery) == 159);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, ReachableTime) == 160);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, TransmitOffload) == 164);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, ReceiveOffload) == 165);
    assert!(std::mem::offset_of!(MIB_IPINTERFACE_ROW, DisableDefaultRoutes) == 166);
    assert!(std::mem::size_of::<SOCKADDR_IN>() == 16);
    assert!(std::mem::offset_of!(SOCKADDR_IN, sin_family) == 0);
    assert!(std::mem::offset_of!(SOCKADDR_IN, sin_port) == 2);
    assert!(std::mem::offset_of!(SOCKADDR_IN, sin_addr) == 4);
    assert!(std::mem::offset_of!(SOCKADDR_IN, sin_zero) == 8);
    assert!(std::mem::size_of::<SOCKADDR_INET>() == 28);
};
#[cfg(not(windows))]
#[path = "../member_carrier_rows.rs"]
mod member_carrier_rows;
#[cfg(not(windows))]
#[path = "member_carrier_rows.rs"]
mod native;
#[cfg(windows)]
use super::*;
#[cfg(not(windows))]
use native::*;
#[cfg(not(windows))]
use windows_sys::Win32::{NetworkManagement::IpHelper::*, Networking::WinSock::*};
#[test]
fn native_address_status_treats_only_exact_not_found_as_absence() {
    assert_eq!(address_status(0), Ok(true));
    assert_eq!(address_status(1168), Ok(false));
    for status in [2, 5, 87, 50, 5010, u32::MAX] {
        assert!(address_status(status).is_err());
    }
}
#[test]
fn native_identity_reconstruction_uses_canonical_full_guid_alias_luid_index_and_virtual_type() {
    let mut row = MIB_IF_ROW2::default();
    row.InterfaceLuid.Value = 3300;
    row.InterfaceIndex = 33;
    row.Type = 53;
    row.InterfaceGuid = windows_sys::core::GUID {
        data1: 0x01234567,
        data2: 0x89ab,
        data3: 0xcdef,
        data4: [1, 2, 3, 4, 5, 6, 7, 8],
    };
    for (i, c) in "owned-C".encode_utf16().enumerate() {
        row.Alias[i] = c;
    }
    let id = decode_identity(&row).unwrap();
    assert_eq!(
        id.guid,
        [1, 35, 69, 103, 137, 171, 205, 239, 1, 2, 3, 4, 5, 6, 7, 8]
    );
    assert_eq!(id.name, "owned-C");
    assert_eq!(
        id.key,
        RowKey {
            luid: 3300,
            index: 33
        }
    );
    for mutate in [
        (|r: &mut MIB_IF_ROW2| r.InterfaceAndOperStatusFlags._bitfield = 0x80)
            as fn(&mut MIB_IF_ROW2),
        |r| r.InterfaceAndOperStatusFlags._bitfield = 2,
        |r| r.InterfaceAndOperStatusFlags._bitfield = 1,
        |r| r.Type = 6,
        |r| r.Alias = [65; 257],
        |r| r.Alias[0] = 0,
        |r| r.InterfaceIndex = 0,
    ] {
        let mut bad = row;
        mutate(&mut bad);
        assert!(decode_identity(&bad).is_err());
    }
}

use nelomai_contracts::RuntimeSlot;

#[test]
fn successful_durable_confirmation_requires_fresh_native_readback_before_return() {
    let fake = Fake::new();
    let mut owner = fake.owner();
    fake.0.borrow_mut().drift_on_confirmation = true;
    assert!(
        owner.change_interface(weak()).is_err(),
        "durable ACK is not a fresh native snapshot"
    );
    assert_eq!(fake.0.borrow().effects, 1);
    assert!(owner.create_address(address_policy()).is_err());
    assert!(owner.stop().is_err());
    assert_eq!(fake.0.borrow().effects, 1);
}

#[test]
fn closing_record_cannot_publish_new_weak_host_policy_or_lose_created_address_history() {
    let fake = Fake::new();
    let _owner = fake.owner();
    let saved = fake.0.borrow().saved.clone().unwrap();
    let mut closing = saved.clone();
    closing.phase = Phase::Closing;
    closing.pending = Some(Pending {
        before: closing.current.clone(),
        target: Target::Interface(weak()),
    });
    assert!(
        closing.encode().is_err(),
        "closing intent must be exact baseline restoration, never resume"
    );
    let mut impossible = saved;
    impossible.creation = Some(decode_address(&address_raw()).unwrap());
    assert!(
        impossible.encode().is_err(),
        "captured create receipt cannot discard its still-owned address"
    );
}
use std::{cell::RefCell, rc::Rc};

#[test]
fn every_writable_field_is_preserved_and_foreign_native_cas_drift_is_never_overwritten() {
    let cases: [fn(&mut MIB_IPINTERFACE_ROW); 21] = [
        |r| r.AdvertisingEnabled = !r.AdvertisingEnabled,
        |r| r.ForwardingEnabled = !r.ForwardingEnabled,
        |r| r.WeakHostSend = !r.WeakHostSend,
        |r| r.WeakHostReceive = !r.WeakHostReceive,
        |r| r.UseAutomaticMetric = !r.UseAutomaticMetric,
        |r| r.UseNeighborUnreachabilityDetection = !r.UseNeighborUnreachabilityDetection,
        |r| r.ManagedAddressConfigurationSupported = !r.ManagedAddressConfigurationSupported,
        |r| r.OtherStatefulConfigurationSupported = !r.OtherStatefulConfigurationSupported,
        |r| r.AdvertiseDefaultRoute = !r.AdvertiseDefaultRoute,
        |r| r.RouterDiscoveryBehavior = 0,
        |r| r.DadTransmits += 1,
        |r| r.BaseReachableTime += 1,
        |r| r.RetransmitTime += 1,
        |r| r.PathMtuDiscoveryTimeout += 1,
        |r| r.LinkLocalAddressBehavior = 1,
        |r| r.LinkLocalAddressTimeout += 1,
        |r| r.ZoneIndices[15] += 1,
        |r| r.SitePrefixLength = 1,
        |r| r.Metric += 1,
        |r| r.NlMtu += 1,
        |r| r.DisableDefaultRoutes = !r.DisableDefaultRoutes,
    ];
    for (i, mutate) in cases.into_iter().enumerate() {
        let mut raw = interface_raw();
        mutate(&mut raw);
        let p = decode_interface(&raw).unwrap().policy;
        if p.site_prefix_length == 0 {
            let encoded = interface_input(
                MIB_IPINTERFACE_ROW::default(),
                RowKey {
                    luid: 3300,
                    index: 33,
                },
                &p,
            )
            .unwrap();
            assert_eq!(
                encoded.AdvertisingEnabled, raw.AdvertisingEnabled,
                "input AdvertisingEnabled, case {i}"
            );
            assert_eq!(
                encoded.ForwardingEnabled, raw.ForwardingEnabled,
                "input ForwardingEnabled, case {i}"
            );
            assert_eq!(
                encoded.WeakHostSend, raw.WeakHostSend,
                "input WeakHostSend, case {i}"
            );
            assert_eq!(
                encoded.WeakHostReceive, raw.WeakHostReceive,
                "input WeakHostReceive, case {i}"
            );
            assert_eq!(
                encoded.UseAutomaticMetric, raw.UseAutomaticMetric,
                "input UseAutomaticMetric, case {i}"
            );
            assert_eq!(
                encoded.UseNeighborUnreachabilityDetection, raw.UseNeighborUnreachabilityDetection,
                "input UseNeighborUnreachabilityDetection, case {i}"
            );
            assert_eq!(
                encoded.ManagedAddressConfigurationSupported,
                raw.ManagedAddressConfigurationSupported,
                "input ManagedAddressConfigurationSupported, case {i}"
            );
            assert_eq!(
                encoded.OtherStatefulConfigurationSupported,
                raw.OtherStatefulConfigurationSupported,
                "input OtherStatefulConfigurationSupported, case {i}"
            );
            assert_eq!(
                encoded.AdvertiseDefaultRoute, raw.AdvertiseDefaultRoute,
                "input AdvertiseDefaultRoute, case {i}"
            );
            assert_eq!(
                encoded.RouterDiscoveryBehavior, raw.RouterDiscoveryBehavior,
                "input RouterDiscoveryBehavior, case {i}"
            );
            assert_eq!(
                encoded.DadTransmits, raw.DadTransmits,
                "input DadTransmits, case {i}"
            );
            assert_eq!(
                encoded.BaseReachableTime, raw.BaseReachableTime,
                "input BaseReachableTime, case {i}"
            );
            assert_eq!(
                encoded.RetransmitTime, raw.RetransmitTime,
                "input RetransmitTime, case {i}"
            );
            assert_eq!(
                encoded.PathMtuDiscoveryTimeout, raw.PathMtuDiscoveryTimeout,
                "input PathMtuDiscoveryTimeout, case {i}"
            );
            assert_eq!(
                encoded.LinkLocalAddressBehavior, raw.LinkLocalAddressBehavior,
                "input LinkLocalAddressBehavior, case {i}"
            );
            assert_eq!(
                encoded.LinkLocalAddressTimeout, raw.LinkLocalAddressTimeout,
                "input LinkLocalAddressTimeout, case {i}"
            );
            assert_eq!(
                encoded.ZoneIndices, raw.ZoneIndices,
                "input ZoneIndices, case {i}"
            );
            assert_eq!(
                encoded.SitePrefixLength, raw.SitePrefixLength,
                "input SitePrefixLength, case {i}"
            );
            assert_eq!(encoded.Metric, raw.Metric, "input Metric, case {i}");
            assert_eq!(encoded.NlMtu, raw.NlMtu, "input NlMtu, case {i}");
            assert_eq!(
                encoded.DisableDefaultRoutes, raw.DisableDefaultRoutes,
                "input DisableDefaultRoutes, case {i}"
            );
        }
        let fake = Fake::new();
        let mut owner = fake.owner();
        mutate(&mut fake.0.borrow_mut().ip);
        assert!(
            owner.change_interface(weak()).is_err(),
            "foreign field case {i}"
        );
        assert_eq!(fake.0.borrow().effects, 0);
    }
}
#[test]
fn all_documented_origins_finite_lifetimes_and_full_observed_scope_are_not_projected_away() {
    for prefix in 0..=4 {
        for suffix in 0..=5 {
            let mut raw = address_raw();
            raw.PrefixOrigin = prefix;
            raw.SuffixOrigin = suffix;
            raw.ValidLifetime = 7200;
            raw.PreferredLifetime = 3600;
            raw.SkipAsSource = true;
            raw.OnLinkPrefixLength = 24;
            raw.ScopeId.Anonymous.Value = 0x12345678;
            let row = decode_address(&raw).unwrap();
            assert_eq!(row.policy.prefix_origin, prefix);
            assert_eq!(row.policy.suffix_origin, suffix);
            assert_eq!(row.policy.valid_lifetime, 7200);
            assert_eq!(row.policy.preferred_lifetime, 3600);
            assert_eq!(row.policy.on_link_prefix_length, 24);
            assert!(row.policy.skip_as_source);
            assert_eq!(row.observed.scope_id, 0x12345678);
            let encoded =
                address_input(MIB_UNICASTIPADDRESS_ROW::default(), row.key, &row.policy).unwrap();
            assert_eq!(encoded.PrefixOrigin, prefix);
            assert_eq!(encoded.SuffixOrigin, suffix);
            assert_eq!(encoded.ValidLifetime, 7200);
            assert_eq!(encoded.PreferredLifetime, 3600);
            assert_eq!(encoded.OnLinkPrefixLength, 24);
            assert!(encoded.SkipAsSource);
            assert_eq!(unsafe { encoded.ScopeId.Anonymous.Value }, 0);
        }
    }
}
#[test]
fn unsupported_creation_attributes_fail_before_intent_and_native_effects() {
    let cases: [fn(&mut AddressPolicy); 6] = [
        |p| p.prefix_origin = 3,
        |p| p.suffix_origin = 3,
        |p| p.skip_as_source = true,
        |p| p.valid_lifetime = 600,
        |p| p.preferred_lifetime = 600,
        |p| p.on_link_prefix_length = 24,
    ];
    for mutate in cases {
        let fake = Fake::new();
        let mut owner = fake.owner();
        let mut policy = address_policy();
        mutate(&mut policy);
        assert!(owner.create_address(policy).is_err());
        assert_eq!(fake.0.borrow().effects, 0);
        assert_eq!(fake.0.borrow().saved.as_ref().unwrap().revision, 1);
    }
}
#[test]
fn unsupported_ipv4_site_prefix_baseline_is_not_silently_zeroed_on_set() {
    let fake = Fake::new();
    fake.0.borrow_mut().ip.SitePrefixLength = 255;
    let mut owner = fake.owner();
    let mut desired = owner.snapshot().unwrap().interface.policy;
    desired.weak_host_send = true;
    assert!(owner.change_interface(desired).is_err());
    assert_eq!(fake.0.borrow().effects, 0);
    assert_eq!(
        fake.0
            .borrow()
            .saved
            .as_ref()
            .unwrap()
            .baseline
            .interface
            .policy
            .site_prefix_length,
        255
    );
}
#[test]
fn each_address_policy_and_stable_observed_change_rejects_cleanup_without_delete() {
    let cases: [fn(&mut MIB_UNICASTIPADDRESS_ROW); 9] = [
        |r| r.PrefixOrigin = 3,
        |r| r.SuffixOrigin = 3,
        |r| r.ValidLifetime -= 1,
        |r| r.PreferredLifetime -= 1,
        |r| r.OnLinkPrefixLength = 24,
        |r| r.SkipAsSource = true,
        |r| r.ScopeId.Anonymous.Value = 1,
        |r| r.CreationTimeStamp += 1,
        |r| r.InterfaceIndex += 1,
    ];
    for mutate in cases {
        let fake = Fake::new();
        let mut owner = fake.owner();
        owner.create_address(address_policy()).unwrap();
        mutate(fake.0.borrow_mut().address.as_mut().unwrap());
        assert!(owner.stop().is_err());
        assert_eq!(fake.0.borrow().effects, 1);
    }
}
#[test]
fn every_durable_failure_revision_preserves_obligation_and_cannot_resume_from_json() {
    for at in 1..=11 {
        for fault in [Fault::Unapplied, Fault::FalseAck] {
            let fake = Fake::new();
            fake.0.borrow_mut().journal_at = Some((at, fault));
            let captured = RowOwner::capture(binding(), fake.clone(), fake.clone(), fake.clone());
            let mut failed = captured.is_err();
            if let Ok(mut owner) = captured {
                failed = owner.change_interface(weak()).is_err()
                    || owner.create_address(address_policy()).is_err()
                    || owner.stop().is_err();
                assert!(failed, "fault not exercised at {at}");
                assert!(
                    owner.create_address(address_policy()).is_err(),
                    "failed owner resumed at {at}"
                );
                // Cleanup can resolve only exact current/pending from retained live history.
                // A failed journal does not create durable address or NIC authority.
                owner.stop().unwrap();
                assert_eq!(
                    fake.0.borrow().saved.as_ref().unwrap().phase,
                    Phase::Stopped
                );
            } else {
                assert_eq!(fake.0.borrow().effects, 0);
            }
            assert!(failed);
            if fake.0.borrow().saved.is_some() {
                assert!(
                    RowOwner::capture(binding(), fake.clone(), fake.clone(), fake.clone()).is_err(),
                    "saved JSON became fresh owner"
                );
            }
        }
    }
}
#[test]
fn stopped_reappearance_and_false_or_lost_create_ack_never_create_delete_rights() {
    let fake = Fake::new();
    let mut owner = fake.owner();
    owner.stop().unwrap();
    fake.0.borrow_mut().address = Some(address_raw());
    assert!(owner.stop().is_err());
    assert_eq!(fake.0.borrow().effects, 0);
    for fault in [Fault::LostAck, Fault::FalseAck, Fault::Unapplied] {
        let fake = Fake::new();
        let mut owner = fake.owner();
        fake.0.borrow_mut().kernel_fault = fault;
        assert!(owner.create_address(address_policy()).is_err());
        assert!(owner.stop().is_err());
        assert_eq!(fake.0.borrow().effects, 1);
    }
}

#[test]
fn fresh_context_is_rechecked_after_native_rows_not_only_before_them() {
    let fake = Fake::new();
    let mut owner = fake.owner();
    fake.0.borrow_mut().drift_on_address = true;
    assert!(
        owner.snapshot().is_err(),
        "a stale pre-row owner query must not authorize returned rows"
    );
    assert_eq!(fake.0.borrow().effects, 0);
}
#[test]
fn missing_optional_fields_are_not_a_legacy_native_row_schema() {
    let fake = Fake::new();
    let _owner = fake.owner();
    let bytes = fake.0.borrow().saved.clone().unwrap().encode().unwrap();
    for path in [
        vec!["pending"],
        vec!["creation"],
        vec!["baseline", "address"],
        vec!["current", "address"],
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let mut object = &mut value;
        for part in &path[..path.len() - 1] {
            object = &mut object[*part];
        }
        object.as_object_mut().unwrap().remove(path[path.len() - 1]);
        assert!(
            Record::decode(&serde_json::to_vec(&value).unwrap()).is_err(),
            "missing {path:?}"
        );
    }
}
#[test]
fn original_owner_replayed_queries_api_failures_and_authorization_denial_are_not_absence() {
    for (replay, api_error, deny_authorize) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let fake = Fake::new();
        let mut owner = fake.owner();
        {
            let mut s = fake.0.borrow_mut();
            s.replay = replay;
            s.api_error = api_error;
            s.deny_authorize = deny_authorize;
        }
        assert!(owner.change_interface(weak()).is_err());
        assert_eq!(fake.0.borrow().effects, 0);
    }
}
#[test]
fn unwind_after_actual_effect_keeps_pending_and_poisoned_owner_cleanup_only() {
    let fake = Fake::new();
    let mut owner = fake.owner();
    fake.0.borrow_mut().panic_set = true;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner.change_interface(weak())
    }));
    assert!(result.is_err());
    assert!(!fake.0.borrow().locked);
    assert!(fake.0.borrow().saved.as_ref().unwrap().pending.is_some());
    assert!(owner.create_address(address_policy()).is_err());
    fake.0.borrow_mut().panic_set = false;
    owner.stop().unwrap();
    assert_eq!(
        fake.0.borrow().saved.as_ref().unwrap().phase,
        Phase::Stopped
    );
}
#[test]
fn every_durable_revision_lost_ack_is_exactly_reread_and_never_repeats_native_effects() {
    for at in 1..=11 {
        let fake = Fake::new();
        fake.0.borrow_mut().journal_at = Some((at, Fault::LostAck));
        let mut owner = fake.owner();
        owner.change_interface(weak()).unwrap();
        owner.create_address(address_policy()).unwrap();
        owner.stop().unwrap();
        assert_eq!(fake.0.borrow().effects, 4, "revision {at}");
        assert_eq!(
            fake.0.borrow().saved.as_ref().unwrap().phase,
            Phase::Stopped
        );
    }
}
fn binding() -> Binding {
    Binding {
        scope: nelomai_client_tunnel::redundancy::SessionScope {
            runtime: RuntimeSlot::Stable,
            runtime_generation: 7,
            connection_generation: 9,
            session_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
        },
        boot_id: [7; 16],
        runtime: nelomai_contracts::dispatcher::EngineIdentity {
            slot: RuntimeSlot::Stable,
            runtime_version: "0.3.3".into(),
            runtime_contract_version: 2,
            container_version: "0.3.3".into(),
            manifest_sha256: "a".repeat(64),
        },
        network_epoch: 19,
        role: Role::Carrier,
        guid: [33; 16],
        name: "owned-C".into(),
        key: RowKey {
            luid: 3300,
            index: 33,
        },
        address: [10, 240, 3, 2],
    }
}
#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    LostAck,
    Unapplied,
    FalseAck,
    Partial,
}
struct State {
    binding: Binding,
    identity: NativeIdentity,
    ip: MIB_IPINTERFACE_ROW,
    address: Option<MIB_UNICASTIPADDRESS_ROW>,
    saved: Option<Record>,
    journal_directory: tempfile::TempDir,
    locked: bool,
    journal_fault: Fault,
    kernel_fault: Fault,
    effects: usize,
    queries: usize,
    creator_alive: bool,
    drift_on_address: bool,
    replay: bool,
    api_error: bool,
    panic_set: bool,
    deny_authorize: bool,
    journal_writes: usize,
    journal_at: Option<(usize, Fault)>,
    drift_on_confirmation: bool,
}
#[derive(Clone)]
struct Fake(Rc<RefCell<State>>);
impl Fake {
    fn new() -> Self {
        let b = binding();
        Self(Rc::new(RefCell::new(State {
            identity: NativeIdentity {
                key: b.key,
                guid: b.guid,
                name: b.name.clone(),
                if_type: 53,
                hardware: false,
            },
            binding: b,
            ip: interface_raw(),
            address: None,
            saved: None,
            journal_directory: tempfile::tempdir().unwrap(),
            locked: false,
            journal_fault: Fault::None,
            kernel_fault: Fault::None,
            effects: 0,
            queries: 0,
            creator_alive: true,
            drift_on_address: false,
            replay: false,
            api_error: false,
            panic_set: false,
            deny_authorize: false,
            journal_writes: 0,
            journal_at: None,
            drift_on_confirmation: false,
        })))
    }
    fn assert_lock(&self) {
        assert!(self.0.borrow().locked, "production escaped serialization");
    }
    fn owner(&self) -> RowOwner<Self, Self, Self> {
        RowOwner::capture(binding(), self.clone(), self.clone(), self.clone()).unwrap()
    }
    // Actual bounded row codec + atomic host-file CAS storage, NOT a protected
    // Windows store or production fallback. Faults affect ACKs at this boundary.
    fn journal_path(&self) -> std::path::PathBuf {
        self.0.borrow().journal_directory.path().join("rows.json")
    }
    fn read_journal(&self) -> Result<Option<Record>> {
        match std::fs::read(self.journal_path()) {
            Ok(bytes) => Record::decode(&bytes).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(Error::Journal),
        }
    }
    fn write_journal(&self, record: &Record) -> Result<()> {
        use std::io::Write;
        let path = self.journal_path();
        let directory = path.parent().unwrap();
        let mut replacement =
            tempfile::NamedTempFile::new_in(directory).map_err(|_| Error::Journal)?;
        replacement
            .write_all(&record.encode()?)
            .map_err(|_| Error::Journal)?;
        replacement
            .as_file()
            .sync_all()
            .map_err(|_| Error::Journal)?;
        replacement.persist(&path).map_err(|_| Error::Journal)?;
        #[cfg(unix)]
        std::fs::File::open(directory)
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::Journal)?;
        Ok(())
    }
}
impl Authority for Fake {
    type Creator = Self;
    fn locked<T>(&mut self, action: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        assert!(!self.0.borrow().locked);
        self.0.borrow_mut().locked = true;
        struct Unlock(Fake);
        impl Drop for Unlock {
            fn drop(&mut self) {
                self.0 .0.borrow_mut().locked = false;
            }
        }
        let _unlock = Unlock(self.clone());
        action(self)
    }
}
impl OriginalCreator for Fake {
    fn query(
        &mut self,
        _scope: &nelomai_client_tunnel::redundancy::SessionScope,
        _role: Role,
        challenge: u64,
    ) -> Result<LiveOwner> {
        self.assert_lock();
        let mut s = self.0.borrow_mut();
        s.queries += 1;
        if !s.creator_alive {
            return Err(Error::Conflict);
        }
        Ok(LiveOwner {
            binding: s.binding.clone(),
            challenge: if s.replay { 0 } else { challenge },
        })
    }
    fn authorize(&mut self, _b: &Binding, _op: &Target) -> Result<()> {
        self.assert_lock();
        if self.0.borrow().creator_alive && !self.0.borrow().deny_authorize {
            Ok(())
        } else {
            Err(Error::Conflict)
        }
    }
}
impl Kernel for Fake {
    fn identity(&mut self, _k: RowKey) -> Result<NativeIdentity> {
        self.assert_lock();
        Ok(self.0.borrow().identity.clone())
    }
    fn interface(&mut self, _k: RowKey) -> Result<MIB_IPINTERFACE_ROW> {
        self.assert_lock();
        let s = self.0.borrow();
        if s.api_error {
            Err(Error::Native)
        } else {
            Ok(s.ip)
        }
    }
    fn address(
        &mut self,
        _k: RowKey,
        _address: [u8; 4],
    ) -> Result<Option<MIB_UNICASTIPADDRESS_ROW>> {
        self.assert_lock();
        let mut s = self.0.borrow_mut();
        if s.drift_on_address {
            s.binding.network_epoch += 1;
            s.drift_on_address = false;
        }
        Ok(s.address)
    }
    fn initialize_interface(&mut self) -> MIB_IPINTERFACE_ROW {
        self.assert_lock();
        MIB_IPINTERFACE_ROW::default()
    }
    fn initialize_address(&mut self) -> MIB_UNICASTIPADDRESS_ROW {
        self.assert_lock();
        MIB_UNICASTIPADDRESS_ROW {
            DadState: 4,
            ..Default::default()
        }
    }
    fn set_interface(&mut self, row: &mut MIB_IPINTERFACE_ROW) -> Result<()> {
        self.assert_lock();
        let mut s = self.0.borrow_mut();
        assert!(
            s.saved.as_ref().unwrap().pending.is_some(),
            "mutation before durable intent"
        );
        s.effects += 1;
        let fault = std::mem::take(&mut s.kernel_fault);
        if matches!(fault, Fault::Unapplied) {
            return Err(Error::Native);
        }
        if matches!(fault, Fault::FalseAck) {
            return Ok(());
        }
        let observed = decode_interface(&s.ip)?.observed;
        let mut next = *row;
        next.MinRouterAdvertisementInterval = observed.min_router_advertisement_interval;
        next.MaxRouterAdvertisementInterval = observed.max_router_advertisement_interval;
        next.Connected = observed.connected;
        next.SupportsNeighborDiscovery = observed.supports_neighbor_discovery;
        next.ReachableTime = observed.reachable_time;
        next.TransmitOffload._bitfield = observed.transmit_offload;
        next.ReceiveOffload._bitfield = observed.receive_offload;
        if matches!(fault, Fault::Partial) {
            next.WeakHostReceive = false;
        }
        s.ip = next;
        if s.panic_set {
            drop(s);
            panic!("native effect unwound");
        }
        if matches!(fault, Fault::LostAck | Fault::Partial) {
            Err(Error::Native)
        } else {
            Ok(())
        }
    }
    fn create_address(&mut self, row: &MIB_UNICASTIPADDRESS_ROW) -> Result<()> {
        self.assert_lock();
        let mut s = self.0.borrow_mut();
        assert!(s.saved.as_ref().unwrap().pending.is_some());
        assert_eq!(row.DadState, 0, "no optimistic DAD write");
        assert_eq!(row.CreationTimeStamp, 0);
        assert!(s.address.is_none());
        s.effects += 1;
        let fault = std::mem::take(&mut s.kernel_fault);
        if matches!(fault, Fault::Unapplied) {
            return Err(Error::Native);
        }
        if matches!(fault, Fault::FalseAck) {
            return Ok(());
        }
        let mut next = *row;
        next.DadState = 1;
        next.CreationTimeStamp = 123456789;
        s.address = Some(next);
        if matches!(fault, Fault::LostAck) {
            Err(Error::Native)
        } else {
            Ok(())
        }
    }
    fn delete_address(&mut self, _row: &MIB_UNICASTIPADDRESS_ROW) -> Result<()> {
        self.assert_lock();
        let mut s = self.0.borrow_mut();
        assert!(s.saved.as_ref().unwrap().pending.is_some());
        s.effects += 1;
        let fault = std::mem::take(&mut s.kernel_fault);
        if matches!(fault, Fault::Unapplied) {
            return Err(Error::Native);
        }
        if matches!(fault, Fault::FalseAck) {
            return Ok(());
        }
        s.address = None;
        if matches!(fault, Fault::LostAck) {
            Err(Error::Native)
        } else {
            Ok(())
        }
    }
}
impl Journal for Fake {
    fn load(&mut self, _b: &Binding) -> Result<Option<Record>> {
        self.assert_lock();
        self.read_journal()
    }
    fn compare_exchange(
        &mut self,
        _b: &Binding,
        expected: Option<&Record>,
        desired: &Record,
    ) -> Result<()> {
        self.assert_lock();
        if self.read_journal()?.as_ref() != expected {
            return Err(Error::Conflict);
        }
        let mut s = self.0.borrow_mut();
        s.journal_writes += 1;
        let fault = if s.journal_at.is_some_and(|(at, _)| at == s.journal_writes) {
            s.journal_at.take().unwrap().1
        } else {
            std::mem::take(&mut s.journal_fault)
        };
        if matches!(fault, Fault::Unapplied) {
            return Err(Error::Journal);
        }
        if matches!(fault, Fault::FalseAck) {
            return Ok(());
        }
        drop(s);
        self.write_journal(desired)?;
        let saved = self.read_journal()?.ok_or(Error::Journal)?;
        let mut s = self.0.borrow_mut();
        s.saved = Some(saved);
        if s.drift_on_confirmation && desired.pending.is_none() && desired.revision > 1 {
            s.ip.Metric += 1;
            s.drift_on_confirmation = false;
        }
        if matches!(fault, Fault::LostAck) {
            Err(Error::Journal)
        } else {
            Ok(())
        }
    }
}
fn weak() -> InterfacePolicy {
    let mut p = decode_interface(&interface_raw()).unwrap().policy;
    p.weak_host_send = true;
    p.weak_host_receive = true;
    p
}
fn address_policy() -> AddressPolicy {
    decode_address(&address_raw()).unwrap().policy
}
#[test]
fn durable_owner_captures_full_baseline_then_exact_weak_address_and_cleanup() {
    let fake = Fake::new();
    let mut owner = fake.owner();
    let baseline = owner.snapshot().unwrap();
    assert_eq!(baseline.interface.observed.transmit_offload, 0xa5);
    assert!(baseline.address.is_none());
    owner.change_interface(weak()).unwrap();
    owner.create_address(address_policy()).unwrap();
    let created = owner.snapshot().unwrap();
    assert_eq!(created.address.unwrap().observed.dad_state, 1);
    owner.stop().unwrap();
    let saved = fake.0.borrow().saved.clone().unwrap();
    assert_eq!(saved.phase, Phase::Stopped);
    assert!(saved.pending.is_none());
    assert_eq!(saved.current.interface.policy, baseline.interface.policy);
    assert!(saved.current.address.is_none());
    assert!(fake.0.borrow().address.is_none());
    assert_eq!(fake.0.borrow().effects, 4);
}
#[test]
fn exact_readback_resolves_lost_set_and_delete_ack_without_blind_retry() {
    let fake = Fake::new();
    let mut owner = fake.owner();
    fake.0.borrow_mut().kernel_fault = Fault::LostAck;
    owner.change_interface(weak()).unwrap();
    owner.create_address(address_policy()).unwrap();
    fake.0.borrow_mut().kernel_fault = Fault::LostAck;
    owner.stop().unwrap();
    assert_eq!(fake.0.borrow().effects, 4);
}
#[test]
fn partial_or_false_set_ack_keeps_durable_pending_and_no_active_resume() {
    for fault in [Fault::Unapplied, Fault::FalseAck, Fault::Partial] {
        let fake = Fake::new();
        let mut owner = fake.owner();
        fake.0.borrow_mut().kernel_fault = fault;
        assert!(owner.change_interface(weak()).is_err());
        assert!(fake.0.borrow().saved.as_ref().unwrap().pending.is_some());
        assert!(owner.create_address(address_policy()).is_err());
        if matches!(fault, Fault::Partial) {
            assert!(owner.stop().is_err());
        } else {
            owner.stop().unwrap();
        }
    }
}
#[test]
fn lost_address_create_ack_never_grants_adoption_or_deletion_authority() {
    let fake = Fake::new();
    let mut owner = fake.owner();
    fake.0.borrow_mut().kernel_fault = Fault::LostAck;
    assert!(owner.create_address(address_policy()).is_err());
    assert!(fake.0.borrow().address.is_some());
    assert!(owner.stop().is_err());
    assert_eq!(fake.0.borrow().effects, 1);
    assert!(fake.0.borrow().saved.as_ref().unwrap().pending.is_some());
}
#[test]
fn kernel_readonly_drift_is_observed_but_creation_timestamp_replacement_blocks_delete() {
    let fake = Fake::new();
    let mut owner = fake.owner();
    fake.0.borrow_mut().ip.Connected = false;
    fake.0.borrow_mut().ip.ReachableTime = 65432;
    owner.change_interface(weak()).unwrap();
    let saved = fake.0.borrow().saved.clone().unwrap();
    assert!(!saved.current.interface.observed.connected);
    assert_eq!(saved.current.interface.observed.reachable_time, 65432);
    owner.create_address(address_policy()).unwrap();
    fake.0.borrow_mut().address.as_mut().unwrap().DadState = 4;
    assert_eq!(
        owner
            .snapshot()
            .unwrap()
            .address
            .unwrap()
            .observed
            .dad_state,
        4
    );
    fake.0
        .borrow_mut()
        .address
        .as_mut()
        .unwrap()
        .CreationTimeStamp += 1;
    let before = fake.0.borrow().effects;
    assert!(owner.stop().is_err());
    assert_eq!(fake.0.borrow().effects, before);
}
#[test]
fn full_context_native_identity_and_live_original_creator_are_required_not_json() {
    let mutate: [fn(&mut State); 8] = [
        |s| s.binding.boot_id = [8; 16],
        |s| s.binding.network_epoch += 1,
        |s| s.binding.scope.connection_generation += 1,
        |s| s.binding.runtime.manifest_sha256 = "b".repeat(64),
        |s| s.identity.guid = [44; 16],
        |s| s.identity.key.index += 1,
        |s| s.identity.hardware = true,
        |s| s.creator_alive = false,
    ];
    for drift in mutate {
        let fake = Fake::new();
        let mut owner = fake.owner();
        drift(&mut fake.0.borrow_mut());
        assert!(owner.change_interface(weak()).is_err());
        assert_eq!(fake.0.borrow().effects, 0);
    }
}
#[test]
fn journal_lost_ack_reread_proceeds_only_exact_and_foreign_revision_is_not_adopted() {
    let fake = Fake::new();
    let mut owner = fake.owner();
    fake.0.borrow_mut().journal_fault = Fault::LostAck;
    owner.change_interface(weak()).unwrap();
    fake.0.borrow_mut().saved.as_mut().unwrap().revision += 1;
    let foreign = fake.0.borrow().saved.clone().unwrap();
    fake.write_journal(&foreign).unwrap();
    assert!(owner.create_address(address_policy()).is_err());
    assert_eq!(fake.0.borrow().effects, 1);
    for fault in [Fault::Unapplied, Fault::FalseAck] {
        let fake = Fake::new();
        let mut owner = fake.owner();
        fake.0.borrow_mut().journal_fault = fault;
        assert!(owner.change_interface(weak()).is_err());
        assert_eq!(fake.0.borrow().effects, 0);
    }
}
#[test]
fn members_never_create_vip_and_preexisting_address_is_not_a_fresh_capture() {
    let fake = Fake::new();
    fake.0.borrow_mut().binding.role = Role::MemberA;
    let mut b = binding();
    b.role = Role::MemberA;
    let mut owner = RowOwner::capture(b, fake.clone(), fake.clone(), fake.clone()).unwrap();
    assert!(owner.create_address(address_policy()).is_err());
    assert_eq!(fake.0.borrow().effects, 0);
    let fake = Fake::new();
    fake.0.borrow_mut().address = Some(address_raw());
    assert!(RowOwner::capture(binding(), fake.clone(), fake.clone(), fake.clone()).is_err());
    assert_eq!(fake.0.borrow().effects, 0);
}
#[test]
fn durable_native_record_rejects_extra_version_malformed_and_bounded_input() {
    let fake = Fake::new();
    let _owner = fake.owner();
    let saved = fake.0.borrow().saved.clone().unwrap();
    let encoded = saved.encode().unwrap();
    assert_eq!(Record::decode(&encoded).unwrap(), saved);
    let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    value["baseline"]["interface"]["observed"]["extra"] = 1.into();
    assert!(Record::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    value["version"] = 2.into();
    assert!(Record::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(Record::decode(&vec![b' '; 65537]).is_err());
    let mut bad = saved;
    bad.current.interface.policy.router_discovery = 6500;
    assert!(bad.encode().is_err());
}

fn address_raw() -> MIB_UNICASTIPADDRESS_ROW {
    let mut r = MIB_UNICASTIPADDRESS_ROW::default();
    r.Address.Ipv4 = SOCKADDR_IN {
        sin_family: 2,
        sin_port: 0,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes([10, 240, 3, 2]),
            },
        },
        sin_zero: [0; 8],
    };
    r.InterfaceLuid.Value = 3300;
    r.InterfaceIndex = 33;
    r.PrefixOrigin = 1;
    r.SuffixOrigin = 1;
    r.ValidLifetime = u32::MAX;
    r.PreferredLifetime = u32::MAX;
    r.OnLinkPrefixLength = 32;
    r.SkipAsSource = false;
    r.DadState = 4;
    r.ScopeId.Anonymous.Value = 0;
    r.CreationTimeStamp = 123456789;
    r
}
fn interface_raw() -> MIB_IPINTERFACE_ROW {
    let mut r = MIB_IPINTERFACE_ROW {
        Family: 2,
        ..Default::default()
    };
    r.InterfaceLuid.Value = 3300;
    r.InterfaceIndex = 33;
    r.MinRouterAdvertisementInterval = 200;
    r.MaxRouterAdvertisementInterval = 600;
    r.UseAutomaticMetric = true;
    r.UseNeighborUnreachabilityDetection = true;
    r.ManagedAddressConfigurationSupported = true;
    r.OtherStatefulConfigurationSupported = true;
    r.RouterDiscoveryBehavior = 2;
    r.DadTransmits = 3;
    r.BaseReachableTime = 30000;
    r.RetransmitTime = 1000;
    r.PathMtuDiscoveryTimeout = 600000;
    r.LinkLocalAddressBehavior = 0;
    r.LinkLocalAddressTimeout = 6500;
    r.ZoneIndices = std::array::from_fn(|i| 100 + i as u32);
    r.Metric = 25;
    r.NlMtu = 1420;
    r.Connected = true;
    r.SupportsNeighborDiscovery = true;
    r.ReachableTime = 32123;
    r.TransmitOffload._bitfield = 0xa5;
    r.ReceiveOffload._bitfield = 0x5a;
    r.DisableDefaultRoutes = true;
    r
}
#[test]
fn full_address_codec_preserves_policy_and_separate_observed_dad_timestamp() {
    let raw = address_raw();
    let row = decode_address(&raw).unwrap();
    assert_eq!(
        row.key,
        RowKey {
            luid: 3300,
            index: 33
        }
    );
    assert_eq!(
        row.policy,
        AddressPolicy {
            address: [10, 240, 3, 2],
            prefix_origin: 1,
            suffix_origin: 1,
            valid_lifetime: u32::MAX,
            preferred_lifetime: u32::MAX,
            on_link_prefix_length: 32,
            skip_as_source: false,
        }
    );
    assert_eq!(
        row.observed,
        AddressObserved {
            dad_state: 4,
            scope_id: 0,
            creation_timestamp: 123456789
        }
    );
    let mut changed = raw;
    changed.DadState = 1;
    let other = decode_address(&changed).unwrap();
    assert_eq!(row.policy, other.policy);
    assert_ne!(row.observed, other.observed);
}
#[test]
fn full_interface_codec_preserves_all_writable_and_kernel_managed_fields() {
    let row = decode_interface(&interface_raw()).unwrap();
    assert_eq!(
        row.policy,
        InterfacePolicy {
            advertising: false,
            forwarding: false,
            weak_host_send: false,
            weak_host_receive: false,
            automatic_metric: true,
            neighbor_unreachability: true,
            managed_address_configuration: true,
            other_stateful_configuration: true,
            advertise_default_route: false,
            router_discovery: 2,
            dad_transmits: 3,
            base_reachable_time: 30000,
            retransmit_time: 1000,
            path_mtu_discovery_timeout: 600000,
            link_local_behavior: 0,
            link_local_timeout: 6500,
            zone_indices: [
                100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115
            ],
            site_prefix_length: 0,
            metric: 25,
            mtu: 1420,
            disable_default_routes: true,
        }
    );
    assert_eq!(
        row.observed,
        InterfaceObserved {
            max_reassembly_size: 0,
            interface_identifier: 0,
            min_router_advertisement_interval: 200,
            max_router_advertisement_interval: 600,
            connected: true,
            supports_wake_up_patterns: false,
            supports_neighbor_discovery: true,
            supports_router_discovery: false,
            reachable_time: 32123,
            transmit_offload: 0xa5,
            receive_offload: 0x5a,
        }
    );
    assert_eq!(row.policy.link_local_timeout, 6500);
    assert_eq!(
        row.policy.zone_indices,
        [100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115]
    );
    assert_eq!(row.policy.router_discovery, 2);
    assert_eq!(row.policy.dad_transmits, 3);
    assert!(row.policy.managed_address_configuration && row.policy.other_stateful_configuration);
    assert!(row.policy.automatic_metric && row.policy.neighbor_unreachability);
    assert_eq!(row.policy.metric, 25);
    assert_eq!(row.policy.mtu, 1420);
    assert_eq!(row.observed.min_router_advertisement_interval, 200);
    assert_eq!(row.observed.max_router_advertisement_interval, 600);
    assert!(row.observed.connected && row.observed.supports_neighbor_discovery);
    assert_eq!(row.observed.reachable_time, 32123);
    assert_eq!(row.observed.transmit_offload, 0xa5);
    assert_eq!(row.observed.receive_offload, 0x5a);
}
#[test]
fn address_codec_rejects_unknown_origins_family_and_unsupported_sockaddr_attributes() {
    let cases: [fn(&mut MIB_UNICASTIPADDRESS_ROW); 8] = [
        |r| r.PrefixOrigin = 16,
        |r| r.SuffixOrigin = 6500,
        |r| r.DadState = 5,
        |r| r.OnLinkPrefixLength = 33,
        |r| r.PreferredLifetime = u32::MAX,
        |r| r.Address.Ipv4.sin_port = 53,
        |r| unsafe { r.Address.Ipv4.sin_zero[7] = 1 },
        |r| r.Address.si_family = 23,
    ];
    for (i, mutate) in cases.into_iter().enumerate() {
        let mut raw = address_raw();
        if i == 4 {
            raw.ValidLifetime = 1;
        }
        mutate(&mut raw);
        assert!(decode_address(&raw).is_err(), "case {i}");
    }
}
#[test]
fn interface_codec_rejects_sentinels_reserved_unknown_fields_and_v6() {
    let cases: [fn(&mut MIB_IPINTERFACE_ROW); 6] = [
        |r| r.RouterDiscoveryBehavior = -1,
        |r| r.LinkLocalAddressBehavior = 6500,
        |r| r.InterfaceIdentifier = 1,
        |r| r.MaxReassemblySize = 1,
        |r| r.Family = 23,
        |r| r.InterfaceIndex = 0,
    ];
    for mutate in cases {
        let mut raw = interface_raw();
        mutate(&mut raw);
        assert!(decode_interface(&raw).is_err());
    }
}
#[test]
fn writable_inputs_preserve_every_policy_field_but_never_write_dad_or_readonly_observations() {
    let address = decode_address(&address_raw()).unwrap();
    let encoded = address_input(
        MIB_UNICASTIPADDRESS_ROW::default(),
        address.key,
        &address.policy,
    )
    .unwrap();
    assert_eq!(encoded.DadState, 0);
    assert_eq!(encoded.CreationTimeStamp, 0);
    assert_eq!(unsafe { encoded.ScopeId.Anonymous.Value }, 0);
    assert_eq!(decode_address(&encoded).unwrap().policy, address.policy);
    let row = decode_interface(&interface_raw()).unwrap();
    let encoded = interface_input(MIB_IPINTERFACE_ROW::default(), row.key, &row.policy).unwrap();
    assert_eq!(decode_interface(&encoded).unwrap().policy, row.policy);
    assert!(!encoded.Connected);
    assert_eq!(encoded.ReachableTime, 0);
    assert_eq!(encoded.TransmitOffload._bitfield, 0);
    assert_eq!(encoded.MinRouterAdvertisementInterval, 0);
}
#[test]
fn readonly_and_unsupported_deltas_fail_capability_instead_of_silently_omitting() {
    let mut p = decode_interface(&interface_raw()).unwrap().policy;
    p.site_prefix_length = 255;
    assert!(interface_input(
        MIB_IPINTERFACE_ROW::default(),
        RowKey {
            luid: 3300,
            index: 33
        },
        &p
    )
    .is_err());
    let before = decode_interface(&interface_raw()).unwrap().policy;
    let mut next = before.clone();
    next.forwarding = true;
    assert!(validate_interface_delta(&before, &next).is_err());
    let mut next = before.clone();
    next.weak_host_send = true;
    next.weak_host_receive = true;
    assert!(validate_interface_delta(&before, &next).is_ok());
}
