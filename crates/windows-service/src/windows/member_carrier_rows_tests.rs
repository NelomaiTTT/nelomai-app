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
#[cfg(windows)]
use super::*;
#[cfg(windows)]
use crate::windows::{member_files as private_files, member_session as protected};
#[cfg(not(windows))]
use crate::{member_files as private_files, member_session as protected};
#[cfg(not(windows))]
use native::*;
#[cfg(not(windows))]
use protected::original_native_rows as native;
use protected::SessionFiles;
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
use std::sync::atomic::AtomicBool;

#[test]
fn initial_capture_cleanup_new_closing_ack_never_adopts_initial_capture_bytes_or_absence() {
    // Break: lose the initial invocation/baseline before failure, mint the old
    // Captured ACK from bytes/absence, or execute SDK row effects during cleanup.
    for fault in [Fault::LostAck, Fault::FalseAck, Fault::Unapplied] {
        let fake = Fake::new();
        fake.0.borrow_mut().journal_fault = fault;
        let mut slot = RowCaptureSlot::new(binding(), fake.clone(), fake.clone(), fake.clone());
        assert!(RowOwner::capture_into(&mut slot).is_err());
        let owner = slot.owner_mut().unwrap();
        let pin = owner.initial_capture_cleanup_pin().unwrap();
        assert!(pin
            .with_cleanup_record(&binding().scope, binding().network_epoch, |_| Ok(()))
            .is_err());
        let queries = fake.0.borrow().queries;
        owner
            .inspect_original_initial_capture(|authority, original, facts| {
                assert!(Rc::ptr_eq(&authority.0, &fake.0));
                assert!(original.same_original(&pin));
                assert!(facts.matches_record_original(&pin));
                assert_eq!(facts.initial_record().revision, 1);
                assert_eq!(facts.initial_record().phase, Phase::Captured);
                assert_eq!(facts.baseline().address, None);
                Ok(())
            })
            .unwrap();
        assert_eq!(fake.0.borrow().queries, queries);
        owner.reconcile_initial_capture_for_cleanup().unwrap();
        let new_ack = row_pin_record(&pin, &binding(), true);
        assert_eq!(new_ack.phase, Phase::Closing);
        assert_eq!(new_ack.revision, 2);
        assert!(new_ack.pending.is_none());
        assert!(new_ack.creation.is_none());
        assert_eq!(new_ack.current, new_ack.baseline);
        assert_eq!(fake.read_journal().unwrap(), Some(new_ack));
        assert_eq!(fake.0.borrow().effects, 0);
        assert!(owner.create_address(address_policy()).is_err());
        assert!(owner.change_interface(weak()).is_err());
    }
}

// Only the OS journal boundary is doubled, using the real private invocation
// view emitted by the actual owner. No caller construction of initial facts.
unsafe impl InitialRowCaptureCleanupJournal for Fake {
    fn compare_exchange_initial_capture_cleanup(
        &mut self,
        b: &Binding,
        old: Option<&Record>,
        new: &Record,
        original: &InitialRowCaptureCleanupRead<'_>,
    ) -> Result<()> {
        self.assert_lock();
        original.verify_exchange(b, old, new)?;
        if self.read_journal()?.as_ref() != old {
            return Err(Error::Conflict);
        }
        let fault = {
            let mut s = self.0.borrow_mut();
            s.journal_writes += 1;
            std::mem::take(&mut s.journal_fault)
        };
        if matches!(fault, Fault::Unapplied) {
            return Err(Error::Journal);
        }
        if matches!(fault, Fault::FalseAck) {
            return Ok(());
        }
        self.write_journal(new)?;
        self.0.borrow_mut().saved = self.read_journal()?;
        if matches!(fault, Fault::LostAck) {
            Err(Error::Journal)
        } else {
            Ok(())
        }
    }
}

#[test]
fn capture_into_retains_original_owner_before_failed_initial_cas_readback() {
    // Break: keep A/K/J or the sampled baseline only on the constructor stack,
    // or manufacture the original baseline ACK from matching durable bytes.
    for failure in 0..3 {
        let fake = Fake::new();
        if failure == 0 {
            fake.0.borrow_mut().journal_fault = Fault::LostAck;
        } else {
            fake.0.borrow_mut().journal_load_fault = Some((1, failure == 2));
        }
        let mut slot = RowCaptureSlot::new(binding(), fake.clone(), fake.clone(), fake.clone());
        let handed = std::cell::Cell::new(false);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            RowOwner::capture_with_record_pin_into(&mut slot, |_| {
                handed.set(true);
                Ok(())
            })
        }));
        if failure == 2 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert!(!handed.get());
        let original = fake.0.borrow().saved.clone().unwrap();
        let owner = slot
            .owner_mut()
            .expect("caller retains SAME attempted owner");
        assert!(owner.record_read_pin().is_err());
        assert_eq!(owner.change_interface(weak()), Err(Error::Retired));
        assert_eq!(original.revision, 1);
        assert_eq!(original.current, original.baseline);
        assert!(RowOwner::capture_with_record_pin_into(&mut slot, |_| Ok(())).is_err());
        assert_eq!(fake.0.borrow().journal_writes, 1);
        assert_eq!(fake.0.borrow().effects, 0);
    }
}

#[test]
fn capture_into_retains_same_ack_and_owner_across_handoff_error_and_unwind() {
    // Break: return the owner through Result or publish the ACK after callback.
    for unwind in [false, true] {
        let fake = Fake::new();
        let mut slot = RowCaptureSlot::new(binding(), fake.clone(), fake.clone(), fake.clone());
        let handed = RefCell::new(None);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            RowOwner::capture_with_record_pin_into(&mut slot, |pin| {
                *handed.borrow_mut() = Some(pin);
                if unwind {
                    panic!("root handoff unwound");
                }
                Err(Error::Journal)
            })
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        let retained = handed.borrow();
        let pin = retained.as_ref().unwrap();
        let owner = slot.owner_mut().unwrap();
        assert!(owner.record_read_pin().unwrap().same_original(pin));
        assert_eq!(row_pin_record(pin, &binding(), true).revision, 1);
        assert!(pin
            .with_record(&binding().scope, binding().network_epoch, |_| Ok(()))
            .is_err());
        assert_eq!(owner.change_interface(weak()), Err(Error::Retired));
        assert_eq!(fake.0.borrow().effects, 0);
    }
}

#[test]
fn capture_into_success_preserves_real_ack_and_supports_original_owner() {
    let fake = Fake::new();
    let mut slot = RowCaptureSlot::new(binding(), fake.clone(), fake.clone(), fake.clone());
    let handed = RefCell::new(None);
    RowOwner::capture_with_record_pin_into(&mut slot, |pin| {
        *handed.borrow_mut() = Some(pin);
        Ok(())
    })
    .unwrap();
    let owner = slot.owner_mut().unwrap();
    assert!(owner
        .record_read_pin()
        .unwrap()
        .same_original(handed.borrow().as_ref().unwrap()));
    owner.change_interface(weak()).unwrap();
    assert_eq!(fake.0.borrow().effects, 1);
}
#[test]
fn capture_into_native_postflight_failure_keeps_same_owner_and_ack_without_forward() {
    // Break: hand the owner out only after SDK postflight, or lose its genuine
    // ACK on unwind after the caller already retained the original pin.
    for unwind in [false, true] {
        let fake = Fake::new();
        let mut slot = RowCaptureSlot::new(binding(), fake.clone(), fake.clone(), fake.clone());
        let handed = RefCell::new(None);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            RowOwner::capture_with_record_pin_into(&mut slot, |pin| {
                *handed.borrow_mut() = Some(pin);
                if unwind {
                    fake.0.borrow_mut().read_hook =
                        Some(Box::new(|_| panic!("SDK postflight unwound")));
                } else {
                    fake.0.borrow_mut().identity_error = true;
                }
                Ok(())
            })
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert!(slot.take_owner().is_err());
        let owner = slot.owner_mut().unwrap();
        let handed = handed.borrow();
        let pin = handed.as_ref().unwrap();
        owner
            .inspect_original_authority(|a, actual| {
                assert!(Rc::ptr_eq(&a.0, &fake.0));
                assert!(actual.same_original(pin));
                Ok(())
            })
            .unwrap();
        assert_eq!(row_pin_record(pin, &binding(), true).revision, 1);
        assert!(pin
            .with_record(&binding().scope, binding().network_epoch, |_| Ok(()))
            .is_err());
        assert!(owner.change_interface(weak()).is_err());
        assert_eq!(fake.0.borrow().effects, 0);
    }
}
#[test]
fn capture_slot_unknown_drop_retains_originals_and_only_success_transfers_owner() {
    // Break: an uncertain constructor/drop releases A/K/J or transfers its
    // incomplete owner; no arbitrary destructor may masquerade as cleanup.
    for case in 0..4 {
        let fake = Fake::new();
        let mut slot = RowCaptureSlot::new(binding(), fake.clone(), fake.clone(), fake.clone());
        match case {
            0 => {} // before any IO
            1 => {
                fake.0.borrow_mut().identity_error = true;
                assert!(RowOwner::capture_into(&mut slot).is_err());
                assert!(slot.owner_mut().is_err());
            }
            2 => {
                fake.0.borrow_mut().journal_fault = Fault::LostAck;
                assert!(RowOwner::capture_into(&mut slot).is_err());
                assert!(slot.take_owner().is_err());
            }
            _ => RowOwner::capture_into(&mut slot).unwrap(),
        }
        assert_eq!(Rc::strong_count(&fake.0), 4); // SAME A/K/J handles + test observer
        drop(slot);
        assert_eq!(Rc::strong_count(&fake.0), 4); // conservative retention, not success
        assert_eq!(fake.0.borrow().effects, 0);
    }
    let fake = Fake::new();
    let mut slot = RowCaptureSlot::new(binding(), fake.clone(), fake.clone(), fake.clone());
    RowOwner::capture_into(&mut slot).unwrap();
    let owner = slot.take_owner().unwrap();
    drop(slot);
    assert_eq!(Rc::strong_count(&fake.0), 4); // original owner, no duplicate construction
    drop(owner);
    assert_eq!(Rc::strong_count(&fake.0), 1);
    assert_eq!(fake.0.borrow().effects, 0);
}
#[test]
fn partial_capture_stopped_drain_retains_same_owner_without_old_sdk_reentry() {
    // Break: refuse a genuinely stopped partial owner, drop its resources in a
    // Result, query an already-closed NIC, or substitute a same-looking pin.
    let fake = Fake::new();
    let mut slot = RowCaptureSlot::new(binding(), fake.clone(), fake.clone(), fake.clone());
    assert!(RowOwner::capture_with_record_pin_into(&mut slot, |_| Err(Error::Journal)).is_err());
    let original = slot.owner_mut().unwrap().record_read_pin().unwrap();
    slot.owner_mut().unwrap().stop().unwrap();
    let queries = fake.0.borrow().queries;
    let writes = fake.0.borrow().journal_writes;
    fake.0.borrow_mut().identity_error = true; // C already closed, old SDK forbidden
    let mut destination = None;
    slot.drain_stopped_into(&original, &mut destination)
        .unwrap();
    let stopped = destination.as_mut().unwrap();
    slot.verify_stopped_drained_into(&original, stopped)
        .unwrap();
    stopped.verify_original(&original).unwrap();
    assert!(slot.owner_mut().is_err());
    assert!(slot.take_owner().is_err());
    assert_eq!(fake.0.borrow().queries, queries);
    assert_eq!(fake.0.borrow().journal_writes, writes);
    assert_eq!(Rc::strong_count(&fake.0), 4);
    let mut raw_owner = None;
    stopped.drain_owner_into(&mut raw_owner).unwrap();
    stopped
        .verify_owner_drained_into(raw_owner.as_ref().unwrap())
        .unwrap();
    slot.verify_stopped_owner_drained_into(&original, raw_owner.as_ref().unwrap())
        .unwrap();
    let foreign_fake = Fake::new();
    let mut foreign_owner = foreign_fake.owner();
    foreign_owner.stop().unwrap();
    assert!(slot
        .verify_stopped_owner_drained_into(&original, &foreign_owner)
        .is_err());
    drop(slot);
    drop(destination);
    assert_eq!(Rc::strong_count(&fake.0), 4); // SAME raw owner, not retaining wrapper
    drop(raw_owner); // test boundary only; product requires its terminal G first
    assert_eq!(Rc::strong_count(&fake.0), 1);
}

#[test]
fn stopped_capture_drain_denies_unknown_lost_ack_foreign_original_and_pending_attempt() {
    for failure in 0..4 {
        let fake = Fake::new();
        let mut slot = RowCaptureSlot::new(binding(), fake.clone(), fake.clone(), fake.clone());
        RowOwner::capture_into(&mut slot).unwrap();
        let original = slot.owner_mut().unwrap().record_read_pin().unwrap();
        if failure != 0 {
            if failure == 1 {
                fake.0.borrow_mut().journal_fault = Fault::LostAck;
            }
            if failure == 3 {
                fake.0.borrow_mut().journal_load_fault = Some((3, false));
            }
            let result = slot.owner_mut().unwrap().stop();
            if failure == 1 || failure == 3 {
                assert!(result.is_err());
            } else {
                result.unwrap();
            }
        }
        let foreign = Fake::new().owner().record_read_pin().unwrap();
        let supplied = if failure == 2 { &foreign } else { &original };
        let mut destination = None;
        assert!(slot.drain_stopped_into(supplied, &mut destination).is_err());
        assert!(destination.is_none());
        assert!(slot
            .owner_mut()
            .unwrap()
            .record_read_pin()
            .unwrap()
            .same_original(&original));
        assert_eq!(Rc::strong_count(&fake.0), 4);
    }
}

#[test]
fn initial_unknown_capture_requires_new_cleanup_and_stop_ack_before_terminal_cut() {
    for fault in [Fault::LostAck, Fault::FalseAck, Fault::Unapplied] {
        let fake = Fake::new();
        fake.0.borrow_mut().journal_fault = fault;
        let mut slot = RowCaptureSlot::new(binding(), fake.clone(), fake.clone(), fake.clone());
        assert!(RowOwner::capture_into(&mut slot).is_err());
        let original = slot
            .owner_mut()
            .unwrap()
            .initial_capture_cleanup_pin()
            .unwrap();
        let mut destination = None;
        assert!(slot
            .drain_stopped_into(&original, &mut destination)
            .is_err());
        assert!(destination.is_none());
        slot.owner_mut()
            .unwrap()
            .reconcile_initial_capture_for_cleanup()
            .unwrap();
        assert_eq!(
            row_pin_record(&original, &binding(), true).phase,
            Phase::Closing
        );
        slot.owner_mut().unwrap().stop().unwrap();
        slot.drain_stopped_into(&original, &mut destination)
            .unwrap();
        slot.verify_stopped_drained_into(&original, destination.as_ref().unwrap())
            .unwrap();
        assert_eq!(fake.0.borrow().effects, 0);
        drop(slot);
        drop(destination); // no explicit raw transfer: retain, never release early
        assert_eq!(Rc::strong_count(&fake.0), 4);
    }
}

#[test]
fn original_authority_inspection_is_pure_same_owner_identity_even_without_capture_ack() {
    // Break: issue the normal ACK-required pin, enter Authority/SDK/journal,
    // or substitute a same-looking authority rather than borrow the original.
    for lost in [false, true] {
        let fake = Fake::new();
        if lost {
            fake.0.borrow_mut().journal_fault = Fault::LostAck;
        }
        let owner = fake.owner();
        let reads = fake.0.borrow().queries;
        let writes = fake.0.borrow().journal_writes;
        owner
            .inspect_original_authority(|authority, pin| {
                assert!(Rc::ptr_eq(&authority.0, &fake.0));
                assert!(!authority.0.borrow().locked);
                if lost {
                    assert!(pin
                        .with_cleanup_record(&binding().scope, binding().network_epoch, |_| Ok(()))
                        .is_err());
                } else {
                    assert!(pin.same_original(&owner.record_read_pin().unwrap()));
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(fake.0.borrow().queries, reads);
        assert_eq!(fake.0.borrow().journal_writes, writes);
        assert_eq!(fake.0.borrow().effects, 0);
    }
}

#[test]
fn known_created_cleanup_reconciles_only_original_sdk_ack_after_confirmation_faults() {
    // Break: ordinary cleanup imports creation, or a matching confirmation
    // reread becomes an ACK rather than a NEW Closing CAS with actual ACK.
    for failure in 0..4 {
        let fake = Fake::new();
        let mut owner = fake.owner();
        let pin = owner.record_read_pin().unwrap();
        match failure {
            0 => fake.0.borrow_mut().journal_at = Some((3, Fault::LostAck)),
            1 => fake.0.borrow_mut().journal_at = Some((3, Fault::Unapplied)),
            _ => fake.0.borrow_mut().journal_load_fault = Some((3, failure == 3)),
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.create_address(address_policy())
        }));
        if failure == 3 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert_eq!(row_pin_record(&pin, &binding(), true).revision, 2);
        fake.0.borrow_mut().cleanup_storage = true;
        // A committed confirmation already present in storage may support an
        // ordinary Closing transition without importing creation. Instead test
        // the prohibited edge directly: original pending Create -> Closing
        // creation confirmation through the ordinary schema firewall.
        let pending = row_pin_record(&pin, &binding(), true);
        let mut imported = pending.clone();
        imported.revision += 1;
        imported.phase = Phase::Closing;
        imported.pending = None;
        imported.current.address =
            Some(decode_address(fake.0.borrow().address.as_ref().unwrap()).unwrap());
        imported.creation = imported.current.address.clone();
        assert!(validate_transition(Some(&pending), &imported, true).is_err());
        let effects = fake.0.borrow().effects;
        owner.reconcile_created_address_for_cleanup().unwrap();
        let actual = fake.read_journal().unwrap().unwrap();
        assert_eq!(actual.phase, Phase::Closing);
        assert!(actual.pending.is_none());
        assert_eq!(actual.creation, actual.current.address);
        assert_eq!(row_pin_record(&pin, &binding(), true), actual);
        assert_eq!(fake.0.borrow().effects, effects);
        assert!(owner.create_address(address_policy()).is_err());
    }
}

#[test]
fn known_created_cleanup_unknown_sdk_ack_and_foreign_same_json_never_authorize() {
    let unknown = Fake::new();
    let mut owner = unknown.owner();
    unknown.0.borrow_mut().kernel_fault = Fault::LostAck;
    assert!(owner.create_address(address_policy()).is_err());
    assert!(unknown.0.borrow().address.is_some());
    let attempts = unknown.0.borrow().journal_writes;
    assert!(owner.reconcile_created_address_for_cleanup().is_err());
    assert_eq!(unknown.0.borrow().journal_writes, attempts);

    let original = Fake::new();
    let mut created = original.owner();
    original.0.borrow_mut().journal_at = Some((3, Fault::Unapplied));
    assert!(created.create_address(address_policy()).is_err());
    let foreign = Fake::new();
    let mut other = foreign.owner();
    let same_json = original.read_journal().unwrap().unwrap();
    foreign.write_journal(&same_json).unwrap();
    foreign.0.borrow_mut().address = original.0.borrow().address;
    let writes = foreign.0.borrow().journal_writes;
    assert!(other.reconcile_created_address_for_cleanup().is_err());
    assert_eq!(foreign.0.borrow().journal_writes, writes);
    assert_eq!(foreign.read_journal().unwrap(), Some(same_json));
}

#[test]
fn known_created_cleanup_failed_new_cas_never_advances_ack_and_retains_original_retry() {
    // Break: acknowledge matching bytes after lost/readback ACK, or drop the
    // private SDK receipt/attempt on typed journal failure or unwind.
    for fault in 0..5 {
        let fake = Fake::new();
        let mut owner = fake.owner();
        let pin = owner.record_read_pin().unwrap();
        fake.0.borrow_mut().journal_at = Some((3, Fault::Unapplied));
        assert!(owner.create_address(address_policy()).is_err());
        let old = row_pin_record(&pin, &binding(), true);
        match fault {
            0 => fake.0.borrow_mut().journal_fault = Fault::Unapplied,
            1 => fake.0.borrow_mut().journal_fault = Fault::FalseAck,
            2 => fake.0.borrow_mut().journal_fault = Fault::LostAck,
            _ => fake.0.borrow_mut().journal_load_fault = Some((3, fault == 4)),
        }
        let effects = fake.0.borrow().effects;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.reconcile_created_address_for_cleanup()
        }));
        if fault == 4 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert_eq!(row_pin_record(&pin, &binding(), true), old);
        assert_eq!(fake.0.borrow().effects, effects);
        // A separate genuine NEW CAS, not readback, can confirm this same
        // owner's still-retained cleanup obligation through the raw boundary.
        owner.reconcile_created_address_for_cleanup().unwrap();
        let ack = row_pin_record(&pin, &binding(), true);
        assert_eq!(ack.phase, Phase::Closing);
        assert!(ack.pending.is_none());
        assert!(ack.revision > old.revision);
        assert_eq!(fake.read_journal().unwrap(), Some(ack));
        assert_eq!(fake.0.borrow().effects, effects);
        assert!(owner.create_address(address_policy()).is_err());
    }
}

// Missing mirror advancement, value-based origin, early/late ACK publication,
// reentrant Authority calls or reversible revocation must break these tests.
fn row_pin_record(pin: &RowRecordReadPin, b: &Binding, cleanup: bool) -> Record {
    let read = |facts: RowRecordFacts<'_>| {
        assert_eq!(facts.binding, b);
        assert_eq!(&facts.acknowledged.binding, b);
        Ok(facts.acknowledged.clone())
    };
    if cleanup {
        pin.with_cleanup_record(&b.scope, b.network_epoch, read)
    } else {
        pin.with_record(&b.scope, b.network_epoch, read)
    }
    .unwrap()
}

#[test]
fn original_row_storage_cleanup_handoff_revokes_before_callback_without_native_effects() {
    let fake = Fake::new();
    let mut owner = fake.owner();
    let b = binding();
    let pin = owner.record_read_pin().unwrap();
    let original = row_pin_record(&pin, &b, false);
    let reads = fake.0.borrow().queries;
    let effects = fake.0.borrow().effects;
    owner
        .enter_storage_cleanup(|journal| {
            assert!(Rc::ptr_eq(&journal.0, &fake.0));
            assert_eq!(
                pin.with_record(&b.scope, b.network_epoch, |_| Ok(())),
                Err(Error::Retired)
            );
            assert_eq!(row_pin_record(&pin, &b, true), original);
            Ok(())
        })
        .unwrap();
    assert_eq!(fake.0.borrow().queries, reads);
    assert_eq!(fake.0.borrow().effects, effects);
    assert!(pin.same_original(&owner.record_read_pin().unwrap()));
    assert!(owner.change_interface(weak()).is_err());
    owner.stop().unwrap();
    assert_eq!(row_pin_record(&pin, &b, true).phase, Phase::Stopped);
}

#[test]
fn original_row_storage_cleanup_error_or_unwind_never_rearms_forward_or_discards_ack() {
    for unwind in [false, true] {
        let fake = Fake::new();
        let mut owner = fake.owner();
        let b = binding();
        let pin = owner.record_read_pin().unwrap();
        let original = row_pin_record(&pin, &b, false);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.enter_storage_cleanup(|_| {
                if unwind {
                    panic!("storage cleanup handoff");
                }
                Err(Error::Journal)
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(owner.change_interface(weak()).is_err());
        assert_eq!(row_pin_record(&pin, &b, true), original);
        assert!(pin.same_original(&owner.record_read_pin().unwrap()));
        assert_eq!(fake.0.borrow().effects, 0);
    }
}

#[test]
fn row_record_pin_tracks_original_capture_each_ack_and_real_stopped_facts() {
    let fake = Fake::new();
    let (mut owner, _files) = protected_owner(&fake, Role::Carrier);
    let b = fake.0.borrow().binding.clone();
    let pin = owner.record_read_pin().unwrap();
    let first = row_pin_record(&pin, &b, false);
    assert_eq!(first.revision, 1);
    assert_eq!(first.phase, Phase::Captured);
    assert!(first.current.address.is_none());
    assert!(first.pending.is_none());
    assert_eq!(first, fake.0.borrow().saved.clone().unwrap());
    owner.change_interface(weak()).unwrap();
    let changed = row_pin_record(&pin, &b, false);
    assert_eq!(changed.revision, 3);
    assert!(changed.current.interface.policy.weak_host_send);
    assert!(changed.current.interface.policy.weak_host_receive);
    assert!(!changed.baseline.interface.policy.weak_host_send);
    assert_eq!(changed, fake.0.borrow().saved.clone().unwrap());
    owner.create_address(address_policy()).unwrap();
    let created = row_pin_record(&pin, &b, false);
    assert_eq!(created.revision, 5);
    assert_eq!(
        created
            .creation
            .as_ref()
            .unwrap()
            .observed
            .creation_timestamp,
        123456789
    );
    assert_eq!(created, fake.0.borrow().saved.clone().unwrap());
    assert!(pin.same_original(&owner.record_read_pin().unwrap()));
    owner.stop().unwrap();
    assert_eq!(
        pin.with_record(&b.scope, b.network_epoch, |_| Ok(())),
        Err(Error::Retired)
    );
    pin.with_cleanup_record(&b.scope, b.network_epoch, |facts| {
        assert!(facts.cleanup_only);
        assert_eq!(facts.acknowledged.revision, 11);
        assert_eq!(facts.acknowledged.phase, Phase::Stopped);
        assert!(facts.acknowledged.current.address.is_none());
        assert!(facts.acknowledged.creation.is_some());
        assert_eq!(facts.acknowledged, fake.0.borrow().saved.as_ref().unwrap());
        Ok(())
    })
    .unwrap();
}

#[test]
fn row_record_pin_same_original_rejects_foreign_owner_with_equal_full_record() {
    let left = Fake::new();
    let right = Fake::new();
    let (a, _a_files) = protected_owner(&left, Role::Carrier);
    let (b, _b_files) = protected_owner(&right, Role::Carrier);
    let p = a.record_read_pin().unwrap();
    let q = b.record_read_pin().unwrap();
    let binding = left.0.borrow().binding.clone();
    assert_eq!(
        row_pin_record(&p, &binding, false),
        row_pin_record(&q, &binding, false)
    );
    assert!(!p.same_original(&q));
    assert!(!q.same_original(&p));
    assert!(p.same_original(&a.record_read_pin().unwrap()));
    assert!(q.same_original(&b.record_read_pin().unwrap()));
}

#[test]
fn row_record_pin_wrong_scope_or_epoch_stickily_revokes_all_same_owner_pins() {
    for epoch in [false, true] {
        let fake = Fake::new();
        let owner = fake.owner();
        let b = binding();
        let p = owner.record_read_pin().unwrap();
        let q = owner.record_read_pin().unwrap();
        let mut wrong = b.scope.clone();
        wrong.connection_generation += u64::from(!epoch);
        assert_eq!(
            p.with_record(&wrong, b.network_epoch + u64::from(epoch), |_| Ok(())),
            Err(Error::Conflict)
        );
        assert_eq!(
            q.with_record(&b.scope, b.network_epoch, |_| Ok(())),
            Err(Error::Retired)
        );
        assert_eq!(row_pin_record(&q, &b, true).revision, 1);
        assert_eq!(
            owner
                .record_read_pin()
                .unwrap()
                .with_record(&b.scope, b.network_epoch, |_| Ok(())),
            Err(Error::Retired)
        );
    }
}

#[test]
fn row_record_pin_reads_inside_same_actual_lock_and_pending_native_bracket_without_io() {
    let fake = Fake::new();
    let (mut owner, _files) = protected_owner(&fake, Role::Carrier);
    let b = fake.0.borrow().binding.clone();
    let p = Rc::new(owner.record_read_pin().unwrap());
    let before = (
        fake.0.borrow().queries,
        fake.0.borrow().private_reads,
        fake.0.borrow().effects,
    );
    fake.clone()
        .locked(|_| {
            assert_eq!(row_pin_record(&p, &b, false).revision, 1);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        (
            fake.0.borrow().queries,
            fake.0.borrow().private_reads,
            fake.0.borrow().effects
        ),
        before
    );
    let observed = Rc::new(std::cell::Cell::new(false));
    fn hook(p: Rc<RowRecordReadPin>, observed: Rc<std::cell::Cell<bool>>) -> ReadHook {
        Box::new(move |s| {
            if s.saved.as_ref().unwrap().pending.is_none() {
                s.read_hook = Some(hook(Rc::clone(&p), Rc::clone(&observed)));
                return;
            }
            assert!(s.locked);
            let record = row_pin_record(&p, &s.binding, false);
            assert_eq!(record.revision, 2);
            assert!(record.pending.is_some());
            assert_eq!(&record, s.saved.as_ref().unwrap());
            observed.set(true);
        })
    }
    fake.0.borrow_mut().read_hook = Some(hook(Rc::clone(&p), Rc::clone(&observed)));
    owner.change_interface(weak()).unwrap();
    assert!(observed.get());
    assert_eq!(row_pin_record(&p, &b, false).revision, 3);
}

#[test]
fn row_record_pin_confirmed_root_ack_survives_native_postflight_error_or_unwind() {
    for unwind in [false, true] {
        let fake = Fake::new();
        let mut owner = fake.owner();
        let b = binding();
        let p = owner.record_read_pin().unwrap();
        fn postflight(unwind: bool) -> ReadHook {
            Box::new(move |s| {
                let saved = s.saved.as_ref().unwrap();
                if saved.revision != 3 || saved.pending.is_some() {
                    s.read_hook = Some(postflight(unwind));
                    return;
                }
                if unwind {
                    panic!("postflight after exact durable ACK");
                }
                s.binding.network_epoch += 1;
            })
        }
        fake.0.borrow_mut().read_hook = Some(postflight(unwind));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.change_interface(weak())
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert_eq!(
            p.with_record(&b.scope, b.network_epoch, |_| Ok(())),
            Err(Error::Retired)
        );
        let receipt = row_pin_record(&p, &b, true);
        assert_eq!(receipt.revision, 3);
        assert!(receipt.pending.is_none());
        assert!(receipt.current.interface.policy.weak_host_send);
        assert_eq!(receipt, fake.0.borrow().saved.clone().unwrap());
    }
}

#[test]
fn row_record_pin_lost_cas_ack_never_overwrites_last_confirmed_receipt() {
    for revision in [2, 3] {
        let fake = Fake::new();
        let mut owner = fake.owner();
        let b = binding();
        let p = owner.record_read_pin().unwrap();
        fake.0.borrow_mut().journal_at = Some((revision, Fault::LostAck));
        let _ = owner.change_interface(weak());
        assert_eq!(
            p.with_record(&b.scope, b.network_epoch, |_| Ok(())),
            Err(Error::Retired)
        );
        let receipt = row_pin_record(&p, &b, true);
        assert_eq!(receipt.revision, revision as u64 - 1);
        assert_eq!(receipt.pending.is_some(), revision == 3);
        assert_eq!(
            fake.0.borrow().saved.as_ref().unwrap().revision,
            revision as u64
        );
        assert!(owner.create_address(address_policy()).is_err());
        // Real cleanup may advance facts, but never rearm forward read use.
        owner.stop().unwrap();
        assert_eq!(row_pin_record(&p, &b, true).phase, Phase::Stopped);
        assert_eq!(
            p.with_record(&b.scope, b.network_epoch, |_| Ok(())),
            Err(Error::Retired)
        );
    }
}

// Break: a lost write ACK discards the SAME owner's attempted bytes, or an
// equal durable reread silently promotes them to an acknowledged receipt.
#[test]
fn cleanup_write_attempt_is_retained_separately_from_actual_ack_after_failed_cas() {
    for revision in [2, 3] {
        let fake = Fake::new();
        let mut owner = fake.owner();
        let b = binding();
        let pin = owner.record_read_pin().unwrap();
        fake.0.borrow_mut().journal_at = Some((revision, Fault::LostAck));
        assert!(owner.change_interface(weak()).is_err());
        let queries = fake.0.borrow().queries;
        let (ack, before, desired) = pin
            .with_cleanup_write_attempt(&b.scope, b.network_epoch, |facts| {
                assert_eq!(facts.binding, &b);
                Ok((
                    facts.acknowledged.clone(),
                    facts.before.clone(),
                    facts.desired.clone(),
                ))
            })
            .unwrap();
        assert_eq!(ack.revision, revision as u64 - 1);
        assert_eq!(before, ack);
        assert_eq!(desired.revision, revision as u64);
        assert_eq!(fake.0.borrow().saved.as_ref(), Some(&desired));
        assert_eq!(fake.0.borrow().queries, queries); // no kernel/Authority/J reads
        assert_eq!(row_pin_record(&pin, &b, true), ack);
        #[cfg(windows)] // Child of actual owner module; standalone host is external.
        let actual_attempt = pin.original.write_attempt.borrow().clone().unwrap();
        assert!(pin
            .with_record(&b.scope, b.network_epoch, |_| Ok(()))
            .is_err());
        owner.stop().unwrap();
        assert_eq!(row_pin_record(&pin, &b, true).phase, Phase::Stopped);
        #[cfg(windows)]
        assert!(Rc::ptr_eq(
            pin.original
                .write_attempt
                .borrow()
                .as_ref()
                .unwrap()
                ._previous
                .as_ref()
                .unwrap(),
            &actual_attempt,
        )); // later acknowledged cleanup never drops the original unknown write
        assert!(pin
            .with_cleanup_write_attempt(&b.scope, b.network_epoch, |_| Ok(()))
            .is_err());
    }
}

// Break: attempt retention happens only after the raw CAS readback; an error
// or unwind between CAS and readback loses the original cleanup obligation.
#[test]
fn cleanup_write_attempt_survives_cas_readback_error_unwind_and_owner_drop() {
    for unwind in [false, true] {
        let fake = Fake::new();
        let mut owner = fake.owner();
        let b = binding();
        let pin = owner.record_read_pin().unwrap();
        fake.0.borrow_mut().journal_load_fault = Some((2, unwind));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.change_interface(weak())
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        drop(owner);
        pin.with_cleanup_write_attempt(&b.scope, b.network_epoch, |facts| {
            assert_eq!(facts.acknowledged.revision, 1);
            assert_eq!(facts.before, facts.acknowledged);
            assert_eq!(facts.desired.revision, 2);
            assert_eq!(fake.0.borrow().saved.as_ref(), Some(facts.desired));
            Ok(())
        })
        .unwrap();
        assert_eq!(fake.0.borrow().effects, 0);
        assert!(pin
            .with_record(&b.scope, b.network_epoch, |_| Ok(()))
            .is_err());
    }
}

#[test]
fn cleanup_write_attempt_rejects_foreign_context_and_callback_advancement() {
    let fake = Fake::new();
    let mut owner = fake.owner();
    let b = binding();
    let pin = owner.record_read_pin().unwrap();
    fake.0.borrow_mut().journal_at = Some((2, Fault::LostAck));
    assert!(owner.change_interface(weak()).is_err());
    let mut foreign = b.scope.clone();
    foreign.connection_generation += 1;
    assert!(pin
        .with_cleanup_write_attempt(&foreign, b.network_epoch, |_| Ok(()))
        .is_err());
    assert!(pin
        .with_cleanup_write_attempt(&b.scope, b.network_epoch + 1, |_| Ok(()))
        .is_err());
    assert!(pin
        .with_cleanup_write_attempt(&b.scope, b.network_epoch, |_| owner.stop())
        .is_err());
    assert_eq!(row_pin_record(&pin, &b, true).phase, Phase::Stopped);
    assert!(pin
        .with_record(&b.scope, b.network_epoch, |_| Ok(()))
        .is_err());
}

#[test]
fn cleanup_write_attempt_does_not_claim_application_of_false_or_failed_cas() {
    for fault in [Fault::FalseAck, Fault::Unapplied] {
        let fake = Fake::new();
        let mut owner = fake.owner();
        let b = binding();
        let pin = owner.record_read_pin().unwrap();
        fake.0.borrow_mut().journal_fault = fault;
        assert!(owner.change_interface(weak()).is_err());
        pin.with_cleanup_write_attempt(&b.scope, b.network_epoch, |facts| {
            assert_eq!(facts.before, facts.acknowledged);
            assert_eq!(fake.0.borrow().saved.as_ref(), Some(facts.before));
            assert_ne!(facts.desired, facts.acknowledged);
            assert_ne!(fake.0.borrow().saved.as_ref(), Some(facts.desired));
            Ok(())
        })
        .unwrap();
        assert_eq!(fake.0.borrow().effects, 0);
        assert_eq!(row_pin_record(&pin, &b, true).revision, 1);
        assert!(owner.create_address(address_policy()).is_err());
    }
    let fake = Fake::new();
    let owner = fake.owner();
    let b = binding();
    assert!(owner
        .record_read_pin()
        .unwrap()
        .with_cleanup_write_attempt(&b.scope, b.network_epoch, |_| Ok(()))
        .is_err());
    assert_eq!(fake.0.borrow().effects, 0);
}

// Break: CAS succeeded but exact readback failed; Stop compares only the old
// local record and cannot retire its own known attempted interface write.
#[test]
fn cleanup_reconciles_own_interface_write_after_cas_readback_error_or_unwind() {
    for site_prefix in [0, 64] {
        for revision in [2, 3] {
            for unwind in [false, true] {
                let fake = Fake::new();
                fake.0.borrow_mut().ip.SitePrefixLength = site_prefix;
                let mut owner = fake.owner();
                let mut desired = owner.snapshot().unwrap().interface.policy;
                desired.weak_host_send = true;
                desired.weak_host_receive = true;
                let b = binding();
                let pin = owner.record_read_pin().unwrap();
                fake.0.borrow_mut().journal_load_fault = Some((revision, unwind));
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    owner.change_interface(desired.clone())
                }));
                assert!(result.is_err() || result.unwrap().is_err());
                let ack = row_pin_record(&pin, &b, true);
                assert_eq!(ack.revision, revision - 1);
                assert!(owner.change_interface(desired).is_err());
                owner.stop().unwrap();
                assert_eq!(row_pin_record(&pin, &b, true).phase, Phase::Stopped);
                assert_eq!(
                    row_pin_record(&pin, &b, true)
                        .baseline
                        .interface
                        .policy
                        .site_prefix_length,
                    site_prefix
                );
                assert_eq!(fake.0.borrow().ip.SitePrefixLength, site_prefix);
                assert_eq!(fake.0.borrow().effects, if revision == 3 { 2 } else { 0 });
                assert!(
                    !decode_interface(&fake.0.borrow().ip)
                        .unwrap()
                        .policy
                        .weak_host_send
                );
                assert!(pin
                    .with_record(&b.scope, b.network_epoch, |_| Ok(()))
                    .is_err());
            }
        }
    }
}

#[test]
fn cleanup_reconcile_denies_foreign_write_or_native_context_without_any_effect() {
    for wrong in 0..5 {
        let fake = Fake::new();
        let mut owner = fake.owner();
        fake.0.borrow_mut().journal_load_fault = Some((2, false));
        assert!(owner.change_interface(weak()).is_err());
        {
            let mut s = fake.0.borrow_mut();
            match wrong {
                0 => s.saved.as_mut().unwrap().revision += 1,
                1 => {
                    s.saved
                        .as_mut()
                        .unwrap()
                        .binding
                        .scope
                        .connection_generation += 1
                }
                2 => {
                    let pending = s.saved.as_mut().unwrap().pending.as_mut().unwrap();
                    let Target::Interface(policy) = &mut pending.target else {
                        panic!("expected pending interface write");
                    };
                    policy.weak_host_receive = !policy.weak_host_receive;
                }
                3 => s.identity.guid[0] ^= 1,
                _ => s.ip.Metric += 1,
            }
        }
        if wrong < 3 {
            // The journal's durable truth is the atomic tempfile, not the
            // observed-write cache used by the native fault adapter.
            let foreign = fake.0.borrow().saved.as_ref().unwrap().clone();
            fake.write_journal(&foreign).unwrap();
        }
        assert!(owner.stop().is_err(), "wrong {wrong}");
        assert_eq!(fake.0.borrow().effects, 0);
    }
}

// Raw-store firewall is actual production validate_transition: an explicit
// cleanup view cannot confirm a forward Captured revision even for own bytes.
#[test]
fn cleanup_resolution_of_pending_interface_writes_never_saves_forward_phase() {
    for fault in 0..3 {
        let fake = Fake::new();
        let mut owner = fake.owner();
        match fault {
            0 => fake.0.borrow_mut().journal_at = Some((2, Fault::LostAck)),
            1 => fake.0.borrow_mut().journal_load_fault = Some((2, false)),
            _ => fake.0.borrow_mut().panic_set = true,
        }
        let changed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.change_interface(weak())
        }));
        if fault == 2 {
            assert!(changed.is_err(), "native effect must unwind after apply");
            fake.0.borrow_mut().panic_set = false;
        } else {
            assert!(changed.unwrap().is_err());
        }
        owner
            .enter_storage_cleanup(|journal| {
                journal.0.borrow_mut().cleanup_storage = true;
                Ok(())
            })
            .unwrap();
        owner.stop().unwrap();
        assert_eq!(
            fake.0.borrow().saved.as_ref().unwrap().phase,
            Phase::Stopped
        );
        assert!(owner.change_interface(weak()).is_err());
    }
}

#[test]
fn row_record_pin_false_or_failed_cas_ack_does_not_advance() {
    for fault in [Fault::FalseAck, Fault::Unapplied] {
        let fake = Fake::new();
        let mut owner = fake.owner();
        let p = owner.record_read_pin().unwrap();
        fake.0.borrow_mut().journal_fault = fault;
        assert!(owner.change_interface(weak()).is_err());
        assert_eq!(row_pin_record(&p, &binding(), true).revision, 1);
        assert_eq!(fake.0.borrow().effects, 0);
        assert_eq!(
            p.with_record(&binding().scope, binding().network_epoch, |_| Ok(())),
            Err(Error::Retired)
        );
    }
}

#[test]
fn row_record_pin_cas_reread_error_or_unwind_keeps_previous_ack() {
    for unwind in [false, true] {
        let fake = Fake::new();
        let mut owner = fake.owner();
        let p = owner.record_read_pin().unwrap();
        fake.0.borrow_mut().journal_load_fault = Some((2, unwind));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.change_interface(weak())
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert_eq!(fake.0.borrow().saved.as_ref().unwrap().revision, 2);
        assert_eq!(row_pin_record(&p, &binding(), true).revision, 1);
        assert_eq!(fake.0.borrow().effects, 0);
        assert_eq!(
            p.with_record(&binding().scope, binding().network_epoch, |_| Ok(())),
            Err(Error::Retired)
        );
    }
}

#[test]
fn row_record_pin_lost_capture_ack_cannot_issue_or_resume_from_equal_json() {
    let fake = Fake::new();
    fake.0.borrow_mut().journal_fault = Fault::LostAck;
    let mut owner = fake.owner();
    assert_eq!(fake.0.borrow().saved.as_ref().unwrap().revision, 1);
    assert!(owner.record_read_pin().is_err());
    assert_eq!(owner.change_interface(weak()), Err(Error::Retired));
    assert!(RowOwner::capture(binding(), fake.clone(), fake.clone(), fake.clone()).is_err());
    assert_eq!(fake.0.borrow().effects, 0);
}

#[test]
fn row_record_pin_capture_handoff_retains_baseline_ack_before_postflight_error_or_unwind() {
    for unwind in [false, true] {
        let fake = Fake::new();
        fn after_ack(unwind: bool) -> ReadHook {
            Box::new(move |s| {
                if s.saved.is_none() {
                    s.read_hook = Some(after_ack(unwind));
                    return;
                }
                assert_eq!(s.saved.as_ref().unwrap().revision, 1);
                if unwind {
                    panic!("capture postflight after baseline ACK");
                }
                s.binding.network_epoch += 1;
            })
        }
        fake.0.borrow_mut().read_hook = Some(after_ack(unwind));
        let handed = Rc::new(RefCell::new(None));
        let mut destination =
            RowCaptureSlot::new(binding(), fake.clone(), fake.clone(), fake.clone());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            RowOwner::capture_with_record_pin_into(&mut destination, |p| {
                assert!(fake.0.borrow().locked);
                assert_eq!(row_pin_record(&p, &binding(), false).revision, 1);
                *handed.borrow_mut() = Some(p);
                Ok(())
            })
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        let owner = destination
            .owner_mut()
            .expect("original owner survives capture failure");
        assert!(owner
            .record_read_pin()
            .unwrap()
            .same_original(handed.borrow().as_ref().unwrap()));
        assert_eq!(owner.change_interface(weak()), Err(Error::Retired));
        let retained = handed.borrow();
        let p = retained
            .as_ref()
            .expect("actual baseline ACK must be retained before postflight");
        assert_eq!(
            p.with_record(&binding().scope, binding().network_epoch, |_| Ok(())),
            Err(Error::Retired)
        );
        let actual = row_pin_record(p, &binding(), true);
        assert_eq!(actual.revision, 1);
        assert_eq!(actual.phase, Phase::Captured);
        assert!(actual.pending.is_none());
        assert_eq!(actual, fake.0.borrow().saved.clone().unwrap());
        assert_eq!(fake.0.borrow().effects, 0);
    }
}

#[test]
fn row_record_pin_capture_handoff_callback_error_or_unwind_retains_cleanup_facts() {
    for unwind in [false, true] {
        let fake = Fake::new();
        let handed = Rc::new(RefCell::new(None));
        let mut destination =
            RowCaptureSlot::new(binding(), fake.clone(), fake.clone(), fake.clone());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            RowOwner::capture_with_record_pin_into(&mut destination, |p| {
                *handed.borrow_mut() = Some(p);
                if unwind {
                    panic!("capture handoff unwound after retention");
                }
                Err(Error::Conflict)
            })
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        let owner = destination
            .owner_mut()
            .expect("original owner survives capture failure");
        assert!(owner
            .record_read_pin()
            .unwrap()
            .same_original(handed.borrow().as_ref().unwrap()));
        assert_eq!(owner.change_interface(weak()), Err(Error::Retired));
        let retained = handed.borrow();
        let p = retained.as_ref().expect("successful original ACK handoff");
        p.with_cleanup_record(&binding().scope, binding().network_epoch, |facts| {
            assert!(facts.cleanup_only);
            assert_eq!(facts.acknowledged.revision, 1);
            assert_eq!(facts.acknowledged.phase, Phase::Captured);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            p.with_record(&binding().scope, binding().network_epoch, |_| Ok(())),
            Err(Error::Retired)
        );
        assert_eq!(fake.0.borrow().effects, 0);
    }
}

#[test]
fn row_record_pin_lost_capture_ack_never_hands_off_an_original_receipt() {
    let fake = Fake::new();
    fake.0.borrow_mut().journal_fault = Fault::LostAck;
    let invoked = std::cell::Cell::new(false);
    let mut destination = RowCaptureSlot::new(binding(), fake.clone(), fake.clone(), fake.clone());
    assert!(
        RowOwner::capture_with_record_pin_into(&mut destination, |_| {
            invoked.set(true);
            Ok(())
        },)
        .is_err()
    );
    let owner = destination
        .owner_mut()
        .expect("lost ACK retains attempted baseline owner");
    assert!(!invoked.get());
    assert!(owner.record_read_pin().is_err());
    assert_eq!(owner.change_interface(weak()), Err(Error::Retired));
    assert_eq!(fake.0.borrow().saved.as_ref().unwrap().revision, 1);
    assert_eq!(fake.0.borrow().effects, 0);
}

#[test]
fn row_record_pin_cleanup_wrong_context_denies_and_does_not_rearm() {
    let fake = Fake::new();
    let owner = fake.owner();
    let p = owner.record_read_pin().unwrap();
    let b = binding();
    assert_eq!(
        p.with_cleanup_record(&b.scope, b.network_epoch + 1, |_| Ok(())),
        Err(Error::Conflict)
    );
    assert_eq!(
        p.with_record(&b.scope, b.network_epoch, |_| Ok(())),
        Err(Error::Retired)
    );
    assert_eq!(row_pin_record(&p, &b, true).revision, 1);
}

#[test]
fn row_record_pin_same_window_read_rejects_ack_change_during_callback() {
    let fake = Fake::new();
    let mut owner = fake.owner();
    let p = owner.record_read_pin().unwrap();
    let b = binding();
    assert_eq!(
        p.with_record(&b.scope, b.network_epoch, |facts| {
            assert_eq!(facts.acknowledged.revision, 1);
            owner.change_interface(weak())?;
            // The immutable borrowed historical receipt remains valid, but cannot
            // be returned as a successful comparison of the now-current window.
            assert_eq!(facts.acknowledged.revision, 1);
            Ok(())
        }),
        Err(Error::Conflict)
    );
    assert_eq!(row_pin_record(&p, &b, true).revision, 3);
    assert_eq!(
        p.with_record(&b.scope, b.network_epoch, |_| Ok(())),
        Err(Error::Retired)
    );
}

#[test]
fn row_record_pin_member_roles_are_facts_and_never_a_carrier_receipt() {
    for role in [Role::MemberA, Role::MemberB] {
        let fake = Fake::new();
        let (mut owner, _files) = protected_owner(&fake, role);
        let p = owner.record_read_pin().unwrap();
        let b = fake.0.borrow().binding.clone();
        p.with_record(&b.scope, b.network_epoch, |facts| {
            assert_eq!(facts.binding.role, role);
            assert!(facts.acknowledged.creation.is_none());
            assert!(facts.acknowledged.current.address.is_none());
            Ok(())
        })
        .unwrap();
        assert!(owner.create_address(address_policy()).is_err());
        assert_eq!(
            p.with_record(&b.scope, b.network_epoch, |_| Ok(())),
            Err(Error::Retired)
        );
        assert_eq!(fake.0.borrow().effects, 0);
    }
}

#[test]
fn row_record_pin_unwound_effect_retains_actual_pending_ack() {
    let fake = Fake::new();
    let mut owner = fake.owner();
    let p = owner.record_read_pin().unwrap();
    fake.0.borrow_mut().panic_set = true;
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || owner.change_interface(weak())
    ))
    .is_err());
    let actual = row_pin_record(&p, &binding(), true);
    assert_eq!(actual.revision, 2);
    assert!(actual.pending.is_some());
    assert!(!actual.current.interface.policy.weak_host_send);
    assert_eq!(actual.phase, Phase::Captured);
    assert_eq!(
        p.with_record(&binding().scope, binding().network_epoch, |_| Ok(())),
        Err(Error::Retired)
    );
    fake.0.borrow_mut().panic_set = false;
    owner.stop().unwrap();
    assert_eq!(row_pin_record(&p, &binding(), true).phase, Phase::Stopped);
}

#[test]
fn row_record_pin_cleanup_failed_stop_and_drop_report_only_acknowledged_facts() {
    let fake = Fake::new();
    let (mut owner, _files) = retained_created(&fake);
    let b = fake.0.borrow().binding.clone();
    let p = owner.record_read_pin().unwrap();
    fake.0.borrow_mut().api_error = true;
    assert!(owner.stop().is_err());
    let effects = fake.0.borrow().effects;
    drop(owner);
    p.with_cleanup_record(&b.scope, b.network_epoch, |facts| {
        assert!(facts.cleanup_only);
        assert_eq!(facts.acknowledged.phase, Phase::Captured);
        assert_eq!(facts.acknowledged.revision, 3);
        assert!(facts.acknowledged.current.address.is_some());
        assert!(facts.acknowledged.pending.is_none());
        Ok(())
    })
    .unwrap();
    assert_eq!(fake.0.borrow().effects, effects);
    assert_eq!(
        p.with_record(&b.scope, b.network_epoch, |_| Ok(())),
        Err(Error::Retired)
    );
}

#[test]
fn row_record_pin_protected_lost_ack_is_not_imported_from_matching_saved_bytes() {
    for confirmation in [false, true] {
        let fake = Fake::new();
        let (mut owner, files) = protected_owner(&fake, Role::Carrier);
        let b = fake.0.borrow().binding.clone();
        let p = owner.record_read_pin().unwrap();
        if confirmation {
            fake.0.borrow_mut().create_hook = Some(Box::new(|s| s.private_fault = Fault::LostAck));
        } else {
            fake.0.borrow_mut().private_fault = Fault::LostAck;
        }
        assert!(owner.create_address(address_policy()).is_err());
        let (mut reopened, saved) =
            protected::WindowsCarrierRowsStore::open(files, b.clone()).unwrap();
        assert_eq!(reopened.load(&b).unwrap(), saved);
        let saved = saved.unwrap();
        assert_eq!(saved.revision, if confirmation { 3 } else { 2 });
        let receipt = row_pin_record(&p, &b, true);
        assert_eq!(receipt.revision, if confirmation { 2 } else { 1 });
        assert_eq!(receipt.pending.is_some(), confirmation);
        assert!(RowOwner::capture(b.clone(), fake.clone(), fake.clone(), reopened).is_err());
        let before = (
            fake.0.borrow().private_bytes.clone(),
            fake.0.borrow().effects,
        );
        assert_eq!(row_pin_record(&p, &b, true), receipt);
        assert_eq!(
            p.with_record(&b.scope, b.network_epoch, |_| Ok(())),
            Err(Error::Retired)
        );
        assert_eq!(
            (
                fake.0.borrow().private_bytes.clone(),
                fake.0.borrow().effects
            ),
            before
        );
    }
}

#[test]
fn row_record_pin_actual_closing_pending_ack_is_not_successful_native_cleanup() {
    let fake = Fake::new();
    let (mut owner, _files) = retained_created(&fake);
    owner.change_interface(weak()).unwrap();
    let b = fake.0.borrow().binding.clone();
    let p = owner.record_read_pin().unwrap();
    fake.0.borrow_mut().deny_authorize = true;
    assert!(owner.stop().is_err());
    p.with_cleanup_record(&b.scope, b.network_epoch, |facts| {
        assert!(facts.cleanup_only);
        assert_eq!(facts.acknowledged.phase, Phase::Closing);
        assert_eq!(facts.acknowledged.revision, 7);
        assert!(facts.acknowledged.pending.is_some());
        assert!(facts.acknowledged.current.address.is_some());
        assert!(facts.acknowledged.current.interface.policy.weak_host_send);
        assert!(fake.0.borrow().address.is_some());
        assert_eq!(facts.acknowledged, fake.0.borrow().saved.as_ref().unwrap());
        Ok(())
    })
    .unwrap();
    assert_eq!(fake.0.borrow().effects, 2);
    fake.0.borrow_mut().deny_authorize = false;
    owner.stop().unwrap();
    assert_eq!(row_pin_record(&p, &b, true).phase, Phase::Stopped);
    assert_eq!(
        p.with_record(&b.scope, b.network_epoch, |_| Ok(())),
        Err(Error::Retired)
    );
}

#[test]
fn row_record_pin_callback_error_unwind_or_swallowed_nested_failure_revokes() {
    for case in 0..3 {
        let fake = Fake::new();
        let owner = fake.owner();
        let p = owner.record_read_pin().unwrap();
        let q = owner.record_read_pin().unwrap();
        let b = binding();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            p.with_record(&b.scope, b.network_epoch, |_| match case {
                0 => Err(Error::Conflict),
                1 => panic!("comparison callback unwound"),
                _ => {
                    let _ = q.with_record(&b.scope, b.network_epoch + 1, |_| Ok(()));
                    Ok(())
                }
            })
        }));
        if case == 1 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert_eq!(
            q.with_record(&b.scope, b.network_epoch, |_| Ok(())),
            Err(Error::Retired)
        );
        assert_eq!(row_pin_record(&q, &b, true).revision, 1);
    }
}

#[test]
fn row_record_pin_drop_before_authority_destructor_cannot_revive_or_synthesize_cleanup() {
    struct DroppingAuthority {
        fake: Fake,
        handed: Rc<RefCell<Option<RowRecordReadPin>>>,
    }
    impl Authority for DroppingAuthority {
        type Creator = Fake;
        fn locked<T>(&mut self, action: impl FnOnce(&mut Fake) -> Result<T>) -> Result<T> {
            self.fake.locked(action)
        }
    }
    impl Drop for DroppingAuthority {
        fn drop(&mut self) {
            let retained = self.handed.borrow();
            let Some(p) = retained.as_ref() else {
                return;
            };
            let b = binding();
            assert_eq!(
                p.with_record(&b.scope, b.network_epoch, |_| Ok(())),
                Err(Error::Retired)
            );
            assert_eq!(row_pin_record(p, &b, true).phase, Phase::Captured);
        }
    }
    let fake = Fake::new();
    let handed = Rc::new(RefCell::new(None));
    let owner = RowOwner::capture(
        binding(),
        DroppingAuthority {
            fake: fake.clone(),
            handed: Rc::clone(&handed),
        },
        fake.clone(),
        fake.clone(),
    )
    .unwrap();
    *handed.borrow_mut() = Some(owner.record_read_pin().unwrap());
    drop(owner);
    assert_eq!(fake.0.borrow().effects, 0);
}

#[test]
fn row_record_pin_and_facts_are_not_clone_send_sync_or_serializable() {
    trait AmbiguousIfClone<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    struct IsClone;
    impl<T: Clone> AmbiguousIfClone<IsClone> for T {}
    trait AmbiguousIfSend<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    struct IsSend;
    impl<T: ?Sized + Send> AmbiguousIfSend<IsSend> for T {}
    trait AmbiguousIfSync<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    struct IsSync;
    impl<T: ?Sized + Sync> AmbiguousIfSync<IsSync> for T {}
    trait AmbiguousIfSerialize<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfSerialize<()> for T {}
    struct IsSerialize;
    impl<T: ?Sized + serde::Serialize> AmbiguousIfSerialize<IsSerialize> for T {}
    trait AmbiguousIfDeserialize<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfDeserialize<()> for T {}
    struct IsDeserialize;
    impl<T: serde::de::DeserializeOwned> AmbiguousIfDeserialize<IsDeserialize> for T {}
    let _ = <RowRecordReadPin as AmbiguousIfClone<_>>::check;
    let _ = <RowRecordReadPin as AmbiguousIfSend<_>>::check;
    let _ = <RowRecordReadPin as AmbiguousIfSync<_>>::check;
    let _ = <RowRecordReadPin as AmbiguousIfSerialize<_>>::check;
    let _ = <RowRecordReadPin as AmbiguousIfDeserialize<_>>::check;
    let _ = <RowRecordFacts<'_> as AmbiguousIfClone<_>>::check;
    let _ = <RowRecordFacts<'_> as AmbiguousIfSend<_>>::check;
    let _ = <RowRecordFacts<'_> as AmbiguousIfSync<_>>::check;
    let _ = <RowRecordFacts<'_> as AmbiguousIfSerialize<_>>::check;
}

// These exercise the actual RowOwner with only creator/kernel/private-file IO
// doubled. Removing ACK provenance, readiness, fresh issuance fences or the
// irreversible shared revocation must break these consumer-visible facts.
fn ready_read_pin(fake: &Fake) -> (ProtectedOwner, ProtectedFiles, CreatedAddressReadPin) {
    let (mut owner, files) = retained_created(fake);
    fake.0.borrow_mut().address.as_mut().unwrap().DadState = 4;
    owner
        .wait_address_ready_with(&AtomicBool::new(false), &mut TestClock::new(fake))
        .unwrap();
    let pin = owner.created_address_read_pin().unwrap();
    (owner, files, pin)
}
#[test]
fn address_read_pin_requires_wait_ready_even_if_native_row_is_preferred() {
    let fake = Fake::new();
    let (mut owner, _) = retained_created(&fake);
    fake.0.borrow_mut().address.as_mut().unwrap().DadState = 4;
    assert!(owner.created_address_read_pin().is_err());
    owner
        .wait_address_ready_with(&AtomicBool::new(false), &mut TestClock::new(&fake))
        .unwrap();
    let pin = owner.created_address_read_pin().unwrap();
    let b = fake.0.borrow().binding.clone();
    let facts = pin.read(&b.scope, b.network_epoch).unwrap();
    assert_eq!(facts.binding, &b);
    assert_eq!(facts.captured.observed.dad_state, 1);
    assert_eq!(facts.captured.observed.creation_timestamp, 123456789);
    assert!(same_address(
        facts.captured,
        &decode_address(&address_raw()).unwrap()
    ));
    assert_eq!(fake.0.borrow().effects, 1);
}
#[test]
fn address_read_pin_is_independent_during_actual_locked_interface_update() {
    let fake = Fake::new();
    let (mut owner, _, pin) = ready_read_pin(&fake);
    let b = fake.0.borrow().binding.clone();
    let second = owner.created_address_read_pin().unwrap();
    fake.0.borrow_mut().read_hook = Some(Box::new(move |s| {
        assert!(s.locked);
        let facts = second.read(&b.scope, b.network_epoch).unwrap();
        assert_eq!(facts.captured.observed.dad_state, 1);
        assert_eq!(facts.binding, &s.binding);
    }));
    owner.change_interface(weak()).unwrap();
    let b = fake.0.borrow().binding.clone();
    assert!(pin.read(&b.scope, b.network_epoch).is_ok());
    owner
        .change_interface(decode_interface(&interface_raw()).unwrap().policy)
        .unwrap();
    assert!(pin.read(&b.scope, b.network_epoch).is_ok());
    assert_eq!(fake.0.borrow().effects, 3);
}
#[test]
fn address_read_pin_caught_nested_error_cannot_be_rearmed_by_successful_update() {
    let fake = Fake::new();
    let (mut owner, _, pin) = ready_read_pin(&fake);
    let nested = owner.created_address_read_pin().unwrap();
    let b = fake.0.borrow().binding.clone();
    let foreign_epoch = b.network_epoch + 1;
    let scope = b.scope.clone();
    fake.0.borrow_mut().read_hook = Some(Box::new(move |_| {
        // G may catch and ignore its own factual pin error while C's update
        // callback still returns success. Neither path may clear revocation.
        assert!(nested.read(&scope, foreign_epoch).is_err());
    }));
    owner.change_interface(weak()).unwrap();
    assert!(owner.snapshot().is_ok());
    assert!(pin.read(&b.scope, b.network_epoch).is_err());
    assert!(owner.created_address_read_pin().is_err());
    owner.stop().unwrap();
    assert!(fake.0.borrow().saved.as_ref().unwrap().creation.is_some());
}
#[test]
fn address_read_pin_caught_nested_error_during_issuance_cannot_return_a_pin() {
    let fake = Fake::new();
    let (mut owner, _, pin) = ready_read_pin(&fake);
    let nested = owner.created_address_read_pin().unwrap();
    let b = fake.0.borrow().binding.clone();
    let scope = b.scope.clone();
    let epoch = b.network_epoch;
    fake.0.borrow_mut().read_hook = Some(Box::new(move |_| {
        assert!(nested.read(&scope, epoch + 1).is_err());
    }));
    assert!(owner.created_address_read_pin().is_err());
    assert!(pin.read(&b.scope, b.network_epoch).is_err());
    assert_eq!(fake.0.borrow().effects, 1);
}
#[test]
fn address_read_pin_rejects_foreign_scope_epoch_without_rearming() {
    for epoch in [false, true] {
        let fake = Fake::new();
        let (mut owner, _, pin) = ready_read_pin(&fake);
        let second = owner.created_address_read_pin().unwrap();
        let b = fake.0.borrow().binding.clone();
        let mut foreign = b.scope.clone();
        foreign.connection_generation += 1;
        assert!(if epoch {
            pin.read(&b.scope, b.network_epoch + 1)
        } else {
            pin.read(&foreign, b.network_epoch)
        }
        .is_err());
        assert!(pin.read(&b.scope, b.network_epoch).is_err());
        assert!(second.read(&b.scope, b.network_epoch).is_err());
        assert!(owner.created_address_read_pin().is_err());
    }
}
#[test]
fn address_read_pin_all_issuances_revoke_on_ignored_owner_error_and_cleanup() {
    let fake = Fake::new();
    let (mut owner, _, pin) = ready_read_pin(&fake);
    let second = owner.created_address_read_pin().unwrap();
    let b = fake.0.borrow().binding.clone();
    fake.0.borrow_mut().api_error = true;
    assert!(owner.snapshot().is_err());
    fake.0.borrow_mut().api_error = false;
    assert!(owner.snapshot().is_ok()); // existing cleanup observation contract
    for pin in [&pin, &second] {
        assert!(pin.read(&b.scope, b.network_epoch).is_err());
    }
    assert!(owner.created_address_read_pin().is_err());
    owner.stop().unwrap();
    assert!(pin.read(&b.scope, b.network_epoch).is_err());
}
#[test]
fn address_read_pin_uncertain_set_or_journal_ack_revokes_even_when_exactly_resolved() {
    for journal in [false, true] {
        let fake = Fake::new();
        let (mut owner, _, pin) = ready_read_pin(&fake);
        let b = fake.0.borrow().binding.clone();
        if journal {
            fake.0.borrow_mut().private_fault = Fault::LostAck;
            assert!(owner.change_interface(weak()).is_err());
        } else {
            fake.0.borrow_mut().kernel_fault = Fault::LostAck;
            owner.change_interface(weak()).unwrap();
        }
        assert!(pin.read(&b.scope, b.network_epoch).is_err());
        assert!(owner.created_address_read_pin().is_err());
    }
}
#[test]
fn address_read_pin_unwind_stop_and_owner_drop_permanently_revoke() {
    for case in 0..4 {
        let fake = Fake::new();
        let (mut owner, _, pin) = ready_read_pin(&fake);
        let b = fake.0.borrow().binding.clone();
        match case {
            0 => {
                fake.0.borrow_mut().panic_set = true;
                assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    owner.change_interface(weak())
                }))
                .is_err());
                fake.0.borrow_mut().panic_set = false;
                owner.stop().unwrap();
            }
            1 => owner.stop().unwrap(),
            2 => {
                fake.0.borrow_mut().api_error = true;
                assert!(owner.stop().is_err());
                fake.0.borrow_mut().api_error = false;
            }
            _ => drop(owner),
        }
        assert!(pin.read(&b.scope, b.network_epoch).is_err(), "case {case}");
    }
}
#[test]
fn address_read_pin_owner_drop_revokes_before_original_authority_is_dropped() {
    struct DroppingAuthority {
        fake: Fake,
        handed_pin: Rc<RefCell<Option<CreatedAddressReadPin>>>,
    }
    impl Authority for DroppingAuthority {
        type Creator = Fake;
        fn locked<T>(&mut self, action: impl FnOnce(&mut Fake) -> Result<T>) -> Result<T> {
            self.fake.locked(action)
        }
    }
    impl Drop for DroppingAuthority {
        fn drop(&mut self) {
            let b = self.fake.0.borrow().binding.clone();
            if let Some(pin) = self.handed_pin.borrow().as_ref() {
                assert!(pin.read(&b.scope, b.network_epoch).is_err());
            }
        }
    }
    let fake = Fake::new();
    let handed_pin = Rc::new(RefCell::new(None));
    let mut owner = RowOwner::capture(
        binding(),
        DroppingAuthority {
            fake: fake.clone(),
            handed_pin: Rc::clone(&handed_pin),
        },
        fake.clone(),
        fake.clone(),
    )
    .unwrap();
    owner.create_address(address_policy()).unwrap();
    fake.0.borrow_mut().address.as_mut().unwrap().DadState = 4;
    owner
        .wait_address_ready_with(&AtomicBool::new(false), &mut TestClock::new(&fake))
        .unwrap();
    *handed_pin.borrow_mut() = Some(owner.created_address_read_pin().unwrap());
    drop(owner);
    assert_eq!(fake.0.borrow().effects, 1);
}
#[test]
fn address_read_pin_timeout_cancel_and_sleep_unwind_revoke_existing_pins() {
    for case in 0..3 {
        let fake = Fake::new();
        let (mut owner, _, pin) = ready_read_pin(&fake);
        let b = fake.0.borrow().binding.clone();
        fake.0.borrow_mut().address.as_mut().unwrap().DadState = 1;
        let mut clock = TestClock::new(&fake);
        if case == 2 {
            clock.after_sleep = Box::new(|_, _, _| panic!("read pin readiness unwind"));
        }
        let cancelled = AtomicBool::new(case == 1);
        if case == 2 {
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                owner.wait_address_ready_with(&cancelled, &mut clock)
            }))
            .is_err());
        } else {
            assert_eq!(
                owner.wait_address_ready_with(&cancelled, &mut clock),
                Err(Error::Retired)
            );
        }
        assert!(pin.read(&b.scope, b.network_epoch).is_err());
        fake.0.borrow_mut().address.as_mut().unwrap().DadState = 4;
        assert!(owner.created_address_read_pin().is_err());
        owner.stop().unwrap();
        assert!(pin.read(&b.scope, b.network_epoch).is_err());
    }
}
#[test]
fn address_read_pin_issuance_rechecks_actual_creator_native_and_protected_journal() {
    let faults: [fn(&mut State); 7] = [
        |s| s.binding.network_epoch += 1,
        |s| s.creator_alive = false,
        |s| s.identity.guid[0] += 1,
        |s| s.address.as_mut().unwrap().CreationTimeStamp += 1,
        |s| s.ip.Metric += 1,
        |s| s.address.as_mut().unwrap().DadState = 3,
        |s| {
            s.private_bytes
                .insert(private_files::PrivateFile::CarrierRows, b"{}".to_vec());
        },
    ];
    for fault in faults {
        let fake = Fake::new();
        let (mut owner, _, pin) = ready_read_pin(&fake);
        let b = fake.0.borrow().binding.clone();
        fault(&mut fake.0.borrow_mut());
        assert!(owner.created_address_read_pin().is_err());
        assert!(pin.read(&b.scope, b.network_epoch).is_err());
        assert_eq!(fake.0.borrow().effects, 1);
    }
}
#[test]
fn address_read_pin_never_imports_native_matches_journal_or_member_role() {
    for role in [Role::Carrier, Role::MemberA, Role::MemberB] {
        let fake = Fake::new();
        let (mut owner, _) = protected_owner(&fake, role);
        fake.0.borrow_mut().address = Some(address_raw());
        assert!(owner.created_address_read_pin().is_err());
        assert_eq!(fake.0.borrow().effects, 0);
    }
    for fault in [Fault::LostAck, Fault::FalseAck, Fault::Unapplied] {
        let fake = Fake::new();
        let (mut owner, _) = protected_owner(&fake, Role::Carrier);
        fake.0.borrow_mut().kernel_fault = fault;
        assert!(owner.create_address(address_policy()).is_err());
        fake.0.borrow_mut().address = Some(address_raw());
        assert!(owner.created_address_read_pin().is_err());
    }
}

#[test]
fn address_read_pin_late_journal_or_epoch_drift_during_issuance_revokes_all_pins() {
    for epoch in [false, true] {
        let fake = Fake::new();
        let (mut owner, _, pin) = ready_read_pin(&fake);
        let b = fake.0.borrow().binding.clone();
        fake.0.borrow_mut().read_hook = Some(Box::new(move |s| {
            if epoch {
                s.binding.network_epoch += 1;
            } else {
                s.private_bytes
                    .insert(private_files::PrivateFile::CarrierRows, b"{}".to_vec());
            }
        }));
        assert!(owner.created_address_read_pin().is_err());
        assert!(pin.read(&b.scope, b.network_epoch).is_err());
        assert_eq!(fake.0.borrow().effects, 1);
    }
}
#[test]
fn address_read_pin_stop_revokes_before_its_first_native_read() {
    let fake = Fake::new();
    let (mut owner, _, pin) = ready_read_pin(&fake);
    let b = fake.0.borrow().binding.clone();
    fake.0.borrow_mut().read_hook = Some(Box::new(move |_| {
        assert!(pin.read(&b.scope, b.network_epoch).is_err());
    }));
    owner.stop().unwrap();
    assert_eq!(fake.0.borrow().effects, 2);
    assert!(fake.0.borrow().saved.as_ref().unwrap().creation.is_some());
}
#[test]
fn address_read_pin_historical_receipt_does_not_claim_current_source_preferred() {
    let fake = Fake::new();
    let (_owner, _, pin) = ready_read_pin(&fake);
    let b = fake.0.borrow().binding.clone();
    fake.0.borrow_mut().address.as_mut().unwrap().DadState = 3;
    let facts = pin.read(&b.scope, b.network_epoch).unwrap();
    assert_eq!(facts.captured.observed.dad_state, 1);
    // Comparison ignores volatile DAD; actual live SourcePreferred must be
    // independently required by NativeRuntime, never inferred from these facts.
    let live = decode_address(fake.0.borrow().address.as_ref().unwrap()).unwrap();
    assert!(same_address(facts.captured, &live));
    assert_eq!(live.observed.dad_state, 3);
}
#[test]
fn address_read_pin_and_borrowed_facts_cannot_clone_send_or_sync() {
    // Ambiguous trait selection is a compile-time negative assertion. A second
    // matching impl appears if a capability accidentally acquires the trait.
    trait AmbiguousIfClone<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    struct IsClone;
    impl<T: Clone> AmbiguousIfClone<IsClone> for T {}
    trait AmbiguousIfSend<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    struct IsSend;
    impl<T: ?Sized + Send> AmbiguousIfSend<IsSend> for T {}
    trait AmbiguousIfSync<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    struct IsSync;
    impl<T: ?Sized + Sync> AmbiguousIfSync<IsSync> for T {}
    let _ = <CreatedAddressReadPin as AmbiguousIfClone<_>>::check;
    let _ = <CreatedAddressReadPin as AmbiguousIfSend<_>>::check;
    let _ = <CreatedAddressReadPin as AmbiguousIfSync<_>>::check;
    let _ = <CreatedAddressFacts<'_> as AmbiguousIfClone<_>>::check;
    let _ = <CreatedAddressFacts<'_> as AmbiguousIfSend<_>>::check;
    let _ = <CreatedAddressFacts<'_> as AmbiguousIfSync<_>>::check;
}

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
fn protected_pending_revision_changed_during_last_native_read_prevents_the_effect() {
    fn drift(s: &mut State) {
        let path = s.journal_directory.path().join("rows.json");
        let mut actual = Record::decode(&std::fs::read(&path).unwrap()).unwrap();
        if actual.pending.is_none() {
            s.read_hook = Some(Box::new(drift));
            return;
        }
        actual.revision += 1;
        std::fs::write(path, actual.encode().unwrap()).unwrap();
        s.saved = Some(actual);
    }
    for create in [false, true] {
        let fake = Fake::new();
        let mut owner = fake.owner();
        fake.0.borrow_mut().read_hook = Some(Box::new(drift));
        let result = if create {
            owner.create_address(address_policy())
        } else {
            owner.change_interface(weak())
        };
        assert!(result.is_err());
        assert_eq!(
            fake.0.borrow().effects,
            0,
            "last durable fence before effect, create={create}"
        );
        assert!(owner.create_address(address_policy()).is_err());
    }
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
fn stage3_interface_cleanup_keeps_original_carrier_address_until_stage6_stop() {
    let fake = Fake::new();
    let mut owner = fake.owner();
    let pin = owner.record_read_pin().unwrap();
    owner.create_address(address_policy()).unwrap();
    owner.change_interface(weak()).unwrap();
    let before = fake.0.borrow().saved.clone().unwrap();
    owner.restore_interface_for_cleanup().unwrap();
    let restored = fake.0.borrow().saved.clone().unwrap();
    assert_eq!(restored.phase, Phase::Closing);
    assert_eq!(restored.creation, before.creation);
    assert_eq!(restored.current.address, before.current.address);
    assert_eq!(
        restored.current.interface.policy,
        restored.baseline.interface.policy
    );
    assert!(restored.pending.is_none());
    assert!(pin
        .with_record(&binding().scope, binding().network_epoch, |_| Ok(()))
        .is_err());
    assert!(owner.change_interface(weak()).is_err());
    owner.restore_interface_for_cleanup().unwrap();
    assert_eq!(fake.0.borrow().saved.as_ref().unwrap(), &restored);
    owner.stop().unwrap();
    let stopped = fake.0.borrow().saved.clone().unwrap();
    assert_eq!(stopped.phase, Phase::Stopped);
    assert_eq!(stopped.creation, before.creation);
    assert!(stopped.current.address.is_none());
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
    // Lost durable ACKs are now cleanup-only, including exact reread. The old
    // successful-default expectation would overwrite an original ACK receipt.
    let expected_effects = [0, 0, 2, 1, 4, 4, 4, 4, 4, 4, 4];
    for at in 1..=11 {
        let fake = Fake::new();
        fake.0.borrow_mut().journal_at = Some((at, Fault::LostAck));
        let mut owner = fake.owner();
        if owner.change_interface(weak()).is_ok() {
            let _ = owner.create_address(address_policy());
        }
        let _ = owner.stop();
        if at == 4 {
            assert_eq!(owner.stop(), Err(Error::Pending));
            assert!(fake.0.borrow().saved.as_ref().unwrap().pending.is_some());
            assert!(fake.0.borrow().address.is_none());
        } else {
            owner.stop().unwrap();
            assert_eq!(
                fake.0.borrow().saved.as_ref().unwrap().phase,
                Phase::Stopped
            );
        }
        assert_eq!(
            fake.0.borrow().effects,
            expected_effects[at - 1],
            "revision {at}"
        );
        assert!(owner.create_address(address_policy()).is_err());
        assert_eq!(
            fake.0.borrow().effects,
            expected_effects[at - 1],
            "duplicate effect at {at}"
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
    SitePrefixChanged,
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
    cleanup_storage: bool, // Raw adapter only; uses actual schema validator.
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
    journal_load_fault: Option<(u64, bool)>,
    drift_on_confirmation: bool,
    private_bytes: std::collections::BTreeMap<private_files::PrivateFile, Vec<u8>>,
    private_reads: usize,
    private_fail: Option<private_files::PrivateFile>,
    private_fault: Fault,
    private_write_hook: Option<ReadHook>,
    read_hook: Option<ReadHook>,
    create_hook: Option<ReadHook>,
    address_error: bool,
    identity_error: bool,
}
type ReadHook = Box<dyn FnMut(&mut State)>;
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
            cleanup_storage: false,
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
            journal_load_fault: None,
            drift_on_confirmation: false,
            private_bytes: Default::default(),
            private_reads: 0,
            private_fail: None,
            private_fault: Fault::None,
            private_write_hook: None,
            read_hook: None,
            create_hook: None,
            address_error: false,
            identity_error: false,
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
        if self.0.borrow().identity_error {
            return Err(Error::Native);
        }
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
        if let Some(mut hook) = s.read_hook.take() {
            hook(&mut s);
        }
        if s.address_error {
            return Err(Error::Native);
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
        assert_eq!(
            row.SitePrefixLength, 0,
            "IPv4 Set requires SDK sentinel input"
        );
        // This IPv4 field cannot be modified by Set. Get retains its original
        // value, except for the explicit post-Set OS drift regression.
        next.SitePrefixLength = if matches!(fault, Fault::SitePrefixChanged) {
            0
        } else {
            s.ip.SitePrefixLength
        };
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
        if let Some(mut hook) = s.create_hook.take() {
            hook(&mut s);
        }
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
        let mut s = self.0.borrow_mut();
        if s.journal_load_fault.is_some_and(|(revision, _)| {
            s.saved
                .as_ref()
                .is_some_and(|saved| saved.revision == revision)
        }) {
            let (_, unwind) = s.journal_load_fault.take().unwrap();
            drop(s);
            if unwind {
                panic!("durable CAS reread unwound");
            }
            return Err(Error::Journal);
        }
        drop(s);
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
        if self.0.borrow().cleanup_storage {
            validate_transition(expected, desired, true)?;
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
// Test raw journal boundary ONLY. The production RowOwner must first issue its
// genuine sealed receipt; this cannot create one from the fake file or SDK row.
unsafe impl CreatedAddressCleanupJournal for Fake {
    fn compare_exchange_created_cleanup(
        &mut self,
        binding: &Binding,
        expected: &Record,
        desired: &Record,
        original: &CreatedAddressCleanupRead<'_>,
    ) -> Result<()> {
        self.assert_lock();
        original.verify_exchange(binding, expected, desired)?;
        if self.read_journal()?.as_ref() != Some(expected) {
            return Err(Error::Conflict);
        }
        let fault = {
            let mut s = self.0.borrow_mut();
            s.journal_writes += 1;
            std::mem::take(&mut s.journal_fault)
        };
        if matches!(fault, Fault::Unapplied) {
            return Err(Error::Journal);
        }
        if matches!(fault, Fault::FalseAck) {
            return Ok(());
        }
        self.write_journal(desired)?;
        self.0.borrow_mut().saved = self.read_journal()?;
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

// Only SDK IO is doubled: identity and row decoding and exact Binding checks
// run in production. Dropping either identity fence, projecting row fields,
// swallowing native errors or issuing an effect must break these tests.
struct ReadonlySdk {
    before: Result<MIB_IF_ROW2>,
    after: Result<MIB_IF_ROW2>,
    interface: Result<MIB_IPINTERFACE_ROW>,
    address: Result<Option<MIB_UNICASTIPADDRESS_ROW>>,
    reads: Vec<&'static str>,
    initializers: usize,
    mutations: usize,
}
impl ReadonlySdk {
    fn new() -> Self {
        let mut id = MIB_IF_ROW2 {
            InterfaceIndex: 33,
            InterfaceGuid: windows_sys::core::GUID {
                data1: 0x21212121,
                data2: 0x2121,
                data3: 0x2121,
                data4: [33; 8],
            },
            Type: 53,
            ..Default::default()
        };
        id.InterfaceLuid.Value = 3300;
        for (i, c) in "owned-C".encode_utf16().enumerate() {
            id.Alias[i] = c;
        }
        Self {
            before: Ok(id),
            after: Ok(id),
            interface: Ok(interface_raw()),
            address: Ok(Some(address_raw())),
            reads: Vec::new(),
            initializers: 0,
            mutations: 0,
        }
    }
    fn assert_no_effects(&self) {
        assert_eq!(self.initializers, 0, "policy called a writable initializer");
        assert_eq!(self.mutations, 0, "read-only view issued a native effect");
    }
}
impl Kernel for ReadonlySdk {
    fn identity(&mut self, key: RowKey) -> Result<NativeIdentity> {
        assert_eq!(
            key,
            RowKey {
                luid: 3300,
                index: 33
            }
        );
        let row = if self.reads.is_empty() {
            self.before
        } else {
            self.after
        };
        self.reads.push("identity");
        decode_identity(&row?)
    }
    fn interface(&mut self, key: RowKey) -> Result<MIB_IPINTERFACE_ROW> {
        assert_eq!(
            key,
            RowKey {
                luid: 3300,
                index: 33
            }
        );
        self.reads.push("interface");
        self.interface
    }
    fn address(
        &mut self,
        key: RowKey,
        address: [u8; 4],
    ) -> Result<Option<MIB_UNICASTIPADDRESS_ROW>> {
        assert_eq!(
            key,
            RowKey {
                luid: 3300,
                index: 33
            }
        );
        assert_eq!(address, [10, 240, 3, 2]);
        self.reads.push("address");
        self.address
    }
    fn initialize_interface(&mut self) -> MIB_IPINTERFACE_ROW {
        self.initializers += 1;
        MIB_IPINTERFACE_ROW::default()
    }
    fn initialize_address(&mut self) -> MIB_UNICASTIPADDRESS_ROW {
        self.initializers += 1;
        MIB_UNICASTIPADDRESS_ROW::default()
    }
    fn set_interface(&mut self, _: &mut MIB_IPINTERFACE_ROW) -> Result<()> {
        self.mutations += 1;
        Err(Error::Native)
    }
    fn create_address(&mut self, _: &MIB_UNICASTIPADDRESS_ROW) -> Result<()> {
        self.mutations += 1;
        Err(Error::Native)
    }
    fn delete_address(&mut self, _: &MIB_UNICASTIPADDRESS_ROW) -> Result<()> {
        self.mutations += 1;
        Err(Error::Native)
    }
}
fn readonly_expected() -> Snapshot {
    Snapshot {
        interface: InterfaceRow {
            key: RowKey {
                luid: 3300,
                index: 33,
            },
            policy: InterfacePolicy {
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
                    100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
                ],
                site_prefix_length: 0,
                metric: 25,
                mtu: 1420,
                disable_default_routes: true,
            },
            observed: InterfaceObserved {
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
            },
        },
        address: Some(AddressRow {
            key: RowKey {
                luid: 3300,
                index: 33,
            },
            policy: AddressPolicy {
                address: [10, 240, 3, 2],
                prefix_origin: 1,
                suffix_origin: 1,
                valid_lifetime: u32::MAX,
                preferred_lifetime: u32::MAX,
                on_link_prefix_length: 32,
                skip_as_source: false,
            },
            observed: AddressObserved {
                dad_state: 4,
                scope_id: 0,
                creation_timestamp: 123456789,
            },
        }),
    }
}
#[test]
fn readonly_original_snapshot_returns_complete_decoded_rows_without_owner_or_effects() {
    let mut sdk = ReadonlySdk::new();
    let snapshot = read_original_snapshot_with(&mut sdk, &binding());
    sdk.assert_no_effects();
    assert_eq!(snapshot, Ok(readonly_expected()));
    assert_eq!(sdk.reads, ["identity", "interface", "address", "identity"]);
}
#[test]
fn readonly_original_snapshot_absence_is_factual_and_still_checks_final_identity() {
    let mut sdk = ReadonlySdk::new();
    sdk.address = Ok(None);
    let mut expected = readonly_expected();
    expected.address = None;
    let snapshot = read_original_snapshot_with(&mut sdk, &binding());
    sdk.assert_no_effects();
    assert_eq!(snapshot, Ok(expected));
    assert_eq!(sdk.reads, ["identity", "interface", "address", "identity"]);
    sdk.reads.clear();
    sdk.after.as_mut().unwrap().InterfaceIndex = 34;
    assert_eq!(
        read_original_snapshot_with(&mut sdk, &binding()),
        Err(Error::Conflict)
    );
    sdk.assert_no_effects();
}
#[test]
fn readonly_original_snapshot_rejects_every_identity_drift_before_and_after_rows() {
    let mutations: [fn(&mut MIB_IF_ROW2); 8] = [
        |r| r.InterfaceGuid.data1 += 1,
        |r| r.InterfaceIndex += 1,
        |r| r.InterfaceLuid.Value = 3400,
        |r| r.Alias[0] = 88,
        |r| r.Type = 6,
        |r| r.InterfaceAndOperStatusFlags._bitfield = 1,
        |r| r.InterfaceAndOperStatusFlags._bitfield = 2,
        |r| r.InterfaceAndOperStatusFlags._bitfield = 0x80,
    ];
    for (case, mutate) in mutations.into_iter().enumerate() {
        for after in [false, true] {
            let mut sdk = ReadonlySdk::new();
            mutate(if after {
                sdk.after.as_mut().unwrap()
            } else {
                sdk.before.as_mut().unwrap()
            });
            assert!(
                read_original_snapshot_with(&mut sdk, &binding()).is_err(),
                "case {case}, after={after}"
            );
            sdk.assert_no_effects();
            assert_eq!(sdk.reads.len(), if after { 4 } else { 1 });
        }
    }
}
#[test]
fn readonly_original_snapshot_rejects_foreign_interface_and_exact_address_rows() {
    for case in 0..5 {
        let mut sdk = ReadonlySdk::new();
        match case {
            0 => sdk.interface.as_mut().unwrap().InterfaceIndex = 34,
            1 => sdk.interface.as_mut().unwrap().InterfaceLuid.Value = 3400,
            2 => {
                sdk.address
                    .as_mut()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .InterfaceIndex = 34
            }
            3 => {
                sdk.address
                    .as_mut()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .InterfaceLuid
                    .Value = 3400
            }
            _ => {
                sdk.address
                    .as_mut()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .Address
                    .Ipv4
                    .sin_addr
                    .S_un
                    .S_addr = u32::from_ne_bytes([10, 240, 3, 3])
            }
        }
        assert_eq!(
            read_original_snapshot_with(&mut sdk, &binding()),
            Err(Error::Conflict),
            "case {case}"
        );
        sdk.assert_no_effects();
    }
}
#[test]
fn readonly_original_snapshot_propagates_each_query_error_without_absence_or_success() {
    for case in 0..4 {
        let mut sdk = ReadonlySdk::new();
        match case {
            0 => sdk.before = Err(Error::Native),
            1 => sdk.interface = Err(Error::Native),
            2 => sdk.address = Err(Error::Native),
            _ => sdk.after = Err(Error::Native),
        }
        assert_eq!(
            read_original_snapshot_with(&mut sdk, &binding()),
            Err(Error::Native),
            "case {case}"
        );
        sdk.assert_no_effects();
        assert_eq!(sdk.reads.len(), case + 1);
    }
}
#[test]
fn readonly_original_snapshot_rejects_invalid_binding_before_sdk_reads() {
    let mutations: [fn(&mut Binding); 8] = [
        |b| b.key.index = 0,
        |b| b.key.luid = 0,
        |b| b.guid = [0; 16],
        |b| b.name.clear(),
        |b| b.boot_id = [0; 16],
        |b| b.network_epoch = 0,
        |b| b.scope.runtime_generation = 0,
        |b| b.address = [0; 4],
    ];
    for mutate in mutations {
        let mut sdk = ReadonlySdk::new();
        let mut b = binding();
        mutate(&mut b);
        assert_eq!(
            read_original_snapshot_with(&mut sdk, &b),
            Err(Error::Invalid)
        );
        sdk.assert_no_effects();
        assert!(sdk.reads.is_empty());
    }
}
#[test]
fn readonly_original_snapshot_rejects_unsupported_sdk_rows_through_real_decoder() {
    for case in 0..8 {
        let mut sdk = ReadonlySdk::new();
        match case {
            0 => sdk.interface.as_mut().unwrap().Family = AF_INET6,
            1 => sdk.interface.as_mut().unwrap().MaxReassemblySize = 1,
            2 => sdk.interface.as_mut().unwrap().InterfaceIdentifier = 1,
            3 => sdk.interface.as_mut().unwrap().RouterDiscoveryBehavior = 6500,
            4 => {
                sdk.address
                    .as_mut()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .Address
                    .Ipv4
                    .sin_family = AF_INET6
            }
            5 => {
                sdk.address
                    .as_mut()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .Address
                    .Ipv4
                    .sin_port = 53
            }
            6 => sdk.address.as_mut().unwrap().as_mut().unwrap().DadState = 5,
            _ => {
                sdk.address
                    .as_mut()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .CreationTimeStamp = -1
            }
        }
        assert_eq!(
            read_original_snapshot_with(&mut sdk, &binding()),
            Err(Error::Unsupported),
            "case {case}"
        );
        sdk.assert_no_effects();
    }
}
#[test]
fn readonly_original_snapshot_preserves_unready_and_skip_source_facts_without_grant() {
    for dad in 0..=4 {
        let mut sdk = ReadonlySdk::new();
        let a = sdk.address.as_mut().unwrap().as_mut().unwrap();
        a.DadState = dad;
        a.SkipAsSource = true;
        a.ScopeId.Anonymous.Value = 17;
        a.CreationTimeStamp = 987654321;
        let mut expected = readonly_expected();
        let a = expected.address.as_mut().unwrap();
        a.observed.dad_state = dad;
        a.policy.skip_as_source = true;
        a.observed.scope_id = 17;
        a.observed.creation_timestamp = 987654321;
        assert_eq!(
            read_original_snapshot_with(&mut sdk, &binding()),
            Ok(expected)
        );
        sdk.assert_no_effects();
    }
}

// Only the private-file IO is fake. Claim/permission/envelope/replay/codec/CAS
// policy below is the actual ProtectedSessionFiles + WindowsCarrierRowsStore.
#[derive(Clone)]
struct ReceiptDisk(Fake);
impl private_files::PrivateRecords for ReceiptDisk {
    fn read(&mut self, file: private_files::PrivateFile) -> std::io::Result<Option<Vec<u8>>> {
        let mut s = self.0 .0.borrow_mut();
        s.private_reads += 1;
        if s.private_fail == Some(file) {
            return Err(std::io::Error::other("private read fault"));
        }
        Ok(s.private_bytes.get(&file).cloned())
    }
    fn compare_exchange(
        &mut self,
        file: private_files::PrivateFile,
        expected: Option<&[u8]>,
        desired: &[u8],
    ) -> std::io::Result<()> {
        let mut s = self.0 .0.borrow_mut();
        if s.private_bytes.get(&file).map(Vec::as_slice) != expected || desired.len() > file.limit()
        {
            return Err(std::io::Error::other("exact private CAS"));
        }
        let row = matches!(
            file,
            private_files::PrivateFile::CarrierRows
                | private_files::PrivateFile::MemberARows
                | private_files::PrivateFile::MemberBRows
        );
        let fault = if row {
            std::mem::take(&mut s.private_fault)
        } else {
            Fault::None
        };
        if matches!(fault, Fault::Unapplied) {
            return Err(std::io::Error::other("private unapplied CAS"));
        }
        if matches!(fault, Fault::FalseAck) {
            return Ok(());
        }
        s.private_bytes.insert(file, desired.to_vec());
        if row {
            let envelope: serde_json::Value = serde_json::from_slice(desired).unwrap();
            s.saved = Some(Record::decode(envelope["data"].as_str().unwrap().as_bytes()).unwrap());
            if let Some(mut hook) = s.private_write_hook.take() {
                hook(&mut s);
            }
        }
        if matches!(fault, Fault::LostAck) {
            Err(std::io::Error::other("private committed lost ACK"))
        } else {
            Ok(())
        }
    }
}
impl private_files::SessionFileIo for ReceiptDisk {
    fn transaction<T>(
        &mut self,
        action: impl FnOnce(&mut dyn private_files::PrivateRecords) -> std::io::Result<T>,
    ) -> std::io::Result<T> {
        action(self)
    }
}
type ProtectedFiles = protected::ProtectedSessionFiles<ReceiptDisk>;
type ProtectedOwner = RowOwner<Fake, Fake, protected::WindowsCarrierRowsStore<ProtectedFiles>>;
fn protected_owner(fake: &Fake, role: Role) -> (ProtectedOwner, ProtectedFiles) {
    let mut b = binding();
    b.network_epoch = 1;
    b.role = role;
    fake.0.borrow_mut().binding = b.clone();
    let mut files =
        ProtectedFiles::new(ReceiptDisk(fake.clone()), b.runtime.clone(), b.boot_id).unwrap();
    files.claim(&b.scope).unwrap();
    let (store, old) = protected::WindowsCarrierRowsStore::open(files.clone(), b.clone()).unwrap();
    assert!(old.is_none());
    let owner = RowOwner::capture(b, fake.clone(), fake.clone(), store).unwrap();
    (owner, files)
}
fn protected_birth_owner(
    fake: &Fake,
) -> (
    ProtectedOwner,
    ProtectedFiles,
    protected::epoch::ExecutionRoot<ReceiptDisk>,
) {
    let (original, root, view) = protected_birth_files(fake);
    let b = fake.0.borrow().binding.clone();
    let (journal, none) = protected::WindowsCarrierRowsStore::open(view, b.clone()).unwrap();
    assert!(none.is_none());
    (
        RowOwner::capture(b, fake.clone(), fake.clone(), journal).unwrap(),
        original,
        root,
    )
}
fn protected_birth_files(
    fake: &Fake,
) -> (
    ProtectedFiles,
    protected::epoch::ExecutionRoot<ReceiptDisk>,
    ProtectedFiles,
) {
    use crate::member_carrier_native_ownership::{Binding as B, Context, Role as R};
    use nelomai_client_tunnel::redundancy::{session::SessionState, Slot};
    let mut b = binding();
    b.network_epoch = 1;
    fake.0.borrow_mut().binding = b.clone();
    let mut original =
        ProtectedFiles::new(ReceiptDisk(fake.clone()), b.runtime.clone(), b.boot_id).unwrap();
    original.claim(&b.scope).unwrap();
    let session = SessionState::new(b.scope.clone(), Slot::A, 0, 0)
        .unwrap()
        .snapshot();
    let mut writer = protected::WindowsSessionStore::open(
        original.clone(),
        b.scope.clone(),
        protected::RecordKind::Session,
    )
    .unwrap()
    .0;
    use nelomai_client_tunnel::redundancy::driver::SessionStore;
    writer.save(&session).unwrap();
    let origin = original.session_ack_root(&b.scope).unwrap();
    let context = Context {
        intent: crate::member_carrier::Intent {
            scope: b.scope.clone(),
            addresses: vec![format!("{}/32", std::net::Ipv4Addr::from(b.address))
                .parse()
                .unwrap()],
        },
        provenance: crate::member_carrier::Provenance {
            boot_id: b.boot_id,
            runtime: b.runtime.clone(),
            network_epoch: 1,
        },
        bindings: std::array::from_fn(|i| {
            let n = [33u8, 11, 12][i];
            let hex = format!("{n:02x}");
            B {
                role: [R::RoleCarrier, R::MemberA, R::MemberB][i],
                guid: [n; 16],
                name: ["owned-C", "owned-A", "owned-B"][i].into(),
                registry_path: format!(
                    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{{}-{}-{}-{}-{}}}",
                    hex.repeat(4),
                    hex.repeat(2),
                    hex.repeat(2),
                    hex.repeat(2),
                    hex.repeat(6)
                ),
            }
        }),
    };
    let ack = origin.inspect(|facts| Ok(facts.ack.clone())).unwrap();
    let root = origin.bind_native_birth(&context, &ack).unwrap();
    let view = original.native_birth_view(&root).unwrap();
    (original, root, view)
}
struct InitialStorageBoundary {
    backend: protected::OriginalSessionFilesIdentity,
    pin: Rc<RowRecordReadPin>,
    pair: Vec<u8>,
    failed: Cell<bool>,
}
struct ProtectedInitialCleanup {
    fake: Fake,
    slot: RowCaptureSlot<Fake, Fake, protected::WindowsCarrierRowsStore<ProtectedFiles>>,
    pin: Rc<RowRecordReadPin>,
    boundary: Rc<InitialStorageBoundary>,
    original: ProtectedFiles,
    root: protected::epoch::ExecutionRoot<ReceiptDisk>,
}
impl ProtectedInitialCleanup {
    fn new(fault: Fault) -> Self {
        let fake = Fake::new();
        let (original, root, view) = protected_birth_files(&fake);
        let b = fake.0.borrow().binding.clone();
        let journal = protected::WindowsCarrierRowsStore::open(view, b.clone())
            .unwrap()
            .0;
        fake.0.borrow_mut().private_fault = fault;
        let mut slot = RowCaptureSlot::new(b, fake.clone(), fake.clone(), journal);
        assert!(RowOwner::capture_into(&mut slot).is_err());
        let pin = Rc::new(
            slot.owner_mut()
                .unwrap()
                .initial_capture_cleanup_pin()
                .unwrap(),
        );
        let pair = protected_closing_pair_with(&fake, |p| p.carrier = None);
        let cleanup = root.native_cleanup_view(&original).unwrap().into_files();
        let boundary = Rc::new(InitialStorageBoundary {
            backend: cleanup.read_identity(),
            pin: pin.clone(),
            pair,
            failed: Cell::new(false),
        });
        slot.owner_mut()
            .unwrap()
            .enter_storage_cleanup(|j| {
                j.retain_initial_capture_cleanup_authority(boundary.clone())?;
                j.enter_initial_capture_cleanup(cleanup)
                    .map_err(|_| Error::Journal)
            })
            .unwrap();
        Self {
            fake,
            slot,
            pin,
            boundary,
            original,
            root,
        }
    }
    fn rotate(&mut self) {
        let cleanup = self
            .root
            .native_cleanup_view(&self.original)
            .unwrap()
            .into_files();
        let new = Rc::new(InitialStorageBoundary {
            backend: cleanup.read_identity(),
            pin: self.pin.clone(),
            pair: self.boundary.pair.clone(),
            failed: Cell::new(false),
        });
        self.slot
            .owner_mut()
            .unwrap()
            .enter_storage_cleanup(|j| {
                j.retain_initial_capture_cleanup_authority(new.clone())?;
                j.enter_initial_capture_cleanup(cleanup)
                    .map_err(|_| Error::Journal)
            })
            .unwrap();
        self.boundary = new;
    }
}
// Double ONLY the unsafe native Calling/Closing issuer. The invocation and pin
// are minted by the actual owner; claim, native birth flight and CAS are real.
unsafe impl protected::OriginalInitialRowCaptureCleanupWrite for InitialStorageBoundary {
    fn backend_original(&self) -> &protected::OriginalSessionFilesIdentity {
        &self.backend
    }
    fn row_original(&self) -> &RowRecordReadPin {
        &self.pin
    }
    fn verify_backend(
        &self,
        origin: &protected::OriginalSessionFilesIdentity,
        original: &InitialRowCaptureCleanupRead<'_>,
    ) -> std::io::Result<()> {
        if self.failed.get()
            || !origin.same_original(&self.backend)
            || !original.matches_record_original(&self.pin)
        {
            return Err(std::io::Error::other("original initial owner/backend"));
        }
        Ok(())
    }
    fn verify_pair(
        &self,
        bytes: &[u8],
        _: &InitialRowCaptureCleanupRead<'_>,
    ) -> std::io::Result<()> {
        if self.failed.get() || bytes != self.pair {
            return Err(std::io::Error::other("original initial Calling Pair"));
        }
        Ok(())
    }
    fn verify_write(
        &self,
        scope: &nelomai_client_tunnel::redundancy::SessionScope,
        kind: protected::RecordKind,
        old: Option<&[u8]>,
        new: &[u8],
        original: &InitialRowCaptureCleanupRead<'_>,
    ) -> std::io::Result<()> {
        if self.failed.get()
            || *scope != original.binding().scope
            || kind != protected::RecordKind::CarrierRows
        {
            return Err(std::io::Error::other("initial scope/role"));
        }
        original
            .verify_payloads(old, new)
            .map_err(|_| std::io::Error::other("initial sealed payload"))
    }
    fn fail_write(&self) {
        self.failed.set(true);
    }
}
#[test]
fn protected_initial_capture_cleanup_requires_original_birth_and_new_closing_ack() {
    for fault in [Fault::LostAck, Fault::FalseAck, Fault::Unapplied] {
        let fake = Fake::new();
        let (original, root, view) = protected_birth_files(&fake);
        let b = fake.0.borrow().binding.clone();
        let (journal, none) = protected::WindowsCarrierRowsStore::open(view, b.clone()).unwrap();
        assert!(none.is_none());
        fake.0.borrow_mut().private_fault = fault;
        let mut slot = RowCaptureSlot::new(b.clone(), fake.clone(), fake.clone(), journal);
        assert!(RowOwner::capture_into(&mut slot).is_err());
        let owner = slot.owner_mut().unwrap();
        let pin = Rc::new(owner.initial_capture_cleanup_pin().unwrap());
        assert!(pin
            .with_cleanup_record(&b.scope, b.network_epoch, |_| Ok(()))
            .is_err());
        let pair = protected_closing_pair_with(&fake, |p| p.carrier = None);
        let cleanup = root.native_cleanup_view(&original).unwrap().into_files();
        let boundary = Rc::new(InitialStorageBoundary {
            backend: cleanup.read_identity(),
            pin: pin.clone(),
            pair,
            failed: Cell::new(false),
        });
        owner
            .enter_storage_cleanup(|j| {
                j.retain_initial_capture_cleanup_authority(boundary.clone())?;
                j.enter_initial_capture_cleanup(cleanup)
                    .map_err(|_| Error::Journal)
            })
            .unwrap();
        owner.reconcile_initial_capture_for_cleanup().unwrap();
        let ack = row_pin_record(&pin, &b, true);
        assert_eq!(ack.phase, Phase::Closing);
        assert_eq!(ack.revision, 2);
        assert_eq!(ack.baseline, ack.current);
        assert!(ack.creation.is_none());
        assert_eq!(fake.0.borrow().effects, 0);
        assert!(root.current_lease().is_err());
        assert!(owner.create_address(address_policy()).is_err());
    }
}
#[test]
fn protected_initial_capture_cleanup_retry_retains_unknown_initial_ack_and_new_attempts() {
    for initial in [Fault::LostAck, Fault::FalseAck, Fault::Unapplied] {
        for closing in [Fault::LostAck, Fault::FalseAck, Fault::Unapplied] {
            let mut f = ProtectedInitialCleanup::new(initial);
            f.fake.0.borrow_mut().private_fault = closing;
            let owner = f.slot.owner_mut().unwrap();
            assert!(owner.reconcile_initial_capture_for_cleanup().is_err());
            let b = f.fake.0.borrow().binding.clone();
            assert!(f
                .pin
                .with_cleanup_record(&b.scope, b.network_epoch, |_| Ok(()))
                .is_err());
            assert!(f.boundary.failed.get());
            let old = f.boundary.clone();
            f.rotate(); // actual new Calling issuer, SAME backend/owner, old rooted
            f.slot
                .owner_mut()
                .unwrap()
                .reconcile_initial_capture_for_cleanup()
                .unwrap();
            let ack = row_pin_record(&f.pin, &b, true);
            assert_eq!(ack.phase, Phase::Closing);
            assert_eq!(
                ack.revision,
                if matches!(closing, Fault::LostAck) {
                    3
                } else {
                    2
                }
            );
            assert!(old.failed.get());
            assert_eq!(f.fake.0.borrow().effects, 0);
        }
    }
}
#[test]
fn protected_initial_capture_cleanup_publication_precedes_native_postflight_and_survives_callback_errors(
) {
    for panic in [false, true] {
        let mut f = ProtectedInitialCleanup::new(Fault::LostAck);
        let published = RefCell::new(None);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            f.slot
                .owner_mut()
                .unwrap()
                .reconcile_initial_capture_for_cleanup_with_record_pin(|pin| {
                    assert!(pin.same_original(&f.pin));
                    published.replace(Some(pin));
                    if panic {
                        panic!("Closing publication failed");
                    }
                    Err(Error::Journal)
                })
        }));
        if panic {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), Err(Error::Journal));
        }
        let b = f.fake.0.borrow().binding.clone();
        let p = published.borrow();
        let ack = row_pin_record(p.as_ref().unwrap(), &b, true);
        assert_eq!(ack.phase, Phase::Closing);
        assert_eq!(ack.revision, 2);
        assert_eq!(f.fake.0.borrow().effects, 0);
        assert!(f
            .slot
            .owner_mut()
            .unwrap()
            .create_address(address_policy())
            .is_err());
        f.rotate();
        f.slot
            .owner_mut()
            .unwrap()
            .reconcile_initial_capture_for_cleanup()
            .unwrap();
        assert_eq!(row_pin_record(&f.pin, &b, true).revision, 3);
    }
}
#[test]
fn protected_initial_capture_cleanup_rejects_rollback_to_initial_or_stopped_history() {
    for stopped in [false, true] {
        let mut f = ProtectedInitialCleanup::new(Fault::LostAck);
        let old = f.fake.0.borrow().private_bytes[&private_files::PrivateFile::CarrierRows].clone();
        f.slot
            .owner_mut()
            .unwrap()
            .reconcile_initial_capture_for_cleanup()
            .unwrap();
        let b = f.fake.0.borrow().binding.clone();
        let ack = row_pin_record(&f.pin, &b, true);
        let mut envelope: serde_json::Value = serde_json::from_slice(&old).unwrap();
        if stopped {
            let mut record = ack.clone();
            record.phase = Phase::Stopped;
            record.revision += 1;
            record.validate().unwrap();
            envelope["data"] =
                serde_json::json!(String::from_utf8(record.encode().unwrap()).unwrap());
        }
        f.fake.0.borrow_mut().private_bytes.insert(
            private_files::PrivateFile::CarrierRows,
            serde_json::to_vec(&envelope).unwrap(),
        );
        let result = f
            .slot
            .owner_mut()
            .unwrap()
            .reconcile_initial_capture_for_cleanup();
        assert!(
            result.is_err(),
            "rolled-back historical bytes were imported: {result:?}"
        );
        assert_eq!(row_pin_record(&f.pin, &b, true), ack);
        assert_eq!(f.fake.0.borrow().effects, 0);
    }
}
#[test]
fn initial_capture_cleanup_readback_failure_and_unwind_keep_invocation_not_ack() {
    for panic in [false, true] {
        let fake = Fake::new();
        fake.0.borrow_mut().journal_load_fault = Some((1, panic));
        let mut slot = RowCaptureSlot::new(binding(), fake.clone(), fake.clone(), fake.clone());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            RowOwner::capture_into(&mut slot)
        }));
        if panic {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        let owner = slot.owner_mut().unwrap();
        let pin = owner.initial_capture_cleanup_pin().unwrap();
        assert!(pin
            .with_cleanup_record(&binding().scope, binding().network_epoch, |_| Ok(()))
            .is_err());
        owner.reconcile_initial_capture_for_cleanup().unwrap();
        assert_eq!(row_pin_record(&pin, &binding(), true).phase, Phase::Closing);
        assert_eq!(fake.0.borrow().effects, 0);
    }
}
#[test]
fn initial_capture_cleanup_cannot_replace_known_initial_ack_or_sdk_create_ack() {
    for create in [false, true] {
        let fake = Fake::new();
        let mut owner =
            RowOwner::capture(binding(), fake.clone(), fake.clone(), fake.clone()).unwrap();
        if create {
            fake.0.borrow_mut().kernel_fault = Fault::LostAck;
            assert!(owner.create_address(address_policy()).is_err());
        }
        let before = fake.read_journal().unwrap();
        let effects = fake.0.borrow().effects;
        assert!(owner.initial_capture_cleanup_pin().is_err());
        assert!(owner.reconcile_initial_capture_for_cleanup().is_err());
        assert_eq!(fake.read_journal().unwrap(), before);
        assert_eq!(fake.0.borrow().effects, effects);
    }
}
#[test]
fn protected_initial_capture_cleanup_rejects_foreign_equal_origin_and_bad_parent() {
    for case in 0..3 {
        let mut f = ProtectedInitialCleanup::new(Fault::LostAck);
        let foreign = ProtectedInitialCleanup::new(Fault::LostAck);
        let before =
            f.fake.0.borrow().private_bytes[&private_files::PrivateFile::CarrierRows].clone();
        let result = f
            .slot
            .owner_mut()
            .unwrap()
            .enter_storage_cleanup(|journal| match case {
                0 => journal.retain_initial_capture_cleanup_authority(foreign.boundary.clone()),
                1 => journal.retain_initial_capture_cleanup_authority(Rc::new(
                    InitialStorageBoundary {
                        backend: f.boundary.backend.clone(),
                        pin: foreign.pin.clone(),
                        pair: f.boundary.pair.clone(),
                        failed: Cell::new(false),
                    },
                )),
                _ => journal
                    .enter_initial_capture_cleanup(
                        foreign
                            .root
                            .native_cleanup_view(&foreign.original)
                            .unwrap()
                            .into_files(),
                    )
                    .map_err(|_| Error::Journal),
            });
        assert!(result.is_err());
        assert_eq!(
            f.fake.0.borrow().private_bytes[&private_files::PrivateFile::CarrierRows],
            before
        );
        assert_eq!(f.fake.0.borrow().effects, 0);
        f.rotate();
        f.slot
            .owner_mut()
            .unwrap()
            .reconcile_initial_capture_for_cleanup()
            .unwrap();
        assert_eq!(
            row_pin_record(&f.pin, &f.fake.0.borrow().binding, true).phase,
            Phase::Closing
        );
    }
}
#[test]
fn protected_initial_capture_cleanup_pair_change_reentry_readback_and_unwind_never_publish_ack() {
    for case in 0..4 {
        let mut f = ProtectedInitialCleanup::new(Fault::LostAck);
        let mut files = f
            .root
            .native_cleanup_view(&f.original)
            .unwrap()
            .into_files();
        let b = f.fake.0.borrow().binding.clone();
        let scope = b.scope.clone();
        f.fake.0.borrow_mut().private_write_hook = Some(Box::new(move |s| match case {
            0 => {
                let mut envelope: serde_json::Value =
                    serde_json::from_slice(&s.private_bytes[&private_files::PrivateFile::Pair])
                        .unwrap();
                let mut pair: serde_json::Value =
                    serde_json::from_str(envelope["data"].as_str().unwrap()).unwrap();
                pair["payload"]["revision"] = serde_json::json!(20);
                envelope["data"] = serde_json::json!(serde_json::to_string(&pair).unwrap());
                s.private_bytes.insert(
                    private_files::PrivateFile::Pair,
                    serde_json::to_vec(&envelope).unwrap(),
                );
            }
            1 => {
                assert!(files
                    .read(&scope, protected::RecordKind::CarrierRows)
                    .is_err());
            }
            2 => {
                s.private_fail = Some(private_files::PrivateFile::CarrierRows);
            }
            _ => panic!("initial cleanup private transaction unwind"),
        }));
        let called = Cell::new(false);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            f.slot
                .owner_mut()
                .unwrap()
                .reconcile_initial_capture_for_cleanup_with_record_pin(|_| {
                    called.set(true);
                    Ok(())
                })
        }));
        if case == 3 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert!(!called.get());
        assert!(f.boundary.failed.get());
        assert!(f
            .pin
            .with_cleanup_record(&b.scope, b.network_epoch, |_| Ok(()))
            .is_err());
        assert_eq!(
            f.fake.0.borrow().saved.as_ref().unwrap().phase,
            Phase::Closing
        ); // obligation only
        assert_eq!(f.fake.0.borrow().effects, 0);
        f.slot
            .owner_mut()
            .unwrap()
            .inspect_original_initial_capture(|a, p, _| {
                assert!(Rc::ptr_eq(&a.0, &f.fake.0));
                assert!(p.same_original(&f.pin));
                Ok(())
            })
            .unwrap();
        if case == 2 {
            f.fake.0.borrow_mut().private_fail = None;
            f.rotate();
            f.slot
                .owner_mut()
                .unwrap()
                .reconcile_initial_capture_for_cleanup()
                .unwrap();
            assert_eq!(row_pin_record(&f.pin, &b, true).revision, 3);
            assert_eq!(f.fake.0.borrow().effects, 0);
        }
    }
}
#[test]
fn protected_initial_capture_cleanup_native_postflight_failure_retains_new_ack_not_initial() {
    for panic in [false, true] {
        let mut f = ProtectedInitialCleanup::new(Fault::LostAck);
        let handed = Cell::new(false);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            f.slot
                .owner_mut()
                .unwrap()
                .reconcile_initial_capture_for_cleanup_with_record_pin(|p| {
                    assert!(p.same_original(&f.pin));
                    assert_eq!(
                        row_pin_record(&p, &f.fake.0.borrow().binding, true).phase,
                        Phase::Closing
                    );
                    handed.set(true);
                    f.fake.0.borrow_mut().read_hook = Some(Box::new(move |s| {
                        if panic {
                            panic!("native postflight unwind after new Closing ACK");
                        }
                        s.address_error = true;
                    }));
                    Ok(())
                })
        }));
        if panic {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert!(handed.get());
        let b = f.fake.0.borrow().binding.clone();
        let ack = row_pin_record(&f.pin, &b, true);
        assert_eq!(ack.phase, Phase::Closing);
        assert_eq!(ack.revision, 2);
        assert_eq!(f.fake.0.borrow().effects, 0);
    }
}
#[test]
fn protected_initial_capture_cleanup_rejects_foreign_native_baseline_and_missing_pair() {
    for case in 0..4 {
        let mut f = ProtectedInitialCleanup::new(Fault::LostAck);
        let before =
            f.fake.0.borrow().private_bytes[&private_files::PrivateFile::CarrierRows].clone();
        match case {
            0 => f.fake.0.borrow_mut().ip.Metric += 1,
            1 => f.fake.0.borrow_mut().identity.guid[0] ^= 1,
            2 => {
                f.fake
                    .0
                    .borrow_mut()
                    .private_bytes
                    .remove(&private_files::PrivateFile::Pair);
            }
            _ => {
                protected_closing_pair_with(&f.fake, |p| {
                    p.carrier = Some(crate::member_owner::InterfaceProof {
                        index: 99,
                        luid: 99,
                        guid: [99; 16],
                    })
                });
            }
        }
        assert!(f
            .slot
            .owner_mut()
            .unwrap()
            .reconcile_initial_capture_for_cleanup()
            .is_err());
        assert_eq!(
            f.fake.0.borrow().private_bytes[&private_files::PrivateFile::CarrierRows],
            before
        );
        let b = f.fake.0.borrow().binding.clone();
        assert!(f
            .pin
            .with_cleanup_record(&b.scope, b.network_epoch, |_| Ok(()))
            .is_err());
        assert_eq!(f.fake.0.borrow().effects, 0);
    }
}
#[test]
fn protected_initial_capture_cleanup_does_not_allow_ordinary_absent_closing_cas() {
    let mut f = ProtectedInitialCleanup::new(Fault::Unapplied);
    let b = f.fake.0.borrow().binding.clone();
    let mut desired = f
        .slot
        .owner_mut()
        .unwrap()
        .inspect_original_initial_capture(|_, _, facts| Ok(facts.initial_record().clone()))
        .unwrap();
    desired.phase = Phase::Closing;
    desired.revision = 2;
    let mut cleanup = f
        .root
        .native_cleanup_view(&f.original)
        .unwrap()
        .into_files();
    assert!(cleanup
        .compare_exchange(
            &b.scope,
            protected::RecordKind::CarrierRows,
            None,
            &desired.encode().unwrap()
        )
        .is_err());
    assert!(cleanup
        .read(&b.scope, protected::RecordKind::CarrierRows)
        .unwrap()
        .is_none());
    f.slot
        .owner_mut()
        .unwrap()
        .reconcile_initial_capture_for_cleanup()
        .unwrap();
    assert_eq!(row_pin_record(&f.pin, &b, true).phase, Phase::Closing);
}
fn protected_closing_pair(fake: &Fake) -> Vec<u8> {
    protected_closing_pair_with(fake, |_| {})
}
fn protected_closing_pair_with(
    fake: &Fake,
    change: impl FnOnce(&mut crate::member_carrier_pair::Record),
) -> Vec<u8> {
    use crate::{member_carrier_guard as guard, member_carrier_pair as pair};
    let b = fake.0.borrow().binding.clone();
    let mut record = pair::Record {
        version: 2,
        scope: b.scope.clone(),
        provenance: crate::member_carrier::Provenance {
            boot_id: b.boot_id,
            runtime: b.runtime.clone(),
            network_epoch: b.network_epoch,
        },
        revision: 19,
        phase: pair::Phase::Closing,
        addresses: vec![format!("{}/32", std::net::Ipv4Addr::from(b.address))
            .parse()
            .unwrap()],
        dns: vec![],
        carrier: Some(crate::member_owner::InterfaceProof {
            index: b.key.index,
            luid: b.key.luid,
            guid: b.guid,
        }),
        members: [None, None],
        active: None,
        options: Some(nelomai_client_tunnel::DesktopTunnelOptions::default()),
        guard: guard::Model::empty(b.scope.clone()).unwrap(),
        pending_guard: None,
        pending: Some(pair::Effect::CarrierAddressDelete),
        network: None,
        stop_stage: 6,
        operation: None,
    };
    change(&mut record);
    record.validate().unwrap();
    #[cfg(not(windows))]
    use crate::member_carrier_pair_store as pair_store;
    #[cfg(windows)]
    use crate::windows::member_carrier_pair_store as pair_store;
    let bytes = pair_store::encode_carrier_payload(&record).unwrap();
    // Raw private IO fixture for the mandatory native Calling/Pair boundary.
    // This is NOT an opaque Pair ACK or a production issuer/native effect gate.
    let mut envelope: serde_json::Value = serde_json::from_slice(
        &fake.0.borrow().private_bytes[&private_files::PrivateFile::Session],
    )
    .unwrap();
    envelope["kind"] = serde_json::json!("Pair");
    envelope["data"] = serde_json::json!(String::from_utf8(bytes.clone()).unwrap());
    fake.0.borrow_mut().private_bytes.insert(
        private_files::PrivateFile::Pair,
        serde_json::to_vec(&envelope).unwrap(),
    );
    bytes
}
struct CreatedStorageBoundary {
    backend: protected::OriginalSessionFilesIdentity,
    pin: Rc<RowRecordReadPin>,
    pair: Vec<u8>,
    failed: std::cell::Cell<bool>,
    checks: std::cell::Cell<[usize; 3]>,
}
// Explicit double of ONLY the native pure authentication boundary. The SDK
// Create receipt and row pin come from the actual protected RowOwner operations;
// backend, epoch/birth/claim and CAS enforcement remain actual Session code.
unsafe impl protected::OriginalCreatedAddressCleanupWrite for CreatedStorageBoundary {
    fn backend_original(&self) -> &protected::OriginalSessionFilesIdentity {
        &self.backend
    }
    fn row_original(&self) -> &RowRecordReadPin {
        &self.pin
    }
    fn verify_backend(
        &self,
        origin: &protected::OriginalSessionFilesIdentity,
        original: &CreatedAddressCleanupRead<'_>,
    ) -> std::io::Result<()> {
        let mut checks = self.checks.get();
        checks[0] += 1;
        self.checks.set(checks);
        if self.failed.get()
            || !origin.same_original(&self.backend)
            || !original.matches_record_original(&self.pin)
        {
            return Err(std::io::Error::other("different actual backend/owner"));
        }
        Ok(())
    }
    fn verify_pair(&self, bytes: &[u8], _: &CreatedAddressCleanupRead<'_>) -> std::io::Result<()> {
        let mut checks = self.checks.get();
        checks[1] += 1;
        self.checks.set(checks);
        if self.failed.get() || bytes != self.pair {
            return Err(std::io::Error::other("different Pair Calling bytes"));
        }
        Ok(())
    }
    fn verify_write(
        &self,
        scope: &nelomai_client_tunnel::redundancy::SessionScope,
        kind: protected::RecordKind,
        old: &[u8],
        new: &[u8],
        original: &CreatedAddressCleanupRead<'_>,
    ) -> std::io::Result<()> {
        let mut checks = self.checks.get();
        checks[2] += 1;
        self.checks.set(checks);
        if self.failed.get()
            || kind != protected::RecordKind::CarrierRows
            || *scope != original.binding().scope
        {
            return Err(std::io::Error::other("different scope/role"));
        }
        original
            .verify_exchange(
                original.binding(),
                &Record::decode(old).map_err(|_| std::io::Error::other("old"))?,
                &Record::decode(new).map_err(|_| std::io::Error::other("new"))?,
            )
            .map_err(|_| std::io::Error::other("not actual sealed receipt"))
    }
    fn fail_write(&self) {
        self.failed.set(true);
    }
}
#[test]
fn protected_known_created_cleanup_requires_real_birth_backend_and_new_cas_ack() {
    assert_protected_created_cleanup_ack(true);
}
#[test]
fn protected_known_created_cleanup_before_carrier_ready_keeps_pair_proof_absent() {
    // Break: require a logical CarrierReady ACK despite the SAME actual owner
    // having retained a real SDK Create ACK before publication failed.
    assert_protected_created_cleanup_ack(false);
}
fn assert_protected_created_cleanup_ack(carrier_ready: bool) {
    let fake = Fake::new();
    let (mut owner, original, root) = protected_birth_owner(&fake);
    let pin = Rc::new(owner.record_read_pin().unwrap());
    fake.0.borrow_mut().create_hook = Some(Box::new(|s| s.private_fault = Fault::LostAck));
    assert!(owner.create_address(address_policy()).is_err());
    let b = fake.0.borrow().binding.clone();
    assert_eq!(row_pin_record(&pin, &b, true).revision, 2);
    let pair = protected_closing_pair_with(&fake, |p| {
        if !carrier_ready {
            p.carrier = None;
        }
    });
    let mut cleanup = root.native_cleanup_view(&original).unwrap().into_files();
    assert_eq!(
        cleanup.read(&b.scope, protected::RecordKind::Pair).unwrap(),
        Some(pair.clone())
    );
    let boundary = Rc::new(CreatedStorageBoundary {
        backend: cleanup.read_identity(),
        pin: pin.clone(),
        pair,
        failed: std::cell::Cell::new(false),
        checks: std::cell::Cell::new([0; 3]),
    });
    owner
        .enter_storage_cleanup(|journal| {
            journal.retain_created_cleanup_authority(boundary.clone())?;
            journal.enter_cleanup(cleanup).map_err(|_| Error::Journal)
        })
        .unwrap();
    let effects = fake.0.borrow().effects;
    let result = owner.reconcile_created_address_for_cleanup();
    assert!(
        result.is_ok(),
        "{result:?}, checks={:?}, failed={}",
        boundary.checks.get(),
        boundary.failed.get()
    );
    let acknowledged = row_pin_record(&pin, &b, true);
    assert_eq!(acknowledged.phase, Phase::Closing);
    assert_eq!(acknowledged.revision, 4);
    assert!(acknowledged.pending.is_none());
    assert_eq!(acknowledged.creation, acknowledged.current.address);
    assert_eq!(fake.0.borrow().effects, effects);
    assert!(owner.create_address(address_policy()).is_err());
    assert!(root.current_lease().is_err());
}

struct ProtectedCreatedCleanup {
    fake: Fake,
    owner: ProtectedOwner,
    _root: protected::epoch::ExecutionRoot<ReceiptDisk>,
    cleanup: ProtectedFiles,
    pin: Rc<RowRecordReadPin>,
    boundary: Rc<CreatedStorageBoundary>,
}
impl ProtectedCreatedCleanup {
    fn new() -> Self {
        let fake = Fake::new();
        let (mut owner, original, root) = protected_birth_owner(&fake);
        let pin = Rc::new(owner.record_read_pin().unwrap());
        fake.0.borrow_mut().create_hook = Some(Box::new(|s| s.private_fault = Fault::Unapplied));
        assert!(owner.create_address(address_policy()).is_err());
        assert_eq!(
            row_pin_record(&pin, &fake.0.borrow().binding, true).revision,
            2
        );
        let pair = protected_closing_pair(&fake);
        let cleanup = root.native_cleanup_view(&original).unwrap().into_files();
        let boundary = Rc::new(CreatedStorageBoundary {
            backend: cleanup.read_identity(),
            pin: pin.clone(),
            pair,
            failed: std::cell::Cell::new(false),
            checks: std::cell::Cell::new([0; 3]),
        });
        Self {
            fake,
            owner,
            _root: root,
            cleanup,
            pin,
            boundary,
        }
    }
    fn handoff(&mut self) {
        self.owner
            .enter_storage_cleanup(|journal| {
                journal.retain_created_cleanup_authority(self.boundary.clone())?;
                journal
                    .enter_cleanup(self.cleanup.clone())
                    .map_err(|_| Error::Journal)
            })
            .unwrap();
    }
}
#[test]
fn protected_known_created_cleanup_requires_original_backend_pin_pair_and_typed_handoff() {
    // Break: accept a caller pin/equal binding, stale or foreign Pair, missing
    // issuer or a boolean cleanup latch instead of actual typed SAME parent.
    for case in 0..7 {
        let mut f = ProtectedCreatedCleanup::new();
        match case {
            0 => {
                f.owner
                    .enter_storage_cleanup(|j| {
                        j.enter_cleanup(f.cleanup.clone())
                            .map_err(|_| Error::Journal)
                    })
                    .unwrap();
            }
            1 => {
                f.owner
                    .enter_storage_cleanup(|j| {
                        j.retain_created_cleanup_authority(f.boundary.clone())
                    })
                    .unwrap();
            }
            2 => {
                let other = Fake::new();
                let b = other.0.borrow().binding.clone();
                let foreign =
                    ProtectedFiles::new(ReceiptDisk(other), b.runtime, b.boot_id).unwrap();
                Rc::get_mut(&mut f.boundary).unwrap().backend = foreign.read_identity();
                assert!(f
                    .owner
                    .enter_storage_cleanup(
                        |j| j.retain_created_cleanup_authority(f.boundary.clone())
                    )
                    .is_err());
            }
            3 => {
                let foreign = Fake::new().owner();
                Rc::get_mut(&mut f.boundary).unwrap().pin =
                    Rc::new(foreign.record_read_pin().unwrap());
                assert!(f
                    .owner
                    .enter_storage_cleanup(
                        |j| j.retain_created_cleanup_authority(f.boundary.clone())
                    )
                    .is_err());
            }
            4 => {
                Rc::get_mut(&mut f.boundary).unwrap().pair.push(b' '); // same record, different original bytes
                f.handoff();
            }
            5 => {
                let foreign = protected_closing_pair_with(&f.fake, |p| {
                    p.carrier.as_mut().unwrap().index += 1
                });
                Rc::get_mut(&mut f.boundary).unwrap().pair = foreign;
                f.handoff();
            }
            _ => {
                f.fake
                    .0
                    .borrow_mut()
                    .private_bytes
                    .remove(&private_files::PrivateFile::Pair);
                f.handoff();
            }
        }
        let b = f.fake.0.borrow().binding.clone();
        let before =
            f.fake.0.borrow().private_bytes[&private_files::PrivateFile::CarrierRows].clone();
        let effects = f.fake.0.borrow().effects;
        assert!(
            f.owner.reconcile_created_address_for_cleanup().is_err(),
            "case {case}"
        );
        assert_eq!(
            f.fake.0.borrow().private_bytes[&private_files::PrivateFile::CarrierRows],
            before
        );
        assert_eq!(row_pin_record(&f.pin, &b, true).revision, 2);
        assert_eq!(f.fake.0.borrow().effects, effects);
        assert!(f.owner.create_address(address_policy()).is_err());
    }
}
#[test]
fn protected_known_created_cleanup_lost_or_false_cas_ack_is_not_a_new_row_ack() {
    // Break: the protected store turns exact durable desired bytes into success
    // when raw CAS returned Err, or trusts a false success without exact readback.
    for fault in [Fault::LostAck, Fault::Unapplied, Fault::FalseAck] {
        let mut f = ProtectedCreatedCleanup::new();
        f.handoff();
        f.fake.0.borrow_mut().private_fault = fault;
        let b = f.fake.0.borrow().binding.clone();
        let effects = f.fake.0.borrow().effects;
        assert!(f.owner.reconcile_created_address_for_cleanup().is_err());
        assert_eq!(row_pin_record(&f.pin, &b, true).revision, 2);
        assert_eq!(f.fake.0.borrow().effects, effects);
        assert!(f.boundary.failed.get());
        let durable = f
            .cleanup
            .read(&b.scope, protected::RecordKind::CarrierRows)
            .unwrap()
            .unwrap();
        let record = Record::decode(&durable).unwrap();
        assert_eq!(
            record.revision,
            if matches!(fault, Fault::LostAck) {
                3
            } else {
                2
            }
        );
        if matches!(fault, Fault::LostAck) {
            assert_eq!(record.phase, Phase::Closing); // obligation only, not ACK
            assert!(record.pending.is_none());
        }
        assert!(f.owner.create_address(address_policy()).is_err());
    }
}
#[test]
fn protected_known_created_cleanup_pair_change_reentry_and_unwind_keep_old_ack() {
    // Break: check only pre-CAS Pair/calling facts, ignore protected reentry,
    // or publish a new row ACK before its raw transaction completes.
    for case in 0..3 {
        let mut f = ProtectedCreatedCleanup::new();
        f.handoff();
        let mut files = f.cleanup.clone();
        let b = f.fake.0.borrow().binding.clone();
        let scope = b.scope.clone();
        f.fake.0.borrow_mut().private_write_hook = Some(Box::new(move |s| match case {
            0 => {
                let mut outer: serde_json::Value =
                    serde_json::from_slice(&s.private_bytes[&private_files::PrivateFile::Pair])
                        .unwrap();
                let mut pair: serde_json::Value =
                    serde_json::from_str(outer["data"].as_str().unwrap()).unwrap();
                pair["payload"]["revision"] = serde_json::json!(20);
                outer["data"] = serde_json::json!(serde_json::to_string(&pair).unwrap());
                s.private_bytes.insert(
                    private_files::PrivateFile::Pair,
                    serde_json::to_vec(&outer).unwrap(),
                );
            }
            1 => {
                assert!(files
                    .read(&scope, protected::RecordKind::CarrierRows)
                    .is_err());
            }
            _ => panic!("private CAS unwound after committed Closing bytes"),
        }));
        let effects = f.fake.0.borrow().effects;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            f.owner.reconcile_created_address_for_cleanup()
        }));
        if case == 2 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert_eq!(row_pin_record(&f.pin, &b, true).revision, 2);
        assert_eq!(f.fake.0.borrow().effects, effects);
        assert!(f.boundary.failed.get());
        let durable = f.fake.0.borrow().saved.clone().unwrap();
        assert_eq!(durable.revision, 3);
        assert_eq!(durable.phase, Phase::Closing);
        f.owner
            .inspect_original_authority(|authority, pin| {
                assert!(Rc::ptr_eq(&authority.0, &f.fake.0));
                assert!(pin.same_original(&f.pin));
                Ok(())
            })
            .unwrap();
        assert!(f.owner.create_address(address_policy()).is_err());
    }
}
#[test]
fn protected_known_created_cleanup_does_not_relax_ordinary_private_row_cas() {
    // Break: globally allow creation import merely because files are genuine
    // native cleanup or a matching SDK address happens to be present.
    let mut f = ProtectedCreatedCleanup::new();
    f.handoff();
    let b = f.fake.0.borrow().binding.clone();
    let old = f
        .cleanup
        .read(&b.scope, protected::RecordKind::CarrierRows)
        .unwrap()
        .unwrap();
    let mut desired = Record::decode(&old).unwrap();
    desired.revision += 1;
    desired.phase = Phase::Closing;
    desired.pending = None;
    desired.current.address =
        Some(decode_address(f.fake.0.borrow().address.as_ref().unwrap()).unwrap());
    desired.creation = desired.current.address.clone();
    let next = desired.encode().unwrap();
    assert!(f
        .cleanup
        .compare_exchange(
            &b.scope,
            protected::RecordKind::CarrierRows,
            Some(&old),
            &next
        )
        .is_err());
    assert_eq!(
        f.cleanup
            .read(&b.scope, protected::RecordKind::CarrierRows)
            .unwrap(),
        Some(old)
    );
    assert_eq!(row_pin_record(&f.pin, &b, true).revision, 2);
    // The SAME owner can still use its sealed private receipt and mandatory
    // original issuer for a NEW typed Closing CAS; no readback ACK is imported.
    f.owner.reconcile_created_address_for_cleanup().unwrap();
    assert_eq!(row_pin_record(&f.pin, &b, true).revision, 3);
}
#[test]
fn protected_known_created_cleanup_rotates_expired_issuer_for_new_original_retry() {
    // Break: either reuse the old expired Calling token or reject the new SAME
    // original issuer solely because it has a different Rc; old history roots
    // must survive replacement so a lost prior ACK cannot lose its obligations.
    let mut f = ProtectedCreatedCleanup::new();
    f.handoff();
    f.fake.0.borrow_mut().private_fault = Fault::LostAck;
    assert!(f.owner.reconcile_created_address_for_cleanup().is_err());
    let b = f.fake.0.borrow().binding.clone();
    assert_eq!(row_pin_record(&f.pin, &b, true).revision, 2);
    let expired = Rc::downgrade(&f.boundary);
    assert!(f.boundary.failed.get());
    let effects = f.fake.0.borrow().effects;
    assert!(f.owner.reconcile_created_address_for_cleanup().is_err());
    f.boundary = Rc::new(CreatedStorageBoundary {
        backend: f.cleanup.read_identity(),
        pin: f.pin.clone(),
        pair: protected_closing_pair(&f.fake),
        failed: std::cell::Cell::new(false),
        checks: std::cell::Cell::new([0; 3]),
    });
    f.handoff(); // NEW authenticated Calling boundary, not revival of old token
    assert!(expired.upgrade().unwrap().failed.get());
    f.owner.reconcile_created_address_for_cleanup().unwrap();
    assert_eq!(row_pin_record(&f.pin, &b, true).revision, 4);
    assert_eq!(f.fake.0.borrow().effects, effects);
    assert!(f.owner.create_address(address_policy()).is_err());
}
#[test]
fn protected_known_created_cleanup_rotation_rejects_foreign_originals_without_losing_history() {
    // Break: compare binding/JSON rather than opaque pin identity, replace the
    // selected issuer before origin validation, or discard failed issuer roots.
    let mut f = ProtectedCreatedCleanup::new();
    let other = ProtectedCreatedCleanup::new();
    f.handoff();
    f.fake.0.borrow_mut().private_fault = Fault::LostAck;
    assert!(f.owner.reconcile_created_address_for_cleanup().is_err());
    let b = f.fake.0.borrow().binding.clone();
    assert_eq!(
        row_pin_record(&f.pin, &b, true),
        row_pin_record(&other.pin, &b, true)
    );
    let old = Rc::downgrade(&f.boundary);
    let durable = f.fake.0.borrow().private_bytes[&private_files::PrivateFile::CarrierRows].clone();
    for foreign_backend in [true, false] {
        let bad = Rc::new(CreatedStorageBoundary {
            backend: if foreign_backend {
                other.cleanup.read_identity()
            } else {
                f.cleanup.read_identity()
            },
            pin: if foreign_backend {
                f.pin.clone()
            } else {
                other.pin.clone()
            },
            pair: protected_closing_pair(&f.fake),
            failed: std::cell::Cell::new(false),
            checks: std::cell::Cell::new([0; 3]),
        });
        let retained = Rc::downgrade(&bad);
        assert!(f
            .owner
            .enter_storage_cleanup(|j| j.retain_created_cleanup_authority(bad.clone()))
            .is_err());
        drop(bad);
        assert!(retained.upgrade().is_some()); // retained BEFORE fallible registration
        assert!(old.upgrade().unwrap().failed.get());
        assert_eq!(
            f.fake.0.borrow().private_bytes[&private_files::PrivateFile::CarrierRows],
            durable
        );
        assert_eq!(row_pin_record(&f.pin, &b, true).revision, 2);
        assert!(f.owner.reconcile_created_address_for_cleanup().is_err()); // old still expired
    }
    f.boundary = Rc::new(CreatedStorageBoundary {
        backend: f.cleanup.read_identity(),
        pin: f.pin.clone(),
        pair: protected_closing_pair(&f.fake),
        failed: std::cell::Cell::new(false),
        checks: std::cell::Cell::new([0; 3]),
    });
    f.handoff();
    f.owner.reconcile_created_address_for_cleanup().unwrap();
    assert!(old.upgrade().unwrap().failed.get());
    assert_eq!(row_pin_record(&f.pin, &b, true).revision, 4);
}
fn retained_created(fake: &Fake) -> (ProtectedOwner, ProtectedFiles) {
    let (mut owner, files) = protected_owner(fake, Role::Carrier);
    owner.create_address(address_policy()).unwrap();
    (owner, files)
}
fn assert_cleanup_only(owner: &mut ProtectedOwner, fake: &Fake) {
    let effects = fake.0.borrow().effects;
    assert_eq!(owner.change_interface(weak()), Err(Error::Retired));
    assert_eq!(owner.create_address(address_policy()), Err(Error::Retired));
    assert!(owner
        .wait_address_ready_with(
            &std::sync::atomic::AtomicBool::new(false),
            &mut TestClock::new(fake)
        )
        .is_err());
    assert_eq!(fake.0.borrow().effects, effects);
}

struct TestClock {
    fake: Fake,
    start: std::time::Instant,
    elapsed: Rc<std::cell::Cell<std::time::Duration>>,
    sleeps: usize,
    after_sleep: SleepHook,
}
type SleepHook = Box<dyn FnMut(&Fake, usize, &std::sync::atomic::AtomicBool)>;
impl TestClock {
    fn new(fake: &Fake) -> Self {
        Self {
            fake: fake.clone(),
            start: std::time::Instant::now(),
            elapsed: Rc::new(std::cell::Cell::new(std::time::Duration::ZERO)),
            sleeps: 0,
            after_sleep: Box::new(|_, _, _| {}),
        }
    }
}
impl ReadinessClock for TestClock {
    fn now(&mut self) -> std::time::Instant {
        self.start + self.elapsed.get()
    }
    fn sleep(&mut self, duration: std::time::Duration, cancelled: &std::sync::atomic::AtomicBool) {
        assert!(
            !self.fake.0.borrow().locked,
            "never hold the privileged lock asleep"
        );
        assert!(duration <= std::time::Duration::from_millis(25));
        self.elapsed.set(self.elapsed.get() + duration);
        self.sleeps += 1;
        (self.after_sleep)(&self.fake, self.sleeps, cancelled);
    }
}
#[test]
fn readiness_requires_actual_created_receipt_then_observes_tentative_to_preferred() {
    let fake = Fake::new();
    let (mut owner, _) = retained_created(&fake);
    let before = fake.0.borrow().private_bytes.clone();
    let queries = fake.0.borrow().queries;
    let mut clock = TestClock::new(&fake);
    clock.after_sleep = Box::new(|fake, sleeps, _| {
        if sleeps == 2 {
            fake.0.borrow_mut().address.as_mut().unwrap().DadState = 4;
        }
    });
    let ready = owner
        .wait_address_ready_with(&std::sync::atomic::AtomicBool::new(false), &mut clock)
        .unwrap();
    assert_eq!(ready.observed.dad_state, 4);
    assert_eq!(ready.observed.creation_timestamp, 123456789);
    assert_eq!(clock.sleeps, 2);
    assert_eq!(
        fake.0.borrow().queries - queries,
        6,
        "fresh before/after creator proof on each poll"
    );
    assert_eq!(fake.0.borrow().effects, 1, "readiness is not a mutation");
    assert_eq!(
        fake.0.borrow().private_bytes,
        before,
        "DAD is a volatile observation, not a writable journal update"
    );
    owner.change_interface(weak()).unwrap();
    owner.stop().unwrap();
}
#[test]
fn readiness_immediate_preferred_is_observed_not_written() {
    let fake = Fake::new();
    let (mut owner, _) = retained_created(&fake);
    fake.0.borrow_mut().address.as_mut().unwrap().DadState = 4;
    let mut clock = TestClock::new(&fake);
    assert_eq!(
        owner
            .wait_address_ready_with(&std::sync::atomic::AtomicBool::new(false), &mut clock)
            .unwrap()
            .observed
            .dad_state,
        4
    );
    assert_eq!(clock.sleeps, 0);
    assert_eq!(fake.0.borrow().effects, 1);
}
#[test]
fn readiness_production_monotonic_entry_observes_owned_preferred_without_sleep() {
    let fake = Fake::new();
    let (mut owner, _) = retained_created(&fake);
    fake.0.borrow_mut().address.as_mut().unwrap().DadState = 4;
    assert_eq!(
        owner
            .wait_address_ready(&std::sync::atomic::AtomicBool::new(false))
            .unwrap()
            .observed
            .dad_state,
        4
    );
    assert_eq!(fake.0.borrow().effects, 1);
    owner.stop().unwrap();
}

#[test]
fn readiness_timeout_permanently_revokes_live_mutations_but_retains_exact_cleanup() {
    let fake = Fake::new();
    let (mut owner, _) = retained_created(&fake);
    let before = fake.0.borrow().private_bytes.clone();
    let queries = fake.0.borrow().queries;
    let mut clock = TestClock::new(&fake);
    assert_eq!(
        owner.wait_address_ready_with(&std::sync::atomic::AtomicBool::new(false), &mut clock),
        Err(Error::Retired)
    );
    assert_eq!(clock.elapsed.get(), std::time::Duration::from_secs(5));
    assert_eq!(clock.sleeps, 200);
    assert_eq!(fake.0.borrow().queries - queries, 400);
    assert_eq!(fake.0.borrow().private_bytes, before);
    fake.0.borrow_mut().address.as_mut().unwrap().DadState = 4;
    assert_cleanup_only(&mut owner, &fake);
    owner.stop().unwrap();
    assert_eq!(
        fake.0.borrow().saved.as_ref().unwrap().phase,
        Phase::Stopped
    );
    assert!(fake.0.borrow().address.is_none());
    assert_eq!(fake.0.borrow().effects, 2);
}
#[test]
fn readiness_cancel_before_read_and_between_polls_is_not_retryable() {
    for before_read in [true, false] {
        let fake = Fake::new();
        let (mut owner, _) = retained_created(&fake);
        let queries = fake.0.borrow().queries;
        let cancelled = std::sync::atomic::AtomicBool::new(before_read);
        let mut clock = TestClock::new(&fake);
        clock.after_sleep =
            Box::new(|_, _, cancelled| cancelled.store(true, std::sync::atomic::Ordering::Release));
        let result = if before_read {
            // Production entry point; already-cancelled means no actual sleep.
            owner.wait_address_ready(&cancelled)
        } else {
            owner.wait_address_ready_with(&cancelled, &mut clock)
        };
        assert_eq!(result, Err(Error::Retired));
        assert_eq!(
            fake.0.borrow().queries - queries,
            if before_read { 0 } else { 2 }
        );
        cancelled.store(false, std::sync::atomic::Ordering::Release);
        assert_cleanup_only(&mut owner, &fake);
        assert!(fake.0.borrow().saved.as_ref().unwrap().creation.is_some());
        owner.stop().unwrap();
    }
}
#[test]
fn readiness_cancel_during_actual_preferred_read_denies_late_success() {
    let fake = Fake::new();
    let (mut owner, _) = retained_created(&fake);
    let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let signal = cancelled.clone();
    fake.0.borrow_mut().read_hook = Some(Box::new(move |s| {
        s.address.as_mut().unwrap().DadState = 4;
        signal.store(true, std::sync::atomic::Ordering::Release);
    }));
    assert_eq!(
        owner.wait_address_ready_with(&cancelled, &mut TestClock::new(&fake)),
        Err(Error::Retired)
    );
    assert_cleanup_only(&mut owner, &fake);
    owner.stop().unwrap();
}
#[test]
fn readiness_native_call_returning_preferred_at_or_after_deadline_is_denied() {
    for millis in [5000, 5001, 60000] {
        let fake = Fake::new();
        let (mut owner, _) = retained_created(&fake);
        let mut clock = TestClock::new(&fake);
        let elapsed = clock.elapsed.clone();
        fake.0.borrow_mut().read_hook = Some(Box::new(move |s| {
            s.address.as_mut().unwrap().DadState = 4;
            // Fake only the native latency/clock boundary, not RowOwner policy.
            elapsed.set(std::time::Duration::from_millis(millis));
        }));
        assert_eq!(
            owner.wait_address_ready_with(&std::sync::atomic::AtomicBool::new(false), &mut clock),
            Err(Error::Retired)
        );
        assert_eq!(clock.sleeps, 0);
        assert_cleanup_only(&mut owner, &fake);
        owner.stop().unwrap();
    }
}
#[test]
fn readiness_preferred_just_before_deadline_passes_but_sleep_cannot_extend_budget() {
    let fake = Fake::new();
    let (mut owner, _) = retained_created(&fake);
    let mut clock = TestClock::new(&fake);
    let elapsed = clock.elapsed.clone();
    fake.0.borrow_mut().read_hook = Some(Box::new(move |s| {
        s.address.as_mut().unwrap().DadState = 4;
        elapsed.set(std::time::Duration::from_millis(4999));
    }));
    assert!(owner
        .wait_address_ready_with(&std::sync::atomic::AtomicBool::new(false), &mut clock)
        .is_ok());

    let fake = Fake::new();
    let (mut owner, _) = retained_created(&fake);
    let mut clock = TestClock::new(&fake);
    let elapsed = clock.elapsed.clone();
    clock.after_sleep = Box::new(move |fake, _, _| {
        fake.0.borrow_mut().address.as_mut().unwrap().DadState = 4;
        elapsed.set(std::time::Duration::from_secs(5));
    });
    assert_eq!(
        owner.wait_address_ready_with(&std::sync::atomic::AtomicBool::new(false), &mut clock),
        Err(Error::Retired)
    );
    assert_eq!(clock.sleeps, 1);
    assert_cleanup_only(&mut owner, &fake);
}
#[test]
fn readiness_frozen_or_regressing_clock_is_finite_and_cleanup_only() {
    for regress in [false, true] {
        let fake = Fake::new();
        let (mut owner, _) = retained_created(&fake);
        let mut clock = TestClock::new(&fake);
        let elapsed = clock.elapsed.clone();
        clock.after_sleep = Box::new(move |_, n, _| {
            elapsed.set(if regress && n == 1 {
                std::time::Duration::from_millis(20)
            } else {
                std::time::Duration::ZERO
            });
        });
        assert_eq!(
            owner.wait_address_ready_with(&std::sync::atomic::AtomicBool::new(false), &mut clock),
            Err(Error::Retired)
        );
        assert!(clock.sleeps <= 200);
        assert_cleanup_only(&mut owner, &fake);
        owner.stop().unwrap();
    }
}
#[test]
fn readiness_sleep_unwind_revokes_owner_without_losing_cleanup_obligation() {
    let fake = Fake::new();
    let (mut owner, _) = retained_created(&fake);
    let mut clock = TestClock::new(&fake);
    clock.after_sleep = Box::new(|_, _, _| panic!("clock boundary unwind"));
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner.wait_address_ready_with(&std::sync::atomic::AtomicBool::new(false), &mut clock)
    }))
    .is_err());
    assert!(!fake.0.borrow().locked);
    assert_cleanup_only(&mut owner, &fake);
    owner.stop().unwrap();
}
#[test]
fn readiness_denies_all_nonusable_dad_states_immediately_on_every_poll() {
    for dad in [0, 2, 3, -1, 5, i32::MAX] {
        for later in [false, true] {
            let fake = Fake::new();
            let (mut owner, _) = retained_created(&fake);
            let mut clock = TestClock::new(&fake);
            if later {
                clock.after_sleep = Box::new(move |fake, _, _| {
                    fake.0.borrow_mut().address.as_mut().unwrap().DadState = dad
                });
            } else {
                fake.0.borrow_mut().address.as_mut().unwrap().DadState = dad;
            }
            assert!(
                owner
                    .wait_address_ready_with(&std::sync::atomic::AtomicBool::new(false), &mut clock)
                    .is_err(),
                "dad {dad}"
            );
            assert_eq!(clock.sleeps, usize::from(later));
            assert_cleanup_only(&mut owner, &fake);
            assert_eq!(fake.0.borrow().effects, 1);
        }
    }
}
#[test]
fn readiness_never_adopts_foreign_preferred_or_journal_creation_without_live_ack() {
    let fake = Fake::new();
    let (mut owner, _) = protected_owner(&fake, Role::Carrier);
    fake.0.borrow_mut().address = Some(address_raw());
    assert_eq!(
        owner.wait_address_ready_with(
            &std::sync::atomic::AtomicBool::new(false),
            &mut TestClock::new(&fake)
        ),
        Err(Error::Pending)
    );
    assert_cleanup_only(&mut owner, &fake);
    assert!(owner.stop().is_err());
    assert_eq!(fake.0.borrow().effects, 0);

    for fault in [Fault::LostAck, Fault::FalseAck, Fault::Unapplied] {
        let fake = Fake::new();
        let (mut owner, _) = protected_owner(&fake, Role::Carrier);
        fake.0.borrow_mut().kernel_fault = fault;
        assert!(owner.create_address(address_policy()).is_err());
        if let Some(row) = fake.0.borrow_mut().address.as_mut() {
            row.DadState = 4;
        }
        assert_cleanup_only(&mut owner, &fake);
        assert!(owner.stop().is_err());
        assert!(fake.0.borrow().saved.as_ref().unwrap().pending.is_some());
        assert_eq!(fake.0.borrow().effects, 1);
    }
}
#[test]
fn readiness_member_closing_stopped_and_previously_failed_owners_never_resume() {
    for role in [Role::MemberA, Role::MemberB] {
        let fake = Fake::new();
        let (mut owner, _) = protected_owner(&fake, role);
        assert_eq!(
            owner.wait_address_ready_with(
                &std::sync::atomic::AtomicBool::new(false),
                &mut TestClock::new(&fake)
            ),
            Err(Error::Retired)
        );
        assert_cleanup_only(&mut owner, &fake);
        owner.stop().unwrap();
        assert_eq!(fake.0.borrow().effects, 0);
    }
    for state in 0..3 {
        let fake = Fake::new();
        let (mut owner, _) = retained_created(&fake);
        match state {
            0 => {
                owner.stop().unwrap();
            }
            1 => {
                fake.0.borrow_mut().kernel_fault = Fault::Unapplied;
                assert!(owner.stop().is_err());
                assert_eq!(
                    fake.0.borrow().saved.as_ref().unwrap().phase,
                    Phase::Closing
                );
            }
            _ => {
                fake.0.borrow_mut().api_error = true;
                assert!(owner.snapshot().is_err());
                fake.0.borrow_mut().api_error = false;
            }
        }
        if let Some(row) = fake.0.borrow_mut().address.as_mut() {
            row.DadState = 4;
        }
        assert_cleanup_only(&mut owner, &fake);
        owner.stop().unwrap();
    }
}
#[test]
fn readiness_reopened_protected_store_is_cleanup_only_not_a_creator() {
    let fake = Fake::new();
    let (mut original, files) = retained_created(&fake);
    fake.0.borrow_mut().address.as_mut().unwrap().DadState = 4;
    let b = fake.0.borrow().binding.clone();
    let (store, old) = protected::WindowsCarrierRowsStore::open(files, b.clone()).unwrap();
    assert!(old.unwrap().creation.is_some());
    assert!(matches!(
        RowOwner::capture(b, fake.clone(), fake.clone(), store),
        Err(Error::Retired)
    ));
    // The original acknowledged owner remains distinct from a reopened record.
    assert!(original
        .wait_address_ready_with(
            &std::sync::atomic::AtomicBool::new(false),
            &mut TestClock::new(&fake)
        )
        .is_ok());
    assert_eq!(fake.0.borrow().effects, 1);
}
#[test]
fn readiness_full_context_identity_creator_and_each_api_fault_are_rechecked_each_poll() {
    let faults: [fn(&mut State); 28] = [
        |s| s.binding.scope.runtime_generation += 1,
        |s| s.binding.scope.connection_generation += 1,
        |s| s.binding.scope.session_id = "11234567-89ab-cdef-0123-456789abcdef".into(),
        |s| s.binding.scope.runtime = RuntimeSlot::Latest,
        |s| s.binding.boot_id[0] += 1,
        |s| s.binding.runtime.runtime_version = "0.3.4".into(),
        |s| s.binding.runtime.runtime_contract_version += 1,
        |s| s.binding.runtime.container_version = "0.3.4".into(),
        |s| s.binding.runtime.manifest_sha256 = "b".repeat(64),
        |s| s.binding.runtime.slot = RuntimeSlot::Latest,
        |s| s.binding.network_epoch += 1,
        |s| s.binding.role = Role::MemberA,
        |s| s.binding.address[3] += 1,
        |s| s.binding.guid[0] += 1,
        |s| s.binding.name.push('X'),
        |s| s.binding.key.luid += 1,
        |s| s.binding.key.index += 1,
        |s| s.identity.guid[0] += 1,
        |s| s.identity.name.push('X'),
        |s| s.identity.key.luid += 1,
        |s| s.identity.key.index += 1,
        |s| s.identity.if_type = 6,
        |s| s.identity.hardware = true,
        |s| s.creator_alive = false,
        |s| s.replay = true,
        |s| s.identity_error = true,
        |s| s.api_error = true,
        |s| s.address_error = true,
    ];
    for (i, fault) in faults.into_iter().enumerate() {
        let fake = Fake::new();
        let (mut owner, _) = retained_created(&fake);
        let mut clock = TestClock::new(&fake);
        clock.after_sleep = Box::new(move |fake, _, _| fault(&mut fake.0.borrow_mut()));
        assert!(
            owner
                .wait_address_ready_with(&std::sync::atomic::AtomicBool::new(false), &mut clock)
                .is_err(),
            "fault {i}"
        );
        assert_eq!(clock.sleeps, 1, "immediate deny fault {i}");
        assert_cleanup_only(&mut owner, &fake);
    }
}
#[test]
fn readiness_creator_and_identity_drift_during_actual_row_read_is_not_stale_proof() {
    for identity in [false, true] {
        let fake = Fake::new();
        let (mut owner, _) = retained_created(&fake);
        fake.0.borrow_mut().read_hook = Some(Box::new(move |s| {
            s.address.as_mut().unwrap().DadState = 4;
            if identity {
                s.identity.guid[0] += 1;
            } else {
                s.binding.network_epoch += 1;
            }
        }));
        let mut clock = TestClock::new(&fake);
        assert!(owner
            .wait_address_ready_with(&std::sync::atomic::AtomicBool::new(false), &mut clock)
            .is_err());
        assert_eq!(clock.sleeps, 0);
        assert_cleanup_only(&mut owner, &fake);
    }
}
#[test]
fn readiness_full_address_policy_and_stable_row_identity_cannot_drift_between_polls() {
    let mutations: [fn(&mut MIB_UNICASTIPADDRESS_ROW); 12] = [
        |r| r.PrefixOrigin = 3,
        |r| r.SuffixOrigin = 3,
        |r| r.ValidLifetime -= 1,
        |r| r.PreferredLifetime -= 1,
        |r| r.OnLinkPrefixLength = 24,
        |r| r.SkipAsSource = true,
        |r| r.ScopeId.Anonymous.Value = 1,
        |r| r.CreationTimeStamp += 1,
        |r| unsafe { r.InterfaceLuid.Value += 1 },
        |r| r.InterfaceIndex += 1,
        |r| r.Address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes([10, 240, 3, 3]),
        |r| r.Address.si_family = AF_INET6,
    ];
    for (i, mutate) in mutations.into_iter().enumerate() {
        let fake = Fake::new();
        let (mut owner, _) = retained_created(&fake);
        let mut clock = TestClock::new(&fake);
        clock.after_sleep = Box::new(move |fake, _, _| {
            let mut s = fake.0.borrow_mut();
            let row = s.address.as_mut().unwrap();
            row.DadState = 4;
            mutate(row);
        });
        assert!(
            owner
                .wait_address_ready_with(&std::sync::atomic::AtomicBool::new(false), &mut clock)
                .is_err(),
            "address field {i}"
        );
        assert_eq!(clock.sleeps, 1);
        assert_cleanup_only(&mut owner, &fake);
        assert!(
            owner.stop().is_err(),
            "no delete against a replaced/foreign row {i}"
        );
        assert_eq!(fake.0.borrow().effects, 1);
    }
}
#[test]
fn readiness_full_interface_policy_is_reconstructed_not_a_logical_weak_host_projection() {
    let mutations: [fn(&mut MIB_IPINTERFACE_ROW); 25] = [
        |r| r.AdvertisingEnabled = !r.AdvertisingEnabled,
        |r| r.ForwardingEnabled = !r.ForwardingEnabled,
        |r| r.WeakHostSend = !r.WeakHostSend,
        |r| r.WeakHostReceive = !r.WeakHostReceive,
        |r| r.UseAutomaticMetric = !r.UseAutomaticMetric,
        |r| r.UseNeighborUnreachabilityDetection = !r.UseNeighborUnreachabilityDetection,
        |r| r.ManagedAddressConfigurationSupported = !r.ManagedAddressConfigurationSupported,
        |r| r.OtherStatefulConfigurationSupported = !r.OtherStatefulConfigurationSupported,
        |r| r.AdvertiseDefaultRoute = !r.AdvertiseDefaultRoute,
        |r| r.RouterDiscoveryBehavior = 1,
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
        |r| unsafe { r.InterfaceLuid.Value += 1 },
        |r| r.InterfaceIndex += 1,
        |r| r.Family = AF_INET6,
        |r| r.MaxReassemblySize = 1,
    ];
    for (i, mutate) in mutations.into_iter().enumerate() {
        let fake = Fake::new();
        let (mut owner, _) = retained_created(&fake);
        let mut clock = TestClock::new(&fake);
        clock.after_sleep = Box::new(move |fake, _, _| {
            let mut s = fake.0.borrow_mut();
            s.address.as_mut().unwrap().DadState = 4;
            mutate(&mut s.ip);
        });
        assert!(
            owner
                .wait_address_ready_with(&std::sync::atomic::AtomicBool::new(false), &mut clock)
                .is_err(),
            "interface field {i}"
        );
        assert_eq!(clock.sleeps, 1);
        assert_cleanup_only(&mut owner, &fake);
        assert!(
            owner.stop().is_err(),
            "foreign policy is not overwritten {i}"
        );
        assert_eq!(fake.0.borrow().effects, 1);
    }
}
#[test]
fn readiness_preserves_volatile_native_observations_without_granting_write_permission() {
    let fake = Fake::new();
    let (mut owner, _) = retained_created(&fake);
    let bytes = fake.0.borrow().private_bytes.clone();
    let mut clock = TestClock::new(&fake);
    clock.after_sleep = Box::new(|fake, _, _| {
        let mut s = fake.0.borrow_mut();
        s.address.as_mut().unwrap().DadState = 4;
        s.ip.MinRouterAdvertisementInterval += 1;
        s.ip.MaxRouterAdvertisementInterval += 1;
        s.ip.Connected = false;
        s.ip.SupportsWakeUpPatterns = !s.ip.SupportsWakeUpPatterns;
        s.ip.SupportsNeighborDiscovery = false;
        s.ip.SupportsRouterDiscovery = !s.ip.SupportsRouterDiscovery;
        s.ip.ReachableTime += 1;
        s.ip.TransmitOffload._bitfield ^= 1;
        s.ip.ReceiveOffload._bitfield ^= 1;
    });
    assert!(owner
        .wait_address_ready_with(&std::sync::atomic::AtomicBool::new(false), &mut clock)
        .is_ok());
    assert_eq!(fake.0.borrow().private_bytes, bytes);
    assert_eq!(fake.0.borrow().effects, 1);
    let row = owner.snapshot().unwrap().interface;
    assert!(!row.observed.connected);
    assert_eq!(row.observed.reachable_time, 32124);
    owner.stop().unwrap();
}
#[test]
fn readiness_missing_created_native_address_is_not_pending_dad_or_absence_authority() {
    let fake = Fake::new();
    let (mut owner, _) = retained_created(&fake);
    let mut clock = TestClock::new(&fake);
    clock.after_sleep = Box::new(|fake, _, _| fake.0.borrow_mut().address = None);
    assert_eq!(
        owner.wait_address_ready_with(&std::sync::atomic::AtomicBool::new(false), &mut clock),
        Err(Error::Conflict)
    );
    assert_eq!(clock.sleeps, 1);
    assert_cleanup_only(&mut owner, &fake);
    assert!(fake.0.borrow().saved.as_ref().unwrap().creation.is_some());
    assert!(owner.stop().is_err());
    assert_eq!(fake.0.borrow().effects, 1);
}
#[test]
fn readiness_pending_interface_or_partial_restore_cannot_be_promoted_by_preferred() {
    for fault in [Fault::Unapplied, Fault::FalseAck, Fault::Partial] {
        let fake = Fake::new();
        let (mut owner, _) = retained_created(&fake);
        fake.0.borrow_mut().kernel_fault = fault;
        assert!(owner.change_interface(weak()).is_err());
        fake.0.borrow_mut().address.as_mut().unwrap().DadState = 4;
        assert!(fake.0.borrow().saved.as_ref().unwrap().pending.is_some());
        assert_cleanup_only(&mut owner, &fake);
        if matches!(fault, Fault::Partial) {
            assert!(owner.stop().is_err());
            assert_eq!(fake.0.borrow().effects, 2);
        } else {
            owner.stop().unwrap();
            assert!(fake.0.borrow().address.is_none());
        }
    }
}
#[test]
fn readiness_protected_journal_fault_corruption_context_and_reconstruction_deny_each_poll() {
    for case in 0..13 {
        let fake = Fake::new();
        let (mut owner, _) = retained_created(&fake);
        let mut clock = TestClock::new(&fake);
        clock.after_sleep = Box::new(move |fake, _, _| {
            let mut s = fake.0.borrow_mut();
            s.address.as_mut().unwrap().DadState = 4;
            let file = private_files::PrivateFile::CarrierRows;
            match case {
                0 => {
                    s.private_fail = Some(file);
                }
                1 => {
                    s.private_fail = Some(private_files::PrivateFile::Index);
                }
                2 => {
                    s.private_bytes.insert(file, b"{".to_vec());
                }
                3 => {
                    s.private_bytes.insert(file, vec![b' '; file.limit() + 1]);
                }
                4 => {
                    s.private_bytes.remove(&file);
                }
                _ => {
                    let mut envelope: serde_json::Value =
                        serde_json::from_slice(&s.private_bytes[&file]).unwrap();
                    let mut row: serde_json::Value =
                        serde_json::from_str(envelope["data"].as_str().unwrap()).unwrap();
                    match case {
                        5 => row["version"] = 99.into(),
                        6 => row["unknown"] = true.into(),
                        7 => row["binding"]["network_epoch"] = 2.into(),
                        8 => row["binding"]["boot_id"][0] = 99.into(),
                        9 => row["revision"] = 100.into(),
                        10 => {
                            row.as_object_mut().unwrap().remove("creation");
                        }
                        11 => envelope["identity"]["runtime"]["runtime_version"] = "0.3.4".into(),
                        _ => envelope["identity"]["scope"]["connection_generation"] = 100.into(),
                    }
                    envelope["data"] = serde_json::to_string(&row).unwrap().into();
                    s.private_bytes
                        .insert(file, serde_json::to_vec(&envelope).unwrap());
                }
            }
        });
        assert!(
            owner
                .wait_address_ready_with(&std::sync::atomic::AtomicBool::new(false), &mut clock)
                .is_err(),
            "journal case {case}"
        );
        assert_eq!(clock.sleeps, 1);
        assert_cleanup_only(&mut owner, &fake);
        assert_eq!(fake.0.borrow().effects, 1);
        assert!(
            fake.0.borrow().address.is_some(),
            "obligation retained {case}"
        );
    }
}
#[test]
fn readiness_protected_journal_is_rechecked_after_native_preferred_read() {
    let fake = Fake::new();
    let (mut owner, _) = retained_created(&fake);
    fake.0.borrow_mut().read_hook = Some(Box::new(|s| {
        s.address.as_mut().unwrap().DadState = 4;
        s.private_bytes
            .insert(private_files::PrivateFile::CarrierRows, b"{}".to_vec());
    }));
    let mut clock = TestClock::new(&fake);
    assert!(owner
        .wait_address_ready_with(&std::sync::atomic::AtomicBool::new(false), &mut clock)
        .is_err());
    assert_eq!(clock.sleeps, 0);
    assert_cleanup_only(&mut owner, &fake);
}
#[test]
fn readiness_fresh_protected_permission_revocation_during_native_read_is_permanent() {
    let fake = Fake::new();
    let (mut owner, mut files) = retained_created(&fake);
    let mut clock = TestClock::new(&fake);
    let b = fake.0.borrow().binding.clone();
    fake.0.borrow_mut().read_hook = Some(Box::new(move |s| {
        s.address.as_mut().unwrap().DadState = 4;
        files.revoke_native_carrier_access(&b.scope).unwrap();
    }));
    assert!(owner
        .wait_address_ready_with(&std::sync::atomic::AtomicBool::new(false), &mut clock)
        .is_err());
    assert_eq!(clock.sleeps, 0);
    assert_cleanup_only(&mut owner, &fake);
    assert!(
        owner.stop().is_err(),
        "revoked store requires explicit cleanup-only reopen; readiness must not upgrade it"
    );
    assert_eq!(fake.0.borrow().effects, 1);
}
#[test]
fn readiness_store_ack_failure_is_not_redeemed_by_exact_bytes_or_created_receipt() {
    for confirm in [false, true] {
        for fault in [Fault::LostAck, Fault::FalseAck, Fault::Unapplied] {
            let fake = Fake::new();
            let (mut owner, mut files) = protected_owner(&fake, Role::Carrier);
            if confirm {
                fake.0.borrow_mut().create_hook = Some(Box::new(move |s| s.private_fault = fault));
            } else {
                fake.0.borrow_mut().private_fault = fault;
            }
            assert!(owner.create_address(address_policy()).is_err());
            let b = fake.0.borrow().binding.clone();
            assert!(!files.native_carrier_access(&b.scope).unwrap().is_fresh());
            if let Some(row) = fake.0.borrow_mut().address.as_mut() {
                row.DadState = 4;
            }
            assert_cleanup_only(&mut owner, &fake);
            let effects = fake.0.borrow().effects;
            assert_eq!(effects, usize::from(confirm));
            let (mut reopened, saved) =
                protected::WindowsCarrierRowsStore::open(files, b.clone()).unwrap();
            assert_eq!(reopened.load(&b).unwrap(), saved);
            assert!(matches!(
                RowOwner::capture(b, fake.clone(), fake.clone(), reopened),
                Err(Error::Retired)
            ));
            assert_eq!(fake.0.borrow().effects, effects);
            if confirm {
                assert!(fake.0.borrow().address.is_some());
            }
        }
    }
}
#[test]
fn durable_owner_captures_full_baseline_then_exact_weak_address_and_cleanup() {
    for site_prefix in [0, 64] {
        let fake = Fake::new();
        if site_prefix == 64 {
            let mut s = fake.0.borrow_mut();
            s.ip.SitePrefixLength = 64;
            s.ip.Metric = 5;
            s.ip.NlMtu = 65535;
        }
        let mut owner = fake.owner();
        let baseline = owner.snapshot().unwrap();
        assert_eq!(baseline.interface.observed.transmit_offload, 0xa5);
        assert!(baseline.address.is_none());
        let mut desired = baseline.interface.policy.clone();
        desired.weak_host_send = true;
        desired.weak_host_receive = true;
        owner.change_interface(desired).unwrap();
        assert_eq!(
            fake.0
                .borrow()
                .saved
                .as_ref()
                .unwrap()
                .current
                .interface
                .policy
                .site_prefix_length,
            site_prefix
        );
        owner.create_address(address_policy()).unwrap();
        let created = owner.snapshot().unwrap();
        assert_eq!(created.address.unwrap().observed.dad_state, 1);
        owner.stop().unwrap();
        let saved = fake.0.borrow().saved.clone().unwrap();
        assert_eq!(saved.phase, Phase::Stopped);
        assert!(saved.pending.is_none());
        assert_eq!(saved.current.interface.policy, baseline.interface.policy);
        assert_eq!(
            saved.baseline.interface.policy.site_prefix_length,
            site_prefix
        );
        assert_eq!(fake.0.borrow().ip.SitePrefixLength, site_prefix);
        assert!(saved.current.address.is_none());
        assert!(fake.0.borrow().address.is_none());
        assert_eq!(fake.0.borrow().effects, 4);
    }
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
    for fault in [
        Fault::Unapplied,
        Fault::FalseAck,
        Fault::Partial,
        Fault::SitePrefixChanged,
    ] {
        let fake = Fake::new();
        if matches!(fault, Fault::SitePrefixChanged) {
            fake.0.borrow_mut().ip.SitePrefixLength = 64;
        }
        let mut owner = fake.owner();
        let mut desired = owner.snapshot().unwrap().interface.policy;
        desired.weak_host_send = true;
        desired.weak_host_receive = true;
        fake.0.borrow_mut().kernel_fault = fault;
        assert!(owner.change_interface(desired).is_err());
        assert!(fake.0.borrow().saved.as_ref().unwrap().pending.is_some());
        assert!(owner.create_address(address_policy()).is_err());
        if matches!(fault, Fault::Partial | Fault::SitePrefixChanged) {
            let effects = fake.0.borrow().effects;
            assert!(owner.stop().is_err());
            assert_eq!(
                fake.0.borrow().effects,
                effects,
                "no retry/rollback over foreign drift"
            );
            if matches!(fault, Fault::SitePrefixChanged) {
                let s = fake.0.borrow();
                let saved = s.saved.as_ref().unwrap();
                assert_eq!(effects, 1);
                assert_eq!(s.ip.SitePrefixLength, 0);
                assert_eq!(saved.baseline.interface.policy.site_prefix_length, 64);
                assert_eq!(saved.current.interface.policy.site_prefix_length, 64);
                assert_eq!(
                    saved
                        .pending
                        .as_ref()
                        .unwrap()
                        .before
                        .interface
                        .policy
                        .site_prefix_length,
                    64
                );
            }
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
fn journal_lost_ack_reread_retains_cleanup_only_and_foreign_revision_is_not_adopted() {
    let fake = Fake::new();
    let mut owner = fake.owner();
    fake.0.borrow_mut().journal_fault = Fault::LostAck;
    assert_eq!(owner.change_interface(weak()), Err(Error::Journal));
    fake.0.borrow_mut().saved.as_mut().unwrap().revision += 1;
    let foreign = fake.0.borrow().saved.clone().unwrap();
    fake.write_journal(&foreign).unwrap();
    assert!(owner.create_address(address_policy()).is_err());
    assert_eq!(fake.0.borrow().effects, 0);
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

fn stopped_member_rows() -> (Fake, RowOwner<Fake, Fake, Fake>, Binding) {
    let fake = Fake::new();
    fake.0.borrow_mut().binding.role = Role::MemberA;
    let mut binding = binding();
    binding.role = Role::MemberA;
    let mut owner =
        RowOwner::capture(binding.clone(), fake.clone(), fake.clone(), fake.clone()).unwrap();
    owner.change_interface(weak()).unwrap();
    owner.stop().unwrap();
    (fake, owner, binding)
}

#[test]
fn stopped_member_row_seal_keeps_same_original_ack_without_rereading_replaced_journal() {
    let (fake, mut owner, binding) = stopped_member_rows();
    let pin = owner.record_read_pin().unwrap();
    let seal = owner.seal_stopped_generation().unwrap();
    let again = owner.seal_stopped_generation().unwrap();
    assert!(Rc::ptr_eq(&seal, &again));
    let stopped = seal
        .inspect_original(&pin, |record| Ok(record.clone()))
        .unwrap();
    assert_eq!(stopped.phase, Phase::Stopped);
    assert_eq!(stopped.binding, binding);
    let (other_fake, other_owner, _) = stopped_member_rows();
    let foreign = other_owner.record_read_pin().unwrap();
    assert!(seal.inspect_original(&foreign, |_| Ok(())).is_err());
    drop(other_fake);
    let queries = fake.0.borrow().queries;
    fake.0.borrow_mut().creator_alive = false;
    let mut replacement = stopped.clone();
    replacement.revision += 1;
    fake.write_journal(&replacement).unwrap();
    drop(owner);
    assert_eq!(
        seal.inspect_original(&pin, |record| Ok(record.clone()))
            .unwrap(),
        stopped
    );
    assert_eq!(fake.0.borrow().queries, queries);
    // Historic seal does not rearm the original pin or confer native absence.
    assert!(pin
        .with_record(&binding.scope, binding.network_epoch, |_| Ok(()))
        .is_err());
}

#[test]
fn stopped_member_row_seal_rejects_carrier_live_and_lost_stop_ack() {
    let fake = Fake::new();
    let mut carrier = fake.owner();
    carrier.stop().unwrap();
    assert!(carrier.seal_stopped_generation().is_err());
    let fake = Fake::new();
    fake.0.borrow_mut().binding.role = Role::MemberA;
    let mut row_binding = binding();
    row_binding.role = Role::MemberA;
    let mut owner =
        RowOwner::capture(row_binding, fake.clone(), fake.clone(), fake.clone()).unwrap();
    assert!(owner.seal_stopped_generation().is_err());
    owner.stop().unwrap();
    owner.seal_stopped_generation().unwrap();
    // Fail the exact terminal write while earlier acknowledged state remains.
    let fake = Fake::new();
    fake.0.borrow_mut().binding.role = Role::MemberA;
    let mut row_binding = binding();
    row_binding.role = Role::MemberA;
    let mut owner =
        RowOwner::capture(row_binding, fake.clone(), fake.clone(), fake.clone()).unwrap();
    let terminal = fake.0.borrow().journal_writes + 2;
    fake.0.borrow_mut().journal_at = Some((terminal, Fault::LostAck));
    assert!(owner.stop().is_err());
    assert!(owner.seal_stopped_generation().is_err());
}

#[test]
fn stopped_member_row_seal_postflight_error_or_unwind_retains_same_unissued_root() {
    for unwind in [false, true] {
        let (fake, mut owner, binding) = stopped_member_rows();
        let pin = owner.record_read_pin().unwrap();
        let held = RefCell::new(None::<Rc<StoppedRowGeneration>>);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.seal_stopped_generation_with_pin(|seal| {
                assert!(seal.inspect_original(&pin, |_| Ok(())).is_err());
                *held.borrow_mut() = Some(seal);
                if unwind {
                    panic!("row seal retained before interrupted postflight");
                }
                fake.0.borrow_mut().identity_error = true;
                Ok(())
            })
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert!(held
            .borrow()
            .as_ref()
            .unwrap()
            .inspect_original(&pin, |_| Ok(()))
            .is_err());
        assert!(pin
            .with_record(&binding.scope, binding.network_epoch, |_| Ok(()))
            .is_err());
        fake.0.borrow_mut().identity_error = false;
        let effects = fake.0.borrow().effects;
        let issued = owner.seal_stopped_generation().unwrap();
        assert!(Rc::ptr_eq(&issued, held.borrow().as_ref().unwrap()));
        issued
            .inspect_original(&pin, |record| {
                assert_eq!(record.phase, Phase::Stopped);
                Ok(())
            })
            .unwrap();
        assert_eq!(fake.0.borrow().effects, effects);
    }
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
    // Actual native Wintun tuple rejected in CI: retain Get's nonmodifiable
    // IPv4 value in the model while Set encodes the documented zero input.
    let mut raw = interface_raw();
    raw.RouterDiscoveryBehavior = 2;
    raw.LinkLocalAddressBehavior = 0;
    raw.Metric = 5;
    raw.NlMtu = 65535;
    raw.SitePrefixLength = 64;
    let captured = decode_interface(&raw).unwrap();
    assert_eq!(captured.policy.site_prefix_length, 64);
    let mut desired = captured.policy.clone();
    desired.weak_host_send = true;
    desired.weak_host_receive = true;
    validate_interface_delta(&captured.policy, &desired).unwrap();
    let encoded = interface_input(MIB_IPINTERFACE_ROW::default(), captured.key, &desired).unwrap();
    assert_eq!(encoded.SitePrefixLength, 0);
    assert_eq!(
        desired.site_prefix_length, 64,
        "SDK sentinel must not rewrite protected policy"
    );
    let mut input_policy = desired;
    input_policy.site_prefix_length = 0;
    assert_eq!(decode_interface(&encoded).unwrap().policy, input_policy);
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
    for site_prefix in [0, 64] {
        let mut before = before.clone();
        before.site_prefix_length = site_prefix;
        for changed in [0, 1, 32, 64, 255] {
            if changed == site_prefix {
                continue;
            }
            let mut next = before.clone();
            next.weak_host_send = true;
            next.site_prefix_length = changed;
            assert!(
                validate_interface_delta(&before, &next).is_err(),
                "foreign site prefix {site_prefix}->{changed}"
            );
        }
    }
}
