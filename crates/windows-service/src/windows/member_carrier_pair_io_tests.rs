use super::*;
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    rc::Rc,
};

#[test]
fn original_terminal_branch_attempted_does_not_probe_or_poison_zero_effect_capture() {
    let no_c = ZeroEffectDisposition::<u32>::default();
    let original = Rc::new(7);
    let selection = ZeroEffectDisposition::default();
    selection
        .capture(|retain| {
            retain(Rc::new(
                OriginalTerminalBranch::<u32, u32>::NativeAttempted(original.clone()),
            ))
        })
        .unwrap();
    let branch = selection.sealed_proof().unwrap();
    let read = dispatch_original_terminal_branch(
        &branch,
        |_| -> io::Result<()> { no_c.capture(|_| panic!("normal must not enter no-C issuer")) },
        |actual| {
            assert!(Rc::ptr_eq(actual, &original));
            Ok(())
        },
    );
    read.unwrap();
    assert_eq!(no_c.capture.get(), 0); // no poisoned/caught fallback
    assert!(no_c.retained_proof().is_err());
}

#[test]
fn original_terminal_branch_zero_effect_adopts_same_sealed_proof_without_second_issuer() {
    let original = Rc::new(7);
    let pending = ZeroEffectDisposition::default();
    pending
        .capture(|retain| {
            retain(Rc::new(OriginalTerminalBranch::<u32, u32>::ZeroEffect(
                original.clone(),
            )))
        })
        .unwrap();
    let branch = pending.sealed_proof().unwrap();
    let destination = ZeroEffectDisposition::default();
    dispatch_original_terminal_branch(
        &branch,
        |actual| destination.capture(|retain| retain(actual.clone())),
        |_| -> io::Result<()> { panic!("no metadata-selected normal fallback") },
    )
    .unwrap();
    assert!(Rc::ptr_eq(&destination.sealed_proof().unwrap(), &original));
    // The provisional branch no longer owns a hidden duplicate Runtime proof.
    pending.dispose(&branch, |_| Ok(())).unwrap();
    pending.release_proof(&branch).unwrap();
    drop(branch);
    assert_eq!(Rc::strong_count(&original), 2); // original + SAME owning lane
}

#[test]
fn original_terminal_branch_unknown_or_postflight_loss_never_dispatches() {
    let pending = ZeroEffectDisposition::<OriginalTerminalBranch<u32, u32>>::default();
    let original = Rc::new(7);
    assert!(pending
        .capture(|retain| {
            retain(Rc::new(OriginalTerminalBranch::NativeAttempted(
                original.clone(),
            )))?;
            Err(io::Error::other(
                "actual original invocation postflight lost",
            ))
        })
        .is_err());
    assert!(pending.sealed_proof().is_err());
    assert!(pending
        .capture(|_| panic!("unknown cannot retry as ZeroEffect"))
        .is_err());
    match pending.retained_proof().unwrap().as_ref() {
        OriginalTerminalBranch::NativeAttempted(same) => assert!(Rc::ptr_eq(same, &original)),
        OriginalTerminalBranch::ZeroEffect(_) => panic!("unknown is not Never"),
    }
}

#[test]
fn zero_effect_disposition_roots_actual_proof_before_fallible_postflight() {
    let sequence = ZeroEffectDisposition::<u32>::default();
    let original = Rc::new(7);
    assert!(sequence
        .capture(|retain| {
            retain(original.clone())?;
            assert!(Rc::ptr_eq(&sequence.retained_proof()?, &original));
            Err(io::Error::other("whole Calling postflight"))
        })
        .is_err());
    assert!(Rc::ptr_eq(&sequence.retained_proof().unwrap(), &original));
    assert!(sequence.sealed_proof().is_err());
    assert!(sequence
        .capture(|_| panic!("no retry or equal replacement"))
        .is_err());
}

#[test]
fn zero_effect_disposition_unwind_and_caught_duplicate_never_seal_or_dispose() {
    let sequence = ZeroEffectDisposition::<u32>::default();
    let original = Rc::new(7);
    assert!(catch_unwind(AssertUnwindSafe(|| sequence.capture(|retain| {
        retain(original.clone())?;
        panic!("postflight unwind");
    })))
    .is_err());
    assert!(Rc::ptr_eq(&sequence.retained_proof().unwrap(), &original));
    assert!(sequence
        .dispose(&original, |_| panic!("no release"))
        .is_err());

    let duplicate = ZeroEffectDisposition::<u32>::default();
    assert!(duplicate
        .capture(|retain| {
            retain(original.clone())?;
            assert!(retain(Rc::new(7)).is_err()); // swallowed boundary failure
            Ok(())
        })
        .is_err());
    assert!(Rc::ptr_eq(&duplicate.retained_proof().unwrap(), &original));
    assert!(duplicate.sealed_proof().is_err());
}

#[test]
fn zero_effect_disposition_requires_same_original_and_actual_provider_success() {
    let sequence = ZeroEffectDisposition::<u32>::default();
    let original = Rc::new(7);
    sequence.capture(|retain| retain(original.clone())).unwrap();
    assert!(Rc::ptr_eq(&sequence.sealed_proof().unwrap(), &original));
    assert!(sequence
        .dispose(&Rc::new(7), |_| panic!("foreign equal proof"))
        .is_err());
    assert!(sequence
        .dispose(&original, |_| panic!("failed entry cannot retry"))
        .is_err());
    let no_ack = ZeroEffectDisposition::<u32>::default();
    assert!(no_ack.capture(|_| Ok(())).is_err());
    assert!(no_ack.sealed_proof().is_err());
}

#[test]
fn zero_effect_disposition_actual_disposal_is_once_and_failure_keeps_owning_resources() {
    let sequence = ZeroEffectDisposition::<u32>::default();
    let original = Rc::new(7);
    sequence.capture(|retain| retain(original.clone())).unwrap();
    let drops = Rc::new(std::cell::Cell::new(0));
    let owned = ActorTerminalParts::new(TestGenerationOwner(drops.clone()));
    assert!(sequence
        .dispose(&original, |_| {
            owned.release_with(|| Err(io::Error::other("actual provider refused inert cut")))
        })
        .is_err());
    assert_eq!(drops.get(), 0);
    assert!(sequence
        .dispose(&original, |_| panic!("no replacement disposal"))
        .is_err());
    drop(owned);
    assert_eq!(drops.get(), 0); // unknown stays retained, no implicit SDK action

    let success = ZeroEffectDisposition::<u32>::default();
    success.capture(|retain| retain(original.clone())).unwrap();
    let owned = ActorTerminalParts::new(TestGenerationOwner(drops.clone()));
    success
        .dispose(&original, |_| owned.release_with(|| Ok(())))
        .unwrap();
    assert_eq!(drops.get(), 1); // boundary double; not a native module ACK
    assert!(success
        .dispose(&original, |_| panic!("dispose twice"))
        .is_err());
}

#[test]
fn zero_effect_disposition_caught_reentry_or_unwind_cannot_finish_resource_release() {
    let sequence = ZeroEffectDisposition::<u32>::default();
    let original = Rc::new(7);
    sequence.capture(|retain| retain(original.clone())).unwrap();
    assert!(sequence
        .dispose(&original, |_| {
            assert!(sequence
                .dispose(&original, |_| panic!("nested disposal"))
                .is_err());
            Ok(()) // catching the rejection cannot approve the outer disposition
        })
        .is_err());
    assert!(sequence.sealed_proof().is_err());
    assert!(Rc::ptr_eq(&sequence.retained_proof().unwrap(), &original));

    let unwind = ZeroEffectDisposition::<u32>::default();
    unwind.capture(|retain| retain(original.clone())).unwrap();
    assert!(
        catch_unwind(AssertUnwindSafe(|| unwind.dispose(&original, |_| {
            panic!("actual raw disarm postflight");
        })))
        .is_err()
    );
    assert!(unwind.sealed_proof().is_err());
    assert!(unwind.dispose(&original, |_| panic!("no retry")).is_err());
}

#[test]
fn zero_effect_disposition_drops_original_proof_alias_only_after_actual_owning_disposition() {
    let drops = Rc::new(std::cell::Cell::new(0));
    let original = Rc::new(TestGenerationOwner(drops.clone()));
    let pending = ZeroEffectDisposition::default();
    pending.capture(|retain| retain(original.clone())).unwrap();
    assert!(pending.release_proof(&original).is_err());
    assert_eq!(Rc::strong_count(&original), 2);
    pending.dispose(&original, |_| Ok(())).unwrap();
    pending.release_proof(&original).unwrap();
    assert!(pending.sealed_proof().is_err()); // disposed is NOT a fresh permit
    assert_eq!(Rc::strong_count(&original), 1);
    drop(original);
    assert_eq!(drops.get(), 1);
}

#[cfg(not(windows))]
use crate::member_carrier_assembly::TerminalResources as GenerationDestination;
#[cfg(windows)]
use crate::windows::member_carrier_assembly::TerminalResources as GenerationDestination;

#[test]
fn original_generation_cut_retains_same_opaque_roots_before_postflight_failure() {
    let owner = Rc::new(std::cell::Cell::new(0));
    let mut old = Some(TestGenerationOwner(owner.clone()));
    let mut transfer = OriginalGenerationTransfer::default();
    let mut destination = GenerationDestination::new(None);
    assert!(transfer
        .capture(&mut destination, |slot| {
            *slot = old.take();
            Err(io::Error::other("postflight"))
        })
        .is_err());
    assert!(old.is_none());
    let original = transfer.original().unwrap();
    assert!(Rc::ptr_eq(
        destination.retained().as_ref().unwrap(),
        &original
    ));
    original
        .inspect(|same| {
            assert!(Rc::ptr_eq(&same.0, &owner));
            Ok(())
        })
        .unwrap();
    assert!(transfer
        .capture(&mut destination, |_| panic!("no retry"))
        .is_err());
    drop(transfer);
    drop(destination); // unknown caller-rooted original is never destructed
    drop(original);
    assert_eq!(owner.get(), 0);
}

#[test]
fn original_generation_cut_unwind_and_foreign_empty_destination_cannot_adopt_originals() {
    let owner = Rc::new(std::cell::Cell::new(0));
    let mut transfer = OriginalGenerationTransfer::default();
    let mut destination = GenerationDestination::new(None);
    assert!(catch_unwind(AssertUnwindSafe(|| transfer.capture(
        &mut destination,
        |slot| {
            *slot = Some(TestGenerationOwner(owner.clone()));
            panic!("after retained originals");
        }
    )))
    .is_err());
    let original = transfer.original().unwrap();
    let foreign = OriginalGenerationTransfer::<TestGenerationOwner>::default();
    assert!(!foreign.same_original(&original));
    assert!(transfer.same_original(&original)); // facts only despite failed postflight
    drop(destination);
    drop(transfer);
    drop(original);
    assert_eq!(owner.get(), 0);
}

#[test]
fn original_generation_cut_occupied_destination_keeps_unmoved_original_and_cannot_retry() {
    let mut transfer = OriginalGenerationTransfer::<u32>::default();
    let mut first = OriginalGenerationTransfer::default();
    let mut destination = GenerationDestination::new(None);
    first
        .capture(&mut destination, |slot| {
            *slot = Some(7);
            Ok(())
        })
        .unwrap();
    let mut original = Some(7);
    assert!(transfer
        .capture(&mut destination, |slot| {
            *slot = original.take();
            Ok(())
        })
        .is_err());
    assert_eq!(original, Some(7));
    assert!(!transfer.same_original(destination.retained().as_ref().unwrap()));
    let mut fresh = GenerationDestination::new(None);
    assert!(transfer
        .capture(&mut fresh, |_| panic!("failed entry cannot retry"))
        .is_err());
    assert!(fresh.retained().is_none());
}

#[test]
fn original_generation_cut_equal_independent_payloads_cannot_replace_original_origin() {
    let mut first = OriginalGenerationTransfer::default();
    let mut foreign = OriginalGenerationTransfer::default();
    let mut original = GenerationDestination::new(None);
    let mut equal = GenerationDestination::new(None);
    first
        .capture(&mut original, |slot| {
            *slot = Some(7);
            Ok(())
        })
        .unwrap();
    foreign
        .capture(&mut equal, |slot| {
            *slot = Some(7);
            Ok(())
        })
        .unwrap();
    original
        .retained()
        .as_ref()
        .unwrap()
        .inspect(|value| {
            equal.retained().as_ref().unwrap().inspect(|other| {
                assert_eq!(value, other);
                Ok(())
            })
        })
        .unwrap();
    assert!(!first.same_original(equal.retained().as_ref().unwrap()));
    assert!(!foreign.same_original(original.retained().as_ref().unwrap()));
}

#[test]
fn original_generation_cut_failed_before_payload_does_not_report_empty_success() {
    let mut source = OriginalGenerationTransfer::<Vec<u32>>::default();
    let mut destination = GenerationDestination::new(None);
    assert!(source
        .capture(&mut destination, |_| Err(io::Error::other("before move")))
        .is_err());
    let retained = source.original().unwrap(); // same retained raw shell only
    assert!(retained
        .inspect::<()>(|_| panic!("unknown payload is not empty history"))
        .is_err());
    assert!(source
        .capture(&mut destination, |_| panic!("no retry"))
        .is_err());
}

#[test]
fn original_generation_cut_has_no_unknown_retaining_wrapper_in_proven_raw_payload() {
    let drops = Rc::new(std::cell::Cell::new(0));
    let mut transfer = OriginalGenerationTransfer::default();
    let mut destination = GenerationDestination::new(None);
    transfer
        .capture(&mut destination, |slot| {
            *slot = Some(TestGenerationOwner(drops.clone()));
            Ok(())
        })
        .unwrap();
    // Ownership transfer ONLY. A real native caller still requires independent
    // original C/G/destructor proof; this double has no native handle/effect.
    let mut owning = None;
    destination.transfer_original_into(&mut owning).unwrap();
    drop(owning);
    assert_eq!(drops.get(), 1);
    assert!(transfer.read_cut().is_err()); // a lost cut is NOT empty history
    drop(transfer); // weak origin, no hidden owning alias or retaining Drop
}

struct TestGenerationOwner(Rc<std::cell::Cell<u32>>);
impl Drop for TestGenerationOwner {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

#[test]
fn terminal_capture_originals_are_same_retained_rcs_never_equal_replacements() {
    let rows = Rc::new(7);
    let probes = Rc::new(7);
    let (actual_rows, actual_probes) =
        clone_original_capture_pair(&Some(rows.clone()), &Some(probes.clone())).unwrap();
    assert!(Rc::ptr_eq(&actual_rows, &rows));
    assert!(Rc::ptr_eq(&actual_probes, &probes));
    assert!(!Rc::ptr_eq(&actual_rows, &Rc::new(7)));
    assert!(!Rc::ptr_eq(&actual_probes, &Rc::new(7)));
}

#[test]
fn terminal_capture_originals_missing_one_actual_pin_is_unknown_not_partial_success() {
    let rows = Rc::new(7);
    let probes = Rc::new(7);
    assert!(clone_original_capture_pair(&Some(rows.clone()), &None::<Rc<u32>>).is_err());
    assert!(clone_original_capture_pair(&None::<Rc<u32>>, &Some(probes.clone())).is_err());
    assert_eq!(Rc::strong_count(&rows), 1);
    assert_eq!(Rc::strong_count(&probes), 1);
}

#[cfg(windows)]
mod storage_cleanup {
    use super::*;
    use std::cell::RefCell;
    use storage_rows as rows;
    use windows_sys::Win32::{NetworkManagement::IpHelper::*, Networking::WinSock::AF_INET};

    // Real RowOwner/codec/CAS and retained originals. Only the external native
    // boundary is replaced; these tests never call an SDK function.
    #[derive(Clone)]
    struct Boundary(Rc<RefCell<State>>);
    struct State {
        binding: rows::Binding,
        locked: bool,
        queries: usize,
        effects: usize,
        cleanup: bool,
        directory: tempfile::TempDir,
    }
    impl Boundary {
        fn new() -> Self {
            Self(Rc::new(RefCell::new(State {
                binding: rows::Binding {
                    scope: nelomai_client_tunnel::redundancy::SessionScope {
                        runtime: nelomai_contracts::RuntimeSlot::Stable,
                        runtime_generation: 7,
                        connection_generation: 9,
                        session_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
                    },
                    boot_id: [7; 16],
                    runtime: nelomai_contracts::dispatcher::EngineIdentity {
                        slot: nelomai_contracts::RuntimeSlot::Stable,
                        runtime_version: "0.3.3".into(),
                        runtime_contract_version: 2,
                        container_version: "0.3.3".into(),
                        manifest_sha256: "a".repeat(64),
                    },
                    network_epoch: 19,
                    role: rows::Role::MemberA,
                    guid: [23; 16],
                    name: "original-A".into(),
                    key: rows::RowKey {
                        luid: 2300,
                        index: 23,
                    },
                    address: [10, 240, 3, 2],
                },
                locked: false,
                queries: 0,
                effects: 0,
                cleanup: false,
                directory: tempfile::tempdir().unwrap(),
            })))
        }
        fn load_record(&self) -> rows::Result<Option<rows::Record>> {
            let path = self.0.borrow().directory.path().join("row");
            match std::fs::read(path) {
                Ok(bytes) => rows::Record::decode(&bytes).map(Some),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(_) => Err(rows::Error::Journal),
            }
        }
        fn owner(&self) -> rows::RowOwner<Self, Self, Self> {
            let binding = self.0.borrow().binding.clone();
            rows::RowOwner::capture(binding, self.clone(), self.clone(), self.clone()).unwrap()
        }
        fn locked(&self) {
            assert!(self.0.borrow().locked);
        }
    }
    impl rows::Authority for Boundary {
        type Creator = Self;
        fn locked<T>(
            &mut self,
            call: impl FnOnce(&mut Self) -> rows::Result<T>,
        ) -> rows::Result<T> {
            assert!(!self.0.borrow().locked);
            self.0.borrow_mut().locked = true;
            struct Unlock(Boundary);
            impl Drop for Unlock {
                fn drop(&mut self) {
                    self.0 .0.borrow_mut().locked = false;
                }
            }
            let _unlock = Unlock(self.clone());
            call(self)
        }
    }
    impl rows::OriginalCreator for Boundary {
        fn query(
            &mut self,
            _: &nelomai_client_tunnel::redundancy::SessionScope,
            _: rows::Role,
            challenge: u64,
        ) -> rows::Result<rows::LiveOwner> {
            self.locked();
            self.0.borrow_mut().queries += 1;
            Ok(rows::LiveOwner {
                binding: self.0.borrow().binding.clone(),
                challenge,
            })
        }
        fn authorize(&mut self, _: &rows::Binding, _: &rows::Target) -> rows::Result<()> {
            self.locked();
            Ok(())
        }
    }
    impl rows::Kernel for Boundary {
        fn identity(&mut self, _: rows::RowKey) -> rows::Result<rows::NativeIdentity> {
            self.locked();
            let state = self.0.borrow();
            Ok(rows::NativeIdentity {
                key: state.binding.key,
                guid: state.binding.guid,
                name: state.binding.name.clone(),
                if_type: 53,
                hardware: false,
            })
        }
        fn interface(&mut self, _: rows::RowKey) -> rows::Result<MIB_IPINTERFACE_ROW> {
            self.locked();
            let mut row = MIB_IPINTERFACE_ROW {
                Family: AF_INET,
                InterfaceIndex: 23,
                NlMtu: 1400,
                ..Default::default()
            };
            row.InterfaceLuid.Value = 2300;
            Ok(row)
        }
        fn address(
            &mut self,
            _: rows::RowKey,
            _: [u8; 4],
        ) -> rows::Result<Option<MIB_UNICASTIPADDRESS_ROW>> {
            self.locked();
            Ok(None)
        }
        fn initialize_interface(&mut self) -> MIB_IPINTERFACE_ROW {
            panic!("no SDK effects expected")
        }
        fn initialize_address(&mut self) -> MIB_UNICASTIPADDRESS_ROW {
            panic!("no SDK effects expected")
        }
        fn set_interface(&mut self, _: &mut MIB_IPINTERFACE_ROW) -> rows::Result<()> {
            self.0.borrow_mut().effects += 1;
            Err(rows::Error::Native)
        }
        fn create_address(&mut self, _: &MIB_UNICASTIPADDRESS_ROW) -> rows::Result<()> {
            panic!("no create")
        }
        fn delete_address(&mut self, _: &MIB_UNICASTIPADDRESS_ROW) -> rows::Result<()> {
            panic!("no delete")
        }
    }
    impl rows::Journal for Boundary {
        fn load(&mut self, _: &rows::Binding) -> rows::Result<Option<rows::Record>> {
            self.locked();
            self.load_record()
        }
        fn compare_exchange(
            &mut self,
            _: &rows::Binding,
            expected: Option<&rows::Record>,
            desired: &rows::Record,
        ) -> rows::Result<()> {
            use std::io::Write;
            self.locked();
            if self.load_record()?.as_ref() != expected {
                return Err(rows::Error::Conflict);
            }
            let state = self.0.borrow();
            let mut next = tempfile::NamedTempFile::new_in(state.directory.path())
                .map_err(|_| rows::Error::Journal)?;
            next.write_all(&desired.encode()?)
                .map_err(|_| rows::Error::Journal)?;
            next.as_file()
                .sync_all()
                .map_err(|_| rows::Error::Journal)?;
            next.persist(state.directory.path().join("row"))
                .map_err(|_| rows::Error::Journal)?;
            Ok(())
        }
    }

    #[test]
    fn terminal_row_requires_actual_same_owner_stop_ack_not_equal_import_or_capture() {
        let boundary = Boundary::new();
        let mut owner = boundary.owner();
        let pin = owner.record_read_pin().unwrap();
        let b = boundary.0.borrow().binding.clone();
        let captured = boundary.load_record().unwrap().unwrap();
        let foreign_boundary = Boundary::new();
        let mut foreign_owner = foreign_boundary.owner();
        let foreign = foreign_owner.record_read_pin().unwrap();
        assert!(!pin.same_original(&foreign));
        assert!(verify_terminal_member_row_original(&owner, &pin, &captured).is_err());
        owner.stop().unwrap();
        let stopped = boundary.load_record().unwrap().unwrap();
        foreign_owner.stop().unwrap();
        // Independent genuine CAS/Stop ACK, byte-equal factual record. Only
        // SAME original ownership can distinguish it, not phase/JSON equality.
        assert_eq!(
            foreign_boundary.load_record().unwrap().as_ref(),
            Some(&stopped)
        );
        foreign
            .with_cleanup_record(&b.scope, b.network_epoch, |facts| {
                assert_eq!(facts.acknowledged, &stopped);
                Ok(())
            })
            .unwrap();
        let queries = boundary.0.borrow().queries;
        verify_terminal_member_row_original(&owner, &pin, &stopped).unwrap();
        assert!(verify_terminal_member_row_original(&owner, &foreign, &stopped).is_err());
        assert!(verify_terminal_member_row_original(&owner, &pin, &captured).is_err());
        assert_eq!(boundary.0.borrow().queries, queries);
        assert_eq!(boundary.0.borrow().effects, 0);
        let resources = ActorTerminalParts::new(owner);
        assert!(resources.release_with(|| Err(conflict())).is_err());
        assert!(pin.same_original(&resources.try_borrow().unwrap().record_read_pin().unwrap()));
        drop(resources); // unknown parts keep the actual stopped owner, no SDK
        pin.with_cleanup_record(&b.scope, b.network_epoch, |facts| {
            assert_eq!(facts.acknowledged, &stopped);
            Ok(())
        })
        .unwrap();
        assert_eq!(boundary.0.borrow().queries, queries);
        assert_eq!(boundary.0.borrow().effects, 0);
    }

    #[test]
    fn canonical_cleanup_is_obtained_after_original_owner_revocation_without_ack_or_effect() {
        let boundary = Boundary::new();
        let mut owner = boundary.owner();
        let pin = owner.record_read_pin().unwrap();
        let b = boundary.0.borrow().binding.clone();
        let captured = boundary.load_record().unwrap().unwrap();
        let queries = boundary.0.borrow().queries;
        enter_original_row_storage_cleanup(
            &mut owner,
            || {
                assert_eq!(
                    pin.with_record(&b.scope, b.network_epoch, |_| Ok(())),
                    Err(rows::Error::Retired)
                );
                Ok(boundary.clone())
            },
            |journal, canonical| {
                assert!(Rc::ptr_eq(&journal.0, &canonical.0));
                journal.0.borrow_mut().cleanup = true;
                Ok(())
            },
        )
        .unwrap();
        assert!(boundary.0.borrow().cleanup);
        assert_eq!(boundary.0.borrow().queries, queries);
        assert_eq!(boundary.0.borrow().effects, 0);
        assert_eq!(boundary.load_record().unwrap(), Some(captured.clone()));
        assert!(pin.same_original(&owner.record_read_pin().unwrap()));
        pin.with_cleanup_record(&b.scope, b.network_epoch, |facts| {
            assert_eq!(facts.acknowledged, &captured);
            Ok(())
        })
        .unwrap();
        owner.stop().unwrap();
        assert_eq!(
            boundary.load_record().unwrap().unwrap().phase,
            rows::Phase::Stopped
        );
    }

    #[test]
    fn failed_or_unwinding_canonical_cleanup_keeps_original_ack_and_never_calls_handoff() {
        for unwind in [false, true] {
            let boundary = Boundary::new();
            let mut owner = boundary.owner();
            let pin = owner.record_read_pin().unwrap();
            let b = boundary.0.borrow().binding.clone();
            let captured = boundary.load_record().unwrap().unwrap();
            let result = catch_unwind(AssertUnwindSafe(|| {
                enter_original_row_storage_cleanup::<_, _, _, ()>(
                    &mut owner,
                    || {
                        if unwind {
                            panic!("canonical cleanup postflight");
                        }
                        Err(rows::Error::Journal)
                    },
                    |_, _| panic!("unverified files cannot reach journal"),
                )
            }));
            assert!(result.is_err() || result.unwrap().is_err());
            assert_eq!(
                pin.with_record(&b.scope, b.network_epoch, |_| Ok(())),
                Err(rows::Error::Retired)
            );
            assert!(pin.same_original(&owner.record_read_pin().unwrap()));
            pin.with_cleanup_record(&b.scope, b.network_epoch, |facts| {
                assert_eq!(facts.acknowledged, &captured);
                Ok(())
            })
            .unwrap();
            assert_eq!(boundary.load_record().unwrap(), Some(captured));
            assert_eq!(boundary.0.borrow().effects, 0);
            assert!(!boundary.0.borrow().cleanup);
        }
    }

    #[test]
    fn journal_handoff_error_or_unwind_retains_same_original_owner_pin_and_captured_ack() {
        for unwind in [false, true] {
            let boundary = Boundary::new();
            let mut owner = boundary.owner();
            let pin = owner.record_read_pin().unwrap();
            let b = boundary.0.borrow().binding.clone();
            let captured = boundary.load_record().unwrap().unwrap();
            let queries = boundary.0.borrow().queries;
            let result = catch_unwind(AssertUnwindSafe(|| {
                enter_original_row_storage_cleanup(
                    &mut owner,
                    || Ok(boundary.clone()),
                    |journal, canonical| {
                        assert!(Rc::ptr_eq(&journal.0, &canonical.0));
                        assert_eq!(
                            pin.with_record(&b.scope, b.network_epoch, |_| Ok(())),
                            Err(rows::Error::Retired)
                        );
                        if unwind {
                            panic!("actual journal cleanup postflight");
                        }
                        Err(rows::Error::Journal)
                    },
                )
            }));
            assert!(result.is_err() || result.unwrap().is_err());
            assert!(pin.same_original(&owner.record_read_pin().unwrap()));
            pin.with_cleanup_record(&b.scope, b.network_epoch, |facts| {
                assert_eq!(facts.acknowledged, &captured);
                Ok(())
            })
            .unwrap();
            assert_eq!(boundary.load_record().unwrap(), Some(captured));
            assert_eq!(boundary.0.borrow().queries, queries);
            assert_eq!(boundary.0.borrow().effects, 0);
        }
    }
}

#[test]
fn row_storage_cleanup_is_closing_restore_or_exact_member_stop_only() {
    use crate::member_carrier_pair::Effect;
    use nelomai_client_tunnel::redundancy::Slot;
    for (stage, effect, slot) in [
        (3, Effect::RestoreWeak, Slot::A),
        (3, Effect::RestoreWeak, Slot::B),
        (4, Effect::MemberStop(Slot::A), Slot::A),
        (5, Effect::MemberStop(Slot::B), Slot::B),
    ] {
        let mut record = closing_record();
        record.stop_stage = stage;
        record.pending = Some(effect);
        record.validate().unwrap();
        require_member_row_storage_cleanup_frame(&record, slot).unwrap();
    }
    for (stage, effect, slot) in [
        (4, Effect::MemberStop(Slot::A), Slot::B),
        (5, Effect::MemberStop(Slot::B), Slot::A),
        (6, Effect::CarrierAddressDelete, Slot::A),
        (9, Effect::NativeEmpty, Slot::A),
        (12, Effect::FullEmpty, Slot::B),
    ] {
        let mut record = closing_record();
        record.stop_stage = stage;
        record.pending = Some(effect);
        record.validate().unwrap();
        assert!(require_member_row_storage_cleanup_frame(&record, slot).is_err());
    }
    let mut record = closing_record();
    record.stop_stage = 3;
    record.pending = None;
    assert!(require_member_row_storage_cleanup_frame(&record, Slot::A).is_err());
}

#[test]
fn rebind_ack_requires_same_nic_new_process_and_exact_retired_original() {
    use crate::member_owner::{Intent, NativeProof, Phase, ProcessProof, Record};
    let prior = Record {
        intent: Intent {
            scope: closing_record().scope,
            slot: nelomai_contracts::dispatcher::TunnelSlot::A,
            transport: nelomai_client_tunnel::TunnelTransport::WireGuard,
            engine: crate::test_engine_path("engine.exe"),
            config_sha256: [9; 32],
        },
        phase: Phase::Running,
        proof: Some(NativeProof {
            process: ProcessProof {
                pid: 301,
                creation_time: 3001,
            },
            interface: crate::member_owner::InterfaceProof {
                index: 21,
                luid: 2100,
                guid: [21; 16],
            },
        }),
        retired_proof: None,
        previous_config_sha256: None,
    };
    crate::member_owner::validate_record_shape(&prior).unwrap();
    let mut next = prior.clone();
    next.retired_proof = prior.proof;
    next.proof.as_mut().unwrap().process = ProcessProof {
        pid: 302,
        creation_time: 3002,
    };
    compare_member_rebind_ack(&prior, &next).unwrap();
    let mutations: [fn(&mut Record); 5] = [
        |r| r.retired_proof = None,
        |r| r.retired_proof.as_mut().unwrap().process.pid = 303,
        |r| r.proof.as_mut().unwrap().interface.index = 22,
        |r| {
            r.proof.as_mut().unwrap().process = ProcessProof {
                pid: 301,
                creation_time: 3001,
            }
        },
        |r| r.previous_config_sha256 = Some([8; 32]),
    ];
    for mutation in mutations {
        let mut foreign = next.clone();
        mutation(&mut foreign);
        assert!(compare_member_rebind_ack(&prior, &foreign).is_err());
    }
}

#[test]
fn full_empty_requires_closed_guard_and_separate_exact_final_read_frame() {
    use crate::member_carrier_pair::{Effect, Phase};
    let mut record = closing_record();
    record.stop_stage = 12;
    record.pending = Some(Effect::FullEmpty);
    record.guard = crate::member_carrier_guard::Model::empty(record.scope.clone()).unwrap();
    require_full_empty_frame(&record).unwrap();
    let mut stopped = record.clone();
    stopped.phase = Phase::Stopped;
    stopped.pending = None;
    require_full_empty_frame(&stopped).unwrap();
    for mutation in [
        (|r: &mut crate::member_carrier_pair::Record| r.stop_stage = 11)
            as fn(&mut crate::member_carrier_pair::Record),
        |r| r.pending = None,
        |r| r.guard.expected.version = 0,
    ] {
        let mut wrong = record.clone();
        mutation(&mut wrong);
        assert!(require_full_empty_frame(&wrong).is_err());
    }
}

#[test]
fn no_constructor_cleanup_compares_actual_snapshot_before_full_empty_stage() {
    use crate::member_carrier_pair::{Effect, Phase};
    use nelomai_client_tunnel::redundancy::Slot;
    let mut record = closing_record();
    for (stage, effect) in [
        (0, Effect::Guard),
        (1, Effect::ReleaseProbes),
        (2, Effect::RestoreNetwork),
        (3, Effect::RestoreWeak),
        (4, Effect::MemberStop(Slot::A)),
        (5, Effect::MemberStop(Slot::B)),
        (6, Effect::CarrierAddressDelete),
        (7, Effect::CarrierSessionEnd),
        (8, Effect::CarrierClose),
        (9, Effect::NativeEmpty),
        (10, Effect::Guard),
        (11, Effect::RestoreKeys),
        (12, Effect::FullEmpty),
    ] {
        record.stop_stage = stage;
        record.pending = Some(effect);
        let actual = record.guard.expected.clone();
        compare_no_constructor_cleanup_snapshot(&record, &actual).unwrap();
        if stage < 12 {
            assert!(compare_full_empty_snapshot(&record, &actual).is_err());
        }
        let mut foreign = actual.clone();
        foreign.scope.connection_generation += 1;
        assert!(compare_no_constructor_cleanup_snapshot(&record, &foreign).is_err());
        let mut wrong = record.clone();
        wrong.pending = None;
        assert!(compare_no_constructor_cleanup_snapshot(&wrong, &actual).is_err());
        wrong = record.clone();
        wrong.carrier = Some(crate::member_owner::InterfaceProof {
            guid: [1; 16],
            index: 1,
            luid: 1,
        });
        assert!(compare_no_constructor_cleanup_snapshot(&wrong, &actual).is_err());
    }
    record.phase = Phase::Stopped;
    record.pending = None;
    assert!(compare_no_constructor_cleanup_snapshot(&record, &record.guard.expected).is_err());
}

#[test]
fn full_empty_snapshot_compares_every_observed_sdk_field_not_model_flags() {
    use crate::member_carrier_guard as guard;
    let mut record = closing_record();
    record.stop_stage = 12;
    record.pending = Some(crate::member_carrier_pair::Effect::FullEmpty);
    let empty = record.guard.expected.clone();
    compare_full_empty_snapshot(&record, &empty).unwrap();
    let identity = guard::Identity {
        scope: record.scope.clone(),
        proof: crate::member_owner::InterfaceProof {
            index: 23,
            luid: 2300,
            guid: [23; 16],
        },
    };
    let mut samples = Vec::new();
    let mut changed = empty.clone();
    changed.version += 1;
    samples.push(changed);
    let mut changed = empty.clone();
    changed.scope.connection_generation += 1;
    samples.push(changed);
    let mut changed = empty.clone();
    changed.carrier = Some(guard::Carrier {
        identity: identity.clone(),
        sources: vec!["10.1.2.3".parse().unwrap()],
    });
    samples.push(changed);
    for i in 0..2 {
        let mut changed = empty.clone();
        changed.egress[i] = Some(identity.clone());
        samples.push(changed);
    }
    let mut changed = empty.clone();
    changed.sublayer = Some(guard::Sublayer {
        key: guard::Key([6; 16]),
        weight: 65534,
        flags: 0,
    });
    samples.push(changed);
    let mut changed = empty.clone();
    changed.filters.push(guard::Filter {
        key: guard::Key([5; 16]),
        sublayer: guard::Key([6; 16]),
        layer: guard::Layer::ForwardV4,
        weight: 10,
        flags: 0,
        action: guard::Action::Block,
        conditions: vec![],
    });
    samples.push(changed);
    for sample in samples {
        assert!(compare_full_empty_snapshot(&record, &sample).is_err());
    }
}

#[test]
fn full_empty_attestation_uses_exact_terminal_channel_before_any_retired_read() {
    use crate::member_carrier_pair::{Effect, Phase};
    let mut closing = closing_record();
    closing.stop_stage = 12;
    closing.pending = Some(Effect::FullEmpty);
    require_attestation(&closing, Effect::FullEmpty).unwrap();
    let mut early = closing.clone();
    early.stop_stage = 11;
    assert!(require_attestation(&early, Effect::FullEmpty).is_err());
    let mut stopped = closing;
    stopped.phase = Phase::Stopped;
    stopped.pending = None;
    require_attestation(&stopped, Effect::FullEmpty).unwrap();
    assert!(require_effect(&stopped, Effect::FullEmpty).is_err());
}

#[test]
fn weak_rows_captures_all_original_baselines_before_carrier_or_member_changes() {
    use nelomai_client_tunnel::redundancy::Slot;
    let mut events = Vec::new();
    weak_rows_sequence([true, true], |step| {
        events.push(step);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        events,
        [
            WeakRowsBoundary::Capture(Slot::A),
            WeakRowsBoundary::Capture(Slot::B),
            WeakRowsBoundary::Carrier,
            WeakRowsBoundary::Member(Slot::A),
            WeakRowsBoundary::Member(Slot::B),
        ]
    );
    let mut events = Vec::new();
    weak_rows_sequence([true, false], |step| {
        events.push(step);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        events,
        [
            WeakRowsBoundary::Capture(Slot::A),
            WeakRowsBoundary::Carrier,
            WeakRowsBoundary::Member(Slot::A)
        ]
    );
}

#[test]
fn weak_rows_capture_failure_never_attempts_interface_mutation() {
    use nelomai_client_tunnel::redundancy::Slot;
    let mut events = Vec::new();
    assert!(weak_rows_sequence([true, true], |step| {
        events.push(step);
        if step == WeakRowsBoundary::Capture(Slot::B) {
            return Err(conflict());
        }
        Ok(())
    })
    .is_err());
    assert_eq!(
        events,
        [
            WeakRowsBoundary::Capture(Slot::A),
            WeakRowsBoundary::Capture(Slot::B)
        ]
    );
}

#[test]
fn member_row_capture_never_reuses_stopped_pending_or_revoked_original() {
    use crate::member_carrier_rows::Phase;
    require_reusable_member_rows(Phase::Captured, false, false).unwrap();
    for (phase, pending, cleanup_only) in [
        (Phase::Stopped, false, true),
        (Phase::Stopped, false, false),
        (Phase::Closing, false, true),
        (Phase::Closing, false, false),
        (Phase::Captured, true, false),
        (Phase::Captured, false, true),
    ] {
        assert!(require_reusable_member_rows(phase, pending, cleanup_only).is_err());
    }
}

#[test]
fn replacement_capture_retains_original_owner_and_receipts_before_error() {
    let original = Rc::new(Cell::new(31));
    let pin = Rc::new(Cell::new(32));
    let seal = Rc::new(Cell::new(33));
    let mut current = Some(original.clone());
    let mut history = Vec::new();
    let result = with_retained_row_original::<_, _, ()>(
        &mut current,
        &mut history,
        (pin.clone(), seal.clone()),
        || {
            assert_eq!(Rc::strong_count(&original), 2);
            assert_eq!(Rc::strong_count(&pin), 2);
            assert_eq!(Rc::strong_count(&seal), 2);
            Err(conflict())
        },
    );
    assert!(result.is_err());
    assert!(current.is_none());
    assert_eq!(history.len(), 1);
    assert!(Rc::ptr_eq(&history[0].0, &original));
    assert!(Rc::ptr_eq(&history[0].1 .0, &pin));
    assert!(Rc::ptr_eq(&history[0].1 .1, &seal));
    assert!(with_retained_row_original::<_, _, ()>(
        &mut current,
        &mut history,
        (pin.clone(), seal.clone()),
        || panic!("missing original is never replacement authority"),
    )
    .is_err());
}

#[test]
fn replacement_capture_unwind_keeps_original_without_rearming_slot() {
    let original = Rc::new(Cell::new(34));
    let receipt = Rc::new(Cell::new(35));
    let mut current = Some(original.clone());
    let mut history = Vec::new();
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _ = with_retained_row_original::<_, _, ()>(
            &mut current,
            &mut history,
            receipt.clone(),
            || panic!("real capture postflight unwind"),
        );
    }))
    .is_err());
    assert!(current.is_none());
    assert!(Rc::ptr_eq(&history[0].0, &original));
    assert!(Rc::ptr_eq(&history[0].1, &receipt));
}

#[test]
fn native_empty_is_exact_closing_facts_dispatch_and_never_rearms_forward() {
    use crate::member_carrier_pair::{Effect, Phase};
    for (stage, effect) in [(9, Effect::NativeEmpty), (10, Effect::Guard)] {
        let serial = ActorSerial::default();
        let mut record = closing_record();
        record.stop_stage = stage;
        record.pending = Some(effect);
        record.validate().unwrap();
        assert_eq!(native_empty_call(&serial, &record, || Ok(23)).unwrap(), 23);
        assert!(serial.revoked.get());
        assert!(serial.run(false, || Ok(())).is_err());
        assert!(native_empty_call::<()>(&serial, &record, || Err(conflict())).is_err());
        let mut wrong = record.clone();
        wrong.pending = None;
        assert!(native_empty_call::<()>(&serial, &wrong, || panic!("no None late read")).is_err());
        let mut wrong = record.clone();
        wrong.stop_stage = 8;
        wrong.pending = Some(Effect::CarrierClose);
        assert!(
            native_empty_call::<()>(&serial, &wrong, || panic!("not stage8 permission")).is_err()
        );
        let mut wrong = record;
        wrong.phase = Phase::Stopped;
        wrong.stop_stage = 12;
        wrong.pending = None;
        assert!(native_empty_call::<()>(&serial, &wrong, || panic!("not terminal read")).is_err());
    }
}

#[test]
fn row_generation_retains_original_before_inventory_then_completes_same_receipt() {
    let original = Rc::new(Cell::new(12));
    let mut retained = Vec::new();
    let events = std::cell::RefCell::new(Vec::new());
    project_generation_order(
        &mut retained,
        || {
            events.borrow_mut().push("rows-retire");
            Ok(original.clone())
        },
        || {
            assert_eq!(Rc::strong_count(&original), 3); // caller + receipt + retained root.
            events.borrow_mut().push("inventory-retire");
            Ok(())
        },
        |receipt| {
            assert!(Rc::ptr_eq(receipt, &original));
            events.borrow_mut().push("rows-complete");
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        *events.borrow(),
        ["rows-retire", "inventory-retire", "rows-complete"]
    );
    assert!(Rc::ptr_eq(&retained[0], &original));
}

#[test]
fn row_generation_inventory_or_completion_failure_retains_original_without_advancing() {
    for inventory_denied in [true, false] {
        let original = Rc::new(Cell::new(13));
        let mut retained = Vec::new();
        let completion = Cell::new(false);
        assert!(project_generation_order(
            &mut retained,
            || Ok(original.clone()),
            || {
                if inventory_denied {
                    return Err(conflict());
                }
                Ok(())
            },
            |receipt| {
                assert!(Rc::ptr_eq(receipt, &original));
                completion.set(true);
                Err(conflict())
            }
        )
        .is_err());
        assert_eq!(completion.get(), !inventory_denied);
        assert!(Rc::ptr_eq(&retained[0], &original));
    }
    let original = Rc::new(Cell::new(14));
    let mut retained = Vec::new();
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _ = project_generation_order(
            &mut retained,
            || Ok(original.clone()),
            || panic!("inventory postflight unwind"),
            |_| panic!("completion must never be entered"),
        );
    }))
    .is_err());
    assert!(Rc::ptr_eq(&retained[0], &original));
}

#[test]
fn generation_ticket_is_rooted_before_projection_and_replacement_preparation() {
    let original = Rc::new(Cell::new(7));
    let mut retained = Vec::new();
    let events = std::cell::RefCell::new(Vec::new());
    retain_generation_once(&mut retained, &original, |ticket| {
        assert!(Rc::ptr_eq(ticket, &original));
        assert_eq!(Rc::strong_count(&original), 2);
        events.borrow_mut().push("project");
        Ok(())
    })
    .unwrap();
    events.borrow_mut().push("prepare");
    assert_eq!(*events.borrow(), ["project", "prepare"]);
    assert!(Rc::ptr_eq(&retained[0], &original));
    assert!(
        retain_generation_once::<_, ()>(&mut retained, &original, |_| {
            panic!("never repeat same original projection")
        })
        .is_err()
    );
    assert_eq!(retained.len(), 1);
}

#[test]
fn generation_projection_denial_retains_ticket_and_never_prepares() {
    let original = Rc::new(Cell::new(8));
    let mut retained = Vec::new();
    let prepared = Cell::new(false);
    let result = retain_generation_once::<_, ()>(&mut retained, &original, |ticket| {
        assert!(Rc::ptr_eq(ticket, &original));
        assert_eq!(Rc::strong_count(&original), 2);
        Err(io::Error::other("actual owner projection denied"))
    });
    if result.is_ok() {
        prepared.set(true);
    }
    assert!(result.is_err());
    assert!(!prepared.get());
    assert!(Rc::ptr_eq(&retained[0], &original));
    assert!(
        retain_generation_once::<_, ()>(&mut retained, &original, |_| {
            panic!("failed projection is not retry authority")
        })
        .is_err()
    );
}

#[test]
fn generation_projection_unwind_retains_ticket_without_equal_retry() {
    let original = Rc::new(Cell::new(9));
    let mut retained = Vec::new();
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _ = retain_generation_once::<_, ()>(&mut retained, &original, |ticket| {
            assert!(Rc::ptr_eq(ticket, &original));
            assert_eq!(Rc::strong_count(&original), 2);
            panic!("fallible inventory postflight")
        });
    }))
    .is_err());
    assert!(Rc::ptr_eq(&retained[0], &original));
    assert!(
        retain_generation_once::<_, ()>(&mut retained, &original, |_| {
            panic!("unwinding projection is not retry authority")
        })
        .is_err()
    );
}

#[test]
fn execution_probe_history_requires_retired_original_read_not_live_tuple_or_missing_lookup() {
    assert_eq!(
        execution_probe_read(1, true, true).unwrap(),
        ExecutionProbeRead::Live
    );
    assert_eq!(
        execution_probe_read(0, true, true).unwrap(),
        ExecutionProbeRead::Retired
    );
    assert_eq!(
        execution_probe_read(0, false, false).unwrap(),
        ExecutionProbeRead::Uncaptured
    );
    for (expected, actor, canonical) in [
        (0, true, false),
        (0, false, true),
        (1, false, false),
        (1, true, false),
        (1, false, true),
        (2, true, true),
    ] {
        assert!(execution_probe_read(expected, actor, canonical).is_err());
    }
}

#[test]
fn execution_binding_comparison_keeps_closed_original_history_out_of_live_inputs() {
    use crate::member_owner::InterfaceProof;
    let original = InterfaceProof {
        index: 41,
        luid: 4100,
        guid: [41; 16],
    };
    let foreign = InterfaceProof {
        index: 41,
        luid: 4100,
        guid: [42; 16],
    };
    compare_execution_member_binding(Some(original), Some(original), None).unwrap();
    compare_execution_member_binding(None, Some(original), Some(original)).unwrap();
    compare_execution_member_binding(None, None, None).unwrap();
    for (live, bound, closed) in [
        (Some(original), Some(original), Some(original)),
        (Some(original), None, Some(original)),
        (Some(original), Some(foreign), None),
        (None, Some(original), None),
        (None, None, Some(original)),
        (None, Some(original), Some(foreign)),
    ] {
        assert!(compare_execution_member_binding(live, bound, closed).is_err());
    }
}

#[test]
fn rebind_pending_storage_epoch_cannot_admit_socket_alias_or_rearm_after_denial() {
    let serial = ActorSerial::default();
    let pending = Cell::new(false);
    assert_eq!(
        execution_forward_call(&serial, &pending, || Ok(17)).unwrap(),
        17
    );
    pending.set(true);
    assert!(execution_forward_call::<()>(&serial, &pending, || panic!(
        "no IO before actual completion"
    ))
    .is_err());
    assert!(serial.revoked.get());
    pending.set(false); // even a cleared/replaced completion fact is no revival.
    assert!(execution_forward_call(&serial, &pending, || Ok(18)).is_err());
    assert_eq!(serial.run(true, || Ok(19)).unwrap(), 19); // factual cleanup only.
    assert!(execution_forward_call(&serial, &pending, || Ok(20)).is_err());
}

#[test]
fn rebind_seal_requires_actual_retention_and_whole_call_success() {
    let mut slot = RebindProofSlot::default();
    let actual = Rc::new(Cell::new(4));
    slot.begin().unwrap();
    slot.seal(|slot| {
        slot.retain(actual.clone())?;
        assert!(Rc::ptr_eq(slot.original.as_ref().unwrap(), &actual));
        assert!(!slot.sealed);
        actual.set(5);
        Ok(())
    })
    .unwrap();
    assert!(slot.active);
    assert!(slot.sealed);
    assert!(slot.begin().is_err());
    assert!(slot.retain(Rc::new(Cell::new(5))).is_err());
    let value = slot
        .complete(|original| {
            assert!(Rc::ptr_eq(original, &actual));
            Ok(original.get())
        })
        .unwrap();
    assert_eq!(value, 5);
    assert!(!slot.active);
    assert!(slot.original.is_none());
    assert!(slot.complete(|_| Ok(())).is_err());
    slot.begin().unwrap(); // distinct next cycle only after exact completion.
    assert!(slot.seal(|_| Ok(())).is_err()); // no original is NOT a receipt.
}

#[test]
fn rebind_seal_failed_postflight_and_unwind_retain_without_retry() {
    for unwind in [false, true] {
        let actual = Rc::new(Cell::new(9));
        let mut slot = RebindProofSlot::default();
        slot.begin().unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| {
            slot.seal(|slot| {
                slot.retain(actual.clone())?;
                if unwind {
                    panic!("real outer postflight unwind");
                }
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "outer postflight",
                ))
            })
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert_eq!(
                result.unwrap().unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        assert!(Rc::ptr_eq(slot.original.as_ref().unwrap(), &actual));
        assert!(!slot.sealed);
        assert!(slot.begin().is_err());
        assert!(slot.seal(|_| panic!("no retry")).is_err());
        assert!(slot
            .complete::<()>(|_| panic!("no unsealed completion"))
            .is_err());
    }
}

#[test]
fn rebind_completion_failed_postflight_keeps_original_and_blocks_next_cycle() {
    let actual = Rc::new(Cell::new(13));
    let mut slot = RebindProofSlot::default();
    slot.begin().unwrap();
    slot.seal(|slot| slot.retain(actual.clone())).unwrap();
    assert!(slot
        .complete::<()>(|original| {
            assert!(Rc::ptr_eq(original, &actual));
            Err(io::Error::other("next ACK postflight"))
        })
        .is_err());
    assert!(Rc::ptr_eq(slot.original.as_ref().unwrap(), &actual));
    assert!(slot.active);
    assert!(slot.begin().is_err());
    assert!(slot.complete::<()>(|_| panic!("no equal retry")).is_err());
}

#[test]
fn actor_terminal_cut_retains_same_original_before_failed_handoff_and_denies_retry() {
    let mut transfer = ActorResourceTransfer::default();
    let mut destination = None;
    let actual = Rc::new(Cell::new(7));
    let original = actual.clone();
    let error = transfer
        .capture(
            &mut destination,
            || original,
            |retained| {
                assert!(Rc::ptr_eq(retained.as_ref(), &actual));
                retained.set(8);
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "actual handoff denied",
                ))
            },
        )
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    let retained = destination.as_ref().unwrap();
    assert!(Rc::ptr_eq(retained, transfer.retained().unwrap()));
    assert!(Rc::ptr_eq(retained.as_ref(), &actual));
    assert_eq!(actual.get(), 8);
    assert!(transfer.finish_release(retained).is_err());
    assert!(transfer
        .capture(
            &mut destination,
            || panic!("no new/equal original"),
            |_| panic!("no retry")
        )
        .is_err());
}

#[test]
fn actor_terminal_cut_unwind_keeps_original_and_occupied_destination_never_builds() {
    let mut transfer = ActorResourceTransfer::default();
    let mut destination = None;
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _ = transfer.capture(
            &mut destination,
            || Cell::new(11),
            |_| panic!("handoff unwind"),
        );
    }))
    .is_err());
    let retained = destination.as_ref().unwrap();
    assert_eq!(retained.get(), 11);
    assert!(Rc::ptr_eq(retained, transfer.retained().unwrap()));
    assert!(transfer.finish_release(retained).is_err());
    let mut other = ActorResourceTransfer::default();
    let foreign = Rc::new(Cell::new(11));
    let mut occupied = Some(foreign.clone());
    assert!(other
        .capture(
            &mut occupied,
            || panic!("must leave source fields untouched"),
            |_| panic!("must not replace root")
        )
        .is_err());
    assert!(Rc::ptr_eq(occupied.as_ref().unwrap(), &foreign));
    assert!(other.retained().is_err());
}

#[test]
fn actor_terminal_cut_unknown_drop_retains_until_exact_private_release() {
    struct Tracked(Rc<Cell<u32>>);
    impl Drop for Tracked {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let dropped = Rc::new(Cell::new(0));
    let mut transfer = ActorResourceTransfer::default();
    let mut destination = None;
    transfer
        .capture(&mut destination, || Tracked(dropped.clone()), |_| Ok(()))
        .unwrap();
    let retained = destination.take().unwrap();
    let foreign = Rc::new(Tracked(dropped.clone()));
    assert!(transfer.finish_release(&foreign).is_err());
    assert!(Rc::ptr_eq(transfer.retained().unwrap(), &retained));
    transfer.finish_release(&retained).unwrap();
    drop(transfer);
    assert_eq!(dropped.get(), 0);
    drop(retained);
    assert_eq!(dropped.get(), 1);
    drop(foreign);
    assert_eq!(dropped.get(), 2);

    let mut unknown = ActorResourceTransfer::default();
    let mut destination = None;
    unknown
        .capture(
            &mut destination,
            || Tracked(dropped.clone()),
            |_| Err(conflict()),
        )
        .unwrap_err();
    drop(destination);
    drop(unknown);
    assert_eq!(dropped.get(), 2); // unknown ownership was retained, not destroyed
}

// Break: last factual Rc destruction is not a terminal native release ACK.
#[test]
fn actor_terminal_parts_unknown_last_alias_does_not_destroy_originals() {
    struct Tracked(Rc<Cell<u32>>);
    impl Drop for Tracked {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let destroyed = Rc::new(Cell::new(0));
    let actual = Rc::new(ActorTerminalParts::new(Tracked(destroyed.clone())));
    let alias = actual.clone();
    drop(actual);
    assert_eq!(destroyed.get(), 0);
    drop(alias);
    assert_eq!(destroyed.get(), 0);
}

#[test]
fn actor_terminal_parts_failed_or_unwound_handoff_keeps_actual_payload() {
    struct Tracked(Rc<Cell<u32>>);
    impl Drop for Tracked {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    for unwind in [false, true] {
        let destroyed = Rc::new(Cell::new(0));
        let mut original = ActorResourceTransfer::default();
        let mut caller = None;
        let result = catch_unwind(AssertUnwindSafe(|| {
            original.capture(
                &mut caller,
                || ActorTerminalParts::new(Tracked(destroyed.clone())),
                |_| {
                    if unwind {
                        panic!("actual root handoff postflight");
                    } else {
                        Err(conflict())
                    }
                },
            )
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        let retained = caller.as_ref().unwrap().clone();
        assert!(Rc::ptr_eq(original.retained().unwrap(), &retained));
        drop(caller);
        drop(original);
        drop(retained);
        assert_eq!(destroyed.get(), 0);
    }
}

#[test]
fn actor_terminal_parts_destroy_only_after_successful_whole_ack_check() {
    struct Tracked(Rc<Cell<u32>>);
    impl Drop for Tracked {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let destroyed = Rc::new(Cell::new(0));
    let original = Rc::new(ActorTerminalParts::new(Tracked(destroyed.clone())));
    let outside = original.clone();
    original
        .release_with(|| {
            assert_eq!(destroyed.get(), 0);
            Ok(())
        })
        .unwrap();
    assert_eq!(destroyed.get(), 1);
    assert!(outside.try_borrow().is_err());
    assert!(outside
        .release_with(|| panic!("duplicate destruction"))
        .is_err());
    drop(original);
    drop(outside);
    assert_eq!(destroyed.get(), 1);
}

#[test]
fn actor_terminal_parts_failed_unwound_or_swallowed_reentry_never_release() {
    struct Tracked(Rc<Cell<u32>>);
    impl Drop for Tracked {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    for fault in 0..3 {
        let destroyed = Rc::new(Cell::new(0));
        let original = ActorTerminalParts::new(Tracked(destroyed.clone()));
        let result = catch_unwind(AssertUnwindSafe(|| {
            original.release_with(|| match fault {
                0 => Err(conflict()),
                1 => panic!("real ACK but lost postflight"),
                _ => {
                    assert!(original.release_with(|| Ok(())).is_err());
                    Ok(())
                }
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert_eq!(destroyed.get(), 0);
        assert!(original.try_borrow().is_ok());
        assert!(original
            .release_with(|| panic!("no equal retry/rearm"))
            .is_err());
        drop(original);
        assert_eq!(destroyed.get(), 0);
    }
}

#[test]
fn actor_terminal_parts_swallowed_borrow_failure_cannot_authorize_outer_destruction() {
    struct Tracked(Rc<Cell<u32>>);
    impl Drop for Tracked {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let destroyed = Rc::new(Cell::new(0));
    let original = ActorTerminalParts::new(Tracked(destroyed.clone()));
    assert!(original
        .release_with(|| {
            let exclusive = original.try_borrow_mut()?;
            assert!(original.try_borrow().is_err()); // provider swallows failed read
            drop(exclusive);
            Ok(())
        })
        .is_err());
    assert!(original.try_borrow().is_ok()); // cleanup facts survive
    assert_eq!(destroyed.get(), 0);
    drop(original);
    assert_eq!(destroyed.get(), 0);
}

mod unload_protocol {
    use super::*;

    struct Tracked(Rc<Cell<u32>>);
    impl Drop for Tracked {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    // External unload boundary only. Actual production uses the opaque
    // NativeModuleReleased and mandatory real gate, not this test token.
    struct BoundaryAck(Rc<()>);

    #[test]
    fn retained_ack_before_failed_or_unwound_postflight_never_destroys_originals() {
        for unwind in [false, true] {
            let sequence = ActorUnloadSequence::default();
            let destroyed = Rc::new(Cell::new(0));
            let parts = ActorTerminalParts::new(Tracked(destroyed.clone()));
            let original = Rc::new(());
            let mut ack = None;
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                sequence.run(
                    &mut ack,
                    &mut (),
                    |_| Ok(()),
                    |retained| {
                        *retained = Some(BoundaryAck(original.clone()));
                        if unwind {
                            panic!("actual ACK retained, supervised postflight unwound");
                        }
                        Err(conflict())
                    },
                    |_, _| parts.release_with(|| Ok(())),
                )
            }));
            assert!(outcome.is_err() || outcome.unwrap().is_err());
            assert!(Rc::ptr_eq(&ack.as_ref().unwrap().0, &original));
            assert!(sequence.verify_release().is_err());
            assert!(sequence
                .run(
                    &mut None::<BoundaryAck>,
                    &mut (),
                    |_| panic!("no retry with an equal/replacement slot"),
                    |_| panic!("no second unload"),
                    |_, _| panic!("no destruction"),
                )
                .is_err());
            assert!(parts.try_borrow().is_ok());
            drop(parts);
            assert_eq!(destroyed.get(), 0);
        }
    }

    // Break: an attempted inner release/unload error swallowed by the real
    // provider must taint the outer one-shot, even if its postflight returns Ok.
    #[test]
    fn swallowed_reentry_cannot_approve_outer_destruction() {
        for inner_release in [false, true] {
            let sequence = ActorUnloadSequence::default();
            let destroyed = Rc::new(Cell::new(0));
            let parts = ActorTerminalParts::new(Tracked(destroyed.clone()));
            let mut ack = None;
            assert!(sequence
                .run(
                    &mut ack,
                    &mut (),
                    |_| Ok(()),
                    |retained| {
                        *retained = Some(BoundaryAck(Rc::new(())));
                        if inner_release {
                            assert!(sequence.verify_release().is_err());
                        } else {
                            assert!(sequence
                                .run(
                                    &mut None::<BoundaryAck>,
                                    &mut (),
                                    |_| panic!("reentry preflight"),
                                    |_| panic!("reentry unload"),
                                    |_, _| panic!("reentry destruction"),
                                )
                                .is_err());
                        }
                        Ok(())
                    },
                    |_, _| parts.release_with(|| Ok(())),
                )
                .is_err());
            assert!(ack.is_some()); // real factual receipt is not discarded
            assert!(sequence.verify_release().is_err());
            assert!(parts.try_borrow().is_ok());
            drop(parts);
            assert_eq!(destroyed.get(), 0);
        }
    }

    #[test]
    fn occupied_slot_and_failed_preflight_never_enter_native_boundary() {
        for occupied in [false, true] {
            let sequence = ActorUnloadSequence::default();
            let original = Rc::new(());
            let mut ack = occupied.then(|| BoundaryAck(original.clone()));
            assert!(sequence
                .run(
                    &mut ack,
                    &mut (),
                    |_| Err(conflict()),
                    |_| panic!("must not unload on incomplete/wrong original cut"),
                    |_, _| panic!("must not destroy"),
                )
                .is_err());
            if occupied {
                assert!(Rc::ptr_eq(&ack.as_ref().unwrap().0, &original));
            } else {
                assert!(ack.is_none());
            }
            assert!(sequence.verify_release().is_err());
        }
    }

    #[test]
    fn successful_boundary_without_ack_cannot_release_or_retry() {
        let sequence = ActorUnloadSequence::default();
        assert!(sequence
            .run(
                &mut None::<BoundaryAck>,
                &mut (),
                |_| Ok(()),
                |_| Ok(()),
                |_, _| panic!("success result is not a retained actual receipt"),
            )
            .is_err());
        assert!(sequence.verify_release().is_err());
    }

    #[test]
    fn swallowed_preflight_reentry_cannot_enter_unload() {
        let sequence = ActorUnloadSequence::default();
        let mut ack = None::<BoundaryAck>;
        assert!(sequence
            .run(
                &mut ack,
                &mut (),
                |_| {
                    assert!(sequence
                        .run(
                            &mut None::<BoundaryAck>,
                            &mut (),
                            |_| panic!("inner preflight"),
                            |_| panic!("inner unload"),
                            |_, _| panic!("inner release"),
                        )
                        .is_err());
                    Ok(())
                },
                |_| panic!("must not unload after swallowed preflight failure"),
                |_, _| panic!("must not dispose originals"),
            )
            .is_err());
        assert!(ack.is_none());
        assert!(sequence.verify_release().is_err());
    }

    #[test]
    fn failed_or_unwound_final_ack_check_retains_original_receipt_and_payload() {
        for unwind in [false, true] {
            let sequence = ActorUnloadSequence::default();
            let destroyed = Rc::new(Cell::new(0));
            let parts = ActorTerminalParts::new(Tracked(destroyed.clone()));
            let original = Rc::new(());
            let mut ack = None;
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                sequence.run(
                    &mut ack,
                    &mut (),
                    |_| Ok(()),
                    |retained| {
                        *retained = Some(BoundaryAck(original.clone()));
                        Ok(())
                    },
                    |_, retained| {
                        assert!(Rc::ptr_eq(&retained.0, &original));
                        parts.release_with(|| {
                            if unwind {
                                panic!(
                                    "whole native call succeeded, final original ACK check unwound"
                                );
                            }
                            Err(conflict())
                        })
                    },
                )
            }));
            assert!(outcome.is_err() || outcome.unwrap().is_err());
            assert!(Rc::ptr_eq(&ack.as_ref().unwrap().0, &original));
            assert!(sequence.verify_release().is_err());
            assert!(parts.try_borrow().is_ok());
            assert!(parts
                .release_with(|| panic!("no final equal retry"))
                .is_err());
            drop(parts);
            assert_eq!(destroyed.get(), 0);
        }
    }

    #[test]
    fn whole_success_disposes_same_payload_only_after_retained_ack_postflight() {
        let sequence = ActorUnloadSequence::default();
        let destroyed = Rc::new(Cell::new(0));
        let parts = ActorTerminalParts::new(Tracked(destroyed.clone()));
        let postflight = Cell::new(false);
        let original = Rc::new(());
        let mut ack = None;
        sequence
            .run(
                &mut ack,
                &mut (),
                |_| {
                    assert!(parts.try_borrow().is_ok());
                    Ok(())
                },
                |retained| {
                    *retained = Some(BoundaryAck(original.clone()));
                    assert!(parts.try_borrow().is_ok());
                    assert_eq!(destroyed.get(), 0);
                    postflight.set(true);
                    Ok(())
                },
                |_, retained| {
                    sequence.verify_release()?;
                    assert!(Rc::ptr_eq(&retained.0, &original));
                    assert!(postflight.get());
                    parts.release_with(|| Ok(()))
                },
            )
            .unwrap();
        assert_eq!(destroyed.get(), 1);
        assert!(parts.try_borrow().is_err());
        assert!(ack.is_some());
        assert!(sequence
            .run(
                &mut None::<BoundaryAck>,
                &mut (),
                |_| panic!("duplicate"),
                |_| panic!("duplicate"),
                |_, _| panic!("duplicate"),
            )
            .is_err());
        drop(parts);
        assert_eq!(destroyed.get(), 1);
    }
}

mod coordinator_originals {
    use super::*;

    struct Original {
        identity: Rc<()>,
        dropped: Rc<Cell<u32>>,
    }
    impl Drop for Original {
        fn drop(&mut self) {
            self.dropped.set(self.dropped.get() + 1);
        }
    }

    // Break: disposing the last shell alias cannot release the original J
    // while native terminal G/ACK remain unknown, even though I retains itself.
    #[test]
    fn unknown_shell_drop_retains_actual_io_and_journal_together() {
        let io_dropped = Rc::new(Cell::new(0));
        let journal_dropped = Rc::new(Cell::new(0));
        let original_journal = Rc::new(());
        let history = Rc::new(());
        let root = ActorRootOriginals::new(
            Original {
                identity: Rc::new(()),
                dropped: io_dropped.clone(),
            },
            Some(Original {
                identity: original_journal.clone(),
                dropped: journal_dropped.clone(),
            }),
            Some(history.clone()),
        );
        root.inspect_journal(|actual| {
            assert!(Rc::ptr_eq(&actual.unwrap().identity, &original_journal));
            Ok(())
        })
        .unwrap();
        assert!(Rc::ptr_eq(root.coordinator.as_ref().unwrap(), &history));
        drop(root);
        assert_eq!(io_dropped.get(), 0);
        assert_eq!(journal_dropped.get(), 0);
    }

    #[test]
    fn callback_error_or_unwind_keeps_same_originals_before_any_postflight() {
        for unwind in [false, true] {
            let io_dropped = Rc::new(Cell::new(0));
            let journal_dropped = Rc::new(Cell::new(0));
            let original_io = Rc::new(());
            let original_journal = Rc::new(());
            let history = Rc::new(());
            let mut transfer = ActorResourceTransfer::default();
            let mut caller = None;
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                transfer.capture(
                    &mut caller,
                    || {
                        ActorRootOriginals::new(
                            Original {
                                identity: original_io.clone(),
                                dropped: io_dropped.clone(),
                            },
                            Some(Original {
                                identity: original_journal.clone(),
                                dropped: journal_dropped.clone(),
                            }),
                            Some(history.clone()),
                        )
                    },
                    |root| {
                        assert!(Rc::ptr_eq(&root.actor.try_borrow()?.identity, &original_io));
                        root.inspect_journal(|actual| {
                            assert!(Rc::ptr_eq(&actual.unwrap().identity, &original_journal));
                            Ok(())
                        })?;
                        assert!(Rc::ptr_eq(root.coordinator.as_ref().unwrap(), &history));
                        if unwind {
                            panic!("canonical/T/G postflight");
                        }
                        Err(conflict())
                    },
                )
            }));
            assert!(outcome.is_err() || outcome.unwrap().is_err());
            let retained = caller.as_ref().unwrap().clone();
            assert!(Rc::ptr_eq(transfer.retained().unwrap(), &retained));
            assert!(retained.actor.try_borrow().is_ok());
            retained
                .inspect_journal(|actual| {
                    assert!(Rc::ptr_eq(&actual.unwrap().identity, &original_journal));
                    Ok(())
                })
                .unwrap();
            drop(caller);
            drop(transfer);
            drop(retained);
            assert_eq!(io_dropped.get(), 0);
            assert_eq!(journal_dropped.get(), 0);
        }
    }
}

#[test]
fn native_health_requires_nonfuture_fresh_handshake_and_keeps_only_unicast_counts() {
    let mut metrics = nelomai_client_tunnel::TunnelMetrics::default();
    for (stamp, fresh) in [
        (None, false),
        (Some(0), false),
        (Some(1), false),
        (Some(20_000), true),
        (Some(200_000), true),
        (Some(200_001), false),
    ] {
        metrics.latest_handshake_epoch_millis = stamp;
        let actual = native_health(&metrics, 13, 17, 200_000);
        assert_eq!(actual.handshake_fresh, fresh, "stamp {stamp:?}");
        assert_eq!((actual.tx_packets, actual.rx_data_packets), (13, 17));
        assert!(actual.admitted);
        assert!(!actual.closed);
    }
}

#[test]
fn metrics_start_fence_comes_from_retained_process_filetime_not_filetime_epoch() {
    assert_eq!(process_birth_ms(116_444_736_123_456_789).unwrap(), 12_345);
    assert!(process_birth_ms(0).is_err());
    assert!(process_birth_ms(116_444_735_999_999_999).is_err());
}

#[test]
fn readonly_plan_can_compare_permitted_guard_but_never_enables_mutation_planning() {
    network_plan_channel(true, false, NetworkPlanUse::ReadOnly).unwrap();
    network_plan_channel(true, true, NetworkPlanUse::ReadOnly).unwrap();
    for (permits, pending) in [(true, false), (false, true), (true, true)] {
        assert!(network_plan_channel(permits, pending, NetworkPlanUse::BeforeMutation).is_err());
    }
    network_plan_channel(false, false, NetworkPlanUse::BeforeMutation).unwrap();
}

#[test]
fn close_boundary_uses_actual_root_capture_even_when_registration_postflight_failed() {
    use crate::member_carrier::CarrierError;
    #[cfg(not(windows))]
    use crate::member_carrier_coordinator::OriginalReadCapture;
    #[cfg(windows)]
    use crate::windows::member_carrier_coordinator::OriginalReadCapture;
    let root = OriginalReadCapture::new(Rc::new(Cell::new(false)));
    assert!(retired_at_boundary(8, root.pin()).unwrap().is_none());
    assert!(retired_at_boundary(9, root.pin()).is_err());
    assert!(retired_at_boundary::<()>(8, Err(CarrierError::Retired)).is_err());
    let actual = Rc::new(());
    assert!(root
        .capture(actual.clone(), |_| Err(CarrierError::Conflict))
        .is_err());
    for stage in [8, 9, 10, 12] {
        let retained = retired_at_boundary(stage, root.pin()).unwrap().unwrap();
        assert!(Rc::ptr_eq(&retained, &actual));
    }
    // No successful cleanup or registration is manufactured by the getter.
    assert!(root.require_registered().is_err());
}

#[test]
fn owned_network_sample_detects_pending_drift_without_borrowing_original_facts() {
    #[cfg(not(windows))]
    use crate::member_carrier_network::RouteFact;
    #[cfg(windows)]
    use crate::windows::member_carrier_network::RouteFact;
    let (_, row, dns) = network_ack_fixture();
    let mut facts = RouteFacts {
        current: vec![RouteFact {
            expected: row.route.clone(),
            actual: Some(row.clone()),
        }],
        pending: None,
        carrier_rows: vec![],
        egress_rows: [vec![], vec![]],
        active: Some(nelomai_client_tunnel::redundancy::Slot::A),
        pending_active: None,
        stopping: false,
    };
    let before = network_sample(&facts, &dns, Some(&[1, 2, 3]));
    facts.pending = Some(vec![RouteFact {
        expected: row.route.clone(),
        actual: None,
    }]);
    assert_ne!(network_sample(&facts, &dns, Some(&[1, 2, 3])), before);
    assert_eq!(before.current[0].1.as_ref().unwrap(), &row);
    assert!(before.pending.is_none());
}

#[test]
fn owned_network_sample_keeps_full_sdk_metadata_dns_and_protected_bytes() {
    #[cfg(not(windows))]
    use crate::member_carrier_network::RouteFact;
    #[cfg(windows)]
    use crate::windows::member_carrier_network::RouteFact;
    let (_, row, dns) = network_ack_fixture();
    let mut facts = RouteFacts {
        current: vec![RouteFact {
            expected: row.route.clone(),
            actual: Some(row.clone()),
        }],
        pending: None,
        carrier_rows: vec![],
        egress_rows: [vec![], vec![]],
        active: Some(nelomai_client_tunnel::redundancy::Slot::A),
        pending_active: None,
        stopping: false,
    };
    let before = network_sample(&facts, &dns, Some(&[1, 2, 3]));
    assert_ne!(network_sample(&facts, &dns, Some(&[1, 2, 4])), before);
    assert_ne!(network_sample(&facts, &dns, None), before);
    let mut changed_dns = dns.clone();
    changed_dns.settings.domain = Some("different".into());
    assert_ne!(
        network_sample(&facts, &changed_dns, Some(&[1, 2, 3])),
        before
    );
    for field in 0..6 {
        match field {
            0 => facts.current[0].actual.as_mut().unwrap().luid += 1,
            1 => facts.carrier_rows.push(row.clone()),
            2 => facts.egress_rows[1].push(row.clone()),
            3 => facts.active = Some(nelomai_client_tunnel::redundancy::Slot::B),
            4 => facts.pending_active = Some(nelomai_client_tunnel::redundancy::Slot::B),
            _ => facts.stopping = true,
        }
        assert_ne!(network_sample(&facts, &dns, Some(&[1, 2, 3])), before);
        match field {
            0 => facts.current[0].actual.as_mut().unwrap().luid -= 1,
            1 => facts.carrier_rows.clear(),
            2 => facts.egress_rows[1].clear(),
            3 => facts.active = Some(nelomai_client_tunnel::redundancy::Slot::A),
            4 => facts.pending_active = None,
            _ => facts.stopping = false,
        }
    }
    drop(facts);
    assert_eq!(before.current[0].1.as_ref().unwrap(), &row);
    assert_eq!(before.protected_record, Some(vec![1, 2, 3]));
}

fn closing_record() -> crate::member_carrier_pair::Record {
    use crate::member_carrier_pair::{Effect, Phase, Record};
    use nelomai_client_tunnel::redundancy::Slot;
    let (guard, _) = guard_creation();
    let scope = guard.expected.scope;
    let record = Record {
        version: 2,
        revision: 11,
        phase: Phase::Closing,
        provenance: crate::member_carrier::Provenance {
            boot_id: [8; 16],
            network_epoch: 1,
            runtime: nelomai_contracts::dispatcher::EngineIdentity {
                slot: scope.runtime,
                runtime_version: "0.3.3".into(),
                container_version: "0.3.3".into(),
                runtime_contract_version: 1,
                manifest_sha256: "a".repeat(64),
            },
        },
        guard: crate::member_carrier_guard::Model::empty(scope.clone()).unwrap(),
        scope,
        addresses: vec![],
        dns: vec![],
        carrier: None,
        members: [None, None],
        active: None,
        options: None,
        pending_guard: None,
        pending: Some(Effect::MemberStop(Slot::A)),
        network: None,
        stop_stage: 4,
        operation: None,
    };
    record.validate().unwrap();
    record
}

// Break: Stop of the actual published C before attach selects missing full G,
// or turns that C into the disjoint no-constructor branch. This exercises the
// SAME selector used by the native actor, not a substitute coordinator.
#[test]
fn published_pregraph_carrier_cleanup_selects_retained_startup_for_each_effect() {
    use crate::member_carrier_pair::Effect;
    let mut record = closing_record();
    record.addresses = vec!["10.7.0.2/32".parse().unwrap()];
    record.options = Some(nelomai_client_tunnel::DesktopTunnelOptions::default());
    record.carrier = Some(crate::member_owner::InterfaceProof {
        guid: [3; 16],
        index: 73,
        luid: 117,
    });
    for (stage, effect) in [
        (3, Effect::RestoreWeak),
        (6, Effect::CarrierAddressDelete),
        (7, Effect::CarrierSessionEnd),
        (8, Effect::CarrierClose),
    ] {
        record.stop_stage = stage;
        record.pending = Some(effect);
        assert_eq!(
            carrier_cleanup_route(&record, effect, false).unwrap(),
            CarrierCleanupRoute::RetainedStartup
        );
        assert_eq!(
            carrier_cleanup_route(&record, effect, true).unwrap(),
            CarrierCleanupRoute::FullGraph
        );
        let mut no_c = record.clone();
        no_c.carrier = None;
        assert_eq!(
            carrier_cleanup_route(&no_c, effect, false).unwrap(),
            CarrierCleanupRoute::NoConstructorRead
        );
        for fault in 0..4 {
            let mut wrong = record.clone();
            match fault {
                0 => wrong.pending = None,
                1 => wrong.stop_stage = 12,
                2 => wrong.pending = Some(Effect::FullEmpty),
                _ => wrong.phase = crate::member_carrier_pair::Phase::Stopped,
            }
            assert!(carrier_cleanup_route(&wrong, effect, false).is_err());
        }
    }
    record.stop_stage = 11;
    record.pending = Some(Effect::RestoreKeys);
    assert!(carrier_cleanup_route(&record, Effect::RestoreKeys, false).is_err());
}

#[test]
fn published_pregraph_guard_reads_use_exact_early_closing_frames() {
    use crate::member_carrier_pair::{Effect, Phase};
    let mut record = closing_record();
    record.addresses = vec!["10.7.0.2/32".parse().unwrap()];
    record.options = Some(nelomai_client_tunnel::DesktopTunnelOptions::default());
    record.carrier = Some(crate::member_owner::InterfaceProof {
        guid: [3; 16],
        index: 73,
        luid: 117,
    });
    for (stage, effect) in [
        (0, Effect::Guard),
        (1, Effect::ReleaseProbes),
        (2, Effect::RestoreNetwork),
        (3, Effect::RestoreWeak),
        (
            4,
            Effect::MemberStop(nelomai_client_tunnel::redundancy::Slot::A),
        ),
        (
            5,
            Effect::MemberStop(nelomai_client_tunnel::redundancy::Slot::B),
        ),
        (6, Effect::CarrierAddressDelete),
        (7, Effect::CarrierSessionEnd),
        (8, Effect::CarrierClose),
    ] {
        record.stop_stage = stage;
        record.pending = Some(effect);
        require_pregraph_closing_read(&record).unwrap();
        for fault in 0..5 {
            let mut wrong = record.clone();
            match fault {
                0 => wrong.pending = None,
                1 => wrong.pending = Some(Effect::FullEmpty),
                2 => wrong.stop_stage = 10,
                3 => wrong.phase = Phase::Stopped,
                _ => wrong.carrier = None,
            }
            assert!(require_pregraph_closing_read(&wrong).is_err());
        }
    }
    for (stage, effect) in [
        (9, Effect::NativeEmpty),
        (10, Effect::Guard),
        (11, Effect::RestoreKeys),
        (12, Effect::FullEmpty),
    ] {
        record.stop_stage = stage;
        record.pending = Some(effect);
        assert!(require_pregraph_closing_read(&record).is_err());
    }
}

#[test]
fn terminal_factual_cache_advances_to_actual_stopped_and_never_back_to_forward() {
    use crate::member_carrier_pair::Phase;
    let mut closing = closing_record();
    closing.stop_stage = 12;
    closing.pending = Some(crate::member_carrier_pair::Effect::FullEmpty);
    let mut stopped = closing.clone();
    stopped.revision += 1;
    stopped.phase = Phase::Stopped;
    stopped.pending = None;
    require_terminal_record(&stopped).unwrap();
    assert!(require_terminal_record(&closing).is_err());
    cache_progress(&closing, &stopped).unwrap();
    let mut resumed = stopped.clone();
    resumed.revision += 1;
    resumed.phase = Phase::Running;
    assert!(cache_progress(&stopped, &resumed).is_err());
    assert!(cache_progress(&stopped, &closing).is_err());
    let mut extra_stopped = stopped.clone();
    extra_stopped.revision += 1;
    assert!(cache_progress(&stopped, &extra_stopped).is_err());
    // Terminal fact reads are not permission for None lateeffects.
    assert!(require_effect(&stopped, crate::member_carrier_pair::Effect::FullEmpty).is_err());
    assert!(require_effect(&stopped, crate::member_carrier_pair::Effect::CarrierClose).is_err());
}

#[test]
fn stopped_attestation_dispatches_only_full_empty_facts_not_a_pending_effect() {
    use crate::member_carrier_pair::{Effect, Phase};
    let mut record = closing_record();
    record.phase = Phase::Stopped;
    record.stop_stage = 12;
    record.pending = None;
    record.validate().unwrap();
    require_attestation(&record, Effect::FullEmpty).unwrap();
    // Dispatch is not authorization: every actual terminal read must still
    // authenticate the original terminal ACK/Calling/native-or-never ledger.
    assert!(require_effect(&record, Effect::FullEmpty).is_err());
    for effect in [
        Effect::NativeEmpty,
        Effect::Guard,
        Effect::RestoreKeys,
        Effect::CarrierClose,
        Effect::MemberStop(nelomai_client_tunnel::redundancy::Slot::A),
    ] {
        assert!(require_attestation(&record, effect).is_err());
    }
    let mut closing = record.clone();
    closing.phase = Phase::Closing;
    closing.validate().unwrap();
    assert!(require_attestation(&closing, Effect::FullEmpty).is_err());
    closing.pending = Some(Effect::FullEmpty);
    require_attestation(&closing, Effect::FullEmpty).unwrap();
    assert!(require_attestation(&closing, Effect::NativeEmpty).is_err());
}

#[test]
fn no_carrier_terminal_guard_requires_independent_full_empty_snapshot_not_missing_lookup() {
    use crate::member_carrier_pair::Phase;
    let mut record = closing_record();
    record.phase = Phase::Stopped;
    record.stop_stage = 12;
    record.pending = None;
    record.validate().unwrap();
    compare_uncaptured_terminal_guard(&record, &record.guard.expected).unwrap();
    let (_, former) = guard_creation();
    assert!(compare_uncaptured_terminal_guard(&record, &former.expected).is_err());
    let mut wrong = record.guard.expected.clone();
    wrong.version = 1;
    assert!(compare_uncaptured_terminal_guard(&record, &wrong).is_err());
    let mut wrong = record.guard.expected.clone();
    wrong.scope.connection_generation += 1;
    assert!(compare_uncaptured_terminal_guard(&record, &wrong).is_err());
    record.phase = Phase::Closing;
    record.pending = Some(crate::member_carrier_pair::Effect::FullEmpty);
    record.validate().unwrap();
    assert!(compare_uncaptured_terminal_guard(&record, &record.guard.expected).is_err());
}

#[test]
fn uncaptured_terminal_read_is_mandatory_and_cannot_rearm_forward_calls() {
    use crate::member_carrier_pair::Phase;
    let mut record = closing_record();
    record.phase = Phase::Stopped;
    record.stop_stage = 12;
    record.pending = None;
    record.validate().unwrap();
    let serial = ActorSerial::default();
    let entered = Cell::new(false);
    uncaptured_terminal_call(&serial, &record, || {
        assert!(serial.busy.get());
        assert!(serial.revoked.get());
        entered.set(true);
        Ok(())
    })
    .unwrap();
    assert!(entered.get());
    assert!(!serial.busy.get());
    assert!(serial.run(false, || Ok(())).is_err());
    let error = uncaptured_terminal_call(&serial, &record, || {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "original_ledger_denied",
        ))
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _ = uncaptured_terminal_call(&serial, &record, || panic!("terminal read unwind"));
    }))
    .is_err());
    assert!(!serial.busy.get());
    assert!(serial.run(false, || Ok(())).is_err());
    record.phase = Phase::Closing;
    record.pending = Some(crate::member_carrier_pair::Effect::FullEmpty);
    record.validate().unwrap();
    assert!(uncaptured_terminal_call(&serial, &record, || panic!(
        "Closing must not enter terminal read"
    ))
    .is_err());
}

#[test]
fn zero_effect_terminal_dispatch_accepts_fresh_stop_and_published_options_but_not_a_metadata_proof()
{
    use crate::member_carrier_pair::Phase;
    let mut fresh = closing_record();
    fresh.phase = Phase::Stopped;
    fresh.stop_stage = 12;
    fresh.pending = None;
    assert!(fresh.addresses.is_empty());
    assert!(fresh.options.is_none());
    let mut after_preflight = fresh.clone();
    after_preflight.addresses = vec!["198.18.0.1/32".parse().unwrap()];
    after_preflight.options = Some(nelomai_client_tunnel::DesktopTunnelOptions::default());
    for actual in [fresh, after_preflight] {
        let serial = ActorSerial::default();
        let proof = ZeroEffectDisposition::<u32>::default();
        assert!(uncaptured_terminal_call(&serial, &actual, || {
            proof.capture(|_| Err(io::Error::other("original Never/Stopped SDK issuer denied")))
        })
        .is_err());
        assert!(proof.sealed_proof().is_err());
        assert!(serial
            .run(false, || -> io::Result<()> { panic!("no forward rearm") })
            .is_err());
        // JSON/empty Options choose no authority; no original provider ACK was
        // retained. Early prepare/store-save loss follows this same denial.
        assert!(proof.retained_proof().is_err());
    }
}

#[test]
fn unstarted_cleanup_dispatch_requires_exact_slot_stage_and_member_stop_edge() {
    use crate::member_carrier_pair::{Effect, Phase};
    use nelomai_client_tunnel::redundancy::Slot;
    let record = closing_record();
    require_effect(&record, Effect::MemberStop(Slot::A)).unwrap();
    assert!(require_effect(&record, Effect::MemberStop(Slot::B)).is_err());
    let mut unperformed = record.clone();
    unperformed.pending = None;
    assert!(require_effect(&unperformed, Effect::MemberStop(Slot::A)).is_err());
    require_unstarted_cleanup(&record, Slot::A).unwrap();
    assert!(require_unstarted_cleanup(&record, Slot::B).is_err());
    for (phase, stage, effect) in [
        (Phase::Closing, 5, Effect::MemberStop(Slot::A)),
        (Phase::Closing, 4, Effect::MemberStop(Slot::B)),
        (Phase::Closing, 4, Effect::RestoreKeys),
        (Phase::Starting, 4, Effect::MemberStop(Slot::A)),
    ] {
        let mut wrong = record.clone();
        wrong.phase = phase;
        wrong.stop_stage = stage;
        wrong.pending = Some(effect);
        wrong.validate().unwrap(); // Semantic dispatch, not a parser rejection.
        assert!(require_unstarted_cleanup(&wrong, Slot::A).is_err());
    }
    let mut b = record.clone();
    b.stop_stage = 5;
    b.pending = Some(Effect::MemberStop(Slot::B));
    require_unstarted_cleanup(&b, Slot::B).unwrap();
}

#[test]
fn bypass_planning_preserves_original_full_physical_path_not_derived_host_route() {
    use crate::member_physical::{
        Family, InterfaceIdentity, InterfaceRecord, PhysicalProof, PhysicalSnapshot,
    };
    use nelomai_client_tunnel::redundancy::network::{RouteScope, RouteValue};
    let proof = PhysicalProof {
        identity: InterfaceIdentity {
            index: 44,
            luid: 4400,
            guid: [44; 16],
        },
        family: Family::V4,
        metric: 35,
    };
    let row = crate::member_routes::Row::static_route(
        RouteValue {
            destination: "0.0.0.0/0".parse().unwrap(),
            scope: RouteScope::WindowsInterface(44),
            interface: 44,
            gateway: Some("192.0.2.1".parse().unwrap()),
            metric: 19,
        },
        crate::member_routes::NativeProof {
            index: 44,
            luid: 4400,
        },
    );
    let physical = PhysicalSnapshot::new(
        vec![row.clone()],
        vec![InterfaceRecord {
            proof,
            alias: "Ethernet".into(),
            if_type: 6,
            tunnel_type: 0,
            oper_status: 1,
            status_flags: 1,
        }],
        &[],
    )
    .unwrap();
    let planned = physical_bypasses(
        &physical,
        &[
            "198.18.0.1/32".parse().unwrap(),
            "0.0.0.0/0".parse().unwrap(),
        ],
    )
    .unwrap();
    assert_eq!(planned.routes.len(), 2);
    assert_eq!(
        planned.routes[0].destination,
        "198.18.0.1/32".parse::<ipnet::IpNet>().unwrap()
    );
    assert_eq!(planned.retained, vec![row.route.clone()]);
    assert_eq!(planned.originals.len(), 2);
    for original in &planned.originals {
        assert_eq!(original.proof, proof);
        assert_eq!(original.row, row);
        physical.verify(original).unwrap();
    }
    // Replacing complete source rows with narrower derived routes cannot pass
    // the independent physical snapshot's exact original-path comparison.
    let mut substituted = planned.originals[0].clone();
    substituted.row.route = planned.routes[0].clone();
    assert!(physical.verify(&substituted).is_err());
}

#[test]
fn upgrade_registration_never_consumes_a_gate_at_pending_none_or_retries_failure() {
    let registration = UpgradeRegistration::default();
    let transfers = Cell::new(0);
    assert!(registration
        .run(false, || {
            transfers.set(transfers.get() + 1);
            Ok(())
        })
        .is_err());
    assert_eq!(transfers.get(), 0);
    // An ineligible entry is itself a failed registration, not a later retry.
    assert!(registration.run(true, || Ok(())).is_err());

    for unwind in [false, true] {
        let registration = UpgradeRegistration::default();
        let root = Rc::new(Cell::new(3));
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            registration.run(true, || {
                root.set(4); // Original input remains rooted before postflight.
                if unwind {
                    panic!("original upgrade postflight");
                }
                Err(conflict())
            })
        }));
        assert!(outcome.is_err() || outcome.unwrap().is_err());
        assert_eq!(root.get(), 4);
        assert!(registration
            .run(true, || {
                root.set(5);
                Ok(())
            })
            .is_err());
        assert_eq!(root.get(), 4);
    }
}

#[test]
fn upgrade_registration_transfers_once_and_is_not_later_effect_permission() {
    let registration = UpgradeRegistration::default();
    let transfers = Cell::new(0);
    registration
        .run(true, || {
            transfers.set(transfers.get() + 1);
            Ok(())
        })
        .unwrap();
    registration
        .run(true, || {
            transfers.set(transfers.get() + 1);
            Ok(())
        })
        .unwrap();
    assert_eq!(transfers.get(), 1);
    // Successful registration cannot clear the independently sticky actor
    // fence or manufacture permission to use the gate after a failed effect.
    let serial = ActorSerial::default();
    assert!(serial.run(false, || Err::<(), _>(conflict())).is_err());
    assert!(serial
        .run(false, || registration.run(true, || Ok(())))
        .is_err());
    assert_eq!(transfers.get(), 1);
}

fn network_ack_fixture() -> (
    crate::member_carrier_pair::NetworkSnapshot,
    crate::member_routes::Row,
    crate::member_dns::Snapshot,
) {
    use crate::member_dns as d;
    let (plan, _) = guard_creation();
    let scope = plan.expected.scope;
    let dns = d::Snapshot {
        interface: d::OwnedInterface {
            scope,
            guid: [33; 16],
            luid: 3300,
            index: 33,
        },
        settings: d::Settings {
            version: 1,
            flags: 0,
            domain: None,
            name_server: None,
            search_list: None,
            registration_enabled: 0,
            register_adapter_name: 0,
            enable_llmnr: 0,
            query_adapter_name: 0,
            profile_name_server: None,
        },
    };
    let row = crate::member_routes::Row::static_route(
        nelomai_client_tunnel::redundancy::network::RouteValue {
            destination: "0.0.0.0/1".parse().unwrap(),
            scope: nelomai_client_tunnel::redundancy::network::RouteScope::WindowsInterface(11),
            interface: 11,
            gateway: None,
            metric: 0,
        },
        crate::member_routes::NativeProof {
            index: 11,
            luid: 1100,
        },
    );
    (
        crate::member_carrier_pair::NetworkSnapshot {
            routes: vec![row.route.clone()],
            dns: Some(dns.clone()),
        },
        row,
        dns,
    )
}

#[test]
fn network_ack_unknown_dns_attempt_is_not_never_exchanged_or_restored() {
    let (expected, row, dns) = network_ack_fixture();
    let attempts = vec![RouteAttempt {
        row: row.clone(),
        deleting: false,
        acknowledged: true,
    }];
    assert!(compare_network_ack(
        &expected,
        &[row.clone()],
        &dns,
        &dns,
        &attempts,
        &(0, vec![])
    )
    .is_ok());
    assert!(compare_network_ack(
        &expected,
        &[row.clone()],
        &dns,
        &dns,
        &attempts,
        &(1, vec![])
    )
    .is_err());
    assert!(compare_network_ack(
        &expected,
        &[row.clone()],
        &dns,
        &dns,
        &attempts,
        &(1, vec![dns.clone()])
    )
    .is_ok());
    let mut changed = dns.clone();
    changed.settings.domain = Some("foreign".into());
    assert!(compare_network_ack(
        &expected,
        &[row],
        &changed,
        &dns,
        &attempts,
        &(1, vec![dns.clone()])
    )
    .is_err());
}

#[test]
fn network_ack_requires_exact_full_original_sdk_row_not_equal_route_value() {
    let (expected, row, dns) = network_ack_fixture();
    let ack = RouteAttempt {
        row: row.clone(),
        deleting: false,
        acknowledged: true,
    };
    for mutation in 0..3 {
        let mut foreign = row.clone();
        match mutation {
            0 => foreign.luid += 1,
            1 => foreign.protocol += 1,
            _ => foreign.valid_lifetime -= 1,
        }
        assert!(compare_network_ack(
            &expected,
            &[foreign],
            &dns,
            &dns,
            &[ack.clone()],
            &(0, vec![])
        )
        .is_err());
    }
    let mut unknown = ack.clone();
    unknown.acknowledged = false;
    assert!(compare_network_ack(
        &expected,
        &[row.clone()],
        &dns,
        &dns,
        &[unknown],
        &(0, vec![])
    )
    .is_err());
    let mut deleted = ack;
    deleted.deleting = true;
    assert!(compare_network_ack(
        &expected,
        &[row.clone()],
        &dns,
        &dns,
        &[deleted],
        &(0, vec![])
    )
    .is_err());
    assert!(compare_network_ack(
        &expected,
        &[row.clone(), row],
        &dns,
        &dns,
        &[],
        &(0, vec![])
    )
    .is_err());
}

#[test]
fn cold_full_capture_keeps_first_original_and_rejects_equal_replacement() {
    let original = Rc::new(17);
    let equal_foreign = Rc::new(17);
    let mut slot = None;
    let mut rejected = Vec::new();
    let mut attempted = false;
    capture_once(&mut slot, &mut rejected, &mut attempted, original.clone()).unwrap();
    assert!(Rc::ptr_eq(slot.as_ref().unwrap(), &original));
    assert!(capture_once(
        &mut slot,
        &mut rejected,
        &mut attempted,
        equal_foreign.clone()
    )
    .is_err());
    assert!(Rc::ptr_eq(slot.as_ref().unwrap(), &original));
    assert!(Rc::ptr_eq(&rejected[0], &equal_foreign));
    assert!(capture_once(&mut slot, &mut rejected, &mut attempted, original.clone()).is_err());
    assert_eq!(rejected.len(), 2);
}

#[test]
fn cold_full_capture_roots_actual_input_before_error_or_unwind_and_never_rearms() {
    for unwind in [false, true] {
        let serial = ActorSerial::default();
        let original = Rc::new(Cell::new(7));
        let weak = Rc::downgrade(&original);
        let mut slot = None;
        let mut rejected = Vec::new();
        let mut attempted = false;
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            serial.run(false, || {
                capture_once(&mut slot, &mut rejected, &mut attempted, original.clone())?;
                assert!(Rc::ptr_eq(slot.as_ref().unwrap(), &original));
                slot.as_ref().unwrap().set(8);
                if unwind {
                    panic!("actual captured root postflight");
                }
                Err::<(), _>(conflict())
            })
        }));
        assert!(outcome.is_err() || outcome.unwrap().is_err());
        assert_eq!(weak.upgrade().unwrap().get(), 8);
        assert!(serial.run(false, || Ok(())).is_err());
        serial
            .run(true, || {
                assert!(Rc::ptr_eq(slot.as_ref().unwrap(), &original));
                Ok(())
            })
            .unwrap();
        assert!(serial.run(false, || Ok(())).is_err());
    }
}

fn guard_creation() -> (
    crate::member_carrier_guard::ExchangePlan,
    crate::member_carrier_guard::Model,
) {
    use crate::{member_carrier_guard as g, member_owner::InterfaceProof};
    let scope = nelomai_client_tunnel::redundancy::SessionScope {
        runtime: nelomai_contracts::RuntimeSlot::Stable,
        runtime_generation: 1,
        session_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
        connection_generation: 2,
    };
    let id = |index: u32| g::Identity {
        scope: scope.clone(),
        proof: InterfaceProof {
            index,
            luid: u64::from(index) * 100,
            guid: [index as u8; 16],
        },
    };
    let desired = g::Model::new(
        scope.clone(),
        g::Carrier {
            identity: id(33),
            sources: vec!["10.8.0.2".parse().unwrap()],
        },
        [
            Some(g::Member {
                identity: id(11),
                probes: vec![],
            }),
            None,
        ],
        None,
    )
    .unwrap()
    .without_permits()
    .unwrap();
    let before = g::Model::empty(scope).unwrap();
    let plan = g::ExchangePlan::new(&before, &desired).unwrap();
    let mut actual = desired.expected.clone();
    actual.sublayer.as_mut().unwrap().weight = 65401;
    (plan, desired.readback_after(&before, &actual).unwrap())
}

#[test]
fn member_key_restore_requires_actual_exact_deny_all_guard_with_target_excluded() {
    use crate::member_carrier_guard::Action;
    use nelomai_client_tunnel::redundancy::Slot;
    let (_, guard) = guard_creation();
    // This exercises only the comparison precondition. No JSON/model creates
    // an original Closed receipt or key CAS permission in the native caller.
    compare_member_key_restore_guard(Slot::B, &guard, &guard.expected).unwrap();
    assert!(compare_member_key_restore_guard(Slot::A, &guard, &guard.expected).is_err());
    let mut changed = guard.expected.clone();
    changed.filters[0].action = Action::Permit;
    assert!(compare_member_key_restore_guard(Slot::B, &guard, &changed).is_err());
    let mut changed = guard.expected.clone();
    changed.filters.pop();
    assert!(compare_member_key_restore_guard(Slot::B, &guard, &changed).is_err());
    let mut changed = guard.expected.clone();
    changed.sublayer.as_mut().unwrap().weight -= 1;
    assert!(compare_member_key_restore_guard(Slot::B, &guard, &changed).is_err());
    let empty = crate::member_carrier_guard::Model::empty(guard.scope.clone()).unwrap();
    assert!(compare_member_key_restore_guard(Slot::B, &empty, &empty.expected).is_err());
}

#[test]
fn generation_projection_keeps_other_active_allows_but_requires_exact_full_guard() {
    use crate::member_carrier_guard as g;
    use nelomai_client_tunnel::redundancy::Slot;
    let (_, base) = guard_creation();
    let guard = g::Model::new(
        base.scope.clone(),
        base.carrier.clone().unwrap(),
        base.members.clone(),
        Some(Slot::A),
    )
    .unwrap()
    .inherit_sublayer_weight(&base)
    .unwrap();
    assert!(guard.permits);
    compare_member_generation_guard(Slot::B, &guard, &guard.expected).unwrap();
    assert!(compare_member_generation_guard(Slot::A, &guard, &guard.expected).is_err());
    let mut wrong = guard.expected.clone();
    wrong.filters.pop();
    assert!(compare_member_generation_guard(Slot::B, &guard, &wrong).is_err());
    let mut wrong = guard.expected.clone();
    wrong.sublayer.as_mut().unwrap().weight -= 1;
    assert!(compare_member_generation_guard(Slot::B, &guard, &wrong).is_err());
    let empty = g::Model::empty(base.scope).unwrap();
    assert!(compare_member_generation_guard(Slot::B, &empty, &empty.expected).is_err());
}

#[test]
fn guard_plan_priority_comes_from_original_exchange_ack_before_journal_postflight() {
    let (plan, ack) = guard_creation();
    let captured = guard_ack_plan(&plan, &plan.expected, &ack).unwrap();
    assert_eq!(captured.captured_sublayer_weight, Some(65401));
    assert_eq!(captured.base, ack);
    assert_eq!(captured.desired, ack);
    assert_eq!(captured.expected, plan.expected);
    captured.validate().unwrap();
}

#[test]
fn guard_plan_does_not_learn_unrelated_equal_priority_snapshot() {
    let (plan, mut ack) = guard_creation();
    ack.expected.carrier.as_mut().unwrap().identity.proof.luid += 1;
    assert!(guard_ack_plan(&plan, &plan.expected, &ack).is_err());
}

#[test]
fn network_exchange_switch_uses_target_not_still_published_old_active() {
    use crate::member_carrier_pair::Operation;
    use nelomai_client_tunnel::redundancy::Slot;
    assert_eq!(
        network_active(Some(Slot::A), Some(Operation::Switch(Slot::B))).unwrap(),
        Slot::B
    );
    assert_eq!(
        network_active(Some(Slot::B), Some(Operation::Start(Slot::A))).unwrap(),
        Slot::A
    );
}

#[test]
fn network_exchange_attach_retire_rebind_keep_actual_active_and_missing_denies() {
    use crate::member_carrier_pair::Operation;
    use nelomai_client_tunnel::redundancy::Slot;
    for operation in [
        Operation::Attach(Slot::B),
        Operation::Retire(Slot::B),
        Operation::Rebind,
    ] {
        assert_eq!(
            network_active(Some(Slot::A), Some(operation)).unwrap(),
            Slot::A
        );
        assert!(network_active(None, Some(operation)).is_err());
    }
    assert!(network_active(None, None).is_err());
}

#[test]
fn caught_reentry_cannot_finish_outer_or_release_its_serialization() {
    let root = ActorSerial::default();
    assert!(root
        .run(false, || {
            assert!(root.run(false, || Ok(())).is_err());
            assert!(root.busy.get());
            assert!(root.run(true, || Ok(())).is_err());
            Ok(())
        })
        .is_err());
    assert!(!root.busy.get());
    assert!(root.run(false, || Ok(())).is_err());
    assert!(root.run(true, || Ok(())).is_ok());
    assert!(root.run(false, || Ok(())).is_err());
}

#[test]
fn error_and_unwind_keep_actor_roots_and_allow_only_independent_cleanup() {
    for unwind in [false, true] {
        let serial = Rc::new(ActorSerial::default());
        let original = Rc::new(Cell::new(7));
        let weak = Rc::downgrade(&original);
        let alias = original.clone();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            serial.run(false, || {
                alias.set(8); // real owning root retained before injected postflight
                if unwind {
                    panic!("postflight");
                }
                Err::<(), _>(conflict())
            })
        }));
        assert!(outcome.is_err() || outcome.unwrap().is_err());
        assert_eq!(weak.upgrade().unwrap().get(), 8);
        assert!(serial.run(false, || Ok(())).is_err());
        assert!(serial
            .run(true, || {
                assert!(Rc::ptr_eq(&original, &alias));
                Ok(())
            })
            .is_ok());
        drop(alias);
        assert!(serial.run(false, || Ok(())).is_err());
    }
}

#[test]
fn cleanup_entry_even_success_is_sticky_and_does_not_invent_cleanup_success() {
    let serial = ActorSerial::default();
    assert!(serial.run(false, || Ok(())).is_ok());
    assert!(serial.run(true, || Err::<(), _>(conflict())).is_err());
    assert!(serial.run(false, || Ok(())).is_err());
    assert!(serial.run(true, || Ok(())).is_ok());
    assert!(serial.run(false, || Ok(())).is_err());
}
