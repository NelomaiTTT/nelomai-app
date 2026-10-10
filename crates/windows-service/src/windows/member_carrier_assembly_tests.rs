//! Host execution uses real PendingNativeOwnership, NativeOwnership and Keys.
//! Only private journal IO, registry effects and actual lease checks are doubles.
use super::*;
#[cfg(not(windows))]
use crate::assembly_keys as keys;
use crate::member_carrier_native_ownership::{Binding, KeyPhase, NativeValue, Role};
#[cfg(windows)]
use crate::windows::member_carrier_keys as keys;
use keys::{NativeAuthority, RegistryKernel};
use nelomai_client_tunnel::redundancy::SessionScope;
use nelomai_contracts::{dispatcher::EngineIdentity, RuntimeSlot};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    rc::Rc,
};

fn context() -> Context {
    Context {
        intent: crate::member_carrier::Intent {
            scope: SessionScope { runtime: RuntimeSlot::Stable, runtime_generation: 2,
                session_id: "11111111-1111-4111-8111-111111111111".into(), connection_generation: 3 },
            addresses: vec!["10.7.0.2/32".parse().unwrap()],
        },
        provenance: crate::member_carrier::Provenance {
            boot_id: [8; 16], network_epoch: 7,
            runtime: EngineIdentity { slot: RuntimeSlot::Stable, runtime_version: "0.3.3".into(),
                container_version: "0.3.3".into(), runtime_contract_version: 1, manifest_sha256: "a".repeat(64) },
        },
        bindings: [1u8, 2, 3].map(|id| {
            let h = format!("{id:02x}");
            let guid = format!("{}-{}-{}-{}-{}", h.repeat(4), h.repeat(2), h.repeat(2), h.repeat(2), h.repeat(6));
            Binding { role: [Role::RoleCarrier, Role::MemberA, Role::MemberB][id as usize - 1],
                guid: [id; 16], name: format!("original-{id}"),
                registry_path: format!("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{{{guid}}}") }
        }),
    }
}

struct Resource(Rc<Cell<u32>>);

#[cfg(not(windows))]
use crate::member_files::{PrivateFile, PrivateRecords, SessionFileIo};
#[cfg(not(windows))]
use crate::member_session as initial_files;
#[cfg(windows)]
use crate::windows::member_files::{PrivateFile, PrivateRecords, SessionFileIo};
#[cfg(windows)]
use crate::windows::member_session as initial_files;
use initial_files::SessionFiles;
use nelomai_client_tunnel::redundancy::driver::SessionStore;

/// Only private file IO is doubled. The claim, original store initialization,
/// execution birth, view handoff and opaque DATA pin are production objects.
#[derive(Clone, Default)]
struct InitialDataDisk(Rc<RefCell<BTreeMap<PrivateFile, Vec<u8>>>>);
impl PrivateRecords for InitialDataDisk {
    fn read(&mut self, file: PrivateFile) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.0.borrow().get(&file).cloned())
    }
    fn compare_exchange(
        &mut self,
        file: PrivateFile,
        old: Option<&[u8]>,
        new: &[u8],
    ) -> std::io::Result<()> {
        let mut disk = self.0.borrow_mut();
        if disk.get(&file).map(Vec::as_slice) != old || new.len() > file.limit() {
            return Err(std::io::Error::other("exact private CAS"));
        }
        disk.insert(file, new.to_vec());
        Ok(())
    }
}
impl SessionFileIo for InitialDataDisk {
    fn transaction<T>(
        &mut self,
        callback: impl FnOnce(&mut dyn PrivateRecords) -> std::io::Result<T>,
    ) -> std::io::Result<T> {
        callback(self)
    }
}

// Break: capture execution=None before canonical handoff, adopt equal/reopened
// ACK data, replace the first opaque pin, or lose it on binding Err/unwind.
#[test]
fn initial_data_capture_uses_actual_cleanup_identity_unborn_and_birth_bound() {
    use initial_files::{
        ProtectedSessionFiles, RecordKind, WindowsNativeCarrierReceiptStore, WindowsSessionStore,
    };
    use nelomai_client_tunnel::redundancy::{session::SessionState, Slot};
    for bound in [false, true] {
        for fault in 0..4 {
            let mut c = context();
            c.provenance.network_epoch = 1; // actual first private claim
            let disk = InitialDataDisk::default();
            let mut files = ProtectedSessionFiles::new(
                disk.clone(),
                c.provenance.runtime.clone(),
                c.provenance.boot_id,
            )
            .unwrap();
            files.claim(&c.intent.scope).unwrap();
            let (mut journal, saved) =
                WindowsNativeCarrierReceiptStore::open(files.clone(), c.clone()).unwrap();
            assert!(saved.is_none());
            let initial = Record {
                version: 2,
                context: c.clone(),
                generation: 1,
                phase: receipt::Phase::Preparing,
                native_rows: receipt::FullNativeRows::Unbound,
                keys: [Role::RoleCarrier, Role::MemberA, Role::MemberB].map(|role| {
                    receipt::KeyReceipt {
                        role,
                        phase: KeyPhase::Unstarted,
                        new_key_ack: false,
                        baseline: receipt::Value::Absent,
                        current: receipt::Value::Absent,
                        pending: None,
                    }
                }),
            };
            journal.compare_exchange(&c, None, &initial).unwrap();
            let premature = journal.original_initial_data_read().unwrap();
            let (reopened, saved) =
                WindowsNativeCarrierReceiptStore::open(files.clone(), c.clone()).unwrap();
            assert_eq!(saved, Some(initial.clone()));
            assert!(
                reopened.original_initial_data_read().is_err(),
                "equal protected bytes do not import the original ACK"
            );
            let mut foreign_files = ProtectedSessionFiles::new(
                InitialDataDisk::default(),
                c.provenance.runtime.clone(),
                c.provenance.boot_id,
            )
            .unwrap();
            foreign_files.claim(&c.intent.scope).unwrap();
            let (mut foreign_journal, _) =
                WindowsNativeCarrierReceiptStore::open(foreign_files, c.clone()).unwrap();
            foreign_journal
                .compare_exchange(&c, None, &initial)
                .unwrap();
            let foreign = foreign_journal.original_initial_data_read().unwrap();
            assert_eq!(foreign.acknowledged(), premature.acknowledged());
            assert!(
                !foreign.same_original(&premature),
                "equal actual ACKs from separate original stores are foreign"
            );
            let execution = if bound {
                WindowsSessionStore::open(
                    files.clone(),
                    c.intent.scope.clone(),
                    RecordKind::Session,
                )
                .unwrap()
                .0
                .save(
                    &SessionState::new(c.intent.scope.clone(), Slot::A, 0, 0)
                        .unwrap()
                        .snapshot(),
                )
                .unwrap();
                let history = files.session_ack_root(&c.intent.scope).unwrap();
                let ack = history.acknowledgements().unwrap().last().unwrap().clone();
                Some(history.bind_native_birth(&c, &ack).unwrap())
            } else {
                None
            };
            let before = disk.0.borrow().clone();
            let journal = RefCell::new(journal);
            let slot = RefCell::new(None);
            let capture_state = TerminalCallState::new();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                retain_initial_cleanup_data(
                    &slot,
                    &capture_state,
                    || {
                        if let Some(root) = &execution {
                            // SAME original initialized J; never reopen/import an ACK.
                            journal
                                .borrow_mut()
                                .bind_original_native_view(files.native_birth_view(root).unwrap())
                                .map_err(|_| Error::Journal)?;
                        }
                        let canonical = match &execution {
                            Some(root) => root.native_cleanup_view(&files).unwrap().into_files(),
                            None => files.recovery_view(RuntimeSlot::Stable).unwrap().unwrap().0,
                        };
                        journal
                            .borrow_mut()
                            .enter_original_initial_cleanup(canonical)
                            .map_err(|_| Error::Journal)
                    },
                    || {
                        journal
                            .borrow()
                            .original_initial_data_read()
                            .map_err(|_| Error::Journal)
                    },
                    |held| {
                        let current = journal.borrow().original_initial_data_read().unwrap();
                        assert!(
                            held.same_original(&current),
                            "first pin must be from selected cleanup view"
                        );
                        assert_eq!(held.acknowledged(), &initial);
                        assert!(!held.same_original(&foreign));
                        assert_eq!(
                            premature.same_original(held),
                            !bound,
                            "execution identity must not be relaxed"
                        );
                        assert!(
                            slot.try_borrow_mut().is_err(),
                            "original is retained during postflight"
                        );
                        match fault {
                            0 => Ok(()),
                            1 => Err(Error::Conflict),
                            2 => panic!("canonical DATA postflight"),
                            _ => {
                                assert!(retain_initial_cleanup_data(
                                    &slot,
                                    &capture_state,
                                    || panic!("reentrant selection"),
                                    || panic!("reentrant capture"),
                                    |_| Ok(())
                                )
                                .is_err());
                                Ok(()) // swallowed reentry still taints original run
                            }
                        }
                    },
                )
            }));
            assert!(slot
                .borrow()
                .as_ref()
                .unwrap()
                .same_original(&journal.borrow().original_initial_data_read().unwrap()));
            assert_eq!(
                disk.0.borrow().clone(),
                before,
                "handoff/capture cannot write DATA"
            );
            if fault == 0 {
                result.unwrap().unwrap();
                capture_state.verify().unwrap();
            } else {
                assert!(result.is_err() || result.unwrap().is_err());
                assert!(capture_state.verify().is_err());
            }
            assert!(retain_initial_cleanup_data(
                &slot,
                &capture_state,
                || panic!("repeat selection"),
                || panic!("replacement capture"),
                |_| Ok(())
            )
            .is_err());
        }
    }
}
impl Drop for Resource {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

// Break: disposal before the authenticated check, forgetting known-disposed
// originals, or retrying disposal after a lost/unwound original check.
#[test]
fn terminal_container_disposal_checks_original_before_drop_and_is_once() {
    let drops = Rc::new(Cell::new(0));
    let mut container = TerminalResources::new(Resource(drops.clone()));
    container
        .release_original_with(|actual| {
            assert!(Rc::ptr_eq(&actual.0, &drops));
            assert_eq!(drops.get(), 0);
            Ok(())
        })
        .unwrap();
    assert_eq!(drops.get(), 1);
    assert!(container
        .release_original_with(|_| panic!("second disposal check"))
        .is_err());
    drop(container);
    assert_eq!(drops.get(), 1);
}

#[test]
fn terminal_container_disposal_error_unwind_and_empty_never_drop_or_retry() {
    for unwind in [false, true] {
        let drops = Rc::new(Cell::new(0));
        let mut container = TerminalResources::new(Resource(drops.clone()));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            container.release_original_with(|actual| {
                assert!(Rc::ptr_eq(&actual.0, &drops));
                if unwind {
                    panic!("disposal authentication unwind");
                }
                Err(std::io::Error::other("lost final ACK"))
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert_eq!(drops.get(), 0);
        assert!(container
            .release_original_with(|_| panic!("retry cannot disarm"))
            .is_err());
        drop(container);
        assert_eq!(drops.get(), 0, "unknown container preserves originals");
    }
    let mut empty = TerminalResources::new(1);
    empty.transfer_original_into(&mut None).unwrap();
    assert!(empty
        .release_original_with(|_| panic!("empty is not proof"))
        .is_err());
}

// Break: a drained wrapper reports a second successful terminal handoff, or
// erases/overwrites the caller-retained original on a conflict/postflight fault.
#[test]
fn terminal_original_handoff_is_once_and_preserves_both_roots_on_conflict() {
    let original = Rc::new(Resource(Rc::new(Cell::new(0))));
    let foreign = Rc::new(Resource(Rc::new(Cell::new(0))));
    let mut source = TerminalResources::new(original.clone());
    let mut destination = TerminalResources::new(Some(foreign.clone()));
    assert!(source
        .transfer_original_into(destination.retained_mut())
        .is_err());
    assert!(Rc::ptr_eq(source.retained(), &original));
    assert!(Rc::ptr_eq(
        destination.retained().as_ref().unwrap(),
        &foreign
    ));
    let mut destination = TerminalResources::new(None);
    source
        .transfer_original_into(destination.retained_mut())
        .unwrap();
    assert!(Rc::ptr_eq(
        destination.retained().as_ref().unwrap(),
        &original
    ));
    assert!(source.transfer_original_into(&mut None).is_err());
    drop(source);
    drop(destination);
    assert_eq!(original.0.get(), 0);
}

// Break: publishing a terminal destination only after transfer/postflight,
// dropping unknown originals, or overwriting a retained foreign destination.
#[test]
fn terminal_drain_retains_same_originals_before_failed_or_unwound_postflight() {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    for unwind in [false, true] {
        let drops = Rc::new(Cell::new(0));
        let original = Rc::new(Resource(drops.clone()));
        let mut source = Some(original.clone());
        let mut destination = TerminalResources::new(None);
        let mut attempted = false;
        let result = catch_unwind(AssertUnwindSafe(|| {
            drain_before_postflight(
                &mut attempted,
                destination.retained_mut(),
                || None,
                |slot| *slot = source.take(),
                |slot| {
                    assert!(Rc::ptr_eq(slot.as_ref().unwrap(), &original));
                    if unwind {
                        panic!("terminal drain postflight");
                    }
                    Err(Error::Conflict)
                },
            )
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(source.is_none());
        assert!(Rc::ptr_eq(
            destination.retained().as_ref().unwrap().as_ref().unwrap(),
            &original
        ));
        assert!(drain_before_postflight(
            &mut attempted,
            destination.retained_mut(),
            || None,
            |_| panic!("repeat must not move"),
            |_| Ok(())
        )
        .is_err());
        drop(original);
        drop(destination);
        assert_eq!(drops.get(), 0, "unknown destination Drop is not cleanup");
    }
}

#[test]
fn terminal_drain_rejects_foreign_destination_without_consuming_source() {
    let original = Rc::new(7u64);
    let foreign = Rc::new(7u64);
    let mut source = Some(original.clone());
    let mut destination = TerminalResources::new(Some(Some(foreign.clone())));
    let mut attempted = false;
    assert!(drain_before_postflight(
        &mut attempted,
        destination.retained_mut(),
        || None,
        |slot| *slot = source.take(),
        |_| Ok(())
    )
    .is_err());
    assert!(Rc::ptr_eq(source.as_ref().unwrap(), &original));
    assert!(Rc::ptr_eq(
        destination.retained().as_ref().unwrap().as_ref().unwrap(),
        &foreign
    ));
    assert!(attempted);
}

#[test]
fn terminal_partial_transfer_unwind_retains_both_moved_and_unmoved_owners() {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    let drops = Rc::new(Cell::new(0));
    let mut source = [Some(Resource(drops.clone())), Some(Resource(drops.clone()))];
    let mut destination = TerminalResources::new(None);
    let mut attempted = false;
    assert!(catch_unwind(AssertUnwindSafe(|| drain_before_postflight(
        &mut attempted,
        destination.retained_mut(),
        || [None, None],
        |slots| {
            slots[0] = source[0].take();
            panic!("between ownership moves");
        },
        |_| Ok(()),
    )))
    .is_err());
    assert!(source[0].is_none());
    assert!(source[1].is_some());
    assert!(destination.retained().as_ref().unwrap()[0].is_some());
    assert_eq!(drops.get(), 0);
    drop(destination);
    assert_eq!(drops.get(), 0);
    drop(source);
    assert_eq!(drops.get(), 1, "only unmoved caller-owned original drops");
}

// Exercise the ACTUAL Assembly drain, not only its portable transfer helper.
#[test]
fn actual_assembly_drain_moves_all_owner_slots_and_unknown_destination_retains() {
    let drops = Rc::new(Cell::new(0));
    let original = Rc::new(Resource(drops.clone()));
    let shared = Rc::new(RefCell::new(State {
        lease: Rc::new(()),
        record: None,
        paths: BTreeMap::new(),
        fault: Fault::None,
        creates: 0,
        writes: 0,
        key_drops: Rc::new(Cell::new(0)),
        nic_after_create: false,
        nic_after_write: false,
    }));
    let mut assembly = Assembly::<Journal, keys::Keys<Kernel, Authority>, _, _>::new(
        context(),
        Journal(shared),
        original.clone(),
    );
    assembly.assets = Some(original.clone());
    let mut destination = TerminalResources::new(None);
    assembly
        .drain_terminal_into(destination.retained_mut(), |raw| {
            assert!(raw.pending.is_some());
            assert!(Rc::ptr_eq(raw.bootstrap.as_ref().unwrap(), &original));
            assert!(Rc::ptr_eq(raw.assets.borrow().as_ref().unwrap(), &original));
            Err(Error::Conflict)
        })
        .unwrap_err();
    assert!(assembly.pending.is_none());
    assert!(assembly.assets.is_none());
    assert!(assembly.bootstrap.is_none());
    assert!(assembly
        .drain_terminal_into(destination.retained_mut(), |_| Ok(()))
        .is_err());
    drop(assembly);
    drop(original);
    drop(destination);
    assert_eq!(drops.get(), 0);
}

#[test]
fn terminal_merge_never_overwrites_foreign_destination_or_clears_it_from_empty_source() {
    let original = Rc::new(7u64);
    let foreign = Rc::new(7u64);
    let mut source = Some(original.clone());
    let mut destination = TerminalResources::new(Some(foreign.clone()));
    assert!(transfer_terminal_slot(&mut source, destination.retained_mut()).is_err());
    assert!(Rc::ptr_eq(source.as_ref().unwrap(), &original));
    assert!(Rc::ptr_eq(
        destination.retained().as_ref().unwrap(),
        &foreign
    ));
    let mut empty = None;
    transfer_terminal_slot(&mut empty, destination.retained_mut()).unwrap();
    assert!(Rc::ptr_eq(
        destination.retained().as_ref().unwrap(),
        &foreign
    ));
    let mut fresh = TerminalResources::new(None);
    transfer_terminal_slot(&mut source, fresh.retained_mut()).unwrap();
    assert!(source.is_none());
    assert!(Rc::ptr_eq(fresh.retained().as_ref().unwrap(), &original));
}
#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    InitialLost,
    InitialPanic,
    CaptureLost,
    CapturePanic,
    DisableLost,
    DisablePanic,
    AttachErr,
    AttachPanic,
    CreateFlushErr,
    CreateFlushPanic,
    MemberRestoreLost,
    MemberRestorePanic,
}
struct State {
    lease: Rc<()>,
    record: Option<Record>,
    paths: BTreeMap<String, NativeValue>,
    fault: Fault,
    creates: u32,
    writes: u32,
    key_drops: Rc<Cell<u32>>,
    nic_after_create: bool,
    nic_after_write: bool,
}
type Shared = Rc<RefCell<State>>;
struct Journal(Shared);
impl NativeJournal for Journal {
    fn load(&mut self, c: &Context) -> Result<Option<Record>> {
        let s = self.0.borrow();
        if s.record.as_ref().is_some_and(|r| &r.context != c) {
            return Err(Error::Conflict);
        }
        Ok(s.record.clone())
    }
    fn compare_exchange(&mut self, c: &Context, old: Option<&Record>, next: &Record) -> Result<()> {
        let mut s = self.0.borrow_mut();
        if s.record.as_ref() != old || c != &next.context {
            return Err(Error::Conflict);
        }
        receipt::validate_transition(old, next, false)?;
        s.record = Some(next.clone());
        if next.phase == receipt::Phase::Preparing
            && next
                .keys
                .iter()
                .skip(1)
                .any(|k| k.phase == KeyPhase::RestorePending)
        {
            match s.fault {
                Fault::MemberRestoreLost => return Err(Error::Journal),
                Fault::MemberRestorePanic => panic!("member restore CAS ACK lost"),
                _ => {}
            }
        }
        match (s.fault, next.generation) {
            (Fault::InitialLost, 1) | (Fault::CaptureLost, 3) | (Fault::DisableLost, 5) => {
                Err(Error::Journal)
            }
            (Fault::InitialPanic, 1) | (Fault::CapturePanic, 3) | (Fault::DisablePanic, 5) => {
                panic!("journal after internal effect")
            }
            _ => Ok(()),
        }
    }
}
struct Authority(Shared);
impl NativeAuthority for Authority {
    type Lock = Rc<()>;
    fn verify(&mut self, lock: &mut Self::Lock, c: &Context) -> Result<()> {
        let s = self.0.borrow();
        if !Rc::ptr_eq(lock, &s.lease) || c != &context() {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn authorize_effect(
        &mut self,
        lock: &mut Self::Lock,
        pending: &Record,
        binding: &Binding,
        e: keys::Effect,
    ) -> Result<()> {
        self.verify(lock, &pending.context)?;
        keys::effect_matches_storage(
            pending,
            binding,
            e,
            self.0.borrow().record.as_ref().ok_or(Error::Pending)?,
            true,
        )?;
        if self.nic_absence(lock, &pending.context, binding)? != (true, true, true) {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn nic_absence(
        &mut self,
        lock: &mut Self::Lock,
        c: &Context,
        _: &Binding,
    ) -> Result<(bool, bool, bool)> {
        self.verify(lock, c)?;
        let state = self.0.borrow();
        let absent = (!state.nic_after_create || state.creates == 0)
            && (!state.nic_after_write || state.writes == 0);
        Ok((absent, absent, absent))
    }
}
const PARENT: &str = r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces";
struct Handle {
    name: String,
    _original: Option<Resource>,
}
struct Kernel(Shared);
impl RegistryKernel for Kernel {
    type Handle = Handle;
    fn interfaces(&mut self) -> Result<Handle> {
        Ok(Handle {
            name: PARENT.into(),
            _original: None,
        })
    }
    fn name(&mut self, h: &Handle) -> Result<String> {
        Ok(h.name.clone())
    }
    fn open(&mut self, _: &Handle, child: &str) -> Result<Option<Handle>> {
        let name = format!("{PARENT}\\{child}");
        Ok(self.0.borrow().paths.contains_key(&name).then_some(Handle {
            name,
            _original: None,
        }))
    }
    fn create(&mut self, _: &Handle, child: &str) -> Result<(Handle, u32)> {
        let mut s = self.0.borrow_mut();
        let name = format!("{PARENT}\\{child}");
        assert!(!s.paths.contains_key(&name));
        let record = s.record.as_ref().unwrap();
        let index = record
            .context
            .bindings
            .iter()
            .position(|b| b.registry_path.ends_with(child))
            .unwrap();
        assert_eq!(record.keys[index].phase, KeyPhase::CreatePending);
        s.creates += 1;
        s.paths.insert(name.clone(), NativeValue::Absent);
        Ok((
            Handle {
                name,
                _original: Some(Resource(s.key_drops.clone())),
            },
            1,
        ))
    }
    fn value(&mut self, h: &Handle) -> Result<NativeValue> {
        self.0
            .borrow()
            .paths
            .get(&h.name)
            .cloned()
            .ok_or(Error::Conflict)
    }
    fn zero(&mut self, h: &Handle) -> Result<()> {
        let mut s = self.0.borrow_mut();
        let record = s.record.as_ref().unwrap();
        let index = record
            .context
            .bindings
            .iter()
            .position(|b| {
                h.name
                    .ends_with(b.registry_path.rsplit('\\').next().unwrap())
            })
            .unwrap();
        assert_eq!(record.keys[index].phase, KeyPhase::DisablePending);
        s.writes += 1;
        s.paths.insert(h.name.clone(), NativeValue::Dword(0));
        Ok(())
    }
    fn delete_value(&mut self, h: &Handle) -> Result<()> {
        let mut s = self.0.borrow_mut();
        let record = s.record.as_ref().unwrap();
        let index = record
            .context
            .bindings
            .iter()
            .position(|b| {
                h.name
                    .ends_with(b.registry_path.rsplit('\\').next().unwrap())
            })
            .unwrap();
        assert_eq!(record.keys[index].phase, KeyPhase::RestorePending);
        let value = s
            .paths
            .get_mut(&h.name)
            .expect("same original retained key");
        assert_eq!(*value, NativeValue::Dword(0));
        *value = NativeValue::Absent;
        s.writes += 1;
        Ok(())
    }
    fn flush(&mut self, _: &Handle) -> Result<()> {
        let s = self.0.borrow();
        if s.creates != 0 {
            match s.fault {
                Fault::CreateFlushErr => return Err(Error::Native),
                Fault::CreateFlushPanic => panic!("key IO internal post-create flush"),
                _ => {}
            }
        }
        Ok(())
    }
}
type Io = keys::Keys<Kernel, Authority>;
impl NativeKeyAttachment<Journal> for Io {
    fn assert_original_journal_lock(
        &mut self,
        journal: &Journal,
        lock: &mut Rc<()>,
        c: &Context,
    ) -> Result<()> {
        self.assert_serialized_lock(lock, c)?;
        if !Rc::ptr_eq(lock, &journal.0.borrow().lease) {
            return Err(Error::Conflict);
        }
        match journal.0.borrow().fault {
            Fault::AttachErr => return Err(Error::Conflict),
            Fault::AttachPanic => panic!("attachment identity boundary"),
            _ => {}
        }
        Ok(())
    }
}
type Root = Assembly<Journal, Io, Resource, Resource>;

// Break: rejecting the initialized no-key original merely because cold load
// was entered, accepting a foreign initial ACK, or keeping a seal after an
// actual key/constructor entry. No SDK or disposal grant is tested here.
#[test]
fn module_only_assembly_source_is_original_initial_and_revokes_before_key_access() {
    for entry in 0..3 {
        let (mut root, state, lock, _) = setup(Fault::None);
        root.initialize().unwrap();
        root.no_sdk.set(false); // actual bootstrap entry, NOT a Never lane
        let mut source = None;
        root.retain_module_only_source_into(&mut source, |_| Ok(()))
            .unwrap();
        let actual = source.as_ref().unwrap();
        root.verify_module_only_source(actual).unwrap();
        actual.verify_no_constructor_seal().unwrap();
        let (mut foreign, _, _, _) = setup(Fault::None);
        foreign.initialize().unwrap();
        assert!(foreign.verify_module_only_source(actual).is_err());
        assert!(root
            .retain_module_only_source_into(&mut None, |_| Ok(()))
            .is_err());
        assert!(
            root.verify_module_only_source(actual).is_err(),
            "duplicate selection poisons the original"
        );
        assert!(actual.verify_no_constructor_seal().is_err());
        // A separate real source for each entry: fail BEFORE missing assets/
        // owner checks, not after a hypothetical SDK operation.
        let (mut root, _, _, _) = setup(Fault::None);
        root.initialize().unwrap();
        let mut source = None;
        root.retain_module_only_source_into(&mut source, |_| Ok(()))
            .unwrap();
        match entry {
            0 => {
                let _ = root.attach_keys(&mut lock.clone());
            }
            1 => {
                let _ = root.prepare_carrier_in(&mut lock.clone(), |call| call());
            }
            _ => {
                root.module_only_allowed.set(false);
            } // native assemble boundary
        }
        assert!(root
            .verify_module_only_source(source.as_ref().unwrap())
            .is_err());
        assert!(source
            .as_ref()
            .unwrap()
            .verify_no_constructor_seal()
            .is_err());
        assert_eq!(state.borrow().creates, 0);
        assert_eq!(state.borrow().writes, 0);
    }
}

#[test]
fn module_only_assembly_source_retains_original_before_error_or_unwind() {
    for unwind in [false, true] {
        let (mut root, _, _, _) = setup(Fault::None);
        root.initialize().unwrap();
        let mut source = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            root.retain_module_only_source_into(&mut source, |_| {
                if unwind {
                    panic!("module-only source postflight");
                }
                Err(Error::Conflict)
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        let original = source.as_ref().expect("rooted original initial read");
        assert!(Rc::ptr_eq(&original.origin, &root.origin));
        assert!(root.verify_module_only_source(original).is_err());
        assert!(original.verify_no_constructor_seal().is_err());
    }
}

#[test]
fn module_only_source_cannot_import_unacknowledged_initial_capture_or_foreign_pin() {
    for fault in [Fault::InitialLost, Fault::InitialPanic] {
        let (mut root, state, _, _) = setup(fault);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| root.initialize()));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(
            state.borrow().record.is_some(),
            "durable DATA may exist without original ACK"
        );
        let mut source = None;
        assert!(root
            .retain_module_only_source_into(&mut source, |_| panic!("unknown ACK callback"))
            .is_err());
        assert!(source.is_none(), "missing original cannot mint a source");
        assert_eq!(state.borrow().creates, 0);
        assert_eq!(state.borrow().writes, 0);
    }
    let (mut root, _, _, _) = setup(Fault::None);
    let (mut foreign, _, _, _) = setup(Fault::None);
    root.initialize().unwrap();
    foreign.initialize().unwrap();
    root.initial = foreign.initial.take();
    let mut source = None;
    assert!(root
        .retain_module_only_source_into(&mut source, |_| panic!("foreign callback"))
        .is_err());
    assert!(
        source.is_some(),
        "actual supplied pin retained, never promoted"
    );
    assert!(root
        .verify_module_only_source(source.as_ref().unwrap())
        .is_err());
}

#[test]
fn module_only_initial_read_selects_original_cleanup_and_never_rearms_forward() {
    let (mut root, state, _, _) = setup(Fault::None);
    root.initialize().unwrap();
    let mut source = None;
    root.retain_module_only_source_into(&mut source, |_| Ok(()))
        .unwrap();
    let source = source.unwrap();
    let record = root.pending.as_ref().unwrap().verify_initial().unwrap();
    let bytes = record.encode().unwrap();
    let selected = std::cell::Cell::new(0);
    for _ in 0..2 {
        inspect_module_only_initial(&source.initial, &record.context, &bytes, |_, _| {
            selected.set(selected.get() + 1);
            Ok(())
        })
        .unwrap();
        root.verify_module_only_source(&source).unwrap();
    }
    assert_eq!(selected.get(), 2);
    assert!(root.pending.as_ref().unwrap().verify_initial().is_err());
    assert_eq!(state.borrow().creates, 0);
    assert_eq!(state.borrow().writes, 0);
}

#[test]
fn module_only_initial_foreign_data_or_handoff_failure_irreversibly_denies_read() {
    for fault in 0..3 {
        let (mut root, state, _, _) = setup(Fault::None);
        root.initialize().unwrap();
        let mut source = None;
        root.retain_module_only_source_into(&mut source, |_| Ok(()))
            .unwrap();
        let source = source.unwrap();
        let record = root.pending.as_ref().unwrap().verify_initial().unwrap();
        let mut observed = record.clone();
        if fault == 0 {
            observed.generation += 1;
        }
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            inspect_module_only_initial(
                &source.initial,
                &record.context,
                &observed.encode().unwrap(),
                |_, _| {
                    if fault == 1 {
                        return Err(Error::Journal);
                    };
                    if fault == 2 {
                        panic!("handoff")
                    };
                    Ok(())
                },
            )
        }));
        assert!(!matches!(outcome, Ok(Ok(()))));
        assert!(inspect_module_only_initial(
            &source.initial,
            &record.context,
            &record.encode().unwrap(),
            |_, _| panic!("unknown original must not retry handoff")
        )
        .is_err());
        assert_eq!(state.borrow().creates, 0);
        assert_eq!(state.borrow().writes, 0);
    }
}
#[test]
fn initial_noc_capability_issue_is_once_even_when_first_attempt_has_no_ack() {
    let (mut root, state, _, _) = setup(Fault::None);
    root.initialize().unwrap();
    let (_, actual) = root.claim_initial_noc_source().unwrap();
    assert!(Rc::ptr_eq(&actual, root.initial.as_ref().unwrap()));
    assert!(root.claim_initial_noc_source().is_err());
    let (mut incomplete, other, _, _) = setup(Fault::None);
    assert!(incomplete.claim_initial_noc_source().is_err());
    incomplete.initialize().unwrap();
    assert!(
        incomplete.claim_initial_noc_source().is_err(),
        "failed issuer cannot be retried into a second origin"
    );
    assert_eq!(state.borrow().creates, 0);
    assert_eq!(other.borrow().creates, 0);
}
// Break: a previously minted initial reader survives a rejected constructor
// entry, or a drained equal-looking destination can replace its original ACK.
#[test]
fn initial_noc_original_survives_own_cut_but_not_constructor_entry() {
    let (mut root, state, _, _) = setup(Fault::None);
    root.initialize().unwrap();
    let (origin, pin) = root.initial_noc_source().unwrap();
    root.verify_initial_noc_original(&origin, &pin).unwrap();
    let mut raw = TerminalResources::new(None);
    root.drain_terminal_into(raw.retained_mut(), |_| Ok(()))
        .unwrap();
    root.verify_initial_noc_original(&origin, &pin).unwrap();
    let actual = raw.retained().as_ref().unwrap();
    assert!(Rc::ptr_eq(actual.initial.as_ref().unwrap(), &pin));
    let (mut other, _, _, _) = setup(Fault::None);
    other.initialize().unwrap();
    let (foreign_origin, foreign_pin) = other.initial_noc_source().unwrap();
    assert!(root
        .verify_initial_noc_original(&foreign_origin, &pin)
        .is_err());
    assert!(root
        .verify_initial_noc_original(&origin, &foreign_pin)
        .is_err());
    // Rejected entry still irreversibly retires its previously issued reader.
    let mut lock = state.borrow().lease.clone();
    assert!(other.attach_keys(&mut lock).is_err());
    assert!(other
        .verify_initial_noc_original(&foreign_origin, &foreign_pin)
        .is_err());
    assert_eq!(state.borrow().creates, 0);
    assert_eq!(state.borrow().writes, 0);
}

// Break: a successful initial journal ACK is lost through an owning Result or
// a raw owner drops before whole terminal proof when postflight fails/unwinds.
#[test]
fn initial_noc_cut_roots_same_ack_and_bootstrap_before_error_or_unwind() {
    for unwind in [false, true] {
        let (mut root, state, _, drops) = setup(Fault::None);
        root.initialize().unwrap();
        let (origin, pin) = root.initial_noc_source().unwrap();
        let mut raw = TerminalResources::new(None);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            root.drain_terminal_into(raw.retained_mut(), |parts| {
                assert!(Rc::ptr_eq(parts.initial.as_ref().unwrap(), &pin));
                assert!(parts.pending.is_some());
                assert!(parts.bootstrap.is_some());
                assert_eq!(drops.get(), 0);
                if unwind {
                    panic!("initial-NoC cut postflight unwind");
                }
                Err(Error::Journal)
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        root.verify_initial_noc_original(&origin, &pin).unwrap();
        root.verify_drained_original(raw.retained().as_ref().unwrap())
            .unwrap();
        assert!(root
            .drain_terminal_into(&mut None, |_| panic!("repeat cut"))
            .is_err());
        assert_eq!(state.borrow().creates, 0);
        assert_eq!(state.borrow().writes, 0);
        drop(raw);
        drop(root);
        assert_eq!(
            drops.get(),
            0,
            "unknown cut did not authorize actual bootstrap disposal"
        );
    }
}

#[test]
fn initial_noc_source_never_adopts_lost_initial_ack_or_unwind() {
    for fault in [Fault::InitialLost, Fault::InitialPanic] {
        let (mut root, state, _, drops) = setup(fault);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| root.initialize()));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(
            state.borrow().record.is_some(),
            "matching persisted DATA is not the original ACK"
        );
        assert!(root.initial_noc_source().is_err());
        assert!(root.pending.is_some());
        assert_eq!(state.borrow().creates, 0);
        assert_eq!(state.borrow().writes, 0);
        drop(root);
        assert_eq!(drops.get(), 0);
    }
}
// Break: accepting an unacknowledged/equal-foreign initial journal, or treating
// initialized metadata as a no-SDK origin after an actual constructor entry.
#[test]
fn initial_noc_source_requires_original_initial_ack_and_no_constructor_entry() {
    let (mut root, state, _, _) = setup(Fault::None);
    assert!(root.initial_noc_source().is_err());
    root.initialize().unwrap();
    let original = root.initial.as_ref().unwrap().clone();
    let (origin, pin) = root.initial_noc_source().unwrap();
    assert!(Rc::ptr_eq(&origin, &root.origin));
    assert!(Rc::ptr_eq(&pin, &original));
    let record = pin.verify(&context()).unwrap();
    assert_eq!(record.generation, 1);
    assert_eq!(record.phase, receipt::Phase::Preparing);
    assert_eq!(state.borrow().creates, 0);
    assert_eq!(state.borrow().writes, 0);
    let (mut foreign, _, _, _) = setup(Fault::None);
    foreign.initialize().unwrap();
    root.initial = foreign.initial.take();
    assert!(root.initial_noc_source().is_err());
    root.initial = Some(original);
    root.attach_attempted = true;
    assert!(root.initial_noc_source().is_err());
    root.attach_attempted = false;
    root.prepare_attempted = true;
    assert!(root.initial_noc_source().is_err());
    root.prepare_attempted = false;
    root.precreation_attempted = true;
    assert!(root.initial_noc_source().is_err());
    root.precreation_attempted = false;
    root.member_attempted[0] = true;
    assert!(root.initial_noc_source().is_err());
    assert_eq!(state.borrow().creates, 0);
    assert_eq!(state.borrow().writes, 0);
}

// Break: considering an empty shell drained into an equal foreign raw, or
// ignoring an original field that a future drain forgot to transfer.
// Break: a genuine loaded-but-unconstructed Assembly is mistaken for Never,
// or a foreign/constructor-touched raw owner is accepted as the original cut.
#[test]
fn module_only_terminal_cut_preserves_loader_history_and_same_initial_owner() {
    let (mut root, state, _, _) = setup(Fault::None);
    root.initialize().unwrap();
    let mut selected = None;
    root.retain_module_only_source_into(&mut selected, |_| Ok(()))
        .unwrap();
    let selected = selected.unwrap();
    root.no_sdk.set(false); // actual loader entry is not a constructor.
    let mut destination = None;
    root.drain_terminal_into(&mut destination, |_| Ok(()))
        .unwrap();
    let raw = destination.as_mut().unwrap();
    root.verify_module_only_terminal_cut(raw, &selected)
        .unwrap();
    assert!(!root.no_sdk.get(), "never reset actual loader history");
    assert!(root
        .verify_initial_noc_original(&root.origin, raw.initial.as_ref().unwrap())
        .is_err());

    let (mut foreign, _, _, _) = setup(Fault::None);
    foreign.initialize().unwrap();
    let mut foreign_selected = None;
    foreign
        .retain_module_only_source_into(&mut foreign_selected, |_| Ok(()))
        .unwrap();
    assert!(root
        .verify_module_only_terminal_cut(raw, &foreign_selected.unwrap())
        .is_err());
    let initial = raw.initial.take();
    raw.initial = foreign.initial.take();
    assert!(root
        .verify_module_only_terminal_cut(raw, &selected)
        .is_err());
    raw.initial = initial;
    root.verify_module_only_terminal_cut(raw, &selected)
        .unwrap();
    root.module_only_allowed.set(false);
    assert!(root
        .verify_module_only_terminal_cut(raw, &selected)
        .is_err());
    assert_eq!(state.borrow().creates, 0);
    assert_eq!(state.borrow().writes, 0);
}

#[test]
fn module_only_terminal_cut_rejects_remaining_or_constructor_owned_slots() {
    for fault in 0..8 {
        let (mut root, _, _, drops) = setup(Fault::None);
        root.initialize().unwrap();
        let mut selected = None;
        root.retain_module_only_source_into(&mut selected, |_| Ok(()))
            .unwrap();
        let selected = selected.unwrap();
        root.no_sdk.set(false);
        let mut destination = None;
        root.drain_terminal_into(&mut destination, |_| Ok(()))
            .unwrap();
        let raw = destination.as_mut().unwrap();
        match fault {
            0 => root.attach_attempted = true,
            1 => root.prepare_attempted = true,
            2 => root.precreation_attempted = true,
            3 => root.member_attempted[1] = true,
            4 => raw.bootstrap = None,
            5 => raw.pending = None,
            6 => *raw.assets.get_mut() = Some(Resource(drops.clone())),
            7 => root.bootstrap = Some(Resource(drops.clone())),
            _ => unreachable!(),
        }
        assert!(
            root.verify_module_only_terminal_cut(raw, &selected)
                .is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn assembly_empty_shell_requires_same_raw_origin_and_every_owner_moved() {
    let (mut first, state, _, drops) = setup(Fault::None);
    let (mut other, _, _, _) = setup(Fault::None);
    let mut raw = TerminalResources::new(None);
    let mut foreign = TerminalResources::new(None);
    first
        .drain_terminal_into(raw.retained_mut(), |_| Ok(()))
        .unwrap();
    other
        .drain_terminal_into(foreign.retained_mut(), |_| Ok(()))
        .unwrap();
    first
        .verify_drained_original(raw.retained().as_ref().unwrap())
        .unwrap();
    assert!(first
        .verify_drained_original(foreign.retained().as_ref().unwrap())
        .is_err());
    first.assets = Some(Resource(drops.clone()));
    assert!(first
        .verify_drained_original(raw.retained().as_ref().unwrap())
        .is_err());
    assert_eq!(state.borrow().creates, 0);
    assert_eq!(state.borrow().writes, 0);
    drop(first);
    assert_eq!(drops.get(), 0, "unknown owner remains rooted, not disarmed");
}
fn setup(fault: Fault) -> (Root, Shared, Rc<()>, Rc<Cell<u32>>) {
    let lock = Rc::new(());
    let drops = Rc::new(Cell::new(0));
    let s = Rc::new(RefCell::new(State {
        lease: lock.clone(),
        record: None,
        paths: BTreeMap::new(),
        fault,
        creates: 0,
        writes: 0,
        key_drops: Rc::new(Cell::new(0)),
        nic_after_create: false,
        nic_after_write: false,
    }));
    (
        Root::new(context(), Journal(s.clone()), Resource(drops.clone())),
        s,
        lock,
        drops,
    )
}
fn retain_io(root: &mut Root, s: &Shared, drops: &Rc<Cell<u32>>) {
    root.assets = Some(Resource(drops.clone()));
    root.io = Some(Io::new(Kernel(s.clone()), Authority(s.clone()), context()));
}

#[test]
fn same_assembly_member_recreation_uses_acknowledged_original_restored_key() {
    let (mut root, state, mut lock, _) = attached(Fault::None);
    root.prepare_carrier_in(&mut lock, |call| call()).unwrap();
    root.assets.take();
    root.with_member_precreation_in(Role::MemberB, &mut lock, &mut |call| call(), |_| Ok(()))
        .unwrap();
    root.restore_member_key(Role::MemberB, &mut lock).unwrap();
    root.with_member_precreation_in(Role::MemberB, &mut lock, &mut |call| call(), |receipt| {
        assert_eq!(receipt.binding, &context().bindings[2]);
        assert_eq!(receipt.record.phase, receipt::Phase::Preparing);
        assert_eq!(receipt.record.keys[0].phase, KeyPhase::Disabled);
        assert_eq!(receipt.record.keys[2].phase, KeyPhase::Disabled);
        Ok(())
    })
    .unwrap();
    assert_eq!(state.borrow().creates, 2);
    // A later SAME original member retirement can renew this slot once again;
    // consumed receipts do not permanently disable the slot or recreate keys.
    root.restore_member_key(Role::MemberB, &mut lock).unwrap();
    root.with_member_precreation_in(Role::MemberB, &mut lock, &mut |call| call(), |_| Ok(()))
        .unwrap();
    assert_eq!(state.borrow().creates, 2);
    assert!(root
        .with_member_precreation_in(Role::MemberB, &mut lock, &mut |call| call(), |_| panic!(
            "duplicate must not create"
        ))
        .is_err());
}

#[test]
fn member_restore_lost_ack_or_unwind_retains_keys_and_forbids_recreation() {
    for fault in [Fault::MemberRestoreLost, Fault::MemberRestorePanic] {
        let (mut root, state, mut lock, drops) = attached(Fault::None);
        root.prepare_carrier_in(&mut lock, |call| call()).unwrap();
        root.assets.take();
        root.with_member_precreation_in(Role::MemberB, &mut lock, &mut |call| call(), |_| Ok(()))
            .unwrap();
        state.borrow_mut().fault = fault;
        let writes = state.borrow().writes;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            root.restore_member_key(Role::MemberB, &mut lock)
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert_eq!(state.borrow().writes, writes);
        assert!(root
            .with_member_precreation_in(Role::MemberB, &mut lock, &mut |call| call(), |_| panic!(
                "lost ACK"
            ))
            .is_err());
        drop(root);
        assert_eq!(state.borrow().key_drops.get(), 0);
        assert_eq!(drops.get(), 1); // The test itself explicitly handed off C assets above.
    }
}
fn attached(fault: Fault) -> (Root, Shared, Rc<()>, Rc<Cell<u32>>) {
    let (mut root, s, mut lock, drops) = setup(fault);
    root.initialize().unwrap();
    retain_io(&mut root, &s, &drops);
    root.attach_keys(&mut lock).unwrap();
    (root, s, lock, drops)
}

#[test]
fn actual_attachment_and_preparation_keep_same_owner_and_current_generation() {
    // Break: prepare a replacement owner, predict generation, or replace ACK.
    let (mut rejected, state, mut rejected_lock, drops) = attached(Fault::None);
    state.borrow_mut().nic_after_create = true;
    assert!(rejected
        .prepare_carrier_in(&mut rejected_lock, |call| call())
        .is_err());
    let record = state.borrow().record.clone().unwrap();
    assert_eq!(record.keys[0].phase, KeyPhase::Captured);
    assert!(
        record.keys[0].new_key_ack,
        "actual returned NEW ACK retained before independent Captured readback"
    );
    assert_eq!((state.borrow().creates, state.borrow().writes), (1, 0));
    assert!(rejected
        .with_precreation_in(&mut rejected_lock, &mut |call| call(), |_, _, _| panic!(
            "NIC conflict allowed create"
        ))
        .is_err());
    drop(rejected);
    assert_eq!(drops.get(), 0);
    assert_eq!(state.borrow().key_drops.get(), 0);
    let (mut rejected, state, mut rejected_lock, drops) = attached(Fault::None);
    state.borrow_mut().nic_after_write = true;
    assert!(rejected
        .prepare_carrier_in(&mut rejected_lock, |call| call())
        .is_err());
    let record = state.borrow().record.clone().unwrap();
    assert_eq!(record.keys[0].phase, KeyPhase::DisablePending);
    assert!(record.keys[0].new_key_ack);
    assert_eq!((state.borrow().creates, state.borrow().writes), (1, 1));
    assert!(rejected
        .with_precreation_in(&mut rejected_lock, &mut |call| call(), |_, _, _| panic!(
            "NIC conflict after value mutation allowed create"
        ))
        .is_err());
    drop(rejected);
    assert_eq!(drops.get(), 0);
    assert_eq!(state.borrow().key_drops.get(), 0);
    let (mut root, s, mut lock, drops) = attached(Fault::None);
    root.prepare_carrier_in(&mut lock, |call| call()).unwrap();
    assert_eq!((s.borrow().creates, s.borrow().writes), (1, 1));
    assert_eq!(root.disabled.as_ref().unwrap().generation, 5);
    let mut calls = 0;
    root.with_precreation_in(
        &mut lock,
        &mut |call| {
            calls += 1;
            call()
        },
        |assets, r, generation| {
            assert!(Rc::ptr_eq(&assets.as_ref().unwrap().0, &drops));
            assert_eq!(generation, 5);
            assert_eq!(r.record.generation, 5);
            assert_eq!(r.binding, &context().bindings[0]);
            assert!(Rc::ptr_eq(r.mutation_lock, &s.borrow().lease));
            keys::reattest_disabled_original_key(
                &mut Kernel(s.clone()),
                r.record,
                r.binding,
                r.new_key_ack,
            )
            .unwrap();
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        calls, 1,
        "precreation check is separate from C construction steps"
    );
    assert_eq!(
        root.prepare_carrier_in(&mut lock, |call| call()),
        Err(Error::Retired)
    );
    assert_eq!(root.attach_keys(&mut lock), Err(Error::Retired));
    assert_eq!(
        root.with_precreation_in(&mut lock, &mut |call| call(), |_, _, _| panic!("repeat")),
        Err(Error::Retired)
    );
}

#[test]
fn member_prerequisite_uses_original_owner_after_carrier_assets_transfer_once_per_role() {
    let (mut root, s, mut lock, drops) = attached(Fault::None);
    root.prepare_carrier_in(&mut lock, |call| call()).unwrap();
    let original_assets = root.assets.take().unwrap();
    assert!(Rc::ptr_eq(&original_assets.0, &drops));
    for (role, index) in [(Role::MemberA, 1), (Role::MemberB, 2)] {
        let calls = std::cell::Cell::new(0);
        root.with_member_precreation_in(
            role,
            &mut lock,
            &mut |call| {
                calls.set(calls.get() + 1);
                call()
            },
            |receipt| {
                assert_eq!(
                    calls.get(),
                    10,
                    "nine durable calls precede the independent create seam"
                );
                assert_eq!(receipt.binding, &context().bindings[index]);
                assert_eq!(receipt.record.keys[0].phase, KeyPhase::Disabled);
                assert_eq!(receipt.record.keys[index].phase, KeyPhase::Disabled);
                assert_eq!(
                    receipt.record.generation,
                    s.borrow().record.as_ref().unwrap().generation
                );
                keys::reattest_disabled_original_member_key(
                    &mut Kernel(s.clone()),
                    receipt.record,
                    &context(),
                    receipt.binding,
                    receipt.record.generation,
                    receipt.new_key_ack,
                )?;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(calls.get(), 10);
        assert_eq!(
            root.with_member_precreation_in(role, &mut lock, &mut |call| call(), |_| panic!(
                "repeat"
            )),
            Err(Error::Retired)
        );
    }
    assert_eq!((s.borrow().creates, s.borrow().writes), (3, 3));
    assert!(root.assets.is_none());
    assert_eq!(
        root.with_member_precreation_in(
            Role::RoleCarrier,
            &mut lock,
            &mut |call| call(),
            |_| panic!("not member")
        ),
        Err(Error::Retired)
    );
}

#[test]
fn member_prerequisite_before_c_preparation_and_after_wrong_lock_fail_without_effects() {
    let (mut root, s, mut lock, _) = attached(Fault::None);
    assert!(root
        .with_member_precreation_in(Role::MemberA, &mut lock, &mut |call| call(), |_| panic!(
            "not ready"
        ))
        .is_err());
    assert_eq!(s.borrow().creates, 0);
    let (mut root, s, mut lock, _) = attached(Fault::None);
    root.prepare_carrier_in(&mut lock, |call| call()).unwrap();
    assert!(root
        .with_member_precreation_in(
            Role::MemberA,
            &mut Rc::new(()),
            &mut |call| call(),
            |_| panic!("wrong lock")
        )
        .is_err());
    assert_eq!(s.borrow().creates, 1);
    assert!(root
        .with_member_precreation_in(Role::MemberA, &mut lock, &mut |call| call(), |_| panic!(
            "replay"
        ))
        .is_err());
}

#[test]
fn member_callback_error_or_unwind_retires_sibling_precreation_and_retains_original_keys() {
    // Break: a failed/unknown A Start permits new B key effects before cleanup.
    for failed_step in 1..=10 {
        for unwind in [false, true] {
            let (mut root, s, mut lock, drops) = attached(Fault::None);
            root.prepare_carrier_in(&mut lock, |call| call()).unwrap();
            let calls = std::cell::Cell::new(0);
            let callback = std::cell::Cell::new(false);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                root.with_member_precreation_in(
                    Role::MemberA,
                    &mut lock,
                    &mut |call| {
                        calls.set(calls.get() + 1);
                        call()?;
                        if calls.get() == failed_step {
                            if unwind {
                                panic!("member durable postflight");
                            }
                            return Err(Error::Pending);
                        }
                        Ok(())
                    },
                    |_| {
                        callback.set(true);
                        Ok(())
                    },
                )
            }));
            assert!(result.is_err() || result.unwrap().is_err());
            assert_eq!(calls.get(), failed_step);
            assert_eq!(callback.get(), failed_step == 10);
            assert_eq!(s.borrow().creates, if failed_step >= 4 { 2 } else { 1 });
            assert!(root
                .with_member_precreation_in(
                    Role::MemberB,
                    &mut lock,
                    &mut |call| call(),
                    |_| panic!("sibling effect")
                )
                .is_err());
            drop(root);
            assert_eq!(drops.get(), 0);
            assert_eq!(
                s.borrow().key_drops.get(),
                0,
                "same C/member originals survive postflight {failed_step}"
            );
        }
    }
    for unwind in [false, true] {
        let (mut root, s, mut lock, drops) = attached(Fault::None);
        root.prepare_carrier_in(&mut lock, |call| call()).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            root.with_member_precreation_in(Role::MemberA, &mut lock, &mut |call| call(), |_| {
                if unwind {
                    panic!("member callback after effect");
                }
                Err(Error::Pending)
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(root
            .with_member_precreation_in(Role::MemberB, &mut lock, &mut |call| call(), |_| panic!(
                "sibling effect"
            ))
            .is_err());
        assert_eq!(s.borrow().creates, 2);
        drop(root);
        assert_eq!(drops.get(), 0);
        assert_eq!(s.borrow().key_drops.get(), 0);
    }
}

#[test]
fn retained_owner_enters_closing_before_native_cleanup_without_restoring_live_keys() {
    // Break: rebuild the native owner from JSON, use cached C generation, or
    // restore keys before the actual member/C cleanup ACKs have been verified.
    let (mut root, s, mut lock, _) = attached(Fault::None);
    root.prepare_carrier_in(&mut lock, |call| call()).unwrap();
    root.assets.take();
    root.with_member_precreation_in(Role::MemberA, &mut lock, &mut |call| call(), |_| Ok(()))
        .unwrap();
    root.owner
        .as_mut()
        .unwrap()
        .with_original_cleanup_storage(&mut lock, |journal, acknowledged| {
            assert!(Rc::ptr_eq(&journal.0, &s));
            assert_eq!(
                journal.load(&acknowledged.context)?.as_ref(),
                Some(acknowledged)
            );
            Ok(())
        })
        .unwrap();
    root.begin_cleanup(&mut lock).unwrap();
    let record = s.borrow().record.clone().unwrap();
    assert_eq!(record.phase, receipt::Phase::Closing);
    assert_eq!(record.generation, 10);
    assert_eq!(record.keys[0].phase, KeyPhase::Disabled);
    assert_eq!(record.keys[1].phase, KeyPhase::Disabled);
    assert_eq!((s.borrow().creates, s.borrow().writes), (2, 2));
    assert!(root
        .with_member_precreation_in(Role::MemberB, &mut lock, &mut |call| call(), |_| panic!(
            "closing"
        ))
        .is_err());
    root.begin_cleanup(&mut lock).unwrap();
    assert_eq!(s.borrow().record.as_ref().unwrap().generation, 10);
    for fault in 0..3 {
        let (mut root, state, mut lock, _) = attached(Fault::None);
        root.prepare_carrier_in(&mut lock, |call| call()).unwrap();
        root.assets.take();
        let acknowledged = state.borrow().record.clone().unwrap();
        let mut foreign_lock = Rc::new(());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            root.owner.as_mut().unwrap().with_original_cleanup_storage(
                if fault == 0 {
                    &mut foreign_lock
                } else {
                    &mut lock
                },
                |journal, current| {
                    assert!(Rc::ptr_eq(&journal.0, &state));
                    assert_eq!(current, &acknowledged);
                    if fault == 2 {
                        panic!("cleanup storage callback unwind");
                    }
                    Err(Error::Journal)
                },
            )
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(root.owner.is_some());
        assert_eq!(state.borrow().record.as_ref(), Some(&acknowledged));
        assert_eq!(state.borrow().key_drops.get(), 0);
        assert!(root
            .owner
            .as_mut()
            .unwrap()
            .prepare_role(Role::MemberB, &mut lock)
            .is_err());
    }
}

// Break: returning/taking the actual native key owner through a fallible close
// callback, allowing reentrant mutable access, or importing an uncut raw owner.
#[test]
fn terminal_key_owner_borrow_retains_original_keys_on_error_and_unwind() {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    for unwind in [false, true] {
        let (mut root, state, mut lock, _) = attached(Fault::None);
        root.prepare_carrier_in(&mut lock, |call| call()).unwrap();
        let mut retained = TerminalResources::new(None);
        root.drain_terminal_into(retained.retained_mut(), |_| Ok(()))
            .unwrap();
        let raw = retained.retained().as_ref().unwrap();
        let entered = Cell::new(false);
        let result = catch_unwind(AssertUnwindSafe(|| {
            raw.with_original_key_owner(|owner| {
                entered.set(true);
                let record = owner.snapshot()?.unwrap();
                assert_eq!(record.keys[0].phase, KeyPhase::Disabled);
                assert!(raw
                    .with_original_key_owner::<()>(|_| panic!("reentrant owner borrow"))
                    .is_err());
                if unwind {
                    panic!("key close postflight boundary");
                }
                Err::<(), _>(Error::Conflict)
            })
        }));
        assert!(entered.get());
        assert!(result.is_err() || result.unwrap().is_err());
        raw.with_original_key_owner(|owner| {
            assert_eq!(owner.snapshot()?.unwrap().keys[0].phase, KeyPhase::Disabled);
            Ok(())
        })
        .unwrap();
        assert_eq!((state.borrow().creates, state.borrow().writes), (1, 1));
        assert_eq!(state.borrow().key_drops.get(), 0);
        drop(root);
        drop(retained);
        assert_eq!(state.borrow().key_drops.get(), 0);
    }
}

#[test]
fn terminal_key_owner_accessor_requires_actual_cut_origin() {
    let (mut root, _, mut lock, _) = attached(Fault::None);
    root.prepare_carrier_in(&mut lock, |call| call()).unwrap();
    let mut retained = TerminalResources::new(None);
    root.drain_terminal_into(retained.retained_mut(), |_| Ok(()))
        .unwrap();
    let raw = retained.retained_mut().as_mut().unwrap();
    let origin = raw.origin.take();
    assert!(raw
        .with_original_key_owner::<()>(|_| panic!("no original cut identity"))
        .is_err());
    assert!(raw.owner.borrow().is_some());
    raw.origin = origin;
    raw.with_original_key_owner(|owner| {
        assert_eq!(owner.snapshot()?.unwrap().keys[0].phase, KeyPhase::Disabled);
        Ok(())
    })
    .unwrap();
}

fn member_pair_fixture() -> (
    crate::member_carrier_pair::Record,
    crate::member_carrier_guard::Carrier,
) {
    use crate::{member_carrier_guard as g, member_carrier_pair as p, member_owner as o};
    use nelomai_client_tunnel::redundancy::Slot;
    let context = context();
    let carrier = g::Carrier {
        identity: g::Identity {
            scope: context.intent.scope.clone(),
            proof: o::InterfaceProof {
                guid: [1; 16],
                index: 7,
                luid: 90,
            },
        },
        sources: vec!["10.7.0.2".parse().unwrap()],
    };
    let record = p::Record {
        version: 2,
        scope: context.intent.scope.clone(),
        provenance: context.provenance,
        revision: 8,
        phase: p::Phase::Starting,
        addresses: context.intent.addresses,
        dns: vec![],
        carrier: Some(carrier.identity.proof),
        members: [
            Some(p::MemberState {
                owner: o::Record {
                    intent: o::Intent {
                        scope: context.intent.scope.clone(),
                        slot: nelomai_contracts::dispatcher::TunnelSlot::A,
                        transport: nelomai_client_tunnel::TunnelTransport::WireGuard,
                        engine: crate::test_engine_path("wireguard.exe"),
                        config_sha256: [4; 32],
                    },
                    phase: o::Phase::Prepared,
                    proof: None,
                    retired_proof: None,
                    previous_config_sha256: None,
                },
                lease_id: "22222222-2222-4222-8222-222222222222".into(),
                probe: nelomai_contracts::RedundantHealthProbe {
                    kind: nelomai_contracts::HealthProbeKind::DnsA,
                    target_ipv4: "1.1.1.1".parse().unwrap(),
                    query_name: "example.com".into(),
                    timeout_ms: 2000,
                },
                endpoint: "192.0.2.11".parse().unwrap(),
                allowed: vec!["0.0.0.0/0".parse().unwrap()],
                peer: [3; 32],
            }),
            None,
        ],
        active: None,
        options: Some(nelomai_client_tunnel::DesktopTunnelOptions::default()),
        guard: g::Model::empty(context.intent.scope).unwrap(),
        pending_guard: None,
        pending: Some(p::Effect::MemberStart(Slot::A)),
        network: None,
        stop_stage: 0,
        operation: Some(p::Operation::Start(Slot::A)),
    };
    record.validate().unwrap();
    (record, carrier)
}

#[test]
fn member_key_window_accepts_current_primary_and_addressless_reserve_not_foreign_or_rebind() {
    // Break: mutate precreation keys with a wrong target/C/epoch/operation or
    // an already live interface; key preparation is not rebind permission.
    use crate::{member_carrier_guard as g, member_carrier_pair as p, member_owner as o};
    use nelomai_client_tunnel::redundancy::Slot;
    let (primary, c) = member_pair_fixture();
    validate_member_key_window(&context(), &primary, Role::MemberA, &c, &[None, None]).unwrap();
    let mut reserve = primary.clone();
    reserve.phase = p::Phase::Running;
    reserve.operation = Some(p::Operation::Attach(Slot::B));
    reserve.pending = Some(p::Effect::MemberStart(Slot::B));
    reserve.active = Some(Slot::A);
    let proof = o::InterfaceProof {
        guid: [2; 16],
        index: 8,
        luid: 91,
    };
    reserve.members[1] = reserve.members[0].clone();
    reserve.members[1].as_mut().unwrap().owner.intent.slot =
        nelomai_contracts::dispatcher::TunnelSlot::B;
    reserve.members[1].as_mut().unwrap().lease_id = "33333333-3333-4333-8333-333333333333".into();
    reserve.members[0].as_mut().unwrap().owner.phase = o::Phase::Running;
    reserve.members[0].as_mut().unwrap().owner.proof = Some(o::NativeProof {
        interface: proof,
        process: o::ProcessProof {
            pid: 50,
            creation_time: 100,
        },
    });
    let e = [
        Some(g::Identity {
            scope: reserve.scope.clone(),
            proof,
        }),
        None,
    ];
    reserve.validate().unwrap();
    validate_member_key_window(&context(), &reserve, Role::MemberB, &c, &e).unwrap();
    for fault in 0..12 {
        let mut r = reserve.clone();
        let mut carrier = c.clone();
        let mut actual = e.clone();
        let mut role = Role::MemberB;
        match fault {
            0 => role = Role::RoleCarrier,
            1 => role = Role::MemberA,
            2 => r.provenance.network_epoch += 1,
            3 => r.pending = Some(p::Effect::Rebind(Slot::B)),
            4 => r.operation = Some(p::Operation::Rebind),
            5 => r.members[1].as_mut().unwrap().owner.previous_config_sha256 = Some([8; 32]),
            6 => actual[1] = actual[0].clone(),
            7 => carrier.identity.proof.luid += 1,
            8 => carrier.sources = vec!["10.7.0.3".parse().unwrap()],
            9 => actual[0] = None,
            10 => r.carrier = None,
            11 => r.stop_stage = 1,
            _ => unreachable!(),
        }
        assert!(
            validate_member_key_window(&context(), &r, role, &carrier, &actual).is_err(),
            "fault{fault}"
        );
    }
}

#[test]
fn live_member_key_restore_requires_original_closed_target_and_completed_retire_order() {
    use crate::{member_carrier_guard as g, member_carrier_pair as p, member_owner as o};
    use nelomai_client_tunnel::redundancy::Slot;
    let (mut record, carrier) = member_pair_fixture();
    record.phase = p::Phase::Running;
    record.active = Some(Slot::A);
    record.operation = Some(p::Operation::Retire(Slot::B));
    record.pending = Some(p::Effect::RestoreKeys);
    record.members[1] = record.members[0].clone();
    let proof = |id: u8| o::NativeProof {
        interface: o::InterfaceProof {
            guid: [id; 16],
            index: 6 + id as u32,
            luid: 89 + id as u64,
        },
        process: o::ProcessProof {
            pid: 40 + id as u32,
            creation_time: 100 + id as u64,
        },
    };
    for i in 0..2 {
        let member = record.members[i].as_mut().unwrap();
        member.owner.intent.slot = if i == 0 {
            nelomai_contracts::dispatcher::TunnelSlot::A
        } else {
            nelomai_contracts::dispatcher::TunnelSlot::B
        };
        member.owner.phase = o::Phase::Running;
        member.owner.proof = Some(proof(i as u8 + 2));
    }
    record.members[1].as_mut().unwrap().lease_id = "33333333-3333-4333-8333-333333333333".into();
    let egress = [
        Some(g::Identity {
            scope: record.scope.clone(),
            proof: proof(2).interface,
        }),
        Some(g::Identity {
            scope: record.scope.clone(),
            proof: proof(3).interface,
        }),
    ];
    record.guard = g::Model::new(
        record.scope.clone(),
        carrier.clone(),
        [
            Some(g::Member {
                identity: egress[0].clone().unwrap(),
                probes: vec![],
            }),
            None,
        ],
        Some(Slot::A),
    )
    .unwrap()
    .without_permits()
    .unwrap();
    record.network = Some(p::NetworkState {
        baseline: p::NetworkSnapshot {
            routes: vec![],
            dns: None,
        },
        current: p::NetworkSnapshot {
            routes: vec![],
            dns: None,
        },
        pending: None,
    });
    let closed_intent = record.members[1].as_ref().unwrap().owner.intent.clone();
    record.validate().unwrap();
    validate_member_restore_window(
        &context(),
        &record,
        Role::MemberB,
        &carrier,
        &egress,
        (&closed_intent, proof(3)),
    )
    .unwrap();
    for fault in 0..16 {
        let mut current = record.clone();
        let mut c = carrier.clone();
        let mut e = egress.clone();
        let mut role = Role::MemberB;
        let mut intent = closed_intent.clone();
        let mut stopped = proof(3);
        match fault {
            0 => role = Role::RoleCarrier,
            1 => role = Role::MemberA,
            2 => current.pending = Some(p::Effect::MemberStop(Slot::B)),
            3 => current.operation = Some(p::Operation::Rebind),
            4 => current.provenance.network_epoch += 1,
            5 => e[1] = None,
            6 => stopped.process.creation_time += 1,
            7 => intent.config_sha256 = [9; 32],
            8 => {
                current.guard = g::Model::new(
                    current.scope.clone(),
                    carrier.clone(),
                    [
                        Some(g::Member {
                            identity: e[0].clone().unwrap(),
                            probes: vec![],
                        }),
                        None,
                    ],
                    Some(Slot::A),
                )
                .unwrap()
            }
            9 => c.identity.proof.luid += 1,
            10 => e[0] = None,
            11 => {
                current.network.as_mut().unwrap().pending =
                    Some(current.network.as_ref().unwrap().current.clone())
            }
            12 => current.stop_stage = 1,
            13 => current.network = None,
            14 => e[1].as_mut().unwrap().scope.connection_generation += 1,
            15 => e[1].as_mut().unwrap().proof.luid += 1,
            _ => unreachable!(),
        }
        assert!(
            validate_member_restore_window(&context(), &current, role, &c, &e, (&intent, stopped))
                .is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn root_drop_retains_all_unknown_resources() {
    // Break: implicit Drop of the original key, bootstrap or remaining assets.
    let (mut root, s, mut lock, drops) = attached(Fault::None);
    root.prepare_carrier_in(&mut lock, |call| call()).unwrap();
    drop(root);
    assert_eq!(drops.get(), 0);
    assert_eq!(s.borrow().key_drops.get(), 0);
}

#[test]
fn internal_initial_err_or_unwind_retains_journal_and_cannot_adopt_equal_json() {
    // Break: repairing durable bytes rearms an initialization/attachment attempt.
    for fault in [Fault::InitialLost, Fault::InitialPanic] {
        let (mut root, s, mut lock, drops) = setup(fault);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| root.initialize()));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(s.borrow().record.is_some());
        assert!(root.pending.is_some());
        assert!(root.initial.is_none());
        s.borrow_mut().fault = Fault::None;
        retain_io(&mut root, &s, &drops);
        assert_eq!(root.initialize(), Err(Error::Retired));
        assert!(root.attach_keys(&mut lock).is_err());
        assert_eq!(s.borrow().creates, 0);
        drop(root);
        assert_eq!(drops.get(), 0);
    }
}

#[test]
fn recovered_initial_record_is_not_an_ack() {
    let (mut root, s, mut lock, drops) = setup(Fault::None);
    let mut publisher = PendingNativeOwnership::new(context(), Journal(s.clone()));
    publisher.initialize().unwrap();
    assert_eq!(root.initialize(), Err(Error::Retired));
    retain_io(&mut root, &s, &drops);
    assert!(root.attach_keys(&mut lock).is_err());
    assert_eq!(s.borrow().creates, 0);
}

#[test]
fn missing_io_fences_attachment_and_keeps_other_assets() {
    let (mut root, s, mut lock, drops) = setup(Fault::None);
    root.initialize().unwrap();
    root.assets = Some(Resource(drops.clone()));
    assert_eq!(root.attach_keys(&mut lock), Err(Error::Pending));
    retain_io_without_replacing_assets(&mut root, &s);
    assert_eq!(root.attach_keys(&mut lock), Err(Error::Retired));
    assert!(root.pending.is_some());
    assert!(root.io.is_some());
    assert!(root.owner.is_none());
    assert_eq!(s.borrow().creates, 0);
    drop(root);
    assert_eq!(drops.get(), 0);
}
fn retain_io_without_replacing_assets(root: &mut Root, s: &Shared) {
    root.io = Some(Io::new(Kernel(s.clone()), Authority(s.clone()), context()));
}

#[test]
fn equal_context_foreign_original_lease_cannot_attach_or_retry() {
    let (mut root, s, mut lock, drops) = setup(Fault::None);
    root.initialize().unwrap();
    retain_io(&mut root, &s, &drops);
    let mut foreign = Rc::new(());
    assert_eq!(root.attach_keys(&mut foreign), Err(Error::Conflict));
    assert_eq!(root.attach_keys(&mut lock), Err(Error::Retired));
    assert!(root.pending.is_some());
    assert!(root.io.is_some());
    assert!(root.owner.is_none());
    assert_eq!(s.borrow().creates, 0);
    drop(root);
    assert_eq!(drops.get(), 0);
}

#[test]
fn internal_capture_or_disable_err_and_unwind_keep_exact_key_and_assets() {
    // Break: hold acknowledged key/other assets only in a fallible return value.
    for fault in [
        Fault::CaptureLost,
        Fault::CapturePanic,
        Fault::DisableLost,
        Fault::DisablePanic,
    ] {
        let (mut root, s, mut lock, drops) = attached(fault);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            root.prepare_carrier_in(&mut lock, |call| call())
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(root.owner.is_some());
        assert!(root.assets.is_some());
        assert_eq!(s.borrow().creates, 1);
        assert_eq!(s.borrow().key_drops.get(), 0);
        s.borrow_mut().fault = Fault::None;
        assert_eq!(
            root.prepare_carrier_in(&mut lock, |call| call()),
            Err(Error::Retired)
        );
        assert!(root
            .with_precreation_in(&mut lock, &mut |call| call(), |_, _, _| panic!(
                "failed preparation"
            ))
            .is_err());
        drop(root);
        assert_eq!(drops.get(), 0);
        assert_eq!(s.borrow().key_drops.get(), 0);
    }
}

#[test]
fn callback_internal_err_or_unwind_retains_originals_and_fences_precreation() {
    for unwind in [false, true] {
        let (mut root, s, mut lock, drops) = attached(Fault::None);
        root.prepare_carrier_in(&mut lock, |call| call()).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            root.with_precreation_in(
                &mut lock,
                &mut |call| call(),
                |assets, receipt, generation| {
                    assert_eq!(generation, 5);
                    assert_eq!(receipt.record.generation, 5);
                    assert!(Rc::ptr_eq(&assets.as_ref().unwrap().0, &drops));
                    if unwind {
                        panic!("main construction boundary");
                    }
                    Err(Error::Native)
                },
            )
        }));
        assert!(result.is_err() || result.unwrap() == Err(Error::Native));
        assert_eq!(
            root.with_precreation_in(&mut lock, &mut |call| call(), |_, _, _| panic!("retry")),
            Err(Error::Retired)
        );
        assert_eq!(s.borrow().key_drops.get(), 0);
        drop(root);
        assert_eq!(drops.get(), 0);
    }
}

#[test]
fn actual_current_receipt_after_member_preparation_overrides_cached_carrier_generation() {
    // Break: constructing Scope from cached C preparation rather than its
    // actual CURRENT borrowed receipt after a legitimate later key revision.
    let (mut root, s, mut lock, _) = attached(Fault::None);
    root.prepare_carrier_in(&mut lock, |call| call()).unwrap();
    root.owner
        .as_mut()
        .unwrap()
        .prepare_role(Role::MemberA, &mut lock)
        .unwrap();
    assert_eq!(root.disabled.as_ref().unwrap().generation, 5);
    root.with_precreation_in(&mut lock, &mut |call| call(), |_, receipt, generation| {
        assert_eq!(generation, 9);
        assert_eq!(receipt.record.generation, 9);
        keys::reattest_disabled_original_key(
            &mut Kernel(s.clone()),
            receipt.record,
            receipt.binding,
            receipt.new_key_ack,
        )
    })
    .unwrap();
}

#[test]
fn attachment_internal_err_or_unwind_keeps_both_original_slots_and_assets() {
    for fault in [Fault::AttachErr, Fault::AttachPanic] {
        let (mut root, s, mut lock, drops) = setup(fault);
        root.initialize().unwrap();
        retain_io(&mut root, &s, &drops);
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| root.attach_keys(&mut lock)));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(root.pending.is_some());
        assert!(root.io.is_some());
        assert!(root.assets.is_some());
        assert!(root.owner.is_none());
        assert_eq!(s.borrow().creates, 0);
        s.borrow_mut().fault = Fault::None;
        assert_eq!(root.attach_keys(&mut lock), Err(Error::Retired));
        drop(root);
        assert_eq!(drops.get(), 0);
    }
}

#[test]
fn preparation_attempt_before_attachment_cannot_be_rearmed_by_later_attachment() {
    let (mut root, s, mut lock, drops) = setup(Fault::None);
    assert_eq!(
        root.prepare_carrier_in(&mut lock, |call| call()),
        Err(Error::Pending)
    );
    root.initialize().unwrap();
    retain_io(&mut root, &s, &drops);
    root.attach_keys(&mut lock).unwrap();
    assert_eq!(
        root.prepare_carrier_in(&mut lock, |call| call()),
        Err(Error::Retired)
    );
    assert_eq!(s.borrow().creates, 0);
}

#[test]
fn occupied_owner_is_never_overwritten_and_attachment_cannot_retry() {
    let (mut root, s, mut lock, drops) = setup(Fault::None);
    let (mut original, foreign, _, _) = attached(Fault::None);
    root.initialize().unwrap();
    retain_io(&mut root, &s, &drops);
    root.owner = original.owner.take();
    assert_eq!(root.attach_keys(&mut lock), Err(Error::Conflict));
    assert!(root.pending.is_some());
    assert!(root.io.is_some());
    assert!(root.owner.is_some());
    assert_eq!(root.attach_keys(&mut lock), Err(Error::Retired));
    assert_eq!(s.borrow().creates, 0);
    assert_eq!(foreign.borrow().creates, 0);
    drop(root);
    assert_eq!(drops.get(), 0);
}

fn internal_create_retention(fault: Fault) {
    let (mut root, s, mut lock, drops) = attached(fault);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        root.prepare_carrier_in(&mut lock, |call| call())
    }));
    assert!(result.is_err() || result.unwrap().is_err());
    assert!(root.owner.is_some());
    assert!(root.assets.is_some());
    assert_eq!(s.borrow().creates, 1);
    assert_eq!(
        root.prepare_carrier_in(&mut lock, |call| call()),
        Err(Error::Retired)
    );
    assert!(root
        .with_precreation_in(&mut lock, &mut |call| call(), |_, _, _| panic!(
            "unacknowledged create"
        ))
        .is_err());
    drop(root);
    assert_eq!(drops.get(), 0);
    assert_eq!(
        s.borrow().key_drops.get(),
        0,
        "existing Keys must retain its internal NEW-key ACK before post-create flush"
    );
}
#[test]
fn internal_native_keys_create_error_requires_original_ack_retention() {
    internal_create_retention(Fault::CreateFlushErr);
}
#[test]
fn internal_native_keys_create_unwind_requires_original_ack_retention() {
    internal_create_retention(Fault::CreateFlushPanic);
}
