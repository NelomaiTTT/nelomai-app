//! Factual module-only terminal observations; never an unload/disposal grant.
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReadError {
    Denied,
    Busy,
    Changed,
    Boundary,
}
type ReadResult<T> = Result<T, ReadError>;

/// Pure origin comparison; neither currentness nor Calling/native permission.
struct OriginalRefs<'a, C, L, P, R> {
    candidate: &'a Rc<C>,
    load: &'a Rc<L>,
    pair: &'a Rc<P>,
    expected: &'a R,
}
impl<C, L, P, R: PartialEq> OriginalRefs<'_, C, L, P, R> {
    fn matches(&self, supplied: &Self) -> bool {
        Rc::ptr_eq(self.candidate, supplied.candidate)
            && Rc::ptr_eq(self.load, supplied.load)
            && Rc::ptr_eq(self.pair, supplied.pair)
            && self.expected == supplied.expected
    }
}

/// External readonly boundaries. Origin/Calling verification is mandatory on
/// every side; None values alone never open this policy.
trait ReadIo {
    type Snapshot: Clone + Eq;
    fn fence(&mut self) -> ReadResult<()>;
    fn records(&mut self) -> ReadResult<[Option<Vec<u8>>; 10]>;
    fn verify_initial(&mut self, bytes: &[u8]) -> ReadResult<()>;
    fn verify_creator(&mut self, bytes: &[u8]) -> ReadResult<()>;
    fn native_empty(&mut self) -> ReadResult<()>;
    fn paths_absent(&mut self) -> ReadResult<()>;
    fn snapshot(&mut self) -> ReadResult<Self::Snapshot>;
    fn verify_empty_snapshot(&mut self, snapshot: &Self::Snapshot) -> ReadResult<()>;
}

struct ReadFacts<S> {
    records: [Option<Vec<u8>>; 10],
    snapshot: S,
}

struct RetainedRead<O, S> {
    original: Rc<O>,
    busy: Cell<bool>,
    failed: Cell<bool>,
    records: RefCell<Option<[Option<Vec<u8>>; 10]>>,
    facts: RefCell<Option<ReadFacts<S>>>,
}
impl<O, S: Clone + Eq> RetainedRead<O, S> {
    fn new(original: Rc<O>) -> Self {
        Self {
            original,
            busy: Cell::new(false),
            failed: Cell::new(false),
            records: RefCell::new(None),
            facts: RefCell::new(None),
        }
    }
    fn read<I: ReadIo<Snapshot = S>>(
        &self,
        original: &Rc<O>,
        io: &mut I,
        inspect: impl FnOnce(&ReadFacts<S>) -> ReadResult<()>,
    ) -> ReadResult<()> {
        macro_rules! step {
            ($label:literal, $read:expr) => {
                $read.inspect_err(|_error| {
                    #[cfg(all(test, target_os = "windows"))]
                    crate::windows::member_carrier_factory_test_os::trace_step($label);
                })?
            };
        }
        if self.busy.replace(true) {
            self.failed.set(true);
            return Err(ReadError::Busy);
        }
        let mut flight = Flight {
            read: self,
            complete: false,
        };
        if self.failed.get() || !Rc::ptr_eq(original, &self.original) {
            return Err(ReadError::Denied);
        }
        step!("module-only full read first fence denied", io.fence());
        let records = step!("module-only full read first inventory denied", io.records());
        *self.records.try_borrow_mut().map_err(|_| ReadError::Busy)? = Some(records.clone());
        step!(
            "module-only full read first record shape denied",
            verify_records(io, &records)
        );
        step!(
            "module-only full read first paths denied",
            io.paths_absent()
        );
        step!(
            "module-only full read first native absence denied",
            io.native_empty()
        );
        let snapshot = step!("module-only full read first snapshot denied", io.snapshot());
        // Retain the actual returned observations BEFORE their fallible
        // comparison, callback or postflight. Failure never promotes them.
        *self.facts.try_borrow_mut().map_err(|_| ReadError::Busy)? =
            Some(ReadFacts { records, snapshot });
        let facts = self.facts.try_borrow().map_err(|_| ReadError::Busy)?;
        let facts = facts.as_ref().ok_or(ReadError::Denied)?;
        step!(
            "module-only full read first empty snapshot denied",
            io.verify_empty_snapshot(&facts.snapshot)
        );
        step!("module-only full read callback fence denied", io.fence());
        step!(
            "module-only full read original callback denied",
            inspect(facts)
        );
        step!(
            "module-only full read second paths denied",
            io.paths_absent()
        );
        step!(
            "module-only full read second native absence denied",
            io.native_empty()
        );
        let after = step!(
            "module-only full read second inventory denied",
            io.records()
        );
        step!(
            "module-only full read second record shape denied",
            verify_records(io, &after)
        );
        let snapshot = step!(
            "module-only full read second snapshot denied",
            io.snapshot()
        );
        step!(
            "module-only full read second empty snapshot denied",
            io.verify_empty_snapshot(&snapshot)
        );
        if after != facts.records || snapshot != facts.snapshot {
            #[cfg(all(test, target_os = "windows"))]
            crate::windows::member_carrier_factory_test_os::trace_step(
                "module-only full read observations changed",
            );
            return Err(ReadError::Changed);
        }
        step!("module-only full read final fence denied", io.fence());
        if self.failed.get() {
            return Err(ReadError::Denied);
        }
        flight.complete = true;
        Ok(())
    }
}

fn verify_records<I: ReadIo>(io: &mut I, records: &[Option<Vec<u8>>; 10]) -> ReadResult<()> {
    if records[0].as_ref().is_none_or(Vec::is_empty)
        || records[1].as_ref().is_none_or(Vec::is_empty)
        || [2, 3, 5, 6, 7, 8].iter().any(|i| records[*i].is_some())
    {
        return Err(ReadError::Changed);
    }
    io.verify_initial(records[4].as_deref().ok_or(ReadError::Changed)?)?;
    // NativeCreator precedes initial capture in the actual claimed startup.
    // Its presence is not a NIC/key/export attempt; its bytes are comparison
    // data ONLY. The SAME retained publisher/store must attest its actual ACK.
    io.verify_creator(records[9].as_deref().ok_or(ReadError::Changed)?)
}

struct Flight<'a, O, S> {
    read: &'a RetainedRead<O, S>,
    complete: bool,
}
impl<O, S> Drop for Flight<'_, O, S> {
    fn drop(&mut self) {
        if !self.complete {
            self.read.failed.set(true);
        }
        self.read.busy.set(false);
    }
}

/// Query-only interface: there is deliberately no create/write/delete method.
trait RegistryRead {
    type Key;
    fn interfaces(&mut self) -> ReadResult<Self::Key>;
    fn name(&mut self, key: &Self::Key) -> ReadResult<String>;
    fn open(&mut self, parent: &Self::Key, child: &str) -> ReadResult<Option<Self::Key>>;
}
fn read_registry_absent<K: RegistryRead>(io: &mut K, children: &[&str; 3]) -> ReadResult<()> {
    for (i, child) in children.iter().enumerate() {
        if child.len() != 38
            || child.contains('\\')
            || children[..i].contains(child)
            || !child.bytes().enumerate().all(|(i, c)| match i {
                0 => c == b'{',
                37 => c == b'}',
                9 | 14 | 19 | 24 => c == b'-',
                _ => c.is_ascii_hexdigit(),
            })
        {
            return Err(ReadError::Changed);
        }
    }
    let parent = io.interfaces()?;
    let name = io.name(&parent)?;
    let lower = name.to_ascii_lowercase();
    let number = lower
        .strip_prefix(r"\registry\machine\system\controlset")
        .and_then(|n| n.strip_suffix(r"\services\tcpip\parameters\interfaces"))
        .ok_or(ReadError::Changed)?;
    if number.len() != 3 || number == "000" || !number.bytes().all(|c| c.is_ascii_digit()) {
        return Err(ReadError::Changed);
    }
    for child in children {
        if !io.name(&parent)?.eq_ignore_ascii_case(&name)
            || io.open(&parent, child)?.is_some()
            || !io.name(&parent)?.eq_ignore_ascii_case(&name)
        {
            return Err(ReadError::Changed);
        }
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::{
        member_carrier::{CarrierError as Error, Result},
        member_carrier_guard::{Model, Snapshot},
        member_carrier_native_ownership::{self as receipt, Context},
        member_carrier_pair::Record,
        windows::{
            member_carrier_assembly::native::NativeAssemblyModuleOnlyRead,
            member_carrier_bootstrap::native::NativeBootstrapModuleOnlyRead,
            member_carrier_guard::ScopedGuardAbsence,
            member_carrier_key_authority::{KeyLock, KeyLockPin},
            member_carrier_keys::{win32::Kernel, RegistryKernel},
            member_carrier_module::native::NativeOriginalModuleLoadRead,
            member_carrier_pair_store::native_store::NativePairIntentRead,
            member_carrier_provider::native::inspect_mixed,
            member_carrier_startup::native::NativeStartupModuleOnlyCandidate,
            member_files::{pin_private_directory, PinnedDirectory},
            member_session::RecordKind,
        },
    };
    use nelomai_contracts::dispatcher::TunnelSlot;
    use std::{
        fs::File,
        os::windows::{ffi::OsStrExt, io::FromRawHandle},
    };
    use windows_sys::Win32::{
        Foundation::{
            GetLastError, ERROR_FILE_NOT_FOUND, ERROR_SERVICE_DOES_NOT_EXIST, GENERIC_READ,
            INVALID_HANDLE_VALUE,
        },
        Storage::FileSystem::{
            CreateFileW, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, OPEN_EXISTING, READ_CONTROL,
        },
    };

    // Actual opaque roots only. No owning Startup/LoadedWintun backedge, no
    // converted SourceRead/OriginalImage/Retired-C, and no numeric-handle import.
    struct Originals {
        candidate: Rc<NativeStartupModuleOnlyCandidate>,
        load: Rc<NativeOriginalModuleLoadRead>,
        pair: Rc<NativePairIntentRead>,
        expected: Record,
        assembly: RefCell<Option<Rc<NativeAssemblyModuleOnlyRead>>>,
        bootstrap: RefCell<Option<Rc<NativeBootstrapModuleOnlyRead>>>,
        directory: RefCell<Option<PinnedDirectory>>,
    }

    pub(crate) struct NativeModuleOnlyTerminalRead {
        read: RetainedRead<Originals, Snapshot>,
    }

    /// Borrowed observations only, valid only in the caller's current actual
    /// Calling/Pair bracket. Not a serializable certificate, unload permit,
    /// root-absence issuer, successful rundown or owning disposition outcome.
    pub(crate) struct NativeModuleOnlyTerminalFacts<'a> {
        original: &'a Originals,
        facts: &'a ReadFacts<Snapshot>,
    }
    impl NativeModuleOnlyTerminalFacts<'_> {
        pub(crate) fn same_original(
            &self,
            candidate: &Rc<NativeStartupModuleOnlyCandidate>,
            load: &Rc<NativeOriginalModuleLoadRead>,
            pair: &Rc<NativePairIntentRead>,
        ) -> bool {
            Rc::ptr_eq(candidate, &self.original.candidate)
                && Rc::ptr_eq(load, &self.original.load)
                && Rc::ptr_eq(pair, &self.original.pair)
        }
        pub(crate) fn snapshot(&self) -> &Snapshot {
            &self.facts.snapshot
        }
        pub(crate) fn protected_records(&self) -> &[Option<Vec<u8>>; 10] {
            &self.facts.records
        }
    }

    impl NativeModuleOnlyTerminalRead {
        /// SDK-free lineage/record comparison BEFORE the caller enters its
        /// runner. True is factual equality only: it does not validate a
        /// current ACK, enter Calling, clear a failure, or authorize disposal.
        pub(crate) fn matches_original(
            &self,
            candidate: &Rc<NativeStartupModuleOnlyCandidate>,
            load: &Rc<NativeOriginalModuleLoadRead>,
            pair: &Rc<NativePairIntentRead>,
            expected: &Record,
        ) -> bool {
            let original = &self.read.original;
            OriginalRefs {
                candidate: &original.candidate,
                load: &original.load,
                pair: &original.pair,
                expected: &original.expected,
            }
            .matches(&OriginalRefs {
                candidate,
                load,
                pair,
                expected,
            })
        }

        /// Pure factual retention BEFORE getters/authentication/SDK reads.
        /// Caller must keep this destination and the actual owning Startup on
        /// error/unwind. Occupied destinations are never replaced or retried.
        pub(crate) fn retain_into(
            candidate: &Rc<NativeStartupModuleOnlyCandidate>,
            load: &Rc<NativeOriginalModuleLoadRead>,
            pair: &Rc<NativePairIntentRead>,
            expected: &Record,
            destination: &mut Option<Rc<Self>>,
        ) -> Result<()> {
            if destination.is_some() {
                return Err(Error::Retired);
            }
            let original = Rc::new(Originals {
                candidate: candidate.clone(),
                load: load.clone(),
                pair: pair.clone(),
                expected: expected.clone(),
                assembly: RefCell::new(None),
                bootstrap: RefCell::new(None),
                directory: RefCell::new(None),
            });
            *destination = Some(Rc::new(Self {
                read: RetainedRead::new(original),
            }));
            Ok(())
        }

        /// Read-only; caller MUST already hold actual bounded Calling AND this
        /// SAME Pair's outer inspect frame. The runner, not this reader, proves
        /// positive watchdog rundown after return. No native/storage effects,
        /// supervisor entry, Never history, Source/Retired recursion or grants.
        /// The callback returns unit; originals and observations stay rooted
        /// here before callback/postflight, even on Err or unwind.
        pub(crate) fn read_in_call(
            &self,
            lock: &KeyLock,
            inspect: impl FnOnce(&NativeModuleOnlyTerminalFacts<'_>) -> Result<()>,
        ) -> Result<()> {
            self.read_original_frame(&lock.pin(), false, inspect)
        }

        /// Fresh full factual universe ONLY during the original module's
        /// actual one-shot pre-release aperture. Never a cached snapshot grant;
        /// the caller owns the separate no-constructor release authorization.
        pub(crate) fn read_in_release_pre_call(&self, lock: &KeyLockPin) -> Result<()> {
            let record = &self.read.original.expected;
            if record.phase != crate::member_carrier_pair::Phase::Stopped
                || record.stop_stage != 12
                || record.pending.is_some()
            {
                return Err(Error::Conflict);
            }
            self.read_original_frame(lock, true, |_| Ok(()))
        }
        fn read_original_frame(
            &self,
            lock: &KeyLockPin,
            release_pre: bool,
            inspect: impl FnOnce(&NativeModuleOnlyTerminalFacts<'_>) -> Result<()>,
        ) -> Result<()> {
            let original = &self.read.original;
            let mut io = NativeIo {
                original,
                lock,
                release_pre,
                absence: None,
            };
            self.read
                .read(original, &mut io, |facts| {
                    inspect(&NativeModuleOnlyTerminalFacts { original, facts })
                        .map_err(|_| ReadError::Boundary)
                })
                .map_err(denied)
        }

        /// After actual own-reference release: only SAME current protected
        /// records/original journal/creator/source/Calling checks. No image,
        /// SDK, BFE or native-resource queries; no retry/release authorization.
        pub(crate) fn verify_release_post_in_call(&self, lock: &KeyLockPin) -> Result<()> {
            let original = &self.read.original;
            if self.read.failed.get()
                || self.read.busy.get()
                || original.expected.phase != crate::member_carrier_pair::Phase::Stopped
                || original.expected.stop_stage != 12
                || original.expected.pending.is_some()
            {
                return Err(Error::Retired);
            }
            original
                .candidate
                .verify_read_origin_in_call(&original.pair, &original.expected)?;
            let facts = self.read.facts.try_borrow().map_err(|_| Error::Conflict)?;
            let facts = facts.as_ref().ok_or(Error::Pending)?;
            let mut io = NativeIo {
                original,
                lock,
                release_pre: true,
                absence: None,
            };
            let now = io.records().map_err(denied)?;
            if now != facts.records {
                return Err(Error::Conflict);
            }
            verify_records(&mut io, &now).map_err(denied)?;
            let bootstrap = original.candidate.assembly()?.bootstrap()?;
            let input = bootstrap.original_inputs();
            if !input.runtime.matches_pin(lock) {
                return Err(Error::Conflict);
            }
            lock.verify_source(input.source)
                .map_err(|_| Error::Conflict)?;
            original
                .candidate
                .verify_read_origin_in_call(&original.pair, &original.expected)
        }
    }

    struct NativeIo<'a> {
        original: &'a Originals,
        lock: &'a KeyLockPin,
        release_pre: bool,
        absence: Option<ScopedGuardAbsence<crate::windows::member_carrier_guard::Wfp>>,
    }
    fn denied(error: ReadError) -> Error {
        match error {
            ReadError::Boundary => Error::Native,
            ReadError::Denied => Error::Retired,
            ReadError::Busy | ReadError::Changed => Error::Conflict,
        }
    }
    fn boundary<T>(result: Result<T>) -> ReadResult<T> {
        result.map_err(|_| ReadError::Boundary)
    }
    impl NativeIo<'_> {
        fn bootstrap(&self) -> ReadResult<Rc<NativeBootstrapModuleOnlyRead>> {
            self.original
                .bootstrap
                .try_borrow()
                .map_err(|_| ReadError::Busy)?
                .as_ref()
                .cloned()
                .ok_or(ReadError::Denied)
        }
    }
    impl ReadIo for NativeIo<'_> {
        type Snapshot = Snapshot;
        fn fence(&mut self) -> ReadResult<()> {
            macro_rules! step {
                ($label:literal, $read:expr) => {
                    $read.inspect_err(|_error| {
                        #[cfg(test)]
                        crate::windows::member_carrier_factory_test_os::trace_step($label);
                    })?
                };
            }
            let root = self.original;
            step!(
                "module-only candidate fence denied",
                boundary(
                    root.candidate
                        .verify_read_origin_in_call(&root.pair, &root.expected),
                )
            );
            // The actual owning loader comparison is mandatory. Source/runtime
            // equality or the candidate's successful boundary-return bit is NOT
            // an original LoadLibrary ACK comparison.
            // The owning Startup compared this SAME private load capture on
            // entry; the original native reader freshly reattests it below.
            if root
                .assembly
                .try_borrow()
                .map_err(|_| ReadError::Busy)?
                .is_none()
            {
                *root
                    .assembly
                    .try_borrow_mut()
                    .map_err(|_| ReadError::Busy)? = Some(boundary(root.candidate.assembly())?);
            }
            let assembly = root
                .assembly
                .try_borrow()
                .map_err(|_| ReadError::Busy)?
                .as_ref()
                .cloned()
                .ok_or(ReadError::Denied)?;
            let bootstrap = boundary(assembly.bootstrap())?;
            {
                let mut retained = root
                    .bootstrap
                    .try_borrow_mut()
                    .map_err(|_| ReadError::Busy)?;
                if let Some(old) = retained.as_ref() {
                    if !Rc::ptr_eq(old, &bootstrap) {
                        return Err(ReadError::Changed);
                    }
                } else {
                    *retained = Some(bootstrap.clone());
                }
            }
            let input = bootstrap.original_inputs();
            let record = &root.expected;
            boundary(receipt::validate_context(input.context))?;
            record.validate().map_err(|_| ReadError::Changed)?;
            boundary(
                crate::windows::member_carrier_startup::compare_module_only_read_record(
                    input.context,
                    record,
                ),
            )?;
            if !input.runtime.matches_pin(self.lock)
                || !root.pair.same_store_origin(input.original_intent)
                || !root.load.matches_runtime(input.runtime)
                || !root.load.matches_source(input.source)
            {
                return Err(ReadError::Changed);
            }
            step!(
                "module-only original storage fence denied",
                boundary(
                    input
                        .runtime
                        .verify_same_session_files(input.context, input.files),
                )
            );
            step!(
                "module-only original source fence denied",
                boundary(input.runtime.verify_source(input.source))
            );
            step!(
                "module-only original deadline runtime fence denied",
                boundary(input.deadline.verify_runtime(
                    input.supervisor,
                    input.runtime,
                    input.context,
                ))
            );
            step!(
                "module-only original Calling fence denied",
                boundary(input.deadline.verify_call(input.supervisor, input.context))
            );
            step!(
                "module-only original Pair fence denied",
                root.pair
                    .verify_module_only_read_bracket(
                        input.runtime,
                        input.supervisor,
                        input.context,
                        record,
                    )
                    .map_err(|_| ReadError::Boundary)
            );
            step!(
                "module-only original native image read denied",
                if self.release_pre {
                    root.load
                        .verify_release_pre_read(input.runtime, input.cancelled)
                } else {
                    root.load
                        .verify_cleanup_read(input.runtime, input.cancelled)
                }
                .map_err(|_| ReadError::Boundary)
            );
            boundary(input.runtime.verify_source(input.source))?;
            boundary(
                input
                    .runtime
                    .verify_same_session_files(input.context, input.files),
            )?;
            boundary(input.deadline.verify_call(input.supervisor, input.context))
        }
        fn records(&mut self) -> ReadResult<[Option<Vec<u8>>; 10]> {
            let bootstrap = self.bootstrap()?;
            let input = bootstrap.original_inputs();
            // Two complete inventories bracket runtime authentication through
            // the existing batch reader. Separate per-kind authentication
            // repeats the same package work and cannot form a stronger join.
            let observed: [Option<Vec<u8>>; 10] = boundary(input.runtime.optional_records(
                input.context,
                &[
                    RecordKind::Session,
                    RecordKind::Pair,
                    RecordKind::Network,
                    RecordKind::Carrier,
                    RecordKind::NativeCarrierReceipts,
                    RecordKind::CarrierGuard,
                    RecordKind::CarrierRows,
                    RecordKind::MemberARows,
                    RecordKind::MemberBRows,
                    RecordKind::NativeCreator,
                ],
            ))
            .inspect_err(|_error| {
                #[cfg(test)]
                crate::windows::member_carrier_factory_test_os::trace_step(
                    "module-only original inventory read denied",
                );
            })?
            .try_into()
            .map_err(|_| ReadError::Changed)?;
            // SAME protected Pair store publishes an envelope, not a bare
            // Record. Decode its strict scope-bound carrier payload; a legacy
            // or foreign envelope must still deny, never supply native rights.
            if crate::windows::member_carrier_pair_store::carrier_payload(
                &self.original.expected.scope,
                observed[1].as_deref().ok_or(ReadError::Changed)?,
            )
            .map_err(|_| ReadError::Changed)?
            .as_ref()
                != Some(&self.original.expected)
            {
                return Err(ReadError::Changed);
            }
            Ok(observed)
        }
        fn verify_initial(&mut self, bytes: &[u8]) -> ReadResult<()> {
            let bootstrap = self.bootstrap()?;
            let input = bootstrap.original_inputs();
            if bytes != input.capture_native_bytes {
                return Err(ReadError::Changed);
            }
            // Original ACK/J + authenticated canonical cleanup view, never a
            // decode-only match or reconstructed initialized journal.
            boundary(bootstrap.verify_current_initial(
                &self.original.pair,
                &self.original.expected,
                bytes,
            ))
            .inspect_err(|_error| {
                #[cfg(test)]
                crate::windows::member_carrier_factory_test_os::trace_step(
                    "module-only original initial journal read denied",
                );
            })
        }
        fn verify_creator(&mut self, bytes: &[u8]) -> ReadResult<()> {
            let bootstrap = self.bootstrap()?;
            let input = bootstrap.original_inputs();
            crate::windows::member_carrier_creator::CreatorRecord::decode(bytes)
                .and_then(|record| record.require_context(input.context))
                .map_err(|_| ReadError::Changed)?;
            // Decoding is comparison only. The original Startup must join its
            // SAME retained CapturedCreator and store publication/readback ACK;
            // missing/unknown publication cannot be adopted from these bytes.
            boundary(self.original.candidate.verify_original_creator_in_call(
                &self.original.pair,
                &self.original.expected,
                bytes,
            ))
            .inspect_err(|_error| {
                #[cfg(test)]
                crate::windows::member_carrier_factory_test_os::trace_step(
                    "module-only original creator read denied",
                );
            })
        }
        fn native_empty(&mut self) -> ReadResult<()> {
            if inspect_mixed(&[])
                .map_err(|_| ReadError::Boundary)?
                .is_empty()
            {
                Ok(())
            } else {
                Err(ReadError::Changed)
            }
        }
        fn paths_absent(&mut self) -> ReadResult<()> {
            let bootstrap = self.bootstrap()?;
            let input = bootstrap.original_inputs();
            registry_absent(input.context)?;
            let root = input
                .files
                .original_state_directory()
                .map_err(|_| ReadError::Boundary)?;
            let mut retained = self
                .original
                .directory
                .try_borrow_mut()
                .map_err(|_| ReadError::Busy)?;
            if retained.is_none() {
                *retained = Some(pin_private_directory(&root).map_err(|_| ReadError::Boundary)?);
            }
            let directory = retained.as_ref().ok_or(ReadError::Denied)?;
            directory.verify().map_err(|_| ReadError::Boundary)?;
            for slot in [TunnelSlot::A, TunnelSlot::B] {
                for name in [
                    crate::redundancy::slot_config_filename(slot),
                    match slot {
                        TunnelSlot::A => "nelomai-a.owner.json",
                        TunnelSlot::B => "nelomai-b.owner.json",
                    },
                ] {
                    directory.verify().map_err(|_| ReadError::Boundary)?;
                    let path: Vec<u16> = root
                        .join(name)
                        .as_os_str()
                        .encode_wide()
                        .chain(Some(0))
                        .collect();
                    let handle = unsafe {
                        CreateFileW(
                            path.as_ptr(),
                            GENERIC_READ | READ_CONTROL,
                            FILE_SHARE_READ,
                            std::ptr::null(),
                            OPEN_EXISTING,
                            FILE_FLAG_OPEN_REPARSE_POINT,
                            std::ptr::null_mut(),
                        )
                    };
                    if handle != INVALID_HANDLE_VALUE {
                        drop(unsafe { File::from_raw_handle(handle) });
                        return Err(ReadError::Changed);
                    }
                    if unsafe { GetLastError() } != ERROR_FILE_NOT_FOUND {
                        return Err(ReadError::Boundary);
                    }
                    directory.verify().map_err(|_| ReadError::Boundary)?;
                }
                for transport in [
                    nelomai_client_tunnel::TunnelTransport::WireGuard,
                    nelomai_client_tunnel::TunnelTransport::AmneziaWg3,
                ] {
                    if crate::windows::install::open_slot_service(
                        slot,
                        transport,
                        windows_service::service::ServiceAccess::QUERY_STATUS,
                    )
                    .map_err(|_| ReadError::Boundary)?
                    .is_some()
                    {
                        return Err(ReadError::Changed);
                    }
                }
            }
            let manager = windows_service::service_manager::ServiceManager::local_computer(
                None::<&str>,
                windows_service::service_manager::ServiceManagerAccess::CONNECT,
            )
            .map_err(|_| ReadError::Boundary)?;
            for name in [
                crate::TUNNEL_SERVICE_NAME,
                crate::AMNEZIAWG_TUNNEL_SERVICE_NAME,
            ] {
                match manager
                    .open_service(name, windows_service::service::ServiceAccess::QUERY_STATUS)
                {
                    Err(windows_service::Error::Winapi(e))
                        if e.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) => {}
                    _ => return Err(ReadError::Changed),
                }
            }
            directory.verify().map_err(|_| ReadError::Boundary)
        }
        fn snapshot(&mut self) -> ReadResult<Snapshot> {
            if self.absence.is_none() {
                self.absence = Some(
                    ScopedGuardAbsence::open(self.original.expected.scope.clone())
                        .map_err(|_| ReadError::Boundary)?,
                );
            }
            self.absence
                .as_mut()
                .ok_or(ReadError::Denied)?
                .read_snapshot(&self.original.expected.scope)
                .map_err(|_| ReadError::Boundary)
        }
        fn verify_empty_snapshot(&mut self, snapshot: &Snapshot) -> ReadResult<()> {
            let empty = Model::empty(self.original.expected.scope.clone())
                .map_err(|_| ReadError::Changed)?;
            if snapshot == &empty.expected {
                Ok(())
            } else {
                Err(ReadError::Changed)
            }
        }
    }

    // Read exact children of the real current ControlSet interfaces handle.
    // Presence, symlink/unknown status, parent drift and malformed paths deny.
    // No create/value-write/adoption/delete operation exists in this reader.
    fn registry_absent(context: &Context) -> ReadResult<()> {
        boundary(receipt::validate_context(context))?;
        let mut children = [""; 3];
        for (i, binding) in context.bindings.iter().enumerate() {
            children[i] = binding
                .registry_path
                .strip_prefix(r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\")
                .ok_or(ReadError::Changed)?;
        }
        read_registry_absent(&mut NativeRegistry(Kernel), &children)
    }

    struct NativeRegistry(Kernel);
    impl RegistryRead for NativeRegistry {
        type Key = crate::windows::member_carrier_keys::win32::Handle;
        fn interfaces(&mut self) -> ReadResult<Self::Key> {
            boundary(self.0.interfaces())
        }
        fn name(&mut self, key: &Self::Key) -> ReadResult<String> {
            boundary(self.0.name(key))
        }
        fn open(&mut self, parent: &Self::Key, child: &str) -> ReadResult<Option<Self::Key>> {
            boundary(self.0.open(parent, child))
        }
    }
}

#[cfg(test)]
#[path = "member_carrier_module_terminal_read_tests.rs"]
mod tests;
