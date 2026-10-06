//! Durable creator-process comparison data, never original native ownership.
#![allow(dead_code)] // Factory remains gated until concrete consumers are joined.

use crate::{
    member_carrier_native_ownership::{validate_context, Context},
    member_owner::ProcessProof,
};
use serde::{Deserialize, Serialize};
use std::{cell::Cell, io, rc::Rc};

const MAX_BYTES: usize = 16 * 1024;
fn conflict() -> io::Error {
    io::Error::other("carrier_creator_lifetime_unproven")
}
fn valid_process(p: ProcessProof) -> bool {
    p.pid > 4 && p.creation_time != 0
}

/// Authenticated protected comparison DATA, not a native handle/creator ACK.
/// Missing legacy data remains unknown on the same boot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "WireCreatorRecord")]
pub(crate) struct CreatorRecord {
    version: u32,
    context: Context,
    process: ProcessProof,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCreatorRecord {
    version: u32,
    context: Context,
    process: ProcessProof,
}
impl TryFrom<WireCreatorRecord> for CreatorRecord {
    type Error = io::Error;
    fn try_from(wire: WireCreatorRecord) -> io::Result<Self> {
        let record = Self {
            version: wire.version,
            context: wire.context,
            process: wire.process,
        };
        record.validate()?;
        Ok(record)
    }
}
impl CreatorRecord {
    fn validate(&self) -> io::Result<()> {
        if self.version != 1 || !valid_process(self.process) {
            return Err(conflict());
        }
        validate_context(&self.context).map_err(|_| conflict())
    }
    pub(crate) fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > MAX_BYTES {
            return Err(conflict());
        }
        let record: Self = serde_json::from_slice(bytes).map_err(|_| conflict())?;
        record.validate()?;
        Ok(record)
    }
    pub(crate) fn encode(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| conflict())?;
        if bytes.len() > MAX_BYTES {
            return Err(conflict());
        }
        Ok(bytes)
    }
    pub(crate) fn context(&self) -> &Context {
        &self.context
    }
    pub(crate) fn process(&self) -> ProcessProof {
        self.process
    }
    pub(crate) fn require_context(&self, context: &Context) -> io::Result<()> {
        self.validate()?;
        if self.context != *context {
            return Err(conflict());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessObservation {
    Absent,
    Running(ProcessProof),
    Exited(ProcessProof),
    Unreadable,
}
/// Factual lifetime comparison ONLY. Caller must independently authenticate
/// record, boot, OLD signed installation, private scope, lock and full inventory.
fn require_creator_dead(original: ProcessProof, observed: ProcessObservation) -> io::Result<()> {
    if !valid_process(original) {
        return Err(conflict());
    }
    match observed {
        ProcessObservation::Absent => Ok(()),
        ProcessObservation::Exited(p) if p == original => Ok(()),
        ProcessObservation::Running(p) | ProcessObservation::Exited(p)
            if valid_process(p)
                && p.pid == original.pid
                && p.creation_time > original.creation_time =>
        {
            Ok(())
        }
        _ => Err(conflict()),
    }
}

/// Historical publication outcome, never current read/effect permission. A
/// returned write means the original producer callback returned its ACK; an
/// inner CAS whose callback lost ACK/readback remains unacknowledged here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreatorPublicationReceipt {
    Unattempted,
    AttemptedUnacknowledged,
    WriteAcknowledged,
    Completed,
}

struct CreatorPublication {
    attempted: Cell<bool>,
    write_acknowledged: Cell<bool>,
    completed: Cell<bool>,
    busy: Cell<bool>,
    failed: Cell<bool>,
}
struct PublicationFlight<'a> {
    state: &'a CreatorPublication,
    returned: bool,
}
impl Drop for PublicationFlight<'_> {
    fn drop(&mut self) {
        self.state.busy.set(false);
        if !self.returned {
            self.state.failed.set(true);
        }
    }
}
impl CreatorPublication {
    fn new() -> Self {
        Self {
            attempted: Cell::new(false),
            write_acknowledged: Cell::new(false),
            completed: Cell::new(false),
            busy: Cell::new(false),
            failed: Cell::new(false),
        }
    }
    fn receipt(&self) -> CreatorPublicationReceipt {
        if self.completed.get() {
            CreatorPublicationReceipt::Completed
        } else if self.write_acknowledged.get() {
            CreatorPublicationReceipt::WriteAcknowledged
        } else if self.attempted.get() {
            CreatorPublicationReceipt::AttemptedUnacknowledged
        } else {
            CreatorPublicationReceipt::Unattempted
        }
    }
    fn enter(&self) -> io::Result<PublicationFlight<'_>> {
        if self.failed.get() || self.busy.get() {
            self.failed.set(true);
            return Err(conflict());
        }
        self.busy.set(true);
        Ok(PublicationFlight {
            state: self,
            returned: false,
        })
    }
    fn run<T>(
        &self,
        check: impl Fn() -> io::Result<()>,
        write: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        let mut flight = self.enter()?;
        if self.attempted.replace(true) {
            return Err(conflict());
        }
        check()?;
        if self.failed.get() {
            return Err(conflict());
        }
        let output = write()?;
        // This is the SAME producer callback's returned ACK, not a readback
        // imported after Err. Retain it before ANY fallible postflight.
        self.write_acknowledged.set(true);
        check()?;
        if self.failed.get() {
            return Err(conflict());
        }
        self.completed.set(true);
        flight.returned = true;
        Ok(output)
    }
    /// Read-only original history bracket. Err/unwind/caught reentry poisons
    /// this original permanently. No write callback, rearm or flag repair.
    fn inspect<T>(
        &self,
        check: impl Fn() -> io::Result<()>,
        read: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        let mut flight = self.enter()?;
        if self.receipt() != CreatorPublicationReceipt::Completed {
            return Err(conflict());
        }
        check()?;
        if self.failed.get() {
            return Err(conflict());
        }
        let output = read()?;
        check()?;
        if self.failed.get() {
            return Err(conflict());
        }
        flight.returned = true;
        Ok(output)
    }
}

/// Private, process-owned capsule. Only native capture supplies its Runtime and
/// current kernel record in production. R is identity, NOT an authority trait;
/// the shared policy's sole external IO seam observes the current process.
struct OriginalCreator<R> {
    runtime: Rc<R>,
    record: CreatorRecord,
    bytes: Vec<u8>,
    publication: CreatorPublication,
}
impl<R> OriginalCreator<R> {
    fn new(runtime: Rc<R>, record: CreatorRecord) -> io::Result<Self> {
        let bytes = record.encode()?;
        Ok(Self {
            runtime,
            record,
            bytes,
            publication: CreatorPublication::new(),
        })
    }
    fn verify_published_read(
        &self,
        runtime: &R,
        context: &Context,
        observed: &[u8],
        current: impl Fn() -> io::Result<ProcessProof>,
    ) -> io::Result<()> {
        self.publication.inspect(
            || {
                // Exact retained Rc allocation, not equal DATA or a newly
                // constructed read pin for a supposedly equivalent runtime.
                if !std::ptr::eq(self.runtime.as_ref(), runtime) {
                    return Err(conflict());
                }
                self.record.require_context(context)?;
                if current()? != self.record.process {
                    return Err(conflict());
                }
                Ok(())
            },
            || {
                if observed != self.bytes {
                    return Err(conflict());
                }
                Ok(())
            },
        )
    }
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::windows::member_carrier_key_authority::RuntimeRead;
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, ERROR_INVALID_PARAMETER, FILETIME, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        System::Threading::{
            GetCurrentProcess, GetCurrentProcessId, GetProcessTimes, OpenProcess,
            WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        },
    };

    fn times(handle: HANDLE, pid: u32) -> io::Result<ProcessProof> {
        let mut creation: FILETIME = unsafe { std::mem::zeroed() };
        let mut exit: FILETIME = unsafe { std::mem::zeroed() };
        let mut kernel: FILETIME = unsafe { std::mem::zeroed() };
        let mut user: FILETIME = unsafe { std::mem::zeroed() };
        if unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let proof = ProcessProof {
            pid,
            creation_time: (u64::from(creation.dwHighDateTime) << 32)
                | u64::from(creation.dwLowDateTime),
        };
        if !valid_process(proof) {
            return Err(conflict());
        }
        Ok(proof)
    }
    fn current() -> io::Result<ProcessProof> {
        // Pseudo handle must not be closed. Both values come from THIS kernel.
        times(unsafe { GetCurrentProcess() }, unsafe {
            GetCurrentProcessId()
        })
    }
    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    /// No impersonation, DLL load, process creation/termination or blocking wait.
    /// Retain the SAME queried handle for creation-time and zero-time rundown.
    pub(crate) fn observe(record: &CreatorRecord) -> io::Result<ProcessObservation> {
        record.validate()?;
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                record.process.pid,
            )
        };
        if handle.is_null() {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
                Ok(ProcessObservation::Absent)
            } else {
                Err(error)
            };
        }
        let handle = Handle(handle);
        let proof = times(handle.0, record.process.pid)?;
        match unsafe { WaitForSingleObject(handle.0, 0) } {
            WAIT_OBJECT_0 => Ok(ProcessObservation::Exited(proof)),
            WAIT_TIMEOUT => Ok(ProcessObservation::Running(proof)),
            _ => Err(conflict()),
        }
    }
    pub(crate) fn verify_dead(record: &CreatorRecord) -> io::Result<()> {
        require_creator_dead(record.process(), observe(record)?)
    }

    /// Original current-kernel capture rooted before any private publication.
    /// No Serialize/Clone/import constructor: only its comparison record is DATA.
    pub(crate) struct CapturedCreator {
        original: OriginalCreator<RuntimeRead>,
    }
    impl CapturedCreator {
        pub(crate) fn capture(runtime: Rc<RuntimeRead>, context: &Context) -> io::Result<Self> {
            runtime.verify(context).map_err(|_| conflict())?;
            let process = current()?;
            let record = CreatorRecord {
                version: 1,
                context: context.clone(),
                process,
            };
            record.validate()?;
            runtime.verify(context).map_err(|_| conflict())?;
            if current()? != process {
                return Err(conflict());
            }
            Ok(Self {
                original: OriginalCreator::new(runtime, record)?,
            })
        }
        /// One actual protected initial CAS/readback inside the original signed
        /// Runtime/current-process bracket. Unknown/lost ACK/unwind never retries.
        pub(crate) fn publish<T>(
            &self,
            write: impl FnOnce(&CreatorRecord) -> io::Result<T>,
        ) -> io::Result<T> {
            let check = || -> io::Result<()> {
                self.original
                    .runtime
                    .verify(&self.original.record.context)
                    .map_err(|_| conflict())?;
                if current()? != self.original.record.process {
                    return Err(conflict());
                }
                Ok(())
            };
            self.original
                .publication
                .run(check, || write(&self.original.record))
        }
        /// Verify PRESENT bytes against THIS original completed publication.
        /// Requires the exact captured RuntimeRead allocation and current kernel
        /// PID/birth before/after; no decode/import, Session write or native grant.
        ///
        /// Deliberately does not request forward freshness or reenter Runtime IO.
        /// Caller MUST separately bracket the read with factual SAME Runtime,
        /// canonical private files and Calling/Pair checks. This component only
        /// proves original publication continuity inside that outer bracket.
        pub(crate) fn verify_published_read(
            &self,
            runtime: &RuntimeRead,
            context: &Context,
            observed: &[u8],
        ) -> io::Result<()> {
            self.original
                .verify_published_read(runtime, context, observed, current)
        }
    }
}

#[cfg(test)]
#[path = "member_carrier_creator_tests.rs"]
mod tests;
