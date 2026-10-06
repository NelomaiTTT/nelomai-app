//! Typed composition over the protected MemberFiles record boundary. No path is
//! accepted from IPC. The concrete adapter uses audited MemberFiles handles,
//! without falling back to std::fs reads/writes or native identity adoption.
#![cfg_attr(not(windows), allow(dead_code))] // Portable fake tests have no native caller.
#[cfg(windows)]
use super::member_carrier_creator::CreatorRecord;
#[cfg(windows)]
use super::member_carrier_pair_store as carrier_pair_store;
#[cfg(windows)]
use super::member_files::{previous_config_valid, PrivateFile, PrivateRecords, SessionFileIo};
use crate::member_carrier::{self as carrier, Record as CarrierRecord};
#[cfg(not(windows))]
use crate::member_carrier_creator::CreatorRecord;
use crate::member_carrier_guard as carrier_guard;
use crate::member_carrier_native_ownership::{self as native_receipt, NativeJournal};
#[cfg(not(windows))]
use crate::member_carrier_pair_store as carrier_pair_store;
use crate::member_carrier_rows as rows;
#[cfg(not(windows))]
use crate::member_files::{previous_config_valid, PrivateFile, PrivateRecords, SessionFileIo};
use crate::member_pair::{failed, PairRecord, PairStore};
use nelomai_client_tunnel::redundancy::{
    driver::SessionStore,
    network::{NetworkJournal, NetworkJournalStore},
    session::SessionSnapshot,
    SessionScope,
};
use nelomai_contracts::RuntimeSlot;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io, marker::PhantomData};
#[path = "member_carrier_epoch.rs"]
pub(crate) mod epoch;
#[cfg(windows)]
use super::member_carrier_rows as original_native_rows;
// Actual owner code and sealed receipt in portable transaction tests. SDK
// structs are real windows-sys types; no native implementation is substituted.
#[cfg(all(test, not(windows)))]
#[path = "member_carrier_rows.rs"]
pub(crate) mod original_native_rows;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum RecordKind {
    Session,
    Pair,
    Network,
    Carrier,
    NativeCarrierReceipts,
    CarrierGuard,
    CarrierRows,
    MemberARows,
    MemberBRows,
    NativeCreator,
}
/// Authenticated protected comparison facts ONLY. Exact payloads are preserved;
/// no Session/native ACK, creator, handle, deletion or completion permission.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ProtectedRecoveryRecords {
    pub scope: SessionScope,
    pub provenance: carrier::Provenance,
    pub changed_boot: bool,
    pub records: [(RecordKind, Option<Vec<u8>>); 10],
    // Original canonical index/envelope bytes, not caller-importable authority.
    // Equality across separate read brackets must fence same-looking rewrites.
    stamp: Vec<Option<Vec<u8>>>,
}
type RecoveryTransactionRead = Option<(ProtectedRecoveryRecords, Vec<Option<Vec<u8>>>)>;
/// # Safety
/// PURE callbacks only: issuer must retain the original signed/owner/native
/// FULL-EMPTY proof and SAME selected private snapshot/backend before writes.
/// No SDK, Runtime or backend reentry. begin is one-shot BEFORE any private IO;
/// failures permanently invalidate this attempt. No metadata/native ACK imports.
pub(crate) unsafe trait OriginalColdNativeEmptyProof {
    fn begin_retirement(
        &self,
        origin: &OriginalSessionFilesIdentity,
        expected: &ProtectedRecoveryRecords,
    ) -> io::Result<()>;
    fn verify_retirement(
        &self,
        origin: &OriginalSessionFilesIdentity,
        expected: &ProtectedRecoveryRecords,
    ) -> io::Result<()>;
    fn fail_retirement(&self);
}
/// Actual protected index-CAS/readback ACK only. Neither SDK EMPTY, a Stopped
/// record nor permission to delete/reopen/native Start. No import constructor.
pub(crate) struct ColdRetirementAck {
    scope: SessionScope,
    origin: OriginalSessionFilesIdentity,
}
impl ColdRetirementAck {
    pub(crate) fn scope(&self) -> &SessionScope {
        &self.scope
    }
    pub(crate) fn matches_origin(&self, origin: &OriginalSessionFilesIdentity) -> bool {
        self.origin.same_original(origin)
    }
}
impl ProtectedRecoveryRecords {
    pub(crate) fn creator_obligation(&self) -> io::Result<Option<CreatorRecord>> {
        self.records
            .iter()
            .find(|(k, _)| *k == RecordKind::NativeCreator)
            .and_then(|(_, b)| b.as_deref())
            .map(|b| creator_payload(&self.scope, b))
            .transpose()
    }
    /// Typed comparison of original captured bytes; no new read or ownership.
    pub(crate) fn carrier_obligation(&self) -> io::Result<Option<CarrierRecord>> {
        self.records
            .iter()
            .find(|(k, _)| *k == RecordKind::Carrier)
            .and_then(|(_, b)| b.as_deref())
            .map(|b| carrier_payload(&self.scope, b))
            .transpose()
    }
    pub(crate) fn network_obligation(&self) -> io::Result<Option<NativeNetworkRecord>> {
        self.records
            .iter()
            .find(|(k, _)| *k == RecordKind::Network)
            .and_then(|(_, b)| b.as_deref())
            .map(|b| NativeNetworkRecord::read_comparison(&self.scope, b))
            .transpose()
    }
}
/// Pure retained original native authentication for a sealed known-Create
/// cleanup write. Neither the files adapter nor a JSON record can issue it.
///
/// # Safety
/// The actual native issuer MUST retain SAME Runtime/row root, original creator,
/// acknowledged capture pin and bound Closing/Calling selection. Every check
/// must match the SAME backend/execution identity, sealed original receipt/pin
/// and current protected Pair ACK bytes. No SDK, backend or Runtime inspection
/// or reentry is permitted in callbacks (including under private transactions).
/// fail_write is pure, non-panicking, and irrevocably denies forward use while
/// retaining obligations. This is storage-only; it grants no native effects.
pub(crate) unsafe trait OriginalCreatedAddressCleanupWrite {
    /// Historical original facts ONLY; these must remain accessible after the
    /// Calling sequence expires. They never refresh that sequence or grant IO.
    fn backend_original(&self) -> &OriginalSessionFilesIdentity;
    fn row_original(&self) -> &original_native_rows::RowRecordReadPin;
    fn verify_backend(
        &self,
        origin: &OriginalSessionFilesIdentity,
        original: &original_native_rows::CreatedAddressCleanupRead<'_>,
    ) -> io::Result<()>;
    fn verify_pair(
        &self,
        protected_pair: &[u8],
        original: &original_native_rows::CreatedAddressCleanupRead<'_>,
    ) -> io::Result<()>;
    fn verify_write(
        &self,
        scope: &SessionScope,
        kind: RecordKind,
        expected: &[u8],
        desired: &[u8],
        original: &original_native_rows::CreatedAddressCleanupRead<'_>,
    ) -> io::Result<()>;
    fn fail_write(&self);
}
/// Separate actual initial-invocation storage authority. No initial ACK, known
/// Create authority, forward permission or SDK effects can be inferred from it.
/// # Safety
/// Product issuer MUST bind actual RowOwner A/private initial pin, SAME backend
/// and birth/claim, source-confirmed C, zero row effects and exact Closing/Calling
/// sequence + Pair ACK. All callbacks (including fail_write) are pure: no SDK,
/// Runtime/backend reentry. Retain the original issuer before fallible publication.
pub(crate) unsafe trait OriginalInitialRowCaptureCleanupWrite {
    fn backend_original(&self) -> &OriginalSessionFilesIdentity;
    fn row_original(&self) -> &original_native_rows::RowRecordReadPin;
    fn verify_backend(
        &self,
        origin: &OriginalSessionFilesIdentity,
        original: &original_native_rows::InitialRowCaptureCleanupRead<'_>,
    ) -> io::Result<()>;
    fn verify_pair(
        &self,
        payload: &[u8],
        original: &original_native_rows::InitialRowCaptureCleanupRead<'_>,
    ) -> io::Result<()>;
    fn verify_write(
        &self,
        scope: &SessionScope,
        kind: RecordKind,
        expected: Option<&[u8]>,
        desired: &[u8],
        original: &original_native_rows::InitialRowCaptureCleanupRead<'_>,
    ) -> io::Result<()>;
    fn fail_write(&self);
}
/// Borrowed original native row-generation write capability. Storage-only:
/// this never grants SDK effects, native creation or general epoch adoption.
///
/// # Safety
/// Production implementations MUST be issued only by the actual RuntimeRows
/// root retaining the ACK'd original RowGenerationReceipt/ticket. begin_write
/// must consume one attempt before any IO; failure/reentry/unwind cannot reset
/// it. verify_write must PURELY authenticate that same original scope, role,
/// old exact payload and new exact payload against retained receipt/root facts,
/// including the actual live replacement and pending WeakRows selection. No
/// SDK, Session/backend or Runtime inspection/reentry is allowed in callbacks.
/// verify_backend is called BEFORE begin_write and before the backend lock;
/// it must compare the retained canonical files' original identity. verify_pair
/// must match the SAME retained original Pair ACK's exact payload bytes, not
/// decode/import an ACK. It and verify_write are also called under the private
/// transaction. fail_write must be pure, idempotent and non-panicking, retaining
/// obligations while irrevocably closing this attempted token on Err/unwind.
/// verify_storage_backend must retain the same actual completed Captured pin,
/// registered original token/root and backend identity after full native
/// postflight, or require the initial live capture while still pending. Equal
/// record data, a boolean alone or missing/expired original roots cannot seed
/// historical storage permission. This method never authorizes initial CAS.
pub(crate) unsafe trait OriginalRowGenerationWrite {
    fn begin_write(
        &self,
        scope: &SessionScope,
        kind: RecordKind,
        expected: &[u8],
        desired: &[u8],
    ) -> io::Result<()>;
    fn verify_backend(&self, origin: &OriginalSessionFilesIdentity) -> io::Result<()>;
    /// Ordinary storage continuation after this holder's actual first CAS ACK.
    /// Until full native capture postflight completes, require the same live
    /// capture as verify_backend. Afterwards require ONLY the SAME retained
    /// completed capture/root and backend identity, never live Started/Rows
    /// forward flags. This is not initial-write or SDK authorization.
    fn verify_storage_backend(&self, origin: &OriginalSessionFilesIdentity) -> io::Result<()>;
    /// Completed-only original storage fact, required before ordinary writes
    /// and explicit cleanup handoff. MUST deny pending raw-ACK-only capture.
    /// Requires the same full-completed registered root, retained Captured pin,
    /// initial baseline and backend. May ignore forward-selection revocation
    /// only for this historical storage fact, never initial CAS/SDK permission.
    fn verify_completed_storage_backend(
        &self,
        origin: &OriginalSessionFilesIdentity,
    ) -> io::Result<()>;
    /// Explicit Closing storage ONLY. Requires actual registered original Rows
    /// root's bound Closing, SAME backend/execution parent and retained initial
    /// Captured ACK pin, even if native postflight failed before full completion.
    /// MUST deny missing/uncertain initial CAS ACK; no readback adoption, initial
    /// write retry, forward effect or generic completed-continuation grant. Pure:
    /// no SDK, Runtime/backend inspection or reentry, including under raw locks.
    fn verify_cleanup_storage_backend(
        &self,
        origin: &OriginalSessionFilesIdentity,
    ) -> io::Result<()>;
    fn verify_pair(&self, protected_pair_payload: &[u8]) -> io::Result<()>;
    fn verify_write(
        &self,
        scope: &SessionScope,
        kind: RecordKind,
        old: &[u8],
        new: &[u8],
    ) -> io::Result<()>;
    fn fail_write(&self);
}
/// Opaque original registration/backend and view-root identity; private fields
/// are copied ONLY by actual ProtectedSessionFiles. No JSON/address constructor.
/// Equality is an origin FACT, not freshness, current claim or SDK permission.
#[derive(Clone)]
pub(crate) struct OriginalSessionFilesIdentity {
    registration: std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<epoch::ClaimHistory>>>>,
    execution: Option<std::sync::Weak<epoch::ExecutionState>>,
    runtime: EngineIdentity,
    boot: [u8; 16],
    current_boot: [u8; 16],
}
impl OriginalSessionFilesIdentity {
    pub(crate) fn same_original(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.registration, &other.registration)
            && match (&self.execution, &other.execution) {
                (None, None) => true,
                (Some(a), Some(b)) => std::sync::Weak::ptr_eq(a, b),
                _ => false,
            }
            && self.runtime == other.runtime
            && self.boot == other.boot
            && self.current_boot == other.current_boot
    }
}
struct RowGenerationWriteFlight<'a> {
    authority: &'a dyn OriginalRowGenerationWrite,
    done: bool,
}
type CreatedCleanupWrite<'a> = (
    &'a original_native_rows::CreatedAddressCleanupRead<'a>,
    &'a dyn OriginalCreatedAddressCleanupWrite,
);
type InitialCleanupWrite<'a> = (
    &'a original_native_rows::InitialRowCaptureCleanupRead<'a>,
    &'a dyn OriginalInitialRowCaptureCleanupWrite,
);
enum RowCleanupWrite<'a> {
    Created(CreatedCleanupWrite<'a>),
    Initial(InitialCleanupWrite<'a>),
}
struct InitialCleanupWriteFlight<'a> {
    authority: &'a dyn OriginalInitialRowCaptureCleanupWrite,
    done: bool,
}
impl Drop for InitialCleanupWriteFlight<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.authority.fail_write();
        }
    }
}
struct CreatedCleanupWriteFlight<'a> {
    authority: &'a dyn OriginalCreatedAddressCleanupWrite,
    done: bool,
}
impl Drop for CreatedCleanupWriteFlight<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.authority.fail_write();
        }
    }
}
impl Drop for RowGenerationWriteFlight<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.authority.fail_write();
        }
    }
}
/// All calls run under the existing serialized engine owner. The implementation
/// authenticates runtime, private root/ancestors/handles and envelope scope;
/// bounds individual reads (no enumeration), rejects reparse/hardlinks and flushes CAS.
/// Scope claim is durable and exclusive; an old scope is never reusable.
pub(crate) trait SessionFiles: Clone {
    fn compare_exchange_initial_row_capture_cleanup(
        &mut self,
        _scope: &SessionScope,
        _expected: Option<&[u8]>,
        _desired: &[u8],
        _original: &original_native_rows::InitialRowCaptureCleanupRead<'_>,
        _authority: &dyn OriginalInitialRowCaptureCleanupWrite,
    ) -> io::Result<()> {
        Err(failed())
    }
    fn verify_initial_row_capture_cleanup_registration(
        &self,
        _authority: &dyn OriginalInitialRowCaptureCleanupWrite,
    ) -> io::Result<()> {
        Err(failed())
    }
    fn verify_initial_row_capture_cleanup_origin(
        &self,
        _original: &original_native_rows::InitialRowCaptureCleanupRead<'_>,
        _authority: &dyn OriginalInitialRowCaptureCleanupWrite,
    ) -> io::Result<()> {
        Err(failed())
    }
    /// Authenticated storage context, not native authority. Default denial
    /// prevents adapters exposing bare JSON from becoming carrier stores.
    fn carrier_access(&mut self, _scope: &SessionScope) -> io::Result<CarrierAccess> {
        Err(failed())
    }
    /// Independent protected permission, never inferred from receipt bytes.
    fn native_carrier_access(&mut self, _scope: &SessionScope) -> io::Result<CarrierAccess> {
        Err(failed())
    }
    /// Revoke the shared fresh claim after an unconfirmed receipt mutation.
    /// Required even when a false success left the receipt file absent.
    fn revoke_native_carrier_access(&mut self, _scope: &SessionScope) -> io::Result<()> {
        Err(failed())
    }
    /// Read-only completion/boot fact, not native ownership or cleanup authority.
    fn completed_in_previous_boot(&mut self, _scope: &SessionScope) -> io::Result<bool> {
        Err(failed())
    }
    /// Explicit storage-only cleanup view; never authorizes native effects.
    fn recovery_view(&mut self, _runtime: RuntimeSlot) -> io::Result<Option<(Self, bool)>>
    where
        Self: Sized,
    {
        Ok(None)
    }
    /// Pure origin comparison for an explicit normal-row cleanup handoff.
    /// Concrete files must retain SAME opaque backend and execution root, and
    /// already be the registered typed cleanup view. No generic fallback.
    fn verify_native_row_cleanup_origin(&self, _original: &Self) -> io::Result<()> {
        Err(failed())
    }
    fn scopes(&mut self, runtime: RuntimeSlot) -> io::Result<Vec<SessionScope>>;
    fn claim(&mut self, scope: &SessionScope) -> io::Result<()>;
    fn read(&mut self, scope: &SessionScope, kind: RecordKind) -> io::Result<Option<Vec<u8>>>;
    fn compare_exchange(
        &mut self,
        scope: &SessionScope,
        kind: RecordKind,
        expected: Option<&[u8]>,
        desired: &[u8],
    ) -> io::Result<()>;
    /// No generic adapter may mint a new generation from a stopped JSON row.
    fn compare_exchange_row_generation(
        &mut self,
        _scope: &SessionScope,
        _kind: RecordKind,
        _expected: &[u8],
        _desired: &[u8],
        _authority: &dyn OriginalRowGenerationWrite,
    ) -> io::Result<()> {
        Err(failed())
    }
    fn compare_exchange_created_row_cleanup(
        &mut self,
        _scope: &SessionScope,
        _expected: &[u8],
        _desired: &[u8],
        _original: &original_native_rows::CreatedAddressCleanupRead<'_>,
        _authority: &dyn OriginalCreatedAddressCleanupWrite,
    ) -> io::Result<()> {
        Err(failed())
    }
    fn verify_created_row_cleanup_origin(
        &self,
        _original: &original_native_rows::CreatedAddressCleanupRead<'_>,
        _authority: &dyn OriginalCreatedAddressCleanupWrite,
    ) -> io::Result<()> {
        Err(failed())
    }
    fn verify_created_row_cleanup_registration(
        &self,
        _authority: &dyn OriginalCreatedAddressCleanupWrite,
    ) -> io::Result<()> {
        Err(failed())
    }
    fn verify_row_generation_origin(
        &self,
        _authority: &dyn OriginalRowGenerationWrite,
    ) -> io::Result<()> {
        Err(failed())
    }
    fn verify_row_generation_storage_origin(
        &self,
        _authority: &dyn OriginalRowGenerationWrite,
    ) -> io::Result<()> {
        Err(failed())
    }
    fn verify_completed_row_generation_origin(
        &self,
        _authority: &dyn OriginalRowGenerationWrite,
    ) -> io::Result<()> {
        Err(failed())
    }
    /// Separate explicit Closing capability; no generic metadata fallback.
    fn verify_cleanup_row_generation_origin(
        &self,
        _authority: &dyn OriginalRowGenerationWrite,
    ) -> io::Result<()> {
        Err(failed())
    }
    /// Read-only original completed member-row obligation after a failed CAS.
    /// No files view, writer, ACK or native permission is returned.
    fn read_completed_row_generation(
        &mut self,
        _scope: &SessionScope,
        _kind: RecordKind,
        _authority: &dyn OriginalRowGenerationWrite,
    ) -> io::Result<(CarrierAccess, Option<Vec<u8>>)> {
        Err(failed())
    }
    /// Caller must first verify native cleanup. The adapter also requires the
    /// durable stopped/empty records before releasing the exclusive claim.
    fn complete(&mut self, _scope: &SessionScope) -> io::Result<()> {
        Err(failed())
    }
    /// Explicit crash-gap recovery only. BEFORE calling, the trusted factory
    /// must verify slot/carrier owner journals and native absence/no effects for this
    /// claim. Missing pair data alone is not that proof. Never called by read.
    fn complete_empty(&mut self, _scope: &SessionScope) -> io::Result<()> {
        Err(failed())
    }
}

#[derive(Clone)]
pub(crate) struct CarrierAccess {
    scope: SessionScope,
    provenance: carrier::Provenance,
    fresh: bool,
    registered_native_birth_view: bool,
}
impl CarrierAccess {
    /// Data from the authenticated private claim, not a caller-selected epoch.
    /// Runtime/source/lock and original creator checks remain mandatory.
    pub(crate) fn provenance(&self) -> &carrier::Provenance {
        &self.provenance
    }
    /// Storage-only exact context comparison. This does NOT attest the Context's
    /// GUID/name/native bindings, creator capability, absence or mutation lock.
    /// Cleanup callers must explicitly supply the retained authenticated epoch.
    pub(crate) fn require_native_context(
        &self,
        context: &native_receipt::Context,
    ) -> io::Result<()> {
        if self.scope != context.intent.scope || self.provenance != context.provenance {
            Err(failed())
        } else {
            Ok(())
        }
    }
    pub(crate) fn is_fresh(&self) -> bool {
        self.fresh
    }
    /// True only after this access completed an original native storage flight.
    /// Identifies immutable birth provenance; not SDK permission, current phase,
    /// root liveness or an independently reusable execution lease.
    pub(crate) fn is_registered_native_birth_view(&self) -> bool {
        self.registered_native_birth_view
    }
}

const MAX_PAYLOAD: usize = 16 * 1024 * 1024;
// Unpublished v1 is intentionally rejected, NOT migrated or truncated. Permanent
// anti-replay markers are separate protected files; this index is constant-size.
const PRIVATE_VERSION: u32 = 2;
type EngineIdentity = nelomai_contracts::dispatcher::EngineIdentity;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionIdentity {
    boot_id: [u8; 16],
    runtime: EngineIdentity,
    scope: SessionScope,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionIndex {
    version: u32,
    active: Option<SessionIdentity>,
    // Only identities still represented by the fixed owned record files.
    // Never the replay authority. Partial overwrites can leave OWNED.len() owners.
    completed: Vec<SessionIdentity>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletedRecord {
    version: u32,
    identity: SessionIdentity,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ColdCompletedRecord {
    version: u32,
    identity: SessionIdentity,
    cold_empty: ColdRetirementStamp,
}
/// Distinct from cold SDK-empty and ordinary native Stopped completion. This
/// permanent marker preserves only authenticated initial NoC DATA disposition.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialDataCompletedRecord {
    version: u32,
    identity: SessionIdentity,
    initial_noc: ColdRetirementStamp,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ColdRetirementStamp {
    version: u32,
    records: Vec<(RecordKind, Option<[u8; 32]>)>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedRecord {
    version: u32,
    identity: SessionIdentity,
    kind: RecordKind,
    network_epoch: u64,
    data: String,
}
struct Backend<I> {
    io: I,
    fresh: Option<SessionScope>,
}
/// Trusted factory supplies the authenticated runtime and an OS boot identifier.
/// No clock/PID fallback. Clones share the process-local claim, not a new Start.
pub(crate) struct ProtectedSessionFiles<I> {
    backend: std::sync::Arc<std::sync::Mutex<Backend<I>>>,
    epoch_history: std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<epoch::ClaimHistory>>>>,
    native_execution: Option<std::sync::Weak<epoch::ExecutionState>>,
    native_cleanup: bool,
    runtime: EngineIdentity,
    boot: [u8; 16],
    // Unlike the retained identity boot, this never changes in cleanup views.
    current_boot: [u8; 16],
    cleanup_only: bool,
    retained_scope: Option<SessionScope>,
}
#[cfg(windows)]
pub(crate) type NativeSessionFiles = ProtectedSessionFiles<super::member_files::MemberFiles>;
#[cfg(windows)]
impl NativeSessionFiles {
    /// Pure captured backend path, not caller metadata or an installation-root
    /// alias. No IO/readiness/claim/SDK authority; caller separately pins it.
    pub(crate) fn original_state_directory(&self) -> io::Result<std::path::PathBuf> {
        Ok(self.backend_guard()?.io.original_state_root().to_owned())
    }
    pub(crate) fn retire_cold_member_data(
        &mut self,
        proof: &super::member_carrier_recovery::native::NativeColdMemberWriteRead<'_>,
        slot: nelomai_contracts::dispatcher::TunnelSlot,
        original: &mut Option<super::member_files::PinnedPayload>,
        history: &std::rc::Rc<
            std::cell::RefCell<Vec<std::rc::Rc<super::member_files::ColdMemberStorageAck>>>,
        >,
    ) -> io::Result<()> {
        if self.native_execution.is_some() {
            return Err(failed());
        }
        proof.verify_backend(&self.read_identity())?;
        let mut backend = self.backend_guard()?;
        backend.fresh = None;
        backend
            .io
            .retire_cold_member_data(proof, slot, original, history)
            .map_err(|_| failed())?;
        proof.verify_backend(&self.read_identity())
    }
}
impl<I> Clone for ProtectedSessionFiles<I> {
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
            epoch_history: self.epoch_history.clone(),
            native_execution: self.native_execution.clone(),
            native_cleanup: self.native_cleanup,
            runtime: self.runtime.clone(),
            boot: self.boot,
            current_boot: self.current_boot,
            cleanup_only: self.cleanup_only,
            retained_scope: self.retained_scope.clone(),
        }
    }
}
impl<I> ProtectedSessionFiles<I> {
    /// Pure original registration/backend and view-root identity. Neither
    /// locks private storage nor authenticates freshness/current claim/SDK.
    pub(crate) fn read_identity(&self) -> OriginalSessionFilesIdentity {
        OriginalSessionFilesIdentity {
            registration: self.epoch_history.clone(),
            execution: self.native_execution.clone(),
            runtime: self.runtime.clone(),
            boot: self.boot,
            current_boot: self.current_boot,
        }
    }
}
impl<I: SessionFileIo> ProtectedSessionFiles<I> {
    pub(crate) fn retire_native_empty(
        &mut self,
        expected: &ProtectedRecoveryRecords,
        proof: &dyn OriginalColdNativeEmptyProof,
        retain: impl FnOnce(std::rc::Rc<ColdRetirementAck>) -> io::Result<()>,
    ) -> io::Result<std::rc::Rc<ColdRetirementAck>> {
        let origin = self.read_identity();
        // Publish one-shot invocation before even taking the backend lock.
        proof.begin_retirement(&origin, expected)?;
        struct Flight<'a>(&'a dyn OriginalColdNativeEmptyProof, bool);
        impl Drop for Flight<'_> {
            fn drop(&mut self) {
                if !self.1 {
                    self.0.fail_retirement();
                }
            }
        }
        let mut flight = Flight(proof, false);
        if self.native_execution.is_some()
            || expected.provenance.runtime.slot != self.runtime.slot
            || expected.changed_boot != (expected.provenance.boot_id != self.current_boot)
        {
            return Err(failed());
        }
        let mut backend = self.backend_guard()?;
        backend.fresh = None;
        let ack = backend
            .io
            .transaction(|files| {
                let (raw, mut index, identity) = match_cold_snapshot(files, expected)?;
                // Context is DATA for independent queries, not Runtime/SDK authority.
                let context = match expected
                    .records
                    .iter()
                    .find(|(k, _)| *k == RecordKind::NativeCarrierReceipts)
                    .and_then(|(_, b)| b.as_deref())
                {
                    Some(bytes) => {
                        native_receipt::Record::decode(bytes)
                            .map_err(|_| failed())?
                            .context
                    }
                    None => expected
                        .records
                        .iter()
                        .find(|(k, _)| *k == RecordKind::CarrierGuard)
                        .and_then(|(_, b)| b.as_deref())
                        .map(CarrierGuardRecord::decode)
                        .transpose()?
                        .map(|r| r.context)
                        .or(expected
                            .records
                            .iter()
                            .find(|(k, _)| *k == RecordKind::NativeCreator)
                            .and_then(|(_, b)| b.as_deref())
                            .map(CreatorRecord::decode)
                            .transpose()?
                            .map(|r| r.context().clone()))
                        .ok_or_else(failed)?,
                };
                native_receipt::validate_context(&context).map_err(|_| failed())?;
                if context.intent.scope != identity.scope
                    || context.provenance.boot_id != identity.boot_id
                    || context.provenance.runtime != identity.runtime
                    || context.provenance.network_epoch > expected.provenance.network_epoch
                {
                    return Err(failed());
                }
                if let Some(bytes) = expected
                    .records
                    .iter()
                    .find(|(k, _)| *k == RecordKind::Pair)
                    .and_then(|(_, b)| b.as_deref())
                {
                    if !matches!(
                        carrier_pair_store::decode_pair_payload(&identity.scope, bytes)?,
                        crate::member_carrier_pair::CleanupRecord::Carrier(_)
                    ) {
                        return Err(failed());
                    }
                }
                proof.verify_retirement(&origin, expected)?;
                let mut stamp = ColdRetirementStamp {
                    version: 1,
                    records: RecordKind::OWNED.map(|kind| (kind, None)).to_vec(),
                };
                let mut residual = Vec::new();
                for (i, (kind, digest)) in stamp.records.iter_mut().enumerate() {
                    if let Some(bytes) = &expected.stamp[i + 1] {
                        let saved = parse_record(*kind, bytes)?;
                        if saved.identity == identity {
                            *digest = Some(Sha256::digest(bytes).into());
                        } else if !index.completed.contains(&saved.identity) {
                            return Err(failed());
                        }
                        if !residual.contains(&saved.identity) {
                            residual.push(saved.identity);
                        }
                    }
                }
                if !residual.contains(&identity) {
                    return Err(failed());
                }
                let marker = completed_file(&identity.scope)?;
                let marker_bytes = serde_json::to_vec(&ColdCompletedRecord {
                    version: 2,
                    identity: identity.clone(),
                    cold_empty: stamp,
                })
                .map_err(|_| failed())?;
                if marker_bytes.len() > marker.limit() {
                    return Err(failed());
                }
                match files.read(marker)? {
                    Some(bytes) if bytes == marker_bytes => {} // NEW native proof required even on retry
                    Some(_) => return Err(failed()), // never overwrite another/legacy disposition
                    None => {
                        files.compare_exchange(marker, None, &marker_bytes)?;
                    }
                }
                if files.read(marker)?.as_deref() != Some(marker_bytes.as_slice()) {
                    return Err(failed());
                }
                // Marker is replay history, not release: actual active index remains
                // unchanged through marker failures. Recheck ALL original bytes.
                match_cold_snapshot(files, expected)?;
                proof.verify_retirement(&origin, expected)?;
                index.completed = residual;
                index.active = None;
                save_index(files, raw.as_deref(), &index)?; // single atomic claim-retirement CAS + exact readback
                let ack = std::rc::Rc::new(ColdRetirementAck {
                    scope: identity.scope.clone(),
                    origin: origin.clone(),
                });
                retain(ack.clone())?; // before private/native postflight, never from equal bytes after lost CAS ACK
                for (i, kind) in RecordKind::OWNED.iter().enumerate() {
                    if files.read(kind.file())? != expected.stamp[i + 1] {
                        return Err(failed());
                    }
                }
                if files.read(marker)?.as_deref() != Some(marker_bytes.as_slice()) {
                    return Err(failed());
                }
                let (_, after) = load_index(files)?;
                if after.active.is_some() || after.completed != index.completed {
                    return Err(failed());
                }
                require_retired_records(files, &after)?;
                proof.verify_retirement(&origin, expected)?;
                Ok(ack)
            })
            .map_err(|_| failed())?;
        flight.1 = true;
        Ok(ack)
    }
    /// Pure constructor/view origin, checked against independently signed
    /// installed identity and CURRENT native boot by factory recovery entry.
    /// No claim, journal epoch adoption or native effect permission.
    pub(crate) fn require_recovery_runtime_origin(
        &self,
        runtime: &EngineIdentity,
        current_boot: [u8; 16],
    ) -> io::Result<()> {
        if self.runtime != *runtime || self.current_boot != current_boot || current_boot == [0; 16]
        {
            return Err(failed());
        }
        Ok(())
    }
    /// Fixed inventory under the original private transaction, before/after
    /// callback. Callback is PURE decoding/comparison: no Runtime/SDK/backend
    /// reentry. The native caller brackets it outside this transaction with its
    /// actual signed RuntimeRead and SAME held engine-owner lease.
    pub(crate) fn inspect_recovery_records<T>(
        &mut self,
        runtime: RuntimeSlot,
        inspect: impl FnOnce(&ProtectedRecoveryRecords) -> io::Result<T>,
    ) -> io::Result<Option<T>> {
        if runtime != self.runtime.slot {
            return Err(failed());
        }
        let mut backend = self.backend_guard()?;
        backend.fresh = None; // selection is cleanup-only BEFORE callback/IO
        backend
            .io
            .transaction(|files| {
                let read = |files: &mut dyn PrivateRecords| -> io::Result<RecoveryTransactionRead> {
                    let (raw_index, index) = load_index(files)?;
                    let Some(identity) = index.active.as_ref() else {
                        require_retired_records(files, &index)?;
                        return Ok(None);
                    };
                    if identity.runtime.slot != runtime
                        || self
                            .retained_scope
                            .as_ref()
                            .is_some_and(|scope| *scope != identity.scope)
                        || (self.cleanup_only && self.identity(&identity.scope)? != *identity)
                    {
                        return Err(failed());
                    }
                    require_active(&index, identity)?;
                    let epoch = current_epoch(files, &index, identity)?;
                    let mut stamp = vec![raw_index];
                    let mut records = RecordKind::OWNED.map(|kind| (kind, None));
                    for (kind, payload) in &mut records {
                        let (raw, saved) = load_record(files, &index, identity, *kind)?;
                        if saved.as_ref().is_some_and(|r| r.network_epoch > epoch) {
                            return Err(failed());
                        }
                        stamp.push(raw);
                        *payload = saved.map(|r| r.data.into_bytes());
                    }
                    require_native_obligation(files, &index, identity)?;
                    Ok(Some((
                        ProtectedRecoveryRecords {
                            scope: identity.scope.clone(),
                            provenance: carrier::Provenance {
                                boot_id: identity.boot_id,
                                runtime: identity.runtime.clone(),
                                network_epoch: epoch,
                            },
                            changed_boot: identity.boot_id != self.current_boot,
                            records,
                            stamp: stamp.clone(),
                        },
                        stamp,
                    )))
                };
                let Some((facts, before)) = read(files)? else {
                    return Ok(None);
                };
                // Native execution is still exact; only an explicitly issued typed
                // cleanup view may bypass forward history. No old-epoch promotion.
                let native = self.native_flight(&facts.scope)?;
                if let Some(flight) = &native {
                    flight.verify(files)?;
                    for (kind, payload) in &facts.records {
                        if *kind != RecordKind::Session {
                            if let Some(bytes) = payload {
                                flight.verify_record(*kind, bytes)?;
                            }
                        }
                    }
                }
                let value = inspect(&facts)?;
                let Some((after, stamp)) = read(files)? else {
                    return Err(failed());
                };
                if facts != after || before != stamp {
                    return Err(failed());
                }
                if let Some(flight) = native {
                    flight.verify(files)?;
                    flight.finish();
                }
                Ok(Some(value))
            })
            .map_err(|_| failed())
    }
    fn revoke_epoch_read(&self) {
        if let Ok(slot) = self.epoch_history.try_lock() {
            if let Some(history) = slot.as_ref() {
                history.revoke();
            }
        }
    }
    fn backend_guard(&self) -> io::Result<std::sync::MutexGuard<'_, Backend<I>>> {
        self.backend.try_lock().map_err(|_| {
            self.revoke_epoch_read();
            failed()
        })
    }
    pub(crate) fn session_ack_root(
        &self,
        scope: &SessionScope,
    ) -> io::Result<epoch::SessionAckRoot<I>> {
        epoch::SessionAckRoot::from_original(self, scope)
    }
    pub(crate) fn native_birth_view(
        &self,
        execution: &epoch::ExecutionRoot<I>,
    ) -> io::Result<Self> {
        execution.view(self)
    }
    fn native_flight(
        &self,
        scope: &SessionScope,
    ) -> io::Result<Option<epoch::ExecutionStorageFlight>> {
        epoch::ExecutionStorageFlight::begin(self, scope)
    }
    /// Comparison of the original backend/context ONLY. This neither grants a
    /// claim nor tests current private-file validity/freshness or native absence.
    #[allow(dead_code)] // Used by actual Windows RuntimeRead composition.
    pub(crate) fn same_original_backend(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.backend, &other.backend)
            && self.runtime == other.runtime
            && self.boot == other.boot
            && self.current_boot == other.current_boot
    }
    pub(crate) fn new(io: I, runtime: EngineIdentity, boot: [u8; 16]) -> io::Result<Self> {
        if boot == [0; 16] || !valid_runtime(&runtime) {
            return Err(failed());
        }
        Ok(Self {
            backend: std::sync::Arc::new(std::sync::Mutex::new(Backend { io, fresh: None })),
            epoch_history: std::sync::Arc::new(std::sync::Mutex::new(None)),
            native_execution: None,
            native_cleanup: false,
            runtime,
            boot,
            current_boot: boot,
            cleanup_only: false,
            retained_scope: None,
        })
    }
    fn identity(&self, scope: &SessionScope) -> io::Result<SessionIdentity> {
        if !scope.validate()
            || scope.runtime != self.runtime.slot
            || self.retained_scope.as_ref().is_some_and(|old| old != scope)
        {
            return Err(failed());
        }
        Ok(SessionIdentity {
            boot_id: self.boot,
            runtime: self.runtime.clone(),
            scope: scope.clone(),
        })
    }
}
impl<I: SessionFileIo> SessionFiles for ProtectedSessionFiles<I> {
    fn verify_initial_row_capture_cleanup_registration(
        &self,
        authority: &dyn OriginalInitialRowCaptureCleanupWrite,
    ) -> io::Result<()> {
        if self.native_execution.is_none()
            || !self
                .read_identity()
                .same_original(authority.backend_original())
        {
            return Err(failed());
        }
        Ok(()) // original registration fact, never a Calling/initial ACK grant
    }
    fn verify_initial_row_capture_cleanup_origin(
        &self,
        original: &original_native_rows::InitialRowCaptureCleanupRead<'_>,
        authority: &dyn OriginalInitialRowCaptureCleanupWrite,
    ) -> io::Result<()> {
        self.verify_initial_row_capture_cleanup_registration(authority)?;
        if !self.cleanup_only
            || !self.native_cleanup
            || !original.matches_record_original(authority.row_original())
        {
            return Err(failed());
        }
        authority.verify_backend(&self.read_identity(), original)
    }
    fn verify_created_row_cleanup_registration(
        &self,
        authority: &dyn OriginalCreatedAddressCleanupWrite,
    ) -> io::Result<()> {
        if self.native_execution.is_none()
            || !self
                .read_identity()
                .same_original(authority.backend_original())
        {
            return Err(failed());
        }
        Ok(()) // pure SAME original registration, NEVER Calling permission
    }
    fn verify_created_row_cleanup_origin(
        &self,
        original: &original_native_rows::CreatedAddressCleanupRead<'_>,
        authority: &dyn OriginalCreatedAddressCleanupWrite,
    ) -> io::Result<()> {
        if !self.cleanup_only || !self.native_cleanup || self.native_execution.is_none() {
            return Err(failed());
        }
        authority.verify_backend(&self.read_identity(), original)
    }
    fn verify_native_row_cleanup_origin(&self, original: &Self) -> io::Result<()> {
        if !self.cleanup_only
            || !self.native_cleanup
            || self.native_execution.is_none()
            || !self
                .read_identity()
                .same_original(&original.read_identity())
        {
            return Err(failed());
        }
        Ok(())
    }
    fn verify_row_generation_origin(
        &self,
        authority: &dyn OriginalRowGenerationWrite,
    ) -> io::Result<()> {
        authority.verify_backend(&self.read_identity())
    }
    fn verify_row_generation_storage_origin(
        &self,
        authority: &dyn OriginalRowGenerationWrite,
    ) -> io::Result<()> {
        authority.verify_storage_backend(&self.read_identity())
    }
    fn verify_completed_row_generation_origin(
        &self,
        authority: &dyn OriginalRowGenerationWrite,
    ) -> io::Result<()> {
        authority.verify_completed_storage_backend(&self.read_identity())
    }
    fn verify_cleanup_row_generation_origin(
        &self,
        authority: &dyn OriginalRowGenerationWrite,
    ) -> io::Result<()> {
        authority.verify_cleanup_storage_backend(&self.read_identity())
    }
    fn read_completed_row_generation(
        &mut self,
        scope: &SessionScope,
        kind: RecordKind,
        authority: &dyn OriginalRowGenerationWrite,
    ) -> io::Result<(CarrierAccess, Option<Vec<u8>>)> {
        if !matches!(kind, RecordKind::MemberARows | RecordKind::MemberBRows) {
            return Err(failed());
        }
        authority.verify_completed_storage_backend(&self.read_identity())?;
        // Product generation stores must have the actual original birth root.
        // Host tests explicitly double only the unsafe native token boundary.
        #[cfg(all(windows, not(test)))]
        if self.native_execution.is_none() {
            return Err(failed());
        }
        let mut factual = self.clone();
        factual.cleanup_only = true;
        factual.native_cleanup = factual.native_execution.is_some();
        factual.retained_scope = Some(scope.clone());
        // The SAME registered Weak execution root/private claim/context and
        // current canonical bytes are verified by the normal cleanup flight.
        // This local view is never published/returned, never writes, and never
        // changes Runtime or restores a forward execution selection.
        let access = factual.native_carrier_access(scope)?;
        let bytes = factual.read(scope, kind)?;
        authority.verify_completed_storage_backend(&factual.read_identity())?;
        Ok((access, bytes))
    }
    fn native_carrier_access(&mut self, scope: &SessionScope) -> io::Result<CarrierAccess> {
        self.carrier_access(scope)
    }
    fn revoke_native_carrier_access(&mut self, scope: &SessionScope) -> io::Result<()> {
        self.identity(scope)?;
        let mut backend = self.backend_guard()?;
        // In-memory permission only; durable active/terminal claims remain intact.
        if backend.fresh.as_ref() == Some(scope) {
            backend.fresh = None;
        }
        Ok(())
    }
    fn carrier_access(&mut self, scope: &SessionScope) -> io::Result<CarrierAccess> {
        let identity = self.identity(scope)?;
        let native = self.native_flight(scope)?;
        let mut backend = self.backend_guard()?;
        let epoch = backend
            .io
            .transaction(|files| {
                let (_, index) = load_index(files)?;
                require_active(&index, &identity)?;
                if let Some(flight) = &native {
                    flight.verify(files)?;
                    Ok(flight.context().provenance.network_epoch)
                } else {
                    current_epoch(files, &index, &identity)
                }
            })
            .map_err(|_| failed())?;
        let registered_native_birth_view = if let Some(flight) = native {
            backend
                .io
                .transaction(|files| flight.verify(files))
                .map_err(|_| failed())?;
            flight.finish();
            true
        } else {
            false
        };
        Ok(CarrierAccess {
            scope: scope.clone(),
            provenance: carrier::Provenance {
                boot_id: identity.boot_id,
                runtime: identity.runtime,
                network_epoch: epoch,
            },
            fresh: !self.cleanup_only && backend.fresh.as_ref() == Some(scope),
            registered_native_birth_view,
        })
    }
    fn completed_in_previous_boot(&mut self, scope: &SessionScope) -> io::Result<bool> {
        if !scope.validate() {
            return Err(failed());
        }
        let mut backend = self.backend_guard()?;
        backend
            .io
            .transaction(|files| {
                let (_, index) = load_index(files)?;
                if index.active.as_ref().is_some_and(|id| id.scope == *scope) {
                    return Err(failed());
                }
                // Physical slots are global. Read the exact permanent marker,
                // even for another runtime slot or an older compacted identity.
                // This does not grant read/write access to that session's records.
                let completed = read_completed(files, scope)?.ok_or_else(failed)?;
                Ok(completed.boot_id != self.current_boot)
            })
            .map_err(|_| failed())
    }
    fn recovery_view(&mut self, runtime: RuntimeSlot) -> io::Result<Option<(Self, bool)>> {
        if runtime != self.runtime.slot {
            return Err(failed());
        }
        if self.native_cleanup {
            // Explicit original native cleanup must not become legacy recovery
            // or adopt the current file epoch. No failure falls through below.
            let scope = self.retained_scope.clone().ok_or_else(failed)?;
            let identity = self.identity(&scope)?;
            let native = self.native_flight(&scope)?.ok_or_else(failed)?;
            let mut backend = self.backend_guard()?;
            let verify = |files: &mut dyn PrivateRecords| {
                native.verify(files)?;
                let (_, index) = load_index(files)?;
                require_active(&index, &identity)?;
                require_native_obligation(files, &index, &identity)?;
                for kind in [
                    RecordKind::Pair,
                    RecordKind::Carrier,
                    RecordKind::NativeCarrierReceipts,
                    RecordKind::CarrierGuard,
                    RecordKind::CarrierRows,
                    RecordKind::MemberARows,
                    RecordKind::MemberBRows,
                ] {
                    if let Some(record) = load_record(files, &index, &identity, kind)?.1 {
                        native.verify_record(kind, record.data.as_bytes())?;
                    }
                }
                native.verify(files)
            };
            backend.io.transaction(verify).map_err(|_| failed())?;
            backend.io.transaction(verify).map_err(|_| failed())?;
            native.finish();
            return Ok(Some((self.clone(), false)));
        }
        let mut backend = self.backend_guard()?;
        let identity = backend
            .io
            .transaction(|files| {
                let (_, index) = load_index(files)?;
                match index.active.as_ref() {
                    Some(id) if id.runtime.slot == runtime => {
                        if self.cleanup_only && self.identity(&id.scope)? != *id {
                            return Err(failed());
                        }
                        require_native_obligation(files, &index, id)?;
                        Ok(Some(id.clone()))
                    }
                    Some(_) => Err(failed()),
                    None => {
                        require_retired_records(files, &index)?;
                        Ok(None)
                    }
                }
            })
            .map_err(|_| failed())?;
        Ok(identity.map(|id| {
            let changed = id.boot_id != self.boot;
            (
                Self {
                    backend: self.backend.clone(),
                    epoch_history: self.epoch_history.clone(),
                    native_execution: None,
                    native_cleanup: false,
                    runtime: id.runtime,
                    boot: id.boot_id,
                    current_boot: self.current_boot,
                    cleanup_only: true,
                    retained_scope: Some(id.scope),
                },
                changed,
            )
        }))
    }
    fn scopes(&mut self, runtime: RuntimeSlot) -> io::Result<Vec<SessionScope>> {
        if runtime != self.runtime.slot {
            return Err(failed());
        }
        let mut backend = self.backend_guard()?;
        backend
            .io
            .transaction(|files| {
                let (_, index) = load_index(files)?;
                match &index.active {
                    Some(id) if self.identity(&id.scope).as_ref().is_ok_and(|own| own == id) => {
                        require_native_obligation(files, &index, id)?;
                        Ok(vec![id.scope.clone()])
                    }
                    Some(_) => Err(failed()), // Retain old journals; never pass old LUIDs to cleanup.
                    None => {
                        require_retired_records(files, &index)?;
                        Ok(vec![])
                    }
                }
            })
            .map_err(|_| failed())
    }
    fn claim(&mut self, scope: &SessionScope) -> io::Result<()> {
        if self.cleanup_only || self.native_execution.is_some() {
            return Err(failed());
        }
        let identity = self.identity(scope)?;
        let mut backend = self.backend_guard()?;
        let birth_epoch = backend
            .io
            .transaction(|files| {
                let (bytes, mut index) = load_index(files)?;
                if index.active.is_some() || read_completed(files, scope)?.is_some() {
                    return Err(failed());
                }
                // Orphan/foreign records cannot become an empty new session merely
                // because an index was removed. Only completed identities may remain.
                require_retired_records(files, &index)?;
                index.active = Some(identity.clone());
                save_index(files, bytes.as_deref(), &index)?;
                current_epoch(files, &index, &identity)
            })
            .map_err(|_| failed())?;
        backend.fresh = Some(scope.clone());
        *self.epoch_history.try_lock().map_err(|_| failed())? = Some(
            epoch::ClaimHistory::new_authenticated_claim(identity, birth_epoch),
        );
        Ok(())
    }
    fn read(&mut self, scope: &SessionScope, kind: RecordKind) -> io::Result<Option<Vec<u8>>> {
        // A birth-bound native facet authenticates typed sidecars, never the
        // unrelated legacy Network journal (including an absent journal).
        if self.native_execution.is_some() && kind == RecordKind::Network {
            return Err(failed());
        }
        let identity = self.identity(scope)?;
        let native = self.native_flight(scope)?;
        let mut backend = self.backend_guard()?;
        let result = backend
            .io
            .transaction(|files| {
                let (_, index) = load_index(files)?;
                require_active(&index, &identity)?;
                if let Some(flight) = &native {
                    flight.verify(files)?;
                }
                let (_, record) = load_record(files, &index, &identity, kind)?;
                if let Some(record) = &record {
                    if kind != RecordKind::Session
                        && record.network_epoch > current_epoch(files, &index, &identity)?
                    {
                        return Err(failed());
                    }
                }
                if let Some(flight) = &native {
                    if let Some(record) = &record {
                        if kind != RecordKind::Session {
                            flight.verify_record(kind, record.data.as_bytes())?;
                        }
                    }
                    flight.verify(files)?;
                }
                Ok(record.map(|r| r.data.into_bytes()))
            })
            .map_err(|_| failed())?;
        if let Some(flight) = native {
            backend
                .io
                .transaction(|files| flight.verify(files))
                .map_err(|_| failed())?;
            flight.finish();
        }
        Ok(result)
    }
    fn compare_exchange(
        &mut self,
        scope: &SessionScope,
        kind: RecordKind,
        expected: Option<&[u8]>,
        desired: &[u8],
    ) -> io::Result<()> {
        self.exchange_private(scope, kind, expected, desired, None, None)
    }
    fn compare_exchange_row_generation(
        &mut self,
        scope: &SessionScope,
        kind: RecordKind,
        expected: &[u8],
        desired: &[u8],
        authority: &dyn OriginalRowGenerationWrite,
    ) -> io::Result<()> {
        let result =
            self.exchange_private(scope, kind, Some(expected), desired, Some(authority), None);
        if result.is_err() {
            let _ = self.revoke_native_carrier_access(scope);
        }
        result
    }
    fn compare_exchange_created_row_cleanup(
        &mut self,
        scope: &SessionScope,
        expected: &[u8],
        desired: &[u8],
        original: &original_native_rows::CreatedAddressCleanupRead<'_>,
        authority: &dyn OriginalCreatedAddressCleanupWrite,
    ) -> io::Result<()> {
        self.exchange_private(
            scope,
            RecordKind::CarrierRows,
            Some(expected),
            desired,
            None,
            Some(RowCleanupWrite::Created((original, authority))),
        )
    }
    fn compare_exchange_initial_row_capture_cleanup(
        &mut self,
        scope: &SessionScope,
        expected: Option<&[u8]>,
        desired: &[u8],
        original: &original_native_rows::InitialRowCaptureCleanupRead<'_>,
        authority: &dyn OriginalInitialRowCaptureCleanupWrite,
    ) -> io::Result<()> {
        self.exchange_private(
            scope,
            RecordKind::CarrierRows,
            expected,
            desired,
            None,
            Some(RowCleanupWrite::Initial((original, authority))),
        )
    }
    fn complete(&mut self, scope: &SessionScope) -> io::Result<()> {
        if self.native_execution.is_some() {
            return Err(failed());
        }
        let identity = self.identity(scope)?;
        let mut backend = self.backend_guard()?;
        backend.fresh = None;
        backend
            .io
            .transaction(|files| {
                let (raw, mut index) = load_index(files)?;
                if already_completed(files, &index, &identity)? {
                    return Ok(());
                }
                require_active(&index, &identity)?;
                let (_, session) = load_record(files, &index, &identity, RecordKind::Session)?;
                let session: SessionSnapshot =
                    decode(scope, session.as_ref().ok_or_else(failed)?.data.as_bytes())?;
                if session.phase
                    != nelomai_client_tunnel::redundancy::session::SessionPhase::Stopped
                {
                    return Err(failed());
                }
                let (_, pair) = load_record(files, &index, &identity, RecordKind::Pair)?;
                if pair
                    .as_ref()
                    .is_some_and(|p| p.network_epoch > session.network_epoch)
                {
                    return Err(failed());
                }
                carrier_pair_store::require_terminal_pair(
                    scope,
                    pair.as_ref().ok_or_else(failed)?.data.as_bytes(),
                )?;
                let (_, network) = load_record(files, &index, &identity, RecordKind::Network)?;
                if let Some(network) = network {
                    let owner =
                        network_owner(network_payload(scope, network.data.as_bytes())?.journal)?;
                    if network.network_epoch > session.network_epoch
                        || owner.has_resources()
                        || owner.active().is_some()
                    {
                        return Err(failed());
                    }
                }
                let (_, carrier) = load_record(files, &index, &identity, RecordKind::Carrier)?;
                if let Some(carrier) = carrier {
                    require_stopped_carrier(&carrier)?;
                    if carrier.network_epoch > session.network_epoch {
                        return Err(failed());
                    }
                }
                let (_, native) =
                    load_record(files, &index, &identity, RecordKind::NativeCarrierReceipts)?;
                if let Some(native) = native {
                    require_stopped_native(&native)?;
                    if native.network_epoch > session.network_epoch {
                        return Err(failed());
                    }
                }
                require_rows_obligations(files, &index, &identity)?;
                if let Some(saved) =
                    load_record(files, &index, &identity, RecordKind::CarrierGuard)?.1
                {
                    require_stopped_guard(&saved)?;
                    if saved.network_epoch > session.network_epoch {
                        return Err(failed());
                    }
                }
                for kind in RecordKind::ROWS {
                    if let Some(saved) = load_record(files, &index, &identity, kind)?.1 {
                        require_stopped_rows(kind, &saved)?;
                        if saved.network_epoch > session.network_epoch {
                            return Err(failed());
                        }
                    }
                }
                finish_completion(files, raw.as_deref(), &mut index, &identity)
            })
            .map_err(|_| failed())?;
        backend.fresh = None;
        Ok(())
    }
    fn complete_empty(&mut self, scope: &SessionScope) -> io::Result<()> {
        let identity = self.identity(scope)?;
        let mut backend = self.backend_guard()?;
        backend.fresh = None;
        backend
            .io
            .transaction(|files| {
                let (raw, mut index) = load_index(files)?;
                if already_completed(files, &index, &identity)? {
                    return Ok(());
                }
                require_active(&index, &identity)?;
                for kind in RecordKind::OWNED {
                    if load_record(files, &index, &identity, kind)?.1.is_some() {
                        return Err(failed());
                    }
                }
                finish_completion(files, raw.as_deref(), &mut index, &identity)
            })
            .map_err(|_| failed())?;
        backend.fresh = None;
        Ok(())
    }
}
impl<I: SessionFileIo> ProtectedSessionFiles<I> {
    fn exchange_private(
        &mut self,
        scope: &SessionScope,
        kind: RecordKind,
        expected: Option<&[u8]>,
        desired: &[u8],
        generation: Option<&dyn OriginalRowGenerationWrite>,
        cleanup: Option<RowCleanupWrite<'_>>,
    ) -> io::Result<()> {
        let (created, initial) = match cleanup {
            Some(RowCleanupWrite::Created(c)) => (Some(c), None),
            Some(RowCleanupWrite::Initial(i)) => (None, Some(i)),
            None => (None, None),
        };
        let mut initial_flight = initial.map(|(_, authority)| InitialCleanupWriteFlight {
            authority,
            done: false,
        });
        if let Some((original, authority)) = initial {
            self.verify_initial_row_capture_cleanup_origin(original, authority)?;
            if kind != RecordKind::CarrierRows || generation.is_some() {
                return Err(failed());
            }
        }
        let mut created_flight = created.map(|(_, authority)| CreatedCleanupWriteFlight {
            authority,
            done: false,
        });
        if let Some((original, authority)) = created {
            self.verify_created_row_cleanup_origin(original, authority)?;
            if kind != RecordKind::CarrierRows || generation.is_some() {
                return Err(failed());
            }
        }
        let mut generation_flight = generation.map(|authority| RowGenerationWriteFlight {
            authority,
            done: false,
        });
        if let Some(authority) = generation {
            authority.verify_backend(&self.read_identity())?;
            authority.begin_write(scope, kind, expected.ok_or_else(failed)?, desired)?;
        }
        if self.native_execution.is_some()
            && matches!(kind, RecordKind::Session | RecordKind::Network)
        {
            return Err(failed());
        }
        let native = self.native_flight(scope)?;
        if (created.is_some() || initial.is_some()) && native.is_none() {
            return Err(failed());
        }
        let history = if kind == RecordKind::Session {
            self.epoch_history.try_lock().map_err(|_| failed())?.clone()
        } else {
            None
        };
        // Portable tests explicitly double only the unsafe native boundary.
        // Product generation writes must use the actual registered birth view.
        #[cfg(all(windows, not(test)))]
        if generation.is_some() && native.is_none() {
            return Err(failed());
        }
        let epoch_flight = history.as_ref().map(|h| h.begin_write(scope)).transpose()?;
        let identity = self.identity(scope)?;
        let mut backend = self.backend_guard()?;
        if let Err(e) = validate_payload(scope, kind, desired) {
            if kind.row_role().is_some()
                || matches!(kind, RecordKind::CarrierGuard | RecordKind::Pair)
            {
                backend.fresh = None;
            }
            return Err(e);
        }
        let fresh = !self.cleanup_only && backend.fresh.as_ref() == Some(scope);
        let result = backend
            .io
            .transaction(|files| {
                let (_, index) = load_index(files)?;
                require_active(&index, &identity)?;
                if let Some(flight) = &native {
                    flight.verify(files)?;
                    flight.verify_record(kind, desired)?;
                }
                let (raw, current) = load_record(files, &index, &identity, kind)?;
                let creator_session = if kind == RecordKind::NativeCreator {
                    Some(require_initial_creator_window(files, &index, &identity)?)
                } else {
                    None
                };
                if let (Some(flight), Some(current)) = (&native, &current) {
                    flight.verify_record(kind, current.data.as_bytes())?;
                }
                if generation.is_some()
                    && !matches!(kind, RecordKind::MemberARows | RecordKind::MemberBRows)
                {
                    return Err(failed());
                }
                let generation_epoch = if generation.is_some() {
                    Some(current_epoch(files, &index, &identity)?)
                } else {
                    None
                };
                let generation_pair = generation
                    .map(|authority| row_generation_pair(files, &index, &identity, authority))
                    .transpose()?;
                let created_pair = created
                    .map(|(original, authority)| {
                        created_cleanup_pair(files, &index, &identity, original, authority)
                    })
                    .transpose()?;
                let initial_pair = initial
                    .map(|(original, authority)| {
                        initial_cleanup_pair(files, &index, &identity, original, authority)
                    })
                    .transpose()?;
                if let (Some(flight), Some(pair)) = (&native, &initial_pair) {
                    flight.verify_record(RecordKind::Pair, pair)?;
                }
                if let (Some(flight), Some(pair)) = (&native, &created_pair) {
                    flight.verify_record(RecordKind::Pair, pair)?;
                }
                if let (Some(flight), Some(pair)) = (&native, &generation_pair) {
                    flight.verify_record(RecordKind::Pair, pair)?;
                }
                let pair_or_guard_epoch =
                    if matches!(kind, RecordKind::CarrierGuard | RecordKind::Pair) {
                        Some(current_epoch(files, &index, &identity)?)
                    } else {
                        None
                    };
                if current.as_ref().map(|r| r.data.as_bytes()) != expected {
                    return Err(failed());
                }
                if self.cleanup_only
                    && kind == RecordKind::Pair
                    && carrier_pair_payload(scope, desired)?.is_none()
                {
                    let next: PairRecord = decode(scope, desired)?;
                    let old = current
                        .as_ref()
                        .map(|r| decode::<PairRecord>(scope, r.data.as_bytes()))
                        .transpose()?;
                    validate_cleanup_pair(old.as_ref(), &next)?;
                }
                let epoch = if kind == RecordKind::Pair {
                    let next = carrier_pair_payload(scope, desired)?;
                    let old = current
                        .as_ref()
                        .map(|r| carrier_pair_payload(scope, r.data.as_bytes()))
                        .transpose()?;
                    // Version selection is immutable for an existing claim.
                    // Neither a legacy cleanup record nor an unknown version can
                    // become the fresh v2 owner (or be erased into legacy).
                    if let Some(old) = &old {
                        if old.is_some() != next.is_some() {
                            return Err(failed());
                        }
                    }
                    let actual_epoch = current_epoch(files, &index, &identity)?;
                    if let Some(next) = next {
                        let retained = next.provenance.network_epoch;
                        if retained > actual_epoch
                            || (fresh
                                && !matches!(
                                    next.phase,
                                    crate::member_carrier_pair::Phase::Closing
                                        | crate::member_carrier_pair::Phase::Stopped
                                )
                                && retained
                                    != native.as_ref().map_or(actual_epoch, |f| {
                                        f.context().provenance.network_epoch
                                    }))
                        {
                            return Err(failed());
                        }
                        // Authenticate from the real private identity/epoch,
                        // not from the supplied Pair JSON or a storage adapter.
                        let provenance = carrier::Provenance {
                            boot_id: identity.boot_id,
                            runtime: identity.runtime.clone(),
                            network_epoch: retained,
                        };
                        carrier_pair_store::validate_carrier_transition(
                            scope,
                            &provenance,
                            old.as_ref().and_then(Option::as_ref),
                            &next,
                            fresh,
                        )?;
                        retained
                    } else {
                        actual_epoch
                    }
                } else if kind == RecordKind::NativeCreator {
                    let next = creator_payload(scope, desired)?;
                    // DATA is published once, before any native journal/effect.
                    // Neither equal JSON nor an existing claim can mint its ACK.
                    if !fresh || current.is_some() || expected.is_some() {
                        return Err(failed());
                    }
                    let epoch = current_epoch(files, &index, &identity)?;
                    authenticate_creator(&next, &identity, epoch)?;
                    if epoch != 1 {
                        return Err(failed());
                    }
                    epoch
                } else if kind == RecordKind::Session {
                    let next: SessionSnapshot = decode(scope, desired)?;
                    use nelomai_client_tunnel::redundancy::session::SessionPhase;
                    if !fresh
                        && !matches!(next.phase, SessionPhase::Stopping | SessionPhase::Stopped)
                    {
                        return Err(failed());
                    }
                    if let Some(old) = &current {
                        let old: SessionSnapshot = decode(scope, old.data.as_bytes())?;
                        if next.network_epoch < old.network_epoch
                            || next.local_revision < old.local_revision
                            || next.role_generation < old.role_generation
                            || next.membership_generation < old.membership_generation
                            || (old.phase == SessionPhase::Stopped
                                && next.phase != SessionPhase::Stopped)
                            || (old.phase == SessionPhase::Stopping
                                && !matches!(
                                    next.phase,
                                    SessionPhase::Stopping | SessionPhase::Stopped
                                ))
                            || (old.phase != SessionPhase::Starting
                                && next.phase == SessionPhase::Starting)
                        {
                            return Err(failed());
                        }
                    }
                    next.network_epoch
                } else if kind == RecordKind::Carrier {
                    let next = carrier_payload(scope, desired)?;
                    let old = current
                        .as_ref()
                        .map(|r| carrier_payload(scope, r.data.as_bytes()))
                        .transpose()?;
                    validate_carrier_transition(old.as_ref(), &next, fresh)?;
                    let epoch = current_epoch(files, &index, &identity)?;
                    if next.provenance.network_epoch > epoch
                        || (fresh
                            && !matches!(
                                next.phase,
                                carrier::Phase::Closing | carrier::Phase::Stopped
                            )
                            && next.provenance.network_epoch
                                != native
                                    .as_ref()
                                    .map_or(epoch, |f| f.context().provenance.network_epoch))
                    {
                        return Err(failed());
                    }
                    authenticate_carrier(&next, &identity, next.provenance.network_epoch)?;
                    // Cleanup keeps the retained envelope epoch, rather than
                    // migrating old carrier provenance to today's session epoch.
                    next.provenance.network_epoch
                } else if kind == RecordKind::NativeCarrierReceipts {
                    let next = native_payload(scope, desired)?;
                    let old = current
                        .as_ref()
                        .map(|r| native_payload(scope, r.data.as_bytes()))
                        .transpose()?;
                    native_receipt::validate_transition(old.as_ref(), &next, !fresh)
                        .map_err(|_| failed())?;
                    let epoch = current_epoch(files, &index, &identity)?;
                    let retained = next.context.provenance.network_epoch;
                    if retained > epoch
                        || (fresh
                            && next.phase == native_receipt::Phase::Preparing
                            && retained
                                != native
                                    .as_ref()
                                    .map_or(epoch, |f| f.context().provenance.network_epoch))
                    {
                        return Err(failed());
                    }
                    authenticate_native(&next, &identity, retained)?;
                    retained
                } else if kind == RecordKind::CarrierGuard {
                    let next = guard_payload(scope, desired)?;
                    let old = current
                        .as_ref()
                        .map(|r| guard_payload(scope, r.data.as_bytes()))
                        .transpose()?;
                    validate_guard_transition(old.as_ref(), &next, fresh)?;
                    let retained = next.context.provenance.network_epoch;
                    let epoch = current_epoch(files, &index, &identity)?;
                    if retained > epoch
                        || (fresh
                            && retained
                                != native
                                    .as_ref()
                                    .map_or(epoch, |f| f.context().provenance.network_epoch))
                    {
                        return Err(failed());
                    }
                    authenticate_guard(&next, &identity, retained)?;
                    retained
                } else if kind.row_role().is_some() {
                    let next = rows_payload(kind, scope, desired)?;
                    let old = current
                        .as_ref()
                        .map(|r| rows_payload(kind, scope, r.data.as_bytes()))
                        .transpose()?;
                    if let Some(authority) = generation {
                        validate_row_generation(
                            kind,
                            old.as_ref().ok_or_else(failed)?,
                            &next,
                            fresh,
                        )?;
                        authority.verify_write(
                            scope,
                            kind,
                            current.as_ref().ok_or_else(failed)?.data.as_bytes(),
                            desired,
                        )?;
                    } else if let Some((original, authority)) = created {
                        let old = old.as_ref().ok_or_else(failed)?;
                        original
                            .verify_exchange(&next.binding, old, &next)
                            .map_err(|_| failed())?;
                        authority.verify_write(
                            scope,
                            kind,
                            expected.ok_or_else(failed)?,
                            desired,
                            original,
                        )?;
                    } else if let Some((original, authority)) = initial {
                        original
                            .verify_exchange(&next.binding, old.as_ref(), &next)
                            .map_err(|_| failed())?;
                        original
                            .verify_payloads(expected, desired)
                            .map_err(|_| failed())?;
                        authority.verify_write(scope, kind, expected, desired, original)?;
                    } else {
                        rows::validate_transition(old.as_ref(), &next, !fresh)
                            .map_err(|_| failed())?;
                    }
                    let epoch = current_epoch(files, &index, &identity)?;
                    let retained = next.binding.network_epoch;
                    if retained > epoch
                        || (fresh
                            && next.phase == rows::Phase::Captured
                            && retained
                                != native
                                    .as_ref()
                                    .map_or(epoch, |f| f.context().provenance.network_epoch))
                    {
                        return Err(failed());
                    }
                    authenticate_rows(&next, &identity, retained)?;
                    require_rows_obligations(files, &index, &identity)?;
                    for other in RecordKind::ROWS {
                        if other == kind {
                            continue;
                        }
                        if let Some(saved) = load_record(files, &index, &identity, other)?.1 {
                            let record = rows_payload(other, scope, saved.data.as_bytes())?;
                            if duplicate_rows_binding(&record.binding, &next.binding) {
                                return Err(failed());
                            }
                        }
                    }
                    retained
                } else {
                    current_epoch(files, &index, &identity)?
                };
                if current.as_ref().is_some_and(|r| r.network_epoch > epoch) {
                    return Err(failed());
                }
                let next = SavedRecord {
                    version: PRIVATE_VERSION,
                    identity,
                    kind,
                    network_epoch: epoch,
                    data: std::str::from_utf8(desired).map_err(|_| failed())?.into(),
                };
                let bytes = serde_json::to_vec(&next).map_err(|_| failed())?;
                if bytes.len() > kind.file().limit() {
                    return Err(failed());
                }
                let session_ack_snapshot = history
                    .as_ref()
                    .map(|_| decode::<SessionSnapshot>(scope, desired))
                    .transpose()?;
                files.compare_exchange(kind.file(), raw.as_deref(), &bytes)?;
                if let (Some(history), Some(snapshot)) =
                    (history.as_ref(), session_ack_snapshot.as_ref())
                {
                    // The value was already fully decoded/validated BEFORE
                    // CAS. Retain the actual successful private CAS origin
                    // BEFORE any readback or outer transaction postflight.
                    history.retain_success(
                        &next.identity,
                        current.is_none(),
                        raw.as_deref(),
                        &bytes,
                        snapshot,
                    );
                }
                if (native.is_some()
                    || kind.row_role().is_some()
                    || matches!(
                        kind,
                        RecordKind::CarrierGuard | RecordKind::Pair | RecordKind::NativeCreator
                    ))
                    && files.read(kind.file())?.as_deref() != Some(bytes.as_slice())
                {
                    return Err(failed());
                }
                if kind == RecordKind::NativeCreator {
                    let (_, after_index) = load_index(files)?;
                    require_active(&after_index, &next.identity)?;
                    if Some(require_initial_creator_window(
                        files,
                        &after_index,
                        &next.identity,
                    )?) != creator_session
                    {
                        return Err(failed());
                    }
                }
                if matches!(kind, RecordKind::CarrierGuard | RecordKind::Pair) && fresh {
                    let (_, index) = load_index(files)?;
                    require_active(&index, &next.identity)?;
                    if Some(current_epoch(files, &index, &next.identity)?) != pair_or_guard_epoch {
                        return Err(failed());
                    }
                }
                if let Some(authority) = generation {
                    let (_, post_index) = load_index(files)?;
                    require_active(&post_index, &next.identity)?;
                    if Some(current_epoch(files, &post_index, &next.identity)?) != generation_epoch
                    {
                        return Err(failed());
                    }
                    if Some(row_generation_pair(
                        files,
                        &post_index,
                        &next.identity,
                        authority,
                    )?) != generation_pair
                    {
                        return Err(failed());
                    }
                    if let (Some(flight), Some(pair)) = (&native, &generation_pair) {
                        flight.verify_record(RecordKind::Pair, pair)?;
                    }
                    authority.verify_write(scope, kind, expected.ok_or_else(failed)?, desired)?;
                }
                if let Some((original, authority)) = created {
                    let (_, after_index) = load_index(files)?;
                    require_active(&after_index, &next.identity)?;
                    if Some(created_cleanup_pair(
                        files,
                        &after_index,
                        &next.identity,
                        original,
                        authority,
                    )?) != created_pair
                    {
                        return Err(failed());
                    }
                    authority.verify_write(
                        scope,
                        kind,
                        expected.ok_or_else(failed)?,
                        desired,
                        original,
                    )?;
                }
                if let Some(flight) = &native {
                    flight.verify(files)?;
                }
                if let Some((original, authority)) = initial {
                    let (_, after_index) = load_index(files)?;
                    require_active(&after_index, &next.identity)?;
                    if Some(initial_cleanup_pair(
                        files,
                        &after_index,
                        &next.identity,
                        original,
                        authority,
                    )?) != initial_pair
                    {
                        return Err(failed());
                    }
                    authority.verify_write(scope, kind, expected, desired, original)?;
                    if let (Some(flight), Some(pair)) = (&native, &initial_pair) {
                        flight.verify_record(RecordKind::Pair, pair)?;
                    }
                    if let Some(flight) = &native {
                        flight.verify(files)?;
                    }
                }
                Ok(())
            })
            .map_err(|_| failed());
        if result.is_err() {
            backend.fresh = None;
        } else if let Some(flight) = native {
            let verified = backend
                .io
                .transaction(|files| flight.verify(files))
                .map_err(|_| failed());
            if verified.is_err() {
                backend.fresh = None;
                return verified;
            }
            flight.finish();
        } else if let Some(history) = history.as_ref() {
            // Factual postflight only: preserve legacy Session CAS results,
            // but never allow a changed/missing/unconfirmed file to refresh
            // this process's original execution-epoch read capability.
            if backend
                .io
                .transaction(|files| history.verify_current(files))
                .is_err()
            {
                history.revoke();
            }
            if let Some(flight) = epoch_flight {
                flight.finish();
            }
        }
        if result.is_ok() {
            if let Some(flight) = generation_flight.as_mut() {
                flight.done = true;
            }
            if let Some(flight) = created_flight.as_mut() {
                flight.done = true;
            }
            if let Some(flight) = initial_flight.as_mut() {
                flight.done = true;
            }
        }
        result
    }
}
impl RecordKind {
    // Legacy fixture inventory; production fencing always uses OWNED.
    #[cfg(test)]
    const ALL: [Self; 4] = [Self::Session, Self::Pair, Self::Network, Self::Carrier];
    const ROWS: [Self; 3] = [Self::CarrierRows, Self::MemberARows, Self::MemberBRows];
    const OWNED: [Self; 10] = [
        Self::Session,
        Self::Pair,
        Self::Network,
        Self::Carrier,
        Self::NativeCarrierReceipts,
        Self::CarrierRows,
        Self::MemberARows,
        Self::MemberBRows,
        Self::CarrierGuard,
        Self::NativeCreator,
    ];
    fn file(self) -> PrivateFile {
        match self {
            Self::Session => PrivateFile::Session,
            Self::Pair => PrivateFile::Pair,
            Self::Network => PrivateFile::Network,
            Self::Carrier => PrivateFile::Carrier,
            Self::NativeCarrierReceipts => PrivateFile::NativeCarrierReceipts,
            Self::CarrierGuard => PrivateFile::CarrierGuard,
            Self::CarrierRows => PrivateFile::CarrierRows,
            Self::MemberARows => PrivateFile::MemberARows,
            Self::MemberBRows => PrivateFile::MemberBRows,
            Self::NativeCreator => PrivateFile::NativeCreator,
        }
    }
    fn row_role(self) -> Option<rows::Role> {
        match self {
            Self::CarrierRows => Some(rows::Role::Carrier),
            Self::MemberARows => Some(rows::Role::MemberA),
            Self::MemberBRows => Some(rows::Role::MemberB),
            _ => None,
        }
    }
}
// Storage fencing only. Exact native absence/ownership must still be proven by
// the cleanup caller; a saved terminal shape is not evidence of native cleanup.
fn validate_cleanup_pair(old: Option<&PairRecord>, next: &PairRecord) -> io::Result<()> {
    use crate::member_guard::{ExchangePlan, Model};
    use crate::member_owner::Phase;
    let empty = Model::empty(next.scope.clone()).map_err(|_| failed())?;
    let terminal = next.active.is_none()
        && next.members.iter().all(Option::is_none)
        && next.dns.iter().all(Option::is_none)
        && next.pending_guard.is_none()
        && next.guard == empty;
    if next.active.is_some() || (!next.closing && !terminal) {
        return Err(failed());
    }
    let Some(old) = old else {
        return if terminal && next.options.is_none() {
            Ok(())
        } else {
            Err(failed())
        };
    };
    if !same_json(&old.options, &next.options)? {
        return Err(failed());
    }
    for i in 0..2 {
        if let Some(member) = &next.members[i] {
            let prior = old.members[i].as_ref().ok_or_else(failed)?;
            let mut immutable = member.clone();
            immutable.owner = prior.owner.clone();
            // Pair Prepared precedes owner/config CAS. Refresh may therefore
            // reveal cleanup metadata already bound by its immutable predecessor.
            // This attests neither native absence nor permission to start.
            let predecessor = prior.prior_stopped.as_ref().filter(|p| {
                p.phase == Phase::Stopped
                    && p.proof.is_none()
                    && p.intent.slot == prior.owner.intent.slot
                    && previous_config_valid(p)
            });
            let previous_config_allowed =
                member.owner.previous_config_sha256.is_none_or(|digest| {
                    Some(digest) == prior.owner.previous_config_sha256
                        || predecessor.is_some_and(|p| {
                            digest == p.intent.config_sha256
                                || Some(digest) == p.previous_config_sha256
                        })
                });
            if !same_json(&immutable, prior)?
                || member.owner.intent != prior.owner.intent
                || !previous_config_allowed
                || (member.owner.phase != prior.owner.phase
                    && !matches!(member.owner.phase, Phase::Stopping | Phase::Stopped))
                || (prior.owner.phase == Phase::Stopped && member.owner.phase != Phase::Stopped)
                || member
                    .owner
                    .proof
                    .is_some_and(|p| Some(p) != prior.owner.proof)
                || member.owner.retired_proof.is_some_and(|p| {
                    Some(p) != prior.owner.retired_proof
                        && Some(p) != prior.owner.proof
                        && !predecessor.is_some_and(|old| old.retired_proof == Some(p))
                })
            {
                return Err(failed());
            }
        }
        if let Some(dns) = &next.dns[i] {
            let prior = old.dns[i].as_ref().ok_or_else(failed)?;
            if dns.baseline != prior.baseline
                || (dns.current != prior.current
                    && dns.current != prior.baseline
                    && Some(&dns.current) != prior.pending.as_ref())
                || dns
                    .pending
                    .as_ref()
                    .is_some_and(|p| p != &prior.baseline && Some(p) != prior.pending.as_ref())
            {
                return Err(failed());
            }
        }
    }
    // Reconciliation can retain only one of the already journaled states.
    // A new plan can only withdraw permits/fence retained interface proofs.
    let fence = |model: &Model| -> bool {
        model.active.is_none()
            && model.members.iter().enumerate().all(|(i, member)| {
                member.as_ref().is_none_or(|m| {
                    m.probes.is_empty()
                        && old.members[i]
                            .as_ref()
                            .and_then(|m| m.owner.proof)
                            .is_some_and(|p| {
                                p.interface.index == m.interface.index
                                    && p.interface.luid == m.interface.luid
                            })
                })
            })
    };
    let mut retained = vec![
        old.guard.clone(),
        old.guard.without_probes().map_err(|_| failed())?,
    ];
    if let Some(p) = &old.pending_guard {
        retained.extend([
            p.expected.clone(),
            p.withdrawn.clone(),
            p.base.clone(),
            p.desired.clone(),
            p.expected.without_probes().map_err(|_| failed())?,
            p.desired.without_probes().map_err(|_| failed())?,
        ]);
    }
    // A pending creation can have received a BFE-assigned sublayer weight before
    // its ACK was saved. Use the SAME exact readback validation as native recovery,
    // not the pre-creation requested weight. This only acknowledges the retained
    // plan and grants no new exchange or native ownership authority.
    let reconciled = next.pending_guard.is_none()
        && old.pending_guard.as_ref().is_some_and(|plan| {
            plan.expected == old.guard
                && plan
                    .resolve(&next.guard.expected)
                    .is_ok_and(|model| model == next.guard)
        });
    if !retained.contains(&next.guard) && !reconciled && !fence(&next.guard) {
        return Err(failed());
    }
    if let Some(p) = &next.pending_guard {
        let unchanged = old.pending_guard.as_ref() == Some(p) && next.guard == old.guard;
        if !unchanged
            && (old.pending_guard.is_some()
                || p.expected != old.guard
                || next.guard != old.guard
                || !fence(&p.desired)
                || *p != ExchangePlan::new(&p.expected, &p.desired).map_err(|_| failed())?)
        {
            return Err(failed());
        }
    }
    Ok(())
}
fn same_json<T: Serialize>(a: &T, b: &T) -> io::Result<bool> {
    Ok(serde_json::to_value(a).map_err(|_| failed())?
        == serde_json::to_value(b).map_err(|_| failed())?)
}

fn valid_runtime(r: &EngineIdentity) -> bool {
    r.runtime_contract_version > 0
        && [&r.runtime_version, &r.container_version]
            .iter()
            .all(|v| !v.is_empty() && v.len() <= 128 && !v.chars().any(char::is_control))
        && r.manifest_sha256.len() == 64
        && r.manifest_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_identity(id: &SessionIdentity) -> bool {
    id.boot_id != [0; 16]
        && valid_runtime(&id.runtime)
        && id.scope.validate()
        && id.scope.runtime == id.runtime.slot
}
fn load_index(files: &mut dyn PrivateRecords) -> io::Result<(Option<Vec<u8>>, SessionIndex)> {
    let bytes = files.read(PrivateFile::Index)?;
    let index: SessionIndex = match &bytes {
        None => SessionIndex {
            version: PRIVATE_VERSION,
            ..Default::default()
        },
        Some(b) => {
            if b.len() > PrivateFile::Index.limit() {
                return Err(failed());
            }
            serde_json::from_slice(b).map_err(|_| failed())?
        }
    };
    if index.version != PRIVATE_VERSION
        || index.completed.len() > RecordKind::OWNED.len()
        || index
            .active
            .iter()
            .chain(index.completed.iter())
            .any(|id| !valid_identity(id))
    {
        return Err(failed());
    }
    let mut seen = std::collections::HashSet::new();
    for id in index.active.iter().chain(index.completed.iter()) {
        if !seen.insert(serde_json::to_vec(&id.scope).map_err(|_| failed())?) {
            return Err(failed());
        }
    }
    for id in &index.completed {
        if read_completed(files, &id.scope)?.as_ref() != Some(id) {
            return Err(failed());
        }
    }
    if let Some(active) = &index.active {
        if read_completed(files, &active.scope)?.is_some_and(|saved| saved != *active) {
            return Err(failed());
        }
    }
    // Every retired identity must actually be represented in the bounded files.
    // With an active claim, partial overwrites may temporarily hide old owners.
    if index.active.is_none() {
        let mut represented = vec![];
        for kind in RecordKind::OWNED {
            let Some(raw) = files.read(kind.file())? else {
                continue;
            };
            let saved = parse_record(kind, &raw)?;
            if kind == RecordKind::CarrierGuard && !cold_retired_record(files, kind, &raw, &saved)?
            {
                require_stopped_guard(&saved)?;
            }
            if !index.completed.contains(&saved.identity) {
                return Err(failed());
            }
            if !represented.contains(&saved.identity) {
                represented.push(saved.identity);
            }
        }
        if represented.len() != index.completed.len() {
            return Err(failed());
        }
    }
    Ok((bytes, index))
}
fn completed_file(scope: &SessionScope) -> io::Result<PrivateFile> {
    if !scope.validate() {
        return Err(failed());
    }
    // Canonical wire bytes: UTF-8 JSON, no whitespace, these four named fields
    // in this order. Keep this definition stable independently of future fields
    // or serde changes to SessionScope itself (permanent replay addresses).
    #[derive(Serialize)]
    struct CanonicalScope<'a> {
        runtime: RuntimeSlot,
        runtime_generation: u64,
        session_id: &'a str,
        connection_generation: u64,
    }
    let bytes = serde_json::to_vec(&CanonicalScope {
        runtime: scope.runtime,
        runtime_generation: scope.runtime_generation,
        session_id: &scope.session_id,
        connection_generation: scope.connection_generation,
    })
    .map_err(|_| failed())?;
    Ok(PrivateFile::Completed(Sha256::digest(bytes).into()))
}
fn read_completed(
    files: &mut dyn PrivateRecords,
    scope: &SessionScope,
) -> io::Result<Option<SessionIdentity>> {
    Ok(read_completed_detail(files, scope)?.map(|(id, _)| id))
}
fn read_completed_detail(
    files: &mut dyn PrivateRecords,
    scope: &SessionScope,
) -> io::Result<Option<(SessionIdentity, Option<ColdRetirementStamp>)>> {
    let file = completed_file(scope)?;
    let Some(bytes) = files.read(file)? else {
        return Ok(None);
    };
    if bytes.len() > file.limit() {
        return Err(failed());
    }
    let (identity, cold) = if let Ok(saved) = serde_json::from_slice::<CompletedRecord>(&bytes) {
        if saved.version != PRIVATE_VERSION {
            return Err(failed());
        }
        (saved.identity, None)
    } else if let Ok(saved) = serde_json::from_slice::<InitialDataCompletedRecord>(&bytes) {
        if saved.version != 3
            || saved.initial_noc.version != 1
            || saved
                .initial_noc
                .records
                .iter()
                .map(|(k, _)| *k)
                .ne(RecordKind::OWNED)
        {
            return Err(failed());
        }
        (saved.identity, Some(saved.initial_noc))
    } else {
        let mut saved: ColdCompletedRecord =
            serde_json::from_slice(&bytes).map_err(|_| failed())?;
        if saved.version != 2 || saved.cold_empty.version != 1 {
            return Err(failed());
        }
        let kinds: Vec<_> = saved.cold_empty.records.iter().map(|(k, _)| *k).collect();
        if kinds == RecordKind::OWNED[..RecordKind::OWNED.len() - 1] {
            // Old permanent marker has no creator digest. Never hide a
            // subsequently added record of that SAME retired identity.
            if let Some(raw) = files.read(PrivateFile::NativeCreator)? {
                if parse_record(RecordKind::NativeCreator, &raw)?.identity == saved.identity {
                    return Err(failed());
                }
            }
            saved
                .cold_empty
                .records
                .push((RecordKind::NativeCreator, None));
        } else if kinds != RecordKind::OWNED {
            return Err(failed());
        }
        (saved.identity, Some(saved.cold_empty))
    };
    if !valid_identity(&identity) || identity.scope != *scope {
        return Err(failed());
    }
    Ok(Some((identity, cold)))
}
fn match_cold_snapshot(
    files: &mut dyn PrivateRecords,
    expected: &ProtectedRecoveryRecords,
) -> io::Result<(Option<Vec<u8>>, SessionIndex, SessionIdentity)> {
    if expected.stamp.len() != RecordKind::OWNED.len() + 1
        || expected
            .records
            .iter()
            .map(|(k, _)| *k)
            .ne(RecordKind::OWNED)
    {
        return Err(failed());
    }
    let (raw, index) = load_index(files)?;
    if raw != expected.stamp[0] {
        return Err(failed());
    }
    let identity = index.active.clone().ok_or_else(failed)?;
    if identity.scope != expected.scope
        || identity.boot_id != expected.provenance.boot_id
        || identity.runtime != expected.provenance.runtime
        || current_epoch(files, &index, &identity)? != expected.provenance.network_epoch
    {
        return Err(failed());
    }
    for (i, (kind, payload)) in expected.records.iter().enumerate() {
        let (raw, saved) = load_record(files, &index, &identity, *kind)?;
        if raw != expected.stamp[i + 1] || saved.map(|r| r.data.into_bytes()) != *payload {
            return Err(failed());
        }
    }
    require_native_obligation(files, &index, &identity)?;
    Ok((raw, index, identity))
}
fn cold_retired_record(
    files: &mut dyn PrivateRecords,
    kind: RecordKind,
    raw: &[u8],
    old: &SavedRecord,
) -> io::Result<bool> {
    let Some((identity, Some(stamp))) = read_completed_detail(files, &old.identity.scope)? else {
        return Ok(false);
    };
    let expected = stamp
        .records
        .iter()
        .find(|(k, _)| *k == kind)
        .and_then(|(_, h)| *h)
        .ok_or_else(failed)?;
    if identity != old.identity || <[u8; 32]>::from(Sha256::digest(raw)) != expected {
        return Err(failed());
    }
    Ok(true) // DATA retirement only: never live context, ACK or native permission
}
fn write_completed(files: &mut dyn PrivateRecords, id: &SessionIdentity) -> io::Result<()> {
    if let Some(saved) = read_completed(files, &id.scope)? {
        // A hash collision, corrupt marker or another boot/runtime is a conflict,
        // never a marker that can be replaced by a new scope claim.
        return if saved == *id { Ok(()) } else { Err(failed()) };
    }
    let file = completed_file(&id.scope)?;
    let bytes = serde_json::to_vec(&CompletedRecord {
        version: PRIVATE_VERSION,
        identity: id.clone(),
    })
    .map_err(|_| failed())?;
    if bytes.len() > file.limit() {
        return Err(failed());
    }
    files.compare_exchange(file, None, &bytes)?;
    // A success ACK without the exact durable marker cannot release a claim.
    // Failed/lost ACK still returns failure; it never reacquires fresh access.
    if files.read(file)?.as_deref() != Some(bytes.as_slice()) {
        return Err(failed());
    }
    Ok(())
}
fn already_completed(
    files: &mut dyn PrivateRecords,
    index: &SessionIndex,
    id: &SessionIdentity,
) -> io::Result<bool> {
    if index.active.is_some() {
        return Ok(false);
    }
    if read_completed(files, &id.scope)?.as_ref() != Some(id) {
        return Err(failed());
    }
    require_retired_records(files, index)?;
    Ok(true)
}
fn finish_completion(
    files: &mut dyn PrivateRecords,
    raw: Option<&[u8]>,
    index: &mut SessionIndex,
    id: &SessionIdentity,
) -> io::Result<()> {
    // Cleanup was verified above. Publish the permanent marker BEFORE releasing
    // the active index. A lost marker ACK leaves the active claim intact; retry
    // revalidates the records and exact marker, never resumes native effects.
    write_completed(files, id)?;
    let mut residual = vec![];
    for kind in RecordKind::OWNED {
        if let Some(raw) = files.read(kind.file())? {
            let saved = parse_record(kind, &raw)?;
            if kind == RecordKind::Pair {
                carrier_pair_store::require_terminal_pair(
                    &saved.identity.scope,
                    saved.data.as_bytes(),
                )?;
            }
            if kind == RecordKind::NativeCarrierReceipts {
                require_stopped_native(&saved)?;
            }
            if kind == RecordKind::CarrierGuard {
                require_stopped_guard(&saved)?;
            }
            if kind.row_role().is_some() {
                require_stopped_rows(kind, &saved)?;
            }
            if saved.identity != *id && !index.completed.contains(&saved.identity) {
                return Err(failed());
            }
            if read_completed(files, &saved.identity.scope)?.as_ref() != Some(&saved.identity) {
                return Err(failed());
            }
            if !residual.contains(&saved.identity) {
                residual.push(saved.identity);
            }
        }
    }
    index.completed = residual;
    index.active = None;
    save_index(files, raw, index)
}
fn save_index(
    files: &mut dyn PrivateRecords,
    expected: Option<&[u8]>,
    index: &SessionIndex,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(index).map_err(|_| failed())?;
    if bytes.len() > PrivateFile::Index.limit() {
        return Err(failed());
    }
    files.compare_exchange(PrivateFile::Index, expected, &bytes)?;
    if files.read(PrivateFile::Index)?.as_deref() != Some(bytes.as_slice()) {
        return Err(failed());
    }
    Ok(())
}
fn require_active(index: &SessionIndex, identity: &SessionIdentity) -> io::Result<()> {
    if index.active.as_ref() != Some(identity) {
        Err(failed())
    } else {
        Ok(())
    }
}
fn require_retired_records(files: &mut dyn PrivateRecords, index: &SessionIndex) -> io::Result<()> {
    for id in &index.completed {
        if let Some((_, Some(stamp))) = read_completed_detail(files, &id.scope)? {
            for (kind, digest) in stamp.records {
                if digest.is_some() && files.read(kind.file())?.is_none() {
                    return Err(failed());
                }
            }
        }
    }
    for kind in RecordKind::OWNED {
        if let Some(raw) = files.read(kind.file())? {
            let old = parse_record(kind, &raw)?;
            if !index.completed.contains(&old.identity) {
                return Err(failed());
            }
            if cold_retired_record(files, kind, &raw, &old)? {
                continue;
            }
            if kind == RecordKind::Pair {
                carrier_pair_store::require_terminal_pair(
                    &old.identity.scope,
                    old.data.as_bytes(),
                )?;
            }
            if kind == RecordKind::Carrier {
                require_stopped_carrier(&old)?;
            }
            if kind == RecordKind::NativeCarrierReceipts {
                require_stopped_native(&old)?;
            }
            if kind == RecordKind::CarrierGuard {
                require_stopped_guard(&old)?;
            }
            if kind.row_role().is_some() {
                require_stopped_rows(kind, &old)?;
            }
        }
    }
    Ok(())
}
fn parse_record(kind: RecordKind, raw: &[u8]) -> io::Result<SavedRecord> {
    if raw.len() > kind.file().limit() {
        return Err(failed());
    }
    let record: SavedRecord = serde_json::from_slice(raw).map_err(|_| failed())?;
    if record.version != PRIVATE_VERSION
        || record.kind != kind
        || record.network_epoch == 0
        || !valid_identity(&record.identity)
    {
        return Err(failed());
    }
    validate_payload(&record.identity.scope, kind, record.data.as_bytes())?;
    if kind == RecordKind::Pair {
        if let Some(pair) = carrier_pair_payload(&record.identity.scope, record.data.as_bytes())? {
            if pair.provenance.boot_id != record.identity.boot_id
                || pair.provenance.runtime != record.identity.runtime
                || pair.provenance.network_epoch != record.network_epoch
            {
                return Err(failed());
            }
        }
    }
    if kind == RecordKind::Session
        && decode::<SessionSnapshot>(&record.identity.scope, record.data.as_bytes())?.network_epoch
            != record.network_epoch
    {
        return Err(failed());
    }
    if kind == RecordKind::NativeCreator {
        authenticate_creator(
            &creator_payload(&record.identity.scope, record.data.as_bytes())?,
            &record.identity,
            record.network_epoch,
        )?;
        if record.network_epoch != 1 {
            return Err(failed());
        }
    }
    if kind == RecordKind::Carrier {
        authenticate_carrier(
            &carrier_payload(&record.identity.scope, record.data.as_bytes())?,
            &record.identity,
            record.network_epoch,
        )?;
    }
    if kind == RecordKind::NativeCarrierReceipts {
        authenticate_native(
            &native_payload(&record.identity.scope, record.data.as_bytes())?,
            &record.identity,
            record.network_epoch,
        )?;
    }
    if kind.row_role().is_some() {
        authenticate_rows(
            &rows_payload(kind, &record.identity.scope, record.data.as_bytes())?,
            &record.identity,
            record.network_epoch,
        )?;
    }
    if kind == RecordKind::CarrierGuard {
        authenticate_guard(
            &guard_payload(&record.identity.scope, record.data.as_bytes())?,
            &record.identity,
            record.network_epoch,
        )?;
    }
    Ok(record)
}
fn load_record(
    files: &mut dyn PrivateRecords,
    index: &SessionIndex,
    id: &SessionIdentity,
    kind: RecordKind,
) -> io::Result<(Option<Vec<u8>>, Option<SavedRecord>)> {
    let raw = files.read(kind.file())?;
    let saved = raw.as_ref().map(|b| parse_record(kind, b)).transpose()?;
    let saved = match saved {
        Some(r) if r.identity == *id => Some(r),
        Some(r) if index.completed.contains(&r.identity) => {
            if cold_retired_record(files, kind, raw.as_deref().ok_or_else(failed)?, &r)? {
                return Ok((raw, None));
            }
            if kind == RecordKind::Pair {
                carrier_pair_store::require_terminal_pair(&r.identity.scope, r.data.as_bytes())?;
            }
            if kind == RecordKind::Carrier {
                require_stopped_carrier(&r)?;
            }
            if kind == RecordKind::NativeCarrierReceipts {
                require_stopped_native(&r)?;
            }
            if kind == RecordKind::CarrierGuard {
                require_stopped_guard(&r)?;
            }
            if kind.row_role().is_some() {
                require_stopped_rows(kind, &r)?;
            }
            None
        }
        Some(_) => return Err(failed()),
        None => None,
    };
    Ok((raw, saved))
}
fn current_epoch(
    files: &mut dyn PrivateRecords,
    index: &SessionIndex,
    id: &SessionIdentity,
) -> io::Result<u64> {
    let (_, state) = load_record(files, index, id, RecordKind::Session)?;
    Ok(state.map(|r| r.network_epoch).unwrap_or(1))
}
fn validate_payload(scope: &SessionScope, kind: RecordKind, bytes: &[u8]) -> io::Result<()> {
    match kind {
        RecordKind::NativeCreator => {
            creator_payload(scope, bytes)?;
        }
        RecordKind::CarrierGuard => {
            guard_payload(scope, bytes)?;
        }
        RecordKind::CarrierRows | RecordKind::MemberARows | RecordKind::MemberBRows => {
            rows_payload(kind, scope, bytes)?;
        }
        RecordKind::NativeCarrierReceipts => {
            let record = native_receipt::Record::decode(bytes).map_err(|_| failed())?;
            if record.context.intent.scope != *scope {
                return Err(failed());
            }
        }
        RecordKind::Carrier => {
            carrier_payload(scope, bytes)?;
        }
        RecordKind::Session => {
            use nelomai_client_tunnel::redundancy::session::SessionPhase;
            let s: SessionSnapshot = decode(scope, bytes)?;
            if s.scope != *scope
                || s.network_epoch == 0
                || s.local_revision == 0
                || s.role_generation > i64::MAX as u64
                || s.membership_generation > i64::MAX as u64
                || s.committed.iter().zip(s.installed).any(|(c, i)| *c && !i)
                || (s.phase == SessionPhase::Running
                    && !s.installed[if s.active == nelomai_client_tunnel::redundancy::Slot::A {
                        0
                    } else {
                        1
                    }])
                || (matches!(s.phase, SessionPhase::Starting | SessionPhase::Stopped)
                    && s.installed.iter().any(|i| *i))
            {
                return Err(failed());
            }
        }
        RecordKind::Pair => {
            if carrier_pair_payload(scope, bytes)?.is_some() {
                return Ok(());
            }
            let p: PairRecord = decode(scope, bytes)?;
            if p.scope != *scope || p.guard.scope != *scope {
                return Err(failed());
            }
            p.guard.validate().map_err(|_| failed())?;
            if let Some(plan) = &p.pending_guard {
                if plan.expected.scope != *scope
                    || *plan
                        != crate::member_guard::ExchangePlan::new(&plan.expected, &plan.desired)
                            .map_err(|_| failed())?
                {
                    return Err(failed());
                }
            }
            if let Some(options) = p.options {
                options.validate().map_err(|_| failed())?;
            }
            for (i, member) in p.members.iter().enumerate() {
                if let Some(m) = member {
                    let slot = if i == 0 {
                        nelomai_contracts::dispatcher::TunnelSlot::A
                    } else {
                        nelomai_contracts::dispatcher::TunnelSlot::B
                    };
                    if m.owner.intent.scope != *scope
                        || m.owner.intent.slot != slot
                        || !previous_config_valid(&m.owner)
                    {
                        return Err(failed());
                    }
                }
            }
            for dns in p.dns.iter().flatten() {
                for s in [&dns.baseline, &dns.current]
                    .into_iter()
                    .chain(dns.pending.iter())
                {
                    if s.interface != dns.baseline.interface
                        || s.interface.scope != *scope
                        || s.interface.index == 0
                        || s.interface.luid == 0
                        || s.interface.guid == [0; 16]
                    {
                        return Err(failed());
                    }
                }
            }
        }
        RecordKind::Network => {
            let n = network_payload(scope, bytes)?;
            network_owner(n.journal)?;
            if n.physical.len() > 32768
                || n.physical.iter().any(|p| {
                    p.interface == 0
                        || p.luid == 0
                        || p.guid == [0; 16]
                        || p.route.interface != p.interface
                })
            {
                return Err(failed());
            }
        }
    }
    Ok(())
}
fn network_payload(scope: &SessionScope, bytes: &[u8]) -> io::Result<NativeNetworkRecord> {
    // Preserve both existing ProtectedStore<NativeNetworkRecord> and the shared
    // WindowsNetworkStore alias; DNS/WFP remain solely in PairRecord.
    decode::<NativeNetworkRecord>(scope, bytes).or_else(|_| {
        decode::<NetworkJournal>(scope, bytes).map(|journal| NativeNetworkRecord {
            journal,
            physical: vec![],
        })
    })
}
struct ReadOnlyNetwork;
impl nelomai_client_tunnel::redundancy::network::NetworkSystem for ReadOnlyNetwork {
    fn read(
        &mut self,
        _: &nelomai_client_tunnel::redundancy::network::ResourceKey,
    ) -> io::Result<Option<nelomai_client_tunnel::redundancy::network::NetworkValue>> {
        Err(failed())
    }
    fn compare_exchange(
        &mut self,
        _: &nelomai_client_tunnel::redundancy::network::ResourceKey,
        _: Option<&nelomai_client_tunnel::redundancy::network::NetworkValue>,
        _: Option<&nelomai_client_tunnel::redundancy::network::NetworkValue>,
    ) -> io::Result<()> {
        Err(failed())
    }
}
impl NetworkJournalStore for ReadOnlyNetwork {
    fn save(&mut self, _: &NetworkJournal) -> io::Result<()> {
        Err(failed())
    }
}
fn network_owner(
    journal: NetworkJournal,
) -> io::Result<
    nelomai_client_tunnel::redundancy::network::NetworkOwner<ReadOnlyNetwork, ReadOnlyNetwork>,
> {
    // recover validates journal structure without invoking native IO or save.
    nelomai_client_tunnel::redundancy::network::NetworkOwner::recover(
        ReadOnlyNetwork,
        ReadOnlyNetwork,
        journal,
    )
    .map_err(|_| failed())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    version: u32,
    scope: SessionScope,
    payload: T,
}
pub(crate) struct ProtectedStore<F, T> {
    files: F,
    scope: SessionScope,
    kind: RecordKind,
    expected: Option<Vec<u8>>,
    marker: PhantomData<T>,
}
impl<F: SessionFiles, T: Serialize + DeserializeOwned> ProtectedStore<F, T> {
    pub(crate) fn open(
        mut files: F,
        scope: SessionScope,
        kind: RecordKind,
    ) -> io::Result<(Self, Option<T>)> {
        if !scope.validate() {
            return Err(failed());
        }
        let expected = files.read(&scope, kind)?;
        if let Some(bytes) = &expected {
            validate_payload(&scope, kind, bytes)?;
        }
        let payload = expected
            .as_ref()
            .map(|bytes| decode::<T>(&scope, bytes))
            .transpose()?;
        Ok((
            Self {
                files,
                scope,
                kind,
                expected,
                marker: PhantomData,
            },
            payload,
        ))
    }
    pub(crate) fn save_value(&mut self, value: &T) -> io::Result<()> {
        let bytes = serde_json::to_vec(&Envelope {
            version: 1,
            scope: self.scope.clone(),
            payload: value,
        })
        .map_err(|_| failed())?;
        validate_payload(&self.scope, self.kind, &bytes)?;
        self.files
            .compare_exchange(&self.scope, self.kind, self.expected.as_deref(), &bytes)?;
        // A lost ACK is an error, not a license to repeat native effects. The
        // next factory recovery reopens durable state and resolves exact proof.
        self.expected = Some(bytes);
        Ok(())
    }
}
/// Select a payload version without changing the legacy publication contract.
/// Legacy cleanup-owner conversion is intentionally a separate stricter gate;
/// it must not accidentally reject old write-ahead Prepared records here.
/// Reparse ORIGINAL bytes into the selected strict type so duplicate fields
/// cannot be hidden by the temporary Value used only for version selection.
fn carrier_pair_payload(
    scope: &SessionScope,
    bytes: &[u8],
) -> io::Result<Option<crate::member_carrier_pair::Record>> {
    let value: serde_json::Value = decode(scope, bytes)?;
    let object = value.as_object().ok_or_else(failed)?;
    if object.contains_key("version") {
        if bytes.len() > 65_536 + 1024 {
            return Err(failed());
        }
        let record: crate::member_carrier_pair::Record = decode(scope, bytes)?;
        record.validate()?;
        record.encode()?;
        if record.scope != *scope {
            return Err(failed());
        }
        Ok(Some(record))
    } else {
        let _: PairRecord = decode(scope, bytes)?;
        Ok(None)
    }
}
fn decode<T: DeserializeOwned>(scope: &SessionScope, bytes: &[u8]) -> io::Result<T> {
    if bytes.len() > MAX_PAYLOAD {
        return Err(failed());
    }
    let saved: Envelope<T> = serde_json::from_slice(bytes).map_err(|_| failed())?;
    if saved.version != 1 || saved.scope != *scope {
        return Err(failed());
    }
    Ok(saved.payload)
}
pub(crate) fn decode_session_payload(
    scope: &SessionScope,
    bytes: &[u8],
) -> io::Result<SessionSnapshot> {
    decode(scope, bytes)
}
pub(crate) type WindowsSessionStore<F> = ProtectedStore<F, SessionSnapshot>;
pub(crate) type WindowsPairStore<F> = ProtectedStore<F, PairRecord>;
pub(crate) type WindowsNetworkStore<F> = ProtectedStore<F, NetworkJournal>;

fn carrier_payload(scope: &SessionScope, bytes: &[u8]) -> io::Result<CarrierRecord> {
    if bytes.len() > PrivateFile::Carrier.limit() {
        return Err(failed());
    }
    let record: CarrierRecord = decode(scope, bytes)?;
    carrier::validate_record_shape(&record).map_err(|_| failed())?;
    if record.intent.scope != *scope {
        return Err(failed());
    }
    Ok(record)
}
fn authenticate_carrier(
    record: &CarrierRecord,
    identity: &SessionIdentity,
    epoch: u64,
) -> io::Result<()> {
    if record.intent.scope != identity.scope
        || record.provenance.boot_id != identity.boot_id
        || record.provenance.runtime != identity.runtime
        || record.provenance.network_epoch != epoch
    {
        return Err(failed());
    }
    Ok(())
}
fn require_stopped_carrier(saved: &SavedRecord) -> io::Result<()> {
    if carrier_payload(&saved.identity.scope, saved.data.as_bytes())?.phase
        != carrier::Phase::Stopped
    {
        return Err(failed());
    }
    Ok(())
}
/// Storage-only progression. The native owner must still prove each readback
/// and eventual absence. Neither this guard nor a Stopped JSON grants native
/// authority, and recovery can never add a captured proof or publish readiness.
fn validate_carrier_transition(
    old: Option<&CarrierRecord>,
    next: &CarrierRecord,
    fresh: bool,
) -> io::Result<()> {
    use carrier::Phase;
    carrier::validate_record_shape(next).map_err(|_| failed())?;
    let Some(old) = old else {
        return if fresh && next.phase == Phase::Prepared && next.generation == 1 {
            Ok(())
        } else {
            Err(failed())
        };
    };
    if old == next {
        return if fresh || matches!(next.phase, Phase::Closing | Phase::Stopped) {
            Ok(())
        } else {
            Err(failed())
        };
    }
    if old.generation.checked_add(1) != Some(next.generation)
        || next.version != old.version
        || next.intent != old.intent
        || next.provenance != old.provenance
    {
        return Err(failed());
    }
    if fresh && old.phase == Phase::Prepared && next.phase == Phase::Created {
        return if next.rows.as_ref().is_some_and(|rows| {
            rows.iter()
                .all(|r| r.current == r.baseline && r.pending.is_none())
        }) {
            Ok(())
        } else {
            Err(failed())
        };
    }
    if next.proof != old.proof || next.rows.is_some() != old.rows.is_some() {
        return Err(failed());
    }
    if next
        .rows
        .as_ref()
        .zip(old.rows.as_ref())
        .is_some_and(|(next, old)| next.iter().zip(old).any(|(n, o)| n.baseline != o.baseline))
    {
        return Err(failed());
    }
    match (old.phase, next.phase) {
        (Phase::Prepared | Phase::Created | Phase::Configured, Phase::Closing)
        | (Phase::Closing, Phase::Stopped) => {
            if next.rows != old.rows {
                return Err(failed());
            }
        }
        (Phase::Created, Phase::Configured) if fresh => {
            if next.rows != old.rows {
                return Err(failed());
            }
        }
        (Phase::Created, Phase::Created) if fresh => validate_carrier_rows(old, next, false)?,
        (Phase::Closing, Phase::Closing) => validate_carrier_rows(old, next, true)?,
        _ => return Err(failed()),
    }
    Ok(())
}
fn validate_carrier_rows(
    old: &CarrierRecord,
    next: &CarrierRecord,
    cleanup: bool,
) -> io::Result<()> {
    let old = old.rows.as_ref().ok_or_else(failed)?;
    let next = next.rows.as_ref().ok_or_else(failed)?;
    let mut changes = 0;
    for (old, next) in old.iter().zip(next) {
        if old == next {
            continue;
        }
        changes += 1;
        match (&old.pending, &next.pending) {
            (None, Some(value))
                if next.current == old.current && (!cleanup || value == &old.baseline) => {}
            (Some(value), None)
                if next.current == *value || (cleanup && next.current == old.current) => {}
            _ => return Err(failed()),
        }
    }
    if changes != 1 {
        return Err(failed());
    }
    Ok(())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PhysicalLease {
    pub interface: u32,
    pub luid: u64,
    pub guid: [u8; 16],
    pub ipv6: bool,
    pub interface_metric: u32,
    pub route: nelomai_client_tunnel::redundancy::network::RouteValue,
    pub protocol: i32,
    pub origin: i32,
    pub site_prefix_length: u8,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub flags: [u8; 4],
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeNetworkRecord {
    pub journal: NetworkJournal,
    pub physical: Vec<PhysicalLease>,
}
impl NativeNetworkRecord {
    /// Bounded scoped decode for independent READ comparisons only. The caller
    /// must read these bytes through the actual private runtime/context fence;
    /// this method supplies no native ownership, ACK, adoption or effect grant.
    pub(super) fn read_comparison(scope: &SessionScope, bytes: &[u8]) -> io::Result<Self> {
        validate_payload(scope, RecordKind::Network, bytes)?;
        network_payload(scope, bytes)
    }
}
impl<F: SessionFiles> SessionStore for WindowsSessionStore<F> {
    fn save(&mut self, s: &SessionSnapshot) -> io::Result<()> {
        if s.scope != self.scope {
            return Err(failed());
        }
        self.save_value(s)
    }
}
impl<F: SessionFiles> PairStore for WindowsPairStore<F> {
    fn save(&mut self, s: &PairRecord) -> io::Result<()> {
        if s.scope != self.scope {
            return Err(failed());
        }
        self.save_value(s)
    }
}
impl<F: SessionFiles> NetworkJournalStore for WindowsNetworkStore<F> {
    fn save(&mut self, s: &NetworkJournal) -> io::Result<()> {
        self.save_value(s)
    }
}

#[cfg(test)]
#[path = "member_carrier_store_tests.rs"]
mod carrier_store_tests;

/// Storage-only v2 journal under the caller's serialized engine mutation lock.
/// SessionFileIo holds its protected lifecycle file lock for each transaction;
/// that is NOT a native registry/NIC ownership lock or proof. The trusted
/// caller supplies the complete independent Context, never one read from JSON.
/// Reopening is cleanup-only. No record can reconstruct a retained HKEY ACK,
/// attest native absence, bind full native rows, or authorize adapter creation.
#[allow(dead_code)] // Native IO/full-row/factory integration remains disabled.
pub(crate) struct WindowsNativeCarrierReceiptStore<F> {
    files: F,
    bound_files: std::sync::OnceLock<F>,
    binding_attempted: std::cell::Cell<bool>,
    binding_failed: std::cell::Cell<bool>,
    // Successful CAS + exact readback from THIS journal only. Never populated
    // by open/load or by matching externally published initial bytes.
    initial_ack: Option<native_receipt::Record>,
    initial_cleanup_files: Option<F>,
    initial_cleanup_failed: bool,
    initial_origin: std::rc::Rc<()>,
    initial_retirement_attempted: bool,
    initial_retirement_ack: Option<std::rc::Rc<InitialDataRetirementAck>>,
    context: native_receipt::Context,
    cleanup_only: bool,
    revoked: bool,
}
/// Opaque factual pin minted ONLY from THIS journal's successful initial CAS
/// and readback. No file decoder or caller context can construct an ACK pin.
#[derive(Clone)]
pub(crate) struct InitialNativeDataRead {
    original: std::rc::Rc<()>,
    backend: OriginalSessionFilesIdentity,
    record: native_receipt::Record,
}
impl InitialNativeDataRead {
    pub(crate) fn same_original(&self, other: &Self) -> bool {
        std::rc::Rc::ptr_eq(&self.original, &other.original)
            && self.backend.same_original(&other.backend)
    }
    pub(crate) fn matches_backend(&self, origin: &OriginalSessionFilesIdentity) -> bool {
        self.backend.same_original(origin)
    }
    pub(crate) fn acknowledged(&self) -> &native_receipt::Record {
        &self.record
    }
}
/// # Safety
/// PURE, no SDK/Runtime/backend reentry. Issuer MUST retain the completed SAME
/// original Startup NoC owning-disposal outcome and this SAME opaque journal
/// pin before invoking retirement. Neither protected bytes nor a Stopped Pair
/// alone certifies that outcome. Failure/reentry/unwind permanently fences the
/// attempt; this is storage DATA retirement, never native deletion permission.
pub(crate) unsafe trait OriginalInitialNativeDataRetirement {
    fn begin_retirement(&self, original: &InitialNativeDataRead) -> io::Result<()>;
    fn verify_retirement(
        &self,
        original: &InitialNativeDataRead,
        current: &ProtectedRecoveryRecords,
    ) -> io::Result<()>;
    fn fail_retirement(&self);
    /// Separate sealed original pre-Pair outcome. Default denial preserves the
    /// existing Pair-backed issuers; absent bytes never select this authority.
    fn verify_absent_pair(
        &self,
        _original: &InitialNativeDataRead,
        _current: &ProtectedRecoveryRecords,
    ) -> io::Result<()> {
        Err(failed())
    }
}
pub(crate) struct InitialDataRetirementAck {
    original: InitialNativeDataRead,
}
impl InitialDataRetirementAck {
    pub(crate) fn matches_original(&self, original: &InitialNativeDataRead) -> bool {
        self.original.same_original(original)
    }
}
impl<I: SessionFileIo> WindowsNativeCarrierReceiptStore<ProtectedSessionFiles<I>> {
    /// Factual opaque journal pin. Obtain after the original cleanup handoff;
    /// cached/equal bytes cannot supply this journal's successful first ACK.
    pub(crate) fn original_initial_data_read(&self) -> io::Result<InitialNativeDataRead> {
        self.require_context(&self.context).map_err(|_| failed())?;
        let record = self.initial_ack.as_ref().ok_or_else(failed)?;
        require_initial_native_data(record)?;
        Ok(InitialNativeDataRead {
            original: self.initial_origin.clone(),
            backend: self.selected_files().read_identity(),
            record: record.clone(),
        })
    }
    /// Separate storage-only completion of acknowledged initial DATA after
    /// SAME completed NoC disposal and durable SessionStopped/PairStopped.
    /// No fake native Stopped, SDK/key writes, forward rearm or ordinary CAS
    /// exemption. `retain` must ONLY publish this Rc in a retained caller slot:
    /// it runs under the original backend transaction, with no IO/SDK/reentry.
    pub(crate) fn retire_original_initial_data(
        &mut self,
        proof: &dyn OriginalInitialNativeDataRetirement,
        retain: impl FnOnce(std::rc::Rc<InitialDataRetirementAck>) -> io::Result<()>,
    ) -> io::Result<std::rc::Rc<InitialDataRetirementAck>> {
        if std::mem::replace(&mut self.initial_retirement_attempted, true) {
            return Err(failed());
        }
        if self.initial_cleanup_files.is_none() || !self.cleanup_only {
            // A rejected premature retirement cannot leave a live initial
            // journal available for subsequent key/SDK bootstrap publication.
            // No cleanup view is fabricated to recover this failed invocation.
            self.revoked = true;
            return Err(failed());
        }
        let original = self.original_initial_data_read()?;
        struct Flight<'a>(&'a dyn OriginalInitialNativeDataRetirement, bool);
        impl Drop for Flight<'_> {
            fn drop(&mut self) {
                if !self.1 {
                    self.0.fail_retirement();
                }
            }
        }
        let mut flight = Flight(proof, false);
        proof.begin_retirement(&original)?;
        let mut selected = self.selected_files().clone();
        if !original.matches_backend(&selected.read_identity()) {
            return Err(failed());
        }
        let expected = selected
            .inspect_recovery_records(self.context.intent.scope.runtime, |facts| Ok(facts.clone()))?
            .ok_or_else(failed)?;
        if expected.changed_boot || expected.scope != self.context.intent.scope {
            return Err(failed());
        }
        proof.verify_retirement(&original, &expected)?;
        let native = selected.native_flight(&expected.scope)?;
        let mut backend = selected.backend_guard()?;
        backend.fresh = None;
        let ack = backend
            .io
            .transaction(|files| {
                if let Some(native) = &native {
                    native.verify(files)?;
                }
                let (raw, mut index, identity) = match_cold_snapshot(files, &expected)?;
                if expected
                    .records
                    .iter()
                    .find(|(kind, _)| *kind == RecordKind::Pair)
                    .and_then(|(_, bytes)| bytes.as_deref())
                    .is_none()
                {
                    proof.verify_absent_pair(&original, &expected)?;
                }
                require_initial_noc_records(&expected, original.acknowledged())?;
                proof.verify_retirement(&original, &expected)?;
                let mut stamp = ColdRetirementStamp {
                    version: 1,
                    records: RecordKind::OWNED.map(|kind| (kind, None)).to_vec(),
                };
                let mut residual = Vec::new();
                for (i, (kind, hash)) in stamp.records.iter_mut().enumerate() {
                    if let Some(bytes) = &expected.stamp[i + 1] {
                        let saved = parse_record(*kind, bytes)?;
                        if saved.identity == identity {
                            *hash = Some(Sha256::digest(bytes).into());
                        } else if !index.completed.contains(&saved.identity) {
                            return Err(failed());
                        }
                        if !residual.contains(&saved.identity) {
                            residual.push(saved.identity);
                        }
                    }
                }
                let marker = completed_file(&identity.scope)?;
                let bytes = serde_json::to_vec(&InitialDataCompletedRecord {
                    version: 3,
                    identity: identity.clone(),
                    initial_noc: stamp,
                })
                .map_err(|_| failed())?;
                if bytes.len() > marker.limit() {
                    return Err(failed());
                }
                // This one-shot original never imports an earlier/lost marker ACK.
                files.compare_exchange(marker, None, &bytes)?;
                if files.read(marker)?.as_deref() != Some(bytes.as_slice()) {
                    return Err(failed());
                }
                match_cold_snapshot(files, &expected)?;
                if let Some(native) = &native {
                    native.verify(files)?;
                }
                proof.verify_retirement(&original, &expected)?;
                index.active = None;
                index.completed = residual;
                save_index(files, raw.as_deref(), &index)?;
                // Actual index-CAS/readback ACK retained BEFORE callback/private
                // postflight. A failed CAS/readback can never reach this constructor.
                let ack = std::rc::Rc::new(InitialDataRetirementAck {
                    original: original.clone(),
                });
                self.initial_retirement_ack = Some(ack.clone());
                retain(ack.clone())?;
                for (i, kind) in RecordKind::OWNED.iter().enumerate() {
                    if files.read(kind.file())? != expected.stamp[i + 1] {
                        return Err(failed());
                    }
                }
                if files.read(marker)?.as_deref() != Some(bytes.as_slice()) {
                    return Err(failed());
                }
                let (_, after) = load_index(files)?;
                if after.active.is_some() || after.completed != index.completed {
                    return Err(failed());
                }
                require_retired_records(files, &after)?;
                proof.verify_retirement(&original, &expected)?;
                Ok(ack)
            })
            .map_err(|_| failed())?;
        if let Some(native) = native {
            native.finish();
        }
        flight.1 = true;
        Ok(ack)
    }
    /// SDK-free one-way SAME original initial journal handoff. Retains the
    /// canonical cleanup view before any validation/IO, and reads exact initial
    /// ACK bytes twice through that view. Only a SAME selected view is repeatable.
    pub(crate) fn enter_original_initial_cleanup(
        &mut self,
        canonical: ProtectedSessionFiles<I>,
    ) -> io::Result<()> {
        let previous = self.selected_files().clone();
        let repeated = self.initial_cleanup_files.is_some();
        let same_view = |a: &ProtectedSessionFiles<I>, b: &ProtectedSessionFiles<I>| {
            a.same_original_backend(b)
                && std::sync::Arc::ptr_eq(&a.epoch_history, &b.epoch_history)
                && a.retained_scope == b.retained_scope
                && a.cleanup_only == b.cleanup_only
                && a.native_cleanup == b.native_cleanup
                && match (&a.native_execution, &b.native_execution) {
                    (None, None) => true,
                    (Some(a), Some(b)) => std::sync::Weak::ptr_eq(a, b),
                    _ => false,
                }
        };
        if !repeated {
            // Publish the actual caller's view BEFORE pure checks, private IO
            // or postflight. Unknown/error/unwind never restores forward access.
            self.initial_cleanup_files = Some(canonical);
        } else if !same_view(&previous, &canonical) {
            self.initial_cleanup_failed = true;
            return Err(failed());
        }
        let already_failed = self.initial_cleanup_failed;
        self.initial_cleanup_failed = true;
        self.cleanup_only = true;
        let selected = self.initial_cleanup_files.as_ref().ok_or_else(failed)?;
        if already_failed
            || self.revoked
            || self.binding_failed.get()
            || !self.files.same_original_backend(selected)
            || !std::sync::Arc::ptr_eq(&self.files.epoch_history, &selected.epoch_history)
            || !selected.cleanup_only
            || selected.retained_scope.as_ref() != Some(&self.context.intent.scope)
            || match (&previous.native_execution, &selected.native_execution) {
                (None, None) => selected.native_cleanup,
                (Some(a), Some(b)) => !selected.native_cleanup || !std::sync::Weak::ptr_eq(a, b),
                _ => true,
            }
        {
            return Err(failed());
        }
        let record = self.initial_ack.as_ref().ok_or_else(failed)?;
        require_initial_native_data(record)?;
        let bytes = record.encode().map_err(|_| failed())?;
        // Read ONLY the selected explicit cleanup view: the old bound forward
        // root may already be revoked by Runtime's canonical cleanup handoff.
        for _ in 0..2 {
            let mut actual = selected.clone();
            let (access, raw, current) = native_snapshot(&mut actual, &self.context)?;
            access.require_native_context(&self.context)?;
            if access.fresh
                || raw.as_deref() != Some(bytes.as_slice())
                || current.as_ref() != Some(record)
            {
                return Err(failed());
            }
        }
        self.initial_cleanup_failed = false;
        Ok(())
    }
    /// Storage-only cleanup view for the SAME advanced original journal.
    /// The owner supplies its retained current ACK; no journal is reopened.
    pub(crate) fn enter_original_cleanup(
        &mut self,
        expected: &native_receipt::Record,
        resolve: impl FnOnce(&ProtectedSessionFiles<I>) -> io::Result<ProtectedSessionFiles<I>>,
    ) -> io::Result<()> {
        let failed_before =
            self.revoked || self.binding_failed.get() || self.initial_cleanup_failed;
        self.cleanup_only = true;
        self.binding_failed.set(true); // Err/unwind cannot restore a forward view.
        if failed_before
            || self.initial_cleanup_files.is_some()
            || self.initial_retirement_attempted
            || expected.context != self.context
        {
            return Err(failed());
        }
        let original = self.selected_files().clone();
        let canonical = resolve(&original)?;
        canonical.verify_native_row_cleanup_origin(&original)?; // pure SAME backend/root
        *self.selected_files_mut() = canonical; // accepted view retained before private IO
        let bytes = expected.encode().map_err(|_| failed())?;
        let context = self.context.clone();
        let (access, raw, current) = native_snapshot(self.selected_files_mut(), &context)?;
        access.require_native_context(&context)?;
        if access.fresh
            || raw.as_deref() != Some(bytes.as_slice())
            || current.as_ref() != Some(expected)
        {
            return Err(failed());
        }
        self.binding_failed.set(false);
        Ok(())
    }
    /// One storage-only handoff of the SAME initial journal, after real Runtime
    /// birth registration and before SDK/key attempts. Reopening an existing
    /// receipt remains cleanup-only. No context/epoch/SDK ACK is manufactured.
    /// Caller retains this journal/initial pin and the execution root first.
    /// The canonical view is retained before postflight; failure/unwind fences
    /// this original journal rather than reverting to its unbound files.
    pub(crate) fn bind_original_native_view(
        &self,
        mut canonical: ProtectedSessionFiles<I>,
    ) -> io::Result<()> {
        if self.binding_attempted.replace(true) {
            self.binding_failed.set(true);
            return Err(failed());
        }
        self.binding_failed.set(true);
        if self.revoked
            || self.cleanup_only
            || !self.files.same_original_backend(&canonical)
            || !std::sync::Arc::ptr_eq(&self.files.epoch_history, &canonical.epoch_history)
            || canonical.native_cleanup
            || canonical.cleanup_only
        {
            return Err(failed());
        }
        let mut old = self.files.clone();
        let (_, raw, current) = native_snapshot(&mut old, &self.context)?;
        let record = current.ok_or_else(failed)?;
        if self.initial_ack.as_ref() != Some(&record)
            || record.generation != 1
            || record.phase != native_receipt::Phase::Preparing
            || record.native_rows != native_receipt::FullNativeRows::Unbound
            || record.keys.iter().any(|k| {
                k.phase != native_receipt::KeyPhase::Unstarted
                    || k.new_key_ack
                    || k.pending.is_some()
                    || k.baseline != native_receipt::Value::Absent
                    || k.current != native_receipt::Value::Absent
            })
        {
            return Err(failed());
        }
        let (access, next_raw, next) = native_snapshot(&mut canonical, &self.context)?;
        if !access.is_registered_native_birth_view()
            || !access.fresh
            || next_raw != raw
            || next.as_ref() != Some(&record)
        {
            return Err(failed());
        }
        access.require_native_context(&self.context)?;
        self.bound_files.set(canonical).map_err(|_| failed())?;
        let mut retained = self.selected_files().clone();
        let (access, after_raw, after) = native_snapshot(&mut retained, &self.context)?;
        access.require_native_context(&self.context)?;
        if !access.fresh
            || !access.is_registered_native_birth_view()
            || after_raw != raw
            || after.as_ref() != Some(&record)
        {
            return Err(failed());
        }
        self.binding_failed.set(false);
        Ok(())
    }
}
#[allow(dead_code)]
impl<F: SessionFiles> WindowsNativeCarrierReceiptStore<F> {
    /// Read-only original backend reference for actual runtime/lock attachment.
    /// No fresh/native rights are supplied by this accessor or equal metadata.
    pub(super) fn original_files(&self, context: &native_receipt::Context) -> carrier::Result<&F> {
        self.require_context(context)?;
        if self.cleanup_only {
            return Err(carrier::CarrierError::Conflict);
        }
        Ok(self.selected_files())
    }
    pub(crate) fn open(
        mut files: F,
        context: native_receipt::Context,
    ) -> io::Result<(Self, Option<native_receipt::Record>)> {
        validate_native_context(&context)?;
        let (access, _, current) = native_snapshot(&mut files, &context)?;
        let cleanup_only = current.is_some() || !access.fresh;
        if !cleanup_only {
            access.require_native_context(&context)?;
        }
        Ok((
            Self {
                files,
                bound_files: std::sync::OnceLock::new(),
                binding_attempted: std::cell::Cell::new(false),
                binding_failed: std::cell::Cell::new(false),
                initial_ack: None,
                initial_cleanup_files: None,
                initial_cleanup_failed: false,
                initial_origin: std::rc::Rc::new(()),
                initial_retirement_attempted: false,
                initial_retirement_ack: None,
                context,
                cleanup_only,
                revoked: false,
            },
            current,
        ))
    }
    fn require_context(&self, context: &native_receipt::Context) -> carrier::Result<()> {
        if *context != self.context {
            return Err(carrier::CarrierError::Conflict);
        }
        if self.revoked || self.binding_failed.get() || self.initial_cleanup_failed {
            return Err(carrier::CarrierError::Journal);
        }
        Ok(())
    }
    fn selected_files(&self) -> &F {
        self.initial_cleanup_files
            .as_ref()
            .unwrap_or_else(|| self.bound_files.get().unwrap_or(&self.files))
    }
    fn selected_files_mut(&mut self) -> &mut F {
        self.initial_cleanup_files
            .as_mut()
            .unwrap_or_else(|| self.bound_files.get_mut().unwrap_or(&mut self.files))
    }
    fn revoke_live(&mut self) {
        if !self.cleanup_only {
            self.revoked = true;
            // Denial is permanent for this instance even if revocation itself
            // fails. The concrete authenticated adapter shares it with clones.
            let scope = self.context.intent.scope.clone();
            let _ = self
                .selected_files_mut()
                .revoke_native_carrier_access(&scope);
        }
    }
}
impl<F: SessionFiles> NativeJournal for WindowsNativeCarrierReceiptStore<F> {
    fn load(
        &mut self,
        context: &native_receipt::Context,
    ) -> carrier::Result<Option<native_receipt::Record>> {
        self.require_context(context)?;
        let (access, _, current) = native_snapshot(self.selected_files_mut(), context)
            .map_err(|_| carrier::CarrierError::Journal)?;
        if !self.cleanup_only
            && (!access.fresh
                || access.provenance.network_epoch != context.provenance.network_epoch)
        {
            return Err(carrier::CarrierError::Journal);
        }
        Ok(current)
    }
    fn compare_exchange(
        &mut self,
        context: &native_receipt::Context,
        expected: Option<&native_receipt::Record>,
        desired: &native_receipt::Record,
    ) -> carrier::Result<()> {
        self.require_context(context)?;
        if self.initial_cleanup_files.is_some() {
            return Err(carrier::CarrierError::Journal);
        }
        if desired.context != *context {
            return Err(carrier::CarrierError::Conflict);
        }
        let bytes = desired.encode()?;
        let (access, raw, current) = native_snapshot(self.selected_files_mut(), context)
            .map_err(|_| carrier::CarrierError::Journal)?;
        if !self.cleanup_only
            && (!access.fresh
                || access.provenance.network_epoch != context.provenance.network_epoch)
        {
            return Err(carrier::CarrierError::Journal);
        }
        if current.as_ref() != expected {
            return Err(carrier::CarrierError::Conflict);
        }
        native_receipt::validate_transition(current.as_ref(), desired, self.cleanup_only)?;
        let result = self.selected_files_mut().compare_exchange(
            &context.intent.scope,
            RecordKind::NativeCarrierReceipts,
            raw.as_deref(),
            &bytes,
        );
        if result.is_err() {
            self.revoke_live();
        }
        // Exact typed readback is necessary even after a success ACK. Snapshot
        // validates every byte's full context; private CAS used original bytes.
        let (actual_raw, actual) = match native_snapshot(self.selected_files_mut(), context) {
            Ok((_, actual_raw, actual)) => (actual_raw, actual),
            Err(_) => {
                self.revoke_live();
                return Err(carrier::CarrierError::Journal);
            }
        };
        if actual.as_ref() == Some(desired) && actual_raw.as_deref() == Some(bytes.as_slice()) {
            // Only cleanup may reconcile committed lost ACK. A fresh instance
            // must reopen cleanup-only even after an exact successful reread.
            if self.revoked {
                return Err(carrier::CarrierError::Journal);
            }
            if !self.cleanup_only && expected.is_none() && result.is_ok() {
                self.initial_ack = Some(desired.clone());
            }
            return Ok(());
        }
        self.revoke_live();
        if actual.as_ref() != expected {
            return Err(carrier::CarrierError::Conflict);
        }
        Err(carrier::CarrierError::Journal)
    }
}

fn validate_native_context(context: &native_receipt::Context) -> io::Result<()> {
    // Semantic reconstruction uses the same strict v2 validator. This template
    // is never stored and confers neither a new-key ACK nor native authority.
    let record = native_receipt::Record {
        version: 2,
        context: context.clone(),
        generation: 1,
        phase: native_receipt::Phase::Preparing,
        keys: [
            native_receipt::Role::RoleCarrier,
            native_receipt::Role::MemberA,
            native_receipt::Role::MemberB,
        ]
        .map(|role| native_receipt::KeyReceipt {
            role,
            phase: native_receipt::KeyPhase::Unstarted,
            new_key_ack: false,
            baseline: native_receipt::Value::Absent,
            current: native_receipt::Value::Absent,
            pending: None,
        }),
        native_rows: native_receipt::FullNativeRows::Unbound,
    };
    native_receipt::validate_record(&record).map_err(|_| failed())
}
fn creator_payload(scope: &SessionScope, bytes: &[u8]) -> io::Result<CreatorRecord> {
    let record = CreatorRecord::decode(bytes)?;
    if &record.context().intent.scope != scope {
        return Err(failed());
    }
    Ok(record)
}
fn require_initial_creator_window(
    files: &mut dyn PrivateRecords,
    index: &SessionIndex,
    identity: &SessionIdentity,
) -> io::Result<Option<Vec<u8>>> {
    let (raw, session) = load_record(files, index, identity, RecordKind::Session)?;
    if session.as_ref().is_some_and(|s| s.network_epoch != 1) {
        return Err(failed());
    }
    if let Some(session) = session {
        if decode::<SessionSnapshot>(&identity.scope, session.data.as_bytes())?.phase
            != nelomai_client_tunnel::redundancy::session::SessionPhase::Starting
        {
            return Err(failed());
        }
    }
    for other in RecordKind::OWNED {
        if !matches!(other, RecordKind::Session | RecordKind::NativeCreator)
            && load_record(files, index, identity, other)?.1.is_some()
        {
            return Err(failed());
        }
    }
    Ok(raw)
}
fn authenticate_creator(
    record: &CreatorRecord,
    identity: &SessionIdentity,
    epoch: u64,
) -> io::Result<()> {
    let context = record.context();
    if context.intent.scope != identity.scope
        || context.provenance.boot_id != identity.boot_id
        || context.provenance.runtime != identity.runtime
        || context.provenance.network_epoch != epoch
    {
        return Err(failed());
    }
    Ok(())
}

pub(crate) struct WindowsNativeCreatorStore<F> {
    files: F,
    context: native_receipt::Context,
    attempted: bool,
    acknowledged: Option<CreatorRecord>,
}
impl<F: SessionFiles> WindowsNativeCreatorStore<F> {
    pub(crate) fn open(mut files: F, context: native_receipt::Context) -> io::Result<Self> {
        let access = files.native_carrier_access(&context.intent.scope)?;
        access.require_native_context(&context)?;
        if !access.fresh
            || files
                .read(&context.intent.scope, RecordKind::NativeCreator)?
                .is_some()
        {
            return Err(failed());
        }
        Ok(Self {
            files,
            context,
            attempted: false,
            acknowledged: None,
        })
    }
    /// Storage DATA receiver. Production MUST invoke this ONLY inside original
    /// CapturedCreator::publish (actual signed Runtime/current-kernel bracket).
    /// Caller retains BOTH store and capture before this one-shot publication.
    pub(crate) fn publish(&mut self, record: &CreatorRecord) -> io::Result<()> {
        if self.attempted {
            return Err(failed());
        }
        self.attempted = true;
        record.require_context(&self.context)?;
        let bytes = record.encode()?;
        let access = self
            .files
            .native_carrier_access(&self.context.intent.scope)?;
        access.require_native_context(&self.context)?;
        if !access.fresh {
            return Err(failed());
        }
        self.files.compare_exchange(
            &self.context.intent.scope,
            RecordKind::NativeCreator,
            None,
            &bytes,
        )?;
        // Genuine protected CAS returned successfully. Retain before readback;
        // a failed readback still fails publish and cannot be retried/adopted.
        self.acknowledged = Some(record.clone());
        if self
            .files
            .read(&self.context.intent.scope, RecordKind::NativeCreator)?
            .as_deref()
            != Some(bytes.as_slice())
        {
            return Err(failed());
        }
        let access = self
            .files
            .native_carrier_access(&self.context.intent.scope)?;
        access.require_native_context(&self.context)?;
        if !access.fresh {
            return Err(failed());
        }
        Ok(())
    }
}
fn native_payload(scope: &SessionScope, bytes: &[u8]) -> io::Result<native_receipt::Record> {
    let record = native_receipt::Record::decode(bytes).map_err(|_| failed())?;
    if record.context.intent.scope != *scope {
        return Err(failed());
    }
    Ok(record)
}
fn authenticate_native(
    record: &native_receipt::Record,
    identity: &SessionIdentity,
    epoch: u64,
) -> io::Result<()> {
    if record.context.intent.scope != identity.scope
        || record.context.provenance.boot_id != identity.boot_id
        || record.context.provenance.runtime != identity.runtime
        || record.context.provenance.network_epoch != epoch
    {
        return Err(failed());
    }
    Ok(())
}
fn require_stopped_native(saved: &SavedRecord) -> io::Result<()> {
    if native_payload(&saved.identity.scope, saved.data.as_bytes())?.phase
        != native_receipt::Phase::Stopped
    {
        return Err(failed());
    }
    Ok(())
}
fn require_initial_native_data(record: &native_receipt::Record) -> io::Result<()> {
    if record.generation != 1
        || record.phase != native_receipt::Phase::Preparing
        || record.native_rows != native_receipt::FullNativeRows::Unbound
        || record.keys.iter().any(|k| {
            k.phase != native_receipt::KeyPhase::Unstarted
                || k.new_key_ack
                || k.pending.is_some()
                || k.baseline != native_receipt::Value::Absent
                || k.current != native_receipt::Value::Absent
        })
    {
        return Err(failed());
    }
    Ok(())
}
fn require_initial_noc_records(
    facts: &ProtectedRecoveryRecords,
    acknowledged: &native_receipt::Record,
) -> io::Result<()> {
    require_initial_native_data(acknowledged)?;
    let payload = |kind| {
        facts
            .records
            .iter()
            .find(|(k, _)| *k == kind)
            .and_then(|(_, b)| b.as_deref())
    };
    if facts.scope != acknowledged.context.intent.scope
        || facts.changed_boot
        || facts.provenance.boot_id != acknowledged.context.provenance.boot_id
        || facts.provenance.runtime != acknowledged.context.provenance.runtime
        || native_receipt::Record::decode(
            payload(RecordKind::NativeCarrierReceipts).ok_or_else(failed)?,
        )
        .map_err(|_| failed())?
            != *acknowledged
        || [
            RecordKind::Network,
            RecordKind::Carrier,
            RecordKind::CarrierGuard,
            RecordKind::CarrierRows,
            RecordKind::MemberARows,
            RecordKind::MemberBRows,
        ]
        .iter()
        .any(|kind| payload(*kind).is_some())
    {
        return Err(failed());
    }
    let session: SessionSnapshot = decode(
        &facts.scope,
        payload(RecordKind::Session).ok_or_else(failed)?,
    )?;
    if session.phase != nelomai_client_tunnel::redundancy::session::SessionPhase::Stopped
        || session.network_epoch != facts.provenance.network_epoch
    {
        return Err(failed());
    }
    if let Some(creator) = facts.creator_obligation()? {
        creator.require_context(&acknowledged.context)?;
    }
    // Missing Pair is admitted ONLY by the separate original outcome check in
    // the same retirement transaction. This predicate supplies no authority.
    let Some(raw_pair) = payload(RecordKind::Pair) else {
        return Ok(());
    };
    let crate::member_carrier_pair::CleanupRecord::Carrier(pair) =
        carrier_pair_store::decode_pair_payload(&facts.scope, raw_pair)?
    else {
        return Err(failed());
    };
    if pair.provenance != acknowledged.context.provenance
        || pair.network.is_some()
        || pair.guard != carrier_guard::Model::empty(facts.scope.clone()).map_err(|_| failed())?
    {
        return Err(failed());
    }
    carrier_pair_store::require_terminal_pair(&facts.scope, raw_pair)?;
    Ok(())
}
fn require_native_obligation(
    files: &mut dyn PrivateRecords,
    index: &SessionIndex,
    identity: &SessionIdentity,
) -> io::Result<()> {
    require_rows_obligations(files, index, identity)?;
    if let Some(saved) = load_record(files, index, identity, RecordKind::CarrierGuard)?.1 {
        if saved.network_epoch > current_epoch(files, index, identity)? {
            return Err(failed());
        }
    }
    let (_, saved) = load_record(files, index, identity, RecordKind::NativeCarrierReceipts)?;
    if let Some(saved) = saved {
        if saved.network_epoch > current_epoch(files, index, identity)? {
            return Err(failed());
        }
    }
    Ok(())
}
type NativeSnapshot = (
    CarrierAccess,
    Option<Vec<u8>>,
    Option<native_receipt::Record>,
);
fn native_snapshot<F: SessionFiles>(
    files: &mut F,
    context: &native_receipt::Context,
) -> io::Result<NativeSnapshot> {
    let access = files.native_carrier_access(&context.intent.scope)?;
    if access.scope != context.intent.scope
        || access.provenance.boot_id != context.provenance.boot_id
        || access.provenance.runtime != context.provenance.runtime
        || context.provenance.network_epoch == 0
        || context.provenance.network_epoch > access.provenance.network_epoch
    {
        return Err(failed());
    }
    let raw = files.read(&context.intent.scope, RecordKind::NativeCarrierReceipts)?;
    let current = raw
        .as_ref()
        .map(|b| native_payload(&context.intent.scope, b))
        .transpose()?;
    if current
        .as_ref()
        .is_some_and(|record| record.context != *context)
    {
        return Err(failed());
    }
    Ok((access, raw, current))
}

#[cfg(test)]
#[path = "member_carrier_native_store_tests.rs"]
mod native_carrier_store_tests;

/// Storage only. The caller supplies independently established FULL Binding;
/// opening/loading never constructs an OriginalCreator or address-create receipt.
/// File transactions do not substitute for the actual native-owner lock.
#[allow(dead_code)] // Deliberately disconnected native factory; exercised by host store tests.
pub(crate) struct WindowsCarrierRowsStore<F> {
    files: F,
    binding: rows::Binding,
    cleanup_only: bool,
    revoked: bool,
    // Separate verified storage channel; never clears the forward latch.
    cleanup_handoff: bool,
    created_cleanup: Option<std::rc::Rc<dyn OriginalCreatedAddressCleanupWrite>>,
    created_cleanup_history: Vec<std::rc::Rc<dyn OriginalCreatedAddressCleanupWrite>>,
    initial_cleanup: Option<std::rc::Rc<dyn OriginalInitialRowCaptureCleanupWrite>>,
    initial_cleanup_history: Vec<std::rc::Rc<dyn OriginalInitialRowCaptureCleanupWrite>>,
}
/// One attempted generation handoff. Original payload and unsafe boundary are
/// retained by construction before validation/IO. Rc is local to this holder,
/// never a field of ProtectedSessionFiles or the ordinary Send row store.
pub(crate) struct WindowsCarrierRowsGenerationStore<F> {
    inner: WindowsCarrierRowsStore<F>,
    stopped_payload: Vec<u8>,
    authority: std::rc::Rc<dyn OriginalRowGenerationWrite>,
    attempted: bool,
    first_acknowledged: bool,
    cleanup_attempted: bool,
}
#[allow(dead_code)] // Opening is explicit; no production selection in this task.
impl<F: SessionFiles> WindowsCarrierRowsStore<F> {
    /// Separate initial-invocation lane, including actual absence after an
    /// unapplied CAS. Only typed SAME execution-root cleanup files are retained;
    /// every write still requires the original sealed invocation/native issuer.
    pub(crate) fn enter_initial_capture_cleanup(&mut self, mut files: F) -> io::Result<()> {
        let original = self.files.clone();
        self.revoked = true;
        self.cleanup_only = true;
        self.cleanup_handoff = false;
        let authority = self.initial_cleanup.clone().ok_or_else(failed)?;
        if self.binding.role != rows::Role::Carrier {
            return Err(failed());
        }
        files.verify_native_row_cleanup_origin(&original)?;
        files.verify_initial_row_capture_cleanup_registration(authority.as_ref())?;
        if authority.row_original().binding_original() != &self.binding {
            return Err(failed());
        }
        let (access, raw, current) = rows_snapshot(&mut files, &self.binding)?;
        if access.is_fresh() || !access.is_registered_native_birth_view() {
            return Err(failed());
        }
        self.files = files; // retained before fallible postflight
        self.files.verify_native_row_cleanup_origin(&original)?;
        self.files
            .verify_initial_row_capture_cleanup_registration(authority.as_ref())?;
        let (after, after_raw, after_current) = rows_snapshot(&mut self.files, &self.binding)?;
        if after.is_fresh()
            || !after.is_registered_native_birth_view()
            || after_raw != raw
            || after_current != current
        {
            return Err(failed());
        }
        self.cleanup_handoff = true;
        Ok(())
    }
    pub(crate) fn retain_initial_capture_cleanup_authority(
        &mut self,
        authority: std::rc::Rc<dyn OriginalInitialRowCaptureCleanupWrite>,
    ) -> rows::Result<()> {
        if self
            .initial_cleanup
            .as_ref()
            .is_some_and(|old| std::rc::Rc::ptr_eq(old, &authority))
        {
            return Ok(());
        }
        self.initial_cleanup_history
            .try_reserve(1)
            .map_err(|_| rows::Error::Journal)?;
        self.initial_cleanup_history.push(authority.clone());
        self.files
            .verify_initial_row_capture_cleanup_registration(authority.as_ref())
            .map_err(|_| rows::Error::Conflict)?;
        if authority.row_original().binding_original() != &self.binding {
            return Err(rows::Error::Conflict);
        }
        if self.initial_cleanup.as_ref().is_some_and(|old| {
            !old.backend_original()
                .same_original(authority.backend_original())
                || !old.row_original().same_original(authority.row_original())
        }) {
            return Err(rows::Error::Conflict);
        }
        self.initial_cleanup = Some(authority);
        Ok(())
    }
    /// Retain every actual issuer before fallible registration; rotate only
    /// within SAME original backend/birth and row pin. Expired issuers stay
    /// rooted as historical obligations, never refreshed. Each use must pass
    /// mandatory pure original/backend/Closing/Calling/Pair checks plus the raw
    /// firewall.
    pub(crate) fn retain_created_cleanup_authority(
        &mut self,
        authority: std::rc::Rc<dyn OriginalCreatedAddressCleanupWrite>,
    ) -> rows::Result<()> {
        if self
            .created_cleanup
            .as_ref()
            .is_some_and(|old| std::rc::Rc::ptr_eq(old, &authority))
        {
            return Ok(()); // registration is NOT a use of an expired token
        }
        self.created_cleanup_history
            .try_reserve(1)
            .map_err(|_| rows::Error::Journal)?;
        self.created_cleanup_history.push(authority.clone()); // before fallible origin checks
        self.files
            .verify_created_row_cleanup_registration(authority.as_ref())
            .map_err(|_| rows::Error::Conflict)?;
        authority.row_original().with_cleanup_record(
            &self.binding.scope,
            self.binding.network_epoch,
            |facts| {
                if facts.binding == &self.binding {
                    Ok(())
                } else {
                    Err(rows::Error::Conflict)
                }
            },
        )?;
        if let Some(old) = &self.created_cleanup {
            if !old
                .backend_original()
                .same_original(authority.backend_original())
                || !old.row_original().same_original(authority.row_original())
            {
                return Err(rows::Error::Conflict);
            }
        }
        self.created_cleanup = Some(authority);
        Ok(())
    }
    /// Keep the original journal/owner/binding. Caller supplies canonical
    /// cleanup files from the SAME original execution root before native cleanup.
    /// This is storage only: no SDK, new owner, durable ACK or forward grant.
    pub(crate) fn enter_cleanup(&mut self, mut files: F) -> io::Result<()> {
        let original = self.files.clone();
        self.revoked = true;
        self.cleanup_only = true;
        self.cleanup_handoff = false;
        files.verify_native_row_cleanup_origin(&original)?; // pure, before IO
        let (access, raw, current) = rows_snapshot(&mut files, &self.binding)?;
        if access.is_fresh() || !access.is_registered_native_birth_view() || current.is_none() {
            return Err(failed());
        }
        self.files = files; // retain supplied original view before postflight
        self.files.verify_native_row_cleanup_origin(&original)?;
        let (after, after_raw, after_current) = rows_snapshot(&mut self.files, &self.binding)?;
        if after.is_fresh()
            || !after.is_registered_native_birth_view()
            || after_raw != raw
            || after_current != current
        {
            return Err(failed());
        }
        self.cleanup_handoff = true;
        Ok(())
    }
    pub(crate) fn open_generation(
        files: F,
        new_binding: rows::Binding,
        stopped_payload: Vec<u8>,
        authority: std::rc::Rc<dyn OriginalRowGenerationWrite>,
    ) -> WindowsCarrierRowsGenerationStore<F> {
        WindowsCarrierRowsGenerationStore {
            inner: Self {
                files,
                binding: new_binding,
                cleanup_only: false,
                revoked: false,
                cleanup_handoff: false,
                created_cleanup: None,
                created_cleanup_history: Vec::new(),
                initial_cleanup: None,
                initial_cleanup_history: Vec::new(),
            },
            stopped_payload,
            authority,
            attempted: false,
            first_acknowledged: false,
            cleanup_attempted: false,
        }
    }
    pub(crate) fn open(
        mut files: F,
        binding: rows::Binding,
    ) -> io::Result<(Self, Option<rows::Record>)> {
        binding.validate().map_err(|_| failed())?;
        let (access, _, current) = rows_snapshot(&mut files, &binding)?;
        let cleanup_only = current.is_some() || !access.is_fresh();
        if !cleanup_only && binding.network_epoch != access.provenance.network_epoch {
            return Err(failed());
        }
        if cleanup_only {
            // Downgrade this private file view too: the raw boundary must
            // independently reject resume even if another clone is still fresh.
            files = files
                .recovery_view(binding.scope.runtime)?
                .ok_or_else(failed)?
                .0;
            let (access, _, again) = rows_snapshot(&mut files, &binding)?;
            if access.fresh || again != current {
                return Err(failed());
            }
        }
        Ok((
            Self {
                files,
                binding,
                cleanup_only,
                revoked: false,
                cleanup_handoff: false,
                created_cleanup: None,
                created_cleanup_history: Vec::new(),
                initial_cleanup: None,
                initial_cleanup_history: Vec::new(),
            },
            current,
        ))
    }
    fn require_binding(&self, binding: &rows::Binding) -> rows::Result<()> {
        if *binding != self.binding {
            return Err(rows::Error::Conflict);
        }
        if self.revoked && !self.cleanup_handoff {
            return Err(rows::Error::Journal);
        }
        Ok(())
    }
    fn revoke(&mut self) {
        if !self.cleanup_only {
            self.revoked = true;
        }
        let _ = self.files.revoke_native_carrier_access(&self.binding.scope);
    }
    fn exchange(
        &mut self,
        binding: &rows::Binding,
        expected: Option<&rows::Record>,
        desired: &rows::Record,
    ) -> rows::Result<()> {
        self.require_binding(binding)?;
        if desired.binding != *binding {
            return Err(rows::Error::Conflict);
        }
        let bytes = desired.encode()?;
        let (access, raw, current) =
            rows_snapshot(&mut self.files, binding).map_err(|_| rows::Error::Journal)?;
        if !self.cleanup_only
            && (!access.fresh || binding.network_epoch != access.provenance.network_epoch)
        {
            return Err(rows::Error::Journal);
        }
        if current.as_ref() != expected {
            return Err(rows::Error::Conflict);
        }
        rows::validate_transition(current.as_ref(), desired, self.cleanup_only)?;
        // Actual original payload bytes; do NOT reserialize expected.
        let result = self.files.compare_exchange(
            &binding.scope,
            rows_kind(binding.role),
            raw.as_deref(),
            &bytes,
        );
        if result.is_err() {
            self.revoke();
        }
        let (_, actual_raw, actual) =
            rows_snapshot(&mut self.files, binding).map_err(|_| rows::Error::Journal)?;
        if actual.as_ref() == Some(desired) && actual_raw.as_deref() == Some(bytes.as_slice()) {
            return if self.revoked && !self.cleanup_handoff {
                Err(rows::Error::Journal)
            } else {
                Ok(())
            };
        }
        if actual.as_ref() != expected {
            return Err(rows::Error::Conflict);
        }
        Err(rows::Error::Journal)
    }
}
impl<F: SessionFiles> rows::Journal for WindowsCarrierRowsStore<F> {
    fn load(&mut self, binding: &rows::Binding) -> rows::Result<Option<rows::Record>> {
        self.require_binding(binding)?;
        let (access, _, current) =
            rows_snapshot(&mut self.files, binding).map_err(|_| rows::Error::Journal)?;
        if !self.cleanup_only
            && (!access.fresh || binding.network_epoch != access.provenance.network_epoch)
        {
            return Err(rows::Error::Journal);
        }
        Ok(current)
    }
    fn compare_exchange(
        &mut self,
        binding: &rows::Binding,
        expected: Option<&rows::Record>,
        desired: &rows::Record,
    ) -> rows::Result<()> {
        let result = self.exchange(binding, expected, desired);
        // EVERY failed/unconfirmed CAS, including preflight/schema/context/CAS
        // mismatch, revokes shared fresh permission, even if no file was written.
        if result.is_err() {
            self.revoke();
        }
        result
    }
}
unsafe impl<F: SessionFiles> original_native_rows::CreatedAddressCleanupJournal
    for WindowsCarrierRowsStore<F>
{
    fn compare_exchange_created_cleanup(
        &mut self,
        binding: &rows::Binding,
        expected: &rows::Record,
        desired: &rows::Record,
        original: &original_native_rows::CreatedAddressCleanupRead<'_>,
    ) -> rows::Result<()> {
        self.require_binding(binding)?;
        if binding.role != rows::Role::Carrier || !self.cleanup_handoff {
            return Err(rows::Error::Retired);
        }
        let authority = self.created_cleanup.clone().ok_or(rows::Error::Retired)?;
        self.files
            .verify_created_row_cleanup_origin(original, authority.as_ref())
            .map_err(|_| rows::Error::Journal)?;
        let (access, raw, current) =
            rows_snapshot(&mut self.files, binding).map_err(|_| rows::Error::Journal)?;
        if access.is_fresh()
            || !access.is_registered_native_birth_view()
            || current.as_ref() != Some(expected)
        {
            return Err(rows::Error::Conflict);
        }
        original.verify_exchange(binding, expected, desired)?;
        let bytes = desired.encode()?;
        let ack = self.files.compare_exchange_created_row_cleanup(
            &binding.scope,
            raw.as_deref().ok_or(rows::Error::Journal)?,
            &bytes,
            original,
            authority.as_ref(),
        );
        if ack.is_err() {
            self.revoke();
        }
        let (_, actual_raw, actual) =
            rows_snapshot(&mut self.files, binding).map_err(|_| rows::Error::Journal)?;
        if actual.as_ref() != Some(desired) || actual_raw.as_deref() != Some(bytes.as_slice()) {
            return Err(rows::Error::Journal);
        }
        // Readback keeps an obligation; NEVER return success for a lost ACK.
        ack.map_err(|_| rows::Error::Journal)
    }
}
unsafe impl<F: SessionFiles> original_native_rows::InitialRowCaptureCleanupJournal
    for WindowsCarrierRowsStore<F>
{
    fn compare_exchange_initial_capture_cleanup(
        &mut self,
        binding: &rows::Binding,
        expected: Option<&rows::Record>,
        desired: &rows::Record,
        original: &original_native_rows::InitialRowCaptureCleanupRead<'_>,
    ) -> rows::Result<()> {
        self.require_binding(binding)?;
        if binding.role != rows::Role::Carrier || !self.cleanup_handoff {
            return Err(rows::Error::Retired);
        }
        let authority = self.initial_cleanup.clone().ok_or(rows::Error::Retired)?;
        self.files
            .verify_initial_row_capture_cleanup_origin(original, authority.as_ref())
            .map_err(|_| rows::Error::Journal)?;
        let (access, raw, current) =
            rows_snapshot(&mut self.files, binding).map_err(|_| rows::Error::Journal)?;
        if access.is_fresh()
            || !access.is_registered_native_birth_view()
            || current.as_ref() != expected
        {
            return Err(rows::Error::Conflict);
        }
        original.verify_exchange(binding, expected, desired)?;
        let bytes = desired.encode()?;
        original.verify_payloads(raw.as_deref(), &bytes)?;
        let ack = self.files.compare_exchange_initial_row_capture_cleanup(
            &binding.scope,
            raw.as_deref(),
            &bytes,
            original,
            authority.as_ref(),
        );
        if ack.is_err() {
            self.revoke();
        }
        let (_, actual_raw, actual) =
            rows_snapshot(&mut self.files, binding).map_err(|_| rows::Error::Journal)?;
        if actual.as_ref() != Some(desired) || actual_raw.as_deref() != Some(bytes.as_slice()) {
            return Err(rows::Error::Journal);
        }
        ack.map_err(|_| rows::Error::Journal)
    }
}
impl<F: SessionFiles> WindowsCarrierRowsGenerationStore<F> {
    /// Explicit storage-only cleanup handoff. Caller retains the same native
    /// RowOwner/pin and obtains canonical typed cleanup files from the original
    /// execution root; this grants no SDK effect and never reopens forward.
    pub(crate) fn enter_cleanup(&mut self, mut files: F) -> io::Result<()> {
        let original = self.inner.files.clone();
        // Irreversible local cleanup, retained before any fallible proof. No
        // reset of revoked: only the separate cleanup path can use this holder.
        self.cleanup_attempted = true;
        self.inner.cleanup_handoff = false;
        self.inner.revoked = true;
        self.inner.cleanup_only = true;
        if !self.first_acknowledged {
            return Err(failed());
        }
        files.verify_native_row_cleanup_origin(&original)?; // pure SAME typed parent
        files.verify_cleanup_row_generation_origin(self.authority.as_ref())?;
        let (access, raw, current) = rows_snapshot(&mut files, &self.inner.binding)?;
        if access.is_fresh() || !access.is_registered_native_birth_view() || current.is_none() {
            return Err(failed());
        }
        self.inner.files = files; // retain SAME provided cleanup view before postflight
        self.inner
            .files
            .verify_native_row_cleanup_origin(&original)?;
        let (after, after_raw, after_current) =
            rows_snapshot(&mut self.inner.files, &self.inner.binding)?;
        self.inner
            .files
            .verify_cleanup_row_generation_origin(self.authority.as_ref())?;
        if after.is_fresh()
            || !after.is_registered_native_birth_view()
            || after_raw != raw
            || after_current != current
        {
            return Err(failed());
        }
        self.inner.cleanup_handoff = true;
        Ok(())
    }
    fn require_binding(&self, binding: &rows::Binding) -> rows::Result<()> {
        binding.validate()?;
        if binding != &self.inner.binding || (self.inner.revoked && !self.inner.cleanup_only) {
            return Err(rows::Error::Retired);
        }
        if self.cleanup_attempted && !self.inner.cleanup_handoff {
            return Err(rows::Error::Journal);
        }
        if self.inner.cleanup_handoff {
            self.inner
                .files
                .verify_native_row_cleanup_origin(&self.inner.files)
                .and_then(|_| {
                    self.inner
                        .files
                        .verify_cleanup_row_generation_origin(self.authority.as_ref())
                })
                .map_err(|_| rows::Error::Journal)?;
        } else if self.inner.revoked {
            self.inner
                .files
                .verify_completed_row_generation_origin(self.authority.as_ref())
                .map_err(|_| rows::Error::Journal)?;
        }
        Ok(())
    }
    fn snapshot(&mut self) -> rows::Result<(Option<Vec<u8>>, Option<rows::Record>)> {
        let b = &self.inner.binding;
        b.validate()?;
        if self.inner.cleanup_handoff {
            self.inner
                .files
                .verify_native_row_cleanup_origin(&self.inner.files)
                .and_then(|_| {
                    self.inner
                        .files
                        .verify_cleanup_row_generation_origin(self.authority.as_ref())
                })
        } else if self.first_acknowledged {
            self.inner
                .files
                .verify_row_generation_storage_origin(self.authority.as_ref())
        } else {
            self.inner
                .files
                .verify_row_generation_origin(self.authority.as_ref())
        }
        .map_err(|_| rows::Error::Journal)?;
        // After genuine handoff, read SAME original typed cleanup files, not
        // the separate completed-only readonly-obligation fallback.
        let obligation =
            self.inner.revoked && self.inner.cleanup_only && !self.inner.cleanup_handoff;
        let (access, raw) = if obligation {
            self.inner.files.read_completed_row_generation(
                &b.scope,
                rows_kind(b.role),
                self.authority.as_ref(),
            )
        } else {
            self.inner
                .files
                .native_carrier_access(&b.scope)
                .and_then(|access| {
                    self.inner
                        .files
                        .read(&b.scope, rows_kind(b.role))
                        .map(|raw| (access, raw))
                })
        }
        .map_err(|_| rows::Error::Journal)?;
        if self.inner.cleanup_handoff {
            self.inner
                .files
                .verify_cleanup_row_generation_origin(self.authority.as_ref())
                .map_err(|_| rows::Error::Journal)?;
        }
        if access.scope != b.scope
            || access.provenance.boot_id != b.boot_id
            || access.provenance.runtime != b.runtime
            || b.network_epoch == 0
            || b.network_epoch > access.provenance.network_epoch
            || (b.network_epoch != access.provenance.network_epoch
                && !access.is_registered_native_birth_view())
        {
            return Err(rows::Error::Journal);
        }
        let current = raw
            .as_deref()
            .map(|bytes| rows_payload(rows_kind(b.role), &b.scope, bytes))
            .transpose()
            .map_err(|_| rows::Error::Journal)?;
        if !self.first_acknowledged {
            if self.attempted
                || !access.fresh
                || raw.as_deref() != Some(self.stopped_payload.as_slice())
            {
                return Err(rows::Error::Journal);
            }
            let old = current.as_ref().ok_or(rows::Error::Conflict)?;
            let mut expected_binding = old.binding.clone();
            expected_binding.key = b.key;
            if old.phase != rows::Phase::Stopped
                || old.pending.is_some()
                || old.creation.is_some()
                || old.current.address.is_some()
                || !rows::same_owned(&old.current, &old.baseline)
                || expected_binding != *b
                || !matches!(b.role, rows::Role::MemberA | rows::Role::MemberB)
            {
                return Err(rows::Error::Conflict);
            }
            Ok((raw, None)) // exact old stopped bytes remain present; no deletion
        } else {
            if !access.fresh {
                self.inner.cleanup_only = true;
            }
            if current.as_ref().is_none_or(|record| record.binding != *b) {
                return Err(rows::Error::Conflict);
            }
            Ok((raw, current))
        }
    }
    fn exchange_generation(
        &mut self,
        binding: &rows::Binding,
        expected: Option<&rows::Record>,
        desired: &rows::Record,
    ) -> rows::Result<()> {
        self.require_binding(binding)?;
        let was_revoked = self.inner.revoked;
        if was_revoked && !self.inner.cleanup_handoff {
            // The readonly completed-obligation reader is not a writer. Only
            // explicit successful SAME-root typed handoff can enable cleanup CAS.
            return Err(rows::Error::Journal);
        }
        // Unwind/fallible paths cannot reopen this holder or import readback.
        self.inner.revoked = true;
        let authority = self.authority.clone();
        let mut flight = RowGenerationWriteFlight {
            authority: authority.as_ref(),
            done: false,
        };
        if desired.binding != *binding {
            return Err(rows::Error::Conflict);
        }
        let bytes = desired.encode()?;
        if !self.first_acknowledged {
            if std::mem::replace(&mut self.attempted, true) || expected.is_some() {
                return Err(rows::Error::Conflict);
            }
            rows::validate_transition(None, desired, false)?;
            self.inner
                .files
                .compare_exchange_row_generation(
                    &binding.scope,
                    rows_kind(binding.role),
                    &self.stopped_payload,
                    &bytes,
                    authority.as_ref(),
                )
                .map_err(|_| rows::Error::Journal)?;
            self.first_acknowledged = true; // actual raw successful ACK, BEFORE fallible readback
        } else {
            if self.inner.cleanup_handoff {
                self.inner
                    .files
                    .verify_cleanup_row_generation_origin(authority.as_ref())
            } else {
                self.inner
                    .files
                    .verify_completed_row_generation_origin(authority.as_ref())
            }
            .map_err(|_| rows::Error::Journal)?;
            let (raw, current) = self.snapshot()?;
            if current.as_ref() != expected {
                return Err(rows::Error::Conflict);
            }
            rows::validate_transition(current.as_ref(), desired, self.inner.cleanup_only)?;
            self.inner
                .files
                .compare_exchange(
                    &binding.scope,
                    rows_kind(binding.role),
                    raw.as_deref(),
                    &bytes,
                )
                .map_err(|_| rows::Error::Journal)?;
        }
        let (actual_raw, actual) = self.snapshot()?;
        if actual_raw.as_deref() != Some(bytes.as_slice()) || actual.as_ref() != Some(desired) {
            return Err(rows::Error::Journal);
        }
        self.inner.revoked = was_revoked; // cleanup never clears prior revocation
        flight.done = true;
        Ok(())
    }
}
impl<F: SessionFiles> rows::Journal for WindowsCarrierRowsGenerationStore<F> {
    fn load(&mut self, binding: &rows::Binding) -> rows::Result<Option<rows::Record>> {
        let result = self
            .require_binding(binding)
            .and_then(|_| self.snapshot().map(|(_, record)| record));
        if result.is_err() {
            self.inner.revoke();
            if self.first_acknowledged {
                self.inner.cleanup_only = true;
            }
            self.authority.fail_write();
        }
        result
    }
    fn compare_exchange(
        &mut self,
        binding: &rows::Binding,
        expected: Option<&rows::Record>,
        desired: &rows::Record,
    ) -> rows::Result<()> {
        let result = self.exchange_generation(binding, expected, desired);
        if result.is_err() {
            self.inner.revoke();
            if self.first_acknowledged {
                self.inner.cleanup_only = true;
            }
            self.authority.fail_write();
        }
        result
    }
}
#[allow(dead_code)] // Typed factory constructor remains unwired.
fn rows_kind(role: rows::Role) -> RecordKind {
    match role {
        rows::Role::Carrier => RecordKind::CarrierRows,
        rows::Role::MemberA => RecordKind::MemberARows,
        rows::Role::MemberB => RecordKind::MemberBRows,
    }
}
fn rows_payload(kind: RecordKind, scope: &SessionScope, bytes: &[u8]) -> io::Result<rows::Record> {
    let record = rows::Record::decode(bytes).map_err(|_| failed())?;
    if record.binding.scope != *scope || kind.row_role() != Some(record.binding.role) {
        return Err(failed());
    }
    Ok(record)
}
fn validate_row_generation(
    kind: RecordKind,
    old: &rows::Record,
    next: &rows::Record,
    fresh: bool,
) -> io::Result<()> {
    old.validate().map_err(|_| failed())?;
    next.validate().map_err(|_| failed())?;
    let mut retained_binding = old.binding.clone();
    retained_binding.key = next.binding.key;
    if !fresh
        || !matches!(kind, RecordKind::MemberARows | RecordKind::MemberBRows)
        || kind.row_role() != Some(old.binding.role)
        || next.binding != retained_binding
        || old.phase != rows::Phase::Stopped
        || old.pending.is_some()
        || old.creation.is_some()
        || old.current.address.is_some()
        || !rows::same_owned(&old.current, &old.baseline)
        || next.phase != rows::Phase::Captured
        || next.revision != 1
        || next.current != next.baseline
        || next.current.address.is_some()
        || next.creation.is_some()
        || next.pending.is_some()
    {
        return Err(failed());
    }
    Ok(())
}
fn created_cleanup_pair(
    files: &mut dyn PrivateRecords,
    index: &SessionIndex,
    identity: &SessionIdentity,
    original: &original_native_rows::CreatedAddressCleanupRead<'_>,
    authority: &dyn OriginalCreatedAddressCleanupWrite,
) -> io::Result<Vec<u8>> {
    let saved = load_record(files, index, identity, RecordKind::Pair)?
        .1
        .ok_or_else(failed)?;
    let bytes = saved.data.as_bytes();
    let pair = carrier_pair_payload(&identity.scope, bytes)?.ok_or_else(failed)?;
    let binding = original.binding();
    // Structural restrictions only. The mandatory native issuer independently
    // authenticates exact original Pair ACK/selected Closing Calling purpose.
    // Neither phase nor an imported JSON record issues that native capability.
    if pair.phase != crate::member_carrier_pair::Phase::Closing
        || pair.pending.is_none() || pair.pending_guard.is_some()
        || pair.guard.permits || pair.active.is_some()
        || pair.scope != binding.scope
        || pair.provenance.boot_id != binding.boot_id
        || pair.provenance.runtime != binding.runtime
        || pair.provenance.network_epoch != binding.network_epoch
        // CarrierReady publication can fail AFTER the genuine SDK Create ACK.
        // Absent logical proof is accepted only through this sealed receipt
        // plus mandatory original issuer, never through the ordinary CAS path.
        || pair.carrier.is_some_and(|proof| proof != crate::member_owner::InterfaceProof {
            index: binding.key.index, luid: binding.key.luid, guid: binding.guid,
        })
    {
        return Err(failed());
    }
    authority.verify_pair(bytes, original)?;
    Ok(bytes.to_vec())
}
fn initial_cleanup_pair(
    files: &mut dyn PrivateRecords,
    index: &SessionIndex,
    identity: &SessionIdentity,
    original: &original_native_rows::InitialRowCaptureCleanupRead<'_>,
    authority: &dyn OriginalInitialRowCaptureCleanupWrite,
) -> io::Result<Vec<u8>> {
    let saved = load_record(files, index, identity, RecordKind::Pair)?
        .1
        .ok_or_else(failed)?;
    let bytes = saved.data.as_bytes();
    let pair = carrier_pair_payload(&identity.scope, bytes)?.ok_or_else(failed)?;
    let b = original.binding();
    if b.role != rows::Role::Carrier
        || pair.phase != crate::member_carrier_pair::Phase::Closing
        || pair.pending.is_none()
        || pair.pending_guard.is_some()
        || pair.guard.permits
        || pair.active.is_some()
        || pair.scope != b.scope
        || pair.provenance.boot_id != b.boot_id
        || pair.provenance.runtime != b.runtime
        || pair.provenance.network_epoch != b.network_epoch
        || pair.carrier.is_some_and(|p| {
            p != crate::member_owner::InterfaceProof {
                index: b.key.index,
                luid: b.key.luid,
                guid: b.guid,
            }
        })
    {
        return Err(failed());
    }
    authority.verify_pair(bytes, original)?;
    Ok(bytes.to_vec())
}
fn row_generation_pair(
    files: &mut dyn PrivateRecords,
    index: &SessionIndex,
    identity: &SessionIdentity,
    authority: &dyn OriginalRowGenerationWrite,
) -> io::Result<Vec<u8>> {
    let saved = load_record(files, index, identity, RecordKind::Pair)?
        .1
        .ok_or_else(failed)?;
    let bytes = saved.data.as_bytes();
    let pair = carrier_pair_payload(&identity.scope, bytes)?.ok_or_else(failed)?;
    use crate::member_carrier_pair::{Effect, Operation, Phase};
    if !matches!(pair.phase, Phase::Starting | Phase::Running)
        || pair.pending != Some(Effect::WeakRows)
        || pair.pending_guard.is_some()
        || pair.guard.permits
        || pair.stop_stage != 0
        || !matches!(
            pair.operation,
            Some(Operation::Start(_) | Operation::Attach(_) | Operation::Rebind)
        )
        || pair.provenance.boot_id != identity.boot_id
        || pair.provenance.runtime != identity.runtime
    {
        return Err(failed());
    }
    authority.verify_pair(bytes)?;
    Ok(bytes.to_vec())
}
fn authenticate_rows(
    record: &rows::Record,
    identity: &SessionIdentity,
    epoch: u64,
) -> io::Result<()> {
    let b = &record.binding;
    if b.scope != identity.scope
        || b.boot_id != identity.boot_id
        || b.runtime != identity.runtime
        || b.network_epoch != epoch
    {
        return Err(failed());
    }
    Ok(())
}
fn require_stopped_rows(kind: RecordKind, saved: &SavedRecord) -> io::Result<()> {
    if rows_payload(kind, &saved.identity.scope, saved.data.as_bytes())?.phase
        != rows::Phase::Stopped
    {
        return Err(failed());
    }
    Ok(())
}
fn duplicate_rows_binding(a: &rows::Binding, b: &rows::Binding) -> bool {
    a.guid == b.guid
        || a.key.luid == b.key.luid
        || a.key.index == b.key.index
        || a.name.eq_ignore_ascii_case(&b.name)
}
fn require_rows_obligations(
    files: &mut dyn PrivateRecords,
    index: &SessionIndex,
    identity: &SessionIdentity,
) -> io::Result<()> {
    let epoch = current_epoch(files, index, identity)?;
    let mut bindings = Vec::new();
    for kind in RecordKind::ROWS {
        if let Some(saved) = load_record(files, index, identity, kind)?.1 {
            if saved.network_epoch > epoch {
                return Err(failed());
            }
            let record = rows_payload(kind, &identity.scope, saved.data.as_bytes())?;
            if bindings
                .iter()
                .any(|other| duplicate_rows_binding(other, &record.binding))
            {
                return Err(failed());
            }
            bindings.push(record.binding);
        }
    }
    Ok(())
}
#[allow(dead_code)] // Typed factory constructor remains unwired.
type RowsSnapshot = (CarrierAccess, Option<Vec<u8>>, Option<rows::Record>);
#[allow(dead_code)] // Typed factory constructor remains unwired.
fn rows_snapshot<F: SessionFiles>(
    files: &mut F,
    binding: &rows::Binding,
) -> io::Result<RowsSnapshot> {
    let access = files.native_carrier_access(&binding.scope)?;
    if access.scope != binding.scope
        || access.provenance.boot_id != binding.boot_id
        || access.provenance.runtime != binding.runtime
        || binding.network_epoch == 0
        || binding.network_epoch > access.provenance.network_epoch
    {
        return Err(failed());
    }
    let raw = files.read(&binding.scope, rows_kind(binding.role))?;
    let current = raw
        .as_ref()
        .map(|b| rows_payload(rows_kind(binding.role), &binding.scope, b))
        .transpose()?;
    if current.as_ref().is_some_and(|r| r.binding != *binding) {
        return Err(failed());
    }
    Ok((access, raw, current))
}
#[cfg(test)]
fn rows_file(role: rows::Role) -> PrivateFile {
    rows_kind(role).file()
}
#[cfg(test)]
#[path = "member_carrier_rows_store_tests.rs"]
mod rows_store_tests;

#[cfg(test)]
#[path = "member_carrier_guard_store_tests.rs"]
mod carrier_guard_store_tests;

/// Protected storage facts only. No serialized field grants WFP ownership,
/// original-interface provenance, held sockets or permission for native effects.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "CarrierGuardWire")]
pub(crate) struct CarrierGuardRecord {
    pub version: u32,
    pub context: native_receipt::Context,
    pub revision: u64,
    pub current: carrier_guard::Model,
    pub pending: Option<carrier_guard::ExchangePlan>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CarrierGuardWire {
    version: u32,
    context: native_receipt::Context,
    revision: u64,
    current: carrier_guard::Model,
    pending: Option<carrier_guard::ExchangePlan>,
}
impl TryFrom<CarrierGuardWire> for CarrierGuardRecord {
    type Error = io::Error;
    fn try_from(wire: CarrierGuardWire) -> io::Result<Self> {
        let record = Self {
            version: wire.version,
            context: wire.context,
            revision: wire.revision,
            current: wire.current,
            pending: wire.pending,
        };
        record.validate()?;
        Ok(record)
    }
}
impl CarrierGuardRecord {
    pub(crate) fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > PrivateFile::CarrierGuard.limit() {
            return Err(failed());
        }
        let record: Self = serde_json::from_slice(bytes).map_err(|_| failed())?;
        record.validate()?;
        Ok(record)
    }
    pub(crate) fn encode(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| failed())?;
        if bytes.len() > PrivateFile::CarrierGuard.limit() {
            return Err(failed());
        }
        Ok(bytes)
    }
    fn validate(&self) -> io::Result<()> {
        if self.version != 2
            || self.revision == 0
            || (self.current.installed && self.current.assigned_sublayer_weight.is_none())
        {
            return Err(failed());
        }
        validate_native_context(&self.context)?;
        validate_guard_model(&self.context, &self.current)?;
        if let Some(plan) = &self.pending {
            plan.validate().map_err(|_| failed())?;
            if plan.expected != self.current {
                return Err(failed());
            }
            for model in [&plan.expected, &plan.withdrawn, &plan.base, &plan.desired] {
                validate_guard_model(&self.context, model)?;
            }
        }
        Ok(())
    }
}
pub(super) fn validate_guard_model(
    context: &native_receipt::Context,
    model: &carrier_guard::Model,
) -> io::Result<()> {
    model.validate().map_err(|_| failed())?;
    if model.scope != context.intent.scope {
        return Err(failed());
    }
    if let Some(carrier) = &model.carrier {
        let mut sources: Vec<_> = context.intent.addresses.iter().map(|a| a.addr()).collect();
        sources.sort();
        if carrier.identity.proof.guid != context.bindings[0].guid || carrier.sources != sources {
            return Err(failed());
        }
    }
    for (i, member) in model.members.iter().enumerate() {
        if member
            .as_ref()
            .is_some_and(|m| m.identity.proof.guid != context.bindings[i + 1].guid)
        {
            return Err(failed());
        }
    }
    Ok(())
}
fn guard_payload(scope: &SessionScope, bytes: &[u8]) -> io::Result<CarrierGuardRecord> {
    let record = CarrierGuardRecord::decode(bytes)?;
    if record.context.intent.scope != *scope {
        return Err(failed());
    }
    Ok(record)
}
fn authenticate_guard(
    record: &CarrierGuardRecord,
    identity: &SessionIdentity,
    epoch: u64,
) -> io::Result<()> {
    if record.context.intent.scope != identity.scope
        || record.context.provenance.boot_id != identity.boot_id
        || record.context.provenance.runtime != identity.runtime
        || record.context.provenance.network_epoch != epoch
    {
        return Err(failed());
    }
    Ok(())
}
fn require_stopped_guard(saved: &SavedRecord) -> io::Result<()> {
    let record = guard_payload(&saved.identity.scope, saved.data.as_bytes())?;
    if record.pending.is_some()
        || record.current
            != carrier_guard::Model::empty(saved.identity.scope.clone()).map_err(|_| failed())?
    {
        return Err(failed());
    }
    Ok(())
}
fn validate_guard_transition(
    old: Option<&CarrierGuardRecord>,
    next: &CarrierGuardRecord,
    fresh: bool,
) -> io::Result<()> {
    next.validate()?;
    let Some(old) = old else {
        return if fresh
            && next.revision == 1
            && next.pending.is_none()
            && next.current
                == carrier_guard::Model::empty(next.context.intent.scope.clone())
                    .map_err(|_| failed())?
        {
            Ok(())
        } else {
            Err(failed())
        };
    };
    old.validate()?;
    if next.context != old.context || old.revision.checked_add(1) != Some(next.revision) {
        return Err(failed());
    }
    match (&old.pending, &next.pending) {
        (None, Some(plan)) if next.current == old.current => {
            if !fresh
                && plan.desired
                    != carrier_guard::Model::empty(next.context.intent.scope.clone())
                        .map_err(|_| failed())?
                && plan.desired != old.current.without_permits().map_err(|_| failed())?
            {
                return Err(failed());
            }
        }
        (Some(previous), Some(plan)) if next.current == old.current && fresh => {
            // The only pending-plan replacement is the exact creation-priority
            // capture already validated by ExchangePlan; no new identity/policy.
            if previous.captured_sublayer_weight.is_some()
                || plan.captured_sublayer_weight.is_none()
                || plan.expected != previous.expected
                || plan.withdrawn != previous.withdrawn
                || previous
                    .base
                    .readback_after(&previous.expected, &plan.base.expected)
                    .map_err(|_| failed())?
                    != plan.base
                || previous
                    .desired
                    .readback_after(&previous.expected, &plan.desired.expected)
                    .map_err(|_| failed())?
                    != plan.desired
            {
                return Err(failed());
            }
        }
        (Some(plan), None) => {
            if plan.resolve(&next.current.expected).map_err(|_| failed())? != next.current
                || (fresh && next.current != plan.desired)
                || (!fresh && next.current.permits)
            {
                return Err(failed());
            }
        }
        _ => return Err(failed()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nelomai_client_tunnel::redundancy::{
        session::{SessionPhase, SessionState},
        Slot,
    };
    use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

    #[derive(Clone, Default)]
    struct Disk(Rc<RefCell<DiskState>>);
    #[derive(Default)]
    struct DiskState {
        bytes: BTreeMap<PrivateFile, Vec<u8>>,
        fail: bool,
        lost_ack: bool,
        fail_file: Option<PrivateFile>,
        lose_file: Option<PrivateFile>,
        writes: usize,
        fail_read: Option<PrivateFile>,
    }
    impl PrivateRecords for Disk {
        fn read(&mut self, file: PrivateFile) -> io::Result<Option<Vec<u8>>> {
            if self.0.borrow().fail_read == Some(file) {
                return Err(io::Error::other("SECRET read failure"));
            }
            Ok(self.0.borrow().bytes.get(&file).cloned())
        }
        fn compare_exchange(
            &mut self,
            file: PrivateFile,
            expected: Option<&[u8]>,
            desired: &[u8],
        ) -> io::Result<()> {
            let mut d = self.0.borrow_mut();
            if d.fail
                || d.fail_file == Some(file)
                || d.bytes.get(&file).map(Vec::as_slice) != expected
            {
                return Err(io::Error::other("SECRET"));
            }
            d.bytes.insert(file, desired.to_vec());
            d.writes += 1;
            if d.lost_ack || d.lose_file == Some(file) {
                d.lost_ack = false;
                d.lose_file = None;
                return Err(io::Error::other("SECRET"));
            }
            Ok(())
        }
    }
    impl SessionFileIo for Disk {
        fn transaction<T>(
            &mut self,
            f: impl FnOnce(&mut dyn PrivateRecords) -> io::Result<T>,
        ) -> io::Result<T> {
            f(self)
        }
    }
    fn runtime() -> nelomai_contracts::dispatcher::EngineIdentity {
        nelomai_contracts::dispatcher::EngineIdentity {
            slot: RuntimeSlot::Stable,
            runtime_version: "1.0.0".into(),
            runtime_contract_version: 1,
            container_version: "1.0.0".into(),
            manifest_sha256: "a".repeat(64),
        }
    }
    fn scope() -> SessionScope {
        SessionScope {
            runtime: RuntimeSlot::Stable,
            runtime_generation: 1,
            session_id: "11111111-1111-4111-8111-111111111111".into(),
            connection_generation: 2,
        }
    }
    fn files(disk: &Disk) -> ProtectedSessionFiles<Disk> {
        ProtectedSessionFiles::new(disk.clone(), runtime(), [7; 16]).unwrap()
    }
    #[test]
    fn original_backend_comparison_accepts_alias_not_equal_independent_reopen() {
        let disk = Disk::default();
        let mut f = files(&disk);
        save_initial(&mut f);
        assert!(f.same_original_backend(&f.clone()));
        assert!(!f.same_original_backend(&files(&disk)));
        let (view, _) = f.recovery_view(RuntimeSlot::Stable).unwrap().unwrap();
        // This comparison must not promote a recovery alias into freshness.
        assert!(f.same_original_backend(&view));
        assert!(!view
            .clone()
            .native_carrier_access(&scope())
            .unwrap()
            .is_fresh());
        let before = disk.0.borrow().writes;
        let mut foreign = f.clone();
        foreign.boot = [8; 16];
        assert!(!f.same_original_backend(&foreign));
        foreign = f.clone();
        foreign.current_boot = [8; 16];
        assert!(!f.same_original_backend(&foreign));
        foreign = f.clone();
        foreign.runtime.manifest_sha256 = "b".repeat(64);
        assert!(!f.same_original_backend(&foreign));
        assert_eq!(disk.0.borrow().writes, before);
    }
    #[test]
    fn recovery_runtime_origin_does_not_adopt_protected_payload_identity() {
        let disk = Disk::default();
        let mut f = files(&disk);
        save_initial(&mut f);
        f.require_recovery_runtime_origin(&runtime(), [7; 16])
            .unwrap();
        let mut foreign = runtime();
        foreign.manifest_sha256 = "b".repeat(64);
        assert!(f
            .require_recovery_runtime_origin(&foreign, [7; 16])
            .is_err());
        assert!(f
            .require_recovery_runtime_origin(&runtime(), [8; 16])
            .is_err());
        assert!(f
            .require_recovery_runtime_origin(&runtime(), [0; 16])
            .is_err());
        // This is constructor/view origin, not a grant or a parsed Session
        // identity. Corrupt/missing durable records still fail actual reading.
        disk.0.borrow_mut().bytes.remove(&PrivateFile::Index);
        f.require_recovery_runtime_origin(&runtime(), [7; 16])
            .unwrap();
        assert!(f.native_carrier_access(&scope()).is_err());
    }
    #[test]
    fn recovery_record_transaction_fences_same_looking_replacement_between_brackets() {
        for file in [PrivateFile::Index, PrivateFile::Session] {
            let disk = Disk::default();
            let mut f = files(&disk);
            save_initial(&mut f);
            let before = f
                .inspect_recovery_records(RuntimeSlot::Stable, |facts| Ok(facts.clone()))
                .unwrap()
                .unwrap();
            disk.0.borrow_mut().bytes.get_mut(&file).unwrap().push(b' ');
            let after = f
                .inspect_recovery_records(RuntimeSlot::Stable, |facts| Ok(facts.clone()))
                .unwrap()
                .unwrap();
            assert!(
                before != after,
                "same-looking private replacement refreshed selection"
            );
            assert!(before.records == after.records);
        }
    }
    #[test]
    fn recovery_record_transaction_does_not_publish_or_complete_an_active_claim() {
        // Break: treat a missing Pair as native-empty, lose the active claim,
        // expose only projected data, or refresh caller's forward permission.
        let disk = Disk::default();
        let mut f = files(&disk);
        save_initial(&mut f);
        let before = disk.0.borrow().bytes.clone();
        let observed = f
            .inspect_recovery_records(RuntimeSlot::Stable, |facts| {
                assert_eq!(facts.scope, scope());
                assert!(!facts.changed_boot);
                assert_eq!(facts.provenance.runtime, runtime());
                assert_eq!(facts.provenance.network_epoch, 1);
                assert_eq!(facts.records.len(), 10);
                assert_eq!(
                    facts.records.last(),
                    Some(&(RecordKind::NativeCreator, None))
                );
                assert!(facts
                    .records
                    .iter()
                    .find(|(kind, _)| *kind == RecordKind::Session)
                    .unwrap()
                    .1
                    .is_some());
                assert!(facts
                    .records
                    .iter()
                    .find(|(kind, _)| *kind == RecordKind::Pair)
                    .unwrap()
                    .1
                    .is_none());
                Ok(())
            })
            .unwrap();
        assert!(observed.is_some());
        assert_eq!(disk.0.borrow().bytes, before);
        assert!(!f.native_carrier_access(&scope()).unwrap().is_fresh());
    }
    #[test]
    fn recovery_record_transaction_rechecks_exact_private_bytes_after_callback() {
        for mutation in 0..3 {
            let disk = Disk::default();
            let mut f = files(&disk);
            save_initial(&mut f);
            let before = disk.0.borrow().bytes.clone();
            let result = f.inspect_recovery_records(RuntimeSlot::Stable, |_| {
                let file = if mutation == 0 {
                    PrivateFile::Index
                } else {
                    PrivateFile::Session
                };
                if mutation == 2 {
                    disk.0.borrow_mut().bytes.remove(&file);
                } else {
                    disk.0.borrow_mut().bytes.get_mut(&file).unwrap().push(b' ');
                }
                Ok(())
            });
            assert!(
                result.is_err(),
                "replacement must not become an original ACK"
            );
            assert!(!disk
                .0
                .borrow()
                .bytes
                .keys()
                .any(|key| matches!(key, PrivateFile::Completed(_))));
            // Preserve altered bytes as an obligation; reader does no rollback.
            assert_ne!(disk.0.borrow().bytes, before);
        }
    }
    #[test]
    fn recovery_record_transaction_changed_boot_is_readonly_not_current_boot_promotion() {
        let disk = Disk::default();
        let mut old = files(&disk);
        save_initial(&mut old);
        let before = disk.0.borrow().bytes.clone();
        let mut current = ProtectedSessionFiles::new(disk.clone(), runtime(), [8; 16]).unwrap();
        current
            .inspect_recovery_records(RuntimeSlot::Stable, |facts| {
                assert!(facts.changed_boot);
                assert_eq!(facts.provenance.boot_id, [7; 16]);
                Ok(())
            })
            .unwrap()
            .unwrap();
        assert_eq!(disk.0.borrow().bytes, before);
        assert!(current.read(&scope(), RecordKind::Session).is_err()); // ordinary rule unchanged
        assert!(current.claim(&scope()).is_err());
    }
    fn initial() -> SessionSnapshot {
        SessionState::new(scope(), Slot::A, 1, 1)
            .unwrap()
            .snapshot()
    }
    fn save_initial(files: &mut ProtectedSessionFiles<Disk>) {
        files.claim(&scope()).unwrap();
        let (mut store, old) =
            WindowsSessionStore::open(files.clone(), scope(), RecordKind::Session).unwrap();
        assert!(old.is_none());
        store.save(&initial()).unwrap();
    }
    fn clean(files: &mut ProtectedSessionFiles<Disk>) {
        let (mut store, _) =
            WindowsSessionStore::open(files.clone(), scope(), RecordKind::Session).unwrap();
        let mut state = SessionState::recover_for_cleanup(scope(), initial()).unwrap();
        state.stopped(&scope()).unwrap();
        store.save(&state.snapshot()).unwrap();
        let pair = PairRecord {
            scope: scope(),
            members: [None, None],
            active: None,
            guard: crate::member_guard::Model::empty(scope()).unwrap(),
            pending_guard: None,
            dns: [None, None],
            options: None,
            closing: false,
        };
        let (mut store, _) =
            WindowsPairStore::open(files.clone(), scope(), RecordKind::Pair).unwrap();
        store.save(&pair).unwrap();
        let (mut store, _) = ProtectedStore::<_, NativeNetworkRecord>::open(
            files.clone(),
            scope(),
            RecordKind::Network,
        )
        .unwrap();
        store.save_value(&NativeNetworkRecord::default()).unwrap();
    }
    fn fresh_carrier_pair() -> crate::member_carrier_pair::Record {
        crate::member_carrier_pair::Record {
            version: 2,
            scope: scope(),
            provenance: carrier::Provenance {
                boot_id: [7; 16],
                runtime: runtime(),
                network_epoch: 1,
            },
            revision: 1,
            phase: crate::member_carrier_pair::Phase::Fresh,
            addresses: vec![],
            dns: vec![],
            carrier: None,
            members: [None, None],
            active: None,
            options: None,
            guard: carrier_guard::Model::empty(scope()).unwrap(),
            pending_guard: None,
            pending: None,
            network: None,
            stop_stage: 0,
            operation: None,
        }
    }
    fn empty_legacy_pair_bytes() -> Vec<u8> {
        serde_json::to_vec(&Envelope {
            version: 1,
            scope: scope(),
            payload: PairRecord {
                scope: scope(),
                members: [None, None],
                active: None,
                guard: crate::member_guard::Model::empty(scope()).unwrap(),
                pending_guard: None,
                dns: [None, None],
                options: None,
                closing: false,
            },
        })
        .unwrap()
    }
    #[test]
    fn carrier_pair_raw_cas_authenticates_identity_revision_and_epoch() {
        for change in 0..8 {
            let disk = Disk::default();
            let mut f = files(&disk);
            save_initial(&mut f);
            let mut r = fresh_carrier_pair();
            match change {
                0 => r.provenance.boot_id = [8; 16],
                1 => r.provenance.runtime.manifest_sha256 = "b".repeat(64),
                2 => r.provenance.network_epoch = 2,
                3 => r.revision = 2,
                4 => r.phase = crate::member_carrier_pair::Phase::Starting,
                5 => r.scope.connection_generation += 1,
                6 => r.version = 99,
                _ => r.provenance.network_epoch = 0,
            }
            // Serialize even invalid records to exercise the REAL raw boundary.
            let raw = serde_json::to_vec(&Envelope {
                version: 1,
                scope: scope(),
                payload: r,
            })
            .unwrap();
            let before = disk.0.borrow().writes;
            assert!(
                f.compare_exchange(&scope(), RecordKind::Pair, None, &raw)
                    .is_err(),
                "{change}"
            );
            assert_eq!(disk.0.borrow().writes, before);
            assert!(f.read(&scope(), RecordKind::Pair).unwrap().is_none());
            assert!(!f.native_carrier_access(&scope()).unwrap().is_fresh());
        }
    }
    #[test]
    fn raw_pair_cas_never_converts_existing_legacy_or_carrier_version() {
        for from_carrier in [false, true] {
            let disk = Disk::default();
            let mut f = files(&disk);
            save_initial(&mut f);
            let carrier =
                carrier_pair_store::encode_carrier_payload(&fresh_carrier_pair()).unwrap();
            let legacy = empty_legacy_pair_bytes();
            let (old, desired) = if from_carrier {
                (&carrier, &legacy)
            } else {
                (&legacy, &carrier)
            };
            f.compare_exchange(&scope(), RecordKind::Pair, None, old)
                .unwrap();
            let before = disk.0.borrow().writes;
            assert!(f
                .compare_exchange(&scope(), RecordKind::Pair, Some(old), desired)
                .is_err());
            assert_eq!(disk.0.borrow().writes, before);
            assert_eq!(
                f.read(&scope(), RecordKind::Pair).unwrap().as_ref(),
                Some(old)
            );
        }
    }
    #[test]
    fn terminal_carrier_pair_is_required_before_real_claim_completion() {
        use crate::member_carrier_pair::Phase;
        let disk = Disk::default();
        let mut f = files(&disk);
        save_initial(&mut f);
        let mut r = fresh_carrier_pair();
        let mut raw = carrier_pair_store::encode_carrier_payload(&r).unwrap();
        f.compare_exchange(&scope(), RecordKind::Pair, None, &raw)
            .unwrap();
        r.phase = Phase::Closing;
        for stage in 0..=12 {
            r.revision += 1;
            r.stop_stage = stage;
            let next = carrier_pair_store::encode_carrier_payload(&r).unwrap();
            f.compare_exchange(&scope(), RecordKind::Pair, Some(&raw), &next)
                .unwrap();
            raw = next;
        }
        let mut state = SessionState::recover_for_cleanup(scope(), initial()).unwrap();
        state.stopped(&scope()).unwrap();
        let (mut session, _) =
            WindowsSessionStore::open(f.clone(), scope(), RecordKind::Session).unwrap();
        session.save(&state.snapshot()).unwrap();
        assert!(f.complete(&scope()).is_err());
        r.revision += 1;
        r.phase = Phase::Stopped;
        let terminal = carrier_pair_store::encode_carrier_payload(&r).unwrap();
        f.compare_exchange(&scope(), RecordKind::Pair, Some(&raw), &terminal)
            .unwrap();
        f.complete(&scope()).unwrap();
        assert!(f.scopes(RuntimeSlot::Stable).unwrap().is_empty());
        assert!(files(&disk).claim(&scope()).is_err());
    }
    #[test]
    fn protected_carrier_pair_payload_cannot_disagree_with_outer_authenticated_identity() {
        for change in 0..3 {
            let disk = Disk::default();
            let mut f = files(&disk);
            save_initial(&mut f);
            let bytes = carrier_pair_store::encode_carrier_payload(&fresh_carrier_pair()).unwrap();
            f.compare_exchange(&scope(), RecordKind::Pair, None, &bytes)
                .unwrap();
            let mut saved: SavedRecord =
                serde_json::from_slice(disk.0.borrow().bytes.get(&PrivateFile::Pair).unwrap())
                    .unwrap();
            let mut r = fresh_carrier_pair();
            match change {
                0 => r.provenance.boot_id = [8; 16],
                1 => r.provenance.runtime.manifest_sha256 = "b".repeat(64),
                _ => saved.network_epoch += 1,
            }
            saved.data =
                String::from_utf8(carrier_pair_store::encode_carrier_payload(&r).unwrap()).unwrap();
            disk.0
                .borrow_mut()
                .bytes
                .insert(PrivateFile::Pair, serde_json::to_vec(&saved).unwrap());
            let before = disk.0.borrow().writes;
            assert!(f.read(&scope(), RecordKind::Pair).is_err());
            assert_eq!(disk.0.borrow().writes, before);
        }
    }
    #[test]
    fn completed_marker_cannot_turn_nonterminal_carrier_pair_into_an_absent_slot() {
        for after_next_claim in [false, true] {
            let disk = Disk::default();
            let mut f = files(&disk);
            save_initial(&mut f);
            clean(&mut f);
            f.complete(&scope()).unwrap();
            let mut next = scope();
            next.session_id = "22222222-2222-4222-8222-222222222222".into();
            next.connection_generation += 1;
            if after_next_claim {
                f.claim(&next).unwrap();
            }
            let mut old: SavedRecord =
                serde_json::from_slice(disk.0.borrow().bytes.get(&PrivateFile::Pair).unwrap())
                    .unwrap();
            // A stale/corrupted original record and a real completed marker are
            // not an independent terminal proof. No native operation occurs.
            old.data = String::from_utf8(
                carrier_pair_store::encode_carrier_payload(&fresh_carrier_pair()).unwrap(),
            )
            .unwrap();
            disk.0
                .borrow_mut()
                .bytes
                .insert(PrivateFile::Pair, serde_json::to_vec(&old).unwrap());
            let before = disk.0.borrow().writes;
            if after_next_claim {
                assert!(f.read(&next, RecordKind::Pair).is_err());
            } else {
                assert!(f.claim(&next).is_err());
            }
            assert_eq!(disk.0.borrow().writes, before);
        }
    }
    #[test]
    fn claim_reopen_is_cleanup_only_and_never_replays_start() {
        let disk = Disk::default();
        let mut f = files(&disk);
        save_initial(&mut f);
        assert!(f.claim(&scope()).is_err());
        let mut reopened = files(&disk);
        assert_eq!(reopened.scopes(RuntimeSlot::Stable).unwrap(), vec![scope()]);
        let (mut store, saved) =
            WindowsSessionStore::open(reopened.clone(), scope(), RecordKind::Session).unwrap();
        assert_eq!(saved.unwrap(), initial());
        assert!(store.save(&initial()).is_err());
        clean(&mut reopened);
        reopened.complete(&scope()).unwrap();
        assert!(reopened.scopes(RuntimeSlot::Stable).unwrap().is_empty());
        assert!(files(&disk).claim(&scope()).is_err());
    }
    #[test]
    fn wrong_scope_runtime_and_boot_cannot_read_or_apply_old_records() {
        let disk = Disk::default();
        let mut f = files(&disk);
        save_initial(&mut f);
        let before = disk.0.borrow().writes;
        let mut other = scope();
        other.connection_generation += 1;
        assert!(f.read(&other, RecordKind::Session).is_err());
        assert!(f.scopes(RuntimeSlot::Latest).is_err());
        let mut rebooted = ProtectedSessionFiles::new(disk.clone(), runtime(), [8; 16]).unwrap();
        assert!(rebooted.scopes(RuntimeSlot::Stable).is_err());
        assert!(rebooted.read(&scope(), RecordKind::Session).is_err());
        assert!(rebooted.claim(&other).is_err());
        let mut changed = runtime();
        changed.manifest_sha256 = "b".repeat(64);
        assert!(ProtectedSessionFiles::new(disk.clone(), changed, [7; 16])
            .unwrap()
            .read(&scope(), RecordKind::Session)
            .is_err());
        assert!(ProtectedSessionFiles::new(disk.clone(), runtime(), [0; 16]).is_err());
        assert_eq!(disk.0.borrow().writes, before);
    }
    #[test]
    fn recovery_view_retains_exact_identity_without_relaxing_normal_access() {
        for boot in [[7; 16], [8; 16]] {
            let disk = Disk::default();
            let mut original = files(&disk);
            save_initial(&mut original);
            let mut upgraded = runtime();
            upgraded.manifest_sha256 = "b".repeat(64);
            let mut caller = ProtectedSessionFiles::new(disk.clone(), upgraded, boot).unwrap();
            let before = disk.0.borrow().bytes.clone();
            assert!(caller.scopes(RuntimeSlot::Stable).is_err());
            let (mut view, changed) = caller.recovery_view(RuntimeSlot::Stable).unwrap().unwrap();
            assert_eq!(changed, boot != [7; 16]);
            assert_eq!(view.scopes(RuntimeSlot::Stable).unwrap(), vec![scope()]);
            let (mut store, saved) =
                WindowsSessionStore::open(view.clone(), scope(), RecordKind::Session).unwrap();
            assert_eq!(saved, Some(initial()));
            assert!(store.save(&initial()).is_err());
            let mut running = initial();
            running.phase = SessionPhase::Running;
            running.installed[0] = true;
            assert!(store.save(&running).is_err());
            assert!(view.claim(&scope()).is_err());
            assert!(view.clone().claim(&scope()).is_err());
            assert!(view.complete(&scope()).is_err());
            assert!(view.complete_empty(&scope()).is_err());
            assert!(caller.read(&scope(), RecordKind::Session).is_err());
            assert_eq!(disk.0.borrow().bytes, before);
            clean(&mut view);
            view.complete(&scope()).unwrap();
            view.complete(&scope()).unwrap();
            assert!(caller.scopes(RuntimeSlot::Stable).unwrap().is_empty());
            assert!(caller.claim(&scope()).is_err());
        }
    }
    #[test]
    fn completed_boot_check_is_read_only_and_uses_current_boot_across_runtime_slots() {
        let disk = Disk::default();
        let mut f = files(&disk);
        save_initial(&mut f);
        clean(&mut f);
        f.complete(&scope()).unwrap();
        let before = disk.0.borrow().bytes.clone();
        assert!(!f.completed_in_previous_boot(&scope()).unwrap());
        let mut other_runtime = runtime();
        other_runtime.slot = RuntimeSlot::Latest;
        other_runtime.manifest_sha256 = "b".repeat(64);
        let mut other = ProtectedSessionFiles::new(disk.clone(), other_runtime, [8; 16]).unwrap();
        assert!(other.completed_in_previous_boot(&scope()).unwrap());
        assert!(other.read(&scope(), RecordKind::Session).is_err());
        assert_eq!(disk.0.borrow().bytes, before);

        // A retained cleanup view's identity boot is old; this fact still uses
        // the caller's current boot, not the identity it is allowed to clean.
        let mut next = scope();
        next.connection_generation += 1;
        f.claim(&next).unwrap();
        let mut rebooted = ProtectedSessionFiles::new(disk.clone(), runtime(), [8; 16]).unwrap();
        let (mut view, _) = rebooted
            .recovery_view(RuntimeSlot::Stable)
            .unwrap()
            .unwrap();
        assert!(view.clone().completed_in_previous_boot(&scope()).unwrap());
        assert!(view.completed_in_previous_boot(&next).is_err());
    }
    #[test]
    fn completed_boot_check_rejects_missing_active_corrupt_and_io_errors() {
        let disk = Disk::default();
        let mut f = files(&disk);
        assert!(f.completed_in_previous_boot(&scope()).is_err());
        save_initial(&mut f);
        assert!(f.completed_in_previous_boot(&scope()).is_err());
        clean(&mut f);
        // Durable marker without index release is NOT yet completed authority.
        disk.0.borrow_mut().lose_file = Some(completed_file(&scope()).unwrap());
        assert!(f.complete(&scope()).is_err());
        assert!(f.completed_in_previous_boot(&scope()).is_err());
        f.complete(&scope()).unwrap();
        let marker = completed_file(&scope()).unwrap();
        let before = disk.0.borrow().bytes.clone();
        for file in [PrivateFile::Index, marker] {
            disk.0.borrow_mut().fail_read = Some(file);
            let error = f.completed_in_previous_boot(&scope()).unwrap_err();
            assert!(!error.to_string().contains("SECRET"));
        }
        disk.0.borrow_mut().fail_read = None;
        assert_eq!(disk.0.borrow().bytes, before);
        disk.0.borrow_mut().bytes.insert(marker, b"SECRET".to_vec());
        assert!(f.completed_in_previous_boot(&scope()).is_err());
        let mut mismatched: CompletedRecord = serde_json::from_slice(&before[&marker]).unwrap();
        mismatched.identity.scope.connection_generation += 1;
        disk.0
            .borrow_mut()
            .bytes
            .insert(marker, serde_json::to_vec(&mismatched).unwrap());
        assert!(f.completed_in_previous_boot(&scope()).is_err());
    }
    #[test]
    fn completed_boot_check_uses_permanent_history_not_recent_index() {
        let disk = Disk::default();
        let mut f = files(&disk);
        save_initial(&mut f);
        clean(&mut f);
        f.complete(&scope()).unwrap();
        for generation in 3..8 {
            let mut next = scope();
            next.connection_generation = generation;
            f.claim(&next).unwrap();
            let (mut store, _) =
                WindowsSessionStore::open(f.clone(), next.clone(), RecordKind::Session).unwrap();
            let mut state = SessionState::new(next.clone(), Slot::A, 1, 1)
                .unwrap()
                .snapshot();
            state.phase = SessionPhase::Stopped;
            store.save(&state).unwrap();
            let mut pair = prepared_pair();
            pair.scope = next.clone();
            pair.members = [None, None];
            pair.guard = crate::member_guard::Model::empty(next.clone()).unwrap();
            let (mut store, _) =
                WindowsPairStore::open(f.clone(), next.clone(), RecordKind::Pair).unwrap();
            store.save(&pair).unwrap();
            let (mut store, _) = ProtectedStore::<_, NativeNetworkRecord>::open(
                f.clone(),
                next.clone(),
                RecordKind::Network,
            )
            .unwrap();
            store.save_value(&NativeNetworkRecord::default()).unwrap();
            f.complete(&next).unwrap();
        }
        let index: SessionIndex =
            serde_json::from_slice(&disk.0.borrow().bytes[&PrivateFile::Index]).unwrap();
        assert!(!index.completed.iter().any(|id| id.scope == scope()));
        let before = disk.0.borrow().bytes.clone();
        let mut rebooted = ProtectedSessionFiles::new(disk.clone(), runtime(), [8; 16]).unwrap();
        assert!(rebooted.completed_in_previous_boot(&scope()).unwrap());
        assert!(!f.completed_in_previous_boot(&scope()).unwrap());
        assert_eq!(disk.0.borrow().bytes, before);
    }
    #[test]
    fn recovery_view_clone_is_never_fresh_and_cannot_follow_new_claim() {
        let disk = Disk::default();
        let mut original = files(&disk);
        save_initial(&mut original);
        // Even a view obtained through a still-fresh same-process handle is cleanup-only.
        let (mut view, changed) = original
            .recovery_view(RuntimeSlot::Stable)
            .unwrap()
            .unwrap();
        assert!(!changed);
        let (mut store, _) =
            WindowsSessionStore::open(view.clone(), scope(), RecordKind::Session).unwrap();
        assert!(store.save(&initial()).is_err());
        clean(&mut view);
        view.complete(&scope()).unwrap();
        let mut next = scope();
        next.connection_generation += 1;
        original.claim(&next).unwrap();
        let before = disk.0.borrow().bytes.clone();
        assert!(view.scopes(RuntimeSlot::Stable).is_err());
        assert!(view.read(&next, RecordKind::Session).is_err());
        assert!(view.complete_empty(&next).is_err());
        assert!(view.recovery_view(RuntimeSlot::Stable).is_err());
        assert!(view.clone().claim(&next).is_err());
        assert_eq!(disk.0.borrow().bytes, before);
    }
    #[test]
    fn recovery_view_empty_foreign_and_malformed_are_read_only() {
        let disk = Disk::default();
        let mut f = files(&disk);
        assert!(f.recovery_view(RuntimeSlot::Stable).unwrap().is_none());
        assert!(f.recovery_view(RuntimeSlot::Latest).is_err());
        save_initial(&mut f);
        let mut foreign = runtime();
        foreign.slot = RuntimeSlot::Latest;
        let mut foreign = ProtectedSessionFiles::new(disk.clone(), foreign, [8; 16]).unwrap();
        assert!(foreign.recovery_view(RuntimeSlot::Latest).is_err());
        disk.0
            .borrow_mut()
            .bytes
            .insert(PrivateFile::Index, b"SECRET".to_vec());
        let before = disk.0.borrow().bytes.clone();
        assert!(f.recovery_view(RuntimeSlot::Stable).is_err());
        assert_eq!(disk.0.borrow().bytes, before);
    }
    #[test]
    fn exact_cas_epoch_and_inner_scope_are_fenced() {
        let disk = Disk::default();
        let mut f = files(&disk);
        save_initial(&mut f);
        let (mut first, _) =
            WindowsSessionStore::open(f.clone(), scope(), RecordKind::Session).unwrap();
        let (mut stale, _) =
            WindowsSessionStore::open(f.clone(), scope(), RecordKind::Session).unwrap();
        let mut newer = initial();
        newer.network_epoch = 2;
        newer.local_revision = 2;
        first.save(&newer).unwrap();
        assert!(stale.save(&initial()).is_err());
        let (mut first, _) =
            WindowsSessionStore::open(f.clone(), scope(), RecordKind::Session).unwrap();
        assert!(first.save(&initial()).is_err());
        let mut bad = newer.clone();
        bad.scope.connection_generation += 1;
        assert!(first.save_value(&bad).is_err());
        bad = newer;
        bad.network_epoch = 0;
        assert!(first.save(&bad).is_err());
    }
    #[test]
    fn failed_and_lost_ack_publications_retain_cleanup_and_redact_errors() {
        let disk = Disk::default();
        let mut f = files(&disk);
        save_initial(&mut f);
        let (mut store, _) =
            WindowsSessionStore::open(f.clone(), scope(), RecordKind::Session).unwrap();
        let mut stopping = initial();
        stopping.phase = SessionPhase::Stopping;
        stopping.local_revision = 2;
        disk.0.borrow_mut().fail = true;
        assert!(!store
            .save(&stopping)
            .unwrap_err()
            .to_string()
            .contains("SECRET"));
        disk.0.borrow_mut().fail = false;
        disk.0.borrow_mut().lost_ack = true;
        assert!(store.save(&stopping).is_err());
        assert!(store.save(&stopping).is_err());
        let (_, saved) =
            WindowsSessionStore::open(files(&disk), scope(), RecordKind::Session).unwrap();
        assert_eq!(saved, Some(stopping));
        assert!(f.complete(&scope()).is_err());
        assert!(files(&disk).claim(&scope()).is_err());
    }
    #[test]
    fn complete_requires_clean_records_and_retains_tombstone_on_lost_ack() {
        let disk = Disk::default();
        let mut f = files(&disk);
        save_initial(&mut f);
        assert!(f.complete(&scope()).is_err());
        clean(&mut f);
        disk.0.borrow_mut().lost_ack = true;
        assert!(f.complete(&scope()).is_err());
        let mut reopened = files(&disk);
        // Marker publication succeeded, but its ACK was lost before index release.
        assert_eq!(reopened.scopes(RuntimeSlot::Stable).unwrap(), vec![scope()]);
        reopened.complete(&scope()).unwrap();
        assert!(reopened.scopes(RuntimeSlot::Stable).unwrap().is_empty());
        assert!(reopened.claim(&scope()).is_err());
        let mut next = scope();
        next.connection_generation += 1;
        reopened.claim(&next).unwrap();
        assert!(reopened.read(&next, RecordKind::Session).unwrap().is_none());
        let (mut store, _) =
            WindowsSessionStore::open(reopened, next.clone(), RecordKind::Session).unwrap();
        let mut snapshot = initial();
        snapshot.scope = next;
        store.save(&snapshot).unwrap();
    }
    #[test]
    fn more_than_1024_sessions_keep_constant_index_and_permanent_replay_fence() {
        let disk = Disk::default();
        let mut f = files(&disk);
        for generation in 1..=1030 {
            let mut next = scope();
            next.connection_generation = generation;
            f.claim(&next).unwrap();
            let (mut state_store, old) =
                WindowsSessionStore::open(f.clone(), next.clone(), RecordKind::Session).unwrap();
            assert!(old.is_none());
            let state = SessionState::new(next.clone(), Slot::A, 1, 1).unwrap();
            state_store.save(&state.snapshot()).unwrap();
            let mut state =
                SessionState::recover_for_cleanup(next.clone(), state.snapshot()).unwrap();
            state.stopped(&next).unwrap();
            state_store.save(&state.snapshot()).unwrap();
            let pair = PairRecord {
                scope: next.clone(),
                members: [None, None],
                active: None,
                guard: crate::member_guard::Model::empty(next.clone()).unwrap(),
                pending_guard: None,
                dns: [None, None],
                options: None,
                closing: false,
            };
            let (mut pair_store, old) =
                WindowsPairStore::open(f.clone(), next.clone(), RecordKind::Pair).unwrap();
            assert!(old.is_none());
            pair_store.save(&pair).unwrap();
            let (mut network_store, _) = ProtectedStore::<_, NativeNetworkRecord>::open(
                f.clone(),
                next.clone(),
                RecordKind::Network,
            )
            .unwrap();
            network_store
                .save_value(&NativeNetworkRecord::default())
                .unwrap();
            f.complete(&next).unwrap();
            assert!(disk.0.borrow().bytes[&PrivateFile::Index].len() < 8192);
        }
        assert!(f.claim(&scope()).is_err());
        let mut next = scope();
        next.connection_generation = 1031;
        files(&disk).claim(&next).unwrap();
    }
    #[test]
    fn unpublished_v1_index_is_rejected_without_truncation_or_migration() {
        let disk = Disk::default();
        let mut f = files(&disk);
        let bytes = serde_json::to_vec(&SessionIndex {
            version: 1,
            active: None,
            completed: vec![f.identity(&scope()).unwrap()],
        })
        .unwrap();
        disk.0
            .borrow_mut()
            .bytes
            .insert(PrivateFile::Index, bytes.clone());
        assert!(f.scopes(RuntimeSlot::Stable).is_err());
        assert!(f.claim(&scope()).is_err());
        assert_eq!(disk.0.borrow().bytes[&PrivateFile::Index], bytes);
        assert_eq!(disk.0.borrow().writes, 0);
    }
    #[test]
    fn orphan_and_corrupt_records_do_not_become_fresh_claims() {
        let disk = Disk::default();
        let mut f = files(&disk);
        save_initial(&mut f);
        disk.0.borrow_mut().bytes.remove(&PrivateFile::Index);
        assert!(files(&disk).claim(&scope()).is_err());
        assert!(files(&disk).scopes(RuntimeSlot::Stable).is_err());
        let error = files(&disk)
            .read(&scope(), RecordKind::Session)
            .unwrap_err();
        assert!(!error.to_string().contains("session_id"));
        disk.0
            .borrow_mut()
            .bytes
            .insert(PrivateFile::Index, b"SECRET invalid JSON".to_vec());
        assert!(!files(&disk)
            .scopes(RuntimeSlot::Stable)
            .unwrap_err()
            .to_string()
            .contains("SECRET"));
    }
    #[test]
    fn complete_cannot_discard_network_intent_or_pending_guard() {
        let disk = Disk::default();
        let mut f = files(&disk);
        save_initial(&mut f);
        clean(&mut f);
        let (mut store, _) =
            ProtectedStore::<_, NativeNetworkRecord>::open(f.clone(), scope(), RecordKind::Network)
                .unwrap();
        let journal:NetworkJournal=serde_json::from_value(serde_json::json!({"owned":[],"active":null,"pending":{"target":[],"active":null},"stopping":true})).unwrap();
        store
            .save_value(&NativeNetworkRecord {
                journal,
                physical: vec![],
            })
            .unwrap();
        assert!(f.complete(&scope()).is_err());
        store.save_value(&NativeNetworkRecord::default()).unwrap();
        let (mut store, saved) =
            WindowsPairStore::open(f.clone(), scope(), RecordKind::Pair).unwrap();
        let mut pair = saved.unwrap();
        pair.pending_guard =
            Some(crate::member_guard::ExchangePlan::new(&pair.guard, &pair.guard).unwrap());
        store.save(&pair).unwrap();
        assert!(f.complete(&scope()).is_err());
        pair.pending_guard = None;
        store.save(&pair).unwrap();
        f.complete(&scope()).unwrap();
    }
    #[test]
    fn pair_nested_scope_and_record_kind_substitution_are_rejected() {
        let disk = Disk::default();
        let mut f = files(&disk);
        save_initial(&mut f);
        clean(&mut f);
        let (mut store, saved) =
            WindowsPairStore::open(f.clone(), scope(), RecordKind::Pair).unwrap();
        let mut pair = saved.unwrap();
        pair.guard.scope.connection_generation += 1;
        assert!(store.save(&pair).is_err());
        let session = disk.0.borrow().bytes[&PrivateFile::Session].clone();
        disk.0.borrow_mut().bytes.insert(PrivateFile::Pair, session);
        assert!(WindowsPairStore::open(f, scope(), RecordKind::Pair).is_err());
    }
    #[test]
    fn unfinished_claim_survives_crash_before_first_record() {
        let disk = Disk::default();
        let mut f = files(&disk);
        f.claim(&scope()).unwrap();
        let mut reopened = files(&disk);
        assert_eq!(reopened.scopes(RuntimeSlot::Stable).unwrap(), vec![scope()]);
        assert!(reopened.read(&scope(), RecordKind::Pair).unwrap().is_none());
        assert!(reopened.complete(&scope()).is_err());
        assert!(reopened.claim(&scope()).is_err());
    }
    #[test]
    fn typed_store_rejects_inner_scope_even_when_outer_envelope_matches() {
        #[derive(Clone)]
        struct Bytes(Vec<u8>);
        impl SessionFiles for Bytes {
            fn scopes(&mut self, _: RuntimeSlot) -> io::Result<Vec<SessionScope>> {
                Ok(vec![])
            }
            fn claim(&mut self, _: &SessionScope) -> io::Result<()> {
                Ok(())
            }
            fn read(&mut self, _: &SessionScope, _: RecordKind) -> io::Result<Option<Vec<u8>>> {
                Ok(Some(self.0.clone()))
            }
            fn compare_exchange(
                &mut self,
                _: &SessionScope,
                _: RecordKind,
                _: Option<&[u8]>,
                _: &[u8],
            ) -> io::Result<()> {
                panic!("invalid value reached file mutation")
            }
        }
        let mut bad = initial();
        bad.scope.connection_generation += 1;
        let bytes = serde_json::to_vec(&Envelope {
            version: 1,
            scope: scope(),
            payload: bad.clone(),
        })
        .unwrap();
        assert!(WindowsSessionStore::open(Bytes(bytes), scope(), RecordKind::Session).is_err());
        let bytes = serde_json::to_vec(&Envelope {
            version: 1,
            scope: scope(),
            payload: initial(),
        })
        .unwrap();
        let (mut store, _) =
            WindowsSessionStore::open(Bytes(bytes), scope(), RecordKind::Session).unwrap();
        assert!(store.save_value(&bad).is_err());
    }
    #[test]
    fn explicit_verified_empty_completion_tombstones_only_empty_current_claim() {
        let disk = Disk::default();
        let mut f = files(&disk);
        f.claim(&scope()).unwrap();
        // This call is the trusted factory's explicit no-native-effects proof;
        // merely reopening/reading the same bytes above never clears the claim.
        let mut reopened = files(&disk);
        reopened.complete_empty(&scope()).unwrap();
        assert!(files(&disk).claim(&scope()).is_err());
        let disk = Disk::default();
        let mut f = files(&disk);
        save_initial(&mut f);
        assert!(files(&disk).complete_empty(&scope()).is_err());
        assert_eq!(
            files(&disk).scopes(RuntimeSlot::Stable).unwrap(),
            vec![scope()]
        );
    }
    #[test]
    fn future_epoch_record_cannot_be_read_or_completed() {
        let disk = Disk::default();
        let mut f = files(&disk);
        save_initial(&mut f);
        clean(&mut f);
        let raw = disk.0.borrow().bytes[&PrivateFile::Network].clone();
        let mut saved: SavedRecord = serde_json::from_slice(&raw).unwrap();
        saved.network_epoch = 2;
        disk.0
            .borrow_mut()
            .bytes
            .insert(PrivateFile::Network, serde_json::to_vec(&saved).unwrap());
        assert!(f.read(&scope(), RecordKind::Network).is_err());
        assert!(f.complete(&scope()).is_err());
        assert_eq!(f.scopes(RuntimeSlot::Stable).unwrap(), vec![scope()]);
    }
    #[test]
    fn completion_publication_faults_never_release_index_before_marker() {
        for fault in 0..3 {
            let disk = Disk::default();
            let mut f = files(&disk);
            save_initial(&mut f);
            clean(&mut f);
            let marker = completed_file(&scope()).unwrap();
            let original_index = disk.0.borrow().bytes[&PrivateFile::Index].clone();
            match fault {
                0 => disk.0.borrow_mut().fail_file = Some(marker),
                1 => disk.0.borrow_mut().fail_file = Some(PrivateFile::Index),
                _ => disk.0.borrow_mut().lose_file = Some(PrivateFile::Index),
            }
            assert!(f.complete(&scope()).is_err());
            assert_eq!(disk.0.borrow().bytes.contains_key(&marker), fault != 0);
            if fault != 2 {
                assert_eq!(disk.0.borrow().bytes[&PrivateFile::Index], original_index);
            }
            assert!(files(&disk).claim(&scope()).is_err());
            disk.0.borrow_mut().fail_file = None;
            let mut reopened = files(&disk);
            reopened.complete(&scope()).unwrap();
            reopened.complete(&scope()).unwrap(); // lost index ACK is idempotent
            assert!(reopened.scopes(RuntimeSlot::Stable).unwrap().is_empty());
            assert!(reopened.claim(&scope()).is_err());
        }
    }
    #[test]
    fn new_claim_before_record_overwrite_never_adopts_prior_records() {
        let disk = Disk::default();
        let mut f = files(&disk);
        save_initial(&mut f);
        clean(&mut f);
        f.complete(&scope()).unwrap();
        let old_pair = disk.0.borrow().bytes[&PrivateFile::Pair].clone();
        for generation in 3..=5 {
            let mut next = scope();
            next.connection_generation = generation;
            f.claim(&next).unwrap(); // crash here: index advanced, old files remain
            let mut reopened = files(&disk);
            for kind in RecordKind::ALL {
                assert!(reopened.read(&next, kind).unwrap().is_none());
            }
            reopened.complete_empty(&next).unwrap();
            assert_eq!(disk.0.borrow().bytes[&PrivateFile::Pair], old_pair);
        }
        let mut next = scope();
        next.connection_generation = 6;
        f.claim(&next).unwrap();
        let (mut state, old) =
            WindowsSessionStore::open(f.clone(), next.clone(), RecordKind::Session).unwrap();
        assert!(old.is_none());
        state
            .save(
                &SessionState::new(next.clone(), Slot::A, 1, 1)
                    .unwrap()
                    .snapshot(),
            )
            .unwrap();
        let mut reopened = files(&disk);
        assert!(reopened.read(&next, RecordKind::Pair).unwrap().is_none());
        assert!(reopened.complete_empty(&next).is_err()); // partial new records retain cleanup authority
        assert!(reopened.claim(&scope()).is_err());
    }
    #[test]
    fn marker_is_exact_identity_not_permission_to_discard_unfinished_claim() {
        let disk = Disk::default();
        let mut f = files(&disk);
        save_initial(&mut f);
        let marker = completed_file(&scope()).unwrap();
        let identity = f.identity(&scope()).unwrap();
        let bytes = serde_json::to_vec(&CompletedRecord {
            version: PRIVATE_VERSION,
            identity: identity.clone(),
        })
        .unwrap();
        disk.0.borrow_mut().bytes.insert(marker, bytes);
        assert!(f.complete(&scope()).is_err());
        assert!(f.complete_empty(&scope()).is_err());
        assert!(f.claim(&scope()).is_err());
        assert_eq!(f.scopes(RuntimeSlot::Stable).unwrap(), vec![scope()]);
        disk.0.borrow_mut().bytes.remove(&PrivateFile::Index);
        assert!(f.scopes(RuntimeSlot::Stable).is_err()); // marker alone cannot adopt orphan records
        assert!(f.claim(&scope()).is_err());
        for mutation in 0..4 {
            let mut changed = identity.clone();
            match mutation {
                0 => changed.scope.connection_generation += 1,
                1 => changed.boot_id = [0; 16],
                2 => changed.runtime.slot = RuntimeSlot::Latest,
                _ => changed.scope.runtime_generation = 0,
            }
            disk.0.borrow_mut().bytes.insert(
                marker,
                serde_json::to_vec(&CompletedRecord {
                    version: PRIVATE_VERSION,
                    identity: changed,
                })
                .unwrap(),
            );
            assert!(read_completed(&mut disk.clone(), &scope()).is_err());
            assert!(f.claim(&scope()).is_err());
        }
        disk.0
            .borrow_mut()
            .bytes
            .insert(marker, b"{\"version\":2,\"identity\":".to_vec());
        assert!(read_completed(&mut disk.clone(), &scope()).is_err());
        assert!(f.claim(&scope()).is_err());
    }
    #[test]
    fn canonical_marker_address_is_stable_and_keeps_every_scope_fence() {
        assert_eq!(completed_file(&scope()).unwrap().name(),"nelomai-redundant-completed-9532b9ff22e6b30ab697d747a8c79967e43e0d651b748952e3257704c0210e2b.json");
        let original = completed_file(&scope()).unwrap();
        for field in 0..4 {
            let mut changed = scope();
            match field {
                0 => changed.runtime = RuntimeSlot::Latest,
                1 => changed.runtime_generation += 1,
                2 => changed.session_id = "22222222-2222-4222-8222-222222222222".into(),
                _ => changed.connection_generation += 1,
            }
            assert_ne!(completed_file(&changed).unwrap(), original);
        }
    }
    fn prepared_pair() -> PairRecord {
        use crate::member_owner::{Intent, Phase, Record};
        use crate::member_pair::MemberRecord;
        let owner = Record {
            intent: Intent {
                scope: scope(),
                slot: nelomai_contracts::dispatcher::TunnelSlot::A,
                transport: nelomai_client_tunnel::TunnelTransport::WireGuard,
                engine: r"C:\Program Files\Nelomai\engine.exe".into(),
                config_sha256: [7; 32],
            },
            phase: Phase::Prepared,
            proof: None,
            retired_proof: None,
            previous_config_sha256: Some([8; 32]),
        };
        let member = MemberRecord {
            owner,
            prior_stopped: None,
            source: "10.0.0.2".parse().unwrap(),
            endpoint: "192.0.2.1".parse().unwrap(),
            allowed: vec![],
            dns: vec![],
            probe: nelomai_contracts::RedundantHealthProbe {
                kind: nelomai_contracts::HealthProbeKind::DnsA,
                target_ipv4: "10.0.0.1".parse().unwrap(),
                query_name: "probe.invalid".into(),
                timeout_ms: 1000,
            },
            peer: [9; 32],
            started_epoch_ms: 1,
        };
        PairRecord {
            scope: scope(),
            members: [Some(member), None],
            active: None,
            guard: crate::member_guard::Model::empty(scope()).unwrap(),
            pending_guard: None,
            dns: [None, None],
            options: None,
            closing: false,
        }
    }
    #[test]
    fn pair_store_validates_nested_previous_config_phase_before_cas() {
        use crate::member_owner::Phase;
        let disk = Disk::default();
        let mut f = files(&disk);
        save_initial(&mut f);
        let mut pair = prepared_pair();
        let (mut store, _) = WindowsPairStore::open(f, scope(), RecordKind::Pair).unwrap();
        store.save(&pair).unwrap();
        let before = disk.0.borrow().writes;
        pair.members[0].as_mut().unwrap().owner.phase = Phase::Stopping;
        assert!(store.save(&pair).is_err());
        assert_eq!(disk.0.borrow().writes, before);
        pair.members[0].as_mut().unwrap().owner.phase = Phase::Stopped;
        store.save(&pair).unwrap();
        let (_, saved) = WindowsPairStore::open(files(&disk), scope(), RecordKind::Pair).unwrap();
        assert_eq!(
            saved.unwrap().members[0]
                .as_ref()
                .unwrap()
                .owner
                .previous_config_sha256,
            Some([8; 32])
        );
    }
    #[test]
    fn recovery_view_pair_only_allows_retained_cleanup_not_start_or_additions() {
        let disk = Disk::default();
        let mut f = files(&disk);
        save_initial(&mut f);
        let pair = prepared_pair();
        let (mut store, _) = WindowsPairStore::open(f.clone(), scope(), RecordKind::Pair).unwrap();
        store.save(&pair).unwrap();
        let (view, _) = f.recovery_view(RuntimeSlot::Stable).unwrap().unwrap();
        let (mut store, _) = WindowsPairStore::open(view, scope(), RecordKind::Pair).unwrap();
        let before = disk.0.borrow().bytes.clone();
        assert!(store.save(&pair).is_err());
        let mut closing = pair.clone();
        closing.closing = true;
        let mut added = closing.clone();
        let mut b = added.members[0].clone().unwrap();
        b.owner.intent.slot = nelomai_contracts::dispatcher::TunnelSlot::B;
        added.members[1] = Some(b);
        assert!(store.save(&added).is_err());
        let mut replaced = closing.clone();
        replaced.members[0]
            .as_mut()
            .unwrap()
            .owner
            .intent
            .config_sha256 = [99; 32];
        assert!(store.save(&replaced).is_err());
        assert_eq!(disk.0.borrow().bytes, before);
        store.save(&closing).unwrap();
        closing.members[0].as_mut().unwrap().owner.phase = crate::member_owner::Phase::Stopped;
        store.save(&closing).unwrap();
        closing.members = [None, None];
        closing.closing = false;
        store.save(&closing).unwrap();
        let mut resurrected = pair;
        resurrected.closing = true;
        assert!(store.save(&resurrected).is_err());
    }
    #[test]
    fn cleanup_store_accepts_creation_readback_with_assigned_weight() {
        use crate::member_guard::{ExchangePlan, Interface, Member, Model};
        use crate::member_owner::{InterfaceProof, NativeProof, Phase, ProcessProof};
        let disk = Disk::default();
        let mut f = files(&disk);
        save_initial(&mut f);
        let mut pair = prepared_pair();
        pair.closing = true;
        let owner = &mut pair.members[0].as_mut().unwrap().owner;
        owner.phase = Phase::Stopped;
        owner.previous_config_sha256 = None;
        owner.retired_proof = Some(NativeProof {
            process: ProcessProof {
                pid: 12,
                creation_time: 42,
            },
            interface: InterfaceProof {
                index: 73,
                luid: 14918723538255872,
                guid: [5; 16],
            },
        });
        let base = Model::new(
            scope(),
            [
                Some(Member {
                    interface: Interface {
                        index: 73,
                        luid: 14918723538255872,
                    },
                    probes: vec![],
                }),
                None,
            ],
            None,
        )
        .unwrap();
        let pending = ExchangePlan::new(&pair.guard, &base).unwrap();
        pair.pending_guard = Some(pending.clone());
        let (mut store, _) = WindowsPairStore::open(f.clone(), scope(), RecordKind::Pair).unwrap();
        store.save(&pair).unwrap();
        let (view, _) = f.recovery_view(RuntimeSlot::Stable).unwrap().unwrap();
        let (mut store, _) =
            WindowsPairStore::open(view.clone(), scope(), RecordKind::Pair).unwrap();
        let mut observed = base.expected.clone();
        observed.sublayer.as_mut().unwrap().weight = 32771;
        pair.guard = pending.resolve(&observed).unwrap();
        pair.pending_guard = None;
        // Unknown keys/filter contents, scope, and a changed member identity are
        // not legitimized by acknowledging a native assignment.
        let before = disk.0.borrow().bytes.clone();
        for mutation in 0..5 {
            let mut bad = pair.clone();
            match mutation {
                0 => bad.guard.expected.filters[0].weight += 1,
                1 => bad.guard.expected.sublayer.as_mut().unwrap().key.0[0] ^= 1,
                2 => bad.guard.scope.connection_generation += 1,
                3 => {
                    bad.guard.members[0].as_mut().unwrap().interface.index += 1;
                }
                4 => bad.members[0].as_mut().unwrap().owner.intent.config_sha256 = [99; 32],
                _ => unreachable!(),
            }
            assert!(store.save(&bad).is_err(), "mutation {mutation}");
            assert_eq!(disk.0.borrow().bytes, before);
        }
        store
            .save(&pair)
            .expect("native creation readback must remain saveable in cleanup view");
        let (_, saved) = WindowsPairStore::open(view.clone(), scope(), RecordKind::Pair).unwrap();
        assert_eq!(
            saved.unwrap().guard.expected.sublayer.unwrap().weight,
            32771
        );
        // Once acknowledged, the same valid shape at a different weight is no
        // longer a creation readback. It must not become a new CAS precondition.
        let mut changed = pair.clone();
        changed.guard.assigned_sublayer_weight = Some(32772);
        changed.guard.expected.sublayer.as_mut().unwrap().weight = 32772;
        changed.guard.validate().unwrap();
        assert!(store.save(&changed).is_err());
        // The retained stopped owner can then withdraw its exact pinned guard.
        let empty = Model::empty(scope()).unwrap();
        pair.pending_guard = Some(ExchangePlan::new(&pair.guard, &empty).unwrap());
        store.save(&pair).unwrap();
        pair.guard = empty;
        pair.pending_guard = None;
        store.save(&pair).unwrap();
        pair.members = [None, None];
        pair.closing = false;
        store.save(&pair).unwrap();
        let mut view = view;
        clean(&mut view);
        view.complete(&scope()).unwrap();
        assert!(view.scopes(RuntimeSlot::Stable).unwrap().is_empty());
    }

    fn pair_with_predecessor() -> PairRecord {
        use crate::member_owner::{InterfaceProof, NativeProof, Phase, ProcessProof};
        let mut pair = prepared_pair();
        let member = pair.members[0].as_mut().unwrap();
        let mut predecessor = member.owner.clone();
        predecessor.intent.scope.connection_generation -= 1;
        predecessor.intent.config_sha256 = [11; 32];
        predecessor.previous_config_sha256 = Some([12; 32]);
        predecessor.phase = Phase::Stopped;
        predecessor.retired_proof = Some(NativeProof {
            process: ProcessProof {
                pid: 12,
                creation_time: 42,
            },
            interface: InterfaceProof {
                index: 3,
                luid: 4,
                guid: [5; 16],
            },
        });
        member.prior_stopped = Some(predecessor);
        member.owner.previous_config_sha256 = None;
        pair
    }
    #[test]
    fn cleanup_refresh_accepts_exact_predecessor_digest_and_retired_proof() {
        use crate::member_owner::Phase;
        for phase in [Phase::Prepared, Phase::Stopped] {
            for digest in [[11; 32], [12; 32]] {
                let disk = Disk::default();
                let mut f = files(&disk);
                save_initial(&mut f);
                let mut pair = pair_with_predecessor();
                let (mut store, _) =
                    WindowsPairStore::open(f.clone(), scope(), RecordKind::Pair).unwrap();
                store.save(&pair).unwrap();
                let (view, _) = f.recovery_view(RuntimeSlot::Stable).unwrap().unwrap();
                let (mut store, _) =
                    WindowsPairStore::open(view.clone(), scope(), RecordKind::Pair).unwrap();
                pair.closing = true;
                let member = pair.members[0].as_mut().unwrap();
                member.owner.phase = phase;
                member.owner.previous_config_sha256 = Some(digest);
                member.owner.retired_proof = member.prior_stopped.as_ref().unwrap().retired_proof;
                store.save(&pair).unwrap();
                let (_, saved) = WindowsPairStore::open(view, scope(), RecordKind::Pair).unwrap();
                assert_eq!(
                    saved.unwrap().members[0].as_ref().unwrap().owner,
                    pair.members[0].as_ref().unwrap().owner
                );
            }
        }
    }
    #[test]
    fn cleanup_refresh_allows_cleared_previous_config_after_owner_advanced() {
        use crate::member_owner::Phase;
        for phase in [Phase::Stopping, Phase::Stopped] {
            let disk = Disk::default();
            let mut f = files(&disk);
            save_initial(&mut f);
            let mut pair = prepared_pair();
            let (mut store, _) =
                WindowsPairStore::open(f.clone(), scope(), RecordKind::Pair).unwrap();
            store.save(&pair).unwrap();
            let (view, _) = f.recovery_view(RuntimeSlot::Stable).unwrap().unwrap();
            let (mut store, _) = WindowsPairStore::open(view, scope(), RecordKind::Pair).unwrap();
            pair.closing = true;
            pair.members[0].as_mut().unwrap().owner.phase = phase;
            pair.members[0]
                .as_mut()
                .unwrap()
                .owner
                .previous_config_sha256 = None;
            store.save(&pair).unwrap();
            pair.members[0].as_mut().unwrap().owner.phase = Phase::Prepared;
            assert!(store.save(&pair).is_err());
        }
    }
    #[test]
    fn cleanup_refresh_rejects_unknown_metadata_and_mutated_predecessor() {
        use crate::member_owner::Phase;
        let disk = Disk::default();
        let mut f = files(&disk);
        save_initial(&mut f);
        let mut pair = pair_with_predecessor();
        let (mut store, _) = WindowsPairStore::open(f.clone(), scope(), RecordKind::Pair).unwrap();
        store.save(&pair).unwrap();
        let (view, _) = f.recovery_view(RuntimeSlot::Stable).unwrap().unwrap();
        let (mut store, _) = WindowsPairStore::open(view, scope(), RecordKind::Pair).unwrap();
        pair.closing = true;
        pair.members[0].as_mut().unwrap().owner.phase = Phase::Stopped;
        let before = disk.0.borrow().bytes.clone();
        for case in 0..7 {
            let mut bad = pair.clone();
            let member = bad.members[0].as_mut().unwrap();
            let retired = member.prior_stopped.as_ref().unwrap().retired_proof;
            match case {
                0 => member.owner.previous_config_sha256 = Some([99; 32]),
                1 => {
                    member.owner.retired_proof = retired;
                    member.owner.retired_proof.as_mut().unwrap().interface.luid += 1;
                }
                2 => {
                    member.prior_stopped.as_mut().unwrap().intent.config_sha256 = [99; 32];
                    member.owner.previous_config_sha256 = Some([99; 32]);
                }
                3 => member.owner.intent.config_sha256 = [99; 32],
                4 => member.peer = [99; 32],
                5 => {
                    member.owner.phase = Phase::Running;
                    member.owner.proof = retired;
                }
                6 => {
                    member.owner.previous_config_sha256 = Some([11; 32]);
                    member.owner.proof = retired;
                }
                _ => unreachable!(),
            }
            assert!(store.save(&bad).is_err(), "case {case}");
        }
        assert_eq!(disk.0.borrow().bytes, before);
    }
    #[test]
    fn recovery_view_guard_reconciliation_and_epoch_fences_survive_reboot() {
        use crate::member_guard::{ExchangePlan, Interface, Member as GuardMember, Model};
        use crate::member_owner::{InterfaceProof, NativeProof, Phase, ProcessProof};
        let disk = Disk::default();
        let mut f = files(&disk);
        save_initial(&mut f);
        let mut pair = prepared_pair();
        let owner = &mut pair.members[0].as_mut().unwrap().owner;
        owner.previous_config_sha256 = None;
        owner.phase = Phase::Running;
        owner.proof = Some(NativeProof {
            process: ProcessProof {
                pid: 12,
                creation_time: 42,
            },
            interface: InterfaceProof {
                index: 3,
                luid: 4,
                guid: [5; 16],
            },
        });
        let members = [
            Some(GuardMember {
                interface: Interface { index: 3, luid: 4 },
                probes: vec![],
            }),
            None,
        ];
        pair.guard = Model::new(scope(), members.clone(), Some(Slot::A)).unwrap();
        pair.active = Some(Slot::A);
        let fence = Model::new(scope(), members, None).unwrap();
        pair.pending_guard = Some(ExchangePlan::new(&pair.guard, &fence).unwrap());
        let (mut store, _) = WindowsPairStore::open(f, scope(), RecordKind::Pair).unwrap();
        store.save(&pair).unwrap();
        let mut rebooted = ProtectedSessionFiles::new(disk.clone(), runtime(), [8; 16]).unwrap();
        let (mut view, changed) = rebooted
            .recovery_view(RuntimeSlot::Stable)
            .unwrap()
            .unwrap();
        assert!(changed);
        let (mut store, _) =
            WindowsPairStore::open(view.clone(), scope(), RecordKind::Pair).unwrap();
        pair.closing = true;
        pair.active = None;
        store.save(&pair).unwrap();
        let mut foreign = pair.clone();
        foreign.members[0]
            .as_mut()
            .unwrap()
            .owner
            .proof
            .as_mut()
            .unwrap()
            .interface
            .luid += 1;
        assert!(store.save(&foreign).is_err());
        pair.guard = fence;
        pair.pending_guard = None;
        store.save(&pair).unwrap();
        let (mut session, _) =
            WindowsSessionStore::open(view.clone(), scope(), RecordKind::Session).unwrap();
        let mut stopping = initial();
        stopping.phase = SessionPhase::Stopping;
        stopping.network_epoch = 2;
        stopping.local_revision = 2;
        session.save(&stopping).unwrap();
        stopping.network_epoch = 1;
        assert!(session.save(&stopping).is_err());
        assert!(view.complete(&scope()).is_err());
        assert!(view.complete_empty(&scope()).is_err());
        pair.guard = Model::empty(scope()).unwrap();
        pair.members = [None, None];
        pair.closing = false;
        store.save(&pair).unwrap();
        stopping.network_epoch = 2;
        stopping.phase = SessionPhase::Stopped;
        session.save(&stopping).unwrap();
        disk.0.borrow_mut().lose_file = Some(PrivateFile::Index);
        assert!(view.complete(&scope()).is_err());
        view.complete(&scope()).unwrap();
        assert!(rebooted
            .recovery_view(RuntimeSlot::Stable)
            .unwrap()
            .is_none());
        assert!(rebooted.claim(&scope()).is_err());
    }
}
