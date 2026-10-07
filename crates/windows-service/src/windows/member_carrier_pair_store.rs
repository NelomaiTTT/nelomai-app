//! Carrier-only exact protected pair journal. Deliberately unselected.
#![allow(dead_code)]

#[cfg(windows)]
use super::member_session::{ProtectedStore, RecordKind, SessionFiles};
use crate::member_carrier_native_ownership::{self as native, Context};
use crate::member_carrier_pair::{self as pair, CleanupRecord, PairJournal, Phase, Record};
#[cfg(not(windows))]
use crate::member_session::{ProtectedStore, RecordKind, SessionFiles};
use nelomai_client_tunnel::redundancy::session::SessionSnapshot;
use nelomai_client_tunnel::redundancy::SessionScope;
use serde::{Deserialize, Serialize};
use std::cell::{Cell, RefCell};
use std::io;

const MAX_PROTECTED_PAIR: usize = 65_536 + 1024;
fn conflict() -> io::Error {
    io::Error::other("carrier_pair_store_pending_or_conflict")
}

/// Existing protected envelope version stays ONE; its carrier payload version
/// is TWO. Unknown envelope/payload versions never fall back to legacy.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    version: u32,
    scope: SessionScope,
    payload: T,
}
fn envelope<T: serde::de::DeserializeOwned>(scope: &SessionScope, bytes: &[u8]) -> io::Result<T> {
    if !scope.validate() || bytes.len() > MAX_PROTECTED_PAIR {
        return Err(conflict());
    }
    let e: Envelope<T> = serde_json::from_slice(bytes).map_err(|_| conflict())?;
    if e.version != 1 || e.scope != *scope {
        return Err(conflict());
    }
    Ok(e.payload)
}

/// Data validation/dispatch ONLY. Actual SessionFiles authenticates the outer
/// protected identity, boot/runtime/epoch, private handles and active claim.
pub(crate) fn decode_pair_payload(scope: &SessionScope, bytes: &[u8]) -> io::Result<CleanupRecord> {
    let probe: serde_json::Value = envelope(scope, bytes)?;
    let object = probe.as_object().ok_or_else(conflict)?;
    // Reparse the ORIGINAL bytes into the selected strict type. Value is used
    // only to select the branch; it cannot erase duplicate fields into authority.
    let payload = if object.contains_key("version") {
        let r: Record = envelope(scope, bytes)?;
        r.encode()?
    } else {
        let r: crate::member_pair::PairRecord = envelope(scope, bytes)?;
        serde_json::to_vec(&r).map_err(|_| conflict())?
    };
    pair::decode_for_cleanup(&payload, scope)
}
pub(crate) fn carrier_payload(scope: &SessionScope, bytes: &[u8]) -> io::Result<Option<Record>> {
    match decode_pair_payload(scope, bytes)? {
        CleanupRecord::Carrier(r) => Ok(Some(*r)),
        CleanupRecord::Legacy(_) => Ok(None),
    }
}
pub(crate) fn encode_carrier_payload(record: &Record) -> io::Result<Vec<u8>> {
    record.validate()?;
    record.encode()?;
    let bytes = serde_json::to_vec(&Envelope {
        version: 1,
        scope: record.scope.clone(),
        payload: record,
    })
    .map_err(|_| conflict())?;
    if bytes.len() > MAX_PROTECTED_PAIR {
        return Err(conflict());
    }
    Ok(bytes)
}

/// Main's raw Pair CAS must invoke this INSIDE its actual protected transaction
/// using independently authenticated provenance/freshness, never caller JSON.
/// This helper itself grants no private/native authority.
pub(crate) fn validate_carrier_transition(
    scope: &SessionScope,
    provenance: &crate::member_carrier::Provenance,
    expected: Option<&Record>,
    desired: &Record,
    authenticated_fresh: bool,
) -> io::Result<()> {
    if desired.scope != *scope
        || desired.provenance != *provenance
        || (!authenticated_fresh && !matches!(desired.phase, Phase::Closing | Phase::Stopped))
        || (!authenticated_fresh && expected.is_none())
        || (matches!(desired.phase, Phase::Closing | Phase::Stopped)
            && (desired.active.is_some() || desired.operation.is_some()))
    {
        return Err(conflict());
    }
    pair::validate_transition(expected, desired)
}

/// Protected TERMINAL data predicate, NOT native EMPTY. Main must still gate
/// SessionFiles.complete on its independent native/row/guard/full-key inventories.
/// Legacy and carrier records retain their separate exact terminal predicates.
pub(crate) fn require_terminal_pair(scope: &SessionScope, bytes: &[u8]) -> io::Result<()> {
    if let Some(record) = carrier_payload(scope, bytes)? {
        if record.phase != Phase::Stopped {
            return Err(conflict());
        }
        return Ok(());
    }
    let r: crate::member_pair::PairRecord = envelope(scope, bytes)?;
    if r.active.is_some()
        || r.closing
        || r.members.iter().any(Option::is_some)
        || r.dns.iter().any(Option::is_some)
        || r.pending_guard.is_some()
        || r.guard != crate::member_guard::Model::empty(scope.clone()).map_err(|_| conflict())?
    {
        return Err(conflict());
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum PublicationAck {
    Unconfirmed,
    Acknowledged,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReceiptReadback {
    Pending,
    Desired,
}
/// One already-acknowledged WHOLE pair write-ahead window. It never performs
/// a DNS-only CAS or advances the owning coordinator's record revision.
/// Its fields are comparison data; native effect authority remains in G and
/// the actual original Source/network/DNS acknowledgement owners.
struct NetworkIntent {
    raw: Vec<u8>,
    record: Record,
}
/// Comparison window from a returned ORIGINAL whole-record publication ACK.
/// It grants no native ownership/effect permission; G still needs every actual
/// registered original and native snapshot. No deserialization constructor.
struct RecordIntent {
    origin: std::rc::Rc<()>,
    raw: Vec<u8>,
    record: Record,
}
impl RecordIntent {
    fn same_store_origin(&self, other: &Self) -> bool {
        std::rc::Rc::ptr_eq(&self.origin, &other.origin)
    }
    fn terminal_entry(&self, expected: &Record) -> io::Result<()> {
        self.record.validate()?;
        if &self.record != expected
            || self.raw != encode_carrier_payload(&self.record)?
            || self.record.phase != Phase::Stopped
            || self.record.stop_stage != 12
            || self.record.pending.is_some()
            || self.record.pending_guard.is_some()
            || self.record.operation.is_some()
            || self.record.active.is_some()
            || self.record.carrier.is_some()
            || self.record.members.iter().any(Option::is_some)
            || self.record.guard
                != crate::member_carrier_guard::Model::empty(self.record.scope.clone())
                    .map_err(|_| conflict())?
            || self.record.network.as_ref().is_some_and(|network| {
                network.pending.is_some() || network.current != network.baseline
            })
        {
            return Err(conflict());
        }
        Ok(())
    }
    fn verify_files<F: SessionFiles>(&self, files: &mut F) -> io::Result<()> {
        if files.read(&self.record.scope, RecordKind::Pair)?.as_deref() != Some(self.raw.as_slice())
        {
            return Err(conflict());
        }
        Ok(())
    }
    /// Comparison only: this private value was minted from the store's original
    /// acknowledged CAS. Native callers must also bracket this read with their
    /// SAME runtime/private bytes and Calling supervisor checks.
    fn inspect_cleanup_effect<T>(
        &self,
        expected: &Record,
        stage: u8,
        inspect: impl FnOnce(&Record) -> io::Result<T>,
    ) -> io::Result<T> {
        self.cleanup()?;
        if &self.record != expected || self.record.stop_stage != stage {
            return Err(conflict());
        }
        inspect(&self.record)
    }
    fn forward_entry(&self, expected: &Record, effect: pair::Effect) -> io::Result<()> {
        self.effect(expected, effect)?;
        if !matches!(self.record.phase, Phase::Starting | Phase::Running)
            || self.record.operation.is_none()
            || self.record.stop_stage != 0
        {
            return Err(conflict());
        }
        Ok(())
    }
    fn cleanup(&self) -> io::Result<()> {
        use nelomai_client_tunnel::redundancy::Slot;
        let expected = match self.record.stop_stage {
            0 | 10 => pair::Effect::Guard,
            1 => pair::Effect::ReleaseProbes,
            2 => pair::Effect::RestoreNetwork,
            3 => pair::Effect::RestoreWeak,
            4 => pair::Effect::MemberStop(Slot::A),
            5 => pair::Effect::MemberStop(Slot::B),
            6 => pair::Effect::CarrierAddressDelete,
            7 => pair::Effect::CarrierSessionEnd,
            8 => pair::Effect::CarrierClose,
            9 => pair::Effect::NativeEmpty,
            11 => pair::Effect::RestoreKeys,
            12 => pair::Effect::FullEmpty,
            _ => return Err(conflict()),
        };
        if self.record.phase != Phase::Closing
            || self.record.active.is_some()
            || self.record.operation.is_some()
        {
            return Err(conflict());
        }
        self.effect(&self.record, expected)
    }
    fn effect(&self, expected: &Record, effect: pair::Effect) -> io::Result<()> {
        self.record.validate()?;
        if &self.record != expected
            || self.raw != encode_carrier_payload(&self.record)?
            || self.record.pending != Some(effect)
            || matches!(self.record.phase, Phase::Fresh | Phase::Stopped)
        {
            return Err(conflict());
        }
        Ok(())
    }
}

/// Serialization and irreversible read failure only, never native authority.
/// Shared by the actual native Pair reads and portable unwind regression tests.
struct PairIntentCall<'a> {
    busy: &'a Cell<bool>,
    revoked: &'a Cell<bool>,
    completed: bool,
}
impl<'a> PairIntentCall<'a> {
    fn begin(busy: &'a Cell<bool>, revoked: &'a Cell<bool>) -> io::Result<Self> {
        if busy.replace(true) {
            revoked.set(true);
            return Err(conflict());
        }
        let call = Self {
            busy,
            revoked,
            completed: false,
        };
        if revoked.get() {
            return Err(conflict());
        }
        Ok(call)
    }
}
impl Drop for PairIntentCall<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.revoked.set(true);
        }
        self.busy.set(false);
    }
}

/// Non-owning lifetime of one authenticated outer read. Unlike `busy`, this
/// slot is installed ONLY after actual private/runtime/Calling preflight.
/// Native D is the SAME supervisor read pin, not metadata or an effect permit.
struct PairReadFrame<'a, D> {
    slot: &'a RefCell<Option<D>>,
}
impl<'a, D> PairReadFrame<'a, D> {
    fn enter(slot: &'a RefCell<Option<D>>, original: D) -> io::Result<Self> {
        let mut value = slot.try_borrow_mut().map_err(|_| conflict())?;
        if value.is_some() {
            return Err(conflict());
        }
        *value = Some(original);
        Ok(Self { slot })
    }
    fn inspect<T>(
        slot: &RefCell<Option<D>>,
        busy: &Cell<bool>,
        revoked: &Cell<bool>,
        inspect: impl FnOnce(&D) -> io::Result<T>,
    ) -> io::Result<T> {
        if !busy.get() || revoked.get() {
            return Err(conflict());
        }
        let value = slot.try_borrow().map_err(|_| conflict())?;
        let result = inspect(value.as_ref().ok_or_else(conflict)?)?;
        if !busy.get() || revoked.get() {
            return Err(conflict());
        }
        Ok(result)
    }
}
impl<D> Drop for PairReadFrame<'_, D> {
    fn drop(&mut self) {
        // No escaped reference/borrow is returned by inspect. This is an
        // ownership-only read pin; no SDK close/unload is performed here.
        if let Ok(mut value) = self.slot.try_borrow_mut() {
            value.take();
        }
    }
}
impl NetworkIntent {
    fn inspect_record<T>(
        &self,
        expected: &Record,
        read: impl FnOnce(&Record) -> io::Result<T>,
    ) -> io::Result<T> {
        self.validate()?;
        if self.record != *expected {
            return Err(conflict());
        }
        read(&self.record)
    }
    fn validate(&self) -> io::Result<()> {
        self.record.validate()?;
        let r = &self.record;
        let cleanup = r.phase == Phase::Closing;
        if !(if cleanup {
            r.stop_stage == 2 && r.pending == Some(pair::Effect::RestoreNetwork)
        } else {
            matches!(r.phase, Phase::Starting | Phase::Running)
                && r.pending == Some(pair::Effect::Network)
        }) || self.raw != encode_carrier_payload(r)?
        {
            return Err(conflict());
        }
        let n = r.network.as_ref().ok_or_else(conflict)?;
        let c = r.carrier.ok_or_else(conflict)?;
        let target = n.pending.as_ref().ok_or_else(conflict)?;
        for snapshot in [&n.baseline, &n.current, target] {
            let d = snapshot.dns.as_ref().ok_or_else(conflict)?;
            if d.interface.scope != r.scope
                || d.interface.index != c.index
                || d.interface.luid != c.luid
                || d.interface.guid != c.guid
            {
                return Err(conflict());
            }
        }
        if cleanup {
            if target != &n.baseline {
                return Err(conflict());
            }
        } else if n
            .current
            .dns
            .as_ref()
            .ok_or_else(conflict)?
            .with_servers(&r.dns)
            .map_err(|_| conflict())?
            != *target.dns.as_ref().ok_or_else(conflict)?
        {
            return Err(conflict());
        }
        Ok(())
    }
    fn dns_transition(
        &self,
        cleanup: bool,
        expected: Option<&crate::member_pair::DnsRecord>,
        desired: Option<&crate::member_pair::DnsRecord>,
        native_ack: Option<&crate::member_dns::Snapshot>,
    ) -> io::Result<()> {
        self.validate()?;
        if cleanup != (self.record.phase == Phase::Closing) {
            return Err(conflict());
        }
        let n = self.record.network.as_ref().ok_or_else(conflict)?;
        let baseline = n.baseline.dns.as_ref().ok_or_else(conflict)?;
        let current = n.current.dns.as_ref().ok_or_else(conflict)?;
        let target = n
            .pending
            .as_ref()
            .and_then(|v| v.dns.as_ref())
            .ok_or_else(conflict)?;
        // Known full metadata is a comparison set, NOT native acknowledgement.
        let known = |v: &crate::member_dns::Snapshot| v == baseline || v == current || v == target;
        for value in [expected, desired].into_iter().flatten() {
            if &value.baseline != baseline
                || !known(&value.current)
                || value.pending.as_ref().is_some_and(|v| !known(v))
            {
                return Err(conflict());
            }
        }
        match (expected, desired) {
            (None, Some(next)) if &next.current == current && next.pending.is_none() => Ok(()),
            (old, Some(next))
                if next.pending.as_ref() == Some(target)
                    && old.map(|r| &r.current).unwrap_or(current) == &next.current =>
            {
                Ok(())
            }
            (Some(old), Some(next))
                if old.pending.as_ref() == Some(target)
                    && next.pending.is_none()
                    && &next.current == target
                    && native_ack == Some(target) =>
            {
                Ok(())
            }
            (Some(old), None)
                if cleanup
                    && old.pending.is_none()
                    && &old.current == baseline
                    && native_ack == Some(baseline) =>
            {
                Ok(())
            }
            _ => Err(conflict()),
        }
    }
}
/// Process-local storage ACK receipt, not serializable native authority.
/// Retained BEFORE fallible post-publication reads/runtime verification.
struct ExchangeReceipt {
    before: Option<Vec<u8>>,
    desired_bytes: Vec<u8>,
    desired: Record,
    ack: PublicationAck,
    readback: ReceiptReadback,
}

/// Generic F is a boundary seam, not a production root constructor. `open` is
/// PRIVATE: only the mandatory native specialization below and child tests use
/// it. No claim(), complete(), pathname, file creation or native effect occurs.
pub(crate) struct WindowsCarrierPairStore<F: SessionFiles> {
    origin: std::rc::Rc<()>,
    files: F,
    context: Context,
    expected: Option<Vec<u8>>,
    receipt: Option<ExchangeReceipt>,
    cleanup_only: bool,
}
impl<F: SessionFiles> WindowsCarrierPairStore<F> {
    fn verify_original_intent(
        &mut self,
        original: &RecordIntent,
        expected: &Record,
    ) -> io::Result<()> {
        if !std::rc::Rc::ptr_eq(&self.origin, &original.origin) {
            return Err(conflict());
        }
        let current = self.record_intent(expected)?;
        if current.raw != original.raw || current.record != original.record {
            return Err(conflict());
        }
        Ok(())
    }
    fn record_intent(&mut self, expected: &Record) -> io::Result<RecordIntent> {
        let (raw, actual) = self.snapshot()?;
        let receipt = self.receipt.as_ref().ok_or_else(conflict)?;
        if actual.as_ref() != Some(expected)
            || receipt.desired != *expected
            || !matches!(receipt.ack, PublicationAck::Acknowledged)
            || receipt.readback != ReceiptReadback::Desired
            || raw.as_deref() != Some(receipt.desired_bytes.as_slice())
        {
            return Err(conflict());
        }
        let intent = RecordIntent {
            origin: self.origin.clone(),
            raw: raw.ok_or_else(conflict)?,
            record: expected.clone(),
        };
        intent.record.validate()?;
        if intent.raw != encode_carrier_payload(&intent.record)? {
            return Err(conflict());
        }
        Ok(intent)
    }
    fn network_intent(&mut self, expected: &Record) -> io::Result<NetworkIntent> {
        let intent = self.record_intent(expected)?;
        let span = NetworkIntent {
            raw: intent.raw,
            record: intent.record,
        };
        span.validate()?;
        Ok(span)
    }
    fn open(mut files: F, context: Context) -> io::Result<(Self, Option<CleanupRecord>)> {
        validate_context(&context)?;
        let fresh = storage_permission(&mut files, &context, true)?;
        let raw = files.read(&context.intent.scope, RecordKind::Pair)?;
        let saved = raw
            .as_ref()
            .map(|b| decode_pair_payload(&context.intent.scope, b))
            .transpose()?;
        if let Some(CleanupRecord::Carrier(r)) = &saved {
            bind_record(&context, r)?;
        }
        let cleanup_only = saved.is_some() || !fresh;
        if cleanup_only {
            files = files
                .recovery_view(context.intent.scope.runtime)?
                .ok_or_else(conflict)?
                .0;
            if storage_permission(&mut files, &context, true)?
                || files.read(&context.intent.scope, RecordKind::Pair)? != raw
            {
                return Err(conflict());
            }
        } else if !storage_permission(&mut files, &context, false)? {
            return Err(conflict());
        }
        Ok((
            Self {
                origin: std::rc::Rc::new(()),
                files,
                context,
                expected: raw,
                receipt: None,
                cleanup_only,
            },
            saved,
        ))
    }
    fn restrict_to_cleanup(&mut self) {
        self.cleanup_only = true;
        // Best effort shared revocation; local live permission is irreversibly
        // gone even if native private storage is currently unreadable.
        let _ = self
            .files
            .revoke_native_carrier_access(&self.context.intent.scope);
    }
    fn cleanup_view(&mut self) -> io::Result<()> {
        self.files = self
            .files
            .recovery_view(self.context.intent.scope.runtime)?
            .ok_or_else(conflict)?
            .0;
        if storage_permission(&mut self.files, &self.context, true)? {
            return Err(conflict());
        }
        Ok(())
    }
    fn snapshot(&mut self) -> io::Result<(Option<Vec<u8>>, Option<Record>)> {
        if self.cleanup_only {
            self.cleanup_view()?;
        }
        let fresh = storage_permission(&mut self.files, &self.context, self.cleanup_only)?;
        if !self.cleanup_only && !fresh {
            return Err(conflict());
        }
        let raw = self
            .files
            .read(&self.context.intent.scope, RecordKind::Pair)?;
        if raw != self.expected
            && !self.receipt.as_ref().is_some_and(|r| {
                r.readback == ReceiptReadback::Pending
                    && (raw == r.before || raw.as_deref() == Some(r.desired_bytes.as_slice()))
            })
        {
            return Err(conflict());
        }
        let record = raw
            .as_ref()
            .map(|b| carrier_payload(&self.context.intent.scope, b)?.ok_or_else(conflict))
            .transpose()?;
        if let Some(record) = &record {
            bind_record(&self.context, record)?;
        }
        let after = storage_permission(&mut self.files, &self.context, self.cleanup_only)?;
        if after != fresh {
            return Err(conflict());
        }
        Ok((raw, record))
    }
}
impl<F: SessionFiles> PairJournal for WindowsCarrierPairStore<F> {
    fn begin_cleanup(&mut self, scope: &SessionScope) -> io::Result<()> {
        if *scope != self.context.intent.scope {
            return Err(conflict());
        }
        self.restrict_to_cleanup();
        self.cleanup_view()
    }
    fn load(&mut self, scope: &SessionScope) -> io::Result<Option<Record>> {
        let result = (|| {
            if *scope != self.context.intent.scope {
                return Err(conflict());
            }
            let (raw, record) = self.snapshot()?;
            if let Some(receipt) = &mut self.receipt {
                if raw.as_deref() == Some(receipt.desired_bytes.as_slice()) {
                    receipt.readback = ReceiptReadback::Desired;
                    self.expected = raw;
                }
            }
            Ok(record)
        })();
        if result.is_err() {
            self.restrict_to_cleanup();
        }
        result
    }
    fn compare_exchange(&mut self, expected: Option<&Record>, desired: &Record) -> io::Result<()> {
        let result = (|| {
            let (raw, current) = self.snapshot()?;
            if current.as_ref() != expected {
                return Err(conflict());
            }
            bind_record(&self.context, desired)?;
            validate_carrier_transition(
                &self.context.intent.scope,
                &self.context.provenance,
                expected,
                desired,
                !self.cleanup_only,
            )?;
            let bytes = encode_carrier_payload(desired)?;
            self.receipt = Some(ExchangeReceipt {
                before: raw.clone(),
                desired_bytes: bytes.clone(),
                desired: desired.clone(),
                ack: PublicationAck::Unconfirmed,
                readback: ReceiptReadback::Pending,
            });
            let ack = self.files.compare_exchange(
                &self.context.intent.scope,
                RecordKind::Pair,
                raw.as_deref(),
                &bytes,
            );
            if ack.is_ok() {
                // Original storage return receipt FIRST, before any fallible read.
                self.receipt.as_mut().ok_or_else(conflict)?.ack = PublicationAck::Acknowledged;
            } else {
                self.restrict_to_cleanup();
            }
            // Reread even after lost ACK. This classifies only known before/after
            // storage state; it NEVER converts a failed ACK into live permission.
            let (actual_raw, actual) = self.snapshot()?;
            if actual_raw.as_deref() == Some(bytes.as_slice()) && actual.as_ref() == Some(desired) {
                self.expected = Some(bytes);
                self.receipt.as_mut().ok_or_else(conflict)?.readback = ReceiptReadback::Desired;
            } else {
                return Err(conflict());
            }
            ack?;
            // Retain the typed original ACK after return: the native wrapper's
            // independently fallible RuntimeRead check has not run yet. The next
            // exact CAS may supersede this history only after known-state readback.
            Ok(())
        })();
        if result.is_err() {
            self.restrict_to_cleanup();
        }
        result
    }
}

fn bind_record(context: &Context, record: &Record) -> io::Result<()> {
    record.validate()?;
    if record.scope != context.intent.scope
        || record.provenance != context.provenance
        || (!record.addresses.is_empty() && record.addresses != context.intent.addresses)
    {
        return Err(conflict());
    }
    Ok(())
}
fn validate_context(context: &Context) -> io::Result<()> {
    // Same strict semantic context validator as protected native receipts. This
    // template is NEVER stored; unstarted keys grant NO native/new-key authority.
    native::validate_record(&native::Record {
        version: 2,
        context: context.clone(),
        generation: 1,
        phase: native::Phase::Preparing,
        keys: [
            native::Role::RoleCarrier,
            native::Role::MemberA,
            native::Role::MemberB,
        ]
        .map(|role| native::KeyReceipt {
            role,
            phase: native::KeyPhase::Unstarted,
            new_key_ack: false,
            baseline: native::Value::Absent,
            current: native::Value::Absent,
            pending: None,
        }),
        native_rows: native::FullNativeRows::Unbound,
    })
    .map_err(|_| conflict())
}
fn storage_permission<F: SessionFiles>(
    files: &mut F,
    context: &Context,
    retained: bool,
) -> io::Result<bool> {
    let scope = &context.intent.scope;
    let access = files.native_carrier_access(scope)?;
    // Current Session is independently authenticated. An explicitly registered
    // original native view keeps immutable birth provenance; its real protected
    // transaction verifies the selected execution ACK, not a caller's old epoch.
    // Unbound/legacy/recovery access keeps the existing current-epoch rule.
    let (_, session) = ProtectedStore::<_, SessionSnapshot>::open(
        files.clone(),
        scope.clone(),
        RecordKind::Session,
    )?;
    let epoch = session.map(|s| s.network_epoch).unwrap_or(1);
    let native_birth = access.is_registered_native_birth_view();
    if epoch == 0
        || context.provenance.network_epoch > epoch
        || (!retained && !native_birth && context.provenance.network_epoch != epoch)
    {
        return Err(conflict());
    }
    let mut current_context = context.clone();
    if !native_birth {
        current_context.provenance.network_epoch = epoch;
    }
    access.require_native_context(&current_context)?;
    let after = files.native_carrier_access(scope)?;
    after.require_native_context(&current_context)?;
    if after.is_fresh() != access.is_fresh()
        || after.is_registered_native_birth_view() != native_birth
    {
        return Err(conflict());
    }
    Ok(after.is_fresh())
}

#[cfg(windows)]
pub(crate) mod native_store {
    use super::super::member_carrier_key_authority::{KeyLock, KeyLockPin, RuntimeRead};
    use super::super::member_session::NativeSessionFiles;
    use super::*;

    /// A read-only, SAME-store original ACK for a whole coordinator operation.
    /// The trusted G registers THIS object, never an imported record/revision.
    /// It authenticates only current write-ahead intent; SDK ownership, original
    /// receipts, bases, held ports and route/DNS lifecycle remain mandatory.
    pub(crate) struct NativePairIntentRead {
        intent: RecordIntent,
        runtime: RuntimeRead,
        lock: KeyLockPin,
        context: Context,
        files: NativeSessionFiles,
        busy: Cell<bool>,
        revoked: Cell<bool>,
        read_frame: RefCell<
            Option<std::rc::Rc<crate::windows::member_native_deadline::NativeDeadlineReadPin>>,
        >,
    }
    impl NativePairIntentRead {
        /// Original publication lineage, not equality of pins or record bytes.
        /// A later ACK is a different read pin from the SAME original writer.
        pub(crate) fn same_store_origin(&self, other: &Self) -> bool {
            self.intent.same_store_origin(&other.intent)
                && self.runtime.same_original_runtime(&other.runtime)
                && self.context == other.context
                && self.runtime.matches_pin(&self.lock)
                && other.runtime.matches_pin(&other.lock)
        }
        pub(crate) fn matches_runtime(&self, runtime: &RuntimeRead) -> bool {
            self.runtime.same_original_runtime(runtime)
        }
        /// Factual pre-entry only: authenticates the SAME successful protected
        /// publication, exact pending record/effect and real RuntimeRead/lock.
        /// This cannot arm a supervisor or grant any native SDK effect.
        pub(crate) fn verify_forward_entry(
            &self,
            runtime: &RuntimeRead,
            context: &Context,
            expected: &Record,
            effect: pair::Effect,
        ) -> io::Result<()> {
            let mut call = PairIntentCall::begin(&self.busy, &self.revoked)?;
            if !self.matches_runtime(runtime) || &self.context != context {
                return Err(conflict());
            }
            self.intent.forward_entry(expected, effect)?;
            if !self.verify()? {
                return Err(conflict());
            }
            call.completed = true;
            Ok(())
        }
        /// Read-only pre-entry proof for the SAME supervisor's cleanup channel.
        /// Original publication ACK, current exact bytes, RuntimeRead/KeyLock
        /// and precise Closing stage are mandatory. This grants no SDK effects.
        pub(crate) fn verify_cleanup_entry(
            &self,
            runtime: &RuntimeRead,
            context: &Context,
        ) -> io::Result<()> {
            let mut call = PairIntentCall::begin(&self.busy, &self.revoked)?;
            if !self.matches_runtime(runtime) || &self.context != context {
                return Err(conflict());
            }
            self.intent.cleanup()?;
            self.verify()?;
            call.completed = true;
            Ok(())
        }
        /// Precise original Closing ACK before watchdog entry, never a caller
        /// request/equal JSON surrogate and never a native-effect permission.
        pub(crate) fn verify_cleanup_entry_for(
            &self,
            runtime: &RuntimeRead,
            context: &Context,
            expected: &Record,
        ) -> io::Result<()> {
            self.verify_cleanup_entry(runtime, context)?;
            if self.intent.record != *expected {
                return Err(conflict());
            }
            Ok(())
        }
        /// Separate terminal factual channel. Does not accept Closing or
        /// pending effects, arm a watchdog, or revive forward execution.
        pub(crate) fn verify_terminal_entry(
            &self,
            runtime: &RuntimeRead,
            context: &Context,
            expected: &Record,
        ) -> io::Result<()> {
            let mut call = PairIntentCall::begin(&self.busy, &self.revoked)?;
            if !self.matches_runtime(runtime) || &self.context != context {
                return Err(conflict());
            }
            self.intent.terminal_entry(expected)?;
            self.verify()?;
            call.completed = true;
            Ok(())
        }
        /// Read ONLY inside this pin's authenticated outer inspect frame.
        /// Reuses its actual supervisor pin without recursively entering Pair,
        /// Source or Retired. This grants no native effect or close receipt.
        pub(crate) fn verify_terminal_bracket(
            &self,
            runtime: &RuntimeRead,
            supervisor: &crate::windows::member_native_deadline::NativeDeadline,
            context: &Context,
            expected: &Record,
        ) -> io::Result<()> {
            let result =
                PairReadFrame::inspect(&self.read_frame, &self.busy, &self.revoked, |deadline| {
                    if !self.matches_runtime(runtime) || &self.context != context {
                        return Err(conflict());
                    }
                    deadline
                        .verify_runtime_call(supervisor, runtime, context)
                        .map_err(|_| conflict())?;
                    self.intent.terminal_entry(expected)?;
                    self.verify()?;
                    deadline
                        .verify_runtime_call(supervisor, runtime, context)
                        .map_err(|_| conflict())
                });
            if result.is_err() {
                self.revoked.set(true);
            }
            result
        }
        /// Factual module-only read frame, not resource/disposal authority.
        /// Both paths require SAME original Pair publication and current bytes.
        pub(crate) fn verify_module_only_read_entry(
            &self,
            runtime: &RuntimeRead,
            context: &Context,
            expected: &Record,
        ) -> io::Result<()> {
            crate::windows::member_carrier_startup::compare_module_only_read_record(
                context, expected,
            )
            .map_err(|_| conflict())?;
            if expected.phase == Phase::Stopped {
                self.verify_terminal_entry(runtime, context, expected)
            } else {
                self.verify_cleanup_entry_for(runtime, context, expected)
            }
        }
        pub(crate) fn verify_module_only_read_bracket(
            &self,
            runtime: &RuntimeRead,
            supervisor: &crate::windows::member_native_deadline::NativeDeadline,
            context: &Context,
            expected: &Record,
        ) -> io::Result<()> {
            crate::windows::member_carrier_startup::compare_module_only_read_record(
                context, expected,
            )
            .map_err(|_| conflict())?;
            if expected.phase == Phase::Stopped {
                return self.verify_terminal_bracket(runtime, supervisor, context, expected);
            }
            let result =
                PairReadFrame::inspect(&self.read_frame, &self.busy, &self.revoked, |deadline| {
                    if !self.matches_runtime(runtime) || &self.context != context {
                        return Err(conflict());
                    }
                    deadline
                        .verify_runtime_call(supervisor, runtime, context)
                        .map_err(|_| conflict())?;
                    self.intent.cleanup()?;
                    if self.intent.record != *expected {
                        return Err(conflict());
                    }
                    self.verify()?;
                    deadline
                        .verify_runtime_call(supervisor, runtime, context)
                        .map_err(|_| conflict())
                });
            if result.is_err() {
                self.revoked.set(true);
            }
            result
        }
        fn verify(&self) -> io::Result<bool> {
            if self.revoked.get() || !self.runtime.matches_pin(&self.lock) {
                return Err(conflict());
            }
            // The getter already fully authenticates this original backend/context.
            let mut files = self
                .runtime
                .native_files_for_original(&self.context, &self.files)
                .map_err(|_| conflict())?;
            self.intent.verify_files(&mut files)?;
            self.runtime
                .verify_same_session_files(&self.context, &self.files)
                .map_err(|_| conflict())
        }
        /// Brackets READ-ONLY independent gate facts under the actual Calling
        /// watchdog and same original runtime/private record. No successful
        /// mutation, file CAS or permission to substitute numeric observations.
        pub(crate) fn inspect<T>(
            &self,
            runtime: &RuntimeRead,
            supervisor: &crate::windows::member_native_deadline::NativeDeadline,
            inspect: impl FnOnce(&Record) -> io::Result<T>,
        ) -> io::Result<T> {
            let mut call = PairIntentCall::begin(&self.busy, &self.revoked)?;
            if !self.matches_runtime(runtime) {
                return Err(conflict());
            }
            let deadline = std::rc::Rc::new(supervisor.read_pin().map_err(|_| conflict())?);
            deadline
                .verify_runtime_call(supervisor, runtime, &self.context)
                .map_err(|_| conflict())?;
            self.verify()?;
            // The protected reread itself can exhaust the original budget.
            deadline
                .verify_call(supervisor, &self.context)
                .map_err(|_| conflict())?;
            let _frame = PairReadFrame::enter(&self.read_frame, deadline.clone())?;
            let result = inspect(&self.intent.record);
            // A normal callback Err is still a returned read: reauthenticate
            // its postflight before propagating it. Unwind revokes via Drop.
            self.verify()?;
            deadline
                .verify_runtime_call(supervisor, runtime, &self.context)
                .map_err(|_| conflict())?;
            let result = result?;
            call.completed = true;
            Ok(result)
        }
        /// Exact acknowledged pending operation ONLY, not the caller's request.
        pub(crate) fn inspect_effect<T>(
            &self,
            runtime: &RuntimeRead,
            supervisor: &crate::windows::member_native_deadline::NativeDeadline,
            expected: &Record,
            effect: pair::Effect,
            inspect: impl FnOnce(&Record) -> io::Result<T>,
        ) -> io::Result<T> {
            self.inspect(runtime, supervisor, |record| {
                self.intent.effect(expected, effect)?;
                inspect(record)
            })
        }
        /// Read the exact Closing stage from this SAME store's original CAS
        /// ACK under the original RuntimeRead/KeyLock/private record and actual
        /// NativeDeadline Calling checks before and after the callback. Cleanup
        /// uses the protected pair's existing stage/effect validator, including
        /// the two distinct Guard stages. This never arms/runs a supervisor,
        /// publishes a record, or grants SDK effects/absence acknowledgements.
        pub(crate) fn inspect_cleanup_effect<T>(
            &self,
            runtime: &RuntimeRead,
            supervisor: &crate::windows::member_native_deadline::NativeDeadline,
            expected: &Record,
            stage: u8,
            inspect: impl FnOnce(&Record) -> io::Result<T>,
        ) -> io::Result<T> {
            self.inspect(runtime, supervisor, |_| {
                self.intent.inspect_cleanup_effect(expected, stage, inspect)
            })
        }
    }

    /// Read capability minted only from this SAME store's successful original
    /// whole-record publication ACK. No public constructor/import/clone or DNS
    /// CAS; G must separately register this exact operation window and retain
    /// original native acknowledgements. Any record advance invalidates it.
    pub(crate) struct NativeNetworkIntentRead {
        span: NetworkIntent,
        runtime: RuntimeRead,
        lock: KeyLockPin,
        context: Context,
        files: NativeSessionFiles,
        busy: Cell<bool>,
        revoked: Cell<bool>,
    }
    struct IntentCall<'a> {
        pin: &'a NativeNetworkIntentRead,
        completed: bool,
    }
    impl Drop for IntentCall<'_> {
        fn drop(&mut self) {
            if !self.completed {
                self.pin.revoked.set(true);
            }
            self.pin.busy.set(false);
        }
    }
    impl NativeNetworkIntentRead {
        pub(crate) fn matches_runtime(&self, runtime: &RuntimeRead) -> bool {
            self.runtime.same_original_runtime(runtime)
        }
        /// Read this store's exact current publication ACK under its original
        /// Calling budget. This only proves journal coverage, never native
        /// route/DNS ACKs or permission for a network effect.
        pub(crate) fn inspect<T>(
            &self,
            runtime: &RuntimeRead,
            supervisor: &crate::windows::member_native_deadline::NativeDeadline,
            expected: &Record,
            inspect: impl FnOnce(&Record) -> io::Result<T>,
        ) -> io::Result<T> {
            if self.busy.replace(true) {
                self.revoked.set(true);
                return Err(conflict());
            }
            let mut call = IntentCall {
                pin: self,
                completed: false,
            };
            if !self.matches_runtime(runtime) {
                return Err(conflict());
            }
            let deadline = supervisor.read_pin().map_err(|_| conflict())?;
            deadline
                .verify_runtime_call(supervisor, runtime, &self.context)
                .map_err(|_| conflict())?;
            self.verify()?;
            deadline
                .verify_call(supervisor, &self.context)
                .map_err(|_| conflict())?;
            let result = self.span.inspect_record(expected, inspect);
            self.verify()?;
            deadline
                .verify_runtime_call(supervisor, runtime, &self.context)
                .map_err(|_| conflict())?;
            let result = result?;
            call.completed = true;
            Ok(result)
        }
        fn verify(&self) -> io::Result<()> {
            if self.revoked.get() || !self.runtime.matches_pin(&self.lock) {
                return Err(conflict());
            }
            // The getter already fully authenticates this original backend/context.
            let mut files = self
                .runtime
                .native_files_for_original(&self.context, &self.files)
                .map_err(|_| conflict())?;
            if files
                .read(&self.span.record.scope, RecordKind::Pair)?
                .as_deref()
                != Some(self.span.raw.as_slice())
            {
                return Err(conflict());
            }
            self.runtime
                .verify_same_session_files(&self.context, &self.files)
                .map_err(|_| conflict())?;
            Ok(())
        }
        /// Checks journal coverage ONLY. This does not Set DNS, publish a child
        /// record, prove bases/no-permits/ports/native ACKs or authorize effects.
        /// The native_ack input is a comparison value: real G must get it from
        /// the registered actual owner, never caller JSON or metadata equality.
        pub(crate) fn dns_transition(
            &self,
            cleanup: bool,
            expected: Option<&crate::member_pair::DnsRecord>,
            desired: Option<&crate::member_pair::DnsRecord>,
            native_ack: Option<&crate::member_dns::Snapshot>,
        ) -> io::Result<()> {
            if self.busy.replace(true) {
                self.revoked.set(true);
                return Err(conflict());
            }
            let mut call = IntentCall {
                pin: self,
                completed: false,
            };
            self.verify()?;
            self.span
                .dns_transition(cleanup, expected, desired, native_ack)?;
            self.verify()?;
            call.completed = true;
            Ok(())
        }
    }

    /// Mandatory actual RuntimeRead/SAME-KeyLock specialization. No generic
    /// successful gate or caller root/NativeSessionFiles replacement is accepted.
    pub(crate) struct NativeCarrierPairStore {
        inner: WindowsCarrierPairStore<NativeSessionFiles>,
        runtime: RuntimeRead,
        lock: KeyLockPin,
        context: Context,
        original_files: NativeSessionFiles,
    }
    impl NativeCarrierPairStore {
        /// Keep the SAME original writer/receipt identity while adopting ONLY
        /// its canonical runtime's explicitly bound native storage view. This
        /// cannot clear cleanup-only/recovery or import an arbitrary old epoch.
        fn synchronize_native_view(&mut self) -> io::Result<()> {
            if !self.runtime.matches_pin(&self.lock) {
                return Err(conflict());
            }
            if !self.inner.cleanup_only {
                self.inner.files = self
                    .runtime
                    .native_files_for_original(&self.context, &self.original_files)
                    .map_err(|_| conflict())?;
                Ok(())
            } else {
                self.verify()
            }
        }
        /// Same originating store publication only, without minting another
        /// native Rc. Runtime/lock/private bytes remain independently checked;
        /// this read grants no native effect or supervisor authority.
        pub(crate) fn verify_original_intent(
            &mut self,
            original: &NativePairIntentRead,
            expected: &Record,
        ) -> io::Result<()> {
            let result = (|| {
                self.verify()?;
                if !original.matches_runtime(&self.runtime) || original.context != self.context {
                    return Err(conflict());
                }
                original.verify()?;
                self.synchronize_native_view()?;
                self.inner
                    .verify_original_intent(&original.intent, expected)?;
                original.verify()?;
                self.verify()
            })();
            if result.is_err() {
                self.inner.restrict_to_cleanup();
            }
            result
        }
        pub(crate) fn record_intent(
            &mut self,
            expected: &Record,
        ) -> io::Result<NativePairIntentRead> {
            let result = (|| {
                self.synchronize_native_view()?;
                let intent = self.inner.record_intent(expected)?;
                let pin = NativePairIntentRead {
                    intent,
                    runtime: self.runtime.read_pin().map_err(|_| conflict())?,
                    lock: self.lock.read_pin(),
                    context: self.context.clone(),
                    files: self.original_files.clone(),
                    busy: Cell::new(false),
                    revoked: Cell::new(false),
                    read_frame: RefCell::new(None),
                };
                pin.verify()?;
                self.verify()?;
                Ok(pin)
            })();
            if result.is_err() {
                self.inner.restrict_to_cleanup();
            }
            result
        }
        pub(crate) fn network_intent(
            &mut self,
            expected: &Record,
        ) -> io::Result<NativeNetworkIntentRead> {
            let result = (|| {
                self.synchronize_native_view()?;
                let span = self.inner.network_intent(expected)?;
                let pin = NativeNetworkIntentRead {
                    span,
                    runtime: self.runtime.read_pin().map_err(|_| conflict())?,
                    lock: self.lock.read_pin(),
                    context: self.context.clone(),
                    files: self.original_files.clone(),
                    busy: Cell::new(false),
                    revoked: Cell::new(false),
                };
                pin.verify()?;
                self.verify()?;
                Ok(pin)
            })();
            if result.is_err() {
                self.inner.restrict_to_cleanup();
            }
            result
        }
        pub(crate) fn from_runtime(
            runtime: &RuntimeRead,
            lock: &KeyLock,
            files: NativeSessionFiles,
            context: Context,
        ) -> io::Result<(Self, Option<CleanupRecord>)> {
            if !runtime.matches_lock(lock) {
                return Err(conflict());
            }
            // Main's actual pointer/backend/runtime check, not metadata equality
            // or a duplicated file getter. It grants no fresh claim by itself.
            runtime
                .verify_same_session_files(&context, &files)
                .map_err(|_| conflict())?;
            let (inner, saved) = WindowsCarrierPairStore::open(files.clone(), context.clone())?;
            let store = Self {
                inner,
                runtime: runtime.read_pin().map_err(|_| conflict())?,
                lock: lock.pin(),
                context,
                original_files: files,
            };
            store.verify()?;
            Ok((store, saved))
        }
        fn verify(&self) -> io::Result<()> {
            if !self.runtime.matches_pin(&self.lock) {
                return Err(conflict());
            }
            self.runtime
                .verify_same_session_files(&self.context, &self.original_files)
                .map(|_| ())
                .map_err(|_| conflict())
        }
    }
    impl PairJournal for NativeCarrierPairStore {
        fn begin_cleanup(&mut self, scope: &SessionScope) -> io::Result<()> {
            if *scope != self.context.intent.scope || !self.runtime.matches_pin(&self.lock) {
                return Err(conflict());
            }
            // Do not first verify the revoked forward view: explicit Stop must
            // reach its own private Closing CAS even after a lost Session ACK.
            // Actual SDK actions still need that returned original Closing ACK.
            self.inner.restrict_to_cleanup();
            self.inner.files = self
                .runtime
                .begin_native_cleanup_storage(&self.context, &self.original_files)
                .map_err(|_| conflict())?;
            self.inner.begin_cleanup(scope)?;
            self.verify()
        }
        fn load(&mut self, scope: &SessionScope) -> io::Result<Option<Record>> {
            let result = (|| {
                self.synchronize_native_view()?;
                let read = self.inner.load(scope);
                let after = self.verify();
                after?;
                read
            })();
            if result.is_err() {
                self.inner.restrict_to_cleanup();
            }
            result
        }
        fn compare_exchange(
            &mut self,
            expected: Option<&Record>,
            desired: &Record,
        ) -> io::Result<()> {
            let result = (|| {
                self.synchronize_native_view()?;
                let ack = self.inner.compare_exchange(expected, desired);
                let after = self.verify();
                after?;
                ack
            })();
            if result.is_err() {
                self.inner.restrict_to_cleanup();
            }
            result
        }
    }
}

#[cfg(windows)]
#[allow(unused_imports)] // Deliberately unselected until actual native/factory gates close.
pub(crate) use native_store::{NativeCarrierPairStore, NativeNetworkIntentRead};

#[cfg(test)]
#[path = "member_carrier_pair_store_tests.rs"]
mod tests;
