//! Registry precreation receipts only. No native implementation or factory wiring.
//!
//! Full native address/IP-interface binding is OPEN. `FullNativeRows::Unbound`
//! grants no row mutation permission. A future version must retain native
//! baseline/current/pending metadata, including PrefixOrigin/SuffixOrigin,
//! SkipAsSource/lifetimes, Forwarding/DHCP/metric/link-local behavior, timeout
//! and read-only metadata. DAD is independently observed, never writable
//! permission. Volatile observations (DAD, changing timers/counters) must be
//! separated from writable exact-CAS fields, not silently projected away.
//! Unsupported fields/versions must reject before effects. There is no binary
//! row format here, no guessed ABI and no claim host tests prove Windows ABI.
#![allow(dead_code)]

use crate::member_carrier::{CarrierError as Error, Intent, Provenance, Result};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

const VERSION: u32 = 2;
const MAX_RECORD_BYTES: usize = 65_536;
const VALUE_NAME: &str = "IPAutoconfigurationEnabled";
const INTERFACES: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\";
// Across owners/recovery in THIS process. Cross-process JSON supplies no live
// tokens; process restart cannot preserve this native authority in a record.
static NEXT_INSPECTION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum InterfaceRole {
    RoleCarrier,
    MemberA,
    MemberB,
}
pub(crate) type Role = InterfaceRole;
impl InterfaceRole {
    fn index(self) -> usize {
        match self {
            Self::RoleCarrier => 0,
            Self::MemberA => 1,
            Self::MemberB => 2,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binding {
    pub role: Role,
    /// Canonical GUID bytes, NOT a Windows GUID memory layout.
    pub guid: [u8; 16],
    pub name: String,
    /// Exact HKLM-relative per-interface path. Never a caller-selected root.
    pub registry_path: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Context {
    pub intent: Intent,
    pub provenance: Provenance,
    pub bindings: [Binding; 3],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum Phase {
    Preparing,
    Closing,
    Stopped,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum KeyPhase {
    Unstarted,
    CreatePending,
    Captured,
    DisablePending,
    Disabled,
    RestorePending,
    Clean,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum Value {
    Absent,
    DwordZero,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyReceipt {
    pub role: Role,
    pub phase: KeyPhase,
    /// Durable evidence that a NEW-key ACK was captured; never handle authority.
    pub new_key_ack: bool,
    pub baseline: Value,
    pub current: Value,
    pub pending: Option<Value>,
}
/// An explicit refusal to bind logical rows to unaudited Windows structures.
/// This variant authorizes NO address/IP-interface row write or restoration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum FullNativeRows {
    Unbound,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "WireRecord")]
pub(crate) struct Record {
    pub version: u32,
    pub context: Context,
    pub generation: u64,
    pub phase: Phase,
    pub keys: [KeyReceipt; 3],
    pub native_rows: FullNativeRows,
}
impl Record {
    /// Required raw storage boundary; direct serde also validates semantics,
    /// but only this entry point enforces the total serialized byte limit.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(Error::Invalid);
        }
        serde_json::from_slice(bytes).map_err(|_| Error::Invalid)
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        validate_record(self)?;
        let bytes = serde_json::to_vec(self).map_err(|_| Error::Invalid)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(Error::Invalid);
        }
        Ok(bytes)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRecord {
    version: u32,
    context: Context,
    generation: u64,
    phase: Phase,
    keys: [KeyReceipt; 3],
    native_rows: FullNativeRows,
}
impl TryFrom<WireRecord> for Record {
    type Error = Error;
    fn try_from(w: WireRecord) -> Result<Self> {
        let record = Self {
            version: w.version,
            context: w.context,
            generation: w.generation,
            phase: w.phase,
            keys: w.keys,
            native_rows: w.native_rows,
        };
        validate_record(&record)?;
        Ok(record)
    }
}

/// Required protected-store seam: independently authenticate full scope,
/// boot/runtime/epoch, private ancestry/handles, bounded bytes and exact CAS.
/// Initial publication requires the existing fresh authenticated claim and
/// permanent replay protection; an empty JSON file is not a fresh claim.
/// Reopened claims are cleanup-only. The implementation must apply
/// validate_transition with its independently held fresh/cleanup permission,
/// and bound/decode/encode exact bytes without trusting JSON as provenance.
/// No defaults, path fallback, claim, deletion or legacy-v1 migration.
pub(crate) trait NativeJournal {
    fn load(&mut self, context: &Context) -> Result<Option<Record>>;
    fn compare_exchange(
        &mut self,
        context: &Context,
        expected: Option<&Record>,
        desired: &Record,
    ) -> Result<()>;
}

/// Neither Clone nor Serialize/Deserialize. K must be the actual retained HKEY
/// authority captured by RegCreateKeyEx, not a path, JSON, GUID or numeric ID.
pub(crate) struct NewKeyAck<K> {
    handle: K,
}
impl<K> NewKeyAck<K> {
    /// Native adapter ONLY: call with the disposition and retained handle from
    /// the SAME successful RegCreateKeyEx invocation. An error/lost ACK must
    /// return no token. Existing/opened-key disposition (2) is always rejected.
    pub(crate) fn from_native_created_new_key(disposition: u32, handle: K) -> Result<Self> {
        if disposition != 1 {
            return Err(Error::Pending);
        }
        Ok(Self { handle })
    }
    pub(crate) fn retained_handle(&self) -> &K {
        &self.handle
    }
}
struct HeldKey<K> {
    context: Context,
    binding: Binding,
    ack: NewKeyAck<K>,
}
/// Can only be moved from an existing live owner, never decoded from a record.
pub(crate) struct RetainedKeys<K> {
    keys: [Option<HeldKey<K>>; 3],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyPresence {
    Absent,
    ExactRetainedNewKey,
    Foreign,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NativeValue {
    Absent,
    /// Surface this only for REG_DWORD with exactly four native bytes. Wrong
    /// type/length/unsupported representation belongs in Other, never coercion.
    Dword(u32),
    Other {
        kind: u32,
        bytes: Vec<u8>,
    },
}
/// Independent fresh native queries, NOT deserializable journal metadata.
pub(crate) struct NativeFacts {
    pub context: Context,
    pub binding: Binding,
    pub generation: u64,
    /// Echo of this inspection's process-local challenge; cached proofs fail.
    pub challenge: u64,
    pub key: KeyPresence,
    pub value: NativeValue,
    pub name_absent: bool,
    pub guid_absent: bool,
    pub retained_nic_absent: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ValueCas {
    pub expected: Value,
    pub desired: Value,
    pub value_name: &'static str,
}
/// Every method is mandatory. Future implementations must recheck actual
/// privileged lock ownership and exact fresh native facts inside each effect;
/// the portable checks are not a kernel CAS or Windows native proof.
pub(crate) trait NativeKeyIo {
    /// An owning native RAII handle, never a deserialized/numeric identity.
    type Key;
    /// The actual caller-held privileged mutation lock, not a journal flag.
    type MutationLock;
    fn assert_serialized_lock(
        &mut self,
        lock: &mut Self::MutationLock,
        context: &Context,
    ) -> Result<()>;
    fn inspect(
        &mut self,
        lock: &mut Self::MutationLock,
        record: &Record,
        binding: &Binding,
        retained: Option<&NewKeyAck<Self::Key>>,
        challenge: u64,
    ) -> Result<NativeFacts>;
    /// Recheck name/GUID/key/value absence, require RegCreateKeyEx disposition1,
    /// retain that exact handle. No OpenKey/adoption fallback on any outcome.
    fn create_new_key(
        &mut self,
        lock: &mut Self::MutationLock,
        pending: &Record,
        binding: &Binding,
        absent: &NativeFacts,
    ) -> Result<NewKeyAck<Self::Key>>;
    /// Exact VALUE-only CAS on retained identity AND current path binding.
    /// Disable: absent -> REG_DWORD0 before any adapter create. Restore: only
    /// exact own REG_DWORD0 -> baseline absence after exact NIC absence.
    /// Flush the owned key/value and reread; never delete a key or subtree.
    fn compare_exchange_value(
        &mut self,
        lock: &mut Self::MutationLock,
        pending: &Record,
        binding: &Binding,
        retained: &NewKeyAck<Self::Key>,
        fresh: &NativeFacts,
        mutation: ValueCas,
    ) -> Result<()>;
}
/// Borrowed prerequisite evidence only; not adapter/address readiness, DAD,
/// full-row authority or permission to enable the disconnected factory.
pub(crate) struct PrecreationReceipt<'a, K, L> {
    pub record: &'a Record,
    pub binding: &'a Binding,
    pub new_key_ack: &'a NewKeyAck<K>,
    pub mutation_lock: &'a mut L,
}
type Precreation<'a, I> =
    PrecreationReceipt<'a, <I as NativeKeyIo>::Key, <I as NativeKeyIo>::MutationLock>;
pub(crate) struct NativeOwnership<J, I: NativeKeyIo> {
    context: Context,
    journal: J,
    io: I,
    current: Option<Record>,
    retained: RetainedKeys<I::Key>,
    cleanup_only: bool,
    attempted: [bool; 3],
    consumed: [bool; 3],
}

fn validate_context(context: &Context) -> Result<()> {
    // Reuse the existing pure logical intent/provenance validation. This does
    // not reinterpret its v1 rows or confer native authority on its proof.
    crate::member_carrier::validate_record_shape(&crate::member_carrier::Record {
        version: 1,
        intent: context.intent.clone(),
        provenance: context.provenance.clone(),
        generation: 1,
        phase: crate::member_carrier::Phase::Prepared,
        proof: None,
        rows: None,
    })?;
    for (i, binding) in context.bindings.iter().enumerate() {
        let guid: String = binding
            .guid
            .iter()
            .enumerate()
            .map(|(i, b)| {
                format!(
                    "{}{b:02x}",
                    if matches!(i, 4 | 6 | 8 | 10) { "-" } else { "" }
                )
            })
            .collect();
        if binding.role.index() != i
            || binding.guid == [0; 16]
            || binding.name.is_empty()
            || binding.name.len() > 128
            || !binding
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            || binding.registry_path != format!("{INTERFACES}{{{guid}}}")
            || context.bindings[..i].iter().any(|previous| {
                previous.guid == binding.guid || previous.name.eq_ignore_ascii_case(&binding.name)
            })
        {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}
pub(crate) fn validate_record(record: &Record) -> Result<()> {
    validate_context(&record.context)?;
    if record.version != VERSION || record.generation == 0 {
        return Err(Error::Invalid);
    }
    let mut pending = 0;
    for (i, key) in record.keys.iter().enumerate() {
        if key.role.index() != i || key.baseline != Value::Absent {
            return Err(Error::Invalid);
        }
        let shape = match key.phase {
            KeyPhase::Unstarted | KeyPhase::CreatePending => {
                !key.new_key_ack && key.current == Value::Absent && key.pending.is_none()
            }
            KeyPhase::Captured => {
                key.new_key_ack && key.current == Value::Absent && key.pending.is_none()
            }
            KeyPhase::DisablePending => {
                key.new_key_ack
                    && key.current == Value::Absent
                    && key.pending == Some(Value::DwordZero)
            }
            KeyPhase::Disabled => {
                key.new_key_ack && key.current == Value::DwordZero && key.pending.is_none()
            }
            KeyPhase::RestorePending => {
                key.new_key_ack
                    && key.current == Value::DwordZero
                    && key.pending == Some(Value::Absent)
            }
            KeyPhase::Clean => key.current == Value::Absent && key.pending.is_none(),
        };
        if !shape
            || record.phase == Phase::Preparing
                && matches!(key.phase, KeyPhase::RestorePending | KeyPhase::Clean)
            || record.phase == Phase::Stopped && key.phase != KeyPhase::Clean
        {
            return Err(Error::Invalid);
        }
        if key.pending.is_some() || key.phase == KeyPhase::CreatePending {
            pending += 1;
        }
    }
    if pending > 1 {
        return Err(Error::Invalid);
    }
    Ok(())
}
/// Pure transition firewall for the future protected v2 store. Native proof
/// remains a separate requirement; passing this function never supplies it.
pub(crate) fn validate_transition(
    old: Option<&Record>,
    next: &Record,
    cleanup: bool,
) -> Result<()> {
    validate_record(next)?;
    let Some(old) = old else {
        if cleanup
            || next.generation != 1
            || next.phase != Phase::Preparing
            || next.keys.iter().any(|k| k.phase != KeyPhase::Unstarted)
        {
            return Err(Error::Invalid);
        }
        return Ok(());
    };
    validate_record(old)?;
    if old.context != next.context
        || old.version != next.version
        || old.native_rows != next.native_rows
    {
        return Err(Error::Conflict);
    }
    if old == next {
        return Ok(());
    }
    if old.generation.checked_add(1) != Some(next.generation) {
        return Err(Error::Conflict);
    }
    if old.phase != next.phase {
        if old.keys == next.keys
            && matches!(
                (old.phase, next.phase),
                (Phase::Preparing, Phase::Closing) | (Phase::Closing, Phase::Stopped)
            )
        {
            return Ok(());
        }
        return Err(Error::Invalid);
    }
    let changes: Vec<_> = old
        .keys
        .iter()
        .zip(&next.keys)
        .filter(|(a, b)| a != b)
        .collect();
    if changes.len() != 1 {
        return Err(Error::Invalid);
    }
    let (a, b) = changes[0];
    if a.role != b.role || a.baseline != b.baseline {
        return Err(Error::Invalid);
    }
    let allowed = match old.phase {
        Phase::Preparing if !cleanup => matches!(
            (a.phase, b.phase),
            (KeyPhase::Unstarted, KeyPhase::CreatePending)
                | (KeyPhase::CreatePending, KeyPhase::Captured)
                | (KeyPhase::Captured, KeyPhase::DisablePending)
                | (KeyPhase::DisablePending, KeyPhase::Disabled)
        ),
        Phase::Closing => {
            a.new_key_ack == b.new_key_ack
                && matches!(
                    (a.phase, b.phase),
                    (KeyPhase::Unstarted, KeyPhase::Clean)
                        | (KeyPhase::Captured, KeyPhase::Clean)
                        | (KeyPhase::DisablePending, KeyPhase::Captured)
                        | (KeyPhase::DisablePending, KeyPhase::Disabled)
                        | (KeyPhase::Disabled, KeyPhase::RestorePending)
                        | (KeyPhase::RestorePending, KeyPhase::Clean)
                )
        }
        _ => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(Error::Invalid)
    }
}
fn initial(context: &Context) -> Record {
    Record {
        version: VERSION,
        context: context.clone(),
        generation: 1,
        phase: Phase::Preparing,
        keys: [Role::RoleCarrier, Role::MemberA, Role::MemberB].map(|role| KeyReceipt {
            role,
            phase: KeyPhase::Unstarted,
            new_key_ack: false,
            baseline: Value::Absent,
            current: Value::Absent,
            pending: None,
        }),
        native_rows: FullNativeRows::Unbound,
    }
}
fn next(record: &Record) -> Result<Record> {
    let mut next = record.clone();
    next.generation = record.generation.checked_add(1).ok_or(Error::Invalid)?;
    Ok(next)
}
fn require_nic_absent(facts: &NativeFacts) -> Result<()> {
    if facts.name_absent && facts.guid_absent && facts.retained_nic_absent {
        Ok(())
    } else {
        Err(Error::Conflict)
    }
}
fn require_value(facts: &NativeFacts, value: Value) -> Result<()> {
    if matches!(
        (&facts.value, value),
        (NativeValue::Absent, Value::Absent) | (NativeValue::Dword(0), Value::DwordZero)
    ) {
        Ok(())
    } else {
        Err(Error::Conflict)
    }
}
fn require_owned(facts: &NativeFacts) -> Result<()> {
    if facts.key == KeyPresence::ExactRetainedNewKey {
        Ok(())
    } else {
        Err(Error::Pending)
    }
}
impl<J: NativeJournal, I: NativeKeyIo> NativeOwnership<J, I> {
    pub(crate) fn new(context: Context, journal: J, io: I) -> Result<Self> {
        validate_context(&context)?;
        Ok(Self {
            context,
            journal,
            io,
            current: None,
            retained: RetainedKeys {
                keys: [None, None, None],
            },
            cleanup_only: false,
            attempted: [false; 3],
            consumed: [false; 3],
        })
    }
    pub(crate) fn recover(
        context: Context,
        saved: Record,
        journal: J,
        io: I,
        retained: Option<RetainedKeys<I::Key>>,
    ) -> Result<Self> {
        let mut owner = Self::new(context, journal, io)?;
        owner.validate(&saved)?;
        if owner.snapshot()?.as_ref() != Some(&saved) {
            return Err(Error::Conflict);
        }
        owner.current = Some(saved);
        owner.cleanup_only = true;
        if let Some(retained) = retained {
            owner.retained = retained;
        }
        for (i, held) in owner.retained.keys.iter().enumerate() {
            if held.as_ref().is_some_and(|h| {
                h.context != owner.context || h.binding != owner.context.bindings[i]
            }) {
                return Err(Error::Conflict);
            }
        }
        Ok(owner)
    }
    pub(crate) fn into_retained(self) -> RetainedKeys<I::Key> {
        self.retained
    }
    pub(crate) fn snapshot(&mut self) -> Result<Option<Record>> {
        let record = self.journal.load(&self.context)?;
        if let Some(r) = &record {
            self.validate(r)?;
        }
        Ok(record)
    }
    pub(crate) fn prepare_role(
        &mut self,
        role: Role,
        lock: &mut I::MutationLock,
    ) -> Result<Record> {
        if self.cleanup_only || self.attempted[role.index()] {
            return Err(Error::Retired);
        }
        self.io.assert_serialized_lock(lock, &self.context)?;
        self.attempted[role.index()] = true;
        let result = self.prepare_inner(role, lock);
        if result.is_err() {
            self.cleanup_only = true;
        }
        result
    }
    fn prepare_inner(&mut self, role: Role, lock: &mut I::MutationLock) -> Result<Record> {
        let i = role.index();
        let mut record = match &self.current {
            Some(record) => record.clone(),
            None => {
                if self.snapshot()?.is_some() {
                    return Err(Error::Retired);
                }
                let record = initial(&self.context);
                self.persist(None, &record, lock)?;
                record
            }
        };
        self.require_current(&record)?;
        if record.phase != Phase::Preparing || record.keys[i].phase != KeyPhase::Unstarted {
            return Err(Error::Retired);
        }
        let absent = self.observe(&record, role, lock)?;
        require_nic_absent(&absent)?;
        require_value(&absent, Value::Absent)?;
        if absent.key != KeyPresence::Absent {
            return Err(Error::Conflict);
        }
        let mut pending = next(&record)?;
        pending.keys[i].phase = KeyPhase::CreatePending;
        self.persist(Some(&record), &pending, lock)?;
        record = pending;
        let absent = self.observe(&record, role, lock)?;
        require_nic_absent(&absent)?;
        require_value(&absent, Value::Absent)?;
        if absent.key != KeyPresence::Absent {
            return Err(Error::Conflict);
        }
        next(&record)?; // Captured ACK must have a representable revision.
        self.io.assert_serialized_lock(lock, &self.context)?;
        let binding = self.context.bindings[i].clone();
        let ack = self
            .io
            .create_new_key(lock, &record, &binding, &absent)
            .map_err(|_| Error::Pending)?;
        self.retained.keys[i] = Some(HeldKey {
            context: self.context.clone(),
            binding,
            ack,
        });
        let mut captured = next(&record)?;
        captured.keys[i].phase = KeyPhase::Captured;
        captured.keys[i].new_key_ack = true;
        self.persist(Some(&record), &captured, lock)?;
        record = captured;
        let facts = self.observe(&record, role, lock)?;
        require_owned(&facts)?;
        require_nic_absent(&facts)?;
        require_value(&facts, Value::Absent)?;
        let mut pending = next(&record)?;
        pending.keys[i].phase = KeyPhase::DisablePending;
        pending.keys[i].pending = Some(Value::DwordZero);
        self.persist(Some(&record), &pending, lock)?;
        self.write_value(&pending, role, Value::Absent, Value::DwordZero, lock)?;
        let mut disabled = next(&pending)?;
        disabled.keys[i].phase = KeyPhase::Disabled;
        disabled.keys[i].current = Value::DwordZero;
        disabled.keys[i].pending = None;
        self.persist(Some(&pending), &disabled, lock)?;
        Ok(disabled)
    }
    /// A single-use registry prerequisite, tied to a borrowed captured token.
    /// The eventual adapter must consume it under the SAME caller lock and
    /// reattest native absence/value immediately before Wintun/member create.
    pub(crate) fn before_adapter_create<'a>(
        &'a mut self,
        role: Role,
        lock: &'a mut I::MutationLock,
    ) -> Result<Precreation<'a, I>> {
        let i = role.index();
        if self.cleanup_only || self.consumed[i] {
            return Err(Error::Retired);
        }
        self.io.assert_serialized_lock(lock, &self.context)?;
        self.consumed[i] = true;
        let result = self.check_precreation(role, lock);
        if result.is_err() {
            self.cleanup_only = true;
        }
        result?;
        Ok(PrecreationReceipt {
            record: self.current.as_ref().ok_or(Error::Pending)?,
            binding: &self.context.bindings[i],
            new_key_ack: &self.retained.keys[i].as_ref().ok_or(Error::Pending)?.ack,
            mutation_lock: lock,
        })
    }
    fn check_precreation(&mut self, role: Role, lock: &mut I::MutationLock) -> Result<()> {
        let record = self.current.clone().ok_or(Error::Pending)?;
        if record.phase != Phase::Preparing || record.keys[role.index()].phase != KeyPhase::Disabled
        {
            return Err(Error::Pending);
        }
        let facts = self.observe(&record, role, lock)?;
        require_owned(&facts)?;
        require_nic_absent(&facts)?;
        require_value(&facts, Value::DwordZero)
    }
    /// Restoration only; no adapter adoption, resumption, key/tree deletion or
    /// recovery-created handle. Ambiguous CreatePending stays pending forever.
    pub(crate) fn cleanup(
        &mut self,
        expected: &Record,
        lock: &mut I::MutationLock,
    ) -> Result<Record> {
        self.io.assert_serialized_lock(lock, &self.context)?;
        self.cleanup_only = true;
        self.consumed = [true; 3];
        self.require_current(expected)?;
        let mut record = expected.clone();
        if record.phase == Phase::Stopped {
            self.verify_clean(&record, lock)?;
            return Ok(record);
        }
        if record.phase != Phase::Closing {
            let mut closing = next(&record)?;
            closing.phase = Phase::Closing;
            self.persist(Some(&record), &closing, lock)?;
            record = closing;
        }
        for role in [Role::RoleCarrier, Role::MemberA, Role::MemberB] {
            record = self.clean_key(record, role, lock)?;
        }
        self.verify_clean(&record, lock)?;
        let mut stopped = next(&record)?;
        stopped.phase = Phase::Stopped;
        self.persist(Some(&record), &stopped, lock)?;
        self.verify_clean(&stopped, lock)?;
        Ok(stopped)
    }
    fn clean_key(
        &mut self,
        mut record: Record,
        role: Role,
        lock: &mut I::MutationLock,
    ) -> Result<Record> {
        let i = role.index();
        if record.keys[i].phase == KeyPhase::CreatePending {
            return Err(Error::Pending);
        }
        let mut facts = self.observe(&record, role, lock)?;
        require_nic_absent(&facts)?;
        if record.keys[i].new_key_ack {
            require_owned(&facts)?;
        } else if facts.key != KeyPresence::Absent {
            return Err(Error::Conflict);
        }
        if record.keys[i].phase == KeyPhase::DisablePending {
            let mut confirmed = next(&record)?;
            match facts.value {
                NativeValue::Absent => confirmed.keys[i].phase = KeyPhase::Captured,
                NativeValue::Dword(0) => {
                    confirmed.keys[i].phase = KeyPhase::Disabled;
                    confirmed.keys[i].current = Value::DwordZero;
                }
                _ => return Err(Error::Conflict),
            }
            confirmed.keys[i].pending = None;
            self.persist(Some(&record), &confirmed, lock)?;
            record = confirmed;
            facts = self.observe(&record, role, lock)?;
            require_nic_absent(&facts)?;
            require_owned(&facts)?;
        }
        if record.keys[i].phase == KeyPhase::Disabled {
            require_value(&facts, Value::DwordZero)?;
            let mut pending = next(&record)?;
            pending.keys[i].phase = KeyPhase::RestorePending;
            pending.keys[i].pending = Some(Value::Absent);
            self.persist(Some(&record), &pending, lock)?;
            record = pending;
            facts = self.observe(&record, role, lock)?;
            require_nic_absent(&facts)?;
            require_owned(&facts)?;
        }
        if record.keys[i].phase == KeyPhase::RestorePending {
            match facts.value {
                NativeValue::Dword(0) => {
                    self.write_value(&record, role, Value::DwordZero, Value::Absent, lock)?
                }
                NativeValue::Absent => {} // Exact owned pending restore readback.
                _ => return Err(Error::Conflict),
            }
        } else {
            require_value(&facts, Value::Absent)?;
        }
        if record.keys[i].phase != KeyPhase::Clean {
            let mut clean = next(&record)?;
            clean.keys[i].phase = KeyPhase::Clean;
            clean.keys[i].current = Value::Absent;
            clean.keys[i].pending = None;
            self.persist(Some(&record), &clean, lock)?;
            record = clean;
        }
        Ok(record)
    }
    fn verify_clean(&mut self, record: &Record, lock: &mut I::MutationLock) -> Result<()> {
        for role in [Role::RoleCarrier, Role::MemberA, Role::MemberB] {
            if record.keys[role.index()].phase != KeyPhase::Clean {
                return Err(Error::Pending);
            }
            let facts = self.observe(record, role, lock)?;
            require_nic_absent(&facts)?;
            require_value(&facts, Value::Absent)?;
            if record.keys[role.index()].new_key_ack {
                require_owned(&facts)?;
            } else if facts.key != KeyPresence::Absent {
                return Err(Error::Conflict);
            }
        }
        Ok(())
    }
    fn write_value(
        &mut self,
        record: &Record,
        role: Role,
        expected: Value,
        desired: Value,
        lock: &mut I::MutationLock,
    ) -> Result<()> {
        next(record)?; // Refuse an effect whose confirmation cannot be recorded.
        let facts = self.observe(record, role, lock)?;
        require_nic_absent(&facts)?;
        require_owned(&facts)?;
        require_value(&facts, expected)?;
        self.io.assert_serialized_lock(lock, &self.context)?;
        let i = role.index();
        let held = self.retained.keys[i].as_ref().ok_or(Error::Pending)?;
        let result = self.io.compare_exchange_value(
            lock,
            record,
            &self.context.bindings[i],
            &held.ack,
            &facts,
            ValueCas {
                expected,
                desired,
                value_name: VALUE_NAME,
            },
        );
        // Both success and failure need exact fresh readback. An error is not
        // proof of absence of effects; a successful ACK is not proof of a write.
        let after = self.observe(record, role, lock)?;
        require_nic_absent(&after)?;
        require_owned(&after)?;
        if require_value(&after, desired).is_err() {
            return Err(result.err().unwrap_or(Error::Pending));
        }
        Ok(())
    }
    fn validate(&self, record: &Record) -> Result<()> {
        validate_record(record)?;
        if record.context != self.context {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn require_current(&mut self, expected: &Record) -> Result<()> {
        self.validate(expected)?;
        if self.current.as_ref() != Some(expected) || self.snapshot()?.as_ref() != Some(expected) {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn persist(
        &mut self,
        old: Option<&Record>,
        desired: &Record,
        lock: &mut I::MutationLock,
    ) -> Result<()> {
        self.io.assert_serialized_lock(lock, &self.context)?;
        self.validate(desired)?;
        validate_transition(old, desired, self.cleanup_only)?;
        if self.current.as_ref() != old || self.snapshot()?.as_ref() != old {
            return Err(Error::Conflict);
        }
        let result = self.journal.compare_exchange(&self.context, old, desired);
        let actual = self.snapshot()?;
        if actual.as_ref() == Some(desired) {
            self.current = Some(desired.clone());
            return Ok(());
        }
        if actual.as_ref() != old {
            return Err(Error::Conflict);
        }
        Err(result.err().unwrap_or(Error::Journal))
    }
    fn observe(
        &mut self,
        record: &Record,
        role: Role,
        lock: &mut I::MutationLock,
    ) -> Result<NativeFacts> {
        self.io.assert_serialized_lock(lock, &self.context)?;
        self.require_current(record)?;
        let i = role.index();
        // A serialized ACK flag or even a native boundary's ownership label
        // cannot replace the independently retained original create token.
        if record.keys[i].new_key_ack && self.retained.keys[i].is_none() {
            return Err(Error::Pending);
        }
        let challenge = NEXT_INSPECTION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| Error::Invalid)?;
        let facts = self.io.inspect(
            lock,
            record,
            &self.context.bindings[i],
            self.retained.keys[i].as_ref().map(|h| &h.ack),
            challenge,
        )?;
        if facts.context != self.context
            || facts.binding != self.context.bindings[i]
            || facts.generation != record.generation
            || facts.challenge != challenge
        {
            return Err(Error::Conflict);
        }
        self.require_current(record)?;
        Ok(facts)
    }
}

#[cfg(test)]
#[path = "member_carrier_native_ownership_tests.rs"]
mod tests;
