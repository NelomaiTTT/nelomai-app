//! Portable carrier lifecycle; deliberately unwired from production factories.
#![allow(dead_code)] // No native adapter or caller is enabled by this task.

use crate::member_owner::InterfaceProof;
use nelomai_client_tunnel::redundancy::SessionScope;
use nelomai_contracts::dispatcher::EngineIdentity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const VERSION: u32 = 1;
const WAIT_MS: u64 = 5_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Intent {
    pub scope: SessionScope,
    pub addresses: Vec<ipnet::IpNet>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Provenance {
    pub boot_id: [u8; 16],
    pub runtime: EngineIdentity,
    pub network_epoch: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum Phase {
    Prepared,
    Created,
    Configured,
    Closing,
    Stopped,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AddressRow {
    pub address: ipnet::IpNet,
    pub skip_as_source: bool,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WeakHostRow {
    pub send: bool,
    pub receive: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum RowValue {
    Address(Option<AddressRow>),
    WeakHost(WeakHostRow),
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RowState {
    pub baseline: RowValue,
    pub current: RowValue,
    pub pending: Option<RowValue>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    #[serde(deserialize_with = "decode_version")]
    pub version: u32,
    pub intent: Intent,
    pub provenance: Provenance,
    pub generation: u64,
    pub phase: Phase,
    pub proof: Option<InterfaceProof>,
    pub rows: Option<[RowState; 2]>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CarrierKey {
    pub name: String,
    pub guid: [u8; 16],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DadState {
    Tentative,
    Preferred,
    Duplicate,
    Deprecated,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Observation {
    pub provenance: Provenance,
    pub by_name: Option<InterfaceProof>,
    pub by_guid: Option<InterfaceProof>,
    pub retained: Vec<InterfaceProof>,
    pub rows: Option<[RowValue; 2]>,
    pub dad: Option<DadState>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Captured {
    pub proof: InterfaceProof,
    pub baseline: [RowValue; 2],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RowKind {
    Address,
    WeakHost,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum CarrierError {
    #[error("carrier_invalid")]
    Invalid,
    #[error("carrier_conflict")]
    Conflict,
    #[error("carrier_pending_cleanup")]
    Pending,
    #[error("carrier_retired")]
    Retired,
    #[error("carrier_native")]
    Native,
    #[error("carrier_journal")]
    Journal,
    #[error("carrier_deadline")]
    Deadline,
}
pub(crate) type Result<T> = std::result::Result<T, CarrierError>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Readiness {
    Tentative,
    Ready(InterfaceProof),
}
pub(crate) trait CarrierJournal {
    /// Keyed by the full scope-derived carrier identity, under the serialized
    /// privileged owner. Native storage must authenticate private ancestry,
    /// runtime, boot and epoch; no IPC path or unprotected storage fallback.
    fn load(&mut self, key: &CarrierKey) -> Result<Option<Record>>;
    /// Atomic, durable CAS. An error may mean a committed write with lost ACK.
    fn compare_exchange(
        &mut self,
        key: &CarrierKey,
        expected: Option<&Record>,
        desired: &Record,
    ) -> Result<()>;
}
pub(crate) trait CarrierIo {
    /// Fresh independent name/GUID and retained index/LUID/GUID lookups. A
    /// lookup/query failure is an error, never absence. Rows cover exactly the
    /// managed address key and the carrier's IPv4 weak-host row; reject any
    /// unsupported attributes rather than projecting away native differences.
    /// Provenance comes from trusted current boot/runtime/epoch evidence.
    fn inspect(
        &mut self,
        intent: &Intent,
        key: &CarrierKey,
        retained: Option<&InterfaceProof>,
    ) -> Result<Observation>;
    /// Reattest expected absence and provenance immediately before creation;
    /// capture identity AND the exact initial rows from the newly created
    /// resource's owned handle. Never open/adopt an existing name or GUID.
    /// An error/ambiguous ACK conveys no proof, even if an adapter now exists.
    fn create_fresh(
        &mut self,
        prepared: &Record,
        key: &CarrierKey,
        expected: &Observation,
    ) -> Result<Captured>;
    /// Reattest full scope/provenance and exact native proof immediately before
    /// the row CAS. Preserve every supported attribute, fail on unsupported
    /// native fields. DAD is a separate observation, not writable row content.
    /// An error may follow a partial/completed effect; retain pending authority.
    fn compare_exchange_row(
        &mut self,
        pending: &Record,
        kind: RowKind,
        expected: &RowValue,
        desired: &RowValue,
    ) -> Result<()>;
    /// Cancel/drain/close only the exact owned handle/proof after reattestation.
    /// This single call must be bounded by budget_ms; no hidden infinite waits.
    /// Return an error if cancellation/draining/closure cannot be acknowledged.
    fn close(&mut self, closing: &Record, budget_ms: u64) -> Result<()>;
}
pub(crate) struct CarrierOwner<J, I> {
    intent: Intent,
    provenance: Provenance,
    journal: J,
    io: I,
    key: CarrierKey,
    cleanup_only: bool,
    consumed: bool,
    failed: bool,
    clock: Option<(u64, u64)>,
    readiness_record: Option<Record>,
}
impl<J: CarrierJournal, I: CarrierIo> CarrierOwner<J, I> {
    /// Factory supplies authenticated provenance independently of saved data.
    /// Full scope generations fence Start; generation below is a CAS revision,
    /// not server allocation, a boot epoch or native ownership evidence.
    pub(crate) fn new(intent: Intent, provenance: Provenance, journal: J, io: I) -> Result<Self> {
        validate_intent(&intent, &provenance)?;
        let key = carrier_key(&intent.scope)?;
        Ok(Self {
            intent,
            provenance,
            journal,
            io,
            key,
            cleanup_only: false,
            consumed: false,
            failed: false,
            clock: None,
            readiness_record: None,
        })
    }
    pub(crate) fn recover_for_cleanup(
        intent: Intent,
        provenance: Provenance,
        saved: Record,
        journal: J,
        io: I,
    ) -> Result<Self> {
        let mut owner = Self::new(intent, provenance, journal, io)?;
        owner.require_current(&saved)?;
        owner.cleanup_only = true;
        owner.consumed = true;
        Ok(owner)
    }
    /// One creation attempt per owner/scope. Preparation configures rows but
    /// publishes a proof only after Preferred plus exact row readback. Caller
    /// supplies monotone milliseconds in this boot; no internal loop or clock.
    pub(crate) fn prepare(&mut self, now_ms: u64) -> Result<Readiness> {
        if self.cleanup_only || self.consumed {
            return Err(CarrierError::Retired);
        }
        self.consumed = true;
        let result = self.prepare_inner(now_ms);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn prepare_inner(&mut self, now_ms: u64) -> Result<Readiness> {
        // Scopes are exclusive and never reused, including a stopped record.
        if self.snapshot()?.is_some() {
            return Err(CarrierError::Retired);
        }
        let before = self.io.inspect(&self.intent, &self.key, None)?;
        self.attest(None, &before)?;
        let prepared = Record {
            version: VERSION,
            intent: self.intent.clone(),
            provenance: self.provenance.clone(),
            generation: 1,
            phase: Phase::Prepared,
            proof: None,
            rows: None,
        };
        self.persist(None, &prepared)?;
        let fresh = self.observe(&prepared)?;
        // The durable Prepared record stays the sole authority on ambiguous
        // create or failed proof persistence. Observations never supply proof.
        let captured = self
            .io
            .create_fresh(&prepared, &self.key, &fresh)
            .map_err(|_| CarrierError::Pending)?;
        let mut record = next(&prepared)?;
        record.phase = Phase::Created;
        record.proof = Some(captured.proof);
        record.rows = Some(captured.baseline.map(|baseline| RowState {
            current: baseline.clone(),
            baseline,
            pending: None,
        }));
        self.persist(Some(&prepared), &record)?;
        let goal = desired_rows(&self.intent);
        // Weak-host precedes address publication. All changes are separately
        // journaled and read back so every partial outcome is recoverable.
        for index in [1, 0] {
            if record.rows.as_ref().unwrap()[index].current != goal[index] {
                record = self.mutate_row(record, index, goal[index].clone())?;
            }
        }
        self.clock = Some((now_ms, now_ms));
        self.readiness_record = Some(record);
        self.poll_inner(now_ms)
    }
    pub(crate) fn poll_ready(&mut self, now_ms: u64) -> Result<Readiness> {
        if self.cleanup_only || self.failed || self.clock.is_none() {
            return Err(CarrierError::Retired);
        }
        let result = self.poll_inner(now_ms);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn poll_inner(&mut self, now_ms: u64) -> Result<Readiness> {
        let (start, last) = self.clock.ok_or(CarrierError::Retired)?;
        if now_ms < last {
            return Err(CarrierError::Invalid);
        }
        self.clock = Some((start, now_ms));
        let record = self.readiness_record.clone().ok_or(CarrierError::Retired)?;
        self.require_current(&record)?;
        if !matches!(record.phase, Phase::Created | Phase::Configured) {
            return Err(CarrierError::Retired);
        }
        if record.phase == Phase::Created && now_ms - start > WAIT_MS {
            return Err(CarrierError::Deadline);
        }
        let observed = self.observe(&record)?;
        self.require_present(&record, &observed)?;
        let goal = desired_rows(&self.intent);
        if observed.rows.as_ref() != Some(&goal)
            || record
                .rows
                .as_ref()
                .unwrap()
                .iter()
                .enumerate()
                .any(|(i, r)| r.current != goal[i] || r.pending.is_some())
        {
            return Err(CarrierError::Conflict);
        }
        match observed.dad {
            Some(DadState::Tentative)
                if record.phase == Phase::Created && now_ms - start < WAIT_MS =>
            {
                Ok(Readiness::Tentative)
            }
            Some(DadState::Tentative) => Err(CarrierError::Deadline),
            Some(DadState::Preferred) => {
                if record.phase != Phase::Configured {
                    let mut configured = next(&record)?;
                    configured.phase = Phase::Configured;
                    self.persist(Some(&record), &configured)?;
                    // CAS acknowledgement does not establish continued native
                    // readiness. Reattest once more before returning authority.
                    let after = self.observe(&configured)?;
                    self.require_present(&configured, &after)?;
                    if after.rows.as_ref() != Some(&goal) {
                        return Err(CarrierError::Conflict);
                    }
                    if after.dad != Some(DadState::Preferred) {
                        return Err(CarrierError::Native);
                    }
                    self.readiness_record = Some(configured);
                }
                Ok(Readiness::Ready(record.proof.unwrap()))
            }
            Some(DadState::Duplicate | DadState::Deprecated) | None => Err(CarrierError::Native),
        }
    }
    pub(crate) fn snapshot(&mut self) -> Result<Option<Record>> {
        let record = self.journal.load(&self.key)?;
        if let Some(r) = &record {
            self.validate(r)?;
        }
        Ok(record)
    }
    /// Recovery is cleanup-only; its proof is never returned as a ready carrier.
    /// On every failure the last durable current/pending values remain intact.
    pub(crate) fn stop(&mut self, expected: &Record) -> Result<Record> {
        self.consumed = true;
        self.failed = true;
        self.require_current(expected)?;
        let mut record = expected.clone();
        let observed = self.observe(&record)?;
        if record.phase == Phase::Stopped {
            self.require_absent(&observed)?;
            return Ok(record);
        }
        if let Some(rows) = &record.rows {
            if self.attest(record.proof.as_ref(), &observed)? {
                require_owned_rows(rows, &observed)?;
            } else if rows
                .iter()
                .any(|r| r.current != r.baseline || r.pending.is_some())
            {
                // A vanished dirty interface is not an observed restoration.
                return Err(CarrierError::Pending);
            }
        }
        if record.phase != Phase::Closing {
            let mut closing = next(&record)?;
            closing.phase = Phase::Closing;
            self.persist(Some(&record), &closing)?;
            record = closing;
        }
        if record.proof.is_some() {
            let observed = self.observe(&record)?;
            if self.attest(record.proof.as_ref(), &observed)? {
                require_owned_rows(record.rows.as_ref().unwrap(), &observed)?;
                // Resolve each outstanding write from fresh exact readback,
                // never assume a native error means "nothing happened".
                for index in [0, 1] {
                    if record.rows.as_ref().unwrap()[index].pending.is_some() {
                        let observed = self.observe(&record)?;
                        self.require_present(&record, &observed)?;
                        require_owned_rows(record.rows.as_ref().unwrap(), &observed)?;
                        let mut confirmed = next(&record)?;
                        let row = &mut confirmed.rows.as_mut().unwrap()[index];
                        row.current = observed.rows.as_ref().unwrap()[index].clone();
                        row.pending = None;
                        self.persist(Some(&record), &confirmed)?;
                        record = confirmed;
                    }
                    let row = &record.rows.as_ref().unwrap()[index];
                    if row.current != row.baseline {
                        let baseline = row.baseline.clone();
                        record = self.mutate_row(record, index, baseline)?;
                    }
                }
                let observed = self.observe(&record)?;
                self.require_present(&record, &observed)?;
                require_owned_rows(record.rows.as_ref().unwrap(), &observed)?;
                // Ensure terminal revision is representable before closing.
                next(&record)?;
                self.io.close(&record, WAIT_MS)?;
            }
        }
        let after = self.observe(&record)?;
        self.require_absent(&after)?;
        let mut stopped = next(&record)?;
        stopped.phase = Phase::Stopped;
        self.persist(Some(&record), &stopped)?;
        Ok(stopped)
    }
    fn mutate_row(&mut self, record: Record, index: usize, desired: RowValue) -> Result<Record> {
        let mut pending = next(&record)?;
        pending.rows.as_mut().unwrap()[index].pending = Some(desired.clone());
        self.persist(Some(&record), &pending)?;
        let observed = self.observe(&pending)?;
        self.require_present(&pending, &observed)?;
        require_owned_rows(pending.rows.as_ref().unwrap(), &observed)?;
        let expected = &pending.rows.as_ref().unwrap()[index].current;
        if &observed.rows.as_ref().unwrap()[index] != expected {
            return Err(CarrierError::Conflict);
        }
        self.io.compare_exchange_row(
            &pending,
            if index == 0 {
                RowKind::Address
            } else {
                RowKind::WeakHost
            },
            expected,
            &desired,
        )?;
        let observed = self.observe(&pending)?;
        self.require_present(&pending, &observed)?;
        require_owned_rows(pending.rows.as_ref().unwrap(), &observed)?;
        if observed.rows.as_ref().unwrap()[index] != desired {
            return Err(CarrierError::Pending);
        }
        let mut confirmed = next(&pending)?;
        let row = &mut confirmed.rows.as_mut().unwrap()[index];
        row.current = desired;
        row.pending = None;
        self.persist(Some(&pending), &confirmed)?;
        Ok(confirmed)
    }
    fn validate(&self, record: &Record) -> Result<()> {
        validate_record_shape(record)?;
        if record.intent != self.intent || record.provenance != self.provenance {
            return Err(CarrierError::Conflict);
        }
        Ok(())
    }
    fn require_current(&mut self, expected: &Record) -> Result<()> {
        self.validate(expected)?;
        if self.snapshot()?.as_ref() != Some(expected) {
            return Err(CarrierError::Conflict);
        }
        Ok(())
    }
    fn persist(&mut self, expected: Option<&Record>, desired: &Record) -> Result<()> {
        self.validate(desired)?;
        let result = self.journal.compare_exchange(&self.key, expected, desired);
        // Also reread successful ACKs: the durable exact desired record, never
        // a blind retry, is the only authority for the following native effect.
        let actual = self.snapshot()?;
        if actual.as_ref() == Some(desired) {
            return Ok(());
        }
        if actual.as_ref() != expected {
            return Err(CarrierError::Conflict);
        }
        Err(result.err().unwrap_or(CarrierError::Journal))
    }
    fn observe(&mut self, record: &Record) -> Result<Observation> {
        self.require_current(record)?;
        let observed = self
            .io
            .inspect(&self.intent, &self.key, record.proof.as_ref())?;
        self.attest(record.proof.as_ref(), &observed)?;
        self.require_current(record)?;
        Ok(observed)
    }
    fn attest(&self, proof: Option<&InterfaceProof>, observed: &Observation) -> Result<bool> {
        if observed.provenance != self.provenance {
            return Err(CarrierError::Conflict);
        }
        if observed.by_name.is_none() && observed.by_guid.is_none() && observed.retained.is_empty()
        {
            if observed.rows.is_some() || observed.dad.is_some() {
                return Err(CarrierError::Conflict);
            }
            return Ok(false);
        }
        let proof = proof.ok_or(CarrierError::Conflict)?;
        if observed.by_name != Some(*proof)
            || observed.by_guid != Some(*proof)
            || observed.retained.as_slice() != [*proof]
            || observed.rows.is_none()
        {
            return Err(CarrierError::Conflict);
        }
        Ok(true)
    }
    fn require_present(&self, record: &Record, observed: &Observation) -> Result<()> {
        if self.attest(record.proof.as_ref(), observed)? {
            Ok(())
        } else {
            Err(CarrierError::Conflict)
        }
    }
    fn require_absent(&self, observed: &Observation) -> Result<()> {
        if self.attest(None, observed)? {
            Err(CarrierError::Pending)
        } else {
            Ok(())
        }
    }
}
pub(crate) fn carrier_key(scope: &SessionScope) -> Result<CarrierKey> {
    if !scope.validate() {
        return Err(CarrierError::Invalid);
    }
    let mut hash = Sha256::new();
    hash.update(b"nelomai-member-carrier/v1\0"); // Disjoint from member/guard domains.
    hash.update([match scope.runtime {
        nelomai_contracts::RuntimeSlot::Stable => 0,
        nelomai_contracts::RuntimeSlot::Latest => 1,
    }]);
    hash.update(scope.runtime_generation.to_be_bytes());
    hash.update(scope.session_id.as_bytes());
    hash.update(scope.connection_generation.to_be_bytes());
    let digest = hash.finalize();
    let mut guid: [u8; 16] = digest[..16].try_into().expect("SHA256 prefix");
    guid[6] = (guid[6] & 0x0f) | 0x80;
    guid[8] = (guid[8] & 0x3f) | 0x80;
    let suffix: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    Ok(CarrierKey {
        name: format!("nelomai-carrier-{suffix}"),
        guid,
    })
}
fn decode_version<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<u32, D::Error> {
    let version = u32::deserialize(d)?;
    if version != VERSION {
        return Err(serde::de::Error::custom("carrier_unknown_version"));
    }
    Ok(version)
}
fn validate_intent(intent: &Intent, provenance: &Provenance) -> Result<()> {
    let r = &provenance.runtime;
    if !intent.scope.validate()
        || intent.addresses.len() != 1
        || !matches!(intent.addresses[0], ipnet::IpNet::V4(a) if a.prefix_len() == 32
            && !a.addr().is_unspecified() && !a.addr().is_loopback() && !a.addr().is_multicast()
            && !a.addr().is_broadcast() && !a.addr().is_link_local()
            && a.addr().octets()[0] != 0 && a.addr().octets()[0] < 240)
        || provenance.boot_id == [0; 16]
        || provenance.network_epoch == 0
        || r.slot != intent.scope.runtime
        || r.runtime_contract_version == 0
        || [&r.runtime_version, &r.container_version]
            .iter()
            .any(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control))
        || r.manifest_sha256.len() != 64
        || !r
            .manifest_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CarrierError::Invalid);
    }
    Ok(())
}
fn desired_rows(intent: &Intent) -> [RowValue; 2] {
    [
        RowValue::Address(Some(AddressRow {
            address: intent.addresses[0],
            skip_as_source: false,
            preferred_lifetime: u32::MAX,
            valid_lifetime: u32::MAX,
        })),
        RowValue::WeakHost(WeakHostRow {
            send: true,
            receive: true,
        }),
    ]
}
/// Structural validation is pure and precedes journal/native effects. This
/// logical schema is NOT a Windows ABI: unsupported native fields must fail at
/// the future adapter boundary. No boot/epoch migration grants native trust.
pub(crate) fn validate_record_shape(record: &Record) -> Result<()> {
    validate_intent(&record.intent, &record.provenance)?;
    if record.version != VERSION || record.generation == 0 {
        return Err(CarrierError::Invalid);
    }
    match (record.proof, &record.rows) {
        (None, None)
            if matches!(
                record.phase,
                Phase::Prepared | Phase::Closing | Phase::Stopped
            ) =>
        {
            return Ok(())
        }
        (Some(proof), Some(rows)) if record.phase != Phase::Prepared => {
            if proof.index == 0
                || proof.luid == 0
                || proof.guid != carrier_key(&record.intent.scope)?.guid
                || rows[0].baseline != RowValue::Address(None)
                || !matches!(rows[1].baseline, RowValue::WeakHost(_))
            {
                return Err(CarrierError::Invalid);
            }
            let goal = desired_rows(&record.intent);
            let mut pending = 0;
            for (i, row) in rows.iter().enumerate() {
                if row.current != row.baseline && row.current != goal[i] {
                    return Err(CarrierError::Invalid);
                }
                if let Some(value) = &row.pending {
                    pending += 1;
                    if value == &row.current
                        || (value != &goal[i] && value != &row.baseline)
                        || (record.phase == Phase::Created && value != &goal[i])
                    {
                        return Err(CarrierError::Invalid);
                    }
                }
                if record.phase == Phase::Configured
                    && (row.current != goal[i] || row.pending.is_some())
                    || record.phase == Phase::Stopped
                        && (row.current != row.baseline || row.pending.is_some())
                {
                    return Err(CarrierError::Invalid);
                }
            }
            if pending > 1 {
                return Err(CarrierError::Invalid);
            }
        }
        _ => return Err(CarrierError::Invalid),
    }
    Ok(())
}
fn next(record: &Record) -> Result<Record> {
    let mut next = record.clone();
    next.generation = record
        .generation
        .checked_add(1)
        .ok_or(CarrierError::Invalid)?;
    Ok(next)
}
fn require_owned_rows(rows: &[RowState; 2], observed: &Observation) -> Result<()> {
    let actual = observed.rows.as_ref().ok_or(CarrierError::Conflict)?;
    if rows
        .iter()
        .enumerate()
        .any(|(i, row)| actual[i] != row.current && row.pending.as_ref() != Some(&actual[i]))
    {
        return Err(CarrierError::Conflict);
    }
    Ok(())
}

#[cfg(test)]
#[path = "member_carrier_tests.rs"]
mod tests;
