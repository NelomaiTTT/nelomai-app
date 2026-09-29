//! Typed composition over the protected MemberFiles record boundary. No path is
//! accepted from IPC. The concrete adapter uses audited MemberFiles handles,
//! without falling back to std::fs reads/writes or native identity adoption.
#![cfg_attr(not(windows), allow(dead_code))] // Portable fake tests have no native caller.
#[cfg(windows)]
use super::member_files::{previous_config_valid, PrivateFile, PrivateRecords, SessionFileIo};
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum RecordKind {
    Session,
    Pair,
    Network,
}
/// All calls run under the existing serialized engine owner. The implementation
/// authenticates runtime, private root/ancestors/handles and envelope scope;
/// bounds individual reads (no enumeration), rejects reparse/hardlinks and flushes CAS.
/// Scope claim is durable and exclusive; an old scope is never reusable.
pub(crate) trait SessionFiles: Clone {
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
    /// Caller must first verify native cleanup. The adapter also requires the
    /// durable stopped/empty records before releasing the exclusive claim.
    fn complete(&mut self, _scope: &SessionScope) -> io::Result<()> {
        Err(failed())
    }
    /// Explicit crash-gap recovery only. BEFORE calling, the trusted factory
    /// must verify slot owner journals and native absence/no effects for this
    /// claim. Missing pair data alone is not that proof. Never called by read.
    fn complete_empty(&mut self, _scope: &SessionScope) -> io::Result<()> {
        Err(failed())
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
    // Only identities still represented by Session/Pair/Network residual files.
    // Never the replay authority. Partial overwrites can leave three owners.
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
    runtime: EngineIdentity,
    boot: [u8; 16],
    // Unlike the retained identity boot, this never changes in cleanup views.
    current_boot: [u8; 16],
    cleanup_only: bool,
    retained_scope: Option<SessionScope>,
}
#[cfg(windows)]
pub(crate) type NativeSessionFiles = ProtectedSessionFiles<super::member_files::MemberFiles>;
impl<I> Clone for ProtectedSessionFiles<I> {
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
            runtime: self.runtime.clone(),
            boot: self.boot,
            current_boot: self.current_boot,
            cleanup_only: self.cleanup_only,
            retained_scope: self.retained_scope.clone(),
        }
    }
}
impl<I: SessionFileIo> ProtectedSessionFiles<I> {
    pub(crate) fn new(io: I, runtime: EngineIdentity, boot: [u8; 16]) -> io::Result<Self> {
        if boot == [0; 16] || !valid_runtime(&runtime) {
            return Err(failed());
        }
        Ok(Self {
            backend: std::sync::Arc::new(std::sync::Mutex::new(Backend { io, fresh: None })),
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
    fn completed_in_previous_boot(&mut self, scope: &SessionScope) -> io::Result<bool> {
        if !scope.validate() {
            return Err(failed());
        }
        let mut backend = self.backend.lock().map_err(|_| failed())?;
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
        let mut backend = self.backend.lock().map_err(|_| failed())?;
        let identity = backend
            .io
            .transaction(|files| {
                let (_, index) = load_index(files)?;
                match index.active.as_ref() {
                    Some(id) if id.runtime.slot == runtime => {
                        if self.cleanup_only && self.identity(&id.scope)? != *id {
                            return Err(failed());
                        }
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
        let mut backend = self.backend.lock().map_err(|_| failed())?;
        backend
            .io
            .transaction(|files| {
                let (_, index) = load_index(files)?;
                match &index.active {
                    Some(id) if self.identity(&id.scope).as_ref().is_ok_and(|own| own == id) => {
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
        if self.cleanup_only {
            return Err(failed());
        }
        let identity = self.identity(scope)?;
        let mut backend = self.backend.lock().map_err(|_| failed())?;
        backend
            .io
            .transaction(|files| {
                let (bytes, mut index) = load_index(files)?;
                if index.active.is_some() || read_completed(files, scope)?.is_some() {
                    return Err(failed());
                }
                // Orphan/foreign records cannot become an empty new session merely
                // because an index was removed. Only completed identities may remain.
                require_retired_records(files, &index)?;
                index.active = Some(identity);
                save_index(files, bytes.as_deref(), &index)
            })
            .map_err(|_| failed())?;
        backend.fresh = Some(scope.clone());
        Ok(())
    }
    fn read(&mut self, scope: &SessionScope, kind: RecordKind) -> io::Result<Option<Vec<u8>>> {
        let identity = self.identity(scope)?;
        let mut backend = self.backend.lock().map_err(|_| failed())?;
        backend
            .io
            .transaction(|files| {
                let (_, index) = load_index(files)?;
                require_active(&index, &identity)?;
                let (_, record) = load_record(files, &index, &identity, kind)?;
                if let Some(record) = &record {
                    if kind != RecordKind::Session
                        && record.network_epoch > current_epoch(files, &index, &identity)?
                    {
                        return Err(failed());
                    }
                }
                Ok(record.map(|r| r.data.into_bytes()))
            })
            .map_err(|_| failed())
    }
    fn compare_exchange(
        &mut self,
        scope: &SessionScope,
        kind: RecordKind,
        expected: Option<&[u8]>,
        desired: &[u8],
    ) -> io::Result<()> {
        let identity = self.identity(scope)?;
        validate_payload(scope, kind, desired)?;
        let mut backend = self.backend.lock().map_err(|_| failed())?;
        let fresh = !self.cleanup_only && backend.fresh.as_ref() == Some(scope);
        let result = backend
            .io
            .transaction(|files| {
                let (_, index) = load_index(files)?;
                require_active(&index, &identity)?;
                let (raw, current) = load_record(files, &index, &identity, kind)?;
                if current.as_ref().map(|r| r.data.as_bytes()) != expected {
                    return Err(failed());
                }
                if self.cleanup_only && kind == RecordKind::Pair {
                    let next: PairRecord = decode(scope, desired)?;
                    let old = current
                        .as_ref()
                        .map(|r| decode::<PairRecord>(scope, r.data.as_bytes()))
                        .transpose()?;
                    validate_cleanup_pair(old.as_ref(), &next)?;
                }
                let epoch = if kind == RecordKind::Session {
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
                files.compare_exchange(kind.file(), raw.as_deref(), &bytes)
            })
            .map_err(|_| failed());
        if result.is_err() {
            backend.fresh = None;
        }
        result
    }
    fn complete(&mut self, scope: &SessionScope) -> io::Result<()> {
        let identity = self.identity(scope)?;
        let mut backend = self.backend.lock().map_err(|_| failed())?;
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
                let pair: PairRecord =
                    decode(scope, pair.as_ref().ok_or_else(failed)?.data.as_bytes())?;
                if pair.active.is_some()
                    || pair.closing
                    || pair.members.iter().any(Option::is_some)
                    || pair.dns.iter().any(Option::is_some)
                    || pair.pending_guard.is_some()
                    || pair.guard
                        != crate::member_guard::Model::empty(scope.clone()).map_err(|_| failed())?
                {
                    return Err(failed());
                }
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
                finish_completion(files, raw.as_deref(), &mut index, &identity)
            })
            .map_err(|_| failed())?;
        backend.fresh = None;
        Ok(())
    }
    fn complete_empty(&mut self, scope: &SessionScope) -> io::Result<()> {
        let identity = self.identity(scope)?;
        let mut backend = self.backend.lock().map_err(|_| failed())?;
        backend.fresh = None;
        backend
            .io
            .transaction(|files| {
                let (raw, mut index) = load_index(files)?;
                if already_completed(files, &index, &identity)? {
                    return Ok(());
                }
                require_active(&index, &identity)?;
                for kind in [RecordKind::Session, RecordKind::Pair, RecordKind::Network] {
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
impl RecordKind {
    fn file(self) -> PrivateFile {
        match self {
            Self::Session => PrivateFile::Session,
            Self::Pair => PrivateFile::Pair,
            Self::Network => PrivateFile::Network,
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
        || index.completed.len() > 3
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
    let file = completed_file(scope)?;
    let Some(bytes) = files.read(file)? else {
        return Ok(None);
    };
    if bytes.len() > file.limit() {
        return Err(failed());
    }
    let saved: CompletedRecord = serde_json::from_slice(&bytes).map_err(|_| failed())?;
    if saved.version != PRIVATE_VERSION
        || !valid_identity(&saved.identity)
        || saved.identity.scope != *scope
    {
        return Err(failed());
    }
    Ok(Some(saved.identity))
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
    files.compare_exchange(file, None, &bytes)
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
    for kind in [RecordKind::Session, RecordKind::Pair, RecordKind::Network] {
        if let Some(raw) = files.read(kind.file())? {
            let saved = parse_record(kind, &raw)?;
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
    files.compare_exchange(PrivateFile::Index, expected, &bytes)
}
fn require_active(index: &SessionIndex, identity: &SessionIdentity) -> io::Result<()> {
    if index.active.as_ref() != Some(identity) {
        Err(failed())
    } else {
        Ok(())
    }
}
fn require_retired_records(files: &mut dyn PrivateRecords, index: &SessionIndex) -> io::Result<()> {
    for kind in [RecordKind::Session, RecordKind::Pair, RecordKind::Network] {
        if let Some(raw) = files.read(kind.file())? {
            let old = parse_record(kind, &raw)?;
            if !index.completed.contains(&old.identity) {
                return Err(failed());
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
    if kind == RecordKind::Session
        && decode::<SessionSnapshot>(&record.identity.scope, record.data.as_bytes())?.network_epoch
            != record.network_epoch
    {
        return Err(failed());
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
        Some(r) if index.completed.contains(&r.identity) => None,
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
pub(crate) type WindowsSessionStore<F> = ProtectedStore<F, SessionSnapshot>;
pub(crate) type WindowsPairStore<F> = ProtectedStore<F, PairRecord>;
pub(crate) type WindowsNetworkStore<F> = ProtectedStore<F, NetworkJournal>;
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
            for kind in [RecordKind::Session, RecordKind::Pair, RecordKind::Network] {
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
