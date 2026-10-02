//! Original protected Session CAS acknowledgements: facts, never native grants.
//! This is a child of member_session so ONLY its protected writer can mint ACKs.
#![allow(dead_code)]
use super::{
    Backend, EngineIdentity, ProtectedSessionFiles, RecordKind, SessionFileIo, SessionFiles,
    SessionIdentity, SessionScope, SessionSnapshot,
};
use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, Weak,
    },
};

fn conflict() -> io::Error {
    io::Error::other("carrier_session_ack_conflict")
}
pub(crate) struct SessionBirthStamp {
    identity: SessionIdentity,
    epoch: u64,
}
impl SessionBirthStamp {
    pub(crate) fn scope(&self) -> &SessionScope {
        &self.identity.scope
    }
    pub(crate) fn network_epoch(&self) -> u64 {
        self.epoch
    }
    pub(crate) fn matches_context(
        &self,
        context: &crate::member_carrier_native_ownership::Context,
    ) -> bool {
        self.identity.scope == context.intent.scope
            && self.identity.boot_id == context.provenance.boot_id
            && self.identity.runtime == context.provenance.runtime
            && self.epoch == context.provenance.network_epoch
    }
}
#[derive(Clone, Copy)]
pub(crate) struct ExecutionEpoch(u64);
impl ExecutionEpoch {
    pub(crate) fn value(self) -> u64 {
        self.0
    }
}
struct AcknowledgedSession {
    sequence: usize,
    canonical: Vec<u8>,
    snapshot: SessionSnapshot,
}
#[derive(Clone)]
pub(crate) struct SessionWriteAck {
    original: Arc<AcknowledgedSession>,
}
impl SessionWriteAck {
    pub(crate) fn same_original(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.original, &other.original)
    }
    pub(crate) fn sequence(&self) -> usize {
        self.original.sequence
    }
}
pub(crate) struct SessionEpochFacts<'a> {
    pub birth: &'a SessionBirthStamp,
    pub execution: ExecutionEpoch,
    pub ack: &'a SessionWriteAck,
    pub session: &'a SessionSnapshot,
}
const MAX_ACKS: usize = 4096;
const MAX_HISTORY_BYTES: usize = 16 * 1024 * 1024;
pub(super) struct ClaimHistory {
    birth: SessionBirthStamp,
    acks: Mutex<Vec<SessionWriteAck>>,
    busy: AtomicBool,
    revoked: AtomicBool,
    tainted: AtomicBool,
    execution: Mutex<Option<Weak<ExecutionState>>>,
}
pub(super) struct HistoryFlight<'a> {
    history: &'a ClaimHistory,
    done: bool,
}
impl HistoryFlight<'_> {
    pub(super) fn finish(mut self) {
        self.done = true;
    }
}
impl Drop for HistoryFlight<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.history.revoke();
        }
        self.history.busy.store(false, Ordering::SeqCst);
    }
}
impl ClaimHistory {
    pub(super) fn new_authenticated_claim(identity: SessionIdentity, epoch: u64) -> Arc<Self> {
        Arc::new(Self {
            birth: SessionBirthStamp { identity, epoch },
            acks: Mutex::new(Vec::new()),
            busy: AtomicBool::new(false),
            revoked: AtomicBool::new(false),
            tainted: AtomicBool::new(false),
            execution: Mutex::new(None),
        })
    }
    pub(super) fn revoke(&self) {
        self.revoked.store(true, Ordering::SeqCst);
        self.tainted.store(true, Ordering::SeqCst);
    }
    fn enter(&self, forward: bool) -> io::Result<HistoryFlight<'_>> {
        if (forward && self.revoked.load(Ordering::SeqCst))
            || self
                .busy
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
        {
            self.revoke();
            return Err(conflict());
        }
        self.tainted.store(false, Ordering::SeqCst);
        Ok(HistoryFlight {
            history: self,
            done: false,
        })
    }
    pub(super) fn begin_write(&self, scope: &SessionScope) -> io::Result<HistoryFlight<'_>> {
        if self.birth.scope() != scope {
            self.revoke();
            return Err(conflict());
        }
        // Observation of legacy cleanup writes must not rearm revoked reads.
        self.enter(false)
    }
    fn require_forward(&self) -> io::Result<()> {
        if self.revoked.load(Ordering::SeqCst) || self.tainted.load(Ordering::SeqCst) {
            Err(conflict())
        } else {
            Ok(())
        }
    }
    fn latest(&self) -> io::Result<SessionWriteAck> {
        self.acks
            .try_lock()
            .map_err(|_| conflict())?
            .last()
            .cloned()
            .ok_or_else(conflict)
    }
    /// Separate current lifecycle ACK from the selected epoch anchor. Every
    /// item is from this claim's successful, continuous protected writer. A
    /// file snapshot can never fill a gap or cross an unselected epoch here.
    fn same_epoch_ack(&self, lease: &ExecutionLease) -> io::Result<SessionWriteAck> {
        let acks = self.acks.try_lock().map_err(|_| conflict())?;
        let index = lease.ack.sequence().checked_sub(1).ok_or_else(conflict)?;
        if acks
            .get(index)
            .is_none_or(|ack| !ack.same_original(&lease.ack))
        {
            return Err(conflict());
        }
        let epoch = lease.ack.original.snapshot.network_epoch;
        for ack in &acks[index..] {
            if ack.original.snapshot.network_epoch != epoch
                || ack.original.snapshot.scope != self.birth.identity.scope
            {
                return Err(conflict());
            }
        }
        acks.last().cloned().ok_or_else(conflict)
    }
    fn previous_epoch_ack(
        &self,
        lease: &ExecutionLease,
        next: &SessionWriteAck,
    ) -> io::Result<SessionWriteAck> {
        let acks = self.acks.try_lock().map_err(|_| conflict())?;
        let index = lease.ack.sequence().checked_sub(1).ok_or_else(conflict)?;
        if acks
            .get(index)
            .is_none_or(|ack| !ack.same_original(&lease.ack))
            || acks.last().is_none_or(|ack| !ack.same_original(next))
            || index >= acks.len().saturating_sub(1)
        {
            return Err(conflict());
        }
        let epoch = lease.ack.original.snapshot.network_epoch;
        for ack in &acks[index..acks.len() - 1] {
            if ack.original.snapshot.network_epoch != epoch
                || ack.original.snapshot.scope != self.birth.identity.scope
            {
                return Err(conflict());
            }
        }
        acks.get(acks.len() - 2).cloned().ok_or_else(conflict)
    }
    /// Only member_session's real private writer can invoke this mint. Called
    /// immediately AFTER successful CAS, BEFORE readback/transaction callbacks.
    pub(super) fn retain_success(
        &self,
        identity: &SessionIdentity,
        first: bool,
        before: Option<&[u8]>,
        canonical: &[u8],
        snapshot: &SessionSnapshot,
    ) {
        if self.revoked.load(Ordering::SeqCst) {
            return;
        }
        let Ok(mut acks) = self.acks.try_lock() else {
            self.revoke();
            return;
        };
        let continuous = match acks.last() {
            Some(last) => before == Some(last.original.canonical.as_slice()) && !first,
            None => {
                first
                    && snapshot.network_epoch == self.birth.epoch
                    && snapshot.phase
                        == nelomai_client_tunnel::redundancy::session::SessionPhase::Starting
            }
        };
        let bytes = acks.iter().try_fold(canonical.len(), |size, ack| {
            size.checked_add(ack.original.canonical.len())
        });
        if identity != &self.birth.identity
            || snapshot.scope != self.birth.identity.scope
            || !continuous
            || acks.len() >= MAX_ACKS
            || bytes.is_none_or(|n| n > MAX_HISTORY_BYTES)
        {
            self.revoke();
            return;
        }
        let sequence = acks.len() + 1;
        acks.push(SessionWriteAck {
            original: Arc::new(AcknowledgedSession {
                sequence,
                canonical: canonical.to_vec(),
                snapshot: snapshot.clone(),
            }),
        });
    }
    fn verify_ack(
        &self,
        files: &mut dyn super::PrivateRecords,
        ack: &SessionWriteAck,
    ) -> io::Result<()> {
        let (_, index) = super::load_index(files)?;
        super::require_active(&index, &self.birth.identity)?;
        let (raw, record) =
            super::load_record(files, &index, &self.birth.identity, RecordKind::Session)?;
        let record = record.ok_or_else(conflict)?;
        if raw.as_deref() != Some(ack.original.canonical.as_slice())
            || super::decode::<SessionSnapshot>(self.birth.scope(), record.data.as_bytes())?
                != ack.original.snapshot
        {
            return Err(conflict());
        }
        self.require_forward()
    }
    pub(super) fn verify_current(&self, files: &mut dyn super::PrivateRecords) -> io::Result<()> {
        self.verify_ack(files, &self.latest()?)
    }
}
pub(crate) struct SessionAckRoot<I> {
    files: ProtectedSessionFiles<I>,
    history: Arc<ClaimHistory>,
}
impl<I> Clone for SessionAckRoot<I> {
    fn clone(&self) -> Self {
        Self {
            files: self.files.clone(),
            history: self.history.clone(),
        }
    }
}
pub(crate) struct SessionAckRead<I> {
    backend: Weak<Mutex<Backend<I>>>,
    registration: Weak<Mutex<Option<Arc<ClaimHistory>>>>,
    history: Weak<ClaimHistory>,
    runtime: EngineIdentity,
    boot: [u8; 16],
    current_boot: [u8; 16],
}
pub(crate) struct ExecutionRoot<I> {
    origin: SessionAckRoot<I>,
    state: Arc<ExecutionState>,
}
pub(crate) struct ExecutionRead<I> {
    origin: SessionAckRead<I>,
    state: Weak<ExecutionState>,
}
pub(crate) struct BirthCleanupView<I> {
    files: ProtectedSessionFiles<I>,
}
impl<I> BirthCleanupView<I> {
    /// The actual bound frontend, not a reconstructed origin or ACK.
    pub(crate) fn files(&self) -> &ProtectedSessionFiles<I> {
        &self.files
    }
    pub(crate) fn into_files(self) -> ProtectedSessionFiles<I> {
        self.files
    }
}
pub(super) struct ExecutionState {
    context: crate::member_carrier_native_ownership::Context,
    history: Weak<ClaimHistory>,
    selected: Mutex<Option<Arc<ExecutionLease>>>,
    busy: AtomicBool,
    revoked: AtomicBool,
}
pub(crate) struct ExecutionLease {
    origin: Weak<ExecutionState>,
    ack: SessionWriteAck,
    stage: ExecutionStage,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ExecutionStage {
    Birth,
    Running,
    Rebinding,
}
pub(crate) struct ExecutionFacts {
    pub context: crate::member_carrier_native_ownership::Context,
    pub session: SessionSnapshot,
    pub execution: ExecutionEpoch,
    pub ack: SessionWriteAck,
}
impl<I: SessionFileIo> ExecutionRoot<I> {
    /// Explicit irreversible storage cleanup for authenticated Stop. This may
    /// precede the first Closing Pair CAS; actual Closing/Stopped ACKs remain
    /// mandatory in Main's independent SDK effect gates. No SDK grant here.
    pub(crate) fn native_cleanup_view(
        &self,
        files: &ProtectedSessionFiles<I>,
    ) -> io::Result<BirthCleanupView<I>> {
        if !self.origin.matches_origin(files) || files.cleanup_only {
            return Err(conflict());
        }
        self.state.require_origin_registered(&self.origin.history)?;
        // Close forward selection BEFORE any fallible cleanup/private read.
        self.state.revoke();
        let mut view = files.clone();
        view.native_execution = Some(Arc::downgrade(&self.state));
        view.native_cleanup = true;
        view.cleanup_only = true;
        view.retained_scope = Some(self.state.context.intent.scope.clone());
        view.native_carrier_access(&self.state.context.intent.scope)?;
        Ok(BirthCleanupView { files: view })
    }
    pub(crate) fn native_birth_cleanup_view(
        &self,
        files: &ProtectedSessionFiles<I>,
    ) -> io::Result<BirthCleanupView<I>> {
        self.native_cleanup_view(files)
    }
    pub(crate) fn downgrade(&self) -> ExecutionRead<I> {
        ExecutionRead {
            origin: self.origin.downgrade(),
            state: Arc::downgrade(&self.state),
        }
    }
    pub(crate) fn same_original(&self, other: &Self) -> bool {
        self.origin.same_original(&other.origin) && Arc::ptr_eq(&self.state, &other.state)
    }
    /// Original backend/frontend metadata and SAME current claim registration
    /// only. Recovery/foreign files deny; equal bytes grant nothing.
    pub(crate) fn matches_origin(&self, files: &ProtectedSessionFiles<I>) -> bool {
        self.origin.matches_origin(files)
    }
    /// Registered view identity only; no private-file or forward grant.
    pub(crate) fn matches_native_view(&self, files: &ProtectedSessionFiles<I>) -> bool {
        self.origin.files.same_original_backend(files)
            && Arc::ptr_eq(&self.origin.files.epoch_history, &files.epoch_history)
            && files.epoch_history.try_lock().is_ok_and(|slot| {
                slot.as_ref()
                    .is_some_and(|history| Arc::ptr_eq(history, &self.origin.history))
            })
            && files
                .native_execution
                .as_ref()
                .is_some_and(|weak| Weak::ptr_eq(weak, &Arc::downgrade(&self.state)))
            && files.cleanup_only == files.native_cleanup
            && files
                .retained_scope
                .as_ref()
                .is_none_or(|scope| *scope == self.state.context.intent.scope)
            && self
                .state
                .require_origin_registered(&self.origin.history)
                .is_ok()
    }
    pub(crate) fn matches_birth_context(
        &self,
        context: &crate::member_carrier_native_ownership::Context,
    ) -> bool {
        self.state.context == *context
    }
    /// Original selected handle, not proof that its ACK is still current.
    pub(crate) fn current_lease(&self) -> io::Result<Arc<ExecutionLease>> {
        self.origin.verify_registration()?;
        self.state.require_registered(&self.origin.history)?;
        self.state.selected()
    }
    /// One-time startup handoff. No native member/SDK readiness is inferred.
    pub(crate) fn select_running(
        &self,
        old: &Arc<ExecutionLease>,
        ack: &SessionWriteAck,
    ) -> io::Result<Arc<ExecutionLease>> {
        self.select(old, ack, ExecutionStage::Running, true)
    }
    pub(crate) fn renew_for_rebind(
        &self,
        old: &Arc<ExecutionLease>,
        ack: &SessionWriteAck,
    ) -> io::Result<Arc<ExecutionLease>> {
        self.select(old, ack, ExecutionStage::Rebinding, false)
    }
    /// STORAGE ONLY: Main must first retain its actual validated SDK proof.
    pub(crate) fn complete_rebind(
        &self,
        old: &Arc<ExecutionLease>,
        ack: &SessionWriteAck,
    ) -> io::Result<Arc<ExecutionLease>> {
        self.select(old, ack, ExecutionStage::Running, false)
    }
    fn select(
        &self,
        old: &Arc<ExecutionLease>,
        ack: &SessionWriteAck,
        stage: ExecutionStage,
        startup: bool,
    ) -> io::Result<Arc<ExecutionLease>> {
        use nelomai_client_tunnel::redundancy::session::SessionPhase;
        self.state.require_selected(old)?;
        let flight = self.state.enter()?;
        let selected = self.origin.inspect(|facts| {
            self.state.require_registered(&self.origin.history)?;
            if !facts.ack.same_original(ack) {
                return Err(conflict());
            }
            let previous = &old.ack.original.snapshot;
            let next = &ack.original.snapshot;
            if startup {
                if old.stage != ExecutionStage::Birth
                    || previous.phase != SessionPhase::Starting
                    || next.phase != SessionPhase::Running
                    || previous.network_epoch != next.network_epoch
                    || previous.scope != next.scope
                    || previous.active != next.active
                    || previous.role_generation != next.role_generation
                    || previous.membership_generation != next.membership_generation
                    || previous.role_confirmed != next.role_confirmed
                    || next.local_revision < previous.local_revision
                {
                    return Err(conflict());
                }
                let history = self
                    .origin
                    .history
                    .acks
                    .try_lock()
                    .map_err(|_| conflict())?;
                for item in history.iter().skip(old.ack.sequence()) {
                    let s = &item.original.snapshot;
                    if s.network_epoch != previous.network_epoch
                        || s.scope != previous.scope
                        || s.active != previous.active
                        || s.role_generation != previous.role_generation
                        || s.membership_generation != previous.membership_generation
                        || s.role_confirmed != previous.role_confirmed
                        || !matches!(s.phase, SessionPhase::Starting | SessionPhase::Running)
                    {
                        return Err(conflict());
                    }
                }
            } else {
                let preceding = self.origin.history.previous_epoch_ack(old, ack)?;
                let previous = &preceding.original.snapshot;
                if !matches!(
                    (old.stage, stage),
                    (ExecutionStage::Running, ExecutionStage::Rebinding)
                        | (ExecutionStage::Rebinding, ExecutionStage::Running)
                ) || previous.phase != SessionPhase::Running
                    || next.phase != SessionPhase::Running
                    || previous.network_epoch.checked_add(1) != Some(next.network_epoch)
                    || preceding.sequence().checked_add(1) != Some(ack.sequence())
                {
                    return Err(conflict());
                }
                let mut expected = previous.clone();
                expected.network_epoch = next.network_epoch;
                if expected != *next {
                    return Err(conflict());
                }
            }
            let lease = Arc::new(ExecutionLease {
                origin: Arc::downgrade(&self.state),
                ack: ack.clone(),
                stage,
            });
            // Publish SAME original selection BEFORE fallible outer postflight.
            *self.state.selected.try_lock().map_err(|_| conflict())? = Some(lease.clone());
            Ok(lease)
        })?;
        flight.finish();
        Ok(selected)
    }
    /// Detached storage facts; all private locks are released on return.
    pub(crate) fn verify_current(&self, lease: &Arc<ExecutionLease>) -> io::Result<ExecutionFacts> {
        self.state.require_selected(lease)?;
        let current_ack = self.origin.history.same_epoch_ack(lease)?;
        let flight = self.state.enter()?;
        let facts = self.origin.inspect(|facts| {
            self.state.require_registered(&self.origin.history)?;
            self.state.require_selected(lease)?;
            if !facts.ack.same_original(&current_ack) {
                return Err(conflict());
            }
            Ok(ExecutionFacts {
                context: self.state.context.clone(),
                session: facts.session.clone(),
                execution: facts.execution,
                ack: facts.ack.clone(),
            })
        })?;
        flight.finish();
        Ok(facts)
    }
    pub(super) fn view(
        &self,
        files: &ProtectedSessionFiles<I>,
    ) -> io::Result<ProtectedSessionFiles<I>> {
        if !self.origin.matches_origin(files)
            || files.native_execution.is_some()
            || files.cleanup_only
        {
            return Err(conflict());
        }
        let lease = self.current_lease()?;
        self.verify_current(&lease)?;
        let mut view = files.clone();
        view.native_execution = Some(Arc::downgrade(&self.state));
        Ok(view)
    }
}
impl<I: SessionFileIo> ExecutionRead<I> {
    pub(crate) fn same_original(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.state, &other.state)
            && Weak::ptr_eq(&self.origin.history, &other.origin.history)
            && Weak::ptr_eq(&self.origin.backend, &other.origin.backend)
    }
    pub(crate) fn upgrade(&self) -> io::Result<ExecutionRoot<I>> {
        let state = self.state.upgrade().ok_or_else(conflict)?;
        let origin = self.origin.upgrade()?;
        state.require_registered(&origin.history)?;
        Ok(ExecutionRoot { origin, state })
    }
    pub(crate) fn current_lease(&self) -> io::Result<Arc<ExecutionLease>> {
        self.upgrade()?.current_lease()
    }
    pub(crate) fn verify_current(&self, lease: &Arc<ExecutionLease>) -> io::Result<ExecutionFacts> {
        self.upgrade()?.verify_current(lease)
    }
}
struct ExecutionFlight {
    state: Arc<ExecutionState>,
    done: bool,
}
impl ExecutionFlight {
    fn finish(mut self) {
        self.done = true;
    }
}
impl Drop for ExecutionFlight {
    fn drop(&mut self) {
        if !self.done {
            self.state.revoke();
        }
        self.state.busy.store(false, Ordering::SeqCst);
    }
}
impl ExecutionState {
    fn revoke(&self) {
        self.revoked.store(true, Ordering::SeqCst);
        if let Some(history) = self.history.upgrade() {
            history.revoke();
        }
    }
    fn selected(&self) -> io::Result<Arc<ExecutionLease>> {
        if self.revoked.load(Ordering::SeqCst) {
            return Err(conflict());
        }
        self.selected
            .try_lock()
            .map_err(|_| conflict())?
            .clone()
            .ok_or_else(conflict)
    }
    fn require_selected(self: &Arc<Self>, lease: &Arc<ExecutionLease>) -> io::Result<()> {
        if !Weak::ptr_eq(&lease.origin, &Arc::downgrade(self))
            || !Arc::ptr_eq(&self.selected()?, lease)
        {
            return Err(conflict());
        }
        Ok(())
    }
    fn require_registered(self: &Arc<Self>, history: &Arc<ClaimHistory>) -> io::Result<()> {
        self.require_origin_registered(history)?;
        history.require_forward()?;
        if self.revoked.load(Ordering::SeqCst) {
            return Err(conflict());
        }
        Ok(())
    }
    fn require_origin_registered(self: &Arc<Self>, history: &Arc<ClaimHistory>) -> io::Result<()> {
        if !history.birth.matches_context(&self.context)
            || !Weak::ptr_eq(&self.history, &Arc::downgrade(history))
            || history
                .execution
                .try_lock()
                .map_err(|_| conflict())?
                .as_ref()
                .is_none_or(|weak| !Weak::ptr_eq(weak, &Arc::downgrade(self)))
        {
            return Err(conflict());
        }
        Ok(())
    }
    fn enter_cleanup(self: &Arc<Self>) -> io::Result<ExecutionFlight> {
        if self
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            self.revoke();
            return Err(conflict());
        }
        Ok(ExecutionFlight {
            state: self.clone(),
            done: false,
        })
    }
    fn enter(self: &Arc<Self>) -> io::Result<ExecutionFlight> {
        if self.revoked.load(Ordering::SeqCst)
            || self
                .busy
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
        {
            self.revoke();
            return Err(conflict());
        }
        Ok(ExecutionFlight {
            state: self.clone(),
            done: false,
        })
    }
}
/// A real protected storage transaction uses this retained original selection,
/// never a caller epoch or cached native/resource permission.
pub(super) struct ExecutionStorageFlight {
    flight: ExecutionFlight,
    history: Arc<ClaimHistory>,
    mode: StorageMode,
    done: bool,
}
enum StorageMode {
    Forward {
        lease: Arc<ExecutionLease>,
        current_ack: SessionWriteAck,
    },
    // Exact private Session bytes are comparison facts, NEVER an ACK or epoch
    // lease. None is retained explicitly; missing Session grants no native effect.
    Cleanup {
        session: Mutex<Option<Option<Vec<u8>>>>,
    },
}
impl ExecutionStorageFlight {
    pub(super) fn begin<I: SessionFileIo>(
        files: &ProtectedSessionFiles<I>,
        scope: &SessionScope,
    ) -> io::Result<Option<Self>> {
        let Some(weak) = files.native_execution.as_ref() else {
            return Ok(None);
        };
        let state = weak.upgrade().ok_or_else(conflict)?;
        let history = files
            .epoch_history
            .try_lock()
            .map_err(|_| conflict())?
            .clone()
            .ok_or_else(conflict)?;
        state.require_origin_registered(&history)?;
        if (files.cleanup_only != files.native_cleanup)
            || state.context.intent.scope != *scope
            || history.birth.identity != files.identity(scope)?
        {
            state.revoke();
            return Err(conflict());
        }
        let (mode, flight) = if files.native_cleanup {
            (
                StorageMode::Cleanup {
                    session: Mutex::new(None),
                },
                state.enter_cleanup()?,
            )
        } else {
            state.require_registered(&history)?;
            let lease = state.selected()?;
            // Only real same-epoch lifecycle ACKs may advance. No new epoch.
            let current_ack = history.same_epoch_ack(&lease)?;
            (StorageMode::Forward { lease, current_ack }, state.enter()?)
        };
        if history
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            history.revoke();
            return Err(conflict());
        }
        if files.native_cleanup {
            history.tainted.store(false, Ordering::SeqCst);
        }
        Ok(Some(Self {
            flight,
            history,
            mode,
            done: false,
        }))
    }
    pub(super) fn context(&self) -> &crate::member_carrier_native_ownership::Context {
        &self.flight.state.context
    }
    pub(super) fn verify(&self, files: &mut dyn super::PrivateRecords) -> io::Result<()> {
        match &self.mode {
            StorageMode::Forward { lease, current_ack } => {
                self.flight.state.require_registered(&self.history)?;
                self.flight.state.require_selected(lease)?;
                if !self
                    .history
                    .same_epoch_ack(lease)?
                    .same_original(current_ack)
                {
                    return Err(conflict());
                }
                self.history.verify_ack(files, current_ack)
            }
            StorageMode::Cleanup { session } => {
                self.flight.state.require_origin_registered(&self.history)?;
                if self.history.tainted.load(Ordering::SeqCst) {
                    return Err(conflict());
                }
                let (_, index) = super::load_index(files)?;
                super::require_active(&index, &self.history.birth.identity)?;
                let (raw, _) = super::load_record(
                    files,
                    &index,
                    &self.history.birth.identity,
                    RecordKind::Session,
                )?;
                let mut retained = session.try_lock().map_err(|_| conflict())?;
                if let Some(expected) = retained.as_ref() {
                    if *expected != raw {
                        return Err(conflict());
                    }
                } else {
                    *retained = Some(raw);
                }
                Ok(())
            }
        }
    }
    pub(super) fn verify_record(&self, kind: RecordKind, bytes: &[u8]) -> io::Result<()> {
        let context = self.context();
        let scope = &context.intent.scope;
        match kind {
            RecordKind::NativeCreator => {
                super::creator_payload(scope, bytes)?.require_context(context)?;
            }
            RecordKind::NativeCarrierReceipts => {
                if super::native_payload(scope, bytes)?.context != *context {
                    return Err(conflict());
                }
            }
            RecordKind::CarrierGuard => {
                if super::guard_payload(scope, bytes)?.context != *context {
                    return Err(conflict());
                }
            }
            RecordKind::Carrier => {
                let r = super::carrier_payload(scope, bytes)?;
                if r.intent != context.intent
                    || r.provenance != context.provenance
                    || r.proof.is_some_and(|p| p.guid != context.bindings[0].guid)
                {
                    return Err(conflict());
                }
            }
            RecordKind::Pair => {
                let r = super::carrier_pair_payload(scope, bytes)?.ok_or_else(conflict)?;
                // v2's original empty claim has not yet published logical
                // addresses. Only explicit cleanup may carry that exact
                // resource-free shape into Closing/Stopped; no absence grant.
                let empty_cleanup_claim = matches!(&self.mode, StorageMode::Cleanup { .. })
                    && matches!(
                        r.phase,
                        crate::member_carrier_pair::Phase::Closing
                            | crate::member_carrier_pair::Phase::Stopped
                    )
                    && r.addresses.is_empty()
                    && r.dns.is_empty()
                    && r.carrier.is_none()
                    && r.members.iter().all(Option::is_none)
                    && r.active.is_none()
                    && r.options.is_none()
                    && r.network.is_none()
                    && r.pending_guard.is_none()
                    && r.operation.is_none()
                    && r.guard
                        == crate::member_carrier_guard::Model::empty(scope.clone())
                            .map_err(|_| conflict())?;
                if r.provenance != context.provenance
                    || (r.addresses != context.intent.addresses
                        && !(r.phase == crate::member_carrier_pair::Phase::Fresh
                            && r.addresses.is_empty())
                        && !empty_cleanup_claim)
                    || r.carrier
                        .is_some_and(|p| p.guid != context.bindings[0].guid)
                {
                    return Err(conflict());
                }
                for (i, m) in r.members.iter().enumerate() {
                    if let Some(member) = m {
                        for proof in [member.owner.proof, member.owner.retired_proof]
                            .into_iter()
                            .flatten()
                        {
                            if proof.interface.guid != context.bindings[i + 1].guid {
                                return Err(conflict());
                            }
                        }
                    }
                }
                super::validate_guard_model(context, &r.guard)?;
                if let Some(plan) = &r.pending_guard {
                    for model in [&plan.expected, &plan.withdrawn, &plan.base, &plan.desired] {
                        super::validate_guard_model(context, model)?;
                    }
                }
            }
            RecordKind::CarrierRows | RecordKind::MemberARows | RecordKind::MemberBRows => {
                let r = super::rows_payload(kind, scope, bytes)?;
                let b = &r.binding;
                let index = match kind {
                    RecordKind::CarrierRows => 0,
                    RecordKind::MemberARows => 1,
                    _ => 2,
                };
                let expected = &context.bindings[index];
                if b.boot_id != context.provenance.boot_id
                    || b.runtime != context.provenance.runtime
                    || b.network_epoch != context.provenance.network_epoch
                    || b.guid != expected.guid
                    || b.name != expected.name
                    || context.intent.addresses.first().map(|a| a.addr())
                        != Some(std::net::IpAddr::V4(b.address.into()))
                {
                    return Err(conflict());
                }
            }
            RecordKind::Session | RecordKind::Network => return Err(conflict()),
        }
        Ok(())
    }
    pub(super) fn finish(mut self) {
        self.done = true;
        self.flight.done = true;
    }
}
impl Drop for ExecutionStorageFlight {
    fn drop(&mut self) {
        if !self.done {
            self.history.revoke();
        }
        self.history.busy.store(false, Ordering::SeqCst);
    }
}
impl<I: SessionFileIo> SessionAckRoot<I> {
    pub(crate) fn bind_native_birth(
        &self,
        context: &crate::member_carrier_native_ownership::Context,
        ack: &SessionWriteAck,
    ) -> io::Result<ExecutionRoot<I>> {
        if self
            .history
            .execution
            .try_lock()
            .map_err(|_| conflict())?
            .is_some()
        {
            return Err(conflict());
        }
        self.inspect(|facts| {
            use nelomai_client_tunnel::redundancy::session::SessionPhase;
            if !facts.ack.same_original(ack)
                || facts.session.phase != SessionPhase::Starting
                || facts.execution.value() != facts.birth.network_epoch()
                || facts.birth.network_epoch() != 1
                || !facts.birth.matches_context(context)
            {
                return Err(conflict());
            }
            super::validate_native_context(context)?;
            let state = Arc::new(ExecutionState {
                context: context.clone(),
                history: Arc::downgrade(&self.history),
                selected: Mutex::new(None),
                busy: AtomicBool::new(false),
                revoked: AtomicBool::new(false),
            });
            let lease = Arc::new(ExecutionLease {
                origin: Arc::downgrade(&state),
                ack: ack.clone(),
                stage: ExecutionStage::Birth,
            });
            *state.selected.try_lock().map_err(|_| conflict())? = Some(lease);
            let mut registration = self.history.execution.try_lock().map_err(|_| conflict())?;
            if registration.is_some() {
                return Err(conflict());
            }
            *registration = Some(Arc::downgrade(&state));
            Ok(ExecutionRoot {
                origin: self.clone(),
                state,
            })
        })
    }
    pub(super) fn from_original(
        files: &ProtectedSessionFiles<I>,
        scope: &SessionScope,
    ) -> io::Result<Self> {
        if files.cleanup_only {
            return Err(conflict());
        }
        let backend = files.backend_guard()?;
        let history = files
            .epoch_history
            .try_lock()
            .map_err(|_| conflict())?
            .clone()
            .ok_or_else(conflict)?;
        if backend.fresh.as_ref() != Some(scope)
            || history.birth.identity != files.identity(scope)?
        {
            history.revoke();
            return Err(conflict());
        }
        history.require_forward()?;
        Ok(Self {
            files: files.clone(),
            history,
        })
    }
    pub(crate) fn same_original(&self, other: &Self) -> bool {
        self.files.same_original_backend(&other.files) && Arc::ptr_eq(&self.history, &other.history)
    }
    pub(crate) fn matches_origin(&self, files: &ProtectedSessionFiles<I>) -> bool {
        !files.cleanup_only
            && self.files.same_original_backend(files)
            && Arc::ptr_eq(&self.files.epoch_history, &files.epoch_history)
            && files
                .epoch_history
                .try_lock()
                .is_ok_and(|slot| slot.as_ref().is_some_and(|h| Arc::ptr_eq(h, &self.history)))
    }
    pub(crate) fn downgrade(&self) -> SessionAckRead<I> {
        SessionAckRead {
            backend: Arc::downgrade(&self.files.backend),
            registration: Arc::downgrade(&self.files.epoch_history),
            history: Arc::downgrade(&self.history),
            runtime: self.files.runtime.clone(),
            boot: self.files.boot,
            current_boot: self.files.current_boot,
        }
    }
    pub(crate) fn acknowledgements(&self) -> io::Result<Vec<SessionWriteAck>> {
        Ok(self
            .history
            .acks
            .try_lock()
            .map_err(|_| conflict())?
            .clone())
    }
    fn verify_registration(&self) -> io::Result<()> {
        if !self.matches_origin(&self.files)
            || self
                .files
                .epoch_history
                .try_lock()
                .map_err(|_| conflict())?
                .as_ref()
                .is_none_or(|h| !Arc::ptr_eq(h, &self.history))
        {
            return Err(conflict());
        }
        self.history.require_forward()
    }
    /// Factual original Session bracket, not native authorization. The callback
    /// runs under the protected backend/private transaction: do not reenter
    /// Session or Runtime readers that themselves read Session. Independent
    /// opaque ACK-history retention does not require a backend borrow.
    pub(crate) fn inspect<T>(
        &self,
        callback: impl FnOnce(&SessionEpochFacts<'_>) -> io::Result<T>,
    ) -> io::Result<T> {
        let flight = self.history.enter(true)?;
        self.verify_registration()?;
        let mut backend = self.files.backend_guard()?;
        if backend.fresh.as_ref() != Some(self.history.birth.scope()) {
            return Err(conflict());
        }
        let ack = self.history.latest()?;
        let result = backend
            .io
            .transaction(|files| {
                self.history.verify_ack(files, &ack)?;
                let facts = SessionEpochFacts {
                    birth: &self.history.birth,
                    execution: ExecutionEpoch(ack.original.snapshot.network_epoch),
                    ack: &ack,
                    session: &ack.original.snapshot,
                };
                let result = callback(&facts)?;
                self.history.verify_ack(files, &ack)?;
                self.verify_registration()?;
                Ok(result)
            })
            .map_err(|_| conflict())?;
        // Second whole private boundary also covers an outer transaction
        // postflight callback. No current file snapshot ever mints an ACK.
        backend
            .io
            .transaction(|files| self.history.verify_ack(files, &ack))
            .map_err(|_| conflict())?;
        self.verify_registration()?;
        if backend.fresh.as_ref() != Some(self.history.birth.scope())
            || !self.history.latest()?.same_original(&ack)
        {
            return Err(conflict());
        }
        flight.finish();
        Ok(result)
    }
}
impl<I: SessionFileIo> SessionAckRead<I> {
    pub(crate) fn upgrade(&self) -> io::Result<SessionAckRoot<I>> {
        let history = self.history.upgrade().ok_or_else(conflict)?;
        let files = ProtectedSessionFiles {
            backend: self.backend.upgrade().ok_or_else(conflict)?,
            epoch_history: self.registration.upgrade().ok_or_else(conflict)?,
            native_execution: None,
            native_cleanup: false,
            runtime: self.runtime.clone(),
            boot: self.boot,
            current_boot: self.current_boot,
            cleanup_only: false,
            retained_scope: None,
        };
        if files
            .epoch_history
            .try_lock()
            .map_err(|_| conflict())?
            .as_ref()
            .is_none_or(|h| !Arc::ptr_eq(h, &history))
        {
            history.revoke();
            return Err(conflict());
        }
        let actual = SessionAckRoot::from_original(&files, history.birth.scope())?;
        if !Arc::ptr_eq(&actual.history, &history) {
            return Err(conflict());
        }
        Ok(actual)
    }
    pub(crate) fn inspect<T>(
        &self,
        callback: impl FnOnce(&SessionEpochFacts<'_>) -> io::Result<T>,
    ) -> io::Result<T> {
        self.upgrade()?.inspect(callback)
    }
}
#[cfg(windows)]
pub(crate) type NativeSessionAckRoot = SessionAckRoot<crate::windows::member_files::MemberFiles>;
#[cfg(windows)]
pub(crate) type NativeSessionAckRead = SessionAckRead<crate::windows::member_files::MemberFiles>;
#[cfg(windows)]
pub(crate) type NativeExecutionRoot = ExecutionRoot<crate::windows::member_files::MemberFiles>;
#[cfg(windows)]
pub(crate) type NativeExecutionRead = ExecutionRead<crate::windows::member_files::MemberFiles>;
pub(crate) type NativeExecutionLease = ExecutionLease;
pub(crate) type NativeExecutionFacts = ExecutionFacts;
#[cfg(windows)]
pub(crate) type NativeBirthCleanupView =
    BirthCleanupView<crate::windows::member_files::MemberFiles>;
#[cfg(test)]
#[path = "member_carrier_epoch_tests.rs"]
mod tests;
