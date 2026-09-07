use super::{PreparedLease, PrivateError};
use nelomai_client_core::{RuntimeWriterGates, RuntimeWriterQuiescence};
use nelomai_client_storage::{RuntimeAuthScope, RuntimeRecordOwner, RuntimeStateStore};
use std::sync::{Arc, Mutex};
use tokio::time::{timeout_at, Instant};

/// Implemented by the sole record owner in the child. No parent record writer
/// and no access token are needed to validate/bind nonsecret provenance.
pub trait ScopeAdmission: Send + Sync {
    fn complete_logout(
        &self,
        _: &nelomai_client_storage::CompletedRuntimeLogoutV1,
        _: &RuntimeWriterQuiescence,
    ) -> Result<(), PrivateError> {
        Err(PrivateError::RecoveryRequired)
    }
    fn check_scope(&self, scope: &RuntimeAuthScope) -> Result<(), PrivateError>;
    fn bind_empty_scope(
        &self,
        scope: &RuntimeAuthScope,
        writers: &RuntimeWriterQuiescence,
    ) -> Result<(), PrivateError>;
    fn cleanup_snapshot(
        &self,
    ) -> Result<nelomai_client_storage::RuntimeCleanupSnapshotV1, PrivateError> {
        Err(PrivateError::RecoveryRequired)
    }
    fn cleanup_snapshot_for(
        &self,
        scope: Option<&RuntimeAuthScope>,
    ) -> Result<nelomai_client_storage::RuntimeCleanupSnapshotV1, PrivateError> {
        let snapshot = self.cleanup_snapshot()?;
        if snapshot.auth_scope.as_ref() != scope {
            return Err(PrivateError::RecoveryRequired);
        }
        Ok(snapshot)
    }
    fn complete_cleanup(
        &self,
        _snapshot: &nelomai_client_storage::RuntimeCleanupSnapshotV1,
        _scope: &RuntimeAuthScope,
        _writers: &RuntimeWriterQuiescence,
    ) -> Result<(), PrivateError> {
        Err(PrivateError::RecoveryRequired)
    }
}

/// Runtime-local owners for selected state and explicitly inherited cleanup
/// namespaces. Old operational state is never copied into selected state.
pub struct RuntimeRecordInventory<S> {
    target: Arc<RuntimeRecordOwner<S>>,
    retained: Vec<Arc<RuntimeRecordOwner<S>>>,
}
impl<S: RuntimeStateStore> RuntimeRecordInventory<S> {
    pub fn new(
        target: Arc<RuntimeRecordOwner<S>>,
        retained: Vec<Arc<RuntimeRecordOwner<S>>>,
    ) -> Self {
        Self { target, retained }
    }
}
impl<S: RuntimeStateStore> ScopeAdmission for RuntimeRecordInventory<S> {
    fn complete_logout(
        &self,
        receipt: &nelomai_client_storage::CompletedRuntimeLogoutV1,
        writers: &RuntimeWriterQuiescence,
    ) -> Result<(), PrivateError> {
        use crate::RuntimeAdmission;
        // Only the exact receipt source is eligible, never all old namespaces.
        let mut matches = Vec::new();
        for owner in self.retained.iter().chain([&self.target]) {
            let snapshot = owner
                .cleanup_snapshot()
                .map_err(|_| PrivateError::RecoveryRequired)?;
            if receipt.source.identity.as_ref().map_or_else(
                || Arc::ptr_eq(owner, &self.target),
                |identity| {
                    identity.slot == snapshot.slot
                        && identity.runtime_version == snapshot.runtime_version
                },
            ) {
                matches.push(owner);
            }
        }
        if matches.len() != 1 {
            return Err(PrivateError::RecoveryRequired);
        }
        crate::RuntimeCacheAdmission::new(matches[0].clone())
            .complete_logout(receipt, writers)
            .map_err(|_| PrivateError::RecoveryRequired)
    }
    fn check_scope(&self, scope: &RuntimeAuthScope) -> Result<(), PrivateError> {
        ScopeAdmission::check_scope(self.target.as_ref(), scope)
    }
    fn bind_empty_scope(
        &self,
        scope: &RuntimeAuthScope,
        writers: &RuntimeWriterQuiescence,
    ) -> Result<(), PrivateError> {
        ScopeAdmission::bind_empty_scope(self.target.as_ref(), scope, writers)
    }
    fn cleanup_snapshot(
        &self,
    ) -> Result<nelomai_client_storage::RuntimeCleanupSnapshotV1, PrivateError> {
        ScopeAdmission::cleanup_snapshot(self.target.as_ref())
    }
    fn cleanup_snapshot_for(
        &self,
        scope: Option<&RuntimeAuthScope>,
    ) -> Result<nelomai_client_storage::RuntimeCleanupSnapshotV1, PrivateError> {
        let mut matches = self
            .retained
            .iter()
            .chain([&self.target])
            .filter_map(|owner| {
                let snapshot = owner.cleanup_snapshot().ok()?;
                (snapshot.auth_scope.as_ref() == scope).then_some(snapshot)
            });
        let snapshot = matches.next().ok_or(PrivateError::RecoveryRequired)?;
        if matches.next().is_some() {
            return Err(PrivateError::RecoveryRequired);
        }
        Ok(snapshot)
    }
    fn complete_cleanup(
        &self,
        snapshot: &nelomai_client_storage::RuntimeCleanupSnapshotV1,
        scope: &RuntimeAuthScope,
        writers: &RuntimeWriterQuiescence,
    ) -> Result<(), PrivateError> {
        let target = self
            .target
            .cleanup_snapshot()
            .map_err(|_| PrivateError::RecoveryRequired)?;
        if target.slot != scope.identity.slot
            || target.runtime_version != scope.identity.runtime_version
        {
            return Err(PrivateError::Protocol);
        }
        let mut matching = self.retained.iter().chain([&self.target]).filter(|owner| {
            owner
                .cleanup_snapshot()
                .is_ok_and(|current| current == *snapshot)
        });
        let source = matching.next().ok_or(PrivateError::RecoveryRequired)?;
        if matching.next().is_some() {
            return Err(PrivateError::RecoveryRequired);
        }
        if Arc::ptr_eq(source, &self.target) {
            return ScopeAdmission::complete_cleanup(source.as_ref(), snapshot, scope, writers);
        }
        // Validate/enroll selected empty state before clearing the exact source.
        // Admission remains closed if either durable operation fails.
        self.target
            .complete_empty_cleanup_and_bind(scope)
            .map_err(|_| PrivateError::RecoveryRequired)?;
        source
            .complete_cleanup(snapshot)
            .map_err(|_| PrivateError::RecoveryRequired)
    }
}
impl<S: RuntimeStateStore> ScopeAdmission for RuntimeRecordOwner<S> {
    fn cleanup_snapshot(
        &self,
    ) -> Result<nelomai_client_storage::RuntimeCleanupSnapshotV1, PrivateError> {
        RuntimeRecordOwner::cleanup_snapshot(self).map_err(|_| PrivateError::RecoveryRequired)
    }
    fn complete_cleanup(
        &self,
        snapshot: &nelomai_client_storage::RuntimeCleanupSnapshotV1,
        scope: &RuntimeAuthScope,
        _: &RuntimeWriterQuiescence,
    ) -> Result<(), PrivateError> {
        if snapshot.slot != scope.identity.slot
            || snapshot.runtime_version != scope.identity.runtime_version
        {
            return Err(PrivateError::Protocol);
        }
        self.complete_cleanup_and_bind(snapshot, scope)
            .map_err(|_| PrivateError::RecoveryRequired)
    }
    fn check_scope(&self, scope: &RuntimeAuthScope) -> Result<(), PrivateError> {
        RuntimeRecordOwner::check_scope(self, scope).map_err(|_| PrivateError::RecoveryRequired)
    }
    fn bind_empty_scope(
        &self,
        scope: &RuntimeAuthScope,
        _: &RuntimeWriterQuiescence,
    ) -> Result<(), PrivateError> {
        if RuntimeRecordOwner::check_scope(self, scope).is_ok() {
            return Ok(());
        }
        RuntimeRecordOwner::bind_empty_scope(self, scope)
            .map_err(|_| PrivateError::RecoveryRequired)
    }
}

struct Held {
    lease: PreparedLease,
    deadline: Instant,
    writers: RuntimeWriterQuiescence,
    committed: Option<RuntimeAuthScope>,
}
#[derive(Default)]
struct State {
    cancel_generation: u64,
    last_request: u64,
    held: Option<Held>,
    admitted: Option<RuntimeAuthScope>,
    closed: bool,
}
impl State {
    fn revoke(&mut self) {
        self.admitted = None;
        self.held = None;
        match self.cancel_generation.checked_add(1) {
            Some(next) => self.cancel_generation = next,
            None => self.closed = true,
        }
    }
    fn expire(&mut self) {
        if self
            .held
            .as_ref()
            .is_some_and(|held| Instant::now() >= held.deadline)
        {
            self.revoke();
        }
    }
    fn held(&mut self, lease: &PreparedLease) -> Result<&mut Held, PrivateError> {
        self.expire();
        self.held
            .as_mut()
            .filter(|held| held.lease == *lease)
            .ok_or(PrivateError::Cancelled)
    }
}

/// Runtime-local admission latch. Task9 must use `check` at child start ingress
/// and wire the independent stop port to the actual CoreLocalStop.
pub struct ChildAdmission {
    incarnation: String,
    writers: Arc<RuntimeWriterGates>,
    record: Arc<dyn ScopeAdmission>,
    state: Mutex<State>,
    cancelled: tokio::sync::Notify,
}
impl ChildAdmission {
    pub(super) fn complete_logout(
        &self,
        lease: &PreparedLease,
        receipt: &nelomai_client_storage::CompletedRuntimeLogoutV1,
    ) -> Result<(), PrivateError> {
        let mut state = self.state.lock().map_err(|_| PrivateError::Closed)?;
        let held = state.held(lease)?;
        if held.committed.is_some() {
            return Err(PrivateError::Cancelled);
        }
        self.record.complete_logout(receipt, &held.writers)
    }
    pub fn new(
        incarnation: String,
        writers: Arc<RuntimeWriterGates>,
        record: Arc<dyn ScopeAdmission>,
    ) -> Self {
        Self {
            incarnation,
            writers,
            record,
            state: Mutex::new(State::default()),
            cancelled: tokio::sync::Notify::new(),
        }
    }
    pub async fn prepare(
        &self,
        request: u64,
        incarnation: &str,
        deadline: Instant,
    ) -> Result<PreparedLease, PrivateError> {
        let cancelled = self.cancelled.notified();
        tokio::pin!(cancelled);
        cancelled.as_mut().enable();
        let generation = {
            let mut state = self.state.lock().map_err(|_| PrivateError::Closed)?;
            state.expire();
            if state.closed
                || incarnation != self.incarnation
                || request <= state.last_request
                || state.held.is_some()
            {
                return Err(PrivateError::Cancelled);
            }
            state.last_request = request;
            state.admitted = None;
            state.cancel_generation
        };
        let writers = tokio::select! { biased;
            _ = &mut cancelled => return Err(PrivateError::Cancelled),
            result = timeout_at(deadline, self.writers.quiesce()) => result.map_err(|_| PrivateError::Timeout)?,
        };
        let mut state = self.state.lock().map_err(|_| PrivateError::Closed)?;
        if state.closed
            || generation != state.cancel_generation
            || request != state.last_request
            || Instant::now() >= deadline
        {
            return Err(PrivateError::Cancelled);
        }
        let lease = PreparedLease {
            incarnation: self.incarnation.clone(),
            request,
            cancel_generation: generation,
        };
        state.held = Some(Held {
            lease: lease.clone(),
            deadline,
            writers,
            committed: None,
        });
        Ok(lease)
    }
    pub fn commit(
        &self,
        lease: &PreparedLease,
        scope: &RuntimeAuthScope,
    ) -> Result<(), PrivateError> {
        scope.validate().map_err(|_| PrivateError::Protocol)?;
        let mut state = self.state.lock().map_err(|_| PrivateError::Closed)?;
        let held = state.held(lease)?;
        if held.committed.is_some() {
            return Err(PrivateError::Cancelled);
        }
        self.record.bind_empty_scope(scope, &held.writers)?;
        held.committed = Some(scope.clone());
        Ok(())
    }
    pub fn cleanup_snapshot_for(
        &self,
        lease: &PreparedLease,
        scope: Option<&RuntimeAuthScope>,
    ) -> Result<nelomai_client_storage::RuntimeCleanupSnapshotV1, PrivateError> {
        let mut state = self.state.lock().map_err(|_| PrivateError::Closed)?;
        state.held(lease)?;
        self.record.cleanup_snapshot_for(scope)
    }
    pub fn complete_cleanup(
        &self,
        lease: &PreparedLease,
        snapshot: &nelomai_client_storage::RuntimeCleanupSnapshotV1,
        scope: &RuntimeAuthScope,
    ) -> Result<(), PrivateError> {
        scope.validate().map_err(|_| PrivateError::Protocol)?;
        let mut state = self.state.lock().map_err(|_| PrivateError::Closed)?;
        let held = state.held(lease)?;
        if held.committed.is_some() {
            return Err(PrivateError::Cancelled);
        }
        self.record
            .complete_cleanup(snapshot, scope, &held.writers)?;
        held.committed = Some(scope.clone());
        Ok(())
    }
    /// Recovery admission checks existing provenance under the held writers;
    /// it cannot enroll an empty/unknown cache or open the admission latch.
    pub fn validate_held_scope(
        &self,
        lease: &PreparedLease,
        scope: &RuntimeAuthScope,
    ) -> Result<(), PrivateError> {
        let mut state = self.state.lock().map_err(|_| PrivateError::Closed)?;
        state.held(lease)?;
        self.record.check_scope(scope)
    }
    pub fn grant(
        &self,
        lease: &PreparedLease,
        scope: &RuntimeAuthScope,
    ) -> Result<(), PrivateError> {
        let mut state = self.state.lock().map_err(|_| PrivateError::Closed)?;
        if state.held(lease)?.committed.as_ref() != Some(scope) {
            return Err(PrivateError::Cancelled);
        }
        self.record.check_scope(scope)?;
        state.admitted = Some(scope.clone());
        state.held = None;
        Ok(())
    }
    pub fn check(&self, scope: &RuntimeAuthScope) -> Result<(), PrivateError> {
        let mut state = self.state.lock().map_err(|_| PrivateError::Closed)?;
        state.expire();
        if state.closed || state.admitted.as_ref() != Some(scope) {
            return Err(PrivateError::RecoveryRequired);
        }
        self.record.check_scope(scope)
    }
    pub fn abort(&self, lease: &PreparedLease) {
        if let Ok(mut state) = self.state.lock() {
            if state.held.as_ref().is_some_and(|held| held.lease == *lease) {
                state.revoke();
            }
        }
    }
    pub fn revoke(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.revoke();
        }
        self.cancelled.notify_waiters();
    }
    pub fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.revoke();
            state.closed = true;
        }
        self.cancelled.notify_waiters();
    }
    /// Called by the independent pump timer, including while no frames arrive.
    pub fn expire(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.expire();
        }
    }
}
