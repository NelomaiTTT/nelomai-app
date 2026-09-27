//! Serialized command owner for one authenticated runtime's native pair.
//! Preparing a pair must have no native effects. Keep this owner after failed
//! Start/commands so scoped Stop can retry cleanup independently of the server.

use crate::{
    redundancy::{
        driver::{NativePair, SessionDriver, SessionStore, TickResult},
        protocol::{uuid, Command, Member, Snapshot},
        session::{SessionPhase, SessionSnapshot, SessionState},
        SessionScope, Slot,
    },
    DesktopTunnelOptions, TunnelMetrics,
};
use nelomai_contracts::{
    RedundantRoleAction, RedundantSessionState, RedundantSessionView, RuntimeSlot,
};
use std::io;

pub trait PairControl: NativePair {
    /// Read-only native diagnostics. Never open a probe or fall back to an
    /// unowned/legacy backend. Platforms without a provider stay unsupported.
    fn metrics(&self, _slot: Slot) -> io::Result<TunnelMetrics> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn physical_network_fingerprint(&self) -> io::Result<String> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn start_primary(
        &mut self,
        scope: &SessionScope,
        member: &Member,
        options: &DesktopTunnelOptions,
    ) -> io::Result<()>;
    fn attach(&mut self, scope: &SessionScope, member: &Member) -> io::Result<()>;
    /// Remove only this inactive member, including partial failed-start state.
    fn remove_standby(&mut self, scope: &SessionScope, slot: Slot) -> io::Result<()>;
    /// True only after the physical network and both members were validated.
    fn rebind_pair(&mut self, scope: &SessionScope) -> io::Result<bool>;
    fn cleanup_pending(&self) -> bool;
}

pub struct SessionControl<N: PairControl, S> {
    driver: SessionDriver<N, S>,
    runtime: RuntimeSlot,
    leases: [Option<String>; 2],
    current_leases: [Option<String>; 2],
    warm_stop_v1: bool,
    primary_ready: bool,
    standby_ready: bool,
    standby_failed: bool,
    stalled: bool,
}

impl<N: PairControl, S: SessionStore> SessionControl<N, S> {
    /// A failed read-only physical discovery is not proof that the old network
    /// still exists. Suspend health and cancel old queries without native rebind
    /// or shutdown. The next validated discovery may retry NetworkChanged.
    pub fn invalidate_network(&mut self, scope: &SessionScope, now: u64) -> io::Result<()> {
        let state = self.driver.state().snapshot();
        if state.scope != *scope || state.phase != SessionPhase::Running {
            return Err(fenced());
        }
        self.clear_readiness();
        let result = self.driver.network_changed(scope, now, false);
        if result.is_err() {
            self.latch_terminal_failure(state.phase);
        }
        result
    }

    pub fn network_validated(&self) -> bool {
        self.driver.network_validated()
    }

    pub fn metrics(&self) -> io::Result<TunnelMetrics> {
        let state = self.driver.state().snapshot();
        if state.phase != SessionPhase::Running || !state.installed[state.active.index()] {
            return Err(io::Error::other("redundant_diagnostics_not_running"));
        }
        self.driver.native().metrics(state.active)
    }

    pub fn physical_network_fingerprint(&self) -> io::Result<String> {
        let state = self.driver.state().snapshot();
        if state.phase != SessionPhase::Running || !state.installed[state.active.index()] {
            return Err(io::Error::other("redundant_diagnostics_not_running"));
        }
        self.driver.native().physical_network_fingerprint()
    }

    pub fn new(
        runtime: RuntimeSlot,
        state: SessionState,
        leases: [Option<String>; 2],
        warm_stop_v1: bool,
        native: N,
        store: S,
        now: u64,
    ) -> io::Result<Self> {
        let snapshot = state.snapshot();
        if !snapshot.scope.validate()
            || snapshot.scope.runtime != runtime
            || snapshot.phase != SessionPhase::Starting
            || snapshot.installed != [false; 2]
            || snapshot.committed != [false; 2]
            || leases[index(snapshot.active)]
                .as_deref()
                .is_none_or(|id| !uuid(id))
            || leases[index(snapshot.active.other())].is_some()
        {
            return Err(fenced());
        }
        Ok(Self {
            driver: SessionDriver::new(state, native, store, now)?,
            runtime,
            current_leases: leases.clone(),
            leases,
            warm_stop_v1,
            primary_ready: false,
            standby_ready: false,
            standby_failed: false,
            stalled: false,
        })
    }
    /// Validate the authenticated runtime and Start, then durably seal Starting.
    /// Install the returned owner in the actor BEFORE calling start_primary.
    pub fn prepare(
        runtime: RuntimeSlot,
        start: &Command,
        native: N,
        store: S,
        now: u64,
    ) -> io::Result<Self> {
        start.validate(runtime)?;
        let Command::Start {
            scope,
            primary,
            role_generation,
            membership_generation,
            warm_stop_v1,
            ..
        } = start
        else {
            return Err(fenced());
        };
        let state = SessionState::new(
            scope.clone(),
            primary.slot,
            *role_generation,
            *membership_generation,
        )
        .map_err(|_| fenced())?;
        let mut leases = [None, None];
        leases[index(primary.slot)] = Some(primary.lease_id.clone());
        Self::new(runtime, state, leases, *warm_stop_v1, native, store, now)
    }

    pub fn start_primary(
        &mut self,
        member: &Member,
        options: &DesktopTunnelOptions,
    ) -> io::Result<Snapshot> {
        member.validate()?;
        options.validate().map_err(|_| fenced())?;
        let state = self.driver.state().snapshot();
        if state.phase != SessionPhase::Starting
            || member.slot != state.active
            || self.leases[index(member.slot)].as_deref() != Some(member.lease_id.as_str())
        {
            return Err(fenced());
        }
        self.clear_readiness();
        self.driver.start_primary(&state.scope, |native| {
            native.start_primary(&state.scope, member, options)
        })?;
        Ok(self.snapshot())
    }

    pub fn execute(&mut self, command: Command, now: u64) -> io::Result<Snapshot> {
        command.validate(self.runtime)?;
        let state = self.driver.state().snapshot();
        if command.scope() != &state.scope {
            return Err(fenced());
        }
        let automatic = !matches!(
            &command,
            Command::Start { .. }
                | Command::Status { .. }
                | Command::Stop { .. }
                | Command::PrepareStop { .. }
        );
        let prior_phase = state.phase;
        let result = self.execute_scoped(command, now, state);
        if automatic && result.is_err() {
            self.latch_terminal_failure(prior_phase);
        }
        result
    }

    fn execute_scoped(
        &mut self,
        command: Command,
        now: u64,
        state: SessionSnapshot,
    ) -> io::Result<Snapshot> {
        match command {
            Command::Start { .. } => return Err(fenced()),
            Command::Status { .. } => (),
            Command::PrepareStop { scope } => {
                self.clear_readiness();
                self.driver.prepare_stop(&scope, now)?;
            }
            Command::PrepareRecoveryStop {
                scope,
                expected_revision,
                expected_network_epoch,
            } => {
                if state.local_revision != expected_revision
                    || state.network_epoch != expected_network_epoch
                    || !self.stalled
                {
                    return Err(fenced());
                }
                match state.phase {
                    SessionPhase::Running => {
                        if self.primary_ready || !self.driver.recovery_stop_eligible(now) {
                            return Err(fenced());
                        }
                        self.clear_readiness();
                        self.driver.prepare_stop(&scope, now)?;
                    }
                    // Exact retry after a lost app journal write. This only
                    // returns the frozen observation for cold cleanup; no new
                    // native work, save, revision, deadline or retaining intent.
                    SessionPhase::Stopping | SessionPhase::Stopped => (),
                    SessionPhase::Starting => return Err(fenced()),
                }
            }
            Command::Stop { scope } => {
                self.clear_readiness();
                self.driver.stop(&scope)?;
            }
            Command::Attach {
                scope,
                member,
                expected_revision,
                expected_network_epoch,
                expected_membership_generation,
                membership_generation,
            } => {
                check_fence(&state, expected_revision, expected_network_epoch)?;
                if expected_membership_generation != state.membership_generation {
                    return Err(fenced());
                }
                self.install(&scope, &member, Some(membership_generation), now)?;
            }
            Command::StageCandidate {
                scope,
                member,
                expected_revision,
                expected_network_epoch,
                expected_membership_generation,
            } => {
                check_fence(&state, expected_revision, expected_network_epoch)?;
                if expected_membership_generation != state.membership_generation {
                    return Err(fenced());
                }
                self.install(&scope, &member, None, now)?;
            }
            Command::RetireInactive {
                scope,
                slot,
                lease_id,
                expected_revision,
                expected_network_epoch,
                expected_membership_generation,
            } => {
                check_fence(&state, expected_revision, expected_network_epoch)?;
                if !state.committed[index(slot)]
                    || self.current_leases[index(slot)].as_deref() != Some(lease_id.as_str())
                    || self.leases[index(slot)].as_deref() != Some(lease_id.as_str())
                {
                    return Err(fenced());
                }
                self.standby_ready = false;
                self.standby_failed = false;
                if let Err(error) = self.driver.retire_inactive(
                    &scope,
                    slot,
                    expected_revision,
                    expected_network_epoch,
                    expected_membership_generation,
                    now,
                    |native| native.remove_standby(&scope, slot),
                ) {
                    self.clear_readiness();
                    return Err(error);
                }
                self.leases[index(slot)] = None;
                // Keep CURRENT identity for panel role/replacement/Stop fences.
            }
            Command::RemoveStandby {
                scope,
                slot,
                lease_id,
                expected_revision,
                expected_network_epoch,
                expected_membership_generation,
            } => {
                check_fence(&state, expected_revision, expected_network_epoch)?;
                if slot == state.active
                    || !state.installed[index(slot)]
                    || state.committed[index(slot)]
                    || expected_membership_generation != state.membership_generation
                    || self.leases[index(slot)].as_deref() != Some(lease_id.as_str())
                {
                    return Err(fenced());
                }
                self.standby_ready = false;
                if let Err(error) = self.driver.remove_candidate(
                    &scope,
                    slot,
                    expected_revision,
                    expected_network_epoch,
                    expected_membership_generation,
                    now,
                    |native| native.remove_standby(&scope, slot),
                ) {
                    self.clear_readiness();
                    return Err(error);
                }
                // Until targeted native cleanup succeeds, the lease remains
                // known even if the driver had to fence and stop the whole pair.
                self.leases[index(slot)] = None;
            }
            Command::CommitCandidate {
                scope,
                slot,
                expected_revision,
                expected_network_epoch,
                session,
            } => {
                check_fence(&state, expected_revision, expected_network_epoch)?;
                let reused = self.current_leases[index(slot)].is_some()
                    && self.current_leases[index(slot)] == self.leases[index(slot)];
                let expected_membership = if reused {
                    Some(state.membership_generation)
                } else {
                    state.membership_generation.checked_add(1)
                };
                if slot == state.active
                    || !state.installed[index(slot)]
                    || state.committed[index(slot)]
                    || session.role_generation != state.role_generation
                    || expected_membership != Some(session.membership_generation)
                {
                    return Err(fenced());
                }
                self.validate_view(&state, &session, true)?;
                // Record a canonical server receipt even if health deteriorated
                // after the commit RPC. Re-sample so stale readiness can never
                // authorize promotion; membership and usability are separate.
                self.tick(now)?;
                if reused {
                    self.driver.recommit_current(
                        &scope,
                        slot,
                        expected_revision,
                        expected_network_epoch,
                        state.membership_generation,
                    )?;
                } else {
                    self.driver.commit_candidate(
                        &scope,
                        slot,
                        expected_revision,
                        expected_network_epoch,
                        state.membership_generation,
                        session.membership_generation,
                    )?;
                }
                self.current_leases = [session.slot_a_lease_id, session.slot_b_lease_id];
                if self.primary_ready || self.standby_ready {
                    self.stalled = false;
                }
            }
            Command::ConfirmRole {
                expected_revision,
                expected_network_epoch,
                response,
                ..
            } => {
                check_fence(&state, expected_revision, expected_network_epoch)?;
                if Some(response.local_active_lease_id.as_str())
                    != self.leases[index(state.active)].as_deref()
                    || response.session.membership_generation != state.membership_generation
                {
                    return Err(fenced());
                }
                if response.action == RedundantRoleAction::Rebase {
                    let other = self.current_leases[index(state.active.other())]
                        .as_deref()
                        .ok_or_else(fenced)?;
                    if state.role_confirmed
                        || Some(other) == self.leases[index(state.active)].as_deref()
                        || state.role_generation.checked_add(1)
                            != Some(response.session.role_generation)
                    {
                        return Err(fenced());
                    }
                    self.validate_view_for_active(&state, &response.session, false, Some(other))?;
                    let update = self.driver.state().role_update().ok_or_else(fenced)?;
                    if let Err(error) = self
                        .driver
                        .observe_role_rebase(&update, response.session.role_generation)
                    {
                        self.clear_readiness();
                        return Err(error);
                    }
                } else {
                    self.validate_view(&state, &response.session, false)?;
                    if state.role_confirmed {
                        if response.session.role_generation != state.role_generation {
                            return Err(fenced());
                        }
                    } else {
                        let update = self.driver.state().role_update().ok_or_else(fenced)?;
                        let same_ack = response.action == RedundantRoleAction::Acknowledged
                            && response.session.role_generation == state.role_generation;
                        if !same_ack
                            && state.role_generation.checked_add(1)
                                != Some(response.session.role_generation)
                        {
                            return Err(fenced());
                        }
                        if let Err(error) = self.driver.confirm_role_response(
                            &update,
                            response.session.role_generation,
                            response.action,
                        ) {
                            self.clear_readiness();
                            return Err(error);
                        }
                    }
                }
            }
            Command::NetworkChanged { scope } => {
                self.clear_readiness();
                // Cancel old probes and persist the new epoch BEFORE native
                // rebind. Errors or an unvalidated result leave ticks suspended.
                self.driver.network_changed(&scope, now, false)?;
                if self.driver.native_mut().rebind_pair(&scope)? {
                    self.driver.network_changed(&scope, now, true)?;
                    self.stalled = false;
                }
            }
        }
        Ok(self.snapshot())
    }

    pub fn tick(&mut self, now: u64) -> io::Result<TickResult> {
        let prior_phase = self.driver.state().snapshot().phase;
        match self.driver.tick(now) {
            Ok(result) => {
                self.primary_ready = result.primary_ready;
                self.standby_ready = result.standby_ready;
                self.standby_failed = result.standby_failed;
                if result.primary_ready || result.switched.is_some() {
                    self.stalled = false;
                } else if result.stalled {
                    self.stalled = true;
                }
                Ok(result)
            }
            Err(error) => {
                self.clear_readiness();
                self.latch_terminal_failure(prior_phase);
                Err(error)
            }
        }
    }

    /// A native/journal failure can close a previously live pair before health
    /// emits Stalled. Preserve that cleanup signal, not arbitrary error strings.
    /// Callers exclude explicit user Stop/PrepareStop; a startup failure and an
    /// error that leaves Running do not create automatic restart authority.
    fn latch_terminal_failure(&mut self, prior_phase: SessionPhase) {
        if prior_phase == SessionPhase::Running
            && matches!(
                self.driver.state().snapshot().phase,
                SessionPhase::Stopping | SessionPhase::Stopped
            )
        {
            self.clear_readiness();
            self.stalled = true;
        }
    }

    pub fn snapshot(&mut self) -> Snapshot {
        let session = self.driver.state().snapshot();
        let running = session.phase == SessionPhase::Running;
        let cleanup_pending =
            session.phase == SessionPhase::Stopping || self.driver.native_mut().cleanup_pending();
        Snapshot {
            session,
            leases: self.leases.clone(),
            current_leases: self.current_leases.clone(),
            standby_failed: running && self.standby_failed,
            stalled: self.stalled,
            primary_ready: running && self.primary_ready,
            standby_ready: running && self.standby_ready,
            cleanup_pending,
            warm_stop_v1: self.warm_stop_v1,
        }
    }

    pub fn warm_slot(&self) -> Option<Slot> {
        if self.warm_stop_v1 {
            self.driver.state().warm_slot()
        } else {
            None
        }
    }

    fn install(
        &mut self,
        scope: &SessionScope,
        member: &Member,
        membership: Option<u64>,
        now: u64,
    ) -> io::Result<()> {
        if self.leases[index(member.slot)].is_some()
            || self
                .leases
                .iter()
                .flatten()
                .any(|id| id == &member.lease_id)
        {
            return Err(fenced());
        }
        let ticket = self
            .driver
            .state()
            .install_ticket(scope, member.slot)
            .map_err(|_| fenced())?;
        self.standby_ready = false;
        if let Err(error) = self.driver.native_mut().attach(scope, member) {
            // Attach may have partially created the inactive member. Preserve A
            // if targeted cleanup succeeds; otherwise fence and stop the pair.
            if self
                .driver
                .native_mut()
                .remove_standby(scope, member.slot)
                .is_err()
            {
                self.clear_readiness();
                let _ = self.driver.stop(scope);
            }
            return Err(error);
        }
        self.leases[index(member.slot)] = Some(member.lease_id.clone());
        let installed = if let Some(generation) = membership {
            self.driver.standby_installed(ticket, generation, now)
        } else {
            self.driver.candidate_installed(ticket, now)
        };
        if let Err(error) = installed {
            self.clear_readiness();
            // Also cover state-transition errors (e.g. revision exhaustion),
            // which occur after attach but before the driver's store callback.
            if self.driver.state().snapshot().phase == SessionPhase::Running {
                let _ = self.driver.stop(scope);
            }
            return Err(error);
        }
        if membership.is_some() {
            self.current_leases[index(member.slot)] = Some(member.lease_id.clone());
            self.stalled = false;
        }
        Ok(())
    }

    fn validate_view(
        &self,
        state: &SessionSnapshot,
        view: &RedundantSessionView,
        include_candidate: bool,
    ) -> io::Result<()> {
        self.validate_view_for_active(
            state,
            view,
            include_candidate,
            self.leases[index(state.active)].as_deref(),
        )
    }

    fn validate_view_for_active(
        &self,
        state: &SessionSnapshot,
        view: &RedundantSessionView,
        include_candidate: bool,
        active_lease: Option<&str>,
    ) -> io::Result<()> {
        let slot_lease = |i: usize| {
            if include_candidate && state.installed[i] {
                self.leases[i].as_deref()
            } else {
                self.current_leases[i].as_deref()
            }
        };
        if view.session_id != state.scope.session_id
            || !matches!(
                view.state,
                RedundantSessionState::Connected | RedundantSessionState::Degraded
            )
            || view.active_lease_id.as_deref() != active_lease
            || view.slot_a_lease_id.as_deref() != slot_lease(0)
            || view.slot_b_lease_id.as_deref() != slot_lease(1)
        {
            return Err(fenced());
        }
        Ok(())
    }

    fn clear_readiness(&mut self) {
        self.primary_ready = false;
        self.standby_ready = false;
        self.standby_failed = false;
    }
}

fn index(slot: Slot) -> usize {
    match slot {
        Slot::A => 0,
        Slot::B => 1,
    }
}
fn check_fence(state: &SessionSnapshot, revision: u64, epoch: u64) -> io::Result<()> {
    if state.phase != SessionPhase::Running
        || state.local_revision != revision
        || state.network_epoch != epoch
    {
        Err(fenced())
    } else {
        Ok(())
    }
}
fn fenced() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "redundant_session_control_fenced",
    )
}
