//! Helper-owned role fences. Native effects and durable writes remain in the
//! enclosing serialized helper actor; no UI lifetime controls this state.
use super::{SessionScope, Slot};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SessionPhase {
    Starting,
    Running,
    Stopping,
    Stopped,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionSnapshot {
    pub scope: SessionScope,
    pub phase: SessionPhase,
    pub active: Slot,
    pub installed: [bool; 2],
    pub committed: [bool; 2],
    pub network_epoch: u64,
    pub local_revision: u64,
    pub role_generation: u64,
    pub membership_generation: u64,
    pub role_confirmed: bool,
}

/// Process-local tickets are not IPC commands or restart authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberTicket {
    scope: SessionScope,
    epoch: u64,
    revision: u64,
    membership: u64,
    slot: Slot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleUpdate {
    pub scope: SessionScope,
    pub active: Slot,
    pub expected_role_generation: u64,
    pub membership_generation: u64,
    revision: u64,
    epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("redundant_session_fenced")]
pub struct SessionFenced;

#[derive(Debug, thiserror::Error)]
pub enum PromotionError<E> {
    #[error("redundant_session_fenced")]
    Fenced,
    #[error("native_promotion_failed")]
    Native(E),
}

#[derive(Clone)]
pub struct SessionState {
    state: SessionSnapshot,
}
impl SessionState {
    pub fn new(
        scope: SessionScope,
        primary: Slot,
        role_generation: u64,
        membership_generation: u64,
    ) -> Result<Self, SessionFenced> {
        if !scope.validate()
            || role_generation > i64::MAX as u64
            || membership_generation > i64::MAX as u64
        {
            return Err(SessionFenced);
        }
        Ok(Self {
            state: SessionSnapshot {
                scope,
                phase: SessionPhase::Starting,
                active: primary,
                installed: [false; 2],
                committed: [false; 2],
                network_epoch: 1,
                local_revision: 1,
                role_generation,
                membership_generation,
                role_confirmed: true,
            },
        })
    }
    pub fn recover_for_cleanup(
        scope: SessionScope,
        mut state: SessionSnapshot,
    ) -> Result<Self, SessionFenced> {
        if !scope.validate()
            || state.scope != scope
            || state.role_generation > i64::MAX as u64
            || state.membership_generation > i64::MAX as u64
            || state.network_epoch == 0
            || state.local_revision == 0
        {
            return Err(SessionFenced);
        }
        state.phase = SessionPhase::Stopping;
        state.role_confirmed = false;
        state.local_revision = state.local_revision.checked_add(1).ok_or(SessionFenced)?;
        Ok(Self { state })
    }
    pub fn snapshot(&self) -> SessionSnapshot {
        self.state.clone()
    }
    pub fn primary_started(&mut self, scope: &SessionScope) -> Result<(), SessionFenced> {
        self.check_scope(scope)?;
        if self.state.phase != SessionPhase::Starting {
            return Err(SessionFenced);
        }
        self.state.installed[self.state.active.index()] = true;
        self.state.committed[self.state.active.index()] = true;
        self.state.phase = SessionPhase::Running;
        Ok(())
    }
    pub fn install_ticket(
        &self,
        scope: &SessionScope,
        slot: Slot,
    ) -> Result<MemberTicket, SessionFenced> {
        self.check_running(scope)?;
        if slot == self.state.active || self.state.installed[slot.index()] {
            return Err(SessionFenced);
        }
        Ok(self.ticket(slot))
    }
    pub fn standby_installed(
        &mut self,
        ticket: MemberTicket,
        membership: u64,
    ) -> Result<(), SessionFenced> {
        self.check_ticket(&ticket)?;
        if ticket.slot == self.state.active
            || self.state.installed[ticket.slot.index()]
            || membership < self.state.membership_generation
            || membership > i64::MAX as u64
        {
            return Err(SessionFenced);
        }
        let next = self.next_revision()?;
        self.state.installed[ticket.slot.index()] = true;
        self.state.committed[ticket.slot.index()] = true;
        self.state.membership_generation = membership;
        self.state.local_revision = next;
        Ok(())
    }
    pub fn candidate_installed(&mut self, ticket: MemberTicket) -> Result<(), SessionFenced> {
        self.check_ticket(&ticket)?;
        if ticket.slot == self.state.active || self.state.installed[ticket.slot.index()] {
            return Err(SessionFenced);
        }
        let next = self.next_revision()?;
        self.state.installed[ticket.slot.index()] = true;
        self.state.committed[ticket.slot.index()] = false;
        self.state.local_revision = next;
        Ok(())
    }
    /// A candidate is probeable, but only a validated panel commit makes it a
    /// CURRENT member eligible for carrying user traffic.
    pub fn commit_candidate(
        &mut self,
        scope: &SessionScope,
        slot: Slot,
        revision: u64,
        epoch: u64,
        expected_membership: u64,
        membership: u64,
    ) -> Result<(), SessionFenced> {
        if expected_membership.checked_add(1) != Some(membership) {
            return Err(SessionFenced);
        }
        self.confirm_candidate(
            scope,
            slot,
            revision,
            epoch,
            expected_membership,
            membership,
        )
    }
    /// Only the protocol owner may use this after matching the candidate's
    /// exact lease against its retained canonical CURRENT identity.
    pub(super) fn recommit_current(
        &mut self,
        scope: &SessionScope,
        slot: Slot,
        revision: u64,
        epoch: u64,
        membership: u64,
    ) -> Result<(), SessionFenced> {
        self.confirm_candidate(scope, slot, revision, epoch, membership, membership)
    }
    fn confirm_candidate(
        &mut self,
        scope: &SessionScope,
        slot: Slot,
        revision: u64,
        epoch: u64,
        expected_membership: u64,
        membership: u64,
    ) -> Result<(), SessionFenced> {
        self.check_running(scope)?;
        if slot == self.state.active
            || !self.state.installed[slot.index()]
            || self.state.committed[slot.index()]
            || self.state.local_revision != revision
            || self.state.network_epoch != epoch
            || self.state.membership_generation != expected_membership
            || membership > i64::MAX as u64
        {
            return Err(SessionFenced);
        }
        let next = self.next_revision()?;
        self.state.committed[slot.index()] = true;
        self.state.membership_generation = membership;
        self.state.local_revision = next;
        Ok(())
    }
    pub fn promotion_ticket(
        &self,
        scope: &SessionScope,
        slot: Slot,
    ) -> Result<MemberTicket, SessionFenced> {
        self.check_running(scope)?;
        if slot == self.state.active
            || !self.state.installed[slot.index()]
            || !self.state.committed[slot.index()]
        {
            return Err(SessionFenced);
        }
        Ok(self.ticket(slot))
    }
    /// Fence a candidate before targeted native cleanup. Only uncommitted
    /// members may be removed without a separate acknowledged server release.
    /// The driver persists this revision before calling the native owner; a
    /// restart still uses cleanup-only recovery of the native ownership journal.
    pub fn remove_candidate(
        &mut self,
        scope: &SessionScope,
        slot: Slot,
        revision: u64,
        epoch: u64,
        membership: u64,
    ) -> Result<(), SessionFenced> {
        self.check_running(scope)?;
        let i = slot.index();
        if slot == self.state.active
            || !self.state.installed[i]
            || self.state.committed[i]
            || self.state.local_revision != revision
            || self.state.network_epoch != epoch
            || self.state.membership_generation != membership
        {
            return Err(SessionFenced);
        }
        let next = self.next_revision()?;
        self.state.installed[i] = false;
        self.state.local_revision = next;
        Ok(())
    }
    pub fn retire_inactive(
        &mut self,
        scope: &SessionScope,
        slot: Slot,
        revision: u64,
        epoch: u64,
        membership: u64,
    ) -> Result<(), SessionFenced> {
        self.check_running(scope)?;
        let i = slot.index();
        if slot == self.state.active
            || !self.state.role_confirmed
            || !self.state.installed[i]
            || !self.state.committed[i]
            || self.state.local_revision != revision
            || self.state.network_epoch != epoch
            || self.state.membership_generation != membership
        {
            return Err(SessionFenced);
        }
        let next = self.next_revision()?;
        self.state.installed[i] = false;
        self.state.committed[i] = false;
        self.state.local_revision = next;
        Ok(())
    }
    /// The helper actor holds its session lock throughout this callback. The
    /// route owner must finish its write-ahead/readback transaction before Ok.
    /// A failed native switch never publishes a new local or server role.
    pub fn promote<E>(
        &mut self,
        ticket: MemberTicket,
        select: impl FnOnce() -> Result<(), E>,
    ) -> Result<(), PromotionError<E>> {
        self.check_ticket(&ticket)
            .map_err(|_| PromotionError::Fenced)?;
        if ticket.slot == self.state.active
            || !self.state.installed[ticket.slot.index()]
            || !self.state.committed[ticket.slot.index()]
        {
            return Err(PromotionError::Fenced);
        }
        let next = self.next_revision().map_err(|_| PromotionError::Fenced)?;
        select().map_err(PromotionError::Native)?;
        self.state.active = ticket.slot;
        self.state.local_revision = next;
        self.state.role_confirmed = false;
        Ok(())
    }
    pub fn role_update(&self) -> Option<RoleUpdate> {
        (self.state.phase == SessionPhase::Running && !self.state.role_confirmed).then(|| {
            RoleUpdate {
                scope: self.state.scope.clone(),
                active: self.state.active,
                expected_role_generation: self.state.role_generation,
                membership_generation: self.state.membership_generation,
                revision: self.state.local_revision,
                epoch: self.state.network_epoch,
            }
        })
    }
    /// False requires fresh server reconciliation, not blind retry with a stale
    /// generation. A response never commands a native switch or resumes Stop.
    pub fn ack_role(&mut self, update: &RoleUpdate, generation: u64) -> bool {
        self.ack_role_response(
            update,
            generation,
            nelomai_contracts::RedundantRoleAction::Accepted,
        )
    }
    /// The command owner has validated a canonical OTHER-current role. Observe
    /// its generation without acknowledging our native role or changing traffic.
    /// Exact process-local fences also reject replay after an earlier observation.
    pub(super) fn observe_role_rebase(&mut self, update: &RoleUpdate, generation: u64) -> bool {
        if self.role_update().as_ref() != Some(update)
            || generation > i64::MAX as u64
            || update.expected_role_generation.checked_add(1) != Some(generation)
        {
            return false;
        }
        self.state.role_generation = generation;
        true
    }
    /// The command owner validates the exact panel active/committed lease map
    /// first. A canonical-role acknowledgement may keep this generation after
    /// an unreported A -> B -> A flip; Accepted still requires exactly +1.
    pub fn ack_role_response(
        &mut self,
        update: &RoleUpdate,
        generation: u64,
        action: nelomai_contracts::RedundantRoleAction,
    ) -> bool {
        use nelomai_contracts::RedundantRoleAction::{Accepted, Acknowledged, Rebase};
        let next = update.expected_role_generation.checked_add(1) == Some(generation);
        let valid = match action {
            Accepted => next,
            Acknowledged => next || generation == update.expected_role_generation,
            Rebase => false,
        };
        if generation > i64::MAX as u64 || self.role_update().as_ref() != Some(update) || !valid {
            return false;
        }
        self.state.role_generation = generation;
        self.state.role_confirmed = true;
        true
    }
    pub fn warm_slot(&self) -> Option<Slot> {
        (self.state.role_confirmed && self.state.phase != SessionPhase::Starting)
            .then_some(self.state.active)
    }
    pub fn network_changed(&mut self, scope: &SessionScope) -> Result<(), SessionFenced> {
        self.check_running(scope)?;
        let next = self
            .state
            .network_epoch
            .checked_add(1)
            .ok_or(SessionFenced)?;
        self.state.network_epoch = next;
        Ok(())
    }
    /// Must be called before async cleanup and persisted before server Stop.
    /// If persistence fails the actor STILL disables its verified local members;
    /// it must not claim server cleanup or a retained WARM lease succeeded.
    pub fn begin_stop(&mut self, scope: &SessionScope) -> Result<(), SessionFenced> {
        self.check_scope(scope)?;
        if matches!(
            self.state.phase,
            SessionPhase::Stopping | SessionPhase::Stopped
        ) {
            return Ok(());
        }
        let next = self.next_revision()?;
        if self.state.phase == SessionPhase::Starting {
            self.state.role_confirmed = false;
        }
        self.state.local_revision = next;
        self.state.phase = SessionPhase::Stopping;
        Ok(())
    }
    pub fn stopped(&mut self, scope: &SessionScope) -> Result<(), SessionFenced> {
        self.check_scope(scope)?;
        if !matches!(
            self.state.phase,
            SessionPhase::Stopping | SessionPhase::Stopped
        ) {
            return Err(SessionFenced);
        }
        self.state.installed = [false; 2];
        self.state.committed = [false; 2];
        self.state.phase = SessionPhase::Stopped;
        Ok(())
    }
    fn ticket(&self, slot: Slot) -> MemberTicket {
        MemberTicket {
            scope: self.state.scope.clone(),
            slot,
            epoch: self.state.network_epoch,
            revision: self.state.local_revision,
            membership: self.state.membership_generation,
        }
    }
    fn check_scope(&self, scope: &SessionScope) -> Result<(), SessionFenced> {
        if scope == &self.state.scope {
            Ok(())
        } else {
            Err(SessionFenced)
        }
    }
    fn check_running(&self, scope: &SessionScope) -> Result<(), SessionFenced> {
        self.check_scope(scope)?;
        if self.state.phase == SessionPhase::Running {
            Ok(())
        } else {
            Err(SessionFenced)
        }
    }
    fn check_ticket(&self, ticket: &MemberTicket) -> Result<(), SessionFenced> {
        self.check_running(&ticket.scope)?;
        if ticket == &self.ticket(ticket.slot) {
            Ok(())
        } else {
            Err(SessionFenced)
        }
    }
    fn next_revision(&self) -> Result<u64, SessionFenced> {
        self.state
            .local_revision
            .checked_add(1)
            .ok_or(SessionFenced)
    }
}

#[cfg(test)]
mod rebase_tests {
    use super::*;
    use nelomai_contracts::{RedundantRoleAction, RuntimeSlot};

    fn unconfirmed(generation: u64) -> SessionState {
        let scope = SessionScope {
            runtime: RuntimeSlot::Latest,
            runtime_generation: 10,
            session_id: "11111111-1111-4111-8111-111111111111".into(),
            connection_generation: 7,
        };
        let mut state = SessionState::new(scope.clone(), Slot::A, generation, 0).unwrap();
        state.primary_started(&scope).unwrap();
        state
            .standby_installed(state.install_ticket(&scope, Slot::B).unwrap(), 0)
            .unwrap();
        state
            .promote(state.promotion_ticket(&scope, Slot::B).unwrap(), || {
                Ok::<(), ()>(())
            })
            .unwrap();
        state
    }

    #[test]
    fn observation_keeps_role_unconfirmed_and_legacy_rebase_ack_strict_at_signed_limit() {
        for generation in [0, i64::MAX as u64 - 1, i64::MAX as u64] {
            let mut state = unconfirmed(generation);
            let update = state.role_update().unwrap();
            let before = state.snapshot();
            assert!(!state.ack_role_response(&update, generation + 1, RedundantRoleAction::Rebase));
            assert_eq!(state.snapshot(), before);
            assert!(!state.observe_role_rebase(&update, generation));
            assert!(!state.observe_role_rebase(&update, generation + 2));
            assert_eq!(state.snapshot(), before);
            let allowed = generation < i64::MAX as u64;
            assert_eq!(state.observe_role_rebase(&update, generation + 1), allowed);
            let mut expected = before;
            if allowed {
                expected.role_generation = generation + 1;
            }
            assert_eq!(state.snapshot(), expected);
            assert_eq!(state.warm_slot(), None);
            assert_eq!(
                state.role_update().unwrap().expected_role_generation,
                expected.role_generation
            );
            assert!(
                !state.observe_role_rebase(&update, generation + 1),
                "replay cannot be observed twice"
            );
        }
    }

    #[test]
    fn observation_requires_exact_current_process_local_update_and_running_unconfirmed_state() {
        let mut state = unconfirmed(4);
        let update = state.role_update().unwrap();
        let before = state.snapshot();
        for wrong in 0..6 {
            let mut stale = update.clone();
            match wrong {
                0 => stale.scope.connection_generation += 1,
                1 => stale.active = Slot::A,
                2 => stale.expected_role_generation += 1,
                3 => stale.membership_generation += 1,
                4 => stale.revision += 1,
                _ => stale.epoch += 1,
            }
            assert!(!state.observe_role_rebase(&stale, stale.expected_role_generation + 1));
            assert_eq!(state.snapshot(), before);
        }
        for phase in [
            SessionPhase::Starting,
            SessionPhase::Stopping,
            SessionPhase::Stopped,
        ] {
            let mut other = state.clone();
            other.state.phase = phase;
            let before = other.snapshot();
            assert!(!other.observe_role_rebase(&update, 5));
            assert_eq!(other.snapshot(), before);
        }
        assert!(state.ack_role(&update, 5));
        let before = state.snapshot();
        assert!(!state.observe_role_rebase(&update, 5));
        assert_eq!(state.snapshot(), before);
    }
}
