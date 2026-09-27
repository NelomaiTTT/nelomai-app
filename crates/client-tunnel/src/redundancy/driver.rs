//! Poll from the privileged helper actor, never from a UI connection. All
//! network/native I/O remains replaceable in tests; no worker per DNS request.
use super::{
    evidence::{NativeHealthSample, ProbeEvidence},
    session::*,
    *,
};
use std::io;

pub trait NativePair {
    type Socket: ProbeDatagram;
    /// Fail-stop integrity is checked even while ordinary network health is
    /// suspended. This is periodic detection, not a continuous killswitch.
    fn check_integrity(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn sample(&mut self, slot: Slot) -> Option<NativeHealthSample>;
    fn open_probe(&mut self, slot: Slot) -> io::Result<(Self::Socket, String)>;
    fn select_active(&mut self, scope: &SessionScope, slot: Slot) -> io::Result<()>;
    fn close(&mut self, scope: &SessionScope) -> io::Result<()>;
}
pub trait SessionStore {
    fn save(&mut self, snapshot: &SessionSnapshot) -> io::Result<()>;
}

#[derive(Default, Debug)]
pub struct TickResult {
    pub primary_ready: bool,
    pub standby_ready: bool,
    pub standby_failed: bool,
    pub switched: Option<Slot>,
    pub stalled: bool,
}

pub struct SessionDriver<N: NativePair, S> {
    state: SessionState,
    native: N,
    store: S,
    schedule: ProbeSchedule,
    monitor: RedundantHealthMonitor,
    evidence: [ProbeEvidence; 2],
    probes: [Option<(ProbeTicket, DnsProbe<N::Socket>)>; 2],
    samples: [Option<NativeHealthSample>; 2],
    episode: Option<u64>,
    last_tick: u64,
    next_sample: u64,
    query_sequence: u16,
    validated: bool,
    // Process-local only. Restart still follows journaled cleanup-only recovery.
    stop_deadline: Option<u64>,
    stop_prepared: bool,
}
impl<N: NativePair, S: SessionStore> SessionDriver<N, S> {
    /// Persist ownership before the first native Start. A factory may also pass
    /// a captured Running pair or cleanup-only recovery. Native Running is NOT
    /// UI readiness: that requires TickResult.primary_ready and data-plane proof.
    pub fn new(state: SessionState, mut native: N, mut store: S, now: u64) -> io::Result<Self> {
        let snapshot = state.snapshot();
        if let Err(e) = store.save(&snapshot) {
            let _ = native.close(&snapshot.scope);
            return Err(e);
        }
        let mut schedule = ProbeSchedule::new(snapshot.active, now);
        schedule.set_standby_available(snapshot.installed[snapshot.active.other().index()]);
        Ok(Self {
            state,
            native,
            store,
            schedule,
            monitor: RedundantHealthMonitor::new(true),
            evidence: [
                ProbeEvidence::new(Slot::A, now),
                ProbeEvidence::new(Slot::B, now),
            ],
            probes: [None, None],
            samples: [None, None],
            episode: None,
            last_tick: now,
            next_sample: now,
            query_sequence: 0,
            validated: true,
            stop_deadline: None,
            stop_prepared: false,
        })
    }
    pub fn state(&self) -> &SessionState {
        &self.state
    }
    pub fn native_mut(&mut self) -> &mut N {
        &mut self.native
    }
    pub fn native(&self) -> &N {
        &self.native
    }
    pub fn network_validated(&self) -> bool {
        self.validated
    }
    /// Read-only evidence guard for an atomic lifecycle freeze. The command
    /// owner must also check its sticky stall and exact scope/revision/epoch.
    /// Do not tick here: rejecting a stale observation must have no effects.
    pub fn recovery_stop_eligible(&self, now: u64) -> bool {
        let state = self.state.snapshot();
        if state.phase != SessionPhase::Running
            || now < self.last_tick
            || !self.validated
            || !self.monitor.network_ready(now)
        {
            return false;
        }
        let active = self.evidence[state.active.index()].observation(true, now, self.episode);
        if self.monitor.primary_ready(now, &active) {
            return false;
        }
        let reserve = state.active.other();
        !(state.installed[reserve.index()]
            && state.committed[reserve.index()]
            && self.monitor.usable(
                now,
                &self.evidence[reserve.index()].observation(false, now, self.episode),
            ))
    }
    pub fn start_primary(
        &mut self,
        scope: &SessionScope,
        start: impl FnOnce(&mut N) -> io::Result<()>,
    ) -> io::Result<()> {
        let snapshot = self.state.snapshot();
        if snapshot.scope != *scope || snapshot.phase != SessionPhase::Starting {
            return Err(fenced());
        }
        if let Err(error) = start(&mut self.native) {
            let _ = self.stop(scope);
            return Err(error);
        }
        self.state.primary_started(scope).map_err(|_| fenced())?;
        if let Err(error) = self.store.save(&self.state.snapshot()) {
            let _ = self.stop(scope);
            return Err(error);
        }
        Ok(())
    }
    pub fn confirm_role(&mut self, update: &RoleUpdate, generation: u64) -> io::Result<()> {
        self.confirm_role_response(
            update,
            generation,
            nelomai_contracts::RedundantRoleAction::Accepted,
        )
    }
    /// Only the command owner may observe a fully validated canonical Rebase.
    /// Leave health, native selection, and role confirmation untouched. A lost
    /// durable-save acknowledgement requires exact-pair cleanup, not adoption.
    pub(super) fn observe_role_rebase(
        &mut self,
        update: &RoleUpdate,
        generation: u64,
    ) -> io::Result<()> {
        let mut observed = self.state.clone();
        if !observed.observe_role_rebase(update, generation) {
            return Err(fenced());
        }
        if let Err(error) = self.store.save(&observed.snapshot()) {
            let scope = self.state.snapshot().scope;
            let _ = self.stop(&scope);
            return Err(error);
        }
        self.state = observed;
        Ok(())
    }
    /// Called after the command owner validates the panel's exact member map.
    pub fn confirm_role_response(
        &mut self,
        update: &RoleUpdate,
        generation: u64,
        action: nelomai_contracts::RedundantRoleAction,
    ) -> io::Result<()> {
        let mut confirmed = self.state.clone();
        if !confirmed.ack_role_response(update, generation, action) {
            return Err(fenced());
        }
        if let Err(error) = self.store.save(&confirmed.snapshot()) {
            let scope = self.state.snapshot().scope;
            let _ = self.stop(&scope);
            return Err(error);
        }
        self.state = confirmed;
        Ok(())
    }
    pub fn standby_installed(
        &mut self,
        ticket: MemberTicket,
        membership: u64,
        now: u64,
    ) -> io::Result<()> {
        self.state
            .standby_installed(ticket, membership)
            .map_err(|_| fenced())?;
        if let Err(e) = self.store.save(&self.state.snapshot()) {
            let scope = self.state.snapshot().scope;
            let _ = self.stop(&scope);
            return Err(e);
        }
        self.schedule.set_standby_available(true);
        self.monitor.membership_changed();
        let slot = self.state.snapshot().active.other();
        self.evidence[slot.index()].reset(now);
        self.next_sample = now;
        Ok(())
    }
    pub fn candidate_installed(&mut self, ticket: MemberTicket, now: u64) -> io::Result<()> {
        self.state
            .candidate_installed(ticket)
            .map_err(|_| fenced())?;
        if let Err(e) = self.store.save(&self.state.snapshot()) {
            let scope = self.state.snapshot().scope;
            let _ = self.stop(&scope);
            return Err(e);
        }
        self.schedule.set_standby_available(true);
        self.evidence[self.state.snapshot().active.other().index()].reset(now);
        self.next_sample = now;
        Ok(())
    }
    pub fn commit_candidate(
        &mut self,
        scope: &SessionScope,
        slot: Slot,
        revision: u64,
        epoch: u64,
        expected: u64,
        membership: u64,
    ) -> io::Result<()> {
        let mut next = self.state.clone();
        next.commit_candidate(scope, slot, revision, epoch, expected, membership)
            .map_err(|_| fenced())?;
        if let Err(e) = self.store.save(&next.snapshot()) {
            let _ = self.stop(scope);
            return Err(e);
        }
        self.state = next;
        self.monitor.membership_changed();
        Ok(())
    }
    pub(super) fn recommit_current(
        &mut self,
        scope: &SessionScope,
        slot: Slot,
        revision: u64,
        epoch: u64,
        membership: u64,
    ) -> io::Result<()> {
        let mut next = self.state.clone();
        next.recommit_current(scope, slot, revision, epoch, membership)
            .map_err(|_| fenced())?;
        if let Err(e) = self.store.save(&next.snapshot()) {
            let _ = self.stop(scope);
            return Err(e);
        }
        self.state = next;
        self.monitor.membership_changed();
        Ok(())
    }
    pub fn network_changed(
        &mut self,
        scope: &SessionScope,
        now: u64,
        validated: bool,
    ) -> io::Result<()> {
        self.state.network_changed(scope).map_err(|_| fenced())?;
        self.cancel_all();
        self.schedule.network_changed(now);
        self.monitor.network_changed(now, validated);
        for e in &mut self.evidence {
            e.reset(now);
        }
        self.samples = [None, None];
        self.episode = None;
        self.next_sample = now;
        self.validated = validated;
        if let Err(e) = self.store.save(&self.state.snapshot()) {
            let _ = self.stop(scope);
            return Err(e);
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)] // Keep the exact scoped native-cleanup fence together.
    pub fn remove_candidate(
        &mut self,
        scope: &SessionScope,
        slot: Slot,
        revision: u64,
        epoch: u64,
        membership: u64,
        now: u64,
        remove: impl FnOnce(&mut N) -> io::Result<()>,
    ) -> io::Result<()> {
        self.remove_inactive(scope, slot, revision, epoch, membership, now, false, remove)
    }
    #[allow(clippy::too_many_arguments)] // Same fence as candidate removal; no scope reconstruction.
    pub fn retire_inactive(
        &mut self,
        scope: &SessionScope,
        slot: Slot,
        revision: u64,
        epoch: u64,
        membership: u64,
        now: u64,
        remove: impl FnOnce(&mut N) -> io::Result<()>,
    ) -> io::Result<()> {
        self.remove_inactive(scope, slot, revision, epoch, membership, now, true, remove)
    }
    #[allow(clippy::too_many_arguments)] // Same exact command fence for candidate/current removal.
    fn remove_inactive(
        &mut self,
        scope: &SessionScope,
        slot: Slot,
        revision: u64,
        epoch: u64,
        membership: u64,
        now: u64,
        current: bool,
        remove: impl FnOnce(&mut N) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut next = self.state.clone();
        if current {
            next.retire_inactive(scope, slot, revision, epoch, membership)
        } else {
            next.remove_candidate(scope, slot, revision, epoch, membership)
        }
        .map_err(|_| fenced())?;
        let i = slot.index();
        if let Some((ticket, _)) = self.probes[i].take() {
            self.evidence[i].probe_cancelled(ticket);
        }
        self.schedule.set_standby_available(false);
        self.evidence[i].reset(now);
        self.samples[i] = None;
        // Losing the save acknowledgement is ambiguous: preserve the caller's
        // lease and stop the pair instead of attempting an unjournaled removal.
        if let Err(error) = self.store.save(&next.snapshot()) {
            let _ = self.stop(scope);
            return Err(error);
        }
        self.state = next;
        if let Err(error) = remove(&mut self.native) {
            let _ = self.stop(scope);
            return Err(error);
        }
        Ok(())
    }
    /// Freeze the exact last-active role under the serialized actor before the
    /// caller sends server Stop. A retry never advances revision or the deadline.
    /// A successful fresh freeze keeps native open; helper ticks enforce the
    /// 1000ms upper bound. Already-failed/recovered stops remain cleanup-only.
    pub fn prepare_stop(&mut self, scope: &SessionScope, now: u64) -> io::Result<()> {
        let snapshot = self.state.snapshot();
        if snapshot.scope != *scope {
            return Err(fenced());
        }
        if now < self.last_tick {
            let _ = self.stop(scope);
            return Err(fenced());
        }
        self.last_tick = now;
        if snapshot.phase == SessionPhase::Stopped {
            return Ok(());
        }
        if snapshot.phase == SessionPhase::Stopping {
            // Only a confirmed durable freeze may be acknowledged unchanged.
            // Failed saves/ordinary failed Stop/recovery are cleanup-only.
            return if self.stop_prepared {
                Ok(())
            } else {
                self.stop(scope)
            };
        }
        let Some(deadline) = now.checked_add(1000) else {
            let _ = self.stop(scope);
            return Err(fenced());
        };
        self.state.begin_stop(scope).map_err(|_| fenced())?;
        self.cancel_all();
        self.schedule.stop();
        self.stop_deadline = Some(deadline);
        if let Err(error) = self.store.save(&self.state.snapshot()) {
            // An error may be a lost durable-save ACK. Never keep traffic open
            // because intent was not confirmed; retain retry if close fails.
            self.stop_deadline = Some(now);
            let _ = self.stop(scope);
            return Err(error);
        }
        self.stop_prepared = true;
        Ok(())
    }
    pub fn stop(&mut self, scope: &SessionScope) -> io::Result<()> {
        self.state.begin_stop(scope).map_err(|_| fenced())?;
        self.cancel_all();
        self.schedule.stop();
        let saved = self.store.save(&self.state.snapshot());
        // Disk/panel errors cannot hold native traffic open.
        let native = self.native.close(scope);
        if native.is_ok() {
            self.state.stopped(scope).map_err(|_| fenced())?;
            self.stop_deadline = None;
        }
        let final_save = self.store.save(&self.state.snapshot());
        native.and(saved).and(final_save)
    }
    pub fn tick(&mut self, now: u64) -> io::Result<TickResult> {
        let snapshot = self.state.snapshot();
        if now < self.last_tick {
            let _ = self.stop(&snapshot.scope);
            return Err(fenced());
        }
        self.last_tick = now;
        if self.stop_deadline.is_some_and(|deadline| now >= deadline) {
            self.stop(&snapshot.scope)?;
            return Ok(TickResult::default());
        }
        if snapshot.phase == SessionPhase::Running {
            if let Err(error) = self.native.check_integrity() {
                let _ = self.stop(&snapshot.scope);
                return Err(error);
            }
        }
        if snapshot.phase != SessionPhase::Running || !self.validated {
            return Ok(TickResult::default());
        }
        let active = snapshot.active;
        if now >= self.next_sample {
            for slot in [active, active.other()] {
                if snapshot.installed[slot.index()] {
                    self.samples[slot.index()] = self.native.sample(slot);
                    self.evidence[slot.index()].sample(self.samples[slot.index()], now);
                }
            }
            self.next_sample = now.saturating_add(500);
        }
        // Resolve completed datagrams before scheduling more. No stale or
        // expired success can enter the evidence reducer.
        for slot in [active, active.other()] {
            let i = slot.index();
            let result = self.probes[i]
                .as_mut()
                .map(|(ticket, p)| (*ticket, p.poll(now)));
            if let Some((ticket, result)) = result {
                if matches!(
                    result,
                    ProbePoll::Succeeded | ProbePoll::Failed | ProbePoll::Finished
                ) {
                    let success = result == ProbePoll::Succeeded;
                    if self.schedule.complete(ticket, success, now) {
                        self.evidence[i].probe_finished(ticket, success, now, self.samples[i]);
                    }
                    // At the deadline schedule.poll emits the failed ticket;
                    // its evidence baseline is retained until that event.
                    self.probes[i] = None;
                }
            }
        }
        let mut batch = self.schedule.poll(now);
        let mut cancelled = std::mem::take(&mut batch.cancelled);
        for ticket in &cancelled {
            self.cancel(*ticket);
        }
        for ticket in batch.timed_out.drain(..) {
            let i = ticket.slot().index();
            self.probes[i] = None;
            self.evidence[i].probe_finished(ticket, false, now, self.samples[i]);
        }
        let a = self.evidence[active.index()].observation(true, now, None);
        let suspected = a.hard_failure || (a.probe_failed && a.independent_failure_signal);
        if suspected && self.episode.is_none() {
            self.episode = Some(now);
            self.schedule.suspect_active(now);
        } else if !suspected {
            self.episode = None;
        }
        // A hard native failure may have cancelled a reserve query in this
        // tick. Drain that cancellation before launching a new socket.
        let follow = self.schedule.poll(now);
        for ticket in follow.cancelled {
            self.cancel(ticket);
            cancelled.push(ticket);
        }
        for ticket in follow.timed_out {
            let i = ticket.slot().index();
            self.probes[i] = None;
            self.evidence[i].probe_finished(ticket, false, now, self.samples[i]);
        }
        batch.started.extend(follow.started);
        for ticket in batch.started.into_iter().filter(|t| !cancelled.contains(t)) {
            let i = ticket.slot().index();
            self.evidence[i].probe_started(ticket, self.samples[i]);
            self.query_sequence = self.query_sequence.wrapping_add(1);
            let query = self
                .native
                .open_probe(ticket.slot())
                .and_then(|(socket, name)| {
                    DnsProbe::start(
                        socket,
                        &name,
                        self.query_sequence,
                        now,
                        ticket.deadline_ms().saturating_sub(now),
                    )
                });
            match query {
                Ok(query) => self.probes[i] = Some((ticket, query)),
                Err(_) => {
                    if self.schedule.complete(ticket, false, now) {
                        self.evidence[i].probe_finished(ticket, false, now, self.samples[i]);
                    }
                }
            }
        }
        let observations = [active, active.other()]
            .into_iter()
            .filter(|slot| snapshot.installed[slot.index()])
            .map(|slot| self.evidence[slot.index()].observation(slot == active, now, self.episode))
            .collect::<Vec<_>>();
        let primary_ready = observations
            .iter()
            .find(|o| o.active)
            .is_some_and(|o| self.monitor.primary_ready(now, o));
        let standby_ready = observations
            .iter()
            .find(|o| !o.active)
            .is_some_and(|o| self.monitor.ready(now, o));
        let standby_failed = observations
            .iter()
            .find(|o| !o.active)
            .is_some_and(|o| self.monitor.failed(now, o));
        let mut result = TickResult {
            primary_ready,
            standby_ready,
            standby_failed,
            ..Default::default()
        };
        let eligible = observations
            .into_iter()
            .filter(|o| snapshot.committed[o.slot.index()])
            .collect::<Vec<_>>();
        match self.monitor.evaluate(now, &eligible) {
            FailoverDecision::None => (),
            FailoverDecision::Stalled => result.stalled = true,
            FailoverDecision::SwitchTo(slot) => {
                let ticket = self
                    .state
                    .promotion_ticket(&snapshot.scope, slot)
                    .map_err(|_| fenced())?;
                let mut intent = snapshot.clone();
                intent.role_confirmed = false;
                self.store.save(&intent)?;
                self.cancel_all();
                if self
                    .state
                    .promote(ticket, || self.native.select_active(&snapshot.scope, slot))
                    .is_err()
                {
                    // Route rollback may itself be pending. Never keep reporting
                    // Running after a partial native selection failure.
                    let _ = self.stop(&snapshot.scope);
                    return Err(io::Error::other("native_promotion_failed"));
                }
                if let Err(e) = self.store.save(&self.state.snapshot()) {
                    let _ = self.stop(&snapshot.scope);
                    return Err(e);
                }
                self.schedule.promote(slot, now);
                self.episode = None;
                self.next_sample = now;
                result.switched = Some(slot);
                result.primary_ready = true;
                result.standby_ready = false;
                result.standby_failed = false;
            }
        }
        Ok(result)
    }
    fn cancel(&mut self, ticket: ProbeTicket) {
        let i = ticket.slot().index();
        if self.probes[i].as_ref().is_some_and(|(t, _)| *t == ticket) {
            self.probes[i] = None;
        }
        self.evidence[i].probe_cancelled(ticket);
    }
    fn cancel_all(&mut self) {
        for slot in [Slot::A, Slot::B] {
            if let Some((ticket, _)) = self.probes[slot.index()].take() {
                self.evidence[slot.index()].probe_cancelled(ticket);
            }
        }
    }
}
fn fenced() -> io::Error {
    io::Error::other("redundant_session_fenced")
}
