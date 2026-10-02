//! Scoped Windows pair composition; never selected by the production backend.
#![cfg_attr(not(windows), allow(dead_code))] // Portable fake tests have no native caller.
use crate::{
    member_dns::Snapshot as DnsSnapshot,
    member_guard::{ExchangePlan, Model, ProbeTuple},
    member_owner::Record as OwnerRecord,
};
use nelomai_client_tunnel::{
    redundancy::{
        control::PairControl, driver::NativePair, evidence::NativeHealthSample, protocol::Member,
        ProbeDatagram, SessionScope, Slot,
    },
    DesktopTunnelOptions, TunnelMetrics,
};
use nelomai_contracts::{dispatcher::TunnelSlot, RedundantHealthProbe};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    io,
    net::{IpAddr, Ipv4Addr},
};

// Both paths must come from the verified installation, never from IPC. Permit
// only canonicalize's local DOS extended-length prefix; do not resolve aliases,
// fold case, or accept a different target after following a reparse point.
pub(crate) fn canonical_engine_matches(
    trusted: &std::path::Path,
    canonical: &std::path::Path,
) -> bool {
    if trusted == canonical {
        return true;
    }
    let Some(dos) = canonical.to_str().and_then(|s| s.strip_prefix(r"\\?\")) else {
        return false;
    };
    let bytes = dos.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && &bytes[1..3] == b":\\"
        && trusted.as_os_str() == std::ffi::OsStr::new(dos)
}

// Comparison-only preclaim decision. The native caller still verifies the SAME
// installation owner, validates the command and performs journaled recovery.
pub(crate) fn require_factory_start_context(
    requested: nelomai_contracts::RuntimeSlot,
    owned: nelomai_contracts::RuntimeSlot,
    in_async_runtime: bool,
    cancelled: bool,
) -> io::Result<()> {
    if requested != owned || in_async_runtime || cancelled {
        return Err(io::Error::other("native_pair_start_context_conflict"));
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MemberRecord {
    pub owner: OwnerRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_stopped: Option<OwnerRecord>,
    pub source: Ipv4Addr,
    pub endpoint: IpAddr,
    pub allowed: Vec<ipnet::IpNet>,
    pub dns: Vec<IpAddr>,
    pub probe: RedundantHealthProbe,
    pub peer: [u8; 32],
    pub started_epoch_ms: u64,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DnsRecord {
    pub baseline: DnsSnapshot,
    pub current: DnsSnapshot,
    pub pending: Option<DnsSnapshot>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PairRecord {
    pub scope: SessionScope,
    pub members: [Option<MemberRecord>; 2],
    pub active: Option<Slot>,
    pub guard: Model,
    pub pending_guard: Option<ExchangePlan>,
    pub dns: [Option<DnsRecord>; 2],
    pub options: Option<DesktopTunnelOptions>,
    pub closing: bool,
}
pub(crate) trait PairStore {
    fn save(&mut self, record: &PairRecord) -> io::Result<()>;
}
/// True only for a still-unpublished member whose exact prior owner CAS never
/// happened. Callers MUST additionally prove absence using that retained owner,
/// or positively empty native/config state when there was no predecessor.
pub(crate) fn matches_unstarted_prior(
    member: &MemberRecord,
    current: Option<&OwnerRecord>,
) -> io::Result<bool> {
    if let Some(prior) = &member.prior_stopped {
        crate::member_owner::validate_prior_stopped(&member.owner.intent, prior)
            .map_err(|_| failed())?;
    }
    if member.owner.phase == crate::member_owner::Phase::Prepared
        && member.owner.proof.is_none()
        && current == member.prior_stopped.as_ref()
    {
        return Ok(true);
    }
    if current.is_some_and(|r| r.intent == member.owner.intent) {
        return Ok(false);
    }
    Err(failed())
}
/// Durable pair-side gate BEFORE replacing an in-memory member owner. Native
/// absence and exact owner-journal equality must ALSO be checked by that owner.
pub(crate) fn verify_retired_slot(
    retired: &OwnerRecord,
    pair: &PairRecord,
    routes: &[nelomai_client_tunnel::redundancy::network::RouteValue],
    guard: &crate::member_guard::Snapshot,
) -> io::Result<()> {
    let slot = slot_shared(retired.intent.slot).idx();
    if retired.intent.scope != pair.scope
        || retired.phase != crate::member_owner::Phase::Stopped
        || retired.proof.is_some()
        || pair.closing
        || pair.pending_guard.is_some()
        || pair.members[slot].is_some()
        || pair.dns[slot].is_some()
        || pair.guard.members[slot].is_some()
        || pair.guard.active == Some(slot_shared(retired.intent.slot))
        || &pair.guard.expected != guard
    {
        return Err(failed());
    }
    pair.guard.validate().map_err(|_| failed())?;
    if let Some(proof) = retired.retired_proof {
        if routes.iter().any(|r| r.interface == proof.interface.index)
            || guard.filters.iter().any(|f| {
                f.conditions.iter().any(|condition| match condition {
                    crate::member_guard::Condition::InterfaceIndex(index)
                    | crate::member_guard::Condition::DestinationInterfaceIndex(index) => {
                        *index == proof.interface.index
                    }
                    crate::member_guard::Condition::LocalInterface(luid) => {
                        *luid == proof.interface.luid
                    }
                    _ => false,
                })
            })
        {
            return Err(failed());
        }
    }
    Ok(())
}
/// Process-local duplicate acknowledgement only; durable replay fencing belongs
/// to SessionFiles. Never cache completion before the protected tombstone ACK.
#[derive(Default)]
pub(crate) struct CompletionState {
    completed: Option<nelomai_client_tunnel::redundancy::session::SessionSnapshot>,
}

/// Scheduling only for original initial-NoC DATA completion. Concrete native
/// callbacks independently authenticate the SAME completed NoC outcome/index.
/// Any lost ACK/Err/unwind permanently retains the caller's originals; a retry
/// cannot rerun retirement or infer success from a Stopped snapshot.
#[derive(Default)]
pub(crate) struct InitialDataCompletionState {
    attempted: bool,
    completed: Option<nelomai_client_tunnel::redundancy::session::SessionSnapshot>,
}
impl InitialDataCompletionState {
    pub(crate) fn save(
        &mut self,
        scope: &SessionScope,
        snapshot: &nelomai_client_tunnel::redundancy::session::SessionSnapshot,
        persist: impl FnOnce(
            &nelomai_client_tunnel::redundancy::session::SessionSnapshot,
        ) -> io::Result<()>,
        retire: impl FnOnce() -> io::Result<()>,
        complete: impl FnOnce(&SessionScope) -> io::Result<()>,
        release: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        if &snapshot.scope != scope || !scope.validate() {
            return Err(failed());
        }
        if let Some(acknowledged) = &self.completed {
            return if acknowledged == snapshot {
                Ok(())
            } else {
                Err(failed())
            };
        }
        if self.attempted {
            return Err(failed());
        }
        if snapshot.phase != nelomai_client_tunnel::redundancy::session::SessionPhase::Stopped {
            return persist(snapshot);
        }
        self.attempted = true; // BEFORE any fallible ACK boundary or unwind
        persist(snapshot)?;
        retire()?;
        complete(scope)?;
        release()?;
        self.completed = Some(snapshot.clone());
        Ok(())
    }
}
impl CompletionState {
    pub(crate) fn save(
        &mut self,
        scope: &SessionScope,
        snapshot: &nelomai_client_tunnel::redundancy::session::SessionSnapshot,
        persist: impl FnOnce(
            &nelomai_client_tunnel::redundancy::session::SessionSnapshot,
        ) -> io::Result<()>,
        complete: impl FnOnce(&SessionScope) -> io::Result<()>,
    ) -> io::Result<()> {
        if &snapshot.scope != scope || !scope.validate() {
            return Err(failed());
        }
        if let Some(saved) = &self.completed {
            return if saved == snapshot {
                Ok(())
            } else {
                Err(failed())
            };
        }
        persist(snapshot)?;
        if snapshot.phase == nelomai_client_tunnel::redundancy::session::SessionPhase::Stopped {
            complete(scope)?;
            self.completed = Some(snapshot.clone());
        }
        Ok(())
    }
}
/// Only after exact native/route/DNS/guard cleanup has succeeded. A crash after
/// initial Pair save but before initial Session save needs a terminal record,
/// not a resurrected role. Zero generations here are tombstone metadata only.
pub(crate) fn stopped_after_cleanup(
    scope: &SessionScope,
    saved: Option<nelomai_client_tunnel::redundancy::session::SessionSnapshot>,
) -> io::Result<nelomai_client_tunnel::redundancy::session::SessionSnapshot> {
    use nelomai_client_tunnel::redundancy::session::SessionState;
    let saved = match saved {
        Some(saved) => saved,
        None => SessionState::new(scope.clone(), Slot::A, 0, 0)
            .map_err(|_| failed())?
            .snapshot(),
    };
    let mut state =
        SessionState::recover_for_cleanup(scope.clone(), saved).map_err(|_| failed())?;
    state.stopped(scope).map_err(|_| failed())?;
    Ok(state.snapshot())
}
/// Claim-before-first-record crash gap only. Missing durable data alone grants
/// no cleanup authority. The serialized owner must positively observe BOTH
/// native slots and the exact scope's WFP key universe as empty, twice. This
/// authorizes only a durable claim tombstone, never native deletion or Start.
pub(crate) fn verify_empty_claim(
    scope: &SessionScope,
    records_present: [bool; 3],
    mut slot_observation: impl FnMut(
        Slot,
    ) -> io::Result<(
        Option<OwnerRecord>,
        crate::member_owner::Observation,
    )>,
    mut guard_snapshot: impl FnMut() -> io::Result<crate::member_guard::Snapshot>,
) -> io::Result<()> {
    if records_present.into_iter().any(|present| present) {
        return Err(failed());
    }
    let expected = Model::empty(scope.clone()).map_err(|_| failed())?.expected;
    for _ in 0..2 {
        for slot in [Slot::A, Slot::B] {
            let (record, observed) = slot_observation(slot)?;
            match &record {
                Some(record) => {
                    crate::member_owner::validate_record_shape(record).map_err(|_| failed())?;
                    if record.intent.slot != slot_native(slot)
                        || record.phase != crate::member_owner::Phase::Stopped
                        || record.intent.scope == *scope
                        || observed.config_sha256.is_some_and(|hash| {
                            hash != record.intent.config_sha256
                                && Some(hash) != record.previous_config_sha256
                        })
                    {
                        return Err(failed());
                    }
                }
                None if observed.config_sha256.is_some() => return Err(failed()),
                None => (),
            }
            if observed.service.is_some()
                || observed.alternative_service_present
                || observed.interface.is_some()
                || !observed.retained_interfaces.is_empty()
            {
                return Err(failed());
            }
        }
        if guard_snapshot()? != expected {
            return Err(failed());
        }
    }
    Ok(())
}
pub(crate) trait PairSocket: ProbeDatagram + Sized {
    fn duplicate(&self) -> io::Result<Self>;
}
impl PairSocket for nelomai_client_tunnel::redundancy::NativeProbeSocket {
    fn duplicate(&self) -> io::Result<Self> {
        self.try_clone()
    }
}

/// Only native effects/discovery are replaceable. Ordering and durable guard/DNS
/// transitions remain in SessionNativePair, including in fake-channel tests.
pub(crate) trait PairIo {
    type Socket: PairSocket;
    fn prepare_member(&mut self, scope: &SessionScope, member: &Member)
        -> io::Result<MemberRecord>;
    fn start(&mut self, member: &MemberRecord) -> io::Result<OwnerRecord>;
    fn current(&mut self, slot: Slot) -> io::Result<Option<OwnerRecord>>;
    /// Cleanup-only CAS gap proof. Returning true cannot start/adopt anything.
    fn abandon_unstarted(&mut self, _member: &MemberRecord) -> io::Result<bool> {
        Ok(false)
    }
    fn verify(&mut self, member: &MemberRecord) -> io::Result<()>;
    /// Read-only scoped endpoint check; never consult the singleton journal.
    /// Called after route activation and before admitting health/probe work.
    fn verify_endpoint(&mut self, member: &MemberRecord) -> io::Result<()>;
    fn confirm_absent(&mut self, member: &MemberRecord) -> io::Result<bool>;
    /// Read-only only: a platform may additionally attest its exact stopped
    /// service with no process/interface. Cleanup still uses confirm_absent.
    fn confirm_inactive_for_discovery(&mut self, member: &MemberRecord) -> io::Result<bool> {
        self.confirm_absent(member)
    }
    fn stop(&mut self, member: &MemberRecord) -> io::Result<OwnerRecord>;
    fn rebind(&mut self, member: &MemberRecord) -> io::Result<OwnerRecord>;
    fn observe(&mut self, member: &MemberRecord)
        -> io::Result<(TunnelMetrics, NativeHealthSample)>;
    fn fingerprint(&mut self, members: &[Option<MemberRecord>; 2]) -> io::Result<String>;
    fn open_base(&mut self, member: &MemberRecord) -> io::Result<(Self::Socket, ProbeTuple)>;
    fn guard_snapshot(&mut self) -> io::Result<crate::member_guard::Snapshot>;
    fn guard_exchange(&mut self, plan: &ExchangePlan) -> io::Result<Model>;
    fn close_permits(&mut self) -> io::Result<()>;
    /// Uses the existing NetworkOwner: durable intent, exact row CAS and
    /// readback/rollback. No preexisting route adoption; no physical metric edits.
    fn select_routes(
        &mut self,
        active: Slot,
        members: &[Option<MemberRecord>; 2],
        options: &DesktopTunnelOptions,
    ) -> io::Result<()>;
    fn cleanup_routes(&mut self) -> io::Result<()>;
    fn read_dns(&mut self, member: &MemberRecord) -> io::Result<DnsSnapshot>;
    fn exchange_dns(&mut self, expected: &DnsSnapshot, desired: &DnsSnapshot) -> io::Result<()>;
}
/// Read-only discovery may outlive a member. Failure to prove liveness is NOT
/// absence: require the exact owner journal/config/retained identities to prove
/// no live native resources instead. This grants no mutation or Start authority.
pub(crate) fn verify_physical_members<I: PairIo>(
    io: &mut I,
    members: &[Option<MemberRecord>; 2],
) -> io::Result<()> {
    for member in members.iter().flatten() {
        if let Err(error) = io.verify(member) {
            if !io.confirm_inactive_for_discovery(member)? {
                return Err(error);
            }
        }
    }
    Ok(())
}
/// Route targets contain only live members. A durably retired member remains
/// in the pair/proof journal for exact cleanup, never in a new route plan.
pub(crate) fn live_route_members<I: PairIo>(
    io: &mut I,
    active: Slot,
    members: &[Option<MemberRecord>; 2],
) -> io::Result<[Option<MemberRecord>; 2]> {
    io.verify(members[active.idx()].as_ref().ok_or_else(failed)?)?;
    let mut live = members.clone();
    for slot in [Slot::A, Slot::B] {
        let Some(member) = &members[slot.idx()] else {
            continue;
        };
        if slot != active && member.owner.phase == crate::member_owner::Phase::Stopped {
            if !io.confirm_absent(member)? {
                return Err(failed());
            }
            live[slot.idx()] = None;
        } else {
            io.verify(member)?;
        }
    }
    Ok(live)
}

pub(crate) struct SessionNativePair<I: PairIo, J: PairStore> {
    io: RefCell<I>,
    store: J,
    record: PairRecord,
    sockets: [Option<I::Socket>; 2],
    tuples: [Option<ProbeTuple>; 2],
    recovery: bool,
    closed: bool,
    // A synchronous rebind failed. Before discovery can retry it, the existing
    // tick must reconcile the guard and prove that the owners are still usable.
    rebind_pending: bool,
    // Retain an observed assignment even if its durable acknowledgement fails.
    // Retry that exact record before any further guard reconciliation/effects.
    guard_save_pending: bool,
    // Sticky for this owned process. Never repair/adopt a vanished guard or
    // resume health after integrity loss; retain journals for exact cleanup.
    integrity_fault: Option<io::Error>,
}
impl<I: PairIo, J: PairStore> SessionNativePair<I, J> {
    #[cfg(test)] // Legacy construction is covered for cleanup regressions only.
    pub(crate) fn new(scope: SessionScope, mut io: I, mut store: J) -> io::Result<Self> {
        if !scope.validate() {
            return Err(failed());
        }
        let guard = Model::empty(scope.clone()).map_err(|_| failed())?;
        if io.guard_snapshot()? != guard.expected {
            return Err(failed());
        }
        let record = PairRecord {
            scope,
            members: [None, None],
            active: None,
            guard,
            pending_guard: None,
            dns: [None, None],
            options: None,
            closing: false,
        };
        store.save(&record)?;
        Ok(Self {
            io: RefCell::new(io),
            store,
            record,
            sockets: [None, None],
            tuples: [None, None],
            recovery: false,
            closed: false,
            rebind_pending: false,
            guard_save_pending: false,
            integrity_fault: None,
        })
    }
    pub(crate) fn recover_for_cleanup(
        scope: SessionScope,
        io: I,
        store: J,
        record: PairRecord,
    ) -> io::Result<Self> {
        if !scope.validate() || record.scope != scope || record.guard.scope != scope {
            return Err(failed());
        }
        record.guard.validate().map_err(|_| failed())?;
        for (i, m) in record
            .members
            .iter()
            .enumerate()
            .filter_map(|(i, m)| m.as_ref().map(|m| (i, m)))
        {
            if m.owner.intent.scope != scope || slot_shared(m.owner.intent.slot).idx() != i {
                return Err(failed());
            }
            if let Some(prior) = &m.prior_stopped {
                crate::member_owner::validate_prior_stopped(&m.owner.intent, prior)
                    .map_err(|_| failed())?;
            }
        }
        if let Some(p) = &record.pending_guard {
            if p.expected != record.guard
                || p.expected.scope != scope
                || *p != ExchangePlan::new(&p.expected, &p.desired).map_err(|_| failed())?
            {
                return Err(failed());
            }
        }
        Ok(Self {
            io: RefCell::new(io),
            store,
            record,
            sockets: [None, None],
            tuples: [None, None],
            recovery: true,
            closed: false,
            integrity_fault: None,
            rebind_pending: false,
            guard_save_pending: false,
        })
    }
    fn check(&self, scope: &SessionScope) -> io::Result<()> {
        if *scope != self.record.scope || !scope.validate() {
            Err(failed())
        } else {
            Ok(())
        }
    }
    fn save(&mut self) -> io::Result<()> {
        self.store
            .save(&self.record)
            .map_err(|e| crate::member_diagnostic::context("pair_journal", e))
    }
    fn live(&self, slot: Slot) -> io::Result<&MemberRecord> {
        if self.recovery
            || self.record.closing
            || self.guard_save_pending
            || self.record.pending_guard.is_some()
            || self.record.active.is_none()
        {
            return Err(failed());
        }
        if self.record.guard.active != self.record.active
            || self.io.borrow_mut().guard_snapshot()? != self.record.guard.expected
        {
            return Err(failed());
        }
        let m = self.record.members[slot.idx()]
            .as_ref()
            .ok_or_else(failed)?;
        self.io.borrow_mut().verify(m)?;
        self.io
            .borrow_mut()
            .verify_endpoint(m)
            .map_err(|e| crate::member_diagnostic::context("endpoint_verify", e))?;
        Ok(m)
    }
    fn model(&self, active: Option<Slot>, probes: bool) -> io::Result<Model> {
        let mut members = [None, None];
        for slot in [Slot::A, Slot::B] {
            if let Some(m) = &self.record.members[slot.idx()] {
                if let Some(proof) = m.owner.proof {
                    members[slot.idx()] = Some(crate::member_guard::Member {
                        interface: crate::member_guard::Interface {
                            index: proof.interface.index,
                            luid: proof.interface.luid,
                        },
                        probes: if probes {
                            self.tuples[slot.idx()].iter().cloned().collect()
                        } else {
                            vec![]
                        },
                    });
                }
            }
        }
        if members.iter().all(Option::is_none) {
            Model::empty(self.record.scope.clone()).map_err(|_| failed())
        } else {
            Model::new(self.record.scope.clone(), members, active)
                .and_then(|m| m.inherit_sublayer_weight(&self.record.guard))
                .map_err(|_| failed())
        }
    }
    fn reconcile_guard(&mut self) -> io::Result<()> {
        if self.guard_save_pending {
            self.save()?;
            self.guard_save_pending = false;
        }
        let actual = self.io.borrow_mut().guard_snapshot()?;
        let empty = Model::empty(self.record.scope.clone()).map_err(|_| failed())?;
        if (self.record.closing || self.recovery) && actual == empty.expected {
            // BFE restart can remove the entire exact guard universe. This is
            // cleanup authority only AFTER every retained native owner proves
            // absence, never a missing-read/foreign-filter or active-run adopt.
            for member in self.record.members.iter().flatten() {
                if !self.io.borrow_mut().confirm_absent(member)? {
                    return Err(failed());
                }
            }
            if self.record.guard != empty || self.record.pending_guard.is_some() {
                self.record.guard = empty;
                self.record.pending_guard = None;
                self.save()?;
            }
            return Ok(());
        }
        if let Some(p) = &self.record.pending_guard {
            if p.expected != self.record.guard {
                return Err(failed());
            }
            let reconciled = p
                .resolve(&actual)
                .map_err(|e| crate::PairFailure::guard("guard_reconcile", e))?;
            // The observed assignment must be durable before cleanup or any
            // later exchange can use it as its exact CAS precondition.
            self.acknowledge_guard(reconciled)?;
        } else if actual != self.record.guard.expected {
            // Recovery or a previous failed Stop may have closed our dynamic
            // session. Accept only its exact withdrawal, including the pinned
            // sublayer and all static filters; never adopt it on a live pair.
            let withdrawn = self.record.guard.without_probes().map_err(|_| failed())?;
            if !(self.recovery || self.record.closing) || actual != withdrawn.expected {
                return Err(failed());
            }
            if !self.recovery {
                // In-process cleanup must also confirm that THIS dynamic
                // session is closed. Re-read after closing: a concurrent foreign
                // change must not become the precondition of the next exchange.
                self.io.borrow_mut().close_permits()?;
                if self.io.borrow_mut().guard_snapshot()? != withdrawn.expected {
                    return Err(failed());
                }
            }
            self.acknowledge_guard(withdrawn)?;
        }
        Ok(())
    }
    fn guard(&mut self, desired: Model) -> io::Result<()> {
        self.reconcile_guard()?;
        let desired = desired
            .inherit_sublayer_weight(&self.record.guard)
            .map_err(|e| crate::PairFailure::guard("guard_plan", e))?;
        if self.record.guard == desired {
            return Ok(());
        }
        let plan = ExchangePlan::new(&self.record.guard, &desired)
            .map_err(|e| crate::PairFailure::guard("guard_plan", e))?;
        self.record.pending_guard = Some(plan.clone());
        self.save()?;
        let committed = self.io.borrow_mut().guard_exchange(&plan)?;
        let actual = self.io.borrow_mut().guard_snapshot()?;
        if actual != committed.expected
            || desired
                .readback_after(&plan.expected, &actual)
                .map_err(|e| crate::PairFailure::guard("guard_readback", e))?
                != committed
        {
            return Err(crate::member_diagnostic::context(
                "guard_readback",
                failed(),
            ));
        }
        self.acknowledge_guard(committed)
    }
    fn acknowledge_guard(&mut self, committed: Model) -> io::Result<()> {
        self.record.guard = committed;
        self.record.pending_guard = None;
        self.guard_save_pending = true;
        self.save()?;
        self.guard_save_pending = false;
        Ok(())
    }
    fn fence(&mut self) -> io::Result<()> {
        self.guard(self.model(None, false)?)
    }
    fn verify_discovery_guard(&self) -> io::Result<()> {
        // A failed rebind can leave our fully acknowledged blocking model in
        // place. This grants discovery, not permission to adopt an unknown WFP
        // state or restore traffic through an incompletely restarted member.
        let fenced = self.record.guard.installed
            && self.record.guard.active.is_none()
            && self.record.guard == self.record.guard.without_probes().map_err(|_| failed())?;
        if self.recovery
            || self.record.closing
            || self.integrity_fault.is_some()
            || self.guard_save_pending
            || self.record.pending_guard.is_some()
            || self.record.active.is_none()
            || (self.record.guard.active != self.record.active && !fenced)
            || self.io.borrow_mut().guard_snapshot()? != self.record.guard.expected
        {
            return Err(failed());
        }
        Ok(())
    }
    fn reconcile_rebind_failure(&mut self) -> io::Result<()> {
        // Lost journal/guard ACKs are retryable only with exact readback and a
        // durable reconciled record. Prepared owners are NOT running authority:
        // if native rebind interrupted a member, use normal close/recovery.
        self.reconcile_guard()?;
        self.verify_discovery_guard()?;
        let active = self.record.active.ok_or_else(failed)?;
        self.io.borrow_mut().verify(
            self.record.members[active.idx()]
                .as_ref()
                .ok_or_else(failed)?,
        )?;
        verify_physical_members(&mut *self.io.borrow_mut(), &self.record.members)?;
        self.save()
    }
    fn refresh(&mut self, slot: Slot) -> io::Result<()> {
        if let Some(current) = self.io.borrow_mut().current(slot)? {
            let m = self.record.members[slot.idx()]
                .as_mut()
                .ok_or_else(failed)?;
            if current.intent != m.owner.intent {
                return Err(failed());
            }
            m.owner = current;
        }
        self.save()
    }
    fn install(&mut self, m: &Member) -> io::Result<()> {
        if self.record.members[m.slot.idx()].is_some() {
            return Err(failed());
        }
        m.validate()?;
        let prepared = self
            .io
            .borrow_mut()
            .prepare_member(&self.record.scope, m)
            .map_err(|e| crate::member_diagnostic::context("member_prepare", e))?;
        if prepared.owner.intent.scope != self.record.scope
            || prepared.owner.intent.slot != slot_native(m.slot)
        {
            return Err(failed());
        }
        self.record.members[m.slot.idx()] = Some(prepared.clone());
        self.save()?;
        let result = self
            .io
            .borrow_mut()
            .start(&prepared)
            .map_err(|e| crate::member_diagnostic::context("member_start", e));
        if result.is_err() && self.io.borrow_mut().abandon_unstarted(&prepared)? {
            // Retain the exact Pair intent until explicit cleanup saves removal.
            return result.map(|_| ());
        }
        self.refresh(m.slot)?;
        result?;
        // No probe or globally visible inactive route exists before this fence.
        self.fence()?;
        // IP_UNICAST_IF connect requires a route on the bound interface. Add
        // the new member's probe route while BOTH members remain fenced; keep
        // the existing primary selected on attach. No permit is admitted until
        // activate has also established DNS and checked exact endpoint identity.
        self.routes(self.record.active.unwrap_or(m.slot))?;
        let member = self.record.members[m.slot.idx()]
            .as_ref()
            .ok_or_else(failed)?;
        let (socket, tuple) = self
            .io
            .borrow_mut()
            .open_base(member)
            .map_err(|e| crate::member_diagnostic::context("probe_socket", e))?;
        self.sockets[m.slot.idx()] = Some(socket);
        self.tuples[m.slot.idx()] = Some(tuple);
        Ok(())
    }
    fn dns(&mut self, active: Option<Slot>) -> io::Result<()> {
        for slot in [Slot::A, Slot::B] {
            let Some(member) = self.record.members[slot.idx()].clone() else {
                continue;
            };
            if member.dns.is_empty() {
                continue;
            }
            // All DNS writes are preceded by a durable baseline. If activation
            // never reached that point, cleanup has no DNS mutation to undo.
            // Do not invent a baseline/read from an already failing interface.
            if active != Some(slot) && self.record.dns[slot.idx()].is_none() {
                continue;
            }
            if active != Some(slot)
                && member.owner.phase == crate::member_owner::Phase::Stopped
                && self.io.borrow_mut().confirm_absent(&member)?
            {
                // Per-member DNS disappears with that exact owned interface.
                // Never write the baseline onto a reused index/new interface.
                self.record.dns[slot.idx()] = None;
                self.save()?;
                continue;
            }
            if self.record.dns[slot.idx()].is_none() {
                let baseline = self.io.borrow_mut().read_dns(&member)?;
                self.record.dns[slot.idx()] = Some(DnsRecord {
                    baseline: baseline.clone(),
                    current: baseline,
                    pending: None,
                });
                self.save()?;
            }
            let saved = self.record.dns[slot.idx()].as_ref().unwrap().clone();
            let actual = self.io.borrow_mut().read_dns(&member)?;
            if actual != saved.current && saved.pending.as_ref() != Some(&actual) {
                return Err(failed());
            }
            let desired = if active == Some(slot) {
                saved
                    .baseline
                    .with_servers(&member.dns)
                    .map_err(|_| failed())?
            } else {
                saved.baseline.clone()
            };
            self.record.dns[slot.idx()].as_mut().unwrap().pending = Some(desired.clone());
            self.save()?;
            if actual != desired {
                self.io.borrow_mut().exchange_dns(&actual, &desired)?;
            }
            if self.io.borrow_mut().read_dns(&member)? != desired {
                return Err(crate::member_diagnostic::context("dns_readback", failed()));
            }
            let saved = self.record.dns[slot.idx()].as_mut().unwrap();
            saved.current = desired;
            saved.pending = None;
            self.save()?;
        }
        Ok(())
    }
    fn routes(&mut self, slot: Slot) -> io::Result<()> {
        self.io.borrow_mut().select_routes(
            slot,
            &self.record.members,
            self.record.options.as_ref().ok_or_else(failed)?,
        )?;
        let live = live_route_members(&mut *self.io.borrow_mut(), slot, &self.record.members)?;
        for member in live.iter().flatten() {
            self.io
                .borrow_mut()
                .verify_endpoint(member)
                .map_err(|e| crate::member_diagnostic::context("endpoint_verify", e))?;
        }
        Ok(())
    }
    // Caller must fence dynamic permits before retiring native or releasing
    // sockets. Keep the stopped owner until route/DNS cleanup has acknowledged
    // its exact absence; discovery alone never authorizes slot reuse.
    fn retire_inactive(&mut self, slot: Slot) -> io::Result<()> {
        let member = self.record.members[slot.idx()].clone().ok_or_else(failed)?;
        if !self
            .io
            .borrow_mut()
            .confirm_inactive_for_discovery(&member)?
        {
            return Err(failed());
        }
        let stopped = self.io.borrow_mut().stop(&member);
        self.refresh(slot)?;
        stopped?;
        let member = self.record.members[slot.idx()]
            .as_ref()
            .ok_or_else(failed)?;
        if member.owner.phase != crate::member_owner::Phase::Stopped
            || !self.io.borrow_mut().confirm_absent(member)?
        {
            return Err(failed());
        }
        self.release(slot);
        Ok(())
    }
    fn activate(&mut self, slot: Slot) -> io::Result<()> {
        if self.recovery || self.record.closing || self.record.members[slot.idx()].is_none() {
            return Err(failed());
        }
        self.io.borrow_mut().verify(
            self.record.members[slot.idx()]
                .as_ref()
                .ok_or_else(failed)?,
        )?;
        let mut retire = Vec::new();
        for other in [Slot::A, Slot::B] {
            if other == slot {
                continue;
            }
            if let Some(member) = &self.record.members[other.idx()] {
                let verified = self.io.borrow_mut().verify(member);
                if let Err(error) = verified {
                    if !self
                        .io
                        .borrow_mut()
                        .confirm_inactive_for_discovery(member)?
                    {
                        return Err(error);
                    }
                    retire.push(other);
                }
            }
        }
        let previous = self.record.active;
        self.fence()?;
        let result = (|| {
            for retired in retire {
                self.retire_inactive(retired)?;
            }
            self.routes(slot)?;
            self.dns(Some(slot))?;
            live_route_members(&mut *self.io.borrow_mut(), slot, &self.record.members)?;
            self.guard(self.model(Some(slot), true)?)?;
            Ok(())
        })();
        if let Err(error) = result {
            let rollback = (|| {
                self.fence()?;
                if let Some(old) = previous {
                    self.routes(old)?;
                    self.dns(Some(old))?;
                    self.guard(self.model(Some(old), true)?)?;
                } else {
                    self.io.borrow_mut().cleanup_routes()?;
                    self.dns(None)?;
                }
                Ok::<_, io::Error>(())
            })();
            if rollback.is_err() {
                self.record.closing = true;
                self.record.active = None;
                let _ = self.save();
            }
            return Err(error);
        }
        self.record.active = Some(slot);
        self.save()
    }
    fn release(&mut self, slot: Slot) {
        self.tuples[slot.idx()] = None;
        self.sockets[slot.idx()] = None;
    }
}
impl<I: PairIo, J: PairStore> NativePair for SessionNativePair<I, J> {
    type Socket = I::Socket;
    fn check_integrity(&mut self) -> io::Result<()> {
        if self.rebind_pending && self.integrity_fault.is_none() && !self.closed {
            match self.reconcile_rebind_failure() {
                Ok(()) => self.rebind_pending = false,
                Err(error) => self.integrity_fault = Some(error),
            }
        }
        if self.integrity_fault.is_none() && !self.recovery && !self.closed {
            let actual = self.io.borrow_mut().guard_snapshot();
            self.integrity_fault = match actual {
                Ok(actual) if actual == self.record.guard.expected => None,
                Ok(_) => Some(failed()),
                Err(error) => Some(error),
            };
        }
        if let Some(error) = &self.integrity_fault {
            let kind = error.kind();
            let scope = self.record.scope.clone();
            // This check runs on the existing helper tick, even with health
            // invalidated. Detection is bounded by serviced ticks/native calls,
            // not a continuous killswitch. Close still tries BOTH proven
            // members when guard, disk, route or DNS cleanup fails.
            let _ = self.close(&scope);
            return Err(io::Error::new(kind, "native pair integrity lost"));
        }
        Ok(())
    }
    fn sample(&mut self, slot: Slot) -> Option<NativeHealthSample> {
        self.check_integrity().ok()?;
        let m = self.live(slot).ok()?.clone();
        self.io.borrow_mut().observe(&m).ok().map(|v| v.1)
    }
    fn open_probe(&mut self, slot: Slot) -> io::Result<(Self::Socket, String)> {
        let name = self.live(slot)?.probe.query_name.clone();
        let socket = self.sockets[slot.idx()]
            .as_ref()
            .ok_or_else(failed)?
            .duplicate()?;
        Ok((socket, name))
    }
    fn select_active(&mut self, scope: &SessionScope, slot: Slot) -> io::Result<()> {
        self.check(scope)?;
        self.activate(slot)
    }
    fn close(&mut self, scope: &SessionScope) -> io::Result<()> {
        self.check(scope)?;
        if self.closed {
            return Ok(());
        }
        self.record.closing = true;
        self.record.active = None;
        let mut error = None;
        for slot in [Slot::A, Slot::B] {
            if let Some(member) = self.record.members[slot.idx()].clone() {
                let result = self.io.borrow_mut().abandon_unstarted(&member);
                match result {
                    Ok(true) => {
                        self.record.members[slot.idx()] = None;
                    }
                    Ok(false) => (),
                    Err(e) => {
                        remember::<()>(&mut error, Err(e));
                    }
                }
            }
        }
        remember(&mut error, self.save());
        let fenced = self.reconcile_guard().and_then(|_| {
            // Exact empty reconciliation already proved all retained owners
            // absent. Do not recreate filters from a stale retained proof.
            if self.record.guard == Model::empty(self.record.scope.clone()).map_err(|_| failed())? {
                Ok(())
            } else {
                self.fence()
            }
        });
        let permits_removed = fenced.is_ok();
        remember(&mut error, fenced);
        let permits_removed = if permits_removed {
            true
        } else {
            let result = self.io.borrow_mut().close_permits();
            let removed = result.is_ok();
            remember(&mut error, result);
            removed
        };
        if permits_removed {
            for slot in [Slot::A, Slot::B] {
                self.release(slot);
            }
        }
        remember(&mut error, self.io.borrow_mut().cleanup_routes());
        remember(&mut error, self.dns(None));
        for slot in [Slot::A, Slot::B] {
            if let Some(m) = self.record.members[slot.idx()].clone() {
                if m.owner.phase != crate::member_owner::Phase::Stopped {
                    let result = self.io.borrow_mut().stop(&m);
                    remember(&mut error, result.map(|_| ()));
                    remember(&mut error, self.refresh(slot));
                }
            }
        }
        // Keep every proof and pending resource if any cleanup failed. The next
        // tick/Stop retries exact cleanup; never report terminal success early.
        if let Some(error) = error {
            return Err(error);
        }
        self.guard(Model::empty(self.record.scope.clone()).map_err(|_| failed())?)?;
        let mut complete = self.record.clone();
        complete.members = [None, None];
        complete.dns = [None, None];
        complete.closing = false;
        self.store.save(&complete)?;
        self.record = complete;
        self.closed = true;
        Ok(())
    }
}
impl<I: PairIo, J: PairStore> PairControl for SessionNativePair<I, J> {
    fn complete_start(&mut self, scope: &SessionScope) -> io::Result<()> {
        self.check(scope)?;
        self.check_integrity()
    }
    fn metrics(&self, slot: Slot) -> io::Result<TunnelMetrics> {
        if self.record.active != Some(slot) {
            return Err(failed());
        }
        let m = self.live(slot)?;
        self.io.borrow_mut().observe(m).map(|v| v.0)
    }
    fn physical_network_fingerprint(&self) -> io::Result<String> {
        if self.rebind_pending {
            return Err(failed());
        }
        self.verify_discovery_guard()?;
        let mut io = self.io.borrow_mut();
        verify_physical_members(&mut *io, &self.record.members)?;
        let fingerprint = io.fingerprint(&self.record.members)?;
        verify_physical_members(&mut *io, &self.record.members)?;
        Ok(fingerprint)
    }
    fn start_primary(
        &mut self,
        scope: &SessionScope,
        m: &Member,
        o: &DesktopTunnelOptions,
    ) -> io::Result<()> {
        self.check(scope)?;
        o.validate().map_err(|_| failed())?;
        if self.recovery || self.record.options.is_some() || self.record.closing {
            return Err(failed());
        }
        self.record.options = Some(o.clone());
        self.save()?;
        self.install(m)?;
        self.activate(m.slot)
    }
    fn attach(&mut self, scope: &SessionScope, m: &Member) -> io::Result<()> {
        self.check(scope)?;
        let active = self.record.active.ok_or_else(failed)?;
        self.live(active)?;
        if m.slot == active {
            return Err(failed());
        }
        self.install(m)?;
        self.activate(active)
    }
    fn remove_standby(&mut self, scope: &SessionScope, slot: Slot) -> io::Result<()> {
        self.check(scope)?;
        let active = self.record.active.ok_or_else(failed)?;
        if active == slot || self.recovery || self.record.closing {
            return Err(failed());
        }
        let Some(m) = self.record.members[slot.idx()].clone() else {
            return Ok(());
        };
        let previous_guard = self.record.guard.clone();
        // Exclude the retiring member from the target route set while retaining
        // its durable identity until DNS restoration and native Stop complete.
        let mut retained = self.record.members.clone();
        retained[slot.idx()] = None;
        let result = (|| {
            self.fence()?;
            // A crashed reserve has no interface on which to restore DNS or
            // read routes. First finish exact owned Stop (including a stopped
            // SCM service) and refresh retained proofs used by route cleanup.
            let live = self.io.borrow_mut().verify(&m).is_ok();
            if !live {
                self.retire_inactive(slot)?;
            }
            self.io.borrow_mut().select_routes(
                active,
                &retained,
                self.record.options.as_ref().ok_or_else(failed)?,
            )?;
            self.dns(Some(active))?;
            if live {
                let result = self.io.borrow_mut().stop(&m);
                self.refresh(slot)?;
                result?;
            }
            self.release(slot);
            self.record.members[slot.idx()] = None;
            self.record.dns[slot.idx()] = None;
            self.save()?;
            self.guard(self.model(Some(active), true)?)
        })();
        if let Err(error) = result {
            let restored = (|| {
                // Restore only while both original member proofs still hold.
                // If native Stop partially applied, fall through to pair close;
                // never recreate the retired reserve merely to fake rollback.
                for member in self.record.members.iter().flatten() {
                    self.io.borrow_mut().verify(member)?;
                }
                self.fence()?;
                self.routes(active)?;
                self.dns(Some(active))?;
                self.guard(previous_guard)?;
                Ok::<_, io::Error>(())
            })();
            if restored.is_err() {
                // close owns both the retryable failure state and the durable
                // terminal ACK. Do not reopen a successfully closed record:
                // subsequent idempotent close would then leave closing=true
                // forever and prevent the session completion tombstone.
                let _ = self.close(scope);
            }
            return Err(error);
        }
        Ok(())
    }
    fn complete_rebind(&mut self, scope: &SessionScope) -> io::Result<()> {
        self.check(scope)?;
        self.check_integrity()
    }
    fn rebind_pair(&mut self, scope: &SessionScope) -> io::Result<bool> {
        self.check(scope)?;
        // Do not enter another native transaction before the previous failure
        // has a proven retry or terminal outcome on the existing helper tick.
        if self.rebind_pending || self.integrity_fault.is_some() {
            return Err(failed());
        }
        self.rebind_pending = true;
        let result = (|| {
            let active = self.record.active.ok_or_else(failed)?;
            if self.recovery || self.record.closing {
                return Err(failed());
            }
            // Discovery may observe a crashed reserve before the UI retires it.
            // Prove the active live and all other identities before any mutation;
            // then use existing exact Stop under the fence, not liveness as a
            // prerequisite for restoring health on the surviving primary.
            self.io.borrow_mut().verify(
                self.record.members[active.idx()]
                    .as_ref()
                    .ok_or_else(failed)?,
            )?;
            verify_physical_members(&mut *self.io.borrow_mut(), &self.record.members)?;
            self.fence()?;
            let inactive = active.other();
            if let Some(member) = &self.record.members[inactive.idx()] {
                let live = self.io.borrow_mut().verify(member).is_ok();
                if !live {
                    self.retire_inactive(inactive)?;
                }
            }
            // Keep the retired record for normal membership cleanup, but never
            // restart it or open a probe socket on its missing interface.
            let live =
                live_route_members(&mut *self.io.borrow_mut(), active, &self.record.members)?;
            for slot in [Slot::A, Slot::B] {
                self.release(slot);
            }
            self.io.borrow_mut().cleanup_routes()?;
            self.dns(None)?;
            self.record.dns = [None, None];
            self.save()?;
            for slot in [Slot::A, Slot::B] {
                if let Some(m) = live[slot.idx()].clone() {
                    let result = self.io.borrow_mut().rebind(&m);
                    self.refresh(slot)?;
                    result?;
                }
            }
            self.fence()?;
            let live =
                live_route_members(&mut *self.io.borrow_mut(), active, &self.record.members)?;
            // Rebind removed the old routes above. Restore owned probe routes
            // under the fence before connecting the replacement base sockets.
            self.routes(active)?;
            for slot in [Slot::A, Slot::B] {
                if let Some(m) = &live[slot.idx()] {
                    let (socket, tuple) = self.io.borrow_mut().open_base(m)?;
                    self.sockets[slot.idx()] = Some(socket);
                    self.tuples[slot.idx()] = Some(tuple);
                }
            }
            self.activate(active)?;
            Ok(true)
        })();
        if result.is_ok() {
            self.rebind_pending = false;
        }
        result
    }
    fn cleanup_pending(&self) -> bool {
        self.record.closing
            || self.guard_save_pending
            || self.record.pending_guard.is_some()
            || self
                .record
                .dns
                .iter()
                .flatten()
                .any(|d| d.pending.is_some())
    }
}
impl<I: PairIo, J: PairStore> Drop for SessionNativePair<I, J> {
    fn drop(&mut self) {
        if self.io.get_mut().close_permits().is_err() {
            // Keep exclusive source ports reserved if permit removal cannot be
            // proven. The owned engine process must exit; never hand them back
            // to another local socket while an allow rule may still exist.
            for socket in &mut self.sockets {
                if let Some(socket) = socket.take() {
                    std::mem::forget(socket);
                }
            }
        }
    }
}
pub(crate) fn slot_native(s: Slot) -> TunnelSlot {
    match s {
        Slot::A => TunnelSlot::A,
        Slot::B => TunnelSlot::B,
    }
}
pub(crate) trait SlotIndex {
    fn idx(self) -> usize;
}
impl SlotIndex for Slot {
    fn idx(self) -> usize {
        match self {
            Slot::A => 0,
            Slot::B => 1,
        }
    }
}
pub(crate) fn slot_shared(s: TunnelSlot) -> Slot {
    match s {
        TunnelSlot::A => Slot::A,
        TunnelSlot::B => Slot::B,
    }
}
pub(crate) fn failed() -> io::Error {
    io::Error::other("owned_pair_operation_failed")
}
fn remember<T>(first: &mut Option<io::Error>, result: io::Result<T>) {
    if let Err(error) = result {
        if first.is_none() {
            *first = Some(error);
        }
    }
}

pub(crate) struct MemberParameters {
    pub source: Ipv4Addr,
    pub endpoint: IpAddr,
    pub peer: [u8; 32],
    pub allowed: Vec<ipnet::IpNet>,
    pub dns: Vec<IpAddr>,
}
impl MemberParameters {
    pub(crate) fn parse(configuration: &str) -> io::Result<Self> {
        // Reuse the member renderer's section/hook validation and zeroization.
        let _canonical =
            crate::redundancy::slot_configuration(configuration).map_err(|_| failed())?;
        let mut fields = std::collections::BTreeMap::new();
        let mut section = "";
        for raw in configuration.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.starts_with('[') {
                section = if line.eq_ignore_ascii_case("[Interface]") {
                    "interface"
                } else {
                    "peer"
                };
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim().to_ascii_lowercase();
            if matches!(
                (section, key.as_str()),
                ("interface", "address" | "dns")
                    | ("peer", "endpoint" | "allowedips" | "publickey")
            ) && fields.insert(key, value.trim()).is_some()
            {
                return Err(failed());
            }
        }
        let get = |key: &str| fields.get(key).copied().ok_or_else(failed);
        let addresses = get("address")?
            .split(',')
            .map(|s| s.trim().parse::<ipnet::IpNet>().map_err(|_| failed()))
            .collect::<io::Result<Vec<_>>>()?;
        let sources = addresses
            .iter()
            .filter_map(|n| match n.addr() {
                IpAddr::V4(a) => Some(a),
                _ => None,
            })
            .collect::<Vec<_>>();
        if sources.len() != 1
            || sources[0].is_unspecified()
            || sources[0].is_loopback()
            || sources[0].is_multicast()
            || sources[0].is_broadcast()
        {
            return Err(failed());
        }
        let endpoint = get("endpoint")?
            .parse::<std::net::SocketAddr>()
            .map_err(|_| failed())?;
        if endpoint.port() == 0
            || endpoint.ip().is_unspecified()
            || endpoint.ip().is_loopback()
            || endpoint.ip().is_multicast()
        {
            return Err(failed());
        }
        let allowed = get("allowedips")?
            .split(',')
            .map(|s| s.trim().parse::<ipnet::IpNet>().map_err(|_| failed()))
            .collect::<io::Result<Vec<_>>>()?;
        if allowed.is_empty()
            || allowed.len() > crate::member_plan::MAX_ROUTES
            || allowed.iter().any(|n| *n != n.trunc())
        {
            return Err(failed());
        }
        let dns = fields
            .get("dns")
            .map(|s| {
                s.split(',')
                    .map(|v| v.trim().parse::<IpAddr>().map_err(|_| failed()))
                    .collect::<io::Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        if dns.len() > 16
            || dns
                .iter()
                .any(|a| !a.is_ipv4() || a.is_unspecified() || a.is_multicast())
        {
            return Err(failed());
        }
        Ok(Self {
            source: sources[0],
            endpoint: endpoint.ip(),
            peer: decode_peer(get("publickey")?)?,
            allowed,
            dns,
        })
    }
}
fn decode_peer(text: &str) -> io::Result<[u8; 32]> {
    // Strict canonical 32-byte WireGuard base64 key, without another dependency.
    if text.len() != 44 || !text.ends_with('=') {
        return Err(failed());
    }
    let mut bytes = [0u8; 32];
    let (mut bits, mut accumulator, mut out) = (0u32, 0u32, 0usize);
    for c in text.bytes().take(43) {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(failed()),
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes[out] = (accumulator >> bits) as u8;
            out += 1;
        }
        accumulator &= (1 << bits) - 1;
    }
    if out != 32 || accumulator != 0 || bytes == [0; 32] {
        return Err(failed());
    }
    Ok(bytes)
}
#[cfg(test)]
#[path = "member_pair_tests.rs"]
mod tests;
