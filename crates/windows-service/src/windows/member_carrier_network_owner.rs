//! Original-pin carrier network effect owner.
use crate::{member_dns as dns, member_pair::DnsRecord};
use std::{cell::Cell, io, net::IpAddr};
#[cfg_attr(all(windows, test), track_caller)]
fn conflict() -> io::Error {
    #[cfg(all(windows, test))]
    crate::windows::member_carrier_factory_test_os::trace_step(&format!(
        "network owner conflict at {}",
        std::panic::Location::caller()
    ));
    io::Error::other("carrier_network_effect_conflict")
}
// Original-owner comparison state. This ledger never authorizes SDK effects;
// its native writer is the private Calling/window capture capability below.
struct PhysicalPlans<L> {
    current: Option<Vec<L>>,
    published: Option<Vec<L>>,
    obligations: Vec<L>,
    revision: Option<u64>,
    capture_pending: bool,
    publication_started: bool,
}
impl<L> Default for PhysicalPlans<L> {
    fn default() -> Self {
        Self {
            current: None,
            published: None,
            obligations: Vec::new(),
            revision: None,
            capture_pending: false,
            publication_started: false,
        }
    }
}
impl<L: Clone + Eq> PhysicalPlans<L> {
    fn current(&self) -> io::Result<Vec<L>> {
        self.current.clone().ok_or_else(conflict)
    }
    fn obligations(&self) -> Vec<L> {
        self.obligations.clone()
    }
    fn retain(&mut self, revision: u64, leases: Vec<L>) -> io::Result<()> {
        if self.capture_pending
            || self.publication_started
            || self.current != self.published
            || self.revision.is_some_and(|old| revision <= old)
            || leases.len() > 32768
        {
            return Err(conflict());
        }
        let mut obligations = self.obligations.clone();
        for lease in &leases {
            if !obligations.contains(lease) {
                obligations.push(lease.clone());
            }
        }
        if obligations.len() > 32768 {
            return Err(conflict());
        }
        // Retain before the enclosing Source/Calling postflight or child save.
        self.obligations = obligations;
        self.current = Some(leases);
        self.revision = Some(revision);
        self.capture_pending = true;
        Ok(())
    }
    fn begin_publication(&mut self) -> io::Result<()> {
        self.current()?;
        self.publication_started = true;
        Ok(())
    }
    fn ack_publication(&mut self) -> io::Result<()> {
        if !self.publication_started {
            return Err(conflict());
        }
        self.published = Some(self.current()?);
        self.publication_started = false;
        self.capture_pending = false;
        Ok(())
    }
    fn accepts_saved(&self, leases: Option<&[L]>) -> io::Result<()> {
        if leases == self.published.as_deref()
            || (self.publication_started && leases == self.current.as_deref())
        {
            Ok(())
        } else {
            Err(conflict())
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RouteAttempt {
    pub row: crate::member_routes::Row,
    pub deleting: bool,
    pub acknowledged: bool,
}
fn begin_dns_effect(count: &Cell<usize>) -> io::Result<()> {
    if count.get() >= 32768 {
        return Err(conflict());
    }
    count.set(count.get() + 1);
    Ok(())
}
fn retained_route(
    attempts: &[RouteAttempt],
    row: &crate::member_routes::Row,
) -> io::Result<Option<crate::member_routes::Row>> {
    let Some(last) = attempts.iter().rev().find(|a| {
        a.row.route.destination == row.route.destination
            && a.row.route.interface == row.route.interface
    }) else {
        return Ok(None);
    };
    // A failed SDK call can have applied. No equal pending/native row adoption.
    if !last.acknowledged {
        return Err(conflict());
    }
    Ok((!last.deleting).then(|| last.row.clone()))
}
trait DnsSystem {
    fn read(&mut self) -> io::Result<dns::Snapshot>;
    /// Only SAME retained original owner can supply a pre-postflight ACK.
    /// Imported pending JSON/native equality is never its source.
    fn retained_ack(&mut self) -> io::Result<Option<dns::Snapshot>> {
        Ok(None)
    }
    fn exchange(
        &mut self,
        before: &dns::Snapshot,
        after: &dns::Snapshot,
    ) -> io::Result<dns::Snapshot>;
}
trait DnsJournal {
    fn save(&mut self, value: Option<&DnsRecord>) -> io::Result<()>;
}
struct DnsOwner<I, J> {
    io: I,
    journal: J,
    record: Option<DnsRecord>,
    ack: Option<dns::Snapshot>,
    cleanup_only: bool,
}
impl<I: DnsSystem, J: DnsJournal> DnsOwner<I, J> {
    fn fresh(io: I, journal: J) -> Self {
        Self {
            io,
            journal,
            record: None,
            ack: None,
            cleanup_only: false,
        }
    }
    fn select(&mut self, servers: &[IpAddr]) -> io::Result<()> {
        if self.cleanup_only {
            return Err(conflict());
        }
        let result = self.apply(servers);
        if result.is_err() {
            self.cleanup_only = true;
        }
        result
    }
    fn preflight(&mut self, servers: &[IpAddr]) -> io::Result<()> {
        if self.cleanup_only {
            return Err(conflict());
        }
        let current = self.io.read()?;
        if self.record.is_some() && self.ack.as_ref() != Some(&current) {
            return Err(conflict());
        }
        current.with_servers(servers).map_err(io::Error::other)?;
        Ok(())
    }
    fn apply(&mut self, servers: &[IpAddr]) -> io::Result<()> {
        if servers.is_empty() {
            return Err(conflict());
        }
        let actual = self.io.read()?;
        let desired = actual.with_servers(servers).map_err(io::Error::other)?;
        if self.record.is_none() {
            self.record = Some(DnsRecord {
                baseline: actual.clone(),
                current: actual.clone(),
                pending: None,
            });
            self.ack = Some(actual.clone());
            self.journal.save(self.record.as_ref())?;
        }
        if self.ack.as_ref() != Some(&actual) {
            return Err(conflict());
        }
        self.record.as_mut().ok_or_else(conflict)?.pending = Some(desired.clone());
        self.journal.save(self.record.as_ref())?;
        let observed = self.io.exchange(&actual, &desired)?;
        if observed != desired {
            return Err(conflict());
        }
        // Retain the real exact IO acknowledgement BEFORE fallible publication.
        self.ack = Some(observed.clone());
        let r = self.record.as_mut().ok_or_else(conflict)?;
        r.current = observed;
        r.pending = None;
        self.journal.save(self.record.as_ref())
    }
    fn cleanup(&mut self) -> io::Result<()> {
        self.cleanup_only = true;
        let Some(record) = self.record.as_ref() else {
            return Ok(());
        };
        let baseline = record.baseline.clone();
        let actual = self.io.read()?;
        // Matching a pending target is NOT ownership after a lost native ACK.
        if self.ack.as_ref() != Some(&actual) {
            let retained = self.io.retained_ack()?;
            if retained.as_ref() != Some(&actual)
                || record.pending.as_ref() != Some(&actual)
                || actual.interface != baseline.interface
            {
                return Err(conflict());
            }
            self.ack = retained;
        }
        // A cleanup ACK may outlive failed child publication/deletion. Retry
        // that exact baseline ACK without a redundant native mutation; a read
        // or an unrelated prior selection ACK never supplies this exception.
        let restored = actual == baseline
            && (record.pending.as_ref() == Some(&baseline)
                || record.current == baseline && record.pending.is_none())
            && self.io.retained_ack()?.as_ref() == Some(&baseline);
        let observed = if restored {
            baseline
        } else {
            self.record.as_mut().ok_or_else(conflict)?.pending = Some(baseline.clone());
            self.journal.save(self.record.as_ref())?;
            let observed = self.io.exchange(&actual, &baseline)?;
            if observed != baseline {
                return Err(conflict());
            }
            observed
        };
        self.ack = Some(observed.clone());
        let r = self.record.as_mut().ok_or_else(conflict)?;
        r.current = observed;
        r.pending = None;
        self.journal.save(self.record.as_ref())?;
        self.journal.save(None)?;
        self.record = None;
        Ok(())
    }
}
#[derive(Default)]
struct EffectFence {
    busy: Cell<bool>,
    revoked: Cell<bool>,
    tainted: Cell<bool>,
}
struct EffectCall<'a> {
    fence: &'a EffectFence,
    finished: bool,
}
impl EffectFence {
    fn enter(&self, cleanup: bool) -> io::Result<EffectCall<'_>> {
        if self.busy.get() || (!cleanup && self.revoked.get()) {
            self.revoked.set(true);
            self.tainted.set(true);
            return Err(conflict());
        }
        self.busy.set(true);
        self.tainted.set(false);
        Ok(EffectCall {
            fence: self,
            finished: false,
        })
    }
    fn require(&self, cleanup: bool) -> io::Result<()> {
        if !self.busy.get() || self.tainted.get() || (!cleanup && self.revoked.get()) {
            Err(conflict())
        } else {
            Ok(())
        }
    }
}
impl EffectCall<'_> {
    fn finish(mut self) {
        self.finished = true;
    }
}
impl Drop for EffectCall<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.fence.revoked.set(true);
        }
        self.fence.busy.set(false);
    }
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::{
        member_physical::{Family, InterfaceIdentity, PhysicalProof, PhysicalRoute},
        member_routes::{IdentityCheck, MemberRoutes, NativeProof, Row, RowIo},
        windows::{
            member_carrier_guard::Bindings,
            member_carrier_runtime::native::{
                NativeBindingsWindow, NativeClosingRead, NativeSourceRead,
            },
            member_dns::NativeDnsIo,
            member_routes::NativeRowIo,
            member_session::{
                NativeNetworkRecord, NativeSessionFiles, PhysicalLease, ProtectedStore, RecordKind,
                SessionFiles,
            },
        },
    };
    use nelomai_client_tunnel::redundancy::{
        network::{
            NetworkJournal, NetworkJournalStore, NetworkOwner, NetworkSystem, NetworkValue,
            ResourceKey,
        },
        Slot,
    };
    use std::{cell::RefCell, rc::Rc};

    /// No implementation/default in this module: the concrete original G is
    /// mandatory. Numeric identities, JSON and prior authorize success cannot
    /// implement this safety contract.
    ///
    /// # Safety
    /// Bind the SAME Source/Closing originals, retained RuntimeRead/KeyLock,
    /// private files/claim, actual NativeDeadline Calling scope and generation.
    /// Each authorize must independently verify actual full protected pending
    /// records, observed static bases/priority, absence of ALL dynamic allows,
    /// weak-row ordering and exact physical endpoints. Cleanup additionally
    /// requires protected Closing and independently observed port withdrawal.
    /// DNS child states are covered by the SAME store's already-acknowledged
    /// whole PairRecord network-intent read pin. Register that actual pin from
    /// NativeCarrierPairStore::network_intent, recheck exact protected bytes on
    /// EVERY child transition, compare the actual retained owner ACKs, and do
    /// NOT advance the coordinator revision with a DNS-only/out-of-band CAS.
    /// No extra file, unprotected publication callback or successful default.
    /// All methods run inside an already bracketed source
    /// inspection: do NOT nest another Source.inspect or reopen WFP transaction.
    pub(crate) unsafe trait NativeNetworkEffectGate {
        /// Mandatory real Pair/Network Calling and deny-all full-SDK plan
        /// capture. The supplied capability can only retain into SAME Pins;
        /// it cannot authorize anything or publish an imported plan.
        fn capture_physical_plan(
            &self,
            window: &NativeBindingsWindow<'_>,
            slot: Slot,
            values: &[NetworkValue],
            servers: &[IpAddr],
            capture: &mut NativePhysicalPlanCapture<'_>,
        ) -> io::Result<()>;
        fn bind_originals(
            &self,
            source: &Rc<NativeSourceRead>,
            closing: Option<&Rc<NativeClosingRead>>,
            files: &NativeSessionFiles,
        ) -> io::Result<()>;
        fn authorize(
            &self,
            cleanup: bool,
            window: &NativeBindingsWindow<'_>,
            effect: &Effect<'_>,
        ) -> io::Result<()>;
        fn network_record(&self, cleanup: bool) -> io::Result<Option<Vec<u8>>>;
        fn verify_dns_intent(
            &self,
            cleanup: bool,
            expected: Option<&DnsRecord>,
            desired: Option<&DnsRecord>,
        ) -> io::Result<()>;
    }
    pub(crate) enum Effect<'a> {
        Read,
        RouteCreate(&'a Row),
        RouteDelete(&'a Row),
        RouteSet(&'a Row),
        Dns {
            before: &'a dns::Snapshot,
            desired: &'a dns::Snapshot,
        },
        PublishNetwork(&'a NetworkJournal),
        Plan {
            slot: Slot,
            values: &'a [NetworkValue],
            servers: &'a [IpAddr],
        },
    }
    struct Pins<G> {
        source: Rc<NativeSourceRead>,
        closing: RefCell<Option<Rc<NativeClosingRead>>>,
        files: NativeSessionFiles,
        gate: Rc<G>,
        fence: EffectFence,
        cleanup: Cell<bool>,
        physical: RefCell<PhysicalPlans<PhysicalLease>>,
        route_attempts: RefCell<Vec<RouteAttempt>>,
        dns_attempts: RefCell<Vec<dns::Snapshot>>,
        dns_effects_started: Cell<usize>,
    }
    /// Private construction, single-use retained-fact sink; never a predicate,
    /// permit, imported read capability or standalone metadata authorizer.
    pub(crate) struct NativePhysicalPlanCapture<'a> {
        plans: &'a RefCell<PhysicalPlans<PhysicalLease>>,
        fence: &'a EffectFence,
        used: bool,
    }
    impl NativePhysicalPlanCapture<'_> {
        pub(crate) fn matches_original<G>(&self, ack: &NativeNetworkAckRead<G>) -> bool {
            std::ptr::eq(self.plans, &ack.pins.physical)
                && std::ptr::eq(self.fence, &ack.pins.fence)
        }
        pub(crate) fn retain(
            &mut self,
            revision: u64,
            leases: Vec<PhysicalLease>,
        ) -> io::Result<()> {
            if self.used {
                return Err(conflict());
            }
            self.used = true;
            self.fence.require(false)?;
            self.plans
                .try_borrow_mut()
                .map_err(|_| conflict())?
                .retain(revision, leases)
        }
    }
    impl<G: NativeNetworkEffectGate> Pins<G> {
        fn capture_plan(
            &self,
            slot: Slot,
            values: &[NetworkValue],
            servers: &[IpAddr],
        ) -> io::Result<()> {
            self.fence.require(false)?;
            let result = self
                .source
                .inspect_window(|window| {
                    let mut capture = NativePhysicalPlanCapture {
                        plans: &self.physical,
                        fence: &self.fence,
                        used: false,
                    };
                    self.gate
                        .capture_physical_plan(window, slot, values, servers, &mut capture)
                        .map_err(|_| crate::windows::member_carrier_wintun::Error::Conflict)?;
                    if !capture.used || self.fence.require(false).is_err() {
                        return Err(crate::windows::member_carrier_wintun::Error::Conflict);
                    }
                    Ok(())
                })
                .map_err(|_| conflict());
            if result.is_err() {
                self.fence.revoked.set(true);
                self.fence.tainted.set(true);
            }
            result
        }
        fn inspect<T>(
            &self,
            effect: &Effect<'_>,
            f: impl FnOnce(&NativeBindingsWindow<'_>) -> io::Result<T>,
        ) -> io::Result<T> {
            let cleanup = self.cleanup.get();
            self.fence.require(cleanup)?;
            let call = |window: &NativeBindingsWindow<'_>| -> io::Result<T> {
                self.fence.require(cleanup)?;
                self.gate.authorize(cleanup, window, effect)?;
                self.fence.require(cleanup)?;
                let result = f(window)?;
                self.fence.require(cleanup)?;
                // Effects can change records; G reattests their exact pending
                // and retained ACK rather than treating a request as success.
                self.gate.authorize(cleanup, window, &Effect::Read)?;
                Ok(result)
            };
            let run = |window: &NativeBindingsWindow<'_>| {
                call(window).map_err(|_| crate::windows::member_carrier_wintun::Error::Conflict)
            };
            let result = if cleanup {
                let closing = self
                    .closing
                    .try_borrow()
                    .map_err(|_| conflict())?
                    .clone()
                    .ok_or_else(conflict)?;
                closing.inspect_window(run)
            } else {
                self.source.inspect_window(run)
            }
            .map_err(|_| conflict());
            if result.is_err() {
                self.fence.revoked.set(true);
                self.fence.tainted.set(true);
            }
            result
        }
        fn identities(&self, b: &Bindings) -> Vec<InterfaceIdentity> {
            b.carrier
                .iter()
                .map(|c| &c.identity)
                .chain(b.egress.iter().flatten())
                .map(|i| InterfaceIdentity {
                    index: i.proof.index,
                    luid: i.proof.luid,
                    guid: i.proof.guid,
                })
                .collect()
        }
        fn physical(&self, b: &Bindings, index: u32) -> io::Result<NativeProof> {
            let obligations = self
                .physical
                .try_borrow()
                .map_err(|_| conflict())?
                .obligations();
            let leases = obligations
                .iter()
                .filter(|p| p.interface == index)
                .collect::<Vec<_>>();
            let first = *leases.first().ok_or_else(conflict)?;
            let owned = self.identities(b);
            for p in leases {
                if p.guid != first.guid || p.luid != first.luid {
                    return Err(conflict());
                }
                let route = PhysicalRoute {
                    proof: PhysicalProof {
                        identity: InterfaceIdentity {
                            index: p.interface,
                            luid: p.luid,
                            guid: p.guid,
                        },
                        family: if p.ipv6 { Family::V6 } else { Family::V4 },
                        metric: p.interface_metric,
                    },
                    row: Row {
                        route: p.route.clone(),
                        luid: p.luid,
                        protocol: p.protocol,
                        origin: p.origin,
                        site_prefix_length: p.site_prefix_length,
                        valid_lifetime: p.valid_lifetime,
                        preferred_lifetime: p.preferred_lifetime,
                        flags: p.flags,
                    },
                };
                crate::windows::member_physical::verify(&route, &owned)?;
            }
            Ok(NativeProof {
                index,
                luid: first.luid,
            })
        }
    }
    // Only borrowed INSIDE actual whole Source/Closing callback. No name lookup,
    // imported MemberRecord or numeric proof retained as effect authority.
    struct LiveIdentity<'a, G> {
        pins: &'a Pins<G>,
        bindings: &'a Bindings,
    }
    impl<G: NativeNetworkEffectGate> IdentityCheck for LiveIdentity<'_, G> {
        fn verify(&mut self, index: u32) -> io::Result<NativeProof> {
            self.pins.fence.require(self.pins.cleanup.get())?;
            if self
                .bindings
                .carrier
                .as_ref()
                .is_some_and(|c| c.identity.proof.index == index)
            {
                return Err(conflict());
            }
            if let Some(m) = self
                .bindings
                .egress
                .iter()
                .flatten()
                .find(|m| m.proof.index == index)
            {
                return Ok(NativeProof {
                    index,
                    luid: m.proof.luid,
                });
            }
            self.pins.physical(self.bindings, index)
        }
    }
    struct Rows<G>(Rc<Pins<G>>);
    struct AcknowledgedRows<'a, G> {
        pins: &'a Pins<G>,
        window: &'a NativeBindingsWindow<'a>,
        io: NativeRowIo,
    }
    impl<G: NativeNetworkEffectGate> AcknowledgedRows<'_, G> {
        fn write(
            &mut self,
            row: &Row,
            deleting: bool,
            effect: Effect<'_>,
            write: fn(&mut NativeRowIo, &Row) -> io::Result<()>,
        ) -> io::Result<()> {
            self.pins.fence.require(self.pins.cleanup.get())?;
            let held = retained_route(&self.pins.route_attempts.borrow(), row)?;
            match &effect {
                Effect::RouteDelete(_) if held.as_ref() != Some(row) => return Err(conflict()),
                Effect::RouteSet(_)
                    if held
                        .as_ref()
                        .is_none_or(|old| old.route.gateway != row.route.gateway) =>
                {
                    return Err(conflict())
                }
                Effect::RouteCreate(_) if held.is_some() => return Err(conflict()),
                _ => {}
            }
            self.pins
                .gate
                .authorize(self.pins.cleanup.get(), self.window, &effect)?;
            self.pins.fence.require(self.pins.cleanup.get())?;
            // Retain attempted effect before SDK; even error may have applied.
            let index = self.pins.route_attempts.borrow().len();
            if index >= 32768 {
                return Err(conflict());
            }
            self.pins.route_attempts.borrow_mut().push(RouteAttempt {
                row: row.clone(),
                deleting,
                acknowledged: false,
            });
            let result = write(&mut self.io, row);
            if result.is_ok() {
                self.pins.route_attempts.borrow_mut()[index].acknowledged = true;
            }
            result
        }
    }
    impl<G: NativeNetworkEffectGate> RowIo for AcknowledgedRows<'_, G> {
        fn read(&mut self, d: ipnet::IpNet, i: u32) -> io::Result<Vec<Row>> {
            self.pins.fence.require(self.pins.cleanup.get())?;
            self.io.read(d, i)
        }
        fn create(&mut self, r: &Row) -> io::Result<()> {
            self.write(r, false, Effect::RouteCreate(r), NativeRowIo::create)
        }
        fn delete(&mut self, r: &Row) -> io::Result<()> {
            self.write(r, true, Effect::RouteDelete(r), NativeRowIo::delete)
        }
        fn set(&mut self, r: &Row) -> io::Result<()> {
            self.write(r, false, Effect::RouteSet(r), NativeRowIo::set)
        }
    }
    impl<G: NativeNetworkEffectGate> NetworkSystem for Rows<G> {
        fn read(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>> {
            let cleanup = self.0.cleanup.get();
            self.0.fence.require(cleanup)?;
            let call = |window: &NativeBindingsWindow<'_>| -> io::Result<Option<NetworkValue>> {
                self.0.fence.require(cleanup)?;
                let b = window.bindings();
                let result = MemberRoutes::new(
                    NativeRowIo,
                    LiveIdentity {
                        pins: &self.0,
                        bindings: b,
                    },
                )
                .read(key)?;
                self.0.fence.require(cleanup)?;
                Ok(result)
            };
            let run = |window: &NativeBindingsWindow<'_>| {
                call(window).map_err(|_| crate::windows::member_carrier_wintun::Error::Conflict)
            };
            let result = if cleanup {
                let closing = self
                    .0
                    .closing
                    .try_borrow()
                    .map_err(|_| conflict())?
                    .clone()
                    .ok_or_else(conflict)?;
                closing.inspect_window(run)
            } else {
                self.0.source.inspect_window(run)
            }
            .map_err(|_| conflict());
            if result.is_err() {
                self.0.fence.revoked.set(true);
                self.0.fence.tainted.set(true);
            }
            result
        }
        fn compare_exchange(
            &mut self,
            key: &ResourceKey,
            before: Option<&NetworkValue>,
            after: Option<&NetworkValue>,
        ) -> io::Result<()> {
            let cleanup = self.0.cleanup.get();
            self.0.fence.require(cleanup)?;
            let call = |window: &NativeBindingsWindow<'_>| -> io::Result<()> {
                self.0.fence.require(cleanup)?;
                let b = window.bindings();
                MemberRoutes::new(
                    AcknowledgedRows {
                        pins: &self.0,
                        window,
                        io: NativeRowIo,
                    },
                    LiveIdentity {
                        pins: &self.0,
                        bindings: b,
                    },
                )
                .compare_exchange(key, before, after)?;
                self.0.fence.require(cleanup)?;
                // Actual writes authorize their effect before recording the
                // attempt; every comparison still reattests its final state.
                self.0.gate.authorize(cleanup, window, &Effect::Read)?;
                Ok(())
            };
            let run = |window: &NativeBindingsWindow<'_>| {
                call(window).map_err(|_| crate::windows::member_carrier_wintun::Error::Conflict)
            };
            let result = if cleanup {
                let closing = self
                    .0
                    .closing
                    .try_borrow()
                    .map_err(|_| conflict())?
                    .clone()
                    .ok_or_else(conflict)?;
                closing.inspect_window(run)
            } else {
                self.0.source.inspect_window(run)
            }
            .map_err(|_| conflict());
            if result.is_err() {
                self.0.fence.revoked.set(true);
                self.0.fence.tainted.set(true);
            }
            result
        }
    }
    struct RouteJournal<G> {
        pins: Rc<Pins<G>>,
        store: ProtectedStore<NativeSessionFiles, NativeNetworkRecord>,
        files: NativeSessionFiles,
        expected: Option<Vec<u8>>,
    }
    impl<G: NativeNetworkEffectGate> NetworkJournalStore for RouteJournal<G> {
        fn save(&mut self, journal: &NetworkJournal) -> io::Result<()> {
            let pins = self.pins.clone();
            pins.inspect(&Effect::PublishNetwork(journal), |_| {
                let cleanup = pins.cleanup.get();
                let scope = pins.source.network_scope();
                let before = self.files.read(scope, RecordKind::Network)?;
                if before != self.expected || pins.gate.network_record(cleanup)? != before {
                    return Err(conflict());
                }
                let physical = pins
                    .physical
                    .try_borrow()
                    .map_err(|_| conflict())?
                    .current()?;
                // Publish attempt retained BEFORE the fallible protected save.
                pins.physical
                    .try_borrow_mut()
                    .map_err(|_| conflict())?
                    .begin_publication()?;
                let result = self.store.save_value(&NativeNetworkRecord {
                    journal: journal.clone(),
                    physical: physical.clone(),
                });
                let after = self.files.read(scope, RecordKind::Network)?;
                if pins.gate.network_record(cleanup)? != after {
                    return Err(conflict());
                }
                // Never refresh CAS after an ambiguous save; retained ACKs stay
                // in Pins, but a matching file is not a newly issued grant.
                result?;
                let saved = after
                    .as_deref()
                    .ok_or_else(conflict)
                    .and_then(|v| NativeNetworkRecord::read_comparison(scope, v))?;
                if serde_json::to_vec(&saved.journal).map_err(|_| conflict())?
                    != serde_json::to_vec(journal).map_err(|_| conflict())?
                    || saved.physical != physical
                {
                    return Err(conflict());
                }
                pins.physical
                    .try_borrow_mut()
                    .map_err(|_| conflict())?
                    .ack_publication()?;
                self.expected = after;
                Ok(())
            })
        }
    }
    struct CarrierDnsIdentity<'a>(&'a Bindings);
    impl dns::Identity for CarrierDnsIdentity<'_> {
        fn verify_owned(&mut self, i: &dns::OwnedInterface) -> dns::Result<dns::Ownership> {
            let c = &self
                .0
                .carrier
                .as_ref()
                .ok_or(dns::DnsError::Ownership)?
                .identity;
            if i.scope != c.scope
                || i.guid != c.proof.guid
                || i.luid != c.proof.luid
                || i.index != c.proof.index
            {
                return Err(dns::DnsError::Ownership);
            }
            Ok(dns::Ownership::NewlyCreated)
        }
    }
    struct Dns<G>(Rc<Pins<G>>);
    impl<G: NativeNetworkEffectGate> Dns<G> {
        fn owned<'a>(
            b: &'a Bindings,
        ) -> io::Result<dns::OwnedDns<CarrierDnsIdentity<'a>, NativeDnsIo>> {
            let c = &b.carrier.as_ref().ok_or_else(conflict)?.identity;
            crate::windows::member_dns::owned(
                dns::OwnedInterface {
                    scope: c.scope.clone(),
                    guid: c.proof.guid,
                    luid: c.proof.luid,
                    index: c.proof.index,
                },
                CarrierDnsIdentity(b),
            )
            .map_err(io::Error::other)
        }
    }
    impl<G: NativeNetworkEffectGate> DnsSystem for Dns<G> {
        fn read(&mut self) -> io::Result<dns::Snapshot> {
            let cleanup = self.0.cleanup.get();
            self.0.fence.require(cleanup)?;
            let call = |window: &NativeBindingsWindow<'_>| -> io::Result<dns::Snapshot> {
                self.0.fence.require(cleanup)?;
                let b = window.bindings();
                let result = Self::owned(b)?.snapshot().map_err(io::Error::other)?;
                self.0.fence.require(cleanup)?;
                Ok(result)
            };
            let run = |window: &NativeBindingsWindow<'_>| {
                call(window).map_err(|_| crate::windows::member_carrier_wintun::Error::Conflict)
            };
            let result = if cleanup {
                let closing = self
                    .0
                    .closing
                    .try_borrow()
                    .map_err(|_| conflict())?
                    .clone()
                    .ok_or_else(conflict)?;
                closing.inspect_window(run)
            } else {
                self.0.source.inspect_window(run)
            }
            .map_err(|_| conflict());
            if result.is_err() {
                self.0.fence.revoked.set(true);
                self.0.fence.tainted.set(true);
            }
            result
        }
        fn exchange(
            &mut self,
            before: &dns::Snapshot,
            after: &dns::Snapshot,
        ) -> io::Result<dns::Snapshot> {
            if self.0.dns_attempts.borrow().len() >= 32768 {
                return Err(conflict());
            }
            self.0.inspect(
                &Effect::Dns {
                    before,
                    desired: after,
                },
                |window| {
                    let b = window.bindings();
                    // Retain BEFORE any actual DNS mutation/readback can fail
                    // or unwind. Empty successful ACK history is NOT no attempt.
                    begin_dns_effect(&self.0.dns_effects_started)?;
                    let ack = Self::owned(b)?
                        .compare_exchange(before, after)
                        .map_err(io::Error::other)?;
                    // Exact native readback ACK precedes Source postflight and Pair
                    // journal publication. No unprotected closure may drop it.
                    self.0.dns_attempts.borrow_mut().push(ack.clone());
                    Ok(ack)
                },
            )
        }
        fn retained_ack(&mut self) -> io::Result<Option<dns::Snapshot>> {
            self.0.inspect(&Effect::Read, |_| {
                Ok(self
                    .0
                    .dns_attempts
                    .try_borrow()
                    .map_err(|_| conflict())?
                    .last()
                    .cloned())
            })
        }
    }
    struct DnsStore<G> {
        pins: Rc<Pins<G>>,
        expected: Option<DnsRecord>,
    }
    impl<G: NativeNetworkEffectGate> DnsJournal for DnsStore<G> {
        fn save(&mut self, value: Option<&DnsRecord>) -> io::Result<()> {
            let cleanup = self.pins.cleanup.get();
            self.pins.fence.require(cleanup)?;
            let call = |window: &NativeBindingsWindow<'_>| -> io::Result<()> {
                self.pins.fence.require(cleanup)?;
                // The child callback checks actual Pair/ACK coverage; no SDK
                // effect precedes it, and final G reattests the complete state.
                self.pins
                    .gate
                    .verify_dns_intent(cleanup, self.expected.as_ref(), value)?;
                self.pins.fence.require(cleanup)?;
                self.pins.gate.authorize(cleanup, window, &Effect::Read)?;
                Ok(())
            };
            let run = |window: &NativeBindingsWindow<'_>| {
                call(window).map_err(|_| crate::windows::member_carrier_wintun::Error::Conflict)
            };
            let result = if cleanup {
                let closing = self
                    .pins
                    .closing
                    .try_borrow()
                    .map_err(|_| conflict())?
                    .clone()
                    .ok_or_else(conflict)?;
                closing.inspect_window(run)
            } else {
                self.pins.source.inspect_window(run)
            }
            .map_err(|_| conflict());
            if result.is_err() {
                self.pins.fence.revoked.set(true);
                self.pins.fence.tainted.set(true);
            }
            result?;
            self.expected = value.cloned();
            Ok(())
        }
    }
    struct State<G> {
        routes: NetworkOwner<Rows<G>, RouteJournal<G>>,
        dns: DnsOwner<Dns<G>, DnsStore<G>>,
    }
    pub(crate) struct NativeCarrierNetworkOwner<G> {
        pins: Rc<Pins<G>>,
        state: RefCell<State<G>>,
    }
    /// Factual SAME-owner acknowledgements, including an SDK success retained
    /// before a failed source/file postflight. No importer/adoption constructor
    /// or effect capability. Reads never borrow the mutable NetworkOwner state,
    /// enter Source, perform IO, or call the resource gate recursively.
    pub(crate) struct NativeNetworkAckRead<G> {
        pins: Rc<Pins<G>>,
    }
    /// Registration held by G is non-owning: Pins themselves retain G.
    /// The actor must retain the real owner; disappearance is an error, not
    /// proof of cleanup or a way to adopt another owner's equal metadata.
    pub(crate) struct NativeNetworkAckWeakRead<G> {
        original: crate::windows::member_carrier_original_read::OriginalRead<Pins<G>>,
    }
    impl<G: NativeNetworkEffectGate> NativeNetworkAckWeakRead<G> {
        pub(crate) fn upgrade(&self) -> io::Result<NativeNetworkAckRead<G>> {
            Ok(NativeNetworkAckRead {
                pins: self.original.upgrade().ok_or_else(conflict)?,
            })
        }
    }
    impl<G: NativeNetworkEffectGate> NativeNetworkAckRead<G> {
        /// Exact captured native physical leases of this original owner, not
        /// route keys inferred from a current table or imported journal.
        pub(crate) fn physical_leases(&self) -> io::Result<Vec<PhysicalLease>> {
            self.pins
                .physical
                .try_borrow()
                .map_err(|_| conflict())?
                .current()
        }
        /// Prior native-captured paths remain fresh-proof cleanup obligations,
        /// never the exact current plan for Install or new route effects.
        pub(crate) fn physical_obligations(&self) -> io::Result<Vec<PhysicalLease>> {
            Ok(self
                .pins
                .physical
                .try_borrow()
                .map_err(|_| conflict())?
                .obligations())
        }
        pub(crate) fn verify_physical_record(
            &self,
            saved: Option<&[PhysicalLease]>,
        ) -> io::Result<()> {
            self.pins
                .physical
                .try_borrow()
                .map_err(|_| conflict())?
                .accepts_saved(saved)
        }
        pub(crate) fn downgrade(&self) -> NativeNetworkAckWeakRead<G> {
            NativeNetworkAckWeakRead {
                original: crate::windows::member_carrier_original_read::OriginalRead::from_retained(
                    &self.pins,
                ),
            }
        }
        pub(crate) fn same_original(&self, other: &Self) -> bool {
            Rc::ptr_eq(&self.pins, &other.pins)
        }
        pub(crate) fn matches_origin(&self, source: &Rc<NativeSourceRead>, gate: &Rc<G>) -> bool {
            Rc::ptr_eq(&self.pins.source, source) && Rc::ptr_eq(&self.pins.gate, gate)
        }
        pub(crate) fn pin(&self) -> Self {
            Self {
                pins: self.pins.clone(),
            }
        }
        pub(crate) fn acknowledgements(
            &self,
        ) -> io::Result<(Vec<RouteAttempt>, Vec<dns::Snapshot>)> {
            Ok((
                self.pins
                    .route_attempts
                    .try_borrow()
                    .map_err(|_| conflict())?
                    .clone(),
                self.pins
                    .dns_attempts
                    .try_borrow()
                    .map_err(|_| conflict())?
                    .clone(),
            ))
        }
        pub(crate) fn dns_exchange_history(&self) -> io::Result<(usize, Vec<dns::Snapshot>)> {
            Ok((
                self.pins.dns_effects_started.get(),
                self.pins
                    .dns_attempts
                    .try_borrow()
                    .map_err(|_| conflict())?
                    .clone(),
            ))
        }
    }
    impl<G: NativeNetworkEffectGate> NativeCarrierNetworkOwner<G> {
        pub(crate) fn read_pin(&self) -> NativeNetworkAckRead<G> {
            NativeNetworkAckRead {
                pins: self.pins.clone(),
            }
        }
        /// Fresh only: an existing Network record is rejected, never imported
        /// as authority. Crash replay remains the enclosing cleanup-only actor.
        pub(crate) fn fresh_uncaptured(
            source: Rc<NativeSourceRead>,
            gate: Rc<G>,
            mut files: NativeSessionFiles,
        ) -> io::Result<Self> {
            gate.bind_originals(&source, None, &files)?;
            let scope = source.network_scope().clone();
            let before = files.read(&scope, RecordKind::Network)?;
            if before.is_some() || gate.network_record(false)? != before {
                return Err(conflict());
            }
            let (store, saved) = ProtectedStore::<_, NativeNetworkRecord>::open(
                files.clone(),
                scope,
                RecordKind::Network,
            )?;
            if saved.is_some() {
                return Err(conflict());
            }
            let pins = Rc::new(Pins {
                source,
                closing: RefCell::new(None),
                files: files.clone(),
                gate,
                fence: EffectFence::default(),
                cleanup: Cell::new(false),
                physical: RefCell::new(PhysicalPlans::default()),
                route_attempts: RefCell::new(Vec::new()),
                dns_attempts: RefCell::new(Vec::new()),
                dns_effects_started: Cell::new(0),
            });
            let routes = NetworkOwner::fresh(
                Rows(pins.clone()),
                RouteJournal {
                    pins: pins.clone(),
                    store,
                    files,
                    expected: None,
                },
            );
            let dns = DnsOwner::fresh(
                Dns(pins.clone()),
                DnsStore {
                    pins: pins.clone(),
                    expected: None,
                },
            );
            Ok(Self {
                pins,
                state: RefCell::new(State { routes, dns }),
            })
        }
        fn operation<T>(
            &self,
            cleanup: bool,
            f: impl FnOnce(&mut State<G>) -> io::Result<T>,
        ) -> io::Result<T> {
            let call = self.pins.fence.enter(cleanup)?;
            if cleanup {
                self.pins.fence.revoked.set(true);
            }
            self.pins.cleanup.set(cleanup);
            let mut state = self.state.try_borrow_mut().map_err(|_| conflict())?;
            let result = f(&mut state);
            if result.is_ok() {
                self.pins.fence.require(cleanup)?;
                call.finish();
            }
            result
        }
        pub(crate) fn select(
            &self,
            slot: Slot,
            values: Vec<NetworkValue>,
            servers: &[IpAddr],
        ) -> io::Result<()> {
            self.operation(false, |s| {
                #[cfg(test)]
                crate::windows::member_carrier_factory_test_os::trace_step(
                    "network owner select capture_plan begin",
                );
                self.pins.capture_plan(slot, &values, servers)?;
                #[cfg(test)]
                crate::windows::member_carrier_factory_test_os::trace_step(
                    "network owner select capture_plan end",
                );
                // Reject unsupported family/settings BEFORE any route effect;
                // this read carries no DNS journal publication or permission.
                if !servers.is_empty() {
                    #[cfg(test)]
                    crate::windows::member_carrier_factory_test_os::trace_step(
                        "network owner select dns.preflight begin",
                    );
                    s.dns.preflight(servers)?;
                    #[cfg(test)]
                    crate::windows::member_carrier_factory_test_os::trace_step(
                        "network owner select dns.preflight end",
                    );
                }
                #[cfg(test)]
                crate::windows::member_carrier_factory_test_os::trace_step(
                    "network owner select routes.select begin",
                );
                s.routes.select(slot, values)?;
                #[cfg(test)]
                crate::windows::member_carrier_factory_test_os::trace_step(
                    "network owner select routes.select end",
                );
                if !servers.is_empty() {
                    #[cfg(test)]
                    crate::windows::member_carrier_factory_test_os::trace_step(
                        "network owner select dns.select begin",
                    );
                    s.dns.select(servers)?;
                    #[cfg(test)]
                    crate::windows::member_carrier_factory_test_os::trace_step(
                        "network owner select dns.select end",
                    );
                }
                Ok(())
            })
        }
        pub(crate) fn cleanup(&self, closing: Rc<NativeClosingRead>) -> io::Result<()> {
            self.operation(true, |s| {
                self.pins.gate.bind_originals(
                    &self.pins.source,
                    Some(&closing),
                    &self.pins.files,
                )?;
                let mut retained = self.pins.closing.try_borrow_mut().map_err(|_| conflict())?;
                if retained
                    .as_ref()
                    .is_some_and(|old| !Rc::ptr_eq(old, &closing))
                {
                    return Err(conflict());
                }
                *retained = Some(closing);
                drop(retained);
                // current starts None; retain is its sole writer and never resets it.
                // Original G/Closing/attempt checks remain; no stopping journal is emitted.
                if self
                    .pins
                    .physical
                    .try_borrow()
                    .map_err(|_| conflict())?
                    .current
                    .is_none()
                {
                    if s.routes.has_resources()
                        || s.routes.active().is_some()
                        || s.dns.record.is_some()
                        || !self
                            .pins
                            .route_attempts
                            .try_borrow()
                            .map_err(|_| conflict())?
                            .is_empty()
                        || self.pins.dns_effects_started.get() != 0
                        || !self
                            .pins
                            .dns_attempts
                            .try_borrow()
                            .map_err(|_| conflict())?
                            .is_empty()
                    {
                        return Err(conflict());
                    }
                    return self.pins.inspect(&Effect::Read, |_| {
                        let mut files = self.pins.files.clone();
                        let native =
                            files.read(self.pins.source.network_scope(), RecordKind::Network)?;
                        let protected = self.pins.gate.network_record(true)?;
                        if native.is_some() || protected.is_some() {
                            return Err(conflict());
                        }
                        Ok(())
                    });
                }
                #[cfg(test)]
                super::super::member_carrier_factory_test_os::trace_step(
                    "network DNS cleanup begin",
                );
                s.dns.cleanup()?;
                #[cfg(test)]
                super::super::member_carrier_factory_test_os::trace_step("network DNS cleanup end");
                #[cfg(test)]
                super::super::member_carrier_factory_test_os::trace_step(
                    "network routes cleanup begin",
                );
                s.routes.cleanup()?;
                #[cfg(test)]
                super::super::member_carrier_factory_test_os::trace_step(
                    "network routes cleanup end",
                );
                Ok(())
            })
        }
    }
}
#[cfg(test)]
#[path = "member_carrier_network_owner_tests.rs"]
mod tests;
