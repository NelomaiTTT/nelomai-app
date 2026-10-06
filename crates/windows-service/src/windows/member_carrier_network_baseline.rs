//! Original SDK DNS baseline facts for partial carrier cleanup. Factory OFF.
//! These comparisons/read pins are never resource, DNS-write or readiness grants.
#![allow(dead_code)]
use super::member_carrier_network::NetworkFacts;
#[cfg(test)]
use crate::member_routes::Row;
use crate::{member_carrier_guard::Carrier, member_dns as dns};
use std::{
    cell::{Cell, RefCell},
    io,
    rc::Rc,
};
fn conflict() -> io::Error {
    io::Error::other("carrier_network_baseline_conflict")
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DnsBaselineDisposition {
    NeverExchanged,
    RestoredByLastAck,
}
fn validate_dns(snapshot: &dns::Snapshot) -> io::Result<()> {
    // Existing complete validator, not a decoder/default success substitute.
    snapshot
        .with_servers(&["1.1.1.1".parse().map_err(|_| conflict())?])
        .map_err(io::Error::other)?;
    Ok(())
}
fn compare_initial(
    carrier: &Carrier,
    facts: &NetworkFacts,
    actual: &dns::Snapshot,
    protected: Option<&[u8]>,
) -> io::Result<()> {
    crate::member_carrier_guard::Model::empty(carrier.identity.scope.clone())
        .map_err(io::Error::other)?;
    validate_dns(actual)?;
    let c = &carrier.identity;
    if carrier.sources.len() != 1
        || !carrier.sources[0].is_ipv4()
        || carrier.sources[0].is_unspecified()
        || carrier.sources[0].is_multicast()
        || carrier.sources[0].is_loopback()
        || actual.interface.scope != c.scope
        || actual.interface.guid != c.proof.guid
        || actual.interface.index != c.proof.index
        || actual.interface.luid != c.proof.luid
        || actual
            .settings
            .name_server
            .as_ref()
            .is_some_and(|s| !s.is_empty())
        || protected.is_some()
        || !facts.current.is_empty()
        || facts.pending.is_some()
        || facts.active.is_some()
        || facts.pending_active.is_some()
        || facts.stopping
        || facts.egress_rows.iter().any(|rows| !rows.is_empty())
        || facts.carrier_rows.len() > 1
    {
        return Err(conflict());
    }
    for row in &facts.carrier_rows {
        crate::member_routes::validate_route(&row.route, carrier.sources[0].into(), c.proof.index)?;
        if row.route.interface != c.proof.index
            || row.luid != c.proof.luid
            || row.route.gateway.is_some()
            || row.route.destination != ipnet::IpNet::from(carrier.sources[0])
            || row.flags != [1, 0, 0, 0]
        {
            return Err(conflict());
        }
    }
    Ok(())
}
fn classify_dns(
    baseline: &dns::Snapshot,
    attempts: usize,
    acks: &[dns::Snapshot],
) -> io::Result<DnsBaselineDisposition> {
    validate_dns(baseline)?;
    if attempts > 32768 || attempts != acks.len() {
        return Err(conflict());
    }
    if attempts == 0 {
        return Ok(DnsBaselineDisposition::NeverExchanged);
    }
    for ack in acks {
        validate_dns(ack)?;
        let mut nameserver_only = baseline.clone();
        nameserver_only.settings.name_server = ack.settings.name_server.clone();
        if ack != &nameserver_only {
            return Err(conflict());
        }
    }
    if acks.last() != Some(baseline) {
        return Err(conflict());
    }
    Ok(DnsBaselineDisposition::RestoredByLastAck)
}
fn compare_record_origin(
    context: &crate::member_carrier_native_ownership::Context,
    record: &crate::member_carrier_pair::Record,
    carrier: &Carrier,
) -> io::Result<()> {
    record.validate()?;
    if record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || record.options.is_none()
        || carrier.identity.scope != record.scope
        || Some(carrier.identity.proof) != record.carrier
        || carrier.identity.proof.guid != context.bindings[0].guid
        || carrier.sources
            != record
                .addresses
                .iter()
                .map(|a| a.addr())
                .collect::<Vec<_>>()
        || record.guard.permits
    {
        return Err(conflict());
    }
    Ok(())
}
fn compare_capture_record(
    context: &crate::member_carrier_native_ownership::Context,
    record: &crate::member_carrier_pair::Record,
    carrier: &Carrier,
) -> io::Result<()> {
    use crate::member_carrier_pair::{Effect, Operation, Phase};
    compare_record_origin(context, record, carrier)?;
    if record.phase != Phase::Starting
        || !matches!(record.operation, Some(Operation::Start(_)))
        || record.active.is_some()
        || record.stop_stage != 0
        || record.network.is_some()
        || !matches!(
            record.pending,
            None | Some(Effect::Guard | Effect::WeakRows)
        )
    {
        return Err(conflict());
    }
    Ok(())
}
fn compare_retired_record(
    context: &crate::member_carrier_native_ownership::Context,
    record: &crate::member_carrier_pair::Record,
    carrier: &Carrier,
    baseline: &dns::Snapshot,
) -> io::Result<()> {
    use crate::member_carrier_pair::{Effect, Phase};
    compare_record_origin(context, record, carrier)?;
    validate_dns(baseline)?;
    let empty = crate::member_carrier_guard::Model::empty(record.scope.clone())
        .map_err(io::Error::other)?;
    if record.phase != Phase::Closing
        || record.stop_stage != 10
        || record.pending != Some(Effect::Guard)
        || record.active.is_some()
        || record.operation.is_some()
        || !record.guard.installed
        || record.guard.assigned_sublayer_weight.is_none()
        || record
            .pending_guard
            .as_ref()
            .is_none_or(|p| p.desired != empty)
        || baseline.interface.scope != carrier.identity.scope
        || baseline.interface.guid != carrier.identity.proof.guid
        || baseline.interface.luid != carrier.identity.proof.luid
        || baseline.interface.index != carrier.identity.proof.index
    {
        return Err(conflict());
    }
    if let Some(network) = &record.network {
        if network.pending.is_some()
            || network.current != network.baseline
            || !network.baseline.routes.is_empty()
            || network.baseline.dns.as_ref() != Some(baseline)
        {
            return Err(conflict());
        }
    }
    Ok(())
}
/// Generic storage protocol only: actual native SDK callback supplies T.
/// No native ACK, successful G or kernel substitute is constructed here.
struct CaptureSlot<T> {
    attempted: Cell<bool>,
    busy: Cell<bool>,
    failed: Cell<bool>,
    tainted: Cell<bool>,
    value: RefCell<Option<Rc<T>>>,
}
impl<T> CaptureSlot<T> {
    fn new() -> Self {
        Self {
            attempted: Cell::new(false),
            busy: Cell::new(false),
            failed: Cell::new(false),
            tainted: Cell::new(false),
            value: RefCell::new(None),
        }
    }
    fn capture(&self, call: impl FnOnce(&Self) -> io::Result<()>) -> io::Result<()> {
        if self.attempted.replace(true) || self.busy.get() {
            self.failed.set(true);
            self.tainted.set(true);
            return Err(conflict());
        }
        self.busy.set(true);
        let mut flight = CaptureFlight {
            slot: self,
            finished: false,
        };
        call(self)?;
        if self.tainted.get() || self.value.try_borrow().map_err(|_| conflict())?.is_none() {
            return Err(conflict());
        }
        flight.finished = true;
        Ok(())
    }
    fn retain(&self, value: Rc<T>) -> io::Result<()> {
        if !self.busy.get() || self.tainted.get() {
            self.failed.set(true);
            self.tainted.set(true);
            return Err(conflict());
        }
        let mut retained = self.value.try_borrow_mut().map_err(|_| {
            self.failed.set(true);
            self.tainted.set(true);
            conflict()
        })?;
        if retained.is_some() {
            self.failed.set(true);
            self.tainted.set(true);
            return Err(conflict());
        }
        *retained = Some(value);
        Ok(())
    }
    fn read(&self) -> io::Result<Rc<T>> {
        self.value
            .try_borrow()
            .map_err(|_| conflict())?
            .as_ref()
            .cloned()
            .ok_or_else(conflict)
    }
}
struct CaptureFlight<'a, T> {
    slot: &'a CaptureSlot<T>,
    finished: bool,
}
impl<T> Drop for CaptureFlight<'_, T> {
    fn drop(&mut self) {
        if !self.finished {
            self.slot.failed.set(true);
        }
        self.slot.busy.set(false);
    }
}
#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::windows::{
        member_carrier_guard::{Bindings, NativeGuard, Wfp, WindowBindingAttestor},
        member_carrier_key_authority::RuntimeRead,
        member_carrier_network::native::NativeNetworkRead,
        member_carrier_network_gate::native::NativeNetworkGate,
        member_carrier_network_owner::native::NativeNetworkAckRead,
        member_carrier_pair_store::native_store::NativePairIntentRead,
        member_carrier_runtime::native::{
            NativeBindingsWindow, NativeSourceRead, RetiredCarrierRead,
        },
        member_native_deadline::{NativeDeadline, NativeDeadlineReadPin},
    };
    use crate::{member_carrier_native_ownership::Context, member_carrier_pair as pair};
    use std::{
        rc::Weak,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };
    struct Origin<A: WindowBindingAttestor> {
        context: Context,
        runtime: RuntimeRead,
        source: Rc<NativeSourceRead>,
        reader: Rc<NativeNetworkRead>,
        guard: Rc<RefCell<NativeGuard<Wfp, A>>>,
        supervisor: Rc<NativeDeadline>,
        deadline: NativeDeadlineReadPin,
        cancelled: Arc<AtomicBool>,
    }
    /// Actor-retained root exists BEFORE ANY fallible capture check. Result
    /// never carries the sole original/read capability. Keep through cleanup.
    pub(crate) struct NativeNetworkBaselineRoot<A: WindowBindingAttestor> {
        origin: Rc<Origin<A>>,
        capture: CaptureSlot<NativeNetworkBaselineRead<A>>,
    }
    /// Immutable factual SDK read, privately minted ONLY below by the actual
    /// NativeNetworkRead callback. NOT a DNS exchange ACK or effect/readiness G.
    pub(crate) struct NativeNetworkBaselineRead<A: WindowBindingAttestor> {
        origin: Rc<Origin<A>>,
        carrier: Carrier,
        snapshot: dns::Snapshot,
    }
    /// Concrete weak read. G stores ONLY this; actor independently retains root
    /// or strong read. Expiry denies, not empty history or a successful default.
    pub(crate) struct NativeNetworkBaselineWeakRead<A: WindowBindingAttestor> {
        original: Weak<NativeNetworkBaselineRead<A>>,
    }
    impl<A: WindowBindingAttestor> Origin<A> {
        fn continuity(&self) -> io::Result<()> {
            self.deadline
                .verify_runtime_call(&self.supervisor, &self.runtime, &self.context)
                .map_err(io::Error::other)
        }
        fn capture_window(&self, window: &NativeBindingsWindow<'_>) -> io::Result<()> {
            self.continuity()?;
            if !window.matches_source(&self.source)
                || !window.matches_runtime(&self.runtime)
                || self.cancelled.load(Ordering::Acquire)
                || !self
                    .runtime
                    .fresh(&self.context)
                    .map_err(io::Error::other)?
            {
                return Err(conflict());
            }
            Ok(())
        }
        fn current(&self, pin: &NativePairIntentRead, expected: &pair::Record) -> io::Result<()> {
            if !pin.matches_runtime(&self.runtime) {
                return Err(conflict());
            }
            pin.inspect(&self.runtime, &self.supervisor, |actual| {
                if actual != expected {
                    return Err(conflict());
                }
                self.continuity()
            })
        }
        fn no_allows(
            &self,
            window: &NativeBindingsWindow<'_>,
            expected: &pair::Record,
        ) -> io::Result<()> {
            // A sibling read, NEVER during a held Guard transaction. Exact
            // original Wfp snapshot/full keys, not a JSON no-permits bit.
            let actual = self
                .guard
                .try_borrow_mut()
                .map_err(|_| conflict())?
                .snapshot_in_window(window)
                .map_err(io::Error::other)?;
            if actual != expected.guard.expected
                || actual
                    .filters
                    .iter()
                    .any(|f| f.action == crate::member_carrier_guard::Action::Permit)
            {
                return Err(conflict());
            }
            Ok(())
        }
    }
    impl<A: WindowBindingAttestor> NativeNetworkBaselineRoot<A> {
        #[allow(clippy::too_many_arguments)]
        pub(crate) fn new(
            context: Context,
            runtime: RuntimeRead,
            source: Rc<NativeSourceRead>,
            reader: Rc<NativeNetworkRead>,
            guard: Rc<RefCell<NativeGuard<Wfp, A>>>,
            supervisor: Rc<NativeDeadline>,
            deadline: NativeDeadlineReadPin,
            cancelled: Arc<AtomicBool>,
        ) -> Rc<Self> {
            Rc::new(Self {
                origin: Rc::new(Origin {
                    context,
                    runtime,
                    source,
                    reader,
                    guard,
                    supervisor,
                    deadline,
                    cancelled,
                }),
                capture: CaptureSlot::new(),
            })
        }
        /// Call in the original outer Source/window + WHOLE actual Calling,
        /// BEFORE Network child/effects and OUTSIDE Pair/Guard/joined borrows.
        /// Read capability is retained INSIDE the first actual SDK callback,
        /// BEFORE the reader's second SDK sample and original Source postflight.
        pub(crate) fn capture_in_window(
            &self,
            window: &NativeBindingsWindow<'_>,
            pin: &NativePairIntentRead,
            expected: &pair::Record,
        ) -> io::Result<()> {
            self.capture.capture(|sink| {
                let origin = &self.origin;
                origin.capture_window(window)?;
                let carrier = window.bindings().carrier.as_ref().ok_or_else(conflict)?;
                compare_capture_record(&origin.context, expected, carrier)?;
                origin.current(pin, expected)?;
                origin.no_allows(window, expected)?;
                origin.reader.inspect_in_window(window, |facts| {
                    compare_initial(
                        carrier,
                        &facts.routes,
                        &facts.dns,
                        facts.protected_record.as_deref(),
                    )?;
                    // No caller-supplied snapshot or public data constructor.
                    sink.retain(Rc::new(NativeNetworkBaselineRead {
                        origin: origin.clone(),
                        carrier: carrier.clone(),
                        snapshot: facts.dns.clone(),
                    }))
                })?;
                origin.no_allows(window, expected)?;
                origin.current(pin, expected)?;
                origin.capture_window(window)
            })
        }
        /// Available even after capture postflight Err/unwind. Historical fact
        /// only; no successful capture/effect/Source revival is claimed.
        pub(crate) fn read_pin(&self) -> io::Result<Rc<NativeNetworkBaselineRead<A>>> {
            self.capture.read()
        }
    }
    impl<A: WindowBindingAttestor> NativeNetworkBaselineRead<A> {
        pub(crate) fn same_original(&self, other: &Self) -> bool {
            std::ptr::eq(self, other)
        }
        pub(crate) fn matches_source_origin(&self, source: &NativeSourceRead) -> bool {
            std::ptr::eq(self.origin.source.as_ref(), source)
        }
        pub(crate) fn matches_reader(&self, reader: &NativeNetworkRead) -> bool {
            std::ptr::eq(self.origin.reader.as_ref(), reader)
        }
        /// Snapshot DATA only, never a DNS exchange or restoration ACK.
        pub(crate) fn snapshot(&self) -> &dns::Snapshot {
            &self.snapshot
        }
        pub(crate) fn downgrade(self: &Rc<Self>) -> NativeNetworkBaselineWeakRead<A> {
            NativeNetworkBaselineWeakRead {
                original: Rc::downgrade(self),
            }
        }
        /// Supplied inside Main's SAME original retired/full-absence + locked
        /// Wfp/current Pair bracket. No reentry or historical C DNS/index query.
        /// Main authenticates canonical Owner ACK pin and no remaining DNS
        /// child/routes/row obligations independently; this is factual ONLY.
        pub(crate) fn inspect_retired_in_bracket<T>(
            &self,
            record: &pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &Bindings,
            owner: &NativeNetworkAckRead<NativeNetworkGate<A>>,
            gate: &Rc<NativeNetworkGate<A>>,
            inspect: impl FnOnce(&dns::Snapshot, DnsBaselineDisposition) -> io::Result<T>,
        ) -> io::Result<T> {
            self.origin.continuity()?;
            compare_retired_record(&self.origin.context, record, &self.carrier, &self.snapshot)?;
            if !retired.matches_source_origin(&self.origin.source)
                || bindings.scope != record.scope
                || bindings.carrier.as_ref() != Some(&self.carrier)
                || !owner.matches_origin(&self.origin.source, gate)
            {
                return Err(conflict());
            }
            // REQUIRED Main seam: count EVERY actual SDK exchange attempt,
            // including failure/unwind, not just successful readback ACKs.
            let (attempts, acks): (usize, Vec<dns::Snapshot>) = owner.dns_exchange_history()?;
            let disposition = classify_dns(&self.snapshot, attempts, &acks)?;
            if record.network.is_none() && disposition != DnsBaselineDisposition::NeverExchanged {
                return Err(conflict());
            }
            let result = inspect(&self.snapshot, disposition);
            if owner.dns_exchange_history()? != (attempts, acks) {
                return Err(conflict());
            }
            self.origin.continuity()?;
            result
        }
    }
    impl<A: WindowBindingAttestor> NativeNetworkBaselineWeakRead<A> {
        pub(crate) fn upgrade(&self) -> io::Result<Rc<NativeNetworkBaselineRead<A>>> {
            self.original.upgrade().ok_or_else(conflict)
        }
        pub(crate) fn same_original(&self, other: &Self) -> bool {
            Weak::ptr_eq(&self.original, &other.original)
        }
    }
}
#[cfg(test)]
#[path = "member_carrier_network_baseline_tests.rs"]
mod tests;
