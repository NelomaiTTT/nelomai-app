//! Original SDK DNS baseline facts for partial carrier cleanup.
//! These comparisons/read pins are never resource, DNS-write or readiness grants.
use super::member_carrier_network::NetworkFacts;
#[cfg(all(test, windows))]
use crate::windows::member_carrier_factory_test_os::trace_step;
use crate::{member_carrier_guard::Carrier, member_dns as dns};
use std::{
    cell::{Cell, RefCell},
    io,
    rc::Rc,
};
fn conflict() -> io::Error {
    io::Error::other("carrier_network_baseline_conflict")
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
        .inspect_err(|_| {
            #[cfg(all(test, windows))]
            trace_step("network baseline compare_initial carrier scope error");
        })
        .map_err(io::Error::other)?;
    validate_dns(actual).inspect_err(|_error| {
        #[cfg(all(test, windows))]
        trace_step(&format!(
            "network baseline compare_initial DNS validation error={_error}",
        ));
    })?;
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
    {
        return Err(conflict());
    }
    Ok(())
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
        member_carrier_guard::{NativeGuard, Wfp, WindowBindingAttestor},
        member_carrier_key_authority::RuntimeRead,
        member_carrier_network::native::NativeNetworkRead,
        member_carrier_pair_store::native_store::NativePairIntentRead,
        member_carrier_runtime::native::{NativeBindingsWindow, NativeSourceRead},
        member_native_deadline::{NativeDeadline, NativeDeadlineReadPin},
    };
    use crate::{member_carrier_native_ownership::Context, member_carrier_pair as pair};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
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
        snapshot: dns::Snapshot,
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
                origin.capture_window(window).inspect_err(|_| {
                    #[cfg(test)]
                    trace_step("network baseline capture_window preflight error");
                })?;
                let carrier = window.bindings().carrier.as_ref().ok_or_else(conflict)?;
                compare_capture_record(&origin.context, expected, carrier).inspect_err(|_| {
                    #[cfg(test)]
                    trace_step("network baseline compare_capture_record error");
                })?;
                origin.current(pin, expected).inspect_err(|_| {
                    #[cfg(test)]
                    trace_step("network baseline current preflight error");
                })?;
                origin.no_allows(window, expected).inspect_err(|_| {
                    #[cfg(test)]
                    trace_step("network baseline no_allows preflight error");
                })?;
                origin.reader.inspect_in_window(window, |facts| {
                    compare_initial(
                        carrier,
                        &facts.routes,
                        &facts.dns,
                        facts.protected_record.as_deref(),
                    )
                    .inspect_err(|_| {
                        #[cfg(test)]
                        {
                            let c = &carrier.identity;
                            trace_step(&format!(
                                "network baseline compare_initial error sources={} current={} pending={} active={} pending_active={} stopping={} protected_record={} dns_name_server_present={} dns_name_server_nonempty={} dns_profile_name_server_present={} dns_profile_name_server_nonempty={} dns_scope_match={} dns_guid_match={} dns_index_match={} dns_luid_match={}",
                                carrier.sources.len(),
                                facts.routes.current.len(),
                                facts.routes.pending.is_some(),
                                facts.routes.active.is_some(),
                                facts.routes.pending_active.is_some(),
                                facts.routes.stopping,
                                facts.protected_record.is_some(),
                                facts.dns.settings.name_server.is_some(),
                                facts.dns.settings.name_server.as_ref().is_some_and(|s| !s.is_empty()),
                                facts.dns.settings.profile_name_server.is_some(),
                                facts.dns.settings.profile_name_server.as_ref().is_some_and(|s| !s.is_empty()),
                                facts.dns.interface.scope == c.scope,
                                facts.dns.interface.guid == c.proof.guid,
                                facts.dns.interface.index == c.proof.index,
                                facts.dns.interface.luid == c.proof.luid,
                            ));
                        }
                    })?;
                    // No caller-supplied snapshot or public data constructor.
                    sink.retain(Rc::new(NativeNetworkBaselineRead {
                        origin: origin.clone(),
                        snapshot: facts.dns.clone(),
                    }))
                }).inspect_err(|_| {
                    #[cfg(test)]
                    trace_step("network baseline reader inspect error");
                })?;
                origin.no_allows(window, expected).inspect_err(|_| {
                    #[cfg(test)]
                    trace_step("network baseline no_allows postflight error");
                })?;
                origin.current(pin, expected).inspect_err(|_| {
                    #[cfg(test)]
                    trace_step("network baseline current postflight error");
                })?;
                origin.capture_window(window).inspect_err(|_| {
                    #[cfg(test)]
                    trace_step("network baseline capture_window postflight error");
                })
            })
        }
        /// Available even after capture postflight Err/unwind. Historical fact
        /// only; no successful capture/effect/Source revival is claimed.
        pub(crate) fn read_pin(&self) -> io::Result<Rc<NativeNetworkBaselineRead<A>>> {
            self.capture.read()
        }
    }
    impl<A: WindowBindingAttestor> NativeNetworkBaselineRead<A> {
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
    }
}
#[cfg(test)]
#[path = "member_carrier_network_baseline_tests.rs"]
mod tests;
