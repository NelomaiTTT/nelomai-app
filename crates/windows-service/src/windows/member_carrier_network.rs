//! Exact network comparison facts for the carrier actor. No native mutation,
//! route/DNS adoption, factory selection or WFP/lifecycle permission here.
#![allow(dead_code)]
#[cfg(test)]
use crate::member_routes::NativeProof;
use crate::{
    member_carrier_guard::{Carrier, Identity, Member, Model},
    member_routes::Row,
};
use nelomai_client_tunnel::redundancy::{
    network::{NetworkJournal, NetworkValue, RouteScope, RouteValue},
    Slot,
};
use std::io;

struct Sources {
    carrier: Carrier,
    members: [Option<Identity>; 2],
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RouteFact {
    pub expected: RouteValue,
    pub actual: Option<Row>,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NetworkFacts {
    pub current: Vec<RouteFact>,
    pub pending: Option<Vec<RouteFact>>,
    pub carrier_rows: Vec<Row>,
    pub egress_rows: [Vec<Row>; 2],
    pub active: Option<Slot>,
    pub pending_active: Option<Slot>,
    pub stopping: bool,
}
fn failed() -> io::Error {
    io::Error::other("carrier_network_read_conflict")
}
#[derive(Default)]
struct NetworkRecordHistory {
    seen: std::cell::Cell<bool>,
}
impl NetworkRecordHistory {
    /// Read-only IO orchestration. The native caller supplies the concrete
    /// terminal-history lease; this private helper grants no native authority.
    /// Postflight is mandatory even if private IO or the consumer returned Err.
    fn inspect_terminal_record<T>(
        &self,
        mut terminal_lease: impl FnMut() -> io::Result<()>,
        read: impl FnMut() -> io::Result<Option<Vec<u8>>>,
        inspect: impl FnOnce(Option<Vec<u8>>) -> io::Result<T>,
    ) -> io::Result<T> {
        terminal_lease()?;
        let result = self.inspect(read, inspect);
        terminal_lease()?;
        result
    }
    fn inspect<T>(
        &self,
        mut read: impl FnMut() -> io::Result<Option<Vec<u8>>>,
        inspect: impl FnOnce(Option<Vec<u8>>) -> io::Result<T>,
    ) -> io::Result<T> {
        let before = read()?;
        if self.seen.get() && before.is_none() {
            return Err(failed());
        }
        if before.is_some() {
            self.seen.set(true);
        }
        let result = inspect(before.clone());
        let after = read()?;
        if after.is_some() {
            self.seen.set(true);
        }
        if before != after {
            return Err(failed());
        }
        result
    }
}
fn checked_samples<T: PartialEq, R>(
    mut read: impl FnMut() -> io::Result<T>,
    inspect: impl FnOnce(&T) -> io::Result<R>,
) -> io::Result<R> {
    let before = read()?;
    let result = inspect(&before);
    if read()? != before {
        return Err(failed());
    }
    result
}
fn compare_routes(
    s: &Sources,
    journal: &NetworkJournal,
    physical: &[(u32, u64, [u8; 16])],
    native: &[Row],
) -> io::Result<NetworkFacts> {
    let scope = &s.carrier.identity.scope;
    let model = Model::new(
        scope.clone(),
        s.carrier.clone(),
        s.members.clone().map(|identity| {
            identity.map(|identity| Member {
                identity,
                probes: vec![],
            })
        }),
        None,
    )
    .map_err(|_| failed())?;
    if model.carrier.as_ref() != Some(&s.carrier)
        || physical.len() > 32768
        || native.len() > crate::member_routes::MAX_TABLE_ROWS
    {
        return Err(failed());
    }
    let mut ids = std::collections::BTreeMap::new();
    for member in s.members.iter().flatten() {
        ids.insert(member.proof.index, (member.proof.luid, member.proof.guid));
    }
    for &(index, luid, guid) in physical {
        if index == 0
            || luid == 0
            || guid == [0; 16]
            || index == s.carrier.identity.proof.index
            || luid == s.carrier.identity.proof.luid
            || guid == s.carrier.identity.proof.guid
            || s.members
                .iter()
                .flatten()
                .any(|m| m.proof.index == index || m.proof.luid == luid || m.proof.guid == guid)
            || ids
                .insert(index, (luid, guid))
                .is_some_and(|previous| previous != (luid, guid))
        {
            return Err(failed());
        }
    }
    let view = journal.read_view()?;
    // A full table is sampled once. Avoid a quadratic scan of up to 32768
    // journal values against up to 65536 native rows under the actor deadline.
    let mut native_keys = std::collections::BTreeMap::new();
    for row in native {
        native_keys
            .entry((row.route.interface, row.route.destination))
            .or_insert_with(Vec::new)
            .push(row);
    }
    let read = |values: Vec<&NetworkValue>| -> io::Result<Vec<RouteFact>> {
        values
            .into_iter()
            .map(|value| {
                let NetworkValue::Route(expected) = value else {
                    return Err(failed());
                };
                if expected.scope != RouteScope::WindowsInterface(expected.interface)
                    || expected.interface == s.carrier.identity.proof.index
                    || !ids.contains_key(&expected.interface)
                {
                    return Err(failed());
                }
                let rows = native_keys
                    .get(&(expected.interface, expected.destination))
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                if rows.len() > 1 {
                    return Err(failed());
                }
                Ok(RouteFact {
                    expected: expected.clone(),
                    actual: rows.first().map(|row| (*row).clone()),
                })
            })
            .collect()
    };
    Ok(NetworkFacts {
        current: read(view.current().collect())?,
        pending: view
            .pending()
            .map(|values| read(values.collect()))
            .transpose()?,
        carrier_rows: native
            .iter()
            .filter(|row| row.route.interface == s.carrier.identity.proof.index)
            .cloned()
            .collect(),
        egress_rows: std::array::from_fn(|i| {
            native
                .iter()
                .filter(|row| {
                    s.members[i]
                        .as_ref()
                        .is_some_and(|m| row.route.interface == m.proof.index)
                })
                .cloned()
                .collect()
        }),
        active: view.recorded_active(),
        pending_active: view.pending_active(),
        stopping: view.stopping(),
    })
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::windows::{
        member_carrier_guard::{Bindings, WindowBindingAttestor},
        member_carrier_network_baseline::native::NativeNetworkBaselineRead,
        member_carrier_network_gate::native::NativeNetworkGate,
        member_carrier_runtime::native::{
            NativeBindingsWindow, NativeClosingRead, NativeSourceRead, RetiredCarrierRead,
        },
        member_session::{NativeNetworkRecord, NativeSessionFiles, RecordKind, SessionFiles},
    };
    use crate::{
        member_dns as dns,
        member_physical::{Family, InterfaceIdentity, PhysicalProof, PhysicalRoute},
    };
    use std::rc::Rc;

    /// Retains the SAME actual source pin, not an imported network/DNS model.
    /// All methods are read-only facts. Real G must separately attest expected
    /// route plan, DNS journal, bases/priority and HELD sockets before permits.
    /// No callback can obtain an OwnedDns/RowIo object or perform a write here.
    pub(crate) struct NativeNetworkRead {
        source: Rc<NativeSourceRead>,
        history: Rc<NetworkRecordHistory>,
    }
    /// Cleanup facts through the original C Closing pin. Shares the observed
    /// protected-network history with its originating live reader; it cannot
    /// turn a disappeared owned record into a fresh empty journal.
    pub(crate) struct NativeClosingNetworkRead {
        closing: Rc<NativeClosingRead>,
        history: Rc<NetworkRecordHistory>,
    }
    #[derive(Debug, PartialEq, Eq)]
    pub(crate) struct NativeNetworkFacts {
        pub routes: NetworkFacts,
        pub dns: dns::Snapshot,
        pub protected_record: Option<Vec<u8>>,
    }
    impl NativeNetworkRead {
        pub(crate) fn new(source: Rc<NativeSourceRead>) -> Self {
            Self {
                source,
                history: Rc::new(NetworkRecordHistory::default()),
            }
        }
        /// Read-only prerequisite, NOT a NativeEmpty/removal effect grant.
        /// Caller holds the original current Pair Calling/ACK bracket and this
        /// SAME Retired reader's full-native-empty bindings/history bracket.
        /// The concrete gate supplies the SAME retained network owner's ACKs;
        /// this reader and baseline alone never imply an absent/restored owner.
        pub(crate) fn verify_native_empty_in_retired_bracket<A: WindowBindingAttestor>(
            &self,
            record: &crate::member_carrier_pair::Record,
            retired: &RetiredCarrierRead,
            bindings: &Bindings,
            baseline: &NativeNetworkBaselineRead<A>,
            gate: &Rc<NativeNetworkGate<A>>,
        ) -> io::Result<()> {
            if !baseline.matches_reader(self)
                || !baseline.matches_source_origin(&self.source)
                || !retired.matches_source_origin(&self.source)
            {
                return Err(failed());
            }
            gate.verify_native_empty_in_retired_bracket(record, retired, bindings, baseline, self)
        }
        /// Private original protected-record history join. No Source/Retired
        /// SDK entry and no old C DNS lookup. The gate authenticates these
        /// immutable original files against Runtime before and after the call;
        /// canonical typed birth/cleanup files deliberately deny Network here.
        pub(crate) fn inspect_original_retired_record<T>(
            &self,
            source: &NativeSourceRead,
            retired: &RetiredCarrierRead,
            files: &mut NativeSessionFiles,
            inspect: impl FnOnce(Option<Vec<u8>>) -> io::Result<T>,
        ) -> io::Result<T> {
            if !std::ptr::eq(self.source.as_ref(), source) || !retired.matches_source_origin(source)
            {
                return Err(failed());
            }
            // This is a lease over an ALREADY ACTIVE SDK bracket, not another
            // Retired.inspect. Without that original outer bracket it denies.
            retired
                .inspect_history_in_bracket(|_| Ok(()))
                .map_err(|_| failed())?;
            let result = self.history.inspect(
                || files.read(source.network_scope(), RecordKind::Network),
                inspect,
            );
            retired
                .inspect_history_in_bracket(|_| Ok(()))
                .map_err(|_| failed())?;
            result
        }
        /// Separate terminal FullEmpty fact channel. The caller holds this
        /// SAME Retired reader's actual terminal full-native-empty history
        /// bracket and authenticates original files/current Pair/Calling.
        /// This does not reopen a source, project terminal state to Closing9,
        /// query old C DNS, or grant any native cleanup effect.
        pub(crate) fn inspect_original_full_empty_record<T>(
            &self,
            source: &NativeSourceRead,
            retired: &RetiredCarrierRead,
            files: &mut NativeSessionFiles,
            inspect: impl FnOnce(Option<Vec<u8>>) -> io::Result<T>,
        ) -> io::Result<T> {
            if !std::ptr::eq(self.source.as_ref(), source) || !retired.matches_source_origin(source)
            {
                return Err(failed());
            }
            // Both leases join the ALREADY ACTIVE actual terminal bracket.
            // The SAME observed-record history survives live/Closing/terminal
            // reads; neither a callback failure nor postread loss resets it.
            self.history.inspect_terminal_record(
                || {
                    retired
                        .inspect_terminal_history_in_bracket(|_| Ok(()))
                        .map_err(|_| failed())
                },
                || files.read(source.network_scope(), RecordKind::Network),
                inspect,
            )
        }
        pub(crate) fn closing_read(
            &self,
            closing: Rc<NativeClosingRead>,
        ) -> io::Result<NativeClosingNetworkRead> {
            if !closing.matches_source_origin(&self.source) {
                return Err(failed());
            }
            Ok(NativeClosingNetworkRead {
                closing,
                history: self.history.clone(),
            })
        }
        /// Ordinary facts only; Closing needs its separately retained original
        /// cleanup reader. Never revive a failed live source or adopt saved NICs.
        /// The enclosing actor must supervise the WHOLE call with its actual
        /// NativeDeadline; source sampling enforces its Calling phase throughout.
        pub(crate) fn inspect<T>(
            &self,
            inspect: impl FnOnce(&NativeNetworkFacts) -> io::Result<T>,
        ) -> io::Result<T> {
            self.source
                .inspect_window(|window| {
                    self.inspect_in_window(window, inspect)
                        .map_err(|_| denied())
                })
                .map_err(|_| failed())
        }
        /// Factual network/DNS read joined to this SAME opaque source window.
        /// Does not enter Source.inspect again or acquire the actual Guard.
        /// The caller must not already be inside window.inspect's joined read.
        pub(crate) fn inspect_in_window<T>(
            &self,
            window: &NativeBindingsWindow<'_>,
            inspect: impl FnOnce(&NativeNetworkFacts) -> io::Result<T>,
        ) -> io::Result<T> {
            if !window.matches_source(&self.source) {
                return Err(failed());
            }
            window
                .inspect(|bindings| {
                    checked_samples(|| self.sample(bindings), inspect).map_err(|_| denied())
                })
                .map_err(|_| failed())
        }
        fn sample(&self, bindings: &Bindings) -> io::Result<NativeNetworkFacts> {
            sample_network(&self.history, self.source.network_scope(), bindings, || {
                self.source.protected_network_record().map_err(|_| failed())
            })
        }
    }
    impl NativeClosingNetworkRead {
        /// Read-only Closing channel. The actual G still authenticates exact
        /// stage2/current Pair/Calling and retained network/row owners before
        /// any restoration. No live source is entered or revived here.
        pub(crate) fn inspect_in_window<T>(
            &self,
            window: &NativeBindingsWindow<'_>,
            inspect: impl FnOnce(&NativeNetworkFacts) -> io::Result<T>,
        ) -> io::Result<T> {
            if !window.matches_closing(&self.closing) {
                return Err(failed());
            }
            window
                .inspect(|bindings| {
                    checked_samples(
                        || {
                            sample_network(
                                &self.history,
                                self.closing.network_scope(),
                                bindings,
                                || {
                                    self.closing
                                        .protected_network_record()
                                        .map_err(|_| failed())
                                },
                            )
                        },
                        inspect,
                    )
                    .map_err(|_| denied())
                })
                .map_err(|_| failed())
        }
    }
    fn sample_network(
        history: &NetworkRecordHistory,
        scope: &nelomai_client_tunnel::redundancy::SessionScope,
        bindings: &Bindings,
        read_record: impl FnMut() -> io::Result<Option<Vec<u8>>>,
    ) -> io::Result<NativeNetworkFacts> {
        let sources = Sources {
            carrier: bindings.carrier.clone().ok_or_else(failed)?,
            members: bindings.egress.clone(),
        };
        history.inspect(read_record, |before| {
            let saved = before
                .as_deref()
                .map(|bytes| NativeNetworkRecord::read_comparison(scope, bytes))
                .transpose()?
                .unwrap_or_default();
            read(&sources, &saved, before)
        })
    }
    fn denied() -> crate::windows::member_carrier_wintun::Error {
        crate::windows::member_carrier_wintun::Error::Conflict
    }
    // This short-lived borrowed comparison identity can only be constructed
    // below INSIDE the actual new-created C source callback. It is never exposed
    // to the caller or stored/imported for later mutations.
    struct DnsReadIdentity<'a>(&'a Carrier);
    impl dns::Identity for DnsReadIdentity<'_> {
        fn verify_owned(&mut self, interface: &dns::OwnedInterface) -> dns::Result<dns::Ownership> {
            let c = &self.0.identity;
            if interface.scope != c.scope
                || interface.guid != c.proof.guid
                || interface.luid != c.proof.luid
                || interface.index != c.proof.index
            {
                return Err(dns::DnsError::Ownership);
            }
            Ok(dns::Ownership::NewlyCreated)
        }
    }
    fn read(
        s: &Sources,
        saved: &NativeNetworkRecord,
        protected_record: Option<Vec<u8>>,
    ) -> io::Result<NativeNetworkFacts> {
        let ids = std::iter::once(&s.carrier.identity)
            .chain(s.members.iter().flatten())
            .map(|id| InterfaceIdentity {
                index: id.proof.index,
                luid: id.proof.luid,
                guid: id.proof.guid,
            })
            .collect::<Vec<_>>();
        // ONE full table capture per sample, not an unbounded per-key table
        // reader. Both families and exact physical identity/metrics are retained.
        let physical = crate::windows::member_physical::capture(&ids)?;
        let mut leases = Vec::with_capacity(saved.physical.len());
        for p in &saved.physical {
            let expected = PhysicalRoute {
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
            physical.verify(&expected).map_err(io::Error::other)?;
            leases.push((p.interface, p.luid, p.guid));
        }
        let routes = compare_routes(s, &saved.journal, &leases, physical.rows())?;
        let c = &s.carrier.identity;
        let interface = dns::OwnedInterface {
            scope: c.scope.clone(),
            guid: c.proof.guid,
            luid: c.proof.luid,
            index: c.proof.index,
        };
        let mut dns = crate::windows::member_dns::owned(interface, DnsReadIdentity(&s.carrier))
            .map_err(io::Error::other)?;
        let dns = dns.snapshot().map_err(io::Error::other)?;
        Ok(NativeNetworkFacts {
            routes,
            dns,
            protected_record,
        })
    }
}

#[cfg(test)]
#[path = "member_carrier_network_tests.rs"]
mod tests;
