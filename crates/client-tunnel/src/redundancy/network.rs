//! The session's single route/DNS owner. Platform adapters do exact native
//! compare-and-mutate under the existing privileged manager mutation lock.
//! Write-ahead state is required before side effects; unsuccessful rollback
//! cannot publish a usable active member or discard cleanup ownership.
use super::{driver::RouteRefreshError, Slot};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    io,
    net::IpAddr,
};

const ROUTE_BATCH_SIZE: usize = 32;
const MIN_ROUTE_BATCH_SIZE: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum RouteScope {
    Global,
    Member(u32),
    /// In Linux's main FIB, two routes to the same prefix can coexist with
    /// distinct priorities. An active-member transition needs both rows until
    /// the new coverage is installed.
    LinuxMainPriority(u32),
    /// Windows route-table key includes the interface. This is globally visible,
    /// NOT an interface-bound probe route: only the guarded Windows owner may
    /// use it. Stable keys let a promotion update metrics without deleting a
    /// different logical row that aliases the same native destination/interface.
    WindowsInterface(u32),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteValue {
    pub destination: IpNet,
    pub scope: RouteScope,
    pub interface: u32,
    pub gateway: Option<IpAddr>,
    pub metric: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsValue {
    pub service: String,
    pub servers: Vec<IpAddr>,
}

/// DNS on a session-owned link, never on the physical uplink. Unlike DnsValue,
/// a preexisting value cannot be adopted. Empty means absence, not a baseline.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkDnsValue {
    pub interface: u32,
    pub servers: Vec<IpAddr>,
}

/// Linux RPDB selector for locally generated, device-bound probe sockets only.
/// Never a general source rule or a catch-all rule for user traffic.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundRuleValue {
    pub ipv6: bool,
    pub priority: u32,
    pub table: u32,
    pub interface: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum NetworkValue {
    Route(RouteValue),
    Dns(DnsValue),
    BoundRule(BoundRuleValue),
    LinkDns(LinkDnsValue),
    /// Exactly the routing-only root domain (~.) on an owned link. Journal it
    /// separately because resolved's DNS and Domains setters are not atomic.
    LinkDnsRoute(u32),
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum ResourceKey {
    Route(IpNet, RouteScope),
    Dns(String),
    BoundRule { ipv6: bool, priority: u32 },
    LinkDns(u32),
    LinkDnsRoute(u32),
}

impl NetworkValue {
    pub fn key(&self) -> ResourceKey {
        match self {
            Self::Route(r) => ResourceKey::Route(r.destination, r.scope),
            Self::Dns(d) => ResourceKey::Dns(d.service.clone()),
            Self::LinkDns(d) => ResourceKey::LinkDns(d.interface),
            Self::LinkDnsRoute(i) => ResourceKey::LinkDnsRoute(*i),
            Self::BoundRule(r) => ResourceKey::BoundRule {
                ipv6: r.ipv6,
                priority: r.priority,
            },
        }
    }
    fn valid(&self) -> bool {
        match self {
            Self::LinkDns(d) => {
                d.interface != 0
                    && d.interface <= i32::MAX as u32
                    && !d.servers.is_empty()
                    && d.servers.len() <= 16
                    && d.servers
                        .iter()
                        .all(|s| !s.is_unspecified() && !s.is_multicast())
                    && d.servers.iter().collect::<HashSet<_>>().len() == d.servers.len()
            }
            Self::LinkDnsRoute(i) => *i != 0 && *i <= i32::MAX as u32,
            Self::BoundRule(r) => {
                r.interface != 0 && (1..32766).contains(&r.priority) && r.table > 255
            }
            Self::Route(r) => {
                r.interface != 0
                    && r.destination == r.destination.trunc()
                    && r.gateway
                        .is_none_or(|g| g.is_ipv4() == r.destination.addr().is_ipv4())
                    && match r.scope {
                        RouteScope::Global => true,
                        RouteScope::LinuxMainPriority(priority) => {
                            priority != 0 && r.metric == priority && r.gateway.is_none()
                        }
                        RouteScope::Member(i) | RouteScope::WindowsInterface(i) => i == r.interface,
                    }
            }
            Self::Dns(d) => {
                !d.service.is_empty()
                    && d.service.len() <= 256
                    && !d.service.chars().any(char::is_control)
                    && d.servers.len() <= 16
            }
        }
    }
}

pub trait NetworkSystem {
    /// Unix journal owners record each route mutation before invoking the kernel.
    fn journal_each_write(&self) -> bool {
        false
    }

    /// The link owner retires these routes. A persisted global key cannot
    /// authorize deletion after the link has vanished or changed owners.
    fn observe_routes_on_close(&self) -> bool {
        false
    }

    /// Check the complete FIB rows at the prefixes of a staged Linux plan.
    /// Both priorities are allowed only while both are in the owner ledger.
    fn check_main_routes(
        &mut self,
        _present: &[&RouteValue],
        _target: &[&RouteValue],
    ) -> io::Result<()> {
        Ok(())
    }

    /// Native identity was captured by the privileged member owner. Seal any
    /// platform table binding before generating route/rule/DNS resources.
    fn member_started(&mut self, _slot: Slot, _interface: u32) -> io::Result<()> {
        Ok(())
    }
    /// Release this binding only after the exact native member and its routes
    /// are gone. A failed release remains retryable and never releases a sibling.
    fn member_stopped(&mut self, _slot: Slot, _interface: u32) -> io::Result<()> {
        Ok(())
    }
    /// Invoked only AFTER both native members and all owned network resources
    /// are absent. A binding journal may now release its exact reservations.
    fn session_closed(&mut self) -> io::Result<()> {
        Ok(())
    }
    /// Pure platform expansion for the active member only. An inactive reserve
    /// must not acquire resolver ownership merely because its interface exists.
    fn dns_resources(
        &self,
        _interface: u32,
        servers: &[IpAddr],
        services: &[String],
    ) -> io::Result<Vec<NetworkValue>> {
        Ok(services
            .iter()
            .map(|service| {
                NetworkValue::Dns(DnsValue {
                    service: service.clone(),
                    servers: servers.to_vec(),
                })
            })
            .collect())
    }
    /// Read-only dependency check. Platforms may accept additional native
    /// metadata here (e.g. a kernel/DHCP route), but never in ownership CAS.
    fn verify_retained_route(&mut self, route: &RouteValue) -> io::Result<bool> {
        let value = NetworkValue::Route(route.clone());
        Ok(self.read(&value.key())? == Some(value))
    }
    /// Confirm how the kernel routes an unbound member transport socket after
    /// the committed data routes change. Native Unix implementations verify the
    /// selected physical link against their read-only discovery.
    fn verify_physical_endpoint(
        &mut self,
        _endpoint: IpAddr,
        _retained: &[RouteValue],
    ) -> io::Result<()> {
        Ok(())
    }
    /// Pure expansion of a route into the platform's separately journaled
    /// resources. Linux member routes need an oif rule as well as a private-table
    /// route; never create that rule as an invisible side effect of route CAS.
    fn route_resources(&self, route: RouteValue) -> io::Result<Vec<NetworkValue>> {
        Ok(vec![NetworkValue::Route(route)])
    }
    /// Must fail on ambiguous/multiple native matches, never select an arbitrary
    /// row. Missing resource is None, not a failed query disguised as absence.
    fn read(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>>;
    /// Read a group without mutation, preserving input order and result count.
    /// Overrides may share a fresh native dump only within this call. CAS and
    /// post-write reads must still inspect the current native state separately.
    fn read_many(&mut self, keys: &[ResourceKey]) -> io::Result<Vec<Option<NetworkValue>>> {
        keys.iter().map(|key| self.read(key)).collect()
    }
    /// Recheck exact native identity, then mutate only that resource. A failure
    /// may have partially applied; the owner will inspect before compensating.
    fn compare_exchange(
        &mut self,
        key: &ResourceKey,
        before: Option<&NetworkValue>,
        after: Option<&NetworkValue>,
    ) -> io::Result<()>;
    /// A definite no-write error excludes this resource from rollback.
    fn compare_exchange_prepared(
        &mut self,
        key: &ResourceKey,
        before: Option<&NetworkValue>,
        after: Option<&NetworkValue>,
        prepare: Option<&mut dyn FnMut() -> io::Result<()>>,
    ) -> Result<(), RouteRefreshError> {
        self.prepare_exchange(key, before, prepare)?;
        self.compare_exchange(key, before, after)
            .map_err(Into::into)
    }

    fn prepare_exchange(
        &mut self,
        key: &ResourceKey,
        before: Option<&NetworkValue>,
        prepare: Option<&mut dyn FnMut() -> io::Result<()>>,
    ) -> Result<(), RouteRefreshError> {
        let check = |system: &mut Self| {
            if system.read(key)?.as_ref() != before {
                return Err(conflict());
            }
            Ok(())
        };
        check(self).map_err(RouteRefreshError::Unchanged)?;
        if let Some(prepare) = prepare {
            prepare().map_err(RouteRefreshError::Unchanged)?;
            // Another owner may have changed the resource during the disk write.
            check(self).map_err(RouteRefreshError::Unchanged)?;
        }
        Ok(())
    }
}
pub trait NetworkJournalStore {
    /// Atomic durable private-file replacement. No side effect is permitted
    /// unless saving this journal succeeded; must not write an untrusted path.
    fn save(&mut self, value: &NetworkJournal) -> io::Result<()>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    original: Option<NetworkValue>,
    current: NetworkValue,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    target: Vec<Entry>,
    active: Option<Slot>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteIntent {
    before: Option<RouteValue>,
    after: Option<RouteValue>,
}

impl RouteIntent {
    fn new(before: Option<&NetworkValue>, after: Option<&NetworkValue>) -> Self {
        let route = |value: Option<&NetworkValue>| match value {
            Some(NetworkValue::Route(route)) => Some(route.clone()),
            _ => None,
        };
        Self {
            before: route(before),
            after: route(after),
        }
    }

    fn key(&self) -> ResourceKey {
        let route = self
            .before
            .as_ref()
            .or(self.after.as_ref())
            .expect("route intent");
        ResourceKey::Route(route.destination, route.scope)
    }

    fn matches(&self, value: &NetworkValue) -> bool {
        matches!(value, NetworkValue::Route(route)
            if self.before.as_ref() == Some(route) || self.after.as_ref() == Some(route))
    }

    fn valid(&self) -> bool {
        let Some(route) = self.before.as_ref().or(self.after.as_ref()) else {
            return false;
        };
        let key = (route.destination, route.scope);
        self.before.iter().chain(&self.after).all(|route| {
            (route.destination, route.scope) == key
                && !matches!(route.scope, RouteScope::WindowsInterface(_))
                && NetworkValue::Route(route.clone()).valid()
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkJournal {
    owned: Vec<Entry>,
    active: Option<Slot>,
    pending: Option<Pending>,
    stopping: bool,
    /// A write may have occurred at these keys. Intent alone never confers deletion authority.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    route_intents: Vec<RouteIntent>,
}

/// Validated borrowed comparison DATA only. This exposes the complete durable
/// lists to an independent native readback; it does not establish ownership,
/// permission to resume, applied ACKs, or absence of foreign native resources.
/// There is no mutation, serialization, construction or effect API on the view.
pub struct NetworkReadView<'a> {
    journal: &'a NetworkJournal,
}
impl NetworkReadView<'_> {
    pub fn current(&self) -> impl Iterator<Item = &NetworkValue> {
        self.journal.owned.iter().map(|entry| &entry.current)
    }
    pub fn pending(&self) -> Option<impl Iterator<Item = &NetworkValue>> {
        self.journal
            .pending
            .as_ref()
            .map(|pending| pending.target.iter().map(|entry| &entry.current))
    }
    /// Recorded metadata, including during ambiguous/stopping transitions.
    /// Never use this as the usable/published active role; NetworkOwner::active
    /// keeps its existing cleanup fence unchanged.
    pub fn recorded_active(&self) -> Option<Slot> {
        self.journal.active
    }
    pub fn pending_active(&self) -> Option<Slot> {
        self.journal
            .pending
            .as_ref()
            .and_then(|pending| pending.active)
    }
    pub fn stopping(&self) -> bool {
        self.journal.stopping
    }
}

impl NetworkJournal {
    fn forget_route(&mut self, key: &ResourceKey) {
        self.owned.retain(|entry| &entry.current.key() != key);
        if let Some(pending) = &mut self.pending {
            pending.target.retain(|entry| &entry.current.key() != key);
        }
    }

    fn clear_route_intent(&mut self, key: &ResourceKey) {
        self.route_intents.retain(|intent| &intent.key() != key);
    }

    pub fn read_view(&self) -> io::Result<NetworkReadView<'_>> {
        validate_entries(&self.owned)?;
        if let Some(pending) = &self.pending {
            validate_entries(&pending.target)?;
        }
        let mut keys = HashSet::new();
        if self.route_intents.len() > 32768
            || !self
                .route_intents
                .iter()
                .all(|intent| intent.valid() && keys.insert(intent.key()))
        {
            return Err(invalid());
        }
        Ok(NetworkReadView { journal: self })
    }
    /// Only the Windows factory, after proving a different boot, may retire
    /// these nonpersistent IP Helper route rows without querying reused indices.
    /// Never discard a saved baseline, global DNS, or another platform's state.
    pub fn windows_boot_resources_are_ephemeral(&self) -> bool {
        self.route_intents.is_empty()
            && validate_entries(&self.owned).is_ok()
            && self
                .pending
                .as_ref()
                .is_none_or(|pending| validate_entries(&pending.target).is_ok())
            && self
                .owned
                .iter()
                .chain(self.pending.iter().flat_map(|p| &p.target))
                .all(|entry| {
                    entry.original.is_none()
                        && matches!(
                            entry.current,
                            NetworkValue::Route(RouteValue {
                                scope: RouteScope::WindowsInterface(_),
                                ..
                            })
                        )
                })
    }
    /// A Unix route has no durable creator ID. A persisted tuple can also
    /// describe a replacement installed while the service was down. On replay
    /// keep it as read-only evidence until the owned tunnel disappears.
    pub fn unix_recovery(mut self) -> io::Result<Self> {
        self.read_view()?;
        let mut indices = std::collections::HashMap::new();
        let uncertain: HashSet<_> = self.route_intents.iter().map(RouteIntent::key).collect();
        for (pending, entries) in [
            (false, self.owned.as_slice()),
            (
                true,
                self.pending
                    .as_ref()
                    .map_or(&[][..], |p| p.target.as_slice()),
            ),
        ] {
            for entry in entries {
                let NetworkValue::Route(route) = &entry.current else {
                    continue;
                };
                if matches!(route.scope, RouteScope::WindowsInterface(_)) {
                    return Err(invalid());
                }
                let key = entry.current.key();
                if uncertain.contains(&key) {
                    continue;
                }
                let index = *indices.entry(key).or_insert_with(|| {
                    self.route_intents.push(RouteIntent {
                        before: None,
                        after: None,
                    });
                    self.route_intents.len() - 1
                });
                let intent = &mut self.route_intents[index];
                if pending {
                    intent.after = Some(route.clone());
                } else {
                    intent.before = Some(route.clone());
                }
            }
        }
        self.owned
            .retain(|e| !matches!(e.current, NetworkValue::Route(_)));
        if let Some(pending) = &mut self.pending {
            pending
                .target
                .retain(|e| !matches!(e.current, NetworkValue::Route(_)));
        }
        self.read_view()?;
        Ok(self)
    }

    /// Cleanup-only projection for a trusted Unix factory which has proved a
    /// different OS boot. Native links, routes and per-link resolver state from
    /// that boot no longer confer authority; persistent service DNS still does.
    /// Never use this to skip cleanup within the same boot or on Windows.
    pub fn persistent_dns_cleanup(&self) -> io::Result<Self> {
        self.read_view()?;
        let dns = |entries: &[Entry]| {
            entries
                .iter()
                .filter(|entry| matches!(entry.current, NetworkValue::Dns(_)))
                .cloned()
                .collect::<Vec<_>>()
        };
        let owned = dns(&self.owned);
        let target = self
            .pending
            .as_ref()
            .map(|pending| dns(&pending.target))
            .unwrap_or_else(|| owned.clone());
        // Also reconcile a previous restoration whose ACK was lost. A value
        // equal to the saved baseline needs no write; a foreign value is never
        // restored over. Existing pending cleanup supplies that exact CAS logic.
        Ok(Self {
            owned,
            active: None,
            pending: Some(Pending {
                target,
                active: None,
            }),
            stopping: true,
            route_intents: Vec::new(),
        })
    }
}

pub struct NetworkOwner<B, S> {
    system: B,
    store: S,
    journal: NetworkJournal,
}

impl<B: NetworkSystem, S: NetworkJournalStore> NetworkOwner<B, S> {
    pub fn fresh(system: B, store: S) -> Self {
        Self {
            system,
            store,
            journal: NetworkJournal::default(),
        }
    }

    /// The enclosing native session validates runtime/session/generation and
    /// interface identities before passing in this private persisted journal.
    pub fn recover(system: B, store: S, journal: NetworkJournal) -> io::Result<Self> {
        journal.read_view()?;
        let owner = Self {
            system,
            store,
            journal,
        };
        // Loading state is not permission to resume traffic or recreate old
        // interfaces. The enclosing lifecycle chooses reconciliation or Stop.
        Ok(owner)
    }

    pub fn active(&self) -> Option<Slot> {
        if self.cleanup_pending() {
            None
        } else {
            self.journal.active
        }
    }
    pub fn cleanup_pending(&self) -> bool {
        self.journal.pending.is_some()
            || !self.journal.route_intents.is_empty()
            || (self.journal.stopping && !self.journal.owned.is_empty())
    }
    pub fn has_resources(&self) -> bool {
        !self.journal.owned.is_empty()
            || self.journal.pending.is_some()
            || !self.journal.route_intents.is_empty()
    }
    /// Exact committed/pending route values, for owner-scoped physical-row
    /// exclusion. Keep before/after metadata at the same key distinct; never
    /// exclude a foreign row merely because its destination matches. No IO.
    pub fn excluded_routes(&self) -> Vec<RouteValue> {
        let mut seen = HashSet::new();
        self.journal
            .owned
            .iter()
            .chain(self.journal.pending.iter().flat_map(|p| p.target.iter()))
            .filter_map(|entry| match &entry.current {
                NetworkValue::Route(route)
                    if seen.insert((
                        route.destination,
                        route.scope,
                        route.interface,
                        route.gateway,
                        route.metric,
                    )) =>
                {
                    Some(route.clone())
                }
                _ => None,
            })
            .collect()
    }
    /// Read-only input to physical-uplink discovery. Never trust an app-provided
    /// exclusion of rows: include both committed and pending owned routes.
    pub fn owned_route_destinations(&self) -> Vec<IpNet> {
        let mut routes = self
            .journal
            .owned
            .iter()
            .chain(self.journal.pending.iter().flat_map(|p| p.target.iter()))
            .filter_map(|e| match &e.current {
                NetworkValue::Route(r) => Some(r.destination),
                _ => None,
            })
            .collect::<Vec<_>>();
        routes.sort();
        routes.dedup();
        routes
    }
    pub fn system_mut(&mut self) -> &mut B {
        &mut self.system
    }
    pub fn into_parts(self) -> (B, S) {
        (self.system, self.store)
    }

    pub fn select(&mut self, active: Slot, values: Vec<NetworkValue>) -> io::Result<()> {
        self.select_plan(active, values, self.system.journal_each_write())
            .map_err(Into::into)
    }

    /// Fence native writes with durable intents during a live refresh.
    pub fn select_with_outcome(
        &mut self,
        active: Slot,
        values: Vec<NetworkValue>,
    ) -> Result<(), RouteRefreshError> {
        self.select_plan(active, values, true)
    }

    fn select_plan(
        &mut self,
        active: Slot,
        values: Vec<NetworkValue>,
        journal_each_write: bool,
    ) -> Result<(), RouteRefreshError> {
        if self.journal.stopping || self.cleanup_pending() {
            return Err(io::Error::other("network_cleanup_pending").into());
        }
        self.transition(Some(active), values, journal_each_write)
    }

    /// Switch an independent crypto slot while retaining the exact shared
    /// native resources. The callback runs once, only after durable pending ACK.
    /// Any ambiguity retains pending for cleanup; it never restores the old role
    /// or reconciles/recreates a missing route.
    pub fn select_metadata(
        &mut self,
        expected: Slot,
        active: Slot,
        switch: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        if self.journal.stopping
            || self.cleanup_pending()
            || self.journal.active != Some(expected)
            || expected == active
        {
            return Err(io::Error::other("network_metadata_fenced"));
        }
        validate_entries(&self.journal.owned)?;
        for entry in &self.journal.owned {
            if self.system.read(&entry.current.key())?.as_ref() != Some(&entry.current) {
                return Err(conflict());
            }
        }
        // Retain the write attempt before persistence, including lost ACKs or
        // unwind. Equality on subsequent readback is never an applied ACK.
        self.journal.pending = Some(Pending {
            target: self.journal.owned.clone(),
            active: Some(active),
        });
        self.store.save(&self.journal)?;
        switch()?;
        for entry in &self.journal.owned {
            if self.system.read(&entry.current.key())?.as_ref() != Some(&entry.current) {
                return Err(conflict());
            }
        }
        let mut committed = self.journal.clone();
        committed.active = Some(active);
        committed.pending = None;
        self.store.save(&committed)?;
        self.journal = committed;
        Ok(())
    }

    /// Retire only owned routes, preserving every retained resource exactly.
    /// A failed delete/save leaves pending for cleanup, never a recreating rollback.
    pub fn retire_owned_route(
        &mut self,
        active: Slot,
        route: Option<&RouteValue>,
    ) -> io::Result<()> {
        if self.journal.stopping || self.cleanup_pending() || self.journal.active != Some(active) {
            return Err(io::Error::other("network_retirement_fenced"));
        }
        validate_entries(&self.journal.owned)?;
        let value = route.cloned().map(NetworkValue::Route);
        if let Some(value) = &value {
            if find(&self.journal.owned, &value.key()).is_some_and(|entry| entry.current != *value)
            {
                return Err(conflict());
            }
        }
        let target = self
            .journal
            .owned
            .iter()
            .filter(|entry| Some(&entry.current) != value.as_ref())
            .cloned()
            .collect::<Vec<_>>();
        let removed = self
            .journal
            .owned
            .iter()
            .filter(|entry| find(&target, &entry.current.key()).is_none())
            .cloned()
            .collect::<Vec<_>>();
        if removed.iter().any(|entry| {
            entry.original.is_some() || !matches!(entry.current, NetworkValue::Route(_))
        }) {
            return Err(invalid());
        }
        for entry in &self.journal.owned {
            if self.system.read(&entry.current.key())?.as_ref() != Some(&entry.current) {
                return Err(conflict());
            }
        }
        self.journal.pending = Some(Pending {
            target: target.clone(),
            active: Some(active),
        });
        self.store.save(&self.journal)?;
        for entry in removed {
            self.system
                .compare_exchange(&entry.current.key(), Some(&entry.current), None)?;
            if self.system.read(&entry.current.key())?.is_some() {
                return Err(conflict());
            }
        }
        for entry in &target {
            if self.system.read(&entry.current.key())?.as_ref() != Some(&entry.current) {
                return Err(conflict());
            }
        }
        let committed = NetworkJournal {
            owned: target,
            active: Some(active),
            pending: None,
            stopping: false,
            route_intents: Vec::new(),
        };
        self.store.save(&committed)?;
        self.journal = committed;
        Ok(())
    }

    pub fn prepare(&mut self, values: Vec<NetworkValue>) -> io::Result<()> {
        if self.journal.active.is_some() || self.journal.stopping || self.cleanup_pending() {
            return Err(io::Error::other("network_prepare_fenced"));
        }
        self.transition(None, values, self.system.journal_each_write())
            .map_err(Into::into)
    }

    pub fn cleanup(&mut self) -> io::Result<()> {
        // Local Stop fences any promotion even if persistence or cleanup fails.
        self.journal.stopping = true;
        if self.system.observe_routes_on_close() {
            self.journal = self.journal.clone().unix_recovery()?;
        }
        self.store.save(&self.journal)?;
        self.prepare_pending_cleanup()?;
        self.transition(None, Vec::new(), self.system.journal_each_write())?;
        self.settle_route_intents()
    }

    /// The caller verified that the original link owners have exited. On a
    /// platform that retires routes with its links, an identical row now
    /// belongs to the replacement link. Keep persistent DNS for cleanup.
    pub fn confirm_links_closed(&mut self) -> io::Result<()> {
        if self.system.observe_routes_on_close() && self.has_resources() {
            let next = self.journal.persistent_dns_cleanup()?;
            self.store.save(&next)?;
            self.journal = next;
        }
        Ok(())
    }

    /// Retire only the routes of a released inactive link. Leave other
    /// members' routes and the DNS baseline owned by the active session.
    pub fn confirm_link_closed(&mut self, interface: u32) -> io::Result<()> {
        if !self.system.observe_routes_on_close() {
            return Ok(());
        }
        self.journal.read_view()?;
        let mut next = self.journal.clone();
        let retain = |entry: &Entry| {
            !matches!(&entry.current,
            NetworkValue::Route(route) if route.interface == interface)
        };
        next.owned.retain(retain);
        if let Some(pending) = &mut next.pending {
            pending.target.retain(retain);
        }
        for intent in &mut next.route_intents {
            if intent
                .before
                .as_ref()
                .is_some_and(|route| route.interface == interface)
            {
                intent.before = None;
            }
            if intent
                .after
                .as_ref()
                .is_some_and(|route| route.interface == interface)
            {
                intent.after = None;
            }
        }
        next.route_intents
            .retain(|intent| intent.before.is_some() || intent.after.is_some());
        self.store.save(&next)?;
        self.journal = next;
        Ok(())
    }

    fn settle_route_intents(&mut self) -> io::Result<()> {
        if self.journal.route_intents.is_empty() {
            return Ok(());
        }
        let keys: Vec<_> = self
            .journal
            .route_intents
            .iter()
            .map(RouteIntent::key)
            .collect();
        let mut error = None;
        let mut retired = HashSet::new();
        let mut observe =
            |intent: &RouteIntent, current: io::Result<Option<NetworkValue>>| match current {
                Ok(Some(value)) if intent.matches(&value) => (),
                Ok(_) => {
                    retired.insert(intent.key());
                }
                Err(err) => {
                    error.get_or_insert(err);
                }
            };
        match self.system.read_many(&keys) {
            Ok(values) if values.len() == keys.len() => {
                for (intent, current) in self.journal.route_intents.iter().zip(values) {
                    observe(intent, Ok(current));
                }
            }
            Ok(_) => return Err(invalid()),
            Err(_) => {
                // Keep unrelated recovery moving when a single native row is ambiguous.
                for (key, intent) in keys.iter().zip(&self.journal.route_intents) {
                    observe(intent, self.system.read(key));
                }
            }
        }
        if !retired.is_empty() {
            let mut next = self.journal.clone();
            next.route_intents.retain(|i| !retired.contains(&i.key()));
            next.owned.retain(|e| !retired.contains(&e.current.key()));
            if let Some(pending) = &mut next.pending {
                pending
                    .target
                    .retain(|e| !retired.contains(&e.current.key()));
            }
            self.store.save(&next)?;
            self.journal = next;
        }
        if let Some(error) = error {
            return Err(error);
        }
        if !self.journal.route_intents.is_empty() {
            return Err(unconfirmed_route());
        }
        Ok(())
    }

    fn transition(
        &mut self,
        active: Option<Slot>,
        values: Vec<NetworkValue>,
        journal_each_write: bool,
    ) -> Result<(), RouteRefreshError> {
        if values.len() > 32768 {
            return Err(RouteRefreshError::Unchanged(invalid()));
        }
        let reconciled = self.reconcile_missing_routes()?;
        let preflight_error = |error| {
            if reconciled {
                RouteRefreshError::Uncertain(error)
            } else {
                RouteRefreshError::Unchanged(error)
            }
        };
        let mut target = Vec::with_capacity(values.len());
        let mut keys = HashSet::new();
        let owned_by_key: HashMap<_, _> = self
            .journal
            .owned
            .iter()
            .map(|entry| (entry.current.key(), entry))
            .collect();
        for value in values {
            if !value.valid() || !keys.insert(value.key()) {
                return Err(preflight_error(invalid()));
            }
            let original = if let Some(entry) = owned_by_key.get(&value.key()) {
                entry.original.clone()
            } else if matches!(value, NetworkValue::Dns(_)) {
                let original = self.system.read(&value.key()).map_err(preflight_error)?;
                if original
                    .as_ref()
                    .is_some_and(|v| v.key() != value.key() || !v.valid())
                {
                    return Err(preflight_error(conflict()));
                }
                original
            } else {
                // New non-DNS resources require absence in the all-changes preflight.
                None
            };
            target.push(Entry {
                original,
                current: value,
            });
        }
        let mut changes = changes(&self.journal.owned, &target);
        let linux_target = main_route_values(&target);
        let linux_routes =
            !linux_target.is_empty() || !main_route_values(&self.journal.owned).is_empty();
        let journal_each_write = journal_each_write || linux_routes;
        let mut staged = 0;
        if !self.journal.stopping && (linux_routes || self.system.observe_routes_on_close()) {
            // Keep the old FIB coverage while staging new prefixes. This also
            // makes rollback restore removed prefixes before dropping their
            // replacements. Linux can stage the same prefix at a new priority.
            if linux_routes {
                self.system
                    .check_main_routes(&main_route_values(&self.journal.owned), &linux_target)?;
            }
            let stage_route = |change: &Change| {
                matches!(change.key, ResourceKey::Route(..)) && change.before.is_none()
            };
            changes.sort_by_key(|change| !stage_route(change));
            staged = changes.partition_point(stage_route);
        }
        // Detect foreign replacement before touching any other resource.
        if !changes.is_empty() {
            let keys: Vec<_> = changes.iter().map(|change| change.key.clone()).collect();
            let current = self.system.read_many(&keys).map_err(preflight_error)?;
            if current.len() != changes.len() {
                return Err(preflight_error(invalid()));
            }
            for (change, current) in changes.iter().zip(current) {
                if current != change.before {
                    if owned_by_key.contains_key(&change.key) {
                        return Err(conflict().into());
                    }
                    return Err(preflight_error(conflict()));
                }
            }
        }
        let mut pending = self.journal.clone();
        pending.pending = Some(Pending {
            target: if journal_each_write {
                Vec::new()
            } else {
                target.clone()
            },
            active,
        });
        self.store.save(&pending)?;
        self.journal = pending;
        let previous_active = self.journal.active;
        let mut attempted = 0;
        let result = (|| -> Result<(), RouteRefreshError> {
            loop {
                if linux_routes && staged != 0 && attempted == staged {
                    self.system.check_main_routes(
                        &main_route_values(&self.journal.owned),
                        &linux_target,
                    )?;
                }
                let Some(change) = changes.get(attempted) else {
                    break;
                };
                let route_count = if journal_each_write {
                    let end = if attempted < staged {
                        staged
                    } else {
                        changes.len()
                    };
                    changes[attempted..end]
                        .iter()
                        .take(ROUTE_BATCH_SIZE)
                        .take_while(|change| matches!(change.key, ResourceKey::Route(..)))
                        .count()
                } else {
                    0
                };
                if route_count >= MIN_ROUTE_BATCH_SIZE {
                    self.apply_route_batch(
                        &changes[attempted..attempted + route_count],
                        &mut attempted,
                    )?;
                    continue;
                }
                if journal_each_write && matches!(change.key, ResourceKey::Route(..)) {
                    self.apply_route_change(
                        &change.key,
                        change.before.as_ref(),
                        change.after.as_ref(),
                        false,
                    )?;
                    attempted += 1;
                } else if journal_each_write {
                    self.apply_journaled_resource(
                        change,
                        find(&target, &change.key),
                        &mut attempted,
                    )?;
                } else {
                    attempted += 1;
                    self.system.compare_exchange(
                        &change.key,
                        change.before.as_ref(),
                        change.after.as_ref(),
                    )?;
                    if self.system.read(&change.key)? != change.after {
                        return Err(io::Error::other("network_change_not_applied").into());
                    }
                }
            }
            if linux_routes && !self.journal.stopping && staged < changes.len() {
                self.system
                    .check_main_routes(&main_route_values(&self.journal.owned), &linux_target)?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            if journal_each_write
                && (self.journal.stopping
                    || (previous_active.is_none() && self.system.observe_routes_on_close()))
            {
                // Stop is one-way. A failed initial activation on a platform
                // with link-owned routes also ends by closing that link.
                self.store.save(&self.journal)?;
            } else if self
                .rollback(&changes, attempted, staged, journal_each_write)
                .is_ok()
                && matches!(error, RouteRefreshError::Unchanged(_))
                && !reconciled
                && self.journal.active == previous_active
                && self.committed_resources_match()
            {
                return Err(error);
            }
            return Err(io::Error::from(error).into());
        }

        let committed = NetworkJournal {
            owned: target,
            active,
            pending: None,
            stopping: self.journal.stopping,
            route_intents: self.journal.route_intents.clone(),
        };
        if let Err(error) = self.store.save(&committed) {
            if !journal_each_write {
                // The save may already have published the new record. Rollback
                // republishes pending before making any compensating changes.
                let _ = self.rollback(&changes, attempted, staged, false);
            }
            return Err(error.into());
        }
        self.journal = committed;
        Ok(())
    }

    fn committed_resources_match(&mut self) -> bool {
        let keys: Vec<_> = self
            .journal
            .owned
            .iter()
            .map(|entry| entry.current.key())
            .collect();
        self.system.read_many(&keys).is_ok_and(|current| {
            current.len() == keys.len()
                && current
                    .iter()
                    .zip(&self.journal.owned)
                    .all(|(value, entry)| value.as_ref() == Some(&entry.current))
        })
    }

    fn apply_route_batch(
        &mut self,
        batch: &[Change],
        attempted: &mut usize,
    ) -> Result<(), RouteRefreshError> {
        let uncertain: HashSet<_> = self
            .journal
            .route_intents
            .iter()
            .map(RouteIntent::key)
            .collect();
        if batch.iter().any(|change| uncertain.contains(&change.key)) {
            return Err(unconfirmed_route().into());
        }
        // Until the checkpoint, recovery must treat the whole batch as uncertain,
        // including keys we may never have reached. Owned rows outside it retain
        // their ordinary cleanup authority.
        let previous_intents = self.journal.route_intents.len();
        self.journal.route_intents.extend(
            batch
                .iter()
                .map(|change| RouteIntent::new(change.before.as_ref(), change.after.as_ref())),
        );
        if let Err(error) = self.store.save(&self.journal) {
            self.journal.route_intents.truncate(previous_intents);
            return Err(error.into());
        }
        // Remove just these old ownership rows in one pass. An interrupted
        // batch remains fenced by its durable intents. Definite no-writes and
        // untouched suffixes retain their original ownership below.
        let keys: HashSet<_> = batch.iter().map(|change| &change.key).collect();
        let mut originals = HashMap::new();
        self.journal.owned.retain(|entry| {
            let key = entry.current.key();
            if keys.contains(&key) {
                originals.insert(key, entry.clone());
                return false;
            }
            true
        });
        for (index, change) in batch.iter().enumerate() {
            if let Err(error) = self.apply_route_change(
                &change.key,
                change.before.as_ref(),
                change.after.as_ref(),
                true,
            ) {
                // Only the still-running owner knows which later CAS calls were
                // never dispatched. Persist this knowledge before compensation.
                if matches!(error, RouteRefreshError::Unchanged(_)) {
                    self.journal.owned.extend(originals.remove(&change.key));
                }
                for untouched in &batch[index + 1..] {
                    self.journal.clear_route_intent(&untouched.key);
                    self.journal.owned.extend(originals.remove(&untouched.key));
                }
                return Err(error);
            }
            *attempted += 1;
        }
        self.store.save(&self.journal)?;
        Ok(())
    }

    fn apply_route_change(
        &mut self,
        key: &ResourceKey,
        before: Option<&NetworkValue>,
        after: Option<&NetworkValue>,
        prejournaled: bool,
    ) -> Result<(), RouteRefreshError> {
        let intent = RouteIntent::new(before, after);
        debug_assert_eq!(&intent.key(), key);
        let journal = &mut self.journal;
        let store = &mut self.store;
        if !prejournaled
            && journal
                .route_intents
                .iter()
                .any(|intent| &intent.key() == key)
        {
            return Err(unconfirmed_route().into());
        }

        let mut prepare = || {
            journal.route_intents.push(intent.clone());
            store.save(journal)
        };
        let outcome = self.system.compare_exchange_prepared(
            key,
            before,
            after,
            (!prejournaled).then_some(&mut prepare as &mut dyn FnMut() -> io::Result<()>),
        );
        match outcome {
            Ok(()) => {
                // The ACK retires the old ownership before any readback.
                if !prejournaled {
                    journal.forget_route(key);
                }
                let current = self.system.read(key)?;
                if current.as_ref() != after {
                    // A contradictory readback is not a confirmed route. Keep
                    // uncertainty only while either exact row can still exist.
                    if !current.as_ref().is_some_and(|value| intent.matches(value)) {
                        journal.clear_route_intent(key);
                    }
                    return Err(io::Error::other("network_change_not_applied").into());
                }
                journal.clear_route_intent(key);
                if let Some(current) = current {
                    journal.owned.push(Entry {
                        original: None,
                        current,
                    });
                }
                if !prejournaled
                    && intent
                        .before
                        .iter()
                        .chain(&intent.after)
                        .any(|route| route.gateway.is_some())
                {
                    // A route through an uplink gateway can outlive all VPN
                    // interfaces. Record the verified outcome independently of
                    // the final transaction commit.
                    store.save(journal)?;
                }
                Ok(())
            }
            Err(RouteRefreshError::Unchanged(error)) => {
                journal.clear_route_intent(key);
                Err(RouteRefreshError::Unchanged(error))
            }
            Err(RouteRefreshError::RouteAddConflict(error)) => {
                if !prejournaled {
                    journal.forget_route(key);
                }
                journal.clear_route_intent(key);
                Err(RouteRefreshError::RouteAddConflict(error))
            }
            Err(error) => Err(error),
        }
    }

    fn apply_journaled_resource(
        &mut self,
        change: &Change,
        entry: Option<&Entry>,
        attempted: &mut usize,
    ) -> Result<(), RouteRefreshError> {
        let journal = &mut self.journal;
        let store = &mut self.store;
        let mut prepare = || {
            journal
                .pending
                .as_mut()
                .expect("transition pending")
                .target
                .extend(entry.cloned());
            store.save(journal)
        };
        let outcome = self.system.compare_exchange_prepared(
            &change.key,
            change.before.as_ref(),
            change.after.as_ref(),
            entry.map(|_| &mut prepare as &mut dyn FnMut() -> io::Result<()>),
        );
        if !matches!(outcome, Err(RouteRefreshError::Unchanged(_))) {
            *attempted += 1;
        }
        outcome?;
        if self.system.read(&change.key)? != change.after {
            return Err(io::Error::other("network_change_not_applied").into());
        }
        Ok(())
    }

    fn rollback(
        &mut self,
        changes: &[Change],
        attempted: usize,
        staged: usize,
        live: bool,
    ) -> io::Result<()> {
        let (started, unstarted) = changes.split_at(attempted);
        if !unstarted.is_empty() {
            let started_keys: HashSet<_> = started.iter().map(|change| &change.key).collect();
            let pending = self.journal.pending.as_mut().expect("transition pending");
            pending
                .target
                .retain(|entry| started_keys.contains(&entry.current.key()));
            pending.target.extend(
                self.journal
                    .owned
                    .iter()
                    .filter(|entry| !started_keys.contains(&entry.current.key()))
                    .filter(|entry| !live || !matches!(entry.current, NetworkValue::Route(_)))
                    .cloned(),
            );
        }
        // Retain the confirmed results and any outstanding intent before reversing writes.
        self.store.save(&self.journal)?;
        let mut error = None;
        let mut remaining = started;
        let staged = staged.min(attempted);
        while let Some((change, prior)) = remaining.split_last() {
            if staged != 0 && remaining.len() == staged {
                // A kernel write may have succeeded without an observable ACK.
                // Do not remove the staged coverage until the old rows are
                // verified, including the failing mutation outside `started`.
                if let Err(err) = self.verify_rollback_route_baseline(changes) {
                    error.get_or_insert(err);
                    break;
                }
            }
            if live {
                let boundary = if remaining.len() > staged { staged } else { 0 };
                let route_count = remaining[boundary..]
                    .iter()
                    .rev()
                    .take(ROUTE_BATCH_SIZE)
                    .take_while(|change| matches!(change.key, ResourceKey::Route(..)))
                    .count();
                if route_count >= MIN_ROUTE_BATCH_SIZE {
                    let (earlier, batch) = remaining.split_at(remaining.len() - route_count);
                    self.rollback_route_batch(batch, &mut error);
                    remaining = earlier;
                    continue;
                }
            }
            remaining = prior;
            let result = if live && matches!(change.key, ResourceKey::Route(..)) {
                self.rollback_route(change)
            } else {
                (|| {
                    let current = self.system.read(&change.key)?;
                    if current == change.before {
                        return Ok(());
                    }
                    if current != change.after && current.is_some() {
                        return Err(conflict());
                    }
                    self.system.compare_exchange(
                        &change.key,
                        current.as_ref(),
                        change.before.as_ref(),
                    )?;
                    if self.system.read(&change.key)? != change.before {
                        return Err(io::Error::other("network_rollback_not_applied"));
                    }
                    Ok(())
                })()
            };
            if let Err(e) = result {
                error.get_or_insert(e);
            }
        }
        if live {
            if let Err(err) = self.settle_route_intents() {
                error.get_or_insert(err);
            }
        }
        if let Some(error) = error {
            self.store.save(&self.journal)?;
            return Err(error);
        }
        let mut restored = self.journal.clone();
        restored.pending = None;
        if live
            && changes.iter().any(|change| {
                matches!(change.key, ResourceKey::Route(..))
                    && find(&restored.owned, &change.key).map(|entry| &entry.current)
                        != change.before.as_ref()
            })
        {
            restored.active = None;
        }
        self.store.save(&restored)?;
        self.journal = restored;
        Ok(())
    }

    fn verify_rollback_route_baseline(&mut self, changes: &[Change]) -> io::Result<()> {
        let old_routes: Vec<_> = changes
            .iter()
            .filter(|change| matches!(change.before, Some(NetworkValue::Route(_))))
            .collect();
        let owned: HashMap<_, _> = self
            .journal
            .owned
            .iter()
            .map(|entry| (entry.current.key(), &entry.current))
            .collect();
        if old_routes
            .iter()
            .any(|change| owned.get(&change.key).copied() != change.before.as_ref())
        {
            return Err(unconfirmed_route());
        }
        let keys: Vec<_> = old_routes.iter().map(|change| change.key.clone()).collect();
        let current = self.system.read_many(&keys)?;
        if current.len() != keys.len()
            || current
                .iter()
                .zip(old_routes)
                .any(|(value, change)| value != &change.before)
        {
            return Err(unconfirmed_route());
        }
        Ok(())
    }

    fn rollback_route_batch(&mut self, forward: &[Change], error: &mut Option<io::Error>) {
        let mut reverse = Vec::new();
        for change in forward.iter().rev() {
            match self.prepare_route_rollback(change) {
                Ok(Some(change)) => reverse.push(change),
                Ok(None) => (),
                Err(err) => {
                    error.get_or_insert(err);
                }
            }
        }
        if reverse.is_empty() {
            return;
        }
        let mut applied = 0;
        if let Err(err) = self.apply_route_batch(&reverse, &mut applied) {
            error.get_or_insert_with(|| err.into());
            // Continue compensating independent rows after a failed native CAS.
            // The failing key may be uncertain and must never be retried here.
            for change in reverse.iter().skip(applied + 1) {
                if let Err(err) = self.apply_route_change(
                    &change.key,
                    change.before.as_ref(),
                    change.after.as_ref(),
                    false,
                ) {
                    error.get_or_insert_with(|| err.into());
                }
            }
        }
    }

    fn rollback_route(&mut self, change: &Change) -> io::Result<()> {
        if let Some(reverse) = self.prepare_route_rollback(change)? {
            self.apply_route_change(
                &reverse.key,
                reverse.before.as_ref(),
                reverse.after.as_ref(),
                false,
            )?;
        }
        Ok(())
    }

    fn prepare_route_rollback(&mut self, change: &Change) -> io::Result<Option<Change>> {
        let current = self.system.read(&change.key)?;
        let owned = find(&self.journal.owned, &change.key);
        if current.is_some() && current.as_ref() != owned.map(|entry| &entry.current) {
            // An exact copy of the retired before-value is also a foreign row.
            self.journal.forget_route(&change.key);
            return Err(conflict());
        }
        if current == change.before {
            if current.is_none() {
                self.journal.forget_route(&change.key);
            }
            return Ok(None);
        }
        Ok(Some(Change {
            key: change.key.clone(),
            before: current,
            after: change.before.clone(),
        }))
    }

    fn reconcile_missing_routes(&mut self) -> Result<bool, RouteRefreshError> {
        if self.journal.owned.is_empty() {
            return Ok(false);
        }
        let keys: Vec<_> = self
            .journal
            .owned
            .iter()
            .map(|entry| entry.current.key())
            .collect();
        let current = self
            .system
            .read_many(&keys)
            .map_err(RouteRefreshError::Unchanged)?;
        if current.len() != self.journal.owned.len() {
            return Err(RouteRefreshError::Unchanged(invalid()));
        }
        let mut next = self.journal.clone();
        next.owned.clear();
        for (entry, current) in self.journal.owned.iter().zip(current) {
            match current {
                Some(value) if value == entry.current => next.owned.push(entry.clone()),
                None if !matches!(entry.current, NetworkValue::Dns(_)) => {
                    if matches!(&entry.current, NetworkValue::Route(r)
                        if matches!(r.scope, RouteScope::Global | RouteScope::LinuxMainPriority(_)))
                    {
                        next.active = None;
                    }
                }
                _ => return Err(conflict().into()),
            }
        }
        if next.owned != self.journal.owned {
            self.store.save(&next)?;
            self.journal = next;
            return Ok(true);
        }
        Ok(false)
    }

    fn prepare_pending_cleanup(&mut self) -> io::Result<()> {
        if self.journal.pending.is_none() && self.journal.route_intents.is_empty() {
            return Ok(());
        }
        let target = self
            .journal
            .pending
            .as_ref()
            .map_or(&[][..], |pending| pending.target.as_slice());
        let uncertain: HashSet<_> = self
            .journal
            .route_intents
            .iter()
            .map(RouteIntent::key)
            .collect();
        let mut seen = HashSet::new();
        let mut owned = Vec::new();
        for entry in self.journal.owned.iter().chain(target) {
            let key = entry.current.key();
            if uncertain.contains(&key) || !seen.insert(key.clone()) {
                continue;
            }
            let before = find(&self.journal.owned, &key);
            let after = find(target, &key);
            let original = before
                .map(|e| e.original.clone())
                .unwrap_or_else(|| entry.original.clone());
            let current = self.system.read(&key)?;
            if current == original {
                continue;
            }
            // Lost links remove their routes automatically. Never recreate them
            // just to roll back an interrupted transition before Stop.
            if current.is_none() && !matches!(key, ResourceKey::Dns(..)) {
                continue;
            }
            let known_before = before.map(|e| &e.current).or(original.as_ref());
            let known_after = after.map(|e| &e.current).or(original.as_ref());
            if current.as_ref() != known_before && current.as_ref() != known_after {
                return Err(conflict());
            }
            let current = current.ok_or_else(conflict)?;
            owned.push(Entry { original, current });
        }
        let stopped = NetworkJournal {
            owned,
            active: None,
            pending: None,
            stopping: true,
            route_intents: self.journal.route_intents.clone(),
        };
        self.store.save(&stopped)?;
        self.journal = stopped;
        Ok(())
    }
}

fn main_route_values(entries: &[Entry]) -> Vec<&RouteValue> {
    entries
        .iter()
        .filter_map(|entry| match &entry.current {
            NetworkValue::Route(route)
                if matches!(route.scope, RouteScope::LinuxMainPriority(_)) =>
            {
                Some(route)
            }
            _ => None,
        })
        .collect()
}

struct Change {
    key: ResourceKey,
    before: Option<NetworkValue>,
    after: Option<NetworkValue>,
}
fn find<'a>(entries: &'a [Entry], key: &ResourceKey) -> Option<&'a Entry> {
    entries.iter().find(|e| &e.current.key() == key)
}
fn changes(before: &[Entry], after: &[Entry]) -> Vec<Change> {
    let mut changes = Vec::new();
    let before_keys: HashSet<_> = before.iter().map(|entry| entry.current.key()).collect();
    let after_by_key: HashMap<_, _> = after
        .iter()
        .map(|entry| (entry.current.key(), entry))
        .collect();
    // Default ordering is replacements and removals before additions. The
    // Unix route owner may stage additions with distinct native keys first.
    for entry in before {
        let key = entry.current.key();
        let next = after_by_key
            .get(&key)
            .map(|e| e.current.clone())
            .or_else(|| entry.original.clone());
        if next.as_ref() != Some(&entry.current) {
            changes.push(Change {
                key,
                before: Some(entry.current.clone()),
                after: next,
            });
        }
    }
    for entry in after {
        let key = entry.current.key();
        if !before_keys.contains(&key) && entry.original.as_ref() != Some(&entry.current) {
            changes.push(Change {
                key,
                before: entry.original.clone(),
                after: Some(entry.current.clone()),
            });
        }
    }
    changes
}
fn validate_entries(entries: &[Entry]) -> io::Result<()> {
    let mut keys = HashSet::new();
    if entries.len() > 32768 {
        return Err(invalid());
    }
    for entry in entries {
        if !entry.current.valid()
            || !keys.insert(entry.current.key())
            || entry.original.as_ref().is_some_and(|v| {
                !v.valid() || v.key() != entry.current.key() || !matches!(v, NetworkValue::Dns(_))
            })
        {
            return Err(invalid());
        }
    }
    Ok(())
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid_network_state")
}
#[derive(Debug)]
pub struct RouteOwnershipUnconfirmed;

impl std::fmt::Display for RouteOwnershipUnconfirmed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("network_route_ownership_unconfirmed")
    }
}

impl std::error::Error for RouteOwnershipUnconfirmed {}

fn unconfirmed_route() -> io::Error {
    io::Error::other(RouteOwnershipUnconfirmed)
}
fn conflict() -> io::Error {
    io::Error::new(io::ErrorKind::AlreadyExists, "network_resource_changed")
}
