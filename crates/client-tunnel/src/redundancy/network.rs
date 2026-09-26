//! The session's single route/DNS owner. Platform adapters do exact native
//! compare-and-mutate under the existing privileged manager mutation lock.
//! Write-ahead state is required before side effects; unsuccessful rollback
//! cannot publish a usable active member or discard cleanup ownership.
use super::Slot;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, io, net::IpAddr};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum RouteScope {
    Global,
    Member(u32),
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
                        RouteScope::Member(i) => i == r.interface,
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
    /// Pure expansion of a route into the platform's separately journaled
    /// resources. Linux member routes need an oif rule as well as a private-table
    /// route; never create that rule as an invisible side effect of route CAS.
    fn route_resources(&self, route: RouteValue) -> io::Result<Vec<NetworkValue>> {
        Ok(vec![NetworkValue::Route(route)])
    }
    /// Must fail on ambiguous/multiple native matches, never select an arbitrary
    /// row. Missing resource is None, not a failed query disguised as absence.
    fn read(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>>;
    /// Recheck exact native identity, then mutate only that resource. A failure
    /// may have partially applied; the owner will inspect before compensating.
    fn compare_exchange(
        &mut self,
        key: &ResourceKey,
        before: Option<&NetworkValue>,
        after: Option<&NetworkValue>,
    ) -> io::Result<()>;
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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkJournal {
    owned: Vec<Entry>,
    active: Option<Slot>,
    pending: Option<Pending>,
    stopping: bool,
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
        validate_entries(&journal.owned)?;
        if let Some(p) = &journal.pending {
            validate_entries(&p.target)?;
        }
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
        self.journal.pending.is_some() || (self.journal.stopping && !self.journal.owned.is_empty())
    }
    pub fn has_resources(&self) -> bool {
        !self.journal.owned.is_empty() || self.journal.pending.is_some()
    }
    pub fn system_mut(&mut self) -> &mut B {
        &mut self.system
    }
    pub fn into_parts(self) -> (B, S) {
        (self.system, self.store)
    }

    pub fn select(&mut self, active: Slot, values: Vec<NetworkValue>) -> io::Result<()> {
        if self.journal.stopping || self.journal.pending.is_some() {
            return Err(io::Error::other("network_cleanup_pending"));
        }
        self.transition(Some(active), values)
    }

    pub fn prepare(&mut self, values: Vec<NetworkValue>) -> io::Result<()> {
        if self.journal.active.is_some() || self.journal.stopping || self.journal.pending.is_some()
        {
            return Err(io::Error::other("network_prepare_fenced"));
        }
        self.transition(None, values)
    }

    pub fn cleanup(&mut self) -> io::Result<()> {
        // Local Stop fences any promotion even if persistence or cleanup fails.
        self.journal.stopping = true;
        self.store.save(&self.journal)?;
        self.prepare_pending_cleanup()?;
        self.transition(None, Vec::new())
    }

    fn transition(&mut self, active: Option<Slot>, values: Vec<NetworkValue>) -> io::Result<()> {
        if values.len() > 32768 {
            return Err(invalid());
        }
        self.reconcile_missing_routes()?;
        let mut target = Vec::with_capacity(values.len());
        let mut keys = HashSet::new();
        for value in values {
            if !value.valid() || !keys.insert(value.key()) {
                return Err(invalid());
            }
            let original = if let Some(entry) = find(&self.journal.owned, &value.key()) {
                entry.original.clone()
            } else {
                let original = self.system.read(&value.key())?;
                // DNS has a baseline to restore; pre-existing routes aren't ours.
                if !matches!(value, NetworkValue::Dns(_)) && original.is_some() {
                    return Err(conflict());
                }
                if original
                    .as_ref()
                    .is_some_and(|v| v.key() != value.key() || !v.valid())
                {
                    return Err(conflict());
                }
                original
            };
            target.push(Entry {
                original,
                current: value,
            });
        }
        let changes = changes(&self.journal.owned, &target);
        // Detect foreign replacement before touching any other resource.
        for change in &changes {
            if self.system.read(&change.key)? != change.before {
                return Err(conflict());
            }
        }
        let mut pending = self.journal.clone();
        pending.pending = Some(Pending {
            target: target.clone(),
            active,
        });
        self.store.save(&pending)?;
        self.journal = pending;
        let result = (|| {
            for change in &changes {
                self.system.compare_exchange(
                    &change.key,
                    change.before.as_ref(),
                    change.after.as_ref(),
                )?;
                if self.system.read(&change.key)? != change.after {
                    return Err(io::Error::other("network_change_not_applied"));
                }
            }
            let committed = NetworkJournal {
                owned: target,
                active,
                pending: None,
                stopping: self.journal.stopping,
            };
            self.store.save(&committed)?;
            self.journal = committed;
            Ok(())
        })();
        if result.is_err() {
            let _ = self.rollback();
        }
        result
    }

    fn rollback(&mut self) -> io::Result<()> {
        let Some(pending) = self.journal.pending.clone() else {
            return Ok(());
        };
        let changes = changes(&self.journal.owned, &pending.target);
        let mut error = None;
        for change in changes.iter().rev() {
            let result = (|| {
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
            })();
            if let Err(e) = result {
                error.get_or_insert(e);
            }
        }
        if let Some(error) = error {
            return Err(error);
        }
        let mut restored = self.journal.clone();
        restored.pending = None;
        self.store.save(&restored)?;
        self.journal = restored;
        Ok(())
    }

    fn reconcile_missing_routes(&mut self) -> io::Result<()> {
        let mut next = self.journal.clone();
        next.owned.clear();
        for entry in &self.journal.owned {
            match self.system.read(&entry.current.key())? {
                Some(value) if value == entry.current => next.owned.push(entry.clone()),
                None if !matches!(entry.current, NetworkValue::Dns(_)) => {
                    if matches!(&entry.current, NetworkValue::Route(r) if r.scope == RouteScope::Global)
                    {
                        next.active = None;
                    }
                }
                _ => return Err(conflict()),
            }
        }
        if next.owned != self.journal.owned {
            self.store.save(&next)?;
            self.journal = next;
        }
        Ok(())
    }

    fn prepare_pending_cleanup(&mut self) -> io::Result<()> {
        let Some(pending) = &self.journal.pending else {
            return Ok(());
        };
        let mut seen = HashSet::new();
        let mut owned = Vec::new();
        for entry in self.journal.owned.iter().chain(&pending.target) {
            let key = entry.current.key();
            if !seen.insert(key.clone()) {
                continue;
            }
            let before = find(&self.journal.owned, &key);
            let after = find(&pending.target, &key);
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
        };
        self.store.save(&stopped)?;
        self.journal = stopped;
        Ok(())
    }
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
    // Removed resources are processed before additions: no duplicate active
    // routes. Platform compare_exchange must recover its own partial operation.
    for entry in before {
        let key = entry.current.key();
        let next = find(after, &key)
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
        if find(before, &key).is_none() && entry.original.as_ref() != Some(&entry.current) {
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
fn conflict() -> io::Error {
    io::Error::new(io::ErrorKind::AlreadyExists, "network_resource_changed")
}
