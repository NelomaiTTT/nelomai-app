//! Private standby WFP policy and journal/transaction seam.
//!
//! The owner must journal the complete ExchangePlan before compare_exchange.
//! A lost acknowledgement is resolved by snapshot, never blind deletion/retry.
//! Native transport errors may invalidate the handle; reopen the same scope and
//! compare its snapshot to the journaled models before deciding what happened.
//! Probe tuples are usable only while the helper holds an exclusively bound UDP
//! socket (SO_EXCLUSIVEADDRUSE, no reuse); withdraw the permit BEFORE releasing
//! that socket. Tuple filtering cannot establish socket ownership itself.
//! Only base blocks/sublayer are static. Probe exceptions are owned by a separate
//! dynamic BFE session and are removed on helper exit/session rundown. There is
//! NO cross-engine atomicity: withdraw -> static CAS -> install, with readbacks.
//! Static, nonpersistent BFE objects survive helper exit/handle close, but NOT
//! BFE/OS restart. Lifecycle/interface revalidation and fail-closed route ordering
//! are required before enablement. This module does not implement that lifecycle.

#![cfg_attr(not(windows), allow(dead_code))] // Portable fake tests have no native caller.

use nelomai_client_tunnel::redundancy::{SessionScope, Slot};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub(crate) struct Key(pub [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct Interface {
    pub index: u32,
    pub luid: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProbeTuple {
    pub source: IpAddr,
    pub source_port: u16,
    pub target: IpAddr,
    pub target_port: u16,
    pub protocol: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Member {
    pub interface: Interface,
    /// At most one exact, exclusively held socket tuple per address family.
    pub probes: Vec<ProbeTuple>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum Layer {
    TransportV4,
    TransportV6,
    ForwardV4,
    ForwardV6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum Action {
    Block,
    Permit,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub(crate) enum Condition {
    InterfaceIndex(u32),
    LocalInterface(u64),
    DestinationInterfaceIndex(u32),
    LocalAddress(IpAddr),
    RemoteAddress(IpAddr),
    LocalPort(u16),
    RemotePort(u16),
    Protocol(u8),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Filter {
    pub key: Key,
    pub sublayer: Key,
    pub layer: Layer,
    pub weight: u64,
    pub flags: u32,
    pub action: Action,
    pub conditions: Vec<Condition>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Sublayer {
    pub key: Key,
    pub weight: u16,
    pub flags: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    pub scope: SessionScope,
    pub sublayer: Option<Sublayer>,
    pub filters: Vec<Filter>,
}

/// Persistable intent AND exact expected objects/GUIDs; never credentials.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Model {
    pub scope: SessionScope,
    pub members: [Option<Member>; 2],
    pub active: Option<Slot>,
    pub installed: bool,
    /// BFE chooses the closest available sublayer weight on creation. Once
    /// observed, persist it and require exact equality for this object's life.
    /// Absent in legacy journals (which requested 0x8000).
    /// https://learn.microsoft.com/en-us/windows/win32/fwp/installing-a-provider
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_sublayer_weight: Option<u16>,
    pub expected: Snapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum GuardError {
    #[error("member_guard_invalid")]
    Invalid,
    #[error("member_guard_ownership_conflict")]
    Conflict,
    #[error("member_guard_epoch_lost")]
    EpochLost,
    #[error("member_guard_permit_removal_unconfirmed")]
    RemovalUnconfirmed,
    #[error("member_guard_native_status_{0}")]
    Native(u32),
}
pub(crate) type Result<T> = std::result::Result<T, GuardError>;

/// Native exchange has THREE separate transaction boundaries; journal its full
/// ExchangePlan first. Failure withdraws own permits, not a rollback of base.
/// A coherent snapshot resolves which base committed after a lost acknowledgement.
pub(crate) trait GuardStore {
    fn snapshot(&mut self, scope: &SessionScope) -> Result<Snapshot>;
    fn compare_exchange(&mut self, expected: &Model, desired: &Model) -> Result<Model>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionKind {
    StaticBase,
    DynamicPermits,
}

/// All four states must be journaled before apply; they are separate BFE commits.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExchangePlan {
    pub expected: Model,
    pub withdrawn: Model,
    pub base: Model,
    pub desired: Model,
}
impl ExchangePlan {
    pub(crate) fn new(expected: &Model, desired: &Model) -> Result<Self> {
        validate_exchange(&expected.scope, expected, desired)?;
        Ok(Self {
            expected: expected.clone(),
            withdrawn: expected.without_probes()?,
            base: desired.without_probes()?,
            desired: desired.clone(),
        })
    }

    /// Only a journaled creation from an empty key universe can learn a weight.
    /// All candidate filter sets and the remaining sublayer fields stay exact.
    pub(crate) fn resolve(&self, actual: &Snapshot) -> Result<Model> {
        if *self != Self::new(&self.expected, &self.desired)? {
            return Err(GuardError::Invalid);
        }
        for candidate in [&self.expected, &self.withdrawn, &self.base, &self.desired] {
            if !self.expected.installed && candidate.installed {
                if let Ok(model) = candidate.created_readback(actual) {
                    return Ok(model);
                }
            } else if candidate.expected == *actual {
                return Ok(candidate.clone());
            }
        }
        Err(GuardError::Conflict)
    }
}

pub(crate) trait SplitEngines {
    fn scope(&self) -> &SessionScope;
    fn snapshot(&mut self) -> Result<Snapshot>;
    fn exchange(&mut self, kind: SessionKind, expected: &Model, desired: &Model) -> Result<Model>;
    /// Close THIS dynamic session, never enumerate/delete foreign objects. No
    /// further writes after failure; socket release requires confirmed removal.
    fn close_permits(&mut self) -> Result<()>;
}

pub(crate) fn apply_split(engines: &mut impl SplitEngines, plan: &ExchangePlan) -> Result<Model> {
    validate_exchange(engines.scope(), &plan.expected, &plan.desired)?;
    if *plan != ExchangePlan::new(&plan.expected, &plan.desired)? {
        return Err(GuardError::Invalid);
    }
    let apply = |engines: &mut dyn SplitEngines| -> Result<Model> {
        let mut before = plan.expected.clone();
        for (kind, after) in [
            (SessionKind::DynamicPermits, &plan.withdrawn),
            (SessionKind::StaticBase, &plan.base),
            (SessionKind::DynamicPermits, &plan.desired),
        ] {
            let after = after.inherit_sublayer_weight(&before)?;
            let committed = engines.exchange(kind, &before, &after)?;
            require_snapshot(&engines.snapshot()?, &committed.expected)?;
            before = committed;
        }
        Ok(before)
    };
    let result = apply(engines);
    if let Err(error) = result {
        // Also covers lost install ACK: closing the owning dynamic session drops
        // any committed permits without guessing which transaction succeeded.
        // No base rollback. Initial installation failure may still mean no base;
        // cleanup may already have removed it. Neither state authorizes routing.
        engines
            .close_permits()
            .map_err(|_| GuardError::RemovalUnconfirmed)?;
        let actual = engines
            .snapshot()
            .map_err(|_| GuardError::RemovalUnconfirmed)?;
        let keys = resource_keys(&plan.expected.scope)?;
        if actual.filters.iter().any(|f| {
            f.action == Action::Permit
                || keys
                    .filters
                    .iter()
                    .enumerate()
                    .any(|(i, k)| i % 6 >= 4 && *k == f.key)
        }) {
            // A foreign/static legacy permit is not ours to delete. Never claim
            // safe socket release merely because our own session was closed.
            return Err(GuardError::RemovalUnconfirmed);
        }
        return Err(error);
    }
    result
}

fn require_snapshot(actual: &Snapshot, expected: &Snapshot) -> Result<()> {
    if expected.sublayer.is_some() && actual.sublayer.is_none() {
        return Err(GuardError::EpochLost);
    }
    if actual != expected {
        return Err(GuardError::Conflict);
    }
    Ok(())
}

pub(crate) fn stage_session_exchange(
    scope: &SessionScope,
    transaction: &mut impl GuardTransaction,
    expected: &Model,
    desired: &Model,
    kind: SessionKind,
) -> Result<Model> {
    validate_exchange(scope, expected, desired)?;
    match kind {
        SessionKind::StaticBase
            if expected
                .expected
                .filters
                .iter()
                .chain(&desired.expected.filters)
                .any(|f| f.action != Action::Block) =>
        {
            return Err(GuardError::Invalid)
        }
        SessionKind::DynamicPermits
            if expected.without_probes()?.expected != desired.without_probes()?.expected =>
        {
            return Err(GuardError::Invalid)
        }
        _ => {}
    }
    stage_exchange(scope, transaction, expected, desired)?;
    // Capture BFE's assignment while the creating transaction still holds the
    // lock. Post-commit readback must match this value, not learn another one.
    let actual = transaction.read()?;
    desired.readback_after(expected, &actual)
}

/// Operations inside an already-open transaction. The owner MUST abort on any
/// error and commit only after stage_session_exchange succeeds. The fake and WFP share
/// readback, ordering, and exact-key cleanup through this seam.
pub(crate) trait GuardTransaction {
    fn read(&mut self) -> Result<Snapshot>;
    fn add_sublayer(&mut self, sublayer: &Sublayer) -> Result<()>;
    fn add_filter(&mut self, filter: &Filter) -> Result<()>;
    fn delete_filter(&mut self, key: Key) -> Result<()>;
    fn delete_sublayer(&mut self, key: Key) -> Result<()>;
}

fn stage_exchange(
    scope: &SessionScope,
    transaction: &mut impl GuardTransaction,
    expected: &Model,
    desired: &Model,
) -> Result<()> {
    validate_exchange(scope, expected, desired)?;
    require_snapshot(&transaction.read()?, &expected.expected)?;
    match (&expected.expected.sublayer, &desired.expected.sublayer) {
        (None, Some(sublayer)) => transaction.add_sublayer(sublayer)?,
        (Some(old), Some(new)) if old != new => return Err(GuardError::Conflict),
        _ => {}
    }
    // Guard the previous active before removing the new active's guard.
    // Single-session diff only. Session allowlisting is enforced by the public
    // staging entry point; this helper is NOT a cross-session transaction.
    for new in &desired.expected.filters {
        if let Some(old) = expected.expected.filters.iter().find(|f| f.key == new.key) {
            if old == new {
                continue;
            }
            transaction.delete_filter(old.key)?;
        }
        transaction.add_filter(new)?;
    }
    for old in &expected.expected.filters {
        if !desired.expected.filters.iter().any(|f| f.key == old.key) {
            transaction.delete_filter(old.key)?;
        }
    }
    if let (Some(old), None) = (&expected.expected.sublayer, &desired.expected.sublayer) {
        // Foreign references cause failure/abort, never a foreign deletion.
        transaction.delete_sublayer(old.key)?;
    }
    Ok(())
}

impl Model {
    pub(crate) fn readback_after(&self, previous: &Self, actual: &Snapshot) -> Result<Self> {
        validate_exchange(&self.scope, previous, self)?;
        if !previous.installed && self.installed {
            self.created_readback(actual)
        } else {
            require_snapshot(actual, &self.expected)?;
            Ok(self.clone())
        }
    }

    pub(crate) fn inherit_sublayer_weight(&self, previous: &Self) -> Result<Self> {
        self.validate()?;
        previous.validate()?;
        if self.scope != previous.scope {
            return Err(GuardError::Conflict);
        }
        let mut model = self.clone();
        if model.installed && previous.installed {
            if model.assigned_sublayer_weight.is_some()
                && model.assigned_sublayer_weight != previous.assigned_sublayer_weight
            {
                return Err(GuardError::Conflict);
            }
            model.assigned_sublayer_weight = previous.assigned_sublayer_weight;
            model.expected.sublayer.as_mut().unwrap().weight =
                previous.expected.sublayer.as_ref().unwrap().weight;
        }
        Ok(model)
    }

    fn created_readback(&self, actual: &Snapshot) -> Result<Self> {
        self.validate()?;
        if !self.installed || self.assigned_sublayer_weight.is_some() {
            return Err(GuardError::Invalid);
        }
        let weight = actual
            .sublayer
            .as_ref()
            .ok_or(GuardError::EpochLost)?
            .weight;
        let mut model = self.clone();
        model.assigned_sublayer_weight = Some(weight);
        model.expected.sublayer.as_mut().unwrap().weight = weight;
        require_snapshot(actual, &model.expected)?;
        Ok(model)
    }

    pub(crate) fn without_probes(&self) -> Result<Self> {
        self.validate()?;
        let mut members = self.members.clone();
        for member in members.iter_mut().flatten() {
            member.probes.clear();
        }
        if self.installed {
            Self::new(self.scope.clone(), members, self.active)?.inherit_sublayer_weight(self)
        } else {
            Self::empty(self.scope.clone())
        }
    }
    pub(crate) fn new(
        scope: SessionScope,
        members: [Option<Member>; 2],
        active: Option<Slot>,
    ) -> Result<Self> {
        let expected = build(&scope, &members, active, true)?;
        Ok(Self {
            scope,
            members,
            active,
            installed: true,
            assigned_sublayer_weight: None,
            expected,
        })
    }
    pub(crate) fn empty(scope: SessionScope) -> Result<Self> {
        let expected = build(&scope, &[None, None], None, false)?;
        Ok(Self {
            scope,
            members: [None, None],
            active: None,
            installed: false,
            assigned_sublayer_weight: None,
            expected,
        })
    }
    pub(crate) fn validate(&self) -> Result<()> {
        let mut expected = build(&self.scope, &self.members, self.active, self.installed)?;
        if let Some(weight) = self.assigned_sublayer_weight {
            expected
                .sublayer
                .as_mut()
                .ok_or(GuardError::Invalid)?
                .weight = weight;
        }
        if self.expected != expected {
            return Err(GuardError::Invalid);
        }
        Ok(())
    }
}

/// Fixed key universe, including ABSENT resources, checked before every write.
/// Changing this version requires retaining recovery support for old journals.
pub(crate) struct ResourceKeys {
    pub sublayer: Key,
    pub filters: [Key; 12],
}
pub(crate) fn resource_keys(scope: &SessionScope) -> Result<ResourceKeys> {
    if !scope.validate() {
        return Err(GuardError::Invalid);
    }
    let key = |purpose: &[u8]| {
        let mut hash = Sha256::new();
        hash.update(b"nelomai-member-guard/v1\0");
        hash.update([match scope.runtime {
            nelomai_contracts::RuntimeSlot::Stable => 0,
            nelomai_contracts::RuntimeSlot::Latest => 1,
        }]);
        hash.update(scope.runtime_generation.to_be_bytes());
        hash.update(scope.session_id.as_bytes()); // validated fixed-width UUID
        hash.update(scope.connection_generation.to_be_bytes());
        hash.update(purpose);
        let digest = hash.finalize();
        let mut bytes: [u8; 16] = digest[..16].try_into().expect("SHA256 prefix");
        bytes[6] = (bytes[6] & 0x0f) | 0x80; // UUIDv8, SHA256-derived
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Key(bytes)
    };
    Ok(ResourceKeys {
        sublayer: key(b"sublayer"),
        filters: std::array::from_fn(|i| key(&[b'f', (i / 6) as u8, (i % 6) as u8])),
    })
}

fn unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_loopback()
                && ip.octets()[0] != 0
                && ip.octets()[0] < 224
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_loopback()
                && ip.to_ipv4_mapped().is_none()
        }
    }
}

fn build(
    scope: &SessionScope,
    members: &[Option<Member>; 2],
    active: Option<Slot>,
    installed: bool,
) -> Result<Snapshot> {
    let keys = resource_keys(scope)?;
    let active_index = active.map(|s| match s {
        Slot::A => 0,
        Slot::B => 1,
    });
    if !installed && (members.iter().any(Option::is_some) || active.is_some())
        || active_index.is_some_and(|i| members[i].is_none())
    {
        return Err(GuardError::Invalid);
    }
    if let [Some(a), Some(b)] = members {
        if a.interface.index == b.interface.index || a.interface.luid == b.interface.luid {
            return Err(GuardError::Invalid);
        }
    }
    let mut filters = Vec::new();
    for (slot, member) in members.iter().enumerate() {
        let Some(member) = member else { continue };
        if member.interface.index == 0 || member.interface.luid == 0 || member.probes.len() > 2 {
            return Err(GuardError::Invalid);
        }
        let mut families = [false; 2];
        for probe in &member.probes {
            let family = usize::from(probe.source.is_ipv6());
            if families[family]
                || !unicast(probe.source)
                || !unicast(probe.target)
                || probe.source.is_ipv4() != probe.target.is_ipv4()
                || probe.source_port == 0
                || probe.target_port != 53
                || probe.protocol != 17
            {
                return Err(GuardError::Invalid);
            }
            families[family] = true;
        }
        if active_index == Some(slot) {
            continue;
        }
        use Condition::*;
        let transport = vec![
            InterfaceIndex(member.interface.index),
            LocalInterface(member.interface.luid),
        ];
        let mut add = |purpose: usize, layer, action, weight, mut conditions: Vec<Condition>| {
            conditions.sort();
            filters.push(Filter {
                key: keys.filters[slot * 6 + purpose],
                sublayer: keys.sublayer,
                layer,
                action,
                weight,
                flags: 0,
                conditions,
            });
        };
        add(0, Layer::TransportV4, Action::Block, 1, transport.clone());
        add(1, Layer::TransportV6, Action::Block, 1, transport.clone());
        add(
            2,
            Layer::ForwardV4,
            Action::Block,
            1,
            vec![DestinationInterfaceIndex(member.interface.index)],
        );
        add(
            3,
            Layer::ForwardV6,
            Action::Block,
            1,
            vec![DestinationInterfaceIndex(member.interface.index)],
        );
        for probe in &member.probes {
            let mut conditions = transport.clone();
            conditions.extend([
                LocalAddress(probe.source),
                RemoteAddress(probe.target),
                LocalPort(probe.source_port),
                RemotePort(probe.target_port),
                Protocol(probe.protocol),
            ]);
            let v6 = probe.source.is_ipv6();
            add(
                if v6 { 5 } else { 4 },
                if v6 {
                    Layer::TransportV6
                } else {
                    Layer::TransportV4
                },
                Action::Permit,
                2,
                conditions,
            );
        }
    }
    filters.sort_by_key(|f| f.key);
    Ok(Snapshot {
        scope: scope.clone(),
        sublayer: installed.then_some(Sublayer {
            key: keys.sublayer,
            weight: 0x8000,
            flags: 0,
        }),
        filters,
    })
}

pub(crate) fn validate_exchange(
    scope: &SessionScope,
    expected: &Model,
    desired: &Model,
) -> Result<()> {
    if scope != &expected.scope || scope != &desired.scope {
        return Err(GuardError::Conflict);
    }
    expected.validate()?;
    desired.validate()?;
    if desired.installed
        && ((!expected.installed && desired.assigned_sublayer_weight.is_some())
            || (expected.installed
                && expected.assigned_sublayer_weight != desired.assigned_sublayer_weight))
    {
        return Err(GuardError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nelomai_contracts::RuntimeSlot;

    fn scope() -> SessionScope {
        SessionScope {
            runtime: RuntimeSlot::Stable,
            runtime_generation: 1,
            session_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
            connection_generation: 2,
        }
    }
    fn member(index: u32) -> Member {
        Member {
            interface: Interface {
                index,
                luid: u64::from(index) * 100,
            },
            probes: vec![
                ProbeTuple {
                    source: "10.8.0.2".parse().unwrap(),
                    source_port: 40123,
                    target: "1.1.1.1".parse().unwrap(),
                    target_port: 53,
                    protocol: 17,
                },
                ProbeTuple {
                    source: "fd00::2".parse().unwrap(),
                    source_port: 40124,
                    target: "2606:4700:4700::1111".parse().unwrap(),
                    target_port: 53,
                    protocol: 17,
                },
            ],
        }
    }
    fn pair(active: Option<Slot>) -> Model {
        Model::new(scope(), [Some(member(11)), Some(member(22))], active).unwrap()
    }

    // Only the OS transaction boundary is faked. Tests exercise real policy and
    // validation, with raw altered objects representing independent BFE writers.
    struct Fake {
        scope: SessionScope,
        state: Snapshot,
        fail_before_commit: bool,
        fail_at: Option<usize>,
        foreign: Vec<Filter>,
        lose_ack: bool,
        published: Vec<Snapshot>,
        last_writes: Vec<(bool, Key)>,
    }
    impl Fake {
        fn new() -> Self {
            Self {
                scope: scope(),
                state: Model::empty(scope()).unwrap().expected,
                fail_before_commit: false,
                fail_at: None,
                foreign: vec![],
                lose_ack: false,
                published: vec![],
                last_writes: vec![],
            }
        }
    }
    impl GuardStore for Fake {
        fn snapshot(&mut self, scope: &SessionScope) -> Result<Snapshot> {
            if scope != &self.scope {
                return Err(GuardError::Conflict);
            }
            Ok(self.state.clone())
        }
        fn compare_exchange(&mut self, expected: &Model, desired: &Model) -> Result<Model> {
            validate_exchange(&self.scope, expected, desired)?;
            let mut pending = Pending {
                state: self.state.clone(),
                assigned_weight: None,
                foreign: &self.foreign,
                fail_at: self.fail_at,
                writes: 0,
                filter_writes: vec![],
            };
            stage_exchange(&self.scope, &mut pending, expected, desired)?;
            if self.fail_before_commit {
                return Err(GuardError::Native(1));
            }
            pending.state.filters.sort_by_key(|f| f.key);
            self.state = pending.state;
            self.last_writes = pending.filter_writes;
            self.published.push(self.state.clone());
            if self.lose_ack {
                Err(GuardError::Native(2))
            } else {
                Ok(desired.clone())
            }
        }
    }

    struct Pending<'a> {
        state: Snapshot,
        assigned_weight: Option<u16>,
        foreign: &'a [Filter],
        fail_at: Option<usize>,
        writes: usize,
        filter_writes: Vec<(bool, Key)>,
    }
    impl Pending<'_> {
        fn writing(&mut self) -> Result<()> {
            if self.fail_at == Some(self.writes) {
                return Err(GuardError::Native(3));
            }
            self.writes += 1;
            Ok(())
        }
    }
    impl GuardTransaction for Pending<'_> {
        fn read(&mut self) -> Result<Snapshot> {
            self.state.filters.sort_by_key(|f| f.key);
            Ok(self.state.clone())
        }
        fn add_sublayer(&mut self, layer: &Sublayer) -> Result<()> {
            self.writing()?;
            if self.state.sublayer.is_some() {
                return Err(GuardError::Conflict);
            }
            self.state.sublayer = Some(layer.clone());
            if let Some(weight) = self.assigned_weight {
                self.state.sublayer.as_mut().unwrap().weight = weight;
            }
            Ok(())
        }
        fn add_filter(&mut self, filter: &Filter) -> Result<()> {
            self.writing()?;
            if self
                .state
                .filters
                .iter()
                .chain(self.foreign)
                .any(|f| f.key == filter.key)
                || self.state.sublayer.as_ref().map(|l| l.key) != Some(filter.sublayer)
            {
                return Err(GuardError::Conflict);
            }
            self.state.filters.push(filter.clone());
            self.filter_writes.push((true, filter.key));
            Ok(())
        }
        fn delete_filter(&mut self, key: Key) -> Result<()> {
            self.writing()?;
            let index = self
                .state
                .filters
                .iter()
                .position(|f| f.key == key)
                .ok_or(GuardError::Conflict)?;
            self.state.filters.remove(index);
            self.filter_writes.push((false, key));
            Ok(())
        }
        fn delete_sublayer(&mut self, key: Key) -> Result<()> {
            self.writing()?;
            if self.state.sublayer.as_ref().map(|l| l.key) != Some(key)
                || self
                    .state
                    .filters
                    .iter()
                    .chain(self.foreign)
                    .any(|f| f.sublayer == key)
            {
                return Err(GuardError::Conflict);
            }
            self.state.sublayer = None;
            Ok(())
        }
    }

    fn decision(
        model: &Model,
        layer: Layer,
        interface: Interface,
        packet: &ProbeTuple,
    ) -> Option<Action> {
        use Condition::*;
        model
            .expected
            .filters
            .iter()
            .filter(|f| {
                f.layer == layer
                    && f.conditions.iter().all(|c| match c {
                        InterfaceIndex(n) | DestinationInterfaceIndex(n) => *n == interface.index,
                        LocalInterface(n) => *n == interface.luid,
                        LocalAddress(ip) => *ip == packet.source,
                        RemoteAddress(ip) => *ip == packet.target,
                        LocalPort(p) => *p == packet.source_port,
                        RemotePort(p) => *p == packet.target_port,
                        Protocol(p) => *p == packet.protocol,
                    })
            })
            .max_by_key(|f| f.weight)
            .map(|f| f.action)
    }

    #[test]
    fn standby_start_blocks_both_families_without_touching_active_or_physical() {
        let model = pair(Some(Slot::A));
        assert_eq!(model.expected.filters.len(), 6);
        for (i, layer) in [Layer::TransportV4, Layer::TransportV6]
            .into_iter()
            .enumerate()
        {
            let mut ordinary = member(22).probes[i].clone();
            ordinary.source_port += 1;
            assert_eq!(
                decision(&model, layer, member(22).interface, &ordinary),
                Some(Action::Block)
            );
            assert_eq!(
                decision(&model, layer, member(11).interface, &ordinary),
                None
            );
            assert_eq!(
                decision(&model, layer, member(99).interface, &ordinary),
                None
            );
        }
        let no_active = pair(None);
        assert_eq!(no_active.expected.filters.len(), 12);
        let only_standby = Model::new(scope(), [None, Some(member(22))], None).unwrap();
        assert_eq!(only_standby.expected.filters.len(), 6);
    }

    #[test]
    fn permit_requires_exact_tuple_and_interface_forwarding_never_exempted() {
        let model = pair(Some(Slot::A));
        for (i, layer, forward) in [
            (0, Layer::TransportV4, Layer::ForwardV4),
            (1, Layer::TransportV6, Layer::ForwardV6),
        ] {
            let probe = member(22).probes[i].clone();
            assert_eq!(
                decision(&model, layer, member(22).interface, &probe),
                Some(Action::Permit)
            );
            assert_eq!(
                decision(&model, forward, member(22).interface, &probe),
                Some(Action::Block)
            );
            for field in 0..5 {
                let mut packet = probe.clone();
                match field {
                    0 => {
                        packet.source = if i == 0 { "10.8.0.3" } else { "fd00::3" }.parse().unwrap()
                    }
                    1 => {
                        packet.target = if i == 0 { "9.9.9.9" } else { "2620:fe::fe" }
                            .parse()
                            .unwrap()
                    }
                    2 => packet.source_port += 1,
                    3 => packet.target_port += 1,
                    _ => packet.protocol = 6,
                }
                assert_eq!(
                    decision(&model, layer, member(22).interface, &packet),
                    Some(Action::Block)
                );
            }
            assert_eq!(
                decision(
                    &model,
                    layer,
                    Interface {
                        index: 22,
                        luid: 999
                    },
                    &probe
                ),
                None
            );
        }
        assert!(model.expected.filters.iter().all(|f| f.flags == 0));
    }

    #[test]
    fn single_session_diff_adds_old_active_guards_before_removing_new_active_guards() {
        let mut store = Fake::new();
        let empty = Model::empty(scope()).unwrap();
        let old = pair(Some(Slot::A));
        let new = pair(Some(Slot::B));
        store.compare_exchange(&empty, &old).unwrap();
        store.fail_before_commit = true;
        assert!(store.compare_exchange(&old, &new).is_err());
        assert_eq!(store.snapshot(&scope()).unwrap(), old.expected);
        store.fail_before_commit = false;
        store.compare_exchange(&old, &new).unwrap();
        assert_eq!(store.published.len(), 2);
        let first_removal = store.last_writes.iter().position(|(add, _)| !add).unwrap();
        for filter in &new.expected.filters {
            assert!(
                store.last_writes[..first_removal].contains(&(true, filter.key)),
                "old active must be guarded before the new active is released"
            );
        }
        let mut packet = member(11).probes[0].clone();
        packet.protocol = 6;
        assert_eq!(
            decision(&new, Layer::TransportV4, member(11).interface, &packet),
            Some(Action::Block)
        );
        assert_eq!(
            decision(&new, Layer::TransportV4, member(22).interface, &packet),
            None
        );
        assert_eq!(new.expected.filters.len(), 6);
    }

    #[test]
    fn lost_ack_is_reconciled_by_snapshot_and_stale_retry_does_not_mutate() {
        let mut store = Fake::new();
        let empty = Model::empty(scope()).unwrap();
        let desired = pair(None);
        store.lose_ack = true;
        assert!(store.compare_exchange(&empty, &desired).is_err());
        assert_eq!(store.snapshot(&scope()).unwrap(), desired.expected);
        assert_eq!(
            store.compare_exchange(&empty, &desired),
            Err(GuardError::Conflict)
        );
        assert_eq!(store.published.len(), 1);
    }

    #[test]
    fn wrong_scope_and_malformed_journal_or_tuple_never_mutate() {
        let empty = Model::empty(scope()).unwrap();
        let desired = pair(None);
        let mut store = Fake::new();
        let mut wrong = desired.clone();
        wrong.scope.connection_generation += 1;
        assert!(store.compare_exchange(&empty, &wrong).is_err());
        let mut bad = desired.clone();
        bad.members[0].as_mut().unwrap().probes[0].source_port = 0;
        assert!(store.compare_exchange(&empty, &bad).is_err());
        let mut altered = desired.clone();
        altered.expected.filters.clear();
        assert!(store.compare_exchange(&empty, &altered).is_err());
        assert_eq!(store.state, empty.expected);
        assert!(store.published.is_empty());
    }

    #[test]
    fn invalid_interfaces_and_probe_tuples_are_rejected_before_apply() {
        for case in 0..14 {
            let mut a = member(11);
            let mut b = member(22);
            match case {
                0 => a.interface.index = 0,
                1 => a.interface.luid = 0,
                2 => b.interface.index = a.interface.index,
                3 => b.interface.luid = a.interface.luid,
                4 => a.probes[0].source_port = 0,
                5 => a.probes[0].target_port = 0,
                6 => a.probes[0].target_port = 54,
                7 => a.probes[0].protocol = 6,
                8 => a.probes[0].source = "0.0.0.0".parse().unwrap(),
                9 => a.probes[0].target = "224.0.0.1".parse().unwrap(),
                10 => a.probes[0].target = "255.255.255.255".parse().unwrap(),
                11 => a.probes[1].source = "::".parse().unwrap(),
                12 => a.probes[1].target = "ff02::1".parse().unwrap(),
                _ => a.probes[0].target = "2606:4700:4700::1111".parse().unwrap(),
            }
            assert!(
                Model::new(scope(), [Some(a), Some(b)], Some(Slot::A)).is_err(),
                "case {case}"
            );
        }
        assert!(Model::new(scope(), [None, Some(member(22))], Some(Slot::A)).is_err());
    }

    #[test]
    fn changed_or_duplicate_owned_filter_blocks_replace_and_cleanup() {
        let model = pair(Some(Slot::A));
        let empty = Model::empty(scope()).unwrap();
        for change in 0..6 {
            let mut store = Fake::new();
            store.compare_exchange(&empty, &model).unwrap();
            match change {
                0 => {
                    store.state.filters[0].action = match store.state.filters[0].action {
                        Action::Permit => Action::Block,
                        Action::Block => Action::Permit,
                    }
                }
                1 => store.state.filters[0].weight += 1,
                2 => store.state.filters[0].conditions.clear(),
                3 => store.state.filters[0].sublayer = Key([0; 16]),
                4 => store.state.filters.push(store.state.filters[0].clone()),
                _ => store.state.sublayer.as_mut().unwrap().weight += 1,
            }
            let foreign = store.state.clone();
            assert_eq!(
                store.compare_exchange(&model, &empty),
                Err(GuardError::Conflict)
            );
            assert_eq!(
                store.compare_exchange(&model, &pair(Some(Slot::B))),
                Err(GuardError::Conflict)
            );
            assert_eq!(store.state, foreign);
        }
    }

    #[test]
    fn journal_roundtrip_stable_keys_and_exact_cleanup() {
        let model = pair(None);
        let empty = Model::empty(scope()).unwrap();
        let mut store = Fake::new();
        let recovered: Model =
            serde_json::from_slice(&serde_json::to_vec(&model).unwrap()).unwrap();
        recovered.validate().unwrap();
        assert_eq!(recovered, model);
        assert_eq!(pair(None).expected, model.expected);
        let mut other_scope = scope();
        other_scope.connection_generation += 1;
        let other = Model::new(other_scope, model.members.clone(), None).unwrap();
        assert!(model.expected.filters.iter().all(|f| other
            .expected
            .filters
            .iter()
            .all(|o| o.key != f.key)));
        store.compare_exchange(&empty, &recovered).unwrap();
        store.compare_exchange(&recovered, &empty).unwrap();
        assert_eq!(store.snapshot(&scope()).unwrap(), empty.expected);
    }

    #[test]
    fn every_staged_failure_rolls_back_start_promotion_tuple_replace_and_cleanup() {
        let empty = Model::empty(scope()).unwrap();
        let old = pair(Some(Slot::A));
        let promoted = pair(Some(Slot::B));
        let mut members = old.members.clone();
        members[1].as_mut().unwrap().probes[0].source_port += 1;
        let tuple_changed = Model::new(scope(), members, old.active).unwrap();
        for (before, after, writes) in [
            (&empty, &old, 7),
            (&old, &promoted, 12),
            (&old, &tuple_changed, 2),
            (&old, &empty, 7),
        ] {
            for fail_at in 0..writes {
                let mut store = Fake::new();
                store.state = before.expected.clone();
                store.fail_at = Some(fail_at);
                assert!(
                    store.compare_exchange(before, after).is_err(),
                    "write {fail_at}/{writes}"
                );
                assert_eq!(store.state, before.expected);
                assert!(store.published.is_empty());
            }
        }
    }

    #[test]
    fn cleanup_preserves_foreign_filters_and_aborts_on_foreign_sublayer_reference() {
        let empty = Model::empty(scope()).unwrap();
        let model = pair(Some(Slot::A));
        let mut other_scope = scope();
        other_scope.runtime = RuntimeSlot::Latest;
        let other = Model::new(other_scope, model.members.clone(), model.active).unwrap();
        let mut store = Fake::new();
        store.foreign = other.expected.filters;
        let foreign = store.foreign.clone();
        store.compare_exchange(&empty, &model).unwrap();
        store.compare_exchange(&model, &empty).unwrap();
        assert_eq!(store.foreign, foreign);
        store.compare_exchange(&empty, &model).unwrap();
        store.foreign[0].sublayer = model.expected.sublayer.as_ref().unwrap().key;
        assert!(store.compare_exchange(&model, &empty).is_err());
        assert_eq!(store.state, model.expected);
    }

    #[test]
    fn standby_without_probe_sockets_still_denies_both_families() {
        let mut standby = member(22);
        standby.probes.clear();
        let model = Model::new(scope(), [None, Some(standby)], None).unwrap();
        assert_eq!(model.expected.filters.len(), 4);
        for (i, layer) in [Layer::TransportV4, Layer::TransportV6]
            .into_iter()
            .enumerate()
        {
            assert_eq!(
                decision(&model, layer, member(22).interface, &member(22).probes[i]),
                Some(Action::Block)
            );
        }
        let mut invalid_scope = scope();
        invalid_scope.runtime_generation = 0;
        assert!(Model::empty(invalid_scope).is_err());
        let keys = resource_keys(&scope()).unwrap();
        let mut unique = std::collections::BTreeSet::from([keys.sublayer]);
        unique.extend(keys.filters);
        assert_eq!(unique.len(), 13);
    }

    struct SplitFake {
        store: Fake,
        assigned_weight: Option<u16>,
        change_weight_after_commit: bool,
        dynamic_keys: Vec<Key>,
        calls: Vec<SessionKind>,
        fail: Option<usize>,
        lost_ack: Option<usize>,
        fail_read: Option<usize>,
        reads: usize,
        fail_close: bool,
        closed: bool,
    }
    impl SplitFake {
        fn installed(model: &Model) -> Self {
            let mut store = Fake::new();
            store.state = model.expected.clone();
            Self {
                store,
                assigned_weight: None,
                change_weight_after_commit: false,
                dynamic_keys: model
                    .expected
                    .filters
                    .iter()
                    .filter(|f| f.action == Action::Permit)
                    .map(|f| f.key)
                    .collect(),
                calls: vec![],
                fail: None,
                lost_ack: None,
                fail_read: None,
                reads: 0,
                fail_close: false,
                closed: false,
            }
        }
    }
    impl SplitEngines for SplitFake {
        fn scope(&self) -> &SessionScope {
            &self.store.scope
        }
        fn snapshot(&mut self) -> Result<Snapshot> {
            let read = self.reads;
            self.reads += 1;
            if self.fail_read == Some(read) {
                return Err(GuardError::Native(4));
            }
            Ok(self.store.state.clone())
        }
        fn exchange(
            &mut self,
            kind: SessionKind,
            expected: &Model,
            desired: &Model,
        ) -> Result<Model> {
            let step = self.calls.len();
            self.calls.push(kind);
            let mut pending = Pending {
                state: self.store.state.clone(),
                assigned_weight: self.assigned_weight,
                foreign: &[],
                fail_at: None,
                writes: 0,
                filter_writes: vec![],
            };
            let committed =
                stage_session_exchange(&scope(), &mut pending, expected, desired, kind)?;
            // Mirror WFP's dynamic-session ownership check, not merely GUID
            // equality: another session's or legacy static permit is foreign.
            if kind == SessionKind::DynamicPermits
                && pending
                    .filter_writes
                    .iter()
                    .any(|(add, key)| !add && !self.dynamic_keys.contains(key))
            {
                return Err(GuardError::Conflict);
            }
            if self.fail == Some(step) {
                return Err(GuardError::Native(1));
            }
            pending.state.filters.sort_by_key(|f| f.key);
            self.store.state = pending.state;
            if self.change_weight_after_commit && !expected.installed && desired.installed {
                self.store.state.sublayer.as_mut().unwrap().weight += 1;
            }
            if kind == SessionKind::DynamicPermits {
                self.dynamic_keys = desired
                    .expected
                    .filters
                    .iter()
                    .filter(|f| f.action == Action::Permit)
                    .map(|f| f.key)
                    .collect();
            }
            self.store.published.push(self.store.state.clone());
            if self.lost_ack == Some(step) {
                return Err(GuardError::Native(2));
            }
            Ok(committed)
        }
        fn close_permits(&mut self) -> Result<()> {
            if self.fail_close {
                return Err(GuardError::Native(5));
            }
            self.store
                .state
                .filters
                .retain(|f| !self.dynamic_keys.contains(&f.key));
            self.dynamic_keys.clear();
            self.closed = true;
            Ok(())
        }
    }

    #[test]
    fn assigned_sublayer_weight_readback_allows_initial_split_install() {
        let empty = Model::empty(scope()).unwrap();
        let desired = pair(None);
        let mut fake = SplitFake::installed(&empty);
        fake.assigned_weight = Some(32771);
        let committed =
            apply_split(&mut fake, &ExchangePlan::new(&empty, &desired).unwrap()).unwrap();
        assert_eq!(committed.assigned_sublayer_weight, Some(32771));
        committed.validate().unwrap();
        assert_eq!(fake.store.state.sublayer.as_ref().unwrap().weight, 32771);
        assert_eq!(fake.store.state.filters, desired.expected.filters);
        assert!(!fake.closed);
    }

    #[test]
    fn assigned_sublayer_weight_change_after_creating_transaction_is_rejected() {
        let empty = Model::empty(scope()).unwrap();
        let mut fake = SplitFake::installed(&empty);
        fake.assigned_weight = Some(32771);
        fake.change_weight_after_commit = true;
        assert_eq!(
            apply_split(&mut fake, &ExchangePlan::new(&empty, &pair(None)).unwrap()),
            Err(GuardError::Conflict)
        );
        assert_eq!(fake.calls.len(), 2);
        assert!(fake.closed);
        assert!(fake
            .store
            .state
            .filters
            .iter()
            .all(|f| f.action == Action::Block));
    }

    #[test]
    fn assigned_sublayer_weight_readback_and_recovery_preserve_all_other_snapshot_checks() {
        let empty = Model::empty(scope()).unwrap();
        let desired = pair(None).without_probes().unwrap();
        let plan = ExchangePlan::new(&empty, &desired).unwrap();
        for mutation in 0..13 {
            let mut actual = desired.expected.clone();
            actual.sublayer.as_mut().unwrap().weight = 32771;
            match mutation {
                0 => actual.scope.connection_generation += 1,
                1 => actual.sublayer.as_mut().unwrap().key.0[0] ^= 1,
                2 => actual.sublayer.as_mut().unwrap().flags = 1,
                3 => actual.filters[0].key.0[0] ^= 1,
                4 => actual.filters[0].sublayer.0[0] ^= 1,
                5 => actual.filters[0].flags = 1,
                6 => actual.filters[0].weight = 2,
                7 => actual.filters[0].action = Action::Permit,
                8 => actual.filters[0].conditions.clear(),
                9 => {
                    actual.filters[0].layer = match actual.filters[0].layer {
                        Layer::TransportV4 => Layer::TransportV6,
                        _ => Layer::TransportV4,
                    }
                }
                10 => {
                    actual.filters.pop();
                }
                11 => actual.filters.push(actual.filters[0].clone()),
                _ => actual.sublayer = None,
            }
            assert!(
                desired.readback_after(&empty, &actual).is_err(),
                "install mutation {mutation}"
            );
            assert!(
                plan.resolve(&actual).is_err(),
                "recovery mutation {mutation}"
            );
        }
    }

    #[test]
    fn assigned_sublayer_weight_is_not_relearned_by_existing_or_pinned_exchanges() {
        let empty = Model::empty(scope()).unwrap();
        let desired = pair(None);
        let mut actual = desired.expected.clone();
        actual.sublayer.as_mut().unwrap().weight = 32771;
        let pinned = desired.readback_after(&empty, &actual).unwrap();
        let pinned: Model = serde_json::from_slice(&serde_json::to_vec(&pinned).unwrap()).unwrap();
        for previous in [&desired, &pinned] {
            let mut changed = previous.expected.clone();
            changed.sublayer.as_mut().unwrap().weight += 1;
            let plan = ExchangePlan::new(previous, &previous.without_probes().unwrap()).unwrap();
            assert!(plan.resolve(&changed).is_err());
            let mut fake = SplitFake::installed(previous);
            fake.store.state = changed;
            assert!(apply_split(&mut fake, &plan).is_err());
            assert!(fake.store.published.is_empty());
        }
        let mut forged = pinned.clone();
        forged.expected.filters[0].weight += 1;
        assert_eq!(forged.validate(), Err(GuardError::Invalid));
        let mut forged = pinned.clone();
        forged.expected.sublayer.as_mut().unwrap().weight += 1;
        assert_eq!(forged.validate(), Err(GuardError::Invalid));
        assert!(ExchangePlan::new(&empty, &pinned).is_err());
        assert!(ExchangePlan::new(&pinned, &desired).is_err());
    }

    #[test]
    fn assigned_sublayer_weight_lost_commit_ack_resolves_only_journaled_states() {
        let empty = Model::empty(scope()).unwrap();
        let plan = ExchangePlan::new(&empty, &pair(None)).unwrap();
        for step in [1, 2] {
            let mut fake = SplitFake::installed(&empty);
            fake.assigned_weight = Some(32771);
            fake.lost_ack = Some(step);
            assert!(apply_split(&mut fake, &plan).is_err());
            let recovered = plan.resolve(&fake.store.state).unwrap();
            assert_eq!(recovered.assigned_sublayer_weight, Some(32771));
            assert!(recovered
                .expected
                .filters
                .iter()
                .all(|f| f.action == Action::Block));
            recovered.validate().unwrap();
        }
    }

    #[test]
    fn split_withdraws_before_base_and_confirms_base_before_install() {
        let old = pair(Some(Slot::A));
        let new = pair(Some(Slot::B));
        let plan = ExchangePlan::new(&old, &new).unwrap();
        let mut fake = SplitFake::installed(&old);
        apply_split(&mut fake, &plan).unwrap();
        assert_eq!(
            fake.calls,
            [
                SessionKind::DynamicPermits,
                SessionKind::StaticBase,
                SessionKind::DynamicPermits
            ]
        );
        assert_eq!(fake.store.published.len(), 3);
        assert_eq!(fake.store.published[0].filters.len(), 4);
        assert_eq!(fake.store.published[1].filters.len(), 4);
        assert!(fake.store.published[..2]
            .iter()
            .flat_map(|s| &s.filters)
            .all(|f| f.action == Action::Block));
        assert_eq!(fake.store.state, new.expected);
        assert!(!fake.closed);
        let recovered: ExchangePlan =
            serde_json::from_slice(&serde_json::to_vec(&plan).unwrap()).unwrap();
        assert_eq!(recovered, plan);
    }

    #[test]
    fn split_failures_and_lost_ack_drop_permits_but_keep_last_committed_base() {
        let old = pair(Some(Slot::A));
        let new = pair(Some(Slot::B));
        let plan = ExchangePlan::new(&old, &new).unwrap();
        for step in 0..3 {
            for lost_ack in [false, true] {
                let mut fake = SplitFake::installed(&old);
                if lost_ack {
                    fake.lost_ack = Some(step);
                } else {
                    fake.fail = Some(step);
                }
                assert!(apply_split(&mut fake, &plan).is_err());
                assert!(fake.closed);
                let committed_new = step == 2 || (step == 1 && lost_ack);
                assert_eq!(
                    fake.store.state,
                    if committed_new {
                        plan.base.expected.clone()
                    } else {
                        plan.withdrawn.expected.clone()
                    }
                );
                assert_eq!(fake.calls.len(), step + 1);
            }
        }
    }

    #[test]
    fn session_allowlist_rejects_static_permits_and_dynamic_base_mutations() {
        let empty = Model::empty(scope()).unwrap();
        let model = pair(None);
        for (kind, before, after) in [
            (SessionKind::StaticBase, &empty, &model),
            (SessionKind::DynamicPermits, &empty, &model),
            (SessionKind::DynamicPermits, &model, &empty),
        ] {
            let mut pending = Pending {
                state: before.expected.clone(),
                assigned_weight: None,
                foreign: &[],
                fail_at: None,
                writes: 0,
                filter_writes: vec![],
            };
            assert!(stage_session_exchange(&scope(), &mut pending, before, after, kind).is_err());
            assert_eq!(pending.writes, 0);
        }
    }

    #[test]
    fn split_conflict_closes_only_own_dynamic_session_without_touching_base() {
        let old = pair(Some(Slot::A));
        let new = pair(Some(Slot::B));
        let mut fake = SplitFake::installed(&old);
        fake.store
            .state
            .filters
            .iter_mut()
            .find(|f| f.action == Action::Block)
            .unwrap()
            .weight += 1;
        let mut untouched = fake.store.state.clone();
        untouched.filters.retain(|f| f.action == Action::Block);
        assert!(apply_split(&mut fake, &ExchangePlan::new(&old, &new).unwrap()).is_err());
        assert_eq!(fake.store.state, untouched);
        assert!(fake.closed);
        assert_eq!(fake.calls.len(), 1);
    }

    #[test]
    fn helper_shutdown_removes_tuple_exception_and_preserves_both_family_blocks() {
        let old = pair(None);
        let empty = Model::empty(scope()).unwrap();
        let mut fake = SplitFake::installed(&empty);
        apply_split(&mut fake, &ExchangePlan::new(&empty, &old).unwrap()).unwrap();
        fake.close_permits().unwrap(); // fake OS dynamic-session rundown
        let base = old.without_probes().unwrap();
        assert_eq!(fake.store.state, base.expected);
        for member in old.members.iter().flatten() {
            for (i, layer) in [Layer::TransportV4, Layer::TransportV6]
                .into_iter()
                .enumerate()
            {
                assert_eq!(
                    decision(&base, layer, member.interface, &member.probes[i]),
                    Some(Action::Block)
                );
            }
        }
    }

    #[test]
    fn split_readback_failure_never_advances_and_revokes_even_newly_installed_permits() {
        let old = pair(Some(Slot::A));
        let new = pair(Some(Slot::B));
        let plan = ExchangePlan::new(&old, &new).unwrap();
        for step in 0..3 {
            let mut fake = SplitFake::installed(&old);
            fake.fail_read = Some(step);
            assert!(apply_split(&mut fake, &plan).is_err());
            assert!(fake.closed);
            assert_eq!(fake.calls.len(), step + 1);
            assert_eq!(
                fake.store.state,
                if step == 0 {
                    plan.withdrawn.expected.clone()
                } else {
                    plan.base.expected.clone()
                }
            );
        }
    }

    #[test]
    fn split_legacy_static_or_other_session_permit_is_not_adopted_or_deleted() {
        let old = pair(Some(Slot::A));
        let mut fake = SplitFake::installed(&old);
        let foreign = fake.dynamic_keys.pop().unwrap();
        let original = fake
            .store
            .state
            .filters
            .iter()
            .find(|f| f.key == foreign)
            .unwrap()
            .clone();
        assert_eq!(
            apply_split(&mut fake, &ExchangePlan::new(&old, &old).unwrap()),
            Err(GuardError::RemovalUnconfirmed)
        );
        assert_eq!(fake.calls.len(), 1);
        assert_eq!(
            fake.store.state.filters.iter().find(|f| f.key == foreign),
            Some(&original)
        );
        assert_eq!(
            fake.store
                .state
                .filters
                .iter()
                .filter(|f| f.action == Action::Block)
                .count(),
            4
        );
        assert!(fake.closed);
    }

    #[test]
    fn failed_session_close_never_claims_safe_socket_release() {
        let old = pair(Some(Slot::A));
        let mut fake = SplitFake::installed(&old);
        fake.fail = Some(0);
        fake.fail_close = true;
        assert_eq!(
            apply_split(&mut fake, &ExchangePlan::new(&old, &old).unwrap()),
            Err(GuardError::RemovalUnconfirmed)
        );
        assert_eq!(fake.store.state, old.expected);
        assert_eq!(fake.calls.len(), 1);
    }

    #[test]
    fn epoch_loss_is_rejected_without_recreating_base_or_permits() {
        let old = pair(Some(Slot::A));
        let mut fake = SplitFake::installed(&Model::empty(scope()).unwrap());
        assert_eq!(
            apply_split(&mut fake, &ExchangePlan::new(&old, &old).unwrap()),
            Err(GuardError::EpochLost)
        );
        assert_eq!(fake.store.state.sublayer, None);
        assert!(fake.store.state.filters.is_empty());
        assert!(fake.store.published.is_empty());
        assert!(fake.closed);
    }

    #[test]
    fn forged_intermediate_and_wrong_scope_plans_do_not_mutate_or_close_sessions() {
        let old = pair(Some(Slot::A));
        let new = pair(Some(Slot::B));
        for mutation in 0..3 {
            let mut plan = ExchangePlan::new(&old, &new).unwrap();
            match mutation {
                0 => plan.withdrawn = old.clone(),
                1 => plan.base = plan.withdrawn.clone(),
                _ => plan.desired.scope.connection_generation += 1,
            }
            let mut fake = SplitFake::installed(&old);
            assert!(apply_split(&mut fake, &plan).is_err());
            assert_eq!(fake.store.state, old.expected);
            assert!(fake.calls.is_empty());
            assert!(!fake.closed);
        }
    }

    #[test]
    fn valid_plan_for_another_scope_cannot_close_this_helpers_permits() {
        let old = pair(Some(Slot::A));
        let mut another_scope = scope();
        another_scope.connection_generation += 1;
        let another = Model::new(another_scope, old.members.clone(), old.active).unwrap();
        let mut fake = SplitFake::installed(&old);
        assert_eq!(
            apply_split(&mut fake, &ExchangePlan::new(&another, &another).unwrap()),
            Err(GuardError::Conflict)
        );
        assert_eq!(fake.store.state, old.expected);
        assert!(fake.calls.is_empty());
        assert!(!fake.closed);
    }

    #[test]
    fn both_members_can_be_blocked_before_external_route_cas_and_cleanup_withdraws_first() {
        let old = pair(Some(Slot::A));
        let blocked = pair(None).without_probes().unwrap();
        let mut fake = SplitFake::installed(&old);
        apply_split(&mut fake, &ExchangePlan::new(&old, &blocked).unwrap()).unwrap();
        assert_eq!(fake.store.state.filters.len(), 8);
        assert!(fake
            .store
            .state
            .filters
            .iter()
            .all(|f| f.action == Action::Block));
        // Enclosing owner can fence route CAS here; this module never changes routes.
        let empty = Model::empty(scope()).unwrap();
        fake.calls.clear();
        apply_split(&mut fake, &ExchangePlan::new(&blocked, &empty).unwrap()).unwrap();
        assert_eq!(fake.calls[0], SessionKind::DynamicPermits);
        assert_eq!(fake.store.state, empty.expected);
    }
}
