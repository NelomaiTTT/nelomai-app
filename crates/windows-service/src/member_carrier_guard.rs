//! Unselected portable C-source / A-B-egress authorization policy.
//! Identity inputs are caller-authenticated, not inferred from numeric WFP
//! conditions. Snapshots include independently attested GUID/scope bindings.
//! Native classification, socket ownership and established-flow reauthorization
//! remain native/factory gates; this module does not establish those facts.
#![allow(dead_code)] // No native adapter or factory is enabled by this sidecar.

pub(crate) use crate::member_guard::SessionKind;
pub(crate) use crate::member_guard::{Action, GuardError, Key, ProbeTuple, Result, Sublayer};
use crate::member_owner::InterfaceProof;
use nelomai_client_tunnel::redundancy::{SessionScope, Slot};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::IpAddr;

const VERSION: u32 = 2;
const REQUESTED_PRIORITY: u16 = 65534;
const RAW_ENDPOINT: u32 = 0x10;
const OUTBOUND_PASS_THRU: u32 = 0x40000;
const INDEXED: u32 = 64;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {
    pub scope: SessionScope,
    pub proof: InterfaceProof,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Carrier {
    pub identity: Identity,
    pub sources: Vec<IpAddr>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Member {
    pub identity: Identity,
    pub probes: Vec<ProbeTuple>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum Layer {
    TransportV4,
    TransportV6,
    PacketV4,
    PacketV6,
    ForwardV4,
    ForwardV6,
    AleConnectV4,
    AleConnectV6,
}
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub(crate) enum Condition {
    EgressIndex(u32),
    LocalInterface(u64),
    DestinationIndex(u32),
    DestinationLuid(u64),
    SourceIndex(u32),
    SourceLuid(u64),
    NextHopIndex(u32),
    NextHopLuid(u64),
    SourceAddress(IpAddr),
    DestinationAddress(IpAddr),
    LocalPort(u16),
    RemotePort(u16),
    Protocol(u8),
    NoneSetFlags(u32),
    AllSetFlags(u32),
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
pub(crate) struct Snapshot {
    #[serde(deserialize_with = "version")]
    pub version: u32,
    pub scope: SessionScope,
    pub carrier: Option<Carrier>,
    pub egress: [Option<Identity>; 2],
    pub sublayer: Option<Sublayer>,
    pub filters: Vec<Filter>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ModelWire")]
pub(crate) struct Model {
    pub version: u32,
    pub scope: SessionScope,
    pub carrier: Option<Carrier>,
    pub members: [Option<Member>; 2],
    pub active: Option<Slot>,
    pub installed: bool,
    pub permits: bool,
    pub assigned_sublayer_weight: Option<u16>,
    pub expected: Snapshot,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelWire {
    version: u32,
    scope: SessionScope,
    carrier: Option<Carrier>,
    members: [Option<Member>; 2],
    active: Option<Slot>,
    installed: bool,
    permits: bool,
    assigned_sublayer_weight: Option<u16>,
    expected: Snapshot,
}
impl TryFrom<ModelWire> for Model {
    type Error = GuardError;
    fn try_from(w: ModelWire) -> Result<Self> {
        let model = Self {
            version: w.version,
            scope: w.scope,
            carrier: w.carrier,
            members: w.members,
            active: w.active,
            installed: w.installed,
            permits: w.permits,
            assigned_sublayer_weight: w.assigned_sublayer_weight,
            expected: w.expected,
        };
        model.validate()?;
        Ok(model)
    }
}
fn version<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<u32, D::Error> {
    let v = u32::deserialize(d)?;
    if v != VERSION {
        return Err(serde::de::Error::custom("carrier_guard_version"));
    }
    Ok(v)
}
pub(crate) struct ResourceKeys {
    pub sublayer: Key,
    pub filters: [Key; 48],
}
pub(crate) fn resource_keys(scope: &SessionScope) -> Result<ResourceKeys> {
    if !scope.validate() {
        return Err(GuardError::Invalid);
    }
    let key = |purpose: &[u8]| {
        let mut hash = Sha256::new();
        hash.update(b"nelomai-carrier-guard/v2\0");
        hash.update([match scope.runtime {
            nelomai_contracts::RuntimeSlot::Stable => 0,
            nelomai_contracts::RuntimeSlot::Latest => 1,
        }]);
        hash.update(scope.runtime_generation.to_be_bytes());
        hash.update(scope.session_id.as_bytes());
        hash.update(scope.connection_generation.to_be_bytes());
        hash.update(purpose);
        let digest = hash.finalize();
        let mut bytes: [u8; 16] = digest[..16].try_into().expect("SHA256 prefix");
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Key(bytes)
    };
    Ok(ResourceKeys {
        sublayer: key(b"sublayer"),
        filters: std::array::from_fn(|i| key(&[b'f', (i / 24) as u8, (i % 24) as u8])),
    })
}
impl Model {
    pub(crate) fn empty(scope: SessionScope) -> Result<Self> {
        Self::construct(scope, None, [None, None], None, false, false)
    }
    pub(crate) fn new(
        scope: SessionScope,
        mut carrier: Carrier,
        mut members: [Option<Member>; 2],
        active: Option<Slot>,
    ) -> Result<Self> {
        carrier.sources.sort();
        for member in members.iter_mut().flatten() {
            member.probes.sort_by_key(probe_key);
        }
        Self::construct(scope, Some(carrier), members, active, true, true)
    }
    fn construct(
        scope: SessionScope,
        carrier: Option<Carrier>,
        members: [Option<Member>; 2],
        active: Option<Slot>,
        installed: bool,
        permits: bool,
    ) -> Result<Self> {
        let mut model = Self {
            version: VERSION,
            expected: Snapshot {
                version: VERSION,
                scope: scope.clone(),
                carrier: None,
                egress: [None, None],
                sublayer: None,
                filters: vec![],
            },
            scope,
            carrier,
            members,
            active,
            installed,
            permits,
            assigned_sublayer_weight: None,
        };
        model.expected = build(&model)?;
        Ok(model)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.version != VERSION || self.expected != build(self)? {
            return Err(GuardError::Invalid);
        }
        Ok(())
    }
    pub(crate) fn without_permits(&self) -> Result<Self> {
        self.validate()?;
        let mut model = self.clone();
        model.permits = false;
        model.expected = build(&model)?;
        Ok(model)
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
            model.expected = build(&model)?;
        }
        Ok(model)
    }
    /// Creation readback must be captured by the adapter while its creating
    /// transaction still owns the lock, then journaled before later exchanges.
    /// Only priority may be learned; all identity/object fields remain exact.
    pub(crate) fn readback_after(&self, previous: &Self, actual: &Snapshot) -> Result<Self> {
        validate_exchange(&self.scope, previous, self)?;
        if !previous.installed && self.installed {
            return self.created_readback(actual);
        }
        require_snapshot(actual, &self.expected)?;
        Ok(self.clone())
    }
    fn created_readback(&self, actual: &Snapshot) -> Result<Self> {
        self.validate()?;
        if !self.installed || self.assigned_sublayer_weight.is_some() {
            return Err(GuardError::Invalid);
        }
        let mut model = self.clone();
        model.assigned_sublayer_weight = Some(
            actual
                .sublayer
                .as_ref()
                .ok_or(GuardError::EpochLost)?
                .weight,
        );
        model.expected = build(&model)?;
        require_snapshot(actual, &model.expected)?;
        Ok(model)
    }
}

fn probe_key(p: &ProbeTuple) -> (IpAddr, u16, IpAddr, u16, u8) {
    (p.source, p.source_port, p.target, p.target_port, p.protocol)
}
fn usable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_link_local()
                && ip.octets()[0] != 0
                && ip.octets()[0] < 224
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && ip.to_ipv4_mapped().is_none()
                && !ip.is_unicast_link_local()
        }
    }
}
fn validate_identity(scope: &SessionScope, identity: &Identity) -> Result<()> {
    if identity.scope != *scope
        || identity.proof.index == 0
        || identity.proof.luid == 0
        || identity.proof.guid == [0; 16]
    {
        return Err(GuardError::Invalid);
    }
    Ok(())
}
fn build(model: &Model) -> Result<Snapshot> {
    let keys = resource_keys(&model.scope)?;
    let mut snapshot = Snapshot {
        version: VERSION,
        scope: model.scope.clone(),
        carrier: model.carrier.clone(),
        egress: model.members.clone().map(|m| m.map(|m| m.identity)),
        sublayer: None,
        filters: vec![],
    };
    if !model.installed {
        if model.carrier.is_some()
            || model.members.iter().any(Option::is_some)
            || model.active.is_some()
            || model.permits
            || model.assigned_sublayer_weight.is_some()
        {
            return Err(GuardError::Invalid);
        }
        return Ok(snapshot);
    }
    let carrier = model.carrier.as_ref().ok_or(GuardError::Invalid)?;
    validate_identity(&model.scope, &carrier.identity)?;
    if carrier.sources.is_empty()
        || carrier.sources.len() > 2
        || carrier.sources.windows(2).any(|p| p[0] >= p[1])
    {
        return Err(GuardError::Invalid);
    }
    let mut families = [false; 2];
    for ip in &carrier.sources {
        let i = usize::from(ip.is_ipv6());
        if !usable(*ip) || families[i] {
            return Err(GuardError::Invalid);
        }
        families[i] = true;
    }
    let selected = model.active.map(|s| match s {
        Slot::A => 0,
        Slot::B => 1,
    });
    if model.members.iter().all(Option::is_none)
        || selected.is_some_and(|i| model.members[i].is_none())
    {
        return Err(GuardError::Invalid);
    }
    let mut identities = vec![carrier.identity.proof];
    let mut ports = std::collections::BTreeSet::new();
    for member in model.members.iter().flatten() {
        validate_identity(&model.scope, &member.identity)?;
        let proof = member.identity.proof;
        if identities
            .iter()
            .any(|p| p.index == proof.index || p.luid == proof.luid || p.guid == proof.guid)
        {
            return Err(GuardError::Invalid);
        }
        identities.push(proof);
        if member.probes.len() > 2
            || member
                .probes
                .windows(2)
                .any(|p| probe_key(&p[0]) >= probe_key(&p[1]))
        {
            return Err(GuardError::Invalid);
        }
        let mut seen = [false; 2];
        for p in &member.probes {
            let family = usize::from(p.source.is_ipv6());
            if seen[family]
                || !carrier.sources.contains(&p.source)
                || !usable(p.target)
                || p.source == p.target
                || p.source.is_ipv4() != p.target.is_ipv4()
                || p.source_port == 0
                || p.target_port != 53
                || p.protocol != 17
                || !ports.insert((p.source, p.source_port))
            {
                return Err(GuardError::Invalid);
            }
            seen[family] = true;
        }
    }
    snapshot.sublayer = Some(Sublayer {
        key: keys.sublayer,
        weight: model.assigned_sublayer_weight.unwrap_or(REQUESTED_PRIORITY),
        flags: 0,
    });
    let c = carrier.identity.proof;
    for (slot, member) in model.members.iter().enumerate() {
        let Some(member) = member else { continue };
        let e = member.identity.proof;
        for family in 0..2 {
            for classification in 0..4 {
                let layer = layer(classification, family == 1);
                let base = match classification {
                    0 | 1 => vec![Condition::EgressIndex(e.index)],
                    2 => vec![Condition::DestinationIndex(e.index)],
                    _ => vec![Condition::NextHopIndex(e.index)],
                };
                let purpose = family * 4 + classification;
                snapshot
                    .filters
                    .push(filter(&keys, slot, purpose, layer, Action::Block, base));
                if !model.permits {
                    continue;
                }
                if selected == Some(slot) {
                    if let Some(source) = carrier
                        .sources
                        .iter()
                        .find(|ip| usize::from(ip.is_ipv6()) == family)
                    {
                        let conditions = permit_conditions(classification, c, e, *source, None);
                        snapshot.filters.push(filter(
                            &keys,
                            slot,
                            8 + purpose,
                            layer,
                            Action::Permit,
                            conditions,
                        ));
                    }
                } else if let Some(probe) = member
                    .probes
                    .iter()
                    .find(|p| usize::from(p.source.is_ipv6()) == family)
                {
                    let conditions =
                        permit_conditions(classification, c, e, probe.source, Some(probe));
                    snapshot.filters.push(filter(
                        &keys,
                        slot,
                        16 + purpose,
                        layer,
                        Action::Permit,
                        conditions,
                    ));
                }
            }
        }
    }
    snapshot.filters.sort_by_key(|f| f.key);
    Ok(snapshot)
}
fn layer(classification: usize, v6: bool) -> Layer {
    match (classification, v6) {
        (0, false) => Layer::TransportV4,
        (0, true) => Layer::TransportV6,
        (1, false) => Layer::PacketV4,
        (1, true) => Layer::PacketV6,
        (2, false) => Layer::ForwardV4,
        (2, true) => Layer::ForwardV6,
        (_, false) => Layer::AleConnectV4,
        (_, true) => Layer::AleConnectV6,
    }
}
fn permit_conditions(
    classification: usize,
    c: InterfaceProof,
    e: InterfaceProof,
    source: IpAddr,
    probe: Option<&ProbeTuple>,
) -> Vec<Condition> {
    use Condition::*;
    let mut conditions = match classification {
        0 => vec![
            EgressIndex(e.index),
            LocalInterface(c.luid),
            NoneSetFlags(RAW_ENDPOINT),
        ],
        1 => vec![EgressIndex(e.index), LocalInterface(e.luid)],
        2 => vec![
            DestinationIndex(e.index),
            DestinationLuid(e.luid),
            SourceIndex(c.index),
            SourceLuid(c.luid),
            AllSetFlags(OUTBOUND_PASS_THRU),
        ],
        _ => vec![
            NextHopIndex(e.index),
            NextHopLuid(e.luid),
            LocalInterface(c.luid),
        ],
    };
    conditions.push(SourceAddress(source));
    if let Some(probe) = probe {
        conditions.push(DestinationAddress(probe.target));
        if classification == 0 || classification == 3 {
            conditions.extend([LocalPort(probe.source_port), RemotePort(53), Protocol(17)]);
        }
    }
    conditions.sort();
    conditions
}
fn filter(
    keys: &ResourceKeys,
    slot: usize,
    purpose: usize,
    layer: Layer,
    action: Action,
    conditions: Vec<Condition>,
) -> Filter {
    Filter {
        key: keys.filters[slot * 24 + purpose],
        sublayer: keys.sublayer,
        layer,
        weight: if action == Action::Block { 1 } else { 2 },
        flags: if action == Action::Permit
            && matches!(layer, Layer::AleConnectV4 | Layer::AleConnectV6)
        {
            INDEXED
        } else {
            0
        },
        action,
        conditions,
    }
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
    // The session's source carrier cannot be replaced by an active exchange.
    if expected.installed && desired.installed && expected.carrier != desired.carrier {
        return Err(GuardError::Conflict);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "PlanWire")]
pub(crate) struct ExchangePlan {
    pub version: u32,
    pub expected: Model,
    pub withdrawn: Model,
    pub base: Model,
    pub desired: Model,
    pub captured_sublayer_weight: Option<u16>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanWire {
    version: u32,
    expected: Model,
    withdrawn: Model,
    base: Model,
    desired: Model,
    captured_sublayer_weight: Option<u16>,
}
impl TryFrom<PlanWire> for ExchangePlan {
    type Error = GuardError;
    fn try_from(w: PlanWire) -> Result<Self> {
        let plan = Self {
            version: w.version,
            expected: w.expected,
            withdrawn: w.withdrawn,
            base: w.base,
            desired: w.desired,
            captured_sublayer_weight: w.captured_sublayer_weight,
        };
        plan.validate()?;
        Ok(plan)
    }
}
pub(crate) trait ExchangeJournal {
    fn load(&mut self, scope: &SessionScope) -> Result<Option<ExchangePlan>>;
    fn compare_exchange(
        &mut self,
        expected: Option<&ExchangePlan>,
        desired: &ExchangePlan,
    ) -> Result<()>;
}
/// Only exact durable plan readback creates this token. It is not native
/// authority; caller-held source/egress/port/route facts are required below.
pub(crate) struct JournaledPlan {
    plan: ExchangePlan,
}
impl ExchangePlan {
    pub(crate) fn new(expected: &Model, desired: &Model) -> Result<Self> {
        validate_exchange(&expected.scope, expected, desired)?;
        Ok(Self {
            version: VERSION,
            expected: expected.clone(),
            withdrawn: expected.without_permits()?,
            base: desired.without_permits()?,
            desired: desired.clone(),
            captured_sublayer_weight: None,
        })
    }
    pub(crate) fn validate(&self) -> Result<()> {
        let mut desired = self.desired.clone();
        if self.captured_sublayer_weight.is_some()
            && (self.expected.installed || !self.base.installed)
        {
            return Err(GuardError::Invalid);
        }
        if self.captured_sublayer_weight.is_some() {
            desired.assigned_sublayer_weight = None;
            desired.expected = build(&desired)?;
        }
        let mut expected = Self::new(&self.expected, &desired)?;
        if self.captured_sublayer_weight.is_some() {
            expected.captured_sublayer_weight = self.captured_sublayer_weight;
            expected.base = expected.bound_candidate(&expected.base)?;
            expected.desired = expected.bound_candidate(&expected.desired)?;
        }
        if self.version != VERSION || *self != expected {
            return Err(GuardError::Invalid);
        }
        Ok(())
    }
    /// Recovery classification only, never a permit to resume traffic. Exact
    /// captured priority and every identity/filter/absent key stay exact.
    /// Never learn a priority from a recovery snapshot after an ambiguous ACK.
    pub(crate) fn resolve(&self, actual: &Snapshot) -> Result<Model> {
        self.validate()?;
        for candidate in [&self.expected, &self.withdrawn, &self.base, &self.desired] {
            let candidate = self.bound_candidate(candidate)?;
            if candidate.expected == *actual {
                return Ok(candidate);
            }
        }
        Err(GuardError::Conflict)
    }
    fn bound_candidate(&self, candidate: &Model) -> Result<Model> {
        let mut model = candidate.clone();
        if model.installed {
            if let Some(weight) = self.captured_sublayer_weight {
                model.assigned_sublayer_weight = Some(weight);
                model.expected = build(&model)?;
            }
        }
        Ok(model)
    }
    pub(crate) fn persist(
        &self,
        journal: &mut impl ExchangeJournal,
        expected: Option<&ExchangePlan>,
    ) -> Result<JournaledPlan> {
        self.validate()?;
        if let Some(old) = expected {
            old.validate()?;
            if old.expected.scope != self.expected.scope {
                return Err(GuardError::Conflict);
            }
        }
        let current = journal.load(&self.expected.scope)?;
        if let Some(current) = &current {
            current.validate()?;
        }
        if current.as_ref() != expected {
            return Err(GuardError::Conflict);
        }
        let acknowledgement = journal.compare_exchange(expected, self);
        let actual = journal.load(&self.expected.scope)?;
        if actual.as_ref() == Some(self) {
            return Ok(JournaledPlan { plan: self.clone() });
        }
        if actual.as_ref() != expected {
            return Err(GuardError::Conflict);
        }
        Err(acknowledgement.err().unwrap_or(GuardError::Conflict))
    }
}
pub(crate) trait SplitEngines {
    fn scope(&self) -> &SessionScope;
    /// Full ordered snapshot AND independently attested scoped GUID bindings.
    fn snapshot(&mut self) -> Result<Snapshot>;
    /// Native transactions must enforce validate_session_exchange, reattest
    /// bindings, capture creation priority inside the lock and abort on error.
    fn exchange(&mut self, kind: SessionKind, expected: &Model, desired: &Model) -> Result<Model>;
    /// Close only this owned dynamic session; never delete foreign allows.
    fn close_permits(&mut self) -> Result<()>;
}
pub(crate) trait Authority {
    /// Reattest identities before base changes; removing a base requires native
    /// absence/owned cleanup. This is NOT proved by a portable model or a GUID.
    fn before_base(&mut self, previous: &Model, base: &Model) -> Result<()>;
    /// Called with permits absent, after base readback. Caller verifies exact
    /// source/DAD/egress/route/DNS facts and exclusively HELD sockets for every
    /// probe tuple. A serialized flag or WFP condition is not port ownership.
    fn before_install(&mut self, desired: &Model) -> Result<()>;
}
pub(crate) fn validate_session_exchange(
    scope: &SessionScope,
    expected: &Model,
    desired: &Model,
    kind: SessionKind,
) -> Result<()> {
    validate_exchange(scope, expected, desired)?;
    match kind {
        SessionKind::StaticBase if expected.permits || desired.permits => Err(GuardError::Invalid),
        SessionKind::DynamicPermits
            if expected.without_permits()?.expected != desired.without_permits()?.expected =>
        {
            Err(GuardError::Invalid)
        }
        _ => Ok(()),
    }
}
/// Three serialized commits, NOT cross-engine atomicity. Success describes an
/// exact verified guard policy, not healthy traffic/established-flow acceptance.
/// Factory publication still requires the separate native/data-plane gates.
pub(crate) fn apply_split(
    engines: &mut impl SplitEngines,
    journaled: &JournaledPlan,
    authority: &mut impl Authority,
    journal: &mut impl ExchangeJournal,
) -> Result<Model> {
    let mut plan = journaled.plan.clone();
    plan.validate()?;
    validate_exchange(engines.scope(), &plan.expected, &plan.desired)?;
    require_journal(journal, &plan)?;
    let targets = [
        (SessionKind::DynamicPermits, plan.withdrawn.clone()),
        (SessionKind::StaticBase, plan.base.clone()),
        (SessionKind::DynamicPermits, plan.desired.clone()),
    ];
    let outcome = (|| {
        require_snapshot(&engines.snapshot()?, &plan.expected.expected)?;
        let mut before = plan.expected.clone();
        for (step, (kind, target)) in targets.into_iter().enumerate() {
            let after = target.inherit_sublayer_weight(&before)?;
            validate_session_exchange(engines.scope(), &before, &after, kind)?;
            if step == 1 {
                authority.before_base(&before, &after)?;
            }
            if step == 2 {
                authority.before_install(&after)?;
            }
            require_journal(journal, &plan)?;
            let committed = engines.exchange(kind, &before, &after)?;
            let exact = after.readback_after(&before, &committed.expected)?;
            if exact != committed {
                return Err(GuardError::Conflict);
            }
            let previous_plan = plan.clone();
            let capture = !before.installed && committed.installed;
            if capture {
                plan.captured_sublayer_weight = committed.assigned_sublayer_weight;
                plan.base = plan.bound_candidate(&plan.base)?;
                plan.desired = plan.bound_candidate(&plan.desired)?;
                plan.validate()?;
            }
            require_snapshot(&engines.snapshot()?, &committed.expected)?;
            if capture {
                plan.persist(journal, Some(&previous_plan))?;
            }
            before = committed;
        }
        require_journal(journal, &plan)?;
        Ok(before)
    })();
    if let Err(error) = outcome {
        // A committed lost install ACK may leave allows. Close only the owned
        // dynamic session, never roll back bases or enumerate foreign objects.
        // Any uncertainty keeps exclusively held ports and cleanup obligations.
        engines
            .close_permits()
            .map_err(|_| GuardError::RemovalUnconfirmed)?;
        confirm_no_permits(engines, &plan)?;
        return Err(error);
    }
    outcome
}
fn require_journal(journal: &mut impl ExchangeJournal, plan: &ExchangePlan) -> Result<()> {
    let current = journal.load(&plan.expected.scope)?;
    if current.as_ref() != Some(plan) {
        return Err(GuardError::Conflict);
    }
    current.as_ref().ok_or(GuardError::Conflict)?.validate()
}
/// Must be freshly called under the serialized owner before socket release.
/// Snapshot bindings must be independently attested, not copied from the plan.
pub(crate) fn confirm_no_permits(
    engines: &mut impl SplitEngines,
    plan: &ExchangePlan,
) -> Result<Model> {
    plan.validate()?;
    if engines.scope() != &plan.expected.scope {
        return Err(GuardError::RemovalUnconfirmed);
    }
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
                .any(|(i, key)| i % 24 >= 8 && *key == f.key)
    }) {
        return Err(GuardError::RemovalUnconfirmed);
    }
    // No-permit reconciliation uses exact base states rather than the original
    // permit-bearing expected/desired states (same fixed ownership universe).
    for candidate in [&plan.expected, &plan.withdrawn, &plan.base, &plan.desired] {
        let base = plan.bound_candidate(candidate)?.without_permits()?;
        let matched = require_snapshot(&actual, &base.expected).map(|_| base);
        if let Ok(model) = matched {
            return Ok(model);
        }
    }
    Err(GuardError::RemovalUnconfirmed)
}

#[cfg(test)]
#[path = "member_carrier_guard_tests.rs"]
mod tests;
