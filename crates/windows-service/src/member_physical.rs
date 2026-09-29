//! Read-only physical path discovery. No source selection, route adoption,
//! policy planning or mutation authority. A snapshot is evidence of a read,
//! not a lock: the owner must reverify immediately before its own guarded CAS.
#![cfg_attr(not(windows), allow(dead_code))] // Portable fake tests have no native caller.

use crate::member_routes::{Row, MAX_TABLE_ROWS};
use nelomai_client_tunnel::redundancy::network::RouteScope;
use std::{collections::BTreeMap, net::IpAddr};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum Family {
    V4,
    V6,
}
impl Family {
    pub(crate) fn of(address: IpAddr) -> Self {
        if address.is_ipv4() {
            Self::V4
        } else {
            Self::V6
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InterfaceIdentity {
    pub index: u32,
    pub luid: u64,
    /// GUID in canonical/network byte order, not Windows struct memory order.
    pub guid: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PhysicalProof {
    pub identity: InterfaceIdentity,
    pub family: Family,
    /// Family-specific interface metric; route metric stays in the full Row.
    pub metric: u32,
}

/// Typed capture seam. Raw SDK classifications are retained so unknown kinds
/// cannot silently become a guessed Ethernet interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InterfaceRecord {
    pub proof: PhysicalProof,
    pub alias: String,
    pub if_type: u32,
    pub tunnel_type: i32,
    pub oper_status: i32,
    /// MIB_IF_ROW2 HardwareInterface/FilterInterface/.../EndPointInterface bits.
    pub status_flags: u8,
}
impl InterfaceRecord {
    fn physical(&self, owned: &[InterfaceIdentity]) -> bool {
        self.oper_status == 1 // IfOperStatusUp
            && self.tunnel_type == 0 // TUNNEL_TYPE_NONE
            && matches!(self.if_type, 6 | 71 | 243 | 244) // Ethernet/WiFi/WWAN, never PPP
            && self.status_flags & 1 != 0 // HardwareInterface required
            && self.status_flags & 0xfa == 0 // no filter, endpoint, or unusable media flags
            && !self.alias.trim().to_ascii_lowercase().starts_with("nelomai")
            && !owned.contains(&self.proof.identity)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum DiscoveryError {
    #[error("physical_discovery_invalid")]
    Invalid,
    #[error("physical_route_missing")]
    NoRoute,
    #[error("physical_route_ambiguous")]
    Ambiguous,
    #[error("physical_route_or_identity_changed")]
    Stale,
}
pub(crate) type Result<T> = std::result::Result<T, DiscoveryError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PhysicalRoute {
    pub proof: PhysicalProof,
    /// Exact retained metadata, NOT a rewritten static/adoptable row.
    pub row: Row,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedHost {
    pub destination: IpAddr,
    pub path: PhysicalRoute,
}
#[derive(Clone, Debug)]
pub(crate) struct PhysicalSnapshot {
    // All rows from BOTH families, including excluded interfaces. Accessors
    // borrow immutable data so callers cannot accidentally rewrite evidence.
    rows: Vec<Row>,
    proofs: BTreeMap<(Family, u32), PhysicalProof>,
}
impl PhysicalSnapshot {
    pub(crate) fn new(
        rows: Vec<Row>,
        interfaces: Vec<InterfaceRecord>,
        owned: &[InterfaceIdentity],
    ) -> Result<Self> {
        if interfaces.len() > MAX_TABLE_ROWS * 2 || owned.len() > MAX_TABLE_ROWS {
            return Err(DiscoveryError::Invalid);
        }
        let mut records = BTreeMap::new();
        let mut identities = BTreeMap::new();
        let mut luids = BTreeMap::new();
        let mut guids = BTreeMap::new();
        for record in interfaces {
            let proof = record.proof;
            let id = proof.identity;
            if id.index == 0
                || id.luid == 0
                || id.guid == [0; 16]
                || record.alias.len() > 1024
                || record.alias.contains('\0')
                || identities.insert(id.index, id).is_some_and(|old| old != id)
                || luids.insert(id.luid, id).is_some_and(|old| old != id)
                || guids.insert(id.guid, id).is_some_and(|old| old != id)
            {
                return Err(DiscoveryError::Invalid);
            }
            let key = (proof.family, id.index);
            if records.get(&key).is_some_and(|old| old != &record) {
                return Err(DiscoveryError::Invalid);
            }
            records.insert(key, record);
        }
        let mut counts = [0usize; 2];
        for row in &rows {
            let r = &row.route;
            let family = Family::of(r.destination.addr());
            counts[usize::from(family == Family::V6)] += 1;
            if counts.iter().any(|n| *n > MAX_TABLE_ROWS)
                || r.destination != r.destination.trunc()
                || r.scope != RouteScope::WindowsInterface(r.interface)
                || r.gateway.is_some_and(|g| {
                    Family::of(g) != family || g.is_unspecified() || g.is_multicast()
                })
                || records
                    .get(&(family, r.interface))
                    .is_none_or(|record| record.proof.identity.luid != row.luid)
            {
                return Err(DiscoveryError::Invalid);
            }
        }
        let proofs = records
            .into_iter()
            .filter(|(_, r)| r.physical(owned))
            .map(|(key, r)| (key, r.proof))
            .collect();
        Ok(Self { rows, proofs })
    }

    pub(crate) fn rows(&self) -> &[Row] {
        &self.rows
    }
    /// Exclude only exact rows backed by the enclosing owner's committed or
    /// pending journal. A foreign replacement at the same native key is an
    /// error, not an exclusion. Different interfaces retain independent rows.
    /// Multiple journal candidates at one key cover before/after CAS states;
    /// multiple ACTUAL rows at that key always fail closed.
    pub(crate) fn without_owned_rows(&self, owned: &[Row]) -> Result<Self> {
        if owned.len() > MAX_TABLE_ROWS * 2 {
            return Err(DiscoveryError::Invalid);
        }
        let mut by_key: BTreeMap<(ipnet::IpNet, u32), Vec<&Row>> = BTreeMap::new();
        for row in owned {
            let family = Family::of(row.route.destination.addr());
            let proof = self
                .proofs
                .get(&(family, row.route.interface))
                .ok_or(DiscoveryError::Stale)?;
            if proof.identity.luid != row.luid
                || row.route.destination != row.route.destination.trunc()
                || row.route.scope
                    != nelomai_client_tunnel::redundancy::network::RouteScope::WindowsInterface(
                        row.route.interface,
                    )
            {
                return Err(DiscoveryError::Stale);
            }
            by_key
                .entry((row.route.destination, row.route.interface))
                .or_default()
                .push(row);
        }
        for (key, candidates) in &by_key {
            let mut actual = self
                .rows
                .iter()
                .filter(|row| (row.route.destination, row.route.interface) == *key);
            if let Some(row) = actual.next() {
                if actual.next().is_some() || !candidates.contains(&row) {
                    return Err(DiscoveryError::Stale);
                }
            }
        }
        Ok(Self {
            rows: self
                .rows
                .iter()
                .filter(|row| !by_key.contains_key(&(row.route.destination, row.route.interface)))
                .cloned()
                .collect(),
            proofs: self.proofs.clone(),
        })
    }
    pub(crate) fn proofs(&self) -> &BTreeMap<(Family, u32), PhysicalProof> {
        &self.proofs
    }

    pub(crate) fn default_route(&self, family: Family) -> Result<Option<PhysicalRoute>> {
        self.select(family, |row| row.route.destination.prefix_len() == 0)
    }

    /// Resolve a physical bypass prefix, retaining the complete native evidence.
    /// An exact on-link LAN row is already scoped by Windows; unlike an endpoint,
    /// it can be multicast, broadcast or IPv6 link-local. Never invent a gateway
    /// or a zone for such a prefix. Endpoint callers must still use resolve_host.
    pub(crate) fn resolve_bypass(&self, destination: ipnet::IpNet) -> Result<PhysicalRoute> {
        if destination != destination.trunc() {
            return Err(DiscoveryError::Invalid);
        }
        let path = if destination.prefix_len() == 0 {
            self.default_route(Family::of(destination.addr()))?
                .ok_or(DiscoveryError::NoRoute)?
        } else {
            match self.resolve_host(destination.addr()) {
                Ok(host) => host.path,
                // Only non-host prefixes take this path. In particular, do not
                // hide ambiguous unicast routes or prefer on-link over a better
                // routed path. These rows will be retained, not newly installed.
                Err(DiscoveryError::Invalid) => self
                    .select(Family::of(destination.addr()), |row| {
                        row.route.destination == destination && row.route.gateway.is_none()
                    })?
                    .ok_or(DiscoveryError::Invalid)?,
                Err(error) => return Err(error),
            }
        };
        if !path.row.route.destination.contains(&destination) {
            return Err(DiscoveryError::Invalid);
        }
        Ok(path)
    }

    pub(crate) fn resolve_host(&self, destination: IpAddr) -> Result<ResolvedHost> {
        let invalid = destination.is_unspecified()
            || destination.is_multicast()
            || destination.is_loopback()
            || match destination {
                IpAddr::V4(ip) => ip.is_broadcast(),
                // No input scope: do not choose a zone for a link-local host.
                // Mapped-v4 and deprecated site-local are equally ambiguous here.
                IpAddr::V6(ip) => {
                    ip.is_unicast_link_local()
                        || ip.to_ipv4_mapped().is_some()
                        || ip.segments()[0] & 0xffc0 == 0xfec0
                }
            };
        if invalid {
            return Err(DiscoveryError::Invalid);
        }
        let path = self
            .select(Family::of(destination), |row| {
                row.route.destination.contains(&destination)
            })?
            .ok_or(DiscoveryError::NoRoute)?;
        Ok(ResolvedHost { destination, path })
    }

    fn select(
        &self,
        family: Family,
        matches: impl Fn(&Row) -> bool,
    ) -> Result<Option<PhysicalRoute>> {
        let mut best: Option<((u8, u64), PhysicalRoute)> = None;
        let mut ambiguous = false;
        for row in &self.rows {
            if Family::of(row.route.destination.addr()) != family
                || !matches(row)
                || row.flags[0] != 0
                || row.valid_lifetime == 0
            {
                continue;
            }
            let Some(proof) = self.proofs.get(&(family, row.route.interface)) else {
                continue;
            };
            // Smaller rank wins: longest prefix, then full non-wrapping sum.
            let rank = (
                128 - row.route.destination.prefix_len(),
                u64::from(row.route.metric) + u64::from(proof.metric),
            );
            let path = PhysicalRoute {
                proof: *proof,
                row: row.clone(),
            };
            match &best {
                None => {
                    best = Some((rank, path));
                    ambiguous = false;
                }
                Some((old_rank, _)) if rank < *old_rank => {
                    best = Some((rank, path));
                    ambiguous = false;
                }
                Some((old_rank, old)) if rank == *old_rank && *old != path => ambiguous = true,
                _ => {}
            }
        }
        if ambiguous {
            return Err(DiscoveryError::Ambiguous);
        }
        Ok(best.map(|(_, path)| path))
    }

    /// Compare against a FRESH capture, never against the original snapshot at
    /// write time. Proves retained identity/metric/metadata still exist, not that
    /// no higher-priority route appeared. Selection must be repeated separately.
    pub(crate) fn verify(&self, expected: &PhysicalRoute) -> Result<()> {
        let proof = expected.proof;
        if self.proofs.get(&(proof.family, proof.identity.index)) != Some(&proof)
            || expected.row.route.interface != proof.identity.index
            || expected.row.luid != proof.identity.luid
            || Family::of(expected.row.route.destination.addr()) != proof.family
            || !self.rows.contains(&expected.row)
        {
            return Err(DiscoveryError::Stale);
        }
        Ok(())
    }
}
