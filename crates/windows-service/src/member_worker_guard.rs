//! Single-TUN policy. Slots are crypto devices, never fabricated OS interfaces.
use crate::{
    member_carrier_guard::{
        Action, Condition, Filter, GuardError, Key, Layer, ResourceKeys, Result, Snapshot, Sublayer,
    },
    member_owner::InterfaceProof,
};
use nelomai_client_tunnel::redundancy::SessionScope;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::IpAddr;

pub(crate) const VERSION: u32 = 1;
pub(crate) fn keys(scope: &SessionScope) -> Result<ResourceKeys> {
    if !scope.validate() {
        return Err(GuardError::Invalid);
    }
    let key = |purpose: &[u8]| {
        let mut hash = Sha256::new();
        hash.update(b"nelomai-worker-guard/v1\0");
        hash.update(
            [if scope.runtime == nelomai_contracts::RuntimeSlot::Stable {
                0
            } else {
                1
            }],
        );
        hash.update(scope.runtime_generation.to_be_bytes());
        hash.update(scope.session_id.as_bytes());
        hash.update(scope.connection_generation.to_be_bytes());
        hash.update(purpose);
        let mut bytes: [u8; 16] = hash.finalize()[..16].try_into().expect("SHA256 prefix");
        bytes[6] = (bytes[6] & 15) | 128;
        bytes[8] = (bytes[8] & 63) | 128;
        Key(bytes)
    };
    Ok(ResourceKeys {
        sublayer: key(b"sublayer"),
        filters: std::array::from_fn(|i| key(&[b'f', i as u8])),
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Model {
    pub version: u32,
    pub scope: SessionScope,
    pub interface: Option<InterfaceProof>,
    pub source: Option<IpAddr>,
    pub admitted: bool,
    pub weight: Option<u16>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plan {
    pub expected: Model,
    pub withdrawn: Model,
    pub base: Model,
    pub desired: Model,
}
impl Plan {
    pub(crate) fn new(expected: Model, desired: Model) -> Result<Self> {
        expected.snapshot()?;
        desired.snapshot()?;
        if expected.scope != desired.scope {
            return Err(GuardError::Conflict);
        }
        let mut withdrawn = expected.clone();
        withdrawn.admitted = false;
        let mut base = desired.clone();
        base.admitted = false;
        Ok(Self {
            expected,
            withdrawn,
            base,
            desired,
        })
    }
    pub(crate) fn bind_created_weight(&mut self, weight: u16) -> Result<()> {
        if self.expected.interface.is_some() || self.base.interface.is_none() {
            return Err(GuardError::Conflict);
        }
        self.base.weight = Some(weight);
        self.desired.weight = Some(weight);
        Ok(())
    }
}
impl Model {
    pub(crate) fn empty(scope: SessionScope) -> Self {
        Self {
            version: VERSION,
            scope,
            interface: None,
            source: None,
            admitted: false,
            weight: None,
        }
    }
    pub(crate) fn snapshot(&self) -> Result<Snapshot> {
        let keys = keys(&self.scope)?;
        if self.version != VERSION {
            return Err(GuardError::Invalid);
        }
        let mut snapshot = Snapshot {
            version: 2,
            scope: self.scope.clone(),
            carrier: None,
            egress: [None, None],
            sublayer: None,
            filters: vec![],
        };
        let Some(p) = self.interface else {
            if self.source.is_some() || self.admitted || self.weight.is_some() {
                return Err(GuardError::Invalid);
            }
            return Ok(snapshot);
        };
        let source = self.source.ok_or(GuardError::Invalid)?;
        if p.index == 0
            || p.luid == 0
            || p.guid == [0; 16]
            || source.is_unspecified()
            || source.is_loopback()
            || source.is_multicast()
        {
            return Err(GuardError::Invalid);
        }
        snapshot.sublayer = Some(Sublayer {
            key: keys.sublayer,
            weight: self.weight.unwrap_or(65534),
            flags: 0,
        });
        for n in 0..8 {
            let layer = [
                Layer::TransportV4,
                Layer::PacketV4,
                Layer::ForwardV4,
                Layer::AleConnectV4,
                Layer::TransportV6,
                Layer::PacketV6,
                Layer::ForwardV6,
                Layer::AleConnectV6,
            ][n];
            use Condition::*;
            let deny = match n % 4 {
                0 | 1 => EgressIndex(p.index),
                2 => DestinationIndex(p.index),
                _ => NextHopIndex(p.index),
            };
            snapshot.filters.push(Filter {
                key: keys.filters[n],
                sublayer: keys.sublayer,
                layer,
                weight: 1,
                flags: 0,
                action: Action::Block,
                conditions: vec![deny],
            });
            // Single-TUN forwarding/raw endpoints are not an admitted app path.
            // No weak-host C→A/B forwarding machinery is enabled in this mode.
            if self.admitted && n % 4 != 2 && usize::from(source.is_ipv6()) == n / 4 {
                let mut conditions = match n % 4 {
                    0 => vec![
                        EgressIndex(p.index),
                        LocalInterface(p.luid),
                        NoneSetFlags(0x10),
                    ],
                    1 => vec![EgressIndex(p.index), LocalInterface(p.luid)],
                    _ => vec![
                        NextHopIndex(p.index),
                        NextHopLuid(p.luid),
                        LocalInterface(p.luid),
                    ],
                };
                conditions.push(SourceAddress(source));
                conditions.sort();
                snapshot.filters.push(Filter {
                    key: keys.filters[8 + n],
                    sublayer: keys.sublayer,
                    layer,
                    weight: 2,
                    flags: 0,
                    action: Action::Permit,
                    conditions,
                });
            }
        }
        snapshot.filters.sort_by_key(|f| f.key);
        Ok(snapshot)
    }
}
