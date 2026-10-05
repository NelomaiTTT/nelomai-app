//! Complete durable IPv4 row metadata and storage transition contract. No native authority.
#![allow(dead_code)] // Factory remains disconnected; host tests use the protected store.
use nelomai_client_tunnel::redundancy::SessionScope;
use nelomai_contracts::dispatcher::EngineIdentity;
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RowKey {
    pub luid: u64,
    pub index: u32,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AddressPolicy {
    pub address: [u8; 4],
    pub prefix_origin: i32,
    pub suffix_origin: i32,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub on_link_prefix_length: u8,
    pub skip_as_source: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AddressObserved {
    pub dad_state: i32,
    pub scope_id: u32,
    pub creation_timestamp: i64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AddressRow {
    pub key: RowKey,
    pub policy: AddressPolicy,
    pub observed: AddressObserved,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InterfacePolicy {
    pub advertising: bool,
    pub forwarding: bool,
    pub weak_host_send: bool,
    pub weak_host_receive: bool,
    pub automatic_metric: bool,
    pub neighbor_unreachability: bool,
    pub managed_address_configuration: bool,
    pub other_stateful_configuration: bool,
    pub advertise_default_route: bool,
    pub router_discovery: i32,
    pub dad_transmits: u32,
    pub base_reachable_time: u32,
    pub retransmit_time: u32,
    pub path_mtu_discovery_timeout: u32,
    pub link_local_behavior: i32,
    pub link_local_timeout: u32,
    pub zone_indices: [u32; 16],
    // Exact IPv4 Get value retained in snapshots/CAS. Set requires zero input
    // for this nonmodifiable field; its sentinel never replaces this value.
    pub site_prefix_length: u32,
    pub metric: u32,
    pub mtu: u32,
    pub disable_default_routes: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InterfaceObserved {
    pub max_reassembly_size: u32,
    pub interface_identifier: u64,
    pub min_router_advertisement_interval: u32,
    pub max_router_advertisement_interval: u32,
    pub connected: bool,
    pub supports_wake_up_patterns: bool,
    pub supports_neighbor_discovery: bool,
    pub supports_router_discovery: bool,
    pub reachable_time: u32,
    pub transmit_offload: u8,
    pub receive_offload: u8,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InterfaceRow {
    pub key: RowKey,
    pub policy: InterfacePolicy,
    pub observed: InterfaceObserved,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum Error {
    #[error("carrier_rows_unsupported")]
    Unsupported,
    #[error("carrier_rows_conflict")]
    Conflict,
    #[error("carrier_rows_pending")]
    Pending,
    #[error("carrier_rows_native")]
    Native,
    #[error("carrier_rows_journal")]
    Journal,
    #[error("carrier_rows_invalid")]
    Invalid,
    #[error("carrier_rows_retired")]
    Retired,
}
pub(crate) type Result<T> = std::result::Result<T, Error>;
impl RowKey {
    pub(crate) fn validate(self) -> Result<()> {
        if self.luid == 0 || self.index == 0 {
            Err(Error::Invalid)
        } else {
            Ok(())
        }
    }
}
impl AddressPolicy {
    pub(crate) fn validate(&self) -> Result<()> {
        let ip = std::net::Ipv4Addr::from(self.address);
        if ip.is_unspecified()
            || ip.is_multicast()
            || ip.is_broadcast()
            || ip.is_loopback()
            || !(0..=4).contains(&self.prefix_origin)
            || !(0..=5).contains(&self.suffix_origin)
            || self.on_link_prefix_length > 32
            || self.preferred_lifetime > self.valid_lifetime
        {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
    pub(crate) fn validate_creation(&self) -> Result<()> {
        self.validate()?;
        if self.prefix_origin != 1
            || self.suffix_origin != 1
            || self.on_link_prefix_length != 32
            || self.skip_as_source
            || self.valid_lifetime != u32::MAX
            || self.preferred_lifetime != u32::MAX
        {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
}
impl InterfacePolicy {
    pub(crate) fn validate(&self) -> Result<()> {
        if !(0..=2).contains(&self.router_discovery)
            || !(0..=2).contains(&self.link_local_behavior)
            || self.metric > 0x7fffffff
            || self.mtu < 68
            || (self.site_prefix_length > 32
                && self.site_prefix_length != 64
                && self.site_prefix_length != 255)
        {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
}
pub(crate) fn validate_interface_delta(
    before: &InterfacePolicy,
    after: &InterfacePolicy,
) -> Result<()> {
    before.validate()?;
    after.validate()?;
    // This sidecar owns weak-host only; all other policy metadata participates
    // in exact CAS and is preserved, including nonmodifiable SitePrefixLength.
    // Forwarding/DHCP/metric/MTU/zone edits need a
    // separate future owner contract, not silently widened permissions.
    let mut permitted = before.clone();
    permitted.weak_host_send = after.weak_host_send;
    permitted.weak_host_receive = after.weak_host_receive;
    if permitted != *after || !matches!(after.site_prefix_length, 0 | 64) {
        return Err(Error::Unsupported);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum Role {
    Carrier,
    MemberA,
    MemberB,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binding {
    pub scope: SessionScope,
    pub boot_id: [u8; 16],
    pub runtime: EngineIdentity,
    pub network_epoch: u64,
    pub role: Role,
    pub guid: [u8; 16],
    pub name: String,
    pub key: RowKey,
    pub address: [u8; 4],
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    pub interface: InterfaceRow,
    #[serde(deserialize_with = "required_optional")]
    pub address: Option<AddressRow>,
}
fn required_optional<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> std::result::Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", deny_unknown_fields)]
pub(crate) enum Target {
    Interface(InterfacePolicy),
    Create(AddressPolicy),
    Delete,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Pending {
    pub before: Snapshot,
    pub target: Target,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum Phase {
    Captured,
    Closing,
    Stopped,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct Record {
    pub version: u32,
    pub domain: String,
    pub binding: Binding,
    pub revision: u64,
    pub phase: Phase,
    pub baseline: Snapshot,
    pub current: Snapshot,
    pub pending: Option<Pending>,
    pub creation: Option<AddressRow>,
}
pub(crate) const DOMAIN: &str = "carrier-native-ipv4-rows-v1";
const MAX_BYTES: usize = 65536;
impl Binding {
    pub(crate) fn validate(&self) -> Result<()> {
        self.key.validate()?;
        let runtime = &self.runtime;
        if !self.scope.validate()
            || runtime.slot != self.scope.runtime
            || self.boot_id == [0; 16]
            || self.network_epoch == 0
            || self.guid == [0; 16]
            || self.name.is_empty()
            || self.name.len() > 128
            || self.name.chars().any(|c| c.is_control())
            || runtime.runtime_version.is_empty()
            || runtime.container_version.is_empty()
            || runtime.runtime_contract_version == 0
            || runtime.manifest_sha256.len() != 64
            || !runtime
                .manifest_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Invalid);
        }
        let ip = std::net::Ipv4Addr::from(self.address);
        if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() || ip.is_loopback() {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
impl Snapshot {
    pub(crate) fn validate(&self, binding: &Binding) -> Result<()> {
        if self.interface.key != binding.key
            || self.interface.observed.max_reassembly_size != 0
            || self.interface.observed.interface_identifier != 0
        {
            return Err(Error::Conflict);
        }
        self.interface.policy.validate()?;
        if let Some(a) = &self.address {
            a.key.validate()?;
            a.policy.validate()?;
            if a.key != binding.key
                || a.policy.address != binding.address
                || !(0..=4).contains(&a.observed.dad_state)
                || a.observed.creation_timestamp < 0
            {
                return Err(Error::Conflict);
            }
        }
        Ok(())
    }
}
pub(crate) fn same_address(a: &AddressRow, b: &AddressRow) -> bool {
    a.key == b.key
        && a.policy == b.policy
        && a.observed.scope_id == b.observed.scope_id
        && a.observed.creation_timestamp == b.observed.creation_timestamp
}
/// Kernel readonly capability/timer/DAD changes remain observable, not writable
/// CAS fields. Address scope+creation stamp remain ownership/replacement fences.
pub(crate) fn same_owned(a: &Snapshot, b: &Snapshot) -> bool {
    a.interface.key == b.interface.key
        && a.interface.policy == b.interface.policy
        && match (&a.address, &b.address) {
            (None, None) => true,
            (Some(a), Some(b)) => same_address(a, b),
            _ => false,
        }
}
impl Record {
    pub(crate) fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        if self.version != 1 || self.domain != DOMAIN || self.revision == 0 {
            return Err(Error::Invalid);
        }
        self.baseline.validate(&self.binding)?;
        self.current.validate(&self.binding)?;
        if self.baseline.address.is_some() {
            return Err(Error::Invalid);
        }
        if self.phase == Phase::Captured
            && self.creation.is_some()
            && self.current.address.is_none()
        {
            return Err(Error::Invalid);
        }
        if let Some(c) = &self.creation {
            c.policy.validate_creation()?;
            if c.key != self.binding.key
                || c.policy.address != self.binding.address
                || c.observed.creation_timestamp <= 0
                || !(0..=4).contains(&c.observed.dad_state)
                || self.binding.role != Role::Carrier
            {
                return Err(Error::Invalid);
            }
            if let Some(a) = &self.current.address {
                if !same_address(a, c) {
                    return Err(Error::Conflict);
                }
            }
        } else if self.current.address.is_some() {
            return Err(Error::Invalid);
        }
        // No writable drift outside this sidecar's weak-host delta even in journals.
        let mut permitted = self.baseline.interface.policy.clone();
        permitted.weak_host_send = self.current.interface.policy.weak_host_send;
        permitted.weak_host_receive = self.current.interface.policy.weak_host_receive;
        if permitted != self.current.interface.policy {
            return Err(Error::Conflict);
        }
        if let Some(p) = &self.pending {
            if p.before != self.current {
                return Err(Error::Invalid);
            }
            match &p.target {
                Target::Interface(policy) => {
                    validate_interface_delta(&self.current.interface.policy, policy)?;
                    if self.phase == Phase::Closing && *policy != self.baseline.interface.policy {
                        return Err(Error::Retired);
                    }
                }
                Target::Create(policy) => {
                    policy.validate_creation()?;
                    if self.binding.role != Role::Carrier
                        || self.current.address.is_some()
                        || self.creation.is_some()
                        || policy.address != self.binding.address
                    {
                        return Err(Error::Invalid);
                    }
                }
                Target::Delete => {
                    if self.phase != Phase::Closing
                        || self.current.address.is_none()
                        || self.creation.is_none()
                    {
                        return Err(Error::Invalid);
                    }
                }
            }
        }
        if self.phase == Phase::Stopped
            && (self.pending.is_some()
                || self.current.address.is_some()
                || self.current.interface.policy != self.baseline.interface.policy)
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| Error::Invalid)?;
        if bytes.len() > MAX_BYTES {
            return Err(Error::Invalid);
        }
        Ok(bytes)
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::Invalid);
        }
        serde_json::from_slice(bytes).map_err(|_| Error::Invalid)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRecord {
    version: u32,
    domain: String,
    binding: Binding,
    revision: u64,
    phase: Phase,
    baseline: Snapshot,
    current: Snapshot,
    #[serde(deserialize_with = "required_optional")]
    pending: Option<Pending>,
    #[serde(deserialize_with = "required_optional")]
    creation: Option<AddressRow>,
}
impl<'de> Deserialize<'de> for Record {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let r = WireRecord::deserialize(d)?;
        let record = Self {
            version: r.version,
            domain: r.domain,
            binding: r.binding,
            revision: r.revision,
            phase: r.phase,
            baseline: r.baseline,
            current: r.current,
            pending: r.pending,
            creation: r.creation,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}
pub(crate) trait Journal {
    /// Protected implementations must bind the full authenticated scope,
    /// runtime/boot/network epoch and fresh-vs-cleanup permission independently
    /// of JSON; fixed namespace and existing SessionFiles protections only.
    fn load(&mut self, binding: &Binding) -> Result<Option<Record>>;
    /// Exact protected durable CAS; an error may be committed/lost ACK. Owner
    /// always rereads. A failed fresh CAS must revoke its live/shared permission;
    /// that live reread must fail rather than authorizing another native effect.
    /// Only a separately opened cleanup view may reconcile an exact lost ACK.
    /// No std::fs implementation or store bypass in this module.
    fn compare_exchange(
        &mut self,
        binding: &Binding,
        expected: Option<&Record>,
        desired: &Record,
    ) -> Result<()>;
}

/// Strict per-revision storage firewall; bytes/ownership are independently checked by the store.
pub(crate) fn validate_transition(
    old: Option<&Record>,
    next: &Record,
    cleanup: bool,
) -> Result<()> {
    next.validate()?;
    let Some(old) = old else {
        return if !cleanup
            && next.revision == 1
            && next.phase == Phase::Captured
            && next.current == next.baseline
            && next.pending.is_none()
            && next.creation.is_none()
        {
            Ok(())
        } else {
            Err(Error::Retired)
        };
    };
    old.validate()?;
    if old == next {
        return Ok(());
    } // Exact storage idempotence grants no native effect.
    if old.binding != next.binding
        || old.baseline != next.baseline
        || old.revision.checked_add(1) != Some(next.revision)
        || old.phase == Phase::Stopped
        || (old.creation.is_some() && old.creation != next.creation)
    {
        return Err(Error::Conflict);
    }
    if cleanup && next.phase == Phase::Captured {
        return Err(Error::Retired);
    }
    match (old.phase, next.phase) {
        (Phase::Captured, Phase::Captured) | (Phase::Closing, Phase::Closing) => {}
        (Phase::Captured, Phase::Closing) => {}
        (Phase::Closing, Phase::Stopped) => {
            return if old.pending.is_none()
                && same_owned(&old.current, &next.current)
                && old.creation == next.creation
            {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        _ => return Err(Error::Retired),
    }
    match (&old.pending, &next.pending) {
        (None, None) => {
            if !same_owned(&old.current, &next.current) || old.creation != next.creation {
                return Err(Error::Conflict);
            }
        }
        (None, Some(p)) => {
            if old.phase != next.phase
                || !same_owned(&old.current, &next.current)
                || old.creation != next.creation
            {
                return Err(Error::Conflict);
            }
            match &p.target {
                Target::Interface(_) if next.phase == Phase::Captured && !cleanup => {}
                Target::Interface(policy)
                    if next.phase == Phase::Closing
                        && *policy == next.baseline.interface.policy => {}
                Target::Create(_) if next.phase == Phase::Captured && !cleanup => {}
                Target::Delete if next.phase == Phase::Closing => {}
                _ => return Err(Error::Retired),
            }
        }
        (Some(p), None) => {
            match &p.target {
                Target::Interface(policy) => {
                    let mut target = p.before.clone();
                    target.interface.policy = policy.clone();
                    if (!same_owned(&next.current, &p.before)
                        && !same_owned(&next.current, &target))
                        || old.creation != next.creation
                    {
                        return Err(Error::Conflict);
                    }
                }
                Target::Create(policy) => {
                    // Even exact current/pending readback cannot reconstruct a
                    // live creator/create ACK. Cleanup may NEVER add history.
                    if cleanup
                        || old.phase != Phase::Captured
                        || next.phase != Phase::Captured
                        || next.current.interface.key != p.before.interface.key
                        || next.current.interface.policy != p.before.interface.policy
                        || next
                            .current
                            .address
                            .as_ref()
                            .is_none_or(|a| a.policy != *policy)
                        || next.creation != next.current.address
                    {
                        return Err(Error::Retired);
                    }
                }
                Target::Delete => {
                    let mut target = p.before.clone();
                    target.address = None;
                    if old.phase != Phase::Closing
                        || next.phase != Phase::Closing
                        || (!same_owned(&next.current, &p.before)
                            && !same_owned(&next.current, &target))
                        || old.creation != next.creation
                    {
                        return Err(Error::Conflict);
                    }
                }
            }
        }
        (Some(a), Some(b)) => {
            // Only a phase fence may carry exactly the same unresolved intent.
            if old.phase != Phase::Captured
                || next.phase != Phase::Closing
                || a != b
                || old.current != next.current
                || old.creation != next.creation
            {
                return Err(Error::Conflict);
            }
        }
    }
    Ok(())
}
