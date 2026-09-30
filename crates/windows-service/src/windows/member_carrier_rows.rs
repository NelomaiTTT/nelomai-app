//! Full native IPv4 rows, deliberately disconnected from the production factory.
#![allow(dead_code)]
pub(crate) use crate::member_carrier_rows::*;
use nelomai_client_tunnel::redundancy::SessionScope;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use windows_sys::Win32::{NetworkManagement::IpHelper::*, Networking::WinSock::*};

/// Timing only: implementations confer no creator, journal or native authority.
pub(crate) trait ReadinessClock {
    fn now(&mut self) -> Instant;
    fn sleep(&mut self, duration: Duration, cancelled: &AtomicBool);
}

struct MonotonicClock;
impl ReadinessClock for MonotonicClock {
    fn now(&mut self) -> Instant {
        Instant::now()
    }
    fn sleep(&mut self, duration: Duration, cancelled: &AtomicBool) {
        if !cancelled.load(Ordering::Acquire) {
            std::thread::sleep(duration);
        }
    }
}
pub(crate) fn address_status(status: u32) -> Result<bool> {
    match status {
        0 => Ok(true),
        1168 => Ok(false),
        _ => Err(Error::Native),
    }
}
fn guid_bytes(g: &windows_sys::core::GUID) -> [u8; 16] {
    let mut b = [0; 16];
    b[..4].copy_from_slice(&g.data1.to_be_bytes());
    b[4..6].copy_from_slice(&g.data2.to_be_bytes());
    b[6..8].copy_from_slice(&g.data3.to_be_bytes());
    b[8..].copy_from_slice(&g.data4);
    b
}
pub(crate) fn decode_identity(row: &MIB_IF_ROW2) -> Result<NativeIdentity> {
    let key = RowKey {
        luid: unsafe { row.InterfaceLuid.Value },
        index: row.InterfaceIndex,
    };
    key.validate()?;
    let end = row
        .Alias
        .iter()
        .position(|c| *c == 0)
        .ok_or(Error::Unsupported)?;
    let name = String::from_utf16(&row.Alias[..end]).map_err(|_| Error::Unsupported)?;
    let guid = guid_bytes(&row.InterfaceGuid);
    if guid == [0; 16]
        || name.is_empty()
        || name.len() > 128
        || name.chars().any(|c| c.is_control())
        || row.Type != 53
        // Known Hardware/Filter/EndPoint roles are unsupported here. These are
        // SDK bits, not invented flags; readiness/power bits remain observations.
        || row.InterfaceAndOperStatusFlags._bitfield & 0x83 != 0
    {
        return Err(Error::Unsupported);
    }
    Ok(NativeIdentity {
        key,
        guid,
        name,
        if_type: row.Type,
        hardware: false,
    })
}
pub(crate) fn decode_address(r: &MIB_UNICASTIPADDRESS_ROW) -> Result<AddressRow> {
    // Read only the family-selected SDK union arm, never padding/inactive bytes.
    if unsafe { r.Address.si_family } != AF_INET {
        return Err(Error::Unsupported);
    }
    let (addr, luid, scope) = unsafe {
        (
            r.Address.Ipv4,
            r.InterfaceLuid.Value,
            r.ScopeId.Anonymous.Value,
        )
    };
    if addr.sin_port != 0 || addr.sin_zero != [0; 8] {
        return Err(Error::Unsupported);
    }
    let row = AddressRow {
        key: RowKey {
            luid,
            index: r.InterfaceIndex,
        },
        policy: AddressPolicy {
            address: unsafe { addr.sin_addr.S_un.S_addr }.to_ne_bytes(),
            prefix_origin: r.PrefixOrigin,
            suffix_origin: r.SuffixOrigin,
            valid_lifetime: r.ValidLifetime,
            preferred_lifetime: r.PreferredLifetime,
            on_link_prefix_length: r.OnLinkPrefixLength,
            skip_as_source: r.SkipAsSource,
        },
        observed: AddressObserved {
            dad_state: r.DadState,
            scope_id: scope,
            creation_timestamp: r.CreationTimeStamp,
        },
    };
    row.key.validate()?;
    row.policy.validate()?;
    if !(0..=4).contains(&row.observed.dad_state) || row.observed.creation_timestamp < 0 {
        return Err(Error::Unsupported);
    }
    Ok(row)
}
pub(crate) fn decode_interface(r: &MIB_IPINTERFACE_ROW) -> Result<InterfaceRow> {
    if r.Family != AF_INET || r.MaxReassemblySize != 0 || r.InterfaceIdentifier != 0 {
        return Err(Error::Unsupported);
    }
    let row = InterfaceRow {
        key: RowKey {
            luid: unsafe { r.InterfaceLuid.Value },
            index: r.InterfaceIndex,
        },
        policy: InterfacePolicy {
            advertising: r.AdvertisingEnabled,
            forwarding: r.ForwardingEnabled,
            weak_host_send: r.WeakHostSend,
            weak_host_receive: r.WeakHostReceive,
            automatic_metric: r.UseAutomaticMetric,
            neighbor_unreachability: r.UseNeighborUnreachabilityDetection,
            managed_address_configuration: r.ManagedAddressConfigurationSupported,
            other_stateful_configuration: r.OtherStatefulConfigurationSupported,
            advertise_default_route: r.AdvertiseDefaultRoute,
            router_discovery: r.RouterDiscoveryBehavior,
            dad_transmits: r.DadTransmits,
            base_reachable_time: r.BaseReachableTime,
            retransmit_time: r.RetransmitTime,
            path_mtu_discovery_timeout: r.PathMtuDiscoveryTimeout,
            link_local_behavior: r.LinkLocalAddressBehavior,
            link_local_timeout: r.LinkLocalAddressTimeout,
            zone_indices: r.ZoneIndices,
            site_prefix_length: r.SitePrefixLength,
            metric: r.Metric,
            mtu: r.NlMtu,
            disable_default_routes: r.DisableDefaultRoutes,
        },
        observed: InterfaceObserved {
            max_reassembly_size: r.MaxReassemblySize,
            interface_identifier: r.InterfaceIdentifier,
            min_router_advertisement_interval: r.MinRouterAdvertisementInterval,
            max_router_advertisement_interval: r.MaxRouterAdvertisementInterval,
            connected: r.Connected,
            supports_wake_up_patterns: r.SupportsWakeUpPatterns,
            supports_neighbor_discovery: r.SupportsNeighborDiscovery,
            supports_router_discovery: r.SupportsRouterDiscovery,
            reachable_time: r.ReachableTime,
            transmit_offload: r.TransmitOffload._bitfield,
            receive_offload: r.ReceiveOffload._bitfield,
        },
    };
    row.key.validate()?;
    row.policy.validate()?;
    Ok(row)
}
/// Caller passes a row from InitializeUnicastIpAddressEntry, NOT a saved raw blob.
pub(crate) fn address_input(
    mut r: MIB_UNICASTIPADDRESS_ROW,
    k: RowKey,
    p: &AddressPolicy,
) -> Result<MIB_UNICASTIPADDRESS_ROW> {
    k.validate()?;
    p.validate()?;
    r.Address.Ipv4 = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes(p.address),
            },
        },
        sin_zero: [0; 8],
    };
    r.InterfaceLuid.Value = k.luid;
    r.InterfaceIndex = k.index;
    r.PrefixOrigin = p.prefix_origin;
    r.SuffixOrigin = p.suffix_origin;
    r.ValidLifetime = p.valid_lifetime;
    r.PreferredLifetime = p.preferred_lifetime;
    r.OnLinkPrefixLength = p.on_link_prefix_length;
    r.SkipAsSource = p.skip_as_source;
    // Never pass Preferred (Windows 10 optimistic DAD override), including if
    // Initialize supplied it. No saved observed DAD/scope/timestamp grants writes.
    r.DadState = 0;
    r.ScopeId.Anonymous.Value = 0;
    r.CreationTimeStamp = 0;
    Ok(r)
}
/// All writable inputs are assigned explicitly after Initialize. Fields ignored
/// by Set remain initializer values, not copied historical readonly metadata.
pub(crate) fn interface_input(
    mut r: MIB_IPINTERFACE_ROW,
    k: RowKey,
    p: &InterfacePolicy,
) -> Result<MIB_IPINTERFACE_ROW> {
    k.validate()?;
    p.validate()?;
    // MS docs REQUIRE zero for IPv4. Do not normalize an unsupported baseline
    // (including 255) behind the journal's back: capability fails before mutation.
    if p.site_prefix_length != 0 {
        return Err(Error::Unsupported);
    }
    r.Family = AF_INET;
    r.InterfaceLuid.Value = k.luid;
    r.InterfaceIndex = k.index;
    r.AdvertisingEnabled = p.advertising;
    r.ForwardingEnabled = p.forwarding;
    r.WeakHostSend = p.weak_host_send;
    r.WeakHostReceive = p.weak_host_receive;
    r.UseAutomaticMetric = p.automatic_metric;
    r.UseNeighborUnreachabilityDetection = p.neighbor_unreachability;
    r.ManagedAddressConfigurationSupported = p.managed_address_configuration;
    r.OtherStatefulConfigurationSupported = p.other_stateful_configuration;
    r.AdvertiseDefaultRoute = p.advertise_default_route;
    r.RouterDiscoveryBehavior = p.router_discovery;
    r.DadTransmits = p.dad_transmits;
    r.BaseReachableTime = p.base_reachable_time;
    r.RetransmitTime = p.retransmit_time;
    r.PathMtuDiscoveryTimeout = p.path_mtu_discovery_timeout;
    r.LinkLocalAddressBehavior = p.link_local_behavior;
    r.LinkLocalAddressTimeout = p.link_local_timeout;
    r.ZoneIndices = p.zone_indices;
    r.SitePrefixLength = p.site_prefix_length;
    r.Metric = p.metric;
    r.NlMtu = p.mtu;
    r.DisableDefaultRoutes = p.disable_default_routes;
    Ok(r)
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LiveOwner {
    pub binding: Binding,
    pub challenge: u64,
}
/// Implement ONLY on a retained original native creator capability. Fresh query
/// verifies scope/runtime/boot/epoch/name/GUID/LUID/index and retained ownership,
/// not numeric equality, JSON, reopening a name, or a successful default.
pub(crate) trait OriginalCreator {
    /// Must independently query retained Wintun/member owner capability, the
    /// actual current privileged runtime/boot/epoch and full native identity.
    /// Neither the requested scope nor challenge nor any saved Binding is proof.
    fn query(&mut self, scope: &SessionScope, role: Role, challenge: u64) -> Result<LiveOwner>;
    /// Under the same verified lock: verify the original creator is still live,
    /// its native/session context matches, and guard/lifecycle authorization
    /// permits THIS exact effect. This does not grant adoption on address readback.
    fn authorize(&mut self, binding: &Binding, operation: &Target) -> Result<()>;
}
/// Must verify actual privileged process-wide serialization and keep the real
/// lock AND original creator borrow across the entire callback. No default.
pub(crate) trait Authority {
    type Creator: OriginalCreator;
    fn locked<T>(&mut self, action: impl FnOnce(&mut Self::Creator) -> Result<T>) -> Result<T>;
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeIdentity {
    pub key: RowKey,
    pub guid: [u8; 16],
    pub name: String,
    pub if_type: u32,
    pub hardware: bool,
}
/// Only the raw OS boundary may be faked. Native methods are private to the
/// serialized row owner. Errors are not absence; writes may lose an ACK.
pub(crate) trait Kernel {
    fn identity(&mut self, key: RowKey) -> Result<NativeIdentity>;
    fn interface(&mut self, key: RowKey) -> Result<MIB_IPINTERFACE_ROW>;
    fn address(
        &mut self,
        key: RowKey,
        address: [u8; 4],
    ) -> Result<Option<MIB_UNICASTIPADDRESS_ROW>>;
    fn initialize_interface(&mut self) -> MIB_IPINTERFACE_ROW;
    fn initialize_address(&mut self) -> MIB_UNICASTIPADDRESS_ROW;
    fn set_interface(&mut self, row: &mut MIB_IPINTERFACE_ROW) -> Result<()>;
    fn create_address(&mut self, row: &MIB_UNICASTIPADDRESS_ROW) -> Result<()>;
    fn delete_address(&mut self, row: &MIB_UNICASTIPADDRESS_ROW) -> Result<()>;
}
use std::sync::atomic::AtomicU64;
static CHALLENGE: AtomicU64 = AtomicU64::new(1);
fn challenge() -> Result<u64> {
    CHALLENGE
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
        .map_err(|_| Error::Retired)
}
pub(crate) struct RowOwner<A, K, J> {
    authority: A,
    state: OwnedRows<K, J>,
}
struct OwnedRows<K, J> {
    binding: Binding,
    kernel: K,
    journal: J,
    record: Record,
    failed: bool,
    // Non-serializable live history. Set ONLY from this actual acknowledged create
    // + immediate exact readback. No constructor imports it from a durable record.
    creation: Option<CreatedAddressReceipt>,
}
// No Clone/Serialize/Deserialize/import constructor. This receipt records a
// successful invocation + immediate exact readback in THIS owner; the original
// native creator capability is independently borrowed for every use as well.
struct CreatedAddressReceipt {
    row: AddressRow,
}
fn read<C: OriginalCreator, K: Kernel>(
    creator: &mut C,
    kernel: &mut K,
    binding: &Binding,
) -> Result<Snapshot> {
    let before_challenge = challenge()?;
    let live = creator.query(&binding.scope, binding.role, before_challenge)?;
    if live.binding != *binding || live.challenge != before_challenge {
        return Err(Error::Conflict);
    }
    let id = kernel.identity(binding.key)?;
    if id.key != binding.key
        || id.guid != binding.guid
        || id.name != binding.name
        || id.hardware
        || id.if_type != 53
    {
        return Err(Error::Conflict);
    }
    let snapshot = Snapshot {
        interface: decode_interface(&kernel.interface(binding.key)?)?,
        address: kernel
            .address(binding.key, binding.address)?
            .as_ref()
            .map(decode_address)
            .transpose()?,
    };
    snapshot.validate(binding)?;
    // The lock serializes our owners, not PnP or the OS. Requery after native
    // reads so stale pre-row context/identity cannot authorize their result.
    let after_challenge = challenge()?;
    let after = creator.query(&binding.scope, binding.role, after_challenge)?;
    if after.binding != *binding
        || after.challenge != after_challenge
        || kernel.identity(binding.key)? != id
    {
        return Err(Error::Conflict);
    }
    Ok(snapshot)
}
impl<A: Authority, K: Kernel, J: Journal> RowOwner<A, K, J> {
    /// Requires a live original adapter creator plus fresh journal/address absence.
    /// Saved bytes never open/adopt a device. There is intentionally no JSON-only
    /// recovery constructor; protected schema/recovery composition remains Task5.
    pub(crate) fn capture(
        binding: Binding,
        mut authority: A,
        mut kernel: K,
        mut journal: J,
    ) -> Result<Self> {
        binding.validate()?;
        let record = authority.locked(|creator| {
            if journal.load(&binding)?.is_some() {
                return Err(Error::Retired);
            }
            let baseline = read(creator, &mut kernel, &binding)?;
            if baseline.address.is_some() {
                return Err(Error::Conflict);
            }
            let record = Record {
                version: 1,
                domain: DOMAIN.into(),
                binding: binding.clone(),
                revision: 1,
                phase: Phase::Captured,
                baseline: baseline.clone(),
                current: baseline,
                pending: None,
                creation: None,
            };
            record.validate()?;
            let _ack = journal.compare_exchange(&binding, None, &record);
            if journal.load(&binding)?.as_ref() != Some(&record) {
                return Err(Error::Journal);
            }
            let after = read(creator, &mut kernel, &binding)?;
            if !same_owned(&after, &record.current) {
                return Err(Error::Conflict);
            }
            Ok(record)
        })?;
        Ok(Self {
            authority,
            state: OwnedRows {
                binding,
                kernel,
                journal,
                record,
                failed: false,
                creation: None,
            },
        })
    }
    fn run<T>(
        &mut self,
        action: impl FnOnce(&mut OwnedRows<K, J>, &mut A::Creator) -> Result<T>,
    ) -> Result<T> {
        let was_failed = self.state.failed;
        // Unwind/lost ACK is cleanup-only, even when a caller catches a panic.
        self.state.failed = true;
        let state = &mut self.state;
        let result = self.authority.locked(|creator| action(state, creator));
        if result.is_ok() && !was_failed && self.state.record.phase == Phase::Captured {
            self.state.failed = false;
        }
        result
    }
    pub(crate) fn snapshot(&mut self) -> Result<Snapshot> {
        self.run(|state, creator| {
            state.require_durable()?;
            if state.record.pending.is_some() {
                return Err(Error::Pending);
            }
            let live = read(creator, &mut state.kernel, &state.binding)?;
            if !same_owned(&live, &state.record.current) {
                return Err(Error::Conflict);
            }
            Ok(live)
        })
    }
    /// Observe DAD only for this live owner's acknowledged creation. This result
    /// is an observation, not a replacement creator handle or mutation permit.
    /// Native calls are synchronous: the deadline rejects late results but is
    /// NOT a hard timeout/preemption guarantee for a blocked Windows API call.
    pub(crate) fn wait_address_ready(&mut self, cancelled: &AtomicBool) -> Result<AddressRow> {
        self.wait_address_ready_with(cancelled, &mut MonotonicClock)
    }
    /// The same policy with a timing boundary; neither the budget nor ownership
    /// checks can be configured away by the clock. Sleep never holds our lock.
    pub(crate) fn wait_address_ready_with<C: ReadinessClock>(
        &mut self,
        cancelled: &AtomicBool,
        clock: &mut C,
    ) -> Result<AddressRow> {
        let was_failed = self.state.failed;
        // Cover cancellation, timeout, errors AND unwinding during read/sleep.
        // Only successful readiness of an originally live owner clears this.
        self.state.failed = true;
        if was_failed {
            return Err(Error::Retired);
        }
        let result = (|| {
            let mut last = clock.now();
            let deadline = last
                .checked_add(Duration::from_secs(5))
                .ok_or(Error::Retired)?;
            // Independent finite poll bound also denies a defective/frozen
            // injected clock; production uses the monotonic Instant below.
            for _ in 0..200 {
                readiness_budget(clock, cancelled, deadline, &mut last)?;
                let state = &mut self.state;
                let row = self.authority.locked(|creator| {
                    if state.binding.role != Role::Carrier || state.record.phase != Phase::Captured
                    {
                        return Err(Error::Retired);
                    }
                    if state.record.pending.is_some() {
                        return Err(Error::Pending);
                    }
                    state.require_durable()?;
                    state.require_receipt()?;
                    // Full native rows plus original creator/runtime and IFROW2
                    // identity are queried before AND after every native snapshot.
                    let live = read(creator, &mut state.kernel, &state.binding)?;
                    if !same_owned(&live, &state.record.current) {
                        return Err(Error::Conflict);
                    }
                    let row = live.address.ok_or(Error::Conflict)?;
                    let receipt = state.creation.as_ref().ok_or(Error::Pending)?;
                    if !same_address(&row, &receipt.row) {
                        return Err(Error::Conflict);
                    }
                    // A late revoked/changed protected journal is not redeemed
                    // by Preferred or by exact native data.
                    state.require_durable()?;
                    state.require_receipt()?;
                    match row.observed.dad_state {
                        1 | 4 => Ok(row), // Tentative or Preferred, read-only DAD
                        _ => Err(Error::Conflict),
                    }
                })?;
                let remaining = readiness_budget(clock, cancelled, deadline, &mut last)?;
                if row.observed.dad_state == 4 {
                    return Ok(row);
                }
                clock.sleep(remaining.min(Duration::from_millis(25)), cancelled);
            }
            Err(Error::Retired)
        })();
        if result.is_ok() {
            self.state.failed = false;
        }
        result
    }
    pub(crate) fn change_interface(&mut self, desired: InterfacePolicy) -> Result<()> {
        if self.state.failed || self.state.record.phase != Phase::Captured {
            return Err(Error::Retired);
        }
        self.run(|state, creator| {
            validate_interface_delta(&state.record.current.interface.policy, &desired)?;
            state.mutate(creator, Target::Interface(desired))
        })
    }
    pub(crate) fn create_address(&mut self, desired: AddressPolicy) -> Result<()> {
        if self.state.failed || self.state.record.phase != Phase::Captured {
            return Err(Error::Retired);
        }
        self.run(|state, creator| {
            desired.validate_creation()?;
            if state.binding.role != Role::Carrier
                || desired.address != state.binding.address
                || state.record.creation.is_some()
                || state.record.current.address.is_some()
            {
                return Err(Error::Retired);
            }
            state.mutate(creator, Target::Create(desired))
        })
    }
    pub(crate) fn stop(&mut self) -> Result<()> {
        self.run(|state, creator| {
            state.require_durable()?;
            if state.record.pending.is_some() {
                state.resolve(creator)?;
            }
            let live = read(creator, &mut state.kernel, &state.binding)?;
            if !same_owned(&live, &state.record.current) {
                return Err(Error::Conflict);
            }
            if state.record.phase == Phase::Stopped {
                return Ok(());
            }
            if state.record.phase != Phase::Closing {
                let mut closing = state.record.clone();
                closing.phase = Phase::Closing;
                state.persist(closing)?;
            }
            if state.record.current.interface.policy != state.record.baseline.interface.policy {
                state.mutate(
                    creator,
                    Target::Interface(state.record.baseline.interface.policy.clone()),
                )?;
            }
            if state.record.current.address.is_some() {
                state.mutate(creator, Target::Delete)?;
            }
            let live = read(creator, &mut state.kernel, &state.binding)?;
            if live.address.is_some()
                || live.interface.policy != state.record.baseline.interface.policy
            {
                return Err(Error::Conflict);
            }
            let mut stopped = state.record.clone();
            stopped.phase = Phase::Stopped;
            stopped.current = live;
            state.persist(stopped)?;
            let after = read(creator, &mut state.kernel, &state.binding)?;
            if !same_owned(&after, &state.record.current) {
                return Err(Error::Conflict);
            }
            Ok(())
        })
    }
}
fn readiness_budget<C: ReadinessClock>(
    clock: &mut C,
    cancelled: &AtomicBool,
    deadline: Instant,
    last: &mut Instant,
) -> Result<Duration> {
    let now = clock.now();
    if cancelled.load(Ordering::Acquire) || now < *last || now >= deadline {
        return Err(Error::Retired);
    }
    *last = now;
    Ok(deadline.duration_since(now))
}
impl<K: Kernel, J: Journal> OwnedRows<K, J> {
    fn require_durable(&mut self) -> Result<()> {
        self.record.validate()?;
        match self.journal.load(&self.binding)? {
            Some(current) if current == self.record => Ok(()),
            _ => Err(Error::Journal),
        }
    }
    fn persist(&mut self, mut desired: Record) -> Result<()> {
        desired.revision = self.record.revision.checked_add(1).ok_or(Error::Retired)?;
        desired.validate()?;
        self.require_durable()?;
        let _ack = self
            .journal
            .compare_exchange(&self.binding, Some(&self.record), &desired);
        if self.journal.load(&self.binding)?.as_ref() != Some(&desired) {
            return Err(Error::Journal);
        }
        self.record = desired;
        Ok(())
    }
    fn target_matches(&self, live: &Snapshot, pending: &Pending) -> bool {
        match &pending.target {
            Target::Interface(p) => {
                live.interface.policy == *p
                    && live.interface.key == pending.before.interface.key
                    && match (&live.address, &pending.before.address) {
                        (None, None) => true,
                        (Some(a), Some(b)) => same_address(a, b),
                        _ => false,
                    }
            }
            Target::Create(p) => {
                live.interface.policy == pending.before.interface.policy
                    && live.address.as_ref().is_some_and(|a| {
                        a.policy == *p
                            && a.key == self.binding.key
                            && a.observed.creation_timestamp > 0
                            && self
                                .creation
                                .as_ref()
                                .is_some_and(|receipt| same_address(&receipt.row, a))
                    })
            }
            Target::Delete => {
                live.address.is_none() && live.interface.policy == pending.before.interface.policy
            }
        }
    }
    fn confirm<C: OriginalCreator>(&mut self, creator: &mut C, live: Snapshot) -> Result<()> {
        let mut desired = self.record.clone();
        desired.current = live;
        desired.pending = None;
        if desired.creation.is_none() {
            desired.creation = self.creation.as_ref().map(|receipt| receipt.row.clone());
        }
        self.persist(desired)?;
        // Durable confirmation itself is not native proof. Reattest/reconstruct
        // again after its exact reread before any caller receives success.
        let after = read(creator, &mut self.kernel, &self.binding)?;
        if !same_owned(&after, &self.record.current) {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn require_receipt(&self) -> Result<()> {
        let Some(live) = &self.creation else {
            return Err(Error::Pending);
        };
        let Some(saved) = &self.record.creation else {
            return Err(Error::Pending);
        };
        let Some(current) = &self.record.current.address else {
            return Err(Error::Pending);
        };
        if !same_address(&live.row, saved) || !same_address(&live.row, current) {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn mutate<C: OriginalCreator>(&mut self, creator: &mut C, target: Target) -> Result<()> {
        self.require_durable()?;
        if self.record.pending.is_some() {
            return Err(Error::Pending);
        }
        // Reserve BOTH intent and confirmation before any native mutation.
        self.record.revision.checked_add(2).ok_or(Error::Retired)?;
        let before = read(creator, &mut self.kernel, &self.binding)?;
        if !same_owned(&before, &self.record.current) {
            return Err(Error::Conflict);
        }
        match &target {
            Target::Interface(p) => {
                validate_interface_delta(&before.interface.policy, p)?;
                // Capability checked even before durable intent: ignored/unsupported fields
                // cannot be normalized by the Initialize/Set path.
                interface_input(MIB_IPINTERFACE_ROW::default(), self.binding.key, p)?;
            }
            Target::Create(p) => {
                p.validate_creation()?;
                if self.binding.role != Role::Carrier
                    || before.address.is_some()
                    || self.creation.is_some()
                    || self.record.creation.is_some()
                    || self.record.phase != Phase::Captured
                {
                    return Err(Error::Retired);
                }
            }
            Target::Delete => {
                if self.record.phase != Phase::Closing {
                    return Err(Error::Retired);
                }
                self.require_receipt()?;
            }
        }
        let mut desired = self.record.clone();
        desired.current = before.clone();
        desired.pending = Some(Pending {
            before,
            target: target.clone(),
        });
        self.persist(desired)?;
        creator.authorize(&self.binding, &target)?;
        let exact = read(creator, &mut self.kernel, &self.binding)?;
        let pending = self.record.pending.clone().ok_or(Error::Pending)?;
        if !same_owned(&exact, &pending.before) {
            return Err(Error::Conflict);
        }
        let ack = match &target {
            Target::Interface(p) => {
                let initialized = self.kernel.initialize_interface();
                let mut row = interface_input(initialized, self.binding.key, p)?;
                self.kernel.set_interface(&mut row)
            }
            Target::Create(p) => {
                let initialized = self.kernel.initialize_address();
                let row = address_input(initialized, self.binding.key, p)?;
                self.kernel.create_address(&row)
            }
            Target::Delete => {
                self.require_receipt()?;
                let current = exact.address.as_ref().ok_or(Error::Conflict)?;
                let initialized = self.kernel.initialize_address();
                let row = address_input(initialized, self.binding.key, &current.policy)?;
                self.kernel.delete_address(&row)
            }
        };
        // Create errors, including a committed lost ACK, never confer row authority.
        if matches!(target, Target::Create(_)) && ack.is_err() {
            return Err(Error::Pending);
        }
        let after = read(creator, &mut self.kernel, &self.binding)?;
        if let Target::Create(p) = &target {
            let row = after.address.as_ref().ok_or(Error::Pending)?;
            if row.policy != *p
                || row.observed.creation_timestamp <= 0
                || after.interface.policy != pending.before.interface.policy
            {
                return Err(Error::Pending);
            }
            self.creation = Some(CreatedAddressReceipt { row: row.clone() });
        }
        if !self.target_matches(&after, &pending) {
            return Err(Error::Pending);
        }
        self.confirm(creator, after)
    }
    fn resolve<C: OriginalCreator>(&mut self, creator: &mut C) -> Result<()> {
        self.require_durable()?;
        self.record.revision.checked_add(1).ok_or(Error::Retired)?;
        let pending = self.record.pending.clone().ok_or(Error::Pending)?;
        if matches!(pending.target, Target::Create(_)) && self.creation.is_none() {
            return Err(Error::Pending);
        }
        if matches!(pending.target, Target::Delete) {
            self.require_receipt()?;
        }
        let live = read(creator, &mut self.kernel, &self.binding)?;
        if !self.target_matches(&live, &pending) && !same_owned(&live, &pending.before) {
            return Err(Error::Conflict);
        }
        self.confirm(creator, live)
    }
}

// Real effects exist only behind this unused constructor plus mandatory live
// original-creator serialization authority. No factory, default attestor, handle
// adoption, table enumeration, physical/global mutation, or recovery opener.
#[cfg(windows)]
mod ip_helper {
    use super::*;
    use windows_sys::{core::GUID, Win32::NetworkManagement::Ndis::NET_LUID_LH};
    pub(crate) struct IpHelper {
        _private: (),
    }
    fn checked(status: u32) -> Result<()> {
        if status == 0 {
            Ok(())
        } else {
            Err(Error::Native)
        }
    }
    impl Kernel for IpHelper {
        fn identity(&mut self, key: RowKey) -> Result<NativeIdentity> {
            key.validate()?;
            let luid = NET_LUID_LH { Value: key.luid };
            let mut by_luid = MIB_IF_ROW2 {
                InterfaceLuid: luid,
                ..Default::default()
            };
            let mut by_index = MIB_IF_ROW2 {
                InterfaceIndex: key.index,
                ..Default::default()
            };
            let mut guid = GUID::from_u128(0);
            let mut from_guid = NET_LUID_LH::default();
            let mut from_index = NET_LUID_LH::default();
            let mut index = 0;
            unsafe {
                checked(GetIfEntry2(&mut by_luid))?;
                checked(GetIfEntry2(&mut by_index))?;
                checked(ConvertInterfaceLuidToGuid(&luid, &mut guid))?;
                checked(ConvertInterfaceGuidToLuid(&guid, &mut from_guid))?;
                checked(ConvertInterfaceIndexToLuid(key.index, &mut from_index))?;
                checked(ConvertInterfaceLuidToIndex(&luid, &mut index))?;
            }
            let a = decode_identity(&by_luid)?;
            let b = decode_identity(&by_index)?;
            if a != b
                || a.key != key
                || a.guid != guid_bytes(&guid)
                || unsafe { from_guid.Value } != key.luid
                || unsafe { from_index.Value } != key.luid
                || index != key.index
            {
                return Err(Error::Conflict);
            }
            Ok(a)
        }
        fn interface(&mut self, key: RowKey) -> Result<MIB_IPINTERFACE_ROW> {
            key.validate()?;
            let mut row = self.initialize_interface();
            row.Family = AF_INET;
            row.InterfaceLuid.Value = key.luid;
            row.InterfaceIndex = key.index;
            unsafe {
                checked(GetIpInterfaceEntry(&mut row))?;
            }
            let decoded = decode_interface(&row)?;
            if decoded.key != key {
                return Err(Error::Conflict);
            }
            Ok(row)
        }
        fn address(
            &mut self,
            key: RowKey,
            address: [u8; 4],
        ) -> Result<Option<MIB_UNICASTIPADDRESS_ROW>> {
            key.validate()?;
            // Address is just the exact lookup key, NOT writable permission.
            let mut row = self.initialize_address();
            row.Address.Ipv4 = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(address),
                    },
                },
                sin_zero: [0; 8],
            };
            row.InterfaceLuid.Value = key.luid;
            row.InterfaceIndex = key.index;
            if !address_status(unsafe { GetUnicastIpAddressEntry(&mut row) })? {
                return Ok(None);
            }
            let decoded = decode_address(&row)?;
            if decoded.key != key || decoded.policy.address != address {
                return Err(Error::Conflict);
            }
            Ok(Some(row))
        }
        fn initialize_interface(&mut self) -> MIB_IPINTERFACE_ROW {
            let mut row = MIB_IPINTERFACE_ROW::default();
            unsafe {
                InitializeIpInterfaceEntry(&mut row);
            }
            row
        }
        fn initialize_address(&mut self) -> MIB_UNICASTIPADDRESS_ROW {
            let mut row = MIB_UNICASTIPADDRESS_ROW::default();
            unsafe {
                InitializeUnicastIpAddressEntry(&mut row);
            }
            row
        }
        fn set_interface(&mut self, row: &mut MIB_IPINTERFACE_ROW) -> Result<()> {
            decode_interface(row)?;
            unsafe { checked(SetIpInterfaceEntry(row)) }
        }
        fn create_address(&mut self, row: &MIB_UNICASTIPADDRESS_ROW) -> Result<()> {
            let decoded = decode_address(row)?;
            decoded.policy.validate_creation()?;
            if decoded.observed.dad_state != 0
                || decoded.observed.scope_id != 0
                || decoded.observed.creation_timestamp != 0
            {
                return Err(Error::Unsupported);
            }
            unsafe { checked(CreateUnicastIpAddressEntry(row)) }
        }
        fn delete_address(&mut self, row: &MIB_UNICASTIPADDRESS_ROW) -> Result<()> {
            decode_address(row)?;
            unsafe { checked(DeleteUnicastIpAddressEntry(row)) }
        }
    }
    impl<A: Authority, J: Journal> RowOwner<A, IpHelper, J> {
        pub(crate) fn capture_native(binding: Binding, authority: A, journal: J) -> Result<Self> {
            Self::capture(binding, authority, IpHelper { _private: () }, journal)
        }
    }
}
#[cfg(all(test, windows))]
#[path = "member_carrier_rows_tests.rs"]
mod tests;
