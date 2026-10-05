//! Full native IPv4 rows, deliberately disconnected from the production factory.
#![allow(dead_code)]
pub(crate) use crate::member_carrier_rows::*;
#[cfg(all(test, windows))]
use crate::windows::member_carrier_factory_test_os::trace_step as trace_observe;
use nelomai_client_tunnel::redundancy::SessionScope;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
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
        .ok_or(Error::Unsupported)
        .inspect_err(|_| {
            #[cfg(all(test, windows))]
            if crate::windows::member_carrier_factory_test_os::state().is_some() {
                trace_observe(&format!(
                    "C actual identity Unsupported Alias unterminated units={}",
                    row.Alias.len()
                ));
            }
        })?;
    let name = String::from_utf16(&row.Alias[..end]).map_err(|_| {
        #[cfg(all(test, windows))]
        if crate::windows::member_carrier_factory_test_os::state().is_some() {
            trace_observe(&format!(
                "C actual identity Unsupported Alias invalid UTF16 units={end}"
            ));
        }
        Error::Unsupported
    })?;
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
        #[cfg(all(test, windows))]
        if crate::windows::member_carrier_factory_test_os::state().is_some() {
            trace_observe(&format!("C actual identity Unsupported guidzero={} aliasbytes={} aliascontrol={} Type={} InterfaceAndOperStatusFlags={:#x}",
                guid == [0; 16], name.len(), name.chars().any(|c| c.is_control()), row.Type, row.InterfaceAndOperStatusFlags._bitfield));
        }
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
        #[cfg(all(test, windows))]
        if crate::windows::member_carrier_factory_test_os::state().is_some() {
            trace_observe(&format!("C actual address Unsupported Family={}", unsafe {
                r.Address.si_family
            }));
        }
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
        #[cfg(all(test, windows))]
        if crate::windows::member_carrier_factory_test_os::state().is_some() {
            trace_observe(&format!(
                "C actual address Unsupported sin_port={} sin_zero_nonzero={}",
                addr.sin_port,
                addr.sin_zero != [0; 8]
            ));
        }
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
    row.policy.validate().inspect_err(|_error| {
        #[cfg(all(test, windows))]
        if *_error == Error::Unsupported
            && crate::windows::member_carrier_factory_test_os::state().is_some()
        {
            trace_observe(&format!("C actual address policy Unsupported address={:?} PrefixOrigin={} SuffixOrigin={} ValidLifetime={} PreferredLifetime={} OnLinkPrefixLength={} SkipAsSource={}",
                row.policy.address, row.policy.prefix_origin, row.policy.suffix_origin, row.policy.valid_lifetime, row.policy.preferred_lifetime, row.policy.on_link_prefix_length, row.policy.skip_as_source));
        }
    })?;
    if !(0..=4).contains(&row.observed.dad_state) || row.observed.creation_timestamp < 0 {
        #[cfg(all(test, windows))]
        if crate::windows::member_carrier_factory_test_os::state().is_some() {
            trace_observe(&format!(
                "C actual address observed Unsupported DadState={} ScopeId={} CreationTimeStamp={}",
                row.observed.dad_state, row.observed.scope_id, row.observed.creation_timestamp
            ));
        }
        return Err(Error::Unsupported);
    }
    Ok(row)
}
pub(crate) fn decode_interface(r: &MIB_IPINTERFACE_ROW) -> Result<InterfaceRow> {
    if r.Family != AF_INET || r.MaxReassemblySize != 0 || r.InterfaceIdentifier != 0 {
        #[cfg(all(test, windows))]
        if crate::windows::member_carrier_factory_test_os::state().is_some() {
            trace_observe(&format!("C actual interface Unsupported Family={} MaxReassemblySize={} InterfaceIdentifier={}",
                r.Family, r.MaxReassemblySize, r.InterfaceIdentifier));
        }
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
    row.policy.validate().inspect_err(|_error| {
        #[cfg(all(test, windows))]
        if *_error == Error::Unsupported
            && crate::windows::member_carrier_factory_test_os::state().is_some()
        {
            trace_observe(&format!("C actual interface policy Unsupported RouterDiscoveryBehavior={} LinkLocalAddressBehavior={} Metric={} NlMtu={} SitePrefixLength={}",
                row.policy.router_discovery, row.policy.link_local_behavior, row.policy.metric, row.policy.mtu, row.policy.site_prefix_length));
        }
    })?;
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
/// Only the raw OS boundary may be faked. Effects remain private to the
/// serialized row owner; the factual snapshot uses only the three queries.
/// Errors are not absence; writes may lose an ACK.
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
// Shared SDK-read policy; no creator, authority, owner or journal borrow. Kept
// private to this module and its tests; callers get ONLY the actual SDK entry.
pub(super) fn read_original_snapshot_with<K: Kernel>(
    kernel: &mut K,
    binding: &Binding,
) -> Result<Snapshot> {
    binding.validate()?;
    let before = kernel.identity(binding.key)?;
    if before.key != binding.key
        || before.guid != binding.guid
        || before.name != binding.name
        || before.if_type != 53
        || before.hardware
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
    // PnP/external changes are not serialized by the caller's original owner.
    // Even a factual absence must not survive a changed native identity.
    if kernel.identity(binding.key)? != before {
        return Err(Error::Conflict);
    }
    Ok(snapshot)
}
#[cfg(windows)]
pub(crate) mod native {
    use super::*;

    /// Factual full IPv4 SDK view, with exact native identity before/after.
    ///
    /// Caller MUST obtain this Binding freshly from the SAME OriginalObserver
    /// and full OriginalUniverse, then authenticate retained original/runtime/
    /// supervisor/pair facts before AND after this read. Every call belongs
    /// inside the caller's actual NativeDeadline Calling callback. This helper
    /// neither owns nor authenticates that supervisor, runtime, pair or creator.
    /// Binding validation is structural only; equality is not ownership proof.
    ///
    /// Uses Get/Convert calls and SDK Initialize lookup buffers ONLY. No native
    /// Set/Create/Delete, reopen, journal, source-ready grant or address adoption.
    /// None denotes only exact managed-address absence, never all-address absence.
    /// Returned DAD/SkipAsSource and other known fields are observations; caller
    /// must compare the full snapshot with its original protected row/ACK facts.
    pub(crate) fn read_original_snapshot(binding: &Binding) -> Result<Snapshot> {
        ip_helper::read_original_snapshot(binding)
    }
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
pub(crate) struct InitialRowCaptureCleanupRead<'a> {
    original: &'a Rc<RowRecordReceipt>,
    initial: Rc<InitialRowCaptureAttempt>,
    exchange: Option<InitialCaptureExchange<'a>>,
}
struct InitialRowCaptureAttempt {
    record: Record,
    payload: Vec<u8>,
    invoked: Cell<bool>,
    acknowledged: Cell<bool>,
}
struct InitialCaptureExchange<'a> {
    expected: Option<&'a Record>,
    desired: &'a Record,
    native: &'a Snapshot,
}
impl InitialRowCaptureCleanupRead<'_> {
    fn verify_initial(&self) -> Result<()> {
        if !self.initial.invoked.get()
            || self.initial.acknowledged.get()
            || self.original.native_effects_started.get()
            || self.initial.record.binding != self.original.binding
            || self.initial.record.binding.role != Role::Carrier
            || self.initial.record.current != self.initial.record.baseline
            || self.initial.record.current.address.is_some()
            || !self
                .original
                .initial
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .as_ref()
                .is_some_and(|actual| Rc::ptr_eq(actual, &self.initial))
        {
            return Err(Error::Retired);
        }
        Ok(())
    }
    pub(crate) fn binding(&self) -> &Binding {
        &self.initial.record.binding
    }
    pub(crate) fn initial_record(&self) -> &Record {
        &self.initial.record
    }
    pub(crate) fn baseline(&self) -> &Snapshot {
        &self.initial.record.baseline
    }
    pub(crate) fn matches_record_original(&self, pin: &RowRecordReadPin) -> bool {
        Rc::ptr_eq(self.original, &pin.original)
    }
    pub(crate) fn verify_exchange(
        &self,
        b: &Binding,
        old: Option<&Record>,
        new: &Record,
    ) -> Result<()> {
        self.verify_initial()?;
        let selected = self.exchange.as_ref().ok_or(Error::Pending)?;
        new.validate()?;
        if let Some(old) = old {
            old.validate()?;
        }
        if b != self.binding()
            || old != selected.expected
            || new != selected.desired
            || new.binding != *b
            || new.phase != Phase::Closing
            || new.revision
                != old
                    .map_or(Some(2), |r| r.revision.checked_add(1))
                    .ok_or(Error::Retired)?
            || new.baseline != *self.baseline()
            || new.current != *selected.native
            || new.pending.is_some()
            || new.creation.is_some()
            || new.current.address.is_some()
            || !same_owned(selected.native, self.baseline())
            || old.is_some_and(|r| {
                !matches!(r.phase, Phase::Captured | Phase::Closing)
                    || r.binding != *b
                    || r.baseline != *self.baseline()
                    || r.pending.is_some()
                    || r.creation.is_some()
                    || r.current.address.is_some()
                    || !same_owned(&r.current, self.baseline())
            })
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub(crate) fn verify_payloads(&self, old: Option<&[u8]>, new: &[u8]) -> Result<()> {
        let selected = self.exchange.as_ref().ok_or(Error::Pending)?;
        self.verify_exchange(self.binding(), selected.expected, selected.desired)?;
        let expected = selected
            .expected
            .map(|r| {
                if r == self.initial_record() {
                    Ok(self.initial.payload.clone())
                } else {
                    r.encode()
                }
            })
            .transpose()?;
        if old != expected.as_deref() || new != selected.desired.encode()? {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}
/// # Safety
/// SAME original backend/birth/Closing/Calling and sealed invocation required;
/// callbacks pure, no SDK/backend reentry or retroactive initial ACK grant.
pub(crate) unsafe trait InitialRowCaptureCleanupJournal: Journal {
    fn compare_exchange_initial_capture_cleanup(
        &mut self,
        binding: &Binding,
        expected: Option<&Record>,
        desired: &Record,
        original: &InitialRowCaptureCleanupRead<'_>,
    ) -> Result<()>;
}
impl<A: Authority, K: Kernel, J: Journal> RowOwner<A, K, J> {
    pub(crate) fn initial_capture_cleanup_pin(&self) -> Result<RowRecordReadPin> {
        self.inspect_original_initial_capture(|_, pin, _| {
            Ok(RowRecordReadPin {
                original: pin.original.clone(),
            })
        })
    }
    pub(crate) fn inspect_original_initial_capture<T>(
        &self,
        inspect: impl FnOnce(&A, &RowRecordReadPin, &InitialRowCaptureCleanupRead<'_>) -> Result<T>,
    ) -> Result<T> {
        let original = &self.state.record_receipt;
        let initial = original
            .initial
            .try_borrow()
            .map_err(|_| Error::Conflict)?
            .clone()
            .ok_or(Error::Pending)?;
        let facts = InitialRowCaptureCleanupRead {
            original,
            initial,
            exchange: None,
        };
        facts.verify_initial()?;
        inspect(
            &self.authority,
            &RowRecordReadPin {
                original: original.clone(),
            },
            &facts,
        )
    }
}
impl<A: Authority, K: Kernel, J: InitialRowCaptureCleanupJournal> RowOwner<A, K, J> {
    pub(crate) fn reconcile_initial_capture_for_cleanup(&mut self) -> Result<()> {
        self.reconcile_initial_capture_for_cleanup_with_record_pin(|_| Ok(()))
    }
    /// Publish only the NEW Closing CAS ACK after exact readback, before native
    /// postflight. Callback errors/unwind retain that factual ACK in this owner;
    /// neither the initial Captured ACK nor forward permission is recovered.
    pub(crate) fn reconcile_initial_capture_for_cleanup_with_record_pin(
        &mut self,
        retain: impl FnOnce(RowRecordReadPin) -> Result<()>,
    ) -> Result<()> {
        self.state.read_pin_revoked.set(true);
        self.state.record_receipt.revoked.set(true);
        self.run(|state, creator| {
            let original = &state.record_receipt;
            let initial = original
                .initial
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .clone()
                .ok_or(Error::Pending)?;
            let facts = InitialRowCaptureCleanupRead {
                original,
                initial: initial.clone(),
                exchange: None,
            };
            facts.verify_initial()?;
            if state.creation.is_some()
                || state.record.creation.is_some()
                || state.record.pending.is_some()
            {
                return Err(Error::Retired);
            }
            let expected = state.journal.load(&state.binding)?;
            let mut permitted = expected.as_ref() == Some(&initial.record)
                && state.record == initial.record
                && original
                    .acknowledged
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .is_none();
            if expected.is_none() {
                // A failed unapplied NEW Closing attempt does not erase the
                // original initial invocation. Absence is still not an ACK.
                permitted = original
                    .acknowledged
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .is_none()
                    && state.record == initial.record;
            } else {
                if original
                    .acknowledged
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .as_deref()
                    == expected.as_ref()
                {
                    permitted = true;
                }
                let mut cursor = original
                    .write_attempt
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .clone();
                while let Some(a) = cursor {
                    if expected.as_ref() == Some(&a.desired)
                        && !a.confirmed.get()
                        && (a.before == state.record || a.desired == state.record)
                    {
                        permitted = true;
                        break;
                    }
                    cursor = a._previous.clone();
                }
            }
            if !permitted {
                return Err(Error::Conflict);
            }
            let live = read(creator, &mut state.kernel, &state.binding)?;
            let mut desired = initial.record.clone();
            desired.revision = expected
                .as_ref()
                .map_or(Some(2), |r| r.revision.checked_add(1))
                .ok_or(Error::Retired)?;
            desired.phase = Phase::Closing;
            desired.current = live.clone();
            let proof = InitialRowCaptureCleanupRead {
                original,
                initial,
                exchange: Some(InitialCaptureExchange {
                    expected: expected.as_ref(),
                    desired: &desired,
                    native: &live,
                }),
            };
            proof.verify_exchange(&state.binding, expected.as_ref(), &desired)?;
            if state.journal.load(&state.binding)? != expected
                || read(creator, &mut state.kernel, &state.binding)? != live
            {
                return Err(Error::Conflict);
            }
            let attempt = Rc::new(RowWriteAttempt {
                before: expected
                    .clone()
                    .unwrap_or_else(|| proof.initial_record().clone()),
                desired: desired.clone(),
                confirmed: Cell::new(false),
                _previous: original
                    .write_attempt
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .clone(),
            });
            *original
                .write_attempt
                .try_borrow_mut()
                .map_err(|_| Error::Conflict)? = Some(attempt.clone());
            let ack = state.journal.compare_exchange_initial_capture_cleanup(
                &state.binding,
                expected.as_ref(),
                &desired,
                &proof,
            );
            if state.journal.load(&state.binding)?.as_ref() != Some(&desired) {
                return Err(Error::Journal);
            }
            state.record = desired.clone(); // obligation only until actual new ACK
            ack?;
            *original
                .acknowledged
                .try_borrow_mut()
                .map_err(|_| Error::Conflict)? = Some(Rc::new(desired.clone()));
            attempt.confirmed.set(true);
            retain(RowRecordReadPin {
                original: original.clone(),
            })?;
            if read(creator, &mut state.kernel, &state.binding)? != live
                || state.journal.load(&state.binding)?.as_ref() != Some(&desired)
            {
                return Err(Error::Conflict);
            }
            Ok(())
        })
    }
}
/// Caller-owned construction destination, retained BEFORE validation or IO.
/// Resources never live solely in a returned capture Result.
pub(crate) struct RowCaptureSlot<A, K, J> {
    binding: Binding,
    authority: Option<A>,
    unprepared: Option<(K, J)>,
    state: Option<OwnedRows<K, J>>,
    owner: Option<RowOwner<A, K, J>>,
    attempted: bool,
    completed: bool,
    stopped_transfer: Option<(Rc<RowRecordReceipt>, Rc<Record>)>,
}
impl<A, K, J> RowCaptureSlot<A, K, J> {
    pub(crate) fn new(binding: Binding, authority: A, kernel: K, journal: J) -> Self {
        Self {
            binding,
            authority: Some(authority),
            unprepared: Some((kernel, journal)),
            state: None,
            owner: None,
            attempted: false,
            completed: false,
            stopped_transfer: None,
        }
    }
    pub(crate) fn owner_mut(&mut self) -> Result<&mut RowOwner<A, K, J>> {
        if self.owner.is_none() {
            if self.authority.is_none() || self.state.is_none() {
                return Err(Error::Pending);
            }
            self.owner = Some(RowOwner {
                authority: self.authority.take().ok_or(Error::Pending)?,
                state: self.state.take().ok_or(Error::Pending)?,
            });
        }
        self.owner.as_mut().ok_or(Error::Pending)
    }
    /// Explicit transfer only AFTER full successful capture. An uncertain
    /// owner remains borrowed in this caller-retained slot for cleanup.
    pub(crate) fn take_owner(&mut self) -> Result<RowOwner<A, K, J>> {
        if !self.completed {
            return Err(Error::Pending);
        }
        self.owner_mut()?;
        self.owner.take().ok_or(Error::Pending)
    }
    /// Pure SAME-owner transfer inside the caller's already-held terminal
    /// protected/SDK bracket. Stopped JSON or a lookup cannot construct the
    /// original ACK required here. No Authority, Source, journal or old NIC
    /// read occurs. This does NOT authorize SDK/module/destructor release.
    pub(crate) fn drain_stopped_into(
        &mut self,
        original: &RowRecordReadPin,
        destination: &mut Option<RowCaptureSlotStopped<A, K, J>>,
    ) -> Result<()> {
        if destination.is_some() || self.stopped_transfer.is_some() {
            return Err(Error::Retired);
        }
        let owner = self.owner_mut()?;
        let stopped = stopped_owner_ack(owner, original)?;
        let receipt = owner.state.record_receipt.clone();
        // The transfer's original identity remains in BOTH wrappers before
        // moving resources. Destination owns A/K/J before any caller postflight.
        self.stopped_transfer = Some((receipt.clone(), stopped.clone()));
        *destination = Some(RowCaptureSlotStopped {
            owner: self.owner.take(),
            original: receipt,
            stopped,
        });
        Ok(())
    }
    pub(crate) fn verify_stopped_drained_into(
        &self,
        original: &RowRecordReadPin,
        destination: &RowCaptureSlotStopped<A, K, J>,
    ) -> Result<()> {
        let (receipt, stopped) = self.stopped_transfer.as_ref().ok_or(Error::Pending)?;
        if self.authority.is_some()
            || self.unprepared.is_some()
            || self.state.is_some()
            || self.owner.is_some()
            || !Rc::ptr_eq(receipt, &original.original)
            || !Rc::ptr_eq(receipt, &destination.original)
            || !Rc::ptr_eq(stopped, &destination.stopped)
            || self.binding != destination.stopped.binding
        {
            return Err(Error::Conflict);
        }
        destination.verify_original(original)
    }
    /// Final private cut, after the intermediate stopped slot has transferred
    /// into the parent's raw owner. Exact original identity survives removal
    /// of that now-empty intermediate wrapper; no lookup/data adoption.
    pub(crate) fn verify_stopped_owner_drained_into(
        &self,
        original: &RowRecordReadPin,
        destination: &RowOwner<A, K, J>,
    ) -> Result<()> {
        let (receipt, stopped) = self.stopped_transfer.as_ref().ok_or(Error::Pending)?;
        if self.authority.is_some()
            || self.unprepared.is_some()
            || self.state.is_some()
            || self.owner.is_some()
            || self.binding != destination.state.binding
            || !Rc::ptr_eq(receipt, &original.original)
            || !Rc::ptr_eq(stopped, &stopped_owner_ack(destination, original)?)
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

/// Caller-retained raw SAME stopped owner. Unknown Drop still retains resources;
/// only explicit transfer into the canonical terminal parent's raw owner cuts
/// that retention. This is storage/ownership sequencing, NEVER native EMPTY or
/// permission to run any destructor. The parent's actual full terminal G must
/// authenticate these precise originals before final release.
pub(crate) struct RowCaptureSlotStopped<A, K, J> {
    owner: Option<RowOwner<A, K, J>>,
    original: Rc<RowRecordReceipt>,
    stopped: Rc<Record>,
}
impl<A, K, J> RowCaptureSlotStopped<A, K, J> {
    pub(crate) fn verify_original(&self, original: &RowRecordReadPin) -> Result<()> {
        if !Rc::ptr_eq(&self.original, &original.original)
            || !self
                .original
                .acknowledged
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .as_ref()
                .is_some_and(|ack| Rc::ptr_eq(ack, &self.stopped))
        {
            return Err(Error::Conflict);
        }
        self.stopped.validate()?;
        if self.stopped.phase != Phase::Stopped
            || self.stopped.pending.is_some()
            || self.stopped.binding != self.original.binding
            || self.stopped.current.address.is_some()
            || !same_owned(&self.stopped.current, &self.stopped.baseline)
        {
            return Err(Error::Conflict);
        }
        if let Some(owner) = &self.owner {
            if !Rc::ptr_eq(&stopped_owner_ack(owner, original)?, &self.stopped) {
                return Err(Error::Conflict);
            }
        }
        Ok(())
    }
    pub(crate) fn drain_owner_into(
        &mut self,
        destination: &mut Option<RowOwner<A, K, J>>,
    ) -> Result<()> {
        if destination.is_some() {
            return Err(Error::Conflict);
        }
        let original = RowRecordReadPin {
            original: self.original.clone(),
        };
        self.verify_original(&original)?;
        if self.owner.is_none() {
            return Err(Error::Retired);
        }
        *destination = self.owner.take();
        Ok(())
    }
    pub(crate) fn verify_owner_drained_into(&self, destination: &RowOwner<A, K, J>) -> Result<()> {
        if self.owner.is_some() {
            return Err(Error::Conflict);
        }
        let original = RowRecordReadPin {
            original: self.original.clone(),
        };
        self.verify_original(&original)?;
        if !Rc::ptr_eq(&stopped_owner_ack(destination, &original)?, &self.stopped) {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}
impl<A, K, J> Drop for RowCaptureSlotStopped<A, K, J> {
    fn drop(&mut self) {
        std::mem::forget(self.owner.take());
    }
}
fn stopped_owner_ack<A, K, J>(
    owner: &RowOwner<A, K, J>,
    original: &RowRecordReadPin,
) -> Result<Rc<Record>> {
    let state = &owner.state;
    state.record.validate()?;
    if !Rc::ptr_eq(&state.record_receipt, &original.original)
        || state.binding != state.record.binding
        || state.binding != original.original.binding
        || state.record.phase != Phase::Stopped
        || state.record.pending.is_some()
        || state.record.current.address.is_some()
        || !same_owned(&state.record.current, &state.record.baseline)
        || !state.read_pin_revoked.get()
        || !state.record_receipt.revoked.get()
    {
        return Err(Error::Conflict);
    }
    let ack = state
        .record_receipt
        .acknowledged
        .try_borrow()
        .map_err(|_| Error::Conflict)?
        .clone()
        .ok_or(Error::Journal)?;
    if *ack != state.record {
        return Err(Error::Journal);
    }
    if state
        .record_receipt
        .write_attempt
        .try_borrow()
        .map_err(|_| Error::Conflict)?
        .as_ref()
        .is_some_and(|attempt| !attempt.confirmed.get() || attempt.desired != state.record)
    {
        return Err(Error::Pending);
    }
    Ok(ack)
}
impl<A, K, J> Drop for RowCaptureSlot<A, K, J> {
    fn drop(&mut self) {
        // Unknown Drop cannot release original native roots or run arbitrary
        // A/K/J destructors. The caller must retain this slot, finish explicit
        // cleanup, and use a separately authenticated terminal release path.
        // Conservative process-lifetime retention is NOT cleanup success.
        std::mem::forget(self.owner.take());
        std::mem::forget(self.state.take());
        std::mem::forget(self.unprepared.take());
        std::mem::forget(self.authority.take());
    }
}
struct OwnedRows<K, J> {
    binding: Binding,
    kernel: K,
    journal: J,
    record: Record,
    failed: bool,
    // Non-serializable live history. Set ONLY from this actual acknowledged create
    // + immediate exact readback. No constructor imports it from a durable record.
    creation: Option<Rc<CreatedAddressReceipt>>,
    address_ready: bool,
    // Independent of the temporary `failed` sentinel during a normal operation.
    // Once revoked, no successful read/write/cleanup may rearm existing pins.
    read_pin_revoked: Rc<Cell<bool>>,
    // Original capture provenance and exact durable ACKs, independent of the
    // mutable authority/kernel/journal borrow used by native G callbacks.
    record_receipt: Rc<RowRecordReceipt>,
    stopped_generation: Option<Rc<StoppedRowGeneration>>,
}
// No Clone/Serialize/Deserialize/import constructor. This receipt records a
// successful invocation + immediate exact readback in THIS owner; the original
// native creator is independently borrowed for the owner's native operations;
// read pins confer only these immutable historical comparison facts.
struct CreatedAddressReceipt {
    binding: Binding,
    row: AddressRow,
    before: Snapshot,
    baseline: Snapshot,
}
/// Sealed borrowed SAME-owner SDK Create receipt. Only the locked original
/// owner can issue this view; matching rows/JSON cannot construct it.
pub(crate) struct CreatedAddressCleanupRead<'a> {
    receipt: &'a Rc<CreatedAddressReceipt>,
    record_original: &'a Rc<RowRecordReceipt>,
    expected: &'a Record,
    desired: &'a Record,
    native: &'a Snapshot,
}
impl CreatedAddressCleanupRead<'_> {
    pub(crate) fn verify_exchange(
        &self,
        binding: &Binding,
        expected: &Record,
        desired: &Record,
    ) -> Result<()> {
        expected.validate()?;
        desired.validate()?;
        let receipt = self.receipt;
        let mut applied = receipt.before.clone();
        applied.address = Some(receipt.row.clone());
        if binding != &receipt.binding
            || binding != &self.record_original.binding
            || expected != self.expected
            || desired != self.desired
            || expected.binding != *binding
            || desired.binding != *binding
            || expected.baseline != receipt.baseline
            || desired.baseline != receipt.baseline
            || expected.revision.checked_add(1) != Some(desired.revision)
            || expected.phase == Phase::Stopped
            || desired.phase != Phase::Closing
            || desired.pending.is_some()
            || desired.creation.as_ref() != Some(&receipt.row)
            || &desired.current != self.native
            || (!same_owned(self.native, &receipt.before) && !same_owned(self.native, &applied))
        {
            return Err(Error::Conflict);
        }
        match &expected.pending {
            Some(p)
                if matches!(&p.target, Target::Create(policy) if *policy == receipt.row.policy)
                    && p.before == receipt.before
                    && expected.creation.is_none() => {}
            None if expected
                .creation
                .as_ref()
                .is_some_and(|r| same_address(r, &receipt.row))
                && (same_owned(&expected.current, &receipt.before)
                    || same_owned(&expected.current, &applied)) => {}
            _ => return Err(Error::Pending),
        }
        Ok(())
    }
    pub(crate) fn binding(&self) -> &Binding {
        &self.receipt.binding
    }
    pub(crate) fn captured(&self) -> &AddressRow {
        &self.receipt.row
    }
    pub(crate) fn matches_record_original(&self, pin: &RowRecordReadPin) -> bool {
        Rc::ptr_eq(self.record_original, &pin.original)
    }
}
/// # Safety
/// Production implementations MUST use the SAME original protected backend,
/// typed birth cleanup view and actual Runtime/Closing/Calling root. Verify the
/// sealed receipt and exact protected Pair/row bytes before AND after a NEW CAS;
/// no SDK/backend/Runtime reentry under raw transactions. No generic creation
/// exception, default callback, initial lost-ACK adoption or native effect.
pub(crate) unsafe trait CreatedAddressCleanupJournal: Journal {
    fn compare_exchange_created_cleanup(
        &mut self,
        binding: &Binding,
        expected: &Record,
        desired: &Record,
        original: &CreatedAddressCleanupRead<'_>,
    ) -> Result<()>;
}
/// Historical create facts ONLY; no creator, lock, native IO or effect authority.
/// Rc keeps the SAME actual ACK receipt immutable and makes this !Send + !Sync.
/// No Clone, serialization or data/import constructor. Every use must also be
/// independently checked against actual original C, runtime, protected rows and
/// full live SDK rows (including current SourcePreferred) by NativeRuntime.
pub(crate) struct CreatedAddressReadPin {
    receipt: Rc<CreatedAddressReceipt>,
    revoked: Rc<Cell<bool>>,
}
/// Borrowed historical comparison data, never a source-ready grant. Captured DAD
/// can be Tentative even though issuance requires successful waitReady.
pub(crate) struct CreatedAddressFacts<'a> {
    pub binding: &'a Binding,
    pub captured: &'a AddressRow,
    // Keep the view tied to the opaque !Send + !Sync pin; plain matching data
    // cannot construct this view or turn it into a thread-safe capability.
    _pin: &'a CreatedAddressReadPin,
}
// Only this actual RowOwner's capture/persist paths can populate the mirror.
// Matching JSON, GUIDs or reopened journals cannot construct an original pin.
struct RowRecordReceipt {
    binding: Binding,
    acknowledged: RefCell<Option<Rc<Record>>>,
    write_attempt: RefCell<Option<Rc<RowWriteAttempt>>>,
    revoked: Cell<bool>,
    initial: RefCell<Option<Rc<InitialRowCaptureAttempt>>>,
    native_effects_started: Cell<bool>,
}
// Original invocation facts, NOT a write ACK, durable adoption or native effect
// grant. Rooted by persist BEFORE CAS; previous unknown attempts stay retained.
struct RowWriteAttempt {
    before: Record,
    desired: Record,
    confirmed: Cell<bool>,
    _previous: Option<Rc<RowWriteAttempt>>,
}
pub(crate) struct RowWriteAttemptFacts<'a> {
    pub binding: &'a Binding,
    pub acknowledged: &'a Record,
    pub before: &'a Record,
    pub desired: &'a Record,
    _pin: &'a RowRecordReadPin,
}
/// Historical original capture/CAS facts ONLY, never ownership/effect authority.
/// No Clone, serialization or import constructor. Rc makes this !Send + !Sync.
pub(crate) struct RowRecordReadPin {
    original: Rc<RowRecordReceipt>,
}
/// Immutable original member-row Stop history, NOT current native absence,
/// journal reuse or effect authority. Issued only by the actual RowOwner after
/// its successful terminal CAS and independently bracketed baseline readback.
pub(crate) struct StoppedRowGeneration {
    original: Rc<RowRecordReceipt>,
    stopped: Rc<Record>,
    acknowledged: Cell<bool>,
}
impl StoppedRowGeneration {
    fn verify(&self) -> Result<()> {
        if !self.acknowledged.get() {
            return Err(Error::Pending);
        }
        self.verify_receipt()
    }
    fn verify_receipt(&self) -> Result<()> {
        if self.stopped.binding.role == Role::Carrier
            || self.stopped.phase != Phase::Stopped
            || self.stopped.pending.is_some()
            || self.stopped.binding != self.original.binding
            || self.stopped.current.address.is_some()
            || self.stopped.current.interface.policy != self.stopped.baseline.interface.policy
            || self
                .original
                .acknowledged
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .as_ref()
                .is_none_or(|ack| !Rc::ptr_eq(ack, &self.stopped))
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    /// SAME original only; no old private journal or deleted-interface query.
    /// The caller separately proves its held owner, new generation and full
    /// current SDK universe before this historical fact is used in storage.
    pub(crate) fn inspect_original<T>(
        &self,
        pin: &RowRecordReadPin,
        inspect: impl FnOnce(&Record) -> Result<T>,
    ) -> Result<T> {
        self.verify()?;
        if !Rc::ptr_eq(&self.original, &pin.original) {
            return Err(Error::Conflict);
        }
        let result = inspect(&self.stopped);
        self.verify()?;
        result
    }
}
/// The actual last successfully acknowledged durable record. Pending remains
/// pending, and even Stopped is only an ACK fact, not proof of native cleanup.
pub(crate) struct RowRecordFacts<'a> {
    pub binding: &'a Binding,
    pub acknowledged: &'a Record,
    /// Sticky revocation or acknowledged Closing/Stopped; never a cleanup grant.
    pub cleanup_only: bool,
    _pin: &'a RowRecordReadPin,
}
impl RowRecordReadPin {
    /// Immutable original binding fact only, even when the initial ACK is None.
    pub(crate) fn binding_original(&self) -> &Binding {
        &self.original.binding
    }
    /// Provenance equality, not value equality of scope/GUID/record bytes.
    pub(crate) fn same_original(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.original, &other.original)
    }
    /// Factual unknown-write obligation from THIS original owner only. Caller
    /// must independently hold the actual Closing/runtime/SDK/effect bracket
    /// and compare protected bytes; attempted data never replaces last ACK or
    /// supplies ownership, forward permission, successful cleanup or absence.
    /// No Authority, journal, kernel or native call is made in this callback.
    pub(crate) fn with_cleanup_write_attempt<T>(
        &self,
        scope: &SessionScope,
        live_epoch: u64,
        read: impl FnOnce(RowWriteAttemptFacts<'_>) -> Result<T>,
    ) -> Result<T> {
        let mut operation = RowRecordOperation::new(&self.original);
        let binding = &self.original.binding;
        if binding.scope != *scope || binding.network_epoch != live_epoch {
            return Err(Error::Conflict);
        }
        let acknowledged = self
            .original
            .acknowledged
            .try_borrow()
            .map_err(|_| Error::Conflict)?
            .clone()
            .ok_or(Error::Journal)?;
        let attempt = self
            .original
            .write_attempt
            .try_borrow()
            .map_err(|_| Error::Conflict)?
            .clone()
            .ok_or(Error::Pending)?;
        if attempt.confirmed.get()
            || attempt.before.binding != *binding
            || attempt.desired.binding != *binding
            || acknowledged.binding != *binding
        {
            return Err(Error::Conflict);
        }
        let value = read(RowWriteAttemptFacts {
            binding,
            acknowledged: &acknowledged,
            before: &attempt.before,
            desired: &attempt.desired,
            _pin: self,
        })?;
        if attempt.confirmed.get()
            || !self
                .original
                .write_attempt
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .as_ref()
                .is_some_and(|current| Rc::ptr_eq(current, &attempt))
            || !self
                .original
                .acknowledged
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .as_ref()
                .is_some_and(|current| Rc::ptr_eq(current, &acknowledged))
        {
            return Err(Error::Conflict);
        }
        operation.completed = true;
        Ok(value)
    }
    /// Call inside the SAME actual original/runtime/native-read window, then
    /// independently compare protected row bytes and full SDK observations.
    /// This callback performs NO Authority, journal, kernel or native queries.
    /// Error/unwind and caught nested revocation permanently deny forward reads.
    pub(crate) fn with_record<T>(
        &self,
        scope: &SessionScope,
        live_epoch: u64,
        read: impl FnOnce(RowRecordFacts<'_>) -> Result<T>,
    ) -> Result<T> {
        self.inspect(scope, live_epoch, false, read)
    }
    /// Cleanup comparison facts survive failure, stop and owner Drop. Caller
    /// MUST independently hold the actual Closing/runtime/original/SDK bracket.
    /// This method does not authenticate that bracket, synthesize successful
    /// cleanup, import a receipt, rearm live use or authorize any effect.
    pub(crate) fn with_cleanup_record<T>(
        &self,
        scope: &SessionScope,
        live_epoch: u64,
        read: impl FnOnce(RowRecordFacts<'_>) -> Result<T>,
    ) -> Result<T> {
        self.inspect(scope, live_epoch, true, read)
    }
    fn inspect<T>(
        &self,
        scope: &SessionScope,
        live_epoch: u64,
        cleanup: bool,
        read: impl FnOnce(RowRecordFacts<'_>) -> Result<T>,
    ) -> Result<T> {
        let mut operation = RowRecordOperation::new(&self.original);
        if !cleanup && self.original.revoked.get() {
            return Err(Error::Retired);
        }
        let binding = &self.original.binding;
        // Comparison fences only; saved context is not live runtime proof.
        if binding.scope != *scope || binding.network_epoch != live_epoch {
            return Err(Error::Conflict);
        }
        // Release the interior borrow before the callback. An independently
        // retained immutable ACK survives nested reads and owner failure/Drop.
        let acknowledged = self
            .original
            .acknowledged
            .borrow()
            .as_ref()
            .cloned()
            .ok_or(Error::Journal)?;
        let cleanup_only = self.original.revoked.get() || acknowledged.phase != Phase::Captured;
        if !cleanup && cleanup_only {
            return Err(Error::Retired);
        }
        let value = read(RowRecordFacts {
            binding,
            acknowledged: &acknowledged,
            cleanup_only,
            _pin: self,
        })?;
        if !cleanup && self.original.revoked.get() {
            return Err(Error::Retired);
        }
        // Do not return a stale successful comparison if the callback advanced
        // the owner's ACK. It must join the same actual observation window.
        if !self
            .original
            .acknowledged
            .borrow()
            .as_ref()
            .is_some_and(|current| Rc::ptr_eq(current, &acknowledged))
        {
            return Err(Error::Conflict);
        }
        operation.completed = true;
        Ok(value)
    }
}
struct RowRecordOperation {
    original: Rc<RowRecordReceipt>,
    completed: bool,
}
impl RowRecordOperation {
    fn new(original: &Rc<RowRecordReceipt>) -> Self {
        Self {
            original: Rc::clone(original),
            completed: false,
        }
    }
}
impl Drop for RowRecordOperation {
    fn drop(&mut self) {
        if !self.completed {
            self.original.revoked.set(true);
        }
    }
}
impl CreatedAddressReadPin {
    pub(crate) fn read(
        &self,
        scope: &SessionScope,
        live_epoch: u64,
    ) -> Result<CreatedAddressFacts<'_>> {
        if self.revoked.get() {
            return Err(Error::Retired);
        }
        let binding = &self.receipt.binding;
        // Arguments are comparison fences, not proof of a live runtime/creator.
        if binding.role != Role::Carrier
            || binding.scope != *scope
            || binding.network_epoch != live_epoch
        {
            self.revoked.set(true);
            return Err(Error::Conflict);
        }
        Ok(CreatedAddressFacts {
            binding,
            captured: &self.receipt.row,
            _pin: self,
        })
    }
}
struct ReadPinOperation {
    revoked: Rc<Cell<bool>>,
    completed: bool,
}
impl ReadPinOperation {
    fn new(revoked: &Rc<Cell<bool>>) -> Self {
        Self {
            revoked: Rc::clone(revoked),
            completed: false,
        }
    }
}
impl Drop for ReadPinOperation {
    fn drop(&mut self) {
        if !self.completed {
            self.revoked.set(true);
        }
    }
}
impl<A, K, J> Drop for RowOwner<A, K, J> {
    fn drop(&mut self) {
        // Revoke before Rust drops the original authority field, including
        // callbacks/unwinds in its destructor. No cleanup effect is issued.
        self.state.read_pin_revoked.set(true);
        self.state.record_receipt.revoked.set(true);
    }
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
    pub(crate) fn inspect_original_authority<T>(
        &self,
        inspect: impl FnOnce(&A, &RowRecordReadPin) -> Result<T>,
    ) -> Result<T> {
        // Pure original identity, never an ACK/native effect/readiness grant.
        // Even an unacknowledged baseline retains this private receipt; its
        // ACK-reading methods independently deny when acknowledged is None.
        let original = RowRecordReadPin {
            original: self.state.record_receipt.clone(),
        };
        inspect(&self.authority, &original)
    }
    pub(crate) fn capture_with_record_pin_into(
        slot: &mut RowCaptureSlot<A, K, J>,
        retain: impl FnOnce(RowRecordReadPin) -> Result<()>,
    ) -> Result<()> {
        if slot.attempted {
            return Err(Error::Retired);
        }
        slot.attempted = true; // before validation, callbacks, IO or unwind
        slot.binding.validate()?;
        let authority = slot.authority.as_mut().ok_or(Error::Retired)?;
        let binding = &slot.binding;
        let unprepared = &mut slot.unprepared;
        let rooted = &mut slot.state;
        let result = authority.locked(|creator| {
            let (kernel, journal) = unprepared.as_mut().ok_or(Error::Retired)?;
            if journal.load(binding)?.is_some() {
                return Err(Error::Retired);
            }
            let baseline = read(creator, kernel, binding)?;
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
            let receipt = Rc::new(RowRecordReceipt {
                binding: binding.clone(),
                acknowledged: RefCell::new(None),
                write_attempt: RefCell::new(None),
                revoked: Cell::new(false),
                initial: RefCell::new(Some(Rc::new(InitialRowCaptureAttempt {
                    payload: record.encode()?,
                    record: record.clone(),
                    invoked: Cell::new(false),
                    acknowledged: Cell::new(false),
                }))),
                native_effects_started: Cell::new(false),
            });
            let (kernel, journal) = unprepared.take().ok_or(Error::Retired)?;
            *rooted = Some(OwnedRows {
                binding: binding.clone(),
                kernel,
                journal,
                record,
                failed: true, // stays closed until full actual postflight
                creation: None,
                address_ready: false,
                read_pin_revoked: Rc::new(Cell::new(false)),
                record_receipt: receipt.clone(),
                stopped_generation: None,
            }); // original baseline + K/J rooted BEFORE first CAS
            let state = rooted.as_mut().ok_or(Error::Retired)?;
            let mut operation = RowRecordOperation::new(&receipt);
            receipt
                .initial
                .borrow()
                .as_ref()
                .ok_or(Error::Pending)?
                .invoked
                .set(true);
            let ack = state.journal.compare_exchange(binding, None, &state.record);
            if ack.is_err() {
                state.read_pin_revoked.set(true);
                receipt.revoked.set(true);
            }
            if state.journal.load(binding)?.as_ref() != Some(&state.record) {
                return Err(Error::Journal);
            }
            ack?; // equal bytes NEVER redeem a lost initial CAS ACK
            *receipt.acknowledged.borrow_mut() = Some(Rc::new(state.record.clone()));
            receipt
                .initial
                .borrow()
                .as_ref()
                .ok_or(Error::Pending)?
                .acknowledged
                .set(true);
            retain(RowRecordReadPin {
                original: receipt.clone(),
            })?;
            let after = read(creator, &mut state.kernel, binding)?;
            if !same_owned(&after, &state.record.current) {
                return Err(Error::Conflict);
            }
            operation.completed = true;
            Ok(())
        });
        if result.is_ok() {
            slot.state.as_mut().ok_or(Error::Retired)?.failed = false;
            slot.completed = true;
        }
        result
    }
    pub(crate) fn capture_into(slot: &mut RowCaptureSlot<A, K, J>) -> Result<()> {
        Self::capture_with_record_pin_into(slot, |_| Ok(()))
    }
    /// Storage-only handoff in the SAME retained owner. The native caller must
    /// supply its actual canonical cleanup view; the journal must authenticate
    /// that original backend/birth lineage. No native read/effect, record ACK,
    /// original-pin replacement or forward rearm is performed here.
    pub(crate) fn enter_storage_cleanup(
        &mut self,
        handoff: impl FnOnce(&mut J) -> Result<()>,
    ) -> Result<()> {
        // Revoke BEFORE callback, including error/unwind. Actual cleanup still
        // requires this owner's independent original/native Authority gates.
        self.state.failed = true;
        self.state.read_pin_revoked.set(true);
        self.state.record_receipt.revoked.set(true);
        handoff(&mut self.state.journal)
    }
    pub(crate) fn record_read_pin(&self) -> Result<RowRecordReadPin> {
        // Issuance is factual only and does not call the original authority.
        // A revoked owner may still hand its SAME receipt to cleanup readers.
        if self.state.record_receipt.acknowledged.borrow().is_none() {
            return Err(Error::Journal);
        }
        Ok(RowRecordReadPin {
            original: Rc::clone(&self.state.record_receipt),
        })
    }
    pub(crate) fn created_address_read_pin(&mut self) -> Result<CreatedAddressReadPin> {
        if self.state.failed
            || self.state.read_pin_revoked.get()
            || self.state.binding.role != Role::Carrier
            || self.state.record.phase != Phase::Captured
        {
            self.state.read_pin_revoked.set(true);
            return Err(Error::Retired);
        }
        // Asking before waitReady is not an operation failure: caller can still
        // wait. Preferred native data alone cannot import a readiness receipt.
        if !self.state.address_ready {
            return Err(Error::Pending);
        }
        self.run(|state, creator| {
            state.require_durable()?;
            if state.record.pending.is_some() {
                return Err(Error::Pending);
            }
            state.require_receipt()?;
            let live = read(creator, &mut state.kernel, &state.binding)?;
            if !same_owned(&live, &state.record.current) {
                return Err(Error::Conflict);
            }
            let row = live.address.as_ref().ok_or(Error::Conflict)?;
            let receipt = state.creation.as_ref().ok_or(Error::Pending)?;
            if !same_address(row, &receipt.row) || row.observed.dad_state != 4 {
                return Err(Error::Conflict);
            }
            state.require_durable()?;
            state.require_receipt()?;
            // A nested G pin read can fail and be caught during the native
            // callback above. Its shared revocation still denies this issuance.
            if state.read_pin_revoked.get() {
                return Err(Error::Retired);
            }
            Ok(CreatedAddressReadPin {
                receipt: Rc::clone(state.creation.as_ref().ok_or(Error::Pending)?),
                revoked: Rc::clone(&state.read_pin_revoked),
            })
        })
    }
    /// Requires a live original adapter creator plus fresh journal/address absence.
    /// Saved bytes never open/adopt a device. There is intentionally no JSON-only
    /// recovery constructor; protected schema/recovery composition remains Task5.
    pub(crate) fn capture(binding: Binding, authority: A, kernel: K, journal: J) -> Result<Self> {
        Self::capture_with_record_pin(binding, authority, kernel, journal, |_| Ok(()))
    }
    /// Retain the original factual pin immediately after the baseline's actual
    /// successful CAS + exact reread, BEFORE fallible native postflight. This
    /// callback runs under the existing Authority lock and must not reenter it.
    /// If postflight/handoff errors or unwinds, a handed pin remains cleanup-only
    /// for the caller's independently actual original/Closing/runtime/SDK window.
    /// A lost baseline CAS ACK invokes no handoff; equal bytes cannot import it.
    pub(crate) fn capture_with_record_pin(
        binding: Binding,
        mut authority: A,
        mut kernel: K,
        mut journal: J,
        retain: impl FnOnce(RowRecordReadPin) -> Result<()>,
    ) -> Result<Self> {
        binding.validate()?;
        let read_pin_revoked = Rc::new(Cell::new(false));
        let record_receipt = Rc::new(RowRecordReceipt {
            binding: binding.clone(),
            acknowledged: RefCell::new(None),
            write_attempt: RefCell::new(None),
            revoked: Cell::new(false),
            initial: RefCell::new(None),
            native_effects_started: Cell::new(false),
        });
        let mut record_operation = RowRecordOperation::new(&record_receipt);
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
            *record_receipt.initial.borrow_mut() = Some(Rc::new(InitialRowCaptureAttempt {
                payload: record.encode()?,
                record: record.clone(),
                invoked: Cell::new(true),
                acknowledged: Cell::new(false),
            }));
            let ack = journal.compare_exchange(&binding, None, &record);
            if ack.is_err() {
                read_pin_revoked.set(true);
                record_receipt.revoked.set(true);
            }
            if journal.load(&binding)?.as_ref() != Some(&record) {
                return Err(Error::Journal);
            }
            if ack.is_ok() {
                // Publish after exact CAS ACK+reread, BEFORE native postflight.
                *record_receipt.acknowledged.borrow_mut() = Some(Rc::new(record.clone()));
                record_receipt
                    .initial
                    .borrow()
                    .as_ref()
                    .ok_or(Error::Pending)?
                    .acknowledged
                    .set(true);
                retain(RowRecordReadPin {
                    original: Rc::clone(&record_receipt),
                })?;
            }
            let after = read(creator, &mut kernel, &binding)?;
            if !same_owned(&after, &record.current) {
                return Err(Error::Conflict);
            }
            Ok(record)
        })?;
        record_operation.completed = true;
        Ok(Self {
            authority,
            state: OwnedRows {
                binding,
                kernel,
                journal,
                record,
                // A matching baseline reread cannot redeem a lost capture ACK.
                failed: record_receipt.revoked.get(),
                creation: None,
                address_ready: false,
                read_pin_revoked,
                record_receipt,
                stopped_generation: None,
            },
        })
    }
    pub(crate) fn seal_stopped_generation(&mut self) -> Result<Rc<StoppedRowGeneration>> {
        self.seal_stopped_generation_with_pin(|_| Ok(()))
    }
    /// Caller roots the SAME inert seal before fallible native postflight. A
    /// failed/unwound read cannot issue an acknowledged seal or rearm forward
    /// pins. Only an explicit retry against this actual owner can finish it.
    pub(crate) fn seal_stopped_generation_with_pin(
        &mut self,
        retain: impl FnOnce(Rc<StoppedRowGeneration>) -> Result<()>,
    ) -> Result<Rc<StoppedRowGeneration>> {
        if let Some(seal) = &self.state.stopped_generation {
            if seal.acknowledged.get() {
                seal.verify()?;
                return Ok(seal.clone());
            }
        }
        self.run(|state, creator| {
            if !matches!(state.binding.role, Role::MemberA | Role::MemberB)
                || state.record.phase != Phase::Stopped
                || state.record.pending.is_some()
                || state.record.current.address.is_some()
                || state.record.current.interface.policy != state.record.baseline.interface.policy
            {
                return Err(Error::Conflict);
            }
            state.require_durable()?;
            let ack = state
                .record_receipt
                .acknowledged
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .as_ref()
                .cloned()
                .ok_or(Error::Pending)?;
            if *ack != state.record {
                return Err(Error::Conflict);
            }
            let seal = if let Some(seal) = &state.stopped_generation {
                if !Rc::ptr_eq(&seal.original, &state.record_receipt)
                    || !Rc::ptr_eq(&seal.stopped, &ack)
                {
                    return Err(Error::Conflict);
                }
                seal.clone()
            } else {
                let seal = Rc::new(StoppedRowGeneration {
                    original: state.record_receipt.clone(),
                    stopped: ack,
                    acknowledged: Cell::new(false),
                });
                state.stopped_generation = Some(seal.clone());
                seal
            };
            retain(seal.clone())?;
            let live = read(creator, &mut state.kernel, &state.binding)?;
            if !same_owned(&live, &state.record.current) || live.address.is_some() {
                return Err(Error::Conflict);
            }
            state.require_durable()?;
            // No callback/effect/fallible native operation after issuance.
            seal.verify_receipt()?;
            seal.acknowledged.set(true);
            Ok(seal)
        })
    }
    fn run<T>(
        &mut self,
        action: impl FnOnce(&mut OwnedRows<K, J>, &mut A::Creator) -> Result<T>,
    ) -> Result<T> {
        let was_failed = self.state.failed;
        let mut pin_operation = ReadPinOperation::new(&self.state.read_pin_revoked);
        let mut record_operation = RowRecordOperation::new(&self.state.record_receipt);
        if was_failed {
            self.state.read_pin_revoked.set(true);
            self.state.record_receipt.revoked.set(true);
        }
        // Unwind/lost ACK is cleanup-only, even when a caller catches a panic.
        self.state.failed = true;
        let state = &mut self.state;
        let result = self.authority.locked(|creator| action(state, creator));
        if result.is_ok() && !was_failed && self.state.record.phase == Phase::Captured {
            self.state.failed = false;
        }
        pin_operation.completed = result.is_ok();
        record_operation.completed = result.is_ok();
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
        let mut pin_operation = ReadPinOperation::new(&self.state.read_pin_revoked);
        let mut record_operation = RowRecordOperation::new(&self.state.record_receipt);
        // Cover cancellation, timeout, errors AND unwinding during read/sleep.
        // Only successful readiness of an originally live owner clears this.
        self.state.failed = true;
        if was_failed || self.state.read_pin_revoked.get() {
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
            self.state.address_ready = true;
        }
        pin_operation.completed = result.is_ok();
        record_operation.completed = result.is_ok();
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
    pub(crate) fn restore_interface_for_cleanup(&mut self) -> Result<()> {
        // Stage 3 must keep the original C address for exact later member/DNS
        // cleanup. This never deletes an address or acknowledges terminal Stop.
        self.state.read_pin_revoked.set(true);
        self.state.record_receipt.revoked.set(true);
        self.run(|state, creator| {
            state.require_cleanup_durable(creator)?;
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
            let after = read(creator, &mut state.kernel, &state.binding)?;
            if !same_owned(&after, &state.record.current)
                || after.interface.policy != state.record.baseline.interface.policy
                || state.record.pending.is_some()
            {
                return Err(Error::Conflict);
            }
            state.require_durable()?;
            Ok(())
        })
    }
    pub(crate) fn stop(&mut self) -> Result<()> {
        // Stop entry revokes even if its first read/persist fails or unwinds.
        self.state.read_pin_revoked.set(true);
        self.state.record_receipt.revoked.set(true);
        self.run(|state, creator| {
            state.require_cleanup_durable(creator)?;
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
impl<A: Authority, K: Kernel, J: CreatedAddressCleanupJournal> RowOwner<A, K, J> {
    pub(crate) fn reconcile_created_address_for_cleanup(&mut self) -> Result<()> {
        self.state.read_pin_revoked.set(true);
        self.state.record_receipt.revoked.set(true);
        self.run(|state, creator| {
            let receipt = state.creation.clone().ok_or(Error::Pending)?;
            let expected = state.journal.load(&state.binding)?.ok_or(Error::Journal)?;
            let acknowledged = state
                .record_receipt
                .acknowledged
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .clone()
                .ok_or(Error::Journal)?;
            let attempted = state
                .record_receipt
                .write_attempt
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .clone();
            // Actual original ACK or THIS retained invocation, not arbitrary
            // equal JSON loaded by another owner. No ACK is advanced here.
            let mut cursor = attempted;
            let mut original_attempt = false;
            while let Some(a) = cursor {
                if !a.confirmed.get()
                    && a.desired == expected
                    && (a.before == state.record || a.desired == state.record)
                {
                    original_attempt = true;
                    break;
                }
                // A failed new Calling attempt must not hide an older SAME
                // rooted lost-CAS desired still in storage. This is invocation
                // history only, not an ACK or adoption of arbitrary saved bytes.
                cursor = a._previous.clone();
            }
            if expected != *acknowledged && !original_attempt {
                return Err(Error::Conflict);
            }
            let live = read(creator, &mut state.kernel, &state.binding)?;
            let mut desired = expected.clone();
            desired.revision = expected.revision.checked_add(1).ok_or(Error::Retired)?;
            desired.phase = Phase::Closing;
            desired.current = live.clone();
            desired.pending = None;
            desired.creation = Some(receipt.row.clone());
            let proof = CreatedAddressCleanupRead {
                receipt: &receipt,
                record_original: &state.record_receipt,
                expected: &expected,
                desired: &desired,
                native: &live,
            };
            proof.verify_exchange(&state.binding, &expected, &desired)?;
            if state.journal.load(&state.binding)?.as_ref() != Some(&expected)
                || read(creator, &mut state.kernel, &state.binding)? != live
            {
                return Err(Error::Conflict);
            }
            let attempt = {
                let mut retained = state
                    .record_receipt
                    .write_attempt
                    .try_borrow_mut()
                    .map_err(|_| Error::Conflict)?;
                let attempt = Rc::new(RowWriteAttempt {
                    before: expected.clone(),
                    desired: desired.clone(),
                    confirmed: Cell::new(false),
                    _previous: retained.clone(),
                });
                *retained = Some(attempt.clone()); // before typed CAS/readback
                attempt
            };
            let ack = state.journal.compare_exchange_created_cleanup(
                &state.binding,
                &expected,
                &desired,
                &proof,
            );
            if state.journal.load(&state.binding)?.as_ref() != Some(&desired) {
                return Err(Error::Journal);
            }
            state.record = desired.clone(); // obligation, not an ACK
            ack?;
            *state.record_receipt.acknowledged.borrow_mut() = Some(Rc::new(desired.clone()));
            attempt.confirmed.set(true); // NEW actual CAS ACK + exact reread only
            if read(creator, &mut state.kernel, &state.binding)? != live
                || state.journal.load(&state.binding)?.as_ref() != Some(&desired)
            {
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
    /// Cleanup-only reconciliation of THIS owner's original attempted storage
    /// write when its post-CAS read failed. Does not import an ACK, address
    /// creation or writer from saved bytes, and performs no native effect.
    fn require_cleanup_durable<C: OriginalCreator>(&mut self, creator: &mut C) -> Result<()> {
        self.record.validate()?;
        let current = self.journal.load(&self.binding)?.ok_or(Error::Journal)?;
        if current == self.record {
            return Ok(());
        }
        if !self.read_pin_revoked.get() || !self.record_receipt.revoked.get() {
            return Err(Error::Retired);
        }
        let attempt = self
            .record_receipt
            .write_attempt
            .try_borrow()
            .map_err(|_| Error::Conflict)?
            .clone()
            .ok_or(Error::Journal)?;
        if attempt.confirmed.get()
            || attempt.before != self.record
            || attempt.desired != current
            || current.binding != self.binding
            || current.baseline != self.record.baseline
            || current.creation != self.record.creation
        {
            return Err(Error::Conflict);
        }
        // This lane may not recreate/adopt pending Create/Delete authority.
        // Their own original effect receipts and existing resolution remain
        // separate. Only exact interface intent/confirmation or phase writes.
        for record in [&attempt.before, &attempt.desired] {
            if record
                .pending
                .as_ref()
                .is_some_and(|p| !matches!(p.target, Target::Interface(_)))
            {
                return Err(Error::Pending);
            }
        }
        validate_transition(Some(&attempt.before), &current, false)?;
        if self.record.current.address.is_some() {
            self.require_receipt()?; // genuine retained SDK Create ACK, never imported
        }
        let live = read(creator, &mut self.kernel, &self.binding)?;
        let matches = if let Some(pending) = &current.pending {
            let Target::Interface(policy) = &pending.target else {
                return Err(Error::Pending);
            };
            let mut applied = pending.before.clone();
            applied.interface.policy = policy.clone();
            same_owned(&live, &pending.before) || same_owned(&live, &applied)
        } else {
            same_owned(&live, &current.current)
        };
        if !matches
            || self.journal.load(&self.binding)?.as_ref() != Some(&current)
            || read(creator, &mut self.kernel, &self.binding)? != live
        {
            return Err(Error::Conflict);
        }
        // Local obligation only. SAME actual last ACK and original attempt stay
        // untouched. A NEW Closing CAS must succeed before any cleanup effect.
        self.record = current;
        Ok(())
    }
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
        let attempt = {
            let mut retained = self
                .record_receipt
                .write_attempt
                .try_borrow_mut()
                .map_err(|_| Error::Conflict)?;
            let attempt = Rc::new(RowWriteAttempt {
                before: self.record.clone(),
                desired: desired.clone(),
                confirmed: Cell::new(false),
                _previous: retained.as_ref().and_then(|old| {
                    if old.confirmed.get() {
                        old._previous.clone() // do not discard older unknown obligations
                    } else {
                        Some(old.clone())
                    }
                }),
            });
            *retained = Some(attempt.clone()); // BEFORE raw CAS or any readback
            attempt
        };
        let ack = self
            .journal
            .compare_exchange(&self.binding, Some(&self.record), &desired);
        if ack.is_err() {
            self.read_pin_revoked.set(true);
            self.record_receipt.revoked.set(true);
        }
        if self.journal.load(&self.binding)?.as_ref() != Some(&desired) {
            return Err(Error::Journal);
        }
        if ack.is_ok() {
            *self.record_receipt.acknowledged.borrow_mut() = Some(Rc::new(desired.clone()));
            attempt.confirmed.set(true); // only actual CAS ACK AND exact reread
        }
        // Exact reread retains the cleanup obligation, but cannot manufacture
        // a successful CAS ACK. Stop the forward operation at this boundary.
        self.record = desired;
        ack
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
    fn confirm<C: OriginalCreator>(
        &mut self,
        creator: &mut C,
        live: Snapshot,
        cleanup: bool,
    ) -> Result<()> {
        let mut desired = self.record.clone();
        desired.current = live;
        desired.pending = None;
        if cleanup
            && self
                .record
                .pending
                .as_ref()
                .is_some_and(|p| !matches!(p.target, Target::Create(_)))
        {
            // A cleanup view cannot persist Captured/forward continuation.
            // Pending Create still requires its existing own-create ACK path;
            // cleanup must never manufacture that creation history.
            desired.phase = Phase::Closing;
        }
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
        // Native/provider reads can be slow and can expose outside changes.
        // The exact protected pending revision must still be ours AFTER them,
        // not merely before authorization. A drift cannot reach the OS effect.
        self.require_durable()?;
        let ack = match &target {
            Target::Interface(p) => {
                let initialized = self.kernel.initialize_interface();
                let mut row = interface_input(initialized, self.binding.key, p)?;
                self.require_durable()?;
                self.record_receipt.native_effects_started.set(true);
                self.kernel.set_interface(&mut row)
            }
            Target::Create(p) => {
                let initialized = self.kernel.initialize_address();
                let row = address_input(initialized, self.binding.key, p)?;
                self.require_durable()?;
                self.record_receipt.native_effects_started.set(true);
                self.kernel.create_address(&row)
            }
            Target::Delete => {
                self.require_receipt()?;
                let current = exact.address.as_ref().ok_or(Error::Conflict)?;
                let initialized = self.kernel.initialize_address();
                let row = address_input(initialized, self.binding.key, &current.policy)?;
                self.require_durable()?;
                self.record_receipt.native_effects_started.set(true);
                self.kernel.delete_address(&row)
            }
        };
        if ack.is_err() {
            self.read_pin_revoked.set(true);
            self.record_receipt.revoked.set(true);
        }
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
            self.creation = Some(Rc::new(CreatedAddressReceipt {
                binding: self.binding.clone(),
                row: row.clone(),
                before: pending.before.clone(),
                baseline: self.record.baseline.clone(),
            }));
        }
        if !self.target_matches(&after, &pending) {
            return Err(Error::Pending);
        }
        self.confirm(creator, after, false)
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
        self.confirm(creator, live, true)
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
    // Construct only the real SDK boundary, never an authority or row owner.
    pub(super) fn read_original_snapshot(binding: &Binding) -> Result<Snapshot> {
        read_original_snapshot_with(&mut IpHelper { _private: () }, binding)
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
        pub(crate) fn capture_native_with_record_pin_into(
            slot: &mut RowCaptureSlot<A, IpHelper, J>,
            retain: impl FnOnce(RowRecordReadPin) -> Result<()>,
        ) -> Result<()> {
            Self::capture_with_record_pin_into(slot, retain)
        }
        pub(crate) fn capture_native(binding: Binding, authority: A, journal: J) -> Result<Self> {
            Self::capture(binding, authority, IpHelper { _private: () }, journal)
        }
        pub(crate) fn capture_native_with_record_pin(
            binding: Binding,
            authority: A,
            journal: J,
            retain: impl FnOnce(RowRecordReadPin) -> Result<()>,
        ) -> Result<Self> {
            Self::capture_with_record_pin(
                binding,
                authority,
                IpHelper { _private: () },
                journal,
                retain,
            )
        }
    }
    impl<A, J> RowCaptureSlot<A, IpHelper, J> {
        pub(crate) fn new_native(binding: Binding, authority: A, journal: J) -> Self {
            Self::new(binding, authority, IpHelper { _private: () }, journal)
        }
    }
}
#[cfg(test)]
#[path = "member_carrier_rows_tests.rs"]
pub(crate) mod tests;

#[cfg(windows)]
pub(crate) type NativeRowOwner<A, J> = RowOwner<A, ip_helper::IpHelper, J>;
#[cfg(windows)]
pub(crate) type NativeRowCaptureSlot<A, J> = RowCaptureSlot<A, ip_helper::IpHelper, J>;
#[cfg(windows)]
pub(crate) type NativeRowCaptureSlotStopped<A, J> =
    RowCaptureSlotStopped<A, ip_helper::IpHelper, J>;
