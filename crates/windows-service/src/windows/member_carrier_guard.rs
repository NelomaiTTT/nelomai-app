//! Unselected native v2 carrier/egress guard. No factory caller.
//! Codec contracts: Microsoft fwpmtypes.h/fwptypes.h/fwpmu.h, SDK-backed
//! windows-sys 0.61.2. No custom packed layout or FFI signature is invented.
//! https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
//! https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer
//! https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
//! Snapshots are neither traffic acceptance nor foreign-priority arbitration.
//! &mut owner access serializes both engines; the future factory must ALSO hold
//! carrier/member/network/socket ownership across these separate commits.
#![allow(dead_code)]

use crate::member_carrier_guard::{
    Action, Carrier, Condition, Filter, GuardError, Identity, Key, Layer, Model, Result,
    SessionKind, Snapshot, SplitEngines, Sublayer,
};
use nelomai_client_tunnel::redundancy::SessionScope;
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};
use windows_sys::{core::GUID, Win32::NetworkManagement::WindowsFilteringPlatform::*};

pub(crate) const NAME: &str = "Nelomai carrier guard v2";

pub(crate) fn guid(value: Key) -> GUID {
    GUID::from_u128(u128::from_be_bytes(value.0))
}
pub(crate) fn key(value: GUID) -> Key {
    let mut bytes = [0; 16];
    bytes[..4].copy_from_slice(&value.data1.to_be_bytes());
    bytes[4..6].copy_from_slice(&value.data2.to_be_bytes());
    bytes[6..8].copy_from_slice(&value.data3.to_be_bytes());
    bytes[8..].copy_from_slice(&value.data4);
    Key(bytes)
}

#[derive(Clone, Debug)]
pub(crate) struct NativeFilter {
    pub policy: Filter,
    pub id: u64,
}
pub(crate) struct EncodedFilter {
    pub raw: FWPM_FILTER0,
    _conditions: Vec<FWPM_FILTER_CONDITION0>,
    _name: Vec<u16>,
    _weight: Box<u64>,
    _backing: Backing,
}
#[derive(Default)]
#[allow(clippy::vec_box)] // FFI pointees must survive moves/reallocation of the owner.
struct Backing {
    words: Vec<Box<u64>>,
    addresses: Vec<Box<FWP_BYTE_ARRAY16>>,
}
impl EncodedFilter {
    pub(crate) fn new(filter: &Filter) -> Result<Self> {
        validate_action(filter.layer, filter.action, filter.flags, filter.weight)?;
        let mut backing = Backing::default();
        let mut conditions = filter
            .conditions
            .iter()
            .map(|c| encode_condition(c, filter.layer, &mut backing))
            .collect::<Result<Vec<_>>>()?;
        if conditions.is_empty()
            || conditions.len() > 8
            || conditions.iter().enumerate().any(|(i, c)| {
                conditions[..i]
                    .iter()
                    .any(|p| key(p.fieldKey) == key(c.fieldKey))
            })
        {
            return Err(GuardError::Invalid);
        }
        let mut name: Vec<_> = NAME.encode_utf16().chain(Some(0)).collect();
        let mut weight = Box::new(filter.weight);
        let raw = FWPM_FILTER0 {
            filterKey: guid(filter.key),
            subLayerKey: guid(filter.sublayer),
            layerKey: layer_guid(filter.layer),
            flags: filter.flags,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: ptr::null_mut(),
            },
            weight: FWP_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_VALUE0_0 {
                    uint64: &mut *weight,
                },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: if filter.action == Action::Block {
                    FWP_ACTION_BLOCK
                } else {
                    FWP_ACTION_PERMIT
                },
                ..Default::default()
            },
            ..Default::default()
        };
        Ok(Self {
            raw,
            _conditions: conditions,
            _name: name,
            _weight: weight,
            _backing: backing,
        })
    }
}
/// Safety: every non-null pointee must be live BFE-owned memory (or the owned
/// EncodedFilter fixture) for this synchronous decode. Never call on JSON bytes.
pub(crate) unsafe fn decode_filter(
    raw: &FWPM_FILTER0,
    expected_key: Key,
    sublayer: Key,
) -> Result<NativeFilter> {
    if key(raw.filterKey) != expected_key
        || key(raw.subLayerKey) != sublayer
        || !raw.providerKey.is_null()
        || raw.providerData.size != 0
        || !raw.providerData.data.is_null()
        || !raw.reserved.is_null()
        || !unsafe { display_matches(&raw.displayData) }
        || unsafe { raw.Anonymous.rawContext } != 0
        || key(unsafe { raw.action.Anonymous.filterType }) != Key([0; 16])
        || raw.filterId == 0
        || raw.numFilterConditions == 0
        || raw.numFilterConditions > 8
        || raw.filterCondition.is_null()
    {
        return Err(GuardError::Conflict);
    }
    let layer = decode_layer(raw.layerKey)?;
    let action = match raw.action.r#type {
        FWP_ACTION_BLOCK => Action::Block,
        FWP_ACTION_PERMIT => Action::Permit,
        _ => return Err(GuardError::Conflict),
    };
    let weight = unsafe { read_weight(&raw.weight) }?;
    if unsafe { read_weight(&raw.effectiveWeight) }? != weight {
        return Err(GuardError::Conflict);
    }
    validate_action(layer, action, raw.flags, weight)?;
    let conditions = unsafe {
        std::slice::from_raw_parts(raw.filterCondition, raw.numFilterConditions as usize)
    };
    let mut decoded = Vec::with_capacity(conditions.len());
    for (i, c) in conditions.iter().enumerate() {
        if conditions[..i]
            .iter()
            .any(|p| key(p.fieldKey) == key(c.fieldKey))
        {
            return Err(GuardError::Conflict);
        }
        decoded.push(unsafe { decode_condition(c, layer) }?);
    }
    decoded.sort();
    Ok(NativeFilter {
        policy: Filter {
            key: expected_key,
            sublayer,
            layer,
            weight,
            flags: raw.flags,
            action,
            conditions: decoded,
        },
        id: raw.filterId,
    })
}
/// Safety: display strings must be valid NUL-terminated BFE-owned memory.
pub(crate) unsafe fn decode_sublayer(raw: &FWPM_SUBLAYER0, expected_key: Key) -> Result<Sublayer> {
    if key(raw.subLayerKey) != expected_key
        || raw.flags != 0
        || !raw.providerKey.is_null()
        || raw.providerData.size != 0
        || !raw.providerData.data.is_null()
        || !unsafe { display_matches(&raw.displayData) }
    {
        return Err(GuardError::Conflict);
    }
    Ok(Sublayer {
        key: expected_key,
        weight: raw.weight,
        flags: raw.flags,
    })
}
fn validate_action(layer: Layer, action: Action, flags: u32, weight: u64) -> Result<()> {
    let indexed =
        action == Action::Permit && matches!(layer, Layer::AleConnectV4 | Layer::AleConnectV6);
    if flags != if indexed { FWPM_FILTER_FLAG_INDEXED } else { 0 }
        || weight != if action == Action::Block { 1 } else { 2 }
    {
        return Err(GuardError::Conflict);
    }
    Ok(())
}
unsafe fn display_matches(display: &FWPM_DISPLAY_DATA0) -> bool {
    if display.name.is_null() {
        return false;
    }
    for (i, n) in NAME.encode_utf16().chain(Some(0)).enumerate() {
        if unsafe { *display.name.add(i) } != n {
            return false;
        }
    }
    display.description.is_null() || unsafe { *display.description } == 0
}
unsafe fn read_weight(raw: &FWP_VALUE0) -> Result<u64> {
    if raw.r#type != FWP_UINT64 {
        return Err(GuardError::Conflict);
    }
    unsafe { raw.Anonymous.uint64.as_ref().copied() }.ok_or(GuardError::Conflict)
}
fn layer_guid(layer: Layer) -> GUID {
    match layer {
        Layer::TransportV4 => FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
        Layer::TransportV6 => FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
        Layer::PacketV4 => FWPM_LAYER_OUTBOUND_IPPACKET_V4,
        Layer::PacketV6 => FWPM_LAYER_OUTBOUND_IPPACKET_V6,
        Layer::ForwardV4 => FWPM_LAYER_IPFORWARD_V4,
        Layer::ForwardV6 => FWPM_LAYER_IPFORWARD_V6,
        Layer::AleConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        Layer::AleConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    }
}
fn decode_layer(raw: GUID) -> Result<Layer> {
    [
        Layer::TransportV4,
        Layer::TransportV6,
        Layer::PacketV4,
        Layer::PacketV6,
        Layer::ForwardV4,
        Layer::ForwardV6,
        Layer::AleConnectV4,
        Layer::AleConnectV6,
    ]
    .into_iter()
    .find(|l| key(layer_guid(*l)) == key(raw))
    .ok_or(GuardError::Conflict)
}
fn forward(layer: Layer) -> bool {
    matches!(layer, Layer::ForwardV4 | Layer::ForwardV6)
}
fn v6(layer: Layer) -> bool {
    matches!(
        layer,
        Layer::TransportV6 | Layer::PacketV6 | Layer::ForwardV6 | Layer::AleConnectV6
    )
}
fn field(condition: &Condition, layer: Layer) -> Result<GUID> {
    use Condition::*;
    let transport = matches!(layer, Layer::TransportV4 | Layer::TransportV6);
    let packet = matches!(layer, Layer::PacketV4 | Layer::PacketV6);
    let ale = matches!(layer, Layer::AleConnectV4 | Layer::AleConnectV6);
    Ok(match condition {
        EgressIndex(_) if transport || packet => FWPM_CONDITION_INTERFACE_INDEX,
        LocalInterface(_) if transport || packet || ale => FWPM_CONDITION_IP_LOCAL_INTERFACE,
        DestinationIndex(_) if forward(layer) => FWPM_CONDITION_DESTINATION_INTERFACE_INDEX,
        DestinationLuid(_) if forward(layer) => FWPM_CONDITION_IP_FORWARD_INTERFACE,
        SourceIndex(_) if forward(layer) => FWPM_CONDITION_SOURCE_INTERFACE_INDEX,
        SourceLuid(_) if forward(layer) => FWPM_CONDITION_IP_LOCAL_INTERFACE,
        NextHopIndex(_) if ale => FWPM_CONDITION_NEXTHOP_INTERFACE_INDEX,
        NextHopLuid(_) if ale => FWPM_CONDITION_IP_NEXTHOP_INTERFACE,
        SourceAddress(ip) if ip.is_ipv6() == v6(layer) => {
            if forward(layer) {
                FWPM_CONDITION_IP_SOURCE_ADDRESS
            } else {
                FWPM_CONDITION_IP_LOCAL_ADDRESS
            }
        }
        DestinationAddress(ip) if ip.is_ipv6() == v6(layer) => {
            if forward(layer) {
                FWPM_CONDITION_IP_DESTINATION_ADDRESS
            } else {
                FWPM_CONDITION_IP_REMOTE_ADDRESS
            }
        }
        LocalPort(_) if transport || ale => FWPM_CONDITION_IP_LOCAL_PORT,
        RemotePort(_) if transport || ale => FWPM_CONDITION_IP_REMOTE_PORT,
        Protocol(_) if transport || ale => FWPM_CONDITION_IP_PROTOCOL,
        NoneSetFlags(n) if transport && *n == FWP_CONDITION_FLAG_IS_RAW_ENDPOINT => {
            FWPM_CONDITION_FLAGS
        }
        AllSetFlags(n) if forward(layer) && *n == FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU => {
            FWPM_CONDITION_FLAGS
        }
        _ => return Err(GuardError::Conflict),
    })
}
fn encode_condition(
    condition: &Condition,
    layer: Layer,
    backing: &mut Backing,
) -> Result<FWPM_FILTER_CONDITION0> {
    use Condition::*;
    let field_key = field(condition, layer)?;
    let (kind, value) = match condition {
        EgressIndex(n) | DestinationIndex(n) | SourceIndex(n) | NextHopIndex(n)
        | NoneSetFlags(n) | AllSetFlags(n) => (FWP_UINT32, FWP_CONDITION_VALUE0_0 { uint32: *n }),
        LocalInterface(n) | DestinationLuid(n) | SourceLuid(n) | NextHopLuid(n) => {
            let mut word = Box::new(*n);
            let value = FWP_CONDITION_VALUE0_0 { uint64: &mut *word };
            backing.words.push(word);
            (FWP_UINT64, value)
        }
        LocalPort(n) | RemotePort(n) => (FWP_UINT16, FWP_CONDITION_VALUE0_0 { uint16: *n }),
        Protocol(n) => (FWP_UINT8, FWP_CONDITION_VALUE0_0 { uint8: *n }),
        SourceAddress(IpAddr::V4(ip)) | DestinationAddress(IpAddr::V4(ip)) => (
            FWP_UINT32,
            FWP_CONDITION_VALUE0_0 {
                uint32: u32::from_be_bytes(ip.octets()),
            },
        ),
        SourceAddress(IpAddr::V6(ip)) | DestinationAddress(IpAddr::V6(ip)) => {
            let mut addr = Box::new(FWP_BYTE_ARRAY16 {
                byteArray16: ip.octets(),
            });
            let value = FWP_CONDITION_VALUE0_0 {
                byteArray16: &mut *addr,
            };
            backing.addresses.push(addr);
            (FWP_BYTE_ARRAY16_TYPE, value)
        }
    };
    Ok(FWPM_FILTER_CONDITION0 {
        fieldKey: field_key,
        matchType: match condition {
            NoneSetFlags(_) => FWP_MATCH_FLAGS_NONE_SET,
            AllSetFlags(_) => FWP_MATCH_FLAGS_ALL_SET,
            _ => FWP_MATCH_EQUAL,
        },
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: kind,
            Anonymous: value,
        },
    })
}
unsafe fn decode_condition(raw: &FWPM_FILTER_CONDITION0, layer: Layer) -> Result<Condition> {
    use Condition::*;
    let f = key(raw.fieldKey);
    let value = &raw.conditionValue;
    let c = unsafe {
        match value.r#type {
            FWP_UINT32 if f == key(FWPM_CONDITION_INTERFACE_INDEX) => {
                EgressIndex(value.Anonymous.uint32)
            }
            FWP_UINT32 if f == key(FWPM_CONDITION_DESTINATION_INTERFACE_INDEX) => {
                DestinationIndex(value.Anonymous.uint32)
            }
            FWP_UINT32 if f == key(FWPM_CONDITION_SOURCE_INTERFACE_INDEX) => {
                SourceIndex(value.Anonymous.uint32)
            }
            FWP_UINT32 if f == key(FWPM_CONDITION_NEXTHOP_INTERFACE_INDEX) => {
                NextHopIndex(value.Anonymous.uint32)
            }
            FWP_UINT64 => {
                let n = value
                    .Anonymous
                    .uint64
                    .as_ref()
                    .copied()
                    .ok_or(GuardError::Conflict)?;
                if f == key(FWPM_CONDITION_IP_LOCAL_INTERFACE) {
                    if forward(layer) {
                        SourceLuid(n)
                    } else {
                        LocalInterface(n)
                    }
                } else if f == key(FWPM_CONDITION_IP_FORWARD_INTERFACE) {
                    DestinationLuid(n)
                } else if f == key(FWPM_CONDITION_IP_NEXTHOP_INTERFACE) {
                    NextHopLuid(n)
                } else {
                    return Err(GuardError::Conflict);
                }
            }
            FWP_UINT16 if f == key(FWPM_CONDITION_IP_LOCAL_PORT) => {
                LocalPort(value.Anonymous.uint16)
            }
            FWP_UINT16 if f == key(FWPM_CONDITION_IP_REMOTE_PORT) => {
                RemotePort(value.Anonymous.uint16)
            }
            FWP_UINT8 if f == key(FWPM_CONDITION_IP_PROTOCOL) => Protocol(value.Anonymous.uint8),
            FWP_UINT32 if f == key(FWPM_CONDITION_FLAGS) => match raw.matchType {
                FWP_MATCH_FLAGS_NONE_SET => NoneSetFlags(value.Anonymous.uint32),
                FWP_MATCH_FLAGS_ALL_SET => AllSetFlags(value.Anonymous.uint32),
                _ => return Err(GuardError::Conflict),
            },
            FWP_UINT32 | FWP_BYTE_ARRAY16_TYPE => {
                let ip = match (v6(layer), value.r#type) {
                    (false, FWP_UINT32) => IpAddr::V4(Ipv4Addr::from(value.Anonymous.uint32)),
                    (true, FWP_BYTE_ARRAY16_TYPE) => IpAddr::V6(Ipv6Addr::from(
                        value
                            .Anonymous
                            .byteArray16
                            .as_ref()
                            .ok_or(GuardError::Conflict)?
                            .byteArray16,
                    )),
                    _ => return Err(GuardError::Conflict),
                };
                if f == key(if forward(layer) {
                    FWPM_CONDITION_IP_SOURCE_ADDRESS
                } else {
                    FWPM_CONDITION_IP_LOCAL_ADDRESS
                }) {
                    SourceAddress(ip)
                } else if f
                    == key(if forward(layer) {
                        FWPM_CONDITION_IP_DESTINATION_ADDRESS
                    } else {
                        FWPM_CONDITION_IP_REMOTE_ADDRESS
                    })
                {
                    DestinationAddress(ip)
                } else {
                    return Err(GuardError::Conflict);
                }
            }
            _ => return Err(GuardError::Conflict),
        }
    };
    if key(field(&c, layer)?) != f
        || raw.matchType
            != match c {
                NoneSetFlags(_) => FWP_MATCH_FLAGS_NONE_SET,
                AllSetFlags(_) => FWP_MATCH_FLAGS_ALL_SET,
                _ => FWP_MATCH_EQUAL,
            }
    {
        return Err(GuardError::Conflict);
    }
    Ok(c)
}

/// Returned by independent fresh native/owner queries, never by copying a Model.
pub(crate) struct Bindings {
    pub scope: SessionScope,
    pub carrier: Option<Carrier>,
    pub egress: [Option<Identity>; 2],
}
pub(crate) trait BindingAttestor {
    /// Called inside EVERY read/write transaction under the serialized owner.
    /// Independently query scope/runtime/boot/epoch, full GUID/index/LUID and
    /// exact C sources/readiness through retained authenticated native owners.
    /// Numerical equality, journal JSON and WFP conditions are not ownership.
    fn observe(&mut self, scope: &SessionScope) -> Result<Bindings>;
    /// Mandatory under the write transaction: exact owners before all effects;
    /// before any permits also verified assigned-priority arbitration, real
    /// route/DNS and exclusively HELD probe ports;
    /// before base removal exact owned absence/cleanup. No success default.
    fn authorize(&mut self, kind: SessionKind, expected: &Model, desired: &Model) -> Result<()>;
}
/// Fake only this native boundary. All policies, exact CAS, readbacks and
/// independent authority checks are implemented by NativeGuard below.
pub(crate) trait NativeApi {
    fn begin(&mut self, kind: SessionKind, read_only: bool) -> Result<()>;
    fn commit(&mut self, kind: SessionKind) -> Result<()>;
    fn abort(&mut self, kind: SessionKind) -> Result<()>;
    fn close(&mut self, kind: SessionKind) -> Result<()>;
    fn sublayer(&mut self, kind: SessionKind, key: Key) -> Result<Option<Sublayer>>;
    fn filter(
        &mut self,
        kind: SessionKind,
        key: Key,
        sublayer: Key,
    ) -> Result<Option<NativeFilter>>;
    fn add_sublayer(&mut self, sublayer: &Sublayer) -> Result<()>;
    fn delete_sublayer(&mut self, key: Key) -> Result<()>;
    fn add_filter(&mut self, kind: SessionKind, filter: &Filter) -> Result<u64>;
    fn delete_filter(&mut self, kind: SessionKind, key: Key) -> Result<()>;
}
pub(crate) struct NativeGuard<N: NativeApi, A: BindingAttestor> {
    scope: SessionScope,
    io: N,
    attestor: A,
    failed: bool,
    current: Model,
    pending: Option<Model>,
    owned_ids: BTreeMap<Key, u64>,
}
impl<N: NativeApi, A: BindingAttestor> NativeGuard<N, A> {
    pub(crate) fn fresh(scope: SessionScope, io: N, attestor: A) -> Result<Self> {
        crate::member_carrier_guard::resource_keys(&scope)?;
        let current = Model::empty(scope.clone())?;
        Ok(Self {
            scope,
            io,
            attestor,
            failed: false,
            current,
            pending: None,
            owned_ids: BTreeMap::new(),
        })
    }
    fn fail<T>(&mut self, error: GuardError) -> Result<T> {
        self.failed = true;
        self.io
            .close(SessionKind::DynamicPermits)
            .map_err(|_| GuardError::RemovalUnconfirmed)?;
        Err(error)
    }
    fn read_snapshot(&mut self) -> Result<Snapshot> {
        transaction(&mut self.io, SessionKind::StaticBase, true, |io| {
            read_locked(
                io,
                &mut self.attestor,
                &self.scope,
                SessionKind::StaticBase,
                &self.owned_ids,
            )
        })
    }
}
impl<N: NativeApi, A: BindingAttestor> SplitEngines for NativeGuard<N, A> {
    fn scope(&self) -> &SessionScope {
        &self.scope
    }
    fn snapshot(&mut self) -> Result<Snapshot> {
        let was_failed = self.failed;
        self.failed = true; // Poison first: caller catching an authority unwind cannot resume.
        let result = (|| {
            let actual = self.read_snapshot()?;
            if !was_failed {
                if actual != self.current.expected {
                    return Err(GuardError::Conflict);
                }
            } else {
                // Ambiguity is terminal for writes. These retained readbacks
                // classify cleanup only; never learn/adopt later priority or
                // accept ANY remaining allow, even one from our own session.
                let known = std::iter::once(&self.current)
                    .chain(self.pending.iter())
                    .any(|m| m.without_permits().is_ok_and(|m| m.expected == actual));
                if !known {
                    return Err(GuardError::RemovalUnconfirmed);
                }
            }
            Ok(actual)
        })();
        match result {
            Ok(s) => {
                self.failed = was_failed;
                Ok(s)
            }
            Err(e) => self.fail(e),
        }
    }
    fn exchange(&mut self, kind: SessionKind, expected: &Model, desired: &Model) -> Result<Model> {
        let validation = crate::member_carrier_guard::validate_session_exchange(
            &self.scope,
            expected,
            desired,
            kind,
        );
        if let Err(e) = validation {
            return self.fail(e);
        }
        if self.failed || self.current != *expected {
            return self.fail(GuardError::Conflict);
        }
        self.failed = true; // Cleared only after ACK AND exact committed reconstruction.
        let scope = &self.scope;
        let ids = &mut self.owned_ids;
        let pending = &mut self.pending;
        let attestor = &mut self.attestor;
        let staged = transaction(&mut self.io, kind, false, |io| {
            let actual = read_locked(io, attestor, scope, kind, ids)?;
            if actual != expected.expected {
                return Err(GuardError::Conflict);
            }
            attestor.authorize(kind, expected, desired)?;
            // Requery after authority, BEFORE effects; never seed bindings by
            // copying expected/desired. New attach and old removal are explicit.
            let bindings = attestor.observe(scope)?;
            validate_bindings(scope, &bindings)?;
            if desired.installed
                && (bindings.carrier != desired.carrier
                    || desired.members.iter().enumerate().any(|(i, m)| {
                        m.as_ref()
                            .is_some_and(|m| bindings.egress[i].as_ref() != Some(&m.identity))
                    }))
            {
                return Err(GuardError::Conflict);
            }
            for old in &expected.expected.filters {
                if !desired.expected.filters.contains(old) {
                    allowed(scope, kind, old.key)?;
                    io.delete_filter(kind, old.key)?;
                }
            }
            match (&expected.expected.sublayer, &desired.expected.sublayer) {
                (Some(old), None) => {
                    if kind != SessionKind::StaticBase {
                        return Err(GuardError::Invalid);
                    }
                    io.delete_sublayer(old.key)?;
                }
                (None, Some(new)) => {
                    if kind != SessionKind::StaticBase {
                        return Err(GuardError::Invalid);
                    }
                    io.add_sublayer(new)?;
                }
                (Some(old), Some(new)) if old != new => return Err(GuardError::Conflict),
                _ => {}
            }
            for new in &desired.expected.filters {
                if !expected.expected.filters.contains(new) {
                    allowed(scope, kind, new.key)?;
                    if (new.action == Action::Permit) != (kind == SessionKind::DynamicPermits) {
                        return Err(GuardError::Invalid);
                    }
                    let id = io.add_filter(kind, new)?;
                    if id == 0 {
                        return Err(GuardError::Conflict);
                    }
                    ids.insert(new.key, id); // Retained even on ambiguous commit; NO adoption.
                }
            }
            let actual = read_locked(io, attestor, scope, kind, ids)?;
            // Creation captures FULL assigned priority in this creating write
            // transaction. No later recovery read is allowed to learn it.
            let captured = desired.readback_after(expected, &actual)?;
            *pending = Some(captured.clone()); // Live native capture, NOT durable/resume authority.
            Ok(captured)
        });
        let captured = match staged {
            Ok(m) => m,
            Err(e) => return self.fail(e),
        };
        let readback = self.read_snapshot(); // serialized independent committed read.
        match readback {
            Ok(s) if s == captured.expected => {
                self.owned_ids
                    .retain(|k, _| captured.expected.filters.iter().any(|f| f.key == *k));
                self.current = captured.clone();
                self.pending = None;
                self.failed = false;
                Ok(captured)
            }
            Ok(_) => self.fail(GuardError::Conflict),
            Err(e) => self.fail(e),
        }
    }
    fn close_permits(&mut self) -> Result<()> {
        self.failed = true;
        self.io
            .close(SessionKind::DynamicPermits)
            .map_err(|_| GuardError::RemovalUnconfirmed)
    }
}
impl<N: NativeApi, A: BindingAttestor> Drop for NativeGuard<N, A> {
    fn drop(&mut self) {
        // Close is NOT proof of allow absence and never releases a probe port.
        // Ordinary nonpersistent bases survive static engine close.
        let _ = self.io.close(SessionKind::DynamicPermits);
        let _ = self.io.close(SessionKind::StaticBase);
    }
}
fn allowed(scope: &SessionScope, kind: SessionKind, k: Key) -> Result<()> {
    let keys = crate::member_carrier_guard::resource_keys(scope)?;
    let i = keys
        .filters
        .iter()
        .position(|p| *p == k)
        .ok_or(GuardError::Invalid)?;
    if (i % 24 >= 8) != (kind == SessionKind::DynamicPermits) {
        return Err(GuardError::Invalid);
    }
    Ok(())
}
fn validate_bindings(scope: &SessionScope, b: &Bindings) -> Result<()> {
    if b.scope != *scope {
        return Err(GuardError::Conflict);
    }
    match &b.carrier {
        Some(c) => {
            let members = b.egress.clone().map(|identity| {
                identity.map(|identity| crate::member_carrier_guard::Member {
                    identity,
                    probes: vec![],
                })
            });
            let model = Model::new(scope.clone(), c.clone(), members, None)?;
            if model.carrier.as_ref() != Some(c) {
                return Err(GuardError::Conflict);
            } // Exact canonical observed sources.
        }
        None if b.egress.iter().any(Option::is_some) => return Err(GuardError::Conflict),
        None => {}
    }
    Ok(())
}
fn read_locked<N: NativeApi, A: BindingAttestor>(
    io: &mut N,
    a: &mut A,
    scope: &SessionScope,
    kind: SessionKind,
    ids: &BTreeMap<Key, u64>,
) -> Result<Snapshot> {
    let bindings = a.observe(scope)?;
    validate_bindings(scope, &bindings)?;
    let keys = crate::member_carrier_guard::resource_keys(scope)?;
    let sublayer = io.sublayer(kind, keys.sublayer)?;
    let mut filters = vec![];
    let mut referenced = [false; 2];
    for (i, k) in keys.filters.into_iter().enumerate() {
        if let Some(native) = io.filter(kind, k, keys.sublayer)? {
            if native.policy.key != k || ids.get(&k) != Some(&native.id) {
                return Err(GuardError::Conflict);
            }
            referenced[i / 24] = true;
            filters.push(native.policy);
        }
    }
    filters.sort_by_key(|f| f.key);
    let installed = sublayer.is_some();
    // Only the bindings REFERENCED by this scoped policy are projected. Facts
    // themselves come exclusively from independent observation, not index/key
    // inference. New physical B may exist before its base is attached.
    Ok(Snapshot {
        version: 2,
        scope: scope.clone(),
        carrier: if installed { bindings.carrier } else { None },
        egress: std::array::from_fn(|i| {
            if referenced[i] {
                bindings.egress[i].clone()
            } else {
                None
            }
        }),
        sublayer,
        filters,
    })
}
struct Transaction<'a, N: NativeApi> {
    io: &'a mut N,
    kind: SessionKind,
    finished: bool,
}
impl<N: NativeApi> Drop for Transaction<'_, N> {
    fn drop(&mut self) {
        if !self.finished {
            if self.io.abort(self.kind).is_err() {
                let _ = self.io.close(self.kind);
            }
            // Also on authority unwinding: never retain an earlier active allow
            // after an aborted operation. Never roll back/delete static bases.
            let _ = self.io.close(SessionKind::DynamicPermits);
        }
    }
}
fn transaction<N: NativeApi, T>(
    io: &mut N,
    kind: SessionKind,
    readonly: bool,
    operation: impl FnOnce(&mut N) -> Result<T>,
) -> Result<T> {
    io.begin(kind, readonly)?;
    let mut tx = Transaction {
        io,
        kind,
        finished: false,
    };
    let result = operation(tx.io)?;
    tx.io.commit(kind)?;
    tx.finished = true;
    Ok(result)
}
pub(crate) fn session(kind: SessionKind) -> FWPM_SESSION0 {
    FWPM_SESSION0 {
        flags: if kind == SessionKind::DynamicPermits {
            FWPM_SESSION_FLAG_DYNAMIC
        } else {
            0
        },
        txnWaitTimeoutInMSec: 5000,
        ..Default::default()
    }
}

#[cfg(windows)]
mod bfe {
    use super::*;
    use std::ffi::c_void;
    use windows_sys::Win32::{
        Foundation::{FWP_E_FILTER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, HANDLE},
        System::Rpc::RPC_C_AUTHN_WINNT,
    };

    pub(crate) struct Wfp {
        scope: SessionScope,
        base: Engine,
        permits: Engine,
    }
    struct Engine {
        handle: HANDLE,
    }
    impl Engine {
        fn open(kind: SessionKind) -> Result<Self> {
            let mut handle = ptr::null_mut();
            let session = session(kind);
            status(unsafe {
                FwpmEngineOpen0(
                    ptr::null(),
                    RPC_C_AUTHN_WINNT,
                    ptr::null(),
                    &session,
                    &mut handle,
                )
            })?;
            if handle.is_null() {
                return Err(GuardError::Conflict);
            }
            Ok(Self { handle })
        }
        fn handle(&self) -> Result<HANDLE> {
            if self.handle.is_null() {
                Err(GuardError::Conflict)
            } else {
                Ok(self.handle)
            }
        }
        fn close(&mut self) -> Result<()> {
            if !self.handle.is_null() {
                status(unsafe { FwpmEngineClose0(self.handle) })?;
                self.handle = ptr::null_mut();
            }
            Ok(()) // Failed close retains handle for Drop/emergency retry.
        }
    }
    impl Drop for Engine {
        fn drop(&mut self) {
            let _ = self.close();
        }
    }
    impl Wfp {
        fn engine(&self, kind: SessionKind) -> &Engine {
            if kind == SessionKind::StaticBase {
                &self.base
            } else {
                &self.permits
            }
        }
        fn engine_mut(&mut self, kind: SessionKind) -> &mut Engine {
            if kind == SessionKind::StaticBase {
                &mut self.base
            } else {
                &mut self.permits
            }
        }
        fn subkey(&self, k: Key) -> Result<()> {
            if crate::member_carrier_guard::resource_keys(&self.scope)?.sublayer != k {
                return Err(GuardError::Invalid);
            }
            Ok(())
        }
    }
    impl<A: BindingAttestor> NativeGuard<Wfp, A> {
        /// Explicit UNUSED opening. No shipping factory can reach this module.
        /// Future factory must first pass native security/priority/epoch gates,
        /// hold serialized owners and provide a real independent attestor.
        /// Fresh use demands empty v2 keys; opening never adopts old resources.
        pub(crate) fn open(scope: SessionScope, attestor: A) -> Result<Self> {
            crate::member_carrier_guard::resource_keys(&scope)?;
            let base = Engine::open(SessionKind::StaticBase)?;
            let permits = Engine::open(SessionKind::DynamicPermits)?;
            Self::fresh(
                scope.clone(),
                Wfp {
                    scope,
                    base,
                    permits,
                },
                attestor,
            )
        }
    }
    impl NativeApi for Wfp {
        fn begin(&mut self, kind: SessionKind, readonly: bool) -> Result<()> {
            status(unsafe {
                FwpmTransactionBegin0(
                    self.engine(kind).handle()?,
                    if readonly { FWPM_TXN_READ_ONLY } else { 0 },
                )
            })
        }
        fn commit(&mut self, kind: SessionKind) -> Result<()> {
            status(unsafe { FwpmTransactionCommit0(self.engine(kind).handle()?) })
        }
        fn abort(&mut self, kind: SessionKind) -> Result<()> {
            status(unsafe { FwpmTransactionAbort0(self.engine(kind).handle()?) })
        }
        fn close(&mut self, kind: SessionKind) -> Result<()> {
            self.engine_mut(kind).close()
        }
        fn sublayer(&mut self, kind: SessionKind, k: Key) -> Result<Option<Sublayer>> {
            self.subkey(k)?;
            let mut raw = ptr::null_mut();
            let code =
                unsafe { FwpmSubLayerGetByKey0(self.engine(kind).handle()?, &guid(k), &mut raw) };
            let memory = Memory(raw);
            if code == FWP_E_SUBLAYER_NOT_FOUND as u32 {
                return Ok(None);
            }
            status(code)?;
            let raw = unsafe { memory.0.as_ref() }.ok_or(GuardError::Conflict)?;
            unsafe { decode_sublayer(raw, k) }.map(Some)
        }
        fn filter(&mut self, kind: SessionKind, k: Key, sub: Key) -> Result<Option<NativeFilter>> {
            self.subkey(sub)?;
            if !crate::member_carrier_guard::resource_keys(&self.scope)?
                .filters
                .contains(&k)
            {
                return Err(GuardError::Invalid);
            }
            let mut raw = ptr::null_mut();
            let code =
                unsafe { FwpmFilterGetByKey0(self.engine(kind).handle()?, &guid(k), &mut raw) };
            let memory = Memory(raw);
            if code == FWP_E_FILTER_NOT_FOUND as u32 {
                return Ok(None);
            }
            status(code)?;
            let raw = unsafe { memory.0.as_ref() }.ok_or(GuardError::Conflict)?;
            unsafe { decode_filter(raw, k, sub) }.map(Some)
        }
        fn add_sublayer(&mut self, sub: &Sublayer) -> Result<()> {
            self.subkey(sub.key)?;
            if sub.flags != 0 {
                return Err(GuardError::Invalid);
            }
            let mut name: Vec<_> = NAME.encode_utf16().chain(Some(0)).collect();
            let raw = FWPM_SUBLAYER0 {
                subLayerKey: guid(sub.key),
                weight: sub.weight,
                flags: 0,
                displayData: FWPM_DISPLAY_DATA0 {
                    name: name.as_mut_ptr(),
                    description: ptr::null_mut(),
                },
                ..Default::default()
            };
            status(unsafe { FwpmSubLayerAdd0(self.base.handle()?, &raw, ptr::null_mut()) })
        }
        fn delete_sublayer(&mut self, k: Key) -> Result<()> {
            self.subkey(k)?;
            status(unsafe { FwpmSubLayerDeleteByKey0(self.base.handle()?, &guid(k)) })
        }
        fn add_filter(&mut self, kind: SessionKind, filter: &Filter) -> Result<u64> {
            allowed(&self.scope, kind, filter.key)?;
            self.subkey(filter.sublayer)?;
            if (filter.action == Action::Permit) != (kind == SessionKind::DynamicPermits) {
                return Err(GuardError::Invalid);
            }
            let native = EncodedFilter::new(filter)?;
            let mut id = 0;
            status(unsafe {
                FwpmFilterAdd0(
                    self.engine(kind).handle()?,
                    &native.raw,
                    ptr::null_mut(),
                    &mut id,
                )
            })?;
            if id == 0 {
                return Err(GuardError::Conflict);
            }
            Ok(id)
        }
        fn delete_filter(&mut self, kind: SessionKind, k: Key) -> Result<()> {
            allowed(&self.scope, kind, k)?;
            // Never bypass WRONG_SESSION by retrying via the ordinary engine.
            status(unsafe { FwpmFilterDeleteByKey0(self.engine(kind).handle()?, &guid(k)) })
        }
    }
    impl Drop for Wfp {
        fn drop(&mut self) {
            let _ = self.permits.close();
            let _ = self.base.close();
        }
    }
    struct Memory<T>(*mut T);
    impl<T> Drop for Memory<T> {
        fn drop(&mut self) {
            if !self.0.is_null() {
                let mut p = self.0.cast::<c_void>();
                unsafe {
                    FwpmFreeMemory0(&mut p);
                }
            }
        }
    }
    fn status(code: u32) -> Result<()> {
        if code == 0 {
            Ok(())
        } else {
            Err(GuardError::Native(code))
        }
    }
}

#[cfg(all(test, windows))]
#[path = "member_carrier_guard_tests.rs"]
mod tests;
