//! Unselected native v2 carrier/egress guard. No factory caller.
//! Codec contracts: Microsoft fwpmtypes.h/fwptypes.h/fwpmu.h, SDK-backed
//! windows-sys 0.61.2. No custom packed layout or FFI signature is invented.
//! https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
//! https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer
//! https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
//! Snapshots alone are not traffic acceptance. Every permit exchange also reads
//! a bounded foreign-priority inventory in the SAME native write transaction.
//! https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
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

#[derive(Clone, Debug, Eq, PartialEq)]
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
/// In final cleanup ONLY, an opaque SAME-owner once-close history pin plus fresh
/// FULL native absence can describe the former bindings still used by owned
/// static bases. Such facts are not live source readiness or effect permission.
/// This is comparison DATA, not a read capability or ownership authority. A
/// native authorizer must bracket the locked WFP read with actual C/A/B reads.
#[derive(PartialEq, Eq)]
pub(crate) struct Bindings {
    pub scope: SessionScope,
    pub carrier: Option<Carrier>,
    pub egress: [Option<Identity>; 2],
}
pub(crate) trait BindingAttestor {
    /// Called inside EVERY read/write transaction under the serialized owner.
    /// Independently query scope/runtime/boot/epoch, full GUID/index/LUID and
    /// exact C sources/readiness through retained authenticated native owners.
    /// After acknowledged C/A/B closure, use the SAME original captured history
    /// ONLY through fresh exact receipts + full absence, so remaining static
    /// bases can be read before removal. Never adopt former bindings from Model
    /// or JSON; closed history must never authorize live/dynamic allows.
    /// Numerical equality, journal JSON and WFP conditions are not ownership.
    fn observe(&mut self, scope: &SessionScope) -> Result<Bindings>;
    /// Mandatory under the write transaction: exact owners before all effects;
    /// before any permits also verified assigned-priority arbitration, real
    /// route/DNS and exclusively HELD probe ports;
    /// before base removal exact owned absence/cleanup. No success default.
    /// `locked` reads the guard's actual current transaction without recursively
    /// borrowing the guard or opening another engine/transaction. Bindings passed
    /// to it are comparison data: bracket the read with actual C/A/B owners.
    fn authorize<N: NativeApi>(
        &mut self,
        kind: SessionKind,
        expected: &Model,
        desired: &Model,
        locked: &mut LockedWfpRead<'_, N>,
    ) -> Result<()>;
}
#[cfg(windows)]
pub(crate) trait WindowBindingAttestor: BindingAttestor {
    /// Mandatory SAME opaque Source/Closing registration, runtime/KeyLock,
    /// Calling supervisor and protected lifecycle. Window metadata alone is not
    /// authority. This runs inside a Source window: do not nest Source.inspect,
    /// reopen/borrow the guard, or perform effects. No successful default.
    fn verify_original_window(
        &mut self,
        window: &crate::windows::member_carrier_runtime::native::NativeBindingsWindow<'_>,
    ) -> Result<()>;
    /// Read-only, inside the SAME original Retired full-native-absence bracket.
    /// Authenticate actual registered Rc/current Pair/Calling without entering
    /// Retired/Source again. This method grants NO mutation/removal rights.
    fn verify_retired_bracket(
        &mut self,
        pair: &std::rc::Rc<
            crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead,
        >,
        record: &crate::member_carrier_pair::Record,
        retired: &crate::windows::member_carrier_runtime::native::RetiredCarrierRead,
        bindings: &Bindings,
    ) -> Result<()>;
}
#[cfg(windows)]
pub(crate) trait TerminalBindingAttestor: BindingAttestor {
    /// Mandatory separate Stopped/NativeKeysStopped lane, inside SAME active
    /// terminal Retired history lease and Calling. Authenticate original
    /// Runtime/KeyLock/Pair STORE origin and current exact Stopped ACK; no
    /// Closing widening, Source/Retired reentry, Guard borrow or native effect.
    fn verify_terminal_bracket(
        &mut self,
        pair: &std::rc::Rc<
            crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead,
        >,
        stopped: &crate::member_carrier_pair::Record,
        retired: &std::rc::Rc<crate::windows::member_carrier_runtime::native::RetiredCarrierRead>,
        bindings: &Bindings,
    ) -> Result<()>;
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
    /// Bounded ALL-filter inventory at the eight protected layers on the SAME
    /// already-active transaction. No conditions are guessed to be disjoint.
    /// Every filter includes its actual sublayer priority; no successful default.
    fn arbitration(&mut self, kind: SessionKind) -> Result<Vec<ArbitrationFilter>>;
    fn add_sublayer(&mut self, sublayer: &Sublayer) -> Result<()>;
    fn delete_sublayer(&mut self, key: Key) -> Result<()>;
    fn add_filter(&mut self, kind: SessionKind, filter: &Filter) -> Result<u64>;
    fn delete_filter(&mut self, kind: SessionKind, key: Key) -> Result<()>;
}
/// Private original engine lifetime, shared with its factual close receipt.
/// Numeric handles are never an origin comparison. Only actual close success
/// creates an ACK; null handles/empty Options cannot do so.
pub(crate) struct EngineCloseAck {
    origin: std::rc::Rc<()>,
    kind: SessionKind,
}
/// # Safety
/// These are the SAME original SDK engine handles. ACKs are minted and stored
/// ONLY after actual successful FwpmEngineClose0, before any postflight; an
/// existing original ACK is returned unchanged. Terminal entry permanently
/// disables ordinary/emergency/Drop retries, including after error/unwind.
/// No implementation/default based on closed flags or equal handles is sound.
pub(crate) unsafe trait TerminalNativeApi: NativeApi {
    fn enter_terminal_lane(&mut self);
    fn engine_origin(&self, kind: SessionKind) -> std::rc::Rc<()>;
    fn engine_close_ack(&self, kind: SessionKind) -> Result<std::rc::Rc<EngineCloseAck>>;
    fn close_terminal_engine(&mut self, kind: SessionKind) -> Result<std::rc::Rc<EngineCloseAck>>;
    fn verify_engine_inert(
        &self,
        kind: SessionKind,
        ack: &std::rc::Rc<EngineCloseAck>,
    ) -> Result<()>;
}
/// Actual close receipts/failure state, never native cleanup/module authority.
/// No constructor, Clone or serialization; roots retain THIS original Rc.
pub(crate) struct GuardEngineClosure {
    scope: SessionScope,
    guard: std::rc::Rc<()>,
    engines: [std::rc::Rc<()>; 2],
    acks: std::cell::RefCell<[Option<std::rc::Rc<EngineCloseAck>>; 2]>,
    attempted: std::cell::Cell<bool>,
    complete: std::cell::Cell<bool>,
    failed: std::cell::Cell<bool>,
}
impl GuardEngineClosure {
    /// Facts only: partial/error/unwind ACKs remain available, never rearm.
    pub(crate) fn acknowledgements(&self) -> Result<[Option<std::rc::Rc<EngineCloseAck>>; 2]> {
        Ok(self
            .acks
            .try_borrow()
            .map_err(|_| GuardError::Conflict)?
            .clone())
    }
}
struct GuardCloseFlight {
    original: std::rc::Rc<GuardEngineClosure>,
    succeeded: bool,
}
impl Drop for GuardCloseFlight {
    fn drop(&mut self) {
        if !self.succeeded {
            self.original.failed.set(true);
        }
    }
}
pub(super) struct EngineLifetime {
    handle: usize,
    kind: SessionKind,
    origin: std::rc::Rc<()>,
    terminal: std::cell::Cell<bool>,
    busy: std::cell::Cell<bool>,
    attempted: std::cell::Cell<bool>,
    failed: std::cell::Cell<bool>,
    ack: std::cell::RefCell<Option<std::rc::Rc<EngineCloseAck>>>,
}
impl EngineLifetime {
    pub(super) fn new(kind: SessionKind, handle: usize) -> Result<Self> {
        if handle == 0 {
            return Err(GuardError::Conflict);
        }
        Ok(Self {
            handle,
            kind,
            origin: std::rc::Rc::new(()),
            terminal: std::cell::Cell::new(false),
            busy: std::cell::Cell::new(false),
            attempted: std::cell::Cell::new(false),
            failed: std::cell::Cell::new(false),
            ack: std::cell::RefCell::new(None),
        })
    }
    pub(super) fn enter_terminal(&self) {
        self.terminal.set(true);
    }
    pub(super) fn original_origin(&self) -> std::rc::Rc<()> {
        self.origin.clone()
    }
    pub(super) fn acknowledged(&self) -> Result<std::rc::Rc<EngineCloseAck>> {
        self.ack
            .try_borrow()
            .map_err(|_| GuardError::Conflict)?
            .as_ref()
            .cloned()
            .ok_or(GuardError::RemovalUnconfirmed)
    }
    pub(super) fn verify_ack(&self, ack: &std::rc::Rc<EngineCloseAck>) -> Result<()> {
        if !std::rc::Rc::ptr_eq(&self.origin, &ack.origin)
            || self.kind != ack.kind
            || !std::rc::Rc::ptr_eq(&self.acknowledged()?, ack)
        {
            return Err(GuardError::Conflict);
        }
        Ok(())
    }
    fn close_actual(
        &self,
        close: impl FnOnce(usize) -> Result<()>,
    ) -> Result<std::rc::Rc<EngineCloseAck>> {
        if self.busy.get() || (self.terminal.get() && self.failed.get()) {
            self.failed.set(true);
            return Err(GuardError::Conflict);
        }
        if let Ok(ack) = self.acknowledged() {
            return Ok(ack);
        }
        if self.terminal.get() && self.attempted.replace(true) {
            self.failed.set(true);
            return Err(GuardError::RemovalUnconfirmed);
        }
        self.busy.set(true);
        struct Flight<'a> {
            owner: &'a EngineLifetime,
            success: bool,
        }
        impl Drop for Flight<'_> {
            fn drop(&mut self) {
                self.owner.busy.set(false);
                if !self.success {
                    self.owner.failed.set(true);
                }
            }
        }
        let mut flight = Flight {
            owner: self,
            success: false,
        };
        close(self.handle)?;
        let ack = std::rc::Rc::new(EngineCloseAck {
            origin: self.origin.clone(),
            kind: self.kind,
        });
        *self.ack.borrow_mut() = Some(ack.clone());
        // Actual success is retained even when the surrounding call was tainted
        // by swallowed reentry. It remains factual, never release permission.
        if self.failed.get() {
            return Err(GuardError::Conflict);
        }
        flight.success = true;
        Ok(ack)
    }
    pub(super) fn close_ordinary(&self, close: impl FnOnce(usize) -> Result<()>) -> Result<()> {
        if self.terminal.get() {
            return Err(GuardError::Conflict);
        }
        self.close_actual(close).map(|_| ())
    }
    pub(super) fn close_terminal(
        &self,
        close: impl FnOnce(usize) -> Result<()>,
    ) -> Result<std::rc::Rc<EngineCloseAck>> {
        if !self.terminal.get() {
            return Err(GuardError::Conflict);
        }
        self.close_actual(close)
    }
    pub(super) fn verify_inert(&self) -> Result<()> {
        if !self.terminal.get() || self.busy.get() || self.failed.get() {
            return Err(GuardError::Conflict);
        }
        self.verify_ack(&self.acknowledged()?)
    }
    pub(super) fn drop_requires_close(&self) -> bool {
        !self.terminal.get() && self.acknowledged().is_err()
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ArbitrationFilter {
    pub key: Key,
    pub id: u64,
    pub layer: Layer,
    pub sublayer: Key,
    pub sublayer_weight: u16,
    pub flags: u32,
    pub action: u32,
}
const MAX_ARBITRATION_FILTERS: usize = 32768;

/// Comparison DATA, not original creator ownership or a WFP permission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ColdGuardPolicies {
    current: Model,
    pending: Option<crate::member_carrier_guard::ExchangePlan>,
    // Exact full protected DATA, including context and revision. Still not ACK.
    protected_record: Vec<u8>,
}
impl ColdGuardPolicies {
    #[cfg(windows)]
    pub(crate) fn from_authenticated_facts(
        facts: &crate::windows::member_carrier_recovery::RecoveryFacts,
    ) -> Result<Self> {
        let (current, pending, protected_record) = if let Some(record) = &facts.guard {
            // Encoding invokes the legacy record's context/model/plan validation.
            let protected_record = record.encode().map_err(|_| GuardError::Conflict)?;
            (
                record.current.clone(),
                record.pending.clone(),
                protected_record,
            )
        } else {
            let pair = facts.pair.as_ref().ok_or(GuardError::Conflict)?;
            pair.validate().map_err(|_| GuardError::Conflict)?;
            let context = facts.context.as_ref().ok_or(GuardError::Conflict)?;
            crate::windows::member_session::validate_guard_model(context, &pair.guard)
                .map_err(|_| GuardError::Conflict)?;
            if let Some(plan) = &pair.pending_guard {
                for model in [&plan.expected, &plan.withdrawn, &plan.base, &plan.desired] {
                    crate::windows::member_session::validate_guard_model(context, model)
                        .map_err(|_| GuardError::Conflict)?;
                }
            }
            let protected_record = pair.encode().map_err(|_| GuardError::Conflict)?;
            (
                pair.guard.clone(),
                pair.pending_guard.clone(),
                protected_record,
            )
        };
        Ok(Self {
            current,
            pending,
            protected_record,
        })
    }
}
/// # Safety
/// Supply ONLY the SAME signed OLD installation, original private protected
/// record/context and held mutation lock, acknowledged dead original creator,
/// current bounded cleanup Calling and full C/A/B, process, socket, network and
/// row native absence. Hold their lease across `read`, reattest before/after
/// EVERY callback, and preserve the authenticated write-ahead record unchanged.
/// Policies are comparison DATA. No reconstructed Source/Retired/creator ACK.
/// Reentry, error (including callback error) or unwind permanently revokes this
/// issuer, even if a caller swallows the failure. No successful default.
pub(crate) unsafe trait ColdStaticAuthorization {
    fn with_cleanup_authority<T>(
        &self,
        scope: &SessionScope,
        read: impl FnOnce(&ColdGuardPolicies) -> Result<T>,
    ) -> Result<T>;
}
/// Only the external static BFE boundary is replaceable in portable tests.
pub(crate) trait ColdStaticNativeApi {
    fn begin(&mut self, readonly: bool) -> Result<()>;
    fn read_full(&mut self, scope: &SessionScope) -> Result<ColdWfpFacts>;
    fn delete_original_block(&mut self, original: &NativeFilter) -> Result<()>;
    fn delete_original_sublayer(&mut self, original: &Sublayer) -> Result<()>;
    fn commit(&mut self) -> Result<()>;
    fn abort(&mut self) -> Result<()>;
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ColdWfpFacts {
    pub(super) sublayer: Option<Sublayer>,
    pub(super) filters: Vec<NativeFilter>,
    pub(super) arbitration: Vec<ArbitrationFilter>,
}
/// Separate retained cleanup issuer. No constructor from JSON, serialization,
/// adoption/live APIs, original Guard ACK or automatic deletion on Drop.
pub(crate) struct ColdStaticCleanup<N: ColdStaticNativeApi, A: ColdStaticAuthorization> {
    scope: SessionScope,
    authority: std::rc::Rc<A>,
    io: std::cell::RefCell<Option<N>>,
    policies: std::cell::RefCell<Option<ColdGuardPolicies>>,
    captured: std::cell::RefCell<Option<ColdWfpFacts>>,
    busy: std::cell::Cell<bool>,
    failed: std::cell::Cell<bool>,
    attempted: std::cell::Cell<bool>,
    commit_ack: std::cell::Cell<bool>,
    complete: std::cell::Cell<bool>,
}
impl<N: ColdStaticNativeApi, A: ColdStaticAuthorization> ColdStaticCleanup<N, A> {
    fn root(scope: SessionScope, authority: std::rc::Rc<A>) -> std::rc::Rc<Self> {
        std::rc::Rc::new(Self {
            scope,
            authority,
            io: std::cell::RefCell::new(None),
            policies: std::cell::RefCell::new(None),
            captured: std::cell::RefCell::new(None),
            busy: std::cell::Cell::new(false),
            failed: std::cell::Cell::new(false),
            attempted: std::cell::Cell::new(false),
            commit_ack: std::cell::Cell::new(false),
            complete: std::cell::Cell::new(false),
        })
    }
    fn enter(&self) -> Result<ColdFlight<'_, N, A>> {
        if self.failed.get() || self.busy.replace(true) {
            self.failed.set(true);
            return Err(GuardError::Conflict);
        }
        Ok(ColdFlight {
            root: self,
            success: false,
        })
    }
    fn healthy(&self) -> Result<()> {
        if self.failed.get() {
            Err(GuardError::Conflict)
        } else {
            Ok(())
        }
    }
    fn authorized<T>(&self, read: impl FnOnce(&ColdGuardPolicies) -> Result<T>) -> Result<T> {
        struct Flight<'a> {
            failed: &'a std::cell::Cell<bool>,
            success: bool,
        }
        impl Drop for Flight<'_> {
            fn drop(&mut self) {
                if !self.success {
                    self.failed.set(true);
                }
            }
        }
        self.healthy()?;
        let mut outer = Flight {
            failed: &self.failed,
            success: false,
        };
        let invoked = std::cell::Cell::new(false);
        let completed = std::cell::Cell::new(false);
        let output = self.authority.with_cleanup_authority(&self.scope, |data| {
            invoked.set(true);
            let mut inner = Flight {
                failed: &self.failed,
                success: false,
            };
            let output = read(data)?;
            self.healthy()?;
            completed.set(true);
            inner.success = true;
            Ok(output)
        })?;
        // Callback failure/unwind is sticky independently of the external
        // authorizer, even if that unsafe boundary wrongly swallows it.
        if !invoked.get() || !completed.get() {
            return Err(GuardError::Conflict);
        }
        self.healthy()?;
        outer.success = true;
        Ok(output)
    }
    pub(super) fn initialize(&self, open: impl FnOnce() -> Result<N>) -> Result<()> {
        let mut flight = self.enter()?;
        if self
            .io
            .try_borrow()
            .map_err(|_| GuardError::Conflict)?
            .is_some()
        {
            return Err(GuardError::Conflict);
        }
        self.authorized(|data| {
            cold_known_policies(&self.scope, data)?;
            self.healthy()?;
            // Actual engine output retained before authorizer postflight.
            *self.io.try_borrow_mut().map_err(|_| GuardError::Conflict)? = Some(open()?);
            *self
                .policies
                .try_borrow_mut()
                .map_err(|_| GuardError::Conflict)? = Some(data.clone());
            self.healthy()
        })?;
        self.healthy()?;
        flight.success = true;
        Ok(())
    }
    fn compare_authorized(&self, data: &ColdGuardPolicies) -> Result<()> {
        cold_known_policies(&self.scope, data)?;
        let original = self
            .policies
            .try_borrow()
            .map_err(|_| GuardError::Conflict)?;
        if original.as_ref() != Some(data) {
            return Err(GuardError::Conflict);
        }
        self.healthy()
    }
    pub(super) fn capture(&self) -> Result<()> {
        let mut flight = self.enter()?;
        if self
            .captured
            .try_borrow()
            .map_err(|_| GuardError::Conflict)?
            .is_some()
            || self.attempted.get()
        {
            return Err(GuardError::Conflict);
        }
        for _ in 0..2 {
            self.authorized(|data| {
                self.compare_authorized(data)?;
                let mut held = self.io.try_borrow_mut().map_err(|_| GuardError::Conflict)?;
                let io = held.as_mut().ok_or(GuardError::Conflict)?;
                cold_transaction(io, true, |io| {
                    let actual = cold_read_checked(io, &self.scope, data)?;
                    let mut captured = self
                        .captured
                        .try_borrow_mut()
                        .map_err(|_| GuardError::Conflict)?;
                    match captured.as_ref() {
                        Some(before) if before != &actual => return Err(GuardError::Conflict),
                        Some(_) => {}
                        // Factual first native IDs retained even on lost read
                        // commit/postflight. They are NOT a creator ACK.
                        None => *captured = Some(actual),
                    }
                    self.healthy()
                })
            })?;
            self.healthy()?;
        }
        flight.success = true;
        Ok(())
    }
    pub(crate) fn cleanup(&self) -> Result<()> {
        let mut flight = self.enter()?;
        if self.attempted.replace(true) || self.complete.get() {
            return Err(GuardError::Conflict);
        }
        let original = self
            .captured
            .try_borrow()
            .map_err(|_| GuardError::Conflict)?
            .clone()
            .ok_or(GuardError::Conflict)?;
        self.authorized(|data| {
            self.compare_authorized(data)?;
            let mut held = self.io.try_borrow_mut().map_err(|_| GuardError::Conflict)?;
            let io = held.as_mut().ok_or(GuardError::Conflict)?;
            cold_transaction(io, false, |io| {
                if cold_read_checked(io, &self.scope, data)? != original {
                    return Err(GuardError::Conflict);
                }
                self.healthy()?;
                for block in &original.filters {
                    self.healthy()?;
                    // SDK implementation rechecks SAME key/ID/full policy and
                    // deletes ById on THIS static engine, never retry dynamic.
                    io.delete_original_block(block)?;
                }
                let remaining = cold_read_checked(io, &self.scope, data)?;
                if !remaining.filters.is_empty() || remaining.sublayer != original.sublayer {
                    return Err(GuardError::Conflict);
                }
                self.healthy()?;
                if let Some(sub) = &original.sublayer {
                    io.delete_original_sublayer(sub)?;
                }
                cold_require_absent(&cold_read_checked(io, &self.scope, data)?)?;
                self.healthy()
            })?;
            // The actual static transaction ACK is rooted BEFORE fallible
            // native absence/authorizer postflight; lost ACK remains unknown.
            self.commit_ack.set(true);
            self.healthy()
        })?;
        self.healthy()?;
        for _ in 0..2 {
            self.authorized(|data| {
                self.compare_authorized(data)?;
                let mut held = self.io.try_borrow_mut().map_err(|_| GuardError::Conflict)?;
                let io = held.as_mut().ok_or(GuardError::Conflict)?;
                cold_transaction(io, true, |io| {
                    cold_require_absent(&cold_read_checked(io, &self.scope, data)?)
                })
            })?;
            self.healthy()?;
        }
        self.complete.set(true);
        flight.success = true;
        Ok(())
    }
    /// Facts only, including partial/lost-ACK outcomes; not release permission.
    pub(crate) fn disposition(&self) -> (bool, bool, bool) {
        (
            self.commit_ack.get(),
            self.complete.get(),
            self.failed.get(),
        )
    }
}
fn retain_cold_issuer<N: ColdStaticNativeApi, A: ColdStaticAuthorization>(
    scope: SessionScope,
    authority: std::rc::Rc<A>,
    retain: impl FnOnce(std::rc::Rc<ColdStaticCleanup<N, A>>) -> Result<()>,
    open: impl FnOnce() -> Result<N>,
) -> Result<std::rc::Rc<ColdStaticCleanup<N, A>>> {
    let root = ColdStaticCleanup::root(scope, authority);
    {
        let mut flight = root.enter()?;
        retain(root.clone())?;
        // Factual ownership/lifetime check only, NOT native permission: reject
        // a callback that discarded the output. Caller must keep this SAME Rc
        // in its serialized owner slot throughout failures and postflight.
        if std::rc::Rc::strong_count(&root) < 2 {
            return Err(GuardError::Conflict);
        }
        root.healthy()?;
        flight.success = true;
    }
    root.initialize(open)?;
    root.capture()?;
    Ok(root)
}
struct ColdFlight<'a, N: ColdStaticNativeApi, A: ColdStaticAuthorization> {
    root: &'a ColdStaticCleanup<N, A>,
    success: bool,
}
impl<N: ColdStaticNativeApi, A: ColdStaticAuthorization> Drop for ColdFlight<'_, N, A> {
    fn drop(&mut self) {
        self.root.busy.set(false);
        if !self.success {
            self.root.failed.set(true);
        }
    }
}
fn cold_known_policies(scope: &SessionScope, data: &ColdGuardPolicies) -> Result<Vec<Snapshot>> {
    if !scope.validate() || data.current.scope != *scope || data.protected_record.is_empty() {
        return Err(GuardError::Conflict);
    }
    data.current.validate()?;
    let mut models = vec![&data.current];
    if let Some(p) = &data.pending {
        p.validate()?;
        if p.expected != data.current {
            return Err(GuardError::Conflict);
        }
        models.extend([&p.expected, &p.withdrawn, &p.base, &p.desired]);
    }
    models
        .into_iter()
        .map(|model| {
            if model.scope != *scope {
                return Err(GuardError::Conflict);
            }
            model.validate()?;
            Ok(model.without_permits()?.expected)
        })
        .collect()
}
fn cold_read_checked<N: ColdStaticNativeApi>(
    io: &mut N,
    scope: &SessionScope,
    data: &ColdGuardPolicies,
) -> Result<ColdWfpFacts> {
    let known = cold_known_policies(scope, data)?;
    let keys = crate::member_carrier_guard::resource_keys(scope)?;
    let mut actual = io.read_full(scope)?;
    if actual.filters.len() > 48 || actual.arbitration.len() > MAX_ARBITRATION_FILTERS {
        return Err(GuardError::Conflict);
    }
    if let Some(sub) = &actual.sublayer {
        if sub.key != keys.sublayer
            || sub.flags != 0
            || !known.iter().any(|s| s.sublayer.as_ref() == Some(sub))
        {
            return Err(GuardError::Conflict);
        }
    } else if !actual.filters.is_empty() {
        return Err(GuardError::Conflict);
    }
    actual.filters.sort_by_key(|f| f.policy.key);
    for (i, f) in actual.filters.iter().enumerate() {
        if f.id == 0
            || f.policy.action != Action::Block
            || f.policy.flags != 0
            || f.policy.weight != 1
            || f.policy.sublayer != keys.sublayer
            || !keys.filters.contains(&f.policy.key)
            || actual.filters[..i]
                .iter()
                .any(|old| old.id == f.id || old.policy.key == f.policy.key)
            || !known
                .iter()
                .any(|s| s.sublayer == actual.sublayer && s.filters.contains(&f.policy))
        {
            return Err(GuardError::Conflict);
        }
    }
    // FULL eight-layer inventory, not just 48 key lookups. Scoped extras,
    // reused IDs, duplicate enumeration and disguised permits deny outright.
    actual.arbitration.sort_by_key(|f| f.id);
    for (i, f) in actual.arbitration.iter().enumerate() {
        if f.id == 0
            || actual.arbitration[..i]
                .iter()
                .any(|old| old.id == f.id || old.key == f.key)
        {
            return Err(GuardError::Conflict);
        }
        if f.sublayer == keys.sublayer {
            let sub = actual.sublayer.as_ref().ok_or(GuardError::Conflict)?;
            if !actual.filters.iter().any(|own| {
                own.id == f.id
                    && own.policy.key == f.key
                    && own.policy.layer == f.layer
                    && f.sublayer_weight == sub.weight
                    && f.flags == 0
                    && f.action == FWP_ACTION_BLOCK
            }) {
                return Err(GuardError::Conflict);
            }
        } else if actual
            .filters
            .iter()
            .any(|own| own.id == f.id || own.policy.key == f.key)
        {
            return Err(GuardError::Conflict);
        }
    }
    if actual
        .filters
        .iter()
        .any(|f| !actual.arbitration.iter().any(|a| a.id == f.id))
    {
        return Err(GuardError::Conflict);
    }
    Ok(actual)
}
fn cold_require_absent(actual: &ColdWfpFacts) -> Result<()> {
    if actual.sublayer.is_some() || !actual.filters.is_empty() {
        Err(GuardError::RemovalUnconfirmed)
    } else {
        Ok(())
    }
}
struct ColdTransaction<'a, N: ColdStaticNativeApi> {
    io: &'a mut N,
    finished: bool,
}
impl<N: ColdStaticNativeApi> Drop for ColdTransaction<'_, N> {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.io.abort();
        }
    }
}
fn cold_transaction<N: ColdStaticNativeApi, T>(
    io: &mut N,
    readonly: bool,
    run: impl FnOnce(&mut N) -> Result<T>,
) -> Result<T> {
    io.begin(readonly)?;
    let mut tx = ColdTransaction {
        io,
        finished: false,
    };
    let output = run(tx.io)?;
    tx.io.commit()?;
    tx.finished = true;
    Ok(output)
}
/// Opaque synchronous read window over the guard's already active write
/// transaction. Only NativeGuard constructs it, from actual retained ownership
/// and the exact native snapshot just checked against the exchange's CAS.
/// No engine, transaction or effect operation is exposed. The borrowed window
/// cannot escape authorize, and cannot move to/share with another thread.
pub(crate) struct LockedWfpRead<'a, N: NativeApi> {
    io: &'a mut N,
    scope: &'a SessionScope,
    kind: SessionKind,
    ids: &'a BTreeMap<Key, u64>,
    captured: &'a Snapshot,
    failed_read: bool,
    _serialized: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl<N: NativeApi> LockedWfpRead<'_, N> {
    /// Fresh read-only sublayer + ALL 48 scoped key queries on the SAME engine.
    /// Exact retained IDs and captured priority/policy/bindings must still match.
    /// The supplied facts are comparison data, never ownership or effect authority.
    pub(crate) fn snapshot(&mut self, bindings: &Bindings) -> Result<Snapshot> {
        // Sticky even if authority catches a native read unwind/error itself.
        let was_failed = self.failed_read;
        self.failed_read = true;
        let actual = read_native_snapshot(self.io, bindings, self.scope, self.kind, self.ids)?;
        if actual != *self.captured {
            return Err(GuardError::Conflict);
        }
        self.failed_read = was_failed;
        Ok(actual)
    }
    /// Conservative arbitration barrier, not a claim that foreign filters are
    /// disjoint, a traffic test or continuous protection against later writers.
    /// An equal/higher foreign hard permit or opaque callout is rejected. Own
    /// sublayer contamination, incomplete inventory and read errors also fail.
    /// Never change foreign policy, raise priority or convert our soft permits.
    pub(crate) fn priority_barrier(&mut self) -> Result<()> {
        let was_failed = self.failed_read;
        self.failed_read = true;
        let filters = self.io.arbitration(self.kind)?;
        validate_arbitration(self.scope, self.captured, self.ids, &filters)?;
        self.failed_read = was_failed;
        Ok(())
    }
}
/// Structural comparison only; caller must obtain every input through the
/// actual same-transaction SDK reader. Equal/imported facts grant no authority.
pub(crate) fn validate_arbitration(
    scope: &SessionScope,
    snapshot: &Snapshot,
    ids: &BTreeMap<Key, u64>,
    filters: &[ArbitrationFilter],
) -> Result<()> {
    let sub = snapshot.sublayer.as_ref().ok_or(GuardError::Conflict)?;
    let keys = crate::member_carrier_guard::resource_keys(scope)?;
    if snapshot.scope != *scope
        || sub.key != keys.sublayer
        || sub.flags != 0
        || filters.len() > MAX_ARBITRATION_FILTERS
    {
        return Err(GuardError::Conflict);
    }
    let mut seen_keys = std::collections::BTreeSet::new();
    let mut seen_ids = std::collections::BTreeSet::new();
    let mut seen_owned = std::collections::BTreeSet::new();
    for f in filters {
        if f.id == 0 || !seen_keys.insert(f.key) || !seen_ids.insert(f.id) {
            return Err(GuardError::Conflict);
        }
        if f.sublayer == sub.key {
            let exact = snapshot
                .filters
                .iter()
                .find(|e| e.key == f.key)
                .ok_or(GuardError::Conflict)?;
            let action = if exact.action == Action::Block {
                FWP_ACTION_BLOCK
            } else {
                FWP_ACTION_PERMIT
            };
            if ids.get(&f.key) != Some(&f.id)
                || f.sublayer_weight != sub.weight
                || exact.layer != f.layer
                || exact.flags != f.flags
                || action != f.action
            {
                return Err(GuardError::Conflict);
            }
            seen_owned.insert(f.key);
        } else {
            // No own key may be crossbound into another provider's sublayer.
            if keys.filters.contains(&f.key) {
                return Err(GuardError::Conflict);
            }
            if f.flags & FWPM_FILTER_FLAG_DISABLED == 0 && f.sublayer_weight >= sub.weight {
                let soft_permit = f.action == FWP_ACTION_PERMIT
                    && f.flags & FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT == 0;
                if !soft_permit && f.action != FWP_ACTION_BLOCK && f.action != FWP_ACTION_CONTINUE {
                    return Err(GuardError::Conflict);
                }
            }
        }
    }
    if seen_owned.len() != snapshot.filters.len() {
        return Err(GuardError::Conflict);
    }
    Ok(())
}
pub(crate) struct NativeGuard<N: NativeApi, A: BindingAttestor> {
    scope: SessionScope,
    io: N,
    attestor: A,
    failed: bool,
    current: Model,
    pending: Option<Model>,
    owned_ids: BTreeMap<Key, u64>,
    original: std::rc::Rc<()>,
    terminal: Option<std::rc::Rc<GuardEngineClosure>>,
    #[cfg(windows)]
    terminal_native: Option<std::rc::Rc<NativeGuardTerminalClose>>,
}
/// Read-only startup inventory. This is NOT ownership, an adopted guard or an
/// effect capability. The coordinator must bracket it with its actual original
/// owners and authenticated operation. Any uncertainty permanently retires it.
pub(crate) struct ScopedGuardAbsence<N: NativeApi> {
    scope: SessionScope,
    io: N,
    failed: bool,
}
impl<N: NativeApi> ScopedGuardAbsence<N> {
    pub(crate) fn new(scope: SessionScope, io: N) -> Result<Self> {
        crate::member_carrier_guard::resource_keys(&scope)?;
        Ok(Self {
            scope,
            io,
            failed: false,
        })
    }
    pub(crate) fn verify(&mut self, expected: &SessionScope) -> Result<()> {
        self.read_snapshot(expected).map(|_| ())
    }
    /// Actual complete scoped SDK snapshot from a committed readonly
    /// transaction, not an empty model imported by the caller. Factual only;
    /// cannot adopt/release filters or authorize any native effect.
    pub(crate) fn read_snapshot(&mut self, expected: &SessionScope) -> Result<Snapshot> {
        let was_failed = self.failed;
        self.failed = true;
        if was_failed || expected != &self.scope {
            return Err(GuardError::Conflict);
        }
        let scope = &self.scope;
        let actual = transaction(&mut self.io, SessionKind::StaticBase, true, |io| {
            let bindings = Bindings {
                scope: scope.clone(),
                carrier: None,
                egress: [None, None],
            };
            let actual = read_native_snapshot(
                io,
                &bindings,
                scope,
                SessionKind::StaticBase,
                &BTreeMap::new(),
            )?;
            if actual != Model::empty(scope.clone())?.expected {
                return Err(GuardError::Conflict);
            }
            Ok(actual)
        })?;
        self.failed = false;
        Ok(actual)
    }
}
impl<N: NativeApi, A: BindingAttestor> NativeGuard<N, A> {
    fn exchange_retired_base(&mut self, expected: &Model) -> Result<Model> {
        let empty = Model::empty(self.scope.clone())?;
        self.exchange_checked(SessionKind::StaticBase, expected, &empty, true)
    }
    fn exchange_checked(
        &mut self,
        kind: SessionKind,
        expected: &Model,
        desired: &Model,
        cleanup: bool,
    ) -> Result<Model> {
        let validation = crate::member_carrier_guard::validate_session_exchange(
            &self.scope,
            expected,
            desired,
            kind,
        );
        if let Err(e) = validation {
            return self.fail(e);
        }
        let known_expected = if cleanup {
            kind == SessionKind::StaticBase
                && !expected.permits
                && *desired == Model::empty(self.scope.clone())?
                && std::iter::once(&self.current)
                    .chain(self.pending.iter())
                    .any(|model| {
                        model
                            .without_permits()
                            .is_ok_and(|model| model == *expected)
                    })
        } else {
            self.current == *expected
        };
        if self.terminal.is_some() || (self.failed && !cleanup) || !known_expected {
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
            {
                let mut locked = LockedWfpRead {
                    io,
                    scope,
                    kind,
                    ids,
                    captured: &actual,
                    failed_read: false,
                    _serialized: std::marker::PhantomData,
                };
                attestor.authorize(kind, expected, desired, &mut locked)?;
                if desired.permits {
                    locked.priority_barrier()?;
                }
                if locked.failed_read {
                    return Err(GuardError::Conflict);
                }
            }
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
                self.failed = cleanup; // Final cleanup never re-arms forward writes.
                Ok(captured)
            }
            Ok(_) => self.fail(GuardError::Conflict),
            Err(e) => self.fail(e),
        }
    }
    fn compare_snapshot(&self, actual: &Snapshot, was_failed: bool) -> Result<()> {
        if !was_failed {
            if *actual != self.current.expected {
                return Err(GuardError::Conflict);
            }
        } else if !std::iter::once(&self.current)
            .chain(self.pending.iter())
            .any(|m| m.without_permits().is_ok_and(|m| m.expected == *actual))
        {
            return Err(GuardError::RemovalUnconfirmed);
        }
        Ok(())
    }
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
            original: std::rc::Rc::new(()),
            terminal: None,
            #[cfg(windows)]
            terminal_native: None,
        })
    }
    fn fail<T>(&mut self, error: GuardError) -> Result<T> {
        self.failed = true;
        if self.terminal.is_some() {
            return Err(error);
        }
        self.io
            .close(SessionKind::DynamicPermits)
            .map_err(|_| GuardError::RemovalUnconfirmed)?;
        Err(error)
    }
    fn read_snapshot(&mut self) -> Result<Snapshot> {
        transaction(&mut self.io, SessionKind::StaticBase, true, |io| {
            let actual = read_locked(
                io,
                &mut self.attestor,
                &self.scope,
                SessionKind::StaticBase,
                &self.owned_ids,
            )?;
            if actual.filters.iter().any(|f| f.action == Action::Permit) {
                let before = self.attestor.observe(&self.scope)?;
                validate_bindings(&self.scope, &before)?;
                let filters = io.arbitration(SessionKind::StaticBase)?;
                validate_arbitration(&self.scope, &actual, &self.owned_ids, &filters)?;
                let after = self.attestor.observe(&self.scope)?;
                validate_bindings(&self.scope, &after)?;
                if before != after {
                    return Err(GuardError::Conflict);
                }
            }
            Ok(actual)
        })
    }
}
impl<N: NativeApi, A: BindingAttestor> SplitEngines for NativeGuard<N, A> {
    fn snapshot(&mut self) -> Result<Snapshot> {
        if self.terminal.is_some() {
            return Err(GuardError::Conflict);
        }
        let was_failed = self.failed;
        self.failed = true; // Poison first: caller catching an authority unwind cannot resume.
        let result = (|| {
            let actual = self.read_snapshot()?;
            // Ambiguity is terminal for writes; only retained no-permit cleanup
            // snapshots qualify. No later priority/policy/native-ID adoption.
            self.compare_snapshot(&actual, was_failed)?;
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
        self.exchange_checked(kind, expected, desired, false)
    }
    fn close_permits(&mut self) -> Result<()> {
        self.failed = true;
        if self.terminal.is_some() {
            return Err(GuardError::Conflict);
        }
        self.io
            .close(SessionKind::DynamicPermits)
            .map_err(|_| GuardError::RemovalUnconfirmed)
    }
}
impl<N: NativeApi, A: BindingAttestor> Drop for NativeGuard<N, A> {
    fn drop(&mut self) {
        if self.terminal.is_some() {
            return;
        }
        // Close is NOT proof of allow absence and never releases a probe port.
        // Ordinary nonpersistent bases survive static engine close.
        let _ = self.io.close(SessionKind::DynamicPermits);
        let _ = self.io.close(SessionKind::StaticBase);
    }
}
impl<N: TerminalNativeApi, A: BindingAttestor> NativeGuard<N, A> {
    fn begin_terminal_close(&mut self) -> Result<std::rc::Rc<GuardEngineClosure>> {
        self.failed = true;
        if let Some(original) = &self.terminal {
            original.failed.set(true);
            return Err(GuardError::Conflict);
        }
        self.io.enter_terminal_lane();
        let original = std::rc::Rc::new(GuardEngineClosure {
            scope: self.scope.clone(),
            guard: self.original.clone(),
            engines: [
                self.io.engine_origin(SessionKind::StaticBase),
                self.io.engine_origin(SessionKind::DynamicPermits),
            ],
            acks: std::cell::RefCell::new([None, None]),
            attempted: std::cell::Cell::new(false),
            complete: std::cell::Cell::new(false),
            failed: std::cell::Cell::new(false),
        });
        self.terminal = Some(original.clone());
        // Emergency permit closure may already have a real ACK. Mirror that
        // SAME original receipt before any terminal registration/postflight;
        // absent/unknown ACK stays absent and can never be inferred from flags.
        for kind in [SessionKind::StaticBase, SessionKind::DynamicPermits] {
            retain_engine_ack(&self.io, &original, kind)?;
        }
        Ok(original)
    }
    fn close_terminal_checked(
        &mut self,
        original: &std::rc::Rc<GuardEngineClosure>,
        bindings: &Bindings,
        bracket: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        close_terminal_parts(
            GuardTerminalParts {
                scope: &self.scope,
                current: &self.current,
                pending: &self.pending,
                ids: &self.owned_ids,
                origin: &self.original,
                terminal: &self.terminal,
                io: &mut self.io,
            },
            original,
            bindings,
            bracket,
        )
    }
    /// SAME original close ACKs plus successful whole lane, not phase/Option
    /// absence. Pure engine destructor proof only; independent terminal SDK and
    /// canonical resource/module gates remain mandatory.
    pub(crate) fn verify_terminal_inert(
        &self,
        original: &std::rc::Rc<GuardEngineClosure>,
    ) -> Result<()> {
        verify_terminal_engine_receipts(&self.io, &self.original, &self.terminal, original)
    }
}
struct GuardTerminalParts<'a, N> {
    scope: &'a SessionScope,
    current: &'a Model,
    pending: &'a Option<Model>,
    ids: &'a BTreeMap<Key, u64>,
    origin: &'a std::rc::Rc<()>,
    terminal: &'a Option<std::rc::Rc<GuardEngineClosure>>,
    io: &'a mut N,
}
/// Retain the actual opaque receipt before calling a fallible registration.
/// This transfers facts only: it never performs/acknowledges a native close.
fn retain_terminal_original<T>(
    destination: &mut Option<std::rc::Rc<T>>,
    original: &std::rc::Rc<T>,
    engines: &std::rc::Rc<GuardEngineClosure>,
    retain: impl FnOnce(std::rc::Rc<T>) -> Result<()>,
) -> Result<()> {
    let mut flight = GuardCloseFlight {
        original: engines.clone(),
        succeeded: false,
    };
    if destination.is_some() {
        return Err(GuardError::Conflict);
    }
    *destination = Some(original.clone());
    retain(original.clone())?;
    if engines.failed.get() {
        return Err(GuardError::Conflict);
    }
    flight.succeeded = true;
    Ok(())
}
fn retain_engine_ack<N: TerminalNativeApi>(
    io: &N,
    original: &GuardEngineClosure,
    kind: SessionKind,
) -> Result<()> {
    if let Ok(ack) = io.engine_close_ack(kind) {
        let index = usize::from(kind == SessionKind::DynamicPermits);
        if !std::rc::Rc::ptr_eq(&ack.origin, &original.engines[index]) || ack.kind != kind {
            original.failed.set(true);
            return Err(GuardError::Conflict);
        }
        original
            .acks
            .try_borrow_mut()
            .map_err(|_| GuardError::Conflict)?[index] = Some(ack);
    }
    Ok(())
}
fn close_terminal_parts<N: TerminalNativeApi>(
    parts: GuardTerminalParts<'_, N>,
    original: &std::rc::Rc<GuardEngineClosure>,
    bindings: &Bindings,
    mut bracket: impl FnMut() -> Result<()>,
) -> Result<()> {
    if parts
        .terminal
        .as_ref()
        .is_none_or(|r| !std::rc::Rc::ptr_eq(r, original))
        || original.attempted.replace(true)
        || original.failed.get()
        || bindings.scope != *parts.scope
        || original.scope != *parts.scope
    {
        original.failed.set(true);
        return Err(GuardError::Conflict);
    }
    let mut flight = GuardCloseFlight {
        original: original.clone(),
        succeeded: false,
    };
    let empty = Model::empty(parts.scope.clone())?;
    if *parts.current != empty || parts.pending.is_some() || !parts.ids.is_empty() {
        original.failed.set(true);
        return Err(GuardError::Conflict);
    }
    bracket()?;
    for _ in 0..2 {
        let actual = transaction(parts.io, SessionKind::StaticBase, true, |io| {
            read_native_snapshot(
                io,
                bindings,
                parts.scope,
                SessionKind::StaticBase,
                parts.ids,
            )
        })?;
        if actual != empty.expected {
            original.failed.set(true);
            return Err(GuardError::Conflict);
        }
        bracket()?;
    }
    for kind in [SessionKind::DynamicPermits, SessionKind::StaticBase] {
        bracket()?;
        let closed = parts.io.close_terminal_engine(kind);
        let captured = retain_engine_ack(parts.io, original, kind);
        // Always run independent post-attempt facts, including on a real
        // close error/lost ACK. They cannot turn an unknown close into ACK.
        let post = bracket();
        closed?;
        captured?;
        post?;
    }
    bracket()?;
    if original.failed.get() {
        return Err(GuardError::Conflict);
    }
    original.complete.set(true);
    verify_terminal_engine_receipts(parts.io, parts.origin, parts.terminal, original)?;
    flight.succeeded = true;
    Ok(())
}
fn verify_terminal_engine_receipts<N: TerminalNativeApi>(
    io: &N,
    guard: &std::rc::Rc<()>,
    retained: &Option<std::rc::Rc<GuardEngineClosure>>,
    original: &std::rc::Rc<GuardEngineClosure>,
) -> Result<()> {
    if retained
        .as_ref()
        .is_none_or(|r| !std::rc::Rc::ptr_eq(r, original))
        || !std::rc::Rc::ptr_eq(guard, &original.guard)
        || !original.complete.get()
        || original.failed.get()
    {
        return Err(GuardError::RemovalUnconfirmed);
    }
    let acks = original.acknowledgements()?;
    for kind in [SessionKind::StaticBase, SessionKind::DynamicPermits] {
        let i = usize::from(kind == SessionKind::DynamicPermits);
        let ack = acks[i].as_ref().ok_or(GuardError::RemovalUnconfirmed)?;
        if !std::rc::Rc::ptr_eq(&io.engine_origin(kind), &original.engines[i]) {
            return Err(GuardError::Conflict);
        }
        io.verify_engine_inert(kind, ack)?;
    }
    Ok(())
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
    crate::member_carrier_guard::validate_factual_bindings(
        scope,
        b.carrier.as_ref(),
        b.egress.each_ref().map(Option::as_ref),
    )?;
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
    let actual = read_native_snapshot(io, &bindings, scope, kind, ids)?;
    // Include even currently unreferenced owners: a foreign/rebound B or source
    // appearing during an EMPTY/base read may not be hidden by the projection.
    // This remains a sampled continuity fence, not atomicity against OS writers.
    let after = a.observe(scope)?;
    validate_bindings(scope, &after)?;
    if bindings != after {
        return Err(GuardError::Conflict);
    }
    Ok(actual)
}
fn read_native_snapshot<N: NativeApi>(
    io: &mut N,
    bindings: &Bindings,
    scope: &SessionScope,
    kind: SessionKind,
    ids: &BTreeMap<Key, u64>,
) -> Result<Snapshot> {
    validate_bindings(scope, bindings)?;
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
    // Only bindings REFERENCED by this scoped policy are projected. Callers
    // supply comparison facts from independent observation, never from WFP
    // index/key inference. New physical B may exist before its base is attached.
    Ok(Snapshot {
        version: 2,
        scope: scope.clone(),
        carrier: if installed {
            bindings.carrier.clone()
        } else {
            None
        },
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

    /// ONE ordinary static cleanup engine, never a reopened live Guard owner.
    /// No add/permit/Source/retirement/module APIs are exposed.
    pub(crate) struct ColdBfe {
        scope: SessionScope,
        engine: Engine,
    }
    pub(crate) type NativeColdStaticCleanup<A> = ColdStaticCleanup<ColdBfe, A>;
    pub(crate) fn issue_cold_static_cleanup<A: ColdStaticAuthorization>(
        scope: SessionScope,
        authority: std::rc::Rc<A>,
        retain: impl FnOnce(std::rc::Rc<NativeColdStaticCleanup<A>>) -> Result<()>,
    ) -> Result<std::rc::Rc<NativeColdStaticCleanup<A>>> {
        retain_cold_issuer(scope.clone(), authority, retain, || {
            Ok(ColdBfe {
                scope,
                engine: Engine::open(SessionKind::StaticBase)?,
            })
        })
    }
    impl ColdStaticNativeApi for ColdBfe {
        fn begin(&mut self, readonly: bool) -> Result<()> {
            status(unsafe {
                FwpmTransactionBegin0(
                    self.engine.handle()?,
                    if readonly { FWPM_TXN_READ_ONLY } else { 0 },
                )
            })
        }
        fn read_full(&mut self, scope: &SessionScope) -> Result<ColdWfpFacts> {
            if scope != &self.scope {
                return Err(GuardError::Conflict);
            }
            let engine = self.engine.handle()?;
            let keys = crate::member_carrier_guard::resource_keys(scope)?;
            let sublayer = read_bfe_sublayer(engine, scope, keys.sublayer)?;
            let mut filters = Vec::new();
            for k in keys.filters {
                if let Some(f) = read_bfe_filter(engine, scope, k, keys.sublayer)? {
                    filters.push(f);
                }
            }
            let arbitration = read_cold_arbitration(engine)?;
            // NULL template: ALL layers. Extra refs outside the eight supported
            // layers are unknown, not hidden by the 48 deterministic lookups.
            let mut all_scoped = Vec::new();
            read_cold_page_set(engine, ptr::null(), |f| {
                if key(f.subLayerKey) == keys.sublayer {
                    let k = key(f.filterKey);
                    if !keys.filters.contains(&k) {
                        return Err(GuardError::Conflict);
                    }
                    all_scoped.push(unsafe { decode_filter(f, k, keys.sublayer) }?);
                }
                Ok(())
            })?;
            filters.sort_by_key(|f| f.policy.key);
            all_scoped.sort_by_key(|f| f.policy.key);
            if filters != all_scoped {
                return Err(GuardError::Conflict);
            }
            Ok(ColdWfpFacts {
                sublayer,
                filters,
                arbitration,
            })
        }
        fn delete_original_block(&mut self, original: &NativeFilter) -> Result<()> {
            let keys = crate::member_carrier_guard::resource_keys(&self.scope)?;
            if original.id == 0
                || original.policy.action != Action::Block
                || original.policy.flags != 0
                || original.policy.sublayer != keys.sublayer
                || !keys.filters.contains(&original.policy.key)
            {
                return Err(GuardError::Conflict);
            }
            let engine = self.engine.handle()?;
            if read_bfe_filter(engine, &self.scope, original.policy.key, keys.sublayer)?.as_ref()
                != Some(original)
            {
                return Err(GuardError::Conflict);
            }
            // Recheck the actual ById mapping too. A static engine cannot
            // remove an object from somebody else's dynamic session; any SDK
            // rejection aborts the WHOLE transaction, with no engine fallback.
            let mut raw = ptr::null_mut();
            let code = unsafe { FwpmFilterGetById0(engine, original.id, &mut raw) };
            let memory = Memory(raw);
            status(code)?;
            let actual = unsafe {
                decode_filter(
                    memory.0.as_ref().ok_or(GuardError::Conflict)?,
                    original.policy.key,
                    keys.sublayer,
                )
            }?;
            if &actual != original {
                return Err(GuardError::Conflict);
            }
            status(unsafe { FwpmFilterDeleteById0(engine, original.id) })
        }
        fn delete_original_sublayer(&mut self, original: &Sublayer) -> Result<()> {
            let engine = self.engine.handle()?;
            if read_bfe_sublayer(engine, &self.scope, original.key)?.as_ref() != Some(original) {
                return Err(GuardError::Conflict);
            }
            // Confirm no hidden references at ANY layer within THIS write txn.
            read_cold_page_set(engine, ptr::null(), |f| {
                if key(f.subLayerKey) == original.key {
                    Err(GuardError::Conflict)
                } else {
                    Ok(())
                }
            })?;
            status(unsafe { FwpmSubLayerDeleteByKey0(engine, &guid(original.key)) })
        }
        fn commit(&mut self) -> Result<()> {
            status(unsafe { FwpmTransactionCommit0(self.engine.handle()?) })
        }
        fn abort(&mut self) -> Result<()> {
            status(unsafe { FwpmTransactionAbort0(self.engine.handle()?) })
        }
    }
    /// Fresh bounded enumeration in the caller's already active transaction.
    /// No implicit transaction, action/condition filtering, or borrowed escape.
    fn read_cold_page_set(
        engine: HANDLE,
        template: *const FWPM_FILTER_ENUM_TEMPLATE0,
        mut inspect: impl FnMut(&FWPM_FILTER0) -> Result<()>,
    ) -> Result<()> {
        let mut handle = ptr::null_mut();
        let code = unsafe { FwpmFilterCreateEnumHandle0(engine, template, &mut handle) };
        let mut enumeration = Enumeration { engine, handle };
        status(code)?;
        if handle.is_null() {
            return Err(GuardError::Conflict);
        }
        let mut total = 0usize;
        loop {
            let mut raw = ptr::null_mut();
            let mut count = 0;
            let code = unsafe { FwpmFilterEnum0(engine, handle, 256, &mut raw, &mut count) };
            let memory = Memory(raw);
            status(code)?;
            total += count as usize;
            if count > 256 || total > MAX_ARBITRATION_FILTERS || (count != 0 && memory.0.is_null())
            {
                return Err(GuardError::Conflict);
            }
            if count != 0 {
                for f in unsafe { std::slice::from_raw_parts(memory.0, count as usize) } {
                    inspect(unsafe { f.as_ref() }.ok_or(GuardError::Conflict)?)?;
                }
            }
            if count < 256 {
                break;
            }
        }
        enumeration.close()
    }
    fn read_cold_arbitration(engine: HANDLE) -> Result<Vec<ArbitrationFilter>> {
        let mut result = Vec::new();
        let mut weights = BTreeMap::new();
        for layer in [
            Layer::TransportV4,
            Layer::TransportV6,
            Layer::PacketV4,
            Layer::PacketV6,
            Layer::ForwardV4,
            Layer::ForwardV6,
            Layer::AleConnectV4,
            Layer::AleConnectV6,
        ] {
            let template = FWPM_FILTER_ENUM_TEMPLATE0 {
                layerKey: layer_guid(layer),
                enumType: FWP_FILTER_ENUM_FULLY_CONTAINED,
                flags: FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME
                    | FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED,
                actionMask: u32::MAX,
                ..Default::default()
            };
            read_cold_page_set(engine, &template, |f| {
                if key(f.layerKey) != key(template.layerKey)
                    || result.len() >= MAX_ARBITRATION_FILTERS
                {
                    return Err(GuardError::Conflict);
                }
                let sub = key(f.subLayerKey);
                let weight = match weights.get(&sub) {
                    Some(w) => *w,
                    None => {
                        let mut raw = ptr::null_mut();
                        let code =
                            unsafe { FwpmSubLayerGetByKey0(engine, &f.subLayerKey, &mut raw) };
                        let memory = Memory(raw);
                        status(code)?;
                        let s = unsafe { memory.0.as_ref() }.ok_or(GuardError::Conflict)?;
                        if key(s.subLayerKey) != sub {
                            return Err(GuardError::Conflict);
                        }
                        weights.insert(sub, s.weight);
                        s.weight
                    }
                };
                result.push(ArbitrationFilter {
                    key: key(f.filterKey),
                    id: f.filterId,
                    layer,
                    sublayer: sub,
                    sublayer_weight: weight,
                    flags: f.flags,
                    action: f.action.r#type,
                });
                Ok(())
            })?;
        }
        Ok(result)
    }

    pub(crate) struct NativeGuardTerminalInput<'a> {
        pub pair: &'a std::rc::Rc<
            crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead,
        >,
        pub stopped: &'a crate::member_carrier_pair::Record,
        pub retired:
            &'a std::rc::Rc<crate::windows::member_carrier_runtime::native::RetiredCarrierRead>,
        pub bindings: &'a Bindings,
    }
    /// # Safety
    /// Authenticate ALL SAME original resource roots, actual terminal Calling,
    /// current protected Stopped/native-key/row/network records, real closed
    /// probe/socket ACKs and full SDK absence before/after each close. supplied
    /// WFP snapshot is factual comparison data, not authority. No Guard/Pair/
    /// Source/Retired reentry, effects, successful defaults or phase-only gate.
    /// Engine closure is this method's only pending obligation; all other
    /// destruction/native-reference disarm still belongs to canonical C/G.
    pub(crate) unsafe trait NativeGuardTerminalFence {
        fn verify_terminal_resources(
            &self,
            original: &NativeGuardTerminalClose,
            bindings: &Bindings,
            observed_wfp: &Snapshot,
        ) -> Result<()>;
    }
    /// SAME original Guard, Pair/Retired readers and actual close receipts.
    /// Partial ACKs/absence facts survive error/unwind, never grant release.
    pub(crate) struct NativeGuardTerminalClose {
        engines: std::rc::Rc<GuardEngineClosure>,
        pair: std::rc::Rc<
            crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead,
        >,
        stopped: crate::member_carrier_pair::Record,
        retired: std::rc::Rc<crate::windows::member_carrier_runtime::native::RetiredCarrierRead>,
        readers: std::cell::RefCell<Vec<std::rc::Rc<TerminalAbsenceReader>>>,
        last_absence: std::cell::RefCell<Option<Snapshot>>,
        busy: std::cell::Cell<bool>,
    }
    impl NativeGuardTerminalClose {
        pub(crate) fn original_pair(
            &self,
        ) -> &std::rc::Rc<
            crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead,
        > {
            &self.pair
        }
        pub(crate) fn expected_stopped(&self) -> &crate::member_carrier_pair::Record {
            &self.stopped
        }
        pub(crate) fn original_retired(
            &self,
        ) -> &std::rc::Rc<crate::windows::member_carrier_runtime::native::RetiredCarrierRead>
        {
            &self.retired
        }
        pub(crate) fn engine_receipts(&self) -> &std::rc::Rc<GuardEngineClosure> {
            &self.engines
        }
        pub(crate) fn inspect_last_absence<T>(
            &self,
            read: impl FnOnce(Option<&Snapshot>) -> Result<T>,
        ) -> Result<T> {
            read(
                self.last_absence
                    .try_borrow()
                    .map_err(|_| GuardError::Conflict)?
                    .as_ref(),
            )
        }
        fn observe_absence(&self, bindings: &Bindings) -> Result<Snapshot> {
            if bindings.scope != self.stopped.scope {
                return Err(GuardError::Conflict);
            }
            // Reserve the actual owning destination before opening an observer.
            // No reopened policy owner: this engine supports readonly queries
            // only, and cannot add/delete/adopt scoped objects.
            let mut roots = self
                .readers
                .try_borrow_mut()
                .map_err(|_| GuardError::Conflict)?;
            let engine = Engine::open(SessionKind::StaticBase)?;
            engine.lifetime.enter_terminal();
            let reader = std::rc::Rc::new(TerminalAbsenceReader {
                scope: bindings.scope.clone(),
                engine,
            });
            roots.push(reader.clone());
            drop(roots);
            let mut io = TerminalBfeRead { original: &reader };
            let empty = Model::empty(bindings.scope.clone())?.expected;
            let sample = |io: &mut TerminalBfeRead<'_>| {
                let actual = read_native_snapshot(
                    io,
                    bindings,
                    &bindings.scope,
                    SessionKind::StaticBase,
                    &BTreeMap::new(),
                )?;
                // Keep actual facts BEFORE observer close/resource postflight.
                *self
                    .last_absence
                    .try_borrow_mut()
                    .map_err(|_| GuardError::Conflict)? = Some(actual.clone());
                if actual != empty {
                    return Err(GuardError::Conflict);
                }
                Ok(actual)
            };
            let observed = transaction(&mut io, SessionKind::StaticBase, true, sample);
            let confirmed = match &observed {
                Ok(before) => {
                    transaction(&mut io, SessionKind::StaticBase, true, sample).and_then(|after| {
                        if &after != before {
                            Err(GuardError::Conflict)
                        } else {
                            Ok(after)
                        }
                    })
                }
                Err(e) => Err(*e),
            };
            // Explicit actual observer close even when a read failed. Unknown
            // ACK leaves this SAME reader rooted, with NO EngineDrop retry.
            let closed = reader
                .engine
                .lifetime
                .close_terminal(|handle| status(unsafe { FwpmEngineClose0(handle as HANDLE) }));
            confirmed?;
            closed?;
            reader.engine.lifetime.verify_inert()?;
            observed
        }
        fn verify_observers_inert(&self) -> Result<()> {
            for original in self
                .readers
                .try_borrow()
                .map_err(|_| GuardError::Conflict)?
                .iter()
            {
                original.engine.lifetime.verify_inert()?;
            }
            Ok(())
        }
    }
    struct TerminalAbsenceReader {
        scope: SessionScope,
        engine: Engine,
    }
    struct TerminalBfeRead<'a> {
        original: &'a TerminalAbsenceReader,
    }
    impl NativeApi for TerminalBfeRead<'_> {
        fn begin(&mut self, kind: SessionKind, readonly: bool) -> Result<()> {
            if kind != SessionKind::StaticBase || !readonly {
                return Err(GuardError::Conflict);
            }
            status(unsafe {
                FwpmTransactionBegin0(self.original.engine.handle()?, FWPM_TXN_READ_ONLY)
            })
        }
        fn commit(&mut self, kind: SessionKind) -> Result<()> {
            if kind != SessionKind::StaticBase {
                return Err(GuardError::Conflict);
            }
            status(unsafe { FwpmTransactionCommit0(self.original.engine.handle()?) })
        }
        fn abort(&mut self, kind: SessionKind) -> Result<()> {
            if kind != SessionKind::StaticBase {
                return Err(GuardError::Conflict);
            }
            status(unsafe { FwpmTransactionAbort0(self.original.engine.handle()?) })
        }
        fn close(&mut self, _: SessionKind) -> Result<()> {
            Err(GuardError::Conflict)
        }
        fn sublayer(&mut self, kind: SessionKind, key: Key) -> Result<Option<Sublayer>> {
            if kind != SessionKind::StaticBase {
                return Err(GuardError::Conflict);
            }
            read_bfe_sublayer(self.original.engine.handle()?, &self.original.scope, key)
        }
        fn filter(
            &mut self,
            kind: SessionKind,
            key: Key,
            sub: Key,
        ) -> Result<Option<NativeFilter>> {
            if kind != SessionKind::StaticBase {
                return Err(GuardError::Conflict);
            }
            read_bfe_filter(
                self.original.engine.handle()?,
                &self.original.scope,
                key,
                sub,
            )
        }
        fn arbitration(&mut self, _: SessionKind) -> Result<Vec<ArbitrationFilter>> {
            Err(GuardError::Conflict)
        }
        fn add_sublayer(&mut self, _: &Sublayer) -> Result<()> {
            Err(GuardError::Conflict)
        }
        fn delete_sublayer(&mut self, _: Key) -> Result<()> {
            Err(GuardError::Conflict)
        }
        fn add_filter(&mut self, _: SessionKind, _: &Filter) -> Result<u64> {
            Err(GuardError::Conflict)
        }
        fn delete_filter(&mut self, _: SessionKind, _: Key) -> Result<()> {
            Err(GuardError::Conflict)
        }
    }
    struct NativeTerminalFlight<'a> {
        original: &'a NativeGuardTerminalClose,
        succeeded: bool,
    }
    impl Drop for NativeTerminalFlight<'_> {
        fn drop(&mut self) {
            self.original.busy.set(false);
            if !self.succeeded {
                self.original.engines.failed.set(true);
            }
        }
    }
    impl NativeGuardTerminalClose {
        fn enter(&self) -> Result<NativeTerminalFlight<'_>> {
            if self.busy.replace(true) {
                self.engines.failed.set(true);
                return Err(GuardError::Conflict);
            }
            Ok(NativeTerminalFlight {
                original: self,
                succeeded: false,
            })
        }
    }

    pub(crate) struct Wfp {
        scope: SessionScope,
        base: Engine,
        permits: Engine,
    }
    struct Engine {
        lifetime: EngineLifetime,
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
            Ok(Self {
                lifetime: EngineLifetime::new(kind, handle as usize)?,
            })
        }
        fn handle(&self) -> Result<HANDLE> {
            if self.lifetime.acknowledged().is_ok() {
                Err(GuardError::Conflict)
            } else {
                Ok(self.lifetime.handle as HANDLE)
            }
        }
        fn close(&mut self) -> Result<()> {
            self.lifetime
                .close_ordinary(|handle| status(unsafe { FwpmEngineClose0(handle as HANDLE) }))
        }
    }
    impl Drop for Engine {
        fn drop(&mut self) {
            if self.lifetime.drop_requires_close() {
                let _ = self.close();
            }
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
    impl ScopedGuardAbsence<Wfp> {
        /// Only factual READS on our own empty sessions, under the caller's
        /// original Calling deadline. No static/dynamic object is added,
        /// deleted, adopted or reopened as an owning policy.
        pub(crate) fn open(scope: SessionScope) -> Result<Self> {
            crate::member_carrier_guard::resource_keys(&scope)?;
            let base = Engine::open(SessionKind::StaticBase)?;
            let permits = Engine::open(SessionKind::DynamicPermits)?;
            Self::new(
                scope.clone(),
                Wfp {
                    scope,
                    base,
                    permits,
                },
            )
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
    impl<A: WindowBindingAttestor> NativeGuard<Wfp, A> {
        /// Read-only native BFE/retained-ID inventory while caller holds the
        /// original full Retired/SDK absence bracket. No nested Retired read.
        pub(crate) fn snapshot_in_retired_bracket(
            &mut self,
            pair: &std::rc::Rc<
                crate::windows::member_carrier_pair_store::native_store::NativePairIntentRead,
            >,
            record: &crate::member_carrier_pair::Record,
            retired: &crate::windows::member_carrier_runtime::native::RetiredCarrierRead,
            bindings: &Bindings,
        ) -> Result<Snapshot> {
            if self.terminal.is_some() {
                return Err(GuardError::Conflict);
            }
            let was_failed = self.failed;
            self.failed = true;
            let result = (|| {
                self.attestor
                    .verify_retired_bracket(pair, record, retired, bindings)?;
                let before = transaction(&mut self.io, SessionKind::StaticBase, true, |io| {
                    read_native_snapshot(
                        io,
                        bindings,
                        &self.scope,
                        SessionKind::StaticBase,
                        &self.owned_ids,
                    )
                })?;
                self.attestor
                    .verify_retired_bracket(pair, record, retired, bindings)?;
                let after = transaction(&mut self.io, SessionKind::StaticBase, true, |io| {
                    read_native_snapshot(
                        io,
                        bindings,
                        &self.scope,
                        SessionKind::StaticBase,
                        &self.owned_ids,
                    )
                })?;
                if before != after || before.filters.iter().any(|f| f.action == Action::Permit) {
                    return Err(GuardError::Conflict);
                }
                self.compare_snapshot(&before, was_failed)?;
                self.attestor
                    .verify_retired_bracket(pair, record, retired, bindings)?;
                Ok(before)
            })();
            match result {
                Ok(snapshot) => {
                    self.failed = was_failed;
                    Ok(snapshot)
                }
                Err(error) => self.fail(error),
            }
        }
        /// Narrow final removal after original C+A+B close ACK/full absence.
        /// The actual transaction attestor separately requires its SAME opaque
        /// Retired registration/current Closing-10 and full resource G. No
        /// caller boolean or normal exchange can reopen forward writes.
        pub(crate) fn remove_base_after_retirement(
            &mut self,
            expected: &Model,
            retired: &crate::windows::member_carrier_runtime::native::RetiredCarrierRead,
        ) -> Result<Model> {
            if self.terminal.is_some() {
                return Err(GuardError::Conflict);
            }
            self.failed = true;
            let result = (|| {
                retired
                    .inspect_bindings(|bindings| {
                        if bindings.scope != self.scope {
                            return Err(crate::windows::member_carrier_wintun::Error::Conflict);
                        }
                        Ok(())
                    })
                    .map_err(|_| GuardError::Conflict)?;
                let result = self.exchange_retired_base(expected)?;
                retired
                    .inspect_bindings(|bindings| {
                        if bindings.scope != self.scope {
                            return Err(crate::windows::member_carrier_wintun::Error::Conflict);
                        }
                        Ok(())
                    })
                    .map_err(|_| GuardError::Conflict)?;
                Ok(result)
            })();
            match result {
                Ok(model) => Ok(model),
                Err(error) => self.fail(error),
            }
        }
        /// Actual SDK/retained-ID read inside a SAME original source window.
        /// Never calls observe/Source.inspect recursively or supplies effects.
        /// Write-transaction authorization must instead use LockedWfpRead on
        /// that already-active engine, with window.inspect around its reads.
        pub(crate) fn snapshot_in_window(
            &mut self,
            window: &crate::windows::member_carrier_runtime::native::NativeBindingsWindow<'_>,
        ) -> Result<Snapshot> {
            if self.terminal.is_some() {
                return Err(GuardError::Conflict);
            }
            let was_failed = self.failed;
            self.failed = true;
            let result = (|| {
                self.attestor.verify_original_window(window)?;
                let actual = window
                    .inspect(|bindings| {
                        transaction(&mut self.io, SessionKind::StaticBase, true, |io| {
                            let actual = read_native_snapshot(
                                io,
                                bindings,
                                &self.scope,
                                SessionKind::StaticBase,
                                &self.owned_ids,
                            )?;
                            if actual.filters.iter().any(|f| f.action == Action::Permit) {
                                let filters = io.arbitration(SessionKind::StaticBase)?;
                                validate_arbitration(
                                    &self.scope,
                                    &actual,
                                    &self.owned_ids,
                                    &filters,
                                )?;
                            }
                            Ok(actual)
                        })
                        .map_err(|_| crate::windows::member_carrier_wintun::Error::Conflict)
                    })
                    .map_err(|_| GuardError::Conflict)?;
                self.attestor.verify_original_window(window)?;
                self.compare_snapshot(&actual, was_failed)?;
                Ok(actual)
            })();
            match result {
                Ok(actual) => {
                    self.failed = was_failed;
                    Ok(actual)
                }
                Err(error) => self.fail(error),
            }
        }
    }
    impl<A: TerminalBindingAttestor> NativeGuard<Wfp, A> {
        /// Call inside original run_terminal_cleanup + Retired terminal history
        /// lease, NOT inside Pair.inspect. No nested deadline/Retired read.
        /// Retain receipt in caller C before fallible registration/postflight.
        pub(crate) fn close_engines_in_terminal_bracket(
            &mut self,
            input: super::NativeGuardTerminalInput<'_>,
            resources: &impl super::NativeGuardTerminalFence,
            retain: impl FnOnce(std::rc::Rc<NativeGuardTerminalClose>) -> Result<()>,
        ) -> Result<()> {
            let engines = self.begin_terminal_close()?;
            let original = std::rc::Rc::new(NativeGuardTerminalClose {
                engines: engines.clone(),
                pair: input.pair.clone(),
                stopped: input.stopped.clone(),
                retired: input.retired.clone(),
                readers: std::cell::RefCell::new(Vec::new()),
                last_absence: std::cell::RefCell::new(None),
                busy: std::cell::Cell::new(false),
            });
            let mut flight = original.enter()?;
            retain_terminal_original(&mut self.terminal_native, &original, &engines, retain)?;
            let attestor = &mut self.attestor;
            let mut bracket = || {
                attestor.verify_terminal_bracket(
                    &original.pair,
                    &original.stopped,
                    &original.retired,
                    input.bindings,
                )?;
                let observed = original.observe_absence(input.bindings)?;
                resources.verify_terminal_resources(&original, input.bindings, &observed)?;
                attestor.verify_terminal_bracket(
                    &original.pair,
                    &original.stopped,
                    &original.retired,
                    input.bindings,
                )
            };
            // Disjoint borrows: authority/resource callbacks cannot enter Guard.
            close_terminal_parts(
                GuardTerminalParts {
                    scope: &self.scope,
                    current: &self.current,
                    pending: &self.pending,
                    ids: &self.owned_ids,
                    origin: &self.original,
                    terminal: &self.terminal,
                    io: &mut self.io,
                },
                &engines,
                input.bindings,
                &mut bracket,
            )?;
            original.verify_observers_inert()?;
            flight.succeeded = true;
            Ok(())
        }
        /// Independently actual facts after partial/error/unwind too. NO inert
        /// grant, successful cleanup or forward rearm is returned by this read.
        pub(crate) fn read_terminal_close_facts_in_retired_bracket(
            &mut self,
            original: &std::rc::Rc<NativeGuardTerminalClose>,
            bindings: &Bindings,
        ) -> Result<Snapshot> {
            if self
                .terminal_native
                .as_ref()
                .is_none_or(|r| !std::rc::Rc::ptr_eq(r, original))
            {
                if let Some(r) = &self.terminal {
                    r.failed.set(true);
                }
                return Err(GuardError::Conflict);
            }
            let mut flight = original.enter()?;
            self.attestor.verify_terminal_bracket(
                &original.pair,
                &original.stopped,
                &original.retired,
                bindings,
            )?;
            let actual = original.observe_absence(bindings)?;
            self.attestor.verify_terminal_bracket(
                &original.pair,
                &original.stopped,
                &original.retired,
                bindings,
            )?;
            flight.succeeded = true;
            Ok(actual)
        }
        /// Canonical G uses this under its already-open terminal Retired lease.
        /// Readonly independent all-key absence + SAME actual close ACKs. No
        /// native close, Pair/Retired reentry or phase/Option destructor grant.
        pub(crate) fn verify_terminal_closed_in_retired_bracket(
            &mut self,
            original: &std::rc::Rc<NativeGuardTerminalClose>,
            bindings: &Bindings,
        ) -> Result<Snapshot> {
            self.verify_terminal_inert(&original.engines)?;
            let actual = self.read_terminal_close_facts_in_retired_bracket(original, bindings)?;
            original.verify_observers_inert()?;
            self.verify_terminal_inert(&original.engines)?;
            Ok(actual)
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
        fn arbitration(&mut self, kind: SessionKind) -> Result<Vec<ArbitrationFilter>> {
            // The guard already holds THIS engine's write transaction. Do not
            // open a second engine/transaction or query conditions selectively.
            let engine = self.engine(kind).handle()?;
            let mut result = Vec::new();
            let mut weights = BTreeMap::new();
            for layer in [
                Layer::TransportV4,
                Layer::TransportV6,
                Layer::PacketV4,
                Layer::PacketV6,
                Layer::ForwardV4,
                Layer::ForwardV6,
                Layer::AleConnectV4,
                Layer::AleConnectV6,
            ] {
                let template = FWPM_FILTER_ENUM_TEMPLATE0 {
                    layerKey: layer_guid(layer),
                    enumType: FWP_FILTER_ENUM_FULLY_CONTAINED,
                    flags: FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME
                        | FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED,
                    actionMask: u32::MAX,
                    ..Default::default()
                };
                let mut enumeration = Enumeration::open(engine, &template)?;
                loop {
                    let mut raw = ptr::null_mut();
                    let mut count = 0;
                    let code = unsafe {
                        FwpmFilterEnum0(engine, enumeration.handle, 256, &mut raw, &mut count)
                    };
                    let memory = Memory(raw);
                    status(code)?;
                    if count > 256
                        || (count != 0 && memory.0.is_null())
                        || result.len() + count as usize > MAX_ARBITRATION_FILTERS
                    {
                        return Err(GuardError::Conflict);
                    }
                    let page = if count == 0 {
                        &[][..]
                    } else {
                        unsafe { std::slice::from_raw_parts(memory.0, count as usize) }
                    };
                    for raw in page {
                        let f = unsafe { raw.as_ref() }.ok_or(GuardError::Conflict)?;
                        if key(f.layerKey) != key(template.layerKey) {
                            return Err(GuardError::Conflict);
                        }
                        let subkey = key(f.subLayerKey);
                        let weight = match weights.get(&subkey) {
                            Some(weight) => *weight,
                            None => {
                                let mut raw = ptr::null_mut();
                                let code = unsafe {
                                    FwpmSubLayerGetByKey0(engine, &f.subLayerKey, &mut raw)
                                };
                                let memory = Memory(raw);
                                status(code)?;
                                let sub =
                                    unsafe { memory.0.as_ref() }.ok_or(GuardError::Conflict)?;
                                if key(sub.subLayerKey) != subkey {
                                    return Err(GuardError::Conflict);
                                }
                                weights.insert(subkey, sub.weight);
                                sub.weight
                            }
                        };
                        result.push(ArbitrationFilter {
                            key: key(f.filterKey),
                            id: f.filterId,
                            layer,
                            sublayer: subkey,
                            sublayer_weight: weight,
                            flags: f.flags,
                            action: f.action.r#type,
                        });
                    }
                    if count < 256 {
                        break;
                    }
                }
                enumeration.close()?;
            }
            Ok(result)
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
    // SAFETY: receipts and lifetime origins belong to these SAME Engine fields;
    // only successful actual FwpmEngineClose0 mints their ACK. No reopened owner,
    // empty handle/Option, SDK absence or imported record creates one.
    unsafe impl TerminalNativeApi for Wfp {
        fn enter_terminal_lane(&mut self) {
            self.base.lifetime.enter_terminal();
            self.permits.lifetime.enter_terminal();
        }
        fn engine_origin(&self, kind: SessionKind) -> std::rc::Rc<()> {
            self.engine(kind).lifetime.original_origin()
        }
        fn engine_close_ack(&self, kind: SessionKind) -> Result<std::rc::Rc<EngineCloseAck>> {
            self.engine(kind).lifetime.acknowledged()
        }
        fn close_terminal_engine(
            &mut self,
            kind: SessionKind,
        ) -> Result<std::rc::Rc<EngineCloseAck>> {
            self.engine(kind)
                .lifetime
                .close_terminal(|handle| status(unsafe { FwpmEngineClose0(handle as HANDLE) }))
        }
        fn verify_engine_inert(
            &self,
            kind: SessionKind,
            ack: &std::rc::Rc<EngineCloseAck>,
        ) -> Result<()> {
            let original = &self.engine(kind).lifetime;
            original.verify_ack(ack)?;
            original.verify_inert()
        }
    }
    impl Drop for Wfp {
        fn drop(&mut self) {
            if self.permits.lifetime.drop_requires_close() {
                let _ = self.permits.close();
            }
            if self.base.lifetime.drop_requires_close() {
                let _ = self.base.close();
            }
        }
    }
    fn read_bfe_sublayer(engine: HANDLE, scope: &SessionScope, k: Key) -> Result<Option<Sublayer>> {
        if crate::member_carrier_guard::resource_keys(scope)?.sublayer != k {
            return Err(GuardError::Invalid);
        }
        let mut raw = ptr::null_mut();
        let code = unsafe { FwpmSubLayerGetByKey0(engine, &guid(k), &mut raw) };
        let memory = Memory(raw);
        if code == FWP_E_SUBLAYER_NOT_FOUND as u32 {
            return Ok(None);
        }
        status(code)?;
        unsafe { decode_sublayer(memory.0.as_ref().ok_or(GuardError::Conflict)?, k) }.map(Some)
    }
    fn read_bfe_filter(
        engine: HANDLE,
        scope: &SessionScope,
        k: Key,
        sub: Key,
    ) -> Result<Option<NativeFilter>> {
        let keys = crate::member_carrier_guard::resource_keys(scope)?;
        if keys.sublayer != sub || !keys.filters.contains(&k) {
            return Err(GuardError::Invalid);
        }
        let mut raw = ptr::null_mut();
        let code = unsafe { FwpmFilterGetByKey0(engine, &guid(k), &mut raw) };
        let memory = Memory(raw);
        if code == FWP_E_FILTER_NOT_FOUND as u32 {
            return Ok(None);
        }
        status(code)?;
        unsafe { decode_filter(memory.0.as_ref().ok_or(GuardError::Conflict)?, k, sub) }.map(Some)
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
    struct Enumeration {
        engine: HANDLE,
        handle: HANDLE,
    }
    impl Enumeration {
        fn open(engine: HANDLE, template: &FWPM_FILTER_ENUM_TEMPLATE0) -> Result<Self> {
            let mut handle = ptr::null_mut();
            status(unsafe { FwpmFilterCreateEnumHandle0(engine, template, &mut handle) })?;
            if handle.is_null() {
                return Err(GuardError::Conflict);
            }
            Ok(Self { engine, handle })
        }
        fn close(&mut self) -> Result<()> {
            if !self.handle.is_null() {
                status(unsafe { FwpmFilterDestroyEnumHandle0(self.engine, self.handle) })?;
                self.handle = ptr::null_mut();
            }
            Ok(())
        }
    }
    impl Drop for Enumeration {
        fn drop(&mut self) {
            let _ = self.close();
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
#[cfg(windows)]
pub(crate) use bfe::{
    NativeGuardTerminalClose, NativeGuardTerminalFence, NativeGuardTerminalInput, Wfp,
};

#[cfg(windows)]
pub(crate) type NativeColdStaticCleanup<A> = bfe::NativeColdStaticCleanup<A>;
#[cfg(windows)]
pub(crate) fn issue_cold_static_cleanup<A: ColdStaticAuthorization>(
    scope: SessionScope,
    authority: std::rc::Rc<A>,
    retain: impl FnOnce(std::rc::Rc<NativeColdStaticCleanup<A>>) -> Result<()>,
) -> Result<std::rc::Rc<NativeColdStaticCleanup<A>>> {
    bfe::issue_cold_static_cleanup(scope, authority, retain)
}

#[cfg(test)]
#[path = "member_carrier_guard_tests.rs"]
mod tests;
