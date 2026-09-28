//! Two-engine WFP owner. Ordinary-session base blocks/sublayer survive
//! helper exit; dynamic-session soft probe permits do not. Drop closes permits
//! first. Each exchange has three SEPARATE transactions, never cross-engine CAS.
//!
//! The pair owner revalidates the exact snapshot and interface identities before
//! native use and fail-stops on guard loss. Periodic checks cannot promise
//! continuous protection across BFE restart; this is not a killswitch.
//! Probes require WSASocket + SO_EXCLUSIVEADDRUSE before bind and retain the
//! socket until its permit is withdrawn. A journal is not live protection.
//!
//! Conditions and soft-permit arbitration:
//! https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer
//! https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
//! Static lifetime: https://learn.microsoft.com/en-us/windows/win32/fwp/object-management

use crate::member_guard::{
    apply_split, resource_keys, stage_session_exchange, validate_exchange, Action, Condition,
    ExchangePlan, Filter, GuardError, GuardStore, GuardTransaction, Key, Layer, Model, Result,
    SessionKind, Snapshot, SplitEngines, Sublayer,
};
use nelomai_client_tunnel::redundancy::SessionScope;
use std::{
    ffi::c_void,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::{FWP_E_FILTER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, HANDLE},
        NetworkManagement::WindowsFilteringPlatform::*,
        System::Rpc::RPC_C_AUTHN_WINNT,
    },
};

const NAME: &str = "Nelomai standby guard v1";

pub(crate) struct NativeGuard {
    base: Engine,
    permits: Engine,
    failed: bool,
}

impl NativeGuard {
    /// No factory wired. Opening does NOT attest a BFE epoch or adopt old permits.
    /// Future factory MUST reject epoch loss, validate journal/native/interface
    /// proof and hold exclusive probe sockets before admitting any member routes.
    pub(crate) fn open(scope: SessionScope) -> Result<Self> {
        let base = Engine::open(scope.clone(), SessionKind::StaticBase)?;
        let permits = Engine::open(scope, SessionKind::DynamicPermits)?;
        Ok(Self {
            base,
            permits,
            failed: false,
        })
    }
}

struct Engine {
    handle: HANDLE,
    scope: SessionScope,
    kind: SessionKind,
}

impl Engine {
    /// Opening is explicit, never done by module initialization or tests.
    fn open(scope: SessionScope, kind: SessionKind) -> Result<Self> {
        resource_keys(&scope)?;
        let mut handle = ptr::null_mut();
        let session = FWPM_SESSION0 {
            flags: match kind {
                SessionKind::StaticBase => 0,
                SessionKind::DynamicPermits => FWPM_SESSION_FLAG_DYNAMIC,
            },
            txnWaitTimeoutInMSec: 5_000,
            ..Default::default()
        };
        // Local BFE, current authenticated service identity; no credential data.
        status(unsafe {
            FwpmEngineOpen0(
                ptr::null(),
                RPC_C_AUTHN_WINNT,
                ptr::null(),
                &session,
                &mut handle,
            )
        })?;
        Ok(Self {
            handle,
            scope,
            kind,
        })
    }

    fn close(&mut self) -> Result<()> {
        if !self.handle.is_null() {
            status(unsafe { FwpmEngineClose0(self.handle) })?;
            self.handle = ptr::null_mut();
        }
        Ok(())
    }

    fn allowed_key(&self, key: Key) -> Result<()> {
        let keys = resource_keys(&self.scope)?;
        let index = keys
            .filters
            .iter()
            .position(|k| *k == key)
            .ok_or(GuardError::Invalid)?;
        if (index % 6 >= 4) != (self.kind == SessionKind::DynamicPermits) {
            return Err(GuardError::Invalid);
        }
        Ok(())
    }

    fn transaction<T>(
        &mut self,
        flags: u32,
        operation: impl FnOnce(&Self) -> Result<T>,
    ) -> Result<T> {
        if self.handle.is_null() {
            return Err(GuardError::Conflict);
        }
        status(unsafe { FwpmTransactionBegin0(self.handle, flags) })?;
        // RAII also aborts on unwinding. A failed abort invalidates this handle.
        let mut transaction = Transaction {
            engine: self,
            finished: false,
        };
        let result = operation(transaction.engine)?;
        status(unsafe { FwpmTransactionCommit0(transaction.engine.handle) })?;
        transaction.finished = true;
        Ok(result)
    }

    /// Called only while the engine transaction lock is held. Lookup the complete
    /// fixed key universe, including keys expected absent; never enumerate BFE.
    fn read_locked(&self) -> Result<Snapshot> {
        let keys = resource_keys(&self.scope)?;
        let sublayer = self.read_sublayer(keys.sublayer)?;
        let mut filters = Vec::new();
        for key in keys.filters {
            if let Some(filter) = self.read_filter(key)? {
                filters.push(filter);
            }
        }
        filters.sort_by_key(|f| f.key);
        Ok(Snapshot {
            scope: self.scope.clone(),
            sublayer,
            filters,
        })
    }

    fn read_sublayer(&self, expected_key: Key) -> Result<Option<Sublayer>> {
        let mut raw = ptr::null_mut();
        let code = unsafe { FwpmSubLayerGetByKey0(self.handle, &guid(expected_key), &mut raw) };
        if code == FWP_E_SUBLAYER_NOT_FOUND as u32 {
            return Ok(None);
        }
        status(code)?;
        let memory = BfeMemory(raw);
        let raw = unsafe { memory.0.as_ref() }.ok_or(GuardError::Conflict)?;
        if key(raw.subLayerKey) != expected_key
            || !raw.providerKey.is_null()
            || raw.providerData.size != 0
            || !display_matches(&raw.displayData)
        {
            return Err(GuardError::Conflict);
        }
        Ok(Some(Sublayer {
            key: expected_key,
            weight: raw.weight,
            flags: raw.flags,
        }))
    }

    fn read_filter(&self, expected_key: Key) -> Result<Option<Filter>> {
        let mut raw = ptr::null_mut();
        let code = unsafe { FwpmFilterGetByKey0(self.handle, &guid(expected_key), &mut raw) };
        if code == FWP_E_FILTER_NOT_FOUND as u32 {
            return Ok(None);
        }
        status(code)?;
        let memory = BfeMemory(raw);
        let raw = unsafe { memory.0.as_ref() }.ok_or(GuardError::Conflict)?;
        if key(raw.filterKey) != expected_key
            || !raw.providerKey.is_null()
            || raw.providerData.size != 0
            || !raw.reserved.is_null()
            || !display_matches(&raw.displayData)
            || raw.flags != 0
            || unsafe { raw.Anonymous.rawContext } != 0
            || key(unsafe { raw.action.Anonymous.filterType }) != Key([0; 16])
            || raw.numFilterConditions > 7
            || raw.numFilterConditions == 0
            || raw.filterCondition.is_null()
        {
            return Err(GuardError::Conflict);
        }
        let weight = read_weight(&raw.weight)?;
        if read_weight(&raw.effectiveWeight)? != weight {
            return Err(GuardError::Conflict);
        }
        let layer = decode_layer(raw.layerKey)?;
        let action = match raw.action.r#type {
            FWP_ACTION_BLOCK => Action::Block,
            FWP_ACTION_PERMIT => Action::Permit,
            _ => return Err(GuardError::Conflict),
        };
        // Count is bounded above; BFE owns a valid array until BfeMemory drops.
        let conditions = unsafe {
            std::slice::from_raw_parts(raw.filterCondition, raw.numFilterConditions as usize)
        };
        let mut decoded = Vec::with_capacity(conditions.len());
        for (index, condition) in conditions.iter().enumerate() {
            if conditions[..index]
                .iter()
                .any(|c| key(c.fieldKey) == key(condition.fieldKey))
            {
                return Err(GuardError::Conflict); // repeated field would mean OR
            }
            decoded.push(decode_condition(condition, layer)?);
        }
        decoded.sort();
        Ok(Some(Filter {
            key: expected_key,
            sublayer: key(raw.subLayerKey),
            layer,
            weight,
            flags: raw.flags,
            action,
            conditions: decoded,
        }))
    }

    fn add_sublayer(&self, sublayer: &Sublayer) -> Result<()> {
        if self.kind != SessionKind::StaticBase {
            return Err(GuardError::Invalid);
        }
        let mut name = super::wide(NAME);
        let native = FWPM_SUBLAYER0 {
            subLayerKey: guid(sublayer.key),
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: ptr::null_mut(),
            },
            flags: sublayer.flags,
            weight: sublayer.weight,
            ..Default::default()
        };
        status(unsafe { FwpmSubLayerAdd0(self.handle, &native, ptr::null_mut()) })
    }

    fn add_filter(&self, filter: &Filter) -> Result<()> {
        self.allowed_key(filter.key)?;
        let action = if self.kind == SessionKind::StaticBase {
            Action::Block
        } else {
            Action::Permit
        };
        if filter.action != action || filter.flags != 0 {
            return Err(GuardError::Invalid);
        }
        let native = EncodedFilter::new(filter);
        status(unsafe {
            FwpmFilterAdd0(self.handle, &native.raw, ptr::null_mut(), ptr::null_mut())
        })
    }

    fn delete_filter(&self, key: Key) -> Result<()> {
        self.allowed_key(key)?;
        // Missing after exact readback is an error, never silently accepted.
        status(unsafe { FwpmFilterDeleteByKey0(self.handle, &guid(key)) })
    }
}

impl GuardStore for NativeGuard {
    fn snapshot(&mut self, scope: &SessionScope) -> Result<Snapshot> {
        if scope != &self.base.scope {
            return Err(GuardError::Conflict);
        }
        SplitEngines::snapshot(self)
    }

    fn compare_exchange(&mut self, expected: &Model, desired: &Model) -> Result<Model> {
        validate_exchange(&self.base.scope, expected, desired)?;
        if self.failed {
            return Err(GuardError::Conflict);
        }
        let plan = ExchangePlan::new(expected, desired)?;
        let result = apply_split(self, &plan);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

impl SplitEngines for NativeGuard {
    fn scope(&self) -> &SessionScope {
        &self.base.scope
    }
    fn snapshot(&mut self) -> Result<Snapshot> {
        self.base
            .transaction(FWPM_TXN_READ_ONLY, |engine| engine.read_locked())
    }
    fn exchange(&mut self, kind: SessionKind, expected: &Model, desired: &Model) -> Result<Model> {
        if self.failed {
            return Err(GuardError::Conflict);
        }
        let engine = match kind {
            SessionKind::StaticBase => &mut self.base,
            SessionKind::DynamicPermits => &mut self.permits,
        };
        validate_exchange(&engine.scope, expected, desired)?;
        let result = engine.transaction(0, |engine| {
            stage_session_exchange(&engine.scope, &mut Locked(engine), expected, desired, kind)
        });
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn close_permits(&mut self) -> Result<()> {
        self.failed = true;
        // Dynamic deletion by key is only legal within its owning session. A
        // foreign/static same-key permit makes withdraw fail; do NOT delete it
        // through the ordinary engine to work around WRONG_SESSION errors.
        self.permits.close()
    }
}

struct Locked<'a>(&'a Engine);
impl GuardTransaction for Locked<'_> {
    fn read(&mut self) -> Result<Snapshot> {
        self.0.read_locked()
    }
    fn add_sublayer(&mut self, sublayer: &Sublayer) -> Result<()> {
        self.0.add_sublayer(sublayer)
    }
    fn add_filter(&mut self, filter: &Filter) -> Result<()> {
        self.0.add_filter(filter)
    }
    fn delete_filter(&mut self, key: Key) -> Result<()> {
        self.0.delete_filter(key)
    }
    fn delete_sublayer(&mut self, key: Key) -> Result<()> {
        if self.0.kind != SessionKind::StaticBase {
            return Err(GuardError::Invalid);
        }
        status(unsafe { FwpmSubLayerDeleteByKey0(self.0.handle, &guid(key)) })
    }
}

impl Drop for NativeGuard {
    fn drop(&mut self) {
        // Explicit ordering; Engine::drop retries if close reported failure.
        // Drop cannot acknowledge removal. The owner must explicitly withdraw
        // and read back BEFORE releasing exclusively held probe sockets.
        let _ = self.permits.close();
        let _ = self.base.close();
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

struct Transaction<'a> {
    engine: &'a mut Engine,
    finished: bool,
}
impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.finished && unsafe { FwpmTransactionAbort0(self.engine.handle) } != 0 {
            // Cannot trust this session's transaction state. Closing aborts any
            // outstanding transaction. Base survives, own dynamic permits do not.
            // Retain handle on failed close so emergency shutdown can retry.
            let _ = self.engine.close();
        }
    }
}

struct BfeMemory<T>(*mut T);
impl<T> Drop for BfeMemory<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let mut pointer = self.0.cast::<c_void>();
            unsafe {
                FwpmFreeMemory0(&mut pointer);
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
fn guid(value: Key) -> GUID {
    GUID::from_u128(u128::from_be_bytes(value.0))
}
fn key(value: GUID) -> Key {
    let mut bytes = [0; 16];
    bytes[..4].copy_from_slice(&value.data1.to_be_bytes());
    bytes[4..6].copy_from_slice(&value.data2.to_be_bytes());
    bytes[6..8].copy_from_slice(&value.data3.to_be_bytes());
    bytes[8..].copy_from_slice(&value.data4);
    Key(bytes)
}
fn layer_guid(layer: Layer) -> GUID {
    match layer {
        Layer::TransportV4 => FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
        Layer::TransportV6 => FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
        Layer::ForwardV4 => FWPM_LAYER_IPFORWARD_V4,
        Layer::ForwardV6 => FWPM_LAYER_IPFORWARD_V6,
    }
}
fn decode_layer(value: GUID) -> Result<Layer> {
    [
        Layer::TransportV4,
        Layer::TransportV6,
        Layer::ForwardV4,
        Layer::ForwardV6,
    ]
    .into_iter()
    .find(|layer| key(layer_guid(*layer)) == key(value))
    .ok_or(GuardError::Conflict)
}

fn display_matches(display: &FWPM_DISPLAY_DATA0) -> bool {
    if display.name.is_null() {
        return false;
    }
    // BFE's strings are NUL terminated. Stop immediately on a shorter string.
    for (i, expected) in NAME.encode_utf16().chain(Some(0)).enumerate() {
        if unsafe { *display.name.add(i) } != expected {
            return false;
        }
    }
    display.description.is_null() || unsafe { *display.description == 0 }
}

fn read_weight(value: &FWP_VALUE0) -> Result<u64> {
    if value.r#type != FWP_UINT64 {
        return Err(GuardError::Conflict);
    }
    unsafe { value.Anonymous.uint64.as_ref().copied() }.ok_or(GuardError::Conflict)
}

fn decode_condition(raw: &FWPM_FILTER_CONDITION0, layer: Layer) -> Result<Condition> {
    if raw.matchType != FWP_MATCH_EQUAL {
        return Err(GuardError::Conflict);
    }
    let field = key(raw.fieldKey);
    let value = &raw.conditionValue;
    // Read only the union member selected by the validated FWP_DATA_TYPE.
    unsafe {
        match (field, value.r#type) {
            (f, FWP_UINT32) if f == key(FWPM_CONDITION_INTERFACE_INDEX) => {
                Ok(Condition::InterfaceIndex(value.Anonymous.uint32))
            }
            (f, FWP_UINT64) if f == key(FWPM_CONDITION_IP_LOCAL_INTERFACE) => {
                Ok(Condition::LocalInterface(
                    value
                        .Anonymous
                        .uint64
                        .as_ref()
                        .copied()
                        .ok_or(GuardError::Conflict)?,
                ))
            }
            (f, FWP_UINT32) if f == key(FWPM_CONDITION_DESTINATION_INTERFACE_INDEX) => {
                Ok(Condition::DestinationInterfaceIndex(value.Anonymous.uint32))
            }
            (f, FWP_UINT16) if f == key(FWPM_CONDITION_IP_LOCAL_PORT) => {
                Ok(Condition::LocalPort(value.Anonymous.uint16))
            }
            (f, FWP_UINT16) if f == key(FWPM_CONDITION_IP_REMOTE_PORT) => {
                Ok(Condition::RemotePort(value.Anonymous.uint16))
            }
            (f, FWP_UINT8) if f == key(FWPM_CONDITION_IP_PROTOCOL) => {
                Ok(Condition::Protocol(value.Anonymous.uint8))
            }
            (f, kind)
                if f == key(FWPM_CONDITION_IP_LOCAL_ADDRESS)
                    || f == key(FWPM_CONDITION_IP_REMOTE_ADDRESS) =>
            {
                let ip = match (layer, kind) {
                    (Layer::TransportV4, FWP_UINT32) => {
                        IpAddr::V4(Ipv4Addr::from(value.Anonymous.uint32))
                    }
                    (Layer::TransportV6, FWP_BYTE_ARRAY16_TYPE) => IpAddr::V6(Ipv6Addr::from(
                        value
                            .Anonymous
                            .byteArray16
                            .as_ref()
                            .ok_or(GuardError::Conflict)?
                            .byteArray16,
                    )),
                    _ => return Err(GuardError::Conflict),
                };
                Ok(if f == key(FWPM_CONDITION_IP_LOCAL_ADDRESS) {
                    Condition::LocalAddress(ip)
                } else {
                    Condition::RemoteAddress(ip)
                })
            }
            _ => Err(GuardError::Conflict),
        }
    }
}

/// Own all pointees through the synchronous FwpmFilterAdd0 call. Box allocations
/// keep union pointers valid as the backing vectors/EncodedFilter itself move.
struct EncodedFilter {
    raw: FWPM_FILTER0,
    _conditions: Vec<FWPM_FILTER_CONDITION0>,
    _name: Vec<u16>,
    _weight: Box<u64>,
    _backing: ConditionBacking,
}
#[derive(Default)]
#[allow(clippy::vec_box)] // FFI union pointees must not move when either vector reallocates.
struct ConditionBacking {
    words: Vec<Box<u64>>,
    addresses: Vec<Box<FWP_BYTE_ARRAY16>>,
}
impl EncodedFilter {
    fn new(filter: &Filter) -> Self {
        let mut backing = ConditionBacking::default();
        let mut conditions: Vec<_> = filter
            .conditions
            .iter()
            .map(|c| encode_condition(c, &mut backing))
            .collect();
        let mut weight = Box::new(filter.weight);
        let mut name = super::wide(NAME);
        let mut raw = FWPM_FILTER0 {
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
            ..Default::default()
        };
        raw.action.r#type = match filter.action {
            Action::Block => FWP_ACTION_BLOCK,
            Action::Permit => FWP_ACTION_PERMIT,
        };
        // flags == 0: soft permit, NEVER CLEAR_ACTION_RIGHT or PERSISTENT.
        Self {
            raw,
            _conditions: conditions,
            _name: name,
            _weight: weight,
            _backing: backing,
        }
    }
}

fn encode_condition(
    condition: &Condition,
    backing: &mut ConditionBacking,
) -> FWPM_FILTER_CONDITION0 {
    use Condition::*;
    let (field, kind, value) = match condition {
        InterfaceIndex(n) => (
            FWPM_CONDITION_INTERFACE_INDEX,
            FWP_UINT32,
            FWP_CONDITION_VALUE0_0 { uint32: *n },
        ),
        DestinationInterfaceIndex(n) => (
            FWPM_CONDITION_DESTINATION_INTERFACE_INDEX,
            FWP_UINT32,
            FWP_CONDITION_VALUE0_0 { uint32: *n },
        ),
        LocalInterface(n) => {
            let mut owned = Box::new(*n);
            let value = FWP_CONDITION_VALUE0_0 {
                uint64: &mut *owned,
            };
            backing.words.push(owned);
            (FWPM_CONDITION_IP_LOCAL_INTERFACE, FWP_UINT64, value)
        }
        LocalPort(n) => (
            FWPM_CONDITION_IP_LOCAL_PORT,
            FWP_UINT16,
            FWP_CONDITION_VALUE0_0 { uint16: *n },
        ),
        RemotePort(n) => (
            FWPM_CONDITION_IP_REMOTE_PORT,
            FWP_UINT16,
            FWP_CONDITION_VALUE0_0 { uint16: *n },
        ),
        Protocol(n) => (
            FWPM_CONDITION_IP_PROTOCOL,
            FWP_UINT8,
            FWP_CONDITION_VALUE0_0 { uint8: *n },
        ),
        LocalAddress(ip) | RemoteAddress(ip) => {
            let field = if matches!(condition, LocalAddress(_)) {
                FWPM_CONDITION_IP_LOCAL_ADDRESS
            } else {
                FWPM_CONDITION_IP_REMOTE_ADDRESS
            };
            match ip {
                // WFP IPv4 and port scalars use host-order numeric values.
                IpAddr::V4(ip) => (
                    field,
                    FWP_UINT32,
                    FWP_CONDITION_VALUE0_0 {
                        uint32: u32::from_be_bytes(ip.octets()),
                    },
                ),
                IpAddr::V6(ip) => {
                    let mut owned = Box::new(FWP_BYTE_ARRAY16 {
                        byteArray16: ip.octets(),
                    });
                    let value = FWP_CONDITION_VALUE0_0 {
                        byteArray16: &mut *owned,
                    };
                    backing.addresses.push(owned);
                    (field, FWP_BYTE_ARRAY16_TYPE, value)
                }
            }
        }
    };
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: kind,
            Anonymous: value,
        },
    }
}
