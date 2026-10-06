//! Cleanup-only protected carrier recovery. Bytes are obligations, never SDK ACKs.

#[cfg(windows)]
use super::member_carrier_creator::CreatorRecord;
#[cfg(windows)]
use super::member_files::previous_config_valid;
#[cfg(windows)]
use super::member_files::SessionFileIo;
#[cfg(windows)]
use super::member_session::{
    ColdRetirementAck, OriginalColdNativeEmptyProof, OriginalSessionFilesIdentity,
};
#[cfg(windows)]
use super::member_session::{ProtectedRecoveryRecords, ProtectedSessionFiles, RecordKind};
#[cfg(windows)]
use super::{
    member_carrier_pair_store as pair_store,
    member_session::{CarrierGuardRecord, NativeNetworkRecord},
};
#[cfg(not(windows))]
use crate::member_carrier_creator::CreatorRecord;
use crate::member_carrier_native_ownership::{self as keys, Context};
#[cfg(not(windows))]
use crate::member_files::previous_config_valid;
#[cfg(not(windows))]
use crate::member_files::SessionFileIo;
#[cfg(not(windows))]
use crate::member_session::{
    ColdRetirementAck, OriginalColdNativeEmptyProof, OriginalSessionFilesIdentity,
};
#[cfg(not(windows))]
use crate::member_session::{ProtectedRecoveryRecords, ProtectedSessionFiles, RecordKind};
use crate::{member_carrier_pair as pair, member_carrier_rows as rows};
#[cfg(not(windows))]
use crate::{
    member_carrier_pair_store as pair_store,
    member_session::{CarrierGuardRecord, NativeNetworkRecord},
};
use nelomai_contracts::RuntimeSlot;
use std::{
    cell::{Cell, RefCell},
    io,
    rc::Rc,
};

fn conflict() -> io::Error {
    io::Error::other("carrier_recovery_original_or_pending")
}

fn require_non_wfp_recovery(facts: &RecoveryFacts) -> io::Result<()> {
    if facts.layout != RecoveryLayout::NativeCarrier
        || facts.context.is_none()
        || (facts.guard.is_none() && facts.pair.is_none())
        || (!facts.changed_boot && facts.creator.is_none())
    {
        return Err(io::Error::other(
            "carrier_cold_original_creator_death_required",
        ));
    }
    Ok(())
}
fn cold_state_paths(
    state: &std::path::Path,
    backend: &std::path::Path,
    configs: [&std::path::Path; 2],
) -> io::Result<()> {
    if !state.is_absolute()
        || state.as_os_str() != backend.as_os_str()
        || state.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
        || configs[0].as_os_str() != state.join("nelomai-a.conf").as_os_str()
        || configs[1].as_os_str() != state.join("nelomai-b.conf").as_os_str()
    {
        return Err(io::Error::other("carrier_cold_state_backend_mismatch"));
    }
    Ok(())
}

fn cold_namespace(
    context: &Context,
    paths: [&std::path::Path; 2],
) -> io::Result<[keys::Binding; 5]> {
    use crate::member_native_guid as guid;
    use nelomai_client_tunnel::TunnelTransport;
    use nelomai_contracts::dispatcher::TunnelSlot;
    keys::validate_context(context).map_err(|_| conflict())?;
    let carrier =
        crate::member_carrier::carrier_key(&context.intent.scope).map_err(|_| conflict())?;
    let text: String = carrier
        .guid
        .iter()
        .enumerate()
        .map(|(i, b)| {
            format!(
                "{}{b:02x}",
                if matches!(i, 4 | 6 | 8 | 10) { "-" } else { "" }
            )
        })
        .collect();
    let c = keys::Binding {
        role: keys::Role::RoleCarrier,
        guid: carrier.guid,
        name: carrier.name,
        registry_path: format!(
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{{text}}}"
        ),
    };
    let member = |slot, path, transport| {
        let (provider, revision) = match transport {
            TunnelTransport::WireGuard => (
                guid::ProviderPath::WireGuardSignedDll,
                guid::WG_SOURCE_REVISION,
            ),
            TunnelTransport::AmneziaWg3 => (
                guid::ProviderPath::AmneziaSignedDll,
                guid::AWG_SOURCE_REVISION,
            ),
        };
        guid::member_binding(
            provider,
            revision,
            slot,
            path,
            crate::redundancy::slot_service_name(slot, transport),
        )
        .map_err(|_| conflict())
    };
    let all = [
        c,
        member(TunnelSlot::A, paths[0], TunnelTransport::WireGuard)?,
        member(TunnelSlot::A, paths[0], TunnelTransport::AmneziaWg3)?,
        member(TunnelSlot::B, paths[1], TunnelTransport::WireGuard)?,
        member(TunnelSlot::B, paths[1], TunnelTransport::AmneziaWg3)?,
    ];
    if context.bindings[0] != all[0]
        || !all[1..3].contains(&context.bindings[1])
        || !all[3..5].contains(&context.bindings[2])
    {
        return Err(io::Error::other("carrier_cold_noncanonical_namespace"));
    }
    Ok(all)
}
fn cold_network_rows(
    facts: &RecoveryFacts,
    table: &crate::member_physical::PhysicalSnapshot,
) -> io::Result<()> {
    use crate::member_physical::{Family, InterfaceIdentity, PhysicalProof, PhysicalRoute};
    use nelomai_client_tunnel::redundancy::network::{NetworkValue, RouteValue};
    let context = facts.context.as_ref().ok_or_else(conflict)?;
    let absent_route = |expected: &RouteValue| {
        // Key absence rejects ANY metric/flags; exact data is not ownership.
        if table.rows().iter().any(|row| {
            row.route.destination == expected.destination
                && row.route.interface == expected.interface
                && row.route.gateway == expected.gateway
        }) {
            Err(io::Error::other("carrier_cold_route_still_present"))
        } else {
            Ok(())
        }
    };
    if let Some(network) = facts.network_obligation()? {
        if !network.journal.windows_boot_resources_are_ephemeral() {
            // This predicate rejects originals/global DNS/non-Windows entries.
            // No old original IO ACK exists here; never guess restoration.
            return Err(io::Error::other(
                "carrier_cold_network_original_or_persistent_obligation",
            ));
        }
        let view = network.journal.read_view()?;
        for value in view.current().chain(view.pending().into_iter().flatten()) {
            match value {
                NetworkValue::Route(route) => absent_route(route)?,
                _ => return Err(io::Error::other("carrier_cold_nonroute_obligation")),
            }
        }
        for lease in &network.physical {
            if context.bindings.iter().any(|b| b.guid == lease.guid) {
                return Err(conflict());
            }
            let expected = PhysicalRoute {
                proof: PhysicalProof {
                    identity: InterfaceIdentity {
                        index: lease.interface,
                        luid: lease.luid,
                        guid: lease.guid,
                    },
                    family: if lease.ipv6 { Family::V6 } else { Family::V4 },
                    metric: lease.interface_metric,
                },
                row: crate::member_routes::Row {
                    route: lease.route.clone(),
                    luid: lease.luid,
                    protocol: lease.protocol,
                    origin: lease.origin,
                    site_prefix_length: lease.site_prefix_length,
                    valid_lifetime: lease.valid_lifetime,
                    preferred_lifetime: lease.preferred_lifetime,
                    flags: lease.flags,
                },
            };
            table
                .verify(&expected)
                .map_err(|_| io::Error::other("carrier_cold_physical_baseline_changed"))?;
        }
    }
    if let Some(network) = facts.pair.as_ref().and_then(|p| p.network.as_ref()) {
        if !network.baseline.routes.is_empty() {
            return Err(io::Error::other(
                "carrier_cold_pair_route_baseline_requires_original",
            ));
        }
        for snapshot in [&network.baseline, &network.current]
            .into_iter()
            .chain(network.pending.as_ref())
        {
            for route in &snapshot.routes {
                absent_route(route)?;
            }
            if let Some(dns) = &snapshot.dns {
                if dns.interface.scope != context.intent.scope
                    || dns.interface.guid != context.bindings[0].guid
                {
                    return Err(io::Error::other("carrier_cold_dns_not_carrier_scoped"));
                }
                // C and its key are independently absent; never query old DNS
                // index/LUID or turn these retained settings into a native ACK.
                dns.with_servers(&[]).map_err(|_| conflict())?;
            }
        }
    }
    Ok(())
}
type ColdIpRow = (u16, u32, u64);
type ColdAddressRow = (u32, u64, std::net::IpAddr);
fn cold_mib_empty(
    context: &Context,
    targets: &[keys::Binding; 5],
    interfaces: &[crate::member_physical::InterfaceIdentity],
    ip: &[ColdIpRow],
    addresses: &[ColdAddressRow],
) -> io::Result<()> {
    use std::collections::{BTreeMap, BTreeSet};
    let limit = crate::member_routes::MAX_TABLE_ROWS;
    if interfaces.len() > limit || ip.len() > limit || addresses.len() > limit {
        return Err(conflict());
    }
    let (mut by_index, mut guids, mut luids) = (BTreeMap::new(), BTreeSet::new(), BTreeSet::new());
    for id in interfaces {
        if id.index == 0
            || id.luid == 0
            || id.guid == [0; 16]
            || targets.iter().any(|b| b.guid == id.guid)
            || by_index.insert(id.index, id.luid).is_some()
            || !guids.insert(id.guid)
            || !luids.insert(id.luid)
        {
            return Err(io::Error::other(
                "carrier_cold_interface_present_or_unknown",
            ));
        }
    }
    let mut families = BTreeSet::new();
    for &(family, index, luid) in ip {
        if !matches!(family, 2 | 23)
            || by_index.get(&index) != Some(&luid)
            || !families.insert((family, index))
        {
            return Err(io::Error::other("carrier_cold_partial_ip_interface_table"));
        }
    }
    let mut seen = BTreeSet::new();
    for &(index, luid, address) in addresses {
        let family = if address.is_ipv4() { 2 } else { 23 };
        if by_index.get(&index) != Some(&luid)
            || !families.contains(&(family, index))
            || !seen.insert((index, address))
            || context.intent.addresses.iter().any(|a| a.addr() == address)
        {
            return Err(io::Error::other("carrier_cold_address_present_or_partial"));
        }
    }
    Ok(())
}
fn cold_member_record(
    bytes: &[u8],
    slot: nelomai_contracts::dispatcher::TunnelSlot,
    context: &Context,
    engine: &std::path::Path,
    canonical_targets: &[keys::Binding; 5],
) -> io::Result<crate::member_owner::Record> {
    use crate::member_owner::{Phase, Record};
    if bytes.len() > 65536 {
        return Err(conflict());
    }
    let record: Record = serde_json::from_slice(bytes).map_err(|_| conflict())?;
    crate::member_owner::validate_record_shape(&record).map_err(|_| conflict())?;
    let i = match slot {
        nelomai_contracts::dispatcher::TunnelSlot::A => 1,
        nelomai_contracts::dispatcher::TunnelSlot::B => 2,
    };
    let slot_targets = match slot {
        nelomai_contracts::dispatcher::TunnelSlot::A => &canonical_targets[1..3],
        nelomai_contracts::dispatcher::TunnelSlot::B => &canonical_targets[3..5],
    };
    // Supplied by the actual canonical state-path namespace builder, which
    // enumerates BOTH transports under the same signed/full native bracket.
    // This retains a Stopped predecessor's old proof as an absence obligation;
    // no numeric lookup, native receipt, Stop permission or Running adoption.
    if canonical_targets[0] != context.bindings[0] || !slot_targets.contains(&context.bindings[i]) {
        return Err(conflict());
    }
    if record.intent.slot != slot
        // A global terminal predecessor survives runtime/scope replacement.
        // Shared validate_prior_stopped admits ONLY this factual data path;
        // the fresh owner still needs its own full native absence before CAS.
        || (record.phase != Phase::Stopped
            && (record.intent.scope != context.intent.scope || record.intent.engine != engine))
        || !record.intent.scope.validate()
        || (record.phase == Phase::Running && record.proof.is_none())
        || (matches!(record.phase, Phase::Prepared | Phase::Stopped) && record.proof.is_some())
        || !previous_config_valid(&record)
        || record.proof.iter().chain(&record.retired_proof).any(|p| {
            p.process.pid == 0
                || p.process.creation_time == 0
                || p.interface.index == 0
                || p.interface.luid == 0
                || if record.phase == Phase::Stopped {
                    !slot_targets.iter().any(|b| b.guid == p.interface.guid)
                } else {
                    p.interface.guid != context.bindings[i].guid
                }
        })
        || record
            .proof
            .zip(record.retired_proof)
            .is_some_and(|(p, r)| p.process == r.process)
    {
        return Err(conflict());
    }
    Ok(record)
}

/// Caller-retained storage destination, allocated BEFORE private IO. No public
/// constructor from records/JSON; initialization is exactly one attempted read.
pub(crate) struct ProtectedRecoveryRoot<I> {
    files: RefCell<ProtectedSessionFiles<I>>,
    facts: RefCell<Option<Rc<RecoveryFacts>>>,
    attempted: Cell<bool>,
    busy: Cell<bool>,
    revoked: Cell<bool>,
    runtime: Cell<Option<RuntimeSlot>>,
    cold: RefCell<Option<Rc<ColdEmptyAttempt>>>,
}
/// # Safety
/// Concrete native issuer must perform bounded independent FULL mixed C/A/B
/// SCM/NIC/MIB/PnP, both transports' canonical names/GUIDs, all owned addresses/
/// routes/DNS/physical obligations, registry keys and complete BFE key universe
/// before AND after exactly one callback. Partial/error/foreign/present/unknown
/// denies. No DLL load, adoption, old-index query or native/global mutation.
/// Saved Context is query DATA only. Native entry independently brackets signed
/// installed identity/current executable/boot/SAME held owner/private ancestry.
pub(crate) unsafe trait NativeColdEmptyInventory {
    fn inspect_empty(
        &self,
        facts: &RecoveryFacts,
        callback: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()>;
}
struct ColdEmptyAttempt {
    scanner: Rc<dyn NativeColdEmptyInventory>,
    selected: Rc<RecoveryFacts>,
    origin: OriginalSessionFilesIdentity,
    proven: Cell<bool>,
    writing: Cell<bool>,
    attempted: Cell<bool>,
    failed: Cell<bool>,
    ack: RefCell<Option<Rc<ColdRetirementAck>>>,
}
struct ColdAttemptFlight<'a>(&'a ColdEmptyAttempt, bool);
impl Drop for ColdAttemptFlight<'_> {
    fn drop(&mut self) {
        if !self.1 {
            self.0.failed.set(true);
            self.0.writing.set(false);
        }
    }
}
unsafe impl OriginalColdNativeEmptyProof for ColdEmptyAttempt {
    fn begin_retirement(
        &self,
        origin: &OriginalSessionFilesIdentity,
        expected: &ProtectedRecoveryRecords,
    ) -> io::Result<()> {
        if self.attempted.replace(true) {
            self.failed.set(true);
            return Err(conflict());
        }
        self.verify_retirement(origin, expected)
    }
    fn verify_retirement(
        &self,
        origin: &OriginalSessionFilesIdentity,
        expected: &ProtectedRecoveryRecords,
    ) -> io::Result<()> {
        if self.failed.get()
            || !self.proven.get()
            || !self.writing.get()
            || !self.origin.same_original(origin)
            || self.selected.authenticated != *expected
        {
            return Err(conflict());
        }
        Ok(())
    }
    fn fail_retirement(&self) {
        self.failed.set(true);
    }
}
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RecoveryFacts {
    pub layout: RecoveryLayout,
    pub context: Option<Context>,
    pub changed_boot: bool,
    pub keys: Option<keys::Record>,
    pub carrier: Option<crate::member_carrier::Record>,
    pub requirements: Vec<RecoveryRequirement>,
    pub pair: Option<pair::Record>,
    pub guard: Option<CarrierGuardRecord>,
    pub creator: Option<CreatorRecord>,
    pub rows: [Option<rows::Record>; 3],
    authenticated: ProtectedRecoveryRecords,
    records: Vec<(RecordKind, Option<Vec<u8>>)>,
}
/// Schema dispatch facts only. Native sidecars can NEVER select legacy, even
/// with Pair missing or a legacy-looking Pair publication beside them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryLayout {
    NativeCarrier,
    LegacyOnly,
    UnpublishedClaim,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryRequirement {
    MissingSession,
    MissingPair,
    ChangedBootNativeEmpty,
    UnknownKeyCreate(keys::Role),
    OriginalKey(keys::Role),
    OriginalCarrier,
    OriginalMember(nelomai_client_tunnel::redundancy::Slot),
    OriginalRows(rows::Role),
    UnknownAddressCreate,
    OriginalNetwork,
    OriginalGuard,
    MissingNativeContext,
    FullNativeEmpty,
}
struct ReadFlight<'a, I>(&'a ProtectedRecoveryRoot<I>, bool);
impl<I> Drop for ReadFlight<'_, I> {
    fn drop(&mut self) {
        if !self.1 {
            self.0.revoked.set(true);
        }
        self.0.busy.set(false);
    }
}
impl<I: SessionFileIo> ProtectedRecoveryRoot<I> {
    pub(crate) fn new(files: ProtectedSessionFiles<I>) -> Self {
        Self {
            files: RefCell::new(files),
            facts: RefCell::new(None),
            attempted: Cell::new(false),
            busy: Cell::new(false),
            revoked: Cell::new(false),
            runtime: Cell::new(None),
            cold: RefCell::new(None),
        }
    }
    fn begin(&self) -> io::Result<ReadFlight<'_, I>> {
        if self.revoked.get() || self.busy.replace(true) {
            self.revoked.set(true);
            return Err(conflict());
        }
        Ok(ReadFlight(self, false))
    }
    pub(crate) fn initialize(&self, runtime: RuntimeSlot) -> io::Result<bool> {
        if self.attempted.replace(true) {
            self.revoked.set(true);
            return Err(conflict());
        }
        let mut flight = self.begin()?;
        self.runtime.set(Some(runtime));
        let found = self
            .files
            .try_borrow_mut()
            .map_err(|_| conflict())?
            .inspect_recovery_records(runtime, |raw| {
                let facts = RecoveryFacts::decode(raw)?;
                // Retain the actual sampled obligations BEFORE private postflight.
                *self.facts.try_borrow_mut().map_err(|_| conflict())? = Some(Rc::new(facts));
                Ok(())
            })?
            .is_some();
        if self.revoked.get() {
            return Err(conflict());
        }
        flight.1 = true;
        Ok(found)
    }
    fn check(&self, expected: &RecoveryFacts) -> io::Result<()> {
        let runtime = self.runtime.get().ok_or_else(conflict)?;
        self.files
            .try_borrow_mut()
            .map_err(|_| conflict())?
            .inspect_recovery_records(runtime, |raw| {
                if RecoveryFacts::decode(raw)? != *expected {
                    return Err(conflict());
                }
                Ok(())
            })?
            .ok_or_else(conflict)
    }
    /// Caller callback is OUTSIDE the backend transaction, so native Runtime
    /// brackets may run without recursive private storage. Exact original bytes
    /// are rechecked on both sides. Failure/unwind/reentry permanently retires
    /// this read selection; historical obligations remain rooted.
    pub(crate) fn inspect<T>(
        &self,
        inspect: impl FnOnce(&RecoveryFacts) -> io::Result<T>,
    ) -> io::Result<T> {
        let mut flight = self.begin()?;
        let facts = self.retained_facts()?;
        self.check(&facts)?;
        let value = inspect(&facts)?;
        self.check(&facts)?;
        if self.revoked.get() {
            return Err(conflict());
        }
        flight.1 = true;
        Ok(value)
    }
    pub(crate) fn retained_facts(&self) -> io::Result<Rc<RecoveryFacts>> {
        self.facts
            .try_borrow()
            .map_err(|_| conflict())?
            .clone()
            .ok_or_else(conflict)
    }
    pub(crate) fn retire_cold_empty(
        &self,
        scanner: Rc<dyn NativeColdEmptyInventory>,
    ) -> io::Result<Rc<ColdRetirementAck>> {
        let mut flight = self.begin()?;
        if self.cold.try_borrow().map_err(|_| conflict())?.is_some() {
            return Err(conflict());
        }
        let selected = self.retained_facts()?;
        if selected.layout != RecoveryLayout::NativeCarrier || selected.context.is_none() {
            return Err(conflict());
        }
        let attempt = Rc::new(ColdEmptyAttempt {
            scanner,
            selected: selected.clone(),
            origin: self
                .files
                .try_borrow()
                .map_err(|_| conflict())?
                .read_identity(),
            proven: Cell::new(false),
            writing: Cell::new(false),
            attempted: Cell::new(false),
            failed: Cell::new(false),
            ack: RefCell::new(None),
        });
        *self.cold.try_borrow_mut().map_err(|_| conflict())? = Some(attempt.clone());
        let mut cold_flight = ColdAttemptFlight(&attempt, false);
        self.check(&selected)?;
        let mut entered = false;
        attempt.scanner.inspect_empty(&selected, &mut || {
            if entered || self.revoked.get() {
                self.revoked.set(true);
                attempt.failed.set(true);
                return Err(conflict());
            }
            entered = true;
            let result = self.check(&selected);
            if result.is_err() {
                self.revoked.set(true);
                attempt.failed.set(true);
            }
            result
        })?;
        if !entered || self.revoked.get() {
            return Err(conflict());
        }
        attempt.proven.set(true); // only successful complete native pre/post bracket
        self.check(&selected)?;
        entered = false;
        attempt.scanner.inspect_empty(&selected, &mut || {
            if entered || self.revoked.get() {
                self.revoked.set(true);
                attempt.failed.set(true);
                return Err(conflict());
            }
            entered = true;
            attempt.writing.set(true);
            let result = self
                .files
                .try_borrow_mut()
                .map_err(|_| conflict())?
                .retire_native_empty(&selected.authenticated, attempt.as_ref(), |ack| {
                    *attempt.ack.try_borrow_mut().map_err(|_| conflict())? = Some(ack);
                    Ok(())
                });
            attempt.writing.set(false);
            result?;
            Ok(())
        })?;
        if !entered || self.revoked.get() || attempt.failed.get() {
            return Err(conflict());
        }
        let ack = attempt
            .ack
            .try_borrow()
            .map_err(|_| conflict())?
            .clone()
            .ok_or_else(conflict)?;
        if !ack.matches_origin(&attempt.origin) {
            return Err(conflict());
        }
        self.revoked.set(true); // old inventory never becomes a forward selection
        cold_flight.1 = true;
        flight.1 = true;
        Ok(ack)
    }
    pub(crate) fn retained_cold_retirement_ack(&self) -> io::Result<Option<Rc<ColdRetirementAck>>> {
        let attempt = self.cold.try_borrow().map_err(|_| conflict())?.clone();
        match attempt {
            Some(a) => Ok(a.ack.try_borrow().map_err(|_| conflict())?.clone()),
            None => Ok(None),
        }
    }
}
impl RecoveryFacts {
    /// Authenticated payload bytes only; NEVER a native handle/ACK.
    #[cfg(test)]
    fn payload(&self, kind: RecordKind) -> Option<&[u8]> {
        self.records
            .iter()
            .find(|(k, _)| *k == kind)
            .and_then(|(_, b)| b.as_deref())
    }
    pub(crate) fn network_obligation(&self) -> io::Result<Option<NativeNetworkRecord>> {
        self.authenticated.network_obligation()
    }
    fn decode(raw: &ProtectedRecoveryRecords) -> io::Result<Self> {
        let payload = |kind| {
            raw.records
                .iter()
                .find(|(k, _)| *k == kind)
                .and_then(|(_, b)| b.as_deref())
        };
        let keys = payload(RecordKind::NativeCarrierReceipts)
            .map(keys::Record::decode)
            .transpose()
            .map_err(|_| conflict())?;
        let guard = payload(RecordKind::CarrierGuard)
            .map(CarrierGuardRecord::decode)
            .transpose()?;
        let creator = raw.creator_obligation()?;
        let context = keys
            .as_ref()
            .map(|k| k.context.clone())
            .or_else(|| guard.as_ref().map(|g| g.context.clone()))
            .or_else(|| creator.as_ref().map(|g| g.context().clone()));
        if let Some(c) = &context {
            keys::validate_context(c).map_err(|_| conflict())?;
            if c.intent.scope != raw.scope
                || c.provenance.boot_id != raw.provenance.boot_id
                || c.provenance.runtime != raw.provenance.runtime
                || c.provenance.network_epoch > raw.provenance.network_epoch
                || guard.as_ref().is_some_and(|g| g.context != *c)
                || creator.as_ref().is_some_and(|g| g.context() != c)
            {
                return Err(conflict());
            }
        }
        let carrier = raw.carrier_obligation()?;
        if let (Some(c), Some(record)) = (&context, &carrier) {
            if record.intent != c.intent
                || record.provenance != c.provenance
                || record
                    .proof
                    .is_some_and(|proof| proof.guid != c.bindings[0].guid)
            {
                return Err(conflict());
            }
        }
        let has_native_sidecar = [
            RecordKind::Carrier,
            RecordKind::NativeCarrierReceipts,
            RecordKind::CarrierGuard,
            RecordKind::NativeCreator,
            RecordKind::CarrierRows,
            RecordKind::MemberARows,
            RecordKind::MemberBRows,
        ]
        .into_iter()
        .any(|k| payload(k).is_some());
        let (pair, layout) = match payload(RecordKind::Pair)
            .map(|b| pair_store::decode_pair_payload(&raw.scope, b))
            .transpose()?
        {
            Some(pair::CleanupRecord::Carrier(record)) => {
                (Some(*record), RecoveryLayout::NativeCarrier)
            }
            Some(pair::CleanupRecord::Legacy(_)) if !has_native_sidecar => {
                (None, RecoveryLayout::LegacyOnly)
            }
            Some(pair::CleanupRecord::Legacy(_)) => return Err(conflict()),
            None => (
                None,
                if has_native_sidecar {
                    RecoveryLayout::NativeCarrier
                } else {
                    RecoveryLayout::UnpublishedClaim
                },
            ),
        };
        if let Some(p) = &pair {
            if p.provenance.boot_id != raw.provenance.boot_id
                || p.provenance.runtime != raw.provenance.runtime
                || p.provenance.network_epoch > raw.provenance.network_epoch
                || context.as_ref().is_some_and(|c| {
                    p.provenance != c.provenance
                        || (!p.addresses.is_empty() && p.addresses != c.intent.addresses)
                })
            {
                return Err(conflict());
            }
        }
        let mut rows = [None, None, None];
        let mut requirements = Vec::new();
        if payload(RecordKind::Session).is_none() {
            requirements.push(RecoveryRequirement::MissingSession);
        }
        for (index, (kind, role)) in [
            (RecordKind::CarrierRows, rows::Role::Carrier),
            (RecordKind::MemberARows, rows::Role::MemberA),
            (RecordKind::MemberBRows, rows::Role::MemberB),
        ]
        .into_iter()
        .enumerate()
        {
            if let Some(b) = payload(kind) {
                let r = rows::Record::decode(b).map_err(|_| conflict())?;
                if r.binding.role != role
                    || r.binding.scope != raw.scope
                    || r.binding.boot_id != raw.provenance.boot_id
                    || r.binding.runtime != raw.provenance.runtime
                    || r.binding.network_epoch > raw.provenance.network_epoch
                {
                    return Err(conflict());
                }
                if let Some(c) = &context {
                    let binding = &c.bindings[index];
                    let address = c.intent.addresses.first().ok_or_else(conflict)?.addr();
                    if r.binding.guid != binding.guid
                        || r.binding.name != binding.name
                        || r.binding.network_epoch != c.provenance.network_epoch
                        || std::net::IpAddr::V4(r.binding.address.into()) != address
                    {
                        return Err(conflict());
                    }
                }
                requirements.push(RecoveryRequirement::OriginalRows(role));
                if r.pending
                    .as_ref()
                    .is_some_and(|p| matches!(p.target, rows::Target::Create(_)))
                {
                    requirements.push(RecoveryRequirement::UnknownAddressCreate);
                }
                rows[index] = Some(r);
            }
        }
        if payload(RecordKind::Pair).is_none() {
            requirements.push(RecoveryRequirement::MissingPair);
        }
        if context.is_none() {
            requirements.push(RecoveryRequirement::MissingNativeContext);
        }
        if raw.changed_boot {
            requirements.push(RecoveryRequirement::ChangedBootNativeEmpty);
        }
        if let Some(k) = &keys {
            for receipt in &k.keys {
                if receipt.phase == keys::KeyPhase::CreatePending {
                    requirements.push(RecoveryRequirement::UnknownKeyCreate(receipt.role));
                }
                if receipt.new_key_ack {
                    requirements.push(RecoveryRequirement::OriginalKey(receipt.role));
                }
            }
        }
        // A retained sidecar, including a terminal one, remains an obligation
        // until independent actual native inventory proves EMPTY.
        if payload(RecordKind::Carrier).is_some()
            || pair.as_ref().is_some_and(|p| p.carrier.is_some())
        {
            requirements.push(RecoveryRequirement::OriginalCarrier);
        }
        if let Some(p) = &pair {
            for (i, member) in p.members.iter().enumerate() {
                if member.is_some() {
                    requirements.push(RecoveryRequirement::OriginalMember(if i == 0 {
                        nelomai_client_tunnel::redundancy::Slot::A
                    } else {
                        nelomai_client_tunnel::redundancy::Slot::B
                    }));
                }
            }
        }
        if payload(RecordKind::Network).is_some()
            || pair.as_ref().is_some_and(|p| p.network.is_some())
        {
            requirements.push(RecoveryRequirement::OriginalNetwork);
        }
        if guard.is_some()
            || pair
                .as_ref()
                .is_some_and(|p| p.guard.installed || p.pending_guard.is_some())
        {
            requirements.push(RecoveryRequirement::OriginalGuard);
        }
        requirements.push(RecoveryRequirement::FullNativeEmpty);
        Ok(Self {
            layout,
            context,
            changed_boot: raw.changed_boot,
            keys,
            carrier,
            requirements,
            pair,
            guard,
            creator,
            rows,
            authenticated: raw.clone(),
            records: raw.records.to_vec(),
        })
    }
}

#[cfg(windows)]
pub(crate) mod native {
    use super::super::{
        member_files::MemberFiles,
        member_session::{NativeSessionFiles, OriginalSessionFilesIdentity},
    };
    use super::*;
    use nelomai_contracts::dispatcher::{Installation, MutationGuard, VerifiedLayout};
    use std::{
        path::{Path, PathBuf},
        sync::Arc,
    };

    struct FactoryAuthentication {
        installation: Installation,
        layout: VerifiedLayout,
        executable: PathBuf,
        executable_pin: super::super::member_files::PinnedPayload,
        boot: [u8; 16],
        directory: super::super::member_files::PinnedDirectory,
    }
    /// Factory ENTRY, before fresh claim or RuntimeRead/Context construction.
    /// Only real production signatures, full installed layout, native boot,
    /// SAME held owner and original protected backend. Classification is not a
    /// Source/SCM/Create/native-empty grant and performs NO native mutation.
    pub(crate) struct NativeFactoryRecoveryEntry {
        root: PathBuf,
        owner: Arc<MutationGuard>,
        slot: RuntimeSlot,
        execution: crate::install_recovery::RecoveryExecutable,
        origin: OriginalSessionFilesIdentity,
        protected: Rc<ProtectedRecoveryRoot<MemberFiles>>,
        authenticated: RefCell<Option<Rc<FactoryAuthentication>>>,
        attempted: Cell<bool>,
    }
    impl NativeFactoryRecoveryEntry {
        /// Current-process cleanup admission only. A raw temporary incoming
        /// helper is denied; the protected staged helper is independently
        /// authenticated by its actual executable pin, signed stage and OLD
        /// installed layout on every verify edge. Never grants engine rights.
        pub(crate) fn require_bounded_cleanup_execution(&self) -> io::Result<()> {
            self.execution.require_bounded_cleanup()?;
            self.verify()
        }
        /// Infallible caller-retained READ root. No SDK or private reads here.
        /// This distinct type cannot be passed as a FULL-EMPTY retirement proof.
        pub(crate) fn native_non_wfp_empty_authority(self: &Rc<Self>) -> Rc<NativeNonWfpEmptyRead> {
            Rc::new(NativeNonWfpEmptyRead {
                scanner: NativeColdScanner {
                    entry: Rc::downgrade(self),
                    readers: RefCell::new(None),
                    busy: Cell::new(false),
                    failed: Cell::new(false),
                    full_frames: Cell::new(0),
                },
            })
        }
        pub(crate) fn new(
            root: &Path,
            owner: Arc<MutationGuard>,
            original_files: NativeSessionFiles,
            slot: RuntimeSlot,
            execution: crate::install_recovery::RecoveryExecutable,
        ) -> Self {
            let origin = original_files.read_identity();
            Self {
                root: root.to_owned(),
                owner,
                slot,
                execution,
                origin,
                protected: Rc::new(ProtectedRecoveryRoot::new(original_files)),
                authenticated: RefCell::new(None),
                attempted: Cell::new(false),
            }
        }
        pub(crate) fn verify(&self) -> io::Result<()> {
            let proof = self
                .authenticated
                .try_borrow()
                .map_err(|_| conflict())?
                .clone()
                .ok_or_else(conflict)?;
            self.owner.verify_at(&self.root.join("engine-owner.lock"))?;
            proof.directory.verify().map_err(|_| conflict())?;
            proof.executable_pin.verify().map_err(|_| conflict())?;
            #[cfg(test)]
            let executable = std::fs::canonicalize(
                super::super::member_carrier_factory_test_os::executable()
                    .map(Ok)
                    .unwrap_or_else(std::env::current_exe)?,
            )?;
            #[cfg(not(test))]
            let executable = std::fs::canonicalize(std::env::current_exe()?)?;
            if executable != proof.executable || super::super::member_boot::boot_id()? != proof.boot
            {
                return Err(conflict());
            }
            // Production pinned signing key; hashes and signatures of the full
            // actual deployed runtime are independently checked on EVERY edge.
            let live = self
                .execution
                .load(&proof.installation, &executable, self.slot)?;
            if live.identity != proof.layout.identity || live.directory != proof.layout.directory {
                return Err(conflict());
            }
            let files = self.protected.files.try_borrow().map_err(|_| conflict())?;
            if !self.origin.same_original(&files.read_identity()) {
                return Err(conflict());
            }
            files.require_recovery_runtime_origin(&live.identity, proof.boot)?;
            drop(files);
            proof.directory.verify().map_err(|_| conflict())?;
            self.owner.verify_at(&self.root.join("engine-owner.lock"))
        }
        /// None is no active protected claim, NOT SDK EMPTY. No completion,
        /// reopening old C, old-index lookup, fresh claim, loading or SCM call.
        pub(crate) fn classify(&self) -> io::Result<Option<RecoveryLayout>> {
            if self.attempted.replace(true) {
                self.protected.revoked.set(true);
                return Err(conflict());
            }
            let result = (|| {
                if !self.root.is_absolute() {
                    return Err(conflict());
                }
                self.owner.verify_at(&self.root.join("engine-owner.lock"))?;
                let directory = super::super::member_files::pin_private_directory(&self.root)
                    .map_err(|_| conflict())?;
                #[cfg(test)]
                let installation =
                    super::super::member_carrier_factory_test_os::installation(&self.root)
                        .map(Ok)
                        .unwrap_or_else(|| Installation::production(&self.root))?;
                #[cfg(not(test))]
                let installation = Installation::production(&self.root)?;
                #[cfg(test)]
                let executable = std::fs::canonicalize(
                    super::super::member_carrier_factory_test_os::executable()
                        .map(Ok)
                        .unwrap_or_else(std::env::current_exe)?,
                )?;
                #[cfg(not(test))]
                let executable = std::fs::canonicalize(std::env::current_exe()?)?;
                let layout = self.execution.load(&installation, &executable, self.slot)?;
                if layout.identity.slot != self.slot {
                    return Err(conflict());
                }
                // Read-only Windows ACL/file/ancestor pin of the actual signed
                // kernel executable. No write/delete sharing or path-only copy
                // proof: retain this SAME file throughout cleanup and postflight.
                let executable_pin = super::super::member_files::pin_runtime_payload(
                    &executable,
                    std::fs::metadata(&executable)?.len(),
                    &nelomai_contracts::dispatcher::file_digest(&executable)?,
                )
                .map_err(|_| conflict())?;
                let boot = super::super::member_boot::boot_id()?;
                // Actual signed proof and retained ancestry/owner precede
                // protected callbacks and all fallible recovery postflight.
                *self
                    .authenticated
                    .try_borrow_mut()
                    .map_err(|_| conflict())? = Some(Rc::new(FactoryAuthentication {
                    installation,
                    layout,
                    executable,
                    executable_pin,
                    boot,
                    directory,
                }));
                self.verify()?;
                if !self.protected.initialize(self.slot)? {
                    self.verify()?;
                    return Ok(None);
                }
                self.inspect(|facts| Ok(Some(facts.layout)))
            })();
            if result.is_err() {
                self.protected.revoked.set(true);
            }
            result
        }
        pub(crate) fn inspect<T>(
            &self,
            inspect: impl FnOnce(&RecoveryFacts) -> io::Result<T>,
        ) -> io::Result<T> {
            self.protected.inspect(|facts| {
                self.verify()?;
                let value = inspect(facts)?;
                self.verify()?;
                Ok(value)
            })
        }
        pub(crate) fn retained_facts(&self) -> io::Result<Rc<RecoveryFacts>> {
            self.protected.retained_facts()
        }
    }

    /// Only the non-WFP prerequisite for the separately authenticated Kant
    /// issuer. Protected Guard stays DATA and unchanged; this is NOT WFP-empty,
    /// creator ownership, Calling, a deletion permit or claim-retirement proof.
    pub(crate) struct NativeNonWfpEmptyRead {
        scanner: NativeColdScanner,
    }
    impl NativeNonWfpEmptyRead {
        pub(crate) fn inspect<T>(
            &self,
            read: impl FnOnce(&RecoveryFacts) -> io::Result<T>,
        ) -> io::Result<T> {
            let entry = self.scanner.entry.upgrade().ok_or_else(conflict)?;
            entry.protected.inspect(|facts| {
                require_non_wfp_recovery(facts)?;
                let mut read = Some(read);
                let mut result = None;
                self.scanner
                    .inspect_class(facts, ColdReadClass::NonWfp, &mut || {
                        entry.verify()?;
                        let callback = read.take().ok_or_else(conflict)?;
                        result = Some(callback(facts)?);
                        entry.verify()
                    })?;
                result.ok_or_else(conflict)
            })
        }
    }

    // Downstream only: constructor/classify/signed execution-role verifier are
    // owned by Main. This adapter adds no authentication fallback or boot relax.
    struct SignedColdInventory {
        entry: std::rc::Weak<NativeFactoryRecoveryEntry>,
        native: Rc<dyn NativeColdEmptyInventory>,
    }
    unsafe impl NativeColdEmptyInventory for SignedColdInventory {
        fn inspect_empty(
            &self,
            facts: &RecoveryFacts,
            callback: &mut dyn FnMut() -> io::Result<()>,
        ) -> io::Result<()> {
            let entry = self.entry.upgrade().ok_or_else(conflict)?;
            entry.verify()?;
            self.native.inspect_empty(facts, &mut || {
                let result = (|| {
                    entry.verify()?;
                    callback()?; // protected transaction releases its lock BEFORE next verify
                    entry.verify()
                })();
                if result.is_err() {
                    entry.protected.revoked.set(true);
                }
                result
            })?;
            entry.verify()
        }
    }
    impl NativeFactoryRecoveryEntry {
        /// COLD storage-only retirement. Caller retains this SAME entry before
        /// scanner construction/calls. Mandatory concrete full native issuer;
        /// no RuntimeRead, old Source, handle adoption or default scanner.
        pub(crate) fn retire_cold_empty(
            self: &Rc<Self>,
            native: Rc<dyn NativeColdEmptyInventory>,
        ) -> io::Result<Rc<ColdRetirementAck>> {
            let signed: Rc<dyn NativeColdEmptyInventory> = Rc::new(SignedColdInventory {
                entry: Rc::downgrade(self),
                native,
            });
            let result = (|| {
                self.verify()?;
                let ack = self.protected.retire_cold_empty(signed)?;
                self.verify()?;
                Ok(ack)
            })();
            if result.is_err() {
                self.protected.revoked.set(true);
            }
            result
        }
        pub(crate) fn retained_cold_retirement_ack(
            &self,
        ) -> io::Result<Option<Rc<ColdRetirementAck>>> {
            self.protected.retained_cold_retirement_ack()
        }
        /// Production cold entry. The concrete sampler is retained by the
        /// protected attempt before any SDK read; only weak links point back.
        pub(crate) fn retire_cold_native(self: &Rc<Self>) -> io::Result<()> {
            let selected = self.retained_facts()?;
            let scanner = Rc::new(NativeColdScanner {
                entry: Rc::downgrade(self),
                readers: RefCell::new(None),
                busy: Cell::new(false),
                failed: Cell::new(false),
                full_frames: Cell::new(0),
            });
            let ack = self.retire_cold_empty(scanner)?;
            let retained = self.retained_cold_retirement_ack()?.ok_or_else(conflict)?;
            if !Rc::ptr_eq(&ack, &retained)
                || !ack.matches_origin(&self.origin)
                || ack.scope() != &selected.authenticated.scope
            {
                return Err(conflict());
            }
            self.verify()
        }
    }

    use super::super::member_carrier_guard::{ScopedGuardAbsence, Wfp};
    use std::{
        io::{Read, Seek, SeekFrom},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER,
            ERROR_SERVICE_DOES_NOT_EXIST, FILETIME, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        NetworkManagement::IpHelper::{
            FreeMibTable, GetIfTable2, GetIpInterfaceTable, GetUnicastIpAddressTable,
            MIB_IF_TABLE2, MIB_IPINTERFACE_TABLE, MIB_UNICASTIPADDRESS_TABLE,
        },
        Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC},
        System::{
            Registry::{
                RegCloseKey, RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE,
                REG_OPTION_OPEN_LINK,
            },
            Threading::{
                GetProcessTimes, OpenProcess, WaitForSingleObject,
                PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
            },
        },
    };
    struct ColdReaders {
        guard: Option<ScopedGuardAbsence<Wfp>>,
        members: [ColdMemberFile; 2],
        state: PathBuf,
        state_pin: super::super::member_files::PinnedDirectory,
    }
    struct ColdMemberFile {
        path: PathBuf,
        pin: Rc<RefCell<Option<super::super::member_files::PinnedPayload>>>,
        record: Option<crate::member_owner::Record>,
        original_record: Option<crate::member_owner::Record>,
        bytes: Option<Vec<u8>>,
        storage_history: Rc<RefCell<Vec<Rc<super::super::member_files::ColdMemberStorageAck>>>>,
    }
    impl ColdMemberFile {
        fn open(
            root: &Path,
            slot: nelomai_contracts::dispatcher::TunnelSlot,
            context: &Context,
            engine: &Path,
            canonical_targets: &[keys::Binding; 5],
        ) -> io::Result<Self> {
            use nelomai_contracts::dispatcher::TunnelSlot;
            use sha2::{Digest, Sha256};
            let path = root.join(match slot {
                TunnelSlot::A => "nelomai-a.owner.json",
                TunnelSlot::B => "nelomai-b.owner.json",
            });
            match std::fs::symlink_metadata(&path) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    return Ok(Self {
                        path,
                        pin: Rc::new(RefCell::new(None)),
                        record: None,
                        original_record: None,
                        bytes: None,
                        storage_history: Rc::new(RefCell::new(Vec::new())),
                    })
                }
                Err(e) => return Err(e),
                Ok(_) => {}
            }
            // DATA only, never an imported member/SCM ACK. Pin the selected
            // actual file against write/delete and verify file-ID/ACL/path on
            // every bracket. No MemberFiles.ready/OPEN_ALWAYS lock creation.
            let mut first =
                super::super::member_files::pin_recovery_marker(&path).map_err(|_| conflict())?;
            let mut bytes = Vec::new();
            Read::by_ref(&mut first)
                .take(65537)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 65536 {
                return Err(conflict());
            }
            let digest = format!("{:x}", Sha256::digest(&bytes));
            let pin =
                super::super::member_files::pin_runtime_payload(&path, bytes.len() as u64, &digest)
                    .map_err(|_| conflict())?;
            let mut current = pin.file().try_clone()?;
            current.seek(SeekFrom::Start(0))?;
            let mut selected = Vec::new();
            current.take(65537).read_to_end(&mut selected)?;
            if selected != bytes {
                return Err(conflict());
            }
            let record = cold_member_record(&bytes, slot, context, engine, canonical_targets)?;
            Ok(Self {
                path,
                pin: Rc::new(RefCell::new(Some(pin))),
                original_record: Some(record.clone()),
                record: Some(record),
                bytes: Some(bytes),
                storage_history: Rc::new(RefCell::new(Vec::new())),
            })
        }
        fn verify(&self) -> io::Result<()> {
            if let Some(pin) = &*self.pin.try_borrow().map_err(|_| conflict())? {
                pin.verify().map_err(|_| conflict())
            } else {
                match std::fs::symlink_metadata(&self.path) {
                    Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                    _ => Err(conflict()),
                }
            }
        }
    }
    struct NativeColdScanner {
        entry: std::rc::Weak<NativeFactoryRecoveryEntry>,
        readers: RefCell<Option<ColdReaders>>,
        busy: Cell<bool>,
        failed: Cell<bool>,
        full_frames: Cell<u8>,
    }
    /// Sealed borrowed storage authorization issued ONLY inside the SECOND
    /// FULL-EMPTY native frame after the first full before/after succeeded.
    /// Not a Stop/Create/Closed ACK, not exposed by NonWfpEmptyRead.
    pub(crate) struct NativeColdMemberWriteRead<'a> {
        scanner: &'a NativeColdScanner,
        entry: &'a NativeFactoryRecoveryEntry,
        slot: nelomai_contracts::dispatcher::TunnelSlot,
        expected: &'a [u8],
        desired: &'a [u8],
    }
    impl NativeColdMemberWriteRead<'_> {
        pub(crate) fn verify_backend(
            &self,
            origin: &OriginalSessionFilesIdentity,
        ) -> io::Result<()> {
            if !self.entry.origin.same_original(origin)
                || self.scanner.failed.get()
                || !self.scanner.busy.get()
                || self.scanner.full_frames.get() != 1
            {
                return Err(conflict());
            }
            Ok(())
        }
        pub(crate) fn verify_write(
            &self,
            state: &Path,
            slot: nelomai_contracts::dispatcher::TunnelSlot,
            expected: &[u8],
            desired: &[u8],
        ) -> io::Result<()> {
            let readers = self.scanner.readers.try_borrow().map_err(|_| conflict())?;
            let readers = readers.as_ref().ok_or_else(conflict)?;
            if readers.state != state
                || slot != self.slot
                || expected != self.expected
                || desired != self.desired
                || self.scanner.failed.get()
                || !self.scanner.busy.get()
                || self.scanner.full_frames.get() != 1
            {
                return Err(conflict());
            }
            Ok(())
        }
        pub(crate) fn expected(&self) -> &[u8] {
            self.expected
        }
        pub(crate) fn desired(&self) -> &[u8] {
            self.desired
        }
    }
    struct ScannerFlight<'a>(&'a NativeColdScanner, bool);
    impl Drop for ScannerFlight<'_> {
        fn drop(&mut self) {
            self.0.busy.set(false);
            if !self.1 {
                self.0.failed.set(true);
            }
        }
    }
    #[derive(Eq, PartialEq)]
    struct ColdTables {
        interfaces: Vec<crate::member_physical::InterfaceIdentity>,
        ip: Vec<ColdIpRow>,
        addresses: Vec<ColdAddressRow>,
    }
    struct ColdSnapshot {
        tables: ColdTables,
        physical: crate::member_physical::PhysicalSnapshot,
    }
    #[derive(Clone, Copy)]
    enum ColdReadClass {
        FullEmpty,
        NonWfp,
    }
    impl NativeColdScanner {
        fn sample(
            &self,
            entry: &NativeFactoryRecoveryEntry,
            facts: &RecoveryFacts,
            targets: &[keys::Binding; 5],
            class: ColdReadClass,
        ) -> io::Result<ColdSnapshot> {
            let context = facts.context.as_ref().ok_or_else(conflict)?;
            entry.verify()?;
            // Context/PID is comparison DATA only. SAME-boot cold cleanup
            // requires the actual independently queried kernel lifetime, on
            // BOTH sides of every bracket. Member PID/lock/current PID cannot
            // substitute for missing creator DATA in legacy records.
            if !facts.changed_boot {
                super::super::member_carrier_creator::native::verify_dead(
                    facts.creator.as_ref().ok_or_else(conflict)?,
                )?;
            }
            // Zero expected providers still enumerates the FULL mixed native
            // Net/PnP/MIB universe. Each canonical transport is also queried.
            super::super::member_carrier_provider::native::inspect_mixed(&[])
                .map_err(|_| conflict())?;
            for target in targets {
                super::super::member_carrier_provider::native::inspect_mixed_absent(
                    &[],
                    target.guid,
                    &target.name,
                )
                .map_err(|_| conflict())?;
                absent_registry(&target.registry_path)?;
                // Interface DNS may leave per-family private configuration
                // after NIC removal. Require both canonical keys absent; do
                // not infer restoration from absent C or query its old index.
                absent_registry(
                    &target
                        .registry_path
                        .replace(r"\Services\Tcpip\", r"\Services\Tcpip6\"),
                )?;
            }
            absent_services()?;
            let tables = read_cold_tables()?;
            cold_mib_empty(
                context,
                targets,
                &tables.interfaces,
                &tables.ip,
                &tables.addresses,
            )?;
            if let Some(pair) = &facts.pair {
                for member in pair.members.iter().flatten() {
                    for proof in member.owner.proof.iter().chain(&member.owner.retired_proof) {
                        absent_process(proof.process)?;
                        if tables
                            .interfaces
                            .iter()
                            .any(|id| id.guid == proof.interface.guid)
                        {
                            return Err(conflict());
                        }
                    }
                }
            }
            let physical = super::super::member_physical::capture(&[])?;
            cold_network_rows(facts, &physical)?;
            {
                let mut readers = self.readers.try_borrow_mut().map_err(|_| conflict())?;
                let readers = readers.as_mut().ok_or_else(conflict)?;
                readers.state_pin.verify().map_err(|_| conflict())?;
                if super::super::install::state_directory().map_err(|_| conflict())?
                    != readers.state
                    || entry
                        .protected
                        .files
                        .try_borrow()
                        .map_err(|_| conflict())?
                        .original_state_directory()?
                        != readers.state
                {
                    return Err(conflict());
                }
                for member in &readers.members {
                    member.verify()?;
                    for ack in member
                        .storage_history
                        .try_borrow()
                        .map_err(|_| conflict())?
                        .iter()
                    {
                        ack.verify_retained(member.bytes.as_deref().ok_or_else(conflict)?)
                            .map_err(|_| conflict())?;
                    }
                    for record in member.record.iter().chain(&member.original_record) {
                        for proof in record.proof.iter().chain(&record.retired_proof) {
                            absent_process(proof.process)?;
                            if tables
                                .interfaces
                                .iter()
                                .any(|id| id.guid == proof.interface.guid)
                            {
                                return Err(conflict());
                            }
                        }
                    }
                }
                if matches!(class, ColdReadClass::FullEmpty) {
                    readers
                        .guard
                        .as_mut()
                        .ok_or_else(conflict)?
                        .read_snapshot(&context.intent.scope)
                        .map_err(|_| conflict())?;
                }
                readers.state_pin.verify().map_err(|_| conflict())?;
            }
            entry.verify()?;
            Ok(ColdSnapshot { tables, physical })
        }
    }
    // SAFETY: actual independent SDK reads only. No Runtime/Source/SDK ACK
    // is reconstructed from protected DATA, and every nonempty/error/partial
    // observation fails closed. These reads cannot authorize any OS mutation.
    unsafe impl NativeColdEmptyInventory for NativeColdScanner {
        fn inspect_empty(
            &self,
            facts: &RecoveryFacts,
            callback: &mut dyn FnMut() -> io::Result<()>,
        ) -> io::Result<()> {
            self.inspect_class(facts, ColdReadClass::FullEmpty, callback)
        }
    }
    impl NativeColdScanner {
        fn inspect_class(
            &self,
            facts: &RecoveryFacts,
            class: ColdReadClass,
            callback: &mut dyn FnMut() -> io::Result<()>,
        ) -> io::Result<()> {
            if self.failed.get() || self.busy.replace(true) {
                self.failed.set(true);
                return Err(conflict());
            }
            let mut flight = ScannerFlight(self, false);
            let entry = self.entry.upgrade().ok_or_else(conflict)?;
            entry.verify()?;
            let context = facts.context.as_ref().ok_or_else(conflict)?;
            use nelomai_contracts::dispatcher::TunnelSlot;
            let paths = [
                super::super::install::slot_config_path(TunnelSlot::A),
                super::super::install::slot_config_path(TunnelSlot::B),
            ]
            .map(|r| r.map_err(|_| conflict()));
            let [a, b] = paths;
            let paths = [a?, b?];
            let state = super::super::install::state_directory().map_err(|_| conflict())?;
            let backend = entry
                .protected
                .files
                .try_borrow()
                .map_err(|_| conflict())?
                .original_state_directory()?;
            cold_state_paths(&state, &backend, [&paths[0], &paths[1]])?;
            let targets = cold_namespace(context, [&paths[0], &paths[1]])?;
            if self.readers.try_borrow().map_err(|_| conflict())?.is_none() {
                let auth = entry
                    .authenticated
                    .try_borrow()
                    .map_err(|_| conflict())?
                    .clone()
                    .ok_or_else(conflict)?;
                let state_pin = super::super::member_files::pin_private_directory(&state)
                    .map_err(|_| conflict())?;
                let members = [
                    ColdMemberFile::open(
                        &state,
                        TunnelSlot::A,
                        context,
                        &auth.layout.engine_path(),
                        &targets,
                    )?,
                    ColdMemberFile::open(
                        &state,
                        TunnelSlot::B,
                        context,
                        &auth.layout.engine_path(),
                        &targets,
                    )?,
                ];
                let guard = match class {
                    ColdReadClass::FullEmpty => Some(
                        ScopedGuardAbsence::open(context.intent.scope.clone())
                            .map_err(|_| conflict())?,
                    ),
                    ColdReadClass::NonWfp => None,
                };
                *self.readers.try_borrow_mut().map_err(|_| conflict())? = Some(ColdReaders {
                    guard,
                    members,
                    state,
                    state_pin,
                });
            }
            let before = self.sample(&entry, facts, &targets, class)?;
            if matches!(class, ColdReadClass::FullEmpty) && self.full_frames.get() == 1 {
                // The original parent snapshot is still active and exact.
                // No backend/SDK borrow is held over this factual check.
                entry.protected.check(facts)?;
                self.retire_member_data(&entry)?;
            }
            let result = callback(); // no SDK/reader/Source/Pair borrow spans this
            let after = self.sample(&entry, facts, &targets, class)?;
            if self.failed.get()
                || before.tables != after.tables
                || before.physical.rows() != after.physical.rows()
                || before.physical.proofs() != after.physical.proofs()
            {
                return Err(conflict());
            }
            result?;
            if matches!(class, ColdReadClass::FullEmpty) {
                self.full_frames
                    .set(self.full_frames.get().checked_add(1).ok_or_else(conflict)?);
            }
            flight.1 = true;
            Ok(())
        }
        fn retire_member_data(&self, entry: &NativeFactoryRecoveryEntry) -> io::Result<()> {
            use nelomai_contracts::dispatcher::TunnelSlot;
            for (index, slot) in [TunnelSlot::A, TunnelSlot::B].into_iter().enumerate() {
                let expected = {
                    let readers = self.readers.try_borrow().map_err(|_| conflict())?;
                    readers.as_ref().ok_or_else(conflict)?.members[index]
                        .bytes
                        .clone()
                };
                let Some(expected) = expected else {
                    continue;
                };
                let desired =
                    super::super::member_files::cold_member_retirement_payload(slot, &expected)
                        .map_err(|_| conflict())?;
                let already_terminal = {
                    let readers = self.readers.try_borrow().map_err(|_| conflict())?;
                    let record = readers.as_ref().ok_or_else(conflict)?.members[index]
                        .record
                        .as_ref()
                        .ok_or_else(conflict)?;
                    record.phase == crate::member_owner::Phase::Stopped
                        && record.proof.is_none()
                        && record.retired_proof.is_none()
                };
                if already_terminal {
                    continue;
                }
                let proof = NativeColdMemberWriteRead {
                    scanner: self,
                    entry,
                    slot,
                    expected: &expected,
                    desired: &desired,
                };
                // Move only the original pin into the write holder; no
                // equal-record replacement or reopening can seed this pin.
                let (pin, history) = {
                    let readers = self.readers.try_borrow().map_err(|_| conflict())?;
                    let member = &readers.as_ref().ok_or_else(conflict)?.members[index];
                    (member.pin.clone(), member.storage_history.clone())
                };
                let result = entry
                    .protected
                    .files
                    .try_borrow_mut()
                    .map_err(|_| conflict())?
                    .retire_cold_member_data(
                        &proof,
                        slot,
                        &mut *pin.try_borrow_mut().map_err(|_| conflict())?,
                        &history,
                    );
                // History and pin holders already belong to the caller's
                // retained scanner even if IO unwinds before this point.
                let mut readers = self.readers.try_borrow_mut().map_err(|_| conflict())?;
                let member = &mut readers.as_mut().ok_or_else(conflict)?.members[index];
                result?;
                member.record = Some(serde_json::from_slice(&desired).map_err(|_| conflict())?);
                member.bytes = Some(desired);
            }
            Ok(())
        }
    }
    fn absent_services() -> io::Result<()> {
        use nelomai_client_tunnel::TunnelTransport;
        use nelomai_contracts::dispatcher::TunnelSlot;
        use windows_service::{
            service::ServiceAccess,
            service_manager::{ServiceManager, ServiceManagerAccess},
        };
        for slot in [TunnelSlot::A, TunnelSlot::B] {
            for transport in [TunnelTransport::WireGuard, TunnelTransport::AmneziaWg3] {
                absent_registry(&format!(
                    r"SYSTEM\CurrentControlSet\Services\{}",
                    crate::redundancy::slot_service_name(slot, transport)
                ))?;
                if super::super::install::open_slot_service(
                    slot,
                    transport,
                    ServiceAccess::QUERY_STATUS,
                )
                .map_err(|_| conflict())?
                .is_some()
                {
                    return Err(conflict());
                }
            }
        }
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|_| conflict())?;
        for name in [
            crate::TUNNEL_SERVICE_NAME,
            crate::AMNEZIAWG_TUNNEL_SERVICE_NAME,
        ] {
            absent_registry(&format!(r"SYSTEM\CurrentControlSet\Services\{name}"))?;
            match manager.open_service(name, ServiceAccess::QUERY_STATUS) {
                Err(windows_service::Error::Winapi(e))
                    if e.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) => {}
                _ => return Err(conflict()),
            }
        }
        Ok(())
    }
    fn absent_registry(path: &str) -> io::Result<()> {
        let wide: Vec<_> = path.encode_utf16().chain(Some(0)).collect();
        let mut key = ptr::null_mut();
        let code = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                wide.as_ptr(),
                REG_OPTION_OPEN_LINK,
                KEY_QUERY_VALUE,
                &mut key,
            )
        };
        if !key.is_null() {
            unsafe { RegCloseKey(key) };
        }
        if code == ERROR_FILE_NOT_FOUND {
            Ok(())
        } else {
            Err(conflict())
        }
    }
    struct ReadHandle(HANDLE);
    impl Drop for ReadHandle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }
    fn absent_process(proof: crate::member_owner::ProcessProof) -> io::Result<()> {
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                proof.pid,
            )
        };
        if handle.is_null() {
            let e = io::Error::last_os_error();
            return if e.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
                Ok(())
            } else {
                Err(e)
            };
        }
        let handle = ReadHandle(handle);
        let mut times = [FILETIME::default(); 4];
        if unsafe {
            GetProcessTimes(
                handle.0,
                &mut times[0],
                &mut times[1],
                &mut times[2],
                &mut times[3],
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let creation =
            u64::from(times[0].dwLowDateTime) | (u64::from(times[0].dwHighDateTime) << 32);
        if creation > proof.creation_time {
            return Ok(());
        } // PID reuse is not adoption
        if creation < proof.creation_time {
            return Err(conflict());
        }
        match unsafe { WaitForSingleObject(handle.0, 0) } {
            WAIT_OBJECT_0 => Ok(()),
            WAIT_TIMEOUT => Err(conflict()),
            _ => Err(io::Error::last_os_error()),
        }
    }
    struct MibMemory(*mut std::ffi::c_void);
    impl Drop for MibMemory {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { FreeMibTable(self.0) };
            }
        }
    }
    fn read_cold_tables() -> io::Result<ColdTables> {
        let mut interfaces: *mut MIB_IF_TABLE2 = ptr::null_mut();
        let status = unsafe { GetIfTable2(&mut interfaces) };
        let _interfaces = MibMemory(interfaces.cast());
        if status != 0 || interfaces.is_null() {
            return Err(conflict());
        }
        let count = unsafe { (*interfaces).NumEntries as usize };
        if count > crate::member_routes::MAX_TABLE_ROWS {
            return Err(conflict());
        }
        let raw = unsafe {
            std::slice::from_raw_parts(
                ptr::addr_of!((*interfaces).Table)
                    .cast::<windows_sys::Win32::NetworkManagement::IpHelper::MIB_IF_ROW2>(),
                count,
            )
        };
        let mut ids = Vec::with_capacity(count);
        for row in raw {
            let g = row.InterfaceGuid;
            let mut guid = [0; 16];
            guid[..4].copy_from_slice(&g.data1.to_be_bytes());
            guid[4..6].copy_from_slice(&g.data2.to_be_bytes());
            guid[6..8].copy_from_slice(&g.data3.to_be_bytes());
            guid[8..].copy_from_slice(&g.data4);
            ids.push(crate::member_physical::InterfaceIdentity {
                index: row.InterfaceIndex,
                luid: unsafe { row.InterfaceLuid.Value },
                guid,
            });
        }
        let mut ip: *mut MIB_IPINTERFACE_TABLE = ptr::null_mut();
        let status = unsafe { GetIpInterfaceTable(AF_UNSPEC, &mut ip) };
        let _ip = MibMemory(ip.cast());
        if status != 0 || ip.is_null() {
            return Err(conflict());
        }
        let count = unsafe { (*ip).NumEntries as usize };
        if count > crate::member_routes::MAX_TABLE_ROWS {
            return Err(conflict());
        }
        let raw = unsafe {
            std::slice::from_raw_parts(
                ptr::addr_of!((*ip).Table)
                    .cast::<windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPINTERFACE_ROW>(),
                count,
            )
        };
        let mut ips = raw
            .iter()
            .map(|r| (r.Family, r.InterfaceIndex, unsafe { r.InterfaceLuid.Value }))
            .collect::<Vec<_>>();
        let mut addr: *mut MIB_UNICASTIPADDRESS_TABLE = ptr::null_mut();
        let status = unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut addr) };
        let _addr = MibMemory(addr.cast());
        if status != 0 || addr.is_null() {
            return Err(conflict());
        }
        let count = unsafe { (*addr).NumEntries as usize };
        if count > crate::member_routes::MAX_TABLE_ROWS {
            return Err(conflict());
        }
        let raw = unsafe {
            std::slice::from_raw_parts(ptr::addr_of!((*addr).Table).cast::<windows_sys::Win32::NetworkManagement::IpHelper::MIB_UNICASTIPADDRESS_ROW>(),count)
        };
        let mut addresses = Vec::with_capacity(count);
        for row in raw {
            let family = unsafe { row.Address.si_family };
            let address = if family == AF_INET {
                let a = unsafe { row.Address.Ipv4 };
                if a.sin_port != 0 || a.sin_zero != [0; 8] {
                    return Err(conflict());
                }
                std::net::IpAddr::from(unsafe { a.sin_addr.S_un.S_addr }.to_ne_bytes())
            } else if family == AF_INET6 {
                let a = unsafe { row.Address.Ipv6 };
                let ip = std::net::Ipv6Addr::from(unsafe { a.sin6_addr.u.Byte });
                let scope = unsafe { a.Anonymous.sin6_scope_id };
                if a.sin6_port != 0
                    || a.sin6_flowinfo != 0
                    || (scope != 0 && (scope != row.InterfaceIndex || !ip.is_unicast_link_local()))
                {
                    return Err(conflict());
                }
                std::net::IpAddr::V6(ip)
            } else {
                return Err(conflict());
            };
            addresses.push((
                row.InterfaceIndex,
                unsafe { row.InterfaceLuid.Value },
                address,
            ));
        }
        ids.sort_by_key(|id| (id.index, id.luid, id.guid));
        ips.sort();
        addresses.sort();
        Ok(ColdTables {
            interfaces: ids,
            ip: ips,
            addresses,
        })
    }
}

#[cfg(test)]
#[path = "member_carrier_recovery_tests.rs"]
mod tests;
