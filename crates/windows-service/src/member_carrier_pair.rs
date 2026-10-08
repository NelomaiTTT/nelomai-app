//! Carrier-only coordinator. Deliberately not selected by any factory.
#![allow(dead_code)]

use crate::{
    member_carrier::Provenance,
    member_carrier_guard as guard,
    member_owner::{InterfaceProof, Record as OwnerRecord},
    member_pair::PairSocket,
};
use nelomai_client_tunnel::redundancy::{
    control::PairControl, driver::NativePair, evidence::NativeHealthSample,
};
use nelomai_client_tunnel::{
    redundancy::{protocol::Member, SessionScope, Slot},
    DesktopTunnelOptions,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cell::{BorrowMutError, Cell, RefCell, RefMut},
    io,
    net::IpAddr,
    rc::Rc,
};

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    #[serde(deserialize_with = "decode_version")]
    pub version: u32,
    pub scope: SessionScope,
    pub provenance: Provenance,
    pub revision: u64,
    pub phase: Phase,
    pub addresses: Vec<ipnet::IpNet>,
    pub dns: Vec<IpAddr>,
    pub carrier: Option<InterfaceProof>,
    pub members: [Option<MemberState>; 2],
    pub active: Option<Slot>,
    pub options: Option<DesktopTunnelOptions>,
    pub guard: guard::Model,
    pub pending_guard: Option<guard::ExchangePlan>,
    pub pending: Option<Effect>,
    pub network: Option<NetworkState>,
    pub stop_stage: u8,
    pub operation: Option<Operation>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum Phase {
    Fresh,
    Starting,
    Running,
    Closing,
    Stopped,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum Operation {
    Start(Slot),
    Attach(Slot),
    Switch(Slot),
    Retire(Slot),
    Rebind,
}

pub(crate) enum CleanupRecord {
    Carrier(Box<Record>),
    Legacy(Box<LegacyCleanupRecord>),
}
pub(crate) struct LegacyCleanupRecord {
    record: crate::member_pair::PairRecord,
}
/// Explicit version dispatch. Unknown/malformed versioned data never falls
/// through to legacy; missing C is never inferred into a live carrier record.
pub(crate) fn decode_for_cleanup(bytes: &[u8], scope: &SessionScope) -> io::Result<CleanupRecord> {
    if bytes.len() > 64 * 1024 || !scope.validate() {
        return Err(failed());
    }
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| failed())?;
    let object = value.as_object().ok_or_else(failed)?;
    if object.contains_key("version") {
        let record = Record::decode(bytes)?;
        if record.scope != *scope {
            return Err(failed());
        }
        return Ok(CleanupRecord::Carrier(Box::new(record)));
    }
    let record: crate::member_pair::PairRecord =
        serde_json::from_slice(bytes).map_err(|_| failed())?;
    if record.scope != *scope || record.guard.scope != *scope {
        return Err(failed());
    }
    record.guard.validate().map_err(|_| failed())?;
    for slot in [Slot::A, Slot::B] {
        if let Some(member) = &record.members[idx(slot)] {
            crate::member_owner::validate_record_shape(&member.owner).map_err(|_| failed())?;
            if member.owner.intent.scope != *scope
                || crate::member_pair::slot_shared(member.owner.intent.slot) != slot
            {
                return Err(failed());
            }
            if let Some(prior) = &member.prior_stopped {
                crate::member_owner::validate_prior_stopped(&member.owner.intent, prior)
                    .map_err(|_| failed())?;
            }
        }
    }
    if let Some(plan) = &record.pending_guard {
        if plan.expected != record.guard
            || *plan
                != crate::member_guard::ExchangePlan::new(&plan.expected, &plan.desired)
                    .map_err(|_| failed())?
        {
            return Err(failed());
        }
    }
    Ok(CleanupRecord::Legacy(Box::new(LegacyCleanupRecord {
        record,
    })))
}
impl LegacyCleanupRecord {
    /// The ONLY conversion surface reuses the existing legacy cleanup owner
    /// with its old exact key domain and recovered/live fencing intact.
    pub(crate) fn recover<I: crate::member_pair::PairIo, J: crate::member_pair::PairStore>(
        self,
        scope: SessionScope,
        io: I,
        store: J,
    ) -> io::Result<crate::member_pair::SessionNativePair<I, J>> {
        crate::member_pair::SessionNativePair::recover_for_cleanup(scope, io, store, self.record)
    }
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MemberState {
    pub owner: OwnerRecord,
    pub lease_id: String,
    pub probe: nelomai_contracts::RedundantHealthProbe,
    pub endpoint: IpAddr,
    pub allowed: Vec<ipnet::IpNet>,
    pub peer: [u8; 32],
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkSnapshot {
    pub routes: Vec<nelomai_client_tunnel::redundancy::network::RouteValue>,
    pub dns: Option<crate::member_dns::Snapshot>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkState {
    pub baseline: NetworkSnapshot,
    pub current: NetworkSnapshot,
    pub pending: Option<NetworkSnapshot>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum Effect {
    CarrierReady,
    MemberStart(Slot),
    Guard,
    WeakRows,
    Network,
    HoldProbe(Slot),
    Data(Slot),
    ReleaseProbes,
    RestoreNetwork,
    RestoreWeak,
    MemberStop(Slot),
    CarrierAddressDelete,
    CarrierSessionEnd,
    CarrierClose,
    NativeEmpty,
    RestoreKeys,
    FullEmpty,
    Rebind(Slot),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Fence {
    pub revision: u64,
    pub network_epoch: u64,
}

/// Process-local ACKs from the required native boundaries. Deliberately neither
/// serializable nor recoverable from pair JSON. The adapter retains the original
/// objects behind these acknowledgements; these values alone grant no authority.
#[derive(Default)]
struct EffectReceipts {
    carrier: Option<InterfaceProof>,
    members: [Option<OwnerRecord>; 2],
    guard: Option<guard::Model>,
}

/// Protected bytes, authenticated full scope/boot/runtime/epoch and serialized
/// owner lock are REQUIRED. None->Fresh additionally requires the actual new
/// protected session claim/anti-replay grant; bare file creation is insufficient.
/// Errors can mean committed writes with lost ACK.
/// Recovery never grants live/original handle authority from these records.
pub(crate) trait PairJournal {
    /// Explicit authenticated Stop entry, before the first reconcile/Closing CAS.
    /// Irreversibly revoke forward storage selection and allow only exact own
    /// cleanup records. This is NOT an original native effect/SDK permission.
    fn begin_cleanup(&mut self, scope: &SessionScope) -> io::Result<()>;
    fn load(&mut self, scope: &SessionScope) -> io::Result<Option<Record>>;
    fn compare_exchange(&mut self, expected: Option<&Record>, desired: &Record) -> io::Result<()>;
}
/// Implementations retain original native/provider objects across EVERY error
/// and on Drop. Every mutation uses its native durable journal, exact original
/// ACK/handles and CAS/readback. Retry resolves only its recorded before/after
/// values; equal lookups/JSON, ambiguous create ACKs, broad deletes and automatic
/// cleanup-and-resume are forbidden. Attestation uses main's actual SourceRead
/// capabilities/NativeG under the real serialized lease, not portable models.
pub(crate) trait CarrierPairIo {
    type Socket: PairSocket;
    /// Actual first Running Session ACK joined to the retained original startup
    /// SDK proof. MUST bracket selection with full actual original Running
    /// guard/C/member rows, network ACK/DNS/endpoints and held-probe reads under
    /// the same Pair/deadline. Returned epoch is comparison facts only, never permission.
    fn select_running_execution(&mut self, record: &Record) -> io::Result<u64>;
    fn preflight_fresh(&mut self, record: &Record) -> io::Result<()>;
    /// Actual provider/source/native/runtime/creator authority BEFORE and AFTER
    /// every boundary. First primary MemberStart's AFTER read instead uses
    /// verify_member on its acknowledged Starting record and captured originals.
    /// No serialized boolean, JSON identity or default G proof. Cleanup checks
    /// allow exact original absence, never foreign adoption.
    fn attest_effect(&mut self, record: &Record, effect: Effect) -> io::Result<()>;
    /// Native key/row journals and original ACK/retained C handle REQUIRED.
    /// Publish ONLY address rows and retained-session DAD readiness here.
    /// Five-second bounded/cancellable readiness; weak rows are a later step.
    fn create_carrier_ready(&mut self, record: &Record) -> io::Result<InterfaceProof>;
    fn verify_carrier_ready(&mut self, record: &Record) -> io::Result<()>;
    /// Read-only prepare, including actual native key/AWG/backend capability
    /// validation before C creation or live guard effects. No config publication
    /// or executable/native create. Actual MemberOwner consumes the zeroizing
    /// addressless rendering. Trusted engine comes from the native adapter.
    fn prepare_member(
        &mut self,
        record: &Record,
        member: &Member,
        native: &str,
    ) -> io::Result<OwnerRecord>;
    fn start_member(
        &mut self,
        record: &Record,
        slot: Slot,
        native: &str,
    ) -> io::Result<OwnerRecord>;
    /// First primary post-publication verification includes the SAME controller
    /// ACK, original initial row capture and full Source/WFP/rows/network/ACK
    /// postconditions before any base, weak-row or traffic effect may follow.
    fn verify_member(&mut self, record: &Record, slot: Slot) -> io::Result<()>;
    fn stop_member(&mut self, record: &Record, slot: Slot) -> io::Result<()>;
    fn verify_member_absent(&mut self, record: &Record, slot: Slot) -> io::Result<()>;
    fn guard_snapshot(&mut self, scope: &SessionScope) -> io::Result<guard::Snapshot>;
    /// Real split-engine transaction, lock-held original priority ACK, full
    /// snapshot/identity readback. No policy copied from journal as observation.
    fn guard_exchange(
        &mut self,
        record: &Record,
        kind: guard::SessionKind,
        expected: &guard::Model,
        desired: &guard::Model,
    ) -> io::Result<guard::Model>;
    fn close_dynamic_permits(&mut self, record: &Record) -> io::Result<()>;
    fn apply_weak_rows(&mut self, record: &Record) -> io::Result<()>;
    fn restore_weak_rows(&mut self, record: &Record) -> io::Result<()>;
    fn restore_member_weak_rows(&mut self, record: &Record, slot: Slot) -> io::Result<()>;
    fn read_network(&mut self, record: &Record) -> io::Result<NetworkSnapshot>;
    fn plan_network(&mut self, record: &Record, active: Slot) -> io::Result<NetworkSnapshot>;
    fn plan_retirement_network(
        &mut self,
        record: &Record,
        retired: Slot,
    ) -> io::Result<NetworkSnapshot>;
    /// Required original-native plan boundary, not model validation. Reattest
    /// the complete computed plan against SAME C/A/B originals, exact physical
    /// GUID/LUID/family/metric/route leases, endpoint bypasses and immutable split
    /// options. Physical routes are not member ownership: caller JSON/numeric
    /// index equality or this method's previous success grants no permission.
    fn verify_network_plan(
        &mut self,
        record: &Record,
        active: Slot,
        desired: &NetworkSnapshot,
    ) -> io::Result<()>;
    /// Existing NetworkOwner and OwnedDns exact native CAS/readback, own full
    /// native metadata journal. C owns DNS; physical endpoint bypass stays.
    fn exchange_network(
        &mut self,
        record: &Record,
        expected: &NetworkSnapshot,
        desired: &NetworkSnapshot,
    ) -> io::Result<()>;
    fn verify_network_and_endpoints(&mut self, record: &Record, active: Slot) -> io::Result<()>;
    fn hold_probe(
        &mut self,
        record: &Record,
        slot: Slot,
    ) -> io::Result<(Self::Socket, guard::ProbeTuple)>;
    fn verify_held_probe(
        &mut self,
        record: &Record,
        slot: Slot,
        socket: &Self::Socket,
        tuple: &guard::ProbeTuple,
    ) -> io::Result<()>;
    /// Re-read full allow absence independently under the actual locked guard
    /// owner immediately before release. close_dynamic_permits ACK is not proof.
    fn release_probe(
        &mut self,
        record: &Record,
        slot: Slot,
        socket: Self::Socket,
    ) -> io::Result<()>;
    /// Original provider-held sockets whose open ACK never reached coordinator,
    /// including cleanup-only reopen. Called ONLY after full allow absence.
    fn release_unpublished_probes(&mut self, record: &Record) -> io::Result<()>;
    fn verify_target_health(&mut self, record: &Record, slot: Slot) -> io::Result<()>;
    fn verify_data(&mut self, record: &Record, slot: Slot) -> io::Result<()>;
    fn delete_carrier_addresses(&mut self, record: &Record) -> io::Result<()>;
    fn end_carrier_session(&mut self, record: &Record) -> io::Result<()>;
    fn close_carrier_handle(&mut self, record: &Record) -> io::Result<()>;
    /// Complete C/A/B/session/address/route/DNS inventory, excluding bases and
    /// retained owned precreation values still needed to protect cleanup.
    fn verify_native_empty(&mut self, record: &Record) -> io::Result<()>;
    fn restore_owned_keys(&mut self, record: &Record) -> io::Result<()>;
    fn restore_member_keys(&mut self, record: &Record, slot: Slot) -> io::Result<()>;
    /// Full independent EMPTY native, row/value/key and v2 48-key universe.
    fn verify_full_empty(&mut self, record: &Record) -> io::Result<()>;
    fn observe(
        &mut self,
        record: &Record,
        slot: Slot,
    ) -> io::Result<(
        nelomai_client_tunnel::TunnelMetrics,
        nelomai_client_tunnel::redundancy::evidence::NativeHealthSample,
    )>;
    fn fingerprint(&mut self, record: &Record) -> io::Result<String>;
    /// Select ONLY the next original protected Session ACK before birth-domain
    /// storage/runtime reads. The returned epoch is a fence fact, not authority.
    fn begin_rebind_execution(&mut self, record: &Record) -> io::Result<u64>;
    /// Retain the actual completed SDK/native graph + exact Pair ACK before
    /// returning native success to the common owner. No Boolean/JSON grant.
    fn seal_rebind_execution(&mut self, record: &Record) -> io::Result<()>;
    /// Join the second original Session ACK to THAT retained native completion.
    fn complete_rebind_execution(&mut self, record: &Record) -> io::Result<u64>;
}
/// Private one-shot holder. Only terminal handoff can remove the value, after
/// the whole coordinator has left its callable/live owner.
struct PairOriginal<T>(RefCell<Option<T>>);
impl<T> PairOriginal<T> {
    fn new(original: T) -> Self {
        Self(RefCell::new(Some(original)))
    }
    fn borrow_mut(&self) -> RefMut<'_, T> {
        RefMut::map(self.0.borrow_mut(), |original| {
            original.as_mut().expect("callable original pair part")
        })
    }
    fn try_borrow_mut(&self) -> Result<RefMut<'_, T>, BorrowMutError> {
        self.0.try_borrow_mut().map(|original| {
            RefMut::map(original, |original| {
                original.as_mut().expect("callable original pair part")
            })
        })
    }
}
pub(crate) struct CarrierNativePair<I: CarrierPairIo, J: PairJournal> {
    io: PairOriginal<I>,
    journal: PairOriginal<J>,
    execution_epoch: Cell<u64>,
    execution_completion_pending: bool,
    startup_completion_attempted: bool,
    // Local original CAS acknowledgement, never recovered from Fresh DATA.
    // An unacknowledged retained construction remains rooted but cannot mint
    // a Closing record merely because a later load is absent/equal.
    initial_publication_acknowledged: bool,
    record: Record,
    sockets: [Option<I::Socket>; 2],
    tuples: [Option<guard::ProbeTuple>; 2],
    cleanup_only: bool,
    faulted: Rc<Cell<bool>>,
    uncertain_write: Option<Record>,
    receipts: EffectReceipts,
    terminal_ack_pending: bool,
}
/// Owns the original coordinator, including uncertain writes and historical
/// receipts. Retention is not native cleanup/destructor authorization.
pub(crate) struct CarrierPairTerminalHandoff<I: CarrierPairIo, J: PairJournal> {
    pair: RefCell<Option<CarrierNativePair<I, J>>>,
    terminal_verified: Cell<bool>,
}
impl<I: CarrierPairIo, J: PairJournal> CarrierPairTerminalHandoff<I, J> {
    fn require_transferable(
        pair: &mut CarrierNativePair<I, J>,
        scope: &SessionScope,
    ) -> io::Result<()> {
        pair.check_scope(scope)?;
        pair.record.validate()?;
        if pair.record.phase != Phase::Stopped
            || pair.record.stop_stage != 12
            || pair.record.pending.is_some()
            || pair.record.pending_guard.is_some()
            || pair.record.operation.is_some()
            || pair.record.active.is_some()
            || pair.record.carrier.is_some()
            || pair.record.members.iter().any(Option::is_some)
            || pair.record.network.as_ref().is_some_and(|network| {
                network.pending.is_some() || network.current != network.baseline
            })
            || pair.record.guard != guard::Model::empty(scope.clone()).map_err(|_| failed())?
            || pair.terminal_ack_pending
            || pair.execution_completion_pending
            || pair.uncertain_write.is_some()
            || !pair.initial_publication_acknowledged
            || pair.sockets.iter().any(Option::is_some)
            || pair.tuples.iter().any(Option::is_some)
            || pair.io.0.get_mut().is_none()
            || pair.journal.0.get_mut().is_none()
        {
            return Err(failed());
        }
        Ok(())
    }
    /// Actual post-Stopped original IO read, after the whole coordinator is
    /// retained by its caller. The native implementation verifies SDK/Pair/G
    /// and selects its SAME opaque terminal Pair pin, not a future JSON ACK.
    /// Failure cannot transfer/drop owners; a later read must run afresh.
    pub(crate) fn verify_original_terminal(&self, scope: &SessionScope) -> io::Result<()> {
        if self.terminal_verified.get() {
            return Err(failed());
        }
        let mut retained = self.pair.try_borrow_mut().map_err(|_| failed())?;
        let pair = retained.as_mut().ok_or_else(failed)?;
        Self::require_transferable(pair, scope)?;
        pair.require_current()?;
        pair.io.borrow_mut().verify_full_empty(&pair.record)?;
        pair.require_current()?;
        Self::require_transferable(pair, scope)?;
        self.terminal_verified.set(true);
        Ok(())
    }
    /// Factual owning transfer ONLY. Actual native Pair/SDK/module/terminal
    /// gates remain mandatory; portable Stopped never grants destructor rights.
    /// No journal read, native call, new receipt or replacement owner is made.
    pub(crate) fn take_originals(&self, scope: &SessionScope) -> io::Result<(I, J)> {
        if !self.terminal_verified.get() {
            return Err(failed());
        }
        let mut retained = self.pair.try_borrow_mut().map_err(|_| failed())?;
        let pair = retained.as_mut().ok_or_else(failed)?;
        Self::require_transferable(pair, scope)?;
        // Both originals are present and exclusively borrowed. There is no
        // fallible operation between removing the first and the second value.
        let io = pair.io.0.get_mut().take().expect("checked original IO");
        let journal = pair
            .journal
            .0
            .get_mut()
            .take()
            .expect("checked original journal");
        Ok((io, journal))
    }
}
impl<I: CarrierPairIo, J: PairJournal> Drop for CarrierPairTerminalHandoff<I, J> {
    fn drop(&mut self) {
        if let Some(mut pair) = self.pair.get_mut().take() {
            if pair.io.0.get_mut().is_none()
                && pair.journal.0.get_mut().is_none()
                && pair.sockets.iter().all(Option::is_none)
            {
                // Only inert common records/latches remain; actual I/J were
                // handed to their caller-owned native terminal roots. This
                // drops no native owner, module, journal or socket obligation.
                return;
            }
            // No native terminal ACK is implied by abandoning this root.
            std::mem::forget(pair);
        }
    }
}
// A panic or caught reentrant RefCell error is a failed observation, not a
// chance to reacquire live authority. This retains only process-local fencing;
// it never invents native cleanup permission or performs effects on Drop.
struct ReadFlight {
    faulted: Rc<Cell<bool>>,
    finished: bool,
}
impl Drop for ReadFlight {
    fn drop(&mut self) {
        if !self.finished {
            self.faulted.set(true);
        }
    }
}
fn failed() -> io::Error {
    io::Error::other("carrier_pair_pending_or_conflict")
}
fn idx(slot: Slot) -> usize {
    if slot == Slot::A {
        0
    } else {
        1
    }
}
/// Structural firewall for the native protected-store CAS. This verifies
/// transitions, not native ownership. The store MUST additionally hold its
/// actual serialized lease, authenticate ancestry/provenance and compare exact
/// canonical protected bytes. No phase or JSON value establishes effect authority.
pub(crate) fn validate_transition(expected: Option<&Record>, desired: &Record) -> io::Result<()> {
    desired.validate()?;
    desired.encode()?;
    let Some(old) = expected else {
        if desired.phase != Phase::Fresh
            || desired.revision != 1
            || desired.carrier.is_some()
            || desired.members.iter().any(Option::is_some)
            || desired.network.is_some()
            || !desired.addresses.is_empty()
            || !desired.dns.is_empty()
            || desired.options.is_some()
            || desired.active.is_some()
            || desired.guard.installed
            || desired.pending.is_some()
            || desired.pending_guard.is_some()
            || desired.operation.is_some()
            || desired.stop_stage != 0
        {
            return Err(failed());
        }
        return Ok(());
    };
    old.validate()?;
    if old.scope != desired.scope
        || old.provenance != desired.provenance
        || old.revision.checked_add(1) != Some(desired.revision)
        || old.phase == Phase::Stopped
        || !matches!(
            (old.phase, desired.phase),
            (
                Phase::Fresh,
                Phase::Fresh | Phase::Starting | Phase::Closing
            ) | (
                Phase::Starting,
                Phase::Starting | Phase::Running | Phase::Closing
            ) | (Phase::Running, Phase::Running | Phase::Closing)
                | (Phase::Closing, Phase::Closing | Phase::Stopped)
        )
        || desired.stop_stage < old.stop_stage
        || desired.stop_stage > old.stop_stage + 1
        || (desired.stop_stage != old.stop_stage && old.phase != Phase::Closing)
        || (old.phase != Phase::Fresh
            && (old.addresses != desired.addresses
                || old.dns != desired.dns
                || old.options != desired.options))
        || (desired.phase != Phase::Stopped
            && old.carrier.is_some_and(|c| desired.carrier != Some(c)))
    {
        return Err(failed());
    }
    if let Some(network) = &old.network {
        if desired
            .network
            .as_ref()
            .is_none_or(|n| n.baseline != network.baseline)
        {
            return Err(failed());
        }
    }
    for slot in [Slot::A, Slot::B] {
        if let Some(member) = &old.members[idx(slot)] {
            match &desired.members[idx(slot)] {
                Some(next)
                    if next.owner.intent == member.owner.intent
                        && next.lease_id == member.lease_id
                        && next.probe == member.probe
                        && next.endpoint == member.endpoint
                        && next.allowed == member.allowed
                        && next.peer == member.peer => {}
                None if (old.operation == Some(Operation::Retire(slot))
                    || desired.phase == Phase::Stopped)
                    && desired.guard.members[idx(slot)].is_none()
                    && desired.active != Some(slot) => {}
                _ => return Err(failed()),
            }
        }
    }
    Ok(())
}
/// Pure construction DATA only, never original journal/native authority.
/// Startup and retained Pair use the same validation before consuming inputs.
pub(crate) fn fresh_record(scope: SessionScope, provenance: Provenance) -> io::Result<Record> {
    let record = Record {
        version: 2,
        guard: guard::Model::empty(scope.clone()).map_err(|_| failed())?,
        scope,
        provenance,
        revision: 1,
        phase: Phase::Fresh,
        addresses: vec![],
        dns: vec![],
        carrier: None,
        members: [None, None],
        active: None,
        options: None,
        pending_guard: None,
        pending: None,
        network: None,
        stop_stage: 0,
        operation: None,
    };
    validate_transition(None, &record)?;
    Ok(record)
}
impl<I: CarrierPairIo, J: PairJournal> CarrierNativePair<I, J> {
    /// Retain the complete SAME owner before any protected journal IO.
    /// Invalid inputs are left in their original slots. An occupied destination
    /// is irreversibly fenced, without replacing it or touching incoming owners.
    /// Error/unwind never retries Fresh or resumes execution. If the initial
    /// CAS ACK is lost, cleanup stays Pending: this interface has no opaque
    /// supplier that could authenticate that ACK from a subsequent equal load.
    pub(crate) fn new_retained_into(
        destination: &mut Option<Self>,
        scope: SessionScope,
        provenance: Provenance,
        io: &mut Option<I>,
        journal: &mut Option<J>,
    ) -> io::Result<()> {
        if let Some(original) = destination.as_mut() {
            original.cleanup_only = true;
            original.faulted.set(true);
            return Err(failed());
        }
        if io.is_none() || journal.is_none() {
            return Err(failed());
        }
        let record = fresh_record(scope, provenance)?;
        *destination = Some(Self {
            io: PairOriginal::new(io.take().ok_or_else(failed)?),
            journal: PairOriginal::new(journal.take().ok_or_else(failed)?),
            execution_epoch: Cell::new(record.provenance.network_epoch),
            execution_completion_pending: false,
            startup_completion_attempted: false,
            initial_publication_acknowledged: false,
            record,
            sockets: [None, None],
            tuples: [None, None],
            cleanup_only: true,
            faulted: Rc::new(Cell::new(true)),
            uncertain_write: None,
            receipts: EffectReceipts::default(),
            terminal_ack_pending: false,
        });
        let retained = destination.as_mut().ok_or_else(failed)?;
        if retained
            .journal
            .borrow_mut()
            .load(&retained.record.scope)?
            .is_some()
        {
            return Err(failed());
        }
        retained
            .journal
            .borrow_mut()
            .compare_exchange(None, &retained.record)?;
        // Root the ACK before the fallible readback, not after it. No ACK is
        // inferred when compare_exchange returns Err or unwinds after a write.
        retained.initial_publication_acknowledged = true;
        retained.require_current()?;
        retained.cleanup_only = false;
        retained.faulted.set(false);
        Ok(())
    }
    pub(crate) fn capture_terminal_into(
        source: &mut Option<Self>,
        destination: &mut Option<Rc<CarrierPairTerminalHandoff<I, J>>>,
        handoff: impl FnOnce(&Rc<CarrierPairTerminalHandoff<I, J>>) -> io::Result<()>,
    ) -> io::Result<()> {
        if destination.is_some() {
            return Err(failed());
        }
        let mut original = source.take().ok_or_else(failed)?;
        original.cleanup_only = true;
        original.faulted.set(true);
        let root = Rc::new(CarrierPairTerminalHandoff {
            pair: RefCell::new(Some(original)),
            terminal_verified: Cell::new(false),
        });
        *destination = Some(root.clone());
        handoff(&root)
    }
    pub(crate) fn snapshot(&self) -> &Record {
        &self.record
    }
    pub(crate) fn fence(&self) -> Fence {
        Fence {
            revision: self.record.revision,
            network_epoch: self.execution_epoch.get(),
        }
    }
    pub(crate) fn recover_for_cleanup(
        scope: SessionScope,
        provenance: Provenance,
        saved: Record,
        io: I,
        mut journal: J,
    ) -> io::Result<Self> {
        saved.validate()?;
        if saved.scope != scope
            || saved.provenance != provenance
            || journal.load(&scope)?.as_ref() != Some(&saved)
        {
            return Err(failed());
        }
        Ok(Self {
            io: PairOriginal::new(io),
            journal: PairOriginal::new(journal),
            execution_epoch: Cell::new(saved.provenance.network_epoch),
            execution_completion_pending: false,
            startup_completion_attempted: false,
            initial_publication_acknowledged: true,
            record: saved,
            sockets: [None, None],
            tuples: [None, None],
            cleanup_only: true,
            faulted: Rc::new(Cell::new(true)),
            uncertain_write: None,
            receipts: EffectReceipts::default(),
            terminal_ack_pending: false,
        })
    }
    fn check_scope(&self, scope: &SessionScope) -> io::Result<()> {
        if !scope.validate() || self.record.scope != *scope {
            Err(failed())
        } else {
            Ok(())
        }
    }
    fn check_live(&self, scope: &SessionScope, fence: Fence) -> io::Result<()> {
        self.check_scope(scope)?;
        if self.cleanup_only
            || self.execution_completion_pending
            || self.faulted.get()
            || self.record.phase != Phase::Running
            || self.record.pending.is_some()
            || self.record.pending_guard.is_some()
            || self.record.operation.is_some()
            || self.fence() != fence
        {
            Err(failed())
        } else {
            Ok(())
        }
    }
    fn require_current(&self) -> io::Result<()> {
        if self
            .journal
            .try_borrow_mut()
            .map_err(|_| failed())?
            .load(&self.record.scope)?
            .as_ref()
            != Some(&self.record)
        {
            Err(failed())
        } else {
            Ok(())
        }
    }
    /// Failed ACK is always sticky, even when readback proves the exact write.
    /// Readback classifies ONLY cleanup authority; it never resumes execution.
    fn save(&mut self, mut next: Record) -> io::Result<()> {
        next.revision = self.record.revision.checked_add(1).ok_or_else(failed)?;
        validate_transition(Some(&self.record), &next)?;
        self.uncertain_write = Some(next.clone());
        let ack = self
            .journal
            .borrow_mut()
            .compare_exchange(Some(&self.record), &next);
        let actual = self.journal.borrow_mut().load(&self.record.scope);
        match actual {
            Ok(Some(actual)) if actual == next => {
                self.record = next;
                self.uncertain_write = None;
            }
            Ok(actual) if actual.as_ref() == Some(&self.record) => {
                self.uncertain_write = None;
                self.faulted.set(true);
                return Err(ack.err().unwrap_or_else(failed));
            }
            _ => {
                self.faulted.set(true);
                return Err(failed());
            }
        }
        if let Err(e) = ack {
            self.faulted.set(true);
            self.terminal_ack_pending = self.record.phase == Phase::Stopped;
            return Err(e);
        }
        Ok(())
    }
    fn begin(&mut self, effect: Effect) -> io::Result<()> {
        let mut next = self.record.clone();
        next.pending = Some(effect);
        self.save(next)?;
        self.before(effect)
    }
    fn before(&mut self, effect: Effect) -> io::Result<()> {
        self.require_current()?;
        self.io.borrow_mut().attest_effect(&self.record, effect)
    }
    fn finish(&mut self, effect: Effect, mut next: Record) -> io::Result<()> {
        self.io.borrow_mut().attest_effect(&self.record, effect)?;
        next.pending = None;
        self.save(next)
    }
    fn outcome<T>(&self, result: io::Result<T>) -> io::Result<T> {
        if result.is_err() {
            self.faulted.set(true);
        }
        result
    }
    fn read_live<T>(&self, read: impl FnOnce(&mut I) -> io::Result<T>) -> io::Result<T> {
        self.check_live(&self.record.scope, self.fence())?;
        let mut flight = ReadFlight {
            faulted: self.faulted.clone(),
            finished: false,
        };
        let result = (|| {
            self.require_current()?;
            let value = {
                let mut io = self.io.try_borrow_mut().map_err(|_| failed())?;
                let verify = |io: &mut I| -> io::Result<()> {
                    if io.guard_snapshot(&self.record.scope)? != self.record.guard.expected {
                        return Err(failed());
                    }
                    io.verify_carrier_ready(&self.record)?;
                    for slot in [Slot::A, Slot::B] {
                        if self.record.members[idx(slot)].is_some() {
                            io.verify_member(&self.record, slot)?;
                        }
                    }
                    io.verify_network_and_endpoints(
                        &self.record,
                        self.record.active.ok_or_else(failed)?,
                    )
                };
                verify(&mut io)?;
                let value = read(&mut io)?;
                verify(&mut io)?;
                value
            };
            self.require_current()?;
            if self.faulted.get() {
                return Err(failed());
            }
            Ok(value)
        })();
        let result = self.outcome(result);
        flight.finished = result.is_ok();
        result
    }
    pub(crate) fn start(
        &mut self,
        scope: &SessionScope,
        member: &Member,
        options: &DesktopTunnelOptions,
    ) -> io::Result<()> {
        self.check_scope(scope)?;
        if self.cleanup_only || self.faulted.get() || self.record.phase != Phase::Fresh {
            return Err(failed());
        }
        member.validate()?;
        options.validate().map_err(|_| failed())?;
        let configuration = crate::redundancy::pair_configuration(member.configuration.expose())
            .map_err(|_| failed())?;
        let parameters =
            crate::member_pair::MemberParameters::parse(member.configuration.expose())?;
        let mut next = self.record.clone();
        next.phase = Phase::Starting;
        next.options = Some(options.clone());
        next.operation = Some(Operation::Start(member.slot));
        next.addresses = configuration.addresses.clone();
        next.dns = configuration.dns.clone();
        // Read-only native profile/backend/cold-capability validation precedes
        // all C creation. Preparing an Owner is not native member Start.
        next.members[idx(member.slot)] =
            Some(self.prepare_state(&next, member, &configuration.native, parameters)?);
        // Durable network intent before fresh native inventory, then C exactly once.
        let result = (|| {
            self.save(next)?;
            self.require_current()?;
            self.io.borrow_mut().preflight_fresh(&self.record)?;
            self.begin(Effect::CarrierReady)?;
            let proof = self.io.borrow_mut().create_carrier_ready(&self.record)?;
            self.receipts.carrier = Some(proof);
            valid_proof(proof)?;
            let mut next = self.record.clone();
            next.carrier = Some(proof);
            self.finish(Effect::CarrierReady, next)?;
            self.io.borrow_mut().verify_carrier_ready(&self.record)?;
            self.install_member(member, &configuration.native)?;
            self.transition_guard(self.model(None, false)?)?;
            self.begin(Effect::WeakRows)?;
            self.io.borrow_mut().apply_weak_rows(&self.record)?;
            self.finish(Effect::WeakRows, self.record.clone())?;
            self.select_network(member.slot)?;
            self.hold(member.slot)?;
            self.install_allows(member.slot)?;
            self.begin(Effect::Data(member.slot))?;
            self.io
                .borrow_mut()
                .verify_data(&self.record, member.slot)?;
            let mut next = self.record.clone();
            next.active = Some(member.slot);
            next.phase = Phase::Running;
            next.operation = None;
            self.finish(Effect::Data(member.slot), next)
        })();
        self.outcome(result)
    }
    fn prepare_state(
        &mut self,
        record: &Record,
        member: &Member,
        native: &str,
        parameters: crate::member_pair::MemberParameters,
    ) -> io::Result<MemberState> {
        let owner = self
            .io
            .borrow_mut()
            .prepare_member(record, member, native)?;
        validate_owner(record, member.slot, &owner)?;
        if owner.phase != crate::member_owner::Phase::Prepared
            || owner.proof.is_some()
            || owner.intent.config_sha256 != <[u8; 32]>::from(Sha256::digest(native.as_bytes()))
            || owner.intent.transport
                != nelomai_client_tunnel::detect_configuration_transport(native)
        {
            return Err(failed());
        }
        Ok(MemberState {
            owner,
            lease_id: member.lease_id.clone(),
            probe: member.probe.clone(),
            endpoint: parameters.endpoint,
            allowed: parameters.allowed,
            peer: parameters.peer,
        })
    }
    fn install_member(&mut self, member: &Member, native: &str) -> io::Result<()> {
        self.io.borrow_mut().verify_carrier_ready(&self.record)?;
        let mut next = self.record.clone();
        next.pending = Some(Effect::MemberStart(member.slot));
        self.save(next)?;
        self.before(Effect::MemberStart(member.slot))?;
        let started = self
            .io
            .borrow_mut()
            .start_member(&self.record, member.slot, native)?;
        self.receipts.members[idx(member.slot)] = Some(started.clone());
        let prepared = &self.record.members[idx(member.slot)]
            .as_ref()
            .ok_or_else(failed)?
            .owner;
        if started.intent != prepared.intent
            || started.phase != crate::member_owner::Phase::Running
            || started.proof.is_none()
        {
            return Err(failed());
        }
        validate_owner(&self.record, member.slot, &started)?;
        let mut next = self.record.clone();
        next.members[idx(member.slot)]
            .as_mut()
            .ok_or_else(failed)?
            .owner = started;
        let initial_primary = self.record.phase == Phase::Starting
            && self.record.operation == Some(Operation::Start(member.slot))
            && self.record.pending == Some(Effect::MemberStart(member.slot))
            && self.record.stop_stage == 0
            && self.record.members[1 - idx(member.slot)].is_none()
            && self.record.active.is_none()
            && self.record.network.is_none()
            && self.record.pending_guard.is_none()
            && self.record.guard
                == guard::Model::empty(self.record.scope.clone()).map_err(|_| failed())?;
        if initial_primary {
            // The actual native Running ACK is already retained. Publish it in
            // Starting before reading live bindings and capturing initial rows;
            // the old Prepared frame cannot describe that live member. Full
            // postconditions still precede every base/row/traffic effect.
            let mut flight = ReadFlight {
                faulted: self.faulted.clone(),
                finished: false,
            };
            next.pending = None;
            self.save(next)?;
            self.io
                .borrow_mut()
                .verify_member(&self.record, member.slot)?;
            flight.finished = true;
            Ok(())
        } else {
            self.finish(Effect::MemberStart(member.slot), next)?;
            self.io
                .borrow_mut()
                .verify_member(&self.record, member.slot)
        }
    }
    fn model(&self, active: Option<Slot>, permits: bool) -> io::Result<guard::Model> {
        self.model_excluding(active, permits, None)
    }
    fn model_excluding(
        &self,
        active: Option<Slot>,
        permits: bool,
        excluded: Option<Slot>,
    ) -> io::Result<guard::Model> {
        let proof = self.record.carrier.ok_or_else(failed)?;
        let carrier = guard::Carrier {
            identity: guard::Identity {
                scope: self.record.scope.clone(),
                proof,
            },
            sources: self.record.addresses.iter().map(|a| a.addr()).collect(),
        };
        let mut members = [None, None];
        for slot in [Slot::A, Slot::B] {
            if Some(slot) != excluded {
                if let Some(member) = &self.record.members[idx(slot)] {
                    let proof = member.owner.proof.ok_or_else(failed)?.interface;
                    members[idx(slot)] = Some(guard::Member {
                        identity: guard::Identity {
                            scope: self.record.scope.clone(),
                            proof,
                        },
                        probes: self.tuples[idx(slot)].clone().into_iter().collect(),
                    });
                }
            }
        }
        let model = guard::Model::new(self.record.scope.clone(), carrier, members, active)
            .and_then(|m| m.inherit_sublayer_weight(&self.record.guard))
            .map_err(|_| failed())?;
        if permits {
            Ok(model)
        } else {
            model.without_permits().map_err(|_| failed())
        }
    }
    /// Exact v2 plan written before EVERY split boundary; creation priority is
    /// captured from the acknowledged locked native transaction and CASed before
    /// any later allow. Error leaves the full original plan for cleanup only.
    fn transition_guard(&mut self, desired: guard::Model) -> io::Result<()> {
        self.transition_guard_inflight(desired)?;
        let mut next = self.record.clone();
        next.pending = None;
        self.save(next)
    }
    /// A Stop stage owns the final Guard ACK. Keep its pending effect until
    /// that caller attests the actual native result and advances the stage.
    fn transition_guard_inflight(&mut self, desired: guard::Model) -> io::Result<()> {
        let mut plan =
            guard::ExchangePlan::new(&self.record.guard, &desired).map_err(|_| failed())?;
        let mut next = self.record.clone();
        next.pending_guard = Some(plan.clone());
        next.pending = Some(Effect::Guard);
        self.save(next)?;
        for (kind, target) in [
            (guard::SessionKind::DynamicPermits, plan.withdrawn.clone()),
            (guard::SessionKind::StaticBase, plan.base.clone()),
            (guard::SessionKind::DynamicPermits, plan.desired.clone()),
        ] {
            let after = target
                .inherit_sublayer_weight(&self.record.guard)
                .map_err(|_| failed())?;
            guard::validate_session_exchange(&self.record.scope, &self.record.guard, &after, kind)
                .map_err(|_| failed())?;
            if after == self.record.guard {
                continue;
            }
            self.before(Effect::Guard)?;
            if self.io.borrow_mut().guard_snapshot(&self.record.scope)?
                != self.record.guard.expected
            {
                return Err(failed());
            }
            if after.permits {
                self.permit_authority(after.active.ok_or_else(failed)?)?;
            }
            let before = self.record.guard.clone();
            let committed =
                self.io
                    .borrow_mut()
                    .guard_exchange(&self.record, kind, &before, &after)?;
            self.receipts.guard = Some(committed.clone());
            if after
                .readback_after(&before, &committed.expected)
                .map_err(|_| failed())?
                != committed
            {
                return Err(failed());
            }
            if self.io.borrow_mut().guard_snapshot(&self.record.scope)? != committed.expected {
                return Err(failed());
            }
            if !before.installed && committed.installed {
                // An ACKed native priority receipt must reach protected bytes.
                plan.captured_sublayer_weight = committed.assigned_sublayer_weight;
                plan.base = plan
                    .base
                    .readback_after(&plan.expected, &committed.expected)
                    .map_err(|_| failed())?;
                plan.desired = plan
                    .desired
                    .inherit_sublayer_weight(&committed)
                    .map_err(|_| failed())?;
                plan.validate().map_err(|_| failed())?;
            }
            self.io
                .borrow_mut()
                .attest_effect(&self.record, Effect::Guard)?;
            let mut next = self.record.clone();
            next.guard = committed;
            next.pending_guard = Some(plan.clone());
            self.save(next)?;
        }
        let mut next = self.record.clone();
        next.pending_guard = None;
        self.save(next)
    }
    fn permit_authority(&mut self, slot: Slot) -> io::Result<()> {
        if self.record.guard.permits {
            return Err(failed());
        }
        let mut io = self.io.borrow_mut();
        io.verify_carrier_ready(&self.record)?;
        for s in [Slot::A, Slot::B] {
            if self.record.members[idx(s)].is_some() {
                io.verify_member(&self.record, s)?;
                let tuple = self.tuples[idx(s)].as_ref().ok_or_else(failed)?;
                let socket = self.sockets[idx(s)].as_ref().ok_or_else(failed)?;
                io.verify_held_probe(&self.record, s, socket, tuple)?;
            }
        }
        io.verify_network_and_endpoints(&self.record, slot)
    }
    fn select_network(&mut self, slot: Slot) -> io::Result<()> {
        if self.record.guard.permits || !self.record.guard.installed {
            return Err(failed());
        }
        let desired = self.io.borrow_mut().plan_network(&self.record, slot)?;
        self.select_network_value(slot, desired)
    }
    fn select_network_value(&mut self, slot: Slot, desired: NetworkSnapshot) -> io::Result<()> {
        if self.record.guard.permits || !self.record.guard.installed {
            return Err(failed());
        }
        validate_network(&self.record, &desired, true)?;
        self.io
            .borrow_mut()
            .verify_network_plan(&self.record, slot, &desired)?;
        let observed = self.io.borrow_mut().read_network(&self.record)?;
        let mut next = self.record.clone();
        if let Some(state) = &next.network {
            if state.pending.is_some() || state.current != observed {
                return Err(failed());
            }
        } else {
            next.network = Some(NetworkState {
                baseline: observed.clone(),
                current: observed.clone(),
                pending: None,
            });
        }
        next.network.as_mut().ok_or_else(failed)?.pending = Some(desired.clone());
        next.pending = Some(Effect::Network);
        self.save(next)?;
        self.before(Effect::Network)?;
        self.io
            .borrow_mut()
            .exchange_network(&self.record, &observed, &desired)?;
        if self.io.borrow_mut().read_network(&self.record)? != desired {
            return Err(failed());
        }
        self.io
            .borrow_mut()
            .verify_network_and_endpoints(&self.record, slot)?;
        let mut next = self.record.clone();
        let state = next.network.as_mut().ok_or_else(failed)?;
        state.current = desired;
        state.pending = None;
        self.finish(Effect::Network, next)
    }
    fn hold(&mut self, slot: Slot) -> io::Result<()> {
        self.begin(Effect::HoldProbe(slot))?;
        let (socket, tuple) = self.io.borrow_mut().hold_probe(&self.record, slot)?;
        // Retain the actual handle BEFORE validating any reported tuple/ACK.
        self.sockets[idx(slot)] = Some(socket);
        self.tuples[idx(slot)] = Some(tuple.clone());
        let member = self.record.members[idx(slot)].as_ref().ok_or_else(failed)?;
        if tuple.source != self.record.addresses[0].addr()
            || tuple.target != IpAddr::V4(member.probe.target_ipv4)
            || tuple.source_port == 0
            || tuple.target_port != 53
            || tuple.protocol != 17
        {
            return Err(failed());
        }
        self.io.borrow_mut().verify_held_probe(
            &self.record,
            slot,
            self.sockets[idx(slot)].as_ref().ok_or_else(failed)?,
            &tuple,
        )?;
        self.finish(Effect::HoldProbe(slot), self.record.clone())
    }
    fn install_allows(&mut self, slot: Slot) -> io::Result<()> {
        if self.record.guard.permits {
            return Err(failed());
        }
        self.transition_guard(self.model(Some(slot), true)?)
    }
    pub(crate) fn attach_member(
        &mut self,
        scope: &SessionScope,
        fence: Fence,
        member: &Member,
    ) -> io::Result<()> {
        self.check_live(scope, fence)?;
        member.validate()?;
        if self.record.members[idx(member.slot)].is_some()
            || self.record.active == Some(member.slot)
            || self
                .record
                .members
                .iter()
                .flatten()
                .any(|m| m.lease_id == member.lease_id)
        {
            return Err(failed());
        }
        let configuration = crate::redundancy::pair_configuration(member.configuration.expose())
            .map_err(|_| failed())?;
        if configuration.addresses != self.record.addresses || configuration.dns != self.record.dns
        {
            return Err(failed());
        }
        let parameters =
            crate::member_pair::MemberParameters::parse(member.configuration.expose())?;
        let active = self.record.active.ok_or_else(failed)?;
        let mut staged = self.record.clone();
        staged.members[idx(member.slot)] =
            Some(self.prepare_state(&staged, member, &configuration.native, parameters)?);
        staged.operation = Some(Operation::Attach(member.slot));
        let result = (|| {
            self.check_integrity()?;
            self.save(staged)?;
            self.transition_guard(self.record.guard.without_permits().map_err(|_| failed())?)?;
            self.install_member(member, &configuration.native)?;
            self.transition_guard(self.model(None, false)?)?;
            self.begin(Effect::WeakRows)?;
            self.io.borrow_mut().apply_weak_rows(&self.record)?;
            self.finish(Effect::WeakRows, self.record.clone())?;
            self.select_network(active)?;
            self.hold(member.slot)?;
            self.install_allows(active)?;
            self.begin(Effect::Data(active))?;
            self.io.borrow_mut().verify_data(&self.record, active)?;
            let mut next = self.record.clone();
            next.operation = None;
            self.finish(Effect::Data(active), next)
        })();
        self.outcome(result)
    }
    pub(crate) fn switch(
        &mut self,
        scope: &SessionScope,
        fence: Fence,
        slot: Slot,
    ) -> io::Result<()> {
        self.check_live(scope, fence)?;
        if self.record.members[idx(slot)].is_none() {
            return Err(failed());
        }
        if self.record.active == Some(slot) {
            return self.check_integrity();
        }
        let result = (|| {
            self.check_integrity()?;
            self.io
                .borrow_mut()
                .verify_target_health(&self.record, slot)?;
            let mut next = self.record.clone();
            next.operation = Some(Operation::Switch(slot));
            self.save(next)?;
            self.transition_guard(self.record.guard.without_permits().map_err(|_| failed())?)?;
            self.select_network(slot)?;
            self.install_allows(slot)?;
            self.begin(Effect::Data(slot))?;
            self.io.borrow_mut().verify_data(&self.record, slot)?;
            let mut next = self.record.clone();
            next.active = Some(slot);
            next.operation = None;
            self.finish(Effect::Data(slot), next)
        })();
        self.outcome(result)
    }
    fn reconcile_for_cleanup(&mut self) -> io::Result<()> {
        let current = self
            .journal
            .borrow_mut()
            .load(&self.record.scope)?
            .ok_or_else(failed)?;
        current.validate()?;
        if current != self.record && self.uncertain_write.as_ref() != Some(&current) {
            return Err(failed());
        }
        self.record = current;
        self.uncertain_write = None;
        Ok(())
    }
    fn closing_with_receipts(&self) -> io::Result<Record> {
        let mut next = self.record.clone();
        next.phase = Phase::Closing;
        next.active = None;
        next.pending = None;
        next.operation = None;
        if let Some(proof) = self.receipts.carrier {
            valid_proof(proof)?;
            if next.carrier.is_some_and(|saved| saved != proof) {
                return Err(failed());
            }
            next.carrier = Some(proof);
        }
        for slot in [Slot::A, Slot::B] {
            if let Some(owner) = &self.receipts.members[idx(slot)] {
                let saved = next.members[idx(slot)].as_mut().ok_or_else(failed)?;
                if owner.intent != saved.owner.intent {
                    return Err(failed());
                }
                saved.owner = owner.clone();
                validate_owner(&next, slot, owner)?;
            }
        }
        if let Some(model) = &self.receipts.guard {
            model.validate().map_err(|_| failed())?;
            if model.scope != next.scope {
                return Err(failed());
            }
            next.guard = model.clone();
        }
        next.validate()?;
        Ok(next)
    }
    fn withdraw_cleanup(&mut self) -> io::Result<()> {
        self.before(Effect::Guard)?;
        self.io.borrow_mut().close_dynamic_permits(&self.record)?;
        let actual = self.io.borrow_mut().guard_snapshot(&self.record.scope)?;
        let mut candidates = vec![self.record.guard.without_permits().map_err(|_| failed())?];
        if let Some(model) = &self.receipts.guard {
            candidates.push(model.without_permits().map_err(|_| failed())?);
        }
        if let Some(plan) = &self.record.pending_guard {
            plan.validate().map_err(|_| failed())?;
            for candidate in [&plan.expected, &plan.withdrawn, &plan.base, &plan.desired] {
                let mut model = candidate.clone();
                if model.installed && plan.captured_sublayer_weight.is_some() {
                    let bound = plan.base.clone();
                    model = model
                        .inherit_sublayer_weight(&bound)
                        .map_err(|_| failed())?;
                }
                candidates.push(model.without_permits().map_err(|_| failed())?);
            }
        }
        let model = candidates
            .into_iter()
            .find(|m| m.expected == actual)
            .ok_or_else(failed)?;
        // Exact equality covers absent keys as well as all allow/filter fields.
        let mut next = self.record.clone();
        next.guard = model;
        next.pending_guard = None;
        // This is still the Guard operation. Its actual native consumer must
        // attest the withdrawal before finish(Guard) acknowledges that stage.
        // Only finish clears the pending effect after that check succeeds.
        self.save(next)
    }
    fn release_all(&mut self) -> io::Result<()> {
        if self.record.guard.permits || self.record.pending_guard.is_some() {
            return Err(failed());
        }
        if self.io.borrow_mut().guard_snapshot(&self.record.scope)? != self.record.guard.expected {
            return Err(failed());
        }
        self.io
            .borrow_mut()
            .release_unpublished_probes(&self.record)?;
        for slot in [Slot::A, Slot::B] {
            if let Some(socket) = self.sockets[idx(slot)].take() {
                self.io
                    .borrow_mut()
                    .release_probe(&self.record, slot, socket)?;
                self.tuples[idx(slot)] = None;
            }
        }
        Ok(())
    }
    fn restore_network(&mut self) -> io::Result<()> {
        let Some(state) = self.record.network.clone() else {
            return Ok(());
        };
        let observed = self.io.borrow_mut().read_network(&self.record)?;
        validate_network(&self.record, &observed, false)?;
        let snapshots = [
            &state.baseline,
            &state.current,
            state.pending.as_ref().unwrap_or(&state.baseline),
        ];
        let known_routes = snapshots.map(|snapshot| {
            snapshot
                .routes
                .iter()
                .map(|route| ((route.destination, route.interface), route))
                .collect::<std::collections::BTreeMap<_, _>>()
        });
        let observed_routes = observed
            .routes
            .iter()
            .map(|route| ((route.destination, route.interface), route))
            .collect::<std::collections::BTreeMap<_, _>>();
        let keys = known_routes
            .iter()
            .flat_map(|routes| routes.keys())
            .chain(observed_routes.keys())
            .collect::<std::collections::BTreeSet<_>>();
        if !snapshots
            .iter()
            .any(|snapshot| snapshot.dns == observed.dns)
            || keys.into_iter().any(|key| {
                !known_routes
                    .iter()
                    .any(|routes| routes.get(key) == observed_routes.get(key))
            })
        {
            return Err(failed());
        }
        let mut next = self.record.clone();
        let network = next.network.as_mut().ok_or_else(failed)?;
        network.current = observed.clone();
        network.pending = Some(state.baseline.clone());
        self.save(next)?;
        self.before(Effect::RestoreNetwork)?;
        self.io
            .borrow_mut()
            .exchange_network(&self.record, &observed, &state.baseline)?;
        if self.io.borrow_mut().read_network(&self.record)? != state.baseline {
            return Err(failed());
        }
        let mut next = self.record.clone();
        let network = next.network.as_mut().ok_or_else(failed)?;
        network.current = state.baseline;
        network.pending = None;
        self.save(next)
    }
    /// Strict sequential cleanup; no publication, resume or speculative panel
    /// authentication. Each stage is durably acknowledged before the next.
    pub(crate) fn stop(&mut self, scope: &SessionScope) -> io::Result<()> {
        self.check_scope(scope)?;
        self.cleanup_only = true;
        self.faulted.set(true);
        if !self.initial_publication_acknowledged {
            return Err(failed());
        }
        self.journal.borrow_mut().begin_cleanup(scope)?;
        self.reconcile_for_cleanup()?;
        if self.record.phase == Phase::Stopped {
            if self.terminal_ack_pending {
                self.before(Effect::FullEmpty)?;
                self.io.borrow_mut().verify_full_empty(&self.record)?;
                if self.io.borrow_mut().guard_snapshot(&self.record.scope)?
                    != self.record.guard.expected
                {
                    return Err(failed());
                }
                self.require_current()?;
                self.terminal_ack_pending = false;
            }
            self.execution_completion_pending = false;
            return Ok(());
        }
        self.cleanup_only = true;
        self.faulted.set(true);
        if self.record.phase != Phase::Closing {
            let next = self.closing_with_receipts()?;
            // protectedClosing is the first cleanup write/effect.
            self.save(next)?;
        }
        while self.record.stop_stage < 12 {
            let stage = self.record.stop_stage;
            let effect = match stage {
                0 => Effect::Guard,
                1 => Effect::ReleaseProbes,
                2 => Effect::RestoreNetwork,
                3 => Effect::RestoreWeak,
                4 => Effect::MemberStop(Slot::A),
                5 => Effect::MemberStop(Slot::B),
                6 => Effect::CarrierAddressDelete,
                7 => Effect::CarrierSessionEnd,
                8 => Effect::CarrierClose,
                9 => Effect::NativeEmpty,
                10 => Effect::Guard,
                _ => Effect::RestoreKeys,
            };
            self.begin(effect)?;
            match stage {
                0 => self.withdraw_cleanup()?,
                1 => self.release_all()?,
                2 => self.restore_network()?,
                3 => self.io.borrow_mut().restore_weak_rows(&self.record)?,
                4 | 5 => {
                    let slot = if stage == 4 { Slot::A } else { Slot::B };
                    self.io.borrow_mut().stop_member(&self.record, slot)?;
                    self.io
                        .borrow_mut()
                        .verify_member_absent(&self.record, slot)?;
                }
                6 => self
                    .io
                    .borrow_mut()
                    .delete_carrier_addresses(&self.record)?,
                7 => self.io.borrow_mut().end_carrier_session(&self.record)?,
                8 => self.io.borrow_mut().close_carrier_handle(&self.record)?,
                9 => self.io.borrow_mut().verify_native_empty(&self.record)?,
                10 => {
                    self.io.borrow_mut().verify_native_empty(&self.record)?;
                    if let Some(plan) = self.record.pending_guard.clone() {
                        let actual = self.io.borrow_mut().guard_snapshot(&self.record.scope)?;
                        let resolved = plan.resolve(&actual).map_err(|_| failed())?;
                        if resolved.permits {
                            return Err(failed());
                        }
                        let mut next = self.record.clone();
                        next.guard = resolved;
                        next.pending_guard = None;
                        self.save(next)?;
                    }
                    self.transition_guard_inflight(
                        guard::Model::empty(self.record.scope.clone()).map_err(|_| failed())?,
                    )?;
                }
                _ => self.io.borrow_mut().restore_owned_keys(&self.record)?,
            }
            let mut next = self.record.clone();
            next.stop_stage = stage + 1;
            self.finish(effect, next)?;
        }
        self.begin(Effect::FullEmpty)?;
        self.io.borrow_mut().verify_full_empty(&self.record)?;
        if self.io.borrow_mut().guard_snapshot(&self.record.scope)?
            != guard::Model::empty(self.record.scope.clone())
                .map_err(|_| failed())?
                .expected
        {
            return Err(failed());
        }
        let mut next = self.record.clone();
        next.phase = Phase::Stopped;
        next.pending_guard = None;
        next.active = None;
        next.carrier = None;
        next.members = [None, None];
        self.finish(Effect::FullEmpty, next)?;
        self.execution_completion_pending = false;
        Ok(())
    }
}

fn decode_version<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u32, D::Error> {
    let version = u32::deserialize(d)?;
    if version != 2 {
        return Err(serde::de::Error::custom("carrier_pair_version"));
    }
    Ok(version)
}
fn valid_proof(proof: InterfaceProof) -> io::Result<()> {
    if proof.index == 0 || proof.luid == 0 || proof.guid == [0; 16] {
        Err(failed())
    } else {
        Ok(())
    }
}
fn validate_owner(record: &Record, slot: Slot, owner: &OwnerRecord) -> io::Result<()> {
    crate::member_owner::validate_record_shape(owner).map_err(|_| failed())?;
    if owner.intent.scope != record.scope
        || crate::member_pair::slot_shared(owner.intent.slot) != slot
    {
        return Err(failed());
    }
    if let Some(proof) = owner.proof {
        valid_proof(proof.interface)?;
        let mut retained = record
            .members
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != idx(slot))
            .filter_map(|(_, m)| m.as_ref()?.owner.proof.map(|p| p.interface))
            .collect::<Vec<_>>();
        retained.extend(record.carrier);
        if retained.iter().any(|p| {
            p.index == proof.interface.index
                || p.luid == proof.interface.luid
                || p.guid == proof.interface.guid
        }) {
            return Err(failed());
        }
    }
    Ok(())
}
fn validate_network(record: &Record, network: &NetworkSnapshot, selected: bool) -> io::Result<()> {
    let c = record.carrier.ok_or_else(failed)?;
    let mut keys = std::collections::BTreeSet::new();
    if network.routes.len() > crate::member_plan::MAX_ROUTES
        || network.routes.iter().any(|r| {
            r.interface == c.index
                || r.destination != r.destination.trunc()
                || r.interface == 0
                || r.scope
                    != nelomai_client_tunnel::redundancy::network::RouteScope::WindowsInterface(
                        r.interface,
                    )
                || r.gateway
                    .is_some_and(|g| g.is_ipv6() != r.destination.addr().is_ipv6())
                || !keys.insert((r.destination, r.interface))
        })
    {
        return Err(failed());
    }
    if selected && network.routes.is_empty() {
        return Err(failed());
    }
    if let Some(dns) = &network.dns {
        if dns.interface.scope != record.scope
            || dns.interface.index != c.index
            || dns.interface.luid != c.luid
            || dns.interface.guid != c.guid
        {
            return Err(failed());
        }
        if selected && !record.dns.is_empty() {
            let desired = dns.with_servers(&record.dns).map_err(|_| failed())?;
            if desired != *dns {
                return Err(failed());
            }
        }
    } else if selected && !record.dns.is_empty() {
        return Err(failed());
    }
    Ok(())
}
impl Record {
    pub(crate) fn encode(&self) -> io::Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self).map_err(|_| failed())?;
        if bytes.len() > 64 * 1024 {
            return Err(failed());
        }
        Ok(bytes)
    }
    pub(crate) fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > 64 * 1024 {
            return Err(failed());
        }
        let record: Self = serde_json::from_slice(bytes).map_err(|_| failed())?;
        record.validate()?;
        Ok(record)
    }
    pub(crate) fn validate(&self) -> io::Result<()> {
        if self.version != 2
            || !self.scope.validate()
            || self.revision == 0
            || self.provenance.boot_id == [0; 16]
            || self.provenance.network_epoch == 0
            || self.provenance.runtime.slot != self.scope.runtime
            || self.stop_stage > 12
            || self.guard.scope != self.scope
        {
            return Err(failed());
        }
        self.guard.validate().map_err(|_| failed())?;
        if let Some(plan) = &self.pending_guard {
            plan.validate().map_err(|_| failed())?;
            if plan.expected.scope != self.scope
                || (self.phase != Phase::Closing && self.pending != Some(Effect::Guard))
            {
                return Err(failed());
            }
        }
        let empty_claim = self.addresses.is_empty()
            && self.options.is_none()
            && self.carrier.is_none()
            && self.members.iter().all(Option::is_none)
            && !self.guard.installed;
        if !(matches!(self.phase, Phase::Fresh | Phase::Stopped) || empty_claim)
            && (self.addresses.len() != 1
                || !matches!(self.addresses[0],ipnet::IpNet::V4(a) if a.prefix_len()==32))
        {
            return Err(failed());
        }
        if let Some(c) = self.carrier {
            valid_proof(c)?;
        }
        if let Some(c) = &self.guard.carrier {
            if Some(c.identity.proof) != self.carrier
                || c.identity.scope != self.scope
                || c.sources != self.addresses.iter().map(|a| a.addr()).collect::<Vec<_>>()
            {
                return Err(failed());
            }
        }
        for slot in [Slot::A, Slot::B] {
            if let Some(egress) = &self.guard.members[idx(slot)] {
                let member = self.members[idx(slot)].as_ref().ok_or_else(failed)?;
                if egress.identity.scope != self.scope
                    || member.owner.proof.map(|p| p.interface) != Some(egress.identity.proof)
                {
                    return Err(failed());
                }
            }
        }
        for slot in [Slot::A, Slot::B] {
            if let Some(m) = &self.members[idx(slot)] {
                validate_owner(self, slot, &m.owner)?;
            }
        }
        if let Some(options) = &self.options {
            options.validate().map_err(|_| failed())?;
        }
        if self.phase == Phase::Running
            && (self.carrier.is_none()
                || self.active.is_none()
                || self.active.is_some_and(|s| self.members[idx(s)].is_none()))
        {
            return Err(failed());
        }
        if self.phase == Phase::Stopped
            && (self.pending.is_some()
                || self.pending_guard.is_some()
                || self.guard.installed
                || self.active.is_some()
                || self.stop_stage != 12
                || self.carrier.is_some()
                || self.members.iter().any(Option::is_some)
                || self.operation.is_some()
                || self
                    .network
                    .as_ref()
                    .is_some_and(|n| n.current != n.baseline || n.pending.is_some()))
        {
            return Err(failed());
        }
        Ok(())
    }
}

impl<I: CarrierPairIo, J: PairJournal> NativePair for CarrierNativePair<I, J> {
    type Socket = I::Socket;
    fn check_integrity(&mut self) -> io::Result<()> {
        self.read_live(|_| Ok(()))
    }
    fn sample(&mut self, slot: Slot) -> Option<NativeHealthSample> {
        self.record.members[idx(slot)].as_ref()?;
        self.read_live(|io| io.observe(&self.record, slot).map(|(_, s)| s))
            .ok()
    }
    fn open_probe(&mut self, slot: Slot) -> io::Result<(Self::Socket, String)> {
        self.read_live(|io| {
            let member = self.record.members[idx(slot)].as_ref().ok_or_else(failed)?;
            let socket = self.sockets[idx(slot)].as_ref().ok_or_else(failed)?;
            io.verify_held_probe(
                &self.record,
                slot,
                socket,
                self.tuples[idx(slot)].as_ref().ok_or_else(failed)?,
            )?;
            Ok((socket.duplicate()?, member.probe.query_name.clone()))
        })
    }
    fn select_active(&mut self, scope: &SessionScope, slot: Slot) -> io::Result<()> {
        self.switch(scope, self.fence(), slot)
    }
    fn close(&mut self, scope: &SessionScope) -> io::Result<()> {
        self.stop(scope)
    }
}
impl<I: CarrierPairIo, J: PairJournal> PairControl for CarrierNativePair<I, J> {
    fn complete_start(&mut self, scope: &SessionScope) -> io::Result<()> {
        self.check_scope(scope)?;
        let fence = self.fence();
        self.check_live(scope, fence)?;
        if self.record.phase != Phase::Running
            || self.record.pending.is_some()
            || self.record.pending_guard.is_some()
            || self.record.operation.is_some()
            || std::mem::replace(&mut self.startup_completion_attempted, true)
        {
            return Err(failed());
        }
        let mut flight = ReadFlight {
            faulted: self.faulted.clone(),
            finished: false,
        };
        let result = (|| {
            self.require_current()?;
            let epoch = self
                .io
                .borrow_mut()
                .select_running_execution(&self.record)?;
            if epoch != self.execution_epoch.get() {
                return Err(failed());
            }
            self.check_live(scope, fence)?;
            self.require_current()
        })();
        let result = self.outcome(result);
        flight.finished = result.is_ok();
        result
    }
    fn complete_rebind(&mut self, scope: &SessionScope) -> io::Result<()> {
        self.check_scope(scope)?;
        if !self.execution_completion_pending
            || self.cleanup_only
            || self.faulted.get()
            || self.record.phase != Phase::Running
            || self.record.pending.is_some()
            || self.record.pending_guard.is_some()
            || self.record.operation.is_some()
        {
            return Err(failed());
        }
        let result = (|| {
            let expected = self
                .execution_epoch
                .get()
                .checked_add(1)
                .ok_or_else(failed)?;
            let actual = self
                .io
                .borrow_mut()
                .complete_rebind_execution(&self.record)?;
            if actual != expected {
                return Err(failed());
            }
            self.execution_epoch.set(actual);
            self.execution_completion_pending = false;
            self.check_integrity()
        })();
        self.outcome(result)
    }
    fn metrics(&self, slot: Slot) -> io::Result<nelomai_client_tunnel::TunnelMetrics> {
        self.check_live(&self.record.scope, self.fence())?;
        if self.record.active != Some(slot) {
            return Err(failed());
        }
        self.read_live(|io| io.observe(&self.record, slot).map(|(m, _)| m))
    }
    fn physical_network_fingerprint(&self) -> io::Result<String> {
        self.read_live(|io| io.fingerprint(&self.record))
    }
    fn start_primary(
        &mut self,
        scope: &SessionScope,
        member: &Member,
        options: &DesktopTunnelOptions,
    ) -> io::Result<()> {
        self.start(scope, member, options)
    }
    fn attach(&mut self, scope: &SessionScope, member: &Member) -> io::Result<()> {
        self.attach_member(scope, self.fence(), member)
    }
    fn remove_standby(&mut self, scope: &SessionScope, slot: Slot) -> io::Result<()> {
        self.check_live(scope, self.fence())?;
        if self.record.active == Some(slot) {
            return Err(failed());
        }
        if self.record.members[idx(slot)].is_none() {
            return Ok(());
        }
        let active = self.record.active.ok_or_else(failed)?;
        let result = (|| {
            self.check_integrity()?;
            let mut next = self.record.clone();
            next.operation = Some(Operation::Retire(slot));
            self.save(next)?;
            self.transition_guard(self.record.guard.without_permits().map_err(|_| failed())?)?;
            let desired = self
                .io
                .borrow_mut()
                .plan_retirement_network(&self.record, slot)?;
            let retired = self.record.members[idx(slot)]
                .as_ref()
                .ok_or_else(failed)?
                .owner
                .proof
                .ok_or_else(failed)?
                .interface;
            if desired.routes.iter().any(|r| r.interface == retired.index) {
                return Err(failed());
            }
            self.select_network_value(active, desired)?;
            // The original live member/carrier pins still exist here. Releasing
            // after weak restoration or member Stop would require inventing
            // live source authority from a retired identity. Keep all bases,
            // independently verify no permits, and close the SAME held socket
            // before retiring any source/member native rows.
            self.begin(Effect::ReleaseProbes)?;
            if self.io.borrow_mut().guard_snapshot(&self.record.scope)?
                != self.record.guard.expected
            {
                return Err(failed());
            }
            if let Some(socket) = self.sockets[idx(slot)].take() {
                self.io
                    .borrow_mut()
                    .release_probe(&self.record, slot, socket)?;
            }
            self.tuples[idx(slot)] = None;
            self.finish(Effect::ReleaseProbes, self.record.clone())?;
            self.begin(Effect::RestoreWeak)?;
            self.io
                .borrow_mut()
                .restore_member_weak_rows(&self.record, slot)?;
            self.finish(Effect::RestoreWeak, self.record.clone())?;
            self.begin(Effect::MemberStop(slot))?;
            self.io.borrow_mut().stop_member(&self.record, slot)?;
            self.io
                .borrow_mut()
                .verify_member_absent(&self.record, slot)?;
            self.finish(Effect::MemberStop(slot), self.record.clone())?;
            self.transition_guard(self.model_excluding(None, false, Some(slot))?)?;
            self.begin(Effect::RestoreKeys)?;
            self.io
                .borrow_mut()
                .restore_member_keys(&self.record, slot)?;
            let mut next = self.record.clone();
            next.members[idx(slot)] = None;
            self.receipts.members[idx(slot)] = None;
            self.finish(Effect::RestoreKeys, next)?;
            self.install_allows(active)?;
            self.begin(Effect::Data(active))?;
            self.io.borrow_mut().verify_data(&self.record, active)?;
            let mut next = self.record.clone();
            next.operation = None;
            self.finish(Effect::Data(active), next)
        })();
        self.outcome(result)
    }
    fn rebind_pair(&mut self, scope: &SessionScope) -> io::Result<bool> {
        self.check_live(scope, self.fence())?;
        let active = self.record.active.ok_or_else(failed)?;
        let carrier = self.record.carrier.ok_or_else(failed)?;
        let result = (|| {
            let expected = self
                .execution_epoch
                .get()
                .checked_add(1)
                .ok_or_else(failed)?;
            let actual = self.io.borrow_mut().begin_rebind_execution(&self.record)?;
            if actual != expected {
                return Err(failed());
            }
            self.execution_epoch.set(actual);
            self.check_integrity()?;
            let mut next = self.record.clone();
            next.operation = Some(Operation::Rebind);
            self.save(next)?;
            self.transition_guard(self.record.guard.without_permits().map_err(|_| failed())?)?;
            self.begin(Effect::ReleaseProbes)?;
            self.release_all()?;
            self.finish(Effect::ReleaseProbes, self.record.clone())?;
            for slot in [Slot::A, Slot::B] {
                if self.record.members[idx(slot)].is_some() {
                    self.io.borrow_mut().verify_member(&self.record, slot)?;
                }
            }
            if self.record.carrier != Some(carrier) {
                return Err(failed());
            }
            self.io.borrow_mut().verify_carrier_ready(&self.record)?;
            self.select_network(active)?;
            for slot in [Slot::A, Slot::B] {
                if self.record.members[idx(slot)].is_some() {
                    self.hold(slot)?;
                }
            }
            self.install_allows(active)?;
            self.begin(Effect::Data(active))?;
            self.io.borrow_mut().verify_data(&self.record, active)?;
            let mut next = self.record.clone();
            next.operation = None;
            self.finish(Effect::Data(active), next)?;
            self.io.borrow_mut().seal_rebind_execution(&self.record)?;
            self.execution_completion_pending = true;
            Ok(true)
        })();
        self.outcome(result)
    }
    fn cleanup_pending(&self) -> bool {
        self.terminal_ack_pending
            || self.execution_completion_pending
            || self.uncertain_write.is_some()
            || (self.record.phase != Phase::Stopped
                && (!self.startup_completion_attempted
                    || self.cleanup_only
                    || self.faulted.get()
                    || self.record.phase != Phase::Running
                    || self.record.pending.is_some()
                    || self.record.pending_guard.is_some()
                    || self.record.operation.is_some()))
    }
}
impl<I: CarrierPairIo, J: PairJournal> Drop for CarrierNativePair<I, J> {
    fn drop(&mut self) {
        // No implicit Stop/CAS/delete. Abandonment must keep exclusive ports
        // unavailable until process exit when allow absence is not proved.
        // Provider I must similarly retain native handles/obligations on Drop.
        for socket in &mut self.sockets {
            if let Some(socket) = socket.take() {
                std::mem::forget(socket);
            }
        }
    }
}

#[cfg(test)]
#[path = "member_carrier_pair_tests.rs"]
pub(crate) mod tests;
