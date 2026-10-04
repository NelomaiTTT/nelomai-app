//! Staged original startup: readonly member preparation precedes C creation.
//! Selected by the retained production factory; native effect gates and
//! hardware acceptance remain mandatory and separate from software coverage.
#![allow(dead_code)]

#[cfg(windows)]
use super::member_carrier_terminal_release::TerminalCallState;
use crate::member_carrier::{CarrierError as Error, Intent, Provenance, Result};
use crate::member_carrier_native_ownership::{Binding, Context, Role};
#[cfg(not(windows))]
use crate::member_carrier_terminal_release::TerminalCallState;
use crate::member_native_guid::{self as guid, ProviderPath};
use nelomai_client_tunnel::{redundancy::SessionScope, TunnelTransport};
use nelomai_contracts::dispatcher::TunnelSlot;
use std::path::Path;

/// Cleanup selection only. The original initialized journal and its ACK remain
/// mandatory inside `select`; completion of this call grants no native absence,
/// owner disposal, Pair phase or initial-DATA retirement permission.
fn run_pre_pair_cleanup_selection(
    already_attempted: bool,
    state: &TerminalCallState,
    select: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if already_attempted {
        return state.verify().map_err(|_| Error::Retired);
    }
    state
        .run(|| select().map_err(|_| std::io::Error::other("pre_pair_cleanup_selection")))
        .map_err(|_| Error::Retired)
}

/// Ownership transfer ONLY. The cold callback is the existing infallible native
/// cold actor composition: no journal/native IO, fallible output or postflight.
/// Every converted owner is in a caller slot before Pair publication; Err or
/// unwind then leaves that SAME complete Pair accessible and non-forward.
fn transfer_startup_retained_into<
    S,
    I: crate::member_carrier_pair::CarrierPairIo,
    J: crate::member_carrier_pair::PairJournal,
>(
    startup: &mut Option<S>,
    io: &mut Option<I>,
    journal: &mut Option<J>,
    pair: &mut Option<crate::member_carrier_pair::CarrierNativePair<I, J>>,
    identity: impl FnOnce(&S) -> (SessionScope, Provenance),
    cold: impl FnOnce(S) -> (I, J),
) -> std::io::Result<()> {
    use crate::member_carrier_pair::{fresh_record, CarrierNativePair};
    if let Some(original) = pair.as_ref() {
        // The occupied constructor branch fences only this existing owner. Its
        // own DATA supplies the arguments for denial, never adoption or IO.
        let scope = original.snapshot().scope.clone();
        let provenance = original.snapshot().provenance.clone();
        return CarrierNativePair::new_retained_into(pair, scope, provenance, io, journal);
    }
    if io.is_some() || journal.is_some() {
        return Err(std::io::Error::other("startup_retained_slots_occupied"));
    }
    let original = startup
        .as_ref()
        .ok_or_else(|| std::io::Error::other("startup_retained_owner_missing"))?;
    let (scope, provenance) = identity(original);
    fresh_record(scope.clone(), provenance.clone())?;
    let original = startup
        .take()
        .ok_or_else(|| std::io::Error::other("startup_retained_owner_missing"))?;
    let (original_io, original_journal) = cold(original);
    *io = Some(original_io);
    *journal = Some(original_journal);
    CarrierNativePair::new_retained_into(pair, scope, provenance, io, journal)
}

fn bind_initial_data_outcome<O>(
    destination: &std::cell::RefCell<Option<std::rc::Rc<O>>>,
    binding: &TerminalCallState,
    original: std::rc::Rc<O>,
    postflight: impl FnOnce(&O) -> Result<()>,
) -> Result<()> {
    binding
        .run(|| {
            let mut slot = destination
                .try_borrow_mut()
                .map_err(|_| std::io::Error::other("noc_data_busy"))?;
            if slot.is_some() {
                return Err(std::io::Error::other("noc_data_duplicate"));
            }
            *slot = Some(original.clone());
            drop(slot);
            postflight(&original).map_err(|_| std::io::Error::other("noc_data_outcome"))
        })
        .map_err(|_| Error::Retired)
}

/// Once-only completion around a separately authenticated, bounded reader.
/// The reader must itself perform actual Calling and positive worker rundown.
/// This state records completion, not native absence or disposition permission.
fn run_module_only_read_call(
    state: &TerminalCallState,
    authenticate: impl Fn() -> Result<()>,
    bounded_read: impl FnOnce() -> Result<()>,
) -> Result<()> {
    state
        .run(|| {
            authenticate().map_err(|_| std::io::Error::other("module_read_preflight"))?;
            let result = bounded_read();
            authenticate().map_err(|_| std::io::Error::other("module_read_postflight"))?;
            result.map_err(|_| std::io::Error::other("module_read_bounded_return"))
        })
        .map_err(|_| Error::Retired)
}

fn run_repeated_module_only_read_call(
    history: &std::cell::RefCell<Vec<std::rc::Rc<TerminalCallState>>>,
    authenticate: impl Fn() -> Result<()>,
    bounded_read: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let state = std::rc::Rc::new(TerminalCallState::new());
    {
        let mut retained = history.try_borrow_mut().map_err(|_| Error::Conflict)?;
        if retained.len() >= 32 {
            return Err(Error::Pending);
        }
        for previous in retained.iter() {
            previous.verify().map_err(|_| Error::Retired)?;
        }
        retained.push(state.clone()); // retain BEFORE preflight/native read/postflight
    }
    run_module_only_read_call(&state, authenticate, bounded_read)
}

/// Caller retains this destination. This is ownership registration only, not
/// a journal/creator ACK, native absence or failed-constructor disposal grant.
fn retain_claim_startup<S>(
    destination: &mut Option<S>,
    original: S,
    publish_initial: impl FnOnce(&mut S) -> Result<()>,
) -> Result<()> {
    if destination.is_some() {
        return Err(Error::Conflict);
    }
    *destination = Some(original);
    publish_initial(destination.as_mut().ok_or(Error::Pending)?)
}

/// Pure acknowledgment/origin comparison for final owner Drop bookkeeping.
/// The actual native provider alone owns/mints these completed call states.
/// This cannot grant SDK access, rearm Calling or replace actor disposal.
fn verify_zero_effect_rundown<S>(
    original: &std::rc::Rc<S>,
    supplied: &S,
    whole: &TerminalCallState,
    disposal: &TerminalCallState,
) -> Result<()> {
    if !std::ptr::eq(original.as_ref(), supplied) {
        return Err(Error::Conflict);
    }
    whole.verify().map_err(|_| Error::Retired)?;
    disposal.verify().map_err(|_| Error::Retired)
}

/// Constructor-attempt fence ONLY. An untouched flag is NOT a resource or
/// Never capability; original private/native/SDK gates remain mandatory.
fn begin_graph_construction(attempted: &std::cell::Cell<bool>) -> Result<()> {
    if attempted.replace(true) {
        return Err(Error::Retired);
    }
    Ok(())
}
fn require_uncaptured_graph(attempted: &std::cell::Cell<bool>) -> Result<()> {
    if attempted.get() {
        return Err(Error::Retired);
    }
    Ok(())
}

// Private invocation identity, not resource permission. The actual Startup
// retains this before invoking create/attach; terminal witnesses use Weak only.
struct StartupInvocationLedger {
    create: std::cell::Cell<bool>,
    attach: std::cell::Cell<bool>,
}
/// Factual private attempted-layout selection ONLY, never native permission.
/// OtherAttempted is explicitly unsupported by the current pregraph disposer;
/// it must not be converted into Never, module_count one, or full graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeAttemptedTerminalLayout {
    PublishedCarrierPregraph,
    GraphAttempted,
    OtherAttempted,
}
fn classify_attempted_layout(
    invocation: &StartupInvocationLedger,
    create: bool,
    attach: bool,
    graph: bool,
    published: bool,
) -> Result<NativeAttemptedTerminalLayout> {
    if !invocation.attempted(create, attach)? || attach && !graph {
        return Err(Error::Conflict);
    }
    Ok(if graph {
        NativeAttemptedTerminalLayout::GraphAttempted
    } else if published {
        NativeAttemptedTerminalLayout::PublishedCarrierPregraph
    } else {
        NativeAttemptedTerminalLayout::OtherAttempted
    })
}
/// Comparison ONLY. A typed actual loader boundary and immutable original
/// no-constructor Assembly seal are separately mandatory; no EMPTY-data grant.
fn compare_module_only_candidate_frame(
    invocation: &StartupInvocationLedger,
    create: bool,
    attach: bool,
    graph: bool,
    context: &Context,
    expected: &crate::member_carrier_pair::Record,
) -> Result<()> {
    if !invocation.attempted(create, attach)? || !create || attach || graph {
        return Err(Error::Conflict);
    }
    compare_module_only_read_record(context, expected)
}

/// Factual read stage only. Original no-constructor/load lineage and actual
/// current Pair publication/Calling remain mandatory in native consumers.
pub(crate) fn compare_module_only_read_record(
    context: &Context,
    expected: &crate::member_carrier_pair::Record,
) -> Result<()> {
    use crate::member_carrier_pair::{Effect, Phase};
    use nelomai_client_tunnel::redundancy::Slot;
    expected.validate().map_err(|_| Error::Conflict)?;
    crate::member_carrier_native_ownership::validate_context(context)?;
    if expected.scope != context.intent.scope
        || expected.provenance != context.provenance
        || expected.addresses != context.intent.addresses
        || expected.options.is_none()
        || expected.carrier.is_some()
        || expected.members.iter().flatten().any(|m| {
            m.owner.phase != crate::member_owner::Phase::Prepared
                || m.owner.proof.is_some()
                || m.owner.retired_proof.is_some()
                || m.owner.previous_config_sha256.is_some()
        })
        || expected.network.is_some()
        || expected.operation.is_some()
        || expected.active.is_some()
        || expected.pending_guard.is_some()
        || expected.guard
            != crate::member_carrier_guard::Model::empty(expected.scope.clone())
                .map_err(|_| Error::Conflict)?
        || !matches!(
            (expected.phase, expected.stop_stage, expected.pending),
            (Phase::Closing, 0, Some(Effect::Guard))
                | (Phase::Closing, 1, Some(Effect::ReleaseProbes))
                | (Phase::Closing, 2, Some(Effect::RestoreNetwork))
                | (Phase::Closing, 3, Some(Effect::RestoreWeak))
                | (Phase::Closing, 4, Some(Effect::MemberStop(Slot::A)))
                | (Phase::Closing, 5, Some(Effect::MemberStop(Slot::B)))
                | (Phase::Closing, 6, Some(Effect::CarrierAddressDelete))
                | (Phase::Closing, 7, Some(Effect::CarrierSessionEnd))
                | (Phase::Closing, 8, Some(Effect::CarrierClose))
                | (Phase::Closing, 9, Some(Effect::NativeEmpty))
                | (Phase::Closing, 10, Some(Effect::Guard))
                | (Phase::Closing, 11, Some(Effect::RestoreKeys))
                | (Phase::Closing, 12, Some(Effect::FullEmpty))
                | (Phase::Stopped, 12, None)
        )
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
pub(crate) fn compare_module_only_read_progress(
    context: &Context,
    original: &crate::member_carrier_pair::Record,
    current: &crate::member_carrier_pair::Record,
) -> Result<()> {
    compare_module_only_read_record(context, original)?;
    compare_module_only_read_record(context, current)?;
    if current.revision < original.revision
        || current.stop_stage < original.stop_stage
        || current.dns != original.dns
        || current.options != original.options
        || (current.phase != crate::member_carrier_pair::Phase::Stopped
            && current.members != original.members)
        || (original.phase == crate::member_carrier_pair::Phase::Stopped
            && current.phase != crate::member_carrier_pair::Phase::Stopped)
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Read-frame slot selection only; no native resource or release permission.
fn module_only_read_stage(expected: &crate::member_carrier_pair::Record) -> Result<usize> {
    use crate::member_carrier_pair::Phase;
    expected.validate().map_err(|_| Error::Conflict)?;
    if expected.phase == Phase::Stopped && expected.stop_stage == 12 && expected.pending.is_none() {
        return Ok(13);
    }
    if expected.phase != Phase::Closing || expected.stop_stage > 12 {
        return Err(Error::Conflict);
    }
    Ok(usize::from(expected.stop_stage))
}
impl StartupInvocationLedger {
    fn new() -> Self {
        Self {
            create: std::cell::Cell::new(false),
            attach: std::cell::Cell::new(false),
        }
    }
    fn begin(&self, attach: bool) -> Result<()> {
        let field = if attach { &self.attach } else { &self.create };
        if field.replace(true) {
            return Err(Error::Retired);
        }
        Ok(())
    }
    fn attempted(&self, create: bool, attach: bool) -> Result<bool> {
        if self.create.get() != create || self.attach.get() != attach {
            return Err(Error::Conflict);
        }
        Ok(self.create.get() || self.attach.get())
    }
}

#[derive(Clone, Copy, PartialEq)]
enum LivePreparationState {
    Idle,
    Calling,
    Failed,
}

/// Invocation fence only, not native permission. Keep it outside the WHOLE
/// supervisor call so outer postflight failure/unwind cannot reopen preparation.
fn run_live_preparation<T>(
    state: &std::cell::Cell<LivePreparationState>,
    call: impl FnOnce() -> Result<T>,
) -> Result<T> {
    if state.replace(LivePreparationState::Failed) != LivePreparationState::Idle {
        return Err(Error::Retired);
    }
    state.set(LivePreparationState::Calling);
    let value = call()?;
    if state.get() != LivePreparationState::Calling {
        return Err(Error::Retired);
    }
    state.set(LivePreparationState::Idle);
    Ok(value)
}

/// Sequence only: an actual opaque retirement ticket and actual caller
/// projection must succeed BEFORE old roots move or a replacement is prepared.
fn prepare_live_generation<S, T, R>(
    state: &mut S,
    replacement: bool,
    ticket: impl FnOnce(&mut S) -> Result<T>,
    project: impl FnOnce(&mut S, &T) -> Result<()>,
    retain: impl FnOnce(&mut S, &T) -> Result<()>,
    prepare: impl FnOnce(&mut S) -> Result<R>,
) -> Result<R> {
    if replacement {
        let original = ticket(state)?;
        project(state, &original)?;
        retain(state, &original)?;
    }
    prepare(state)
}

#[derive(Clone, Copy)]
enum StartupRead {
    Forward,
    Cleanup,
    Terminal,
}

/// Ordering comparison only. Actual Runtime.bind_native_execution_birth must
/// authenticate SAME Session/Starting/Runtime root; these fields grant nothing.
fn begin_native_birth(
    attempted: &mut bool,
    phase: crate::member_carrier_pair::Phase,
    carrier_present: bool,
    create_attempted: bool,
) -> Result<()> {
    if std::mem::replace(attempted, true) {
        return Err(Error::Retired);
    }
    if phase != crate::member_carrier_pair::Phase::Starting || carrier_present || create_attempted {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn compare_uncaptured_terminal_snapshot(
    scope: &SessionScope,
    actual: &crate::member_carrier_guard::Snapshot,
) -> Result<()> {
    let empty =
        crate::member_carrier_guard::Model::empty(scope.clone()).map_err(|_| Error::Conflict)?;
    if *actual != empty.expected {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NoCarrierConfiguration {
    Unconfigured,
    Configured,
}
// Shape comparison ONLY. The actual Startup Never ledger/SDK whole-call proof
// remains mandatory; this never turns record data into owning disposition.
fn compare_zero_effect_terminal_record(
    context: &Context,
    expected: &crate::member_carrier_pair::Record,
) -> Result<NoCarrierConfiguration> {
    use crate::member_carrier_pair::Phase;
    compare_bootstrap_origin(context, expected, BootstrapOrigin::OriginalNever)?;
    if expected.phase != Phase::Stopped
        || expected.stop_stage != 12
        || expected.pending.is_some()
        || expected.pending_guard.is_some()
        || expected.operation.is_some()
        || expected.active.is_some()
        || expected.members.iter().any(Option::is_some)
    {
        return Err(Error::Conflict);
    }
    match (&expected.options, expected.addresses.is_empty()) {
        (None, true) if expected.dns.is_empty() => Ok(NoCarrierConfiguration::Unconfigured),
        (Some(_), false) if expected.addresses == context.intent.addresses => {
            Ok(NoCarrierConfiguration::Configured)
        }
        _ => Err(Error::Conflict),
    }
}

/// Full-snapshot comparison only. Caller must independently authenticate the
/// SAME Never ledger or opaque Retired/full-resource proof inside Calling.
#[derive(Clone, Copy)]
enum BootstrapOrigin {
    OriginalNever,
    CreatedRetired,
}
fn inspect_bootstrap_empty(
    context: &Context,
    expected: &crate::member_carrier_pair::Record,
    origin: BootstrapOrigin,
    mut read: impl FnMut() -> Result<crate::member_carrier_guard::Snapshot>,
) -> Result<()> {
    read_bootstrap_empty(context, expected, origin, &mut read).map(|_| ())
}
fn read_bootstrap_empty(
    context: &Context,
    expected: &crate::member_carrier_pair::Record,
    origin: BootstrapOrigin,
    mut read: impl FnMut() -> Result<crate::member_carrier_guard::Snapshot>,
) -> Result<crate::member_carrier_guard::Snapshot> {
    compare_bootstrap_empty_frame(context, expected, origin)?;
    let actual = read()?;
    if actual != expected.guard.expected
        || actual
            .filters
            .iter()
            .any(|f| f.action == crate::member_carrier_guard::Action::Permit)
        || read()? != actual
    {
        return Err(Error::Conflict);
    }
    Ok(actual)
}
fn compare_bootstrap_empty_frame(
    context: &Context,
    expected: &crate::member_carrier_pair::Record,
    origin: BootstrapOrigin,
) -> Result<()> {
    use crate::member_carrier_pair::{Effect, Phase};
    compare_bootstrap_origin(context, expected, origin)?;
    if expected.phase != Phase::Closing
        || expected.active.is_some()
        || expected.operation.is_some()
        || expected.pending_guard.is_some()
        || expected.guard.permits
        || !matches!(
            (expected.stop_stage, expected.pending),
            (9, Some(Effect::NativeEmpty)) | (10, Some(Effect::Guard))
        )
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn compare_bootstrap_origin(
    context: &Context,
    expected: &crate::member_carrier_pair::Record,
    origin: BootstrapOrigin,
) -> Result<()> {
    expected.validate().map_err(|_| Error::Conflict)?;
    crate::member_carrier_native_ownership::validate_context(context)?;
    // Channel is comparison facts, NOT a capability. Only the native caller's
    // original zero-attempt Never ledger may select OriginalNever. A created C
    // can never acquire the Fresh-address exception after Close/absence.
    match origin {
        BootstrapOrigin::OriginalNever => {
            if (!expected.addresses.is_empty() && expected.addresses != context.intent.addresses)
                || (expected.addresses.is_empty()
                    && (!expected.dns.is_empty() || expected.options.is_some()))
                || expected.carrier.is_some()
                || expected.network.is_some()
                || expected.guard
                    != crate::member_carrier_guard::Model::empty(expected.scope.clone())
                        .map_err(|_| Error::Conflict)?
                || expected.members.iter().flatten().any(|m| {
                    m.owner.phase != crate::member_owner::Phase::Prepared
                        || m.owner.proof.is_some()
                        || m.owner.retired_proof.is_some()
                        || m.owner.previous_config_sha256.is_some()
                })
            {
                return Err(Error::Conflict);
            }
        }
        BootstrapOrigin::CreatedRetired if expected.addresses != context.intent.addresses => {
            return Err(Error::Conflict);
        }
        BootstrapOrigin::CreatedRetired => {}
    }
    if expected.scope != context.intent.scope || expected.provenance != context.provenance {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Dispatcher comparison ONLY. The original C/row owner and mandatory native
/// gate still authenticate every SDK effect. An interrupted attach is never
/// eligible, even if its partial graph has no returned fields.
fn compare_pregraph_cleanup(
    invocation: &StartupInvocationLedger,
    create_attempted: bool,
    attach_attempted: bool,
    context: &Context,
    expected: &crate::member_carrier_pair::Record,
) -> Result<()> {
    use crate::member_carrier_pair::{Effect, Phase};
    invocation.attempted(create_attempted, attach_attempted)?;
    compare_bootstrap_origin(context, expected, BootstrapOrigin::CreatedRetired)?;
    if !create_attempted
        || attach_attempted
        || expected.phase != Phase::Closing
        || expected.active.is_some()
        || expected.operation.is_some()
        || expected.pending_guard.is_some()
        || expected.network.is_some()
        || expected.guard
            != crate::member_carrier_guard::Model::empty(expected.scope.clone())
                .map_err(|_| Error::Conflict)?
        || expected.members.iter().flatten().any(|member| {
            member.owner.phase != crate::member_owner::Phase::Prepared
                || member.owner.proof.is_some()
                || member.owner.retired_proof.is_some()
                || member.owner.previous_config_sha256.is_some()
        })
        || !matches!(
            (expected.stop_stage, expected.pending),
            (3, Some(Effect::RestoreWeak))
                | (6, Some(Effect::CarrierAddressDelete))
                | (7, Some(Effect::CarrierSessionEnd))
                | (8, Some(Effect::CarrierClose))
        )
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Factual read result only. Original Never/Retired capability and Calling
/// must bracket the caller's full SDK reads; this cannot mint either proof.
fn inspect_bootstrap_full_empty(
    context: &Context,
    expected: &crate::member_carrier_pair::Record,
    origin: BootstrapOrigin,
    mut read: impl FnMut() -> Result<crate::member_carrier_guard::Snapshot>,
) -> Result<crate::member_carrier_guard::Snapshot> {
    use crate::member_carrier_pair::{Effect, Phase};
    compare_bootstrap_origin(context, expected, origin)?;
    if expected.phase != Phase::Closing
        || expected.stop_stage != 12
        || expected.pending != Some(Effect::FullEmpty)
        || expected.pending_guard.is_some()
        || expected.active.is_some()
        || expected.operation.is_some()
        || expected.guard
            != crate::member_carrier_guard::Model::empty(expected.scope.clone())
                .map_err(|_| Error::Conflict)?
    {
        return Err(Error::Conflict);
    }
    let actual = read()?;
    compare_uncaptured_terminal_snapshot(&expected.scope, &actual)?;
    if actual != expected.guard.expected || read()? != actual {
        return Err(Error::Conflict);
    }
    Ok(actual)
}

// Join ordering only. The native caller supplies the actual private prepared
// originals reader INSIDE its current C terminal SDK lease, never a default G.
fn inspect_prepublication_full_empty(
    context: &Context,
    expected: &crate::member_carrier_pair::Record,
    mut verify_originals: impl FnMut() -> Result<()>,
    mut read: impl FnMut() -> Result<crate::member_carrier_guard::Snapshot>,
) -> Result<crate::member_carrier_guard::Snapshot> {
    verify_originals()?;
    let result =
        inspect_bootstrap_full_empty(context, expected, BootstrapOrigin::CreatedRetired, || {
            verify_originals()?;
            let sampled = read();
            verify_originals()?;
            sampled
        });
    verify_originals()?;
    result
}
fn inspect_prepublication_native_empty(
    context: &Context,
    expected: &crate::member_carrier_pair::Record,
    mut verify_originals: impl FnMut() -> Result<()>,
    mut read: impl FnMut() -> Result<crate::member_carrier_guard::Snapshot>,
) -> Result<crate::member_carrier_guard::Snapshot> {
    verify_originals()?;
    let result = read_bootstrap_empty(context, expected, BootstrapOrigin::CreatedRetired, || {
        verify_originals()?;
        let sampled = read();
        verify_originals()?;
        sampled
    });
    verify_originals()?;
    result
}

/// Comparison only. Native cleanup must additionally authenticate the exact
/// original Closing ACK and an actual Calling watchdog; phase is no authority.
fn startup_read_allowed(
    cancelled: bool,
    phase: crate::member_carrier_pair::Phase,
    purpose: StartupRead,
) -> Result<()> {
    if (cancelled && matches!(purpose, StartupRead::Forward))
        || (matches!(purpose, StartupRead::Cleanup)
            && phase != crate::member_carrier_pair::Phase::Closing)
        || (matches!(purpose, StartupRead::Terminal)
            && phase != crate::member_carrier_pair::Phase::Stopped)
    {
        return Err(Error::Retired);
    }
    Ok(())
}

/// Comparison-only deterministic layout. No caller GUID/name/index, server
/// allocator change, filesystem effect or ownership permission is accepted.
fn requested_context(
    scope: &SessionScope,
    provenance: &Provenance,
    logical: &str,
    paths: [&Path; 2],
) -> Result<Context> {
    let rendered = crate::redundancy::pair_configuration(logical).map_err(|_| Error::Invalid)?;
    crate::member_pair::MemberParameters::parse(logical).map_err(|_| Error::Invalid)?;
    let transport = nelomai_client_tunnel::detect_configuration_transport(logical);
    let (provider, revision) = match transport {
        TunnelTransport::WireGuard => (ProviderPath::WireGuardSignedDll, guid::WG_SOURCE_REVISION),
        TunnelTransport::AmneziaWg3 => (ProviderPath::AmneziaSignedDll, guid::AWG_SOURCE_REVISION),
    };
    let carrier = crate::member_carrier::carrier_key(scope)?;
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
    let member = |slot: TunnelSlot, path: &Path| {
        guid::member_binding(
            provider,
            revision,
            slot,
            path,
            crate::redundancy::slot_service_name(slot, transport),
        )
        .map_err(|_| Error::Invalid)
    };
    let context = Context {
        intent: Intent {
            scope: scope.clone(),
            addresses: rendered.addresses,
        },
        provenance: provenance.clone(),
        bindings: [
            Binding {
                role: Role::RoleCarrier,
                guid: carrier.guid,
                name: carrier.name,
                registry_path: format!(
                    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{{text}}}"
                ),
            },
            member(TunnelSlot::A, paths[0])?,
            member(TunnelSlot::B, paths[1])?,
        ],
    };
    crate::member_carrier_native_ownership::validate_context(&context)?;
    Ok(context)
}

/// Configuration comparison only. Cold primary uses the original command;
/// live reserve may use its own endpoint/key but not another carrier address,
/// provider or caller-edited addressless native rendering.
fn compare_member_text(
    context: &Context,
    transport: TunnelTransport,
    cold_primary: Option<&str>,
    logical: &str,
    native: &str,
) -> Result<()> {
    if cold_primary.is_some_and(|original| original != logical)
        || nelomai_client_tunnel::detect_configuration_transport(logical) != transport
    {
        return Err(Error::Conflict);
    }
    crate::member_pair::MemberParameters::parse(logical).map_err(|_| Error::Invalid)?;
    let rendered = crate::redundancy::pair_configuration(logical).map_err(|_| Error::Invalid)?;
    if rendered.addresses != context.intent.addresses || rendered.native.as_str() != native {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) mod native {
    #[cfg(test)]
    use super::super::member_carrier_factory_test_os::trace_step;
    use super::*;
    use crate::{
        member_carrier_pair as pair,
        windows::{
            member_carrier_assembly::native::{
                NativeAssemblyModuleOnlyRead, NativeAssemblySlot, NativeAssemblyTerminalResources,
                NativeInitialAssemblyNoCRead,
            },
            member_carrier_assembly::{
                drain_before_postflight, transfer_terminal_slot, TerminalResources,
            },
            member_carrier_creator::native::CapturedCreator,
            member_carrier_creators::Observer,
            member_carrier_guard_attestor::native::{NativeGuardAttestor, NativeGuardSelection},
            member_carrier_guard_gate::native::{
                NativeGuardResourceSelection, NativeResourceGuardGate,
            },
            member_carrier_key_authority::{KeyLock, KeyLockPin, RuntimeRead},
            member_carrier_lifecycle_gate::native::{
                FullNativeLifecycleGate, NativeLifecycleSelection,
            },
            member_carrier_member_controller::native::NativeMemberAttachment,
            member_carrier_member_controller::native::{
                NativeNeverMemberEffectInputs, NativeNeverMemberEffects, NativePreparedMember,
                NativePreparedMemberInputs, NativeRetiredMemberRoots,
            },
            member_carrier_member_gate::native::{NativeMemberGate, NativeMemberGateInputs},
            member_carrier_members::native::MemberInventoryRead,
            member_carrier_module::native::OriginalImage,
            member_carrier_network::native::NativeNetworkRead,
            member_carrier_network_baseline::native::{
                NativeNetworkBaselineRead, NativeNetworkBaselineRoot,
            },
            member_carrier_network_gate::native::NativeNetworkGate,
            member_carrier_network_owner::native::{
                NativeCarrierNetworkOwner, NativeNetworkAckRead,
            },
            member_carrier_pair_io::native::{
                self as actor, NativeActorInputs, NativeAttemptedTerminalProof,
                NativeLiveMemberPreparation, NativeStartup, NativeStartupTerminalBranch,
                NativeZeroEffectTerminalProof,
            },
            member_carrier_pair_store::native_store::{
                NativeCarrierPairStore, NativePairIntentRead,
            },
            member_carrier_payload::native::{MemberSource, WintunSource},
            member_carrier_probe_gate::native::NativeProbeResourceState,
            member_carrier_probes::native::ProbeInventory,
            member_carrier_ready::native::{
                NativeCarrierPins, NativeCarrierRoot, NativeCarrierTerminalResources,
                PrepublicationTerminalRead,
            },
            member_carrier_runtime::native::{NativeLifecycleGate, NativeResourceRowsRead},
            member_carrier_wintun::native::OriginalWintun,
            member_native_deadline::NativeDeadline,
            member_session::{
                InitialDataRetirementAck, InitialNativeDataRead, NativeSessionFiles,
                OriginalInitialNativeDataRetirement, ProtectedRecoveryRecords, RecordKind,
                SessionFiles, WindowsCarrierGuardStore, WindowsNativeCarrierReceiptStore,
                WindowsNativeCreatorStore,
            },
        },
    };
    use nelomai_contracts::dispatcher::MutationGuard;
    use std::{
        cell::RefCell,
        path::PathBuf,
        rc::Rc,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };
    use zeroize::Zeroizing;

    /// Before-C owning state, retained by the same serialized actor. Readonly
    /// preparation does not invent C/Source, native ACKs or future Pair records.
    /// Loaded module/key/carrier outputs remain inside assembly/carrier slots.
    pub(crate) struct NativeStartupRoot {
        context: Context,
        runtime: Rc<RuntimeRead>,
        creator: Option<Rc<CapturedCreator>>,
        creator_store: Option<WindowsNativeCreatorStore<NativeSessionFiles>>,
        lock: Option<KeyLock>,
        files: NativeSessionFiles,
        store: Rc<RefCell<NativeCarrierPairStore>>,
        source: Rc<WintunSource>,
        member_source: Rc<MemberSource>,
        engine: PathBuf,
        logical: Zeroizing<String>,
        supervisor: Rc<NativeDeadline>,
        cancelled: Arc<AtomicBool>,
        prepared: [Option<NativePreparedMember>; 2],
        never_effects: Option<Rc<NativeNeverMemberEffects>>,
        assembly: Option<NativeAssemblySlot>,
        initial_noc: Option<Rc<NativeInitialAssemblyNoCRead>>,
        initial_data_retirement: Option<Rc<NativeNoCInitialDataRetirement>>,
        initial_cleanup_attempted: bool,
        pre_pair_cleanup_attempted: bool,
        pre_pair_cleanup: Rc<TerminalCallState>,
        pre_pair_terminal: Option<Rc<NativeStartupPrePairTerminal>>,
        pre_pair_outcome: Option<Rc<NativePrePairOutcome>>,
        carrier: Option<NativeCarrierRoot<'static>>,
        pins: Option<NativeCarrierPins>,
        proof: Option<crate::member_owner::InterfaceProof>,
        create_attempted: bool,
        graph: Rc<RefCell<GraphSlot>>,
        attach_attempted: bool,
        terminal_attempted: bool,
        birth_attempted: bool,
        live_preparation: Rc<std::cell::Cell<LivePreparationState>>,
        retired_members: Option<Vec<NativeRetiredMemberRoots<actor::MemberGate>>>,
        zero_effect_terminal: Option<Rc<NativeStartupZeroEffectTerminal>>,
        zero_effect_outcome: Option<Rc<NativeZeroEffectOutcome>>,
        zero_effect_terminal_attempted: bool,
        invocation: Rc<StartupInvocationLedger>,
        terminal_selection: Rc<crate::windows::member_carrier_terminal_release::TerminalCallState>,
        attempted_terminal: Option<Rc<NativeStartupAttemptedTerminal>>,
        terminal_keys_call: Rc<crate::windows::member_carrier_terminal_release::TerminalCallState>,
        terminal_key_closes: [Option<Rc<crate::windows::member_carrier_keys::KeyHandleClosed>>; 3],
        module_only_candidate: Option<Rc<NativeStartupModuleOnlyCandidate>>,
        module_only_selection: Rc<TerminalCallState>,
        module_only_cleanup_read_calls: [RefCell<Vec<Rc<TerminalCallState>>>; 14],
        module_only_load_read: RefCell<Option<Rc<crate::windows::member_carrier_module::native::NativeOriginalModuleLoadRead>>>,
        module_only_native_read: RefCell<Option<Rc<crate::windows::member_carrier_module_terminal_read::native::NativeModuleOnlyTerminalRead>>>,
        module_only_cleanup_native_reads: RefCell<[Vec<Option<Rc<crate::windows::member_carrier_module_terminal_read::native::NativeModuleOnlyTerminalRead>>>; 14]>,
        module_only_release: Option<Rc<NativeNoConstructorReleaseRoot>>,
        module_only_outcome: Option<Rc<NativeModuleOnlyOutcome>>,
    }
    /// Original lineage/caller-retention aperture, NOT native load ACK or SDK
    /// permission. The finisher additionally requires actual loader disposition.
    pub(crate) struct NativeStartupModuleOnlyCandidate {
        invocation: Rc<StartupInvocationLedger>,
        creator: Rc<CapturedCreator>,
        pair: Rc<NativePairIntentRead>,
        expected: pair::Record,
        runtime: Rc<RuntimeRead>,
        source: Rc<WintunSource>,
        supervisor: Rc<NativeDeadline>,
        graph: Rc<RefCell<GraphSlot>>,
        selection: Rc<TerminalCallState>,
        assembly: RefCell<Option<Rc<NativeAssemblyModuleOnlyRead>>>,
    }
    /// Borrowed original roots for ONE bounded factual read. Only the owning
    /// Startup constructs this aperture; it carries no imported ACK/permission.
    pub(crate) struct NativeModuleOnlyReadEntry<'a> {
        startup: &'a NativeStartupRoot,
        candidate: &'a Rc<NativeStartupModuleOnlyCandidate>,
        load: &'a Rc<crate::windows::member_carrier_module::native::NativeOriginalModuleLoadRead>,
        pair: &'a Rc<NativePairIntentRead>,
        expected: &'a pair::Record,
    }
    impl NativeModuleOnlyReadEntry<'_> {
        pub(crate) fn context(&self) -> &Context {
            &self.startup.context
        }
        pub(crate) fn verify(&self, supervisor: &NativeDeadline) -> Result<()> {
            self.startup.verify_module_only_reader_entry(
                supervisor,
                self.candidate,
                self.load,
                self.pair,
                self.expected,
            )
        }
    }
    impl NativeStartupModuleOnlyCandidate {
        /// Detached SAME original roots: enables readonly pre-release checks
        /// while the owning Assembly is mutably borrowed. The private actual
        /// revocation seal, not copied flags/JSON, supplies constructor lineage.
        pub(crate) fn verify_read_origin_in_call(
            &self,
            pair: &NativePairIntentRead,
            expected: &pair::Record,
        ) -> Result<()> {
            self.verify_read_origin(pair, expected)?;
            let bootstrap = self.assembly()?.bootstrap()?;
            let input = bootstrap.original_inputs();
            input
                .deadline
                .verify_runtime(input.supervisor, input.runtime, input.context)?;
            input
                .deadline
                .verify_call(input.supervisor, input.context)?;
            pair.verify_module_only_read_bracket(
                input.runtime,
                input.supervisor,
                input.context,
                expected,
            )
            .map_err(|_| Error::Conflict)
        }
        fn verify_read_origin(
            &self,
            pair: &NativePairIntentRead,
            expected: &pair::Record,
        ) -> Result<()> {
            self.selection.verify().map_err(|_| Error::Retired)?;
            self.invocation.attempted(true, false)?;
            self.graph
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .require_pristine()?;
            let assembly = self.assembly()?;
            assembly.verify_no_constructor_seal()?;
            let bootstrap = assembly.bootstrap()?;
            let input = bootstrap.original_inputs();
            // Bootstrap retains read_pin(), whose wrapper has a new address.
            // Authenticate its SAME original runtime Rc and serialized lease,
            // not equality of context metadata or wrapper storage addresses.
            if !input.runtime.same_original_runtime(self.runtime.as_ref())
                || !Rc::ptr_eq(input.source, &self.source)
                || !Rc::ptr_eq(input.supervisor, &self.supervisor)
                || !pair.same_store_origin(&self.pair)
            {
                return Err(Error::Conflict);
            }
            compare_module_only_read_progress(input.context, &self.expected, expected)?;
            // Entry can be idle after a normally returned forward Err. The
            // original revoked pin is valid only INSIDE cleanup Calling; keep
            // that pin check in verify_read_origin_in_call. Entry authenticates
            // the SAME supervisor/runtime/lease through its cleanup-only gate.
            input
                .supervisor
                .verify_cleanup_runtime_entry(input.runtime, input.context)?;
            input
                .runtime
                .verify_same_session_files(input.context, input.files)?;
            input.runtime.verify_source(input.source)
        }
        pub(crate) fn verify_original_creator_in_call(
            &self,
            pair: &NativePairIntentRead,
            expected: &pair::Record,
            observed: &[u8],
        ) -> Result<()> {
            self.verify_read_origin_in_call(pair, expected)?;
            let bootstrap = self.assembly()?.bootstrap()?;
            let input = bootstrap.original_inputs();
            if input
                .runtime
                .record(input.context, RecordKind::NativeCreator)?
                .as_slice()
                != observed
            {
                return Err(Error::Conflict);
            }
            // Creator captured THIS original RuntimeRead allocation. The
            // bootstrap's read_pin() shares its authenticated backing/lease
            // (verified above), but cannot replace the publisher's original Rc.
            self.creator
                .verify_published_read(self.runtime.as_ref(), input.context, observed)
                .map_err(|_| Error::Conflict)?;
            self.verify_read_origin_in_call(pair, expected)?;
            if input
                .runtime
                .record(input.context, RecordKind::NativeCreator)?
                .as_slice()
                != observed
            {
                return Err(Error::Conflict);
            }
            Ok(())
        }
        pub(crate) fn assembly(&self) -> Result<Rc<NativeAssemblyModuleOnlyRead>> {
            self.selection.verify().map_err(|_| Error::Retired)?;
            self.assembly
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .as_ref()
                .cloned()
                .ok_or(Error::Pending)
        }
    }

    /// Caller-retained original release attempt. ACK is OUTSIDE the supplier
    /// to avoid a proof->ACK->proof cycle. No DLL/DATA effect in Drop.
    struct NativeNoConstructorReleaseRoot {
        proof: Rc<NativeNoConstructorReleaseProof>,
        ack: RefCell<
            Option<
                crate::windows::member_carrier_module::native::NativeNoConstructorModuleReleased<
                    NativeNoConstructorReleaseProof,
                >,
            >,
        >,
        whole: TerminalCallState,
        disposal: TerminalCallState,
        bootstrap_raw: RefCell<
            crate::windows::member_carrier_bootstrap::native::NativeBootstrapTerminalResources,
        >,
    }
    /// Issued ONLY after the SAME original loader's whole ACK AND canonical
    /// Startup owning disposition. No constructor/NativeC/Never substitution.
    pub(crate) struct NativeModuleOnlyOutcome {
        original: Rc<NativeNoConstructorReleaseRoot>,
    }
    impl NativeModuleOnlyOutcome {
        pub(crate) fn verify_supervisor_terminal_drop(
            &self,
            supervisor: &NativeDeadline,
        ) -> Result<()> {
            let root = &self.original;
            root.whole.verify().map_err(|_| Error::Retired)?;
            root.disposal.verify().map_err(|_| Error::Retired)?;
            let input = root.proof.bootstrap.original_inputs();
            if !std::ptr::eq(input.supervisor.as_ref(), supervisor)
                || root
                    .ack
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .is_none()
                || module_only_read_stage(&root.proof.expected)? != 13
            {
                return Err(Error::Conflict);
            }
            root.proof
                .candidate
                .selection
                .verify()
                .map_err(|_| Error::Retired)?;
            root.proof
                .candidate
                .assembly()?
                .verify_no_constructor_seal()?;
            root.proof
                .bootstrap
                .original_initial_data_read()
                .map(|_| ())
        }
    }
    pub(crate) struct NativeNoConstructorReleaseProof {
        candidate: Rc<NativeStartupModuleOnlyCandidate>,
        load: Rc<crate::windows::member_carrier_module::native::NativeOriginalModuleLoadRead>,
        pair: Rc<NativePairIntentRead>,
        expected: pair::Record,
        bootstrap: Rc<crate::windows::member_carrier_bootstrap::native::NativeBootstrapModuleOnlyRead>,
        reader: Rc<crate::windows::member_carrier_module_terminal_read::native::NativeModuleOnlyTerminalRead>,
        lock: KeyLockPin,
    }
    impl NativeNoConstructorReleaseProof {
        pub(crate) fn context(&self) -> &Context {
            self.bootstrap.original_inputs().context
        }
        /// Before/after outer Calling: SAME actual retained roots/current Pair,
        /// but no image queries and no successful-native-return inference.
        pub(crate) fn verify_entry(&self, supervisor: &NativeDeadline) -> Result<()> {
            self.verify_origins(supervisor)?;
            let input = self.bootstrap.original_inputs();
            self.pair
                .verify_module_only_read_entry(input.runtime, input.context, &self.expected)
                .map_err(|_| Error::Conflict)
        }
        fn verify_origins(&self, supervisor: &NativeDeadline) -> Result<()> {
            let input = self.bootstrap.original_inputs();
            if !std::ptr::eq(input.supervisor.as_ref(), supervisor)
                || module_only_read_stage(&self.expected)? != 13
                || !input.runtime.matches_pin(&self.lock)
                || !self.load.matches_runtime(input.runtime)
                || !self.load.matches_source(input.source)
                || !self.reader.matches_original(
                    &self.candidate,
                    &self.load,
                    &self.pair,
                    &self.expected,
                )
                || !Rc::ptr_eq(&self.candidate.assembly()?.bootstrap()?, &self.bootstrap)
            {
                return Err(Error::Conflict);
            }
            self.candidate
                .verify_read_origin(&self.pair, &self.expected)?;
            supervisor.verify_cleanup_runtime_entry(input.runtime, input.context)?;
            self.lock
                .verify_source(input.source)
                .map_err(|_| Error::Conflict)
        }
        fn verify_call(&self) -> Result<()> {
            // The SAME Pair inspect frame is already active. Entry would begin
            // another PairIntentCall and revoke that original on reentry. Keep
            // every origin check, then validate the actual in-call bracket.
            self.verify_origins(self.bootstrap.original_inputs().supervisor)?;
            self.candidate
                .verify_read_origin_in_call(&self.pair, &self.expected)
        }
    }
    // SAFETY: issued only by SAME actual Startup/Assembly successful loader
    // owner below. Private no-constructor revocation seal/current original Pair
    // are reauthenticated on both sides. Pre executes the FULL original native
    // read (all SDK/private/services/keys + two scoped BFE snapshots) inside the
    // actual loader's irreversible pre aperture and SAME bounded Calling.
    // Post reads only protected/original journal/creator/source/Calling, never
    // image/SDK after FreeLibrary. Whole watchdog completion is required by the
    // owning release root; this supplier/ACK cannot itself retire DATA/session.
    unsafe impl crate::windows::member_carrier_module::native::NativeNoConstructorModuleReleaseProof
        for NativeNoConstructorReleaseProof
    {
        fn pre_release(
            &self,
            original: &crate::windows::member_carrier_module::native::NativeOriginalModuleLoadRead,
        ) -> crate::windows::member_carrier_module::Result<()> {
            if !self.load.same_original(original) {
                return Err(crate::windows::member_carrier_module::Error::Conflict);
            }
            self.verify_call()
                .map_err(|_| crate::windows::member_carrier_module::Error::Conflict)?;
            self.reader
                .read_in_release_pre_call(&self.lock)
                .map_err(|_| crate::windows::member_carrier_module::Error::Conflict)?;
            self.verify_call()
                .map_err(|_| crate::windows::member_carrier_module::Error::Conflict)
        }
        fn post_release(
            &self,
            original: &crate::windows::member_carrier_module::native::NativeOriginalModuleLoadRead,
        ) -> crate::windows::member_carrier_module::Result<()> {
            if !self.load.same_original(original) {
                return Err(crate::windows::member_carrier_module::Error::Conflict);
            }
            self.verify_call()
                .map_err(|_| crate::windows::member_carrier_module::Error::Conflict)?;
            self.reader
                .verify_release_post_in_call(&self.lock)
                .map_err(|_| crate::windows::member_carrier_module::Error::Conflict)?;
            self.verify_call()
                .map_err(|_| crate::windows::member_carrier_module::Error::Conflict)
        }
    }

    // Factual discriminator only: no owning Runtime/SDK/module/KeyLock aliases.
    // Startup retains the private invocation and completion roots until its
    // original owning disposition has completed; witnesses cannot extend them.
    struct NativeStartupAttemptedTerminal {
        invocation: std::rc::Weak<StartupInvocationLedger>,
        create: bool,
        attach: bool,
        selection:
            std::rc::Weak<crate::windows::member_carrier_terminal_release::TerminalCallState>,
        pair: std::rc::Weak<NativePairIntentRead>,
        expected: pair::Record,
        graph: std::rc::Weak<RefCell<GraphSlot>>,
        layout: NativeAttemptedTerminalLayout,
        retired: Option<
            std::rc::Weak<crate::windows::member_carrier_runtime::native::RetiredCarrierRead>,
        >,
    }
    impl NativeStartupAttemptedTerminal {
        /// PURE discriminator, not SDK absence/resource/unload permission.
        /// Main's actor forwards the mandatory attempted-proof/witness API.
        fn original_layout(
            &self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<NativeAttemptedTerminalLayout> {
            self.verify_original(original, expected)?;
            let graph = self.graph.upgrade().ok_or(Error::Retired)?;
            let graph = graph.try_borrow().map_err(|_| Error::Conflict)?;
            let published = self
                .retired
                .as_ref()
                .map(|r| r.upgrade().ok_or(Error::Retired))
                .transpose()?
                .is_some();
            let invocation = self.invocation.upgrade().ok_or(Error::Retired)?;
            let layout = classify_attempted_layout(
                &invocation,
                self.create,
                self.attach,
                graph.construction_attempted.get(),
                published,
            )?;
            if layout != self.layout {
                return Err(Error::Conflict);
            }
            Ok(layout)
        }
    }
    // SAFETY: minted solely from actual create/attach entry, not returned
    // objects or record data. The SAME whole Stopped/Calling postflight must
    // complete before this pure weak witness can be observed as acknowledged.
    unsafe impl NativeAttemptedTerminalProof for NativeStartupAttemptedTerminal {
        fn original_layout(
            &self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<NativeAttemptedTerminalLayout> {
            NativeStartupAttemptedTerminal::original_layout(self, original, expected)
        }
        fn verify_original(
            &self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<()> {
            self.selection
                .upgrade()
                .ok_or(Error::Retired)?
                .verify()
                .map_err(|_| Error::Retired)?;
            let invocation = self.invocation.upgrade().ok_or(Error::Retired)?;
            if !invocation.attempted(self.create, self.attach)?
                || !self
                    .pair
                    .upgrade()
                    .is_some_and(|same| Rc::ptr_eq(&same, original))
                || &self.expected != expected
            {
                return Err(Error::Conflict);
            }
            Ok(())
        }
    }

    // Minted ONLY by this original Startup after its private Never ledger and
    // whole native terminal read. Owning aliases are rooted before the external
    // callback; no Source/image/module capability exists or is manufactured.
    struct NativeStartupZeroEffectTerminal {
        pair: Rc<NativePairIntentRead>,
        expected: pair::Record,
        configuration: NoCarrierConfiguration,
        context: Context,
        runtime: Rc<RuntimeRead>,
        source: Rc<WintunSource>,
        member_source: Rc<MemberSource>,
        supervisor: Rc<NativeDeadline>,
        never: Rc<NativeNeverMemberEffects>,
        initial_noc: Rc<NativeInitialAssemblyNoCRead>,
        graph: Rc<RefCell<GraphSlot>>,
        store: Rc<RefCell<NativeCarrierPairStore>>,
        whole: crate::windows::member_carrier_terminal_release::TerminalCallState,
        disposal: crate::windows::member_carrier_terminal_release::TerminalCallState,
    }
    /// Actual completed Startup-Never read + owning raw-disposal outcome.
    /// No import/data constructor, module ACK, SDK permit or forward lifetime.
    /// Main's actor still must acknowledge its SAME I/J/local disposition.
    pub(crate) struct NativeZeroEffectOutcome {
        original: Rc<NativeStartupZeroEffectTerminal>,
    }
    /// Actual original pre-Pair lane. No Pair or future record is constructed.
    /// All originals/output slots are retained BEFORE read/drain/disposal.
    struct NativeStartupPrePairTerminal {
        context: Context,
        runtime: Rc<RuntimeRead>,
        source: Rc<WintunSource>,
        member_source: Rc<MemberSource>,
        supervisor: Rc<NativeDeadline>,
        creator: Rc<CapturedCreator>,
        never: Rc<NativeNeverMemberEffects>,
        initial: Rc<NativeInitialAssemblyNoCRead>,
        graph: Rc<RefCell<GraphSlot>>,
        store: Rc<RefCell<NativeCarrierPairStore>>,
        raw: Rc<RefCell<TerminalStartupResources<'static>>>,
        whole: TerminalCallState,
        disposal: TerminalCallState,
    }
    pub(crate) struct NativePrePairOutcome {
        original: Rc<NativeStartupPrePairTerminal>,
    }
    impl NativeStartupPrePairTerminal {
        fn read(&self, lock: &KeyLock) -> Result<()> {
            // SAFETY: actual original Never/initial journal, held lock and
            // bounded Calling bracket surround full read-only native checks.
            unsafe {
                self.supervisor.run_pre_pair_terminal_read(
                    &self.context,
                    &self.initial,
                    &self.never,
                    || {
                        self.never.verify_pre_pair_absent(&self.initial, lock)?;
                        let bytes = self
                            .runtime
                            .record(&self.context, RecordKind::NativeCreator)?;
                        self.creator
                            .verify_published_read(&self.runtime, &self.context, &bytes)
                            .map_err(|_| Error::Conflict)?;
                        let mut guard =
                            crate::windows::member_carrier_guard::ScopedGuardAbsence::open(
                                self.context.intent.scope.clone(),
                            )
                            .map_err(|_| Error::Conflict)?;
                        let before = guard
                            .read_snapshot(&self.context.intent.scope)
                            .map_err(|_| Error::Conflict)?;
                        compare_uncaptured_terminal_snapshot(&self.context.intent.scope, &before)?;
                        self.never.verify_pre_pair_absent(&self.initial, lock)?;
                        if guard
                            .read_snapshot(&self.context.intent.scope)
                            .map_err(|_| Error::Conflict)?
                            != before
                            || self
                                .runtime
                                .record(&self.context, RecordKind::NativeCreator)?
                                != bytes
                        {
                            return Err(Error::Conflict);
                        }
                        self.creator
                            .verify_published_read(&self.runtime, &self.context, &bytes)
                            .map_err(|_| Error::Conflict)
                    },
                )
            }
        }
    }
    impl NativePrePairOutcome {
        pub(crate) fn verify_supervisor_terminal_drop(
            &self,
            supplied: &NativeDeadline,
        ) -> Result<()> {
            verify_zero_effect_rundown(
                &self.original.supervisor,
                supplied,
                &self.original.whole,
                &self.original.disposal,
            )?;
            self.original
                .initial
                .verify_ready(&self.original.runtime, &self.original.context)
        }
    }
    /// Deferred SDK-free DATA retirement. Before NoC selection it owns only
    /// a weak source only, so normal-C cannot retain its
    /// Runtime through this handle. A completed NoC outcome is rooted before
    /// binding postflight and kept across retirement Err/unwind/lost ACK.
    pub(crate) struct NativeNoCInitialDataRetirement {
        source: std::rc::Weak<NativeInitialAssemblyNoCRead>,
        data: RefCell<Option<InitialNativeDataRead>>,
        outcome: RefCell<Option<Rc<NativeZeroEffectOutcome>>>,
        module_outcome: RefCell<Option<Rc<NativeModuleOnlyOutcome>>>,
        pre_pair_outcome: RefCell<Option<Rc<NativePrePairOutcome>>>,
        binding: TerminalCallState,
        retirement: TerminalCallState,
        begun: std::cell::Cell<bool>,
        failed: std::cell::Cell<bool>,
        ack: RefCell<Option<Rc<InitialDataRetirementAck>>>,
    }
    impl NativeNoCInitialDataRetirement {
        fn new(source: &Rc<NativeInitialAssemblyNoCRead>) -> Self {
            Self {
                source: Rc::downgrade(source),
                data: RefCell::new(None),
                outcome: RefCell::new(None),
                module_outcome: RefCell::new(None),
                pre_pair_outcome: RefCell::new(None),
                binding: TerminalCallState::new(),
                retirement: TerminalCallState::new(),
                begun: std::cell::Cell::new(false),
                failed: std::cell::Cell::new(false),
                ack: RefCell::new(None),
            }
        }
        fn original_data(&self) -> Result<InitialNativeDataRead> {
            self.data
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .as_ref()
                .cloned()
                .ok_or(Error::Pending)
        }
        fn bind_pre_pair_completed(&self, outcome: Rc<NativePrePairOutcome>) -> Result<()> {
            bind_initial_data_outcome(&self.pre_pair_outcome, &self.binding, outcome, |actual| {
                if self
                    .outcome
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .is_some()
                    || self
                        .module_outcome
                        .try_borrow()
                        .map_err(|_| Error::Conflict)?
                        .is_some()
                {
                    return Err(Error::Conflict);
                }
                let source = self.source.upgrade().ok_or(Error::Retired)?;
                if !Rc::ptr_eq(&source, &actual.original.initial) {
                    return Err(Error::Conflict);
                }
                let original = source.original_initial_data_read()?;
                let mut data = self.data.try_borrow_mut().map_err(|_| Error::Conflict)?;
                if data.is_some() {
                    return Err(Error::Conflict);
                }
                *data = Some(original); // actual original DATA retained before postflight
                drop(data);
                actual.verify_supervisor_terminal_drop(&actual.original.supervisor)
            })
        }
        pub(crate) fn completed_pre_pair(&self) -> Result<bool> {
            let slot = self
                .pre_pair_outcome
                .try_borrow()
                .map_err(|_| Error::Conflict)?;
            let Some(outcome) = slot.as_ref() else {
                return Ok(false);
            };
            self.verify_completed(&self.original_data()?)
                .map_err(|_| Error::Retired)?;
            outcome.verify_supervisor_terminal_drop(&outcome.original.supervisor)?;
            Ok(true)
        }
        fn bind_completed(&self, outcome: Rc<NativeZeroEffectOutcome>) -> Result<()> {
            bind_initial_data_outcome(&self.outcome, &self.binding, outcome, |actual| {
                let source = self.source.upgrade().ok_or(Error::Retired)?;
                // FIRST actual DATA identity comes from the already selected
                // original cleanup J, never from the unborn constructor view.
                let original = source.original_initial_data_read()?;
                let mut slot = self.data.try_borrow_mut().map_err(|_| Error::Conflict)?;
                if slot.is_some() {
                    return Err(Error::Conflict);
                }
                *slot = Some(original); // retained BEFORE binding postflight
                drop(slot);
                let data = self.original_data()?;
                if !Rc::ptr_eq(&source, &actual.original.initial_noc)
                    || !data.same_original(&source.original_initial_data_read()?)
                {
                    return Err(Error::Conflict);
                }
                actual.verify_supervisor_terminal_drop(&actual.original.supervisor)
            })
        }
        fn bind_module_completed(&self, outcome: Rc<NativeModuleOnlyOutcome>) -> Result<()> {
            bind_initial_data_outcome(&self.module_outcome, &self.binding, outcome, |actual| {
                if self
                    .outcome
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .is_some()
                {
                    return Err(Error::Conflict);
                }
                let original = actual
                    .original
                    .proof
                    .bootstrap
                    .original_initial_data_read()?;
                let mut data = self.data.try_borrow_mut().map_err(|_| Error::Conflict)?;
                if data.is_some() {
                    return Err(Error::Conflict);
                }
                *data = Some(original);
                drop(data);
                actual.verify_supervisor_terminal_drop(
                    actual.original.proof.bootstrap.original_inputs().supervisor,
                )
            })
        }
        fn verify_completed(&self, original: &InitialNativeDataRead) -> std::io::Result<()> {
            let denied = || std::io::Error::other("initial_data_original_noc_outcome");
            let data = self.original_data().map_err(|_| denied())?;
            if self.failed.get()
                || !data.same_original(original)
                || data.acknowledged() != original.acknowledged()
            {
                return Err(denied());
            }
            self.binding.verify()?;
            let pre = self.pre_pair_outcome.try_borrow().map_err(|_| denied())?;
            if let Some(outcome) = pre.as_ref() {
                if self.outcome.try_borrow().map_err(|_| denied())?.is_some()
                    || self
                        .module_outcome
                        .try_borrow()
                        .map_err(|_| denied())?
                        .is_some()
                {
                    return Err(denied());
                }
                let source = self.source.upgrade().ok_or_else(denied)?;
                if !Rc::ptr_eq(&source, &outcome.original.initial)
                    || !data
                        .same_original(&source.original_initial_data_read().map_err(|_| denied())?)
                {
                    return Err(denied());
                }
                return outcome
                    .verify_supervisor_terminal_drop(&outcome.original.supervisor)
                    .map_err(|_| denied());
            }
            let module = self.module_outcome.try_borrow().map_err(|_| denied())?;
            if let Some(outcome) = module.as_ref() {
                if self.outcome.try_borrow().map_err(|_| denied())?.is_some()
                    || !data.same_original(
                        &outcome
                            .original
                            .proof
                            .bootstrap
                            .original_initial_data_read()
                            .map_err(|_| denied())?,
                    )
                {
                    return Err(denied());
                }
                return outcome
                    .verify_supervisor_terminal_drop(
                        outcome
                            .original
                            .proof
                            .bootstrap
                            .original_inputs()
                            .supervisor,
                    )
                    .map_err(|_| denied());
            }
            let slot = self.outcome.try_borrow().map_err(|_| denied())?;
            let outcome = slot.as_ref().ok_or_else(denied)?;
            let source = self.source.upgrade().ok_or_else(denied)?;
            if !Rc::ptr_eq(&source, &outcome.original.initial_noc)
                || !data.same_original(&source.original_initial_data_read().map_err(|_| denied())?)
            {
                return Err(denied());
            }
            outcome
                .verify_supervisor_terminal_drop(&outcome.original.supervisor)
                .map_err(|_| denied())
        }
        /// Call ONLY after actual SessionStopped CAS, before files.complete.
        /// No SDK/Runtime/Pair inspection; SAME original private store performs
        /// full before/after protected DATA checks and retains its actual ACK.
        pub(crate) fn retire(&self) -> Result<()> {
            self.retirement
                .run(|| {
                    let data = self
                        .original_data()
                        .map_err(|_| std::io::Error::other("initial_data_missing"))?;
                    self.verify_completed(&data)?;
                    let retain = |ack| {
                        let mut slot = self
                            .ack
                            .try_borrow_mut()
                            .map_err(|_| std::io::Error::other("initial_data_ack_busy"))?;
                        if slot.is_some() {
                            return Err(std::io::Error::other("initial_data_duplicate_ack"));
                        }
                        *slot = Some(ack); // root actual ACK BEFORE store postflight
                        Ok(())
                    };
                    let module = self
                        .module_outcome
                        .try_borrow()
                        .map_err(|_| std::io::Error::other("initial_data_module_busy"))?;
                    match module.as_ref() {
                        Some(outcome) => outcome
                            .original
                            .proof
                            .bootstrap
                            .retire_original_initial_data(self, retain),
                        None => self
                            .source
                            .upgrade()
                            .ok_or_else(|| std::io::Error::other("initial_data_source"))?
                            .retire_original_initial_data(self, retain),
                    }
                    .map_err(|_| std::io::Error::other("initial_data_store_retirement"))?;
                    drop(module);
                    let ack = self
                        .ack
                        .try_borrow()
                        .map_err(|_| std::io::Error::other("initial_data_ack_busy"))?;
                    if ack.as_ref().is_none_or(|ack| !ack.matches_original(&data)) {
                        return Err(std::io::Error::other("initial_data_ack_original"));
                    }
                    self.verify_completed(&data)
                })
                .map_err(|_| Error::Retired)
        }
        /// After retire AND ordinary private completion. Exact native/store
        /// ACKs, not a caller phase or success boolean, allow these alias drops.
        pub(crate) fn release_retired_originals(&self) -> Result<()> {
            self.retirement.verify().map_err(|_| Error::Retired)?;
            let data = self.original_data()?;
            self.verify_completed(&data).map_err(|_| Error::Retired)?;
            // Acquire every destination before cutting any original. A busy
            // alias/error must not partially drop the acknowledged outcome.
            let mut ack = self.ack.try_borrow_mut().map_err(|_| Error::Conflict)?;
            let mut held_data = self.data.try_borrow_mut().map_err(|_| Error::Conflict)?;
            let mut outcome = self.outcome.try_borrow_mut().map_err(|_| Error::Conflict)?;
            let mut module = self
                .module_outcome
                .try_borrow_mut()
                .map_err(|_| Error::Conflict)?;
            let mut pre = self
                .pre_pair_outcome
                .try_borrow_mut()
                .map_err(|_| Error::Conflict)?;
            if ack.as_ref().is_none_or(|ack| !ack.matches_original(&data))
                || held_data
                    .as_ref()
                    .is_none_or(|held| !held.same_original(&data))
                || [outcome.is_some(), module.is_some(), pre.is_some()]
                    .into_iter()
                    .filter(|v| *v)
                    .count()
                    != 1
            {
                return Err(Error::Conflict);
            }
            outcome.take();
            module.take();
            pre.take();
            ack.take();
            held_data.take();
            Ok(())
        }
    }
    // SAFETY: no data import can construct this issuer. Both original source
    // and actual whole NoC disposal are sealed; callbacks are PURE, including
    // while the original journal/private backend is mutably borrowed.
    unsafe impl OriginalInitialNativeDataRetirement for NativeNoCInitialDataRetirement {
        fn begin_retirement(&self, original: &InitialNativeDataRead) -> std::io::Result<()> {
            if self.begun.replace(true) {
                self.failed.set(true);
                return Err(std::io::Error::other("initial_data_repeat"));
            }
            self.verify_completed(original)
        }
        fn verify_retirement(
            &self,
            original: &InitialNativeDataRead,
            current: &ProtectedRecoveryRecords,
        ) -> std::io::Result<()> {
            self.verify_completed(original)?;
            let pre = self
                .pre_pair_outcome
                .try_borrow()
                .map_err(|_| std::io::Error::other("initial_pre_pair_busy"))?;
            if pre.is_some() {
                return self.verify_absent_pair(original, current);
            }
            let slot = self
                .outcome
                .try_borrow()
                .map_err(|_| std::io::Error::other("initial_data_busy"))?;
            let module = self
                .module_outcome
                .try_borrow()
                .map_err(|_| std::io::Error::other("initial_data_module_busy"))?;
            let (context, expected) = match (slot.as_ref(), module.as_ref()) {
                (Some(outcome), None) => (&outcome.original.context, &outcome.original.expected),
                (None, Some(outcome)) => (
                    outcome.original.proof.bootstrap.original_inputs().context,
                    &outcome.original.proof.expected,
                ),
                _ => return Err(std::io::Error::other("initial_data_outcome")),
            };
            if current.changed_boot
                || current.scope != context.intent.scope
                || current.provenance != context.provenance
                || current.records.iter().map(|(kind, _)| *kind).ne([
                    RecordKind::Session,
                    RecordKind::Pair,
                    RecordKind::Network,
                    RecordKind::Carrier,
                    RecordKind::NativeCarrierReceipts,
                    RecordKind::CarrierRows,
                    RecordKind::MemberARows,
                    RecordKind::MemberBRows,
                    RecordKind::CarrierGuard,
                    RecordKind::NativeCreator,
                ])
            {
                return Err(std::io::Error::other("initial_data_context"));
            }
            let payload = |kind| {
                current
                    .records
                    .iter()
                    .find(|(k, _)| *k == kind)
                    .and_then(|(_, bytes)| bytes.as_deref())
            };
            let raw = payload(RecordKind::Pair)
                .ok_or_else(|| std::io::Error::other("initial_data_pair"))?;
            let crate::member_carrier_pair::CleanupRecord::Carrier(actual) =
                crate::windows::member_carrier_pair_store::decode_pair_payload(
                    &current.scope,
                    raw,
                )?
            else {
                return Err(std::io::Error::other("initial_data_pair"));
            };
            if actual.as_ref() != expected
                || crate::member_carrier_native_ownership::Record::decode(
                    payload(RecordKind::NativeCarrierReceipts)
                        .ok_or_else(|| std::io::Error::other("initial_data_ack"))?,
                )
                .map_err(|_| std::io::Error::other("initial_data_ack"))?
                    != *original.acknowledged()
            {
                return Err(std::io::Error::other("initial_data_current"));
            }
            // SessionStopped/all other effects/creator are independently and
            // strictly checked by original store require_initial_noc_records.
            self.verify_completed(original)
        }
        fn fail_retirement(&self) {
            self.failed.set(true);
        }
        fn verify_absent_pair(
            &self,
            original: &InitialNativeDataRead,
            current: &ProtectedRecoveryRecords,
        ) -> std::io::Result<()> {
            self.verify_completed(original)?;
            let slot = self
                .pre_pair_outcome
                .try_borrow()
                .map_err(|_| std::io::Error::other("initial_pre_pair_busy"))?;
            let outcome = slot
                .as_ref()
                .ok_or_else(|| std::io::Error::other("initial_pre_pair_outcome"))?;
            let context = &outcome.original.context;
            if current.changed_boot
                || current.scope != context.intent.scope
                || current.provenance != context.provenance
                || current.records.iter().map(|(kind, _)| *kind).ne([
                    RecordKind::Session,
                    RecordKind::Pair,
                    RecordKind::Network,
                    RecordKind::Carrier,
                    RecordKind::NativeCarrierReceipts,
                    RecordKind::CarrierRows,
                    RecordKind::MemberARows,
                    RecordKind::MemberBRows,
                    RecordKind::CarrierGuard,
                    RecordKind::NativeCreator,
                ])
            {
                return Err(std::io::Error::other("initial_pre_pair_context"));
            }
            let payload = |kind| {
                current
                    .records
                    .iter()
                    .find(|(k, _)| *k == kind)
                    .and_then(|(_, bytes)| bytes.as_deref())
            };
            if payload(RecordKind::Pair).is_some()
                || payload(RecordKind::NativeCreator).is_none()
                || crate::member_carrier_native_ownership::Record::decode(
                    payload(RecordKind::NativeCarrierReceipts)
                        .ok_or_else(|| std::io::Error::other("initial_pre_pair_ack"))?,
                )
                .map_err(|_| std::io::Error::other("initial_pre_pair_ack"))?
                    != *original.acknowledged()
            {
                return Err(std::io::Error::other("initial_pre_pair_current"));
            }
            // PURE inside the backend transaction; the original store also
            // requires SessionStopped and absence of every other native record.
            self.verify_completed(original)
        }
    }
    impl Drop for NativeNoCInitialDataRetirement {
        fn drop(&mut self) {
            if let Some(original) = self.pre_pair_outcome.get_mut().take() {
                std::mem::forget(original);
            }
            if let Some(original) = self.module_outcome.get_mut().take() {
                std::mem::forget(original);
            }
            if let Some(original) = self.outcome.get_mut().take() {
                // Explicit release_retired_originals empties this only after
                // actual completed retirement. Unknown Drop is not success.
                std::mem::forget(original);
            }
            if let Some(ack) = self.ack.get_mut().take() {
                std::mem::forget(ack);
            }
        }
    }
    impl NativeZeroEffectOutcome {
        /// PURE exact original/acknowledgment checks for final ProcessOwner
        /// bookkeeping only. The original whole call included SDK/private
        /// checks and positive watchdog rundown before disposal could complete.
        pub(crate) fn verify_supervisor_terminal_drop(
            &self,
            supervisor: &NativeDeadline,
        ) -> Result<()> {
            verify_zero_effect_rundown(
                &self.original.supervisor,
                supervisor,
                &self.original.whole,
                &self.original.disposal,
            )?;
            self.original
                .verify_original(&self.original.pair, &self.original.expected)
        }
    }
    // SAFETY: the private original is retained before SDK/callback/postflight.
    // Only a successful original full terminal read completes whole. This pure
    // comparison cannot issue native effects or certify current SDK absence.
    unsafe impl NativeZeroEffectTerminalProof for NativeStartupZeroEffectTerminal {
        fn verify_original(
            &self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<()> {
            self.whole.verify().map_err(|_| Error::Retired)?;
            if !Rc::ptr_eq(original, &self.pair)
                || expected != &self.expected
                || compare_zero_effect_terminal_record(&self.context, expected)?
                    != self.configuration
            {
                return Err(Error::Conflict);
            }
            self.initial_noc
                .verify_ready(&self.runtime, &self.context)?;
            Ok(())
        }
    }
    /// Caller-retained destination. Unknown Drop retains EVERYTHING, even when
    /// a later Graph borrow/check fails after Ready/Assembly have already moved.
    pub(crate) type TerminalStartupResources<'a> = TerminalResources<TerminalStartupRaw<'a>>;
    pub(crate) struct TerminalStartupRaw<'a> {
        // SAME private invocation/graph originals, not imported attempt flags.
        pregraph_invocation: Option<Rc<StartupInvocationLedger>>,
        pregraph_graph: Option<Rc<RefCell<GraphSlot>>>,
        pub(crate) carrier: Option<NativeCarrierTerminalResources<'a>>,
        pub(crate) assembly: Option<NativeAssemblyTerminalResources>,
        pub(crate) graph: Option<NativeGraphTerminalResources>,
        pub(crate) startup: Option<NativeStartupTerminalPins>,
        pub(crate) lock: RefCell<Option<KeyLock>>,
        pub(crate) prepared: [Option<NativePreparedMember>; 2],
        pub(crate) never_effects: Option<Rc<NativeNeverMemberEffects>>,
        pub(crate) pins: Option<NativeCarrierPins>,
        pub(crate) proof: Option<crate::member_owner::InterfaceProof>,
        pub(crate) retired_members: Option<Vec<NativeRetiredMemberRoots<actor::MemberGate>>>,
        pub(crate) terminal_keys_call:
            Option<Rc<crate::windows::member_carrier_terminal_release::TerminalCallState>>,
        pub(crate) terminal_key_closes:
            [Option<Rc<crate::windows::member_carrier_keys::KeyHandleClosed>>; 3],
    }
    /// SAME opaque base-owner aliases; never a recreated runtime/source/lock.
    pub(crate) struct NativeStartupTerminalPins {
        pub(crate) context: Context,
        pub(crate) runtime: Rc<RuntimeRead>,
        // Owning originals, not imported creator DATA or resource permission.
        creator: Option<Rc<CapturedCreator>>,
        creator_store: Option<WindowsNativeCreatorStore<NativeSessionFiles>>,
        initial_noc: Option<Rc<NativeInitialAssemblyNoCRead>>,
        initial_data_retirement: Option<Rc<NativeNoCInitialDataRetirement>>,
        pub(crate) files: NativeSessionFiles,
        pub(crate) store: Rc<RefCell<NativeCarrierPairStore>>,
        pub(crate) source: Rc<WintunSource>,
        pub(crate) member_source: Rc<MemberSource>,
        pub(crate) supervisor: Rc<NativeDeadline>,
        pub(crate) cancelled: Arc<AtomicBool>,
        pub(crate) engine: PathBuf,
        pub(crate) logical: Zeroizing<String>,
    }
    impl<'a> TerminalResources<TerminalStartupRaw<'a>> {
        pub(crate) fn empty() -> Self {
            Self::new(TerminalStartupRaw::empty())
        }
    }
    impl<'a> TerminalStartupRaw<'a> {
        /// Pure owning-origin check. The actual private invocation and exact
        /// graph transfer origin must survive the cut. This is not SDK absence
        /// or release permission; the terminal G separately joins all originals.
        pub(crate) fn verify_pregraph_original_cut(&self) -> Result<()> {
            let invocation = self.pregraph_invocation.as_ref().ok_or(Error::Pending)?;
            if !invocation.attempted(true, false)? {
                return Err(Error::Conflict);
            }
            let original = self
                .pregraph_graph
                .as_ref()
                .ok_or(Error::Pending)?
                .try_borrow()
                .map_err(|_| Error::Conflict)?;
            let raw = self.graph.as_ref().ok_or(Error::Pending)?;
            require_uncaptured_graph(&original.construction_attempted)?;
            if !original.terminal_attempted
                || raw
                    .terminal_origin
                    .as_ref()
                    .is_none_or(|origin| !Rc::ptr_eq(origin, &original.terminal_origin))
            {
                return Err(Error::Conflict);
            }
            raw.require_zero_effect_shape()?;
            // Same source wrapper must be empty; its private transfer origin,
            // not these Options, authenticates the destination above.
            if original.input_transfer.is_some()
                || original.members.is_some()
                || original.image.is_some()
                || original.originals.is_some()
                || original.rows.is_some()
                || original.guard.is_some()
                || original.guard_journal.is_some()
                || original.attestor.is_some()
                || original.guard_resources.is_some()
                || original.lifecycle.is_some()
                || original.lifecycle_gate.is_some()
                || original.probes.is_some()
                || original.probe_read.is_some()
                || original.probe_state.is_some()
                || original.network_read.is_some()
                || original.baseline_root.is_some()
                || original.baseline.is_some()
                || original.network_gate.is_some()
                || original.network_owner.is_some()
                || original.network_ack.is_some()
                || original.member_gates.iter().any(Option::is_some)
            {
                return Err(Error::Conflict);
            }
            Ok(())
        }
        pub(crate) fn empty() -> Self {
            Self {
                pregraph_invocation: None,
                pregraph_graph: None,
                carrier: None,
                assembly: None,
                graph: None,
                startup: None,
                lock: RefCell::new(None),
                prepared: [None, None],
                never_effects: None,
                pins: None,
                proof: None,
                retired_members: None,
                terminal_keys_call: None,
                terminal_key_closes: [None, None, None],
            }
        }
    }
    /// Every partial graph object stays here through constructor/capture errors.
    /// This is ownership retention, not effect/readiness permission. Actual
    /// resource gates continue to bracket original Pair/runtime/SDK/WFP reads.
    #[derive(Default)]
    struct GraphSlot {
        terminal_origin: Rc<()>,
        input_transfer: Option<NativeGraphTransferRead>,
        construction_attempted: std::cell::Cell<bool>,
        members: Option<Rc<MemberInventoryRead>>,
        image: Option<Rc<OriginalImage>>,
        originals: Option<Rc<Observer<OriginalWintun>>>,
        rows: Option<Rc<NativeResourceRowsRead>>,
        guard: Option<Rc<RefCell<actor::Guard>>>,
        guard_journal: Option<WindowsCarrierGuardStore<NativeSessionFiles>>,
        attestor: Option<Rc<NativeGuardSelection>>,
        guard_resources: Option<Rc<NativeGuardResourceSelection<actor::OriginalGuardAttestor>>>,
        lifecycle: Option<NativeLifecycleSelection<actor::OriginalGuardAttestor>>,
        lifecycle_gate: Option<Box<dyn NativeLifecycleGate>>,
        probes: Option<actor::Probes>,
        probe_read: Option<Rc<actor::ProbeRead>>,
        probe_state: Option<Rc<NativeProbeResourceState<actor::OriginalGuardAttestor>>>,
        network_read: Option<Rc<NativeNetworkRead>>,
        baseline_root: Option<Rc<NativeNetworkBaselineRoot<actor::OriginalGuardAttestor>>>,
        baseline: Option<Rc<NativeNetworkBaselineRead<actor::OriginalGuardAttestor>>>,
        network_gate: Option<Rc<actor::NetworkGate>>,
        network_owner: Option<actor::NetworkOwner>,
        network_ack: Option<Rc<NativeNetworkAckRead<actor::NetworkGate>>>,
        member_gates: [Option<Rc<RefCell<actor::MemberGate>>>; 2],
        terminal_attempted: bool,
    }
    /// Actual canonical graph without GraphSlot's unknown-retaining Drop.
    /// Partial/missing fields stay unknown; mandatory terminal G proves inert
    /// destructors from real ACKs, never presence/phase/default metadata.
    #[derive(Default)]
    pub(crate) struct NativeGraphTerminalResources {
        terminal_origin: Option<Rc<()>>,
        pub(crate) input_transfer: Option<NativeGraphTransferRead>,
        pub(crate) construction_attempted: bool,
        pub(crate) members: Option<Rc<MemberInventoryRead>>,
        pub(crate) image: Option<Rc<OriginalImage>>,
        pub(crate) originals: Option<Rc<Observer<OriginalWintun>>>,
        pub(crate) rows: Option<Rc<NativeResourceRowsRead>>,
        pub(crate) guard: Option<Rc<RefCell<actor::Guard>>>,
        pub(crate) guard_journal: Option<WindowsCarrierGuardStore<NativeSessionFiles>>,
        pub(crate) attestor: Option<Rc<NativeGuardSelection>>,
        pub(crate) guard_resources:
            Option<Rc<NativeGuardResourceSelection<actor::OriginalGuardAttestor>>>,
        pub(crate) lifecycle: Option<NativeLifecycleSelection<actor::OriginalGuardAttestor>>,
        pub(crate) lifecycle_gate: Option<Box<dyn NativeLifecycleGate>>,
        pub(crate) probes: Option<actor::Probes>,
        pub(crate) probe_read: Option<Rc<actor::ProbeRead>>,
        pub(crate) probe_state: Option<Rc<NativeProbeResourceState<actor::OriginalGuardAttestor>>>,
        pub(crate) network_read: Option<Rc<NativeNetworkRead>>,
        pub(crate) baseline_root:
            Option<Rc<NativeNetworkBaselineRoot<actor::OriginalGuardAttestor>>>,
        pub(crate) baseline: Option<Rc<NativeNetworkBaselineRead<actor::OriginalGuardAttestor>>>,
        pub(crate) network_gate: Option<Rc<actor::NetworkGate>>,
        pub(crate) network_owner: Option<actor::NetworkOwner>,
        pub(crate) network_ack: Option<Rc<NativeNetworkAckRead<actor::NetworkGate>>>,
        pub(crate) member_gates: [Option<Rc<RefCell<actor::MemberGate>>>; 2],
    }
    /// Factual original handoff identity, rooted BEFORE actor input moves and
    /// its fallible retain callback. This cannot prove terminal/destructor ACK.
    /// Only the actual Startup move below constructs it; absent graph fields
    /// alone can never establish that their owners moved into the actual actor.
    pub(crate) struct NativeGraphTransferRead {
        _original_move: (),
        pub(crate) pair: Rc<NativePairIntentRead>,
        pub(crate) guard: Rc<RefCell<actor::Guard>>,
        pub(crate) rows: Rc<NativeResourceRowsRead>,
        pub(crate) probes: Rc<actor::ProbeRead>,
        pub(crate) network: Rc<NativeNetworkAckRead<actor::NetworkGate>>,
    }
    impl NativeGraphTerminalResources {
        // Shape only, not absence/disposal authority. The caller must also hold
        // its SAME original Startup Never proof and actual source transfer.
        fn require_zero_effect_shape(&self) -> Result<()> {
            if self.construction_attempted || self.member_gates.iter().any(Option::is_some) {
                return Err(Error::Conflict);
            }
            macro_rules! absent { ($($field:ident),*) => { $(
                if self.$field.is_some() { return Err(Error::Conflict); }
            )* }; }
            absent!(
                input_transfer,
                members,
                image,
                originals,
                rows,
                guard,
                guard_journal,
                attestor,
                guard_resources,
                lifecycle,
                lifecycle_gate,
                probes,
                probe_read,
                probe_state,
                network_read,
                baseline_root,
                baseline,
                network_gate,
                network_owner,
                network_ack
            );
            Ok(())
        }
    }
    impl GraphSlot {
        fn require_pristine(&self) -> Result<()> {
            require_uncaptured_graph(&self.construction_attempted)?;
            if self.terminal_attempted {
                return Err(Error::Retired);
            }
            macro_rules! absent { ($($field:ident),*) => { $(
                if self.$field.is_some() { return Err(Error::Conflict); }
            )* }; }
            absent!(
                input_transfer,
                members,
                image,
                originals,
                rows,
                guard,
                guard_journal,
                attestor,
                guard_resources,
                lifecycle,
                lifecycle_gate,
                probes,
                probe_read,
                probe_state,
                network_read,
                baseline_root,
                baseline,
                network_gate,
                network_owner,
                network_ack
            );
            if self.member_gates.iter().any(Option::is_some) {
                return Err(Error::Conflict);
            }
            Ok(())
        }
        fn drain_terminal_into(
            &mut self,
            destination: &mut Option<NativeGraphTerminalResources>,
        ) -> Result<()> {
            drain_before_postflight(
                &mut self.terminal_attempted,
                destination,
                NativeGraphTerminalResources::default,
                |raw| {
                    raw.terminal_origin = Some(self.terminal_origin.clone());
                    raw.construction_attempted = self.construction_attempted.get();
                    macro_rules! transfer { ($($field:ident),*) => { $(raw.$field = self.$field.take();)* }; }
                    transfer!(
                        input_transfer,
                        members,
                        image,
                        originals,
                        rows,
                        guard,
                        guard_journal,
                        attestor,
                        guard_resources,
                        lifecycle,
                        lifecycle_gate,
                        probes,
                        probe_read,
                        probe_state,
                        network_read,
                        baseline_root,
                        baseline,
                        network_gate,
                        network_owner,
                        network_ack
                    );
                    raw.member_gates = std::mem::take(&mut self.member_gates);
                },
                |_| Ok(()),
            )
        }
        fn complete(&self) -> Result<()> {
            if self.terminal_attempted {
                return Err(Error::Retired);
            }
            macro_rules! require {
                ($($field:ident),*) => {
                    $(if self.$field.is_none() { return Err(Error::Pending); })*
                };
            }
            require!(
                members,
                image,
                originals,
                rows,
                guard,
                guard_journal,
                attestor,
                guard_resources,
                lifecycle,
                lifecycle_gate,
                probes,
                probe_read,
                probe_state,
                network_read,
                baseline,
                network_gate,
                network_owner,
                network_ack
            );
            Ok(())
        }
        fn construct_in_call(
            &mut self,
            input: &NativeStartupRoot,
            pins: &NativeCarrierPins,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<()> {
            // Consume before any field move, constructor, private read or SDK
            // postflight. Failed empty-looking partial graphs are never cold.
            begin_graph_construction(&self.construction_attempted)?;
            if self.terminal_attempted {
                return Err(Error::Retired);
            }
            if expected.carrier != input.proof
                || expected.carrier.is_none()
                || expected.pending.is_some()
                || expected.phase != pair::Phase::Starting
                || expected.network.is_some()
                || expected.guard
                    != crate::member_carrier_guard::Model::empty(expected.scope.clone())
                        .map_err(|_| Error::Conflict)?
            {
                return Err(Error::Conflict);
            }
            // These SAME strong roots outlive every gate's Weak registration.
            // Equal readers minted per gate would disappear after construction.
            self.members = Some(Rc::new(pins.members.read_pin()));
            self.image = Some(Rc::new(pins.image.read_pin().map_err(|_| Error::Conflict)?));
            self.originals = Some(Rc::new(pins.originals.clone()));
            let rows = Rc::new(NativeResourceRowsRead::new(
                input.context.clone(),
                input.runtime.read_pin()?,
                pins.source.clone(),
                pins.carrier_rows.clone(),
            ));
            self.rows = Some(rows.clone());
            let (g, selection) = NativeResourceGuardGate::<actor::OriginalGuardAttestor>::new(
                input.context.clone(),
                input.runtime.read_pin()?,
                &pins.source,
                input.supervisor.clone(),
                input.supervisor.read_pin()?,
                input.cancelled.clone(),
            );
            let selection = Rc::new(selection);
            self.guard_resources = Some(selection.clone());
            let (attestor, handle) = NativeGuardAttestor::new(
                input.context.clone(),
                input.runtime.read_pin()?,
                Some(pins.source.clone()),
                None,
                original.clone(),
                expected.clone(),
                input.supervisor.clone(),
                input.supervisor.read_pin()?,
                input.cancelled.clone(),
                g,
            );
            self.attestor = Some(Rc::new(handle));
            self.guard = Some(Rc::new(RefCell::new(
                actor::Guard::open(
                    expected.scope.clone(),
                    actor::OriginalGuardAttestor::original(attestor),
                )
                .map_err(|_| Error::Native)?,
            )));
            let guard = self.guard.as_ref().ok_or(Error::Pending)?.clone();
            let (journal, saved) =
                WindowsCarrierGuardStore::open(input.files.clone(), input.context.clone())
                    .map_err(|_| Error::Journal)?;
            self.guard_journal = Some(journal);
            if saved.is_some() {
                return Err(Error::Conflict);
            }
            selection
                .select(original.clone(), expected.clone())
                .map_err(|_| Error::Conflict)?;
            self.network_read = Some(Rc::new(NativeNetworkRead::new(pins.source.clone())));
            let network = self.network_read.as_ref().ok_or(Error::Pending)?.clone();
            self.probe_state = Some(NativeProbeResourceState::new(
                input.context.clone(),
                input.runtime.read_pin()?,
                pins.source.clone(),
                guard.clone(),
                rows.clone(),
                network.clone(),
                original.clone(),
                expected.clone(),
                input.supervisor.clone(),
                input.supervisor.read_pin()?,
                input.cancelled.clone(),
            ));
            let state = self.probe_state.as_ref().ok_or(Error::Pending)?.clone();
            self.probes = Some(
                ProbeInventory::new(pins.source.clone(), guard.clone(), state.gate())
                    .map_err(|_| Error::Conflict)?,
            );
            self.probe_read = Some(Rc::new(
                self.probes.as_ref().ok_or(Error::Pending)?.read_pin(),
            ));
            self.network_gate = Some(NativeNetworkGate::new_pre_network(
                input.context.clone(),
                input.runtime.read_pin()?,
                input.files.clone(),
                pins.source.clone(),
                original.clone(),
                expected.clone(),
                guard.clone(),
                rows.clone(),
                input.supervisor.clone(),
                input.supervisor.read_pin()?,
                input.cancelled.clone(),
            ));
            let network_gate = self.network_gate.as_ref().ok_or(Error::Pending)?.clone();
            // No route/DNS exchange has occurred. The explicit uncaptured
            // state denies effects until its original per-plan SDK capture.
            self.network_owner = Some(
                NativeCarrierNetworkOwner::fresh_uncaptured(
                    pins.source.clone(),
                    network_gate.clone(),
                    input.files.clone(),
                )
                .map_err(|_| Error::Conflict)?,
            );
            self.network_ack = Some(Rc::new(
                self.network_owner
                    .as_ref()
                    .ok_or(Error::Pending)?
                    .read_pin(),
            ));
            self.baseline_root = Some(NativeNetworkBaselineRoot::new(
                input.context.clone(),
                input.runtime.read_pin()?,
                pins.source.clone(),
                network.clone(),
                guard.clone(),
                input.supervisor.clone(),
                input.supervisor.read_pin()?,
                input.cancelled.clone(),
            ));
            let capture = self.baseline_root.as_ref().ok_or(Error::Pending)?.clone();
            pins.source
                .inspect_window(|window| {
                    capture
                        .capture_in_window(window, original, expected)
                        .map_err(|_| crate::windows::member_carrier_wintun::Error::Conflict)
                })
                .map_err(|_| Error::Conflict)?;
            self.baseline = Some(capture.read_pin().map_err(|_| Error::Conflict)?);
            let (full, lifecycle) = FullNativeLifecycleGate::<actor::OriginalGuardAttestor>::new(
                input.context.clone(),
                input.runtime.read_pin()?,
                input.supervisor.clone(),
                input.supervisor.read_pin()?,
                input.cancelled.clone(),
            );
            self.lifecycle = Some(lifecycle);
            self.lifecycle_gate = Some(Box::new(full));
            for (i, prepared) in input.prepared.iter().enumerate() {
                if prepared.is_some() {
                    self.member_gates[i] = Some(Rc::new(RefCell::new(NativeMemberGate::new(
                        NativeMemberGateInputs {
                            context: input.context.clone(),
                            intent: expected.members[i]
                                .as_ref()
                                .ok_or(Error::Conflict)?
                                .owner
                                .intent
                                .clone(),
                            runtime: input.runtime.read_pin()?,
                            member_source: input.member_source.clone(),
                            source: pins.source.clone(),
                            guard: guard.clone(),
                            rows: rows.clone(),
                            members: self.members.as_ref().ok_or(Error::Pending)?.clone(),
                            probes: self.probe_read.as_ref().ok_or(Error::Pending)?.clone(),
                            probe_gate: state.gate(),
                            network: network.clone(),
                            supervisor: input.supervisor.clone(),
                            cancelled: input.cancelled.clone(),
                        },
                    ))));
                }
            }
            Ok(())
        }
    }

    struct PregraphKeyFence<'a> {
        context: &'a Context,
        runtime: &'a RuntimeRead,
        supervisor: &'a Rc<NativeDeadline>,
        pair: &'a Rc<NativePairIntentRead>,
        expected: &'a pair::Record,
        retired: &'a crate::windows::member_carrier_runtime::native::RetiredCarrierRead,
        bindings: &'a crate::windows::member_carrier_guard::Bindings,
        graph: &'a Rc<RefCell<GraphSlot>>,
        original_rows: &'a crate::windows::member_carrier_rows::RowRecordReadPin,
        never: &'a Rc<NativeNeverMemberEffects>,
        prepared: &'a [Option<NativePreparedMember>; 2],
        retired_members: &'a [NativeRetiredMemberRoots<actor::MemberGate>],
    }
    // SAFETY: instantiated ONLY inside the actual Ready/Retired SDK callback
    // under SAME whole Stopped Pair.inspect/Calling. Every original stays in
    // its canonical Startup/Assembly slot. This does not inspect closed HKEYs
    // or reenter Authority/Source/Pair/SDK; private row bytes are reattested.
    unsafe impl crate::windows::member_carrier_keys::NativeKeyTerminalFence for PregraphKeyFence<'_> {
        fn verify_original_terminal(&self, context: &Context, binding: &Binding) -> Result<()> {
            if context != self.context
                || context.bindings.get(binding.role as usize) != Some(binding)
            {
                return Err(Error::Conflict);
            }
            self.pair
                .verify_terminal_bracket(self.runtime, self.supervisor, context, self.expected)
                .map_err(|_| Error::Conflict)?;
            self.graph
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .require_pristine()?;
            self.retired
                .inspect_terminal_history_in_bracket(|history| {
                    if !history.is_empty() {
                        return Err(crate::windows::member_carrier_wintun::Error::Conflict);
                    }
                    Ok(())
                })
                .map_err(|_| Error::Conflict)?;
            self.never.verify_terminal_original_roots(
                self.prepared,
                [None, None],
                self.retired_members,
                self.runtime,
                context,
                self.expected,
                &[],
            )?;
            let c = self.bindings.carrier.as_ref().ok_or(Error::Conflict)?;
            self.original_rows
                .with_cleanup_record(
                    &context.intent.scope,
                    context.provenance.network_epoch,
                    |facts| {
                        let before = self
                            .runtime
                            .record(
                                context,
                                crate::windows::member_session::RecordKind::CarrierRows,
                            )
                            .map_err(|_| crate::member_carrier_rows::Error::Journal)?;
                        let saved = crate::member_carrier_rows::Record::decode(&before)?;
                        crate::windows::member_carrier_ready::compare_pregraph_stopped_rows(
                            context,
                            c.identity.proof,
                            facts.binding,
                            facts.acknowledged,
                            &saved,
                        )
                        .map_err(|_| crate::member_carrier_rows::Error::Conflict)?;
                        if self
                            .runtime
                            .record(
                                context,
                                crate::windows::member_session::RecordKind::CarrierRows,
                            )
                            .map_err(|_| crate::member_carrier_rows::Error::Journal)?
                            != before
                        {
                            return Err(crate::member_carrier_rows::Error::Conflict);
                        }
                        Ok(())
                    },
                )
                .map_err(|_| Error::Conflict)?;
            self.pair
                .verify_terminal_bracket(self.runtime, self.supervisor, context, self.expected)
                .map_err(|_| Error::Conflict)
        }
    }
    impl Drop for GraphSlot {
        fn drop(&mut self) {
            // Partial graph abandonment is never an independently proven close.
            // Explicit actor cleanup owns release; preserve unknown originals.
            macro_rules! keep {($($field:ident),*)=>{$(if let Some(v)=self.$field.take(){std::mem::forget(v);})*};}
            keep!(
                input_transfer,
                members,
                image,
                originals,
                rows,
                guard,
                guard_journal,
                attestor,
                guard_resources,
                lifecycle,
                lifecycle_gate,
                probes,
                probe_read,
                probe_state,
                network_read,
                baseline_root,
                baseline,
                network_gate,
                network_owner,
                network_ack
            );
            for v in self.member_gates.iter_mut().filter_map(Option::take) {
                std::mem::forget(v);
            }
        }
    }
    impl NativeStartupRoot {
        fn module_only_read_origins(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<(
            Rc<NativeStartupModuleOnlyCandidate>,
            Rc<crate::windows::member_carrier_module::native::NativeOriginalModuleLoadRead>,
        )> {
            let candidate = if let Some(candidate) = self.module_only_candidate.as_ref() {
                candidate.clone()
            } else {
                let mut retained = None;
                self.retain_module_only_candidate_into(original, expected, &mut retained)?;
                retained.ok_or(Error::Pending)?
            };
            self.verify_module_only_candidate(&candidate, original, expected)?;
            if self
                .module_only_load_read
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .is_none()
            {
                self.retain_module_only_load_read_into(
                    &candidate,
                    original,
                    expected,
                    &mut *self
                        .module_only_load_read
                        .try_borrow_mut()
                        .map_err(|_| Error::Conflict)?,
                )?;
            }
            let load = self
                .module_only_load_read
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .as_ref()
                .cloned()
                .ok_or(Error::Pending)?;
            self.verify_module_only_load_read(&candidate, original, expected, &load)?;
            Ok((candidate, load))
        }
        /// No-constructor lineage, not empty carrier slots, is verified by the
        /// original Assembly/loader. Full SDK, protected records, all private
        /// paths/services/keys and two WFP reads stay mandatory. Read only:
        /// this cannot close a handle, unload the DLL or retire initial DATA.
        fn read_module_only_cleanup_root(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<crate::member_carrier_guard::Snapshot> {
            compare_module_only_read_record(&self.context, expected)?;
            let index = module_only_read_stage(expected)?;
            let (candidate, load) = self.module_only_read_origins(original, expected)?;
            let mut observed = None;
            let inspect = |facts: &crate::windows::member_carrier_module_terminal_read::native::NativeModuleOnlyTerminalFacts<'_>| {
                if !facts.same_original(&candidate, &load, original) { return Err(Error::Conflict); }
                observed = Some(facts.snapshot().clone());
                Ok(())
            };
            let mut readers = self
                .module_only_cleanup_native_reads
                .try_borrow_mut()
                .map_err(|_| Error::Conflict)?;
            let stage = readers.get_mut(index).ok_or(Error::Conflict)?;
            // Each protected CAS produces a new actual Pair ACK. Keep every
            // original read frame; equal stage numbers are not currentness.
            let reuse = stage.last().and_then(Option::as_ref).is_some_and(|reader| {
                reader.matches_original(&candidate, &load, original, expected)
            });
            if !reuse {
                if stage.len() >= 32 {
                    return Err(Error::Retired);
                }
                stage.push(None); // retain destination BEFORE authentication/native reads
            }
            let destination = stage.last_mut().ok_or(Error::Pending)?;
            if let Some(reader) = destination.as_ref() {
                self.read_module_only_terminal(
                    &candidate, &load, original, expected, reader, inspect,
                )?;
            } else {
                self.retain_and_read_module_only_terminal(
                    &candidate,
                    &load,
                    original,
                    expected,
                    destination,
                    inspect,
                )?;
            }
            observed.ok_or(Error::Pending)
        }
        /// SDK-free selection of SAME already-retained attempted originals.
        /// Caller retains destination before invoking. This neither performs
        /// unload nor substitutes Never/Retired/SourceRead or EMPTY JSON for G.
        pub(crate) fn retain_module_only_candidate_into(
            &mut self,
            pair: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            destination: &mut Option<Rc<NativeStartupModuleOnlyCandidate>>,
        ) -> Result<()> {
            let selection = self.module_only_selection.clone();
            selection
                .run(|| {
                    if destination.is_some() || self.module_only_candidate.is_some() {
                        return Err(std::io::Error::other("module_only_duplicate"));
                    }
                    let original = Rc::new(NativeStartupModuleOnlyCandidate {
                        invocation: self.invocation.clone(),
                        creator: self
                            .creator
                            .as_ref()
                            .ok_or_else(|| std::io::Error::other("module_only_creator"))?
                            .clone(),
                        pair: pair.clone(),
                        expected: expected.clone(),
                        runtime: self.runtime.clone(),
                        source: self.source.clone(),
                        supervisor: self.supervisor.clone(),
                        graph: self.graph.clone(),
                        selection: selection.clone(),
                        assembly: RefCell::new(None),
                    });
                    self.module_only_candidate = Some(original.clone());
                    *destination = Some(original.clone()); // root BEFORE all fallible checks
                    compare_module_only_candidate_frame(
                        &self.invocation,
                        self.create_attempted,
                        self.attach_attempted,
                        self.graph
                            .try_borrow()
                            .map_err(|_| std::io::Error::other("module_only_graph"))?
                            .construction_attempted
                            .get(),
                        &self.context,
                        expected,
                    )
                    .map_err(|_| std::io::Error::other("module_only_frame"))?;
                    // SAFETY: read-only selection only. Actual finite Calling and
                    // authenticated outer protected Pair frame bracket the facts;
                    // no resource SDK operation or unload is hidden here.
                    unsafe {
                        self.supervisor.run_module_only_read_selection(
                            &self.context,
                            pair,
                            expected,
                            || {
                                pair.inspect(&self.runtime, &self.supervisor, |actual| {
                                    if actual != expected {
                                        return Err(std::io::Error::other("module_only_pair"));
                                    }
                                    self.assembly
                                        .as_ref()
                                        .ok_or_else(|| {
                                            std::io::Error::other("module_only_assembly")
                                        })?
                                        .retain_module_only_candidate_in_call(
                                            pair,
                                            expected,
                                            &mut original.assembly.borrow_mut(),
                                        )
                                        .map_err(|_| std::io::Error::other("module_only_originals"))
                                })
                                .map_err(|_| Error::Conflict)
                            },
                        )
                    }
                    .map_err(|_| std::io::Error::other("module_only_selection"))
                })
                .map_err(|_| Error::Retired)?;
            self.verify_module_only_candidate(
                destination.as_ref().ok_or(Error::Pending)?,
                pair,
                expected,
            )
        }
        pub(crate) fn verify_module_only_candidate(
            &self,
            original: &Rc<NativeStartupModuleOnlyCandidate>,
            pair: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<()> {
            original.selection.verify().map_err(|_| Error::Retired)?;
            if self.terminal_attempted
                || self.creator_store.is_none()
                || self
                    .creator
                    .as_ref()
                    .is_none_or(|creator| !Rc::ptr_eq(creator, &original.creator))
                || self
                    .module_only_candidate
                    .as_ref()
                    .is_none_or(|r| !Rc::ptr_eq(r, original))
                || !pair.same_store_origin(&original.pair)
                || !Rc::ptr_eq(&self.invocation, &original.invocation)
                || !Rc::ptr_eq(&self.runtime, &original.runtime)
                || !Rc::ptr_eq(&self.source, &original.source)
                || !Rc::ptr_eq(&self.supervisor, &original.supervisor)
                || !Rc::ptr_eq(&self.graph, &original.graph)
            {
                return Err(Error::Conflict);
            }
            compare_module_only_read_progress(&self.context, &original.expected, expected)?;
            compare_module_only_candidate_frame(
                &self.invocation,
                self.create_attempted,
                self.attach_attempted,
                self.graph
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .construction_attempted
                    .get(),
                &self.context,
                expected,
            )?;
            self.assembly
                .as_ref()
                .ok_or(Error::Pending)?
                .verify_module_only_candidate(original.assembly()?.as_ref(), pair, expected)
        }
        /// Borrow ONLY. The SAME actual module remains caller-rooted before
        /// any external unload/postflight. The callback returns unit, and MUST
        /// root its actual native ACK externally before postflight. A separate
        /// concrete no-C full-SDK gate/unload permit is still mandatory.
        pub(crate) fn with_original_module_only(
            &mut self,
            original: &Rc<NativeStartupModuleOnlyCandidate>,
            pair: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            call: impl FnOnce(
                &mut crate::windows::member_carrier_module::native::LoadedWintun,
            ) -> Result<()>,
        ) -> Result<()> {
            self.verify_module_only_candidate(original, pair, expected)?;
            pair.verify_terminal_bracket(&self.runtime, &self.supervisor, &self.context, expected)
                .map_err(|_| Error::Conflict)?;
            let result = self
                .assembly
                .as_mut()
                .ok_or(Error::Pending)?
                .with_original_module_only(original.assembly()?.as_ref(), pair, expected, call);
            self.verify_module_only_candidate(original, pair, expected)?;
            result
        }
        /// Separate original-reference operation, not yet actor/session DATA
        /// completion. Every owning root/ACK is retained across Err/unwind.
        fn release_original_no_constructor(
            &mut self,
            pair: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<()> {
            if module_only_read_stage(expected)? != 13 {
                return Err(Error::Conflict);
            }
            if self.module_only_release.is_none() {
                let (candidate, load) = self.module_only_read_origins(pair, expected)?;
                let mut reader = None;
                crate::windows::member_carrier_module_terminal_read::native::NativeModuleOnlyTerminalRead::retain_into(
                    &candidate, &load, pair, expected, &mut reader,
                )?;
                let bootstrap = candidate.assembly()?.bootstrap()?;
                let proof = Rc::new(NativeNoConstructorReleaseProof {
                    candidate,
                    load,
                    pair: pair.clone(),
                    expected: expected.clone(),
                    bootstrap,
                    reader: reader.ok_or(Error::Pending)?,
                    lock: self.lock.as_ref().ok_or(Error::Retired)?.pin(),
                });
                self.module_only_release = Some(Rc::new(NativeNoConstructorReleaseRoot {
                    proof,
                    ack: RefCell::new(None),
                    whole: TerminalCallState::new(),
                    disposal: TerminalCallState::new(),
                    bootstrap_raw: RefCell::new(crate::windows::member_carrier_assembly::TerminalResources::new(
                        crate::windows::member_carrier_bootstrap::native::NativeBootstrapTerminalParts::empty(),
                    )),
                })); // retain before whole-call authentication/native operation
            }
            let root = self
                .module_only_release
                .as_ref()
                .ok_or(Error::Pending)?
                .clone();
            let proof = root.proof.clone();
            if !Rc::ptr_eq(&proof.pair, pair) || &proof.expected != expected {
                return Err(Error::Conflict);
            }
            if root.whole.verify().is_ok() {
                // SAME actual completed whole call + opaque returned native
                // ACK only. Never reopen the loader borrow or query its image.
                if root
                    .ack
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .is_none()
                {
                    return Err(Error::Pending);
                }
                return proof.verify_entry(&self.supervisor);
            }
            root.whole
                .run(|| {
                    let supervisor = self.supervisor.clone();
                    let runtime = self.runtime.clone();
                    // SAFETY: actual issuer/loader/current Pair roots are retained
                    // above; independent native supplier does full preflight within
                    // module.1, records exact ACK before SDK-free postflight. SAME
                    // positive bounded whole Calling spans native+all postflights.
                    unsafe {
                        supervisor.run_no_constructor_module_release(&proof, || {
                            pair.inspect(&runtime, &supervisor, |actual| {
                                if actual != expected {
                                    return Err(std::io::Error::other("module_release_pair"));
                                }
                                self.with_original_module_only(
                                    &proof.candidate,
                                    pair,
                                    expected,
                                    |module| {
                                        let mut ack = root
                                            .ack
                                            .try_borrow_mut()
                                            .map_err(|_| Error::Conflict)?;
                                        module
                                            .release_no_constructor_into(
                                                &proof.load,
                                                proof.clone(),
                                                &mut ack,
                                            )
                                            .map_err(|_| Error::Native)?;
                                        module
                                            .verify_no_constructor_disposition(
                                                ack.as_ref().ok_or(Error::Pending)?,
                                            )
                                            .map_err(|_| Error::Retired)
                                    },
                                )
                                .map_err(|_| std::io::Error::other("module_release_original"))
                            })
                            .map_err(|_| Error::Conflict)
                        })
                    }
                    .map_err(|_| std::io::Error::other("module_release_whole"))
                })
                .map_err(|_| Error::Retired)
        }
        /// Actual loader ACK lineage, not a successful original boundary bit.
        /// Pure comparison leaves the once-only native disposition borrow unused.
        pub(crate) fn verify_module_only_load_read(
            &self,
            original: &Rc<NativeStartupModuleOnlyCandidate>,
            pair: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            read: &Rc<crate::windows::member_carrier_module::native::NativeOriginalModuleLoadRead>,
        ) -> Result<()> {
            self.verify_module_only_candidate(original, pair, expected)?;
            self.assembly
                .as_ref()
                .ok_or(Error::Pending)?
                .verify_module_only_load_read(
                    original.assembly()?.as_ref(),
                    pair,
                    expected,
                    read,
                )?;
            self.verify_module_only_candidate(original, pair, expected)
        }
        pub(crate) fn retain_module_only_load_read_into(
            &self,
            original: &Rc<NativeStartupModuleOnlyCandidate>,
            pair: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            destination: &mut Option<
                Rc<crate::windows::member_carrier_module::native::NativeOriginalModuleLoadRead>,
            >,
        ) -> Result<()> {
            self.verify_module_only_candidate(original, pair, expected)?;
            self.assembly
                .as_ref()
                .ok_or(Error::Pending)?
                .retain_module_only_load_read_into(
                    original.assembly()?.as_ref(),
                    pair,
                    expected,
                    destination,
                )?;
            self.verify_module_only_load_read(
                original,
                pair,
                expected,
                destination.as_ref().ok_or(Error::Pending)?,
            )
        }
        /// Actual idle/Calling entry authentication for the module-only reader.
        /// Not a native absence, unload, root-delete or DATA-release issuer.
        pub(crate) fn verify_module_only_reader_entry(
            &self,
            supervisor: &NativeDeadline,
            original: &Rc<NativeStartupModuleOnlyCandidate>,
            load: &Rc<crate::windows::member_carrier_module::native::NativeOriginalModuleLoadRead>,
            pair: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<()> {
            if !std::ptr::eq(self.supervisor.as_ref(), supervisor) {
                return Err(Error::Conflict);
            }
            self.verify_module_only_load_read(original, pair, expected, load)?;
            let lock = self.lock.as_ref().ok_or(Error::Retired)?;
            if !self.runtime.matches_lock(lock) {
                return Err(Error::Conflict);
            }
            supervisor.verify_cleanup_runtime_entry(&self.runtime, &self.context)?;
            self.runtime
                .verify_same_session_files(&self.context, &self.files)?;
            self.runtime.verify_source(&self.source)?;
            pair.verify_module_only_read_entry(&self.runtime, &self.context, expected)
                .map_err(|_| Error::Conflict)?;
            self.verify_module_only_load_read(original, pair, expected, load)
        }
        /// Current protected creator DATA must match the SAME actual original
        /// publication ACK/current kernel capture. Missing/equal foreign JSON
        /// never supplies origin. Only the bounded reader's outer Pair frame.
        pub(crate) fn verify_module_only_creator_read(
            &self,
            original: &Rc<NativeStartupModuleOnlyCandidate>,
            pair: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            observed: &[u8],
        ) -> Result<()> {
            self.verify_module_only_candidate(original, pair, expected)?;
            pair.verify_module_only_read_bracket(
                &self.runtime,
                &self.supervisor,
                &self.context,
                expected,
            )
            .map_err(|_| Error::Conflict)?;
            let creator = self.creator.as_ref().ok_or(Error::Pending)?;
            // The store and captured publication are retained from from_claim;
            // current bytes come from this original Runtime's canonical view.
            if self.creator_store.is_none()
                || self
                    .runtime
                    .record(&self.context, RecordKind::NativeCreator)?
                    .as_slice()
                    != observed
            {
                return Err(Error::Conflict);
            }
            creator
                .verify_published_read(&self.runtime, &self.context, observed)
                .map_err(|_| Error::Conflict)?;
            pair.verify_module_only_read_bracket(
                &self.runtime,
                &self.supervisor,
                &self.context,
                expected,
            )
            .map_err(|_| Error::Conflict)?;
            if self
                .runtime
                .record(&self.context, RecordKind::NativeCreator)?
                .as_slice()
                != observed
            {
                return Err(Error::Conflict);
            }
            self.verify_module_only_candidate(original, pair, expected)
        }
        /// One full factual read under SAME finite Calling and outer Pair
        /// bracket, followed by positive watchdog rundown. Caller already roots
        /// Startup, loader read and this reader across every Err/unwind.
        pub(crate) fn read_module_only_terminal(
            &self,
            original: &Rc<NativeStartupModuleOnlyCandidate>,
            load: &Rc<crate::windows::member_carrier_module::native::NativeOriginalModuleLoadRead>,
            pair: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            reader: &Rc<crate::windows::member_carrier_module_terminal_read::native::NativeModuleOnlyTerminalRead>,
            inspect: impl FnOnce(&crate::windows::member_carrier_module_terminal_read::native::NativeModuleOnlyTerminalFacts<'_>) -> Result<()>,
        ) -> Result<()> {
            let entry = NativeModuleOnlyReadEntry {
                startup: self,
                candidate: original,
                load,
                pair,
                expected,
            };
            compare_module_only_read_record(&self.context, expected)?;
            let authenticate = || {
                if !reader.matches_original(original, load, pair, expected) {
                    return Err(Error::Conflict);
                }
                self.verify_module_only_reader_entry(
                    &self.supervisor,
                    original,
                    load,
                    pair,
                    expected,
                )
            };
            let bounded_read = || {
                // SAFETY: this exact reader only queries native/protected
                // observations. No SDK create/close/unload or storage write.
                unsafe {
                    self.supervisor.run_module_only_terminal_read(&entry, || {
                        pair.inspect(&self.runtime, &self.supervisor, |actual| {
                            if actual != expected {
                                return Err(std::io::Error::other("module_read_pair"));
                            }
                            reader
                                .read_in_call(
                                    self.lock
                                        .as_ref()
                                        .ok_or_else(|| std::io::Error::other("module_read_lock"))?,
                                    inspect,
                                )
                                .map_err(|_| std::io::Error::other("module_read_native"))
                        })
                        .map_err(|_| Error::Conflict)
                    })
                }
            };
            let index = module_only_read_stage(expected)?;
            run_repeated_module_only_read_call(
                self.module_only_cleanup_read_calls
                    .get(index)
                    .ok_or(Error::Conflict)?,
                authenticate,
                bounded_read,
            )
        }
        /// Retain the actual query-only reader in the caller's owning slot
        /// BEFORE authentication/Calling/any observation. Never replace an
        /// existing attempt; Err/unwind keeps all returned observations rooted.
        /// Success is factual read completion ONLY, not unload/DATA permission.
        pub(crate) fn retain_and_read_module_only_terminal(
            &self,
            original: &Rc<NativeStartupModuleOnlyCandidate>,
            load: &Rc<crate::windows::member_carrier_module::native::NativeOriginalModuleLoadRead>,
            pair: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            destination: &mut Option<Rc<crate::windows::member_carrier_module_terminal_read::native::NativeModuleOnlyTerminalRead>>,
            inspect: impl FnOnce(&crate::windows::member_carrier_module_terminal_read::native::NativeModuleOnlyTerminalFacts<'_>) -> Result<()>,
        ) -> Result<()> {
            use crate::windows::member_carrier_module_terminal_read::native::NativeModuleOnlyTerminalRead;
            if destination.is_some() {
                return Err(Error::Retired);
            }
            // Construction is pure root registration, with no native/file IO.
            let mut retained = None;
            NativeModuleOnlyTerminalRead::retain_into(
                original,
                load,
                pair,
                expected,
                &mut retained,
            )?;
            retain_claim_startup(
                destination,
                retained.take().ok_or(Error::Pending)?,
                |reader| {
                    self.read_module_only_terminal(
                        original,
                        load,
                        pair,
                        expected,
                        reader,
                        |facts| {
                            if !facts.same_original(original, load, pair)
                                || facts.snapshot()
                                    != &crate::member_carrier_guard::Model::empty(
                                        expected.scope.clone(),
                                    )
                                    .map_err(|_| Error::Conflict)?
                                    .expected
                                || facts.protected_records()[1].as_deref()
                                    != Some(
                                        crate::windows::member_carrier_pair_store::encode_carrier_payload(expected)
                                            .map_err(|_| Error::Conflict)?
                                            .as_slice(),
                                    )
                                || facts.protected_records()[9].is_none()
                            {
                                return Err(Error::Conflict);
                            }
                            inspect(facts)
                        },
                    )
                },
            )
        }
        /// SAME early initialized Assembly selects its cleanup view, not a
        /// reopened journal or absent receipt. Entry is SDK-free; Never later
        /// authenticates the full native read inside original Calling.
        fn bind_initial_noc_cleanup(&mut self) -> Result<()> {
            if self.create_attempted || self.attach_attempted || self.terminal_attempted {
                return Err(Error::Retired);
            }
            if !self.initial_cleanup_attempted {
                self.initial_cleanup_attempted = true;
                // Pair Stop must select this SAME supervisor's storage-only
                // cleanup lease before Never registers the original journal.
                // Calling/Pair/native absence gates remain in the later read.
                self.supervisor
                    .begin_original_cleanup_storage(&self.runtime, &self.context)?;
                let original = self.initial_noc.as_ref().ok_or(Error::Pending)?.clone();
                // Resolve the actual parent cleanup view OUTSIDE original J's
                // RefCell/private backend bracket. No lock or writer replaced.
                let canonical = self
                    .runtime
                    .native_files_for_original(&self.context, &self.files)
                    .map_err(|_| Error::Conflict)?;
                original.enter_cleanup(&self.runtime, &self.context, canonical)?;
                self.never_effects
                    .as_ref()
                    .ok_or(Error::Pending)?
                    .retain_initial_noc_read(&original)?;
            }
            self.initial_noc
                .as_ref()
                .ok_or(Error::Pending)?
                .verify_ready(&self.runtime, &self.context)
        }
        /// Destination is retained BEFORE this call. Partial/error returns keep
        /// moved originals in it and unmoved graph originals in THIS root.
        /// No native effect, read, disarm ACK or terminal permission is minted.
        pub(crate) fn drain_terminal_into(
            &mut self,
            destination: &mut TerminalStartupResources<'static>,
        ) -> Result<()> {
            self.drain_terminal_with(destination, |raw| raw)
        }
        /// Borrow a Startup raw field of Hooke's aggregate retained T. No
        /// callback takes owning originals through Result; partial/error/unwind
        /// leaves the entire destination rooted outside this call.
        pub(crate) fn drain_terminal_with<T>(
            &mut self,
            destination: &mut TerminalResources<T>,
            project: fn(&mut T) -> &mut TerminalStartupRaw<'static>,
        ) -> Result<()> {
            let raw = project(destination.retained_mut());
            drain_before_postflight(
                &mut self.terminal_attempted,
                &mut raw.startup,
                || NativeStartupTerminalPins {
                    context: self.context.clone(),
                    runtime: self.runtime.clone(),
                    creator: None,
                    creator_store: None,
                    initial_noc: None,
                    initial_data_retirement: None,
                    files: self.files.clone(),
                    store: self.store.clone(),
                    source: self.source.clone(),
                    member_source: self.member_source.clone(),
                    supervisor: self.supervisor.clone(),
                    cancelled: self.cancelled.clone(),
                    engine: self.engine.clone(),
                    logical: Zeroizing::new(String::new()),
                },
                |pins| {
                    pins.creator = self.creator.take();
                    pins.creator_store = self.creator_store.take();
                    pins.initial_noc = self.initial_noc.take();
                    // Deferred root is also retained by Startup/caller; no
                    // backedge to this raw owner or the completed outcome.
                    pins.initial_data_retirement = self.initial_data_retirement.clone();
                    pins.logical = std::mem::take(&mut self.logical);
                },
                |_| Ok(()),
            )?;
            if raw.pregraph_invocation.is_some() || raw.pregraph_graph.is_some() {
                return Err(Error::Conflict);
            }
            raw.pregraph_invocation = Some(self.invocation.clone());
            raw.pregraph_graph = Some(self.graph.clone());
            // A supplied aggregate may already retain other originals. Never
            // overwrite one, or clear it merely because THIS source is empty.
            // A partial conflict leaves every moved owner in the rooted raw
            // destination and every unmoved owner in the source.
            transfer_terminal_slot(&mut self.lock, raw.lock.get_mut())?;
            for (source, destination) in self.prepared.iter_mut().zip(raw.prepared.iter_mut()) {
                transfer_terminal_slot(source, destination)?;
            }
            transfer_terminal_slot(&mut self.never_effects, &mut raw.never_effects)?;
            transfer_terminal_slot(&mut self.pins, &mut raw.pins)?;
            transfer_terminal_slot(&mut self.proof, &mut raw.proof)?;
            transfer_terminal_slot(&mut self.retired_members, &mut raw.retired_members)?;
            if raw.terminal_keys_call.is_some()
                || raw.terminal_key_closes.iter().any(Option::is_some)
            {
                return Err(Error::Conflict);
            }
            raw.terminal_keys_call = Some(self.terminal_keys_call.clone());
            raw.terminal_key_closes = std::mem::take(&mut self.terminal_key_closes);
            if let Some(carrier) = self.carrier.as_mut() {
                carrier.drain_terminal_into(&mut raw.carrier)?;
            }
            if let Some(assembly) = self.assembly.as_mut() {
                assembly.drain_terminal_into(&mut raw.assembly)?;
            }
            // The source wrappers are now empty but their unknown Drop paths
            // remain unchanged for any root that was NOT transferred.
            let mut graph = self.graph.try_borrow_mut().map_err(|_| Error::Conflict)?;
            graph.drain_terminal_into(&mut raw.graph)
        }
        /// The existing factory has already authenticated/claimed this scope.
        /// No re-claim, replacement MutationGuard or current-epoch import.
        /// Caller keeps destination across Err/unwind. Install the actual
        /// Startup BEFORE creator publication and the original initial CAS.
        /// A failed attempt is not disposable merely because no Pair exists.
        // Original claimed inputs stay separate; destination is the additional
        // caller-owned failure root, not a replacement lock/files bundle.
        #[allow(clippy::too_many_arguments)]
        pub(crate) fn from_claim_into(
            destination: &mut Option<Self>,
            root: &Path,
            engine: PathBuf,
            owner: Arc<MutationGuard>,
            mut files: NativeSessionFiles,
            scope: &SessionScope,
            logical: &str,
            cancelled: Arc<AtomicBool>,
        ) -> Result<()> {
            if destination.is_some() {
                return Err(Error::Conflict);
            }
            let access = files
                .native_carrier_access(scope)
                .map_err(|_| Error::Conflict)?;
            if !access.is_fresh() {
                return Err(Error::Retired);
            }
            let paths = [
                crate::windows::install::slot_config_path(TunnelSlot::A)
                    .map_err(|_| Error::Invalid)?,
                crate::windows::install::slot_config_path(TunnelSlot::B)
                    .map_err(|_| Error::Invalid)?,
            ];
            let context =
                requested_context(scope, access.provenance(), logical, [&paths[0], &paths[1]])?;
            access
                .require_native_context(&context)
                .map_err(|_| Error::Conflict)?;
            let (runtime, lock) =
                RuntimeRead::new(root, owner.clone(), files.clone(), context.clone())?;
            let runtime = Rc::new(runtime);
            let source = Rc::new(WintunSource::new(root, owner.clone())?);
            runtime.verify_source(&source)?;
            let transport = nelomai_client_tunnel::detect_configuration_transport(logical);
            let member_source = Rc::new(MemberSource::new(root, owner, transport, &source)?);
            let supervisor = Rc::new(NativeDeadline::new(&runtime, &context)?);
            let (store, saved) = NativeCarrierPairStore::from_runtime(
                &runtime,
                &lock,
                files.clone(),
                context.clone(),
            )
            .map_err(|_| Error::Journal)?;
            if saved.is_some() {
                return Err(Error::Conflict);
            }
            let startup = Self {
                context,
                runtime,
                creator: None,
                creator_store: None,
                lock: Some(lock),
                files,
                store: Rc::new(RefCell::new(store)),
                source,
                member_source,
                engine,
                logical: Zeroizing::new(logical.to_owned()),
                supervisor,
                cancelled,
                prepared: [None, None],
                never_effects: None,
                assembly: None,
                initial_noc: None,
                initial_data_retirement: None,
                initial_cleanup_attempted: false,
                pre_pair_cleanup_attempted: false,
                pre_pair_cleanup: Rc::new(TerminalCallState::new()),
                pre_pair_terminal: None,
                pre_pair_outcome: None,
                carrier: Some(NativeCarrierRoot::empty()),
                pins: None,
                proof: None,
                create_attempted: false,
                graph: Rc::new(RefCell::new(GraphSlot::default())),
                attach_attempted: false,
                terminal_attempted: false,
                birth_attempted: false,
                live_preparation: Rc::new(std::cell::Cell::new(LivePreparationState::Idle)),
                retired_members: Some(Vec::new()),
                zero_effect_terminal: None,
                zero_effect_outcome: None,
                zero_effect_terminal_attempted: false,
                invocation: Rc::new(StartupInvocationLedger::new()),
                terminal_selection: Rc::new(
                    crate::windows::member_carrier_terminal_release::TerminalCallState::new(),
                ),
                attempted_terminal: None,
                terminal_keys_call: Rc::new(
                    crate::windows::member_carrier_terminal_release::TerminalCallState::new(),
                ),
                terminal_key_closes: [None, None, None],
                module_only_candidate: None,
                module_only_selection: Rc::new(TerminalCallState::new()),
                module_only_cleanup_read_calls: std::array::from_fn(|_| RefCell::new(Vec::new())),
                module_only_load_read: RefCell::new(None),
                module_only_native_read: RefCell::new(None),
                module_only_cleanup_native_reads: RefCell::new(std::array::from_fn(|_| Vec::new())),
                module_only_release: None,
                module_only_outcome: None,
            };
            retain_claim_startup(destination, startup, |startup| {
                // SAME signed Runtime/current-process capture. The capsule and its
                // original store stay in the caller root even if CAS/readback or
                // the capsule's postflight fails/unwinds. No import/retry ACK.
                startup.creator = Some(Rc::new(
                    CapturedCreator::capture(startup.runtime.clone(), &startup.context)
                        .map_err(|_| Error::Conflict)?,
                ));
                startup.creator_store = Some(
                    WindowsNativeCreatorStore::open(startup.files.clone(), startup.context.clone())
                        .map_err(|_| Error::Journal)?,
                );
                let creator = startup.creator.as_ref().ok_or(Error::Pending)?.clone();
                creator
                    .publish(|record| {
                        startup
                            .creator_store
                            .as_mut()
                            .ok_or_else(|| std::io::Error::other("creator_store_not_retained"))?
                            .publish(record)
                    })
                    .map_err(|_| Error::Journal)?;
                // SAFETY: this is the sole serialized startup root. The SAME
                // capability is mandatory in every member preparation/attachment;
                // create_ready marks the original carrier attempt BEFORE any
                // fallible assembly/module/key/C construction. No replacement or
                // recovery import seeds this ledger.
                unsafe {
                    NativeNeverMemberEffects::root(
                        &mut startup.never_effects,
                        NativeNeverMemberEffectInputs {
                            context: startup.context.clone(),
                            runtime: startup.runtime.clone(),
                            source: startup.member_source.clone(),
                            carrier: startup.source.clone(),
                            supervisor: startup.supervisor.clone(),
                        },
                        startup.lock.as_ref().ok_or(Error::Retired)?,
                    )?;
                }
                // Retain this SAME early journal before its first CAS. This DATA
                // initialization precedes PairFresh and every DLL/key/NIC attempt;
                // failure leaves the SAME Assembly accessible in the caller root.
                let (journal, saved) = WindowsNativeCarrierReceiptStore::open(
                    startup.files.clone(),
                    startup.context.clone(),
                )
                .map_err(|_| Error::Journal)?;
                if saved.is_some() {
                    return Err(Error::Conflict);
                }
                startup.assembly = Some(NativeAssemblySlot::new(startup.context.clone(), journal));
                startup
                    .assembly
                    .as_mut()
                    .ok_or(Error::Pending)?
                    .initialize()?;
                startup
                    .assembly
                    .as_ref()
                    .ok_or(Error::Pending)?
                    .retain_initial_noc_read_into(
                        &startup.runtime,
                        &startup.context,
                        &mut startup.initial_noc,
                    )?;
                startup.initial_data_retirement =
                    Some(Rc::new(NativeNoCInitialDataRetirement::new(
                        startup.initial_noc.as_ref().ok_or(Error::Pending)?,
                    )));
                startup
                    .never_effects
                    .as_ref()
                    .ok_or(Error::Pending)?
                    .retain_forward_initial_read(
                        startup.initial_noc.as_ref().ok_or(Error::Pending)?,
                    )?;
                Ok(())
            })
        }
        pub(crate) fn store(&self) -> Rc<RefCell<NativeCarrierPairStore>> {
            self.store.clone()
        }
        /// Retain in the factory/session caller BEFORE closing/into_pair.
        /// This original handle cannot grant native IO or DATA retirement
        /// until the same Startup has bound its completed whole NoC outcome.
        pub(crate) fn initial_data_retirement_root(
            &self,
        ) -> Result<Rc<NativeNoCInitialDataRetirement>> {
            self.initial_data_retirement
                .as_ref()
                .cloned()
                .ok_or(Error::Pending)
        }
        /// Explicit cleanup selection of this retained, pre-Pair owner. The
        /// SAME runtime revokes forward storage before fallible private reads;
        /// an initialized journal hands off through its original NoC supplier.
        /// No Pair record, native absence or terminal disposal ACK is created.
        pub(crate) fn begin_cleanup_before_pair(&mut self, scope: &SessionScope) -> Result<()> {
            if *scope != self.context.intent.scope
                || self.create_attempted
                || self.attach_attempted
                || self.birth_attempted
                || self.terminal_attempted
            {
                return Err(Error::Conflict);
            }
            let state = self.pre_pair_cleanup.clone();
            run_pre_pair_cleanup_selection(
                std::mem::replace(&mut self.pre_pair_cleanup_attempted, true),
                &state,
                || {
                    // Storage selection precedes the initial journal handoff.
                    // Never's registration checks this exact supervisor's
                    // cleanup-only lease; no Calling/native grant is issued.
                    self.supervisor
                        .begin_original_cleanup_storage(&self.runtime, &self.context)?;
                    use crate::member_carrier_pair::PairJournal;
                    self.store
                        .try_borrow_mut()
                        .map_err(|_| Error::Conflict)?
                        .begin_cleanup(scope)
                        .map_err(|_| Error::Journal)?;
                    self.bind_initial_noc_cleanup()
                },
            )
        }
        /// Complete ONLY this original acknowledged initialization before
        /// Pair publication. Unknown initialization/read/disposal remains
        /// retained Pending. No Pair, module ACK or future native state exists.
        pub(crate) fn finish_cleanup_before_pair(&mut self, scope: &SessionScope) -> Result<()> {
            if *scope != self.context.intent.scope {
                return Err(Error::Conflict);
            }
            self.pre_pair_cleanup.verify().map_err(|_| Error::Retired)?;
            if let Some(outcome) = &self.pre_pair_outcome {
                return outcome.verify_supervisor_terminal_drop(&self.supervisor);
            }
            if self.pre_pair_terminal.is_some()
                || self.create_attempted
                || self.attach_attempted
                || self.birth_attempted
                || self.terminal_attempted
                || self.prepared.iter().any(Option::is_some)
                || self.pins.is_some()
                || self.proof.is_some()
                || self
                    .retired_members
                    .as_ref()
                    .is_none_or(|roots| !roots.is_empty())
            {
                return Err(Error::Retired);
            }
            self.graph
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .require_pristine()?;
            let original = Rc::new(NativeStartupPrePairTerminal {
                context: self.context.clone(),
                runtime: self.runtime.clone(),
                source: self.source.clone(),
                member_source: self.member_source.clone(),
                supervisor: self.supervisor.clone(),
                creator: self.creator.as_ref().ok_or(Error::Pending)?.clone(),
                never: self.never_effects.as_ref().ok_or(Error::Pending)?.clone(),
                initial: self.initial_noc.as_ref().ok_or(Error::Pending)?.clone(),
                graph: self.graph.clone(),
                store: self.store.clone(),
                raw: Rc::new(RefCell::new(TerminalStartupResources::empty())),
                whole: TerminalCallState::new(),
                disposal: TerminalCallState::new(),
            });
            self.pre_pair_terminal = Some(original.clone()); // before any SDK/cut/unwind
            original
                .whole
                .run(|| {
                    original
                        .read(
                            self.lock
                                .as_ref()
                                .ok_or_else(|| std::io::Error::other("pre_pair_lock"))?,
                        )
                        .map_err(|_| std::io::Error::other("pre_pair_whole"))?;
                    self.graph
                        .try_borrow()
                        .map_err(|_| std::io::Error::other("pre_pair_graph"))?
                        .require_pristine()
                        .map_err(|_| std::io::Error::other("pre_pair_graph"))
                })
                .map_err(|_| Error::Retired)?;
            let raw = original.raw.clone();
            self.drain_terminal_into(&mut *raw.try_borrow_mut().map_err(|_| Error::Conflict)?)?;
            original
                .disposal
                .run(|| {
                    raw.try_borrow_mut()
                        .map_err(|_| std::io::Error::other("pre_pair_raw_busy"))?
                        .release_original_with(|raw| {
                            let pins = raw
                                .startup
                                .as_ref()
                                .ok_or_else(|| std::io::Error::other("pre_pair_pins"))?;
                            if pins.context != original.context
                                || !Rc::ptr_eq(&pins.runtime, &original.runtime)
                                || !Rc::ptr_eq(&pins.source, &original.source)
                                || !Rc::ptr_eq(&pins.member_source, &original.member_source)
                                || !Rc::ptr_eq(&pins.supervisor, &original.supervisor)
                                || !Rc::ptr_eq(&pins.store, &original.store)
                                || pins
                                    .creator
                                    .as_ref()
                                    .is_none_or(|c| !Rc::ptr_eq(c, &original.creator))
                                || pins
                                    .initial_noc
                                    .as_ref()
                                    .is_none_or(|c| !Rc::ptr_eq(c, &original.initial))
                                || raw
                                    .never_effects
                                    .as_ref()
                                    .is_none_or(|c| !Rc::ptr_eq(c, &original.never))
                                || raw.prepared.iter().any(Option::is_some)
                                || raw.pins.is_some()
                                || raw.proof.is_some()
                                || raw
                                    .retired_members
                                    .as_ref()
                                    .is_none_or(|roots| !roots.is_empty())
                            {
                                return Err(std::io::Error::other("pre_pair_original"));
                            }
                            let graph = raw
                                .graph
                                .as_ref()
                                .ok_or_else(|| std::io::Error::other("pre_pair_graph"))?;
                            graph
                                .require_zero_effect_shape()
                                .map_err(|_| std::io::Error::other("pre_pair_graph"))?;
                            let source_graph = original
                                .graph
                                .try_borrow()
                                .map_err(|_| std::io::Error::other("pre_pair_graph"))?;
                            if !source_graph.terminal_attempted
                                || graph
                                    .terminal_origin
                                    .as_ref()
                                    .is_none_or(|o| !Rc::ptr_eq(o, &source_graph.terminal_origin))
                            {
                                return Err(std::io::Error::other("pre_pair_graph_origin"));
                            }
                            drop(source_graph);
                            self.assembly
                                .as_ref()
                                .ok_or_else(|| std::io::Error::other("pre_pair_assembly"))?
                                .verify_initial_noc_terminal_cut(
                                    raw.assembly.as_ref().ok_or_else(|| {
                                        std::io::Error::other("pre_pair_assembly")
                                    })?,
                                    &original.initial,
                                )
                                .map_err(|_| std::io::Error::other("pre_pair_assembly_origin"))?;
                            let ready = raw
                                .carrier
                                .as_ref()
                                .ok_or_else(|| std::io::Error::other("pre_pair_ready"))?;
                            self.carrier
                                .as_ref()
                                .ok_or_else(|| std::io::Error::other("pre_pair_ready"))?
                                .verify_terminal_drained_into(ready)
                                .map_err(|_| std::io::Error::other("pre_pair_ready_origin"))?;
                            ready
                                .verify_unconstructed_shape()
                                .map_err(|_| std::io::Error::other("pre_pair_ready"))?;
                            original.whole.verify()?;
                            // Fresh full original absence before the held KeyLock
                            // is disposed, followed by positive watchdog rundown.
                            let lock = raw
                                .lock
                                .try_borrow()
                                .map_err(|_| std::io::Error::other("pre_pair_lock"))?;
                            original
                                .read(
                                    lock.as_ref()
                                        .ok_or_else(|| std::io::Error::other("pre_pair_lock"))?,
                                )
                                .map_err(|_| std::io::Error::other("pre_pair_disposal_read"))?;
                            original.whole.verify()
                        })
                })
                .map_err(|_| Error::Retired)?;
            let outcome = Rc::new(NativePrePairOutcome { original });
            self.pre_pair_outcome = Some(outcome.clone()); // actual disposal ACK before binding
            self.initial_data_retirement
                .as_ref()
                .ok_or(Error::Pending)?
                .bind_pre_pair_completed(outcome.clone())?;
            self.supervisor.allow_pre_pair_terminal_drop(&outcome)
        }
        pub(crate) fn context(&self) -> &Context {
            &self.context
        }
        /// Compose the real coordinator and serialized actor using THIS SAME
        /// protected store. Coordinator::new alone publishes Fresh; the actor
        /// mints its first original ACK afterwards, never a speculative pin.
        /// This is not service selection or recovery/capability acceptance.
        pub(crate) fn into_pair(
            self,
        ) -> std::io::Result<
            pair::CarrierNativePair<actor::NativeCarrierPairIo<'static>, actor::NativePairJournal>,
        > {
            let scope = self.context.intent.scope.clone();
            let provenance = self.context.provenance.clone();
            let store = self.store.clone();
            let io = actor::NativeCarrierPairIo::cold(actor::NativeColdActorInputs {
                store: store.clone(),
                startup: Box::new(self),
            });
            pair::CarrierNativePair::new(
                scope,
                provenance,
                io,
                actor::NativePairJournal::original(store),
            )
        }
        /// Retained counterpart to `into_pair`. Caller's four original slots
        /// must outlive this fallible/unwinding frame. No owning resource is
        /// returned through Result, and only Pair's retained constructor does
        /// the protected Fresh load/CAS/readback. Actual native gates are
        /// unchanged; failed initial publication cannot grant Stop/Start from
        /// absence, equal effect DATA or a new scope.
        pub(crate) fn into_pair_retained_into(
            startup: &mut Option<Self>,
            io: &mut Option<actor::NativeCarrierPairIo<'static>>,
            journal: &mut Option<actor::NativePairJournal>,
            pair: &mut Option<
                pair::CarrierNativePair<
                    actor::NativeCarrierPairIo<'static>,
                    actor::NativePairJournal,
                >,
            >,
        ) -> std::io::Result<()> {
            transfer_startup_retained_into(
                startup,
                io,
                journal,
                pair,
                |original| {
                    (
                        original.context.intent.scope.clone(),
                        original.context.provenance.clone(),
                    )
                },
                |original| {
                    let store = original.store.clone();
                    let journal = actor::NativePairJournal::original(store.clone());
                    let io = actor::NativeCarrierPairIo::cold(actor::NativeColdActorInputs {
                        store,
                        startup: Box::new(original),
                    });
                    (io, journal)
                },
            )
        }
        fn continuity(
            &self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<()> {
            if self.cancelled.load(Ordering::SeqCst)
                || !original.matches_runtime(&self.runtime)
                || !self
                    .runtime
                    .matches_lock(self.lock.as_ref().ok_or(Error::Retired)?)
            {
                return Err(Error::Retired);
            }
            self.continuity_runtime(original, expected)
        }
        fn continuity_runtime(
            &self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<()> {
            self.continuity_runtime_for(original, expected, StartupRead::Forward)
        }
        fn continuity_runtime_for(
            &self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            purpose: StartupRead,
        ) -> Result<()> {
            if self.terminal_attempted {
                return Err(Error::Retired);
            }
            startup_read_allowed(
                self.cancelled.load(Ordering::SeqCst),
                expected.phase,
                purpose,
            )?;
            if !original.matches_runtime(&self.runtime) {
                return Err(Error::Retired);
            }
            if !matches!(purpose, StartupRead::Forward) {
                // A cancellation flag/Closing request is not permission:
                // authenticate the precise actual publication and SAME Calling.
                self.verify_cleanup_publication(original, expected, purpose)?;
                self.supervisor
                    .read_pin()?
                    .verify_call(&self.supervisor, &self.context)?;
            }
            self.runtime
                .verify_same_session_files(&self.context, &self.files)?;
            self.runtime.verify_source(&self.source)?;
            self.store
                .try_borrow_mut()
                .map_err(|_| Error::Conflict)?
                .verify_original_intent(original, expected)
                .map_err(|_| Error::Journal)?;
            self.runtime.verify(&self.context)?;
            if !matches!(purpose, StartupRead::Forward) {
                self.verify_cleanup_publication(original, expected, purpose)?;
                self.supervisor
                    .read_pin()?
                    .verify_call(&self.supervisor, &self.context)?;
            }
            Ok(())
        }
        fn verify_cleanup_publication(
            &self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            purpose: StartupRead,
        ) -> Result<()> {
            match purpose {
                StartupRead::Cleanup => original
                    .verify_cleanup_entry_for(&self.runtime, &self.context, expected)
                    .map_err(|_| Error::Conflict)?,
                StartupRead::Terminal => original
                    .verify_terminal_entry(&self.runtime, &self.context, expected)
                    .map_err(|_| Error::Conflict)?,
                StartupRead::Forward => return Err(Error::Conflict),
            }
            Ok(())
        }
        /// Bounded no-C terminal check of THIS retained cold startup ledger.
        /// An absent carrier/receipt is not proof of no attempted effects.
        pub(crate) fn verify_uncaptured_terminal_root(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<crate::member_carrier_guard::Snapshot> {
            if self.attach_attempted || self.create_attempted {
                return Err(Error::Pending);
            }
            self.bind_initial_noc_cleanup()?;
            let supervisor = self.supervisor.clone();
            let context = self.context.clone();
            let never = self.never_effects.as_ref().ok_or(Error::Pending)?.clone();
            // SAFETY: only original ledger's full read-only private/SCM/key/
            // mixed SDK absence checks run here; no constructor or effect.
            unsafe {
                supervisor.run_uncaptured_terminal_read(
                    &context,
                    original,
                    expected,
                    &never,
                    || {
                        self.continuity_runtime_for(original, expected, StartupRead::Terminal)?;
                        let lock = self.lock.as_mut().ok_or(Error::Retired)?;
                        if !self.runtime.matches_lock(lock) {
                            return Err(Error::Conflict);
                        }
                        never.verify_terminal_original_roots(
                            &self.prepared,
                            [None, None],
                            self.retired_members.as_deref().ok_or(Error::Pending)?,
                            &self.runtime,
                            &context,
                            expected,
                            &[],
                        )?;
                        never.verify_uncaptured_terminal_absent(original, expected, lock)?;
                        let mut reader =
                            crate::windows::member_carrier_guard::ScopedGuardAbsence::open(
                                expected.scope.clone(),
                            )
                            .map_err(|_| Error::Conflict)?;
                        let actual = reader
                            .read_snapshot(&expected.scope)
                            .map_err(|_| Error::Conflict)?;
                        // The held no-effect ledger, key lock and private ACK must
                        // still be current after the complete readonly BFE query.
                        never.verify_uncaptured_terminal_absent(original, expected, lock)?;
                        if reader
                            .read_snapshot(&expected.scope)
                            .map_err(|_| Error::Conflict)?
                            != actual
                        {
                            return Err(Error::Conflict);
                        }
                        never.verify_terminal_original_roots(
                            &self.prepared,
                            [None, None],
                            self.retired_members.as_deref().ok_or(Error::Pending)?,
                            &self.runtime,
                            &context,
                            expected,
                            &[],
                        )?;
                        self.continuity_runtime_for(original, expected, StartupRead::Terminal)?;
                        Ok(actual)
                    },
                )
            }
        }
        /// READONLY Closing12/FullEmpty, distinct from acknowledged Stopped.
        /// The destination retains all actual owners throughout Err/unwind.
        fn read_bootstrap_full_empty_root(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<crate::member_carrier_guard::Snapshot> {
            if self.terminal_attempted || self.lock.is_none() || self.attach_attempted {
                return Err(Error::Retired);
            }
            let supervisor = self.supervisor.clone();
            let context = self.context.clone();
            if self.create_attempted
                && !self
                    .graph
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .construction_attempted
                    .get()
            {
                if expected.carrier.is_none() {
                    return self.read_module_only_cleanup_root(original, expected);
                }
                return self.read_prepublication_full_empty_root(original, expected);
            }
            if !self.create_attempted {
                self.bind_initial_noc_cleanup()?;
                let never = self.never_effects.as_ref().ok_or(Error::Pending)?.clone();
                // Safety: exact original zero-attempt entry is authenticated by
                // supervisor; callback ONLY performs mandatory full absence reads.
                unsafe {
                    supervisor.run_uncaptured_read(&context, original, expected, &never, || {
                        self.continuity_runtime_for(original, expected, StartupRead::Cleanup)?;
                        inspect_bootstrap_full_empty(
                            &context,
                            expected,
                            BootstrapOrigin::OriginalNever,
                            || {
                                let lock = self.lock.as_mut().ok_or(Error::Retired)?;
                                if !self.runtime.matches_lock(lock) {
                                    return Err(Error::Conflict);
                                }
                                let actual =
                                    never.read_bootstrap_full_empty(original, expected, lock)?;
                                self.continuity_runtime_for(
                                    original,
                                    expected,
                                    StartupRead::Cleanup,
                                )?;
                                Ok(actual)
                            },
                        )
                    })
                }
            } else {
                let retired = self.carrier.as_ref().ok_or(Error::Pending)?.retired_pin()?;
                let source = self.pins.as_ref().ok_or(Error::Pending)?.source.clone();
                if !retired.matches_source_origin(&source) {
                    return Err(Error::Conflict);
                }
                supervisor.run_cleanup(&context, original, || {
                    self.continuity_runtime_for(original, expected, StartupRead::Cleanup)?;
                    if !self
                        .runtime
                        .matches_lock(self.lock.as_ref().ok_or(Error::Retired)?)
                    {
                        return Err(Error::Conflict);
                    }
                    let graph = self.graph.try_borrow().map_err(|_| Error::Conflict)?;
                    if graph.terminal_attempted {
                        return Err(Error::Retired);
                    }
                    let lifecycle = graph.lifecycle.as_ref().ok_or(Error::Pending)?;
                    // No ordinary Closing Retired reread after key restoration.
                    let actual = retired
                        .inspect_terminal_bindings_and_history(|bindings, history| {
                            inspect_bootstrap_full_empty(
                                &context,
                                expected,
                                BootstrapOrigin::CreatedRetired,
                                || {
                                    lifecycle
                                        .verify_full_empty_in_retired_bracket(
                                            original, expected, &retired, bindings, history,
                                        )
                                        .map_err(|_| Error::Conflict)?;
                                    graph
                                        .guard
                                        .as_ref()
                                        .ok_or(Error::Pending)?
                                        .try_borrow_mut()
                                        .map_err(|_| Error::Conflict)?
                                        .snapshot_in_retired_bracket(&retired, bindings)
                                        .map_err(|_| Error::Conflict)
                                },
                            )
                            .map_err(|_| crate::windows::member_carrier_wintun::Error::Conflict)
                        })
                        .map_err(|_| Error::Conflict)?;
                    drop(graph);
                    self.continuity_runtime_for(original, expected, StartupRead::Cleanup)?;
                    Ok(actual)
                })
            }
        }
        /// Real prepublication close-origin dispatch, never a No-C Never
        /// fallback. Ready retains the actual close/row owners throughout this
        /// read. Full native terminal keys/SDK are checked by its opaque reader.
        fn read_prepublication_full_empty_root(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<crate::member_carrier_guard::Snapshot> {
            self.read_prepublication_empty_root(original, expected, false)
        }
        // The boolean selects disjoint readonly stages, never native authority.
        // Both paths require actual pristine graph and original closed C/rows.
        fn read_prepublication_empty_root(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            native_empty: bool,
        ) -> Result<crate::member_carrier_guard::Snapshot> {
            if !self.create_attempted
                || self.attach_attempted
                || self.terminal_attempted
                || self.lock.is_none()
            {
                return Err(Error::Retired);
            }
            self.graph
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .require_pristine()?;
            if self
                .retired_members
                .as_ref()
                .is_none_or(|members| !members.is_empty())
            {
                return Err(Error::Pending);
            }
            let never = self.never_effects.as_ref().ok_or(Error::Pending)?.clone();
            let runtime = self.runtime.clone();
            let supervisor = self.supervisor.clone();
            let context = self.context.clone();
            let origin = self
                .carrier
                .as_ref()
                .ok_or(Error::Pending)?
                .pregraph_terminal_read()?;
            supervisor.run_cleanup(&context, original, || {
                self.continuity_runtime_for(original, expected, StartupRead::Cleanup)?;
                if !self
                    .runtime
                    .matches_lock(self.lock.as_ref().ok_or(Error::Retired)?)
                {
                    return Err(Error::Conflict);
                }
                self.graph
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .require_pristine()?;
                let mut absence = crate::windows::member_carrier_guard::ScopedGuardAbsence::open(
                    expected.scope.clone(),
                )
                .map_err(|_| Error::Conflict)?;
                let prepared = &self.prepared;
                let mut inspect = || {
                    let verify = || {
                        if native_empty {
                            never.verify_pregraph_native_empty_originals(
                                prepared, &runtime, &context, expected,
                            )
                        } else {
                            never.verify_prepublication_full_empty_originals(
                                prepared, &runtime, &context, expected,
                            )
                        }
                    };
                    let read = || {
                        absence
                            .read_snapshot(&expected.scope)
                            .map_err(|_| Error::Conflict)
                    };
                    if native_empty {
                        inspect_prepublication_native_empty(&context, expected, verify, read)
                    } else {
                        inspect_prepublication_full_empty(&context, expected, verify, read)
                    }
                };
                let carrier = self.carrier.as_mut().ok_or(Error::Pending)?;
                let actual = match origin {
                    PrepublicationTerminalRead::Published(pin) => {
                        if !Rc::ptr_eq(&pin, &carrier.retired_pin()?) {
                            return Err(Error::Conflict);
                        }
                        if native_empty {
                            carrier.inspect_pregraph_native_empty_in_call(
                                original,
                                expected,
                                |_| inspect(),
                            )?
                        } else {
                            carrier.inspect_pregraph_terminal_in_call(original, expected, |_| {
                                inspect()
                            })?
                        }
                    }
                    PrepublicationTerminalRead::Unpublished(_pin) => {
                        // No Closing9/10 authority is inferred for an unknown
                        // identity/creator outcome. Its distinct channel remains Pending.
                        if native_empty {
                            return Err(Error::Pending);
                        }
                        carrier.inspect_unpublished_terminal_in_call(original, expected, inspect)?
                    }
                };
                self.graph
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .require_pristine()?;
                self.continuity_runtime_for(original, expected, StartupRead::Cleanup)?;
                Ok(actual)
            })
        }
        /// READONLY exact Closing11 before/after actual key restoration.
        /// SAME published C and original cold prepared/row owners, never an
        /// imported Empty frame, full-graph substitute or key effect grant.
        fn read_pregraph_key_restore_root(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            restored: Option<bool>,
        ) -> Result<crate::member_carrier_guard::Snapshot> {
            crate::windows::member_carrier_ready::compare_pregraph_key_restore_frame(
                &self.context,
                expected,
                self.proof.ok_or(Error::Pending)?,
            )?;
            if !self.create_attempted
                || self.attach_attempted
                || self.terminal_attempted
                || !self.invocation.attempted(true, false)?
                || self.pins.is_none()
                || self
                    .retired_members
                    .as_ref()
                    .is_none_or(|members| !members.is_empty())
            {
                return Err(Error::Conflict);
            }
            self.graph
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .require_pristine()?;
            let supervisor = self.supervisor.clone();
            let context = self.context.clone();
            let runtime = self.runtime.clone();
            let never = self.never_effects.as_ref().ok_or(Error::Pending)?.clone();
            supervisor.run_cleanup(&context, original, || {
                self.continuity_runtime_for(original, expected, StartupRead::Cleanup)?;
                if !runtime.matches_lock(self.lock.as_ref().ok_or(Error::Retired)?) {
                    return Err(Error::Conflict);
                }
                // Pair.begin/finish use the SAME attestation entry. Select
                // actual native key phase INSIDE Calling, never by read failure.
                let restored = match restored {
                    Some(restored) => restored,
                    None => {
                        let raw = runtime.record(&context, RecordKind::NativeCarrierReceipts)?;
                        let native = crate::member_carrier_native_ownership::Record::decode(&raw)?;
                        crate::windows::member_carrier_ready::key_restore_read_is_terminal(
                            &context, expected, &native,
                        )?
                    }
                };
                let prepared = &self.prepared;
                let mut guard = crate::windows::member_carrier_guard::ScopedGuardAbsence::open(
                    expected.scope.clone(),
                )
                .map_err(|_| Error::Conflict)?;
                let actual = self
                    .carrier
                    .as_mut()
                    .ok_or(Error::Pending)?
                    .inspect_pregraph_key_restore_in_call(original, expected, restored, |_| {
                        let verify = || {
                            never.verify_pregraph_key_restore_originals(
                                prepared, &runtime, &context, expected,
                            )
                        };
                        verify()?;
                        let before = guard
                            .read_snapshot(&expected.scope)
                            .map_err(|_| Error::Conflict)?;
                        verify()?;
                        if before != expected.guard.expected
                            || guard
                                .read_snapshot(&expected.scope)
                                .map_err(|_| Error::Conflict)?
                                != before
                        {
                            return Err(Error::Conflict);
                        }
                        verify()?;
                        Ok(before)
                    })?;
                self.graph
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .require_pristine()?;
                if !runtime.matches_lock(self.lock.as_ref().ok_or(Error::Retired)?) {
                    return Err(Error::Conflict);
                }
                self.continuity_runtime_for(original, expected, StartupRead::Cleanup)?;
                Ok(actual)
            })
        }
        /// READONLY exact Closing9/10. The original cold ledger or actual
        /// retained Retired C/full-resource graph is mandatory, never None or
        /// a historical SDK index. All owners stay in this startup root.
        fn read_bootstrap_native_empty_root(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<crate::member_carrier_guard::Snapshot> {
            let supervisor = self.supervisor.clone();
            let context = self.context.clone();
            if self.terminal_attempted || self.lock.is_none() {
                return Err(Error::Retired);
            }
            if self.create_attempted
                && !self
                    .graph
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .construction_attempted
                    .get()
            {
                if expected.carrier.is_none() {
                    return self.read_module_only_cleanup_root(original, expected);
                }
                return self.read_prepublication_empty_root(original, expected, true);
            }
            if !self.create_attempted {
                self.bind_initial_noc_cleanup()?;
                let never = self.never_effects.as_ref().ok_or(Error::Pending)?.clone();
                // This actual zero-attempt ledger, not the branch flag, proves
                // entry. A failed module/key/C attempt cannot use this channel.
                never.verify_bootstrap_native_empty_entry(
                    &supervisor,
                    original,
                    expected,
                    &context,
                )?;
                compare_bootstrap_empty_frame(&context, expected, BootstrapOrigin::OriginalNever)?;
                // SAFETY: only actual original ledger/private/SCM/full mixed
                // SDK/full-key reads inside SAME authenticated cleanup Calling.
                unsafe {
                    supervisor.run_uncaptured_read(&context, original, expected, &never, || {
                        self.continuity_runtime_for(original, expected, StartupRead::Cleanup)?;
                        let actual = read_bootstrap_empty(
                            &context,
                            expected,
                            BootstrapOrigin::OriginalNever,
                            || {
                                let lock = self.lock.as_mut().ok_or(Error::Retired)?;
                                if !self.runtime.matches_lock(lock) {
                                    return Err(Error::Conflict);
                                }
                                let actual =
                                    never.read_bootstrap_native_empty(original, expected, lock)?;
                                self.continuity_runtime_for(
                                    original,
                                    expected,
                                    StartupRead::Cleanup,
                                )?;
                                Ok(actual)
                            },
                        )?;
                        self.continuity_runtime_for(original, expected, StartupRead::Cleanup)?;
                        Ok(actual)
                    })
                }
            } else {
                // Missing/incomplete partial owners remain unknown. No cold
                // fallback; actual C CloseACK and full resource ACKs are needed.
                let retired = self.carrier.as_ref().ok_or(Error::Pending)?.retired_pin()?;
                let source = self.pins.as_ref().ok_or(Error::Pending)?.source.clone();
                if !retired.matches_source_origin(&source) {
                    return Err(Error::Conflict);
                }
                compare_bootstrap_empty_frame(&context, expected, BootstrapOrigin::CreatedRetired)?;
                supervisor.run_cleanup(&context, original, || {
                    self.continuity_runtime_for(original, expected, StartupRead::Cleanup)?;
                    if !self
                        .runtime
                        .matches_lock(self.lock.as_ref().ok_or(Error::Retired)?)
                    {
                        return Err(Error::Conflict);
                    }
                    let graph_read = self.graph.try_borrow().map_err(|_| Error::Conflict)?;
                    let graph = &*graph_read;
                    if graph.terminal_attempted {
                        return Err(Error::Retired);
                    }
                    graph
                        .attestor
                        .as_ref()
                        .ok_or(Error::Pending)?
                        .select(original.clone(), expected.clone())
                        .map_err(|_| Error::Conflict)?;
                    graph
                        .probe_state
                        .as_ref()
                        .ok_or(Error::Pending)?
                        .select(original.clone(), expected.clone())
                        .map_err(|_| Error::Conflict)?;
                    graph
                        .network_gate
                        .as_ref()
                        .ok_or(Error::Pending)?
                        .select_retired_guard_resources(
                            original.clone(),
                            expected.clone(),
                            retired.clone(),
                        )
                        .map_err(|_| Error::Conflict)?;
                    let actual = retired
                        .inspect_bindings(|bindings| {
                            read_bootstrap_empty(
                                &context,
                                expected,
                                BootstrapOrigin::CreatedRetired,
                                || {
                                    Self::bootstrap_retired_resources(
                                        graph, expected, &retired, bindings, &source,
                                    )
                                },
                            )
                            .map_err(|_| crate::windows::member_carrier_wintun::Error::Conflict)
                        })
                        .map_err(|_| Error::Conflict)?;
                    drop(graph_read);
                    self.continuity_runtime_for(original, expected, StartupRead::Cleanup)?;
                    Ok(actual)
                })
            }
        }
        /// Called INSIDE the supplied SAME Retired full-native bracket. Never
        /// enter live Source or query historical DNS/NICs from here.
        fn bootstrap_retired_resources(
            graph: &GraphSlot,
            expected: &pair::Record,
            retired: &crate::windows::member_carrier_runtime::native::RetiredCarrierRead,
            bindings: &crate::windows::member_carrier_guard::Bindings,
            source: &Rc<crate::windows::member_carrier_runtime::native::NativeSourceRead>,
        ) -> Result<crate::member_carrier_guard::Snapshot> {
            let guard = graph.guard.as_ref().ok_or(Error::Pending)?;
            let probes = graph.probe_read.as_ref().ok_or(Error::Pending)?;
            let state = graph.probe_state.as_ref().ok_or(Error::Pending)?;
            let network = graph.network_read.as_ref().ok_or(Error::Pending)?;
            let gate = graph.network_gate.as_ref().ok_or(Error::Pending)?;
            let baseline = graph.baseline.as_ref().ok_or(Error::Pending)?;
            let ack = graph.network_ack.as_ref().ok_or(Error::Pending)?;
            if !retired.matches_source_origin(source)
                || !baseline.matches_source_origin(source)
                || !baseline.matches_reader(network)
                || !ack.matches_origin(source, gate)
            {
                return Err(Error::Conflict);
            }
            probes
                .matches_caps(source, guard, &state.gate())
                .map_err(|_| Error::Conflict)?;
            let before = guard
                .try_borrow_mut()
                .map_err(|_| Error::Conflict)?
                .snapshot_in_retired_bracket(retired, bindings)
                .map_err(|_| Error::Conflict)?;
            graph
                .rows
                .as_ref()
                .ok_or(Error::Pending)?
                .inspect_retired_in_bracket(retired, bindings, |facts| {
                    if facts.rows[0].is_none()
                        || facts.rows.iter().flatten().any(|row| {
                            row.observed.is_some()
                                || row.acknowledged.phase
                                    != crate::member_carrier_rows::Phase::Stopped
                                || row.acknowledged.pending.is_some()
                                || row.acknowledged.current.address.is_some()
                                || row.acknowledged.current.interface.policy
                                    != row.acknowledged.baseline.interface.policy
                        })
                    {
                        return Err(crate::windows::member_carrier_wintun::Error::Conflict);
                    }
                    Ok(())
                })
                .map_err(|_| Error::Conflict)?;
            probes.inspect_retired().map_err(|_| Error::Conflict)?;
            network
                .verify_native_empty_in_retired_bracket(expected, retired, bindings, baseline, gate)
                .map_err(|_| Error::Conflict)?;
            if guard
                .try_borrow_mut()
                .map_err(|_| Error::Conflict)?
                .snapshot_in_retired_bracket(retired, bindings)
                .map_err(|_| Error::Conflict)?
                != before
            {
                return Err(Error::Conflict);
            }
            Ok(before)
        }
        pub(crate) fn prepare_in_call(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            current: &pair::Record,
            proposal: &pair::Record,
            member: &nelomai_client_tunnel::redundancy::protocol::Member,
            native: &str,
        ) -> Result<crate::member_owner::Record> {
            #[cfg(test)]
            trace_step("member preparation begin original continuity");
            self.continuity(original, current).inspect_err(|error| {
                #[cfg(test)]
                super::super::member_carrier_factory_test_os::trace_native(
                    "member preparation current original",
                    error,
                );
                #[cfg(not(test))]
                let _ = error;
            })?;
            #[cfg(test)]
            trace_step("member preparation end original continuity");
            member.validate().map_err(|_| Error::Invalid)?;
            compare_member_text(
                &self.context,
                self.member_source.transport(),
                Some(&self.logical),
                member.configuration.expose(),
                native,
            )?;
            let slot = crate::member_pair::slot_native(member.slot);
            let i = usize::from(slot == TunnelSlot::B);
            let input = NativePreparedMemberInputs {
                context: self.context.clone(),
                runtime: self.runtime.read_pin()?,
                engine: self.engine.clone(),
                slot,
                source: self.member_source.clone(),
                carrier: self.source.clone(),
                supervisor: self.supervisor.clone(),
                never_effects: self.never_effects.as_ref().ok_or(Error::Pending)?.clone(),
            };
            #[cfg(test)]
            trace_step("member preparation original runtime pin retained");
            let lock = self.lock.as_mut().ok_or(Error::Retired)?;
            #[cfg(test)]
            trace_step("member preparation begin readonly owner");
            NativePreparedMember::prepare(
                &mut self.prepared[i],
                input,
                member.configuration.expose(),
                lock,
            )
            .inspect_err(|error| {
                #[cfg(test)]
                super::super::member_carrier_factory_test_os::trace_native(
                    "readonly native member preparation",
                    error,
                );
                #[cfg(not(test))]
                let _ = error;
            })?;
            #[cfg(test)]
            trace_step("member preparation end readonly owner");
            let prepared = self.prepared[i].as_mut().ok_or(Error::Pending)?;
            #[cfg(test)]
            trace_step("member preparation begin original proposal");
            let record = prepared
                .verify_proposal(original, proposal, lock)
                .inspect_err(|error| {
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_native(
                        "prepared member proposal",
                        error,
                    );
                    #[cfg(not(test))]
                    let _ = error;
                })?;
            #[cfg(test)]
            trace_step("member preparation end original proposal");
            self.continuity(original, current)?;
            #[cfg(test)]
            trace_step("member preparation final original continuity");
            Ok(record)
        }
        pub(crate) fn preflight_in_call(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<()> {
            self.continuity(original, expected)?;
            if self.create_attempted || self.proof.is_some() || expected.carrier.is_some() {
                return Err(Error::Retired);
            }
            let slot = match expected.operation {
                Some(pair::Operation::Start(slot)) => slot,
                _ => return Err(Error::Conflict),
            };
            self.prepared[usize::from(slot == nelomai_client_tunnel::redundancy::Slot::B)]
                .as_mut()
                .ok_or(Error::Pending)?
                .preflight_before_carrier(
                    original,
                    expected,
                    self.lock.as_mut().ok_or(Error::Retired)?,
                )?;
            self.continuity(original, expected)
        }
        /// Each existing bootstrap stage owns its whole original Calling.
        /// Never wrap these methods in another NativeDeadline operation.
        pub(crate) fn create_ready(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<crate::member_owner::InterfaceProof> {
            macro_rules! step {
                ($label:literal, $result:expr) => {{
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step(concat!(
                        "begin ", $label
                    ));
                    let value = $result.inspect_err(|_error| {
                        #[cfg(test)]
                        super::super::member_carrier_factory_test_os::trace_native($label, _error);
                    })?;
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step($label);
                    value
                }};
            }
            // Retain the actual invocation identity before any fallible access,
            // even if the Never ledger or Assembly has not produced an owner.
            step!(
                "CarrierReady original invocation",
                self.invocation.begin(false)
            );
            self.create_attempted = true;
            self.never_effects
                .as_ref()
                .ok_or(Error::Pending)?
                .begin_carrier_construction();
            step!(
                "CarrierReady entry continuity",
                self.continuity(original, expected)
            );
            // Re-resolve the SAME retained Runtime birth/backend before any
            // receipt store, DLL assembly or graph is constructed. An ordering
            // latch or Starting JSON cannot substitute for this actual root.
            self.files = step!(
                "CarrierReady canonical birth view",
                self.runtime
                    .native_birth_files(&self.context)
                    .map_err(|_| Error::Conflict)
            );
            if expected.pending != Some(pair::Effect::CarrierReady) || expected.carrier.is_some() {
                return Err(Error::Conflict);
            }
            // The original early Assembly/initial journal is never reopened or
            // reinitialized after PairFresh or after Runtime birth binding.
            let assembly = self.assembly.as_mut().ok_or(Error::Pending)?;
            let initial = step!(
                "CarrierReady original initial reader",
                assembly.initial_read_pin()
            );
            let lock = self.lock.as_mut().ok_or(Error::Retired)?;
            {
                let mut store = self.store.try_borrow_mut().map_err(|_| Error::Conflict)?;
                let bootstrap = step!("CarrierReady original bootstrap", assembly.bootstrap_mut());
                step!(
                    "CarrierReady original cold load",
                    bootstrap.load_cold(
                        &self.runtime,
                        lock,
                        &mut store,
                        &self.files,
                        &self.source,
                        &self.context,
                        expected,
                        original.clone(),
                        &self.logical,
                        &self.supervisor,
                        &self.cancelled,
                        initial,
                    )
                );
                step!(
                    "CarrierReady original composition",
                    assembly
                        .bootstrap_mut()?
                        .compose_originals(lock, &mut store)
                );
            }
            step!(
                "CarrierReady original assembly",
                assembly.assemble(lock, original)
            );
            step!("CarrierReady original keys", assembly.prepare_carrier(lock));
            let carrier = self.carrier.as_mut().ok_or(Error::Retired)?;
            self.proof = Some(step!(
                "CarrierReady original C creation",
                carrier.create_ready(assembly, lock, &self.files)
            ));
            self.pins = Some(carrier.member_pins()?);
            self.continuity(original, expected)?;
            self.proof.ok_or(Error::Pending)
        }
        /// Cold actor dispatch before graph attachment, NOT a Never fallback.
        /// Owns the same whole cleanup Calling and leaves every partial owner
        /// in this Startup on Err/unwind. Ready/Rows/NativeAuthority still gate
        /// the original operation; no skipped SDK or invented row ACK here.
        pub(crate) fn cleanup_pregraph_carrier(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<()> {
            compare_pregraph_cleanup(
                &self.invocation,
                self.create_attempted,
                self.attach_attempted,
                &self.context,
                expected,
            )?;
            if self.terminal_attempted || self.lock.is_none() {
                return Err(Error::Retired);
            }
            self.graph
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .require_pristine()?;
            let supervisor = self.supervisor.clone();
            let context = self.context.clone();
            supervisor.run_cleanup(&context, original, || {
                self.continuity_runtime_for(original, expected, StartupRead::Cleanup)?;
                if !self
                    .runtime
                    .matches_lock(self.lock.as_ref().ok_or(Error::Retired)?)
                {
                    return Err(Error::Conflict);
                }
                self.graph
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .require_pristine()?;
                let carrier = self.carrier.as_mut().ok_or(Error::Pending)?;
                if expected.stop_stage == 3 {
                    carrier.restore_interface_in_call(original.clone(), expected)?;
                } else {
                    carrier.cleanup_carrier_in_call(original.clone(), expected)?;
                }
                self.graph
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .require_pristine()?;
                self.continuity_runtime_for(original, expected, StartupRead::Cleanup)
            })
        }
        /// Explicit SAME original NEW-HKEY closure for published pre-graph C.
        /// Call OUTSIDE Calling, BEFORE draining Startup. All native ACK output
        /// slots are already fields in this root; callback/SDK/postflight error
        /// leaves every original in place and cannot repeat RegCloseKey.
        /// Does not release a module, dispose actor locals or publish terminal
        /// resource permission. Unpublished/no-row/unknown C cannot use it.
        pub(crate) fn close_pregraph_terminal_keys(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<()> {
            self.invocation
                .attempted(self.create_attempted, self.attach_attempted)?;
            if !self.create_attempted || self.attach_attempted || self.terminal_attempted {
                return Err(Error::Retired);
            }
            self.graph
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .require_pristine()?;
            let carrier = self.carrier.as_ref().ok_or(Error::Pending)?;
            let retired = match carrier.pregraph_terminal_read()? {
                PrepublicationTerminalRead::Published(original) => original,
                PrepublicationTerminalRead::Unpublished(_) => return Err(Error::Pending),
            };
            let row = carrier.carrier_row_pin()?;
            let whole = self.terminal_keys_call.clone();
            let supervisor = self.supervisor.clone();
            let context = self.context.clone();
            whole.run(|| {
                supervisor.run_terminal_cleanup(&context, original, expected, || {
                    self.continuity_runtime_for(original, expected, StartupRead::Terminal)?;
                    original.inspect(&self.runtime, &supervisor, |actual| {
                        if actual != expected { return Err(std::io::Error::other("pregraph_terminal_foreign_pair")); }
                        let runtime = self.runtime.clone();
                        let graph = self.graph.clone();
                        let never = self.never_effects.as_ref().ok_or_else(|| std::io::Error::other("pregraph_member_originals"))?;
                        let prepared = &self.prepared;
                        let retired_members = self.retired_members.as_deref().ok_or_else(|| std::io::Error::other("pregraph_member_originals"))?;
                        let assembly = self.assembly.as_mut().ok_or_else(|| std::io::Error::other("pregraph_key_owner"))?;
                        let lock = self.lock.as_mut().ok_or_else(|| std::io::Error::other("pregraph_key_lock"))?;
                        if !runtime.matches_lock(lock) { return Err(std::io::Error::other("pregraph_key_lock")); }
                        let retained = &mut self.terminal_key_closes;
                        self.carrier.as_mut().ok_or_else(|| std::io::Error::other("pregraph_carrier"))?
                            .inspect_pregraph_stopped_in_call(original, expected, |bindings| {
                                let fence = PregraphKeyFence { context: &context, runtime: &runtime, supervisor: &supervisor,
                                    pair: original, expected, retired: &retired, bindings, graph: &graph,
                                    original_rows: &row, never, prepared, retired_members };
                                assembly.with_original_terminal_key_owner(|owner| {
                                    owner.with_terminal_original_keys(lock, |_, keys, _| {
                                        for (slot, original_key) in keys.into_iter().enumerate() {
                                            if let Some(original_key) = original_key {
                                                crate::windows::member_carrier_keys::close_terminal_original_key(original_key, &fence, |ack| {
                                                    if retained[slot].is_some() { return Err(Error::Conflict); }
                                                    retained[slot] = Some(ack); // BEFORE native/supervisor postflight
                                                    Ok(())
                                                })?;
                                            } else if retained[slot].is_some() { return Err(Error::Conflict); }
                                        }
                                        Ok(())
                                    })?;
                                    // Pure original-list/ACK reattestation: never query a closed HKEY.
                                    owner.with_terminal_original_key_reads(lock, |_, keys| {
                                        for (slot, key) in keys.into_iter().enumerate() {
                                            match (key, retained[slot].as_ref()) {
                                                (Some(key), Some(ack)) => crate::windows::member_carrier_keys::verify_terminal_original_key_closed(key, ack)?,
                                                (None, None) => (), // authenticated owner's original key list, NOT lookup absence
                                                _ => return Err(Error::Conflict),
                                            }
                                        }
                                        Ok(())
                                    })
                                })
                            }).map_err(|_| std::io::Error::other("pregraph_terminal_key_close"))
                    }).map_err(|_| Error::Conflict)?;
                    self.continuity_runtime_for(original, expected, StartupRead::Terminal)
                }).map_err(|_| std::io::Error::other("pregraph_terminal_key_call"))
            }).map_err(|_| Error::Retired)
        }
        fn attach_in_call(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            retain: &mut dyn FnMut(NativeActorInputs<'static>) -> Result<()>,
        ) -> Result<()> {
            self.continuity(original, expected)?;
            let pins = self.pins.as_ref().ok_or(Error::Pending)?;
            if !self.runtime.same_original_runtime(&pins.runtime)
                || self.context != pins.context
                || !Rc::ptr_eq(&self.supervisor, &pins.supervisor)
                || !Arc::ptr_eq(&self.cancelled, &pins.cancelled)
            {
                return Err(Error::Conflict);
            }
            for (i, member) in expected.members.iter().enumerate() {
                if let Some(member) = member {
                    if self.prepared[i]
                        .as_mut()
                        .ok_or(Error::Pending)?
                        .prepared_record(self.lock.as_mut().ok_or(Error::Retired)?)?
                        != member.owner
                    {
                        return Err(Error::Conflict);
                    }
                } else if self.prepared[i].is_some() {
                    return Err(Error::Conflict);
                }
            }
            let graph_root = self.graph.clone();
            let mut graph = graph_root.try_borrow_mut().map_err(|_| Error::Conflict)?;
            // Root is already owned independently by self.graph. Capture/read
            // failure never returns the sole native graph through Result.
            graph.construct_in_call(self, pins, original, expected)?;
            graph.complete()?;
            if self.lock.is_none() || self.assembly.is_none() || self.carrier.is_none() {
                return Err(Error::Pending);
            }
            self.continuity(original, expected)?;
            let source = pins.source.clone();
            if graph.input_transfer.is_some() {
                return Err(Error::Conflict);
            }
            graph.input_transfer = Some(NativeGraphTransferRead {
                _original_move: (),
                pair: original.clone(),
                guard: graph.guard.as_ref().ok_or(Error::Pending)?.clone(),
                rows: graph.rows.as_ref().ok_or(Error::Pending)?.clone(),
                probes: graph.probe_read.as_ref().ok_or(Error::Pending)?.clone(),
                network: graph.network_ack.as_ref().ok_or(Error::Pending)?.clone(),
            });
            // Presence was checked before ANY move. Construction below has no
            // fallible boundary. The actor retains this whole original input
            // before its comparison/registration/postflight, including Err.
            macro_rules! take {
                ($field:ident) => {
                    graph.$field.take().expect("checked original graph")
                };
            }
            let input = NativeActorInputs {
                context: self.context.clone(),
                runtime: self.runtime.clone(),
                member_source: self.member_source.clone(),
                lock: self.lock.take().expect("checked original lock"),
                files: self.files.clone(),
                store: self.store.clone(),
                pair: original.clone(),
                expected: expected.clone(),
                assembly: self.assembly.take().expect("checked original assembly"),
                carrier: self.carrier.take().expect("checked original carrier"),
                pins: self.pins.take().expect("checked original pins"),
                originals: take!(originals),
                image: take!(image),
                members: take!(members),
                rows: take!(rows),
                guard: take!(guard),
                guard_journal: take!(guard_journal),
                attestor: take!(attestor),
                guard_resources: take!(guard_resources),
                lifecycle: take!(lifecycle),
                lifecycle_gate: Some(take!(lifecycle_gate)),
                probes: take!(probes),
                probe_read: take!(probe_read),
                probe_state: take!(probe_state),
                network_read: take!(network_read),
                baseline: take!(baseline),
                network_gate: take!(network_gate),
                network_owner: take!(network_owner),
                network_ack: take!(network_ack),
                controllers: [None, None],
                member_gates: std::mem::take(&mut graph.member_gates),
            };
            drop(graph);
            let result = retain(input);
            // SAME runtime/store Source factual postflight. KeyLock is now in
            // the actor, not recreated or borrowed from an unrelated owner.
            self.continuity_runtime(original, expected)?;
            source
                .inspect_bindings(|bindings| {
                    if bindings.carrier.as_ref().map(|c| c.identity.proof) != self.proof {
                        return Err(crate::windows::member_carrier_wintun::Error::Conflict);
                    }
                    Ok(())
                })
                .map_err(|_| Error::Conflict)?;
            result
        }
    }

    impl Drop for NativeStartupRoot {
        fn drop(&mut self) {
            if self.pre_pair_outcome.is_none() {
                if let Some(original) = self.pre_pair_terminal.take() {
                    std::mem::forget(original); // unknown actual raw/read history
                }
            }
            // No terminal ACK => retain attempted publication originals. The
            // actual terminal drain moves them into retained raw T; only its
            // mandatory successful disposal drops these SAME originals.
            if let Some(original) = self.creator.take() {
                std::mem::forget(original);
            }
            if let Some(original) = self.creator_store.take() {
                std::mem::forget(original);
            }
            if let Some(original) = self.initial_noc.take() {
                std::mem::forget(original);
            }
            for original in std::mem::take(&mut self.terminal_key_closes)
                .into_iter()
                .flatten()
            {
                // Unknown terminal abandonment keeps the actual native close
                // history alongside the retained owner. Successful raw drain
                // already moved these SAME receipts, so its empty shell drops.
                std::mem::forget(original);
            }
            if let Some(originals) = self.retired_members.take() {
                // Unknown abandonment cannot discard original generation
                // histories. Terminal drain moves these into caller-retained
                // raw T before release checks; no close/disarm is inferred.
                std::mem::forget(originals);
            }
        }
    }
    // SAFETY: this owns and roots the actual same-runtime/same-store originals,
    // prepared owners and partial native graph before every fallible boundary.
    // Every method enters the actual supervisor or inherits Assembly's whole
    // Calling; registration is never used as native effect authorization.
    unsafe impl NativeStartup<'static> for NativeStartupRoot {
        fn release_module_only_terminal(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<()> {
            self.release_original_no_constructor(original, expected)
        }
        fn verify_module_only_release(
            &self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<()> {
            let root = self.module_only_release.as_ref().ok_or(Error::Pending)?;
            root.whole.verify().map_err(|_| Error::Retired)?;
            if !Rc::ptr_eq(&root.proof.pair, original) || &root.proof.expected != expected {
                return Err(Error::Conflict);
            }
            let source = root.proof.candidate.assembly()?;
            source.verify_no_constructor_seal()?;
            self.assembly
                .as_ref()
                .ok_or(Error::Pending)?
                .verify_completed_no_constructor_release(
                    &source,
                    original,
                    expected,
                    root.ack
                        .try_borrow()
                        .map_err(|_| Error::Conflict)?
                        .as_ref()
                        .ok_or(Error::Pending)?,
                )
        }
        fn dispose_module_only_terminal(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            destination: &mut TerminalStartupResources<'static>,
        ) -> Result<()> {
            let root = self
                .module_only_release
                .as_ref()
                .ok_or(Error::Pending)?
                .clone();
            let proof = &root.proof;
            root.whole.verify().map_err(|_| Error::Retired)?;
            if !Rc::ptr_eq(&proof.pair, original)
                || &proof.expected != expected
                || !self.create_attempted
                || self.attach_attempted
                || !self.terminal_attempted
                || !Rc::ptr_eq(&self.graph, &proof.candidate.graph)
                || self.module_only_outcome.is_some()
            {
                return Err(Error::Conflict);
            }
            proof.candidate.assembly()?.verify_no_constructor_seal()?;
            let ack_guard = root.ack.try_borrow().map_err(|_| Error::Conflict)?;
            let ack = ack_guard.as_ref().ok_or(Error::Pending)?;
            root.disposal
                .run(|| {
                    // The actual raw destination was rooted before transfer. Do
                    // every origin check BEFORE either owning container is dropped.
                    // FreeLibrary and its whole supervisor postflight already ACKed;
                    // all checks here are PURE: never query SDK/image/closed handles.
                    let raw = destination.retained_mut();
                    let pins = raw
                        .startup
                        .as_ref()
                        .ok_or_else(|| std::io::Error::other("module_disposal_pins"))?;
                    let input = proof.bootstrap.original_inputs();
                    if pins.context != *input.context
                        || !Rc::ptr_eq(&pins.runtime, &self.runtime)
                        || !Rc::ptr_eq(&pins.source, &self.source)
                        || !Rc::ptr_eq(&pins.member_source, &self.member_source)
                        || !Rc::ptr_eq(&pins.supervisor, &self.supervisor)
                        || !Rc::ptr_eq(&pins.store, &self.store)
                        || raw
                            .pregraph_invocation
                            .as_ref()
                            .is_none_or(|invocation| !Rc::ptr_eq(invocation, &self.invocation))
                        || raw
                            .pregraph_graph
                            .as_ref()
                            .is_none_or(|graph| !Rc::ptr_eq(graph, &self.graph))
                        || pins
                            .creator
                            .as_ref()
                            .is_none_or(|creator| !Rc::ptr_eq(creator, &proof.candidate.creator))
                        || pins.initial_data_retirement.as_ref().is_none_or(|data| {
                            self.initial_data_retirement
                                .as_ref()
                                .is_none_or(|original| !Rc::ptr_eq(data, original))
                        })
                        || raw.prepared.iter().any(Option::is_some)
                        || raw
                            .retired_members
                            .as_ref()
                            .is_none_or(|members| !members.is_empty())
                        || raw.pins.is_some()
                        || raw.proof.is_some()
                        || raw.terminal_key_closes.iter().any(Option::is_some)
                    {
                        return Err(std::io::Error::other("module_disposal_original"));
                    }
                    let lock = raw
                        .lock
                        .try_borrow()
                        .map_err(|_| std::io::Error::other("module_disposal_lock"))?;
                    if !self.runtime.matches_lock(
                        lock.as_ref()
                            .ok_or_else(|| std::io::Error::other("module_disposal_lock"))?,
                    ) {
                        return Err(std::io::Error::other("module_disposal_lock"));
                    }
                    drop(lock);
                    raw.verify_pregraph_original_cut()
                        .map_err(|_| std::io::Error::other("module_disposal_graph"))?;
                    let ready = raw
                        .carrier
                        .as_ref()
                        .ok_or_else(|| std::io::Error::other("module_disposal_ready"))?;
                    self.carrier
                        .as_ref()
                        .ok_or_else(|| std::io::Error::other("module_disposal_ready"))?
                        .verify_terminal_drained_into(ready)
                        .map_err(|_| std::io::Error::other("module_disposal_ready"))?;
                    ready
                        .verify_unconstructed_shape()
                        .map_err(|_| std::io::Error::other("module_disposal_ready"))?;
                    let assembly = self
                        .assembly
                        .as_ref()
                        .ok_or_else(|| std::io::Error::other("module_disposal_assembly"))?;
                    let assembly_raw = raw
                        .assembly
                        .as_mut()
                        .ok_or_else(|| std::io::Error::other("module_disposal_assembly"))?;
                    let source = proof
                        .candidate
                        .assembly()
                        .map_err(|_| std::io::Error::other("module_disposal_source"))?;
                    let mut bootstrap_raw = root
                        .bootstrap_raw
                        .try_borrow_mut()
                        .map_err(|_| std::io::Error::other("module_disposal_bootstrap"))?;
                    assembly
                        .drain_module_only_bootstrap(
                            assembly_raw,
                            &source,
                            expected,
                            ack,
                            &mut bootstrap_raw,
                        )
                        .map_err(|_| std::io::Error::other("module_disposal_bootstrap"))?;
                    // The nested Bootstrap contains the actual loader owner. Its
                    // empty source wrapper alone is not disposal permission: rejoin
                    // the SAME typed complete native ACK before its inert Drop.
                    destination.release_original_with(|raw| {
                        bootstrap_raw.release_original_with(|bootstrap| {
                            root.whole.verify()?;
                            proof
                                .candidate
                                .assembly()
                                .map_err(|_| std::io::Error::other("module_disposal_source"))?
                                .verify_no_constructor_seal()
                                .map_err(|_| std::io::Error::other("module_disposal_source"))?;
                            assembly
                                .verify_released_module_only_cut(
                                    raw.assembly.as_ref().ok_or_else(|| {
                                        std::io::Error::other("module_disposal_assembly")
                                    })?,
                                    &source,
                                    ack,
                                    bootstrap,
                                )
                                .map_err(|_| std::io::Error::other("module_disposal_ack"))
                        })
                        // No fallible/native work after inner original disposal.
                    })
                })
                .map_err(|_| Error::Retired)?;
            drop(ack_guard);
            let outcome = Rc::new(NativeModuleOnlyOutcome { original: root });
            self.module_only_outcome = Some(outcome.clone()); // before binding/postflight
            self.initial_data_retirement
                .as_ref()
                .ok_or(Error::Pending)?
                .bind_module_completed(outcome.clone())?;
            self.supervisor.allow_module_only_terminal_drop(&outcome)
        }
        fn verify_module_only_disposition(
            &self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<()> {
            let outcome = self.module_only_outcome.as_ref().ok_or(Error::Pending)?;
            if !Rc::ptr_eq(&outcome.original.proof.pair, original)
                || &outcome.original.proof.expected != expected
            {
                return Err(Error::Conflict);
            }
            outcome.verify_supervisor_terminal_drop(&self.supervisor)
        }
        fn observe_attempted_module_only_terminal(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<()> {
            let (candidate, load) = self.module_only_read_origins(original, expected)?;
            self.retain_and_read_module_only_terminal(
                &candidate,
                &load,
                original,
                expected,
                &mut *self
                    .module_only_native_read
                    .try_borrow_mut()
                    .map_err(|_| Error::Conflict)?,
                |facts| {
                    if !facts.same_original(&candidate, &load, original) {
                        return Err(Error::Conflict);
                    }
                    Ok(())
                },
            )
        }
        fn select_terminal_branch(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            retain: &mut dyn FnMut(NativeStartupTerminalBranch<'static>) -> Result<()>,
        ) -> Result<()> {
            let selection = self.terminal_selection.clone();
            selection.run(|| {
                let attempted = self.invocation.attempted(self.create_attempted, self.attach_attempted)
                    .map_err(|_| std::io::Error::other("startup_invocation_mismatch"))?;
                if !attempted {
                    // Issue the actual full Never/SDK/BFE seal, never infer it
                    // from absent fields, nor catch attempted-lane errors here.
                    return self.capture_zero_effect_terminal(original, expected, &mut |proof| {
                        retain(crate::windows::member_carrier_pair_io::OriginalTerminalBranch::ZeroEffect(proof))
                    }).map_err(|_| std::io::Error::other("startup_zero_effect_selection"));
                }
                let proof = Rc::new(NativeStartupAttemptedTerminal {
                    invocation: Rc::downgrade(&self.invocation),
                    create: self.create_attempted,
                    attach: self.attach_attempted,
                    selection: Rc::downgrade(&selection),
                    pair: Rc::downgrade(original),
                    expected: expected.clone(),
                    graph: Rc::downgrade(&self.graph),
                    layout: {
                        let graph = self.graph.try_borrow().map_err(|_| std::io::Error::other("startup_graph_layout"))?;
                        classify_attempted_layout(&self.invocation, self.create_attempted, self.attach_attempted,
                            graph.construction_attempted.get(), self.carrier.as_ref()
                                .and_then(|c| c.retired_pin().ok()).is_some())
                            .map_err(|_| std::io::Error::other("startup_attempted_layout"))?
                    },
                    retired: self.carrier.as_ref().and_then(|c| c.retired_pin().ok()).map(|r| Rc::downgrade(&r)),
                });
                self.attempted_terminal = Some(proof.clone());
                let runtime = self.runtime.clone();
                let supervisor = self.supervisor.clone();
                // SAFETY: SDK-free selection only reads SAME protected Pair /
                // invocation facts and retains a weak original discriminator.
                // No Source, native resource query, storage/native effect or
                // destructor permission is issued by this callback.
                unsafe { supervisor.run_terminal_selection(&self.context, original, expected, || {
                    original.inspect(&runtime, &supervisor, |actual| {
                        if actual != expected { return Err(std::io::Error::other("startup_terminal_foreign")); }
                        // Retain before SDK-free supervisor postflight. The
                        // witness remains unacknowledged until selection.run
                        // finishes, including an external callback Err/unwind.
                        retain(crate::windows::member_carrier_pair_io::OriginalTerminalBranch::NativeAttempted(proof.clone()))
                            .map_err(|_| std::io::Error::other("startup_terminal_retain"))?;
                        self.invocation.attempted(self.create_attempted, self.attach_attempted)
                            .map_err(|_| std::io::Error::other("startup_invocation_changed"))?;
                        Ok(())
                    }).map_err(|_| Error::Conflict)
                }) }.map_err(|_| std::io::Error::other("startup_terminal_selection"))
            }).map_err(|_| Error::Retired)?;
            if let Some(proof) = &self.attempted_terminal {
                proof.original_layout(original, expected)?;
            }
            Ok(())
        }
        fn capture_zero_effect_terminal(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            retain: &mut dyn FnMut(Rc<dyn NativeZeroEffectTerminalProof>) -> Result<()>,
        ) -> Result<()> {
            if self.zero_effect_terminal_attempted {
                if let Some(original) = &self.zero_effect_terminal {
                    // Caught reentry/repeat must invalidate this SAME private
                    // whole-call proof, not merely return a suppressible error.
                    let _ = original
                        .whole
                        .run(|| Err(std::io::Error::other("zero_effect_repeat")));
                }
                return Err(Error::Retired);
            }
            self.zero_effect_terminal_attempted = true;
            if self.create_attempted || self.attach_attempted || self.terminal_attempted {
                return Err(Error::Retired);
            }
            let configuration = compare_zero_effect_terminal_record(&self.context, expected)?;
            let proof = Rc::new(NativeStartupZeroEffectTerminal {
                pair: original.clone(),
                expected: expected.clone(),
                configuration,
                context: self.context.clone(),
                runtime: self.runtime.clone(),
                source: self.source.clone(),
                member_source: self.member_source.clone(),
                supervisor: self.supervisor.clone(),
                never: self.never_effects.as_ref().ok_or(Error::Pending)?.clone(),
                initial_noc: self.initial_noc.as_ref().ok_or(Error::Pending)?.clone(),
                graph: self.graph.clone(),
                store: self.store.clone(),
                whole: crate::windows::member_carrier_terminal_release::TerminalCallState::new(),
                disposal: crate::windows::member_carrier_terminal_release::TerminalCallState::new(),
            });
            self.zero_effect_terminal = Some(proof.clone());
            // The external actor can retain ONLY; verify_original denies until
            // the genuine supervisor's SDK/private-record postflight returns.
            proof
                .whole
                .run(|| {
                    retain(proof.clone())
                        .map_err(|_| std::io::Error::other("zero_effect_retain"))?;
                    self.graph
                        .try_borrow()
                        .map_err(|_| std::io::Error::other("zero_effect_graph"))?
                        .require_pristine()
                        .map_err(|_| std::io::Error::other("zero_effect_graph"))?;
                    let actual = self
                        .verify_uncaptured_terminal_root(original, expected)
                        .map_err(|_| std::io::Error::other("zero_effect_terminal_sdk"))?;
                    compare_uncaptured_terminal_snapshot(&expected.scope, &actual)
                        .map_err(|_| std::io::Error::other("zero_effect_terminal_bfe"))
                })
                .map_err(|_| Error::Retired)?;
            proof.verify_original(original, expected)
        }
        fn dispose_zero_effect_terminal(
            &mut self,
            proof: &Rc<dyn NativeZeroEffectTerminalProof>,
            destination: &mut TerminalStartupResources<'static>,
        ) -> Result<()> {
            let original = self
                .zero_effect_terminal
                .as_ref()
                .ok_or(Error::Pending)?
                .clone();
            let opaque: Rc<dyn NativeZeroEffectTerminalProof> = original.clone();
            if !Rc::ptr_eq(proof, &opaque)
                || self.create_attempted
                || self.attach_attempted
                || !self.terminal_attempted
                || !Rc::ptr_eq(&self.graph, &original.graph)
            {
                return Err(Error::Conflict);
            }
            original.verify_original(&original.pair, &original.expected)?;
            original.disposal.run(|| {
                destination.release_original_with(|raw| {
                    let pins = raw.startup.as_ref().ok_or_else(|| std::io::Error::other("zero_effect_pins"))?;
                    if pins.context != original.context
                        || !Rc::ptr_eq(&pins.runtime, &original.runtime)
                        || !Rc::ptr_eq(&pins.source, &original.source)
                        || !Rc::ptr_eq(&pins.member_source, &original.member_source)
                        || !Rc::ptr_eq(&pins.supervisor, &original.supervisor)
                        || !Rc::ptr_eq(&pins.store, &original.store)
                        || raw.never_effects.as_ref().is_none_or(|n| !Rc::ptr_eq(n, &original.never))
                        || pins.initial_noc.as_ref().is_none_or(|n| !Rc::ptr_eq(n, &original.initial_noc))
                        || raw.pins.is_some() || raw.proof.is_some()
                    {
                        return Err(std::io::Error::other("zero_effect_original"));
                    }
                    self.assembly.as_ref().ok_or_else(|| std::io::Error::other("zero_effect_assembly"))?
                        .verify_initial_noc_terminal_cut(
                            raw.assembly.as_ref().ok_or_else(|| std::io::Error::other("zero_effect_assembly"))?,
                            &original.initial_noc,
                        ).map_err(|_| std::io::Error::other("zero_effect_initial_origin"))?;
                    let ready = raw.carrier.as_ref().ok_or_else(|| std::io::Error::other("zero_effect_ready"))?;
                    self.carrier.as_ref().ok_or_else(|| std::io::Error::other("zero_effect_ready"))?
                        .verify_terminal_drained_into(ready).map_err(|_| std::io::Error::other("zero_effect_ready"))?;
                    ready.verify_zero_effect_terminal(proof.as_ref(), &original.pair, &original.expected)
                        .map_err(|_| std::io::Error::other("zero_effect_ready"))?;
                    raw.graph.as_ref().ok_or_else(|| std::io::Error::other("zero_effect_graph"))?
                        .require_zero_effect_shape().map_err(|_| std::io::Error::other("zero_effect_graph"))?;
                    // All private/SCM/key/full-SDK/BFE reads complete BEFORE the
                    // actual KeyLock is disposed. No Source/image/C is minted.
                    // SAFETY: the SAME private Never ledger, original stopped
                    // pin and actual KeyLock bracket read-only SDK/SCM/48-key
                    // absence checks only; no source/effect/native owner mint.
                    let fresh = unsafe {
                        original.supervisor.run_uncaptured_terminal_read(
                            &original.context, &original.pair, &original.expected, &original.never, || {
                                let mut lock = raw.lock.try_borrow_mut().map_err(|_| Error::Conflict)?;
                                let lock = lock.as_mut().ok_or(Error::Retired)?;
                                if !original.runtime.matches_lock(lock) { return Err(Error::Conflict); }
                                original.never.verify_terminal_original_roots(
                                    &raw.prepared, [None, None],
                                    raw.retired_members.as_deref().ok_or(Error::Pending)?,
                                    &original.runtime, &original.context, &original.expected, &[])?;
                                original.never.verify_uncaptured_terminal_absent(&original.pair, &original.expected, lock)?;
                                let mut guard = crate::windows::member_carrier_guard::ScopedGuardAbsence::open(
                                    original.expected.scope.clone()).map_err(|_| Error::Conflict)?;
                                let before = guard.read_snapshot(&original.expected.scope).map_err(|_| Error::Conflict)?;
                                compare_uncaptured_terminal_snapshot(&original.expected.scope, &before)?;
                                original.never.verify_uncaptured_terminal_absent(&original.pair, &original.expected, lock)?;
                                if guard.read_snapshot(&original.expected.scope).map_err(|_| Error::Conflict)? != before {
                                    return Err(Error::Conflict);
                                }
                                Ok(())
                            })
                    };
                    fresh.map_err(|_| std::io::Error::other("zero_effect_disposal_postflight"))?;
                    original.verify_original(&original.pair, &original.expected)
                        .map_err(|_| std::io::Error::other("zero_effect_original"))
                })
            }).map_err(|_| Error::Retired)?;
            // Retain the SAME typed outcome before fallible owner bookkeeping.
            // Failed/unknown disposal cannot reach this constructor. No DLL
            // existed here; neither ModuleReleased nor a phase/absence flag is
            // fabricated. Later uncertainty still poisons the old owner.
            let outcome = Rc::new(NativeZeroEffectOutcome { original });
            self.zero_effect_outcome = Some(outcome.clone());
            self.initial_data_retirement
                .as_ref()
                .ok_or(Error::Pending)?
                .bind_completed(outcome.clone())?;
            self.supervisor.allow_zero_effect_terminal_drop(&outcome)
        }
        fn drain_terminal_into(
            &mut self,
            destination: &mut TerminalStartupResources<'static>,
        ) -> Result<()> {
            NativeStartupRoot::drain_terminal_into(self, destination)
        }
        fn read_bootstrap_full_empty(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<crate::member_carrier_guard::Snapshot> {
            self.read_bootstrap_full_empty_root(original, expected)
        }
        fn read_bootstrap_no_constructor_cleanup(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<crate::member_carrier_guard::Snapshot> {
            // The original Assembly and actual successful loader authenticate
            // no constructor. No Carrier=None, missing graph or JSON fallback.
            if self.create_attempted {
                return self.read_module_only_cleanup_root(original, expected);
            }
            if self.attach_attempted || self.terminal_attempted {
                return Err(Error::Retired);
            }
            self.bind_initial_noc_cleanup().inspect_err(|error| {
                #[cfg(test)]
                crate::windows::member_carrier_factory_test_os::trace_native("no-C bind", error);
                #[cfg(not(test))]
                let _ = error;
            })?;
            #[cfg(test)]
            if crate::windows::member_carrier_factory_test_os::state().is_some() {
                eprintln!("actual no-C bind completed");
            }
            let never = self.never_effects.as_ref().ok_or(Error::Pending)?.clone();
            let supervisor = self.supervisor.clone();
            let context = self.context.clone();
            // SAFETY: before actual loader/constructor attempts only this
            // original Never ledger can enter the full readonly universe.
            // No attempt flag is reset and no attempted-lane error falls back.
            unsafe {
                supervisor
                    .run_uncaptured_read(&context, original, expected, &never, || {
                        self.continuity_runtime_for(original, expected, StartupRead::Cleanup)
                            .inspect_err(|error| {
                                #[cfg(test)]
                                crate::windows::member_carrier_factory_test_os::trace_native(
                                    "no-C Calling continuity",
                                    error,
                                );
                                #[cfg(not(test))]
                                let _ = error;
                            })?;
                        #[cfg(test)]
                        if crate::windows::member_carrier_factory_test_os::state().is_some() {
                            eprintln!("actual no-C Calling continuity completed");
                        }
                        let lock = self.lock.as_ref().ok_or(Error::Retired)?;
                        let actual = never
                            .read_no_constructor_cleanup(original, expected, lock)
                            .inspect_err(|error| {
                                #[cfg(test)]
                                crate::windows::member_carrier_factory_test_os::trace_native(
                                    "no-C full native read",
                                    error,
                                );
                                #[cfg(not(test))]
                                let _ = error;
                            })?;
                        self.continuity_runtime_for(original, expected, StartupRead::Cleanup)
                            .inspect_err(|error| {
                                #[cfg(test)]
                                crate::windows::member_carrier_factory_test_os::trace_native(
                                    "no-C Calling continuity",
                                    error,
                                );
                                #[cfg(not(test))]
                                let _ = error;
                            })?;
                        Ok(actual)
                    })
                    .inspect_err(|error| {
                        #[cfg(test)]
                        crate::windows::member_carrier_factory_test_os::trace_native(
                            "no-C supervised read",
                            error,
                        );
                        #[cfg(not(test))]
                        let _ = error;
                    })
            }
        }
        fn read_bootstrap_no_constructor_terminal(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<crate::member_carrier_guard::Snapshot> {
            // Terminal facts ONLY. Select by the original actual invocation,
            // never by absent receipts and never by catching an attempted read.
            if expected.phase != pair::Phase::Stopped
                || expected.stop_stage != 12
                || expected.pending.is_some()
            {
                return Err(Error::Conflict);
            }
            if self.create_attempted {
                self.read_module_only_cleanup_root(original, expected)
            } else {
                self.verify_uncaptured_terminal_root(original, expected)
            }
        }
        fn read_bootstrap_native_empty(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<crate::member_carrier_guard::Snapshot> {
            self.read_bootstrap_native_empty_root(original, expected)
        }
        fn verify_uncaptured_terminal(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<()> {
            let actual = self.verify_uncaptured_terminal_root(original, expected)?;
            compare_uncaptured_terminal_snapshot(&expected.scope, &actual)
        }
        fn read_uncaptured_terminal(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<crate::member_carrier_guard::Snapshot> {
            self.verify_uncaptured_terminal_root(original, expected)
        }
        fn preflight_fresh(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<()> {
            macro_rules! reached {
                ($step:literal) => {
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step($step);
                };
            }
            let supervisor = self.supervisor.clone();
            let context = self.context.clone();
            supervisor.run(&context, || {
                reached!("preflight Calling entered");
                begin_native_birth(
                    &mut self.birth_attempted,
                    expected.phase,
                    expected.carrier.is_some(),
                    self.create_attempted,
                )?;
                reached!("preflight birth ordering accepted");
                // Common Starting CAS has already ACKed. Authenticate that
                // SAME actual Pair/Calling before binding; Runtime retains the
                // actual execution root before its fallible view/postflight.
                self.continuity(original, expected)?;
                reached!("preflight current Pair continuity accepted");
                self.runtime
                    .bind_native_execution_birth(&context)
                    .map_err(|_| Error::Conflict)?;
                reached!("preflight original native execution birth retained");
                let canonical = self
                    .runtime
                    .native_birth_files(&context)
                    .map_err(|_| Error::Conflict)?;
                reached!("preflight canonical native birth files returned");
                let initial = self
                    .assembly
                    .as_ref()
                    .ok_or(Error::Pending)?
                    .initial_read_pin()?;
                reached!("preflight initial assembly read retained");
                initial.inspect_initial(&context, |journal, _| {
                    journal
                        .bind_original_native_view(canonical.clone())
                        .map_err(|_| Error::Journal)
                })?;
                reached!("preflight initial assembly canonical view bound");
                self.files = canonical;
                // Store resolves this canonical backend itself, preserving its
                // original writer/receipt and sticky cleanup selection.
                self.preflight_in_call(original, expected)
            })
        }
        fn prepare_member(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            current: &pair::Record,
            proposal: &pair::Record,
            member: &nelomai_client_tunnel::redundancy::protocol::Member,
            native: &str,
        ) -> Result<crate::member_owner::Record> {
            let supervisor = self.supervisor.clone();
            let context = self.context.clone();
            supervisor.run(&context, || {
                #[cfg(test)]
                trace_step("bootstrap member Calling entered");
                // Actor already loaded current and minted THIS original Rc.
                // prepare_in_call reauthenticates the exact store/record under
                // Calling before preparation and again before returning.
                self.prepare_in_call(original, current, proposal, member, native)
            })
        }
        fn prepare_live_member(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            current: &pair::Record,
            proposal: &pair::Record,
            member: &nelomai_client_tunnel::redundancy::protocol::Member,
            native: &str,
            preparation: NativeLiveMemberPreparation<'_>,
        ) -> Result<crate::member_owner::Record> {
            let supervisor = self.supervisor.clone();
            let context = self.context.clone();
            let state = self.live_preparation.clone();
            run_live_preparation(&state, || {
                supervisor.run(&context, || {
                    self.continuity_runtime(original, current)?;
                    if self.lock.is_some()
                        || !self.runtime.matches_lock(preparation.lock)
                        || self.proof.is_none()
                        || current.carrier != self.proof
                        || current.phase != pair::Phase::Running
                        || current.pending.is_some()
                    {
                        return Err(Error::Conflict);
                    }
                    member.validate().map_err(|_| Error::Invalid)?;
                    compare_member_text(
                        &self.context,
                        self.member_source.transport(),
                        None,
                        member.configuration.expose(),
                        native,
                    )?;
                    let slot = crate::member_pair::slot_native(member.slot);
                    let input = NativePreparedMemberInputs {
                        context: self.context.clone(),
                        runtime: self.runtime.read_pin()?,
                        engine: self.engine.clone(),
                        slot,
                        source: self.member_source.clone(),
                        carrier: self.source.clone(),
                        supervisor: supervisor.clone(),
                        never_effects: self.never_effects.as_ref().ok_or(Error::Pending)?.clone(),
                    };
                    let i = usize::from(slot == TunnelSlot::B);
                    let never = input.never_effects.clone();
                    let replacement = preparation.controller.is_some();
                    let mut slots = (self, preparation);
                    prepare_live_generation(
                        &mut slots,
                        replacement,
                        |(startup, preparation)| {
                            let ticket = preparation
                                .controller
                                .as_mut()
                                .ok_or(Error::Pending)?
                                .retire_preparation_generation(
                                    original,
                                    current,
                                    preparation.lock,
                                )?;
                            ticket.verify_original(&never, &startup.runtime, &startup.context)?;
                            Ok(ticket)
                        },
                        |(_, preparation), ticket| {
                            (preparation.after_ticket)(ticket, &never, preparation.lock)
                        },
                        |(startup, preparation), ticket| {
                            NativePreparedMember::retain_closed_generation(
                                &mut startup.prepared[i],
                                preparation.controller,
                                ticket,
                                startup.retired_members.as_mut().ok_or(Error::Retired)?,
                            )
                        },
                        |(startup, preparation)| {
                            NativePreparedMember::prepare(
                                &mut startup.prepared[i],
                                input,
                                member.configuration.expose(),
                                preparation.lock,
                            )?;
                            let prepared = startup.prepared[i].as_mut().ok_or(Error::Pending)?;
                            // Running Attach is NOT the cold Fresh-only proposal.
                            // Join SAME live Source and surviving actual controller.
                            prepared.verify_live_attach_proposal(
                                original,
                                proposal,
                                preparation.source,
                                preparation.other.as_mut().ok_or(Error::Pending)?,
                                preparation.lock,
                            )?;
                            let record = prepared.prepared_record(preparation.lock)?;
                            startup.continuity_runtime(original, current)?;
                            Ok(record)
                        },
                    )
                })
            })
        }
        fn attest_bootstrap(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            effect: pair::Effect,
        ) -> Result<()> {
            if effect != pair::Effect::CarrierReady {
                return Err(Error::Conflict);
            }
            let supervisor = self.supervisor.clone();
            let context = self.context.clone();
            supervisor.run_intent(&context, original, expected, effect, || {
                self.continuity(original, expected)?;
                if expected.phase != pair::Phase::Starting || expected.carrier.is_some() {
                    return Err(Error::Conflict);
                }
                if let Some(proof) = self.proof {
                    self.pins
                        .as_ref()
                        .ok_or(Error::Pending)?
                        .source
                        .inspect_bindings(|bindings| {
                            if bindings.carrier.as_ref().map(|c| c.identity.proof) != Some(proof) {
                                return Err(crate::windows::member_carrier_wintun::Error::Conflict);
                            }
                            Ok(())
                        })
                        .map_err(|_| Error::Conflict)?;
                } else if self.create_attempted {
                    return Err(Error::Retired);
                }
                self.continuity(original, expected)
            })
        }
        fn cleanup_pregraph_carrier(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            effect: pair::Effect,
        ) -> Result<()> {
            // Join the already-existing original-owner method, not a parallel
            // cleanup implementation. It owns the whole Calling and checks
            // private invocation/graph/Runtime/KeyLock before/after effects.
            if expected.pending != Some(effect)
                || expected.carrier.is_none()
                || expected.carrier != self.proof
                || self.pins.is_none()
            {
                return Err(Error::Conflict);
            }
            NativeStartupRoot::cleanup_pregraph_carrier(self, original, expected)
        }
        fn create_ready(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<crate::member_owner::InterfaceProof> {
            NativeStartupRoot::create_ready(self, original, expected)
        }
        fn read_pregraph_closing_cleanup(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<crate::member_carrier_guard::Snapshot> {
            crate::windows::member_carrier_ready::compare_pregraph_closing_frame(
                &self.context,
                expected,
                self.proof.ok_or(Error::Pending)?,
            )?;
            if !self.create_attempted
                || self.attach_attempted
                || self.terminal_attempted
                || !self.invocation.attempted(true, false)?
                || self.pins.is_none()
                || self
                    .retired_members
                    .as_ref()
                    .is_none_or(|members| !members.is_empty())
            {
                return Err(Error::Conflict);
            }
            self.graph
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .require_pristine()?;
            let supervisor = self.supervisor.clone();
            let context = self.context.clone();
            let runtime = self.runtime.clone();
            let never = self.never_effects.as_ref().ok_or(Error::Pending)?.clone();
            supervisor.run_cleanup(&context, original, || {
                self.continuity_runtime_for(original, expected, StartupRead::Cleanup)?;
                if !runtime.matches_lock(self.lock.as_ref().ok_or(Error::Retired)?) {
                    return Err(Error::Conflict);
                }
                self.graph
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .require_pristine()?;
                let prepared = &self.prepared;
                let mut guard = crate::windows::member_carrier_guard::ScopedGuardAbsence::open(
                    expected.scope.clone(),
                )
                .map_err(|_| Error::Conflict)?;
                let actual = self
                    .carrier
                    .as_mut()
                    .ok_or(Error::Pending)?
                    .inspect_pregraph_closing_in_call(original, expected, |_| {
                        let verify = || {
                            never.verify_pregraph_closing_originals(
                                prepared, &runtime, &context, expected,
                            )
                        };
                        verify()?;
                        let before = guard
                            .read_snapshot(&expected.scope)
                            .map_err(|_| Error::Conflict)?;
                        verify()?;
                        if before != expected.guard.expected
                            || guard
                                .read_snapshot(&expected.scope)
                                .map_err(|_| Error::Conflict)?
                                != before
                        {
                            return Err(Error::Conflict);
                        }
                        verify()?;
                        Ok(before)
                    })?;
                self.graph
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .require_pristine()?;
                if !runtime.matches_lock(self.lock.as_ref().ok_or(Error::Retired)?) {
                    return Err(Error::Conflict);
                }
                self.continuity_runtime_for(original, expected, StartupRead::Cleanup)?;
                Ok(actual)
            })
        }
        fn restore_pregraph_keys(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<()> {
            // Before and after reads are independent whole Calling intervals.
            // The original key owner performs real restoration OUTSIDE the
            // immutable SDK read bracket, authenticating each effect itself.
            self.read_pregraph_key_restore_root(original, expected, Some(false))?;
            let supervisor = self.supervisor.clone();
            let context = self.context.clone();
            supervisor.run_cleanup(&context, original, || {
                self.continuity_runtime_for(original, expected, StartupRead::Cleanup)?;
                self.graph
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .require_pristine()?;
                let lock = self.lock.as_mut().ok_or(Error::Retired)?;
                if !self.runtime.matches_lock(lock) {
                    return Err(Error::Conflict);
                }
                let assembly = self.assembly.as_mut().ok_or(Error::Pending)?;
                let (owner, _) = assembly.retained_parts();
                let owner = owner.as_mut().ok_or(Error::Pending)?;
                let current = owner.snapshot()?.ok_or(Error::Pending)?;
                if current.context != context {
                    return Err(Error::Conflict);
                }
                owner.cleanup(&current, lock)?;
                self.graph
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .require_pristine()?;
                self.continuity_runtime_for(original, expected, StartupRead::Cleanup)
            })?;
            self.read_pregraph_key_restore_root(original, expected, Some(true))
                .map(|_| ())
        }
        fn read_pregraph_key_restore(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
        ) -> Result<crate::member_carrier_guard::Snapshot> {
            self.read_pregraph_key_restore_root(original, expected, None)
        }
        fn attach_full(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            retain: &mut dyn FnMut(NativeActorInputs<'static>) -> Result<()>,
        ) -> Result<()> {
            self.invocation.begin(true)?;
            self.attach_attempted = true;
            let supervisor = self.supervisor.clone();
            let context = self.context.clone();
            supervisor.run(&context, || self.attach_in_call(original, expected, retain))
        }
        fn attach_member(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            slot: nelomai_client_tunnel::redundancy::Slot,
            attachment: NativeMemberAttachment<actor::MemberGate>,
            destination: &mut Option<actor::Controller>,
            lock: &mut KeyLock,
        ) -> Result<()> {
            self.continuity_runtime(original, expected)?;
            if !self.runtime.matches_lock(lock) {
                return Err(Error::Conflict);
            }
            self.prepared[usize::from(slot == nelomai_client_tunnel::redundancy::Slot::B)]
                .as_mut()
                .ok_or(Error::Pending)?
                .attach(destination, attachment, original, expected, lock)?;
            self.continuity_runtime(original, expected)
        }
        fn verify_unstarted_member(
            &mut self,
            original: &Rc<NativePairIntentRead>,
            expected: &pair::Record,
            slot: nelomai_client_tunnel::redundancy::Slot,
            closing: Option<&Rc<crate::windows::member_carrier_runtime::native::NativeClosingRead>>,
            actor_lock: Option<&mut KeyLock>,
        ) -> Result<()> {
            let i = usize::from(slot == nelomai_client_tunnel::redundancy::Slot::B);
            if let Some(lock) = actor_lock {
                self.continuity_runtime_for(original, expected, StartupRead::Cleanup)?;
                if self.lock.is_some() || !self.runtime.matches_lock(lock) || closing.is_none() {
                    return Err(Error::Conflict);
                }
                if let Some(prepared) = self.prepared[i].as_mut() {
                    prepared.verify_unstarted_absent(
                        original,
                        expected,
                        closing.map(Rc::as_ref),
                        lock,
                    )?;
                } else {
                    // Empty slot is not an ACK: require the actual factory
                    // never-attempted history plus its private/SCM/key/SDK
                    // absence bracket, joined to the SAME Closing C reader.
                    self.never_effects
                        .as_ref()
                        .ok_or(Error::Pending)?
                        .verify_uncaptured_member_absent(
                            original,
                            expected,
                            crate::member_pair::slot_native(slot),
                            closing.map(Rc::as_ref),
                            lock,
                        )?;
                }
                self.continuity_runtime_for(original, expected, StartupRead::Cleanup)
            } else {
                if closing.is_some() || self.attach_attempted {
                    return Err(Error::Conflict);
                }
                let supervisor = self.supervisor.clone();
                let context = self.context.clone();
                let never = self.never_effects.as_ref().ok_or(Error::Pending)?.clone();
                let attempted = self.create_attempted;
                if !attempted {
                    self.bind_initial_noc_cleanup()?;
                }
                let read = || {
                    self.continuity_runtime_for(original, expected, StartupRead::Cleanup)?;
                    if !self
                        .runtime
                        .matches_lock(self.lock.as_ref().ok_or(Error::Retired)?)
                    {
                        return Err(Error::Conflict);
                    }
                    if let Some(prepared) = self.prepared[i].as_mut() {
                        prepared.verify_unstarted_absent(
                            original,
                            expected,
                            None,
                            self.lock.as_mut().ok_or(Error::Retired)?,
                        )?;
                    } else {
                        self.never_effects
                            .as_ref()
                            .ok_or(Error::Pending)?
                            .verify_before_carrier_absent(
                                original,
                                expected,
                                crate::member_pair::slot_native(slot),
                                self.lock.as_mut().ok_or(Error::Retired)?,
                            )?;
                    }
                    self.continuity_runtime_for(original, expected, StartupRead::Cleanup)
                };
                if attempted {
                    supervisor.run_cleanup(&context, original, read)
                } else {
                    // No effects allowed here. The actual factory ledger and
                    // exact Closing ACK authenticate pre-entry; the callback
                    // performs complete private/SCM/key/SDK absence in Calling.
                    unsafe {
                        supervisor.run_uncaptured_read(&context, original, expected, &never, read)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "member_carrier_startup_tests.rs"]
mod tests;
