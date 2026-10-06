//! Independent factual member inventory. No service creation/effect authority.
#![allow(dead_code)]

#[cfg(windows)]
use super::member_carrier_provider::{ExpectedProvider, ProviderKind};
#[cfg(windows)]
use super::member_carrier_wintun_package::Device as PackageDevice;
use crate::member_carrier::{CarrierError as Error, Result};
use crate::member_carrier_native_ownership::{Context, Role};
#[cfg(not(windows))]
use crate::member_carrier_provider::{ExpectedProvider, ProviderKind};
#[cfg(not(windows))]
use crate::member_carrier_wintun_package::Device as PackageDevice;
use crate::member_owner::{Intent, NativeProof};
use nelomai_client_tunnel::TunnelTransport;
use nelomai_contracts::dispatcher::TunnelSlot;
use std::cell::Cell;

/// Comparison DATA only. Actual original old/new process ACKs and full
/// private/SDK brackets are mandatory before inventory renewal.
pub(crate) fn rebind_registration(
    context: &Context,
    native: crate::member_carrier_native_ownership::Phase,
    record: &crate::member_carrier_pair::Record,
    index: usize,
) -> Result<()> {
    use crate::{member_carrier_native_ownership::Phase, member_carrier_pair as pair};
    use nelomai_client_tunnel::redundancy::Slot;
    let slot = match index {
        0 => Slot::A,
        1 => Slot::B,
        _ => return Err(Error::Conflict),
    };
    record.validate().map_err(|_| Error::Conflict)?;
    if native != Phase::Preparing
        || record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || record.phase != pair::Phase::Running
        || record.operation != Some(pair::Operation::Rebind)
        || record.pending != Some(pair::Effect::Rebind(slot))
        || record.stop_stage != 0
        || record.guard.permits
        || record.pending_guard.is_some()
        || record
            .carrier
            .is_none_or(|c| c.guid != context.bindings[0].guid)
        || record.members.iter().any(|m| {
            m.as_ref().is_none_or(|m| {
                m.owner.phase != crate::member_owner::Phase::Running || m.owner.proof.is_none()
            })
        })
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Publication comparison only; the native caller additionally authenticates
/// the SAME opaque Pair pin, runtime and original member Stop receipt.
pub(crate) fn retirement_registration(
    context: &Context,
    native: crate::member_carrier_native_ownership::Phase,
    record: &crate::member_carrier_pair::Record,
    index: usize,
) -> Result<()> {
    use crate::{member_carrier_native_ownership::Phase, member_carrier_pair as pair};
    use nelomai_client_tunnel::redundancy::Slot;
    record.validate().map_err(|_| Error::Conflict)?;
    let slot = match index {
        0 => Slot::A,
        1 => Slot::B,
        _ => return Err(Error::Conflict),
    };
    let other = 1 - index;
    if native != Phase::Preparing
        || record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || record.phase != pair::Phase::Running
        || record.stop_stage != 0
        || record.operation != Some(pair::Operation::Retire(slot))
        || record.pending != Some(pair::Effect::MemberStop(slot))
        || record.active != Some(if index == 0 { Slot::B } else { Slot::A })
        || record.members[index]
            .as_ref()
            .is_none_or(|m| m.owner.proof.is_none())
        || record.members[other].as_ref().is_none_or(|m| {
            m.owner.phase != crate::member_owner::Phase::Running || m.owner.proof.is_none()
        })
        || record.guard.permits
        || record.pending_guard.is_some()
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Selection DATA only. Native absence still requires full MIB/PnP/stack reads.
pub(crate) fn completed_retirement_registration(
    context: &Context,
    native: crate::member_carrier_native_ownership::Phase,
    record: &crate::member_carrier_pair::Record,
    index: usize,
) -> Result<()> {
    use crate::{member_carrier_native_ownership::Phase, member_carrier_pair as pair};
    use nelomai_client_tunnel::redundancy::Slot;
    record.validate().map_err(|_| Error::Conflict)?;
    let active = match index {
        0 => Slot::B,
        1 => Slot::A,
        _ => return Err(Error::Conflict),
    };
    if native != Phase::Preparing
        || record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || record.phase != pair::Phase::Running
        || record.stop_stage != 0
        || record.pending.is_some()
        || record.operation.is_some()
        || record.pending_guard.is_some()
        || record.active != Some(active)
        || record.members[index].is_some()
        || record.guard.members[index].is_some()
        || record
            .carrier
            .is_none_or(|c| c.guid != context.bindings[0].guid)
        || record.members[1 - index].as_ref().is_none_or(|m| {
            m.owner.phase != crate::member_owner::Phase::Running || m.owner.proof.is_none()
        })
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Selection DATA only. Native absence still requires full MIB/PnP/stack reads.
pub(crate) fn key_provider_inputs(
    context: &Context,
    carrier: &[ExpectedProvider],
    members: &[ExpectedProvider],
    closing: bool,
    target: &crate::member_carrier_native_ownership::Binding,
) -> Result<Vec<ExpectedProvider>> {
    let inputs = complete_provider_inputs(context, carrier, members)?;
    if !context.bindings.contains(target)
        || closing && !inputs.is_empty()
        || inputs.iter().any(|p| {
            p.identity.guid == target.guid || p.identity.name.eq_ignore_ascii_case(&target.name)
        })
    {
        return Err(Error::Conflict);
    }
    Ok(inputs)
}

/// Package DATA projection after independent FULL mixed original verification.
/// The caller MUST retain/query all actual owners; this helper grants no rights.
pub(crate) fn package_devices(
    kinds: &[ProviderKind],
    devices: &[PackageDevice],
) -> Result<Vec<PackageDevice>> {
    if kinds.len() != devices.len() || kinds.len() > 3 {
        return Err(Error::Conflict);
    }
    let mut result = Vec::new();
    for (index, (kind, device)) in kinds.iter().zip(devices).enumerate() {
        let prefix = match kind {
            ProviderKind::Wintun => r"SWD\WINTUN\{",
            ProviderKind::WireGuardNt => r"SWD\WIREGUARD\{",
        };
        let upper = device.instance.to_ascii_uppercase();
        let guid = upper
            .strip_prefix(prefix)
            .and_then(|v| v.strip_suffix('}'))
            .ok_or(Error::Conflict)?;
        if guid.len() != 36
            || guid.bytes().enumerate().any(|(i, byte)| {
                if [8, 13, 18, 23].contains(&i) {
                    byte != b'-'
                } else {
                    !byte.is_ascii_hexdigit()
                }
            })
            || !guid.bytes().any(|v| v.is_ascii_hexdigit() && v != b'0')
            || device.problem != 0
            || device.status & 8 == 0
            || device.status & 0x8044_8420 != 0
            || devices[..index]
                .iter()
                .any(|old| old.instance.eq_ignore_ascii_case(&device.instance))
        {
            return Err(Error::Conflict);
        }
        if *kind == ProviderKind::Wintun {
            result.push(device.clone());
        }
    }
    Ok(result)
}

/// Irreversible observation failure, not ownership/effect authority. Cleanup
/// has a separate factual path and can never clear this forward-read fence.
#[derive(Default)]
struct ReadHealth {
    revoked: Cell<bool>,
    busy: Cell<bool>,
    tainted: Cell<bool>,
}
struct ReadAttempt<'a> {
    health: &'a ReadHealth,
    complete: bool,
}
/// Spans separate stable Source callbacks without borrowing/reentering their
/// shared inventory. Unknown unwind must retain roots and deny forward use.
struct RetirementFlight<'a> {
    health: &'a ReadHealth,
    complete: bool,
}
impl Drop for RetirementFlight<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.health.revoked.set(true);
        }
    }
}
impl Drop for ReadAttempt<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.health.revoked.set(true);
        }
        self.health.busy.set(false);
    }
}
impl ReadHealth {
    fn observe<T>(
        &self,
        mode: impl FnOnce() -> Result<bool>,
        read: impl FnOnce(bool) -> Result<T>,
    ) -> Result<T> {
        if self.busy.replace(true) {
            self.revoked.set(true);
            self.tainted.set(true);
            return Err(Error::Conflict);
        }
        self.tainted.set(false);
        let mut attempt = ReadAttempt {
            health: self,
            complete: false,
        };
        // The initial expensive phase/runtime read is INSIDE the failure guard.
        let cleanup = mode()?;
        if cleanup {
            self.revoked.set(true);
        }
        if self.tainted.get() || !cleanup && self.revoked.get() {
            return Err(Error::Conflict);
        }
        let facts = read(cleanup)?;
        if self.tainted.get() || !cleanup && self.revoked.get() {
            return Err(Error::Conflict);
        }
        attempt.complete = true;
        Ok(facts)
    }
    fn forward<T>(&self, read: impl FnOnce() -> Result<T>) -> Result<T> {
        self.observe(|| Ok(false), |_| read())
    }
    fn cleanup<T>(&self, read: impl FnOnce() -> Result<T>) -> Result<T> {
        self.observe(|| Ok(true), |_| read())
    }
}

fn validate_member_binding(
    context: &Context,
    intent: &Intent,
    proof: &NativeProof,
    provider: &ExpectedProvider,
) -> Result<usize> {
    let index = match intent.slot {
        TunnelSlot::A => 0,
        TunnelSlot::B => 1,
    };
    let binding = &context.bindings[index + 1];
    let kind = match intent.transport {
        TunnelTransport::WireGuard => ProviderKind::WireGuardNt,
        TunnelTransport::AmneziaWg3 => ProviderKind::Wintun,
    };
    if context.intent.scope != intent.scope
        || proof.process.pid == 0
        || proof.process.creation_time == 0
        || provider.kind != kind
        || provider.identity.guid != binding.guid
        || provider.identity.guid != proof.interface.guid
        || provider.identity.luid != proof.interface.luid
        || provider.identity.index != proof.interface.index
        || provider.identity.index == 0
        || provider.identity.name != binding.name
        || provider.identity.if_type != 53
        || provider.identity.tunnel_type != 0
        || context.bindings.iter().enumerate().any(|(n, b)| {
            b.role != [Role::RoleCarrier, Role::MemberA, Role::MemberB][n]
                || b.guid == [0; 16]
                || context.bindings[..n]
                    .iter()
                    .any(|old| old.guid == b.guid || old.name.eq_ignore_ascii_case(&b.name))
        })
    {
        return Err(Error::Conflict);
    }
    Ok(index)
}

/// Retired comparison DATA from the actual retained reader/receipt and the
/// provider captured while live. No lookup/reconstruction of a removed NIC.
fn closed_member_history<J: crate::member_owner::Journal, I: crate::member_owner::MemberIo>(
    context: &Context,
    index: usize,
    original: &mut crate::member_original::OriginalMemberRead<J, I>,
    receipt: &crate::member_original::ClosedMemberReceipt<J, I>,
    captured: &ExpectedProvider,
) -> Result<(Intent, ExpectedProvider)> {
    let (intent, proof) = original
        .read_closed_history(receipt)
        .map_err(|_| Error::Conflict)?;
    if validate_member_binding(context, &intent, &proof, captured)? != index {
        return Err(Error::Conflict);
    }
    Ok((intent, captured.clone()))
}

struct RetainedEntry<J, I, S> {
    source: S,
    original: crate::member_original::OriginalMemberRead<J, I>,
    provider: ExpectedProvider,
    closed: Option<std::rc::Rc<crate::member_original::ClosedMemberReceipt<J, I>>>,
}

/// Original owner receipt captured BEFORE any Start effect or Running reader.
struct PendingEntry<J, I, S> {
    source: S,
    original: crate::member_original::PendingMemberRead<J, I>,
    captured: Option<ExpectedProvider>,
    closed: Option<std::rc::Rc<crate::member_original::ClosedMemberReceipt<J, I>>>,
}

/// Actual old-process roots after SAME-owner rebind. They remain inert and
/// never enter current provider queries or reread a replaced private journal.
struct ReboundInventoryEntry<J, I, S> {
    receipt: std::rc::Rc<crate::member_original::ClosedOldProcessReceipt<J, I>>,
    entry: RetainedEntry<J, I, S>,
    pending: Option<PendingEntry<J, I, S>>,
}

struct ReboundInputs<J, I, S> {
    source: S,
    original: crate::member_original::OriginalMemberRead<J, I>,
    pending: crate::member_original::PendingMemberRead<J, I>,
    receipt: std::rc::Rc<crate::member_original::ClosedOldProcessReceipt<J, I>>,
}

/// SAME opaque receipt -> retired and replacement reader provenance, not equal
/// saved proofs. Caller independently brackets full native/provider/private
/// state. Retain old roots BEFORE postflight; failure cannot erase obligations.
fn renew_rebound_entry<
    J: crate::member_owner::Journal,
    I: crate::member_owner::MemberIo,
    S: Clone,
>(
    context: &Context,
    entries: &mut [Option<RetainedEntry<J, I, S>>; 2],
    pending: &mut [Option<PendingEntry<J, I, S>>; 2],
    history: &mut Vec<ReboundInventoryEntry<J, I, S>>,
    mut input: ReboundInputs<J, I, S>,
    same_source: impl Fn(&S, &S) -> bool,
    mut verify: impl FnMut(&S, &Intent, &NativeProof) -> Result<()>,
) -> Result<usize> {
    let receipt = &input.receipt;
    receipt
        .verify_replacement_original_read(&input.original)
        .map_err(|_| Error::Conflict)?;
    receipt
        .verify_replacement_pending_read(&input.pending)
        .map_err(|_| Error::Conflict)?;
    if !input.pending.matches_live(&input.original) {
        return Err(Error::Conflict);
    }
    let (intent, proof) = input.original.read().map_err(|_| Error::Conflict)?;
    let running = receipt.running_record();
    if running.phase != crate::member_owner::Phase::Running
        || running.intent != intent
        || running.proof != Some(proof)
        || running
            .retired_proof
            .is_none_or(|old| old.interface != proof.interface || old.process == proof.process)
    {
        return Err(Error::Conflict);
    }
    let index = pending_index(context, &intent)?;
    let prior = entries[index].as_ref().ok_or(Error::Conflict)?;
    if prior.closed.is_some() || !same_source(&prior.source, &input.source) {
        return Err(Error::Conflict);
    }
    receipt
        .verify_retired_original_read(&prior.original)
        .map_err(|_| Error::Conflict)?;
    if validate_member_binding(context, &intent, &proof, &prior.provider)? != index {
        return Err(Error::Conflict);
    }
    if let Some(old) = &pending[index] {
        if old.closed.is_some()
            || !same_source(&old.source, &input.source)
            || old.captured.as_ref().is_some_and(|p| p != &prior.provider)
        {
            return Err(Error::Conflict);
        }
        receipt
            .verify_retired_pending_read(&old.original)
            .map_err(|_| Error::Conflict)?;
    }
    verify(&input.source, &intent, &proof)?;
    if input.original.read().map_err(|_| Error::Conflict)? != (intent.clone(), proof) {
        return Err(Error::Conflict);
    }
    history.try_reserve(1).map_err(|_| Error::Pending)?;
    let provider = prior.provider.clone();
    let source = input.source.clone();
    let new_pending = PendingEntry {
        source: input.source,
        original: input.pending,
        captured: Some(provider.clone()),
        closed: None,
    };
    // Caller supplies no clonable native owner. Source clones retain only the
    // same signed source pins, never SCM/process mutation authority.
    let old = entries[index].take().ok_or(Error::Conflict)?;
    history.push(ReboundInventoryEntry {
        receipt: input.receipt,
        entry: old,
        pending: pending[index].take(),
    });
    pending[index] = Some(new_pending);
    entries[index] = Some(RetainedEntry {
        source,
        original: input.original,
        provider,
        closed: None,
    });
    let current = entries[index].as_mut().ok_or(Error::Conflict)?;
    verify(&current.source, &intent, &proof)?;
    if current.original.read().map_err(|_| Error::Conflict)? != (intent, proof) {
        return Err(Error::Conflict);
    }
    Ok(index)
}

/// Inert historical roots kept after an explicitly acknowledged generation
/// transition. Neither entry participates in current SDK/provider reads.
struct RetiredInventoryEntry<J, I, S> {
    original: std::rc::Rc<crate::member_original::RetiredMemberGeneration<J, I>>,
    receipt: std::rc::Rc<crate::member_original::ClosedMemberReceipt<J, I>>,
    entry: Option<RetainedEntry<J, I, S>>,
    pending: Option<PendingEntry<J, I, S>>,
}

fn retire_closed_entries<J: crate::member_owner::Journal, I: crate::member_owner::MemberIo, S>(
    context: &Context,
    index: usize,
    entries: &mut [Option<RetainedEntry<J, I, S>>; 2],
    pending: &mut [Option<PendingEntry<J, I, S>>; 2],
    retired: &mut Vec<RetiredInventoryEntry<J, I, S>>,
    original: &std::rc::Rc<crate::member_original::RetiredMemberGeneration<J, I>>,
    receipt: &std::rc::Rc<crate::member_original::ClosedMemberReceipt<J, I>>,
) -> Result<()> {
    use std::rc::Rc;
    let (intent, proof) = original
        .read_history(receipt)
        .map_err(|_| Error::Conflict)?;
    if pending_index(context, &intent)? != index {
        return Err(Error::Conflict);
    }
    if let Some(prior) = retired
        .iter()
        .find(|old| Rc::ptr_eq(&old.original, original))
    {
        if !Rc::ptr_eq(&prior.receipt, receipt)
            || entries[index].is_some()
            || pending[index].is_some()
        {
            return Err(Error::Conflict);
        }
        // Retry the same inert root only, without querying a private journal
        // which may already belong to a separately authorized next generation.
        return Ok(());
    }
    if entries[index].is_none() && pending[index].is_none() {
        return Err(Error::Conflict);
    }
    if let Some(entry) = &entries[index] {
        if entry
            .closed
            .as_ref()
            .is_none_or(|closed| !Rc::ptr_eq(closed, receipt))
        {
            return Err(Error::Conflict);
        }
        original
            .verify_live_reader(&entry.original)
            .map_err(|_| Error::Conflict)?;
        if validate_member_binding(
            context,
            &intent,
            &proof.ok_or(Error::Conflict)?,
            &entry.provider,
        )? != index
        {
            return Err(Error::Conflict);
        }
    }
    if let Some(entry) = &pending[index] {
        if entry
            .closed
            .as_ref()
            .is_none_or(|closed| !Rc::ptr_eq(closed, receipt))
        {
            return Err(Error::Conflict);
        }
        original
            .verify_pending_reader(&entry.original)
            .map_err(|_| Error::Conflict)?;
        if let Some(captured) = &entry.captured {
            if validate_member_binding(context, &intent, &proof.ok_or(Error::Conflict)?, captured)?
                != index
            {
                return Err(Error::Conflict);
            }
        }
    }
    // Allocate BEFORE removing either old root. No fallible step between moves
    // and retention. Later native/protected postflight may fail without losing
    // the original service/process owner or its exact closure ACK.
    retired.try_reserve(1).map_err(|_| Error::Pending)?;
    retired.push(RetiredInventoryEntry {
        original: original.clone(),
        receipt: receipt.clone(),
        entry: entries[index].take(),
        pending: pending[index].take(),
    });
    Ok(())
}

/// Comparison-only identity retired by an exact original Stop receipt.
/// Distinct from live SDK provider input; no removed NIC metadata is queried.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClosedMemberBinding {
    pub intent: Intent,
    pub proof: NativeProof,
}
impl ClosedMemberBinding {
    pub(crate) fn comparison_provider(&self, context: &Context) -> Result<ExpectedProvider> {
        let index = pending_index(context, &self.intent)?;
        let provider = ExpectedProvider {
            kind: match self.intent.transport {
                TunnelTransport::WireGuard => ProviderKind::WireGuardNt,
                TunnelTransport::AmneziaWg3 => ProviderKind::Wintun,
            },
            identity: {
                #[cfg(windows)]
                use super::member_carrier_provider::Expected;
                #[cfg(not(windows))]
                use crate::member_carrier_provider::Expected;
                Expected {
                    guid: self.proof.interface.guid,
                    luid: self.proof.interface.luid,
                    index: self.proof.interface.index,
                    name: context.bindings[index + 1].name.clone(),
                    description: String::new(),
                    if_type: 53,
                    tunnel_type: 0,
                }
            },
        };
        validate_member_binding(context, &self.intent, &self.proof, &provider)?;
        Ok(provider)
    }
}
fn read_mixed_closed_bindings<
    J: crate::member_owner::Journal,
    I: crate::member_owner::MemberIo,
    S,
>(
    context: &Context,
    entries: &mut [Option<RetainedEntry<J, I, S>>; 2],
    pending: &mut [Option<PendingEntry<J, I, S>>; 2],
    mut verify: impl FnMut(&S, Option<&Intent>) -> Result<()>,
) -> Result<Vec<ClosedMemberBinding>> {
    let mut result = Vec::new();
    for (index, entry) in entries.iter_mut().enumerate() {
        let Some(entry) = entry else { continue };
        let Some(receipt) = &entry.closed else {
            continue;
        };
        verify(&entry.source, None)?;
        let (intent, proof) = entry
            .original
            .read_closed_history(receipt)
            .map_err(|_| Error::Pending)?;
        if validate_member_binding(context, &intent, &proof, &entry.provider)? != index {
            return Err(Error::Conflict);
        }
        verify(&entry.source, Some(&intent))?;
        if entry
            .original
            .read_closed_history(receipt)
            .map_err(|_| Error::Pending)?
            != (intent.clone(), proof)
        {
            return Err(Error::Conflict);
        }
        result.push(ClosedMemberBinding { intent, proof });
    }
    for (index, entry) in pending.iter_mut().enumerate() {
        if entries[index].is_some() {
            continue;
        };
        let Some(entry) = entry else { continue };
        let Some(receipt) = &entry.closed else {
            continue;
        };
        if pending_index(context, entry.original.intent())? != index {
            return Err(Error::Conflict);
        }
        verify(&entry.source, None)?;
        let proof = entry
            .original
            .read_closed_proof(receipt)
            .map_err(|_| Error::Pending)?;
        verify(&entry.source, Some(entry.original.intent()))?;
        if let Some((intent, proof)) = &proof {
            let history = ClosedMemberBinding {
                intent: intent.clone(),
                proof: *proof,
            };
            history.comparison_provider(context)?;
            if let Some(captured) = &entry.captured {
                if validate_member_binding(context, intent, proof, captured)? != index {
                    return Err(Error::Conflict);
                }
            }
            result.push(history);
        }
        if entry
            .original
            .read_closed_proof(receipt)
            .map_err(|_| Error::Pending)?
            != proof
        {
            return Err(Error::Conflict);
        }
    }
    Ok(result)
}
type MixedClosingSample = (Vec<u8>, Vec<ExpectedProvider>, Vec<ClosedMemberBinding>);
fn read_terminal_closed_bindings<
    J: crate::member_owner::Journal,
    I: crate::member_owner::MemberIo,
    S,
>(
    context: &Context,
    entries: &mut [Option<RetainedEntry<J, I, S>>; 2],
    pending: &mut [Option<PendingEntry<J, I, S>>; 2],
    mut verify: impl FnMut(&S, Option<&Intent>) -> Result<()>,
) -> Result<Vec<ClosedMemberBinding>> {
    for index in 0..2 {
        if entries[index]
            .as_ref()
            .is_some_and(|entry| entry.closed.is_none())
        {
            return Err(Error::Pending);
        }
        if let Some(entry) = &mut pending[index] {
            let receipt = entry.closed.as_ref().ok_or(Error::Pending)?;
            if pending_index(context, entry.original.intent())? != index {
                return Err(Error::Conflict);
            }
            if let Some(live) = &entries[index] {
                if !entry.original.matches_live(&live.original)
                    || live
                        .closed
                        .as_ref()
                        .is_none_or(|ack| !std::rc::Rc::ptr_eq(ack, receipt))
                {
                    return Err(Error::Conflict);
                }
            }
            verify(&entry.source, Some(entry.original.intent()))?;
            let before = entry
                .original
                .read_closed(receipt)
                .map_err(|_| Error::Pending)?;
            verify(&entry.source, Some(entry.original.intent()))?;
            if entry
                .original
                .read_closed(receipt)
                .map_err(|_| Error::Pending)?
                != before
            {
                return Err(Error::Conflict);
            }
        }
    }
    read_mixed_closed_bindings(context, entries, pending, verify)
}

fn inspect_mixed_closing_with<T>(
    mut read: impl FnMut() -> Result<MixedClosingSample>,
    mut query: impl FnMut(&[ExpectedProvider]) -> Result<()>,
    inspect: impl FnOnce(&[ExpectedProvider], &[ClosedMemberBinding]) -> Result<T>,
) -> Result<T> {
    let before = read()?;
    query(&before.1)?;
    let facts = inspect(&before.1, &before.2)?;
    query(&before.1)?;
    if read()? != before {
        return Err(Error::Conflict);
    }
    Ok(facts)
}
fn retain_pending<J: crate::member_owner::Journal, I: crate::member_owner::MemberIo, S>(
    context: &Context,
    entries: &mut [Option<PendingEntry<J, I, S>>; 2],
    source: S,
    original: crate::member_original::PendingMemberRead<J, I>,
    same_source: impl Fn(&S, &S) -> bool,
    mut verify: impl FnMut(&S, &Intent) -> Result<()>,
) -> Result<()> {
    let index = pending_index(context, original.intent())?;
    verify(&source, original.intent())?;
    if let Some(prior) = &entries[index] {
        if !same_source(&prior.source, &source)
            || !prior.original.same_original(&original)
            || prior.closed.is_some()
        {
            return Err(Error::Conflict);
        }
    } else {
        // Root the FIRST actual receipt before any fallible publication read.
        entries[index] = Some(PendingEntry {
            source,
            original,
            captured: None,
            closed: None,
        });
    }
    let entry = entries[index].as_ref().ok_or(Error::Pending)?;
    verify(&entry.source, entry.original.intent())
}
fn pending_index(context: &Context, intent: &Intent) -> Result<usize> {
    let index = match intent.slot {
        TunnelSlot::A => 0,
        TunnelSlot::B => 1,
    };
    if intent.scope != context.intent.scope
        || context.bindings[index + 1].role != [Role::MemberA, Role::MemberB][index]
    {
        return Err(Error::Conflict);
    }
    Ok(index)
}
fn publish_pending_closed<J: crate::member_owner::Journal, I: crate::member_owner::MemberIo, S>(
    context: &Context,
    entries: &mut [Option<PendingEntry<J, I, S>>; 2],
    index: usize,
    receipt: &std::rc::Rc<crate::member_original::ClosedMemberReceipt<J, I>>,
    mut verify: impl FnMut(&S, &Intent) -> Result<()>,
) -> Result<()> {
    let entry = entries
        .get_mut(index)
        .and_then(Option::as_mut)
        .ok_or(Error::Conflict)?;
    if pending_index(context, entry.original.intent())? != index
        || entry
            .closed
            .as_ref()
            .is_some_and(|old| !std::rc::Rc::ptr_eq(old, receipt))
    {
        return Err(Error::Conflict);
    }
    verify(&entry.source, entry.original.intent())?;
    let stopped = entry
        .original
        .read_closed(receipt)
        .map_err(|_| Error::Pending)?;
    if stopped.intent != *entry.original.intent() {
        return Err(Error::Conflict);
    }
    entry.closed = Some(receipt.clone());
    verify(&entry.source, &stopped.intent)?;
    entry
        .original
        .read_closed(receipt)
        .map_err(|_| Error::Pending)?;
    Ok(())
}

fn read_pending_members<J: crate::member_owner::Journal, I: crate::member_owner::MemberIo, S>(
    context: &Context,
    entries: &mut [Option<PendingEntry<J, I, S>>; 2],
    registered: [bool; 2],
    cleanup: bool,
    history: bool,
    verify: impl FnMut(&S, &Intent) -> Result<()>,
    identity: impl FnMut(&S, &NativeProof) -> Result<ExpectedProvider>,
) -> Result<Vec<ExpectedProvider>> {
    read_pending_members_excluding(
        context,
        entries,
        registered,
        (cleanup, history, None),
        verify,
        identity,
    )
}

/// Selection only: native caller must authenticate the SAME opaque partial
/// service pin before selecting an exclusion. All ordinary readers use None.
fn read_pending_members_excluding<
    J: crate::member_owner::Journal,
    I: crate::member_owner::MemberIo,
    S,
>(
    context: &Context,
    entries: &mut [Option<PendingEntry<J, I, S>>; 2],
    registered: [bool; 2],
    channel: (bool, bool, Option<usize>),
    mut verify: impl FnMut(&S, &Intent) -> Result<()>,
    mut identity: impl FnMut(&S, &NativeProof) -> Result<ExpectedProvider>,
) -> Result<Vec<ExpectedProvider>> {
    let (cleanup, history, excluded) = channel;
    if let Some(index) = excluded {
        let entry = entries
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(Error::Conflict)?;
        if registered[index]
            || !cleanup
            || history
            || entry.closed.is_some()
            || entry.captured.is_some()
            || pending_index(context, entry.original.intent())? != index
        {
            return Err(Error::Conflict);
        }
    }
    let mut result = Vec::new();
    for (index, entry) in entries.iter_mut().enumerate() {
        let Some(entry) = entry else { continue };
        if registered[index] {
            continue;
        } // Live entry verifies the SAME pin.
        if pending_index(context, entry.original.intent())? != index {
            return Err(Error::Conflict);
        }
        verify(&entry.source, entry.original.intent())?;
        if excluded == Some(index) {
            // Only a separate actual SCM pin permits the native caller to
            // select this branch; no partial observation becomes a provider.
            continue;
        }
        if let Some(receipt) = &entry.closed {
            if !cleanup {
                return Err(Error::Conflict);
            }
            let stopped = entry
                .original
                .read_closed(receipt)
                .map_err(|_| Error::Pending)?;
            if let Some(captured) = &entry.captured {
                let proof = stopped.retired_proof.ok_or(Error::Conflict)?;
                if validate_member_binding(context, &stopped.intent, &proof, captured)? != index {
                    return Err(Error::Conflict);
                }
                if history {
                    result.push(captured.clone());
                }
            } else if history {
                // Final RetiredC projection also retains a genuinely retired
                // original Stop proof, without inventing removed SDK metadata.
                // These comparison-only rows NEVER enter live SDK inputs.
                if let Some((intent, proof)) = entry
                    .original
                    .read_closed_proof(receipt)
                    .map_err(|_| Error::Pending)?
                {
                    result
                        .push(ClosedMemberBinding { intent, proof }.comparison_provider(context)?);
                }
            }
            verify(&entry.source, &stopped.intent)?;
            entry
                .original
                .read_closed(receipt)
                .map_err(|_| Error::Pending)?;
            continue;
        }
        if history {
            return Err(Error::Pending);
        }
        let read = |original: &mut crate::member_original::PendingMemberRead<J, I>| {
            if cleanup {
                original.read_for_cleanup()
            } else {
                original.read_preparing()
            }
        };
        let (intent, proof) = read(&mut entry.original).map_err(|_| Error::Pending)?;
        if let Some(proof) = proof {
            let provider = identity(&entry.source, &proof)?;
            if validate_member_binding(context, &intent, &proof, &provider)? != index
                || entry.captured.as_ref().is_some_and(|old| old != &provider)
            {
                return Err(Error::Conflict);
            }
            entry.captured = Some(provider.clone());
            result.push(provider);
        } else if entry.captured.is_some() {
            return Err(Error::Conflict);
        }
        verify(&entry.source, &intent)?;
        if read(&mut entry.original).map_err(|_| Error::Pending)? != (intent, proof) {
            return Err(Error::Conflict);
        }
    }
    Ok(result)
}

fn read_closed_members<J: crate::member_owner::Journal, I: crate::member_owner::MemberIo, S>(
    context: &Context,
    entries: &mut [Option<RetainedEntry<J, I, S>>; 2],
    mut verify_source: impl FnMut(&S, Option<&Intent>) -> Result<()>,
) -> Result<Vec<ExpectedProvider>> {
    let mut history = Vec::with_capacity(2);
    for (index, entry) in entries.iter_mut().enumerate() {
        let Some(entry) = entry else { continue };
        verify_source(&entry.source, None)?;
        let receipt = entry.closed.as_ref().ok_or(Error::Conflict)?;
        let (intent, provider) = closed_member_history(
            context,
            index,
            &mut entry.original,
            receipt,
            &entry.provider,
        )?;
        verify_source(&entry.source, Some(&intent))?;
        history.push(provider);
    }
    Ok(history)
}

/// The native caller supplies actual Closing/runtime/source/revision and ALL
/// opaque receipt checks as one sampled read. Historical members are separate
/// from empty live inputs on BOTH full native queries and the full callback.
fn inspect_closed_history_with<T>(
    mut read: impl FnMut() -> Result<(Vec<u8>, Vec<ExpectedProvider>)>,
    mut inspect_empty: impl FnMut(&[ExpectedProvider]) -> Result<()>,
    inspect: impl FnOnce(&[ExpectedProvider], &[ExpectedProvider]) -> Result<T>,
) -> Result<T> {
    let before = read()?;
    inspect_empty(&[])?;
    let facts = inspect(&[], &before.1)?;
    inspect_empty(&[])?;
    if read()? != before {
        return Err(Error::Conflict);
    }
    Ok(facts)
}

fn read_closing_members<J: crate::member_owner::Journal, I: crate::member_owner::MemberIo, S>(
    context: &Context,
    entries: &mut [Option<RetainedEntry<J, I, S>>; 2],
    mut verify_source: impl FnMut(&S, Option<&Intent>) -> Result<()>,
    mut native_identity: impl FnMut(&S, &NativeProof) -> Result<ExpectedProvider>,
) -> Result<Vec<ExpectedProvider>> {
    for entry in entries.iter().flatten() {
        entry.original.retire_forward();
    }
    let mut live = Vec::with_capacity(2);
    for (index, entry) in entries.iter_mut().enumerate() {
        let Some(entry) = entry else { continue };
        verify_source(&entry.source, None)?;
        if let Some(receipt) = &entry.closed {
            // History never becomes a live native query target. Only the
            // actual SAME-owner ACK plus current durable/native absence counts.
            let (intent, _) = closed_member_history(
                context,
                index,
                &mut entry.original,
                receipt,
                &entry.provider,
            )?;
            verify_source(&entry.source, Some(&intent))?;
            continue;
        }
        let (intent, proof) = entry
            .original
            .read_for_cleanup()
            .map_err(|_| Error::Conflict)?;
        verify_source(&entry.source, Some(&intent))?;
        let provider = native_identity(&entry.source, &proof)?;
        if provider != entry.provider
            || validate_member_binding(context, &intent, &proof, &provider)? != index
            || entry
                .original
                .read_for_cleanup()
                .map_err(|_| Error::Conflict)?
                != (intent.clone(), proof)
        {
            return Err(Error::Conflict);
        }
        verify_source(&entry.source, Some(&intent))?;
        live.push(provider);
    }
    Ok(live)
}

fn inspect_closing_with<T>(
    mut read: impl FnMut() -> Result<(Vec<u8>, Vec<ExpectedProvider>)>,
    inspect: impl FnOnce(&[ExpectedProvider]) -> Result<T>,
) -> Result<T> {
    let before = read()?;
    let facts = inspect(&before.1)?;
    if read()? != before {
        return Err(Error::Conflict);
    }
    Ok(facts)
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::member_carrier_native_ownership::{Phase, Record};
    use crate::member_original::{ClosedMemberReceipt, OriginalMemberRead, PendingMemberRead};
    use crate::windows::{
        member_carrier_key_authority::RuntimeRead,
        member_carrier_module::native::OriginalImage,
        member_carrier_payload::native::{MemberSource, WintunSource},
        member_files::MemberFiles,
        member_owner::NativeMemberIo,
        member_session::RecordKind,
    };
    use std::{cell::RefCell, rc::Rc};
    use windows_sys::Win32::NetworkManagement::{
        IpHelper::{GetIfEntry2, MIB_IF_ROW2},
        Ndis::NET_LUID_LH,
    };

    type MemberRead = OriginalMemberRead<MemberFiles, NativeMemberIo<MemberFiles>>;
    type Closed = ClosedMemberReceipt<MemberFiles, NativeMemberIo<MemberFiles>>;
    type Pending = PendingMemberRead<MemberFiles, NativeMemberIo<MemberFiles>>;
    type Entry = RetainedEntry<MemberFiles, NativeMemberIo<MemberFiles>, Rc<MemberSource>>;
    type PendingNative = PendingEntry<MemberFiles, NativeMemberIo<MemberFiles>, Rc<MemberSource>>;
    type Retired =
        RetiredInventoryEntry<MemberFiles, NativeMemberIo<MemberFiles>, Rc<MemberSource>>;

    pub(crate) struct NativeRetirementInputs<'a> {
        pub ticket: &'a Rc<super::super::member_carrier_member_controller::native::NativeMemberPreparationGeneration>,
        pub never: &'a Rc<super::super::member_carrier_member_controller::native::NativeNeverMemberEffects>,
        pub source: &'a Rc<super::super::member_carrier_runtime::native::NativeSourceRead>,
        pub pair: &'a super::super::member_carrier_pair_store::native_store::NativePairIntentRead,
        pub expected: &'a crate::member_carrier_pair::Record,
        pub supervisor: &'a super::super::member_native_deadline::NativeDeadline,
    }

    pub(crate) struct NativeRebindPublication<'a> {
        pub source: &'a Rc<super::super::member_carrier_runtime::native::NativeSourceRead>,
        pub receipt: &'a Rc<
            super::super::member_carrier_member_controller::native::NativeMemberRebindReceipt,
        >,
        pub pair: &'a super::super::member_carrier_pair_store::native_store::NativePairIntentRead,
        pub expected: &'a crate::member_carrier_pair::Record,
        pub supervisor: &'a super::super::member_native_deadline::NativeDeadline,
    }

    /// Actual original member owners + original signed sources. The global
    /// provider queries remain separate FULL native reads, not owned filtering.
    /// This object exposes no service/native effects or metadata ACK constructor.
    pub(crate) struct MemberInventory {
        runtime: RuntimeRead,
        context: Context,
        carrier: Rc<WintunSource>,
        entries: [Option<Entry>; 2],
        pending: [Option<PendingNative>; 2],
        retired: Vec<Retired>,
        retired_generations: Vec<Rc<super::super::member_carrier_member_controller::native::NativeMemberPreparationGeneration>>,
        rebound: Vec<ReboundInventoryEntry<MemberFiles, NativeMemberIo<MemberFiles>, Rc<MemberSource>>>,
    }

    /// Read-only shared retention of the actual inventory. The failure signal
    /// is OUTSIDE its RefCell, so a failed/reentrant borrow cannot escape
    /// revocation. No mutable inventory/source/native handle is exposed.
    pub(crate) struct MemberInventoryRead {
        inventory: Rc<RefCell<MemberInventory>>,
        health: Rc<ReadHealth>,
    }

    impl MemberInventoryRead {
        /// Explicit SAME-owner process-reader publication. No owner/SCM/NIC is
        /// recovered from saved metadata. The caller roots its original native
        /// ACK before invoking us and performs mandatory resource G afterwards.
        pub(crate) fn publish_rebind(
            &self,
            source: Rc<MemberSource>,
            original: MemberRead,
            pending: Pending,
            input: NativeRebindPublication<'_>,
        ) -> Result<()> {
            self.health.forward(|| {
                let (context, runtime) = {
                    let inventory = self.inventory.try_borrow().map_err(|_| Error::Conflict)?;
                    (inventory.context.clone(), inventory.runtime.read_pin()?)
                };
                let index = pending_index(&context, &input.receipt.running_record().intent)?;
                let old = input.expected.members[index]
                    .as_ref()
                    .ok_or(Error::Conflict)?;
                let running = input.receipt.running_record();
                if old.owner.intent != running.intent
                    || running.retired_proof != old.owner.proof
                    || running.proof.is_none_or(|p| {
                        Some(p.interface) != old.owner.proof.map(|old| old.interface)
                    })
                {
                    return Err(Error::Conflict);
                }
                let verify_pair = || -> Result<()> {
                    input
                        .pair
                        .inspect_effect(
                            &runtime,
                            input.supervisor,
                            input.expected,
                            crate::member_carrier_pair::Effect::Rebind(if index == 0 {
                                nelomai_client_tunnel::redundancy::Slot::A
                            } else {
                                nelomai_client_tunnel::redundancy::Slot::B
                            }),
                            |_| Ok(()),
                        )
                        .map_err(|_| Error::Conflict)
                };
                verify_pair()?;
                input
                    .source
                    .inspect_inventory_renewal_carrier(&context, &runtime, self, |carrier| {
                        let mut inventory = self
                            .inventory
                            .try_borrow_mut()
                            .map_err(|_| super::super::member_carrier_wintun::Error::Conflict)?;
                        let run = || -> Result<()> {
                            let before = inventory.revision()?;
                            rebind_registration(
                                &context,
                                Record::decode(&before)?.phase,
                                input.expected,
                                index,
                            )?;
                            if !source.matches_carrier(&inventory.carrier)
                                || Some(crate::member_owner::InterfaceProof {
                                    guid: carrier.identity.guid,
                                    index: carrier.identity.index,
                                    luid: carrier.identity.luid,
                                }) != input.expected.carrier
                            {
                                return Err(Error::Conflict);
                            }
                            // Old process aliases are intentionally retired. Only
                            // its opaque receipt verifies that target; the other
                            // live member is freshly read through its actual owner.
                            let mut providers = Vec::with_capacity(2);
                            for (n, entry) in inventory.entries.iter_mut().enumerate() {
                                let entry = entry.as_mut().ok_or(Error::Conflict)?;
                                if entry.closed.is_some() {
                                    return Err(Error::Conflict);
                                }
                                if n == index {
                                    input
                                        .receipt
                                        .verify_retired_original_read(&entry.original)
                                        .map_err(|_| Error::Conflict)?;
                                } else {
                                    let (intent, proof) =
                                        entry.original.read().map_err(|_| Error::Conflict)?;
                                    if input.expected.members[n].as_ref().is_none_or(|m| {
                                        m.owner.intent != intent || m.owner.proof != Some(proof)
                                    }) {
                                        return Err(Error::Conflict);
                                    }
                                    runtime.verify_member_intent(
                                        &context,
                                        &entry.source,
                                        &intent,
                                    )?;
                                    if native_identity(&proof, entry.source.transport())?
                                        != entry.provider
                                    {
                                        return Err(Error::Conflict);
                                    }
                                }
                                providers.push(entry.provider.clone());
                            }
                            let complete = complete_provider_inputs(
                                &context,
                                std::slice::from_ref(carrier),
                                &providers,
                            )?;
                            let sdk_before =
                                super::super::member_carrier_provider::native::inspect_mixed(
                                    &complete,
                                )
                                .map_err(|_| Error::Native)?;
                            verify_pair()?;
                            let MemberInventory {
                                entries,
                                pending: current_pending,
                                rebound,
                                ..
                            } = &mut *inventory;
                            renew_rebound_entry(
                                &context,
                                entries,
                                current_pending,
                                rebound,
                                ReboundInputs {
                                    source,
                                    original,
                                    pending,
                                    receipt: input.receipt.clone(),
                                },
                                Rc::ptr_eq,
                                |source, intent, proof| {
                                    runtime.verify_member_intent(&context, source, intent)?;
                                    let provider = native_identity(proof, source.transport())?;
                                    if validate_member_binding(&context, intent, proof, &provider)?
                                        != index
                                        || provider != providers[index]
                                    {
                                        return Err(Error::Conflict);
                                    }
                                    Ok(())
                                },
                            )?;
                            if inventory.read_all_inner()? != providers
                                || super::super::member_carrier_provider::native::inspect_mixed(
                                    &complete,
                                )
                                .map_err(|_| Error::Native)?
                                    != sdk_before
                                || inventory.revision()? != before
                            {
                                return Err(Error::Conflict);
                            }
                            verify_pair()
                        };
                        run().map_err(|_| super::super::member_carrier_wintun::Error::Conflict)
                    })
                    .map_err(|_| Error::Conflict)?;
                verify_pair()
            })
        }
        /// Exact original aliases only, never equal metadata or a native ACK.
        pub(crate) fn same_original(&self, other: &Self) -> bool {
            Rc::ptr_eq(&self.inventory, &other.inventory) && Rc::ptr_eq(&self.health, &other.health)
        }
        pub(crate) fn read_pin(&self) -> Self {
            Self {
                inventory: self.inventory.clone(),
                health: self.health.clone(),
            }
        }
        /// Pure retained-owner shape/origin comparison, including after DLL
        /// release. No native absence, load/release ACK or effect authority.
        pub(crate) fn verify_never_populated(
            &self,
            context: &Context,
            runtime: &RuntimeRead,
            carrier: &Rc<WintunSource>,
        ) -> Result<()> {
            let inventory = self.inventory.try_borrow().map_err(|_| Error::Conflict)?;
            if &inventory.context != context
                || !inventory.runtime.same_original_runtime(runtime)
                || !Rc::ptr_eq(&inventory.carrier, carrier)
                || inventory.entries.iter().any(Option::is_some)
                || inventory.pending.iter().any(Option::is_some)
                || !inventory.retired.is_empty()
                || !inventory.retired_generations.is_empty()
                || !inventory.rebound.is_empty()
            {
                return Err(Error::Conflict);
            }
            Ok(())
        }
        /// Explicit, read-only generation transition. This grants NO Start,
        /// key/row reuse or WFP permission. The original actor additionally
        /// brackets all 48 filters and the retained row/key closure ACKs.
        /// Never mutate this inventory INSIDE a Source callback: each Source
        /// window remains independently stable and full-SDK bracketed.
        pub(crate) fn retire_generation(
            &mut self,
            input: NativeRetirementInputs<'_>,
        ) -> Result<()> {
            let (context, runtime) = {
                let inventory = self.inventory.try_borrow().map_err(|_| Error::Conflict)?;
                (inventory.context.clone(), inventory.runtime.read_pin()?)
            };
            let index = match input.ticket.slot() {
                TunnelSlot::A => 0,
                TunnelSlot::B => 1,
            };
            if !input.source.matches_member_inventory(self) {
                return Err(Error::Conflict);
            }
            let mut flight = RetirementFlight {
                health: &self.health,
                complete: false,
            };
            input.ticket.verify_source(input.source)?;
            input
                .ticket
                .verify_original(input.never, &runtime, &context)?;
            let verify_pair = || {
                input
                    .pair
                    .inspect(&runtime, input.supervisor, |actual| {
                        if actual != input.expected {
                            return Err(std::io::Error::other(
                                "carrier_inventory_generation_conflict",
                            ));
                        }
                        completed_retirement_registration(&context, Phase::Preparing, actual, index)
                            .map_err(|_| {
                                std::io::Error::other("carrier_inventory_generation_conflict")
                            })
                    })
                    .map_err(|_| Error::Conflict)
            };
            verify_pair()?;
            let receipt = input.ticket.closed_receipt();
            let sealed = input.ticket.retired_original();
            let (intent, proof) = sealed.read_history(receipt).map_err(|_| Error::Conflict)?;
            let before = input
                .source
                .inspect_window(|window| {
                    let bindings = window.bindings();
                    if !window.matches_source(input.source)
                        || !window.matches_runtime(&runtime)
                        || bindings.scope != context.intent.scope
                        || bindings.carrier.as_ref().map(|c| c.identity.proof)
                            != input.expected.carrier
                        || bindings.egress[1 - index].as_ref().map(|m| m.proof)
                            != input.expected.members[1 - index]
                                .as_ref()
                                .and_then(|m| m.owner.proof)
                                .map(|p| p.interface)
                        || window
                            .closed_member(if index == 0 {
                                TunnelSlot::B
                            } else {
                                TunnelSlot::A
                            })
                            .is_some()
                    {
                        return Err(super::super::member_carrier_wintun::Error::Conflict);
                    }
                    match (
                        proof,
                        window.closed_member(intent.slot),
                        &bindings.egress[index],
                    ) {
                        (Some(proof), Some(history), Some(member))
                            if history.intent == intent
                                && history.proof == proof
                                && member.proof == proof.interface => {}
                        (None, None, None) => (),
                        _ => return Err(super::super::member_carrier_wintun::Error::Conflict),
                    }
                    Ok((bindings.carrier.clone(), bindings.egress[1 - index].clone()))
                })
                .map_err(|_| Error::Conflict)?;
            verify_pair()?;
            // Enter the local failure fence only after releasing the Source
            // borrow. Retain original roots BEFORE any fallible postflight.
            self.health.forward(|| {
                let mut inventory = self
                    .inventory
                    .try_borrow_mut()
                    .map_err(|_| Error::Conflict)?;
                let revision = inventory.revision()?;
                completed_retirement_registration(
                    &context,
                    Record::decode(&revision)?.phase,
                    input.expected,
                    index,
                )?;
                if !inventory
                    .retired_generations
                    .iter()
                    .any(|old| Rc::ptr_eq(old, input.ticket))
                {
                    inventory
                        .retired_generations
                        .try_reserve(1)
                        .map_err(|_| Error::Pending)?;
                    inventory.retired_generations.push(input.ticket.clone());
                }
                let MemberInventory {
                    entries,
                    pending,
                    retired,
                    ..
                } = &mut *inventory;
                retire_closed_entries(&context, index, entries, pending, retired, sealed, receipt)?;
                if inventory.revision()? != revision {
                    return Err(Error::Conflict);
                }
                Ok(())
            })?;
            // No old journal read here: only immutable original history and
            // the new current C+other live SDK universe. A failed postflight
            // leaves every retired root retained and poisons forward reads.
            let postflight = (|| {
                input
                    .source
                    .inspect_window(|window| {
                        let bindings = window.bindings();
                        if !window.matches_source(input.source)
                            || !window.matches_runtime(&runtime)
                            || bindings.scope != context.intent.scope
                            || bindings.carrier != before.0
                            || bindings.egress[1 - index] != before.1
                            || bindings.egress[index].is_some()
                            || window.closed_member(intent.slot).is_some()
                        {
                            return Err(super::super::member_carrier_wintun::Error::Conflict);
                        }
                        Ok(())
                    })
                    .map_err(|_| Error::Conflict)?;
                verify_pair()?;
                input.ticket.verify_source(input.source)?;
                input
                    .ticket
                    .verify_original(input.never, &runtime, &context)
            })();
            if postflight.is_err() {
                self.health.revoked.set(true);
            }
            flight.complete = postflight.is_ok();
            postflight
        }
        fn closing(&self) -> Result<bool> {
            let inventory = self.inventory.try_borrow().map_err(|_| Error::Conflict)?;
            Ok(Record::decode(&inventory.revision()?)?.phase == Phase::Closing)
        }
        pub(crate) fn matches_original_runtime_image(
            &self,
            runtime: &RuntimeRead,
            image: &OriginalImage,
        ) -> Result<()> {
            self.health.observe(
                || self.closing(),
                |_| {
                    self.inventory
                        .try_borrow()
                        .map_err(|_| Error::Conflict)?
                        .matches_original_runtime_image(runtime, image)
                },
            )
        }
        pub(crate) fn register(
            &mut self,
            source: Rc<MemberSource>,
            original: MemberRead,
        ) -> Result<()> {
            self.health.forward(|| {
                self.inventory
                    .try_borrow_mut()
                    .map_err(|_| Error::Conflict)?
                    .register_inner(source, original)
            })
        }
        /// Enroll original owner/source BEFORE Start, without claiming Running.
        pub(crate) fn register_pending(
            &mut self,
            source: Rc<MemberSource>,
            original: Pending,
        ) -> Result<()> {
            self.health.forward(|| {
                self.inventory
                    .try_borrow_mut()
                    .map_err(|_| Error::Conflict)?
                    .register_pending_inner(source, original)
            })
        }
        pub(crate) fn verify_pending_cleanup(
            &self,
            source: &Rc<MemberSource>,
            original: &Pending,
        ) -> Result<()> {
            self.health.cleanup(|| {
                let inventory = self.inventory.try_borrow().map_err(|_| Error::Conflict)?;
                let before = inventory.revision()?;
                if Record::decode(&before)?.phase != Phase::Closing {
                    return Err(Error::Conflict);
                }
                let index = pending_index(&inventory.context, original.intent())?;
                let entry = inventory.pending[index].as_ref().ok_or(Error::Pending)?;
                if !Rc::ptr_eq(source, &entry.source) || !original.same_original(&entry.original) {
                    return Err(Error::Conflict);
                }
                inventory.runtime.verify_member_intent(
                    &inventory.context,
                    source,
                    original.intent(),
                )?;
                if before != inventory.revision()? {
                    return Err(Error::Conflict);
                }
                Ok(())
            })
        }
        pub(crate) fn closed(&mut self, index: usize, receipt: &Rc<Closed>) -> Result<()> {
            self.health.cleanup(|| {
                self.inventory
                    .try_borrow_mut()
                    .map_err(|_| Error::Conflict)?
                    .closed_inner(index, receipt, None)
            })
        }
        /// Normal standby retirement must not enter global Closing/revoke the
        /// other live member. This publishes ONLY the SAME owner's Stop ACK;
        /// the controller's independent resource/native G remains mandatory.
        pub(crate) fn closed_retirement(
            &mut self,
            index: usize,
            receipt: &Rc<Closed>,
            pair: &super::super::member_carrier_pair_store::native_store::NativePairIntentRead,
            expected: &crate::member_carrier_pair::Record,
            supervisor: &super::super::member_native_deadline::NativeDeadline,
        ) -> Result<()> {
            self.health.forward(|| {
                let runtime = self
                    .inventory
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .runtime
                    .read_pin()?;
                let effect = expected.pending.ok_or(Error::Conflict)?;
                pair.inspect_effect(&runtime, supervisor, expected, effect, |_| Ok(()))
                    .map_err(|_| Error::Conflict)?;
                self.inventory
                    .try_borrow_mut()
                    .map_err(|_| Error::Conflict)?
                    .closed_inner(index, receipt, Some(expected))?;
                pair.inspect_effect(&runtime, supervisor, expected, effect, |_| Ok(()))
                    .map_err(|_| Error::Conflict)?;
                Ok(())
            })
        }
        pub(crate) fn read_all(&self) -> Result<Vec<ExpectedProvider>> {
            self.health.forward(|| {
                let mut inventory = self
                    .inventory
                    .try_borrow_mut()
                    .map_err(|_| Error::Conflict)?;
                let before = inventory.revision()?;
                if Record::decode(&before)?.phase != Phase::Preparing {
                    return Err(Error::Conflict);
                }
                let members = inventory.read_all_in_revision(&before)?;
                if inventory.revision()? != before {
                    return Err(Error::Conflict);
                }
                Ok(members)
            })
        }
        pub(crate) fn inspect_full<T>(
            &self,
            context: &Context,
            runtime: &RuntimeRead,
            image: &OriginalImage,
            inspect: impl FnOnce(&[ExpectedProvider]) -> Result<T>,
        ) -> Result<T> {
            self.health.observe(
                || self.closing(),
                |cleanup| {
                    self.inventory
                        .try_borrow_mut()
                        .map_err(|_| Error::Conflict)?
                        .inspect_full_inner(context, runtime, image, cleanup, inspect)
                },
            )
        }

        /// Factual restoration observation under actual protected Closing.
        /// The callback receives only still-live actual original A/B. Already
        /// closed entries require their retained SAME-owner Stop receipts and
        /// fresh absence; they never appear as live inputs. The callback may
        /// copy the facts for a later independent FULL mixed query, or perform
        /// that query here, without recursively borrowing this inventory.
        pub(crate) fn inspect_closing_full<T>(
            &self,
            context: &Context,
            runtime: &RuntimeRead,
            image: &OriginalImage,
            inspect: impl FnOnce(&[ExpectedProvider]) -> Result<T>,
        ) -> Result<T> {
            self.health.cleanup(|| {
                self.inventory
                    .try_borrow_mut()
                    .map_err(|_| Error::Conflict)?
                    .inspect_closing_full_inner(context, runtime, image, inspect)
            })
        }

        /// Mid-stop comparison: keep exact closed ACK identities separate from
        /// still-live SDK inputs. Carrier facts must be copied from actual C
        /// outside this inventory borrow; caller retains/rechecks its original
        /// C read. SDK selection data never grants original C/effect authority.
        /// FULL mixed SDK queries use C + live ONLY, before and after callback.
        /// Callback is read-only; never invoke Source/Inventory recursively.
        pub(crate) fn inspect_closing_bindings_full<T>(
            &self,
            context: &Context,
            runtime: &RuntimeRead,
            image: &OriginalImage,
            carrier: &[ExpectedProvider],
            inspect: impl FnOnce(&[ExpectedProvider], &[ClosedMemberBinding]) -> Result<T>,
        ) -> Result<T> {
            self.health.cleanup(|| {
                self.inventory
                    .try_borrow_mut()
                    .map_err(|_| Error::Conflict)?
                    .inspect_closing_bindings_full_inner(context, runtime, image, carrier, inspect)
            })
        }

        /// Separate service-only factual channel for the SAME uncommitted
        /// NEW SCM origin. Its SDK namespace is compared but NEVER enters live
        /// bindings; the caller's actual partial pin independently attests SCM.
        pub(crate) fn inspect_partial_closing_bindings<T>(
            &self,
            context: &Context,
            runtime: &RuntimeRead,
            image: &OriginalImage,
            carrier: &[ExpectedProvider],
            partial: &super::super::member_carrier_member_controller::native::PartialCleanup,
            inspect: impl FnOnce(&[ExpectedProvider], &[ClosedMemberBinding]) -> Result<T>,
        ) -> Result<T> {
            self.health.cleanup(|| {
                if carrier.len() != 1 {
                    return Err(Error::Conflict);
                }
                let mut inventory = self
                    .inventory
                    .try_borrow_mut()
                    .map_err(|_| Error::Conflict)?;
                let target = pending_index(context, partial.intent())?;
                let binding = &context.bindings[target + 1];
                let kind = match partial.intent().transport {
                    TunnelTransport::WireGuard => ProviderKind::WireGuardNt,
                    TunnelTransport::AmneziaWg3 => ProviderKind::Wintun,
                };
                inspect_mixed_closing_with(
                    || {
                        inventory
                            .partial_closing_bindings_revision(context, runtime, image, partial)
                    },
                    |live| {
                        let wants = complete_provider_inputs(context, carrier, live)?;
                        super::super::member_carrier_provider::native::inspect_mixed_partial(
                            &wants,
                            binding.guid,
                            &binding.name,
                            kind,
                        )
                        .map_err(|_| Error::Pending)
                    },
                    inspect,
                )
            })
        }

        /// Live C with zero or more SAME-original retired member histories.
        /// History never enters SDK inputs and cannot revive a closed member.
        pub(crate) fn inspect_source_bindings_full<T>(
            &self,
            context: &Context,
            runtime: &RuntimeRead,
            image: &OriginalImage,
            carrier: &[ExpectedProvider],
            inspect: impl FnOnce(&[ExpectedProvider], &[ClosedMemberBinding]) -> Result<T>,
        ) -> Result<T> {
            self.health.forward(|| {
                let mut inventory = self
                    .inventory
                    .try_borrow_mut()
                    .map_err(|_| Error::Conflict)?;
                if carrier.len() != 1 {
                    return Err(Error::Conflict);
                }
                inspect_mixed_closing_with(
                    || inventory.source_bindings_revision(context, runtime, image),
                    |live| {
                        let wants = complete_provider_inputs(context, carrier, live)?;
                        super::super::member_carrier_provider::native::inspect_mixed(&wants)
                            .map(|_| ())
                            .map_err(|_| Error::Pending)
                    },
                    inspect,
                )
            })
        }

        /// Cleanup-only full factual callback. Its first input remains the
        /// empty LIVE universe; the second is captured retired A/B history.
        /// Full native emptiness is queried independently before and after.
        pub(crate) fn inspect_closed_history_full<T>(
            &self,
            context: &Context,
            runtime: &RuntimeRead,
            image: &OriginalImage,
            inspect: impl FnOnce(&[ExpectedProvider], &[ExpectedProvider]) -> Result<T>,
        ) -> Result<T> {
            self.health.cleanup(|| {
                self.inventory
                    .try_borrow_mut()
                    .map_err(|_| Error::Conflict)?
                    .inspect_closed_history_full_inner(context, runtime, image, inspect)
            })
        }

        /// Typed original Stop histories, never live provider input. Both full
        /// mixed SDK emptiness reads bracket the callback and exact revision.
        pub(crate) fn inspect_retired_bindings_full<T>(
            &self,
            context: &Context,
            runtime: &RuntimeRead,
            image: &OriginalImage,
            inspect: impl FnOnce(&[ClosedMemberBinding]) -> Result<T>,
        ) -> Result<T> {
            self.health.cleanup(|| {
                let mut inventory = self
                    .inventory
                    .try_borrow_mut()
                    .map_err(|_| Error::Conflict)?;
                // Includes original closure receipts for published and partial
                // starts. Numeric index absence alone never supplies history.
                inspect_mixed_closing_with(
                    || inventory.closing_bindings_revision(context, runtime, image),
                    |live| {
                        if !live.is_empty() {
                            return Err(Error::Conflict);
                        }
                        let observed =
                            super::super::member_carrier_provider::native::inspect_mixed(&[])
                                .map_err(|_| Error::Native)?;
                        if !observed.is_empty() {
                            return Err(Error::Conflict);
                        }
                        Ok(())
                    },
                    |live, history| {
                        if !live.is_empty() {
                            return Err(Error::Conflict);
                        }
                        inspect(history)
                    },
                )
            })
        }

        /// Final factual bracket after the actual native key owner acknowledged
        /// Stopped/restored. This cannot be used during Closing or for effects.
        /// Every registered original still requires its SAME Stop ACK; absence
        /// queries never manufacture one for a pending or live owner.
        pub(crate) fn inspect_terminal_bindings_full<T>(
            &self,
            context: &Context,
            runtime: &RuntimeRead,
            image: &OriginalImage,
            inspect: impl FnOnce(&[ClosedMemberBinding]) -> Result<T>,
        ) -> Result<T> {
            self.health.cleanup(|| {
                let mut inventory = self
                    .inventory
                    .try_borrow_mut()
                    .map_err(|_| Error::Conflict)?;
                inspect_mixed_closing_with(
                    || inventory.terminal_bindings_revision(context, runtime, image),
                    |live| {
                        if !live.is_empty() {
                            return Err(Error::Conflict);
                        }
                        if !super::super::member_carrier_provider::native::inspect_mixed(&[])
                            .map_err(|_| Error::Native)?
                            .is_empty()
                        {
                            return Err(Error::Conflict);
                        }
                        Ok(())
                    },
                    |live, history| {
                        if !live.is_empty() {
                            return Err(Error::Conflict);
                        }
                        inspect(history)
                    },
                )
            })
        }
    }

    impl MemberInventory {
        fn terminal_revision(
            &self,
            context: &Context,
            runtime: &RuntimeRead,
            image: &OriginalImage,
        ) -> Result<Vec<u8>> {
            if context != &self.context
                || !self.runtime.same_original_runtime(runtime)
                || !image.matches_source(&self.carrier)
            {
                return Err(Error::Conflict);
            }
            self.runtime.verify(&self.context)?;
            self.runtime.verify_source(&self.carrier)?;
            image.verify_runtime(runtime).map_err(|_| Error::Conflict)?;
            let bytes = self
                .runtime
                .record(&self.context, RecordKind::NativeCarrierReceipts)?;
            let record = Record::decode(&bytes)?;
            super::super::member_carrier_runtime::validate_terminal_stage(
                &record,
                &self.context,
                &self.context.bindings[0],
                1,
            )?;
            self.runtime.verify(&self.context)?;
            Ok(bytes)
        }
        fn terminal_bindings_revision(
            &mut self,
            context: &Context,
            runtime: &RuntimeRead,
            image: &OriginalImage,
        ) -> Result<MixedClosingSample> {
            let before = self.terminal_revision(context, runtime, image)?;
            let history = read_terminal_closed_bindings(
                &self.context,
                &mut self.entries,
                &mut self.pending,
                |source, intent| {
                    if let Some(intent) = intent {
                        self.runtime
                            .verify_member_intent(&self.context, source, intent)
                    } else {
                        self.runtime.verify_member_source(&self.context, source)
                    }
                },
            )?;
            if self.terminal_revision(context, runtime, image)? != before {
                return Err(Error::Conflict);
            }
            Ok((before, vec![], history))
        }
        pub(crate) fn retain(
            runtime: &RuntimeRead,
            context: Context,
            carrier: Rc<WintunSource>,
        ) -> Result<MemberInventoryRead> {
            runtime.verify(&context)?;
            runtime.verify_source(&carrier)?;
            let inventory = Self {
                runtime: runtime.read_pin()?,
                context,
                carrier,
                entries: [None, None],
                pending: [None, None],
                retired: Vec::new(),
                retired_generations: Vec::new(),
                rebound: Vec::new(),
            };
            inventory.revision()?;
            Ok(MemberInventoryRead {
                inventory: Rc::new(RefCell::new(inventory)),
                health: Rc::new(ReadHealth::default()),
            })
        }

        pub(crate) fn matches_original_runtime_image(
            &self,
            runtime: &RuntimeRead,
            image: &OriginalImage,
        ) -> Result<()> {
            if !self.runtime.same_original_runtime(runtime) || !image.matches_source(&self.carrier)
            {
                return Err(Error::Conflict);
            }
            // One complete image read authenticates the SAME runtime/source,
            // lease and protected context on both sides of the mapping read.
            // This method compares opaque origins only; it invokes no member
            // callback or native effect. The final revision independently
            // authenticates and rereads the current full native receipt.
            image.verify_runtime(runtime).map_err(|_| Error::Conflict)?;
            self.revision()?;
            Ok(())
        }

        fn revision(&self) -> Result<Vec<u8>> {
            // Source verification already authenticates this SAME runtime;
            // record then authenticates and rereads the complete protected
            // bytes before/after. Decoding them performs no native or file IO.
            self.runtime.verify_source(&self.carrier)?;
            let bytes = self
                .runtime
                .record(&self.context, RecordKind::NativeCarrierReceipts)?;
            let record = Record::decode(&bytes)?;
            if record.context != self.context
                || !matches!(record.phase, Phase::Preparing | Phase::Closing)
            {
                return Err(Error::Conflict);
            }
            Ok(bytes)
        }

        /// Captures no Start ACK from facts. The supplied read capability owns
        /// the SAME real MemberOwner/J/NativeIO, which already acknowledged its
        /// fresh Running CAS and original NEW service/process handles.
        fn register_inner(
            &mut self,
            source: Rc<MemberSource>,
            mut original: MemberRead,
        ) -> Result<()> {
            let before = self.revision()?;
            if Record::decode(&before)?.phase != Phase::Preparing
                || !source.matches_carrier(&self.carrier)
            {
                return Err(Error::Conflict);
            }
            let (intent, proof) = original.read().map_err(|_| Error::Conflict)?;
            self.runtime
                .verify_member_intent(&self.context, &source, &intent)?;
            let provider = native_identity(&proof, source.transport())?;
            let index = validate_member_binding(&self.context, &intent, &proof, &provider)?;
            if self.pending[index].as_ref().is_some_and(|pending| {
                !Rc::ptr_eq(&pending.source, &source)
                    || !pending.original.matches_live(&original)
                    || pending.closed.is_some()
            }) {
                return Err(Error::Conflict);
            }
            if self.entries[index].is_some() {
                return Err(Error::Conflict);
            }
            if original.read().map_err(|_| Error::Conflict)? != (intent.clone(), proof) {
                return Err(Error::Conflict);
            }
            self.runtime
                .verify_member_intent(&self.context, &source, &intent)?;
            if before != self.revision()? {
                return Err(Error::Conflict);
            }
            self.entries[index] = Some(Entry {
                source,
                original,
                provider,
                closed: None,
            });
            Ok(())
        }

        fn register_pending_inner(
            &mut self,
            source: Rc<MemberSource>,
            original: Pending,
        ) -> Result<()> {
            let before = self.revision()?;
            if Record::decode(&before)?.phase != Phase::Preparing
                || !source.matches_carrier(&self.carrier)
            {
                return Err(Error::Conflict);
            }
            let index = pending_index(&self.context, original.intent())?;
            if self.entries[index].is_some() {
                return Err(Error::Conflict);
            }
            retain_pending(
                &self.context,
                &mut self.pending,
                source,
                original,
                Rc::ptr_eq,
                |source, intent| {
                    self.runtime
                        .verify_member_intent(&self.context, source, intent)
                },
            )?;
            if before != self.revision()? {
                return Err(Error::Conflict);
            }
            Ok(())
        }

        /// Transfer only an opaque SAME-owner acknowledged closure receipt.
        /// A cleanup request, equal StopResponse or lookup absence cannot seed it.
        fn closed_inner(
            &mut self,
            index: usize,
            receipt: &Rc<Closed>,
            retirement: Option<&crate::member_carrier_pair::Record>,
        ) -> Result<()> {
            let before = self.revision()?;
            let phase = Record::decode(&before)?.phase;
            if let Some(pair) = retirement {
                retirement_registration(&self.context, phase, pair, index)?;
            } else if phase != Phase::Closing {
                return Err(Error::Conflict);
            }
            if self.pending.get(index).and_then(Option::as_ref).is_some() {
                publish_pending_closed(
                    &self.context,
                    &mut self.pending,
                    index,
                    receipt,
                    |source, intent| {
                        self.runtime
                            .verify_member_intent(&self.context, source, intent)
                    },
                )?;
                if self.entries.get(index).and_then(Option::as_ref).is_none() {
                    // No Running reader ever existed. Only SAME owner's Stop
                    // ACK was published; postflight still queries full SDK.
                    if before != self.revision()? {
                        return Err(Error::Conflict);
                    }
                    return Ok(());
                }
            }
            let entry = self
                .entries
                .get_mut(index)
                .and_then(Option::as_mut)
                .ok_or(Error::Conflict)?;
            if let Some(prior) = &entry.closed {
                // SAME opaque actual receipt can reconcile a lost factual
                // publication ACK; neither equal data nor a new owner can.
                if !Rc::ptr_eq(prior, receipt) {
                    return Err(Error::Conflict);
                }
            }
            entry
                .original
                .verify_closed(receipt)
                .map_err(|_| Error::Conflict)?;
            self.runtime
                .verify_member_source(&self.context, &entry.source)?;
            // Store the actual ACK before any later fallible revision/publication.
            // A failed publication remains an obligation, never permission rearm.
            // Caller ALSO retains this read-only receipt across every fallible
            // check. A pre-storage transient error cannot consume the sole ACK.
            entry.closed = Some(receipt.clone());
            if before != self.revision()? {
                return Err(Error::Conflict);
            }
            Ok(())
        }

        fn pending_members(
            &mut self,
            cleanup: bool,
            history: bool,
        ) -> Result<Vec<ExpectedProvider>> {
            let registered = self.entries.each_ref().map(Option::is_some);
            read_pending_members(
                &self.context,
                &mut self.pending,
                registered,
                cleanup,
                history,
                |source, intent| {
                    self.runtime
                        .verify_member_intent(&self.context, source, intent)
                },
                |source, proof| native_identity(proof, source.transport()),
            )
        }

        fn read_all_inner(&mut self) -> Result<Vec<ExpectedProvider>> {
            let before = self.revision()?;
            let wants = self.read_all_in_revision(&before)?;
            if before != self.revision()? {
                return Err(Error::Conflict);
            }
            Ok(wants)
        }

        // Factual member reads inside the caller's complete revision frame.
        // Original service/process/close receipts are still read twice; this
        // does not grant Start or reconstruct an owner from the saved bytes.
        fn read_all_in_revision(&mut self, revision: &[u8]) -> Result<Vec<ExpectedProvider>> {
            let mut wants = Vec::with_capacity(2);
            for (index, entry) in self.entries.iter_mut().enumerate() {
                let Some(entry) = entry else {
                    continue;
                };
                self.runtime
                    .verify_member_source(&self.context, &entry.source)?;
                if let Some(receipt) = &entry.closed {
                    entry
                        .original
                        .verify_closed(receipt)
                        .map_err(|_| Error::Conflict)?;
                    continue;
                }
                let (intent, proof) = entry.original.read().map_err(|_| Error::Conflict)?;
                self.runtime
                    .verify_member_intent(&self.context, &entry.source, &intent)?;
                let provider = native_identity(&proof, entry.source.transport())?;
                if provider != entry.provider
                    || validate_member_binding(&self.context, &intent, &proof, &provider)? != index
                    || entry.original.read().map_err(|_| Error::Conflict)?
                        != (intent.clone(), proof)
                {
                    return Err(Error::Conflict);
                }
                self.runtime
                    .verify_member_intent(&self.context, &entry.source, &intent)?;
                wants.push(provider);
            }
            wants.extend(
                self.pending_members(Record::decode(revision)?.phase == Phase::Closing, false)?,
            );
            Ok(wants)
        }

        fn closing_live_revision(
            &mut self,
            context: &Context,
            runtime: &RuntimeRead,
            image: &OriginalImage,
        ) -> Result<(Vec<u8>, Vec<ExpectedProvider>)> {
            if context != &self.context {
                return Err(Error::Conflict);
            }
            self.matches_original_runtime_image(runtime, image)?;
            let before = self.revision()?;
            if Record::decode(&before)?.phase != Phase::Closing {
                return Err(Error::Conflict);
            }
            let mut members = read_closing_members(
                &self.context,
                &mut self.entries,
                |source, intent| {
                    if let Some(intent) = intent {
                        self.runtime
                            .verify_member_intent(&self.context, source, intent)
                    } else {
                        self.runtime.verify_member_source(&self.context, source)
                    }
                },
                |source, proof| native_identity(proof, source.transport()),
            )?;
            members.extend(self.pending_members(true, false)?);
            self.matches_original_runtime_image(runtime, image)?;
            if self.revision()? != before {
                return Err(Error::Conflict);
            }
            Ok((before, members))
        }

        fn source_bindings_revision(
            &mut self,
            context: &Context,
            runtime: &RuntimeRead,
            image: &OriginalImage,
        ) -> Result<MixedClosingSample> {
            if context != &self.context {
                return Err(Error::Conflict);
            }
            self.matches_original_runtime_image(runtime, image)?;
            let before = self.revision()?;
            if Record::decode(&before)?.phase != Phase::Preparing {
                return Err(Error::Conflict);
            }
            let live = self.read_all_in_revision(&before)?;
            let history = read_mixed_closed_bindings(
                &self.context,
                &mut self.entries,
                &mut self.pending,
                |source, intent| {
                    if let Some(intent) = intent {
                        self.runtime
                            .verify_member_intent(&self.context, source, intent)
                    } else {
                        self.runtime.verify_member_source(&self.context, source)
                    }
                },
            )?;
            self.matches_original_runtime_image(runtime, image)?;
            if self.revision()? != before {
                return Err(Error::Conflict);
            }
            Ok((before, live, history))
        }

        fn inspect_closing_full_inner<T>(
            &mut self,
            context: &Context,
            runtime: &RuntimeRead,
            image: &OriginalImage,
            inspect: impl FnOnce(&[ExpectedProvider]) -> Result<T>,
        ) -> Result<T> {
            for entry in self.entries.iter().flatten() {
                entry.original.retire_forward();
            }
            for entry in self.pending.iter().flatten() {
                entry.original.retire_forward();
            }
            inspect_closing_with(
                || self.closing_live_revision(context, runtime, image),
                inspect,
            )
        }

        fn closing_bindings_revision(
            &mut self,
            context: &Context,
            runtime: &RuntimeRead,
            image: &OriginalImage,
        ) -> Result<MixedClosingSample> {
            let (revision, live) = self.closing_live_revision(context, runtime, image)?;
            let history = read_mixed_closed_bindings(
                &self.context,
                &mut self.entries,
                &mut self.pending,
                |source, intent| {
                    if let Some(intent) = intent {
                        self.runtime
                            .verify_member_intent(&self.context, source, intent)
                    } else {
                        self.runtime.verify_member_source(&self.context, source)
                    }
                },
            )?;
            self.matches_original_runtime_image(runtime, image)?;
            if self.revision()? != revision {
                return Err(Error::Conflict);
            }
            Ok((revision, live, history))
        }

        fn partial_closing_bindings_revision(
            &mut self,
            context: &Context,
            runtime: &RuntimeRead,
            image: &OriginalImage,
            partial: &super::super::member_carrier_member_controller::native::PartialCleanup,
        ) -> Result<MixedClosingSample> {
            if context != &self.context {
                return Err(Error::Conflict);
            }
            self.matches_original_runtime_image(runtime, image)?;
            let before = self.revision()?;
            if Record::decode(&before)?.phase != Phase::Closing {
                return Err(Error::Conflict);
            }
            let index = pending_index(context, partial.intent())?;
            let entry = self.pending[index].as_ref().ok_or(Error::Pending)?;
            if self.entries[index].is_some() || entry.captured.is_some() || entry.closed.is_some() {
                return Err(Error::Conflict);
            }
            partial
                .verify_pending_original(&entry.original)
                .map_err(|_| Error::Conflict)?;
            self.runtime
                .verify_member_intent(context, &entry.source, partial.intent())?;
            let observed = partial.inspect().map_err(|_| Error::Conflict)?;
            let mut live = read_closing_members(
                context,
                &mut self.entries,
                |source, intent| match intent {
                    Some(intent) => self.runtime.verify_member_intent(context, source, intent),
                    None => self.runtime.verify_member_source(context, source),
                },
                |source, proof| native_identity(proof, source.transport()),
            )?;
            let registered = self.entries.each_ref().map(Option::is_some);
            live.extend(read_pending_members_excluding(
                context,
                &mut self.pending,
                registered,
                (true, false, Some(index)),
                |source, intent| self.runtime.verify_member_intent(context, source, intent),
                |source, proof| native_identity(proof, source.transport()),
            )?);
            let history = read_mixed_closed_bindings(
                context,
                &mut self.entries,
                &mut self.pending,
                |source, intent| match intent {
                    Some(intent) => self.runtime.verify_member_intent(context, source, intent),
                    None => self.runtime.verify_member_source(context, source),
                },
            )?;
            let entry = self.pending[index].as_ref().ok_or(Error::Pending)?;
            partial
                .verify_pending_original(&entry.original)
                .map_err(|_| Error::Conflict)?;
            self.runtime
                .verify_member_intent(context, &entry.source, partial.intent())?;
            if partial.inspect().map_err(|_| Error::Conflict)? != observed
                || self.revision()? != before
            {
                return Err(Error::Conflict);
            }
            self.matches_original_runtime_image(runtime, image)?;
            Ok((before, live, history))
        }
        fn inspect_closing_bindings_full_inner<T>(
            &mut self,
            context: &Context,
            runtime: &RuntimeRead,
            image: &OriginalImage,
            carrier: &[ExpectedProvider],
            inspect: impl FnOnce(&[ExpectedProvider], &[ClosedMemberBinding]) -> Result<T>,
        ) -> Result<T> {
            for entry in self.entries.iter().flatten() {
                entry.original.retire_forward();
            }
            for entry in self.pending.iter().flatten() {
                entry.original.retire_forward();
            }
            if carrier.len() != 1 {
                return Err(Error::Conflict);
            }
            inspect_mixed_closing_with(
                || self.closing_bindings_revision(context, runtime, image),
                |live| {
                    let wants = complete_provider_inputs(context, carrier, live)?;
                    super::super::member_carrier_provider::native::inspect_mixed(&wants)
                        .map(|_| ())
                        .map_err(|_| Error::Pending)
                },
                inspect,
            )
        }

        fn closed_history_revision(
            &mut self,
            context: &Context,
            runtime: &RuntimeRead,
            image: &OriginalImage,
        ) -> Result<(Vec<u8>, Vec<ExpectedProvider>)> {
            if context != &self.context {
                return Err(Error::Conflict);
            }
            self.matches_original_runtime_image(runtime, image)?;
            let before = self.revision()?;
            if Record::decode(&before)?.phase != Phase::Closing {
                return Err(Error::Conflict);
            }
            let mut history =
                read_closed_members(&self.context, &mut self.entries, |source, intent| {
                    if let Some(intent) = intent {
                        self.runtime
                            .verify_member_intent(&self.context, source, intent)
                    } else {
                        self.runtime.verify_member_source(&self.context, source)
                    }
                })?;
            history.extend(self.pending_members(true, true)?);
            if self.revision()? != before {
                return Err(Error::Conflict);
            }
            self.matches_original_runtime_image(runtime, image)?;
            if self.revision()? != before {
                return Err(Error::Conflict);
            }
            Ok((before, history))
        }

        fn inspect_closed_history_full_inner<T>(
            &mut self,
            context: &Context,
            runtime: &RuntimeRead,
            image: &OriginalImage,
            inspect: impl FnOnce(&[ExpectedProvider], &[ExpectedProvider]) -> Result<T>,
        ) -> Result<T> {
            inspect_closed_history_with(
                || self.closed_history_revision(context, runtime, image),
                |live| {
                    // This performs ALL mixed PnP/MIB/stack queries even for
                    // zero wants. History must NEVER enter this live universe.
                    if !live.is_empty() {
                        return Err(Error::Conflict);
                    }
                    let observations =
                        super::super::member_carrier_provider::native::inspect_mixed(&[])
                            .map_err(|_| Error::Native)?;
                    if !observations.is_empty() {
                        return Err(Error::Conflict);
                    }
                    Ok(())
                },
                inspect,
            )
        }

        /// This brackets the WHOLE caller's independent native provider read,
        /// not just a cached list of member identities. Errors/unwind revoke
        /// every later forward read, while exact closure receipts remain held.
        fn inspect_full_inner<T>(
            &mut self,
            context: &Context,
            runtime: &RuntimeRead,
            image: &OriginalImage,
            cleanup: bool,
            inspect: impl FnOnce(&[ExpectedProvider]) -> Result<T>,
        ) -> Result<T> {
            let phase = if cleanup {
                Phase::Closing
            } else {
                Phase::Preparing
            };
            if context != &self.context {
                return Err(Error::Conflict);
            }
            if !self.runtime.same_original_runtime(runtime) || !image.matches_source(&self.carrier)
            {
                return Err(Error::Conflict);
            }
            image.verify_runtime(runtime).map_err(|_| Error::Conflict)?;
            let before = self.revision()?;
            if Record::decode(&before)?.phase != phase {
                return Err(Error::Conflict);
            }
            if phase == Phase::Closing
                && (self.entries.iter().flatten().any(|e| e.closed.is_none())
                    || self.pending.iter().flatten().any(|e| e.closed.is_none()))
            {
                return Err(Error::Conflict);
            }
            let members = self.read_all_in_revision(&before)?;
            let facts = inspect(&members)?;
            if self.read_all_in_revision(&before)? != members || self.revision()? != before {
                return Err(Error::Conflict);
            }
            image.verify_runtime(runtime).map_err(|_| Error::Conflict)?;
            if self.revision()? != before {
                return Err(Error::Conflict);
            }
            Ok(facts)
        }
    }

    fn native_identity(
        proof: &NativeProof,
        transport: TunnelTransport,
    ) -> Result<ExpectedProvider> {
        let mut row = MIB_IF_ROW2 {
            InterfaceLuid: NET_LUID_LH {
                Value: proof.interface.luid,
            },
            ..Default::default()
        };
        if unsafe { GetIfEntry2(&mut row) } != 0 {
            return Err(Error::Native);
        }
        let identity = decode_row(&row)?;
        let mut second = MIB_IF_ROW2 {
            InterfaceIndex: proof.interface.index,
            ..Default::default()
        };
        if unsafe { GetIfEntry2(&mut second) } != 0 {
            return Err(Error::Native);
        }
        if decode_row(&second)? != identity
            || identity.guid != proof.interface.guid
            || identity.index != proof.interface.index
            || identity.luid != proof.interface.luid
        {
            return Err(Error::Conflict);
        }
        Ok(ExpectedProvider {
            identity,
            kind: match transport {
                TunnelTransport::WireGuard => ProviderKind::WireGuardNt,
                TunnelTransport::AmneziaWg3 => ProviderKind::Wintun,
            },
        })
    }

    fn decode_row(row: &MIB_IF_ROW2) -> Result<super::super::member_carrier_provider::Expected> {
        if row.InterfaceAndOperStatusFlags._bitfield & 0x83 != 0 {
            return Err(Error::Conflict);
        }
        let mut guid = [0; 16];
        guid[..4].copy_from_slice(&row.InterfaceGuid.data1.to_be_bytes());
        guid[4..6].copy_from_slice(&row.InterfaceGuid.data2.to_be_bytes());
        guid[6..8].copy_from_slice(&row.InterfaceGuid.data3.to_be_bytes());
        guid[8..].copy_from_slice(&row.InterfaceGuid.data4);
        let text = |data: &[u16]| -> Result<String> {
            let end = data.iter().position(|v| *v == 0).ok_or(Error::Conflict)?;
            String::from_utf16(&data[..end]).map_err(|_| Error::Conflict)
        };
        Ok(super::super::member_carrier_provider::Expected {
            guid,
            luid: unsafe { row.InterfaceLuid.Value },
            index: row.InterfaceIndex,
            name: text(&row.Alias)?,
            description: text(&row.Description)?,
            if_type: row.Type,
            tunnel_type: row.TunnelType,
        })
    }
}

pub(crate) fn complete_provider_inputs(
    context: &Context,
    carrier: &[ExpectedProvider],
    members: &[ExpectedProvider],
) -> Result<Vec<ExpectedProvider>> {
    if carrier.len() > 1
        || members.len() > 2
        || context.bindings.iter().enumerate().any(|(n, binding)| {
            binding.role != [Role::RoleCarrier, Role::MemberA, Role::MemberB][n]
                || binding.guid == [0; 16]
                || context.bindings[..n].iter().any(|old| {
                    old.guid == binding.guid || old.name.eq_ignore_ascii_case(&binding.name)
                })
        })
    {
        return Err(Error::Conflict);
    }
    let mut result: Vec<ExpectedProvider> = Vec::with_capacity(carrier.len() + members.len());
    for (item, carrier_role) in carrier
        .iter()
        .map(|item| (item, true))
        .chain(members.iter().map(|item| (item, false)))
    {
        let identity = &item.identity;
        let matches = if carrier_role {
            &context.bindings[..1]
        } else {
            &context.bindings[1..]
        };
        if carrier_role && item.kind != ProviderKind::Wintun
            || !matches
                .iter()
                .any(|b| b.guid == identity.guid && b.name == identity.name)
            || identity.luid == 0
            || identity.index == 0
            || identity.if_type != 53
            || identity.tunnel_type != 0
            || result.iter().any(|old| {
                old.identity.guid == identity.guid
                    || old.identity.luid == identity.luid
                    || old.identity.index == identity.index
                    || old.identity.name.eq_ignore_ascii_case(&identity.name)
            })
        {
            return Err(Error::Conflict);
        }
        result.push(item.clone());
    }
    Ok(result)
}

#[cfg(test)]
#[path = "member_carrier_members_tests.rs"]
mod tests;
