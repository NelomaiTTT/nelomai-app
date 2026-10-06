//! Caller-rooted addressless member operations. Not a factory or a gate implementation.
#![allow(dead_code)]

use std::rc::Rc;

trait NeverRegistryRead {
    type Handle;
    fn interfaces(&mut self) -> crate::member_carrier::Result<Self::Handle>;
    fn name(&mut self, key: &Self::Handle) -> crate::member_carrier::Result<String>;
    fn open(
        &mut self,
        parent: &Self::Handle,
        child: &str,
    ) -> crate::member_carrier::Result<Option<Self::Handle>>;
}

fn inspect_never_member_key<K: NeverRegistryRead>(
    kernel: &mut K,
    context: &crate::member_carrier_native_ownership::Context,
    index: usize,
) -> crate::member_carrier::Result<()> {
    use crate::{
        member_carrier::CarrierError as Error, member_carrier_native_ownership as ownership,
    };
    ownership::validate_context(context)?;
    let binding = context.bindings.get(index).ok_or(Error::Invalid)?;
    let child = binding
        .registry_path
        .strip_prefix(r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\")
        .filter(|c| c.len() == 38 && !c.contains('\\'))
        .ok_or(Error::Invalid)?;
    let parent = kernel.interfaces()?;
    let name = kernel.name(&parent)?;
    let normalized = name.to_ascii_lowercase();
    let prefix = r"\registry\machine\system\controlset";
    let suffix = r"\services\tcpip\parameters\interfaces";
    let number = normalized
        .strip_prefix(prefix)
        .and_then(|n| n.strip_suffix(suffix))
        .ok_or(Error::Conflict)?;
    if number.len() != 3 || !number.bytes().all(|b| b.is_ascii_digit()) || number == "000" {
        return Err(Error::Conflict);
    }
    if kernel.open(&parent, child)?.is_some() {
        return Err(Error::Pending);
    }
    if !kernel.name(&parent)?.eq_ignore_ascii_case(&name) {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn require_never_native_records(
    records: &[Option<Vec<u8>>; 7],
) -> crate::member_carrier::Result<()> {
    if records.iter().any(Option::is_some) {
        return Err(crate::member_carrier::CarrierError::Pending);
    }
    Ok(())
}

/// Protected comparison inventory only. Initial receipt admission must come
/// from the registered original Assembly reader, never this DATA predicate.
fn require_never_inventory(
    context: &crate::member_carrier_native_ownership::Context,
    effects: &[Option<Vec<u8>>; 7],
    creator: Option<&[u8]>,
    verify_initial: impl FnOnce(&[u8]) -> crate::member_carrier::Result<()>,
) -> crate::member_carrier::Result<()> {
    use crate::member_carrier::CarrierError as Error;
    #[cfg(not(windows))]
    use crate::member_carrier_creator::CreatorRecord;
    #[cfg(windows)]
    use crate::windows::member_carrier_creator::CreatorRecord;
    crate::member_carrier_native_ownership::validate_context(context)?;
    if let Some(bytes) = creator {
        CreatorRecord::decode(bytes)
            .and_then(|record| record.require_context(context))
            .map_err(|_| Error::Conflict)?;
    }
    if effects
        .iter()
        .enumerate()
        .any(|(i, r)| i != 2 && r.is_some())
    {
        return Err(Error::Pending);
    }
    if let Some(bytes) = &effects[2] {
        use crate::member_carrier_native_ownership::{
            FullNativeRows, KeyPhase, Phase, Record, Value,
        };
        let record = Record::decode(bytes)?;
        if record.context != *context
            || record.generation != 1
            || record.phase != Phase::Preparing
            || record.native_rows != FullNativeRows::Unbound
            || record.keys.iter().any(|key| {
                key.phase != KeyPhase::Unstarted
                    || key.new_key_ack
                    || key.baseline != Value::Absent
                    || key.current != Value::Absent
                    || key.pending.is_some()
            })
        {
            return Err(Error::Conflict);
        }
        // This comparison alone admits nothing. The actual registered initial
        // ACK and journal must independently verify the SAME observed bytes.
        verify_initial(bytes)?;
    }
    Ok(())
}

/// Protected DATA frame only. The actual original Never/initial journal,
/// Calling, lock, full SDK/private/services/keys and BFE checks remain required.
fn require_pre_pair_session(
    context: &crate::member_carrier_native_ownership::Context,
    session: &nelomai_client_tunnel::redundancy::session::SessionSnapshot,
    pair_present: bool,
) -> crate::member_carrier::Result<()> {
    use crate::member_carrier::CarrierError as Error;
    use nelomai_client_tunnel::redundancy::session::SessionPhase;
    crate::member_carrier_native_ownership::validate_context(context)?;
    if pair_present
        || session.scope != context.intent.scope
        || session.phase != SessionPhase::Stopping
        || session.network_epoch != context.provenance.network_epoch
        || session.installed != [false; 2]
        || session.committed != [false; 2]
        || session.role_confirmed
        || session.local_revision == 0
        || session.role_generation == 0
        || session.membership_generation == 0
        || session.role_generation > i64::MAX as u64
        || session.membership_generation > i64::MAX as u64
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Does not own the Assembly (which may retain the Never ledger). An attempted
/// registration cannot be replaced after error, unwind, reentry or weak expiry.
struct InitialNoCRegistration<T> {
    original: std::cell::RefCell<Option<std::rc::Weak<T>>>,
    attempted: std::cell::Cell<bool>,
    tainted: std::cell::Cell<bool>,
    acknowledged: std::cell::Cell<bool>,
}
impl<T> InitialNoCRegistration<T> {
    fn new() -> Self {
        Self {
            original: std::cell::RefCell::new(None),
            attempted: std::cell::Cell::new(false),
            tainted: std::cell::Cell::new(false),
            acknowledged: std::cell::Cell::new(false),
        }
    }
    fn retain(
        &self,
        original: &Rc<T>,
        postflight: impl FnOnce(&T) -> crate::member_carrier::Result<()>,
    ) -> crate::member_carrier::Result<()> {
        use crate::member_carrier::CarrierError as Error;
        if self.attempted.replace(true) {
            self.tainted.set(true);
            return Err(Error::Retired);
        }
        // No RefCell borrow survives into the actual journal/runtime callback.
        *self
            .original
            .try_borrow_mut()
            .map_err(|_| Error::Conflict)? = Some(Rc::downgrade(original));
        postflight(original)?;
        if self.tainted.get() {
            return Err(Error::Retired);
        }
        self.acknowledged.set(true);
        Ok(())
    }
    fn read(&self) -> crate::member_carrier::Result<Rc<T>> {
        use crate::member_carrier::CarrierError as Error;
        if !self.acknowledged.get() || self.tainted.get() {
            return Err(Error::Pending);
        }
        self.original
            .try_borrow()
            .map_err(|_| Error::Conflict)?
            .as_ref()
            .and_then(std::rc::Weak::upgrade)
            .ok_or(Error::Retired)
    }
}

/// Private original factory history, not caller-selected absence bits. Every
/// member construction/Start goes through the SAME retained history.
struct NeverMemberHistory {
    carrier_attempted: std::cell::Cell<bool>,
    prepared: [std::cell::Cell<bool>; 2],
    started: [std::cell::Cell<bool>; 2],
    generation: [std::cell::Cell<u64>; 2],
}
#[derive(Clone, Copy)]
enum TerminalMemberRoot {
    Prepared(u64),
    Unstarted(u64),
    Closed(u64),
}
fn verify_terminal_generation_coverage(
    history: &NeverMemberHistory,
    current: [Option<TerminalMemberRoot>; 2],
    retired: &[(usize, u64, u64)],
) -> crate::member_carrier::Result<()> {
    use crate::member_carrier::CarrierError as Error;
    for (position, &(slot, old, next)) in retired.iter().enumerate() {
        if slot >= 2
            || old == 0
            || old.checked_add(1) != Some(next)
            || next > history.generation[slot].get()
            || !history.carrier_attempted.get()
            || retired[..position]
                .iter()
                .any(|&(s, g, _)| s == slot && g == old)
        {
            return Err(Error::Conflict);
        }
    }
    for (slot, root) in current.into_iter().enumerate() {
        let generation = history.generation[slot].get();
        if generation == 0
            || u64::try_from(retired.iter().filter(|&&(s, _, _)| s == slot).count()).ok()
                != Some(generation - 1)
            || (history.started[slot].get()
                && (!history.prepared[slot].get() || !history.carrier_attempted.get()))
        {
            return Err(Error::Pending);
        }
        match root {
            Some(TerminalMemberRoot::Closed(g))
                if g == generation && history.started[slot].get() => {}
            Some(TerminalMemberRoot::Prepared(g) | TerminalMemberRoot::Unstarted(g))
                if g == generation
                    && history.prepared[slot].get()
                    && !history.started[slot].get() => {}
            // A failed readonly constructor leaves the original preparation
            // flag but cannot enter Start without a rooted controller. This is
            // private no-Start history, NOT None-as-native-absence evidence.
            None if !history.started[slot].get() => (),
            _ => return Err(Error::Pending),
        }
    }
    Ok(())
}

fn verify_prepublication_prepared_coverage(
    history: &NeverMemberHistory,
    rooted: [Option<u64>; 2],
    published: [bool; 2],
) -> crate::member_carrier::Result<()> {
    use crate::member_carrier::CarrierError as Error;
    if !history.carrier_attempted.get() {
        return Err(Error::Pending);
    }
    for index in 0..2 {
        match rooted[index] {
            Some(1) => history.verify_unstarted_preparation(index, 1)?,
            None if !published[index] => history.uncaptured(index)?,
            _ => return Err(Error::Pending),
        }
    }
    Ok(())
}
impl Default for NeverMemberHistory {
    fn default() -> Self {
        Self {
            carrier_attempted: std::cell::Cell::new(false),
            prepared: std::array::from_fn(|_| std::cell::Cell::new(false)),
            started: std::array::from_fn(|_| std::cell::Cell::new(false)),
            generation: std::array::from_fn(|_| std::cell::Cell::new(1)),
        }
    }
}
impl NeverMemberHistory {
    fn verify_unstarted_preparation(
        &self,
        index: usize,
        generation: u64,
    ) -> crate::member_carrier::Result<()> {
        use crate::member_carrier::CarrierError as Error;
        let current = self.generation.get(index).ok_or(Error::Invalid)?;
        if generation == 0
            || current.get() != generation
            || !self.prepared[index].get()
            || self.started[index].get()
            || !self.carrier_attempted.get()
        {
            return Err(Error::Pending);
        }
        Ok(())
    }
    fn prepare(&self, index: usize) -> crate::member_carrier::Result<u64> {
        let flag = self
            .prepared
            .get(index)
            .ok_or(crate::member_carrier::CarrierError::Invalid)?;
        if flag.replace(true) {
            return Err(crate::member_carrier::CarrierError::Retired);
        }
        Ok(self.generation[index].get())
    }
    fn start(&self, index: usize, generation: u64) -> crate::member_carrier::Result<()> {
        use crate::member_carrier::CarrierError;
        let flag = self.started.get(index).ok_or(CarrierError::Invalid)?;
        if self.generation[index].get() != generation {
            return Err(CarrierError::Retired);
        }
        if flag.replace(true) || !self.prepared[index].get() || !self.carrier_attempted.get() {
            return Err(CarrierError::Pending);
        }
        Ok(())
    }
    // Called ONLY after native wrapper verifies/root-retains actual original
    // ClosedMemberReceipt; this pure state transition supplies no SDK authority.
    fn retire_generation(
        &self,
        index: usize,
        generation: u64,
    ) -> crate::member_carrier::Result<u64> {
        use crate::member_carrier::CarrierError as Error;
        let current = self.generation.get(index).ok_or(Error::Invalid)?;
        if current.get() != generation
            || !self.prepared[index].get()
            || !self.started[index].get()
            || !self.carrier_attempted.get()
        {
            return Err(Error::Pending);
        }
        let next = generation.checked_add(1).ok_or(Error::Pending)?;
        current.set(next);
        self.prepared[index].set(false);
        self.started[index].set(false);
        Ok(next)
    }
    fn verify_retired_generation(
        &self,
        index: usize,
        old: u64,
        next: u64,
    ) -> crate::member_carrier::Result<()> {
        use crate::member_carrier::CarrierError as Error;
        let current = self.generation.get(index).ok_or(Error::Invalid)?;
        if old == 0
            || old.checked_add(1) != Some(next)
            || current.get() != next
            || !self.carrier_attempted.get()
            || self.started[index].get()
        {
            return Err(Error::Retired);
        }
        Ok(())
    }
    fn verify_started_generation(
        &self,
        index: usize,
        old: u64,
        next: u64,
    ) -> crate::member_carrier::Result<()> {
        use crate::member_carrier::CarrierError as Error;
        let current = self.generation.get(index).ok_or(Error::Invalid)?;
        if old == 0
            || old.checked_add(1) != Some(next)
            || current.get() != next
            || !self.carrier_attempted.get()
            || !self.prepared[index].get()
            || !self.started[index].get()
        {
            return Err(Error::Retired);
        }
        Ok(())
    }
    fn verify_initial_started(
        &self,
        index: usize,
        generation: u64,
    ) -> crate::member_carrier::Result<()> {
        use crate::member_carrier::CarrierError as Error;
        let current = self.generation.get(index).ok_or(Error::Invalid)?;
        if generation != 1
            || current.get() != 1
            || !self.carrier_attempted.get()
            || !self.prepared[index].get()
            || !self.started[index].get()
        {
            return Err(Error::Retired);
        }
        Ok(())
    }
    fn cold(&self) -> crate::member_carrier::Result<()> {
        if self.carrier_attempted.get() || self.started.iter().any(std::cell::Cell::get) {
            return Err(crate::member_carrier::CarrierError::Pending);
        }
        Ok(())
    }
    fn uncaptured(&self, index: usize) -> crate::member_carrier::Result<()> {
        use crate::member_carrier::CarrierError;
        if self.prepared.get(index).ok_or(CarrierError::Invalid)?.get()
            || self.started[index].get()
            || self.generation[index].get() != 1
        {
            return Err(CarrierError::Pending);
        }
        Ok(())
    }
}

fn validate_never_member_frame(
    context: &crate::member_carrier_native_ownership::Context,
    current: &crate::member_carrier_pair::Record,
    slot: nelomai_contracts::dispatcher::TunnelSlot,
) -> crate::member_carrier::Result<()> {
    use crate::{member_carrier::CarrierError as Error, member_carrier_pair as pair};
    current.validate().map_err(|_| Error::Conflict)?;
    if current.scope != context.intent.scope || current.provenance != context.provenance {
        return Err(Error::Conflict);
    }
    if current.phase == pair::Phase::Fresh {
        return Ok(());
    }
    let original = current.members
        [usize::from(slot == nelomai_contracts::dispatcher::TunnelSlot::B)]
    .as_ref()
    .map(|m| &m.owner.intent);
    if current.phase == crate::member_carrier_pair::Phase::Closing && current.stop_stage == 12 {
        return validate_closing12_unstarted(context, current, slot, original);
    }
    validate_unstarted_closing(context, current, slot, original)
}

/// Comparison-only frame for the disjoint readonly FullEmpty lane. Actual
/// original owner/never ledger, Calling, key lock and retained closed-C SDK
/// bracket are mandatory in native callers; Prepared JSON is not a no-Start ACK.
fn validate_closing12_unstarted(
    context: &crate::member_carrier_native_ownership::Context,
    current: &crate::member_carrier_pair::Record,
    slot: nelomai_contracts::dispatcher::TunnelSlot,
    original: Option<&crate::member_owner::Intent>,
) -> crate::member_carrier::Result<()> {
    use crate::{member_carrier::CarrierError as Error, member_carrier_pair as pair};
    if current.stop_stage != 12 || current.pending != Some(pair::Effect::FullEmpty) {
        return Err(Error::Conflict);
    }
    validate_prepublication_unstarted_origin(context, current, slot, original)
}
fn validate_prepublication_unstarted_origin(
    context: &crate::member_carrier_native_ownership::Context,
    current: &crate::member_carrier_pair::Record,
    slot: nelomai_contracts::dispatcher::TunnelSlot,
    original: Option<&crate::member_owner::Intent>,
) -> crate::member_carrier::Result<()> {
    use crate::{
        member_carrier::CarrierError as Error, member_carrier_pair as pair, member_owner::Phase,
    };
    crate::member_carrier_native_ownership::validate_context(context)?;
    current.validate().map_err(|_| Error::Conflict)?;
    let index = usize::from(slot == nelomai_contracts::dispatcher::TunnelSlot::B);
    if current.scope != context.intent.scope
        || current.provenance != context.provenance
        || current.phase != pair::Phase::Closing
        || current.pending_guard.is_some()
        || current.active.is_some()
        || current.operation.is_some()
        || current.network.is_some()
        || current.guard
            != crate::member_carrier_guard::Model::empty(current.scope.clone())
                .map_err(|_| Error::Conflict)?
        || (!current.addresses.is_empty() && current.addresses != context.intent.addresses)
        || (current.addresses.is_empty() && (!current.dns.is_empty() || current.options.is_some()))
        || current
            .carrier
            .is_some_and(|c| c.guid != context.bindings[0].guid)
        || original.is_some_and(|i| i.scope != current.scope || i.slot != slot)
        || current.members[index]
            .as_ref()
            .is_some_and(|m| original != Some(&m.owner.intent))
        || current.members.iter().flatten().any(|m| {
            m.owner.phase != Phase::Prepared
                || m.owner.proof.is_some()
                || m.owner.retired_proof.is_some()
                || m.owner.previous_config_sha256.is_some()
        })
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn validate_pregraph_native_empty_unstarted(
    context: &crate::member_carrier_native_ownership::Context,
    current: &crate::member_carrier_pair::Record,
    slot: nelomai_contracts::dispatcher::TunnelSlot,
    original: Option<&crate::member_owner::Intent>,
) -> crate::member_carrier::Result<()> {
    use crate::{member_carrier::CarrierError as Error, member_carrier_pair as pair};
    if !matches!(
        (current.stop_stage, current.pending),
        (9, Some(pair::Effect::NativeEmpty)) | (10, Some(pair::Effect::Guard))
    ) || current.addresses != context.intent.addresses
        || current.options.is_none()
    {
        return Err(Error::Conflict);
    }
    validate_prepublication_unstarted_origin(context, current, slot, original)
}

#[derive(Clone, Copy)]
enum PrepublicationOriginalRead {
    EarlyClosing,
    NativeEmpty,
    RestoringKeys,
    FullEmpty,
}

fn validate_never_bootstrap_native_frame(
    context: &crate::member_carrier_native_ownership::Context,
    current: &crate::member_carrier_pair::Record,
) -> crate::member_carrier::Result<()> {
    use crate::{member_carrier::CarrierError as Error, member_carrier_pair as pair};
    validate_never_bootstrap_origin(context, current)?;
    if !matches!(
        (current.stop_stage, current.pending.as_ref()),
        (9, Some(pair::Effect::NativeEmpty)) | (10, Some(pair::Effect::Guard))
    ) {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn validate_never_cleanup_stage_frame(
    context: &crate::member_carrier_native_ownership::Context,
    current: &crate::member_carrier_pair::Record,
) -> crate::member_carrier::Result<()> {
    validate_never_bootstrap_origin(context, current)?;
    #[cfg(not(windows))]
    use crate::member_carrier_pair_io::require_no_constructor_cleanup_frame;
    #[cfg(windows)]
    use crate::windows::member_carrier_pair_io::require_no_constructor_cleanup_frame;
    require_no_constructor_cleanup_frame(current)
        .map_err(|_| crate::member_carrier::CarrierError::Conflict)
}

// Shared comparison facts ONLY, not a receipt/Calling/effect capability.
// The disjoint callers must additionally require their own exact stage/effect.
fn validate_never_bootstrap_origin(
    context: &crate::member_carrier_native_ownership::Context,
    current: &crate::member_carrier_pair::Record,
) -> crate::member_carrier::Result<()> {
    use crate::{
        member_carrier::CarrierError as Error, member_carrier_pair as pair, member_owner::Phase,
    };
    current.validate().map_err(|_| Error::Conflict)?;
    crate::member_carrier_native_ownership::validate_context(context)?;
    if current.scope != context.intent.scope
        || current.provenance != context.provenance
        || current.phase != pair::Phase::Closing
        || current.carrier.is_some()
        || current.network.is_some()
        || current.active.is_some()
        || current.operation.is_some()
        || current.pending_guard.is_some()
        || current.guard
            != crate::member_carrier_guard::Model::empty(current.scope.clone())
                .map_err(|_| Error::Conflict)?
        || (!current.addresses.is_empty() && current.addresses != context.intent.addresses)
        || (current.addresses.is_empty() && (!current.dns.is_empty() || current.options.is_some()))
        || current.members.iter().flatten().any(|m| {
            m.owner.phase != Phase::Prepared
                || m.owner.proof.is_some()
                || m.owner.retired_proof.is_some()
                || m.owner.previous_config_sha256.is_some()
        })
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn verify_never_bootstrap_reads(
    history: &NeverMemberHistory,
    context: &crate::member_carrier_native_ownership::Context,
    current: &crate::member_carrier_pair::Record,
    mut read: impl FnMut() -> crate::member_carrier::Result<()>,
) -> crate::member_carrier::Result<()> {
    history.cold()?;
    validate_never_bootstrap_native_frame(context, current)?;
    for _ in 0..2 {
        read()?;
        history.cold()?;
        validate_never_bootstrap_native_frame(context, current)?;
    }
    Ok(())
}

fn verify_never_bootstrap_full_reads(
    history: &NeverMemberHistory,
    context: &crate::member_carrier_native_ownership::Context,
    current: &crate::member_carrier_pair::Record,
    mut read: impl FnMut() -> crate::member_carrier::Result<()>,
) -> crate::member_carrier::Result<()> {
    history.cold()?;
    validate_never_bootstrap_full_frame(context, current)?;
    for _ in 0..2 {
        read()?;
        history.cold()?;
        validate_never_bootstrap_full_frame(context, current)?;
    }
    Ok(())
}

fn validate_never_bootstrap_full_frame(
    context: &crate::member_carrier_native_ownership::Context,
    current: &crate::member_carrier_pair::Record,
) -> crate::member_carrier::Result<()> {
    use crate::{member_carrier::CarrierError as Error, member_carrier_pair as pair};
    validate_never_bootstrap_origin(context, current)?;
    if current.stop_stage != 12 || current.pending != Some(pair::Effect::FullEmpty) {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn validate_never_member_terminal_frame(
    context: &crate::member_carrier_native_ownership::Context,
    current: &crate::member_carrier_pair::Record,
) -> crate::member_carrier::Result<()> {
    use crate::{member_carrier::CarrierError as Error, member_carrier_pair as pair};
    current.validate().map_err(|_| Error::Conflict)?;
    if current.scope != context.intent.scope
        || current.provenance != context.provenance
        || current.phase != pair::Phase::Stopped
        || current.stop_stage != 12
        || current.carrier.is_some()
        || current.members.iter().any(Option::is_some)
        || current.network.is_some()
        || current.pending.is_some()
        || current.pending_guard.is_some()
        || current.operation.is_some()
        || current.active.is_some()
        || current.guard
            != crate::member_carrier_guard::Model::empty(current.scope.clone())
                .map_err(|_| Error::Conflict)?
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn verify_absent_file_reads<E>(
    mut verify_parent: impl FnMut() -> Result<(), E>,
    mut open_existing: impl FnMut() -> Result<bool, E>,
    conflict: impl Fn() -> E,
) -> Result<(), E> {
    verify_parent()?;
    if open_existing()? {
        return Err(conflict());
    }
    verify_parent()?;
    if open_existing()? {
        return Err(conflict());
    }
    verify_parent()
}

fn validate_before_carrier(
    context: &crate::member_carrier_native_ownership::Context,
    record: &crate::member_carrier_pair::Record,
    intent: &crate::member_owner::Intent,
) -> crate::member_carrier::Result<()> {
    use crate::{
        member_carrier::CarrierError as Error, member_carrier_pair as pair, member_owner::Phase,
    };
    use nelomai_client_tunnel::redundancy::Slot;
    record.validate().map_err(|_| Error::Conflict)?;
    let index = usize::from(intent.slot == nelomai_contracts::dispatcher::TunnelSlot::B);
    let slot = if index == 0 { Slot::A } else { Slot::B };
    if record.scope != context.intent.scope
        || record.provenance != context.provenance
        || record.addresses != context.intent.addresses
        || intent.scope != record.scope
        || record.phase != pair::Phase::Starting
        || record.operation != Some(pair::Operation::Start(slot))
        || record.pending.is_some()
        || record.carrier.is_some()
        || record.active.is_some()
        || record.stop_stage != 0
        || record.network.is_some()
        || record.pending_guard.is_some()
        || record.guard
            != crate::member_carrier_guard::Model::empty(record.scope.clone())
                .map_err(|_| Error::Conflict)?
        || record.members[1 - index].is_some()
        || record.members[index].as_ref().is_none_or(|m| {
            m.owner.intent != *intent
                || m.owner.phase != Phase::Prepared
                || m.owner.proof.is_some()
                || m.owner.retired_proof.is_some()
                || m.owner.previous_config_sha256.is_some()
        })
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[derive(Debug)]
enum ColdPackageError<E> {
    Retired,
    Boundary(E),
}
struct ColdPackageRoot<P> {
    original: Option<P>,
    denied: bool,
}
impl<P> ColdPackageRoot<P> {
    fn verify_existing<E>(
        &mut self,
        authenticate: impl FnMut() -> Result<(), E>,
        refresh: impl FnMut(&mut P) -> Result<(), E>,
        missing: E,
    ) -> Result<(), ColdPackageError<E>> {
        // After C construction the original cold observation MUST exist.
        // This path cannot construct/import a new package from equal metadata.
        self.verify(authenticate, || Err(missing), refresh)
    }
    fn new() -> Self {
        Self {
            original: None,
            denied: false,
        }
    }
    fn verify<E>(
        &mut self,
        mut authenticate: impl FnMut() -> Result<(), E>,
        construct: impl FnOnce() -> Result<P, E>,
        mut refresh: impl FnMut(&mut P) -> Result<(), E>,
    ) -> Result<(), ColdPackageError<E>> {
        if self.denied {
            return Err(ColdPackageError::Retired);
        }
        self.denied = true; // Err/unwind cannot resurrect a prior observation.
        authenticate().map_err(ColdPackageError::Boundary)?;
        if let Some(original) = &mut self.original {
            refresh(original).map_err(ColdPackageError::Boundary)?;
        } else {
            // Real constructor return retained BEFORE any fallible postflight.
            self.original = Some(construct().map_err(ColdPackageError::Boundary)?);
        }
        authenticate().map_err(ColdPackageError::Boundary)?;
        self.denied = false;
        Ok(())
    }
}

/// The builder is private and infallible; all fallible origin/registration/G
/// checks run only after the SAME owner has been placed in the caller's slot.
struct PreparedRoot<O> {
    owner: Option<O>,
}
pub(crate) struct RetiredGenerationRoots<P, C, T> {
    _prepared: P,
    _controller: C,
    _ticket: Rc<T>,
}
fn retain_verified_closed_generation<P, C, T>(
    prepared: &mut Option<P>,
    controller: &mut Option<C>,
    ticket: &Rc<T>,
    retired: &mut Vec<RetiredGenerationRoots<P, C, T>>,
) -> crate::member_carrier::Result<()> {
    use crate::member_carrier::CarrierError as Error;
    if prepared.is_none() || controller.is_none() {
        return Err(Error::Retired);
    }
    retired.try_reserve(1).map_err(|_| Error::Pending)?;
    retired.push(RetiredGenerationRoots {
        _prepared: prepared.take().expect("verified original preparation"),
        _controller: controller
            .take()
            .expect("verified original closed controller"),
        _ticket: ticket.clone(),
    });
    Ok(())
}
fn validate_preparation_proposal(
    context: &crate::member_carrier_native_ownership::Context,
    current: &crate::member_carrier_pair::Record,
    proposal: &crate::member_carrier_pair::Record,
    intent: &crate::member_owner::Intent,
) -> crate::member_carrier::Result<()> {
    use crate::{member_carrier::CarrierError as Error, member_carrier_pair as pair};
    use nelomai_client_tunnel::redundancy::Slot;
    current.validate().map_err(|_| Error::Conflict)?;
    proposal.validate().map_err(|_| Error::Conflict)?;
    let slot = if intent.slot == nelomai_contracts::dispatcher::TunnelSlot::A {
        Slot::A
    } else {
        Slot::B
    };
    if current.phase != pair::Phase::Fresh
        || current.scope != context.intent.scope
        || current.provenance != context.provenance
        || intent.scope != current.scope
        || current.carrier.is_some()
        || current.members.iter().any(Option::is_some)
        || current.active.is_some()
        || current.network.is_some()
        || current.options.is_some()
        || current.pending.is_some()
        || current.pending_guard.is_some()
        || current.operation.is_some()
        || current.stop_stage != 0
        || !current.addresses.is_empty()
        || !current.dns.is_empty()
        || current.guard
            != crate::member_carrier_guard::Model::empty(current.scope.clone())
                .map_err(|_| Error::Conflict)?
        || proposal.version != current.version
        || proposal.revision != current.revision
        || proposal.scope != current.scope
        || proposal.provenance != current.provenance
        || proposal.phase != pair::Phase::Starting
        || proposal.operation != Some(pair::Operation::Start(slot))
        || proposal.addresses != context.intent.addresses
        || proposal.carrier.is_some()
        || proposal.members.iter().any(Option::is_some)
        || proposal.active.is_some()
        || proposal.network.is_some()
        || proposal.pending.is_some()
        || proposal.pending_guard.is_some()
        || proposal.stop_stage != 0
        || proposal.guard != current.guard
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
impl<O> PreparedRoot<O> {
    fn new(owner: O) -> Self {
        Self { owner: Some(owner) }
    }
    fn attach<T, E>(
        &mut self,
        slot: &mut Option<T>,
        build: impl FnOnce(O) -> T,
        validate: impl FnOnce(&mut T) -> Result<(), E>,
    ) -> Result<(), RootError<E>> {
        if slot.is_some() {
            return Err(RootError::Retired);
        }
        let owner = self.owner.take().ok_or(RootError::Retired)?;
        *slot = Some(build(owner));
        validate(slot.as_mut().expect("rooted SAME prepared owner")).map_err(RootError::Operation)
    }
}

fn validate_live_preparation_proposal(
    context: &crate::member_carrier_native_ownership::Context,
    current: &crate::member_carrier_pair::Record,
    proposal: &crate::member_carrier_pair::Record,
    intent: &crate::member_owner::Intent,
) -> crate::member_carrier::Result<()> {
    use crate::{member_carrier::CarrierError as Error, member_carrier_pair as pair, member_owner};
    use nelomai_client_tunnel::redundancy::Slot;
    let index = usize::from(intent.slot == nelomai_contracts::dispatcher::TunnelSlot::B);
    let other_slot = if index == 0 { Slot::B } else { Slot::A };
    current.validate().map_err(|_| Error::Conflict)?;
    proposal.validate().map_err(|_| Error::Conflict)?;
    if current != proposal
        || current.scope != context.intent.scope
        || current.provenance != context.provenance
        || current.addresses != context.intent.addresses
        || intent.scope != current.scope
        || current.phase != pair::Phase::Running
        || current.operation.is_some()
        || current.pending.is_some()
        || current.pending_guard.is_some()
        || current.stop_stage != 0
        || current.active != Some(other_slot)
        || current
            .carrier
            .is_none_or(|c| c.guid != context.bindings[0].guid)
        || current.members[index].is_some()
        || current.members[1 - index].as_ref().is_none_or(|m| {
            m.owner.phase != member_owner::Phase::Running
                || m.owner
                    .proof
                    .is_none_or(|p| p.interface.guid != context.bindings[2 - index].guid)
        })
        || current.network.as_ref().is_none_or(|n| n.pending.is_some())
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn validate_live_preparation_observation(
    context: &crate::member_carrier_native_ownership::Context,
    current: &crate::member_carrier_pair::Record,
    intent: &crate::member_owner::Intent,
    carrier: Option<crate::member_owner::InterfaceProof>,
    members: [Option<crate::member_owner::InterfaceProof>; 2],
    closed: [bool; 2],
    other: &(
        crate::member_owner::Intent,
        crate::member_owner::NativeProof,
    ),
) -> crate::member_carrier::Result<()> {
    use crate::member_carrier::CarrierError as Error;
    validate_live_preparation_proposal(context, current, current, intent)?;
    let index = usize::from(intent.slot == nelomai_contracts::dispatcher::TunnelSlot::B);
    let remaining = &current.members[1 - index]
        .as_ref()
        .ok_or(Error::Conflict)?
        .owner;
    if carrier != current.carrier
        || members[index].is_some()
        || closed != [false; 2]
        || remaining.intent != other.0
        || remaining.proof != Some(other.1)
        || members[1 - index] != Some(other.1.interface)
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn validate_replacement_prior(
    context: &crate::member_carrier_native_ownership::Context,
    intent: &crate::member_owner::Intent,
    stopped: &crate::member_owner::Record,
    prior: Option<&crate::member_owner::Record>,
) -> crate::member_carrier::Result<()> {
    use crate::{member_carrier::CarrierError as Error, member_owner as owner};
    let index = usize::from(intent.slot == nelomai_contracts::dispatcher::TunnelSlot::B);
    owner::validate_prior_stopped(intent, stopped).map_err(|_| Error::Conflict)?;
    if intent.scope != context.intent.scope
        || stopped.phase != owner::Phase::Stopped
        || stopped
            .retired_proof
            .is_none_or(|p| p.interface.guid != context.bindings[index + 1].guid)
        || prior != Some(stopped)
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

struct ReplacementHistory<'a> {
    closed: [bool; 2],
    stopped: &'a crate::member_owner::Record,
    intent: &'a crate::member_owner::Intent,
    proof: crate::member_owner::NativeProof,
}
fn validate_replacement_preparation_observation(
    context: &crate::member_carrier_native_ownership::Context,
    current: &crate::member_carrier_pair::Record,
    intent: &crate::member_owner::Intent,
    carrier: Option<crate::member_owner::InterfaceProof>,
    members: [Option<crate::member_owner::InterfaceProof>; 2],
    history: ReplacementHistory<'_>,
    other: &(
        crate::member_owner::Intent,
        crate::member_owner::NativeProof,
    ),
) -> crate::member_carrier::Result<()> {
    use crate::member_carrier::CarrierError as Error;
    validate_replacement_prior(context, intent, history.stopped, Some(history.stopped))?;
    let index = usize::from(intent.slot == nelomai_contracts::dispatcher::TunnelSlot::B);
    let mut closed = [false; 2];
    closed[index] = true;
    if history.closed != closed
        || history.intent != &history.stopped.intent
        || history.stopped.retired_proof != Some(history.proof)
    {
        return Err(Error::Conflict);
    }
    // Comparison history is intentionally NOT an ExpectedProvider/native SDK
    // input. Original Source already sampled full SDK C+live only.
    validate_live_preparation_observation(
        context, current, intent, carrier, members, [false; 2], other,
    )
}

fn validate_live_preparation_attachment(
    context: &crate::member_carrier_native_ownership::Context,
    prepared_against: &crate::member_carrier_pair::Record,
    current: &crate::member_carrier_pair::Record,
    intent: &crate::member_owner::Intent,
) -> crate::member_carrier::Result<()> {
    use crate::{member_carrier::CarrierError as Error, member_carrier_pair as pair};
    use nelomai_client_tunnel::redundancy::Slot;
    validate_live_preparation_proposal(context, prepared_against, prepared_against, intent)?;
    validate_member_operation(context, current, intent, MemberOperation::Start)?;
    let index = usize::from(intent.slot == nelomai_contracts::dispatcher::TunnelSlot::B);
    let slot = if index == 0 { Slot::A } else { Slot::B };
    if current.phase != pair::Phase::Running
        || current.operation != Some(pair::Operation::Attach(slot))
        || current.pending_guard.is_some()
        || current.revision <= prepared_against.revision
        || current.carrier != prepared_against.carrier
        || current.members[1 - index] != prepared_against.members[1 - index]
        || current.active != prepared_against.active
        || current.dns != prepared_against.dns
        || current.options != prepared_against.options
        || current.network != prepared_against.network
        || current.guard
            != prepared_against
                .guard
                .without_permits()
                .map_err(|_| Error::Conflict)?
        || current.members[index].as_ref().is_none_or(|m| {
            m.owner.retired_proof.is_some() || m.owner.previous_config_sha256.is_some()
        })
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

struct PreparedSourceRegistration<T>(std::rc::Weak<T>);
struct InitialStartedOrigin<O, S> {
    original: Rc<O>,
    source: PreparedSourceRegistration<S>,
}
impl<O, S> InitialStartedOrigin<O, S> {
    fn from_original(original: &Rc<O>, source: &Rc<S>) -> Self {
        Self {
            original: original.clone(),
            source: PreparedSourceRegistration::from_original(source),
        }
    }
    fn verify(&self, original: &Rc<O>, source: &Rc<S>) -> crate::member_carrier::Result<()> {
        if !Rc::ptr_eq(&self.original, original) || !self.source.verify(source) {
            return Err(crate::member_carrier::CarrierError::Conflict);
        }
        Ok(())
    }
    fn verify_retained_source(&self) -> crate::member_carrier::Result<()> {
        self.source
            .0
            .upgrade()
            .ok_or(crate::member_carrier::CarrierError::Retired)?;
        Ok(())
    }
}
impl<T> PreparedSourceRegistration<T> {
    fn from_original(original: &Rc<T>) -> Self {
        Self(Rc::downgrade(original))
    }
    fn verify(&self, original: &Rc<T>) -> bool {
        self.0
            .upgrade()
            .is_some_and(|actual| Rc::ptr_eq(&actual, original))
    }
}

fn validate_closed_generation_retirement(
    context: &crate::member_carrier_native_ownership::Context,
    current: &crate::member_carrier_pair::Record,
    stopped: &crate::member_owner::Record,
) -> crate::member_carrier::Result<()> {
    use crate::{
        member_carrier::CarrierError as Error, member_carrier_pair as pair, member_owner as owner,
    };
    use nelomai_client_tunnel::redundancy::Slot;
    current.validate().map_err(|_| Error::Conflict)?;
    owner::validate_record_shape(stopped).map_err(|_| Error::Conflict)?;
    let index = usize::from(stopped.intent.slot == nelomai_contracts::dispatcher::TunnelSlot::B);
    let other = if index == 0 { Slot::B } else { Slot::A };
    if current.scope != context.intent.scope
        || current.provenance != context.provenance
        || current.addresses != context.intent.addresses
        || stopped.intent.scope != current.scope
        || stopped.phase != owner::Phase::Stopped
        || stopped.proof.is_some()
        || stopped
            .retired_proof
            .is_none_or(|p| p.interface.guid != context.bindings[index + 1].guid)
        || current.phase != pair::Phase::Running
        || current.pending.is_some()
        || current.pending_guard.is_some()
        || current.operation.is_some()
        || current.stop_stage != 0
        || current.active != Some(other)
        || current.members[index].is_some()
        || current.guard.members[index].is_some()
        || current.members[1 - index]
            .as_ref()
            .is_none_or(|m| m.owner.phase != owner::Phase::Running || m.owner.proof.is_none())
        || current
            .carrier
            .is_none_or(|c| c.guid != context.bindings[0].guid)
        || current.network.as_ref().is_none_or(|n| n.pending.is_some())
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn validate_unstarted_closing(
    context: &crate::member_carrier_native_ownership::Context,
    current: &crate::member_carrier_pair::Record,
    slot: nelomai_contracts::dispatcher::TunnelSlot,
    original: Option<&crate::member_owner::Intent>,
) -> crate::member_carrier::Result<()> {
    use crate::{member_carrier::CarrierError as Error, member_carrier_pair as pair, member_owner};
    use nelomai_client_tunnel::redundancy::Slot;
    let index = usize::from(slot == nelomai_contracts::dispatcher::TunnelSlot::B);
    let target = if index == 0 { Slot::A } else { Slot::B };
    current.validate().map_err(|_| Error::Conflict)?;
    if current.scope != context.intent.scope
        || current.provenance != context.provenance
        || (!current.addresses.is_empty() && current.addresses != context.intent.addresses)
        || current.phase != pair::Phase::Closing
        || current.active.is_some()
        || current.operation.is_some()
        || current.pending_guard.is_some()
        || current.guard.permits
        || current.stop_stage != 4 + index as u8
        || current.pending != Some(pair::Effect::MemberStop(target))
        || original.is_some_and(|i| i.scope != current.scope || i.slot != slot)
        || current.members[index].as_ref().is_some_and(|m| {
            original != Some(&m.owner.intent)
                || m.owner.phase != member_owner::Phase::Prepared
                || m.owner.proof.is_some()
                || m.owner.retired_proof.is_some()
                || m.owner.previous_config_sha256.is_some()
        })
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum MemberOperation {
    Start,
    Stop,
    Retire,
}

fn validate_member_operation(
    context: &crate::member_carrier_native_ownership::Context,
    expected: &crate::member_carrier_pair::Record,
    intent: &crate::member_owner::Intent,
    operation: MemberOperation,
) -> crate::member_carrier::Result<()> {
    use crate::{member_carrier::CarrierError as Error, member_carrier_pair as pair};
    use nelomai_client_tunnel::redundancy::Slot;
    use nelomai_contracts::dispatcher::TunnelSlot;
    expected.validate().map_err(|_| Error::Conflict)?;
    let (index, slot) = match intent.slot {
        TunnelSlot::A => (0, Slot::A),
        TunnelSlot::B => (1, Slot::B),
    };
    let member = expected.members[index].as_ref().ok_or(Error::Conflict)?;
    if expected.scope != context.intent.scope
        || intent.scope != context.intent.scope
        || expected.provenance != context.provenance
        || expected.addresses != context.intent.addresses
        || member.owner.intent != *intent
    {
        return Err(Error::Conflict);
    }
    let admitted = match operation {
        MemberOperation::Start => {
            matches!(expected.phase, pair::Phase::Starting | pair::Phase::Running)
                && expected.pending == Some(pair::Effect::MemberStart(slot))
                && expected.stop_stage == 0
                && expected.operation.is_some()
                && member.owner.phase == crate::member_owner::Phase::Prepared
                && member.owner.proof.is_none()
        }
        MemberOperation::Stop => {
            expected.phase == pair::Phase::Closing
                && expected.active.is_none()
                && expected.operation.is_none()
                && expected.stop_stage == 4 + index as u8
                && expected.pending == Some(pair::Effect::MemberStop(slot))
        }
        MemberOperation::Retire => {
            super::member_carrier_member_gate::validate_retirement(context, expected, intent)
                .is_ok()
        }
    };
    if !admitted {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Comparison only. The native consumer must also reattest the borrowed opaque
/// NEW-key ACK and actual RuntimeRead/KeyLock, never infer them from these data.
fn validate_member_precreation(
    context: &crate::member_carrier_native_ownership::Context,
    current: &crate::member_carrier_native_ownership::Record,
    borrowed: &crate::member_carrier_native_ownership::Record,
    binding: &crate::member_carrier_native_ownership::Binding,
    slot: nelomai_contracts::dispatcher::TunnelSlot,
) -> crate::member_carrier::Result<()> {
    use crate::{
        member_carrier::CarrierError as Error,
        member_carrier_native_ownership::{self as native, KeyPhase, Phase, Role, Value},
    };
    use nelomai_contracts::dispatcher::TunnelSlot;
    native::validate_record(current)?;
    let (index, role) = match slot {
        TunnelSlot::A => (1, Role::MemberA),
        TunnelSlot::B => (2, Role::MemberB),
    };
    let key = &current.keys[index];
    if current != borrowed
        || current.context != *context
        || current.generation == 0
        || current.phase != Phase::Preparing
        || binding != &context.bindings[index]
        || binding.role != role
        || key.phase != KeyPhase::Disabled
        || !key.new_key_ack
        || key.baseline != Value::Absent
        || key.current != Value::DwordZero
        || key.pending.is_some()
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn validate_retirement_history(
    context: &crate::member_carrier_native_ownership::Context,
    expected: &crate::member_carrier_pair::Record,
    intent: &crate::member_owner::Intent,
    history: &super::member_carrier_members::ClosedMemberBinding,
) -> crate::member_carrier::Result<()> {
    let index = super::member_carrier_member_gate::validate_retirement(context, expected, intent)?;
    if history.intent != *intent
        || expected.members[index].as_ref().and_then(|m| m.owner.proof) != Some(history.proof)
    {
        return Err(crate::member_carrier::CarrierError::Conflict);
    }
    Ok(())
}

fn validate_original_observation(
    context: &crate::member_carrier_native_ownership::Context,
    pair: &crate::member_carrier_pair::Record,
    running: &crate::member_owner::Record,
    actual: &(
        crate::member_owner::Intent,
        crate::member_owner::NativeProof,
    ),
) -> crate::member_carrier::Result<()> {
    use crate::{member_carrier::CarrierError as Error, member_owner::Phase};
    pair.validate().map_err(|_| Error::Conflict)?;
    crate::member_owner::validate_record_shape(running).map_err(|_| Error::Conflict)?;
    let index = usize::from(running.intent.slot == nelomai_contracts::dispatcher::TunnelSlot::B);
    if pair.scope != context.intent.scope
        || pair.provenance != context.provenance
        || pair.addresses != context.intent.addresses
        || running.intent.scope != pair.scope
        || running.phase != Phase::Running
        || pair.members[index].as_ref().map(|m| &m.owner) != Some(running)
        || actual.0 != running.intent
        || Some(actual.1) != running.proof
        || actual.1.interface.guid != context.bindings[index + 1].guid
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn validate_rebind_operation(
    context: &crate::member_carrier_native_ownership::Context,
    expected: &crate::member_carrier_pair::Record,
    intent: &crate::member_owner::Intent,
) -> crate::member_carrier::Result<()> {
    use crate::{member_carrier::CarrierError as Error, member_carrier_pair as pair};
    use nelomai_client_tunnel::redundancy::Slot;
    let index = usize::from(intent.slot == nelomai_contracts::dispatcher::TunnelSlot::B);
    let slot = if index == 0 { Slot::A } else { Slot::B };
    expected.validate().map_err(|_| Error::Conflict)?;
    if expected.scope != context.intent.scope
        || expected.provenance != context.provenance
        || expected.addresses != context.intent.addresses
        || expected.phase != pair::Phase::Running
        || expected.operation != Some(pair::Operation::Rebind)
        || expected.pending != Some(pair::Effect::Rebind(slot))
        || expected.guard.permits
        || expected.pending_guard.is_some()
        || expected.stop_stage != 0
        || expected.active.is_none()
        || expected
            .carrier
            .is_none_or(|c| c.guid != context.bindings[0].guid)
        || expected.members[index].as_ref().is_none_or(|m| {
            m.owner.intent != *intent
                || m.owner.phase != crate::member_owner::Phase::Running
                || m.owner.proof.is_none()
        })
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn validate_rebound_record(
    context: &crate::member_carrier_native_ownership::Context,
    expected: &crate::member_carrier_pair::Record,
    prior: &crate::member_owner::Record,
    rebound: &crate::member_owner::Record,
) -> crate::member_carrier::Result<()> {
    validate_rebind_operation(context, expected, &prior.intent)?;
    use crate::{member_carrier::CarrierError as Error, member_owner as owner};
    let index = usize::from(prior.intent.slot == nelomai_contracts::dispatcher::TunnelSlot::B);
    owner::validate_record_shape(rebound).map_err(|_| Error::Conflict)?;
    let old = prior.proof.ok_or(Error::Pending)?;
    let proof = rebound
        .proof
        .ok_or(crate::member_carrier::CarrierError::Pending)?;
    if expected.members[index].as_ref().map(|m| &m.owner) != Some(prior)
        || rebound.intent != prior.intent
        || rebound.phase != owner::Phase::Running
        || rebound.retired_proof != Some(old)
        || rebound.previous_config_sha256.is_some()
        || proof.process == old.process
        || proof.interface != old.interface
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
enum RootError<E> {
    Retired,
    Operation(E),
}
fn pending_unknown(
    error: crate::member_carrier::CarrierError,
) -> crate::member_carrier::CarrierError {
    use crate::member_carrier::CarrierError;
    match error {
        CarrierError::Native | CarrierError::Journal => CarrierError::Pending,
        other => other,
    }
}

/// O includes the actual owner AND all source/runtime/lease pins. Return ACKs
/// are stored here before any registration or postflight can fail or unwind.
struct OperationRoot<O, R, P, C> {
    owner: Option<O>,
    running: Option<R>,
    reader: Option<P>,
    stopped: Option<R>,
    closed: Option<Rc<C>>,
    attempted: bool,
    registered: bool,
    closed_registered: bool,
    completed: bool,
}
impl<O, R, P, C> OperationRoot<O, R, P, C> {
    fn verify_terminal_inert(&self) -> crate::member_carrier::Result<()> {
        use crate::member_carrier::CarrierError as Error;
        if self.owner.is_none() {
            return Err(Error::Retired);
        }
        if self.attempted {
            if !self.completed
                || !self.closed_registered
                || self.closed.is_none()
                || self.stopped.is_none()
            {
                return Err(Error::Pending);
            }
        } else if self.completed
            || self.closed_registered
            || self.registered
            || self.running.is_some()
            || self.reader.is_some()
            || self.closed.is_some()
            || self.stopped.is_some()
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn new(owner: O) -> Self {
        Self {
            owner: Some(owner),
            running: None,
            reader: None,
            stopped: None,
            closed: None,
            attempted: false,
            registered: false,
            closed_registered: false,
            completed: false,
        }
    }
    fn start<E>(
        &mut self,
        start: impl FnOnce(&mut O) -> Result<R, E>,
        read: impl FnOnce(&mut O) -> Result<P, E>,
        register: impl FnOnce(&mut O, &mut P) -> Result<(), E>,
        postflight: impl FnOnce(&R, &mut P) -> Result<(), E>,
    ) -> Result<(), RootError<E>> {
        if self.attempted {
            return Err(RootError::Retired);
        }
        self.attempted = true;
        let owner = self.owner.as_mut().ok_or(RootError::Retired)?;
        self.running = Some(start(owner).map_err(RootError::Operation)?);
        self.reader = Some(read(owner).map_err(RootError::Operation)?);
        let reader = self.reader.as_mut().expect("rooted original reader");
        register(owner, reader).map_err(RootError::Operation)?;
        self.registered = true;
        postflight(self.running.as_ref().expect("rooted Running ACK"), reader)
            .map_err(RootError::Operation)
    }
    fn stop<E>(
        &mut self,
        stop: impl FnOnce(&mut O) -> Result<(R, C), E>,
        register: impl FnOnce(&Rc<C>) -> Result<(), E>,
        postflight: impl FnOnce(&R, &Rc<C>, (&mut O, Option<&mut P>)) -> Result<(), E>,
    ) -> Result<(), RootError<E>> {
        if !self.attempted || self.completed {
            return Err(RootError::Retired);
        }
        if self.closed.is_none() {
            let (record, receipt) = stop(self.owner.as_mut().ok_or(RootError::Retired)?)
                .map_err(RootError::Operation)?;
            self.stopped = Some(record);
            self.closed = Some(Rc::new(receipt));
        }
        let receipt = self.closed.as_ref().expect("rooted SAME Stop receipt");
        register(receipt).map_err(RootError::Operation)?;
        self.closed_registered = true;
        postflight(
            self.stopped.as_ref().expect("rooted Stopped ACK"),
            receipt,
            (
                self.owner.as_mut().ok_or(RootError::Retired)?,
                self.reader.as_mut(),
            ),
        )
        .map_err(RootError::Operation)?;
        self.completed = true;
        Ok(())
    }
}

impl<O, R, P, C> Drop for OperationRoot<O, R, P, C> {
    fn drop(&mut self) {
        if self.attempted && !self.completed {
            // Abandonment is not Stop/absence authority. Keep the entire native
            // owner/source/runtime bundle and ACKs, including partial Start.
            retain_unknown(&mut self.owner);
            retain_unknown(&mut self.running);
            retain_unknown(&mut self.reader);
            retain_unknown(&mut self.stopped);
            retain_unknown(&mut self.closed);
        }
    }
}
fn retain_unknown<T>(slot: &mut Option<T>) {
    if let Some(value) = slot.take() {
        std::mem::forget(value);
    }
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::{
        member_carrier::{CarrierError as Error, Result},
        member_carrier_native_ownership::{
            self as keys_record, Context, Phase, PrecreationReceipt,
        },
        member_carrier_pair::{self as pair, Record as PairRecord},
        member_original::{
            ClosedMemberReceipt, ClosedOldProcessReceipt, OriginalMemberRead,
            OriginalMemberRegistration, PartialMemberCleanup, PendingMemberRead, RetainedMember,
            RetiredMemberGeneration,
        },
        member_owner::{Intent, MemberOwner, Phase as MemberPhase, Record as MemberRecord},
        windows::{
            member_carrier_assembly::native::NativeInitialAssemblyNoCRead,
            member_carrier_guard::Bindings,
            member_carrier_key_authority::{KeyLock, RuntimeRead},
            member_carrier_keys::{self as keys, win32},
            member_carrier_members::{
                complete_provider_inputs, native::MemberInventoryRead, ClosedMemberBinding,
            },
            member_carrier_module::native::OriginalImage,
            member_carrier_pair_store::native_store::NativePairIntentRead,
            member_carrier_payload::native::{MemberSource, WintunSource},
            member_carrier_preload::native::WintunPreload,
            member_carrier_provider::{self as provider, ExpectedProvider, ProviderKind},
            member_carrier_runtime::native::{
                NativeBindingsWindow, NativeClosingRead, NativeSourceRead,
            },
            member_files::MemberFiles,
            member_native_deadline::NativeDeadline,
            member_owner::NativeMemberIo,
            member_session::RecordKind,
        },
    };
    use nelomai_client_tunnel::redundancy::Slot;
    use nelomai_contracts::dispatcher::TunnelSlot;
    use std::{cell::RefCell, io, path::PathBuf};
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetIfEntry2, MIB_IF_ROW2};

    type Member = RetainedMember<MemberFiles, NativeMemberIo<MemberFiles>>;
    pub(crate) type NativeMemberRead = OriginalMemberRead<MemberFiles, NativeMemberIo<MemberFiles>>;
    pub(crate) type NativeMemberRebindReceipt =
        ClosedOldProcessReceipt<MemberFiles, NativeMemberIo<MemberFiles>>;
    pub(crate) type NativeMemberRebindReads = (NativeMemberRead, Pending);
    type Reader = NativeMemberRead;
    type Closed = ClosedMemberReceipt<MemberFiles, NativeMemberIo<MemberFiles>>;
    pub(crate) type RetiredOriginal =
        RetiredMemberGeneration<MemberFiles, NativeMemberIo<MemberFiles>>;
    pub(crate) type Pending = PendingMemberRead<MemberFiles, NativeMemberIo<MemberFiles>>;
    pub(crate) type PartialCleanup = PartialMemberCleanup<MemberFiles, NativeMemberIo<MemberFiles>>;
    type Receipt<'a> = PrecreationReceipt<'a, keys::Held<win32::Handle>, KeyLock>;
    type RawOwner = MemberOwner<MemberFiles, NativeMemberIo<MemberFiles>>;

    struct NeverNativeRegistry(win32::Kernel);
    impl NeverRegistryRead for NeverNativeRegistry {
        type Handle = win32::Handle;
        fn interfaces(&mut self) -> Result<Self::Handle> {
            keys::RegistryKernel::interfaces(&mut self.0)
        }
        fn name(&mut self, key: &Self::Handle) -> Result<String> {
            keys::RegistryKernel::name(&mut self.0, key)
        }
        fn open(&mut self, parent: &Self::Handle, child: &str) -> Result<Option<Self::Handle>> {
            keys::RegistryKernel::open(&mut self.0, parent, child)
        }
    }

    pub(crate) struct NativeNeverMemberEffectInputs {
        pub context: Context,
        pub runtime: Rc<RuntimeRead>,
        pub source: Rc<MemberSource>,
        pub carrier: Rc<WintunSource>,
        pub supervisor: Rc<NativeDeadline>,
    }
    /// Original factory ledger + authenticated readonly roots. Not a member,
    /// Running/Stop receipt, key ownership or native-effect permission.
    pub(crate) struct NativeNeverMemberEffects {
        input: NativeNeverMemberEffectInputs,
        history: NeverMemberHistory,
        directory: RefCell<Option<super::super::member_files::PinnedDirectory>>,
        retired: RefCell<Vec<Rc<NativeMemberPreparationGeneration>>>,
        initial_forward: InitialNoCRegistration<NativeInitialAssemblyNoCRead>,
        initial_noc: InitialNoCRegistration<NativeInitialAssemblyNoCRead>,
    }
    /// Original Stop-bound READONLY preparation transition. No SDK admission,
    /// row/key retirement, pending inventory replacement or native grant.
    pub(crate) struct NativeMemberPreparationGeneration {
        receipt: Rc<Closed>,
        retired_original: Rc<RetiredOriginal>,
        stopped: MemberRecord,
        source: PreparedSourceRegistration<NativeSourceRead>,
        context: Context,
        original: PreparedSourceRegistration<NativeNeverMemberEffects>,
        slot: TunnelSlot,
        old: u64,
        next: u64,
        acknowledged: std::cell::Cell<bool>,
    }
    /// Actual prepared replacement -> SAME retained owner -> committed Start
    /// reader lineage. No constructor/Clone/serde or native/row/storage grant.
    pub(crate) struct NativeMemberStartedGeneration {
        origin: Rc<PreparedMemberOrigin>,
        ticket: Rc<NativeMemberPreparationGeneration>,
        registration: OriginalMemberRegistration<MemberFiles, NativeMemberIo<MemberFiles>>,
        acknowledged: std::cell::Cell<bool>,
    }
    /// Actual first-generation prepared -> transferred owner -> Running read.
    /// Separate from a retired-generation ticket, and never native permission.
    /// Source is weak: Source/inventory/member may retain this registration.
    pub(crate) struct NativeMemberStartedInitial {
        lineage: InitialStartedOrigin<PreparedMemberOrigin, NativeSourceRead>,
        registration: OriginalMemberRegistration<MemberFiles, NativeMemberIo<MemberFiles>>,
        acknowledged: std::cell::Cell<bool>,
    }
    impl NativeMemberStartedInitial {
        pub(crate) fn context(&self) -> &Context {
            &self.lineage.original.context
        }
        pub(crate) fn slot(&self) -> TunnelSlot {
            self.lineage.original.intent.slot
        }
        pub(crate) fn generation(&self) -> u64 {
            self.lineage.original.generation
        }
        pub(crate) fn proof(&self) -> Result<crate::member_owner::NativeProof> {
            self.verify_retained_original()?;
            Ok(self.registration.proof())
        }
        /// Pure original registration facts; no Runtime/storage/Pair/SDK read.
        pub(crate) fn verify_initial_original(
            &self,
            never: &Rc<NativeNeverMemberEffects>,
            runtime: &RuntimeRead,
            context: &Context,
        ) -> Result<()> {
            if !self.acknowledged.get() {
                return Err(Error::Pending);
            }
            self.verify_lineage(never, runtime, context)
        }
        fn verify_lineage(
            &self,
            never: &Rc<NativeNeverMemberEffects>,
            runtime: &RuntimeRead,
            context: &Context,
        ) -> Result<()> {
            let origin = &self.lineage.original;
            self.lineage.verify_retained_source()?;
            if origin.replacement.is_some()
                || origin.generation != 1
                || !Rc::ptr_eq(&origin.never_effects, never)
                || origin.context != *context
                || never.input.context != *context
                || !origin.runtime.same_original_runtime(runtime)
                || !never.input.runtime.same_original_runtime(runtime)
                || !Rc::ptr_eq(&origin.source, &never.input.source)
                || !Rc::ptr_eq(&origin.carrier, &never.input.carrier)
                || !Rc::ptr_eq(&origin.supervisor, &never.input.supervisor)
            {
                return Err(Error::Conflict);
            }
            never
                .history
                .verify_initial_started(slot_index(origin.intent.slot), origin.generation)?;
            self.registration.verify_current().map_err(owner_error)
        }
        fn verify_retained_original(&self) -> Result<()> {
            let origin = &self.lineage.original;
            self.verify_initial_original(&origin.never_effects, &origin.runtime, &origin.context)
        }
        pub(crate) fn verify_original_read(&self, reader: &NativeMemberRead) -> Result<()> {
            self.verify_retained_original()?;
            self.registration
                .verify_original_read(reader)
                .map_err(owner_error)
        }
        pub(crate) fn verify_pending_reader(&self, reader: &Pending) -> Result<()> {
            self.verify_retained_original()?;
            self.registration
                .verify_pending_read(reader)
                .map_err(owner_error)
        }
        pub(crate) fn verify_prepared(&self, prepared: &NativePreparedMember) -> Result<()> {
            self.verify_retained_original()?;
            if !Rc::ptr_eq(&self.lineage.original, &prepared.origin)
                || prepared.root.owner.is_some()
            {
                return Err(Error::Conflict);
            }
            Ok(())
        }
        pub(crate) fn verify_source(&self, source: &Rc<NativeSourceRead>) -> Result<()> {
            self.verify_retained_original()?;
            self.lineage.verify(&self.lineage.original, source)
        }
    }
    impl NativeMemberStartedGeneration {
        pub(crate) fn context(&self) -> &Context {
            &self.origin.context
        }
        pub(crate) fn slot(&self) -> TunnelSlot {
            self.origin.intent.slot
        }
        pub(crate) fn next_generation(&self) -> u64 {
            self.origin.generation
        }
        /// Actual captured proof DATA, not current native presence.
        pub(crate) fn proof(&self) -> Result<crate::member_owner::NativeProof> {
            if !self.acknowledged.get() {
                return Err(Error::Pending);
            }
            self.registration.verify_current().map_err(owner_error)?;
            Ok(self.registration.proof())
        }
        /// Pure pointer/ledger/current-reader-generation facts. NO Runtime
        /// verify/storage, Source, Pair, SDK or native queries in this API.
        pub(crate) fn verify_original(
            &self,
            ticket: &Rc<NativeMemberPreparationGeneration>,
            never: &Rc<NativeNeverMemberEffects>,
            runtime: &RuntimeRead,
            context: &Context,
        ) -> Result<()> {
            if !self.acknowledged.get() {
                return Err(Error::Pending);
            }
            self.verify_lineage(ticket, never, runtime, context)
        }
        fn verify_lineage(
            &self,
            ticket: &Rc<NativeMemberPreparationGeneration>,
            never: &Rc<NativeNeverMemberEffects>,
            runtime: &RuntimeRead,
            context: &Context,
        ) -> Result<()> {
            if !Rc::ptr_eq(&self.ticket, ticket)
                || !ticket.acknowledged.get()
                || self
                    .origin
                    .replacement
                    .as_ref()
                    .is_none_or(|t| !Rc::ptr_eq(t, ticket))
                || !Rc::ptr_eq(&self.origin.never_effects, never)
                || !ticket.original.verify(never)
                || self.origin.context != *context
                || ticket.context != *context
                || never.input.context != *context
                || !self.origin.runtime.same_original_runtime(runtime)
                || !never.input.runtime.same_original_runtime(runtime)
                || ticket.slot != self.origin.intent.slot
                || ticket.next != self.origin.generation
                || !never
                    .retired
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .iter()
                    .any(|t| Rc::ptr_eq(t, ticket))
            {
                return Err(Error::Conflict);
            }
            never.history.verify_started_generation(
                slot_index(ticket.slot),
                ticket.old,
                ticket.next,
            )?;
            self.registration.verify_current().map_err(owner_error)
        }
        pub(crate) fn verify_original_read(&self, reader: &NativeMemberRead) -> Result<()> {
            self.verify_original(
                &self.ticket,
                &self.origin.never_effects,
                &self.origin.runtime,
                &self.origin.context,
            )?;
            self.registration
                .verify_original_read(reader)
                .map_err(owner_error)
        }
        pub(crate) fn verify_pending_reader(&self, reader: &Pending) -> Result<()> {
            self.verify_original(
                &self.ticket,
                &self.origin.never_effects,
                &self.origin.runtime,
                &self.origin.context,
            )?;
            self.registration
                .verify_pending_read(reader)
                .map_err(owner_error)
        }
        pub(crate) fn verify_prepared(&self, prepared: &NativePreparedMember) -> Result<()> {
            if !Rc::ptr_eq(&self.origin, &prepared.origin) || prepared.root.owner.is_some() {
                return Err(Error::Conflict);
            }
            self.verify_original(
                &self.ticket,
                &self.origin.never_effects,
                &self.origin.runtime,
                &self.origin.context,
            )
        }
        pub(crate) fn verify_source(&self, source: &Rc<NativeSourceRead>) -> Result<()> {
            self.verify_original(
                &self.ticket,
                &self.origin.never_effects,
                &self.origin.runtime,
                &self.origin.context,
            )?;
            self.ticket.verify_source(source)
        }
    }
    impl NativeMemberPreparationGeneration {
        pub(crate) fn context(&self) -> &Context {
            &self.context
        }
        pub(crate) fn slot(&self) -> TunnelSlot {
            self.slot
        }
        pub(crate) fn old_generation(&self) -> u64 {
            self.old
        }
        pub(crate) fn next_generation(&self) -> u64 {
            self.next
        }
        pub(crate) fn closed_receipt(&self) -> &Rc<Closed> {
            &self.receipt
        }
        /// SAME original sealed Stop history for inventory retirement only.
        /// This is not current absence or permission to reuse private storage.
        pub(crate) fn retired_original(&self) -> &Rc<RetiredOriginal> {
            &self.retired_original
        }
        /// Pure original-reader comparison against THIS retained seal/Stop ACK.
        /// Safe inside an inventory callback: no Runtime/Pair/Source/journal or
        /// SDK query. Caller must independently bracket actual retirement with
        /// verify_original/current Pair/protected revision/full C+live SDK.
        pub(crate) fn verify_retired_original_read(&self, reader: &NativeMemberRead) -> Result<()> {
            if !self.acknowledged.get() {
                return Err(Error::Pending);
            }
            self.retired_original
                .verify_retired_original_read(reader, &self.receipt, &self.stopped)
                .map_err(owner_error)
        }
        /// SAME pending-owner comparison only; no inventory/Source reentry or
        /// renewed absence. Only the actual sealed Stop may supply history.
        pub(crate) fn verify_pending_reader(&self, reader: &Pending) -> Result<()> {
            if !self.acknowledged.get() {
                return Err(Error::Pending);
            }
            self.retired_original
                .verify_pending_reader(reader)
                .map_err(owner_error)?;
            let (intent, proof) = self
                .retired_original
                .read_history(&self.receipt)
                .map_err(owner_error)?;
            if intent != self.stopped.intent || proof != self.stopped.retired_proof {
                return Err(Error::Conflict);
            }
            Ok(())
        }
        /// Comparison data from the SAME acknowledged closure, not adoption.
        pub(crate) fn stopped_record(&self) -> &MemberRecord {
            &self.stopped
        }
        pub(crate) fn verify_source(&self, source: &Rc<NativeSourceRead>) -> Result<()> {
            if !self.acknowledged.get() || !self.source.verify(source) {
                return Err(Error::Conflict);
            }
            Ok(())
        }
        /// Original identity/fence facts ONLY, not native re-disable or
        /// replacement permission. Consumer must separately verify the SAME
        /// held key, current Pair/effect, SDK universe and native ownership ACK.
        pub(crate) fn verify_original(
            self: &Rc<Self>,
            original: &Rc<NativeNeverMemberEffects>,
            runtime: &RuntimeRead,
            context: &Context,
        ) -> Result<()> {
            if !self.acknowledged.get()
                || !self.original.verify(original)
                || self.context != *context
                || original.input.context != *context
                || !original.input.runtime.same_original_runtime(runtime)
                || !original
                    .retired
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .iter()
                    .any(|ticket| Rc::ptr_eq(ticket, self))
            {
                return Err(Error::Conflict);
            }
            runtime.verify(context)?;
            let (intent, proof) = self
                .retired_original
                .read_history(&self.receipt)
                .map_err(owner_error)?;
            if intent != self.stopped.intent || proof != self.stopped.retired_proof {
                return Err(Error::Conflict);
            }
            original.history.verify_retired_generation(
                slot_index(self.slot),
                self.old,
                self.next,
            )?;
            runtime.verify(context)
        }
    }
    impl NativeNeverMemberEffects {
        /// Register the actual initial DATA reader before Pair/DLL publication.
        /// This weak factual channel cannot select cleanup or grant SDK effects.
        pub(crate) fn retain_forward_initial_read(
            &self,
            original: &Rc<NativeInitialAssemblyNoCRead>,
        ) -> Result<()> {
            self.initial_forward.retain(original, |reader| {
                self.history.cold()?;
                let inspect = || {
                    self.inspect_no_effect_records(|bytes| {
                        reader.verify_forward_current(
                            &self.input.runtime,
                            &self.input.context,
                            bytes,
                        )
                    })
                };
                let records = inspect()?;
                if records[4].is_none() {
                    return Err(Error::Pending);
                }
                if inspect()? != records {
                    return Err(Error::Conflict);
                }
                self.history.cold()
            })
        }
        /// SAME original initialized Assembly only; weak to avoid a ledger /
        /// Startup / Assembly retention cycle. Failed or duplicate registration
        /// is never replaceable. This is SDK-free and grants no native effects.
        pub(crate) fn retain_initial_noc_read(
            &self,
            original: &Rc<NativeInitialAssemblyNoCRead>,
        ) -> Result<()> {
            self.initial_noc.retain(original, |reader| {
                self.history.cold()?;
                self.input
                    .supervisor
                    .verify_cleanup_runtime_entry(&self.input.runtime, &self.input.context)?;
                reader.verify_ready(&self.input.runtime, &self.input.context)?;
                let records = self.inspect_no_effect_records(|bytes| {
                    reader.verify_current(&self.input.runtime, &self.input.context, bytes)
                })?;
                if records[4].is_none() {
                    return Err(Error::Pending);
                }
                if self.inspect_no_effect_records(|bytes| {
                    reader.verify_current(&self.input.runtime, &self.input.context, bytes)
                })? != records
                {
                    return Err(Error::Conflict);
                }
                reader.verify_ready(&self.input.runtime, &self.input.context)?;
                self.input
                    .supervisor
                    .verify_cleanup_runtime_entry(&self.input.runtime, &self.input.context)?;
                self.history.cold()
            })
        }
        /// Pure original-supplier inside Startup's actual retained C terminal
        /// SDK/rows/Calling/Pair/KeyLock bracket. Not an SDK absence, Stopped
        /// projection, destructor permission or native effect grant. No file,
        /// Source, Pair, inventory or NativeAuthority reentry from the callback.
        pub(crate) fn verify_prepublication_full_empty_originals(
            self: &Rc<Self>,
            prepared: &[Option<NativePreparedMember>; 2],
            runtime: &RuntimeRead,
            context: &Context,
            expected: &PairRecord,
        ) -> Result<()> {
            self.verify_prepublication_originals(
                prepared,
                runtime,
                context,
                expected,
                PrepublicationOriginalRead::FullEmpty,
            )
        }
        /// SAME private prepared origins for readonly Closing9/10. Never a
        /// substitute Never ledger after attempted C creation or a key ACK.
        pub(crate) fn verify_pregraph_native_empty_originals(
            self: &Rc<Self>,
            prepared: &[Option<NativePreparedMember>; 2],
            runtime: &RuntimeRead,
            context: &Context,
            expected: &PairRecord,
        ) -> Result<()> {
            self.verify_prepublication_originals(
                prepared,
                runtime,
                context,
                expected,
                PrepublicationOriginalRead::NativeEmpty,
            )
        }
        /// SAME private prepared origins inside the actual C-only Closing SDK
        /// bracket. No started member/key ACK or terminal disposition is made.
        pub(crate) fn verify_pregraph_closing_originals(
            self: &Rc<Self>,
            prepared: &[Option<NativePreparedMember>; 2],
            runtime: &RuntimeRead,
            context: &Context,
            expected: &PairRecord,
        ) -> Result<()> {
            self.verify_prepublication_originals(
                prepared,
                runtime,
                context,
                expected,
                PrepublicationOriginalRead::EarlyClosing,
            )
        }
        pub(crate) fn verify_pregraph_key_restore_originals(
            self: &Rc<Self>,
            prepared: &[Option<NativePreparedMember>; 2],
            runtime: &RuntimeRead,
            context: &Context,
            expected: &PairRecord,
        ) -> Result<()> {
            self.verify_prepublication_originals(
                prepared,
                runtime,
                context,
                expected,
                PrepublicationOriginalRead::RestoringKeys,
            )
        }
        fn verify_prepublication_originals(
            self: &Rc<Self>,
            prepared: &[Option<NativePreparedMember>; 2],
            runtime: &RuntimeRead,
            context: &Context,
            expected: &PairRecord,
            channel: PrepublicationOriginalRead,
        ) -> Result<()> {
            if context != &self.input.context
                || !self.input.runtime.same_original_runtime(runtime)
                || !self
                    .retired
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .is_empty()
            {
                return Err(Error::Conflict);
            }
            let mut rooted = [None, None];
            for (index, prepared) in prepared.iter().enumerate() {
                let slot = if index == 0 {
                    TunnelSlot::A
                } else {
                    TunnelSlot::B
                };
                let original = prepared.as_ref().map(|p| &p.origin.intent);
                match channel {
                    PrepublicationOriginalRead::EarlyClosing => {
                        crate::windows::member_carrier_ready::compare_pregraph_closing_frame(
                            context,
                            expected,
                            expected.carrier.ok_or(Error::Conflict)?,
                        )?;
                        validate_prepublication_unstarted_origin(
                            context, expected, slot, original,
                        )?;
                    }
                    PrepublicationOriginalRead::NativeEmpty => {
                        validate_pregraph_native_empty_unstarted(
                            context, expected, slot, original,
                        )?;
                    }
                    PrepublicationOriginalRead::RestoringKeys => {
                        crate::windows::member_carrier_ready::compare_pregraph_key_restore_frame(
                            context,
                            expected,
                            expected.carrier.ok_or(Error::Conflict)?,
                        )?;
                        validate_prepublication_unstarted_origin(
                            context, expected, slot, original,
                        )?;
                    }
                    PrepublicationOriginalRead::FullEmpty => {
                        validate_closing12_unstarted(context, expected, slot, original)?;
                    }
                }
                if let Some(prepared) = prepared {
                    self.terminal_prepared_origin(&prepared.origin, index, runtime, context)?;
                    if prepared.live_source.is_some()
                        || prepared.live_preparation.is_some()
                        || prepared.origin.replacement.is_some()
                        || prepared.origin.generation != 1
                    {
                        return Err(Error::Pending);
                    }
                    let state = prepared.root.owner.as_ref().ok_or(Error::Pending)?;
                    match (&state.raw, &state.retained, &state.pending) {
                        // The private sole prepared constructor owns this raw
                        // value; Start must transfer it into a controller first.
                        // Equal intent is comparison only, never imported authority.
                        (Some(raw), None, None) if raw.intent() == &prepared.origin.intent => (),
                        (None, Some(member), Some(pending)) => {
                            if member
                                .verify_terminal_unstarted_registration(pending)
                                .map_err(owner_error)?
                                != prepared.origin.intent
                            {
                                return Err(Error::Conflict);
                            }
                        }
                        _ => return Err(Error::Pending),
                    }
                    rooted[index] = Some(prepared.origin.generation);
                }
            }
            verify_prepublication_prepared_coverage(
                &self.history,
                rooted,
                std::array::from_fn(|i| expected.members[i].is_some()),
            )
        }

        /// Pure destructor-disposition verification INSIDE the caller's exact
        /// original Stopped/Calling/full-empty terminal bracket. Does not
        /// borrow NativeAuthority, inspect files/Source/Pair/SDK, issue a pin,
        /// renew an epoch or grant native effects/current absence. All old
        /// identities stay historical; the caller independently reads current
        /// full SDK emptiness and authenticates the opaque Stopped publication.
        // Keep each independent original-root/fence input explicit for the
        // stable terminal consumers; bundling them must not imply authority.
        #[allow(clippy::too_many_arguments)]
        pub(crate) fn verify_terminal_original_roots<G: NativeMemberLifecycle>(
            self: &Rc<Self>,
            prepared: &[Option<NativePreparedMember>; 2],
            controllers: [Option<&NativeMemberController<G>>; 2],
            retired: &[NativeRetiredMemberRoots<G>],
            runtime: &RuntimeRead,
            context: &Context,
            stopped: &PairRecord,
            history: &[ClosedMemberBinding],
        ) -> Result<()> {
            validate_never_member_terminal_frame(context, stopped)?;
            if self.input.context != *context || !self.input.runtime.same_original_runtime(runtime)
            {
                return Err(Error::Conflict);
            }
            let tickets = self.retired.try_borrow().map_err(|_| Error::Conflict)?;
            if tickets.len() != retired.len() {
                return Err(Error::Pending);
            }
            let mut generations = Vec::new();
            generations
                .try_reserve(retired.len())
                .map_err(|_| Error::Pending)?;
            for (position, old) in retired.iter().enumerate() {
                let ticket = &old._ticket;
                if !tickets.iter().any(|t| Rc::ptr_eq(t, ticket))
                    || retired[..position]
                        .iter()
                        .any(|r| Rc::ptr_eq(&r._ticket, ticket))
                    || !ticket.acknowledged.get()
                    || !ticket.original.verify(self)
                    || ticket.context != *context
                {
                    return Err(Error::Conflict);
                }
                let index = slot_index(ticket.slot);
                let closed = self.terminal_controller_registration(
                    &old._controller,
                    Some(&old._prepared),
                    index,
                    runtime,
                    context,
                )?;
                let owned = old._controller.root.owner.as_ref().ok_or(Error::Retired)?;
                if !matches!(closed, TerminalMemberRoot::Closed(g) if g == ticket.old)
                    || old
                        ._controller
                        .root
                        .closed
                        .as_ref()
                        .is_none_or(|c| !Rc::ptr_eq(c, &ticket.receipt))
                    || old._controller.root.stopped.as_ref() != Some(&ticket.stopped)
                {
                    return Err(Error::Conflict);
                }
                ticket.verify_source(&owned.original_source)?;
                ticket.verify_pending_reader(&owned.pending)?;
                if let Some(reader) = &old._controller.root.reader {
                    ticket.verify_retired_original_read(reader)?;
                }
                // The seal is original immutable history, even after another
                // generation rewrote the journal. Never reread its old NIC.
                let (intent, proof) = ticket
                    .retired_original
                    .read_history(&ticket.receipt)
                    .map_err(owner_error)?;
                if intent != ticket.stopped.intent || proof != ticket.stopped.retired_proof {
                    return Err(Error::Conflict);
                }
                generations.push((index, ticket.old, ticket.next));
            }
            let mut current = [None, None];
            let mut current_history = Vec::new();
            current_history.try_reserve(2).map_err(|_| Error::Pending)?;
            for index in 0..2 {
                let preparation = prepared[index].as_ref();
                if let Some(controller) = controllers[index] {
                    current[index] = Some(self.terminal_controller_registration(
                        controller,
                        preparation,
                        index,
                        runtime,
                        context,
                    )?);
                    if let Some(record) = &controller.root.stopped {
                        if let Some(proof) = record.retired_proof {
                            current_history.push(ClosedMemberBinding {
                                intent: record.intent.clone(),
                                proof,
                            });
                        }
                    }
                } else if let Some(preparation) = preparation {
                    self.terminal_prepared_origin(&preparation.origin, index, runtime, context)?;
                    let owner = preparation.root.owner.as_ref().ok_or(Error::Pending)?;
                    match (&owner.raw, &owner.retained, &owner.pending) {
                        (Some(raw), None, None) if raw.intent() == &preparation.origin.intent => (),
                        (None, Some(member), Some(pending)) => {
                            if member
                                .verify_terminal_unstarted_registration(pending)
                                .map_err(owner_error)?
                                != preparation.origin.intent
                            {
                                return Err(Error::Conflict);
                            }
                        }
                        _ => return Err(Error::Pending),
                    }
                    current[index] =
                        Some(TerminalMemberRoot::Prepared(preparation.origin.generation));
                }
            }
            verify_terminal_generation_coverage(&self.history, current, &generations)?;
            // Inventory supplies CURRENT closed histories only. Retired and
            // rebind-old identities above remain separate immutable originals.
            if history.len() != current_history.len()
                || history.iter().any(|h| {
                    current_history
                        .iter()
                        .filter(|original| *original == h)
                        .count()
                        != 1
                })
                || current_history
                    .iter()
                    .any(|h| history.iter().filter(|actual| *actual == h).count() != 1)
            {
                return Err(Error::Conflict);
            }
            Ok(())
        }

        fn terminal_prepared_origin(
            self: &Rc<Self>,
            origin: &PreparedMemberOrigin,
            index: usize,
            runtime: &RuntimeRead,
            context: &Context,
        ) -> Result<()> {
            if slot_index(origin.intent.slot) != index
                || origin.generation == 0
                || origin.intent.scope != context.intent.scope
                || origin.context != *context
                || !origin.runtime.same_original_runtime(runtime)
                || !Rc::ptr_eq(&origin.never_effects, self)
                || !Rc::ptr_eq(&origin.source, &self.input.source)
                || !Rc::ptr_eq(&origin.carrier, &self.input.carrier)
                || !Rc::ptr_eq(&origin.supervisor, &self.input.supervisor)
            {
                return Err(Error::Conflict);
            }
            if let Some(ticket) = &origin.replacement {
                if !ticket.acknowledged.get()
                    || !ticket.original.verify(self)
                    || ticket.context != *context
                    || ticket.slot != origin.intent.slot
                    || ticket.next != origin.generation
                    || !self
                        .retired
                        .try_borrow()
                        .map_err(|_| Error::Conflict)?
                        .iter()
                        .any(|t| Rc::ptr_eq(t, ticket))
                {
                    return Err(Error::Conflict);
                }
            } else if origin.generation != 1 {
                return Err(Error::Conflict);
            }
            Ok(())
        }

        fn terminal_controller_registration<G: NativeMemberLifecycle>(
            self: &Rc<Self>,
            controller: &NativeMemberController<G>,
            prepared: Option<&NativePreparedMember>,
            index: usize,
            runtime: &RuntimeRead,
            context: &Context,
        ) -> Result<TerminalMemberRoot> {
            controller.root.verify_terminal_inert()?;
            let owned = controller.root.owner.as_ref().ok_or(Error::Retired)?;
            if owned.context != *context
                || owned.intent.scope != context.intent.scope
                || slot_index(owned.intent.slot) != index
                || owned.generation == 0
                || !owned.runtime.same_original_runtime(runtime)
                || !Rc::ptr_eq(&owned.never_effects, self)
                || !Rc::ptr_eq(&owned.source, &self.input.source)
                || !Rc::ptr_eq(&owned.carrier, &self.input.carrier)
                || !Rc::ptr_eq(&owned.supervisor, &self.input.supervisor)
            {
                return Err(Error::Conflict);
            }
            let origin = &owned.prepared_origin;
            let preparation = prepared.ok_or(Error::Conflict)?;
            self.terminal_prepared_origin(origin, index, runtime, context)?;
            if !Rc::ptr_eq(origin, &preparation.origin)
                || preparation.root.owner.is_some()
                || origin.intent != owned.intent
                || origin.generation != owned.generation
            {
                return Err(Error::Conflict);
            }
            if !controller.root.attempted {
                if !controller.rebinds.is_empty()
                    || owned.partial_cleanup.is_some()
                    || owned
                        .member
                        .verify_terminal_unstarted_registration(&owned.pending)
                        .map_err(owner_error)?
                        != owned.intent
                {
                    return Err(Error::Conflict);
                }
                return Ok(TerminalMemberRoot::Unstarted(owned.generation));
            }
            let receipt = controller.root.closed.as_ref().ok_or(Error::Pending)?;
            let record = owned
                .member
                .verify_terminal_closed_registration(&owned.pending, receipt)
                .map_err(owner_error)?;
            if controller.root.stopped.as_ref() != Some(&record)
                || record.intent != owned.intent
                || record
                    .retired_proof
                    .is_some_and(|p| p.interface.guid != context.bindings[index + 1].guid)
            {
                return Err(Error::Conflict);
            }
            for (position, rebound) in controller.rebinds.iter().enumerate() {
                rebound
                    .receipt
                    .verify_retired_original_read(&rebound._prior_reader)
                    .map_err(owner_error)?;
                if rebound.prior.intent != owned.intent
                    || rebound.prior.proof != rebound.receipt.running_record().retired_proof
                {
                    return Err(Error::Conflict);
                }
                if let Some(next) = controller.rebinds.get(position + 1) {
                    rebound
                        .receipt
                        .verify_replacement_original_read(&next._prior_reader)
                        .map_err(owner_error)?;
                    if rebound.receipt.running_record() != &next.prior {
                        return Err(Error::Conflict);
                    }
                } else {
                    rebound
                        .receipt
                        .verify_replacement_pending_read(&owned.pending)
                        .map_err(owner_error)?;
                    if controller.root.running.as_ref() != Some(rebound.receipt.running_record()) {
                        return Err(Error::Conflict);
                    }
                }
            }
            Ok(TerminalMemberRoot::Closed(owned.generation))
        }

        /// Root before fallible validation and BEFORE any preparation/assembly
        /// attempt. A failed construction retains the SAME original roots.
        ///
        /// # Safety
        /// The sole serialized factory retains this exact slot; all member
        /// constructors use its mandatory input capability, and it calls
        /// begin_carrier_construction BEFORE ANY assembly/module/key/C attempt.
        /// No second ledger/replacement/recovery import may seed this history.
        pub(crate) unsafe fn root(
            slot: &mut Option<Rc<Self>>,
            input: NativeNeverMemberEffectInputs,
            lock: &KeyLock,
        ) -> Result<()> {
            if slot.is_some() {
                return Err(Error::Retired);
            }
            *slot = Some(Rc::new(Self {
                input,
                history: NeverMemberHistory::default(),
                directory: RefCell::new(None),
                retired: RefCell::new(Vec::new()),
                initial_forward: InitialNoCRegistration::new(),
                initial_noc: InitialNoCRegistration::new(),
            }));
            let original = slot.as_ref().expect("retained never-effect root");
            original.verify_roots(lock)?;
            let path = super::super::install::state_directory().map_err(|_| Error::Pending)?;
            *original.directory.borrow_mut() = Some(
                super::super::member_files::pin_private_directory(&path)
                    .map_err(|_| Error::Pending)?,
            );
            original.verify_roots(lock)
        }
        /// History only; grants nothing and never clears even after Err/unwind.
        pub(crate) fn begin_carrier_construction(&self) {
            self.history.carrier_attempted.set(true);
        }
        /// Separate exact no-C Closing9/NativeEmpty or Closing10/Guard entry.
        /// Factual only: no idle ReadPin, SDK observation or native permission.
        /// A partial-C attempt requires actual retired roots in the caller's
        /// other path; absence of a receipt cannot select this cold ledger.
        pub(crate) fn verify_bootstrap_native_empty_entry(
            &self,
            owner: &NativeDeadline,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            context: &Context,
        ) -> Result<()> {
            (|| {
                self.history.cold()?;
                validate_never_bootstrap_native_frame(context, expected)?;
                self.verify_uncaptured_cleanup_entry_inner(owner, pair, expected, context)?;
                validate_never_bootstrap_native_frame(context, expected)?;
                self.history.cold()
            })()
            .map_err(pending_unknown)
        }
        /// Factual BEFORE watchdog entry only. Exact original Closing ACK,
        /// runtime/deadline/private no-effect records; NO Calling/SDK/effects.
        pub(crate) fn verify_uncaptured_cleanup_entry(
            &self,
            owner: &NativeDeadline,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            context: &Context,
        ) -> Result<()> {
            self.verify_uncaptured_cleanup_entry_inner(owner, pair, expected, context)
                .map_err(pending_unknown)
        }
        fn verify_uncaptured_cleanup_entry_inner(
            &self,
            owner: &NativeDeadline,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            context: &Context,
        ) -> Result<()> {
            if !std::ptr::eq(owner, Rc::as_ptr(&self.input.supervisor))
                || context != &self.input.context
                || !pair.matches_runtime(&self.input.runtime)
            {
                return Err(Error::Conflict);
            }
            self.history.cold()?;
            if expected.carrier.is_some()
                || expected.network.is_some()
                || expected.members.iter().flatten().any(|m| {
                    m.owner.phase != MemberPhase::Prepared
                        || m.owner.proof.is_some()
                        || m.owner.retired_proof.is_some()
                })
            {
                return Err(Error::Pending);
            }
            owner
                .verify_cleanup_runtime_entry(&self.input.runtime, context)
                .inspect_err(|error| {
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_native(
                        "no-C entry Runtime",
                        error,
                    );
                    #[cfg(not(test))]
                    let _ = error;
                })?;
            pair.verify_cleanup_entry_for(&self.input.runtime, context, expected)
                .map_err(|_| Error::Conflict)?;
            let before = self.no_effect_records().inspect_err(|error| {
                #[cfg(test)]
                super::super::member_carrier_factory_test_os::trace_native(
                    "no-C entry ledger",
                    error,
                );
                #[cfg(not(test))]
                let _ = error;
            })?;
            self.history.cold()?;
            pair.verify_cleanup_entry_for(&self.input.runtime, context, expected)
                .map_err(|_| Error::Conflict)?;
            if self.no_effect_records().inspect_err(|error| {
                #[cfg(test)]
                super::super::member_carrier_factory_test_os::trace_native(
                    "no-C entry ledger postflight",
                    error,
                );
                #[cfg(not(test))]
                let _ = error;
            })? != before
            {
                return Err(Error::Conflict);
            }
            owner
                .verify_cleanup_runtime_entry(&self.input.runtime, context)
                .inspect_err(|error| {
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_native(
                        "no-C entry Runtime",
                        error,
                    );
                    #[cfg(not(test))]
                    let _ = error;
                })?;
            self.history.cold()
        }
        /// Separate no-C terminal pre-entry. SAME original ledger/deadline and
        /// Stopped publication ACK, no native records, no Calling pin or SDK.
        /// This cannot authorize effects or relax the Closing entry decoder.
        pub(crate) fn verify_uncaptured_terminal_entry(
            &self,
            owner: &NativeDeadline,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            context: &Context,
        ) -> Result<()> {
            self.verify_uncaptured_terminal_entry_inner(owner, pair, expected, context)
                .map_err(pending_unknown)
        }
        fn verify_uncaptured_terminal_entry_inner(
            &self,
            owner: &NativeDeadline,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            context: &Context,
        ) -> Result<()> {
            if !std::ptr::eq(owner, Rc::as_ptr(&self.input.supervisor))
                || context != &self.input.context
                || !pair.matches_runtime(&self.input.runtime)
            {
                return Err(Error::Conflict);
            }
            self.history.cold()?;
            validate_never_member_terminal_frame(context, expected)?;
            owner.verify_cleanup_runtime_entry(&self.input.runtime, context)?;
            pair.verify_terminal_entry(&self.input.runtime, context, expected)
                .map_err(|_| Error::Conflict)?;
            let before = self.no_effect_records()?;
            self.history.cold()?;
            pair.verify_terminal_entry(&self.input.runtime, context, expected)
                .map_err(|_| Error::Conflict)?;
            if self.no_effect_records()? != before {
                return Err(Error::Conflict);
            }
            owner.verify_cleanup_runtime_entry(&self.input.runtime, context)?;
            self.history.cold()
        }
        fn pre_pair_inventory(
            &self,
            initial: &Rc<NativeInitialAssemblyNoCRead>,
        ) -> Result<Vec<Option<Vec<u8>>>> {
            self.history.cold()?;
            if !Rc::ptr_eq(&self.initial_noc.read()?, initial) {
                return Err(Error::Conflict);
            }
            initial.verify_ready(&self.input.runtime, &self.input.context)?;
            let records = self.no_effect_records()?;
            let session = super::super::member_session::decode_session_payload(
                &self.input.context.intent.scope,
                records[0].as_deref().ok_or(Error::Pending)?,
            )
            .map_err(|_| Error::Conflict)?;
            require_pre_pair_session(&self.input.context, &session, records[1].is_some())?;
            if records[4].is_none() || records[9].is_none() {
                return Err(Error::Pending);
            }
            self.history.cold()?;
            Ok(records)
        }
        /// SAME no-effect ledger and acknowledged original initial journal.
        /// Real absent Pair is independently read, never a synthetic Stopped
        /// Pair or a replacement pin. Entry grants no Calling or SDK effect.
        pub(crate) fn verify_pre_pair_entry(
            &self,
            owner: &NativeDeadline,
            initial: &Rc<NativeInitialAssemblyNoCRead>,
            context: &Context,
        ) -> Result<()> {
            if !std::ptr::eq(owner, Rc::as_ptr(&self.input.supervisor))
                || context != &self.input.context
            {
                return Err(Error::Conflict);
            }
            owner.verify_cleanup_runtime_entry(&self.input.runtime, context)?;
            let before = self.pre_pair_inventory(initial)?;
            if self.pre_pair_inventory(initial)? != before {
                return Err(Error::Conflict);
            }
            owner.verify_cleanup_runtime_entry(&self.input.runtime, context)
        }
        /// Full native absence inside the original pre-Pair Calling. Sources,
        /// held KeyLock and the initial journal are actual retained originals.
        /// Independent scoped BFE reads are performed by the Startup caller.
        pub(crate) fn verify_pre_pair_absent(
            &self,
            initial: &Rc<NativeInitialAssemblyNoCRead>,
            lock: &KeyLock,
        ) -> Result<()> {
            self.verify_roots(lock)?;
            let before = self.pre_pair_inventory(initial)?;
            for _ in 0..2 {
                for slot in [TunnelSlot::A, TunnelSlot::B] {
                    self.file_absence(slot)?;
                    self.services_absent(slot)?;
                }
                for index in 0..3 {
                    self.key_fact(index)?;
                }
                provider::native::inspect_mixed(&complete_provider_inputs(
                    &self.input.context,
                    &[],
                    &[],
                )?)
                .map_err(|_| Error::Pending)?;
                self.verify_roots(lock)?;
                if self.pre_pair_inventory(initial)? != before {
                    return Err(Error::Conflict);
                }
            }
            self.verify_roots(lock)
        }
        fn matches(
            &self,
            context: &Context,
            runtime: &RuntimeRead,
            source: &Rc<MemberSource>,
            carrier: &Rc<WintunSource>,
            supervisor: &Rc<NativeDeadline>,
        ) -> bool {
            self.input.context == *context
                && self.input.runtime.same_original_runtime(runtime)
                && Rc::ptr_eq(&self.input.source, source)
                && Rc::ptr_eq(&self.input.carrier, carrier)
                && Rc::ptr_eq(&self.input.supervisor, supervisor)
        }
        fn preparation_ticket(
            self: &Rc<Self>,
            slot: TunnelSlot,
            generation: u64,
            runtime: &RuntimeRead,
            context: &Context,
        ) -> Result<Option<Rc<NativeMemberPreparationGeneration>>> {
            if generation == 1 {
                return Ok(None);
            }
            let ticket = self
                .retired
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .iter()
                .find(|t| t.slot == slot && t.next == generation)
                .cloned()
                .ok_or(Error::Pending)?;
            ticket.verify_original(self, runtime, context)?;
            Ok(Some(ticket))
        }
        fn verify_roots(&self, lock: &KeyLock) -> Result<()> {
            keys_record::validate_context(&self.input.context)?;
            if !self.input.runtime.matches_lock(lock)
                || !self.input.source.matches_carrier(&self.input.carrier)
            {
                return Err(Error::Conflict);
            }
            self.input
                .runtime
                .verify_member_source(&self.input.context, &self.input.source)?;
            self.input
                .supervisor
                .read_pin()
                .map_err(|_| Error::Pending)?
                .verify_runtime(
                    &self.input.supervisor,
                    &self.input.runtime,
                    &self.input.context,
                )
                .map_err(|_| Error::Conflict)
        }
        fn pair(
            &self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &KeyLock,
        ) -> Result<()> {
            self.verify_roots(lock)?;
            pair.inspect(&self.input.runtime, &self.input.supervisor, |current| {
                if current != expected {
                    return Err(io_error(Error::Conflict));
                }
                Ok(())
            })
            .map_err(|_| Error::Conflict)?;
            self.verify_roots(lock)
        }
        fn file_absence(&self, slot: TunnelSlot) -> Result<()> {
            use std::{
                fs::File,
                os::windows::{ffi::OsStrExt, io::FromRawHandle},
            };
            use windows_sys::Win32::{
                Foundation::{
                    GetLastError, ERROR_FILE_NOT_FOUND, GENERIC_READ, INVALID_HANDLE_VALUE,
                },
                Storage::FileSystem::{
                    CreateFileW, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, OPEN_EXISTING,
                    READ_CONTROL,
                },
            };
            let root = super::super::install::state_directory().map_err(|_| Error::Pending)?;
            let pinned = self.directory.try_borrow().map_err(|_| Error::Conflict)?;
            let pinned = pinned.as_ref().ok_or(Error::Pending)?;
            for name in [
                crate::redundancy::slot_config_filename(slot),
                match slot {
                    TunnelSlot::A => "nelomai-a.owner.json",
                    TunnelSlot::B => "nelomai-b.owner.json",
                },
            ] {
                let path: Vec<u16> = root
                    .join(name)
                    .as_os_str()
                    .encode_wide()
                    .chain(Some(0))
                    .collect();
                verify_absent_file_reads(
                    || pinned.verify().map_err(|_| Error::Pending),
                    || {
                        let handle = unsafe {
                            CreateFileW(
                                path.as_ptr(),
                                GENERIC_READ | READ_CONTROL,
                                FILE_SHARE_READ,
                                std::ptr::null(),
                                OPEN_EXISTING,
                                FILE_FLAG_OPEN_REPARSE_POINT,
                                std::ptr::null_mut(),
                            )
                        };
                        if handle == INVALID_HANDLE_VALUE {
                            return if unsafe { GetLastError() } == ERROR_FILE_NOT_FOUND {
                                Ok(false)
                            } else {
                                Err(Error::Pending)
                            };
                        }
                        // Sole owner of an actual OPEN_EXISTING handle. Presence
                        // always denies; no bytes/path/ACL can be adopted.
                        drop(unsafe { File::from_raw_handle(handle) });
                        Ok(true)
                    },
                    || Error::Conflict,
                )?;
            }
            Ok(())
        }
        fn services_absent(&self, slot: TunnelSlot) -> Result<()> {
            for transport in [
                nelomai_client_tunnel::TunnelTransport::WireGuard,
                nelomai_client_tunnel::TunnelTransport::AmneziaWg3,
            ] {
                if super::super::install::open_slot_service(
                    slot,
                    transport,
                    windows_service::service::ServiceAccess::QUERY_STATUS,
                )
                .map_err(|_| Error::Pending)?
                .is_some()
                {
                    return Err(Error::Pending);
                }
            }
            Ok(())
        }
        fn key_fact(&self, index: usize) -> Result<()> {
            inspect_never_member_key(
                &mut NeverNativeRegistry(win32::Kernel),
                &self.input.context,
                index,
            )
        }
        fn forward_no_effect_records(&self) -> Result<Vec<Option<Vec<u8>>>> {
            let original = self.initial_forward.read().inspect_err(|error| {
                #[cfg(test)]
                super::super::member_carrier_factory_test_os::trace_native(
                    "cold forward initial registration",
                    error,
                );
                #[cfg(not(test))]
                let _ = error;
            })?;
            let records = self
                .inspect_no_effect_records(|bytes| {
                    original
                        .verify_forward_current(&self.input.runtime, &self.input.context, bytes)
                        .inspect_err(|error| {
                            #[cfg(test)]
                            super::super::member_carrier_factory_test_os::trace_native(
                                "cold forward original initial ACK",
                                error,
                            );
                            #[cfg(not(test))]
                            let _ = error;
                        })
                })
                .inspect_err(|error| {
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_native(
                        "cold forward initial inventory",
                        error,
                    );
                    #[cfg(not(test))]
                    let _ = error;
                })?;
            if records[4].is_none() {
                return Err(Error::Pending);
            }
            #[cfg(test)]
            super::super::member_carrier_factory_test_os::trace_step(
                "cold forward original initial inventory accepted",
            );
            Ok(records)
        }
        fn no_effect_records(&self) -> Result<Vec<Option<Vec<u8>>>> {
            // Once registered, loss of the original reader or its acknowledged
            // initial record cannot fall back to the never-initialized lane.
            let original = if self.initial_noc.attempted.get() {
                Some(self.initial_noc.read()?)
            } else {
                None
            };
            let records = self.inspect_no_effect_records(|bytes| {
                original.as_ref().ok_or(Error::Pending)?.verify_current(
                    &self.input.runtime,
                    &self.input.context,
                    bytes,
                )
            })?;
            if original.is_some() && records[4].is_none() {
                return Err(Error::Pending);
            }
            Ok(records)
        }
        fn inspect_no_effect_records(
            &self,
            verify_initial: impl FnOnce(&[u8]) -> Result<()>,
        ) -> Result<Vec<Option<Vec<u8>>>> {
            // EVERY protected kind is read, including Session/Pair. Their
            // existing original publication is not a native effect receipt.
            let records = self.input.runtime.optional_records(
                &self.input.context,
                &[
                    RecordKind::Session,
                    RecordKind::Pair,
                    RecordKind::Network,
                    RecordKind::Carrier,
                    RecordKind::NativeCarrierReceipts,
                    RecordKind::CarrierGuard,
                    RecordKind::CarrierRows,
                    RecordKind::MemberARows,
                    RecordKind::MemberBRows,
                    RecordKind::NativeCreator,
                ],
            )?;
            require_never_inventory(
                &self.input.context,
                &std::array::from_fn(|i| records[i + 2].clone()),
                records[9].as_deref(),
                verify_initial,
            )?;
            Ok(records)
        }
        fn cold_absence(
            &self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            slot: TunnelSlot,
            lock: &KeyLock,
        ) -> Result<()> {
            self.history.cold()?;
            validate_never_member_frame(&self.input.context, expected, slot)?;
            if expected.carrier.is_some()
                || expected.network.is_some()
                || expected.members.iter().flatten().any(|m| {
                    m.owner.phase != MemberPhase::Prepared
                        || m.owner.proof.is_some()
                        || m.owner.retired_proof.is_some()
                })
            {
                return Err(Error::Pending);
            }
            self.cold_full_absence(pair, expected, lock)
        }
        // Shared native READONLY observations only. Each public caller first
        // validates its disjoint frame, and this body authenticates actual
        // Calling + SAME Pair/runtime/source/lock before and after observations.
        fn cold_full_absence(
            &self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &KeyLock,
        ) -> Result<()> {
            #[cfg(test)]
            super::super::member_carrier_factory_test_os::trace_step("full absence entry");
            self.history.cold()?;
            self.pair(pair, expected, lock).inspect_err(|error| {
                #[cfg(test)]
                super::super::member_carrier_factory_test_os::trace_native(
                    "same Pair and native roots",
                    error,
                );
                #[cfg(not(test))]
                let _ = error;
            })?;
            #[cfg(test)]
            super::super::member_carrier_factory_test_os::trace_step("full absence Pair completed");
            let before = self.no_effect_records()?;
            #[cfg(test)]
            super::super::member_carrier_factory_test_os::trace_step(
                "full absence ledger completed",
            );
            for _ in 0..2 {
                for slot in [TunnelSlot::A, TunnelSlot::B] {
                    self.file_absence(slot).inspect_err(|error| {
                        #[cfg(test)]
                        super::super::member_carrier_factory_test_os::trace_native(
                            "private member file absence",
                            error,
                        );
                        #[cfg(not(test))]
                        let _ = error;
                    })?;
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step(
                        "private file absence completed",
                    );
                    self.services_absent(slot).inspect_err(|error| {
                        #[cfg(test)]
                        super::super::member_carrier_factory_test_os::trace_native(
                            "SCM member absence",
                            error,
                        );
                        #[cfg(not(test))]
                        let _ = error;
                    })?;
                }
                #[cfg(test)]
                super::super::member_carrier_factory_test_os::trace_step("SCM absence completed");
                for index in 0..3 {
                    self.key_fact(index).inspect_err(|error| {
                        #[cfg(test)]
                        super::super::member_carrier_factory_test_os::trace_native(
                            "native key absence",
                            error,
                        );
                        #[cfg(not(test))]
                        let _ = error;
                    })?;
                }
                #[cfg(test)]
                super::super::member_carrier_factory_test_os::trace_step(
                    "key absence completed; entering SDK",
                );
                provider::native::inspect_mixed(&complete_provider_inputs(
                    &self.input.context,
                    &[],
                    &[],
                )?)
                .map_err(|_| Error::Pending)
                .inspect_err(|error| {
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_native(
                        "native SDK or WFP absence",
                        error,
                    );
                    #[cfg(not(test))]
                    let _ = error;
                })?;
                #[cfg(test)]
                super::super::member_carrier_factory_test_os::trace_step("SDK absence completed");
                self.pair(pair, expected, lock).inspect_err(|error| {
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_native(
                        "same Pair and native roots",
                        error,
                    );
                    #[cfg(not(test))]
                    let _ = error;
                })?;
                self.history.cold()?;
                if self.no_effect_records()? != before {
                    return Err(Error::Conflict);
                }
            }
            Ok(())
        }
        /// Before any loader/constructor attempt, under the SAME original
        /// cleanup Calling. Exact stage/Pair ACK and full SDK, all native keys,
        /// private paths/services/initial-J/creator and BFE are independently
        /// reread. This is not a no-op permission from missing actor fields.
        pub(crate) fn read_no_constructor_cleanup(
            &self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &KeyLock,
        ) -> Result<crate::member_carrier_guard::Snapshot> {
            (|| {
                self.history.cold()?;
                validate_never_cleanup_stage_frame(&self.input.context, expected)?;
                self.pair(pair, expected, lock).inspect_err(|error| {
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_native(
                        "same Pair and native roots",
                        error,
                    );
                    #[cfg(not(test))]
                    let _ = error;
                })?;
                #[cfg(test)]
                super::super::member_carrier_factory_test_os::trace_step(
                    "no-C Pair read completed",
                );
                let before = self.no_effect_records()?;
                #[cfg(test)]
                super::super::member_carrier_factory_test_os::trace_step(
                    "no-C ledger read completed; opening BFE",
                );
                let mut guard = super::super::member_carrier_guard::ScopedGuardAbsence::open(
                    expected.scope.clone(),
                )
                .map_err(|_| Error::Pending)
                .inspect_err(|error| {
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_native(
                        "native SDK or WFP absence",
                        error,
                    );
                    #[cfg(not(test))]
                    let _ = error;
                })?;
                #[cfg(test)]
                super::super::member_carrier_factory_test_os::trace_step(
                    "no-C BFE opened; reading snapshot",
                );
                let actual = guard
                    .read_snapshot(&expected.scope)
                    .map_err(|_| Error::Pending)
                    .inspect_err(|error| {
                        #[cfg(test)]
                        super::super::member_carrier_factory_test_os::trace_native(
                            "native SDK or WFP absence",
                            error,
                        );
                        #[cfg(not(test))]
                        let _ = error;
                    })?;
                #[cfg(test)]
                super::super::member_carrier_factory_test_os::trace_step(
                    "no-C BFE snapshot completed",
                );
                for _ in 0..2 {
                    pair.verify_cleanup_entry_for(
                        &self.input.runtime,
                        &self.input.context,
                        expected,
                    )
                    .map_err(|_| Error::Conflict)?;
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step(
                        "no-C cleanup entry reverified",
                    );
                    self.cold_full_absence(pair, expected, lock)
                        .inspect_err(|error| {
                            #[cfg(test)]
                            super::super::member_carrier_factory_test_os::trace_native(
                                "full absence",
                                error,
                            );
                            #[cfg(not(test))]
                            let _ = error;
                        })?;
                    if guard
                        .read_snapshot(&expected.scope)
                        .map_err(|_| Error::Pending)?
                        != actual
                        || self.no_effect_records()? != before
                    {
                        return Err(Error::Conflict);
                    }
                    validate_never_cleanup_stage_frame(&self.input.context, expected)?;
                    self.pair(pair, expected, lock).inspect_err(|error| {
                        #[cfg(test)]
                        super::super::member_carrier_factory_test_os::trace_native(
                            "same Pair and native roots",
                            error,
                        );
                        #[cfg(not(test))]
                        let _ = error;
                    })?;
                    self.history.cold()?;
                }
                Ok(actual)
            })()
            .map_err(pending_unknown)
        }

        /// Exact no-C Closing9/10, inside SAME run_uncaptured_read Calling.
        /// Actual original Closing ACK, runtime/source/held lock, private
        /// no-effect ledger and full native absence are mandatory on both
        /// sides. No receipt/owner is manufactured and no object is mutated.
        pub(crate) fn read_bootstrap_native_empty(
            &self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<crate::member_carrier_guard::Snapshot> {
            (|| {
                self.history.cold()?;
                validate_never_bootstrap_native_frame(&self.input.context, expected)?;
                self.pair(pair, expected, lock)?;
                pair.verify_cleanup_entry_for(&self.input.runtime, &self.input.context, expected)
                    .map_err(|_| Error::Conflict)?;
                let before = self.no_effect_records()?;
                let mut guard = super::super::member_carrier_guard::ScopedGuardAbsence::open(
                    expected.scope.clone(),
                )
                .map_err(|_| Error::Pending)?;
                let mut snapshot = None;
                verify_never_bootstrap_reads(&self.history, &self.input.context, expected, || {
                    self.pair(pair, expected, lock)?;
                    pair.verify_cleanup_entry_for(
                        &self.input.runtime,
                        &self.input.context,
                        expected,
                    )
                    .map_err(|_| Error::Conflict)?;
                    let empty = guard
                        .read_snapshot(&expected.scope)
                        .map_err(|_| Error::Pending)?;
                    if snapshot.as_ref().is_some_and(|before| before != &empty) {
                        return Err(Error::Conflict);
                    }
                    // Return THIS reader's actual sample only after both full
                    // SDK/private/runtime brackets. Never synthesize an empty
                    // snapshot or make Startup reopen a second WFP reader.
                    snapshot = Some(empty.clone());
                    self.cold_full_absence(pair, expected, lock)?;
                    if guard
                        .read_snapshot(&expected.scope)
                        .map_err(|_| Error::Pending)?
                        != empty
                        || self.no_effect_records()? != before
                    {
                        return Err(Error::Conflict);
                    }
                    pair.verify_cleanup_entry_for(
                        &self.input.runtime,
                        &self.input.context,
                        expected,
                    )
                    .map_err(|_| Error::Conflict)?;
                    self.pair(pair, expected, lock)
                })?;
                snapshot.ok_or(Error::Pending)
            })()
            .map_err(pending_unknown)
        }
        /// Exact original no-C Closing12 / pending FullEmpty, inside SAME
        /// run_uncaptured_read Calling. This is neither Closing9/10 nor an
        /// acknowledged Stopped frame. Never-ledger, actual Closing ACK,
        /// runtime/source/held lock, ALL protected no-effect records, both
        /// private member/service namespaces, all three keys, full mixed SDK
        /// and the scoped WFP universe are reattested around both reads.
        /// Partial C attempts cannot use this channel even if SDK looks empty.
        pub(crate) fn read_bootstrap_full_empty(
            &self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<crate::member_carrier_guard::Snapshot> {
            (|| {
                self.history.cold()?;
                validate_never_bootstrap_full_frame(&self.input.context, expected)?;
                self.pair(pair, expected, lock)?;
                pair.verify_cleanup_entry_for(&self.input.runtime, &self.input.context, expected)
                    .map_err(|_| Error::Conflict)?;
                let before = self.no_effect_records()?;
                let mut guard = super::super::member_carrier_guard::ScopedGuardAbsence::open(
                    expected.scope.clone(),
                )
                .map_err(|_| Error::Pending)?;
                let mut snapshot = None;
                verify_never_bootstrap_full_reads(
                    &self.history,
                    &self.input.context,
                    expected,
                    || {
                        self.pair(pair, expected, lock)?;
                        pair.verify_cleanup_entry_for(
                            &self.input.runtime,
                            &self.input.context,
                            expected,
                        )
                        .map_err(|_| Error::Conflict)?;
                        let empty = guard
                            .read_snapshot(&expected.scope)
                            .map_err(|_| Error::Pending)?;
                        if snapshot.as_ref().is_some_and(|before| before != &empty) {
                            return Err(Error::Conflict);
                        }
                        snapshot = Some(empty.clone());
                        self.cold_full_absence(pair, expected, lock)?;
                        if guard
                            .read_snapshot(&expected.scope)
                            .map_err(|_| Error::Pending)?
                            != empty
                            || self.no_effect_records()? != before
                        {
                            return Err(Error::Conflict);
                        }
                        pair.verify_cleanup_entry_for(
                            &self.input.runtime,
                            &self.input.context,
                            expected,
                        )
                        .map_err(|_| Error::Conflict)?;
                        self.pair(pair, expected, lock)
                    },
                )?;
                snapshot.ok_or(Error::Pending)
            })()
            .map_err(pending_unknown)
        }
        /// No-C repeated Stop, inside SAME supervised Calling. Original
        /// Stopped ACK and immutable no-attempt ledger are mandatory; absent
        /// NativeCarrierReceipts alone is never a terminal proof.
        pub(crate) fn verify_uncaptured_terminal_absent(
            &self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<()> {
            self.verify_uncaptured_terminal_absent_inner(pair, expected, lock)
                .map_err(pending_unknown)
        }
        fn verify_uncaptured_terminal_absent_inner(
            &self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &KeyLock,
        ) -> Result<()> {
            validate_never_member_terminal_frame(&self.input.context, expected)?;
            pair.verify_terminal_entry(&self.input.runtime, &self.input.context, expected)
                .map_err(|_| Error::Conflict)?;
            self.cold_full_absence(pair, expected, lock)?;
            pair.verify_terminal_entry(&self.input.runtime, &self.input.context, expected)
                .map_err(|_| Error::Conflict)?;
            validate_never_member_terminal_frame(&self.input.context, expected)
        }
        /// Genuine uncaptured target history; NEVER missing lookup -> ACK.
        /// C present uses original Closing + full mixed SDK, not empty universe.
        /// Includes readonly preparation failures BEFORE owner publication.
        /// The original ledger proves no native attempt, not a missing Option.
        pub(crate) fn verify_before_carrier_absent(
            &self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            slot: TunnelSlot,
            lock: &mut KeyLock,
        ) -> Result<()> {
            self.cold_absence(pair, expected, slot, lock)
                .map_err(pending_unknown)
        }
        pub(crate) fn verify_uncaptured_member_absent(
            &self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            slot: TunnelSlot,
            closing: Option<&NativeClosingRead>,
            lock: &mut KeyLock,
        ) -> Result<()> {
            self.uncaptured_inner(pair, expected, slot, closing, lock)
                .map_err(pending_unknown)
        }
        fn uncaptured_inner(
            &self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            slot: TunnelSlot,
            closing: Option<&NativeClosingRead>,
            lock: &KeyLock,
        ) -> Result<()> {
            let index = slot_index(slot);
            self.history.uncaptured(index)?;
            validate_never_member_frame(&self.input.context, expected, slot)?;
            if expected.members[index].is_some() {
                return Err(Error::Conflict);
            }
            if expected.stop_stage == 12 && self.history.carrier_attempted.get() {
                return Err(Error::Pending); // Ordinary live-C sampler is never terminal authority.
            }
            if expected.carrier.is_none() {
                if closing.is_some() {
                    return Err(Error::Conflict);
                }
                self.cold_absence(pair, expected, slot, lock)?;
            } else {
                if !self.history.carrier_attempted.get() {
                    return Err(Error::Conflict);
                }
                let closing = closing.ok_or(Error::Pending)?;
                let before = self
                    .input
                    .runtime
                    .record(&self.input.context, RecordKind::NativeCarrierReceipts)?;
                let native = keys_record::Record::decode(&before)?;
                let key = &native.keys[index + 1];
                if native.context != self.input.context
                    || native.phase != Phase::Closing
                    || native.generation == 0
                    || key.phase != keys_record::KeyPhase::Unstarted
                    || key.new_key_ack
                    || key.baseline != keys_record::Value::Absent
                    || key.current != keys_record::Value::Absent
                    || key.pending.is_some()
                {
                    return Err(Error::Pending);
                }
                for _ in 0..2 {
                    self.pair(pair, expected, lock)?;
                    self.file_absence(slot)?;
                    self.services_absent(slot)?;
                    self.key_fact(index + 1)?; // Facts ONLY, not retained-key authority.
                    closing
                        .inspect_window(|window| {
                            if !window.matches_runtime(&self.input.runtime)
                                || !window.matches_closing(closing)
                                || window.bindings().scope != self.input.context.intent.scope
                                || window.bindings().carrier.as_ref().map(|c| c.identity.proof)
                                    != expected.carrier
                                || window.bindings().egress[index].is_some()
                                || window.closed_member(slot).is_some()
                            {
                                return Err(super::super::member_carrier_wintun::Error::Conflict);
                            }
                            Ok(())
                        })
                        .map_err(|_| Error::Pending)?;
                    self.history.uncaptured(index)?;
                    self.pair(pair, expected, lock)?;
                    if self
                        .input
                        .runtime
                        .record(&self.input.context, RecordKind::NativeCarrierReceipts)?
                        != before
                    {
                        return Err(Error::Conflict);
                    }
                }
            }
            self.history.uncaptured(index)
        }
    }

    struct UnstartedEnvelope<'a> {
        context: &'a Context,
        runtime: &'a RuntimeRead,
        source: &'a Rc<MemberSource>,
        carrier: &'a Rc<WintunSource>,
        supervisor: &'a Rc<NativeDeadline>,
        intent: &'a Intent,
    }
    impl UnstartedEnvelope<'_> {
        fn verify(
            &self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &KeyLock,
        ) -> Result<Vec<u8>> {
            validate_unstarted_closing(
                self.context,
                expected,
                self.intent.slot,
                Some(self.intent),
            )?;
            let deadline = self.supervisor.read_pin().map_err(|_| Error::Conflict)?;
            deadline
                .verify_runtime_call(self.supervisor, self.runtime, self.context)
                .map_err(|_| Error::Conflict)?;
            if !self.runtime.matches_lock(lock) || !self.source.matches_carrier(self.carrier) {
                return Err(Error::Conflict);
            }
            self.runtime.verify_source(self.carrier)?;
            self.runtime
                .verify_member_intent(self.context, self.source, self.intent)?;
            let bytes = self
                .runtime
                .record(self.context, RecordKind::NativeCarrierReceipts)?;
            let native = keys_record::Record::decode(&bytes)?;
            if native.context != *self.context
                || native.generation == 0
                || native.phase != Phase::Closing
                || native.keys[slot_index(self.intent.slot) + 1]
                    .pending
                    .is_some()
            {
                return Err(Error::Pending);
            }
            pair.inspect_cleanup_effect(
                self.runtime,
                self.supervisor,
                expected,
                4 + slot_index(self.intent.slot) as u8,
                |_| Ok(()),
            )
            .map_err(|_| Error::Conflict)?;
            deadline
                .verify_call(self.supervisor, self.context)
                .map_err(|_| Error::Conflict)?;
            if !self.runtime.matches_lock(lock)
                || self
                    .runtime
                    .record(self.context, RecordKind::NativeCarrierReceipts)?
                    != bytes
            {
                return Err(Error::Conflict);
            }
            Ok(bytes)
        }
        fn inspect_sdk(
            &self,
            expected: &PairRecord,
            closing: Option<&NativeClosingRead>,
        ) -> Result<()> {
            let index = slot_index(self.intent.slot);
            if let Some(carrier) = expected.carrier {
                let closing = closing.ok_or(Error::Pending)?;
                closing
                    .inspect_window(|window| {
                        if !window.matches_closing(closing)
                            || !window.matches_runtime(self.runtime)
                            || window.bindings().scope != self.context.intent.scope
                            || window.bindings().carrier.as_ref().map(|c| c.identity.proof)
                                != Some(carrier)
                            || window.bindings().egress[index].is_some()
                            || window.closed_member(self.intent.slot).is_some()
                        {
                            return Err(super::super::member_carrier_wintun::Error::Conflict);
                        }
                        Ok(())
                    })
                    .map_err(|_| Error::Pending)
            } else {
                if closing.is_some() {
                    return Err(Error::Conflict);
                }
                provider::native::inspect_mixed(&complete_provider_inputs(self.context, &[], &[])?)
                    .map(|_| ())
                    .map_err(|_| Error::Pending)
            }
        }
    }

    /// Immutable original file/runtime/Calling roots. No public constructor,
    /// metadata import, native member ACK, Source or guard is supplied here.
    pub(crate) struct PreparedMemberOrigin {
        context: Context,
        intent: Intent,
        runtime: RuntimeRead,
        source: Rc<MemberSource>,
        carrier: Rc<WintunSource>,
        supervisor: Rc<NativeDeadline>,
        never_effects: Rc<NativeNeverMemberEffects>,
        generation: u64,
        replacement: Option<Rc<NativeMemberPreparationGeneration>>,
        // DATA-only package/source pins, not a module/driver/effect grant.
        // Travels with the SAME prepared origin into the retained controller.
        // No Source/inventory/actor reverse edge: WintunPreload owns only the
        // passive WintunSource and package file pins, so no strong root cycle.
        cold_carrier_package: RefCell<ColdPackageRoot<WintunPreload>>,
        cold_wireguard_package: RefCell<
            ColdPackageRoot<
                crate::member_owner::cold_wireguard_data::native::CheckedOriginalWireGuardPackage,
            >,
        >,
    }
    impl PreparedMemberOrigin {
        fn verify(&self, lock: &KeyLock) -> Result<()> {
            if self.never_effects.history.generation[slot_index(self.intent.slot)].get()
                != self.generation
            {
                return Err(Error::Retired);
            }
            let deadline = self.supervisor.read_pin().map_err(|_| Error::Conflict)?;
            deadline
                .verify_runtime_call(&self.supervisor, &self.runtime, &self.context)
                .map_err(|_| Error::Conflict)?;
            if !self.runtime.matches_lock(lock)
                || !self.runtime.fresh(&self.context)?
                || !self.source.matches_carrier(&self.carrier)
            {
                return Err(Error::Conflict);
            }
            self.runtime.verify_source(&self.carrier)?;
            self.runtime
                .verify_member_intent(&self.context, &self.source, &self.intent)?;
            deadline
                .verify_call(&self.supervisor, &self.context)
                .map_err(|_| Error::Conflict)?;
            Ok(())
        }
        pub(crate) fn same_original(&self, other: &Self) -> bool {
            std::ptr::eq(self, other)
        }
    }
    struct PreparedOwner {
        raw: Option<RawOwner>,
        retained: Option<Member>,
        pending: Option<Pending>,
        prior: Option<Option<MemberRecord>>,
    }
    pub(crate) struct NativePreparedMemberInputs {
        pub context: Context,
        pub runtime: RuntimeRead,
        pub engine: PathBuf,
        pub slot: TunnelSlot,
        pub source: Rc<MemberSource>,
        pub carrier: Rc<WintunSource>,
        pub supervisor: Rc<NativeDeadline>,
        pub never_effects: Rc<NativeNeverMemberEffects>,
    }
    /// Actor roots this BEFORE C. It owns the single real MemberOwner whose
    /// addressless configuration is zeroizing; construction never writes it.
    pub(crate) struct NativePreparedMember {
        root: PreparedRoot<PreparedOwner>,
        origin: Rc<PreparedMemberOrigin>,
        live_source: Option<PreparedSourceRegistration<NativeSourceRead>>,
        live_preparation: Option<PairRecord>,
    }
    pub(crate) struct NativeMemberAttachment<G> {
        pub image: OriginalImage,
        pub original_source: Rc<NativeSourceRead>,
        pub inventory: MemberInventoryRead,
        pub gate: Rc<RefCell<G>>,
    }
    impl NativePreparedMember {
        pub(crate) fn prepare(
            slot: &mut Option<Self>,
            input: NativePreparedMemberInputs,
            logical: &str,
            lock: &mut KeyLock,
        ) -> Result<()> {
            if slot.is_some() {
                return Err(Error::Retired);
            }
            if !input.never_effects.matches(
                &input.context,
                &input.runtime,
                &input.source,
                &input.carrier,
                &input.supervisor,
            ) {
                return Err(Error::Conflict);
            }
            // SAME original creator history is marked BEFORE fallible readonly
            // owner construction; Err/unwind never turns it back into uncaptured.
            let generation = input
                .never_effects
                .history
                .prepare(slot_index(input.slot))?;
            let replacement = input.never_effects.preparation_ticket(
                input.slot,
                generation,
                &input.runtime,
                &input.context,
            )?;
            let transport = input.source.transport();
            let io = NativeMemberIo::from_trusted_factory(
                input.engine.clone(),
                input.slot,
                transport,
                MemberFiles::new().map_err(owner_error)?,
            )
            .map_err(owner_error)
            .inspect_err(|error| {
                #[cfg(test)]
                super::super::member_carrier_factory_test_os::trace_native(
                    "prepared native member adapter",
                    error,
                );
                #[cfg(not(test))]
                let _ = error;
            })?;
            let owner = MemberOwner::from_trusted_carrier_engine(
                &input.context.intent,
                input.slot,
                transport,
                input.engine,
                logical,
                MemberFiles::new().map_err(owner_error)?,
                io,
            )
            .map_err(owner_error)
            .inspect_err(|error| {
                #[cfg(test)]
                super::super::member_carrier_factory_test_os::trace_native(
                    "prepared addressless member owner",
                    error,
                );
                #[cfg(not(test))]
                let _ = error;
            })?;
            let origin = Rc::new(PreparedMemberOrigin {
                context: input.context,
                intent: owner.intent().clone(),
                runtime: input.runtime,
                source: input.source,
                carrier: input.carrier,
                supervisor: input.supervisor,
                never_effects: input.never_effects,
                generation,
                replacement,
                cold_carrier_package: RefCell::new(ColdPackageRoot::new()),
                cold_wireguard_package: RefCell::new(ColdPackageRoot::new()),
            });
            *slot = Some(Self {
                root: PreparedRoot::new(PreparedOwner {
                    raw: Some(owner),
                    retained: None,
                    pending: None,
                    prior: None,
                }),
                origin,
                live_source: None,
                live_preparation: None,
            });
            slot.as_mut()
                .expect("rooted readonly preparation")
                .prepared_record(lock)
                .map(|_| ())
                .inspect_err(|error| {
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_native(
                        "prepared readonly member profile",
                        error,
                    );
                    #[cfg(not(test))]
                    let _ = error;
                })
        }
        /// Move both SAME closed roots into caller retention, not Drop/None
        /// inference. Does NOT replace inventory entries or admit native Start.
        pub(crate) fn retain_closed_generation<G: NativeMemberLifecycle>(
            prepared: &mut Option<Self>,
            controller: &mut Option<NativeMemberController<G>>,
            ticket: &Rc<NativeMemberPreparationGeneration>,
            retired: &mut Vec<NativeRetiredMemberRoots<G>>,
        ) -> Result<()> {
            let old_prepared = prepared.as_ref().ok_or(Error::Retired)?;
            let old_controller = controller.as_ref().ok_or(Error::Retired)?;
            let owned = old_controller.root.owner.as_ref().ok_or(Error::Retired)?;
            if !ticket.acknowledged.get()
                || !old_controller.root.completed
                || !old_controller.root.closed_registered
                || owned.generation != ticket.old
                || owned.intent.slot != ticket.slot
                || old_controller
                    .root
                    .closed
                    .as_ref()
                    .is_none_or(|c| !Rc::ptr_eq(c, &ticket.receipt))
                || !Rc::ptr_eq(&owned.prepared_origin, &old_prepared.origin)
                || old_prepared.root.owner.is_some()
                || !owned
                    .never_effects
                    .retired
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .iter()
                    .any(|t| Rc::ptr_eq(t, ticket))
            {
                return Err(Error::Conflict);
            }
            retain_verified_closed_generation(prepared, controller, ticket, retired)
        }
        /// prepare_state receives UNSAVED next, before assigning its member
        /// and before save(next). The opaque current pin must still be Fresh.
        /// This compares the relation only; it neither publishes next nor
        /// constructs/imports a protected Pair ACK for the proposal.
        pub(crate) fn verify_proposal(
            &mut self,
            current_fresh: &NativePairIntentRead,
            proposal: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<MemberRecord> {
            if self.live_source.is_some() {
                return Err(Error::Conflict);
            }
            let prepared = self.prepared_record(lock)?;
            current_fresh
                .inspect(&self.origin.runtime, &self.origin.supervisor, |actual| {
                    validate_preparation_proposal(
                        &self.origin.context,
                        actual,
                        proposal,
                        &prepared.intent,
                    )
                    .map_err(io_error)
                })
                .map_err(|_| Error::Conflict)?;
            self.origin.verify(lock)?;
            // Only immutable intent/Prepared DATA crosses this return. The
            // original owner and readonly profile stay in this retained root;
            // the callback above only validates the protected proposal. Do not
            // repeat the complete readonly preparation to reconstruct this DATA.
            Ok(prepared)
        }
        /// Attach prepare_state receives an unchanged, UNSAVED Running clone;
        /// it adds Prepared/Attach only AFTER this returns. Actor supplies its
        /// original live Source, other rooted controller and SAME borrowed lock.
        /// This is readonly SDK/original proof, NOT native profile acceptance.
        pub(crate) fn verify_live_attach_proposal<G: NativeMemberLifecycle>(
            &mut self,
            pair: &NativePairIntentRead,
            proposal: &PairRecord,
            source: &Rc<NativeSourceRead>,
            other: &mut NativeMemberController<G>,
            lock: &mut KeyLock,
        ) -> Result<()> {
            self.live_preparation = None;
            let prepared = self.prepared_record(lock)?;
            let replacement = self.origin.replacement.clone();
            if let Some(ticket) = &replacement {
                ticket.verify_original(
                    &self.origin.never_effects,
                    &self.origin.runtime,
                    &self.origin.context,
                )?;
                ticket.verify_source(source)?;
            }
            let verify_pair = || {
                pair.inspect(&self.origin.runtime, &self.origin.supervisor, |actual| {
                    validate_live_preparation_proposal(
                        &self.origin.context,
                        actual,
                        proposal,
                        &prepared.intent,
                    )
                    .map_err(io_error)
                })
                .map_err(|_| Error::Conflict)
            };
            verify_pair()?; // Release protected Pair callback before Source reads.
            if let Some(original) = &self.live_source {
                if !original.verify(source) {
                    return Err(Error::Conflict);
                }
            } else {
                // Keep the first original identity even if subsequent reads fail.
                self.live_source = Some(PreparedSourceRegistration::from_original(source));
            }
            let other_owned = other.root.owner.as_ref().ok_or(Error::Retired)?;
            if !Rc::ptr_eq(source, &other_owned.original_source)
                || !other_owned
                    .runtime
                    .same_original_runtime(&self.origin.runtime)
                || other_owned.context != self.origin.context
                || other_owned.intent.slot == self.origin.intent.slot
            {
                return Err(Error::Conflict);
            }
            let before_other = other.observe_original(pair, proposal, lock)?;
            let owner = self.root.owner.as_mut().ok_or(Error::Retired)?;
            let raw = owner.raw.as_mut().ok_or(Error::Retired)?;
            let prior = raw.prior_stopped().map_err(owner_error)?;
            if owner
                .prior
                .as_ref()
                .is_some_and(|original| original != &prior)
            {
                return Err(Error::Conflict);
            }
            owner.prior = Some(prior.clone());
            source
                .inspect_window(|window| {
                    if !window.matches_source(source)
                        || !window.matches_runtime(&self.origin.runtime)
                        || window.bindings().scope != self.origin.context.intent.scope
                    {
                        return Err(super::super::member_carrier_wintun::Error::Conflict);
                    }
                    let carrier = window.bindings().carrier.as_ref().map(|c| c.identity.proof);
                    let members = std::array::from_fn(|i| {
                        window.bindings().egress[i].as_ref().map(|m| m.proof)
                    });
                    let closed = [
                        window.closed_member(TunnelSlot::A).is_some(),
                        window.closed_member(TunnelSlot::B).is_some(),
                    ];
                    if let Some(history) = window.closed_member(self.origin.intent.slot) {
                        let ticket = replacement
                            .as_ref()
                            .ok_or(super::super::member_carrier_wintun::Error::Conflict)?;
                        validate_replacement_preparation_observation(
                            &self.origin.context,
                            proposal,
                            &prepared.intent,
                            carrier,
                            members,
                            ReplacementHistory {
                                closed,
                                stopped: &ticket.stopped,
                                intent: &history.intent,
                                proof: history.proof,
                            },
                            &before_other,
                        )
                    } else {
                        validate_live_preparation_observation(
                            &self.origin.context,
                            proposal,
                            &prepared.intent,
                            carrier,
                            members,
                            closed,
                            &before_other,
                        )
                    }
                    .map_err(|_| super::super::member_carrier_wintun::Error::Conflict)
                })
                .map_err(|_| Error::Conflict)?;
            if raw.prior_stopped().map_err(owner_error)? != prior
                || other.observe_original(pair, proposal, lock)? != before_other
            {
                return Err(Error::Conflict);
            }
            verify_pair()?;
            if let Some(ticket) = &replacement {
                ticket.verify_source(source)?;
                ticket.verify_original(
                    &self.origin.never_effects,
                    &self.origin.runtime,
                    &self.origin.context,
                )?;
            }
            self.origin.verify(lock)?;
            self.live_preparation = Some(proposal.clone()); // No protected ACK minted.
            Ok(())
        }
        pub(crate) fn prepared_record(&mut self, lock: &mut KeyLock) -> Result<MemberRecord> {
            self.origin.verify(lock)?;
            self.verify_replacement_prior(lock)?;
            let owner = self.root.owner.as_mut().ok_or(Error::Retired)?;
            let raw = owner.raw.as_mut().ok_or(Error::Retired)?;
            if raw.intent() != &self.origin.intent {
                return Err(Error::Retired);
            }
            // Actual zeroizing owner and signed Source are already caller-
            // rooted before this fallible readonly compiler. No config write,
            // SDK driver load/install or SCM effects. Repeated preparation must
            // return the SAME private profile original, not a hash-only receipt.
            let profile = raw.prepare_readonly_native_profile().map_err(owner_error)?;
            raw.verify_readonly_native_profile(&profile)
                .map_err(owner_error)?;
            let record = MemberRecord {
                intent: self.origin.intent.clone(),
                phase: MemberPhase::Prepared,
                proof: None,
                retired_proof: None,
                previous_config_sha256: None,
            };
            crate::member_owner::validate_record_shape(&record).map_err(owner_error)?;
            self.origin.verify(lock)?;
            Ok(record)
        }
        fn verify_replacement_prior(&mut self, lock: &KeyLock) -> Result<()> {
            let Some(ticket) = &self.origin.replacement else {
                return Ok(());
            };
            ticket.verify_original(
                &self.origin.never_effects,
                &self.origin.runtime,
                &self.origin.context,
            )?;
            let owner = self.root.owner.as_mut().ok_or(Error::Retired)?;
            let raw = owner.raw.as_mut().ok_or(Error::Retired)?;
            let prior = raw
                .prior_stopped()
                .map_err(|e| pending_unknown(owner_error(e)))?;
            validate_replacement_prior(
                &self.origin.context,
                &self.origin.intent,
                &ticket.stopped,
                prior.as_ref(),
            )?;
            if owner.prior.as_ref().is_some_and(|old| old != &prior) {
                return Err(Error::Conflict);
            }
            owner.prior = Some(prior.clone()); // Root actual predecessor BEFORE postflight.
            if raw
                .prior_stopped()
                .map_err(|e| pending_unknown(owner_error(e)))?
                != prior
            {
                return Err(Error::Conflict);
            }
            ticket.verify_original(
                &self.origin.never_effects,
                &self.origin.runtime,
                &self.origin.context,
            )?;
            self.origin.verify(lock)
        }
        /// Readonly cleanup for this SAME prepared, never-started owner. No
        /// config/journal CAS, SCM effect or synthetic Stopped/Closed ACK. With
        /// no C, query the complete EMPTY SDK universe; otherwise use actual C
        /// Closing. Whole Calling/Pair/lock/private predecessor bracket both.
        pub(crate) fn verify_unstarted_absent(
            &mut self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            closing: Option<&NativeClosingRead>,
            lock: &mut KeyLock,
        ) -> Result<()> {
            self.verify_unstarted_absent_inner(pair, expected, closing, lock)
                .map_err(pending_unknown)
        }
        fn verify_unstarted_absent_inner(
            &mut self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            closing: Option<&NativeClosingRead>,
            lock: &mut KeyLock,
        ) -> Result<()> {
            if self
                .origin
                .runtime
                .optional_record(&self.origin.context, RecordKind::NativeCarrierReceipts)?
                .is_none()
            {
                if closing.is_some() || self.live_source.is_some() {
                    return Err(Error::Conflict);
                }
                let owner = self.root.owner.as_ref().ok_or(Error::Retired)?;
                if owner
                    .raw
                    .as_ref()
                    .is_none_or(|o| o.intent() != &self.origin.intent)
                    || !self.origin.never_effects.matches(
                        &self.origin.context,
                        &self.origin.runtime,
                        &self.origin.source,
                        &self.origin.carrier,
                        &self.origin.supervisor,
                    )
                {
                    return Err(Error::Conflict);
                }
                self.origin.runtime.verify_member_intent(
                    &self.origin.context,
                    &self.origin.source,
                    &self.origin.intent,
                )?;
                validate_never_member_frame(
                    &self.origin.context,
                    expected,
                    self.origin.intent.slot,
                )?;
                if expected.members[slot_index(self.origin.intent.slot)]
                    .as_ref()
                    .is_some_and(|m| m.owner.intent != self.origin.intent)
                {
                    return Err(Error::Conflict);
                }
                // Separate original never-effect proof; absence of native JSON
                // alone never takes this branch to success or mints Closing.
                self.origin.never_effects.cold_absence(
                    pair,
                    expected,
                    self.origin.intent.slot,
                    lock,
                )?;
                return self.origin.runtime.verify_member_intent(
                    &self.origin.context,
                    &self.origin.source,
                    &self.origin.intent,
                );
            }
            let envelope = UnstartedEnvelope {
                context: &self.origin.context,
                runtime: &self.origin.runtime,
                source: &self.origin.source,
                carrier: &self.origin.carrier,
                supervisor: &self.origin.supervisor,
                intent: &self.origin.intent,
            };
            let native = envelope.verify(pair, expected, lock)?;
            if let Some(registered) = &self.live_source {
                let source = registered.0.upgrade().ok_or(Error::Retired)?;
                if !closing.is_some_and(|c| c.matches_source_origin(&source)) {
                    return Err(Error::Conflict);
                }
            }
            let state = self.root.owner.as_mut().ok_or(Error::Retired)?;
            if state.retained.is_none() {
                state.retained = Some(RetainedMember::new(state.raw.take().ok_or(Error::Retired)?));
            }
            if state.pending.is_none() {
                state.pending = Some(
                    state
                        .retained
                        .as_ref()
                        .ok_or(Error::Retired)?
                        .pending_read()
                        .map_err(owner_error)?,
                );
            }
            let pending = state.pending.as_mut().ok_or(Error::Retired)?;
            let before = pending.read_unstarted_for_cleanup().map_err(owner_error)?;
            if before.0 != self.origin.intent
                || state.prior.as_ref().is_some_and(|prior| prior != &before.1)
            {
                return Err(Error::Conflict);
            }
            state.prior = Some(before.1.clone());
            envelope.inspect_sdk(expected, closing)?;
            if pending.read_unstarted_for_cleanup().map_err(owner_error)? != before
                || envelope.verify(pair, expected, lock)? != native
            {
                return Err(Error::Conflict);
            }
            envelope.inspect_sdk(expected, closing)?;
            if envelope.verify(pair, expected, lock)? != native {
                return Err(Error::Conflict);
            }
            Ok(())
        }
        /// Shared C/Wintun package prerequisite for BOTH native member backends,
        /// BEFORE any C load/create or member SCM/config effect. Does not claim
        /// WireGuardNT package acceptance, running-driver ownership, executable
        /// lifetime or permission to load/install/replace anything. The actual
        /// original signed WintunSource is already part of this private origin.
        /// Only exact saved Starting/no-pending/no-C under SAME Calling/lock
        /// may read this cold checker; live Attach never reuses cold absence.
        pub(crate) fn verify_cold_carrier_package_before_carrier(
            &self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<()> {
            let origin = &self.origin;
            let mut original_records = None;
            origin
                .cold_carrier_package
                .try_borrow_mut()
                .map_err(|_| Error::Pending)?
                .verify(
                    || {
                        origin.never_effects.history.cold()?;
                        validate_before_carrier(&origin.context, expected, &origin.intent)?;
                        origin.verify(lock)?;
                        pair.inspect(&origin.runtime, &origin.supervisor, |actual| {
                            if actual == expected {
                                Ok(())
                            } else {
                                Err(io_error(Error::Conflict))
                            }
                        })
                        .map_err(|_| Error::Conflict)?; // Release Pair before native reads.
                        let records = origin.never_effects.forward_no_effect_records()?;
                        if original_records
                            .as_ref()
                            .is_some_and(|before| before != &records)
                        {
                            return Err(Error::Conflict);
                        }
                        original_records = Some(records);
                        for index in 0..3 {
                            origin.never_effects.key_fact(index).inspect_err(|error| {
                                #[cfg(test)]
                                super::super::member_carrier_factory_test_os::trace_native(
                                    [
                                        "cold prerequisite C key",
                                        "cold prerequisite A key",
                                        "cold prerequisite B key",
                                    ][index],
                                    error,
                                );
                                #[cfg(not(test))]
                                let _ = error;
                            })?;
                        }
                        origin.verify(lock).inspect_err(|error| {
                            #[cfg(test)]
                            super::super::member_carrier_factory_test_os::trace_native(
                                "cold prerequisite original postflight",
                                error,
                            );
                            #[cfg(not(test))]
                            let _ = error;
                        })
                    },
                    || WintunPreload::new(&origin.carrier),
                    WintunPreload::reattest,
                )
                .map_err(|error| match error {
                    ColdPackageError::Retired => Error::Retired,
                    ColdPackageError::Boundary(error) => pending_unknown(error),
                })?;
            #[cfg(test)]
            super::super::member_carrier_factory_test_os::trace_step(
                "member preflight actual cold carrier package accepted",
            );
            super::super::member_owner::verify_readonly_cold_backend_modules(
                &origin.source,
                &origin.carrier,
            )
            .map_err(|_| Error::Pending)?;
            #[cfg(test)]
            super::super::member_carrier_factory_test_os::trace_step(
                "member preflight cold backend module absence accepted",
            );
            Ok(())
        }
        /// Original signed WireGuardNT DATA package, exact installed bytes and
        /// FULL legacy/problem universe under the original cold Calling fence.
        /// Never module/driver lifetime or permission to execute DriverInstall.
        pub(crate) fn verify_cold_wireguard_package_before_carrier(
            &self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<()> {
            let origin = &self.origin;
            if origin.intent.transport != nelomai_client_tunnel::TunnelTransport::WireGuard {
                return Err(Error::Invalid);
            }
            let mut original_records = None;
            origin
                .cold_wireguard_package
                .try_borrow_mut()
                .map_err(|_| Error::Pending)?
                .verify(
                    || {
                        origin.never_effects.history.cold()?;
                        validate_before_carrier(&origin.context, expected, &origin.intent)?;
                        origin.verify(lock)?;
                        pair.inspect(&origin.runtime, &origin.supervisor, |actual| {
                            if actual == expected {
                                Ok(())
                            } else {
                                Err(io_error(Error::Conflict))
                            }
                        })
                        .map_err(|_| Error::Conflict)?; // Release Pair before native reads.
                        let records = origin.never_effects.forward_no_effect_records()?;
                        if original_records
                            .as_ref()
                            .is_some_and(|before| before != &records)
                        {
                            return Err(Error::Conflict);
                        }
                        original_records = Some(records);
                        for index in 0..3 {
                            origin.never_effects.key_fact(index).inspect_err(|error| {
                                #[cfg(test)]
                                super::super::member_carrier_factory_test_os::trace_native(
                                    [
                                        "cold prerequisite C key",
                                        "cold prerequisite A key",
                                        "cold prerequisite B key",
                                    ][index],
                                    error,
                                );
                                #[cfg(not(test))]
                                let _ = error;
                            })?;
                        }
                        origin.verify(lock).inspect_err(|error| {
                            #[cfg(test)]
                            super::super::member_carrier_factory_test_os::trace_native(
                                "cold prerequisite original postflight",
                                error,
                            );
                            #[cfg(not(test))]
                            let _ = error;
                        })
                    },
                    || {
                        let source = Rc::new(
                            super::super::member_owner::NativeWireGuardSource::new(
                                &origin.source,
                                &origin.carrier,
                            )
                            .inspect_err(|_error| {
                                #[cfg(test)]
                                if super::super::member_carrier_factory_test_os::state().is_some() {
                                    eprintln!("actual cold WireGuard original source: {_error:?}");
                                }
                            })
                            .map_err(|_| Error::Pending)?,
                        );
                        crate::member_owner::cold_wireguard_data::native::from_original_source(
                            &source,
                        )
                        .inspect_err(|_error| {
                            #[cfg(test)]
                            if super::super::member_carrier_factory_test_os::state().is_some() {
                                eprintln!("actual cold WireGuard DATA package: {_error:?}");
                            }
                        })
                        .map_err(|_| Error::Pending)
                    },
                    |checked| {
                        if !checked.matches_original(&origin.source, &origin.carrier) {
                            return Err(Error::Conflict);
                        }
                        checked.reattest_cold().map_err(|_| Error::Pending)
                    },
                )
                .map_err(|error| match error {
                    ColdPackageError::Retired => Error::Retired,
                    ColdPackageError::Boundary(error) => pending_unknown(error),
                })
        }

        /// AFTER save(next), unlike verify_proposal: the current original pin
        /// now authenticates Starting with this actual Prepared owner present.
        /// Normative prepare -> protected Pair -> full fresh preflight -> C.
        /// No original Source/loaded module/C exists or is fabricated here.
        pub(crate) fn preflight_before_carrier(
            &mut self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<()> {
            macro_rules! reached {
                ($step:literal) => {
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step($step);
                };
            }
            let prepared = self.prepared_record(lock)?;
            reached!("member preflight original prepared record accepted");
            validate_before_carrier(&self.origin.context, expected, &prepared.intent)?;
            reached!("member preflight Starting shape accepted");
            let verify_pair = || {
                pair.inspect(&self.origin.runtime, &self.origin.supervisor, |actual| {
                    if actual == expected {
                        Ok(())
                    } else {
                        Err(io_error(Error::Conflict))
                    }
                })
                .map_err(|_| Error::Conflict)
            };
            verify_pair()?;
            reached!("member preflight current Starting ACK accepted");
            let owner = self.root.owner.as_mut().ok_or(Error::Retired)?;
            let raw = owner.raw.as_mut().ok_or(Error::Retired)?;
            let before = raw.prior_stopped().map_err(owner_error)?;
            reached!("member preflight original prior-stopped read returned");
            if owner.prior.as_ref().is_some_and(|p| p != &before) {
                #[cfg(test)]
                super::super::member_carrier_factory_test_os::trace_step(
                    "member preflight original prior-stopped changed",
                );
                return Err(Error::Conflict);
            }
            owner.prior = Some(before.clone());
            provider::native::inspect_mixed(&complete_provider_inputs(
                &self.origin.context,
                &[],
                &[],
            )?)
            .map_err(|_| Error::Conflict)?;
            reached!("member preflight first full native absence returned");
            if raw.prior_stopped().map_err(owner_error)? != before {
                return Err(Error::Conflict);
            }
            verify_pair()?;
            Ok(())
        }
        /// Final independent native reread AFTER both passive packages. The
        /// caller owns a separate actual Calling; package DATA grants no SDK
        /// permission and an incomplete/denied package cannot finish preflight.
        pub(crate) fn finish_preflight_before_carrier(
            &mut self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<()> {
            validate_before_carrier(&self.origin.context, expected, &self.origin.intent)?;
            self.origin.never_effects.history.cold()?;
            let carrier = self
                .origin
                .cold_carrier_package
                .try_borrow()
                .map_err(|_| Error::Conflict)?;
            if carrier.denied || carrier.original.is_none() {
                return Err(Error::Pending);
            }
            drop(carrier);
            if self.origin.intent.transport == nelomai_client_tunnel::TunnelTransport::WireGuard {
                let backend = self
                    .origin
                    .cold_wireguard_package
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?;
                if backend.denied || backend.original.is_none() {
                    return Err(Error::Pending);
                }
            }
            let owner = self.root.owner.as_mut().ok_or(Error::Retired)?;
            let raw = owner.raw.as_mut().ok_or(Error::Retired)?;
            let before = owner.prior.as_ref().ok_or(Error::Pending)?;
            if &raw.prior_stopped().map_err(owner_error)? != before {
                return Err(Error::Conflict);
            }
            // No partial package observation replaces the original full native
            // absence preflight. Requery the entire C+member universe afterward.
            provider::native::inspect_mixed(&complete_provider_inputs(
                &self.origin.context,
                &[],
                &[],
            )?)
            .map_err(|_| Error::Conflict)?;
            if &raw.prior_stopped().map_err(owner_error)? != before {
                return Err(Error::Conflict);
            }
            pair.inspect(&self.origin.runtime, &self.origin.supervisor, |actual| {
                if actual == expected {
                    Ok(())
                } else {
                    Err(io_error(Error::Conflict))
                }
            })
            .map_err(|_| Error::Conflict)?;
            self.origin.verify(lock)
        }
        /// Publish SAME owner in the persistent controller slot BEFORE any
        /// fallible pending enrollment or original Pair postflight.
        pub(crate) fn attach<G: NativeMemberLifecycle>(
            &mut self,
            slot: &mut Option<NativeMemberController<G>>,
            input: NativeMemberAttachment<G>,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<()> {
            if slot.is_some() {
                return Err(Error::Retired);
            }
            self.origin.verify(lock)?;
            self.verify_replacement_prior(lock)?;
            if let Some(ticket) = &self.origin.replacement {
                ticket.verify_source(&input.original_source)?;
            }
            validate_member_operation(
                &self.origin.context,
                expected,
                &self.origin.intent,
                MemberOperation::Start,
            )?;
            if expected.phase == pair::Phase::Running {
                validate_live_preparation_attachment(
                    &self.origin.context,
                    self.live_preparation.as_ref().ok_or(Error::Pending)?,
                    expected,
                    &self.origin.intent,
                )?;
                if !self
                    .live_source
                    .as_ref()
                    .is_some_and(|original| original.verify(&input.original_source))
                {
                    return Err(Error::Conflict);
                }
            } else if self.live_source.is_some() {
                return Err(Error::Conflict);
            }
            let state = self.root.owner.as_mut().ok_or(Error::Retired)?;
            if let Some(raw) = state.raw.as_mut() {
                let actual_prior = raw.prior_stopped().map_err(owner_error)?;
                if state.prior.as_ref().is_some_and(|p| p != &actual_prior) {
                    return Err(Error::Conflict);
                }
                state.prior = Some(actual_prior);
            }
            if state.retained.is_none() {
                state.retained = Some(RetainedMember::new(state.raw.take().ok_or(Error::Retired)?));
            }
            if state.pending.is_none() {
                state.pending = Some(
                    state
                        .retained
                        .as_ref()
                        .ok_or(Error::Retired)?
                        .pending_read()
                        .map_err(owner_error)?,
                );
            }
            let origin = self.origin.clone();
            // Fallible pin acquisition must precede the infallible transfer;
            // an Err leaves the actual owner rooted in this preparation.
            let runtime = origin.runtime.read_pin()?;
            self.root
                .attach(
                    slot,
                    |mut state| NativeMemberController {
                        rebinds: Vec::new(),
                        root: OperationRoot::new(OwnedMember {
                            member: state.retained.take().expect("SAME prepared retained owner"),
                            pending: state.pending.take().expect("SAME pending original"),
                            partial_cleanup: None,
                            context: origin.context.clone(),
                            intent: origin.intent.clone(),
                            runtime,
                            source: origin.source.clone(),
                            carrier: origin.carrier.clone(),
                            image: input.image,
                            original_source: input.original_source,
                            inventory: input.inventory,
                            supervisor: origin.supervisor.clone(),
                            gate: input.gate,
                            never_effects: origin.never_effects.clone(),
                            generation: origin.generation,
                            prepared_origin: origin,
                            started_generation: None,
                            started_initial: None,
                            prior: state.prior,
                        }),
                    },
                    |controller| {
                        let owned = controller.root.owner.as_ref().ok_or(Error::Retired)?;
                        owned.verify_sources()?;
                        owned
                            .inventory
                            .read_pin()
                            .register_pending(owned.source.clone(), owned.pending.read_pin())?;
                        owned.prepared_origin.verify(lock)?;
                        pair.inspect_effect(
                            &owned.runtime,
                            &owned.supervisor,
                            expected,
                            pair::Effect::MemberStart(shared_slot(owned.intent.slot)),
                            |_| Ok(()),
                        )
                        .map_err(|_| Error::Conflict)?;
                        owned.prepared_origin.verify(lock)
                    },
                )
                .map_err(root_error)
        }
    }

    /// Main's concrete coordinator supplies this permission separately from
    /// protected Pair comparison and original SDK/source reads. No default or
    /// implementation exists here; factual inventory never implements it.
    ///
    /// # Safety
    /// The SAME serialized actor retains the actual guard/endpoint/IPC/network/
    /// row/socket owners through this entire operation, with the exact Calling
    /// supervisor. Start must require original C readiness, full SDK absence,
    /// native key preparation and signed installed capability; reserve Start
    /// must preserve existing bases and active permissions. Stop must freshly
    /// prove Closing stage4/5, permits absent before port release, restored
    /// routes/DNS/weak rows, exact original member, and static bases retained.
    /// This contract includes every MemberOwner/NativeMemberIo internal effect;
    /// neither method may infer permission from these comparison records.
    pub(crate) unsafe trait NativeMemberLifecycle {
        fn authorize_start(
            &mut self,
            context: &Context,
            pair: &PairRecord,
            intent: &Intent,
            window: &NativeBindingsWindow<'_>,
        ) -> Result<()>;
        fn authorize_stop(
            &mut self,
            context: &Context,
            pair: &PairRecord,
            intent: &Intent,
            window: &NativeBindingsWindow<'_>,
        ) -> Result<()>;
        /// Normal Running/Retire(target), exact MemberStop effect, Preparing
        /// ownership and SAME original Source. All permits are withdrawn;
        /// target original probe closed/weak restored/routes removed while
        /// C and active OTHER resources remain owned/live. Not Closing cleanup.
        /// Also recheck the same resources after this controller has retained
        /// and registered its opaque StopACK; typed target history then replaces
        /// only that member's live SDK observation, never the other's.
        /// Mandatory independent native resource grant, no default callback.
        fn authorize_retire(
            &mut self,
            context: &Context,
            pair: &PairRecord,
            intent: &Intent,
            window: &NativeBindingsWindow<'_>,
        ) -> Result<()>;
        /// Exact current Running/Rebind(target)/Preparing/Calling; all permits
        /// absent and all original probes retired, SAME original network/rows
        /// and captured-priority static bases retained. This includes BOTH
        /// held-SCM Stop and restart and independently rechecks postpublication.
        /// No Closing grant, no default, no cold driver/install permission.
        fn authorize_rebind(
            &mut self,
            context: &Context,
            pair: &PairRecord,
            intent: &Intent,
            window: &NativeBindingsWindow<'_>,
        ) -> Result<()>;
        /// Mandatory separate cleanup authorization for an actual enrolled
        /// owner whose Start/read/registration did not return a usable live
        /// reader. No old-live Source window or inferred SDK identity exists.
        /// G must prove exact current Closing/Calling, guards/permits absent,
        /// restored rows and all resource ownership before this owner's Stop.
        /// Unknown native state is NOT an absence fact: final FULL SDK and the
        /// original Closing Source window remain mandatory AFTER its Stop ACK.
        /// No default; main must implement this concrete guard contract.
        fn authorize_partial_stop(
            &mut self,
            context: &Context,
            pair: &PairRecord,
            intent: &Intent,
            original: &Pending,
            service: Option<&Rc<PartialCleanup>>,
        ) -> Result<()>;
    }

    /// Pins live in the same root as the actual owner, not a temporary Start
    /// stack. Dropping an uncertain controller retains this entire bundle.
    struct OwnedMember<G> {
        member: Member,
        pending: Pending,
        partial_cleanup: Option<Rc<PartialCleanup>>,
        context: Context,
        intent: Intent,
        runtime: RuntimeRead,
        source: Rc<MemberSource>,
        carrier: Rc<WintunSource>,
        image: OriginalImage,
        original_source: Rc<NativeSourceRead>,
        inventory: MemberInventoryRead,
        supervisor: Rc<NativeDeadline>,
        gate: Rc<RefCell<G>>,
        prepared_origin: Rc<PreparedMemberOrigin>,
        started_generation: Option<Rc<NativeMemberStartedGeneration>>,
        started_initial: Option<Rc<NativeMemberStartedInitial>>,
        never_effects: Rc<NativeNeverMemberEffects>,
        generation: u64,
        prior: Option<Option<MemberRecord>>,
    }
    pub(crate) struct NativeMemberController<G: NativeMemberLifecycle> {
        root: OperationRoot<OwnedMember<G>, MemberRecord, Reader, Closed>,
        rebinds: Vec<NativeMemberRebindRoot>,
    }
    struct NativeMemberRebindRoot {
        prior: MemberRecord,
        _prior_reader: Reader,
        receipt: Rc<NativeMemberRebindReceipt>,
    }
    pub(crate) type NativeRetiredMemberRoots<G> = RetiredGenerationRoots<
        NativePreparedMember,
        NativeMemberController<G>,
        NativeMemberPreparationGeneration,
    >;

    impl<G: NativeMemberLifecycle> NativeMemberController<G> {
        /// First-generation counterpart: ONLY the actual prepared owner/read,
        /// no replacement ticket or imported generation. Retained before inventory.
        pub(crate) fn started_initial_registration(
            &self,
            never: &Rc<NativeNeverMemberEffects>,
        ) -> Result<Rc<NativeMemberStartedInitial>> {
            let owned = self.root.owner.as_ref().ok_or(Error::Retired)?;
            let token = owned.started_initial.as_ref().ok_or(Error::Pending)?;
            token.verify_initial_original(never, &owned.runtime, &owned.context)?;
            token.verify_source(&owned.original_source)?;
            token.verify_original_read(self.root.reader.as_ref().ok_or(Error::Pending)?)?;
            token.verify_pending_reader(&owned.pending)?;
            Ok(token.clone())
        }
        /// Original token rooted by this controller before fallible inventory
        /// publication. Pure registration, never a Pair-JSON generation claim.
        pub(crate) fn started_generation_registration(
            &self,
            ticket: &Rc<NativeMemberPreparationGeneration>,
            never: &Rc<NativeNeverMemberEffects>,
        ) -> Result<Rc<NativeMemberStartedGeneration>> {
            let owned = self.root.owner.as_ref().ok_or(Error::Retired)?;
            let token = owned.started_generation.as_ref().ok_or(Error::Pending)?;
            token.verify_original(ticket, never, &owned.runtime, &owned.context)?;
            token.verify_original_read(self.root.reader.as_ref().ok_or(Error::Pending)?)?;
            token.verify_pending_reader(&owned.pending)?;
            Ok(token.clone())
        }
        /// Read actual SAME retained service/process/NIC proof, independently
        /// of copied Pair/JSON metadata. No metrics or lifecycle rights issued.
        pub(crate) fn observe_original(
            &mut self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<(Intent, crate::member_owner::NativeProof)> {
            if !self.root.registered || self.root.closed.is_some() {
                return Err(Error::Pending);
            }
            let owned = self.root.owner.as_ref().ok_or(Error::Retired)?;
            let running = self.root.running.as_ref().ok_or(Error::Pending)?;
            let native = owned.forward_read_envelope(pair, expected, lock)?;
            let reader = self.root.reader.as_mut().ok_or(Error::Pending)?;
            let actual = reader.read().map_err(owner_error)?;
            validate_original_observation(&owned.context, expected, running, &actual)?;
            owned
                .original_source
                .inspect_window(|window| {
                    let index = slot_index(owned.intent.slot);
                    if !window.matches_source(&owned.original_source)
                        || !window.matches_runtime(&owned.runtime)
                        || window.closed_member(owned.intent.slot).is_some()
                        || window.bindings().egress[index].as_ref().is_none_or(|i| {
                            i.scope != owned.context.intent.scope || i.proof != actual.1.interface
                        })
                        || window.bindings().carrier.as_ref().map(|c| c.identity.proof)
                            != expected.carrier
                    {
                        return Err(super::super::member_carrier_wintun::Error::Conflict);
                    }
                    Ok(())
                })
                .map_err(|_| Error::Conflict)?;
            if reader.read().map_err(owner_error)? != actual
                || owned.forward_read_envelope(pair, expected, lock)? != native
            {
                return Err(Error::Conflict);
            }
            Ok(actual)
        }
        pub(crate) fn verify(
            &mut self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<()> {
            self.observe_original(pair, expected, lock).map(|_| ())
        }
        /// Absence requires THIS owner's opaque Stop ACK, its actual original
        /// private reader and FULL Source/Closing SDK after publication. Equal
        /// JSON, missing services and lookup/native-interface disappearance deny.
        pub(crate) fn verify_absent(
            &mut self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            closing: Option<&NativeClosingRead>,
            lock: &mut KeyLock,
        ) -> Result<()> {
            if !self.root.closed_registered {
                return Err(Error::Pending);
            }
            let owned = self.root.owner.as_mut().ok_or(Error::Retired)?;
            let receipt = self.root.closed.as_ref().ok_or(Error::Pending)?;
            let envelope = |owned: &OwnedMember<G>, lock: &mut KeyLock| {
                if expected.phase == pair::Phase::Closing {
                    if closing.is_none() {
                        return Err(Error::Conflict);
                    }
                    owned.cleanup_envelope(pair, expected, lock)
                } else {
                    if closing.is_some() {
                        return Err(Error::Conflict);
                    }
                    owned.retirement_envelope(pair, expected, lock)
                }
            };
            envelope(owned, lock)?;
            owned.member.verify_closed(receipt).map_err(owner_error)?;
            let (intent, proof) = if let Some(reader) = self.root.reader.as_mut() {
                reader.read_closed_history(receipt).map_err(owner_error)?
            } else {
                owned
                    .pending
                    .read_closed_proof(receipt)
                    .map_err(owner_error)?
                    .ok_or(Error::Pending)?
            };
            if intent != owned.intent
                || self.root.stopped.as_ref().is_none_or(|r| {
                    r.intent != intent
                        || r.phase != MemberPhase::Stopped
                        || r.retired_proof != Some(proof)
                })
            {
                return Err(Error::Conflict);
            }
            let inspect = |window: &NativeBindingsWindow<'_>| {
                if !window.matches_runtime(&owned.runtime)
                    || window
                        .closed_member(owned.intent.slot)
                        .is_none_or(|h| h.intent != intent || h.proof != proof)
                {
                    return Err(super::super::member_carrier_wintun::Error::Conflict);
                }
                Ok(())
            };
            if let Some(closing) = closing {
                if !closing.matches_source_origin(&owned.original_source) {
                    return Err(Error::Conflict);
                }
                closing
                    .inspect_window(|window| {
                        if !window.matches_closing(closing) {
                            return Err(super::super::member_carrier_wintun::Error::Conflict);
                        }
                        inspect(window)
                    })
                    .map_err(|_| Error::Conflict)?;
            } else {
                owned
                    .original_source
                    .inspect_window(|window| {
                        if !window.matches_source(&owned.original_source) {
                            return Err(super::super::member_carrier_wintun::Error::Conflict);
                        }
                        inspect(window)
                    })
                    .map_err(|_| Error::Conflict)?;
            }
            owned.member.verify_closed(receipt).map_err(owner_error)?;
            envelope(owned, lock)
        }
        /// Attached pending owner that never entered actual MemberOwner Start.
        /// Failed/lost Start ACK is NOT unstarted; private pending reader denies.
        /// Retains all roots, never fabricates a stopped record or close receipt.
        pub(crate) fn verify_unstarted_absent(
            &mut self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            closing: &NativeClosingRead,
            lock: &mut KeyLock,
        ) -> Result<()> {
            self.verify_unstarted_absent_inner(pair, expected, closing, lock)
                .map_err(pending_unknown)
        }
        fn verify_unstarted_absent_inner(
            &mut self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            closing: &NativeClosingRead,
            lock: &mut KeyLock,
        ) -> Result<()> {
            if self.root.running.is_some() || self.root.closed.is_some() {
                return Err(Error::Pending);
            }
            let owned = self.root.owner.as_mut().ok_or(Error::Retired)?;
            if !closing.matches_source_origin(&owned.original_source) {
                return Err(Error::Conflict);
            }
            let envelope = UnstartedEnvelope {
                context: &owned.context,
                runtime: &owned.runtime,
                source: &owned.source,
                carrier: &owned.carrier,
                supervisor: &owned.supervisor,
                intent: &owned.intent,
            };
            let native = envelope.verify(pair, expected, lock)?;
            owned
                .inventory
                .verify_pending_cleanup(&owned.source, &owned.pending)?;
            let before = owned
                .pending
                .read_unstarted_for_cleanup()
                .map_err(owner_error)?;
            if before.0 != owned.intent || owned.prior.as_ref().is_some_and(|p| p != &before.1) {
                return Err(Error::Conflict);
            }
            envelope.inspect_sdk(expected, Some(closing))?;
            owned
                .inventory
                .verify_pending_cleanup(&owned.source, &owned.pending)?;
            if owned
                .pending
                .read_unstarted_for_cleanup()
                .map_err(owner_error)?
                != before
                || envelope.verify(pair, expected, lock)? != native
            {
                return Err(Error::Conflict);
            }
            Ok(())
        }
        /// Actual SAME owner's Stop receipt after fully published normal
        /// Retire. This is NOT inventory/row/key retirement or replacement
        /// permission: caller must root/consume this original in those owners
        /// before moving these old roots and admitting a new slot generation.
        /// Never clears this controller/preparation, and never infers empty on Drop.
        pub(crate) fn closed_generation_receipt(
            &mut self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<Rc<Closed>> {
            if !self.root.completed || !self.root.closed_registered {
                return Err(Error::Pending);
            }
            let stopped = self.root.stopped.as_ref().ok_or(Error::Pending)?;
            let receipt = self.root.closed.as_ref().ok_or(Error::Pending)?;
            let owned = self.root.owner.as_mut().ok_or(Error::Retired)?;
            validate_closed_generation_retirement(&owned.context, expected, stopped)?;
            let native = owned.forward_read_envelope(pair, expected, lock)?;
            owned.member.verify_closed(receipt).map_err(owner_error)?;
            let (intent, proof) = if let Some(reader) = self.root.reader.as_mut() {
                reader.read_closed_history(receipt).map_err(owner_error)?
            } else {
                owned
                    .pending
                    .read_closed_proof(receipt)
                    .map_err(owner_error)?
                    .ok_or(Error::Pending)?
            };
            if intent != owned.intent
                || intent != stopped.intent
                || stopped.retired_proof != Some(proof)
            {
                return Err(Error::Conflict);
            }
            owned
                .original_source
                .inspect_window(|window| {
                    if !window.matches_source(&owned.original_source)
                        || !window.matches_runtime(&owned.runtime)
                        || window.bindings().carrier.as_ref().map(|c| c.identity.proof)
                            != expected.carrier
                        || window
                            .closed_member(owned.intent.slot)
                            .is_none_or(|h| h.intent != intent || h.proof != proof)
                    {
                        return Err(super::super::member_carrier_wintun::Error::Conflict);
                    }
                    let other_index = 1 - slot_index(owned.intent.slot);
                    if window.bindings().egress[other_index]
                        .as_ref()
                        .map(|m| m.proof)
                        != expected.members[other_index]
                            .as_ref()
                            .and_then(|m| m.owner.proof.map(|p| p.interface))
                    {
                        return Err(super::super::member_carrier_wintun::Error::Conflict);
                    }
                    Ok(())
                })
                .map_err(|_| Error::Conflict)?;
            owned.member.verify_closed(receipt).map_err(owner_error)?;
            if owned.forward_read_envelope(pair, expected, lock)? != native {
                return Err(Error::Conflict);
            }
            Ok(receipt.clone())
        }
        /// Genuine original Stop-bound readonly preparation generation. Keep
        /// ACK first, retry ONLY its SAME Rc. No inventory/rows/key/native grant.
        pub(crate) fn retire_preparation_generation(
            &mut self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<Rc<NativeMemberPreparationGeneration>> {
            self.retire_preparation_generation_inner(pair, expected, lock)
                .map_err(pending_unknown)
        }
        fn retire_preparation_generation_inner(
            &mut self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<Rc<NativeMemberPreparationGeneration>> {
            let receipt = self.closed_generation_receipt(pair, expected, lock)?;
            let owned = self.root.owner.as_mut().ok_or(Error::Retired)?;
            let effects = &owned.never_effects;
            let mut retired = effects
                .retired
                .try_borrow_mut()
                .map_err(|_| Error::Conflict)?;
            if let Some(ticket) = retired.iter().find(|t| Rc::ptr_eq(&t.receipt, &receipt)) {
                if ticket.old != owned.generation
                    || ticket.slot != owned.intent.slot
                    || !ticket.acknowledged.get()
                {
                    return Err(Error::Pending);
                }
                if let Some(reader) = self.root.reader.as_ref() {
                    ticket.verify_retired_original_read(reader)?;
                } else {
                    ticket.verify_pending_reader(&owned.pending)?;
                }
                return Ok(ticket.clone());
            }
            retired.try_reserve(1).map_err(|_| Error::Pending)?;
            let before = owned.forward_read_envelope(pair, expected, lock)?;
            let retired_original = owned
                .member
                .seal_closed_generation(&receipt)
                .map_err(owner_error)?;
            if owned.forward_read_envelope(pair, expected, lock)? != before {
                return Err(Error::Conflict);
            }
            let ticket = Rc::new(NativeMemberPreparationGeneration {
                receipt,
                retired_original,
                stopped: self.root.stopped.as_ref().ok_or(Error::Pending)?.clone(),
                source: PreparedSourceRegistration::from_original(&owned.original_source),
                context: owned.context.clone(),
                original: PreparedSourceRegistration::from_original(effects),
                slot: owned.intent.slot,
                old: owned.generation,
                next: owned.generation.checked_add(1).ok_or(Error::Pending)?,
                acknowledged: std::cell::Cell::new(false),
            });
            retired.push(ticket.clone()); // SAME opaque original retained first.
            let next = effects
                .history
                .retire_generation(slot_index(owned.intent.slot), owned.generation)?;
            if next != ticket.next {
                return Err(Error::Conflict);
            }
            ticket.acknowledged.set(true);
            if let Some(reader) = self.root.reader.as_ref() {
                ticket.verify_retired_original_read(reader)?;
            } else {
                ticket.verify_pending_reader(&owned.pending)?;
            }
            Ok(ticket)
        }
        /// Actual native ACK stage only, NOT Pair effect completion. Actor must
        /// publish rebind_readers through SAME inventory and call complete_rebind
        /// before returning a Running record. ACK/read roots precede postflight.
        pub(crate) fn rebind(
            &mut self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<Rc<NativeMemberRebindReceipt>> {
            self.rebind_inner(pair, expected, lock)
                .map_err(pending_unknown)
        }
        fn rebind_inner(
            &mut self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<Rc<NativeMemberRebindReceipt>> {
            let owned = self.root.owner.as_mut().ok_or(Error::Retired)?;
            validate_rebind_operation(&owned.context, expected, &owned.intent)?;
            owned.forward_read_envelope(pair, expected, lock)?;
            if let Some(ack) = self.rebinds.last() {
                if expected.members[slot_index(owned.intent.slot)]
                    .as_ref()
                    .map(|m| &m.owner)
                    == Some(&ack.prior)
                {
                    owned
                        .member
                        .verify_rebind_receipt(&ack.receipt)
                        .map_err(owner_error)?;
                    return Ok(ack.receipt.clone()); // SAME original ACK retry, no second native effects.
                }
            }
            if !self.root.registered || self.root.closed.is_some() || self.root.reader.is_none() {
                return Err(Error::Pending);
            }
            self.rebinds.try_reserve(1).map_err(|_| Error::Pending)?;
            let prior = self.root.running.as_ref().ok_or(Error::Pending)?.clone();
            self.verify(pair, expected, lock)?;
            let owned = self.root.owner.as_mut().ok_or(Error::Retired)?;
            owned.rebind_envelope(pair, expected, lock)?;
            let (running, receipt, reader) =
                owned.member.rebind_original(&prior).map_err(owner_error)?;
            let old_reader = self
                .root
                .reader
                .replace(reader)
                .expect("original reader checked before effects");
            self.root.running = Some(running);
            self.rebinds.push(NativeMemberRebindRoot {
                prior: prior.clone(),
                _prior_reader: old_reader,
                receipt: receipt.clone(),
            });
            // The SAME native ACK/new reader now remain rooted through EVERY
            // fallible pending-reader creation, inventory registration and G.
            validate_rebound_record(&owned.context, expected, &prior, receipt.running_record())?;
            owned.pending = owned
                .member
                .pending_rebind_read(&receipt)
                .map_err(owner_error)?;
            owned.forward_read_envelope(pair, expected, lock)?;
            Ok(receipt)
        }
        /// Invoke outside inventory/Source callbacks under whole actual Calling.
        pub(crate) fn rebind_readers(
            &mut self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            receipt: &Rc<NativeMemberRebindReceipt>,
            lock: &mut KeyLock,
        ) -> Result<NativeMemberRebindReads> {
            self.rebind_readers_inner(pair, expected, receipt, lock)
                .map_err(pending_unknown)
        }
        fn rebind_readers_inner(
            &mut self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            receipt: &Rc<NativeMemberRebindReceipt>,
            lock: &mut KeyLock,
        ) -> Result<NativeMemberRebindReads> {
            let owned = self.root.owner.as_mut().ok_or(Error::Retired)?;
            self.rebinds
                .last()
                .filter(|root| Rc::ptr_eq(&root.receipt, receipt))
                .ok_or(Error::Conflict)?;
            validate_rebind_operation(&owned.context, expected, &owned.intent)?;
            owned.forward_read_envelope(pair, expected, lock)?;
            owned
                .member
                .verify_rebind_receipt(receipt)
                .map_err(owner_error)?;
            let reader = owned.member.original_read().map_err(owner_error)?;
            let pending = owned
                .member
                .pending_rebind_read(receipt)
                .map_err(owner_error)?;
            receipt
                .verify_replacement_original_read(&reader)
                .map_err(owner_error)?;
            receipt
                .verify_replacement_pending_read(&pending)
                .map_err(owner_error)?;
            owned.forward_read_envelope(pair, expected, lock)?;
            Ok((reader, pending))
        }
        /// Mandatory postpublication SAME Source/full SDK/resource G. Old
        /// inventory readers remain stale, so unregistered renewal fails closed.
        pub(crate) fn complete_rebind(
            &mut self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            receipt: &Rc<NativeMemberRebindReceipt>,
            lock: &mut KeyLock,
        ) -> Result<MemberRecord> {
            self.complete_rebind_inner(pair, expected, receipt, lock)
                .map_err(pending_unknown)
        }
        fn complete_rebind_inner(
            &mut self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            receipt: &Rc<NativeMemberRebindReceipt>,
            lock: &mut KeyLock,
        ) -> Result<MemberRecord> {
            let owned = self.root.owner.as_mut().ok_or(Error::Retired)?;
            let root = self
                .rebinds
                .last()
                .filter(|r| Rc::ptr_eq(&r.receipt, receipt))
                .ok_or(Error::Conflict)?;
            validate_rebound_record(
                &owned.context,
                expected,
                &root.prior,
                receipt.running_record(),
            )?;
            owned
                .member
                .verify_rebind_receipt(receipt)
                .map_err(owner_error)?;
            let reader = self.root.reader.as_mut().ok_or(Error::Pending)?;
            receipt
                .verify_replacement_original_read(reader)
                .map_err(owner_error)?;
            let facts = reader.read().map_err(owner_error)?;
            if facts
                != (
                    owned.intent.clone(),
                    receipt.running_record().proof.ok_or(Error::Pending)?,
                )
            {
                return Err(Error::Conflict);
            }
            owned.rebind_envelope(pair, expected, lock)?;
            owned
                .member
                .verify_rebind_receipt(receipt)
                .map_err(owner_error)?;
            if reader.read().map_err(owner_error)? != facts {
                return Err(Error::Conflict);
            }
            owned.forward_read_envelope(pair, expected, lock)?;
            Ok(receipt.running_record().clone()) // DATA backed by this rooted original ACK, not adoption.
        }
        pub(crate) fn retained_stopped(&self) -> Option<&MemberRecord> {
            self.root.stopped.as_ref()
        }
        pub(crate) fn prepared_intent(&self) -> &Intent {
            &self
                .root
                .owner
                .as_ref()
                .expect("retained member owner")
                .intent
        }
        /// Called INSIDE the SAME supervisor.run_intent Calling operation.
        /// The native typed receipt is borrowed from the caller's SAME actual
        /// NativeOwnership; it cannot be reconstructed from Pair JSON.
        /// Independent A/B reattestation reads the original disabled HKEY.
        pub(crate) fn start(
            &mut self,
            pair_read: &NativePairIntentRead,
            expected: &PairRecord,
            receipt: Receipt<'_>,
            prior: Option<&MemberRecord>,
        ) -> Result<MemberRecord> {
            self.start_inner(pair_read, expected, receipt, prior)
                .map_err(pending_unknown)
        }
        fn start_inner(
            &mut self,
            pair_read: &NativePairIntentRead,
            expected: &PairRecord,
            receipt: Receipt<'_>,
            prior: Option<&MemberRecord>,
        ) -> Result<MemberRecord> {
            let owner = self.root.owner.as_ref().ok_or(Error::Retired)?;
            if owner
                .prior
                .as_ref()
                .is_some_and(|actual| actual.as_ref() != prior)
            {
                return Err(Error::Conflict);
            }
            let context = owner.context.clone();
            let runtime = owner.runtime.read_pin()?;
            let source = owner.source.clone();
            let original_source = owner.original_source.clone();
            let supervisor = owner.supervisor.clone();
            let mut inventory = owner.inventory.read_pin();
            self.root.start(
                |owned| {
                    owned.start_preflight(pair_read, expected, receipt)?;
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step("member start preflight complete");
                    owned.never_effects.history.start(slot_index(owned.intent.slot), owned.generation)?;
                    // Real service/process path, never a successful stub.
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step("member start native begin");
                    let result = owned.member.start_with_prior(prior).map_err(owner_error);
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step("member start native returned");
                    result
                },
                |owned| {
                    let reader = owned.member.original_read().map_err(owner_error)?;
                    owned.root_started_generation(&reader)?;
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step("member start generation rooted");
                    Ok(reader)
                },
                |owned, rooted_reader| {
                    let (intent, _) = rooted_reader.read().map_err(owner_error)?;
                    owned.runtime.verify_member_intent(&owned.context, &owned.source, &intent)?;
                    // Retain FIRST original reader before acquiring/transferring
                    // a second SAME-owner read to fallible inventory registration.
                    let inventory_reader = owned.member.original_read().map_err(owner_error)?;
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step("member start inventory register begin");
                    let result = inventory.register(owned.source.clone(), inventory_reader);
                    #[cfg(test)]
                    super::super::member_carrier_factory_test_os::trace_step("member start inventory register returned");
                    result
                },
                |running, rooted_reader| {
                    if running.phase != MemberPhase::Running || running.proof.is_none()
                        || rooted_reader.read().map_err(owner_error)? != (running.intent.clone(), running.proof.ok_or(Error::Conflict)?) {
                        return Err(Error::Conflict);
                    }
                    runtime.verify_member_intent(&context, &source, &running.intent)?;
                    pair_read.inspect_effect(&runtime, &supervisor, expected,
                        pair::Effect::MemberStart(shared_slot(running.intent.slot)), |_| {
                            #[cfg(test)]
                            super::super::member_carrier_factory_test_os::trace_step("member start source postflight begin");
                            let result = original_source.inspect_window(|window| {
                                if !window.matches_source(&original_source) || !window.matches_runtime(&runtime) {
                                    return Err(super::super::member_carrier_wintun::Error::Conflict);
                                }
                                Ok(())
                            }).map_err(io_error);
                            #[cfg(test)]
                            super::super::member_carrier_factory_test_os::trace_step("member start source postflight returned");
                            result
                        }).map_err(|_| Error::Conflict)
                },
            ).map_err(root_error)?;
            self.root.running.clone().ok_or(Error::Pending)
        }

        /// Closing comparison uses the actual original C read and SAME lock;
        /// RetainedMember.stop issues the sole opaque receipt. It and Stopped
        /// are rooted before closed registration, source reads or Pair postflight.
        pub(crate) fn stop(
            &mut self,
            pair_read: &NativePairIntentRead,
            expected: &PairRecord,
            closing: &NativeClosingRead,
            lock: &mut KeyLock,
        ) -> Result<MemberRecord> {
            self.stop_inner(pair_read, expected, closing, lock)
                .map_err(pending_unknown)
        }
        /// Normal standby retirement INSIDE the SAME Calling operation. This
        /// never creates/selects a Closing pin or retires the other member.
        /// Actual Stop ACK/read/owner roots are shared with full cleanup so an
        /// Err/unwind can still reconcile the SAME owner in later Closing.
        pub(crate) fn retire(
            &mut self,
            pair_read: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<MemberRecord> {
            self.retire_inner(pair_read, expected, lock)
                .map_err(pending_unknown)
        }
        fn retire_inner(
            &mut self,
            pair_read: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<MemberRecord> {
            if !self.root.registered {
                return Err(Error::Pending);
            }
            let had_closed = self.root.closed.is_some();
            let owned = self.root.owner.as_mut().ok_or(Error::Retired)?;
            owned.retirement_envelope(pair_read, expected, lock)?;
            if !had_closed {
                owned.retirement_preflight(pair_read, expected, lock)?;
            }
            let mut inventory = owned.inventory.read_pin();
            let supervisor = owned.supervisor.clone();
            let index = slot_index(owned.intent.slot);
            self.root
                .stop(
                    |owned| {
                        let current = owned
                            .member
                            .snapshot()
                            .map_err(owner_error)?
                            .ok_or(Error::Pending)?;
                        if Some(&current) != expected.members[index].as_ref().map(|m| &m.owner) {
                            return Err(Error::Conflict);
                        }
                        // The private SAME owner, not an imported/equal JSON owner.
                        owned.member.stop(&current).map_err(owner_error)
                    },
                    |receipt| {
                        inventory.closed_retirement(
                            index,
                            receipt,
                            pair_read,
                            expected,
                            &supervisor,
                        )
                    },
                    |stopped, receipt, (owned, reader)| {
                        owned.member.verify_closed(receipt).map_err(owner_error)?;
                        let (actual_intent, actual_proof) = reader
                            .ok_or(Error::Pending)?
                            .read_closed_history(receipt)
                            .map_err(owner_error)?;
                        if stopped.phase != MemberPhase::Stopped
                            || stopped.intent != owned.intent
                            || actual_intent != owned.intent
                        {
                            return Err(Error::Conflict);
                        }
                        owned.retirement_envelope(pair_read, expected, lock)?;
                        // Source brackets C + LIVE SDK inputs and separately
                        // authenticates typed closed history. Never call full_universe
                        // with the target's old provider, nor borrow inventory here.
                        owned
                            .original_source
                            .inspect_window(|window| {
                                if !window.matches_source(&owned.original_source)
                                    || !window.matches_runtime(&owned.runtime)
                                {
                                    return Err(
                                        super::super::member_carrier_wintun::Error::Conflict,
                                    );
                                }
                                let history = window
                                    .closed_member(owned.intent.slot)
                                    .ok_or(super::super::member_carrier_wintun::Error::Conflict)?;
                                validate_retirement_history(
                                    &owned.context,
                                    expected,
                                    &owned.intent,
                                    history,
                                )
                                .map_err(|_| {
                                    super::super::member_carrier_wintun::Error::Conflict
                                })?;
                                if history.proof != actual_proof
                                    || window
                                        .closed_member(if index == 0 {
                                            TunnelSlot::B
                                        } else {
                                            TunnelSlot::A
                                        })
                                        .is_some()
                                    || window.bindings().carrier.as_ref().map(|c| c.identity.proof)
                                        != expected.carrier
                                    || window.bindings().egress.iter().zip(&expected.members).any(
                                        |(i, m)| {
                                            i.as_ref().is_none_or(|i| {
                                                i.scope != expected.scope
                                                    || Some(i.proof)
                                                        != m.as_ref().and_then(|m| {
                                                            m.owner.proof.map(|p| p.interface)
                                                        })
                                            })
                                        },
                                    )
                                {
                                    return Err(
                                        super::super::member_carrier_wintun::Error::Conflict,
                                    );
                                }
                                owned
                                    .gate
                                    .try_borrow_mut()
                                    .map_err(|_| {
                                        super::super::member_carrier_wintun::Error::Conflict
                                    })?
                                    .authorize_retire(
                                        &owned.context,
                                        expected,
                                        &owned.intent,
                                        window,
                                    )
                                    .map_err(|_| {
                                        super::super::member_carrier_wintun::Error::Conflict
                                    })
                            })
                            .map_err(|_| Error::Conflict)?;
                        owned.retirement_envelope(pair_read, expected, lock)
                    },
                )
                .map_err(root_error)?;
            self.root.stopped.clone().ok_or(Error::Pending)
        }
        fn stop_inner(
            &mut self,
            pair_read: &NativePairIntentRead,
            expected: &PairRecord,
            closing: &NativeClosingRead,
            lock: &mut KeyLock,
        ) -> Result<MemberRecord> {
            let owned = self.root.owner.as_mut().ok_or(Error::Retired)?;
            let context = owned.context.clone();
            let runtime = owned.runtime.read_pin()?;
            let source = owned.source.clone();
            let index = slot_index(owned.intent.slot);
            let mut inventory = owned.inventory.read_pin();
            // Reconciliation still reauthenticates current Closing before any
            // registration, including when the SAME native Stop ACK is rooted.
            if self.root.closed.is_some() {
                // No new native effect: republish only our rooted SAME Stop ACK.
                // A Closing full inventory cannot precede this republish: its
                // old live entry may already be absent after a lost register ACK.
                owned.cleanup_envelope(pair_read, expected, lock)?;
            } else if !self.root.registered
                || expected.members[index]
                    .as_ref()
                    .is_some_and(|m| m.owner.proof.is_none())
            {
                owned.partial_stop_preflight(pair_read, expected, lock)?;
            } else {
                owned.stop_preflight(pair_read, expected, closing, lock)?;
            }
            self.root
                .stop(
                    |owned| {
                        // Snapshot is read from THIS actual owner, not adopted from
                        // imported/equal JSON. Allows its own uncertain Stop ACK to
                        // reconcile Stopping/Stopped via RetainedMember.stop.
                        let current = owned
                            .member
                            .snapshot()
                            .map_err(owner_error)?
                            .ok_or(Error::Pending)?;
                        if current.intent != owned.intent {
                            return Err(Error::Conflict);
                        }
                        if let Some(original) = &owned.partial_cleanup {
                            owned
                                .member
                                .stop_partial_original(&current, original)
                                .map_err(owner_error)
                        } else {
                            owned.member.stop(&current).map_err(owner_error)
                        }
                    },
                    |receipt| inventory.closed(index, receipt),
                    |stopped, receipt, (owned, reader)| {
                        owned.member.verify_closed(receipt).map_err(owner_error)?;
                        if let Some(reader) = reader {
                            reader.verify_closed(receipt).map_err(owner_error)?;
                        }
                        if stopped.phase != MemberPhase::Stopped
                            || stopped.intent.scope != context.intent.scope
                        {
                            return Err(Error::Conflict);
                        }
                        runtime.verify_member_intent(&context, &source, &stopped.intent)?;
                        owned.cleanup_envelope(pair_read, expected, lock)?;
                        closing
                            .inspect_window(|window| {
                                if !window.matches_closing(closing)
                                    || !window.matches_runtime(&runtime)
                                {
                                    return Err(
                                        super::super::member_carrier_wintun::Error::Conflict,
                                    );
                                }
                                // Closing already brackets C+LIVE full SDK and
                                // separately original Closed ACKs. Do not feed old
                                // history to SDK or recursively borrow inventory.
                                Ok(())
                            })
                            .map_err(|_| Error::Conflict)?;
                        owned.cleanup_envelope(pair_read, expected, lock)
                    },
                )
                .map_err(root_error)?;
            self.root.stopped.clone().ok_or(Error::Pending)
        }
    }

    impl<G: NativeMemberLifecycle> OwnedMember<G> {
        fn root_started_generation(&mut self, reader: &Reader) -> Result<()> {
            let origin = &self.prepared_origin;
            let Some(ticket) = origin.replacement.as_ref() else {
                if self.generation != 1 {
                    return Err(Error::Pending);
                }
                if self.started_initial.is_none() {
                    self.started_initial = Some(Rc::new(NativeMemberStartedInitial {
                        lineage: InitialStartedOrigin::from_original(origin, &self.original_source),
                        registration: reader.registration().map_err(owner_error)?,
                        acknowledged: std::cell::Cell::new(false),
                    })); // Root actual initial original BEFORE inventory/postflight.
                    #[cfg(test)]
                    self.started_initial
                        .as_ref()
                        .expect("retained initial member")
                        .registration
                        .observe_native_factory_root();
                }
                let token = self.started_initial.as_ref().ok_or(Error::Pending)?;
                if self.context != origin.context
                    || self.intent != origin.intent
                    || self.generation != origin.generation
                {
                    return Err(Error::Conflict);
                }
                token.lineage.verify(origin, &self.original_source)?;
                token.verify_lineage(&self.never_effects, &self.runtime, &self.context)?;
                token
                    .registration
                    .verify_original_read(reader)
                    .map_err(owner_error)?;
                token
                    .registration
                    .verify_pending_read(&self.pending)
                    .map_err(owner_error)?;
                token.acknowledged.set(true);
                return Ok(());
            };
            if self.started_generation.is_none() {
                self.started_generation = Some(Rc::new(NativeMemberStartedGeneration {
                    origin: origin.clone(),
                    ticket: ticket.clone(),
                    registration: reader.registration().map_err(owner_error)?,
                    acknowledged: std::cell::Cell::new(false),
                })); // Actual lineage retained FIRST, before fallible validation/publication.
            }
            let token = self.started_generation.as_ref().ok_or(Error::Pending)?;
            if !Rc::ptr_eq(&token.origin, origin)
                || self.context != origin.context
                || self.intent != origin.intent
                || self.generation != origin.generation
            {
                return Err(Error::Conflict);
            }
            token.verify_lineage(ticket, &self.never_effects, &self.runtime, &self.context)?;
            token
                .registration
                .verify_original_read(reader)
                .map_err(owner_error)?;
            token
                .registration
                .verify_pending_read(&self.pending)
                .map_err(owner_error)?;
            token.acknowledged.set(true);
            Ok(())
        }
        fn rebind_envelope(
            &self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<()> {
            validate_rebind_operation(&self.context, expected, &self.intent)?;
            let before = self.forward_read_envelope(pair, expected, lock)?;
            let effect = expected.pending.ok_or(Error::Conflict)?;
            pair.inspect_effect(
                &self.runtime,
                &self.supervisor,
                expected,
                effect,
                |_| Ok(()),
            )
            .map_err(|_| Error::Conflict)?;
            self.original_source
                .inspect_window(|window| {
                    if !window.matches_source(&self.original_source)
                        || !window.matches_runtime(&self.runtime)
                        || window.closed_member(self.intent.slot).is_some()
                        || window.bindings().carrier.as_ref().map(|c| c.identity.proof)
                            != expected.carrier
                        || window.bindings().egress[slot_index(self.intent.slot)]
                            .as_ref()
                            .map(|m| m.proof)
                            != expected.members[slot_index(self.intent.slot)]
                                .as_ref()
                                .and_then(|m| m.owner.proof.map(|p| p.interface))
                    {
                        return Err(super::super::member_carrier_wintun::Error::Conflict);
                    }
                    self.gate
                        .try_borrow_mut()
                        .map_err(|_| super::super::member_carrier_wintun::Error::Conflict)?
                        .authorize_rebind(&self.context, expected, &self.intent, window)
                        .map_err(|_| super::super::member_carrier_wintun::Error::Conflict)
                })
                .map_err(|_| Error::Conflict)?;
            pair.inspect_effect(
                &self.runtime,
                &self.supervisor,
                expected,
                effect,
                |_| Ok(()),
            )
            .map_err(|_| Error::Conflict)?;
            if self.forward_read_envelope(pair, expected, lock)? != before {
                return Err(Error::Conflict);
            }
            Ok(())
        }
        fn forward_read_envelope(
            &self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<Vec<u8>> {
            self.verify_sources()?;
            let deadline = self.supervisor.read_pin().map_err(|_| Error::Conflict)?;
            deadline
                .verify_runtime_call(&self.supervisor, &self.runtime, &self.context)
                .map_err(|_| Error::Conflict)?;
            let bytes = self
                .runtime
                .record(&self.context, RecordKind::NativeCarrierReceipts)?;
            let native = keys_record::Record::decode(&bytes)?;
            keys_record::validate_record(&native)?;
            if !self.runtime.matches_lock(lock)
                || !self.runtime.fresh(&self.context)?
                || native.context != self.context
                || native.generation == 0
                || native.phase != Phase::Preparing
            {
                return Err(Error::Conflict);
            }
            pair.inspect(&self.runtime, &self.supervisor, |actual| {
                if actual != expected {
                    return Err(io_error(Error::Conflict));
                }
                Ok(())
            })
            .map_err(|_| Error::Conflict)?;
            if !self.runtime.matches_lock(lock)
                || self
                    .runtime
                    .record(&self.context, RecordKind::NativeCarrierReceipts)?
                    != bytes
            {
                return Err(Error::Conflict);
            }
            self.verify_sources()?;
            deadline
                .verify_call(&self.supervisor, &self.context)
                .map_err(|_| Error::Conflict)?;
            Ok(bytes)
        }
        fn retirement_envelope(
            &self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<()> {
            self.verify_sources()?;
            validate_member_operation(
                &self.context,
                expected,
                &self.intent,
                MemberOperation::Retire,
            )?;
            let bytes = self
                .runtime
                .record(&self.context, RecordKind::NativeCarrierReceipts)?;
            let native = keys_record::Record::decode(&bytes)?;
            keys_record::validate_record(&native)?;
            if !self.runtime.matches_lock(lock)
                || !pair.matches_runtime(&self.runtime)
                || native.context != self.context
                || native.generation == 0
                || native.phase != Phase::Preparing
                || !self.runtime.fresh(&self.context)?
            {
                return Err(Error::Conflict);
            }
            pair.inspect_effect(
                &self.runtime,
                &self.supervisor,
                expected,
                pair::Effect::MemberStop(shared_slot(self.intent.slot)),
                |_| Ok(()),
            )
            .map_err(|_| Error::Conflict)?;
            if !self.runtime.matches_lock(lock)
                || self
                    .runtime
                    .record(&self.context, RecordKind::NativeCarrierReceipts)?
                    != bytes
            {
                return Err(Error::Conflict);
            }
            self.verify_sources()
        }
        fn retirement_preflight(
            &mut self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<()> {
            self.retirement_envelope(pair, expected, lock)?;
            let index = slot_index(self.intent.slot);
            let current = self
                .member
                .snapshot()
                .map_err(owner_error)?
                .ok_or(Error::Pending)?;
            if Some(&current) != expected.members[index].as_ref().map(|m| &m.owner) {
                return Err(Error::Conflict);
            }
            // Pair callback has ended. G may independently reauthenticate it;
            // no inventory borrow is held when Source or joined readers sample.
            self.original_source
                .inspect_window(|window| {
                    if !window.matches_source(&self.original_source)
                        || !window.matches_runtime(&self.runtime)
                        || [TunnelSlot::A, TunnelSlot::B]
                            .into_iter()
                            .any(|s| window.closed_member(s).is_some())
                    {
                        return Err(super::super::member_carrier_wintun::Error::Conflict);
                    }
                    self.gate
                        .try_borrow_mut()
                        .map_err(|_| super::super::member_carrier_wintun::Error::Conflict)?
                        .authorize_retire(&self.context, expected, &self.intent, window)
                        .map_err(|_| super::super::member_carrier_wintun::Error::Conflict)
                })
                .map_err(|_| Error::Conflict)?;
            self.retirement_envelope(pair, expected, lock)
        }
        fn partial_stop_preflight(
            &mut self,
            pair: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<()> {
            self.cleanup_envelope(pair, expected, lock)?;
            self.inventory
                .verify_pending_cleanup(&self.source, &self.pending)?;
            if self.partial_cleanup.is_none() {
                self.partial_cleanup = Some(Rc::new(
                    self.pending.partial_cleanup().map_err(owner_error)?,
                ));
            } // Retain actual original BEFORE any fallible native/G/Source read.
            let original = self.partial_cleanup.as_ref().ok_or(Error::Pending)?;
            original
                .verify_pending_original(&self.pending)
                .map_err(owner_error)?;
            self.gate
                .try_borrow_mut()
                .map_err(|_| Error::Conflict)?
                .authorize_partial_stop(
                    &self.context,
                    expected,
                    &self.intent,
                    &self.pending,
                    Some(original),
                )?;
            self.inventory
                .verify_pending_cleanup(&self.source, &self.pending)?;
            self.cleanup_envelope(pair, expected, lock)
        }
        fn verify_sources(&self) -> Result<()> {
            self.member
                .verify_readonly_native_profile()
                .map_err(owner_error)?;
            self.verify_source_roots()?;
            self.member
                .verify_readonly_native_profile()
                .map_err(owner_error)
        }
        fn verify_source_roots(&self) -> Result<()> {
            self.runtime
                .verify_member_intent(&self.context, &self.source, &self.intent)?;
            if !self.source.matches_carrier(&self.carrier)
                || !self.image.matches_source(&self.carrier)
            {
                return Err(Error::Conflict);
            }
            self.inventory
                .matches_original_runtime_image(&self.runtime, &self.image)
        }

        fn reattest_initial_wireguard_package(
            &self,
            pair_read: &NativePairIntentRead,
            expected: &PairRecord,
            receipt: &Receipt<'_>,
            native: &keys_record::Record,
        ) -> Result<()> {
            // Live Attach is NOT a cold device-universe observation. Its full
            // original-owned backend lifecycle/SDK gate remains mandatory.
            if expected.phase != pair::Phase::Starting
                || self.intent.transport != nelomai_client_tunnel::TunnelTransport::WireGuard
            {
                return Ok(());
            }
            let origin = &self.prepared_origin;
            if origin.intent != self.intent
                || !origin.runtime.same_original_runtime(&self.runtime)
                || !Rc::ptr_eq(&origin.source, &self.source)
            {
                return Err(Error::Conflict);
            }
            origin
                .cold_wireguard_package
                .try_borrow_mut()
                .map_err(|_| Error::Pending)?
                .verify_existing(
                    || {
                        origin.verify(receipt.mutation_lock)?;
                        self.verify_sources()?;
                        pair_read
                            .inspect_effect(
                                &self.runtime,
                                &self.supervisor,
                                expected,
                                pair::Effect::MemberStart(shared_slot(self.intent.slot)),
                                |_| Ok(()),
                            )
                            .map_err(|_| Error::Conflict)?;
                        // Pair borrow is released before any package native queries.
                        let current = keys_record::Record::decode(
                            &self
                                .runtime
                                .record(&self.context, RecordKind::NativeCarrierReceipts)?,
                        )?;
                        if current != *native {
                            return Err(Error::Conflict);
                        }
                        origin.verify(receipt.mutation_lock)
                    },
                    |package| {
                        if !package.matches_original(&self.source, &self.carrier) {
                            return Err(Error::Conflict);
                        }
                        package.reattest_cold().map_err(|_| Error::Pending)
                    },
                    Error::Pending,
                )
                .map_err(|error| match error {
                    ColdPackageError::Retired => Error::Retired,
                    ColdPackageError::Boundary(error) => pending_unknown(error),
                })
        }

        fn start_preflight(
            &self,
            pair_read: &NativePairIntentRead,
            expected: &PairRecord,
            receipt: Receipt<'_>,
        ) -> Result<()> {
            self.verify_sources()?;
            if let Some(ticket) = &self.prepared_origin.replacement {
                ticket.verify_original(&self.never_effects, &self.runtime, &self.context)?;
                ticket.verify_source(&self.original_source)?;
                validate_replacement_prior(
                    &self.context,
                    &self.intent,
                    &ticket.stopped,
                    self.prior.as_ref().and_then(Option::as_ref),
                )?;
            }
            validate_member_operation(
                &self.context,
                expected,
                &self.intent,
                MemberOperation::Start,
            )?;
            let index = slot_index(self.intent.slot);
            let native = keys_record::Record::decode(
                &self
                    .runtime
                    .record(&self.context, RecordKind::NativeCarrierReceipts)?,
            )?;
            if !self.runtime.matches_lock(receipt.mutation_lock)
                || !pair_read.matches_runtime(&self.runtime)
            {
                return Err(Error::Conflict);
            }
            validate_member_precreation(
                &self.context,
                &native,
                receipt.record,
                receipt.binding,
                self.intent.slot,
            )?;
            // Read the SAME original live tuple, releasing its inventory borrow
            // BEFORE Source/G. That Source bracket independently joins the full
            // native census; exact target absence is still checked below.
            let (members, _) =
                self.inventory
                    .read_source_bindings(&self.context, &self.runtime, &self.image)?;
            pair_read
                .inspect_effect(
                    &self.runtime,
                    &self.supervisor,
                    expected,
                    pair::Effect::MemberStart(shared_slot(self.intent.slot)),
                    |_| Ok(()),
                )
                .map_err(|_| Error::Conflict)?;
            self.reattest_initial_wireguard_package(pair_read, expected, &receipt, &native)?;
            // G reauthenticates this SAME Pair and inspects this SAME Source
            // window. Do not hold a Pair or inventory callback across G.
            self.original_source
                .inspect_window(|window| {
                    if !window.matches_source(&self.original_source)
                        || !window.matches_runtime(&self.runtime)
                        || window.bindings().egress[index].is_some()
                    {
                        return Err(super::super::member_carrier_wintun::Error::Conflict);
                    }
                    let inspect = || -> Result<()> {
                        let wants = full_universe(&self.context, window.bindings(), &members)?;
                        provider::native::inspect_mixed_absent(
                            &wants,
                            receipt.binding.guid,
                            &receipt.binding.name,
                        )
                        .map_err(|_| Error::Conflict)?;
                        keys::reattest_disabled_original_member_key(
                            &mut win32::Kernel,
                            receipt.record,
                            &self.context,
                            receipt.binding,
                            native.generation,
                            receipt.new_key_ack,
                        )?;
                        self.gate
                            .try_borrow_mut()
                            .map_err(|_| Error::Conflict)?
                            .authorize_start(&self.context, expected, &self.intent, window)
                    };
                    inspect().map_err(|_| super::super::member_carrier_wintun::Error::Conflict)
                })
                .map_err(|_| Error::Conflict)?;
            pair_read
                .inspect_effect(
                    &self.runtime,
                    &self.supervisor,
                    expected,
                    pair::Effect::MemberStart(shared_slot(self.intent.slot)),
                    |_| Ok(()),
                )
                .map_err(|_| Error::Conflict)?;
            self.verify_sources()?;
            if !self.runtime.matches_lock(receipt.mutation_lock)
                || keys_record::Record::decode(
                    &self
                        .runtime
                        .record(&self.context, RecordKind::NativeCarrierReceipts)?,
                )? != native
            {
                return Err(Error::Conflict);
            }
            Ok(())
        }
        fn stop_preflight(
            &self,
            pair_read: &NativePairIntentRead,
            expected: &PairRecord,
            closing: &NativeClosingRead,
            lock: &mut KeyLock,
        ) -> Result<()> {
            self.cleanup_envelope(pair_read, expected, lock)?;
            self.verify_sources()?;
            validate_member_operation(
                &self.context,
                expected,
                &self.intent,
                MemberOperation::Stop,
            )?;
            let index = slot_index(self.intent.slot);
            let native = keys_record::Record::decode(
                &self
                    .runtime
                    .record(&self.context, RecordKind::NativeCarrierReceipts)?,
            )?;
            if !self.runtime.matches_lock(lock)
                || native.context != self.context
                || native.phase != Phase::Closing
            {
                return Err(Error::Conflict);
            }
            pair_read
                .inspect_cleanup_effect(
                    &self.runtime,
                    &self.supervisor,
                    expected,
                    4 + index as u8,
                    |_| Ok(()),
                )
                .map_err(|_| Error::Conflict)?;
            // The concrete cleanup gate may reauthenticate the SAME Pair;
            // release our Pair/inventory borrows before its joined read.
            closing
                .inspect_window(|window| {
                    if !window.matches_closing(closing) || !window.matches_runtime(&self.runtime) {
                        return Err(super::super::member_carrier_wintun::Error::Conflict);
                    }
                    self.gate
                        .try_borrow_mut()
                        .map_err(|_| super::super::member_carrier_wintun::Error::Conflict)?
                        .authorize_stop(&self.context, expected, &self.intent, window)
                        .map_err(|_| super::super::member_carrier_wintun::Error::Conflict)
                })
                .map_err(|_| Error::Conflict)?;
            pair_read
                .inspect_cleanup_effect(
                    &self.runtime,
                    &self.supervisor,
                    expected,
                    4 + index as u8,
                    |_| Ok(()),
                )
                .map_err(|_| Error::Conflict)?;
            self.verify_sources()?;
            if !self.runtime.matches_lock(lock)
                || keys_record::Record::decode(
                    &self
                        .runtime
                        .record(&self.context, RecordKind::NativeCarrierReceipts)?,
                )? != native
            {
                return Err(Error::Conflict);
            }
            Ok(())
        }
        fn cleanup_envelope(
            &self,
            pair_read: &NativePairIntentRead,
            expected: &PairRecord,
            lock: &mut KeyLock,
        ) -> Result<()> {
            self.verify_sources()?;
            validate_member_operation(
                &self.context,
                expected,
                &self.intent,
                MemberOperation::Stop,
            )?;
            let native = self
                .runtime
                .record(&self.context, RecordKind::NativeCarrierReceipts)?;
            let record = keys_record::Record::decode(&native)?;
            if !self.runtime.matches_lock(lock)
                || record.context != self.context
                || record.phase != Phase::Closing
            {
                return Err(Error::Conflict);
            }
            pair_read
                .inspect_cleanup_effect(
                    &self.runtime,
                    &self.supervisor,
                    expected,
                    4 + slot_index(self.intent.slot) as u8,
                    |_| Ok(()),
                )
                .map_err(|_| Error::Conflict)?;
            if !self.runtime.matches_lock(lock)
                || self
                    .runtime
                    .record(&self.context, RecordKind::NativeCarrierReceipts)?
                    != native
            {
                return Err(Error::Conflict);
            }
            self.verify_sources()
        }
    }

    /// Get full original C metadata from SDK within its opaque window, then
    /// attest the ENTIRE mixed SDK universe. No filtered-owned PnP shortcut.
    fn full_universe(
        context: &Context,
        bindings: &Bindings,
        members: &[ExpectedProvider],
    ) -> Result<Vec<ExpectedProvider>> {
        let carrier = bindings.carrier.as_ref().ok_or(Error::Conflict)?;
        let proof = carrier.identity.proof;
        if bindings.scope != context.intent.scope || proof.guid != context.bindings[0].guid {
            return Err(Error::Conflict);
        }
        let mut row = MIB_IF_ROW2 {
            InterfaceIndex: proof.index,
            ..Default::default()
        };
        if unsafe { GetIfEntry2(&mut row) } != 0 {
            return Err(Error::Native);
        }
        let text = |wide: &[u16]| -> Result<String> {
            let end = wide.iter().position(|v| *v == 0).ok_or(Error::Conflict)?;
            String::from_utf16(&wide[..end]).map_err(|_| Error::Conflict)
        };
        let mut guid = [0; 16];
        guid[..4].copy_from_slice(&row.InterfaceGuid.data1.to_be_bytes());
        guid[4..6].copy_from_slice(&row.InterfaceGuid.data2.to_be_bytes());
        guid[6..8].copy_from_slice(&row.InterfaceGuid.data3.to_be_bytes());
        guid[8..].copy_from_slice(&row.InterfaceGuid.data4);
        let identity = provider::Expected {
            guid,
            luid: unsafe { row.InterfaceLuid.Value },
            index: row.InterfaceIndex,
            name: text(&row.Alias)?,
            description: text(&row.Description)?,
            if_type: row.Type,
            tunnel_type: row.TunnelType,
        };
        if identity.guid != proof.guid
            || identity.luid != proof.luid
            || identity.index != proof.index
            || identity.name != context.bindings[0].name
            || row.InterfaceAndOperStatusFlags._bitfield & 0x83 != 0
        {
            return Err(Error::Conflict);
        }
        complete_provider_inputs(
            context,
            &[ExpectedProvider {
                identity,
                kind: ProviderKind::Wintun,
            }],
            members,
        )
    }
    fn shared_slot(slot: TunnelSlot) -> Slot {
        match slot {
            TunnelSlot::A => Slot::A,
            TunnelSlot::B => Slot::B,
        }
    }
    fn slot_index(slot: TunnelSlot) -> usize {
        match slot {
            TunnelSlot::A => 0,
            TunnelSlot::B => 1,
        }
    }
    fn root_error(error: RootError<Error>) -> Error {
        match error {
            RootError::Retired => Error::Retired,
            RootError::Operation(e) => e,
        }
    }
    fn owner_error(error: crate::member_owner::OwnerError) -> Error {
        use crate::member_owner::OwnerError;
        match error {
            OwnerError::Invalid => Error::Invalid,
            OwnerError::Conflict => Error::Conflict,
            OwnerError::Pending => Error::Pending,
            OwnerError::Retired => Error::Retired,
            OwnerError::Native => Error::Native,
            OwnerError::Journal => Error::Journal,
        }
    }
    fn io_error(_: impl std::fmt::Debug) -> io::Error {
        io::Error::other("native_member_controller_conflict")
    }
}

#[cfg(test)]
#[path = "member_carrier_member_controller_tests.rs"]
mod tests;
