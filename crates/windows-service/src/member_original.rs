//! Shared retention of the actual member owner, not a copied native proof.
#![allow(dead_code)] // Native carrier coordinator consumes this before factory enablement.

use crate::member_owner::{
    Intent, Journal, MemberIo, MemberOwner, NativeProof, OriginalMemberRebindIo, OriginalRebindAck,
    OwnerError, Phase, Record, Result,
};
use crate::member_owner::{OriginalMemberPartialCleanupIo, PartialServiceObservation};
use std::{
    cell::{Cell, RefCell},
    rc::{Rc, Weak},
};

struct Shared<J, I> {
    owner: RefCell<MemberOwner<J, I>>,
    revoked: Cell<bool>,
    completed: RefCell<Option<Record>>,
    stop_attempt: RefCell<Option<Record>>,
    receipt_issued: Cell<bool>,
    cleanup_busy: Cell<bool>,
    cleanup_tainted: Cell<bool>,
    start_attempted: Cell<bool>,
    partial_issued: Cell<bool>,
    sealed_generation: RefCell<Option<Weak<RetiredMemberGeneration<J, I>>>>,
    read_generation: Cell<u64>,
}
impl<J, I> Shared<J, I> {
    fn deny_cleanup_reentry(&self) -> Result<()> {
        if self.cleanup_busy.get() {
            self.revoked.set(true);
            self.cleanup_tainted.set(true);
            return Err(OwnerError::Conflict);
        }
        Ok(())
    }
}

/// The unique controller and its readers retain the SAME actual owner, files
/// and native IO. Neither equal records nor reopened files seed provenance.
pub(crate) struct RetainedMember<J, I> {
    shared: Rc<Shared<J, I>>,
    retired_generation: Option<Rc<RetiredMemberGeneration<J, I>>>,
    closed_processes: Vec<Rc<ClosedOldProcessReceipt<J, I>>>,
}

/// No effect methods, Clone, serialization or caller-supplied proof constructor.
pub(crate) struct OriginalMemberRead<J, I> {
    shared: Rc<Shared<J, I>>,
    intent: Intent,
    proof: NativeProof,
    generation: u64,
}

/// Pure identity pin issued ONLY from an actual original live reader. No
/// public constructor, native presence/storage/effect grant or SDK access.
pub(crate) struct OriginalMemberRegistration<J, I> {
    shared: Rc<Shared<J, I>>,
    intent: Intent,
    proof: NativeProof,
    generation: u64,
}
impl<J, I> OriginalMemberRegistration<J, I> {
    pub(crate) fn proof(&self) -> NativeProof {
        self.proof
    }
    pub(crate) fn verify_current(&self) -> Result<()> {
        if self.shared.revoked.get()
            || self.shared.receipt_issued.get()
            || !self.shared.start_attempted.get()
            || self.shared.read_generation.get() != self.generation
        {
            return Err(OwnerError::Retired);
        }
        Ok(())
    }
    pub(crate) fn verify_original_read(&self, reader: &OriginalMemberRead<J, I>) -> Result<()> {
        self.verify_current()?;
        if !Rc::ptr_eq(&self.shared, &reader.shared)
            || self.intent != reader.intent
            || self.proof != reader.proof
            || self.generation != reader.generation
        {
            return Err(OwnerError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn verify_pending_read(&self, reader: &PendingMemberRead<J, I>) -> Result<()> {
        self.verify_current()?;
        if !Rc::ptr_eq(&self.shared, &reader.shared)
            || self.intent != reader.intent
            || self.generation != reader.generation
        {
            return Err(OwnerError::Conflict);
        }
        Ok(())
    }
}
impl<J, I> OriginalMemberRead<J, I> {
    pub(crate) fn registration(&self) -> Result<OriginalMemberRegistration<J, I>> {
        let pin = OriginalMemberRegistration {
            shared: self.shared.clone(),
            intent: self.intent.clone(),
            proof: self.proof,
            generation: self.generation,
        };
        pin.verify_current()?;
        Ok(pin)
    }
}

/// Issued once only after actual Stop ACK, durable Stopped and fresh absence.
/// Keeps the actual files/native owner retained through independent readback.
pub(crate) struct ClosedMemberReceipt<J, I> {
    shared: Rc<Shared<J, I>>,
    stopped: Record,
    generation: u64,
}

/// Original old-process closure + actual replacement ACK. Retains the SAME
/// MemberOwner/native IO (including both native process handles), never a new
/// owner or service-name lookup. No public constructor, Clone or serialization.
pub(crate) struct ClosedOldProcessReceipt<J, I> {
    shared: Rc<Shared<J, I>>,
    native: Rc<OriginalRebindAck>,
    running: Record,
    old_generation: u64,
    new_generation: u64,
}
pub(crate) type OriginalMemberRebind<J, I> = (
    Record,
    Rc<ClosedOldProcessReceipt<J, I>>,
    OriginalMemberRead<J, I>,
);
impl<J, I> ClosedOldProcessReceipt<J, I> {
    pub(crate) fn running_record(&self) -> &Record {
        &self.running
    }
    pub(crate) fn verify_retired_original_read(
        &self,
        reader: &OriginalMemberRead<J, I>,
    ) -> Result<()> {
        if !Rc::ptr_eq(&self.shared, &reader.shared)
            || reader.generation != self.old_generation
            || reader.intent != *self.native.intent()
            || reader.proof != self.native.old_proof()
            || self.native.replacement_proof()? != self.running.proof.ok_or(OwnerError::Pending)?
        {
            return Err(OwnerError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn verify_replacement_original_read(
        &self,
        reader: &OriginalMemberRead<J, I>,
    ) -> Result<()> {
        if !Rc::ptr_eq(&self.shared, &reader.shared)
            || reader.generation != self.new_generation
            || reader.intent != self.running.intent
            || Some(reader.proof) != self.running.proof
            || self.native.replacement_proof()? != reader.proof
        {
            return Err(OwnerError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn verify_retired_pending_read(
        &self,
        reader: &PendingMemberRead<J, I>,
    ) -> Result<()> {
        if !Rc::ptr_eq(&self.shared, &reader.shared)
            || reader.generation != self.old_generation
            || reader.intent != *self.native.intent()
            || self.native.replacement_proof()? != self.running.proof.ok_or(OwnerError::Pending)?
        {
            return Err(OwnerError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn verify_replacement_pending_read(
        &self,
        reader: &PendingMemberRead<J, I>,
    ) -> Result<()> {
        if !Rc::ptr_eq(&self.shared, &reader.shared)
            || reader.generation != self.new_generation
            || reader.intent != self.running.intent
            || self.native.replacement_proof()? != self.running.proof.ok_or(OwnerError::Pending)?
        {
            return Err(OwnerError::Conflict);
        }
        Ok(())
    }
}

/// Historical identity only, sealed by THIS retained owner after its original
/// Stop ACK and fresh private/native absence. Never current absence, SDK
/// membership, storage reuse, key/row retirement or any native-effect grant.
pub(crate) struct RetiredMemberGeneration<J, I> {
    receipt: Rc<ClosedMemberReceipt<J, I>>,
    proof: Option<NativeProof>,
    acknowledged: Cell<bool>,
}
impl<J: Journal, I: MemberIo> RetiredMemberGeneration<J, I> {
    fn verify_registration(&self) -> Result<()> {
        let shared = &self.receipt.shared;
        shared.deny_cleanup_reentry()?;
        if !self.acknowledged.get()
            || !shared.revoked.get()
            || !shared.receipt_issued.get()
            || shared
                .completed
                .try_borrow()
                .map_err(|_| OwnerError::Conflict)?
                .as_ref()
                != Some(&self.receipt.stopped)
            || shared
                .sealed_generation
                .try_borrow()
                .map_err(|_| OwnerError::Conflict)?
                .as_ref()
                .and_then(Weak::upgrade)
                .is_none_or(|registered| !std::ptr::eq(self, Rc::as_ptr(&registered)))
        {
            return Err(OwnerError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn read_history(
        &self,
        receipt: &Rc<ClosedMemberReceipt<J, I>>,
    ) -> Result<(Intent, Option<NativeProof>)> {
        self.verify_registration()?;
        if !Rc::ptr_eq(&self.receipt, receipt) {
            return Err(OwnerError::Conflict);
        }
        // Immutable original history, NOT a fresh absence query. In particular
        // never reread the old journal after an independently authorized owner
        // replaces it. Existing Closed verification still checks fresh absence.
        Ok((self.receipt.stopped.intent.clone(), self.proof))
    }
    pub(crate) fn verify_live_reader(&self, reader: &OriginalMemberRead<J, I>) -> Result<()> {
        self.verify_registration()?;
        if !Rc::ptr_eq(&self.receipt.shared, &reader.shared)
            || self.receipt.stopped.intent != reader.intent
            || self.proof != Some(reader.proof)
            || self.receipt.generation != reader.generation
        {
            return Err(OwnerError::Conflict);
        }
        Ok(())
    }
    /// Historical comparison only. The caller's record is compared against
    /// this seal's private ACK, never accepted as an original or native proof.
    pub(crate) fn verify_retired_original_read(
        &self,
        reader: &OriginalMemberRead<J, I>,
        receipt: &Rc<ClosedMemberReceipt<J, I>>,
        stopped: &Record,
    ) -> Result<()> {
        self.verify_live_reader(reader)?;
        let (intent, proof) = self.read_history(receipt)?;
        if stopped != &self.receipt.stopped
            || intent != stopped.intent
            || proof != stopped.retired_proof
        {
            return Err(OwnerError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn verify_pending_reader(&self, reader: &PendingMemberRead<J, I>) -> Result<()> {
        self.verify_registration()?;
        if !Rc::ptr_eq(&self.receipt.shared, &reader.shared)
            || self.receipt.stopped.intent != reader.intent
            || self.receipt.generation != reader.generation
        {
            return Err(OwnerError::Conflict);
        }
        Ok(())
    }
}

/// Retains the original owner before Start; never a Running capability.
pub(crate) struct PendingMemberRead<J, I> {
    shared: Rc<Shared<J, I>>,
    intent: Intent,
    generation: u64,
}

/// SAME original owner plus actual retained NEW-service cleanup pin. No live
/// reader, NIC identity, serializable grant or public constructor.
pub(crate) struct PartialMemberCleanup<J, I: OriginalMemberPartialCleanupIo> {
    shared: Rc<Shared<J, I>>,
    intent: Intent,
    generation: u64,
    pin: I::CleanupPin,
}
impl<J: Journal, I: OriginalMemberPartialCleanupIo> PendingMemberRead<J, I> {
    pub(crate) fn partial_cleanup(&self) -> Result<PartialMemberCleanup<J, I>> {
        self.retire_forward();
        self.shared.deny_cleanup_reentry()?;
        if self.generation != self.shared.read_generation.get()
            || !self.shared.start_attempted.get()
            || self.shared.receipt_issued.get()
        {
            return Err(OwnerError::Retired);
        }
        if self.shared.partial_issued.replace(true) {
            return Err(OwnerError::Retired);
        }
        let mut owner = self
            .shared
            .owner
            .try_borrow_mut()
            .map_err(|_| OwnerError::Conflict)?;
        if owner.intent() != &self.intent {
            return Err(OwnerError::Conflict);
        }
        let pin = owner.partial_cleanup_pin()?; // No external read before caller roots this actual pin.
        Ok(PartialMemberCleanup {
            shared: self.shared.clone(),
            intent: self.intent.clone(),
            generation: self.generation,
            pin,
        })
    }
}
impl<J: Journal, I: OriginalMemberPartialCleanupIo> PartialMemberCleanup<J, I> {
    pub(crate) fn intent(&self) -> &Intent {
        &self.intent
    }
    pub(crate) fn verify_pending_original(&self, pending: &PendingMemberRead<J, I>) -> Result<()> {
        if !Rc::ptr_eq(&self.shared, &pending.shared)
            || self.intent != pending.intent
            || self.generation != pending.generation
        {
            return Err(OwnerError::Conflict);
        }
        self.verify_current()
    }
    fn verify_current(&self) -> Result<()> {
        if self.generation != self.shared.read_generation.get()
            || self.shared.receipt_issued.get()
            || !self.shared.start_attempted.get()
        {
            return Err(OwnerError::Retired);
        }
        Ok(())
    }
    pub(crate) fn inspect(&self) -> Result<PartialServiceObservation> {
        self.verify_current()?;
        self.shared.revoked.set(true);
        self.shared.deny_cleanup_reentry()?;
        self.shared.cleanup_busy.set(true);
        self.shared.cleanup_tainted.set(false);
        let _attempt = CleanupAttempt {
            shared: &self.shared,
        };
        let mut owner = self
            .shared
            .owner
            .try_borrow_mut()
            .map_err(|_| OwnerError::Conflict)?;
        if owner.intent() != &self.intent {
            return Err(OwnerError::Conflict);
        }
        let observation = owner.inspect_partial_cleanup(&self.pin)?;
        self.verify_current()?;
        if self.shared.cleanup_tainted.get() {
            return Err(OwnerError::Conflict);
        }
        Ok(observation)
    }
}
impl<J: Journal, I: OriginalMemberPartialCleanupIo> RetainedMember<J, I> {
    pub(crate) fn stop_partial_original(
        &mut self,
        expected: &Record,
        original: &PartialMemberCleanup<J, I>,
    ) -> Result<(Record, ClosedMemberReceipt<J, I>)> {
        original.verify_current()?;
        if !Rc::ptr_eq(&self.shared, &original.shared) {
            return Err(OwnerError::Conflict);
        }
        self.shared.revoked.set(true);
        self.shared.deny_cleanup_reentry()?;
        self.shared.cleanup_busy.set(true);
        self.shared.cleanup_tainted.set(false);
        let _attempt = CleanupAttempt {
            shared: &self.shared,
        };
        let mut owner = self
            .shared
            .owner
            .try_borrow_mut()
            .map_err(|_| OwnerError::Conflict)?;
        if expected.phase == Phase::Stopped {
            let prior = self.shared.stop_attempt.borrow();
            let prior = prior.as_ref().ok_or(OwnerError::Retired)?;
            if expected.intent != prior.intent
                || expected.proof.is_some()
                || expected.retired_proof != prior.proof.or(prior.retired_proof)
            {
                return Err(OwnerError::Conflict);
            }
        } else {
            *self.shared.stop_attempt.borrow_mut() = Some(expected.clone());
        }
        let stopped = owner.stop_partial_original(expected, &original.pin)?;
        *self.shared.completed.borrow_mut() = Some(stopped.clone());
        verify_absent(&mut owner, &stopped)?;
        if self.shared.cleanup_tainted.get() {
            return Err(OwnerError::Conflict);
        }
        self.shared.receipt_issued.set(true);
        Ok((
            stopped.clone(),
            ClosedMemberReceipt {
                shared: self.shared.clone(),
                stopped,
                generation: self.shared.read_generation.get(),
            },
        ))
    }
}
struct PendingReadAttempt<'a, J, I> {
    shared: &'a Shared<J, I>,
    complete: bool,
}
impl<J, I> Drop for PendingReadAttempt<'_, J, I> {
    fn drop(&mut self) {
        self.shared.cleanup_busy.set(false);
        if !self.complete {
            self.shared.revoked.set(true);
        }
    }
}
impl<J: Journal, I: MemberIo> PendingMemberRead<J, I> {
    /// SAME unconsumed owner's private/native absence observation only. This
    /// never issues a Running/Stopped/Closed ACK; complete SDK absence remains
    /// the native controller's separate mandatory Closing bracket.
    pub(crate) fn read_unstarted_for_cleanup(&mut self) -> Result<(Intent, Option<Record>)> {
        if self.generation != self.shared.read_generation.get() {
            return Err(OwnerError::Retired);
        }
        self.retire_forward();
        self.shared.deny_cleanup_reentry()?;
        if self.shared.start_attempted.get()
            || self.shared.receipt_issued.get()
            || self
                .shared
                .completed
                .try_borrow()
                .map_err(|_| OwnerError::Conflict)?
                .is_some()
            || self
                .shared
                .stop_attempt
                .try_borrow()
                .map_err(|_| OwnerError::Conflict)?
                .is_some()
        {
            return Err(OwnerError::Pending);
        }
        self.shared.cleanup_busy.set(true);
        self.shared.cleanup_tainted.set(false);
        let _attempt = CleanupAttempt {
            shared: &self.shared,
        };
        let mut owner = self
            .shared
            .owner
            .try_borrow_mut()
            .map_err(|_| OwnerError::Conflict)?;
        if owner.intent() != &self.intent {
            return Err(OwnerError::Conflict);
        }
        let prior = owner.prior_stopped()?;
        if owner.prior_stopped()? != prior || self.shared.cleanup_tainted.get() {
            return Err(OwnerError::Conflict);
        }
        Ok((self.intent.clone(), prior))
    }
    pub(crate) fn read_preparing(&mut self) -> Result<(Intent, Option<NativeProof>)> {
        if self.generation != self.shared.read_generation.get() {
            return Err(OwnerError::Retired);
        }
        self.shared.deny_cleanup_reentry()?;
        if self.shared.revoked.get() {
            return Err(OwnerError::Pending);
        }
        self.shared.cleanup_busy.set(true);
        self.shared.cleanup_tainted.set(false);
        let mut attempt = PendingReadAttempt {
            shared: &self.shared,
            complete: false,
        };
        let mut owner = self
            .shared
            .owner
            .try_borrow_mut()
            .map_err(|_| OwnerError::Conflict)?;
        if owner.intent() != &self.intent {
            return Err(OwnerError::Conflict);
        }
        if !self.shared.start_attempted.get() {
            // No member effect has been attempted by THIS owner. This is not
            // native absence; inventory's full SDK query remains mandatory.
            attempt.complete = true;
            return Ok((self.intent.clone(), None));
        }
        let (intent, proof) = owner.original_live()?.read()?;
        if intent != self.intent || self.shared.cleanup_tainted.get() || self.shared.revoked.get() {
            return Err(OwnerError::Conflict);
        }
        attempt.complete = true;
        Ok((intent, Some(proof)))
    }
    pub(crate) fn read_closed(&mut self, receipt: &ClosedMemberReceipt<J, I>) -> Result<Record> {
        verify_original_closed(&self.shared, &self.intent, receipt)?;
        Ok(receipt.stopped.clone())
    }
    /// Only proof retired by THIS original owner's explicit Stop attempt.
    /// An inherited previous incarnation's retired proof is not this member.
    pub(crate) fn read_closed_proof(
        &mut self,
        receipt: &ClosedMemberReceipt<J, I>,
    ) -> Result<Option<(Intent, NativeProof)>> {
        self.read_closed(receipt)?;
        let prior = self
            .shared
            .stop_attempt
            .try_borrow()
            .map_err(|_| OwnerError::Conflict)?;
        let prior = prior.as_ref().ok_or(OwnerError::Pending)?;
        if prior.intent != self.intent {
            return Err(OwnerError::Conflict);
        }
        let Some(proof) = prior.proof else {
            return Ok(None);
        };
        if receipt.stopped.retired_proof != Some(proof) {
            return Err(OwnerError::Conflict);
        }
        Ok(Some((self.intent.clone(), proof)))
    }
    pub(crate) fn read_pin(&self) -> Self {
        Self {
            shared: self.shared.clone(),
            intent: self.intent.clone(),
            generation: self.generation,
        }
    }
    pub(crate) fn intent(&self) -> &Intent {
        &self.intent
    }
    pub(crate) fn same_original(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.shared, &other.shared)
            && self.intent == other.intent
            && self.generation == other.generation
    }
    pub(crate) fn matches_live(&self, other: &OriginalMemberRead<J, I>) -> bool {
        Rc::ptr_eq(&self.shared, &other.shared)
            && self.intent == other.intent
            && self.generation == other.generation
    }
    pub(crate) fn retire_forward(&self) {
        if self.generation == self.shared.read_generation.get() {
            self.shared.revoked.set(true);
        }
    }
    pub(crate) fn read_for_cleanup(&mut self) -> Result<(Intent, Option<NativeProof>)> {
        if self.generation != self.shared.read_generation.get() {
            return Err(OwnerError::Retired);
        }
        self.retire_forward();
        self.shared.deny_cleanup_reentry()?;
        self.shared.cleanup_busy.set(true);
        self.shared.cleanup_tainted.set(false);
        let _attempt = CleanupAttempt {
            shared: &self.shared,
        };
        let mut owner = self
            .shared
            .owner
            .try_borrow_mut()
            .map_err(|_| OwnerError::Conflict)?;
        if owner.intent() != &self.intent {
            return Err(OwnerError::Conflict);
        }
        if !self.shared.start_attempted.get() {
            return Ok((self.intent.clone(), None));
        }
        // Only MemberOwner's actual committed original-run receipt may supply
        // proof. A partial or lost native ACK stays Pending, never lookup/adopt.
        let (intent, proof) = owner
            .read_original_for_cleanup()
            .map_err(|_| OwnerError::Pending)?;
        if self.shared.cleanup_tainted.get() || intent != self.intent {
            return Err(OwnerError::Conflict);
        }
        Ok((intent, Some(proof)))
    }
}

fn verify_original_closed<J: Journal, I: MemberIo>(
    shared: &Shared<J, I>,
    intent: &Intent,
    receipt: &ClosedMemberReceipt<J, I>,
) -> Result<()> {
    shared.revoked.set(true);
    shared.deny_cleanup_reentry()?;
    shared.cleanup_busy.set(true);
    shared.cleanup_tainted.set(false);
    let _attempt = CleanupAttempt { shared };
    if !std::ptr::eq(shared, Rc::as_ptr(&receipt.shared))
        || &receipt.stopped.intent != intent
        || !shared.receipt_issued.get()
        || shared.completed.borrow().as_ref() != Some(&receipt.stopped)
    {
        return Err(OwnerError::Conflict);
    }
    let mut owner = shared
        .owner
        .try_borrow_mut()
        .map_err(|_| OwnerError::Conflict)?;
    verify_absent(&mut owner, &receipt.stopped)?;
    if shared.cleanup_tainted.get() {
        return Err(OwnerError::Conflict);
    }
    Ok(())
}

struct ReadAttempt<'a> {
    revoked: &'a Cell<bool>,
    complete: bool,
}

struct CleanupAttempt<'a, J, I> {
    shared: &'a Shared<J, I>,
}
impl<J, I> Drop for CleanupAttempt<'_, J, I> {
    fn drop(&mut self) {
        self.shared.cleanup_busy.set(false);
        self.shared.revoked.set(true);
    }
}
impl Drop for ReadAttempt<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.revoked.set(true);
        }
    }
}

impl<J: Journal, I: MemberIo> RetainedMember<J, I> {
    /// Original destructor disposition facts only; no journal/native reads,
    /// current absence, publication, SDK membership or effect authority.
    pub(crate) fn verify_terminal_unstarted_registration(
        &self,
        pending: &PendingMemberRead<J, I>,
    ) -> Result<Intent> {
        self.verify_terminal_pending_registration(pending)?;
        if self.shared.start_attempted.get()
            || self.shared.receipt_issued.get()
            || self
                .shared
                .completed
                .try_borrow()
                .map_err(|_| OwnerError::Conflict)?
                .is_some()
            || self
                .shared
                .stop_attempt
                .try_borrow()
                .map_err(|_| OwnerError::Conflict)?
                .is_some()
        {
            return Err(OwnerError::Pending);
        }
        Ok(pending.intent.clone())
    }
    pub(crate) fn verify_terminal_closed_registration(
        &self,
        pending: &PendingMemberRead<J, I>,
        receipt: &ClosedMemberReceipt<J, I>,
    ) -> Result<Record> {
        self.verify_terminal_pending_registration(pending)?;
        if !Rc::ptr_eq(&self.shared, &receipt.shared)
            || receipt.generation != pending.generation
            || receipt.stopped.intent != pending.intent
            || receipt.stopped.phase != Phase::Stopped
            || !self.shared.start_attempted.get()
            || !self.shared.revoked.get()
            || !self.shared.receipt_issued.get()
            || self
                .shared
                .completed
                .try_borrow()
                .map_err(|_| OwnerError::Conflict)?
                .as_ref()
                != Some(&receipt.stopped)
        {
            return Err(OwnerError::Conflict);
        }
        crate::member_owner::validate_record_shape(&receipt.stopped)?;
        Ok(receipt.stopped.clone())
    }
    fn verify_terminal_pending_registration(
        &self,
        pending: &PendingMemberRead<J, I>,
    ) -> Result<()> {
        if self.shared.cleanup_busy.get()
            || self.shared.cleanup_tainted.get()
            || !Rc::ptr_eq(&self.shared, &pending.shared)
            || pending.generation != self.shared.read_generation.get()
            || self
                .shared
                .owner
                .try_borrow()
                .map_err(|_| OwnerError::Conflict)?
                .intent()
                != &pending.intent
        {
            return Err(OwnerError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn pending_read(&self) -> Result<PendingMemberRead<J, I>> {
        self.shared.deny_cleanup_reentry()?;
        if self.shared.start_attempted.get() || self.shared.revoked.get() {
            return Err(OwnerError::Retired);
        }
        let owner = self
            .shared
            .owner
            .try_borrow()
            .map_err(|_| OwnerError::Conflict)?;
        Ok(PendingMemberRead {
            shared: self.shared.clone(),
            intent: owner.intent().clone(),
            generation: self.shared.read_generation.get(),
        })
    }
    pub(crate) fn verify_closed(&mut self, receipt: &ClosedMemberReceipt<J, I>) -> Result<()> {
        let intent = self
            .shared
            .owner
            .try_borrow()
            .map_err(|_| OwnerError::Conflict)?
            .intent()
            .clone();
        verify_original_closed(&self.shared, &intent, receipt)
    }
    /// Root before fallible postflight. Retry accepts only the exact original
    /// Rc and returns that SAME seal; shared registration is Weak, not a cycle.
    pub(crate) fn seal_closed_generation(
        &mut self,
        receipt: &Rc<ClosedMemberReceipt<J, I>>,
    ) -> Result<Rc<RetiredMemberGeneration<J, I>>> {
        self.shared.deny_cleanup_reentry()?;
        if let Some(retired) = &self.retired_generation {
            if !Rc::ptr_eq(&retired.receipt, receipt) {
                return Err(OwnerError::Conflict);
            }
            if retired.acknowledged.get() {
                retired.verify_registration()?;
                return Ok(retired.clone());
            }
        } else {
            self.verify_closed(receipt)?;
            let attempt = self
                .shared
                .stop_attempt
                .try_borrow()
                .map_err(|_| OwnerError::Conflict)?;
            let attempt = attempt.as_ref().ok_or(OwnerError::Pending)?;
            if attempt.intent != receipt.stopped.intent
                || attempt
                    .proof
                    .is_some_and(|proof| receipt.stopped.retired_proof != Some(proof))
            {
                return Err(OwnerError::Conflict);
            }
            let retired = Rc::new(RetiredMemberGeneration {
                receipt: receipt.clone(),
                proof: attempt.proof,
                acknowledged: Cell::new(false),
            });
            *self
                .shared
                .sealed_generation
                .try_borrow_mut()
                .map_err(|_| OwnerError::Conflict)? = Some(Rc::downgrade(&retired));
            self.retired_generation = Some(retired);
        }
        self.verify_closed(receipt)?;
        let retired = self
            .retired_generation
            .as_ref()
            .ok_or(OwnerError::Pending)?;
        retired.acknowledged.set(true);
        retired.verify_registration()?;
        Ok(retired.clone())
    }
    pub(crate) fn new(owner: MemberOwner<J, I>) -> Self {
        Self {
            shared: Rc::new(Shared {
                owner: RefCell::new(owner),
                revoked: Cell::new(false),
                completed: RefCell::new(None),
                stop_attempt: RefCell::new(None),
                receipt_issued: Cell::new(false),
                cleanup_busy: Cell::new(false),
                cleanup_tainted: Cell::new(false),
                start_attempted: Cell::new(false),
                partial_issued: Cell::new(false),
                sealed_generation: RefCell::new(None),
                read_generation: Cell::new(1),
            }),
            retired_generation: None,
            closed_processes: Vec::new(),
        }
    }

    /// Serialized readonly parser preparation on the SAME retained owner.
    /// Not a native package/driver permission and not a native presence read.
    pub(crate) fn prepare_readonly_native_profile(&self) -> Result<()> {
        self.shared.deny_cleanup_reentry()?;
        if self.shared.revoked.get() {
            return Err(OwnerError::Retired);
        }
        self.shared
            .owner
            .try_borrow_mut()
            .map_err(|_| OwnerError::Conflict)?
            .prepare_readonly_native_profile()
            .map(|_| ())
    }

    pub(crate) fn verify_readonly_native_profile(&self) -> Result<()> {
        self.shared.deny_cleanup_reentry()?;
        // This immutable original parser fact survives actual Stop so closed
        // retirement postflight can still compare the SAME prepared lineage.
        // It reads no private files/SDK and grants NO live/effect authority;
        // those readers and mutation methods retain their revocation fences.
        let owner = self
            .shared
            .owner
            .try_borrow()
            .map_err(|_| OwnerError::Conflict)?;
        owner.verify_readonly_native_profile(owner.readonly_native_profile()?)
    }

    #[cfg(test)]
    fn start(&mut self) -> Result<Record> {
        self.start_with_prior(None)
    }

    pub(crate) fn start_with_prior(&mut self, prior: Option<&Record>) -> Result<Record> {
        self.shared.deny_cleanup_reentry()?;
        if self.shared.revoked.get() {
            return Err(OwnerError::Retired);
        }
        if self.shared.start_attempted.replace(true) {
            return Err(OwnerError::Retired);
        }
        let mut attempt = ReadAttempt {
            revoked: &self.shared.revoked,
            complete: false,
        };
        let result = self
            .shared
            .owner
            .try_borrow_mut()
            .map_err(|_| OwnerError::Conflict)?
            .start_with_prior(prior)?;
        attempt.complete = true;
        Ok(result)
    }

    pub(crate) fn snapshot(&mut self) -> Result<Option<Record>> {
        self.shared.deny_cleanup_reentry()?;
        let result = self
            .shared
            .owner
            .try_borrow_mut()
            .map_err(|_| OwnerError::Conflict)
            .and_then(|mut owner| owner.snapshot());
        if result.is_err() {
            self.shared.revoked.set(true);
        }
        result
    }

    pub(crate) fn original_read(&mut self) -> Result<OriginalMemberRead<J, I>> {
        self.shared.deny_cleanup_reentry()?;
        if self.shared.revoked.get() {
            return Err(OwnerError::Retired);
        }
        let mut attempt = ReadAttempt {
            revoked: &self.shared.revoked,
            complete: false,
        };
        let (intent, proof) = self
            .shared
            .owner
            .try_borrow_mut()
            .map_err(|_| OwnerError::Conflict)?
            .original_live()?
            .read()?;
        let reader = OriginalMemberRead {
            shared: self.shared.clone(),
            intent,
            proof,
            generation: self.shared.read_generation.get(),
        };
        attempt.complete = true;
        Ok(reader)
    }

    pub(crate) fn stop(
        &mut self,
        expected: &Record,
    ) -> Result<(Record, ClosedMemberReceipt<J, I>)> {
        self.shared.revoked.set(true); // Even failed cleanup cannot rearm reads.
        self.shared.deny_cleanup_reentry()?;
        if self.shared.receipt_issued.get() {
            return Err(OwnerError::Retired);
        }
        let mut owner = self
            .shared
            .owner
            .try_borrow_mut()
            .map_err(|_| OwnerError::Conflict)?;
        let stopped = if expected.phase == Phase::Stopped {
            // Reconcile only THIS actual owner's uncertain terminal ACK. An
            // equal existing/recovery record cannot manufacture the attempt.
            if self.shared.completed.borrow().as_ref() != Some(expected) {
                let prior = self.shared.stop_attempt.borrow();
                let prior = prior.as_ref().ok_or(OwnerError::Retired)?;
                if expected.intent != prior.intent
                    || expected.proof.is_some()
                    || expected.retired_proof != prior.proof.or(prior.retired_proof)
                    || expected.previous_config_sha256 != prior.previous_config_sha256
                {
                    return Err(OwnerError::Conflict);
                }
            }
            expected.clone()
        } else {
            if owner.snapshot()?.as_ref() != Some(expected) {
                return Err(OwnerError::Conflict);
            }
            *self.shared.stop_attempt.borrow_mut() = Some(expected.clone());
            let stopped = owner.stop(expected)?;
            *self.shared.completed.borrow_mut() = Some(stopped.clone());
            stopped
        };
        verify_absent(&mut owner, &stopped)?;
        *self.shared.completed.borrow_mut() = Some(stopped.clone());
        self.shared.receipt_issued.set(true);
        let receipt = ClosedMemberReceipt {
            shared: self.shared.clone(),
            stopped: stopped.clone(),
            generation: self.shared.read_generation.get(),
        };
        Ok((stopped, receipt))
    }
}

fn verify_absent<J: Journal, I: MemberIo>(
    owner: &mut MemberOwner<J, I>,
    stopped: &Record,
) -> Result<()> {
    if stopped.phase != Phase::Stopped || owner.snapshot()?.as_ref() != Some(stopped) {
        return Err(OwnerError::Conflict);
    }
    if !owner.confirm_absent(stopped)? {
        return Err(OwnerError::Pending);
    }
    if owner.snapshot()?.as_ref() != Some(stopped) {
        return Err(OwnerError::Conflict);
    }
    Ok(())
}

impl<J: Journal, I: OriginalMemberRebindIo> RetainedMember<J, I> {
    pub(crate) fn rebind_original(
        &mut self,
        expected: &Record,
    ) -> Result<OriginalMemberRebind<J, I>> {
        self.shared.deny_cleanup_reentry()?;
        if self.shared.revoked.get() || self.shared.receipt_issued.get() {
            return Err(OwnerError::Retired);
        }
        let old_generation = self.shared.read_generation.get();
        let new_generation = old_generation.checked_add(1).ok_or(OwnerError::Pending)?;
        self.closed_processes
            .try_reserve(1)
            .map_err(|_| OwnerError::Pending)?;
        self.shared.read_generation.set(new_generation); // Retire all old aliases before native effects.
        self.shared.revoked.set(true);
        let mut attempt = ReadAttempt {
            revoked: &self.shared.revoked,
            complete: false,
        };
        let (running, native) = self
            .shared
            .owner
            .try_borrow_mut()
            .map_err(|_| OwnerError::Conflict)?
            .rebind_original(expected)?;
        let receipt = Rc::new(ClosedOldProcessReceipt {
            shared: self.shared.clone(),
            native,
            running: running.clone(),
            old_generation,
            new_generation,
        });
        self.closed_processes.push(receipt.clone()); // Root actual ACK before fallible readback.
        self.shared
            .owner
            .try_borrow_mut()
            .map_err(|_| OwnerError::Conflict)?
            .verify_original_rebind(&receipt.native, &running)?;
        let reader = OriginalMemberRead {
            shared: self.shared.clone(),
            intent: running.intent.clone(),
            proof: running.proof.ok_or(OwnerError::Pending)?,
            generation: new_generation,
        };
        receipt.verify_replacement_original_read(&reader)?;
        self.shared.revoked.set(false);
        attempt.complete = true;
        Ok((running, receipt, reader))
    }
    pub(crate) fn verify_rebind_receipt(
        &mut self,
        receipt: &Rc<ClosedOldProcessReceipt<J, I>>,
    ) -> Result<()> {
        self.shared.deny_cleanup_reentry()?;
        if self.shared.revoked.get()
            || self.shared.read_generation.get() != receipt.new_generation
            || !Rc::ptr_eq(&self.shared, &receipt.shared)
            || !self
                .closed_processes
                .iter()
                .any(|own| Rc::ptr_eq(own, receipt))
        {
            return Err(OwnerError::Retired);
        }
        let mut attempt = ReadAttempt {
            revoked: &self.shared.revoked,
            complete: false,
        };
        self.shared
            .owner
            .try_borrow_mut()
            .map_err(|_| OwnerError::Conflict)?
            .verify_original_rebind(&receipt.native, &receipt.running)?;
        attempt.complete = true;
        Ok(())
    }
    pub(crate) fn pending_rebind_read(
        &mut self,
        receipt: &Rc<ClosedOldProcessReceipt<J, I>>,
    ) -> Result<PendingMemberRead<J, I>> {
        self.verify_rebind_receipt(receipt)?;
        Ok(PendingMemberRead {
            shared: self.shared.clone(),
            intent: receipt.running.intent.clone(),
            generation: receipt.new_generation,
        })
    }
}

impl<J: Journal, I: MemberIo> OriginalMemberRead<J, I> {
    /// Retire the shared forward fence before a cleanup inventory checks any
    /// other dependency. This grants no facts and cannot rearm native reads.
    pub(crate) fn retire_forward(&self) {
        if self.generation == self.shared.read_generation.get() {
            self.shared.revoked.set(true);
        }
    }

    /// Factual cleanup only through the SAME captured actual original owner.
    /// Entering retires every forward reader before any durable/native query.
    /// Forward poison is never reset; Stop, absence and source checks still
    /// belong to their actual owners and cannot be manufactured from this DATA.
    pub(crate) fn read_for_cleanup(&mut self) -> Result<(Intent, NativeProof)> {
        if self.generation != self.shared.read_generation.get() {
            return Err(OwnerError::Retired);
        }
        self.retire_forward();
        if self.shared.cleanup_busy.replace(true) {
            self.shared.cleanup_tainted.set(true);
            return Err(OwnerError::Conflict);
        }
        self.shared.cleanup_tainted.set(false);
        let _attempt = CleanupAttempt {
            shared: &self.shared,
        };
        let facts = self
            .shared
            .owner
            .try_borrow_mut()
            .map_err(|_| OwnerError::Conflict)?
            .read_original_for_cleanup()?;
        if self.shared.cleanup_tainted.get() || facts != (self.intent.clone(), self.proof) {
            return Err(OwnerError::Conflict);
        }
        Ok(facts)
    }

    /// Cleanup DATA only, captured by this reader while the actual owner was
    /// live. Every access independently rechecks the SAME opaque Stop ACK,
    /// current durable Stopped and native absence; no live capability is issued.
    pub(crate) fn read_closed_history(
        &mut self,
        receipt: &ClosedMemberReceipt<J, I>,
    ) -> Result<(Intent, NativeProof)> {
        self.verify_closed(receipt)?;
        Ok((self.intent.clone(), self.proof))
    }

    pub(crate) fn read(&mut self) -> Result<(Intent, NativeProof)> {
        if self.generation != self.shared.read_generation.get() {
            return Err(OwnerError::Retired);
        }
        self.shared.deny_cleanup_reentry()?;
        if self.shared.revoked.get() {
            return Err(OwnerError::Retired);
        }
        let mut attempt = ReadAttempt {
            revoked: &self.shared.revoked,
            complete: false,
        };
        let facts = self
            .shared
            .owner
            .try_borrow_mut()
            .map_err(|_| OwnerError::Conflict)?
            .original_live()?
            .read()?;
        if facts != (self.intent.clone(), self.proof) {
            return Err(OwnerError::Conflict);
        }
        attempt.complete = true;
        Ok(facts)
    }

    pub(crate) fn verify_closed(&mut self, receipt: &ClosedMemberReceipt<J, I>) -> Result<()> {
        self.shared.deny_cleanup_reentry()?;
        let mut attempt = ReadAttempt {
            revoked: &self.shared.revoked,
            complete: false,
        };
        if !Rc::ptr_eq(&self.shared, &receipt.shared)
            || receipt.stopped.intent != self.intent
            || receipt.stopped.retired_proof != Some(self.proof)
            || receipt.generation != self.generation
            || !self.shared.receipt_issued.get()
            || self.shared.completed.borrow().as_ref() != Some(&receipt.stopped)
        {
            return Err(OwnerError::Conflict);
        }
        let mut owner = self
            .shared
            .owner
            .try_borrow_mut()
            .map_err(|_| OwnerError::Conflict)?;
        verify_absent(&mut owner, &receipt.stopped)?;
        attempt.complete = true;
        Ok(())
    }
}

#[cfg(test)]
#[path = "member_original_rebind_test_support.rs"]
pub(crate) mod rebind_test_support;

#[cfg(test)]
#[path = "member_original_tests.rs"]
mod tests;
