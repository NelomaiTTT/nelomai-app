//! Original creator inventory, independent of a Carrier's outer mutable borrow.
//! Context/intent are data; publication and closure require actual native ACKs.
#![cfg(any(windows, test))]
#![allow(dead_code)] // Main owns NativeKernel/factory and module integration.

use crate::member_carrier_native_ownership::{self as receipt, Binding, Context, Role};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Invalid,
    Conflict,
    Pending,
    Poisoned,
    Native,
    Changed,
}
pub(crate) type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    Intent,
    Empty,
    Creating,
    Ambiguous,
    Live,
    Retiring,
    Closed,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Scope {
    pub context: Context,
    pub binding: Binding,
    pub generation: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    pub guid: [u8; 16],
    pub luid: u64,
    pub index: u32,
    pub name: String,
    pub description: String,
    pub if_type: u32,
    pub tunnel_type: i32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Observation<P> {
    pub scope: Scope,
    pub identity: Identity,
    pub provider: P,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OriginalIdentity {
    pub scope: Scope,
    pub identity: Identity,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UniverseObservation<P> {
    pub context: Context,
    pub originals: Vec<Observation<P>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AbsenceFacts {
    pub scope: Scope,
    pub matches: Vec<Identity>,
}

/// Owning native capability; production implementations are Windows-only.
/// # Safety
/// Self is non-Clone, !Send, !Sync and owns the ORIGINAL successful NEW-create
/// acknowledgement and actual native resource/runtime/source pins, never a reopened name/GUID, number,
/// journal/JSON proof or borrowed raw pointer. Read methods independently query
/// that same original raw resource identity and actual current
/// boot/runtime/epoch/serialization. No call to Carrier.capture or an authority
/// path which recursively queries this inventory. Provider is concrete native
/// metadata, never a success bit. All read methods are strictly read-only and
/// propagate missing/unknown/error; no successful defaults. CloseReceipt is an
/// opaque non-Clone, !Send, !Sync receipt
/// produced only AFTER consuming this exact original native close ONCE; verify
/// must reject foreign, fabricated, lost or repeated acknowledgements. A close
/// failure/unknown outcome cannot fabricate a receipt or retry the native close.
/// Self must not expose duplicatable effect authority; shared internal retention
/// must preserve all original pins. Neither Self nor CloseReceipt may provide a
/// safe data/lookup constructor that invents acknowledgment. Drop MUST NOT
/// close/delete/remove or unload unclosed native resources. This contract
/// confers no effect/runtime rights.
pub(crate) unsafe trait OriginalNative: Sized {
    type Provider: Clone + Eq;
    type CloseReceipt;
    type Universe: NativeUniverse<Self>;
    fn original_identity(&self, scope: &Scope) -> Result<OriginalIdentity>;
    fn verify_close_receipt(&self, scope: &Scope, receipt: &Self::CloseReceipt) -> Result<()>;
}
/// ONE factual provider query over the COMPLETE actually retained universe.
/// # Safety
/// Call native inspect_all / equivalent bounded full PnP/interface enumeration
/// once for the entire input, not single inspect per NIC and never an owned-only
/// filter hiding foreign/extra/problem instances. Inputs are comparison facts,
/// not native ownership: only OriginalNative's retained ACK supplies ownership.
/// Independently verify current scope/runtime/source/pins/SAME serialized lock.
/// Returned per-original provider metadata must be concrete stable native facts.
/// Do not call Carrier.capture, this observer, or an authority which recursively
/// collects this inventory. No mutation, adoption, or successful query defaults.
pub(crate) unsafe trait NativeUniverse<N: OriginalNative> {
    fn inspect_universe(
        &self,
        context: &Context,
        originals: &[OriginalIdentity],
    ) -> Result<UniverseObservation<N::Provider>>;
}
/// Independent bounded native absence inventory, not a lookup-adoption seam.
/// # Safety
/// Query all matching name/GUID/original identities freshly under the SAME
/// actual serialized owner and independently validate current Context. Include
/// ambiguous/foreign/problem matches, propagate errors; do not call this registry
/// or Carrier.capture to derive absence. Returned scope is independently bound,
/// not accepted from JSON. No mutations or successful default implementations.
pub(crate) unsafe trait NativeAbsence {
    fn inspect_absence(&mut self, scope: &Scope) -> Result<AbsenceFacts>;
}

struct Attempt {
    scope: Scope,
    acknowledged: Cell<bool>,
    published: Cell<bool>,
    retiring: Cell<bool>,
    completion: RefCell<Option<Rc<()>>>,
}
struct Held<N: OriginalNative> {
    native: Rc<N>,
    original: Option<Observation<N::Provider>>,
    close: Option<Rc<N::CloseReceipt>>,
}
struct Slot<N: OriginalNative> {
    state: Cell<State>,
    scope: RefCell<Option<Scope>>,
    attempt: RefCell<Option<Rc<Attempt>>>,
    held: RefCell<Option<Held<N>>>,
}
struct Shared<N: OriginalNative> {
    context: Context,
    universe: N::Universe,
    slots: [Slot<N>; 3],
    poisoned: Cell<bool>,
    alive: Cell<bool>,
    busy: Cell<bool>,
    faults: Cell<u64>,
}
pub(crate) struct Producer<N: OriginalNative> {
    shared: Rc<Shared<N>>,
}
pub(crate) struct Observer<N: OriginalNative> {
    shared: Rc<Shared<N>>,
}
pub(crate) struct Begin<N: OriginalNative> {
    shared: Rc<Shared<N>>,
    attempt: Rc<Attempt>,
}
pub(crate) struct NewCreate<N: OriginalNative> {
    shared: Rc<Shared<N>>,
    attempt: Rc<Attempt>,
    completed: bool,
}
pub(crate) struct Retirement<N: OriginalNative> {
    shared: Rc<Shared<N>>,
    attempt: Rc<Attempt>,
    native: Rc<N>,
    completed: bool,
}
pub(crate) struct CloseAck<N: OriginalNative> {
    shared: Rc<Shared<N>>,
    attempt: Rc<Attempt>,
    nonce: Rc<()>,
    completed: bool,
}
pub(crate) struct Released<N: OriginalNative> {
    shared: Rc<Shared<N>>,
    attempt: Rc<Attempt>,
    native: Rc<N>,
    receipt: Rc<N::CloseReceipt>,
    scope: Scope,
    captured: Option<Observation<N::Provider>>,
}

/// Read-only retention of a SAME-owner original's once-close acknowledgement.
/// Captured identity is historical comparison data, never a live interface,
/// effect capability, lookup adoption or forward permission. No public data
/// constructor exists; only an actual completed Released can supply this pin.
pub(crate) struct RetiredRead<N: OriginalNative> {
    shared: Rc<Shared<N>>,
    attempt: Rc<Attempt>,
    native: Rc<N>,
    receipt: Rc<N::CloseReceipt>,
    captured: Observation<N::Provider>,
    read_frame: Cell<Option<u64>>,
    original_cut_busy: Cell<bool>,
}

struct RetiredFrame<'a>(&'a Cell<Option<u64>>);
impl Drop for RetiredFrame<'_> {
    fn drop(&mut self) {
        self.0.set(None);
    }
}
struct OriginalCut<'a, N: OriginalNative> {
    busy: &'a Cell<bool>,
    shared: &'a Shared<N>,
    completed: bool,
}
impl<N: OriginalNative> Drop for OriginalCut<'_, N> {
    fn drop(&mut self) {
        if !self.completed {
            self.shared.fail();
        }
        self.busy.set(false);
    }
}

/// SAME original create/close pins after C failed BEFORE provider publication.
/// This has no captured live identity and cannot supply a former WFP binding,
/// a RetiredRead, Source, absence permission, or authority to unload resources.
pub(crate) struct UnpublishedClosedRead<N: OriginalNative> {
    shared: Rc<Shared<N>>,
    attempt: Rc<Attempt>,
    native: Rc<N>,
    receipt: Rc<N::CloseReceipt>,
    scope: Scope,
}

/// Distinct factual channels chosen from the actual publication outcome. An
/// error reading published history MUST NOT select the unpublished channel.
pub(crate) enum ClosedRead<N: OriginalNative> {
    Published(RetiredRead<N>),
    Unpublished(UnpublishedClosedRead<N>),
}

/// Factual cleanup result after exact receipt AND fresh complete absence. It
/// deliberately is not the live UniverseObservation type used by creators.
pub(crate) struct RetiredObservation<P> {
    captured: Observation<P>,
}
impl<P> RetiredObservation<P> {
    pub(crate) fn captured(&self) -> &Observation<P> {
        &self.captured
    }
}

fn index(role: Role) -> usize {
    match role {
        Role::RoleCarrier => 0,
        Role::MemberA => 1,
        Role::MemberB => 2,
    }
}
fn validate_context(context: &Context) -> Result<()> {
    // Reuse the ACTUAL native receipt validator, including logical intent,
    // runtime/boot/epoch, role order, exact key paths and disjoint bindings.
    // This synthetic record is shape validation only; it grants no ACK/rights.
    receipt::validate_record(&receipt::Record {
        version: 2,
        context: context.clone(),
        generation: 1,
        phase: receipt::Phase::Preparing,
        native_rows: receipt::FullNativeRows::Unbound,
        keys: [Role::RoleCarrier, Role::MemberA, Role::MemberB].map(|role| receipt::KeyReceipt {
            role,
            phase: receipt::KeyPhase::Unstarted,
            new_key_ack: false,
            baseline: receipt::Value::Absent,
            current: receipt::Value::Absent,
            pending: None,
        }),
    })
    .map_err(|_| Error::Invalid)
}
fn validate_observation<P>(scope: &Scope, observed: &Observation<P>) -> Result<()> {
    let id = &observed.identity;
    if &observed.scope != scope
        || id.guid != scope.binding.guid
        || id.name != scope.binding.name
        || id.luid == 0
        || id.index == 0
        || id.if_type != 53
        || id.tunnel_type != 0
        || id.description.is_empty()
        || id.description.encode_utf16().count() > 256
        || id.description.chars().any(char::is_control)
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
impl<N: OriginalNative> Shared<N> {
    fn read_universe(self: &Rc<Self>) -> Result<UniverseObservation<N::Provider>> {
        self.read_universe_for(false)
    }
    fn read_universe_for(
        self: &Rc<Self>,
        cleanup: bool,
    ) -> Result<UniverseObservation<N::Provider>> {
        let operation = Operation::enter(self, cleanup)?;
        let observed = self.read_universe_locked(cleanup, &operation)?;
        operation.finish()?;
        Ok(observed)
    }
    fn read_universe_locked(
        self: &Rc<Self>,
        cleanup: bool,
        operation: &Operation<N>,
    ) -> Result<UniverseObservation<N::Provider>> {
        // Snapshot private strong retention only. No RefCell borrow crosses a
        // native callback, and no numeric identity is used to obtain ownership.
        let mut retained = Vec::with_capacity(3);
        for (i, slot) in self.slots.iter().enumerate() {
            let held = slot.held.try_borrow().map_err(|_| Error::Conflict)?;
            if let Some(h) = held.as_ref() {
                let attempt = slot.attempt.try_borrow().map_err(|_| Error::Conflict)?;
                let attempt = attempt.as_ref().ok_or(Error::Conflict)?;
                if !attempt.acknowledged.get()
                    || self.scope(&attempt.scope)? != i
                    || slot
                        .scope
                        .try_borrow()
                        .map_err(|_| Error::Conflict)?
                        .as_ref()
                        != Some(&attempt.scope)
                    || !(matches!(
                        slot.state.get(),
                        State::Creating | State::Live | State::Retiring
                    ) || cleanup && slot.state.get() == State::Ambiguous)
                    || h.close.is_some() && slot.state.get() != State::Retiring
                {
                    return Err(Error::Conflict);
                }
                retained.push((
                    attempt.scope.clone(),
                    h.native.clone(),
                    h.original.clone(),
                    h.close.clone(),
                ));
            } else if matches!(
                slot.state.get(),
                State::Creating | State::Live | State::Retiring | State::Ambiguous
            ) {
                // Unattempted roles may be globally poisoned by another role's
                // failure. Only their NO-attempt local fact is admissible;
                // actual full native absence is still independently queried.
                if !(cleanup
                    && slot.state.get() == State::Ambiguous
                    && slot
                        .attempt
                        .try_borrow()
                        .map_err(|_| Error::Conflict)?
                        .is_none())
                {
                    return Err(Error::Conflict);
                }
            }
        }
        let mut identities = Vec::with_capacity(3);
        for (scope, native, _, closed) in &retained {
            // Only an actual original-close receipt can exclude a formerly
            // owned NIC. State/metadata alone can never exclude a device.
            if let Some(closed) = closed {
                native.verify_close_receipt(scope, closed)?;
            } else {
                let facts = native.original_identity(scope)?;
                validate_observation(
                    scope,
                    &Observation {
                        scope: facts.scope.clone(),
                        identity: facts.identity.clone(),
                        provider: (),
                    },
                )?;
                for other in &identities {
                    let other: &OriginalIdentity = other;
                    if other.identity.guid == facts.identity.guid
                        || other.identity.luid == facts.identity.luid
                        || other.identity.index == facts.identity.index
                        || other
                            .identity
                            .name
                            .eq_ignore_ascii_case(&facts.identity.name)
                    {
                        return Err(Error::Conflict);
                    }
                }
                identities.push(facts);
            }
            operation.check()?;
        }
        // Full actual PnP universe, exactly ONCE after ALL raw-original reads.
        // Even the empty input must enumerate and reject unexpected devices.
        let universe = self.universe.inspect_universe(&self.context, &identities)?;
        operation.check()?;
        if universe.context != self.context || universe.originals.len() != identities.len() {
            return Err(Error::Conflict);
        }
        let mut originals = Vec::with_capacity(3);
        for id in &identities {
            let mut matches = universe.originals.iter().filter(|o| o.scope == id.scope);
            let facts = matches.next().ok_or(Error::Conflict)?;
            if matches.next().is_some() || facts.identity != id.identity {
                return Err(Error::Conflict);
            }
            validate_observation(&id.scope, facts)?;
            if let Some(previous) = retained
                .iter()
                .find(|(s, _, _, _)| s == &id.scope)
                .and_then(|(_, _, p, _)| p.as_ref())
            {
                if facts != previous {
                    return Err(Error::Changed);
                }
            }
            originals.push(facts.clone());
        }
        // Fence every actual raw original again AFTER the whole provider read;
        // replaced/reused handles or runtime/identity drift fail closed.
        for (scope, native, _, closed) in &retained {
            if let Some(closed) = closed {
                native.verify_close_receipt(scope, closed)?;
            } else {
                let after = native.original_identity(scope)?;
                if !identities.iter().any(|before| before == &after) {
                    return Err(Error::Changed);
                }
            }
            operation.check()?;
        }
        Ok(UniverseObservation {
            context: self.context.clone(),
            originals,
        })
    }
    fn fail(&self) {
        self.poisoned.set(true);
        if let Some(next) = self.faults.get().checked_add(1) {
            self.faults.set(next);
        } else {
            // A saturated stamp cannot distinguish a caught nested fault from
            // the enclosing operation. Permanently retire this owner instead
            // of letting cleanup publish a falsely unchanged observation.
            self.alive.set(false);
        }
        for slot in &self.slots {
            if matches!(
                slot.state.get(),
                State::Intent | State::Empty | State::Creating | State::Live
            ) {
                slot.state.set(State::Ambiguous);
            }
        }
    }
    fn idle(&self, cleanup: bool) -> Result<()> {
        if self.busy.get() {
            self.fail();
            return Err(Error::Conflict);
        }
        if !self.alive.get() || !cleanup && self.poisoned.get() {
            return Err(Error::Poisoned);
        }
        Ok(())
    }
    fn binding(&self, context: &Context, binding: &Binding) -> Result<usize> {
        let i = index(binding.role);
        if context != &self.context || binding != &self.context.bindings[i] {
            self.fail();
            return Err(Error::Conflict);
        }
        Ok(i)
    }
    fn scope(&self, s: &Scope) -> Result<usize> {
        let i = self.binding(&s.context, &s.binding)?;
        if s.generation == 0 {
            self.fail();
            return Err(Error::Invalid);
        }
        Ok(i)
    }
    fn attempt(&self, a: &Rc<Attempt>) -> Result<usize> {
        let i = self.scope(&a.scope)?;
        let stored = self.slots[i].attempt.try_borrow().map_err(|_| {
            self.fail();
            Error::Conflict
        })?;
        if !stored.as_ref().is_some_and(|s| Rc::ptr_eq(s, a)) {
            self.fail();
            return Err(Error::Conflict);
        }
        Ok(i)
    }
    fn retained(&self, i: usize) -> Result<Rc<N>> {
        self.slots[i]
            .held
            .try_borrow()
            .map_err(|_| {
                self.fail();
                Error::Conflict
            })?
            .as_ref()
            .map(|h| h.native.clone())
            .ok_or(Error::Pending)
    }
    fn close_parts(&self, i: usize) -> Result<(Rc<N>, Rc<N::CloseReceipt>)> {
        let held = self.slots[i].held.try_borrow().map_err(|_| {
            self.fail();
            Error::Conflict
        })?;
        let held = held.as_ref().ok_or(Error::Pending)?;
        Ok((
            held.native.clone(),
            held.close.as_ref().ok_or(Error::Pending)?.clone(),
        ))
    }
}
impl<N: OriginalNative> Drop for Shared<N> {
    fn drop(&mut self) {
        // If every owner/observer/token is lost, unresolved native pins must
        // STILL not be implicitly released. Bounded deliberate leak, not close.
        for slot in &mut self.slots {
            if let Some(held) = slot.held.get_mut().take() {
                std::mem::forget(held);
            }
        }
    }
}
struct Operation<N: OriginalNative> {
    shared: Rc<Shared<N>>,
    faults: u64,
    finished: bool,
}
impl<N: OriginalNative> Operation<N> {
    fn enter(shared: &Rc<Shared<N>>, cleanup: bool) -> Result<Self> {
        shared.idle(cleanup)?;
        shared.busy.set(true);
        Ok(Self {
            shared: shared.clone(),
            faults: shared.faults.get(),
            finished: false,
        })
    }
    fn finish(mut self) -> Result<()> {
        self.check()?;
        self.finished = true;
        self.shared.busy.set(false);
        Ok(())
    }
    fn check(&self) -> Result<()> {
        if self.shared.faults.get() != self.faults || !self.shared.alive.get() {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }
}
impl<N: OriginalNative> Drop for Operation<N> {
    fn drop(&mut self) {
        if !self.finished {
            self.shared.fail();
            self.shared.busy.set(false);
        }
    }
}
fn absent_facts(scope: &Scope, facts: AbsenceFacts) -> Result<()> {
    if &facts.scope != scope || !facts.matches.is_empty() {
        Err(Error::Conflict)
    } else {
        Ok(())
    }
}

impl<N: OriginalNative> Clone for Observer<N> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}
impl<N: OriginalNative> Producer<N> {
    /// Retains the SAME read-only registry. Does not revive forward authority,
    /// permit creation, or replace the independently required native query.
    pub(crate) fn observer(&self) -> Observer<N> {
        Observer {
            shared: self.shared.clone(),
        }
    }
    /// Actual original native query owner, for concrete runtime/pin comparison.
    /// No mutation or replacement of the registry's native boundary is exposed.
    pub(crate) fn original_universe(&self) -> &N::Universe {
        &self.shared.universe
    }
    pub(crate) fn intent(context: Context, universe: N::Universe) -> Result<(Self, Observer<N>)> {
        validate_context(&context)?;
        let shared = Rc::new(Shared {
            context,
            universe,
            slots: std::array::from_fn(|_| Slot {
                state: Cell::new(State::Intent),
                scope: RefCell::new(None),
                attempt: RefCell::new(None),
                held: RefCell::new(None),
            }),
            poisoned: Cell::new(false),
            alive: Cell::new(true),
            busy: Cell::new(false),
            faults: Cell::new(0),
        });
        Ok((
            Self {
                shared: shared.clone(),
            },
            Observer { shared },
        ))
    }
    pub(crate) fn confirm_empty(
        &mut self,
        scope: Scope,
        query: &mut impl NativeAbsence,
    ) -> Result<()> {
        self.shared.idle(false)?;
        let i = self.shared.scope(&scope)?;
        if self.shared.slots[i].state.get() != State::Intent {
            return Err(Error::Pending);
        }
        let operation = Operation::enter(&self.shared, false)?;
        absent_facts(&scope, query.inspect_absence(&scope)?)?;
        operation.finish()?;
        *self.shared.slots[i].scope.borrow_mut() = Some(scope);
        self.shared.slots[i].state.set(State::Empty);
        Ok(())
    }
    pub(crate) fn begin(&mut self, scope: Scope) -> Result<Begin<N>> {
        self.shared.idle(false)?;
        let i = self.shared.scope(&scope)?;
        let slot = &self.shared.slots[i];
        if slot.state.get() != State::Empty {
            return Err(Error::Pending);
        }
        if slot.scope.borrow().as_ref() != Some(&scope) {
            self.shared.fail();
            return Err(Error::Conflict);
        }
        let attempt = Rc::new(Attempt {
            scope,
            acknowledged: Cell::new(false),
            published: Cell::new(false),
            retiring: Cell::new(false),
            completion: RefCell::new(None),
        });
        *slot.attempt.borrow_mut() = Some(attempt.clone());
        slot.state.set(State::Creating);
        Ok(Begin {
            shared: self.shared.clone(),
            attempt,
        })
    }
    pub(crate) fn publish(&mut self, mut ack: NewCreate<N>) -> Result<()> {
        self.shared.idle(false)?;
        if !Rc::ptr_eq(&self.shared, &ack.shared) {
            self.shared.fail();
            ack.shared.fail();
            return Err(Error::Conflict);
        }
        let i = self.shared.attempt(&ack.attempt)?;
        if !ack.attempt.acknowledged.get()
            || ack.attempt.published.get()
            || self.shared.slots[i].state.get() != State::Creating
        {
            self.shared.fail();
            return Err(Error::Conflict);
        }
        let facts = self
            .shared
            .read_universe()?
            .originals
            .into_iter()
            .find(|f| f.scope == ack.attempt.scope)
            .ok_or(Error::Conflict)?;
        self.shared.slots[i]
            .held
            .borrow_mut()
            .as_mut()
            .ok_or(Error::Pending)?
            .original = Some(facts);
        ack.attempt.published.set(true);
        self.shared.slots[i].state.set(State::Live);
        ack.completed = true;
        Ok(())
    }
    /// Returns the SAME original capability for caller-authorized cleanup. It
    /// never authorizes or invokes native close. Even poison cannot adopt a new
    /// capability or issue this destructive-close seam a second time.
    pub(crate) fn retire(&mut self, scope: &Scope) -> Result<Retirement<N>> {
        self.shared.idle(true)?;
        let i = self.shared.scope(scope)?;
        let slot = &self.shared.slots[i];
        let attempt = slot
            .attempt
            .borrow()
            .as_ref()
            .ok_or(Error::Pending)?
            .clone();
        if &attempt.scope != scope {
            self.shared.fail();
            return Err(Error::Conflict);
        }
        if attempt.retiring.get() {
            return Err(Error::Conflict);
        }
        if !matches!(
            slot.state.get(),
            State::Live | State::Creating | State::Ambiguous
        ) {
            return Err(Error::Pending);
        }
        let native = self.shared.retained(i)?;
        attempt.retiring.set(true);
        slot.state.set(State::Retiring);
        Ok(Retirement {
            shared: self.shared.clone(),
            attempt,
            native,
            completed: false,
        })
    }
    /// Cleanup-only retry of receipt verification/absence; NEVER repeats close.
    pub(crate) fn resume_close(&mut self, scope: &Scope) -> Result<CloseAck<N>> {
        self.shared.idle(true)?;
        let i = self.shared.scope(scope)?;
        let slot = &self.shared.slots[i];
        let attempt = slot
            .attempt
            .borrow()
            .as_ref()
            .ok_or(Error::Pending)?
            .clone();
        if &attempt.scope != scope {
            self.shared.fail();
            return Err(Error::Conflict);
        }
        if slot.state.get() != State::Retiring || attempt.completion.borrow().is_some() {
            return Err(Error::Pending);
        }
        self.shared.close_parts(i)?;
        let nonce = Rc::new(());
        *attempt.completion.borrow_mut() = Some(nonce.clone());
        Ok(CloseAck {
            shared: self.shared.clone(),
            attempt,
            nonce,
            completed: false,
        })
    }
    pub(crate) fn complete_close(
        &mut self,
        mut ack: CloseAck<N>,
        query: &mut impl NativeAbsence,
    ) -> Result<Released<N>> {
        self.shared.idle(true)?;
        if !Rc::ptr_eq(&self.shared, &ack.shared) {
            self.shared.fail();
            ack.shared.fail();
            return Err(Error::Conflict);
        }
        let i = self.shared.attempt(&ack.attempt)?;
        if self.shared.slots[i].state.get() != State::Retiring
            || !ack
                .attempt
                .completion
                .borrow()
                .as_ref()
                .is_some_and(|n| Rc::ptr_eq(n, &ack.nonce))
        {
            self.shared.fail();
            return Err(Error::Conflict);
        }
        let operation = Operation::enter(&self.shared, true)?;
        // Rc clones are PRIVATE retention only. No RefCell borrow crosses any
        // external callback; observers can inspect local state without panic.
        let (native, receipt) = self.shared.close_parts(i)?;
        native.verify_close_receipt(&ack.attempt.scope, &receipt)?;
        operation.check()?;
        absent_facts(
            &ack.attempt.scope,
            query.inspect_absence(&ack.attempt.scope)?,
        )?;
        operation.check()?;
        native.verify_close_receipt(&ack.attempt.scope, &receipt)?;
        operation.finish()?;
        let held = self.shared.slots[i]
            .held
            .borrow_mut()
            .take()
            .ok_or(Error::Pending)?;
        // Keep the captured original and receipt in the returned non-Clone
        // release object through main's independently authorized pin release.
        let released = Released {
            shared: self.shared.clone(),
            attempt: ack.attempt.clone(),
            native: held.native,
            receipt,
            scope: ack.attempt.scope.clone(),
            captured: held.original,
        };
        self.shared.slots[i].state.set(State::Closed);
        ack.attempt.completion.borrow_mut().take();
        ack.completed = true;
        Ok(released)
    }
}
impl<N: OriginalNative> Drop for Producer<N> {
    fn drop(&mut self) {
        self.shared.alive.set(false);
        self.shared.fail();
    }
}
impl<N: OriginalNative> Observer<N> {
    /// Factual SAME raw C handle bracket, not a complete provider universe,
    /// absence proof or effect permission. A/B process-generation publication
    /// cannot recursively read the integrated inventory while renewing it.
    /// Its caller MUST independently query the full mixed SDK universe here.
    /// No mutable/retained native capability escapes; errors/unwind/reentry
    /// permanently poison forward use, preserving original cleanup roots.
    pub(crate) fn inspect_live_carrier_identity<T>(
        &self,
        expected: &Scope,
        inspect: impl FnOnce(&OriginalIdentity) -> Result<T>,
    ) -> Result<T> {
        let operation = Operation::enter(&self.shared, false)?;
        if self.shared.scope(expected)? != 0 || expected.binding.role != Role::RoleCarrier {
            return Err(Error::Conflict);
        }
        // This integrated topology owns only C in the raw creator registry.
        // Member SCM/process roots belong to their independent inventory.
        for slot in &self.shared.slots[1..] {
            if !matches!(slot.state.get(), State::Intent | State::Empty)
                || slot
                    .held
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .is_some()
                || slot
                    .attempt
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .is_some()
            {
                return Err(Error::Conflict);
            }
        }
        let slot = &self.shared.slots[0];
        let attempt = slot
            .attempt
            .try_borrow()
            .map_err(|_| Error::Conflict)?
            .as_ref()
            .ok_or(Error::Pending)?
            .clone();
        let (native, captured) = {
            let held = slot.held.try_borrow().map_err(|_| Error::Conflict)?;
            let held = held.as_ref().ok_or(Error::Pending)?;
            if held.close.is_some() {
                return Err(Error::Conflict);
            }
            (
                held.native.clone(),
                held.original.as_ref().ok_or(Error::Pending)?.clone(),
            )
        };
        let check = || -> Result<()> {
            if slot.state.get() != State::Live
                || attempt.scope != *expected
                || !attempt.acknowledged.get()
                || !attempt.published.get()
                || slot
                    .scope
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .as_ref()
                    != Some(expected)
                || !Rc::ptr_eq(&self.shared.retained(0)?, &native)
            {
                return Err(Error::Conflict);
            }
            self.shared.attempt(&attempt)?;
            operation.check()
        };
        check()?;
        let before = native.original_identity(expected)?;
        if before.scope != *expected
            || before.identity != captured.identity
            || captured.scope != *expected
        {
            return Err(Error::Changed);
        }
        validate_observation(expected, &captured)?;
        operation.check()?;
        let value = inspect(&before)?;
        operation.check()?;
        if native.original_identity(expected)? != before {
            return Err(Error::Changed);
        }
        check()?;
        operation.finish()?;
        Ok(value)
    }
    /// Opaque SAME-registry comparison only. Equal context or original IDs do
    /// not make an independently constructed registry our retained creator.
    pub(crate) fn same_original_registry(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.shared, &other.shared)
    }
    /// Comparison metadata only. No original, absence or native effect proof.
    pub(crate) fn context(&self) -> &Context {
        &self.shared.context
    }
    /// Cleanup-only LOCAL fact, never native absence or effect permission. The
    /// caller must independently prove full native absence under the protected
    /// Closing record, original HKEY and SAME serialized lease. Poison does not
    /// erase an attempted create or rearm this registry for another attempt.
    pub(crate) fn assert_no_creator_for_key_cleanup(
        &self,
        context: &Context,
        binding: &Binding,
    ) -> Result<()> {
        self.shared.idle(true)?;
        let i = self.shared.binding(context, binding)?;
        let slot = &self.shared.slots[i];
        if slot.state.get() == State::Closed {
            return self.assert_closed_for_cleanup(context, binding);
        }
        if !matches!(
            slot.state.get(),
            State::Intent | State::Empty | State::Ambiguous
        ) || slot
            .attempt
            .try_borrow()
            .map_err(|_| Error::Conflict)?
            .is_some()
            || slot
                .held
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .is_some()
        {
            return Err(Error::Pending);
        }
        Ok(())
    }
    /// Factual completed closure only, including after poison. This neither
    /// revives forward absence permission nor authorizes any package effect.
    pub(crate) fn assert_closed_for_cleanup(
        &self,
        context: &Context,
        binding: &Binding,
    ) -> Result<()> {
        self.shared.idle(true)?;
        let i = self.shared.binding(context, binding)?;
        if self.shared.slots[i].state.get() != State::Closed {
            return Err(Error::Pending);
        }
        if self.shared.slots[i]
            .held
            .try_borrow()
            .map_err(|_| {
                self.shared.fail();
                Error::Conflict
            })?
            .is_some()
        {
            self.shared.fail();
            return Err(Error::Conflict);
        }
        Ok(())
    }
    /// Local tombstones only; callable after poison. This is not native proof.
    pub(crate) fn snapshot(&self, context: &Context) -> Result<[State; 3]> {
        if context != &self.shared.context {
            self.shared.fail();
            return Err(Error::Conflict);
        }
        Ok(std::array::from_fn(|i| self.shared.slots[i].state.get()))
    }
    /// Absence of retained originals in THIS same registry. Caller still must
    /// freshly query physical/native absence and authenticate real runtime.
    pub(crate) fn assert_absent(&self, context: &Context, binding: &Binding) -> Result<()> {
        self.shared.idle(false)?;
        let i = self.shared.binding(context, binding)?;
        if !matches!(
            self.shared.slots[i].state.get(),
            State::Empty | State::Closed
        ) {
            return Err(Error::Pending);
        }
        if self.shared.slots[i]
            .held
            .try_borrow()
            .map_err(|_| Error::Conflict)?
            .is_some()
        {
            self.shared.fail();
            return Err(Error::Conflict);
        }
        Ok(())
    }
    /// Read-only pre-key preparation BEFORE any native attempt/generation is
    /// bound. It does NOT transition Intent -> Empty or authorize begin/create.
    /// Unlike bare context metadata, a complete independent native universe is
    /// queried even for zero originals. Any lost ACK/attempt/poison denies this
    /// path forever; callers still independently check exact target absence.
    pub(crate) fn assert_never_attempted(
        &self,
        context: &Context,
        binding: &Binding,
    ) -> Result<()> {
        self.shared.idle(false)?;
        let i = self.shared.binding(context, binding)?;
        let check = || -> Result<()> {
            let slot = &self.shared.slots[i];
            if slot.state.get() != State::Intent
                || slot
                    .scope
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .is_some()
                || slot
                    .attempt
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .is_some()
                || slot
                    .held
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .is_some()
            {
                return Err(Error::Pending);
            }
            Ok(())
        };
        check()?;
        self.shared.read_universe()?;
        self.shared.idle(false)?;
        check()
    }
    pub(crate) fn observe(&self, scope: &Scope) -> Result<Observation<N::Provider>> {
        self.shared.idle(false)?;
        let i = self.shared.scope(scope)?;
        let slot = &self.shared.slots[i];
        if slot.state.get() != State::Live {
            return Err(Error::Pending);
        }
        let expected = slot
            .held
            .try_borrow()
            .map_err(|_| {
                self.shared.fail();
                Error::Conflict
            })?
            .as_ref()
            .and_then(|h| h.original.clone())
            .ok_or(Error::Pending)?;
        if &expected.scope != scope {
            self.shared.fail();
            return Err(Error::Conflict);
        }
        self.shared
            .read_universe()?
            .originals
            .into_iter()
            .find(|f| f.scope == expected.scope)
            .ok_or(Error::Conflict)
    }
    /// Includes C and both AWG members from their ACTUAL retained originals.
    /// Pending intent without ACK is not an original and cannot supply absence;
    /// the native whole-universe query must reject any unexpected actual NIC.
    pub(crate) fn observe_all(
        &self,
        context: &Context,
    ) -> Result<UniverseObservation<N::Provider>> {
        self.shared.idle(false)?;
        if context != &self.shared.context {
            self.shared.fail();
            return Err(Error::Conflict);
        }
        self.shared.read_universe()
    }
    /// Factual cleanup-only full universe from retained raw originals/opaque
    /// once-close receipts. NEVER rearm poison, authorize an effect, or infer
    /// absence for a lost ACK. Caller independently proves protected Closing,
    /// SAME serialized runtime/source/lease and exact cleanup ordering.
    pub(crate) fn observe_all_for_cleanup(
        &self,
        context: &Context,
    ) -> Result<UniverseObservation<N::Provider>> {
        self.shared.idle(true)?;
        if context != &self.shared.context {
            self.shared.fail();
            return Err(Error::Conflict);
        }
        self.shared.read_universe_for(true)
    }
}
impl<N: OriginalNative> Begin<N> {
    /// # Safety
    /// Called ONLY at the original successful NEW native-create return for this
    /// unique pending attempt, with the actual owned acknowledged capability.
    /// Native effects were independently authorized; this method authorizes none.
    pub(crate) unsafe fn acknowledge_original(self, original: N) -> Result<NewCreate<N>> {
        let i = index(self.attempt.scope.binding.role);
        // Retain BEFORE any fallible provider/identity validation. Even late
        // acknowledgement under poison must retain this original for cleanup.
        if self.shared.attempt(&self.attempt).is_err()
            || self.attempt.acknowledged.get()
            || self.shared.slots[i].held.borrow().is_some()
        {
            // This branch needs a forged/repeated unsafe call. Never implicitly
            // destroy a caller's unclosed native capability, even on misuse.
            std::mem::forget(original);
            self.shared.fail();
            return Err(Error::Conflict);
        }
        *self.shared.slots[i].held.borrow_mut() = Some(Held {
            native: Rc::new(original),
            original: None,
            close: None,
        });
        self.attempt.acknowledged.set(true);
        if !self.shared.alive.get() || self.shared.poisoned.get() || self.shared.busy.get() {
            self.shared.fail();
            return Err(Error::Poisoned);
        }
        Ok(NewCreate {
            shared: self.shared.clone(),
            attempt: self.attempt.clone(),
            completed: false,
        })
    }
}
impl<N: OriginalNative> Drop for Begin<N> {
    fn drop(&mut self) {
        if !self.attempt.acknowledged.get() {
            self.shared.fail();
        }
    }
}
impl<N: OriginalNative> Drop for NewCreate<N> {
    fn drop(&mut self) {
        if !self.completed {
            self.shared.fail();
        }
    }
}
impl<N: OriginalNative> Retirement<N> {
    pub(crate) fn original(&self) -> &N {
        &self.native
    }
    pub(crate) fn acknowledge_closed(mut self, receipt: N::CloseReceipt) -> Result<CloseAck<N>> {
        self.shared.idle(true)?;
        let i = self.shared.attempt(&self.attempt)?;
        if self.shared.slots[i].state.get() != State::Retiring
            || self.attempt.completion.borrow().is_some()
        {
            self.shared.fail();
            return Err(Error::Conflict);
        }
        let operation = Operation::enter(&self.shared, true)?;
        let receipt = Rc::new(receipt);
        {
            let mut held = self.shared.slots[i].held.borrow_mut();
            let held = held.as_mut().ok_or(Error::Pending)?;
            if held.close.is_some() {
                return Err(Error::Conflict);
            }
            held.close = Some(receipt.clone());
        }
        self.native
            .verify_close_receipt(&self.attempt.scope, &receipt)?;
        operation.finish()?;
        let nonce = Rc::new(());
        *self.attempt.completion.borrow_mut() = Some(nonce.clone());
        self.completed = true;
        Ok(CloseAck {
            shared: self.shared.clone(),
            attempt: self.attempt.clone(),
            nonce,
            completed: false,
        })
    }
}
impl<N: OriginalNative> Drop for Retirement<N> {
    fn drop(&mut self) {
        if !self.completed {
            self.shared.fail();
        }
    }
}
impl<N: OriginalNative> Drop for CloseAck<N> {
    fn drop(&mut self) {
        if !self.completed {
            self.shared.fail();
            let mut active = self.attempt.completion.borrow_mut();
            if active.as_ref().is_some_and(|n| Rc::ptr_eq(n, &self.nonce)) {
                active.take();
            }
        }
    }
}
impl<N: OriginalNative> Released<N> {
    pub(crate) fn cleanup_read_pin(&self) -> Result<ClosedRead<N>> {
        match (self.attempt.published.get(), self.captured.is_some()) {
            (true, true) => self.read_pin().map(ClosedRead::Published),
            (false, false) => self
                .read_unpublished_closed_pin()
                .map(ClosedRead::Unpublished),
            _ => Err(Error::Conflict),
        }
    }
    /// Pure retention, ONLY for an actual once-closed, never-published C.
    /// Independent current runtime/key/row/network/guard gates remain required.
    pub(crate) fn read_unpublished_closed_pin(&self) -> Result<UnpublishedClosedRead<N>> {
        if self.captured.is_some()
            || self.attempt.published.get()
            || !self.attempt.acknowledged.get()
            || !self.attempt.retiring.get()
            || self.scope.binding.role != Role::RoleCarrier
            || self.scope != self.attempt.scope
            || self.shared.slots[self.shared.attempt(&self.attempt)?]
                .state
                .get()
                != State::Closed
        {
            return Err(Error::Conflict);
        }
        Ok(UnpublishedClosedRead {
            shared: self.shared.clone(),
            attempt: self.attempt.clone(),
            native: self.native.clone(),
            receipt: self.receipt.clone(),
            scope: self.scope.clone(),
        })
    }
    /// Retention only. Acknowledged but never independently captured originals
    /// still must be cleaned up, but cannot invent a former WFP binding.
    pub(crate) fn read_pin(&self) -> Result<RetiredRead<N>> {
        let captured = self.captured.as_ref().ok_or(Error::Pending)?;
        validate_observation(&self.scope, captured)?;
        Ok(RetiredRead {
            shared: self.shared.clone(),
            attempt: self.attempt.clone(),
            native: self.native.clone(),
            receipt: self.receipt.clone(),
            captured: captured.clone(),
            read_frame: Cell::new(None),
            original_cut_busy: Cell::new(false),
        })
    }
    pub(crate) fn original(&self) -> &N {
        &self.native
    }
    pub(crate) fn scope(&self) -> &Scope {
        &self.scope
    }
    pub(crate) fn receipt(&self) -> &N::CloseReceipt {
        &self.receipt
    }
}

impl<N: OriginalNative> UnpublishedClosedRead<N> {
    /// Factual read bracket only. BOTH sides verify the original opaque close
    /// receipt, full independent native universe and exact target absence.
    /// No post-close raw identity read can fabricate publication history.
    pub(crate) fn inspect<T>(
        &self,
        expected: &Scope,
        query: &mut impl NativeAbsence,
        inspect: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.shared.fail();
        let operation = Operation::enter(&self.shared, true)?;
        self.verify_locked(expected, query, &operation)?;
        let result = inspect()?;
        operation.check()?;
        self.verify_locked(expected, query, &operation)?;
        operation.finish()?;
        Ok(result)
    }

    fn verify_locked(
        &self,
        expected: &Scope,
        query: &mut impl NativeAbsence,
        operation: &Operation<N>,
    ) -> Result<()> {
        let i = self.shared.attempt(&self.attempt)?;
        let slot = &self.shared.slots[i];
        if expected != &self.scope
            || self.scope != self.attempt.scope
            || i != 0
            || !self.attempt.acknowledged.get()
            || self.attempt.published.get()
            || !self.attempt.retiring.get()
            || slot.state.get() != State::Closed
            || slot
                .held
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .is_some()
            || slot
                .scope
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .as_ref()
                != Some(expected)
            || self
                .attempt
                .completion
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .is_some()
        {
            return Err(Error::Conflict);
        }
        self.native.verify_close_receipt(expected, &self.receipt)?;
        operation.check()?;
        if !self
            .shared
            .read_universe_locked(true, operation)?
            .originals
            .is_empty()
        {
            return Err(Error::Pending);
        }
        absent_facts(expected, query.inspect_absence(expected)?)?;
        operation.check()?;
        self.native.verify_close_receipt(expected, &self.receipt)?;
        operation.check()
    }
}

impl<N: OriginalNative> RetiredRead<N> {
    /// Fresh factual cleanup only, even after forward revocation. Every read
    /// verifies the SAME actual local completion/receipt, a full native empty
    /// universe AND exact independent target absence under one reentrancy fence.
    /// Does not reopen/query the closed raw interface, remove a base, authorize
    /// effects or clear poison. Errors/unwind retain every opaque original pin.
    pub(crate) fn observe(
        &self,
        query: &mut impl NativeAbsence,
    ) -> Result<RetiredObservation<N::Provider>> {
        // Entering final retired-history cleanup permanently retires ALL
        // forward registry queries, including roles never attempted. Historical
        // success is not permission to start another role in this owner epoch.
        self.shared.fail();
        let operation = Operation::enter(&self.shared, true)?;
        self.verify_history_locked(query, &operation)?;
        operation.finish()?;
        Ok(RetiredObservation {
            captured: self.captured.clone(),
        })
    }
    /// Keep the original owner/reentrancy fence across the WHOLE caller read,
    /// not just the preflight. An ignored nested failure or changed native
    /// absence after that read must deny its result; no forward rearm occurs.
    pub(crate) fn inspect<T>(
        &self,
        query: &mut impl NativeAbsence,
        inspect: impl FnOnce(&RetiredObservation<N::Provider>) -> Result<T>,
    ) -> Result<T> {
        self.shared.fail();
        let operation = Operation::enter(&self.shared, true)?;
        self.verify_history_locked(query, &operation)?;
        if self.read_frame.replace(Some(operation.faults)).is_some() {
            self.shared.fail();
            return Err(Error::Conflict);
        }
        let _frame = RetiredFrame(&self.read_frame);
        let result = inspect(&RetiredObservation {
            captured: self.captured.clone(),
        })?;
        operation.check()?;
        self.verify_history_locked(query, &operation)?;
        operation.finish()?;
        Ok(result)
    }
    /// Borrow the SAME closed original only inside THIS reader's full outer
    /// inspect callback. Busy on a sibling or during universe preflight is not
    /// authorization. This supplies original pins, not an effect grant: native
    /// callers must additionally hold the actual Pair/Runtime/Calling gates.
    pub(crate) fn with_original_closed_in_bracket<T>(
        &self,
        inspect: impl FnOnce(&N, &N::CloseReceipt) -> Result<T>,
    ) -> Result<T> {
        let verify = || {
            let faults = self.read_frame.get().ok_or(Error::Conflict)?;
            if !self.shared.busy.get()
                || !self.shared.alive.get()
                || self.shared.faults.get() != faults
            {
                return Err(Error::Conflict);
            }
            let i = self.shared.attempt(&self.attempt)?;
            let slot = &self.shared.slots[i];
            if slot.state.get() != State::Closed
                || self.attempt.scope != self.captured.scope
                || !self.attempt.acknowledged.get()
                || !self.attempt.published.get()
                || !self.attempt.retiring.get()
                || slot
                    .held
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .is_some()
                || slot
                    .scope
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .as_ref()
                    != Some(&self.captured.scope)
                || self
                    .attempt
                    .completion
                    .try_borrow()
                    .map_err(|_| Error::Conflict)?
                    .is_some()
            {
                return Err(Error::Conflict);
            }
            Ok(())
        };
        verify()?;
        if self.original_cut_busy.replace(true) {
            self.shared.fail();
            return Err(Error::Conflict);
        }
        let mut cut = OriginalCut {
            busy: &self.original_cut_busy,
            shared: &self.shared,
            completed: false,
        };
        let value = inspect(&self.native, &self.receipt)?;
        verify()?;
        cut.completed = true;
        Ok(value)
    }
    fn verify_history_locked(
        &self,
        query: &mut impl NativeAbsence,
        operation: &Operation<N>,
    ) -> Result<()> {
        let scope = &self.captured.scope;
        validate_observation(scope, &self.captured)?;
        let i = self.shared.attempt(&self.attempt)?;
        let slot = &self.shared.slots[i];
        if scope != &self.attempt.scope
            || slot.state.get() != State::Closed
            || slot
                .held
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .is_some()
            || slot
                .scope
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .as_ref()
                != Some(scope)
            || self
                .attempt
                .completion
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .is_some()
        {
            return Err(Error::Conflict);
        }
        self.native.verify_close_receipt(scope, &self.receipt)?;
        operation.check()?;
        let universe = self.shared.read_universe_locked(true, operation)?;
        if !universe.originals.is_empty() {
            return Err(Error::Pending);
        }
        absent_facts(scope, query.inspect_absence(scope)?)?;
        operation.check()?;
        self.native.verify_close_receipt(scope, &self.receipt)?;
        operation.check()
    }
}

#[cfg(test)]
#[path = "member_carrier_creators_tests.rs"]
mod tests;
