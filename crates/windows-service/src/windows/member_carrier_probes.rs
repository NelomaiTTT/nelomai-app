//! Retained original C-source / addressless A-B-egress probe sockets.
//! Comparison tuples are factual values, not grants. Concrete G must supply the
//! required original-runtime/guard/lifecycle authorization before integration.

use crate::{
    member_carrier_guard::{Action, Carrier, Identity, ProbeTuple, Snapshot},
    member_guard::{GuardError, Result},
};
use nelomai_client_tunnel::redundancy::{SessionScope, Slot};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::rc::Rc;

#[derive(Default)]
struct Serial {
    failed: Cell<bool>,
    busy: Cell<bool>,
    tainted: Cell<bool>,
}
struct Call<'a> {
    serial: &'a Serial,
    cleanup: bool,
    succeeded: bool,
}
impl Serial {
    fn call(&self, cleanup: bool) -> Result<Call<'_>> {
        if self.busy.replace(true) {
            self.failed.set(true);
            self.tainted.set(true);
            return Err(GuardError::Conflict);
        }
        if !cleanup && self.failed.get() {
            self.busy.set(false);
            return Err(GuardError::Conflict);
        }
        self.tainted.set(false);
        Ok(Call {
            serial: self,
            cleanup,
            succeeded: false,
        })
    }
}
impl Call<'_> {
    fn verify(&self) -> Result<()> {
        if self.serial.tainted.get() || (!self.cleanup && self.serial.failed.get()) {
            return Err(GuardError::Conflict);
        }
        Ok(())
    }
    fn finish(mut self) -> Result<()> {
        self.verify()?;
        self.succeeded = true;
        Ok(())
    }
}
impl Drop for Call<'_> {
    fn drop(&mut self) {
        if !self.succeeded {
            self.serial.failed.set(true);
        }
        self.serial.busy.set(false);
    }
}

/// This boundary owns the actual socket. Close must preserve it on failure and
/// report success only after a native last-handle close acknowledgement.
trait SocketOwner {
    fn clone_held(&self) -> Result<Self>
    where
        Self: Sized;
    fn close_checked(&mut self) -> Result<()>;
}

struct CloneHandle<S> {
    socket: S,
    live: Rc<Cell<bool>>,
}

// Canonical actor slots are never removed/rearmed, including failed opens and
// acknowledged retirement. A slot is reserved BEFORE any native creation.
struct Entry<T> {
    original: T,
    published: bool,
}
struct Canonical<T> {
    entries: [Option<Entry<T>>; 2],
}
fn slot_index(slot: Slot) -> usize {
    match slot {
        Slot::A => 0,
        Slot::B => 1,
    }
}
impl<T> Canonical<T> {
    fn new() -> Self {
        Self {
            entries: [None, None],
        }
    }
    fn begin(&mut self, slot: Slot, original: T) -> Result<()> {
        let entry = &mut self.entries[slot_index(slot)];
        if entry.is_some() {
            return Err(GuardError::Conflict);
        }
        *entry = Some(Entry {
            original,
            published: false,
        });
        Ok(())
    }
    fn publish(&mut self, slot: Slot) -> Result<()> {
        let entry = self.entries[slot_index(slot)]
            .as_mut()
            .ok_or(GuardError::Conflict)?;
        if entry.published {
            return Err(GuardError::Conflict);
        }
        entry.published = true;
        Ok(())
    }
    fn unpublished(&self) -> impl Iterator<Item = &T> {
        self.entries
            .iter()
            .flatten()
            .filter(|e| !e.published)
            .map(|e| &e.original)
    }
    fn all(&self) -> impl Iterator<Item = &T> {
        self.entries.iter().flatten().map(|e| &e.original)
    }
    fn by_slot(&self) -> [Option<&T>; 2] {
        self.entries
            .each_ref()
            .map(|entry| entry.as_ref().map(|e| &e.original))
    }
}

// Private witness constructed ONLY after all clone and base close ACKs. It is
// neither a lifecycle request nor independently importable metadata.
struct Closed;

struct Held<S: SocketOwner, C> {
    socket: Option<S>,
    caps: Option<C>,
    clones: BTreeMap<u64, CloneHandle<S>>,
    next_clone: u64,
    revoked: bool,
    closed: Option<Closed>,
}
impl<S: SocketOwner, C> Held<S, C> {
    fn new(socket: S, caps: C) -> Self {
        Self {
            socket: Some(socket),
            caps: Some(caps),
            clones: BTreeMap::new(),
            next_clone: 0,
            revoked: false,
            closed: None,
        }
    }
    fn pending() -> Self {
        Self {
            socket: None,
            caps: None,
            clones: BTreeMap::new(),
            next_clone: 0,
            revoked: false,
            closed: None,
        }
    }
    fn retired(&self) -> Result<&Closed> {
        if self.socket.is_some() || !self.clones.is_empty() {
            return Err(GuardError::RemovalUnconfirmed);
        }
        self.closed.as_ref().ok_or(GuardError::RemovalUnconfirmed)
    }
    #[cfg(test)]
    fn clone_held(&mut self) -> Result<u64> {
        if self.revoked {
            return Err(GuardError::Conflict);
        }
        let id = self.next_clone.checked_add(1).ok_or(GuardError::Conflict)?;
        let clone = self
            .socket
            .as_ref()
            .ok_or(GuardError::Conflict)?
            .clone_held()?;
        // The acknowledged handle is retained before any further read/callback.
        self.clones.insert(
            id,
            CloneHandle {
                socket: clone,
                live: Rc::new(Cell::new(true)),
            },
        );
        self.next_clone = id;
        Ok(id)
    }
    fn retire_clone(&mut self, id: u64) -> Result<()> {
        let clone = self.clones.get_mut(&id).ok_or(GuardError::Conflict)?;
        clone.live.set(false);
        clone.socket.close_checked()?;
        self.clones.remove(&id);
        Ok(())
    }
    fn retire_orphans_after_withdrawal(&mut self) -> Result<()> {
        let ids: Vec<_> = self
            .clones
            .iter()
            .filter_map(|(id, clone)| (!clone.live.get()).then_some(*id))
            .collect();
        for id in ids {
            self.retire_clone(id)?;
        }
        Ok(())
    }
    fn release_after_withdrawal(&mut self) -> Result<()> {
        if !self.clones.is_empty() {
            return Err(GuardError::RemovalUnconfirmed);
        }
        self.socket
            .as_mut()
            .ok_or(GuardError::Conflict)?
            .close_checked()?;
        self.socket.take();
        self.revoked = true;
        self.closed = Some(Closed);
        Ok(())
    }
}
impl<S: SocketOwner, C> Drop for Held<S, C> {
    fn drop(&mut self) {
        if let Some(socket) = self.socket.take() {
            // An error/unwind/owner drop is NOT proof of allow absence. Keep the
            // exclusive socket AND original source/guard caps until process exit.
            std::mem::forget(socket);
            for (_, clone) in std::mem::take(&mut self.clones) {
                std::mem::forget(clone.socket);
            }
            if let Some(caps) = self.caps.take() {
                std::mem::forget(caps);
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Facts {
    scope: SessionScope,
    carrier: Option<Carrier>,
    egress: [Option<Identity>; 2],
}
#[derive(Clone, PartialEq, Eq)]
struct Expected {
    scope: SessionScope,
    carrier: Carrier,
    egress: Identity,
    slot: Slot,
    source: Ipv4Addr,
    target: Ipv4Addr,
}
impl Expected {
    fn from_facts(bindings: &Facts, slot: Slot, target: Ipv4Addr) -> Result<Self> {
        let carrier = bindings.carrier.as_ref().ok_or(GuardError::Conflict)?;
        // Validate the whole observed inventory before selected-slot use.
        crate::member_carrier_guard::validate_factual_bindings(
            &bindings.scope,
            Some(carrier),
            bindings.egress.each_ref().map(Option::as_ref),
        )?;
        let index = match slot {
            Slot::A => 0,
            Slot::B => 1,
        };
        let egress = bindings.egress[index]
            .as_ref()
            .ok_or(GuardError::Conflict)?;
        let [IpAddr::V4(source)] = carrier.sources.as_slice() else {
            return Err(GuardError::Invalid);
        };
        if !bindings.scope.validate()
            || carrier.identity.scope != bindings.scope
            || egress.scope != bindings.scope
            || carrier.identity.proof == egress.proof
            || carrier.identity.proof.index == 0
            || egress.proof.index == 0
            || source.is_unspecified()
            || source.is_loopback()
            || source.is_multicast()
            || source.is_broadcast()
            || target.is_unspecified()
            || target.is_loopback()
            || target.is_multicast()
            || target.is_broadcast()
        {
            return Err(GuardError::Invalid);
        }
        Ok(Self {
            scope: bindings.scope.clone(),
            carrier: carrier.clone(),
            egress: egress.clone(),
            slot,
            source: *source,
            target,
        })
    }
    fn matches_facts(&self, bindings: &Facts) -> Result<()> {
        if *self != Self::from_facts(bindings, self.slot, self.target)? {
            return Err(GuardError::Conflict);
        }
        Ok(())
    }
    // Comparison-only read; the actual native caller must bracket it in the
    // SAME Source window and retain the original socket/publication ACK.
    fn read_tuple(
        &self,
        bindings: &Facts,
        acknowledged: &ProbeTuple,
        read: impl FnOnce() -> Result<ProbeTuple>,
    ) -> Result<ProbeTuple> {
        self.matches_facts(bindings)?;
        let actual = read()?;
        if &actual != acknowledged {
            return Err(GuardError::Conflict);
        }
        Ok(actual)
    }
}

fn snapshot_matches(bindings: &Facts, snapshot: &Snapshot, no_allows: bool) -> Result<()> {
    if snapshot.version != 2
        || snapshot.scope != bindings.scope
        || snapshot.carrier != bindings.carrier
        || snapshot.egress != bindings.egress
        || (no_allows && snapshot.filters.iter().any(|f| f.action == Action::Permit))
    {
        return Err(GuardError::RemovalUnconfirmed);
    }
    Ok(())
}

fn open_snapshot(bindings: &Facts, snapshot: &Snapshot) -> Result<()> {
    snapshot_matches(bindings, snapshot, true)
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::{
        member_carrier_guard::{ProbeTuple, SplitEngines},
        windows::{
            member_carrier_guard::{BindingAttestor, Bindings, NativeApi, NativeGuard},
            member_carrier_runtime::native::{
                NativeBindingsWindow, NativeClosingRead, NativeSourceRead,
            },
            member_carrier_wintun::Error as SourceError,
        },
    };
    use nelomai_client_tunnel::redundancy::{NativeProbeSocket, ProbeDatagram};
    use std::{cell::RefCell, io, rc::Rc};

    /// Required concrete-G integration seam, NOT implemented in this module.
    ///
    /// # Safety
    /// `N` MUST be the actual SDK-backed original WFP engines, NEVER a fake,
    /// snapshot-only adapter or model store. It is generic only because the
    /// actual Wfp type currently lives in a private child of the guard module;
    /// main must specialize this unsafe seam to that actual backend.
    /// Verify the SAME original source and original guard registration (opaque
    /// pins, actual RuntimeRead/KeyLock/supervisor and native context), not equal
    /// numeric/JSON metadata. `verify_closing` additionally requires the SAME
    /// original runtime's current protected Closing, correct withdrawal/probe
    /// stage BEFORE network/DNS restoration, and actual cleanup
    /// bindings. No successful defaults or production test gate are provided.
    /// `authorize_use` must independently check current protected lifecycle,
    /// actual bases/priority/permits, route/DNS/endpoint ownership and original
    /// held-port registration before each send/receive. The supplied read pin is
    /// opaque original identity; tuple data alone is never authorization. Do not
    /// recursively inspect this owner while authorizing its serialized call.
    /// `verify_inventory` MUST match the one registered opaque inventory pin
    /// for this actor, as well as the SAME actual source/guard/G. Equal bindings
    /// or constructing another inventory with those caps NEVER authorize it.
    /// `verify_preparing` requires current protected Preparing at the exact
    /// withdrawal/retirement stage, BEFORE row/member rebinding. It is NOT a
    /// Closing substitute: a revoked Source cannot be revived through this API.
    pub(crate) unsafe trait NativeProbeGate<N: NativeApi, A: BindingAttestor>:
        Sized
    {
        fn verify_inventory(&self, inventory: &ProbeInventoryRead<N, A, Self>) -> Result<()>;
        /// Exact protected HoldProbe/new-operation stage, SAME registered native
        /// generation and actual Calling deadline, bases/priority/no ANY permits
        /// and exact original C/egress/endpoint/plan. Use the borrowed original
        /// window for joined SDK reads, NEVER recurse into Source.inspect. This
        /// is required immediately before creation AND before publication; a
        /// constructor/registration or equal tuple is not a new-port grant.
        fn authorize_open(
            &self,
            inventory: &ProbeInventoryRead<N, A, Self>,
            window: &NativeBindingsWindow<'_>,
            slot: Slot,
            target: Ipv4Addr,
        ) -> Result<()>;
        fn verify_original(
            &self,
            source: &Rc<NativeSourceRead>,
            guard: &Rc<RefCell<NativeGuard<N, A>>>,
        ) -> Result<()>;
        fn authorize_use(
            &self,
            original: &HeldProbeRead<N, A, Self>,
            tuple: &ProbeTuple,
        ) -> Result<()>;
        fn verify_closing(
            &self,
            source: &Rc<NativeSourceRead>,
            guard: &Rc<RefCell<NativeGuard<N, A>>>,
            closing: &NativeClosingRead,
        ) -> Result<()>;
        fn verify_preparing(
            &self,
            source: &Rc<NativeSourceRead>,
            guard: &Rc<RefCell<NativeGuard<N, A>>>,
        ) -> Result<()>;
    }

    fn facts(b: &Bindings) -> Facts {
        Facts {
            scope: b.scope.clone(),
            carrier: b.carrier.clone(),
            egress: b.egress.clone(),
        }
    }
    impl Expected {
        fn from_actual(b: &Bindings, slot: Slot, target: Ipv4Addr) -> Result<Self> {
            Self::from_facts(&facts(b), slot, target)
        }
        fn matches(&self, b: &Bindings) -> Result<()> {
            self.matches_facts(&facts(b))
        }
        fn tuple(&self, socket: &NativeSocket) -> Result<ProbeTuple> {
            let local = socket
                .0
                .as_ref()
                .ok_or(GuardError::Conflict)?
                .attest_binding(self.egress.proof.index, self.source, self.target)
                .map_err(native_error)?;
            Ok(ProbeTuple {
                source: local.ip().to_owned().into(),
                source_port: local.port(),
                target: self.target.into(),
                target_port: 53,
                protocol: 17,
            })
        }
    }
    fn exact_snapshot(b: &Bindings, snapshot: &Snapshot, no_allows: bool) -> Result<()> {
        snapshot_matches(&facts(b), snapshot, no_allows)
    }
    fn native_error(_: io::Error) -> GuardError {
        GuardError::Conflict
    }
    fn source_error(_: SourceError) -> GuardError {
        GuardError::Conflict
    }
    fn denied(_: GuardError) -> SourceError {
        SourceError::Conflict
    }

    struct NativeSocket(Option<NativeProbeSocket>);
    impl SocketOwner for NativeSocket {
        fn clone_held(&self) -> Result<Self> {
            self.0
                .as_ref()
                .ok_or(GuardError::Conflict)?
                .try_clone()
                .map(|s| Self(Some(s)))
                .map_err(native_error)
        }
        fn close_checked(&mut self) -> Result<()> {
            let socket = self.0.take().ok_or(GuardError::Conflict)?;
            match socket.close_checked() {
                Ok(()) => Ok(()),
                Err((socket, _)) => {
                    self.0 = Some(socket);
                    Err(GuardError::RemovalUnconfirmed)
                }
            }
        }
    }
    struct Caps<N: NativeApi, A: BindingAttestor, G: NativeProbeGate<N, A>> {
        source: Rc<NativeSourceRead>,
        guard: Rc<RefCell<NativeGuard<N, A>>>,
        gate: Rc<G>,
        expected: Expected,
        tuple: Option<ProbeTuple>,
    }
    struct Original<N: NativeApi, A: BindingAttestor, G: NativeProbeGate<N, A>> {
        held: RefCell<Held<NativeSocket, Caps<N, A, G>>>,
        serial: Serial,
    }
    impl<N: NativeApi, A: BindingAttestor, G: NativeProbeGate<N, A>> Original<N, A, G> {
        fn tuple_in_window(&self, window: &NativeBindingsWindow<'_>) -> Result<ProbeTuple> {
            let call = self.serial.call(false)?;
            let held = self.held.try_borrow().map_err(|_| GuardError::Conflict)?;
            let caps = held.caps.as_ref().ok_or(GuardError::Conflict)?;
            if held.revoked {
                return Err(GuardError::Conflict);
            }
            caps.gate.verify_original(&caps.source, &caps.guard)?;
            // Never open Source.inspect inside its own callback. This borrowed
            // window brackets ALL actual C/A/B/protected/SDK facts and taints
            // its outer actor if a joined read fails, even when G catches it.
            let tuple = window
                .inspect(|b| {
                    if !window.matches_source(&caps.source) {
                        return Err(SourceError::Conflict);
                    }
                    caps.expected
                        .read_tuple(
                            &facts(b),
                            caps.tuple.as_ref().ok_or(SourceError::Conflict)?,
                            || {
                                caps.expected
                                    .tuple(held.socket.as_ref().ok_or(GuardError::Conflict)?)
                            },
                        )
                        .map_err(denied)
                })
                .map_err(source_error)?;
            caps.gate.verify_original(&caps.source, &caps.guard)?;
            call.finish()?;
            Ok(tuple)
        }
        fn tuple(&self, clone: Option<u64>) -> Result<ProbeTuple> {
            let call = self.serial.call(false)?;
            let held = self.held.try_borrow().map_err(|_| GuardError::Conflict)?;
            let caps = held.caps.as_ref().ok_or(GuardError::Conflict)?;
            if held.revoked {
                return Err(GuardError::Conflict);
            }
            caps.gate.verify_original(&caps.source, &caps.guard)?;
            let tuple = caps
                .source
                .inspect_bindings(|b| {
                    caps.expected.matches(b).map_err(denied)?;
                    let socket = match clone {
                        None => held.socket.as_ref(),
                        Some(id) => held
                            .clones
                            .get(&id)
                            .filter(|c| c.live.get())
                            .map(|c| &c.socket),
                    }
                    .ok_or(SourceError::Conflict)?;
                    let tuple = caps.expected.tuple(socket).map_err(denied)?;
                    if Some(&tuple) != caps.tuple.as_ref() {
                        return Err(SourceError::Conflict);
                    }
                    Ok(tuple)
                })
                .map_err(source_error)?;
            caps.gate.verify_original(&caps.source, &caps.guard)?;
            call.finish()?;
            Ok(tuple)
        }
    }

    struct Inventory<N: NativeApi, A: BindingAttestor, G: NativeProbeGate<N, A>> {
        source: Rc<NativeSourceRead>,
        guard: Rc<RefCell<NativeGuard<N, A>>>,
        gate: Rc<G>,
        entries: RefCell<Canonical<Rc<Original<N, A, G>>>>,
        serial: Serial,
    }
    /// Sole per-actor canonical registry. No Clone/Serialize/adoption; !Send/Sync.
    /// Construction retains caps only. G must register this exact read pin before
    /// open; construction/equal models confer no port/effect permission.
    pub(crate) struct ProbeInventory<N: NativeApi, A: BindingAttestor, G: NativeProbeGate<N, A>> {
        inventory: Rc<Inventory<N, A, G>>,
    }
    pub(crate) struct ProbeInventoryRead<N: NativeApi, A: BindingAttestor, G: NativeProbeGate<N, A>> {
        inventory: Rc<Inventory<N, A, G>>,
    }
    /// G retains this non-owning registration; the actor retains the actual
    /// inventory. The inventory itself retains G, so a strong back-reference
    /// would leak the entire original resource graph after acknowledged Stop.
    pub(crate) struct ProbeInventoryWeakRead<
        N: NativeApi,
        A: BindingAttestor,
        G: NativeProbeGate<N, A>,
    > {
        original: crate::windows::member_carrier_original_read::OriginalRead<Inventory<N, A, G>>,
    }
    impl<N: NativeApi, A: BindingAttestor, G: NativeProbeGate<N, A>> ProbeInventoryWeakRead<N, A, G> {
        pub(crate) fn upgrade(&self) -> Result<ProbeInventoryRead<N, A, G>> {
            Ok(ProbeInventoryRead {
                inventory: self.original.upgrade().ok_or(GuardError::Conflict)?,
            })
        }
    }
    /// Opaque SAME-original closed witness. Only actual cloned/base close ACKs
    /// create it; no bool/numeric/import/constructor-based retirement grant.
    pub(crate) struct RetiredProbeRead<N: NativeApi, A: BindingAttestor, G: NativeProbeGate<N, A>> {
        original: Rc<Original<N, A, G>>,
    }
    /// Published alias to the inventory's SAME original (not a second owner).
    /// No Clone/Serialize/raw-handle/socket escape.
    pub(crate) struct HeldProbeOwner<N: NativeApi, A: BindingAttestor, G: NativeProbeGate<N, A>> {
        original: Rc<Original<N, A, G>>,
    }
    /// Opaque factual read pin, not an independently reopened socket or grant.
    pub(crate) struct HeldProbeRead<N: NativeApi, A: BindingAttestor, G: NativeProbeGate<N, A>> {
        original: Rc<Original<N, A, G>>,
    }
    /// Actual duplicate handle to the SAME socket, retained in the original
    /// owner. Its last close is acknowledged or remains an orphan obligation.
    pub(crate) struct HeldProbeLease<N: NativeApi, A: BindingAttestor, G: NativeProbeGate<N, A>> {
        original: Rc<Original<N, A, G>>,
        id: u64,
        live: Rc<Cell<bool>>,
    }

    #[derive(Clone, Copy)]
    enum ReleasePhase<'a> {
        Closing(&'a NativeClosingRead),
        Preparing,
    }
    impl ReleasePhase<'_> {
        fn verify<N: NativeApi, A: BindingAttestor, G: NativeProbeGate<N, A>>(
            self,
            caps: &Caps<N, A, G>,
        ) -> Result<()> {
            match self {
                Self::Closing(closing) => {
                    caps.gate.verify_closing(&caps.source, &caps.guard, closing)
                }
                Self::Preparing => caps.gate.verify_preparing(&caps.source, &caps.guard),
            }
        }
        fn inspect<N: NativeApi, A: BindingAttestor, G: NativeProbeGate<N, A>>(
            self,
            caps: &Caps<N, A, G>,
            snapshot: &Snapshot,
        ) -> Result<()> {
            let inspect = |b: &Bindings| {
                caps.expected.matches(b).map_err(denied)?;
                exact_snapshot(b, snapshot, true).map_err(denied)
            };
            match self {
                Self::Closing(closing) => closing.inspect_bindings(inspect),
                Self::Preparing => caps.source.inspect_bindings(inspect),
            }
            .map_err(source_error)
        }
    }

    impl<N: NativeApi, A: BindingAttestor, G: NativeProbeGate<N, A>> ProbeInventory<N, A, G> {
        pub(crate) fn new(
            source: Rc<NativeSourceRead>,
            guard: Rc<RefCell<NativeGuard<N, A>>>,
            gate: Rc<G>,
        ) -> Result<Self> {
            gate.verify_original(&source, &guard)?;
            Ok(Self {
                inventory: Rc::new(Inventory {
                    source,
                    guard,
                    gate,
                    entries: RefCell::new(Canonical::new()),
                    serial: Serial::default(),
                }),
            })
        }
        pub(crate) fn read_pin(&self) -> ProbeInventoryRead<N, A, G> {
            ProbeInventoryRead {
                inventory: self.inventory.clone(),
            }
        }
        /// Sole actual socket constructor. Even a pre-ACK failure permanently
        /// consumes this slot. Post-ACK failures leave a canonical unpublished
        /// object retrievable for protected cleanup, without process restart.
        pub(crate) fn open(
            &mut self,
            slot: Slot,
            target: Ipv4Addr,
        ) -> Result<HeldProbeOwner<N, A, G>> {
            let call = self.inventory.serial.call(false)?;
            let original = Rc::new(Original {
                held: RefCell::new(Held::pending()),
                serial: Serial::default(),
            });
            // Canonical entry exists BEFORE the first fallible source/gate read
            // or native ACK. Never remove it, including after a failed attempt.
            self.inventory
                .entries
                .try_borrow_mut()
                .map_err(|_| GuardError::Conflict)?
                .begin(slot, original.clone())?;
            let creation = original.serial.call(false)?;
            let source = &self.inventory.source;
            let guard = &self.inventory.guard;
            let gate = &self.inventory.gate;
            gate.verify_inventory(&self.read_pin())?;
            gate.verify_original(source, guard)?;
            let snapshot = guard
                .try_borrow_mut()
                .map_err(|_| GuardError::Conflict)?
                .snapshot()
                .inspect_err(|_error| {
                    #[cfg(all(test, windows))]
                    eprintln!("actual native probe open guard slot={slot:?}: {_error:?}");
                })?;
            source
                .inspect_window(|window| {
                    let b = window.bindings();
                    open_snapshot(&facts(b), &snapshot)
                        .map_err(denied)
                        .inspect_err(|_error| {
                            #[cfg(all(test, windows))]
                            eprintln!(
                                "actual native probe open snapshot slot={slot:?}: {_error:?}"
                            );
                        })?;
                    let expected = Expected::from_actual(b, slot, target)
                        .map_err(denied)
                        .inspect_err(|_error| {
                            #[cfg(all(test, windows))]
                            eprintln!(
                                "actual native probe open expected slot={slot:?}: {_error:?}"
                            );
                        })?;
                    // Acquire the canonical destination and all caps BEFORE
                    // creating the socket, so no fallible borrow follows ACK.
                    let mut held = original
                        .held
                        .try_borrow_mut()
                        .map_err(|_| SourceError::Conflict)?;
                    let caps = Caps {
                        source: source.clone(),
                        guard: guard.clone(),
                        gate: gate.clone(),
                        expected,
                        tuple: None,
                    };
                    creation.verify().map_err(denied)?;
                    call.verify().map_err(denied)?;
                    gate.authorize_open(&self.read_pin(), window, slot, target)
                        .map_err(denied)
                        .inspect_err(|_error| {
                            #[cfg(all(test, windows))]
                            eprintln!(
                                "actual native probe open preSDK gate slot={slot:?}: {_error:?}"
                            );
                        })?;
                    let socket = NativeProbeSocket::open(
                        caps.expected.egress.proof.index,
                        caps.expected.source,
                        caps.expected.target,
                    )
                    .inspect_err(|_error| {
                        #[cfg(all(test, windows))]
                        eprintln!("actual native probe open socket slot={slot:?}: {_error:?}");
                    })
                    .map_err(|_| SourceError::Native)?;
                    // ACK retained canonically BEFORE tuple/readback/postflight.
                    *held = Held::new(NativeSocket(Some(socket)), caps);
                    #[cfg(all(test, windows))]
                    eprintln!("actual native probe open SDK ACK retained slot={slot:?}");
                    let actual = held
                        .caps
                        .as_ref()
                        .ok_or(SourceError::Conflict)?
                        .expected
                        .tuple(held.socket.as_ref().ok_or(SourceError::Conflict)?)
                        .map_err(denied)
                        .inspect_err(|_error| {
                            #[cfg(all(test, windows))]
                            eprintln!(
                                "actual native probe open first tuple slot={slot:?}: {_error:?}"
                            );
                        })?;
                    let caps = held.caps.as_mut().ok_or(SourceError::Conflict)?;
                    caps.tuple = Some(actual);
                    creation.verify().map_err(denied)?;
                    Ok(())
                })
                .map_err(source_error)
                .inspect_err(|_error| {
                    #[cfg(all(test, windows))]
                    eprintln!("actual native probe open source slot={slot:?}: {_error:?}");
                })?;
            gate.verify_original(source, guard)?;
            let after = guard
                .try_borrow_mut()
                .map_err(|_| GuardError::Conflict)?
                .snapshot()
                .inspect_err(|_error| {
                    #[cfg(all(test, windows))]
                    eprintln!("actual native probe open postguard slot={slot:?}: {_error:?}");
                })?;
            source
                .inspect_window(|window| {
                    open_snapshot(&facts(window.bindings()), &after).map_err(denied)?;
                    gate.authorize_open(&self.read_pin(), window, slot, target)
                        .map_err(denied)
                })
                .map_err(source_error)
                .inspect_err(|_error| {
                    #[cfg(all(test, windows))]
                    eprintln!("actual native probe open postgate slot={slot:?}: {_error:?}");
                })?;
            gate.verify_inventory(&self.read_pin())?;
            creation.finish()?;
            original.tuple(None).inspect_err(|_error| {
                #[cfg(all(test, windows))]
                eprintln!("actual native probe open final tuple slot={slot:?}: {_error:?}");
            })?;
            call.verify()?;
            self.inventory
                .entries
                .try_borrow_mut()
                .map_err(|_| GuardError::Conflict)?
                .publish(slot)
                .inspect_err(|_error| {
                    #[cfg(all(test, windows))]
                    eprintln!("actual native probe open publish slot={slot:?}: {_error:?}");
                })?;
            call.finish()?;
            Ok(HeldProbeOwner { original })
        }
        /// Cleanup only unpublished ACKs from this inventory. Published aliases
        /// remain their own explicit obligations; failed/empty slots never rearm.
        pub(crate) fn release_unpublished(
            &mut self,
            closing: &NativeClosingRead,
        ) -> Result<Vec<RetiredProbeRead<N, A, G>>> {
            self.release_inventory(ReleasePhase::Closing(closing))
        }
        /// Healthy SAME Source Preparing only. A Source-postflight failure may
        /// irrevocably revoke Live reads, in which case this refuses and the real
        /// protected Closing cleanup pin is required. Never fake Closing.
        pub(crate) fn release_unpublished_preparing(
            &mut self,
        ) -> Result<Vec<RetiredProbeRead<N, A, G>>> {
            self.release_inventory(ReleasePhase::Preparing)
        }
        fn release_inventory(
            &mut self,
            phase: ReleasePhase<'_>,
        ) -> Result<Vec<RetiredProbeRead<N, A, G>>> {
            let call = self.inventory.serial.call(true)?;
            self.inventory.gate.verify_inventory(&self.read_pin())?;
            let entries = self
                .inventory
                .entries
                .try_borrow()
                .map_err(|_| GuardError::Conflict)?;
            let originals: Vec<_> = entries.unpublished().cloned().collect();
            drop(entries);
            let mut retired = Vec::new();
            for original in originals {
                let has_ack = original
                    .held
                    .try_borrow()
                    .map_err(|_| GuardError::Conflict)?
                    .caps
                    .is_some();
                if has_ack {
                    retired.push(HeldProbeOwner { original }.release_in(phase)?);
                }
            }
            call.finish()?;
            Ok(retired)
        }
    }
    impl<N: NativeApi, A: BindingAttestor, G: NativeProbeGate<N, A>> HeldProbeOwner<N, A, G> {
        pub(crate) fn read_pin(&self) -> HeldProbeRead<N, A, G> {
            HeldProbeRead {
                original: self.original.clone(),
            }
        }
        pub(crate) fn lease(&mut self) -> Result<HeldProbeLease<N, A, G>> {
            self.original.tuple(None)?;
            let call = self.original.serial.call(false)?;
            let mut held = self
                .original
                .held
                .try_borrow_mut()
                .map_err(|_| GuardError::Conflict)?;
            // Borrow disjoint fields for actual SourceFence over clone creation.
            let Held {
                socket,
                caps,
                clones,
                next_clone,
                revoked,
                ..
            } = &mut *held;
            if *revoked {
                return Err(GuardError::Conflict);
            }
            let caps = caps.as_ref().ok_or(GuardError::Conflict)?;
            let id = next_clone.checked_add(1).ok_or(GuardError::Conflict)?;
            let live = Rc::new(Cell::new(false));
            caps.source
                .inspect_bindings(|b| {
                    caps.expected.matches(b).map_err(denied)?;
                    let clone = socket
                        .as_ref()
                        .ok_or(SourceError::Conflict)?
                        .clone_held()
                        .map_err(denied)?;
                    clones.insert(
                        id,
                        CloneHandle {
                            socket: clone,
                            live: live.clone(),
                        },
                    ); // ACK retained first.
                    *next_clone = id;
                    let actual = caps
                        .expected
                        .tuple(&clones.get(&id).ok_or(SourceError::Conflict)?.socket)
                        .map_err(denied)?;
                    if Some(&actual) != caps.tuple.as_ref() {
                        return Err(SourceError::Conflict);
                    }
                    Ok(())
                })
                .map_err(source_error)?;
            caps.gate.verify_original(&caps.source, &caps.guard)?;
            call.verify()?;
            clones.get(&id).ok_or(GuardError::Conflict)?.live.set(true);
            call.finish()?;
            Ok(HeldProbeLease {
                original: self.original.clone(),
                id,
                live,
            })
        }
        /// Caller must use the actual SAME-runtime Closing pin. Both independent
        /// original-guard snapshots are freshly read with all scope keys/IDs;
        /// zero ANY permits required BEFORE orphan/base socket close. A close
        /// request alone cannot be returned as success. No BFE mutation API is
        /// exposed here; the actual guard's existing fail-stop can run down its
        /// own dynamic session on a failed independent read.
        pub(crate) fn release(
            &mut self,
            closing: &NativeClosingRead,
        ) -> Result<RetiredProbeRead<N, A, G>> {
            self.release_in(ReleasePhase::Closing(closing))
        }
        /// Requires SAME source's current healthy protected Preparing and G's
        /// actual retirement stage, no ANY permits, exact old bindings BEFORE
        /// rebind. A revoked source/pending rebinding is explicitly unsupported;
        /// never reconstruct Closing from equal metadata to permit release.
        pub(crate) fn release_preparing(&mut self) -> Result<RetiredProbeRead<N, A, G>> {
            self.release_in(ReleasePhase::Preparing)
        }
        fn release_in(&mut self, phase: ReleasePhase<'_>) -> Result<RetiredProbeRead<N, A, G>> {
            let call = self.original.serial.call(true)?;
            let mut held = self
                .original
                .held
                .try_borrow_mut()
                .map_err(|_| GuardError::Conflict)?;
            // Partial cleanup retry: prior close ACK is permanent factual proof,
            // not another native effect/readiness grant. No re-open is possible.
            if held.retired().is_ok() {
                call.finish()?;
                return Ok(RetiredProbeRead {
                    original: self.original.clone(),
                });
            }
            let caps = held.caps.as_ref().ok_or(GuardError::Conflict)?;
            phase.verify(caps)?;
            call.verify()?;
            let before = caps
                .guard
                .try_borrow_mut()
                .map_err(|_| GuardError::Conflict)?
                .snapshot()?;
            phase.inspect(caps, &before)?;
            let after = caps
                .guard
                .try_borrow_mut()
                .map_err(|_| GuardError::Conflict)?
                .snapshot()?;
            if before != after {
                return Err(GuardError::RemovalUnconfirmed);
            }
            phase.inspect(caps, &after)?;
            phase.verify(caps)?;
            call.verify()?;
            held.revoked = true;
            held.retire_orphans_after_withdrawal()?;
            held.release_after_withdrawal()?;
            call.finish()?;
            Ok(RetiredProbeRead {
                original: self.original.clone(),
            })
            // Native closesocket ACK, not full port/route/native absence.
        }
    }
    impl<N: NativeApi, A: BindingAttestor, G: NativeProbeGate<N, A>> ProbeInventoryRead<N, A, G> {
        pub(crate) fn downgrade(&self) -> ProbeInventoryWeakRead<N, A, G> {
            ProbeInventoryWeakRead {
                original: crate::windows::member_carrier_original_read::OriginalRead::from_retained(
                    &self.inventory,
                ),
            }
        }
        pub(crate) fn pin(&self) -> Self {
            Self {
                inventory: self.inventory.clone(),
            }
        }
        /// Opaque identity only. Concrete G must compare its registered original
        /// pin, never accept a newly constructed inventory with equal caps.
        pub(crate) fn same_inventory(&self, other: &Self) -> bool {
            Rc::ptr_eq(&self.inventory, &other.inventory)
        }
        pub(crate) fn matches_caps(
            &self,
            source: &Rc<NativeSourceRead>,
            guard: &Rc<RefCell<NativeGuard<N, A>>>,
            gate: &Rc<G>,
        ) -> Result<()> {
            if Rc::ptr_eq(source, &self.inventory.source)
                && Rc::ptr_eq(guard, &self.inventory.guard)
                && Rc::ptr_eq(gate, &self.inventory.gate)
            {
                Ok(())
            } else {
                Err(GuardError::Conflict)
            }
        }
        /// Enumerates canonical actual ACKs, including unpublished failed opens.
        /// No nested Source reads; facts/grants are not manufactured here.
        pub(crate) fn originals(&self) -> Result<Vec<HeldProbeRead<N, A, G>>> {
            let entries = self
                .inventory
                .entries
                .try_borrow()
                .map_err(|_| GuardError::Conflict)?;
            let mut reads = Vec::new();
            for original in entries.all() {
                if original
                    .held
                    .try_borrow()
                    .map_err(|_| GuardError::Conflict)?
                    .caps
                    .is_some()
                {
                    reads.push(HeldProbeRead {
                        original: original.clone(),
                    });
                }
            }
            Ok(reads)
        }
        /// Actual canonical slot identity, independent of equal tuple metadata
        /// and including unpublished ACKs. A reserved pre-ACK slot remains
        /// consumed even though it has no socket read pin yet.
        pub(crate) fn originals_by_slot(&self) -> Result<[Option<HeldProbeRead<N, A, G>>; 2]> {
            let entries = self
                .inventory
                .entries
                .try_borrow()
                .map_err(|_| GuardError::Conflict)?;
            let mut reads = [None, None];
            for (i, original) in entries.by_slot().into_iter().enumerate() {
                if let Some(original) = original {
                    if original
                        .held
                        .try_borrow()
                        .map_err(|_| GuardError::Conflict)?
                        .caps
                        .is_some()
                    {
                        reads[i] = Some(HeldProbeRead {
                            original: original.clone(),
                        });
                    }
                }
            }
            Ok(reads)
        }
        /// SAME opaque membership only, safe while the original socket map is
        /// mutably borrowed by IO. G can verify its registered canonical pin
        /// without nesting Source reads or recursively borrowing that socket.
        pub(crate) fn verify_member(&self, read: &HeldProbeRead<N, A, G>) -> Result<()> {
            let entries = self
                .inventory
                .entries
                .try_borrow()
                .map_err(|_| GuardError::Conflict)?;
            if entries
                .all()
                .any(|original| Rc::ptr_eq(original, &read.original))
            {
                Ok(())
            } else {
                Err(GuardError::Conflict)
            }
        }
        /// Exact canonical slot+opaque identity only. Safe while the same
        /// original held socket is mutably borrowed by authorize_use/IO.
        pub(crate) fn verify_member_slot(
            &self,
            slot: Slot,
            read: &HeldProbeRead<N, A, G>,
        ) -> Result<()> {
            let entries = self
                .inventory
                .entries
                .try_borrow()
                .map_err(|_| GuardError::Conflict)?;
            if entries.by_slot()[slot_index(slot)]
                .is_some_and(|original| Rc::ptr_eq(original, &read.original))
            {
                Ok(())
            } else {
                Err(GuardError::Conflict)
            }
        }
        /// StageBeforeEnd/Close fact: ALL original ACKs in this exact canonical
        /// inventory retired via clone/base close ACKs. A never-ACKed reserved
        /// slot has no original to retire, and remains permanently consumed.
        /// No Runtime/G lifecycle grant or native port/route absence is implied.
        pub(crate) fn inspect_retired(&self) -> Result<Vec<RetiredProbeRead<N, A, G>>> {
            // Never claim an empty/retired inventory while a reserved slot is
            // still inside ACK creation or cleanup publication. Reentry taints
            // the actual outer call, even if its caller ignores this failure.
            let call = self.inventory.serial.call(true)?;
            let retired = self
                .originals()?
                .into_iter()
                .map(|read| read.retired())
                .collect::<Result<Vec<_>>>()?;
            call.finish()?;
            Ok(retired)
        }
    }
    impl<N: NativeApi, A: BindingAttestor, G: NativeProbeGate<N, A>> Drop for ProbeInventory<N, A, G> {
        fn drop(&mut self) {
            self.inventory.serial.failed.set(true);
            if let Ok(entries) = self.inventory.entries.try_borrow() {
                for original in entries.all() {
                    original.serial.failed.set(true);
                }
            }
            // No effect/unchecked close. Held Drop retains unretired sockets and
            // original caps; external factual read pins may still observe ACKs.
        }
    }
    impl<N: NativeApi, A: BindingAttestor, G: NativeProbeGate<N, A>> RetiredProbeRead<N, A, G> {
        pub(crate) fn verify_same_original(&self, live: &HeldProbeRead<N, A, G>) -> Result<()> {
            if !Rc::ptr_eq(&self.original, &live.original) {
                return Err(GuardError::Conflict);
            }
            self.original
                .held
                .try_borrow()
                .map_err(|_| GuardError::Conflict)?
                .retired()?;
            Ok(())
        }
    }
    impl<N: NativeApi, A: BindingAttestor, G: NativeProbeGate<N, A>> HeldProbeRead<N, A, G> {
        /// Read the SAME held original inside an already active Source window,
        /// without recursively acquiring Source. Closing windows and unrelated
        /// equal sources deny; this returns facts only, never send permission.
        pub(crate) fn inspect_tuple_in_window(
            &self,
            window: &NativeBindingsWindow<'_>,
        ) -> Result<ProbeTuple> {
            self.original.tuple_in_window(window)
        }
        pub(crate) fn inspect_tuple(&self) -> Result<ProbeTuple> {
            self.original.tuple(None)
        }
        pub(crate) fn same_original(&self, other: &Self) -> bool {
            Rc::ptr_eq(&self.original, &other.original)
        }
        pub(crate) fn pin(&self) -> Self {
            Self {
                original: self.original.clone(),
            }
        }
        pub(crate) fn retired(&self) -> Result<RetiredProbeRead<N, A, G>> {
            self.original
                .held
                .try_borrow()
                .map_err(|_| GuardError::Conflict)?
                .retired()?;
            Ok(RetiredProbeRead {
                original: self.original.clone(),
            })
        }
    }
    impl<N: NativeApi, A: BindingAttestor, G: NativeProbeGate<N, A>> HeldProbeLease<N, A, G> {
        fn operate<T>(
            &self,
            action: impl FnOnce(&mut NativeProbeSocket) -> io::Result<T>,
        ) -> io::Result<T> {
            let error = |_| io::Error::from(io::ErrorKind::PermissionDenied);
            let tuple = self.original.tuple(Some(self.id)).map_err(error)?;
            let call = self.original.serial.call(false).map_err(error)?;
            let mut held = self
                .original
                .held
                .try_borrow_mut()
                .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
            let Held {
                caps,
                clones,
                revoked,
                ..
            } = &mut *held;
            if *revoked {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let caps = caps.as_ref().ok_or(io::ErrorKind::PermissionDenied)?;
            let read = HeldProbeRead {
                original: self.original.clone(),
            };
            caps.gate.authorize_use(&read, &tuple).map_err(error)?;
            let mut io_result = None;
            caps.source
                .inspect_bindings(|b| {
                    caps.expected.matches(b).map_err(denied)?;
                    let socket = &mut clones
                        .get_mut(&self.id)
                        .filter(|c| c.live.get())
                        .ok_or(SourceError::Conflict)?
                        .socket;
                    if caps.expected.tuple(socket).map_err(denied)? != tuple {
                        return Err(SourceError::Conflict);
                    }
                    call.verify().map_err(denied)?;
                    // Preserve ordinary WouldBlock as an IO result, while STILL
                    // completing both socket/source postflight checks.
                    io_result = Some(action(socket.0.as_mut().ok_or(SourceError::Conflict)?));
                    if caps.expected.tuple(socket).map_err(denied)? != tuple {
                        return Err(SourceError::Conflict);
                    }
                    Ok(())
                })
                .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
            caps.gate.authorize_use(&read, &tuple).map_err(error)?;
            call.finish().map_err(error)?;
            io_result.ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?
        }
    }
    impl<N: NativeApi, A: BindingAttestor, G: NativeProbeGate<N, A>> ProbeDatagram
        for HeldProbeLease<N, A, G>
    {
        fn send(&mut self, packet: &[u8]) -> io::Result<usize> {
            self.operate(|socket| socket.send(packet))
        }
        fn receive(&mut self, packet: &mut [u8]) -> io::Result<usize> {
            self.operate(|socket| socket.receive(packet))
        }
    }
    impl<N: NativeApi, A: BindingAttestor, G: NativeProbeGate<N, A>> Drop for HeldProbeLease<N, A, G> {
        fn drop(&mut self) {
            // Update without borrowing the map: reentrant Drop leaves a
            // retryable retained orphan, never an unchecked native close.
            self.live.set(false);
            match self.original.held.try_borrow_mut() {
                Ok(mut held) => {
                    if held.retire_clone(self.id).is_err() {
                        self.original.serial.failed.set(true);
                    }
                }
                Err(_) => {
                    // Retained orphan blocks release until fresh no-allows
                    // cleanup can acknowledge its close.
                    self.original.serial.failed.set(true);
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "member_carrier_probes_tests.rs"]
mod tests;
