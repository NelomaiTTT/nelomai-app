//! Serialized product-facing carrier control; native terminal completion is a
//! separate mandatory provider boundary, not the coordinator's Stopped record.
#![allow(dead_code)]
use crate::member_carrier_pair::{CarrierNativePair, CarrierPairIo, PairJournal};
use nelomai_client_tunnel::{
    redundancy::{
        control::PairControl, driver::NativePair, evidence::NativeHealthSample, protocol::Member,
        SessionScope, Slot,
    },
    DesktopTunnelOptions, TunnelMetrics,
};
use std::io;

/// The concrete native provider owns every actual terminal output BEFORE
/// fallible handoff, closes/disarms originals in authenticated native brackets,
/// and returns success only after actual module ACK and whole resource release.
/// No default implementation or permission from matching phase/JSON exists.
pub(crate) trait CarrierPairFinalizer<I: CarrierPairIo, J: PairJournal> {
    fn finish(
        &mut self,
        original: &mut Option<CarrierNativePair<I, J>>,
        scope: &SessionScope,
    ) -> io::Result<()>;
}
pub(crate) struct CarrierPairControl<I: CarrierPairIo, J: PairJournal, F> {
    pair: Option<CarrierNativePair<I, J>>,
    scope: SessionScope,
    finalizer: F,
    closing: bool,
    completed: bool,
}
fn conflict() -> io::Error {
    io::Error::other("carrier_terminal_completion_pending")
}
/// Dispatch only: this conveys no native release or absence authority.
/// A selected pregraph lane stays selected after the actor's release; its
/// retained module container and release slot still require their own checks.
pub(crate) fn continue_pregraph_terminal(selected_pregraph: bool, _actor_released: bool) -> bool {
    selected_pregraph
}

#[cfg(test)]
#[test]
fn pregraph_continuation_survives_actor_release_without_selecting_other_lanes() {
    assert!(continue_pregraph_terminal(true, false));
    assert!(continue_pregraph_terminal(true, true));
    assert!(!continue_pregraph_terminal(false, false));
    assert!(!continue_pregraph_terminal(false, true));
}
impl<I: CarrierPairIo, J: PairJournal, F: CarrierPairFinalizer<I, J>> CarrierPairControl<I, J, F> {
    pub(crate) fn new(pair: CarrierNativePair<I, J>, finalizer: F) -> Self {
        let scope = pair.snapshot().scope.clone();
        Self {
            pair: Some(pair),
            scope,
            finalizer,
            closing: false,
            completed: false,
        }
    }
    fn live(&self) -> io::Result<&CarrierNativePair<I, J>> {
        if self.closing || self.completed {
            return Err(conflict());
        }
        self.pair.as_ref().ok_or_else(conflict)
    }
    fn live_mut(&mut self) -> io::Result<&mut CarrierNativePair<I, J>> {
        if self.closing || self.completed {
            return Err(conflict());
        }
        self.pair.as_mut().ok_or_else(conflict)
    }
}
impl<I: CarrierPairIo, J: PairJournal, F: CarrierPairFinalizer<I, J>> NativePair
    for CarrierPairControl<I, J, F>
{
    type Socket = I::Socket;
    fn check_integrity(&mut self) -> io::Result<()> {
        self.live_mut()?.check_integrity()
    }
    fn sample(&mut self, slot: Slot) -> Option<NativeHealthSample> {
        self.live_mut().ok()?.sample(slot)
    }
    fn open_probe(&mut self, slot: Slot) -> io::Result<(Self::Socket, String)> {
        self.live_mut()?.open_probe(slot)
    }
    fn select_active(&mut self, scope: &SessionScope, slot: Slot) -> io::Result<()> {
        self.live_mut()?.select_active(scope, slot)
    }
    fn close(&mut self, scope: &SessionScope) -> io::Result<()> {
        if *scope != self.scope {
            return Err(conflict());
        }
        if self.completed {
            return Ok(());
        }
        // Latch BEFORE any native or provider boundary, including an unwind.
        // Retry is scoped cleanup only; no method can reopen forward activity.
        self.closing = true;
        if let Some(original) = self.pair.as_mut() {
            original.close(scope)?;
        }
        self.finalizer.finish(&mut self.pair, scope)?;
        if self.pair.is_some() {
            return Err(conflict());
        }
        // Only the concrete finisher's whole terminal release may reach here.
        // This local state never constructs an SDK/module/ownership receipt.
        self.completed = true;
        Ok(())
    }
}
impl<I: CarrierPairIo, J: PairJournal, F: CarrierPairFinalizer<I, J>> PairControl
    for CarrierPairControl<I, J, F>
{
    fn complete_start(&mut self, scope: &SessionScope) -> io::Result<()> {
        self.live_mut()?.complete_start(scope)
    }
    fn complete_rebind(&mut self, scope: &SessionScope) -> io::Result<()> {
        self.live_mut()?.complete_rebind(scope)
    }
    fn metrics(&self, slot: Slot) -> io::Result<TunnelMetrics> {
        self.live()?.metrics(slot)
    }
    fn physical_network_fingerprint(&self) -> io::Result<String> {
        self.live()?.physical_network_fingerprint()
    }
    fn start_primary(
        &mut self,
        scope: &SessionScope,
        member: &Member,
        options: &DesktopTunnelOptions,
    ) -> io::Result<()> {
        self.live_mut()?.start_primary(scope, member, options)
    }
    fn attach(&mut self, scope: &SessionScope, member: &Member) -> io::Result<()> {
        self.live_mut()?.attach(scope, member)
    }
    fn remove_standby(&mut self, scope: &SessionScope, slot: Slot) -> io::Result<()> {
        self.live_mut()?.remove_standby(scope, slot)
    }
    fn rebind_pair(&mut self, scope: &SessionScope) -> io::Result<bool> {
        self.live_mut()?.rebind_pair(scope)
    }
    fn cleanup_pending(&self) -> bool {
        if self.completed {
            false
        } else if self.closing {
            true
        } else {
            self.pair.as_ref().is_none_or(PairControl::cleanup_pending)
        }
    }
}
