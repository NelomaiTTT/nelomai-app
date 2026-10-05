//! Unwired scoped member lifecycle. Journal is durable authority, never an SCM
//! name alone. The trusted factory must serialize ownership of each native slot.
#![cfg_attr(not(windows), allow(dead_code))] // Portable fake tests have no native caller.

use nelomai_client_tunnel::{redundancy::SessionScope, TunnelTransport};
use nelomai_contracts::dispatcher::TunnelSlot;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Intent {
    pub scope: SessionScope,
    pub slot: TunnelSlot,
    #[serde(with = "transport_wire")]
    pub transport: TunnelTransport,
    pub engine: PathBuf,
    pub config_sha256: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum Phase {
    Prepared,
    Running,
    Stopping,
    Stopped,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessProof {
    pub pid: u32,
    pub creation_time: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InterfaceProof {
    pub index: u32,
    pub luid: u64,
    pub guid: [u8; 16],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeProof {
    pub process: ProcessProof,
    pub interface: InterfaceProof,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub intent: Intent,
    pub phase: Phase,
    pub proof: Option<NativeProof>,
    pub retired_proof: Option<NativeProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_config_sha256: Option<[u8; 32]>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServiceObservation {
    pub exact_spec: bool,
    /// None only for a positively observed stopped service, never query failure.
    pub process: Option<ProcessProof>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Observation {
    /// Digest obtained from a still-private regular, non-reparse, single-link
    /// config under verified private ancestors. Unsafe reads MUST return error.
    pub config_sha256: Option<[u8; 32]>,
    pub service: Option<ServiceObservation>,
    pub alternative_service_present: bool,
    pub interface: Option<InterfaceProof>,
    /// Lookups of retained index/LUID/GUID also fence reuse after alias deletion.
    pub retained_interfaces: Vec<InterfaceProof>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum OwnerError {
    #[error("member_owner_invalid")]
    Invalid,
    #[error("member_owner_conflict")]
    Conflict,
    #[error("member_owner_pending_cleanup")]
    Pending,
    #[error("member_owner_retired")]
    Retired,
    #[error("member_owner_native_unavailable")]
    Native,
    #[error("member_owner_journal_unavailable")]
    Journal,
}
pub(crate) type Result<T> = std::result::Result<T, OwnerError>;

mod transport_wire {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        value: &TunnelTransport,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(match value {
            TunnelTransport::WireGuard => "wireguard",
            TunnelTransport::AmneziaWg3 => "amneziawg3",
        })
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<TunnelTransport, D::Error> {
        match String::deserialize(deserializer)?.as_str() {
            "wireguard" => Ok(TunnelTransport::WireGuard),
            "amneziawg3" => Ok(TunnelTransport::AmneziaWg3),
            _ => Err(serde::de::Error::custom("member_owner_invalid_transport")),
        }
    }
}

/// compare_exchange MUST persist atomically and durably before returning Ok.
/// On failure/lost acknowledgement the caller rereads; no blind effects/retry.
/// Native implementation requires audited ACL/ancestor/reparse/hardlink checks.
pub(crate) trait Journal {
    fn load(&mut self, slot: TunnelSlot) -> Result<Option<Record>>;
    fn compare_exchange(
        &mut self,
        slot: TunnelSlot,
        expected: Option<&Record>,
        desired: &Record,
    ) -> Result<()>;
}
pub(crate) trait MemberIo {
    fn inspect(&mut self, intent: &Intent, retained: Option<&NativeProof>) -> Result<Observation>;
    /// Requires retained NEW SCM service and running-process handles from THIS
    /// fresh start. Ordinary name/PID lookup or equal facts cannot satisfy this.
    /// No successful default: each native boundary must supply its own origin.
    fn inspect_original(&mut self, intent: &Intent, retained: &NativeProof) -> Result<Observation>;
    /// Cleanup FACTS through the SAME retained original create/service/process
    /// handles. Forward poison may be ignored only by this separate read, never
    /// reset. Recovered data/ordinary name/PID lookup cannot supply provenance.
    /// Boundaries without this actual-origin surface deny, not fall back.
    fn inspect_original_for_cleanup(
        &mut self,
        _intent: &Intent,
        _retained: &NativeProof,
    ) -> Result<Observation> {
        Err(OwnerError::Retired)
    }
    /// Revokes independently held original read pins too, without native effects.
    fn revoke_original(&mut self);
    fn write_private_config(
        &mut self,
        intent: &Intent,
        expected_sha256: Option<[u8; 32]>,
        canonical: &str,
    ) -> Result<()>;
    fn start_fresh(&mut self, intent: &Intent, retired: Option<&NativeProof>) -> Result<()>;
    /// Implementations recheck expected evidence immediately before the effect.
    fn stop_slot(
        &mut self,
        intent: &Intent,
        retained: Option<&NativeProof>,
        expected: &Observation,
    ) -> Result<()>;
    fn rebind(
        &mut self,
        intent: &Intent,
        proof: &NativeProof,
        expected: &Observation,
    ) -> Result<()>;
}

/// Optional native factual-pin surface, with no default/fact constructor.
/// Ordinary lifecycle adapters do not implement this extra surface.
pub(crate) trait OriginalMemberPinSource: MemberIo {
    type Pin;
    fn original_read_pin(&mut self) -> Result<Self::Pin>;
}
/// Extra actual-origin lifecycle boundary. No defaults: ordinary lookup/rebind
/// cannot issue this opaque native old-process closure and replacement ACK.
pub(crate) trait OriginalMemberRebindIo: MemberIo {
    fn rebind_original(
        &mut self,
        intent: &Intent,
        old: &NativeProof,
    ) -> Result<std::rc::Rc<OriginalRebindAck>>;
    fn read_rebound_original(
        &mut self,
        ack: &std::rc::Rc<OriginalRebindAck>,
    ) -> Result<NativeProof>;
}

/// Separate SAME retained NEW-service cleanup boundary. No live/NIC grant and
/// no fallback to name/PID lookup or committed Running metadata.
pub(crate) trait OriginalMemberPartialCleanupIo: MemberIo {
    type CleanupPin;
    fn partial_cleanup_pin(&mut self, intent: &Intent) -> Result<Self::CleanupPin>;
    fn inspect_partial_cleanup(
        &mut self,
        pin: &Self::CleanupPin,
    ) -> Result<PartialServiceObservation>;
    fn stop_partial_original(&mut self, pin: &Self::CleanupPin) -> Result<()>;
}
pub(crate) trait OriginalServiceCleanupNative: OriginalMemberNative {
    fn service_cleanup_facts(
        &mut self,
        service: &Self::Service,
        intent: &Intent,
    ) -> Result<ServiceCleanupFacts>;
    fn verify_cleanup_process_image(
        &mut self,
        process: &Self::Process,
        intent: &Intent,
    ) -> Result<()>;
}
pub(crate) struct ServiceCleanupFacts {
    pub exact_spec: bool,
    pub pid: u32,
    pub state: ServiceCleanupState,
    pub alternative_service_present: bool,
}
/// Factual SCM state only, never a process/NIC ownership or absence grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ServiceCleanupState {
    Stopped,
    Running,
    StartPending,
    StopPending,
}
/// Comparison-only service facts. No public fields/proof conversion/effects.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct PartialServiceObservation {
    pid: u32,
    state: ServiceCleanupState,
    process: Option<ProcessProof>,
    deleted: bool,
}
impl PartialServiceObservation {
    pub(crate) fn service_deleted(&self) -> bool {
        self.deleted
    }
}
pub(crate) struct OriginalServiceCleanup<S, P> {
    resources: std::rc::Rc<std::cell::RefCell<OriginalMemberResources<S, P>>>,
    intent: Intent,
    pinned_pid: Option<u32>,
    tainted: std::rc::Rc<std::cell::Cell<bool>>,
    process_origin: std::cell::Cell<Option<ProcessProof>>,
}
impl<S, P> RetainedMemberOrigin<S, P> {
    pub(crate) fn partial_cleanup_pin(
        &mut self,
        intent: &Intent,
    ) -> Result<OriginalServiceCleanup<S, P>> {
        let mut state = self.resources.try_borrow_mut().map_err(|_| {
            self.read_tainted.set(true);
            OwnerError::Conflict
        })?;
        state.revoked = true;
        if state.intent.as_ref() != Some(intent) || !state.attempted {
            return Err(OwnerError::Conflict);
        }
        if state.partial_denied
            || state.delete_attempted
            || state.service.is_none()
            || !matches!(state.scm_state, OriginalScmState::Live)
        {
            return Err(OwnerError::Retired);
        }
        Ok(OriginalServiceCleanup {
            resources: self.resources.clone(),
            intent: intent.clone(),
            pinned_pid: state.pinned_pid,
            tainted: self.read_tainted.clone(),
            process_origin: std::cell::Cell::new(
                state.proof.map(|p| p.process).or(state.process_birth),
            ),
        })
    }
}
impl<S, P> OriginalServiceCleanup<S, P> {
    pub(crate) fn matches_origin(&self, origin: &RetainedMemberOrigin<S, P>) -> bool {
        std::rc::Rc::ptr_eq(&self.resources, &origin.resources)
    }
    pub(crate) fn inspect<B: OriginalServiceCleanupNative<Service = S, Process = P>>(
        &self,
        boundary: &mut B,
        mut read_config: impl FnMut() -> Result<Option<[u8; 32]>>,
    ) -> Result<PartialServiceObservation> {
        let mut state = self.resources.try_borrow_mut().map_err(|_| {
            self.tainted.set(true);
            OwnerError::Conflict
        })?;
        if state.intent.as_ref() != Some(&self.intent) || state.pinned_pid != self.pinned_pid {
            return Err(OwnerError::Conflict);
        }
        if state.partial_denied {
            return Err(OwnerError::Retired);
        }
        if matches!(state.scm_state, OriginalScmState::Closed)
            && state.service.is_none()
            && state.delete_attempted
        {
            state.partial_denied = true;
            self.tainted.set(false);
            let mut process = None;
            for _ in 0..2 {
                if read_config()? != Some(self.intent.config_sha256) {
                    return Err(OwnerError::Conflict);
                }
                if let Some(handle) = &state.process {
                    boundary.verify_cleanup_process_image(handle, &self.intent)?;
                    let (proof, code) = boundary.query_process(handle)?;
                    if Some(proof.pid) != self.pinned_pid
                        || proof.creation_time == 0
                        || code == 259
                        || self.process_origin.get().is_some_and(|p| p != proof)
                        || process.is_some_and(|p| p != proof)
                    {
                        return Err(OwnerError::Conflict);
                    }
                    process = Some(proof);
                } else if self.pinned_pid.is_some() {
                    return Err(OwnerError::Conflict);
                }
            }
            if read_config()? != Some(self.intent.config_sha256) || self.tainted.get() {
                return Err(OwnerError::Conflict);
            }
            state.partial_denied = false;
            return Ok(PartialServiceObservation {
                pid: 0,
                state: ServiceCleanupState::Stopped,
                process,
                deleted: true,
            });
        }
        self.check(&state)?;
        state.revoked = true;
        state.partial_denied = true; // Error/unwind cannot mint a fresh replacement pin.
        self.tainted.set(false);
        let facts = self.read(&state, boundary, &mut read_config)?;
        state.partial_denied = false;
        Ok(facts)
    }
    fn check(&self, state: &OriginalMemberResources<S, P>) -> Result<()> {
        if state.intent.as_ref() != Some(&self.intent) || state.pinned_pid != self.pinned_pid {
            return Err(OwnerError::Conflict);
        }
        if state.partial_denied
            || state.delete_attempted
            || state.service.is_none()
            || !matches!(state.scm_state, OriginalScmState::Live)
        {
            return Err(OwnerError::Retired);
        }
        Ok(())
    }
    fn read<B: OriginalServiceCleanupNative<Service = S, Process = P>>(
        &self,
        state: &OriginalMemberResources<S, P>,
        boundary: &mut B,
        read_config: &mut impl FnMut() -> Result<Option<[u8; 32]>>,
    ) -> Result<PartialServiceObservation> {
        let mut prior = None;
        for _ in 0..2 {
            if read_config()? != Some(self.intent.config_sha256) {
                return Err(OwnerError::Conflict);
            }
            let facts = boundary.service_cleanup_facts(
                state.service.as_ref().ok_or(OwnerError::Retired)?,
                &self.intent,
            )?;
            if !facts.exact_spec || facts.alternative_service_present {
                return Err(OwnerError::Conflict);
            }
            let pid = match facts.state {
                ServiceCleanupState::Stopped if facts.pid != 0 => return Err(OwnerError::Conflict),
                ServiceCleanupState::Stopped => 0,
                ServiceCleanupState::Running => facts.pid,
                // QueryServiceStatusEx cannot authenticate these PIDs. The
                // explicit state remains in every comparison; zero is NOT
                // stopped/absent and never enters process acquisition.
                ServiceCleanupState::StartPending | ServiceCleanupState::StopPending => 0,
            };
            let process = if let Some(handle) = &state.process {
                boundary.verify_cleanup_process_image(handle, &self.intent)?;
                let (proof, code) = boundary.query_process(handle)?;
                if Some(proof.pid) != self.pinned_pid
                    || proof.creation_time == 0
                    || state.proof.is_some_and(|p| p.process != proof)
                    || self.process_origin.get().is_some_and(|p| p != proof)
                    || (facts.state == ServiceCleanupState::Running
                        && (pid != proof.pid || code != 259))
                    || (facts.state == ServiceCleanupState::Stopped && code == 259)
                {
                    return Err(OwnerError::Conflict);
                }
                self.process_origin.set(Some(proof));
                Some(proof)
            } else {
                if self.pinned_pid.is_some() {
                    return Err(OwnerError::Conflict);
                }
                if facts.state != ServiceCleanupState::Stopped {
                    state.partial_unpinned_process.set(true);
                }
                None // SCM PID is observation only, never adopted/pinned by this read.
            };
            let next = PartialServiceObservation {
                pid,
                state: facts.state,
                process,
                deleted: false,
            };
            if prior.as_ref().is_some_and(|old| old != &next) || self.tainted.get() {
                return Err(OwnerError::Conflict);
            }
            prior = Some(next);
        }
        if read_config()? != Some(self.intent.config_sha256) || self.tainted.get() {
            return Err(OwnerError::Conflict);
        }
        prior.ok_or(OwnerError::Pending)
    }
    pub(crate) fn stop_delete<B: OriginalServiceCleanupNative<Service = S, Process = P>>(
        &self,
        boundary: &mut B,
        mut read_config: impl FnMut() -> Result<Option<[u8; 32]>>,
    ) -> Result<()> {
        let mut state = self.resources.try_borrow_mut().map_err(|_| {
            self.tainted.set(true);
            OwnerError::Conflict
        })?;
        if state.intent.as_ref() == Some(&self.intent)
            && state.pinned_pid == self.pinned_pid
            && !state.partial_denied
            && matches!(state.scm_state, OriginalScmState::Closed)
            && state.service.is_none()
            && state.delete_attempted
        {
            return Ok(());
        } // SAME actual Delete ACK, no repeated effect.
        self.check(&state)?;
        state.revoked = true;
        state.partial_denied = true;
        self.tainted.set(false);
        self.read(&state, boundary, &mut read_config)?;
        state.scm_state = OriginalScmState::Closing;
        boundary.stop(state.service.as_ref().ok_or(OwnerError::Retired)?)?;
        let closed = self.read(&state, boundary, &mut read_config)?;
        if closed.pid != 0 || closed.state != ServiceCleanupState::Stopped {
            return Err(OwnerError::Pending);
        }
        state.delete_attempted = true;
        boundary.delete(state.service.as_ref().ok_or(OwnerError::Retired)?)?;
        state.service = None;
        state.scm_state = OriginalScmState::Closed;
        if state.partial_unpinned_process.get() {
            // Only SCM deletion is acknowledged. An observed unpinned process
            // may outlive SERVICE_STOPPED: no process absence or full Closed ACK.
            return Err(OwnerError::Pending);
        }
        state.partial_denied = false;
        Ok(())
    }
}

/// External SCM/process operations only. The production retention policy below
/// owns the returned objects; equal lookups are never a source of receipts.
pub(crate) trait OriginalMemberNative {
    type Service;
    type Process;
    fn create(&mut self, intent: &Intent) -> Result<Self::Service>;
    #[cfg(test)] // Existing composite start fixtures only; native uses split start.
    fn finish_created(&mut self, service: &Self::Service) -> Result<()>;
    fn running_pid(&mut self, service: &Self::Service) -> Result<u32>;
    fn pin_process(&mut self, pid: u32) -> Result<Self::Process>;
    fn query_process(&mut self, process: &Self::Process) -> Result<(ProcessProof, u32)>;
    fn observe(
        &mut self,
        service: &Self::Service,
        intent: &Intent,
        retained: Option<&NativeProof>,
    ) -> Result<OriginalMemberFacts>;
    fn observe_cleanup(
        &mut self,
        service: &Self::Service,
        intent: &Intent,
        retained: Option<&NativeProof>,
    ) -> Result<Observation>;
    fn stop(&mut self, service: &Self::Service) -> Result<()>;
    fn start_existing(&mut self, service: &Self::Service) -> Result<()>;
    fn delete(&mut self, service: &Self::Service) -> Result<()>;
}

/// Separate original NEW-service start boundary, not a default implementation
/// for legacy/recovery callers. Start ACK and the first valid Running PID are
/// distinct from the fallible post-start acceptance checks.
pub(crate) trait OriginalMemberStartNative: OriginalMemberNative {
    fn configure_created(&mut self, service: &Self::Service, intent: &Intent) -> Result<()>;
    fn start_created(&mut self, service: &Self::Service) -> Result<()>;
    fn first_running_pid(&mut self, service: &Self::Service) -> Result<u32>;
    fn finish_started(
        &mut self,
        service: &Self::Service,
        process: &Self::Process,
        birth: &ProcessProof,
        intent: &Intent,
    ) -> Result<()>;
}

/// External SCM status facts only. This selector cannot mint ownership from a
/// PID; it is consumed only after SAME NEW SCM and actual Start ACK retention.
pub(crate) enum OriginalServiceStartStatus {
    StartPending(Option<u32>),
    Running(Option<u32>),
    Stopped,
    Other,
}
pub(crate) fn original_start_process_pid(
    status: OriginalServiceStartStatus,
) -> Result<Option<u32>> {
    match status {
        OriginalServiceStartStatus::StartPending(_reported_pid) => Ok(None),
        OriginalServiceStartStatus::Running(pid) => pid
            .filter(|pid| *pid != 0)
            .map(Some)
            .ok_or(OwnerError::Pending),
        OriginalServiceStartStatus::Stopped => Err(OwnerError::Pending),
        OriginalServiceStartStatus::Other => Err(OwnerError::Conflict),
    }
}

/// No constructor/serialization/effect methods. Issued only by the original
/// NEW-service holder after its pinned old process has exited and the SAME
/// service acknowledges restart. The owning IO retains both process handles.
pub(crate) struct OriginalRebindAck {
    intent: Intent,
    old: NativeProof,
    next: std::cell::Cell<Option<NativeProof>>,
    old_closed: std::cell::Cell<bool>,
    acknowledged: std::cell::Cell<bool>,
}
impl OriginalRebindAck {
    pub(crate) fn intent(&self) -> &Intent {
        &self.intent
    }
    pub(crate) fn old_proof(&self) -> NativeProof {
        self.old
    }
    pub(crate) fn replacement_proof(&self) -> Result<NativeProof> {
        if !self.old_closed.get() || !self.acknowledged.get() {
            return Err(OwnerError::Pending);
        }
        self.next.get().ok_or(OwnerError::Pending)
    }
}
struct OriginalRebindResources<P> {
    ack: std::rc::Rc<OriginalRebindAck>,
    process: P,
}

#[derive(Eq, PartialEq)]
pub(crate) struct OriginalMemberFacts {
    pub exact_spec: bool,
    pub pid: u32,
    pub alternative_service_present: bool,
    pub interface: Option<InterfaceProof>,
    pub retained_interfaces: Vec<InterfaceProof>,
}

struct OriginalMemberResources<S, P> {
    intent: Option<Intent>,
    service: Option<S>,
    process: Option<P>,
    pinned_pid: Option<u32>,
    process_birth: Option<ProcessProof>,
    partial_denied: bool,
    partial_unpinned_process: std::cell::Cell<bool>,
    proof: Option<NativeProof>,
    attempted: bool,
    revoked: bool,
    delete_attempted: bool,
    scm_state: OriginalScmState,
    rebinds: Vec<OriginalRebindResources<P>>,
}
enum OriginalScmState {
    Uncreated,
    Live,
    Closing,
    Closed,
}

/// Private shared retention, not a serializable or cloneable grant. Only a NEW
/// create acknowledgement can populate service, and only its Running PID can
/// populate process. Closing these handles never stops/deletes a native object.
pub(crate) struct RetainedMemberOrigin<S, P> {
    resources: std::rc::Rc<std::cell::RefCell<OriginalMemberResources<S, P>>>,
    read_tainted: std::rc::Rc<std::cell::Cell<bool>>,
}
pub(crate) struct OriginalMemberPin<S, P> {
    resources: std::rc::Rc<std::cell::RefCell<OriginalMemberResources<S, P>>>,
    read_tainted: std::rc::Rc<std::cell::Cell<bool>>,
    proof: NativeProof,
}
impl<S, P> RetainedMemberOrigin<S, P> {
    pub(crate) fn start_retaining_process<
        B: OriginalMemberStartNative<Service = S, Process = P>,
    >(
        &mut self,
        boundary: &mut B,
        intent: &Intent,
    ) -> Result<()> {
        let mut state = self.resources.try_borrow_mut().map_err(|_| {
            self.read_tainted.set(true);
            OwnerError::Conflict
        })?;
        if state.attempted {
            return Err(OwnerError::Retired);
        }
        state.attempted = true;
        state.intent = Some(intent.clone());
        state.service = Some(boundary.create(intent)?); // Root NEW ACK first.
        state.scm_state = OriginalScmState::Live;
        let service = state.service.as_ref().ok_or(OwnerError::Pending)?;
        boundary.configure_created(service, intent)?;
        boundary.start_created(service)?; // Missing/lost ACK never reaches PID capture.
        let pid = boundary.first_running_pid(service)?;
        if pid == 0 {
            return Err(OwnerError::Pending);
        }
        state.process = Some(boundary.pin_process(pid)?); // No postflight before rooting.
        state.pinned_pid = Some(pid);
        let (birth, code) =
            boundary.query_process(state.process.as_ref().ok_or(OwnerError::Pending)?)?;
        if birth.pid != pid || birth.creation_time == 0 {
            return Err(OwnerError::Conflict);
        }
        state.process_birth = Some(birth); // Immutable original before further fallible work.
        if code != 259 {
            return Err(OwnerError::Pending);
        }
        boundary.finish_started(
            state.service.as_ref().ok_or(OwnerError::Pending)?,
            state.process.as_ref().ok_or(OwnerError::Pending)?,
            &birth,
            intent,
        )?;
        if boundary.query_process(state.process.as_ref().ok_or(OwnerError::Pending)?)?
            != (birth, 259)
            || boundary.running_pid(state.service.as_ref().ok_or(OwnerError::Pending)?)? != pid
        {
            return Err(OwnerError::Conflict);
        }
        let facts = boundary.observe(
            state.service.as_ref().ok_or(OwnerError::Pending)?,
            intent,
            None,
        )?;
        let proof = NativeProof {
            process: birth,
            interface: facts.interface.ok_or(OwnerError::Pending)?,
        };
        validate_proof(&proof)?;
        if !facts.exact_spec || facts.pid != pid || facts.alternative_service_present {
            return Err(OwnerError::Conflict);
        }
        state.proof = Some(proof);
        read_original_native(&state, boundary)?;
        if self.read_tainted.get() {
            return Err(OwnerError::Conflict);
        }
        state.revoked = false;
        Ok(())
    }
    pub(crate) fn empty() -> Self {
        Self {
            resources: std::rc::Rc::new(std::cell::RefCell::new(OriginalMemberResources {
                intent: None,
                service: None,
                process: None,
                pinned_pid: None,
                process_birth: None,
                partial_denied: false,
                partial_unpinned_process: std::cell::Cell::new(false),
                proof: None,
                attempted: false,
                revoked: true,
                delete_attempted: false,
                scm_state: OriginalScmState::Uncreated,
                rebinds: Vec::new(),
            })),
            read_tainted: std::rc::Rc::new(std::cell::Cell::new(false)),
        }
    }
    #[cfg(test)] // Legacy composite boundary fixtures, not the native start consumer.
    pub(crate) fn start<B: OriginalMemberNative<Service = S, Process = P>>(
        &mut self,
        boundary: &mut B,
        intent: &Intent,
    ) -> Result<()> {
        let mut state = self.resources.borrow_mut();
        if state.attempted {
            return Err(OwnerError::Retired);
        }
        state.attempted = true;
        state.intent = Some(intent.clone());
        // No post-create fallible work before storing the actual returned
        // object. Error/unwind leaves this obligation retained and revoked.
        state.service = Some(boundary.create(intent)?);
        state.scm_state = OriginalScmState::Live;
        let service = state.service.as_ref().ok_or(OwnerError::Native)?;
        boundary.finish_created(service)?;
        let pid = boundary.running_pid(service)?;
        if pid == 0 {
            return Err(OwnerError::Conflict);
        }
        state.process = Some(boundary.pin_process(pid)?);
        state.pinned_pid = Some(pid);
        let process = state.process.as_ref().ok_or(OwnerError::Native)?;
        let (observed, code) = boundary.query_process(process)?;
        if observed.pid != pid || observed.creation_time == 0 || code != 259 {
            return Err(OwnerError::Conflict);
        }
        let facts = boundary.observe(
            state.service.as_ref().ok_or(OwnerError::Native)?,
            intent,
            None,
        )?;
        let proof = NativeProof {
            process: observed,
            interface: facts.interface.ok_or(OwnerError::Conflict)?,
        };
        validate_proof(&proof)?;
        if !facts.exact_spec || facts.pid != pid || facts.alternative_service_present {
            return Err(OwnerError::Conflict);
        }
        state.proof = Some(proof);
        read_original_native(&state, boundary)?;
        state.revoked = false;
        Ok(())
    }
    pub(crate) fn pin(&self) -> Result<OriginalMemberPin<S, P>> {
        let state = self.resources.try_borrow().map_err(|_| {
            self.read_tainted.set(true);
            OwnerError::Conflict
        })?;
        if state.revoked
            || !matches!(state.scm_state, OriginalScmState::Live)
            || state.proof.is_none()
            || state.service.is_none()
            || state.process.is_none()
        {
            return Err(OwnerError::Retired);
        }
        Ok(OriginalMemberPin {
            resources: self.resources.clone(),
            read_tainted: self.read_tainted.clone(),
            proof: state.proof.ok_or(OwnerError::Retired)?,
        })
    }
    pub(crate) fn rebind_original<B: OriginalMemberNative<Service = S, Process = P>>(
        &mut self,
        boundary: &mut B,
        intent: &Intent,
        old: &NativeProof,
        mut read_config: impl FnMut() -> Result<Option<[u8; 32]>>,
    ) -> Result<std::rc::Rc<OriginalRebindAck>> {
        let mut state = self.resources.try_borrow_mut().map_err(|_| {
            self.read_tainted.set(true);
            OwnerError::Conflict
        })?;
        state.revoked = true;
        self.read_tainted.set(false);
        if state.intent.as_ref() != Some(intent)
            || state.proof != Some(*old)
            || !matches!(state.scm_state, OriginalScmState::Live)
            || state.delete_attempted
            || state
                .rebinds
                .last()
                .is_some_and(|r| !r.ack.acknowledged.get())
        {
            return Err(OwnerError::Retired);
        }
        for _ in 0..2 {
            if read_config()? != Some(intent.config_sha256) {
                return Err(OwnerError::Conflict);
            }
            read_original_native(&state, boundary)?;
            if self.read_tainted.get() {
                return Err(OwnerError::Conflict);
            }
        }
        state
            .rebinds
            .try_reserve(1)
            .map_err(|_| OwnerError::Pending)?;
        let ack = std::rc::Rc::new(OriginalRebindAck {
            intent: intent.clone(),
            old: *old,
            next: std::cell::Cell::new(None),
            old_closed: std::cell::Cell::new(false),
            acknowledged: std::cell::Cell::new(false),
        });
        let process = state.process.take().ok_or(OwnerError::Retired)?;
        state.rebinds.push(OriginalRebindResources {
            ack: ack.clone(),
            process,
        });
        // Original SCM + old process are rooted before either effect, Err or unwind.
        boundary.stop(state.service.as_ref().ok_or(OwnerError::Retired)?)?;
        let retired = state.rebinds.last().ok_or(OwnerError::Pending)?;
        require_closed_pinned_process(boundary.query_process(&retired.process)?, old.process)?;
        let idle = boundary.observe(
            state.service.as_ref().ok_or(OwnerError::Retired)?,
            intent,
            Some(old),
        )?;
        if !idle.exact_spec
            || idle.pid != 0
            || idle.alternative_service_present
            || idle.interface.is_some_and(|p| p != old.interface)
            || idle.retained_interfaces.iter().any(|p| p != &old.interface)
            || read_config()? != Some(intent.config_sha256)
            || self.read_tainted.get()
        {
            return Err(OwnerError::Conflict);
        }
        require_closed_pinned_process(boundary.query_process(&retired.process)?, old.process)?;
        ack.old_closed.set(true);
        boundary.start_existing(state.service.as_ref().ok_or(OwnerError::Retired)?)?;
        let pid = boundary.running_pid(state.service.as_ref().ok_or(OwnerError::Retired)?)?;
        if pid == 0 {
            return Err(OwnerError::Conflict);
        }
        state.process = Some(boundary.pin_process(pid)?); // Before fallible process/native read.
        state.pinned_pid = Some(pid);
        let (process, code) =
            boundary.query_process(state.process.as_ref().ok_or(OwnerError::Pending)?)?;
        let facts = boundary.observe(
            state.service.as_ref().ok_or(OwnerError::Retired)?,
            intent,
            None,
        )?;
        let next = NativeProof {
            process,
            interface: facts.interface.ok_or(OwnerError::Pending)?,
        };
        validate_proof(&next)?;
        if code != 259
            || process.pid != pid
            || process == old.process
            || next.interface != old.interface
            || !facts.exact_spec
            || facts.pid != pid
            || facts.alternative_service_present
        {
            return Err(OwnerError::Conflict);
        }
        state.proof = Some(next);
        ack.next.set(Some(next)); // Actual returned handles/proof rooted before postflight.
        for _ in 0..2 {
            if read_config()? != Some(intent.config_sha256) {
                return Err(OwnerError::Conflict);
            }
            require_closed_pinned_process(
                boundary
                    .query_process(&state.rebinds.last().ok_or(OwnerError::Pending)?.process)?,
                old.process,
            )?;
            read_original_native(&state, boundary)?;
            if self.read_tainted.get() {
                return Err(OwnerError::Conflict);
            }
        }
        if read_config()? != Some(intent.config_sha256) || self.read_tainted.get() {
            return Err(OwnerError::Conflict);
        }
        ack.acknowledged.set(true);
        state.revoked = false;
        Ok(ack)
    }
    pub(crate) fn read_rebound_original<B: OriginalMemberNative<Service = S, Process = P>>(
        &mut self,
        boundary: &mut B,
        ack: &std::rc::Rc<OriginalRebindAck>,
        mut read_config: impl FnMut() -> Result<Option<[u8; 32]>>,
    ) -> Result<NativeProof> {
        let mut state = self.resources.try_borrow_mut().map_err(|_| {
            self.read_tainted.set(true);
            OwnerError::Conflict
        })?;
        if state.revoked {
            return Err(OwnerError::Retired);
        }
        state.revoked = true;
        let retired = state
            .rebinds
            .iter()
            .find(|r| std::rc::Rc::ptr_eq(&r.ack, ack))
            .ok_or(OwnerError::Conflict)?;
        let next = ack.replacement_proof()?;
        if state.intent.as_ref() != Some(&ack.intent)
            || state.proof != Some(next)
            || !matches!(state.scm_state, OriginalScmState::Live)
            || state.delete_attempted
        {
            return Err(OwnerError::Conflict);
        }
        self.read_tainted.set(false);
        for _ in 0..2 {
            if read_config()? != Some(ack.intent.config_sha256) {
                return Err(OwnerError::Conflict);
            }
            require_closed_pinned_process(
                boundary.query_process(&retired.process)?,
                ack.old.process,
            )?;
            if read_original_native(&state, boundary)? != (ack.intent.clone(), next)
                || self.read_tainted.get()
            {
                return Err(OwnerError::Conflict);
            }
        }
        if read_config()? != Some(ack.intent.config_sha256) || self.read_tainted.get() {
            return Err(OwnerError::Conflict);
        }
        state.revoked = false;
        Ok(next)
    }
    pub(crate) fn revoke(&mut self) {
        self.resources.borrow_mut().revoked = true;
    }
    pub(crate) fn creation_attempted(&self) -> bool {
        self.resources.borrow().attempted
    }
    /// Called only under the actual owner's durable Stop fence. Cleanup remains
    /// available after read revocation/partial Start. Never retries an uncertain
    /// delete and never turns a name lookup into an original create receipt.
    pub(crate) fn stop_delete<B: OriginalMemberNative<Service = S, Process = P>>(
        &mut self,
        boundary: &mut B,
        intent: &Intent,
        retained: Option<&NativeProof>,
        expected: &Observation,
    ) -> Result<()> {
        let mut state = self.resources.borrow_mut();
        state.revoked = true;
        if state.delete_attempted && state.service.is_some() {
            return Err(OwnerError::Pending);
        }
        if state.intent.as_ref() != Some(intent) {
            return Err(OwnerError::Conflict);
        }
        let service = state.service.as_ref().ok_or(OwnerError::Retired)?;
        // Match the caller's complete immediately prior cleanup observation;
        // this uses the retained SCM object even after a rebind changes its PID.
        let actual = boundary.observe_cleanup(service, intent, retained)?;
        if &actual != expected {
            return Err(OwnerError::Conflict);
        }
        state.scm_state = OriginalScmState::Closing;
        boundary.stop(state.service.as_ref().ok_or(OwnerError::Native)?)?;
        state.delete_attempted = true;
        boundary.delete(state.service.as_ref().ok_or(OwnerError::Native)?)?;
        // Delete ACK alone is not native absence. Close the SAME shared SCM
        // holder now (all pins lose it); MemberOwner independently checks full
        // native absence before publishing Stopped. Keep process/read metadata.
        state.service = None;
        state.scm_state = OriginalScmState::Closed;
        Ok(())
    }
    pub(crate) fn inspect_original<B: OriginalMemberNative<Service = S, Process = P>>(
        &mut self,
        boundary: &mut B,
        intent: &Intent,
        retained: &NativeProof,
        mut read_config: impl FnMut() -> Result<Option<[u8; 32]>>,
    ) -> Result<Observation> {
        let mut state = self.resources.try_borrow_mut().map_err(|_| {
            self.read_tainted.set(true);
            OwnerError::Conflict
        })?;
        if state.revoked || !matches!(state.scm_state, OriginalScmState::Live) {
            return Err(OwnerError::Retired);
        }
        state.revoked = true; // Error AND unwind revoke every independent pin.
        self.read_tainted.set(false);
        if state.intent.as_ref() != Some(intent) || state.proof != Some(*retained) {
            return Err(OwnerError::Conflict);
        }
        for _ in 0..2 {
            if read_config()? != Some(intent.config_sha256) {
                return Err(OwnerError::Conflict);
            }
            read_original_native(&state, boundary)?;
            if self.read_tainted.get() {
                return Err(OwnerError::Conflict);
            }
        }
        if read_config()? != Some(intent.config_sha256) || self.read_tainted.get() {
            return Err(OwnerError::Conflict);
        }
        state.revoked = false;
        Ok(Observation {
            config_sha256: Some(intent.config_sha256),
            service: Some(ServiceObservation {
                exact_spec: true,
                process: Some(retained.process),
            }),
            alternative_service_present: false,
            interface: Some(retained.interface),
            retained_interfaces: vec![retained.interface],
        })
    }
    /// Read-only SAME-original still-running facts for Closing restoration.
    /// Retires before all reads and NEVER clears poison. It cannot observe an
    /// uncommitted, stopped/deleted, rebound, missing or replaced original.
    pub(crate) fn inspect_original_for_cleanup<
        B: OriginalMemberNative<Service = S, Process = P>,
    >(
        &mut self,
        boundary: &mut B,
        intent: &Intent,
        retained: &NativeProof,
        mut read_config: impl FnMut() -> Result<Option<[u8; 32]>>,
    ) -> Result<Observation> {
        let mut state = self.resources.try_borrow_mut().map_err(|_| {
            self.read_tainted.set(true);
            OwnerError::Conflict
        })?;
        state.revoked = true;
        self.read_tainted.set(false);
        if !matches!(state.scm_state, OriginalScmState::Live)
            || state.delete_attempted
            || state.intent.as_ref() != Some(intent)
            || state.proof != Some(*retained)
        {
            return Err(OwnerError::Retired);
        }
        for _ in 0..2 {
            if read_config()? != Some(intent.config_sha256) {
                return Err(OwnerError::Conflict);
            }
            read_original_native(&state, boundary)?;
            if self.read_tainted.get() {
                return Err(OwnerError::Conflict);
            }
        }
        if read_config()? != Some(intent.config_sha256) || self.read_tainted.get() {
            return Err(OwnerError::Conflict);
        }
        Ok(Observation {
            config_sha256: Some(intent.config_sha256),
            service: Some(ServiceObservation {
                exact_spec: true,
                process: Some(retained.process),
            }),
            alternative_service_present: false,
            interface: Some(retained.interface),
            retained_interfaces: vec![retained.interface],
        })
    }
}
fn require_closed_pinned_process(actual: (ProcessProof, u32), old: ProcessProof) -> Result<()> {
    if actual.0 != old || actual.1 == 259 {
        return Err(OwnerError::Conflict);
    }
    Ok(())
}
impl<S, P> Drop for RetainedMemberOrigin<S, P> {
    fn drop(&mut self) {
        // Losing the actual lifecycle owner revokes read pins, but never
        // performs implicit Stop/Delete. Native obligations remain durable.
        self.resources.borrow_mut().revoked = true;
    }
}
impl<S, P> OriginalMemberPin<S, P> {
    pub(crate) fn read<B: OriginalMemberNative<Service = S, Process = P>>(
        &mut self,
        boundary: &mut B,
    ) -> Result<(Intent, NativeProof)> {
        let mut state = self.resources.try_borrow_mut().map_err(|_| {
            self.read_tainted.set(true);
            OwnerError::Conflict
        })?;
        if state.proof != Some(self.proof) {
            return Err(OwnerError::Retired);
        }
        if state.revoked || !matches!(state.scm_state, OriginalScmState::Live) {
            return Err(OwnerError::Retired);
        }
        state.revoked = true;
        self.read_tainted.set(false);
        let facts = read_original_native(&state, boundary)?;
        if self.read_tainted.get() {
            return Err(OwnerError::Conflict);
        }
        state.revoked = false;
        Ok(facts)
    }
}

fn read_original_native<S, P, B: OriginalMemberNative<Service = S, Process = P>>(
    state: &OriginalMemberResources<S, P>,
    boundary: &mut B,
) -> Result<(Intent, NativeProof)> {
    let intent = state.intent.as_ref().ok_or(OwnerError::Retired)?;
    let proof = state.proof.ok_or(OwnerError::Retired)?;
    let service = state.service.as_ref().ok_or(OwnerError::Retired)?;
    let process = state.process.as_ref().ok_or(OwnerError::Retired)?;
    // Pinned process -> SCM config/status/full interface -> pinned process ->
    // SCM config/status/full interface -> pinned process. No PID/name reopen.
    for _ in 0..2 {
        if boundary.query_process(process)? != (proof.process, 259) {
            return Err(OwnerError::Conflict);
        }
        let facts = boundary.observe(service, intent, Some(&proof))?;
        if !facts.exact_spec
            || facts.pid != proof.process.pid
            || facts.alternative_service_present
            || facts.interface != Some(proof.interface)
            || facts.retained_interfaces != [proof.interface]
        {
            return Err(OwnerError::Conflict);
        }
    }
    if boundary.query_process(process)? != (proof.process, 259) {
        return Err(OwnerError::Conflict);
    }
    Ok((intent.clone(), proof))
}

/// In-memory provenance from THIS owner's acknowledged fresh Start, not from
/// JSON equality or an existing service lookup. Keep captured evidence even
/// when the Running CAS fails; it supplies no new cleanup/effect authority.
struct OriginalRun {
    #[allow(dead_code)] // Read consumer remains gated on native lifecycle integration.
    running: Record,
    committed: bool,
}

/// Read access to the SAME retained MemberOwner, Journal and MemberIo. No Clone,
/// serialization, raw handles, native mutation or access to the owner is exposed.
/// The mutable borrow prevents Stop/rebind or owner replacement while held.
/// This portable provenance does NOT prove an original SCM/process handle:
/// the concrete native lifecycle gate must independently supply that guarantee.
#[allow(dead_code)] // Main's native lifecycle gate has not yet consumed this borrow.
pub(crate) struct OriginalLiveMember<'a, J, I> {
    owner: &'a mut MemberOwner<J, I>,
}

impl<J: Journal, I: MemberIo> OriginalLiveMember<'_, J, I> {
    /// Only freshly observed intent/process/interface facts, never effect rights.
    /// Any failed or unwound read permanently revokes this owner's read access.
    #[allow(dead_code)] // Read consumer remains gated on native lifecycle integration.
    pub(crate) fn read(&mut self) -> Result<(Intent, NativeProof)> {
        let mut attempt = OriginalReadAttempt {
            owner: self.owner,
            succeeded: false,
        };
        let facts = attempt.owner.read_original_live()?;
        attempt.succeeded = true;
        Ok(facts)
    }
}

impl<J: Journal, I: OriginalMemberPinSource> OriginalLiveMember<'_, J, I> {
    /// Validates the SAME owner/private files/durable receipt before deriving
    /// an independent native factual pin. The pin never clones F or this owner.
    #[allow(dead_code)] // Main's original C/A/B creator composition will use it.
    pub(crate) fn native_read_pin(&mut self) -> Result<I::Pin> {
        self.read()?;
        self.owner.io.original_read_pin()
    }
}

#[allow(dead_code)] // Unwind guard for the still-gated read consumer.
struct OriginalReadAttempt<'a, J, I: MemberIo> {
    owner: &'a mut MemberOwner<J, I>,
    succeeded: bool,
}
impl<J, I: MemberIo> Drop for OriginalReadAttempt<'_, J, I> {
    fn drop(&mut self) {
        if !self.succeeded {
            self.owner.original_read_revoked = true;
            self.owner.io.revoke_original();
        }
    }
}

/// Readonly acceptance of the closed addressless profile grammar used by the
/// pinned WG Windows/AWG3 adapters. NOT an installed-driver/package receipt or
/// permission to execute a DLL. No constructor, serialization, Clone or Debug:
/// decoded secrets stay zeroizing and the actual owner retains this original.
pub(crate) struct ReadonlyNativeProfile {
    origin: std::rc::Rc<()>,
    intent: Intent,
    keys: zeroize::Zeroizing<Vec<[u8; 32]>>,
}

fn profile_number(value: &str, maximum: u32) -> Result<u32> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(OwnerError::Invalid);
    }
    let n: u32 = value.parse().map_err(|_| OwnerError::Invalid)?;
    (n <= maximum).then_some(n).ok_or(OwnerError::Invalid)
}

fn profile_range(value: &str, maximum: u32) -> Result<(u32, u32)> {
    let (lo, hi) = value.split_once('-').unwrap_or((value, value));
    let range = (profile_number(lo, maximum)?, profile_number(hi, maximum)?);
    // AWG PickOne computes hi-lo+1 in uint32. The full uint32 interval is
    // syntactically valid to FromString but overflows that runtime operation.
    if range.1 < range.0 || range.1 - range.0 == u32::MAX {
        return Err(OwnerError::Invalid);
    }
    Ok(range)
}

fn profile_key(value: &str, allow_zero: bool) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    fn digit(b: u8) -> Result<u8> {
        match b {
            b'A'..=b'Z' => Ok(b - b'A'),
            b'a'..=b'z' => Ok(b - b'a' + 26),
            b'0'..=b'9' => Ok(b - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(OwnerError::Invalid),
        }
    }
    let bytes = value.as_bytes();
    if bytes.len() != 44 || bytes[43] != b'=' {
        return Err(OwnerError::Invalid);
    }
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    for i in 0..10 {
        let j = i * 4;
        let n = ((digit(bytes[j])? as u32) << 18)
            | ((digit(bytes[j + 1])? as u32) << 12)
            | ((digit(bytes[j + 2])? as u32) << 6)
            | digit(bytes[j + 3])? as u32;
        key[i * 3..i * 3 + 3].copy_from_slice(&n.to_be_bytes()[1..]);
    }
    let (a, b, c) = (digit(bytes[40])?, digit(bytes[41])?, digit(bytes[42])?);
    if c & 3 != 0 {
        return Err(OwnerError::Invalid);
    }
    key[30] = (a << 2) | (b >> 4);
    key[31] = (b << 4) | (c >> 2);
    if !allow_zero && key.iter().all(|b| *b == 0) {
        return Err(OwnerError::Invalid);
    }
    Ok(key)
}

// Conservative, bounded subset of the actual AWG3 obf builders, not a fake
// dry-run Device or service. I1..I5 are initiation packets with empty payload;
// dynamic data builders therefore add zero bytes. Reject ignored text/arguments
// rather than accepting input that the upstream parser silently discards.
fn profile_obfuscation(mut value: &str) -> Result<()> {
    let mut size = 0u32;
    let mut count = 0;
    while !value.trim().is_empty() {
        value = value.trim();
        let rest = value.strip_prefix('<').ok_or(OwnerError::Invalid)?;
        let (tag, next) = rest.split_once('>').ok_or(OwnerError::Invalid)?;
        let mut words = tag.split_whitespace();
        let kind = words.next().ok_or(OwnerError::Invalid)?;
        let argument = words.next();
        if words.next().is_some() {
            return Err(OwnerError::Invalid);
        }
        let amount = match kind {
            "b" => {
                let hex = argument.ok_or(OwnerError::Invalid)?;
                let hex = hex.strip_prefix("0x").unwrap_or(hex);
                if hex.is_empty()
                    || !hex.len().is_multiple_of(2)
                    || !hex.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err(OwnerError::Invalid);
                }
                u32::try_from(hex.len() / 2).map_err(|_| OwnerError::Invalid)?
            }
            "r" | "rc" | "rd" | "dz" => {
                profile_number(argument.ok_or(OwnerError::Invalid)?, 65507)?
            }
            "t" if argument.is_none() => 4,
            "d" | "ds" if argument.is_none() => 0,
            _ => return Err(OwnerError::Invalid),
        };
        size = size.checked_add(amount).ok_or(OwnerError::Invalid)?;
        count += 1;
        if size > 2016 || count > 256 {
            return Err(OwnerError::Invalid);
        }
        value = next;
    }
    if count == 0 || size == 0 {
        return Err(OwnerError::Invalid);
    }
    Ok(())
}

fn compile_readonly_profile(
    intent: &Intent,
    origin: std::rc::Rc<()>,
    text: &str,
) -> Result<ReadonlyNativeProfile> {
    if text.is_empty()
        || text.len() > crate::MAX_FRAME_SIZE
        || text.contains('\0')
        || Sha256::digest(text.as_bytes())[..] != intent.config_sha256
        || nelomai_client_tunnel::detect_configuration_transport(text) != intent.transport
    {
        return Err(OwnerError::Invalid);
    }
    let awg = intent.transport == TunnelTransport::AmneziaWg3;
    let mut section = 0;
    let mut seen = std::collections::BTreeSet::new();
    let mut keys = zeroize::Zeroizing::new(Vec::new());
    let mut headers = [(1, 1), (2, 2), (3, 3), (4, 4)];
    let mut paddings = [0; 4];
    let mut junk = [0; 3];
    let mut header_protection = false;
    let mut mtu = 1420;
    let mut content_padding = 0;
    for line in text.lines().map(str::trim).filter(|s| !s.is_empty()) {
        if line == "[Interface]" && section == 0 {
            section = 1;
            continue;
        }
        if line == "[Peer]" && section == 1 {
            section = 2;
            continue;
        }
        let (key, value) = line.split_once('=').ok_or(OwnerError::Invalid)?;
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        if section == 0 || value.is_empty() || !seen.insert((section, key.clone())) {
            return Err(OwnerError::Invalid);
        }
        match (section, key.as_str()) {
            (1, "privatekey") | (2, "publickey") | (2, "presharedkey") => {
                keys.push(*profile_key(value, key == "presharedkey")?);
            }
            (1, "table") if value == "off" => {}
            (1, "mtu") => {
                mtu = profile_number(value, 65535)?;
                if mtu < 576 {
                    return Err(OwnerError::Invalid);
                }
            }
            (2, "persistentkeepalive") => {
                if value != "off" && !(awg && value == "(off)") {
                    profile_number(value, 65535)?;
                }
            }
            (2, "endpoint") => {
                let endpoint: std::net::SocketAddr =
                    value.parse().map_err(|_| OwnerError::Invalid)?;
                if endpoint.port() == 0
                    || endpoint.ip().is_unspecified()
                    || endpoint.ip().is_loopback()
                    || endpoint.ip().is_multicast()
                {
                    return Err(OwnerError::Invalid);
                }
            }
            (2, "allowedips") => {
                let mut networks = std::collections::BTreeSet::new();
                for network in value.split(',') {
                    let net: ipnet::IpNet =
                        network.trim().parse().map_err(|_| OwnerError::Invalid)?;
                    if net != net.trunc() || !networks.insert(net) {
                        return Err(OwnerError::Invalid);
                    }
                }
                if networks.is_empty() || networks.len() > crate::member_plan::MAX_ROUTES {
                    return Err(OwnerError::Invalid);
                }
            }
            (1, "jc" | "jmin" | "jmax") if awg => {
                let index = match key.as_str() {
                    "jc" => 0,
                    "jmin" => 1,
                    _ => 2,
                };
                junk[index] = profile_number(value, 65535)?;
            }
            (1, "s1" | "s2" | "s3" | "s4") if awg => {
                paddings[(key.as_bytes()[1] - b'1') as usize] = profile_number(value, 65535)?;
            }
            (1, "h1" | "h2" | "h3" | "h4") if awg => {
                headers[(key.as_bytes()[1] - b'1') as usize] = profile_range(value, u32::MAX)?;
            }
            (1, "i1" | "i2" | "i3" | "i4" | "i5") if awg => {
                profile_obfuscation(value)?;
            }
            (1, "headerprotectionkey") if awg => {
                let key = profile_key(value, true)?;
                header_protection = key.iter().any(|b| *b != 0);
                keys.push(*key);
            }
            (1, "contentpaddingaddition") if awg => {
                content_padding = profile_range(value, 2016)?.1;
            }
            (
                1,
                "rekeyaftertime"
                | "rekeytimeout"
                | "rejectaftertime"
                | "keepalivetimeout"
                | "maxhandshakeattempts",
            ) if awg => {
                // Avoid zero timers/busy loops and second->duration overflow.
                if profile_range(value, 86400)?.0 == 0 {
                    return Err(OwnerError::Invalid);
                }
            }
            _ => return Err(OwnerError::Invalid),
        }
    }
    for (section, key) in [
        (1, "privatekey"),
        (1, "table"),
        (2, "publickey"),
        (2, "allowedips"),
        (2, "endpoint"),
    ] {
        if !seen.contains(&(section, key.into())) {
            return Err(OwnerError::Invalid);
        }
    }
    if awg {
        for (i, left) in headers.iter().enumerate() {
            for right in &headers[i + 1..] {
                if left.0 <= right.1 && right.0 <= left.1 {
                    return Err(OwnerError::Invalid);
                }
            }
        }
        if header_protection && paddings.iter().any(|s| *s < 12) {
            return Err(OwnerError::Invalid);
        }
        // Pinned AWG3 Windows has a 2016-byte message buffer, not the 64KiB
        // default-platform buffer. Include transport tag/header and worst-case
        // alignment padding before accepting the actual profile.
        if [148, 92, 64]
            .iter()
            .zip(paddings)
            .any(|(message, padding)| message + padding > 2016)
            || mtu + paddings[3] + content_padding + 15 + 32 > 2016
            || junk[2] < junk[1]
            || junk[2] > 2016
            || (junk[0] != 0
                && (junk[2] == junk[1]
                    || u64::from(junk[0]) * u64::from(junk[2]) > crate::MAX_FRAME_SIZE as u64))
        {
            return Err(OwnerError::Invalid);
        }
    }
    Ok(ReadonlyNativeProfile {
        origin,
        intent: intent.clone(),
        keys,
    })
}

pub(crate) struct MemberOwner<J, I> {
    intent: Intent,
    configuration: zeroize::Zeroizing<String>,
    journal: J,
    io: I,
    cleanup_only: bool,
    start_consumed: bool,
    original_run: Option<OriginalRun>,
    original_read_revoked: bool,
    rebind_ack: Option<std::rc::Rc<OriginalRebindAck>>,
    profile_origin: std::rc::Rc<()>,
    readonly_profile: Option<std::rc::Rc<ReadonlyNativeProfile>>,
}

impl<J: Journal, I: OriginalMemberPartialCleanupIo> MemberOwner<J, I> {
    pub(crate) fn partial_cleanup_pin(&mut self) -> Result<I::CleanupPin> {
        self.original_read_revoked = true;
        self.io.revoke_original();
        if self.cleanup_only || !self.start_consumed {
            return Err(OwnerError::Retired);
        }
        self.io.partial_cleanup_pin(&self.intent)
    }
    pub(crate) fn inspect_partial_cleanup(
        &mut self,
        pin: &I::CleanupPin,
    ) -> Result<PartialServiceObservation> {
        self.original_read_revoked = true;
        self.io.revoke_original();
        if self.cleanup_only {
            return Err(OwnerError::Retired);
        }
        let before = self.snapshot()?.ok_or(OwnerError::Pending)?;
        let observation = self.io.inspect_partial_cleanup(pin)?;
        if before.phase == Phase::Stopped && !observation.service_deleted() {
            return Err(OwnerError::Conflict);
        }
        self.require_current(&before)?;
        Ok(observation)
    }
    /// Outer original controller/G must retain exact Calling/MemberStop/lock,
    /// no-permits and complete resource/universe fence. This method can ONLY
    /// Stop/Delete this actual retained NEW SCM object, never a NIC or row.
    pub(crate) fn stop_partial_original(
        &mut self,
        expected: &Record,
        pin: &I::CleanupPin,
    ) -> Result<Record> {
        self.original_read_revoked = true;
        self.io.revoke_original();
        if self.cleanup_only {
            return Err(OwnerError::Retired);
        }
        self.require_current(expected)?;
        if expected.previous_config_sha256.is_some() {
            return Err(OwnerError::Conflict);
        }
        if expected.proof.is_some()
            && self.original_run.as_ref().is_none_or(|r| {
                r.running.intent != expected.intent || r.running.proof != expected.proof
            })
        {
            return Err(OwnerError::Conflict);
        }
        let mut stopping = expected.clone();
        if expected.phase != Phase::Stopped {
            self.io.inspect_partial_cleanup(pin)?;
            self.require_current(expected)?;
            stopping.phase = Phase::Stopping;
            if &stopping != expected {
                self.journal
                    .compare_exchange(self.intent.slot, Some(expected), &stopping)?;
            }
        }
        self.require_current(&stopping)?;
        self.io.stop_partial_original(pin)?; // SAME retained SCM only; no recovery fallback.
        let original = self.io.inspect_partial_cleanup(pin)?;
        if !original.service_deleted() || original.process.is_none() {
            // SCM absence/PID zero alone cannot prove an uncertain Start never
            // spawned a process. Only SAME original held-process exit may close
            // a member; the separate unstarted/never-effect lane is unchanged.
            return Err(OwnerError::Pending);
        }
        self.require_current(&stopping)?;
        let before = self.io.inspect(&self.intent, None)?;
        require_no_native(&before)?;
        if before.config_sha256 != Some(self.intent.config_sha256) {
            return Err(OwnerError::Conflict);
        }
        self.require_current(&stopping)?;
        let after = self.io.inspect(&self.intent, None)?;
        require_no_native(&after)?;
        if before != after {
            return Err(OwnerError::Conflict);
        }
        self.require_current(&stopping)?;
        let stopped = Record {
            intent: self.intent.clone(),
            phase: Phase::Stopped,
            proof: None,
            retired_proof: stopping.proof.or(stopping.retired_proof),
            previous_config_sha256: None,
        };
        if stopped != stopping {
            self.journal
                .compare_exchange(self.intent.slot, Some(&stopping), &stopped)?;
        }
        Ok(stopped)
    }
}
impl<J: Journal, I: MemberIo> MemberOwner<J, I> {
    /// Render the existing server profile for an addressless member of the
    /// separately owned carrier. The native owner hashes/publishes only those
    /// rendered bytes. This does not attest C or authorize native creation:
    /// the enclosing factory still supplies real carrier/row/key/WFP guards.
    #[allow(dead_code)] // New factory remains gated on native integration.
    pub(crate) fn from_trusted_carrier_engine(
        carrier: &crate::member_carrier::Intent,
        slot: TunnelSlot,
        transport: TunnelTransport,
        engine: PathBuf,
        logical_configuration: &str,
        journal: J,
        io: I,
    ) -> Result<Self> {
        let rendered = crate::redundancy::pair_configuration(logical_configuration)
            .map_err(|_| OwnerError::Invalid)?;
        if rendered.addresses != carrier.addresses {
            return Err(OwnerError::Conflict);
        }
        Self::from_rendered(
            carrier.scope.clone(),
            slot,
            transport,
            engine,
            rendered.native,
            journal,
            io,
        )
    }
    /// Factory-only: engine is canonical and authenticated by the trusted layout,
    /// never a native path supplied by the app. No production factory is wired.
    pub(crate) fn from_trusted_engine(
        scope: SessionScope,
        slot: TunnelSlot,
        transport: TunnelTransport,
        engine: PathBuf,
        configuration: &str,
        journal: J,
        io: I,
    ) -> Result<Self> {
        let configuration = crate::redundancy::slot_configuration(configuration)
            .map_err(|_| OwnerError::Invalid)?;
        Self::from_rendered(scope, slot, transport, engine, configuration, journal, io)
    }
    /// Both renderers keep their own validation semantics. Never run the
    /// ordinary Address-preserving renderer on a carrier member's native bytes.
    fn from_rendered(
        scope: SessionScope,
        slot: TunnelSlot,
        transport: TunnelTransport,
        engine: PathBuf,
        configuration: zeroize::Zeroizing<String>,
        journal: J,
        io: I,
    ) -> Result<Self> {
        if !scope.validate()
            || !engine.is_absolute()
            || engine.to_str().is_none()
            || engine.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(OwnerError::Invalid);
        }
        if nelomai_client_tunnel::detect_configuration_transport(&configuration) != transport {
            return Err(OwnerError::Invalid);
        }
        let config_sha256 = Sha256::digest(configuration.as_bytes()).into();
        Ok(Self {
            intent: Intent {
                scope,
                slot,
                transport,
                engine,
                config_sha256,
            },
            configuration,
            journal,
            io,
            cleanup_only: false,
            start_consumed: false,
            original_run: None,
            original_read_revoked: false,
            rebind_ack: None,
            profile_origin: std::rc::Rc::new(()),
            readonly_profile: None,
        })
    }
    /// Reopen durable authority only. This constructor never reads configuration
    /// secrets or creates/adopts native resources. The runtime owner supplies the
    /// trusted engine and scope independently of the saved record.
    pub(crate) fn recover_for_cleanup(
        scope: SessionScope,
        slot: TunnelSlot,
        transport: TunnelTransport,
        engine: PathBuf,
        saved: Record,
        journal: J,
        io: I,
    ) -> Result<Self> {
        if !scope.validate()
            || saved.intent.scope != scope
            || saved.intent.slot != slot
            || saved.intent.transport != transport
            || saved.intent.engine != engine
            || !engine.is_absolute()
            || engine.to_str().is_none()
            || engine.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(OwnerError::Invalid);
        }
        let mut owner = Self {
            intent: saved.intent.clone(),
            configuration: zeroize::Zeroizing::new(String::new()),
            journal,
            io,
            cleanup_only: true,
            start_consumed: true,
            original_run: None,
            original_read_revoked: true,
            rebind_ack: None,
            profile_origin: std::rc::Rc::new(()),
            readonly_profile: None,
        };
        owner.require_current(&saved)?;
        Ok(owner)
    }
    pub(crate) fn snapshot(&mut self) -> Result<Option<Record>> {
        let current = self.journal.load(self.intent.slot)?;
        if let Some(record) = &current {
            self.validate_record(record)?;
        }
        Ok(current)
    }
    pub(crate) fn intent(&self) -> &Intent {
        &self.intent
    }
    /// No journal, filesystem, SCM, DLL, SDK or network access. The retained
    /// proof is a mandatory parser prerequisite, NOT whole cold readiness.
    pub(crate) fn prepare_readonly_native_profile(
        &mut self,
    ) -> Result<std::rc::Rc<ReadonlyNativeProfile>> {
        if let Some(profile) = &self.readonly_profile {
            self.verify_readonly_native_profile(profile)?;
            return Ok(profile.clone());
        }
        if self.cleanup_only || self.start_consumed {
            return Err(OwnerError::Retired);
        }
        let profile = std::rc::Rc::new(compile_readonly_profile(
            &self.intent,
            self.profile_origin.clone(),
            &self.configuration,
        )?);
        self.readonly_profile = Some(profile.clone()); // BEFORE caller postflight.
        Ok(profile)
    }
    pub(crate) fn verify_readonly_native_profile(
        &self,
        profile: &ReadonlyNativeProfile,
    ) -> Result<()> {
        if self.cleanup_only
            || !std::rc::Rc::ptr_eq(&self.profile_origin, &profile.origin)
            || self
                .readonly_profile
                .as_ref()
                .is_none_or(|p| !std::ptr::eq(p.as_ref(), profile))
            || profile.intent != self.intent
            || profile.keys.len() < 2
            || Sha256::digest(self.configuration.as_bytes())[..] != profile.intent.config_sha256
        {
            return Err(OwnerError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn readonly_native_profile(&self) -> Result<&ReadonlyNativeProfile> {
        self.readonly_profile.as_deref().ok_or(OwnerError::Pending)
    }
    /// Borrow a read-only capability. Acquisition yields no cached facts; every
    /// read refreshes the actual dependencies. No caller-supplied Record/proof
    /// can seed provenance, including an idempotent Start of an existing member.
    #[allow(dead_code)] // Main's native lifecycle gate has not yet consumed this API.
    pub(crate) fn original_live(&mut self) -> Result<OriginalLiveMember<'_, J, I>> {
        if self.original_read_revoked
            || self.cleanup_only
            || self.original_run.as_ref().is_none_or(|run| !run.committed)
        {
            self.original_read_revoked = true;
            self.io.revoke_original();
            return Err(OwnerError::Retired);
        }
        Ok(OriginalLiveMember { owner: self })
    }
    #[allow(dead_code)] // Validation used only by the still-gated read consumer.
    fn read_original_live(&mut self) -> Result<(Intent, NativeProof)> {
        if self.original_read_revoked {
            return Err(OwnerError::Retired);
        }
        self.read_original(false)
    }
    /// Only an actual committed original-run receipt in THIS owner can supply
    /// cleanup facts. Equal durable Running data/recovery has no such receipt.
    pub(crate) fn read_original_for_cleanup(&mut self) -> Result<(Intent, NativeProof)> {
        self.original_read_revoked = true;
        self.io.revoke_original();
        self.read_original(true)
    }
    fn read_original(&mut self, cleanup: bool) -> Result<(Intent, NativeProof)> {
        let expected = self
            .original_run
            .as_ref()
            .filter(|run| run.committed)
            .ok_or(OwnerError::Retired)?
            .running
            .clone();
        let retained = expected.proof.ok_or(OwnerError::Invalid)?;
        // Durable -> native -> durable -> native -> durable. In particular a
        // native read that changes the journal cannot escape the final fence.
        // This is sampled factual readback under the actual mutable owner borrow,
        // not an atomic cross-resource CAS or native lifecycle authorization.
        self.require_current(&expected)?;
        let before = if cleanup {
            self.io
                .inspect_original_for_cleanup(&self.intent, &retained)
        } else {
            self.io.inspect_original(&self.intent, &retained)
        }?;
        original_running_proof(&expected, &before)?;
        self.require_current(&expected)?;
        let after = if cleanup {
            self.io
                .inspect_original_for_cleanup(&self.intent, &retained)
        } else {
            self.io.inspect_original(&self.intent, &retained)
        }?;
        let proof = original_running_proof(&expected, &after)?;
        if before != after {
            return Err(OwnerError::Conflict);
        }
        self.require_current(&expected)?;
        Ok((expected.intent, proof))
    }
    pub(crate) fn verify_live(&mut self, expected: &Record) -> Result<()> {
        if self.cleanup_only || expected.phase != Phase::Running {
            return Err(OwnerError::Pending);
        }
        self.verify_retained(expected)
    }
    /// Read-only proof verification is also available to a cleanup owner. It
    /// does not confer Start/rebind authority or adopt a currently named member.
    pub(crate) fn verify_retained(&mut self, expected: &Record) -> Result<()> {
        if !matches!(expected.phase, Phase::Running | Phase::Stopping) {
            return Err(OwnerError::Pending);
        }
        self.require_current(expected)?;
        let proof = expected.proof.ok_or(OwnerError::Invalid)?;
        let current = self.io.inspect(&self.intent, Some(&proof))?;
        authorize(expected, &current)?;
        if current.service.as_ref().and_then(|s| s.process) != Some(proof.process)
            || current.interface != Some(proof.interface)
        {
            return Err(OwnerError::Conflict);
        }
        Ok(())
    }
    pub(crate) fn confirm_absent(&mut self, expected: &Record) -> Result<bool> {
        self.require_current(expected)?;
        let current = self.io.inspect(
            &self.intent,
            expected.proof.as_ref().or(expected.retired_proof.as_ref()),
        )?;
        authorize(expected, &current)?;
        if current.service.is_none()
            && current.interface.is_none()
            && current.retained_interfaces.is_empty()
        {
            Ok(true)
        } else {
            Ok(false)
        }
    }
    /// Read-only physical discovery is independent of an owned service's
    /// liveness. An exact installed-but-stopped service is acceptable here,
    /// never as native absence for cleanup, slot reuse or adoption.
    pub(crate) fn confirm_inactive_for_discovery(&mut self, expected: &Record) -> Result<bool> {
        self.require_current(expected)?;
        let retained = expected
            .proof
            .or(expected.retired_proof)
            .ok_or(OwnerError::Invalid)?;
        let current = self.io.inspect(&self.intent, Some(&retained))?;
        authorize(expected, &current)?;
        self.require_current(expected)?;
        Ok(current.service.as_ref().is_none_or(|s| s.process.is_none())
            && current.interface.is_none()
            && current.retained_interfaces.is_empty())
    }
    #[cfg(test)]
    pub(crate) fn start(&mut self) -> Result<Record> {
        self.start_inner(None)
    }
    /// Bind the native CAS to the exact predecessor persisted by the pair owner.
    pub(crate) fn start_with_prior(&mut self, prior: Option<&Record>) -> Result<Record> {
        self.start_inner(Some(prior))
    }
    pub(crate) fn prior_stopped(&mut self) -> Result<Option<Record>> {
        if self.cleanup_only || self.start_consumed {
            return Err(OwnerError::Retired);
        }
        let prior = self.journal.load(self.intent.slot)?;
        if let Some(old) = &prior {
            validate_prior_stopped(&self.intent, old)?;
        }
        let observed = self.io.inspect(
            &self.intent,
            prior.as_ref().and_then(|r| r.retired_proof.as_ref()),
        )?;
        if let Some(old) = &prior {
            authorize(old, &observed)?;
        } else if observed.config_sha256.is_some() {
            return Err(OwnerError::Conflict);
        }
        require_no_native(&observed)?;
        Ok(prior)
    }
    fn start_inner(&mut self, expected_prior: Option<Option<&Record>>) -> Result<Record> {
        if self.cleanup_only || self.start_consumed {
            return Err(OwnerError::Retired);
        }
        self.start_consumed = true;
        // A FRESH factory owner can reincarnate only a positively retired slot.
        // Read directly: its old scope/config need not equal the new intent.
        let previous = self.journal.load(self.intent.slot)?;
        if expected_prior.is_some_and(|expected| previous.as_ref() != expected) {
            return Err(OwnerError::Conflict);
        }
        if let Some(old) = &previous {
            validate_prior_stopped(&self.intent, old)?;
        }
        let retired = previous.as_ref().and_then(|old| old.retired_proof);
        let before = self.io.inspect(&self.intent, retired.as_ref())?;
        if let Some(old) = &previous {
            authorize(old, &before)?;
            require_no_native(&before)?;
        } else {
            require_absent(&self.intent, &before)?;
            if before.config_sha256.is_some() {
                return Err(OwnerError::Conflict);
            }
        }
        let mut prepared = Record {
            intent: self.intent.clone(),
            phase: Phase::Prepared,
            proof: None,
            retired_proof: retired,
            previous_config_sha256: before.config_sha256,
        };
        self.journal
            .compare_exchange(self.intent.slot, previous.as_ref(), &prepared)?;
        self.require_current(&prepared)?;
        let still_absent = self.io.inspect(&self.intent, retired.as_ref())?;
        authorize(&prepared, &still_absent)?;
        require_no_native(&still_absent)?;
        if before.config_sha256 != still_absent.config_sha256 {
            return Err(OwnerError::Conflict);
        }
        self.io
            .write_private_config(&self.intent, before.config_sha256, &self.configuration)?;
        let ready = self.io.inspect(&self.intent, retired.as_ref())?;
        require_absent(&self.intent, &ready)?;
        if ready.config_sha256 != Some(self.intent.config_sha256) {
            return Err(OwnerError::Conflict);
        }
        if prepared.previous_config_sha256.is_some() {
            let mut ready = prepared.clone();
            ready.previous_config_sha256 = None;
            self.journal
                .compare_exchange(self.intent.slot, Some(&prepared), &ready)?;
            prepared = ready;
        }
        self.require_current(&prepared)?;
        let mut attempt = OriginalReadAttempt {
            owner: self,
            succeeded: false,
        };
        attempt
            .owner
            .io
            .start_fresh(&attempt.owner.intent, retired.as_ref())?;
        let running = attempt.owner.capture_running(&prepared, true)?;
        attempt.succeeded = true;
        Ok(running)
    }
    pub(crate) fn stop(&mut self, expected: &Record) -> Result<Record> {
        self.original_read_revoked = true;
        self.io.revoke_original();
        self.start_consumed = true;
        self.require_current(expected)?;
        if expected.previous_config_sha256.is_some() {
            // No SCM effect is ever permitted while either config digest is
            // acceptable. Retain both exact digests across terminal cleanup.
            let before = self
                .io
                .inspect(&self.intent, expected.retired_proof.as_ref())?;
            authorize(expected, &before)?;
            require_no_native(&before)?;
            let after = self
                .io
                .inspect(&self.intent, expected.retired_proof.as_ref())?;
            authorize(expected, &after)?;
            require_no_native(&after)?;
            if before != after {
                return Err(OwnerError::Conflict);
            }
            let mut stopped = expected.clone();
            stopped.phase = Phase::Stopped;
            if &stopped != expected {
                self.journal
                    .compare_exchange(self.intent.slot, Some(expected), &stopped)?;
            }
            return Ok(stopped);
        }
        if expected.phase == Phase::Stopped {
            return Ok(expected.clone());
        }
        let before = self.io.inspect(&self.intent, expected.proof.as_ref())?;
        authorize(expected, &before)?;
        self.authorize_cleanup(expected, &before)?;
        let mut stopping = expected.clone();
        stopping.phase = Phase::Stopping;
        if &stopping != expected {
            self.journal
                .compare_exchange(self.intent.slot, Some(expected), &stopping)?;
        }
        let current = self.io.inspect(&self.intent, stopping.proof.as_ref())?;
        authorize(&stopping, &current)?;
        self.authorize_cleanup(&stopping, &current)?;
        if current.service.is_some() {
            self.io
                .stop_slot(&self.intent, stopping.proof.as_ref(), &current)?;
        }
        let after = self.io.inspect(&self.intent, stopping.proof.as_ref())?;
        authorize(&stopping, &after)?;
        if after.service.is_some()
            || after.interface.is_some()
            || !after.retained_interfaces.is_empty()
        {
            return Err(OwnerError::Pending);
        }
        let stopped = Record {
            intent: self.intent.clone(),
            phase: Phase::Stopped,
            proof: None,
            retired_proof: stopping.proof.or(stopping.retired_proof),
            previous_config_sha256: None,
        };
        self.journal
            .compare_exchange(self.intent.slot, Some(&stopping), &stopped)?;
        Ok(stopped)
    }
    /// Stop is a revocation of already-proven native authority. A failed durable
    /// Stopping write must not keep that process forwarding. Preserve the first
    /// error and the old durable proof for exact cleanup on a later attempt.
    pub(crate) fn stop_best_effort(&mut self, expected: &Record) -> Result<Record> {
        match self.stop(expected) {
            Ok(record) => Ok(record),
            Err(error) => {
                let cut = (|| {
                    let current = self.snapshot()?.ok_or(OwnerError::Conflict)?;
                    if current.intent != expected.intent
                        || current.proof != expected.proof
                        || current.retired_proof != expected.retired_proof
                    {
                        return Err(OwnerError::Conflict);
                    }
                    let observed = self.io.inspect(&self.intent, current.proof.as_ref())?;
                    authorize(&current, &observed)?;
                    self.authorize_cleanup(&current, &observed)?;
                    if observed.service.is_some() {
                        self.io
                            .stop_slot(&self.intent, current.proof.as_ref(), &observed)?;
                    }
                    Ok(())
                })();
                let _ = cut; // Original failure remains the caller-visible result.
                Err(error)
            }
        }
    }
    /// Enclosing guard/route owner MUST fence routes before calling this and
    /// retain that fence until the new proof is durable. No route work occurs here.
    pub(crate) fn rebind(&mut self, expected: &Record) -> Result<Record> {
        self.original_read_revoked = true;
        self.io.revoke_original();
        if self.cleanup_only {
            return Err(OwnerError::Retired);
        }
        self.require_current(expected)?;
        if expected.phase != Phase::Running {
            return Err(OwnerError::Pending);
        }
        let proof = expected.proof.ok_or(OwnerError::Invalid)?;
        let before = self.io.inspect(&self.intent, Some(&proof))?;
        authorize(expected, &before)?;
        if before.service.as_ref().and_then(|s| s.process) != Some(proof.process)
            || before.interface != Some(proof.interface)
        {
            return Err(OwnerError::Conflict);
        }
        let prepared = Record {
            intent: self.intent.clone(),
            phase: Phase::Prepared,
            proof: None,
            retired_proof: Some(proof),
            previous_config_sha256: None,
        };
        self.journal
            .compare_exchange(self.intent.slot, Some(expected), &prepared)?;
        self.io.rebind(&self.intent, &proof, &before)?;
        self.capture_running(&prepared, false)
    }
    fn capture_running(&mut self, prepared: &Record, fresh_start: bool) -> Result<Record> {
        let current = self.io.inspect(&self.intent, None)?;
        authorize(prepared, &current)?;
        let proof = NativeProof {
            process: current
                .service
                .as_ref()
                .and_then(|s| s.process)
                .ok_or(OwnerError::Pending)?,
            interface: current.interface.ok_or(OwnerError::Pending)?,
        };
        validate_proof(&proof)?;
        // An acknowledged rebind must retire the process identity, even if the
        // driver legitimately retains its interface. Never revive old authority.
        if prepared
            .retired_proof
            .is_some_and(|old| old.process == proof.process)
        {
            return Err(OwnerError::Conflict);
        }
        let running = Record {
            intent: self.intent.clone(),
            phase: Phase::Running,
            proof: Some(proof),
            retired_proof: prepared.retired_proof,
            previous_config_sha256: None,
        };
        if fresh_start {
            // Reached only after THIS instance's start_fresh returned Ok and
            // independent inspection captured valid process/interface evidence.
            self.original_run = Some(OriginalRun {
                running: running.clone(),
                committed: false,
            });
        }
        self.journal
            .compare_exchange(self.intent.slot, Some(prepared), &running)?;
        if fresh_start {
            if let Some(run) = &mut self.original_run {
                run.committed = true;
            }
        }
        Ok(running)
    }
    fn require_current(&mut self, expected: &Record) -> Result<()> {
        self.validate_record(expected)?;
        if self.snapshot()?.as_ref() != Some(expected) {
            return Err(OwnerError::Conflict);
        }
        Ok(())
    }
    fn authorize_cleanup(&self, record: &Record, current: &Observation) -> Result<()> {
        if self.cleanup_only
            && current.service.as_ref().and_then(|s| s.process).is_some()
            && record.proof.is_none()
        {
            return Err(OwnerError::Conflict);
        }
        Ok(())
    }
    fn validate_record(&self, record: &Record) -> Result<()> {
        if record.intent != self.intent {
            return Err(OwnerError::Conflict);
        }
        validate_record_shape(record)
    }
}

impl<J: Journal, I: OriginalMemberRebindIo> MemberOwner<J, I> {
    /// Enclosing controller MUST retain its exact no-permits/retired-probe,
    /// network/rows/static-base/SDK/current Pair fence across this operation.
    /// Neither a caller Record nor legacy rebind can seed original provenance.
    pub(crate) fn rebind_original(
        &mut self,
        expected: &Record,
    ) -> Result<(Record, std::rc::Rc<OriginalRebindAck>)> {
        let was_revoked = self.original_read_revoked;
        self.original_read_revoked = true;
        self.io.revoke_original();
        if self.cleanup_only
            || was_revoked
            || self
                .original_run
                .as_ref()
                .is_none_or(|run| !run.committed || run.running != *expected)
        {
            return Err(OwnerError::Retired);
        }
        // Factual read through the same retained original, never re-arm an old
        // forward pin while validating the replacement proposal.
        let facts = self.read_original(true)?;
        let old = expected.proof.ok_or(OwnerError::Pending)?;
        if facts != (expected.intent.clone(), old) || expected.phase != Phase::Running {
            return Err(OwnerError::Conflict);
        }
        let mut attempt = OriginalReadAttempt {
            owner: self,
            succeeded: false,
        };
        let owner = &mut attempt.owner;
        owner.original_read_revoked = true;
        owner.io.revoke_original();
        owner.require_current(expected)?;
        let prepared = Record {
            intent: owner.intent.clone(),
            phase: Phase::Prepared,
            proof: None,
            retired_proof: Some(old),
            previous_config_sha256: None,
        };
        owner
            .journal
            .compare_exchange(owner.intent.slot, Some(expected), &prepared)?;
        let ack = owner.io.rebind_original(&owner.intent, &old)?;
        owner.rebind_ack = Some(ack.clone()); // Root actual native ACK before fallible CAS/postflight.
        let next = owner.io.read_rebound_original(&ack)?;
        if ack.intent() != &owner.intent
            || ack.old_proof() != old
            || ack.replacement_proof()? != next
            || next.process == old.process
            || next.interface != old.interface
        {
            return Err(OwnerError::Conflict);
        }
        let running = Record {
            intent: owner.intent.clone(),
            phase: Phase::Running,
            proof: Some(next),
            retired_proof: Some(old),
            previous_config_sha256: None,
        };
        owner.original_run = Some(OriginalRun {
            running: running.clone(),
            committed: false,
        });
        owner
            .journal
            .compare_exchange(owner.intent.slot, Some(&prepared), &running)?;
        owner
            .original_run
            .as_mut()
            .ok_or(OwnerError::Pending)?
            .committed = true;
        owner.require_current(&running)?;
        if owner.io.read_rebound_original(&ack)? != next {
            return Err(OwnerError::Conflict);
        }
        owner.require_current(&running)?;
        owner.original_read_revoked = false; // Only SAME acknowledged native replacement, never old proof.
        attempt.succeeded = true;
        Ok((running, ack))
    }
    pub(crate) fn verify_original_rebind(
        &mut self,
        ack: &std::rc::Rc<OriginalRebindAck>,
        running: &Record,
    ) -> Result<()> {
        if self.original_read_revoked
            || self
                .rebind_ack
                .as_ref()
                .is_none_or(|own| !std::rc::Rc::ptr_eq(own, ack))
            || self
                .original_run
                .as_ref()
                .is_none_or(|run| !run.committed || run.running != *running)
            || running.intent != *ack.intent()
            || running.proof != Some(ack.replacement_proof()?)
            || running.retired_proof != Some(ack.old_proof())
        {
            return Err(OwnerError::Retired);
        }
        let mut attempt = OriginalReadAttempt {
            owner: self,
            succeeded: false,
        };
        for _ in 0..2 {
            attempt.owner.require_current(running)?;
            if Some(attempt.owner.io.read_rebound_original(ack)?) != running.proof {
                return Err(OwnerError::Conflict);
            }
        }
        attempt.owner.require_current(running)?;
        attempt.succeeded = true;
        Ok(())
    }
}

#[allow(dead_code)] // Native proof projection for the still-gated read consumer.
fn original_running_proof(record: &Record, current: &Observation) -> Result<NativeProof> {
    authorize(record, current)?;
    let actual = NativeProof {
        process: current
            .service
            .as_ref()
            .and_then(|service| service.process)
            .ok_or(OwnerError::Conflict)?,
        interface: current.interface.ok_or(OwnerError::Conflict)?,
    };
    if record.phase != Phase::Running || record.proof != Some(actual) {
        return Err(OwnerError::Conflict);
    }
    Ok(actual)
}

pub(crate) fn validate_prior_stopped(intent: &Intent, record: &Record) -> Result<()> {
    validate_record_shape(record)?;
    // A global slot's terminal journal survives engine/runtime updates. This
    // permits only predecessor validation for a FRESH owner: callers still
    // bind the exact prior record, authorize its config digest and positively
    // prove native/retired identity absence before CAS. It grants no authority
    // to run the old engine, adopt native resources or resume a cleanup owner.
    if record.intent.slot != intent.slot {
        return Err(OwnerError::Conflict);
    }
    if record.phase != Phase::Stopped {
        return Err(OwnerError::Pending);
    }
    Ok(())
}
pub(crate) fn validate_record_shape(record: &Record) -> Result<()> {
    if !record.intent.scope.validate()
        || !record.intent.engine.is_absolute()
        || record.intent.engine.to_str().is_none()
        || record.intent.engine.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
        || (record.previous_config_sha256.is_some()
            && (!matches!(record.phase, Phase::Prepared | Phase::Stopped)
                || record.proof.is_some()))
    {
        return Err(OwnerError::Invalid);
    }
    match record.phase {
        Phase::Running if record.proof.is_none() => return Err(OwnerError::Invalid),
        Phase::Prepared | Phase::Stopped if record.proof.is_some() => {
            return Err(OwnerError::Invalid)
        }
        _ => (),
    }
    for proof in [record.proof, record.retired_proof].into_iter().flatten() {
        validate_proof(&proof)?;
    }
    if record
        .proof
        .zip(record.retired_proof)
        .is_some_and(|(live, retired)| live.process == retired.process)
    {
        return Err(OwnerError::Invalid);
    }
    Ok(())
}

fn validate_proof(proof: &NativeProof) -> Result<()> {
    if proof.process.pid == 0
        || proof.process.creation_time == 0
        || proof.interface.index == 0
        || proof.interface.luid == 0
        || proof.interface.guid == [0; 16]
    {
        return Err(OwnerError::Invalid);
    }
    Ok(())
}
/// A missing SCM name does not prove the retained process has exited. A reused
/// PID is a conflict, not absence; access/query errors stay errors in native IO.
pub(crate) fn require_retired_process_absent(
    expected: &ProcessProof,
    current: Option<(ProcessProof, u32)>,
) -> Result<()> {
    if expected.pid == 0 || expected.creation_time == 0 {
        return Err(OwnerError::Invalid);
    }
    match current {
        None => Ok(()),
        Some((actual, _)) if actual != *expected => Err(OwnerError::Conflict),
        Some((_, 259)) => Err(OwnerError::Pending),
        Some(_) => Ok(()),
    }
}
fn require_absent(intent: &Intent, current: &Observation) -> Result<()> {
    require_no_native(current)?;
    if current
        .config_sha256
        .is_some_and(|hash| hash != intent.config_sha256)
    {
        return Err(OwnerError::Conflict);
    }
    Ok(())
}
fn require_no_native(current: &Observation) -> Result<()> {
    if current.service.is_some()
        || current.alternative_service_present
        || current.interface.is_some()
        || !current.retained_interfaces.is_empty()
    {
        return Err(OwnerError::Conflict);
    }
    Ok(())
}
fn authorize(record: &Record, current: &Observation) -> Result<()> {
    if let Some(previous) = record.previous_config_sha256 {
        validate_record_shape(record)?;
        require_no_native(current)?;
        return if current
            .config_sha256
            .is_none_or(|hash| hash == previous || hash == record.intent.config_sha256)
        {
            Ok(())
        } else {
            Err(OwnerError::Conflict)
        };
    }
    if current.alternative_service_present
        || current
            .config_sha256
            .is_some_and(|hash| hash != record.intent.config_sha256)
    {
        return Err(OwnerError::Conflict);
    }
    if let Some(service) = &current.service {
        if !service.exact_spec || current.config_sha256 != Some(record.intent.config_sha256) {
            return Err(OwnerError::Conflict);
        }
    } else if current.interface.is_some() || !current.retained_interfaces.is_empty() {
        // No name-only interface destruction if SCM has already disappeared.
        return Err(OwnerError::Conflict);
    }
    if let Some(proof) = record.proof {
        if current.interface.is_some_and(|i| i != proof.interface)
            || current
                .retained_interfaces
                .iter()
                .any(|i| *i != proof.interface)
        {
            return Err(OwnerError::Conflict);
        }
        if let Some(process) = current.service.as_ref().and_then(|s| s.process) {
            if process != proof.process || current.interface != Some(proof.interface) {
                return Err(OwnerError::Conflict);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "member_owner_tests.rs"]
mod tests;

// DATA-only backend validation; never executable load or effect authority.
pub(super) mod cold_wireguard_data {
    pub(crate) fn verify_cold_backend_modules(
        transport: nelomai_client_tunnel::TunnelTransport,
        mut query: impl FnMut(&'static str) -> Result<Option<()>>,
    ) -> Result<()> {
        use nelomai_client_tunnel::TunnelTransport;
        let names: &[&str] = match transport {
            TunnelTransport::WireGuard => &["wireguard.dll", "tunnel.dll"],
            TunnelTransport::AmneziaWg3 => &["amneziawg-tunnel.dll"],
        };
        for _ in 0..2 {
            for name in names {
                if query(name)?.is_some() {
                    return Err(Error::Changed);
                }
            }
        }
        Ok(())
    }
    // Official packager-pinned wireguard-nt-1.1.zip SHA256:
    // dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace.
    // Independently inspected as DATA in memory; never loaded/extracted to a runtime.
    pub(super) fn require_audited_source_digest(digest: &[u8; 32]) -> Result<()> {
        if *digest
            != [
                0xb1, 0xb8, 0x5e, 0x07, 0x2c, 0x45, 0xd8, 0x13, 0x58, 0xbe, 0x29, 0xd9, 0x4c, 0x59,
                0x9d, 0xc7, 0x66, 0x52, 0xf9, 0x12, 0xbe, 0x8c, 0x0f, 0x0a, 0x41, 0xe2, 0xd5, 0xd8,
                0x9a, 0x64, 0x61, 0xd3,
            ]
        {
            return Err(Error::Unsupported("unaudited WireGuardNT executable"));
        }
        Ok(())
    }
    #[derive(Debug, PartialEq, Eq)]
    pub(super) struct SharePolicy {
        pub(super) read: bool,
        pub(super) write: bool,
        pub(super) delete: bool,
    }
    pub(super) fn share_policy(directory: bool) -> SharePolicy {
        SharePolicy {
            read: true,
            write: directory,
            delete: false,
        }
    }

    #[cfg(windows)]
    pub(crate) mod native {
        use super::*;
        use crate::windows::member_owner::NativeWireGuardSource;
        use sha2::Digest;
        use std::{
            fs::{File, OpenOptions},
            mem::{offset_of, size_of},
            os::windows::{
                fs::{FileExt, OpenOptionsExt},
                io::AsRawHandle,
            },
            path::{Component, Path, PathBuf},
            ptr,
        };
        use windows_sys::{
            core::w,
            Wdk::System::SystemServices::RtlGetVersion,
            Win32::{
                Devices::DeviceAndDriverInstallation::*,
                Foundation::{
                    GetLastError, ERROR_FILE_NOT_FOUND, ERROR_HANDLE_EOF, ERROR_INVALID_DATA,
                    ERROR_NO_MORE_ITEMS, ERROR_SERVICE_DOES_NOT_EXIST, FILETIME,
                    INVALID_HANDLE_VALUE,
                },
                Security::{Cryptography::Catalog::*, WinTrust::*},
                Storage::FileSystem::*,
                System::{
                    Registry::*,
                    Services::*,
                    SystemInformation::{
                        GetSystemDirectoryW, GetWindowsDirectoryW, OSVERSIONINFOW,
                    },
                    Threading::{GetCurrentProcess, IsWow64Process2},
                },
            },
        };

        const BUFFER: usize = 64 * 1024;
        const MAX_NODES: u32 = 16_384;
        fn last(op: &'static str) -> Error {
            Error::Native(op, unsafe { GetLastError() })
        }
        fn io(op: &'static str, e: std::io::Error) -> Error {
            Error::Native(op, e.raw_os_error().unwrap_or(-1) as u32)
        }
        fn wide(s: &str) -> Result<Vec<u16>> {
            if s.contains('\0') || s.encode_utf16().count() > 32767 {
                return Err(Error::Invalid("native path/string"));
            }
            Ok(s.encode_utf16().chain([0]).collect())
        }
        fn ft(t: FILETIME) -> u64 {
            (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime)
        }
        fn native_platform() -> Result<bool> {
            let mut os = OSVERSIONINFOW {
                dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
                ..Default::default()
            };
            let status = unsafe { RtlGetVersion(&mut os) };
            if status != 0 {
                return Err(Error::Native("RtlGetVersion", status as u32));
            }
            if os.dwMajorVersion != 10 || os.dwMinorVersion != 0 || os.dwBuildNumber < 10240 {
                return Ok(false);
            }
            let (mut process, mut machine) = (0, 0);
            if unsafe { IsWow64Process2(GetCurrentProcess(), &mut process, &mut machine) } == 0 {
                return Err(last("IsWow64Process2"));
            }
            Ok(process == 0 && machine == 0x8664 && cfg!(target_arch = "x86_64"))
        }
        fn os_directory(system: bool) -> Result<PathBuf> {
            let mut b = [0u16; 32768];
            let n = unsafe {
                if system {
                    GetSystemDirectoryW(b.as_mut_ptr(), b.len() as u32)
                } else {
                    GetWindowsDirectoryW(b.as_mut_ptr(), b.len() as u32)
                }
            } as usize;
            if n == 0 {
                return Err(last("Get OS directory"));
            }
            if n >= b.len() {
                return Err(Error::Invalid("OS directory bound"));
            }
            Ok(PathBuf::from(wide_z(&b[..n + 1])?))
        }
        fn clean_absolute(path: &Path) -> Result<()> {
            let mut c = path.components();
            match c.next() {
                Some(Component::Prefix(p)) if matches!(p.kind(), std::path::Prefix::Disk(_)) => {}
                _ => return Err(Error::Unsupported("local DOS path required")),
            }
            if c.next() != Some(Component::RootDir) || c.any(|c| !matches!(c, Component::Normal(_)))
            {
                return Err(Error::Invalid("noncanonical native path"));
            }
            // Alternate data streams, device paths, trailing-dot/space aliases rejected.
            for part in path.components().filter_map(|c| {
                if let Component::Normal(p) = c {
                    Some(p)
                } else {
                    None
                }
            }) {
                let s = part.to_str().ok_or(Error::Invalid("non-Unicode path"))?;
                if s.contains(':') || s.ends_with(['.', ' ']) {
                    return Err(Error::Invalid("aliased native path"));
                }
            }
            Ok(())
        }
        fn same_path(a: &Path, b: &Path) -> bool {
            a.to_str()
                .zip(b.to_str())
                .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
        }
        fn final_path(file: &File) -> Result<PathBuf> {
            let mut b = [0u16; 32768];
            let n = unsafe {
                GetFinalPathNameByHandleW(
                    file.as_raw_handle(),
                    b.as_mut_ptr(),
                    b.len() as u32,
                    FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
                )
            } as usize;
            if n == 0 {
                return Err(last("GetFinalPathNameByHandleW"));
            }
            if n >= b.len() {
                return Err(Error::Invalid("final path bound"));
            }
            let text = wide_z(&b[..n + 1])?;
            let text = text
                .strip_prefix("\\\\?\\")
                .ok_or(Error::Invalid("final DOS path"))?;
            let path = PathBuf::from(text);
            clean_absolute(&path)?;
            Ok(path)
        }
        fn stamp(file: &File, directory: bool) -> Result<Stamp> {
            stamp_links(file, directory, 1)
        }
        fn stamp_links(file: &File, directory: bool, links: u32) -> Result<Stamp> {
            let mut info = BY_HANDLE_FILE_INFORMATION::default();
            if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
                return Err(last("GetFileInformationByHandle"));
            }
            if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
                || (!directory && (info.nNumberOfLinks != links || !matches!(links, 1 | 2)))
            {
                return Err(Error::Invalid("reparse/type/link count"));
            }
            Ok(Stamp {
                volume: info.dwVolumeSerialNumber,
                id: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
                size: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
                modified: ft(info.ftLastWriteTime),
            })
        }
        fn readonly_open(path: &Path, directory: bool) -> Result<File> {
            readonly_open_links(path, directory, 1)
        }
        fn readonly_open_links(path: &Path, directory: bool, links: u32) -> Result<File> {
            clean_absolute(path)?;
            let flags = FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    0
                };
            let file = OpenOptions::new()
                .read(true)
                // Attribute/security-only ancestor handles permit normal directory
                // activity. Payload handles retain GENERIC_READ and deny write/delete.
                .access_mode(if directory {
                    FILE_READ_ATTRIBUTES | READ_CONTROL
                } else {
                    windows_sys::Win32::Foundation::GENERIC_READ
                })
                .share_mode({
                    let policy = share_policy(directory);
                    (u32::from(policy.read) * FILE_SHARE_READ)
                        | (u32::from(policy.write) * FILE_SHARE_WRITE)
                        | (u32::from(policy.delete) * FILE_SHARE_DELETE)
                })
                .custom_flags(flags)
                .open(path)
                .map_err(|e| io("open readonly pin", e))?;
            stamp_links(&file, directory, links)?;
            if !same_path(&final_path(&file)?, path) {
                return Err(Error::Changed);
            }
            Ok(file)
        }
        struct Pin {
            file: File,
            path: PathBuf,
            parents: Vec<(File, PathBuf, Stamp)>,
            driver_links: Option<([String; 2], Vec<String>)>,
        }
        fn hardlink_names(path: &Path) -> Result<Vec<String>> {
            clean_absolute(path)?;
            let text = path.to_str().ok_or(Error::Invalid("link path"))?;
            let volume = text.get(..2).ok_or(Error::Invalid("link volume"))?;
            let path = wide(text)?;
            let mut buffer = vec![0u16; 32768];
            let mut length = buffer.len() as u32;
            let raw =
                unsafe { FindFirstFileNameW(path.as_ptr(), 0, &mut length, buffer.as_mut_ptr()) };
            if raw == INVALID_HANDLE_VALUE {
                return Err(last("FindFirstFileNameW"));
            }
            struct Search(windows_sys::Win32::Foundation::HANDLE);
            impl Drop for Search {
                fn drop(&mut self) {
                    unsafe { FindClose(self.0) };
                }
            }
            let search = Search(raw);
            let mut result = vec![];
            loop {
                if length as usize > buffer.len() {
                    return Err(Error::Invalid("hardlink buffer"));
                }
                let name = wide_z(&buffer)?;
                if !name.starts_with('\\') || name.starts_with(r"\\") {
                    return Err(Error::Invalid("hardlink rooted path"));
                }
                let full = format!("{volume}{name}");
                clean_absolute(Path::new(&full))?;
                result.push(full.to_ascii_lowercase());
                if result.len() > 2 {
                    return Err(Error::Invalid("unexpected third package link"));
                }
                buffer.fill(0);
                length = buffer.len() as u32;
                if unsafe { FindNextFileNameW(search.0, &mut length, buffer.as_mut_ptr()) } == 0 {
                    if unsafe { GetLastError() } != ERROR_HANDLE_EOF {
                        return Err(last("FindNextFileNameW"));
                    }
                    result.sort();
                    return Ok(result);
                }
            }
        }
        impl Pin {
            fn open(path: &Path) -> Result<Self> {
                Self::open_inner(path, None)
            }
            fn open_driver(path: &Path, allowed: [String; 2]) -> Result<Self> {
                let reported = hardlink_names(path)?;
                package_link_set(
                    path.to_str().ok_or(Error::Invalid("driver link path"))?,
                    &allowed,
                    &reported,
                    reported.len() as u32,
                )?;
                let pin = Self::open_inner(path, Some((allowed, reported)))?;
                pin.verify_links()?;
                Ok(pin)
            }
            fn open_inner(
                path: &Path,
                driver_links: Option<([String; 2], Vec<String>)>,
            ) -> Result<Self> {
                clean_absolute(path)?;
                let mut ancestors = path.ancestors().skip(1).collect::<Vec<_>>();
                ancestors.reverse();
                let mut parents = vec![];
                for path in ancestors {
                    let file = readonly_open(path, true)?;
                    let observed = stamp(&file, true)?;
                    parents.push((file, path.to_owned(), observed));
                }
                let count = driver_links
                    .as_ref()
                    .map_or(1, |(_, paths)| paths.len() as u32);
                let file = readonly_open_links(path, false, count)?;
                Ok(Self {
                    file,
                    path: path.to_owned(),
                    parents,
                    driver_links,
                })
            }
            fn link_count(&self) -> u32 {
                self.driver_links
                    .as_ref()
                    .map_or(1, |(_, p)| p.len() as u32)
            }
            fn verify_links(&self) -> Result<()> {
                if let Some((allowed, expected)) = &self.driver_links {
                    let reported = hardlink_names(&self.path)?;
                    package_link_set(
                        self.path.to_str().ok_or(Error::Invalid("driver path"))?,
                        allowed,
                        &reported,
                        self.link_count(),
                    )?;
                    if &reported != expected {
                        return Err(Error::Changed);
                    }
                }
                Ok(())
            }
            fn observe(&self) -> Result<Observed> {
                self.verify_links()?;
                for (file, path, expected) in &self.parents {
                    // Directory size/mtime changes from unrelated OS activity are not
                    // identity replacement. Reparse/type/identity remain mandatory.
                    let held = stamp(file, true)?;
                    let reopened = readonly_open(path, true)?;
                    let now = stamp(&reopened, true)?;
                    if held.volume != expected.volume
                        || held.id != expected.id
                        || now.volume != expected.volume
                        || now.id != expected.id
                    {
                        return Err(Error::Changed);
                    }
                }
                let current = readonly_open_links(&self.path, false, self.link_count())?;
                if stamp_links(&current, false, self.link_count())?
                    != stamp_links(&self.file, false, self.link_count())?
                {
                    return Err(Error::Changed);
                }
                let observed = observe_links(&self.file, self.link_count())?;
                self.verify_links()?;
                Ok(observed)
            }
        }
        fn observe(file: &File) -> Result<Observed> {
            observe_links(file, 1)
        }
        fn observe_links(file: &File, links: u32) -> Result<Observed> {
            let before = stamp_links(file, false, links)?;
            let length = usize::try_from(before.size).map_err(|_| Error::Invalid("file size"))?;
            if length == 0 || length > MAX_SOURCE {
                return Err(Error::Invalid("file bound"));
            }
            let mut bytes = vec![0; length];
            let mut offset = 0;
            while offset < length {
                let count = file
                    .seek_read(&mut bytes[offset..], offset as u64)
                    .map_err(|e| io("read retained file", e))?;
                if count == 0 {
                    return Err(Error::Changed);
                }
                offset += count;
            }
            if stamp_links(file, false, links)? != before {
                return Err(Error::Changed);
            }
            Ok(Observed {
                stamp: before,
                bytes,
            })
        }

        struct InfoSet(HDEVINFO);
        impl InfoSet {
            fn from(handle: HDEVINFO) -> Result<Self> {
                if handle == -1 {
                    Err(last("SetupAPI inventory set"))
                } else {
                    Ok(Self(handle))
                }
            }
        }
        impl Drop for InfoSet {
            fn drop(&mut self) {
                unsafe { SetupDiDestroyDeviceInfoList(self.0) };
            }
        }
        fn candidates(root: &Path) -> Result<Vec<Candidate>> {
            let set = InfoSet::from(unsafe {
                SetupDiCreateDeviceInfoList(&GUID_DEVCLASS_NET, ptr::null_mut())
            })?;
            // This changes only query-list configuration in our private, in-memory
            // HDEVINFO. No synthetic device/property setters or global enumeration writes.
            let mut params = SP_DEVINSTALL_PARAMS_W {
                cbSize: size_of::<SP_DEVINSTALL_PARAMS_W>() as u32,
                ..Default::default()
            };
            if unsafe { SetupDiGetDeviceInstallParamsW(set.0, ptr::null(), &mut params) } == 0 {
                return Err(last("SetupDiGetDeviceInstallParamsW"));
            }
            let inf_dir = root.join("Inf");
            let driver_path = wide(inf_dir.to_str().ok_or(Error::Invalid("INF root"))?)?;
            if driver_path.len() > params.DriverPath.len() {
                return Err(Error::Invalid("INF root bound"));
            }
            params.DriverPath.fill(0);
            params.DriverPath[..driver_path.len()].copy_from_slice(&driver_path);
            params.FlagsEx |= DI_FLAGSEX_ALLOWEXCLUDEDDRVS;
            if unsafe { SetupDiSetDeviceInstallParamsW(set.0, ptr::null(), &params) } == 0 {
                return Err(last("SetupDiSetDeviceInstallParamsW query config"));
            }
            if unsafe { SetupDiBuildDriverInfoList(set.0, ptr::null_mut(), SPDIT_CLASSDRIVER) } == 0
            {
                return Err(last("SetupDiBuildDriverInfoList"));
            }
            let mut found = vec![];
            for index in 0..MAX_NODES {
                let mut node = SP_DRVINFO_DATA_V2_W {
                    cbSize: size_of::<SP_DRVINFO_DATA_V2_W>() as u32,
                    ..Default::default()
                };
                if unsafe {
                    SetupDiEnumDriverInfoW(set.0, ptr::null(), SPDIT_CLASSDRIVER, index, &mut node)
                } == 0
                {
                    if unsafe { GetLastError() } == ERROR_NO_MORE_ITEMS {
                        found.sort_by(|a: &Candidate, b| a.published_inf.cmp(&b.published_inf));
                        return Ok(found);
                    }
                    return Err(last("SetupDiEnumDriverInfoW"));
                }
                let mut storage = vec![0u64; BUFFER / 8];
                let detail = storage.as_mut_ptr().cast::<SP_DRVINFO_DETAIL_DATA_W>();
                unsafe { (*detail).cbSize = size_of::<SP_DRVINFO_DETAIL_DATA_W>() as u32 };
                let mut required = 0;
                if unsafe {
                    SetupDiGetDriverInfoDetailW(
                        set.0,
                        ptr::null(),
                        &node,
                        detail,
                        BUFFER as u32,
                        &mut required,
                    )
                } == 0
                {
                    return Err(last("SetupDiGetDriverInfoDetailW"));
                }
                let id_offset = offset_of!(SP_DRVINFO_DETAIL_DATA_W, HardwareID);
                let word_count = driver_detail_words(required as usize, id_offset, BUFFER)?;
                // Backing allocation is initialized and larger than the FULL SDK
                // struct. Read all static fields but never count its C tail padding
                // as returned ID data or require Windows to include that padding.
                let info = unsafe { ptr::read(detail) };
                if info.cbSize != size_of::<SP_DRVINFO_DETAIL_DATA_W>() as u32 {
                    return Err(Error::Invalid("driver detail cbSize"));
                }
                let words = unsafe {
                    std::slice::from_raw_parts(
                        storage.as_ptr().cast::<u8>().add(id_offset).cast::<u16>(),
                        word_count,
                    )
                };
                let ids = driver_ids(
                    words,
                    info.CompatIDsOffset as usize,
                    info.CompatIDsLength as usize,
                )?;
                if !ids.iter().any(|id| id.eq_ignore_ascii_case("WireGuard")) {
                    continue;
                }
                if found.len() >= 64 {
                    return Err(Error::Invalid("compatible candidates bound"));
                }
                let published = PathBuf::from(wide_z(&info.InfFileName)?);
                clean_absolute(&published)?;
                let filename = published
                    .file_name()
                    .and_then(|s| s.to_str())
                    .ok_or(Error::Invalid("published INF name"))?
                    .to_ascii_lowercase();
                let number = filename
                    .strip_prefix("oem")
                    .and_then(|s| s.strip_suffix(".inf"))
                    .ok_or(Error::Unsupported("published OEM INF"))?;
                if number.is_empty()
                    || !number.bytes().all(|b| b.is_ascii_digit())
                    || !published.parent().is_some_and(|p| same_path(p, &inf_dir))
                {
                    return Err(Error::Invalid("published INF location"));
                }
                let source = wide(published.to_str().ok_or(Error::Invalid("published INF"))?)?;
                let mut buffer = [0u16; 32768];
                let mut needed = 0;
                if unsafe {
                    SetupGetInfDriverStoreLocationW(
                        source.as_ptr(),
                        ptr::null(),
                        ptr::null(),
                        buffer.as_mut_ptr(),
                        buffer.len() as u32,
                        &mut needed,
                    )
                } == 0
                {
                    return Err(last("SetupGetInfDriverStoreLocationW"));
                }
                if needed == 0 || needed as usize > buffer.len() {
                    return Err(Error::Invalid("driverstore location bound"));
                }
                let store = PathBuf::from(wide_z(&buffer[..needed as usize])?);
                clean_absolute(&store)?;
                let directory = store.parent().ok_or(Error::Invalid("driverstore parent"))?;
                let repo = os_directory(true)?
                    .join("DriverStore")
                    .join("FileRepository");
                if !store
                    .file_name()
                    .is_some_and(|s| s.eq_ignore_ascii_case("wireguard.inf"))
                    || !directory.parent().is_some_and(|p| same_path(p, &repo))
                    || !directory
                        .file_name()
                        .and_then(|s| s.to_str())
                        .is_some_and(|s| s.to_ascii_lowercase().starts_with("wireguard.inf_amd64_"))
                {
                    return Err(Error::Unsupported("driverstore platform/location"));
                }
                let path = |p: PathBuf| {
                    p.to_str()
                        .map(str::to_owned)
                        .ok_or(Error::Invalid("native Unicode path"))
                };
                found.push(Candidate {
                    date: ft(node.DriverDate),
                    version: node.DriverVersion,
                    provider: wide_z(&node.ProviderName)?,
                    published_inf: path(published)?,
                    store_inf: path(store.clone())?,
                    store_cat: path(directory.join("wireguard.cat"))?,
                    store_sys: path(directory.join("wireguard.sys"))?,
                });
            }
            Err(Error::Invalid("driver enumeration bound"))
        }
        fn property(
            set: &InfoSet,
            device: &SP_DEVINFO_DATA,
            property: SETUP_DI_REGISTRY_PROPERTY,
            expected_type: u32,
        ) -> Result<Option<Vec<u16>>> {
            let mut bytes = vec![0u8; BUFFER];
            let (mut kind, mut required) = (0, 0);
            if unsafe {
                SetupDiGetDeviceRegistryPropertyW(
                    set.0,
                    device,
                    property,
                    &mut kind,
                    bytes.as_mut_ptr(),
                    bytes.len() as u32,
                    &mut required,
                )
            } == 0
            {
                let error = unsafe { GetLastError() };
                if error == ERROR_INVALID_DATA {
                    return Ok(None);
                }
                return Err(Error::Native("SetupDiGetDeviceRegistryPropertyW", error));
            }
            if kind != expected_type
                || required == 0
                || required as usize > bytes.len()
                || required % 2 != 0
            {
                return Err(Error::Invalid("device property type/bound"));
            }
            Ok(Some(
                bytes[..required as usize]
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect(),
            ))
        }
        fn devices() -> Result<Vec<Device>> {
            // ALLCLASSES without PRESENT: includes legacy ROOT\NET, SWD stubs,
            // phantom/problem instances and unusual class/service bindings.
            let set = InfoSet::from(unsafe {
                SetupDiGetClassDevsW(ptr::null(), ptr::null(), ptr::null_mut(), DIGCF_ALLCLASSES)
            })?;
            let mut found = vec![];
            for index in 0..MAX_NODES {
                let mut device = SP_DEVINFO_DATA {
                    cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
                    ..Default::default()
                };
                if unsafe { SetupDiEnumDeviceInfo(set.0, index, &mut device) } == 0 {
                    if unsafe { GetLastError() } == ERROR_NO_MORE_ITEMS {
                        found.sort_by(|a: &Device, b| a.instance.cmp(&b.instance));
                        return Ok(found);
                    }
                    return Err(last("SetupDiEnumDeviceInfo"));
                }
                let mut name = [0u16; 4096];
                let mut needed = 0;
                if unsafe {
                    SetupDiGetDeviceInstanceIdW(
                        set.0,
                        &device,
                        name.as_mut_ptr(),
                        name.len() as u32,
                        &mut needed,
                    )
                } == 0
                {
                    return Err(last("SetupDiGetDeviceInstanceIdW"));
                }
                if needed == 0 || needed as usize > name.len() {
                    return Err(Error::Invalid("device instance bound"));
                }
                let instance = wide_z(&name[..needed as usize])?;
                let mut ids = vec![];
                for prop in [SPDRP_HARDWAREID, SPDRP_COMPATIBLEIDS] {
                    if let Some(words) = property(&set, &device, prop, REG_MULTI_SZ)? {
                        ids.extend(multi_sz(&words)?);
                    }
                }
                let service = property(&set, &device, SPDRP_SERVICE, REG_SZ)?
                    .map(|s| wide_z(&s))
                    .transpose()?;
                if !related_device(&instance, &ids, service.as_deref()) {
                    continue;
                }
                let (mut status, mut problem) = (0, 0);
                let result =
                    unsafe { CM_Get_DevNode_Status(&mut status, &mut problem, device.DevInst, 0) };
                if result != CR_SUCCESS {
                    return Err(Error::Native("CM_Get_DevNode_Status", result));
                }
                if found.len() >= 4096 {
                    return Err(Error::Invalid("WireGuard device bound"));
                }
                found.push(Device {
                    instance,
                    status,
                    problem,
                });
            }
            Err(Error::Invalid("device enumeration bound"))
        }
        struct ServiceHandle(SC_HANDLE);
        impl Drop for ServiceHandle {
            fn drop(&mut self) {
                unsafe { CloseServiceHandle(self.0) };
            }
        }
        fn service(system_sys: &Path, windows_root: &Path) -> Result<(u32, u32, u32)> {
            observe_service(system_sys, windows_root)?.ok_or(Error::Native(
                "OpenServiceW WireGuard",
                ERROR_SERVICE_DOES_NOT_EXIST,
            ))
        }
        /// Absence is an actual SCM observation. Production still requires
        /// the original service through service() rather than a cold substitute.
        fn observe_service(
            system_sys: &Path,
            windows_root: &Path,
        ) -> Result<Option<(u32, u32, u32)>> {
            let manager = ServiceHandle(unsafe {
                OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT)
            });
            if manager.0.is_null() {
                return Err(last("OpenSCManagerW"));
            }
            let service = ServiceHandle(unsafe {
                OpenServiceW(
                    manager.0,
                    w!("WireGuard"),
                    SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
                )
            });
            if service.0.is_null() {
                let error = unsafe { GetLastError() };
                return if error == ERROR_SERVICE_DOES_NOT_EXIST {
                    Ok(None)
                } else {
                    Err(Error::Native("OpenServiceW WireGuard", error))
                };
            }
            let mut storage = service_query_buffer();
            let capacity = std::mem::size_of_val(storage.as_slice());
            let config = storage.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
            let mut needed = 0;
            if unsafe { QueryServiceConfigW(service.0, config, capacity as u32, &mut needed) } == 0
            {
                return Err(last("QueryServiceConfigW"));
            }
            let config = unsafe { ptr::read(config) };
            let base = storage.as_ptr() as usize;
            let address = config.lpBinaryPathName as usize;
            if address < base || address >= base + capacity || address % 2 != 0 {
                return Err(Error::Invalid("service binary pointer"));
            }
            let words = unsafe {
                std::slice::from_raw_parts(config.lpBinaryPathName, (base + capacity - address) / 2)
            };
            let binary = wide_z(words)?;
            let binary = binary
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(&binary);
            let path = if binary
                .get(..12)
                .is_some_and(|s| s.eq_ignore_ascii_case("\\SystemRoot\\"))
            {
                windows_root.join(&binary[12..])
            } else {
                PathBuf::from(binary)
            };
            clean_absolute(&path)?;
            if !same_path(&path, system_sys) {
                return Err(Error::Changed);
            }
            let mut status = SERVICE_STATUS_PROCESS::default();
            if unsafe {
                QueryServiceStatusEx(
                    service.0,
                    SC_STATUS_PROCESS_INFO,
                    (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
                    size_of::<SERVICE_STATUS_PROCESS>() as u32,
                    &mut needed,
                )
            } == 0
            {
                return Err(last("QueryServiceStatusEx"));
            }
            if status.dwServiceType != config.dwServiceType {
                return Err(Error::Changed);
            }
            Ok(Some((
                config.dwServiceType,
                config.dwStartType,
                status.dwCurrentState,
            )))
        }

        struct CatalogContext(isize);
        impl Drop for CatalogContext {
            fn drop(&mut self) {
                unsafe { CryptCATAdminReleaseContext(self.0, 0) };
            }
        }
        fn wintrust(data: &mut WINTRUST_DATA) -> Result<()> {
            let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
            data.dwUIChoice = WTD_UI_NONE;
            data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
            data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL
                | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
                | WTD_DISABLE_MD2_MD4;
            data.dwStateAction = WTD_STATEACTION_VERIFY;
            let status = unsafe {
                WinVerifyTrust(
                    ptr::null_mut(),
                    &mut action,
                    (data as *mut WINTRUST_DATA).cast(),
                )
            };
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            let close = unsafe {
                WinVerifyTrust(
                    ptr::null_mut(),
                    &mut action,
                    (data as *mut WINTRUST_DATA).cast(),
                )
            };
            trust_status(status)?;
            trust_status(close)
        }
        fn signed_file(pin: &Pin) -> Result<()> {
            let path = wide(pin.path.to_str().ok_or(Error::Invalid("signature path"))?)?;
            let mut info = WINTRUST_FILE_INFO {
                cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
                pcwszFilePath: path.as_ptr(),
                hFile: pin.file.as_raw_handle(),
                ..Default::default()
            };
            let mut data = WINTRUST_DATA {
                dwUnionChoice: WTD_CHOICE_FILE,
                Anonymous: WINTRUST_DATA_0 { pFile: &mut info },
                ..Default::default()
            };
            wintrust(&mut data)
        }
        fn catalog_member(
            cat: &Pin,
            member: &Pin,
            context: &CatalogContext,
            expected_length: u32,
        ) -> Result<()> {
            let mut digest = [0u8; 64];
            let mut length = digest.len() as u32;
            if unsafe {
                CryptCATAdminCalcHashFromFileHandle2(
                    context.0,
                    member.file.as_raw_handle(),
                    &mut length,
                    digest.as_mut_ptr(),
                    0,
                )
            } == 0
            {
                return Err(last("CryptCATAdminCalcHashFromFileHandle2"));
            }
            if length != expected_length {
                return Err(Error::Unsupported("catalog hash length"));
            }
            let tag = digest[..length as usize]
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<String>();
            let (tag, cat_path, member_path) = (
                wide(&tag)?,
                wide(cat.path.to_str().ok_or(Error::Invalid("catalog path"))?)?,
                wide(member.path.to_str().ok_or(Error::Invalid("member path"))?)?,
            );
            let mut info = WINTRUST_CATALOG_INFO {
                cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
                pcwszCatalogFilePath: cat_path.as_ptr(),
                pcwszMemberTag: tag.as_ptr(),
                pcwszMemberFilePath: member_path.as_ptr(),
                hMemberFile: member.file.as_raw_handle(),
                pbCalculatedFileHash: digest.as_mut_ptr(),
                cbCalculatedFileHash: length,
                hCatAdmin: context.0,
                ..Default::default()
            };
            let mut data = WINTRUST_DATA {
                dwUnionChoice: WTD_CHOICE_CATALOG,
                Anonymous: WINTRUST_DATA_0 {
                    pCatalog: &mut info,
                },
                ..Default::default()
            };
            wintrust(&mut data)
        }

        struct Native {
            source: std::rc::Rc<NativeWireGuardSource>,
        }
        /// External inventory input for the actual native factory fixture.
        /// The audited parser, original source/pins, bytes, catalog membership
        /// and Windows signatures still execute. No driver is installed.
        #[cfg(test)]
        pub(crate) fn prepare_fixture_package(
            source: &Path,
            directory: &Path,
        ) -> Result<([PathBuf; 5], u64)> {
            let bytes = std::fs::read(source).map_err(|e| io("fixture WG source", e))?;
            require_audited_source_digest(&sha2::Sha256::digest(&bytes).into())?;
            let package = extract_package(&bytes)?;
            std::fs::create_dir(directory).map_err(|e| io("fixture WG package directory", e))?;
            let paths = [
                "published.inf",
                "store.inf",
                "wireguard.cat",
                "store.sys",
                "system.sys",
            ]
            .map(|name| directory.join(name));
            for (path, bytes) in paths.iter().zip([
                &package.inf,
                &package.inf,
                &package.cat,
                &package.sys,
                &package.sys,
            ]) {
                std::fs::write(path, bytes).map_err(|e| io("fixture WG package input", e))?;
            }
            Ok((paths, package.date))
        }
        fn pending_maintenance() -> Result<(bool, PendingSnapshot)> {
            let mut handle = ptr::null_mut();
            let status = unsafe {
                RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    w!("SYSTEM\\CurrentControlSet\\Control\\Session Manager"),
                    0,
                    KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                    &mut handle,
                )
            };
            if status != 0 {
                return Err(Error::Native("open pending queue", status));
            }
            struct Key(HKEY);
            impl Drop for Key {
                fn drop(&mut self) {
                    unsafe { RegCloseKey(self.0) };
                }
            }
            let key = Key(handle);
            let mut snapshot = PendingSnapshot::default();
            for (index, name) in [
                w!("PendingFileRenameOperations"),
                w!("PendingFileRenameOperations2"),
            ]
            .into_iter()
            .enumerate()
            {
                let mut bytes = vec![0; BUFFER];
                let (mut kind, mut length) = (0, bytes.len() as u32);
                let status = unsafe {
                    RegQueryValueExW(
                        key.0,
                        name,
                        ptr::null(),
                        &mut kind,
                        bytes.as_mut_ptr(),
                        &mut length,
                    )
                };
                if status == ERROR_FILE_NOT_FOUND {
                    continue;
                }
                if status != 0 {
                    return Err(Error::Native("read pending queue", status));
                }
                if kind != REG_MULTI_SZ || length as usize > bytes.len() || length % 2 != 0 {
                    return Err(Error::Invalid("pending queue type/length"));
                }
                bytes.truncate(length as usize);
                // No WG-native evidence yet for ignoring ANY pending deletion.
                // Keep this deliberately stricter than the independently audited C policy.
                if bytes != [0, 0, 0, 0] {
                    return Err(Error::MaintenanceRequired);
                }
                snapshot.queues[index] = Some(bytes);
            }
            Ok((false, snapshot))
        }
        impl Kernel for Native {
            type Pin = Pin;
            fn source(&mut self) -> Result<Observed> {
                let source = observe(self.source.file()?)?;
                require_audited_source_digest(&sha2::Sha256::digest(&source.bytes).into())?;
                Ok(source)
            }
            fn inventory(&mut self) -> Result<Inventory> {
                let native_amd64_win10_plus = native_platform()?;
                if !native_amd64_win10_plus {
                    return Err(Error::Unsupported("native platform"));
                }
                let root = os_directory(false)?;
                let system_root = os_directory(true)?;
                let system = system_root.join("drivers").join("wireguard.sys");
                #[cfg(test)]
                if let Some((paths, date)) =
                    crate::windows::wireguard_package_paths(&final_path(self.source.file()?)?)
                {
                    let [published_inf, store_inf, store_cat, store_sys, system_sys] =
                        paths.map(|path| path.to_string_lossy().into_owned());
                    let devices = devices()?;
                    // The fixture stages package files. ONLY actual SCM
                    // absence preserves its staged cold tuple; real service
                    // type/start/state/path and the complete census stay real.
                    let (service_type, service_start, service_state) =
                        observe_service(&system, &root)?.unwrap_or((1, 3, 1));
                    return Ok(Inventory {
                        native_amd64_win10_plus,
                        candidates: vec![Candidate {
                            date,
                            version: 0x0001_0001_0000_0000,
                            provider: "WireGuard LLC".into(),
                            published_inf,
                            store_inf,
                            store_cat,
                            store_sys,
                        }],
                        devices,
                        service_type,
                        service_start,
                        service_state,
                        pending_maintenance: false,
                        pending: PendingSnapshot::default(),
                        system_sys,
                    });
                }
                let candidates = candidates(&root)?;
                let devices = devices()?;
                let (service_type, service_start, service_state) = service(&system, &root)?;
                let (pending_maintenance, pending) = pending_maintenance()?;
                Ok(Inventory {
                    native_amd64_win10_plus,
                    candidates,
                    devices,
                    service_type,
                    service_start,
                    service_state,
                    pending_maintenance,
                    pending,
                    system_sys: system
                        .to_str()
                        .ok_or(Error::Invalid("system path"))?
                        .to_owned(),
                })
            }
            fn open(&mut self, path: &str) -> Result<Pin> {
                Pin::open(Path::new(path))
            }
            fn open_driver_pair(&mut self, paths: [&str; 2]) -> Result<[Pin; 2]> {
                let allowed = paths.map(str::to_owned);
                let pins = [
                    Pin::open_driver(Path::new(paths[0]), allowed.clone())?,
                    Pin::open_driver(Path::new(paths[1]), allowed)?,
                ];
                if pins.iter().any(|p| p.link_count() == 2) {
                    let a = stamp_links(&pins[0].file, false, pins[0].link_count())?;
                    let b = stamp_links(&pins[1].file, false, pins[1].link_count())?;
                    if pins[0].link_count() != 2
                        || pins[1].link_count() != 2
                        || a.volume != b.volume
                        || a.id != b.id
                    {
                        return Err(Error::Changed);
                    }
                }
                Ok(pins)
            }
            fn read(&mut self, pin: &Pin) -> Result<Observed> {
                pin.observe()
            }
            fn signatures(&mut self, pins: &[Pin; 5]) -> Result<()> {
                // Direct embedded Authenticode + signed catalog and actual membership,
                // never GetAuthenticodeSignature text/JSON or a caller success flag.
                signed_file(&pins[2])?;
                signed_file(&pins[4])?;
                // Closed SHA256 catalog membership. No SHA1 fallback or signature-version surrogate.
                let algorithm = wide("SHA256")?;
                let expected_length = 32;
                let mut raw = 0;
                if unsafe {
                    CryptCATAdminAcquireContext2(
                        &mut raw,
                        ptr::null(),
                        algorithm.as_ptr(),
                        ptr::null(),
                        0,
                    )
                } == 0
                {
                    return Err(last("CryptCATAdminAcquireContext2"));
                }
                let context = CatalogContext(raw);
                for index in [0, 1, 3, 4] {
                    catalog_member(&pins[2], &pins[index], &context, expected_length)?;
                }
                Ok(())
            }
        }

        /// Original signed Source and installed DATA pins only; no module/driver
        /// lease, service execution, device creation, or package maintenance permission.
        pub(crate) struct CheckedOriginalWireGuardPackage {
            checked: Checked<Native>,
        }
        impl CheckedOriginalWireGuardPackage {
            pub(crate) fn matches_original(
                &self,
                source: &std::rc::Rc<crate::windows::member_owner::MemberSource>,
                carrier: &std::rc::Rc<crate::windows::member_owner::WintunSource>,
            ) -> bool {
                self.checked.kernel.source.matches_original(source, carrier)
            }
            pub(crate) fn reattest_cold(&mut self) -> Result<()> {
                if !self.checked.valid {
                    return Err(Error::Changed);
                }
                self.checked.valid = false; // Retain all pins across source Err/unwind.
                self.checked.kernel.source.verify()?;
                self.checked.refresh()?;
                self.checked.kernel.source.verify()?;
                self.checked.valid = true;
                Ok(())
            }
        }
        pub(crate) fn from_original_source(
            source: &std::rc::Rc<NativeWireGuardSource>,
        ) -> Result<CheckedOriginalWireGuardPackage> {
            source.verify()?;
            let checked = check(Native {
                source: source.clone(),
            })?;
            source.verify()?;
            Ok(CheckedOriginalWireGuardPackage { checked })
        }
    }

    const MAX_SOURCE: usize = 32 * 1024 * 1024;
    const MAX_RESOURCE: usize = 16 * 1024 * 1024;
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct Package {
        pub(super) inf: Vec<u8>,
        pub(super) cat: Vec<u8>,
        pub(super) sys: Vec<u8>,
        pub(super) date: u64,
    }
    fn slice(bytes: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
        bytes
            .get(offset..offset.checked_add(size).ok_or(Error::Invalid("overflow"))?)
            .ok_or(Error::Invalid("truncated binary"))
    }
    fn u16_at(bytes: &[u8], p: usize) -> Result<u16> {
        Ok(u16::from_le_bytes(
            slice(bytes, p, 2)?
                .try_into()
                .map_err(|_| Error::Invalid("u16"))?,
        ))
    }
    fn u32_at(bytes: &[u8], p: usize) -> Result<u32> {
        Ok(u32::from_le_bytes(
            slice(bytes, p, 4)?
                .try_into()
                .map_err(|_| Error::Invalid("u32"))?,
        ))
    }
    fn pe_header(bytes: &[u8]) -> Result<usize> {
        if bytes.len() > MAX_SOURCE || slice(bytes, 0, 2)? != b"MZ" {
            return Err(Error::Invalid("PE bound/magic"));
        }
        let p = u32_at(bytes, 0x3c)? as usize;
        if slice(bytes, p, 4)? != b"PE\0\0"
            || u16_at(bytes, p + 4)? != 0x8664
            || u16_at(bytes, p + 24)? != 0x20b
            || u16_at(bytes, p + 20)? != 240
        {
            return Err(Error::Unsupported("native AMD64 PE32+ required"));
        }
        slice(bytes, p + 24, 240)?;
        Ok(p)
    }
    struct Pe<'a> {
        pub(super) bytes: &'a [u8],
        pub(super) sections: Vec<(u32, u32, usize)>,
    }
    impl<'a> Pe<'a> {
        fn new(bytes: &'a [u8], p: usize) -> Result<Self> {
            let count = u16_at(bytes, p + 6)? as usize;
            if count == 0 || count > 96 {
                return Err(Error::Invalid("PE sections"));
            }
            let mut sections = vec![];
            for i in 0..count {
                let s = p + 24 + 240 + i * 40;
                slice(bytes, s, 40)?;
                let rva = u32_at(bytes, s + 12)?;
                let size = u32_at(bytes, s + 16)?;
                let raw = u32_at(bytes, s + 20)? as usize;
                slice(bytes, raw, size as usize)?;
                let end = rva
                    .checked_add(size)
                    .ok_or(Error::Invalid("PE RVA overflow"))?;
                for &(other, other_end, _) in &sections {
                    if rva < other_end && other < end {
                        return Err(Error::Invalid("overlapping PE sections"));
                    }
                }
                sections.push((rva, end, raw));
            }
            Ok(Self { bytes, sections })
        }
        fn rva(&self, rva: u32, len: usize) -> Result<&'a [u8]> {
            let end = u64::from(rva) + len as u64;
            for &(start, limit, raw) in &self.sections {
                if rva >= start && end <= u64::from(limit) {
                    return slice(self.bytes, raw + (rva - start) as usize, len);
                }
            }
            Err(Error::Invalid("unmapped PE RVA"))
        }
    }
    fn directory(bytes: &[u8], offset: usize) -> Result<Vec<(u32, u32)>> {
        slice(bytes, offset, 16)?;
        let names = u16_at(bytes, offset + 12)? as usize;
        let ids = u16_at(bytes, offset + 14)? as usize;
        if names + ids == 0 || names + ids > 128 {
            return Err(Error::Invalid("resource directory bound"));
        }
        let mut rows = vec![];
        for i in 0..names + ids {
            let key = u32_at(bytes, offset + 16 + i * 8)?;
            if (key >> 31 != 0) != (i < names) || rows.iter().any(|(k, _)| *k == key) {
                return Err(Error::Invalid("resource key"));
            }
            rows.push((key, u32_at(bytes, offset + 20 + i * 8)?));
        }
        Ok(rows)
    }
    pub(super) fn extract_package(bytes: &[u8]) -> Result<Package> {
        let p = pe_header(bytes)?;
        let pe = Pe::new(bytes, p)?;
        if u32_at(bytes, p + 24 + 108)? != 16 {
            return Err(Error::Unsupported("PE directories"));
        }
        let rva = u32_at(bytes, p + 24 + 112 + 16)?;
        let size = u32_at(bytes, p + 24 + 112 + 20)? as usize;
        if size == 0 || size > MAX_RESOURCE {
            return Err(Error::Invalid("resource bound"));
        }
        let r = pe.rva(rva, size)?;
        let (_, type_dir) = directory(r, 0)?
            .into_iter()
            .find(|(key, _)| *key == 10)
            .ok_or(Error::Invalid("no RCDATA"))?;
        if type_dir >> 31 != 1 {
            return Err(Error::Invalid("RCDATA directory"));
        }
        let mut found = std::collections::BTreeMap::new();
        for (key, lang_dir) in directory(r, (type_dir & 0x7fffffff) as usize)? {
            if key >> 31 != 1 || lang_dir >> 31 != 1 {
                return Err(Error::Unsupported("named resources required"));
            }
            let off = (key & 0x7fffffff) as usize;
            let len = u16_at(r, off)? as usize;
            if len == 0 || len > 64 {
                return Err(Error::Invalid("resource name"));
            }
            let name = String::from_utf16(
                &slice(r, off + 2, len * 2)?
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect::<Vec<_>>(),
            )
            .map_err(|_| Error::Invalid("resource UTF16"))?
            .to_ascii_lowercase();
            if ![
                "wireguard.inf",
                "wireguard.cat",
                "wireguard.sys",
                "wireguard-arm64.inf",
                "wireguard-arm64.cat",
                "wireguard-arm64.sys",
                "setupapihost-arm64.dll",
            ]
            .contains(&name.as_str())
            {
                return Err(Error::Unsupported("unknown RCDATA"));
            }
            let langs = directory(r, (lang_dir & 0x7fffffff) as usize)?;
            if langs.len() != 1 || ![0, 1033].contains(&langs[0].0) || langs[0].1 >> 31 != 0 {
                return Err(Error::Unsupported("resource language"));
            }
            let ent = langs[0].1 as usize;
            let data_rva = u32_at(r, ent)?;
            let data_len = u32_at(r, ent + 4)? as usize;
            if data_len == 0
                || data_len > MAX_RESOURCE
                || u32_at(r, ent + 12)? != 0
                || ![0, 1200].contains(&u32_at(r, ent + 8)?)
            {
                return Err(Error::Invalid("resource data entry"));
            }
            // Require data inside this same resource range, not an arbitrary executable section.
            let relative = data_rva
                .checked_sub(rva)
                .ok_or(Error::Invalid("resource data RVA"))? as usize;
            let data = slice(r, relative, data_len)?.to_vec();
            if found.insert(name, data).is_some() {
                return Err(Error::Invalid("duplicate resource name"));
            }
        }
        let extras = [
            "wireguard-arm64.inf",
            "wireguard-arm64.cat",
            "wireguard-arm64.sys",
            "setupapihost-arm64.dll",
        ]
        .iter()
        .filter(|n| found.contains_key(**n))
        .count();
        if extras != 0 && extras != 4 {
            return Err(Error::Invalid("partial ARM64 resource group"));
        }
        // Pinned amd64 sources may contain an unused ARM64 helper group. Native
        // machine/process checks below prohibit taking that DriverInstall branch.
        let mut take = |n| found.remove(n).ok_or(Error::Invalid("missing resource"));
        let package = Package {
            inf: take("wireguard.inf")?,
            cat: take("wireguard.cat")?,
            sys: take("wireguard.sys")?,
            date: 0,
        };
        let date = parse_inf(&package.inf)?;
        let package = Package { date, ..package };
        pe_header(&package.sys)?;
        Ok(package)
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct Stamp {
        pub(super) volume: u32,
        pub(super) id: u64,
        pub(super) size: u64,
        pub(super) modified: u64,
    }
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct Observed {
        pub(super) stamp: Stamp,
        pub(super) bytes: Vec<u8>,
    }
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct Candidate {
        pub(super) date: u64,
        pub(super) version: u64,
        pub(super) provider: String,
        pub(super) published_inf: String,
        pub(super) store_inf: String,
        pub(super) store_cat: String,
        pub(super) store_sys: String,
    }
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct Device {
        pub(super) instance: String,
        pub(super) status: u32,
        pub(super) problem: u32,
    }
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct Inventory {
        pub(super) native_amd64_win10_plus: bool,
        pub(super) candidates: Vec<Candidate>,
        // Includes ALL relevant instances, not just DIGCF_PRESENT.
        pub(super) devices: Vec<Device>,
        pub(super) service_type: u32,
        pub(super) service_start: u32,
        pub(super) service_state: u32,
        pub(super) pending_maintenance: bool,
        pub(super) pending: PendingSnapshot,
        pub(super) system_sys: String,
    }
    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub(super) struct PendingSnapshot {
        pub(super) queues: [Option<Vec<u8>>; 2],
        pub(super) files: Vec<(String, Stamp)>,
    }

    // Private native boundary. No successful defaults, metadata-to-authority constructors,
    // filesystem fallback, or deserializable proof. Tests replace only this boundary.
    pub(super) trait Kernel {
        type Pin;
        fn source(&mut self) -> Result<Observed>;
        fn inventory(&mut self) -> Result<Inventory>;
        fn open(&mut self, path: &str) -> Result<Self::Pin>;
        fn open_driver_pair(&mut self, paths: [&str; 2]) -> Result<[Self::Pin; 2]>;
        fn read(&mut self, pin: &Self::Pin) -> Result<Observed>;
        fn signatures(&mut self, pins: &[Self::Pin; 5]) -> Result<()>;
    }
    pub(super) struct Checked<K: Kernel> {
        pub(super) kernel: K,
        pub(super) source: Observed,
        pub(super) inventory: Inventory,
        pub(super) files: [Observed; 5],
        pub(super) pins: [K::Pin; 5],
        pub(super) valid: bool,
    }

    fn wide_z(words: &[u16]) -> Result<String> {
        if words.len() > 32768 {
            return Err(Error::Invalid("UTF16 bound"));
        }
        let end = words
            .iter()
            .position(|w| *w == 0)
            .ok_or(Error::Invalid("unterminated UTF16"))?;
        String::from_utf16(&words[..end]).map_err(|_| Error::Invalid("invalid UTF16"))
    }
    fn multi_sz(words: &[u16]) -> Result<Vec<String>> {
        if words.len() < 2 || words.len() > 32768 || !words.ends_with(&[0, 0]) {
            return Err(Error::Invalid("MULTI_SZ termination/bound"));
        }
        if words == [0, 0] {
            return Ok(vec![]);
        }
        let mut result = vec![];
        let mut pos = 0;
        while pos < words.len() - 1 {
            let end = words[pos..]
                .iter()
                .position(|w| *w == 0)
                .ok_or(Error::Invalid("MULTI_SZ item"))?;
            if end == 0 {
                return Err(Error::Invalid("empty MULTI_SZ item/trailing data"));
            }
            result.push(wide_z(&words[pos..pos + end + 1])?);
            pos += end + 1;
        }
        if pos != words.len() - 1 {
            return Err(Error::Invalid("MULTI_SZ length"));
        }
        Ok(result)
    }
    fn package_link_set(
        path: &str,
        allowed: &[String; 2],
        reported: &[String],
        count: u32,
    ) -> Result<()> {
        if !matches!(count, 1 | 2)
            || count as usize != reported.len()
            || allowed[0].eq_ignore_ascii_case(&allowed[1])
            || !allowed.iter().any(|p| p.eq_ignore_ascii_case(path))
        {
            return Err(Error::Invalid("package link count/scope"));
        }
        let mut actual = reported
            .iter()
            .map(|p| p.to_ascii_lowercase())
            .collect::<Vec<_>>();
        actual.sort();
        let mut expected = if count == 1 {
            vec![path.to_ascii_lowercase()]
        } else {
            allowed.iter().map(|p| p.to_ascii_lowercase()).collect()
        };
        expected.sort();
        if actual != expected {
            return Err(Error::Invalid("foreign/missing/duplicate package link"));
        }
        Ok(())
    }
    fn driver_detail_words(required: usize, id_offset: usize, capacity: usize) -> Result<usize> {
        // RequiredSize ends at the variable HardwareID buffer, not C tail padding.
        // Actual Win32 empty-ID replies are offsetof(HardwareID)+one WCHAR NUL.
        // cbSize supplied TO SetupAPI remains the FULL sizeof SDK structure.
        let tail = required
            .checked_sub(id_offset)
            .ok_or(Error::Invalid("driver detail prefix"))?;
        if required > capacity || tail < 2 || tail % 2 != 0 {
            return Err(Error::Invalid("driver detail bound"));
        }
        Ok(tail / 2)
    }
    fn service_query_buffer() -> Vec<u64> {
        // QueryServiceConfigW's RPC contract caps this array at8192 bytes; the
        // 64KiB SetupAPI/registry buffer is NOT legal for this different API.
        vec![0; 8 * 1024 / std::mem::size_of::<u64>()]
    }
    fn driver_ids(words: &[u16], offset: usize, length: usize) -> Result<Vec<String>> {
        if words.len() > 32768 || offset > words.len() {
            return Err(Error::Invalid("driver IDs bound"));
        }
        let mut ids = vec![];
        if offset > 1 {
            let primary = words
                .get(..offset)
                .ok_or(Error::Invalid("primary ID bound"))?;
            if primary.last() != Some(&0) || primary[..primary.len() - 1].contains(&0) {
                return Err(Error::Invalid("primary ID termination"));
            }
            ids.push(wide_z(primary)?);
        } else if words.first() != Some(&0) {
            return Err(Error::Invalid("missing primary ID sentinel"));
        }
        if length > 0 {
            let end = offset
                .checked_add(length)
                .ok_or(Error::Invalid("compatible ID overflow"))?;
            ids.extend(multi_sz(
                words
                    .get(offset..end)
                    .ok_or(Error::Invalid("compatible ID bound"))?,
            )?);
        }
        Ok(ids)
    }
    fn related_device(instance: &str, ids: &[String], service: Option<&str>) -> bool {
        let upper = instance.to_ascii_uppercase();
        upper == "SWD\\WIREGUARD"
            || upper.starts_with("SWD\\WIREGUARD\\")
            || upper == "ROOT\\WIREGUARD"
            || upper.starts_with("ROOT\\WIREGUARD\\")
            || ids.iter().any(|s| s.eq_ignore_ascii_case("WireGuard"))
            || service.is_some_and(|s| s.eq_ignore_ascii_case("WireGuard"))
    }
    fn trust_status(code: i32) -> Result<()> {
        if code == 0 {
            Ok(())
        } else {
            Err(Error::Native("WinVerifyTrust", code as u32))
        }
    }

    fn validate_inventory(i: &Inventory, date: u64) -> Result<&Candidate> {
        if !i.native_amd64_win10_plus {
            return Err(Error::Unsupported("native AMD64 Win10"));
        }
        if !i.devices.is_empty()
            || i.candidates.len() != 1
            || i.service_type != 1
            || i.service_start != 3
            || i.service_state != 1
            || i.pending_maintenance
        {
            return Err(Error::MaintenanceRequired);
        }
        let c = &i.candidates[0];
        if c.date != date || c.version != 0x0001_0001_0000_0000 || c.provider != "WireGuard LLC" {
            return Err(Error::MaintenanceRequired);
        }
        Ok(c)
    }
    pub(super) fn check<K: Kernel>(mut kernel: K) -> Result<Checked<K>> {
        let source = kernel.source()?;
        let package = extract_package(&source.bytes)?;
        let inventory = kernel.inventory()?;
        let c = validate_inventory(&inventory, package.date)?;
        let [published, inf, cat] = [
            kernel.open(&c.published_inf)?,
            kernel.open(&c.store_inf)?,
            kernel.open(&c.store_cat)?,
        ];
        let [store_sys, system_sys] =
            kernel.open_driver_pair([&c.store_sys, &inventory.system_sys])?;
        let pins = [published, inf, cat, store_sys, system_sys];
        let files = [
            kernel.read(&pins[0])?,
            kernel.read(&pins[1])?,
            kernel.read(&pins[2])?,
            kernel.read(&pins[3])?,
            kernel.read(&pins[4])?,
        ];
        for (file, expected) in files.iter().zip([
            &package.inf,
            &package.inf,
            &package.cat,
            &package.sys,
            &package.sys,
        ]) {
            if file.bytes != *expected || file.stamp.size != file.bytes.len() as u64 {
                return Err(Error::Changed);
            }
        }
        kernel.signatures(&pins)?;
        let mut checked = Checked {
            kernel,
            source,
            inventory,
            files,
            pins,
            valid: true,
        };
        checked.reattest()?;
        Ok(checked)
    }
    impl<K: Kernel> Checked<K> {
        pub(super) fn reattest(&mut self) -> Result<()> {
            if !self.valid {
                return Err(Error::Changed);
            }
            self.valid = false;
            self.refresh()?;
            self.valid = true;
            Ok(())
        }
        fn refresh(&mut self) -> Result<()> {
            // Fresh failures invalidate the caller's observation; no cached success.
            if self.kernel.source()? != self.source || self.kernel.inventory()? != self.inventory {
                return Err(Error::Changed);
            }
            for (pin, expected) in self.pins.iter().zip(&self.files) {
                if self.kernel.read(pin)? != *expected {
                    return Err(Error::Changed);
                }
            }
            self.kernel.signatures(&self.pins)?;
            for (pin, expected) in self.pins.iter().zip(&self.files) {
                if self.kernel.read(pin)? != *expected {
                    return Err(Error::Changed);
                }
            }
            if self.kernel.inventory()? != self.inventory || self.kernel.source()? != self.source {
                return Err(Error::Changed);
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum Error {
        Invalid(&'static str),
        Unsupported(&'static str),
        Native(&'static str, u32),
        Changed,
        MaintenanceRequired,
    }
    pub(crate) type Result<T> = std::result::Result<T, Error>;
    const MAX_INF: usize = 64 * 1024;
    const INF_SCHEMA: &[(&str, &[&str])] = &[
        (
            "version",
            &[
                "signature=\"$Windows NT$\"",
                "class=net",
                "classguid={4d36e972-e325-11ce-bfc1-08002be10318}",
                "provider=%wireguard.companyname%",
                "catalogfile.nt=wireguard.cat",
                "pnplockdown=1",
            ],
        ),
        (
            "manufacturer",
            &["%wireguard.companyname%=%wireguard.name%,ntamd64"],
        ),
        ("sourcedisksnames", &["1=%wireguard.diskdesc%,\"\",,"]),
        ("sourcedisksfiles", &["wireguard.sys=1"]),
        (
            "destinationdirs",
            &["defaultdestdir=12", "wireguard.copyfiles.sys=12"],
        ),
        ("wireguard.copyfiles.sys", &["wireguard.sys,,,0x00004002"]),
        (
            "wireguard.ntamd64",
            &["%wireguard.devicedesc%=wireguard.install,wireguard"],
        ),
        (
            "wireguard.install",
            &[
                "characteristics=0x1",
                "addreg=wireguard.ndi",
                "addproperty=wireguard.properties",
                "copyfiles=wireguard.copyfiles.sys",
                "*iftype=53",
                "*mediatype=19",
                "*physicalmediatype=0",
                "enabledhcp=0",
            ],
        ),
        (
            "wireguard.properties",
            &[
                "deviceicon,,,,\"%12%\\wireguard.sys,-7\"",
                "devicebrandingicon,,,,\"%12%\\wireguard.sys,-7\"",
                "devicevendorwebsite,,,,\"https://www.wireguard.com/\"",
            ],
        ),
        (
            "wireguard.install.services",
            &["addservice=wireguard,2,wireguard.service,wireguard.eventlog"],
        ),
        (
            "wireguard.ndi",
            &[
                "hkr,ndi,service,0,wireguard",
                "hkr,ndi\\interfaces,upperrange,,\"ndis5\"",
                "hkr,ndi\\interfaces,lowerrange,,\"nolower\"",
            ],
        ),
        (
            "wireguard.service",
            &[
                "displayname=%wireguard.name%",
                "description=%wireguard.devicedesc%",
                "servicetype=1",
                "starttype=3",
                "errorcontrol=1",
                "servicebinary=%12%\\wireguard.sys",
            ],
        ),
        (
            "wireguard.eventlog",
            &[
                "hkr,,eventmessagefile,0x00020000,\"%11%\\IoLogMsg.dll;%12%\\wireguard.sys\"",
                "hkr,,typessupported,0x00010001,7",
            ],
        ),
        (
            "strings",
            &[
                "wireguard.name=\"WireGuard\"",
                "wireguard.diskdesc=\"WireGuard Driver Install Disk\"",
                "wireguard.devicedesc=\"WireGuard Tunnel\"",
                "wireguard.companyname=\"WireGuard LLC\"",
            ],
        ),
    ];
    pub(super) fn parse_inf(bytes: &[u8]) -> Result<u64> {
        if bytes.is_empty() || bytes.len() > MAX_INF {
            return Err(Error::Invalid("INF bound"));
        }
        let text = if bytes.starts_with(&[0xff, 0xfe]) {
            if bytes.len() % 2 != 0 {
                return Err(Error::Invalid("UTF16 INF length"));
            }
            String::from_utf16(
                &bytes[2..]
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect::<Vec<_>>(),
            )
            .map_err(|_| Error::Invalid("UTF16 INF"))?
        } else {
            std::str::from_utf8(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes))
                .map_err(|_| Error::Invalid("UTF8 INF"))?
                .to_owned()
        };
        if !text.is_ascii() || text.contains('\0') {
            return Err(Error::Invalid("INF characters"));
        }
        let mut sections = std::collections::BTreeMap::<String, Vec<String>>::new();
        let mut current = None;
        for line in text.lines() {
            let mut quoted = false;
            let mut row = String::new();
            for c in line.chars() {
                if c == '"' {
                    quoted = !quoted;
                    row.push(c);
                } else if c == ';' && !quoted {
                    break;
                } else if quoted {
                    row.push(c);
                } else if !c.is_ascii_whitespace() {
                    row.push(c.to_ascii_lowercase());
                }
            }
            if quoted {
                return Err(Error::Invalid("INF quote"));
            }
            if row.is_empty() {
                continue;
            }
            if row.starts_with('[') && row.ends_with(']') {
                let name = row[1..row.len() - 1].to_owned();
                if sections.insert(name.clone(), vec![]).is_some() {
                    return Err(Error::Invalid("duplicate INF section"));
                }
                current = Some(name);
            } else {
                sections
                    .get_mut(
                        current
                            .as_ref()
                            .ok_or(Error::Invalid("INF outside section"))?,
                    )
                    .ok_or(Error::Invalid("INF section"))?
                    .push(row);
            }
        }

        let version = sections
            .get_mut("version")
            .ok_or(Error::Invalid("INF version"))?;
        let stamps = version
            .iter()
            .filter(|line| line.starts_with("driverver="))
            .cloned()
            .collect::<Vec<_>>();
        if stamps.len() != 1 {
            return Err(Error::Invalid("INF driver stamp"));
        }
        let date = stamped_date(&stamps[0])?;
        version.retain(|line| !line.starts_with("driverver="));
        if sections.len() != INF_SCHEMA.len() {
            return Err(Error::Unsupported("INF sections"));
        }
        for (section, expected) in INF_SCHEMA {
            let mut actual = sections
                .remove(*section)
                .ok_or(Error::Unsupported("INF platform/section"))?;
            let mut expected = expected.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
            actual.sort();
            expected.sort();
            if actual != expected {
                return Err(Error::Unsupported("INF directive/version/provider"));
            }
        }
        Ok(date)
    }

    fn stamped_date(stamp: &str) -> Result<u64> {
        let date = stamp
            .strip_prefix("driverver=")
            .and_then(|s| s.strip_suffix(",1.1.0.0"))
            .ok_or(Error::Unsupported("WireGuardNT 1.1 stamped version"))?;
        let b = date.as_bytes();
        if b.len() != 10
            || b[2] != b'/'
            || b[5] != b'/'
            || b.iter()
                .enumerate()
                .any(|(i, c)| ![2, 5].contains(&i) && !c.is_ascii_digit())
        {
            return Err(Error::Invalid("INF date"));
        }
        let number = |s: &str| s.parse::<u64>().map_err(|_| Error::Invalid("INF date"));
        let (month, day, year) = (
            number(&date[..2])?,
            number(&date[3..5])?,
            number(&date[6..])?,
        );
        if !(2000..=2099).contains(&year) || !(1..=12).contains(&month) {
            return Err(Error::Unsupported("INF date range"));
        }
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let months = [
            31,
            28 + u64::from(leap),
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        if day == 0 || day > months[(month - 1) as usize] {
            return Err(Error::Invalid("INF calendar date"));
        }
        // FILETIME midnight, Gregorian calendar from 1601; no local-time/DLL-version substitution.
        let before = |y: u64| 365 * y + y / 4 - y / 100 + y / 400;
        let days = before(year - 1) - before(1600)
            + months[..(month - 1) as usize].iter().sum::<u64>()
            + day
            - 1;
        Ok(days * 864000000000)
    }
}
