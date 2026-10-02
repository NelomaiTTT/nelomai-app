//! Shared TEST-ONLY original member rebind support. No native Windows effects.
//! Receipts/readers come only from the real owner/origin/retention algorithms.

use super::{ClosedOldProcessReceipt, OriginalMemberRead, PendingMemberRead, RetainedMember};
use crate::member_owner::{
    Intent, Journal, MemberIo, MemberOwner, NativeProof, Observation, OriginalMemberFacts,
    OriginalMemberNative, OriginalMemberPin, OriginalMemberPinSource, OriginalMemberRebindIo,
    OriginalRebindAck, OwnerError, Phase, ProcessProof, Record, Result, RetainedMemberOrigin,
    ServiceObservation,
};
use nelomai_client_tunnel::{redundancy::SessionScope, TunnelTransport};
use nelomai_contracts::dispatcher::TunnelSlot;
use sha2::{Digest, Sha256};
use std::{cell::RefCell, path::PathBuf, rc::Rc};

pub(crate) type Member = RetainedMember<FixtureJournal, FixtureIo>;
pub(crate) type Reader = OriginalMemberRead<FixtureJournal, FixtureIo>;
pub(crate) type Pending = PendingMemberRead<FixtureJournal, FixtureIo>;
pub(crate) type RebindReceipt = Rc<ClosedOldProcessReceipt<FixtureJournal, FixtureIo>>;
pub(crate) type RebindOutcome = (Record, RebindReceipt, Reader);

pub(crate) struct StartedOriginal {
    pub member: Member,
    pub running: Record,
    pub reader: Reader,
    pub pending: Pending,
    pub control: Control,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Fault {
    None,
    OldProcessStillActive,
    ReplacementNic,
    ReplacementQueryError,
    ReplacementQueryUnwind,
    LostRunningAck,
    FailRunningSave,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Counts {
    pub service_creates: usize,
    pub service_drops: usize,
    pub process_pins: usize,
    pub process_drops: usize,
    pub stops: usize,
    pub restarts: usize,
    pub deletes: usize,
    pub journal_writes: usize,
    pub config_writes: usize,
}

/// Monitor does not contain owners/handles/ACKs, and cannot mint or import one.
#[derive(Clone)]
pub(crate) struct Control(Rc<RefCell<State>>);
impl Control {
    pub(crate) fn set_fault(&self, fault: Fault) {
        self.0.borrow_mut().fault = fault;
    }
    pub(crate) fn counts(&self) -> Counts {
        self.0.borrow().counts
    }
    pub(crate) fn saved_record(&self) -> Option<Record> {
        self.0.borrow().record.clone()
    }
}

struct State {
    token: Rc<()>,
    slot: TunnelSlot,
    record: Option<Record>,
    digest: Option<[u8; 32]>,
    service: Option<Intent>,
    interface: Option<crate::member_owner::InterfaceProof>,
    processes: Vec<(ProcessProof, u32)>,
    current: usize,
    counts: Counts,
    fault: Fault,
}
impl State {
    fn observation(&self, retained: Option<&NativeProof>) -> Observation {
        let process = self.service.as_ref().and_then(|_| {
            let (proof, code) = self.processes[self.current];
            (code == 259).then_some(proof)
        });
        Observation {
            config_sha256: self.digest,
            service: self.service.as_ref().map(|_| ServiceObservation {
                exact_spec: true,
                process,
            }),
            alternative_service_present: false,
            interface: self.service.as_ref().and(self.interface),
            retained_interfaces: if retained.is_some() && self.service.is_some() {
                self.interface.into_iter().collect()
            } else {
                vec![]
            },
        }
    }
}

/// Simulates only the external atomic journal boundary, not the owner policy.
pub(crate) struct FixtureJournal(Rc<RefCell<State>>);
impl Journal for FixtureJournal {
    fn load(&mut self, slot: TunnelSlot) -> Result<Option<Record>> {
        let state = self.0.borrow();
        if slot != state.slot {
            return Err(OwnerError::Conflict);
        }
        Ok(state.record.clone())
    }
    fn compare_exchange(
        &mut self,
        slot: TunnelSlot,
        expected: Option<&Record>,
        desired: &Record,
    ) -> Result<()> {
        let mut state = self.0.borrow_mut();
        if slot != state.slot || desired.intent.slot != slot || state.record.as_ref() != expected {
            return Err(OwnerError::Conflict);
        }
        let rebound = desired.phase == Phase::Running && state.counts.restarts != 0;
        if rebound && state.fault == Fault::FailRunningSave {
            return Err(OwnerError::Journal);
        }
        state.record = Some(desired.clone());
        state.counts.journal_writes += 1;
        if rebound && state.fault == Fault::LostRunningAck {
            return Err(OwnerError::Journal);
        }
        Ok(())
    }
}

// Opaque non-Clone handles: identity is an original namespace token plus the
// exact pinned object index, never a name, PID or caller JSON lookup.
pub(crate) struct ServiceHandle {
    token: Rc<()>,
    state: Rc<RefCell<State>>,
}
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        self.state.borrow_mut().counts.service_drops += 1;
    }
}
pub(crate) struct ProcessHandle {
    token: Rc<()>,
    state: Rc<RefCell<State>>,
    index: usize,
}
impl Drop for ProcessHandle {
    fn drop(&mut self) {
        self.state.borrow_mut().counts.process_drops += 1;
    }
}

struct Boundary(Rc<RefCell<State>>);
impl Boundary {
    fn verify_service(&self, service: &ServiceHandle) -> Result<()> {
        if !Rc::ptr_eq(&self.0, &service.state)
            || !Rc::ptr_eq(&self.0.borrow().token, &service.token)
            || self.0.borrow().service.is_none()
        {
            return Err(OwnerError::Conflict);
        }
        Ok(())
    }
}
impl OriginalMemberNative for Boundary {
    type Service = ServiceHandle;
    type Process = ProcessHandle;
    fn create(&mut self, intent: &Intent) -> Result<ServiceHandle> {
        let mut state = self.0.borrow_mut();
        if state.service.is_some() || intent.slot != state.slot || state.counts.service_creates != 0
        {
            return Err(OwnerError::Conflict);
        }
        state.service = Some(intent.clone());
        state.counts.service_creates += 1;
        Ok(ServiceHandle {
            token: state.token.clone(),
            state: self.0.clone(),
        })
    }
    fn finish_created(&mut self, service: &ServiceHandle) -> Result<()> {
        self.verify_service(service)
    }
    fn running_pid(&mut self, service: &ServiceHandle) -> Result<u32> {
        self.verify_service(service)?;
        let state = self.0.borrow();
        let (proof, code) = state.processes[state.current];
        Ok(if code == 259 { proof.pid } else { 0 })
    }
    fn pin_process(&mut self, pid: u32) -> Result<ProcessHandle> {
        let mut state = self.0.borrow_mut();
        if state.service.is_none() || state.processes[state.current].0.pid != pid || pid == 0 {
            return Err(OwnerError::Conflict);
        }
        state.counts.process_pins += 1;
        Ok(ProcessHandle {
            token: state.token.clone(),
            state: self.0.clone(),
            index: state.current,
        })
    }
    fn query_process(&mut self, handle: &ProcessHandle) -> Result<(ProcessProof, u32)> {
        let state = self.0.borrow();
        if !Rc::ptr_eq(&self.0, &handle.state) || !Rc::ptr_eq(&state.token, &handle.token) {
            return Err(OwnerError::Conflict);
        }
        if handle.index != 0 {
            if state.fault == Fault::ReplacementQueryUnwind {
                panic!("replacement handle query unwind");
            }
            if state.fault == Fault::ReplacementQueryError {
                return Err(OwnerError::Native);
            }
        }
        state
            .processes
            .get(handle.index)
            .copied()
            .ok_or(OwnerError::Conflict)
    }
    fn observe(
        &mut self,
        service: &ServiceHandle,
        intent: &Intent,
        retained: Option<&NativeProof>,
    ) -> Result<OriginalMemberFacts> {
        self.verify_service(service)?;
        let state = self.0.borrow();
        if state.service.as_ref() != Some(intent) {
            return Err(OwnerError::Conflict);
        }
        let observation = state.observation(retained);
        Ok(OriginalMemberFacts {
            exact_spec: true,
            pid: observation
                .service
                .and_then(|s| s.process)
                .map_or(0, |p| p.pid),
            alternative_service_present: observation.alternative_service_present,
            interface: observation.interface,
            retained_interfaces: observation.retained_interfaces,
        })
    }
    fn observe_cleanup(
        &mut self,
        service: &ServiceHandle,
        intent: &Intent,
        retained: Option<&NativeProof>,
    ) -> Result<Observation> {
        self.verify_service(service)?;
        let state = self.0.borrow();
        if state.service.as_ref() != Some(intent) {
            return Err(OwnerError::Conflict);
        }
        Ok(state.observation(retained))
    }
    fn stop(&mut self, service: &ServiceHandle) -> Result<()> {
        self.verify_service(service)?;
        let mut state = self.0.borrow_mut();
        state.counts.stops += 1;
        if state.fault != Fault::OldProcessStillActive {
            let current = state.current;
            state.processes[current].1 = 0;
        }
        Ok(())
    }
    fn start_existing(&mut self, service: &ServiceHandle) -> Result<()> {
        self.verify_service(service)?;
        let mut state = self.0.borrow_mut();
        let (old, exit_code) = state.processes[state.current];
        if exit_code == 259 {
            return Err(OwnerError::Conflict);
        }
        let replacement = ProcessProof {
            pid: old.pid.checked_add(1).ok_or(OwnerError::Conflict)?,
            creation_time: old
                .creation_time
                .checked_add(1)
                .ok_or(OwnerError::Conflict)?,
        };
        state.processes.push((replacement, 259));
        state.current = state.processes.len() - 1;
        state.counts.restarts += 1;
        if state.fault == Fault::ReplacementNic {
            let interface = state.interface.as_mut().ok_or(OwnerError::Conflict)?;
            interface.index = interface.index.checked_add(1).ok_or(OwnerError::Conflict)?;
        }
        Ok(())
    }
    fn delete(&mut self, service: &ServiceHandle) -> Result<()> {
        self.verify_service(service)?;
        let mut state = self.0.borrow_mut();
        if state.processes[state.current].1 == 259 {
            return Err(OwnerError::Conflict);
        }
        state.counts.deletes += 1;
        state.service = None;
        state.interface = None;
        Ok(())
    }
}

pub(crate) struct FixtureIo {
    original: RetainedMemberOrigin<ServiceHandle, ProcessHandle>,
    boundary: Boundary,
}
impl MemberIo for FixtureIo {
    fn inspect(&mut self, intent: &Intent, retained: Option<&NativeProof>) -> Result<Observation> {
        let state = self.boundary.0.borrow();
        if intent.slot != state.slot
            || state
                .service
                .as_ref()
                .is_some_and(|actual| actual != intent)
        {
            return Err(OwnerError::Conflict);
        }
        Ok(state.observation(retained))
    }
    fn inspect_original(&mut self, intent: &Intent, proof: &NativeProof) -> Result<Observation> {
        let state = self.boundary.0.clone();
        self.original
            .inspect_original(&mut self.boundary, intent, proof, || {
                Ok(state.borrow().digest)
            })
    }
    fn inspect_original_for_cleanup(
        &mut self,
        intent: &Intent,
        proof: &NativeProof,
    ) -> Result<Observation> {
        let state = self.boundary.0.clone();
        self.original
            .inspect_original_for_cleanup(&mut self.boundary, intent, proof, || {
                Ok(state.borrow().digest)
            })
    }
    fn revoke_original(&mut self) {
        self.original.revoke();
    }
    fn write_private_config(
        &mut self,
        intent: &Intent,
        expected: Option<[u8; 32]>,
        canonical: &str,
    ) -> Result<()> {
        let mut state = self.boundary.0.borrow_mut();
        if intent.slot != state.slot
            || state.digest != expected
            || Sha256::digest(canonical.as_bytes())[..] != intent.config_sha256
        {
            return Err(OwnerError::Conflict);
        }
        state.digest = Some(intent.config_sha256);
        state.counts.config_writes += 1;
        Ok(())
    }
    fn start_fresh(&mut self, intent: &Intent, retired: Option<&NativeProof>) -> Result<()> {
        if retired.is_some() {
            return Err(OwnerError::Conflict);
        }
        {
            let mut state = self.boundary.0.borrow_mut();
            if state.digest != Some(intent.config_sha256) {
                return Err(OwnerError::Conflict);
            }
            // This external namespace is absent until the real NEW create path.
            // The supplied initial interface becomes visible with that service.
            state.processes[0].1 = 259;
        }
        self.original.start(&mut self.boundary, intent)
    }
    fn stop_slot(
        &mut self,
        intent: &Intent,
        retained: Option<&NativeProof>,
        expected: &Observation,
    ) -> Result<()> {
        self.original
            .stop_delete(&mut self.boundary, intent, retained, expected)
    }
    fn rebind(&mut self, _: &Intent, _: &NativeProof, _: &Observation) -> Result<()> {
        Err(OwnerError::Retired) // No legacy lookup/rebind shortcut to an ACK.
    }
}
impl OriginalMemberPinSource for FixtureIo {
    type Pin = OriginalMemberPin<ServiceHandle, ProcessHandle>;
    fn original_read_pin(&mut self) -> Result<Self::Pin> {
        self.original.pin()
    }
}
impl OriginalMemberRebindIo for FixtureIo {
    fn rebind_original(
        &mut self,
        intent: &Intent,
        old: &NativeProof,
    ) -> Result<Rc<OriginalRebindAck>> {
        let state = self.boundary.0.clone();
        self.original
            .rebind_original(&mut self.boundary, intent, old, || {
                Ok(state.borrow().digest)
            })
    }
    fn read_rebound_original(&mut self, ack: &Rc<OriginalRebindAck>) -> Result<NativeProof> {
        let state = self.boundary.0.clone();
        self.original
            .read_rebound_original(&mut self.boundary, ack, || Ok(state.borrow().digest))
    }
}

/// Fixed valid test profile, actual fresh owner/SCM-create/process-pin path.
/// The returned running record is authoritative for the fixture's config hash;
/// no supplied Record/config hash can seed original member authority.
pub(crate) fn start_original(
    scope: SessionScope,
    slot: TunnelSlot,
    transport: TunnelTransport,
    engine: PathBuf,
    proof: NativeProof,
) -> Result<StartedOriginal> {
    let state = Rc::new(RefCell::new(State {
        token: Rc::new(()),
        slot,
        record: None,
        digest: None,
        service: None,
        interface: Some(proof.interface),
        processes: vec![(proof.process, 0)],
        current: 0,
        counts: Counts::default(),
        fault: Fault::None,
    }));
    let awg = if transport == TunnelTransport::AmneziaWg3 {
        "HeaderProtectionKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nContentPaddingAddition = 1\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\n"
    } else {
        ""
    };
    let configuration = zeroize::Zeroizing::new(format!(
        "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n{awg}[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n"));
    let mut raw = MemberOwner::from_trusted_engine(
        scope,
        slot,
        transport,
        engine,
        &configuration,
        FixtureJournal(state.clone()),
        FixtureIo {
            original: RetainedMemberOrigin::empty(),
            boundary: Boundary(state.clone()),
        },
    )?;
    raw.prepare_readonly_native_profile()?;
    let mut member = RetainedMember::new(raw);
    let pending = member.pending_read()?;
    let running = member.start_with_prior(None)?;
    let reader = member.original_read()?;
    Ok(StartedOriginal {
        member,
        running,
        reader,
        pending,
        control: Control(state),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::member_owner::{InterfaceProof, NativeProof, ProcessProof};
    use nelomai_client_tunnel::{redundancy::SessionScope, TunnelTransport};
    use nelomai_contracts::{dispatcher::TunnelSlot, RuntimeSlot};

    fn initial() -> NativeProof {
        NativeProof {
            process: ProcessProof {
                pid: 20,
                creation_time: 30,
            },
            interface: InterfaceProof {
                index: 40,
                luid: 50,
                guid: [6; 16],
            },
        }
    }
    fn scope() -> SessionScope {
        SessionScope {
            runtime: RuntimeSlot::Stable,
            runtime_generation: 2,
            session_id: "11111111-1111-4111-8111-111111111111".into(),
            connection_generation: 3,
        }
    }
    fn fixture() -> StartedOriginal {
        start_original(
            scope(),
            TunnelSlot::A,
            TunnelTransport::WireGuard,
            crate::test_engine_path("engine.exe"),
            initial(),
        )
        .unwrap()
    }

    #[test]
    fn original_rebind_support_yields_real_ack_and_readers_not_equal_metadata() {
        let mut own = fixture();
        let (running, receipt, mut replacement): RebindOutcome =
            own.member.rebind_original(&own.running).unwrap();
        assert_eq!(
            running.proof.unwrap().process,
            ProcessProof {
                pid: 21,
                creation_time: 31
            }
        );
        assert_eq!(running.proof.unwrap().interface, initial().interface);
        assert_eq!(running.retired_proof, Some(initial()));
        assert_eq!(own.control.saved_record(), Some(running.clone()));
        receipt.verify_retired_original_read(&own.reader).unwrap();
        receipt.verify_retired_pending_read(&own.pending).unwrap();
        receipt
            .verify_replacement_original_read(&replacement)
            .unwrap();
        own.member.verify_rebind_receipt(&receipt).unwrap();
        assert_eq!(
            replacement.read().unwrap(),
            (running.intent.clone(), running.proof.unwrap())
        );
        assert!(own.reader.read().is_err());
        let pending = own.member.pending_rebind_read(&receipt).unwrap();
        assert!(receipt.verify_retired_pending_read(&pending).is_err());
        assert_eq!(own.control.counts().config_writes, 1);
        let mut foreign = fixture();
        let (equal, foreign_receipt, foreign_reader) =
            foreign.member.rebind_original(&foreign.running).unwrap();
        assert_eq!(running, equal);
        assert!(receipt
            .verify_retired_original_read(&foreign.reader)
            .is_err());
        assert!(receipt
            .verify_retired_pending_read(&foreign.pending)
            .is_err());
        assert!(receipt
            .verify_replacement_original_read(&foreign_reader)
            .is_err());
        assert!(own.member.verify_rebind_receipt(&foreign_receipt).is_err());
        assert_eq!(own.control.counts().service_creates, 1);
        assert_eq!(own.control.counts().restarts, 1);
        assert_eq!(own.control.counts().process_pins, 2);
        assert_eq!(own.control.counts().process_drops, 0);
        assert_eq!(own.control.counts().deletes, 0);
    }

    #[test]
    fn original_rebind_support_keeps_both_process_handles_through_readers_and_receipt() {
        let mut own = fixture();
        let (_, receipt, replacement) = own.member.rebind_original(&own.running).unwrap();
        let monitor = own.control.clone();
        drop(own);
        assert_eq!(monitor.counts().service_drops, 0);
        assert_eq!(monitor.counts().process_drops, 0);
        drop(replacement);
        assert_eq!(monitor.counts().process_drops, 0);
        drop(receipt);
        assert_eq!(monitor.counts().service_drops, 1);
        assert_eq!(monitor.counts().process_drops, 2);
        // Dropping original handles is NOT an implicit native stop/delete.
        assert_eq!(monitor.counts().stops, 1);
        assert_eq!(monitor.counts().deletes, 0);
    }

    #[test]
    fn original_rebind_support_rejects_uncertain_native_lifecycle_and_retains_roots() {
        for fault in [
            Fault::OldProcessStillActive,
            Fault::ReplacementNic,
            Fault::ReplacementQueryError,
            Fault::ReplacementQueryUnwind,
            Fault::LostRunningAck,
            Fault::FailRunningSave,
        ] {
            let mut own = fixture();
            own.control.set_fault(fault);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                own.member.rebind_original(&own.running)
            }));
            if fault == Fault::ReplacementQueryUnwind {
                assert!(result.is_err());
            } else {
                assert!(result.unwrap().is_err(), "{fault:?}");
            }
            assert!(own.reader.read().is_err());
            assert!(own.member.original_read().is_err());
            let counts = own.control.counts();
            assert_eq!(counts.service_creates, 1);
            assert_eq!(counts.service_drops, 0);
            assert_eq!(counts.process_drops, 0);
            assert_eq!(
                counts.restarts,
                usize::from(fault != Fault::OldProcessStillActive)
            );
            if fault != Fault::OldProcessStillActive {
                assert_eq!(counts.process_pins, 2);
            }
            assert_eq!(counts.deletes, 0);
            let stored = own.control.saved_record().unwrap();
            assert_eq!(stored.retired_proof, Some(initial()));
            if fault == Fault::LostRunningAck {
                assert_eq!(stored.phase, Phase::Running);
                assert_ne!(stored.proof, Some(initial()));
            } else {
                assert_eq!(stored.phase, Phase::Prepared);
                assert!(stored.proof.is_none());
            }
            own.control.set_fault(Fault::None);
            assert!(own.member.rebind_original(&own.running).is_err());
            assert_eq!(own.control.counts(), counts);
        }
    }

    #[test]
    fn original_rebind_support_duplicate_and_scope_mismatch_do_not_restart_or_rewrite() {
        for wrong_scope in [false, true] {
            let mut own = fixture();
            let mut expected = own.running.clone();
            if wrong_scope {
                expected.intent.scope.connection_generation += 1;
            } else {
                own.member.rebind_original(&expected).unwrap();
            }
            let before = own.control.counts();
            assert!(own.member.rebind_original(&expected).is_err());
            assert_eq!(own.control.counts(), before);
        }
    }

    #[test]
    fn original_rebind_support_uses_real_wg_and_awg_originals_for_both_slots() {
        for slot in [TunnelSlot::A, TunnelSlot::B] {
            for transport in [TunnelTransport::WireGuard, TunnelTransport::AmneziaWg3] {
                let mut own = start_original(
                    scope(),
                    slot,
                    transport,
                    crate::test_engine_path("engine.exe"),
                    initial(),
                )
                .unwrap();
                assert_eq!(own.running.intent.slot, slot);
                assert_eq!(own.running.intent.transport, transport);
                let (running, receipt, mut reader) =
                    own.member.rebind_original(&own.running).unwrap();
                receipt.verify_retired_original_read(&own.reader).unwrap();
                receipt.verify_replacement_original_read(&reader).unwrap();
                assert_eq!(
                    reader.read().unwrap(),
                    (running.intent, running.proof.unwrap())
                );
                let counts = own.control.counts();
                assert_eq!(counts.service_creates, 1);
                assert_eq!(counts.process_pins, 2);
                assert_eq!(counts.stops, 1);
                assert_eq!(counts.restarts, 1);
                assert_eq!(counts.config_writes, 1);
            }
        }
    }
}
