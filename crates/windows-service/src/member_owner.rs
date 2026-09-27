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

pub(crate) struct MemberOwner<J, I> {
    intent: Intent,
    configuration: zeroize::Zeroizing<String>,
    journal: J,
    io: I,
    cleanup_only: bool,
    start_consumed: bool,
}
impl<J: Journal, I: MemberIo> MemberOwner<J, I> {
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
        let configuration = crate::redundancy::slot_configuration(configuration)
            .map_err(|_| OwnerError::Invalid)?;
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
        self.io.start_fresh(&self.intent, retired.as_ref())?;
        self.capture_running(&prepared)
    }
    pub(crate) fn stop(&mut self, expected: &Record) -> Result<Record> {
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
        self.capture_running(&prepared)
    }
    fn capture_running(&mut self, prepared: &Record) -> Result<Record> {
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
        self.journal
            .compare_exchange(self.intent.slot, Some(prepared), &running)?;
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
