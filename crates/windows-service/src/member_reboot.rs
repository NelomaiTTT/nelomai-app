//! Cleanup of a protected member after a proven different kernel boot.
//! The caller supplies boot evidence from the protected session adapter, not
//! IPC. Old PID/index/LUID values must never reach the native cleanup API.
#![cfg_attr(not(windows), allow(dead_code))] // Portable fake tests have no native caller.
use crate::member_owner::{Journal, Observation, OwnerError, Phase, Record, Result};

pub(crate) trait RebootIo {
    /// Observe the current exact service/config and both slot aliases. Reject
    /// a remaining old adapter GUID, without looking up old PID/index/LUID.
    fn observe(&mut self, record: &Record) -> Result<Observation>;
    /// Revalidate this observation immediately before removing ONLY a stopped
    /// exact-spec service. No process termination or adapter deletion by name.
    fn remove_stopped(&mut self, record: &Record, before: &Observation) -> Result<()>;
}

pub(crate) fn retire_member<J: Journal, I: RebootIo>(
    different_boot: bool,
    journal: &mut J,
    io: &mut I,
    expected: &Record,
) -> Result<Record> {
    if !different_boot {
        return Err(OwnerError::Invalid);
    }
    crate::member_owner::validate_record_shape(expected)?;
    if journal.load(expected.intent.slot)?.as_ref() != Some(expected) {
        return Err(OwnerError::Conflict);
    }
    let before = io.observe(expected)?;
    authorize(expected, &before)?;
    if before.service.is_some() {
        // The old durable intent remains authority across a lost delete ACK.
        // A retry may see the service absent, but never a running replacement.
        io.remove_stopped(expected, &before)?;
    }
    let after = io.observe(expected)?;
    authorize(expected, &after)?;
    if after.service.is_some() || before.config_sha256 != after.config_sha256 {
        return Err(OwnerError::Pending);
    }
    let mut stopped = expected.clone();
    stopped.phase = Phase::Stopped;
    stopped.proof = None;
    stopped.retired_proof = None;
    if &stopped != expected {
        journal.compare_exchange(expected.intent.slot, Some(expected), &stopped)?;
    }
    if journal.load(expected.intent.slot)?.as_ref() != Some(&stopped) {
        return Err(OwnerError::Conflict);
    }
    Ok(stopped)
}

fn authorize(record: &Record, observed: &Observation) -> Result<()> {
    if observed.alternative_service_present
        || observed.interface.is_some()
        || !observed.retained_interfaces.is_empty()
        || observed.config_sha256.is_some_and(|digest| {
            digest != record.intent.config_sha256 && Some(digest) != record.previous_config_sha256
        })
        || observed.service.as_ref().is_some_and(|service| {
            !service.exact_spec
                || service.process.is_some()
                || record.previous_config_sha256.is_some()
                || observed.config_sha256 != Some(record.intent.config_sha256)
        })
    {
        return Err(OwnerError::Conflict);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::member_owner::{
        Intent, InterfaceProof, NativeProof, ProcessProof, ServiceObservation,
    };
    use nelomai_client_tunnel::{redundancy::SessionScope, TunnelTransport};
    use nelomai_contracts::{dispatcher::TunnelSlot, RuntimeSlot};
    struct Saved {
        record: Record,
        fail: bool,
    }
    impl Journal for Saved {
        fn load(&mut self, _: TunnelSlot) -> Result<Option<Record>> {
            Ok(Some(self.record.clone()))
        }
        fn compare_exchange(
            &mut self,
            _: TunnelSlot,
            expected: Option<&Record>,
            desired: &Record,
        ) -> Result<()> {
            assert_eq!(expected, Some(&self.record));
            if self.fail {
                return Err(OwnerError::Journal);
            }
            self.record = desired.clone();
            Ok(())
        }
    }
    struct Io {
        observed: Observation,
        deletes: usize,
        fail: bool,
    }
    impl RebootIo for Io {
        fn observe(&mut self, _: &Record) -> Result<Observation> {
            if self.fail {
                return Err(OwnerError::Native);
            }
            Ok(self.observed.clone())
        }
        fn remove_stopped(&mut self, record: &Record, before: &Observation) -> Result<()> {
            authorize(record, before)?;
            assert_eq!(&self.observed, before);
            self.deletes += 1;
            self.observed.service = None;
            Ok(())
        }
    }
    fn fixture() -> (Saved, Io) {
        let record = Record {
            intent: Intent {
                scope: SessionScope {
                    runtime: RuntimeSlot::Latest,
                    runtime_generation: 10,
                    session_id: "11111111-1111-4111-8111-111111111111".into(),
                    connection_generation: 1,
                },
                slot: TunnelSlot::A,
                transport: TunnelTransport::WireGuard,
                engine: crate::test_engine_path("old-engine"),
                config_sha256: [1; 32],
            },
            phase: Phase::Running,
            proof: Some(NativeProof {
                process: ProcessProof {
                    pid: 10,
                    creation_time: 11,
                },
                interface: InterfaceProof {
                    index: 12,
                    luid: 13,
                    guid: [14; 16],
                },
            }),
            retired_proof: None,
            previous_config_sha256: None,
        };
        let observed = Observation {
            config_sha256: Some([1; 32]),
            service: Some(ServiceObservation {
                exact_spec: true,
                process: None,
            }),
            alternative_service_present: false,
            interface: None,
            retained_interfaces: vec![],
        };
        (
            Saved {
                record,
                fail: false,
            },
            Io {
                observed,
                deletes: 0,
                fail: false,
            },
        )
    }
    #[test]
    fn different_boot_retires_stopped_service_without_replaying_native_ids() {
        let (mut saved, mut io) = fixture();
        let expected = saved.record.clone();
        assert!(retire_member(false, &mut saved, &mut io, &expected).is_err());
        assert_eq!(io.deletes, 0);
        let result = retire_member(true, &mut saved, &mut io, &expected).unwrap();
        assert_eq!(result.phase, Phase::Stopped);
        assert!(result.proof.is_none() && result.retired_proof.is_none());
        assert_eq!(io.deletes, 1);
        retire_member(true, &mut saved, &mut io, &result).unwrap();
        assert_eq!(io.deletes, 1);
    }
    #[test]
    fn foreign_or_running_resources_and_query_failures_never_grant_cleanup() {
        for kind in 0..6 {
            let (mut saved, mut io) = fixture();
            let expected = saved.record.clone();
            match kind {
                0 => {
                    io.observed.service.as_mut().unwrap().process = Some(ProcessProof {
                        pid: 99,
                        creation_time: 99,
                    })
                }
                1 => io.observed.service.as_mut().unwrap().exact_spec = false,
                2 => io.observed.config_sha256 = Some([99; 32]),
                3 => io.observed.alternative_service_present = true,
                4 => io
                    .observed
                    .retained_interfaces
                    .push(expected.proof.unwrap().interface),
                _ => io.fail = true,
            }
            assert!(retire_member(true, &mut saved, &mut io, &expected).is_err());
            assert_eq!(io.deletes, 0);
            assert_eq!(saved.record, expected);
        }
    }
    #[test]
    fn lost_completion_keeps_old_authority_and_allows_exact_absence_retry() {
        let (mut saved, mut io) = fixture();
        let expected = saved.record.clone();
        saved.fail = true;
        assert!(retire_member(true, &mut saved, &mut io, &expected).is_err());
        assert_eq!(saved.record, expected);
        assert_eq!(io.deletes, 1);
        saved.fail = false;
        retire_member(true, &mut saved, &mut io, &expected).unwrap();
        assert_eq!(io.deletes, 1);
    }
}
