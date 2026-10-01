use super::*;
use nelomai_contracts::RuntimeSlot;
use std::{cell::RefCell, rc::Rc};

const CONFIG: &str =
    "[Interface]\nPrivateKey = PRIVATE-TEST-KEY\nDNS = 9.9.9.9\n[Peer]\nPublicKey = test\n";
fn scope() -> SessionScope {
    SessionScope {
        runtime: RuntimeSlot::Stable,
        runtime_generation: 2,
        session_id: "11111111-1111-4111-8111-111111111111".into(),
        connection_generation: 3,
    }
}
fn proof() -> NativeProof {
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
struct State {
    record: Option<Record>,
    observation: Observation,
    events: Vec<&'static str>,
    fail_save: Option<Phase>,
    lost_save_ack: Option<Phase>,
    change_after_stopping: bool,
    fail_start: bool,
    fail_capture: bool,
    fail_stop: bool,
    fail_rebind: bool,
    changed_after_capture: bool,
    next_proof: NativeProof,
    save_count: usize,
    fail_save_number: Option<usize>,
    lost_save_number: Option<usize>,
    fail_config: bool,
    lost_config_ack: bool,
    written_config: Option<zeroize::Zeroizing<String>>,
}
type Shared = Rc<RefCell<State>>;
struct Disk(Shared);
struct Io(Shared);
impl Journal for Disk {
    fn load(&mut self, slot: TunnelSlot) -> Result<Option<Record>> {
        assert_eq!(slot, TunnelSlot::B);
        Ok(self.0.borrow().record.clone())
    }
    fn compare_exchange(
        &mut self,
        slot: TunnelSlot,
        expected: Option<&Record>,
        desired: &Record,
    ) -> Result<()> {
        assert_eq!(slot, TunnelSlot::B);
        let mut s = self.0.borrow_mut();
        if s.record.as_ref() != expected {
            return Err(OwnerError::Conflict);
        }
        s.save_count += 1;
        s.events.push(match desired.phase {
            Phase::Prepared => "prepared",
            Phase::Running => "running",
            Phase::Stopping => "stopping",
            Phase::Stopped => "stopped",
        });
        if s.fail_save == Some(desired.phase) || s.fail_save_number == Some(s.save_count) {
            return Err(OwnerError::Journal);
        }
        s.record = Some(desired.clone());
        if desired.phase == Phase::Stopping && s.change_after_stopping {
            s.observation
                .service
                .as_mut()
                .unwrap()
                .process
                .as_mut()
                .unwrap()
                .creation_time += 1;
        }
        if s.lost_save_ack == Some(desired.phase) || s.lost_save_number == Some(s.save_count) {
            return Err(OwnerError::Journal);
        }
        Ok(())
    }
}
impl MemberIo for Io {
    fn inspect(&mut self, intent: &Intent, retained: Option<&NativeProof>) -> Result<Observation> {
        assert_eq!(intent.slot, TunnelSlot::B);
        let mut s = self.0.borrow_mut();
        s.events.push("inspect");
        if s.fail_capture && s.observation.service.is_some() {
            return Err(OwnerError::Native);
        }
        let mut out = s.observation.clone();
        if retained.is_some() && out.retained_interfaces.is_empty() {
            out.retained_interfaces = out.interface.into_iter().collect();
        }
        Ok(out)
    }
    fn write_private_config(
        &mut self,
        intent: &Intent,
        expected_sha256: Option<[u8; 32]>,
        canonical: &str,
    ) -> Result<()> {
        assert_eq!(intent.slot, TunnelSlot::B);
        assert!(canonical.contains("Table = off"));
        assert!(!canonical.contains("DNS"));
        let mut s = self.0.borrow_mut();
        if s.observation.config_sha256 != expected_sha256 {
            return Err(OwnerError::Conflict);
        }
        assert_eq!(s.record.as_ref().unwrap().phase, Phase::Prepared);
        s.events.push("config");
        if s.fail_config {
            return Err(OwnerError::Native);
        }
        s.observation.config_sha256 = Some(intent.config_sha256);
        s.written_config = Some(zeroize::Zeroizing::new(canonical.to_owned()));
        if s.lost_config_ack {
            return Err(OwnerError::Native);
        }
        Ok(())
    }
    fn start_fresh(&mut self, intent: &Intent, _: Option<&NativeProof>) -> Result<()> {
        assert_eq!(intent.slot, TunnelSlot::B);
        let mut s = self.0.borrow_mut();
        assert!(s.observation.service.is_none());
        assert!(!s.observation.alternative_service_present);
        assert_eq!(s.record.as_ref().unwrap().phase, Phase::Prepared);
        assert!(s.record.as_ref().unwrap().previous_config_sha256.is_none());
        s.events.push("start");
        s.observation.service = Some(ServiceObservation {
            exact_spec: true,
            process: Some(s.next_proof.process),
        });
        s.observation.interface = Some(s.next_proof.interface);
        if s.fail_start {
            Err(OwnerError::Native)
        } else {
            Ok(())
        }
    }
    fn stop_slot(
        &mut self,
        intent: &Intent,
        _: Option<&NativeProof>,
        expected: &Observation,
    ) -> Result<()> {
        assert_eq!(intent.slot, TunnelSlot::B);
        let mut s = self.0.borrow_mut();
        assert!(matches!(
            s.record.as_ref().unwrap().phase,
            Phase::Running | Phase::Stopping
        ));
        assert_eq!(expected.service, s.observation.service);
        s.events.push("stop");
        s.observation.service.as_mut().unwrap().process = None;
        s.observation.interface = None;
        s.observation.retained_interfaces.clear();
        if s.fail_stop {
            return Err(OwnerError::Native);
        }
        s.observation.service = None;
        Ok(())
    }
    fn rebind(&mut self, intent: &Intent, old: &NativeProof, expected: &Observation) -> Result<()> {
        assert_eq!(intent.slot, TunnelSlot::B);
        let mut s = self.0.borrow_mut();
        assert_eq!(s.record.as_ref().unwrap().phase, Phase::Prepared);
        assert_eq!(expected.service, s.observation.service);
        assert_eq!(*old, proof());
        s.events.push("rebind");
        if s.fail_rebind {
            return Err(OwnerError::Native);
        }
        if !s.changed_after_capture {
            s.observation.service.as_mut().unwrap().process = Some(ProcessProof {
                pid: 21,
                creation_time: 31,
            });
            s.observation.interface = Some(InterfaceProof {
                index: 41,
                luid: 51,
                guid: [7; 16],
            });
        }
        Ok(())
    }
}
fn owner(s: Shared) -> MemberOwner<Disk, Io> {
    MemberOwner::from_trusted_engine(
        scope(),
        TunnelSlot::B,
        TunnelTransport::WireGuard,
        crate::test_engine_path("engine.exe"),
        CONFIG,
        Disk(s.clone()),
        Io(s),
    )
    .unwrap()
}
fn setup() -> (MemberOwner<Disk, Io>, Shared) {
    let s = Rc::new(RefCell::new(State {
        record: None,
        observation: Observation {
            config_sha256: None,
            service: None,
            alternative_service_present: false,
            interface: None,
            retained_interfaces: vec![],
        },
        events: vec![],
        fail_save: None,
        lost_save_ack: None,
        change_after_stopping: false,
        fail_start: false,
        fail_capture: false,
        fail_stop: false,
        fail_rebind: false,
        changed_after_capture: false,
        next_proof: proof(),
        save_count: 0,
        fail_save_number: None,
        lost_save_number: None,
        fail_config: false,
        lost_config_ack: false,
        written_config: None,
    }));
    (owner(s.clone()), s)
}

fn replacement(s: Shared, scope: SessionScope) -> MemberOwner<Disk, Io> {
    replacement_engine(s, scope, &crate::test_engine_path("engine.exe"))
}

const CARRIER_CONFIG: &str = "[Interface]\nPrivateKey = PRIVATE-TEST-KEY\nAddress = 10.240.5.2/32\nDNS = 9.9.9.9\nTable = auto\n[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\nPersistentKeepalive = 25\n";
const CARRIER_NATIVE: &str = "[Interface]\nTable = off\nPrivateKey = PRIVATE-TEST-KEY\n[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\nPersistentKeepalive = 25\n";

fn carrier_intent() -> crate::member_carrier::Intent {
    crate::member_carrier::Intent {
        scope: scope(),
        addresses: vec!["10.240.5.2/32".parse().unwrap()],
    }
}

#[test]
fn carrier_member_start_publishes_and_hashes_only_addressless_native_configuration() {
    for (transport, extra) in [
        (TunnelTransport::WireGuard, ""),
        (
            TunnelTransport::AmneziaWg3,
            "Jc = 4\nJmin = 40\nJmax = 70\nHeaderProtectionKey = synthetic-header\nContentPaddingAddition = 1\n",
        ),
    ] {
        let (_, s) = setup();
        let logical = CARRIER_CONFIG.replace("[Peer]", &format!("{extra}[Peer]"));
        let expected = CARRIER_NATIVE.replace("[Peer]", &format!("{extra}[Peer]"));
        let mut owner = MemberOwner::from_trusted_carrier_engine(
            &carrier_intent(),
            TunnelSlot::B,
            transport,
            crate::test_engine_path("engine.exe"),
            &logical,
            Disk(s.clone()),
            Io(s.clone()),
        )
        .unwrap();
        // Construction cannot claim/start/configure anything; only the existing
        // durable Prepared→config CAS→native Start→Running path can do so.
        assert!(s.borrow().events.is_empty());
        let running = owner.start_with_prior(None).unwrap();
        assert_eq!(running.intent.scope, scope());
        assert_eq!(running.intent.transport, transport);
        assert_eq!(
            running.intent.config_sha256,
            <[u8; 32]>::from(Sha256::digest(expected.as_bytes()))
        );
        assert_ne!(
            running.intent.config_sha256,
            <[u8; 32]>::from(Sha256::digest(logical.as_bytes()))
        );
        assert_eq!(
            s.borrow().written_config.as_deref().map(|s| s.as_str()),
            Some(expected.as_str())
        );
        assert_eq!(running.proof, Some(proof()));
        assert_eq!(owner.stop(&running).unwrap().phase, Phase::Stopped);
    }
}

#[test]
fn carrier_member_rejects_mismatched_network_before_any_journal_or_native_call() {
    for addresses in [
        vec![],
        vec!["10.240.5.3/32".parse().unwrap()],
        vec!["10.240.5.2/24".parse().unwrap()],
        vec!["fd00::2/128".parse().unwrap()],
        vec![
            "10.240.5.2/32".parse().unwrap(),
            "10.240.5.3/32".parse().unwrap(),
        ],
    ] {
        let (_, s) = setup();
        let intent = crate::member_carrier::Intent {
            addresses,
            ..carrier_intent()
        };
        assert!(matches!(
            MemberOwner::from_trusted_carrier_engine(
                &intent,
                TunnelSlot::B,
                TunnelTransport::WireGuard,
                crate::test_engine_path("engine.exe"),
                CARRIER_CONFIG,
                Disk(s.clone()),
                Io(s.clone()),
            ),
            Err(OwnerError::Conflict)
        ));
        assert!(s.borrow().events.is_empty());
        assert!(s.borrow().record.is_none());
    }
}

#[test]
fn carrier_member_never_accepts_unvalidated_native_input_or_wrong_transport() {
    let cases = [
        (CARRIER_NATIVE.to_owned(), TunnelTransport::WireGuard),
        (
            CARRIER_CONFIG.replace("10.240.5.2/32", "10.240.5.2/24"),
            TunnelTransport::WireGuard,
        ),
        (
            CARRIER_CONFIG.replace("10.240.5.2/32", "fd00::2/128"),
            TunnelTransport::WireGuard,
        ),
        (
            CARRIER_CONFIG.replace("[Peer]", "PostUp = do-not-run\n[Peer]"),
            TunnelTransport::WireGuard,
        ),
        (
            CARRIER_CONFIG.replace("[Peer]", "ForeignOption = 1\n[Peer]"),
            TunnelTransport::WireGuard,
        ),
        (
            CARRIER_CONFIG.replace(
                "PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                "PublicKey = invalid",
            ),
            TunnelTransport::WireGuard,
        ),
        (CARRIER_CONFIG.to_owned(), TunnelTransport::AmneziaWg3),
        (
            CARRIER_CONFIG.replace("[Peer]", "Jc = 4\nJmin = 40\nJmax = 70\nHeaderProtectionKey = synthetic-header\nContentPaddingAddition = 1\n[Peer]"),
            TunnelTransport::WireGuard,
        ),
    ];
    for (logical, transport) in cases {
        let (_, s) = setup();
        assert!(matches!(
            MemberOwner::from_trusted_carrier_engine(
                &carrier_intent(),
                TunnelSlot::B,
                transport,
                crate::test_engine_path("engine.exe"),
                &logical,
                Disk(s.clone()),
                Io(s.clone()),
            ),
            Err(OwnerError::Invalid)
        ));
        assert!(s.borrow().events.is_empty());
    }
}

#[test]
fn carrier_member_construction_keeps_actual_scope_and_engine_validation() {
    for (scope, engine) in [
        (
            SessionScope {
                connection_generation: 0,
                ..scope()
            },
            crate::test_engine_path("engine.exe"),
        ),
        (
            SessionScope {
                session_id: "foreign".into(),
                ..scope()
            },
            crate::test_engine_path("engine.exe"),
        ),
        (scope(), PathBuf::from("relative.exe")),
        (scope(), crate::test_engine_path("../engine.exe")),
    ] {
        let (_, s) = setup();
        let intent = crate::member_carrier::Intent {
            scope,
            ..carrier_intent()
        };
        assert!(matches!(
            MemberOwner::from_trusted_carrier_engine(
                &intent,
                TunnelSlot::B,
                TunnelTransport::WireGuard,
                engine,
                CARRIER_CONFIG,
                Disk(s.clone()),
                Io(s.clone()),
            ),
            Err(OwnerError::Invalid)
        ));
        assert!(s.borrow().events.is_empty());
    }
}

#[test]
fn ordinary_member_keeps_address_and_does_not_use_carrier_renderer() {
    let (_, s) = setup();
    let mut owner = MemberOwner::from_trusted_engine(
        scope(),
        TunnelSlot::B,
        TunnelTransport::WireGuard,
        crate::test_engine_path("engine.exe"),
        CARRIER_CONFIG,
        Disk(s.clone()),
        Io(s.clone()),
    )
    .unwrap();
    let running = owner.start_with_prior(None).unwrap();
    let expected = CARRIER_NATIVE.replace(
        "PrivateKey = PRIVATE-TEST-KEY\n",
        "PrivateKey = PRIVATE-TEST-KEY\nAddress = 10.240.5.2/32\n",
    );
    assert_eq!(
        s.borrow().written_config.as_deref().map(|s| s.as_str()),
        Some(expected.as_str())
    );
    assert_eq!(
        running.intent.config_sha256,
        <[u8; 32]>::from(Sha256::digest(expected.as_bytes()))
    );
}

#[test]
fn carrier_member_lost_prepare_ack_never_writes_config_or_starts() {
    let (_, s) = setup();
    s.borrow_mut().lost_save_ack = Some(Phase::Prepared);
    let mut owner = MemberOwner::from_trusted_carrier_engine(
        &carrier_intent(),
        TunnelSlot::B,
        TunnelTransport::WireGuard,
        crate::test_engine_path("engine.exe"),
        CARRIER_CONFIG,
        Disk(s.clone()),
        Io(s.clone()),
    )
    .unwrap();
    assert_eq!(owner.start_with_prior(None), Err(OwnerError::Journal));
    assert!(s.borrow().written_config.is_none());
    assert!(!s.borrow().events.contains(&"start"));
    assert_eq!(owner.start_with_prior(None), Err(OwnerError::Retired));
    assert_eq!(s.borrow().record.as_ref().unwrap().phase, Phase::Prepared);
}
fn replacement_engine(
    s: Shared,
    scope: SessionScope,
    engine: &std::path::Path,
) -> MemberOwner<Disk, Io> {
    MemberOwner::from_trusted_engine(
        scope,
        TunnelSlot::B,
        TunnelTransport::WireGuard,
        PathBuf::from(engine),
        "[Interface]\nPrivateKey = NEXT-PRIVATE-KEY\n[Peer]\nPublicKey = next\n",
        Disk(s.clone()),
        Io(s),
    )
    .unwrap()
}

#[test]
fn reincarnation_stopped_predecessor_allows_new_engine_and_runtime_only_when_absent() {
    for (engine, runtime) in [
        (
            crate::test_engine_path("new-engine.exe"),
            RuntimeSlot::Stable,
        ),
        (crate::test_engine_path("engine.exe"), RuntimeSlot::Latest),
        (
            crate::test_engine_path("new-engine.exe"),
            RuntimeSlot::Latest,
        ),
    ] {
        let (mut old, s) = setup();
        let running = old.start().unwrap();
        let prior = old.stop(&running).unwrap();
        let mut cleanup = recover(&prior, s.clone()).unwrap();
        let next_scope = SessionScope {
            runtime,
            connection_generation: 4,
            ..scope()
        };
        s.borrow_mut().next_proof.process.creation_time += 1;
        let mut next = replacement_engine(s.clone(), next_scope.clone(), &engine);
        assert_eq!(next.prior_stopped().unwrap(), Some(prior.clone()));
        let current = next.start_with_prior(Some(&prior)).unwrap();
        assert_eq!(current.intent.engine, engine);
        assert_eq!(current.intent.scope, next_scope);
        assert_eq!(current.retired_proof, prior.retired_proof);
        assert_eq!(s.borrow().record.as_ref(), Some(&current));
        assert_eq!(old.start(), Err(OwnerError::Retired));
        assert_eq!(cleanup.start(), Err(OwnerError::Retired));
    }
}

#[test]
fn reincarnation_cross_runtime_still_rejects_live_foreign_stale_and_nonstopped_prior() {
    for mutation in 0..8 {
        let (mut old, s) = setup();
        let running = old.start().unwrap();
        let prior = old.stop(&running).unwrap();
        {
            let mut state = s.borrow_mut();
            state.events.clear();
            match mutation {
                0 => {
                    state.observation.service = Some(ServiceObservation {
                        exact_spec: true,
                        process: Some(proof().process),
                    })
                }
                1 => state.observation.alternative_service_present = true,
                2 => {
                    state.observation.service = Some(ServiceObservation {
                        exact_spec: false,
                        process: None,
                    })
                }
                3 => state.observation.retained_interfaces.push(InterfaceProof {
                    guid: [9; 16],
                    ..proof().interface
                }),
                4 => {
                    state
                        .record
                        .as_mut()
                        .unwrap()
                        .intent
                        .scope
                        .connection_generation += 1
                }
                5 => {
                    let mut record = prior.clone();
                    record.phase = Phase::Prepared;
                    state.record = Some(record);
                }
                6 => state.record = Some(running),
                _ => state.observation.config_sha256 = Some([99; 32]),
            }
        }
        let baseline = s.borrow().record.clone();
        let next_scope = SessionScope {
            runtime: RuntimeSlot::Latest,
            connection_generation: 4,
            ..scope()
        };
        let mut next = replacement_engine(
            s.clone(),
            next_scope,
            &crate::test_engine_path("new-engine.exe"),
        );
        // Bind the observed predecessor as a pair would. A changed journal
        // after capturing prior is never accepted merely because it is Stopped.
        let bound_prior = if matches!(mutation, 5 | 6) {
            baseline.as_ref()
        } else {
            Some(&prior)
        };
        assert!(next.start_with_prior(bound_prior).is_err());
        assert_eq!(s.borrow().record, baseline);
        assert!(!s
            .borrow()
            .events
            .iter()
            .any(|e| matches!(*e, "prepared" | "config" | "start" | "stop")));
    }
}

#[test]
fn reincarnation_fresh_owner_replaces_stopped_same_or_new_scope_without_deleting_journal() {
    for next_scope in [
        scope(),
        SessionScope {
            connection_generation: 4,
            ..scope()
        },
    ] {
        let (mut original, shared) = setup();
        let running = original.start().unwrap();
        let stopped = original.stop(&running).unwrap();
        shared.borrow_mut().events.clear();
        shared.borrow_mut().next_proof.process.creation_time += 1;
        let mut next = replacement(shared.clone(), next_scope.clone());
        let running = next.start().unwrap();
        assert_eq!(running.phase, Phase::Running);
        assert_eq!(running.intent.scope, next_scope);
        assert_ne!(running.intent.config_sha256, stopped.intent.config_sha256);
        assert_eq!(running.retired_proof, stopped.retired_proof);
        assert_eq!(shared.borrow().record.as_ref(), Some(&running));
        assert!(original.start().is_err());
        assert!(original.stop(&stopped).is_err());
        let stopped = next.stop(&running).unwrap();
        assert!(next.start().is_err());
        assert_eq!(shared.borrow().record.as_ref(), Some(&stopped));
    }
}

#[test]
fn reincarnation_attempt_consumes_fresh_owner_even_when_first_save_fails() {
    let (mut original, shared) = setup();
    shared.borrow_mut().fail_save = Some(Phase::Prepared);
    assert_eq!(original.start().unwrap_err(), OwnerError::Journal);
    shared.borrow_mut().fail_save = None;
    shared.borrow_mut().events.clear();
    assert_eq!(original.start().unwrap_err(), OwnerError::Retired);
    assert!(shared.borrow().record.is_none());
    assert!(shared.borrow().events.is_empty());
}

#[test]
fn reincarnation_stop_consumes_even_a_fresh_owner_used_only_for_cleanup() {
    let (mut original, s) = setup();
    let running = original.start().unwrap();
    let mut other = owner(s.clone());
    other.stop(&running).unwrap();
    s.borrow_mut().events.clear();
    assert_eq!(other.start(), Err(OwnerError::Retired));
    assert!(s.borrow().events.is_empty());
}

#[test]
fn reincarnation_rejects_orphan_config_foreign_service_and_retained_identity_before_cas() {
    for mutation in 0..7 {
        let (mut original, shared) = setup();
        let running = original.start().unwrap();
        let stopped = original.stop(&running).unwrap();
        {
            let mut s = shared.borrow_mut();
            s.events.clear();
            match mutation {
                0 => s.observation.config_sha256 = Some([9; 32]),
                1 => s.observation.alternative_service_present = true,
                2 => {
                    s.observation.service = Some(ServiceObservation {
                        exact_spec: false,
                        process: None,
                    })
                }
                3 => {
                    s.observation.service = Some(ServiceObservation {
                        exact_spec: true,
                        process: Some(ProcessProof {
                            pid: 20,
                            creation_time: 99,
                        }),
                    })
                }
                4 => s.observation.retained_interfaces.push(InterfaceProof {
                    guid: [9; 16],
                    ..proof().interface
                }),
                5 => s.observation.interface = Some(proof().interface),
                _ => s.record.as_mut().unwrap().proof = Some(proof()),
            }
        }
        assert!(replacement(shared.clone(), scope()).start().is_err());
        assert!(!shared
            .borrow()
            .events
            .iter()
            .any(|e| matches!(*e, "prepared" | "config" | "start")));
        if mutation != 6 {
            assert_eq!(shared.borrow().record, Some(stopped));
        }
    }
}

#[test]
fn reincarnation_failed_boundaries_never_start_before_previous_digest_is_durably_cleared() {
    for boundary in 0..6 {
        let (mut original, shared) = setup();
        let running = original.start().unwrap();
        let stopped = original.stop(&running).unwrap();
        {
            let mut s = shared.borrow_mut();
            s.events.clear();
            s.save_count = 0;
            match boundary {
                0 => s.fail_save_number = Some(1),
                1 => s.lost_save_number = Some(1),
                2 => s.fail_config = true,
                3 => s.lost_config_ack = true,
                4 => s.fail_save_number = Some(2),
                _ => s.lost_save_number = Some(2),
            }
        }
        let mut next = replacement(shared.clone(), scope());
        assert!(next.start().is_err());
        assert!(next.start().is_err());
        assert!(!shared.borrow().events.contains(&"start"));
        let s = shared.borrow();
        let saved = s.record.as_ref().unwrap();
        if boundary == 0 {
            assert_eq!(saved, &stopped);
        } else {
            assert_eq!(saved.phase, Phase::Prepared);
            assert_eq!(
                saved.previous_config_sha256,
                if boundary == 5 {
                    None
                } else {
                    Some(stopped.intent.config_sha256)
                }
            );
            assert_eq!(saved.retired_proof, stopped.retired_proof);
        }
        assert_eq!(
            s.observation.config_sha256,
            Some(if boundary <= 2 {
                stopped.intent.config_sha256
            } else {
                next.intent().config_sha256
            })
        );
    }
}

#[test]
fn reincarnation_transition_cleanup_retains_actual_old_new_or_absent_config_without_writing() {
    for digest in 0..3 {
        let (mut original, s) = setup();
        let running = original.start().unwrap();
        let old = original.stop(&running).unwrap();
        s.borrow_mut().fail_config = true;
        let mut next = replacement(s.clone(), scope());
        assert!(next.start().is_err());
        let prepared = s.borrow().record.clone().unwrap();
        let observed = match digest {
            0 => Some(old.intent.config_sha256),
            1 => Some(prepared.intent.config_sha256),
            _ => None,
        };
        s.borrow_mut().observation.config_sha256 = observed;
        s.borrow_mut().events.clear();
        let mut cleanup = recover(&prepared, s.clone()).unwrap();
        let stopped = cleanup.stop(&prepared).unwrap();
        assert_eq!(stopped.phase, Phase::Stopped);
        assert_eq!(
            stopped.previous_config_sha256,
            Some(old.intent.config_sha256)
        );
        assert_eq!(s.borrow().observation.config_sha256, observed);
        assert!(!s
            .borrow()
            .events
            .iter()
            .any(|v| matches!(*v, "config" | "start" | "stop")));
        assert!(cleanup.start().is_err());
        assert!(cleanup.confirm_absent(&stopped).unwrap());
        s.borrow_mut().save_count = 0;
        s.borrow_mut().lost_save_number = Some(1);
        let mut third = replacement(s.clone(), scope());
        assert!(third.start().is_err());
        assert_eq!(
            s.borrow().record.as_ref().unwrap().previous_config_sha256,
            observed
        );
    }
}

#[test]
fn reincarnation_transition_cleanup_lost_terminal_ack_is_exactly_recoverable() {
    let (mut original, s) = setup();
    let running = original.start().unwrap();
    original.stop(&running).unwrap();
    s.borrow_mut().fail_config = true;
    let mut next = replacement(s.clone(), scope());
    assert!(next.start().is_err());
    let prepared = s.borrow().record.clone().unwrap();
    let mut cleanup = recover(&prepared, s.clone()).unwrap();
    s.borrow_mut().lost_save_ack = Some(Phase::Stopped);
    assert_eq!(cleanup.stop(&prepared), Err(OwnerError::Journal));
    let stopped = s.borrow().record.clone().unwrap();
    assert_eq!(stopped.phase, Phase::Stopped);
    s.borrow_mut().lost_save_ack = None;
    assert_eq!(
        recover(&stopped, s.clone())
            .unwrap()
            .stop(&stopped)
            .unwrap(),
        stopped
    );
    for mode in 0..3 {
        let mut bad = prepared.clone();
        if mode == 0 {
            bad.phase = Phase::Running;
            bad.proof = Some(proof());
        }
        if mode == 1 {
            bad.phase = Phase::Stopping;
        }
        if mode == 2 {
            bad.phase = Phase::Stopped;
            bad.proof = Some(proof());
        }
        s.borrow_mut().record = Some(bad.clone());
        assert!(recover(&bad, s.clone()).is_err());
    }
}

#[test]
fn retired_process_absence_rejects_live_or_recycled_pid_even_without_scm_name() {
    let old = proof().process;
    assert!(require_retired_process_absent(&old, None).is_ok());
    assert!(require_retired_process_absent(&old, Some((old, 0))).is_ok());
    assert_eq!(
        require_retired_process_absent(&old, Some((old, 259))),
        Err(OwnerError::Pending)
    );
    assert_eq!(
        require_retired_process_absent(
            &old,
            Some((
                ProcessProof {
                    creation_time: 99,
                    ..old
                },
                0
            ))
        ),
        Err(OwnerError::Conflict)
    );
}

#[test]
fn reincarnation_pair_bound_prior_rejects_old_writer_before_config_or_native_effects() {
    let (mut original, s) = setup();
    let running = original.start().unwrap();
    let old = original.stop(&running).unwrap();
    let mut next = replacement(s.clone(), scope());
    assert_eq!(next.prior_stopped().unwrap(), Some(old.clone()));
    s.borrow_mut()
        .record
        .as_mut()
        .unwrap()
        .intent
        .scope
        .connection_generation += 1;
    s.borrow_mut().events.clear();
    assert_eq!(next.start_with_prior(Some(&old)), Err(OwnerError::Conflict));
    assert!(s.borrow().events.is_empty());
    assert!(original.stop(&old).is_err());
}

fn recover(saved: &Record, s: Shared) -> Result<MemberOwner<Disk, Io>> {
    MemberOwner::recover_for_cleanup(
        scope(),
        TunnelSlot::B,
        TunnelTransport::WireGuard,
        crate::test_engine_path("engine.exe"),
        saved.clone(),
        Disk(s.clone()),
        Io(s),
    )
}
#[test]
fn recovery_has_no_start_or_rebind_authority_and_closes_exact_saved_proof() {
    let (mut original, shared) = setup();
    let saved = original.start().unwrap();
    shared.borrow_mut().events.clear();
    let mut recovered = recover(&saved, shared.clone()).unwrap();
    assert!(recovered.start().is_err());
    assert!(recovered.rebind(&saved).is_err());
    assert!(shared.borrow().events.is_empty());
    assert_eq!(recovered.stop(&saved).unwrap().phase, Phase::Stopped);
    assert!(!shared.borrow().events.contains(&"start"));
    assert!(!shared.borrow().events.contains(&"config"));
}
#[test]
fn recovery_rejects_changed_saved_scope_engine_and_journal_record() {
    let (mut original, shared) = setup();
    let saved = original.start().unwrap();
    for field in 0..3 {
        let mut changed = saved.clone();
        match field {
            0 => changed.intent.scope.connection_generation += 1,
            1 => changed.intent.engine = crate::test_engine_path("other-engine.exe"),
            _ => changed.proof.as_mut().unwrap().process.creation_time += 1,
        }
        assert!(recover(&changed, shared.clone()).is_err());
    }
}
#[test]
fn cleanup_recovery_never_adopts_unproven_live_process_after_partial_start() {
    let (mut original, shared) = setup();
    let mut saved = original.start().unwrap();
    saved.phase = Phase::Prepared;
    saved.proof = None;
    shared.borrow_mut().record = Some(saved.clone());
    shared.borrow_mut().events.clear();
    let mut recovered = recover(&saved, shared.clone()).unwrap();
    assert!(recovered.stop(&saved).is_err());
    assert!(!shared.borrow().events.contains(&"stop"));
}
#[test]
fn physical_discovery_accepts_exact_stopped_service_without_granting_absence_or_liveness() {
    let (mut owner, s) = setup();
    let running = owner.start().unwrap();
    {
        let mut state = s.borrow_mut();
        state.observation.service.as_mut().unwrap().process = None;
        state.observation.interface = None;
        state.observation.retained_interfaces.clear();
        state.events.clear();
    }
    assert!(!owner.confirm_absent(&running).unwrap());
    assert!(owner.confirm_inactive_for_discovery(&running).unwrap());
    assert!(owner.verify_live(&running).is_err());
    assert_eq!(s.borrow().record, Some(running));
    assert!(s.borrow().events.iter().all(|e| *e == "inspect"));
    assert_eq!(owner.start(), Err(OwnerError::Retired));
}

#[test]
fn physical_discovery_stopped_service_rejects_unproven_identity_config_and_read_errors() {
    for mutation in 0..10 {
        let (mut owner, s) = setup();
        let running = owner.start().unwrap();
        {
            let mut state = s.borrow_mut();
            state.observation.service.as_mut().unwrap().process = None;
            state.observation.interface = None;
            state.observation.retained_interfaces.clear();
            match mutation {
                0 => state.observation.service.as_mut().unwrap().exact_spec = false,
                1 => {
                    state.observation.service.as_mut().unwrap().process = Some(ProcessProof {
                        creation_time: 99,
                        ..proof().process
                    })
                }
                2 => state.observation.interface = Some(proof().interface),
                3 => state.observation.retained_interfaces.push(InterfaceProof {
                    guid: [99; 16],
                    ..proof().interface
                }),
                4 => state.observation.config_sha256 = None,
                5 => state.observation.config_sha256 = Some([99; 32]),
                6 => state.observation.alternative_service_present = true,
                7 => {
                    state
                        .record
                        .as_mut()
                        .unwrap()
                        .intent
                        .scope
                        .connection_generation += 1
                }
                8 => state.fail_capture = true,
                _ => state.record.as_mut().unwrap().proof = None,
            }
            state.events.clear();
        }
        let baseline = s.borrow().record.clone();
        assert!(
            !matches!(owner.confirm_inactive_for_discovery(&running), Ok(true)),
            "mutation {mutation}"
        );
        assert_eq!(s.borrow().record, baseline);
        assert!(s.borrow().events.iter().all(|e| *e == "inspect"));
    }
}

#[test]
fn read_only_live_check_rejects_guid_reuse_without_native_effects() {
    let (mut o, s) = setup();
    let r = o.start().unwrap();
    s.borrow_mut().events.clear();
    o.verify_live(&r).unwrap();
    s.borrow_mut().observation.interface.as_mut().unwrap().guid = [9; 16];
    assert!(o.verify_live(&r).is_err());
    assert!(s.borrow().events.iter().all(|v| *v == "inspect"));
}
#[test]
fn stopping_disk_failure_still_cuts_exact_native_and_retains_saved_proof() {
    let (mut owner, s) = setup();
    let saved = owner.start().unwrap();
    s.borrow_mut().fail_save = Some(Phase::Stopping);
    assert_eq!(owner.stop_best_effort(&saved), Err(OwnerError::Journal));
    assert!(s.borrow().observation.service.is_none());
    assert_eq!(s.borrow().record, Some(saved));
}
#[test]
fn retired_absence_proof_rejects_reused_native_interface() {
    let (mut owner, s) = setup();
    let saved = owner.start().unwrap();
    let stopped = owner.stop(&saved).unwrap();
    assert!(owner.confirm_absent(&stopped).unwrap());
    s.borrow_mut()
        .observation
        .retained_interfaces
        .push(proof().interface);
    assert!(owner.confirm_absent(&stopped).is_err());
}
#[test]
fn prepared_is_durable_before_config_and_start_running_carries_exact_proof() {
    let (mut o, s) = setup();
    let r = o.start().unwrap();
    assert_eq!(r.phase, Phase::Running);
    assert_eq!(r.proof, Some(proof()));
    assert_eq!(
        s.borrow().events,
        ["inspect", "prepared", "inspect", "config", "inspect", "start", "inspect", "running"]
    );
    assert_ne!(r.intent.config_sha256, [0; 32]);
    assert!(!serde_json::to_string(&r)
        .unwrap()
        .contains("PRIVATE-TEST-KEY"));
    assert_eq!(
        serde_json::from_str::<Record>(&serde_json::to_string(&r).unwrap()).unwrap(),
        r
    );
}
#[test]
fn before_start_journal_failure_has_no_effects() {
    let (mut o, s) = setup();
    s.borrow_mut().fail_save = Some(Phase::Prepared);
    assert_eq!(o.start(), Err(OwnerError::Journal));
    assert!(s.borrow().observation.service.is_none());
    assert!(s.borrow().observation.config_sha256.is_none());
}
#[test]
fn crash_gap_and_capture_or_running_save_failure_keep_prepared_cleanup_authority() {
    for mode in 0..3 {
        let (mut o, s) = setup();
        match mode {
            0 => s.borrow_mut().fail_start = true,
            1 => s.borrow_mut().fail_capture = true,
            _ => s.borrow_mut().fail_save = Some(Phase::Running),
        };
        assert!(o.start().is_err());
        let saved = s.borrow().record.clone().unwrap();
        assert_eq!(saved.phase, Phase::Prepared);
        s.borrow_mut().fail_capture = false;
        s.borrow_mut().fail_save = None;
        let mut recovered = owner(s.clone());
        assert_eq!(recovered.stop(&saved).unwrap().phase, Phase::Stopped);
        assert!(s.borrow().observation.service.is_none());
    }
}
#[test]
fn prepared_without_any_start_cleans_without_scm_call() {
    let (mut o, s) = setup();
    s.borrow_mut().fail_save = Some(Phase::Running);
    assert!(o.start().is_err());
    let saved = s.borrow().record.clone().unwrap();
    s.borrow_mut().observation.service = None;
    s.borrow_mut().observation.interface = None;
    s.borrow_mut().fail_save = None;
    s.borrow_mut().events.clear();
    assert_eq!(owner(s.clone()).stop(&saved).unwrap().phase, Phase::Stopped);
    assert!(!s.borrow().events.contains(&"stop"));
}
#[test]
fn both_transport_names_and_interface_must_be_absent_before_start() {
    for mode in 0..3 {
        let (mut o, s) = setup();
        match mode {
            0 => s.borrow_mut().observation.alternative_service_present = true,
            1 => {
                s.borrow_mut().observation.service = Some(ServiceObservation {
                    exact_spec: true,
                    process: None,
                })
            }
            _ => s.borrow_mut().observation.interface = Some(proof().interface),
        };
        assert_eq!(o.start(), Err(OwnerError::Conflict));
        assert!(s.borrow().record.is_none());
        assert!(!s.borrow().events.contains(&"start"));
    }
}
#[test]
fn prepared_cleanup_never_trusts_name_without_exact_spec_and_private_digest() {
    for mode in 0..3 {
        let (mut o, s) = setup();
        s.borrow_mut().fail_start = true;
        assert!(o.start().is_err());
        let saved = s.borrow().record.clone().unwrap();
        match mode {
            0 => {
                s.borrow_mut()
                    .observation
                    .service
                    .as_mut()
                    .unwrap()
                    .exact_spec = false
            }
            1 => s.borrow_mut().observation.config_sha256 = Some([1; 32]),
            _ => s.borrow_mut().observation.config_sha256 = None,
        };
        assert_eq!(o.stop(&saved), Err(OwnerError::Conflict));
        assert!(!s.borrow().events.contains(&"stop"));
        assert_eq!(s.borrow().record.as_ref().unwrap().phase, Phase::Prepared);
    }
}
#[test]
fn pid_creation_index_luid_and_guid_reuse_never_authorizes_cleanup_or_rebind() {
    for mode in 0..5 {
        let (mut o, s) = setup();
        let r = o.start().unwrap();
        match mode {
            0 => {
                s.borrow_mut()
                    .observation
                    .service
                    .as_mut()
                    .unwrap()
                    .process
                    .as_mut()
                    .unwrap()
                    .pid += 1
            }
            1 => {
                s.borrow_mut()
                    .observation
                    .service
                    .as_mut()
                    .unwrap()
                    .process
                    .as_mut()
                    .unwrap()
                    .creation_time += 1
            }
            2 => s.borrow_mut().observation.interface.as_mut().unwrap().index += 1,
            3 => s.borrow_mut().observation.interface.as_mut().unwrap().luid += 1,
            _ => s.borrow_mut().observation.interface.as_mut().unwrap().guid = [8; 16],
        };
        assert_eq!(o.stop(&r), Err(OwnerError::Conflict));
        assert_eq!(o.rebind(&r), Err(OwnerError::Conflict));
        assert!(!s.borrow().events.contains(&"stop"));
        assert!(!s.borrow().events.contains(&"rebind"));
    }
}
#[test]
fn absent_service_and_interface_is_complete_but_reused_retained_index_is_not() {
    for reuse in [false, true] {
        let (mut o, s) = setup();
        let r = o.start().unwrap();
        s.borrow_mut().observation.service = None;
        s.borrow_mut().observation.interface = None;
        if reuse {
            s.borrow_mut().observation.retained_interfaces = vec![InterfaceProof {
                index: 40,
                luid: 999,
                guid: [9; 16],
            }];
            assert_eq!(o.stop(&r), Err(OwnerError::Conflict));
        } else {
            assert_eq!(o.stop(&r).unwrap().phase, Phase::Stopped);
        }
        assert!(!s.borrow().events.contains(&"stop"));
    }
}
#[test]
fn partial_stop_stays_stopping_and_recovery_never_touches_sibling() {
    let (mut o, s) = setup();
    let r = o.start().unwrap();
    s.borrow_mut().fail_stop = true;
    assert_eq!(o.stop(&r), Err(OwnerError::Native));
    let stopping = s.borrow().record.clone().unwrap();
    assert_eq!(stopping.phase, Phase::Stopping);
    s.borrow_mut().fail_stop = false;
    assert_eq!(
        owner(s.clone()).stop(&stopping).unwrap().phase,
        Phase::Stopped
    );
}
#[test]
fn wrong_scope_or_retired_proof_has_no_effects() {
    let (mut o, s) = setup();
    let r = o.start().unwrap();
    let mut wrong = r.clone();
    wrong.intent.scope.connection_generation += 1;
    s.borrow_mut().events.clear();
    assert_eq!(o.stop(&wrong), Err(OwnerError::Conflict));
    assert!(s.borrow().events.is_empty());
    let stopped = o.stop(&r).unwrap();
    s.borrow_mut().events.clear();
    assert_eq!(o.stop(&r), Err(OwnerError::Conflict));
    assert_eq!(o.stop(&stopped).unwrap(), stopped);
    assert!(s.borrow().events.is_empty());
    assert_eq!(o.start(), Err(OwnerError::Retired));
}
#[test]
fn rebind_journals_prepared_then_new_proof_and_rejects_retired_proof() {
    let (mut o, s) = setup();
    let old = o.start().unwrap();
    s.borrow_mut().events.clear();
    let new = o.rebind(&old).unwrap();
    assert_ne!(new.proof, old.proof);
    assert_eq!(new.retired_proof, old.proof);
    assert_eq!(
        s.borrow().events,
        ["inspect", "prepared", "rebind", "inspect", "running"]
    );
    assert_eq!(o.stop(&old), Err(OwnerError::Conflict));
}
#[test]
fn rebind_failure_or_unchanged_process_never_restores_running_authority() {
    for no_change in [false, true] {
        let (mut o, s) = setup();
        let old = o.start().unwrap();
        s.borrow_mut().fail_rebind = !no_change;
        s.borrow_mut().changed_after_capture = no_change;
        assert!(o.rebind(&old).is_err());
        assert_eq!(s.borrow().record.as_ref().unwrap().phase, Phase::Prepared);
    }
}

#[test]
fn stopping_save_failure_and_identity_change_after_save_never_issue_stop() {
    for changed in [false, true] {
        let (mut o, s) = setup();
        let r = o.start().unwrap();
        if changed {
            s.borrow_mut().change_after_stopping = true;
        } else {
            s.borrow_mut().fail_save = Some(Phase::Stopping);
        }
        assert_eq!(
            o.stop(&r),
            Err(if changed {
                OwnerError::Conflict
            } else {
                OwnerError::Journal
            })
        );
        assert!(!s.borrow().events.contains(&"stop"));
    }
}

#[test]
fn stopped_save_failure_leaves_durable_stopping_for_idempotent_completion() {
    let (mut o, s) = setup();
    let r = o.start().unwrap();
    s.borrow_mut().fail_save = Some(Phase::Stopped);
    assert_eq!(o.stop(&r), Err(OwnerError::Journal));
    let stopping = s.borrow().record.clone().unwrap();
    assert_eq!(stopping.phase, Phase::Stopping);
    assert!(s.borrow().observation.service.is_none());
    s.borrow_mut().fail_save = None;
    s.borrow_mut().events.clear();
    assert_eq!(
        owner(s.clone()).stop(&stopping).unwrap().phase,
        Phase::Stopped
    );
    assert!(!s.borrow().events.contains(&"stop"));
}

#[test]
fn lost_journal_ack_is_reconciled_by_reread_never_duplicate_start() {
    for phase in [Phase::Prepared, Phase::Running] {
        let (mut o, s) = setup();
        s.borrow_mut().lost_save_ack = Some(phase);
        assert_eq!(o.start(), Err(OwnerError::Journal));
        let record = o.snapshot().unwrap().unwrap();
        assert_eq!(record.phase, phase);
        assert_eq!(o.start(), Err(OwnerError::Retired));
        assert_eq!(
            s.borrow()
                .events
                .iter()
                .filter(|op| **op == "start")
                .count(),
            usize::from(phase == Phase::Running)
        );
        s.borrow_mut().lost_save_ack = None;
        assert_eq!(
            owner(s.clone()).stop(&record).unwrap().phase,
            Phase::Stopped
        );
    }
}

#[test]
fn wrong_journal_identity_and_malformed_proof_fail_before_native_inspection() {
    for mode in 0..5 {
        let (mut o, s) = setup();
        let mut r = o.start().unwrap();
        match mode {
            0 => r.intent.scope.runtime_generation += 1,
            1 => r.intent.slot = TunnelSlot::A,
            2 => r.intent.engine = crate::test_engine_path("foreign-engine.exe"),
            3 => r.intent.config_sha256 = [7; 32],
            _ => r.proof.as_mut().unwrap().interface.index = 0,
        };
        s.borrow_mut().record = Some(r);
        s.borrow_mut().events.clear();
        assert!(o.snapshot().is_err());
        assert!(o.start().is_err());
        assert!(s.borrow().events.is_empty());
    }
}

#[test]
fn rebind_save_failure_has_no_scm_effect_and_running_save_failure_is_recoverable() {
    for phase in [Phase::Prepared, Phase::Running] {
        let (mut o, s) = setup();
        let old = o.start().unwrap();
        s.borrow_mut().fail_save = Some(phase);
        assert_eq!(o.rebind(&old), Err(OwnerError::Journal));
        if phase == Phase::Prepared {
            assert!(!s.borrow().events.contains(&"rebind"));
            assert_eq!(o.snapshot().unwrap(), Some(old));
        } else {
            let prepared = o.snapshot().unwrap().unwrap();
            assert_eq!(prepared.phase, Phase::Prepared);
            s.borrow_mut().fail_save = None;
            assert_eq!(o.stop(&prepared).unwrap().phase, Phase::Stopped);
        }
    }
}

#[test]
fn journal_cannot_revive_a_retired_process_proof() {
    let (mut o, s) = setup();
    let mut r = o.start().unwrap();
    r.retired_proof = r.proof;
    s.borrow_mut().record = Some(r);
    s.borrow_mut().events.clear();
    assert_eq!(o.snapshot(), Err(OwnerError::Invalid));
    assert!(s.borrow().events.is_empty());
}
