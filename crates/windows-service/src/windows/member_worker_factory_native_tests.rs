//! One native acceptance scenario through the actual production actor/factory.
use super::member_carrier_factory_test_os::Fixture;
use crate::{
    member_actor::CompositeBackend, ServiceError, ServiceTunnelBackend, ServiceTunnelState,
};
use nelomai_client_tunnel::{
    redundancy::{
        protocol::{Command, Member},
        session::SessionPhase,
        SessionScope, Slot,
    },
    DesktopTunnelOptions, TunnelConfiguration, TunnelTransport,
};
use nelomai_contracts::{HealthProbeKind, RedundantHealthProbe, RuntimeSlot};
use std::{
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, WaitForSingleObject,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    },
};

// Pair commands must never enter the unused single-tunnel backend.
struct SingleStopped;
impl ServiceTunnelBackend for SingleStopped {
    fn start(
        &mut self,
        _: &str,
        _: &DesktopTunnelOptions,
        _: TunnelTransport,
    ) -> Result<ServiceTunnelState, ServiceError> {
        panic!("pair entered single Start")
    }
    fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        panic!("pair entered single Stop")
    }
    fn status(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        Ok(ServiceTunnelState::Stopped)
    }
}

#[test]
#[ignore = "requires elevated clean Windows VM and signed worker fixture inputs"]
fn worker_factory_initial_publication_failure_retains_scoped_cleanup() {
    use super::member_files::{MemberFiles, PrivateFile, SessionFileIo};
    let mut pending = Vec::new();
    for (unwind, foreign) in [(false, false), (true, false), (false, true), (true, true)] {
        let fixture = Fixture::new_worker_modules().expect("signed private runtime fixture");
        let mut actor = CompositeBackend::new(
            RuntimeSlot::Latest,
            SingleStopped,
            fixture.worker_factory().unwrap(),
        )
        .unwrap();
        let scope = SessionScope {
            runtime: RuntimeSlot::Latest,
            runtime_generation: 2,
            session_id: format!(
                "7ef40200-0000-4000-8000-{:012x}",
                u64::from(std::process::id()) * 4 + u64::from(unwind) * 2 + u64::from(foreign)
            ),
            connection_generation: 1,
        };
        let command = Command::Start {
                scope: scope.clone(),
                primary: Member {
                    slot: Slot::A,
                    lease_id: "22222222-2222-4222-8222-222222222222".into(),
                    configuration: TunnelConfiguration::new("[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.7.0.2/32\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nAllowedIPs = 198.51.100.0/24\nEndpoint = 192.0.2.1:51820\n".into()),
                    probe: RedundantHealthProbe { kind: HealthProbeKind::DnsA, target_ipv4: "198.51.100.53".parse().unwrap(), query_name: "example.com".into(), timeout_ms: 2000 },
                },
                role_generation: 1,
                membership_generation: 1,
                warm_stop_v1: true,
                options: DesktopTunnelOptions::default(),
        };
        let mut fresh = serde_json::to_value(&command).unwrap();
        fresh["scope"]["connection_generation"] = 2.into();
        fresh["scope"]["session_id"] = "7ef40201-0000-4000-8000-000000000001".into();
        let fresh: Command = serde_json::from_value(fresh).unwrap();
        fresh.validate(RuntimeSlot::Latest).unwrap();
        fixture.lose_ack(PrivateFile::Worker, unwind);
        let start =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| actor.redundant(command)));
        assert!(start.is_err() || start.unwrap().is_err(), "unwind={unwind}");
        fixture
            .verify_files()
            .expect("actual Worker publication fault reached");
        let status = actor
            .redundant(Command::Status {
                scope: scope.clone(),
            })
            .unwrap();
        assert!(status.cleanup_pending);
        assert_ne!(status.session.phase, SessionPhase::Running);
        assert_eq!(status.session.installed, [false, false]);
        let directory = super::member_carrier_factory_test_os::state().unwrap();
        let before: serde_json::Value = serde_json::from_slice(
            &std::fs::read(directory.join("nelomai-redundant-worker.json")).unwrap(),
        )
        .unwrap();
        assert!(before["process"].is_null() && before["interface"].is_null());
        assert!(
            observe_worker().is_err(),
            "child spawned before cold publication ACK"
        );
        assert!(!super::member_carrier_provider::native::table()
            .unwrap()
            .iter()
            .any(|r| r.identity.name.starts_with("NeloWorker-")));
        assert!(
            actor.redundant(fresh).is_err(),
            "fresh pair replaced pending owner"
        );
        let foreign_bytes = if foreign {
            let mut replacement = before.clone();
            replacement["requested_guid"][0] =
                (replacement["requested_guid"][0].as_u64().unwrap() ^ 1).into();
            let bytes = serde_json::to_vec(&replacement).unwrap();
            MemberFiles::new()
                .unwrap()
                .transaction(|files| {
                    let expected = files.read(PrivateFile::Worker)?.unwrap();
                    files.compare_exchange(PrivateFile::Worker, Some(&expected), &bytes)
                })
                .unwrap();
            Some(bytes)
        } else {
            None
        };
        let stop_at = Instant::now();
        let first = actor.redundant(Command::Stop {
            scope: scope.clone(),
        });
        let first_ok = first.is_ok();
        // Retain the same owner on any first-call failure; never replace it.
        let stopped = if first.is_err() {
            actor.redundant(Command::Stop {
                scope: scope.clone(),
            })
        } else {
            first
        };
        let elapsed = stop_at.elapsed();
        eprintln!(
            "worker cold publication unwind={unwind} foreign={foreign} first_ok={first_ok} local Stop={elapsed:?} scoped Stop={stopped:?}"
        );
        assert!(
            elapsed <= Duration::from_secs(7),
            "cold scoped Stop elapsed {elapsed:?}"
        );
        if let Some(bytes) = foreign_bytes {
            assert!(stopped.is_err(), "foreign Worker predecessor terminalized");
            assert!(
                actor
                    .redundant(Command::Status { scope })
                    .unwrap()
                    .cleanup_pending
            );
            assert_eq!(
                std::fs::read(directory.join("nelomai-redundant-worker.json")).unwrap(),
                bytes,
                "cleanup overwrote foreign Worker bytes"
            );
            continue;
        }
        let stopped = match stopped {
            Ok(stopped) => stopped,
            Err(_) => {
                let retained = actor.redundant(Command::Status { scope }).unwrap();
                assert!(retained.cleanup_pending);
                assert_ne!(retained.session.phase, SessionPhase::Running);
                pending.push(unwind);
                continue;
            }
        };
        assert!(
            first_ok,
            "cold scoped Stop required a terminal publication retry"
        );
        assert_eq!(stopped.session.phase, SessionPhase::Stopped);
        assert!(!stopped.cleanup_pending);
        let after: serde_json::Value = serde_json::from_slice(
            &std::fs::read(directory.join("nelomai-redundant-worker.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(after["stopped"], true);
        assert!(after["process"].is_null() && after["interface"].is_null());
        let repeat_at = Instant::now();
        let repeated = actor.redundant(Command::Stop { scope });
        let repeat_elapsed = repeat_at.elapsed();
        eprintln!("worker cold publication unwind={unwind} repeated Stop={repeated:?} elapsed={repeat_elapsed:?}");
        assert!(repeat_elapsed <= Duration::from_secs(7));
        let repeated = repeated.expect("same original completed scope accepts repeated Stop");
        assert_eq!(repeated.session, stopped.session);
        assert!(!repeated.cleanup_pending);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &std::fs::read(directory.join("nelomai-redundant-worker.json")).unwrap()
            )
            .unwrap(),
            after,
            "repeated Stop rewrote terminal Worker state"
        );
    }
    assert!(pending.is_empty(), "same retained cold owner cannot terminalize lost Worker publication ACK: unwind={pending:?}");
}

#[test]
#[ignore = "requires elevated clean Windows VM and NELOMAI_FACTORY_RUNTIME_DIRECTORY with signed fixture inputs"]
fn worker_factory_start_stop_fresh_child_repeat() {
    // This signed fixture contains ONLY service, worker and Wintun. The old
    // C/A/B selector must reject its missing member DLLs before native effects.
    let fixture = Fixture::new_worker_modules().expect("signed private runtime fixture");
    let mut actor = CompositeBackend::new(
        RuntimeSlot::Latest,
        SingleStopped,
        fixture.worker_factory().unwrap(),
    )
    .unwrap();
    // External OS double publishes only UDP endpoints and public keys. Keep
    // crypto and raw DNS inside the actual production worker/actor path.
    let peer_file =
        std::env::var_os("NELOMAI_WORKER_PROOF_PEERS_JSON").expect("external peer ready JSON");
    assert!(std::fs::metadata(&peer_file).unwrap().len() <= 4096);
    let peers: serde_json::Value =
        serde_json::from_slice(&std::fs::read(peer_file).unwrap()).unwrap();
    assert_eq!(
        peers.as_array().unwrap().len(),
        3,
        "three independent external peers"
    );
    let endpoints = [
        peers[0]["endpoint"].as_str().unwrap(),
        peers[1]["endpoint"].as_str().unwrap(),
        peers[2]["endpoint"].as_str().unwrap(),
    ];
    let public = [
        peers[0]["public_key"].as_str().unwrap(),
        peers[1]["public_key"].as_str().unwrap(),
        peers[2]["public_key"].as_str().unwrap(),
    ];
    let mut previous_process = None;
    for round in 0..2 {
        let scope = SessionScope {
            runtime: RuntimeSlot::Latest,
            runtime_generation: 2,
            session_id: format!(
                "7ef40100-0000-4000-8000-{:012x}",
                u64::from(std::process::id()) * 2 + round
            ),
            connection_generation: round + 1,
        };

        let primary = Member { slot: Slot::A, lease_id: format!("22222222-2222-4222-8222-{:012x}", round + 1),
            configuration: TunnelConfiguration::new(format!("[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.7.0.2/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = {}\nAllowedIPs = 198.51.100.0/24\nEndpoint = {}\nPersistentKeepalive = 1\n",public[0],endpoints[0])),
            probe: RedundantHealthProbe { kind: HealthProbeKind::DnsA, target_ipv4: "198.51.100.53".parse().unwrap(), query_name: "example.com".into(), timeout_ms: 2000 } };
        let standby = Member {
            slot: Slot::B,
            lease_id: format!("33333333-3333-4333-8333-{:012x}", round + 1),
            configuration: TunnelConfiguration::new(
                primary
                    .configuration
                    .expose()
                    .replace(
                        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                        "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
                    )
                    .replace(public[0], public[1])
                    .replace(endpoints[0], endpoints[1]),
            ),
            probe: primary.probe.clone(),
        };
        let primary_lease = primary.lease_id.clone();
        let fresh = Member {
            slot: Slot::A,
            lease_id: "44444444-4444-4444-8444-444444444444".into(),
            configuration: TunnelConfiguration::new(
                primary
                    .configuration
                    .expose()
                    .replace(
                        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                        "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=",
                    )
                    .replace(public[0], public[2])
                    .replace(endpoints[0], endpoints[2]),
            ),
            probe: primary.probe.clone(),
        };
        let started = actor.redundant(Command::Start {
            scope: scope.clone(),
            primary,
            role_generation: 1,
            membership_generation: 1,
            warm_stop_v1: true,
            options: DesktopTunnelOptions::default(),
        });
        // Extend the same actual actor route; no direct private Native calls.
        // These configured real Go devices need not be Healthy or handshaken.
        let attached = if round == 0 {
            Some(
                started
                    .as_ref()
                    .map_err(|_| "Start A failed")
                    .and_then(|state| {
                        actor
                            .redundant(Command::Attach {
                                scope: scope.clone(),
                                member: standby,
                                expected_revision: state.session.local_revision,
                                expected_network_epoch: state.session.network_epoch,
                                expected_membership_generation: state.session.membership_generation,
                                membership_generation: state.session.membership_generation + 1,
                            })
                            .map_err(|_| "actual worker factory Attach B failed")
                    }),
            )
        } else {
            None
        };
        let mut readiness = None;
        let mut promotion = None;
        let mut promoted_network = None;
        let mut replacement = None;
        let mut before_network = None;
        if round == 0 && attached.as_ref().is_some_and(|result| result.is_ok()) {
            let clock = Instant::now();
            loop {
                if actor.tick(clock.elapsed().as_millis() as u64).is_err() {
                    break;
                }
                let status = actor.redundant(Command::Status {
                    scope: scope.clone(),
                });
                let ready = status
                    .as_ref()
                    .is_ok_and(|state| state.primary_ready && state.standby_ready);
                readiness = Some(status);
                if ready || clock.elapsed() >= Duration::from_secs(25) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(25)); // actual actor cadence
            }
            if readiness.as_ref().is_some_and(|result| {
                result
                    .as_ref()
                    .is_ok_and(|state| state.primary_ready && state.standby_ready)
            }) {
                before_network =
                    super::member_carrier_factory_test_os::state().and_then(|directory| {
                        let value: serde_json::Value = serde_json::from_slice(
                            &std::fs::read(directory.join("nelomai-redundant-worker.json")).ok()?,
                        )
                        .ok()?;
                        let identity =
                            serde_json::from_value::<crate::member_owner::InterfaceProof>(
                                value.get("interface")?.clone(),
                            )
                            .ok()?;
                        let network = serde_json::from_value::<
                            nelomai_client_tunnel::redundancy::network::NetworkJournal,
                        >(value.get("network")?.clone())
                        .ok()?;
                        Some((identity, network))
                    });
                promotion = Some((|| -> std::io::Result<_> {
                    let address = peers[0]["control"]
                        .as_str()
                        .ok_or_else(|| std::io::Error::other("peer control missing"))?
                        .parse::<std::net::SocketAddr>()
                        .map_err(std::io::Error::other)?;
                    let token = peers[0]["token"]
                        .as_str()
                        .ok_or_else(|| std::io::Error::other("peer token missing"))?;
                    let control = std::net::UdpSocket::bind("0.0.0.0:0")?;
                    control.connect(address)?;
                    control.set_read_timeout(Some(Duration::from_secs(2)))?;
                    control.send(format!("close-a:{token}").as_bytes())?;
                    let mut reply = [0u8; 128];
                    let n = control.recv(&mut reply)?;
                    if &reply[..n] != format!("closed-a:{token}").as_bytes() {
                        return Err(std::io::Error::other("peer close ACK mismatch"));
                    }
                    let failed_at = clock.elapsed();
                    loop {
                        actor
                            .tick(clock.elapsed().as_millis() as u64)
                            .map_err(|_| std::io::Error::other("promotion tick failed"))?;
                        let status = actor
                            .redundant(Command::Status {
                                scope: scope.clone(),
                            })
                            .map_err(|_| std::io::Error::other("promotion status failed"))?;
                        if status.session.active == Slot::B && status.primary_ready {
                            return Ok(status);
                        }
                        if clock.elapsed().saturating_sub(failed_at) >= Duration::from_secs(15) {
                            return Err(std::io::Error::other("genuine B promotion deadline"));
                        }
                        std::thread::sleep(Duration::from_millis(25));
                    }
                })());
                replacement = Some((|| -> std::io::Result<_> {
                    let promoted = promotion
                        .as_ref()
                        .unwrap()
                        .as_ref()
                        .map_err(|_| std::io::Error::other("promotion failed"))?;
                    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(
                        super::member_carrier_factory_test_os::state()
                            .ok_or_else(|| std::io::Error::other("private state missing"))?
                            .join("nelomai-redundant-worker.json"),
                    )?)?;
                    promoted_network = Some((
                        serde_json::from_value::<crate::member_owner::InterfaceProof>(
                            value["interface"].clone(),
                        )?,
                        serde_json::from_value::<
                            nelomai_client_tunnel::redundancy::network::NetworkJournal,
                        >(value["network"].clone())?,
                    ));
                    let active_lease = promoted.current_leases[1]
                        .clone()
                        .ok_or_else(|| std::io::Error::other("current B lease missing"))?;
                    let confirmed = actor
                        .redundant(Command::ConfirmRole {
                            scope: scope.clone(),
                            expected_revision: promoted.session.local_revision,
                            expected_network_epoch: promoted.session.network_epoch,
                            response: nelomai_contracts::RedundantRoleResponse {
                                api_version: nelomai_contracts::ApiVersion::V1,
                                request_id: "worker-fixture-role".into(),
                                action: nelomai_contracts::RedundantRoleAction::Accepted,
                                local_active_lease_id: active_lease.clone(),
                                session: nelomai_contracts::RedundantSessionView {
                                    session_id: scope.session_id.clone(),
                                    state: nelomai_contracts::RedundantSessionState::Connected,
                                    active_lease_id: Some(active_lease),
                                    slot_a_lease_id: promoted.current_leases[0].clone(),
                                    slot_b_lease_id: promoted.current_leases[1].clone(),
                                    standby_desired: true,
                                    role_generation: promoted.session.role_generation + 1,
                                    membership_generation: promoted.session.membership_generation,
                                    reason: None,
                                },
                            },
                        })
                        .map_err(|_| std::io::Error::other("canonical B role ACK failed"))?;
                    if !confirmed.session.role_confirmed {
                        return Err(std::io::Error::other("role remained unconfirmed"));
                    }
                    let retired = actor
                        .redundant(Command::RetireInactive {
                            scope: scope.clone(),
                            slot: Slot::A,
                            lease_id: primary_lease,
                            expected_revision: confirmed.session.local_revision,
                            expected_network_epoch: confirmed.session.network_epoch,
                            expected_membership_generation: confirmed.session.membership_generation,
                        })
                        .map_err(|_| std::io::Error::other("actual inactive retirement failed"))?;
                    if retired.session.active != Slot::B
                        || retired.session.installed != [false, true]
                        || !retired.primary_ready
                    {
                        return Err(std::io::Error::other("retirement interrupted active B"));
                    }
                    let staged = actor
                        .redundant(Command::StageCandidate {
                            scope: scope.clone(),
                            member: fresh,
                            expected_revision: retired.session.local_revision,
                            expected_network_epoch: retired.session.network_epoch,
                            expected_membership_generation: retired.session.membership_generation,
                        })
                        .map_err(|_| {
                            std::io::Error::other("actual fresh candidate attach failed")
                        })?;
                    let staged_at = clock.elapsed();
                    let ready = loop {
                        actor
                            .tick(clock.elapsed().as_millis() as u64)
                            .map_err(|_| {
                                std::io::Error::other("fresh candidate health tick failed")
                            })?;
                        let status = actor
                            .redundant(Command::Status {
                                scope: scope.clone(),
                            })
                            .map_err(|_| std::io::Error::other("fresh candidate status failed"))?;
                        if status.primary_ready && status.standby_ready {
                            break status;
                        }
                        if clock.elapsed().saturating_sub(staged_at) >= Duration::from_secs(25) {
                            return Err(std::io::Error::other(
                                "authentic fresh A readiness deadline",
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(25));
                    };
                    if ready.session.active != Slot::B
                        || ready.session.committed != [false, true]
                        || ready.session.membership_generation
                            != staged.session.membership_generation
                    {
                        return Err(std::io::Error::other(
                            "candidate health changed role/membership",
                        ));
                    }
                    actor
                        .redundant(Command::CommitCandidate {
                            scope: scope.clone(),
                            slot: Slot::A,
                            expected_revision: ready.session.local_revision,
                            expected_network_epoch: ready.session.network_epoch,
                            session: nelomai_contracts::RedundantSessionView {
                                session_id: scope.session_id.clone(),
                                state: nelomai_contracts::RedundantSessionState::Connected,
                                active_lease_id: ready.current_leases[1].clone(),
                                slot_a_lease_id: ready.leases[0].clone(),
                                slot_b_lease_id: ready.current_leases[1].clone(),
                                standby_desired: true,
                                role_generation: ready.session.role_generation,
                                membership_generation: ready.session.membership_generation + 1,
                                reason: None,
                            },
                        })
                        .map_err(|_| {
                            std::io::Error::other("canonical healthy candidate commit failed")
                        })
                })());
            }
        }
        let during = super::member_carrier_provider::native::table().unwrap();
        let retained = super::member_carrier_factory_test_os::state().and_then(|directory| {
            let value: serde_json::Value = serde_json::from_slice(
                &std::fs::read(directory.join("nelomai-redundant-worker.json")).ok()?,
            )
            .ok()?;
            let identity = serde_json::from_value::<crate::member_owner::InterfaceProof>(
                value.get("interface")?.clone(),
            )
            .ok()?;
            let network = serde_json::from_value::<
                nelomai_client_tunnel::redundancy::network::NetworkJournal,
            >(value.get("network")?.clone())
            .ok()?;
            Some((identity, network))
        });
        // Read-only independent observer. This HANDLE cannot authorize cleanup;
        // production retains its OWN original Child HANDLE from process creation.
        let observed = observe_worker();
        // Always attempt the actual scoped cleanup before asserting a red Start.
        let stop_at = Instant::now();
        let stopped = actor.redundant(Command::Stop {
            scope: scope.clone(),
        });
        let elapsed = stop_at.elapsed();
        eprintln!("worker factory round={round} local Stop={elapsed:?}");
        let after = super::member_carrier_provider::native::table().unwrap();
        let started = started.expect("actual worker factory Start A");
        let stopped = stopped.expect("actual worker factory Stop");
        assert!(
            elapsed <= Duration::from_secs(7),
            "local Stop elapsed {elapsed:?}"
        );
        assert_eq!(started.session.phase, SessionPhase::Running);
        assert_eq!(stopped.session.phase, SessionPhase::Stopped);
        assert!(!stopped.cleanup_pending);
        if let Some(attached) = attached {
            let attached = attached.expect("actual worker factory Attach B");
            assert_eq!(attached.session.phase, SessionPhase::Running);
            assert_eq!(attached.session.active, Slot::A);
            assert_eq!(attached.session.installed, [true, true]);
            assert_eq!(attached.session.membership_generation, 2);
        }
        if round == 0 {
            let readiness = readiness
                .expect("health/probe tick completed")
                .expect("production actor health tick");
            assert!(
                readiness.primary_ready && readiness.standby_ready,
                "missing authentic per-slot sample/raw DNS readiness"
            );
            assert_eq!(readiness.session.active, Slot::A);
            let promotion = promotion
                .expect("external A outage after readiness")
                .expect("production actor promoted B");
            assert_eq!(promotion.session.active, Slot::B);
            assert!(promotion.primary_ready);
            assert_eq!(promotion.session.installed, [true, true]);
            assert!(!promotion.cleanup_pending);
            let replacement = replacement
                .expect("retirement and replacement attempted")
                .expect("actual fresh candidate behind original TUN");
            assert_eq!(replacement.session.active, Slot::B);
            assert_eq!(replacement.session.installed, [true, true]);
            assert_eq!(replacement.session.committed, [true, true]);
            assert_eq!(replacement.session.membership_generation, 3);
            assert_eq!(
                replacement.current_leases[0].as_deref(),
                Some("44444444-4444-4444-8444-444444444444")
            );
            assert!(replacement.primary_ready);
            assert!(replacement.standby_ready);
            assert!(!replacement.cleanup_pending);
        }
        let (identity, network) = retained.expect("original worker interface/network");
        let network = network.read_view().unwrap();
        assert!(network.pending().is_none());
        assert_eq!(
            network.recorded_active(),
            Some(if round == 0 { Slot::B } else { Slot::A })
        );
        if round == 0 {
            let (before_identity, before) =
                before_network.expect("exact pre-promotion interface/network facts");
            let (promoted_identity, promoted) =
                promoted_network.expect("exact post-promotion facts before retirement");
            assert_eq!(
                promoted_identity, before_identity,
                "promotion replaced original GUID/LUID/index"
            );
            assert_eq!(
                identity, promoted_identity,
                "replacement changed original TUN"
            );
            let before = before.read_view().unwrap();
            let promoted = promoted.read_view().unwrap();
            assert_eq!(
                serde_json::to_vec(&promoted.current().collect::<Vec<_>>()).unwrap(),
                serde_json::to_vec(&before.current().collect::<Vec<_>>()).unwrap(),
                "promotion mutated exact route bytes"
            );
        }
        let endpoints =
            endpoints.map(|endpoint| endpoint.parse::<std::net::SocketAddr>().unwrap().ip());
        let mut expected_routes = vec![
            ipnet::IpNet::from(endpoints[0]),
            "198.51.100.0/24".parse().unwrap(),
        ];
        if round == 0 {
            expected_routes.push(ipnet::IpNet::from(endpoints[1]));
        }
        for destination in expected_routes {
            assert!(network.current().any(|value| matches!(value, nelomai_client_tunnel::redundancy::network::NetworkValue::Route(route) if route.destination==destination)), "original owned route disappeared: {destination}");
        }
        assert_eq!(
            during
                .iter()
                .filter(|row| row.identity.guid == identity.guid
                    && row.identity.luid == identity.luid
                    && row.identity.index == identity.index)
                .count(),
            1,
            "one independently matched real TUN"
        );
        assert!(
            after.iter().all(|row| row.identity.guid != identity.guid
                && row.identity.luid != identity.luid
                && row.identity.index != identity.index),
            "original exact GUID/LUID/index remained or was reused"
        );
        let (pid, process) =
            observed.expect("signed worker child was not selected by actual factory");
        assert_eq!(
            unsafe { WaitForSingleObject(process.as_raw_handle(), 0) },
            WAIT_OBJECT_0,
            "Stop ACK preceded original process exit"
        );
        assert_ne!(
            previous_process.as_ref().map(|(pid, _handle)| *pid),
            Some(pid),
            "repeat reused the old worker process"
        );
        previous_process = Some((pid, process));
    }
}

fn observe_worker() -> std::io::Result<(u32, OwnedHandle)> {
    let directory = super::member_carrier_factory_test_os::state()
        .ok_or_else(|| std::io::Error::other("fixture state absent"))?;
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(
        directory.join("nelomai-redundant-worker.json"),
    )?)?;
    let pid = value
        .get("process")
        .and_then(|p| p.get("pid"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid != 0)
        .ok_or_else(|| std::io::Error::other("worker process missing"))?;
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let process = unsafe { OwnedHandle::from_raw_handle(handle) };
    let mut image = vec![0u16; 32768];
    let mut length = image.len() as u32;
    if unsafe {
        QueryFullProcessImageNameW(process.as_raw_handle(), 0, image.as_mut_ptr(), &mut length)
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let image = String::from_utf16(&image[..length as usize]).map_err(std::io::Error::other)?;
    let expected = super::member_carrier_factory_test_os::executable()
        .ok_or_else(|| std::io::Error::other("fixture executable absent"))?
        .with_file_name("nelomai-windows-worker.exe");
    if std::fs::canonicalize(&image)? != std::fs::canonicalize(&expected)?
        || unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } != WAIT_TIMEOUT
    {
        return Err(std::io::Error::other(
            "worker image or live HANDLE mismatch",
        ));
    }
    Ok((pid, process))
}
