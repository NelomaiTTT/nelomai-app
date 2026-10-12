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
    let endpoints = [
        peers[0]["endpoint"].as_str().unwrap(),
        peers[1]["endpoint"].as_str().unwrap(),
    ];
    let public = [
        peers[0]["public_key"].as_str().unwrap(),
        peers[1]["public_key"].as_str().unwrap(),
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
        }
        let (identity, network) = retained.expect("original worker interface/network");
        let network = network.read_view().unwrap();
        assert!(network.pending().is_none());
        assert_eq!(network.recorded_active(), Some(Slot::A));
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
            elapsed <= Duration::from_secs(7),
            "local Stop elapsed {elapsed:?}"
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
