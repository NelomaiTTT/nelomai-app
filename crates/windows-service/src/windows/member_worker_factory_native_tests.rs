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
    Foundation::{FILETIME, WAIT_OBJECT_0, WAIT_TIMEOUT},
    NetworkManagement::IpHelper::{
        GetIpInterfaceEntry, InitializeIpInterfaceEntry, MIB_IPINTERFACE_ROW,
    },
    Networking::WinSock::AF_INET,
    System::Threading::{
        GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, WaitForSingleObject,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    },
};

// One-shot interruption of the external cleanup/pipe boundary. Native effects
// still use the production actor, original worker and retained OS handles.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum StopFault {
    RoutesCleanup,
    StopReply,
    GuardWithdrawal,
}
thread_local! {
    pub(crate) static STOP_FAULT: std::cell::Cell<Option<StopFault>> = const { std::cell::Cell::new(None) };
}

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
    for (case, (unwind, foreign, closing_unwind)) in [
        (false, false, None),
        (true, false, None),
        (false, true, None),
        (true, true, None),
        (false, false, Some(false)),
        (true, false, Some(true)),
    ]
    .into_iter()
    .enumerate()
    {
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
                u64::from(std::process::id()) * 8 + case as u64
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
            observe_worker(None).is_err(),
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
        if let Some(unwind) = closing_unwind {
            fixture.lose_ack(PrivateFile::Worker, unwind);
        }
        let stop_at = Instant::now();
        let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            actor.redundant(Command::Stop {
                scope: scope.clone(),
            })
        }));
        let first_ok = first.as_ref().is_ok_and(|result| result.is_ok());
        if closing_unwind.is_some() {
            assert!(!first_ok, "Closing publication ACK fault was ignored");
            fixture
                .verify_files()
                .expect("actual Closing publication fault reached");
            let closing: serde_json::Value = serde_json::from_slice(
                &std::fs::read(directory.join("nelomai-redundant-worker.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(closing["closing"], true);
            assert_eq!(closing["stopped"], false);
        }
        // Retain the same owner on any first-call failure; never replace it.
        let stopped = match first {
            Ok(result) if result.is_ok() => result,
            _ => actor.redundant(Command::Stop {
                scope: scope.clone(),
            }),
        };
        let elapsed = stop_at.elapsed();
        eprintln!(
            "worker cold publication unwind={unwind} foreign={foreign} closing_unwind={closing_unwind:?} first_ok={first_ok} local Stop={elapsed:?} scoped Stop={stopped:?}"
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
                pending.push((unwind, closing_unwind));
                continue;
            }
        };
        if closing_unwind.is_none() {
            assert!(
                first_ok,
                "cold scoped Stop required a terminal publication retry"
            );
        }
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
    let crash = std::env::var("NELOMAI_WORKER_ENGINE_CRASH").ok();
    assert!(
        crash.as_deref().is_none_or(|value| value == "1"),
        "unknown crash scenario"
    );
    let role = std::env::var("NELOMAI_WORKER_ENGINE_CRASH_ROLE").ok();
    assert!(
        role.as_deref()
            .is_none_or(|value| crash.is_some() && ["engine", "recover"].contains(&value)),
        "unknown crash role"
    );
    if crash.is_some() && role.is_none() {
        // Parent retains the actual original engine Child HANDLE. Killing it
        // executes no Rust Drop/Stop and releases its real KILL_ON_JOB_CLOSE Job.
        let output = tempfile::tempdir().unwrap();
        let ready = output.path().join("ready.json");
        let test_exe = std::env::current_exe().unwrap();
        let child_test = format!(
            "{}::worker_factory_start_stop_fresh_child_repeat",
            module_path!().split_once("::").unwrap().1
        );
        let stdout = output.path().join("engine.stdout");
        let stderr = output.path().join("engine.stderr");
        let mut engine = std::process::Command::new(&test_exe)
            .args([
                "--exact",
                &child_test,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("NELOMAI_WORKER_ENGINE_CRASH_ROLE", "engine")
            .env("NELOMAI_WORKER_ENGINE_CRASH_READY", &ready)
            .env_remove("NELOMAI_WORKER_ENGINE_CRASH_ROOT")
            .stdout(std::fs::File::create(&stdout).unwrap())
            .stderr(std::fs::File::create(&stderr).unwrap())
            .spawn()
            .unwrap();
        let clock = Instant::now();
        while !ready.is_file() {
            if engine.try_wait().unwrap().is_some() || clock.elapsed() > Duration::from_secs(30) {
                let _ = engine.kill();
                let _ = engine.wait();
                eprintln!(
                    "engine readiness stdout={} stderr={}",
                    std::fs::read_to_string(&stdout).unwrap(),
                    std::fs::read_to_string(&stderr).unwrap()
                );
                panic!("actual engine did not durably reach Running");
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(std::fs::metadata(&ready).unwrap().len() <= 16384);
        let ready: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&ready).unwrap()).unwrap();
        let root = std::path::PathBuf::from(ready["root"].as_str().unwrap());
        let executable = std::path::PathBuf::from(ready["executable"].as_str().unwrap());
        let state = root.parent().unwrap().join("state");
        let worker = observe_worker(Some((&state, &executable)))
            .expect("independent original live worker observer");
        assert_eq!(
            unsafe { WaitForSingleObject(engine.as_raw_handle(), 0) },
            WAIT_TIMEOUT
        );
        engine
            .kill()
            .expect("terminate only our original engine Child");
        let engine_status = engine.wait().unwrap();
        assert_eq!(
            unsafe { WaitForSingleObject(engine.as_raw_handle(), 0) },
            WAIT_OBJECT_0
        );
        let worker_wait = unsafe { WaitForSingleObject(worker.1.as_raw_handle(), 7000) };
        assert_eq!(
            worker_wait, WAIT_OBJECT_0,
            "original Job did not stop original worker after engine death"
        );
        let worker_pid = worker.0;
        // Production engine death drops every original worker process HANDLE.
        // Release this test-only observer only after actual original exit proof;
        // keep the separate original engine Child/HANDLE through recovery.
        drop(worker);
        let worker_json: serde_json::Value = serde_json::from_slice(
            &std::fs::read(state.join("nelomai-redundant-worker.json")).unwrap(),
        )
        .unwrap();
        let network: nelomai_client_tunnel::redundancy::network::NetworkJournal =
            serde_json::from_value(worker_json["network"].clone()).unwrap();
        for value in network.read_view().unwrap().current() {
            if let nelomai_client_tunnel::redundancy::network::NetworkValue::Route(route) = value {
                let rows = crate::member_routes::RowIo::read(
                    &mut super::member_routes::NativeRowIo,
                    route.destination,
                    route.interface,
                );
                eprintln!("after engine death addressed native route={route:?} rows={rows:?}");
            }
        }
        let interface: crate::member_owner::InterfaceProof =
            serde_json::from_value(worker_json["interface"].clone()).unwrap();
        let rows = super::member_carrier_provider::native::table().unwrap();
        let exact_rows = rows
            .iter()
            .filter(|row| {
                row.identity.guid == interface.guid
                    || row.identity.index == interface.index
                    || row.identity.luid == interface.luid
            })
            .collect::<Vec<_>>();
        let scope: SessionScope = serde_json::from_value(worker_json["scope"].clone()).unwrap();
        let guard_absent = super::member_worker_guard::Guard::open(
            crate::member_worker_guard::Model::empty(scope.clone()),
        )
        .and_then(|mut guard| guard.close(false, None));
        eprintln!("actual engine crash engine_pid={} engine_status={engine_status:?} worker_pid={} worker_wait={worker_wait} Worker={worker_json} exact_MIB={exact_rows:?} WFP_absence={guard_absent:?}", engine.id(), worker_pid);
        eprintln!(
            "engine stdout={} stderr={}",
            std::fs::read_to_string(&stdout).unwrap(),
            std::fs::read_to_string(&stderr).unwrap()
        );
        let stdout = output.path().join("recover.stdout");
        let stderr = output.path().join("recover.stderr");
        let mut recovery = std::process::Command::new(&test_exe)
            .args([
                "--exact",
                &child_test,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("NELOMAI_WORKER_ENGINE_CRASH_ROLE", "recover")
            .env("NELOMAI_WORKER_ENGINE_CRASH_ROOT", &root)
            .env("NELOMAI_WORKER_ENGINE_CRASH_TEST_EXE", &test_exe)
            .env(
                "NELOMAI_WORKER_ENGINE_CRASH_ENGINE_PID",
                engine.id().to_string(),
            )
            .stdout(std::fs::File::create(&stdout).unwrap())
            .stderr(std::fs::File::create(&stderr).unwrap())
            .spawn()
            .unwrap();
        let status = loop {
            if let Some(status) = recovery.try_wait().unwrap() {
                break status;
            }
            if clock.elapsed() > Duration::from_secs(85) {
                recovery.kill().unwrap();
                break recovery.wait().unwrap();
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        eprintln!(
            "fresh factory recovery status={status:?} elapsed={:?} stdout={} stderr={}",
            clock.elapsed(),
            std::fs::read_to_string(&stdout).unwrap(),
            std::fs::read_to_string(&stderr).unwrap()
        );
        let after: serde_json::Value = serde_json::from_slice(
            &std::fs::read(state.join("nelomai-redundant-worker.json")).unwrap(),
        )
        .unwrap();
        eprintln!(
            "after fresh process Worker={after} MIB={:?}",
            super::member_carrier_provider::native::table().unwrap()
        );
        assert!(
            status.success(),
            "fresh process cannot recover engine crash and complete fresh Start/Stop/repeat"
        );
        assert_eq!(after["stopped"], true);
        assert_ne!(after["scope"], worker_json["scope"]);
        assert_ne!(
            after["process"], worker_json["process"],
            "fresh factory reused original process proof"
        );
        assert!(
            super::member_carrier_provider::native::table()
                .unwrap()
                .iter()
                .all(|row| row.identity.guid != interface.guid
                    && row.identity.index != interface.index
                    && row.identity.luid != interface.luid),
            "old exact GUID/LUID/index remained or was reused"
        );
        super::member_worker_guard::Guard::open(crate::member_worker_guard::Model::empty(scope))
            .and_then(|mut guard| guard.close(false, None))
            .expect("old exact WFP scope remained after fresh recovery");
        return;
    }
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
    let rounds = match role.as_deref() {
        Some("engine") => 1..2,
        Some("recover") => 2..4,
        _ => 0..3,
    };
    for round in rounds {
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
            configuration: TunnelConfiguration::new(format!("[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.7.0.2/32\nDNS = 1.1.1.1\nMTU = 1280\nJc = 2\nJmin = 40\nJmax = 80\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\nH1 = 111111\nH2 = 222222\nH3 = 333333\nH4 = 444444\nHeaderProtectionKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nContentPaddingAddition = 0-32\n[Peer]\nPublicKey = {}\nAllowedIPs = 198.51.100.0/24\nEndpoint = {}\nPersistentKeepalive = 1\n",public[0],endpoints[0])),
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
        let start_at = Instant::now();
        let started = actor.redundant(Command::Start {
            scope: scope.clone(),
            primary,
            role_generation: 1,
            membership_generation: 1,
            warm_stop_v1: true,
            options: DesktopTunnelOptions::default(),
        });
        eprintln!("round={round} Start={:?}", start_at.elapsed());
        if role.as_deref() == Some("engine") {
            assert_eq!(
                started.as_ref().expect("actual engine Start").session.phase,
                SessionPhase::Running
            );
            let state = super::member_carrier_factory_test_os::state().unwrap();
            let worker: serde_json::Value = serde_json::from_slice(
                &std::fs::read(state.join("nelomai-redundant-worker.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(worker["guard"]["admitted"], true);
            assert!(!worker["process"].is_null() && !worker["interface"].is_null());
            assert!(!worker["dns"].is_null() && !worker["address"].is_null());
            let network: nelomai_client_tunnel::redundancy::network::NetworkJournal =
                serde_json::from_value(worker["network"].clone()).unwrap();
            assert!(network.read_view().unwrap().current().next().is_some());
            assert_eq!(worker["closing"], false);
            assert_eq!(worker["stopped"], false);
            let ready = serde_json::json!({"root":fixture.original_root(), "executable":super::member_carrier_factory_test_os::executable().unwrap()});
            let path = std::path::PathBuf::from(
                std::env::var_os("NELOMAI_WORKER_ENGINE_CRASH_READY").unwrap(),
            );
            let pending = path.with_extension("pending");
            // Parent observes readiness only after a complete durable publication.
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&pending)
                .unwrap();
            std::io::Write::write_all(&mut file, &serde_json::to_vec(&ready).unwrap()).unwrap();
            file.sync_all().unwrap();
            drop(file);
            std::fs::rename(&pending, &path).unwrap();
            eprintln!("actual engine durable Running Worker={worker}");
            loop {
                std::thread::park();
            }
        }
        // Extend the same actual actor route; no direct private Native calls.
        // These configured real Go devices need not be Healthy or handshaken.
        let starting_metrics = started.as_ref().ok().map(|_| actor.metrics(false));
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
        let mut primary_metrics = None;
        let mut promoted_metrics = None;
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
                // Retain diagnostics failures until AFTER exact scoped cleanup.
                primary_metrics = Some(actor.metrics(false));
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
                if promotion.as_ref().is_some_and(|result| result.is_ok()) {
                    promoted_metrics = Some(actor.metrics(false));
                }
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
        let interface_settings = retained.as_ref().and_then(|(proof, _)| {
            let mut row = MIB_IPINTERFACE_ROW::default();
            unsafe { InitializeIpInterfaceEntry(&mut row) };
            row.Family = AF_INET;
            row.InterfaceIndex = proof.index;
            row.InterfaceLuid.Value = proof.luid;
            (unsafe { GetIpInterfaceEntry(&mut row) } == 0
                && row.InterfaceIndex == proof.index
                && unsafe { row.InterfaceLuid.Value } == proof.luid)
                .then_some((row.NlMtu, row.DadTransmits))
        });
        // Read-only independent observer. This HANDLE cannot authorize cleanup;
        // production retains its OWN original Child HANDLE from process creation.
        let observed = observe_worker(None);
        // Opt-in regression: let the trigger-start service stop naturally while
        // this actual worker owns its TUN. Removing the cleanup wake must then
        // fail the existing bounded Stop and exact interface absence assertions.
        let idle_service = (crash.is_none()
            && matches!(round, 0 | 2)
            && std::env::var("NELOMAI_WORKER_WAIT_NETSETUP_IDLE").as_deref() == Ok("1"))
        .then(|| -> std::io::Result<Duration> {
            use windows_service::service::{ServiceAccess, ServiceState};
            use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
            let manager =
                ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
                    .map_err(std::io::Error::other)?;
            let service = manager
                .open_service("NetSetupSvc", ServiceAccess::QUERY_STATUS)
                .map_err(std::io::Error::other)?;
            let waiting = Instant::now();
            while service
                .query_status()
                .map_err(std::io::Error::other)?
                .current_state
                != ServiceState::Stopped
            {
                if waiting.elapsed() >= Duration::from_secs(300) {
                    return Err(std::io::Error::other("NetSetupSvc natural idle deadline"));
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            eprintln!(
                "NetSetupSvc naturally stopped before worker Stop after {:?}",
                waiting.elapsed()
            );
            Ok(waiting.elapsed())
        });
        // Always attempt the actual scoped cleanup before asserting a red Start.
        let fault = match round {
            0 => StopFault::RoutesCleanup,
            1 => StopFault::StopReply,
            _ => StopFault::GuardWithdrawal,
        };
        STOP_FAULT.with(|value| value.set(Some(fault)));
        let stop_at = Instant::now();
        let interrupted = actor.redundant(Command::Stop {
            scope: scope.clone(),
        });
        let first_elapsed = stop_at.elapsed();
        let interruption_reached = STOP_FAULT.with(|value| value.take().is_none());
        let pending = actor.redundant(Command::Status {
            scope: scope.clone(),
        });
        let first_wait = observed
            .as_ref()
            .ok()
            .map(|(_, process)| unsafe { WaitForSingleObject(process.as_raw_handle(), 0) });
        let repeat_at = Instant::now();
        let stopped = actor.redundant(Command::Stop {
            scope: scope.clone(),
        });
        let elapsed = repeat_at.elapsed();
        let start_failure = started.as_ref().err().map(|error| match error {
            ServiceError::PairOperation(failure) => failure.to_string(),
            _ => error.code().to_owned(),
        });
        assert!(
            interruption_reached,
            "native {fault:?} interruption not reached; Start failure={start_failure:?}"
        );
        assert!(
            interrupted.is_err(),
            "native {fault:?} interruption ACK was ignored"
        );
        let pending = pending.expect("same scope retained after interrupted Stop");
        assert_eq!(pending.session.phase, SessionPhase::Stopping);
        assert!(pending.cleanup_pending);
        assert_eq!(
            first_wait,
            Some(if round == 0 {
                WAIT_TIMEOUT
            } else {
                WAIT_OBJECT_0
            }),
            "original worker lifecycle after {fault:?}"
        );
        assert!(
            first_elapsed <= Duration::from_secs(7),
            "interrupted Stop elapsed {first_elapsed:?}"
        );
        eprintln!("worker factory round={round} local Stop={elapsed:?}");
        let after = super::member_carrier_provider::native::table().unwrap();
        let started = started.expect("actual worker factory Start A");
        let stopped = stopped.expect("actual worker factory Stop");
        if let Some(idle_service) = idle_service {
            idle_service.expect("NetSetupSvc naturally stopped before scoped cleanup");
        }
        assert!(
            elapsed <= Duration::from_secs(7),
            "local Stop elapsed {elapsed:?}"
        );
        assert_eq!(started.session.phase, SessionPhase::Running);
        assert_eq!(
            interface_settings.map(|value| value.0),
            Some(1280),
            "actual owned Windows MTU"
        );
        assert_eq!(
            interface_settings.map(|value| value.1),
            Some(0),
            "actual owned Windows IPv4 DadTransmits"
        );
        assert_eq!(stopped.session.phase, SessionPhase::Stopped);
        assert!(!stopped.cleanup_pending);
        starting_metrics
            .expect("A-only metrics attempted after Start")
            .expect("actual worker A-only metrics");
        assert!(
            actor.metrics(false).is_err(),
            "stopped pair exposed metrics"
        );
        let repeated = actor
            .redundant(Command::Stop {
                scope: scope.clone(),
            })
            .expect("same interrupted scope terminal repeat Stop");
        assert_eq!(repeated.session, stopped.session);
        assert!(!repeated.cleanup_pending);
        if let Some(attached) = attached {
            let attached = attached.expect("actual worker factory Attach B");
            assert_eq!(attached.session.phase, SessionPhase::Running);
            assert_eq!(attached.session.active, Slot::A);
            assert_eq!(attached.session.installed, [true, true]);
            assert_eq!(attached.session.membership_generation, 2);
        }
        if round == 0 {
            let primary_metrics = primary_metrics
                .expect("A metrics attempted before promotion")
                .expect("actual worker A metrics");
            let promoted_metrics = promoted_metrics
                .expect("B metrics attempted after promotion")
                .expect("actual worker B metrics");
            assert!(primary_metrics
                .latest_handshake_epoch_millis
                .is_some_and(|value| value > 0));
            assert!(promoted_metrics
                .latest_handshake_epoch_millis
                .is_some_and(|value| value > 0));
            // One retained TUN: user IP byte totals survive the A -> B switch.
            assert!(promoted_metrics.received_bytes >= primary_metrics.received_bytes);
            assert!(promoted_metrics.sent_bytes >= primary_metrics.sent_bytes);
            assert!(
                primary_metrics.probe_target.is_none() && promoted_metrics.probe_target.is_none()
            );
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
    if crash.is_none() {
        // The default native gate also executes actual engine death and two
        // fresh sessions under a new process using the same protected root.
        let test_exe = std::env::current_exe().unwrap();
        let child_test = format!(
            "{}::worker_factory_start_stop_fresh_child_repeat",
            module_path!().split_once("::").unwrap().1
        );
        let result = std::process::Command::new(test_exe)
            .args([
                "--exact",
                &child_test,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("NELOMAI_WORKER_ENGINE_CRASH", "1")
            .env_remove("NELOMAI_WORKER_ENGINE_CRASH_ROLE")
            .status()
            .unwrap();
        assert!(
            result.success(),
            "default native engine-crash recovery failed"
        );
    }
}

fn observe_worker(
    context: Option<(&std::path::Path, &std::path::Path)>,
) -> std::io::Result<(u32, OwnedHandle)> {
    let directory = context
        .map(|(state, _)| state.to_owned())
        .or_else(super::member_carrier_factory_test_os::state)
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
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    if unsafe {
        GetProcessTimes(
            process.as_raw_handle(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    } == 0
        || value["process"]["creation_time"].as_u64()
            != Some((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    {
        return Err(std::io::Error::other(
            "original worker creation time mismatch",
        ));
    }
    let mut image = vec![0u16; 32768];
    let mut length = image.len() as u32;
    if unsafe {
        QueryFullProcessImageNameW(process.as_raw_handle(), 0, image.as_mut_ptr(), &mut length)
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let image = String::from_utf16(&image[..length as usize]).map_err(std::io::Error::other)?;
    let expected = context
        .map(|(_, executable)| executable.to_owned())
        .or_else(super::member_carrier_factory_test_os::executable)
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
