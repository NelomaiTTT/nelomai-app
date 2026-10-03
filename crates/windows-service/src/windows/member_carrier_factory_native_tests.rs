//! Native entry execution, with external source/file ACK fixtures only.
use super::*;
use crate::{
    member_actor::PairFactory,
    windows::{
        member_carrier_factory_test_os::Fixture, member_files::PrivateFile,
        member_pair::NativePairFactory,
    },
};
use nelomai_client_tunnel::{
    redundancy::{
        protocol::{Command, Member},
        Slot,
    },
    DesktopTunnelOptions, TunnelConfiguration,
};
use nelomai_contracts::{HealthProbeKind, RedundantHealthProbe, RuntimeSlot};

#[test]
fn carrier_factory_selects_new_path_for_supported_pair() {
    // Each unknown publication retains the original process KeyLock. Run each
    // case in its OWN child; process exit is not a synthesized cleanup receipt.
    // libtest names start at the crate's modules; module_path! includes the
    // crate name. Retain the exact single-child count check below.
    let child_module = module_path!()
        .split_once("::")
        .expect("crate-qualified module")
        .1;
    let child_test = format!("{child_module}::carrier_factory_actual_cold_child");
    // Two Stop lifecycles each persist twelve stages, with independent
    // preflight/effect/postflight native reads plus final retirement. The
    // whole-case aperture must span these calls, not truncate the fourth stage.
    // Every individual call still has the production 30s watchdog; this bound
    // only terminates this fixture's OWN child and never attests cleanup.
    let case_budget =
        std::time::Duration::from_millis(crate::member_native_deadline::HARD_BUDGET_MS * 96);
    for case in [
        "cold",
        "primary-data-denial",
        "creator-ack",
        "initial-native-ack",
        "initial-native-unwind",
        "fresh-ack",
        "starting-ack",
    ] {
        // The case spans preparation, many independently supervised cleanup
        // calls and a second session. This outer bound is not a native Calling
        // budget: every actual call keeps its unchanged 30s watchdog. Owned
        // files also prevent a full pipe from blocking the child before exit.
        let output_dir = tempfile::tempdir().unwrap();
        let stdout_path = output_dir.path().join("stdout");
        let stderr_path = output_dir.path().join("stderr");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &child_test,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("NELOMAI_FACTORY_OS_CASE", case)
            .stdout(std::fs::File::create(&stdout_path).unwrap())
            .stderr(std::fs::File::create(&stderr_path).unwrap())
            .spawn()
            .unwrap();
        let started = std::time::Instant::now();
        let (status, timed_out) = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break (status, false);
            }
            if started.elapsed() > case_budget {
                child.kill().unwrap();
                break (child.wait().unwrap(), true);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        let stdout = std::fs::read_to_string(stdout_path).unwrap();
        let stderr = std::fs::read_to_string(stderr_path).unwrap();
        assert!(
            !timed_out,
            "actual native factory {case} exceeded whole-case {case_budget:?}: {stdout} {stderr}"
        );
        assert!(
            status.success(),
            "actual native factory {case} status={status}: {stdout} {stderr}"
        );
        assert!(
            stdout.contains("1 passed; 0 failed"),
            "empty child selection at {case}"
        );
    }
}

#[test]
#[ignore = "executed exactly by the bounded native factory parent, one OS case per process"]
fn carrier_factory_actual_cold_child() {
    let case = std::env::var("NELOMAI_FACTORY_OS_CASE").expect("bounded factory parent required");
    let fixture = Fixture::new().expect("external signed/private fixture");
    let mut factory: NativePairFactory<NativeSessionFiles> = fixture.factory().unwrap();
    let scope = SessionScope {
        runtime: RuntimeSlot::Latest,
        runtime_generation: 2,
        session_id: "11111111-1111-4111-8111-111111111111".into(),
        connection_generation: 3,
    };
    let primary = Member { slot: Slot::A, lease_id: "22222222-2222-4222-8222-222222222222".into(),
        configuration: TunnelConfiguration::new("[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.7.0.2/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.11:51820\nPersistentKeepalive = 25\n".into()),
        probe: RedundantHealthProbe { kind: HealthProbeKind::DnsA, target_ipv4: "1.1.1.1".parse().unwrap(), query_name: "example.com".into(), timeout_ms: 2000 } };
    let mut command = Command::Start {
        scope: scope.clone(),
        primary,
        role_generation: 1,
        membership_generation: 1,
        warm_stop_v1: true,
        options: DesktopTunnelOptions::default(),
    };
    match case.as_str() {
        "cold" | "primary-data-denial" => (),
        "creator-ack" => fixture.lose_ack(PrivateFile::NativeCreator, false),
        "initial-native-ack" => fixture.lose_ack(PrivateFile::NativeCarrierReceipts, false),
        "initial-native-unwind" => fixture.lose_ack(PrivateFile::NativeCarrierReceipts, true),
        "fresh-ack" => fixture.lose_ack(PrivateFile::Pair, false),
        "starting-ack" => fixture.lose_ack(PrivateFile::Session, false),
        _ => panic!("unknown bounded case"),
    }
    let mut retained = None;
    eprintln!("actual factory {case}: prepare_retained_into");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        factory.prepare_retained_into(&mut retained, RuntimeSlot::Latest, &command, 7)
    }));
    if matches!(case.as_str(), "cold" | "primary-data-denial") {
        result
            .expect("actual cold prepare unwound")
            .expect("actual cold factory preparation");
    } else {
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "external ACK did not fault at {case}"
        );
    }
    let mut original = retained.expect("factory lost its actual SessionControl before DLL");
    assert_eq!(original.snapshot().session.scope, scope);
    assert_eq!(original.snapshot().session.phase, SessionPhase::Starting);
    eprintln!("actual factory {case}: retained Starting");
    fixture.verify_files().unwrap();
    if case == "primary-data-denial" {
        let Command::Start {
            primary, options, ..
        } = &command
        else {
            unreachable!()
        };
        assert!(
            original.start_primary(primary, options).is_err(),
            "signed DATA must not become an executable carrier package"
        );
        fixture.require_package_source_read();
        assert!(original.snapshot().cleanup_pending);
    }
    eprintln!("actual factory {case}: original Stop");
    let stopped = original.execute(
        Command::Stop {
            scope: scope.clone(),
        },
        8,
    );
    if stopped.is_err() {
        fixture.trace_pair_stage();
    }
    if matches!(case.as_str(), "cold" | "primary-data-denial") {
        let stopped = stopped.expect("actual prepared-before-DLL native Stop");
        assert_eq!(stopped.session.phase, SessionPhase::Stopped);
        assert!(!stopped.cleanup_pending);
        // CompositeBackend drops its terminal previous control before calling
        // this factory for the next session. Exercise that production order.
        drop(original);
        // SAME factory, real new Startup and KeyLock after exact old completion.
        // There is no process module anchor yet: full primary/pin acceptance is
        // a later scenario, never inferred from this before-DLL repeat.
        let Command::Start { scope: next, .. } = &mut command else {
            unreachable!()
        };
        next.session_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into();
        next.connection_generation += 1;
        let next = next.clone();
        eprintln!("actual factory {case}: repeat prepare");
        let mut second = factory
            .prepare(RuntimeSlot::Latest, &command, 9)
            .expect("actual before-DLL repeat factory preparation");
        eprintln!("actual factory {case}: repeat Stop");
        let stopped = second
            .execute(Command::Stop { scope: next }, 10)
            .expect("actual before-DLL repeat native Stop");
        assert_eq!(stopped.session.phase, SessionPhase::Stopped);
        assert!(!stopped.cleanup_pending);
    } else {
        match stopped {
            Ok(snapshot) => {
                assert_eq!(snapshot.session.phase, SessionPhase::Stopped);
                assert!(!snapshot.cleanup_pending);
            }
            Err(_) => {
                assert!(original.snapshot().cleanup_pending);
                // Unknown native/record ACK remains with the original owner.
                // Process exit is not an invented successful disposition.
                std::mem::forget(original);
                std::mem::forget(factory);
            }
        }
    }
}
