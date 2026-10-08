//! Native entry execution, with external source/file ACK fixtures only.
use super::*;
use crate::{
    member_actor::PairFactory,
    member_owner::Journal,
    windows::{
        member_carrier_factory_test_os::{ChildCurrentCheckReport, Fixture, NativePublication},
        member_files::{MemberFiles, PrivateFile},
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
use nelomai_contracts::{
    dispatcher::TunnelSlot, HealthProbeKind, RedundantHealthProbe, RuntimeSlot,
};
use sha2::{Digest, Sha256};

#[test]
fn carrier_factory_selects_new_path_for_supported_pair() {
    // Each unknown publication retains the original process KeyLock. Run each
    // case in its OWN child; process exit is not a synthesized cleanup receipt.
    // libtest names start at the crate's modules; module_path! includes the
    // crate name. Each resolver lane also exercises its distinct adapter
    // reference and pre-create table failure in fresh children. Retain the
    // exact count checks below.
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
    let cases = [
        "primary",
        "network-route-postflight",
        "module-load-read-error",
        "module-load-read-unwind",
        "resolver-reference-error",
        "resolver-reference-unwind",
        "carrier-ack",
        "carrier-unwind",
        "member-ack",
        "member-unwind",
        "running-ack",
        "running-unwind",
        "cold",
        "primary-data-denial",
        "creator-ack",
        "initial-native-ack",
        "initial-native-unwind",
        "fresh-ack",
        "starting-ack",
    ];
    let selected = match std::env::var("NELOMAI_FACTORY_SYSTEM_CASE") {
        Ok(case) => {
            assert!(
                cases.contains(&case.as_str()),
                "unknown native factory case"
            );
            Some(case)
        }
        Err(std::env::VarError::NotPresent) => None,
        Err(_) => panic!("invalid native factory case"),
    };
    let mut completed = 0;
    for case in cases
        .into_iter()
        .filter(|case| selected.as_deref().is_none_or(|selected| *case == selected))
        .flat_map(|case| {
            let partials = match case {
                "resolver-reference-error" => {
                    Some(["adapter-reference-error", "absence-table-error"])
                }
                "resolver-reference-unwind" => {
                    Some(["adapter-reference-unwind", "absence-table-unwind"])
                }
                _ => None,
            };
            std::iter::once(case).chain(partials.into_iter().flatten())
        })
    {
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
        let elapsed = started.elapsed();
        let stdout = std::fs::read_to_string(stdout_path).unwrap();
        let stderr = std::fs::read_to_string(stderr_path).unwrap();
        let runtime_auth = stderr
            .lines()
            .filter(|line| line.contains("runtime begin installed payload authentication"))
            .count();
        let source_auth = stderr
            .lines()
            .filter(|line| line.contains("source begin installed payload authentication"))
            .count();
        let current_check_footers = stderr
            .lines()
            .filter_map(|line| {
                line.strip_prefix(
                    "actual native factory current checks runtime_current_check_attempts=",
                )
            })
            .collect::<Vec<_>>();
        let current_checks = match current_check_footers.as_slice() {
            [footer] => footer
                .split_once(" source_current_check_attempts=")
                .and_then(|(runtime, source)| {
                    Some((runtime.parse::<u64>().ok()?, source.parse::<u64>().ok()?))
                }),
            _ => None,
        };
        let (runtime_current_checks, source_current_checks) = current_checks
            .map(|(runtime, source)| (runtime.to_string(), source.to_string()))
            .unwrap_or_else(|| ("unknown".into(), "unknown".into()));
        let lifetime_rechecks = stderr
            .lines()
            .filter(|line| line.contains("installation lifetime recheck"))
            .count();
        let final_inventory_rechecks = stderr
            .lines()
            .filter(|line| line.contains("installation final inventory recheck"))
            .count();
        println!(
            "actual native factory cost case={case} runtime_full_auth_attempts={runtime_auth} source_full_auth_attempts={source_auth} runtime_current_check_attempts={runtime_current_checks} source_current_check_attempts={source_current_checks} installed_lifetime_recheck_attempts={lifetime_rechecks} installed_final_inventory_recheck_attempts={final_inventory_rechecks} elapsed_ms={}",
            elapsed.as_millis()
        );
        if !timed_out && !status.success() {
            let proofs = stderr
                .lines()
                .filter_map(|line| line.strip_prefix("actual expired Stop comparison_only_proof="))
                .take(2)
                .collect::<Vec<_>>();
            let proof = match proofs.as_slice() {
                [json] if json.len() <= 256 => {
                    serde_json::from_str::<crate::member_owner::InterfaceProof>(json)
                        .ok()
                        .filter(|p| p.guid != [0; 16] && p.luid != 0 && p.index != 0)
                }
                _ => None,
            };
            if let Some(proof) = proof {
                use windows_sys::Win32::NetworkManagement::{
                    IpHelper::{GetIfEntry2, MIB_IF_ROW2},
                    Ndis::NET_LUID_LH,
                };
                println!("actual post-exit comparison case={case} child_pid={} child_process_exited=true static_wfp=unconfirmed guid={:?} luid={} index={}", child.id(), proof.guid, proof.luid, proof.index);
                let observing = std::time::Instant::now();
                for sample in 0..4 {
                    let due = std::time::Duration::from_secs(sample * 5);
                    if let Some(wait) = due.checked_sub(observing.elapsed()) {
                        std::thread::sleep(wait);
                    }
                    if observing.elapsed() >= std::time::Duration::from_secs(20) {
                        break;
                    }
                    let mut row = MIB_IF_ROW2 {
                        InterfaceLuid: NET_LUID_LH { Value: proof.luid },
                        ..Default::default()
                    };
                    let status = unsafe { GetIfEntry2(&mut row) };
                    if status == 0 {
                        let guid = crate::windows::member_carrier_guard::key(row.InterfaceGuid).0;
                        let luid = unsafe { row.InterfaceLuid.Value };
                        let exact = guid == proof.guid
                            && luid == proof.luid
                            && row.InterfaceIndex == proof.index;
                        println!("actual post-exit entry sample={sample} elapsed_ms={} status={status} guid={guid:?} luid={luid} index={} exact={exact} oper_status={} admin_status={} media_connect_state={} flags={:#04x}", observing.elapsed().as_millis(), row.InterfaceIndex, row.OperStatus, row.AdminStatus, row.MediaConnectState, row.InterfaceAndOperStatusFlags._bitfield);
                    } else {
                        println!(
                            "actual post-exit entry sample={sample} elapsed_ms={} status={status}",
                            observing.elapsed().as_millis()
                        );
                    }
                    match crate::windows::member_carrier_provider::native::table() {
                        Ok(rows) => {
                            let mut exact = 0;
                            let mut collisions = 0;
                            for row in rows {
                                let identity = row.identity;
                                if identity.guid == proof.guid
                                    && identity.luid == proof.luid
                                    && identity.index == proof.index
                                {
                                    exact += 1;
                                } else if identity.guid == proof.guid
                                    || identity.luid == proof.luid
                                    || identity.index == proof.index
                                {
                                    collisions += 1;
                                }
                            }
                            println!("actual post-exit rundown sample={sample} elapsed_ms={} exact={exact} collisions={collisions}", observing.elapsed().as_millis());
                        }
                        Err(error) => println!("actual post-exit rundown sample={sample} elapsed_ms={} error={error:?}", observing.elapsed().as_millis()),
                    }
                }
            } else {
                println!("actual post-exit comparison case={case} child_process_exited=true proof=missing_invalid_or_ambiguous static_wfp=unconfirmed");
            }
        }
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
        if case == "absence-table-error" {
            assert!(
                stderr.contains("actual native surviving original key disposition ACK"),
                "surviving original key disposition was not acknowledged: {stderr}"
            );
        }
        if matches!(case, "primary" | "running-ack") {
            let mut completed = 0;
            for after_dns in stderr.split("network DNS cleanup end").skip(1) {
                let (boundary, _) = after_dns
                    .split_once("network routes cleanup begin")
                    .expect("routes must follow completed DNS cleanup");
                assert!(
                    boundary.contains("cleanup Calling authentication completed"),
                    "routes reused the DNS Calling window: {boundary}"
                );
                completed += 1;
            }
            assert!(completed > 0, "missing actual DNS/routes cleanup evidence");
        }
        // Keep meaningful native step/ACK evidence on successful runs as well.
        // Authentication remains real; its repeated timing labels need not
        // obscure the actual lifecycle in the parent output.
        for line in stderr.lines().filter(|line| {
            !line.contains("runtime begin installed payload authentication")
                && !line.contains("runtime end installed payload authentication")
                && !line.contains("source begin installed payload authentication")
                && !line.contains("source end installed payload authentication")
                && !line.starts_with("actual native factory current checks ")
                && !line.contains("installation lifetime recheck")
        }) {
            println!("{line}");
        }
        completed += 1;
    }
    let expected = match selected.as_deref() {
        Some("resolver-reference-error" | "resolver-reference-unwind") => 3,
        Some(_) => 1,
        None => cases.len() + 4,
    };
    assert_eq!(completed, expected);
    println!(
        "actual native factory coverage case={} completed={completed}",
        selected.as_deref().unwrap_or("all")
    );
}

#[test]
#[ignore = "executed exactly by the bounded native factory parent, one OS case per process"]
fn carrier_factory_actual_cold_child() {
    let _current_check_report = ChildCurrentCheckReport::new();
    let case = std::env::var("NELOMAI_FACTORY_OS_CASE").expect("bounded factory parent required");
    let module_partial = matches!(
        case.as_str(),
        "module-load-read-error" | "module-load-read-unwind"
    );
    let full_primary = case == "primary";
    let route_partial = case == "network-route-postflight";
    let resolver_partial = matches!(
        case.as_str(),
        "resolver-reference-error" | "resolver-reference-unwind"
    );
    let absence_partial = matches!(
        case.as_str(),
        "absence-table-error" | "absence-table-unwind"
    );
    let adapter_partial = matches!(
        case.as_str(),
        "adapter-reference-error" | "adapter-reference-unwind"
    );
    let native_partial = match case.as_str() {
        "carrier-ack" => Some((NativePublication::Carrier, false)),
        "carrier-unwind" => Some((NativePublication::Carrier, true)),
        "member-ack" => Some((NativePublication::Member, false)),
        "member-unwind" => Some((NativePublication::Member, true)),
        "running-ack" => Some((NativePublication::Running, false)),
        "running-unwind" => Some((NativePublication::Running, true)),
        _ => None,
    };
    let native_path = module_partial
        || resolver_partial
        || adapter_partial
        || absence_partial
        || full_primary
        || route_partial
        || native_partial.is_some();
    let preparation_succeeds =
        native_path || matches!(case.as_str(), "cold" | "primary-data-denial");
    let fixture = if native_path {
        Fixture::new_native_modules()
    } else {
        Fixture::new()
    }
    .expect("external signed/private fixture");
    let mut factory: NativePairFactory<NativeSessionFiles> = fixture.factory().unwrap();
    // A prior partial child deliberately leaves its original registry keys.
    // Distinct cases and repeat sessions must never reuse those carrier GUIDs.
    let session_ids = [0u8, 1].map(|round| {
        let mut hash = Sha256::new();
        hash.update(b"nelomai-native-factory-test-session/v1\0");
        hash.update(case.as_bytes());
        hash.update([round]);
        let mut bytes: [u8; 16] = hash.finalize()[..16].try_into().unwrap();
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        )
    });
    let scope = SessionScope {
        runtime: RuntimeSlot::Latest,
        runtime_generation: 2,
        session_id: session_ids[0].clone(),
        connection_generation: 3,
    };
    let primary = Member { slot: Slot::A, lease_id: "22222222-2222-4222-8222-222222222222".into(),
        configuration: TunnelConfiguration::new("[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.7.0.2/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nAllowedIPs = 198.51.100.0/24\nEndpoint = 192.0.2.11:51820\nPersistentKeepalive = 25\n".into()),
        probe: RedundantHealthProbe { kind: HealthProbeKind::DnsA, target_ipv4: "198.51.100.53".parse().unwrap(), query_name: "example.com".into(), timeout_ms: 2000 } };
    let mut command = Command::Start {
        scope: scope.clone(),
        primary,
        role_generation: 1,
        membership_generation: 1,
        warm_stop_v1: true,
        options: DesktopTunnelOptions::default(),
    };
    match case.as_str() {
        _ if preparation_succeeds => (),
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
    if let Ok(Err(error)) = &result {
        eprintln!("actual factory {case}: preparation error {error:?}");
    }
    if preparation_succeeds {
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
    if resolver_partial {
        fixture.lose_resolver_reference_postflight(case == "resolver-reference-unwind");
        let Command::Start {
            primary, options, ..
        } = &command
        else {
            unreachable!()
        };
        let started = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            original.start_primary(primary, options)
        }));
        assert!(
            started.is_err() || started.unwrap().is_err(),
            "resolver fault accepted"
        );
        assert!(original.snapshot().cleanup_pending);
        fixture.require_retained_resolver_reference();
        assert!(
            original.start_primary(primary, options).is_err(),
            "uncertain resolver retried"
        );
        fixture.require_retained_resolver_reference();
        let stopped = original.execute(
            Command::Stop {
                scope: scope.clone(),
            },
            8,
        );
        assert!(stopped.is_err(), "uncertain resolver became completed Stop");
        assert!(original.snapshot().cleanup_pending);
        fixture.require_retained_resolver_reference();
        // Process exit is not a completed release or protected retirement ACK.
        std::mem::forget(original);
        std::mem::forget(factory);
        return;
    }
    if adapter_partial || absence_partial {
        let unwind = matches!(
            case.as_str(),
            "adapter-reference-unwind" | "absence-table-unwind"
        );
        fixture.lose_precreate_postflight(unwind, absence_partial);
        let Command::Start {
            primary, options, ..
        } = &command
        else {
            unreachable!()
        };
        let started = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            original.start_primary(primary, options)
        }));
        if unwind {
            assert!(
                started.is_err(),
                "actual pre-create boundary did not unwind"
            );
        } else {
            assert!(
                matches!(started, Ok(Err(_))),
                "actual pre-create error accepted"
            );
        }
        if !absence_partial || original.snapshot().cleanup_pending {
            assert!(original.snapshot().cleanup_pending);
            if !absence_partial || unwind {
                fixture.require_retained_precreate_originals();
            }
            assert!(
                original.start_primary(primary, options).is_err(),
                "failed pre-create boundary retried"
            );
            if !absence_partial || unwind {
                fixture.require_retained_precreate_originals();
            }
        } else {
            assert_eq!(original.snapshot().session.phase, SessionPhase::Stopped);
        }
        let stopped = original.execute(
            Command::Stop {
                scope: scope.clone(),
            },
            8,
        );
        if stopped.is_err() {
            assert!(original.snapshot().cleanup_pending);
            if !absence_partial || unwind {
                fixture.require_retained_precreate_originals();
            }
        }
        if absence_partial && !unwind {
            // No adapter/reference attempt: actual original key/module cleanup
            // must complete; process exit is never a substitute release ACK.
            let stopped = stopped.expect("actual post-key/pre-C Stop completion");
            assert_eq!(stopped.session.phase, SessionPhase::Stopped);
            assert!(!stopped.cleanup_pending);
            let repeated = original
                .execute(Command::Stop { scope }, 8)
                .expect("actual post-key/pre-C repeated Stop");
            assert_eq!(repeated, stopped);
            return;
        }
        assert!(
            stopped.is_err(),
            "uncertain pre-create outcome became completed Stop"
        );
        assert!(original.snapshot().cleanup_pending);
        // An unwind permanently revokes this original supervisor. Retention
        // passes without declaring cleanup complete or replacing its runtime.
        // No adapter CloseACK exists, and process exit supplies no release ACK.
        std::mem::forget(original);
        std::mem::forget(factory);
        return;
    }
    if let Some((target, unwind)) = native_partial {
        fixture.lose_native_publication_ack(target, unwind);
        let Command::Start {
            primary, options, ..
        } = &command
        else {
            unreachable!()
        };
        eprintln!("actual factory {case}: primary through {target:?} publication");
        let started = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            original.start_primary(primary, options)
        }));
        assert!(
            started.is_err() || started.unwrap().is_err(),
            "lost native publication ACK accepted"
        );
        let snapshot = original.snapshot();
        eprintln!(
            "actual native publication fault {target:?} unwind={unwind} phase={:?} cleanup_pending={}",
            snapshot.session.phase, snapshot.cleanup_pending
        );
        // SAME control reaches Stopped only after actual native terminal close;
        // aggregate cleanup_pending can still require a protected Session save.
        fixture.require_native_publication_fault(
            target,
            unwind || snapshot.session.phase != SessionPhase::Stopped,
        );
        if !snapshot.cleanup_pending {
            assert_eq!(
                snapshot.session.phase,
                SessionPhase::Stopped,
                "owner discarded without actual completion"
            );
        }
    }
    if route_partial {
        fixture.lose_route_postflight();
        let Command::Start {
            primary, options, ..
        } = &command
        else {
            unreachable!()
        };
        assert!(
            original.start_primary(primary, options).is_err(),
            "post-create table fault accepted"
        );
        fixture.require_route_postflight_fault();
        let snapshot = original.snapshot();
        assert!(matches!(
            snapshot.session.phase,
            SessionPhase::Stopping | SessionPhase::Stopped
        ));
        if !snapshot.cleanup_pending {
            assert_eq!(snapshot.session.phase, SessionPhase::Stopped);
        }
    }
    if full_primary {
        let Command::Start {
            primary, options, ..
        } = &command
        else {
            unreachable!()
        };
        eprintln!("actual factory {case}: primary Start");
        let started = original.start_primary(primary, options);
        if started.is_err() {
            fixture.trace_pair_stage();
        }
        let running = started.expect("actual native primary Start");
        assert_eq!(running.session.scope, scope);
        assert_eq!(running.session.phase, SessionPhase::Running);
        assert!(!running.cleanup_pending);
        fixture.require_package_source_read();
    }
    if module_partial {
        eprintln!("actual factory {case}: primary through audited module load");
        fixture.lose_inventory_after_load(case == "module-load-read-unwind");
        let Command::Start {
            primary, options, ..
        } = &command
        else {
            unreachable!()
        };
        let started = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            original.start_primary(primary, options)
        }));
        assert!(started.is_err() || started.unwrap().is_err());
        let snapshot = original.snapshot();
        fixture.require_original_load_and_fault(snapshot.cleanup_pending);
        if case == "module-load-read-unwind" {
            assert!(snapshot.cleanup_pending);
        } else if !snapshot.cleanup_pending {
            // start_primary already called the actual original Stop on Err.
            // Only its real native/protected completion may discard the owner.
            assert_eq!(snapshot.session.phase, SessionPhase::Stopped);
        }
    }
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
        let snapshot = original.snapshot();
        if !snapshot.cleanup_pending {
            // A rejected package can finish its actual original Stop before
            // Start returns Err. The retained control must then be terminal;
            // the explicit Stop/repeat preparation below still checks completion.
            assert_eq!(snapshot.session.phase, SessionPhase::Stopped);
        }
    }
    eprintln!("actual factory {case}: original Stop");
    let stop_started = std::time::Instant::now();
    let mut stopped = original.execute(
        Command::Stop {
            scope: scope.clone(),
        },
        8,
    );
    if let Err(error) = &stopped {
        eprintln!("actual factory {case}: Stop error {error:?}");
        fixture.trace_pair_stage();
    }
    if case == "module-load-read-unwind" {
        // Native supervisor permanently revokes uncertain unwind timing.
        // Preserve the actual returned owner; never turn revocation/exit into
        // permission to unload or into successful protected completion.
        assert!(stopped.is_err());
        assert!(original.snapshot().cleanup_pending);
        fixture.require_original_load_and_fault(true);
        std::mem::forget(original);
        std::mem::forget(factory);
        return;
    }
    if matches!(case.as_str(), "cold" | "primary-data-denial")
        || module_partial
        || full_primary
        || route_partial
    {
        let retry_started = std::time::Instant::now();
        while stopped.is_err()
            && original.snapshot().cleanup_pending
            && retry_started.elapsed() <= std::time::Duration::from_secs(30)
        {
            assert_eq!(original.snapshot().session.phase, SessionPhase::Stopping);
            let now = 8 + stop_started.elapsed().as_millis() as u64;
            match original.tick(now) {
                Ok(_) => {
                    let snapshot = original.snapshot();
                    if !snapshot.cleanup_pending {
                        stopped = Ok(snapshot);
                    }
                }
                Err(error) => {
                    eprintln!("actual factory {case}: Stop tick error {error:?}");
                    assert!(original.snapshot().cleanup_pending);
                    fixture.trace_pair_stage();
                    stopped = Err(error);
                }
            }
            if original.snapshot().cleanup_pending {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
        if stopped.is_err() && retry_started.elapsed() > std::time::Duration::from_secs(30) {
            if let Some(record) = fixture
                .trace_pair_stage()
                .filter(|r| r.phase == crate::member_carrier_pair::Phase::Closing)
            {
                let comparison = match record.pending {
                    Some(crate::member_carrier_pair::Effect::CarrierClose)
                        if record.stop_stage == 8 =>
                    {
                        record.carrier.map(|proof| ("C", proof))
                    }
                    Some(crate::member_carrier_pair::Effect::MemberStop(slot))
                        if record.stop_stage == 4 + u8::from(slot == Slot::B) =>
                    {
                        let kind = match slot {
                            Slot::A => "member A",
                            Slot::B => "member B",
                        };
                        record.members[usize::from(slot == Slot::B)]
                            .as_ref()
                            .and_then(|member| member.owner.proof.or(member.owner.retired_proof))
                            .map(|proof| (kind, proof.interface))
                    }
                    _ => None,
                };
                if let Some((kind, proof)) = comparison {
                    eprintln!(
                        "actual expired Stop comparison_only_proof={}",
                        serde_json::to_string(&proof).expect("comparison-only interface proof")
                    );
                    eprintln!("actual expired Stop {kind} observation case={case} pid={} guid={:?} luid={} index={} stop_elapsed_ms={} retry_elapsed_ms={}", std::process::id(), proof.guid, proof.luid, proof.index, stop_started.elapsed().as_millis(), retry_started.elapsed().as_millis());
                    use windows_sys::Win32::{
                        NetworkManagement::{
                            IpHelper::{GetIfEntry2, MIB_IF_ROW2},
                            Ndis::NET_LUID_LH,
                        },
                        System::Registry::{
                            RegCloseKey, RegEnumValueW, RegOpenKeyExW, RegQueryInfoKeyW,
                            HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, REG_OPTION_OPEN_LINK,
                        },
                    };
                    // By-name diagnostic only; the retained original HKEY is unavailable here.
                    let guid = windows_sys::core::GUID::from_u128(u128::from_be_bytes(proof.guid));
                    let path = format!(
                        r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
                        guid.data1, guid.data2, guid.data3,
                        guid.data4[0], guid.data4[1], guid.data4[2], guid.data4[3],
                        guid.data4[4], guid.data4[5], guid.data4[6], guid.data4[7],
                    ).encode_utf16().chain(Some(0)).collect::<Vec<_>>();
                    let mut key = std::ptr::null_mut();
                    let opened = unsafe {
                        RegOpenKeyExW(
                            HKEY_LOCAL_MACHINE,
                            path.as_ptr(),
                            REG_OPTION_OPEN_LINK,
                            KEY_QUERY_VALUE,
                            &mut key,
                        )
                    };
                    let (mut subkeys, mut values) = (0, 0);
                    let mut names = Vec::new();
                    let (mut info, mut closed) = (None, None);
                    if opened == 0 {
                        info = Some(unsafe {
                            RegQueryInfoKeyW(
                                key,
                                std::ptr::null_mut(),
                                std::ptr::null_mut(),
                                std::ptr::null(),
                                &mut subkeys,
                                std::ptr::null_mut(),
                                std::ptr::null_mut(),
                                &mut values,
                                std::ptr::null_mut(),
                                std::ptr::null_mut(),
                                std::ptr::null_mut(),
                                std::ptr::null_mut(),
                            )
                        });
                        if info == Some(0) {
                            for index in 0..values.min(16) {
                                let mut name = [0u16; 512];
                                let mut length = name.len() as u32;
                                let status = unsafe {
                                    RegEnumValueW(
                                        key,
                                        index,
                                        name.as_mut_ptr(),
                                        &mut length,
                                        std::ptr::null(),
                                        std::ptr::null_mut(),
                                        std::ptr::null_mut(),
                                        std::ptr::null_mut(),
                                    )
                                };
                                names.push((index, status, length, name));
                            }
                        }
                        closed = Some(unsafe { RegCloseKey(key) });
                    }
                    eprintln!("actual expired Stop {kind} registry by_name_only=true original_handle=unavailable open_status={opened} info_status={info:?} subkeys={subkeys} values={values} names_truncated={} close_status={closed:?}", values > 16);
                    for (index, status, length, name) in names {
                        let text = if status == 0 && (length as usize) <= name.len() {
                            Some(String::from_utf16_lossy(&name[..length as usize]))
                        } else {
                            None
                        };
                        eprintln!("actual expired Stop {kind} registry value_name index={index} status={status} length={length} name={text:?}");
                    }
                    let observing = std::time::Instant::now();
                    while observing.elapsed() < std::time::Duration::from_secs(60) {
                        let mut row = MIB_IF_ROW2 {
                            InterfaceLuid: NET_LUID_LH { Value: proof.luid },
                            ..Default::default()
                        };
                        let status = unsafe { GetIfEntry2(&mut row) };
                        if status == 0 {
                            let actual_guid =
                                crate::windows::member_carrier_guard::key(row.InterfaceGuid).0;
                            let actual_luid = unsafe { row.InterfaceLuid.Value };
                            let exact = actual_guid == proof.guid
                                && actual_luid == proof.luid
                                && row.InterfaceIndex == proof.index;
                            eprintln!("actual expired Stop {kind} entry elapsed_ms={} status={status} guid={actual_guid:?} luid={actual_luid} index={} exact={exact} oper_status={} admin_status={} media_connect_state={} flags={:#04x}", observing.elapsed().as_millis(), row.InterfaceIndex, row.OperStatus, row.AdminStatus, row.MediaConnectState, row.InterfaceAndOperStatusFlags._bitfield);
                        } else {
                            eprintln!(
                                "actual expired Stop {kind} entry elapsed_ms={} status={status}",
                                observing.elapsed().as_millis()
                            );
                        }
                        match crate::windows::member_carrier_provider::native::table() {
                            Ok(rows) => {
                                let matches = rows
                                    .iter()
                                    .filter(|r| {
                                        r.identity.guid == proof.guid
                                            || r.identity.luid == proof.luid
                                            || r.identity.index == proof.index
                                    })
                                    .collect::<Vec<_>>();
                                let exact = matches
                                    .iter()
                                    .filter(|r| {
                                        r.identity.guid == proof.guid
                                            && r.identity.luid == proof.luid
                                            && r.identity.index == proof.index
                                    })
                                    .count();
                                eprintln!("actual expired Stop {kind} rundown elapsed_ms={} exact={} collisions={}", observing.elapsed().as_millis(), exact, matches.len() - exact);
                            }
                            Err(error) => eprintln!(
                                "actual expired Stop {kind} rundown elapsed_ms={} error={error:?}",
                                observing.elapsed().as_millis()
                            ),
                        }
                        if observing.elapsed() + std::time::Duration::from_secs(5)
                            >= std::time::Duration::from_secs(60)
                        {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_secs(5));
                    }
                }
            }
        }
        assert!(retry_started.elapsed() <= std::time::Duration::from_secs(30));
        let stopped = stopped.expect("actual retained native Stop");
        assert_eq!(stopped.session.phase, SessionPhase::Stopped);
        assert!(!stopped.cleanup_pending);
        if full_primary {
            let repeated = original
                .execute(
                    Command::Stop {
                        scope: scope.clone(),
                    },
                    8,
                )
                .expect("actual native primary repeated Stop");
            assert_eq!(repeated, stopped);
        }
        if module_partial {
            // A post-LoadLibrary error/unwind must clean the SAME native
            // returned module. Do not call process exit a release ACK.
            return;
        }
        // CompositeBackend drops its terminal previous control before calling
        // this factory for the next session. Exercise that production order.
        drop(original);
        // SAME factory, real new Startup and KeyLock after exact old completion.
        // Only the full primary case establishes the actual process code PIN.
        // Its repeat must still create a NEW session through the SAME factory.
        let Command::Start { scope: next, .. } = &mut command else {
            unreachable!()
        };
        next.session_id = session_ids[1].clone();
        next.connection_generation += 1;
        let next = next.clone();
        let mut retained_members = if !full_primary {
            let mut files = MemberFiles::new().expect("actual retained member files");
            let records = [TunnelSlot::A, TunnelSlot::B].map(|slot| {
                let record = files.load(slot).expect("actual predecessor member journal");
                if let Some(record) = &record {
                    assert_eq!(record.phase, crate::member_owner::Phase::Stopped);
                    assert_ne!(record.intent.scope, next);
                }
                record
            });
            Some((files, records))
        } else {
            None
        };
        eprintln!("actual factory {case}: repeat prepare");
        let mut second = factory
            .prepare(RuntimeSlot::Latest, &command, 9)
            .expect("actual repeat factory preparation");
        assert_eq!(second.snapshot().session.scope, next);
        assert_eq!(second.snapshot().session.phase, SessionPhase::Starting);
        if full_primary {
            let Command::Start {
                primary, options, ..
            } = &command
            else {
                unreachable!()
            };
            eprintln!("actual factory {case}: repeat primary Start");
            let running = second
                .start_primary(primary, options)
                .expect("actual native repeat primary Start");
            assert_eq!(running.session.scope, next);
            assert_eq!(running.session.phase, SessionPhase::Running);
            assert!(!running.cleanup_pending);
        }
        eprintln!("actual factory {case}: repeat Stop");
        let stop_started = std::time::Instant::now();
        let mut stopped = second.execute(
            Command::Stop {
                scope: next.clone(),
            },
            10,
        );
        if let Err(error) = &stopped {
            eprintln!("actual factory {case}: repeat Stop error {error:?}");
            fixture.trace_pair_stage();
        }
        let retry_started = std::time::Instant::now();
        while stopped.is_err() && second.snapshot().cleanup_pending {
            assert_eq!(second.snapshot().session.phase, SessionPhase::Stopping);
            assert!(retry_started.elapsed() <= std::time::Duration::from_secs(30));
            let now = 10 + stop_started.elapsed().as_millis() as u64;
            match second.tick(now) {
                Ok(_) => {
                    let snapshot = second.snapshot();
                    if !snapshot.cleanup_pending {
                        stopped = Ok(snapshot);
                    }
                }
                Err(error) => {
                    eprintln!("actual factory {case}: repeat Stop tick error {error:?}");
                    assert!(second.snapshot().cleanup_pending);
                    fixture.trace_pair_stage();
                    stopped = Err(error);
                }
            }
            assert!(retry_started.elapsed() <= std::time::Duration::from_secs(30));
            if second.snapshot().cleanup_pending {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
        let stopped = stopped.expect("actual repeat native Stop");
        assert_eq!(stopped.session.phase, SessionPhase::Stopped);
        assert!(!stopped.cleanup_pending);
        let repeated = second
            .execute(Command::Stop { scope: next }, 10)
            .expect("actual second repeated Stop");
        assert_eq!(repeated, stopped);
        if let Some((files, records)) = &mut retained_members {
            for (slot, record) in [TunnelSlot::A, TunnelSlot::B].into_iter().zip(records) {
                assert_eq!(
                    files
                        .load(slot)
                        .expect("actual preserved predecessor journal"),
                    *record,
                    "cold repeat Stop changed its predecessor journal"
                );
            }
        }
    } else {
        match stopped {
            Ok(snapshot) => {
                assert_eq!(snapshot.session.phase, SessionPhase::Stopped);
                assert!(!snapshot.cleanup_pending);
            }
            Err(_) => {
                assert!(original.snapshot().cleanup_pending);
                if let Some((target, unwind)) = native_partial {
                    fixture.require_native_publication_fault(
                        target,
                        unwind || original.snapshot().session.phase != SessionPhase::Stopped,
                    );
                }
                // Unknown native/record ACK remains with the original owner.
                // Process exit is not an invented successful disposition.
                std::mem::forget(original);
                std::mem::forget(factory);
            }
        }
    }
}
