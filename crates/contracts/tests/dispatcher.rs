use ed25519_dalek::{Signer, SigningKey};
use nelomai_contracts::dispatcher::*;
use nelomai_contracts::CONTAINER_MANIFEST_SIGNATURE_DOMAIN;
use serde_json::json;
use std::{fs, io, path::Path};
use tempfile::TempDir;

fn fixture() -> (TempDir, SigningKey) {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[81; 32]);
    let engine = dir
        .path()
        .join("engines/latest/0.2.16/nelomai-unix-service");
    fs::create_dir_all(engine.parent().unwrap()).unwrap();
    fs::write(engine, b"synthetic engine").unwrap();
    let bytes = serde_json::to_vec(&json!({
        "format_version":1,"container_version":"0.2.16","release_set_id":"test-0.2.16",
        "minimum_runtime_contract":1,"maximum_runtime_contract":1,
        "slots":[{"slot":"latest","manifest":{
            "format_version":1,"runtime_version":"0.2.16",
            "source_commit":"0123456789abcdef0123456789abcdef01234567",
            "platform":"macos","architecture":"aarch64","contract_version":1,
            "files":[{"path":"nelomai-unix-service","size_bytes":16,
                "sha256":digest(b"synthetic engine"),"role":"executable"}]
        }}]
    }))
    .unwrap();
    let mut message = CONTAINER_MANIFEST_SIGNATURE_DOMAIN.to_vec();
    message.extend(&bytes);
    fs::write(dir.path().join(MANIFEST_NAME), &bytes).unwrap();
    fs::write(
        dir.path().join(SIGNATURE_NAME),
        key.sign(&message).to_bytes(),
    )
    .unwrap();
    (dir, key)
}

#[test]
fn dispatcher_wire_rejects_paths_unknown_methods_and_oversize() {
    for value in [
        json!({"contract_version":1,"command":"version","executable":"/tmp/evil"}),
        json!({"contract_version":1,"command":"rebind_udp"}),
        json!({"contract_version":9,"command":"status"}),
    ] {
        assert!(decode_request(&encode_frame(&value).unwrap()).is_err());
    }
    assert!(decode_request(&vec![0; MAX_DISPATCHER_FRAME + 5]).is_err());
    assert!(decode_request(
        &encode_frame(&json!({"contract_version":1,"command":"version"})).unwrap()
    )
    .is_ok());
}

#[test]
fn installer_rejects_bad_signature_and_hash_without_publishing() {
    for signature_failure in [true, false] {
        let (source, key) = fixture();
        let target = tempfile::tempdir().unwrap();
        if signature_failure {
            fs::write(source.path().join(SIGNATURE_NAME), [0; 64]).unwrap();
        } else {
            fs::write(
                source
                    .path()
                    .join("engines/latest/0.2.16/nelomai-unix-service"),
                b"tampered",
            )
            .unwrap();
        }
        let installer = Installation::for_owner(
            target.path(),
            key.verifying_key().to_bytes(),
            "macos",
            "aarch64",
            current_owner(),
        );
        assert!(installer
            .install(
                source.path(),
                &std::env::current_exe().unwrap(),
                "501",
                &RealInstallIo
            )
            .is_err());
        assert!(!target.path().join(POINTER_NAME).exists());
    }
}

struct FailingIo {
    copy: bool,
}

struct FailedDurability;
impl InstallIo for FailedDurability {
    fn copy(&self, from: &Path, to: &Path) -> io::Result<()> {
        RealInstallIo.copy(from, to)
    }
    fn publish(&self, from: &Path, to: &Path) -> io::Result<()> {
        RealInstallIo.publish(from, to)?;
        Err(io::Error::other("injected post-rename durability failure"))
    }
}

#[test]
fn pointer_failure_after_rename_restores_the_previous_generation() {
    let (source, key) = fixture();
    let target = tempfile::tempdir().unwrap();
    let installation = Installation::for_owner(
        target.path(),
        key.verifying_key().to_bytes(),
        "macos",
        "aarch64",
        current_owner(),
    );
    let broker = std::env::current_exe().unwrap();
    installation
        .install(source.path(), &broker, "501", &RealInstallIo)
        .unwrap();
    let before = fs::read(target.path().join(POINTER_NAME)).unwrap();
    assert!(installation
        .install(source.path(), &broker, "501", &FailedDurability)
        .is_err());
    assert_eq!(fs::read(target.path().join(POINTER_NAME)).unwrap(), before);
    assert!(installation.load().unwrap().engine_path().is_file());
}

#[test]
fn failed_platform_activation_restores_verified_previous_pointer_but_cannot_rollback_running_engine(
) {
    let (source, key) = fixture();
    let target = tempfile::tempdir().unwrap();
    let installation = Installation::for_owner(
        target.path(),
        key.verifying_key().to_bytes(),
        "macos",
        "aarch64",
        current_owner(),
    );
    let broker = std::env::current_exe().unwrap();
    installation
        .install(source.path(), &broker, "501", &RealInstallIo)
        .unwrap();
    let old = fs::read_to_string(target.path().join(POINTER_NAME)).unwrap();
    installation
        .install(source.path(), &broker, "501", &RealInstallIo)
        .unwrap();
    let new = fs::read_to_string(target.path().join(POINTER_NAME)).unwrap();
    fs::write(target.path().join(ACTIVE_ENGINE_NAME), b"active").unwrap();
    assert!(installation.rollback_activation(&new, Some(&old)).is_err());
    assert_eq!(
        fs::read_to_string(target.path().join(POINTER_NAME)).unwrap(),
        new
    );
    fs::remove_file(target.path().join(ACTIVE_ENGINE_NAME)).unwrap();
    installation.rollback_activation(&new, Some(&old)).unwrap();
    assert_eq!(
        fs::read_to_string(target.path().join(POINTER_NAME)).unwrap(),
        old
    );
    assert!(installation.load().is_ok());
}
impl InstallIo for FailingIo {
    fn copy(&self, from: &Path, to: &Path) -> io::Result<()> {
        if self.copy {
            Err(io::Error::other("injected copy failure"))
        } else {
            RealInstallIo.copy(from, to)
        }
    }
    fn publish(&self, _from: &Path, _to: &Path) -> io::Result<()> {
        Err(io::Error::other("injected swap failure"))
    }
}

#[test]
fn failed_replacement_and_running_engine_preserve_previous_pointer_and_files() {
    let (source, key) = fixture();
    let target = tempfile::tempdir().unwrap();
    let installer = Installation::for_owner(
        target.path(),
        key.verifying_key().to_bytes(),
        "macos",
        "aarch64",
        current_owner(),
    );
    let broker = std::env::current_exe().unwrap();
    installer
        .install(source.path(), &broker, "501", &RealInstallIo)
        .unwrap();
    let old = fs::read(target.path().join(POINTER_NAME)).unwrap();
    for copy in [true, false] {
        assert!(installer
            .install(source.path(), &broker, "501", &FailingIo { copy })
            .is_err());
        assert_eq!(fs::read(target.path().join(POINTER_NAME)).unwrap(), old);
        assert!(installer.load().unwrap().engine_path().is_file());
    }
    fs::write(target.path().join(ACTIVE_ENGINE_NAME), b"active").unwrap();
    assert!(installer
        .install(source.path(), &broker, "501", &RealInstallIo)
        .is_err());
    assert_eq!(fs::read(target.path().join(POINTER_NAME)).unwrap(), old);
}

#[test]
fn layout_rejects_symlinked_engine_and_mismatched_identity() {
    let (source, key) = fixture();
    let target = tempfile::tempdir().unwrap();
    let installer = Installation::for_owner(
        target.path(),
        key.verifying_key().to_bytes(),
        "macos",
        "aarch64",
        current_owner(),
    );
    installer
        .install(
            source.path(),
            &std::env::current_exe().unwrap(),
            "501",
            &RealInstallIo,
        )
        .unwrap();
    let layout = installer.load().unwrap();
    let mut wrong = layout.identity.clone();
    wrong.runtime_version = "0.2.15".into();
    assert!(layout.authorize(&wrong).is_err());
    wrong = layout.identity.clone();
    wrong.manifest_sha256 = "0".repeat(64);
    assert!(layout.authorize(&wrong).is_err());
    wrong = layout.identity.clone();
    wrong.slot = nelomai_contracts::RuntimeSlot::Stable;
    assert!(layout.authorize(&wrong).is_err());
    wrong = layout.identity.clone();
    wrong.runtime_contract_version = 2;
    assert!(layout.authorize(&wrong).is_err());
    wrong = layout.identity.clone();
    wrong.container_version = "0.3.0".into();
    assert!(layout.authorize(&wrong).is_err());
    #[cfg(unix)]
    {
        let path = layout.engine_path();
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("/bin/sh", path).unwrap();
        assert!(installer.load().is_err());
    }
}

#[test]
fn mutation_lock_rejects_concurrent_owners() {
    let target = tempfile::tempdir().unwrap();
    let _guard = MutationGuard::acquire(target.path()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(target.path().join("mutation.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0,
            "unprivileged peers must not open the privileged mutation lock"
        );
    }
    assert!(MutationGuard::acquire(target.path()).is_err());
}

#[test]
fn broker_policy_rejects_same_hash_at_another_kernel_path_and_changed_installed_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let broker = directory.path().join("broker");
    let runtime = directory.path().join("runtime");
    fs::write(&broker, b"same executable").unwrap();
    fs::write(&runtime, b"same executable").unwrap();
    let policy = BrokerPolicy {
        owner: "501".into(),
        executable: broker.clone(),
        sha256: digest(b"same executable"),
        manifest_sha256: "a".repeat(64),
    };
    policy.authorize("501", &broker).unwrap();
    assert!(policy.authorize("502", &broker).is_err());
    assert!(policy.authorize("501", &runtime).is_err());
    fs::write(&broker, b"replaced executable").unwrap();
    assert!(policy.authorize("501", &broker).is_err());
}

#[test]
fn inherited_scm_primitive_rejects_paths_and_unknown_operations() {
    for value in [
        serde_json::json!({"engine_primitive":"start_wireguard","executable":"C:/evil.exe"}),
        serde_json::json!({"engine_primitive":"install_arbitrary_service"}),
    ] {
        assert!(serde_json::from_value::<PrimitiveRequest>(value).is_err());
    }
}

#[test]
fn dispatcher_status_and_version_do_not_launch_or_modify_engine_state() {
    let (source, key) = fixture();
    let target = tempfile::tempdir().unwrap();
    let installation = Installation::for_owner(
        target.path(),
        key.verifying_key().to_bytes(),
        "macos",
        "aarch64",
        current_owner(),
    );
    installation
        .install(
            source.path(),
            &std::env::current_exe().unwrap(),
            "501",
            &RealInstallIo,
        )
        .unwrap();
    let mut dispatcher = ProcessDispatcher::new(installation).unwrap();
    let _held_mutation = MutationGuard::acquire(target.path()).unwrap();
    for command in [
        DispatcherRequest::Status {
            contract_version: 1,
        },
        DispatcherRequest::Version {
            contract_version: 1,
        },
    ] {
        let response = dispatcher.handle(command, &mut |_| {
            Err(io::Error::other("no platform mutation permitted"))
        });
        assert!(response.ok);
        assert!(!response.running);
        assert_eq!(response.identity.unwrap().runtime_version, "0.2.16");
    }
    assert!(!target.path().join(ACTIVE_ENGINE_NAME).exists());
}

#[cfg(unix)]
fn process_fixture() -> (TempDir, SigningKey) {
    let (directory, key) = fixture();
    let engine = br##"#!/usr/bin/python3
import json,struct,sys,os,fcntl,time,signal
root=sys.argv[2]
lease=open(root+'/engine-owner.lock','a')
fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
while True:
    size=sys.stdin.buffer.read(4)
    if not size: break
    value=json.loads(sys.stdin.buffer.read(struct.unpack('<I',size)[0]))
    if value.get('command')=='crash': os._exit(1)
    if value.get('command')=='hang':
        signal.alarm(10)
        if os.fork()==0:
            signal.alarm(10)
            time.sleep(60)
            os._exit(0)
        open(root+'/persisted-tunnel','w').write('needs recovery')
        time.sleep(60)
    if value.get('dispatcher_control')=='ready': reply={'engine_ready':True}
    elif value.get('dispatcher_control')=='stop':
        if os.path.exists(root+'/persisted-tunnel'): os.unlink(root+'/persisted-tunnel')
        reply={'engine_stopped':True}
    else: reply={'private_operation':value['command'],'preserved':value.get('probe')}
    data=json.dumps(reply).encode()
    sys.stdout.buffer.write(struct.pack('<I',len(data))+data); sys.stdout.buffer.flush()
"##;
    fs::write(
        directory
            .path()
            .join("engines/latest/0.2.16/nelomai-unix-service"),
        engine,
    )
    .unwrap();
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.path().join(MANIFEST_NAME)).unwrap()).unwrap();
    manifest["slots"][0]["manifest"]["files"][0]["size_bytes"] = json!(engine.len());
    manifest["slots"][0]["manifest"]["files"][0]["sha256"] = json!(digest(engine));
    let bytes = serde_json::to_vec(&manifest).unwrap();
    let mut message = CONTAINER_MANIFEST_SIGNATURE_DOMAIN.to_vec();
    message.extend(&bytes);
    fs::write(directory.path().join(MANIFEST_NAME), bytes).unwrap();
    fs::write(
        directory.path().join(SIGNATURE_NAME),
        key.sign(&message).to_bytes(),
    )
    .unwrap();
    (directory, key)
}

#[cfg(unix)]
#[test]
fn real_child_relay_preserves_private_operations_and_shared_mutation_exclusion() {
    let (source, key) = process_fixture();
    let target = tempfile::tempdir().unwrap();
    let installation = Installation::for_owner(
        target.path(),
        key.verifying_key().to_bytes(),
        "macos",
        "aarch64",
        current_owner(),
    );
    installation
        .install(
            source.path(),
            &std::env::current_exe().unwrap(),
            "501",
            &RealInstallIo,
        )
        .unwrap();
    let mut dispatcher = ProcessDispatcher::new(installation).unwrap();
    let identity = dispatcher.layout.identity.clone();
    let mut primitive = |_| Err(io::Error::other("no SCM on Unix"));
    assert!(
        dispatcher
            .handle(
                DispatcherRequest::Start {
                    contract_version: 1,
                    identity: identity.clone()
                },
                &mut primitive
            )
            .ok
    );
    let lock = MutationGuard::acquire(target.path()).unwrap();
    assert!(dispatcher
        .relay(
            &encode_frame(&json!({"command":"rebind_udp"})).unwrap(),
            &mut primitive
        )
        .is_err());
    drop(lock);
    for operation in [
        "metrics",
        "diagnostics",
        "physical_network_fingerprint",
        "defender_status",
        "rebind_udp",
    ] {
        let response = dispatcher
            .relay(
                &encode_frame(&json!({"command":operation,"probe":true})).unwrap(),
                &mut primitive,
            )
            .unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(frame_body(&response, MAX_ENGINE_FRAME).unwrap()).unwrap();
        assert_eq!(
            value,
            json!({"private_operation":operation,"preserved":true})
        );
    }
    assert!(
        dispatcher
            .handle(
                DispatcherRequest::Stop {
                    contract_version: 1,
                    identity
                },
                &mut primitive
            )
            .ok
    );
    assert!(!target.path().join(ACTIVE_ENGINE_NAME).exists());
}

#[cfg(unix)]
#[test]
fn dispatcher_death_fixture_entry() {
    let Some(root) = std::env::var_os("NELOMAI_TEST_OWNED_DISPATCHER_ROOT") else {
        return;
    };
    let installation = Installation::for_owner(
        Path::new(&root),
        SigningKey::from_bytes(&[81; 32]).verifying_key().to_bytes(),
        "macos",
        "aarch64",
        current_owner(),
    );
    let mut dispatcher = ProcessDispatcher::new(installation).unwrap();
    assert!(
        dispatcher
            .handle(
                DispatcherRequest::Start {
                    contract_version: 1,
                    identity: dispatcher.layout.identity.clone()
                },
                &mut |_| Ok(())
            )
            .ok
    );
    let _ = dispatcher.relay(
        &encode_frame(&json!({"command":"hang"})).unwrap(),
        &mut |_| Ok(()),
    );
}

#[cfg(unix)]
#[test]
fn dispatcher_death_terminates_hung_owned_tree_and_recovers_persisted_state() {
    let (source, key) = process_fixture();
    let target = tempfile::tempdir().unwrap();
    let installation = Installation::for_owner(
        target.path(),
        key.verifying_key().to_bytes(),
        "macos",
        "aarch64",
        current_owner(),
    );
    installation
        .install(
            source.path(),
            &std::env::current_exe().unwrap(),
            "501",
            &RealInstallIo,
        )
        .unwrap();
    let mut owner = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "dispatcher_death_fixture_entry"])
        .env("NELOMAI_TEST_OWNED_DISPATCHER_ROOT", target.path())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !target.path().join("persisted-tunnel").exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "fixture never entered its hung operation"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(MutationGuard::at(&target.path().join("engine-owner.lock")).is_err());
    owner.kill().unwrap(); // exact owned dispatcher handle, no PID-file adoption
    owner.wait().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if let Ok(lease) = MutationGuard::at(&target.path().join("engine-owner.lock")) {
            drop(lease);
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "hung owned engine tree survived dispatcher death with lifetime lease"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(target.path().join(ACTIVE_ENGINE_NAME).exists());
    let mut restarted = ProcessDispatcher::new(installation).unwrap();
    assert!(
        restarted
            .handle(
                DispatcherRequest::Stop {
                    contract_version: 1,
                    identity: restarted.layout.identity.clone()
                },
                &mut |_| Ok(())
            )
            .ok
    );
    assert!(!target.path().join("persisted-tunnel").exists());
    assert!(!target.path().join(ACTIVE_ENGINE_NAME).exists());
}

#[cfg(unix)]
#[test]
fn crashed_engine_status_is_not_running_and_cleanup_keeps_recovery_marker_until_stopped() {
    let (source, key) = process_fixture();
    let target = tempfile::tempdir().unwrap();
    let installation = Installation::for_owner(
        target.path(),
        key.verifying_key().to_bytes(),
        "macos",
        "aarch64",
        current_owner(),
    );
    installation
        .install(
            source.path(),
            &std::env::current_exe().unwrap(),
            "501",
            &RealInstallIo,
        )
        .unwrap();
    let mut dispatcher = ProcessDispatcher::new(installation).unwrap();
    let identity = dispatcher.layout.identity.clone();
    let mut primitive = |_| Err(io::Error::other("no SCM"));
    assert!(
        dispatcher
            .handle(
                DispatcherRequest::Start {
                    contract_version: 1,
                    identity: identity.clone()
                },
                &mut primitive
            )
            .ok
    );
    assert!(dispatcher
        .relay(
            &encode_frame(&json!({"command":"crash"})).unwrap(),
            &mut primitive
        )
        .is_err());
    let status = dispatcher.handle(
        DispatcherRequest::Status {
            contract_version: 1,
        },
        &mut primitive,
    );
    assert!(
        !status.running,
        "a crashed child must not be reported as running"
    );
    assert!(target.path().join(ACTIVE_ENGINE_NAME).exists());
    assert!(
        dispatcher
            .handle(
                DispatcherRequest::Cleanup {
                    contract_version: 1,
                    identity
                },
                &mut primitive
            )
            .ok
    );
    assert!(!target.path().join(ACTIVE_ENGINE_NAME).exists());
}

#[test]
fn cleanup_removes_only_stopped_verified_previous_generations() {
    let (source, key) = fixture();
    let target = tempfile::tempdir().unwrap();
    let installation = Installation::for_owner(
        target.path(),
        key.verifying_key().to_bytes(),
        "macos",
        "aarch64",
        current_owner(),
    );
    let broker = std::env::current_exe().unwrap();
    let previous = installation
        .install(source.path(), &broker, "501", &RealInstallIo)
        .unwrap();
    let current = installation
        .install(source.path(), &broker, "501", &RealInstallIo)
        .unwrap();
    let unrelated = target.path().join("releases/unrelated");
    fs::create_dir(&unrelated).unwrap();
    let mut dispatcher = ProcessDispatcher::new(installation).unwrap();
    let response = dispatcher.handle(
        DispatcherRequest::Cleanup {
            contract_version: 1,
            identity: current.identity.clone(),
        },
        &mut |_| Err(io::Error::other("must not launch anything")),
    );
    assert!(response.ok);
    assert!(!previous.directory.exists());
    assert!(current.directory.exists());
    assert!(unrelated.exists());
}

fn current_owner() -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(std::env::current_exe().unwrap())
            .unwrap()
            .uid()
    }
    #[cfg(not(unix))]
    {
        0
    }
}
