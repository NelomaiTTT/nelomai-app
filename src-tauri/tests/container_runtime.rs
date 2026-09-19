#![cfg(unix)]
use ed25519_dalek::{Signer, SigningKey};
use nelomai_client_container::desktop::VerifiedRuntime;
use nelomai_contracts::{dispatcher::digest, RuntimeSlot, CONTAINER_MANIFEST_SIGNATURE_DOMAIN};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
};

struct Fixture {
    root: tempfile::TempDir,
    key: SigningKey,
}
impl Fixture {
    fn replace_executable(&self, bytes: &[u8]) {
        fs::write(self.executable(), bytes).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(
            &fs::read(self.root.path().join("container-manifest-v1.json")).unwrap(),
        )
        .unwrap();
        value["slots"][0]["manifest"]["files"][0]["size_bytes"] = bytes.len().into();
        value["slots"][0]["manifest"]["files"][0]["sha256"] = digest(bytes).into();
        let bytes = serde_json::to_vec(&value).unwrap();
        let signed = [CONTAINER_MANIFEST_SIGNATURE_DOMAIN, bytes.as_slice()].concat();
        fs::write(self.root.path().join("container-manifest-v1.json"), bytes).unwrap();
        fs::write(
            self.root.path().join("container-manifest-v1.sig"),
            self.key.sign(&signed).to_bytes(),
        )
        .unwrap();
    }
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let payload = root.path().join("engines/latest/0.2.16");
        fs::create_dir_all(&payload).unwrap();
        fs::write(payload.join("nelomai-runtime"), b"runtime executable").unwrap();
        fs::set_permissions(
            payload.join("nelomai-runtime"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let key = SigningKey::from_bytes(&[49; 32]);
        let value = serde_json::json!({
            "format_version":1,"container_version":"0.2.16","release_set_id":"task-9-local",
            "minimum_runtime_contract":1,"maximum_runtime_contract":1,
            "slots":[{"slot":"latest","manifest":{
                "format_version":1,"runtime_version":"0.2.16","source_commit":"632cc4b40872c559a75e5d7104b72bae17ac91c3",
                "platform":std::env::consts::OS,"architecture":std::env::consts::ARCH,"contract_version":1,
                "files":[{"path":"nelomai-runtime","size_bytes":18,"sha256":digest(b"runtime executable"),"role":"executable"}]
            }}]
        });
        let bytes = serde_json::to_vec(&value).unwrap();
        let signed = [CONTAINER_MANIFEST_SIGNATURE_DOMAIN, bytes.as_slice()].concat();
        fs::write(root.path().join("container-manifest-v1.json"), bytes).unwrap();
        fs::write(
            root.path().join("container-manifest-v1.sig"),
            key.sign(&signed).to_bytes(),
        )
        .unwrap();
        Self { root, key }
    }
    fn open(&self, slot: RuntimeSlot) -> std::io::Result<VerifiedRuntime> {
        VerifiedRuntime::open(
            self.root.path(),
            &self.key.verifying_key().to_bytes(),
            slot,
            std::env::consts::OS,
            std::env::consts::ARCH,
            unsafe { libc::geteuid() },
        )
    }
    fn executable(&self) -> std::path::PathBuf {
        self.root
            .path()
            .join("engines/latest/0.2.16/nelomai-runtime")
    }
}

#[test]
#[cfg(target_os = "macos")]
fn macos_admits_product_named_runtime_and_rejects_modified_bytes() {
    for name in ["Nelomai", "Nelomai.app/Contents/MacOS/Nelomai"] {
        let fixture = Fixture::new();
        assert!(
            fixture.open(RuntimeSlot::Latest).is_ok(),
            "legacy runtime remains supported"
        );
        let resources = fixture.executable().parent().unwrap().to_path_buf();
        let executable = resources.join(name);
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::rename(fixture.executable(), &executable).unwrap();
        let manifest = fixture.root.path().join("container-manifest-v1.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
        value["slots"][0]["manifest"]["files"][0]["path"] = name.into();
        let bytes = serde_json::to_vec(&value).unwrap();
        let signed = [CONTAINER_MANIFEST_SIGNATURE_DOMAIN, bytes.as_slice()].concat();
        fs::write(&manifest, bytes).unwrap();
        fs::write(
            fixture.root.path().join("container-manifest-v1.sig"),
            fixture.key.sign(&signed).to_bytes(),
        )
        .unwrap();
        assert_eq!(
            fixture.open(RuntimeSlot::Latest).unwrap().executable(),
            executable
        );
        assert_eq!(
            fixture.open(RuntimeSlot::Latest).unwrap().resource_root(),
            resources
        );
        fs::write(executable, b"modified runtime!!").unwrap();
        assert!(fixture.open(RuntimeSlot::Latest).is_err());
    }
}

#[test]
fn actual_spawn_verifies_kernel_path_and_does_not_inherit_secrets_or_unrelated_fds() {
    use std::os::unix::process::CommandExt;
    use std::{io::Read, process::Command};
    // A separate test process supplies real synthetic secret variables without
    // mutating the environment of concurrently running test threads.
    if std::env::var_os("NELOMAI_TASK9_LAUNCHER_FIXTURE").is_none() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        // Runner/shell descriptors are not launcher leaks. Isolate only the
        // initial fixture process, before any private channel is created.
        // The unrelated child below remains unsanitized to detect real leaks.
        for fd in 3..256 {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags >= 0 && flags & libc::FD_CLOEXEC == 0 {
                eprintln!("fixture inherited runner descriptor: {fd}");
                #[cfg(target_os = "linux")]
                eprintln!(
                    "descriptor target: {:?}",
                    fs::read_link(format!("/proc/self/fd/{fd}"))
                );
            }
        }
        unsafe {
            command.pre_exec(|| {
                for fd in 3..256 {
                    let flags = libc::fcntl(fd, libc::F_GETFD);
                    if flags >= 0 && libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        assert!(command
            .args([
                "--exact",
                "actual_spawn_verifies_kernel_path_and_does_not_inherit_secrets_or_unrelated_fds"
            ])
            .env("NELOMAI_TASK9_LAUNCHER_FIXTURE", "1")
            .env(
                "NELOMAI_TEST_REFRESH_SECRET",
                "synthetic-not-a-real-refresh"
            )
            .env(
                "NELOMAI_TEST_INSTALL_SECRET",
                "synthetic-not-a-real-install-secret"
            )
            .status()
            .unwrap()
            .success());
        return;
    }
    let f = Fixture::new();
    let compiled = f.root.path().join("probe");
    assert!(Command::new("rustc")
        .args(["--edition=2021", "tests/fixtures/runtime_probe.rs", "-o"])
        .arg(&compiled)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .unwrap()
        .success());
    f.replace_executable(&fs::read(compiled).unwrap());
    let verified = f.open(RuntimeSlot::Latest).unwrap();
    let mut child = verified.spawn().unwrap();
    assert_eq!(
        child.kernel_executable().unwrap(),
        fs::canonicalize(f.executable()).unwrap()
    );
    let mut response = [0; 2];
    child.native().read_exact(&mut response).unwrap();
    assert_eq!(response,[0,0],"child argv/environment must contain only the private protocol marker and allowed desktop environment");
    let unrelated = Command::new(f.executable()).status().unwrap();
    assert_eq!(
        unrelated.code(),
        Some(42),
        "unrelated child cannot use launch IPC"
    );
    // Negative control: initial fixture isolation must not hide a channel
    // deliberately made inheritable after the launcher has run.
    {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let fd = unsafe { libc::fcntl(child.native().as_raw_fd(), libc::F_DUPFD, 10) };
        assert!((10..256).contains(&fd));
        let _leaked_channel = unsafe { OwnedFd::from_raw_fd(fd) };
        assert_eq!(
            Command::new(f.executable()).status().unwrap().code(),
            Some(44),
            "probe must still detect an actual inherited launcher channel"
        );
    }
    let pid = child.id();
    let process = std::sync::Mutex::new(Some(child));
    let result = tauri::async_runtime::block_on(
        nelomai_client_container::desktop::stop_runtime_before_helper(&process, async {
            assert_ne!(
                unsafe { libc::kill(pid as i32, 0) },
                0,
                "runtime must be reaped before helper stop is attempted"
            );
            Err(std::io::Error::other("helper stop has no receipt"))
        }),
    );
    assert!(
        result.is_err(),
        "runtime exit alone must not acknowledge helper stop"
    );
    assert!(process.lock().unwrap().as_mut().unwrap().exited().unwrap());
    fs::write(f.executable(), b"replaced after validation").unwrap();
    assert!(verified.spawn().is_err());
}

#[test]
fn latest_launch_requires_verified_manifest_and_reports_stable_unavailable() {
    let f = Fixture::new();
    assert_eq!(
        f.open(RuntimeSlot::Latest).unwrap().executable(),
        f.executable()
    );
    assert!(f.open(RuntimeSlot::Stable).is_err());
    assert!(VerifiedRuntime::open(
        f.root.path(),
        &[0; 32],
        RuntimeSlot::Latest,
        std::env::consts::OS,
        std::env::consts::ARCH,
        unsafe { libc::geteuid() }
    )
    .is_err());
    assert!(VerifiedRuntime::open(
        f.root.path(),
        &f.key.verifying_key().to_bytes(),
        RuntimeSlot::Latest,
        "windows",
        "x86_64",
        unsafe { libc::geteuid() }
    )
    .is_err());
}

#[test]
fn intentional_reap_keeps_common_alive_but_new_runtime_eof_is_unsolicited() {
    use nelomai_client_container::desktop::RuntimeExitOwner;
    use std::{io::Read, process::Command, sync::Mutex};
    let f = Fixture::new();
    let compiled = f.root.path().join("probe");
    assert!(Command::new("rustc")
        .args(["--edition=2021", "tests/fixtures/runtime_probe.rs", "-o"])
        .arg(&compiled)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .unwrap()
        .success());
    f.replace_executable(&fs::read(compiled).unwrap());
    let mut child = f.open(RuntimeSlot::Latest).unwrap().spawn().unwrap();
    let mut native = child.native().try_clone().unwrap();
    native.read_exact(&mut [0; 2]).unwrap();
    let process = Mutex::new(Some(child));
    let owner = RuntimeExitOwner::default();
    tauri::async_runtime::block_on(owner.stop_for_transition(&process, async {
        assert_eq!(native.read(&mut [0; 1]).unwrap(), 0);
        assert!(
            !owner.finish_on_native_eof(),
            "intentional EOF must leave common alive through helper acknowledgement"
        );
        Err(std::io::Error::other("independent helper receipt missing"))
    }))
    .unwrap_err();
    assert!(
        !owner.finish_on_native_eof(),
        "failed helper stop remains owned and retryable, not app exit"
    );
    owner.runtime_launched();
    assert!(
        owner.finish_on_native_eof(),
        "new runtime unsolicited EOF must still finish common"
    );
    assert!(
        tauri::async_runtime::block_on(owner.stop_for_transition(&process, async { Ok(()) }))
            .is_err(),
        "cannot steal an unsolicited failure already owned by finish"
    );
}

#[test]
fn installer_handoff_reaps_before_pending_check_and_never_infers_success() {
    use nelomai_client_container::desktop::RuntimeExitOwner;
    use std::{io::Read, process::Command, sync::Mutex};
    let f = Fixture::new();
    let compiled = f.root.path().join("probe");
    assert!(Command::new("rustc")
        .args(["--edition=2021", "tests/fixtures/runtime_probe.rs", "-o"])
        .arg(&compiled)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .unwrap()
        .success());
    f.replace_executable(&fs::read(compiled).unwrap());
    let mut child = f.open(RuntimeSlot::Latest).unwrap().spawn().unwrap();
    let pid = child.id();
    let mut native = child.native().try_clone().unwrap();
    native.read_exact(&mut [0; 2]).unwrap();
    let process = Mutex::new(Some(child));
    let owner = RuntimeExitOwner::default();
    let result = tauri::async_runtime::block_on(owner.handoff_installer(
        &process,
        async {
            assert_ne!(
                unsafe { libc::kill(pid as i32, 0) },
                0,
                "pending handoff validation must follow actual child reap"
            );
            assert_eq!(native.read(&mut [0; 1]).unwrap(), 0);
            assert!(!owner.finish_on_native_eof());
            Err(std::io::Error::other("pending authority missing or stale"))
        },
        || panic!("installer must not launch without pending stop authority"),
    ));
    assert!(result.is_err());
    let launched = std::cell::Cell::new(false);
    let result =
        tauri::async_runtime::block_on(owner.handoff_installer(&process, async { Ok(()) }, || {
            launched.set(true);
            assert_ne!(unsafe { libc::kill(pid as i32, 0) }, 0);
            Ok(())
        }));
    assert!(launched.get());
    assert!(
        result.is_err(),
        "a returning installer launch is not successful replacement evidence"
    );
}

#[test]
fn signed_but_incompatible_contract_or_escaping_path_is_rejected() {
    for (field, value) in [
        ("contract_version", serde_json::json!(999)),
        ("path", serde_json::json!("../nelomai-runtime")),
    ] {
        let f = Fixture::new();
        let path = f.root.path().join("container-manifest-v1.json");
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        if field == "path" {
            manifest["slots"][0]["manifest"]["files"][0][field] = value;
        } else {
            manifest["slots"][0]["manifest"][field] = value;
        }
        let bytes = serde_json::to_vec(&manifest).unwrap();
        fs::write(path, &bytes).unwrap();
        fs::write(
            f.root.path().join("container-manifest-v1.sig"),
            f.key
                .sign(&[CONTAINER_MANIFEST_SIGNATURE_DOMAIN, bytes.as_slice()].concat())
                .to_bytes(),
        )
        .unwrap();
        assert!(f.open(RuntimeSlot::Latest).is_err());
    }
}

#[test]
fn launch_refuses_changed_hash_mode_owner_or_symlink() {
    let f = Fixture::new();
    fs::write(f.executable(), b"tampered executable").unwrap();
    assert!(f.open(RuntimeSlot::Latest).is_err());
    let f = Fixture::new();
    fs::set_permissions(f.executable(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(f.open(RuntimeSlot::Latest).is_err());
    fs::set_permissions(f.executable(), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(f.open(RuntimeSlot::Latest).is_err());
    let f = Fixture::new();
    assert!(VerifiedRuntime::open(
        f.root.path(),
        &f.key.verifying_key().to_bytes(),
        RuntimeSlot::Latest,
        std::env::consts::OS,
        std::env::consts::ARCH,
        unsafe { libc::geteuid() }.wrapping_add(1)
    )
    .is_err());
    fs::rename(f.executable(), f.root.path().join("outside")).unwrap();
    symlink(f.root.path().join("outside"), f.executable()).unwrap();
    assert!(f.open(RuntimeSlot::Latest).is_err());
}

#[test]
fn native_channel_preserves_full_engine_frame_and_bounds_control_before_allocation() {
    use nelomai_client_container::desktop::{read_native_frame, write_native_frame};
    let engine = vec![1; 1024 * 1024];
    let mut wire = Vec::new();
    write_native_frame(&mut wire, 1, &engine).unwrap();
    assert_eq!(wire.len(), 1024 * 1024 + 5);
    assert_eq!(
        read_native_frame(&mut wire.as_slice()).unwrap(),
        (1, engine)
    );
    assert!(write_native_frame(&mut Vec::new(), 1, &vec![0; 1024 * 1024 + 1]).is_err());
    assert!(write_native_frame(&mut Vec::new(), 2, &vec![0; 65537]).is_err());
    assert!(read_native_frame(&mut [2, 1, 0, 1, 0].as_slice()).is_err());
    assert!(read_native_frame(&mut [99, 0, 0, 0, 0].as_slice()).is_err());
    assert!(read_native_frame(&mut [1, 3, 0, 0, 0, 7].as_slice()).is_err());
}

#[test]
fn protected_installation_does_not_roll_back_and_repairs_an_updated_user_owned_bundle_before_auth()
{
    use nelomai_app_lib::container::{installation_action, InstallationAction::*};
    assert_eq!(
        installation_action("0.2.16", None, false, false).unwrap(),
        InstallCandidate
    );
    assert_eq!(
        installation_action("0.2.16", Some("0.2.17"), true, false).unwrap(),
        LaunchInstalled
    );
    assert_eq!(
        installation_action("0.2.16", Some("0.2.17"), false, false).unwrap(),
        RepairInstalled
    );
    assert_eq!(
        installation_action("0.2.16", Some("0.2.16"), true, true).unwrap(),
        Continue
    );
    assert_eq!(
        installation_action("0.2.17", Some("0.2.16"), true, false).unwrap(),
        InstallCandidate
    );
    assert!(installation_action("0.2.16", Some("invalid"), true, false).is_err());
}
