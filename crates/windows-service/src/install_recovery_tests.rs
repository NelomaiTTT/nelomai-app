use super::*;

#[test]
fn bounded_cleanup_role_accepts_only_engine_or_protected_staged_helper() {
    RecoveryExecutable::Engine
        .require_bounded_cleanup()
        .unwrap();
    RecoveryExecutable::StagedInstaller
        .require_bounded_cleanup()
        .unwrap();
    assert!(RecoveryExecutable::Installer {
        source: std::path::PathBuf::from("unprotected-incoming-package")
    }
    .require_bounded_cleanup()
    .is_err());
    // A cleanup role is never a forward/engine capability.
    assert!(RecoveryExecutable::StagedInstaller
        .require_engine()
        .is_err());
}
use ed25519_dalek::{Signer, SigningKey};
use nelomai_contracts::CONTAINER_MANIFEST_SIGNATURE_DOMAIN;
use serde_json::json;
use std::fs;

// Real signed installation/marker/locks. The fake executable is data, never run.
fn fixture() -> (tempfile::TempDir, Installation, Vec<u8>) {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let engine = source.join("engines/latest/0.3.3/nelomai-windows-service.exe");
    fs::create_dir_all(engine.parent().unwrap()).unwrap();
    fs::write(&engine, b"fake-native-engine").unwrap();
    let key = SigningKey::from_bytes(&[81; 32]);
    let bytes = serde_json::to_vec(&json!({
        "format_version":1,"container_version":"0.3.3","release_set_id":"test-0.3.3",
        "minimum_runtime_contract":1,"maximum_runtime_contract":1,
        "slots":[{"slot":"latest","manifest":{
            "format_version":1,"runtime_version":"0.3.3",
            "source_commit":"0123456789abcdef0123456789abcdef01234567",
            "platform":"windows","architecture":"x86_64","contract_version":1,
            "files":[{"path":"nelomai-windows-service.exe","size_bytes":18,
                "sha256":d::digest(b"fake-native-engine"),"role":"executable"}]
        }}]
    }))
    .unwrap();
    let mut message = CONTAINER_MANIFEST_SIGNATURE_DOMAIN.to_vec();
    message.extend(&bytes);
    fs::write(source.join(d::MANIFEST_NAME), &bytes).unwrap();
    fs::write(
        source.join(d::SIGNATURE_NAME),
        key.sign(&message).to_bytes(),
    )
    .unwrap();
    let broker = temp.path().join("broker.exe");
    fs::write(&broker, b"broker").unwrap();
    #[cfg(unix)]
    let owner = {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(&broker).unwrap().uid()
    };
    #[cfg(not(unix))]
    let owner = 0;
    let installation = Installation::for_owner(
        &temp.path().join("privileged"),
        key.verifying_key().to_bytes(),
        "windows",
        "x86_64",
        owner,
    );
    let layout = installation
        .install(&source, &broker, "S-1-5-21-1000", &d::RealInstallIo)
        .unwrap();
    let marker = serde_json::to_vec(&layout.identity).unwrap();
    d::write_new(&installation.root.join(d::ACTIVE_ENGINE_NAME), &marker).unwrap();
    (temp, installation, marker)
}

#[test]
fn installer_cleanup_rejects_modified_old_manager_dispatcher_before_callback() {
    let (temp, installation, marker) = fixture();
    let layout = installation.load().unwrap();
    let dispatcher = layout.dispatcher_path();
    // The installed dispatcher is a separate copy from the signed engine.
    // Its unchanged path/configuration is not proof of its current bytes.
    let tampered = b"forged-dispatcher!";
    assert_eq!(
        fs::metadata(&dispatcher).unwrap().len(),
        tampered.len() as u64
    );
    fs::write(&dispatcher, tampered).unwrap();
    let installer = temp.path().join("nelomai-windows-service.exe");
    fs::copy(
        temp.path()
            .join("source/engines/latest/0.3.3/nelomai-windows-service.exe"),
        &installer,
    )
    .unwrap();
    let role = RecoveryExecutable::Installer {
        source: temp.path().join("source"),
    };
    let executable = fs::canonicalize(&installer).unwrap();
    assert!(role
        .load(
            &installation,
            &executable,
            nelomai_contracts::RuntimeSlot::Latest
        )
        .is_err());
    let mut called = false;
    assert!(recover(&installation, |_| {
        called = true;
        Ok(())
    })
    .is_err());
    assert!(!called);
    assert_eq!(
        fs::read(installation.root.join(d::ACTIVE_ENGINE_NAME)).unwrap(),
        marker
    );
}

#[test]
fn manager_cleanup_needs_exact_old_dispatcher_command_not_a_service_name() {
    use std::ffi::{OsStr, OsString};
    let expected = Path::new("C:\\Program Files\\Nelomai\\privileged\\releases\\old\\dispatcher\\1\\nelomai-windows-service.exe");
    let args = [
        expected.as_os_str().to_owned(),
        OsString::from("--manager-service"),
    ];
    require_owned_manager_command(&args, Some(expected), true, Some(OsStr::new("LocalSystem")))
        .unwrap();
    assert!(
        require_owned_manager_command(&args, None, true, Some(OsStr::new("LocalSystem"))).is_err()
    );
    assert!(require_owned_manager_command(
        &args,
        Some(expected),
        false,
        Some(OsStr::new("LocalSystem"))
    )
    .is_err());
    assert!(require_owned_manager_command(
        &args,
        Some(expected),
        true,
        Some(OsStr::new("foreign-user"))
    )
    .is_err());
    let foreign = [OsString::from("C:\\foreign.exe"), args[1].clone()];
    assert!(require_owned_manager_command(
        &foreign,
        Some(expected),
        true,
        Some(OsStr::new("LocalSystem"))
    )
    .is_err());
    let extra = [
        args[0].clone(),
        args[1].clone(),
        OsString::from("--engine-mode"),
    ];
    assert!(require_owned_manager_command(
        &extra,
        Some(expected),
        true,
        Some(OsStr::new("LocalSystem"))
    )
    .is_err());
}

#[test]
fn stale_marker_retires_only_after_verified_owned_cleanup_under_both_locks() {
    let (_temp, installation, marker) = fixture();
    let path = installation.root.join(d::ACTIVE_ENGINE_NAME);
    let mut called = false;
    recover(&installation, |layout| {
        called = true;
        assert_eq!(layout.identity.runtime_version, "0.3.3");
        assert_eq!(fs::read(&path).unwrap(), marker);
        assert!(d::MutationGuard::acquire(&installation.root).is_err());
        assert!(d::MutationGuard::at(&installation.root.join("engine-owner.lock")).is_err());
        Ok(())
    })
    .unwrap();
    assert!(called);
    assert!(!path.exists());
}

#[test]
fn signed_colocated_installer_recovers_old_layout_without_becoming_its_engine() {
    let (temp, installation, _bytes) = fixture();
    let source = temp.path().join("source");
    let installer = temp.path().join("nelomai-windows-service.exe");
    fs::copy(
        source.join("engines/latest/0.3.3/nelomai-windows-service.exe"),
        &installer,
    )
    .unwrap();
    let executable = fs::canonicalize(&installer).unwrap();
    // The actual update helper is a signed copy, not the old engine path.
    assert!(installation.load_engine(&executable).is_err());
    let role = RecoveryExecutable::Installer {
        source: source.clone(),
    };
    assert!(role.require_engine().is_err());
    let mut called = false;
    recover_with_owner(&installation, |layout, owner| {
        owner.verify_at(&installation.root.join("engine-owner.lock"))?;
        let verified = role.load(&installation, &executable, layout.identity.slot)?;
        verified.authorize(&layout.identity)?;
        called = true;
        Ok(())
    })
    .unwrap();
    assert!(called);
    assert!(!installation.root.join(d::ACTIVE_ENGINE_NAME).exists());
}

#[test]
fn engine_recovery_cannot_fallback_to_installer_or_select_another_slot() {
    let (temp, installation, _) = fixture();
    let layout = installation.load().unwrap();
    let engine = fs::canonicalize(layout.engine_path()).unwrap();
    let role = RecoveryExecutable::Engine;
    role.require_engine().unwrap();
    role.load(
        &installation,
        &engine,
        nelomai_contracts::RuntimeSlot::Latest,
    )
    .unwrap();
    assert!(role
        .load(
            &installation,
            &engine,
            nelomai_contracts::RuntimeSlot::Stable
        )
        .is_err());
    let installer = temp.path().join("nelomai-windows-service.exe");
    fs::copy(&engine, &installer).unwrap();
    assert!(role
        .load(
            &installation,
            &fs::canonicalize(installer).unwrap(),
            nelomai_contracts::RuntimeSlot::Latest
        )
        .is_err());
}

#[test]
fn newer_signed_installer_does_not_replace_the_old_cleanup_identity() {
    let (temp, installation, _) = fixture();
    let source = temp.path().join("source");
    let engine_root = source.join("engines/latest");
    fs::rename(engine_root.join("0.3.3"), engine_root.join("0.3.4")).unwrap();
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(source.join(d::MANIFEST_NAME)).unwrap()).unwrap();
    manifest["container_version"] = json!("0.3.4");
    manifest["release_set_id"] = json!("test-0.3.4");
    manifest["slots"][0]["manifest"]["runtime_version"] = json!("0.3.4");
    let bytes = serde_json::to_vec(&manifest).unwrap();
    let mut message = CONTAINER_MANIFEST_SIGNATURE_DOMAIN.to_vec();
    message.extend(&bytes);
    fs::write(source.join(d::MANIFEST_NAME), bytes).unwrap();
    fs::write(
        source.join(d::SIGNATURE_NAME),
        SigningKey::from_bytes(&[81; 32]).sign(&message).to_bytes(),
    )
    .unwrap();
    let installer = temp.path().join("nelomai-windows-service.exe");
    fs::copy(
        engine_root.join("0.3.4/nelomai-windows-service.exe"),
        &installer,
    )
    .unwrap();
    assert_eq!(
        installation
            .manifest_identity(&source)
            .unwrap()
            .runtime_version,
        "0.3.4"
    );
    let verified = RecoveryExecutable::Installer { source }
        .load(
            &installation,
            &fs::canonicalize(installer).unwrap(),
            nelomai_contracts::RuntimeSlot::Latest,
        )
        .unwrap();
    assert_eq!(verified.identity.runtime_version, "0.3.3");
    assert_eq!(verified.identity.container_version, "0.3.3");
}

#[test]
fn embedded_signed_helper_is_staging_data_only_and_copies_exact_new_bytes() {
    let (temp, installation, marker) = fixture();
    let source = temp.path().join("source");
    let helper = temp.path().join("nelomai-update-helper.exe");
    fs::copy(
        source.join("engines/latest/0.3.3/nelomai-windows-service.exe"),
        &helper,
    )
    .unwrap();
    let manifest = fs::read(source.join(d::MANIFEST_NAME)).unwrap();
    let signature = fs::read(source.join(d::SIGNATURE_NAME)).unwrap();
    let payload = installation
        .update_helper_payload(&manifest, &signature, &fs::canonicalize(&helper).unwrap())
        .unwrap();
    let directory = installation
        .root
        .join("update-recovery/stage-1234567890abcdef");
    fs::create_dir_all(&directory).unwrap();
    let staged = payload.write_stage(&directory).unwrap();
    assert_eq!(fs::read(staged).unwrap(), b"fake-native-engine");
    assert_eq!(
        fs::read(directory.join(d::UPDATE_HELPER_MANIFEST_NAME)).unwrap(),
        manifest
    );
    assert_eq!(
        fs::read(directory.join(d::UPDATE_HELPER_SIGNATURE_NAME)).unwrap(),
        signature
    );
    assert_eq!(
        fs::read(installation.root.join(d::ACTIVE_ENGINE_NAME)).unwrap(),
        marker
    );
    assert!(installation
        .load_engine(&fs::canonicalize(helper).unwrap())
        .is_err());
}

#[test]
fn embedded_helper_rejects_mutations_and_never_overwrites_stage_files() {
    let (temp, installation, marker) = fixture();
    let source = temp.path().join("source");
    let helper =
        fs::canonicalize(source.join("engines/latest/0.3.3/nelomai-windows-service.exe")).unwrap();
    let manifest = fs::read(source.join(d::MANIFEST_NAME)).unwrap();
    let signature = fs::read(source.join(d::SIGNATURE_NAME)).unwrap();
    let mut corrupted = manifest.clone();
    corrupted[0] ^= 1;
    assert!(installation
        .update_helper_payload(&corrupted, &signature, &helper)
        .is_err());
    let mut bad_signature = signature.clone();
    bad_signature[0] ^= 1;
    assert!(installation
        .update_helper_payload(&manifest, &bad_signature, &helper)
        .is_err());
    assert!(installation
        .update_helper_payload(&manifest, &signature[..63], &helper)
        .is_err());
    assert!(installation
        .update_helper_payload(&manifest, &signature, Path::new("relative.exe"))
        .is_err());
    let payload = installation
        .update_helper_payload(&manifest, &signature, &helper)
        .unwrap();
    // Mutating the temporary source after verification cannot change copied DATA.
    fs::write(&helper, b"foreign changed helper").unwrap();
    assert!(installation
        .update_helper_payload(&manifest, &signature, &helper)
        .is_err());
    let directory = temp.path().join("stage");
    fs::create_dir(&directory).unwrap();
    payload.write_stage(&directory).unwrap();
    assert_eq!(
        fs::read(directory.join("nelomai-windows-service.exe")).unwrap(),
        b"fake-native-engine"
    );
    assert!(payload.write_stage(&directory).is_err());
    assert_eq!(
        fs::read(directory.join(d::UPDATE_HELPER_MANIFEST_NAME)).unwrap(),
        manifest
    );
    assert_eq!(
        fs::read(installation.root.join(d::ACTIVE_ENGINE_NAME)).unwrap(),
        marker
    );
}

#[test]
fn protected_staged_helper_is_cleanup_only_and_keeps_old_identity() {
    let (temp, installation, marker) = fixture();
    let source = temp.path().join("source");
    let helper =
        fs::canonicalize(source.join("engines/latest/0.3.3/nelomai-windows-service.exe")).unwrap();
    let payload = installation
        .update_helper_payload(
            &fs::read(source.join(d::MANIFEST_NAME)).unwrap(),
            &fs::read(source.join(d::SIGNATURE_NAME)).unwrap(),
            &helper,
        )
        .unwrap();
    let stage = installation
        .root
        .join("update-recovery/stage-1234567890abcdef");
    fs::create_dir_all(&stage).unwrap();
    let executable = fs::canonicalize(payload.write_stage(&stage).unwrap()).unwrap();
    let role = RecoveryExecutable::StagedInstaller;
    assert!(role.require_engine().is_err());
    let old = role
        .load(
            &installation,
            &executable,
            nelomai_contracts::RuntimeSlot::Latest,
        )
        .unwrap();
    assert_eq!(old.identity, installation.load().unwrap().identity);
    assert!(role
        .load(
            &installation,
            &helper,
            nelomai_contracts::RuntimeSlot::Latest
        )
        .is_err());
    fs::write(stage.join(d::UPDATE_HELPER_SIGNATURE_NAME), [0; 64]).unwrap();
    assert!(role
        .load(
            &installation,
            &executable,
            nelomai_contracts::RuntimeSlot::Latest
        )
        .is_err());
    assert_eq!(
        fs::read(installation.root.join(d::ACTIVE_ENGINE_NAME)).unwrap(),
        marker
    );
}

#[test]
fn staged_cleanup_rejects_foreign_namespace_malformed_nonce_and_changed_old_runtime() {
    for fault in [
        "foreign-root",
        "uppercase-nonce",
        "short-nonce",
        "renamed-helper",
        "old-engine",
    ] {
        let (temp, installation, marker) = fixture();
        let source = temp.path().join("source");
        let helper =
            fs::canonicalize(source.join("engines/latest/0.3.3/nelomai-windows-service.exe"))
                .unwrap();
        let payload = installation
            .update_helper_payload(
                &fs::read(source.join(d::MANIFEST_NAME)).unwrap(),
                &fs::read(source.join(d::SIGNATURE_NAME)).unwrap(),
                &helper,
            )
            .unwrap();
        let stage = match fault {
            "foreign-root" => temp
                .path()
                .join("foreign/update-recovery/stage-1234567890abcdef"),
            "uppercase-nonce" => installation
                .root
                .join("update-recovery/stage-1234567890ABCDEf"),
            "short-nonce" => installation.root.join("update-recovery/stage-123"),
            _ => installation
                .root
                .join("update-recovery/stage-1234567890abcdef"),
        };
        fs::create_dir_all(&stage).unwrap();
        let mut executable = payload.write_stage(&stage).unwrap();
        if fault == "renamed-helper" {
            let renamed = stage.join("foreign.exe");
            fs::rename(&executable, &renamed).unwrap();
            executable = renamed;
        }
        if fault == "old-engine" {
            fs::write(
                installation.load().unwrap().engine_path(),
                b"changed old engine",
            )
            .unwrap();
        }
        assert!(
            RecoveryExecutable::StagedInstaller
                .load(
                    &installation,
                    &fs::canonicalize(executable).unwrap(),
                    nelomai_contracts::RuntimeSlot::Latest
                )
                .is_err(),
            "{fault}"
        );
        assert_eq!(
            fs::read(installation.root.join(d::ACTIVE_ENGINE_NAME)).unwrap(),
            marker
        );
    }
}

#[test]
fn installer_cleanup_rejects_wrong_executable_source_and_installed_identity() {
    for fault in [
        "installer-bytes",
        "installer-path",
        "source-signature",
        "source-engine",
        "installed-engine",
        "slot",
    ] {
        let (temp, installation, marker) = fixture();
        let source = temp.path().join("source");
        let installer = temp.path().join("nelomai-windows-service.exe");
        fs::copy(
            source.join("engines/latest/0.3.3/nelomai-windows-service.exe"),
            &installer,
        )
        .unwrap();
        let installed = installation.load().unwrap();
        let mut executable = fs::canonicalize(&installer).unwrap();
        let mut slot = installed.identity.slot;
        match fault {
            "installer-bytes" => fs::write(&installer, b"foreign executable").unwrap(),
            "installer-path" => {
                let other = temp.path().join("foreign.exe");
                fs::copy(&installer, &other).unwrap();
                executable = fs::canonicalize(other).unwrap();
            }
            "source-signature" => fs::write(source.join(d::SIGNATURE_NAME), [0; 64]).unwrap(),
            "source-engine" => fs::write(
                source.join("engines/latest/0.3.3/nelomai-windows-service.exe"),
                b"tampered",
            )
            .unwrap(),
            "installed-engine" => fs::write(installed.engine_path(), b"tampered").unwrap(),
            _ => slot = nelomai_contracts::RuntimeSlot::Stable,
        }
        assert!(
            installation
                .load_installer_recovery(&source, &executable, slot)
                .is_err(),
            "{fault}"
        );
        assert_eq!(
            fs::read(installation.root.join(d::ACTIVE_ENGINE_NAME)).unwrap(),
            marker,
            "{fault}"
        );
    }
}

#[test]
fn live_owner_or_dispatcher_mutation_fences_recovery_without_native_effects() {
    for name in ["engine-owner.lock", "mutation.lock"] {
        let (_temp, installation, bytes) = fixture();
        let _live = d::MutationGuard::at(&installation.root.join(name)).unwrap();
        assert!(recover(&installation, |_| panic!("live owner")).is_err());
        assert_eq!(
            fs::read(installation.root.join(d::ACTIVE_ENGINE_NAME)).unwrap(),
            bytes
        );
    }
}

#[test]
fn cleanup_failure_retains_exact_marker_and_prevents_publication() {
    let (_temp, installation, bytes) = fixture();
    let mut called = false;
    assert!(recover(&installation, |_| {
        called = true;
        Err(d::blocked())
    })
    .is_err());
    assert!(called);
    assert_eq!(
        fs::read(installation.root.join(d::ACTIVE_ENGINE_NAME)).unwrap(),
        bytes
    );
}

#[test]
fn invalid_identity_signature_or_engine_never_reaches_cleanup() {
    for fault in ["identity", "signature", "engine", "corrupt"] {
        let (_temp, installation, _) = fixture();
        let layout = installation.load().unwrap();
        let marker = installation.root.join(d::ACTIVE_ENGINE_NAME);
        match fault {
            "identity" => {
                let mut wrong = layout.identity.clone();
                wrong.manifest_sha256 = "f".repeat(64);
                fs::write(&marker, serde_json::to_vec(&wrong).unwrap()).unwrap();
            }
            "signature" => fs::write(layout.directory.join(d::SIGNATURE_NAME), [0; 64]).unwrap(),
            "engine" => fs::write(layout.engine_path(), b"tampered").unwrap(),
            _ => fs::write(&marker, b"corrupt").unwrap(),
        }
        let before = fs::read(&marker).unwrap();
        assert!(recover(&installation, |_| panic!("unverified owner")).is_err());
        assert_eq!(fs::read(&marker).unwrap(), before);
    }
}

#[test]
fn changed_marker_is_not_retired_after_cleanup() {
    let (_temp, installation, _) = fixture();
    let marker = installation.root.join(d::ACTIVE_ENGINE_NAME);
    let mut called = false;
    assert!(recover(&installation, |_| {
        called = true;
        fs::write(&marker, b"different owner")?;
        Ok(())
    })
    .is_err());
    assert!(called);
    assert_eq!(fs::read(marker).unwrap(), b"different owner");
}

#[test]
fn missing_marker_has_no_native_effects() {
    let (_temp, installation, _) = fixture();
    fs::remove_file(installation.root.join(d::ACTIVE_ENGINE_NAME)).unwrap();
    recover(&installation, |_| panic!("nothing to recover")).unwrap();
}

#[test]
fn recovery_transfers_same_held_owner_into_cleanup_and_retains_its_lifetime() {
    let (_temp, installation, bytes) = fixture();
    let path = installation.root.join("engine-owner.lock");
    let mut retained = None;
    recover_with_owner(&installation, |layout, owner| {
        assert_eq!(layout.identity.runtime_version, "0.3.3");
        assert_eq!(
            fs::read(installation.root.join(d::ACTIVE_ENGINE_NAME))?,
            bytes
        );
        owner.verify_at(&path)?;
        assert!(d::MutationGuard::at(&path).is_err());
        retained = Some(owner);
        Ok(())
    })
    .unwrap();
    assert!(!installation.root.join(d::ACTIVE_ENGINE_NAME).exists());
    retained.as_ref().unwrap().verify_at(&path).unwrap();
    assert!(d::MutationGuard::at(&path).is_err());
    drop(retained);
    assert!(d::MutationGuard::at(&path).is_ok());
}

#[cfg(unix)]
#[test]
fn recovery_owner_replacement_after_callback_preserves_marker_and_original() {
    let (_temp, installation, bytes) = fixture();
    let path = installation.root.join("engine-owner.lock");
    let original_path = installation.root.join("retained-owner.lock");
    let mut retained = None;
    assert!(recover_with_owner(&installation, |_, owner| {
        owner.verify_at(&path)?;
        fs::rename(&path, &original_path)?;
        fs::write(&path, b"replacement")?;
        retained = Some(owner);
        Ok(())
    })
    .is_err());
    assert!(retained.is_some());
    assert!(d::MutationGuard::at(&original_path).is_err());
    assert_eq!(
        fs::read(installation.root.join(d::ACTIVE_ENGINE_NAME)).unwrap(),
        bytes
    );
}

#[test]
fn recovery_callback_failure_or_unwind_keeps_transferred_owner_and_marker() {
    for unwind in [false, true] {
        let (_temp, installation, bytes) = fixture();
        let path = installation.root.join("engine-owner.lock");
        let mut retained = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            recover_with_owner(&installation, |_, owner| {
                owner.verify_at(&path)?;
                retained = Some(owner);
                if unwind {
                    panic!("after original cleanup owner was retained");
                }
                Err(d::blocked())
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert_eq!(
            fs::read(installation.root.join(d::ACTIVE_ENGINE_NAME)).unwrap(),
            bytes
        );
        retained.as_ref().unwrap().verify_at(&path).unwrap();
        assert!(d::MutationGuard::at(&path).is_err());
        drop(retained);
        assert!(d::MutationGuard::at(&path).is_ok());
    }
}

#[cfg(unix)]
#[test]
fn recovery_mutation_lock_replacement_after_cleanup_cannot_retire_marker() {
    let (_temp, installation, bytes) = fixture();
    let path = installation.root.join("mutation.lock");
    let mut called = false;
    assert!(recover_with_owner(&installation, |_, owner| {
        owner.verify_at(&installation.root.join("engine-owner.lock"))?;
        called = true;
        fs::rename(&path, installation.root.join("retained-mutation.lock"))?;
        fs::write(&path, b"replacement")?;
        Ok(())
    })
    .is_err());
    assert!(called);
    assert_eq!(
        fs::read(installation.root.join(d::ACTIVE_ENGINE_NAME)).unwrap(),
        bytes
    );
}
