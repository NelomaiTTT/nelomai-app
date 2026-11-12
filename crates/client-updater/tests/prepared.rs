use nelomai_client_updater::DownloadValidator;
use nelomai_client_updater::{PreparedCache, PreparedUpdate, ResolvedUpdate};
use sha2::{Digest, Sha256};
use std::io::Write;
fn resolved(signature: &str) -> ResolvedUpdate {
    ResolvedUpdate {
        version: "0.4.1".into(),
        target: "test-target".into(),
        artifact_url: "https://nelomai.ru/api/client/v1/updates/artifacts/test".into(),
        signature: signature.into(),
        key_identity: "test-key".into(),
        sha256: None,
        size_bytes: None,
    }
}
fn commit(cache: &PreparedCache, descriptor: ResolvedUpdate) -> PreparedUpdate {
    let mut download = cache.begin().unwrap();
    download.write_all(b"verified-by-platform").unwrap();
    cache
        .commit_verified(download, descriptor, &sha256(b"verified-by-platform"))
        .unwrap()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
#[test]
fn partial_never_ready_and_abandoned_download_is_removed() {
    let root = tempfile::tempdir().unwrap();
    let cache = PreparedCache::open(root.path().join("packages")).unwrap();
    let part = cache.begin().unwrap();
    let path = part.path().to_owned();
    assert!(cache.cached_path(&resolved("a")).unwrap().is_none());
    drop(part);
    assert!(!path.exists());
}

#[test]
fn dropping_unverified_staging_preserves_a_replacement() {
    let root = tempfile::tempdir().unwrap();
    let cache = PreparedCache::open(root.path().join("packages")).unwrap();
    let mut staged = cache.begin().unwrap();
    staged.write_all(b"download prefix").unwrap();
    let path = staged.path().to_owned();
    let original = root.path().join("original");
    std::fs::rename(&path, &original).unwrap();
    std::fs::write(&path, b"foreign").unwrap();

    drop(staged);
    assert_eq!(std::fs::read(path).unwrap(), b"foreign");
    assert_eq!(std::fs::read(original).unwrap(), b"download prefix");
}

#[test]
fn publishing_an_interrupted_download_preserves_a_replaced_source() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("packages");
    let cache = PreparedCache::open(path.clone()).unwrap();
    let descriptor = resolved("partial source");
    let validator = DownloadValidator::new(&descriptor.artifact_url, "\"fixture\"", 11).unwrap();
    let mut staged = cache.begin().unwrap();
    staged.write_all(b"hello").unwrap();
    let staging = staged.path().to_owned();
    let original = root.path().join("original");
    std::fs::rename(&staging, &original).unwrap();
    std::fs::write(&staging, b"other").unwrap();

    assert!(cache.save_partial(staged, &descriptor, &validator).is_err());
    assert!(!path.join("resume-download.bin").exists());
    assert!(!path.join("resume-download.json").exists());
    assert_eq!(std::fs::read(staging).unwrap(), b"other");
    assert_eq!(std::fs::read(original).unwrap(), b"hello");
}

#[test]
fn interrupted_download_can_resume_after_reopen_only_for_the_same_artifact() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("packages");
    let descriptor = resolved("original signature");
    let cache = PreparedCache::open(path.clone()).unwrap();
    let mut part = cache.begin().unwrap();
    part.write_all(b"hello").unwrap();
    let validator = DownloadValidator::new(&descriptor.artifact_url, "\"artifact-a\"", 11).unwrap();
    cache.save_partial(part, &descriptor, &validator).unwrap();

    let cache = PreparedCache::open(path).unwrap();
    cache.recover("0.4.0").unwrap();
    assert!(cache.cached_path(&descriptor).unwrap().is_none());
    assert!(cache
        .partial(&resolved("different signature"))
        .unwrap()
        .is_none());
    let saved = cache.partial(&descriptor).unwrap().unwrap();
    assert_eq!(saved.received(), 5);
    for range in ["bytes 5-10/11", "Bytes 5-10/11", "BYTES 005-010/011"] {
        assert!(
            saved.accepts_range(&descriptor.artifact_url, "\"artifact-a\"", range, Some(6)),
            "{range}"
        );
    }
    for range in [
        "bytes 4-10/11",
        "bytes 5-9/11",
        "bytes 5-10/12",
        "bytes */11",
        "bytes 5-10/*",
        "items 5-10/11",
        "bytes +5-10/11",
        "bytes 5-10/18446744073709551616",
        "bytes 5-10/11, bytes 5-10/11",
    ] {
        assert!(!saved.accepts_range(&descriptor.artifact_url, "\"artifact-a\"", range, None));
    }
    assert!(!saved.accepts_range(
        &descriptor.artifact_url,
        "\"artifact-b\"",
        "bytes 5-10/11",
        Some(6)
    ));
    assert!(!saved.accepts_range(
        &descriptor.artifact_url,
        "W/\"artifact-a\"",
        "bytes 5-10/11",
        Some(6)
    ));
    assert!(!saved.accepts_range(
        &descriptor.artifact_url.replace(".ru", ".top"),
        "\"artifact-a\"",
        "bytes 5-10/11",
        Some(6)
    ));
    assert!(!saved.accepts_range(
        &descriptor.artifact_url,
        "\"artifact-a\"",
        "bytes 5-10/11",
        Some(5)
    ));
    let mut next = cache.begin_resume(saved).unwrap();
    next.write_all(b" world").unwrap();
    let complete = cache.finish_resume(next).unwrap();
    assert_eq!(std::fs::read(complete.path()).unwrap(), b"hello world");
    assert!(cache.partial(&descriptor).unwrap().is_none());
}
#[test]
fn resume_uses_the_durable_checkpoint_after_an_abandoned_append() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("packages");
    let descriptor = resolved("original signature");
    let cache = PreparedCache::open(path.clone()).unwrap();
    let mut part = cache.begin().unwrap();
    part.write_all(b"hello").unwrap();
    let validator = DownloadValidator::new(&descriptor.artifact_url, "\"artifact-a\"", 11).unwrap();
    cache.save_partial(part, &descriptor, &validator).unwrap();

    // A process can stop after writing a suffix but before publishing its length.
    let mut data = std::fs::OpenOptions::new()
        .append(true)
        .open(path.join("resume-download.bin"))
        .unwrap();
    data.write_all(b" stale").unwrap();
    data.sync_all().unwrap();
    drop((data, cache));

    let cache = PreparedCache::open(path).unwrap();
    cache.recover("0.4.0").unwrap();
    let saved = cache.partial(&descriptor).unwrap().unwrap();
    assert_eq!(saved.received(), 5);
    let mut resumed = cache.begin_resume(saved).unwrap();
    resumed.write_all(b" wo").unwrap();
    cache.checkpoint_resume(resumed).unwrap();
    let saved = cache.partial(&descriptor).unwrap().unwrap();
    assert_eq!(saved.received(), 8);
    let mut resumed = cache.begin_resume(saved).unwrap();
    resumed.write_all(b"rld").unwrap();
    let complete = cache.finish_resume(resumed).unwrap();
    assert_eq!(std::fs::read(complete.path()).unwrap(), b"hello world");
}

#[test]
fn verified_full_package_cleans_the_checkpoint_for_the_same_artifact() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("packages");
    let cache = PreparedCache::open(path.clone()).unwrap();
    let descriptor = resolved("original signature");
    let validator = DownloadValidator::new(&descriptor.artifact_url, "\"artifact-a\"", 11).unwrap();
    let mut partial = cache.begin().unwrap();
    partial.write_all(b"hello").unwrap();
    cache
        .save_partial(partial, &descriptor, &validator)
        .unwrap();

    let mut complete = cache.begin().unwrap();
    complete.write_all(b"hello world").unwrap();
    let prepared = cache
        .commit_verified(complete, descriptor.clone(), &sha256(b"hello world"))
        .unwrap();
    prepared.revalidate().unwrap();
    assert!(cache.partial(&descriptor).unwrap().is_none());
    assert!(!path.join("resume-download.bin").exists());
    assert!(!path.join("resume-download.json").exists());
}
#[test]
fn a_range_offer_cannot_append_to_a_replacement_cache_entry() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("packages");
    let cache = PreparedCache::open(path.clone()).unwrap();
    let descriptor = resolved("signature");
    let validator = DownloadValidator::new(&descriptor.artifact_url, "\"artifact-a\"", 11).unwrap();
    let mut part = cache.begin().unwrap();
    part.write_all(b"hello").unwrap();
    cache.save_partial(part, &descriptor, &validator).unwrap();
    let saved = cache.partial(&descriptor).unwrap().unwrap();

    let data = path.join("resume-download.bin");
    std::fs::rename(&data, root.path().join("first")).unwrap();
    std::fs::write(&data, b"other").unwrap();
    assert!(cache.begin_resume(saved).is_err());
    assert_eq!(std::fs::read(&data).unwrap(), b"other");
}

#[cfg(unix)]
#[test]
fn checkpoint_survives_a_changed_mount_device_number() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("packages");
    let cache = PreparedCache::open(path.clone()).unwrap();
    let descriptor = resolved("signature");
    let validator = DownloadValidator::new(&descriptor.artifact_url, "\"fixture\"", 11).unwrap();
    let mut file = cache.begin().unwrap();
    file.write_all(b"hello").unwrap();
    cache.save_partial(file, &descriptor, &validator).unwrap();

    let sidecar = path.join("resume-download.json");
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&sidecar).unwrap()).unwrap();
    for name in ["data_identity", "sidecar_identity"] {
        let old = json[name]["volume"].as_u64().unwrap();
        json[name]["volume"] = (old ^ 1).into();
    }
    std::fs::write(sidecar, serde_json::to_vec(&json).unwrap()).unwrap();
    let restarted = PreparedCache::open(path).unwrap();
    restarted.recover("0.4.0").unwrap();
    assert_eq!(
        restarted.partial(&descriptor).unwrap().unwrap().received(),
        5
    );
}

#[test]
fn replacement_partial_is_never_admitted_or_removed_on_restart() {
    for replacement in [b"other".as_slice(), b"foreign contents".as_slice()] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("packages");
        let cache = PreparedCache::open(path.clone()).unwrap();
        let descriptor = resolved("signature");
        let validator =
            DownloadValidator::new(&descriptor.artifact_url, "\"fixture\"", 11).unwrap();
        let mut file = cache.begin().unwrap();
        file.write_all(b"hello").unwrap();
        cache.save_partial(file, &descriptor, &validator).unwrap();

        let data = path.join("resume-download.bin");
        std::fs::rename(&data, root.path().join("original")).unwrap();
        std::fs::write(&data, replacement).unwrap();
        assert!(cache.partial(&descriptor).unwrap().is_none());

        let restarted = PreparedCache::open(path).unwrap();
        restarted.recover(&descriptor.version).unwrap();
        assert_eq!(std::fs::read(&data).unwrap(), replacement);
        assert!(restarted.partial(&descriptor).unwrap().is_none());
    }
}

#[test]
fn hard_linked_partial_is_never_admitted_for_writes() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("packages");
    let cache = PreparedCache::open(path.clone()).unwrap();
    let descriptor = resolved("signature");
    let validator = DownloadValidator::new(&descriptor.artifact_url, "\"artifact-a\"", 11).unwrap();
    let mut part = cache.begin().unwrap();
    part.write_all(b"hello").unwrap();
    cache.save_partial(part, &descriptor, &validator).unwrap();
    let saved = cache.partial(&descriptor).unwrap().unwrap();

    let outside = root.path().join("outside");
    std::fs::hard_link(path.join("resume-download.bin"), &outside).unwrap();
    assert!(cache.partial(&descriptor).unwrap().is_none());
    assert!(cache.begin_resume(saved).is_err());
    cache.discard_partial().unwrap();
    assert_eq!(std::fs::read(outside).unwrap(), b"hello");
}

#[cfg(unix)]
#[test]
fn a_cache_writable_by_other_unix_users_cannot_stage_an_installer() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("packages");
    let cache = PreparedCache::open(path.clone()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o775)).unwrap();
    assert!(cache.begin().is_err());
    assert_eq!(std::fs::read_dir(path).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn existing_nonprivate_cache_can_stage_fresh_without_resuming_in_place() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("packages");
    let cache = PreparedCache::open(path.clone()).unwrap();
    let descriptor = resolved("signature");
    let validator = DownloadValidator::new(&descriptor.artifact_url, "\"artifact-a\"", 11).unwrap();
    let mut part = cache.begin().unwrap();
    part.write_all(b"hello").unwrap();
    cache.save_partial(part, &descriptor, &validator).unwrap();
    let saved = cache.partial(&descriptor).unwrap().unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    drop(cache);

    let cache = PreparedCache::open(path).unwrap();
    cache.recover("0.4.0").unwrap();
    assert!(cache.partial(&descriptor).unwrap().is_none());
    assert!(cache.begin_resume(saved).is_err());
    assert!(commit(&cache, descriptor).revalidate().is_ok());
}

#[cfg(unix)]
#[test]
fn nonprivate_cache_drops_an_interrupted_download_without_publishing_a_checkpoint() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("packages");
    let cache = PreparedCache::open(path.clone()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let descriptor = resolved("fresh");
    let validator = DownloadValidator::new(&descriptor.artifact_url, "\"fixture\"", 11).unwrap();
    let mut file = cache.begin().unwrap();
    file.write_all(b"hello").unwrap();
    cache.save_partial(file, &descriptor, &validator).unwrap();
    assert_eq!(std::fs::read_dir(path).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn nonprivate_cache_keeps_verified_bytes_only_for_the_temporary_lease() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("packages");
    let cache = PreparedCache::open(path.clone()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let descriptor = resolved("fresh");
    let prepared = commit(&cache, descriptor.clone());
    let staged = prepared.path().to_owned();
    assert_eq!(std::fs::read(&staged).unwrap(), b"verified-by-platform");
    assert!(cache.cached_path(&descriptor).unwrap().is_none());
    cache.consumed(&prepared).unwrap();
    drop(prepared);
    assert!(!staged.exists());
    assert_eq!(std::fs::read_dir(path).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn fresh_only_cache_recovers_owned_staging_and_preserves_unowned_names() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("packages");
    let cache = PreparedCache::open(path.clone()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut staged = cache.begin().unwrap();
    staged.write_all(b"abandoned bytes").unwrap();
    let (file, staged_path) = staged.keep().unwrap();
    drop(file);
    let mut uncertain = cache.begin().unwrap();
    uncertain.write_all(b"unproved record").unwrap();
    let (file, uncertain_path) = uncertain.keep().unwrap();
    drop((file, cache));
    let marker = uncertain_path.with_file_name(format!(
        "{}.owner",
        uncertain_path.file_name().unwrap().to_str().unwrap()
    ));
    std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o666)).unwrap();
    let foreign = path.join(".package-ABC123.part");
    std::fs::write(&foreign, b"foreign bytes").unwrap();

    let cache = PreparedCache::open(path).unwrap();
    cache.recover("0.4.0").unwrap();
    assert!(!staged_path.exists());
    assert_eq!(std::fs::read(foreign).unwrap(), b"foreign bytes");
    assert_eq!(std::fs::read(uncertain_path).unwrap(), b"unproved record");
    assert!(marker.exists());
}

#[test]
fn origin_checkpoints_survive_restart_and_commit_retires_both() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("packages");
    let cache = PreparedCache::open(path.clone()).unwrap();
    let descriptor = resolved("two origins");
    let primary_url = &descriptor.artifact_url;
    let alternate_url = primary_url.replace("nelomai.ru", "nelomai.top");
    let primary = DownloadValidator::new(primary_url, "\"primary\"", 11).unwrap();
    let alternate = DownloadValidator::new(&alternate_url, "\"alternate\"", 11).unwrap();
    for (validator, prefix) in [
        (&primary, b"one".as_slice()),
        (&alternate, b"second".as_slice()),
    ] {
        let mut file = cache.begin().unwrap();
        file.write_all(prefix).unwrap();
        cache.save_partial(file, &descriptor, validator).unwrap();
    }
    drop(cache);

    let cache = PreparedCache::open(path).unwrap();
    cache.recover("0.4.0").unwrap();
    let primary = cache
        .download_partial_for(&descriptor, false)
        .unwrap()
        .unwrap();
    let alternate = cache
        .download_partial_for(&descriptor, true)
        .unwrap()
        .unwrap();
    assert!(primary.accepts_range(primary_url, "\"primary\"", "bytes 3-10/11", Some(8)));
    assert!(alternate.accepts_range(&alternate_url, "\"alternate\"", "bytes 6-10/11", Some(5)));
    assert!(primary.etag_for(&alternate_url).is_none());
    assert!(alternate.etag_for(primary_url).is_none());

    let mut primary = cache.begin_resume(primary).unwrap();
    primary.write_all(b" and").unwrap();
    cache.checkpoint_resume(primary).unwrap();

    let mut alternate = cache.begin_resume(alternate).unwrap();
    alternate.write_all(b" only").unwrap();
    let complete = cache.finish_resume(alternate).unwrap();
    assert_eq!(std::fs::read(complete.path()).unwrap(), b"second only");
    assert_eq!(
        cache
            .download_partial_for(&descriptor, false)
            .unwrap()
            .unwrap()
            .received(),
        7
    );

    // A completed signed package invalidates any other checkpoint for it.
    let mut alternate = cache.begin().unwrap();
    alternate.write_all(b"later").unwrap();
    let validator = DownloadValidator::new(&alternate_url, "\"later\"", 11).unwrap();
    cache
        .save_partial(alternate, &descriptor, &validator)
        .unwrap();
    let _prepared = cache
        .commit_verified(complete, descriptor.clone(), &sha256(b"second only"))
        .unwrap();
    assert!(cache
        .download_partial_for(&descriptor, false)
        .unwrap()
        .is_none());
    assert!(cache
        .download_partial_for(&descriptor, true)
        .unwrap()
        .is_none());
}

#[test]
fn readmitting_a_verified_package_retries_interrupted_checkpoint_cleanup() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("packages");
    let cache = PreparedCache::open(path.clone()).unwrap();
    let descriptor = resolved("cache cleanup retry");
    drop(commit(&cache, descriptor.clone()));

    // Leave the on-disk state a crash between publication and cleanup could leave.
    let alternate = descriptor.artifact_url.replace("nelomai.ru", "nelomai.top");
    for url in [&descriptor.artifact_url, &alternate] {
        let validator = DownloadValidator::new(url, "\"saved\"", 11).unwrap();
        let mut prefix = cache.begin().unwrap();
        prefix.write_all(b"partial").unwrap();
        cache.save_partial(prefix, &descriptor, &validator).unwrap();
    }
    drop(cache);

    let cache = PreparedCache::open(path).unwrap();
    cache.recover("0.4.0").unwrap();
    let (_, verified) = cache.open_cached_package(&descriptor).unwrap().unwrap();
    assert_eq!(
        cache
            .admit_verified(descriptor.clone(), &verified, &sha256(b"other bytes"))
            .unwrap_err()
            .code(),
        "update_hash_mismatch"
    );
    // The platform re-verifies the signature before re-admitting these bytes.
    let prepared = cache
        .admit_verified(
            descriptor.clone(),
            &verified,
            &sha256(b"verified-by-platform"),
        )
        .unwrap();
    prepared.revalidate().unwrap();
    for is_alternate in [false, true] {
        assert!(cache
            .download_partial_for(&descriptor, is_alternate)
            .unwrap()
            .is_none());
    }
}

#[test]
fn readmitting_a_replaced_package_preserves_the_checkpoint() {
    let root = tempfile::tempdir().unwrap();
    let cache = PreparedCache::open(root.path().join("packages")).unwrap();
    let descriptor = resolved("cache ownership");
    drop(commit(&cache, descriptor.clone()));

    let validator = DownloadValidator::new(&descriptor.artifact_url, "\"saved\"", 11).unwrap();
    let mut prefix = cache.begin().unwrap();
    prefix.write_all(b"partial").unwrap();
    cache.save_partial(prefix, &descriptor, &validator).unwrap();

    let (package, verified) = cache.open_cached_package(&descriptor).unwrap().unwrap();
    let original = root.path().join("original");
    std::fs::rename(&package, &original).unwrap();
    std::fs::copy(&original, &package).unwrap();

    let replacement = std::fs::File::open(&package).unwrap();
    for file in [&verified, &replacement] {
        assert!(cache
            .admit_verified(descriptor.clone(), file, &sha256(b"verified-by-platform"))
            .is_err());
    }
    assert!(cache.cached_path(&descriptor).unwrap().is_none());
    assert_eq!(cache.partial(&descriptor).unwrap().unwrap().received(), 7);
    assert_eq!(std::fs::read(&package).unwrap(), b"verified-by-platform");
}

#[test]
fn restart_reuses_verified_bytes_not_consent() {
    let root = tempfile::tempdir().unwrap();
    let cache = PreparedCache::open(root.path().join("packages")).unwrap();
    let package = commit(&cache, resolved("a"));
    let restarted = PreparedCache::open(root.path().join("packages")).unwrap();
    assert_eq!(
        restarted.cached_path(&resolved("a")).unwrap().as_deref(),
        Some(package.path())
    );
    assert!(restarted.cached_path(&resolved("b")).unwrap().is_none());
}
#[test]
fn corrupted_owned_package_is_rejected_then_replaced_by_verified_bytes() {
    let root = tempfile::tempdir().unwrap();
    let cache = PreparedCache::open(root.path().join("packages")).unwrap();
    let descriptor = resolved("a");
    let package = commit(&cache, descriptor.clone());
    let canonical = package.path().to_owned();
    std::fs::write(package.path(), b"tampered").unwrap();
    assert!(package.revalidate().is_err());
    assert!(cache.cached_path(&descriptor).unwrap().is_none());
    drop(package);

    let replacement = commit(&cache, descriptor.clone());
    assert_eq!(replacement.path(), canonical);
    drop(replacement);
    let restarted = PreparedCache::open(root.path().join("packages")).unwrap();
    restarted.recover("0.4.0").unwrap();
    assert_eq!(restarted.cached_path(&descriptor).unwrap(), Some(canonical));
}
#[test]
fn active_installer_file_not_pruned() {
    let root = tempfile::tempdir().unwrap();
    let cache = PreparedCache::open(root.path().join("packages")).unwrap();
    let old = commit(&cache, resolved("a"));
    let path = old.path().to_owned();
    let active = old.clone();
    let new = commit(&cache, resolved("b"));
    drop(old);
    cache.prune_except(new.resolved()).unwrap();
    assert!(path.exists());
    drop(active);
    cache.prune_except(new.resolved()).unwrap();
    assert!(!path.exists());
    assert!(new.path().exists());
}
#[test]
fn failed_new_download_preserves_ready_package_and_foreign_files() {
    let root = tempfile::tempdir().unwrap();
    let cache = PreparedCache::open(root.path().join("packages")).unwrap();
    let old = commit(&cache, resolved("a"));
    let mut part = cache.begin().unwrap();
    part.write_all(b"incomplete").unwrap();
    let mut bad = resolved("b");
    bad.size_bytes = Some(500);
    assert!(cache
        .commit_verified(part, bad, &sha256(b"incomplete"))
        .is_err());
    assert!(old.revalidate().is_ok());
    let foreign = root.path().join("packages/user-download.zip");
    std::fs::write(&foreign, b"keep").unwrap();
    cache.prune_except(old.resolved()).unwrap();
    assert!(foreign.exists());
}
#[test]
#[cfg(unix)]
fn cache_cleanup_does_not_follow_links() {
    let root = tempfile::tempdir().unwrap();
    let cache = PreparedCache::open(root.path().join("packages")).unwrap();
    let outside = root.path().join("outside");
    std::fs::write(&outside, b"keep").unwrap();
    let link = root
        .path()
        .join("packages")
        .join(format!("package-{}.bin", "a".repeat(64)));
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    cache.prune_except(&resolved("b")).unwrap();
    assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
    assert!(std::fs::symlink_metadata(link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(PreparedCache::open(root.path().join("alias")).is_ok());
    let alias = root.path().join("bad-root");
    std::os::unix::fs::symlink(root.path().join("packages"), &alias).unwrap();
    assert!(PreparedCache::open(alias).is_err());
}
#[test]
fn cleanup_preserves_replaced_prepared_packages() {
    for cleanup in ["recover", "prune", "consumed"] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("packages");
        let cache = PreparedCache::open(path.clone()).unwrap();
        let descriptor = resolved("old");
        let old = commit(&cache, descriptor.clone());
        let package = old.path().to_owned();
        std::fs::rename(&package, root.path().join("old")).unwrap();
        std::fs::write(&package, b"foreign bytes").unwrap();
        match cleanup {
            "recover" => {
                drop(old);
                drop(cache);
                let restarted = PreparedCache::open(path).unwrap();
                restarted.recover(&descriptor.version).unwrap();
            }
            "prune" => {
                drop(old);
                cache.prune_except(&resolved("new")).unwrap();
            }
            "consumed" => cache.consumed(&old).unwrap(),
            _ => unreachable!(),
        }
        assert_eq!(
            std::fs::read(package).unwrap(),
            b"foreign bytes",
            "{cleanup}"
        );
    }
}

#[test]
fn commit_does_not_overwrite_an_unowned_canonical_name() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("packages");
    let cache = PreparedCache::open(path.clone()).unwrap();
    let descriptor = resolved("new");
    let package = path.join(format!("package-{}.bin", descriptor.cache_key().unwrap()));
    std::fs::write(&package, b"foreign bytes").unwrap();
    let prepared = commit(&cache, descriptor);
    assert_eq!(std::fs::read(&package).unwrap(), b"foreign bytes");
    assert_eq!(
        std::fs::read(prepared.path()).unwrap(),
        b"verified-by-platform"
    );
    cache.consumed(&prepared).unwrap();
    let staging = prepared.path().to_owned();
    drop(prepared);
    assert!(!staging.exists());
    assert_eq!(std::fs::read(&package).unwrap(), b"foreign bytes");
}

#[test]
fn dropping_a_temporary_verified_lease_preserves_a_replaced_staging_file() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("packages");
    let cache = PreparedCache::open(path.clone()).unwrap();
    let descriptor = resolved("temporary");
    let canonical = path.join(format!("package-{}.bin", descriptor.cache_key().unwrap()));
    std::fs::write(&canonical, b"canonical occupant").unwrap();
    let prepared = commit(&cache, descriptor);
    let staging = prepared.path().to_owned();
    let original = root.path().join("original");
    std::fs::rename(&staging, &original).unwrap();
    std::fs::write(&staging, b"new occupant").unwrap();

    drop(prepared);
    assert_eq!(std::fs::read(staging).unwrap(), b"new occupant");
    assert_eq!(std::fs::read(original).unwrap(), b"verified-by-platform");
    assert_eq!(std::fs::read(canonical).unwrap(), b"canonical occupant");
}

#[test]
fn legacy_prepared_package_stays_readable_without_authorizing_cleanup() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("packages");
    let cache = PreparedCache::open(path.clone()).unwrap();
    let descriptor = resolved("legacy");
    let prepared = commit(&cache, descriptor.clone());
    let package = prepared.path().to_owned();
    let sidecar = package.with_extension("json");
    let mut legacy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&sidecar).unwrap()).unwrap();
    legacy.as_object_mut().unwrap().remove("ownership");
    std::fs::write(&sidecar, serde_json::to_vec(&legacy).unwrap()).unwrap();
    drop(prepared);

    let original = root.path().join("original");
    std::fs::rename(&package, &original).unwrap();
    std::fs::copy(&original, &package).unwrap();
    let validator = DownloadValidator::new(&descriptor.artifact_url, "\"saved\"", 11).unwrap();
    let mut prefix = cache.begin().unwrap();
    prefix.write_all(b"partial").unwrap();
    cache.save_partial(prefix, &descriptor, &validator).unwrap();
    drop(cache);

    let cache = PreparedCache::open(path).unwrap();
    cache.recover("0.4.0").unwrap();
    let (cached_path, file) = cache.open_cached_package(&descriptor).unwrap().unwrap();
    assert_eq!(cached_path, package);
    assert!(cache.partial(&descriptor).unwrap().is_some());
    let prepared = cache
        .admit_verified(descriptor.clone(), &file, &sha256(b"verified-by-platform"))
        .unwrap();
    prepared.revalidate().unwrap();
    assert_eq!(
        cache
            .partial(&descriptor)
            .unwrap()
            .map(|part| part.received()),
        Some(7)
    );

    drop((prepared, file));
    cache.recover(&descriptor.version).unwrap();
    cache.prune_except(&resolved("new")).unwrap();
    assert_eq!(std::fs::read(package).unwrap(), b"verified-by-platform");
    assert!(sidecar.is_file());
}

#[test]
fn recovery_removes_an_owned_stage_and_preserves_its_replacement() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("packages");
    let cache = PreparedCache::open(path.clone()).unwrap();
    let mut owned = cache.begin().unwrap();
    owned.write_all(b"abandoned").unwrap();
    let (owned_handle, owned_path) = owned.keep().unwrap();
    drop(owned_handle);

    let mut replaced = cache.begin().unwrap();
    replaced.write_all(b"staging data").unwrap();
    let (replaced_handle, replaced_path) = replaced.keep().unwrap();
    drop(replaced_handle);
    std::fs::rename(&replaced_path, root.path().join("original")).unwrap();
    std::fs::write(&replaced_path, b"foreign bytes").unwrap();
    drop(cache);

    let cache = PreparedCache::open(path).unwrap();
    cache.recover("0.4.0").unwrap();
    assert!(!owned_path.exists());
    assert_eq!(std::fs::read(replaced_path).unwrap(), b"foreign bytes");
}

#[test]
fn recovery_recognizes_the_resumed_inode_promoted_into_staging() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("packages");
    let cache = PreparedCache::open(path.clone()).unwrap();
    let descriptor = resolved("resumed");
    let validator = DownloadValidator::new(&descriptor.artifact_url, "\"fixture\"", 11).unwrap();
    let mut partial = cache.begin().unwrap();
    partial.write_all(b"hello").unwrap();
    cache
        .save_partial(partial, &descriptor, &validator)
        .unwrap();
    let mut resumed = cache
        .begin_resume(cache.partial(&descriptor).unwrap().unwrap())
        .unwrap();
    resumed.write_all(b" world").unwrap();
    let staging = cache.finish_resume(resumed).unwrap();
    let (file, staged_path) = staging.keep().unwrap();
    drop((file, cache));

    let cache = PreparedCache::open(path).unwrap();
    cache.recover("0.4.0").unwrap();
    assert!(!staged_path.exists());
}

#[test]
fn startup_removes_owned_abandoned_parts_and_installed_packages_only() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("packages");
    let cache = PreparedCache::open(path.clone()).unwrap();
    let mut old = resolved("a");
    old.version = "0.4.0".into();
    let package = commit(&cache, old);
    let old_path = package.path().to_owned();
    drop(package);
    drop(cache);
    let part = path.join(".package-ABC123.part");
    let foreign = path.join("user.dmg");
    std::fs::write(&part, b"interrupted").unwrap();
    std::fs::write(&foreign, b"keep").unwrap();
    let cache = PreparedCache::open(path).unwrap();
    cache.recover("0.4.0").unwrap();
    assert_eq!(std::fs::read(part).unwrap(), b"interrupted");
    assert!(!old_path.exists());
    assert!(foreign.exists());
    let mut next = resolved("b");
    next.version = "0.4.1".into();
    let prepared = commit(&cache, next);
    cache.recover("0.4.0").unwrap();
    assert!(prepared.path().exists());
}
