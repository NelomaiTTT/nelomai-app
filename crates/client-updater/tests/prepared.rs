use nelomai_client_updater::{PreparedCache, PreparedUpdate, ResolvedUpdate};
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
    download
        .as_file_mut()
        .write_all(b"verified-by-platform")
        .unwrap();
    cache.commit_verified(download, descriptor).unwrap()
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
fn tampered_cached_package_rejected() {
    let root = tempfile::tempdir().unwrap();
    let cache = PreparedCache::open(root.path().join("packages")).unwrap();
    let package = commit(&cache, resolved("a"));
    std::fs::write(package.path(), b"tampered").unwrap();
    assert!(package.revalidate().is_err());
    assert!(cache.cached_path(&resolved("a")).unwrap().is_none());
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
    part.as_file_mut().write_all(b"incomplete").unwrap();
    let mut bad = resolved("b");
    bad.size_bytes = Some(500);
    assert!(cache.commit_verified(part, bad).is_err());
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
    assert!(!part.exists());
    assert!(!old_path.exists());
    assert!(foreign.exists());
    let mut next = resolved("b");
    next.version = "0.4.1".into();
    let prepared = commit(&cache, next);
    cache.recover("0.4.0").unwrap();
    assert!(prepared.path().exists());
}
