use super::*;
use std::{
    collections::HashMap,
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::Path,
    sync::{Arc, Mutex},
};

const AUTH: &str = "auth-v1";
const RUNTIME: &str = "runtime/stable/state/0.3.11/state-v1.json";
const SECRET: &[u8] = b"synthetic auth token kept out of the filesystem";

#[derive(Default)]
struct TestKeychain(Mutex<HashMap<Uuid, [u8; 32]>>);

impl VaultKeychain for TestKeychain {
    fn load(&self, installation: Uuid) -> Result<Option<VaultKey>, StorageError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(&installation)
            .copied()
            .map(VaultKey::new))
    }

    fn add(&self, installation: Uuid, key: &[u8; 32]) -> Result<(), StorageError> {
        use std::collections::hash_map::Entry;
        match self.0.lock().unwrap().entry(installation) {
            Entry::Occupied(_) => Err(StorageError::RecoveryRequired("duplicate test key")),
            Entry::Vacant(entry) => {
                entry.insert(*key);
                Ok(())
            }
        }
    }
}

fn vault_test_dir() -> tempfile::TempDir {
    // macOS can report TMPDIR through /var, a symlink to /private/var.
    // Resolve the fixture base before creating paths for the vault to check.
    let base = std::env::temp_dir().canonicalize().unwrap();
    tempfile::tempdir_in(base).unwrap()
}

fn owner() -> (tempfile::TempDir, Arc<ContainerOwnerLock>) {
    let root = vault_test_dir();
    let lock = Arc::new(ContainerOwnerLock::try_acquire_for_macos_vault(root.path()).unwrap());
    (root, lock)
}

fn files(owner: &ContainerOwnerLock) -> Vec<std::path::PathBuf> {
    let mut paths: Vec<_> = fs::read_dir(owner.root().join("common/vault-v1"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "record"))
        .collect();
    paths.sort();
    paths
}

#[test]
fn authenticated_files_round_trip_with_private_modes_and_fresh_nonces() {
    let (_root, owner) = owner();
    let keys = TestKeychain::default();
    let id = Uuid::from_u128(1);
    let vault = MacosVault::initialize_with_keychain(owner.clone(), id, &keys).unwrap();
    assert!(vault.read(AUTH).unwrap().is_none());
    vault.write(AUTH, SECRET).unwrap();
    let path = files(&owner).pop().unwrap();
    let first = fs::read(&path).unwrap();
    assert!(!first.windows(SECRET.len()).any(|bytes| bytes == SECRET));
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    vault.write(AUTH, SECRET).unwrap();
    assert_ne!(fs::read(path).unwrap(), first);
    vault.write(RUNTIME, b"runtime bytes").unwrap();
    drop(vault);

    let reopened = MacosVault::open_with_keychain(owner, id, &keys).unwrap();
    assert_eq!(reopened.read(AUTH).unwrap().unwrap().as_ref(), SECRET);
    assert_eq!(
        reopened.read(RUNTIME).unwrap().unwrap().as_ref(),
        b"runtime bytes"
    );
    assert_eq!(keys.0.lock().unwrap().len(), 1);
}

#[test]
fn file_cannot_be_moved_to_another_namespace_or_modified() {
    let (_root, owner) = owner();
    let keys = TestKeychain::default();
    let vault =
        MacosVault::initialize_with_keychain(owner.clone(), Uuid::from_u128(1), &keys).unwrap();
    vault.write(AUTH, SECRET).unwrap();
    let auth_path = files(&owner).pop().unwrap();
    vault.write(RUNTIME, b"runtime bytes").unwrap();
    let runtime_path = files(&owner)
        .into_iter()
        .find(|path| *path != auth_path)
        .unwrap();
    let auth = fs::read(&auth_path).unwrap();
    let runtime = fs::read(&runtime_path).unwrap();
    fs::write(&auth_path, &runtime).unwrap();
    fs::write(&runtime_path, &auth).unwrap();
    assert!(vault.read(AUTH).is_err());
    assert!(vault.read(RUNTIME).is_err());

    fs::write(&runtime_path, &runtime).unwrap();
    let mut damaged = auth;
    *damaged.last_mut().unwrap() ^= 1;
    fs::write(&auth_path, &damaged).unwrap();
    assert!(vault.read(AUTH).is_err());
    assert!(vault.write(AUTH, b"replacement").is_err());
    assert_eq!(fs::read(auth_path).unwrap(), damaged);
}

#[test]
fn same_key_cannot_open_another_installations_vault_or_records() {
    let (_root, first_owner) = owner();
    let (_other_root, second_owner) = owner();
    let keys = TestKeychain::default();
    let first = Uuid::from_u128(1);
    let second = Uuid::from_u128(2);
    let vault = MacosVault::initialize_with_keychain(first_owner.clone(), first, &keys).unwrap();
    vault.write(AUTH, SECRET).unwrap();
    let key = *keys.0.lock().unwrap().get(&first).unwrap();
    keys.0.lock().unwrap().insert(second, key);
    assert!(MacosVault::open_with_keychain(first_owner.clone(), second, &keys).is_err());

    let other = MacosVault::initialize_with_keychain(second_owner.clone(), second, &keys).unwrap();
    other.write(AUTH, b"different installation").unwrap();
    fs::copy(
        files(&first_owner).pop().unwrap(),
        files(&second_owner).pop().unwrap(),
    )
    .unwrap();
    assert!(other.read(AUTH).is_err());
}

#[test]
fn existing_vault_with_lost_key_is_never_reinitialized() {
    let (_root, owner) = owner();
    let keys = TestKeychain::default();
    let id = Uuid::from_u128(1);
    let vault = MacosVault::initialize_with_keychain(owner.clone(), id, &keys).unwrap();
    vault.write(AUTH, SECRET).unwrap();
    let path = files(&owner).pop().unwrap();
    let original = fs::read(&path).unwrap();
    drop(vault);
    keys.0.lock().unwrap().clear();

    assert!(MacosVault::open_with_keychain(owner.clone(), id, &keys).is_err());
    assert!(MacosVault::initialize_with_keychain(owner, id, &keys).is_err());
    assert!(keys.0.lock().unwrap().is_empty());
    assert_eq!(fs::read(path).unwrap(), original);
}

#[test]
fn provisioning_reuses_key_after_interruption_before_directory_commit() {
    let (_root, owner) = owner();
    let keys = TestKeychain::default();
    let id = Uuid::from_u128(1);
    let existing = [77; 32];
    keys.add(id, &existing).unwrap();
    assert!(MacosVault::open_with_keychain(owner.clone(), id, &keys).is_err());
    let vault = MacosVault::initialize_with_keychain(owner.clone(), id, &keys).unwrap();
    vault.write(AUTH, SECRET).unwrap();
    drop(vault);
    assert_eq!(keys.0.lock().unwrap().get(&id), Some(&existing));
    let reopened = MacosVault::open_with_keychain(owner, id, &keys).unwrap();
    assert_eq!(reopened.read(AUTH).unwrap().unwrap().as_ref(), SECRET);
}

#[test]
fn linked_record_is_rejected_without_touching_its_target() {
    let (root, owner) = owner();
    let keys = TestKeychain::default();
    let vault =
        MacosVault::initialize_with_keychain(owner.clone(), Uuid::from_u128(1), &keys).unwrap();
    vault.write(AUTH, SECRET).unwrap();
    let path = files(&owner).pop().unwrap();
    let outside = root.path().join("outside");
    let original = fs::read(&path).unwrap();
    fs::rename(&path, &outside).unwrap();
    symlink(&outside, &path).unwrap();
    assert!(vault.read(AUTH).is_err());
    assert!(vault.write(AUTH, b"replacement").is_err());
    assert_eq!(fs::read(&outside).unwrap(), original);
    assert!(fs::symlink_metadata(path).unwrap().file_type().is_symlink());
}

#[test]
fn open_vault_rejects_replacement_of_its_common_or_vault_directory() {
    for relative in ["common", "common/vault-v1"] {
        let (root, owner) = owner();
        let keys = TestKeychain::default();
        let id = Uuid::from_u128(1);
        let vault = MacosVault::initialize_with_keychain(owner, id, &keys).unwrap();
        vault.write(AUTH, SECRET).unwrap();
        let live = root.path().join(relative);
        fs::rename(&live, root.path().join("original")).unwrap();
        let replacement = root.path().join("common/vault-v1");
        fs::create_dir_all(&replacement).unwrap();
        for directory in [live, replacement.clone()] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }

        assert!(vault.read(AUTH).is_err(), "replaced {relative}");
        assert!(vault.write(AUTH, b"replacement").is_err());
        assert_eq!(fs::read_dir(replacement).unwrap().count(), 0);
    }
}

#[test]
fn reopen_rejects_common_replacement_even_if_lock_and_vault_were_moved() {
    let (root, owner) = owner();
    let keys = TestKeychain::default();
    let id = Uuid::from_u128(1);
    let vault = MacosVault::initialize_with_keychain(owner.clone(), id, &keys).unwrap();
    vault.write(AUTH, SECRET).unwrap();
    drop(vault);
    let common = root.path().join("common");
    let moved = root.path().join("moved");
    fs::rename(&common, &moved).unwrap();
    fs::create_dir(&common).unwrap();
    fs::set_permissions(&common, fs::Permissions::from_mode(0o700)).unwrap();
    for name in [crate::owner_lock::OWNER_LOCK_FILE, DIRECTORY] {
        fs::rename(moved.join(name), common.join(name)).unwrap();
    }
    assert!(MacosVault::open_with_keychain(owner, id, &keys).is_err());
}

#[test]
fn reopening_visible_vault_retries_failed_publication_sync() {
    for parent_index in [0, 1] {
        let (root, owner) = owner();
        let keys = TestKeychain::default();
        let id = Uuid::from_u128(1);
        filesystem::fail_ancestor_sync_after(parent_index);
        assert!(MacosVault::initialize_with_keychain(owner.clone(), id, &keys).is_err());
        assert!(root.path().join("common/vault-v1/binding").is_file());

        filesystem::fail_ancestor_sync_after(parent_index);
        assert!(MacosVault::open_with_keychain(owner.clone(), id, &keys).is_err());
        filesystem::fail_ancestor_sync_after(parent_index);
        assert!(MacosVault::initialize_with_keychain(owner.clone(), id, &keys).is_err());

        let vault = MacosVault::open_with_keychain(owner, id, &keys).unwrap();
        vault.write(AUTH, SECRET).unwrap();
        assert_eq!(vault.read(AUTH).unwrap().unwrap().as_ref(), SECRET);
        assert_eq!(keys.0.lock().unwrap().len(), 1);
    }
}

#[test]
fn reopen_reclaims_interrupted_write_and_preserves_committed_record() {
    const CHILD_ROOT: &str = "NELOMAI_VAULT_INTERRUPTED_WRITE_ROOT";
    let keys = TestKeychain::default();
    let id = Uuid::from_u128(1);
    keys.add(id, &[77; 32]).unwrap();
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        let owner =
            Arc::new(ContainerOwnerLock::try_acquire_for_macos_vault(Path::new(&root)).unwrap());
        let vault = MacosVault::open_with_keychain(owner, id, &keys).unwrap();
        vault.write(AUTH, b"not committed").unwrap();
        panic!("interruption hook did not run");
    }
    let (root, owner) = owner();
    let vault = MacosVault::initialize_with_keychain(owner, id, &keys).unwrap();
    vault.write(AUTH, SECRET).unwrap();
    drop(vault);

    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "macos_vault::tests::reopen_reclaims_interrupted_write_and_preserves_committed_record",
            "--nocapture",
        ])
        .env(CHILD_ROOT, root.path())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(77));
    let pending = root.path().join("common/vault-v1/.record-pending");
    assert!(pending.is_file());

    let owner = Arc::new(ContainerOwnerLock::try_acquire_for_macos_vault(root.path()).unwrap());
    let vault = MacosVault::open_with_keychain(owner, id, &keys).unwrap();
    assert!(!pending.exists());
    assert_eq!(vault.read(AUTH).unwrap().unwrap().as_ref(), SECRET);
}

#[test]
fn vault_rejects_acl_on_common_before_provisioning_key() {
    let (root, owner) = owner();
    let keys = TestKeychain::default();
    let common = root.path().join("common");
    add_acl(
        &common,
        "everyone allow search,list,file_inherit,directory_inherit",
    );

    assert!(MacosVault::initialize_with_keychain(owner, Uuid::from_u128(1), &keys).is_err());
    assert!(keys.0.lock().unwrap().is_empty());
    assert!(!common.join("vault-v1").exists());
}

#[test]
fn vault_rejects_record_acl_without_replacing_record() {
    let (_root, owner) = owner();
    let keys = TestKeychain::default();
    let vault =
        MacosVault::initialize_with_keychain(owner.clone(), Uuid::from_u128(1), &keys).unwrap();
    vault.write(AUTH, SECRET).unwrap();
    let path = files(&owner).pop().unwrap();
    add_acl(&path, "everyone allow read,write");
    let original = fs::read(&path).unwrap();

    assert!(vault.read(AUTH).is_err());
    assert!(vault.write(AUTH, b"replacement").is_err());
    assert_eq!(fs::read(path).unwrap(), original);
}

#[test]
fn legacy_and_vault_owners_exclude_each_other() {
    const CHILD: &str = "NELOMAI_VAULT_LOCK_COMPAT_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // Isolate the lock lifetime from concurrent fork/exec in other tests.
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "macos_vault::tests::legacy_and_vault_owners_exclude_each_other",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap()
            .success());
        return;
    }
    let root = vault_test_dir();
    let legacy = ContainerOwnerLock::try_acquire(root.path()).unwrap();
    assert_eq!(
        ContainerOwnerLock::try_acquire_for_macos_vault(root.path())
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(legacy);
    let vault = ContainerOwnerLock::try_acquire_for_macos_vault(root.path()).unwrap();
    assert_eq!(
        ContainerOwnerLock::try_acquire(root.path())
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(vault);
    ContainerOwnerLock::try_acquire(root.path()).unwrap();
}

#[test]
fn vault_owner_refuses_a_root_with_shared_write_access() {
    let root = vault_test_dir();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o770)).unwrap();
    let result = ContainerOwnerLock::try_acquire_for_macos_vault(root.path());
    assert!(result.is_err());
    assert!(!root.path().join("common").exists());
    ContainerOwnerLock::try_acquire(root.path()).unwrap();
}

#[test]
fn vault_owner_refuses_an_ancestor_acl_that_allows_directory_replacement() {
    let container = vault_test_dir();
    let root = container.path().join("app-data");
    fs::create_dir(&root).unwrap();
    add_acl(
        container.path(),
        "everyone allow add_subdirectory,delete_child",
    );
    assert!(ContainerOwnerLock::try_acquire_for_macos_vault(&root).is_err());
    assert!(!root.join("common").exists());
}

#[test]
fn vault_owner_refuses_symlink_even_beneath_a_sticky_parent() {
    let container = vault_test_dir();
    let sticky = container.path().join("aliases");
    fs::create_dir(&sticky).unwrap();
    fs::set_permissions(&sticky, fs::Permissions::from_mode(0o1777)).unwrap();
    let alias = sticky.join("data");
    for target in ["first", "second"] {
        let root = container.path().join(target);
        fs::create_dir(&root).unwrap();
        symlink(&root, &alias).unwrap();
        assert!(ContainerOwnerLock::try_acquire_for_macos_vault(&alias).is_err());
        assert!(!root.join("common").exists());
        fs::remove_file(&alias).unwrap();
        ContainerOwnerLock::try_acquire_for_macos_vault(&root).unwrap();
    }
}

#[test]
fn legacy_owner_can_create_lock_under_inherited_delete_denial() {
    let root = vault_test_dir();
    let common = root.path().join("common");
    fs::create_dir(&common).unwrap();
    add_acl(&common, "everyone deny delete,file_inherit");
    let owner = ContainerOwnerLock::try_acquire(root.path());
    for path in [common.join(crate::owner_lock::OWNER_LOCK_FILE), common] {
        if path.exists() {
            assert!(std::process::Command::new("/bin/chmod")
                .arg("-N")
                .arg(path)
                .status()
                .unwrap()
                .success());
        }
    }
    owner.unwrap();
}

#[test]
fn vault_opens_beneath_search_only_ancestor() {
    let container = vault_test_dir();
    let ancestor = container.path().join("search-only");
    let root = ancestor.join("app-data");
    fs::create_dir_all(&root).unwrap();
    // Default macOS home paths may contain a deny ACE, which does not
    // give another user a way to move the lock's containing directory.
    add_acl(&ancestor, "everyone deny add_file");
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o111)).unwrap();
    let result: Result<_, StorageError> = (|| {
        let owner = Arc::new(ContainerOwnerLock::try_acquire_for_macos_vault(&root)?);
        let keys = TestKeychain::default();
        let vault = MacosVault::initialize_with_keychain(owner, Uuid::from_u128(1), &keys)?;
        vault.write(AUTH, SECRET)?;
        vault.read(AUTH)
    })();
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(result.unwrap().unwrap().as_ref(), SECRET);
}

#[test]
fn interrupted_owner_creation_reuses_its_unpublished_stage() {
    const COMMON_ROOT: &str = "NELOMAI_VAULT_INTERRUPT_COMMON_ROOT";
    const LOCK_ROOT: &str = "NELOMAI_VAULT_INTERRUPT_OWNER_FILE_ROOT";
    if let Some(root) = std::env::var_os(COMMON_ROOT).or_else(|| std::env::var_os(LOCK_ROOT)) {
        // SAFETY: this subprocess runs only this test and can change its umask.
        unsafe { libc::umask(0o700) };
        ContainerOwnerLock::try_acquire_for_macos_vault(Path::new(&root)).unwrap();
        panic!("interruption hook did not run");
    }
    for (variable, exit_code, stage_parent, destination) in [
        (COMMON_ROOT, 78, "", "common"),
        (LOCK_ROOT, 79, "common", "common/container-owner.lock"),
    ] {
        let root = vault_test_dir();
        for _ in 0..2 {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "macos_vault::tests::interrupted_owner_creation_reuses_its_unpublished_stage",
                    "--nocapture",
                ])
                .env(variable, root.path())
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(exit_code));
            assert!(!root.path().join(destination).exists());
            let stages = owner_stages(&root.path().join(stage_parent));
            assert_eq!(stages.len(), 1);
            let metadata = fs::symlink_metadata(&stages[0]).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0);
        }
        if variable == COMMON_ROOT {
            let stage = owner_stages(root.path()).pop().unwrap();
            fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)).unwrap();
            let unexpected = stage.join("unexpected");
            fs::write(&unexpected, b"preserve").unwrap();
            assert!(ContainerOwnerLock::try_acquire_for_macos_vault(root.path()).is_err());
            assert_eq!(fs::read(&unexpected).unwrap(), b"preserve");
            fs::remove_file(unexpected).unwrap();
        }
        let owner = Arc::new(ContainerOwnerLock::try_acquire_for_macos_vault(root.path()).unwrap());
        assert!(owner_stages(&root.path().join(stage_parent)).is_empty());
        let keys = TestKeychain::default();
        MacosVault::initialize_with_keychain(owner, Uuid::from_u128(1), &keys).unwrap();
    }
}

fn owner_stages(parent: &Path) -> Vec<std::path::PathBuf> {
    fs::read_dir(parent)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".nelomai-vault-init-")
        })
        .collect()
}

#[test]
fn concurrent_first_acquisition_publishes_one_lock() {
    let root = vault_test_dir();
    let path = root.path().join("new-root");
    let start = std::sync::Barrier::new(2);
    let (left, right) = std::thread::scope(|threads| {
        let acquire = || {
            start.wait();
            ContainerOwnerLock::try_acquire_for_macos_vault(&path)
        };
        let left = threads.spawn(acquire);
        let right = threads.spawn(acquire);
        (left.join().unwrap(), right.join().unwrap())
    });
    let (_owner, error) = match (left, right) {
        (Ok(owner), Err(error)) | (Err(error), Ok(owner)) => (owner, error),
        results => panic!("expected exactly one acquisition, got {results:?}"),
    };
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    assert!(owner_stages(root.path()).is_empty());
    assert!(owner_stages(&path).is_empty());
    assert!(owner_stages(&path.join("common")).is_empty());
}

#[test]
fn contender_recognizes_its_stage_after_another_owner_publishes_it() {
    use std::{sync::mpsc, time::Duration};
    let root = vault_test_dir();
    let path = root.path().join("new-root");
    let contender_path = path.clone();
    let (opened, reached) = mpsc::channel();
    let (resume, waiting) = mpsc::channel();
    let contender = std::thread::spawn(move || {
        crate::owner_lock::macos::after_stage_open_for_test(move || {
            opened.send(()).unwrap();
            waiting.recv_timeout(Duration::from_secs(5)).unwrap();
        });
        ContainerOwnerLock::try_acquire_for_macos_vault(&contender_path)
    });
    reached.recv_timeout(Duration::from_secs(5)).unwrap();
    let stage = owner_stages(root.path()).pop().unwrap();
    let winner = ContainerOwnerLock::try_acquire_for_macos_vault(&path).unwrap();
    assert!(path.join("common").is_dir());
    // A third contender that previously saw the destination as missing
    // can have made a new, empty stage under the same reserved name.
    fs::create_dir(&stage).unwrap();
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)).unwrap();
    resume.send(()).unwrap();
    let error = contender.join().unwrap().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    assert!(owner_stages(root.path()).is_empty());
    drop(winner);
}

#[test]
fn restrictive_umask_still_allows_private_vault_and_record_creation() {
    const CHILD: &str = "NELOMAI_VAULT_UMASK_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let root = vault_test_dir();
        let app_root = root.path().join("new").join("app-data");
        let keys = TestKeychain::default();
        let id = Uuid::from_u128(1);
        // SAFETY: this subprocess runs only this test and can change its umask.
        unsafe { libc::umask(0o700) };
        let owner = Arc::new(ContainerOwnerLock::try_acquire_for_macos_vault(&app_root).unwrap());
        let vault = MacosVault::initialize_with_keychain(owner, id, &keys).unwrap();
        vault.write(AUTH, SECRET).unwrap();
        drop(vault);
        let owner = Arc::new(ContainerOwnerLock::try_acquire_for_macos_vault(&app_root).unwrap());
        let vault = MacosVault::open_with_keychain(owner, id, &keys).unwrap();
        assert_eq!(vault.read(AUTH).unwrap().unwrap().as_ref(), SECRET);
        return;
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "macos_vault::tests::restrictive_umask_still_allows_private_vault_and_record_creation",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .status()
        .unwrap();
    assert!(status.success());
}

fn add_acl(path: &Path, acl: &str) {
    assert!(std::process::Command::new("/bin/chmod")
        .args(["+a", acl])
        .arg(path)
        .status()
        .unwrap()
        .success());
}

#[test]
fn concurrent_read_observes_whole_records_during_atomic_replacement() {
    let (_root, owner) = owner();
    let keys = TestKeychain::default();
    let vault = MacosVault::initialize_with_keychain(owner, Uuid::from_u128(1), &keys).unwrap();
    let old = vec![0x72; 8_192];
    let new = vec![0x89; 8_192];
    vault.write(AUTH, &old).unwrap();
    let start = std::sync::Barrier::new(2);
    std::thread::scope(|threads| {
        threads.spawn(|| {
            start.wait();
            for value in [&new, &old].into_iter().cycle().take(100) {
                vault.write(AUTH, value).unwrap();
            }
        });
        start.wait();
        for _ in 0..2_000 {
            let record = vault.read(AUTH).unwrap().unwrap();
            assert!(record.as_ref() == old || record.as_ref() == new);
        }
    });
    assert_eq!(vault.read(AUTH).unwrap().unwrap().as_ref(), old);
}
