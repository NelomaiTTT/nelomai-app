use nelomai_client_storage::ContainerOwnerLock;

#[test]
fn owner_lock_child() {
    let Some(root) = std::env::var_os("NELOMAI_SYNTHETIC_OWNER_LOCK_ROOT") else {
        return;
    };
    std::process::exit(
        if ContainerOwnerLock::try_acquire(std::path::Path::new(&root)).is_ok() {
            0
        } else {
            42
        },
    );
}

#[test]
fn competing_process_is_rejected_and_kernel_releases_owner_without_unlinking() {
    let root = tempfile::tempdir().unwrap();
    let lock = ContainerOwnerLock::try_acquire(root.path()).unwrap();
    let child = || {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "owner_lock_child"])
            .env("NELOMAI_SYNTHETIC_OWNER_LOCK_ROOT", root.path())
            .status()
            .unwrap()
            .code()
            .unwrap()
    };
    assert_eq!(child(), 42, "second process must not initialize secrets");
    assert!(root.path().join("common/container-owner.lock").is_file());
    drop(lock);
    assert!(root.path().join("common/container-owner.lock").is_file());
    assert_eq!(child(), 0);
}
