// Explicit elevated gate: scripts/windows/test-member-file-operations.ps1.
// Default cargo test retains policy/payload coverage without changing owners.
use super::*;
use std::{cell::Cell, io, time::Instant};
use windows_sys::Win32::Security::{SetFileSecurityW, PROTECTED_DACL_SECURITY_INFORMATION};

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct Calls {
    directories: usize,
    opens: usize,
    acls: usize,
    locks: usize,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Boundary {
    Preflight,
    Locked,
}
thread_local! {
    static CALLS: Cell<Calls> = Cell::new(Calls::default());
    static FAULT: Cell<Option<Boundary>> = const { Cell::new(None) };
}
fn count(change: impl FnOnce(&mut Calls)) {
    CALLS.with(|value| {
        let mut calls = value.get();
        change(&mut calls);
        value.set(calls);
    });
}
pub(super) fn count_directory() {
    count(|v| v.directories += 1);
}
pub(super) fn count_open_directory() {
    count(|v| v.opens += 1);
}
pub(super) fn count_acl() {
    count(|v| v.acls += 1);
}
pub(super) fn count_lock_open() {
    count(|v| v.locks += 1);
}
pub(super) fn after_preflight(root: &Path) -> Result<()> {
    boundary(Boundary::Preflight, root)
}
pub(super) fn after_lock(root: &Path) -> Result<()> {
    boundary(Boundary::Locked, root)
}
fn boundary(point: Boundary, root: &Path) -> Result<()> {
    if FAULT.with(|fault| {
        if fault.get() == Some(point) {
            fault.set(None);
            true
        } else {
            false
        }
    }) {
        set_security(
            root,
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GR;;;WD)",
            false,
        )?;
    }
    Ok(())
}
fn set_security(path: &Path, sddl: &str, owner: bool) -> Result<()> {
    assert!(path.file_name().is_some_and(|v| v == "state"
        || v == "nelomai-redundant.lock"
        || v.to_string_lossy().starts_with("NelomaiOperation-")));
    let security = Security::new(sddl)?;
    let mut flags = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    if owner {
        flags |= OWNER_SECURITY_INFORMATION;
    }
    // SetNamedSecurityInfo recalculates inheritance/control bits and changes
    // pinned facts even when the DACL is restored. Apply this fixture's exact
    // descriptor without propagating ACL changes into its protected children.
    let path = wide(path)?;
    if unsafe { SetFileSecurityW(path.as_ptr(), flags, security.0 .0) } == 0 {
        return Err(OwnerError::Native);
    }
    Ok(())
}
// Retain the checked parent chain through cleanup. The leaf permits only
// privileged writers (read-only public access is fine), before any creation.
// This is an exclusive per-process test namespace. Other Admin/SYSTEM actors
// are trusted not to rename/replace it while the fixture lives. The standard
// Win32 create/open and close/remove pairs do not exclude such privileged races.
// Checks below reject observed mismatches; they are not an atomic delete proof.
struct FixtureDirectory {
    path: PathBuf,
    parents: PinnedDirectory,
    original: Option<Directory>,
}
impl FixtureDirectory {
    fn new(parent: &Path) -> Result<Self> {
        let parents = pin_directory_chain(parent, Protection::Payload)?;
        parents.verify()?;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| OwnerError::Native)?
            .as_nanos();
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            "NelomaiOperation-{}-{time:x}-{sequence:x}",
            std::process::id()
        ));
        let security = Security::new("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")?;
        // Atomic private ACL/owner: never inherit a writable DACL then repair it.
        if unsafe { CreateDirectoryW(wide(&path)?.as_ptr(), &security.attributes()) } == 0 {
            return Err(OwnerError::Native); // No repair/adoption when create reports an existing name.
        }
        let mut owned = Self {
            path,
            parents,
            original: None,
        };
        let file = open_directory(&owned.path).map_err(|_| OwnerError::Native)?;
        let id = stamp(&file, true, 0)?.id;
        let security = acl(&file, Protection::Directory)?;
        owned.original = Some(Directory {
            path: owned.path.clone(),
            file,
            id,
            acl: security,
            protection: Protection::Directory,
        });
        owned.parents.verify()?;
        owned
            .original
            .as_ref()
            .ok_or(OwnerError::Native)?
            .verify()?;
        Ok(owned)
    }
    fn path(&self) -> &Path {
        &self.path
    }
}
impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let verified = self
            .parents
            .verify()
            .and_then(|_| self.original.as_ref().ok_or(OwnerError::Native)?.verify());
        if verified.is_err() {
            // Retain a restricted orphan rather than recursively touch an
            // identity/security mismatch, including a partially pinned create.
            if std::thread::panicking() {
                eprintln!("owned test fixture cleanup denied: identity/security changed");
            } else {
                panic!("owned test fixture cleanup denied: identity/security changed");
            }
            return;
        }
        drop(self.original.take()); // Release our no-delete pin before removal.
        if let Err(error) = std::fs::remove_dir_all(&self.path) {
            if std::thread::panicking() {
                eprintln!("owned test fixture cleanup failed: {:?}", error.kind());
            } else {
                panic!("owned test fixture cleanup failed: {:?}", error.kind());
            }
        }
    }
}

struct Fixture {
    files: MemberFiles,
    _parent: FixtureDirectory,
}
impl Fixture {
    fn new() -> Self {
        let parent = std::env::var_os("NELOMAI_MEMBER_FILES_TEST_ROOT")
            .or_else(|| std::env::var_os("ProgramFiles"))
            .expect("native test parent");
        Self::new_in(Path::new(&parent))
    }
    fn new_in(parent: &Path) -> Self {
        let parent = FixtureDirectory::new(parent)
            .expect("checked private fixture parent and atomic create");
        let root = parent.path().join("state");
        Self {
            files: MemberFiles {
                root,
                directories: Vec::new(),
            },
            _parent: parent,
        }
    }
    fn warm(&mut self) {
        self.files
            .transaction(|records| records.compare_exchange(PrivateFile::Worker, None, b"original"))
            .unwrap();
    }
    fn read(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.files
            .transaction(|records| records.read(PrivateFile::Worker))
    }
    fn restore(&self) {
        set_security(&self.files.root, DIRECTORY_SDDL, false).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        FAULT.with(|fault| fault.set(None));
    }
}

#[test]
#[ignore = "requires elevated Windows; run scripts/windows/test-member-file-operations.ps1"]
fn operation_fixture_parent_is_validated_before_creation() {
    let f = Fixture::new();
    let target = f._parent.path().join("target");
    let link = f._parent.path().join("link");
    std::fs::create_dir(&target).unwrap();
    std::os::windows::fs::symlink_dir(&target, &link).unwrap();
    let attempted = std::panic::catch_unwind(|| Fixture::new_in(&link));
    assert!(
        attempted.is_err(),
        "reparse parent must be rejected before creating a fixture"
    );
    assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
    std::fs::remove_dir(&link).unwrap();
    let mutable = f._parent.path().join("NelomaiOperation-mutable-parent");
    std::fs::create_dir(&mutable).unwrap();
    set_security(
        &mutable,
        // NULL SID has no members; exercise the real ACL policy without
        // granting write rights to a principal on this host. It is an ACE,
        // not a NULL DACL. See Microsoft well-known-sids documentation.
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x116;;;S-1-0-0)",
        false,
    )
    .unwrap();
    let descriptor = acl(&open_directory(&mutable).unwrap(), Protection::Ancestor).unwrap();
    assert!(
        descriptor
            .aces
            .iter()
            .any(|ace| ace.sid == "S-1-0-0" && ace.mask == 0x116),
        "mutable policy fixture must use an inactive SID, never a live unprivileged group"
    );
    let attempted = std::panic::catch_unwind(|| Fixture::new_in(&mutable));
    assert!(
        attempted.is_err(),
        "mutable parent must be rejected before creating a fixture"
    );
    assert_eq!(std::fs::read_dir(&mutable).unwrap().count(), 0);
}

#[test]
#[ignore = "requires elevated Windows; run scripts/windows/test-member-file-operations.ps1"]
fn operation_warm_read_has_one_prelock_directory_pass() {
    let mut f = Fixture::new();
    f.warm();
    let depth = f.files.directories.len();
    assert!(depth >= 2);
    for _ in 0..8 {
        assert_eq!(f.read().unwrap().as_deref(), Some(b"original".as_slice()));
    }
    CALLS.with(|v| v.set(Calls::default()));
    let begin = Instant::now();
    for _ in 0..128 {
        assert_eq!(f.read().unwrap().as_deref(), Some(b"original".as_slice()));
    }
    let elapsed = begin.elapsed();
    let calls = CALLS.with(Cell::get);
    eprintln!("native-operation-read depth={depth} iterations=128 directory_checks={} directory_opens={} security_reads={} lock_opens={} elapsed_us={}",calls.directories,calls.opens,calls.acls,calls.locks,elapsed.as_micros());
    assert_eq!(
        calls.directories,
        3 * depth * 128,
        "one pre-lock, one post-lock and one post-action pass; adjacent preflight must not repeat"
    );
    assert_eq!(calls.opens, 3 * depth * 128);
    assert_eq!(calls.acls, (6 * depth + 3) * 128);
    assert_eq!(calls.locks, 128);
}

#[test]
#[ignore = "requires elevated Windows; run scripts/windows/test-member-file-operations.ps1"]
fn operation_cold_init_and_cas_preserve_exact_bytes() {
    let mut f = Fixture::new();
    assert!(!f.files.root.exists());
    f.warm();
    assert!(f.files.root.join("nelomai-redundant.lock").is_file());
    assert_eq!(f.read().unwrap().as_deref(), Some(b"original".as_slice()));
    f.files
        .transaction(|r| r.compare_exchange(PrivateFile::Worker, Some(b"original"), b"next"))
        .unwrap();
    assert!(f
        .files
        .transaction(|r| r.compare_exchange(PrivateFile::Worker, Some(b"original"), b"stale"))
        .is_err());
    assert_eq!(f.read().unwrap().as_deref(), Some(b"next".as_slice()));
}

#[test]
#[ignore = "requires elevated Windows; run scripts/windows/test-member-file-operations.ps1"]
fn operation_no_share_lock_rejects_contention_and_retries_after_release() {
    let mut f = Fixture::new();
    f.warm();
    let held = f.files.lock_named("nelomai-redundant.lock").unwrap();
    let mut called = false;
    assert!(f
        .files
        .transaction(|_| {
            called = true;
            Ok(())
        })
        .is_err());
    assert!(!called);
    drop(held);
    assert_eq!(f.read().unwrap().as_deref(), Some(b"original".as_slice()));
}

#[test]
#[ignore = "requires elevated Windows; run scripts/windows/test-member-file-operations.ps1"]
fn operation_existing_lock_acl_denies_callback_and_retries_after_restore() {
    let mut f = Fixture::new();
    f.warm();
    let lock = f.files.root.join("nelomai-redundant.lock");
    set_security(&lock, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;WD)", false).unwrap();
    let mut called = false;
    assert!(f
        .files
        .transaction(|_| {
            called = true;
            Ok(())
        })
        .is_err());
    assert!(!called);
    set_security(&lock, FILE_SDDL, false).unwrap();
    assert_eq!(f.read().unwrap().as_deref(), Some(b"original".as_slice()));
}

#[test]
#[ignore = "requires elevated Windows; run scripts/windows/test-member-file-operations.ps1"]
fn operation_existing_nonempty_lock_denies_callback_and_retries_after_restore() {
    let mut f = Fixture::new();
    f.warm();
    let lock = f.files.root.join("nelomai-redundant.lock");
    std::fs::write(&lock, b"invalid lock data").unwrap();
    let mut called = false;
    assert!(f
        .files
        .transaction(|_| {
            called = true;
            Ok(())
        })
        .is_err());
    assert!(!called);
    std::fs::write(&lock, b"").unwrap();
    assert_eq!(f.read().unwrap().as_deref(), Some(b"original".as_slice()));
}

#[test]
#[ignore = "requires elevated Windows; run scripts/windows/test-member-file-operations.ps1"]
fn operation_preflight_acl_drift_denies_before_lock_open() {
    let mut f = Fixture::new();
    f.warm();
    set_security(
        &f.files.root,
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GR;;;WD)",
        false,
    )
    .unwrap();
    CALLS.with(|v| v.set(Calls::default()));
    let mut called = false;
    assert!(f
        .files
        .transaction(|_| {
            called = true;
            Ok(())
        })
        .is_err());
    assert!(!called);
    assert_eq!(
        CALLS.with(Cell::get).locks,
        0,
        "bad preflight must never enter native lock open"
    );
    f.restore();
    assert_eq!(f.read().unwrap().as_deref(), Some(b"original".as_slice()));
}

#[test]
#[ignore = "requires elevated Windows; run scripts/windows/test-member-file-operations.ps1"]
fn operation_acl_drift_after_preflight_or_lock_denies_callback_and_releases_lock() {
    for point in [Boundary::Preflight, Boundary::Locked] {
        let mut f = Fixture::new();
        f.warm();
        FAULT.with(|v| v.set(Some(point)));
        let mut called = false;
        assert!(f
            .files
            .transaction(|_| {
                called = true;
                Ok(())
            })
            .is_err());
        assert!(!called);
        f.restore();
        assert_eq!(f.read().unwrap().as_deref(), Some(b"original".as_slice()));
    }
}

#[test]
#[ignore = "requires elevated Windows; run scripts/windows/test-member-file-operations.ps1"]
fn operation_postaction_acl_drift_denies_success_without_claiming_write_rollback() {
    let mut f = Fixture::new();
    f.warm();
    let root = f.files.root.clone();
    assert!(f
        .files
        .transaction(|r| {
            r.compare_exchange(PrivateFile::Worker, Some(b"original"), b"committed")?;
            set_security(
                &root,
                "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GR;;;WD)",
                false,
            )
            .map_err(|_| io::Error::other("own root ACL"))?;
            Ok(())
        })
        .is_err());
    f.restore();
    assert_eq!(f.read().unwrap().as_deref(), Some(b"committed".as_slice()));
    assert!(f
        .files
        .transaction(|r| r.compare_exchange(PrivateFile::Worker, Some(b"original"), b"stale"))
        .is_err());
}

#[test]
#[ignore = "requires elevated Windows; run scripts/windows/test-member-file-operations.ps1"]
fn operation_postaction_acl_drift_overrides_callback_error() {
    let mut f = Fixture::new();
    f.warm();
    let root = f.files.root.clone();
    let error = f
        .files
        .transaction::<()>(|_| {
            set_security(
                &root,
                "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GR;;;WD)",
                false,
            )
            .unwrap();
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "controlled action with ACL drift",
            ))
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert_eq!(error.to_string(), "protected_session_file_failed");
    assert!(f.read().is_err());
    f.restore();
    assert_eq!(f.read().unwrap().as_deref(), Some(b"original".as_slice()));
}

#[test]
#[ignore = "requires elevated Windows; run scripts/windows/test-member-file-operations.ps1"]
fn operation_callback_error_and_unwind_release_lock_and_recheck_on_retry() {
    let mut f = Fixture::new();
    f.warm();
    let error = f
        .files
        .transaction::<()>(|_| {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "controlled action",
            ))
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert_eq!(error.to_string(), "controlled action");
    assert_eq!(f.read().unwrap().as_deref(), Some(b"original".as_slice()));
    let root = f.files.root.clone();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = f.files.transaction::<()>(|records| {
            records
                .compare_exchange(
                    PrivateFile::Worker,
                    Some(b"original"),
                    b"committed-before-unwind",
                )
                .unwrap();
            set_security(
                &root,
                "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GR;;;WD)",
                false,
            )
            .unwrap();
            panic!("controlled operation unwind")
        });
    }))
    .is_err());
    assert!(f.read().is_err());
    f.restore();
    // Reopen the backend after unwind: the first write may be committed,
    // another record is untouched, and retry must use the actual value.
    f.files = MemberFiles {
        root,
        directories: Vec::new(),
    };
    assert_eq!(
        f.read().unwrap().as_deref(),
        Some(b"committed-before-unwind".as_slice())
    );
    assert!(f
        .files
        .transaction(|records| records.read(PrivateFile::Carrier))
        .unwrap()
        .is_none());
    assert!(f
        .files
        .transaction(|records| records.compare_exchange(
            PrivateFile::Worker,
            Some(b"original"),
            b"stale"
        ))
        .is_err());
    f.files
        .transaction(|records| {
            records.compare_exchange(
                PrivateFile::Worker,
                Some(b"committed-before-unwind"),
                b"recovered",
            )
        })
        .unwrap();
    assert_eq!(f.read().unwrap().as_deref(), Some(b"recovered".as_slice()));
}
