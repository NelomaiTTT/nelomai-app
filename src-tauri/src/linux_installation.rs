//! Linux bootstrap installer boundary, also exercised by portable Unix tests.
use std::{
    io,
    path::Path,
    process::{Command, ExitStatus},
};

pub(super) fn script<'a>(installed: &'a Path, candidate: &'a Path) -> &'a Path {
    // A stale user-writable file must never gain precedence as root code.
    if protected(installed) {
        installed
    } else {
        candidate
    }
}

fn protected(path: &Path) -> bool {
    path.ancestors()
        .all(|path| nelomai_contracts::dispatcher::trusted(path, 0).is_ok())
}

pub(super) fn run(
    installer: &Path,
    archive: &Path,
    sha: &str,
    staging_root: &Path,
    status: impl FnOnce(&mut Command) -> io::Result<ExitStatus>,
) -> io::Result<ExitStatus> {
    use std::{
        fs,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };
    let mut command = Command::new("/usr/bin/pkexec");
    command.arg("/bin/sh");
    // Keep installed root-owned code on its protected path. It is already
    // root-readable and must not become mutable by the desktop user.
    if protected(installer) {
        return status(command.arg(installer).arg(archive).arg(sha));
    }
    // Root cannot reopen a script under an ordinary user FUSE mount. Copy only
    // the script before elevation into a private directory on the host /tmp.
    // Keep its guard alive until installer_status has waited/reaped the child.
    let staging = tempfile::Builder::new()
        .prefix("nelomai-common-install-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(staging_root)?;
    let script = staging.path().join("install-common-linux.sh");
    let mut source = fs::File::open(installer)?;
    let mut target = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&script)?;
    io::copy(&mut source, &mut target)?;
    drop(target);
    status(command.arg(&script).arg(archive).arg(sha))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::OsString,
        fs,
        os::unix::fs::{symlink, PermissionsExt},
    };

    // Only elevation/FUSE access is simulated. Command argument construction,
    // private files, lifetime, cleanup and the child /bin/sh are real.
    fn shell(command: &Command) -> Command {
        assert_eq!(command.get_program(), "/usr/bin/pkexec");
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args[0], "/bin/sh");
        let mut child = Command::new("/bin/sh");
        child.args(&args[1..]);
        child
    }

    #[test]
    fn staged_installer_runs_when_the_source_is_inaccessible_after_elevation() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("user-fuse");
        fs::create_dir(&source).unwrap();
        let installer = source.join("install-common-linux.sh");
        fs::write(&installer, b"printf '%s\n%s\n' \"$1\" \"$2\"\n").unwrap();
        let staging_root = root.path().join("staging");
        fs::create_dir(&staging_root).unwrap();
        let archive = root.path().join("candidate's AppImage");
        let sha = "ab".repeat(32);
        let mut staged = None;
        let status = run(&installer, &archive, &sha, &staging_root, |command| {
            let args: Vec<OsString> = command.get_args().map(Into::into).collect();
            let script = Path::new(&args[1]);
            staged = Some(script.to_owned());
            // Simulate root's inability to reopen the source user FUSE mount.
            fs::remove_dir_all(&source).unwrap();
            let output = shell(command).output()?;
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                output.stdout,
                format!("{}\n{}\n", archive.display(), sha).as_bytes()
            );
            assert!(script.starts_with(&staging_root));
            assert_eq!(
                fs::metadata(script.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(script).unwrap().permissions().mode() & 0o777,
                0o600
            );
            Ok(output.status)
        })
        .unwrap();
        assert!(status.success());
        assert!(!staged.unwrap().exists());
        assert_eq!(fs::read_dir(&staging_root).unwrap().count(), 0);
    }

    #[test]
    fn cancellation_failure_and_retry_remove_only_their_private_staging() {
        let root = tempfile::tempdir().unwrap();
        let installer = root.path().join("installer.sh");
        let staging = root.path().join("staging");
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("unrelated"), b"keep").unwrap();
        for (exit, wait_error) in [(126, false), (1, false), (0, true), (0, false)] {
            fs::write(&installer, format!("exit {exit}\n")).unwrap();
            let mut path = None;
            let result = run(
                &installer,
                Path::new("archive"),
                "digest",
                &staging,
                |command| {
                    path = command.get_args().nth(1).map(std::path::PathBuf::from);
                    if wait_error {
                        return Err(io::Error::other("simulated installer wait failure"));
                    }
                    shell(command).status()
                },
            );
            if wait_error {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap().code(), Some(exit));
            }
            assert!(!path.unwrap().exists());
            assert_eq!(fs::read_dir(&staging).unwrap().count(), 1);
            assert_eq!(fs::read(staging.join("unrelated")).unwrap(), b"keep");
        }
    }

    #[test]
    fn failed_copy_cleans_partial_staging_before_retry() {
        let root = tempfile::tempdir().unwrap();
        let staging = root.path().join("staging");
        fs::create_dir(&staging).unwrap();
        // Opening a directory succeeds on Unix; copying its bytes fails.
        assert!(run(
            root.path(),
            Path::new("archive"),
            "digest",
            &staging,
            |_| panic!("must not elevate a partial copy")
        )
        .is_err());
        assert_eq!(fs::read_dir(&staging).unwrap().count(), 0);
        let installer = root.path().join("valid.sh");
        fs::write(&installer, b"exit 0\n").unwrap();
        assert!(run(
            &installer,
            Path::new("archive"),
            "digest",
            &staging,
            |command| shell(command).status()
        )
        .unwrap()
        .success());
        assert_eq!(fs::read_dir(&staging).unwrap().count(), 0);
    }

    #[test]
    fn interrupted_child_is_reaped_before_staging_is_removed_and_retry_succeeds() {
        let root = tempfile::tempdir().unwrap();
        let staging = root.path().join("staging");
        fs::create_dir(&staging).unwrap();
        let installer = root.path().join("installer.sh");
        fs::write(&installer, b"printf ready > \"$1\"; exec /bin/sleep 30\n").unwrap();
        let marker = root.path().join("ready");
        let mut staged = None;
        let status = run(&installer, &marker, "digest", &staging, |command| {
            let path = std::path::PathBuf::from(command.get_args().nth(1).unwrap());
            staged = Some(path.clone());
            let mut child = shell(command).spawn()?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while !marker.exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let started = marker.exists();
            assert!(path.exists());
            child.kill()?;
            let status = child.wait()?;
            assert!(started, "child did not execute the staged script");
            assert!(
                path.exists(),
                "staging removed before the native wait completed"
            );
            Ok(status)
        })
        .unwrap();
        assert!(!status.success());
        assert!(!staged.unwrap().exists());
        assert_eq!(fs::read_dir(&staging).unwrap().count(), 0);
        fs::write(&installer, b"exit 0\n").unwrap();
        assert!(
            run(&installer, &marker, "digest", &staging, |command| shell(
                command
            )
            .status())
            .unwrap()
            .success()
        );
        assert_eq!(fs::read_dir(&staging).unwrap().count(), 0);
    }

    #[test]
    fn protected_installed_helper_keeps_precedence() {
        // A real root-owned executable exercises the same path trust checks;
        // it is selected but never invoked as an installer.
        let protected = Path::new("/usr/bin/true");
        let candidate = Path::new("/missing/candidate-installer.sh");
        assert_eq!(script(protected, candidate), protected);
        let root = tempfile::tempdir().unwrap();
        run(
            protected,
            Path::new("archive"),
            "digest",
            root.path(),
            |command| {
                assert_eq!(
                    command.get_args().nth(1).unwrap(),
                    protected.as_os_str(),
                    "protected installed code must not become user-writable staging"
                );
                assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
                Command::new("/bin/sh").args(["-c", "exit 0"]).status()
            },
        )
        .unwrap();
    }

    #[test]
    fn missing_untrusted_and_symlinked_installed_helpers_use_candidate() {
        let root = tempfile::tempdir().unwrap();
        let installed = root.path().join("old-installer.sh");
        let candidate = root.path().join("candidate-installer.sh");
        assert_eq!(script(&installed, &candidate), candidate);
        fs::write(&installed, b"exit 42\n").unwrap();
        assert_eq!(script(&installed, &candidate), candidate);
        fs::remove_file(&installed).unwrap();
        symlink("/bin/sh", &installed).unwrap();
        assert_eq!(script(&installed, &candidate), candidate);
    }
}
