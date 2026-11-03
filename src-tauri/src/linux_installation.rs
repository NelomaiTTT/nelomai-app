//! Linux bootstrap installer boundary, also exercised by portable Unix tests.
use std::{
    io,
    path::Path,
    process::{Command, ExitStatus},
};

fn protected(path: &Path) -> bool {
    path.ancestors()
        .all(|path| nelomai_contracts::dispatcher::trusted(path, 0).is_ok())
}

pub(super) fn run(
    installed: &Path,
    candidate: &Path,
    archive: &Path,
    sha: &str,
    status: impl FnOnce(&mut Command) -> io::Result<ExitStatus>,
) -> io::Result<ExitStatus> {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    let mut command = Command::new("/usr/bin/pkexec");
    command.arg("/bin/sh");
    if protected(installed) {
        command.arg(installed);
    } else {
        // Root cannot reopen the user FUSE mount. Freeze the candidate's code
        // in argv before authorization; no mutable script path crosses polkit.
        let code = OsString::from_vec(std::fs::read(candidate)?);
        command.arg("-c").arg(code).arg("install-common-linux.sh");
    }
    status(command.arg(archive).arg(sha))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsStr, fs, os::unix::fs::symlink};

    // Only elevation/FUSE access is simulated. Command argument construction,
    // candidate reads and the child /bin/sh are real.
    fn shell(command: &Command) -> Command {
        assert_eq!(command.get_program(), "/usr/bin/pkexec");
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args[0], "/bin/sh");
        let mut child = Command::new("/bin/sh");
        child.args(&args[1..]);
        child
    }

    #[test]
    fn candidate_bytes_cannot_be_swapped_during_authorization() {
        let root = tempfile::tempdir().unwrap();
        let candidate = root.path().join("install-common-linux.sh");
        fs::write(
            &candidate,
            br#"printf 'original\n%s\n%s\n%s\n' "$#" "$1" "$2"
"#,
        )
        .unwrap();
        let archive = root.path().join("candidate's $(echo unexpected) AppImage");
        let sha = "ab".repeat(32);
        run(
            &root.path().join("missing"),
            &candidate,
            &archive,
            &sha,
            |command| {
                // Same-UID attacker acts after pkexec's arguments are prepared.
                let mut attacker = Command::new("/bin/sh");
                attacker
                    .args([
                        "-c",
                        r#"for path do printf 'echo replacement\n' > "$path"; done"#,
                        "attacker",
                    ])
                    .arg(&candidate);
                if let Some(path) = command.get_args().nth(1).filter(|arg| *arg != "-c") {
                    attacker.arg(path);
                }
                assert!(attacker.status()?.success());
                let output = shell(command).output()?;
                assert!(output.status.success());
                assert_eq!(
                    String::from_utf8_lossy(&output.stdout),
                    format!("original\n2\n{}\n{sha}\n", archive.display())
                );
                Ok(output.status)
            },
        )
        .unwrap();
    }

    #[test]
    fn cancellation_failure_and_retry_use_new_candidate_bytes() {
        let root = tempfile::tempdir().unwrap();
        let installed = root.path().join("missing");
        let candidate = root.path().join("installer.sh");
        for (exit, wait_error) in [(126, false), (1, false), (0, true), (0, false)] {
            fs::write(&candidate, format!("exit {exit}\n")).unwrap();
            let result = run(
                &installed,
                &candidate,
                Path::new("archive"),
                "digest",
                |command| {
                    // Model the source FUSE mount becoming inaccessible to root.
                    fs::remove_file(&candidate)?;
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
        }
    }

    #[test]
    fn candidate_read_failure_does_not_request_elevation() {
        let root = tempfile::tempdir().unwrap();
        assert!(run(
            &root.path().join("missing"),
            root.path(),
            Path::new("archive"),
            "digest",
            |_| panic!("must not elevate an unreadable candidate")
        )
        .is_err());
    }

    #[test]
    fn interrupted_child_is_reaped_and_retry_succeeds() {
        let root = tempfile::tempdir().unwrap();
        let installed = root.path().join("missing");
        let candidate = root.path().join("installer.sh");
        fs::write(&candidate, b"printf ready > \"$1\"; exec /bin/sleep 30\n").unwrap();
        let marker = root.path().join("ready");
        let status = run(&installed, &candidate, &marker, "digest", |command| {
            let mut child = shell(command).spawn()?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while !marker.exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            child.kill()?;
            let status = child.wait()?;
            assert!(marker.exists(), "child did not run the candidate");
            Ok(status)
        })
        .unwrap();
        assert!(!status.success());
        fs::write(&candidate, b"exit 0\n").unwrap();
        assert!(
            run(&installed, &candidate, &marker, "digest", |command| shell(
                command
            )
            .status())
            .unwrap()
            .success()
        );
    }

    #[test]
    fn protected_installed_helper_keeps_precedence() {
        // Some distributions expose true as a symlink; the fixture must be trusted.
        let protected = fs::canonicalize("/usr/bin/true").unwrap();
        run(
            &protected,
            Path::new("/missing/candidate"),
            Path::new("archive"),
            "digest",
            |command| {
                assert_eq!(
                    command.get_args().collect::<Vec<_>>(),
                    [
                        OsStr::new("/bin/sh"),
                        protected.as_os_str(),
                        OsStr::new("archive"),
                        OsStr::new("digest"),
                    ]
                );
                Command::new(&protected).status()
            },
        )
        .unwrap();
    }

    #[test]
    fn missing_untrusted_and_symlinked_installed_helpers_use_candidate() {
        let root = tempfile::tempdir().unwrap();
        let installed = root.path().join("old-installer.sh");
        let candidate = root.path().join("candidate-installer.sh");
        fs::write(&candidate, b"exit 0\n").unwrap();
        let install = || {
            run(
                &installed,
                &candidate,
                Path::new("archive"),
                "digest",
                |command| shell(command).status(),
            )
            .unwrap()
            .success()
        };
        assert!(install());
        fs::write(&installed, b"exit 42\n").unwrap();
        assert!(install());
        fs::remove_file(&installed).unwrap();
        symlink("/bin/sh", &installed).unwrap();
        assert!(install());
    }
}
