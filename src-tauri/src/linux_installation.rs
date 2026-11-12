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
) -> io::Result<bool> {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    let mut command = Command::new("/usr/bin/pkexec");
    // pkexec forwards the authorized child's status. Normalize installer
    // failures so exit 126 only identifies a dismissed authorization prompt.
    command.args([
        "/bin/sh",
        "-c",
        r#"/bin/sh "$@" || exit 1"#,
        "install-common-linux.sh",
    ]);
    if protected(installed) {
        command.arg(installed);
    } else {
        // Root cannot reopen the user FUSE mount. Freeze the candidate's code
        // in argv before authorization; no mutable script path crosses polkit.
        let code = OsString::from_vec(std::fs::read(candidate)?);
        command.arg("-c").arg(code).arg("install-common-linux.sh");
    }
    match status(command.arg(archive).arg(sha))?.code() {
        Some(0) => Ok(true),
        Some(126) => Ok(false),
        _ => Err(io::Error::other("common installation failed")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::OsStr,
        fs,
        os::unix::{
            fs::symlink,
            process::{CommandExt, ExitStatusExt},
        },
    };

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
                if let Some(path) = command.get_args().nth(4).filter(|arg| *arg != "-c") {
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
        for (exit, dismissed, wait_error, expected) in [
            (126, true, false, Some(false)),
            (126, false, false, None),
            (1, false, false, None),
            (127, false, false, None),
            (0, false, true, None),
            (0, false, false, Some(true)),
        ] {
            fs::write(&candidate, format!("exit {exit}\n")).unwrap();
            let result = run(
                &installed,
                &candidate,
                Path::new("archive"),
                "digest",
                |command| {
                    // Model the source FUSE mount becoming inaccessible to root.
                    fs::remove_file(&candidate)?;
                    if dismissed {
                        return Ok(ExitStatus::from_raw(126 << 8));
                    }
                    if wait_error {
                        return Err(io::Error::other("simulated installer wait failure"));
                    }
                    shell(command).status()
                },
            );
            assert_eq!(result.ok(), expected, "exit {exit}, dismissed={dismissed}");
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
        let result = run(&installed, &candidate, &marker, "digest", |command| {
            let mut child = shell(command).process_group(0).spawn()?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while !marker.exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            assert_eq!(
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) },
                0
            );
            let status = child.wait()?;
            assert!(marker.exists(), "child did not run the candidate");
            Ok(status)
        });
        assert!(result.is_err());
        fs::write(&candidate, b"exit 0\n").unwrap();
        assert!(
            run(&installed, &candidate, &marker, "digest", |command| shell(
                command
            )
            .status())
            .unwrap()
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
                        OsStr::new("-c"),
                        OsStr::new(r#"/bin/sh "$@" || exit 1"#),
                        OsStr::new("install-common-linux.sh"),
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
        };
        assert!(install());
        fs::write(&installed, b"exit 42\n").unwrap();
        assert!(install());
        fs::remove_file(&installed).unwrap();
        symlink("/bin/sh", &installed).unwrap();
        assert!(install());
    }
}
