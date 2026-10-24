use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::process::ExitStatus;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub(crate) const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn output_with_timeout(command: &mut Command, timeout: Duration) -> io::Result<Output> {
    command
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let _tree_owner = nelomai_contracts::dispatcher::own_process_group(command)?;
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("child stdout unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("child stderr unavailable"))?;
    let stdout_reader = thread::spawn(move || read_all(stdout));
    let stderr_reader = thread::spawn(move || read_all(stderr));
    let deadline = Instant::now() + timeout;
    let status = loop {
        #[cfg(target_os = "macos")]
        let result = wait_for_child_exit(&mut child, deadline);
        #[cfg(not(target_os = "macos"))]
        let result = child.try_wait();
        match result {
            Ok(Some(status)) => {
                // A helper may leave a descendant behind with our output pipes open. The
                // direct child is already reaped, but its process group can still be killed.
                terminate_process_group_members(child.id());
                break status;
            }
            Ok(None) => {}
            Err(error) => {
                terminate_process_group(&mut child);
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(error);
            }
        }
        if Instant::now() >= deadline {
            terminate_process_group(&mut child);
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "helper command timed out",
            ));
        }
        #[cfg(not(target_os = "macos"))]
        thread::sleep(Duration::from_millis(20));
    };
    Ok(Output {
        status,
        stdout: join_reader(stdout_reader)?,
        stderr: join_reader(stderr_reader)?,
    })
}

fn terminate_process_group(child: &mut std::process::Child) {
    terminate_process_group_members(child.id());
    let _ = child.kill();
    let _ = child.wait();
}

fn terminate_process_group_members(process_id: u32) {
    let _ = unsafe { libc::kill(-(process_id as i32), libc::SIGKILL) };
}

pub(crate) fn status_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> io::Result<ExitStatus> {
    command.process_group(0);
    let mut tree_owner = nelomai_contracts::dispatcher::own_process_group(command)?;
    let mut child = command.spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        #[cfg(target_os = "macos")]
        let result = wait_for_child_exit(&mut child, deadline);
        #[cfg(not(target_os = "macos"))]
        let result = child.try_wait();
        match result {
            Ok(Some(status)) => {
                // Go daemon startup intentionally outlives this short command.
                // Its existing persisted-state backend handles later cleanup.
                tree_owner.write_all(&[1])?;
                return Ok(status);
            }
            Ok(None) => {}
            Err(error) => {
                terminate_process_group(&mut child);
                return Err(error);
            }
        }
        if Instant::now() >= deadline {
            terminate_process_group(&mut child);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "helper command timed out",
            ));
        }
        #[cfg(not(target_os = "macos"))]
        thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(target_os = "macos")]
fn wait_for_child_exit(
    child: &mut std::process::Child,
    deadline: Instant,
) -> io::Result<Option<ExitStatus>> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    if let Some(status) = child.try_wait()? {
        return Ok(Some(status));
    }
    let descriptor = unsafe { libc::kqueue() };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let queue = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let change = libc::kevent {
        ident: child.id() as libc::uintptr_t,
        filter: libc::EVFILT_PROC,
        flags: libc::EV_ADD | libc::EV_ONESHOT,
        fflags: libc::NOTE_EXIT,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    let mut exit_observed = false;
    loop {
        // Reap an exit before registration, or during an interrupted wait.
        // Child caches the status; only the caller decides descendant cleanup.
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        // XNU may remove the PID / publish NOTE_EXIT before it is waitable.
        // Bound this terminal gap by the original deadline without spinning.
        if exit_observed {
            thread::sleep(remaining.min(Duration::from_millis(1)));
            continue;
        }
        let timeout = libc::timespec {
            tv_sec: remaining.as_secs() as libc::time_t,
            tv_nsec: remaining.subsec_nanos() as libc::c_long,
        };
        let mut event: libc::kevent = unsafe { std::mem::zeroed() };
        let count = unsafe { libc::kevent(queue.as_raw_fd(), &change, 1, &mut event, 1, &timeout) };
        let error = if count < 0 {
            Some(io::Error::last_os_error())
        } else if count > 0 && event.flags & libc::EV_ERROR != 0 {
            Some(io::Error::from_raw_os_error(event.data as i32))
        } else {
            None
        };
        if let Some(error) = error {
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ESRCH) {
                exit_observed = true;
                continue;
            }
            return Err(error);
        }
        if count == 0 {
            return child.try_wait();
        }
        if event.ident != child.id() as libc::uintptr_t
            || event.filter != libc::EVFILT_PROC
            || event.fflags & libc::NOTE_EXIT == 0
        {
            return Err(io::Error::other("unexpected child exit event"));
        }
        exit_observed = true;
    }
}

fn read_all(mut reader: impl Read) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader.read_to_end(&mut output)?;
    Ok(output)
}

fn join_reader(reader: thread::JoinHandle<io::Result<Vec<u8>>>) -> io::Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| io::Error::other("helper output reader failed"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRunner(std::process::Child);

    impl Drop for TestRunner {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn hung_command_fixture_entry() {
        let Some(root) = std::env::var_os("NELOMAI_TEST_HUNG_COMMAND_ROOT") else {
            return;
        };
        // Bound an orphan even if the process-group guardian regresses.
        unsafe { libc::alarm(10) };
        let root = std::path::PathBuf::from(root);
        let _lease = nelomai_contracts::dispatcher::MutationGuard::at(&root.join("lease"))
            .expect("fixture lease");
        std::fs::write(root.join("ready"), b"").unwrap();
        thread::sleep(Duration::from_secs(60));
    }

    #[test]
    fn runner_death_fixture_entry() {
        let Some(root) = std::env::var_os("NELOMAI_TEST_RUNNER_ROOT") else {
            return;
        };
        let _ = status_with_timeout(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "process::tests::hung_command_fixture_entry"])
                .env("NELOMAI_TEST_HUNG_COMMAND_ROOT", root),
            Duration::from_secs(30),
        );
    }

    #[test]
    fn runner_death_terminates_its_separate_hung_command_group() {
        let root = tempfile::tempdir().unwrap();
        let mut runner = TestRunner(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "process::tests::runner_death_fixture_entry"])
                .env("NELOMAI_TEST_RUNNER_ROOT", root.path())
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while !root.path().join("ready").exists() {
            assert!(
                runner.0.try_wait().unwrap().is_none(),
                "fixture runner exited before readiness"
            );
            assert!(
                Instant::now() < deadline,
                "fixture command did not become ready"
            );
            thread::sleep(Duration::from_millis(10));
        }
        let lease_path = root.path().join("lease");
        assert!(nelomai_contracts::dispatcher::MutationGuard::at(&lease_path).is_err());
        runner.0.kill().unwrap();
        runner.0.wait().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok(lease) = nelomai_contracts::dispatcher::MutationGuard::at(&lease_path) {
                drop(lease);
                break;
            }
            assert!(
                Instant::now() < deadline,
                "command group survived its exact runner parent's death"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn returns_completed_command_output() {
        let output = output_with_timeout(
            Command::new("/bin/sh").args(["-c", "printf ready"]),
            Duration::from_secs(1),
        )
        .expect("command output");

        assert!(output.status.success());
        assert_eq!(output.stdout, b"ready");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn short_commands_do_not_accumulate_a_polling_interval_per_exit() {
        let mut blocking_elapsed = Duration::ZERO;
        let mut bounded_elapsed = Duration::ZERO;
        for _ in 0..16 {
            for capture_output in [true, false] {
                // Include the same spawn/guardian cost in the baseline. Compare
                // paired calls so a busy VM does not impose a per-exit deadline.
                let started = Instant::now();
                let mut command = Command::new("/bin/sh");
                command
                    .args(["-c", "sleep 0.005; printf ready; exit 7"])
                    .process_group(0)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                let tree_owner =
                    nelomai_contracts::dispatcher::own_process_group(&mut command).unwrap();
                let child = command.spawn().unwrap();
                let process_id = child.id();
                let output = child.wait_with_output().unwrap();
                terminate_process_group_members(process_id);
                drop(tree_owner);
                blocking_elapsed += started.elapsed();
                assert_eq!(output.status.code(), Some(7));
                assert_eq!(output.stdout, b"ready");

                let started = Instant::now();
                let mut command = Command::new("/bin/sh");
                command
                    .args(["-c", "sleep 0.005; printf ready; exit 7"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                let status = if capture_output {
                    let output = output_with_timeout(&mut command, Duration::from_secs(1)).unwrap();
                    assert_eq!(output.stdout, b"ready");
                    output.status
                } else {
                    status_with_timeout(&mut command, Duration::from_secs(1)).unwrap()
                };
                bounded_elapsed += started.elapsed();
                assert_eq!(status.code(), Some(7));
            }
        }
        eprintln!("32 short commands: blocking={blocking_elapsed:?}, bounded={bounded_elapsed:?}");
        assert!(
            bounded_elapsed < blocking_elapsed + Duration::from_millis(256),
            "short commands accumulated polling latency: blocking={blocking_elapsed:?}, bounded={bounded_elapsed:?}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn interrupted_wait_does_not_restart_the_command_deadline() {
        extern "C" fn interrupt(_: libc::c_int) {}
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = interrupt as usize;
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGUSR1, &action, &mut previous) },
            0
        );
        let target = unsafe { libc::pthread_self() } as usize;
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sender = {
            let done = done.clone();
            thread::spawn(move || {
                for _ in 0..60 {
                    thread::sleep(Duration::from_millis(5));
                    if done.load(std::sync::atomic::Ordering::Acquire) {
                        break;
                    }
                    assert_eq!(
                        unsafe { libc::pthread_kill(target as libc::pthread_t, libc::SIGUSR1) },
                        0
                    );
                }
            })
        };
        let started = Instant::now();
        let result = output_with_timeout(
            Command::new("/bin/sh").args(["-c", "sleep 2"]),
            Duration::from_millis(75),
        );
        let elapsed = started.elapsed();
        done.store(true, std::sync::atomic::Ordering::Release);
        sender.join().unwrap();
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGUSR1, &previous, std::ptr::null_mut()) },
            0
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(
            elapsed < Duration::from_millis(250),
            "deadline extended by signals: {elapsed:?}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn child_exit_wait_preserves_status_and_bounds_delayed_children() {
        let mut child = TestRunner(
            Command::new("/bin/sh")
                .args(["-c", "exit 7"])
                .spawn()
                .unwrap(),
        );
        let status = child.0.wait().unwrap();
        assert_eq!(status.code(), Some(7));
        assert_eq!(
            wait_for_child_exit(&mut child.0, Instant::now()).unwrap(),
            Some(status)
        );
        let mut delayed = TestRunner(
            Command::new("/bin/sh")
                .args(["-c", "sleep 0.05; exit 7"])
                .spawn()
                .unwrap(),
        );
        let status = wait_for_child_exit(&mut delayed.0, Instant::now() + Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert_eq!(status.code(), Some(7));
        let mut unfinished = TestRunner(Command::new("/bin/sleep").arg("2").spawn().unwrap());
        let started = Instant::now();
        assert!(wait_for_child_exit(&mut unfinished.0, started)
            .unwrap()
            .is_none());
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[test]
    fn kills_a_command_after_its_deadline() {
        let started = Instant::now();
        let error = output_with_timeout(
            Command::new("/bin/sh").args(["-c", "sleep 2"]),
            Duration::from_millis(50),
        )
        .expect_err("timeout");

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn completed_parent_cannot_leave_output_readers_blocked() {
        let started = Instant::now();
        let output = output_with_timeout(
            Command::new("/bin/sh").args(["-c", "sleep 2 & printf ready"]),
            Duration::from_secs(1),
        )
        .expect("command output");

        assert!(output.status.success());
        assert_eq!(output.stdout, b"ready");
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn status_timeout_preserves_configured_standard_streams() {
        let status = status_with_timeout(
            Command::new("/bin/sh")
                .args(["-c", "test -c /dev/fd/1"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
            Duration::from_secs(1),
        )
        .expect("command status");

        assert!(status.success());
    }

    #[test]
    fn status_timeout_kills_a_command_after_its_deadline() {
        let started = Instant::now();
        let error = status_with_timeout(
            Command::new("/bin/sh")
                .args(["-c", "sleep 2"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
            Duration::from_millis(50),
        )
        .expect_err("timeout");

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
