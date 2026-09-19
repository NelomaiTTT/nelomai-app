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
        match child.try_wait() {
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
        match child.try_wait() {
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
        thread::sleep(Duration::from_millis(20));
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

    #[test]
    fn runner_death_fixture_entry() {
        let Some(root) = std::env::var_os("NELOMAI_TEST_RUNNER_ROOT") else {
            return;
        };
        let _ = status_with_timeout(Command::new("/usr/bin/python3").args(["-c", "import sys,fcntl,signal,time,os; signal.alarm(10); f=open(sys.argv[1]+'/lease','w'); fcntl.flock(f,fcntl.LOCK_EX); open(sys.argv[1]+'/ready','w').close(); time.sleep(60)"]).arg(root), Duration::from_secs(30));
    }

    #[test]
    fn runner_death_terminates_its_separate_hung_command_group() {
        let root = tempfile::tempdir().unwrap();
        let mut runner = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "process::tests::runner_death_fixture_entry"])
            .env("NELOMAI_TEST_RUNNER_ROOT", root.path())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !root.path().join("ready").exists() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
        let lease_path = root.path().join("lease");
        assert!(nelomai_contracts::dispatcher::MutationGuard::at(&lease_path).is_err());
        runner.kill().unwrap();
        runner.wait().unwrap();
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
