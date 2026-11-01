//! Bounded read-only OS helpers. No shell is used by production callers.
use std::{
    io::{self, Read},
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
const LIMIT: usize = 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(2);
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        // A descendant must not keep a pipe or helper alive after cancellation.
        unsafe {
            libc::kill(-(self.0.id() as i32), libc::SIGKILL);
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
pub(super) fn run(program: &str, args: &[&str]) -> io::Result<String> {
    run_with_timeout(program, args, TIMEOUT)
}
pub(super) fn run_with_timeout(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> io::Result<String> {
    if !program.starts_with('/') {
        return Err(invalid());
    }
    let deadline = Instant::now() + timeout;
    let mut child = Process(
        Command::new(program)
            .args(args)
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()?,
    );
    let mut stdout = child.0.stdout.take().ok_or_else(invalid)?;
    let mut stderr = child.0.stderr.take().ok_or_else(invalid)?;
    for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
        {
            return Err(io::Error::last_os_error());
        }
    }
    let mut out = Vec::new();
    let mut total = 0;
    let mut open = [true, true];
    let mut status = None;
    loop {
        for (i, reader) in [&mut stdout as &mut dyn Read, &mut stderr as &mut dyn Read]
            .into_iter()
            .enumerate()
        {
            let mut chunk = [0u8; 8192];
            while open[i] {
                match reader.read(&mut chunk) {
                    Ok(0) => open[i] = false,
                    Ok(n) => {
                        total += n;
                        if total > LIMIT {
                            return Err(invalid());
                        }
                        if i == 0 {
                            out.extend_from_slice(&chunk[..n]);
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
                if Instant::now() >= deadline {
                    return Err(timed_out());
                }
            }
        }
        if status.is_none() {
            status = child.0.try_wait()?;
            if status.is_some() {
                unsafe {
                    libc::kill(-(child.0.id() as i32), libc::SIGKILL);
                }
            }
        }
        if !open[0] && !open[1] {
            if let Some(status) = status {
                if !status.success() {
                    return Err(io::Error::other("physical_network_command_failed"));
                }
                return String::from_utf8(out).map_err(|_| invalid());
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(timed_out());
        }
        let mut fds = [
            libc::pollfd {
                fd: stdout.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stderr.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let result =
            unsafe { libc::poll(fds.as_mut_ptr(), 2, remaining.as_millis().min(10) as i32) };
        if result == -1 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "physical_network_command_output_invalid",
    )
}
fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "physical_network_command_timeout")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_query_timeout_is_not_replaced_with_metadata_timeout() {
        let start = Instant::now();
        let error = run_with_timeout("/bin/sh", &["-c", "sleep 10"], Duration::from_millis(50))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn captures_stdout_but_rejects_failure() {
        assert_eq!(
            run("/bin/sh", &["-c", "printf native-state"]).unwrap(),
            "native-state"
        );
        assert!(run("/bin/sh", &["-c", "printf private-error >&2; exit 7"]).is_err());
    }
    #[test]
    fn output_limit_and_deadline_bound_helpers() {
        let overflow = run("/bin/sh",&["-c","while :; do printf 012345678901234567890123456789012345678901234567890123456789012345; done"]).unwrap_err();
        assert_eq!(overflow.kind(), io::ErrorKind::InvalidData);
        let start = std::time::Instant::now();
        assert!(run("/bin/sh", &["-c", "sleep 10"]).is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(4));
    }
}
