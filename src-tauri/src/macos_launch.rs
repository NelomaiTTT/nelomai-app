//! LaunchServices handoff after the caller has verified the protected bundle.
use std::{io, path::Path, process::Command};

pub(crate) fn launch_application(bundle: &Path) -> io::Result<()> {
    // An exec handoff retains the PID but changes its audit generation.
    // ControlCenter on macOS 26 then rejects NSStatusItem's process identity.
    // Use the exact bundle URL, not its shared identifier, and do not use -n:
    // LaunchServices should reopen an already running protected owner.
    let status = Command::new("/usr/bin/open")
        .arg("-a")
        .arg(bundle)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other("protected application launch failed"))
    }
}

pub(crate) fn restart_after_exit(bundle: &Path) -> io::Result<()> {
    use std::process::Stdio;
    // The existing owner still holds auth/journal locks. A short-lived helper
    // waits for its exit before asking LaunchServices to start a fresh owner.
    // No -n: concurrent user opens must reuse that owner as well.
    Command::new("/bin/sh")
        .arg("-c")
        .arg(concat!(
            "nelomai_wait_count=0; ",
            "while /bin/kill -0 \"$1\" 2>/dev/null; do ",
            "[ \"$nelomai_wait_count\" -lt 300 ] || exit 1; ",
            "/bin/sleep 0.1; nelomai_wait_count=$((nelomai_wait_count + 1)); done; ",
            "exec /usr/bin/open -a \"$2\""
        ))
        .arg("nelomai-relaunch")
        .arg(std::process::id().to_string())
        .arg(bundle)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(())
}
