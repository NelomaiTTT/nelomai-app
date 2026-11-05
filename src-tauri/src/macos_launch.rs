//! LaunchServices handoff after the caller has verified the protected bundle.
use std::{io, path::Path, process::Command};

/// Read-only admission: a shipped Tauri owner's native Quit bypasses its
/// guarded stop/retire path. The user must use the existing tray Quit action.
pub(crate) fn require_closed_before_replacement(bundle: &Path) -> io::Result<()> {
    use objc2_app_kit::NSWorkspace;
    let executable = std::fs::canonicalize(bundle.join("Contents/MacOS/nelomai-app"))?;
    let running = NSWorkspace::sharedWorkspace()
        .runningApplications()
        .into_iter()
        .any(|app| {
            !app.isTerminated()
                && app
                    .executableURL()
                    .and_then(|url| url.path())
                    .and_then(|path| std::fs::canonicalize(path.to_string()).ok())
                    .is_some_and(|path| path == executable)
        });
    if running {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "installed application must be closed through its tray menu",
        ));
    }
    Ok(())
}

pub(crate) fn show_replacement_notice() -> io::Result<()> {
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSAlert, NSApplication};
    use objc2_foundation::NSString;
    let main = MainThreadMarker::new()
        .ok_or_else(|| io::Error::other("installation notice requires main thread"))?;
    let _application = NSApplication::sharedApplication(main);
    let alert = NSAlert::new(main);
    alert.setMessageText(&NSString::from_str("Завершите работу Nelomai"));
    alert.setInformativeText(&NSString::from_str("В меню значка Nelomai в строке меню выберите «Выйти». Дождитесь завершения работы приложения, затем снова откройте этот установщик. Текущая установка пока не изменена."));
    alert.runModal();
    Ok(())
}

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
