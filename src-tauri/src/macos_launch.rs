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
    prepare_restart_after_exit(bundle)?.commit();
    Ok(())
}

pub(crate) struct Relaunch(Option<std::process::Child>);
impl Relaunch {
    fn commit(mut self) {
        self.0.take();
    }
}
impl Drop for Relaunch {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub(crate) fn prepare_restart_after_exit(bundle: &Path) -> io::Result<Relaunch> {
    use std::process::Stdio;
    // The existing owner still holds auth/journal locks. A short-lived helper
    // waits for its exit before asking LaunchServices to start a fresh owner.
    // No -n: concurrent user opens must reuse that owner as well.
    let child = Command::new("/bin/sh")
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
    Ok(Relaunch(Some(child)))
}

/// Authorization can outlive its UI/IPC waiter. The owned operation must keep
/// its native gate until installation and handoff have actually completed.
pub(crate) async fn run_update(
    operation: impl std::future::Future<Output = Result<(), nelomai_client_updater::UpdateBackendError>>
        + Send
        + 'static,
) -> Result<(), nelomai_client_updater::UpdateBackendError> {
    tokio::spawn(operation).await.map_err(|_| {
        nelomai_client_updater::UpdateBackendError::new("update_install_outcome_unknown")
    })?
}

/// Complete a verified replacement without asking the replaced broker to
/// authenticate with the new helper. Arm LaunchServices before reaping the old
/// UI so a launch failure can retain the existing manual Restart fallback.
pub(crate) async fn finish_update(
    stop_runtime: impl std::future::Future<Output = io::Result<()>>,
    relaunch: impl FnOnce() -> io::Result<Relaunch>,
    exit: impl FnOnce(),
) -> io::Result<()> {
    let relaunch = relaunch()?;
    stop_runtime.await?;
    exit();
    relaunch.commit();
    Ok(())
}

#[cfg(test)]
mod update_tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    struct Runtime(Mutex<std::process::Child>);
    impl Runtime {
        fn start() -> Self {
            Self(Mutex::new(
                Command::new("/bin/sleep").arg("30").spawn().unwrap(),
            ))
        }
        fn alive(&self) -> bool {
            self.0.lock().unwrap().try_wait().unwrap().is_none()
        }
        fn stop(&self) -> io::Result<()> {
            let mut child = self.0.lock().unwrap();
            child.kill()?;
            child.wait()?;
            Ok(())
        }
    }
    impl Drop for Runtime {
        fn drop(&mut self) {
            let child = self.0.get_mut().unwrap();
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    #[tokio::test]
    async fn cancelled_waiter_does_not_release_installation_gate_or_abandon_handoff() {
        let gate = Arc::new(tokio::sync::Mutex::new(()));
        let guard = gate.clone().lock_owned().await;
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let runtime = Arc::new(Runtime::start());
        let waiter = {
            let started = started.clone();
            let release = release.clone();
            let runtime = runtime.clone();
            tokio::spawn(run_update(async move {
                let _guard = guard;
                started.notify_one();
                release.notified().await;
                runtime
                    .stop()
                    .map_err(|_| nelomai_client_updater::UpdateBackendError::new("stop"))
            }))
        };
        tokio::time::timeout(std::time::Duration::from_secs(2), started.notified())
            .await
            .unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(
            gate.try_lock().is_err(),
            "cancelled waiter must not release live installer ordering"
        );
        assert!(runtime.alive());
        release.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while runtime.alive() || gate.try_lock().is_err() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn completed_update_reaps_old_runtime_before_common_exit() {
        let runtime = Runtime::start();
        let armed = Arc::new(AtomicBool::new(false));
        let exited = AtomicBool::new(false);
        finish_update(
            async {
                assert!(
                    armed.load(Ordering::SeqCst),
                    "arm relaunch before closing UI"
                );
                runtime.stop()
            },
            || {
                assert!(runtime.alive());
                armed.store(true, Ordering::SeqCst);
                Ok(Relaunch(None))
            },
            || {
                assert!(
                    !runtime.alive(),
                    "old runtime must be reaped before common exits"
                );
                exited.store(true, Ordering::SeqCst);
            },
        )
        .await
        .unwrap();
        assert!(
            !runtime.alive(),
            "successful update must not leave old runtime in preparation"
        );
        assert!(
            exited.load(Ordering::SeqCst),
            "common must exit after successful handoff"
        );
    }

    #[tokio::test]
    async fn relaunch_failure_keeps_old_ui_for_manual_restart() {
        let runtime = Runtime::start();
        let exited = AtomicBool::new(false);
        let result = finish_update(
            async { runtime.stop() },
            || Err(io::Error::other("LaunchServices helper unavailable")),
            || {
                exited.store(true, Ordering::SeqCst);
            },
        )
        .await;
        assert!(result.is_err());
        assert!(runtime.alive());
        assert!(!exited.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn failed_runtime_stop_does_not_allow_common_exit() {
        let runtime = Runtime::start();
        let exited = AtomicBool::new(false);
        let result = finish_update(
            async { Err(io::Error::other("owned runtime could not be reaped")) },
            || Ok(Relaunch(None)),
            || {
                exited.store(true, Ordering::SeqCst);
            },
        )
        .await;
        assert!(result.is_err());
        assert!(runtime.alive());
        assert!(!exited.load(Ordering::SeqCst));
    }
    #[tokio::test]
    async fn failed_handoff_cancels_and_reaps_its_relaunch_helper() {
        struct Cleanup(i32);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                unsafe {
                    let mut status = 0;
                    if libc::waitpid(self.0, &mut status, libc::WNOHANG) == 0 {
                        libc::kill(self.0, libc::SIGKILL);
                        libc::waitpid(self.0, &mut status, 0);
                    }
                }
            }
        }
        let child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        let _cleanup = Cleanup(pid);
        let result = finish_update(
            async { Err(io::Error::other("runtime reap failed")) },
            || Ok(Relaunch(Some(child))),
            || panic!("failed handoff cannot exit common"),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            -1,
            "failed handoff must not leave a helper waiting to reopen the app"
        );
    }
}
