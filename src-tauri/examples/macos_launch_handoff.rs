//! Isolated native handoff regression driver: no auth, installer or VPN.
#[cfg(target_os = "macos")]
#[path = "../src/macos_launch.rs"]
mod macos_launch;

#[cfg(target_os = "macos")]
fn main() {
    let executable = std::env::current_exe().unwrap();
    let bundle = executable
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let target = bundle.parent().unwrap().join("protected/Nelomai.app");
    if std::env::args().nth(1).as_deref() == Some("restart") {
        macos_launch::restart_after_exit(&target).unwrap();
        std::fs::write(bundle.parent().unwrap().join("waiting"), b"ready").unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));
    } else {
        macos_launch::launch_application(&target).unwrap();
    }
}
#[cfg(not(target_os = "macos"))]
fn main() {}
