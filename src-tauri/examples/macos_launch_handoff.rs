//! Isolated native handoff regression driver: no auth, installer or VPN.
#[cfg(target_os = "macos")]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "this driver only exercises the launch handoff")
)]
#[path = "../src/macos_launch.rs"]
mod macos_launch;

#[cfg(target_os = "macos")]
fn main() {
    if std::env::args().nth(1).as_deref() == Some("notice") {
        macos_launch::show_replacement_notice().unwrap();
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("check-closed") {
        let target = std::env::args().nth(2).unwrap();
        if macos_launch::require_closed_before_replacement(std::path::Path::new(&target)).is_err() {
            std::process::exit(1);
        }
        return;
    }
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
