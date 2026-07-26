#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod unix;
#[cfg(desktop)]
pub mod updater;
#[cfg(windows)]
pub mod windows;
