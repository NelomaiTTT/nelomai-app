#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#[cfg(not(target_os = "android"))]
fn main() {
    nelomai_app_lib::runtime::run()
}

// Android loads the existing versioned JNI library, never a desktop executable.
#[cfg(target_os = "android")]
fn main() {}
