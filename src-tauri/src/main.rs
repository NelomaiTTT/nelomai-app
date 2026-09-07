// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(not(target_os = "android"))]
    nelomai_app_lib::container::run();
    #[cfg(target_os = "android")]
    nelomai_app_lib::run();
}
