//! Common JNI owner. This library deliberately has no Tauri/UI dependency.
#[cfg(target_os = "android")]
mod android;
pub mod native_reply;
#[cfg(any(target_os = "android", test))]
mod owner_lifecycle;
