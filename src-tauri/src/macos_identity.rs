//! Initial product presentation, including bare development/legacy runtimes.
//! Packaged runtimes also carry bundle metadata so Dock transitions retain it.
use objc2::{AllocAnyThread, MainThreadMarker};
use objc2_app_kit::{NSApplication, NSImage};
use objc2_foundation::NSData;

pub(crate) fn install_icon(mtm: MainThreadMarker) {
    let data = NSData::with_bytes(include_bytes!("../icons/icon.icns"));
    if let Some(icon) = NSImage::initWithData(NSImage::alloc(), &data) {
        // Called on the app's main thread, after AppKit initialization.
        unsafe { NSApplication::sharedApplication(mtm).setApplicationIconImage(Some(&icon)) };
    }
}
