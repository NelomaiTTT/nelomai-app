//! Native regression probe. No credentials, product state, installer or VPN.
#[cfg(target_os = "macos")]
#[path = "../src/macos_identity.rs"]
mod macos_identity;
#[cfg(target_os = "macos")]
fn main() {
    if std::env::args().nth(1).as_deref() == Some("--cycle") {
        run_cycle_probe();
        return;
    }
    use objc2::{AllocAnyThread, MainThreadMarker};
    use objc2_app_kit::{NSApplication, NSImage, NSRunningApplication};
    use objc2_foundation::NSData;

    let mtm = MainThreadMarker::new().unwrap();
    let app = NSApplication::sharedApplication(mtm);
    let before = app
        .applicationIconImage()
        .unwrap()
        .TIFFRepresentation()
        .unwrap();
    macos_identity::install_icon(mtm);
    assert_eq!(
        NSRunningApplication::currentApplication()
            .localizedName()
            .map(|name| name.to_string())
            .as_deref(),
        Some("Nelomai"),
        "Dock sees the technical executable name"
    );
    let icon = app.applicationIconImage().expect("runtime Dock icon");
    assert!(icon.isValid());
    let expected = NSImage::initWithData(
        NSImage::alloc(),
        &NSData::with_bytes(include_bytes!("../icons/icon.icns")),
    )
    .unwrap();
    assert!(expected.isValid());
    assert_eq!(icon.size(), expected.size());
    // AppKit re-encodes/resamples ICNS representations; TIFF byte equality with
    // the source asset is not meaningful. Check that the native Dock icon
    // actually changed from the generic executable image.
    assert!(
        !icon.TIFFRepresentation().unwrap().isEqualToData(&before),
        "Dock uses the generic executable icon instead of Nelomai"
    );
    if let Some(output) = std::env::args_os().nth(1) {
        std::fs::write(output, icon.TIFFRepresentation().unwrap().to_vec()).unwrap();
    }
    println!("macOS runtime identity: Nelomai, native icon valid");
}

#[cfg(target_os = "macos")]
fn run_cycle_probe() {
    let marker = std::path::PathBuf::from(std::env::args_os().nth(2).unwrap());
    let app = tauri::Builder::default()
        .build(tauri::generate_context!())
        .unwrap();
    app.run(move |app, event| {
        if matches!(event, tauri::RunEvent::Ready) {
            macos_identity::install_icon(objc2::MainThreadMarker::new().unwrap());
            let marker = marker.clone();
            let handle = app.clone();
            std::thread::spawn(move || {
                // Coordinate with the external observer: NSRunningApplication
                // must be inspected outside this process, like Dock does.
                std::fs::write(&marker, "ready").unwrap();
                let proceed = marker.with_extension("proceed");
                for cycle in 1..=3 {
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                    while !proceed.exists() && std::time::Instant::now() < deadline {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                    if !proceed.exists() {
                        handle.exit(1);
                        return;
                    }
                    std::fs::remove_file(&proceed).unwrap();
                    handle.set_dock_visibility(false).unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(1300));
                    handle.set_dock_visibility(true).unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(1300));
                    std::fs::write(&marker, cycle.to_string()).unwrap();
                }
                // Give the observer time to read the final native icon.
                std::thread::sleep(std::time::Duration::from_secs(5));
                handle.exit(0);
            });
        }
    });
}

#[cfg(not(target_os = "macos"))]
fn main() {}
