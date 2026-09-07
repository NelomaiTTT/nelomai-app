//! Harmless host smoke for a bare versioned Tauri/WebView executable. No common
//! auth, protected records, updater, tunnel adapter or installer is constructed.
#[tauri::command]
fn smoke_ready(app: tauri::AppHandle) {
    std::fs::write(
        std::env::var_os("NELOMAI_WINDOW_SMOKE_RECEIPT").expect("explicit isolated receipt"),
        b"bare versioned WebView loaded compiled product assets\n",
    )
    .unwrap();
    app.exit(0);
}
fn main() {
    let mut context = tauri::generate_context!();
    context.config_mut().identifier = "ru.nelomai.task9.window-smoke".into();
    context
        .config_mut()
        .app
        .windows
        .push(tauri::utils::config::WindowConfig {
            title: "Nelomai — local runtime smoke".into(),
            width: 800.0,
            height: 600.0,
            ..Default::default()
        });
    let app = tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![smoke_ready])
        .on_page_load(|webview, event| {
            if matches!(event.event(), tauri::webview::PageLoadEvent::Finished) {
                let _ = webview.eval("window.__TAURI_INTERNALS__.invoke('smoke_ready')");
            }
        })
        .setup(|app| {
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(15));
                handle.exit(2);
            });
            Ok(())
        })
        .build(context)
        .expect("bare runtime WebView build");
    app.run(|_, _| {});
}
