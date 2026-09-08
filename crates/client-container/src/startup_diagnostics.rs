//! Opt-in diagnostic build only; ordinary releases do not write startup logs.
pub fn setup<T>(
    run: impl FnOnce() -> Result<T, Box<dyn std::error::Error>>,
) -> Result<T, Box<dyn std::error::Error>> {
    run().inspect_err(|cause| error("common.setup", cause.as_ref()))
}
pub fn init() {
    #[cfg(feature = "startup-diagnostics")]
    enabled::init();
}
pub fn stage(name: &str) {
    #[cfg(feature = "startup-diagnostics")]
    enabled::write(&format!("stage={name}"));
    let _ = name;
}
pub fn error(stage: &str, error: &dyn std::error::Error) {
    #[cfg(feature = "startup-diagnostics")]
    {
        enabled::write(&format!("error stage={stage}: {error}"));
        let mut source = error.source();
        for _ in 0..8 {
            let Some(cause) = source else { break };
            enabled::write(&format!("caused by: {cause}"));
            source = cause.source();
        }
    }
    let _ = (stage, error);
}

#[cfg(feature = "startup-diagnostics")]
mod enabled {
    use std::{
        fs::File,
        io::Write,
        path::PathBuf,
        sync::{Mutex, OnceLock},
        time::{SystemTime, UNIX_EPOCH},
    };
    static LOG: OnceLock<Mutex<File>> = OnceLock::new();

    pub fn init() {
        let Some(root) = std::env::var_os("LOCALAPPDATA") else {
            return;
        };
        let root = PathBuf::from(root).join("Nelomai");
        if std::fs::create_dir_all(&root).is_err() {
            return;
        }
        let Ok(file) = File::create(root.join("startup-diagnostics.log")) else {
            return;
        };
        if LOG.set(Mutex::new(file)).is_err() {
            return;
        }
        write(&format!(
            "diagnostic common startup pid={}",
            std::process::id()
        ));
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            // Panic values may contain runtime/user data: retain location and
            // backtrace, not the panic payload or any auth/config snapshots.
            write(&format!(
                "panic location={:?}\n{}",
                info.location(),
                std::backtrace::Backtrace::force_capture()
            ));
            previous(info);
        }));
    }

    pub fn write(message: &str) {
        let Some(log) = LOG.get() else { return };
        let Ok(mut file) = log.lock() else { return };
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let bounded: String = message.chars().take(8192).collect();
        let _ = writeln!(file, "{timestamp} {bounded}");
        let _ = file.flush();
    }
}
