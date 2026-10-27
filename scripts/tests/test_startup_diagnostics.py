"""Exercise the real Rust startup logger without compiling the application."""
import os
import re
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class StartupDiagnosticsTests(unittest.TestCase):
    def test_partial_startup_keeps_native_cleanup_available_after_tray_failure(self):
        container = (ROOT / "src-tauri/src/container.rs").read_text()
        tail = container.split('app.manage(state.clone());', 1)[1].split('\n                Ok(())', 1)[0]
        driver = '''use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
static PUMP: AtomicBool = AtomicBool::new(false);
#[derive(Clone)] struct App;
impl App { fn handle(&self) -> &Self { self } }
mod startup { pub fn stage(_: &str) {} }
mod tauri { pub mod async_runtime { pub fn spawn_blocking(f: impl FnOnce()) { f(); } } }
mod desktop { pub fn setup_tray(_: &super::App) -> Result<(), Box<dyn std::error::Error>> {
    Err(std::io::Error::other("synthetic tray unavailable").into())
} }
fn serve_native(_: App, _: Arc<()>, _: ()) { PUMP.store(true, Ordering::SeqCst); }
fn main() {
    let app = &App; let state = Arc::new(()); let native = ();
    let result = (|| -> Result<(), Box<dyn std::error::Error>> { %s Ok(()) })();
    assert!(result.is_err());
    assert!(PUMP.load(Ordering::SeqCst), "fallback Quit must have a live native cleanup pump");
}
''' % tail
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, binary = root / "partial.rs", root / "probe"
            source.write_text(driver)
            subprocess.run(["rustc", "--edition=2021", str(source), "-o", str(binary)], check=True, capture_output=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_common_setup_failure_is_presented_without_callback_panic(self):
        # Execute the shipping outer setup callback, replacing only the host
        # initialization with a missing-Keychain error and the window with a spy.
        container = (ROOT / "src-tauri/src/container.rs").read_text()
        callback = container.split('.setup(|app| {', 1)[1].split('\n        });\n    let mut context', 1)[0]
        start = callback.index('startup::setup(|| {')
        end = callback.index('\n            })', start) + len('\n            })')
        callback = callback[:start] + '''startup::setup(|| -> Result<(), Box<dyn std::error::Error>> {
            Err(std::io::Error::other("common auth anchor missing").into())
        })''' + callback[end:]
        module = ROOT / "crates/client-container/src/startup_diagnostics.rs"
        driver = '''#[path = "%s"] mod startup;
use std::sync::atomic::{AtomicUsize, Ordering};
static REPORTED: AtomicUsize = AtomicUsize::new(0);
fn show_startup_failure(_: &mut ()) -> Result<(), Box<dyn std::error::Error>> {
    REPORTED.fetch_add(1, Ordering::SeqCst);
    Ok(())
}
fn main() {
    let setup = |app: &mut ()| -> Result<(), Box<dyn std::error::Error>> { %s };
    assert!(setup(&mut ()).is_ok(), "Tauri panics on Err from its Ready callback");
    assert_eq!(REPORTED.load(Ordering::SeqCst), 1);
}
''' % (module.as_posix(), callback)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "setup.rs"
            binary = root / "probe"
            source.write_text(driver)
            subprocess.run(["rustc", "--edition=2021", str(source), "-o", str(binary)], check=True, capture_output=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_windows_login_admission_platform_wiring(self):
        commands = (ROOT / "src-tauri/src/commands.rs").read_text()
        login = commands.split("pub async fn app_login(", 1)[1].split("#[tauri::command]", 1)[0]
        gate = re.search(r'#\[cfg\(([^]]+)\)\]\s*\{\s*let owner =.*?PrivateRuntimeAuthClient.*?RuntimeStartup.*?\.ensure_ready',
                         login, re.DOTALL).group(1)
        # Compile the actual command's cfg expression, not a copied platform
        # predicate. This is wiring coverage; RuntimeStartup behavior is Rust-tested.
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "login-cfg.rs"
            source.write_text(f'''#[cfg({gate})] fn admits() -> bool {{ true }}
#[cfg(not({gate}))] fn admits() -> bool {{ false }}
fn main() {{ assert!(admits(), "Windows login skipped runtime admission"); }}
''')
            binary = Path(directory) / ("probe.exe" if os.name == "nt" else "probe")
            subprocess.run(["rustc", "--edition=2021", "--cfg", "windows", "--allow",
                            "explicit_builtin_cfgs_in_flags", str(source), "-o", str(binary)],
                           check=True, capture_output=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_diagnostic_build_preserves_stage_and_error_even_on_panic(self):
        self.exercise(True)

    def test_ordinary_build_creates_no_diagnostic_log(self):
        self.exercise(False)

    def test_deferred_setup_records_original_error_before_framework_panic(self):
        self.exercise(True, deferred_setup=True)

    def exercise(self, enabled, deferred_setup=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "probe.rs"
            module = ROOT / "crates/client-container/src/startup_diagnostics.rs"
            driver = '''#[path = %s] mod diagnostics;
fn main() {
    diagnostics::init();
    diagnostics::stage("native.prepare");
    diagnostics::error("native.prepare", &std::io::Error::from_raw_os_error(5));
    panic!("do-not-record-panic-payload");
}
''' % ('"' + module.as_posix() + '"')
            if deferred_setup:
                driver = driver.replace('diagnostics::stage("native.prepare");', '''
    let callback = || diagnostics::setup(|| -> Result<(), Box<dyn std::error::Error>> {
        Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "fixture-storage-denied").into())
    });
    diagnostics::stage("event_loop");
    let result = callback();
    assert_eq!(result.unwrap_err().downcast_ref::<std::io::Error>().unwrap().kind(), std::io::ErrorKind::PermissionDenied);
    diagnostics::stage("native.prepare");''')
            source.write_text(driver)
            binary = root / ("probe.exe" if os.name == "nt" else "probe")
            command = ["rustc", "--edition=2021", str(source), "-o", str(binary)]
            if enabled:
                command += ["--cfg", 'feature="startup-diagnostics"']
            subprocess.run(command, check=True, capture_output=True)
            result = subprocess.run([str(binary)], env={**os.environ, "LOCALAPPDATA": str(root)}, capture_output=True)
            self.assertEqual(result.returncode, 101)
            log = root / "Nelomai/startup-diagnostics.log"
            if enabled:
                self.assertTrue(log.is_file(), "diagnostic build lost the startup failure")
                contents = log.read_text()
                self.assertIn("stage=native.prepare", contents)
                self.assertIn("error stage=native.prepare", contents)
                self.assertIn("panic location=", contents)
                self.assertNotIn("do-not-record-panic-payload", contents)
                if deferred_setup:
                    self.assertIn("error stage=common.setup: fixture-storage-denied", contents)
            else:
                self.assertFalse(log.exists())


if __name__ == "__main__":
    unittest.main()
