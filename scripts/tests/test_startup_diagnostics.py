"""Exercise the real Rust startup logger without compiling the application."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class StartupDiagnosticsTests(unittest.TestCase):
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
