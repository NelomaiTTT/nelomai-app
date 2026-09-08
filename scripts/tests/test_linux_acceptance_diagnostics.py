import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import unittest


spec = importlib.util.spec_from_file_location(
    "linux_acceptance", Path(__file__).resolve().parents[1] / "linux/run-package-acceptance.py")
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


class DiagnosticsTests(unittest.TestCase):
    def test_captured_failure_preserves_cause_and_exit_status(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            with self.assertRaises(subprocess.CalledProcessError) as error:
                acceptance.run(sys.executable, "-c",
                    "import sys; print('startup reached'); print('runtime failed', file=sys.stderr); sys.exit(7)",
                    capture_output=True, text=True)
        self.assertEqual(error.exception.returncode, 7)
        self.assertIn("startup reached", output.getvalue())
        self.assertIn("runtime failed", output.getvalue())

