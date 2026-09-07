import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.tests.test_runtime_artifact import ROOT


class AndroidStagingIdentityTest(unittest.TestCase):
    def test_invalid_full_length_source_is_refused_before_any_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            result = subprocess.run([sys.executable, str(ROOT / "scripts/android/stage-runtime-build.py"),
                "--root", str(ROOT), "--output", str(output), "--native", str(Path(directory) / "absent"),
                "--tunnel", str(Path(directory) / "absent"), "--readelf", str(Path(directory) / "absent"),
                "--slot", "latest", "--source-commit", "x" * 40], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("full lowercase source commit", result.stderr)
            self.assertFalse(output.exists())
