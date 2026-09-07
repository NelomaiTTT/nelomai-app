import subprocess
import sys
import unittest
from scripts.tests.test_runtime_artifact import ROOT


class FullAcceptanceGateTest(unittest.TestCase):
    def test_no_caller_assertion_can_authorize_missing_task12_acceptance(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts/require-candidate-acceptance.py"),
            "--source-sha", "a" * 40, "--release-set-sha256", "b" * 64,
            "--inventory-sha256", "c" * 64, "--candidate-directory", str(ROOT / "target")],
            capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("UNRUN", result.stderr)
        self.assertIn("Task12", result.stderr)
        self.assertNotIn('"accepted": true', result.stdout)
