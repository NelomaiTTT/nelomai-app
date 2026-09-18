import importlib.util
import subprocess
import sys
import unittest
from scripts.tests.test_runtime_artifact import SCRIPTS


class LinuxAcceptanceAdapterTest(unittest.TestCase):
    def test_disposable_adapter_refuses_nonlinux_or_nonisolated_invocation(self):
        command = SCRIPTS / "linux/run-package-acceptance.py"
        self.assertTrue(command.is_file(), "ordinary packaged Linux execution adapter is missing")
        result = subprocess.run([sys.executable, str(command), "--inside"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("isolated disposable Linux container", result.stderr)

    def test_webview_probe_requires_all_real_login_controls_in_one_process(self):
        path = SCRIPTS / "linux/check-runtime-webview.py"
        self.assertTrue(path.is_file(), "real WebView accessibility probe missing")
        spec = importlib.util.spec_from_file_location("probe", path)
        probe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(probe)
        self.assertFalse(probe.login_visible(["Вход в Nelomai", "Пароль"]))
        self.assertTrue(probe.login_visible(["Вход в Nelomai", "Пароль", "Войти"]))
        self.assertFalse(probe.login_visible(["Browser error", "Пароль", "Войти"]))
