"""Static failure evidence must retain bytes without launching the test image."""
import json
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.tests.test_runtime_artifact import module


class WindowsLoaderDiagnosticsTest(unittest.TestCase):
    def test_retains_exact_executable_and_recurses_imports_without_executing_images(self):
        collector = module("windows/collect-loader-diagnostics")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            deps, system, output = root / "deps", root / "system", root / "output"
            deps.mkdir()
            system.mkdir()
            exe = deps / "nelomai_app_lib-fixture.exe"
            exe.write_bytes(b"compiled test bytes")
            dll = system / "example.dll"
            dll.write_bytes(b"system DLL bytes")
            child = system / "child.dll"
            child.write_bytes(b"transitive DLL bytes")
            calls = []

            def dumpbin(command, **kwargs):
                calls.append(command)
                path = Path(command[-1])
                text = "    example.dll\n        123 missing_symbol\n" if path == exe else "    child.dll\n" if path == dll else ""
                return subprocess.CompletedProcess(command, 0, text, "")

            with patch.object(collector.subprocess, "run", side_effect=dumpbin):
                collector.collect(deps, output, "dumpbin", [system], max_images=8)
            report = json.loads((output / "report.json").read_text())
            self.assertEqual((output / "binary" / exe.name).read_bytes(), b"compiled test bytes")
            self.assertEqual(report["selected_executable"], str(exe))
            self.assertEqual({entry["path"] for entry in report["images"]}, {str(exe), str(dll), str(child)})
            self.assertTrue(all(command[:2] in (["dumpbin", "/imports"], ["dumpbin", "/exports"]) for command in calls))
            self.assertIn("missing_symbol", (output / "image-000-imports.txt").read_text())

    def test_ambiguous_test_images_are_reported_without_selecting_or_running_one(self):
        collector = module("windows/collect-loader-diagnostics")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("nelomai_app_lib-one.exe", "nelomai_app_lib-two.exe"):
                (root / name).write_bytes(b"test")
            with patch.object(collector.subprocess, "run", side_effect=AssertionError("must not execute")):
                collector.collect(root, root / "out", None, [], max_images=8)
            report = json.loads((root / "out/report.json").read_text())
            self.assertIsNone(report["selected_executable"])
            self.assertEqual(len(report["test_executables"]), 2)
            self.assertIn("exactly one", " ".join(report["limitations"]))

    def test_missing_tool_leaves_readable_partial_evidence(self):
        collector = module("windows/collect-loader-diagnostics")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "nelomai_app_lib-fixture.exe").write_bytes(b"test")
            collector.collect(root, root / "out", None, [], max_images=1)
            report = json.loads((root / "out/report.json").read_text())
            self.assertTrue((root / "out/binary/nelomai_app_lib-fixture.exe").is_file())
            self.assertIn("dumpbin unavailable", report["limitations"])
            self.assertEqual(len(report["images"]), 1)


    def test_image_budget_stops_recursion_and_records_partial_evidence(self):
        collector = module("windows/collect-loader-diagnostics")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "nelomai_app_lib-fixture.exe").write_bytes(b"test")
            (root / "example.dll").write_bytes(b"dll")
            result = subprocess.CompletedProcess([], 0, "    example.dll\n", "")
            with patch.object(collector.subprocess, "run", return_value=result):
                collector.collect(root, root / "out", "dumpbin", [], max_images=1)
            report = json.loads((root / "out/report.json").read_text())
            self.assertEqual(len(report["images"]), 1)
            self.assertIn("evidence is partial", " ".join(report["limitations"]))

    def test_dumpbin_timeout_retains_binary_and_error_instead_of_retrying_test(self):
        collector = module("windows/collect-loader-diagnostics")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "nelomai_app_lib-fixture.exe").write_bytes(b"test")
            with patch.object(collector.subprocess, "run", side_effect=subprocess.TimeoutExpired("dumpbin", 10)):
                collector.collect(root, root / "out", "dumpbin", [])
            report = json.loads((root / "out/report.json").read_text())
            self.assertIn("timed out", report["images"][0]["imports_error"])
            self.assertTrue((root / "out/binary/nelomai_app_lib-fixture.exe").is_file())


if __name__ == "__main__":
    unittest.main()
