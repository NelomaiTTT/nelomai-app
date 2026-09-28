"""Build-input and extracted-byte gates; not Windows installer acceptance."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.tests.test_runtime_artifact import module


class WindowsUpdateHelperTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="windows-update-helper-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.builder = module("build-runtime-acceptance-container")
        self.staged = self.root / "signed stage"
        self.dispatcher = self.staged / "dispatcher/1/nelomai-windows-service.exe"
        self.dispatcher.parent.mkdir(parents=True)
        self.dispatcher.write_bytes(b"authenticated new dispatcher fixture")

    def test_bundler_receives_staged_helper_not_an_inherited_old_binary(self):
        repo = self.root / "repo"
        (repo / "src-tauri").mkdir(parents=True)
        (repo / "src-tauri/bundle.windows.conf.json").write_text(json.dumps({
            "bundle": {"resources": {}}}))
        runtime = self.staged / "runtime"
        (runtime / "engines/latest/0.3.3/webview").mkdir(parents=True)
        (runtime / "engines/latest/0.3.3/webview/index.html").write_text("UI fixture")
        (runtime / "container-manifest-v1.json").write_text(json.dumps({
            "container_version": "0.3.3", "slots": [{"slot": "latest", "manifest": {
                "runtime_version": "0.3.3"}}]}))

        class NativeBuildBoundary(Exception):
            pass

        def compiler(command, **kwargs):
            self.assertEqual(command[1], "build")
            received = kwargs["env"].get("NELOMAI_WINDOWS_UPDATE_HELPER")
            self.assertEqual(received, str(self.dispatcher.resolve()))
            self.assertEqual(Path(received).read_bytes(), b"authenticated new dispatcher fixture")
            raise NativeBuildBoundary

        with patch.object(self.builder.subprocess, "run", side_effect=compiler):
            with self.assertRaises(NativeBuildBoundary):
                self.builder.package_desktop(self.staged, self.root / "package", self.root / "pub",
                    "windows", "x86_64", root=repo,
                    environment={"NELOMAI_WINDOWS_UPDATE_HELPER": "untrusted-old.exe"})

    def test_extracted_helper_must_be_unique_and_match_authenticated_dispatcher(self):
        extracted = self.root / "extracted"
        helper = extracted / "$PLUGINSDIR/nelomai-update-helper.exe"
        helper.parent.mkdir(parents=True)
        self.assertTrue(callable(getattr(self.builder, "verify_windows_update_helper", None)),
                        "extracted update helper has no integrity gate")
        check = self.builder.verify_windows_update_helper
        with self.assertRaises(ValueError):
            check(extracted, self.staged)
        helper.write_bytes(b"old helper that cannot recover current journals")
        with self.assertRaises(ValueError):
            check(extracted, self.staged)
        helper.write_bytes(self.dispatcher.read_bytes())
        check(extracted, self.staged)
        duplicate = extracted / "nelomai-update-helper.exe"
        duplicate.write_bytes(helper.read_bytes())
        with self.assertRaises(ValueError):
            check(extracted, self.staged)
        duplicate.unlink()
        helper.unlink()
        helper.symlink_to(self.dispatcher)
        with self.assertRaises(ValueError):
            check(extracted, self.staged)
