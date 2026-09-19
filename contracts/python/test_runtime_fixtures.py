"""Mutation checks for the real shared runtime fixture validator."""

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import validate_fixtures as checks


class RuntimeFixtureValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for source in checks.RUNTIME.glob("*.json"):
            shutil.copyfile(source, self.root / source.name)
        self.artifact = json.loads(
            (self.root / "stable-artifact-manifest-v1.json").read_text()
        )

    def test_valid_fixtures_pass(self):
        with patch.object(checks, "RUNTIME", self.root):
            checks.validate_runtime_fixtures()

    def test_artifact_rejects_invalid_identity_and_types(self):
        for key, value in [
            ("format_version", True), ("contract_version", True),
            ("runtime_version", "invalid version"), ("runtime_version", 1),
            ("runtime_version", "1.2.3-beta+build"), ("runtime_version", "1" * 65),
            ("source_commit", "x"), ("source_commit", 1),
            ("platform", "unknown"), ("architecture", "unknown"), ("files", []),
        ]:
            with self.subTest(key=key, value=value):
                manifest = copy.deepcopy(self.artifact)
                manifest[key] = value
                with self.assertRaises(AssertionError):
                    checks.assert_artifact_manifest(manifest)

    def test_artifact_rejects_unsafe_paths_and_invalid_sizes(self):
        for key, value in [
            ("path", "../escape"), ("path", "a//b"), ("path", "C:/escape"),
            ("path", "bin/NUL.txt"), ("path", "bin/a:stream"),
            ("path", "bin/control\x7f"), ("path", "bin/name."),
            ("size_bytes", True), ("size_bytes", -1), ("size_bytes", 2**64),
        ]:
            with self.subTest(key=key, value=value):
                manifest = copy.deepcopy(self.artifact)
                manifest["files"][0][key] = value
                with self.assertRaises(AssertionError):
                    checks.assert_artifact_manifest(manifest)

    def test_artifact_rejects_unicode_aliases(self):
        for left, right in [("bin/σ", "bin/ς"), ("bin/Straße", "bin/STRASSE")]:
            with self.subTest(left=left, right=right):
                manifest = copy.deepcopy(self.artifact)
                entry = manifest["files"][0]
                manifest["files"] = [{**entry, "path": left}, {**entry, "path": right}]
                with self.assertRaises(AssertionError):
                    checks.assert_artifact_manifest(manifest)

    def test_root_and_container_reject_invalid_identity(self):
        for filename, changes in [
            ("release-set-manifest-v1.json", {"format_version": True}),
            ("release-set-manifest-v1.json", {"runtime_version": "invalid version"}),
            ("release-set-manifest-v1.json", {"source_commit": "x"}),
            ("release-set-manifest-v1.json", {"release_set_id": ""}),
            ("container-manifest-v1.json", {"container_version": "invalid version"}),
            ("container-manifest-v1.json", {"release_set_id": ""}),
            ("container-manifest-v1.json", {"minimum_runtime_contract": True}),
        ]:
            with self.subTest(filename=filename, changes=changes):
                target = self.root / filename
                original = target.read_bytes()
                target.write_text(json.dumps(
                    {**json.loads(original), **changes}, ensure_ascii=False,
                    sort_keys=True, separators=(",", ":"),
                ))
                try:
                    with patch.object(checks, "RUNTIME", self.root):
                        with self.assertRaises(AssertionError):
                            checks.validate_runtime_fixtures()
                finally:
                    target.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
