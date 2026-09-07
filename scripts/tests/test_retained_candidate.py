"""Promotion consumes the exact GitHub-retained ZIP, not a caller's receipt."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
import zipfile

from scripts.tests.test_runtime_artifact import module, SOURCE


class RetainedCandidateTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.archive = self.root / "retained.zip"
        self.directory = self.root / "candidate"
        self.directory.mkdir()
        self.files = {"candidate-inventory.json": b"inventory", "installer.exe": b"exact installer"}
        with zipfile.ZipFile(self.archive, "w") as archive:
            for name, value in self.files.items():
                archive.writestr(name, value)
                (self.directory / name).write_bytes(value)
        self.metadata = {"id": 17, "name": "candidate-0.2.16", "expired": False,
            "expires_at": "2999-01-01T00:00:00Z", "size_in_bytes": self.archive.stat().st_size,
            "digest": "sha256:" + hashlib.sha256(self.archive.read_bytes()).hexdigest(),
            "workflow_run": {"id": 42, "head_sha": SOURCE, "repository_id": 123, "head_repository_id": 123}}
        self.gates = module("release-candidate-gates")

    def check(self, metadata=None):
        self.assertTrue(callable(getattr(self.gates, "verify_retained_artifact", None)), "retained ZIP provenance is missing")
        self.gates.verify_retained_artifact(metadata or self.metadata, self.archive, self.directory, 17, 42, SOURCE, 123)

    def test_accepts_exact_retained_bytes_and_rejects_local_substitution(self):
        self.check()
        (self.directory / "installer.exe").write_bytes(b"substituted installer")
        with self.assertRaisesRegex(ValueError, "retained"):
            self.check()

    def test_rejects_expiry_foreign_run_fork_source_id_and_missing_digest(self):
        self.assertTrue(callable(getattr(self.gates, "verify_retained_artifact", None)), "retained ZIP provenance is missing")
        changes = [{"expired": True}, {"expires_at": "2000-01-01T00:00:00Z"}, {"digest": None},
            {"id": 18}, {"name": "unapproved"}, {"size_in_bytes": 1}]
        for field, value in (("id", 43), ("head_sha", "b" * 40), ("repository_id", 124), ("head_repository_id", 124)):
            changes.append({"workflow_run": {**self.metadata["workflow_run"], field: value}})
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.check({**copy.deepcopy(self.metadata), **change})

    def test_rejects_zip_tampering_and_extra_extracted_file(self):
        self.check()
        (self.directory / "extra").write_bytes(b"unretained")
        with self.assertRaises(ValueError):
            self.check()
        (self.directory / "extra").unlink()
        with self.archive.open("ab") as stream:
            stream.write(b"trailing substitution")
        with self.assertRaises(ValueError):
            self.check()


if __name__ == "__main__":
    unittest.main()
