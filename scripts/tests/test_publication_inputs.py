import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("publication", Path(__file__).resolve().parents[1] / "check-publication-inputs.py")
publication = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publication)


class PublicationInputsTest(unittest.TestCase):
    def test_selects_030_candidate_without_accepting_wrong_identity(self):
        source = "a" * 40
        endpoint = "repos/owner/repo/actions/runs/42"
        run = dict(id=42, head_sha=source, path=".github/workflows/release.yml",
                   event="workflow_dispatch", status="completed", conclusion="success",
                   repository={"full_name": "owner/repo"},
                   head_repository={"full_name": "owner/repo"})
        artifact = dict(id=123, name="candidate-0.3.0", expired=False,
                        workflow_run={"id": 42, "head_sha": source})

        def fetch(path):
            return {endpoint: run, endpoint + "/artifacts?per_page=100&page=1":
                    {"artifacts": [artifact]}}[path]

        self.assertEqual(publication.select_candidate("owner/repo", "42", source, "0.3.0", fetch), 123)
        for changed in ({"name": "candidate-0.2.20"}, {"expired": True},
                        {"workflow_run": {"id": 43, "head_sha": source}},
                        {"workflow_run": {"id": 42, "head_sha": "b" * 40}}):
            with self.subTest(changed=changed), patch.dict(artifact, changed):
                with self.assertRaises(ValueError):
                    publication.select_candidate("owner/repo", "42", source, "0.3.0", fetch)
        for version in ("", "0.3.1", "0.3.0a"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                publication.select_candidate("owner/repo", "42", source, version, fetch)

    def test_selected_release_needs_no_approval_but_rejects_wrong_build_or_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            assets = {}
            for name in publication.gates.PUBLISH_ASSETS:
                body = name.encode()
                (directory / name).write_bytes(body)
                assets[name] = hashlib.sha256(body).hexdigest()
            inventory = dict(source_sha="a" * 40, run_id="42", mode="sign_candidate",
                             trust="release", purpose="shipping", assets=assets)
            def save():
                body = json.dumps(inventory).encode()
                (directory / "candidate-inventory.json").write_bytes(body)
                return hashlib.sha256(body).hexdigest()
            digest = save()
            publication.check(directory, "a" * 40, "42", digest)
            for source, run in (("b" * 40, "42"), ("a" * 40, "43")):
                with self.assertRaises(ValueError):
                    publication.check(directory, source, run, digest)
            inventory["mode"] = "build_only"
            with self.assertRaises(ValueError):
                publication.check(directory, "a" * 40, "42", save())
            inventory["mode"] = "sign_candidate"
            digest = save()
            (directory / next(iter(assets))).write_bytes(b"changed")
            with self.assertRaises(ValueError):
                publication.check(directory, "a" * 40, "42", digest)
