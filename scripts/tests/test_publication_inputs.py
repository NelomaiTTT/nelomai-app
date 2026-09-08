import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("publication", Path(__file__).resolve().parents[1] / "check-publication-inputs.py")
publication = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publication)


class PublicationInputsTest(unittest.TestCase):
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
