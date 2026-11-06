"""Run the retained-verifier CLI; GitHub and private-signature authorities are doubles."""
import hashlib
import importlib.abc
import importlib.util
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.tests.test_runtime_artifact import ROOT, module


class DesktopCandidateVerifierTest(unittest.TestCase):
    def test_exact_desktop_dmg_inventory_reaches_signature_verification_without_android(self):
        publication = module("check-publication-inputs")
        signer = module("sign-macos-common-package")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate"
            candidate.mkdir()
            for name in publication.gates.PUBLISH_ASSETS:
                (candidate / name).write_bytes(name.encode())
            pin = "dde0dd9b1f84cc24f8527fd6f50f95355b33c4ba"
            source = "b" * 40
            inventory = dict(source_sha=source, run_id="42", mode="sign_candidate", trust="release", purpose="shipping",
                assets={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in candidate.iterdir()},
                macos_common_signature=signer.signature_metadata(pin))
            raw = json.dumps(inventory).encode()
            (candidate / "candidate-inventory.json").write_bytes(raw)
            runtime, updater = root / "runtime-verifier", root / "updater-verifier"
            runtime.touch()
            updater.touch()
            app = root / "verified-macos/Nelomai.app"
            app.mkdir(parents=True)
            public_key = "WtTc6wVyswcmE5LC0PuOJ+XX82GTW+iPgs4yvZBP2YY="
            repo = "owner/repo"
            prefix = f"repos/{repo}"
            responses = {
                prefix + "/actions/runs/42": dict(id=42, head_sha=source, status="completed", conclusion="success"),
                prefix + "/actions/runs/43": dict(id=43, head_sha=source, status="completed", conclusion="success",
                    path=".github/workflows/checks.yml", repository={"full_name": repo}, head_repository={"full_name": repo}),
                prefix + "/actions/runs/42/jobs?per_page=100": {"jobs": [
                    {"name": "publish", "conclusion": "skipped"}, {"name": "macos_common_sign", "conclusion": "success"}]},
                prefix + "/git/matching-refs/tags/v0.4.1": [],
                prefix + "/releases?per_page=100&page=1": [],
                prefix + "/actions/variables/NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64": {"value": public_key},
            }
            def github(command, **_kwargs):
                self.assertEqual(command[:4], ["gh", "api", "--method", "GET"])
                if command[4] not in responses:
                    raise AssertionError("unexpected GitHub dependency: " + command[4])
                return json.dumps(responses[command[4]])
            class Loader(importlib.abc.Loader):
                def __init__(self, existing):
                    self.existing = existing
                def create_module(self, _spec):
                    return self.existing
                def exec_module(self, _module):
                    pass
            original_spec = importlib.util.spec_from_file_location
            def spec(name, location, *args, **kwargs):
                existing = {"check-publication-inputs": publication, "sign-macos-common-package": signer}.get(Path(location).stem)
                if existing is not None:
                    return importlib.util.spec_from_loader(name, Loader(existing))
                return original_spec(name, location, *args, **kwargs)
            argv = ["verify", "--app", str(ROOT), "--root", str(root), "--repository", repo,
                    "--run", "42", "--ci", "43", "--source", source, "--artifact", "17",
                    "--inventory-sha256", hashlib.sha256(raw).hexdigest(),
                    "--runtime-verifier", str(runtime), "--updater-verifier", str(updater)]
            with patch.dict(os.environ), patch.object(sys, "argv", argv), patch.object(subprocess, "check_output", side_effect=github), \
                 patch.object(importlib.util, "spec_from_file_location", side_effect=spec), \
                 patch.object(publication.gates, "verify_source"), patch.object(publication, "select_candidate", return_value=17), \
                 patch.object(publication.gates, "verify_runtime_release"), \
                 patch.object(publication.gates, "verify_updater_release") as verify_updater, \
                 patch.object(signer, "extract", return_value=(app, "Contents/MacOS/nelomai-app")), \
                 patch.object(signer, "verify_signature"):
                runpy.run_path(str(ROOT / "scripts/verify-desktop-candidate-040.py"), run_name="__main__")
                verify_updater.assert_called_once_with(candidate, root / "runtime-public.raw", root / "updater-public.txt", "")
            result = json.loads((root / "verification.json").read_bytes())
            self.assertEqual(result["assets_sha256_verified"], 18)
            self.assertFalse(result["installed"])
