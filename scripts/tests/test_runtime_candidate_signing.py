"""Manifest finalization preserves every draft payload byte before native wrapping."""
import json
import shutil
import subprocess
import contextlib
import io
import os
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from scripts.tests.test_runtime_artifact import ArtifactFixture, SOURCE, SCRIPTS, module
import scripts.tests.test_runtime_release_set as fixtures


class RuntimeCandidateSigningTest(ArtifactFixture):
    def test_cli_signs_without_github_approval_environment(self):
        drafts = self.drafts()
        output = self.root / "cli-signed"
        signer = module("sign-runtime-candidate")
        arguments = ["sign-runtime-candidate.py", "--mode", "sign_candidate",
                     "--drafts", str(drafts), "--output", str(output), "--source-sha", SOURCE,
                     "--signing-key", str(self.keyfile), "--public-key", str(self.public)]
        with patch.dict(os.environ, {}, clear=True), patch("sys.argv", arguments), contextlib.redirect_stdout(io.StringIO()) as stdout:
            signer.main()
        digest = stdout.getvalue().strip()
        module("release-candidate-gates").verify_runtime_release(
            output / "release", "0.2.16", SOURCE, digest, self.public)

    def drafts(self):
        four = fixtures.RuntimeReleaseSetTest.four_candidates(self)
        drafts = self.root / "drafts"
        for platform, architecture in module("verify-runtime-artifact").TARGETS:
            folder = drafts / platform
            (folder / "stable").mkdir(parents=True)
            (folder / "latest").mkdir()
            shutil.copyfile(self.public, folder / "draft-public-key.raw")
            shutil.copyfile(self.public, folder / "runtime-public-key.raw")
            prefix = f"nelomai-runtime-0.2.16-{platform}-{architecture}"
            for suffix in (".zip", ".manifest.json", ".manifest.sig"):
                for slot in ("stable", "latest"):
                    shutil.copyfile(four / (prefix + suffix), folder / slot / (prefix + suffix))
        return drafts

    def test_final_signatures_bind_both_containers_without_rebuilding_payloads(self):
        self.assertTrue((SCRIPTS / "sign-runtime-candidate.py").exists(), "protected manifest signing phase missing")
        drafts = self.drafts()
        final_key = Ed25519PrivateKey.generate()
        final_private = self.root / "final.raw"
        final_public = self.root / "final-public.raw"
        final_private.write_bytes(final_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
        final_public.write_bytes(final_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        for folder in drafts.iterdir():
            shutil.copyfile(final_public, folder / "runtime-public-key.raw")
        before = {str(path.relative_to(drafts)): path.read_bytes() for path in drafts.rglob("*") if path.is_file()}
        output = self.root / "signed"
        digest = module("sign-runtime-candidate").sign(drafts, output, SOURCE, final_private, final_public)
        module("release-candidate-gates").verify_runtime_release(output / "release", "0.2.16", SOURCE, digest, final_public)
        verifier = module("verify-runtime-artifact")
        for platform, architecture in verifier.TARGETS:
            prefix = f"nelomai-runtime-0.2.16-{platform}-{architecture}"
            self.assertEqual((output / "release" / (prefix + ".zip")).read_bytes(),
                             (drafts / platform / "stable" / (prefix + ".zip")).read_bytes())
            for kind, expected in (("shipping", ["latest"]), ("acceptance", ["latest", "stable"])):
                folder = output / "containers" / platform / kind
                container = verifier.authenticated("container", folder / "container-manifest-v1.json",
                    folder / "container-manifest-v1.sig", final_public, platform, architecture)
                self.assertEqual([slot["slot"] for slot in container["slots"]], expected)
                if kind == "acceptance":
                    self.assertEqual(container["stable_release_set_sha256"], digest)
                    self.assertEqual(container["slots"][0]["manifest"]["runtime_version"], "0.2.17")
            self.assertFalse(any("acceptance" in path.name for path in (output / "release").iterdir()))
        self.assertEqual(before, {str(path.relative_to(drafts)): path.read_bytes() for path in drafts.rglob("*") if path.is_file()})
        with self.assertRaisesRegex(ValueError, "immutable"):
            module("sign-runtime-candidate").sign(drafts, output, SOURCE, final_private, final_public)

    def test_invalid_draft_or_wrong_compilation_pin_cannot_be_signed(self):
        self.assertTrue((SCRIPTS / "sign-runtime-candidate.py").exists(), "protected manifest signing phase missing")
        drafts = self.drafts()
        public = drafts / "linux/runtime-public-key.raw"
        public.write_bytes(bytes(32))
        with self.assertRaisesRegex(ValueError, "compile"):
            module("sign-runtime-candidate").sign(drafts, self.root / "rejected", SOURCE, self.keyfile, self.public)
        shutil.copyfile(self.public, public)
        archive = next((drafts / "linux/stable").glob("*.zip"))
        archive.write_bytes(b"changed native payload")
        with self.assertRaises(Exception):
            module("sign-runtime-candidate").sign(drafts, self.root / "rejected", SOURCE, self.keyfile, self.public)
        self.assertFalse((self.root / "rejected").exists())
