import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from scripts.tests.test_runtime_artifact import ArtifactFixture, SOURCE, SCRIPTS, ROOT, module


class ReleasePhaseConsumersTest(ArtifactFixture):
    def test_promotion_rechecks_signed_release_index_and_every_updater_payload(self):
        gates = module("release-candidate-gates")
        self.assertTrue(callable(getattr(gates, "verify_updater_release", None)), "promotion updater trust recheck is missing")
        builder = module("build-release-platform")
        work = self.root / "index-signer"
        work.mkdir()
        environment = builder.updater_environment("build_only", work, os.environ)
        public = self.root / "index-public.b64"
        public.write_text(environment["NELOMAI_UPDATER_PUBLIC_KEY"])
        candidate = self.root / "updater-candidate"
        candidate.mkdir()
        artifacts = []
        for platform, name in gates.PACKAGE_NAMES.items():
            path = candidate / name
            path.write_bytes((platform + " final bytes").encode())
            signature = "d" * 64
            if platform != "android":
                subprocess.run([str(ROOT / "node_modules/.bin/tauri"), "signer", "sign", str(path)],
                               env=environment, check=True, capture_output=True)
                signature = path.with_name(name + ".sig").read_text().strip()
            artifacts.append(dict(platform=platform, asset_name=name, size_bytes=path.stat().st_size,
                sha256=module("verify-runtime-artifact").digest(path), signature=signature))
        raw = json.dumps(dict(schema_version=1, version="0.2.19", artifacts=artifacts)).encode()
        manifest = candidate / "nelomai-release-manifest.json"
        manifest.write_bytes(raw)
        (candidate / "nelomai-release-manifest.sig").write_bytes(base64.b64encode(self.key.sign(raw)))
        gates.verify_updater_release(candidate, self.public, public, "d" * 64)
        manifest.write_bytes(raw + b" ")
        with self.assertRaises(Exception):
            gates.verify_updater_release(candidate, self.public, public, "d" * 64)
        manifest.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "certificate"):
            gates.verify_updater_release(candidate, self.public, public, "e" * 64)
        (candidate / gates.PACKAGE_NAMES["macos"]).write_bytes(b"changed bytes")
        with self.assertRaisesRegex(ValueError, "digest"):
            gates.verify_updater_release(candidate, self.public, public, "d" * 64)

    def test_real_updater_signature_rejects_wrong_pin_changed_package_and_malformed_signature(self):
        example = ROOT / "target/debug/examples/verify-updater-signature"
        self.assertTrue(example.is_file(), "Tauri-compatible updater signature verifier is missing")
        builder = module("build-release-platform")
        work = self.root / "signer"
        work.mkdir()
        environment = builder.updater_environment("build_only", work, os.environ)
        package = self.root / "final.AppImage"
        package.write_bytes(b"exact final installer bytes")
        subprocess.run([str(ROOT / "node_modules/.bin/tauri"), "signer", "sign", str(package)],
                       env=environment, check=True, capture_output=True)
        public = self.root / "updater-public.b64"
        public.write_text(environment["NELOMAI_UPDATER_PUBLIC_KEY"])
        signature = self.root / "final.AppImage.sig"
        original = signature.read_bytes()
        command = [str(example), str(package), str(signature), str(public)]
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
        package.write_bytes(b"changed after final signing")
        self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
        package.write_bytes(b"exact final installer bytes")
        for invalid in (b"malformed", original[:12], b""):
            signature.write_bytes(invalid)
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
        signature.write_bytes(original)
        other = self.root / "other-signer"
        other.mkdir()
        public.write_text(builder.updater_environment("build_only", other, os.environ)["NELOMAI_UPDATER_PUBLIC_KEY"])
        self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)

    def test_public_test_pin_is_regenerated_without_passing_private_artifacts(self):
        environment = {**os.environ, "SOURCE_SHA": SOURCE, "GITHUB_REPOSITORY": "example/repo", "GITHUB_RUN_ID": "42"}
        command = [sys.executable, str(SCRIPTS / "prepare-release-trust.py"), "--mode", "build_only"]
        first = self.root / "compile-public.raw"
        subprocess.run([*command, "--public-key", str(first)], env=environment, check=True, capture_output=True)
        second, private = self.root / "sign-public.raw", self.root / "private.raw"
        result = subprocess.run([*command, "--phase", "signing", "--public-key", str(second), "--private-key", str(private)],
                                env=environment, check=True, capture_output=True)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(first.read_bytes(), Ed25519PrivateKey.from_private_bytes(private.read_bytes()).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        self.assertEqual(result.stdout, b"")
        self.assertEqual(private.stat().st_mode & 0o777, 0o600)
        blocked = subprocess.run([sys.executable, str(SCRIPTS / "prepare-release-trust.py"), "--mode", "publish_approved_candidate",
            "--phase", "finalization", "--public-key", str(self.root / "blocked-public"), "--private-key", str(self.root / "blocked-private")],
            env=environment, capture_output=True, text=True)
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("forbidden", blocked.stderr)
        self.assertFalse((self.root / "blocked-private").exists())

    def test_actual_tauri_test_signer_does_not_require_release_secrets(self):
        builder = module("build-release-platform")
        work = self.root / "test-updater"
        work.mkdir()
        environment = {key: value for key, value in os.environ.items() if "SIGNING" not in key}
        generated = builder.updater_environment("build_only", work, environment)
        self.assertTrue(generated["TAURI_SIGNING_PRIVATE_KEY"])
        self.assertIn(b"minisign public key", base64.b64decode(generated["NELOMAI_UPDATER_PUBLIC_KEY"]))
        self.assertEqual(environment.get("TAURI_SIGNING_PRIVATE_KEY"), None)

    def test_apk_signature_layer_cannot_hide_changes_to_native_dex_or_resources(self):
        finalizer = module("finalize-release-candidate")
        before, after = self.root / "unsigned.apk", self.root / "signed.apk"
        content = {"classes.dex": b"real digest fixture", "lib/arm64-v8a/runtime.so": b"native",
                   "assets/runtime/container-manifest-v1.json": b"signed manifest"}
        with zipfile.ZipFile(before, "w") as archive:
            for name, value in content.items():
                archive.writestr(name, value)
        with zipfile.ZipFile(after, "w") as archive:
            for name, value in content.items():
                archive.writestr(name, value)
            archive.writestr("META-INF/CERT.RSA", b"outer signature")
            archive.writestr("META-INF/MANIFEST.MF", b"signature manifest")
        self.assertEqual(finalizer.apk_payload(before), finalizer.apk_payload(after))
        with zipfile.ZipFile(after, "w") as archive:
            for name, value in content.items():
                archive.writestr(name, value + (b"changed" if name == "classes.dex" else b""))
        self.assertNotEqual(finalizer.apk_payload(before), finalizer.apk_payload(after))
