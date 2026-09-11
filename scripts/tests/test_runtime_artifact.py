"""Release-facing runtime gates; synthetic ELF bytes are structural fixtures only."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from scripts.tests.test_desktop_runtime_package import elf

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
SOURCE = "a" * 40
PREFIX = "nelomai-runtime-0.2.18-linux-x86_64"


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), SCRIPTS / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class ArtifactFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="runtime-release-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.key = Ed25519PrivateKey.generate()
        self.keyfile = self.root / "test-key"
        self.keyfile.write_bytes(self.key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
        self.public = self.root / "public-key"
        self.public.write_bytes(self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        self.payload = self.root / "payload"
        self.payload.mkdir()
        for name in ("nelomai-runtime", "nelomai-unix-service", "amneziawg-go"):
            self.put(name, elf(), 0o755)
        self.put("resolvconf", b"#!/bin/sh\nexit 0\n", 0o755)
        self.put("webview/index.html", b"structural fixture")
        for name in ("TAURI-MIT.txt", "TAURI-APACHE-2.0.txt", "AMNEZIAWG-GO-LICENSE.txt"):
            self.put("licenses/" + name, b"fixture attribution")

    def put(self, name, value, mode=0o644):
        path = self.payload / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        path.chmod(mode)

    def command(self, name, *args):
        return subprocess.run([sys.executable, str(SCRIPTS / (name + ".py")), *map(str, args)],
                              capture_output=True, text=True)

    def build(self, output="candidate"):
        return self.command("build-runtime-manifest", "--payload", self.payload,
                            "--output", self.root / output, "--version", "0.2.18",
                            "--source-commit", SOURCE, "--platform", "linux",
                            "--architecture", "x86_64", "--signing-key", self.keyfile)


class RuntimeArtifactTest(ArtifactFixture):
    def test_android_wrapper_rejects_embedded_signing_key_before_packager(self):
        key = self.payload / "innocent-resource"
        key.write_bytes(self.keyfile.read_bytes())
        result = self.command("build-runtime-manifest", "--payload", self.payload, "--output", self.root / "candidate",
            "--version", "0.2.18", "--source-commit", SOURCE, "--platform", "android",
            "--architecture", "aarch64", "--signing-key", key, "--readelf", self.root / "absent-readelf")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signing key must be outside payload", result.stderr)

    def test_android_incomplete_payload_is_rejected_before_native_tools(self):
        verifier = module("verify-runtime-artifact")
        with self.assertRaisesRegex(ValueError, "incomplete"):
            verifier.inspect(self.payload, {"platform": "android", "architecture": "aarch64"}, self.root / "absent-readelf")

    def test_authenticated_but_wrong_contract_shape_or_identity_is_rejected(self):
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        verifier = module("verify-runtime-artifact")
        candidate = self.root / "candidate"
        manifest = candidate / (PREFIX + ".manifest.json")
        signature = candidate / (PREFIX + ".manifest.sig")
        original = json.loads(manifest.read_bytes())
        for changes in ({"format_version": True}, {"contract_version": 2}, {"extra": "unrecognized"},
                        {"platform": "windows"}, {"architecture": "aarch64"}, {"files": []}):
            raw = json.dumps({**original, **changes}, sort_keys=True, separators=(",", ":")).encode()
            manifest.write_bytes(raw)
            signature.write_bytes(self.key.sign(b"nelomai-runtime-manifest-v1\0" + raw))
            with self.assertRaises((ValueError, subprocess.CalledProcessError), msg=str(changes)):
                verifier.verify(candidate / (PREFIX + ".zip"), manifest, signature,
                    self.public, "0.2.18", SOURCE, "linux", "x86_64")

    def test_archive_rejects_tampered_file_symlink_and_mode_changes(self):
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        verifier = module("verify-runtime-artifact")
        candidate = self.root / "candidate"
        archive_path = candidate / (PREFIX + ".zip")
        with zipfile.ZipFile(archive_path) as archive:
            original = [(info, archive.read(info)) for info in archive.infolist()]
        for change in ("hash", "mode", "symlink"):
            with zipfile.ZipFile(archive_path, "w") as archive:
                for info, value in original:
                    copy = zipfile.ZipInfo(info.filename)
                    copy.external_attr = info.external_attr
                    if info.filename == "nelomai-runtime":
                        if change == "hash": value = b"!" + value[1:]
                        elif change == "mode": copy.external_attr = 0o100644 << 16
                        else: copy.external_attr = 0o120755 << 16
                    archive.writestr(copy, value)
            with self.assertRaises((ValueError, subprocess.CalledProcessError), msg=change):
                verifier.verify(archive_path, candidate / (PREFIX + ".manifest.json"),
                    candidate / (PREFIX + ".manifest.sig"), self.public, "0.2.18", SOURCE, "linux", "x86_64")

    @unittest.skipUnless(sys.platform == "darwin", "actual macOS verifier required")
    def test_macos_reextraction_verifies_final_adhoc_signatures_without_resigning(self):
        source = self.root / "probe.c"
        source.write_text("int main(void) { return 0; }\n")
        executable = self.root / "probe"
        subprocess.run(["/usr/bin/cc", "-arch", "arm64", str(source), "-o", str(executable)], check=True, capture_output=True)
        for name in ("nelomai-runtime", "nelomai-unix-service", "amneziawg-go", "wireguard-go"):
            self.put(name, executable.read_bytes(), 0o755)
        (self.payload / "resolvconf").unlink()
        self.put("licenses/WIREGUARD-GO-LICENSE.txt", b"fixture attribution")
        candidate = self.root / "candidate"
        result = self.command("build-runtime-manifest", "--payload", self.payload, "--output", candidate,
            "--version", "0.2.18", "--source-commit", SOURCE, "--platform", "macos",
            "--architecture", "aarch64", "--signing-key", self.keyfile)
        self.assertEqual(result.returncode, 0, result.stderr)
        prefix = "nelomai-runtime-0.2.18-macos-aarch64"
        before = {path.name: path.read_bytes() for path in candidate.iterdir()}
        verifier = module("verify-runtime-artifact")
        manifest = verifier.verify(candidate / (prefix + ".zip"), candidate / (prefix + ".manifest.json"),
            candidate / (prefix + ".manifest.sig"), self.public, "0.2.18", SOURCE, "macos", "aarch64",
            output=self.root / "extracted")
        self.assertEqual(before, {path.name: path.read_bytes() for path in candidate.iterdir()})
        for item in manifest["files"]:
            self.assertEqual(hashlib.sha256((self.root / "extracted" / item["path"]).read_bytes()).hexdigest(), item["sha256"])

    def test_immutable_names_preserve_existing_packager_final_bytes(self):
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        candidate = self.root / "candidate"
        module("package-runtime-artifact").package(self.payload, self.root / "original",
            "0.2.18", SOURCE, "linux", "x86_64", self.keyfile)
        for final, original in ((".zip", "runtime.zip"),
                                (".manifest.json", "runtime-manifest-v1.json"),
                                (".manifest.sig", "runtime-manifest-v1.sig")):
            self.assertEqual((candidate / (PREFIX + final)).read_bytes(),
                             (self.root / "original" / original).read_bytes())
        self.assertNotEqual(self.build().returncode, 0, "immutable candidate was replaced")

    def test_verifier_checks_signature_identity_archive_and_executable_modes(self):
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        verifier = module("verify-runtime-artifact")
        candidate = self.root / "candidate"
        manifest = candidate / (PREFIX + ".manifest.json")
        args = (candidate / (PREFIX + ".zip"), manifest,
                candidate / (PREFIX + ".manifest.sig"), self.public, "0.2.18", SOURCE,
                "linux", "x86_64")
        verified = verifier.verify(*args)
        self.assertEqual(verified["source_commit"], SOURCE)
        signature = args[2].read_bytes()
        args[2].write_bytes(bytes(64))
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            verifier.verify(*args)
        args[2].write_bytes(signature)
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            verifier.verify(*args[:5], "b" * 40, *args[6:])
        with zipfile.ZipFile(args[0], "a") as archive:
            archive.writestr("unindexed", b"not authenticated")
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            verifier.verify(*args)


if __name__ == "__main__":
    unittest.main()
