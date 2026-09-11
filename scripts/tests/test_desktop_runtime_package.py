"""Exercise the packager CLI; header fixtures are not runnable release engines."""
import hashlib
import json
import os
import plistlib
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption


SCRIPT = Path(__file__).resolve().parents[1] / "package-runtime-artifact.py"


def elf(machine=62):
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", header, 16, 2, machine, 1)
    return bytes(header)


def pe(dll=False):
    header = bytearray(512)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3c, 0x80)
    header[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", header, 0x84, 0x8664, 1, 0, 0, 0, 240, 0x2022 if dll else 0x22)
    struct.pack_into("<H", header, 0x98, 0x20b)
    return bytes(header)


class DesktopPackageTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="nelomai-desktop-package-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.payload = self.root / "payload"
        self.payload.mkdir()
        self.key = Ed25519PrivateKey.generate()
        self.key_path = self.root / "local-test-key"
        self.key_path.write_bytes(self.key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
        for name in ("nelomai-runtime", "nelomai-unix-service", "amneziawg-go"):
            self.put(name, elf(), executable=True)
        self.put("resolvconf", b"#!/bin/sh\nexit 0\n", executable=True)
        self.put("webview/index.html", b"<html>structural fixture only</html>")
        self.put("webview/_app/start.js", b"window.fixture = true;")
        for name in ("AMNEZIAWG-GO-LICENSE.txt", "TAURI-MIT.txt", "TAURI-APACHE-2.0.txt"):
            self.put("licenses/" + name, b"Test attribution fixture; not a release license.")

    def put(self, name, value, executable=False):
        path = self.payload / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        path.chmod(0o755 if executable else 0o644)
        return path

    def run_package(self, output="output", platform="linux", architecture="x86_64", version="0.2.18", source_commit="a" * 40):
        return subprocess.run([
            sys.executable, str(SCRIPT), "--payload", str(self.payload),
            "--output", str(self.root / output), "--version", version,
            "--source-commit", source_commit, "--platform", platform,
            "--architecture", architecture, "--signing-key", str(self.key_path),
        ], capture_output=True, text=True)

    def test_archive_preserves_executable_modes_and_signs_exact_bytes_deterministically(self):
        result = self.run_package()
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.root / "output"
        raw = (output / "runtime-manifest-v1.json").read_bytes()
        manifest = json.loads(raw)
        self.key.public_key().verify((output / "runtime-manifest-v1.sig").read_bytes(),
                                     b"nelomai-runtime-manifest-v1\0" + raw)
        self.assertEqual({key: manifest[key] for key in manifest if key != "files"}, {
            "format_version": 1, "runtime_version": "0.2.18", "source_commit": "a" * 40,
            "platform": "linux", "architecture": "x86_64", "contract_version": 1,
        })
        with zipfile.ZipFile(output / "runtime.zip") as archive:
            self.assertIn("webview/_app/start.js", archive.namelist())
            self.assertEqual(set(archive.namelist()), {item["path"] for item in manifest["files"]})
            for item in manifest["files"]:
                value = archive.read(item["path"])
                self.assertEqual(hashlib.sha256(value).hexdigest(), item["sha256"])
                self.assertEqual(len(value), item["size_bytes"])
            self.assertEqual(stat.S_IMODE(archive.getinfo("nelomai-runtime").external_attr >> 16), 0o755)
            self.assertEqual(stat.S_IMODE(archive.getinfo("webview/index.html").external_attr >> 16), 0o644)
        self.assertEqual(self.run_package("second").returncode, 0)
        for name in ("runtime.zip", "runtime-manifest-v1.json", "runtime-manifest-v1.sig"):
            self.assertEqual((output / name).read_bytes(), (self.root / "second" / name).read_bytes())

    def assert_rejected(self, **kwargs):
        result = self.run_package(**kwargs)
        self.assertNotEqual(result.returncode, 0, "unsafe/incomplete payload was signed")
        self.assertFalse((self.root / kwargs.get("output", "output")).exists())

    def test_missing_engine_ui_or_license_is_not_signed(self):
        for index, name in enumerate(("nelomai-runtime", "nelomai-unix-service", "amneziawg-go",
                                      "resolvconf", "webview/index.html", "licenses/TAURI-MIT.txt")):
            with self.subTest(name=name):
                path = self.payload / name
                withheld = self.root / "withheld"
                path.rename(withheld)
                try:
                    self.assert_rejected(output="missing-" + str(index))
                finally:
                    withheld.rename(path)

    def test_symlink_cannot_smuggle_an_external_file(self):
        (self.payload / "external").symlink_to(self.key_path)
        self.assert_rejected()

    def test_nonportable_paths_are_not_signed(self):
        for index, name in enumerate(("CON.txt", "bad\\name", "trailing. ", "control\u0085.txt")):
            with self.subTest(name=name):
                path = self.put(name, b"bad path")
                try:
                    self.assert_rejected(output="path-" + str(index))
                finally:
                    path.unlink()

    def test_wrong_architecture_or_binary_format_is_rejected(self):
        relocatable = bytearray(elf())
        struct.pack_into("<H", relocatable, 16, 1)
        for index, value in enumerate((elf(183), b"not a compiled executable", bytes(relocatable))):
            self.put("nelomai-runtime", value, executable=True)
            self.assert_rejected(output="binary-" + str(index))

    def test_nonexecutable_runtime_is_rejected(self):
        (self.payload / "nelomai-runtime").chmod(0o644)
        self.assert_rejected()

    def test_unsupported_target_is_not_relabelled(self):
        self.assert_rejected(platform="linux", architecture="aarch64")

    def test_explicit_signing_key_must_be_outside_payload(self):
        self.key_path = self.put("key-material", self.key_path.read_bytes())
        self.assert_rejected()

    def test_environment_file_is_not_embedded(self):
        self.put(".env.production", b"TEST_PRIVATE_VALUE=not-a-real-secret")
        self.assert_rejected()

    def test_hardlinked_signing_key_is_not_embedded(self):
        os.link(self.key_path, self.payload / "apparently-harmless-resource")
        self.assert_rejected()

    def test_identity_must_fit_runtime_v1_contract(self):
        for index, version in enumerate(("0.2.18-" + "x" * 64, "0.2.18-pre+build", "invalid")):
            self.assert_rejected(output="version-" + str(index), version=version)
        self.assert_rejected(output="source", source_commit="main")

    def test_manifest_larger_than_verifier_limit_is_not_published(self):
        for index in range(3000):
            self.put("resources/" + str(index) + "-" + "x" * 225, b"x")
        self.assert_rejected()

    def test_existing_output_even_empty_is_never_replaced(self):
        output = self.root / "output"
        output.mkdir()
        result = self.run_package()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(output.iterdir()), [])

    def test_windows_index_marks_exe_and_dll_roles_without_unix_mode_bits(self):
        self.payload = self.root / "windows"
        self.payload.mkdir()
        for name in ("nelomai-runtime.exe", "nelomai-windows-service.exe"):
            self.put(name, pe())
        for name in ("tunnel.dll", "wireguard.dll", "amneziawg-tunnel.dll", "wintun.dll"):
            self.put(name, pe(dll=True))
        self.put("webview/index.html", b"Windows UI fixture")
        for name in ("TAURI-MIT.txt", "TAURI-APACHE-2.0.txt", "AMNEZIAWG-GO-LICENSE.txt",
                     "WIREGUARD-WINDOWS-LICENSE.txt", "WIREGUARD-NT-LICENSE.txt",
                     "AMNEZIAWG-WINDOWS-README.txt", "WINTUN-LICENSE.txt"):
            self.put("licenses/" + name, b"Test attribution only")
        result = self.run_package(platform="windows")
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads((self.root / "output/runtime-manifest-v1.json").read_bytes())
        roles = {item["path"]: item["role"] for item in manifest["files"]}
        self.assertEqual(roles["nelomai-runtime.exe"], "executable")
        self.assertEqual(roles["wintun.dll"], "shared_library")
        self.put("wintun.dll", elf())
        self.assert_rejected(output="wrong-dll", platform="windows")

    @unittest.skipUnless(sys.platform == "darwin", "actual macOS ad-hoc signer required")
    def test_macos_signs_final_copied_executables_before_hashing_without_changing_input(self):
        source = self.root / "probe.c"
        source.write_text("int main(void) { return 0; }\n")
        runtime = self.payload / "nelomai-runtime"
        subprocess.run(["/usr/bin/cc", "-arch", "arm64", "-Wl,-no_adhoc_codesign",
                        str(source), "-o", str(runtime)], check=True, capture_output=True)
        original = runtime.read_bytes()
        self.assertNotEqual(subprocess.run(["/usr/bin/codesign", "--verify", str(runtime)],
                                          capture_output=True).returncode, 0)
        for name in ("nelomai-unix-service", "amneziawg-go", "wireguard-go"):
            shutil.copyfile(runtime, self.payload / name)
            (self.payload / name).chmod(0o755)
        (self.payload / "resolvconf").unlink()
        self.put("licenses/WIREGUARD-GO-LICENSE.txt", b"Test attribution only")
        result = self.run_package(platform="macos", architecture="aarch64")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(runtime.read_bytes(), original)
        manifest = json.loads((self.root / "output/runtime-manifest-v1.json").read_bytes())
        with zipfile.ZipFile(self.root / "output/runtime.zip") as archive:
            self.assertIn("Nelomai.app/Contents/MacOS/Nelomai", archive.namelist())
            info = plistlib.loads(archive.read("Nelomai.app/Contents/Info.plist"))
            self.assertEqual(info["CFBundleExecutable"], "Nelomai")
            self.assertEqual(info["CFBundleIconFile"], "icon.icns")
            self.assertIn("Nelomai.app/Contents/Resources/icon.icns", archive.namelist())
            self.assertNotIn("nelomai-runtime", archive.namelist())
            extracted_bundle = self.root / "extracted"
            archive.extractall(extracted_bundle)
            for item in manifest["files"]:
                value = archive.read(item["path"])
                self.assertEqual(hashlib.sha256(value).hexdigest(), item["sha256"])
                if item["role"] == "executable":
                    extracted = extracted_bundle / item["path"]
                    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(extracted)],
                                   check=True, capture_output=True)
                    detail = subprocess.run(["/usr/bin/codesign", "-dv", str(extracted)],
                                            check=True, capture_output=True, text=True)
                    self.assertIn("Signature=adhoc", detail.stderr)
                    self.assertNotEqual(value, original)
            subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict",
                            str(extracted_bundle / "Nelomai.app")], check=True, capture_output=True)
        again = self.run_package("repeat-mac", platform="macos", architecture="aarch64")
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual((self.root / "output/runtime.zip").read_bytes(),
                         (self.root / "repeat-mac/runtime.zip").read_bytes())


if __name__ == "__main__":
    unittest.main()
