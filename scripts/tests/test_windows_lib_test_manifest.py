"""A library-test manifest is checked in PE resources, not by string presence."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.tests.test_runtime_artifact import module

MANIFEST = b'''<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><dependency><dependentAssembly><assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*" /></dependentAssembly></dependency></assembly>'''


def image(manifest=MANIFEST, resource_id=1):
    # Hand-built PE32+ resource tree: RT_MANIFEST(24) / ID / language 1033.
    data = bytearray(1024 + len(manifest))
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", data, 0x84, 0x8664, 1)
    struct.pack_into("<H", data, 0x94, 240)
    struct.pack_into("<H", data, 0x98, 0x20b)
    struct.pack_into("<I", data, 0x98 + 108, 16)
    struct.pack_into("<II", data, 0x98 + 112 + 16, 0x1000, 512 + len(manifest))
    section = 0x98 + 240
    struct.pack_into("<8sIIII", data, section, b".rsrc\0\0\0", 512 + len(manifest), 0x1000, 512 + len(manifest), 512)
    for offset, key, target in ((0, 24, 24), (24, resource_id, 48), (48, 1033, 72)):
        struct.pack_into("<H", data, 512 + offset + 14, 1)
        struct.pack_into("<II", data, 512 + offset + 16, key, target | (0x80000000 if offset < 48 else 0))
    struct.pack_into("<IIII", data, 512 + 72, 0x1200, len(manifest), 65001, 0)
    data[1024:] = manifest
    return bytes(data)


class WindowsLibTestManifestTest(unittest.TestCase):
    def test_resource_one_requires_exact_v6_dependency_and_no_elevation(self):
        tool = module("windows/prepare-lib-test-manifest")
        with tempfile.TemporaryDirectory() as temporary:
            exe = Path(temporary) / "test.exe"
            exe.write_bytes(image())
            tool.verify_manifest(exe)
            for value in (image(resource_id=2), image(MANIFEST.replace(b'6.0.0.0', b'5.0.0.0')),
                          image(MANIFEST.replace(b'6595b64144ccf1df', b'0000000000000000')),
                          image(MANIFEST.replace(b'</assembly>', b'<trustInfo><requestedExecutionLevel level="requireAdministrator" /></trustInfo></assembly>')),
                          b"MZ" + MANIFEST):
                with self.subTest(value=value[:20]), self.assertRaises(ValueError):
                    exe.write_bytes(value)
                    tool.verify_manifest(exe)

    def test_prepares_exact_compiler_artifact_and_verifies_embedded_bytes(self):
        tool = module("windows/prepare-lib-test-manifest")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            exe = root / "target/debug/deps/nelomai_app_lib-abcdef.exe"
            exe.parent.mkdir(parents=True)
            exe.write_bytes(b"unmanifested original")
            source = root / "registry/tauri-build-2.6.3/src/windows-app-manifest.xml"
            source.parent.mkdir(parents=True)
            source.write_bytes(MANIFEST)
            record = root / "record.json"
            sdk = root / "sdk"
            mt = sdk / "10.0.26100.0/x64/mt.exe"
            mt.parent.mkdir(parents=True)
            mt.write_bytes(b"tool substitute")
            artifact = dict(reason="compiler-artifact", target=dict(name="nelomai_app_lib"),
                            profile=dict(test=True), executable=str(exe))

            embed = True
            artifacts = [artifact]

            def run(command, **kwargs):
                if command[:2] == ["cargo", "metadata"]:
                    return subprocess.CompletedProcess(command, 0, json.dumps(dict(target_directory=str(root / "target"),
                        packages=[dict(name="tauri-build", manifest_path=str(source.parents[1] / "Cargo.toml"))])), "")
                if command[:2] == ["cargo", "test"]:
                    self.assertEqual(command[2:], ["--locked", "-p", "nelomai-app", "--lib", "--no-run", "--message-format=json"])
                    return subprocess.CompletedProcess(command, 0, "\n".join(map(json.dumps, artifacts)) + "\n", "")
                self.assertEqual(command, [str(mt), "-nologo", "-manifest", str(source), f"-outputresource:{exe};#1"])
                if embed:
                    exe.write_bytes(image())
                return subprocess.CompletedProcess(command, 0, "", "")

            with patch.object(tool.subprocess, "run", side_effect=run):
                tool.prepare(root, record, sdk)
            saved = json.loads(record.read_text())
            self.assertEqual(saved["executable"], str(exe))
            self.assertEqual(saved["manifest_sha256"], hashlib.sha256(MANIFEST).hexdigest())
            tool.verify_record(record)
            exe.write_bytes(image().replace(b'6.0.0.0', b'5.0.0.0'))
            with self.assertRaisesRegex(ValueError, "changed after preparation"):
                tool.verify_record(record)
            # An exit-0 SDK tool without a resource update must not pass.
            embed = False
            original = bytearray(image())
            struct.pack_into("<II", original, 0x98 + 112 + 16, 0, 0)
            exe.write_bytes(original)
            record.unlink()
            with patch.object(tool.subprocess, "run", side_effect=run), self.assertRaisesRegex(ValueError, "resource directory"):
                tool.prepare(root, record, sdk)
            self.assertFalse(record.exists())
            artifacts = [artifact, dict(artifact, executable=str(exe.with_name("nelomai_app_lib-123456.exe")))]
            with patch.object(tool.subprocess, "run", side_effect=run), self.assertRaisesRegex(ValueError, "exactly one"):
                tool.prepare(root, record, sdk)
            artifacts = [dict(artifact, executable=str(root / "nelomai_app_lib-abcdef.exe"))]
            with patch.object(tool.subprocess, "run", side_effect=run), self.assertRaisesRegex(ValueError, "expected library-test image"):
                tool.prepare(root, record, sdk)
            # Compiler failure propagates before mt.exe can be invoked.
            with patch.object(tool.subprocess, "run", side_effect=subprocess.CalledProcessError(101, "cargo")):
                with self.assertRaises(subprocess.CalledProcessError):
                    tool.prepare(root, record, sdk)

    def test_mt_success_without_manifest_cannot_make_preparation_pass(self):
        # Validate the postcondition itself: an exit-0 mt double is insufficient.
        tool = module("windows/prepare-lib-test-manifest")
        with tempfile.TemporaryDirectory() as temporary:
            exe = Path(temporary) / "test.exe"
            data = bytearray(image())
            struct.pack_into("<II", data, 0x98 + 112 + 16, 0, 0)
            exe.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "resource directory"):
                tool.verify_manifest(exe)


if __name__ == "__main__":
    unittest.main()
