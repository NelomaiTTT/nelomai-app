"""A library-test manifest is checked in PE resources, not by string presence."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import tomllib
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


def configure_and_run(tool, root, record, sdk):
    config = root / "runner with spaces.toml"
    original_images = {path: path.read_bytes() for path in (root / "target").rglob("*.exe")}
    record.write_text("stale preparation")
    tool.configure(root, config, record, sdk)
    assert all(path.read_bytes() == data for path, data in original_images.items()), "preflight must not embed before the final Cargo link"
    assert not record.exists(), "preflight must not claim a prepared executable"
    runner = tomllib.loads(config.read_text(encoding="utf-8"))["target"]["x86_64-pc-windows-msvc"]["runner"]
    assert runner[:3] == [sys.executable, str(Path(tool.__file__).resolve()), "run"]
    assert runner[-1] == "--"
    options = dict(zip(runner[3:-1:2], runner[4:-1:2]))
    exe = Path(options["--expected-executable"])
    return tool.run_harness([str(exe)], exe, Path(options["--manifest"]), Path(options["--mt"]), Path(options["--record"]))


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

    def test_runner_prepares_after_relink_and_preserves_failure_and_postguard(self):
        tool = module("windows/prepare-lib-test-manifest")
        self.assertTrue(callable(getattr(tool, "run_harness", None)),
                        "manifest preparation must run inside Cargo runner after final link")
        with tempfile.TemporaryDirectory(prefix="runner with spaces ") as temporary:
            root = Path(temporary)
            exe = root / "nelomai_app_lib-abcdef.exe"
            source = root / "locked manifest.xml"
            source.write_bytes(MANIFEST)
            mt = root / "mt.exe"
            record = root / "prepared.json"
            command = [str(exe), "platform::updater::", "--nocapture", "argument with spaces"]
            for test_exit, corrupt_after, embed in ((0, False, True), (17, False, True),
                                                    (0, True, True), (17, True, True), (0, False, False)):
                exe.write_bytes(b"final Cargo relink without resource")
                calls = []
                def run(argv, **kwargs):
                    calls.append(argv)
                    if argv[0] == str(mt):
                        self.assertEqual(argv, [str(mt), "-nologo", "-manifest", str(source), f"-outputresource:{exe};#1"])
                        if embed:
                            exe.write_bytes(image())
                        return subprocess.CompletedProcess(argv, 0)
                    self.assertEqual(argv, command)
                    self.assertNotIn("cwd", kwargs)
                    self.assertNotIn("env", kwargs)
                    tool.verify_manifest(exe)
                    self.assertEqual(json.loads(record.read_text())["executable_sha256"], tool.digest(exe))
                    if corrupt_after:
                        exe.write_bytes(b"changed during test")
                    return subprocess.CompletedProcess(argv, test_exit)
                with patch.object(tool.subprocess, "run", side_effect=run):
                    if not embed:
                        with self.assertRaises(ValueError):
                            tool.run_harness(command, exe, source, mt, record)
                        self.assertEqual(len(calls), 1)
                    else:
                        result = tool.run_harness(command, exe, source, mt, record)
                        self.assertEqual(result, test_exit or int(corrupt_after))
                        self.assertEqual(len(calls), 2)
            with patch.object(tool.subprocess, "run", side_effect=AssertionError("must not launch")):
                with self.assertRaisesRegex(ValueError, "Cargo-selected"):
                    tool.run_harness([str(root / "wrong.exe")], exe, source, mt, record)

    def test_runner_real_spawn_inherits_argv_environment_and_cwd(self):
        tool = module("windows/prepare-lib-test-manifest")
        real_run = subprocess.run
        with tempfile.TemporaryDirectory(prefix="spawn with spaces ") as temporary:
            root = Path(temporary)
            exe = Path(sys.executable)
            observed = root / "observed.json"
            child = ("import os,sys,json; from pathlib import Path; "
                     "Path(os.environ['RUNNER_OBSERVED']).write_text(json.dumps(dict(argv=sys.argv[1:], cwd=os.getcwd(), sentinel=os.environ['RUNNER_SENTINEL']))); "
                     "sys.exit(23)")
            manifest = root / "manifest.xml"
            manifest.write_bytes(MANIFEST)
            mt = root / "mt.exe"
            prepared = root / "sdk-prepared"
            command = [str(exe), "-c", child, "platform::updater::", "--exact", "argument with spaces", "", 'quote"and\\slash']
            def run(argv, **kwargs):
                if argv[0] == str(mt):
                    prepared.touch()
                    return subprocess.CompletedProcess(argv, 0)
                self.assertTrue(prepared.exists())
                return real_run(argv, **kwargs)
            # Only SDK/PE format are substituted. The runner's process spawn is real.
            with patch.dict(os.environ, RUNNER_OBSERVED=str(observed), RUNNER_SENTINEL="inherited value"), \
                 patch.object(tool.subprocess, "run", side_effect=run), \
                 patch.object(tool, "verify_manifest"):
                self.assertEqual(tool.run_harness(command, exe, manifest, mt, root / "record.json"), 23)
            self.assertEqual(json.loads(observed.read_text()), dict(argv=command[3:], cwd=os.getcwd(), sentinel="inherited value"))

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
                if command == [str(exe)]:
                    return subprocess.CompletedProcess(command, 0)
                self.assertEqual(command, [str(mt), "-nologo", "-manifest", str(source), f"-outputresource:{exe};#1"])
                if embed:
                    exe.write_bytes(image())
                return subprocess.CompletedProcess(command, 0, "", "")

            with patch.object(tool.subprocess, "run", side_effect=run):
                configure_and_run(tool, root, record, sdk)
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
                configure_and_run(tool, root, record, sdk)
            self.assertFalse(record.exists())
            artifacts = [artifact, dict(artifact, executable=str(exe.with_name("nelomai_app_lib-123456.exe")))]
            with patch.object(tool.subprocess, "run", side_effect=run), self.assertRaisesRegex(ValueError, "exactly one"):
                configure_and_run(tool, root, record, sdk)
            artifacts = [dict(artifact, executable=str(root / "nelomai_app_lib-abcdef.exe"))]
            with patch.object(tool.subprocess, "run", side_effect=run), self.assertRaisesRegex(ValueError, "expected library-test image"):
                configure_and_run(tool, root, record, sdk)
            # Compiler failure propagates before mt.exe can be invoked.
            with patch.object(tool.subprocess, "run", side_effect=subprocess.CalledProcessError(101, "cargo")):
                with self.assertRaises(subprocess.CalledProcessError):
                    configure_and_run(tool, root, record, sdk)

    def test_cargo_json_utf8_bytes_are_independent_of_windows_cp1252_reader(self):
        tool = module("windows/prepare-lib-test-manifest")
        real_run = subprocess.run
        for stage in ("metadata", "test"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / ("registry-ā" if stage == "metadata" else "registry") / "tauri-build/src/windows-app-manifest.xml"
                source.parent.mkdir(parents=True)
                source.write_bytes(MANIFEST)
                exe = root / "target/debug" / ("deps-ā" if stage == "test" else "deps") / "nelomai_app_lib-abcdef.exe"
                exe.parent.mkdir(parents=True)
                exe.write_bytes(b"unmanifested original")
                sdk = root / "sdk"
                mt = sdk / "10.0.26100.0/x64/mt.exe"
                mt.parent.mkdir(parents=True)
                mt.touch()
                record = root / "record.json"
                metadata = dict(target_directory=str(root / "target"), packages=[dict(
                    name="tauri-build", manifest_path=str(source.parents[1] / "Cargo.toml"))])
                artifact = dict(reason="compiler-artifact", target=dict(name="nelomai_app_lib"),
                                profile=dict(test=True), executable=str(exe))

                def run(command, **kwargs):
                    if command[:1] == ["cargo"]:
                        value = metadata if command[1] == "metadata" else artifact
                        payload = (json.dumps(value, ensure_ascii=False) + "\n").encode("utf-8")
                        if command[1] == stage:
                            self.assertIn(b"\x81", payload)  # UTF-8 ā contains a byte undefined in cp1252.
                        # A real child writes bytes; subprocess performs the actual pipe decoding.
                        child = [sys.executable, "-c", "import sys; sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]))", payload.hex()]
                        return real_run(child, **kwargs)
                    if command == [str(exe)]:
                        return subprocess.CompletedProcess(command, 0)
                    self.assertEqual(command, [str(mt), "-nologo", "-manifest", str(source), f"-outputresource:{exe};#1"])
                    exe.write_bytes(image())
                    return subprocess.CompletedProcess(command, 0)

                with patch.object(tool.subprocess, "_text_encoding", return_value="cp1252"), \
                     patch.object(tool.subprocess, "run", side_effect=run):
                    configure_and_run(tool, root, record, sdk)
                saved = json.loads(record.read_text())
                self.assertEqual(saved["manifest_source"], str(source))
                self.assertEqual(saved["executable"], str(exe))

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
