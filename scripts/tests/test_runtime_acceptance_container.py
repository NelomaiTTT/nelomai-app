"""Structural staging tests, not GUI, installed ownership, or tunnel acceptance."""
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch
from packaging.version import InvalidVersion, Version

from scripts.tests.test_runtime_artifact import ArtifactFixture, SOURCE, PREFIX, SCRIPTS, module
import scripts.tests.test_runtime_release_set as release_set_fixture


class AcceptanceContainerTest(ArtifactFixture):
    def test_linux_final_pack_uses_output_plugin_and_rechecks_exact_bytes(self):
        self.stage()
        builder = module("build-runtime-acceptance-container")
        root, output = self.root / "repo", self.root / "package"
        (root / "src-tauri").mkdir(parents=True)
        (root / "src-tauri/bundle.linux.conf.json").write_text(json.dumps({"bundle": {"resources": {}}}))
        calls = []
        real_run = subprocess.run
        def native_tool(command, **kwargs):
            if command[1] not in ("build", "--appimage-extract", "--appimage-extract-and-run"):
                return real_run(command, **kwargs)
            calls.append(command)
            if command[1] == "build":
                self.assertEqual(kwargs["env"]["XDG_CACHE_HOME"], str(output / "tools-cache"))
                bundle = output / "target/x86_64-unknown-linux-gnu/release/bundle/appimage/test.AppImage"
                bundle.parent.mkdir(parents=True)
                bundle.write_bytes(b"intermediate")
                plugin = output / "tools-cache/tauri/linuxdeploy-plugin-appimage.AppImage"
                plugin.parent.mkdir(parents=True)
                plugin.write_bytes(b"same output plugin")
            elif command[1] == "--appimage-extract":
                destination = kwargs["cwd"] / "squashfs-root"
                if Path(command[0]).name == "test.AppImage":
                    shutil.copytree(self.root / "staged", destination / "usr/lib/Nelomai")
                    (destination / "usr/lib/Nelomai/runtime/engines/latest/0.2.18/nelomai-runtime").write_bytes(b"patched")
                else:
                    shutil.copytree(output / "linuxdeploy-extracted/squashfs-root", destination)
            else:
                self.assertEqual(command[1:3], ["--appimage-extract-and-run", "--appdir"])
                builder.verify_packaged_tree(Path(command[3]), self.root / "staged", self.public, "linux", "x86_64")
                Path(kwargs["env"]["OUTPUT"]).write_bytes(b"final AppImage")
            return subprocess.CompletedProcess(command, 0)
        with patch.object(builder.subprocess, "run", side_effect=native_tool):
            package = builder.package_desktop(self.root / "staged", output, self.public, "linux", "x86_64", root=root)
        self.assertTrue(package.is_file())
        self.assertEqual(len(calls), 4)

    def test_linux_repack_restores_only_signed_payload_and_preserves_dependencies(self):
        self.stage()
        builder = module("build-runtime-acceptance-container")
        extracted = self.root / "extracted/AppDir/usr/lib/Nelomai"
        shutil.copytree(self.root / "staged", extracted)
        dependency = extracted.parent / "libexample.so"
        dependency.write_bytes(b"bundled dependency")
        for relative in ("runtime/engines/stable/0.2.17/nelomai-runtime",
                         "dispatcher/1/nelomai-unix-service"):
            path = extracted / relative
            path.write_bytes(b"linuxdeploy rewritten ELF")
            path.chmod(0o644)
        builder.restore_linux_signed_payload(self.root / "extracted", self.root / "staged", self.public, "x86_64")
        builder.verify_packaged_tree(self.root / "extracted", self.root / "staged", self.public, "linux", "x86_64")
        self.assertEqual(dependency.read_bytes(), b"bundled dependency")
        unexpected = extracted / "runtime/unindexed"
        unexpected.write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "file set"):
            builder.restore_linux_signed_payload(self.root / "extracted", self.root / "staged", self.public, "x86_64")
        unexpected.unlink()
        signature = extracted / "runtime/container-manifest-v1.sig"
        signature.write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "signed metadata"):
            builder.restore_linux_signed_payload(self.root / "extracted", self.root / "staged", self.public, "x86_64")

    def test_keyless_native_stage_consumes_final_signatures_and_exact_zip_bytes(self):
        self.stage()
        builder = module("build-runtime-acceptance-container")
        self.assertTrue(callable(getattr(builder, "stage_signed", None)), "keyless native staging is missing")
        signed = self.root / "signed"
        shutil.copytree(self.candidate, signed / "release")
        shutil.copytree(self.root / "staged/runtime", signed / "containers/linux/acceptance")
        latest = signed / "latest/linux"
        latest.mkdir(parents=True)
        for suffix in (".zip", ".manifest.json", ".manifest.sig"):
            shutil.copyfile(self.candidate / (PREFIX + suffix), latest / (PREFIX + suffix))
        # Desktop fixture's latest and stable native payloads are identical;
        # only synthetic slot identity is different in its signed container.
        output = self.root / "keyless"
        builder.stage_signed(signed, self.root_digest, output, self.public, "linux", "x86_64", SOURCE, "acceptance")
        for path in (self.root / "staged").rglob("*"):
            if path.is_file():
                self.assertEqual(path.read_bytes(), (output / path.relative_to(self.root / "staged")).read_bytes())
        manifest = signed / "containers/linux/acceptance/container-manifest-v1.json"
        manifest.write_bytes(manifest.read_bytes() + b" ")
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            builder.stage_signed(signed, self.root_digest, self.root / "rejected-keyless", self.public,
                                 "linux", "x86_64", SOURCE, "acceptance")
        self.assertFalse((self.root / "rejected-keyless").exists())

    def setUp(self):
        super().setUp()
        self.candidate = release_set_fixture.RuntimeReleaseSetTest.four_candidates(self)
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        for path in (self.root / "candidate").iterdir():
            shutil.copyfile(path, self.candidate / path.name)
        aggregate = module("build-runtime-release-set")
        self.root_digest = aggregate.build(self.candidate, self.root / "root", "0.2.17", SOURCE, self.keyfile, self.public)
        for path in (self.root / "root").iterdir():
            shutil.copyfile(path, self.candidate / path.name)

    def stage(self, digest=None):
        self.assertTrue((SCRIPTS / "build-runtime-acceptance-container.py").is_file(), "two-slot acceptance builder is missing")
        return module("build-runtime-acceptance-container").stage(self.candidate, digest or self.root_digest,
            self.payload, self.root / "staged", self.keyfile, self.public, "linux", "x86_64", SOURCE)

    def test_two_slots_bind_root_and_preserve_every_final_stable_byte(self):
        before = {path.name: path.read_bytes() for path in self.candidate.iterdir()}
        self.stage()
        resources = self.root / "staged/runtime"
        verified = module("verify-runtime-artifact").authenticated("container",
            resources / "container-manifest-v1.json", resources / "container-manifest-v1.sig",
            self.public, "linux", "x86_64")
        # The panel consumes PEP 440 versions; Rust-authenticated semver alone
        # admitted a synthetic identity that could never enroll with that panel.
        try:
            synthetic = Version(verified["slots"][0]["manifest"]["runtime_version"])
        except InvalidVersion as error:
            self.fail(f"signed synthetic runtime is rejected by the panel version parser: {error}")
        self.assertGreater(synthetic, Version("0.2.17"))
        self.assertEqual([(slot["slot"], slot["manifest"]["runtime_version"]) for slot in verified["slots"]],
                         [("latest", "0.2.18"), ("stable", "0.2.17")])
        self.assertEqual(verified["stable_release_set_sha256"], self.root_digest)
        raw = self.candidate / (PREFIX + ".manifest.json")
        self.assertEqual(verified["stable_platform_manifest_sha256"], hashlib.sha256(raw.read_bytes()).hexdigest())
        self.assertEqual(verified["slots"][1]["manifest"], json.loads(raw.read_bytes()))
        for item in verified["slots"][1]["manifest"]["files"]:
            extracted = resources / "engines/stable/0.2.17" / item["path"]
            self.assertEqual(hashlib.sha256(extracted.read_bytes()).hexdigest(), item["sha256"])
            self.assertEqual(extracted.stat().st_mode & 0o777, 0o755 if item["role"] == "executable" else 0o644)
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.candidate.iterdir()})
        with self.assertRaisesRegex(ValueError, "immutable"):
            self.stage()

    def test_platform_digest_cannot_replace_root_digest(self):
        self.assertTrue((SCRIPTS / "build-runtime-acceptance-container.py").is_file(), "two-slot acceptance builder is missing")
        digest = hashlib.sha256((self.candidate / (PREFIX + ".manifest.json")).read_bytes()).hexdigest()
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            self.stage(digest)
        self.assertFalse((self.root / "staged").exists())

    def test_changed_candidate_is_not_staged(self):
        self.assertTrue((SCRIPTS / "build-runtime-acceptance-container.py").is_file(), "two-slot acceptance builder is missing")
        with (self.candidate / (PREFIX + ".zip")).open("ab") as stream:
            stream.write(b"changed after approval")
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            self.stage()
        self.assertFalse((self.root / "staged").exists())

    def test_native_package_reextraction_rejects_changed_modes_bytes_and_extra_runtime_files(self):
        self.stage()
        builder = module("build-runtime-acceptance-container")
        self.assertTrue(callable(getattr(builder, "verify_packaged_tree", None)), "post-packager exact-byte verification is missing")
        extracted = self.root / "extracted/AppDir/usr/lib/Nelomai"
        shutil.copytree(self.root / "staged", extracted)
        builder.verify_packaged_tree(self.root / "extracted", self.root / "staged", self.public, "linux", "x86_64")
        executable = extracted / "runtime/engines/stable/0.2.17/nelomai-runtime"
        original = executable.read_bytes()
        executable.write_bytes(b"rewritten after final signing")
        with self.assertRaisesRegex(ValueError, "packaged runtime bytes changed: engines/stable/0.2.17/nelomai-runtime"):
            builder.verify_packaged_tree(self.root / "extracted", self.root / "staged", self.public, "linux", "x86_64")
        executable.write_bytes(original)
        executable.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "packaged runtime mode changed: engines/stable/0.2.17/nelomai-runtime.*0755.*0644"):
            builder.verify_packaged_tree(self.root / "extracted", self.root / "staged", self.public, "linux", "x86_64")
        executable.chmod(0o755)
        (extracted / "runtime/unindexed").write_bytes(b"unexpected")
        with self.assertRaisesRegex(ValueError, "packaged"):
            builder.verify_packaged_tree(self.root / "extracted", self.root / "staged", self.public, "linux", "x86_64")
