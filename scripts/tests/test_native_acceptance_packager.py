"""Opt-in actual host packager regression; never release/physical acceptance.

Uses retained locally built payloads only as test inputs. Other platforms in
the aggregate are structural fixtures; these runs cannot authorize publication.
"""
import base64
import os
import json
import shutil
import subprocess
import sys
import unittest
import zipfile
from unittest.mock import patch

from scripts.tests.test_runtime_artifact import ArtifactFixture, ROOT, SOURCE, module
from scripts.tests.test_android_runtime_collisions import native_tools
import scripts.tests.test_runtime_release_set as release_set_fixture


@unittest.skipUnless(os.environ.get("NELOMAI_RUN_NATIVE_PACKAGE_TEST") == "1", "explicit expensive native packager test")
class NativeAcceptancePackagerTest(ArtifactFixture):
    def final_signed(self, candidates, android_latest=None):
        drafts = self.root / "native-drafts"
        for platform, architecture in module("verify-runtime-artifact").TARGETS:
            folder = drafts / platform
            (folder / "stable").mkdir(parents=True)
            (folder / "latest").mkdir()
            shutil.copyfile(self.public, folder / "draft-public-key.raw")
            shutil.copyfile(self.public, folder / "runtime-public-key.raw")
            prefix = f"nelomai-runtime-0.2.16-{platform}-{architecture}"
            for suffix in (".zip", ".manifest.json", ".manifest.sig"):
                for slot in ("latest", "stable"):
                    shutil.copyfile(candidates / (prefix + suffix), folder / slot / (prefix + suffix))
            if platform == "android" and android_latest is not None:
                shutil.copyfile(android_latest / "collision-input.zip", folder / "latest" / (prefix + ".zip"))
                raw = (android_latest / "runtime-manifest-v1.json").read_bytes()
                (folder / "latest" / (prefix + ".manifest.json")).write_bytes(raw)
                (folder / "latest" / (prefix + ".manifest.sig")).write_bytes(self.key.sign(b"nelomai-runtime-manifest-v1\0" + raw))
        output = self.root / "final-signed"
        digest = module("sign-runtime-candidate").sign(drafts, output, SOURCE, self.keyfile, self.public)
        return output, digest

    def candidates(self, platform, architecture, payload, readelf=None):
        candidates = release_set_fixture.RuntimeReleaseSetTest.four_candidates(self)
        module("build-runtime-manifest").package(payload, self.root / "native", "0.2.16", SOURCE,
            platform, architecture, self.keyfile, readelf)
        for path in (self.root / "native").iterdir():
            shutil.copyfile(path, candidates / path.name)
        digest = module("build-runtime-release-set").build(candidates, self.root / "root", "0.2.16", SOURCE,
            self.keyfile, self.public)
        for path in (self.root / "root").iterdir():
            shutil.copyfile(path, candidates / path.name)
        return candidates, digest

    @unittest.skipUnless(sys.platform == "darwin", "macOS native bundler required")
    def test_actual_macos_app_retains_both_final_slot_payloads(self):
        payload = ROOT / "target/task9-desktop-smoke/payload-fix1"
        self.assertTrue(payload.is_dir(), "retained local test payload is unavailable")
        candidates, digest = self.candidates("macos", "aarch64", payload)
        signed, digest = self.final_signed(candidates)
        builder = module("build-runtime-acceptance-container")
        staged = self.root / "staged"
        builder.stage_signed(signed, digest, staged, self.public, "macos", "aarch64", SOURCE, "acceptance")
        with patch.dict(os.environ, {"NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64": base64.b64encode(self.public.read_bytes()).decode()}):
            package = builder.package_desktop(staged, self.root / "packaged", self.public, "macos", "aarch64")
        self.assertTrue(package.is_file())
        self.assertGreater(package.stat().st_size, 1024 * 1024)

    def test_actual_android_apk_links_exact_final_stable_aar_and_native_bytes(self):
        ndk, _ = native_tools()
        stable = ROOT / "target/task8-stable-c4521ec/payload"
        self.assertTrue(stable.is_dir(), "retained local native test payload is unavailable")
        candidates, digest = self.candidates("android", "aarch64", stable, ndk / "llvm-readelf")
        latest = self.root / "latest"
        shutil.copytree(ROOT / "target/task8-latest-c4521ec/payload", latest / "payload")
        original = json.loads((ROOT / "target/task8-latest-c4521ec/runtime-manifest-v1.json").read_bytes())
        # Explicit structural test identity; not a claimed new-source rebuild.
        (latest / "runtime-manifest-v1.json").write_text(json.dumps({**original, "source_commit": SOURCE},
            sort_keys=True, separators=(",", ":")))
        with zipfile.ZipFile(latest / "collision-input.zip", "w") as archive:
            for path in (latest / "payload").rglob("*"):
                if path.is_file():
                    info = zipfile.ZipInfo(path.relative_to(latest / "payload").as_posix())
                    info.external_attr = 0o100644 << 16
                    archive.writestr(info, path.read_bytes())
        builder = module("build-runtime-acceptance-container")
        staged = self.root / "staged"
        signed, digest = self.final_signed(candidates, latest)
        builder.stage_signed(signed, digest, staged, self.public, "android", "aarch64", SOURCE,
                             "acceptance", ndk / "llvm-readelf")
        environment = {**os.environ, "NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64": base64.b64encode(self.public.read_bytes()).decode(),
            "CC_aarch64_linux_android": str(ndk / "aarch64-linux-android24-clang"),
            "AR_aarch64_linux_android": str(ndk / "llvm-ar"),
            "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER": str(ndk / "aarch64-linux-android24-clang")}
        subprocess.run(["cargo", "rustc", "--locked", "--offline", "-p", "nelomai-android-container",
            "--target", "aarch64-linux-android", "--", "-C", "link-arg=-Wl,-soname,libnelomai_android_container.so"],
            cwd=ROOT, env=environment, check=True)
        with patch.dict(os.environ, environment):
            package = builder.package_android(staged, self.root / "packaged", self.public, ndk / "llvm-readelf",
                __import__('pathlib').Path(environment["ANDROID_HOME"]) / "cmdline-tools/latest/bin/apkanalyzer",
                ROOT / "target/aarch64-linux-android/debug/libnelomai_android_container.so")
        self.assertTrue(package.is_file())
        self.assertGreater(package.stat().st_size, 1024 * 1024)
