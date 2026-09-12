"""Native fixture inspection for the synthetic latest side, not device acceptance."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

from scripts.tests.test_runtime_artifact import module, SOURCE
from scripts.tests.test_android_runtime_collisions import native_tools


class AndroidAcceptanceInputsTest(unittest.TestCase):
    def test_latest_inputs_use_compiled_identity_and_exact_staged_archive(self):
        ndk, javac = native_tools()
        builder = module("build-runtime-acceptance-container")
        self.assertTrue(callable(getattr(builder, "stage_android_latest", None)), "Android latest acceptance staging is missing")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "payload"
            payload.mkdir()
            java = root / "Engine.java"
            java.write_text("package ru.nelomai.latest; public class Engine {}")
            subprocess.run([str(javac), "-d", str(root), str(java)], check=True, capture_output=True)
            library = payload / "runtime/latest-classes.zip"
            library.parent.mkdir()
            with zipfile.ZipFile(library, "w") as archive:
                archive.write(root / "ru/nelomai/latest/Engine.class", "ru/nelomai/latest/Engine.class")
            for name in ("libnelomai_app_lib.so", "libwg-go.so"):
                source = root / (name + ".c")
                source.write_text("void Java_ru_nelomai_latest_" + name.replace(".", "_").replace("-", "_") + "(void) {}")
                destination = payload / "jni/arm64-v8a" / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                subprocess.run([str(ndk / "aarch64-linux-android24-clang"), "-shared", "-nostdlib",
                    "-Wl,-soname," + name, str(source), "-o", str(destination)], check=True, capture_output=True)
            webview = payload / "webview/index.html"
            webview.parent.mkdir()
            webview.write_text("compiled UI fixture")
            for name in module("android/build-runtime-artifact").REQUIRED_LICENSES:
                path = payload / "licenses" / name
                path.parent.mkdir(exist_ok=True)
                path.write_text("fixture attribution")
            files = []
            with zipfile.ZipFile(root / "collision-input.zip", "w") as archive:
                for path in sorted(payload.rglob("*")):
                    if path.is_file():
                        path.chmod(0o644)
                        name = path.relative_to(payload).as_posix()
                        value = path.read_bytes()
                        archive.write(path, name)
                        files.append(dict(path=name, size_bytes=len(value), sha256=hashlib.sha256(value).hexdigest(),
                            role="shared_library" if name.endswith(".so") else "license" if name.startswith("licenses/") else "resource"))
            manifest = dict(format_version=1, runtime_version="0.2.19", source_commit=SOURCE,
                platform="android", architecture="aarch64", contract_version=1, files=files)
            (root / "runtime-manifest-v1.json").write_text(json.dumps(manifest))
            result = builder.stage_android_latest(payload, root / "extracted", SOURCE, ndk / "llvm-readelf")
            self.assertEqual(result["runtime_version"], "0.2.20")
            self.assertEqual((root / "extracted/runtime/latest-classes.zip").read_bytes(), library.read_bytes())
            manifest["source_commit"] = "b" * 40
            (root / "runtime-manifest-v1.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "identity"):
                builder.stage_android_latest(payload, root / "rejected", SOURCE, ndk / "llvm-readelf")
            self.assertFalse((root / "rejected").exists())
