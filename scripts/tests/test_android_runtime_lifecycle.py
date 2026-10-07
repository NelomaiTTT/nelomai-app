"""Exercise guard generation and the real Gradle compiler/codegen task contract."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts/android" / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Small template fixtures exercise generated output, including unchanged native
# calls. The real locked templates are exercised by the Android lifecycle tests.
WRY = """package ru.nelomai.client
abstract class WryActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ProcessLifecycleOwner.get().lifecycle.addObserver(WryLifecycleObserver)
        Rust.onActivityCreate(this)
    }
    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        Rust.onWindowFocusChanged(this, hasFocus)
    }
    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        Rust.onActivitySaveInstanceState()
    }
    override fun onDestroy() {
        super.onDestroy()
        Rust.onActivityDestroy(this)
        Rust.onWebviewDestroy(this, "")
    }
    override fun onLowMemory() {
        super.onLowMemory()
        Rust.onActivityLowMemory()
    }
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        Rust.onNewIntent(intent)
    }
}
"""
TAURI = """package ru.nelomai.client
abstract class TauriActivity : WryActivity() {
  fun getPluginManager(): PluginManager { return PluginManager }
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    PluginManager.onActivityCreate(this)
  }
  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    PluginManager.onNewIntent(intent)
  }
  override fun onRestart() {
    super.onRestart()
    PluginManager.onRestart(this)
  }
  override fun onDestroy() {
    super.onDestroy()
    PluginManager.onDestroy(this)
  }
  override fun onConfigurationChanged(newConfig: Configuration) {
    super.onConfigurationChanged(newConfig)
    PluginManager.onConfigurationChanged(newConfig)
  }
}
"""


class RuntimeLifecycleGeneratorTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.direct = load("generate-build-inputs.py")
        self.stable = load("generate-stable-sources.py")
        names = ("tauri", "wry", "tauri-plugin-opener", "tauri-plugin-tunnel-android",
                 "tauri-plugin-push-android", "tauri-plugin-updater-android")
        self.packages = {name: self.root / "deps" / name for name in names}
        for name, directory in self.packages.items():
            android = directory / ("mobile/android" if name == "tauri" else "android")
            android.mkdir(parents=True)
            (android / "build.gradle.kts").touch()
        self.write("deps/tauri/mobile/proguard-tauri.pro", "-keep class $PACKAGE.TauriActivity\n")
        self.write("deps/tauri/mobile/android-codegen/TauriActivity.kt", TAURI)
        self.write("deps/wry/src/android/kotlin/WryActivity.kt", WRY)
        self.app = self.root / "src-tauri/gen/android/app"
        self.app.mkdir(parents=True)
        self.generated = self.app / "src/main/java/ru/nelomai/client/generated"
        for name in ("LatestRuntimeActivity", "RuntimeEntrypoint", "StartupDiagnostics"):
            self.write(f"src-tauri/gen/android/app/src/main/java/ru/nelomai/client/{name}.kt", "package ru.nelomai.client\n")
        self.write("src-tauri/gen/android/app/src/main/java/io/crates/keyring/Keyring.kt", "package io.crates.keyring\n")
        self.write("plugins/amneziawg-android-tunnel/build/generated/runtimeHostJava/org/amnezia/awg/GoBackend.java",
                   "package org.amnezia.awg;\nclass GoBackend {}\n")
        graph = {"packages": [{"name": name, "manifest_path": str(path / "Cargo.toml")}
                              for name, path in self.packages.items()]}
        real_run = subprocess.run

        def run(args, **kwargs):
            if args[:2] == ["cargo", "metadata"]:
                return subprocess.CompletedProcess(args, 0, json.dumps(graph))
            kwargs.setdefault("capture_output", True)
            return real_run(args, **kwargs)

        self.run = run

    def write(self, path, value):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value)

    def direct_generate(self):
        with patch.object(self.direct.subprocess, "run", side_effect=self.run):
            self.direct.generate(self.root)

    def stable_generate(self):
        with patch.object(self.stable, "packages", return_value=self.packages):
            self.stable.generate(self.root, self.root / "stable")

    def assert_guarded(self, directory):
        for name, original in (("WryActivity.kt", WRY), ("TauriActivity.kt", TAURI)):
            value = (directory / name).read_text()
            for line in original.splitlines():
                if "super." in line:
                    self.assertIn(line + "\n" + line[:len(line) - len(line.lstrip())]
                                  + "if (!runtimeLifecycleEnabled) return", value)
                if "Rust." in line or "PluginManager." in line or "getPluginManager" in line:
                    self.assertIn(line, value)
            self.assertEqual(value.count("if (!runtimeLifecycleEnabled) return"), 6 if name.startswith("Wry") else 5)

    def test_direct_release_inputs_keep_super_and_native_calls_and_are_idempotent(self):
        self.direct_generate()
        self.assert_guarded(self.generated)
        first = {file.name: file.read_bytes() for file in self.generated.iterdir()}
        self.direct_generate()
        self.assertEqual(first, {file.name: file.read_bytes() for file in self.generated.iterdir()})

    def test_stable_generator_guards_raw_cli_sources_without_modifying_them(self):
        self.generated.mkdir(parents=True)
        (self.generated / "WryActivity.kt").write_text(WRY)
        (self.generated / "TauriActivity.kt").write_text(TAURI)
        self.stable_generate()
        output = self.root / "stable/java/ru/nelomai/runtime/stable"
        self.assert_guarded(output)
        first = (output / "WryActivity.kt").read_bytes()
        self.stable_generate()
        self.assertEqual(first, (output / "WryActivity.kt").read_bytes())
        self.assertEqual(WRY, (self.generated / "WryActivity.kt").read_text())
        self.assertEqual(TAURI, (self.generated / "TauriActivity.kt").read_text())

    def test_both_generators_fail_closed_on_native_or_superclass_template_drift(self):
        for bad in (WRY.replace("Rust.onActivityCreate(this)", "Rust.onActivityCreate(this)\n        Rust.newCallback()"),
                    WRY.replace("super.onDestroy()", "super.onStop()"),
                    WRY.replace("        Rust.onActivityCreate(this)\n", "")
                       .replace("        super.onCreate(savedInstanceState)",
                                "        Rust.onActivityCreate(this)\n        super.onCreate(savedInstanceState)")):
            with self.subTest(template=bad):
                self.write("deps/wry/src/android/kotlin/WryActivity.kt", bad)
                with self.assertRaises(subprocess.CalledProcessError):
                    self.direct_generate()
                with self.assertRaises(ValueError):
                    self.stable_generate()


# SDK variables alone do not mean the ignored Tauri project inputs and locked
# Gradle dependencies have been prepared (e.g. the generic CI Python job).
# Generator behavior above is portable; opt in to this real-project integration
# check after generate-build-inputs.py and the normal Android dependency setup.
@unittest.skipUnless(os.environ.get("NELOMAI_RUN_GRADLE_WIRING_TESTS") == "1",
                     "prepared Android Gradle project required; set NELOMAI_RUN_GRADLE_WIRING_TESTS=1")
class RuntimeLifecycleGradleWiringTest(unittest.TestCase):
    def gradle(self, *args):
        result = subprocess.run(["./gradlew", "--offline", "--console=plain", *args],
                                cwd=ROOT / "src-tauri/gen/android", text=True, capture_output=True)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        return result.stdout

    def test_release_codegen_precedes_compiler_even_if_requested_after_it(self):
        output = self.gradle("--dry-run", ":app:compileArm64ReleaseKotlin", ":app:rustBuildArm64Release")
        self.assertLess(output.index(":app:rustBuildArm64Release SKIPPED"),
                        output.index(":app:compileArm64ReleaseKotlin SKIPPED"), output)

    def test_stable_source_copy_waits_for_requested_codegen(self):
        output = self.gradle("--dry-run", ":stable-runtime-android:prepareStableSources", ":app:rustBuildArm64Release")
        self.assertLess(output.index(":app:rustBuildArm64Release SKIPPED"),
                        output.index(":stable-runtime-android:prepareStableSources SKIPPED"), output)

    def test_staged_compiler_does_not_schedule_omitted_or_excluded_rust_build(self):
        for args in ((), (":app:rustBuildArm64Release", "-x", ":app:rustBuildArm64Release")):
            output = self.gradle("--dry-run", ":app:compileArm64ReleaseKotlin", *args)
            self.assertNotIn(":app:rustBuild", output)


if __name__ == "__main__":
    unittest.main()
