"""Stable Android source generation preserves shared runtime contracts."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


def load_generator():
    path = ROOT / "scripts/android/generate-stable-sources.py"
    spec = importlib.util.spec_from_file_location("generate_stable_sources", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StableSourceGenerationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.output = self.root / "output"
        app_java = self.root / "src-tauri/gen/android/app/src/main/java"
        for name in ("LatestRuntimeActivity.kt", "StartupDiagnostics.kt", "RuntimeEntrypoint.kt"):
            path = app_java / "ru/nelomai/client" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("package ru.nelomai.client\n")
        keyring = app_java / "io/crates/keyring/Keyring.kt"
        keyring.parent.mkdir(parents=True, exist_ok=True)
        keyring.write_text("package io.crates.keyring\n")

        service = self.root / "plugins/tunnel-android/android/src/main/java/NelomaiVpnService.kt"
        service.parent.mkdir(parents=True, exist_ok=True)
        service.write_text(
            "package ru.nelomai.tunnel\n"
            "import ru.nelomai.client.RuntimeDispatchGuard\n"
            "val icon = R.drawable.ic_vpn_notification\n"
            "val pending = RuntimeDispatchGuard.hasPending()\n"
        )
        for plugin in ("push-android", "updater-android"):
            (self.root / f"plugins/{plugin}/android/src/main/java").mkdir(parents=True)
            (self.root / f"plugins/{plugin}/android/src/main/res").mkdir(parents=True)

        go_backend = self.root / "plugins/amneziawg-android-tunnel/build/generated/runtimeHostJava/org/amnezia/awg/backend/GoBackend.java"
        go_backend.parent.mkdir(parents=True, exist_ok=True)
        go_backend.write_text("package org.amnezia.awg.backend; public class GoBackend {}\n")
        (app_java / "ru/nelomai/client/generated").mkdir(parents=True)

        drawable = self.root / "src-tauri/gen/android/app/src/main/res/drawable/ic_vpn_notification.xml"
        drawable.parent.mkdir(parents=True, exist_ok=True)
        drawable.write_text("<shape xmlns:android=\"http://schemas.android.com/apk/res/android\"/>\n")

        self.generator = load_generator()
        dependency_roots = {}
        for name in ("tauri", "tauri-plugin-opener"):
            dependency_roots[name] = self.root / "deps" / name
            relative = "mobile/android/src/main/java" if name == "tauri" else "android/src/main/java"
            (dependency_roots[name] / relative).mkdir(parents=True)
        self.generator.packages = lambda _root: dependency_roots
        self.generator.generate(self.root, self.output)
        self.generated = (
            self.output / "java/ru/nelomai/runtime/stable/tunnel/NelomaiVpnService.kt"
        ).read_text()

    def tearDown(self):
        self.temp.cleanup()

    def test_dispatch_guard_remains_shared_with_the_quick_tile_process(self):
        self.assertIn("import ru.nelomai.client.RuntimeDispatchGuard", self.generated)
        self.assertNotIn("import ru.nelomai.runtime.stable.RuntimeDispatchGuard", self.generated)

    def test_resource_import_is_not_hidden_by_a_longer_runtime_import(self):
        self.assertIn("import ru.nelomai.runtime.stable.R\n", self.generated)
        self.assertIn("R.drawable.stable_runtime_ic_vpn_notification", self.generated)


if __name__ == "__main__":
    unittest.main()
