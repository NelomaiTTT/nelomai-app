"""Real collector/manifest contracts for the archive-to-DMG compatibility bridge."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.tests.test_runtime_artifact import ROOT, module


class DmgReleaseTransitionTest(unittest.TestCase):
    def test_bridge_retains_archive_and_later_release_has_only_dmg_installer(self):
        gates = module("release-candidate-gates")
        for version, archive in (("0.4.0", True), ("0.4.1", True), ("0.4.2", False), ("0.5.0", False), ("1.0.0", False)):
            with self.subTest(version=version):
                expected = {
                    ("linux", "x86_64", "appimage"): f"nelomai-{version}-linux-x86_64.AppImage",
                    ("windows", "x86_64", "nsis"): f"nelomai-{version}-windows-x86_64.exe",
                    ("macos", "aarch64", "dmg"): f"nelomai-{version}-macos-aarch64.dmg",
                }
                if archive:
                    expected[("macos", "aarch64", "app")] = f"nelomai-{version}-macos-aarch64.app.tar.gz"
                self.assertEqual(gates.updater_packages(version), expected)
                assets = gates.publication_assets(version)
                self.assertEqual(len(assets), 18 if archive else 17)
                self.assertEqual(f"nelomai-{version}-macos-aarch64.app.tar.gz" in assets, archive)
                self.assertIn(f"nelomai-{version}-macos-aarch64.dmg.sig", assets)
                # Runtime archives are consumed as future stable inputs.
                for platform, architecture in (("macos", "aarch64"), ("windows", "x86_64"), ("linux", "x86_64")):
                    self.assertIn(f"nelomai-runtime-{version}-{platform}-{architecture}.zip", assets)
        for version in ("0.4.2-beta.1", "v0.4.2", "0.4", "0.04.2", "unknown"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                gates.updater_packages(version)

    def test_collector_preserves_both_mac_formats_without_metadata_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            search, output = root / "source", root / "collector"
            search.mkdir()
            for kind, suffix in (("app", ".app.tar.gz"), ("dmg", ".dmg")):
                source = search / ("signed-input" + suffix)
                source.write_bytes(kind.encode())
                source.with_name(source.name + ".sig").write_text(kind + "-signature")
                result = subprocess.run([sys.executable, str(ROOT / "scripts/collect-release-artifact.py"),
                    "--search-root", str(search), "--output-dir", str(output), "--version", "0.4.1",
                    "--platform", "macos", "--architecture", "aarch64", "--package-kind", kind], capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            entries = [json.loads(p.read_bytes()) for p in output.glob("*.artifact.json")]
            self.assertEqual({item["package_kind"] for item in entries}, {"app", "dmg"})
            self.assertEqual(len(entries), 2)
            for item in entries:
                self.assertEqual((output / item["asset_name"]).read_bytes(), item["package_kind"].encode())
                self.assertEqual(item["signature"], item["package_kind"] + "-signature")
            result = subprocess.run([sys.executable, str(ROOT / "scripts/collect-release-artifact.py"),
                "--search-root", str(search), "--output-dir", str(root / "invalid"), "--version", "0.4.1",
                "--platform", "windows", "--architecture", "x86_64", "--package-kind", "dmg"], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "invalid").exists())

    def test_inventory_cannot_drop_bridge_or_add_archive_after_bridge(self):
        gates = module("release-candidate-gates")
        for version in ("0.4.1", "0.4.2"):
            with self.subTest(version=version), patch.multiple(gates, VERSION=version,
                    MACOS_DMG_NAME=f"nelomai-{version}-macos-aarch64.dmg",
                    PUBLISH_ASSETS=gates.publication_assets(version)):
                assets = {name: "d" * 64 for name in gates.PUBLISH_ASSETS}
                identities = {name: i for i, name in enumerate(gates.CANDIDATE_ENVIRONMENTS, 1)}
                inventory = dict(trust="release", mode="sign_candidate", source_sha="a" * 40,
                    run_id="42", run_attempt=1, environment_ids=identities, assets=assets)
                gates.require_publishable_inventory(inventory, "42", "a" * 40, identities)
                for name in gates.updater_packages(version).values():
                    with self.subTest(missing=name), self.assertRaises(ValueError):
                        gates.require_publishable_inventory({**inventory, "assets": {
                            key: value for key, value in assets.items() if key != name}}, "42", "a" * 40, identities)
                if version == "0.4.2":
                    with self.assertRaises(ValueError):
                        gates.require_publishable_inventory({**inventory, "assets": {
                            **assets, f"nelomai-{version}-macos-aarch64.app.tar.gz": "e" * 64}}, "42", "a" * 40, identities)
