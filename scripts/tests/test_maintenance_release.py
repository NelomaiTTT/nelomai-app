"""Maintenance release identity and TLS floor, without building an application."""
import json
from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
VERSION = json.loads((ROOT / "package.json").read_text())["version"]


class MaintenanceReleaseTest(unittest.TestCase):
    def test_application_and_lock_versions_match_canonical(self):
        for relative in ('package.json', 'src-tauri/tauri.conf.json', 'package-lock.json'):
            with self.subTest(path=relative):
                self.assertEqual(json.loads((ROOT / relative).read_text())['version'], VERSION)
        self.assertEqual(json.loads((ROOT / 'package-lock.json').read_text())['packages']['']['version'], VERSION)
        lock = tomllib.loads((ROOT / 'Cargo.lock').read_text())['package']
        for relative in ('src-tauri/Cargo.toml', 'crates/android-container/Cargo.toml',
                         'crates/unix-service/Cargo.toml', 'crates/windows-service/Cargo.toml'):
            with self.subTest(path=relative):
                package = tomllib.loads((ROOT / relative).read_text())['package']
                self.assertEqual(package['version'], VERSION)
                self.assertEqual([p['version'] for p in lock if p['name'] == package['name']], [VERSION])

    def test_tls_lock_uses_reviewed_security_updates(self):
        lock = tomllib.loads((ROOT / 'Cargo.lock').read_text())['package']
        for name, version in (('rustls-webpki', '0.103.16'),
                              ('webpki-roots', '1.0.10'), ('webpki-root-certs', '1.0.10')):
            with self.subTest(package=name):
                self.assertEqual([p['version'] for p in lock if p['name'] == name], [version])

    def test_one_version_command_updates_metadata_and_release_consumers(self):
        import importlib.util
        import shutil
        import subprocess
        import sys
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / 'scripts', root / 'scripts', ignore=shutil.ignore_patterns('__pycache__'))
            verifier = root / 'target/debug/verify-runtime-manifest'
            verifier.parent.mkdir(parents=True)
            shutil.copyfile(ROOT / 'target/debug/verify-runtime-manifest', verifier)
            verifier.chmod(0o755)
            files = ['package.json', 'package-lock.json', 'Cargo.lock',
                     'src-tauri/tauri.conf.json', 'src-tauri/Cargo.toml',
                     'crates/android-container/Cargo.toml', 'crates/unix-service/Cargo.toml',
                     'crates/windows-service/Cargo.toml']
            for name in files:
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)
            subprocess.run([sys.executable, str(root / 'scripts/set-release-version.py'), '0.2.99'], check=True)
            checked = subprocess.run([sys.executable, str(root / 'scripts/set-release-version.py'), '--check'],
                                     capture_output=True, text=True)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertEqual(checked.stdout.strip(), '0.2.99')
            spec = importlib.util.spec_from_file_location('changed_release', root / 'scripts/release-candidate-gates.py')
            gates = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(gates)
            self.assertEqual(gates.VERSION, '0.2.99')
            self.assertEqual(gates.SYNTHETIC_LATEST, '0.2.100')
            self.assertTrue(all('0.2.99' in name for name in gates.PACKAGE_NAMES.values()))
            self.assertIn('nelomai-runtime-0.2.99-release-set.manifest.json', gates.PUBLISH_ASSETS)
            # Run real release tests under the changed identity, not only import constants.
            # Explicit selection excludes native builds and this enclosing test.
            tested = subprocess.run([
                sys.executable, '-m', 'unittest',
                'scripts.tests.test_runtime_candidate_signing',
                'scripts.tests.test_runtime_release_set',
                'scripts.tests.test_android_apk_manifest',
                'scripts.tests.test_retained_candidate',
                'scripts.tests.test_desktop_runtime_staging',
                'scripts.tests.test_maintenance_release.MaintenanceReleaseTest.test_application_and_lock_versions_match_canonical',
            ], cwd=root, capture_output=True, text=True)
            self.assertEqual(tested.returncode, 0, tested.stdout + tested.stderr)
            # A missed derived version must fail before a build rather than silently drift.
            config = root / 'src-tauri/tauri.conf.json'
            value = json.loads(config.read_text())
            value['version'] = '0.2.98'
            config.write_text(json.dumps(value))
            self.assertNotEqual(subprocess.run(
                [sys.executable, str(root / 'scripts/set-release-version.py'), '--check'],
                capture_output=True).returncode, 0)
