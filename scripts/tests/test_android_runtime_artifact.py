import hashlib
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from scripts.tests.test_android_runtime_collisions import module


class ArtifactTest(unittest.TestCase):
    def setUp(self):
        self.builder = module('build-runtime-artifact')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.payload = self.root / 'payload'
        self.payload.mkdir()
        self.output = self.root / 'output'
        self.key = Ed25519PrivateKey.generate()
        self.key_path = self.root / 'test-key'
        self.key_path.write_bytes(self.key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))

    def test_missing_licenses_prevents_any_output(self):
        (self.payload / 'index.html').write_text('runtime UI')
        with self.assertRaisesRegex(ValueError, 'license'):
            self.builder.package(self.payload, self.output, '0.2.17', 'a' * 40, self.key_path)
        self.assertFalse(self.output.exists())

    def test_shared_validation_rejects_incomplete_payload_before_native_tools(self):
        self.assertTrue(callable(getattr(self.builder, 'validate_payload', None)),
                        'shared Android payload validator is missing')
        self.licenses()
        before = {path.relative_to(self.payload): path.read_bytes() for path in self.payload.rglob('*') if path.is_file()}
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            self.builder.validate_payload(self.payload, self.root / 'absent-readelf')
        self.assertEqual(before, {path.relative_to(self.payload): path.read_bytes() for path in self.payload.rglob('*') if path.is_file()})
        self.assertFalse(self.output.exists())

    def test_cli_rejects_incomplete_payload_before_native_tools_and_signing(self):
        self.licenses()
        result = subprocess.run([sys.executable, str(Path(self.builder.__file__)),
            '--payload', str(self.payload), '--output', str(self.output), '--version', '0.2.17',
            '--source-commit', 'a' * 40, '--signing-key', str(self.key_path),
            '--readelf', str(self.root / 'absent-readelf')], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('compiled runtime payload is incomplete', result.stderr)
        self.assertNotIn('FileNotFoundError', result.stderr)
        self.assertFalse(self.output.exists())

    def test_symlink_cannot_include_external_file(self):
        (self.payload / 'secret').symlink_to(self.key_path)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.builder.package(self.payload, self.output, '0.2.17', 'a' * 40, self.key_path)
        self.assertFalse(self.output.exists())

    def test_missing_runtime_is_rejected_even_with_licenses(self):
        self.licenses()
        with self.assertRaisesRegex(ValueError, 'runtime payload'):
            self.builder.package(self.payload, self.output, '0.2.17', 'a' * 40, self.key_path)
        self.assertFalse(self.output.exists())

    def licenses(self):
        for name in ('AMNEZIAWG-ANDROID-APACHE-2.0.txt', 'AMNEZIAWG-TOOLS-GPL-2.0.txt', 'ELF-CLEANER-GPL-2.0.txt', 'AMNEZIAWG-GO-MIT.txt', 'SOURCE-OFFER.txt', 'TAURI-APACHE-2.0.txt', 'TAURI-MIT.txt'):
            path = self.payload / 'licenses' / name
            path.parent.mkdir(exist_ok=True)
            path.write_text('Test fixture attribution; not a release license.')

    def test_signed_index_binds_every_byte_without_nested_apk(self):
        self.licenses()
        # Structural packaging test; binary admission is checked independently
        # by inspect_archive before release. No fixture is called a built engine.
        for name, content in {
            'runtime/runtime.aar': b'compiled AAR fixture',
            'webview/index.html': b'<html>fixture</html>',
            'jni/arm64-v8a/libnelomai_runtime_stable.so': b'ELF fixture',
            'jni/arm64-v8a/libstable_runtime_wg_go.so': b'tunnel ELF fixture',
        }.items():
            path = self.payload / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        self.builder.package(self.payload, self.output, '0.2.17', 'a' * 40, self.key_path)
        manifest_bytes = (self.output / 'runtime-manifest-v1.json').read_bytes()
        self.key.public_key().verify((self.output / 'runtime-manifest-v1.sig').read_bytes(), b'nelomai-runtime-manifest-v1\0' + manifest_bytes)
        manifest = json.loads(manifest_bytes)
        self.assertEqual(manifest['source_commit'], 'a' * 40)
        self.assertEqual(manifest['runtime_version'], '0.2.17')
        with zipfile.ZipFile(self.output / 'runtime.zip') as archive:
            self.assertEqual(set(archive.namelist()), {item['path'] for item in manifest['files']})
            for item in manifest['files']:
                value = archive.read(item['path'])
                self.assertEqual(len(value), item['size_bytes'])
                self.assertEqual(hashlib.sha256(value).hexdigest(), item['sha256'])


if __name__ == '__main__':
    unittest.main()
