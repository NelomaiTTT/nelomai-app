"""Single-platform diagnostic staging; fixtures are not executable acceptance."""
import json
import shutil
import subprocess
from scripts.tests.test_runtime_artifact import ArtifactFixture, SOURCE, PREFIX, SCRIPTS, module


class LinuxTestPackageTest(ArtifactFixture):
    def stage(self, source=SOURCE):
        self.assertTrue((SCRIPTS / 'package-linux-test.py').is_file(), 'Linux-only packaging is missing')
        return module('package-linux-test').stage(
            self.root / 'draft', self.root / 'staged', source, self.keyfile, self.public)

    def prepare(self):
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        shutil.copytree(self.root / 'candidate', self.root / 'draft/latest')
        for name in ('draft-public-key.raw', 'runtime-public-key.raw'):
            shutil.copyfile(self.public, self.root / 'draft' / name)

    def test_single_linux_draft_produces_verified_latest_only_tree(self):
        self.prepare()
        self.stage()
        staged = self.root / 'staged'
        manifest = json.loads((staged / 'runtime/container-manifest-v1.json').read_bytes())
        self.assertEqual([s['slot'] for s in manifest['slots']], ['latest'])
        self.assertEqual(manifest['slots'][0]['manifest']['source_commit'], SOURCE)
        self.assertNotIn('stable_release_set_sha256', manifest)
        self.key.public_key().verify((staged / 'runtime/container-manifest-v1.sig').read_bytes(),
            b'nelomai-container-manifest-v1\0' + (staged / 'runtime/container-manifest-v1.json').read_bytes())
        for name in ('nelomai-runtime', 'nelomai-unix-service', 'amneziawg-go'):
            self.assertEqual((staged / 'runtime/engines/latest/0.2.18' / name).read_bytes(),
                (self.payload / name).read_bytes())
        self.assertEqual((staged / 'dispatcher/1/nelomai-unix-service').read_bytes(),
            (self.payload / 'nelomai-unix-service').read_bytes())

    def test_foreign_source_is_rejected_before_staging(self):
        self.prepare()
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            self.stage('b' * 40)
        self.assertFalse((self.root / 'staged').exists())

    def test_mismatched_compile_pin_is_rejected(self):
        self.prepare()
        (self.root / 'draft/runtime-public-key.raw').write_bytes(b'x' * 32)
        with self.assertRaisesRegex(ValueError, 'pin'):
            self.stage()
        self.assertFalse((self.root / 'staged').exists())

    def test_tampered_runtime_is_rejected(self):
        self.prepare()
        (self.root / 'draft/latest' / (PREFIX + '.manifest.sig')).write_bytes(b'x' * 64)
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            self.stage()
        self.assertFalse((self.root / 'staged').exists())

    def test_existing_stage_is_not_overwritten(self):
        self.prepare()
        self.stage()
        with self.assertRaisesRegex(ValueError, 'exists'):
            self.stage()
