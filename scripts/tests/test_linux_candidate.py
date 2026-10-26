"""Linux candidate crypto boundaries; structural ELF fixtures are never executed."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
import yaml

from scripts.tests.test_runtime_artifact import ArtifactFixture, ROOT, SOURCE, module
import scripts.tests.test_runtime_release_set as release_fixtures


class LinuxCandidateTest(ArtifactFixture):
    def setUp(self):
        super().setUp()
        self.assertTrue((ROOT / 'scripts/linux-candidate.py').is_file(), 'Linux candidate orchestration missing')
        self.candidate = module('linux-candidate')
        self.stable = release_fixtures.RuntimeReleaseSetTest.four_candidates(self)
        native = self.root / 'native-stable'
        module('build-runtime-manifest').package(self.payload, native, '0.2.20', SOURCE,
                                                'linux', 'x86_64', self.keyfile)
        for path in native.iterdir():
            shutil.copyfile(path, self.stable / path.name)
        digest = module('build-runtime-release-set').build(self.stable, self.root / 'stable-root',
            '0.2.20', SOURCE, self.keyfile, self.public)
        for path in self.stable.iterdir():
            if '-linux-x86_64.' not in path.name:
                path.unlink()
        for path in (self.root / 'stable-root').iterdir():
            shutil.copyfile(path, self.stable / path.name)
        self.source = 'b' * 40
        self.draft = self.root / 'draft'
        module('build-runtime-manifest').package(self.payload, self.draft / 'latest', '0.4.0', self.source,
                                                'linux', 'x86_64', self.keyfile)
        self.final_private, self.final_public = self.root / 'final-private', self.root / 'final-public'
        final = Ed25519PrivateKey.generate()
        self.final_private.write_bytes(final.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
        self.final_public.write_bytes(final.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        shutil.copyfile(self.public, self.draft / 'draft-public-key.raw')
        shutil.copyfile(self.final_public, self.draft / 'runtime-public-key.raw')
        self.signed = self.root / 'signed'
        self.addCleanup(patch.stopall)
        patch.object(self.candidate.gates, 'STABLE_SOURCE', SOURCE).start()
        patch.object(self.candidate.gates, 'STABLE_ROOT_SHA256', digest).start()

    def sign(self):
        self.candidate.sign(self.draft, self.stable, self.signed, self.source,
                            self.final_private, self.final_public, self.public)

    def test_linux_membership_stages_exact_latest_and_stable_without_other_platform_files(self):
        before = self.candidate.snapshot(self.stable)
        self.sign()
        staged = self.root / 'staged'
        self.candidate.stage(self.signed, staged, self.source, self.final_public, self.public)
        doc, inventory = self.candidate.verified(self.signed, self.source, self.final_public, self.public)
        self.assertEqual([(slot['slot'], slot['manifest']['runtime_version']) for slot in doc['slots']],
                         [('latest', '0.4.0'), ('stable', '0.2.20')])
        self.assertEqual(before, self.candidate.snapshot(self.stable))
        self.assertFalse(any('/release/' in path or any(p in path for p in ('windows', 'android', 'macos'))
                             for path in inventory))
        for slot, version in (('latest', '0.4.0'), ('stable', '0.2.20')):
            self.assertEqual((staged / 'runtime/engines' / slot / version / 'nelomai-runtime').read_bytes(),
                             (self.payload / 'nelomai-runtime').read_bytes())
        self.assertEqual((staged / 'dispatcher/1/nelomai-unix-service').read_bytes(),
                         (self.payload / 'nelomai-unix-service').read_bytes())
        self.assertNotIn(self.final_private.read_bytes(), [path.read_bytes() for path in self.signed.rglob('*') if path.is_file()])

    def test_sign_rejects_compile_pin_wrong_source_payload_and_unscoped_input(self):
        archive = self.draft / 'latest/nelomai-runtime-0.4.0-linux-x86_64.zip'
        raw = archive.read_bytes()
        archive.write_bytes(b'tampered payload')
        with self.assertRaises(Exception): self.sign()
        self.assertFalse(self.signed.exists())
        archive.write_bytes(raw)
        pin = self.draft / 'runtime-public-key.raw'
        pin.write_bytes(bytes(32))
        with self.assertRaisesRegex(ValueError, 'pin'): self.sign()
        self.assertFalse(self.signed.exists())
        shutil.copyfile(self.final_public, pin)
        with self.assertRaises(Exception):
            self.candidate.sign(self.draft, self.stable, self.signed, 'c' * 40,
                                self.final_private, self.final_public, self.public)
        (self.draft / 'other-platform.zip').write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError, 'inventory'): self.sign()
        self.assertFalse(self.signed.exists())

    def test_stable_root_and_each_linux_member_digest_are_required(self):
        for path in self.stable.iterdir():
            raw = path.read_bytes()
            with self.subTest(path=path.name):
                path.write_bytes(raw + b'tampered')
                with self.assertRaises(Exception): self.sign()
                self.assertFalse(self.signed.exists())
                path.write_bytes(raw)
        with patch.object(self.candidate.gates, 'STABLE_ROOT_SHA256', '0' * 64):
            with self.assertRaises(Exception): self.sign()
        self.assertFalse(self.signed.exists())

    def test_staging_rejects_extra_files_and_stable_public_key_substitution(self):
        self.sign()
        (self.signed / 'unexpected.key').write_bytes(b'not allowed')
        with self.assertRaisesRegex(ValueError, 'inventory'):
            self.candidate.stage(self.signed, self.root / 'rejected', self.source, self.final_public, self.public)
        (self.signed / 'unexpected.key').unlink()
        (self.signed / 'stable-public-key.raw').write_bytes(bytes(32))
        with self.assertRaises(ValueError):
            self.candidate.stage(self.signed, self.root / 'rejected', self.source, self.final_public, self.public)
        self.assertFalse((self.root / 'rejected').exists())

    def test_download_requests_only_pinned_root_and_three_linux_assets(self):
        expected = {path.name for path in self.stable.iterdir()}
        def download(*command, **kwargs):
            self.assertEqual(command[:5], ('gh', 'release', 'download', 'v0.2.20', '--repo'))
            names = {command[index + 1] for index, value in enumerate(command) if value == '--pattern'}
            self.assertEqual(names, expected)
            destination = Path(command[command.index('--dir') + 1])
            shutil.copytree(self.stable, destination)
        with patch.object(self.candidate.builder, 'run', side_effect=download):
            output = self.root / 'downloaded'
            self.candidate.download_stable(output, self.public)
        self.assertEqual(self.candidate.snapshot(output), self.candidate.snapshot(self.stable))

    def test_source_boundaries_use_real_clean_git_and_both_public_pins(self):
        root = self.root / 'checkout'
        (root / 'src-tauri').mkdir(parents=True)
        for name in ('package.json', 'src-tauri/tauri.conf.json'):
            (root / name).write_text('{"version":"0.4.0"}')
        (root / 'src-tauri/Cargo.toml').write_text('[package]\nversion="0.4.0"\n')
        for args in (('init', '-q'), ('add', '.'), ('-c', 'user.name=Fixture', '-c',
                     'user.email=fixture@invalid', 'commit', '-qm', 'fixture')):
            subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True)
        sha = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
        env = dict(GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_REPOSITORY='NelomaiTTT/nelomai-app',
            GITHUB_REF='refs/heads/Future/desktop-0.4.0', GITHUB_SHA=sha,
            NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64=base64.b64encode(self.final_public.read_bytes()).decode(),
            NELOMAI_UPDATER_PUBLIC_KEY=self.candidate.UPDATER_PUBLIC)
        with patch.object(self.candidate.gates, 'BASE', sha):
            self.candidate.source(sha, root=root, environment=env, keyless=True)
            self.candidate.source(sha, root=root, environment={**env, 'GITHUB_EVENT_NAME': 'push'}, keyless=True)
            for override in ({'GITHUB_REF': 'refs/heads/main'}, {'GITHUB_REF': 'refs/heads/Future/unrelated'},
                             {'GITHUB_SHA': 'c' * 40}, {'GITHUB_EVENT_NAME': 'pull_request'},
                             {'GITHUB_REPOSITORY': 'foreign/repo'}, {'NELOMAI_UPDATER_PUBLIC_KEY': 'wrong'},
                             {'NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64': ''},
                             {'ANDROID_KEYSTORE_BASE64': 'private Android keystore'},
                             {'APPLE_API_KEY': 'private Apple key'},
                             {'TAURI_SIGNING_PRIVATE_KEY': 'must remain outside native'}):
                with self.subTest(override=override), self.assertRaises(ValueError):
                    self.candidate.source(sha, root=root, environment={**env, **override}, keyless=True)
            (root / 'untracked').write_text('dirty')
            with self.assertRaises(ValueError): self.candidate.source(sha, root=root, environment=env)
            (root / 'untracked').unlink()
            (root / 'package.json').write_text('{"version":"0.3.0"}')
            with self.assertRaises(ValueError): self.candidate.source(sha, root=root, environment=env)

    def test_finalize_signs_unchanged_appimage_and_records_only_linux_candidate_inventory(self):
        self.sign()
        packages = self.root / 'packages'
        def native_bundle(staged, work, public, platform, architecture, *, environment):
            self.assertEqual((platform, architecture), ('linux', 'x86_64'))
            self.assertEqual(environment['NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64'],
                base64.b64encode(self.final_public.read_bytes()).decode())
            self.assertEqual(environment['NELOMAI_UPDATER_PUBLIC_KEY'], self.candidate.UPDATER_PUBLIC)
            work.mkdir(parents=True)
            result = work / 'fixture.AppImage'
            result.write_bytes(b'structural AppImage fixture, never executed')
            return result
        with patch.dict(os.environ, {'NELOMAI_UPDATER_PUBLIC_KEY': self.candidate.UPDATER_PUBLIC}), \
             patch.object(self.candidate.container, 'package_desktop', side_effect=native_bundle):
            self.candidate.package(self.signed, self.root / 'native-package', self.source, self.final_public, self.public)
        # Mirror the workflow's retained artifact: no native staging/build work.
        shutil.copytree(self.root / 'native-package/shipping', packages / 'shipping')
        shutil.copyfile(self.root / 'native-package/package-digests.json', packages / 'package-digests.json')
        appimage = packages / 'shipping/nelomai-0.4.0-linux-x86_64.AppImage'
        self.assertEqual(json.loads((packages / 'package-digests.json').read_bytes())['sha256'],
                         hashlib.sha256(appimage.read_bytes()).hexdigest())
        keydir = self.root / 'updater'
        keydir.mkdir()
        env = self.candidate.builder.updater_environment('build_only', keydir, os.environ)
        with patch.dict(os.environ, env), patch.object(self.candidate, 'UPDATER_PUBLIC', env['NELOMAI_UPDATER_PUBLIC_KEY']):
            output = self.root / 'final'
            self.candidate.finalize(packages, self.signed, output, self.source, self.final_public, self.public)
            self.assertEqual((output / appimage.name).read_bytes(), appimage.read_bytes())
            self.assertTrue((output / (appimage.name + '.sig')).is_file())
            inventory = json.loads((output / 'candidate-inventory.json').read_bytes())
            self.assertIs(inventory['publishable'], False)
            self.assertEqual(inventory['purpose'], 'linux-candidate')
            self.assertEqual(inventory['version'], '0.4.0')
            self.assertEqual(set(inventory['assets']), {p.relative_to(output).as_posix() for p in output.rglob('*')
                if p.is_file() and p.name != 'candidate-inventory.json'})
            appimage.write_bytes(b'tampered')
            with self.assertRaises(ValueError):
                self.candidate.finalize(packages, self.signed, self.root / 'rejected-final', self.source,
                                        self.final_public, self.public)
            self.assertFalse((self.root / 'rejected-final').exists())


class LinuxCandidateWorkflowTest(unittest.TestCase):
    def test_scoped_push_and_manual_linux_candidate_keep_keys_on_protected_hosted_jobs(self):
        path = ROOT / '.github/workflows/linux-candidate.yml'
        self.assertTrue(path.is_file(), 'separate Linux candidate workflow missing')
        workflow = yaml.safe_load(path.read_text())
        triggers = workflow.get('on', workflow.get(True))
        self.assertEqual(set(triggers), {'push', 'workflow_dispatch'})
        self.assertEqual(triggers['push'], {'branches': ['Future/desktop-0.4.0'],
            'paths': ['.github/workflows/linux-candidate.yml']})
        self.assertTrue(triggers['workflow_dispatch']['inputs']['source_sha']['required'])
        self.assertEqual(workflow['permissions'], {'contents': 'read', 'actions': 'read'})
        self.assertEqual(set(workflow['jobs']), {'build', 'sign', 'package', 'finalize'})
        for name, job in workflow['jobs'].items():
            with self.subTest(job=name):
                if name in ('build', 'package'):
                    self.assertEqual(job['runs-on'], ['self-hosted', 'Linux', 'X64', 'nelomai-040-linux-vm'])
                    self.assertNotIn('environment', job)
                    for secret in ('NELOMAI_RELEASE_MANIFEST_PRIVATE_KEY_B64', 'TAURI_SIGNING_PRIVATE_KEY'):
                        self.assertNotIn('secrets.' + secret, yaml.safe_dump(job))
                else:
                    self.assertEqual(job['runs-on'], 'ubuntu-22.04')
                    self.assertEqual(job['environment'], 'release-candidate-' + ('signing' if name == 'sign' else 'finalization'))
                expression = job['if'].replace('&&', ' and ').replace('||', ' or ').strip()
                allowed = dict(event_name='workflow_dispatch', repository='NelomaiTTT/nelomai-app',
                    ref='refs/heads/Future/desktop-0.4.0', sha=SOURCE)
                for override, expected in (({}, True), ({'event_name': 'push'}, False),
                                 ({'event_name': 'push', 'sha': 'b' * 40}, False),
                                 ({'event_name': 'pull_request'}, False), ({'repository': 'foreign/repo'}, False),
                                 ({'ref': 'refs/heads/main'}, False), ({'sha': 'b' * 40}, False),
                                 ({'ref': 'refs/heads/Future/unrelated'}, False)):
                    self.assertEqual(bool(eval(expression, {'__builtins__': {}}, {
                        'github': SimpleNamespace(**{**allowed, **override}),
                        'inputs': SimpleNamespace(source_sha=SOURCE)})), expected)
                steps = job['steps']
                checkout = next(step for step in steps if step.get('uses', '').startswith('actions/checkout@'))
                self.assertEqual(checkout['with']['ref'], '${{ env.SOURCE_SHA }}')
                self.assertIs(checkout['with']['persist-credentials'], False)
                guard = next(index for index, step in enumerate(steps) if step.get('id') == 'guard')
                local = next(index for index, step in enumerate(steps) if step.get('uses', '').startswith('./'))
                self.assertLess(guard, local)
                forbidden = next(line.strip()[len('for name in '):].removesuffix('; do')
                    for line in steps[guard]['run'].splitlines() if line.strip().startswith('for name in '))
                self.assertEqual(set(shlex.split(forbidden)), set(module('linux-candidate').PRIVATE_ENV))
                commands = '\n'.join(step.get('run', '') for step in steps)
                self.assertIn('linux-candidate.py source --source-sha "$SOURCE_SHA" --keyless', commands)
                self.assertNotIn('release create', commands)
                self.assertNotIn('git tag', commands)
                self.assertNotIn('build-runtime-release-set.py', commands)
                private = [index for index, step in enumerate(steps) if any('secrets.' in str(value)
                    and ('PRIVATE' in key or 'PASSWORD' in key) for key, value in step.get('env', {}).items())]
                if private:
                    tests = next(index for index, step in enumerate(steps) if 'unittest' in step.get('run', ''))
                    self.assertTrue(all(tests < index for index in private))


if __name__ == '__main__':
    unittest.main()
