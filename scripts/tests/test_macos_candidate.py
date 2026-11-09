"""macOS candidate trust boundaries; no native compilation, signing or installation."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
import yaml

from scripts.tests.test_runtime_artifact import ROOT, module


class MacosCandidateTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue((ROOT / 'scripts/macos-candidate.py').is_file(), 'macOS candidate orchestration missing')
        self.c = module('macos-candidate')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sha = 'b' * 40
        self.old_sha = 'a' * 40
        self.key = Ed25519PrivateKey.generate()
        self.old_key = Ed25519PrivateKey.generate()
        self.private = self.root / 'private'
        self.private.write_bytes(self.key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
        self.public = self.root / 'public'
        self.public.write_bytes(self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        self.old_public = self.root / 'old-public'
        self.old_public.write_bytes(self.old_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        self.draft = self.root / 'draft'
        self.stable = self.root / 'stable'
        self.signed = self.root / 'signed'
        self.runtime(self.draft / 'latest', '0.4.2', self.sha, self.old_key)
        shutil.copyfile(self.old_public, self.draft / 'draft-public-key.raw')
        shutil.copyfile(self.public, self.draft / 'runtime-public-key.raw')
        self.runtime(self.stable, '0.2.20', self.old_sha, self.old_key)
        prefix = 'nelomai-runtime-0.2.20-macos-aarch64'
        entry = dict(platform='macos', architecture='aarch64')
        for kind, suffix in zip(('archive', 'manifest', 'signature'), ('.zip', '.manifest.json', '.manifest.sig')):
            entry[kind + '_name'] = prefix + suffix
            entry[kind + '_sha256'] = self.digest(self.stable / (prefix + suffix))
        raw = self.c.canonical(dict(runtime_version='0.2.20', source_commit=self.old_sha, artifacts=[entry]))
        name = self.stable / 'nelomai-runtime-0.2.20-release-set.manifest'
        name.with_suffix('.manifest.json').write_bytes(raw)
        name.with_suffix('.manifest.sig').write_bytes(self.old_key.sign(b'nelomai-runtime-release-set-v1\0' + raw))
        self.root_digest = hashlib.sha256(raw).hexdigest()
        self.addCleanup(patch.stopall)
        patch.object(self.c.gates, 'STABLE_VERSION', '0.2.20').start()
        patch.object(self.c.gates, 'STABLE_SOURCE', self.old_sha).start()
        patch.object(self.c.gates, 'STABLE_ROOT_SHA256', self.root_digest).start()
        # Only the external Rust contract process is replaced. Real Ed25519,
        # archive extraction/digests, source/slot checks and inventory remain.
        patch.object(self.c.verifier, 'authenticated', side_effect=self.authenticate).start()

    @staticmethod
    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def authenticate(self, kind, manifest, signature, public, target, architecture='-'):
        domain = {'artifact': b'nelomai-runtime-manifest-v1\0', 'container': b'nelomai-container-manifest-v1\0',
                  'release-set': b'nelomai-runtime-release-set-v1\0'}[kind]
        Ed25519PublicKey.from_public_bytes(public.read_bytes()).verify(signature.read_bytes(), domain + manifest.read_bytes())
        if kind == 'release-set' and self.digest(manifest) != target:
            raise ValueError('pinned root digest mismatch')
        doc = json.loads(manifest.read_bytes())
        if kind == 'artifact' and (doc['platform'], doc['architecture']) != (target, architecture):
            raise ValueError('platform identity mismatch')
        return doc

    def runtime(self, folder, version, source, key):
        folder.mkdir(parents=True)
        prefix = f'nelomai-runtime-{version}-macos-aarch64'
        files = []
        with zipfile.ZipFile(folder / (prefix + '.zip'), 'w') as archive:
            for name, value, role, mode in (
                ('fixture', b'authenticated fixture; never executed', 'resource', 0o100644),
                ('nelomai-unix-service', b'structural service fixture; never executed', 'executable', 0o100755)):
                info = zipfile.ZipInfo(name)
                info.external_attr = mode << 16
                archive.writestr(info, value)
                files.append(dict(path=name, role=role, size_bytes=len(value), sha256=hashlib.sha256(value).hexdigest()))
        raw = self.c.canonical(dict(format_version=1, runtime_version=version, source_commit=source,
            platform='macos', architecture='aarch64', contract_version=1, files=files))
        (folder / (prefix + '.manifest.json')).write_bytes(raw)
        (folder / (prefix + '.manifest.sig')).write_bytes(key.sign(b'nelomai-runtime-manifest-v1\0' + raw))

    def sign(self):
        self.c.sign(self.draft, self.stable, self.signed, self.sha, self.private, self.public, self.old_public)

    def test_signs_only_current_macos_latest_and_pinned_confirmed_stable(self):
        before = self.c.snapshot(self.draft), self.c.snapshot(self.stable)
        self.sign()
        doc, files = self.c.verified(self.signed, self.sha, self.public, self.old_public)
        self.assertEqual([(s['slot'], s['manifest']['runtime_version']) for s in doc['slots']],
                         [('latest', '0.4.2'), ('stable', '0.2.20')])
        self.assertEqual(doc['release_set_id'], 'macos-candidate-' + self.sha)
        self.assertEqual(before, (self.c.snapshot(self.draft), self.c.snapshot(self.stable)))
        self.assertFalse(any('/release/' in n or any(p in n for p in ('linux', 'windows', 'android')) for n in files))
        self.assertNotIn(self.private.read_bytes(), [p.read_bytes() for p in self.signed.rglob('*') if p.is_file()])
        with self.assertRaises(ValueError): self.sign()

    def test_native_staging_preserves_both_authenticated_slots_and_current_dispatcher(self):
        self.sign()
        staged = self.root / 'staged'
        inspected = []
        def native_inspect(payload, manifest):
            inspected.append((manifest['runtime_version'], (payload / 'nelomai-unix-service').read_bytes()))
        with patch.object(self.c.verifier, 'inspect', side_effect=native_inspect):
            self.c.stage(self.signed, staged, self.sha, self.public, self.old_public)
        service = b'structural service fixture; never executed'
        self.assertEqual(inspected, [('0.4.2', service), ('0.2.20', service)])
        self.assertEqual((staged / 'dispatcher/1/nelomai-unix-service').read_bytes(), service)
        for slot, version in (('latest', '0.4.2'), ('stable', '0.2.20')):
            path = staged / 'runtime/engines' / slot / version / 'nelomai-unix-service'
            self.assertEqual(path.read_bytes(), service)
            self.assertEqual(path.stat().st_mode & 0o777, 0o755)
        self.assertEqual((staged / 'runtime/container-manifest-v1.json').read_bytes(),
                         (self.signed / 'containers/macos/shipping/container-manifest-v1.json').read_bytes())

    def test_rejects_wrong_source_compile_pin_extra_input_and_tampered_stable_members(self):
        for path in list(self.stable.iterdir()) + [self.draft / 'runtime-public-key.raw']:
            raw = path.read_bytes()
            path.write_bytes(raw + b'tampered')
            with self.subTest(path=path.name), self.assertRaises(Exception): self.sign()
            self.assertFalse(self.signed.exists())
            path.write_bytes(raw)
        with self.assertRaises(Exception):
            self.c.sign(self.draft, self.stable, self.signed, 'c' * 40, self.private, self.public, self.old_public)
        (self.draft / 'another-platform.zip').write_bytes(b'unscoped')
        with self.assertRaisesRegex(ValueError, 'inventory'): self.sign()
        self.assertFalse(self.signed.exists())

    def test_finalization_requires_common_identity_exact_index_and_unchanged_archive(self):
        self.sign()
        packages = self.root / 'packages'
        (packages / 'shipping').mkdir(parents=True)
        archive = packages / 'shipping' / self.c.PACKAGE
        archive.write_bytes(b'synthetic archive never installed')
        index = self.c.package_index(archive, self.signed, self.sha)
        image = packages / 'shipping' / self.c.DMG
        image.write_bytes(b'manual image fixture')
        index['packages']['dmg'] = dict(name=image.name, sha256=self.digest(image), size_bytes=image.stat().st_size)
        target = packages / 'package-digests.json'
        target.write_bytes(self.c.canonical(index))
        env = {'NELOMAI_UPDATER_PUBLIC_KEY': self.c.UPDATER_PUBLIC, 'NELOMAI_MACOS_SIGNER_SHA1': '12' * 20}
        output = self.root / 'final'
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(ValueError, 'common'): self.c.finalize(packages, self.signed, output, self.sha, self.public, self.old_public)
            index['macos_common_signature'] = self.c.common.signature_metadata('12' * 20)
            target.write_bytes(self.c.canonical(index))
            archive.write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError, 'package'): self.c.finalize(packages, self.signed, output, self.sha, self.public, self.old_public)
        self.assertFalse(output.exists())

    def test_finalizer_emits_nonpublishable_inventory_after_external_updater_verification(self):
        self.sign()
        packages = self.root / 'packages'
        (packages / 'shipping').mkdir(parents=True)
        archive = packages / 'shipping' / self.c.PACKAGE
        archive.write_bytes(b'outer common already signed by native protected phase')
        index = {**self.c.package_index(archive, self.signed, self.sha),
                 'macos_common_signature': self.c.common.signature_metadata('12' * 20)}
        image = packages / 'shipping' / self.c.DMG
        image.write_bytes(b'manual image fixture')
        index['packages']['dmg'] = dict(name=image.name, sha256=self.digest(image), size_bytes=image.stat().st_size)
        (packages / 'package-digests.json').write_bytes(self.c.canonical(index))
        before = self.c.snapshot(packages)
        output = self.root / 'final'
        env = dict(NELOMAI_UPDATER_PUBLIC_KEY=self.c.UPDATER_PUBLIC, NELOMAI_MACOS_SIGNER_SHA1='12' * 20,
                   TAURI_SIGNING_PRIVATE_KEY='external-signer-fixture', GITHUB_RUN_ID='42', GITHUB_RUN_ATTEMPT='1')
        calls = []
        def external(*command, **kwargs):
            calls.append(command)
            if command[1:3] == ('signer', 'sign'):
                Path(str(command[3]) + '.sig').write_bytes(b'updater-signature-fixture')
            else:
                self.assertEqual(Path(command[2]).read_bytes(), b'updater-signature-fixture')
                self.assertEqual(Path(command[3]).read_text(), self.c.UPDATER_PUBLIC)
        with patch.dict(os.environ, env, clear=True), patch.object(self.c.builder, 'run', side_effect=external):
            self.c.finalize(packages, self.signed, output, self.sha, self.public, self.old_public)
        inventory = json.loads((output / 'candidate-inventory.json').read_bytes())
        self.assertIs(inventory['publishable'], False)
        self.assertEqual(inventory['full_acceptance'], 'UNRUN')
        self.assertEqual(inventory['source_sha'], self.sha)
        self.assertEqual(inventory['macos_common_signature']['certificate_sha1'], '12' * 20)
        self.assertEqual(inventory['assets'][self.c.PACKAGE], self.digest(archive))
        self.assertIn(self.c.PACKAGE + '.sig', inventory['assets'])
        self.assertEqual(inventory['assets'][self.c.DMG], self.digest(image))
        self.assertIn(self.c.DMG + '.sig', inventory['assets'])
        self.assertFalse(any('0.4.2-release-set' in n or 'release-manifest' in n for n in inventory['assets']))
        self.assertEqual(before, self.c.snapshot(packages))
        self.assertEqual(len(calls), 4)

    def test_source_rejects_foreign_event_branch_sha_and_private_credentials_before_git(self):
        env = dict(GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_REPOSITORY='NelomaiTTT/nelomai-app',
            GITHUB_REF='refs/heads/Future/desktop-0.4.0', GITHUB_SHA=self.sha,
            NELOMAI_UPDATER_PUBLIC_KEY=self.c.UPDATER_PUBLIC,
            NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64=base64.b64encode(self.public.read_bytes()).decode())
        for change in ({'GITHUB_EVENT_NAME': 'pull_request'}, {'GITHUB_REF': 'refs/heads/main'},
                       {'GITHUB_SHA': 'c' * 40}, {'NELOMAI_UPDATER_PUBLIC_KEY': 'wrong'},
                       {'NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64': ''}):
            with self.subTest(change=change), self.assertRaises(ValueError): self.c.source(self.sha, environment={**env, **change}, keyless=True)
        for name in self.c.PRIVATE_ENV:
            with self.subTest(secret=name), self.assertRaises(ValueError): self.c.source(self.sha, environment={**env, name: 'secret'}, keyless=True)


class MacosCandidateWorkflowTest(unittest.TestCase):
    def test_rollback_runner_reads_literal_default_keychain_path(self):
        runner = module('test-macos-rollback')
        path = r'/tmp/Original "Keychain"\\store.keychain-db'
        result = subprocess.CompletedProcess([], 0, os.fsencode(f'    "{path}"\n'), b'')
        with patch.object(runner.subprocess, 'run', return_value=result):
            self.assertEqual(runner.default_keychain(), [path])

    def test_rollback_runner_rejects_partial_keychain_list(self):
        runner = module('test-macos-rollback')
        partial = subprocess.CompletedProcess([], 0, b' "/tmp/existing.keychain-db"\n',
            b'security: SecKeychainGetPath failed\n')
        with (
            patch.object(runner.subprocess, 'run', return_value=partial),
            patch.object(runner.sys.stderr, 'write'),
            self.assertRaisesRegex(RuntimeError, 'reported incomplete results'),
        ):
            runner.security('list-keychains', '-d', 'user', require_quiet=True)

    def test_rollback_runner_checks_default_is_restorable_before_creation(self):
        runner = module('test-macos-rollback')
        old = '/tmp/missing.keychain-db'
        calls = []

        def security(operation, *args, **kwargs):
            calls.append((operation, *args))
            if (operation, args) == ('list-keychains', ('-d', 'user')):
                return f'    "{old}"\n'
            self.assertEqual((operation, args), ('default-keychain', ('-d', 'user', '-s', old)))
            self.assertTrue(kwargs.get('require_quiet'))
            raise RuntimeError('default is not restorable')

        with (
            patch.dict(os.environ, {
                'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                'RUNNER_TEMP': tempfile.gettempdir(),
            }),
            patch.object(runner.sys, 'platform', 'darwin'),
            patch.object(runner, 'default_keychain', return_value=[old]),
            patch.object(runner, 'security', side_effect=security),
            patch.object(runner.subprocess, 'check_output',
                         return_value=''.join(f'{name}: test\n' for name in runner.TESTS)),
        ):
            with self.assertRaisesRegex(RuntimeError, 'default is not restorable'):
                runner.main()
        self.assertEqual(calls, [
            ('list-keychains', '-d', 'user'),
            ('default-keychain', '-d', 'user', '-s', old),
        ])

    def test_rollback_runner_restores_keychain_settings_after_test_failure(self):
        runner = module('test-macos-rollback')
        search = r'/Users/runner/Library/Keychains/Original "Keychain"\\store.keychain-db'
        listed = os.fsencode(f'    "{search}"\n')
        expected = [
            'common_host_preserves_runtime_record_across_version_rollback',
            'common_host_preserves_legacy_install_identity_after_completed_migration',
        ]
        for default in ([search], []):
            calls = []

            def run(command, **kwargs):
                if command[0] == 'cargo':
                    self.assertEqual(command[-3:], ['--exact', *expected])
                    self.assertIn('--include-ignored', command[command.index('--') + 1:])
                    self.assertEqual(kwargs['env']['NELOMAI_TEST_ROLLBACK_KEYCHAIN'],
                                     str(calls[-1][-1]))
                    raise subprocess.CalledProcessError(101, command)
                operation, *args = command[1:]
                calls.append((operation, *args))
                if (operation, args) == ('default-keychain', ['-d', 'user']):
                    if default:
                        return subprocess.CompletedProcess(command, 0, listed, b'')
                    return subprocess.CompletedProcess(command, 1, b'',
                        b'security: SecKeychainCopyDomainDefault user: A default keychain could not be found.\n')
                if operation == 'error':
                    self.assertEqual(args, ['-25307'])
                    return subprocess.CompletedProcess(command, 1,
                        b'Error: 0xFFFF9D25 -25307 A default keychain could not be found.\n', b'')
                if (operation, args) == ('list-keychains', ['-d', 'user']):
                    return subprocess.CompletedProcess(command, 0, listed, b'')
                if operation == 'create-keychain':
                    args[-1].touch()
                return subprocess.CompletedProcess(command, 0, b'', b'')

            with (
                self.subTest(default=default),
                tempfile.TemporaryDirectory() as temp,
                patch.dict(os.environ, {
                    'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_TEMP': temp,
                }),
                patch.object(runner.sys, 'platform', 'darwin'),
                patch.object(runner.subprocess, 'check_output',
                             return_value=''.join(f'{name}: test\n' for name in expected)),
                patch.object(runner.subprocess, 'run', side_effect=run),
                patch.object(runner, 'security', wraps=runner.security) as security,
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    runner.main()
                keychain = next(args[-1] for operation, *args in calls if operation == 'create-keychain')
                self.assertEqual(keychain.parent.parent, Path(temp).resolve())
                cleanup = [
                    ('default-keychain', '-d', 'user', '-s', *default),
                ] if default else []
                if default:
                    self.assertEqual(calls[2], cleanup[0])
                self.assertEqual(calls[-(3 + len(cleanup)):], [
                    ('default-keychain', '-d', 'user', '-s', keychain),
                    *cleanup,
                    ('delete-keychain', keychain),
                    ('list-keychains', '-d', 'user', '-s', search),
                ])
                security.assert_called_with('list-keychains', '-d', 'user', '-s', search,
                                            require_quiet=True)

    def test_rollback_runner_rejects_an_unreadable_default_keychain(self):
        runner = module('test-macos-rollback')
        denied = subprocess.CompletedProcess([], 1, b'',
            b'security: SecKeychainCopyDomainDefault user: User interaction is not allowed.\n')
        missing = subprocess.CompletedProcess([], 1,
            b'Error: 0xFFFF9D25 -25307 A default keychain could not be found.\n', b'')
        with patch.object(runner.subprocess, 'run', side_effect=[denied, missing]):
            with self.assertRaisesRegex(RuntimeError, "cannot identify"):
                runner.default_keychain()

    def test_rollback_regressions_run_on_native_macos_jobs(self):
        for workflow_file, job_name in (('checks.yml', 'macos-development'),
                                        ('macos-candidate.yml', 'build'),
                                        ('release.yml', 'native_drafts')):
            with self.subTest(workflow=workflow_file):
                workflow = yaml.safe_load((ROOT / '.github/workflows' / workflow_file).read_text())
                job = workflow['jobs'][job_name]
                step = next((step for step in job['steps']
                             if step.get('run') == 'python3 scripts/test-macos-rollback.py'), None)
                self.assertIsNotNone(step)
                self.assertFalse(step.get('continue-on-error', False))
                if workflow_file == 'release.yml':
                    self.assertEqual(step['if'], "matrix.platform == 'macos'")
                    matrix = job['strategy']['matrix']['include']
                    self.assertEqual([item['runner'] for item in matrix if item['platform'] == 'macos'],
                                     ['macos-15'])
                    continue
                self.assertEqual(job['runs-on'], 'macos-15')
                if workflow_file == 'checks.yml':
                    self.assertEqual(step['if'],
                        "${{ !cancelled() && steps.guard.outcome == 'success' && steps.rust.outcome == 'success' }}")
                else:
                    self.assertNotIn('if', step)
                    self.assertGreater(job['steps'].index(step), next(
                        i for i, candidate in enumerate(job['steps'])
                        if 'scripts/macos-candidate.py source --source-sha' in candidate.get('run', '')))

    def test_development_compilation_uses_hosted_apple_silicon(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/checks.yml').read_text())
        self.assertEqual(workflow['jobs']['macos-development']['runs-on'],
                         'macos-15')

    def test_shell_guard_rejects_foreign_context_moved_head_dirty_tree_and_keys(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/macos-candidate.yml').read_text())
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / 'repo'
            repo.mkdir()
            def git(*args):
                return subprocess.check_output(['git', '-C', str(repo), *args], text=True, stderr=subprocess.DEVNULL).strip()
            git('init', '-b', 'Future/desktop-0.4.0')
            git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--allow-empty', '-m', 'source')
            sha = git('rev-parse', 'HEAD')
            remote = 'refs/remotes/origin/Future/desktop-0.4.0'
            git('update-ref', remote, sha)
            envfile = root / 'env'
            tools = root / 'bin'
            tools.mkdir()
            # Native platform checks see the intended VM shape in this shell
            # fixture; no real native/runtime/security command is invoked.
            for name, body in {'uname': 'if [ "$1" = -s ]; then echo Darwin; else echo arm64; fi',
                               'id': 'echo 501'}.items():
                tool = tools / name
                tool.write_text('#!/bin/sh\n' + body + '\n')
                tool.chmod(0o755)
            env = dict(PATH=str(tools) + os.pathsep + os.environ['PATH'], GITHUB_EVENT_NAME='workflow_dispatch',
                GITHUB_REPOSITORY='NelomaiTTT/nelomai-app', GITHUB_REF='refs/heads/Future/desktop-0.4.0',
                GITHUB_SHA=sha, SOURCE_SHA=sha, GITHUB_ENV=str(envfile), RUNNER_TEMP=str(root))
            for name, job in workflow['jobs'].items():
                guard = next(step['run'] for step in job['steps'] if step.get('id') == 'guard')
                def run(change=None):
                    envfile.write_text('')
                    return subprocess.run(['bash', '-e', '-c', guard], cwd=repo, env={**env, **(change or {})},
                                          capture_output=True, text=True)
                with self.subTest(job=name):
                    self.assertEqual(run().returncode, 0)
                    for change in ({'GITHUB_EVENT_NAME': 'pull_request'}, {'GITHUB_EVENT_NAME': 'push'}, {'GITHUB_REF': 'refs/heads/main'},
                                   {'GITHUB_REPOSITORY': 'foreign/repo'}, {'SOURCE_SHA': 'a' * 40},
                                   {'SOURCE_SHA': sha[:12]}, {'NELOMAI_MACOS_SIGNING_P12_BASE64': 'secret'},
                                   {'TAURI_SIGNING_PRIVATE_KEY': 'secret'}):
                        self.assertNotEqual(run(change).returncode, 0, str(change))
                        self.assertEqual(envfile.read_text(), '')
                    (repo / 'dirty').write_text('untracked')
                    self.assertNotEqual(run().returncode, 0)
                    (repo / 'dirty').unlink()
                    git('update-ref', '-d', remote)
                    self.assertNotEqual(run().returncode, 0)
                    git('update-ref', remote, sha)

    def test_workflow_keeps_native_hosts_keyless_and_private_phases_protected(self):
        path = ROOT / '.github/workflows/macos-candidate.yml'
        self.assertTrue(path.is_file(), 'macOS installable candidate workflow missing')
        workflow = yaml.safe_load(path.read_text())
        self.assertEqual(workflow['permissions'], {'contents': 'read', 'actions': 'read'})
        self.assertEqual(workflow['concurrency'], {'group': 'macos-candidate-hosted', 'cancel-in-progress': False})
        jobs = workflow['jobs']
        self.assertEqual(set(jobs), {'build', 'sign', 'package', 'common_sign', 'finalize'})
        for name, job in jobs.items():
            if name not in ('build', 'package'):
                self.assertNotIn('self-hosted', str(job['runs-on']))
            self.assertIn("github.ref == 'refs/heads/Future/desktop-0.4.0'", job['if'])
            self.assertIn('github.sha == inputs.source_sha', job['if'])
            checkouts = [s for s in job['steps'] if s.get('uses', '').startswith('actions/checkout@')]
            self.assertEqual(checkouts[0]['with']['ref'], '${{ github.sha }}')
            self.assertFalse(checkouts[0]['with']['persist-credentials'])
            commands = '\n'.join(s.get('run', '') for s in job['steps'])
            self.assertNotIn('gh release create', commands)
            self.assertNotIn('git tag', commands)
            for step in job['steps']:
                private = {k for k in step.get('env', {}) if k in module('macos-candidate').PRIVATE_ENV}
                allowed = {'sign': {'NELOMAI_RELEASE_MANIFEST_PRIVATE_KEY_B64'},
                    'common_sign': {'NELOMAI_MACOS_SIGNING_P12_BASE64', 'NELOMAI_MACOS_SIGNING_P12_PASSWORD'},
                    'finalize': {'TAURI_SIGNING_PRIVATE_KEY', 'TAURI_SIGNING_PRIVATE_KEY_PASSWORD'}}.get(name, set())
                self.assertLessEqual(private, allowed)
            if name in ('build', 'package'):
                self.assertNotIn('environment', job)
                self.assertEqual(job['runs-on'], 'macos-15')
        self.assertEqual(jobs['sign']['environment'], 'release-candidate-signing')
        self.assertEqual(jobs['common_sign']['environment'], 'release-candidate-finalization')
        self.assertEqual(jobs['finalize']['environment'], 'release-candidate-finalization')
        final = jobs['finalize']['steps']
        uploads = [s['with'] for s in final if s.get('uses', '').startswith('actions/upload-artifact@')]
        self.assertEqual(uploads[0]['name'], 'macos-test-candidate-${{ env.SOURCE_SHA }}')
        self.assertEqual(uploads[0]['if-no-files-found'], 'error')


if __name__ == '__main__':
    unittest.main()
