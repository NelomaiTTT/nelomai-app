"""Single-platform diagnostic staging; fixtures are not executable acceptance."""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
import yaml
from scripts.tests.test_runtime_artifact import ArtifactFixture, SOURCE, PREFIX, SCRIPTS, ROOT, module


class LinuxWorkflowTest(unittest.TestCase):
    def workflow(self):
        path = ROOT / '.github/workflows/linux-build.yml'
        self.assertTrue(path.is_file(), 'standalone Linux workflow is missing')
        return yaml.safe_load(path.read_text())

    def test_only_owner_branch_exact_source_can_schedule_linux_runner(self):
        workflow = self.workflow()
        triggers = workflow.get('on', workflow.get(True))
        self.assertEqual(set(triggers), {'push', 'workflow_dispatch'})
        self.assertEqual(triggers['push'], {'branches': ['Future/desktop-0.4.0'],
            'paths': ['.github/workflows/linux-build.yml']})
        self.assertTrue(triggers['workflow_dispatch']['inputs']['source_sha']['required'])
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        self.assertEqual(list(workflow['jobs']), ['linux-package-diagnostic'])
        job = workflow['jobs']['linux-package-diagnostic']
        self.assertEqual(job['runs-on'], 'ubuntu-22.04')
        self.assertNotIn('environment', job)
        self.assertNotIn('strategy', job)
        expression = job['if'].removeprefix('${{').removesuffix('}}').replace('&&', ' and ').replace('||', ' or ').strip()
        source_expression = job['env']['SOURCE_SHA'].removeprefix('${{').removesuffix('}}').replace(
            '&&', ' and ').replace('||', ' or ').strip()
        allowed = dict(event_name='workflow_dispatch', repository='NelomaiTTT/nelomai-app',
            ref='refs/heads/Future/desktop-0.4.0', sha=SOURCE)
        for override, expected in (({}, True), ({'event_name': 'push'}, False),
                         ({'event_name': 'push', 'sha': 'b' * 40}, False),
                         ({'event_name': 'pull_request'}, False),
                         ({'repository': 'foreign/nelomai-app'}, False), ({'ref': 'refs/heads/main'}, False),
                         ({'ref': 'refs/heads/Future/unrelated'}, False),
                         ({'ref': 'refs/tags/v0.4.0'}, False), ({'sha': 'b' * 40}, False)):
            with self.subTest(override=override):
                context = {
                    'github': SimpleNamespace(**{**allowed, **override}),
                    'inputs': SimpleNamespace(source_sha=SOURCE)}
                selected = eval(expression, {'__builtins__': {}}, context)
                self.assertEqual(bool(selected), expected)
                if expected:
                    self.assertEqual(eval(source_expression, {'__builtins__': {}}, context), context['github'].sha)
        checkout = next(step for step in job['steps'] if step.get('uses', '').startswith('actions/checkout@'))
        self.assertEqual(checkout['with']['ref'], '${{ env.SOURCE_SHA }}')
        self.assertIs(checkout['with']['persist-credentials'], False)
        self.assertEqual(checkout['with']['fetch-depth'], 0)
        uploads = [step for step in job['steps'] if step.get('uses', '').startswith('actions/upload-artifact@')]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(uploads[0]['with']['name'], 'nelomai-test-0.4.0-linux-x86_64-${{ env.SOURCE_SHA }}')
        self.assertEqual(uploads[0]['with']['path'], '${{ env.RUN_ROOT }}/packages-linux/')
        self.assertNotIn('secrets.', yaml.safe_dump(workflow))

    def test_guard_rejects_dirty_foreign_or_private_key_runner_before_local_code(self):
        steps = self.workflow()['jobs']['linux-package-diagnostic']['steps']
        guard_index = next(index for index, step in enumerate(steps) if step.get('id') == 'guard')
        local_index = next(index for index, step in enumerate(steps) if step.get('uses', '').startswith('./'))
        self.assertLess(guard_index, local_index)
        self.assertFalse(any('scripts/' in step.get('run', '') for step in steps[:guard_index]))
        guard = steps[guard_index]['run']
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(['git', 'init', '-q', root], check=True)
            (root / 'tracked').write_text('clean')
            subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
            subprocess.run(['git', '-C', str(root), '-c', 'user.name=Fixture', '-c',
                            'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture'], check=True)
            source = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
            subprocess.run(['git', '-C', str(root), 'update-ref',
                'refs/remotes/origin/Future/desktop-0.4.0', source], check=True)
            env = {'PATH': os.environ['PATH'], 'HOME': temporary, 'SOURCE_SHA': source,
                'GITHUB_SHA': source, 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                'GITHUB_REPOSITORY': 'NelomaiTTT/nelomai-app',
                'GITHUB_REF': 'refs/heads/Future/desktop-0.4.0'}
            cases = [{}, {'GITHUB_EVENT_NAME': 'push'}, {'SOURCE_SHA': 'b' * 40}, {'SOURCE_SHA': source[:12]},
                {'GITHUB_SHA': 'b' * 40}, {'GITHUB_EVENT_NAME': 'pull_request'},
                {'GITHUB_REPOSITORY': 'foreign/repo'}, {'GITHUB_REF': 'refs/heads/main'},
                {'GITHUB_REF': 'refs/heads/Future/unrelated'},
                *({name: 'private-test-value'} for name in (
                    'NELOMAI_RELEASE_MANIFEST_PRIVATE_KEY_B64', 'TAURI_SIGNING_PRIVATE_KEY',
                    'TAURI_SIGNING_PRIVATE_KEY_PASSWORD', 'ANDROID_KEYSTORE_PATH',
                    'ANDROID_KEYSTORE_BASE64', 'ANDROID_KEYSTORE_PASSWORD', 'ANDROID_KEY_PASSWORD',
                    'NELOMAI_MACOS_SIGNING_P12_BASE64', 'NELOMAI_MACOS_SIGNING_P12_PASSWORD'))]
            for override in cases:
                with self.subTest(override=list(override)):
                    result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', guard],
                        cwd=root, env={**env, **override}, capture_output=True, text=True)
                    expected = not override or override == {'GITHUB_EVENT_NAME': 'push'}
                    self.assertEqual(result.returncode == 0, expected, result.stderr)
                    self.assertNotIn('private-test-value', result.stdout + result.stderr)
            for dirty in ('tracked', 'untracked'):
                with self.subTest(dirty=dirty):
                    (root / dirty).write_text('dirty')
                    result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', guard],
                        cwd=root, env=env, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    (root / 'tracked').write_text('clean')

    def test_build_and_package_use_existing_linux_only_nonpublishing_chain(self):
        steps = self.workflow()['jobs']['linux-package-diagnostic']['steps']
        native = next(step for step in steps if step.get('uses') == './.github/actions/release-native-host')
        self.assertEqual(native['with'], {'platform': 'linux', 'target': 'x86_64-unknown-linux-gnu', 'node24': 'true'})
        opener = next((step for step in steps if ['sudo', 'apt-get', 'install', '-y', 'xdg-utils'] in [
            shlex.split(line) for line in step.get('run', '').splitlines()
            if line.strip().startswith('sudo apt-get install')]), None)
        self.assertIsNotNone(opener, 'headless Linux needs xdg-open before AppImage packaging')
        self.assertLess(steps.index(native), steps.index(opener))
        self.assertLess(steps.index(opener), next(index for index, step in enumerate(steps)
            if 'scripts/package-linux-test.py' in step.get('run', '')))
        commands = [shlex.split(line) for step in steps for line in step.get('run', '').replace('\\\n', ' ').splitlines()
                    if line.strip().startswith('python scripts/')]
        build = next(command for command in commands if command[1] == 'scripts/build-release-platform.py')
        package = next(command for command in commands if command[1] == 'scripts/package-linux-test.py')
        source = next(command for command in commands if command[1] == 'scripts/release-candidate-gates.py')
        for command in (build, package, source):
            self.assertEqual(command[command.index('--source-sha') + 1], '$SOURCE_SHA')
        self.assertEqual(build[build.index('--platform') + 1], 'linux')
        self.assertEqual(build[build.index('--mode') + 1], 'build_only')
        self.assertEqual(source[source.index('--version') + 1], '0.4.0')
        self.assertEqual(source[source.index('--mode') + 1], 'build_only')
        trust = next(command for command in commands if command[1] == 'scripts/prepare-release-trust.py')
        self.assertEqual(trust[trust.index('--mode') + 1], 'build_only')
        report_step = next(step for step in steps if step.get('id') == 'verify-package')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'packages-linux').mkdir()
            report = dict(source_sha=SOURCE, platform='linux', architecture='x86_64',
                mode='build_only', publishable=False, full_acceptance='UNRUN')
            path = root / 'packages-linux/package-digests.json'
            for override in ({}, {'source_sha': 'b' * 40}, {'platform': 'windows'},
                             {'publishable': True}, {'full_acceptance': 'PASS'}, {'mode': 'sign_candidate'}):
                with self.subTest(override=override):
                    path.write_text(json.dumps({**report, **override}))
                    result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', report_step['run']],
                        cwd=root, env={'PATH': os.environ['PATH'], 'RUN_ROOT': str(root), 'SOURCE_SHA': SOURCE},
                        capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, not override, result.stderr)


class LinuxTestPackageTest(ArtifactFixture):
    def test_current_linux_diagnostic_consumes_030_native_drafts(self):
        builder = module('package-linux-test')
        draft = self.root / 'draft'
        module('build-runtime-manifest').package(self.payload, draft / 'latest', '0.3.0', SOURCE,
            'linux', 'x86_64', self.keyfile)
        for name in ('draft-public-key.raw', 'runtime-public-key.raw'):
            shutil.copyfile(self.public, draft / name)
        result = builder.stage(draft, self.root / 'staged', SOURCE, self.keyfile, self.public, version='0.3.0')
        self.assertEqual(result['container_version'], '0.3.0')
        self.assertEqual((self.root / 'staged/runtime/engines/latest/0.3.0/nelomai-runtime').read_bytes(),
                         (self.payload / 'nelomai-runtime').read_bytes())

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
            self.assertEqual((staged / 'runtime/engines/latest/0.2.20' / name).read_bytes(),
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
