"""Verify an explicitly selected retained 0.4.0 candidate; no install or publish."""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
if not __debug__:
    raise RuntimeError('Verification requires Python assertions enabled')
parser = argparse.ArgumentParser(description=__doc__)
for name in ('app', 'root', 'runtime-verifier', 'updater-verifier'):
    parser.add_argument('--' + name, type=Path, required=True)
for name in ('repository', 'run', 'source', 'ci', 'inventory-sha256'):
    parser.add_argument('--' + name, required=True)
parser.add_argument('--artifact', type=int, required=True)
args = parser.parse_args()
APP, ROOT = args.app.resolve(strict=True), args.root.resolve(strict=True)
REPO, RUN, SOURCE = args.repository, args.run, args.source
VERSION = '0.4.0'
RUNTIME_PUBLIC_KEY_B64 = 'WtTc6wVyswcmE5LC0PuOJ+XX82GTW+iPgs4yvZBP2YY='
MACOS_PIN = 'dde0dd9b1f84cc24f8527fd6f50f95355b33c4ba'


def gh(endpoint):
    return json.loads(subprocess.check_output(['gh', 'api', '--method', 'GET', endpoint], text=True))


def load(name):
    spec = importlib.util.spec_from_file_location(name, APP / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


publication = load('check-publication-inputs')
gates = publication.gates
assert gates.VERSION == VERSION
gates.verify_source(APP, SOURCE, VERSION, mode='sign_candidate')
run = gh(f'repos/{REPO}/actions/runs/{RUN}')
assert str(run['id']) == RUN and run['head_sha'] == SOURCE
assert run['status'] == 'completed' and run['conclusion'] == 'success'
ci = gh(f'repos/{REPO}/actions/runs/{args.ci}')
assert str(ci['id']) == args.ci and ci['head_sha'] == SOURCE
assert ci['status'] == 'completed' and ci['conclusion'] == 'success'
assert ci['path'] == '.github/workflows/checks.yml'
assert ci['repository']['full_name'] == ci['head_repository']['full_name'] == REPO
jobs = gh(f'repos/{REPO}/actions/runs/{RUN}/jobs?per_page=100')['jobs']
assert [j['conclusion'] for j in jobs if j['name'] == 'publish'] == ['skipped']
assert [j['conclusion'] for j in jobs if j['name'] == 'macos_common_sign'] == ['success']
refs = gh(f'repos/{REPO}/git/matching-refs/tags/v{VERSION}')
assert isinstance(refs, list) and len(refs) <= 100
assert all(ref['ref'] != f'refs/tags/v{VERSION}' for ref in refs)
for page in range(1, 21):
    releases = gh(f'repos/{REPO}/releases?per_page=100&page={page}')
    assert isinstance(releases, list) and len(releases) <= 100
    assert all(release['tag_name'] != f'v{VERSION}' for release in releases)
    if len(releases) < 100:
        break
else:
    raise RuntimeError('Release history exceeds bounded absence check')
assert publication.select_candidate(REPO, RUN, SOURCE, VERSION) == args.artifact
candidate = ROOT / 'candidate'
publication.check(candidate, SOURCE, RUN, args.inventory_sha256)
inventory = json.loads((candidate / 'candidate-inventory.json').read_bytes())
assert len(inventory['assets']) == 22
runtime_key = gh(f'repos/{REPO}/actions/variables/NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64')['value']
assert runtime_key == RUNTIME_PUBLIC_KEY_B64
public = ROOT / 'runtime-public.raw'
public.write_bytes(base64.b64decode(runtime_key, validate=True))
updater = ROOT / 'updater-public.txt'
updater.write_text(json.loads((APP / 'src-tauri/tauri.conf.json').read_text())['plugins']['updater']['pubkey'])
android_pin = gh(f'repos/{REPO}/actions/variables/ANDROID_SIGNER_SHA256')['value']
os.environ['TMPDIR'] = str(ROOT)
os.environ['NELOMAI_RUNTIME_CONTRACT_VERIFIER'] = str(args.runtime_verifier.resolve(strict=True))
os.environ['NELOMAI_UPDATER_SIGNATURE_VERIFIER'] = str(args.updater_verifier.resolve(strict=True))
root_name = f'nelomai-runtime-{VERSION}-release-set.manifest.json'
gates.verify_runtime_release(candidate, VERSION, SOURCE, inventory['assets'][root_name], public)
gates.verify_updater_release(candidate, public, updater, android_pin)
signer = load('sign-macos-common-package')
assert inventory['macos_common_signature'] == signer.signature_metadata(MACOS_PIN)
app, _ = signer.extract(candidate / gates.PACKAGE_NAMES['macos'], ROOT / 'verified-macos')
signer.verify_signature(app, MACOS_PIN)
result = {'source': SOURCE, 'run_id': RUN, 'ci_run_id': args.ci, 'artifact_id': args.artifact,
          'inventory_sha256': args.inventory_sha256, 'assets_sha256_verified': 22,
          'runtime_and_updater_signatures': 'verified', 'macos_strict_signature': 'verified',
          'publish': 'skipped', 'tag_and_release': 'absent', 'installed': False,
          'windows_installer_sha256': inventory['assets'][gates.PACKAGE_NAMES['windows']]}
(ROOT / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result))
