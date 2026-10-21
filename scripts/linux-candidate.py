#!/usr/bin/env python3
"""Linux-only nonpublishable candidate; use the existing runtime and updater contracts."""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import tomllib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

spec = importlib.util.spec_from_file_location('builder', Path(__file__).with_name('build-release-platform.py'))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
verifier, gates = builder.verifier, builder.gates
container = verifier.load_script('build-runtime-acceptance-container.py')
canonical = container.release_set.canonical
VERSION = '0.4.0'
LATEST = 'nelomai-runtime-0.4.0-linux-x86_64'
PACKAGE = 'nelomai-0.4.0-linux-x86_64.AppImage'
SUFFIXES = ('.zip', '.manifest.json', '.manifest.sig')
UPDATER_PUBLIC = json.loads((builder.ROOT / 'src-tauri/tauri.conf.json').read_bytes())['plugins']['updater']['pubkey']
PRIVATE_ENV = ('NELOMAI_RELEASE_MANIFEST_PRIVATE_KEY_B64', 'TAURI_SIGNING_PRIVATE_KEY',
    'TAURI_SIGNING_PRIVATE_KEY_PASSWORD', 'ANDROID_KEYSTORE_PATH', 'ANDROID_KEYSTORE_BASE64',
    'ANDROID_KEYSTORE_PASSWORD', 'ANDROID_KEY_PASSWORD', 'NELOMAI_MACOS_SIGNING_P12_BASE64',
    'NELOMAI_MACOS_SIGNING_P12_PASSWORD', 'APPLE_CERTIFICATE', 'APPLE_CERTIFICATE_PASSWORD',
    'APPLE_SIGNING_IDENTITY', 'APPLE_ID', 'APPLE_PASSWORD', 'APPLE_API_KEY', 'APPLE_API_KEY_PATH')


def source(sha, *, root=builder.ROOT, environment=None, keyless=False):
    env = os.environ if environment is None else environment
    gates.full_source(sha)
    if (env.get('GITHUB_EVENT_NAME') not in ('push', 'workflow_dispatch')
            or (env.get('GITHUB_REPOSITORY'), env.get('GITHUB_REF'), env.get('GITHUB_SHA')) != (
                'NelomaiTTT/nelomai-app', 'refs/heads/Future/linux-hot-standby-0.4.0', sha)):
        raise ValueError('Linux candidate requires exact repository/ref/source and push or manual event')
    if keyless and any(env.get(name) for name in PRIVATE_ENV):
        raise ValueError('native Linux candidate must be private-keyless')
    if env.get('NELOMAI_UPDATER_PUBLIC_KEY') != UPDATER_PUBLIC:
        raise ValueError('Linux candidate updater public pin mismatch')
    if len(base64.b64decode(env.get('NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64', ''), validate=True)) != 32:
        raise ValueError('explicit runtime public pin required')
    versions = [json.loads((root / name).read_bytes())['version'] for name in ('package.json', 'src-tauri/tauri.conf.json')]
    versions.append(tomllib.loads((root / 'src-tauri/Cargo.toml').read_text())['package']['version'])
    if versions != [VERSION] * 3 or gates.git(root, 'status', '--porcelain', '--untracked-files=all', '--ignore-submodules=none'):
        raise ValueError('Linux candidate requires clean exact 0.4.0 source')
    gates.verify_source(root, sha, VERSION, base=gates.BASE, mode='sign_candidate')


def snapshot(directory):
    if directory.is_symlink() or not directory.is_dir() or any(path.is_symlink() for path in directory.rglob('*')):
        raise ValueError('regular candidate input tree required')
    return {path.relative_to(directory).as_posix(): verifier.digest(path)
            for path in directory.rglob('*') if path.is_file()}


def stable_linux(directory, public):
    prefix = f'nelomai-runtime-{gates.STABLE_VERSION}-linux-x86_64'
    root = f'nelomai-runtime-{gates.STABLE_VERSION}-release-set.manifest'
    names = [prefix + suffix for suffix in SUFFIXES] + [root + '.json', root + '.sig']
    if set(snapshot(directory)) != set(names):
        raise ValueError('confirmed stable inventory must contain only Linux and pinned root')
    doc = verifier.authenticated('release-set', directory / (root + '.json'), directory / (root + '.sig'),
                                 public, gates.STABLE_ROOT_SHA256)
    if (doc['runtime_version'], doc['source_commit']) != (gates.STABLE_VERSION, gates.STABLE_SOURCE):
        raise ValueError('confirmed stable root identity mismatch')
    entries = [entry for entry in doc['artifacts'] if (entry['platform'], entry['architecture']) == ('linux', 'x86_64')]
    if len(entries) != 1:
        raise ValueError('confirmed stable Linux membership missing')
    for kind, suffix in zip(('archive', 'manifest', 'signature'), SUFFIXES):
        if (entries[0][kind + '_name'] != prefix + suffix
                or entries[0][kind + '_sha256'] != verifier.digest(directory / (prefix + suffix))):
            raise ValueError('confirmed stable Linux bytes differ from pinned root')
    manifest = verifier.verify(*(directory / (prefix + suffix) for suffix in SUFFIXES), public,
        gates.STABLE_VERSION, gates.STABLE_SOURCE, 'linux', 'x86_64')
    return manifest, names


def download_stable(output, public):
    if output.exists() or output.is_symlink():
        raise ValueError('immutable confirmed stable output exists')
    prefix = f'nelomai-runtime-{gates.STABLE_VERSION}'
    names = [prefix + '-linux-x86_64' + suffix for suffix in SUFFIXES]
    names += [prefix + '-release-set.manifest' + suffix for suffix in ('.json', '.sig')]
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.linux-stable-', dir=output.parent) as temporary:
        staged = Path(temporary) / 'stable'
        builder.run('gh', 'release', 'download', 'v' + gates.STABLE_VERSION, '--repo', 'NelomaiTTT/nelomai-app',
            *(argument for name in names for argument in ('--pattern', name)), '--dir', staged)
        stable_linux(staged, public)
        staged.rename(output)


def sign(draft, stable, output, sha, private, public, stable_public):
    gates.require_operation('sign_candidate', 'release_sign')
    gates.full_source(sha)
    if output.exists() or output.is_symlink():
        raise ValueError('immutable signed output exists')
    before, old_before = snapshot(draft), snapshot(stable)
    required = {'latest/' + LATEST + suffix for suffix in SUFFIXES} | {'draft-public-key.raw', 'runtime-public-key.raw'}
    if not required <= before.keys() or before.keys() - required - {'linux-x86_64.sizes.json'}:
        raise ValueError('Linux draft inventory must contain only latest and public pins')
    if private.is_symlink() or any(private.resolve().is_relative_to(path.resolve()) for path in (draft, stable, output)):
        raise ValueError('private signing key must be outside candidate artifacts')
    if (draft / 'runtime-public-key.raw').read_bytes() != public.read_bytes():
        raise ValueError('native compile pin differs from final runtime pin')
    old, old_names = stable_linux(stable, stable_public)
    latest = verifier.verify(*(draft / 'latest' / (LATEST + suffix) for suffix in SUFFIXES),
        draft / 'draft-public-key.raw', VERSION, sha, 'linux', 'x86_64')
    key = Ed25519PrivateKey.from_private_bytes(private.read_bytes())
    if key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) != public.read_bytes():
        raise ValueError('final signing key differs from public pin')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.linux-sign-', dir=output.parent) as temporary:
        staged = Path(temporary) / 'signed'
        for folder in ('latest/linux', 'confirmed-stable', 'containers/linux/shipping'):
            (staged / folder).mkdir(parents=True)
        latest_dir = staged / 'latest/linux'
        for suffix in ('.zip', '.manifest.json'):
            shutil.copyfile(draft / 'latest' / (LATEST + suffix), latest_dir / (LATEST + suffix))
        (latest_dir / (LATEST + '.manifest.sig')).write_bytes(key.sign(
            b'nelomai-runtime-manifest-v1\0' + (latest_dir / (LATEST + '.manifest.json')).read_bytes()))
        for name in old_names:
            shutil.copyfile(stable / name, staged / 'confirmed-stable' / name)
        shutil.copyfile(public, staged / 'runtime-public-key.raw')
        shutil.copyfile(stable_public, staged / 'stable-public-key.raw')
        doc = dict(format_version=1, container_version=VERSION, release_set_id='linux-candidate-' + sha,
            minimum_runtime_contract=1, maximum_runtime_contract=1,
            stable_release_set_sha256=gates.STABLE_ROOT_SHA256,
            stable_platform_manifest_sha256=verifier.digest(stable / old_names[1]),
            slots=[dict(slot='latest', manifest=latest), dict(slot='stable', manifest=old)])
        docs = staged / 'containers/linux/shipping'
        raw = canonical(doc)
        (docs / 'container-manifest-v1.json').write_bytes(raw)
        (docs / 'container-manifest-v1.sig').write_bytes(key.sign(b'nelomai-container-manifest-v1\0' + raw))
        verified(staged, sha, public, stable_public)
        if before != snapshot(draft) or old_before != snapshot(stable):
            raise ValueError('candidate inputs changed during signing')
        staged.rename(output)


def verified(signed, sha, public, stable_public):
    gates.full_source(sha)
    before = snapshot(signed)
    old, names = stable_linux(signed / 'confirmed-stable', stable_public)
    expected = {'latest/linux/' + LATEST + suffix for suffix in SUFFIXES} | {'confirmed-stable/' + name for name in names}
    expected |= {'runtime-public-key.raw', 'stable-public-key.raw',
        'containers/linux/shipping/container-manifest-v1.json', 'containers/linux/shipping/container-manifest-v1.sig'}
    if (set(before) != expected or (signed / 'runtime-public-key.raw').read_bytes() != public.read_bytes()
            or (signed / 'stable-public-key.raw').read_bytes() != stable_public.read_bytes()):
        raise ValueError('signed Linux inventory or public pin mismatch')
    latest = verifier.verify(*(signed / 'latest/linux' / (LATEST + suffix) for suffix in SUFFIXES),
        public, VERSION, sha, 'linux', 'x86_64')
    docs = signed / 'containers/linux/shipping'
    doc = verifier.authenticated('container', docs / 'container-manifest-v1.json',
                                 docs / 'container-manifest-v1.sig', public, 'linux', 'x86_64')
    if (doc['container_version'] != VERSION or doc['release_set_id'] != 'linux-candidate-' + sha
            or doc['stable_release_set_sha256'] != gates.STABLE_ROOT_SHA256
            or doc['stable_platform_manifest_sha256'] != verifier.digest(signed / 'confirmed-stable' / names[1])
            or doc['slots'] != [dict(slot='latest', manifest=latest), dict(slot='stable', manifest=old)]):
        raise ValueError('Linux container requires exact latest and confirmed stable')
    return doc, before


def stage(signed, output, sha, public, stable_public):
    doc, before = verified(signed, sha, public, stable_public)
    if output.exists() or output.is_symlink():
        raise ValueError('immutable Linux staging output exists')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.linux-stage-', dir=output.parent) as temporary:
        staged = Path(temporary) / 'resources'
        for slot in doc['slots']:
            manifest = slot['manifest']
            folder = signed / ('latest/linux' if slot['slot'] == 'latest' else 'confirmed-stable')
            prefix = f"nelomai-runtime-{manifest['runtime_version']}-linux-x86_64"
            payload = staged / 'runtime/engines' / slot['slot'] / manifest['runtime_version']
            verifier.extract(folder / (prefix + '.zip'), manifest, payload)
            verifier.inspect(payload, manifest)
        dispatcher = staged / 'dispatcher/1/nelomai-unix-service'
        dispatcher.parent.mkdir(parents=True)
        shutil.copy2(staged / 'runtime/engines/latest/0.4.0/nelomai-unix-service', dispatcher)
        for suffix in ('.json', '.sig'):
            shutil.copyfile(signed / 'containers/linux/shipping' / ('container-manifest-v1' + suffix),
                            staged / 'runtime' / ('container-manifest-v1' + suffix))
        if before != snapshot(signed):
            raise ValueError('signed Linux inputs changed during staging')
        staged.rename(output)


def package_index(appimage, signed, sha):
    return dict(purpose='linux-candidate', source_sha=sha, platform='linux', architecture='x86_64',
        name=PACKAGE, sha256=verifier.digest(appimage), size_bytes=appimage.stat().st_size,
        container_sha256=verifier.digest(signed / 'containers/linux/shipping/container-manifest-v1.json'))


def package(signed, output, sha, public, stable_public):
    if any(os.environ.get(name) for name in PRIVATE_ENV) or os.environ.get('NELOMAI_UPDATER_PUBLIC_KEY') != UPDATER_PUBLIC:
        raise ValueError('Linux packaging requires keyless environment and pinned updater public key')
    if output.exists() or output.is_symlink():
        raise ValueError('immutable Linux package output exists')
    stage(signed, output / 'staged', sha, public, stable_public)
    environment = {**os.environ, 'NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64': base64.b64encode(public.read_bytes()).decode()}
    appimage = container.package_desktop(output / 'staged', output / 'work', public, 'linux', 'x86_64', environment=environment)
    destination = output / 'shipping' / PACKAGE
    destination.parent.mkdir()
    shutil.copyfile(appimage, destination)
    (output / 'package-digests.json').write_bytes(canonical(package_index(destination, signed, sha)))


def finalize(packages, signed, output, sha, public, stable_public):
    gates.require_operation('sign_candidate', 'release_sign')
    _, before = verified(signed, sha, public, stable_public)
    expected_files = {'shipping/' + PACKAGE, 'package-digests.json'}
    package_before = snapshot(packages)
    if set(package_before) != expected_files or os.environ.get('NELOMAI_UPDATER_PUBLIC_KEY') != UPDATER_PUBLIC:
        raise ValueError('Linux package inventory or updater public pin mismatch')
    appimage = packages / 'shipping' / PACKAGE
    index = json.loads((packages / 'package-digests.json').read_bytes())
    if index != package_index(appimage, signed, sha):
        raise ValueError('Linux package changed before finalization')
    if output.exists() or output.is_symlink():
        raise ValueError('immutable finalized Linux candidate exists')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.linux-final-', dir=output.parent) as temporary:
        work = Path(temporary)
        candidate = work / 'candidate'
        candidate.mkdir()
        destination = candidate / PACKAGE
        shutil.copyfile(appimage, destination)
        env = builder.updater_environment('sign_candidate', work, os.environ)
        builder.run(builder.ROOT / 'node_modules/.bin/tauri', 'signer', 'sign', destination, env=env, capture=True)
        updater = work / 'updater-public.b64'
        updater.write_text(UPDATER_PUBLIC)
        executable = os.environ.get('NELOMAI_UPDATER_SIGNATURE_VERIFIER', str(builder.ROOT / 'target/debug/examples/verify-updater-signature'))
        builder.run(executable, destination, candidate / (PACKAGE + '.sig'), updater, capture=True)
        if (verifier.digest(destination) != index['sha256'] or package_before != snapshot(packages)
                or before != snapshot(signed)):
            raise ValueError('Linux candidate inputs changed during finalization')
        shutil.copytree(signed, candidate / 'runtime')
        inventory = dict(purpose='linux-candidate', publishable=False, platform='linux', architecture='x86_64',
            source_sha=sha, version=VERSION, stable_release_set_sha256=gates.STABLE_ROOT_SHA256,
            full_acceptance='UNRUN', run_id=os.environ.get('GITHUB_RUN_ID'), run_attempt=os.environ.get('GITHUB_RUN_ATTEMPT'),
            assets=snapshot(candidate))
        (candidate / 'candidate-inventory.json').write_bytes(canonical(inventory))
        candidate.rename(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('source', 'stable', 'sign', 'package', 'finalize'))
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--keyless', action='store_true')
    for name in ('draft', 'stable', 'signed', 'packages', 'output', 'private-key', 'public-key', 'stable-public-key'):
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args()
    source(args.source_sha, keyless=args.keyless or args.phase in ('stable', 'package'))
    if args.phase == 'stable': download_stable(args.output, args.public_key)
    elif args.phase == 'sign':
        sign(args.draft, args.stable, args.output, args.source_sha, args.private_key, args.public_key, args.stable_public_key)
    elif args.phase == 'package': package(args.signed, args.output, args.source_sha, args.public_key, args.stable_public_key)
    elif args.phase == 'finalize': finalize(args.packages, args.signed, args.output, args.source_sha, args.public_key, args.stable_public_key)


if __name__ == '__main__':
    main()
