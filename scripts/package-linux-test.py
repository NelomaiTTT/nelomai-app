#!/usr/bin/env python3
"""Linux-only diagnostic AppImage. Never emits a release set or publishable candidate."""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

spec = importlib.util.spec_from_file_location('builder', Path(__file__).with_name('build-release-platform.py'))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
verifier = builder.verifier
container = verifier.load_script('build-runtime-acceptance-container.py')


def stage(draft, output, source, private_key, public_key):
    builder.gates.full_source(source)
    if output.exists() or output.is_symlink():
        raise ValueError('immutable Linux test stage exists')
    key = Ed25519PrivateKey.from_private_bytes(private_key.read_bytes())
    pin = public_key.read_bytes()
    if (key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) != pin
            or (draft / 'runtime-public-key.raw').read_bytes() != pin):
        raise ValueError('test signer differs from compile pin')
    prefix = 'nelomai-runtime-0.2.17-linux-x86_64'
    archive, manifest, signature = [draft / 'latest' / (prefix + suffix)
        for suffix in ('.zip', '.manifest.json', '.manifest.sig')]
    runtime = verifier.verify(archive, manifest, signature, draft / 'draft-public-key.raw',
        '0.2.17', source, 'linux', 'x86_64')
    document = dict(format_version=1, container_version='0.2.17',
        release_set_id='linux-test-' + source, minimum_runtime_contract=1, maximum_runtime_contract=1,
        slots=[dict(slot='latest', manifest=runtime)])
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.linux-test-', dir=output.parent) as temporary:
        staged = Path(temporary) / 'resources'
        payload = staged / 'runtime/engines/latest/0.2.17'
        verifier.extract(archive, runtime, payload)
        dispatcher = staged / 'dispatcher/1/nelomai-unix-service'
        dispatcher.parent.mkdir(parents=True)
        shutil.copy2(payload / 'nelomai-unix-service', dispatcher)
        manifest = staged / 'runtime/container-manifest-v1.json'
        signature = manifest.with_name('container-manifest-v1.sig')
        body = container.release_set.canonical(document)
        manifest.write_bytes(body)
        signature.write_bytes(key.sign(b'nelomai-container-manifest-v1\0' + body))
        verifier.authenticated('container', manifest, signature, public_key, 'linux', 'x86_64')
        staged.rename(output)
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('draft', 'output', 'work', 'private-key', 'public-key'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--source-sha', required=True)
    args = parser.parse_args()
    for name in ('draft', 'output', 'work', 'private_key', 'public_key'):
        setattr(args, name, getattr(args, name).resolve())
    builder.gates.require_operation('build_only', 'test_sign')
    if args.output.exists() or args.work.exists():
        raise ValueError('immutable Linux test output exists')
    args.work.mkdir(parents=True)
    staged = args.work / 'staged'
    stage(args.draft, staged, args.source_sha, args.private_key, args.public_key)
    env = {**os.environ, 'NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64':
        base64.b64encode(args.public_key.read_bytes()).decode()}
    env = builder.updater_environment('build_only', args.work, env)
    env.pop('TAURI_SIGNING_PRIVATE_KEY', None)
    env.pop('TAURI_SIGNING_PRIVATE_KEY_PASSWORD', None)
    package = container.package_desktop(staged, args.work / 'packaged', args.public_key,
        'linux', 'x86_64', environment=env)
    args.output.mkdir(parents=True)
    destination = args.output / 'nelomai-test-0.2.17-linux-x86_64.AppImage'
    shutil.copy2(package, destination)
    shutil.copyfile(args.public_key, args.output / 'runtime-public-key.raw')
    (args.output / 'package-digests.json').write_text(json.dumps(dict(
        source_sha=args.source_sha, platform='linux', architecture='x86_64', mode='build_only',
        publishable=False, native_payloads='verified', full_acceptance='UNRUN',
        packages={'shipping': dict(name=destination.name, sha256=verifier.digest(destination),
            size_bytes=destination.stat().st_size)}), sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
