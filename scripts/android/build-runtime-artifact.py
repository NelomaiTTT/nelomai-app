#!/usr/bin/env python3
"""Package compiled Android stable payload with the runtime-v1 signed index.

This command signs only with an explicitly supplied raw Ed25519 key. It never
reads release signing environment variables and never builds or nests an APK.
Compilation and binary collision inspection are separate mandatory build steps.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REQUIRED_LICENSES = (
    'AMNEZIAWG-ANDROID-APACHE-2.0.txt', 'AMNEZIAWG-TOOLS-GPL-2.0.txt',
    'ELF-CLEANER-GPL-2.0.txt', 'AMNEZIAWG-GO-MIT.txt', 'SOURCE-OFFER.txt',
    'TAURI-APACHE-2.0.txt', 'TAURI-MIT.txt',
)
DOMAIN = b'nelomai-runtime-manifest-v1\0'


def verify_runtime_abi(path, readelf):
    symbols = subprocess.run([str(readelf), '--dyn-syms', str(path)], check=True, capture_output=True, text=True).stdout
    exports = {line.split()[-1] for line in symbols.splitlines() if 'GLOBAL DEFAULT' in line and ' UND ' not in line}
    if not {'nelomai_runtime_v1', 'Java_ru_nelomai_runtime_stable_RuntimeEntrypoint_attach'} <= exports:
        raise ValueError('stable runtime ABI entrypoints are missing')
    if any(value.startswith('Java_') and not value.startswith('Java_ru_nelomai_runtime_stable_') for value in exports):
        raise ValueError('stable runtime ABI contains non-relocated JNI exports')
    dynamic = subprocess.run([str(readelf), '-d', str(path)], check=True, capture_output=True, text=True).stdout
    if re.findall(r'\(SONAME\).*\[([^]]+)\]', dynamic) != ['libnelomai_runtime_stable.so']:
        raise ValueError('stable runtime ABI SONAME is incorrect')


def collision_module():
    spec = importlib.util.spec_from_file_location('runtime_collisions', Path(__file__).with_name('check-runtime-collisions.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def payload_files(payload):
    check = collision_module()
    result, seen = [], set()
    if payload.is_symlink() or not payload.is_dir():
        raise ValueError('invalid runtime payload root')
    for path in sorted(payload.rglob('*')):
        if path.is_symlink():
            raise ValueError('symlink in runtime payload')
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError('nonregular runtime payload file')
        name = path.relative_to(payload).as_posix()
        check.safe_path(name)
        if name.casefold() in seen:
            raise ValueError('colliding runtime payload path')
        seen.add(name.casefold())
        if path.suffix.lower() == '.apk':
            raise ValueError('nested APK is not a runtime artifact')
        size = path.stat().st_size
        if not size or size > check.MAX_FILE:
            raise ValueError('invalid runtime payload file size')
        result.append((name, path))
    return result


def package(payload, output, version, source_commit, signing_key):
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?', version):
        raise ValueError('invalid runtime version')
    if not re.fullmatch(r'[0-9a-f]{40}', source_commit):
        raise ValueError('invalid runtime source commit')
    files = payload_files(payload)
    names = {name for name, _ in files}
    missing = {'licenses/' + name for name in REQUIRED_LICENSES} - names
    if missing:
        raise ValueError('required runtime license files are missing: ' + ', '.join(sorted(missing)))
    if not {'runtime/runtime.aar', 'webview/index.html',
            'jni/arm64-v8a/libnelomai_runtime_stable.so',
            'jni/arm64-v8a/libstable_runtime_wg_go.so'} <= names:
        raise ValueError('compiled runtime payload is incomplete')
    if output.exists():
        raise ValueError('runtime output already exists; immutable artifact cannot be overwritten')
    key = Ed25519PrivateKey.from_private_bytes(signing_key.read_bytes())
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='nelomai-artifact-', dir=output.parent) as temporary:
        staged = Path(temporary) / 'ready'
        staged.mkdir()
        index = []
        with zipfile.ZipFile(staged / 'runtime.zip', 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, path in files:
                # Hash exactly the bytes written; never stat/hash/copy separately.
                value = path.read_bytes()
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, value)
                role = 'license' if name.startswith('licenses/') else 'shared_library' if name.endswith('.so') else 'resource'
                index.append({'path': name, 'size_bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest(), 'role': role})
        manifest = {'format_version': 1, 'runtime_version': version, 'source_commit': source_commit,
                    'platform': 'android', 'architecture': 'aarch64', 'contract_version': 1, 'files': index}
        value = json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        (staged / 'runtime-manifest-v1.json').write_bytes(value)
        (staged / 'runtime-manifest-v1.sig').write_bytes(key.sign(DOMAIN + value))
        staged.rename(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--payload', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--signing-key', type=Path, required=True)
    parser.add_argument('--readelf', type=Path, required=True)
    args = parser.parse_args()
    verify_runtime_abi(args.payload / 'jni/arm64-v8a/libnelomai_runtime_stable.so', args.readelf)
    # Actual CLI gate: fail closed on malformed AAR/ELF before signing.
    check = collision_module()
    for name, path in payload_files(args.payload):
        if name.endswith(('.aar', '.so')):
            if name.endswith('.aar'):
                inventory = check.inspect_archive(path.read_bytes(), readelf=args.readelf)
                if not inventory['classes'] or any(not item.startswith('ru.nelomai.runtime.stable.') for item in inventory['classes']):
                    raise ValueError('stable artifact contains non-relocated runtime classes')
                if any(not item.split('/', 1)[1].startswith('stable_runtime_') for item in inventory['resources']):
                    raise ValueError('stable artifact contains non-prefixed resources')
            else:
                import io
                data = io.BytesIO()
                with zipfile.ZipFile(data, 'w') as archive:
                    archive.writestr(name, path.read_bytes())
                check.inspect_archive(data.getvalue(), readelf=args.readelf)
    package(args.payload, args.output, args.version, args.source_commit, args.signing_key)


if __name__ == '__main__':
    main()
