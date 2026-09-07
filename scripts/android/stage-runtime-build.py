#!/usr/bin/env python3
"""Stage actual compiled runtime bytes and optional latest-only APK inputs.

No downloads, key discovery, signing credentials, installs, or release writes.
--local-test-container explicitly makes a disposable trust key for local APK
verification. Production packaging uses build-runtime-artifact.py with an
explicit key and the same staged binary payload.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption


def copy(source, target):
    if not source.is_file() or source.is_symlink(): raise ValueError('missing or unsafe compiled input: ' + str(source))
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'output', 'native', 'tunnel', 'readelf'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--slot', choices=('latest', 'stable'), required=True)
    parser.add_argument('--source-commit', required=True)
    signing = parser.add_mutually_exclusive_group()
    signing.add_argument('--local-test-container', action='store_true')
    signing.add_argument('--container-signing-key', type=Path, help='Explicit raw key for normal latest-only APK inputs; no key discovery')
    parser.add_argument('--host', type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}', args.source_commit): raise ValueError('full lowercase source commit is required')
    if args.local_test_container or args.container_signing_key:
        if args.slot != 'latest' or args.host is None: raise ValueError('signed APK inputs require latest and common host')
    if args.output.exists(): raise ValueError('immutable staging directory already exists')
    root = args.root.resolve(); output = args.output.resolve()
    version = json.loads((root / 'src-tauri/tauri.conf.json').read_text())['version']
    payload = output / 'payload'; payload.mkdir(parents=True)
    library = 'libnelomai_runtime_stable.so' if args.slot == 'stable' else 'libnelomai_app_lib.so'
    tunnel = 'libstable_runtime_wg_go.so' if args.slot == 'stable' else 'libwg-go.so'
    strip = args.readelf.with_name('llvm-strip')
    for source, name in [(args.native, library), (args.tunnel, tunnel)]:
        target = payload / 'jni/arm64-v8a' / name; target.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([str(strip), '--strip-debug', '-o', str(target), str(source)], check=True)
    shutil.copytree(root / 'build', payload / 'webview')
    licenses = root / 'plugins/amneziawg-android-tunnel/build/generated/amneziawgLicenseAssets/licenses'
    shutil.copytree(licenses, payload / 'licenses')
    graph = json.loads(subprocess.run(['cargo', 'metadata', '--locked', '--offline', '--format-version', '1'], cwd=root, check=True, capture_output=True, text=True).stdout)
    tauri = next(Path(p['manifest_path']).parent for p in graph['packages'] if p['name'] == 'tauri')
    copy(tauri / 'LICENSE_APACHE-2.0', payload / 'licenses/TAURI-APACHE-2.0.txt')
    copy(tauri / 'LICENSE_MIT', payload / 'licenses/TAURI-MIT.txt')
    runtime = payload / 'runtime'; runtime.mkdir()
    if args.slot == 'stable':
        copy(root / 'plugins/stable-runtime-android/build/outputs/aar/stable-runtime-android-debug.aar', runtime / 'runtime.aar')
    else:
        with zipfile.ZipFile(runtime / 'latest-classes.zip', 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            app = root / 'src-tauri/gen/android/app/build/intermediates'
            archive.write(app / 'runtime_app_classes_jar/arm64Debug/bundleArm64DebugClassesToRuntimeJar/classes.jar', 'app.jar')
            archive.write(app / 'runtime_symbol_list/arm64Debug/processArm64DebugResources/R.txt', 'R.txt')
            archive.write(app / 'merged_manifests/arm64Debug/processArm64DebugManifest/AndroidManifest.xml', 'AndroidManifest.xml')
            libraries = [root / 'plugins' / name / 'android' for name in ('tunnel-android', 'push-android', 'updater-android')]
            libraries += [root / 'plugins/amneziawg-android-tunnel', tauri / 'mobile/android',
                next(Path(p['manifest_path']).parent for p in graph['packages'] if p['name'] == 'tauri-plugin-opener') / 'android']
            for index, directory in enumerate(libraries):
                archive.write(directory / 'build/intermediates/runtime_library_classes_jar/debug/bundleLibRuntimeToJarDebug/classes.jar', f'library-{index}.jar')
    index = []
    for path in sorted(payload.rglob('*')):
        if not path.is_file(): continue
        # Android's signed payload roles are data/shared libraries, not host
        # executables. Normalize before hashing/archiving, never after signing.
        path.chmod(0o644)
        name = path.relative_to(payload).as_posix(); data = path.read_bytes()
        index.append({'path':name, 'size_bytes':len(data), 'sha256':hashlib.sha256(data).hexdigest(),
            'role':'license' if name.startswith('licenses/') else 'shared_library' if name.endswith('.so') else 'resource'})
    manifest = {'format_version':1,'runtime_version':version,'source_commit':args.source_commit,'platform':'android','architecture':'aarch64','contract_version':1,'files':index}
    (output / 'runtime-manifest-v1.json').write_text(json.dumps(manifest, sort_keys=True, separators=(',', ':')))
    with zipfile.ZipFile(output / 'collision-input.zip', 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(payload.rglob('*')):
            if path.is_file(): archive.write(path, path.relative_to(payload))
    if args.local_test_container or args.container_signing_key:
        if args.container_signing_key:
            if args.container_signing_key.is_symlink() or args.container_signing_key.resolve().is_relative_to(output):
                raise ValueError('container signing key must be a regular file outside output')
            key = Ed25519PrivateKey.from_private_bytes(args.container_signing_key.read_bytes())
        else:
            key = Ed25519PrivateKey.generate()
            (output / 'LOCAL-TEST-KEY-NOT-FOR-RELEASE').write_bytes(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
        public = base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
        (output / ('test-public-key.b64' if args.local_test_container else 'container-public-key.b64')).write_text(public)
        container = {'format_version':1,'container_version':version,'release_set_id':'android-latest-' + args.source_commit,
            'minimum_runtime_contract':1,'maximum_runtime_contract':1,'slots':[{'slot':'latest','manifest':manifest}]}
        value = json.dumps(container, sort_keys=True, separators=(',', ':')).encode()
        resources = output / 'apk/assets/runtime'; resources.mkdir(parents=True)
        shutil.copytree(payload, resources / 'engines/latest' / version)
        (resources / 'container-manifest-v1.json').write_bytes(value)
        (resources / 'container-manifest-v1.sig').write_bytes(key.sign(b'nelomai-container-manifest-v1\0' + value))
        for path in (payload / 'jni/arm64-v8a').iterdir(): copy(path, output / 'apk/jniLibs/arm64-v8a' / path.name)
        subprocess.run([str(strip), '--strip-debug', '-o', str(output / 'apk/jniLibs/arm64-v8a/libnelomai_android_container.so'), str(args.host)], check=True)
        if args.local_test_container: print('Local verification trust key: ' + str(output / 'test-public-key.b64'))
    print(str(output))


if __name__ == '__main__': main()
