#!/usr/bin/env python3
"""Check the actual packaged DEX, native payload and decoded APK manifest."""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET
import zipfile
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ANDROID = '{http://schemas.android.com/apk/res/android}'


def verify_signature(value, signature, public_key):
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, b'nelomai-container-manifest-v1\0' + value)
    except (ValueError, InvalidSignature) as error:
        raise ValueError('APK container signature is invalid') from error
    canonical = json.dumps(json.loads(value), sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    if canonical != value: raise ValueError('APK container signature binds noncanonical JSON')


def verify_version(xml, version):
    if not isinstance(version, str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        raise ValueError('APK release version must be major.minor.patch')
    major, minor, patch = map(int, version.split('.'))
    code = major * 1_000_000 + minor * 1_000 + patch
    if minor > 999 or patch > 999 or not 0 < code <= 2_100_000_000:
        raise ValueError('APK release version exceeds Android versionCode range')
    manifest = ET.fromstring(xml)
    if (manifest.get(ANDROID + 'versionName') != version
            or manifest.get(ANDROID + 'versionCode') != str(code)):
        raise ValueError(f'APK version must be {version} / versionCode {code}')


def verify_manifest(xml, acceptance=False):
    manifest = ET.fromstring(xml)
    package = manifest.get('package')
    if package != 'ru.nelomai.client':
        raise ValueError('unexpected common application ID')
    components = {}
    for item in manifest.findall('./application/*'):
        name = item.get(ANDROID + 'name', '')
        if name.startswith('.'): name = package + name
        components[name] = item
    vpns = [item for item in components.values() if item.tag == 'service' and
        (item.get(ANDROID + 'permission') == 'android.permission.BIND_VPN_SERVICE' or
         any(action.get(ANDROID + 'name') == 'android.net.VpnService' for action in item.findall('./intent-filter/action')))]
    vpn = components.get('ru.nelomai.client.RuntimeVpnDispatcherService')
    if len(vpns) != 1 or vpns[0] is not vpn or vpn.get(ANDROID + 'exported') != 'false' or vpn.get(ANDROID + 'process') != ':vpn' or vpn.get(ANDROID + 'permission') != 'android.permission.BIND_VPN_SERVICE':
        raise ValueError('APK must have one non-exported common VPN service')
    broker = components.get('ru.nelomai.client.RuntimeAuthBrokerService')
    if broker is None or broker.get(ANDROID + 'exported') != 'false' or broker.findall('intent-filter'):
        raise ValueError('APK broker must be explicit and non-exported')
    runtime = components.get('ru.nelomai.client.LatestRuntimeActivity')
    if runtime is None or runtime.get(ANDROID + 'exported') != 'false' or runtime.get(ANDROID + 'process') != ':runtime':
        raise ValueError('APK runtime Activity must be private and isolated')
    lifecycle = components.get('androidx.startup.InitializationProvider')
    if (lifecycle is None or lifecycle.tag != 'provider'
            or lifecycle.get(ANDROID + 'process') != ':runtime'
            or lifecycle.get(ANDROID + 'exported') != 'false'
            or not any(item.get(ANDROID + 'name') == 'androidx.lifecycle.ProcessLifecycleInitializer'
                       and item.get(ANDROID + 'value') == 'androidx.startup'
                       for item in lifecycle.findall('meta-data'))):
        raise ValueError('APK runtime lifecycle initializer must run in the UI process')
    stable = components.get('ru.nelomai.runtime.stable.LatestRuntimeActivity')
    if acceptance:
        if stable is None or stable.get(ANDROID + 'exported') != 'false' or stable.get(ANDROID + 'process') != ':runtime':
            raise ValueError('acceptance APK stable Activity must be private and isolated')
    elif any(name.startswith('ru.nelomai.runtime.stable.') for name in components):
        raise ValueError('0.2.17 shipping manifest must be latest-only')


def verify_classes(classes, acceptance=False):
    required = {'ru.nelomai.client.MainActivity', 'ru.nelomai.client.RuntimeAuthBrokerService',
        'ru.nelomai.client.RuntimeVpnDispatcherService', 'ru.nelomai.client.LatestRuntimeActivity',
        'ru.nelomai.tunnel.LatestRuntimeVpnEngineV1',
        'ru.nelomai.tunnel.LatestRuntimeQuickActionsV1', 'ru.nelomai.tunnel.LatestRuntimeStorageV1',
        'ru.nelomai.tunnel.LatestRuntimeNativeBridgeV1', 'ru.nelomai.client.RuntimeNativeCallbacks',
        'ru.nelomai.client.RuntimeNativeHost', 'ru.nelomai.client.RuntimeEntrypoint'}
    if not required <= classes:
        raise ValueError('APK omits compiled dispatcher/runtime classes: ' + ', '.join(sorted(required - classes)))
    stable = {'ru.nelomai.runtime.stable.LatestRuntimeActivity', 'ru.nelomai.runtime.stable.RuntimeEntrypoint',
        'ru.nelomai.runtime.stable.tunnel.LatestRuntimeVpnEngineV1',
        'ru.nelomai.runtime.stable.tunnel.LatestRuntimeQuickActionsV1',
        'ru.nelomai.runtime.stable.tunnel.LatestRuntimeStorageV1',
        'ru.nelomai.runtime.stable.tunnel.LatestRuntimeNativeBridgeV1'}
    if acceptance:
        if not stable <= classes:
            raise ValueError('acceptance APK omits compiled stable entrypoints: ' + ', '.join(sorted(stable - classes)))
    elif any(name.startswith('ru.nelomai.runtime.stable.') for name in classes):
        raise ValueError('0.2.17 container must be latest-only')


def verify_slots(manifest, acceptance=False, root_digest=None, stable_digest=None):
    slots = manifest['slots']
    if not acceptance:
        if [slot['slot'] for slot in slots] != ['latest']:
            raise ValueError('0.2.17 container must index only latest')
        return
    if (not all(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value)
                for value in (root_digest, stable_digest))
            or manifest.get('stable_release_set_sha256') != root_digest
            or manifest.get('stable_platform_manifest_sha256') != stable_digest
            or [(slot['slot'], slot['manifest']['runtime_version']) for slot in slots]
               != [('latest', '0.2.18'), ('stable', '0.2.17')]):
        raise ValueError('acceptance APK does not bind exact approved stable/root identities')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--apkanalyzer', type=Path, required=True)
    parser.add_argument('--public-key', type=Path, required=True, help='Pinned raw 32-byte or base64 Ed25519 public key')
    parser.add_argument('--acceptance', action='store_true', help='Separate two-slot test package only; never shipping 0.2.17')
    parser.add_argument('--release-set-sha256')
    parser.add_argument('--stable-manifest-sha256')
    args = parser.parse_args()
    xml = subprocess.run([str(args.apkanalyzer), 'manifest', 'print', str(args.apk)], check=True, capture_output=True, text=True).stdout
    verify_manifest(xml, args.acceptance)
    # Called from Rust/JNI, invisible to R8's Java reachability analysis.
    # Inspect the final DEX, not merely the presence of a ProGuard source rule.
    subprocess.run([str(args.apkanalyzer), 'dex', 'code', '--class',
                    'ru.nelomai.client.TauriActivity', '--method',
                    'getPluginManager()Lapp/tauri/plugin/PluginManager;',
                    str(args.apk)], check=True, capture_output=True, text=True)
    spec = importlib.util.spec_from_file_location('collisions', Path(__file__).with_name('check-runtime-collisions.py'))
    check = importlib.util.module_from_spec(spec); spec.loader.exec_module(check)
    classes = set()
    with zipfile.ZipFile(args.apk) as apk:
        for name in apk.namelist():
            if name.endswith('.dex'):
                for value in check.dex_classes(apk.read(name)):
                    if value in classes: raise ValueError('duplicate APK DEX class')
                    classes.add(value)
        verify_classes(classes, args.acceptance)
        value = apk.read('assets/runtime/container-manifest-v1.json')
        public = args.public_key.read_bytes()
        if len(public) != 32: public = base64.b64decode(public.strip(), validate=True)
        verify_signature(value, apk.read('assets/runtime/container-manifest-v1.sig'), public)
        manifest = json.loads(value)
        verify_version(xml, manifest['container_version'])
        verify_slots(manifest, args.acceptance, args.release_set_sha256, args.stable_manifest_sha256)
        for slot in manifest['slots']:
            prefix = 'assets/runtime/engines/' + slot['slot'] + '/' + slot['manifest']['runtime_version'] + '/'
            for item in slot['manifest']['files']:
                data = apk.read(prefix + item['path'])
                if len(data) != item['size_bytes'] or hashlib.sha256(data).hexdigest() != item['sha256']:
                    raise ValueError('APK runtime payload differs from signed index')
                if item['path'].endswith('.so') and data != apk.read('lib/arm64-v8a/' + Path(item['path']).name):
                    raise ValueError('APK loaded ELF differs from indexed ELF')
        if 'lib/arm64-v8a/libnelomai_android_container.so' not in apk.namelist():
            raise ValueError('APK common native host is missing')
    print(json.dumps({'dex_classes': len(classes), 'vpn_services': 1,
        'runtime_slots': ['latest', 'stable'] if args.acceptance else ['latest'], 'payload_hashes': 'verified'}, sort_keys=True))


if __name__ == '__main__': main()
