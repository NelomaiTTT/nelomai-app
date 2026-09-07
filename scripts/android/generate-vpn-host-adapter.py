#!/usr/bin/env python3
"""Generate the bundled GoBackend host adapter without editing vendor checkouts.

Inputs are vendor HEAD plus the two tracked parent Java patches. Working-tree
vendor mutations and build caches are neither used as source nor overwritten.
"""
import argparse
import io
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('GoBackend host adaptation no longer matches vendor source')
    return text.replace(before, after)


def generate(root, output):
    vendor = root / 'vendor/amneziawg-android'
    payload = subprocess.run(['git', '-C', str(vendor), 'archive', 'HEAD'], check=True, capture_output=True).stdout
    with tempfile.TemporaryDirectory(prefix='nelomai-vpn-host-') as temporary:
        staged = Path(temporary)
        with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
            archive.extractall(staged, filter='data')
        for name in ('amneziawg-android-network-telemetry.patch', 'amneziawg-android-memory-diagnostics.patch'):
            subprocess.run(['git', 'apply', str(root / 'patches' / name)], cwd=staged, check=True, capture_output=True)
        source = staged / 'tunnel/src/main/java'
        backend = source / 'org/amnezia/awg/backend/GoBackend.java'
        value = backend.read_text()
        value = replace_once(value, 'context.startService(new Intent(context, VpnService.class));',
                             'context.startService(ru.nelomai.runtime.v1.RuntimeServiceIntents.vpn(context));')
        value = replace_once(value, 'final VpnService.Builder builder = service.getBuilder();',
                             'final android.net.VpnService.Builder builder = service.getBuilder();')
        value = replace_once(value, 'public static class VpnService extends android.net.VpnService {',
                             'public static class VpnService extends ru.nelomai.runtime.v1.RuntimeVpnServiceAdapter {\n        public VpnService(android.net.VpnService host) { super(host); }')
        value = replace_once(value, 'public Builder getBuilder() {\n            return new Builder();\n        }',
                             'public android.net.VpnService.Builder getBuilder() {\n            return super.getBuilder();\n        }')
        backend.write_text(value)
        output.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, output, dirs_exist_ok=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    generate(args.root.resolve(), args.output.resolve())
