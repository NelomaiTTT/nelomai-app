#!/usr/bin/env python3
"""Build ARM64 Go/JNI tunnel from pinned vendor revisions and parent patches.

The caller supplies an already cached Go archive. No toolchain downloads,
vendor checkout edits, live installs, signing, or release writes occur here.
"""
import argparse
import io
import os
from pathlib import Path
import platform
import subprocess
import tarfile


def ndk_compiler(ndk, system=None):
    tag = {'Linux': 'linux-x86_64', 'Darwin': 'darwin-x86_64'}.get(system or platform.system())
    if tag is None:
        raise ValueError('unsupported Android tunnel build host')
    compiler = ndk / 'toolchains/llvm/prebuilt' / tag / 'bin/aarch64-linux-android24-clang'
    if not compiler.is_file() or not os.access(compiler, os.X_OK):
        raise ValueError('Android NDK host compiler is missing or not executable')
    return compiler


def vendor(root, name, output, patches):
    value = subprocess.run(['git', '-C', str(root / 'vendor' / name), 'archive', 'HEAD'], check=True, capture_output=True).stdout
    output.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(value)) as archive:
        archive.extractall(output, filter='data')
    for patch in patches:
        subprocess.run(['git', 'apply', str(root / 'patches' / patch)], cwd=output, check=True, capture_output=True)


def build(root, output, ndk, go_archive, slot):
    if output.exists(): raise ValueError('native build output already exists')
    compiler = ndk_compiler(ndk)
    output.mkdir(parents=True)
    source = output / 'source'
    android = source / 'amneziawg-android'
    vendor(root, 'amneziawg-android', android, ['amneziawg-android-network-telemetry.patch', 'amneziawg-android-memory-diagnostics.patch'])
    vendor(root, 'amneziawg-go', source / 'amneziawg-go', ['amneziawg-go-network-recovery.patch', 'amneziawg-go-android-memory.patch'])
    bridge = android / 'tunnel/tools/libwg-go'
    with tarfile.open(go_archive) as archive:
        archive.extractall(output / 'toolchain', filter='data')
    go_root = output / 'toolchain/go'
    subprocess.run(['git', 'apply', '--include=src/runtime/sys_linux_arm64.s', str(bridge / 'goruntime-boottime-over-monotonic.diff')], cwd=go_root, check=True, capture_output=True)
    name = 'libstable_runtime_wg_go.so' if slot == 'stable' else 'libwg-go.so'
    if slot == 'stable':
        jni = bridge / 'jni.c'
        jni.write_text(jni.read_text().replace('Java_org_amnezia_awg_', 'Java_ru_nelomai_runtime_stable_awg_'))
    module = bridge / 'go.mod'
    module.write_text(module.read_text() + '\nreplace github.com/amnezia-vpn/amneziawg-go/v3 => ../../../../amneziawg-go\n')
    environment = os.environ.copy()
    environment.update({'GOOS':'android', 'GOARCH':'arm64', 'CGO_ENABLED':'1', 'GOTOOLCHAIN':'local', 'GOWORK':'off',
        'GOROOT':str(go_root), 'CC':str(compiler),
        'CGO_CFLAGS':'-O2', 'CGO_LDFLAGS':'-Wl,-z,max-page-size=16384 -Wl,-soname,' + name})
    destination = output / 'jni/arm64-v8a'
    destination.mkdir(parents=True)
    subprocess.run([str(go_root / 'bin/go'), 'build', '-tags', 'linux', '-ldflags=-s -w -buildid=',
        '-trimpath', '-buildvcs=false', '-o', str(destination / name), '-buildmode=c-shared'],
        cwd=bridge, env=environment, check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ndk', type=Path, required=True)
    parser.add_argument('--go-archive', type=Path, required=True)
    parser.add_argument('--slot', choices=('latest', 'stable'), required=True)
    args = parser.parse_args()
    build(args.root.resolve(), args.output.resolve(), args.ndk.resolve(), args.go_archive.resolve(), args.slot)
