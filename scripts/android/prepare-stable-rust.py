#!/usr/bin/env python3
"""Generate an isolated stable Rust source variant, including JNI dependency code.

Cargo registry/vendor inputs remain untouched. Build-only transformations occur
before compilation and are never applied to a published stable artifact.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess


def prepare(root, output):
    if output.exists():
        raise ValueError('stable source destination already exists; use a fresh build directory')
    graph = json.loads(subprocess.run(['cargo', 'metadata', '--locked', '--offline', '--format-version', '1'], cwd=root, check=True, capture_output=True, text=True).stdout)
    packages = {p['name']: Path(p['manifest_path']).parent for p in graph['packages']}
    output.mkdir(parents=True)
    # Copy only build inputs, never target/SDK/dependency caches or signing files.
    for name in ('crates', 'plugins', 'src-tauri', 'spikes', 'build'):
        shutil.copytree(root / name, output / name,
            ignore=shutil.ignore_patterns('target', 'build', '.gradle', '.kotlin', '.cxx', 'node_modules', '*.so', '*.keystore', 'keystore.properties', 'local.properties'),
            dirs_exist_ok=True)
    # Frontend build is an input, not the excluded Gradle build directory.
    shutil.copytree(root / 'build', output / 'build', dirs_exist_ok=True)
    for name in ('Cargo.toml', 'Cargo.lock'):
        shutil.copyfile(root / name, output / name)
    rewrites = {
        'ru.nelomai.client': 'ru.nelomai.runtime.stable',
        'ru.nelomai.tunnel': 'ru.nelomai.runtime.stable.tunnel',
        'ru.nelomai.push': 'ru.nelomai.runtime.stable.push',
        'ru.nelomai.updater': 'ru.nelomai.runtime.stable.updater',
        'Java_ru_nelomai_client_': 'Java_ru_nelomai_runtime_stable_',
        'app.tauri': 'ru.nelomai.runtime.stable.tauri',
        'app/tauri': 'ru/nelomai/runtime/stable/tauri',
        'app_tauri': 'ru_nelomai_runtime_stable_tauri',
        'Java_io_crates_keyring_': 'Java_ru_nelomai_runtime_stable_keyring_',
    }
    cached = output / 'stable-dependencies'
    cached.mkdir()
    patch_lines = []
    for name in ('tauri', 'tauri-plugin-opener', 'android-native-keyring-store'):
        target = cached / name
        shutil.copytree(packages[name], target)
        patch_lines.append(f'{name} = {{ path = "stable-dependencies/{name}" }}')
    for directory in (output / 'src-tauri/src', output / 'plugins', cached):
        for file in directory.rglob('*.rs'):
            value = file.read_text()
            for before, after in rewrites.items(): value = value.replace(before, after)
            file.write_text(value)
    manifest = output / 'Cargo.toml'
    manifest.write_text(manifest.read_text() + '\n[patch.crates-io]\n' + '\n'.join(patch_lines) + '\n')
    manifest = output / 'src-tauri/Cargo.toml'
    value = manifest.read_text().replace('name = "nelomai_app_lib"', 'name = "nelomai_runtime_stable"')
    manifest.write_text(value)
    config_file = output / 'src-tauri/tauri.conf.json'
    config = json.loads(config_file.read_text())
    config['identifier'] = 'ru.nelomai.runtime.stable'
    config_file.write_text(json.dumps(config, indent=2) + '\n')
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    prepare(args.root.resolve(), args.output.resolve())
