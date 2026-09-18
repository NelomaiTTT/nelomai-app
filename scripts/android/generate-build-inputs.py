#!/usr/bin/env python3
"""Generate ignored Tauri Gradle/Kotlin inputs from the locked Cargo graph.

This supports direct Gradle unit/manifest builds without a running Tauri CLI
session. It does not modify Cargo caches, source manifests, or signing inputs.
"""
import argparse
import json
from pathlib import Path
import subprocess


def generate(root):
    graph = json.loads(subprocess.run(['cargo', 'metadata', '--locked', '--offline', '--format-version', '1'], cwd=root, check=True, stdout=subprocess.PIPE, text=True).stdout)
    packages = {package['name']: Path(package['manifest_path']).parent for package in graph['packages']}
    android = root / 'src-tauri/gen/android'
    projects = {'tauri-android': packages['tauri'] / 'mobile/android'}
    for name in ('tauri-plugin-opener', 'tauri-plugin-tunnel-android', 'tauri-plugin-push-android', 'tauri-plugin-updater-android'):
        projects[name] = packages[name] / 'android'
    lines = ['// Generated from cargo metadata --locked; do not edit.']
    for name, path in projects.items():
        if not (path / 'build.gradle.kts').is_file():
            raise ValueError('missing locked Android library: ' + name)
        lines += [f"include ':{name}'", f"project(':{name}').projectDir = new File({json.dumps(str(path))})"]
    (android / 'tauri.settings.gradle').write_text('\n'.join(lines) + '\n')
    (android / 'app/tauri.build.gradle.kts').write_text('dependencies {\n' + ''.join(f'    add("implementation", project(":{name}"))\n' for name in projects) + '}\n')
    # tauri/build.rs normally emits this outside android-codegen. Direct Gradle
    # packaging skips that build script but still needs its Rust/JNI keep rules.
    rules = (packages['tauri'] / 'mobile/proguard-tauri.pro').read_text()
    (android / 'app/proguard-tauri.pro').write_text(rules.replace('$PACKAGE', 'ru.nelomai.client'))
    output = android / 'app/src/main/java/ru/nelomai/client/generated'
    output.mkdir(parents=True, exist_ok=True)
    for source in (packages['tauri'] / 'mobile/android-codegen', packages['wry'] / 'src/android/kotlin'):
        for file in source.iterdir():
            if file.suffix not in ('.kt', '.pro'):
                continue
            value = file.read_text()
            for key, replacement in {'package': 'ru.nelomai.client', 'package-unescaped': 'ru.nelomai.client', 'library': 'nelomai_app_lib', 'class-extension': '', 'class-init': ''}.items():
                value = value.replace('{{' + key + '}}', replacement)
            if '{{' in value:
                raise ValueError('unknown Kotlin generator placeholder')
            (output / file.name).write_text(value)
    return projects


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    generate(args.root.resolve())
