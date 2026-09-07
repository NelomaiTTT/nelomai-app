#!/usr/bin/env python3
"""Compile-time namespace/resource relocation for the immutable stable AAR.

Only generated source is transformed. Published runtime artifacts are never
renamed, patched, resigned or rebuilt by a future embedding container.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

NAMESPACE = 'ru.nelomai.runtime.stable'
PREFIX = 'stable_runtime_'


def packages(root):
    graph = json.loads(subprocess.run(['cargo', 'metadata', '--locked', '--offline', '--format-version', '1'], cwd=root, check=True, capture_output=True, text=True).stdout)
    return {package['name']: Path(package['manifest_path']).parent for package in graph['packages']}


def generate(root, output):
    deps = packages(root)
    output.mkdir(parents=True, exist_ok=True)
    java = output / 'java'
    java.mkdir(exist_ok=True)
    resources = output / 'res'
    resources.mkdir(exist_ok=True)
    app = root / 'src-tauri/gen/android/app/src/main'
    replacements = {
        'ru.nelomai.client': NAMESPACE,
        'ru.nelomai.tunnel': NAMESPACE + '.tunnel',
        'ru.nelomai.push': NAMESPACE + '.push',
        'ru.nelomai.updater': NAMESPACE + '.updater',
        'org.amnezia.awg': NAMESPACE + '.awg',
        'app.tauri': NAMESPACE + '.tauri',
        'io.crates.keyring': NAMESPACE + '.keyring',
    }
    source_dirs = [root / f'plugins/{name}/android/src/main/java' for name in ('tunnel-android', 'push-android', 'updater-android')]
    source_dirs += [deps['tauri'] / 'mobile/android/src/main/java', deps['tauri-plugin-opener'] / 'android/src/main/java']
    source_dirs += [root / 'plugins/amneziawg-android-tunnel/build/generated/runtimeHostJava', app / 'java/ru/nelomai/client/generated']
    selected = [app / 'java/ru/nelomai/client' / name for name in ('LatestRuntimeActivity.kt', 'StartupDiagnostics.kt', 'RuntimeEntrypoint.kt')]
    selected += [app / 'java/io/crates/keyring/Keyring.kt']
    for source in source_dirs:
        selected.extend(path for path in source.rglob('*') if path.suffix in ('.kt', '.java'))
    if not any(path.name == 'GoBackend.java' for path in selected):
        raise ValueError('generated versioned GoBackend source is missing')
    resource_dirs = [app / 'res'] + [root / f'plugins/{name}/android/src/main/res' for name in ('tunnel-android', 'push-android', 'updater-android')]
    resource_names = set()
    for source in resource_dirs:
        for file in source.rglob('*'):
            if not file.is_file(): continue
            if file.parent.name.startswith('values'):
                tree = ET.fromstring(file.read_bytes())
                resource_names.update(node.get('name') for node in tree if node.get('name'))
            else:
                resource_names.add(file.stem)

    def transform(value):
        for before, after in replacements.items():
            value = value.replace(before, after)
        value = value.replace(NAMESPACE + '.RuntimeSelectionStore', 'ru.nelomai.client.RuntimeSelectionStore')
        value = value.replace('nelomai_app_lib', 'nelomai_runtime_stable')
        for before, after in [('"wg-go"', '"stable_runtime_wg_go"'), ('"wg"', '"stable_runtime_wg"'), ('"wg-quick"', '"stable_runtime_wg_quick"')]:
            value = value.replace(before, after)
        # All generated code owns one stable resource namespace.
        value = re.sub(r'ru\.nelomai\.runtime\.stable(?:\.[A-Za-z0-9_]+)*\.(R|BuildConfig)\b', NAMESPACE + r'.\1', value)
        for name in sorted(resource_names, key=len, reverse=True):
            escaped = re.escape(name)
            value = re.sub(r'(@(?:\+)?[a-z_]+/)' + escaped + r'(?=["\s<])', r'\1' + PREFIX + name, value)
            value = value.replace('name="' + name + '"', 'name="' + PREFIX + name + '"')
            value = re.sub(r'(R\.[a-z_]+\.)' + re.escape(name.replace('.', '_')) + r'\b', r'\1' + PREFIX + name.replace('.', '_'), value)
        return value

    for file in selected:
        value = transform(file.read_text())
        match = re.search(r'^package\s+([\w.]+)', value, re.MULTILINE)
        if not match or not match[1].startswith(NAMESPACE):
            raise ValueError('unrelocated stable source package')
        package = match[1]
        imports = [NAMESPACE + '.R', NAMESPACE + '.BuildConfig']
        if file.name == 'RuntimeEntrypoint.kt':
            imports += ['ru.nelomai.client.RuntimeSelectionCodec', 'ru.nelomai.client.RuntimeProcessSelection', 'ru.nelomai.client.RuntimeDispatchPolicy']
        addition = ''.join('\nimport ' + name + (';' if file.suffix == '.java' else '') for name in imports if 'import ' + name not in value)
        end = value.find('\n', match.end())
        value = value[:end] + '\n' + addition + value[end:]
        target = java / package.replace('.', '/') / file.name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value)
    for source in resource_dirs:
        for file in source.rglob('*'):
            if not file.is_file(): continue
            name = file.name if file.parent.name.startswith('values') else PREFIX + file.name
            target = resources / file.parent.name / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if file.suffix == '.xml': target.write_text(transform(file.read_text()))
            else: shutil.copyfile(file, target)
    manifest = f'''<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application>
<activity android:name="{NAMESPACE}.LatestRuntimeActivity" android:exported="false" android:process=":runtime" android:launchMode="singleTask" android:configChanges="orientation|keyboardHidden|keyboard|screenSize|locale|smallestScreenSize|screenLayout|uiMode"/>
<service android:name="{NAMESPACE}.tunnel.AutomaticDiagnosticsJobService" android:exported="false" android:permission="android.permission.BIND_JOB_SERVICE" android:process=":vpn"/>
</application></manifest>'''
    (output / 'AndroidManifest.xml').write_text(manifest)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    generate(args.root.resolve(), args.output.resolve())
