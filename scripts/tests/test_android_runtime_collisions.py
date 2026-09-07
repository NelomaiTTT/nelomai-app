"""Acceptance checks consume compiled class/ELF bytes, not declared inventories."""
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
NDK = Path('/opt/homebrew/share/android-commandlinetools/ndk/28.2.13676358/toolchains/llvm/prebuilt/darwin-x86_64/bin')
JAVAC = Path('/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home/bin/javac')


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts/android' / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def archive(entries):
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as output:
        for name, value in entries.items():
            output.writestr(name, value)
    return data.getvalue()


class CollisionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.check = module('check-runtime-collisions')
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.classes = {}
        for package in ('latest', 'stable'):
            source = cls.root / package / 'Engine.java'
            source.parent.mkdir()
            source.write_text(f'package ru.nelomai.{package}; public class Engine {{ public native void start(); }}')
            subprocess.run([str(JAVAC), '-d', str(source.parent), str(source)], check=True, capture_output=True)
            cls.classes[package] = (source.parent / f'ru/nelomai/{package}/Engine.class').read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def aar(self, package, **overrides):
        values = {
            'classes.jar': archive({f'ru/nelomai/{package}/Engine.class': self.classes[package]}),
            'R.txt': f'int string {package}_runtime_title 0x0\n',
            'AndroidManifest.xml': f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="ru.nelomai.{package}"><application><activity android:name=".EngineActivity" android:exported="false"/></application></manifest>',
        }
        values.update(overrides)
        return archive(values)

    def inventory(self, payload):
        return self.check.inspect_archive(payload, readelf=NDK / 'llvm-readelf')

    def test_distinct_compiled_classes_resources_and_components_pass(self):
        self.assertEqual(self.check.collisions(self.inventory(self.aar('latest')), self.inventory(self.aar('stable'))), {})

    def test_duplicate_class_uses_bytecode_identity_not_zip_entry(self):
        disguised = self.aar('stable', **{'classes.jar': archive({'unrelated.class': self.classes['latest']})})
        with self.assertRaisesRegex(ValueError, 'class.*path'):
            self.inventory(disguised)

    def test_reports_all_conflict_categories(self):
        own = self.inventory(self.aar('latest'))
        conflicts = self.check.collisions(own, own)
        self.assertEqual(set(conflicts), {'classes', 'resources', 'components'})
        self.assertEqual(conflicts['classes'], ['ru.nelomai.latest.Engine'])

    def test_nested_archive_path_traversal_is_rejected(self):
        payload = self.aar('latest', **{'libs/helper.jar': archive({'../escape.class': self.classes['latest']})})
        with self.assertRaisesRegex(ValueError, 'path'):
            self.inventory(payload)

    def test_nested_apk_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'APK'):
            self.inventory(self.aar('latest', **{'assets/hidden.apk': b'not an embeddable runtime'}))

    def test_compiled_elf_soname_library_and_jni_conflicts(self):
        source = self.root / 'engine.c'
        source.write_text('void Java_ru_nelomai_engine_start(void) {}\nint nelomai_runtime_v1(void) { return 1; }\n')
        output = self.root / 'libengine.so'
        subprocess.run([str(NDK / 'aarch64-linux-android24-clang'), '-shared', '-nostdlib', '-Wl,-soname,libengine.so', str(source), '-o', str(output)], check=True, capture_output=True)
        own = self.inventory(archive({'jni/arm64-v8a/libengine.so': output.read_bytes()}))
        conflicts = self.check.collisions(own, own)
        self.assertEqual(conflicts['native_libraries'], ['arm64-v8a/libengine.so'])
        self.assertEqual(conflicts['sonames'], ['arm64-v8a/libengine.so'])
        self.assertEqual(conflicts['jni_exports'], ['Java_ru_nelomai_engine_start'])

    def test_stable_native_admission_requires_actual_versioned_entrypoint(self):
        builder = module('build-runtime-artifact')
        source = self.root / 'abi.c'
        output = self.root / 'libnelomai_runtime_stable.so'
        for abi, accepted in [('', False), ('int nelomai_runtime_v1(void) { return 1; }', True)]:
            source.write_text('void Java_ru_nelomai_runtime_stable_RuntimeEntrypoint_attach(void) {}\n' + abi)
            subprocess.run([str(NDK / 'aarch64-linux-android24-clang'), '-shared', '-nostdlib', '-Wl,-soname,libnelomai_runtime_stable.so', str(source), '-o', str(output)], check=True, capture_output=True)
            if accepted:
                builder.verify_runtime_abi(output, NDK / 'llvm-readelf')
            else:
                with self.assertRaisesRegex(ValueError, 'ABI'):
                    builder.verify_runtime_abi(output, NDK / 'llvm-readelf')


if __name__ == '__main__':
    unittest.main()
