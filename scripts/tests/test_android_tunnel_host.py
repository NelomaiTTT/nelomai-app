"""NDK host selection must not send Linux builders to the macOS toolchain."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from scripts.tests.test_runtime_artifact import ROOT, module
from scripts.tests import test_android_runtime_collisions as fixtures


class TunnelHostTest(unittest.TestCase):
    def test_stable_tunnel_namespaces_every_redundant_jni_export(self):
        builder = module("android/build-tunnel-runtime")
        patch = (ROOT / "patches/amneziawg-android-network-telemetry.patch").read_text()
        names = sorted(set(re.findall(r'Java_ru_nelomai_tunnel_JniRedundantNativeApi_\w+', patch)))
        self.assertEqual(len(names), 12)
        names.append('Java_org_amnezia_awg_GoBackend_awgTurnOn')
        source = '\n'.join('void ' + name + '(void) {}' for name in names)
        rewritten = builder.stable_jni_source(source)
        ndk, _ = fixtures.native_tools()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            library = root / 'stable.so'
            subprocess.run([str(ndk / 'aarch64-linux-android24-clang'), '-shared', '-nostdlib',
                '-x', 'c', '-', '-o', str(library)], input=rewritten, text=True, check=True, capture_output=True)
            symbols = subprocess.run([str(ndk / 'llvm-readelf'), '--dyn-syms', '--wide', str(library)],
                check=True, capture_output=True, text=True).stdout
            self.assertNotIn('Java_ru_nelomai_tunnel_', symbols)
            self.assertNotIn('Java_org_amnezia_awg_', symbols)
            for name in names:
                expected = name.replace('Java_ru_nelomai_tunnel_', 'Java_ru_nelomai_runtime_stable_tunnel_').replace(
                    'Java_org_amnezia_awg_', 'Java_ru_nelomai_runtime_stable_awg_')
                self.assertIn(expected, symbols)

    def test_native_fixtures_resolve_explicit_jdk_and_ndk_for_both_hosts(self):
        resolve = getattr(fixtures, "native_tools", None)
        self.assertTrue(callable(resolve), "compiled fixture toolchain still assumes a Homebrew host")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            java = root / "jdk/bin/javac"
            java.parent.mkdir(parents=True)
            java.write_text("fixture")
            java.chmod(0o755)
            for system, tag in (("Linux", "linux-x86_64"), ("Darwin", "darwin-x86_64")):
                tools = root / "ndk/toolchains/llvm/prebuilt" / tag / "bin"
                tools.mkdir(parents=True)
                for name in ("aarch64-linux-android24-clang", "llvm-readelf"):
                    path = tools / name
                    path.write_text("fixture")
                    path.chmod(0o755)
                self.assertEqual(resolve({"JAVA_HOME": str(root / "jdk"), "ANDROID_NDK_HOME": str(root / "ndk")}, system),
                                 (tools, java))
            with self.assertRaisesRegex(ValueError, "JAVA_HOME|NDK"):
                resolve({}, "Linux")
            java.unlink()
            with self.assertRaisesRegex(ValueError, "javac"):
                resolve({"JAVA_HOME": str(root / "jdk"), "NDK_HOME": str(root / "ndk")}, "Linux")

    def test_resolves_existing_linux_and_macos_compilers(self):
        builder = module("android/build-tunnel-runtime")
        self.assertTrue(callable(getattr(builder, "ndk_compiler", None)), "host-aware NDK selection is missing")
        with tempfile.TemporaryDirectory() as directory:
            ndk = Path(directory)
            for system, tag in (("Linux", "linux-x86_64"), ("Darwin", "darwin-x86_64")):
                compiler = ndk / "toolchains/llvm/prebuilt" / tag / "bin/aarch64-linux-android24-clang"
                compiler.parent.mkdir(parents=True)
                compiler.write_text("toolchain fixture")
                compiler.chmod(0o755)
                self.assertEqual(builder.ndk_compiler(ndk, system), compiler)
            with self.assertRaisesRegex(ValueError, "unsupported"):
                builder.ndk_compiler(ndk, "Windows")
            with self.assertRaisesRegex(ValueError, "compiler"):
                builder.ndk_compiler(ndk / "missing", "Linux")


if __name__ == "__main__":
    unittest.main()
