"""NDK host selection must not send Linux builders to the macOS toolchain."""
from pathlib import Path
import tempfile
import unittest

from scripts.tests.test_runtime_artifact import module


class TunnelHostTest(unittest.TestCase):
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
