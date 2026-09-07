import subprocess
import sys
from scripts.tests.test_runtime_artifact import ArtifactFixture, SCRIPTS, module


class ReleasePlatformTest(ArtifactFixture):
    def test_native_draft_cli_never_accepts_a_release_private_key(self):
        result = subprocess.run([sys.executable, str(SCRIPTS / "build-release-platform.py"),
            "--platform", "linux", "--architecture", "x86_64", "--source-sha", "a" * 40,
            "--mode", "build_only", "--public-key", str(self.public), "--output", str(self.root / "output"),
            "--work", str(self.root / "work"), "--signing-key", str(self.keyfile)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrecognized arguments: --signing-key", result.stderr)
        self.assertFalse((self.root / "work").exists())

    def test_build_trust_rejects_promotion_and_mismatched_key_before_building(self):
        self.assertTrue((SCRIPTS / "build-release-platform.py").is_file(), "platform build consumer is missing")
        builder = module("build-release-platform")
        self.assertEqual(builder.build_trust("build_only", self.keyfile, self.public)["trust"], "test")
        with self.assertRaisesRegex(ValueError, "forbidden"):
            builder.build_trust("publish_approved_candidate", self.keyfile, self.public)
        self.public.write_bytes(bytes(32))
        with self.assertRaisesRegex(ValueError, "trust"):
            builder.build_trust("build_only", self.keyfile, self.public)
