"""Android-only release uses the real signed root and exact asset gates."""
import json
import shutil
import subprocess

from scripts.tests.test_runtime_artifact import ArtifactFixture, SOURCE, module
import scripts.tests.test_runtime_release_set as fixtures
import scripts.tests.test_runtime_candidate_signing as signing_fixtures


class AndroidReleaseScopeTest(ArtifactFixture):
    def test_desktop_staging_rejects_android_root_without_fallback_or_output(self):
        drafts = signing_fixtures.RuntimeCandidateSigningTest.drafts(self)
        for path in drafts.iterdir():
            if path.name != "android":
                shutil.rmtree(path)
        signer = module("sign-runtime-candidate")
        signed = self.root / "signed"
        digest = signer.sign(drafts, signed, SOURCE, self.keyfile, self.public, scope="android")
        stage = module("build-runtime-acceptance-container")
        for scope in ("all", "android"):
            for platform, arch in (("linux", "x86_64"), ("windows", "x86_64"), ("macos", "aarch64")):
                with self.subTest(scope=scope, platform=platform):
                    output = self.root / (scope + platform)
                    with self.assertRaises((ValueError, FileNotFoundError, subprocess.CalledProcessError)):
                        stage.stage_signed(signed, digest, output, self.public, platform, arch,
                                           SOURCE, "shipping", scope=scope)
                    self.assertFalse(output.exists())

    def test_signed_android_root_requires_explicit_scope_and_rejects_extra_target(self):
        aggregate = module("build-runtime-release-set")
        full = fixtures.RuntimeReleaseSetTest.four_candidates(self)
        with self.assertRaises(ValueError):
            aggregate.build(full, self.root / "full-rejected", "0.2.20", SOURCE,
                            self.keyfile, self.public, scope="android")
        android = self.root / "android"
        android.mkdir()
        for path in full.glob("*-android-aarch64.*"):
            shutil.copyfile(path, android / path.name)
        with self.assertRaises(ValueError):
            aggregate.build(android, self.root / "rejected", "0.2.20", SOURCE, self.keyfile, self.public)
        digest = aggregate.build(android, self.root / "root", "0.2.20", SOURCE,
                                 self.keyfile, self.public, scope="android")
        for path in (self.root / "root").iterdir():
            shutil.copyfile(path, android / path.name)
        gates = module("release-candidate-gates")
        gates.verify_runtime_release(android, "0.2.20", SOURCE, digest, self.public, scope="android")
        with self.assertRaises(ValueError):
            gates.verify_runtime_release(android, "0.2.20", SOURCE, digest, self.public)
        for path in full.glob("*-linux-x86_64.*"):
            shutil.copyfile(path, android / path.name)
        with self.assertRaises(ValueError):
            gates.verify_runtime_release(android, "0.2.20", SOURCE, digest, self.public, scope="android")

    def test_publication_requires_exact_scope_and_asset_inventory(self):
        consumer = module("check-publication-inputs")
        gates = consumer.gates
        assets = gates.publish_assets("android")
        self.assertEqual(len(assets), 10)
        self.assertFalse(any(token in name for name in assets for token in ("windows", "macos", "linux")))
        candidate = self.root / "candidate"
        candidate.mkdir()
        for name in assets:
            (candidate / name).write_bytes(b"retained bytes")
        inventory = dict(source_sha=SOURCE, run_id="42", mode="sign_candidate", trust="release",
                         purpose="shipping", release_scope="android",
                         assets={name: gates.file_hash(candidate / name) for name in assets})
        path = candidate / "candidate-inventory.json"
        path.write_text(json.dumps(inventory))
        consumer.check(candidate, SOURCE, "42", scope="android")
        with self.assertRaises(ValueError):
            consumer.check(candidate, SOURCE, "42")
        inventory["release_scope"] = "all"
        path.write_text(json.dumps(inventory))
        with self.assertRaises(ValueError):
            consumer.check(candidate, SOURCE, "42", scope="android")
        with self.assertRaises(ValueError):
            gates.publish_assets("unknown")
