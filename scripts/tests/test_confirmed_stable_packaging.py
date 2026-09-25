"""Real signing/verification with independent latest and archived stable sources."""
import hashlib
import json
import shutil
import tomllib
from unittest.mock import patch

from scripts.tests.test_runtime_artifact import ArtifactFixture, ROOT, SOURCE, module
from scripts.tests.test_runtime_release_set import RuntimeReleaseSetTest


class ConfirmedStablePackagingTest(ArtifactFixture):
    def test_android_common_host_version_matches_container_and_latest(self):
        expected = json.loads((ROOT / "src-tauri/tauri.conf.json").read_bytes())["version"]
        for name in ("crates/android-container/Cargo.toml", "src-tauri/Cargo.toml"):
            self.assertEqual(tomllib.loads((ROOT / name).read_text())["package"]["version"], expected, name)

    def test_android_shipping_requires_current_latest_and_pinned_stable(self):
        checker = module("android/check-container-apk")
        gates = module("release-candidate-gates")
        manifest = dict(container_version="0.3.1", stable_release_set_sha256=gates.STABLE_ROOT_SHA256,
            stable_platform_manifest_sha256="d" * 64,
            slots=[dict(slot="latest", manifest=dict(runtime_version="0.3.1")),
                   dict(slot="stable", manifest=dict(runtime_version="0.2.20", source_commit=gates.STABLE_SOURCE))])
        checker.verify_slots(manifest, root_digest=gates.STABLE_ROOT_SHA256, stable_digest="d" * 64)
        for change in ({"slots": manifest["slots"][:1]}, {"stable_release_set_sha256": "0" * 64}):
            with self.assertRaises(ValueError):
                checker.verify_slots({**manifest, **change}, root_digest=gates.STABLE_ROOT_SHA256, stable_digest="d" * 64)

    def inputs(self, native_linux=False):
        stable = RuntimeReleaseSetTest.four_candidates(self)
        if native_linux:
            module("build-runtime-manifest").package(self.payload, self.root / "linux-native", "0.2.20", SOURCE,
                "linux", "x86_64", self.keyfile)
            for path in (self.root / "linux-native").iterdir():
                shutil.copyfile(path, stable / path.name)
        aggregate = module("build-runtime-release-set")
        digest = aggregate.build(stable, self.root / "root-index", "0.2.20", SOURCE,
                                 self.keyfile, self.public)
        for path in (self.root / "root-index").iterdir():
            shutil.copyfile(path, stable / path.name)
        drafts = self.root / "drafts"
        for platform, architecture in module("verify-runtime-artifact").TARGETS:
            folder = drafts / platform
            folder.mkdir(parents=True)
            for keyname in ("draft-public-key.raw", "runtime-public-key.raw"):
                shutil.copyfile(self.public, folder / keyname)
            old = f"nelomai-runtime-0.2.20-{platform}-{architecture}"
            new = f"nelomai-runtime-0.3.1-{platform}-{architecture}"
            for slot in ("stable", "latest"):
                target = folder / slot
                target.mkdir()
                shutil.copyfile(stable / (old + ".zip"), target / (new + ".zip"))
                doc = json.loads((stable / (old + ".manifest.json")).read_bytes())
                doc.update(runtime_version="0.3.1", source_commit="b" * 40)
                raw = aggregate.canonical(doc)
                (target / (new + ".manifest.json")).write_bytes(raw)
                (target / (new + ".manifest.sig")).write_bytes(
                    self.key.sign(b"nelomai-runtime-manifest-v1\0" + raw))
        return drafts, stable, digest

    def test_native_staging_keeps_archived_stable_and_rejects_substituted_bytes(self):
        drafts, stable, digest = self.inputs(native_linux=True)
        signer = module("sign-runtime-candidate")
        stage = module("build-runtime-acceptance-container")
        signed = self.root / "signed"
        with patch.object(signer.gates, "STABLE_SOURCE", SOURCE), \
             patch.object(signer.gates, "STABLE_ROOT_SHA256", digest):
            current_digest = signer.sign(drafts, signed, "b" * 40, self.keyfile, self.public,
                version="0.3.1", confirmed_stable=stable, stable_public_key=self.public)
        with patch.object(stage.gates, "STABLE_SOURCE", SOURCE), \
             patch.object(stage.gates, "STABLE_ROOT_SHA256", digest):
            output = self.root / "staged"
            stage.stage_signed(signed, current_digest, output, self.public, "linux", "x86_64", "b" * 40, "shipping")
            for slot, version in (("latest", "0.3.1"), ("stable", "0.2.20")):
                for path in self.payload.rglob("*"):
                    if path.is_file():
                        self.assertEqual(path.read_bytes(),
                            (output / "runtime/engines" / slot / version / path.relative_to(self.payload)).read_bytes())
            archive = signed / "confirmed-stable/nelomai-runtime-0.2.20-linux-x86_64.zip"
            archive.write_bytes(archive.read_bytes() + b"substitution")
            with self.assertRaises(Exception):
                stage.stage_signed(signed, current_digest, self.root / "rejected", self.public,
                    "linux", "x86_64", "b" * 40, "shipping")
            self.assertFalse((self.root / "rejected").exists())

    def test_shipping_binds_independent_stable_source_and_preserves_all_archived_bytes(self):
        drafts, stable, digest = self.inputs()
        before = {p.name: p.read_bytes() for p in stable.iterdir()}
        signer = module("sign-runtime-candidate")
        with patch.object(signer.gates, "STABLE_SOURCE", SOURCE), \
             patch.object(signer.gates, "STABLE_ROOT_SHA256", digest):
            signer.sign(drafts, self.root / "signed", "b" * 40, self.keyfile, self.public,
                        version="0.3.1", confirmed_stable=stable, stable_public_key=self.public)
        archived = self.root / "signed/confirmed-stable"
        self.assertEqual(before, {p.name: p.read_bytes() for p in archived.iterdir()})
        verifier = module("verify-runtime-artifact")
        for platform, arch in verifier.TARGETS:
            folder = self.root / "signed/containers" / platform / "shipping"
            container = verifier.authenticated("container", folder / "container-manifest-v1.json",
                folder / "container-manifest-v1.sig", self.public, platform, arch)
            self.assertEqual(container["container_version"], "0.3.1")
            self.assertEqual([(s["slot"], s["manifest"]["runtime_version"], s["manifest"]["source_commit"])
                              for s in container["slots"]],
                             [("latest", "0.3.1", "b" * 40), ("stable", "0.2.20", SOURCE)])
            self.assertEqual(container["stable_release_set_sha256"], digest)
            name = f"nelomai-runtime-0.2.20-{platform}-{arch}.manifest.json"
            self.assertEqual(container["stable_platform_manifest_sha256"], hashlib.sha256(before[name]).hexdigest())
        self.assertEqual(before, {p.name: p.read_bytes() for p in stable.iterdir()})

    def test_031_cannot_fall_back_to_latest_only_or_rebuilt_stable(self):
        drafts, stable, digest = self.inputs()
        signer = module("sign-runtime-candidate")
        with self.assertRaisesRegex(ValueError, "confirmed stable"):
            signer.sign(drafts, self.root / "missing", "b" * 40, self.keyfile, self.public,
                        version="0.3.1")
        with patch.object(signer.gates, "STABLE_SOURCE", SOURCE), \
             patch.object(signer.gates, "STABLE_ROOT_SHA256", "0" * 64):
            with self.assertRaises(Exception):
                signer.sign(drafts, self.root / "wrong-root", "b" * 40, self.keyfile, self.public,
                            version="0.3.1", confirmed_stable=stable, stable_public_key=self.public)
        with patch.object(signer.gates, "STABLE_SOURCE", "c" * 40), \
             patch.object(signer.gates, "STABLE_ROOT_SHA256", digest):
            with self.assertRaisesRegex(ValueError, "identity"):
                signer.sign(drafts, self.root / "wrong-source", "b" * 40, self.keyfile, self.public,
                            version="0.3.1", confirmed_stable=stable, stable_public_key=self.public)
        for name in ("missing", "wrong-root", "wrong-source"):
            self.assertFalse((self.root / name).exists())
