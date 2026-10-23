"""Real signing/verification with independent latest and archived stable sources."""
import hashlib
import json
import shutil
from pathlib import Path
import subprocess
import tomllib
from unittest.mock import patch

from scripts.tests.test_runtime_artifact import ArtifactFixture, ROOT, SOURCE, module
from scripts.tests.test_runtime_release_set import RuntimeReleaseSetTest


VERSION = module("release-candidate-gates").VERSION
STABLE_VERSION = module("release-candidate-gates").STABLE_VERSION

class ConfirmedStablePackagingTest(ArtifactFixture):
    def test_download_authenticates_pinned_candidate_before_exposing_output(self):
        _, stable, digest = self.inputs()
        downloader = module("download-confirmed-stable")
        real_run = subprocess.run
        run = dict(id=int(downloader.gates.STABLE_RUN_ID), head_sha=SOURCE,
                   path=".github/workflows/release.yml", status="completed", conclusion="success")

        def network(command, **kwargs):
            if command[:2] == ["gh", "api"]:
                return subprocess.CompletedProcess(command, 0, stdout=json.dumps(run))
            if command[:3] == ["gh", "run", "download"]:
                destination = Path(command[command.index("--dir") + 1])
                shutil.copytree(stable, destination / "release")
                return subprocess.CompletedProcess(command, 0)
            if command[0] == "gh":
                raise AssertionError("must use the pinned candidate without publishing a release")
            return real_run(command, **kwargs)

        with patch.object(downloader.gates, "STABLE_SOURCE", SOURCE), \
             patch.object(downloader.gates, "STABLE_ROOT_SHA256", digest), \
             patch.object(downloader.subprocess, "run", side_effect=network):
            output = self.root / "downloaded"
            downloader.download(output, self.public)
            self.assertEqual({p.name: p.read_bytes() for p in output.iterdir()},
                             {p.name: p.read_bytes() for p in stable.iterdir()})
            run["conclusion"] = "failure"
            with self.assertRaises(ValueError):
                downloader.download(self.root / "failed-run", self.public)
            self.assertFalse((self.root / "failed-run").exists())
            run["conclusion"] = "success"
            archive = next(stable.glob("*.zip"))
            archive.write_bytes(archive.read_bytes() + b"tampered")
            with self.assertRaises(Exception):
                downloader.download(self.root / "tampered", self.public)
            self.assertFalse((self.root / "tampered").exists())

    def test_android_common_host_version_matches_container_and_latest(self):
        expected = json.loads((ROOT / "src-tauri/tauri.conf.json").read_bytes())["version"]
        for name in ("crates/android-container/Cargo.toml", "src-tauri/Cargo.toml"):
            self.assertEqual(tomllib.loads((ROOT / name).read_text())["package"]["version"], expected, name)

    def test_android_shipping_requires_current_latest_and_pinned_stable(self):
        checker = module("android/check-container-apk")
        gates = module("release-candidate-gates")
        manifest = dict(container_version=VERSION, stable_release_set_sha256=gates.STABLE_ROOT_SHA256,
            stable_platform_manifest_sha256="d" * 64,
            slots=[dict(slot="latest", manifest=dict(runtime_version=VERSION)),
                   dict(slot="stable", manifest=dict(runtime_version=STABLE_VERSION, source_commit=gates.STABLE_SOURCE))])
        checker.verify_slots(manifest, root_digest=gates.STABLE_ROOT_SHA256, stable_digest="d" * 64)
        for change in ({"slots": manifest["slots"][:1]}, {"stable_release_set_sha256": "0" * 64}):
            with self.assertRaises(ValueError):
                checker.verify_slots({**manifest, **change}, root_digest=gates.STABLE_ROOT_SHA256, stable_digest="d" * 64)

    def inputs(self, native_linux=False):
        stable = RuntimeReleaseSetTest.four_candidates(self, version=STABLE_VERSION)
        if native_linux:
            module("build-runtime-manifest").package(self.payload, self.root / "linux-native", STABLE_VERSION, SOURCE,
                "linux", "x86_64", self.keyfile)
            for path in (self.root / "linux-native").iterdir():
                shutil.copyfile(path, stable / path.name)
        aggregate = module("build-runtime-release-set")
        digest = aggregate.build(stable, self.root / "root-index", STABLE_VERSION, SOURCE,
                                 self.keyfile, self.public)
        for path in (self.root / "root-index").iterdir():
            shutil.copyfile(path, stable / path.name)
        drafts = self.root / "drafts"
        for platform, architecture in module("verify-runtime-artifact").TARGETS:
            folder = drafts / platform
            folder.mkdir(parents=True)
            for keyname in ("draft-public-key.raw", "runtime-public-key.raw"):
                shutil.copyfile(self.public, folder / keyname)
            old = f"nelomai-runtime-{STABLE_VERSION}-{platform}-{architecture}"
            new = f"nelomai-runtime-{VERSION}-{platform}-{architecture}"
            for slot in ("stable", "latest"):
                target = folder / slot
                target.mkdir()
                shutil.copyfile(stable / (old + ".zip"), target / (new + ".zip"))
                doc = json.loads((stable / (old + ".manifest.json")).read_bytes())
                doc.update(runtime_version=VERSION, source_commit="b" * 40)
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
                version=VERSION, confirmed_stable=stable, stable_public_key=self.public)
        with patch.object(stage.gates, "STABLE_SOURCE", SOURCE), \
             patch.object(stage.gates, "STABLE_ROOT_SHA256", digest):
            output = self.root / "staged"
            stage.stage_signed(signed, current_digest, output, self.public, "linux", "x86_64", "b" * 40, "shipping")
            for slot, version in (("latest", VERSION), ("stable", STABLE_VERSION)):
                for path in self.payload.rglob("*"):
                    if path.is_file():
                        self.assertEqual(path.read_bytes(),
                            (output / "runtime/engines" / slot / version / path.relative_to(self.payload)).read_bytes())
            archive = signed / f"confirmed-stable/nelomai-runtime-{STABLE_VERSION}-linux-x86_64.zip"
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
                        version=VERSION, confirmed_stable=stable, stable_public_key=self.public)
        archived = self.root / "signed/confirmed-stable"
        self.assertEqual(before, {p.name: p.read_bytes() for p in archived.iterdir()})
        verifier = module("verify-runtime-artifact")
        for platform, arch in verifier.TARGETS:
            folder = self.root / "signed/containers" / platform / "shipping"
            container = verifier.authenticated("container", folder / "container-manifest-v1.json",
                folder / "container-manifest-v1.sig", self.public, platform, arch)
            self.assertEqual(container["container_version"], VERSION)
            self.assertEqual([(s["slot"], s["manifest"]["runtime_version"], s["manifest"]["source_commit"])
                              for s in container["slots"]],
                             [("latest", VERSION, "b" * 40), ("stable", STABLE_VERSION, SOURCE)])
            self.assertEqual(container["stable_release_set_sha256"], digest)
            name = f"nelomai-runtime-{STABLE_VERSION}-{platform}-{arch}.manifest.json"
            self.assertEqual(container["stable_platform_manifest_sha256"], hashlib.sha256(before[name]).hexdigest())
        self.assertEqual(before, {p.name: p.read_bytes() for p in stable.iterdir()})

    def test_current_cannot_fall_back_to_latest_only_or_rebuilt_stable(self):
        drafts, stable, digest = self.inputs()
        signer = module("sign-runtime-candidate")
        with self.assertRaisesRegex(ValueError, "confirmed stable"):
            signer.sign(drafts, self.root / "missing", "b" * 40, self.keyfile, self.public,
                        version=VERSION)
        with patch.object(signer.gates, "STABLE_SOURCE", SOURCE), \
             patch.object(signer.gates, "STABLE_ROOT_SHA256", "0" * 64):
            with self.assertRaises(Exception):
                signer.sign(drafts, self.root / "wrong-root", "b" * 40, self.keyfile, self.public,
                            version=VERSION, confirmed_stable=stable, stable_public_key=self.public)
        with patch.object(signer.gates, "STABLE_SOURCE", "c" * 40), \
             patch.object(signer.gates, "STABLE_ROOT_SHA256", digest):
            with self.assertRaisesRegex(ValueError, "identity"):
                signer.sign(drafts, self.root / "wrong-source", "b" * 40, self.keyfile, self.public,
                            version=VERSION, confirmed_stable=stable, stable_public_key=self.public)
        for name in ("missing", "wrong-root", "wrong-source"):
            self.assertFalse((self.root / name).exists())
