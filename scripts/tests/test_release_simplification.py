"""Exercise shipping-only consumers and selection of a retained build, offline."""
import json
import os
import shutil
import sys
import contextlib
import io
import subprocess
import zipfile
from unittest.mock import patch

from scripts.tests.test_runtime_artifact import ArtifactFixture, SOURCE, ROOT, module
import scripts.tests.test_runtime_candidate_signing as candidate_fixtures


class ReleaseSimplificationTest(ArtifactFixture):
    def test_shipping_only_finalizer_produces_complete_publishable_file_set(self):
        drafts = candidate_fixtures.RuntimeCandidateSigningTest.drafts(self)
        signed = self.root / "signed"
        digest = module("sign-runtime-candidate").sign(drafts, signed, SOURCE, self.keyfile, self.public)
        consumer = module("finalize-release-candidate")
        packages = self.root / "packages"
        for platform, architecture in consumer.verifier.TARGETS:
            folder = packages / platform
            (folder / "shipping").mkdir(parents=True)
            package = folder / "shipping" / consumer.gates.PACKAGE_NAMES[platform]
            if platform == "android":
                with zipfile.ZipFile(package, "w") as archive:
                    archive.writestr("classes.dex", b"fixture" * 300000)
            else:
                package.write_bytes(b"fixture" * 300000)
            (folder / "package-digests.json").write_text(json.dumps(dict(
                source_sha=SOURCE, release_set_sha256=digest, mode="build_only", platform=platform,
                architecture=architecture, packages={"shipping": dict(name=package.name,
                    sha256=consumer.verifier.digest(package), size_bytes=package.stat().st_size)})))
        for suffix in (".tar.gz", ".tar.gz.sha256"):
            (packages / "android/shipping" / ("nelomai-0.2.19-amneziawg-android-source" + suffix)).write_bytes(b"source fixture")
        output, work = self.root / "finalized", self.root / "finalization"
        arguments = ["finalize-release-candidate", "--packages", str(packages), "--signed", str(signed),
                     "--output", str(output), "--private-key", str(self.keyfile), "--public-key", str(self.public),
                     "--work", str(work), "--sdk", str(self.root / "sdk"), "--source-sha", SOURCE,
                     "--release-set-sha256", digest]
        run = consumer.builder.run

        def native_signer(*command, **kwargs):
            if str(command[0]).endswith("/apksigner"):
                self.assertEqual(command[1:4], ("verify", "--verbose", "--print-certs"))
                return subprocess.CompletedProcess(command, 0, "Signer #1 certificate SHA-256 digest: " + "d" * 64 + "\n", "")
            return run(*command, **kwargs)

        with patch.object(sys, "argv", arguments), patch.object(consumer.builder, "run", side_effect=native_signer), \
             patch.dict(os.environ, {"GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "3"}), \
             contextlib.redirect_stdout(io.StringIO()) as result:
            consumer.main()
        inventory = json.loads((output / "candidate/candidate-inventory.json").read_bytes())
        self.assertEqual(set(inventory["assets"]), consumer.gates.PUBLISH_ASSETS)
        self.assertEqual(inventory["purpose"], "shipping")
        self.assertEqual(inventory["run_attempt"], 3)
        self.assertEqual(set(json.loads(result.getvalue())), {"inventory_sha256"})
        self.assertEqual({folder.name for folder in output.iterdir()}, {"candidate"})

    def test_regular_packaging_emits_only_shipping_without_rebuilding_ui(self):
        self.check_packaging(False)

    def test_explicit_diagnostic_packaging_retains_linux_acceptance_inputs(self):
        self.check_packaging(True)

    def check_packaging(self, diagnostic):
        drafts = candidate_fixtures.RuntimeCandidateSigningTest.drafts(self)
        result = self.build("linux-native")
        self.assertEqual(result.returncode, 0, result.stderr)
        for slot in ("latest", "stable"):
            for artifact in (self.root / "linux-native").iterdir():
                shutil.copyfile(artifact, drafts / "linux" / slot / artifact.name)
        signed = self.root / "signed"
        digest = module("sign-runtime-candidate").sign(drafts, signed, SOURCE, self.keyfile, self.public)
        consumer = module("package-release-platform")
        output = self.root / "packages"
        commands = []

        def native_package(staged, work, *_args, **_kwargs):
            work.mkdir(parents=True)
            package = work / "nelomai-acceptance-0.2.19-linux-x86_64.AppImage"
            package.write_bytes(b"native package substitute")
            return package

        arguments = ["package-release-platform", "--signed", str(signed), "--draft", str(drafts / "linux"),
                     "--output", str(output), "--public-key", str(self.public), "--source-sha", SOURCE,
                     "--release-set-sha256", digest, "--platform", "linux", "--architecture", "x86_64"]
        if diagnostic:
            arguments.append("--include-acceptance")
        with patch.object(sys, "argv", arguments), patch.dict(os.environ, {}, clear=True), \
             patch.object(consumer.builder, "run", side_effect=lambda *a, **kw: commands.append(a)), \
             patch.object(consumer.container, "package_desktop", side_effect=native_package):
            try:
                consumer.main()
            except SystemExit as error:
                self.fail(f"diagnostic packaging rejected required CLI inputs: {error}")
        index = json.loads((output / "package-digests.json").read_bytes())
        self.assertEqual(set(index["packages"]), {"shipping", "acceptance"} if diagnostic else {"shipping"})
        self.assertEqual((output / "acceptance").exists(), diagnostic)
        if diagnostic:
            self.assertTrue((output / "staged/acceptance/runtime/container-manifest-v1.json").is_file())
        self.assertFalse(any(command[:3] in (("npm", "run", "build"), ("npm.cmd", "run", "build"))
                             for command in commands))

    def test_desktop_wrapper_uses_staged_ui_without_tauri_before_build_hook(self):
        consumer = module("build-runtime-acceptance-container")
        staged = self.root / "staged"
        ui = staged / "runtime/engines/latest/0.2.19/webview"
        ui.mkdir(parents=True)
        (ui / "index.html").write_text("signed UI")
        (staged / "runtime/container-manifest-v1.json").write_text(json.dumps({
            "slots": [{"slot": "latest", "manifest": {"runtime_version": "0.2.19"}}]}))
        output = self.root / "package"

        class NativeBuildReached(Exception):
            pass

        with patch.object(consumer.subprocess, "run", side_effect=NativeBuildReached):
            with self.assertRaises(NativeBuildReached):
                consumer.package_desktop(staged, output, self.public, "macos", "aarch64", root=ROOT)
        config = json.loads((output / "bundle-config.json").read_bytes())
        self.assertEqual(config.get("build", {}).get("beforeBuildCommand"), "")
        self.assertEqual(config["build"]["frontendDist"], str(ui.resolve()))

    def test_publication_selects_exact_retained_artifact_after_rerun(self):
        consumer = module("check-publication-inputs")
        self.assertTrue(callable(getattr(consumer, "select_candidate", None)), "automatic build selection missing")
        run = dict(id=42, head_sha=SOURCE, path=".github/workflows/release.yml", event="workflow_dispatch",
                   status="completed", conclusion="success", run_attempt=3,
                   repository={"full_name": "owner/repo"}, head_repository={"full_name": "owner/repo"})
        artifact = dict(id=123, name="candidate-0.2.19", expired=False,
                        workflow_run={"id": 42, "head_sha": SOURCE})

        def fetch(endpoint):
            if "/artifacts?" in endpoint:
                return {"total_count": 1, "artifacts": [artifact]}
            return run

        self.assertEqual(consumer.select_candidate("owner/repo", "42", SOURCE, "0.2.19", fetch), 123)
        for changes in ({"head_sha": "b" * 40}, {"conclusion": "failure"}, {"status": "in_progress"},
                        {"path": ".github/workflows/windows-build.yml"}):
            with patch.dict(run, changes), self.assertRaises(ValueError):
                consumer.select_candidate("owner/repo", "42", SOURCE, "0.2.19", fetch)
        with patch.dict(artifact, {"expired": True}), self.assertRaises(ValueError):
            consumer.select_candidate("owner/repo", "42", SOURCE, "0.2.19", fetch)
        with self.assertRaises(ValueError):
            consumer.select_candidate("owner/repo", "42", SOURCE, "0.2.19", lambda endpoint:
                {"total_count": 2, "artifacts": [artifact, {**artifact, "id": 124}]} if "/artifacts?" in endpoint else run)
