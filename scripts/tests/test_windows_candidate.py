"""Windows-only candidate crypto/staging; PE fixtures are never executed."""
import json
import os
import shutil
import subprocess
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from scripts.tests.test_runtime_artifact import ArtifactFixture, SOURCE, module
import scripts.tests.test_runtime_release_set as release_fixtures
from scripts.tests.test_desktop_runtime_package import pe


class WindowsCandidateTest(ArtifactFixture):
    def setUp(self):
        super().setUp()
        self.candidate = module("windows-candidate")
        self.payload = self.root / "windows-payload"
        self.payload.mkdir()
        for name in ("nelomai-runtime.exe", "nelomai-windows-service.exe", "nelomai-windows-worker.exe"):
            self.put(name, pe())
        for name in ("tunnel.dll", "wireguard.dll", "amneziawg-tunnel.dll", "wintun.dll"):
            self.put(name, pe(dll=True))
        self.put("webview/index.html", b"Windows structural UI fixture")
        for name in ("TAURI-MIT.txt", "TAURI-APACHE-2.0.txt", "AMNEZIAWG-GO-LICENSE.txt",
                     "WIREGUARD-WINDOWS-LICENSE.txt", "WIREGUARD-NT-LICENSE.txt",
                     "AMNEZIAWG-WINDOWS-README.txt", "WINTUN-LICENSE.txt"):
            self.put("licenses/" + name, b"fixture attribution")
        self.stable = release_fixtures.RuntimeReleaseSetTest.four_candidates(self)
        native = self.root / "stable-native"
        module("build-runtime-manifest").package(self.payload, native, "0.2.20", SOURCE,
                                                "windows", "x86_64", self.keyfile)
        for path in native.iterdir():
            shutil.copyfile(path, self.stable / path.name)
        aggregate = module("build-runtime-release-set")
        self.stable_digest = aggregate.build(self.stable, self.root / "stable-root", "0.2.20", SOURCE,
                                             self.keyfile, self.public)
        for path in (self.root / "stable-root").iterdir():
            shutil.copyfile(path, self.stable / path.name)
        self.source = "b" * 40
        self.draft = self.root / "draft"
        module("build-runtime-manifest").package(self.payload, self.draft / "latest", "0.4.0", self.source,
                                                "windows", "x86_64", self.keyfile)
        self.final_private, self.final_public = self.root / "final-private", self.root / "final-public"
        final = Ed25519PrivateKey.generate()
        self.final_private.write_bytes(final.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
        self.final_public.write_bytes(final.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        shutil.copyfile(self.public, self.draft / "draft-public-key.raw")
        shutil.copyfile(self.final_public, self.draft / "runtime-public-key.raw")
        self.signed = self.root / "signed"
        self.addCleanup(patch.stopall)
        patch.object(self.candidate.gates, "STABLE_SOURCE", SOURCE).start()
        patch.object(self.candidate.gates, "STABLE_ROOT_SHA256", self.stable_digest).start()

    def sign(self):
        return self.candidate.sign(self.draft, self.stable, self.signed, self.source,
                                   self.final_private, self.final_public, self.public)

    def test_sign_and_stage_only_windows_latest_preserving_confirmed_stable_bytes(self):
        before = {p.relative_to(self.stable).as_posix(): p.read_bytes() for p in self.stable.iterdir()}
        self.sign()
        verifier = module("verify-runtime-artifact")
        docs = self.signed / "containers/windows/shipping"
        container = verifier.authenticated("container", docs / "container-manifest-v1.json",
            docs / "container-manifest-v1.sig", self.final_public, "windows", "x86_64")
        self.assertEqual([(s["slot"], s["manifest"]["runtime_version"], s["manifest"]["source_commit"])
                          for s in container["slots"]], [("latest", "0.4.0", self.source), ("stable", "0.2.20", SOURCE)])
        self.assertEqual(container["stable_release_set_sha256"], self.stable_digest)
        self.assertFalse((self.signed / "release").exists(), "no fabricated current four-platform root")
        staged = self.root / "staged"
        self.candidate.stage(self.signed, staged, self.source, self.final_public)
        for slot, version in (("latest", "0.4.0"), ("stable", "0.2.20")):
            for p in self.payload.rglob("*"):
                if p.is_file():
                    self.assertEqual(p.read_bytes(), (staged / "runtime/engines" / slot / version / p.relative_to(self.payload)).read_bytes())
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.stable.iterdir()})
        self.assertNotIn(self.final_private.read_bytes(), [p.read_bytes() for p in self.signed.rglob("*") if p.is_file()])

    def test_sign_refuses_changed_payload_compile_pin_and_unpinned_stable_before_output(self):
        archive = next((self.draft / "latest").glob("*.zip"))
        original = archive.read_bytes()
        archive.write_bytes(b"changed payload")
        with self.assertRaises(Exception): self.sign()
        self.assertFalse(self.signed.exists())
        archive.write_bytes(original)
        (self.draft / "runtime-public-key.raw").write_bytes(bytes(32))
        with self.assertRaisesRegex(ValueError, "pin"): self.sign()
        self.assertFalse(self.signed.exists())
        shutil.copyfile(self.final_public, self.draft / "runtime-public-key.raw")
        with patch.object(self.candidate.gates, "STABLE_ROOT_SHA256", "0" * 64):
            with self.assertRaises(Exception): self.sign()
        self.assertFalse(self.signed.exists())

    def test_stage_rejects_stable_substitution_and_validly_signed_latest_only_container(self):
        self.sign()
        archive = next((self.signed / "confirmed-stable").glob("*windows*.zip"))
        original = archive.read_bytes()
        archive.write_bytes(original + b"substitution")
        with self.assertRaises(Exception):
            self.candidate.stage(self.signed, self.root / "rejected", self.source, self.final_public)
        self.assertFalse((self.root / "rejected").exists())

        archive.write_bytes(original)
        docs = self.signed / "containers/windows/shipping"
        path = docs / "container-manifest-v1.json"
        container = json.loads(path.read_bytes()); container["slots"] = container["slots"][:1]
        raw = module("build-runtime-release-set").canonical(container)
        path.write_bytes(raw)
        (docs / "container-manifest-v1.sig").write_bytes(Ed25519PrivateKey.from_private_bytes(
            self.final_private.read_bytes()).sign(b"nelomai-container-manifest-v1\0" + raw))
        with self.assertRaises(Exception):
            self.candidate.stage(self.signed, self.root / "rejected", self.source, self.final_public)
        self.assertFalse((self.root / "rejected").exists())

    def test_windows_gate_ignores_global_macos_failure_but_requires_exact_windows_jobs(self):
        run = dict(id=17, run_attempt=1, event="push", head_sha=self.source,
            head_branch="Future/desktop-0.4.0", path=".github/workflows/checks.yml",
            repository={"full_name": self.candidate.REPOSITORY}, head_repository={"full_name": self.candidate.REPOSITORY},
            status="in_progress", conclusion=None)
        jobs = [dict(name=n, status="completed", conclusion="success") for n in ("windows-build", "windows-worker-native", "windows")]
        jobs.append(dict(name="macos", status="completed", conclusion="failure"))
        fresh_attempt = 1
        def api(endpoint):
            if "workflows/checks.yml/runs?" in endpoint: return {"total_count": 1, "workflow_runs": [run]}
            if "/jobs?" in endpoint: return {"total_count": len(jobs), "jobs": jobs}
            return {**run, "run_attempt": fresh_attempt}
        with patch.object(self.candidate.gates, "github_get", side_effect=api):
            self.assertEqual(self.candidate.windows_gate(self.source)["run_id"], 17)
            jobs[1]["conclusion"] = "failure"
            with self.assertRaises(ValueError): self.candidate.windows_gate(self.source)
            jobs[1]["conclusion"] = "success"; jobs[1]["status"] = "queued"
            with self.assertRaises(ValueError): self.candidate.windows_gate(self.source)
            jobs[1]["status"] = "completed"; run["head_sha"] = "c" * 40
            with self.assertRaises(ValueError): self.candidate.windows_gate(self.source)
            run["head_sha"] = self.source; fresh_attempt = 2
            with self.assertRaises(ValueError): self.candidate.windows_gate(self.source)

    def test_source_and_native_keyless_boundaries_fail_before_build(self):
        root = self.root / "checkout"; (root / "src-tauri").mkdir(parents=True)
        for name in ("package.json", "src-tauri/tauri.conf.json"):
            (root / name).write_text('{"version":"0.4.0"}')
        (root / "src-tauri/Cargo.toml").write_text('[package]\nversion="0.4.0"\n')
        for args in (("init", "-b", "Future/desktop-0.4.0"), ("add", "."),
                     ("-c", "user.name=Fixture", "-c", "user.email=fixture@invalid", "commit", "-m", "fixture")):
            subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)
        sha = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
        env = dict(GITHUB_REPOSITORY=self.candidate.REPOSITORY, GITHUB_REF=self.candidate.REF, GITHUB_SHA=sha,
                   NELOMAI_UPDATER_PUBLIC_KEY=self.candidate.UPDATER_PUBLIC)
        with patch.object(self.candidate.gates, "BASE", sha):
            self.candidate.source(sha, root=root, environment=env, native=True)
            for pin in (None, "wrong public pin"):
                with self.subTest(updater_public_key=pin), self.assertRaisesRegex(ValueError, "updater"):
                    self.candidate.source(sha, root=root, environment={**env, "NELOMAI_UPDATER_PUBLIC_KEY": pin}, native=True)
            for changes in ({"GITHUB_REF": "refs/heads/main"}, {"GITHUB_REPOSITORY": "fork/app"},
                            {"GITHUB_SHA": "c" * 40}, {"TAURI_SIGNING_PRIVATE_KEY": "must not reach native"}):
                with self.assertRaises(ValueError):
                    self.candidate.source(sha, root=root, environment={**env, **changes}, native=True)
            (root / "unknown").write_text("untracked")
            with self.assertRaises(ValueError): self.candidate.source(sha, root=root, environment=env)
            (root / "unknown").unlink()
            (root / "package.json").write_text('{"version":"0.3.2"}')
            with self.assertRaises(ValueError): self.candidate.source(sha, root=root, environment=env)

    def test_final_updater_signature_verifies_and_installer_mutation_is_refused(self):
        self.sign()
        packages = self.root / "packages"; (packages / "shipping").mkdir(parents=True)
        name = "nelomai-0.4.0-windows-x86_64.exe"
        installer = packages / "shipping" / name; installer.write_bytes(b"Windows fixture, never executed")
        index = dict(source_sha=self.source, purpose="windows-candidate", container_sha256=module("verify-runtime-artifact").digest(
            self.signed / "containers/windows/shipping/container-manifest-v1.json"),
            name=name, sha256=module("verify-runtime-artifact").digest(installer), size_bytes=installer.stat().st_size)
        (packages / "package-digests.json").write_text(json.dumps(index))
        work = self.root / "updater"; work.mkdir()
        environment = self.candidate.builder.updater_environment("build_only", work, os.environ)
        with patch.dict(os.environ, environment), patch.object(self.candidate, "UPDATER_PUBLIC", environment["NELOMAI_UPDATER_PUBLIC_KEY"]):
            output = self.root / "finalized"
            self.candidate.finalize(packages, self.signed, output, self.source, self.final_public)
            self.assertEqual((output / name).read_bytes(), installer.read_bytes())
            self.assertTrue((output / (name + ".sig")).is_file())
            self.assertEqual(json.loads((output / "candidate-inventory.json").read_bytes())["purpose"], "windows-candidate")
            installer.write_bytes(b"mutated")
            with self.assertRaises(ValueError):
                self.candidate.finalize(packages, self.signed, self.root / "rejected-final", self.source, self.final_public)
            self.assertFalse((self.root / "rejected-final").exists())
