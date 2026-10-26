"""Desktop release topology and authenticated inventory regressions."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import yaml

from scripts.tests.test_runtime_artifact import ArtifactFixture, SOURCE, ROOT, module
from scripts.tests import test_runtime_release_set as release_fixtures


class DesktopReleaseTest(ArtifactFixture):
    def test_04_aggregation_accepts_exact_desktops_and_rejects_android(self):
        aggregate = module("build-runtime-release-set")
        folder = release_fixtures.RuntimeReleaseSetTest.four_candidates(self, version="0.4.0")
        with self.assertRaises(ValueError):
            aggregate.collect(folder, "0.4.0", SOURCE, self.public)
        for path in folder.glob("*android*"):
            path.unlink()
        digest = aggregate.build(folder, self.root / "root", "0.4.0", SOURCE, self.keyfile, self.public)
        for path in (self.root / "root").iterdir():
            path.rename(folder / path.name)
        module("release-candidate-gates").verify_runtime_release(folder, "0.4.0", SOURCE, digest, self.public)
        self.assertEqual(len(json.loads(next(folder.glob("*release-set.manifest.json")).read_bytes())["artifacts"]), 3)

    def test_publish_inventory_is_exactly_sixteen_desktop_assets(self):
        gates = module("release-candidate-gates")
        self.assertEqual(set(gates.PACKAGE_NAMES), {"linux", "windows", "macos"})
        self.assertEqual(len(gates.PUBLISH_ASSETS), 16)
        self.assertFalse(any("android" in name for name in gates.PUBLISH_ASSETS))

    def test_required_bullet_changelog_rejects_empty_prose_and_preserves_shell_text(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
        inputs = workflow.get("on", workflow.get(True))["workflow_dispatch"]["inputs"]
        self.assertIs(inputs["release_notes"].get("required"), True)
        guard = workflow["jobs"]["publish"]["steps"][1]
        for notes, accepted in (("", False), ("  ", False), ("Описание", False),
                                ("- Исправлено соединение\n- Ускорен запуск", True),
                                ("- Исправлено $(touch injected)", True)):
            with self.subTest(notes=notes), tempfile.TemporaryDirectory() as tmp:
                # Run only the extracted changelog validation, keeping input in env.
                program = guard["run"].split("python - <<'PY'\n", 1)[1].split("\nPY", 1)[0]
                result = subprocess.run(["python3", "-c", program], cwd=tmp,
                    env={**os.environ, "RELEASE_NOTES": notes}, capture_output=True)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                self.assertFalse((Path(tmp) / "injected").exists())

    def test_promotion_rejects_notes_different_from_retained_release_manifest(self):
        checker = module("check-publication-inputs")
        directory = self.root / "candidate"
        directory.mkdir()
        for name in checker.gates.PUBLISH_ASSETS:
            (directory / name).write_bytes(b"fixture")
        notes = "- Исправлено соединение\n- Ускорен запуск"
        (directory / "nelomai-release-manifest.json").write_text(json.dumps({"release_notes": notes}))
        inventory = dict(source_sha=SOURCE, run_id="42", mode="sign_candidate", trust="release", purpose="shipping",
            assets={path.name: checker.gates.file_hash(path) for path in directory.iterdir()})
        (directory / "candidate-inventory.json").write_text(json.dumps(inventory))
        checker.check(directory, SOURCE, "42", release_notes=notes)
        with self.assertRaisesRegex(ValueError, "changelog"):
            checker.check(directory, SOURCE, "42", release_notes="- Другие изменения")

    def test_source_guard_rejects_foreign_context_dirty_tree_and_invalid_notes(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
        programs = {job["steps"][1]["run"] for job in workflow["jobs"].values()}
        self.assertEqual(len(programs), 1)
        program = programs.pop()
        repo = self.root / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=Fixture", "-c",
                        "user.email=fixture@example.invalid", "commit", "--allow-empty", "-qm", "source"], check=True)
        source = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        environment = {**os.environ, "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": "NelomaiTTT/nelomai-app",
            "GITHUB_REF": "refs/heads/Future/desktop-0.4.0", "SOURCE_SHA": source, "GITHUB_SHA": source,
            "RELEASE_VERSION": "0.4.0", "RELEASE_NOTES": "- Исправлена ошибка"}
        def run(changes):
            return subprocess.run(["bash", "-c", program], cwd=repo,
                env={**environment, **changes}, capture_output=True).returncode
        self.assertEqual(run({}), 0)
        for changes in ({"GITHUB_EVENT_NAME": "push"}, {"GITHUB_REPOSITORY": "foreign/repo"},
                        {"GITHUB_REF": "refs/heads/main"}, {"GITHUB_REF": "refs/tags/v0.4.0"},
                        {"SOURCE_SHA": "a" * 40}, {"GITHUB_SHA": "a" * 40}, {"SOURCE_SHA": "main"},
                        {"RELEASE_VERSION": "0.4.1"}, {"RELEASE_NOTES": ""}, {"RELEASE_NOTES": "- "}):
            with self.subTest(changes=changes):
                self.assertNotEqual(run(changes), 0)
        (repo / "untracked.txt").write_text("dirty")
        self.assertNotEqual(run({}), 0)

    def test_every_job_guards_branch_and_repository_before_local_code_or_keys(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
        for name, job in workflow["jobs"].items():
            with self.subTest(job=name):
                self.assertIn("github.repository == 'NelomaiTTT/nelomai-app'", job.get("if", ""))
                self.assertIn("github.ref == 'refs/heads/Future/desktop-0.4.0'", job.get("if", ""))
                steps = job["steps"]
                self.assertEqual(steps[0]["uses"], "actions/checkout@v7.0.1")
                guard = steps[1]
                self.assertEqual(guard["name"], "Exact desktop release source before local code")
                for required in ('test "$GITHUB_REPOSITORY" = NelomaiTTT/nelomai-app',
                                 'test "$GITHUB_REF" = refs/heads/Future/desktop-0.4.0',
                                 'test "$SOURCE_SHA" = "$GITHUB_SHA"',
                                 'test "$(git rev-parse HEAD)" = "$SOURCE_SHA"'):
                    self.assertIn(required, guard["run"])
                self.assertNotIn("secrets.", yaml.safe_dump(steps[:2]))
                for step in steps:
                    if step.get("uses") == "./.github/actions/release-native-host":
                        self.assertEqual(step["with"]["node24"], "true")
