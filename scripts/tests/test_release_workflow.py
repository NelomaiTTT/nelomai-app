"""Required static authorization graph checks, complemented by executable gates."""
import re
import unittest
import yaml

from scripts.tests.test_runtime_artifact import ROOT


class ReleaseWorkflowTest(unittest.TestCase):
    def test_existing_release_inputs_keep_repository_secret_bindings(self):
        # These inputs were provisioned as Secrets for existing releases.
        # A Variables-only binding silently passes an empty value to the runner.
        environment = self.workflow()["env"]
        for name in ("NELOMAI_UPDATER_PUBLIC_KEY", "NELOMAI_FIREBASE_APPLICATION_ID",
                     "NELOMAI_FIREBASE_API_KEY", "NELOMAI_FIREBASE_PROJECT_ID"):
            with self.subTest(name=name):
                self.assertEqual(environment[name], "${{ secrets." + name + " }}")

    def test_discovery_host_provisions_mandatory_compiled_android_fixtures(self):
        steps = self.workflow()["jobs"]["verify"]["steps"]
        host = next(step for step in steps if step.get("uses") == "./.github/actions/release-native-host")
        self.assertEqual(str(host["with"].get("android-fixtures")).lower(), "true",
                         "discovery executes mandatory Android fixtures without its toolchain")
        action = yaml.safe_load((ROOT / ".github/actions/release-native-host/action.yml").read_text())
        setup = action["runs"]["steps"]
        for prefix in ("actions/setup-java@", "android-actions/setup-android@"):
            step = next(step for step in setup if step.get("uses", "").startswith(prefix))
            self.assertIn("inputs.android-fixtures == 'true'", step["if"])
        ndk = next(step for step in setup if "sdkmanager " in step.get("run", ""))
        self.assertIn("inputs.android-fixtures == 'true'", ndk["if"])
        self.assertIn("ndk;28.2.13676358", ndk["run"])
        self.assertIn("ANDROID_NDK_HOME=", ndk["run"])

    def workflow(self):
        return yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())

    def test_fresh_verify_host_builds_shared_contract_cli_before_python_consumers(self):
        commands = [step.get("run", "") for step in self.workflow()["jobs"]["verify"]["steps"]]
        build = next((index for index, command in enumerate(commands)
                      if "cargo build --locked -p nelomai-contracts --bin verify-runtime-manifest" in command), None)
        self.assertIsNotNone(build, "fresh runner has no shared verifier executable for Python gates")
        gate = next(index for index, command in enumerate(commands) if "scripts/release-workflow-check.py" in command)
        self.assertLess(build, gate)

    def test_only_separate_promotion_can_write_and_cannot_build_or_sign(self):
        workflow = self.workflow()
        self.assertEqual(workflow["permissions"].get("contents"), "read", "default workflow is not read-only")
        jobs = workflow["jobs"]
        writers = [name for name, job in jobs.items() if job.get("permissions", {}).get("contents") == "write"]
        self.assertEqual(writers, ["publish"])
        publish = jobs["publish"]
        self.assertIn("publish_approved_candidate", publish["if"])
        self.assertEqual(publish["environment"], "release-publication")
        body = yaml.safe_dump(publish, width=100000)
        self.assertNotRegex(body, r"cargo (?:build|test)|tauri (?:build|bundle)|build-release-manifest|signing-key|PRIVATE_KEY")
        self.assertIn("--target", body)
        self.assertIn("SOURCE_SHA", body)
        self.assertIn("check-publication-inputs.py", body)
        self.assertNotIn("release-candidate-gates.py approval", body)
        self.assertIn("release-candidate-gates.py tag", body)
        self.assertIn("panel_notification_ready", body)

    def test_every_checkout_is_pinned_and_root_requires_four_native_builds(self):
        workflow = self.workflow()
        jobs = workflow["jobs"]
        for name, job in jobs.items():
            for step in job.get("steps", []):
                if step.get("uses", "").startswith("actions/checkout@"):
                    self.assertEqual(step.get("with", {}).get("ref"), "${{ inputs.source_sha }}", name)
                    self.assertEqual(step["with"].get("fetch-depth"), 0, name)
        for name in ("native_drafts", "native_packages"):
            targets = jobs[name]["strategy"]["matrix"]["include"]
            self.assertEqual({(row["platform"], row["architecture"]) for row in targets},
                {("linux", "x86_64"), ("windows", "x86_64"), ("macos", "aarch64"), ("android", "aarch64")})
        self.assertEqual(jobs["sign"]["environment"], "release-candidate-signing")
        self.assertEqual(jobs["finalize"]["environment"], "release-candidate-finalization")
        for name in ("native_drafts", "native_packages"):
            self.assertNotIn("environment", jobs[name])
        self.assertEqual(jobs["sign"]["needs"], "native_drafts")
        self.assertIn("sign", jobs["native_packages"]["needs"])
        self.assertIn("native_packages", jobs["finalize"]["needs"])
        self.assertIn("build-runtime-release-set.py", yaml.safe_dump(jobs["sign"]))

    def test_build_only_has_no_release_secrets_or_full_acceptance_requirement(self):
        workflow = self.workflow()
        dispatch = workflow.get("on", workflow.get(True))["workflow_dispatch"]["inputs"]
        self.assertEqual(dispatch.get("mode", {}).get("default"), "build_only")
        self.assertTrue(dispatch["source_sha"]["required"])
        build = yaml.safe_dump([workflow["jobs"][name] for name in ("native_drafts", "native_packages")])
        self.assertNotIn("secrets.", build)
        self.assertNotIn("contents: write", build)
        self.assertNotIn("panel_notification_ready", build)
        self.assertNotIn("candidate_acceptance", workflow["jobs"])
        self.assertNotIn("native_recheck", workflow["jobs"])
        self.assertNotIn("verify_promotion", workflow["jobs"])

    def test_merged_signing_steps_expose_release_credentials_only_in_release_mode(self):
        jobs = self.workflow()["jobs"]
        for job in ("sign", "finalize"):
            self.assertIn(job, jobs, "single signing/finalization consumer is missing")
            for step in jobs[job]["steps"]:
                for value in step.get("env", {}).values():
                    if "secrets." in str(value):
                        self.assertTrue("inputs.mode == 'sign_candidate'" in str(value)
                                        or step.get("if") == "inputs.mode == 'sign_candidate'",
                                        "test signing step receives a production credential")
        self.assertEqual(jobs["sign"]["needs"], "native_drafts")
        self.assertEqual(set(jobs["native_packages"]["needs"]), {"native_drafts", "sign"})
        self.assertEqual(set(jobs["finalize"]["needs"]), {"native_packages", "sign"})

    def test_publish_resolves_artifact_from_run_without_manual_hashes(self):
        workflow = self.workflow()
        dispatch = workflow.get("on", workflow.get(True))["workflow_dispatch"]["inputs"]
        for field in ("candidate_artifact_id", "release_set_sha256", "inventory_sha256"):
            self.assertNotIn(field, dispatch)
        steps = workflow["jobs"]["publish"]["steps"]
        selection = next(step for step in steps if "--select" in step.get("run", ""))
        download = next(step for step in steps if step.get("uses", "").startswith("actions/download-artifact@"))
        self.assertEqual(download["with"]["artifact-ids"], "${{ steps.select.outputs.artifact_id }}")
        self.assertEqual(selection["id"], "select")
        self.assertLess(steps.index(selection), steps.index(download))


if __name__ == "__main__":
    unittest.main()
