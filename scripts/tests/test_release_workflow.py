"""Required static authorization graph checks, complemented by executable gates."""
import re
import shlex
import os
import subprocess
import unittest
from types import SimpleNamespace
import yaml

from scripts.tests.test_runtime_artifact import ROOT


class ReleaseWorkflowTest(unittest.TestCase):
    def expression(self, expression, *, mode, result="success", cancelled=False):
        """Evaluate the boolean/string expressions used by our dispatch graph."""
        expression = expression.removeprefix("${{").removesuffix("}}").strip()
        expression = expression.replace("&&", " and ").replace("||", " or ")
        expression = re.sub(r"!(?!=)", " not ", expression)
        return eval(expression.strip(), {"__builtins__": {}}, {
            "inputs": SimpleNamespace(mode=mode, candidate_run_id="42"),
            "github": SimpleNamespace(run_id="99"),
            "needs": SimpleNamespace(finalize=SimpleNamespace(result=result, outputs=SimpleNamespace(
                artifact_id="123", inventory_sha256="a" * 64))),
            "steps": SimpleNamespace(select=SimpleNamespace(outputs=SimpleNamespace(artifact_id="456"))),
            "secrets": SimpleNamespace(**{name: "release-secret" for name in (
                "NELOMAI_RELEASE_MANIFEST_PRIVATE_KEY_B64", "ANDROID_KEYSTORE_BASE64",
                "TAURI_SIGNING_PRIVATE_KEY", "TAURI_SIGNING_PRIVATE_KEY_PASSWORD",
                "ANDROID_KEY_ALIAS", "ANDROID_KEYSTORE_PASSWORD", "ANDROID_KEY_PASSWORD")}),
            "always": lambda: True, "cancelled": lambda: cancelled,
        })

    def test_build_and_publish_uses_existing_signed_candidate_pipeline(self):
        workflow = self.workflow()
        self.assertIn("build_and_publish", workflow[True]["workflow_dispatch"]["inputs"]["mode"]["options"])
        for mode, expected in (("build_only", "build_only"), ("sign_candidate", "sign_candidate"),
                               ("build_and_publish", "sign_candidate"),
                               ("publish_approved_candidate", "publish_approved_candidate")):
            with self.subTest(mode=mode):
                self.assertEqual(self.expression(workflow["env"]["RELEASE_MODE"], mode=mode), expected)

    def test_publication_waits_for_finalization_but_retained_promotion_needs_no_build(self):
        job = self.workflow()["jobs"]["publish"]
        self.assertEqual(job.get("needs"), ["finalize"])
        # Without an explicit status function GitHub skips the standalone path
        # because its build dependencies were skipped.
        self.assertIn("always()", job["if"])
        for mode, result, cancelled, expected in (
            ("build_and_publish", "success", False, True),
            ("build_and_publish", "failure", False, False),
            ("build_and_publish", "cancelled", False, False),
            ("build_and_publish", "skipped", False, False),
            ("build_and_publish", "success", True, False),
            ("sign_candidate", "success", False, False),
            ("build_only", "success", False, False),
            ("publish_approved_candidate", "skipped", False, True),
            ("publish_approved_candidate", "skipped", True, False),
        ):
            with self.subTest(mode=mode, result=result, cancelled=cancelled):
                self.assertEqual(bool(self.expression(job["if"], mode=mode, result=result,
                                                     cancelled=cancelled)), expected)

    def test_inline_publication_downloads_exact_finalized_artifact_and_pins_inventory(self):
        jobs = self.workflow()["jobs"]
        final = jobs["finalize"]
        upload = next(s for s in final["steps"] if s.get("uses", "").startswith("actions/upload-artifact@"))
        self.assertEqual(final["outputs"].get("artifact_id"),
                         "${{ steps." + upload.get("id", "MISSING") + ".outputs.artifact-id }}")
        publish = jobs["publish"]
        self.assertEqual(publish["env"].get("RELEASE_MODE"), "publish_approved_candidate")
        download = next(s for s in publish["steps"] if s.get("uses", "").startswith("actions/download-artifact@"))
        selection = next(s for s in publish["steps"] if "--select" in s.get("run", ""))
        for mode, run, artifact, selects in (("build_and_publish", "99", "123", False),
                                            ("publish_approved_candidate", "42", "456", True)):
            with self.subTest(mode=mode):
                self.assertEqual(self.expression(publish["env"]["CANDIDATE_RUN"], mode=mode), run)
                self.assertEqual(self.expression(download["with"]["artifact-ids"], mode=mode), artifact)
                self.assertEqual(self.expression(selection.get("if", "always()"), mode=mode), selects)
        self.assertEqual(download["with"]["run-id"], "${{ env.CANDIDATE_RUN }}")
        self.assertEqual(publish["env"].get("INVENTORY_SHA256"), "${{ needs.finalize.outputs.inventory_sha256 }}")
        commands = "\n".join(s.get("run", "") for s in publish["steps"])
        self.assertIn('--inventory-sha256 "$INVENTORY_SHA256"', commands)

    def test_inline_publication_rejects_missing_finalization_outputs(self):
        steps = self.workflow()["jobs"]["publish"]["steps"]
        gate = next(s for s in steps if "test -n \"$FINALIZED_ARTIFACT_ID\"" in s.get("run", ""))
        download = next(s for s in steps if s.get("uses", "").startswith("actions/download-artifact@"))
        self.assertLess(steps.index(gate), steps.index(download))
        self.assertTrue(self.expression(gate["if"], mode="build_and_publish"))
        self.assertFalse(self.expression(gate["if"], mode="publish_approved_candidate"))
        for artifact, digest, expected in (("123", "a" * 64, 0), ("", "a" * 64, 1),
                                           ("123", "", 1), ("", "", 1)):
            with self.subTest(artifact=artifact, digest=digest):
                result = subprocess.run(["bash", "--noprofile", "--norc", "-e", "-c", gate["run"]],
                                        env={**os.environ, "FINALIZED_ARTIFACT_ID": artifact,
                                             "INVENTORY_SHA256": digest}, capture_output=True)
                self.assertEqual(result.returncode, expected)

    def test_linux_diagnostic_source_gate_tracks_current_version(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/checks.yml').read_text())
        commands = '\n'.join(step.get('run', '') for step in workflow['jobs']['linux-package-diagnostic']['steps'])
        self.assertIn('--version 0.3.2 --mode build_only', commands)

    def test_032_signing_downloads_pinned_stable_before_signing_containers(self):
        workflow = self.workflow()
        self.assertEqual(workflow[True]["workflow_dispatch"]["inputs"]["version"]["default"], "0.3.2")
        commands = "\n".join(step.get("run", "") for step in workflow["jobs"]["sign"]["steps"])
        self.assertLess(commands.index("scripts/download-confirmed-stable.py"),
                        commands.index("scripts/sign-runtime-candidate.py"))
        signing = commands[commands.index("scripts/sign-runtime-candidate.py"):]
        for argument in ("--confirmed-stable", "--stable-public-key", '--version "$RELEASE_VERSION"'):
            self.assertIn(argument, signing)

    def test_checks_android_setup_does_not_request_retired_sdk_tools(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/checks.yml").read_text())
        steps = workflow["jobs"]["android-plugin"]["steps"]
        setup = next(step for step in steps
                     if step.get("uses", "").startswith("android-actions/setup-android@"))
        self.assertEqual(setup.get("with", {}).get("packages"), "",
                         "SDK packages are installed explicitly in the following sdkmanager step")

    def test_checks_install_yaml_before_running_workflow_validator(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/checks.yml").read_text())
        steps = workflow["jobs"]["contracts-python"]["steps"]
        gate = next(index for index, step in enumerate(steps)
                    if "scripts/release-workflow-check.py" in step.get("run", ""))
        dependencies = []
        for step in steps[:gate]:
            command = shlex.split(step.get("run", ""))
            if command[:4] == ["python", "-m", "pip", "install"]:
                dependencies.extend(command[4:])
        self.assertTrue(any(re.split(r"[<>=!~]", value)[0].lower() == "pyyaml"
                            for value in dependencies),
                        "release-workflow-check imports yaml on a fresh CI runner")

    def test_every_source_gate_receives_the_selected_release_mode(self):
        workflow = self.workflow()
        for name, job in workflow["jobs"].items():
            for step in job.get("steps", []):
                for line in step.get("run", "").replace("\\\n", " ").splitlines():
                    if "scripts/release-candidate-gates.py source" not in line:
                        continue
                    command = shlex.split(line)
                    if "scripts/release-candidate-gates.py" not in command or "source" not in command:
                        continue
                    with self.subTest(job=name):
                        self.assertIn("--mode", command)
                        variable = command[command.index("--mode") + 1]
                        self.assertEqual(variable, "$RELEASE_MODE")
                        effective = {**workflow["env"], **job.get("env", {})}[variable[1:]]
                        if name == "publish":
                            self.assertEqual(effective, "publish_approved_candidate")
                        else:
                            for mode, expected in (("build_only", "build_only"),
                                                   ("sign_candidate", "sign_candidate"),
                                                   ("build_and_publish", "sign_candidate")):
                                self.assertEqual(self.expression(effective, mode=mode), expected)

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
            if prefix == "android-actions/setup-android@":
                self.assertEqual(step.get("with", {}).get("packages"), "",
                                 "setup-android must not request the retired SDK tools package")
        ndk = next(step for step in setup if "sdkmanager " in step.get("run", ""))
        self.assertIn("inputs.android-fixtures == 'true'", ndk["if"])
        self.assertIn("ndk;28.2.13676358", ndk["run"])
        self.assertIn("ANDROID_NDK_HOME=", ndk["run"])

    def workflow(self):
        return yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())

    def test_fresh_verify_host_builds_shared_contract_cli_before_python_consumers(self):
        checks = yaml.safe_load((ROOT / ".github/workflows/checks.yml").read_text())
        for name, job in (("release", self.workflow()["jobs"]["verify"]),
                          ("checks", checks["jobs"]["contracts-python"])):
            with self.subTest(workflow=name):
                commands = [step.get("run", "") for step in job["steps"]]
                build = next((index for index, command in enumerate(commands)
                              if "cargo build --locked -p nelomai-contracts --bin verify-runtime-manifest" in command), None)
                self.assertIsNotNone(build, "fresh runner has no shared verifier executable for Python gates")
                gate = next(index for index, command in enumerate(commands) if "scripts/release-workflow-check.py" in command)
                self.assertLess(build, gate)

    def test_only_publication_job_can_write_and_cannot_build_or_sign(self):
        workflow = self.workflow()
        self.assertEqual(workflow["permissions"].get("contents"), "read", "default workflow is not read-only")
        jobs = workflow["jobs"]
        self.assertEqual(jobs["native_drafts"].get("if"), "inputs.mode != 'publish_approved_candidate'",
                         "publication-only runs must not start native builds")
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
        self.assertNotIn("needs", jobs["native_drafts"])
        self.assertEqual(set(jobs["sign"]["needs"]), {"verify", "native_drafts"})
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
                        for mode, expected in (("build_only", ""), ("publish_approved_candidate", ""),
                                               ("sign_candidate", "release-secret"),
                                               ("build_and_publish", "release-secret")):
                            self.assertEqual(self.expression(value, mode=mode), expected)
            keystores = [step for step in jobs[job]["steps"] if "ANDROID_KEYSTORE_BASE64" in step.get("run", "")]
            for step in keystores:
                for mode, enabled in (("build_only", False), ("sign_candidate", True),
                                      ("build_and_publish", True)):
                    self.assertEqual(self.expression(step["if"], mode=mode), enabled)
        self.assertNotIn("needs", jobs["native_drafts"])
        self.assertEqual(set(jobs["sign"]["needs"]), {"verify", "native_drafts"})
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
        self.assertEqual(self.expression(download["with"]["artifact-ids"],
                                         mode="publish_approved_candidate"), "456")
        self.assertEqual(selection["id"], "select")
        self.assertLess(steps.index(selection), steps.index(download))


if __name__ == "__main__":
    unittest.main()
