"""Required static authorization graph checks, complemented by executable gates."""
import re
import shlex
import os
import subprocess
import unittest
import hashlib
import json
import tempfile
import sys
from pathlib import Path
from types import SimpleNamespace
import yaml
import zipfile

from scripts.tests.test_runtime_artifact import ROOT, module


class ReleaseWorkflowTest(unittest.TestCase):
    def test_windows_defender_preflight_uses_captured_reserve_route_and_keeps_saved_guard(self):
        checker = module("release-workflow-check")
        intent = (ROOT / "src-tauri/src/connection_intent.rs").read_text()
        commands = (ROOT / "src-tauri/src/commands.rs").read_text()
        checker.assert_windows_defender_preflight_routing(intent, commands)
        mutations = (
            (intent.replace("&initial_preflight, reserve_requested)", "&initial_preflight, false)"), commands),
            (intent.replace("state.reserve_requested,", "false,"), commands),
            (intent.replace("&& !desktop_reserve_eligible(options, reserve_requested)", ""), commands),
            (intent.replace("&& !desktop_reserve_eligible(options, reserve_requested)",
                            "&& desktop_reserve_eligible(options, reserve_requested)"), commands),
            (intent.replace("options.layer == nelomai_contracts::Layer::Stray", "true"), commands),
            (intent, commands.replace("    ensure_defender_ready_for_awg(&diagnostics).await?;", "")),
        )
        for index, (changed_intent, changed_commands) in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assertNotEqual((changed_intent, changed_commands), (intent, commands))
                with self.assertRaisesRegex(RuntimeError, "captured reserve routing"):
                    checker.assert_windows_defender_preflight_routing(changed_intent, changed_commands)

    def test_windows_build_artifact_is_source_bound_and_every_byte_is_checked(self):
        artifact = module("windows/carrier-factory-artifact")
        self.assertIn("nelomai-windows-worker.exe", artifact.RUNTIME_FILES)
        self.assertIn("worker-peers.exe", artifact.PAYLOAD_FILES)
        source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = root / "input"
            runtime.mkdir()
            test = root / "suite.exe"
            test.write_bytes(b"service library test bytes")
            peer = root / "peers.exe"
            peer.write_bytes(b"worker external peer test bytes")
            for name in artifact.RUNTIME_FILES:
                (runtime / name).write_bytes(name.encode())
            output = root / "artifact"
            digest = artifact.create(test, runtime, output, source, peer)
            artifact.verify(output, source, digest)
            for relative in artifact.PAYLOAD_FILES:
                with self.subTest(file=relative):
                    path = output / relative
                    original = path.read_bytes()
                    path.write_bytes(original + b"changed")
                    with self.assertRaises(ValueError):
                        artifact.verify(output, source, digest)
                    path.write_bytes(original)
            manifest = output / "manifest.json"
            original = manifest.read_bytes()
            data = json.loads(original)
            data["source_sha"] = "0" * 40
            manifest.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                artifact.verify(output, source, digest)  # external build digest, not self-described
            with self.assertRaises(ValueError):
                artifact.verify(output, source, hashlib.sha256(manifest.read_bytes()).hexdigest())
            data["source_sha"] = source
            data["files"]["../outside"] = data["files"].pop("runtime/wintun.dll")
            manifest.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                artifact.verify(output, source, hashlib.sha256(manifest.read_bytes()).hexdigest())
            manifest.write_bytes(original)
            with self.assertRaises(ValueError):
                artifact.verify(output, "0" * 40, digest)  # actual checkout HEAD remains mandatory
            with self.assertRaises(ValueError):
                artifact.verify(output, source, "")  # missing build output cannot fall back
            outputs = root / "github-output"
            cli_output = root / "cli-artifact"
            name = "windows-factory-99-1-" + source
            subprocess.run([sys.executable, str(ROOT / "scripts/windows/carrier-factory-artifact.py"), "create",
                            "--test-executable", str(test), "--peer-executable", str(peer), "--runtime-directory", str(runtime),
                            "--output", str(cli_output), "--source-sha", source, "--artifact-name", name],
                           env={**os.environ, "GITHUB_OUTPUT": str(outputs)}, check=True)
            self.assertEqual(outputs.read_text().splitlines(), ["manifest_sha256=" + digest, "artifact_name=" + name])
            subprocess.run([sys.executable, str(ROOT / "scripts/windows/carrier-factory-artifact.py"), "verify",
                            "--directory", str(cli_output), "--source-sha", source, "--manifest-sha256", digest], check=True)

    def test_windows_artifact_rejects_extra_missing_and_nonregular_paths(self):
        artifact = module("windows/carrier-factory-artifact")
        source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = root / "input"
            runtime.mkdir()
            test = root / "suite.exe"
            test.write_bytes(b"suite")
            peer = root / "peers.exe"
            peer.write_bytes(b"peers")
            for name in artifact.RUNTIME_FILES:
                (runtime / name).write_bytes(name.encode())
            output = root / "artifact"
            digest = artifact.create(test, runtime, output, source, peer)
            for directory in (False, True):
                extra = output / "unexpected"
                extra.mkdir() if directory else extra.write_bytes(b"extra")
                with self.assertRaises(ValueError):
                    artifact.verify(output, source, digest)
                extra.rmdir() if directory else extra.unlink()
            path = output / "factory-tests.exe"
            path.unlink()
            with self.assertRaises(ValueError):
                artifact.verify(output, source, digest)
            path.mkdir()
            with self.assertRaises(ValueError):
                artifact.verify(output, source, digest)
            path.rmdir()
            path.symlink_to(test)
            with self.assertRaises(ValueError):
                artifact.verify(output, source, digest)
            path.unlink()
            path.write_bytes(b"suite")
            original_runtime = root / "original-runtime"
            (output / "runtime").rename(original_runtime)
            (output / "runtime").symlink_to(original_runtime, target_is_directory=True)
            with self.assertRaises(ValueError):
                artifact.verify(output, source, digest)

    def test_windows_factory_build_and_native_graph_rejects_guard_bypasses(self):
        import copy
        checker = module("release-workflow-check")
        workflow = yaml.safe_load((ROOT / ".github/workflows/checks.yml").read_text())
        factory = (ROOT / "crates/windows-service/src/windows/member_carrier_factory_native_tests.rs").read_text()
        cases = ["primary", "standby", "retire-stop", "hot-pair-stop", "network-route-postflight",
                 "metrics-post-read-error", "module-load-read-error", "module-load-read-unwind",
                 "resolver-reference-error", "resolver-reference-unwind", "carrier-ack", "carrier-unwind",
                 "member-ack", "member-unwind", "running-ack", "running-unwind", "cold", "primary-data-denial",
                 "creator-ack", "initial-native-ack", "initial-native-unwind", "fresh-ack", "starting-ack"]
        # A pending workflow edit must not make an incomplete real matrix PASS.
        # Exercise the exact proposed inventory without modifying that workflow.
        if workflow["jobs"]["windows-native"]["strategy"]["matrix"]["case"] != cases:
            with self.assertRaises(RuntimeError):
                checker.assert_windows_factory_jobs(workflow, factory)
            workflow = copy.deepcopy(workflow)
            workflow["jobs"]["windows-native"]["strategy"]["matrix"]["case"] = cases
        artifact = next(step for step in workflow["jobs"]["windows-build"]["steps"]
                        if step.get("name") == "Assemble exact factory test artifact")
        self.assertIn("cargo test --release --locked", artifact["run"])
        self.assertEqual(workflow["jobs"]["windows-native"]["steps"][-1], {
            "name": "Retain actual factory diagnostics",
            "if": "always()",
            "uses": "actions/upload-artifact@v4",
            "with": {
                "name": "windows-native-result-${{ github.run_id }}-${{ github.run_attempt }}-${{ github.sha }}-${{ matrix.case }}",
                "path": "${{ runner.temp }}/carrier-factory-system-*/factory.log\n"
                        "${{ runner.temp }}/carrier-factory-system-*/factory.log.stdout\n"
                        "${{ runner.temp }}/carrier-factory-system-*/factory.log.stderr\n"
                        "${{ runner.temp }}/carrier-factory-system-*/result.json\n"
                        "${{ runner.temp }}/carrier-factory-system-*/etw-*\n",
                "if-no-files-found": "warn",
                "retention-days": 1,
            },
        })
        build = workflow["jobs"]["windows-build"]
        for event, ref, expected in (
            ("push", "refs/heads/Future/desktop-0.4.0", "windows-latest"),
            ("push", "refs/heads/main", "windows-latest"),
            ("push", "refs/heads/Future/another-branch", "windows-latest"),
            ("push", "refs/tags/0.4.0", "windows-latest"),
            ("pull_request", "refs/pull/42/merge", "windows-latest"),
            ("pull_request", "refs/heads/Future/desktop-0.4.0", "windows-latest"),
            ("pull_request_target", "refs/heads/Future/desktop-0.4.0", "windows-latest"),
            ("workflow_dispatch", "refs/heads/Future/desktop-0.4.0", "windows-latest"),
        ):
            with self.subTest(event=event, ref=ref):
                selected = self.expression(build["runs-on"], mode="build_only", context={
                    "github": SimpleNamespace(event_name=event, ref=ref),
                }) if build["runs-on"].startswith("${{") else build["runs-on"]
                self.assertEqual(selected, expected)
        checker.assert_windows_factory_jobs(workflow, factory)
        mutations = (
            lambda jobs: jobs["windows-build"].update(**{"runs-on": ["self-hosted", "Windows", "x64", "nelomai-040-worker-host"]}),
            lambda jobs: jobs["windows-build"]["steps"][-2].update(
                run=jobs["windows-build"]["steps"][-2]["run"].replace("--release ", "")),
            lambda jobs: jobs["windows"]["needs"].remove("windows-build"),
            lambda jobs: jobs["windows"]["steps"][0].update(run='test "$NATIVE_RESULT" = success'),
            lambda jobs: jobs["windows-native"].update(needs=[]),
            lambda jobs: jobs["windows-native"]["strategy"]["matrix"]["case"].pop(),
            lambda jobs: jobs["windows-native"]["steps"][2]["with"].update(name="old-artifact"),
            lambda jobs: jobs["windows-native"]["env"].update(MANIFEST_SHA256="self-described"),
            lambda jobs: jobs["windows-native"]["steps"][3].update(run="echo verify skipped"),
            lambda jobs: jobs["windows-native"]["steps"][4].update(**{"continue-on-error": True}),
            lambda jobs: jobs["windows-native"]["steps"][4].update(**{"if": "always()"}),
            lambda jobs: jobs["windows-native"]["steps"][-1].update(**{"if": "success()"}),
            lambda jobs: jobs["windows-native"]["steps"][-1]["with"].update(
                path="${{ runner.temp }}/factory-artifact/"),
            lambda jobs: jobs["windows-native"]["steps"][-1]["with"].update(
                name="windows-native-result"),
            lambda jobs: jobs["windows-native"]["steps"].pop(),
            lambda jobs: jobs["windows-build"]["steps"][5].update(run="cargo check -p nelomai-windows-service"),
            lambda jobs: jobs["windows-build"]["steps"][-1].update(**{"if": "always()"}),
            lambda jobs: jobs["windows-build"]["steps"][-1]["with"].update(**{"retention-days": 14}),
            lambda jobs: jobs["windows-build"]["steps"][8].update(run="cargo build -p nelomai-windows-service"),
            lambda jobs: jobs["windows-build"]["steps"].insert(8, jobs["windows-build"]["steps"].pop(
                next(index for index, step in enumerate(jobs["windows-build"]["steps"])
                     if step.get("name") == "Actual factory runtime input"))),
            lambda jobs: jobs["contracts-python"].update(steps=[
                step for step in jobs["contracts-python"]["steps"]
                if step.get("name") != "Isolated contracts Rustup home"]),
            lambda jobs: jobs["contracts-python"]["steps"][4].update(
                run='echo "RUSTUP_HOME=/home/runner/.rustup" >> "$GITHUB_ENV"'),
            lambda jobs: jobs["contracts-python"]["steps"].append(
                jobs["contracts-python"]["steps"].pop(4)),
            lambda jobs: jobs["contracts-python"].update(env={"RUSTUP_HOME": "${{ runner.temp }}/nelomai-contracts-rustup"}),
            lambda jobs: jobs["windows-native"].update(**{"if": "github.event_name != 'workflow_dispatch'"}),
            lambda jobs: jobs["windows-native"].update(**{"runs-on": "nelomai-040-worker-host"}),
            lambda jobs: jobs["windows-native"]["strategy"]["matrix"]["case"].__setitem__(1, "primary"),
            lambda jobs: jobs["windows-build"]["steps"][3]["with"].update(**{"go-version": "latest"}),
            lambda jobs: jobs["windows-worker-native"].update(**{"if": "always()"}),
            lambda jobs: jobs["windows-worker-native"].update(**{"runs-on": "windows-2022"}),
            lambda jobs: jobs["windows-worker-native"]["concurrency"].update(**{"cancel-in-progress": True}),
            lambda jobs: jobs["windows-worker-native"]["steps"][0]["with"].update(ref="main"),
            lambda jobs: jobs["windows-worker-native"]["steps"][2].update(run="echo native skipped"),
            lambda jobs: jobs["windows-worker-native"]["steps"][2].update(**{"continue-on-error": True}),
            lambda jobs: jobs["windows-worker-native"]["env"].update(
                NELOMAI_WORKER_PEER_ADDRESS="${{ vars.NELOMAI_WORKER_PEER_ADDRESS }}"),
            lambda jobs: jobs["windows-worker-native"]["steps"][2].update(
                run=jobs["windows-worker-native"]["steps"][2]["run"].replace(
                    "-InterfaceAlias 'vEthernet (Default Switch)'", "-InterfaceAlias 'Ethernet'")),
            lambda jobs: jobs["windows-worker-native"]["steps"][2].update(
                run=jobs["windows-worker-native"]["steps"][2]["run"].replace(
                    "$peerAddresses.Count -ne 1", "$peerAddresses.Count -lt 1")),
            lambda jobs: jobs["windows-worker-native"]["steps"][2].update(
                run=jobs["windows-worker-native"]["steps"][2]["run"].replace(
                    "-PeerAddress $peerAddresses[0].IPAddress", "-PeerAddress $env:NELOMAI_WORKER_PEER_ADDRESS")),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                changed = copy.deepcopy(workflow)
                mutate(changed["jobs"])
                with self.assertRaises((RuntimeError, KeyError, ValueError)):
                    checker.assert_windows_factory_jobs(changed, factory)
        for unified in ("true", "false"):
            for build in ("success", "failure", "skipped", "cancelled"):
                for native in ("success", "failure", "skipped", "cancelled"):
                    result = subprocess.run(["bash", "-e", "-c", workflow["jobs"]["windows"]["steps"][0]["run"]],
                                            env={**os.environ, "BUILD_RESULT": build, "NATIVE_RESULT": native,
                                                 "UNIFIED_PUSH": unified}, capture_output=True)
                    expected = build == "success" and native == ("skipped" if unified == "true" else "success")
                    self.assertEqual(result.returncode == 0, expected, (unified, build, native))
        with self.assertRaises(RuntimeError):
            checker.assert_windows_factory_jobs(workflow, factory.replace("None => cases.len() + 4", "None => cases.len()"))

    def test_worker_native_is_opt_in_manual_diagnostic_only(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/checks.yml").read_text())
        inputs = (workflow.get("on", workflow.get(True))["workflow_dispatch"] or {}).get("inputs", {})
        self.assertIn("windows_worker_native", inputs)
        self.assertEqual(inputs["windows_worker_native"]["type"], "boolean")
        self.assertIs(inputs["windows_worker_native"]["default"], False)
        self.assertEqual(workflow["jobs"]["windows"]["needs"], ["windows-build", "windows-native"])
        repo = "NelomaiTTT/nelomai-app"
        for event, ref, repository, opt_in, expected in (
            ("push", "refs/heads/Future/desktop-0.4.0", repo, False, (True, False, False, True, False)),
            ("push", "refs/heads/main", repo, False, (True, True, False, True, False)),
            ("pull_request", "refs/pull/42/merge", repo, False, (True, True, False, True, False)),
            ("workflow_dispatch", "refs/heads/Future/desktop-0.4.0", repo, False, (False, False, False, False, True)),
            ("workflow_dispatch", "refs/heads/Future/desktop-0.4.0", repo, True, (True, False, True, False, False)),
            ("workflow_dispatch", "refs/heads/main", repo, True, (False, False, False, False, False)),
            ("workflow_dispatch", "refs/heads/Future/desktop-0.4.0", "fork/app", True, (False, False, False, False, False)),
            ("push", "refs/heads/Future/desktop-0.4.0", repo, True, (True, False, False, True, False)),
        ):
            with self.subTest(event=event, ref=ref, repository=repository, opt_in=opt_in):
                context = {"github": SimpleNamespace(event_name=event, ref=ref, repository=repository),
                           "inputs": SimpleNamespace(windows_worker_native=opt_in)}
                actual = tuple(bool(self.expression(workflow["jobs"][name]["if"], mode="build_only", context=context))
                               for name in ("windows-build", "windows-native", "windows-worker-native", "windows", "linux-package-diagnostic"))
                self.assertEqual(actual, expected)

    def expression(self, expression, *, mode, result="success", cancelled=False, context=None):
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
                "NELOMAI_MACOS_SIGNING_P12_BASE64", "NELOMAI_MACOS_SIGNING_P12_PASSWORD",
                "ANDROID_KEY_ALIAS", "ANDROID_KEYSTORE_PASSWORD", "ANDROID_KEY_PASSWORD")}),
            "always": lambda: True, "cancelled": lambda: cancelled,
            "fromJSON": json.loads, "toJSON": json.dumps, **(context or {}),
        })

    def test_windows_candidate_build_and_package_use_hosted_runners(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/windows-candidate.yml").read_text())
        for name in ("build", "package"):
            with self.subTest(job=name):
                self.assertEqual(workflow["jobs"][name]["runs-on"], "windows-latest")

    def test_build_and_publish_uses_existing_signed_candidate_pipeline(self):
        workflow = self.workflow()
        self.assertIn("build_and_publish", workflow[True]["workflow_dispatch"]["inputs"]["mode"]["options"])
        for mode, expected in (("build_only", "build_only"), ("sign_candidate", "sign_candidate"),
                               ("build_and_publish", "sign_candidate"),
                               ("publish_approved_candidate", "publish_approved_candidate")):
            with self.subTest(mode=mode):
                self.assertEqual(self.expression(workflow["env"]["RELEASE_MODE"], mode=mode), expected)

    def test_common_signing_is_protected_keyless_builds_stay_keyless(self):
        jobs = self.workflow()["jobs"]
        self.assertIn("macos_common_sign", jobs, "missing isolated macOS signing phase")
        job = jobs["macos_common_sign"]
        self.assertEqual(job["runs-on"], "macos-14")
        self.assertEqual(job["environment"], "release-candidate-finalization")
        self.assertEqual(set(job["needs"]), {"native_packages", "sign"})
        for mode, enabled in (("publish_approved_candidate", False), ("build_only", True),
                              ("sign_candidate", True), ("build_and_publish", True)):
            self.assertEqual(self.expression(job["if"], mode=mode), enabled)
        signing = [s for s in job["steps"] if "sign-macos-common-package.py" in s.get("run", "")]
        self.assertEqual(len(signing), 1)
        for name in ("NELOMAI_MACOS_SIGNING_P12_BASE64", "NELOMAI_MACOS_SIGNING_P12_PASSWORD"):
            value = signing[0]["env"][name]
            for mode, expected in (("build_only", ""), ("publish_approved_candidate", ""),
                                   ("sign_candidate", "release-secret"), ("build_and_publish", "release-secret")):
                self.assertEqual(self.expression(value, mode=mode), expected)
            # Credentials must not escape into build steps/job/global env.
            for other_name, other in jobs.items():
                for step in other.get("steps", []):
                    if other_name != "macos_common_sign" or step is not signing[0]:
                        self.assertNotIn(name, step.get("env", {}))
                self.assertNotIn(name, other.get("env", {}))
            self.assertNotIn(name, self.workflow().get("env", {}))
        downloads = [s["with"]["name"] for s in job["steps"] if s.get("uses", "").startswith("actions/download-artifact@")]
        self.assertEqual(downloads, ["packages-macos"])

    def test_finalization_consumes_only_common_signed_macos_artifact(self):
        jobs = self.workflow()["jobs"]
        self.assertIn("macos_common_sign", jobs["finalize"]["needs"])
        downloads = [s["with"] for s in jobs["finalize"]["steps"] if s.get("uses", "").startswith("actions/download-artifact@")]
        signed = [d for d in downloads if d.get("name") == "signed-common-macos"]
        self.assertEqual(signed, [{"name": "signed-common-macos", "path": "packages/macos"}])
        # Execute the actual platform separation shell in a scratch tree. The
        # unsigned macOS artifact must not be moved into the final input.
        step = next(s for s in jobs["finalize"]["steps"] if s.get("name") == "Keep platform and purpose separation")
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            for platform in ("macos", "linux", "windows", "android"):
                p = Path(tmp) / "package-downloads" / ("packages-" + platform)
                p.mkdir(parents=True)
                (p / "marker").write_text(platform)
            subprocess.run(["bash", "-eu", "-c", step["run"]], cwd=tmp, check=True)
            self.assertFalse((Path(tmp) / "packages/macos").exists())
            for platform in ("linux", "windows", "android"):
                self.assertEqual((Path(tmp) / "packages" / platform / "marker").read_text(), platform)

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
        self.assertIn('--version 0.4.0 --mode build_only', commands)

    def test_032_signing_downloads_pinned_stable_before_signing_containers(self):
        workflow = self.workflow()
        self.assertEqual(workflow[True]["workflow_dispatch"]["inputs"]["version"]["default"], "0.4.0")
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

    def test_native_host_node24_opt_in_preserves_legacy_default_and_signing_exclusion(self):
        action = yaml.safe_load((ROOT / ".github/actions/release-native-host/action.yml").read_text())
        default = action["inputs"]["node24"]["default"]
        self.assertEqual(default, "false")
        nodes = [step for step in action["runs"]["steps"]
                 if step.get("uses", "").startswith("actions/setup-node@")]
        self.assertEqual([step["uses"] for step in nodes],
                         ["actions/setup-node@v4", "actions/setup-node@v7.1.0"])
        for step in nodes:
            self.assertEqual(step["with"], {"node-version-file": ".nvmrc", "cache": "npm"})
        for purpose in ("build", "packaging", "signing", "finalization"):
            for node24 in (default, "true"):
                with self.subTest(purpose=purpose, node24=node24):
                    selected = [step["uses"] for step in nodes if self.expression(
                        step["if"], mode="build_only",
                        context={"inputs": SimpleNamespace(purpose=purpose, node24=node24)})]
                    expected = [] if purpose == "signing" else [
                        "actions/setup-node@v7.1.0" if node24 == "true" else "actions/setup-node@v4"]
                    self.assertEqual(selected, expected)

    def test_discovery_host_provisions_mandatory_compiled_android_fixtures(self):
        steps = self.workflow()["jobs"]["verify"]["steps"]
        host = next(step for step in steps if step.get("uses") == "./.github/actions/release-native-host")
        self.assertEqual(str(host["with"].get("android-fixtures")).lower(), "true",
                         "discovery executes mandatory Android fixtures without its toolchain")
        action = yaml.safe_load((ROOT / ".github/actions/release-native-host/action.yml").read_text())
        setup = action["runs"]["steps"]
        go = next(step for step in setup if step.get("uses") == "actions/setup-go@v5")
        self.assertEqual(go["if"], "inputs.purpose == 'build'",
                         "Windows candidate worker build must use the pinned Go toolchain")
        self.assertEqual(go["with"]["go-version"], "1.26.10")
        self.assertIn("\ngo 1.25.0\n", (ROOT / "workers/windows-go/go.mod").read_text())
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

        runtime = (ROOT / "scripts/windows/prepare-runtime.ps1").read_text()
        replacement = re.search(
            r"\$amneziaBuildText\.Replace\(\s*\$amneziaArchiveExtractor,\s*'([^']+)'\s*\)", runtime)
        self.assertIsNotNone(replacement, "pinned Amnezia ZIP extraction still uses system tar")
        self.assertIn("[regex]::Matches($amneziaBuildText, [regex]::Escape($amneziaArchiveExtractor)).Count -ne 1", runtime)
        self.assertIn("$amneziaArchiveExtractor = 'tar -xf %1 %~4 || exit /b 1'", runtime)
        command, failure = replacement.group(1).split(" || ")
        self.assertEqual(failure, "exit /b 1")
        arguments = shlex.split(command)
        self.assertEqual(arguments, ["python", "-m", "zipfile", "-e", "%1", "."])
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            archive = directory / "go.zip"
            output = directory / "extracted"
            output.mkdir()
            paths = ("go/test/fixedbugs/issue27836.dir/Äfoo.go", "go/test/fixedbugs/issue27836.dir/Äfoo_test.go")
            with zipfile.ZipFile(archive, "w") as zipped:
                for path in paths:
                    zipped.writestr(path, path.encode("utf-8"))
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            result = subprocess.run([sys.executable, *[str(archive) if value == "%1" else value for value in arguments[1:]]],
                                    cwd=output, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), digest)
            for path in paths:
                self.assertEqual((output / path).read_bytes(), path.encode("utf-8"))
            archive.write_bytes(b"not a ZIP archive")
            result = subprocess.run([sys.executable, *[str(archive) if value == "%1" else value for value in arguments[1:]]],
                                    cwd=output, capture_output=True)
            self.assertNotEqual(result.returncode, 0)

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
        checks = yaml.safe_load((ROOT / ".github/workflows/checks.yml").read_text())
        draft_windows = next(row for row in jobs["native_drafts"]["strategy"]["matrix"]["include"]
                             if row["platform"] == "windows")
        checks_runner = checks["jobs"]["windows-build"]["runs-on"]
        hosted_runner = self.expression(checks_runner, mode="build_only", context={
            "github": SimpleNamespace(event_name="pull_request", ref="refs/pull/42/merge"),
        }) if checks_runner.startswith("${{") else checks_runner
        self.assertEqual(draft_windows["runner"], hosted_runner,
                         "Windows draft fallback must retain the hosted checks build runner")
        package_windows = next(row for row in jobs["native_packages"]["strategy"]["matrix"]["include"]
                               if row["platform"] == "windows")
        self.assertEqual(package_windows["runner"], "windows-2022")
        # Native release builds use their hosted matrix runner in every mode.
        for name in ("native_drafts", "native_packages"):
            for row in jobs[name]["strategy"]["matrix"]["include"]:
                for mode in ("build_only", "sign_candidate", "build_and_publish", "publish_approved_candidate"):
                    for event, ref, sha in (
                        ("workflow_dispatch", "refs/heads/Future/desktop-0.4.0", "a" * 40),
                        ("push", "refs/heads/Future/desktop-0.4.0", "a" * 40),
                        ("pull_request", "refs/heads/Future/desktop-0.4.0", "a" * 40),
                        ("pull_request_target", "refs/heads/Future/desktop-0.4.0", "a" * 40),
                        ("workflow_dispatch", "refs/heads/main", "a" * 40),
                        ("workflow_dispatch", "refs/heads/Future/another-branch", "a" * 40),
                        ("workflow_dispatch", "refs/tags/0.4.0", "a" * 40),
                        ("workflow_dispatch", "refs/heads/Future/desktop-0.4.0", "b" * 40),
                    ):
                        with self.subTest(job=name, platform=row["platform"], mode=mode, event=event, ref=ref, sha=sha):
                            selected = self.expression(jobs[name]["runs-on"], mode=mode, context={
                                "inputs": SimpleNamespace(mode=mode, source_sha="a" * 40),
                                "github": SimpleNamespace(event_name=event, ref=ref, sha=sha),
                                "matrix": SimpleNamespace(**row),
                            })
                            self.assertEqual(selected, row["runner"])
        for name, script, expected in (
            ("native_drafts", "scripts/build-release-platform.py", [
                "--mode", "$RELEASE_MODE", "--source-sha", "$SOURCE_SHA", "--platform", "$PLATFORM",
                "--architecture", "$ARCHITECTURE", "--public-key", "$RUNNER_TEMP/runtime-public.raw",
                "--output", "$RUNNER_TEMP/draft/$PLATFORM", "--work", "$RUNNER_TEMP/native-work"]),
            ("native_packages", "scripts/package-release-platform.py", [
                "--mode", "$RELEASE_MODE", "--source-sha", "$SOURCE_SHA", "--release-set-sha256", "$ROOT_SHA256",
                "--platform", "$PLATFORM", "--architecture", "$ARCHITECTURE", "--signed", "signed",
                "--draft", "draft/$PLATFORM", "--public-key", "$RUNNER_TEMP/runtime-public.raw",
                "--output", "packages/$PLATFORM"]),
        ):
            consumers = [step for step in jobs[name]["steps"] if script in step.get("run", "")]
            for row in jobs[name]["strategy"]["matrix"]["include"]:
                for mode in ("build_only", "sign_candidate", "build_and_publish", "publish_approved_candidate"):
                    with self.subTest(job=name, platform=row["platform"], mode=mode):
                        selected = [step for step in consumers if self.expression(
                            step.get("if", "True"), mode=mode, context={"matrix": SimpleNamespace(**row)})]
                        self.assertEqual(len(selected), 1, "exactly one native phase must run")
                        step = selected[0]
                        self.assertEqual(step.get("shell", workflow["defaults"]["run"]["shell"]),
                                         "pwsh" if row["platform"] == "windows" else "bash")
                        command = next(line for line in step["run"].replace("\\\n", " ").replace("`\n", " ").splitlines()
                                       if line.strip().startswith("python "))
                        arguments = shlex.split(command)
                        if arguments[-1] == "${extra[@]}":
                            arguments.pop()
                        self.assertEqual([value.replace("$env:", "$") for value in arguments],
                                         ["python", script, *expected])
        self.assertEqual(jobs["sign"]["runs-on"], "ubuntu-22.04")
        self.assertEqual(jobs["finalize"]["runs-on"], "ubuntu-22.04")
        self.assertEqual(jobs["macos_common_sign"]["runs-on"], "macos-14")
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
        packages = workflow["jobs"]["native_packages"]
        downloads = [step for step in packages["steps"] if step.get("uses") == "actions/download-artifact@v4"]
        signed = next(step for step in downloads if step["with"]["name"] == "signed-runtime")
        draft = next(step for step in downloads if step["with"]["name"] == "draft-${{ matrix.platform }}")
        for platform, required in (("linux", True), ("windows", False), ("macos", True), ("android", True)):
            for mode in ("build_only", "sign_candidate", "build_and_publish", "publish_approved_candidate"):
                with self.subTest(platform=platform, mode=mode):
                    context = {"matrix": SimpleNamespace(platform=platform)}
                    self.assertTrue(self.expression(signed.get("if", "True"), mode=mode, context=context))
                    self.assertEqual(self.expression(draft.get("if", "True"), mode=mode, context=context), required)
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
        self.assertEqual(set(jobs["finalize"]["needs"]), {"native_packages", "sign", "macos_common_sign"})

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
