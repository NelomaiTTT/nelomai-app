"""The stable digest identifies all four final platforms, never one manifest."""
import hashlib
import json
import unittest
import zipfile
import subprocess
from unittest.mock import patch

from scripts.tests.test_runtime_artifact import ArtifactFixture, SOURCE, module


class RuntimeReleaseSetTest(ArtifactFixture):
    def four_candidates(self):
        folder = self.root / "four"
        folder.mkdir()
        for platform, architecture in (("linux", "x86_64"), ("windows", "x86_64"),
                                       ("macos", "aarch64"), ("android", "aarch64")):
            prefix = f"nelomai-runtime-0.2.16-{platform}-{architecture}"
            value = b"authenticated structural fixture only"
            with zipfile.ZipFile(folder / (prefix + ".zip"), "w") as archive:
                info = zipfile.ZipInfo("fixture")
                info.external_attr = 0o100644 << 16
                archive.writestr(info, value)
            body = dict(format_version=1, runtime_version="0.2.16", source_commit=SOURCE,
                platform=platform, architecture=architecture, contract_version=1,
                files=[dict(path="fixture", size_bytes=len(value), role="resource",
                            sha256=hashlib.sha256(value).hexdigest())])
            raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            (folder / (prefix + ".manifest.json")).write_bytes(raw)
            (folder / (prefix + ".manifest.sig")).write_bytes(self.key.sign(b"nelomai-runtime-manifest-v1\0" + raw))
        return folder

    def test_root_signs_all_four_exact_final_artifacts_and_digest_is_root_bytes(self):
        folder = self.four_candidates()
        result = self.command("build-runtime-release-set", "--input-dir", folder,
            "--output", self.root / "root", "--version", "0.2.16", "--source-commit", SOURCE,
            "--signing-key", self.keyfile, "--public-key", self.public)
        self.assertEqual(result.returncode, 0, result.stderr)
        name = "nelomai-runtime-0.2.16-release-set.manifest"
        raw = (self.root / "root" / (name + ".json")).read_bytes()
        signature = (self.root / "root" / (name + ".sig")).read_bytes()
        self.key.public_key().verify(signature, b"nelomai-runtime-release-set-v1\0" + raw)
        manifest = json.loads(raw)
        self.assertEqual(len(manifest["artifacts"]), 4)
        self.assertNotIn("stable_manifest_sha256", manifest)
        for entry in manifest["artifacts"]:
            for kind in ("archive", "manifest", "signature"):
                self.assertEqual(entry[kind + "_sha256"], hashlib.sha256((folder / entry[kind + "_name"]).read_bytes()).hexdigest())
            self.assertNotEqual(entry["manifest_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(json.loads(result.stdout)["stable_manifest_sha256"], hashlib.sha256(raw).hexdigest())

    def test_aggregation_rejects_invalid_signature_source_contract_and_extra_platform(self):
        folder = self.four_candidates()
        prefix = "nelomai-runtime-0.2.16-linux-x86_64"
        manifest = folder / (prefix + ".manifest.json")
        signature = folder / (prefix + ".manifest.sig")
        original = manifest.read_bytes()
        for changes in ({"source_commit": "b" * 40}, {"runtime_version": "0.2.15"},
                        {"contract_version": 2}, {"platform": "windows"}):
            raw = json.dumps({**json.loads(original), **changes}, sort_keys=True, separators=(",", ":")).encode()
            manifest.write_bytes(raw)
            signature.write_bytes(self.key.sign(b"nelomai-runtime-manifest-v1\0" + raw))
            result = self.command("build-runtime-release-set", "--input-dir", folder,
                "--output", self.root / "rejected", "--version", "0.2.16", "--source-commit", SOURCE,
                "--signing-key", self.keyfile, "--public-key", self.public)
            self.assertNotEqual(result.returncode, 0, str(changes))
            self.assertFalse((self.root / "rejected").exists())
        manifest.write_bytes(original)
        signature.write_bytes(bytes(64))
        result = self.command("build-runtime-release-set", "--input-dir", folder,
            "--output", self.root / "rejected", "--version", "0.2.16", "--source-commit", SOURCE,
            "--signing-key", self.keyfile, "--public-key", self.public)
        self.assertNotEqual(result.returncode, 0, "unsigned manifest was aggregated")
        signature.write_bytes(self.key.sign(b"nelomai-runtime-manifest-v1\0" + original))
        duplicate = folder / "duplicate"
        duplicate.mkdir()
        (duplicate / manifest.name).write_bytes(original)
        result = self.command("build-runtime-release-set", "--input-dir", folder,
            "--output", self.root / "rejected", "--version", "0.2.16", "--source-commit", SOURCE,
            "--signing-key", self.keyfile, "--public-key", self.public)
        self.assertNotEqual(result.returncode, 0, "duplicate immutable platform filename was accepted")

    def test_missing_platform_cannot_emit_signed_root(self):
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.command("build-runtime-release-set", "--input-dir", self.root / "candidate",
            "--output", self.root / "root", "--version", "0.2.16", "--source-commit", SOURCE,
            "--signing-key", self.keyfile, "--public-key", self.public)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "root").exists())


class ReleaseAuthorizationTest(ArtifactFixture):
    def test_finalization_requires_its_own_unique_current_environment_approval(self):
        gates = module("release-candidate-gates")
        final = "release-candidate-finalization"
        identities = {gates.SIGNING_ENVIRONMENT: 11, gates.ACCEPTANCE_ENVIRONMENT: 12, final: 13}
        approval = {"state": "approved", "environments": [
            {"name": name, "id": identity} for name, identity in identities.items()]}
        with self.approval_api(gates, reviews=[approval], environment_ids=identities):
            self.assertEqual(gates.check_approvals("example/repo", "42"), identities)
        for final_reviews in ([], [{"state": "approved", "environments": [{"name": final, "id": 9}]}],
                              [{"state": "approved", "environments": [{"name": final, "id": 13}]},
                               {"state": "rejected", "environments": [{"name": final, "id": 13}]}]):
            reviews = [{"state": "approved", "environments": approval["environments"][:2]}] + final_reviews
            with self.approval_api(gates, reviews=reviews, environment_ids=identities):
                with self.assertRaises(ValueError):
                    gates.check_approvals("example/repo", "42")

    def approval_api(self, gates, reviews=None, run_attempt=1, environment_ids=None):
        identities = environment_ids or {gates.SIGNING_ENVIRONMENT: 11, gates.ACCEPTANCE_ENVIRONMENT: 12,
                                         gates.FINALIZATION_ENVIRONMENT: 13}
        run = dict(id=42, run_attempt=run_attempt, event="workflow_dispatch", head_sha=SOURCE,
                   path=".github/workflows/release.yml", repository={"full_name": "example/repo"})
        if reviews is None:
            reviews = [{"state": "approved", "environments": [
                {"name": name, "id": identity} for name, identity in identities.items()]}]
        elif environment_ids is None:
            # Keep earlier acceptance/signing negative cases independent of the
            # additional finalization obligation instead of failing on its absence.
            reviews = reviews + [{"state": "approved", "environments": [
                {"name": gates.FINALIZATION_ENVIRONMENT, "id": 13}]}]
        responses = {"repos/example/repo/actions/runs/42": run,
                     "repos/example/repo/actions/runs/42/approvals": reviews}
        for name, identity in identities.items():
            responses["repos/example/repo/environments/" + name] = {"id": identity, "name": name,
                "protection_rules": [{"type": "required_reviewers", "prevent_self_review": True,
                    "reviewers": [{"type": "User", "reviewer": {"id": 7}}]}]}
        return patch.object(gates, "github_get", side_effect=lambda endpoint: responses[endpoint])

    def test_approval_then_rejection_is_never_current_authorization_in_either_order(self):
        gates = module("release-candidate-gates")
        approval = {"state": "approved", "environments": [
            {"name": gates.SIGNING_ENVIRONMENT, "id": 11}, {"name": gates.ACCEPTANCE_ENVIRONMENT, "id": 12}]}
        rejection = {"state": "rejected", "environments": [{"name": gates.ACCEPTANCE_ENVIRONMENT, "id": 12}]}
        for reviews in ([approval, rejection], [rejection, approval]):
            with self.approval_api(gates, reviews=reviews):
                with self.assertRaises(ValueError):
                    gates.check_approvals("example/repo", "42")

    def test_approval_for_recreated_environment_or_without_id_is_rejected(self):
        gates = module("release-candidate-gates")
        for acceptance in ({"name": gates.ACCEPTANCE_ENVIRONMENT, "id": 10},
                           {"name": gates.ACCEPTANCE_ENVIRONMENT}):
            reviews = [{"state": "approved", "environments": [
                {"name": gates.SIGNING_ENVIRONMENT, "id": 11}, acceptance]}]
            with self.approval_api(gates, reviews=reviews):
                with self.assertRaises(ValueError):
                    gates.check_approvals("example/repo", "42")

    def test_repeated_approval_records_are_ambiguous_and_require_new_run(self):
        gates = module("release-candidate-gates")
        approval = {"state": "approved", "environments": [
            {"name": gates.SIGNING_ENVIRONMENT, "id": 11}, {"name": gates.ACCEPTANCE_ENVIRONMENT, "id": 12}]}
        with self.approval_api(gates, reviews=[approval, approval]):
            with self.assertRaises(ValueError):
                gates.check_approvals("example/repo", "42")

    def test_rerun_cannot_reuse_first_attempt_approval_or_inventory(self):
        gates = module("release-candidate-gates")
        for attempt in (2, None, True):
            with self.approval_api(gates, run_attempt=attempt):
                with self.assertRaises(ValueError):
                    gates.check_approvals("example/repo", "42")

    def test_publishable_inventory_requires_every_exact_installer_digest(self):
        gates = module("release-candidate-gates")
        assets = {name: "d" * 64 for name in (
            "nelomai-0.2.16-linux-x86_64.AppImage", "nelomai-0.2.16-windows-x86_64.exe",
            "nelomai-0.2.16-macos-aarch64.app.tar.gz", "nelomai-0.2.16-android-aarch64.apk")}
        inventory = {"trust": "release", "mode": "sign_candidate", "source_sha": SOURCE,
                     "run_id": "42", "run_attempt": 1, "assets": assets,
                     "environment_ids": {gates.SIGNING_ENVIRONMENT: 11, gates.ACCEPTANCE_ENVIRONMENT: 12,
                                         gates.FINALIZATION_ENVIRONMENT: 13}}
        identities = inventory["environment_ids"]
        gates.require_publishable_inventory(inventory, "42", SOURCE, identities)
        with self.assertRaisesRegex(ValueError, "publishable"):
            gates.require_publishable_inventory({**inventory, "assets": {**assets,
                "nelomai-acceptance-0.2.16-linux-x86_64.AppImage": "e" * 64}}, "42", SOURCE, identities)
        for changes in ({"run_attempt": 2}, {"run_attempt": None}, {"run_attempt": True},
                        {"environment_ids": {gates.SIGNING_ENVIRONMENT: 10, gates.ACCEPTANCE_ENVIRONMENT: 12}}):
            with self.assertRaises(ValueError):
                gates.require_publishable_inventory({**inventory, **changes}, "42", SOURCE, identities)
        for name in assets:
            with self.assertRaises(ValueError, msg=name):
                gates.require_publishable_inventory({**inventory, "assets": {key: value for key, value in assets.items() if key != name}}, "42", SOURCE, identities)

    def test_protection_rule_alone_does_not_substitute_actual_run_approval(self):
        gates = module("release-candidate-gates")
        for reviews in ([], [{"state": "rejected", "environments": [{"name": gates.SIGNING_ENVIRONMENT, "id": 11}]}],
                        [{"state": "approved", "environments": [{"name": gates.SIGNING_ENVIRONMENT, "id": 11}]}]):
            with self.approval_api(gates, reviews=reviews):
                with self.assertRaises(ValueError):
                    gates.check_approvals("example/repo", "42")
        with self.approval_api(gates):
            gates.check_approvals("example/repo", "42")
    def test_default_build_only_and_signing_modes_reject_every_publication_write(self):
        gates = module("release-candidate-gates")
        self.assertTrue(callable(getattr(gates, "mode_policy", None)), "default nonpublishing mode gate is missing")
        self.assertEqual(gates.mode_policy()["contents"], "read")
        self.assertEqual(gates.mode_policy()["trust"], "test")
        for mode in ("build_only", "sign_candidate"):
            for operation in ("create_tag", "create_release", "replace_asset", "retag", "notify"):
                with self.assertRaises(ValueError):
                    gates.require_operation(mode, operation)
        for operation in ("build", "release_sign", "test_sign", "replace_asset", "retag"):
            with self.assertRaises(ValueError):
                gates.require_operation("publish_approved_candidate", operation)
        with self.assertRaises(ValueError):
            gates.require_operation("build_only", "release_sign")

    def test_remote_tag_peels_annotated_refs_and_api_errors_never_mean_missing(self):
        gates = module("release-candidate-gates")
        with patch.object(gates, "github_get", return_value=[]):
            self.assertFalse(gates.check_remote_tag("example/repo", "0.2.16", SOURCE))
        ref = {"ref": "refs/tags/v0.2.16", "object": {"type": "tag", "sha": "c" * 40}}
        with patch.object(gates, "github_get", side_effect=[[ref], {"object": {"type": "commit", "sha": SOURCE}}]) as api:
            self.assertTrue(gates.check_remote_tag("example/repo", "0.2.16", SOURCE))
            self.assertEqual(api.call_args.args[0], "repos/example/repo/git/tags/" + "c" * 40)
        with patch.object(gates, "github_get", side_effect=[[ref], {"object": {"type": "commit", "sha": "d" * 40}}]):
            with self.assertRaises(ValueError):
                gates.check_remote_tag("example/repo", "0.2.16", SOURCE)
        with patch.object(gates, "github_get", side_effect=RuntimeError("API denied")):
            with self.assertRaises(RuntimeError):
                gates.check_remote_tag("example/repo", "0.2.16", SOURCE)

    def test_inventory_rejects_changed_installer_extra_asset_and_missing_retained_bytes(self):
        gates = module("release-candidate-gates")
        assets = self.root / "assets"
        assets.mkdir()
        package = assets / "nelomai-0.2.16-linux-x86_64.AppImage"
        package.write_bytes(b"exact approved package fixture")
        inventory = assets / "candidate-inventory.json"
        inventory.write_text(json.dumps({"assets": {package.name: hashlib.sha256(package.read_bytes()).hexdigest()}}))
        approved = hashlib.sha256(inventory.read_bytes()).hexdigest()
        gates.verify_inventory(assets, inventory, approved)
        original = package.read_bytes()
        package.write_bytes(b"rebuilt changed package")
        with self.assertRaises(ValueError):
            gates.verify_inventory(assets, inventory, approved)
        package.write_bytes(original)
        extra = assets / "extra"
        extra.write_bytes(b"unapproved")
        with self.assertRaises(ValueError):
            gates.verify_inventory(assets, inventory, approved)
        extra.unlink()
        package.unlink()
        with self.assertRaises(ValueError):
            gates.verify_inventory(assets, inventory, approved)

    def test_promotion_rechecks_release_root_with_pinned_release_key_and_all_asset_digests(self):
        gates = module("release-candidate-gates")
        self.assertTrue(callable(getattr(gates, "verify_runtime_release", None)), "promotion runtime trust recheck is missing")
        folder = RuntimeReleaseSetTest.four_candidates(self)
        root = self.root / "root"
        result = self.command("build-runtime-release-set", "--input-dir", folder, "--output", root,
            "--version", "0.2.16", "--source-commit", SOURCE, "--signing-key", self.keyfile, "--public-key", self.public)
        self.assertEqual(result.returncode, 0, result.stderr)
        for path in root.iterdir():
            path.rename(folder / path.name)
        root_sha = json.loads(result.stdout)["stable_manifest_sha256"]
        gates.verify_runtime_release(folder, "0.2.16", SOURCE, root_sha, self.public)
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            gates.verify_runtime_release(folder, "0.2.16", SOURCE, "0" * 64, self.public)
        self.public.write_bytes(bytes(32))
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            gates.verify_runtime_release(folder, "0.2.16", SOURCE, root_sha, self.public)

    def test_source_gate_rejects_mutable_ref_wrong_head_and_merge_history(self):
        gates = module("release-candidate-gates")
        repo = self.root / "repo"
        repo.mkdir()
        def git(*args):
            return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()
        git("init", "-b", "maintenance")
        git("config", "user.name", "Fixture")
        git("config", "user.email", "fixture@example.invalid")
        tracked = repo / "source.txt"
        tracked.write_text("pinned source")
        git("add", "source.txt")
        git("commit", "--allow-empty", "-m", "base")
        base = git("rev-parse", "HEAD")
        git("commit", "--allow-empty", "-m", "candidate")
        source = git("rev-parse", "HEAD")
        gates.verify_source(repo, source, "0.2.16", base=base)
        tracked.write_text("uncommitted source change")
        with self.assertRaises(ValueError):
            gates.verify_source(repo, source, "0.2.16", base=base)
        tracked.write_text("pinned source")
        for invalid in ("main", source[:12], "A" * 40, base):
            with self.assertRaises(ValueError):
                gates.verify_source(repo, invalid, "0.2.16", base=base)
        git("tag", "-a", "v0.2.16", "-m", "candidate", source)
        gates.verify_source(repo, source, "0.2.16", base=base)
        git("tag", "-d", "v0.2.16")
        git("tag", "v0.2.16", base)
        with self.assertRaises(ValueError):
            gates.verify_source(repo, source, "0.2.16", base=base)
        git("tag", "-d", "v0.2.16")
        git("checkout", "-b", "foreign", base)
        git("commit", "--allow-empty", "-m", "foreign work")
        git("checkout", "maintenance")
        git("merge", "--no-ff", "foreign", "-m", "merge")
        with self.assertRaises(ValueError):
            gates.verify_source(repo, git("rev-parse", "HEAD"), "0.2.16", base=base)

    def test_environment_name_without_actual_review_protection_is_rejected(self):
        gates = module("release-candidate-gates")
        for environment in ({}, {"name": "release-candidate-signing", "protection_rules": []},
                            {"protection_rules": [{"type": "required_reviewers", "reviewers": []}]}):
            with self.assertRaises(ValueError):
                gates.require_protected_environment(environment)
        gates.require_protected_environment({"protection_rules": [{
            "type": "required_reviewers", "prevent_self_review": True,
            "reviewers": [{"type": "User", "reviewer": {"id": 1}}]}]})

    def test_manual_self_review_still_requires_configured_reviewers(self):
        gates = module("release-candidate-gates")
        rule = {"type": "required_reviewers", "prevent_self_review": False,
                "reviewers": [{"type": "User", "reviewer": {"id": 149905325}}]}
        gates.require_protected_environment({"protection_rules": [rule]})
        for reviewers in ([], [{"type": "User", "reviewer": {}}]):
            with self.assertRaises(ValueError):
                gates.require_protected_environment({"protection_rules": [{**rule, "reviewers": reviewers}]})

    def test_test_trust_failed_run_or_wrong_source_cannot_be_promoted(self):
        gates = module("release-candidate-gates")
        run = dict(id=42, run_attempt=1, status="completed", conclusion="success", event="workflow_dispatch",
                   head_sha=SOURCE, path=".github/workflows/release.yml", repository={"full_name": "example/repo"})
        gates.require_candidate_run(run, "42", SOURCE, "example/repo")
        for changes in ({"run_attempt": 2}, {"run_attempt": None}, {"run_attempt": True},
                        {"conclusion": "failure"}, {"head_sha": "b" * 40}, {"event": "pull_request"},
                        {"repository": {"full_name": "foreign/repo"}}, {"path": ".github/workflows/other.yml"}):
            with self.assertRaises(ValueError):
                gates.require_candidate_run({**run, **changes}, "42", SOURCE, "example/repo")
        with self.assertRaises(ValueError):
            gates.require_publishable_inventory({"trust": "test", "source_sha": SOURCE, "run_id": "42", "run_attempt": 1}, "42", SOURCE, {})


if __name__ == "__main__":
    unittest.main()
