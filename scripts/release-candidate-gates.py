#!/usr/bin/env python3
"""Release authorization checks; no private key discovery and no write API.

All GitHub calls are GET. Only the separate publication job may create a
release, after this module has rechecked pinned source and retained bytes.
Only first attempts with unique reviews for current environment IDs qualify.
Failed/rejected attempts or ambiguous review history require a new workflow
run and fresh approvals; GitHub's rerun action cannot reuse these approvals.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

BASE = "632cc4b40872c559a75e5d7104b72bae17ac91c3"
SIGNING_ENVIRONMENT = "release-candidate-signing"
ACCEPTANCE_ENVIRONMENT = "release-candidate-acceptance"
PUBLICATION_ENVIRONMENT = "release-publication"


def mode_policy(mode="build_only"):
    """Necessary mode restriction, never sufficient proof of environment approval."""
    if mode == "build_only":
        return {"contents": "read", "trust": "test", "environments": [],
                "operations": ["build", "test_sign", "verify", "upload_candidate"]}
    if mode == "sign_candidate":
        return {"contents": "read", "trust": "release",
                "environments": [SIGNING_ENVIRONMENT, ACCEPTANCE_ENVIRONMENT],
                "operations": ["build", "release_sign", "verify", "upload_candidate", "accept"]}
    if mode == "publish_approved_candidate":
        return {"contents": "write", "trust": "release", "environments": [PUBLICATION_ENVIRONMENT],
                "operations": ["verify", "create_tag", "create_release", "notify"]}
    raise ValueError("unknown release mode")


def require_operation(mode, operation):
    if operation not in mode_policy(mode)["operations"]:
        raise ValueError("release operation is forbidden in this mode")


def git(root, *args, allow_missing=False):
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)
    if result.returncode:
        if allow_missing and result.returncode == 1:
            return None
        raise ValueError("source check failed: " + result.stderr.strip())
    return result.stdout.strip()


def full_source(source):
    if not isinstance(source, str) or not re.fullmatch("[0-9a-f]{40}", source):
        raise ValueError("source_sha must be full lowercase 40-hex")


def verify_source(root, source, version, *, base=BASE):
    full_source(source)
    if version != "0.2.16":
        raise ValueError("this maintenance workflow only builds 0.2.16")
    if git(root, "rev-parse", "HEAD") != source:
        raise ValueError("checkout HEAD differs from source_sha")
    # Run before generated build inputs/parent-managed vendor patches. Never
    # repair a dirty caller checkout: only a clean pinned checkout can pass.
    git(root, "diff", "--exit-code", "--ignore-submodules=none", "HEAD", "--")
    git(root, "merge-base", "--is-ancestor", base, source)
    # This maintenance line is linear. Rejecting every merge after the base
    # closes main/hot-standby merges even after their branch refs disappear.
    if git(root, "rev-list", "--merges", base + ".." + source):
        raise ValueError("maintenance source must not contain merges")
    tag = "refs/tags/v" + version
    if git(root, "show-ref", "--verify", "--quiet", tag, allow_missing=True) is not None:
        if git(root, "rev-parse", tag + "^{}") != source:
            raise ValueError("existing peeled tag differs from source_sha")


def require_protected_environment(environment):
    rules = environment.get("protection_rules", [])
    approval = [rule for rule in rules if rule.get("type") == "required_reviewers"]
    if (len(approval) != 1
            or approval[0].get("prevent_self_review") is not True
            or not approval[0].get("reviewers")
            or not all(reviewer.get("reviewer", {}).get("id") for reviewer in approval[0]["reviewers"])):
        raise ValueError("environment requires configured reviewers and no self-review")


def require_first_attempt(run, run_id, run_attempt=1):
    # Review history has no documented deployment-attempt association. Never
    # reuse that history for a rerun or infer freshness from record ordering.
    if (type(run_attempt) is not int or run_attempt != 1
            or type(run.get("run_attempt")) is not int or run["run_attempt"] != run_attempt
            or not re.fullmatch(r"[1-9][0-9]*", str(run_id)) or str(run.get("id")) != str(run_id)):
        raise ValueError("approval requires the first attempt of a new workflow run")


def require_candidate_run(run, run_id, source, repository, run_attempt=1):
    require_first_attempt(run, run_id, run_attempt)
    full_source(source)
    if (run.get("status") != "completed" or run.get("conclusion") != "success"
            or run.get("event") != "workflow_dispatch" or run.get("head_sha") != source
            or run.get("path") != ".github/workflows/release.yml"
            or run.get("repository", {}).get("full_name") != repository):
        raise ValueError("approved candidate run provenance mismatch")


def require_publishable_inventory(inventory, run_id, source, environment_ids, run_attempt=1):
    require_first_attempt({"id": inventory.get("run_id"), "run_attempt": inventory.get("run_attempt")}, run_id, run_attempt)
    if (inventory.get("trust") != "release" or inventory.get("mode") != "sign_candidate"
            or inventory.get("source_sha") != source or str(inventory.get("run_id")) != str(run_id)
            or not environment_ids or inventory.get("environment_ids") != environment_ids):
        raise ValueError("test-key, build-only or foreign candidate is permanently nonpublishable")
    packages = {
        "nelomai-0.2.16-linux-x86_64.AppImage", "nelomai-0.2.16-windows-x86_64.exe",
        "nelomai-0.2.16-macos-aarch64.app.tar.gz", "nelomai-0.2.16-android-aarch64.apk"}
    assets = inventory.get("assets", {})
    if not isinstance(assets, dict) or any(not re.fullmatch(r"[0-9a-f]{64}", str(assets.get(name, ""))) for name in packages):
        raise ValueError("approved digests for all four exact installer/package names required")


def github_get(endpoint):
    result = subprocess.run(["gh", "api", "--method", "GET", endpoint], check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def check_environment(repository, name):
    if name not in (SIGNING_ENVIRONMENT, ACCEPTANCE_ENVIRONMENT, PUBLICATION_ENVIRONMENT):
        raise ValueError("unknown release environment")
    environment = github_get(f"repos/{repository}/environments/{name}")
    require_protected_environment(environment)
    if environment.get("name") != name or type(environment.get("id")) is not int or environment["id"] <= 0:
        raise ValueError("current environment identity is unavailable")
    return environment["id"]


def check_approvals(repository, run_id, required=(SIGNING_ENVIRONMENT, ACCEPTANCE_ENVIRONMENT), *, run_attempt=1):
    run_endpoint = f"repos/{repository}/actions/runs/{run_id}"
    require_first_attempt(github_get(run_endpoint), run_id, run_attempt)
    identities = {name: check_environment(repository, name) for name in required}
    approvals = github_get(f"repos/{repository}/actions/runs/{run_id}/approvals")
    if not identities or not isinstance(approvals, list):
        raise ValueError("approval association is unavailable")
    approved = set()
    for review in approvals:
        for environment in review.get("environments", []):
            name, identity = environment.get("name"), environment.get("id")
            if name not in identities and identity not in identities.values():
                continue
            if (review.get("state") != "approved" or name not in identities
                    or type(identity) is not int or identity != identities[name] or name in approved):
                raise ValueError("conflicting, stale or ambiguous approval history; start a new run")
            approved.add(name)
    if set(identities) != approved:
        raise ValueError("candidate lacks actual required environment approvals")
    # Do not accept a rerun or environment replacement that happened while the
    # read-only checks were in progress.
    require_first_attempt(github_get(run_endpoint), run_id, run_attempt)
    if identities != {name: check_environment(repository, name) for name in required}:
        raise ValueError("environment identity changed during approval verification")
    return identities


def check_remote_tag(repository, version, source):
    full_source(source)
    # Query matching refs rather than interpreting all API failures as 404.
    refs = github_get(f"repos/{repository}/git/matching-refs/tags/v{version}")
    exact = [ref for ref in refs if ref.get("ref") == f"refs/tags/v{version}"]
    if not exact:
        return False
    if len(exact) != 1:
        raise ValueError("ambiguous release tag")
    value = exact[0]["object"]
    seen = set()
    while value["type"] == "tag":
        if value["sha"] in seen or len(seen) >= 8:
            raise ValueError("invalid annotated tag chain")
        seen.add(value["sha"])
        value = github_get(f"repos/{repository}/git/tags/{value['sha']}")["object"]
    if value.get("type") != "commit" or value.get("sha") != source:
        raise ValueError("remote peeled tag differs from source_sha; never retag")
    return True


def file_hash(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("candidate asset missing or nonregular")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_inventory(directory, inventory, expected_digest):
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest) or file_hash(inventory) != expected_digest:
        raise ValueError("approved installer/package inventory digest mismatch")
    document = json.loads(inventory.read_bytes())
    assets = document.get("assets")
    if not isinstance(assets, dict) or not assets:
        raise ValueError("candidate inventory is empty")
    for name, digest in assets.items():
        if (Path(name).name != name or name.startswith(".") or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or file_hash(directory / name) != digest):
            raise ValueError("approved candidate asset digest mismatch")
    actual = {path.name for path in directory.iterdir() if path != inventory}
    if actual != set(assets):
        raise ValueError("candidate contains missing or additional assets")
    return document


def verify_runtime_release(directory, version, source, root_sha256, public_key):
    spec = importlib.util.spec_from_file_location("runtime_release_set", Path(__file__).with_name("build-runtime-release-set.py"))
    aggregate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(aggregate)
    name = f"nelomai-runtime-{version}-release-set.manifest"
    root = aggregate.verifier.authenticated("release-set", directory / (name + ".json"),
        directory / (name + ".sig"), public_key, root_sha256)
    if root["runtime_version"] != version or root["source_commit"] != source:
        raise ValueError("approved release-set identity mismatch")
    actual = aggregate.collect(directory, version, source, public_key)
    if sorted(root["artifacts"], key=lambda item: item["platform"]) != sorted(actual, key=lambda item: item["platform"]):
        raise ValueError("retained artifacts differ from approved release-set digests")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    mode_parser = commands.add_parser("mode")
    mode_parser.add_argument("--mode", default="build_only")
    mode_parser.add_argument("--operation", required=True)
    source_parser = commands.add_parser("source")
    source_parser.add_argument("--root", type=Path, default=Path.cwd())
    source_parser.add_argument("--source-sha", required=True)
    source_parser.add_argument("--version", required=True)
    environment_parser = commands.add_parser("environment")
    environment_parser.add_argument("--repository", required=True)
    environment_parser.add_argument("--name", required=True)
    approval_parser = commands.add_parser("approval")
    approval_parser.add_argument("--repository", required=True)
    approval_parser.add_argument("--run-id", required=True)
    approval_parser.add_argument("--run-attempt", type=int, required=True)
    approval_parser.add_argument("--name", choices=(SIGNING_ENVIRONMENT, ACCEPTANCE_ENVIRONMENT, PUBLICATION_ENVIRONMENT), required=True)
    tag_parser = commands.add_parser("tag")
    tag_parser.add_argument("--repository", required=True)
    tag_parser.add_argument("--version", required=True)
    tag_parser.add_argument("--source-sha", required=True)
    candidate = commands.add_parser("candidate")
    for name in ("repository", "run-id", "source-sha", "inventory-sha256", "release-set-sha256"):
        candidate.add_argument("--" + name, required=True)
    candidate.add_argument("--directory", type=Path, required=True)
    candidate.add_argument("--public-key", type=Path, required=True)
    candidate.add_argument("--run-attempt", type=int, required=True)
    args = parser.parse_args()
    if args.command == "mode":
        require_operation(args.mode, args.operation)
        print(json.dumps(mode_policy(args.mode)))
        return
    if args.command == "source":
        verify_source(args.root, args.source_sha, args.version)
        config = json.loads((args.root / "src-tauri/tauri.conf.json").read_bytes())
        if config["version"] != args.version:
            raise ValueError("checked-in version differs; pinned source must not be rewritten")
    elif args.command == "environment":
        check_environment(args.repository, args.name)
    elif args.command == "approval":
        check_approvals(args.repository, args.run_id, (args.name,), run_attempt=args.run_attempt)
    elif args.command == "tag":
        check_remote_tag(args.repository, args.version, args.source_sha)
    else:
        for name in (SIGNING_ENVIRONMENT, ACCEPTANCE_ENVIRONMENT, PUBLICATION_ENVIRONMENT):
            check_environment(args.repository, name)
        require_candidate_run(github_get(f"repos/{args.repository}/actions/runs/{args.run_id}"),
                              args.run_id, args.source_sha, args.repository, args.run_attempt)
        environment_ids = check_approvals(args.repository, args.run_id, run_attempt=args.run_attempt)
        inventory = verify_inventory(args.directory, args.directory / "candidate-inventory.json", args.inventory_sha256)
        require_publishable_inventory(inventory, args.run_id, args.source_sha, environment_ids, args.run_attempt)
        verify_runtime_release(args.directory, "0.2.16", args.source_sha, args.release_set_sha256, args.public_key)
        require_candidate_run(github_get(f"repos/{args.repository}/actions/runs/{args.run_id}"),
                              args.run_id, args.source_sha, args.repository, args.run_attempt)
    print("OK: release authorization checks passed")


if __name__ == "__main__":
    main()
