#!/usr/bin/env python3
"""Check selected build identity and file completeness, not signatures or acceptance."""
import argparse
import importlib.util
from pathlib import Path
import os

spec = importlib.util.spec_from_file_location("gates", Path(__file__).with_name("release-candidate-gates.py"))
gates = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gates)


def select_candidate(repository, run_id, source_sha, version, fetch=gates.github_get):
    """Resolve a unique retained shipping artifact; re-runs are ordinary builds."""
    gates.full_source(source_sha)
    if not str(run_id).isdigit() or version != "0.2.18":
        raise ValueError("invalid candidate run or version")
    endpoint = f"repos/{repository}/actions/runs/{run_id}"
    run = fetch(endpoint)
    if (str(run.get("id")) != str(run_id) or run.get("head_sha") != source_sha
            or run.get("path") != ".github/workflows/release.yml"
            or run.get("event") != "workflow_dispatch" or run.get("status") != "completed"
            or run.get("conclusion") != "success"
            or run.get("repository", {}).get("full_name") != repository
            or run.get("head_repository", {}).get("full_name") != repository):
        raise ValueError("selected run is not a successful release build of this source")
    candidates = []
    page = 1
    while True:
        artifacts = fetch(f"{endpoint}/artifacts?per_page=100&page={page}")["artifacts"]
        candidates.extend(artifact for artifact in artifacts
                          if artifact.get("name") == f"candidate-{version}" and not artifact.get("expired", True))
        if len(artifacts) < 100:
            break
        page += 1
    if len(candidates) != 1:
        raise ValueError("shipping artifact is missing, expired or ambiguous")
    artifact = candidates[0]
    origin = artifact.get("workflow_run", {})
    if str(origin.get("id")) != str(run_id) or origin.get("head_sha") != source_sha:
        raise ValueError("artifact belongs to a different build")
    return int(artifact["id"])


def check(directory, source_sha, run_id, inventory_sha256=None):
    gates.full_source(source_sha)
    inventory_sha256 = inventory_sha256 or gates.file_hash(directory / "candidate-inventory.json")
    inventory = gates.verify_inventory(directory, directory / "candidate-inventory.json", inventory_sha256)
    if (inventory.get("source_sha") != source_sha or str(inventory.get("run_id")) != run_id
            or inventory.get("mode") != "sign_candidate" or inventory.get("trust") != "release"
            or inventory.get("purpose") != "shipping" or set(inventory["assets"]) != gates.PUBLISH_ASSETS):
        raise ValueError("selected build is not the requested shipping release")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--select", action="store_true")
    parser.add_argument("--repository")
    parser.add_argument("--version", default="0.2.18")
    parser.add_argument("--inventory-sha256")
    for name in ("source-sha", "run-id"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    if args.select:
        if not args.repository:
            parser.error("--select requires --repository")
        artifact = select_candidate(args.repository, args.run_id, args.source_sha, args.version)
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            output.write(f"artifact_id={artifact}\n")
    else:
        if args.directory is None:
            parser.error("--directory is required for downloaded build validation")
        check(args.directory, args.source_sha, args.run_id, args.inventory_sha256)
