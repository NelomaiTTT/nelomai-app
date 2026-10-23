#!/usr/bin/env python3
"""Download the pinned stable candidate; authenticate before exposing output."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location("gates", Path(__file__).with_name("release-candidate-gates.py"))
gates = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gates)


def download(output, public_key):
    if output.exists() or output.is_symlink():
        raise ValueError("immutable confirmed stable output exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    repository = "NelomaiTTT/nelomai-app"
    run = json.loads(subprocess.run(
        ["gh", "api", f"repos/{repository}/actions/runs/{gates.STABLE_RUN_ID}"],
        check=True, capture_output=True, text=True,
    ).stdout)
    if (str(run.get("id")) != gates.STABLE_RUN_ID
            or run.get("head_sha") != gates.STABLE_SOURCE
            or run.get("path") != ".github/workflows/release.yml"
            or run.get("status") != "completed" or run.get("conclusion") != "success"):
        raise ValueError("pinned stable candidate is not a successful build of the expected source")
    with tempfile.TemporaryDirectory(prefix=".confirmed-stable-", dir=output.parent) as temporary:
        staged = Path(temporary) / "release"
        subprocess.run(["gh", "run", "download", gates.STABLE_RUN_ID,
            "--repo", repository, "--name", "signed-runtime", "--dir", temporary], check=True)
        gates.verify_runtime_release(staged, gates.STABLE_VERSION, gates.STABLE_SOURCE,
                                     gates.STABLE_ROOT_SHA256, public_key)
        staged.rename(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    args = parser.parse_args()
    download(args.output, args.public_key)
