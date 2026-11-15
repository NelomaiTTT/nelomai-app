#!/usr/bin/env python3
"""Download archived stable bytes; authenticate before exposing output."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location("gates", Path(__file__).with_name("release-candidate-gates.py"))
gates = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gates)

# This successful candidate retains the original stable set under confirmed-stable/.
# Its source is provenance for the carrier only; stable identity/signature/hash pins
# remain unchanged in release-candidate-gates.py.
STABLE_ARCHIVE_RUN_ID = "42123287698"
STABLE_ARCHIVE_SOURCE = "a5c64b5159eaa8a05648307f875cadbbc797eeaf"


def download(output, public_key):
    if output.exists() or output.is_symlink():
        raise ValueError("immutable confirmed stable output exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    repository = "NelomaiTTT/nelomai-app"
    run = json.loads(subprocess.run(
        ["gh", "api", f"repos/{repository}/actions/runs/{STABLE_ARCHIVE_RUN_ID}"],
        check=True, capture_output=True, text=True,
    ).stdout)
    if (str(run.get("id")) != STABLE_ARCHIVE_RUN_ID
            or run.get("head_sha") != STABLE_ARCHIVE_SOURCE
            or run.get("path") != ".github/workflows/release.yml"
            or run.get("status") != "completed" or run.get("conclusion") != "success"):
        raise ValueError("pinned stable archive is not a successful build of the expected source")
    with tempfile.TemporaryDirectory(prefix=".confirmed-stable-", dir=output.parent) as temporary:
        staged = Path(temporary) / "confirmed-stable"
        subprocess.run(["gh", "run", "download", STABLE_ARCHIVE_RUN_ID,
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
