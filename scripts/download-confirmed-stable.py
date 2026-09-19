#!/usr/bin/env python3
"""Download the pinned published stable; authenticate before exposing output."""
import argparse
import importlib.util
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
    with tempfile.TemporaryDirectory(prefix=".confirmed-stable-", dir=output.parent) as temporary:
        staged = Path(temporary) / "release"
        subprocess.run(["gh", "release", "download", "v" + gates.STABLE_VERSION,
            "--repo", "NelomaiTTT/nelomai-app", "--pattern", "nelomai-runtime-*", "--dir", str(staged)], check=True)
        gates.verify_runtime_release(staged, gates.STABLE_VERSION, gates.STABLE_SOURCE,
                                     gates.STABLE_ROOT_SHA256, public_key)
        staged.rename(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    args = parser.parse_args()
    download(args.output, args.public_key)
