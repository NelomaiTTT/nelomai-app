#!/usr/bin/env python3
"""Check selected build identity and file completeness, not signatures or acceptance."""
import argparse
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("gates", Path(__file__).with_name("release-candidate-gates.py"))
gates = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gates)


def check(directory, source_sha, run_id, inventory_sha256):
    gates.full_source(source_sha)
    inventory = gates.verify_inventory(directory, directory / "candidate-inventory.json", inventory_sha256)
    if (inventory.get("source_sha") != source_sha or str(inventory.get("run_id")) != run_id
            or inventory.get("mode") != "sign_candidate" or inventory.get("trust") != "release"
            or inventory.get("purpose") != "shipping" or set(inventory["assets"]) != gates.PUBLISH_ASSETS):
        raise ValueError("selected build is not the requested shipping release")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    for name in ("source-sha", "run-id", "inventory-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    check(args.directory, args.source_sha, args.run_id, args.inventory_sha256)
