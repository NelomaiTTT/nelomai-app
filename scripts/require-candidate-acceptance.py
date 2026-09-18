#!/usr/bin/env python3
"""Mandatory unresolved Task12 gate; packaging is never full acceptance.

This is deliberately NOT an evidence parser or an approval issuer. Task12 must
replace this refusal with actual exact-candidate execution and verifiable
provenance. Environment approval or caller JSON cannot override it.

Task12 source checks now cover signed slot selection in the production
dispatcher/immutable engine and real broker/panel/PostgreSQL process faults.
Run scripts/run-real-panel-acceptance.py against the recorded isolated panel for
that local evidence. It does not execute the exact signed packaged candidate,
release trust, UI/business tunnel or required physical platform checks.
"""
import argparse
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--release-set-sha256", required=True)
    parser.add_argument("--inventory-sha256", required=True)
    parser.add_argument("--candidate-directory", type=Path, required=True)
    args = parser.parse_args()
    if (not re.fullmatch(r"[0-9a-f]{40}", args.source_sha)
            or not all(re.fullmatch(r"[0-9a-f]{64}", value) for value in (args.release_set_sha256, args.inventory_sha256))):
        raise SystemExit("invalid exact candidate identity")
    raise SystemExit("UNRUN: Task12 authoritative exact-candidate UI/broker/business HTTP/dispatcher/tunnel and platform "
        "acceptance is not fully implemented/verified. Task12 local source producer "
        "scripts/run-real-panel-acceptance.py and signed-slot dispatcher tests are separate evidence, not exact-candidate approval. "
        "Packaging, supplemental tests, caller JSON and environment approval do not authorize publication.")


if __name__ == "__main__":
    main()
