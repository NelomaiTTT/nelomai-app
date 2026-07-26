#!/usr/bin/env python3
"""Cross-language fixture checks using only the Python standard library."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALID = ROOT / "fixtures" / "valid"
COMPAT = ROOT / "fixtures" / "compat"
INVALID = ROOT / "fixtures" / "invalid"

SAFE_ERROR_KEYS = {"request_id", "code", "message"}
ROUTES = {"standalone", "via_tak"}
LAYERS = {"tic", "stray"}
TIC_MODES = {"personal", "dynamic"}
LEASE_STATUSES = {"allocating", "issued", "connected", "warm", "released", "failed"}


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    assert isinstance(value, dict), f"{path} must contain an object"
    return value


def main() -> None:
    fixtures = {path.stem: load(path) for path in sorted(VALID.glob("*.json"))}
    assert fixtures["bootstrap"]["api_version"] == "1"
    assert fixtures["peer-options"]["peers"]
    assert fixtures["probe-results"]["probes"]
    assert fixtures["server-candidates"]["candidates"]
    start = fixtures["connection-start"]
    assert start["layer"] in LAYERS
    assert start["tic_connection_mode"] in TIC_MODES
    assert start["route_mode"] in ROUTES
    assert start["operation_id"]
    assert fixtures["connection-start-response"]["connection"]["status"] in LEASE_STATUSES
    assert fixtures["connection-operation"]["connection"]["status"] in LEASE_STATUSES
    assert set(fixtures["error"]) == SAFE_ERROR_KEYS

    future = load(COMPAT / "bootstrap-extra-optional.json")
    assert future["future_optional"]["value"] is True

    unknown_route = load(INVALID / "connection-start-unknown-route.json")
    assert unknown_route["route_mode"] not in ROUTES

    unsafe_error = load(INVALID / "error-with-config.json")
    assert set(unsafe_error) - SAFE_ERROR_KEYS
    print(f"validated {len(fixtures)} shared client contract fixtures")


if __name__ == "__main__":
    main()
