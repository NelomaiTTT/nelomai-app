#!/usr/bin/env python3
"""Cross-language fixture checks using only the Python standard library."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALID = ROOT / "fixtures" / "valid"
COMPAT = ROOT / "fixtures" / "compat"
INVALID = ROOT / "fixtures" / "invalid"
RUNTIME = ROOT / "fixtures" / "runtime"

SAFE_ERROR_KEYS = {"request_id", "code", "message"}
ROUTES = {"standalone", "via_tak"}
LAYERS = {"tic", "stray"}
TIC_MODES = {"personal", "dynamic"}
LEASE_STATUSES = {"allocating", "issued", "connected", "warm", "released", "failed"}
RUNTIME_TARGETS = {
    ("linux", "x86_64"),
    ("windows", "x86_64"),
    ("macos", "aarch64"),
    ("android", "aarch64"),
}


def assert_canonical(path: Path) -> dict:
    raw = path.read_bytes()
    value = json.loads(raw)
    canonical = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    assert raw == canonical, f"{path} is not canonical JSON"
    assert isinstance(value, dict), f"{path} must contain an object"
    return value


def assert_sha256(value: object) -> None:
    assert isinstance(value, str)
    assert len(value) == 64
    assert all(character in "0123456789abcdef" for character in value)


def assert_artifact_manifest(manifest: dict) -> None:
    assert set(manifest) == {
        "format_version", "runtime_version", "source_commit", "platform",
        "architecture", "contract_version", "files",
    }
    assert manifest["format_version"] == 1
    assert manifest["contract_version"] == 1
    assert manifest["runtime_version"]
    assert manifest["source_commit"]
    assert manifest["platform"]
    assert manifest["architecture"]
    paths = set()
    for entry in manifest["files"]:
        assert set(entry) == {"path", "size_bytes", "sha256", "role"}
        assert entry["path"] not in paths
        paths.add(entry["path"])
        assert isinstance(entry["size_bytes"], int) and entry["size_bytes"] >= 0
        assert_sha256(entry["sha256"])
        assert entry["role"] in {
            "executable", "shared_library", "resource", "license", "metadata",
        }


def validate_runtime_fixtures() -> None:
    container = assert_canonical(RUNTIME / "container-manifest-v1.json")
    assert set(container) == {
        "format_version", "container_version", "release_set_id",
        "minimum_runtime_contract", "maximum_runtime_contract", "slots",
    }
    assert container["format_version"] == 1
    assert container["minimum_runtime_contract"] == 1
    assert container["maximum_runtime_contract"] == 1
    assert [slot["slot"] for slot in container["slots"]] == ["latest"]
    assert_artifact_manifest(container["slots"][0]["manifest"])

    stable = assert_canonical(RUNTIME / "stable-artifact-manifest-v1.json")
    assert_artifact_manifest(stable)
    assert stable["runtime_version"] != container["slots"][0]["manifest"]["runtime_version"]

    release_set = assert_canonical(RUNTIME / "release-set-manifest-v1.json")
    assert set(release_set) == {
        "format_version", "release_set_id", "runtime_version", "source_commit", "artifacts",
    }
    assert "stable_manifest_sha256" not in release_set
    assert len(release_set["artifacts"]) == 4
    targets = set()
    for entry in release_set["artifacts"]:
        assert set(entry) == {
            "platform", "architecture", "archive_name", "archive_sha256",
            "manifest_name", "manifest_sha256", "signature_name", "signature_sha256",
        }
        targets.add((entry["platform"], entry["architecture"]))
        assert_sha256(entry["archive_sha256"])
        assert_sha256(entry["manifest_sha256"])
        assert_sha256(entry["signature_sha256"])
    assert targets == RUNTIME_TARGETS


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
    assert fixtures["update-manifest"]["url"].startswith(
        "https://nelomai.ru/api/client/v1/updates/artifacts/"
    )
    assert fixtures["update-manifest"]["signature"]
    assert set(fixtures["error"]) == SAFE_ERROR_KEYS

    future = load(COMPAT / "bootstrap-extra-optional.json")
    assert future["future_optional"]["value"] is True

    unknown_route = load(INVALID / "connection-start-unknown-route.json")
    assert unknown_route["route_mode"] not in ROUTES

    unsafe_error = load(INVALID / "error-with-config.json")
    assert set(unsafe_error) - SAFE_ERROR_KEYS
    validate_runtime_fixtures()
    print(f"validated {len(fixtures)} shared client contract fixtures")


if __name__ == "__main__":
    main()
