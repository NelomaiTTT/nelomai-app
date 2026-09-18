#!/usr/bin/env python3
"""Cross-language fixture checks using only the Python standard library."""

from __future__ import annotations

import json
import re
import unicodedata
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


def assert_uint(value: object, maximum: int = 2**32 - 1) -> None:
    assert type(value) is int and 0 <= value <= maximum


def assert_text(value: object, maximum: int = 1024) -> None:
    assert isinstance(value, str) and 0 < len(value.encode("utf-8")) <= maximum
    assert not any(unicodedata.category(char) == "Cc" for char in value)


def assert_version(value: object) -> None:
    assert_text(value, 64)
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", value)


def assert_commit(value: object) -> None:
    assert isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value)


def portable_path_alias(value: object) -> str:
    assert_text(value)
    assert not value.startswith("/") and "\\" not in value
    aliases = []
    for segment in value.split("/"):
        assert segment not in {"", ".", ".."} and not segment.endswith((".", " "))
        assert not any(char in '<>:"|?*' for char in segment)
        alias = unicodedata.normalize("NFKC", segment).casefold()
        base = alias.split(".")[0]
        assert base not in {"con", "prn", "aux", "nul"}
        assert not re.fullmatch(r"(?:com|lpt)[1-9]", base)
        aliases.append(alias)
    return "/".join(aliases)


def assert_artifact_manifest(manifest: dict) -> None:
    assert isinstance(manifest, dict)
    assert set(manifest) == {
        "format_version", "runtime_version", "source_commit", "platform",
        "architecture", "contract_version", "files",
    }
    for field in ("format_version", "contract_version"):
        assert_uint(manifest[field])
        assert manifest[field] == 1
    assert_version(manifest["runtime_version"])
    assert_commit(manifest["source_commit"])
    assert_text(manifest["platform"])
    assert_text(manifest["architecture"])
    assert (manifest["platform"], manifest["architecture"]) in RUNTIME_TARGETS
    assert isinstance(manifest["files"], list) and 1 <= len(manifest["files"]) <= 4096
    paths = set()
    for entry in manifest["files"]:
        assert isinstance(entry, dict)
        assert set(entry) == {"path", "size_bytes", "sha256", "role"}
        alias = portable_path_alias(entry["path"])
        assert alias not in paths
        paths.add(alias)
        assert_uint(entry["size_bytes"], 2**64 - 1)
        assert_sha256(entry["sha256"])
        assert isinstance(entry["role"], str)
        assert entry["role"] in {
            "executable", "shared_library", "resource", "license", "metadata",
        }


def validate_runtime_fixtures() -> None:
    container = assert_canonical(RUNTIME / "container-manifest-v1.json")
    assert set(container) == {
        "format_version", "container_version", "release_set_id",
        "minimum_runtime_contract", "maximum_runtime_contract", "slots",
    }
    for field in ("format_version", "minimum_runtime_contract", "maximum_runtime_contract"):
        assert_uint(container[field])
    assert container["format_version"] == 1
    assert_version(container["container_version"])
    assert_text(container["release_set_id"])
    assert container["minimum_runtime_contract"] == 1
    assert container["maximum_runtime_contract"] == 1
    assert isinstance(container["slots"], list)
    for slot in container["slots"]:
        assert isinstance(slot, dict) and set(slot) == {"slot", "manifest"}
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
    assert_uint(release_set["format_version"])
    assert release_set["format_version"] == 1
    assert_text(release_set["release_set_id"])
    assert_version(release_set["runtime_version"])
    assert_commit(release_set["source_commit"])
    assert isinstance(release_set["artifacts"], list)
    assert len(release_set["artifacts"]) == 4
    targets = set()
    for entry in release_set["artifacts"]:
        assert isinstance(entry, dict)
        assert set(entry) == {
            "platform", "architecture", "archive_name", "archive_sha256",
            "manifest_name", "manifest_sha256", "signature_name", "signature_sha256",
        }
        assert_text(entry["platform"])
        assert_text(entry["architecture"])
        target = (entry["platform"], entry["architecture"])
        assert target not in targets
        targets.add(target)
        for field in ("archive_name", "manifest_name", "signature_name"):
            portable_path_alias(entry[field])
            assert "/" not in entry[field]
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
