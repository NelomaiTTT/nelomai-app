#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


VERSION_PATTERN = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$"
)
COPY_CHUNK_BYTES = 1024 * 1024


def env_bool(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def copy_and_hash(source: Path, destination: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size_bytes = 0
    with source.open("rb") as source_file, destination.open("xb") as output:
        while chunk := source_file.read(COPY_CHUNK_BYTES):
            output.write(chunk)
            digest.update(chunk)
            size_bytes += len(chunk)
        output.flush()
        os.fsync(output.fileno())
    return size_bytes, digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    version = args.version.removeprefix("v")
    if not VERSION_PATTERN.fullmatch(version):
        raise SystemExit("invalid release version")

    artifacts = []
    targets: set[tuple[str, str, str]] = set()
    asset_names: set[str] = set()
    metadata_files = sorted(args.input_dir.rglob("*.artifact.json"))
    if not metadata_files:
        raise SystemExit("release artifact metadata is missing")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for metadata_path in metadata_files:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        target = (
            str(metadata["platform"]),
            str(metadata["architecture"]),
            str(metadata["package_kind"]),
        )
        if target in targets:
            raise SystemExit(f"duplicate release target: {target}")
        targets.add(target)
        source = metadata_path.parent / str(metadata["asset_name"])
        if not source.is_file():
            raise SystemExit(f"release artifact is missing: {source}")
        if source.name in asset_names:
            raise SystemExit(f"duplicate release asset name: {source.name}")
        asset_names.add(source.name)
        destination = args.output_dir / source.name
        size_bytes, sha256 = copy_and_hash(source, destination)
        artifacts.append(
            {
                **metadata,
                "size_bytes": size_bytes,
                "sha256": sha256,
            }
        )

    manifest = {
        "schema_version": 1,
        "version": version,
        "release_notes": os.environ.get("RELEASE_NOTES", "").strip(),
        "critical": env_bool("RELEASE_CRITICAL"),
        "minimum_supported": env_bool("RELEASE_MINIMUM_SUPPORTED"),
        "minimum_panel_api_version": os.environ.get(
            "MINIMUM_PANEL_API_VERSION", "1"
        ).strip(),
        "minimum_agent_contract_version": os.environ.get(
            "MINIMUM_AGENT_CONTRACT_VERSION", "1"
        ).strip(),
        "published_at": datetime.now(UTC).isoformat(),
        "artifacts": sorted(
            artifacts,
            key=lambda item: (
                item["platform"],
                item["architecture"],
                item["package_kind"],
            ),
        ),
    }
    manifest_bytes = json.dumps(
        manifest,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    private_key_b64 = os.environ.get(
        "NELOMAI_RELEASE_MANIFEST_PRIVATE_KEY_B64", ""
    ).strip()
    try:
        private_key = base64.b64decode(private_key_b64, validate=True)
    except Exception as exc:
        raise SystemExit("release manifest private key is not valid base64") from exc
    if len(private_key) != 32:
        raise SystemExit("release manifest private key must contain 32 bytes")
    signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(
        manifest_bytes
    )
    (args.output_dir / "nelomai-release-manifest.json").write_bytes(
        manifest_bytes
    )
    (args.output_dir / "nelomai-release-manifest.sig").write_bytes(
        base64.b64encode(signature) + b"\n"
    )


if __name__ == "__main__":
    main()
