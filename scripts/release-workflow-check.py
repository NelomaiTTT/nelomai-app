#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]


def run() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    for token in (
        "verify:",
        "needs: verify",
        "needs: [verify, build]",
        "npm test",
        "cargo clippy --workspace --all-targets -- -D warnings",
        "cargo test --workspace",
        "TAURI_SIGNING_PRIVATE_KEY",
        "NELOMAI_UPDATER_PUBLIC_KEY",
        "NELOMAI_RELEASE_MANIFEST_PRIVATE_KEY_B64",
        '--bundles "${{ matrix.package_kind }}"',
        'target/${{ matrix.rust_target }}/release/bundle',
        "ubuntu-22.04",
        "windows-2022",
        "macos-15-intel",
        "macos-14",
        "gh release create",
    ):
        if token not in workflow:
            raise RuntimeError(f"release workflow misses {token}")

    tauri_config = json.loads(
        (ROOT / "src-tauri" / "tauri.conf.json").read_text(encoding="utf-8")
    )
    updater_public_key = (
        tauri_config.get("plugins", {}).get("updater", {}).get("pubkey", "")
    )
    if not isinstance(updater_public_key, str) or not updater_public_key.strip():
        raise RuntimeError("Tauri updater public key is missing")
    try:
        decoded_updater_key = base64.b64decode(
            updater_public_key, validate=True
        )
    except ValueError as exc:
        raise RuntimeError("Tauri updater public key is not valid base64") from exc
    if b"minisign public key" not in decoded_updater_key:
        raise RuntimeError("Tauri updater public key has an invalid format")

    private_key = Ed25519PrivateKey.generate()
    seed = private_key.private_bytes_raw()
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        bundle = root / "bundle"
        bundle.mkdir()
        updater = bundle / "Nelomai.AppImage"
        updater_payload = b"signed-updater-artifact" * 131_072
        updater.write_bytes(updater_payload)
        (bundle / "Nelomai.AppImage.sig").write_text(
            "tauri-signature",
            encoding="utf-8",
        )
        collected = root / "collected"
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "collect-release-artifact.py"),
                "--search-root",
                str(bundle),
                "--output-dir",
                str(collected),
                "--version",
                "1.2.3",
                "--platform",
                "linux",
                "--architecture",
                "x86_64",
                "--package-kind",
                "appimage",
            ],
            check=True,
        )
        windows_updater = bundle / "Nelomai_1.2.3_x64-setup.exe"
        windows_updater_payload = b"signed-windows-updater" * 131_072
        windows_updater.write_bytes(windows_updater_payload)
        (bundle / "Nelomai_1.2.3_x64-setup.exe.sig").write_text(
            "tauri-windows-signature",
            encoding="utf-8",
        )
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "collect-release-artifact.py"),
                "--search-root",
                str(bundle),
                "--output-dir",
                str(collected),
                "--version",
                "1.2.3",
                "--platform",
                "windows",
                "--architecture",
                "x86_64",
                "--package-kind",
                "nsis",
            ],
            check=True,
        )
        published = root / "published"
        environment = {
            **os.environ,
            "NELOMAI_RELEASE_MANIFEST_PRIVATE_KEY_B64": base64.b64encode(
                seed
            ).decode("ascii"),
            "RELEASE_NOTES": "Release workflow check",
        }
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "build-release-manifest.py"),
                "--input-dir",
                str(collected),
                "--output-dir",
                str(published),
                "--version",
                "1.2.3",
            ],
            env=environment,
            check=True,
        )
        manifest_bytes = (
            published / "nelomai-release-manifest.json"
        ).read_bytes()
        signature = base64.b64decode(
            (published / "nelomai-release-manifest.sig").read_bytes().strip(),
            validate=True,
        )
        private_key.public_key().verify(signature, manifest_bytes)
        manifest = json.loads(manifest_bytes)
        if manifest["version"] != "1.2.3" or len(manifest["artifacts"]) != 2:
            raise RuntimeError("release manifest content is invalid")
        artifacts = {
            artifact["package_kind"]: artifact
            for artifact in manifest["artifacts"]
        }
        artifact = artifacts["appimage"]
        if artifact["package_kind"] != "appimage":
            raise RuntimeError("release artifact type is invalid")
        published_artifact = published / artifact["asset_name"]
        if not published_artifact.is_file():
            raise RuntimeError("published updater artifact is missing")
        if artifact["size_bytes"] != len(updater_payload):
            raise RuntimeError("release artifact size is invalid")
        if artifact["sha256"] != hashlib.sha256(updater_payload).hexdigest():
            raise RuntimeError("release artifact hash is invalid")
        windows_artifact = artifacts["nsis"]
        published_windows_artifact = published / windows_artifact["asset_name"]
        if not published_windows_artifact.is_file():
            raise RuntimeError("published Windows updater artifact is missing")
        if windows_artifact["size_bytes"] != len(windows_updater_payload):
            raise RuntimeError("Windows release artifact size is invalid")
        if windows_artifact["sha256"] != hashlib.sha256(
            windows_updater_payload
        ).hexdigest():
            raise RuntimeError("Windows release artifact hash is invalid")
    print("OK: release workflow check passed")


if __name__ == "__main__":
    run()
