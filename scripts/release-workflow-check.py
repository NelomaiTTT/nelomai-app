#!/usr/bin/env python3
from __future__ import annotations

import base64
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
        "TAURI_SIGNING_PRIVATE_KEY",
        "NELOMAI_UPDATER_PUBLIC_KEY",
        "NELOMAI_RELEASE_MANIFEST_PRIVATE_KEY_B64",
        "ubuntu-22.04",
        "windows-2022",
        "macos-13",
        "macos-14",
        "gh release create",
    ):
        if token not in workflow:
            raise RuntimeError(f"release workflow misses {token}")

    private_key = Ed25519PrivateKey.generate()
    seed = private_key.private_bytes_raw()
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        bundle = root / "bundle"
        bundle.mkdir()
        updater = bundle / "Nelomai.AppImage.tar.gz"
        updater.write_bytes(b"signed-updater-artifact")
        (bundle / "Nelomai.AppImage.tar.gz.sig").write_text(
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
        if manifest["version"] != "1.2.3" or len(manifest["artifacts"]) != 1:
            raise RuntimeError("release manifest content is invalid")
        artifact = manifest["artifacts"][0]
        if artifact["package_kind"] != "appimage":
            raise RuntimeError("release artifact type is invalid")
        if not (published / artifact["asset_name"]).is_file():
            raise RuntimeError("published updater artifact is missing")
    print("OK: release workflow check passed")


if __name__ == "__main__":
    run()
