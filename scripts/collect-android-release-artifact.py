#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil


VERSION_PATTERN = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$"
)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--signer-sha256", required=True)
    args = parser.parse_args()

    version = args.version.removeprefix("v")
    if not VERSION_PATTERN.fullmatch(version):
        raise SystemExit("invalid Android release version")
    if not args.apk.is_file() or args.apk.suffix.lower() != ".apk":
        raise SystemExit("signed Android APK is missing")
    signer_sha256 = (
        args.signer_sha256.strip().lower().replace(":", "").replace(" ", "")
    )
    if not SHA256_PATTERN.fullmatch(signer_sha256):
        raise SystemExit("Android signer SHA-256 is invalid")

    asset_name = f"nelomai-{version}-android-aarch64.apk"
    args.output_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.apk, args.output_dir / asset_name)
    metadata = {
        "platform": "android",
        "architecture": "aarch64",
        "package_kind": "apk",
        "asset_name": asset_name,
        "signature": signer_sha256,
    }
    (args.output_dir / "android-aarch64.artifact.json").write_text(
        json.dumps(metadata, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
