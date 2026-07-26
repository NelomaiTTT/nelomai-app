#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil


SIGNATURE_SUFFIXES = {
    "app": ".app.tar.gz.sig",
    "appimage": ".AppImage.tar.gz.sig",
    "nsis": ".nsis.zip.sig",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--search-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--platform", choices=("macos", "linux", "windows"), required=True)
    parser.add_argument("--architecture", choices=("x86_64", "aarch64"), required=True)
    parser.add_argument("--package-kind", choices=tuple(SIGNATURE_SUFFIXES), required=True)
    args = parser.parse_args()

    suffix = SIGNATURE_SUFFIXES[args.package_kind]
    signatures = sorted(
        path
        for path in args.search_root.rglob(f"*{suffix}")
        if path.is_file()
    )
    if len(signatures) != 1:
        raise SystemExit(
            f"expected exactly one {suffix} below {args.search_root}, found {len(signatures)}"
        )
    source_signature = signatures[0]
    source_artifact = Path(str(source_signature)[: -len(".sig")])
    if not source_artifact.is_file():
        raise SystemExit(f"updater artifact is missing: {source_artifact}")

    updater_suffix = source_artifact.name[
        source_artifact.name.lower().find(
            {
                "app": ".app.tar.gz",
                "appimage": ".appimage.tar.gz",
                "nsis": ".nsis.zip",
            }[args.package_kind]
        ) :
    ]
    if not updater_suffix:
        raise SystemExit("unable to determine updater artifact suffix")
    asset_name = (
        f"nelomai-{args.version}-{args.platform}-{args.architecture}"
        f"{updater_suffix}"
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    destination = args.output_dir / asset_name
    shutil.copyfile(source_artifact, destination)
    signature = source_signature.read_text(encoding="utf-8").strip()
    if not signature:
        raise SystemExit("Tauri updater signature is empty")
    metadata = {
        "platform": args.platform,
        "architecture": args.architecture,
        "package_kind": args.package_kind,
        "asset_name": asset_name,
        "signature": signature,
    }
    (args.output_dir / f"{args.platform}-{args.architecture}.artifact.json").write_text(
        json.dumps(metadata, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
