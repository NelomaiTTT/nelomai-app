#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
VERSION_PATTERN = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$"
)


def update_json(path: Path, version: str) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["version"] = version
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def update_cargo(path: Path, version: str) -> None:
    content = path.read_text(encoding="utf-8")
    updated, count = re.subn(
        r'(?m)^(version\s*=\s*)"[^"]+"',
        rf'\1"{version}"',
        content,
        count=1,
    )
    if count != 1:
        raise RuntimeError(f"version is missing in {path}")
    path.write_text(updated, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("version")
    args = parser.parse_args()
    version = args.version.removeprefix("v")
    if not VERSION_PATTERN.fullmatch(version):
        raise SystemExit("invalid release version")
    update_json(ROOT / "package.json", version)
    update_json(ROOT / "src-tauri" / "tauri.conf.json", version)
    update_cargo(ROOT / "src-tauri" / "Cargo.toml", version)
    update_cargo(ROOT / "crates" / "unix-service" / "Cargo.toml", version)
    update_cargo(ROOT / "crates" / "windows-service" / "Cargo.toml", version)


if __name__ == "__main__":
    main()
