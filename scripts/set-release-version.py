#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import tomllib


ROOT = Path(__file__).resolve().parents[1]


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


CARGO_MANIFESTS = (
    Path("src-tauri") / "Cargo.toml",
    Path("crates") / "android-container" / "Cargo.toml",
    Path("crates") / "unix-service" / "Cargo.toml",
    Path("crates") / "windows-service" / "Cargo.toml",
)


def check_versions(version: str) -> None:
    for relative in ("package.json", "package-lock.json", "src-tauri/tauri.conf.json"):
        if json.loads((ROOT / relative).read_text())["version"] != version:
            raise ValueError(f"version mismatch: {relative}")
    npm = json.loads((ROOT / "package-lock.json").read_text())
    if npm["packages"][""]["version"] != version:
        raise ValueError("version mismatch: npm root package")
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]
    for relative in CARGO_MANIFESTS:
        package = tomllib.loads((ROOT / relative).read_text())["package"]
        if package["version"] != version or [
            item["version"] for item in lock if item["name"] == package["name"]
        ] != [version]:
            raise ValueError(f"version mismatch: {relative} or Cargo.lock")


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync versions from package.json or an explicit version")
    parser.add_argument("version", nargs="?")
    parser.add_argument("--check", action="store_true", help="Validate all metadata and print the release version; no writes")
    args = parser.parse_args()
    version = (args.version or json.loads((ROOT / "package.json").read_text())["version"]).removeprefix("v")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise SystemExit("invalid release version")
    if args.check:
        check_versions(version)
        print(version)
        return
    update_json(ROOT / "package.json", version)
    update_json(ROOT / "src-tauri" / "tauri.conf.json", version)
    npm_path = ROOT / "package-lock.json"
    npm = json.loads(npm_path.read_text())
    npm["version"] = npm["packages"][""]["version"] = version
    npm_path.write_text(json.dumps(npm, ensure_ascii=False, indent=2) + "\n")
    lock_path = ROOT / "Cargo.lock"
    lock = lock_path.read_text()
    for relative in CARGO_MANIFESTS:
        path = ROOT / relative
        name = tomllib.loads(path.read_text())["package"]["name"]
        update_cargo(path, version)
        lock, count = re.subn(
            r'(?m)(^name = "' + re.escape(name) + r'"\nversion = ")[^"]+("$)',
            lambda match: match[1] + version + match[2], lock,
        )
        if count != 1:
            raise ValueError(f"missing or ambiguous Cargo.lock package: {name}")
    lock_path.write_text(lock)
    check_versions(version)


if __name__ == "__main__":
    main()
