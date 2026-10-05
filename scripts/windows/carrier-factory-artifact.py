#!/usr/bin/env python3
"""Current-source CI inputs only; never a product/runtime authority constructor."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[2]
RUNTIME_FILES = (
    "nelomai-windows-service.exe", "wintun.dll", "wireguard.dll",
    "tunnel.dll", "amneziawg-tunnel.dll",
)
PAYLOAD_FILES = ("factory-tests.exe", *("runtime/" + name for name in RUNTIME_FILES))


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_source(source_sha):
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if not re.fullmatch(r"[a-f0-9]{40}", source_sha) or head != source_sha:
        raise ValueError("Factory artifact source must equal the exact checkout HEAD")


def require_layout(directory):
    # Reject links/reparse points and extra directories as well as extra files.
    # Never normalize a manifest-controlled path into the accepted inventory.
    expected = {".": stat.S_IFDIR, "runtime": stat.S_IFDIR, **{
        name: stat.S_IFREG for name in (*PAYLOAD_FILES, "manifest.json")
    }}
    actual = {}
    pending = [directory]
    while pending:
        path = pending.pop()
        facts = path.lstat()
        if stat.S_ISLNK(facts.st_mode) or getattr(facts, "st_file_attributes", 0) & 0x400:
            raise ValueError("Factory artifact cannot contain links or reparse points")
        name = path.relative_to(directory).as_posix()
        actual[name] = stat.S_IFMT(facts.st_mode)
        if actual[name] == expected.get(name) == stat.S_IFDIR:
            pending.extend(path.iterdir())  # Only the checked root/runtime; never follow a link.
    if actual != expected:
        raise ValueError("Factory artifact must contain exactly the fixed files and runtime directory")


def create(test_executable, runtime_directory, output, source_sha):
    require_source(source_sha)
    output.mkdir()  # A fresh build must never reuse/merge a prior artifact tree.
    (output / "runtime").mkdir()
    shutil.copyfile(test_executable, output / "factory-tests.exe")
    for name in RUNTIME_FILES:
        shutil.copyfile(runtime_directory / name, output / "runtime" / name)
    if any((output / name).stat().st_size == 0 for name in PAYLOAD_FILES):
        raise ValueError("Factory artifact inputs cannot be empty")
    manifest = {"source_sha": source_sha, "files": {
        name: sha256(output / name) for name in PAYLOAD_FILES
    }}
    (output / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
    digest = sha256(output / "manifest.json")
    verify(output, source_sha, digest)
    return digest


def verify(directory, source_sha, manifest_sha256):
    require_source(source_sha)
    require_layout(directory)
    manifest = directory / "manifest.json"
    if not re.fullmatch(r"[a-f0-9]{64}", manifest_sha256) or sha256(manifest) != manifest_sha256:
        raise ValueError("Factory manifest does not match the successful build output hash")
    data = json.loads(manifest.read_text(encoding="utf-8"))
    if set(data) != {"source_sha", "files"} or data["source_sha"] != source_sha:
        raise ValueError("Factory manifest source/schema mismatch")
    files = data["files"]
    if not isinstance(files, dict) or set(files) != set(PAYLOAD_FILES):
        raise ValueError("Factory manifest must whitelist exactly the fixed six files")
    for name in PAYLOAD_FILES:
        if files[name] != sha256(directory / name):
            raise ValueError(f"Factory artifact file hash mismatch: {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("create")
    build.add_argument("--test-executable", type=Path, required=True)
    build.add_argument("--runtime-directory", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--source-sha", required=True)
    build.add_argument("--artifact-name", required=True)
    consumer = commands.add_parser("verify")
    consumer.add_argument("--directory", type=Path, required=True)
    consumer.add_argument("--source-sha", required=True)
    consumer.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    if args.command == "create":
        digest = create(args.test_executable, args.runtime_directory, args.output, args.source_sha)
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write(f"manifest_sha256={digest}\nartifact_name={args.artifact_name}\n")
    else:
        verify(args.directory, args.source_sha, args.manifest_sha256)


if __name__ == "__main__":
    main()
