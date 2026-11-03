#!/usr/bin/env python3
"""Prepare only Cargo's exact Windows library-test exe with Tauri's locked manifest."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
IDENTITY = dict(type="win32", name="Microsoft.Windows.Common-Controls", version="6.0.0.0",
                processorArchitecture="*", publicKeyToken="6595b64144ccf1df", language="*")
NS = {"asm": "urn:schemas-microsoft-com:asm.v1"}


def check_xml(data):
    try:
        root = ET.fromstring(data)
    except ET.ParseError as error:
        raise ValueError("invalid embedded manifest XML") from error
    dependencies = root.findall("asm:dependency/asm:dependentAssembly/asm:assemblyIdentity", NS)
    if [item.attrib for item in dependencies if item.get("name") == IDENTITY["name"]] != [IDENTITY]:
        raise ValueError("manifest must require Common Controls v6 with its exact assembly identity")
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == "requestedExecutionLevel" and (
                element.get("level") != "asInvoker" or element.get("uiAccess", "false") != "false"):
            raise ValueError("library-test manifest must not request elevation or UI access")


def verify_manifest(executable):
    """Extract RT_MANIFEST / ID 1 from PE resources, checking every language."""
    data = executable.read_bytes()
    try:
        u16 = lambda offset: struct.unpack_from("<H", data, offset)[0]
        u32 = lambda offset: struct.unpack_from("<I", data, offset)[0]
        pe = u32(0x3c)
        if data[:2] != b"MZ" or data[pe:pe + 4] != b"PE\0\0":
            raise ValueError("not a PE executable")
        optional = pe + 24
        magic = u16(optional)
        if magic not in (0x10b, 0x20b):
            raise ValueError("unsupported PE optional header")
        directories = optional + (112 if magic == 0x20b else 96)
        rva, size = u32(directories + 16), u32(directories + 20)
        if not rva or not size:
            raise ValueError("PE resource directory is absent; missing manifest #1")
        sections = optional + u16(pe + 20)

        def position(address, length):
            for index in range(u16(pe + 6)):
                section = sections + index * 40
                start, raw_size, raw = u32(section + 12), u32(section + 16), u32(section + 20)
                if start <= address and address - start + length <= raw_size:
                    result = raw + address - start
                    if result + length <= len(data):
                        return result
            raise ValueError("resource RVA is outside PE section data")

        base = position(rva, size)

        def entries(offset):
            count = u16(base + offset + 12) + u16(base + offset + 14)
            if offset + 16 + 8 * count > size:
                raise ValueError("resource directory exceeds its bounds")
            return [(u32(base + offset + 16 + index * 8), u32(base + offset + 20 + index * 8))
                    for index in range(count)]

        def directory(offset, resource_id):
            matches = [target for name, target in entries(offset) if name == resource_id]
            if len(matches) != 1 or not matches[0] & 0x80000000:
                raise ValueError("missing RT_MANIFEST resource #1")
            return matches[0] & 0x7fffffff

        languages = entries(directory(directory(0, 24), 1))
        if not languages:
            raise ValueError("manifest #1 has no language resource")
        for _language, target in languages:
            if target & 0x80000000 or target + 16 > size:
                raise ValueError("invalid manifest resource entry")
            address, length = u32(base + target), u32(base + target + 4)
            if not 0 < length <= 1024 * 1024:
                raise ValueError("invalid manifest resource size")
            start = position(address, length)
            check_xml(data[start:start + length])
    except (struct.error, IndexError) as error:
        raise ValueError("truncated PE resources") from error


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def configure(root, config, record, sdk=None):
    # Resolve inputs before Cargo owns its build lock; never call Cargo from the runner.
    record = record.resolve()
    record.unlink(missing_ok=True)
    metadata = json.loads(subprocess.run(["cargo", "metadata", "--locked", "--format-version=1",
        "--filter-platform=x86_64-pc-windows-msvc"], cwd=root, check=True, capture_output=True, text=True, encoding="utf-8").stdout)
    packages = [item for item in metadata["packages"] if item["name"] == "tauri-build"]
    if len(packages) != 1:
        raise ValueError("expected exactly one locked tauri-build package")
    manifest = Path(packages[0]["manifest_path"]).parent / "src/windows-app-manifest.xml"
    check_xml(manifest.read_bytes())
    sdk = sdk or Path(os.environ["ProgramFiles(x86)"]) / "Windows Kits/10/bin"
    tools = [path for path in sdk.glob("*/x64/mt.exe") if re.fullmatch(r"\d+(?:\.\d+)+", path.parents[1].name)]
    if not tools:
        raise ValueError("Windows SDK x64 mt.exe is unavailable")
    mt = max(tools, key=lambda path: tuple(map(int, path.parents[1].name.split("."))))
    result = subprocess.run(["cargo", "test", "--locked", "-p", "nelomai-app", "--lib", "--no-run",
                             "--message-format=json"], cwd=root, stdout=subprocess.PIPE, text=True, encoding="utf-8")
    artifacts = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    for item in artifacts:
        if item.get("reason") == "compiler-message" and item.get("message", {}).get("rendered"):
            print(item["message"]["rendered"], file=sys.stderr, end="")
    result.check_returncode()
    executables = [Path(item["executable"]).resolve() for item in artifacts if item.get("reason") == "compiler-artifact"
        and item.get("target", {}).get("name") == "nelomai_app_lib" and item.get("profile", {}).get("test")
        and item.get("executable")]
    if len(executables) != 1:
        raise ValueError("expected exactly one app library-test compiler executable")
    executable = executables[0]
    if not re.fullmatch(r"nelomai_app_lib-[a-f0-9]+\.exe", executable.name) or not executable.is_relative_to(Path(metadata["target_directory"]).resolve()):
        raise ValueError("compiler executable is not the expected library-test image")
    runner = [sys.executable, str(Path(__file__).resolve()), "run", "--record", str(record),
              "--expected-executable", str(executable), "--manifest", str(manifest), "--mt", str(mt), "--"]
    config.parent.mkdir(parents=True, exist_ok=True)
    # JSON strings/arrays are also TOML; keep paths with spaces as individual argv entries.
    config.write_text("target.x86_64-pc-windows-msvc.runner = " + json.dumps(runner, ensure_ascii=False) + "\n", encoding="utf-8")


def run_harness(command, expected_executable, manifest, mt, record):
    if not command or Path(command[0]).resolve() != expected_executable.resolve():
        raise ValueError("Cargo-selected executable differs from the app library-test compiler artifact")
    executable = Path(command[0]).resolve()
    check_xml(manifest.read_bytes())
    subprocess.run([str(mt), "-nologo", "-manifest", str(manifest), f"-outputresource:{executable};#1"], check=True)
    verify_manifest(executable)
    saved = dict(executable=str(executable), executable_sha256=digest(executable), manifest_source=str(manifest),
                 manifest_sha256=digest(manifest), sdk_mt=str(mt))
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(json.dumps(saved, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(saved), flush=True)
    # Cargo supplies the exact argv, package CWD and dynamic-library environment.
    result = subprocess.run(command)
    try:
        verify_record(record)
    except (ValueError, OSError) as error:
        print(f"post-test manifest verification failed: {error}", file=sys.stderr)
        return result.returncode or 1
    return result.returncode


def verify_record(record):
    saved = json.loads(record.read_text(encoding="utf-8"))
    executable = Path(saved["executable"])
    if digest(executable) != saved["executable_sha256"]:
        raise ValueError("library-test executable changed after preparation; possible relink")
    verify_manifest(executable)
    print(json.dumps(dict(executable=str(executable), unchanged_sha256=saved["executable_sha256"], manifest_resource=1)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("configure", "run", "verify"))
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--expected-executable", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--mt", type=Path)
    # Everything following -- belongs to Cargo's executable, including its flags.
    arguments = sys.argv[1:]
    separator = arguments.index("--") if "--" in arguments else len(arguments)
    args = parser.parse_args(arguments[:separator])
    command = arguments[separator + 1:]
    if args.mode in ("configure", "run") and os.name != "nt":
        parser.error("manifest preparation requires the native Windows SDK")
    if args.mode == "configure":
        if args.config is None:
            parser.error("configure requires --config")
        configure(ROOT, args.config, args.record)
    elif args.mode == "run":
        if not command or any(value is None for value in (args.expected_executable, args.manifest, args.mt)):
            parser.error("run requires --expected-executable, --manifest, --mt and -- executable [args]")
        sys.exit(run_harness(command, args.expected_executable, args.manifest, args.mt, args.record))
    else:
        verify_record(args.record)
