#!/usr/bin/env python3
"""Build a signed desktop runtime archive from an assembled slot payload.

The signing key is explicit; no release environment or publication is accessed.
Source identity is provided by the pinned build job, not inferred from binaries.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unicodedata
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DOMAIN = b"nelomai-runtime-manifest-v1\0"
TARGETS = {("linux", "x86_64"), ("windows", "x86_64"), ("macos", "aarch64")}
COMMON_LICENSES = {"TAURI-MIT.txt", "TAURI-APACHE-2.0.txt", "AMNEZIAWG-GO-LICENSE.txt"}
WINDOWS_DLLS = {"tunnel.dll", "wireguard.dll", "amneziawg-tunnel.dll", "wintun.dll"}


def portable_alias(name):
    if (not name or len(name.encode()) > 1024 or "\\" in name or name.startswith("/")
            or any(unicodedata.category(char) == "Cc" for char in name)):
        raise ValueError("nonportable payload path")
    parts = []
    for part in name.split("/"):
        alias = unicodedata.normalize("NFKC", part).casefold()
        base = alias.split(".")[0]
        if (part in ("", ".", "..") or part.endswith((".", " "))
                or any(char in part for char in '<>:"|?*')
                or base in ("con", "prn", "aux", "nul") or re.fullmatch(r"(?:com|lpt)[1-9]", base)):
            raise ValueError("nonportable payload path")
        if alias.startswith(".env"):
            raise ValueError("environment file in runtime payload")
        parts.append(alias)
    return "/".join(parts)


def payload_files(payload):
    if payload.is_symlink() or not payload.is_dir():
        raise ValueError("invalid payload root")
    result, seen, total = [], set(), 0
    for path in sorted(payload.rglob("*")):
        if path.is_symlink():
            raise ValueError("symlink in payload")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("nonregular payload file")
        name = path.relative_to(payload).as_posix()
        alias = portable_alias(name)
        if alias in seen:
            raise ValueError("colliding payload paths")
        seen.add(alias)
        size = path.stat().st_size
        total += size
        if not size or size > 512 * 1024 * 1024 or total > 2 * 1024 * 1024 * 1024 or len(seen) > 4096:
            raise ValueError("runtime payload size limit")
        result.append((name, path))
    return result


def verify_binary(path, platform, architecture):
    with path.open("rb") as source:
        header = source.read(4096)
    if (len(header) >= 64 and header[:7] == b"\x7fELF\x02\x01\x01"
            and struct.unpack_from("<H", header, 16)[0] in (2, 3)
            and struct.unpack_from("<H", header, 18)[0] == 62
            and (platform, architecture) == ("linux", "x86_64")):
        return
    if (platform, architecture) == ("macos", "aarch64"):
        if header[:4] == b"\xcf\xfa\xed\xfe" and len(header) >= 32 and struct.unpack_from("<I", header, 4)[0] == 0x0100000c:
            return
    if (platform, architecture) == ("windows", "x86_64") and header[:2] == b"MZ" and len(header) >= 64:
        offset = struct.unpack_from("<I", header, 0x3c)[0]
        if (offset <= len(header) - 26 and header[offset:offset + 4] == b"PE\0\0"
                and struct.unpack_from("<H", header, offset + 4)[0] == 0x8664
                and struct.unpack_from("<H", header, offset + 24)[0] == 0x20b):
            characteristics = struct.unpack_from("<H", header, offset + 22)[0]
            if bool(characteristics & 0x2000) == (path.suffix.lower() == ".dll"):
                return
    raise ValueError("wrong executable format or architecture: " + path.name)


def file_role(name, path):
    if name.startswith("licenses/"):
        return "license"
    if path.suffix.lower() in (".dll", ".so", ".dylib"):
        return "shared_library"
    if path.suffix.lower() == ".exe" or path.stat().st_mode & 0o111:
        return "executable"
    return "resource"


def validate_payload(payload, platform, architecture):
    files = payload_files(payload)
    paths = dict(files)
    binaries = {"nelomai-runtime", "nelomai-unix-service", "amneziawg-go"}
    licenses, scripts = set(COMMON_LICENSES), set()
    if platform == "linux":
        scripts.add("resolvconf")
    elif platform == "macos":
        binaries.add("wireguard-go")
        licenses.add("WIREGUARD-GO-LICENSE.txt")
    else:
        binaries = {"nelomai-runtime.exe", "nelomai-windows-service.exe"} | WINDOWS_DLLS
        licenses |= {"WIREGUARD-WINDOWS-LICENSE.txt", "WIREGUARD-NT-LICENSE.txt",
                     "AMNEZIAWG-WINDOWS-README.txt", "WINTUN-LICENSE.txt"}
    missing = ({"webview/index.html"} | binaries | scripts
               | {"licenses/" + name for name in licenses}) - paths.keys()
    if missing:
        raise ValueError("incomplete runtime payload: " + ", ".join(sorted(missing)))
    for name in binaries:
        if platform != "windows" and not paths[name].stat().st_mode & 0o111:
            raise ValueError("runtime executable permission missing")
    for name, path in files:
        if name in scripts:
            if not path.stat().st_mode & 0o111 or not path.read_bytes().startswith(b"#!/"):
                raise ValueError("invalid resolver script")
        elif file_role(name, path) in ("executable", "shared_library"):
            verify_binary(path, platform, architecture)
    return files


def sign_macos(files, version):
    if sys.platform != "darwin":
        raise ValueError("macOS runtime must be finalized on macOS")
    for name, path in files:
        if file_role(name, path) not in ("executable", "shared_library"):
            continue
        identifier = "ru.nelomai.runtime.v1." + version + "." + hashlib.sha256(name.encode()).hexdigest()[:16]
        # No --deep: sign only the newly built slot's exact executable files.
        # Published stable bytes are embedded later without another signing pass.
        subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none",
                        "--identifier", identifier, str(path)], check=True, capture_output=True)
        subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(path)],
                       check=True, capture_output=True)


def package(payload, output, version, source_commit, platform, architecture, signing_key):
    if (platform, architecture) not in TARGETS:
        raise ValueError("unsupported runtime target")
    if len(version) > 64 or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", version):
        raise ValueError("invalid runtime version")
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ValueError("invalid source commit")
    if output.exists() or output.is_symlink():
        raise ValueError("immutable output already exists")
    if output.resolve().is_relative_to(payload.resolve()) or signing_key.resolve().is_relative_to(payload.resolve()):
        raise ValueError("output and signing key must be outside payload")
    files = validate_payload(payload, platform, architecture)
    if any(path.samefile(signing_key) for _, path in files):
        raise ValueError("signing key must not be embedded through a hardlink")
    key = Ed25519PrivateKey.from_private_bytes(signing_key.read_bytes())
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="nelomai-desktop-artifact-", dir=output.parent) as temporary:
        final_payload = Path(temporary) / "payload"
        final_payload.mkdir()
        for name, source in files:
            destination = final_payload / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            destination.chmod(0o755 if file_role(name, source) == "executable" else 0o644)
        files = validate_payload(final_payload, platform, architecture)
        if platform == "macos":
            sign_macos(files, version)
        staged = Path(temporary) / "ready"
        staged.mkdir()
        index = []
        with zipfile.ZipFile(staged / "runtime.zip", "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, path in files:
                value = path.read_bytes()
                role = file_role(name, path)
                executable = role == "executable"
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (stat.S_IFREG | (0o755 if executable else 0o644)) << 16
                archive.writestr(info, value)
                index.append({"path": name, "size_bytes": len(value),
                              "sha256": hashlib.sha256(value).hexdigest(), "role": role})
        manifest = {"format_version": 1, "runtime_version": version, "source_commit": source_commit,
                    "platform": platform, "architecture": architecture, "contract_version": 1, "files": index}
        raw = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        if len(raw) > 1024 * 1024:
            raise ValueError("runtime manifest exceeds verifier size limit")
        (staged / "runtime-manifest-v1.json").write_bytes(raw)
        (staged / "runtime-manifest-v1.sig").write_bytes(key.sign(DOMAIN + raw))
        staged.rename(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("payload", "output", "signing-key"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("version", "source-commit", "platform", "architecture"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    package(args.payload, args.output, args.version, args.source_commit,
            args.platform, args.architecture, args.signing_key)


if __name__ == "__main__":
    main()
