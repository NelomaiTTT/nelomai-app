#!/usr/bin/env python3
"""Authenticate with the shared Rust contracts, then inspect exact extracted bytes.

This verifier never signs, builds, downloads, installs, or discovers private keys.
Compile its contracts adapter once with cargo build -p nelomai-contracts
--bin verify-runtime-manifest. Set NELOMAI_RUNTIME_CONTRACT_VERIFIER for a
non-default target directory. Platform jobs must run native binary inspection.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = (("android", "aarch64"), ("linux", "x86_64"), ("macos", "aarch64"), ("windows", "x86_64"))


def load_script(relative):
    spec = importlib.util.spec_from_file_location(relative.replace("/", "_").replace("-", "_"), ROOT / "scripts" / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("missing or nonregular artifact")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def authenticated(kind, manifest, signature, public_key, target, architecture="-"):
    executable = os.environ.get("NELOMAI_RUNTIME_CONTRACT_VERIFIER", str(ROOT / "target/debug" /
        ("verify-runtime-manifest.exe" if os.name == "nt" else "verify-runtime-manifest")))
    result = subprocess.run([executable, kind, str(manifest), str(signature), str(public_key), target, architecture],
                            check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def extract(archive_path, manifest, output):
    """Extract only authenticated files, with signed sizes and portable modes."""
    packager = load_script("package-runtime-artifact.py")
    entries = {item["path"]: item for item in manifest["files"]}
    if len(entries) != len(manifest["files"]):
        raise ValueError("duplicate runtime file")
    total = sum(item["size_bytes"] for item in entries.values())
    if total > 2 * 1024**3 or any(not 0 < item["size_bytes"] <= 512 * 1024**2 for item in entries.values()):
        raise ValueError("runtime file size limit")
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        if len(infos) != len(entries) or {item.filename for item in infos} != entries.keys():
            raise ValueError("archive differs from authenticated file set")
        for info in infos:
            packager.portable_alias(info.filename)
            item = entries[info.filename]
            expected_mode = 0o755 if item["role"] == "executable" else 0o644
            mode = info.external_attr >> 16
            if (info.is_dir() or info.flag_bits & 1 or not stat.S_ISREG(mode)
                    or stat.S_IMODE(mode) != expected_mode or info.file_size != item["size_bytes"]):
                raise ValueError("runtime archive type, mode, or size mismatch")
            path = output / info.filename
            path.parent.mkdir(parents=True, exist_ok=True)
            actual, written = hashlib.sha256(), 0
            with archive.open(info) as source, path.open("xb") as destination:
                while chunk := source.read(1024 * 1024):
                    written += len(chunk)
                    if written > item["size_bytes"]:
                        raise ValueError("runtime archive exceeds signed size")
                    actual.update(chunk)
                    destination.write(chunk)
            if actual.hexdigest() != item["sha256"] or written != item["size_bytes"]:
                raise ValueError("runtime payload digest mismatch")
            path.chmod(expected_mode)


def inspect(payload, manifest, readelf=None):
    platform, architecture = manifest["platform"], manifest["architecture"]
    if platform != "android":
        packager = load_script("package-runtime-artifact.py")
        files = packager.validate_payload(payload, platform, architecture)
        if platform == "macos":
            for name, path in files:
                if packager.file_role(name, path) not in ("executable", "shared_library"):
                    continue
                subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(path)], check=True, capture_output=True)
                detail = subprocess.run(["/usr/bin/codesign", "-dv", str(path)], check=True, capture_output=True, text=True)
                if "Signature=adhoc" not in detail.stderr:
                    raise ValueError("macOS runtime must retain its final ad-hoc signature")
    else:
        if readelf is None:
            raise ValueError("Android re-extraction requires LLVM readelf")
        packager = load_script("android/build-runtime-artifact.py")
        files = packager.payload_files(payload)
        required = {"licenses/" + name for name in packager.REQUIRED_LICENSES} | {
            "runtime/runtime.aar", "webview/index.html",
            "jni/arm64-v8a/libnelomai_runtime_stable.so", "jni/arm64-v8a/libstable_runtime_wg_go.so"}
        if not required <= {name for name, _ in files}:
            raise ValueError("compiled Android runtime payload is incomplete")
        packager.verify_runtime_abi(payload / "jni/arm64-v8a/libnelomai_runtime_stable.so", readelf)
        checker = packager.collision_module()
        for name, path in files:
            if name.endswith(".aar"):
                inventory = checker.inspect_archive(path.read_bytes(), readelf=readelf)
                if not inventory["classes"] or any(not name.startswith("ru.nelomai.runtime.stable.") for name in inventory["classes"]):
                    raise ValueError("unrelocated Android runtime class")
                if any(not name.split("/", 1)[1].startswith("stable_runtime_") for name in inventory["resources"]):
                    raise ValueError("unrelocated Android runtime resource")
            elif name.endswith(".so"):
                import io
                data = io.BytesIO()
                with zipfile.ZipFile(data, "w") as archive:
                    archive.writestr(name, path.read_bytes())
                checker.inspect_archive(data.getvalue(), readelf=readelf)


def verify(archive, manifest_path, signature, public_key, version, source, platform, architecture,
           readelf=None, output=None, inspect_native=True):
    if (platform, architecture) not in TARGETS:
        raise ValueError("unsupported runtime target")
    prefix = f"nelomai-runtime-{version}-{platform}-{architecture}"
    if (archive.name, manifest_path.name, signature.name) != (prefix + ".zip", prefix + ".manifest.json", prefix + ".manifest.sig"):
        raise ValueError("runtime filenames do not identify this immutable candidate")
    before = tuple(digest(path) for path in (archive, manifest_path, signature))
    manifest = authenticated("artifact", manifest_path, signature, public_key, platform, architecture)
    if manifest["runtime_version"] != version or manifest["source_commit"] != source:
        raise ValueError("runtime candidate identity mismatch")
    if output is not None and (output.exists() or output.is_symlink()):
        raise ValueError("immutable extraction output exists")
    with tempfile.TemporaryDirectory(prefix="runtime-verify-") as temporary:
        payload = Path(temporary) / "payload"
        payload.mkdir()
        extract(archive, manifest, payload)
        if inspect_native:
            inspect(payload, manifest, readelf)
        if before != tuple(digest(path) for path in (archive, manifest_path, signature)):
            raise ValueError("candidate changed during verification")
        if output is not None:
            import shutil
            shutil.copytree(payload, output)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "manifest", "signature", "public-key"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("version", "source-commit", "platform", "architecture"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--readelf", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    manifest = verify(args.archive, args.manifest, args.signature, args.public_key, args.version,
                      args.source_commit, args.platform, args.architecture, args.readelf, args.output)
    print(json.dumps({"archive_sha256": digest(args.archive), "files": len(manifest["files"]),
                      "uncompressed_bytes": sum(item["size_bytes"] for item in manifest["files"])}))


if __name__ == "__main__":
    main()
