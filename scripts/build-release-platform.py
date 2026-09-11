#!/usr/bin/env python3
"""Pinned native payload build; no release private key is accepted here.

The workflow supplies one explicit runtime trust key before any compilation.
Updater minisign keys remain a separate format. This command never publishes,
installs, elevates, contacts the panel, or edits bundled vendor sources itself.
"""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("runtime_verifier", ROOT / "scripts/verify-runtime-artifact.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
gates = verifier.load_script("release-candidate-gates.py")


def build_trust(mode, private, public):
    gates.require_operation(mode, "build")
    if private.is_symlink() or public.is_symlink():
        raise ValueError("explicit regular trust files required")
    key = Ed25519PrivateKey.from_private_bytes(private.read_bytes())
    if key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) != public.read_bytes():
        raise ValueError("build signer differs from runtime trust pin")
    return gates.mode_policy(mode)


def run(*command, cwd=ROOT, env=None, capture=False):
    return subprocess.run(list(map(str, command)), cwd=cwd, env=env, check=True,
                          capture_output=capture, text=True, encoding="utf-8")


def script(name, *arguments, **kwargs):
    return run(sys.executable, ROOT / "scripts" / name, *arguments, **kwargs)


def updater_environment(mode, work, environment):
    environment = environment.copy()
    cli = ROOT / "node_modules/.bin" / ("tauri.cmd" if os.name == "nt" else "tauri")
    if mode == "build_only":
        private = work / "TEST-ONLY-updater.key"
        run(cli, "signer", "generate", "--ci", "--password", "", "--write-keys", private, capture=True)
        private.chmod(0o600)
        environment["TAURI_SIGNING_PRIVATE_KEY"] = private.read_text().strip()
        environment["TAURI_SIGNING_PRIVATE_KEY_PASSWORD"] = ""
        environment["NELOMAI_UPDATER_PUBLIC_KEY"] = private.with_suffix(".key.pub").read_text().strip()
    elif not all(environment.get(name) for name in ("TAURI_SIGNING_PRIVATE_KEY", "NELOMAI_UPDATER_PUBLIC_KEY")):
        raise ValueError("approved candidate requires separate Tauri updater trust")
    return environment


def desktop(args, work, environment):
    target = {"linux": "x86_64-unknown-linux-gnu", "windows": "x86_64-pc-windows-msvc",
              "macos": "aarch64-apple-darwin"}[args.platform]
    service = "nelomai-windows-service" if args.platform == "windows" else "nelomai-unix-service"
    extension = ".exe" if args.platform == "windows" else ""
    run("cargo", "build", "--locked", "--release", "--target", target, "-p", service, env=environment)
    run("cargo", "build", "--locked", "--release", "--target", target, "-p", "nelomai-app",
        "--features", "custom-protocol,desktop-runtime", "--bin", "nelomai-runtime", env=environment)
    if args.platform == "windows":
        run("cargo", "test", "--locked", "--target", target, "-p", "nelomai-windows-service", env=environment)
        run("pwsh", "-NoProfile", "-File", ROOT / "crates/windows-service/tests/defender-exclusions.ps1", env=environment)
        run("pwsh", "-NoProfile", "-File", ROOT / "scripts/windows/prepare-runtime.ps1", env=environment)
        native = ROOT / "src-tauri/windows/runtime"
    else:
        run("sh", ROOT / "scripts/unix/prepare-runtime.sh", args.platform, target, env=environment)
        native = ROOT / "src-tauri/platform-runtime"
    payload = work / "latest-payload"
    payload.mkdir()
    for path in native.iterdir():
        if path.is_file():
            destination = payload / ("licenses" if path.suffix.lower() == ".txt" else "") / path.name
            destination.parent.mkdir(exist_ok=True)
            shutil.copy2(path, destination)
    shutil.copy2(ROOT / "target" / target / "release" / ("nelomai-runtime" + extension), payload / ("nelomai-runtime" + extension))
    graph = json.loads(run("cargo", "metadata", "--locked", "--format-version", "1", capture=True).stdout)
    tauri = next(Path(package["manifest_path"]).parent for package in graph["packages"] if package["name"] == "tauri")
    for source, name in (("LICENSE_MIT", "TAURI-MIT.txt"), ("LICENSE_APACHE-2.0", "TAURI-APACHE-2.0.txt")):
        shutil.copyfile(tauri / source, payload / "licenses" / name)
    shutil.copytree(ROOT / "build", payload / "webview")
    runtime_output = args.output / "stable"
    verifier.load_script("build-runtime-manifest.py").package(payload, runtime_output, "0.2.18", args.source_sha,
        args.platform, args.architecture, args.draft_key)
    prefix = f"nelomai-runtime-0.2.18-{args.platform}-{args.architecture}"
    manifest = verifier.verify(*(runtime_output / (prefix + suffix) for suffix in (".zip", ".manifest.json", ".manifest.sig")),
        args.draft_public, "0.2.18", args.source_sha, args.platform, args.architecture)
    # Both identities consume already finalized native bytes. Synthetic latest
    # changes only its container identity, not the immutable stable package.
    shutil.copytree(runtime_output, args.output / "latest")
    return manifest


def android(args, work, environment):
    if args.ndk is None or args.go_archive is None:
        raise ValueError("Android build requires explicit NDK and cached pinned Go archive")
    compiler = verifier.load_script("android/build-tunnel-runtime.py").ndk_compiler(args.ndk)
    readelf = compiler.with_name("llvm-readelf")
    environment = {**environment, "CC_aarch64_linux_android": str(compiler),
        "AR_aarch64_linux_android": str(compiler.with_name("llvm-ar")),
        "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER": str(compiler), "CARGO_PROFILE_RELEASE_STRIP": "symbols"}
    # Metadata resolves the entire locked graph, including non-host targets.
    # Building only the contracts verifier does not populate that cold cache.
    run("cargo", "fetch", "--locked", env=environment)
    script("android/generate-build-inputs.py", "--root", ROOT, env=environment)
    gradle = ROOT / "src-tauri/gen/android/gradlew"
    android_root = gradle.parent
    # Resolve/build JVM inputs before offline deterministic stable generation.
    run(gradle, ":app:testArm64DebugUnitTest", ":tauri-plugin-tunnel-android:testDebugUnitTest",
        ":stable-runtime-android:assembleDebug", "--no-daemon", cwd=android_root, env=environment)
    run("cargo", "rustc", "--locked", "--release", "-p", "nelomai-android-container", "--target", "aarch64-linux-android",
        "--", "-C", "link-arg=-Wl,-soname,libnelomai_android_container.so", env=environment)
    latest_env = {**environment, "WRY_ANDROID_PACKAGE": "ru.nelomai.client", "WRY_ANDROID_LIBRARY": "nelomai_app_lib",
        "WRY_ANDROID_KOTLIN_FILES_OUT_DIR": str(android_root / "app/src/main/java/ru/nelomai/client/generated")}
    run("cargo", "rustc", "--locked", "--release", "-p", "nelomai-app", "--lib", "--features", "custom-protocol",
        "--target", "aarch64-linux-android", "--", "-C", "link-arg=-Wl,-soname,libnelomai_app_lib.so", env=latest_env)
    stable_source = work / "stable-source"
    script("android/prepare-stable-rust.py", "--root", ROOT, "--output", stable_source, env=environment)
    stable_env = {**environment, "WRY_ANDROID_PACKAGE": "ru.nelomai.runtime.stable", "WRY_ANDROID_LIBRARY": "nelomai_runtime_stable",
        "WRY_ANDROID_KOTLIN_FILES_OUT_DIR": str(stable_source / "src-tauri/gen/android/app/src/main/java/ru/nelomai/client/generated")}
    # The reviewed generator introduces local path patches; resolve only this
    # generated lockfile offline, never rewrite the pinned repository lockfile.
    run("cargo", "rustc", "--offline", "--release", "-p", "nelomai-app", "--lib", "--features", "custom-protocol",
        "--target", "aarch64-linux-android", "--target-dir", work / "stable-target", "--", "-C",
        "link-arg=-Wl,-soname,libnelomai_runtime_stable.so", cwd=stable_source, env=stable_env)
    for slot in ("latest", "stable"):
        script("android/build-tunnel-runtime.py", "--root", ROOT, "--output", work / (slot + "-tunnel"),
            "--ndk", args.ndk, "--go-archive", args.go_archive, "--slot", slot, env=environment)
        native = (ROOT / "target/aarch64-linux-android/release/libnelomai_app_lib.so" if slot == "latest" else
                  work / "stable-target/aarch64-linux-android/release/libnelomai_runtime_stable.so")
        tunnel = work / (slot + "-tunnel") / "jni/arm64-v8a" / ("libwg-go.so" if slot == "latest" else "libstable_runtime_wg_go.so")
        command = ["--root", ROOT, "--output", work / (slot + "-stage"), "--native", native, "--tunnel", tunnel,
            "--readelf", readelf, "--slot", slot, "--source-commit", args.source_sha]
        script("android/stage-runtime-build.py", *command, env=environment)
    script("android/check-runtime-collisions.py", "--latest", work / "latest-stage/collision-input.zip",
        "--stable", work / "stable-stage/collision-input.zip", "--readelf", readelf, env=environment)
    runtime_output = args.output / "stable"
    verifier.load_script("build-runtime-manifest.py").package(work / "stable-stage/payload", runtime_output,
        "0.2.18", args.source_sha, "android", "aarch64", args.draft_key, readelf)
    prefix = "nelomai-runtime-0.2.18-android-aarch64"
    manifest = verifier.verify(*(runtime_output / (prefix + suffix) for suffix in (".zip", ".manifest.json", ".manifest.sig")),
        args.draft_public, "0.2.18", args.source_sha, "android", "aarch64", readelf=readelf)
    latest = args.output / "latest"
    latest.mkdir()
    shutil.copyfile(work / "latest-stage/collision-input.zip", latest / (prefix + ".zip"))
    raw = (work / "latest-stage/runtime-manifest-v1.json").read_bytes()
    (latest / (prefix + ".manifest.json")).write_bytes(raw)
    (latest / (prefix + ".manifest.sig")).write_bytes(
        Ed25519PrivateKey.from_private_bytes(args.draft_key.read_bytes()).sign(b"nelomai-runtime-manifest-v1\0" + raw))
    verifier.verify(*(latest / (prefix + suffix) for suffix in (".zip", ".manifest.json", ".manifest.sig")),
        args.draft_public, "0.2.18", args.source_sha, "android", "aarch64", inspect_native=False)
    shutil.copyfile(ROOT / "target/aarch64-linux-android/release/libnelomai_android_container.so", args.output / "common-host.so")
    source_archive(args.output, work, args.source_sha)
    return manifest


def source_archive(output, work, source):
    source_tar = work / "source.tar"
    with source_tar.open("xb") as stream:
        subprocess.run(["git", "archive", "--format=tar", source], cwd=ROOT, stdout=stream, check=True)
    destination = output / "nelomai-0.2.18-amneziawg-android-source.tar.gz"
    with tarfile.open(destination, "w:gz") as result:
        with tarfile.open(source_tar) as archive:
            for member in archive:
                if member.isfile() and not any(part.startswith(".env") for part in Path(member.name).parts):
                    result.addfile(member, archive.extractfile(member))
        for vendor in ("amneziawg-android", "amneziawg-go"):
            vendor_tar = work / (vendor + ".tar")
            with vendor_tar.open("xb") as stream:
                subprocess.run(["git", "archive", "--format=tar", "HEAD"], cwd=ROOT / "vendor" / vendor, stdout=stream, check=True)
            with tarfile.open(vendor_tar) as archive:
                for member in archive:
                    if member.isfile():
                        member.name = "vendor/" + vendor + "/" + member.name
                        result.addfile(member, archive.extractfile(member))
    destination.with_name(destination.name + ".sha256").write_text(verifier.digest(destination) + "  " + destination.name + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("platform", "architecture", "source-sha", "mode"):
        parser.add_argument("--" + name, required=True)
    for name in ("public-key", "output", "work"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--ndk", type=Path)
    parser.add_argument("--go-archive", type=Path)
    args = parser.parse_args()
    gates.require_operation(args.mode, "build")
    policy = gates.mode_policy(args.mode)
    if args.public_key.is_symlink() or args.public_key.stat().st_size != 32:
        raise ValueError("explicit regular raw compile-time public pin required")
    gates.verify_source(ROOT, args.source_sha, "0.2.18", mode=args.mode)
    if (args.platform, args.architecture) not in verifier.TARGETS:
        raise ValueError("unsupported native release target")
    if args.work.exists() or args.output.exists():
        raise ValueError("immutable native build output already exists")
    for name in ("work", "output", "public_key"):
        setattr(args, name, getattr(args, name).resolve())
    args.work.mkdir(parents=True)
    args.output.mkdir(parents=True)
    args.draft_key = args.work / "EPHEMERAL-DRAFT-KEY.raw"
    args.draft_public = args.output / "draft-public-key.raw"
    key = Ed25519PrivateKey.generate()
    args.draft_key.write_bytes(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    args.draft_key.chmod(0o600)
    args.draft_public.write_bytes(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    shutil.copyfile(args.public_key, args.output / "runtime-public-key.raw")
    environment = {**os.environ, "NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64": base64.b64encode(args.public_key.read_bytes()).decode()}
    run("cargo", "build", "--locked", "-p", "nelomai-contracts", "--bin", "verify-runtime-manifest", env=environment)
    run("npm.cmd" if os.name == "nt" else "npm", "run", "build", env=environment)
    manifest = (android if args.platform == "android" else desktop)(args, args.work, environment)
    report = dict(platform=args.platform, architecture=args.architecture, source_sha=args.source_sha,
        trust=policy["trust"], native_verification="verified", files=len(manifest["files"]),
        uncompressed_runtime_bytes=sum(item["size_bytes"] for item in manifest["files"]),
        assets={path.relative_to(args.output).as_posix(): {"sha256": verifier.digest(path), "size_bytes": path.stat().st_size}
                for path in args.output.rglob("*") if path.is_file()}, execution_acceptance="UNRUN")
    (args.output / f"{args.platform}-{args.architecture}.sizes.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
