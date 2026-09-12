#!/usr/bin/env python3
"""Keyless native wrapping after final embedded manifest signatures.

Only the ordinary shipping installer is built by the release pipeline.
No installer execution, signing credentials, or publication is allowed here.
"""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil

spec = importlib.util.spec_from_file_location("builder", Path(__file__).with_name("build-release-platform.py"))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
verifier = builder.verifier
container = verifier.load_script("build-runtime-acceptance-container.py")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("signed", "draft", "output", "public-key"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("platform", "architecture", "source-sha", "release-set-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--mode", choices=("build_only", "sign_candidate"), default="build_only")
    parser.add_argument("--ndk", type=Path)
    parser.add_argument("--include-acceptance", action="store_true", help="Also build explicit diagnostic test inputs")
    args = parser.parse_args()
    builder.gates.require_operation(args.mode, "build")
    if any(os.environ.get(name) for name in ("TAURI_SIGNING_PRIVATE_KEY", "NELOMAI_RELEASE_MANIFEST_PRIVATE_KEY_B64",
            "ANDROID_KEYSTORE_PATH", "ANDROID_KEYSTORE_PASSWORD", "ANDROID_KEY_PASSWORD")):
        raise ValueError("native wrapper must be keyless")
    if (args.signed / "runtime-public-key.raw").read_bytes() != args.public_key.read_bytes():
        raise ValueError("native compile pin differs from final signed candidate")
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("immutable native package output exists")
    for name in ("signed", "draft", "output", "public_key"):
        setattr(args, name, getattr(args, name).resolve())
    environment = {**os.environ, "NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64": base64.b64encode(args.public_key.read_bytes()).decode()}
    builder.run("cargo", "build", "--locked", "-p", "nelomai-contracts", "--bin", "verify-runtime-manifest", env=environment)
    readelf = None
    if args.platform == "android":
        if args.ndk is None:
            raise ValueError("Android native wrapper requires NDK")
        compiler = verifier.load_script("android/build-tunnel-runtime.py").ndk_compiler(args.ndk)
        readelf = compiler.with_name("llvm-readelf")
        builder.run("cargo", "fetch", "--locked", env=environment)
        builder.script("android/generate-build-inputs.py", "--root", builder.ROOT, env=environment)
        if args.mode == "sign_candidate" and not all(environment.get(name) for name in (
            "NELOMAI_FIREBASE_APPLICATION_ID", "NELOMAI_FIREBASE_API_KEY", "NELOMAI_FIREBASE_PROJECT_ID")):
            raise ValueError("candidate Android packaging requires public Firebase release configuration")
    packages = {}
    for kind in (("shipping", "acceptance") if args.include_acceptance else ("shipping",)):
        staged = args.output / "staged" / kind
        container.stage_signed(args.signed, args.release_set_sha256, staged, args.public_key,
            args.platform, args.architecture, args.source_sha, kind, readelf)
        work = args.output / "work" / kind
        if args.platform == "android":
            package = container.package_android(staged, work, args.public_key, readelf,
                args.ndk.parent.parent / "cmdline-tools/latest/bin/apkanalyzer", args.draft / "common-host.so",
                acceptance=kind == "acceptance", variant="Release" if args.mode == "sign_candidate" else "Debug",
                environment=environment, offline=False)
        else:
            package = container.package_desktop(staged, work, args.public_key, args.platform, args.architecture,
                                                environment=environment)
        name = package.name.replace("nelomai-acceptance-", "nelomai-") if kind == "shipping" else package.name
        destination = args.output / kind / name
        destination.parent.mkdir(parents=True)
        shutil.copyfile(package, destination)
        packages[kind] = {"name": name, "sha256": verifier.digest(destination), "size_bytes": destination.stat().st_size}
    if args.platform == "android":
        for suffix in (".tar.gz", ".tar.gz.sha256"):
            name = "nelomai-0.2.19-amneziawg-android-source" + suffix
            shutil.copyfile(args.draft / name, args.output / "shipping" / name)
    (args.output / "package-digests.json").write_text(json.dumps(dict(source_sha=args.source_sha,
        release_set_sha256=args.release_set_sha256, platform=args.platform, architecture=args.architecture,
        mode=args.mode, packages=packages, native_payloads="verified", full_acceptance="UNRUN"), sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
