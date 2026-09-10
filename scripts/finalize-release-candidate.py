#!/usr/bin/env python3
"""Second protected phase: sign final installers, never rebuild embedded payloads.

Candidate inventory contains only an explicit ordinary shipping allowlist.
Only shipping packages enter this phase; acceptance installers are not required.
"""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import zipfile

spec = importlib.util.spec_from_file_location("builder", Path(__file__).with_name("build-release-platform.py"))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
gates, verifier = builder.gates, builder.verifier


def apk_payload(archive):
    with zipfile.ZipFile(archive) as apk:
        names = apk.namelist()
        if len(names) != len(set(names)):
            raise ValueError("duplicate APK entries")
        return {name: __import__("hashlib").sha256(apk.read(name)).hexdigest() for name in names
                if not re.fullmatch(r"META-INF/(?:MANIFEST\.MF|[^/]+\.(?:SF|RSA|DSA|EC))", name)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("packages", "signed", "output", "private-key", "public-key", "work", "sdk"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("source-sha", "release-set-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--mode", choices=("build_only", "sign_candidate"), default="build_only")
    args = parser.parse_args()
    policy = builder.build_trust(args.mode, args.private_key, args.public_key)
    gates.require_operation(args.mode, "test_sign" if args.mode == "build_only" else "release_sign")
    identities = {}
    if args.output.exists() or args.work.exists():
        raise ValueError("immutable installer finalization output exists")
    gates.verify_runtime_release(args.signed / "release", "0.2.17", args.source_sha, args.release_set_sha256, args.public_key)
    args.work.mkdir(parents=True)
    environment = builder.updater_environment(args.mode, args.work, os.environ)
    cli = builder.ROOT / "node_modules/.bin/tauri"
    final_inputs = args.work / "collector"
    final_inputs.mkdir()
    for platform, architecture in verifier.TARGETS:
        folder = args.packages / platform
        index = json.loads((folder / "package-digests.json").read_bytes())
        if (index.get("source_sha") != args.source_sha or index.get("release_set_sha256") != args.release_set_sha256
                or index.get("mode") != args.mode or index.get("platform") != platform or index.get("architecture") != architecture):
            raise ValueError("native package identity mismatch")
        name = gates.PACKAGE_NAMES[platform]
        path = folder / "shipping" / name
        expected = index["packages"]["shipping"]
        if expected != dict(name=name, sha256=verifier.digest(path), size_bytes=path.stat().st_size):
            raise ValueError("native package changed before final signing")
        destination = args.work / ("shipping-" + name)
        shutil.copyfile(path, destination)
        if platform == "android":
            apksigner = args.sdk / "build-tools/36.0.0/apksigner"
            before = apk_payload(destination)
            if args.mode == "sign_candidate":
                builder.run(apksigner, "sign", "--ks", os.environ["ANDROID_KEYSTORE_PATH"],
                    "--ks-key-alias", os.environ["ANDROID_KEY_ALIAS"], "--ks-pass", "env:ANDROID_KEYSTORE_PASSWORD",
                    "--key-pass", "env:ANDROID_KEY_PASSWORD", destination, env=environment, capture=True)
            if apk_payload(destination) != before:
                raise ValueError("APK signing changed final runtime/DEX/resource bytes")
            certificate = builder.run(apksigner, "verify", "--verbose", "--print-certs", destination,
                                      capture=True, env=environment).stdout
            matches = re.findall(r"^Signer #1 certificate SHA-256 digest: ([0-9a-f]{64})$", certificate, re.MULTILINE)
            if len(matches) != 1 or (args.mode == "sign_candidate" and matches[0] != os.environ["ANDROID_SIGNER_SHA256"]):
                raise ValueError("final APK signer differs from explicit release certificate pin")
            builder.script("collect-android-release-artifact.py", "--apk", destination, "--output-dir", final_inputs,
                "--version", "0.2.17", "--signer-sha256", matches[0])
        else:
            before = verifier.digest(destination)
            builder.run(cli, "signer", "sign", destination, env=environment, capture=True)
            if verifier.digest(destination) != before:
                raise ValueError("updater signing changed final installer bytes")
            builder.script("collect-release-artifact.py", "--search-root", args.work, "--output-dir", final_inputs,
                "--version", "0.2.17", "--platform", platform, "--architecture", architecture,
                "--package-kind", {"linux": "appimage", "macos": "app", "windows": "nsis"}[platform])
    environment["NELOMAI_RELEASE_MANIFEST_PRIVATE_KEY_B64"] = base64.b64encode(args.private_key.read_bytes()).decode()
    candidate = args.output / "candidate"
    builder.script("build-release-manifest.py", "--input-dir", final_inputs, "--output-dir", candidate,
                   "--version", "0.2.17", env=environment)
    for path in (args.signed / "release").iterdir():
        shutil.copyfile(path, candidate / path.name)
    for suffix in (".tar.gz", ".tar.gz.sha256"):
        name = "nelomai-0.2.17-amneziawg-android-source" + suffix
        shutil.copyfile(args.packages / "android/shipping" / name, candidate / name)
    if {path.name for path in candidate.iterdir()} != gates.PUBLISH_ASSETS:
        raise ValueError("final candidate must match the exact ordinary shipping asset allowlist")
    updater_public = args.work / "updater-public.b64"
    updater_public.write_text(environment["NELOMAI_UPDATER_PUBLIC_KEY"])
    android_metadata = json.loads((final_inputs / "android-aarch64.artifact.json").read_bytes())
    gates.verify_updater_release(candidate, args.public_key, updater_public, android_metadata["signature"])
    inventory = dict(source_sha=args.source_sha, release_set_sha256=args.release_set_sha256, mode=args.mode,
        trust=policy["trust"], purpose="shipping", run_id=os.environ["GITHUB_RUN_ID"],
        run_attempt=int(os.environ["GITHUB_RUN_ATTEMPT"]), environment_ids=identities,
        assets={path.name: verifier.digest(path) for path in candidate.iterdir()})
    (candidate / "candidate-inventory.json").write_bytes(verifier.load_script("build-runtime-release-set.py").canonical(inventory))
    print(json.dumps(dict(inventory_sha256=verifier.digest(candidate / "candidate-inventory.json"))))


if __name__ == "__main__":
    main()
