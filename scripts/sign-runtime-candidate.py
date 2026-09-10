#!/usr/bin/env python3
"""First signing phase: final runtime/root/container signatures, never native repacking.

Native jobs authenticate and inspect draft archives under ephemeral TEST keys.
This job repeats shared-contract and exact ZIP validation on all four targets,
then signs the unchanged payload indexes with the explicit final trust key.
Native outer packaging and installer/updater finalization happen afterward.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

spec = importlib.util.spec_from_file_location("aggregate", Path(__file__).with_name("build-runtime-release-set.py"))
aggregate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aggregate)
verifier = aggregate.verifier
gates = verifier.load_script("release-candidate-gates.py")


def sign(drafts, output, source, signing_key, public_key):
    gates.full_source(source)
    if output.exists() or output.is_symlink():
        raise ValueError("immutable signed candidate output exists")
    if signing_key.is_symlink() or signing_key.resolve().is_relative_to(drafts.resolve()):
        raise ValueError("private key must be a separate regular input, never a draft artifact")
    key = Ed25519PrivateKey.from_private_bytes(signing_key.read_bytes())
    if key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) != public_key.read_bytes():
        raise ValueError("final signer differs from runtime trust pin")
    if {path.name for path in drafts.iterdir()} != {platform for platform, _ in verifier.TARGETS}:
        raise ValueError("exactly four native draft directories required")
    # Complete read-only preflight before producing any final signatures.
    documents = {}
    snapshots = {}
    for platform, architecture in verifier.TARGETS:
        folder = drafts / platform
        if (folder / "runtime-public-key.raw").read_bytes() != public_key.read_bytes():
            raise ValueError("native compile-time runtime pin differs from final signer")
        prefix = f"nelomai-runtime-0.2.17-{platform}-{architecture}"
        for slot in ("stable", "latest"):
            paths = [folder / slot / (prefix + suffix) for suffix in (".zip", ".manifest.json", ".manifest.sig")]
            snapshots.update({path: verifier.digest(path) for path in paths})
            documents[platform, slot] = verifier.verify(*paths, folder / "draft-public-key.raw", "0.2.17",
                source, platform, architecture, inspect_native=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".final-runtime-", dir=output.parent) as temporary:
        staged = Path(temporary) / "signed"
        release = staged / "release"
        release.mkdir(parents=True)
        for platform, architecture in verifier.TARGETS:
            prefix = f"nelomai-runtime-0.2.17-{platform}-{architecture}"
            for slot in ("stable", "latest"):
                destination = release if slot == "stable" else staged / "latest" / platform
                destination.mkdir(parents=True, exist_ok=True)
                for suffix in (".zip", ".manifest.json"):
                    shutil.copyfile(drafts / platform / slot / (prefix + suffix), destination / (prefix + suffix))
                body = (destination / (prefix + ".manifest.json")).read_bytes()
                (destination / (prefix + ".manifest.sig")).write_bytes(key.sign(b"nelomai-runtime-manifest-v1\0" + body))
        digest = aggregate.build(release, staged / "root", "0.2.17", source, signing_key, public_key)
        for path in (staged / "root").iterdir():
            path.rename(release / path.name)
        (staged / "root").rmdir()
        for platform, architecture in verifier.TARGETS:
            prefix = f"nelomai-runtime-0.2.17-{platform}-{architecture}"
            for kind in ("shipping", "acceptance"):
                latest = documents[platform, "latest"]
                if kind == "acceptance":
                    latest = {**latest, "runtime_version": "0.2.18"}
                container = dict(format_version=1, container_version="0.2.17",
                    release_set_id=kind + "-" + source, minimum_runtime_contract=1, maximum_runtime_contract=1,
                    slots=[dict(slot="latest", manifest=latest)])
                if kind == "acceptance":
                    container.update(stable_release_set_sha256=digest,
                        stable_platform_manifest_sha256=verifier.digest(release / (prefix + ".manifest.json")))
                    container["slots"].append(dict(slot="stable", manifest=documents[platform, "stable"]))
                destination = staged / "containers" / platform / kind
                destination.mkdir(parents=True)
                manifest, signature = destination / "container-manifest-v1.json", destination / "container-manifest-v1.sig"
                body = aggregate.canonical(container)
                manifest.write_bytes(body)
                signature.write_bytes(key.sign(b"nelomai-container-manifest-v1\0" + body))
                verifier.authenticated("container", manifest, signature, public_key, platform, architecture)
        if snapshots != {path: verifier.digest(path) for path in snapshots}:
            raise ValueError("native draft changed during signing")
        shutil.copyfile(public_key, staged / "runtime-public-key.raw")
        staged.rename(output)
    return digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("drafts", "output", "signing-key", "public-key"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--mode", choices=("build_only", "sign_candidate"), default="build_only")
    args = parser.parse_args()
    gates.require_operation(args.mode, "test_sign" if args.mode == "build_only" else "release_sign")
    print(sign(args.drafts, args.output, args.source_sha, args.signing_key, args.public_key))


if __name__ == "__main__":
    main()
