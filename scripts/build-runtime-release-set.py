#!/usr/bin/env python3
"""Aggregate four authenticated final runtime archives into one immutable root.

Native re-extraction is mandatory in each platform job. The aggregation host
repeats signatures, contract, identity and ZIP/file checks for all platforms;
it does not claim to execute foreign native binaries.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

spec = importlib.util.spec_from_file_location("runtime_verifier", Path(__file__).with_name("verify-runtime-artifact.py"))
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
DOMAIN = b"nelomai-runtime-release-set-v1\0"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def collect(input_dir, version, source, public_key):
    manifests = sorted(input_dir.rglob("nelomai-runtime-*.manifest.json"))
    manifests = [path for path in manifests if not path.name.endswith("-release-set.manifest.json")]
    if len(manifests) != 4:
        raise ValueError("exactly four successful platform artifacts required")
    result, seen = [], set()
    for platform, architecture in verifier.TARGETS:
        prefix = f"nelomai-runtime-{version}-{platform}-{architecture}"
        matches = [path for path in manifests if path.name == prefix + ".manifest.json"]
        if len(matches) != 1:
            raise ValueError("missing or duplicate runtime target")
        manifest = matches[0]
        archive, signature = manifest.with_name(prefix + ".zip"), manifest.with_name(prefix + ".manifest.sig")
        snapshots = [verifier.digest(path) for path in (archive, manifest, signature)]
        verifier.verify(archive, manifest, signature, public_key, version, source,
                        platform, architecture, inspect_native=False)
        if snapshots != [verifier.digest(path) for path in (archive, manifest, signature)]:
            raise ValueError("candidate changed during aggregation")
        entry = {"platform": platform, "architecture": architecture}
        for kind, path, digest in zip(("archive", "manifest", "signature"), (archive, manifest, signature), snapshots):
            if path.name in seen:
                raise ValueError("mutable or duplicate runtime asset name")
            seen.add(path.name)
            entry[kind + "_name"] = path.name
            entry[kind + "_sha256"] = digest
        result.append(entry)
    return result


def build(input_dir, output, version, source, signing_key, public_key):
    if output.exists() or output.is_symlink():
        raise ValueError("immutable release-set output already exists")
    artifacts = collect(input_dir, version, source, public_key)
    if signing_key.is_symlink():
        raise ValueError("explicit regular signing key required")
    key = Ed25519PrivateKey.from_private_bytes(signing_key.read_bytes())
    if key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) != public_key.read_bytes():
        raise ValueError("release-set signer differs from runtime trust root")
    body = dict(format_version=1, release_set_id=f"nelomai-runtime-{version}-{source}",
                runtime_version=version, source_commit=source, artifacts=artifacts)
    raw = canonical(body)
    name = f"nelomai-runtime-{version}-release-set.manifest"
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".runtime-root-", dir=output.parent) as temporary:
        staged = Path(temporary) / "root"
        staged.mkdir()
        manifest, signature = staged / (name + ".json"), staged / (name + ".sig")
        manifest.write_bytes(raw)
        signature.write_bytes(key.sign(DOMAIN + raw))
        digest = verifier.digest(manifest)
        verifier.authenticated("release-set", manifest, signature, public_key, digest)
        staged.rename(output)
    return digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("input-dir", "output", "signing-key", "public-key"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("version", "source-commit"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    digest = build(args.input_dir, args.output, args.version, args.source_commit, args.signing_key, args.public_key)
    print(json.dumps({"stable_manifest_sha256": digest}))


if __name__ == "__main__":
    main()
