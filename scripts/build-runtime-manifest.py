#!/usr/bin/env python3
"""Compose the existing final-byte packagers and assign immutable release names."""
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile


def package(payload, output, version, source_commit, platform, architecture, signing_key, readelf=None):
    if output.exists() or output.is_symlink():
        raise ValueError("immutable runtime output already exists")
    if (signing_key.resolve().is_relative_to(payload.resolve())
            or any(path.is_file() and path.samefile(signing_key) for path in payload.rglob("*"))):
        raise ValueError("signing key must be outside payload, including hardlinks")
    if signing_key.is_symlink() or signing_key.stat().st_size != 32:
        raise ValueError("explicit regular raw Ed25519 key required")
    if output.resolve().is_relative_to(payload.resolve()):
        raise ValueError("runtime output must be outside payload")
    scripts = Path(__file__).resolve().parent
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".runtime-release-", dir=output.parent) as temporary:
        artifact = Path(temporary) / "artifact"
        script = scripts / ("android/build-runtime-artifact.py" if platform == "android" else "package-runtime-artifact.py")
        command = [sys.executable, str(script), "--payload", str(payload), "--output", str(artifact),
                   "--version", version, "--source-commit", source_commit, "--signing-key", str(signing_key)]
        if platform == "android":
            if architecture != "aarch64" or readelf is None:
                raise ValueError("Android runtime requires aarch64 and LLVM readelf")
            command += ["--readelf", str(readelf)]
        else:
            command += ["--platform", platform, "--architecture", architecture]
        subprocess.run(command, check=True)
        prefix = f"nelomai-runtime-{version}-{platform}-{architecture}"
        for old, suffix in (("runtime.zip", ".zip"), ("runtime-manifest-v1.json", ".manifest.json"),
                            ("runtime-manifest-v1.sig", ".manifest.sig")):
            (artifact / old).rename(artifact / (prefix + suffix))
        artifact.rename(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("payload", "output", "signing-key"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("version", "source-commit", "platform", "architecture"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--readelf", type=Path)
    args = parser.parse_args()
    package(args.payload, args.output, args.version, args.source_commit,
            args.platform, args.architecture, args.signing_key, args.readelf)


if __name__ == "__main__":
    main()
