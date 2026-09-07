#!/usr/bin/env python3
"""Materialize explicit public pins or phase-local keys; never emit keys to stdout.

Build-only keys are deterministic PUBLIC TEST DATA, not release credentials.
They are regenerated per source/run, never uploaded as private-key artifacts.
"""
import argparse
import base64
import hashlib
import importlib.util
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("build_only", "sign_candidate", "publish_approved_candidate"), default="build_only")
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--private-key", type=Path)
    parser.add_argument("--phase", choices=("signing", "finalization"))
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("gates", Path(__file__).with_name("release-candidate-gates.py"))
    gates = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gates)
    source = os.environ["SOURCE_SHA"]
    gates.full_source(source)
    if args.private_key:
        gates.require_operation(args.mode, "test_sign" if args.mode == "build_only" else "release_sign")
        if not args.phase:
            raise ValueError("phase-local private key requires an explicit signing phase")
        if args.mode == "sign_candidate":
            gates.check_approvals(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_RUN_ID"],
                (gates.SIGNING_ENVIRONMENT if args.phase == "signing" else gates.FINALIZATION_ENVIRONMENT,),
                run_attempt=int(os.environ["GITHUB_RUN_ATTEMPT"]))
    private = None
    if args.mode == "build_only":
        # An intentionally public seed cannot later be mistaken for release
        # trust. Promotion independently rejects this mode and its provenance.
        private = hashlib.sha256(("NELOMAI-PUBLIC-TEST-ONLY-v1\0" + os.environ["GITHUB_REPOSITORY"]
            + "\0" + source + "\0" + os.environ["GITHUB_RUN_ID"]).encode()).digest()
        public = Ed25519PrivateKey.from_private_bytes(private).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    else:
        public = base64.b64decode(os.environ["NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64"], validate=True)
        if len(public) != 32:
            raise ValueError("explicit release public pin must be 32 bytes")
        if args.private_key:
            private = base64.b64decode(os.environ["NELOMAI_RELEASE_MANIFEST_PRIVATE_KEY_B64"], validate=True)
            if Ed25519PrivateKey.from_private_bytes(private).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) != public:
                raise ValueError("phase-local release key differs from pinned public key")
    for path, body in ((args.public_key, public), (args.private_key, private)):
        if path:
            if path.exists() or path.is_symlink():
                raise ValueError("immutable explicit trust output exists")
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(body)
            path.chmod(0o600 if path == args.private_key else 0o644)


if __name__ == "__main__":
    main()
