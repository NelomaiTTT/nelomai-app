"""Run the rollback regressions with a disposable runner Keychain."""

import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile


TESTS = (
    "common_host_preserves_runtime_record_across_version_rollback",
    "common_host_preserves_legacy_install_identity_after_completed_migration",
)


def security(operation, *args, require_quiet=False):
    result = subprocess.run(["/usr/bin/security", operation, *args], capture_output=True)
    if result.stderr:
        sys.stderr.write(os.fsdecode(result.stderr))
    if result.returncode:
        raise RuntimeError(f"security {operation} failed ({result.returncode})")
    if require_quiet and result.stderr:
        raise RuntimeError(f"security {operation} reported incomplete results")
    return os.fsdecode(result.stdout)


def keychain_paths(output):
    # security wraps each raw pathname in quotes without shell escaping.
    *lines, tail = output.split("\n")
    if tail:
        raise RuntimeError("unexpected security Keychain path output")
    paths = []
    for line in lines:
        quoted = line.lstrip(" \t")
        if not quoted.startswith('"/') or not quoted.endswith('"') or "\0" in quoted:
            raise RuntimeError("unexpected security Keychain path output")
        paths.append(quoted[1:-1])
    return paths


def default_keychain():
    result = subprocess.run(
        ["/usr/bin/security", "default-keychain", "-d", "user"], capture_output=True,
    )
    if result.returncode == 0 and not result.stderr:
        default = keychain_paths(os.fsdecode(result.stdout))
        if len(default) == 1:
            return default
    elif (result.returncode == 1 and not result.stdout
            and result.stderr.startswith(b"security: SecKeychainCopyDomainDefault ")):
        # security returns 1 for every OSStatus. Match the localized text
        # produced by the same tool for errSecNoDefaultKeychain.
        error = subprocess.run(
            ["/usr/bin/security", "error", "-25307"], capture_output=True,
        )
        description = error.stdout.partition(b" -25307 ")[2].strip()
        if description and result.stderr.rstrip().endswith(b": " + description):
            return []
    raise RuntimeError("cannot identify the runner's original default Keychain")


def main():
    if (sys.platform != "darwin" or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise RuntimeError("rollback Keychain setup requires a disposable hosted macOS runner")

    cargo = [
        "cargo", "test", "--locked", "--target", "aarch64-apple-darwin",
        "-p", "nelomai-client-container", "--test", "selection", "--",
        "--include-ignored", "--exact", *TESTS,
    ]
    listing = subprocess.check_output([*cargo, "--list", "--format", "terse"], text=True)
    if set(listing.splitlines()) != {f"{name}: test" for name in TESTS}:
        raise RuntimeError("expected both rollback tests in the native harness")

    default = default_keychain()
    search = keychain_paths(security("list-keychains", "-d", "user", require_quiet=True))
    if default:
        # The getter can return a stale path. Prove the native setter accepts
        # the original value before installing a temporary default.
        security("default-keychain", "-d", "user", "-s", *default, require_quiet=True)
    with tempfile.TemporaryDirectory(prefix="nelomai-rollback-", dir=os.environ["RUNNER_TEMP"]) as work:
        keychain = Path(work).resolve() / "rollback.keychain-db"
        password = secrets.token_urlsafe(32)
        try:
            security("create-keychain", "-p", password, keychain)
            security("unlock-keychain", "-p", password, keychain)
            security("default-keychain", "-d", "user", "-s", keychain, require_quiet=True)
            subprocess.run(cargo, check=True, env={
                **os.environ, "NELOMAI_TEST_ROLLBACK_KEYCHAIN": str(keychain),
            })
        finally:
            try:
                # With no original default, deleting the temporary one clears it.
                if default:
                    security("default-keychain", "-d", "user", "-s", *default, require_quiet=True)
            finally:
                try:
                    if keychain.exists():
                        security("delete-keychain", keychain)
                finally:
                    security("list-keychains", "-d", "user", "-s", *search, require_quiet=True)


if __name__ == "__main__":
    main()
