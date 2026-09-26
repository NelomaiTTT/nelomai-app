#!/usr/bin/env python3
"""Sign only the common host of an already verified macOS shipping package.

No compilation, embedded-runtime signing, installation or Keychain item migration.
Production credentials are scoped to this phase, never to native packaging.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import tarfile
import tempfile

IDENTIFIER = "ru.nelomai.client"
SECRET_NAMES = ("NELOMAI_MACOS_SIGNING_P12_BASE64", "NELOMAI_MACOS_SIGNING_P12_PASSWORD")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def requirement(pin):
    if not re.fullmatch(r"[0-9a-fA-F]{40}", pin):
        raise ValueError("explicit macOS certificate SHA1 pin required")
    return f'identifier "{IDENTIFIER}" and certificate leaf = H"{pin.lower()}"'


def signature_metadata(pin):
    return dict(identifier=IDENTIFIER, certificate_sha1=pin.lower(), designated_requirement=requirement(pin))


def run(*command):
    # Never expose argv or native stderr: security arguments include passwords.
    environment = {k: v for k, v in os.environ.items() if k not in SECRET_NAMES}
    try:
        result = subprocess.run([str(c) for c in command], capture_output=True, text=True,
                                timeout=60, env=environment)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("macOS signing command could not complete") from None
    if result.returncode:
        raise RuntimeError(f"macOS signing command failed ({Path(command[0]).name}, exit {result.returncode})")
    return result.stdout + result.stderr


def verify_signature(app, pin):
    expected = requirement(pin)
    run("/usr/bin/codesign", "--verify", "--strict", "-R", "=" + expected, app)
    details = run("/usr/bin/codesign", "--display", "-r-", app)
    if re.findall(r"^designated => (.+)$", details, re.MULTILINE) != [expected]:
        raise ValueError("macOS common designated requirement is not the stable pinned identity")


def sign_bundle(app, pin, work, environment):
    expected = requirement(pin)
    with tempfile.TemporaryDirectory(prefix="signing-", dir=work) as temporary:
        private = Path(temporary)
        keychain = private / "common.keychain-db"
        p12 = private / "identity.p12"
        p12.write_bytes(base64.b64decode(environment[SECRET_NAMES[0]], validate=True))
        p12.chmod(0o600)
        password = secrets.token_urlsafe(32)
        search = shlex.split(run("/usr/bin/security", "list-keychains", "-d", "user"))
        try:
            run("/usr/bin/security", "create-keychain", "-p", password, keychain)
            run("/usr/bin/security", "unlock-keychain", "-p", password, keychain)
            run("/usr/bin/security", "import", p12, "-k", keychain, "-P", environment[SECRET_NAMES[1]],
                "-T", "/usr/bin/codesign")
            run("/usr/bin/security", "set-key-partition-list", "-S", "apple-tool:,apple:,codesign:",
                "-s", "-k", password, keychain)
            run("/usr/bin/security", "list-keychains", "-d", "user", "-s", *search, keychain)
            run("/usr/bin/codesign", "--force", "--sign", pin, "--keychain", keychain,
                "--identifier", IDENTIFIER, "--requirements", "=designated => " + expected,
                "--preserve-metadata=entitlements,flags", "--timestamp=none", app)
            verify_signature(app, pin)
        finally:
            try:
                run("/usr/bin/security", "list-keychains", "-d", "user", "-s", *search)
            finally:
                if keychain.exists():
                    run("/usr/bin/security", "delete-keychain", keychain)


def extract(archive, destination):
    def package_filter(member, target):
        filtered = tarfile.data_filter(member, target)
        # data_filter intentionally drops directory modes. Restore only their
        # safe archive bits so extraction does not substitute the process umask
        # before our first snapshot. Keep ownership/path/link protections.
        if member.isdir():
            filtered = filtered.replace(mode=member.mode & 0o755)
        return filtered

    with tarfile.open(archive, "r:gz") as tar:
        seen = set()
        for member in tar.getmembers():
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or not path.parts
                    or path.parts[0] != "Nelomai.app" or path in seen
                    or not (member.isfile() or member.isdir()) or member.mode & 0o7000):
                raise ValueError("unsafe or duplicate macOS package entry")
            seen.add(path)
        tar.extractall(destination, filter=package_filter)
    app = destination / "Nelomai.app"
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    executable = info.get("CFBundleExecutable", "")
    if (info.get("CFBundleIdentifier") != IDENTIFIER or not re.fullmatch(r"[A-Za-z0-9_-]+", executable)
            or not (app / "Contents/MacOS" / executable).is_file()
            or not (app / "Contents/MacOS" / executable).stat().st_mode & 0o111):
        raise ValueError("unexpected common bundle identity/executable")
    return app, "Contents/MacOS/" + executable


def snapshot(app):
    result = {}
    for path in (app, *app.rglob("*")):
        mode = path.lstat().st_mode
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise ValueError("non-regular signed bundle entry")
        result[path.relative_to(app).as_posix()] = (stat.S_IMODE(mode), None if path.is_dir() else digest(path))
    return result


def check_unchanged(before, after, executable):
    # Only common Mach-O signature bytes and the outer resource seal may change.
    # Native packaging has already ad-hoc signed the outer bundle, so its seal
    # and file set must exist before this phase. Preserve all permission bits.
    seal = "Contents/_CodeSignature/CodeResources"
    if before.keys() != after.keys():
        raise ValueError("common signing changed bundle file set")
    for name in before:
        if before[name][0] != after[name][0]:
            raise ValueError("common signing changed bundle permissions: " + name)
        if name in (executable, seal) and before[name][1] is not None and after[name][1] is not None:
            continue
        if before[name] != after[name]:
            raise ValueError("common signing changed protected bundle content: " + name)


def process(args, environment):
    if args.mode not in ("build_only", "sign_candidate"):
        raise ValueError("unsupported signing mode")
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("immutable signing output exists")
    metadata = None
    if args.mode == "sign_candidate":
        metadata = signature_metadata(args.certificate_sha1)
        if not all(environment.get(name) for name in SECRET_NAMES):
            raise ValueError("macOS candidate requires permanent signing credentials")
    elif any(environment.get(name) for name in SECRET_NAMES):
        raise ValueError("build_only must not receive production signing credentials")
    index = json.loads((args.input / "package-digests.json").read_bytes())
    for key, value in dict(source_sha=args.source_sha, release_set_sha256=args.release_set_sha256,
                           mode=args.mode, platform="macos", architecture="aarch64").items():
        if index.get(key) != value:
            raise ValueError("native package identity mismatch")
    item = index["packages"]["shipping"]
    name = item["name"]
    if not re.fullmatch(r"nelomai-[0-9]+\.[0-9]+\.[0-9]+-macos-aarch64\.app\.tar\.gz", name):
        raise ValueError("unexpected shipping archive name")
    archive = args.input / "shipping" / name
    if archive.is_symlink() or item != dict(name=name, sha256=digest(archive), size_bytes=archive.stat().st_size):
        raise ValueError("native package changed before common signing")
    args.work.mkdir(parents=True, exist_ok=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="common-", dir=args.work) as temporary, \
         tempfile.TemporaryDirectory(prefix=".common-output-", dir=args.output.parent) as output_tmp:
        work = Path(temporary)
        result = Path(output_tmp) / "result"
        (result / "shipping").mkdir(parents=True)
        destination = result / "shipping" / name
        app, executable = extract(archive, work / "before")
        if metadata:
            before = snapshot(app)
            sign_bundle(app, args.certificate_sha1, work, environment)
            after = snapshot(app)
            check_unchanged(before, after, executable)
            with tarfile.open(destination, "w:gz") as tar:
                tar.add(app, arcname=app.name)
            unpacked, _ = extract(destination, work / "after")
            if snapshot(unpacked) != after:
                raise ValueError("repacking changed signed bundle")
            verify_signature(unpacked, args.certificate_sha1)
            index["macos_common_signature"] = metadata
        else:
            shutil.copyfile(archive, destination)
        index["packages"]["shipping"] = dict(name=name, sha256=digest(destination), size_bytes=destination.stat().st_size)
        (result / "package-digests.json").write_text(json.dumps(index, sort_keys=True) + "\n")
        result.rename(args.output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("input", "output", "work"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("source-sha", "release-set-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--mode", choices=("build_only", "sign_candidate"), required=True)
    parser.add_argument("--certificate-sha1", default="")
    args = parser.parse_args()
    try:
        process(args, os.environ)
    except Exception:
        # Do not let arbitrary native/library exception strings leak credentials.
        parser.exit(1, "macOS common signing failed; no package published\n")


if __name__ == "__main__":
    main()
