#!/usr/bin/env python3
"""Private Windows test candidate only; no current four-platform root or publication."""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

spec = importlib.util.spec_from_file_location("builder", Path(__file__).with_name("build-release-platform.py"))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
verifier, gates = builder.verifier, builder.gates
container = verifier.load_script("build-runtime-acceptance-container.py")
canonical = container.release_set.canonical
REPOSITORY = "NelomaiTTT/nelomai-app"
REF = "refs/heads/Future/desktop-0.4.0"
VERSION = "0.4.0"
LATEST = "nelomai-runtime-0.4.0-windows-x86_64"
SUFFIXES = (".zip", ".manifest.json", ".manifest.sig")


def snapshot(directory):
    if directory.is_symlink() or not directory.is_dir() or any(p.is_symlink() for p in directory.rglob("*")):
        raise ValueError("regular immutable input tree required")
    return {p.relative_to(directory).as_posix(): verifier.digest(p) for p in directory.rglob("*") if p.is_file()}


def stable_windows(directory, public):
    prefix = f"nelomai-runtime-{gates.STABLE_VERSION}-windows-x86_64"
    root = f"nelomai-runtime-{gates.STABLE_VERSION}-release-set.manifest"
    doc = verifier.authenticated("release-set", directory / (root + ".json"), directory / (root + ".sig"),
                                 public, gates.STABLE_ROOT_SHA256)
    if (doc["runtime_version"], doc["source_commit"]) != (gates.STABLE_VERSION, gates.STABLE_SOURCE):
        raise ValueError("confirmed stable root identity mismatch")
    entries = [a for a in doc["artifacts"] if (a["platform"], a["architecture"]) == ("windows", "x86_64")]
    if len(entries) != 1:
        raise ValueError("confirmed stable Windows membership missing")
    for kind, suffix in zip(("archive", "manifest", "signature"), SUFFIXES):
        if entries[0][kind + "_name"] != prefix + suffix or entries[0][kind + "_sha256"] != verifier.digest(directory / (prefix + suffix)):
            raise ValueError("confirmed stable Windows bytes differ from pinned root")
    manifest = verifier.verify(*(directory / (prefix + s) for s in SUFFIXES), public,
        gates.STABLE_VERSION, gates.STABLE_SOURCE, "windows", "x86_64", inspect_native=False)
    return manifest, [prefix + s for s in SUFFIXES] + [root + ".json", root + ".sig"]


def sign(draft, stable, output, source, private, public, stable_public):
    gates.full_source(source)
    if output.exists() or output.is_symlink():
        raise ValueError("immutable signed output exists")
    before, stable_before = snapshot(draft), snapshot(stable)
    required = {"latest/" + LATEST + s for s in SUFFIXES} | {"draft-public-key.raw", "runtime-public-key.raw"}
    if not required <= before.keys() or before.keys() - required - {"windows-x86_64.sizes.json"}:
        raise ValueError("only one Windows draft and public pins are accepted")
    if private.is_symlink() or any(private.resolve().is_relative_to(p.resolve()) for p in (draft, stable, output)):
        raise ValueError("private signing key must be outside artifacts")
    key = Ed25519PrivateKey.from_private_bytes(private.read_bytes())
    if (key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) != public.read_bytes()
            or (draft / "runtime-public-key.raw").read_bytes() != public.read_bytes()):
        raise ValueError("native compile pin differs from final signing pin")
    gates.verify_runtime_release(stable, gates.STABLE_VERSION, gates.STABLE_SOURCE, gates.STABLE_ROOT_SHA256, stable_public)
    old, old_files = stable_windows(stable, stable_public)
    latest = verifier.verify(*(draft / "latest" / (LATEST + s) for s in SUFFIXES), draft / "draft-public-key.raw",
                              VERSION, source, "windows", "x86_64", inspect_native=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".windows-sign-", dir=output.parent) as temporary:
        staged = Path(temporary) / "signed"
        latest_dir, old_dir, docs = staged / "latest/windows", staged / "confirmed-stable", staged / "containers/windows/shipping"
        for p in (latest_dir, old_dir, docs): p.mkdir(parents=True)
        for suffix in (".zip", ".manifest.json"):
            shutil.copyfile(draft / "latest" / (LATEST + suffix), latest_dir / (LATEST + suffix))
        (latest_dir / (LATEST + ".manifest.sig")).write_bytes(key.sign(b"nelomai-runtime-manifest-v1\0" + (latest_dir / (LATEST + ".manifest.json")).read_bytes()))
        for name in old_files: shutil.copyfile(stable / name, old_dir / name)
        shutil.copyfile(public, staged / "runtime-public-key.raw")
        shutil.copyfile(stable_public, staged / "stable-public-key.raw")
        doc = dict(format_version=1, container_version=VERSION, release_set_id="windows-candidate-" + source,
            minimum_runtime_contract=1, maximum_runtime_contract=1, stable_release_set_sha256=gates.STABLE_ROOT_SHA256,
            stable_platform_manifest_sha256=verifier.digest(old_dir / old_files[1]),
            slots=[dict(slot="latest", manifest=latest), dict(slot="stable", manifest=old)])
        raw = canonical(doc)
        (docs / "container-manifest-v1.json").write_bytes(raw)
        (docs / "container-manifest-v1.sig").write_bytes(key.sign(b"nelomai-container-manifest-v1\0" + raw))
        verifier.authenticated("container", docs / "container-manifest-v1.json", docs / "container-manifest-v1.sig", public, "windows", "x86_64")
        if before != snapshot(draft) or stable_before != snapshot(stable):
            raise ValueError("candidate inputs changed during signing")
        staged.rename(output)


def verified(signed, source, public):
    gates.full_source(source)
    before = snapshot(signed)
    old, old_files = stable_windows(signed / "confirmed-stable", signed / "stable-public-key.raw")
    docs = signed / "containers/windows/shipping"
    expected = {"latest/windows/" + LATEST + s for s in SUFFIXES} | {"confirmed-stable/" + n for n in old_files}
    expected |= {"runtime-public-key.raw", "stable-public-key.raw", "containers/windows/shipping/container-manifest-v1.json", "containers/windows/shipping/container-manifest-v1.sig"}
    if set(before) != expected or (signed / "runtime-public-key.raw").read_bytes() != public.read_bytes():
        raise ValueError("Windows signed inventory or public pin mismatch")
    latest = verifier.verify(*(signed / "latest/windows" / (LATEST + s) for s in SUFFIXES), public,
                              VERSION, source, "windows", "x86_64", inspect_native=False)
    doc = verifier.authenticated("container", docs / "container-manifest-v1.json", docs / "container-manifest-v1.sig", public, "windows", "x86_64")
    if (doc["container_version"] != VERSION or doc["release_set_id"] != "windows-candidate-" + source
            or doc["stable_release_set_sha256"] != gates.STABLE_ROOT_SHA256
            or doc["stable_platform_manifest_sha256"] != verifier.digest(signed / "confirmed-stable" / old_files[1])
            or doc["slots"] != [dict(slot="latest", manifest=latest), dict(slot="stable", manifest=old)]):
        raise ValueError("Windows candidate requires exact current latest and confirmed stable")
    return doc, before


def stage(signed, output, source, public):
    doc, before = verified(signed, source, public)
    if output.exists() or output.is_symlink():
        raise ValueError("immutable Windows staging output exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".windows-stage-", dir=output.parent) as temporary:
        staged = Path(temporary) / "resources"
        for slot in doc["slots"]:
            manifest = slot["manifest"]
            prefix = f"nelomai-runtime-{manifest['runtime_version']}-windows-x86_64"
            folder = signed / ("latest/windows" if slot["slot"] == "latest" else "confirmed-stable")
            payload = staged / "runtime/engines" / slot["slot"] / manifest["runtime_version"]
            verifier.extract(folder / (prefix + ".zip"), manifest, payload)
            verifier.inspect(payload, manifest)
        service = "nelomai-windows-service.exe"
        dispatcher = staged / "dispatcher/1" / service
        dispatcher.parent.mkdir(parents=True)
        shutil.copy2(staged / "runtime/engines/latest" / VERSION / service, dispatcher)
        for suffix in ("json", "sig"):
            shutil.copyfile(signed / "containers/windows/shipping" / ("container-manifest-v1." + suffix), staged / "runtime" / ("container-manifest-v1." + suffix))
        if before != snapshot(signed):
            raise ValueError("signed inputs changed during native staging")
        staged.rename(output)
    return doc


UPDATER_PUBLIC = json.loads((builder.ROOT / "src-tauri/tauri.conf.json").read_bytes())["plugins"]["updater"]["pubkey"]
PRIVATE_ENV = ("NELOMAI_RELEASE_MANIFEST_PRIVATE_KEY_B64", "TAURI_SIGNING_PRIVATE_KEY", "ANDROID_KEYSTORE_PATH", "ANDROID_KEYSTORE_PASSWORD", "ANDROID_KEY_PASSWORD")


def source(sha, *, root=builder.ROOT, environment=None, native=False):
    env = os.environ if environment is None else environment
    gates.full_source(sha)
    if (env.get("GITHUB_REPOSITORY"), env.get("GITHUB_REF"), env.get("GITHUB_SHA")) != (REPOSITORY, REF, sha):
        raise ValueError("Windows candidate repository/ref/full source mismatch")
    if native and any(env.get(n) for n in PRIVATE_ENV):
        raise ValueError("native Windows job must be private-keyless")
    # Preserve the compile-time updater backend in both native build phases.
    if native and env.get("NELOMAI_UPDATER_PUBLIC_KEY") != UPDATER_PUBLIC:
        raise ValueError("native Windows updater public pin missing or mismatch")
    import tomllib
    versions = [json.loads((root / p).read_bytes())["version"] for p in ("package.json", "src-tauri/tauri.conf.json")]
    versions.append(tomllib.loads((root / "src-tauri/Cargo.toml").read_text())["package"]["version"])
    if versions != [VERSION] * 3 or gates.git(root, "status", "--porcelain", "--untracked-files=normal", "--ignore-submodules=none"):
        raise ValueError("Windows candidate requires clean exact 0.4.0 source")
    gates.verify_source(root, sha, VERSION, base=gates.BASE, mode="sign_candidate")


def windows_gate(sha, *, wait=False):
    gates.full_source(sha)
    deadline = time.monotonic() + 2700
    while True:
        response = gates.github_get(f"repos/{REPOSITORY}/actions/workflows/checks.yml/runs?head_sha={sha}&per_page=100")
        if response["total_count"] > 100:
            raise ValueError("ambiguous checks run inventory")
        runs = response["workflow_runs"]
        runs = [r for r in runs if r.get("head_sha") == sha and r.get("path") == ".github/workflows/checks.yml"
            and r.get("event") == "push" and r.get("head_branch") == REF.removeprefix("refs/heads/")
            and r.get("repository", {}).get("full_name") == REPOSITORY and r.get("head_repository", {}).get("full_name") == REPOSITORY]
        if runs:
            run = max(runs, key=lambda r: int(r["id"]))
            attempt = int(run["run_attempt"])
            response = gates.github_get(f"repos/{REPOSITORY}/actions/runs/{run['id']}/attempts/{attempt}/jobs?per_page=100")
            jobs = response["jobs"]
            if response["total_count"] > 100 or attempt < 1:
                raise ValueError("ambiguous Windows check inventory")
            selected = [[j for j in jobs if j["name"] == n] for n in ("windows-build", "windows-worker-native", "windows")]
            if any(len(j) > 1 for j in selected) or any(j and j[0].get("conclusion") not in (None, "success") for j in selected):
                raise ValueError("exact Windows build/native gate failed")
            if all(len(j) == 1 and j[0].get("status") == "completed" and j[0].get("conclusion") == "success" for j in selected):
                fresh = gates.github_get(f"repos/{REPOSITORY}/actions/runs/{run['id']}")
                if fresh.get("id") != run["id"] or fresh.get("head_sha") != sha or fresh.get("run_attempt") != attempt:
                    raise ValueError("Windows check attempt changed during verification")
                return dict(run_id=run["id"], run_attempt=attempt, source_sha=sha, checks=[j[0]["name"] for j in selected])
        remaining = deadline - time.monotonic()
        if not wait or remaining <= 0:
            raise ValueError("exact source Windows checks not ready")
        print("Waiting for exact-source Windows build/native checks only", flush=True)
        time.sleep(min(600, remaining))


def package(signed, output, sha, public):
    if any(os.environ.get(n) for n in PRIVATE_ENV):
        raise ValueError("native Windows packaging must be private-keyless")
    if output.exists() or output.is_symlink():
        raise ValueError("immutable Windows package output exists")
    staged = output / "staged"
    stage(signed, staged, sha, public)
    environment = {**os.environ, "NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64": base64.b64encode(public.read_bytes()).decode()}
    installer = container.package_desktop(staged, output / "work", public, "windows", "x86_64", environment=environment)
    name = gates.PACKAGE_NAMES["windows"]
    destination = output / "shipping" / name
    destination.parent.mkdir()
    shutil.copyfile(installer, destination)
    index = dict(source_sha=sha, purpose="windows-candidate", name=name, sha256=verifier.digest(destination), size_bytes=destination.stat().st_size,
        container_sha256=verifier.digest(signed / "containers/windows/shipping/container-manifest-v1.json"))
    (output / "package-digests.json").write_bytes(canonical(index))


def finalize(packages, signed, output, sha, public):
    _, before = verified(signed, sha, public)
    index = json.loads((packages / "package-digests.json").read_bytes())
    name = gates.PACKAGE_NAMES["windows"]
    installer = packages / "shipping" / name
    expected = dict(source_sha=sha, purpose="windows-candidate", name=name, sha256=verifier.digest(installer), size_bytes=installer.stat().st_size,
        container_sha256=verifier.digest(signed / "containers/windows/shipping/container-manifest-v1.json"))
    if index != expected or os.environ.get("NELOMAI_UPDATER_PUBLIC_KEY") != UPDATER_PUBLIC:
        raise ValueError("Windows package changed or updater pin mismatch")
    if output.exists() or output.is_symlink():
        raise ValueError("immutable finalized output exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".windows-final-", dir=output.parent) as temporary:
        work = Path(temporary)
        candidate = work / "candidate"; candidate.mkdir()
        destination = candidate / name
        shutil.copyfile(installer, destination)
        environment = builder.updater_environment("sign_candidate", work, os.environ)
        builder.run(builder.ROOT / "node_modules/.bin/tauri", "signer", "sign", destination, env=environment, capture=True)
        updater = work / "updater-public.b64"; updater.write_text(UPDATER_PUBLIC)
        executable = os.environ.get("NELOMAI_UPDATER_SIGNATURE_VERIFIER", str(builder.ROOT / "target/debug/examples/verify-updater-signature"))
        builder.run(executable, destination, candidate / (name + ".sig"), updater, capture=True)
        if verifier.digest(destination) != index["sha256"] or verifier.digest(installer) != index["sha256"] or snapshot(signed) != before:
            raise ValueError("Windows payload changed during finalization")
        shutil.copytree(signed, candidate / "runtime")
        inventory = dict(purpose="windows-candidate", publishable=False, source_sha=sha, version=VERSION,
            stable_release_set_sha256=gates.STABLE_ROOT_SHA256, run_id=os.environ.get("GITHUB_RUN_ID"),
            assets=snapshot(candidate))
        (candidate / "candidate-inventory.json").write_bytes(canonical(inventory))
        candidate.rename(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("source", "gate", "sign", "package", "finalize"))
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--keyless", action="store_true")
    for name in ("draft", "stable", "signed", "packages", "output", "private-key", "public-key", "stable-public-key"):
        parser.add_argument("--" + name, type=Path)
    args = parser.parse_args()
    source(args.source_sha, native=args.keyless or args.phase == "package")
    if args.phase == "source": return
    if args.phase == "gate":
        print(json.dumps(windows_gate(args.source_sha, wait=True))); return
    if args.phase == "sign":
        sign(args.draft, args.stable, args.output, args.source_sha, args.private_key, args.public_key, args.stable_public_key)
    elif args.phase == "package": package(args.signed, args.output, args.source_sha, args.public_key)
    else: finalize(args.packages, args.signed, args.output, args.source_sha, args.public_key)


if __name__ == "__main__":
    main()
