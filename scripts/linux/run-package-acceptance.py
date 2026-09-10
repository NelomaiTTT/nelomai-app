#!/usr/bin/env python3
"""Disposable Linux-only real package startup plus separately scoped stable harness.

Never run the installed-layout operation on the host. It is confined to this
script's disposable network-none Docker container and fresh user data. No
physical tunnel or production-panel HTTP acceptance is claimed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
ISOLATED = Path("/opt/nelomai-acceptance")
APP = Path("/usr/local/libexec/nelomai/common/AppDir")


def run(*command, **kwargs):
    try:
        return subprocess.run(list(map(str, command)), check=True, **kwargs)
    except subprocess.CalledProcessError as error:
        # Captured disposable-container output must not hide the actual failure.
        for output in (error.stdout, error.stderr):
            if output:
                print(output.decode("utf-8", errors="replace") if isinstance(output, bytes) else output,
                      file=sys.stderr)
        raise


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def isolated(root_required=True):
    if (sys.platform != "linux" or not Path("/.dockerenv").is_file()
            or Path(__file__).resolve() != ISOLATED / "scripts/linux/run-package-acceptance.py"
            or {path.name for path in Path("/sys/class/net").iterdir()} != {"lo"}
            or (os.geteuid() == 0) != root_required):
        raise SystemExit("requires an isolated disposable Linux container with external networking disabled")


def process_with_executable(expected, *, parent=None, engine=False):
    for process in Path("/proc").iterdir():
        if not process.name.isdecimal():
            continue
        try:
            executable = (process / "exe").resolve(strict=True)
            status = dict(line.split(":", 1) for line in (process / "status").read_text().splitlines() if ":" in line)
            command = (process / "cmdline").read_bytes().split(b"\0")
        except (OSError, ValueError):
            continue
        if ((expected is None or executable == expected) and (parent is None or int(status["PPid"]) == parent)
                and (not engine or b"--engine-mode" in command)):
            return int(process.name), executable
    return None


def session(kind):
    isolated(root_required=False)
    run("gsettings", "set", "org.gnome.desktop.interface", "toolkit-accessibility", "true")
    if kind == "supplemental":
        return run(ISOLATED / "linux-runtime-acceptance", ISOLATED / "acceptance-resources",
                   ISOLATED / "inputs/public-key.raw", "http://127.0.0.1:56590")
    common = APP / "usr/bin/nelomai-app"
    expected = APP / "usr/lib/Nelomai/runtime/engines/latest/0.2.17/nelomai-runtime"
    with subprocess.Popen([str(common)]) as child:
        try:
            deadline = time.monotonic() + 30
            runtime = None
            while time.monotonic() < deadline and child.poll() is None:
                runtime = process_with_executable(expected, parent=child.pid)
                if runtime:
                    break
                time.sleep(0.2)
            if runtime is None:
                raise RuntimeError("ordinary installed common did not launch the exact latest runtime")
            run("python3", ISOLATED / "check-runtime-webview.py", "--pid", runtime[0])
            deadline = time.monotonic() + 15
            engine = None
            while time.monotonic() < deadline:
                engine = process_with_executable(None, engine=True)
                if engine:
                    break
                time.sleep(0.2)
            if engine is None or not str(engine[1]).startswith("/usr/local/libexec/nelomai/"):
                raise RuntimeError("ordinary dispatcher did not execute its real installed engine")
            source_engine = APP / "usr/lib/Nelomai/runtime/engines/latest/0.2.17/nelomai-unix-service"
            if digest(engine[1]) != digest(source_engine):
                raise RuntimeError("ordinary installed engine bytes differ from final package")
            print(json.dumps(dict(scope="ordinary-installed-latest-startup", common_sha256=digest(common),
                runtime_sha256=digest(expected), engine_sha256=digest(engine[1]), webview="observed",
                physical_tunnel="UNRUN", production_http="UNRUN")), flush=True)
        finally:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


def inside():
    isolated()
    import pwd
    acceptance_uid = pwd.getpwnam("acceptance").pw_uid
    spec = importlib.util.spec_from_file_location("container", ROOT / "scripts/build-runtime-acceptance-container.py")
    container = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(container)
    # Actual AppImage bytes are executed for extraction only inside isolation.
    for kind in ("shipping", "acceptance"):
        extracted = ISOLATED / (kind + "-extracted")
        extracted.mkdir()
        package = ISOLATED / "inputs" / (kind + ".AppImage")
        run(package, "--appimage-extract", cwd=extracted, stdout=subprocess.DEVNULL)
        runtime = container.verify_packaged_tree(extracted, ISOLATED / "inputs/staged" / kind,
            ISOLATED / "inputs/public-key.raw", "linux", "x86_64")
        if kind == "shipping":
            shutil.copytree(extracted / "squashfs-root", APP)
        else:
            shutil.copytree(runtime.parent, ISOLATED / "acceptance-resources")
    common = APP / "usr/bin/nelomai-app"
    resources = APP / "usr/lib/Nelomai"
    helper = resources / "dispatcher/1/nelomai-unix-service"
    # The real production installation API, but in a disposable root-owned
    # namespace only. No sudo/pkexec/host installer is invoked.
    installed = run(helper, "install-layout", resources / "runtime", common, acceptance_uid,
                    capture_output=True, text=True).stdout.strip()
    dispatcher = subprocess.Popen([installed, "--dispatcher"])
    xvfb = subprocess.Popen(["Xvfb", ":99", "-screen", "0", "1280x800x24", "-nolisten", "tcp"])
    environment = {**os.environ, "DISPLAY": ":99", "NO_AT_BRIDGE": "0", "GTK_MODULES": "gail:atk-bridge"}
    try:
        for kind in ("ordinary", "supplemental"):
            run("runuser", "-u", "acceptance", "--", "dbus-run-session", "--", "python3", Path(__file__),
                "--session", kind, env=environment)
    finally:
        dispatcher.terminate()
        xvfb.terminate()
        dispatcher.wait(timeout=10)
        xvfb.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--session", choices=("ordinary", "supplemental"))
    parser.add_argument("--packages", type=Path)
    parser.add_argument("--public-key", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.inside:
        inside()
        return
    if args.session:
        session(args.session)
        return
    if sys.platform != "linux" or not all((args.packages, args.public_key, args.output)):
        raise SystemExit("UNRUN: native Linux host, packages, explicit public key and evidence output required")
    if args.output.exists():
        raise SystemExit("immutable Linux evidence output exists")
    with tempfile.TemporaryDirectory(prefix="nelomai-linux-acceptance-") as temporary:
        context = Path(temporary)
        shutil.copytree(ROOT / "scripts", context / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
        for source, name in ((ROOT / "target/debug/verify-runtime-manifest", "verify-runtime-manifest"),
                             (ROOT / "target/debug/examples/linux-runtime-acceptance", "linux-runtime-acceptance")):
            shutil.copy2(source, context / name)
        shutil.copytree(args.packages / "staged", context / "inputs/staged")
        shutil.copyfile(args.public_key, context / "inputs/public-key.raw")
        package_digests = {}
        for kind in ("shipping", "acceptance"):
            packages = list((args.packages / kind).glob("*.AppImage"))
            if len(packages) != 1:
                raise ValueError("exactly one separate package per purpose required")
            package_digests[kind] = digest(packages[0])
            shutil.copy2(packages[0], context / "inputs" / (kind + ".AppImage"))
            (context / "inputs" / (kind + ".AppImage")).chmod(0o755)
        image_id = context / "image-id"
        run("docker", "build", "--iidfile", image_id, "-f", context / "scripts/linux/acceptance.Dockerfile", context)
        completed = run("docker", "run", "--rm", "--network", "none", "--cap-drop", "NET_RAW",
            "--cap-add", "SYS_PTRACE",
            "--security-opt", "no-new-privileges", image_id.read_text().strip(), capture_output=True, text=True)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(dict(scope="linux-supplemental-only", packages=package_digests,
            output=completed.stdout, production_http="UNRUN", physical_tunnel="UNRUN",
            stable_production_dispatcher_and_engine="NOT_IMPLEMENTED", full_candidate_acceptance="UNRUN"), sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
