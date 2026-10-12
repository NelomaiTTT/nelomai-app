#!/usr/bin/env python3
"""Stage pinned sources without modifying submodules; build the Windows worker."""
import argparse
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile


def run(*args, cwd=None, env=None):
    return subprocess.run(args, cwd=cwd, env=env, check=True, capture_output=True)


def stage(root, vendor_root, output):
    if output.exists():
        raise ValueError("output must be a new directory")
    output.mkdir(parents=True)
    source = output / "source"
    source.mkdir()
    for name, patches in (
        ("amneziawg-go", ["amneziawg-go-network-recovery.patch", "amneziawg-go-android-memory.patch"]),
        ("amneziawg-android", ["amneziawg-android-network-telemetry.patch", "amneziawg-android-memory-diagnostics.patch"]),
    ):
        expected = run("git", "-C", str(root), "rev-parse", "HEAD:vendor/" + name).stdout.decode().strip()
        vendor = vendor_root / name
        actual = run("git", "-C", str(vendor), "rev-parse", "HEAD").stdout.decode().strip()
        if actual != expected:
            raise ValueError(name + " does not match this repository's pinned gitlink")
        destination = source / name
        destination.mkdir()
        archive = run("git", "-C", str(vendor), "archive", expected).stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as stream:
            stream.extractall(destination, filter="data")
        for patch in patches:
            run("git", "apply", str(root / "patches" / patch), cwd=destination)
    run("git", "apply", str(root / "workers/windows-go/windows-bind.patch"), cwd=source / "amneziawg-go")
    worker = source / "worker"
    worker.mkdir()
    directory = root / "workers/windows-go"
    for path in directory.iterdir():
        if path.suffix == ".go" or path.name in ("go.mod", "go.sum"):
            shutil.copy2(path, worker / path.name)
    bridge = source / "amneziawg-android/tunnel/tools/libwg-go"
    for name in ("redundant_tun.go", "redundant_real_writer.go"):
        shutil.copy2(bridge / name, worker / name)
    run("git", "apply", str(directory / "windows-dispatcher.patch"), cwd=worker)
    with (worker / "go.mod").open("a") as module:
        module.write("\nreplace github.com/amnezia-vpn/amneziawg-go/v3 => ../amneziawg-go\n")
    return worker


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--vendor-root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--go", default="go")
    parser.add_argument("--test", action="store_true", help="also compile the one Windows integration test")
    parser.add_argument("--host-test", action="store_true", help="run the same scenario with only native OS effects replaced")
    args = parser.parse_args()
    root = args.root.resolve()
    output = args.output.resolve()
    worker = stage(root, (args.vendor_root or root / "vendor").resolve(), output)
    environment = dict(os.environ, CGO_ENABLED="0", GOTOOLCHAIN="local", GOWORK="off", GOPROXY="off", GOSUMDB="off")
    if args.host_test:
        result = run(args.go, "test", "-mod=readonly", "-race", "-v", ".", cwd=worker,
                     env=dict(environment, CGO_ENABLED="1"))
        print(result.stdout.decode(), end="")
    environment.update(GOOS="windows", GOARCH="amd64")
    run(args.go, "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o",
        str(output / "nelomai-windows-worker.exe"), ".", cwd=worker, env=environment)
    if args.test:
        run(args.go, "test", "-mod=readonly", "-trimpath", "-c", "-o",
            str(output / "windows-worker.test.exe"), ".", cwd=worker, env=environment)
    print(output)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(error.stdout.decode(), end="")
        print(error.stderr.decode(), end="")
        raise SystemExit(error.returncode)
