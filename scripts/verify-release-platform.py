#!/usr/bin/env python3
"""Native exact-byte recheck AFTER final installer/APK signatures, without signing."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

spec = importlib.util.spec_from_file_location("builder", Path(__file__).with_name("build-release-platform.py"))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
verifier, gates = builder.verifier, builder.gates
container = verifier.load_script("build-runtime-acceptance-container.py")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("candidate", "acceptance", "signed", "public-key", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("platform", "architecture", "source-sha", "release-set-sha256", "inventory-sha256", "acceptance-inventory-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--ndk", type=Path)
    parser.add_argument("--linux-execution", action="store_true",
                        help="Run separate ordinary startup/supplemental adapter in a disposable network-none container")
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("immutable native evidence output exists")
    indexes = {"shipping": gates.verify_inventory(args.candidate, args.candidate / "candidate-inventory.json", args.inventory_sha256),
        "acceptance": gates.verify_inventory(args.acceptance, args.acceptance / "acceptance-inventory.json", args.acceptance_inventory_sha256)}
    for document in indexes.values():
        if document["source_sha"] != args.source_sha or document["release_set_sha256"] != args.release_set_sha256:
            raise ValueError("final native inventory identity mismatch")
    readelf = None
    if args.platform == "android":
        if args.ndk is None:
            raise ValueError("Android native recheck requires explicit NDK")
        readelf = verifier.load_script("android/build-tunnel-runtime.py").ndk_compiler(args.ndk).with_name("llvm-readelf")
    results = {}
    with tempfile.TemporaryDirectory(prefix="final-native-check-") as temporary:
        work = Path(temporary)
        for kind, folder in (("shipping", args.candidate), ("acceptance", args.acceptance)):
            name = gates.PACKAGE_NAMES[args.platform]
            if kind == "acceptance":
                name = name.replace("nelomai-", "nelomai-acceptance-", 1)
            package = folder / name
            staged = work / (kind + "-staged")
            manifest = container.stage_signed(args.signed, args.release_set_sha256, staged, args.public_key,
                args.platform, args.architecture, args.source_sha, kind, readelf)
            if args.platform == "android":
                sdk = args.ndk.parent.parent
                arguments = (["--acceptance", "--release-set-sha256", args.release_set_sha256,
                              "--stable-manifest-sha256", manifest["stable_platform_manifest_sha256"]] if kind == "acceptance" else [])
                builder.script("android/check-container-apk.py", "--apk", package, "--public-key", args.public_key,
                    "--apkanalyzer", sdk / "cmdline-tools/latest/bin/apkanalyzer", *arguments)
                builder.run(sdk / "build-tools/36.0.0/apksigner", "verify", "--verbose", package)
                with zipfile.ZipFile(package) as archive:
                    for path in (staged / "runtime").rglob("*"):
                        if path.is_file() and archive.read("assets/runtime/" + path.relative_to(staged / "runtime").as_posix()) != path.read_bytes():
                            raise ValueError("final APK differs from signed native staged payload")
                    for entry in archive.namelist():
                        if entry.startswith("lib/arm64-v8a/") and entry.endswith(".so"):
                            library = work / Path(entry).name
                            library.write_bytes(archive.read(entry))
                            sections = builder.run(readelf, "-S", "--wide", library, capture=True).stdout
                            if ".debug_" in sections or ".symtab" in sections:
                                raise ValueError("Android final library retains debug/static symbols")
                    symbols = builder.run(readelf, "--dyn-syms", "--wide", work / "libwg-go.so", capture=True).stdout
                    for method in ("awgGetNetworkTelemetry", "awgCloseUdp", "awgRebindUdp", "awgSendKeepalives",
                                   "awgStartHandshakeProbe", "awgHandshakeProbeStatus", "awgHandshakeProbeTimeoutMillis"):
                        if "Java_org_amnezia_awg_GoBackend_" + method not in symbols:
                            raise ValueError("final Android tunnel omits required compiled JNI method")
            else:
                extracted = work / (kind + "-extracted")
                extracted.mkdir()
                if args.platform == "macos":
                    with tarfile.open(package) as archive:
                        archive.extractall(extracted, filter="data")
                    apps = list(extracted.glob("*.app"))
                    if len(apps) != 1:
                        raise ValueError("final macOS app layout mismatch")
                    builder.run("/usr/bin/codesign", "--verify", "--strict", apps[0])
                elif args.platform == "windows":
                    builder.run("7z", "x", "-y", "-o" + str(extracted), package, stdout=subprocess.DEVNULL)
                else:
                    executable = work / (kind + ".AppImage")
                    shutil.copyfile(package, executable)
                    executable.chmod(0o755)
                    builder.run(executable, "--appimage-extract", cwd=extracted, stdout=subprocess.DEVNULL)
                container.verify_packaged_tree(extracted, staged, args.public_key, args.platform, args.architecture)
            results[kind] = verifier.digest(package)
        if args.linux_execution:
            if args.platform != "linux":
                raise ValueError("Linux execution adapter cannot accept a foreign target")
            packages = work / "linux-packages"
            for kind, source in (("shipping", args.candidate), ("acceptance", args.acceptance)):
                shutil.copytree(work / (kind + "-staged"), packages / "staged" / kind)
                name = gates.PACKAGE_NAMES["linux"]
                if kind == "acceptance":
                    name = name.replace("nelomai-", "nelomai-acceptance-", 1)
                (packages / kind).mkdir()
                shutil.copyfile(source / name, packages / kind / name)
            builder.script("linux/run-package-acceptance.py", "--packages", packages, "--public-key", args.public_key,
                           "--output", args.output.with_name("linux-supplemental.json"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dict(platform=args.platform, architecture=args.architecture, source_sha=args.source_sha,
        release_set_sha256=args.release_set_sha256, packages=results, native_reextraction="verified",
        hardware_execution="UNRUN", full_candidate_acceptance="UNRUN"), sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
