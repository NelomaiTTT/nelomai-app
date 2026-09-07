#!/usr/bin/env python3
"""Build a separate synthetic two-slot package; never modify stable candidates.

Staging is not acceptance. Native package extraction and execution are separate
mandatory gates. The synthetic latest identity is restricted to this builder;
shipping 0.2.16 continues to use the existing latest-only container stage.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_set", ROOT / "scripts/build-runtime-release-set.py")
release_set = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release_set)
verifier = release_set.verifier
SYNTHETIC_LATEST = "0.2.17"


def stage_signed(signed, root_digest, output, public_key, platform, architecture, source, kind, readelf=None):
    """Keyless native consumer of first-phase final signatures and unchanged ZIPs."""
    if kind not in ("shipping", "acceptance"):
        raise ValueError("unknown container purpose")
    if output.exists() or output.is_symlink():
        raise ValueError("immutable signed staging output exists")
    verifier.load_script("release-candidate-gates.py").verify_runtime_release(
        signed / "release", "0.2.16", source, root_digest, public_key)
    documents = signed / "containers" / platform / kind
    manifest_path, signature = documents / "container-manifest-v1.json", documents / "container-manifest-v1.sig"
    container = verifier.authenticated("container", manifest_path, signature, public_key, platform, architecture)
    slots = [slot["slot"] for slot in container["slots"]]
    if slots != (["latest", "stable"] if kind == "acceptance" else ["latest"]):
        raise ValueError("container purpose differs from signed slots")
    prefix = f"nelomai-runtime-0.2.16-{platform}-{architecture}"
    if kind == "acceptance" and (container.get("stable_release_set_sha256") != root_digest
            or container.get("stable_platform_manifest_sha256") != verifier.digest(signed / "release" / (prefix + ".manifest.json"))):
        raise ValueError("acceptance container differs from final stable root")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".keyless-stage-", dir=output.parent) as temporary:
        staged = Path(temporary) / "resources"
        archives = {}
        for slot in container["slots"]:
            latest = slot["slot"] == "latest"
            folder = signed / "latest" / platform if latest else signed / "release"
            archive = folder / (prefix + ".zip")
            original = verifier.verify(archive, folder / (prefix + ".manifest.json"),
                folder / (prefix + ".manifest.sig"), public_key, "0.2.16", source, platform, architecture,
                inspect_native=False)
            expected = {**original, "runtime_version": SYNTHETIC_LATEST} if latest and kind == "acceptance" else original
            if slot["manifest"] != expected:
                raise ValueError("container embedded manifest differs from final native artifact")
            payload = staged / "runtime/engines" / slot["slot"] / expected["runtime_version"]
            verifier.extract(archive, expected, payload)
            if platform == "android" and latest:
                # Existing collision inspector understands compiled latest Java
                # and SO inputs; the stable-only completeness rule is not reused
                # for a differently named latest ABI.
                check = verifier.load_script("android/check-runtime-collisions.py")
                inventory = check.inspect_archive(archive.read_bytes(), readelf=readelf)
                if not inventory["classes"] or any(name.startswith("ru.nelomai.runtime.stable.") for name in inventory["classes"]):
                    raise ValueError("invalid compiled Android latest classes")
            else:
                verifier.inspect(payload, expected, readelf)
            archives[slot["slot"]] = archive
        if platform == "android" and kind == "acceptance":
            check = verifier.load_script("android/check-runtime-collisions.py")
            conflicts = check.collisions(*(check.inspect_archive(archives[slot].read_bytes(), readelf=readelf)
                                          for slot in ("latest", "stable")))
            if conflicts:
                raise ValueError("Android runtime collisions: " + json.dumps(conflicts, sort_keys=True))
        if platform != "android":
            service = "nelomai-windows-service.exe" if platform == "windows" else "nelomai-unix-service"
            dispatcher = staged / "dispatcher/1" / service
            dispatcher.parent.mkdir(parents=True)
            shutil.copy2(staged / "runtime/engines/latest" / container["slots"][0]["manifest"]["runtime_version"] / service, dispatcher)
        for path in (manifest_path, signature):
            shutil.copyfile(path, staged / "runtime" / path.name)
        staged.rename(output)
    return container


def stage_android_latest(payload, output, source, readelf):
    """Consume the existing compiler-stage index/ZIP, never another APK or DEX receipt."""
    manifest = json.loads((payload.parent / "runtime-manifest-v1.json").read_bytes())
    if ({name: manifest.get(name) for name in ("format_version", "runtime_version", "source_commit",
            "platform", "architecture", "contract_version")} != dict(format_version=1, runtime_version="0.2.16",
            source_commit=source, platform="android", architecture="aarch64", contract_version=1)):
        raise ValueError("Android latest compiler-stage identity mismatch")
    packager = verifier.load_script("android/build-runtime-artifact.py")
    required = {"runtime/latest-classes.zip", "jni/arm64-v8a/libnelomai_app_lib.so", "jni/arm64-v8a/libwg-go.so",
                "webview/index.html"} | {"licenses/" + name for name in packager.REQUIRED_LICENSES}
    if not required <= {item["path"] for item in manifest["files"]}:
        raise ValueError("incomplete Android latest compiler-stage payload")
    archive = payload.parent / "collision-input.zip"
    check = packager.collision_module()
    inventory = check.inspect_archive(archive.read_bytes(), readelf=readelf)
    if not inventory["classes"] or any(name.startswith("ru.nelomai.runtime.stable.") for name in inventory["classes"]):
        raise ValueError("Android latest archive contains no classes or contains stable classes")
    if output.exists() or output.is_symlink():
        raise ValueError("immutable Android latest extraction output exists")
    verifier.extract(archive, manifest, output)
    return {**manifest, "runtime_version": SYNTHETIC_LATEST}


def stage(candidate, root_digest, latest_payload, output, signing_key, public_key,
          platform, architecture, source, readelf=None):
    if output.exists() or output.is_symlink():
        raise ValueError("immutable acceptance staging output already exists")
    gates = verifier.load_script("release-candidate-gates.py")
    gates.verify_runtime_release(candidate, "0.2.16", source, root_digest, public_key)
    if signing_key.is_symlink() or signing_key.stat().st_size != 32:
        raise ValueError("explicit regular raw Ed25519 key required")
    key = Ed25519PrivateKey.from_private_bytes(signing_key.read_bytes())
    if key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) != public_key.read_bytes():
        raise ValueError("acceptance signer differs from candidate trust root")
    prefix = f"nelomai-runtime-0.2.16-{platform}-{architecture}"
    stable_inputs = [candidate / (prefix + suffix) for suffix in (".zip", ".manifest.json", ".manifest.sig")]
    before = [verifier.digest(path) for path in stable_inputs]
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".acceptance-stage-", dir=output.parent) as temporary:
        work = Path(temporary)
        staged = work / "resources"
        runtime = staged / "runtime"
        stable = verifier.verify(*stable_inputs, public_key, "0.2.16", source, platform, architecture,
                                 readelf=readelf, output=runtime / "engines/stable/0.2.16")
        if platform == "android":
            latest = stage_android_latest(latest_payload, runtime / "engines/latest" / SYNTHETIC_LATEST, source, readelf)
            check = verifier.load_script("android/check-runtime-collisions.py")
            conflicts = check.collisions(check.inspect_archive(stable_inputs[0].read_bytes(), readelf=readelf),
                check.inspect_archive((latest_payload.parent / "collision-input.zip").read_bytes(), readelf=readelf))
            if conflicts:
                raise ValueError("Android runtime collisions: " + json.dumps(conflicts, sort_keys=True))
        else:
            latest_artifact = work / "latest-artifact"
            packager = verifier.load_script("build-runtime-manifest.py")
            packager.package(latest_payload, latest_artifact, SYNTHETIC_LATEST, source,
                             platform, architecture, signing_key, readelf)
            latest_prefix = f"nelomai-runtime-{SYNTHETIC_LATEST}-{platform}-{architecture}"
            latest = verifier.verify(*(latest_artifact / (latest_prefix + suffix) for suffix in
                (".zip", ".manifest.json", ".manifest.sig")), public_key, SYNTHETIC_LATEST, source,
                platform, architecture, readelf=readelf, output=runtime / "engines/latest" / SYNTHETIC_LATEST)
            service = "nelomai-windows-service.exe" if platform == "windows" else "nelomai-unix-service"
            dispatcher = staged / "dispatcher/1" / service
            dispatcher.parent.mkdir(parents=True)
            shutil.copy2(runtime / "engines/latest" / SYNTHETIC_LATEST / service, dispatcher)
        container = dict(format_version=1, container_version="0.2.16",
            release_set_id="acceptance-" + source, minimum_runtime_contract=1, maximum_runtime_contract=1,
            stable_release_set_sha256=root_digest, stable_platform_manifest_sha256=before[1],
            slots=[dict(slot="latest", manifest=latest), dict(slot="stable", manifest=stable)])
        body = release_set.canonical(container)
        manifest, signature = runtime / "container-manifest-v1.json", runtime / "container-manifest-v1.sig"
        manifest.write_bytes(body)
        signature.write_bytes(key.sign(b"nelomai-container-manifest-v1\0" + body))
        verifier.authenticated("container", manifest, signature, public_key, platform, architecture)
        if before != [verifier.digest(path) for path in stable_inputs]:
            raise ValueError("stable candidate changed while packaging")
        staged.rename(output)
    return container


def verify_packaged_tree(extracted, staged, public_key, platform, architecture):
    manifests = list(extracted.rglob("container-manifest-v1.json"))
    if len(manifests) != 1:
        raise ValueError("packaged container manifest is missing or ambiguous")
    runtime = manifests[0].parent
    expected = staged / "runtime"
    actual_files = {path.relative_to(runtime).as_posix() for path in runtime.rglob("*") if not path.is_dir()}
    expected_files = {path.relative_to(expected).as_posix() for path in expected.rglob("*") if not path.is_dir()}
    if actual_files != expected_files or any(path.is_symlink() for path in runtime.rglob("*")):
        raise ValueError("packaged runtime file set differs from staged signed inputs")
    for name in expected_files:
        if (verifier.digest(runtime / name) != verifier.digest(expected / name)
                or (platform != "windows" and (runtime / name).stat().st_mode & 0o777
                    != (expected / name).stat().st_mode & 0o777)):
            raise ValueError("packaged runtime bytes or executable modes changed")
    manifest = verifier.authenticated("container", runtime / "container-manifest-v1.json",
        runtime / "container-manifest-v1.sig", public_key, platform, architecture)
    for slot in manifest["slots"]:
        verifier.inspect(runtime / "engines" / slot["slot"] / slot["manifest"]["runtime_version"], slot["manifest"])
    service = "nelomai-windows-service.exe" if platform == "windows" else "nelomai-unix-service"
    installed_dispatcher = runtime.parent / (service if platform == "windows" else "dispatcher/1/" + service)
    if verifier.digest(installed_dispatcher) != verifier.digest(staged / "dispatcher/1" / service):
        raise ValueError("packaged dispatcher identity changed")
    return runtime


def package_desktop(staged, output, public_key, platform, architecture, *, root=ROOT, environment=None):
    """Invoke the actual Tauri native bundler, then inspect its extracted bytes.

    --no-sign prevents the bundler from recursively re-signing stable resources.
    Only the outer macOS app/common executable gets a new ad-hoc signature;
    the final slot payloads must still compare byte-for-byte afterward.
    """
    if output.exists() or output.is_symlink():
        raise ValueError("immutable acceptance package output already exists")
    targets = {"linux": ("x86_64-unknown-linux-gnu", "appimage"),
               "windows": ("x86_64-pc-windows-msvc", "nsis"), "macos": ("aarch64-apple-darwin", "app")}
    target, bundle = targets[platform]
    configuration = json.loads((root / "src-tauri" / f"bundle.{platform}.conf.json").read_bytes())
    resources = configuration["bundle"]["resources"]
    configuration["bundle"]["resources"] = {
        str(staged / source.removeprefix("platform-runtime/desktop-bundle/"))
            if source.startswith("platform-runtime/desktop-bundle/") else source: destination
        for source, destination in resources.items()}
    # Acceptance installers are separate from the normal updater payload and
    # never create another updater signature for an already approved installer.
    configuration["bundle"]["createUpdaterArtifacts"] = False
    output.mkdir(parents=True)
    config_path = output / "bundle-config.json"
    config_path.write_bytes(release_set.canonical(configuration))
    environment = (environment or os.environ).copy()
    # Build-only/test trust and release trust must use separate output/cache roots.
    environment["CARGO_TARGET_DIR"] = str(output / "target")
    cli = root / "node_modules/.bin" / ("tauri.cmd" if os.name == "nt" else "tauri")
    subprocess.run([str(cli), "build", "--ci", "--no-sign", "--target", target,
        "--features", "custom-protocol", "--bundles", bundle, "--config", str(config_path), "--", "--locked"],
        cwd=root, env=environment, check=True)
    bundle_dir = output / "target" / target / "release/bundle"
    suffix = {"linux": "*.AppImage", "windows": "*.exe", "macos": "*.app"}[platform]
    matches = list((bundle_dir / ("macos" if platform == "macos" else bundle)).glob(suffix))
    if len(matches) != 1:
        raise ValueError("native packager did not emit one acceptance installer")
    name = f"nelomai-acceptance-0.2.16-{platform}-{architecture}"
    extracted = output / "extracted"
    extracted.mkdir()
    if platform == "macos":
        subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", str(matches[0])], check=True)
        package = output / (name + ".app.tar.gz")
        with tarfile.open(package, "w:gz") as archive:
            archive.add(matches[0], arcname=matches[0].name)
        with tarfile.open(package) as archive:
            archive.extractall(extracted, filter="data")
        subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(extracted / matches[0].name)], check=True)
    elif platform == "linux":
        package = output / (name + ".AppImage")
        shutil.copy2(matches[0], package)
        subprocess.run([str(package), "--appimage-extract"], cwd=extracted, check=True, stdout=subprocess.DEVNULL)
    else:
        package = output / (name + ".exe")
        shutil.copy2(matches[0], package)
        subprocess.run(["7z", "x", "-y", "-o" + str(extracted), str(package)], check=True, stdout=subprocess.DEVNULL)
    verify_packaged_tree(extracted, staged, public_key, platform, architecture)
    return package


def package_android(staged, output, public_key, readelf, apkanalyzer, common_host, *, root=ROOT,
                    acceptance=True, variant="Debug", environment=None, offline=True):
    if output.exists() or output.is_symlink():
        raise ValueError("immutable acceptance APK output already exists")
    if readelf is None or apkanalyzer is None or common_host is None:
        raise ValueError("Android packaging requires LLVM readelf, apkanalyzer and compiled common host")
    runtime = staged / "runtime"
    manifest = verifier.authenticated("container", runtime / "container-manifest-v1.json",
        runtime / "container-manifest-v1.sig", public_key, "android", "aarch64")
    if variant not in ("Debug", "Release") or len(manifest["slots"]) != (2 if acceptance else 1):
        raise ValueError("APK purpose or build variant mismatch")
    inputs = output / "inputs"
    shutil.copytree(runtime, inputs / "assets/runtime")
    native = inputs / "jniLibs/arm64-v8a"
    native.mkdir(parents=True)
    for slot in manifest["slots"]:
        for library in (runtime / "engines" / slot["slot"] / slot["manifest"]["runtime_version"] / "jni/arm64-v8a").iterdir():
            if (native / library.name).exists():
                raise ValueError("Android native library name collision")
            shutil.copyfile(library, native / library.name)
    subprocess.run([str(readelf.with_name("llvm-strip")), "--strip-debug", "-o",
        str(native / "libnelomai_android_container.so"), str(common_host)], check=True)
    stable_aar = runtime / "engines/stable/0.2.16/runtime/runtime.aar"
    android = root / "src-tauri/gen/android"
    gradle = android / ("gradlew.bat" if os.name == "nt" else "gradlew")
    arguments = (["-PnelomaiAcceptance=true", "-PnelomaiStableRuntimeAar=" + str(stable_aar)] if acceptance else [])
    subprocess.run([str(gradle), ":app:assembleArm64" + variant, "--no-daemon", *( ["--offline"] if offline else []), *arguments,
        "-PnelomaiRuntimeInputs=" + str(inputs), "-x", ":app:rustBuildArm64" + variant],
        cwd=android, env=environment, check=True)
    package = output / "nelomai-acceptance-0.2.16-android-aarch64.apk"
    # Candidate release packaging is keyless. apksigner consumes this exact
    # unsigned APK only in the later protected finalization job.
    apk_name = "app-arm64-debug.apk" if variant == "Debug" else "app-arm64-release-unsigned.apk"
    shutil.copyfile(android / "app/build/outputs/apk/arm64" / variant.lower() / apk_name, package)
    # DEX and resources necessarily pass through D8/AAPT. Embedded AAR, ELF and
    # WebView bytes must remain exact, and actual compiled DEX entrypoints are
    # required independently by the acceptance-only APK checker.
    import sys
    arguments = (["--acceptance", "--release-set-sha256", manifest["stable_release_set_sha256"],
                  "--stable-manifest-sha256", manifest["stable_platform_manifest_sha256"]] if acceptance else [])
    subprocess.run([sys.executable, str(root / "scripts/android/check-container-apk.py"),
        "--apk", str(package), "--apkanalyzer", str(apkanalyzer), "--public-key", str(public_key), *arguments],
        env=environment, check=True)
    with zipfile.ZipFile(package) as apk:
        for path in runtime.rglob("*"):
            if path.is_file() and apk.read("assets/runtime/" + path.relative_to(runtime).as_posix()) != path.read_bytes():
                raise ValueError("packaged Android stable/container bytes changed")
    return package


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("candidate", "latest-payload", "output", "signing-key", "public-key"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("release-set-sha256", "source-commit", "platform", "architecture"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--readelf", type=Path)
    parser.add_argument("--apkanalyzer", type=Path)
    parser.add_argument("--common-host", type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("immutable acceptance build output already exists")
    stage(args.candidate.resolve(), args.release_set_sha256, args.latest_payload.resolve(),
        args.output.resolve() / "staged", args.signing_key.resolve(), args.public_key.resolve(),
        args.platform, args.architecture, args.source_commit, args.readelf)
    if args.platform == "android":
        package = package_android(args.output.resolve() / "staged", args.output.resolve() / "package",
            args.public_key.resolve(), args.readelf, args.apkanalyzer, args.common_host)
    else:
        package = package_desktop(args.output.resolve() / "staged", args.output.resolve() / "package",
                                  args.public_key.resolve(), args.platform, args.architecture)
    print(json.dumps({"package": str(package), "sha256": verifier.digest(package),
        "size_bytes": package.stat().st_size, "packaging": "verified", "execution_acceptance": "UNRUN"}))


if __name__ == "__main__":
    main()
