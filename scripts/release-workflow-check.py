#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]


def run() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    windows_workflow = (
        ROOT / ".github" / "workflows" / "windows-build.yml"
    ).read_text(encoding="utf-8")
    for token in (
        "verify:",
        "needs: verify",
        "needs: [verify, build, build-android]",
        "npm test",
        "cargo clippy --workspace --all-targets -- -D warnings",
        "cargo test --workspace",
        "TAURI_SIGNING_PRIVATE_KEY",
        "NELOMAI_UPDATER_PUBLIC_KEY",
        'test -n "$NELOMAI_UPDATER_PUBLIC_KEY"',
        "NELOMAI_RELEASE_MANIFEST_PRIVATE_KEY_B64",
        "prepare-runtime.ps1",
        "prepare-runtime.sh",
        "nelomai-windows-service",
        "nelomai-unix-service",
        '--bundles "${{ matrix.package_kind }}"',
        'target/${{ matrix.rust_target }}/release/bundle',
        "ubuntu-22.04",
        "windows-2022",
        "macos-14",
        "build-android:",
        "aarch64-linux-android",
        "ndk;28.2.13676358",
        "ANDROID_KEYSTORE_BASE64",
        "ANDROID_KEYSTORE_PASSWORD",
        "ANDROID_KEY_PASSWORD",
        "ANDROID_KEY_ALIAS",
        "NELOMAI_FIREBASE_APPLICATION_ID",
        "NELOMAI_FIREBASE_API_KEY",
        "NELOMAI_FIREBASE_PROJECT_ID",
        "android build --ci --apk --target aarch64",
        "app/build/outputs/apk/universal/release/app-universal-release.apk",
        "apksigner",
        "collect-android-release-artifact.py",
        "Signer #1 certificate SHA-256 digest",
        "path: release-android/",
        "gh release create",
    ):
        if token not in workflow:
            raise RuntimeError(f"release workflow misses {token}")
    for forbidden in ("macos-15-intel", "x86_64-apple-darwin"):
        if forbidden in workflow:
            raise RuntimeError(f"release workflow still contains {forbidden}")

    android_gradle = (
        ROOT / "src-tauri" / "gen" / "android" / "app" / "build.gradle.kts"
    ).read_text(encoding="utf-8")
    for token in (
        "ANDROID_KEYSTORE_PATH",
        "ANDROID_KEYSTORE_PASSWORD",
        "ANDROID_KEY_PASSWORD",
        "ANDROID_KEY_ALIAS",
        "releaseSigningConfigured",
    ):
        if token not in android_gradle:
            raise RuntimeError(f"Android release signing misses {token}")

    for token in (
        "workflow_dispatch:",
        "windows-2022",
        "cargo test --target x86_64-pc-windows-msvc",
        "prepare-runtime.ps1",
        "bundle.windows.conf.json",
        "actions/upload-artifact@v4",
    ):
        if token not in windows_workflow:
            raise RuntimeError(f"Windows build workflow misses {token}")

    version_script = (ROOT / "scripts" / "set-release-version.py").read_text(
        encoding="utf-8"
    )
    for helper in ("unix-service", "windows-service"):
        if f'"{helper}" / "Cargo.toml"' not in version_script:
            raise RuntimeError(f"release version misses {helper}")

    tauri_config = json.loads(
        (ROOT / "src-tauri" / "tauri.conf.json").read_text(encoding="utf-8")
    )
    updater_public_key = (
        tauri_config.get("plugins", {}).get("updater", {}).get("pubkey", "")
    )
    if not isinstance(updater_public_key, str) or not updater_public_key.strip():
        raise RuntimeError("Tauri updater public key is missing")
    try:
        decoded_updater_key = base64.b64decode(
            updater_public_key, validate=True
        )
    except ValueError as exc:
        raise RuntimeError("Tauri updater public key is not valid base64") from exc
    if b"minisign public key" not in decoded_updater_key:
        raise RuntimeError("Tauri updater public key has an invalid format")

    app_entrypoint = (ROOT / "src-tauri" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    for command in (
        "app_update_status",
        "app_update_set_automatic",
        "app_update_install",
        "app_update_restart",
    ):
        if command not in app_entrypoint:
            raise RuntimeError(f"native updater command is not registered: {command}")
    client_api = (ROOT / "crates" / "client-api" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    if "X-Nelomai-App-Version" not in client_api:
        raise RuntimeError("bootstrap does not report the running app version")

    windows_config = json.loads(
        (ROOT / "src-tauri" / "bundle.windows.conf.json").read_text(
            encoding="utf-8"
        )
    )
    windows_bundle = windows_config.get("bundle", {})
    windows_resources = windows_bundle.get("resources", {})
    for resource in (
        "nelomai-windows-service.exe",
        "tunnel.dll",
        "wireguard.dll",
    ):
        if resource not in windows_resources.values():
            raise RuntimeError(f"Windows bundle misses {resource}")
    nsis = windows_bundle.get("windows", {}).get("nsis", {})
    if nsis.get("installMode") != "perMachine":
        raise RuntimeError("Windows tunnel service requires a per-machine installer")
    if not nsis.get("installerHooks"):
        raise RuntimeError("Windows service installer hooks are missing")

    macos_resources = json.loads(
        (ROOT / "src-tauri" / "bundle.macos.conf.json").read_text(
            encoding="utf-8"
        )
    ).get("bundle", {}).get("resources", {})
    for resource in ("nelomai-unix-service", "wireguard-go", "install-macos.sh"):
        if resource not in macos_resources.values():
            raise RuntimeError(f"macOS bundle misses {resource}")

    linux_resources = json.loads(
        (ROOT / "src-tauri" / "bundle.linux.conf.json").read_text(
            encoding="utf-8"
        )
    ).get("bundle", {}).get("resources", {})
    for resource in (
        "nelomai-unix-service",
        "install-linux.sh",
        "resolvconf-linux.sh",
    ):
        if resource not in linux_resources.values():
            raise RuntimeError(f"Linux bundle misses {resource}")
    linux_installer = (
        ROOT / "crates" / "unix-service" / "install" / "install-linux.sh"
    ).read_text(encoding="utf-8")
    if "CapabilityBoundingSet=CAP_CHOWN CAP_NET_ADMIN CAP_NET_RAW" not in linux_installer:
        raise RuntimeError("Linux helper cannot assign its socket to the app user")
    for token in (
        "resolvconf-linux.sh",
        "Environment=PATH=$INSTALL_DIR:",
    ):
        if token not in linux_installer:
            raise RuntimeError(f"Linux helper DNS integration misses {token}")

    private_key = Ed25519PrivateKey.generate()
    seed = private_key.private_bytes_raw()
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        bundle = root / "bundle"
        bundle.mkdir()
        updater = bundle / "Nelomai.AppImage"
        updater_payload = b"signed-updater-artifact" * 131_072
        updater.write_bytes(updater_payload)
        (bundle / "Nelomai.AppImage.sig").write_text(
            "tauri-signature",
            encoding="utf-8",
        )
        collected = root / "collected"
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "collect-release-artifact.py"),
                "--search-root",
                str(bundle),
                "--output-dir",
                str(collected),
                "--version",
                "1.2.3",
                "--platform",
                "linux",
                "--architecture",
                "x86_64",
                "--package-kind",
                "appimage",
            ],
            check=True,
        )
        android_apk = bundle / "nelomai.apk"
        android_payload = b"signed-android-apk" * 131_072
        android_apk.write_bytes(android_payload)
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "collect-android-release-artifact.py"),
                "--apk",
                str(android_apk),
                "--output-dir",
                str(collected),
                "--version",
                "1.2.3",
                "--signer-sha256",
                "ab:" * 31 + "ab",
            ],
            check=True,
        )
        windows_updater = bundle / "Nelomai_1.2.3_x64-setup.exe"
        windows_updater_payload = b"signed-windows-updater" * 131_072
        windows_updater.write_bytes(windows_updater_payload)
        (bundle / "Nelomai_1.2.3_x64-setup.exe.sig").write_text(
            "tauri-windows-signature",
            encoding="utf-8",
        )
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "collect-release-artifact.py"),
                "--search-root",
                str(bundle),
                "--output-dir",
                str(collected),
                "--version",
                "1.2.3",
                "--platform",
                "windows",
                "--architecture",
                "x86_64",
                "--package-kind",
                "nsis",
            ],
            check=True,
        )
        published = root / "published"
        environment = {
            **os.environ,
            "NELOMAI_RELEASE_MANIFEST_PRIVATE_KEY_B64": base64.b64encode(
                seed
            ).decode("ascii"),
            "RELEASE_NOTES": "Release workflow check",
        }
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "build-release-manifest.py"),
                "--input-dir",
                str(collected),
                "--output-dir",
                str(published),
                "--version",
                "1.2.3",
            ],
            env=environment,
            check=True,
        )
        manifest_bytes = (
            published / "nelomai-release-manifest.json"
        ).read_bytes()
        signature = base64.b64decode(
            (published / "nelomai-release-manifest.sig").read_bytes().strip(),
            validate=True,
        )
        private_key.public_key().verify(signature, manifest_bytes)
        manifest = json.loads(manifest_bytes)
        if manifest["version"] != "1.2.3" or len(manifest["artifacts"]) != 3:
            raise RuntimeError("release manifest content is invalid")
        artifacts = {
            artifact["package_kind"]: artifact
            for artifact in manifest["artifacts"]
        }
        artifact = artifacts["appimage"]
        if artifact["package_kind"] != "appimage":
            raise RuntimeError("release artifact type is invalid")
        published_artifact = published / artifact["asset_name"]
        if not published_artifact.is_file():
            raise RuntimeError("published updater artifact is missing")
        if artifact["size_bytes"] != len(updater_payload):
            raise RuntimeError("release artifact size is invalid")
        if artifact["sha256"] != hashlib.sha256(updater_payload).hexdigest():
            raise RuntimeError("release artifact hash is invalid")
        windows_artifact = artifacts["nsis"]
        published_windows_artifact = published / windows_artifact["asset_name"]
        if not published_windows_artifact.is_file():
            raise RuntimeError("published Windows updater artifact is missing")
        if windows_artifact["size_bytes"] != len(windows_updater_payload):
            raise RuntimeError("Windows release artifact size is invalid")
        if windows_artifact["sha256"] != hashlib.sha256(
            windows_updater_payload
        ).hexdigest():
            raise RuntimeError("Windows release artifact hash is invalid")
        android_artifact = artifacts["apk"]
        if android_artifact["platform"] != "android":
            raise RuntimeError("Android release platform is invalid")
        if android_artifact["signature"] != "ab" * 32:
            raise RuntimeError("Android signer fingerprint is invalid")
        published_android_artifact = published / android_artifact["asset_name"]
        if not published_android_artifact.is_file():
            raise RuntimeError("published Android APK is missing")
        if android_artifact["sha256"] != hashlib.sha256(
            android_payload
        ).hexdigest():
            raise RuntimeError("Android APK hash is invalid")
    print("OK: release workflow check passed")


if __name__ == "__main__":
    run()
