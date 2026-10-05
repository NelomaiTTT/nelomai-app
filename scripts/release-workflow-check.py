#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

import yaml

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
AMNEZIAWG_GO_REVISION = "08d68cdae27762c3e07f36bbb12d2bad32f81926"


def assert_amneziawg_go_workflow_revision(workflow: str, label: str) -> None:
    marker = "git -C vendor/amneziawg-go rev-parse HEAD"
    if marker not in workflow:
        raise RuntimeError(f"{label} does not verify the AmneziaWG Go revision")
    checked_revision = re.search(r"[a-f0-9]{40}", workflow.split(marker, 1)[1][:256])
    if checked_revision is None or checked_revision.group(0) != AMNEZIAWG_GO_REVISION:
        raise RuntimeError(f"{label} uses another AmneziaWG Go revision")


def assert_windows_factory_jobs(workflow: dict, factory_test: str) -> None:
    """Require the actual producer/consumer graph and its critical programs."""
    def require(condition, message):
        if not condition:
            raise RuntimeError(message)

    def program(step):
        return "\n".join(line.strip() for line in step.get("run", "").splitlines()
                         if line.strip() and not line.strip().startswith("#"))

    jobs = workflow["jobs"]
    require(set(jobs) == {"linux-package-diagnostic", "frontend", "rust", "android-plugin",
                          "windows-build", "windows-native", "windows", "macos", "contracts-python"},
            "Checks must retain all six required checks and the isolated Windows graph")
    require("defaults" not in workflow, "Checks cannot override critical command shells")
    build, native, aggregate = (jobs[name] for name in ("windows-build", "windows-native", "windows"))
    for name, job in (("windows-build", build), ("windows-native", native), ("windows", aggregate)):
        require(set(job) <= {"if", "name", "runs-on", "env", "steps", "outputs", "needs", "strategy"},
                f"{name} cannot mask or replace its execution/status gates")
        for step in job["steps"]:
            require(set(step) <= {"name", "uses", "with", "run", "id", "env", "timeout-minutes"},
                    f"{name} steps must execute unconditionally and fail normally")
    for name in ("frontend", "rust", "android-plugin", "windows-build", "windows-native", "macos", "contracts-python"):
        require(jobs[name].get("if") == "github.event_name != 'workflow_dispatch'",
                f"{name} cannot skip normal checks")
    require(jobs["contracts-python"].get("env") == {
        "RUSTUP_HOME": "${{ runner.temp }}/nelomai-contracts-rustup"}
        and all("RUSTUP_HOME" not in step.get("env", {}) for step in jobs["contracts-python"]["steps"]),
            "Contracts Python must use its isolated runner-temp Rustup home without step overrides")
    require(build["runs-on"] == native["runs-on"] == "windows-latest", "Every native case needs a fresh Windows runner")
    require("strategy" not in build and "needs" not in build, "Windows common build must execute only once")
    require(native.get("needs") == ["windows-build"], "Native execution must require the successful common build")
    require(build.get("env") == {"SOURCE_SHA": "${{ github.sha }}"}, "Build must pin the current source")
    require(build.get("outputs") == {
        "manifest_sha256": "${{ steps.artifact.outputs.manifest_sha256 }}",
        "artifact_name": "${{ steps.artifact.outputs.artifact_name }}"}, "Build must expose its original artifact name and digest")
    require(native.get("env") == {
        "SOURCE_SHA": "${{ github.sha }}",
        "MANIFEST_SHA256": "${{ needs.windows-build.outputs.manifest_sha256 }}",
        "ARTIFACT_NAME": "${{ needs.windows-build.outputs.artifact_name }}"}, "Consumer must bind the successful build outputs")
    inventory = re.search(r"(?:for case in|let cases =)\s*\[([^]]+)\]", factory_test)
    require(inventory is not None, "Missing actual factory case inventory")
    cases = re.findall(r'"([a-z-]+)"', inventory.group(1))
    parent_count = re.search(r"let expected = match selected\.as_deref\(\) \{(.*?)\};\s*assert_eq!\(completed, expected\);", factory_test, re.DOTALL)
    require(parent_count is not None and " ".join(parent_count.group(1).split()) ==
            'Some("resolver-reference-error" | "resolver-reference-unwind") => 2, Some(_) => 1, None => cases.len() + 2,',
            "Actual native parent must require exact resolver/adapter and ordinary child completion counts")
    harness = (ROOT / "scripts/windows/test-carrier-factory-system.ps1").read_text()
    completion = re.search(r"^ *\$expectedCompleted =.*?^ *\}", harness, re.MULTILINE | re.DOTALL)
    require(completion is not None and "\n".join(line.strip() for line in completion.group(0).splitlines()) == r"""$expectedCompleted = if ($Case -in @('resolver-reference-error', 'resolver-reference-unwind')) { 2 } else { 1 }
if ($output -notmatch ('(?m)^actual native factory coverage case=' + [regex]::Escape($Case) + ' completed=' + $expectedCompleted + '\r?$')) {
throw 'Missing exact selected factory case completion; no partial-matrix PASS'
}""", "SYSTEM harness must reject incomplete selected child coverage")
    strategy = native["strategy"]
    selected = strategy.get("matrix", {}).get("case", [])
    require(set(strategy) == {"fail-fast", "matrix"} and strategy["fail-fast"] is False
            and set(strategy["matrix"]) == {"case"}, "Native matrix cannot suppress remaining cases")
    require(len(cases) == len(set(cases)) == len(selected) == len(set(selected)) == 18
            and set(selected) == set(cases), "Native matrix must cover every actual factory case exactly once")
    checkout = {"uses": "actions/checkout@v4", "with": {"ref": "${{ github.sha }}", "submodules": "recursive"}}
    require(build["steps"][0] == native["steps"][0] == checkout, "Producer and consumer checkouts must use exact current SHA")
    require(build["steps"][1] == {"uses": "dtolnay/rust-toolchain@master", "with": {
        "toolchain": "1.88.0", "components": "rustfmt, clippy"}}, "Common build must retain the audited toolchain")
    build_programs = [
        'cargo check -p nelomai-windows-service --all-targets',
        'cargo clippy --locked -p nelomai-windows-service --all-targets -- -D warnings',
        'cargo check -p nelomai-app',
        'cargo test -p nelomai-client-updater',
        'cargo test -p nelomai-windows-service -- --skip windows::member_carrier_factory::actual_execution::carrier_factory_selects_new_path_for_supported_pair',
        """$tests = & cargo test --locked -p nelomai-windows-service --lib native_security_buffer_sizes_readonly_descriptor_without_capacity_padding -- --list
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$selected = @($tests | Where-Object { $_ -match 'native_security_buffer_sizes_readonly_descriptor_without_capacity_padding: test$' })
if ($selected.Count -ne 1) { throw 'Expected exactly one readonly security-size gate; no empty-filter PASS' }
cargo test --locked -p nelomai-windows-service --lib native_security_buffer_sizes_readonly_descriptor_without_capacity_padding -- --nocapture --test-threads=1""",
        """$tests = & cargo test --locked -p nelomai-windows-service --lib txr_transient_enlist_isolated_gate -- --ignored --list
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$selected = @($tests | Where-Object { $_ -match 'txr_transient_enlist_isolated_gate: test$' })
if ($selected.Count -ne 1) { throw 'Expected exactly one isolated TxR gate; no empty-filter PASS' }
cargo test --locked -p nelomai-windows-service --lib txr_transient_enlist_isolated_gate -- --ignored --nocapture --test-threads=1""",
        """cargo build --locked -p nelomai-windows-service --bin nelomai-windows-service --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$engine = (Resolve-Path -LiteralPath 'target/release/nelomai-windows-service.exe').Path
Write-Output "Actual factory release engine bytes=$((Get-Item -LiteralPath $engine).Length)"
$runtime = Join-Path $env:RUNNER_TEMP 'factory-runtime'
./scripts/windows/prepare-runtime.ps1 -OutputDirectory $runtime -ServiceExecutable $engine
if ((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $runtime 'wintun.dll')).Hash.ToLowerInvariant() -ne 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce') {
throw 'Audited factory Wintun input hash mismatch'
}
if ((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $runtime 'wireguard.dll')).Hash.ToLowerInvariant() -ne 'b1b85e072c45d81358be29d94c599dc76652f912be8c0f0a41e2d5d89a6461d3') {
throw 'Audited factory WireGuard DLL hash mismatch'
}
"NELOMAI_FACTORY_RUNTIME_DIRECTORY=$runtime" | Out-File -FilePath $env:GITHUB_ENV -Append""",
        """$build = @(& cargo test --locked -p nelomai-windows-service --lib --no-run --message-format=json)
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$tests = @($build | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object {
$_.reason -eq 'compiler-artifact' -and $_.target.name -eq 'nelomai_windows_service' -and $_.profile.test -and $_.executable
})
if ($tests.Count -ne 1) { throw 'Expected exactly one service library test executable' }
python scripts/windows/carrier-factory-artifact.py create `
--test-executable $tests[0].executable --runtime-directory $env:NELOMAI_FACTORY_RUNTIME_DIRECTORY `
--output "$env:RUNNER_TEMP/factory-artifact" --source-sha $env:SOURCE_SHA --artifact-name $env:ARTIFACT_NAME
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }""",
    ]
    require(len(build["steps"]) == 12 and [program(step) for step in build["steps"][2:-1]] == build_programs,
            "Common build must run ordinary/security/TxR gates before factory runtime preparation and retain all strict gates before artifact assembly")
    require(all("env" not in step for step in build["steps"][:10]), "Common gates cannot override their source/runtime environment")
    require(build["steps"][7].get("timeout-minutes") == build["steps"][8].get("timeout-minutes") == 2,
            "Native readonly and isolated TxR gate budgets must remain unchanged")
    artifact = build["steps"][-2]
    require(artifact.get("id") == "artifact" and artifact.get("env") == {
        "ARTIFACT_NAME": "windows-factory-${{ github.run_id }}-${{ github.run_attempt }}-${{ github.sha }}"},
        "Artifact name must identify its build run, attempt and source")
    require(build["steps"][-1] == {"uses": "actions/upload-artifact@v4", "with": {
        "name": "${{ steps.artifact.outputs.artifact_name }}", "path": "${{ runner.temp }}/factory-artifact/",
        "if-no-files-found": "error", "retention-days": 1}}, "Upload only the exact successful build artifact for one day")
    require(len(native["steps"]) == 5, "Native cases must only download/verify and execute, never rebuild or fall back")
    native_programs = [
        """if ([string]::IsNullOrWhiteSpace($env:ARTIFACT_NAME) -or $env:MANIFEST_SHA256 -notmatch '^[a-f0-9]{64}$') {
throw 'Missing successful build artifact outputs; no fallback'
}""",
        """python scripts/windows/carrier-factory-artifact.py verify `
--directory "$env:RUNNER_TEMP/factory-artifact" --source-sha $env:SOURCE_SHA --manifest-sha256 $env:MANIFEST_SHA256
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }""",
        """./scripts/windows/test-carrier-factory-system.ps1 -TestExecutable "$env:RUNNER_TEMP/factory-artifact/factory-tests.exe" `
-RuntimeDirectory "$env:RUNNER_TEMP/factory-artifact/runtime" `
-OutputDirectory $env:RUNNER_TEMP -Case ${{ matrix.case }}""",
    ]
    require([program(step) for step in native["steps"] if "run" in step] == native_programs,
            "Native artifact outputs/manifest must be checked before the unchanged explicit-case SYSTEM harness")
    require(native["steps"][2] == {"uses": "actions/download-artifact@v4", "with": {
        "name": "${{ needs.windows-build.outputs.artifact_name }}", "path": "${{ runner.temp }}/factory-artifact/"}},
        "Native case must download only this successful build, without previous-run or cache fallback")
    require(all("env" not in step for step in native["steps"]), "Native steps cannot override pinned build outputs")
    require(native["steps"][-1].get("timeout-minutes") == 55, "SYSTEM factory aperture must remain unchanged")
    require(aggregate.get("if") == "${{ always() && github.event_name != 'workflow_dispatch' }}"
            and aggregate.get("needs") == ["windows-build", "windows-native"]
            and aggregate["runs-on"] == "ubuntu-latest" and len(aggregate["steps"]) == 1,
            "Required Windows check must observe both producer and every native case even on failure")
    require(aggregate["steps"][0].get("env") == {
        "BUILD_RESULT": "${{ needs.windows-build.result }}", "NATIVE_RESULT": "${{ needs.windows-native.result }}"}
        and program(aggregate["steps"][0]) == 'test "$BUILD_RESULT" = success\ntest "$NATIVE_RESULT" = success',
        "Required Windows check must reject cancelled/skipped/failed producer or matrix")


def run() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    panel_gate_errors = []
    for token in (
        "panel_notification_ready:",
        "Подтверждаю, что панель с producer уведомлений уже развёрнута",
        "Проверить готовность панели к уведомлению",
        "inputs.panel_notification_ready",
    ):
        if token not in workflow:
            panel_gate_errors.append(
                f"release workflow misses panel-first gate: {token}"
            )
    release_triggers = workflow.split("permissions:", 1)[0]
    if "push:" in release_triggers or "tags:" in release_triggers:
        panel_gate_errors.append(
            "release workflow must not bypass the panel-first gate via a tag push"
        )
    if panel_gate_errors:
        raise RuntimeError("\n".join(panel_gate_errors))
    windows_workflow = (
        ROOT / ".github" / "workflows" / "windows-build.yml"
    ).read_text(encoding="utf-8")
    checks_workflow = (
        ROOT / ".github" / "workflows" / "checks.yml"
    ).read_text(encoding="utf-8")
    assert_amneziawg_go_workflow_revision(workflow, "release workflow")
    assert_amneziawg_go_workflow_revision(checks_workflow, "checks workflow")
    # Parsed topology and exact critical programs; a token in a comment cannot
    # stand in for an executing build, digest comparison or failure gate.
    factory_test = (ROOT / "crates/windows-service/src/windows/member_carrier_factory_native_tests.rs").read_text()
    assert_windows_factory_jobs(yaml.safe_load(checks_workflow), factory_test)
    submodule_entry = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--stage", "vendor/amneziawg-go"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    fields = submodule_entry.split()
    if len(fields) < 4 or fields[0] != "160000" or fields[1] != AMNEZIAWG_GO_REVISION:
        raise RuntimeError("vendor/amneziawg-go uses another revision")
    tunnel_plugin = (
        ROOT
        / "plugins"
        / "tunnel-android"
        / "android"
        / "src"
        / "main"
        / "java"
        / "TunnelPlugin.kt"
    ).read_text(encoding="utf-8")
    if f'"git-{AMNEZIAWG_GO_REVISION[:7]}"' not in tunnel_plugin:
        raise RuntimeError("Android diagnostics use another AmneziaWG Go revision")
    # Authorization is checked as a parsed job graph, not old inline build
    # command tokens that no longer describe the native phase consumers.
    subprocess.run([sys.executable, "-m", "unittest", "scripts.tests.test_release_workflow"],
                   cwd=ROOT, check=True)
    consumers = "\n".join((ROOT / name).read_text(encoding="utf-8") for name in (
        "scripts/build-release-platform.py", "scripts/package-release-platform.py",
        "scripts/finalize-release-candidate.py", "scripts/verify-release-platform.py",
        ".github/actions/release-native-host/action.yml"))
    for token in (
        "prepare-runtime.ps1", "prepare-runtime.sh", "nelomai-windows-service", "nelomai-unix-service",
        "ndk;28.2.13676358", "ANDROID_KEYSTORE_PASSWORD", "ANDROID_KEY_PASSWORD", "ANDROID_KEY_ALIAS",
        "NELOMAI_FIREBASE_APPLICATION_ID", "NELOMAI_FIREBASE_API_KEY", "NELOMAI_FIREBASE_PROJECT_ID",
        "CARGO_PROFILE_RELEASE_STRIP", "apksigner", ".debug_", ".symtab",
        "collect-android-release-artifact.py", "amneziawg-android-source.tar.gz",
        "Signer #1 certificate SHA-256 digest", "defender-exclusions.ps1",
        "awgGetNetworkTelemetry", "awgCloseUdp", "awgRebindUdp", "awgSendKeepalives",
        "awgStartHandshakeProbe", "awgHandshakeProbeStatus", "awgHandshakeProbeTimeoutMillis",
    ):
        if token not in consumers:
            raise RuntimeError(f"native release consumers miss required gate: {token}")
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

    windows_runtime_script = (
        ROOT / "scripts" / "windows" / "prepare-runtime.ps1"
    ).read_text(encoding="utf-8")
    for token in (
        "windows.FOLDERID_ProgramData",
        'root = filepath.Join(root, "Nelomai", "AmneziaWG")',
        "Pinned AmneziaWG path source no longer contains the expected known folder",
        "Pinned AmneziaWG path source no longer contains the expected data directory",
    ):
        if token not in windows_runtime_script:
            raise RuntimeError(
                "Windows AmneziaWG runtime does not isolate the Nelomai data directory"
            )
    for token in (
        "$WireGuardBuildMaximumAttempts = 3",
        "for ($wireGuardBuildAttempt = 1;",
        "WireGuard tunnel.dll build attempt",
        "Start-Sleep -Seconds",
    ):
        if token not in windows_runtime_script:
            raise RuntimeError(
                f"Windows WireGuard bootstrap does not have bounded retry: {token}"
            )

    android_network_patch = (
        ROOT / "patches" / "amneziawg-android-network-telemetry.patch"
    ).read_text(encoding="utf-8")
    if (
        '-ldflags="-s -w -X github.com/amnezia-vpn/amneziawg-go/'
        not in android_network_patch
    ):
        raise RuntimeError("Android libwg-go release build retains Go symbols")
    for token in (
        "CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO",
        "-Wl,--strip-all",
    ):
        if token not in android_network_patch:
            raise RuntimeError(
                f"Android C runtime release build retains symbols: {token}"
            )

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
    windows_updater = (
        tauri_config.get("plugins", {}).get("updater", {}).get("windows", {})
    )
    if windows_updater.get("installMode") != "passive":
        raise RuntimeError("Windows per-machine updater must support elevation")

    app_entrypoint = (ROOT / "src-tauri" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    for command in (
        "app_update_status",
        "app_update_refresh",
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
        "runtime/",
    ):
        if resource not in windows_resources.values():
            raise RuntimeError(f"Windows bundle misses {resource}")
    # DLLs/licenses now live inside the authenticated latest slot, not as
    # competing top-level resources. The real packager tests retain their
    # completeness and the native verifier runs after installer extraction.
    subprocess.run([sys.executable, "-m", "unittest", "scripts.tests.test_runtime_artifact"], cwd=ROOT, check=True)
    nsis = windows_bundle.get("windows", {}).get("nsis", {})
    if nsis.get("installMode") != "perMachine":
        raise RuntimeError("Windows tunnel service requires a per-machine installer")
    if not nsis.get("installerHooks"):
        raise RuntimeError("Windows service installer hooks are missing")
    windows_hooks = (ROOT / "src-tauri" / "windows" / "hooks.nsh").read_text(
        encoding="utf-8"
    )
    for token in (
        "$UpdateMode = 1",
        "ProfileList\\$NelomaiOwnerSid",
        "UninstallString",
        "$NelomaiLegacyStartShortcut",
        "UnpinShortcut",
        "MUI_STARTMENU_GETFOLDER",
        "SetLnkAppUserModelId",
    ):
        if token not in windows_hooks:
            raise RuntimeError(f"Windows update shortcut refresh misses {token}")
    preinstall_hook = windows_hooks.split("!macro NSIS_HOOK_PREINSTALL", 1)[1].split(
        "!macroend", 1
    )[0]
    postinstall_hook = windows_hooks.split("!macro NSIS_HOOK_POSTINSTALL", 1)[1].split(
        "!macroend", 1
    )[0]
    for token in (
        "RunAsUser",
        '"/S /UPDATE"',
        "Pop $2",
        "nelomai_legacy_install_wait",
    ):
        if token not in preinstall_hook:
            raise RuntimeError(f"Windows legacy migration misses {token}")
    if "RunAsUser" in postinstall_hook:
        raise RuntimeError("Windows legacy migration must finish before post-install")
    if preinstall_hook.index("RunAsUser") > preinstall_hook.index(
        "Stopping the previous Nelomai tunnel service"
    ):
        raise RuntimeError("Windows legacy migration must precede service replacement")
    for token in (
        "amneziawg-tunnel.dll",
        '!insertmacro NelomaiManagedDefender "add"',
    ):
        if token not in preinstall_hook:
            raise RuntimeError(f"Windows Defender setup misses {token}")
    if preinstall_hook.index('!insertmacro NelomaiManagedDefender "add"') < preinstall_hook.index(
        "Stopping the previous Nelomai tunnel service"
    ):
        raise RuntimeError("Windows Defender exclusion must be the final pre-install mutation")
    if "StrCmp $NelomaiLegacyStartShortcut 1" not in postinstall_hook:
        raise RuntimeError("Windows legacy migration does not restore its Start shortcut")
    preuninstall_hook = windows_hooks.split(
        "!macro NSIS_HOOK_PREUNINSTALL", 1
    )[1].split("!macroend", 1)[0]
    for token in (
        "$UpdateMode <> 1",
        '!insertmacro NelomaiManagedDefender "cleanup"',
    ):
        if token not in preuninstall_hook:
            raise RuntimeError(f"Windows Defender cleanup misses {token}")
    defender_runtime = (
        ROOT / "crates" / "windows-service" / "src" / "windows" / "defender.rs"
    ).read_text(encoding="utf-8")
    for token in (
        "Get-MpComputerStatus",
        "MpCmdRun.exe",
        "-CheckExclusion",
        'include_str!("../../install/defender-exclusions.ps1")',
        "CREATE_NO_WINDOW",
    ):
        if token not in defender_runtime:
            raise RuntimeError(f"Windows Defender runtime check misses {token}")
    defender_script = (ROOT / "crates/windows-service/install/defender-exclusions.ps1").read_text(encoding="utf-8")
    for token in ("Add-MpPreference -ExclusionPath", "Remove-MpPreference -ExclusionPath", "ManagedDefenderExclusionPath", "Get-OwnershipName", "Test-ManagedPath"):
        if token not in defender_script:
            raise RuntimeError(f"Windows Defender shared ownership script misses {token}")
    defender_hook = windows_hooks.split("!macro NelomaiManagedDefender ACTION", 1)[1].split("!macroend", 1)[0]
    for token in ("${NelomaiDefenderScript}", "$SYSDIR\\WindowsPowerShell\\v1.0\\powershell.exe", "NELOMAI_DEFENDER_INSTALL_DIR", "NELOMAI_DEFENDER_PRIVILEGED_DIR", "NELOMAI_DEFENDER_ACTION", "NELOMAI_DEFENDER_EXCLUSION_PATH"):
        if token not in defender_hook:
            raise RuntimeError(f"Windows Defender hook misses {token}")
    windows_commands = (ROOT / "src-tauri" / "src" / "commands.rs").read_text(
        encoding="utf-8"
    )
    for token in (
        "app_windows_defender_status",
        "app_windows_defender_repair",
        "windows.defender.before_awg_start",
        "amneziawg_component_missing",
    ):
        if token not in windows_commands:
            raise RuntimeError(f"Windows Defender app integration misses {token}")
    for command in ("app_windows_defender_status", "app_windows_defender_repair"):
        if command not in app_entrypoint:
            raise RuntimeError(f"Windows Defender command is not registered: {command}")

    macos_resources = json.loads(
        (ROOT / "src-tauri" / "bundle.macos.conf.json").read_text(
            encoding="utf-8"
        )
    ).get("bundle", {}).get("resources", {})
    for resource in (
        "runtime/",
        "dispatcher/1/nelomai-unix-service",
        "install-macos.sh",
        "install-common-macos.sh",
    ):
        if resource not in macos_resources.values():
            raise RuntimeError(f"macOS bundle misses {resource}")

    linux_resources = json.loads(
        (ROOT / "src-tauri" / "bundle.linux.conf.json").read_text(
            encoding="utf-8"
        )
    ).get("bundle", {}).get("resources", {})
    for resource in (
        "runtime/",
        "dispatcher/1/nelomai-unix-service",
        "install-linux.sh",
        "install-common-linux.sh",
    ):
        if resource not in linux_resources.values():
            raise RuntimeError(f"Linux bundle misses {resource}")
    linux_installer = (
        ROOT / "crates" / "unix-service" / "install" / "install-linux.sh"
    ).read_text(encoding="utf-8")
    if "CapabilityBoundingSet=CAP_CHOWN CAP_NET_ADMIN CAP_NET_RAW" not in linux_installer:
        raise RuntimeError("Linux helper cannot assign its socket to the app user")
    for token in ("Environment=PATH=$INSTALL_DIR:", "install-layout", "--dispatcher"):
        if token not in linux_installer:
            raise RuntimeError(f"Linux helper DNS integration misses {token}")
    unix_prepare = (ROOT / "scripts/unix/prepare-runtime.sh").read_text(encoding="utf-8")
    if 'resolvconf-linux.sh" "$OUTPUT/resolvconf"' not in unix_prepare:
        raise RuntimeError("Linux signed runtime slot omits the actual DNS helper")

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
