# Confirmed Stable Dual Runtime 0.3.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the reviewed runtime-v1 foundation to current main and ship one 0.3.0 container whose latest code can be manually replaced at next full launch by the exact published 0.2.16 runtime.

**Architecture:** Keep the current main checkout and its Android hot-standby behavior, port maintenance infrastructure in reviewable layers, and resolve storage/service/updater conflicts through tests rather than wholesale file selection. Release jobs fetch immutable 0.2.16 payloads by exact manifest digest, verify and embed them without rebuilding, then inspect the final installer byte-for-byte. The common container owns identity, auth, updater, selection, and system dispatch; each slot retains its own complete UI/core/tunnel engine and state.

**Tech Stack:** Rust 1.88, Tauri 2, Svelte 5, Kotlin/JVM 17, Gradle/Android SDK 36, Windows service, Unix helper, GitHub Actions, Python artifact tooling, Ed25519.

**Spec:** `docs/superpowers/specs/2026-09-02-confirmed-stable-runtime-design.md`

## Global Constraints

- Work inline in `/Users/altzxd/Documents/GitHub/nelomai-app` on `main`; do not create another branch/worktree unless the verified state makes inline work unsafe.
- Preserve the two expected dirty vendor submodules and never reset, clean, stage, or modify them.
- Port only reviewed runtime-v1 infrastructure from the 0.2.16 maintenance branch; do not replace main’s Android hot-standby, recovery, updater fixes, or later state fields with older files.
- Stable is exactly runtime 0.2.16 with its accepted signed manifest digest. Do not rebuild its source or select another version automatically.
- The toggle is manual. Switching stops the tunnel now, changes runtime after a full restart, and offers “Позже”/“Перезапустить сейчас”.
- Container update always resets selection to latest. Runtime crash never changes selection.
- One package/application ID, one account/device/session, one system service/permission, and one active runtime.
- Developer ID/notarization are absent by design; retain updater signature, manifest signature, hashes, and deterministic ad-hoc macOS signing where required.
- No push, release, deploy, production mutation, agent update, or capability enablement without a separate direct user command.
- Commits use Russian messages.

---

### Task 1: Audit and port the 0.2.16 foundation onto current main

**Files:**
- Modify: the runtime-v1 files introduced by the completed 0.2.16 plan
- Review carefully: `crates/client-storage/src/lib.rs`
- Review carefully: `crates/client-application/src/lib.rs`
- Review carefully: `src-tauri/src/lib.rs`
- Review carefully: `src-tauri/src/updates.rs`
- Review carefully: `plugins/tunnel-android/android/src/main/java/AndroidRecoveryStore.kt`
- Review carefully: `plugins/tunnel-android/android/src/main/java/BackgroundCredentialStore.kt`
- Review carefully: `plugins/tunnel-android/android/src/main/java/QuickTunnelPlanStore.kt`
- Review carefully: `plugins/tunnel-android/android/src/main/java/NelomaiVpnService.kt`

**Interfaces:**
- Consumes the reviewed maintenance branch `codex/confirmed-stable-0.2.16` and its complete green evidence.
- Produces the same manifest/auth/container/dispatcher public interfaces on main while retaining all post-0.2.15 fields and behavior.

- [ ] **Step 1: Record immutable baselines.** Verify main is current with origin, list local commits, status, expected submodule dirt, and successful workflows. Verify the maintenance branch descends from `632cc4b...` and has no merge from current main.
- [ ] **Step 2: Build a port manifest by commit subject.** Use the Russian commit subjects from the 0.2.16 plan and record every changed path:

```bash
git log --reverse --format='%H %s' 632cc4b40872c559a75e5d7104b72bae17ac91c3..codex/confirmed-stable-0.2.16
git diff --name-status 632cc4b40872c559a75e5d7104b72bae17ac91c3..codex/confirmed-stable-0.2.16
```

- [ ] **Step 3: Add RED main-only migration fixtures before porting storage.** Serialize a current-main `StoredAuth`/Android recovery state containing redundant session, both lease slots, membership/role generations, cancellation tombstone, pending compensation, quick plan, background activation, diagnostics sequence, and split-tunnel applied state. The post-port reader must preserve every value in the latest 0.3.0 namespace.
- [ ] **Step 4: Run the fixtures RED because runtime-v1 migration is absent on main.**
- [ ] **Step 5: Cherry-pick only nonconflicting focused commits; stop each conflicting pick and resolve file-by-file against the RED fixtures.** Never use “ours/theirs” on an entire storage, Android service, application, updater, or workflow file.
- [ ] **Step 6: Run the narrow suite after each resolved commit.**

```bash
cargo test -p nelomai-client-storage
cargo test -p nelomai-client-application
cargo test -p nelomai-client-updater
./src-tauri/gen/android/gradlew -p src-tauri/gen/android :app:testDebugUnitTest
```

- [ ] **Step 7: Confirm the migration fixture is GREEN and no 0.3.0 field was dropped by permissive serde defaults.** Add `deny_unknown_fields` only to newly versioned records where forward compatibility is intentionally rejected; keep explicit legacy readers for prior shapes.
- [ ] **Step 8: Commit conflict-resolution tests and main adaptations.**

```bash
git add Cargo.toml crates plugins src-tauri scripts contracts
git commit -m "Перенести runtime-v1 без потери hot-standby"
```

### Task 2: Complete shared auth and runtime isolation with hot-standby state

**Files:**
- Modify: `crates/client-storage/src/auth.rs`
- Modify: `crates/client-storage/src/runtime_state.rs`
- Modify: `crates/client-storage/src/migration.rs`
- Modify: `crates/client-application/src/lib.rs`
- Modify: `crates/client-container/src/auth_broker.rs`
- Modify: `plugins/tunnel-android/android/src/main/java/BackgroundCredentialStore.kt`
- Modify: `plugins/tunnel-android/android/src/main/java/AndroidRecoveryStore.kt`
- Modify: `plugins/tunnel-android/android/src/main/java/QuickTunnelPlanStore.kt`
- Test: `crates/client-storage/tests/auth_migration.rs`
- Test: `crates/client-storage/tests/runtime_state.rs`
- Test: Android store/service tests

**Interfaces:**
- Latest preference namespace migrates to 0.3.0; stable 0.2.16 preferences remain separate.
- Latest operational state is under exact version 0.3.0; stable operational state is under exact version 0.2.16.
- Background credentials carry slot, runtime version, and common session generation.

- [ ] **Step 1: Add RED cross-slot tests.** Latest hot-standby state cannot be read from stable; stable cannot deserialize redundant-session fields; switching does not copy leases, quick plans, recovery, applied split-tunnel state, or diagnostics sequence; each slot preserves its own durable preferences.
- [ ] **Step 2: Add RED generation tests.** A background callback from latest after switch, logout, or re-login cannot persist tokens or schedule recovery; cleanup using the old scoped capability may finish only the envelope’s IDs; stable receives a new scoped capability after application.
- [ ] **Step 3: Run RED tests.**
- [ ] **Step 4: Extend the versioned runtime record with every current-main field and explicit conversion from the pre-container main shape.** Stable 0.2.16 uses only fields defined by its manifest contract and never sees 0.3.0 records.
- [ ] **Step 5: Make Android encrypted stores use broker-owned namespace/generation.** Native service startup verifies selected slot and generation before loading recovery or quick plan; stale data is quarantined for diagnostics, not executed.
- [ ] **Step 6: Run storage/application/Android suites GREEN.**
- [ ] **Step 7: Commit.**

```bash
git add crates/client-storage crates/client-application crates/client-container plugins/tunnel-android
git commit -m "Изолировать hot-standby по версии runtime"
```

### Task 3: Expose manual stable selection in the 0.3.0 UI

**Files:**
- Modify: `src/lib/RuntimeSelector.svelte`
- Modify: `src/lib/RuntimeSelector.test.ts`
- Modify: `src/lib/app-model.ts`
- Modify: `src/lib/app-model.test.ts`
- Modify: `src/lib/native-client.ts`
- Modify: `src/routes/+page.svelte`
- Modify: `src-tauri/src/commands.rs`
- Modify: `src-tauri/src/desktop.rs`

**Interfaces:**
- Consumes `runtime_status` and `runtime_select` from the common container.
- Produces setting “Использовать стабильную версию”, stable version 0.2.16, active/pending version labels, and restart notice with “Позже”/“Перезапустить сейчас”.

- [ ] **Step 1: Add RED UI state tests.** Toggle reflects pending selection, not optimistic active selection; failed durable write rolls back visually; pending switch disables connect/recovery and informs tile/tray state; returning toggle to active cancels pending only after cleanup completion; closing to tray does not apply; full exit/relaunch does.
- [ ] **Step 2: Add RED accessibility/localization tests.** The toggle has an associated Russian label, version text is readable without color, busy/error/restart messages are announced, and both actions are keyboard accessible.
- [ ] **Step 3: Run RED frontend tests.**

```bash
npm run test:unit -- RuntimeSelector app-model native-client
```

- [ ] **Step 4: Implement one model flow.** Svelte calls native commands and renders returned container state; it never edits slot files or kills processes directly. “Перезапустить сейчас” invokes the container’s full-relaunch command, while “Позже” leaves the current runtime UI open with tunnel start blocked.
- [ ] **Step 5: Run frontend tests and `npm run check` GREEN.**
- [ ] **Step 6: Commit.**

```bash
git add src src-tauri/src/commands.rs src-tauri/src/desktop.rs
git commit -m "Включить ручной выбор стабильной версии"
```

### Task 4: Embed and launch two desktop runtime payloads

**Files:**
- Modify: `src-tauri/src/container.rs`
- Modify: `src-tauri/src/runtime.rs`
- Modify: `src-tauri/src/bin/nelomai-runtime.rs`
- Modify: `src-tauri/bundle.linux.conf.json`
- Modify: `src-tauri/bundle.macos.conf.json`
- Modify: `src-tauri/bundle.windows.conf.json`
- Modify: `scripts/package-runtime-artifact.py`
- Create: `scripts/embed-stable-runtime.py`
- Create: `scripts/verify-final-runtime-payload.py`
- Test: `src-tauri/tests/container_runtime.rs`
- Create: `scripts/tests/test_embed_stable_runtime.py`

**Interfaces:**
- Latest executable/engine path is versioned under `latest/0.3.0`; stable path is `stable/0.2.16`.
- Stable input is the accepted platform/architecture archive plus manifest/signature and expected manifest SHA-256.
- Final-package verifier extracts stable files and byte-compares them with manifest-approved input files.

- [ ] **Step 1: Add RED ingestion tests.** Reject wrong manifest digest/signature/source commit/version/platform/architecture/contract, draft/prerelease identity metadata, missing file, altered byte, extra executable, path collision, path traversal, and repacked/re-signed stable content.
- [ ] **Step 2: Add RED launcher integration tests.** Repeated latest/stable switches launch only one child; wrong hash falls back to latest with explicit integrity error; stable process cannot connect to privileged service except through broker; tray/autostart route to selected slot; runtime crash does not change selection.
- [ ] **Step 3: Add RED macOS tests.** Final ad-hoc signing is deterministic for the assembled bundle structure, all nested executable hashes are recorded after signing, and no check requires Developer ID/notarization.
- [ ] **Step 4: Run RED tests.**
- [ ] **Step 5: Implement verified extraction into a staging tree.** Refuse symlinks/hardlinks/special files, apply fixed modes, verify bytes, then atomically publish the container manifest pointer. Do not transform stable binaries or frontend assets.
- [ ] **Step 6: Update Tauri platform bundles.** Include common container, both runtime trees, one dispatcher/service, and signed container manifest; keep update package identity/version at 0.3.0 regardless of selected runtime.
- [ ] **Step 7: Re-extract stable files from locally built final bundles and byte-compare GREEN.**
- [ ] **Step 8: Commit.**

```bash
git add src-tauri scripts/embed-stable-runtime.py scripts/verify-final-runtime-payload.py scripts/tests/test_embed_stable_runtime.py
git commit -m "Встроить стабильный runtime в desktop пакеты"
```

### Task 5: Embed and dispatch two Android runtime payloads

**Files:**
- Modify: `src-tauri/gen/android/app/build.gradle.kts`
- Modify: `src-tauri/gen/android/app/src/main/AndroidManifest.xml`
- Modify: `src-tauri/gen/android/app/src/main/java/ru/nelomai/client/MainActivity.kt`
- Modify: `src-tauri/gen/android/app/src/main/java/ru/nelomai/client/NelomaiQuickTileService.kt`
- Modify: `src-tauri/gen/android/app/src/main/java/ru/nelomai/client/RuntimeVpnDispatcherService.kt`
- Modify: `src-tauri/gen/android/app/src/main/java/ru/nelomai/client/RuntimeAuthBrokerService.kt`
- Modify: `plugins/tunnel-android/android/src/main/java/NelomaiVpnService.kt`
- Modify: `plugins/tunnel-android/android/src/main/java/RedundantConnectionCoordinator.kt`
- Modify: `scripts/android/check-runtime-collisions.py`
- Test: Android JVM/instrumentation suites

**Interfaces:**
- One installed `ru.nelomai.client` APK/versionCode/VPN permission.
- Latest 0.3.0 and stable 0.2.16 retain distinct classes/resources/assets/native libraries and use common `nelomai_runtime_v1` dispatcher ABI.
- Quick Settings and background actions resolve only the verified selected slot/generation.

- [ ] **Step 1: Add RED packaging tests using the real accepted 0.2.16 archive.** Prove final APK contains both expected WebView assets, DEX class sets, native engines and licenses; collision scan is empty; only common MainActivity/tile/VpnService are externally addressable.
- [ ] **Step 2: Add RED lifecycle tests.** Switch with ordinary tunnel, two-member hot-standby tunnel, start in progress, compensation cleanup, total-loss recovery, tile start, tile stop, UI process death, and VPN process timeout. No old callback may re-enable desired-active or publish a new lease after the switch fence.
- [ ] **Step 3: Add RED process test.** After switching, the prior `:vpn` PID is gone before a new selected engine loads; the same process never loads both `nelomai_app_lib`/latest and `nelomai_runtime_stable`.
- [ ] **Step 4: Run RED JVM/instrumentation/artifact tests.**
- [ ] **Step 5: Wire common dispatch to the selected engine.** The dispatcher receives no route/recovery policy, validates manifest hash and session generation, delegates the bounded ABI, and owns final process termination. Hot-standby logic stays entirely inside latest 0.3.0.
- [ ] **Step 6: Make MainActivity load only selected full UI/code.** Stable uses its archived DEX/assets/native payload without rebuilding or namespace rewriting. Binder components remain explicit and non-exported.
- [ ] **Step 7: Build a local release APK, verify signer/manifest, re-extract stable payload, and byte-compare GREEN.**
- [ ] **Step 8: Commit.**

```bash
git add src-tauri/gen/android plugins/tunnel-android scripts/android
git commit -m "Встроить стабильный runtime в Android APK"
```

### Task 6: Enforce stable inputs and provenance in the 0.3.0 release workflow

**Files:**
- Modify: `.github/workflows/release.yml`
- Modify: `scripts/release-workflow-check.py`
- Modify: `scripts/verify-runtime-artifact.py`
- Modify: `scripts/verify-final-runtime-payload.py`
- Modify: `scripts/tests/test_runtime_artifact.py`
- Modify: `docs/runtime-artifacts.md`
- Modify: `docs/application-updates.md`

**Interfaces:**
- Workflow inputs are mandatory `stable_version` and `stable_manifest_sha256`.
- Workflow input `panel_runtime_contract_revision` is mandatory and equals the deployed panel response revision approved for this release.
- For 0.3.0, policy additionally asserts `stable_version == 0.2.16`.
- Release provenance records stable manifest digest and release asset identities for each platform/architecture.

- [ ] **Step 1: Add RED static/workflow tests.** Missing inputs, partial platform set, draft/prerelease asset, reused release-set ID, wrong contract/range, silent version substitution, source rebuild, or final byte mismatch must fail the whole workflow before publication.
- [ ] **Step 2: Run RED tests.**

```bash
python -m unittest scripts.tests.test_runtime_artifact
python scripts/release-workflow-check.py
```

- [ ] **Step 3: Add a verification job before platform builds.** It fetches exact published assets for 0.2.16, compares manifest digest to the explicit input, verifies detached signature and every file, then reads `https://nelomai.ru/api/client/v1/runtime-contracts`, requires the explicit deployed revision and a range containing runtime 0.2.16/contract 1, records the response digest in provenance, and uploads only verified short-lived CI artifacts to dependent jobs. Network, TLS, schema, revision, or range failure stops the build.
- [ ] **Step 4: Make every platform build consume only that verified job artifact.** After building, extract stable bytes from APK/app/NSIS/AppImage and compare with the accepted manifest. Any platform failure prevents release creation; no latest-only fallback exists.
- [ ] **Step 5: Emit size/provenance report.** Record common/latest/stable byte counts and identify duplicated files by digest so accidental toolchain duplication is visible.
- [ ] **Step 6: Run workflow tests GREEN and commit.**

```bash
git add .github/workflows/release.yml scripts docs/runtime-artifacts.md docs/application-updates.md
git commit -m "Зафиксировать стабильный runtime в сборке 0.3.0"
```

### Task 7: Verify switch, logout, reconciliation, and update transactions end to end

**Files:**
- Modify: `crates/client-container/tests/switch.rs`
- Modify: `crates/client-container/tests/update.rs`
- Modify: `crates/client-container/tests/auth_broker.rs`
- Modify: `crates/client-application/tests/http_flow.rs`
- Modify: `src-tauri/tests/container_runtime.rs`
- Modify: Android service tests
- Create: `tests/runtime-switch.e2e.ts`

**Interfaces:**
- Consumes the deployed panel reconciliation contract and both embedded runtime payloads.
- Produces deterministic integration evidence for all crash/retry boundaries before physical E2E.

- [ ] **Step 1: Add a phase-by-phase crash matrix.** For every switch phase and every update phase, terminate/reconstruct the container and assert target UI starts, first tunnel start waits for `clean`, operation ID is stable, no second lease/session/device appears, and the source engine/process remains stopped.
- [ ] **Step 2: Add unavailable-panel tests.** UI and selected runtime remain usable; tunnel start returns retryable state with bounded backoff; repeated clicks do not create requests with new operation IDs or an infinite busy state.
- [ ] **Step 3: Add shared-auth tests.** Login in latest, switch to stable, refresh, switch back, logout in either slot, late refresh/background callbacks, re-login, and account change all retain one install identity and enforce session generation.
- [ ] **Step 4: Add update tests from active stable.** Shutdown barrier stops local engine and journals server cleanup; successful 0.3.0-to-next-container fixture selects latest; failed installer restores stable selection/tunnel availability; partially installed privileged layout keeps the old manifest pointer.
- [ ] **Step 5: Add integrity tests.** Corrupt stable selects latest with an explicit error; corrupt latest is a hard launch failure rather than silently switching stable; runtime crash leaves selected slot unchanged.
- [ ] **Step 6: Run all integration suites GREEN.**
- [ ] **Step 7: Commit.**

```bash
git add crates/client-container crates/client-application src-tauri plugins/tunnel-android tests/runtime-switch.e2e.ts
git commit -m "Проверить транзакции смены runtime"
```

### Task 8: Prepare 0.3.0 changelog and automated acceptance evidence

**Files:**
- Modify: version files changed by `scripts/set-release-version.py`
- Modify: `CHANGELOG.md`
- Create: `docs/reviews/2026-09-03-confirmed-stable-runtime-0.3.0.md`

**Interfaces:**
- Produces an unpushed main revision ready for controlled physical testing and, later, an explicitly authorized release.

- [ ] **Step 1: Set version 0.3.0 through the repository script and write Russian changelog.** Describe manual stable 0.2.16 selection, tunnel stop/restart requirement, selection reset after update, shared account, and absence of automatic fallback.

```bash
python scripts/set-release-version.py 0.3.0
```

- [ ] **Step 2: Run the complete automated gate.**

```bash
npm test
python contracts/python/validate_fixtures.py
python scripts/release-workflow-check.py
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
./src-tauri/gen/android/gradlew -p src-tauri/gen/android :app:testDebugUnitTest
git diff --check
```

- [ ] **Step 3: Build all CI platform matrices without publishing.** Verify linux-x86_64 AppImage, windows-x86_64 NSIS, macos-aarch64 app/updater artifact, and android-aarch64 APK plus both runtime payload reports. Use CI test signing where production secrets are unavailable; never commit signing material.
- [ ] **Step 4: Perform three review passes and record exact findings/fixes.** Pass 1 covers common identity/auth/storage/generation. Pass 2 covers switching, cleanup, hot-standby, tile/tray/autostart, and updater. Pass 3 covers artifact provenance, Android collisions, desktop privilege boundary, macOS no-notarization path, and secret/vendor scope. Fix each actionable finding with a failing regression test first.
- [ ] **Step 5: Run final source/status checks.**

```bash
git status --short --branch
git diff --check
git diff --submodule=log origin/main...HEAD
rg -n "BEGIN (RSA|OPENSSH|EC) PRIVATE KEY|ANDROID_KEYSTORE_PASSWORD|TAURI_SIGNING_PRIVATE_KEY=" --glob '!package-lock.json' .
```

Expected: only intended app changes and the two pre-existing dirty vendor submodules; no secrets or production configuration.

- [ ] **Step 6: Commit release preparation and review evidence.**

```bash
git add CHANGELOG.md docs/reviews/2026-09-03-confirmed-stable-runtime-0.3.0.md package.json package-lock.json src-tauri/Cargo.toml src-tauri/tauri.conf.json
git commit -m "Подготовить версию 0.3.0 со стабильным runtime"
```

- [ ] **Step 7: Stop before push/release.** Report exact HEAD, stable manifest digest, package verification evidence, and physical E2E checklist. Do not push or start the release workflow.

### Task 9: Execute available physical E2E under explicit release-test authorization

**Files:**
- Modify: `docs/reviews/2026-09-03-confirmed-stable-runtime-0.3.0.md`

**Interfaces:**
- Produces signed-off evidence for Android, macOS, Windows, and automated-only Linux.
- Does not itself authorize production release/deploy.

- [ ] **Step 1: Android physical matrix.** Upgrade from 0.2.16; verify first launch latest; login identity unchanged; ordinary and hot-standby tunnel; latest→stable and stable→latest with active/stopped tunnel; tile on/off; VPN permission; UI/process death; logout from each slot; successful/failed update fixture.
- [ ] **Step 2: macOS physical matrix.** Upgrade, both slots, sleep/wake tunnel recovery in each slot, tray/autostart/full restart, helper lifecycle, updater signature/runtime hash/ad-hoc bundle consistency, and no notarization expectation.
- [ ] **Step 3: Windows physical matrix.** Upgrade, both slots, one registered service, named-pipe caller rejection, active-tunnel switch, tray/autostart, and successful/failed installer rollback.
- [ ] **Step 4: Linux automated matrix.** AppImage launch, both runtimes, signed manifest/hash, IPC peer rejection, dispatcher/test tunnel adapter, update transaction fixtures. Mark physical Linux system-tunnel E2E as unavailable, not passed.
- [ ] **Step 5: Record device/OS/container/runtime/result for every case without credentials, keys, tunnel configuration, or production configuration.**
- [ ] **Step 6: Re-run any affected automated test after a physical finding is fixed, then repeat the entire relevant platform matrix.**
- [ ] **Step 7: Stop at the final release authorization gate.** A later direct user command is required for push, release workflow execution, panel deployment, production migration, agent update, or capability change.
