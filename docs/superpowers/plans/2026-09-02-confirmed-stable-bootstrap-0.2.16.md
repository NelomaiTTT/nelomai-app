# Confirmed Stable Bootstrap 0.2.16 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a tunnel-compatible 0.2.16 maintenance release that establishes `runtime-v1`, migrates 0.2.15 safely, exposes only latest, and publishes immutable payloads that a later container can embed as stable.

**Architecture:** Work from an isolated maintenance checkout at the exact 0.2.15 release commit so unreleased 0.3.0 hot-standby code cannot enter the package. Split common auth/container state from exact-version runtime state, add crash-safe switch/update journals, place platform tunnel engines behind a small versioned dispatcher contract, and build both normal installers and signed embeddable runtime payloads from the same revision.

**Tech Stack:** Rust 1.88, Tauri 2, Svelte 5, Kotlin/JVM 17, Gradle/Android SDK 36, Windows service, Unix root helper, GitHub Actions, Python release tooling, Ed25519.

**Spec:** `docs/superpowers/specs/2026-09-02-confirmed-stable-runtime-design.md`

## Global Constraints

- Create the maintenance line from commit `632cc4b40872c559a75e5d7104b72bae17ac91c3`, not current `main`.
- The isolation requirement is a factual exception to the earlier inline-main preference: never move or reset the dirty current main checkout to the release commit.
- `0.2.16` keeps 0.2.15 tunnel behavior and does not receive Android hot-standby.
- One runtime is available: latest 0.2.16. Stable metadata may equal latest only to prove packaging; the user toggle remains hidden.
- Preserve one `install_secret`, one panel device, and valid login across upgrade.
- Never create a fresh `install_secret` while legacy or migration state exists.
- Runtime source must not read refresh tokens; only the common auth broker owns refresh and logout.
- No bundled vendor source edits. Existing parent-repository patch application remains unchanged.
- No Developer ID or notarization. macOS uses the existing updater signature plus signed manifest/hashes and reproducible ad-hoc signing if required.
- No push, release publication, production mutation, agent update, or capability enablement without a separate direct command.
- Commits use Russian messages.

---

### Task 1: Create and verify the isolated maintenance worktree

**Files:**
- Create at execution time: sibling worktree directory chosen by `superpowers:using-git-worktrees`
- Read: `.gitmodules`
- Read: `patches/**`
- Read: `.github/workflows/release.yml`

**Interfaces:**
- Produces branch `codex/confirmed-stable-0.2.16` whose merge-base and initial HEAD are exactly `632cc4b40872c559a75e5d7104b72bae17ac91c3`.
- Does not modify the current main checkout or either dirty vendor submodule.

- [ ] **Step 1: Invoke `superpowers:using-git-worktrees` and inspect the repository’s worktree convention.**
- [ ] **Step 2: Verify the release commit and tag read-only.**

```bash
git cat-file -e 632cc4b40872c559a75e5d7104b72bae17ac91c3^{commit}
git show --no-patch --format='%H %s' 632cc4b40872c559a75e5d7104b72bae17ac91c3
git ls-remote --tags origin refs/tags/v0.2.15
```

Expected: the remote peeled release identity resolves to the stated commit.

- [ ] **Step 3: Create the isolated branch/worktree without changing current main.**

```bash
maintenance_worktree=/Users/altzxd/Documents/GitHub/nelomai-app-0.2.16-maintenance
test ! -e "$maintenance_worktree"
git worktree add -b codex/confirmed-stable-0.2.16 "$maintenance_worktree" 632cc4b40872c559a75e5d7104b72bae17ac91c3
```

If the worktree skill finds that this exact path conflicts with an established repository convention, it must stop and report the collision instead of silently choosing a second checkout. The branch name and start commit are fixed.

- [ ] **Step 4: Initialize submodules, apply the repository’s tracked vendor patches through its existing script, and verify that resulting vendor differences match only tracked patch files.** Never clean/reset the user’s main-checkout submodules.
- [ ] **Step 5: Run the 0.2.15 baseline suites before edits.**

```bash
npm ci
npm test
cargo test --workspace
cargo fmt --all --check
git diff --check
```

Expected: a recorded green baseline or a precisely documented pre-existing failure before feature code begins.

### Task 2: Define runtime-v1 contracts and signed container manifest

**Files:**
- Create: `crates/contracts/src/runtime.rs`
- Modify: `crates/contracts/src/lib.rs`
- Create: `crates/contracts/tests/runtime.rs`
- Create: `contracts/fixtures/runtime/container-manifest-v1.json`
- Create: `contracts/fixtures/runtime/stable-artifact-manifest-v1.json`
- Modify: `contracts/python/validate_fixtures.py`

**Interfaces:**
- Produces `RuntimeSlot::{Latest, Stable}`.
- Produces `RuntimeIdentity { slot, runtime_version, runtime_contract_version, container_version, session_generation }`.
- Produces `ContainerManifestV1 { format_version, container_version, release_set_id, minimum_runtime_contract, maximum_runtime_contract, slots }`.
- Produces `RuntimeArtifactManifestV1 { format_version, runtime_version, source_commit, platform, architecture, contract_version, files }`.
- Produces `verify_container_manifest(bytes, signature, public_key, platform, architecture) -> Result<VerifiedContainerManifest, RuntimeManifestError>`.

- [ ] **Step 1: Write RED serialization/validation tests.** Cover exact snake_case values; duplicate slots; missing latest; equal latest/stable treated as stable unavailable; wrong platform/architecture; contract outside inclusive range; path traversal; duplicate paths; malformed 64-character SHA-256; signature failure; and unknown manifest version.
- [ ] **Step 2: Run RED tests.**

```bash
cargo test -p nelomai-contracts --test runtime
python contracts/python/validate_fixtures.py
```

- [ ] **Step 3: Implement the types with fail-closed validation.** File entries use normalized relative UTF-8 paths and byte length:

```rust
pub struct RuntimeFileV1 {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub role: RuntimeFileRole,
}
```

The verifier checks detached Ed25519 signature before trusting paths or hashes, then checks contract/platform/architecture against compile-time container support.

- [ ] **Step 4: Run Rust and Python fixtures GREEN.**
- [ ] **Step 5: Commit.**

```bash
git add crates/contracts contracts/fixtures/runtime contracts/python/validate_fixtures.py
git commit -m "Добавить контракт манифеста runtime-v1"
```

### Task 3: Split shared authentication from versioned runtime state

**Files:**
- Create: `crates/client-storage/src/auth.rs`
- Create: `crates/client-storage/src/runtime_state.rs`
- Create: `crates/client-storage/src/migration.rs`
- Modify: `crates/client-storage/src/lib.rs`
- Create: `crates/client-storage/tests/auth_migration.rs`
- Create: `crates/client-storage/tests/runtime_state.rs`

**Interfaces:**
- Produces `AuthStoreV1 { schema_version: 1, install_secret, access_token, refresh_token, session_generation, logout_state }`.
- Produces `RuntimeStateV1` containing the former connection, lease, pending operation, compatibility, recovery, and applied split-tunnel fields.
- Produces `RuntimePaths::new(root, slot, runtime_version)` with separate preference and operational-state paths.
- Produces `migrate_legacy_auth(legacy_store, auth_store, runtime_store, journal) -> Result<MigrationOutcome, StorageError>`.

- [ ] **Step 1: Write RED tests for every migration phase.** Inject a crash after `legacy_read`, `auth_written`, `runtime_written`, `committed`, and `verified`; resume twice; assert one unchanged install secret, one token set, exact legacy runtime fields, and no call to `StoredAuth::new_install`.
- [ ] **Step 2: Add RED corruption/rollback tests.** Invalid new checksum with intact legacy must return a recoverable migration error; successful bootstrap replaces legacy content with a tombstone containing the same install secret and no tokens/connections/pending work; old deserialization of the tombstone requires login rather than creating a device.
- [ ] **Step 3: Add RED path isolation tests.** Assert exact paths:

```text
runtime/latest/preferences-v1.json
runtime/latest/state/0.2.16/state-v1.json
runtime/stable/0.2.16/preferences-v1.json
runtime/stable/state/0.2.16/state-v1.json
```

Opening another exact runtime version must not deserialize the first version’s operational state.

- [ ] **Step 4: Run RED tests.**

```bash
cargo test -p nelomai-client-storage --test auth_migration
cargo test -p nelomai-client-storage --test runtime_state
```

- [ ] **Step 5: Implement atomic stores and migration journal.** Every record has schema version and SHA-256 of canonical serialized content; writes use same-directory temporary file, flush, atomic rename, and parent-directory sync where supported. Secret material remains in keyring/protected fallback, while nonsecret journals live under app data with mode 0600 on Unix.
- [ ] **Step 6: Keep a compatibility adapter for application code.** `RuntimeStorageSession` may project `AuthStoreV1 + RuntimeStateV1` into the old in-memory shape, but save must split fields back into their owner stores and must never expose the refresh token to later runtime-process IPC.
- [ ] **Step 7: Run focused and full storage tests GREEN.**
- [ ] **Step 8: Commit.**

```bash
git add crates/client-storage/src crates/client-storage/tests
git commit -m "Разделить авторизацию и состояние runtime"
```

### Task 4: Add the common auth broker and generation fence

**Files:**
- Create: `crates/client-container/Cargo.toml`
- Create: `crates/client-container/src/lib.rs`
- Create: `crates/client-container/src/auth_broker.rs`
- Create: `crates/client-container/src/ipc.rs`
- Create: `crates/client-container/tests/auth_broker.rs`
- Modify: `Cargo.toml`
- Modify: `crates/client-application/src/lib.rs`
- Modify: `crates/client-api/src/lib.rs`

**Interfaces:**
- Produces bounded protocol `AuthRequestV1::{State, Login, AccessToken, Logout, BackgroundCredential}` and `AuthResponseV1`.
- Produces `AuthBroker::serve(peer, expected_runtime, verified_executable_hash)`.
- Produces `ClientApi::with_runtime_identity(RuntimeIdentity)` injecting both version headers.
- Runtime application consumes access tokens but has no `SecretStore` access to refresh tokens.

- [ ] **Step 1: Write RED broker tests.** Cover serialized refresh races, a late refresh response after logout, a response from an old session generation, request over 64 KiB, 10-second request timeout, wrong protocol version, wrong slot/runtime, wrong executable hash, and redacted Debug/log output.
- [ ] **Step 2: Write RED API tests.** Login serializes legacy `app_version=container_version` plus all runtime-v1 fields; bootstrap adds `X-Nelomai-App-Version`, `X-Nelomai-Container-Version`, and `X-Nelomai-Runtime-Version` from broker-owned identity; a runtime cannot override these headers.
- [ ] **Step 3: Run RED tests.**

```bash
cargo test -p nelomai-client-container --test auth_broker
cargo test -p nelomai-client-api
cargo test -p nelomai-client-application
```

- [ ] **Step 4: Implement the broker state machine.** Login increments generation only when replacing a session; logout first marks `LogoutPending`, rejects token issuance, invokes the supplied cleanup barrier, calls panel logout, clears tokens, increments generation, and marks `LoggedOut`. Compare generation immediately before persisting every asynchronous result.
- [ ] **Step 5: Implement private transport.** Desktop receives an inherited socketpair/handle rather than a globally named endpoint; Android exposes the same messages through an explicit non-exported Binder used in Task 8. Never put tokens or handles in argv text, environment, diagnostics, or logs.
- [ ] **Step 6: Run focused tests GREEN.**
- [ ] **Step 7: Commit.**

```bash
git add Cargo.toml crates/client-container crates/client-api crates/client-application
git commit -m "Вынести общую авторизацию в контейнер"
```

### Task 5: Implement slot selection and the crash-safe switch coordinator

**Files:**
- Create: `crates/client-container/src/selection.rs`
- Create: `crates/client-container/src/switch.rs`
- Create: `crates/client-container/src/cleanup.rs`
- Create: `crates/client-container/tests/selection.rs`
- Create: `crates/client-container/tests/switch.rs`
- Modify: `crates/client-api/src/lib.rs`

**Interfaces:**
- Produces `SlotSelectionV1 { container_version, selected_slot, pending_slot }`.
- Produces switch phases `Requested`, `CleanupHandedOff`, `RuntimeStopping`, `LocalStopped`, `ServerReconciling`, `Complete`.
- Produces `CleanupEnvelopeV1` containing IDs/fingerprints/contracts/engine role/background reference but no tunnel configuration.
- Produces `SwitchCoordinator::request(target)`, `recover()`, `before_tunnel_start()`, and `cancel_pending()`.

- [ ] **Step 1: Write RED state-machine tests.** For each phase, crash and reconstruct; assert no new tunnel start in the source runtime, bounded graceful stop, one forced-kill request after timeout, resumable server reconciliation, and target UI availability while panel is unavailable.
- [ ] **Step 2: Add RED selection tests.** Container-version mismatch selects latest and removes pending; corrupted/incompatible stable selects latest with an error; changing back to active slot waits for cleanup completion then cancels pending; a runtime crash alone leaves selection unchanged.
- [ ] **Step 3: Add RED cleanup-envelope tests.** Round-trip known lease/redundant session/operation/fingerprint/contract/engine/background reference; reject serialized full tunnel configuration, private keys, tokens, or install secret by both typed API and content scan.
- [ ] **Step 4: Run RED tests.**

```bash
cargo test -p nelomai-client-container --test selection
cargo test -p nelomai-client-container --test switch
```

- [ ] **Step 5: Implement atomic journals and reconciliation client.** `before_tunnel_start()` calls the panel endpoint with the journal’s stable operation ID, accepts only `clean`, maps panel/network failure to a retryable state with capped exponential delays 1, 2, 4, 8, 16, 30 seconds, and never leaves an unbounded busy flag.
- [ ] **Step 6: Configure the 0.2.16 manifest with latest only.** The public slot view returns `stable_available=false`, so the UI toggle is hidden while the coordinator is fully testable with fixture manifests.
- [ ] **Step 7: Run focused tests GREEN.**
- [ ] **Step 8: Commit.**

```bash
git add crates/client-container crates/client-api
git commit -m "Добавить журнал переключения runtime"
```

### Task 6: Put update installation behind the same shutdown barrier

**Files:**
- Create: `crates/client-container/src/update.rs`
- Create: `crates/client-container/tests/update.rs`
- Modify: `crates/client-updater/src/lib.rs`
- Modify: `src-tauri/src/updates.rs`
- Modify: `src-tauri/src/platform/updater.rs`
- Modify: `src-tauri/src/platform/android_updater.rs`
- Test: `crates/client-updater/tests/coordinator.rs`

**Interfaces:**
- Produces `UpdateJournalV1 { source_container, source_runtime, target_container, previous_slot, phase }`.
- Produces `UpdateBarrier::prepare(target_version)`, `installer_opened()`, `installer_failed()`, and `recover(installed_container_version)`.
- Updater backend may run only after `prepare()` reports `LocalStopped`.

- [ ] **Step 1: Add RED tests for active/stopped tunnel, graceful-stop timeout, Android installer-opened, desktop install success, installer error, process death after each journal phase, and new-container first launch.**
- [ ] **Step 2: Run RED tests.**
- [ ] **Step 3: Wrap both update backends.** Before download/install transition that can replace the package, block new starts, capture cleanup envelope, stop local engine, persist server cleanup, then invoke the existing verified installer. On installer failure in the old container, restore previous selected slot and permit a fresh tunnel start only after journal cancellation.
- [ ] **Step 4: On a different installed container version, select latest before runtime launch and require reconciliation before its first tunnel start.** A partially updated privileged dispatcher does not advance the installed version marker.
- [ ] **Step 5: Run focused updater/container tests GREEN.**
- [ ] **Step 6: Commit.**

```bash
git add crates/client-container crates/client-updater src-tauri/src/updates.rs src-tauri/src/platform/updater.rs src-tauri/src/platform/android_updater.rs crates/client-updater/tests
git commit -m "Защитить установку обновления остановкой туннеля"
```

### Task 7: Version the Windows and Unix privileged engine boundary

**Files:**
- Create: `crates/contracts/src/dispatcher.rs`
- Modify: `crates/contracts/src/lib.rs`
- Modify: `crates/windows-service/src/lib.rs`
- Modify: `crates/windows-service/src/windows/service.rs`
- Modify: `crates/windows-service/src/windows/ipc.rs`
- Modify: `crates/windows-service/src/windows/install.rs`
- Modify: `crates/unix-service/src/lib.rs`
- Modify: `crates/unix-service/src/socket.rs`
- Modify: `crates/unix-service/src/process.rs`
- Modify: `crates/unix-service/install/install-linux.sh`
- Modify: `crates/unix-service/install/install-macos.sh`
- Modify: `scripts/windows/prepare-runtime.ps1`
- Modify: `scripts/unix/prepare-runtime.sh`
- Test: `crates/windows-service/tests/protocol.rs`
- Test: `crates/windows-service/tests/install.rs`
- Test: `crates/unix-service/tests/socket.rs`
- Test: `crates/unix-service/tests/helper.rs`

**Interfaces:**
- Produces dispatcher protocol `start`, `stop`, `status`, `cleanup`, `version` only.
- Produces root-owned manifest layout `dispatcher/1`, `engines/latest/0.2.16`, `container-manifest.json`.
- Produces an atomic installer that changes manifest pointer only after signature/hash verification.

- [ ] **Step 1: Add RED protocol tests.** Reject arbitrary executable paths, unknown methods, oversized messages, contract mismatch, slot/runtime/hash mismatch, and concurrent mutations; prove status/version are bounded read operations.
- [ ] **Step 2: Add RED installer rollback tests.** Simulate copy failure, hash failure, signature failure, pointer-swap failure, and engine still running; assert the old pointer/files remain usable and the old engine is not deleted.
- [ ] **Step 3: Preserve platform peer checks in RED tests.** Windows accepts only common broker SID plus exact installed path and manifest identity; Unix accepts one authenticated unprivileged common broker peer and does not allow the runtime child to connect directly.
- [ ] **Step 4: Run RED service suites.**
- [ ] **Step 5: Implement versioned layout and serialized dispatcher.** Dispatcher resolves executable from its root-owned manifest, never from request paths. Installer stages to a sibling temporary directory, verifies every manifest entry, atomically switches the pointer, and deletes old engines only after confirmed stop.
- [ ] **Step 6: Run focused service suites GREEN and platform compilation checks.**
- [ ] **Step 7: Commit.**

```bash
git add crates/contracts crates/windows-service crates/unix-service scripts/windows/prepare-runtime.ps1 scripts/unix/prepare-runtime.sh
git commit -m "Разделить системный dispatcher и versioned engine"
```

### Task 8: Add the Android common dispatcher and stable-slot build variant

**Files:**
- Create: `src-tauri/gen/android/app/src/main/java/ru/nelomai/client/RuntimeSelectionStore.kt`
- Create: `src-tauri/gen/android/app/src/main/java/ru/nelomai/client/RuntimeAuthBrokerService.kt`
- Create: `src-tauri/gen/android/app/src/main/java/ru/nelomai/client/RuntimeVpnDispatcherService.kt`
- Modify: `src-tauri/gen/android/app/src/main/java/ru/nelomai/client/MainActivity.kt`
- Modify: `src-tauri/gen/android/app/src/main/java/ru/nelomai/client/NelomaiQuickTileService.kt`
- Modify: `src-tauri/gen/android/app/src/main/AndroidManifest.xml`
- Modify: `src-tauri/gen/android/app/build.gradle.kts`
- Modify: `src-tauri/Cargo.toml`
- Modify: `src-tauri/gen/android/app/src/main/java/io/crates/keyring/Keyring.kt`
- Create: `src-tauri/gen/android/app/src/test/java/ru/nelomai/client/RuntimeDispatcherTest.kt`
- Create: `scripts/android/build-runtime-artifact.py`
- Create: `scripts/android/check-runtime-collisions.py`

**Interfaces:**
- Common package remains `ru.nelomai.client` with one VPN permission/service.
- Stable artifact namespace is `ru.nelomai.runtime.stable`, resource prefix `stable_runtime_`, native library `nelomai_runtime_stable`, ABI `nelomai_runtime_v1`.
- Latest uses its existing namespace/library through an explicit latest adapter; dispatcher is the sole exported system VPN component.

- [ ] **Step 1: Add RED JVM tests.** Main activity dispatches only the verified selected slot; Binder is explicit/non-exported and checks slot/runtime/generation; tile refuses start during pending switch; VPN process stops after slot change; only one manifest VPN service owns permission.
- [ ] **Step 2: Add RED artifact/collision fixtures.** Detect duplicate class names, Android resources, manifest components, JNI exports, ELF sonames, and native library names. Verify path traversal and missing license files fail the build.
- [ ] **Step 3: Run RED tests.**

```bash
./src-tauri/gen/android/gradlew -p src-tauri/gen/android :app:testDebugUnitTest
python -m unittest scripts.tests.test_android_runtime_artifact scripts.tests.test_android_runtime_collisions
```

- [ ] **Step 4: Implement one common dispatcher.** It reads verified common selection, starts only the selected `nelomai_runtime_v1` engine, owns foreground notification/VPN interface lifecycle, and kills the `:vpn` process after stop so two native engines are never loaded into one process.
- [ ] **Step 5: Implement the stable build variant.** Gradle/Rust build flags change namespace/resource prefix/library name at compile time from the same source revision. Replace the hard-coded `System.loadLibrary("nelomai_app_lib")` route with a broker-controlled mapping that never accepts a string from runtime UI.
- [ ] **Step 6: Build the 0.2.16 artifact archive.** It contains AAR/DEX, WebView assets, `.so`, tunnel engine, licenses, and signed manifest; it does not contain a nested APK.
- [ ] **Step 7: Run JVM, artifact, Android Rust target, and APK manifest tests GREEN.**
- [ ] **Step 8: Commit.**

```bash
git add src-tauri/gen/android src-tauri/Cargo.toml scripts/android scripts/tests
git commit -m "Подготовить Android runtime для встраивания"
```

### Task 9: Launch the desktop runtime through the common container

**Files:**
- Create: `src-tauri/src/container.rs`
- Create: `src-tauri/src/runtime.rs`
- Create: `src-tauri/src/bin/nelomai-runtime.rs`
- Modify: `src-tauri/src/main.rs`
- Modify: `src-tauri/src/lib.rs`
- Modify: `src-tauri/tauri.conf.json`
- Modify: `src-tauri/bundle.linux.conf.json`
- Modify: `src-tauri/bundle.macos.conf.json`
- Modify: `src-tauri/bundle.windows.conf.json`
- Create: `src-tauri/tests/container_runtime.rs`
- Create: `scripts/package-runtime-artifact.py`

**Interfaces:**
- Installed main executable is the common container/broker.
- Versioned child is `engines/latest/0.2.16/nelomai-runtime[.exe]` and receives only an inherited private IPC handle plus nonsecret startup identity.
- Stable payload archive contains the runtime executable, WebView assets/resources, versioned tunnel engine, licenses, and manifest.

- [ ] **Step 1: Add RED launcher tests.** Verify selected manifest hash before spawn; refuse wrong owner/permissions/path/hash/contract/platform; pass no secrets in argv/environment; close inheritable handle in unrelated children; terminate runtime then helper during switch; distinguish closing to tray from full restart.
- [ ] **Step 2: Add RED single-runtime behavior tests.** With only latest in 0.2.16, startup works, stable unavailable is reported, and product UI/tunnel behavior stays in the versioned child.
- [ ] **Step 3: Run RED tests.**

```bash
cargo test -p nelomai-app --test container_runtime
```

- [ ] **Step 4: Refactor Tauri entry points.** Move the existing product setup/invoke handlers into `runtime::run(RuntimeBootstrap)`; `main.rs` runs the common container, verifies the manifest, creates private broker/dispatcher channels, and spawns `nelomai-runtime`. The common container owns updater, slot journals, tray/autostart routing, and process lifecycle only.
- [ ] **Step 5: Package platform-specific runtime archives.** On macOS, preserve the current non-Developer-ID model and apply deterministic ad-hoc signing after the final bundle layout is assembled; record every nested executable hash after signing.
- [ ] **Step 6: Run launcher tests and desktop package smoke builds GREEN on available host/CI.**
- [ ] **Step 7: Commit.**

```bash
git add src-tauri scripts/package-runtime-artifact.py
git commit -m "Запускать desktop runtime через общий контейнер"
```

### Task 10: Add the hidden toggle contract, restart notice, and diagnostics

**Files:**
- Modify: `src/lib/native-client.ts`
- Modify: `src/lib/app-model.ts`
- Modify: `src/routes/+page.svelte`
- Create: `src/lib/RuntimeSelector.svelte`
- Create: `src/lib/RuntimeSelector.test.ts`
- Modify: `src-tauri/src/commands.rs`
- Modify: `src-tauri/src/diagnostics.rs`
- Test: `src/lib/native-client.test.ts`
- Test: `src/lib/app-model.test.ts`

**Interfaces:**
- Produces command/view `runtime_status` with container, active/pending slots, latest/stable versions, contract, manifest verification, switch ID/phase.
- Produces command `runtime_select({ useStable: boolean })`.
- Produces actions “Позже” and “Перезапустить сейчас”; 0.2.16 reports `stableAvailable=false` and renders no toggle.

- [ ] **Step 1: Add RED frontend/native tests.** Hidden when stable is absent/equal latest; visible metadata when distinct; toggle requests switch once; pending state blocks tunnel start and tile route; later leaves UI open; restart-now requests a full exit/relaunch rather than closing to tray.
- [ ] **Step 2: Add RED diagnostic redaction tests.** Reports include container/active/pending/latest/stable/contract/switch phase/manifest result/action source/engine role and exclude all secret/tunnel configuration fields.
- [ ] **Step 3: Run RED tests.**
- [ ] **Step 4: Implement the component and Tauri commands against `client-container`; do not duplicate selection state in Svelte.**
- [ ] **Step 5: Run frontend, command, and diagnostic tests GREEN.**
- [ ] **Step 6: Commit.**

```bash
git add src src-tauri/src/commands.rs src-tauri/src/diagnostics.rs
git commit -m "Добавить интерфейс выбора runtime"
```

### Task 11: Extend release workflow with immutable runtime artifacts

**Files:**
- Modify: `.github/workflows/release.yml`
- Create: `scripts/build-runtime-manifest.py`
- Create: `scripts/verify-runtime-artifact.py`
- Create: `scripts/tests/test_runtime_artifact.py`
- Modify: `scripts/release-workflow-check.py`
- Modify: `docs/application-updates.md`
- Create: `docs/runtime-artifacts.md`

**Interfaces:**
- Every build job emits the normal installer plus `nelomai-runtime-0.2.16-<platform>-<arch>.zip`, `.manifest.json`, and `.manifest.sig`.
- Manifest signing reuses the project’s release Ed25519 trust root but a domain-separated message prefix `nelomai-runtime-manifest-v1\0`.

- [ ] **Step 1: Add RED workflow/static tests.** Require runtime artifacts for linux-x86_64, windows-x86_64, macos-aarch64, android-aarch64; reject unsigned/missing manifests, inconsistent source commit/version/platform/architecture/contract, mutable filename reuse, and macOS notarization/Developer-ID requirements.
- [ ] **Step 2: Run RED tests.**

```bash
python -m unittest scripts.tests.test_runtime_artifact
python scripts/release-workflow-check.py
```

- [ ] **Step 3: Build payload, canonical manifest, detached signature, and size report in each platform job.** Runtime manifest records exact source commit and every file hash. Upload retention for pre-release job artifacts remains short; published release assets become the immutable source for later containers.
- [ ] **Step 4: Re-extract each payload before upload and verify bytes/hash/signature.** Android runs the collision checker; desktop checks owner/layout metadata and executable identities; macOS verifies ad-hoc signatures without claiming notarization.
- [ ] **Step 5: Document release inputs and provenance.** State that workflow execution/publication is outside this task until directly authorized.
- [ ] **Step 6: Run workflow tests GREEN.**
- [ ] **Step 7: Commit.**

```bash
git add .github/workflows/release.yml scripts docs/application-updates.md docs/runtime-artifacts.md
git commit -m "Выпускать подписанные артефакты runtime"
```

### Task 12: Set 0.2.16 metadata and run the acceptance gate

**Files:**
- Modify: version files changed by `scripts/set-release-version.py`
- Modify: `CHANGELOG.md`
- Create: `docs/reviews/2026-09-02-confirmed-stable-bootstrap-0.2.16.md`

**Interfaces:**
- Consumes Tasks 1–11 and the already deployed panel contract from the separate panel plan.
- Produces a reviewed, unpushed maintenance branch ready for an explicitly authorized release.

- [ ] **Step 1: Set version 0.2.16 using the repository script and add a Russian changelog entry.** The entry states compatibility/bootstrap work and no Android hot-standby or user-visible stable switch yet.

```bash
python scripts/set-release-version.py 0.2.16
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

- [ ] **Step 3: Build unsigned/local verification packages and runtime artifacts for the host-supported targets.** Verify manifest signatures with test keys only, inspect package contents, and record unavailable cross-platform physical checks rather than treating them as passed.
- [ ] **Step 4: Perform three review passes and record findings/fixes.** Pass 1: auth/migration/generation. Pass 2: tunnel shutdown/dispatcher/update barrier. Pass 3: artifact integrity/platform packaging/secret scan. Each finding is fixed with a new RED test before code changes.
- [ ] **Step 5: Run final status and secret/vendor checks.**

```bash
git status --short --branch
git diff --check
git diff --submodule=log 632cc4b40872c559a75e5d7104b72bae17ac91c3...HEAD
rg -n "BEGIN (RSA|OPENSSH|EC) PRIVATE KEY|ANDROID_KEYSTORE_PASSWORD|TAURI_SIGNING_PRIVATE_KEY=" --glob '!package-lock.json' .
```

Expected: no secrets; no untracked vendor-source changes; all source modifications are intentional maintenance commits.

- [ ] **Step 6: Commit release preparation and review evidence.**

```bash
git add CHANGELOG.md docs/reviews/2026-09-02-confirmed-stable-bootstrap-0.2.16.md package.json package-lock.json src-tauri/Cargo.toml src-tauri/tauri.conf.json
git commit -m "Подготовить версию 0.2.16"
```

- [ ] **Step 7: Stop before push/release.** Report branch, HEAD, complete test evidence, panel deployment prerequisite status, and physical E2E still required. Do not push or start the release workflow.
