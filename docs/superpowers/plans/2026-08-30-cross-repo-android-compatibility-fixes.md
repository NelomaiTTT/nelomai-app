# Cross-Repo Android Compatibility Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every genuinely new Android connection intent refresh and persist the panel capability before validation, and align Android/Rust recovery classification with the panel's real 5xx/stop errors.

**Architecture:** Keep exact replay and cleanup inside the existing durable coordinator unchanged. Its existing `begin()` boundary invokes a new refresh-and-validate helper only after proving work is genuinely new; the helper uses the active Device credential, conservative store merge, and the existing service executor. Normalize HTTP errors at the Android transport boundary, then add `connection_stop_failed` to the shared policy fixture and both classifiers so cleanup retries the same stored stop operation.

**Tech Stack:** Kotlin/JVM Android service and unit tests, Rust workspace contract/core tests, JSON shared fixture.

**Spec:** `docs/superpowers/specs/2026-08-28-automatic-connection-intent-recovery-design.md`

## Global Constraints

- Existing exact replay, reconciliation, cancellation, and cleanup are never capability-gated.
- Capability revisions merge monotonically; equal revisions use `false` and the earlier expiry.
- Device authorization is required for `/api/client/v1/background/capabilities`.
- Transport and HTTP 5xx failures stay retryable and must not persist a false downgrade.
- Missing, disabled, expired, `404`, and stable unsupported capability responses deny new work.
- Use the existing service executor/coordinator; do not add another scheduler.
- Do not edit the panel worktree, vendor trees, production, workflows, commits, pushes, deploys, or releases.

---

### Task 1: Refresh capability at the genuinely-new-intent boundary

**Files:**
- Modify: `plugins/tunnel-android/android/src/main/java/NelomaiVpnService.kt`
- Test: `plugins/tunnel-android/android/src/test/java/NelomaiVpnServiceTest.kt`

**Interfaces:**
- Consumes: `AndroidConnectionIntentCoordinator.begin(template, validateNewIntent)`, `BackgroundConnectionClient.capabilities(credential)`, `BackgroundCredentialStore.updateCapability(expectedRevision, capability)`.
- Produces: `refreshAndValidateNewIntentCapability(store, template, nowUnix, fetch): Unit` used by the service's existing `validateNewIntentCapability` callback.

- [x] **Step 1: Write the failing production-boundary test**

```kotlin
val accepted = coordinator.begin(template()) { candidate ->
    refreshAndValidateNewIntentCapability(credentials, candidate, nowUnix = 100) {
        fetches += 1
        BackgroundCapabilitySnapshot(2, true, 500)
    }
}
assertTrue(accepted is AndroidCoordinatorResult.Accepted)
assertEquals(2L, credentials.read().credentialSuccess().capability?.revision)
coordinator.begin(template()) { throw AssertionError("exact replay must not refresh") }
```

Add independent cases proving an HTTP/transport exception leaves the old snapshot and no new lease transaction, while disabled/expired/unsupported refresh persists the conservative result and rejects new work.

- [x] **Step 2: Run the focused test and confirm RED**

Run:

```bash
src-tauri/gen/android/gradlew -p plugins/tunnel-android/android :testDebugUnitTest --tests 'ru.nelomai.tunnel.NelomaiVpnServiceTest.genuinelyNewIntentRefreshesCapabilityBeforePersistenceWhileExactReplayBypassesRefresh'
```

Expected: compile failure because `refreshAndValidateNewIntentCapability` does not exist, or behavior failure because only credential rotation refreshes capability.

- [x] **Step 3: Implement the minimal refresh boundary**

```kotlin
internal fun refreshAndValidateNewIntentCapability(
    store: BackgroundCredentialStore,
    template: AndroidIntentTemplate,
    nowUnix: Long,
    fetch: (BackgroundCredential) -> BackgroundCapabilitySnapshot,
) {
    val before = store.read().credentialOrThrow()
    val credential = before.active ?: throw BackgroundConnectionException("invalid_background_token")
    val refreshed = refreshBackgroundCapability(before.capability, nowUnix) { fetch(credential) }
    val after = store.updateCapability(before.revision, refreshed).credentialOrThrow()
    val capability = after.capability
    if (credential.deviceId != template.deviceId || capability == null ||
        !capability.enabled || capability.expiresAtUnix <= nowUnix
    ) throw BackgroundConnectionException("background_credential_capability_unavailable")
}
```

Wire the service's existing validator to this helper with `BackgroundConnectionClient::capabilities`; do not change coordinator replay/cleanup ordering.

- [x] **Step 4: Run the focused test and confirm GREEN**

Run the command from Step 2 and the complete `NelomaiVpnServiceTest` class.

---

### Task 2: Normalize panel errors and align exact-stop retry policy

**Files:**
- Modify: `plugins/tunnel-android/android/src/main/java/BackgroundConnectionClient.kt`
- Modify: `plugins/tunnel-android/android/src/main/java/ConnectionIntentErrorPolicy.kt`
- Modify: `contracts/fixtures/valid/connection-intent-error-policy.json`
- Modify: `crates/client-core/src/connection_intent.rs`
- Test: `plugins/tunnel-android/android/src/test/java/BackgroundConnectionClientTest.kt`
- Test: `plugins/tunnel-android/android/src/test/java/NelomaiVpnServiceTest.kt`
- Test: existing Kotlin/Rust fixture parity tests.

**Interfaces:**
- Consumes: `backgroundPanelErrorCode(endpoint, status, panelCode)` and the common policy fixture.
- Produces: unstructured 5xx → `http_5xx`; structured 5xx → exact panel code; `connection_stop_failed` → `retry_same_operation` in Kotlin and Rust.

- [x] **Step 1: Write failing transport/policy/cleanup tests**

```kotlin
assertEquals("http_5xx", backgroundPanelErrorCode("background/connections/stop", 503, null))
assertEquals("connection_stop_failed", backgroundPanelErrorCode("background/connections/stop", 503, "connection_stop_failed"))
assertEquals(ConnectionIntentDecision.RETRY_SAME_OPERATION, policy.classify("connection_stop_failed"))
```

Add a coordinator cleanup test whose first panel stop throws `connection_stop_failed` with `Retry-After`, reconstructs the coordinator, and proves the second stop uses the identical stored operation ID before cleanup completes.

- [x] **Step 2: Run focused tests and confirm RED**

```bash
src-tauri/gen/android/gradlew -p plugins/tunnel-android/android :testDebugUnitTest --tests 'ru.nelomai.tunnel.BackgroundConnectionClientTest' --tests 'ru.nelomai.tunnel.ConnectionIntentErrorPolicyTest' --tests 'ru.nelomai.tunnel.NelomaiVpnServiceTest.cleanup503RetriesTheExactStoredStopOperation'
cargo test -p nelomai-client-core connection_intent_classifier_matches_the_shared_policy_fixture -- --nocapture
```

Expected: unstructured 503 maps to `background_panel_error`, `connection_stop_failed` classifies terminal, and cleanup becomes terminal instead of replaying the stop ID.

- [x] **Step 3: Implement minimal normalization and parity**

Make `backgroundPanelErrorCode` prefer endpoint-specific 404 handling, then a nonblank structured panel code, then `http_5xx` for status 500–599, and finally `background_panel_error`. Add one `connection_stop_failed` retry-same entry to the shared fixture and the Kotlin/Rust retry-same sets. Leave `BackgroundConnectionException.retryAfterHeader` propagation unchanged.

- [x] **Step 4: Run focused tests and confirm GREEN**

Run the commands from Step 2.

- [x] **Step 5: Run full verification and update the task report**

```bash
src-tauri/gen/android/gradlew -p plugins/tunnel-android/android :testDebugUnitTest
cargo test -p tauri-plugin-tunnel-android
cargo test -p nelomai-contracts
cargo test -p nelomai-client-core connection_intent -- --nocapture
cargo test -p nelomai-app android_ -- --nocapture
cargo check -p nelomai-app --target aarch64-linux-android
cargo fmt --all -- --check
git diff --check
```

Append RED/GREEN evidence, files, exact test counts, and the read-only panel compatibility evidence to `.superpowers/sdd/2026-08-28-automatic-connection-intent-recovery/task-12-report.md`. Do not commit.

## Self-Review

- Spec coverage: Task 1 covers fresh Device-auth capability refresh, conservative persistence, deny/failure behavior, and exact replay bypass. Task 2 covers 5xx normalization, structured codes, Retry-After preservation, classifier parity, and exact stop replay.
- Placeholder scan: no deferred implementation or unspecified test step remains.
- Type consistency: the helper consumes the existing credential store/snapshot/exception types; policy names match the shared fixture's existing `retry_same_operation` spelling.
