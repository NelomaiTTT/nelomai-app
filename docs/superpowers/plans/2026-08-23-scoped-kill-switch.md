# Scoped Kill Switch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Реализовать локальный scoped kill switch для Android, Windows, Linux и macOS, который блокирует только защищаемый трафик после успешного запуска туннеля и сохраняет явные split-исключения.

**Architecture:** Общая state machine `off/armed/blocked` живёт в платформенно-независимом tunnel-контракте, но фактическое enforcement-состояние принадлежит Android `VpnService` или привилегированному desktop helper. Первоначальный Start считается успешным только после установки защиты; внутренние reconnect-операции сохраняют её, а пользовательский Stop снимает.

**Tech Stack:** Rust 1.88, Tauri 2, Svelte/TypeScript, Kotlin/Android `VpnService`, Windows Filtering Platform, Linux nftables, macOS PF, serde JSON IPC, Vitest, Cargo tests, Kotlin/JUnit.

**Spec:** `docs/superpowers/specs/2026-08-23-scoped-kill-switch-design.md`

## Global Constraints

- Настройка локальна для устройства, общая для Tic/Tak и Stray и по умолчанию равна `false`.
- Runtime-защита включается только после успешного поднятия туннеля.
- Ошибка первоначального Start оставляет обычный интернет доступным.
- Явный Stop, logout и подготовка обновления снимают защиту.
- Internal reconnect, смена сети/порта/сервера и смена Tic/Tak ↔ Stray сохраняют защиту.
- Явные application/address/domain/local split-исключения имеют приоритет над блокировкой.
- Служебный трафик Nelomai не блокируется.
- Перезагрузка ОС начинает с туннелем и runtime kill switch в состоянии `off`.
- Не менять глобальные firewall defaults и не удалять объекты, не принадлежащие Nelomai.
- Не записывать в диагностику IP панели/серверов, package ID, конфигурацию или credentials.
- Все новые мутации проходят через существующие serialized operation gates.
- Каждый этап выполняется через RED → GREEN → полный регрессионный прогон → русскоязычный commit.

---

## File map

### Shared core

- `crates/client-tunnel/src/lib.rs` — общие состояния, stop intent, options и trait API.
- `crates/client-core/src/lib.rs` — переходы Start/Stop/Reconnect/Failure и bounded recovery.
- `crates/client-core/tests/runtime.rs` — сквозные state-machine тесты.
- `src-tauri/src/preferences.rs` — сохранённая локальная настройка.
- `src-tauri/src/commands.rs` — Tauri-команды и состояние для UI.
- `src/lib/app-model.ts`, `src/routes/+page.svelte` — клиентская модель и элементы UI.

### Android

- `plugins/tunnel-android/src/models.rs` — Rust/Kotlin wire-модель.
- `plugins/tunnel-android/src/lib.rs` — реализация `TunnelController`.
- `plugins/tunnel-android/android/src/main/java/KillSwitchController.kt` — новый владелец Android state machine и blackhole descriptor.
- `plugins/tunnel-android/android/src/main/java/TunnelPlugin.kt` — сериализация start/reconnect/stop и backend handover.
- `plugins/tunnel-android/android/src/main/java/NelomaiVpnService.kt` — service IPC, notification actions и lifecycle.
- `plugins/tunnel-android/android/src/main/java/TunnelServiceProtocol.kt` — typed service messages.
- `plugins/tunnel-android/android/src/main/java/AndroidSplitTunnel.kt` — повторное использование эффективных app/route исключений.
- `plugins/tunnel-android/android/src/test/java/KillSwitchControllerTest.kt` — чистые state-machine тесты.

### Windows

- `crates/windows-service/src/lib.rs` — protocol v9, state/status и typed commands.
- `crates/windows-service/src/windows/killswitch.rs` — новый WFP provider/sublayer/filter manager.
- `crates/windows-service/src/windows/backend.rs` — atomic start/arm, reconnect и stop/disarm.
- `crates/windows-service/src/windows/install.rs` — защищённые paths/state и uninstall cleanup.
- `crates/windows-service/tests/protocol.rs`, `tests/service.rs` — protocol и backend тесты.

### Unix

- `crates/unix-service/src/lib.rs` — protocol v6, state/status и typed commands.
- `crates/unix-service/src/killswitch.rs` — общая state persistence, ownership и boot identity.
- `crates/unix-service/src/killswitch/linux.rs` — nftables renderer/executor.
- `crates/unix-service/src/killswitch/macos.rs` — PF anchor/token renderer/executor.
- `crates/unix-service/src/backend/linux.rs`, `backend/macos.rs` — lifecycle integration.
- `crates/unix-service/tests/helper.rs` — protocol, reconciliation и rollback.

### Diagnostics and documentation

- `src-tauri/src/diagnostics.rs`, `src-tauri/src/automatic_diagnostics.rs` — transition events and report triggers.
- `docs/split-tunnel.md`, `docs/windows-tunnel-service.md`, `docs/unix-tunnel-helper.md` — operational contract and recovery commands.
- `.github/workflows/checks.yml`, `.github/workflows/release.yml` — platform compile/test gates.

---

### Task 1: Shared kill-switch contracts

**Files:**
- Modify: `crates/client-tunnel/src/lib.rs`
- Test: `crates/client-tunnel/src/lib.rs`

**Interfaces:**
- Produces: `KillSwitchState`, `TunnelStopIntent`, `TunnelRuntimeStatus`.
- Produces: `TunnelOptions.kill_switch_enabled` and `DesktopTunnelOptions.kill_switch_enabled`.
- Changes: `TunnelController::stop(intent)`, `TunnelController::runtime_status()`, `TunnelController::set_kill_switch_enabled(enabled)`.

- [ ] **Step 1: Write failing contract tests**

Add tests asserting canonical serde names and safe defaults:

```rust
#[test]
fn kill_switch_contract_defaults_fail_open_before_first_start() {
    assert_eq!(KillSwitchState::default(), KillSwitchState::Off);
    assert!(!TunnelOptions::default().kill_switch_enabled);
    assert!(!DesktopTunnelOptions::default().kill_switch_enabled);
}

#[test]
fn desktop_options_copy_kill_switch_without_a_split_policy() {
    let options = TunnelOptions {
        kill_switch_enabled: true,
        ..TunnelOptions::default()
    };
    assert!(DesktopTunnelOptions::from_tunnel_options(&options).kill_switch_enabled);
}
```

- [ ] **Step 2: Run the focused tests and confirm RED**

Run: `cargo test -p nelomai-client-tunnel kill_switch -- --nocapture`

Expected: compilation fails because the new fields/types do not exist.

- [ ] **Step 3: Add the shared types and trait methods**

Use these public shapes:

```rust
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchState { #[default] Off, Armed, Blocked }

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelStopIntent { #[default] User, Reconnect }

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TunnelRuntimeStatus {
    pub tunnel: TunnelStatus,
    pub kill_switch: KillSwitchState,
}
```

Change the trait without silent defaults for stop intent:

```rust
async fn stop(&self, intent: TunnelStopIntent) -> Result<(), TunnelError>;
async fn runtime_status(&self) -> Result<TunnelRuntimeStatus, TunnelError>;
async fn set_kill_switch_enabled(&self, enabled: bool) -> Result<KillSwitchState, TunnelError>;
```

Keep `status()` as a compatibility wrapper returning
`runtime_status().await?.tunnel` so existing read-only callers migrate
incrementally. Update `DesktopTunnelOptions::from_tunnel_options` so the kill
switch field is copied even when `policy_hash` is absent.

- [ ] **Step 4: Run focused and workspace tests**

Run:

```bash
cargo test -p nelomai-client-tunnel
cargo test --workspace
```

Expected: all tests pass after downstream mocks are updated with explicit
`TunnelStopIntent::User` or `Reconnect`.

- [ ] **Step 5: Commit shared contracts**

```bash
git add crates/client-tunnel crates/client-core plugins/tunnel-android crates/windows-service crates/unix-service
git commit -m "Добавить контракт состояния kill switch"
```

---

### Task 2: Persisted preference and UI model

**Files:**
- Modify: `src-tauri/src/preferences.rs`
- Modify: `src-tauri/src/commands.rs`
- Modify: `src-tauri/src/lib.rs`
- Modify: `src/lib/native-client.ts`
- Modify: `src/lib/app-model.ts`
- Modify: `src/lib/app-model.test.ts`
- Modify: `src/routes/+page.svelte`

**Interfaces:**
- Consumes: `KillSwitchState` from Task 1.
- Produces: `AppPreferences.kill_switch_enabled: bool`.
- Produces: Tauri command `app_set_kill_switch_enabled(enabled: bool)`.
- Produces: UI fields `killSwitchEnabled` and `killSwitchState`.

- [ ] **Step 1: Add failing Rust and TypeScript preference tests**

Rust assertions:

```rust
assert!(!AppPreferences::default().kill_switch_enabled);
store.set_kill_switch_enabled(true).unwrap();
assert!(AppPreferenceStore::new(&path).get().kill_switch_enabled);
```

TypeScript assertions:

```ts
expect(normalizePreferences({} as NativeAppPreferences).killSwitchEnabled).toBe(false);
expect(killSwitchMessage("blocked")).toContain("Интернет заблокирован");
```

- [ ] **Step 2: Confirm RED**

Run:

```bash
cargo test -p nelomai-app preferences::tests::kill_switch
npm run test:unit -- src/lib/app-model.test.ts
```

Expected: missing preference and model fields.

- [ ] **Step 3: Implement preference, command and UI switch**

Add `kill_switch_enabled` with `#[serde(default)]` so old preference files load
as disabled. `app_set_kill_switch_enabled` must:

1. acquire the existing connection mutation gate;
2. call `TunnelController::set_kill_switch_enabled` when a tunnel is running or
   blocked;
3. persist the preference only after platform success;
4. persist immediately without platform mutation while disconnected;
5. return the confirmed runtime state.

Render one device-wide switch in the connection settings. Disable it only
while another connection mutation is active. Do not restart the tunnel.

- [ ] **Step 4: Run tests and frontend verification**

Run:

```bash
cargo test -p nelomai-app preferences::tests
npm test
```

Expected: persisted default/migration tests, Svelte check and production build
all pass.

- [ ] **Step 5: Commit preference and UI**

```bash
git add src-tauri/src/preferences.rs src-tauri/src/commands.rs src-tauri/src/lib.rs src/lib src/routes/+page.svelte
git commit -m "Добавить настройку kill switch"
```

---

### Task 3: Core lifecycle and explicit stop intent

**Files:**
- Modify: `crates/client-core/src/lib.rs`
- Modify: `crates/client-core/tests/runtime.rs`
- Modify: `crates/client-application/src/lib.rs`
- Test: `crates/client-application/tests/http_flow.rs`

**Interfaces:**
- Consumes: `TunnelStopIntent`, `TunnelRuntimeStatus`.
- Produces: one bounded `retry_blocked_connection()` operation.
- Produces: `Phase::Error` plus `KillSwitchState::Blocked` without releasing the
  panel connection until Stop or replacement succeeds.

- [ ] **Step 1: Write failing lifecycle tests**

Cover these exact cases with the recording tunnel mock:

```rust
#[tokio::test]
async fn initial_start_failure_never_arms_or_blocks() { /* assert Off */ }

#[tokio::test]
async fn policy_reconnect_stops_with_reconnect_intent() { /* assert Reconnect */ }

#[tokio::test]
async fn user_stop_disarms_before_reporting_ready() { /* assert User + Off */ }

#[tokio::test]
async fn blocked_retry_is_bounded_and_keeps_the_lease() { /* one episode */ }
```

- [ ] **Step 2: Confirm RED**

Run: `cargo test -p nelomai-client-core kill_switch -- --nocapture`

Expected: lifecycle assertions fail because every stop currently has identical
semantics.

- [ ] **Step 3: Route every stop call through an explicit intent**

Use `User` for the public Stop, logout, account replacement and updater
shutdown. Use `Reconnect` for physical-network changes, split-policy changes,
local restart, endpoint rotation, service recovery, server replacement and
Tic/Tak-to-Stray switching.

Do not release an active panel lease merely because platform state is
`blocked`. `retry_blocked_connection()` performs one existing bounded recovery
episode and returns `recovered`, `still_blocked`, or `stopped`.

- [ ] **Step 4: Run focused and core regression tests**

Run:

```bash
cargo test -p nelomai-client-core
cargo test -p nelomai-client-application
```

Expected: every stop call is classified and existing connection recovery tests
remain green.

- [ ] **Step 5: Commit lifecycle changes**

```bash
git add crates/client-core crates/client-application
git commit -m "Разделить остановку и переподключение kill switch"
```

---

### Task 4: Cached control-plane addresses

**Files:**
- Modify: `crates/client-api/src/lib.rs`
- Modify: `crates/client-storage/src/lib.rs`
- Modify: `crates/client-storage/tests/split_tunnel.rs`
- Modify: `crates/client-core/src/lib.rs`
- Modify: `crates/client-tunnel/src/lib.rs`

**Interfaces:**
- Produces: `ControlPlaneRouteSet { panel_ips, endpoint_ips }` with at most 16
  canonical addresses per collection.
- Produces: API connection override that preserves hostname/SNI while using a
  cached numeric panel address.
- Consumes: control-plane route set in every desktop Start/Arm call.

- [ ] **Step 1: Add failing bounded-storage and HTTPS-resolution tests**

```rust
#[test]
fn control_plane_routes_reject_duplicates_and_more_than_sixteen_addresses() {}

#[tokio::test]
async fn cached_panel_ip_keeps_original_https_hostname() {}
```

The HTTP test uses a local TLS test server and verifies the requested hostname,
not a production address.

- [ ] **Step 2: Confirm RED**

Run:

```bash
cargo test -p nelomai-client-storage control_plane
cargo test -p nelomai-client-api cached_panel
```

- [ ] **Step 3: Implement canonical bounded route storage**

Store only canonical `IpAddr` strings, update the cache after a healthy API
request, and retain the previous working set on DNS failure. Configure reqwest
host resolution for cached addresses while still validating the original
panel hostname. Never log or upload the addresses.

- [ ] **Step 4: Run API/storage/core tests**

Run:

```bash
cargo test -p nelomai-client-api
cargo test -p nelomai-client-storage
cargo test -p nelomai-client-core
```

- [ ] **Step 5: Commit control-plane recovery**

```bash
git add crates/client-api crates/client-storage crates/client-core crates/client-tunnel
git commit -m "Сохранить маршруты управления для kill switch"
```

---

### Task 5: Android blackhole controller

**Files:**
- Create: `plugins/tunnel-android/android/src/main/java/KillSwitchController.kt`
- Create: `plugins/tunnel-android/android/src/test/java/KillSwitchControllerTest.kt`
- Modify: `plugins/tunnel-android/android/src/main/java/AndroidSplitTunnel.kt`
- Modify: `plugins/tunnel-android/android/src/test/java/AndroidSplitTunnelTest.kt`

**Interfaces:**
- Produces: `AndroidKillSwitchState` and pure transition function.
- Produces: `BlockingVpnPlan`, containing addresses, routes, DNS servers,
  allowed/disallowed packages and excluded routes without secret keys.
- Produces: `arm`, `enterBlocked`, `recover`, `disarm` serialized methods.

- [ ] **Step 1: Write failing pure state and precedence tests**

```kotlin
@Test fun initialFailureStaysOff() {}
@Test fun backendFailureAfterArmBecomesBlocked() {}
@Test fun reconnectKeepsProtection() {}
@Test fun userStopDisarms() {}
@Test fun excludedPackagesAndRoutesStayOutsideBlockingPlan() {}
@Test fun nelomaiPackageNeverEntersProtectedSet() {}
```

- [ ] **Step 2: Confirm RED**

Run:

```bash
src-tauri/gen/android/gradlew -p plugins/tunnel-android/android testDebugUnitTest \
  --tests '*KillSwitchControllerTest*'
```

- [ ] **Step 3: Implement pure transition and immutable plan construction**

The controller accepts only immutable plans and descriptor operations supplied
by `TunnelPlugin`, which keeps unit tests independent from Android framework
objects. Reject transitions not listed in the spec with stable code
`kill_switch_invalid_transition`.

- [ ] **Step 4: Run Android unit tests**

Run:

```bash
src-tauri/gen/android/gradlew -p plugins/tunnel-android/android testDebugUnitTest
```

- [ ] **Step 5: Commit Android state model**

```bash
git add plugins/tunnel-android/android/src/main/java/KillSwitchController.kt \
  plugins/tunnel-android/android/src/main/java/AndroidSplitTunnel.kt \
  plugins/tunnel-android/android/src/test
git commit -m "Добавить модель Android kill switch"
```

---

### Task 6: Android service handover and IPC

**Files:**
- Modify: `plugins/tunnel-android/src/models.rs`
- Modify: `plugins/tunnel-android/src/lib.rs`
- Modify: `plugins/tunnel-android/android/src/main/java/TunnelPlugin.kt`
- Modify: `plugins/tunnel-android/android/src/main/java/NelomaiVpnService.kt`
- Modify: `plugins/tunnel-android/android/src/main/java/TunnelServiceProtocol.kt`
- Modify: `plugins/tunnel-android/android/src/test/java/TunnelServiceProtocolTest.kt`
- Modify: `plugins/tunnel-android/android/src/test/java/NelomaiVpnServiceTest.kt`

**Interfaces:**
- Bump: Android tunnel API version from 2 to 3.
- Produces: status payload with `killSwitchState`.
- Produces: service commands `setKillSwitchEnabled`, `retryBlocked`, and
  `stop(intent)`.

- [ ] **Step 1: Add failing protocol and handover tests**

Assert that old API requests receive `unsupported_api_version`, new requests
round-trip the state, `Reconnect` never closes the blocking descriptor, and an
initial arm failure closes the new tunnel and returns `kill_switch_arm_failed`.

- [ ] **Step 2: Confirm RED**

Run:

```bash
cargo test -p tauri-plugin-tunnel-android
src-tauri/gen/android/gradlew -p plugins/tunnel-android/android testDebugUnitTest
```

- [ ] **Step 3: Implement seamless blackhole handover**

Before destroying a running backend during protected recovery, establish the
blackhole descriptor from `BlockingVpnPlan`; close the backend only after the
descriptor succeeds. On recovery, establish and verify the working backend,
then close the blackhole descriptor. Keep `desiredActive=true` in `blocked`.

The notification exposes `Повторить` and `Стоп`. Deduplicate it by blocked
episode ID. Exhausted recovery schedules no retry timer.

- [ ] **Step 4: Run Rust/Kotlin tests and assemble the plugin**

Run:

```bash
cargo test -p tauri-plugin-tunnel-android
src-tauri/gen/android/gradlew -p plugins/tunnel-android/android \
  testDebugUnitTest :amneziawg-tunnel:assembleDebug
```

- [ ] **Step 5: Commit Android enforcement**

```bash
git add plugins/tunnel-android
git commit -m "Реализовать Android kill switch"
```

---

### Task 7: Windows WFP manager

**Files:**
- Modify: `crates/windows-service/Cargo.toml`
- Create: `crates/windows-service/src/windows/killswitch.rs`
- Modify: `crates/windows-service/src/windows/mod.rs`
- Modify: `crates/windows-service/src/windows/install.rs`
- Test: `crates/windows-service/src/windows/killswitch.rs`

**Interfaces:**
- Produces: `WindowsKillSwitchManager::arm`, `block`, `disarm`, `reconcile`.
- Consumes: canonical tunnel interface identity, endpoint and split/control
  routes.

- [ ] **Step 1: Add failing filter-plan tests using an injected WFP backend**

```rust
#[test]
fn filter_plan_permits_owned_exemptions_before_blocking_physical_egress() {}
#[test]
fn disarm_removes_only_recorded_nelomai_filter_keys() {}
#[test]
fn a_new_boot_identity_discards_stale_state() {}
```

- [ ] **Step 2: Confirm RED on all hosts**

Run: `cargo test -p nelomai-windows-service kill_switch`

The pure planner tests must compile and run on non-Windows hosts; Win32 calls
remain behind `cfg(windows)`.

- [ ] **Step 3: Implement WFP provider/sublayer and exact ownership**

Add the required `windows-sys` Windows Filtering Platform feature. Use fixed
provider/sublayer GUIDs and random per-session filter GUIDs stored atomically
under `%ProgramData%\Nelomai\Tunnel`. Add simple user-mode permit/block filters;
do not add a callout driver and do not change firewall profiles.

`arm` commits all filters in one WFP transaction. Any failure aborts the
transaction. `disarm` deletes only the stored filter keys and verifies their
provider/sublayer before deletion.

- [ ] **Step 4: Run tests and Windows cross-check**

Run locally: `cargo test -p nelomai-windows-service`

Run in GitHub Windows CI:

```powershell
cargo check -p nelomai-windows-service --all-targets
cargo test -p nelomai-windows-service
```

- [ ] **Step 5: Commit the WFP layer**

```bash
git add crates/windows-service
git commit -m "Добавить WFP-правила kill switch"
```

---

### Task 8: Windows service protocol and lifecycle integration

**Files:**
- Modify: `crates/windows-service/src/lib.rs`
- Modify: `crates/windows-service/src/windows/backend.rs`
- Modify: `crates/windows-service/src/windows/service.rs`
- Modify: `crates/windows-service/tests/protocol.rs`
- Modify: `crates/windows-service/tests/service.rs`
- Modify: `src-tauri/src/platform/windows.rs`

**Interfaces:**
- Bump: Windows service protocol from 8 to 9.
- Consumes: `WindowsKillSwitchManager`.
- Produces: typed request/response fields for stop intent, enable change,
  runtime state and retry.

- [ ] **Step 1: Add failing transaction tests**

Cover initial tunnel success + arm, arm rollback, reconnect retaining filters,
backend failure becoming blocked, service restart reconciliation, user Stop,
and preference disable while running/blocked.

- [ ] **Step 2: Confirm RED**

Run: `cargo test -p nelomai-windows-service kill_switch -- --nocapture`

- [ ] **Step 3: Integrate WFP into the serialized service backend**

Initial Start order:

```text
resolve/pin endpoint -> apply split routes -> start backend -> verify backend
-> WFP arm transaction -> return Running + Armed
```

On arm failure: remove backend, routes, transient config and partial WFP state;
return `kill_switch_arm_failed`. On `Reconnect`, retain WFP while replacing the
backend. On `User`, stop backend and routes, disarm WFP, then return Stopped.

- [ ] **Step 4: Run Windows service and workspace tests**

Run:

```bash
cargo test -p nelomai-windows-service
cargo test --workspace
```

- [ ] **Step 5: Commit Windows lifecycle integration**

```bash
git add crates/windows-service src-tauri/src/platform/windows.rs
git commit -m "Подключить kill switch к службе Windows"
```

---

### Task 9: Unix shared state and protocol

**Files:**
- Modify: `crates/unix-service/src/lib.rs`
- Create: `crates/unix-service/src/killswitch.rs`
- Modify: `crates/unix-service/src/main.rs`
- Modify: `crates/unix-service/tests/helper.rs`
- Modify: `src-tauri/src/platform/unix.rs`

**Interfaces:**
- Bump: Unix helper protocol from 5 to 6.
- Produces: `KillSwitchBackend` trait with `arm`, `block`, `disarm`, `reconcile`.
- Produces: bounded atomic state at `/var/run/nelomai/killswitch-state.json`.

- [ ] **Step 1: Add failing state-file and protocol tests**

Test mode `0600`, root ownership validation, maximum 64 KiB, canonical routes,
duplicate rejection, corrupt-state fail-closed handling, exact boot identity,
and explicit old-protocol rejection.

- [ ] **Step 2: Confirm RED**

Run: `cargo test -p nelomai-unix-service kill_switch -- --nocapture`

- [ ] **Step 3: Implement platform-neutral persistence and commands**

Use atomic create/fsync/rename and the existing root-owned runtime directory.
The state stores only runtime enum, boot identity, platform object identity and
canonical exemption counts/routes. It never stores tunnel keys or panel
credentials.

- [ ] **Step 4: Run Unix helper tests**

Run: `cargo test -p nelomai-unix-service`

- [ ] **Step 5: Commit Unix shared layer**

```bash
git add crates/unix-service/src/lib.rs crates/unix-service/src/killswitch.rs \
  crates/unix-service/src/main.rs crates/unix-service/tests/helper.rs \
  src-tauri/src/platform/unix.rs
git commit -m "Добавить контракт Unix kill switch"
```

---

### Task 10: Linux nftables enforcement

**Files:**
- Create: `crates/unix-service/src/killswitch/linux.rs`
- Modify: `crates/unix-service/src/killswitch.rs`
- Modify: `crates/unix-service/src/backend/linux.rs`
- Test: `crates/unix-service/src/killswitch/linux.rs`

**Interfaces:**
- Implements: `KillSwitchBackend` for Linux.
- Owns: nftables table `inet nelomai_killswitch`.

- [ ] **Step 1: Add failing renderer and ownership tests**

Assert stable transaction output, canonical CIDR ordering, tunnel/endpoint and
split exemption precedence, no shell interpolation, exact table ownership and
no command that flushes another table.

- [ ] **Step 2: Confirm RED**

Run: `cargo test -p nelomai-unix-service killswitch::linux`

- [ ] **Step 3: Implement atomic nft transaction execution**

Write the generated ruleset to child stdin of `/usr/sbin/nft -f -` with the
existing command timeout. Do not invoke a shell. Verify the resulting table
from one bounded `nft --json list table inet nelomai_killswitch` snapshot.

- [ ] **Step 4: Run tests and Linux namespace smoke**

Run unit tests, then in Linux CI create an isolated network namespace and
verify: tunnel destination passes, explicit exclusion passes, arbitrary
physical destination fails, User Stop restores it, and namespace recreation
starts off.

- [ ] **Step 5: Commit Linux enforcement**

```bash
git add crates/unix-service/src/killswitch crates/unix-service/src/backend/linux.rs .github/workflows/checks.yml
git commit -m "Реализовать Linux kill switch"
```

---

### Task 11: macOS PF enforcement

**Files:**
- Create: `crates/unix-service/src/killswitch/macos.rs`
- Modify: `crates/unix-service/src/killswitch.rs`
- Modify: `crates/unix-service/src/backend/macos.rs`
- Test: `crates/unix-service/src/killswitch/macos.rs`

**Interfaces:**
- Implements: `KillSwitchBackend` for macOS.
- Owns: PF anchor `com.apple/nelomai` and one enable reference token.

- [ ] **Step 1: Add failing PF renderer/token tests**

Assert escaped/canonical rules, pass-before-block ordering, exact anchor name,
token parsing, refusal to flush the main ruleset, and deletion limited to the
owned anchor/token.

- [ ] **Step 2: Confirm RED**

Run: `cargo test -p nelomai-unix-service killswitch::macos`

- [ ] **Step 3: Implement PF anchor lifecycle**

Use direct `pfctl` argv calls with timeouts:

```text
pfctl -E
pfctl -a com.apple/nelomai -f <generated-file>
pfctl -a com.apple/nelomai -s rules
pfctl -a com.apple/nelomai -F rules
pfctl -X <owned-token>
```

Never call `pfctl -F all`, never rewrite `/etc/pf.conf`, and never run
`pfctl -d`. Persist the parsed token before reporting `armed`.

- [ ] **Step 4: Run tests and root-authorized macOS smoke**

On this Mac, use the installed launch daemon rather than invoking PF from the
unprivileged test runner. Verify existing Apple anchors remain byte-for-byte
unchanged before/after the smoke.

- [ ] **Step 5: Commit macOS enforcement**

```bash
git add crates/unix-service/src/killswitch crates/unix-service/src/backend/macos.rs .github/workflows/checks.yml
git commit -m "Реализовать macOS kill switch"
```

---

### Task 12: Unix lifecycle integration and reconciliation

**Files:**
- Modify: `crates/unix-service/src/backend/linux.rs`
- Modify: `crates/unix-service/src/backend/macos.rs`
- Modify: `crates/unix-service/src/lib.rs`
- Modify: `crates/unix-service/tests/helper.rs`

**Interfaces:**
- Consumes: both platform `KillSwitchBackend` implementations.
- Produces: atomic initial Start, retained Reconnect and confirmed User Stop.

- [ ] **Step 1: Add failing backend transaction tests**

Use injected route/tunnel/killswitch backends to prove every ordering and
rollback path. Include helper crash reconciliation during the same boot and
stale cleanup after a different boot identity.

- [ ] **Step 2: Confirm RED**

Run: `cargo test -p nelomai-unix-service lifecycle_kill_switch`

- [ ] **Step 3: Integrate lifecycle ordering**

Mirror the Windows transaction. A reconnect never invokes `disarm`. A user
stop does not return success until route cleanup and enforcement removal both
succeed. On disarm failure return `kill_switch_disarm_failed` and retain
`blocked` in the status response.

- [ ] **Step 4: Run Unix and workspace tests**

Run:

```bash
cargo test -p nelomai-unix-service
cargo test --workspace
```

- [ ] **Step 5: Commit Unix lifecycle integration**

```bash
git add crates/unix-service
git commit -m "Подключить kill switch к Unix helper"
```

---

### Task 13: Diagnostics, notifications and user-facing recovery

**Files:**
- Modify: `src-tauri/src/diagnostics.rs`
- Modify: `src-tauri/src/automatic_diagnostics.rs`
- Modify: `src-tauri/src/lib.rs`
- Modify: `src-tauri/src/commands.rs`
- Modify: `src/lib/app-model.ts`
- Modify: `src/routes/+page.svelte`
- Modify: Android notification files from Task 6.

**Interfaces:**
- Produces: stable event names from the spec.
- Produces: commands `app_retry_blocked_connection` and existing Stop reuse.

- [ ] **Step 1: Add failing redaction, deduplication and message tests**

Prove that reports contain transition names, failure codes and exemption
counts, but reject raw IP addresses, package IDs, endpoints and configuration.
Prove one report/notification per blocked episode and one terminal report for
recovered or exhausted.

- [ ] **Step 2: Confirm RED**

Run:

```bash
cargo test -p nelomai-app kill_switch
npm run test:unit -- src/lib/app-model.test.ts
```

- [ ] **Step 3: Implement UI state and bounded actions**

Use the approved Russian messages from the spec. `Повторить` invokes exactly
one bounded episode. `Стоп` uses the normal user Stop. Disable duplicate action
buttons while the serialized operation is active.

- [ ] **Step 4: Run application and frontend tests**

Run:

```bash
cargo test -p nelomai-app
npm test
```

- [ ] **Step 5: Commit recovery UX and diagnostics**

```bash
git add src-tauri/src src/lib src/routes/+page.svelte plugins/tunnel-android/android/src/main
git commit -m "Добавить диагностику и восстановление kill switch"
```

---

### Task 14: Documentation, CI gates and full verification

**Files:**
- Modify: `docs/split-tunnel.md`
- Modify: `docs/windows-tunnel-service.md`
- Modify: `docs/unix-tunnel-helper.md`
- Modify: `.github/workflows/checks.yml`
- Modify: `.github/workflows/release.yml`

**Interfaces:**
- Documents: state machine, split precedence, platform limits, inspection and
  safe recovery commands.
- Adds: CI compilation/tests for WFP, nft and PF modules.

- [ ] **Step 1: Add workflow contract checks before editing workflow**

Extend `scripts/release-workflow-check.py` to require Windows service protocol
v9, Unix protocol v6, Android API v3 test jobs, and presence of Linux/macOS
kill-switch smoke gates.

- [ ] **Step 2: Confirm workflow check RED**

Run: `python scripts/release-workflow-check.py`

Expected: failure naming the missing kill-switch gates.

- [ ] **Step 3: Update documentation and workflows**

Document only Nelomai-owned inspection commands. Include an emergency Stop
through the app/helper protocol; do not instruct users to flush WFP, nftables
or PF globally.

- [ ] **Step 4: Run the complete automated suite**

Run:

```bash
npm test
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python contracts/python/validate_fixtures.py
python scripts/release-workflow-check.py
src-tauri/gen/android/gradlew -p plugins/tunnel-android/android \
  testDebugUnitTest :amneziawg-tunnel:assembleDebug
git diff --check
```

Expected: every command exits 0.

- [ ] **Step 5: Run required platform smoke matrix**

For every platform, test WireGuard and AWG3/Tic and Stray where supported:

1. preference off, initial start failure leaves direct Internet;
2. enable while connected without interface recreation;
3. force endpoint failure and observe `blocked`;
4. verify protected destination fails and every explicit exemption succeeds;
5. replace network and recover to `armed`;
6. exhaust recovery and confirm one notification/no loop;
7. press Retry and recover;
8. press Stop and restore direct Internet;
9. kill only the UI and verify enforcement remains;
10. restart helper/service in the same boot and verify reconciliation;
11. reboot and verify tunnel/runtime state start `off`;
12. disable while running without reconnect and while blocked with cleanup.

Android additionally tests process survival and records the documented leak
boundary after forcibly killing `:vpn` without system lockdown. Windows checks
that unrelated firewall rules are unchanged. Linux checks unrelated nftables
tables. macOS checks unrelated PF anchors and enable references.

- [ ] **Step 6: Perform final security review**

Review exact ownership before deletion, fail-open initial Start, fail-closed
armed recovery, API address redaction, bounded state files, command argument
safety, protocol version rejection and updater/logout Stop ordering. Fix only
issues found in this feature and rerun Step 4.

- [ ] **Step 7: Commit documentation and verification gates**

```bash
git add docs .github/workflows scripts/release-workflow-check.py
git commit -m "Документировать и проверить kill switch"
```

---

## Deployment sequence after implementation approval

1. Land shared contracts/preferences/core with the switch hidden behind a
   compile-time false capability.
2. Land Android enforcement and complete Android smoke before exposing Android
   capability.
3. Land Windows WFP and real Windows smoke before exposing Windows capability.
4. Land Linux nftables and macOS PF independently; expose each only after its
   own smoke passes.
5. Enable the UI switch only when the current platform reports capability.
6. Release as a normal application release; no panel deployment is required.
7. Observe blocked/recovered/exhausted diagnostic counts before changing the
   default, which remains disabled by this specification.

## Explicit stop conditions during implementation

Stop implementation and return for design review if any of these occurs:

- Android cannot establish a replacement TUN before releasing the active one.
- A desktop platform requires changing global firewall defaults or flushing an
  unowned ruleset.
- Control-plane recovery requires allowing unrestricted system DNS.
- A helper cannot distinguish same-boot crash recovery from a new OS boot.
- Three independent fix attempts fail on the same platform smoke scenario.
