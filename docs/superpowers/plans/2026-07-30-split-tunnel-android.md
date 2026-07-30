# Split-Tunnel Shared Core and Android Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add policy synchronization, per-device split-tunnel settings, atomic policy application, and Android application/address exclusions without expanding WireGuard `AllowedIPs`.

**Architecture:** The panel remains the source of compact policy data. Rust contracts, API, storage, and core code own synchronization and rollback. The Android plugin owns installed-app discovery and translates effective policy into WireGuard application rules plus Android 13+ `VpnService.Builder.excludeRoute()` calls. Android 12 and older keep every connection mode available but always start a normal full tunnel with all split options removed.

**Tech Stack:** Rust 1.88, Tokio, Reqwest, Serde, Tauri 2, Svelte 5, TypeScript, Kotlin/JVM 17, Android `VpnService`, WireGuard Android tunnel `1.0.20260102`, Vitest, Cargo tests, JUnit.

## Global Constraints

- Do not alter the raw native WireGuard `AllowedIPs = 0.0.0.0/0`.
- Do not calculate or transfer an `AllowedIPs` complement.
- Android address exclusions use `excludeRoute(IpPrefix)` only on API 33 and newer.
- Android API 32 and older keep `Tic + via_tak`, `Tic + standalone`, and Stray operational as ordinary full tunnels; no split rule may block connection.
- `Tic + standalone` never applies split rules on any platform.
- Stray applies split rules whenever the platform supports them, even though its technical route mode is `standalone`.
- The complete installed-application inventory and local physical networks remain on the device.
- Do not log WireGuard configuration, package inventory, local networks, access tokens, or install secrets.
- Cached policy never expires in a way that blocks VPN. Panel unavailability produces only a non-blocking warning.
- Global rollout flag is initially disabled on the panel.
- Commit messages are in Russian.
- Do not push or deploy without a direct user command.

---

### Task 1: Add Versioned Split-Tunnel Contracts

**Files:**
- Create: `crates/contracts/src/split_tunnel.rs`
- Modify: `crates/contracts/src/lib.rs`
- Modify: `crates/contracts/tests/fixtures.rs`

- [ ] Add failing JSON fixture tests for all wire types.

Cover these exact shapes:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitTunnelMode {
    ExcludeSelected,
    IncludeSelected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitTunnelRevision {
    pub enabled: bool,
    pub revision: i64,
    pub force_revision: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitTunnelSelectedPackage {
    pub package_id: String,
    pub display_name: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitTunnelPolicy {
    pub format_version: u16,
    pub enabled: bool,
    pub revision: i64,
    pub force_revision: i64,
    pub policy_hash: String,
    pub mode: SplitTunnelMode,
    pub exclude_local_networks: bool,
    pub mandatory_excluded_packages: Vec<String>,
    pub suggested_name_fragments: Vec<String>,
    pub selected_packages: Vec<String>,
    pub excluded_ipv4_cidrs: Vec<String>,
    pub generated_at: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitTunnelSettingsUpdate {
    pub mode: SplitTunnelMode,
    pub exclude_local_networks: bool,
    pub selected_packages: Vec<SplitTunnelSelectedPackage>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitTunnelApplyStatus {
    Applied,
    RolledBack,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitTunnelApplyResult {
    pub format_version: u16,
    pub revision: i64,
    pub force_revision: i64,
    pub policy_hash: String,
    pub status: SplitTunnelApplyStatus,
    pub error_code: Option<String>,
    pub applied_at: String,
}
```

- [ ] Assert unknown `format_version` remains parseable at the transport boundary but is rejected by the core before application.
- [ ] Assert API JSON uses `snake_case` enum values and never serializes an application icon or full inventory.
- [ ] Treat `generated_at` and `applied_at` as RFC 3339 strings at the contract boundary and validate them with the existing `time` dependency before use.
- [ ] Implement custom `Debug` for policy/settings that prints revision, mode, booleans, hash, and list counts but never package IDs, display names, or CIDRs.
- [ ] Export the module types from `crates/contracts/src/lib.rs`.
- [ ] Run the failing test and confirm the expected compile or assertion failure:

```bash
cargo test -p nelomai-contracts --test fixtures split_tunnel -- --nocapture
```

- [ ] Implement the contracts and make the focused test pass.
- [ ] Run all contracts tests:

```bash
cargo test -p nelomai-contracts
```

- [ ] Commit:

```bash
git add crates/contracts
git commit -m "Добавить контракты split-tunnel"
```

---

### Task 2: Add Panel API Methods and Strict Response Limits

**Files:**
- Modify: `crates/client-api/src/lib.rs`
- Modify: `crates/client-api/Cargo.toml`
- Modify: `crates/client-application/tests/http_flow.rs`

- [ ] Add failing mock-server tests for:
  - `GET /api/client/v1/split-tunnel/revision`;
  - `GET /api/client/v1/split-tunnel/policy`;
  - `PUT /api/client/v1/split-tunnel/settings`;
  - `POST /api/client/v1/split-tunnel/apply-result`.
- [ ] Assert each request carries the existing bearer token and the panel's request ID behavior remains unchanged.
- [ ] Assert a policy body above `1 MiB` is rejected before JSON deserialization with a stable `split_tunnel_policy_too_large` client error.
- [ ] Assert settings with more than 512 selected packages are rejected locally.
- [ ] Assert a serialized settings request above `256 KiB` is rejected locally before transmission.
- [ ] Implement these methods on `ClientApi`:

```rust
pub async fn split_tunnel_revision(
    &self,
    access_token: &str,
) -> Result<SplitTunnelRevision, ClientApiError>;

pub async fn split_tunnel_policy(
    &self,
    access_token: &str,
) -> Result<SplitTunnelPolicy, ClientApiError>;

pub async fn update_split_tunnel_settings(
    &self,
    access_token: &str,
    request: &SplitTunnelSettingsUpdate,
) -> Result<SplitTunnelPolicy, ClientApiError>;

pub async fn report_split_tunnel_apply_result(
    &self,
    access_token: &str,
    request: &SplitTunnelApplyResult,
) -> Result<SuccessResponse, ClientApiError>;
```

- [ ] Reuse the current authenticated request and token refresh path; do not create a second HTTP client.
- [ ] Redact policy bodies and selected package IDs from transport error text.
- [ ] Run focused tests:

```bash
cargo test -p nelomai-client-application --test http_flow split_tunnel -- --nocapture
```

- [ ] Run API and application tests:

```bash
cargo test -p nelomai-client-api
cargo test -p nelomai-client-application
```

- [ ] Commit:

```bash
git add crates/client-api crates/client-application
git commit -m "Подключить API политики split-tunnel"
```

---

### Task 3: Store Policy State Outside the Credential Store

**Files:**
- Create: `crates/client-storage/src/split_tunnel.rs`
- Modify: `crates/client-storage/src/lib.rs`
- Modify: `crates/client-storage/Cargo.toml`
- Create: `crates/client-storage/tests/split_tunnel.rs`

- [ ] Add failing tests for an atomic file-backed `SplitTunnelStore`.
- [ ] Define persisted state:

```rust
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSplitTunnelState {
    pub cached_policy: Option<SplitTunnelPolicy>,
    pub working_policy_hash: Option<String>,
    pub previous_working_policy: Option<SplitTunnelPolicy>,
    pub last_full_sync_unix: Option<i64>,
    pub last_revision_check_unix: Option<i64>,
    pub last_seen_force_revision: i64,
    pub pending_apply_results: Vec<SplitTunnelApplyResult>,
}

pub trait SplitTunnelStore: Send + Sync {
    fn load(&self) -> Result<StoredSplitTunnelState, StorageError>;
    fn save(&self, state: &StoredSplitTunnelState) -> Result<(), StorageError>;
    fn delete(&self) -> Result<(), StorageError>;
}
```

- [ ] Use `<app_data>/split-tunnel/state.json`; keep credentials and WireGuard keys out of this file.
- [ ] Add `MemorySplitTunnelStore` for deterministic unit tests and for the backward-compatible constructors used by existing tests.
- [ ] Enforce a `1 MiB` read/write limit and reject malformed state without silently truncating it.
- [ ] Write to a sibling temporary file, `fsync`, set mode `0600` on Unix, rename atomically, and `fsync` the directory.
- [ ] Keep at most 32 pending apply results, dropping oldest successful entries before failed entries.
- [ ] Ensure `Debug` for persisted state omits selected package IDs and CIDRs.
- [ ] Run focused tests:

```bash
cargo test -p nelomai-client-storage --test split_tunnel -- --nocapture
```

- [ ] Run all storage tests:

```bash
cargo test -p nelomai-client-storage
```

- [ ] Commit:

```bash
git add crates/client-storage
git commit -m "Добавить локальное хранилище split-tunnel"
```

---

### Task 4: Build the Shared Effective-Policy Engine

**Files:**
- Create: `crates/client-core/src/split_tunnel.rs`
- Modify: `crates/client-core/src/lib.rs`
- Modify: `crates/client-core/Cargo.toml`
- Create: `crates/client-core/tests/split_tunnel.rs`
- Modify: `crates/client-tunnel/src/lib.rs`

- [ ] Add failing table-driven tests for activation by platform, Android API, layer, and route.
- [ ] Encode the exact activation rule:

```rust
pub fn split_tunnel_active(context: SplitTunnelContext) -> bool {
    if !context.global_enabled {
        return false;
    }
    if context.platform == TunnelPlatform::Android
        && context.android_api_level.is_some_and(|level| level <= 32)
    {
        return false;
    }
    match (context.layer, context.route_mode) {
        (Layer::Tic, RouteMode::ViaTak) => true,
        (Layer::Tic, RouteMode::Standalone) => false,
        (Layer::Stray, _) => true,
        _ => false,
    }
}
```

- [ ] Add tests proving Android API 24–32 can start every connection mode with `TunnelOptions::default()`.
- [ ] Add tests proving API 33+ uses split for `Tic + via_tak` and Stray but not `Tic + standalone`.
- [ ] Add tests for precedence:
  - mandatory package ID is always excluded;
  - a mandatory package is removed from suggestions;
  - display-name matching is Unicode case-insensitive;
  - unavailable packages are removed from the active selection but not panel history.
- [ ] Reject policies with more than 512 mandatory package IDs, 128 name suggestions, 512 selected package IDs, or 16,384 compact CIDRs before application.
- [ ] Add tests for include-only mode:
  - empty effective selection blocks Start only when split is active;
  - mandatory exclusions are not presented as selectable includes;
  - Android 12 and older do not block Start because split is inactive.
- [ ] Replace the tunnel start signature with a versioned request:

```rust
#[derive(Debug)]
pub struct TunnelStartRequest {
    pub configuration: TunnelConfiguration,
    pub options: TunnelOptions,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TunnelOptions {
    pub application_mode: Option<SplitTunnelMode>,
    pub package_ids: Vec<String>,
    pub excluded_ipv4_cidrs: Vec<String>,
    pub exclude_local_networks: bool,
    pub policy_hash: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TunnelPlatform {
    Android,
    Windows,
    Linux,
    Macos,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TunnelCapabilities {
    pub platform: TunnelPlatform,
    pub android_api_level: Option<u32>,
    pub address_split_tunnel: bool,
    pub application_split_tunnel: bool,
}

#[async_trait]
pub trait TunnelController: Send + Sync {
    async fn start(&self, request: TunnelStartRequest) -> Result<(), TunnelError>;
    async fn stop(&self) -> Result<(), TunnelError>;
    async fn status(&self) -> Result<TunnelStatus, TunnelError>;
    async fn capabilities(&self) -> Result<TunnelCapabilities, TunnelError> {
        Ok(TunnelCapabilities::default())
    }
}
```

- [ ] Keep `TunnelStartRequest` debug output redacted and validate package IDs/CIDRs before crossing into a helper or plugin.
- [ ] Make Android capabilities come from the plugin probe and `Build.VERSION.SDK_INT`; desktop controllers report address support and no application support. Keep the trait default so existing test controllers compile unchanged.
- [ ] Implement `EffectiveSplitTunnelPolicy::build(...)` in `client-core`, returning default options whenever split is inactive.
- [ ] Run focused tests:

```bash
cargo test -p nelomai-client-core --test split_tunnel -- --nocapture
cargo test -p nelomai-client-tunnel
```

- [ ] Run all core tests:

```bash
cargo test -p nelomai-client-core
```

- [ ] Commit:

```bash
git add crates/client-core crates/client-tunnel
git commit -m "Добавить движок политики split-tunnel"
```

---

### Task 5: Implement Synchronization, Cache Fallback, and Atomic Reapply

**Files:**
- Modify: `crates/client-core/src/split_tunnel.rs`
- Modify: `crates/client-core/src/lib.rs`
- Modify: `crates/client-application/src/lib.rs`
- Modify: `crates/client-application/tests/http_flow.rs`
- Modify: `crates/client-core/tests/split_tunnel.rs`
- Modify: `crates/client-core/tests/runtime.rs`

- [ ] Add failing tests for a `SplitTunnelCoordinator` with:
  - revision poll interval of five minutes while the app is running;
  - full policy sync interval of 24 hours;
  - immediate full fetch when `force_revision` increases;
  - immediate full fetch after the user saves settings;
  - no reconnect when `policy_hash` is unchanged;
  - cached policy used indefinitely when the panel is unavailable;
  - no split-policy task or operation log emitted for routine revision polls.
- [ ] Add failing runtime tests for policy application while connected:
  1. remember current connection and effective options;
  2. stop the tunnel;
  3. start with the new policy;
  4. if that fails, start once with the prior working policy;
  5. if rollback succeeds, remain connected and report `rolled_back`;
  6. if rollback fails, remain stopped and report `failed`.
- [ ] Prove `Tic + standalone` settings save without reconnect.
- [ ] Prove Android API 32 settings save and synchronize but never trigger a split reapply.
- [ ] Prove a newer unknown policy format preserves the previous working policy and returns a non-blocking update warning.
- [ ] Add coordinator state to `ClientCore` without holding the main state mutex across HTTP or tunnel operations.
- [ ] Extend `CoreApi` and its `ClientApi` implementation with revision, policy, settings, and apply-result methods so mocked core tests use the same boundary as production.
- [ ] Store `Arc<dyn SplitTunnelStore>` inside `ClientCore` rather than adding a fifth generic parameter. Add:

```rust
pub fn with_split_tunnel_store(
    api: Arc<A>,
    secret_store: Arc<S>,
    split_tunnel_store: Arc<dyn SplitTunnelStore>,
    tunnel: Arc<T>,
    logger: Arc<L>,
) -> Self;
```

Keep the existing `ClientCore::new(...)` signature and delegate it to
`with_split_tunnel_store(...)` with a `MemorySplitTunnelStore`, so existing
focused tests need no mechanical constructor churn.

- [ ] Add the matching `ClientApplication::with_split_tunnel_store(...)` constructor and keep its existing `new(...)` as the same compatibility wrapper.
- [ ] Queue failed apply-result uploads in `SplitTunnelStore` and retry after the next authenticated panel request.
- [ ] Update `ClientCore::start` and `start_saved_stray_offline` to pass the computed `TunnelStartRequest`.
- [ ] For offline saved Stray, use the cached policy; if no cached policy exists, start full tunnel and expose a warning rather than failing.
- [ ] Run focused tests:

```bash
cargo test -p nelomai-client-core split_tunnel -- --nocapture
cargo test -p nelomai-client-application split_tunnel -- --nocapture
```

- [ ] Run all affected crates:

```bash
cargo test -p nelomai-client-core
cargo test -p nelomai-client-application
```

- [ ] Commit:

```bash
git add crates/client-core crates/client-application
git commit -m "Добавить синхронизацию и откат split-tunnel"
```

---

### Task 6: Discover Android Applications Without Uploading Inventory

**Files:**
- Modify: `plugins/tunnel-android/android/src/main/AndroidManifest.xml`
- Modify: `plugins/tunnel-android/android/src/main/java/TunnelPlugin.kt`
- Create: `plugins/tunnel-android/android/src/main/java/InstalledApplications.kt`
- Modify: `plugins/tunnel-android/src/models.rs`
- Modify: `plugins/tunnel-android/src/commands.rs`
- Modify: `plugins/tunnel-android/src/mobile.rs`
- Modify: `plugins/tunnel-android/src/lib.rs`
- Modify: `plugins/tunnel-android/guest-js/index.ts`
- Modify: `plugins/tunnel-android/permissions/default.toml`
- Create: `plugins/tunnel-android/permissions/autogenerated/commands/installed_applications.toml`
- Create: `plugins/tunnel-android/android/src/test/java/InstalledApplicationsTest.kt`

- [ ] Add a failing Kotlin test for deterministic sorting, regular/system classification, and package ID deduplication.
- [ ] Add `<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />` and document why complete inventory is required for a VPN client.
- [ ] Add a plugin command returning only:

```kotlin
data class InstalledApplication(
    val packageId: String,
    val displayName: String,
    val system: Boolean,
)
```

- [ ] Query launchable and installed packages through `PackageManager`, exclude Nelomai itself, and resolve labels safely when an app has no label.
- [ ] Sort by localized display name, then package ID; never return icons over the Tauri bridge.
- [ ] Add Rust and TypeScript models and the generated permission entry.
- [ ] Ensure inventory is held only in frontend memory and is not written into diagnostics or generic command tracing.
- [ ] Run plugin tests:

```bash
./src-tauri/gen/android/gradlew -p src-tauri/gen/android :tauri-plugin-tunnel-android:test
cargo test -p tauri-plugin-tunnel-android
```

- [ ] Commit:

```bash
git add plugins/tunnel-android
git commit -m "Добавить локальный список Android приложений"
```

---

### Task 7: Apply Android Package and Address Rules

**Files:**
- Modify: `plugins/tunnel-android/android/src/main/AndroidManifest.xml`
- Create: `plugins/tunnel-android/android/src/main/java/NelomaiVpnService.kt`
- Create: `plugins/tunnel-android/android/src/main/java/AndroidSplitTunnel.kt`
- Modify: `plugins/tunnel-android/android/src/main/java/TunnelPlugin.kt`
- Modify: `plugins/tunnel-android/android/src/test/java/TunnelPayloadTest.kt`
- Create: `plugins/tunnel-android/android/src/test/java/AndroidSplitTunnelTest.kt`
- Modify: `plugins/tunnel-android/src/models.rs`

- [ ] Add failing tests for tunnel-option validation:
  - included and excluded packages cannot both be non-empty;
  - package IDs are deduplicated and limited to 512;
  - IPv4 CIDRs are canonical, deduplicated, and limited to 16,384;
  - API 32 converts every option set to empty effective options;
  - API 33 preserves valid options.
- [ ] Increment `TUNNEL_API_VERSION` to `2` in Rust and Kotlin.
- [ ] Add `androidApiLevel`, `addressSplitTunnel`, and `applicationSplitTunnel` to the Android probe response; API 32 reports both split capabilities false, API 33+ reports both true.
- [ ] Register `NelomaiVpnService` with `android.permission.BIND_VPN_SERVICE`, `exported="false"`, and the standard `android.net.VpnService` intent filter.
- [ ] Implement the no-fork WireGuard hook:

```kotlin
class NelomaiVpnService : GoBackend.VpnService() {
    override fun getBuilder(): VpnService.Builder =
        object : VpnService.Builder(this) {
            override fun establish(): ParcelFileDescriptor? {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    AndroidSplitTunnel.currentExcludedRoutes().forEach { prefix ->
                        excludeRoute(prefix)
                    }
                }
                return super.establish()
            }
        }
}
```

- [ ] Start `NelomaiVpnService` before constructing or calling `GoBackend`, so the inherited WireGuard service future resolves to the subclass.
- [ ] Rebuild the parsed WireGuard `Config` through the dependency's structured API:
  - copy addresses, DNS, search domains, key pair, optional listen port, and optional MTU from the original `Interface` into `Interface.Builder`;
  - `ExcludeSelected` calls `Interface.Builder.excludeApplications(packageIds)`;
  - `IncludeSelected` calls `Interface.Builder.includeApplications(packageIds)`;
  - do not copy an old included/excluded application set;
  - build the replacement `Interface`, then use `Config.Builder.setInterface(...)` and `addPeers(original.peers)`;
  - never use both application lists.
- [ ] Feed compact IPv4 CIDRs to `AndroidSplitTunnel` immediately before `GoBackend.setState(UP, config)`.
- [ ] On API 32 and older:
  - clear package and route options;
  - keep the original WireGuard config;
  - start every connection mode normally;
  - return a capability flag explaining that split requires Android 13.
- [ ] Never place excluded routes into WireGuard `AllowedIPs`.
- [ ] Clear route state and in-memory config references on Stop, failed Start, and plugin shutdown.
- [ ] Run Kotlin and Rust tests:

```bash
./src-tauri/gen/android/gradlew -p src-tauri/gen/android :tauri-plugin-tunnel-android:test
cargo test -p tauri-plugin-tunnel-android
```

- [ ] Build a debug APK and inspect its manifest:

```bash
pnpm tauri android build --debug
apkanalyzer manifest print src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk
```

- [ ] Commit:

```bash
git add plugins/tunnel-android
git commit -m "Применить split-tunnel на Android"
```

---

### Task 8: Exclude Actual Local Networks and Reapply on Network Change

**Files:**
- Create: `plugins/tunnel-android/android/src/main/java/PhysicalNetworks.kt`
- Modify: `plugins/tunnel-android/android/src/main/java/AndroidSplitTunnel.kt`
- Modify: `plugins/tunnel-android/android/src/main/java/TunnelPlugin.kt`
- Create: `plugins/tunnel-android/android/src/test/java/PhysicalNetworksTest.kt`

- [ ] Add failing tests for converting Android `LinkAddress` values into canonical physical-network CIDRs.
- [ ] Include only active networks with Wi-Fi, cellular, or Ethernet transport.
- [ ] Exclude VPN transports, loopback, multicast, link-local, and host-only `/32` addresses.
- [ ] Do not substitute all RFC1918 ranges; use only actual on-link networks reported by `LinkProperties`.
- [ ] When `exclude_local_networks` is enabled, merge detected local CIDRs with panel CIDRs in memory and pass them to `excludeRoute()`.
- [ ] Register a `ConnectivityManager.NetworkCallback` only while a split-enabled tunnel is running.
- [ ] Fingerprint canonical physical CIDRs. If the fingerprint changes:
  - serialize the operation on the existing tunnel executor;
  - stop the current backend state;
  - apply the new local routes;
  - restart the same in-memory WireGuard config;
  - retry once with the previous local-route snapshot if restart fails.
- [ ] Do not notify the panel about local CIDRs or include them in diagnostics.
- [ ] On API 32 and older, do not register this split-specific callback.
- [ ] Run tests:

```bash
./src-tauri/gen/android/gradlew -p src-tauri/gen/android :tauri-plugin-tunnel-android:test
```

- [ ] Commit:

```bash
git add plugins/tunnel-android
git commit -m "Добавить исключение локальных сетей Android"
```

---

### Task 9: Add Split-Tunnel Commands, Scheduler, and Settings UI

**Files:**
- Modify: `src-tauri/src/lib.rs`
- Modify: `src-tauri/src/commands.rs`
- Modify: `src-tauri/src/platform/mod.rs`
- Modify: `src/lib/native-client.ts`
- Modify: `src/lib/native-client.test.ts`
- Create: `src/lib/split-tunnel.ts`
- Create: `src/lib/split-tunnel.test.ts`
- Create: `src/lib/SplitTunnelSettings.svelte`
- Create: `src/lib/SplitTunnelSettings.test.ts`
- Modify: `src/routes/+page.svelte`

- [ ] Add failing command and model tests for:
  - reading effective settings and capability;
  - scanning installed Android applications;
  - saving mode, local-network toggle, and selected applications;
  - forcing a local refresh;
  - confirming reconnect when effective policy changes.
- [ ] Construct `FileSplitTunnelStore` from `<app_data>/split-tunnel` in `src-tauri/src/lib.rs` and initialize production through `ClientApplication::with_split_tunnel_store(...)`.
- [ ] Start one scheduler per process:
  - revision check every five minutes while authenticated and running;
  - full refresh no more often than 24 hours unless force revision or local save requires it;
  - no overlapping requests through a Tokio mutex;
  - suspend ordinary polling while signed out.
- [ ] Add Tauri commands:

```rust
app_split_tunnel_state
app_split_tunnel_installed_applications
app_split_tunnel_save
app_split_tunnel_refresh
```

- [ ] Build the settings view with:
  - mode selector;
  - `Исключить локальные адреса` toggle, on by default;
  - regular applications shown first;
  - optional system-applications toggle;
  - search;
  - locked mandatory exclusions;
  - suggestions from case-insensitive display-name fragments;
  - no suggestion when package ID is already mandatory.
- [ ] On Android 12 and older, keep settings readable/savable but show `Split-tunnel доступен на Android 13 и новее`; do not disable Start or hide connection modes.
- [ ] In include-only mode with no effective selected app, disable Start with `Выберите хотя бы одно приложение для подключения через VPN`.
- [ ] While connected, ask for confirmation only when the effective policy hash changes; `Tic + standalone` saves without reconnect.
- [ ] Surface cached/offline state as a warning and never block Start.
- [ ] Run frontend tests:

```bash
pnpm test -- --run
pnpm check
```

- [ ] Run Tauri and Rust tests:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] Commit:

```bash
git add src src-tauri
git commit -m "Добавить настройки split-tunnel в приложение"
```

---

### Task 10: Verify Android Behavior and Document the Contract

**Files:**
- Modify: `README.md`
- Create: `docs/split-tunnel.md`
- Modify: `.github/workflows/ci.yml`

- [ ] Document:
  - supported connection combinations;
  - Android 13+ requirement for split behavior;
  - Android 12 and older full-tunnel fallback without connection restrictions;
  - local-only package inventory and local-network data;
  - five-minute revision and 24-hour full-sync cadence;
  - rollback behavior and panel-offline fallback.
- [ ] Add CI jobs for Rust, frontend, and Android plugin unit tests without building every release artifact.
- [ ] Run formatting:

```bash
cargo fmt --all -- --check
pnpm exec prettier --check "src/**/*.{ts,svelte}"
```

- [ ] Run the complete local suite:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
pnpm test -- --run
pnpm check
./src-tauri/gen/android/gradlew -p src-tauri/gen/android :tauri-plugin-tunnel-android:test
```

- [ ] Build the APK locally:

```bash
pnpm tauri android build --debug
```

- [ ] On an Android 13+ device verify:
  - `Tic + via_tak` exclusion mode;
  - `Tic + via_tak` include-only mode;
  - `Tic + standalone` remains full tunnel;
  - compact address exclusions work without a large `AllowedIPs`;
  - local LAN remains reachable;
  - Wi-Fi change reapplies safely;
  - panel outage keeps cached behavior.
- [ ] On an Android 12-or-older emulator/device verify all three connection combinations start as full tunnel and no split option blocks Start.
- [ ] Confirm diagnostics contain no package inventory, local CIDRs, or WireGuard material.
- [ ] Inspect the final diff for accidental generated APKs, secrets, and unrelated changes:

```bash
git status --short
git diff --check
git diff --stat
rg -n "PrivateKey|access_token|refresh_token|QUERY_ALL_PACKAGES" --glob '!docs/**' .
```

- [ ] Commit documentation and CI:

```bash
git add README.md docs/split-tunnel.md .github/workflows/ci.yml
git commit -m "Завершить первый этап split-tunnel Android"
```
