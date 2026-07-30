# Split-Tunnel Desktop Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply compact IPv4 address exclusions on Windows, Linux, and macOS through privileged native routing while keeping WireGuard configurations small and preserving reliable stop, rollback, and crash recovery.

**Architecture:** The shared core from the Android plan passes a `TunnelStartRequest` containing raw WireGuard configuration plus validated compact exclusions. Version-2 desktop helper protocols carry those options to the existing trusted helper/service. Each platform captures its physical egress before starting WireGuard, installs only Nelomai-owned direct routes, persists enough non-secret state for exact cleanup, and removes those routes during Stop or startup recovery. Desktop application-based split tunneling remains out of the first stage.

**Tech Stack:** Rust 1.88, Tokio, Serde, Tauri 2, `windows-sys` IP Helper API, `rtnetlink` on Linux, fixed-path `/sbin/route` and macOS System Configuration commands, WireGuardNT, `defguard-wireguard-rs`, wireguard-go.

## Global Constraints

- Keep native WireGuard `AllowedIPs = 0.0.0.0/0`.
- Never build an address complement and never pass one CIDR per allowed fragment.
- Apply split rules only for `Tic + via_tak` and Stray. `Tic + standalone` gets no Nelomai direct routes.
- Stage one has address exclusions only on desktop. Do not expose non-functional per-application selectors.
- Only the privileged helper may alter the route table.
- Execute fixed trusted binaries directly; never invoke a shell or interpolate command strings.
- Persist no WireGuard private keys, access tokens, or package lists. Local
  network CIDRs may appear only inside the root/service-owned exact route state
  required for crash cleanup; they never enter diagnostics or panel requests.
- A failed route operation must not leave a half-started tunnel or stale Nelomai routes.
- Cleanup deletes only exact routes created by Nelomai.
- Cached policy and panel unavailability behavior are owned by the shared-core plan.
- Commit messages are in Russian.
- Do not push or deploy without a direct user command.

---

### Task 1: Upgrade Both Helper Protocols to Version 2

**Files:**
- Modify: `crates/unix-service/src/lib.rs`
- Modify: `crates/unix-service/tests/helper.rs`
- Modify: `crates/unix-service/tests/socket.rs`
- Modify: `crates/windows-service/src/lib.rs`
- Modify: `crates/windows-service/tests/protocol.rs`
- Modify: `crates/windows-service/tests/service.rs`
- Modify: `src-tauri/src/platform/unix.rs`
- Modify: `src-tauri/src/platform/windows.rs`

- [ ] Add failing serialization and compatibility tests for `PROTOCOL_VERSION = 2`.
- [ ] Change both `Request::Start` variants to:

```rust
Start {
    protocol_version: u16,
    configuration: Zeroizing<String>,
    options: DesktopTunnelOptions,
}
```

- [ ] Define a shared wire shape in `nelomai-client-tunnel` and re-export it from both service crates:

```rust
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopTunnelOptions {
    pub excluded_ipv4_cidrs: Vec<String>,
    pub exclude_local_networks: bool,
    pub policy_hash: Option<String>,
}
```

- [ ] Keep application package fields out of the desktop protocol.
- [ ] Increase both `MAX_FRAME_SIZE` constants from `64 KiB` to `1 MiB`, while retaining the length-prefix check before allocation.
- [ ] Reject more than 16,384 CIDRs, non-IPv4 entries, non-canonical networks, duplicate entries after normalization, or a policy hash longer than 128 ASCII characters.
- [ ] Implement redacted `Debug` for options and requests: log counts and policy-hash presence, not CIDR contents or configuration.
- [ ] Make a version-1 helper produce the existing `unsupported_protocol` error so the app can display the reinstall-components flow.
- [ ] Update the Tauri controllers to pass `TunnelStartRequest.options`; translate inactive split into `DesktopTunnelOptions::default()`.
- [ ] Run focused tests:

```bash
cargo test -p nelomai-unix-service protocol -- --nocapture
cargo test -p nelomai-windows-service protocol -- --nocapture
```

- [ ] Run all helper tests:

```bash
cargo test -p nelomai-unix-service
cargo test -p nelomai-windows-service
```

- [ ] Commit:

```bash
git add crates/client-tunnel crates/unix-service crates/windows-service src-tauri/src/platform
git commit -m "Обновить протоколы помощников split-tunnel"
```

---

### Task 2: Add a Platform-Neutral Owned-Route Plan

**Files:**
- Create: `crates/client-tunnel/src/routes.rs`
- Modify: `crates/client-tunnel/src/lib.rs`
- Modify: `crates/client-tunnel/Cargo.toml`
- Create: `crates/client-tunnel/tests/routes.rs`

- [ ] Add failing tests for parsing, canonicalizing, sorting, deduplicating, and collapsing adjacent/covered IPv4 exclusions.
- [ ] Define:

```rust
#[derive(Clone, PartialEq, Eq)]
pub struct Ipv4RoutePlan {
    pub policy_hash: Option<String>,
    pub excluded_networks: Vec<Ipv4Net>,
    pub include_local_networks: bool,
}

impl Ipv4RoutePlan {
    pub fn from_options(options: &DesktopTunnelOptions) -> Result<Self, RoutePlanError>;
    pub fn merged_with_local_networks(
        &self,
        local_networks: impl IntoIterator<Item = Ipv4Net>,
    ) -> Result<Self, RoutePlanError>;
}
```

- [ ] Preserve the semantic distinction between no split options and a valid empty exclusion list.
- [ ] Limit post-merge routes to 16,384 and return `route_plan_too_large` before touching the OS.
- [ ] Add tests proving:
  - `10.0.0.0/9` plus `10.128.0.0/9` collapses to `10.0.0.0/8`;
  - `10.0.0.0/8` covers `10.1.0.0/16`;
  - public and private routes are treated identically;
  - no complement of `0.0.0.0/0` is produced.
- [ ] Ensure `Debug` reports route count only.
- [ ] Run tests:

```bash
cargo test -p nelomai-client-tunnel --test routes -- --nocapture
cargo test -p nelomai-client-tunnel
```

- [ ] Commit:

```bash
git add crates/client-tunnel
git commit -m "Добавить компактный план прямых маршрутов"
```

---

### Task 3: Add Helper-Owned Route State and Crash Recovery

**Files:**
- Create: `crates/unix-service/src/routes.rs`
- Modify: `crates/unix-service/src/lib.rs`
- Create: `crates/windows-service/src/routes.rs`
- Modify: `crates/windows-service/src/lib.rs`
- Create: `crates/unix-service/tests/routes.rs`
- Create: `crates/windows-service/tests/routes.rs`

- [ ] Add failing tests for route-state validation and exact cleanup.
- [ ] Define non-secret persisted records:

```rust
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedRoute {
    pub destination: String,
    pub interface_identifier: String,
    pub gateway: Option<String>,
    pub metric: Option<u32>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedRouteState {
    pub format_version: u16,
    pub policy_hash: Option<String>,
    pub routes: Vec<OwnedRoute>,
}
```

- [ ] Store Unix state under the existing root-owned helper runtime directory as `routes-state.json` with mode `0600`.
- [ ] Store Windows state under `%ProgramData%\Nelomai\Tunnel\routes-state.json` with the existing service-owned ACL.
- [ ] Write temporary state atomically before declaring Start successful.
- [ ] Validate owner, regular-file status, size under `1 MiB`, format version, and route count before recovery.
- [ ] Implement redacted `Debug` for route plans and state that reports only counts and policy-hash presence.
- [ ] On helper startup:
  - load state;
  - attempt exact removal of every owned route;
  - retain failed records for the next cleanup attempt;
  - remove the file only after all records are gone.
- [ ] Never perform prefix-wide cleanup or delete routes that do not match destination, interface, gateway, and metric.
- [ ] Add a `RouteBackend` trait so route lifecycle can be tested without root:

```rust
pub trait RouteBackend {
    type Egress;
    fn discover_egress(&self) -> Result<Self::Egress, ServiceError>;
    fn local_networks(&self, egress: &Self::Egress) -> Result<Vec<Ipv4Net>, ServiceError>;
    fn add_route(&self, egress: &Self::Egress, network: Ipv4Net)
        -> Result<OwnedRoute, ServiceError>;
    fn remove_route(&self, route: &OwnedRoute) -> Result<(), ServiceError>;
}
```

- [ ] Run tests:

```bash
cargo test -p nelomai-unix-service routes -- --nocapture
cargo test -p nelomai-windows-service routes -- --nocapture
```

- [ ] Commit:

```bash
git add crates/unix-service crates/windows-service
git commit -m "Добавить учет маршрутов помощников"
```

---

### Task 4: Implement Linux Direct Routes Through Netlink

**Files:**
- Modify: `crates/unix-service/Cargo.toml`
- Create: `crates/unix-service/src/routes/linux.rs`
- Modify: `crates/unix-service/src/routes.rs`
- Modify: `crates/unix-service/src/backend/linux.rs`
- Create: `crates/unix-service/tests/linux_routes.rs`

- [ ] Add failing parser/planner tests using captured netlink route/link fixtures.
- [ ] Add `rtnetlink`, `netlink-packet-route`, and `futures-util` dependencies compatible with Rust 1.88.
- [ ] Discover the pre-tunnel IPv4 egress:
  - enumerate default routes excluding `nlm-wg0`;
  - ignore links marked loopback or down;
  - ignore known virtual link kinds (`wireguard`, `tun`, `tap`, `veth`, `bridge`, `docker`, `tailscale`);
  - choose the lowest metric route with a gateway;
  - retain interface index, gateway, and source address.
- [ ] Discover local networks only from on-link unicast routes on the chosen egress interface.
- [ ] Add direct routes with a reserved Nelomai metric and explicit gateway/interface through netlink.
- [ ] Treat an already-existing exact Nelomai route as idempotent only when all attributes match.
- [ ] Start sequence:
  1. clean stale owned routes;
  2. discover physical egress before WireGuard;
  3. merge panel exclusions and optional actual local networks;
  4. add and record direct routes;
  5. create/configure `nlm-wg0`;
  6. on any failure, remove the interface and exact owned routes.
- [ ] Stop sequence:
  1. remove `nlm-wg0`;
  2. remove exact owned routes;
  3. retain state only for cleanup failures.
- [ ] Ensure status becomes `Failed` when an interface is gone but owned routes remain.
- [ ] Run tests:

```bash
cargo test -p nelomai-unix-service linux_routes -- --nocapture
cargo test -p nelomai-unix-service
```

- [ ] Commit:

```bash
git add crates/unix-service
git commit -m "Добавить маршрутизацию split-tunnel Linux"
```

---

### Task 5: Implement macOS Direct Routes Through the Physical Gateway

**Files:**
- Create: `crates/unix-service/src/routes/macos.rs`
- Modify: `crates/unix-service/src/routes.rs`
- Modify: `crates/unix-service/src/backend/macos.rs`
- Create: `crates/unix-service/tests/macos_routes.rs`

- [ ] Add failing tests for parsing fixed-locale output from:
  - `/sbin/route -n get default`;
  - `/sbin/ifconfig <interface>`;
  - `/usr/sbin/scutil --nwi`.
- [ ] Discover the physical egress before launching wireguard-go:
  - prefer the active IPv4 interface reported by `scutil --nwi`;
  - reject `utun*`, `lo*`, bridge, and tunnel interfaces;
  - resolve its gateway with `/sbin/route -n get -ifscope <interface> default`;
  - fail with `physical_egress_unavailable` instead of guessing.
- [ ] Derive actual local networks only from `inet` address/netmask entries on that interface.
- [ ] Execute only fixed binaries with `LANG=C` and `LC_ALL=C`; pass each argument separately.
- [ ] Add routes using:

```text
/sbin/route -n add -net <cidr> <gateway>
```

and remove only recorded routes using:

```text
/sbin/route -n delete -net <cidr> <gateway>
```

- [ ] Integrate route application before wireguard-go startup and cleanup after interface/DNS teardown.
- [ ] If WireGuard or DNS setup fails, remove newly added routes before returning.
- [ ] Preserve existing endpoint-route and DNS restoration behavior.
- [ ] Add startup recovery tests where DNS, interface, endpoints, and routes have independent stale state.
- [ ] Run tests:

```bash
cargo test -p nelomai-unix-service macos_routes -- --nocapture
cargo test -p nelomai-unix-service
```

- [ ] Perform a local non-destructive parser test on macOS:

```bash
/usr/sbin/scutil --nwi
/sbin/route -n get default
```

- [ ] Commit:

```bash
git add crates/unix-service
git commit -m "Добавить маршрутизацию split-tunnel macOS"
```

---

### Task 6: Implement Windows Direct Routes Through IP Helper

**Files:**
- Modify: `crates/windows-service/Cargo.toml`
- Create: `crates/windows-service/src/windows/routes.rs`
- Modify: `crates/windows-service/src/windows/mod.rs`
- Modify: `crates/windows-service/src/windows/backend.rs`
- Create: `crates/windows-service/tests/windows_routes.rs`

- [ ] Add failing pure tests for Windows route-row conversion and exact identity comparison.
- [ ] Enable only the required `windows-sys` features:
  - `Win32_NetworkManagement_IpHelper`;
  - `Win32_Networking_WinSock`;
  - existing Foundation/System features.
- [ ] Before starting the WireGuard tunnel service, use `GetBestRoute2` for a public probe address to capture the physical interface LUID, index, source, gateway, and metric.
- [ ] Reject loopback, tunnel, and WireGuard adapters; use `GetIfEntry2` to require an operational Ethernet, Wi-Fi, or cellular interface.
- [ ] Enumerate on-link IPv4 prefixes for that interface through `GetIpForwardTable2` when local-network exclusion is enabled.
- [ ] Create each direct route using initialized `MIB_IPFORWARD_ROW2` plus `CreateIpForwardEntry2`, with explicit interface LUID, next hop, destination prefix, and a reserved Nelomai metric.
- [ ] Record the normalized row fields needed for `DeleteIpForwardEntry2`; never delete by destination alone.
- [ ] Treat `ERROR_OBJECT_ALREADY_EXISTS` as success only after the exact row is read back and matches.
- [ ] Integrate sequence:
  1. recover stale route state;
  2. discover physical egress;
  3. add/record routes;
  4. create and start `WireGuardTunnel$Nelomai`;
  5. remove routes and config/service on any failure.
- [ ] Stop the tunnel service before deleting direct routes.
- [ ] Ensure service diagnostics contain stable error codes, not localized OS error messages or CIDR contents.
- [ ] Run cross-platform pure tests locally:

```bash
cargo test -p nelomai-windows-service --tests
```

- [ ] Run a Windows build without executing privileged tests:

```powershell
cargo test -p nelomai-windows-service --no-run
cargo clippy -p nelomai-windows-service --all-targets -- -D warnings
```

- [ ] Commit:

```bash
git add crates/windows-service
git commit -m "Добавить маршрутизацию split-tunnel Windows"
```

---

### Task 7: Detect Physical-Network Changes and Reapply Safely

**Files:**
- Modify: `crates/client-tunnel/src/lib.rs`
- Modify: `crates/unix-service/src/lib.rs`
- Modify: `crates/windows-service/src/lib.rs`
- Modify: `src-tauri/src/platform/unix.rs`
- Modify: `src-tauri/src/platform/windows.rs`
- Modify: `src-tauri/src/lib.rs`
- Modify: `crates/client-core/src/split_tunnel.rs`
- Modify: `crates/client-core/tests/split_tunnel.rs`
- Modify: `crates/unix-service/tests/helper.rs`
- Modify: `crates/windows-service/tests/service.rs`

- [ ] Add protocol command `physical_network_fingerprint` to both helpers.
- [ ] Return only a SHA-256 hash of normalized physical interface identifier, gateway, source, and on-link IPv4 networks; do not return the networks to the unprivileged app.
- [ ] Extend `TunnelController`:

```rust
async fn physical_network_fingerprint(&self) -> Result<Option<String>, TunnelError>;
```

Android returns `None` because its plugin owns the network callback.
- [ ] Add failing core tests for a 30-second desktop watcher active only while a split-enabled tunnel is running.
- [ ] Reapply only when:
  - two consecutive successful fingerprints differ;
  - the effective policy includes local-network exclusion or direct routes whose gateway may change;
  - no other tunnel operation is running.
- [ ] Reuse the common atomic stop/start/rollback path from the Android/shared-core plan.
- [ ] If fingerprint probing fails, keep the current tunnel and retry later; never disconnect solely because probing failed.
- [ ] Suspend the watcher for `Tic + standalone` and when globally disabled.
- [ ] Ensure only one watcher exists and it exits on logout/application shutdown.
- [ ] Run tests:

```bash
cargo test -p nelomai-client-core split_tunnel -- --nocapture
cargo test -p nelomai-unix-service
cargo test -p nelomai-windows-service
```

- [ ] Commit:

```bash
git add crates/client-core crates/client-tunnel crates/unix-service crates/windows-service src-tauri
git commit -m "Добавить обновление маршрутов при смене сети"
```

---

### Task 8: Update Installers and Component Compatibility

**Files:**
- Modify: `crates/unix-service/install/install-linux.sh`
- Modify: `crates/unix-service/install/install-macos.sh`
- Modify: `crates/unix-service/install/install-macos.applescript`
- Modify: `crates/windows-service/src/windows/install.rs`
- Modify: `src-tauri/windows/hooks.nsh`
- Modify: `src-tauri/src/platform/unix.rs`
- Modify: `src-tauri/src/platform/windows.rs`
- Modify: `crates/unix-service/tests/helper.rs`
- Modify: `crates/windows-service/tests/install.rs`

- [ ] Add failing tests proving a protocol-1 helper is reported as outdated and a protocol-2 helper is accepted.
- [ ] Increment helper component versions and ensure installers replace the helper atomically.
- [ ] Preserve existing owner UID/SID and installed-client-path authorization.
- [ ] Ensure helper update/reinstall does not run on every connection after a successful installation.
- [ ] On uninstall, stop the tunnel and perform exact owned-route cleanup before deleting helper files.
- [ ] Keep macOS password prompts limited to install/update/uninstall, not ordinary Start.
- [ ] Keep Windows service automatic and reuse the existing elevation flow only for installation/update.
- [ ] Run installer tests:

```bash
cargo test -p nelomai-unix-service helper -- --nocapture
cargo test -p nelomai-windows-service install -- --nocapture
```

- [ ] Commit:

```bash
git add crates/unix-service/install crates/windows-service src-tauri
git commit -m "Обновить установку компонентов split-tunnel"
```

---

### Task 9: Run Desktop Verification and Document Recovery

**Files:**
- Modify: `docs/split-tunnel.md`
- Modify: `README.md`
- Modify: `.github/workflows/ci.yml`

- [ ] Document:
  - compact route architecture;
  - exact supported combinations;
  - route-state paths and cleanup behavior;
  - no desktop per-app support in stage one;
  - helper protocol version 2;
  - troubleshooting commands that do not reveal secrets.
- [ ] Add Linux helper tests to CI.
- [ ] Keep Windows compilation in a Windows-only workflow and macOS compilation in a macOS-only workflow; do not run privileged route mutations in shared CI.
- [ ] Run formatting and static checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
git diff --check
```

- [ ] Run the complete Rust and frontend suite:

```bash
cargo test --workspace
pnpm test -- --run
pnpm check
```

- [ ] On Linux VM verify:
  - `Tic + via_tak` excluded CIDR uses the physical gateway;
  - `Tic + standalone` creates no Nelomai route;
  - local LAN works when enabled;
  - Stop removes only Nelomai routes;
  - killing/restarting helper recovers stale routes.
- [ ] On this Apple-silicon Mac verify the same cases and confirm ordinary Start does not request an administrator password after helper installation.
- [ ] On the physical Windows machine verify the same cases and inspect the route table before/after Stop.
- [ ] For each platform, simulate a bad policy application and confirm one rollback restores the prior working connection.
- [ ] Confirm panel unavailability starts with cached policy and no connection is blocked.
- [ ] Inspect diagnostics and route-state files for secrets:

```bash
rg -n "PrivateKey|access_token|refresh_token|configuration" \
  /var/run/nelomai "$HOME/Library/Application Support/ru.nelomai.app" 2>/dev/null
```

- [ ] Inspect the final diff and worktree:

```bash
git status --short
git diff --stat
git diff --check
```

- [ ] Commit:

```bash
git add README.md docs/split-tunnel.md .github/workflows/ci.yml
git commit -m "Завершить первый этап split-tunnel desktop"
```
