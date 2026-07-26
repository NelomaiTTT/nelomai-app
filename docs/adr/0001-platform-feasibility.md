# ADR 0001: Platform feasibility

- Status: Accepted with deferred Windows validation
- Date: 2026-07-25
- Task profile: GPT-5.6 Sol, reasoning High

## Context

Nelomai App targets Android, Windows, macOS, and Linux. It must control
WireGuard with low idle overhead, keep private keys out of process arguments,
and allow a tunnel to outlive the visible UI. macOS must work without an Apple
Developer ID.

This spike intentionally uses generated documentation-range addresses and
ephemeral keys. It does not use panel APIs, production endpoints, or user
peers.

Host used for local measurements:

- Apple M5, macOS 26.5.2;
- Rust 1.97.1, Go 1.26.5, Java 17;
- Tauri 2.11.5;
- WireGuard tools 1.0.20260223;
- wireguard-go 0.0.20250522.

## Decision

Keep Tauri 2, Rust, and platform-native WireGuard backends.

- Android uses the official WireGuard Android tunnel library and `VpnService`.
- Linux uses kernel WireGuard through a root-owned helper and netlink. Calling
  the `wg` CLI is acceptable for diagnostics, not for the final runtime path.
- macOS uses bundled `wireguard-go` through a manually installed root-owned
  launchd helper. The app itself can remain unsigned or ad-hoc signed.
- Windows is intended to use the official WireGuard
  `embeddable-dll-service`, controlled by a Windows service with a
  current-user/admin-only named-pipe ACL.

Task 0 is accepted. By the project owner's decision on 2026-07-26, the real
Windows 10/11 runtime smoke is deferred until the first Windows implementation
is available and does not block contract or panel API work. The macOS
root-helper installation still needs one manual administrator-authorized
end-to-end run before the first macOS release.

## Results

### Android: pass

Environment:

- Android 35 Google APIs arm64 emulator;
- Android SDK 36, build tools 35/36, NDK 28.2;
- `com.wireguard.android:tunnel:1.0.20260102`;
- backend version reported by the library: `f333402`.

Observed behavior:

- the system VPN permission dialog opened and permission was granted;
- the official `libwg-go.so` loaded successfully;
- the smoke tunnel started in 46-103 ms across repeated runs and stopped in
  21 ms;
- Android `vpn_management` reported `ru.nelomai.client` as the active VPN with
  session `nelomai-spike`;
- after the Activity moved to `STOPPED`, the VPN service remained active;
- the app process became a background foreground-service process with 0% CPU;
- active-tunnel PSS was about 129 MB and RSS about 255 MB in a debug emulator
  build. The WebView shell dominates this value; stopping the tunnel did not
  materially change it.

The first start attempt exposed a real integration requirement:
`GoBackend.setState()` must not run on the Android UI thread. Moving tunnel
operations to a single-thread executor fixed the failure.

The smoke keys are generated inside Kotlin memory. They are not passed through
JavaScript or command-line arguments.

### Linux: pass

A disposable local arm64 Ubuntu 26.04 VM with kernel 7.0 was used. Two isolated
network namespaces were connected by a veth underlay and separate kernel
WireGuard interfaces.

Observed behavior:

- kernel WireGuard loaded successfully;
- the peers completed a real handshake;
- three encrypted overlay pings succeeded with no packet loss;
- first response arrived 6 ms after bringing up the WireGuard interfaces;
- deleting both WireGuard interfaces took 118 ms;
- transfer counters increased in both directions;
- namespaces and ephemeral keys were removed after the run.

Ubuntu 26.04 applies an AppArmor profile to `/usr/bin/wg` and only permits
configuration/key files below `/etc/wireguard/**`. This is another reason for
the final helper to use netlink directly instead of spawning `wg`.

The Unix helper prototype compiles for both `x86_64-unknown-linux-gnu` and
`aarch64-unknown-linux-gnu`.

### macOS: fallback accepted, end-to-end root run pending

The desktop Tauri debug build starts successfully. At idle it measured:

- 0% CPU;
- 24.1 MB physical footprint, 27.3 MB peak;
- about 107 MB RSS when shared system frameworks are included.

The installed `wireguard-go` binary supports Darwin arm64, but an ordinary
unsigned process cannot create `utun`:

```text
Failed to create TUN device: operation not permitted
```

Therefore the accepted no-Developer-ID path is a one-time, manually authorized
installation of a root-owned launchd helper. The helper owns `utun`,
`wireguard-go`, routes, and DNS state; the Tauri UI remains unprivileged.

The helper security prototype proves the local boundary used by that design:

- Unix socket mode is `0600`;
- macOS obtains the caller UID from `getpeereid`;
- Linux obtains it from `SO_PEERCRED`;
- a UID other than the configured owner is rejected;
- tunnel configuration is redacted from Rust `Debug`;
- the in-memory configuration is explicitly zeroized when its request drops;
- the configuration travels in the socket body, never in process arguments.

Five helper unit tests pass, including peer-UID rejection, strict command
parsing, redaction, and socket-body transport. A live local socket request also
passed. Creating the actual `utun` was not tested because the current session
has no passwordless administrator authorization.

### Windows: runtime pending

The official WireGuard Windows source contains the maintained
`embeddable-dll-service` example and `WireGuardTunnelService` entry point.
That is the selected backend.

No Windows host or VM is connected to this workspace, so this spike does not
claim that service installation, Wintun loading, named-pipe ACLs, or tunnel
survival have been tested. Before the first Windows alpha build is distributed,
a Windows 10/11 runner must verify:

1. install and remove the helper service;
2. bring up a generated smoke tunnel through `tunnel.dll`;
3. reject a named-pipe client with another SID;
4. close the UI while the service keeps the tunnel;
5. stop the tunnel and verify adapter/service cleanup;
6. record idle memory, CPU, start time, and stop time.

## Security boundary

The final desktop process split is:

```text
Tauri UI (user)
  -> authenticated local IPC
root/SYSTEM helper
  -> platform WireGuard backend
```

The helper must accept a small typed command set, validate the OS peer
credential before parsing a request, serialize mutating operations, and avoid
shell execution. Private keys must be held in locked/zeroized native memory
where practical and must never enter logs, URLs, JavaScript state, environment
variables, or process arguments.

Android remains platform-native: `VpnService` owns the tunnel and the app only
invokes typed plugin commands.

## Consequences

- The shared stack is viable and has low desktop idle overhead.
- Android and Linux have real tunnel proof.
- macOS cannot be a zero-install portable app without Developer ID; the helper
  installation is an explicit product requirement.
- Windows runtime validation remains a Windows alpha-release gate, but does not
  block shared contracts or panel API implementation.
- The diagnostic UI and smoke commands must be removed or compiled out before
  a production build.
