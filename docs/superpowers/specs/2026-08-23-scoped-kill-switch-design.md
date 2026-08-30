# Scoped Kill Switch Design

## Context

Nelomai supports Android, Windows, Linux, and macOS tunnels, personal and
dynamic Tic/Tak connections, Stray, address split tunneling on every platform,
and application split tunneling on Android. A kill switch must prevent an
unexpected tunnel failure from sending traffic that the user intended for the
VPN over the physical network. It must preserve every explicit split-tunnel
exception and must not prevent Nelomai from recovering the connection.

The feature is local to one device. It does not require a panel setting or a
server-side policy.

## Goals

- Add one device-wide kill-switch preference shared by Tic/Tak and Stray.
- Keep the preference disabled until the user explicitly enables it.
- Arm protection only after a tunnel has been successfully established.
- Preserve protection through internal reconnects, network changes, UDP port
  rotation, server replacement, and Tic/Tak-to-Stray switching.
- Block only traffic that would otherwise belong to the VPN.
- Keep application, address, domain, and local-network split exceptions direct.
- Keep Nelomai control traffic available for recovery and diagnostics.
- Remove protection after an explicit user Stop or after the user disables the
  preference.
- Avoid hot or overlapping recovery loops; passive retry remains rate-capped
  until explicit Stop or a terminal failure.
- Leave the device unblocked after an operating-system reboot.

## Non-goals

- Automatically enabling Android's system lockdown mode.
- Preserving a running tunnel or active kill-switch runtime state across an OS
  reboot.
- Adding desktop application split tunneling.
- Changing global firewall defaults or deleting firewall rules not owned by
  Nelomai.
- Making the panel the source of truth for the local preference.
- Supporting iOS.

## Approved semantics

The local preference is a boolean named `kill_switch_enabled`. It defaults to
`false` and persists across application launches and application updates. The
runtime state is not restored after an OS reboot.

The runtime state is one of:

- `off`: no kill-switch enforcement is present;
- `armed`: the tunnel is running and enforcement is already present;
- `blocked`: the protected traffic is blocked while the tunnel is unavailable.

`arming` and `disarming` may exist as private implementation states, but the UI
must expose them as a busy operation rather than as durable states.

The transition rules are:

```text
preference disabled + no tunnel                         -> off
initial start begins                                    -> off
initial start fails before protection is installed      -> off
tunnel starts and protection installs atomically        -> armed
armed tunnel loses its backend or enters an internal
reconnect                                                -> blocked
blocked tunnel recovers                                  -> armed
confirmed user Stop cleanup from armed or blocked        -> off
user disables preference while tunnel is running         -> off, tunnel remains running
user disables preference while blocked                   -> off, failed tunnel is stopped
OS reboot                                                -> off
```

An initial connection is successful only after the tunnel and the platform
enforcement have both completed. If enforcement cannot be installed, the
initial tunnel is stopped and ordinary connectivity remains available.

An explicit Stop differs from an internal reconnect. The tunnel abstraction
must carry this intent so policy refresh, physical-network changes, route
changes, server changes, and recovery cannot accidentally disarm protection.

Each active automatic recovery burst has bounded attempts and remains
`blocked` when it does not recover. The app emits one notification and moves to
a passive retry no more often than once every five minutes while connection
intent remains active. `Retry` may wake one immediate attempt and `Stop` cancels
the intent. Attempts are serialized and the app must not start a hot or
overlapping reconnect loop.

`connection_intent_status` refines these transitions without adding a new
firewall state. While it is `recovering`, a previously `armed` session remains
`blocked`; internal lease cleanup, restart, replacement, and passive backoff do
not disarm it. `blocked_terminal` stops automatic retries but preserves the
same recovery context and `blocked` enforcement. `Повторить` may begin a new
bounded recovery attempt after the required action. Within automatic-recovery
state transitions, only a user-requested Stop whose existing tunnel and
enforcement cleanup has been confirmed may transition the kill switch to
`off`. Separately, explicitly disabling the kill-switch preference remains an
approved user transition to `off` under the rules above. A terminal failure,
cancellation callback, failed cleanup, or coordinator shutdown alone must not
do so.

## Rule precedence

The effective precedence from strongest exemption to final block is:

1. Nelomai control traffic required to maintain or recover the connection.
2. Android applications explicitly outside the tunnel.
3. Explicit address, domain, and local-network split exclusions.
4. Traffic routed over the active VPN interface.
5. Every other protected flow is blocked while enforcement is active.

For Android `exclude_selected`, every disallowed application remains direct.
For Android `include_selected`, only the selected applications are protected;
unselected applications remain direct. Exact mandatory package exclusions
from panel policy have the same precedence as user-selected exclusions.

The Nelomai Android package is control-plane traffic and is never included in
the protected application set. On desktop, control-plane exceptions are
restricted by executable identity where supported and otherwise by the last
known panel addresses and destination ports. System-wide DNS bypass is not
permitted.

## Shared architecture

`nelomai-client-tunnel` owns the platform-neutral types:

```rust
pub enum KillSwitchState {
    Off,
    Armed,
    Blocked,
}

pub enum TunnelStopIntent {
    User,
    Reconnect,
}

pub struct TunnelRuntimeStatus {
    pub tunnel: TunnelStatus,
    pub kill_switch: KillSwitchState,
}
```

`TunnelOptions` and `DesktopTunnelOptions` carry
`kill_switch_enabled: bool`. `TunnelController` exposes runtime status, a
stop operation with `TunnelStopIntent`, and a method that changes the
preference's enforcement for an already-running tunnel without rebuilding it.

The native application core remains the coordinator. The privileged platform
component is the source of truth for runtime enforcement. The UI must never
claim `armed` based only on the saved preference.

Every platform operation is serialized with start, stop, rebind, and split
policy changes. Enabling or disabling the setting while a mutation is already
running returns the existing stable busy error instead of racing the mutation.

## Android

Android uses an application-scoped blackhole VPN rather than Android's global
lockdown setting.

- A successful start records `armed` before returning success to Rust.
- A backend failure keeps the existing TUN when possible.
- When the backend must be destroyed, the service establishes a replacement
  blackhole TUN with the same addresses, routes, DNS configuration, allowed or
  disallowed application list, and route exclusions before closing the old
  backend.
- Recovery establishes the replacement working tunnel before closing the
  blackhole descriptor.
- The blackhole descriptor is owned by the `:vpn` foreground service and is
  closed only after recovery, explicit Stop, preference disable, VPN revoke, or
  service teardown.
- The existing quick tile and background reconnect path query the same runtime
  state and never treat `blocked` as `stopped`.

Android cannot guarantee this scoped behavior after the operating system
fully destroys the `:vpn` process. The UI may display the separately detected
system Always-on/lockdown state, but this design does not enable it and does
not present it as equivalent to the scoped switch.

## Windows

The LocalSystem manager service owns a dedicated Windows Filtering Platform
provider and sublayer. It installs only Nelomai filters and never changes the
global Windows Firewall profile.

The WFP policy permits:

- loopback and required network control traffic;
- output through the active tunnel interface;
- the pinned VPN endpoint on the physical interface;
- explicit split and local-network destinations;
- the installed and path-validated Nelomai client/service control traffic.

It blocks other protected outbound IPv4 and IPv6 traffic over physical
interfaces. Filter keys, current boot identity, state, allowed destinations,
and the owning session are stored in the existing protected service state
directory. A service restart during the same boot reconciles the filters. A
new OS boot removes stale filters before accepting client operations and starts
in `off`.

The WFP implementation uses user-mode filters and does not add a kernel driver.

## Linux

The root helper owns an `inet` nftables table named `nelomai_killswitch` and a
serialized root-owned state file below `/var/run/nelomai`.

The output chain permits loopback, the tunnel interface, endpoint traffic,
explicit split/local destinations, and cached panel control addresses. It
drops other protected physical egress. Rule installation and deletion are
performed as atomic nft transactions. Existing non-Nelomai tables are never
flushed or rewritten.

The table survives a helper restart during the same boot and disappears on an
OS reboot. Helper startup reconciles only rules bearing Nelomai's table and
state identity.

## macOS

The launch daemon owns the PF anchor `com.apple/nelomai` under the standard
`com.apple/*` anchor point present in the default `/etc/pf.conf`.

The anchor permits loopback, the active `utun` interface, endpoint traffic,
explicit split/local destinations, and cached panel control addresses, then
blocks other protected physical egress. The helper enables PF with `pfctl -E`,
stores its own enable reference token in `/var/run/nelomai`, and releases only
that token. It never flushes the global PF ruleset or disables PF on behalf of
other components.

The anchor and token are reconciled after a launch-daemon restart during the
same boot. They are not restored after an OS reboot.

## Control-plane recovery

Before arming desktop enforcement, the app records the current numeric VPN
endpoint and a bounded set of successfully resolved panel IP addresses. During
`blocked`, the API client connects to a cached panel IP while preserving the
original HTTPS hostname and certificate verification. This supports session
refresh, dynamic lease replacement, diagnostics, and retry without opening
system DNS.

The cached address set is refreshed while connectivity is healthy. It contains
addresses only, no credentials, and uses the same protected local storage as
other non-secret runtime state. If all cached addresses become stale while the
tunnel is unavailable, recovery fails closed and the user can press Stop to
restore ordinary networking.

Android excludes the Nelomai package from the protected application set, so
its API, FCM, updater, and diagnostic traffic can use the underlying network
without a special DNS exception.

## UI and messages

The settings UI contains one device-wide switch, disabled by default. Enabling
it while disconnected changes only the saved preference. Enabling it while
connected arms the current tunnel without reconnecting. Disabling it while
connected removes enforcement without reconnecting.

The connection card displays:

- no additional status for `off`;
- `Kill switch включён` for `armed`;
- `Интернет заблокирован до восстановления VPN` for `blocked`.

The blocked notification and card expose:

- `Повторить` — wake one immediate bounded recovery attempt without creating a
  parallel operation;
- `Стоп` — explicitly stop the session, remove enforcement, and restore direct
  connectivity.

For a transient failure, passive retry continues at the capped interval without
requiring `Повторить`. For a terminal failure, automatic retry stops and the
connection intent becomes `blocked_terminal`; the card remains `blocked`,
explains the required action, and keeps both
`Повторить` for use after the action and `Стоп` until enforcement is explicitly
removed.

An enforcement installation failure during initial start uses:

`Не удалось включить защиту от утечки. VPN не запущен, интернет работает напрямую. Попробуйте снова или выключите kill switch в настройках.`

## Diagnostics

Diagnostics record state transitions and outcomes without IP addresses,
package IDs, tunnel configuration, or credentials:

- `kill_switch.arm_started`, `armed`, `arm_failed`;
- `kill_switch.blocked`, with the tunnel failure code;
- `kill_switch.recovery_started`, `recovered`, `recovery_slow`,
  `recovery_terminal`;
- `kill_switch.disarm_started`, `disarmed`, `disarm_failed`;
- platform reconciliation and stale-state cleanup results;
- counts of application/address exemptions, never their values.

One automatic diagnostic report is queued when entering `blocked` and another
when recovery succeeds, first enters passive slow recovery, or becomes
terminal. Existing report deduplication and rate limits remain in force.

## Security and failure handling

- Platform state files remain root/System-owned, bounded, canonical, and
  atomically replaced.
- Every firewall object has a fixed Nelomai namespace and an exact stored
  identity before it can be removed.
- Failure to install enforcement rolls back the initial tunnel and leaves the
  network unblocked.
- Failure to remove enforcement after an explicit Stop is visible and
  retryable; the app must not report ordinary connectivity until the platform
  confirms removal.
- Internal reconnect failure remains fail-closed in `blocked`.
- Logout is an explicit user operation and uses `TunnelStopIntent::User` before
  credentials are cleared.
- Application update shutdown uses the same explicit Stop path. It does not
  preserve runtime enforcement across the update.

## Acceptance criteria

- Initial start failure never leaves the device blocked.
- No protected direct packet is observable between an armed tunnel failure and
  entry into `blocked` on desktop.
- Android preserves scoped routing while the `:vpn` process remains alive.
- Every explicit application/address/domain/local exclusion remains usable
  while blocked.
- Nelomai can obtain a replacement dynamic lease while blocked.
- Internal reconnect never disarms protection.
- Explicit Stop always attempts to remove protection and reports removal
  failure instead of claiming success.
- Enabling/disabling while connected does not restart the tunnel.
- Slow recovery produces one notification, serialized passive retry no more
  often than once every five minutes, and no hot or overlapping reconnect loop.
- Terminal recovery remains `blocked` with an available explicit `Stop` until
  enforcement removal is confirmed; `blocked_terminal` itself never disarms it.
- Reboot starts with tunnel off and kill switch runtime state off.
- Existing split-tunnel, quick tile, updater, diagnostics, and AWG3 recovery
  tests continue to pass.
