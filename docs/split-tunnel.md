# Split tunnel

## Supported connections

Split tunnel changes only the native platform routing policy. The WireGuard
configuration remains opaque to the frontend. On Windows, an active address
split replaces each full-range `AllowedIPs` entry with two fixed half-range
entries so WireGuard for Windows does not enable its blocking firewall mode.
This does not produce an address complement.

| Connection | Split behavior |
| --- | --- |
| Tic through Tak | Apply address rules everywhere and application rules on Android |
| Tic standalone | Apply address rules everywhere and application rules on Android |
| Stray | Apply address rules everywhere and application rules on Android |

Android applies split behavior only on API 33 and newer. Android 12 and older
keep every connection mode available, but always start a normal full tunnel.
The limitation never blocks the Start button.

Windows, Linux, and macOS currently support address rules only. Their
application selectors stay hidden until the separate per-application stage is
implemented.

## Application rules

The panel sends a compact policy with:

- exact mandatory package IDs that must remain outside the tunnel;
- display-name fragments that are suggestions only;
- the user's selected package IDs;
- either `exclude_selected` or `include_selected` mode.

Mandatory packages cannot be removed by the user. A package already matched by
an exact mandatory ID is not repeated as a suggestion. Suggestions use a
case-insensitive display-name match and remain optional. The application list
is read locally on Android and only the packages explicitly selected by the
user are sent to the panel.

`include_selected` requires at least one installed, non-mandatory selected
application. If none is available, the UI explains the problem and disables
Start until the selection is corrected. In this mode mandatory exclusions are
shown as locked outside the VPN rather than as selected applications.

## Address and local-network rules

The panel sends compact IPv4 CIDRs. Android passes them to `VpnService` route
exclusion. Windows installs direct routes through the physical gateway. Linux
and macOS apply exclusions to the destinations routed over the tunnel. The
peer configuration keeps its original `AllowedIPs`, and excluded traffic
follows the existing OS routes. Linux and macOS check the expanded route
count before applying a policy. Many scattered exclusions can exceed the
16,384-route budget even when the list itself is shorter. The client reserves
space for both VPN peer endpoints and, on macOS, for the two unspecified
addresses that preserve the system defaults. It reports the limit instead of
replacing the running routes with a partial plan. After
a newer authoritative revision is recorded, an automatic reconnect must
not reinstall superseded direct bypasses; a failed new plan does not grant
permission to reuse rules that it may have revoked.

The application also accepts personal IPv4 addresses, domain names, and full
HTTP(S) URLs. For a URL the native core extracts its normalized hostname before
the request; the panel validates the result and retains the same URL parsing as
a defensive fallback for older clients. Path, port, query, and fragment do not
affect routing. The two scopes are explicit:
`Для этого устройства` applies only to the current application device, while
`Для всех моих` is delivered to every application device of the same account.
IPv4 values become `/32` exclusions. Domains are normalized by the panel and
resolved to IPv4 on the device whenever the effective policy is applied; the
normal 24-hour full-policy refresh resolves them again. Resolution is
asynchronous, runs in a bounded parallel batch, and keeps the last successfully
resolved addresses if DNS is temporarily unavailable. A domain without either
a fresh result or a cached result is not silently omitted: the new policy
remains pending and the existing connection keeps its last working routes. A
domain never changes regular panel peer configuration.

`Исключить локальные адреса` is enabled by default. On Android 13 and newer the
user can change it. Desktop systems always keep real Wi-Fi and Ethernet
networks outside the tunnel by using their existing on-link routes; the desktop
UI therefore shows this behavior as fixed instead of offering a switch that
the operating-system route table cannot safely honor. The same networks are
included in the opaque physical-network fingerprint used to detect a network
change. VPN, loopback, multicast, link-local, any-local, IPv6, and host-only
`/32` routes are ignored.

macOS keeps the unspecified IPv4 and IPv6 host addresses outside the tunnel's
route prefixes. XNU treats a route whose destination starts at the all-zero
address as a primary default even with a nonzero prefix length. Preserving the
system default lets the panel socket use its bound physical interface while
ordinary traffic to the same server still follows the tunnel.

On Linux, ordinary WireGuard and AWG3 routes refer to the owned tunnel
interface. The kernel removes them when the helper tears down that interface.
The helper records its identity for same-boot recovery in the root-owned
`ordinary-routing/ordinary-link.json`. macOS journals ordinary tunnel routes in
`ordinary-routing/ordinary-routes.json`. Both paths are under the helper's
runtime directory. Windows records its direct routes in the service-owned
`%ProgramData%\Nelomai\Tunnel\routes-state.json`.

While a desktop tunnel with address exclusions is active, the app checks the
physical network every 30 seconds. The privileged helper returns only a
SHA-256 fingerprint derived from the physical interface, gateway, source
address, and local IPv4 networks. Two matching observations of a changed
fingerprint are required before one serialized local reconnect. A failed probe
never disconnects the tunnel. If the helper cannot stop a still-running tunnel,
the app waits five minutes before retrying instead of repeating the operation
on every poll. The helper protocol version for this operation is 3.

Neither physical network details nor the installed package inventory is
written to diagnostics or uploaded to the panel.

## Synchronization and offline behavior

The native process owns one serialized scheduler:

- revision checks run every five minutes while the user is authenticated;
- a full policy refresh runs no more than once per 24 hours unless the revision
  changes, the administrator forces a revision, or the user requests a forced
  synchronization;
- login and bootstrap schedule an immediate throttled revision check;
- logout and account replacement remove the previous account's cached policy
  and application selection.

A forced synchronization refreshes the local application inventory and asks
the panel for the complete policy. If the effective policy changes while a
tunnel is active, the native core briefly reconnects it. This applies to both
Tic route modes and to Stray.

When the panel is unavailable, the last validated policy remains usable and
the UI shows a warning without blocking Start. An unsupported or invalid new
policy does not replace the previous working policy. Android 13 and newer also
require a successful local application inventory before starting an active
split tunnel, so mandatory package exclusions cannot silently disappear.

Policies without active personal address rules retain format 1 so already
installed clients can continue using their last supported configuration. The
panel emits format 2 as soon as at least one personal address rule is active.
When split-tunnel is globally disabled, stored personal rules are omitted and
the disabled policy uses format 1 so legacy clients can remove old routes. A
client that does not support format 2 keeps the previous working policy and
does not report the new policy as successfully applied.

## Apply and rollback

Policy application is serialized with connection mutations. The native core
stops the current tunnel, starts it once with the new effective options, and
rolls back once to the previous working options if the new start fails. Apply
failures have a one-hour retry cooldown; a new policy or an explicit forced
synchronization may retry immediately. Apply results may be queued locally and
reported later, but diagnostics and frontend responses contain no local CIDRs,
access tokens, or WireGuard material. Diagnostic reports also contain no
installed-package inventory.

## Desktop recovery checks

On Linux, select the ordinary tunnel interface for the active transport.
These commands inspect routing and journal metadata.

```bash
# Linux
interface=nlm-wg0   # Use nlm-awg0 for AWG3.
ip -4 route show table main dev "$interface"
ip -6 route show table main dev "$interface"
sudo ls -l /var/run/nelomai/ordinary-routing/ordinary-link.json

# macOS
sudo route -n get default
sudo ls -l /var/run/nelomai/ordinary-routing/ordinary-routes.json
```

On Windows, inspect routes with metric `42760` and the service-owned state:

```powershell
Get-NetRoute -AddressFamily IPv4 |
  Where-Object RouteMetric -eq 42760
Get-Item "$env:ProgramData\Nelomai\Tunnel\routes-state.json" -ErrorAction SilentlyContinue
```
