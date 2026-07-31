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
exclusion. Desktop helpers install direct routes through the physical gateway.
Neither implementation produces a large inverse `AllowedIPs` list.

`Исключить локальные адреса` is enabled by default. On Android 13 and newer the
user can change it. Desktop systems always keep real Wi-Fi and Ethernet
networks outside the tunnel by using their existing on-link routes; the desktop
UI therefore shows this behavior as fixed instead of offering a switch that
the operating-system route table cannot safely honor. The same networks are
included in the opaque physical-network fingerprint used to detect a network
change. VPN, loopback, multicast, link-local, any-local, IPv6, and host-only
`/32` routes are ignored.

Desktop helpers own every direct route they create. Linux and macOS persist
non-secret cleanup state in their root-owned runtime directory as
`routes-state.json` with mode `0600`. Windows stores equivalent service-owned
state in `%ProgramData%\Nelomai\Tunnel\routes-state.json`. Stop, uninstall, and
startup recovery remove only the exact recorded routes.

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

The following commands show only Nelomai-owned state and do not print
WireGuard configuration or access tokens:

```bash
# Linux
sudo ip -4 route show metric 42760
sudo ls -l /var/run/nelomai/routes-state.json

# macOS
sudo route -n get default
sudo ls -l /var/run/nelomai/routes-state.json
```

On Windows, inspect routes with metric `42760` and the service-owned state:

```powershell
Get-NetRoute -AddressFamily IPv4 |
  Where-Object RouteMetric -eq 42760
Get-Item "$env:ProgramData\Nelomai\Tunnel\routes-state.json" -ErrorAction SilentlyContinue
```
