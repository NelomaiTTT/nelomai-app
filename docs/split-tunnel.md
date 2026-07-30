# Split tunnel

## Supported connections

Split tunnel changes only the native platform routing policy. The WireGuard
configuration remains opaque to the frontend and its `AllowedIPs` are not
rewritten or expanded.

| Connection | Split behavior |
| --- | --- |
| Tic through Tak | Apply the selected application and address rules |
| Tic standalone | Always use a full tunnel |
| Stray | Apply the selected application and address rules |

Android applies split behavior only on API 33 and newer. Android 12 and older
keep every connection mode available, but always start a normal full tunnel.
The limitation never blocks the Start button.

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
Start until the selection is corrected.

## Address and local-network rules

The panel sends compact IPv4 CIDRs. Android passes them to `VpnService` route
exclusion and does not produce a large inverse `AllowedIPs` list.

`Исключить локальные адреса` is enabled by default. While split tunnel is
active, Android discovers real Wi-Fi, cellular, and Ethernet link routes in
memory and merges them with the panel exclusions. VPN, loopback, multicast,
link-local, any-local, IPv6, and host-only `/32` routes are ignored. A physical
network change is debounced before one serialized reconnect. Neither the
discovered networks nor the installed package inventory is written to
diagnostics or uploaded to the panel.

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
tunnel is active, the native core briefly reconnects it. `Tic + standalone`
never reconnects for split settings because its effective policy is always a
full tunnel.

When the panel is unavailable, the last validated policy remains usable and
the UI shows a warning without blocking Start. An unsupported or invalid new
policy does not replace the previous working policy.

## Apply and rollback

Policy application is serialized with connection mutations. The native core
stops the current tunnel, starts it once with the new effective options, and
rolls back once to the previous working options if the new start fails. Apply
results may be queued locally and reported later, but diagnostics and frontend
responses contain no local CIDRs, access tokens, or WireGuard material.
Diagnostic reports also contain no installed-package inventory.
