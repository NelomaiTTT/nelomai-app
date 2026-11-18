# Unix tunnel helper

Nelomai uses one root-owned helper architecture on Linux and macOS:

```text
Tauri application
  -> owner-only Unix socket
nelomai-unix-service (root)
  -> platform WireGuard or AmneziaWG 3 backend, routes and DNS
```

The socket protocol exposes only `start`, `stop`, `status`, and `version`.
Requests are limited to 64 KiB. The helper validates the caller UID before
reading a request and serializes all tunnel changes in one process. The tunnel
configuration is sent in the socket body, never in process arguments. Complete
AWG3 markers select the AWG runtime; ordinary configurations keep the existing
WireGuard backend.

## Linux

An ordinary connection uses kernel WireGuard on `nlm-wg0` or the bundled
`amneziawg-go` runtime on `nlm-awg0`. The helper reads the physical route
tables and checks the route to each peer endpoint. It installs IPv4 and IPv6
routes for the tunnel's share of the peer's allowed addresses in the main
table, using exclusive netlink adds on the owned interface. Peer endpoints,
address exclusions, and more-specific OS routes keep their existing paths.
Both transports check that the standard policy rules select the main table
for each tunnel address family. Start fails if an unsupported rule could
redirect the traffic.

The root-only journal at `/var/run/nelomai/ordinary-routing/ordinary-link.json`
records the boot and interface identity for recovery. On Stop, the helper
verifies ownership and tears down the interface. Linux then removes its routes.
A reserved interface name alone cannot authorize teardown. A surviving
physical route or policy rule matching an old cleanup journal requires
operator review because another process could have replaced it.

In an isolated Linux network namespace, both transports retained their
IPv4 and IPv6 peer, exclusion, and static routes across a same-boot helper
process exit, reopen, and Stop. The physical routing tables and policy rules
matched their initial snapshots after Stop, including a static route replaced
with an identical row while connected. Recovery also preserved a foreign
WireGuard interface created under the former tunnel's name.

The AppImage contains the matching helper. On the first connection after an
install or update, the application opens the system authorization dialog and
installs or updates the root-owned service through `pkexec`. Runtime
connections do not require elevation.

Manual development installation:

```sh
cargo build --release -p nelomai-unix-service
sudo crates/unix-service/install/install-linux.sh \
  "$(id -u)" \
  target/release/nelomai-unix-service \
  "$(command -v amneziawg-go)"
```

The installer creates and starts `nelomai-tunnel.service`. No password is
needed after the one-time installation.

## macOS

macOS uses the official `wireguard-go` userspace implementation for WireGuard
and the pinned bundled `amneziawg-go` runtime for AWG3. On the first connection
after an install or update, the application opens the native administrator
authorization dialog. Its bundled installer copies the helper and both runtime
binaries to a root-owned directory and registers launch daemon
`ru.nelomai.tunnel`.

Manual development installation:

```sh
cargo build --release -p nelomai-unix-service
sudo crates/unix-service/install/install-macos.sh \
  "$(id -u)" \
  target/release/nelomai-unix-service \
  "$(command -v wireguard-go)" \
  "$(command -v amneziawg-go)"
```

For an ordinary macOS tunnel that overrides DNS, the helper records the
explicit server lists and a write intent in `/var/run/nelomai/dns-state.json`
with mode `0600`. It writes the servers and a receipt in one
SystemConfiguration transaction. Stop and recovery restore only services
that still have the servers written by that transaction. Search domains
remain unchanged. Data routes attach to the owned `utun` interfaces; peer
endpoints keep using the system's existing physical routes.

The app may remain unsigned or ad-hoc signed. macOS will still request the
administrator password during this one-time helper installation.

## Release gates

- Run real WireGuard and AWG3 tunnels through the installed Linux helper.
- Run real WireGuard and AWG3 tunnels through the installed macOS launch daemon.
- Verify DNS and the default route before start and after stop.
- Kill and restart the helper while connected and verify recovery.
- Confirm that a process under another UID cannot connect to the socket.
