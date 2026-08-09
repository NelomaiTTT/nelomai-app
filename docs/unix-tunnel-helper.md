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

Linux uses the kernel WireGuard implementation and netlink for ordinary
connections. AWG3 uses the pinned bundled `amneziawg-go` userspace runtime.
The runtime path does not invoke the `wg` command. The helper owns `nlm-wg0`
for WireGuard or `nlm-awg0` for AWG3, plus routing, fwmark rules, and resolver
changes. AWG3 uses a dedicated policy-routing table and fixed rule priorities;
their root-only recovery state is stored in
`/var/run/nelomai/awg-routes-state.json`. The helper removes only rules that
still match that state and cleans stale rules after an interrupted lifecycle.

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

Before starting `wireguard-go`, the helper stores the current DNS servers and
search domains for every network service in
`/var/run/nelomai/dns-state.json` with mode `0600`. It restores that state when
the tunnel stops and after helper recovery, including configurations that do
not override DNS. Routes are attached to the generated `utun` interface and
the endpoint route is removed explicitly.

The app may remain unsigned or ad-hoc signed. macOS will still request the
administrator password during this one-time helper installation.

## Release gates

- Run real WireGuard and AWG3 tunnels through the installed Linux helper.
- Run real WireGuard and AWG3 tunnels through the installed macOS launch daemon.
- Verify DNS and the default route before start and after stop.
- Kill and restart the helper while connected and verify recovery.
- Confirm that a process under another UID cannot connect to the socket.
