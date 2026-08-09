# Windows tunnel service

Nelomai uses the official WireGuard `embeddable-dll-service` entry point and
the AmneziaWG 3 tunnel DLL on Windows. The visible Tauri process remains
unprivileged; a LocalSystem service owns the selected tunnel transport.

## Installed files

The release installer must place these files in one protected directory below
`%ProgramFiles%\Nelomai`:

- `Nelomai.exe`;
- `nelomai-windows-service.exe`;
- the architecture-matched official WireGuard `tunnel.dll`;
- the architecture-matched official WireGuardNT `wireguard.dll`, required by
  `tunnel.dll`;
- the pinned official AmneziaWG 3 `amneziawg-tunnel.dll`;
- the architecture-matched official `wintun.dll`, required by the AmneziaWG
  tunnel runtime.

The helper rejects installation when it or the visible client is outside
`Program Files`, or when they do not share the same directory. This keeps a
same-user process from replacing the authorized executable without elevation.

The release pipeline must obtain `tunnel.dll` from the official WireGuard
Windows build or release process, `wireguard.dll` from the official WireGuardNT
download source, and `amneziawg-tunnel.dll` from the pinned official
AmneziaWG Windows source. The same pinned build supplies `wintun.dll` and its
license. The pipeline records the source revisions and SHA-256 values. No DLL
is downloaded at tunnel start.

## Installation

The NSIS release is a per-machine installer. It places the application,
service, and the WireGuard/AmneziaWG libraries in the same protected directory,
records the signed-in desktop user's SID, and starts the automatic
`NelomaiTunnelManager` service. Windows shows a UAC prompt during installation
and updates. Runtime start, stop, and status operations do not require
elevation.

Only one transport tunnel service is active at a time. WireGuard uses
`WireGuardTunnel$Nelomai`; AWG3 uses the separate dollar-free service and
interface name `NelomaiAmneziaWg3`, as required by the AWG runtime. The
uninstaller stops and removes the manager and both possible transport services
with their private runtime state.

## Security boundary

- IPC accepts only `start`, `stop`, `status`, and `version`.
- The named pipe rejects remote clients and has an ACL for LocalSystem,
  administrators, and the installed user's SID.
- The service also verifies the caller's token SID and exact process image
  path before reading the request body.
- WireGuard configuration is bounded to 64 KiB, redacted from `Debug`,
  zeroized in request memory, and stored only below
  `%ProgramData%\Nelomai\Tunnel`.
- The state directory grants access only to LocalSystem and administrators.
- Tunnel configuration is never passed through process arguments.
- Mutating operations are serialized by the single manager service loop.

The application is intentionally usable without a paid code-signing
certificate. Windows may therefore show SmartScreen warnings until the
project gains reputation. Path and ACL validation protect the local privilege
boundary, but they do not replace publisher identity.

## Required Windows smoke

The first Windows alpha still requires a Windows 10/11 runtime check:

1. install and remove both services;
2. start generated WireGuard and AWG3 tunnels through their respective DLLs;
3. reject a client with another SID and a copied client executable;
4. close the UI and verify that the tunnel remains active;
5. stop the tunnel and verify service, adapter, route, DNS, and config cleanup;
6. switch between WireGuard and AWG3 without leaving a stale service or adapter;
7. record idle CPU, memory, start time, and stop time.

This runtime smoke is deferred by project decision and is not emulated on
macOS.
