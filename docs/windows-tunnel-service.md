# Windows tunnel service

Nelomai uses the official WireGuard `embeddable-dll-service` entry point on
Windows. The visible Tauri process remains unprivileged; a LocalSystem service
owns the WireGuard tunnel.

## Installed files

The release installer must place these files in one protected directory below
`%ProgramFiles%\Nelomai`:

- `Nelomai.exe`;
- `nelomai-windows-service.exe`;
- the architecture-matched official WireGuard `tunnel.dll`;
- the architecture-matched official WireGuardNT `wireguard.dll`, required by
  `tunnel.dll`.

The helper rejects installation when it or the visible client is outside
`Program Files`, or when they do not share the same directory. This keeps a
same-user process from replacing the authorized executable without elevation.

The release pipeline must obtain `tunnel.dll` from the official WireGuard
Windows build or release process and `wireguard.dll` from the official
WireGuardNT download source. It records the source version and SHA-256 of both
files. Neither DLL is downloaded at tunnel start.

## One-time installation

The installer invokes:

```powershell
.\scripts\windows\install-tunnel-service.ps1 `
  -ServiceExecutable "C:\Program Files\Nelomai\nelomai-windows-service.exe" `
  -ClientExecutable "C:\Program Files\Nelomai\Nelomai.exe"
```

Windows shows one UAC prompt. The script records the current user's SID before
elevation and installs the automatic `NelomaiTunnelManager` service. Runtime
start, stop, and status operations do not require elevation.

Uninstall with:

```powershell
.\scripts\windows\uninstall-tunnel-service.ps1 `
  -ServiceExecutable "C:\Program Files\Nelomai\nelomai-windows-service.exe"
```

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
2. start a generated test tunnel through `tunnel.dll`;
3. reject a client with another SID and a copied client executable;
4. close the UI and verify that the tunnel remains active;
5. stop the tunnel and verify service, adapter, route, DNS, and config cleanup;
6. record idle CPU, memory, start time, and stop time.

This runtime smoke is deferred by project decision and is not emulated on
macOS.
