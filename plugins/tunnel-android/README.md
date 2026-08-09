# Nelomai Android tunnel plugin

The plugin binds the shared Rust `TunnelController` to the official
AmneziaWG Android backend. The backend accepts both regular WireGuard and AWG3
configurations, so Android keeps one VPN service while each panel connection
selects its transport explicitly.

The source is pinned to upstream `v3.0.1`
(`f82900455f1aceaa85658686dc2c5e32c2c42a73`) as the recursive
`vendor/amneziawg-android` submodule.
The matching AmneziaWG Go backend is pinned to `v3.0.1`
(`9f5d948bc72cc554791cfe0fb91527e4acfb6b79`) in
`vendor/amneziawg-go`. The repository-root `go.work` makes the upstream native
wrapper resolve that local tree instead of downloading the declared module.
CI and release builds verify the resolved module directory, and the workspace
file is included in every corresponding-source archive.
Clone and CI checkouts must initialize submodules recursively; the local
`plugins/amneziawg-android-tunnel` Gradle wrapper builds the upstream tunnel
library and native Go backend for Nelomai's application ID.

- `GoBackend.VpnService` owns the active VPN independently of the WebView.
- The Quick Settings tile talks directly to the native tunnel runtime and never
  starts the Tauri activity. The last usable plan is encrypted with Android
  Keystore; dynamic plans retain their panel-provided expiry.
- Tunnel mutations run on one dedicated executor.
- The system VPN permission is requested only by an explicit user action.
- WireGuard or AWG3 configuration is passed from Rust as bytes and wiped
  immediately after native parsing.
- JavaScript can request permission and read status, but cannot submit tunnel
  configuration or directly start and stop the VPN.
- Android 13 and newer apply package and compact IPv4 split-tunnel rules
  through `VpnService`; Android 12 and older intentionally keep a full tunnel.
- The plugin never expands address rules into an `AllowedIPs` complement. The
  original transport configuration, including AWG3 obfuscation parameters,
  remains unchanged.
- Physical local-network routes are discovered in memory and are never sent to
  the panel or diagnostics.
- The Nelomai package itself stays outside its VPN so authentication,
  diagnostics, and update control traffic remain available while connected.
