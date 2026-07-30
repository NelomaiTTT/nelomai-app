# Nelomai Android tunnel plugin

The plugin binds the shared Rust `TunnelController` to the official WireGuard
Android backend.

- `GoBackend.VpnService` owns the active VPN independently of the WebView.
- Tunnel mutations run on one dedicated executor.
- The system VPN permission is requested only by an explicit user action.
- WireGuard configuration is passed from Rust as bytes and wiped immediately
  after native parsing.
- JavaScript can request permission and read status, but cannot submit tunnel
  configuration or directly start and stop the VPN.
- Android 13 and newer apply package and compact IPv4 split-tunnel rules
  through `VpnService`; Android 12 and older intentionally keep a full tunnel.
- The plugin never expands address rules into a WireGuard `AllowedIPs`
  complement. The original WireGuard configuration remains unchanged.
- Physical local-network routes are discovered in memory and are never sent to
  the panel or diagnostics.
