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
- The versioned options contract reserves package and route split tunneling.
  Non-empty options are rejected until that feature is implemented.
