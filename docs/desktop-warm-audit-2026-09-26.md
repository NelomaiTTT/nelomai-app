# Desktop WARM: prerequisite audit

Update 26.09.2026: the user clarified that full desktop hot-standby was already
authorized, not only WARM. The authorization blocker below was a mistaken reading
and is superseded. Technical findings remain valid. Work continues in this same
local branch; see `superpowers/specs/2026-09-26-desktop-hot-standby-design.md`.

Base: main 6b8aa90 (candidate0.3.3), read-only code audit, no device test.

The premise that desktop already runs two hot-standby tunnels is false in this
source. Do not enable redundant WARM by merely setting a request flag.

Evidence:

- `src-tauri/src/commands.rs::app_start` reads `use_reserve_connection` only
  under `cfg(target_os="android")`. Desktop delegates to DesktopConnectionIntent;
  Android explicitly calls `start_recovery_v2` for reserve-enabled starts.
- UnixTunnelController and WindowsTunnelController Start serialize one
  configuration and DesktopTunnelOptions to their respective helper services.
- RedundantTunnelStart exists in shared contracts; Android native coordinator
  owns its lifecycle, probes, role reporting, standby and session Stop. Shared
  types alone do not implement desktop native ownership.
- Ordinary desktop single-lease Stop already accepts WARM. It is not the requested
  last-active-member WARM of a two-member session.

User clarified: if two tunnels already exist, implement only WARM. That condition
is not met. This branch records the blocker without silently implementing a new
desktop hot-standby subsystem or changing single-lease behavior. No product code
changed; no remote branch.

Required next decision: authorize full desktop hot-standby first, including native
two-interface routing/health/role ownership and durable session Stop, or defer it.
After that, reuse existing server warm_stop_v1 negotiation: retain only the last
active member for one hour, release standby, acquire fresh standby on next Start.
Tests must cover failover-before-Stop (memberB kept), stale role/ACK, stop retry,
logout/update (full cleanup), unsupported server fallback and retained-peer reuse.
