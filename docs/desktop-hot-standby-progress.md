# Desktop hot-standby — local implementation checkpoint

2026-09-26, existing branch `codex/desktop-redundant-warm`, base6b8aa90.
User approved the design and immediate implementation after the plan. No further
permission to begin is required. This checkpoint is NOT feature completion.

## Implemented

- SessionMembers now fences runtime/session/Start generation, rejects single
 backends and mismatched IPv4/IPv6 VIPs, verifies captured native interface
 identities before metrics/probes/rebind, retains partial-start cleanup and
 tries both members on Stop even when one fails. Subnet addresses cannot add
 unintended connected routes on reserve.
- SessionNetwork composes those members with the route/DNS owner: physical
 endpoint bypass before native Start, primary routes without reserve, standby
 adds only its scoped probe, active IPv4/IPv6 switch with rollback, terminal
 local Stop, both endpoint bypasses repaired before rebind on network change.
 This is native composition code, still not connected to the helper IPC loop.
- Route recovery is read-only until a scoped operation: Stop after an interrupted
 switch removes known remaining routes without recreating a disappeared primary.
 A kernel-removed route no longer prevents promotion to a live reserve.
- macOS WG member now retains rebind peers as AWG does; ordinary single remains
 unchanged. Linux kernel WG rebind still needs an adapter, not falsely reported
 as implemented by retaining those peer records.

- Continuation after user “Тогда продолжай брат”: connected nonblocking DNS
 probes with exact native interface binding, response/timeout validation and no
 unbound fallback; shared transactional route/DNS journal and native macOS
 command adapter; primary-first IPv4/IPv6 route plan keeps reserve probes
 interface-scoped. Private Unix journal checks runtime/session/Start generation.
 These are native building blocks, not an enabled desktop redundant connection.
- Linux kernel-member cleanup retains captured interface index on failure,
 refuses deletion after replacement and verifies absence before dropping owner.
 Host test covers the cleanup decision seam, not a real Linux kernel/backend.

- Task1: deterministic health policy and staggered probe scheduler;22 new tests,
 33 total in client-tunnel. Fresh handshake/probe required for promotion, no
 stale ticket acceptance after network change/Stop/promotion; expired probes
 explicitly returned to the caller. Commit c1b1750.
- Task2 partial: Unix member mode separates interface/runtime paths from the
 single backend and suppresses per-member routing/DNS changes. Linux member
 interface names differ from single and each other; macOS utun state is separate.
- macOS userspace removal cannot use vendor remove_interface: pinned defguard
 0.10.0 wgapi_userspace.rs clears DNS on all services. Members now remove only
 their captured socket identity (root owner + device/inode), wait for interface
 disappearance, and retain cleanup state on error. Replacement/socket ownership
 tests are local Unix sockets, not VPN tests.
- Windows: fixed A/B SCM/config names, addressed start/stop/rebind primitives
 over the existing authenticated engine channel. No caller-selected service
 names or file paths. Ordinary primitive JSON stays unchanged. Slot services
 are on-demand, not boot-started; full engine Stop also cleans their fixed names.
- Windows slot config renderer removes DNS/fixed ListenPort, enforces Table=off,
 keeps peer AllowedIPs/AWG settings, rejects ambiguous structures/hooks. The SCM
 start validates canonical config before starting the slot service. AWG entry
 point accepts only the two fixed slot selectors and exact private config path.

## Remaining, not hidden behind a capability flag

- Task2 finish native policy discovery/factory and durable member lifecycle;
 Linux/Windows network adapters and per-member
 Windows metrics still needed. Verify same-VIP behavior and socket egress per OS.
 The panel gives both members the same configured DNS health target, not a
 dedicated per-slot diagnostic address. A lower route metric alone is not proof
 of standby isolation. Do not enable the feature based only on Table=off.
- Durable session/resource recovery: current member constructors refuse to
 adopt an already running interface (`slot_recovery_requires_owner`). This is
 a temporary safe boundary, not implemented crash recovery. Persisted owner,
 native member identity/recovery and stale-cleanup tests are still needed.
 The new route journal is scope-bound, but is not whole-session crash recovery.
- Task3 helper-owned coordinator, timer/IPC/capabilities and role ACK fencing.
- Task4 foreground/background/quick-action server lifecycle and last-active
 WARM (one hour, reserve released). No desktop WARM wiring exists yet.
- Task5 end-to-end fake lifecycle, whole-workspace/frontend regressions, final
 whole-feature review; later authorized native packet/hardware tests.

## Verification

Latest continuation: **214 tests passed** in client-tunnel + Unix/Windows
services, host Clippy `-D warnings` and Windows MSVC check passed. Includes
16 session/member tests and four extra interrupted-route/recovery regressions.
No actual VPN/network changes or native packet tests. Full workspace and
whole-feature review remain for Task5; Linux native build remains unavailable.

Continuation verification: client-tunnel + Unix/Windows services **193 passed**
(26 new tests in this continuation); host Clippy `-D warnings` and Windows MSVC
cargo check passed again. Native test commands did not install/start any VPN or
change host routes/DNS/firewall. Linux native compilation remains unverified.
This is Task2 partial verification, not a whole-feature verdict.

Safe test commands use `TMPDIR` inside the app project (short path necessary for
macOS Unix-socket SUN_LEN), shared app target cache. No host VPN/firewall/Keychain
changes, installation, production, push or release.

- Previous checkpoint contracts + client-tunnel + Unix/Windows service suites:228 passed,
 including the socket-identity regression (4 Unix slot tests,7 Windows slot
 tests,22 shared health/scheduler tests added). Test log retained in this plan's
 ignored `.superpowers/sdd/2026-09-26-desktop-hot-standby/native-tests.log`.
- Host/macOS Clippy with -D warnings and Windows MSVC cargo check passed.
- Linux cross-check stopped in dependency ring: aarch64-linux-gnu-gcc missing.
 Linux-specific Rust/backend build and native behavior are NOT verified.
- Tests were written RED before implementation. Parent review only, per user
 instruction; this is a partial-stage review, not a release verdict.

Useful code references: pinned upstream defguard_wireguard_rs0.10.0
wgapi_userspace.rs:268–313; Windows TableOff addressconfig.go in the exact WG/AWG
revisions listed in the implementation plan. Windows route preference is metric
based ([Microsoft](https://learn.microsoft.com/en-us/windows-server/networking/technologies/network-subsystem/net-sub-interface-metric)); this does not by itself
establish correct pair isolation.
