# Desktop hot-standby — local implementation checkpoint

## 2026-09-27 Windows rebind failure outcomes

The review's remaining three stuck-Running cases (pair journal failure, native
rebind failure, and failure to persist the new Running owner) were reproduced
in a permanent composed actor/pair/MemberOwner test before the fix.

- A failed rebind now requires verification on the existing integrity tick
  before another discovery/rebind. Existing guard reconciliation, exact guard
  readback, proven usable owners and durable pair state allow safe retry.
  An incomplete native restart or unproven state instead takes the existing
  close/driver Stop path and emits the existing stalled recovery signal. No
  new timer, server path or relaxed owner verification was introduced.
- Fourteen fault/control cases cover primary and reserve writes, lost ACKs,
  native restart, guard failures and persistent storage outage with exact
  PrepareRecoveryStop completion. Additional negative cases retain foreign
  process/config/owner resources and cleanup journals. The OS Stop fake now
  models the real adapter's exact observation check; real MemberOwner still
  decides cleanup authority, including interrupted live-owner operations.
- Fresh verification: pair tests42/42; full Rust workspace/doctests exit0
  (1930 reported passes across110 suites including nested child output; one
  pre-existing real-panel fixture ignored). Host workspace/all-targets and
  Windows MSVC/all-targets Clippy with warnings denied passed; diff check clean.
  Evidence: .tmp/rebind-errors-{red,focused,workspace,host-clippy,windows-clippy}.log.

Local only, no commit/push/install/production or hardware changes. This fixes
the reviewed error paths; it does not constitute native hardware acceptance.

## 2026-09-27 Windows actor rebind retry follow-up

The next review reproduced two actor-level deadlocks: a transient route cleanup
failure fenced the pair and then prevented physical discovery from scheduling a
retry; an owned reserve crash before NetworkChanged left readiness suspended
while Core needed primary readiness to retire that reserve. Both repros were
moved into permanent tests and failed against the pre-fix implementation.

- Read-only physical discovery now accepts an installed, fully acknowledged,
  permit-free blocking guard with exact native readback. Missing/foreign guard,
  residual probe permits and pending guard transactions still reject discovery.
  This does not enable traffic or adopt an unknown WFP state.
- Rebind proves the selected member live and all member identities before
  mutations. Under the existing fence it finishes exact Stop of a proven absent
  inactive member, preserves its journal for normal retirement, and rebinds only
  live members. No new timers, server paths, or recovery subsystem.
- Pair suite40 passed, including actor retries after route/SCM cleanup faults,
  both absent and installed-stopped SCM reserves, and six negative guard cases.
  Host workspace and Windows MSVC all-targets Clippy-Dwarnings passed.
  Full Rust workspace including doctests passed (exit0), with one pre-existing
  real-panel fixture ignored; see `.tmp/rebind-retry-*.log`.

No push, merge, install, production changes or hardware tests.

## 2026-09-27 Windows retirement/rebind follow-up

Both subsequent review findings reproduced in retained-owner regressions before
the fix: absent reserve removal stopped the healthy primary, and physical rebind
after A-to-B failover rejected the durably retired A with `Pending`.

- Reserve removal now fences permits, completes exact owned retirement and
  refreshes its retained proof before route/DNS cleanup of an absent interface.
  The live-reserve path still restores DNS before native Stop. The existing
  Windows `current` adapter updates route proofs before the removal transaction;
  foreign identity and failed cleanup are not treated as absence.
- Rebind uses the proven live member set and separately proves retired members
  absent. It neither restarts retired members nor opens their probe sockets.
  Journals remain until ordinary member cleanup. Promotion and removal share
  the same small retirement helper; no new service or server backend.
- Four new regressions cover cleanup/replacement, rebind after promotion,
  foreign/unproven identities and cleanup/storage failures. The composed actor
  test also changes the physical network before the UI removes retired A and
  verifies B health resumes autonomously. Focused pair suite:37 passed.
- Host workspace/all-targets and Windows MSVC/all-targets Clippy with warnings
  denied passed (`.tmp/windows-retirement-{host,cross}-clippy.log`). Full workspace
  tests including doctests passed, exit0 (`.tmp/windows-retirement-workspace.log`);
  one pre-existing real-panel fixture remains explicitly ignored.

Local only; no commit, push, installation, hardware tests or production changes.

## 2026-09-27 review fixes after c430d25

Local, uncommitted follow-up; no push, installation, hardware testing or panel
changes. The server backend remains the existing Android-compatible redundancy
service/API: desktop uses access-token routes; Android's background-token wrapper
calls the same services (with its existing unmeasured-selection allowance).

- Physical discovery no longer interprets a proven vanished VPN member as loss
  of the physical network. Unix tests compose actor/health/native pair/route CAS;
  Windows tests compose actor/pair/real MemberOwner with fake OS I/O. Windows
  promotion retires only the exact stopped/absent old member through existing
  Stop, withdraws its probe permits before releasing sockets, excludes it from
  new routes and skips DNS writes to its absent interface. A foreign identity,
  failed cleanup or journal failure still prevents promotion.
- Missing-reserve selection refreshes the existing scoped probe cache. Retry
  retains operation identity while replacing measurements. Healthy, stopped,
  absent and candidate-bearing pairs do not trigger needless discovery. The UI
  scheduler retains one in-flight step across its two-second poll budget; scope
  reset aborts that task. Existing API deadlines remain unchanged.
- A failed uncommitted candidate is reconciled with the panel before targeted
  local removal. The acquire operation survives ambiguous outcomes; the existing
  server five-minute candidate TTL handles server cleanup. A consumed ID is
  replaced only after exact canonical membership reconciliation. No release call
  that disables standby intent, no new server subsystem. Lost commit receipts
  update membership even after health deteriorates, but never authorize promotion
  or clear a stalled pair without usable health evidence.

Final verification after the Windows author froze the diff: full Rust workspace
exit0 (`.tmp/review-fix-workspace-final.log`), including doctests; one pre-existing
real-panel fixture ignored. Host workspace/all-targets and Windows MSVC/all-targets
Clippy with warnings denied exit0 (`review-fix-clippy-final.log`,
`review-fix-windows.log`). Linux aarch64/all-targets Clippy exit0
(`review-fix-linux.log`); Android Core/Application compile exit0 with the same three
pre-existing stalled-recovery warnings (`review-fix-android.log`). Core11 and
scheduler5 focused tests plus shared Core/Application/tunnel suites passed.
The earlier workspace run captured a Windows test while its RED→GREEN change was
still in progress; it is not final evidence. No hardware/packet acceptance claim.

## 2026-09-27 integration checkpoint (supersedes older partial checkpoints below)

Local branch only. Shared helper driver/IPC, Unix and Windows factories, Core
primary-first server orchestration, reserve lifecycle/role reconciliation,
DesktopConnectionIntent recovery, immediate local Stop and negotiated last-active
WARM are connected. Windows service composition is now wired locally; no host
installation or feature operation has occurred. Parent cross-layer review and
local automated verification are complete; this is not a hardware acceptance claim.

Recent parent review fixes: exact durable cold-stop acceptance across storage
failure/ACK-loss and worker races; persistent Unix journals and DNS-only recovery
after a verified new boot; Windows old-boot cleanup without old PID/index/LUID
replay, exact previous configuration CAS, terminal predecessor reuse across
runtime updates, and empty-claim recovery preserving stopped predecessor configs.
Retained cleanup cannot start/rebind old executables or write configuration.

Windows guard loss is bounded helper fail-stop, **not continuous killswitch**.
Both owned tunnels are stopped even if the UI is absent. Exact empty WFP state
can finish cleanup only after native absence is confirmed; no filter reinstall
or foreign-object deletion. See [Microsoft object lifetime](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management).

Mac launch proof uses a durable nonce/executable receipt plus kernel socket peer,
process identity and environment proof. Definitely-not-spawned failures in the
same invocation retire that receipt; nonzero exit/timeout/crash/absent socket do
not. An ambiguous same-boot pre-capture crash remains fail-closed; new boot has
separate cleanup-only recovery. No name-only process adoption.

Final evidence (logs retained locally in worktree/.tmp, never committed):

- `desktop-handoff-workspace.log`: full Rust workspace exit0, including doctests;
  one pre-existing real-panel/loopback fixture explicitly ignored.
- `desktop-handoff-final-clippy.log`: host workspace/all-targets exit0, warnings
  denied. `desktop-final-windows-clippy.log`: native Windows MSVC/all-targets exit0
  after removing obsolete blanket dead-code suppression. Windows portable fake
  suites also pass in `desktop-final-windows-host-tests.log`.
- `desktop-handoff-linux-clippy.log`: native Linux aarch64/all-targets exit0.
- `desktop-frozen-frontend.log`:129 tests, Svelte0errors/0warnings, build pass.
- `desktop-packaging-tests-bundled.log`:22 packaging/staging tests;32 shared
  Python wire fixtures pass (`desktop-python-contracts.log`).
- `desktop-android-final-check.log`: core/application Android aarch64 compile
  pass using the existing NDK. New desktop-only code is cfg-excluded. Three
  pre-existing stalled-recovery warnings remain; this is not an APK test or an
  Android Clippy-Dwarnings claim. No SDK installation or device changes.

Added a composed SessionControl/driver/native-fake lifecycle test:
primary-first → standby ready → autonomous B promotion → network change →
Stop/WARM B → fresh scoped Start with a new reserve. A late previous Stop has no
effect on the new pair. Complementary Core/API tests verify the WARM request,
role reconciliation and durable retry; no live panel was contacted.

One earlier full run timed out while the dispatcher-death fixture was setting up
(before persisted-tunnel appeared). The original cause is **not established**:
isolated and five complete22-test repeats passed. Test-only progress/early-exit
diagnostics and exact owned-child RAII cleanup were added; production behavior
and timeout budgets were not changed. The final complete run passed. Earlier
cancelled runs and the concurrent-edit doctest failure are not final evidence.

Remaining acceptance boundaries: same-VIP packets, actual OS upgrades/reboot,
power-loss timing and BFE restart require native tests. Linux pair DNS requires
a supported systemd-resolved stub/static mode, not arbitrary resolv.conf or
openresolv. Keep this branch local until authorized hardware/install/publication.

2026-09-26, existing branch `codex/desktop-redundant-warm`, base6b8aa90.
User approved the design and immediate implementation after the plan. No further
permission to begin is required. This checkpoint is NOT feature completion.

## Implemented

- Linux pair DNS now uses systemd-resolved **owned VPN link** properties through
  the same session NetworkOwner journal. DNS servers and routing-only root domain
  are separate records/setters; standby creation does not acquire DNS, promotion
  transfers it, and Stop never resets physical/global DNS or calls RevertLink.
  Full DNSEx reads preserve foreign port/SNI by rejecting rather than flattening
  them. Foreign domains, ambiguous values and replaced interface name/index fail
  closed. A deleted owned link's DNS is already absent, not a reason to recreate it.
- Read-only Linux resolve_policy now combines physical routes with resolved
  preflight before member launch. Only stub/static resolv.conf with UDP+TCP stub
  is supported in this adapter; uplink/foreign/missing modes and openresolv are
  explicitly unsupported, not silently accepted. Native factory still absent.
  Cleanup does not depend on the resolver remaining in a usable stub mode.
- Added14 tests: shared journal rollback/restart/absence, real SessionNetwork
  A-only DNS then promotion/Stop, Linux DNSEx parsing and exact scoped writes,
  resolver compatibility, native identity reuse, full read-only policy, real
  adapter+journal lost-ACK/failure rollback. Own review caught/fixed numeric DBus
  path encoding and stale property observation across slow manager preflight;
  both have failing-then-passing regressions. Native I/O is fake in tests.
  Final offline Rust workspace exit0; host/Linux aarch64/Windows MSVC all-target
  Clippy-D warnings exit0. One pre-existing real-panel fixture remains ignored.
  Logs in plan workspace: dns-final-workspace.log, dns-final-clippy.log,
  dns-final-linux-clippy.log, dns-windows-clippy.log. No capability enabled.

DNS API/fixture references (primary systemd v257 source):
[resolve1 interface](https://raw.githubusercontent.com/systemd/systemd/v257/man/org.freedesktop.resolve1.xml),
[link setters](https://raw.githubusercontent.com/systemd/systemd/v257/src/resolve/resolved-link-bus.c),
[DNSEx serialization](https://raw.githubusercontent.com/systemd/systemd/v257/src/resolve/resolved-bus.c),
[busctl JSON](https://raw.githubusercontent.com/systemd/systemd/v257/src/busctl/busctl.c),
[object-path escaping](https://raw.githubusercontent.com/systemd/systemd/v257/src/basic/bus-label.c).

- Shared probe scheduler now also checks healthy-primary standby: immediate
  first probe, then5s from completion,15s after three consecutive successes;
  failed/expired probe resets warmup. This cadence does NOT grant Ready without
  the existing handshake/dwell checks. A new active-failure episode fences and
  emits cancellation of an earlier in-flight normal reserve probe, then keeps
  the accepted1s phase/2s urgent cadence. Repeated failure in the same episode
  does not cancel its fresh probe. Network change/replacement clears cadence.
  Seven new fake-clock regressions,18 scheduler tests total. Native helper
  integration is still absent: Task3 must consume ProbeBatch.cancelled before
  launching new I/O, and cancel all handles on Stop/network epoch/promotion.
  This closes the known normal-cadence gap, not the whole native health driver.
  Final offline Rust workspace exit0 (one pre-existing ignored panel fixture);
  host, Linux aarch64 and Windows MSVC all-target Clippy-D warnings exit0.
  Logs: cadence-workspace.log, cadence-{clippy,linux-clippy,windows-clippy}.log
  in the plan workspace. No native packet/hardware testing or feature activation.

- Linux read-only physical-route discovery now excludes VPN/slave/down links,
  validates interface identity, chooses the most-specific physical prefix and
  lowest-cost unambiguous next hop, and supports IPv4/IPv6 endpoint bypasses.
  Kernel/DHCP/RA routes are read-only dependencies, not rewritten as app routes.
  Unknown policy routing or deviceless blackhole/multipath entries fail closed.
  Only standard main-table rules plus exact registered member probe rules are
  accepted. Resolver integration is still separate and unfinished: the result
  is PhysicalRoutes, not a complete NetworkPolicy or enabled Linux factory.
- SessionNetwork now uses an explicit read-only dependency check, including
  the late-standby endpoint path. Linux owned-route CAS remains strict proto4;
  accepting a kernel route for dependency verification never authorizes deletion.
  Twelve added tests cover route discovery/conflicts, identity/metadata changes,
  retained-route Start/switch/Stop and late reserve attachment. All native I/O
  in these tests is fake; no host routing command was executed.
  Full offline Rust workspace, host Clippy-D warnings, Linux aarch64 all-target
  Clippy-D warnings and Windows MSVC check all exit0. Existing real-panel test
  remains ignored. Logs: this plan's physical-*.log. Task2 is not complete.

- Linux route resources now expand through the actual SessionNetwork planner:
 member route + bound RPDB rule enter the same journal/rollback/Stop transaction.
 Integration tests prove a failed standby rule leaves primary routes/DNS intact;
 promotion retains both probe rules and Stop removes both. Registration now
 permits zero/one member followed by standby; no constructor dependency on B.
 Native binding persistence and free-table allocation still belong to the
 unfinished Linux factory; registration itself performs no native commands.
- Five additional tests RED→GREEN; the three affected service/shared crate
 suites report281 passes, host Clippy-D warnings and Windows MSVC check pass.
- The old Linux compile limitation has now been removed locally: downloaded
 Zig0.15.2 from the official distribution, verified SHA256
 `3cc2bab367e185cdfb27501c4b30b1b0653c28d9f73df8dc91488e66ece5fa6b`,
 all compiler/cache files under
 app/.tmp/linux-cross.j4Tyyw. Corrected only cc-rs→Zig target spelling in a local
 wrapper. `cargo check -p nelomai-unix-service --target aarch64-unknown-linux-gnu
 --offline --quiet` now exits0, including native Linux backend/routing/RPF code.
 This proves compilation, not packet behavior. No system compiler installation.
 Linux all-target Clippy-D warnings also exits0 after correcting Mac-only test
 compilation boundaries and checking restored journal/scope values in fixtures.
 Host Unix library tests116pass after those changes. Tool source/checksum:
 [official Zig download index](https://ziglang.org/download/index.json).
 Final complete Rust workspace run after all code edits: exit0, one existing
 ignored real-panel fixture; host all-target Clippy-D warnings also exit0.
 Logs: `continuation-final-workspace.log`, `continuation-final-clippy.log` in
 this plan's ignored workspace. No full-feature completion or hardware claim.

- Windows member telemetry now reads the addressed WireGuardNT1.1 adapter or
 protected AmneziaWG UAPI pipe, never the global ringlogger. Capture requires
 the engine's own Start PID/index; every sample checks SCM PID, process creation
 time, interface index/LUID/alias before and after I/O. AWG also checks pipe
 server PID; WG checks adapter LUID/state. Handshake must belong to the exact
 expected peer and be no older than this member's Start; transport counters and
 interface data counters remain separate. This is NOT wired to pair IPC yet.
- Native configuration buffers are bounded/aligned/zeroized, with bounded NT
 size retries. UAPI uses cancellable nonblocking I/O (1s metrics deadline),
 framing/size checks and no blocking worker left behind on timeout. Errors do
 not format configuration. Eleven portable tests cover decoders and I/O seams;
 Windows target also type-checks that the health-read future is Send.
- Verification: full offline Rust workspace exit0 (one pre-existing ignored
 real-panel fixture), host Clippy-D warnings exit0; Windows MSVC check and
 all-targets Clippy-D warnings exit0. Native Windows telemetry was NOT executed.
 Source audit uses the actual AWG DLL root main.go/service.go, not the separate
 tunnel/ package: its supplied name becomes the UAPI/interface name; fixed-GUID
 mode still hashes that name, so different A/B names do not share one GUID.
 Windows data-route/probe isolation, durable ownership and helper integration
 remain; no capability/feature enablement, hardware/install/production changes.

Windows sources: [pinned AWG DLL entry](https://github.com/amnezia-vpn/amneziawg-windows/blob/575626d8f8aa5b64114cf378a08e54bf852d909b/main.go),
[actual DLL service](https://github.com/amnezia-vpn/amneziawg-windows/blob/575626d8f8aa5b64114cf378a08e54bf852d909b/service.go),
[per-name GUID](https://github.com/amnezia-vpn/amneziawg-windows/blob/575626d8f8aa5b64114cf378a08e54bf852d909b/deterministicguid.go),
[WG-NT1.1 ABI](https://github.com/WireGuard/wireguard-nt/blob/1.1/api/wireguard.h).

- Linux pair route adapter now renders exact IPv4/IPv6 main data routes and
 separate per-member probe tables with device-bound `oif` RPDB rules. Rules are
 first-class owned journal resources, never an unjournaled companion command.
 Foreign/duplicate/modified rules fail closed; detached rules can be removed
 after native Stop, but name reuse cannot authorize cleanup of a new interface.
 A failed rule add rolls back its probe route through the real NetworkOwner.
- iproute2 JSON parsing verified against upstream print_string/numeric behavior;
 table dumps use `table all` plus exact filtering because a never-created table
 is not reliably an empty successful dump. Parser rejects unknown route/rule
 attributes instead of forgetting them during ownership comparison.
- Linux member creation configures only its verified VPN interface rp_filter=2
 (loose), with readback. `all`/`default`/physical interfaces are untouched; native
 interface deletion removes the setting. Strict RPF would otherwise discard
 standby replies while the ordinary reverse route points at the active member.
 Native procfs/ip wrappers have NOT been executed or Linux-cross-compiled here.
- This is still Task2, NOT complete Linux pair networking: resolver ownership,
 physical-policy discovery/retained routes, durable table/interface bindings,
 table allocation preflight and session integration remain. DNS explicitly
 returns Unsupported; no new capability/UI path is enabled. Incremental member
 registration is now present (follow-up above); factory persistence/preflight
 must connect it after each native Start without waiting for reserve.

Linux references used for this stage:
[iproute2 rule JSON](https://github.com/iproute2/iproute2/blob/main/ip/iprule.c),
[route JSON](https://github.com/iproute2/iproute2/blob/main/ip/iproute.c),
[numeric name formatting](https://github.com/iproute2/iproute2/blob/main/lib/rt_names.c),
[kernel rp_filter semantics](https://www.kernel.org/doc/html/v6.17/networking/ip-sysctl.html).

Stage verification: 22 added tests (3 shared journal,13 Linux route/rule,6 member
RPF); final `cargo test --workspace --offline --quiet` exit0, one existing ignored
real-panel synthetic-fixture test. Clippy-D warnings and Windows MSVC check exit0.
Linux cross-check exit101 before native adapter compilation: ring needs absent
`aarch64-linux-gnu-gcc`. Logs: this plan's ignored workspace, `linux-network-final-*`.
Partial-stage parent review only; full feature review and hardware proof remain.

- macOS member ownership is now durable and exact: local runtime/session/Start
 scope + slot + OS boot + interface/index + socket device/inode. Persist intent
 before launch and identity before peer configuration. Restarted pair construction
 loads cleanup-only state, never replays Start or stale Running/health. Scope/boot
 mismatches and replaced native resources fail closed without adoption.
- Added private Mac pair factory joining the two owned native backends, scoped
 network journal and native network adapter. Reopening cannot take the fresh
 path; symlinked slot directories and unknown initial directory contents are
 preserved/rejected. This factory is not yet wired to helper IPC/timer lifecycle.
- Native Stop verifies actual disappearance and retains cleanup proof on errors;
 disk write failure no longer prevents turning off an in-memory verified member.
 Session Stop cuts native traffic before slow DNS/route cleanup, and route-only
 remnants remain pending even when both native members are already gone.
- Rebind uses the verified owned interface, not a replaceable interface-name file.
 Cleaned individual slots may be reused in a live session; the whole-session Stop
 fence stays terminal in SessionMembers/NetworkOwner.
- Linux member WG now has an addressed netlink listening-socket reset using
 only verified IfIndex + ListenPort(0). It avoids configure_interface (which in
 pinned defguard flushes addresses), does not rewrite keys/peers/routes, and
 confirms the kernel ACK plus native interface/port readback. Four portable
 request/ACK tests cover failure and unrelated replies; native Linux execution
 and compilation are NOT verified here (missing aarch64-linux-gnu-gcc for ring).

- macOS read-only physical policy discovery now selects the physical gateway,
 keeps both outer endpoints outside the VPN, preserves existing LAN/endpoint
 routes as verified but unowned dependencies, and handles IPv6 link-local gateway
 zones. Unneeded IPv6 default ambiguity cannot block IPv4 endpoints. No native
 policy discovery or application was executed against this Mac in tests.
- Corrected a plan/implementation mismatch: DNS response budget is Android's
 2 seconds, not the 1-second standby phase. A 1.5-second reply regression was
 first RED then GREEN. Healthy standby warmup/ready scheduling is still pending
 in the actual health driver and must not be represented as complete parity.

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
 unchanged. Linux kernel WG reset adapter is now written separately (above);
 retaining peer records alone was not a rebind implementation.

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

- Task2 connect the Mac factory to engine lifecycle; finish durable member lifecycle;
 Linux binding allocation and durable recovery/factory (resolved adapter now
 implemented; other resolver modes unsupported); Windows data-route and
 probe isolation, resolver/recovery/factory remain. Windows addressed metrics
 and Linux physical route discovery are implemented above, not remaining tasks.
 Verify same-VIP behavior and socket egress per OS.
 The panel gives both members the same configured DNS health target, not a
 dedicated per-slot diagnostic address. A lower route metric alone is not proof
 of standby isolation. Do not enable the feature based only on Table=off.
- macOS captured member identity now permits verified cleanup recovery. The
 launch-to-durable-capture crash window still fails closed (no name-only cleanup);
 Linux/Windows durable native recovery remains missing. The service must still
 select/reconcile the saved session and server intent; this is not automatic
 whole-application restart recovery or resumed hot-standby after helper death.
- Task3 helper-owned coordinator, timer/IPC/capabilities and role ACK fencing.
- Task4 foreground/background/quick-action server lifecycle and last-active
 WARM (one hour, reserve released). No desktop WARM wiring exists yet.
- Task5 end-to-end fake lifecycle, whole-workspace/frontend regressions, final
 whole-feature review; later authorized native packet/hardware tests.

## Verification

Current continuation: full `cargo test --workspace --offline --quiet` **passed**
(1194 reported passes, including nested child-test output; one pre-existing
ignored real-panel recovery test requires a synthetic external fixture).
Host Clippy for client-tunnel/Unix/Windows services `--all-targets -D warnings`
passed; Windows MSVC check passed; `git diff --check` clean. Linux target check
stopped in ring's C build: missing `aarch64-linux-gnu-gcc`, so Linux native
compilation and execution are explicitly unverified. No npm/frontend test run
in this continuation (no frontend changes); whole-feature review still pending.
No host VPN/routes/DNS/Keychain/firewall changes, install, push or production work.

Latest follow-up: **224 tests passed** in client-tunnel + Unix/Windows services;
host Clippy `-D warnings`, `git diff --check`, Windows MSVC check passed. No Linux
native build, host network/Keychain/production mutation or hardware validation.
The two local implementation commits after3d4ba6e are not whole-feature completion.

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
