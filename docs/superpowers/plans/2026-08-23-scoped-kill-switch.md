# Scoped Kill Switch Implementation Plan

Reviewed 26 October 2026. This plan replaces the August implementation recipes.
The [specification](../specs/2026-08-23-scoped-kill-switch-design.md) is the single
source of product decisions, their reasons, platform limits and UI wording.
This plan maps those decisions to implementation and acceptance; it does not
repeat them as a second independently editable policy list.

## Scope and status

Shared requirements apply to Android and desktops in 0.5.x. Android starts from
the 0.3.x hot-standby baseline; desktop integration is coordinated with its owner.
Do not modify the 0.4.x branch/worktree during this work. No product implementation,
build, deployment or release is implied by this documentation review.

Completed evidence: the real-AWG S23U experiment established retained TUN behavior
across both-slot stop/native close, one split-excluded UID, and offline local
release. It did not establish normal recovery, network change, live split changes,
IPv6, process-death recovery, forced Stop fallback or desktop behavior.
Current Android implementation and first-build evidence are tracked in
[the 29 October checkpoint](2026-10-29-android-prebuild-progress.md). Device and
desktop acceptance gates below remain open until their own evidence exists.

### Android implementation started, 28 October 2026

The user authorized starting Android 0.5.0. The first local increment extends the
existing GoBackend lifecycle patch with explicit, opt-in descriptor retention.
The ordinary constructor does not duplicate the TUN: native close leaves no extra
backend handle, and retention duplication cannot fail an unprotected Start.
An owner can request capture before native fd transfer using the constructor's
`retainTunDescriptor` argument, then acquire an independent duplicate after socket
admission. Existing production callers still use the ordinary constructor.

Review corrections: a failed close keeps the owned wrapper available for another
Stop or destroy attempt. Returning from close is not sufficient: the captured
FileDescriptor must also be invalid before clearing the handle and error. Pending
cleanup rejects new Start/duplication; repeated Stop retries cleanup even after
native has already stopped. Successful confirmed cleanup permits the next Start.

Validation: 19 ownership tests plus 7 existing backend Stop/local restart tests
pass. Four isolated mutations of the review fixes (unconditional capture, sticky
close error, skipped Stop retry and blindly trusted close return) are detected.
Tests run the generated GoBackend and existing runtime callbacks, substituting JNI,
VPN establishment and Android descriptor duplication. Robolectric's ordinary dup
shares a Java descriptor, so this fixture uses independent file handles; it does
not validate dup(2), kernel TUN lifetime, routing or traffic blocking.

This is a backend prerequisite, not enabled killswitch protection. The service has
not yet acquired a protection handle; preference/UI, redundant native
backend, recovery/Stop integration and hardware acceptance remain open. Socket
admission alone is not connection readiness. Keep the task-3 acceptance unchecked.
The constructor argument is selected before Start; it does not implement first
enable on an already running ordinary backend. That approved no-reconnect behavior
still requires integration and must not be replaced with a reconnect workaround.
No version/capability advertisement, APK, commit, push or deployment accompanies
this increment. Original sources remain internal; test copies/caches/results are
on the external SSD under the project storage rule.

Use system mechanisms and existing project ownership/cancellation/recovery first.
Do not add mandatory controllers, parallel recovery schedulers, new IPC commands,
common firewall traits or a panel-address cache just because an old plan named
them. No seamless protected runtime handover: the approved flow is confirmation,
local Stop, then switch. No server ACK barrier for local Stop.

### Service integration review fixes, 29 October 2026

Both review findings are fixed locally; no commit, push or candidate build.
`confirmTunReady` uses a short readiness gate that is never held across JNI,
DNS or configuration work. Native admission publishes eligibility; stop and
policy replacement revoke it before closing the transport. The existing
service Start completion/cancellation gate remains authoritative.

Core now sends its existing unique Start operation ID through `start_for_attempt`
and identifies rejected attempts through `stop_failed_start`. Default trait
implementations preserve other platforms' previous start/cleanup behavior.
Android extends the existing Start/Stop payloads, retaining the legacy-only
ownership barrier; no new IPC command, dependency or operation registry.
A lease ID is deliberately insufficient because the same lease may be reused.

Retention snapshots whether protection existed before that attempt. Rejection
rolls back only newly acquired protection and prevents late handshake telemetry
from re-arming it. Replayed Start keeps the original snapshot; a rejected attempt
cannot restart under the same ID. A new attempt can proceed. Existing protection
survives failed recovery. A busy Stop records rejection before returning so a
later generic cleanup retry still releases the provisional handle. Close failure
remains retryable, including when the transport is already stopped.

Validation on external SSD: 251 targeted JVM tests, 5 Core tests, 18 Rust model
wire-format tests; Android `aarch64-linux-android` cargo check passed. Eight targeted
mutations were caught, then affected tests passed with the intended code restored.
Evidence: `/Volumes/Apple-VM/Nelomai/android-050/logs/tun-service-fixes-20261029/`.
The service, factory, protocol and runtime code are real; JNI, Android TUN and
network backends are substitutes with file-backed descriptors. No actual TUN,
device routing, emulator/hardware acceptance or production change was performed.
Preference/UI/capability remain disabled/unconnected as before.

### Service and hot-standby integration, 29 October 2026

The next authorized increment connects descriptor ownership to NelomaiVpnService.
Its explicit constructor opt-in defaults to false; preference/UI/capability are
still unconnected. It keeps the established descriptor and transfers an independent
duplicate to native. Both GoBackend and the service's redundant factory use this
same owner. No second VPN service, recovery scheduler, IPC command or dependency
was added. The ordinary backend constructor still retains no extra descriptor.

The initial handle is provisional. Legacy native RUNNING does not arm it: existing
metrics/periodic statistics must observe a handshake (the current Core criterion),
or existing telemetry must observe decrypted TUN traffic. Hot-standby uses its
existing primary readiness gate, with client Start confirmation inside the existing
operation gate. Initial native/admission failure or cancellation releases provisional
ownership. Once armed, slot stop, promotion, full backend close, scoped Core cleanup,
generation cleanup and failed recovery preserve ownership. A new establish may
replace the old descriptor; a failed native duplicate during armed recovery keeps
the new original. This does not prove route continuity during Android replacement.

Explicit service Stop/tile Stop/logout release the descriptor; revoke/destroy also
permanently fence this owner. Stop does not wait for an in-flight establish, rejects
its late result and permits another explicitly admitted Start. Failed/no-op close
remains retryable and is not acknowledged as successful release. Idle service/process
cleanup cannot discard a retained handle. Existing durable cleanup/ACK remains intact.

Integration boundary: `legacyOnly` Stop is ambiguous in the old Core (automatic
compensation and user cleanup share it), so it cannot authorize protection removal.
Before enabling the preference in the UI, explicit local disarm must go through the
existing unscoped service Stop/current-intent Stop, including Core-owned single
connections. This is part of task 2/4, not a new meaning assigned to compensation.

Validation: 256 targeted JVM tests passed across descriptor ownership, real
service/factory callbacks, legacy runtime, cancellation and redundant coordinators.
The factory tests substitute its native backend; GoBackend tests substitute JNI.
TUN establishment, Android package-manager verification and dup use file-backed
fixtures. No actual kernel TUN, app routing, live split continuity/rollback, IPv6,
device lifecycle or production traffic acceptance was performed. These exit gates
remain unchecked. Healthy enable/disable without reconnect, preference/disclosure,
authoritative protection status and bounded forced Stop fallback also remain open.
Five isolated mutations were caught: automatic disarm on native close, missing
establish epoch fence, omitted redundant close notification, arming legacy on
RUNNING before handshake, and trusting a no-op descriptor close. Product sources
were restored and the affected 43 tests passed again; the other 213 baseline
tests ran on the same final product code. No full application/native build was run.
All test copies/cache/results are on the SSD in `logs/tun-service-20261029`.
No commit, push, candidate/APK, installation or production changes.

## 1. Map current ownership and contracts

- [ ] Review current core/tunnel, Android and desktop contracts with their owners.
  Start with `crates/client-tunnel`, `crates/client-core`,
  `crates/client-application`, `src-tauri/src/commands.rs`, existing connection
  intent and Android plugin models/protocol. Paths are integration points, not
  a mandate for a new type in each file.
- [ ] Trace all TUN/native handles and local enforcement ownership through initial
  Start, transport loss, full backend close, recovery, Stop, revoke and runtime
  replacement. Inspect `NelomaiVpnService.kt`, `RedundantNativeBackend.kt`,
  redundant total-loss/production adapters and runtime dispatcher.
- [ ] Classify automatic teardown versus explicitly authorized disarm. Reuse
  existing intents/generations; do not default missing intent to user Stop.
- [ ] Keep capability, preference, connection intent and confirmed enforcement
  distinct. Include status unavailable/error semantics in the existing contract;
  neither IPC failure nor saved preference implies off/armed/blocked.
- [ ] Extend contracts only as necessary. Verify runtime capabilities instead of
  literal release versions or latest/stable labels. Assign protocol revisions
  from current definitions only if needed; do not copy old version numbers.

Exit evidence: a concrete ownership/transition map tied to current code, minimal
contract diff and focused compatibility tests. A new retry command is justified
only if existing retry/wake paths cannot represent the agreed action.

## 2. Preference, disclosure and UI integration

Existing integration points: application preferences/commands, native-client
bindings, app model, connection/settings view and local notification actions.

- [ ] Implement default-false, device-wide persistence and first-enable
  confirmation. Preserve preference through ordinary Stop/logout/account change,
  update/runtime switch and reboot. Disable saves false; failed explicit enable
  retains true under the approved failure policy. Test persistence failure
  reporting so the UI does not claim a saved choice that was not stored.
- [ ] Enable on a healthy VPN without reconnect; disconnected enable changes
  preference only. Disable on a healthy VPN preserves the tunnel; blocked
  disable uses local Stop and cancels recovery.
- [ ] Show confirmed protection or explicit uncertainty/unavailability. Unsupported
  runtime notice remains visible offline; never infer support from the version.
- [ ] Keep local Stop reachable without bootstrap, panel access or valid remote
  authorization. Local caller/owner authorization remains mandatory.
- [ ] Wire agreed blocked-state actions and cause reporting. Prevent duplicate
  retry while preserving Stop during a stalled operation.
- [ ] Implement one outage notification after 20 continuous seconds, immediate
  actionable/lost-protection notices, deduplication and cancellation after
  recovery/Stop. No new reporting scheduler. Notification permission is not
  required for access to the local Stop UI.

Exit evidence: preference/migration and UI tests covering first-enable cancel,
unknown platform state, offline controls, late responses and unsupported runtime.

## 3. Retain Android TUN in its existing owner

- [ ] Add meaningful lifecycle regression tests for descriptor ownership before
  product changes: native close preserves the held TUN, one-slot failure preserves
  the healthy path, initial failure cleans resources, late callbacks cannot
  recreate enforcement after Stop.
- [ ] Keep an independently held duplicate before transferring the engine fd.
  Healthy preference-disable releases only the retained copy. Stop releases the
  owned local transports and all TUN handles, with result verification.
- [ ] Preserve the shared interface and effective split/DNS/routes through recovery
  and hot-standby promotion. Retention must cover supported single-transport paths
  too; hot-standby off is not an exemption from killswitch.
- [ ] Test duplication/close failures, native preparation cancellation, backend
  restart and ownership transfer. Do not copy the diagnostic APK's rejection
  of new `establish()` calls into product recovery.
- [ ] Implement live split changes using existing policy/serialization. If a new
  interface is required, verify safe replacement and rollback, including existing
  flows. If a safe path is not demonstrated, stop that subtask and record the
  unresolved constraint rather than globally disarming.

Exit evidence: relevant Kotlin/native tests and a minimal integration on real
AWG with traffic observation. No mandatory blackhole interface, new owner service
or backend rewrite follows from the feasibility experiment.

## 4. Stop, recovery and lifecycle integration

- [ ] Accept Stop immediately, cancel/fence active intent, show stopping and avoid
  queuing teardown behind network calls or server cleanup. Reuse durable server
  cleanup without weakening quarantine, ACK or runtime admission checks.
- [ ] Bound ordinary local teardown and implement an authorized forced fallback.
  Choose its timeout from code review and measurements. Verify outcome after
  both paths; uncertainty is not successful removal or confirmed blocking.
  Android fallback must target the current VPN owner and prevent service restart
  after Stop. Desktop fallback must remove verified owned rules, not just kill
  a helper. Keep local retry available after an unconfirmed outcome.
- [ ] Integrate protection into the existing recovery coordinator. After transient
  fast attempts, retry every five minutes; network arrival/change and manual retry
  wake one immediate attempt. Coalesce triggers. Stop cancels pending attempts;
  confirmed terminal causes stop automatic attempts until resolved.
- [ ] Keep enforcement through lease cleanup/replacement; do not require preserving
  an obsolete lease. No additional server-side feature is required by killswitch.
- [ ] Handle Android revoke without automatic reclaim. Handle owner-process death
  with honest loss-of-protection status and existing recovery only for active
  intent; exclude explicit Stop, revoke, reboot and OS force-stop restrictions.
- [ ] Use physical-network captive-portal capability through existing callbacks.
  Lack of VALIDATED alone is not a portal diagnosis. Do not auto-disarm or add
  broad exceptions; test the system login activity separately.
- [ ] Keep VPN/protection when UI closes. Use confirmed local Stop for logout and
  account replacement. Update, every runtime switch and desktop full exit require
  the agreed warnings/confirmation, then verified local teardown. Cancellation
  preserves current operation; failed teardown blocks replacement/install/exit.
- [ ] Reboot does not restore previous blocking. Preference survives. Same-boot
  service restart is not reboot; preserve protection where the platform supports
  it and explicitly report actual loss on Android owner death.

Exit evidence: lifecycle tests for stalled IPC, forced fallback, terminal auth,
late Start/promotion results, reboot/revoke, installer failure and both capable
and unsupported runtime transitions. No test relies on panel reachability for Stop.

## 5. Desktop platform work, coordinated separately

WFP, nftables and PF are candidates described in the specification, not approved
line-by-line implementations. Review each against the current desktop branch
with its owner before changing shared contracts or choosing a new abstraction.

- [ ] Validate narrow control-plane/transport exceptions using existing mechanisms.
  Add bounded cached-address resolution only if necessary, retaining TLS hostname,
  certificate checks and authorization. No unrestricted system DNS allowance.
- [ ] Validate atomic enforcement installation/removal and split updates, IPv4/IPv6,
  existing TCP/UDP flows, filter ordering and effective output paths.
- [ ] Establish exact ownership and safe privileged storage where required.
  Use bounded direct argv/stdin calls, never shell interpolation or global flushes.
- [ ] Validate same-boot helper restart, explicit forced Stop and real reboot
  without GUI startup. Do not rely on GUI reconciliation to remove boot-stale
  persistent rules. Do not assume every PF anchor/WFP lifetime choice provides
  the needed guarantees.
- [ ] Implement each platform independently and expose capability only after its
  own acceptance. No new kernel driver or universal firewall framework by default.

Exit evidence: reviewed platform design and actual platform acceptance, including
unchanged unrelated firewall objects. Android tests cannot accept desktop behavior.

## 6. Acceptance matrix

Run meaningful automated checks for each touched component, then the applicable
hardware scenarios. Avoid scripted tests that merely mirror the implementation.
Use the current repository test commands rather than stale commands copied from
August. Run relevant broader regressions once after integration; repeat only
for changes/failures. Documentation edits alone do not require app builds.

| Scenario | Required observation |
| --- | --- |
| Preference absent/off; initial pending/failed/cancelled Start | Direct access remains possible; no false protection claim |
| First enable, subsequent enable, disable on healthy VPN | Confirmation rules, saved choice, no reconnect, verified state |
| Arming failure on initial or healthy VPN | VPN locally stopped, true preference retained, honest teardown outcome |
| Single path and hot-standby: one/both slot loss, backend close | Enforcement retained; healthy slot still works; no protected direct traffic |
| Actual standby promotion and ordinary recovery | Continuous enforcement, readiness/admission checks, successful traffic |
| Wi-Fi → LTE and LTE → Wi-Fi | Working underlay baseline, recovery with protection off/on and standby off/on; no bypass |
| Split include/exclude, addresses/domains/LAN, live edits | Expected direct exceptions, other traffic protected, rollback and existing flows |
| IPv4, working IPv6, DNS and cached DNS46 destinations | Intended routing/scope remains correct; unavailable IPv6 explicitly untested |
| Panel unavailable, expired auth, terminal failures | Block retained where present; local Stop works; retry never bypasses admission |
| Fast attempts, passive/network/manual retry | One attempt at a time, five-minute timer, no outage-clock reset |
| Outage below/above 20 seconds; immediate actionable cause | Correct notification timing and deduplication; warning cleared on recovery |
| Ordinary/forced Stop, stalled recovery/IPC, late callbacks | Local result verified, no server wait, no resurrection, honest unknown status |
| UI close/reopen, recents dismissal, screen off | Existing owner/protection survives UI lifetime under platform limits |
| Android owner death versus native close; revoke | Accurate protection-loss status; only permitted recovery; no reclaim after revoke |
| Captive portal, delayed detection, unvalidated network | System evidence, retained protection, tested login path without assumed bypass |
| Logout/account replacement and background 401 | Explicit logout uses Stop; old replies fenced; background auth does not disarm |
| Update/full exit/runtime switch confirm/cancel/failure | Verified local teardown before replacement, preserved preference, truthful gap |
| Supported ↔ unsupported runtime | Capability-driven notice, offline controls, saved choice and subsequent re-arm |
| Service restart and real OS reboot | Platform-specific same-boot behavior; no Nelomai boot-time block; preference retained |

Android API support baseline is 24, with no increase required for this method.
Record OS/API/build; cover oldest supported API, intermediate lifecycle changes,
current target and OEM hardware when available. A missing device/working underlay
is a coverage gap. Do not claim acceptance based on TUN presence or UI alone.

Use isolated fixtures, owned test resources and authorized device tests. Protect
unrelated users/firewalls; no deployment, production fault injection or new build
is authorized by this plan alone. Record evidence and restore temporary test state.

## 7. Review and delivery

- [ ] Verify security boundaries: local caller/owner, stale generation, bounded
  input, exact object removal, control-plane scope, TLS/admission, log redaction.
- [ ] Review requirement coverage against the specification, including uncertainty
  and platform-loss states. Fix contradictions without adding a second policy list.
- [ ] Update user help and existing operational docs only for implemented behavior.
  Provide local app/helper recovery, never instructions to flush global firewalls.
- [ ] Add relevant checks to existing CI. Read capabilities/revisions from canonical
  contracts; do not require a release build merely to test documentation or create
  workflow tests that only assert step names.
- [ ] Commit/push/build/release only when requested. Keep default disabled; do not
  silently change it based on telemetry. Release capability per tested platform.

Return with evidence for design review if safe split replacement, control-plane
recovery, forced Stop verification or platform lifetime cannot satisfy the spec.
Do not silently weaken protection, add a duplicate coordinator or restart a
three-attempt ritual irrespective of the actual problem.
