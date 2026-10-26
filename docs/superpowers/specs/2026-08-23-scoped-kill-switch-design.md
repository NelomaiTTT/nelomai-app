# Scoped Kill Switch Design

## Decision record — 26 October 2026

This is the shared Android/desktop requirements document for 0.5.x. Android
0.3.x supplies the hot-standby baseline; desktop 0.4.x is a separate development
line and will not be released for Android. These documentation changes do not
modify the 0.4.x branch/worktree or claim desktop implementation/acceptance.
Coordinate changes to shared ownership, Start/Stop, runtime state and IPC with
the desktop owner before merging; Android implementation details are not a
cross-platform API requirement.

**Approved in the current discussion:** use the Mullvad-style scoped Android
approach built on the standard `VpnService` TUN and the existing AWG backend.
Retain ownership of the existing TUN across loss/closure of both transports;
release it explicitly on local disable. Do not introduce a new network stack,
firewall, transport backend or recovery coordinator for this purpose.

## Android version compatibility

Reviewed 26 October 2026. The current application and tunnel plugin declare
`minSdk = 24` (Android 7.0); the application declares `targetSdk = 36`.
Source: `src-tauri/gen/android/app/build.gradle.kts` and
`plugins/tunnel-android/android/build.gradle.kts`. These are inspected baseline
values, not duplicated release configuration or a reason to hardcode capability
checks. The retained-TUN mechanism requires no increase to the current minimum.

| Primitive | First available API | Use |
| --- | --- | --- |
| `VpnService.Builder.establish()` | 14 (Android 4.0) | System TUN and scoped routing |
| `ParcelFileDescriptor.fromFd(int)` / static `dup(FileDescriptor)` | 13 | Independently held duplicate fd |
| `addAllowedApplication` / `addDisallowedApplication` | 21 (Android 5.0) | Application split scope |
| `NET_CAPABILITY_CAPTIVE_PORTAL` / `VALIDATED` | 23 (Android 6.0) | System network diagnosis |

Sources: [VpnService.Builder](https://developer.android.com/reference/android/net/VpnService.Builder),
[ParcelFileDescriptor](https://developer.android.com/reference/android/os/ParcelFileDescriptor),
[NetworkCapabilities](https://developer.android.com/reference/android/net/NetworkCapabilities).

Android 7.0+ has all these primitives. Android below 7.0 remains outside current
application support even though individual primitives predate it. This does not
promise compatibility with future untested OS releases. Android 8.0+ requires
the VPN service to enter foreground execution; comply with subsequent applicable
service/notification/target-SDK requirements through the existing service.
See the [Android VPN guide](https://developer.android.com/develop/connectivity/vpn).
Notification permission must not become the only way to perform local Stop.

API availability is not release acceptance. Test the oldest supported API,
representative intermediate behavior changes, the current target OS, and real
vendor devices when available. Verify background/screen-off ownership, network
change, split, recovery and forced Stop. Emulators may check API compatibility
but do not establish OEM background-process reliability. Record OS/API/build
for every acceptance run and mark missing devices as untested.

The S23U experiment is the only completed real-AWG feasibility evidence here;
its OS must be taken from recorded device evidence, not inferred from the model.
No acceptance claim is made for every Android version, Huawei or Realme.
All supported versions share the same fundamental limit: when the TUN owner is
lost or permission revoked, this method cannot guarantee continued protection.

## Confirmed product decisions

### Explicit Stop — confirmed 26 October 2026

For all platforms, an explicit user Stop stops VPN and removes Nelomai's local
kill-switch enforcement, restoring the possibility of direct connectivity. It
preserves the saved preference (including `true`): when enabled, protection
arms again after the next successful connection. No separate unblock action is required after successful
Stop. Confirm local removal without waiting for panel authorization, lease
cleanup or ACK; fence late start/recovery callbacks. Automatic teardown,
transport errors and reconnects never count as explicit Stop.

This does not disable an independently enabled Android system lockdown or
other external network restrictions; the UI must explain remaining restrictions
instead of claiming that Internet connectivity is guaranteed.

### Initial Start — confirmed 26 October 2026

For all platforms, enabling the preference does not block direct connectivity
before the first successful VPN connection. Initial Start does not intentionally block direct traffic; failure or
cancellation before successful connection performs local cleanup. Report `off`
only when absence/removal of enforcement is known; a partial arming or teardown
failure must not be presented as confirmed ordinary connectivity. The connection is reported successful only when the tunnel is ready
and enforcement is installed; this is the transition to `armed`.

The user explicitly chose arm-after-success rather than blocking from the Start
button press. Consequence: protected applications may use the direct network
while the initial connection is pending; UI text must not claim protection yet.
After an explicit Stop, the next Start has the same initial-start behavior even
though the preference remains enabled. An internal restart/reconnect after an
armed connection is different: enforcement remains present (with `blocked` when
no usable path remains) until recovery
or explicit user Stop/disable, even if the transport or lease is recreated.

### Explicit logout — confirmed 26 October 2026

For all platforms, an explicit user logout follows the local Stop semantics:
cancel/fence connection intent, stop local VPN traffic, remove local enforcement,
confirm removal, then complete local logout. Do not wait for panel access or
server lease cleanup/ACK. Preserve the device-wide `kill_switch_enabled`
preference. Reuse the existing durable logout/cleanup path without retaining
usable credentials or weakening revocation and ownership checks.

Reason: a deliberate exit must leave a usable device and must be possible while
the panel is unavailable. Consequence: after successful local logout, traffic
may go directly; the next successful VPN connection can arm protection again.
If local enforcement removal fails, report the failure and keep the local
recovery action available; do not claim that protection has been removed.

Authorization expiry/revocation, background 401, bootstrap failure and other
automatic authentication failures are not user logout and do not disarm an
already armed connection. If recovery cannot proceed, retain `blocked` and offer
explicit Stop/disable/logout. Account replacement uses explicit logout as confirmed
below. Application update
follows the separate explicit confirmation policy below, not implicit logout
authorization.

### User-confirmed update — confirmed 26 October 2026

For all platforms, pressing `Обновить` presents an additional explicit warning
and confirmation before stopping an active VPN or removing kill-switch
enforcement. Explain that VPN and leak protection will be turned off and that
traffic can use the direct network during installation. The initial button
press alone is not consent to disarm. Cancellation/dismissal preserves the
current connection intent, tunnel and enforcement.

After confirmation, use the existing explicit local Stop path: cancel/fence
recovery and late starts, stop local traffic, remove enforcement, confirm local
teardown, then proceed to installation. Do not wait for panel cleanup/ACK to
release local protection; preserve durable server cleanup and all updater
signature/hash/identity checks. If local teardown fails, do not start the
installer or claim that protection has been removed; show the failure and a
local retry/recovery action.

The confirmation authorizes a temporary disarm, not a preference reset:
`kill_switch_enabled` remains saved. After the update, protection arms on the
next successful VPN connection under the approved initial-Start policy; do not
claim protection across installation. Whether that connection is started
automatically remains governed by the existing separately agreed startup policy.
If installation fails after confirmed Stop, the device remains locally stopped;
report this honestly and do not silently undo the user's Stop intent.

Background download/checking alone must not stop VPN or disarm protection.
Automatic installation must not bypass the required confirmation while VPN or
kill-switch enforcement is active. Do not silently defer the user's confirmed
update until a separate Stop: the confirmed update itself initiates Stop.
Independently enabled Android system lockdown remains active and must be
explained; this flow does not promise to switch it off or guarantee direct
Internet access despite external restrictions.

Suggested confirmation meaning (final wording may be refined):
`Для установки обновления VPN и защита от утечки будут отключены. Во время
обновления трафик сможет идти напрямую. Продолжить?` Actions: cancel / confirm
update. Do not warn about an active protection state that is actually absent.

### Runtime without killswitch — confirmed 26 October 2026

For all platforms, switching to a runtime without killswitch support requires
an explicit warning and user confirmation. Explain that the target runtime
cannot enforce the saved protection setting and that the transition can remove
current protection. Cancellation/dismissal leaves the runtime, connection intent
and enforcement unchanged.

After confirmation, use the existing authorized runtime handover and local Stop
path; confirm local teardown before destroying the old owner or activating the
target. Do not wait for server cleanup/ACK to remove local enforcement, and do
not bypass runtime identity/admission checks. Failure of local teardown blocks
the transition rather than being presented as a successful protected handover.

Preserve the device-wide preference, including `kill_switch_enabled=true`.
Show a persistent explicit status such as `Защита от утечки недоступна в этом
runtime` in the selected runtime's UI/settings. A saved enabled preference must
not render as `armed` or suggest enforcement is present. Unsupported capability
is separate from runtime enforcement `off/armed/blocked`; do not add a fake
`armed` state to preserve a checked switch visually. The notice must not depend
on panel reachability or disappear merely because login/bootstrap fails.

Read support from verified runtime capabilities/contracts/manifest data, never
from a literal version number, platform name alone, or `latest`/`stable` label.
If support cannot be verified, do not assume it exists; surface the uncertainty
and require the same unprotected-transition confirmation. This decision does
not authorize admission of an otherwise invalid runtime.

On returning to a compatible runtime, the saved preference applies again:
protection is reported armed only after a successful connection and confirmed
platform enforcement. No protection is claimed during the unsupported runtime
or transition. Switching between supporting runtimes follows the same warning/confirmation
and temporary-disarm policy specified below; no seamless handover is attempted.

### OS reboot — confirmed 26 October 2026

For all platforms, after an OS reboot Nelomai does not block direct Internet
access. Preserve the saved `kill_switch_enabled` preference, but start runtime
enforcement in `off`. Protection arms only after the next successful VPN
connection and confirmed platform enforcement. Failed or pending initial Start
must not restore a previous boot's `blocked` state.

Reason: protection should not leave the device without connectivity after a
reboot before a working VPN is available. Consequence: direct traffic is possible
between boot and successful connection; UI/documentation must not imply boot-time
leak protection. This decision does not itself enable automatic VPN startup.

Desktop enforcement must respect the boot boundary: select OS object lifetimes
and reconciliation that prevent previous-boot blocking rules from stranding the
device until the user opens the app. Do not rely solely on late GUI startup to
remove persistent filters. Same-boot helper/service restart is NOT an OS reboot
and must not silently disarm a previously protected session. Verify each platform
with real reboot tests, including boot without opening the UI and failed initial
connection. Reconcile only Nelomai-owned objects; never reset unrelated firewalls.

The selected Android scoped mode has no reboot-persistent TUN enforcement.
Externally enabled Android lockdown or other OS/network restrictions are not
removed by Nelomai: explain that they may still block connectivity. The promise
is that Nelomai does not retain its own reboot-time block, not that it overrides
independent system restrictions.

### Recovery failure — confirmed 26 October 2026

For all platforms, once protection is armed, failure to recover VPN retains
`blocked` until an explicit user action authorized to disarm under this spec.
No timeout, retry-count exhaustion, unavailable server/panel, access expiration,
authorization failure or terminal recovery error may automatically restore
direct protected traffic. A successful recovery returns to `armed`, not `off`.
This rule is subject to the documented platform limits (owner-process loss and
OS reboot); it is not a new guarantee that Android enforcement survives them.

Show the known reason and available actions. Distinguish verified terminal
conditions from transient failures and unknown causes; do not invent a server
or authorization diagnosis. Keep explicit local Stop/disable available without
network or successful bootstrap. Retry begins an existing serialized bounded
attempt and does not remove enforcement. Logout and confirmed update/runtime
handover use their separately approved disarm rules.

Reason: the absence of a working VPN must not turn a protection feature into an
automatic leak after a hidden deadline. Consequence: protected applications can
remain without Internet indefinitely, while explicit split exceptions retain
their agreed behavior. Explain this in the blocked UI and avoid repeated noisy
notifications. Transient passive retries remain capped; terminal errors stop
automatic retries without removing the block. Retry cadence is separate from
enforcement lifetime and never acts as a disarm timer.

### Hot-standby and killswitch — confirmed 26 October 2026

For all platforms, hot-standby and killswitch are independent settings and may
be enabled together. Redundancy improves availability; killswitch prevents
protected traffic from falling back to direct connectivity when VPN transport
is unavailable. Enabling one must not implicitly disable the other.

Once armed, enforcement remains present throughout primary-to-standby switching;
do not disarm and re-arm it around promotion. A healthy usable transport can
continue carrying protected traffic. When no transport is ready, preserve
blocking until a validated path is available. Do not send traffic directly while
waiting for standby readiness or confirmation. Explicit split exceptions retain
their agreed direct behavior. On Android the shared TUN remains owned across
slot loss/promotion; reuse existing readiness, ownership and generation checks.

The S23U dual-stop/native-close test proves the retention primitive, not leak
freedom during actual promotion. Acceptance must cover a ready standby, an
unready/failed standby, loss of both slots, recovery, late promotion callbacks
and Stop during promotion, with traffic observations across the transition.

The user proposed mutually exclusive hot-standby/killswitch modes as a possible
simplification. Keep that as a fallback for renewed discussion only if concrete
implementation problems are demonstrated. Do not impose the restriction now,
weaken readiness/security barriers, or silently change settings. Record the
failing scenario, evidence and available simpler alternatives before revisiting
this decision with the user.

### Default preference — confirmed 26 October 2026

For all platforms, killswitch defaults to disabled when no saved preference
exists, including first installation and migration from a version without the
setting. Only an explicit user choice enables it. An update must neither
silently enable protection nor reset an existing enabled preference.

Preserve the device-wide choice across explicit Stop, logout, application
updates, OS reboot and runtime changes, including an unsupported runtime as
specified above. Preference persistence does not imply active enforcement:
`armed` is reported only after successful connection and platform confirmation.
Reason: the connectivity restriction is opt-in, while an existing user choice
must not be lost during normal lifecycle operations.

### Network change — conditional decision, 26 October 2026

Preserving killswitch enforcement during network changes is conditionally
accepted: its ability to coexist with successful VPN recovery must be verified.
It is NOT yet demonstrated that enforcement leaves all required control-plane,
DNS and transport-rebind paths usable on the new physical network. The completed
S23U experiment tested offline local removal, not network-change recovery while
protection remained enabled. Do not cite it as acceptance of this scenario.

Before marking this requirement implemented/accepted, test Wi-Fi → mobile data
and mobile data → Wi-Fi on a real Android device, plus applicable desktop network
changes. Establish working underlay connectivity independently, then verify:

- enforcement stays present and protected traffic does not escape directly;
- the existing VPN sockets/replacement sockets use the new physical network
  through the required protection/binding and admission barriers;
- necessary control-plane access and DNS remain usable without a broad bypass;
- VPN traffic actually resumes, including the hot-standby enabled/disabled cases;
- explicit split exceptions remain usable when underlying connectivity permits;
- Stop/local disable remains available during failed or stalled recovery.

Compare recovery with killswitch off/on under comparable network conditions;
record timing, traffic and failure reasons rather than inferring success from
UI state or the existence of a TUN. An unavailable mobile network is not a
passing test and must not be conflated with a killswitch-induced failure.
If enforcement obstructs recovery, investigate the concrete path and revisit
the conditional decision with the user if needed. Never add an automatic disarm
on network change or timeout as a workaround. Server and Tic/Tak ↔ Stray changes
remain separately testable transitions; this conditional approval does not
constitute their hardware acceptance.

### Live split-policy changes — confirmed 26 October 2026

For every split mode supported by a platform, apply explicit split changes
immediately, including while killswitch is `blocked`, rather than deferring them
to the next connection. An application/destination newly excluded from VPN may
use the direct path; an item returned to VPN becomes protected (and remains
blocked if no usable VPN path exists). The user-selected change does not disarm
killswitch for the remaining protected traffic. Mandatory policy exclusions and
existing validation/authorization rules continue to apply.

Reason: users must be able to change the intended protection scope without
stopping VPN or waiting for recovery. Consequence: newly excluded traffic may
leave directly as soon as the change commits; this is intentional split behavior,
not a global escape from protection. Do not mark a change applied based solely
on saved preferences or UI state; confirm the effective platform policy.

On failure, retain the previous effective policy and show the reason; do not
partially apply exclusions or drop existing protection. Use existing serialized
policy/ownership gates and a safe handover/transaction. Android may need a new
system interface for changed application lists; validate ordering rather than
assuming that retaining a descriptor alone makes replacement atomic. If an
unrecoverable platform failure prevents preserving the old policy, surface the
failure explicitly and preserve fail-closed behavior wherever possible; never
claim a successful rollback that did not occur.

Separate acceptance is required: add/remove exclusions while `armed` and
`blocked`, concurrent recovery/Stop, injected application failure and rollback,
existing TCP/UDP flows and new connections, DNS and working IPv6. Verify that
unaffected protected flows do not gain a direct path. The earlier S23U test had
a fixed excluded UID and does not prove safe live policy replacement.

### All runtime switches — confirmed 26 October 2026

For all platforms, every runtime switch uses an explicit warning and user
confirmation of temporary VPN/killswitch shutdown, including switching between
two killswitch-capable runtimes. Do not implement preservation of enforcement
across runtime replacement, cross-process TUN handover or a seamless protected
runtime-switch special case. This supersedes the previously open question about
handover between capable runtimes.

Cancellation/dismissal preserves the current runtime, connection intent and
protection. After confirmation, cancel/fence the old intent and late callbacks,
perform local Stop and confirm removal of local enforcement before destroying
the old owner or activating the target. Do not wait for panel lease cleanup/ACK;
keep existing durable cleanup and runtime identity/admission checks. If local
teardown fails, block the switch and expose a local recovery action.

Preserve the saved killswitch preference. No protection is claimed during the
switch. In a supporting target, protection arms only after the next successful
connection and platform confirmation; the existing separately agreed startup
policy determines whether connection starts automatically. In an unsupported
target, persistently show protection unavailable as described above. An
independently enabled Android lockdown remains outside this local control.

Reason: the user explicitly chose the simpler confirmed-disconnection behavior
over seamless runtime handover. Consequence: direct traffic can flow during
replacement, which the confirmation must clearly explain. This exception applies
to runtime replacement only, not network changes, ordinary recovery, hot-standby
promotion, split updates or Tic/Tak ↔ Stray changes within the same runtime.

Acceptance: both capable→capable and capable→unsupported transitions, cancel
without mutation, teardown failure, offline local Stop, stale callbacks,
preserved preference, correct unsupported status and re-arming after successful
connection. Do not add a protected-handover implementation or test requirement.

### Closing the interface and full exit — confirmed 26 October 2026

On every platform, closing the application window or dismissing it from recent
applications is not consent to stop VPN or disarm killswitch. Keep the existing
background VPN owner and protection running independently of UI lifetime.
An explicit Stop remains the ordinary way to stop VPN and remove protection.

The desktop action “Fully quit” must warn that VPN and protection will stop and
require confirmation before doing so. Cancellation/dismissal leaves the current
connection and protection intact. Confirmation uses the existing local Stop
path: fence pending work and late callbacks, confirm local teardown, then quit;
do not wait for the panel or server cleanup ACK. Preserve the saved preference.
If teardown fails, report the failure instead of completing a misleading exit.

Reason: dismissing an interface is a routine action, not permission to expose
protected traffic. Full exit is a deliberate shutdown with an explicitly accepted
loss of protection. This requirement does not promise survival after OS force-stop
or destruction of the TUN owner; retain the documented process-death limitation
and do not introduce a second owner merely to emulate such a guarantee.

Acceptance: close/reopen UI while armed and blocked, dismiss Android recents,
confirm/cancel desktop full exit, offline teardown and late callbacks. Verify
actual background ownership, effective protection and retained preference.

### Account replacement — confirmed 26 October 2026

On every platform, explicit account replacement goes through ordinary user
logout: cancel/fence the old connection intent, stop VPN and remove local
killswitch enforcement, complete local logout, then show login for another
account. Use the existing logout and local Stop paths; do not add a separate
account-switch lifecycle or wait for panel availability/server cleanup ACK.
Retain existing durable cleanup and credential revocation handling. If local
teardown fails, report it rather than claiming successful removal of protection.

The killswitch preference belongs to the device and survives account replacement.
Protection arms again only after a successful connection under the new account
and platform confirmation. Do not inherit the old account's armed state or permit
late replies from it to start VPN or re-arm protection.

Reason: choosing another account is an explicit user shutdown of the current
session. Consequence: direct Internet can be available between accounts, as after
ordinary logout. Expired/revoked authorization, background 401 and bootstrap
failures are not explicit account replacement and must not disarm protection.

Acceptance: account replacement while armed and blocked, panel unavailable,
local teardown failure, stale old-account callbacks, preserved preference and
re-arming after the new account connects. Verify background authorization errors
leave an existing block intact.

### Blocked-state interface — confirmed 26 October 2026

For all platforms, show “Интернет заблокирован для защиты IP” when enforcement
is confirmed blocked, along with the known cause (or an explicit unknown cause).
Explain that explicit split exclusions remain direct; do not imply all device
traffic is blocked. Provide two actions:

- “Повторить подключение”: retry through the existing recovery path without
  removing enforcement or bypassing authorization/admission checks.
- “Выключить VPN и блокировку”: explicit local Stop and enforcement removal,
  available without panel access or successful authorization. Preserve the
  saved preference; confirm actual local teardown before claiming direct access
  is restored, and surface failure honestly.

While automatic recovery is running, display its progress and do not start a
second parallel attempt from the retry button. Use existing operation gates;
late replies must not reverse a subsequent explicit Stop. Keep the local Stop
accessible while recovery is running and when bootstrap fails.

Reason: the user must distinguish continued protection from an application hang
and choose between protected recovery and intentionally restoring direct access.
Acceptance: armed-to-blocked UI, known/unknown cause, offline/expired-auth Stop,
manual retry during automatic recovery, teardown failure and stale callbacks.

### Disabling the preference — confirmed 26 October 2026

Disabling the killswitch setting is distinct from ordinary Stop. With a healthy
working VPN, remove only killswitch enforcement and keep the VPN connected,
without restarting it. While blocked, cancel/fence recovery and perform local
Stop to remove enforcement and allow direct access; late recovery results must
not reconnect or re-arm. Neither path waits for panel availability or cleanup ACK.

After successful application, persist the device preference as disabled in both
cases, so subsequent connections do not re-arm automatically. Report actual
platform state and teardown errors; do not claim protection was removed when it
was not. External system lockdown remains outside this setting's control.

Reason: the setting changes the user's continuing protection preference, whereas
ordinary Stop preserves it. Acceptance covers healthy VPN continuity, blocked
recovery cancellation, offline operation, late callbacks, removal failure and
subsequent Start with the disabled preference.

### Failure to enable protection — confirmed 26 October 2026

When killswitch is selected but platform enforcement cannot be established,
stop VPN and explicitly report the protection failure. Apply the same policy
after a new connection and when enabling the setting on an already healthy VPN.
Never report armed based on preference alone. Preserve the enabled preference
for the next connection attempt, including when this explicit enable request
failed; persistence of user intent is distinct from confirmed enforcement.

Use existing local teardown and ownership gates to remove any partial enforcement
and fence late callbacks, without waiting for server cleanup. After confirmed
teardown, show “Не удалось включить защиту. VPN выключен, интернет доступен
напрямую”. If teardown fails or an external restriction remains, report the actual
state instead of claiming direct access. Do not silently continue the VPN with
an implied protection guarantee or automatically restart in a failure loop.

This rule concerns initial arming or explicit enabling on a healthy VPN. It does
not authorize removing already active protection during recovery: previously
armed recovery failures retain the block under the existing policy.

Reason: a selected protection option must not appear effective after installation
failed. Consequence: local teardown intentionally permits direct access after
failure, and the message must make that limitation explicit. Acceptance covers
both entry paths, partial installation/teardown failure, retained enabled
preference, truthful UI, stale replies and subsequent connection attempts.

### First-enable disclosure — confirmed 26 October 2026

Before the first explicit enable of killswitch, show a concise explanation of
its actual platform guarantees and require one-time confirmation. On Android,
explain that protection begins after a successful connection, persists during
tunnel interruption while its owner survives, and is not guaranteed after
force-stop, VPN-owner process death or device reboot. Explicit split exclusions
continue to use direct Internet. Do not describe this mechanism as equivalent
to system lockdown.

Keep this explanation accessible next to the setting after confirmation; do not
repeat the initial prompt on ordinary subsequent enables. Cancellation leaves
the preference and enforcement unchanged. Desktop text must reflect validated
platform guarantees rather than copying Android limitations or promising
unverified process-death protection. Use existing local settings/UI mechanisms.

Reason: users need to understand the scope before relying on protection, without
repeated prompts becoming routine noise. Acceptance: first-enable confirm/cancel,
subsequent enable without repeated prompt, persistent access to the explanation,
accurate per-platform wording and no arming based on acknowledgement alone.

### Recovery notification threshold — confirmed 26 October 2026

Use 20 seconds of continuous absence of a usable VPN path as the notification
threshold after an armed connection loses connectivity. Immediately display
recovery and blocked protection in the UI. If connectivity recovers before the
threshold, do not issue a separate interruption notification. Otherwise issue
one notification that VPN has not recovered and protection is blocking traffic,
with the agreed recovery and local Stop actions. A confirmed cause requiring
user action, such as expired access, is notified immediately.

Measure the interval across recovery attempts and standby-slot changes; starting
another attempt does not reset it. Use the existing verified usable-path state,
not merely a Start request or backend creation. Failed subsequent attempts update
status without repeated sounds or popups. Successful recovery clears the warning.
A late timer must not notify after recovery or explicit Stop.

This is a notification threshold only: it neither ends recovery nor removes
protection and does not change the recovery retry budget/backoff. In particular,
do not wait for all active recovery attempts to be exhausted before notifying.
Reason: tolerate short interruptions without hiding a prolonged outage.
Acceptance: recovery before/after 20 seconds, repeated attempts across the
threshold, immediate actionable failure, notification deduplication, and races
with recovery/Stop.

### Passive recovery retries — confirmed 26 October 2026

After bounded fast recovery attempts are exhausted on a transient failure,
retry in the background once every five minutes while connection intent remains
active. Arrival of a usable network or a network change wakes an immediate
attempt instead of waiting for that timer. The explicit “Повторить подключение”
action also wakes an immediate attempt. All attempts retain enforcement and use
the existing serialized recovery path; coalesce duplicate network events and
timer/manual triggers rather than starting overlapping or queued retry storms.
Do not reset the continuous-outage notification clock on a retry trigger.

For a confirmed failure requiring user action, stop automatic attempts until the
cause is resolved. A network event alone must not bypass a still-valid terminal
failure or authorization checks. Explicit retry revalidates the prerequisites;
it does not override them. Explicit Stop cancels pending timers and attempts;
late results cannot restart the connection or re-arm protection.

Reason: allow recovery without user supervision while avoiding hot retry loops,
but do not delay recovery for five minutes when network conditions have changed.
Acceptance: passive timer, network arrival/change, manual retry, concurrent
triggers, unresolved actionable failures, continuous blocking and Stop races.

### Android VPN permission revocation — confirmed 26 October 2026

If Android revokes Nelomai's VPN permission, including when the user activates
another VPN, stop automatic recovery and do not attempt to reclaim VPN ownership.
Fence pending attempts and late callbacks through existing lifecycle gates.
Report “VPN Nelomai отключён системой, защита Nelomai не действует”; preserve
the saved killswitch preference. Resume only after explicit Start and the normal
system consent/admission checks. Protection then arms after successful connection.

Revocation is an externally imposed loss of enforcement, not a successful local
Stop or a protected recovery state. Do not claim blocking survives revocation,
and do not infer that another VPN protects the intended traffic. Do not claim
direct Internet is available either: another VPN or system lockdown may control
it. Record the confirmed revocation without guessing which application caused it.

Reason: respect the user's system-level VPN choice and avoid competing VPN restart
loops. Consequence: Nelomai cannot guarantee protection after permission is revoked.
Acceptance: revoke while armed/blocked, concurrent recovery, no automatic reclaim,
truthful status, preference retention and explicit Start with renewed consent.
This Android policy does not authorize removing desktop firewall protection merely
because another VPN interface appears; desktop behavior needs platform evidence.

### Captive portal detection — confirmed 26 October 2026

On Android, observe the relevant physical network through existing network
callbacks and use NET_CAPABILITY_CAPTIVE_PORTAL as the system-reported evidence
that Wi-Fi requires authorization. Do not build a custom portal detector or
inspect only the VPN network's capabilities. Detection follows network attachment
and system probing; it is neither immediate nor guaranteed. Absence of
NET_CAPABILITY_VALIDATED alone does not prove a captive portal.

When the system reports a portal, show “Wi-Fi требует авторизации” immediately,
without waiting for the 20-second recovery notification threshold. Deduplicate
notifications and do not misattribute an unrelated available network's portal
to the currently working VPN path. Before initial connection, protection has
not armed, so offer authorization before Start. If protection is already active,
retain it until an explicit authorized user action; portal detection never
permits automatic disarm or temporary direct-traffic exceptions.

Separately verify whether the standard system login page works while Nelomai
retains the TUN. Do not universally require disabling protection before opening
it, and do not promise that it works until tested. If local Stop is necessary,
make the loss of protection explicit and use the agreed user action. Successful
network authorization may trigger existing recovery when connection intent is
still active, but must not restart VPN after explicit Stop.

Reason: reuse system detection to explain the network prerequisite without
inventing a probe subsystem or weakening protection. Acceptance: detected portal,
unknown/unvalidated network, delayed capability changes, initial Start versus
armed recovery, system login page with retained TUN, split behavior and no direct
leak for protected applications. Desktop detection requires its own verified
platform mechanism; Android capability names are not a cross-platform contract.

Reference: https://developer.android.com/develop/connectivity/network-ops/reading-network-state

### Android VPN-owner process death — confirmed 26 October 2026

If the VPN-owner process dies and its retained TUN is lost, attempt recovery
through the existing mechanism when the failure is detected, provided the user
connection intent is still active. Immediately report “Защита прервана,
восстанавливаем VPN”; do not wait for the ordinary 20-second blocked-recovery
notification threshold. Do not claim traffic remains blocked while ownership
and enforcement are absent. Re-arm only after successful connection and
confirmed enforcement, preserving the saved preference.

This recovery rule does not apply after explicit Stop, system revocation of VPN
permission or OS reboot. Respect existing consent, authorization, ownership and
cancellation checks, with bounded retries and no competing recovery loop. It is
not permission to circumvent Android force-stop restrictions. If no process is
alive to detect/report the failure, report it at the next available opportunity;
do not promise an immediate notification from a destroyed application.

Reason: recover the user's still-active connection intent without misrepresenting
a known enforcement gap. Consequence: protected traffic may leave directly before
recovery; this remains the disclosed Android process-death limitation, not normal
blocked recovery. Acceptance: actual owner death, surviving UI versus later reopen,
truthful lost-protection status, successful re-arm, retry limits and exclusion of
Stop/revoke/reboot paths. Controlled native backend close with a retained TUN is
a different case and does not constitute acceptance of owner-death behavior.

### Enabling the preference — confirmed 26 October 2026

When explicitly enabling killswitch on a healthy working VPN, apply protection
immediately without reconnecting, through existing platform ownership/mutation
gates. Show armed only after platform confirmation. Apply the agreed first-enable
disclosure before changing the preference; arming failure follows the confirmed
failure-to-enable policy, including retained enabled intent and local VPN teardown.

When VPN is disconnected, enabling only saves the preference: direct connectivity
remains available until a successful VPN connection and confirmed enforcement.
Saving the preference or accepting the disclosure does not itself establish
protection. Concurrent Stop or connection changes must use the existing gates
and stale-result fencing rather than a second lifecycle.

Reason: users need not interrupt a healthy connection to opt into protection,
while enabling a setting offline must not unexpectedly block Internet access.
Acceptance: healthy VPN continuity during enable, confirmed armed state,
disconnected preference-only enable, first-enable cancellation, arming failure
and concurrent Stop.

### Stop with a forced fallback — confirmed 26 October 2026

Expose one user Stop action. Immediately show stopping, cancel the connection
intent and fence late Start/recovery results. Stop takes priority over recovery:
it must not wait for completion of network requests, panel availability, server
cleanup ACK or an indefinitely held recovery operation. Use existing ownership
and cancellation mechanisms rather than a second recovery controller.

First perform bounded local transport shutdown and enforcement removal. If that
path stalls, automatically invoke a platform-specific forced fallback through
the authorized VPN owner. Do not require a separate “stronger Stop” button.
On Android, terminating the verified VPN-owner process can release its TUN;
this is a fallback candidate to validate, not permission to kill arbitrary
processes or the UI. Respect ownership/generation checks and prevent automatic
service recovery from undoing explicit Stop. On desktop, process termination
alone is not proof that firewall rules were removed: use authorized platform
teardown and verify removal of Nelomai-owned enforcement only.

Verify the outcome after both ordinary and forced paths. IPC loss alone proves
neither successful Stop nor continued protection. If the result remains unknown,
show “Не удалось подтвердить отключение VPN и блокировки” and keep local Stop
available; do not report either confirmed protection or confirmed direct access.
External system lockdown is outside this operation's authority. Preserve the
killswitch preference for ordinary Stop; preference disable still saves false
under its separate confirmed policy.

Reason: user Stop must promptly override stalled recovery without making false
claims about a security-relevant transition. Acceptance: stalled recovery/IPC,
ordinary teardown, forced fallback, verified enforcement removal, unknown
outcome, stale callbacks and no unintended service restart. Exact local timeout
and platform fallback mechanics require implementation review and hardware tests.

### Requirements, reasons and consequences

| Requirement / decision | Reason | Consequence for implementation |
| --- | --- | --- |
| Disabling protection is a local operation available without the panel, login or a functioning transport. | Most users cannot be expected to navigate unfamiliar OS settings to recover connectivity; panel/auth failures must not trap them. | Provide an offline-capable local UI path, independent of bootstrap success. Reuse authenticated local platform IPC; do not make it remotely callable or dependent on a panel token. |
| Explicit Stop/disable removes local protection after confirmed local teardown, without waiting for server lease cleanup/ACK. | Server cleanup is asynchronous and previously caused long user-visible Stop delays. | Cancel/fence the old connection intent first so late callbacks cannot re-arm it. Keep lease quarantine, ACK and server cleanup running through existing mechanisms. Never claim successful local removal before platform confirmation. |
| Explicit split exceptions remain usable while protected traffic is blocked. | The selected scope is traffic the user assigned to VPN, not all device connectivity. | Preserve effective app and destination exclusions, including mandatory policy; no broader DNS or control-plane bypass. |
| Use OS enforcement primitives and existing project mechanisms first. | Custom hot-standby alternatives previously cost substantial rework. | Android: retain standard TUN ownership. Desktop: validate WFP/nftables/PF against current platform code; do not port the Android fd technique to desktops. Add abstractions only for a demonstrated unmet need. |
| Do not enable Android system lockdown automatically. | It survives VPN-process death, but an ordinary app cannot disable it directly; its split semantics differ from the requested scope. | The chosen mode cannot promise protection after complete destruction of the TUN owner. Detect/report separately enabled lockdown; local disable must not falsely promise Internet access while that OS restriction remains. |
| Keep protection independent of the tunnel engine's lifetime while its owner remains alive. | Stopping a transport must not implicitly open direct routes. | Engine close and enforcement release are different operations, with explicit ownership and generation checks. Do not assume all processes or services survive. |

The user considered accepting blocked split applications when system lockdown
triggers, but that concession did not solve the in-app disable requirement.
It is not the policy of the selected scoped mode. Android lockdown can block
excluded apps even while VPN is connected. A notification/shortcut may open
Android VPN settings; it cannot switch system lockdown off on the user's behalf.
Do not implement direct TCP/UDP forwarding through a dummy VPN to pretend that
system lockdown has been disabled.

### Evidence and limits

The selection is based on inspected Mullvad code, not a reusable drop-in
library: [TUN provider](https://github.com/mullvad/mullvadvpn-app/blob/0508389502500fdd8e375d1e53756d4053ca23de/talpid-tunnel/src/tun_provider/android/mod.rs),
[Android service](https://github.com/mullvad/mullvadvpn-app/blob/0508389502500fdd8e375d1e53756d4053ca23de/android/lib/talpid/src/main/kotlin/net/mullvad/talpid/TalpidVpnService.kt),
[blocked-state integration](https://github.com/mullvad/mullvadvpn-app/blob/0508389502500fdd8e375d1e53756d4053ca23de/talpid-core/src/tunnel_state_machine/mod.rs#L725-L754).
System constraints: [Android VPN guide](https://developer.android.com/develop/connectivity/vpn)
and [DevicePolicyManager](https://developer.android.com/reference/android/app/admin/DevicePolicyManager).

On S23U, a temporary diagnostic 0.3.8 retained a duplicate TUN descriptor while
using the unmodified shipped AWG native library. Both real Stray slots on
servers 57/59 completed handshakes and HTTPS worked before interruption.
Stopping both native slots and then closing the complete native backend left
protected IPv4 HTTPS/UDP DNS blocked while an excluded test UID continued to
work. Explicitly closing the retained fd with Wi-Fi and mobile data disabled
removed the TUN without panel access (46 ms UI callback-to-close, not
click-to-first-traffic). Connectivity returned after restoring the networks.

A separate primitive experiment showed that `stopService()` alone did not
release a system-bound VPN service; explicit fd close was required. Force-stop
of the TUN owner removed protection without system lockdown. Neither test
establishes a guarantee after owner-process death.

Evidence is in the maintenance workspace, not a required build dependency:
`/Users/altzxd/Documents/Panel/.private/killswitch-real-awg-20261026/REPORT.md`
and sibling `result.json`; primitive test:
`/Users/altzxd/Documents/Panel/.private/killswitch-s23u-20261026/REPORT.md`.
The original APK and settings were restored and test leases cleaned up.

This is feasibility evidence, not release acceptance: automatic recreation of
TUN was deliberately rejected during the diagnostic outage. Normal recovery,
concurrent Stop/Start, runtime switching, working IPv6, LTE and other Android
vendors were not accepted by this experiment. No desktop behavior was tested.

## Shared technical contract

### Scope and actual state

One local device preference covers Tic/Tak and Stray, defaults to false, and is
not a panel setting. Capability, saved preference, connection intent and actual
enforcement are distinct. Reuse existing status/error plumbing; do not invent
a parallel state machine or silently map unavailable status to `off`/`blocked`.
The known enforcement states have these meanings:

| State | Evidence required |
| --- | --- |
| `off` | Nelomai enforcement is known absent; this does not guarantee Internet access |
| `armed` | A usable VPN path and effective enforcement are confirmed |
| `blocked` | Enforcement is confirmed present but no usable VPN path exists |

If status cannot be verified, expose the uncertainty using the existing error/
status-availability mechanism. A saved `true`, IPC timeout, backend creation or
stale cached state proves none of these states. Busy transitions are transient
UI state, not a reason to make local Stop unavailable.

Initial connection becomes successful only after the existing usable-path checks
and enforcement confirmation. It is not a requirement for one impossible atomic
transaction spanning network handshake and OS installation; no protection is
promised before successful initial connection. Once armed, normal recovery must
not remove enforcement. Process death/revoke are separately disclosed losses,
not protected recovery or authorization to silently report `blocked`.

### Split scope and control plane

Apply the existing effective split policy, including mandatory exclusions:

1. Necessary Nelomai control traffic and pinned VPN transport endpoints.
2. Android applications outside the protected set (exclude/include modes).
3. Existing explicit address/domain/local-network exclusions.
4. Traffic through a usable VPN path.
5. Other protected egress is blocked while enforcement exists.

An exclusion is not a promise that its destination is reachable; underlying
network failure and system lockdown still apply. Do not widen DNS, IPv6 or
LAN exceptions merely to make a test pass. Use existing domain-resolution and
split mechanisms; test cached DNS46 destinations and DNS/IPv6 behavior without
inventing a second domain tracker. Do not add desktop application split tunneling
as part of this feature.

On Android, preserve the existing Nelomai package exemption and socket protection/
binding. Another package, including system push or portal-login components, does
not automatically inherit that exemption. Do not use `allowBypass()` as a shortcut
for recovery. Validate control-plane access on both physical networks.

For desktops, first inspect the current helper/control-plane path and use a
narrow OS-supported exception where available. A new persistent panel-IP cache,
TLS connection override or common route-set abstraction is not mandatory. Only
if existing mechanisms cannot recover under enforcement, design the smallest
bounded fallback and review its scope. Preserve hostname/SNI, certificate and
runtime authorization checks; never add a blanket system-DNS bypass. A stale
endpoint/cache fails recovery without removing existing protection.

### Ownership, cancellation and cleanup

Extend existing Start/Stop, operation gates, generation/owner checks, durable
intent and local authenticated IPC. Do not default missing intent to destructive
user Stop. Review compatibility with the desktop owner before changing shared
contracts; capabilities come from verified contracts, not version literals.
Prefer existing retry/wake paths over adding an IPC command with identical meaning.

Local enforcement lifetime is independent of server lease lifetime. Recovery
may reconcile, clean up or replace old leases under existing rules while local
protection remains. Do not require retaining the same lease throughout blocked
recovery. Stop confirms local teardown without server ACK, while existing
quarantine, admission, cleanup and audit checks remain intact.

Every protection-release path follows a confirmed product decision above.
An internal close, failed cleanup or coordinator shutdown is not user consent.
Cancel intent before teardown; stale native/network results cannot resurrect it.
Forced Stop still checks caller identity and the exact current owner. Loss of
IPC alone must not justify killing another owner or deleting unowned objects.

### Android implementation boundary

Retain a duplicate of the existing TUN fd in the existing VPN owner before
passing the engine fd to native code. Native backend/slot close must not release
the retained interface. Preserve one shared TUN across hot-standby operation.
Disabling protection on a healthy tunnel closes the retained copy, not the
engine's still-required descriptor. Stop closes local transports and all owned
TUN handles and verifies removal; do not rely solely on `stopService()`.

Reuse `NelomaiVpnService`, `RedundantNativeBackend`, existing redundant ownership/
total-loss lifecycle and the connection-intent coordinator. Do not require a new
controller, owner process, network stack, blackhole TUN or native backend rewrite.
Retain the interface during restart when possible. If effective split policy
requires replacement, validate safe system handover and rollback; do not claim
atomicity from fd duplication alone. The diagnostic rejection of new `establish()`
is fault injection, not product logic.

Android system lockdown is separate. Never enable it automatically or imply this
app can disable it; report observable external restrictions and offer OS settings
when needed. Do not emulate unrestricted access by userspace direct forwarding.

### Desktop candidates, not approved implementation recipes

| Platform | Candidate system mechanism | Required review before implementation |
| --- | --- | --- |
| Windows | WFP user-mode filters | Existing service ownership, transaction ordering, IPv4/IPv6 and flow coverage, same-boot restart and boot-boundary lifetime |
| Linux | Owned nftables rules/table | Existing helper integration, atomic updates, rule ordering, flow/split scope and same-boot reconciliation |
| macOS | Owned PF anchor and enable reference | Actual anchor placement/order, stateful-flow behavior, safe transactions, owned reference release and restart/reboot behavior |

Do not add a kernel driver, generic firewall framework or mandatory shared
backend trait without demonstrated need. These candidates are not validated by
S23U and must be reviewed against the desktop baseline without modifying 0.4.x
as part of this documentation work. Do not prescribe a particular PF anchor path,
WFP filter lifetime or nft rule renderer before that review.

Use only owned objects; never flush global rules, change global defaults, disable
another component's firewall or remove someone else's enable reference. Validate
existing established TCP/UDP flows as well as new flows: a ruleset listing alone
does not prove enforcement. Privileged state, if needed, uses existing protected
storage, bounded input, canonical values and atomic updates. Preserve same-boot
protection, but do not restore a previous boot's block or leave it until GUI opens.
If cleanup cannot confirm state, report uncertainty rather than `blocked` by fiat.

## Diagnostics and verification

Use existing local diagnostics, automatic-report deduplication and rate limits.
Record safe transition/reason/stage codes, timings, state availability, ordinary
versus forced Stop outcome and exemption counts. Never record credentials,
configuration, endpoints/IP addresses or package identifiers. Reuse existing
report triggers; do not introduce mandatory uploads for every blocked transition
or a second diagnostics scheduler. Notification timing is the confirmed 20-second
policy, not report delivery or recovery-burst exhaustion.

The checklist in the [implementation plan](../plans/2026-08-23-scoped-kill-switch.md)
is the implementation/acceptance map. Tests must observe real traffic and platform
state, not only UI or mocked success. A network with no working baseline cannot
prove blocking or recovery. No IPv6 baseline means IPv6 is untested, not passed.
The feasibility evidence above is not full release acceptance.

## Technical questions remaining

Product decisions above are approved; the following need code review/measurement,
not invented product defaults:

- Safe live split changes and rollback with no leak for unaffected traffic.
- Wi-Fi ↔ LTE recovery with enforcement, and system portal login while blocked.
- Forced Stop timeout/mechanism and independent result verification per platform.
- Desktop enforcement ordering, existing-flow coverage and same-boot versus
  reboot lifetimes, including shutdown without opening the UI at next boot.
- Minimal additive contract fields and capability negotiation against current
  Android and desktop owners; no parallel coordinator or literal release checks.

If a platform cannot satisfy a requirement, retain the limitation as unresolved
and return with concrete evidence. Do not silently relax protection or promise
untested guarantees. Builds, releases and deployment require their own task;
this review changes documentation only.
