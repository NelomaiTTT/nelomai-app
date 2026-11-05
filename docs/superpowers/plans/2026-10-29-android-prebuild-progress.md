# Android 0.5.0 — first-build checkpoint

Authorized by Андрей on 29 October: work personally through implementation and review/fix after each stage; stop when the next step is the first build. No delegation, push, candidate/APK assembly, emulator/device launch or production action. Source stays in the Android worktree on the internal disk; all generated files, dependencies, test snapshots and logs stay on the external SSD.

Source: HEAD branch `Future/android-killswitch-0.5.x`, base `9e6262c20ebdf3bf289302bb9759300792bb5f0d`; the filesystem ref is lowercase `future/android-killswitch-0.5.x` (use that for local cloning; do not rename shared refs). The existing scoped-kill-switch specification remains authoritative. This checkpoint covers readiness for a first local test build, not release acceptance. Historical checklists in the main plan include device and desktop gates and therefore remain unchecked where those gates have not run.

## Stage 1 — previous review defects: closed

Offline reconnect now carries a unique Start identity through start and failed-start cleanup. Cancellation/logout remains an explicit Stop. Native cancellation after handshake rejects only the provisional protection from that attempt. An already-down backend retries the service-owned descriptor close instead of acknowledging a leaked protection handle.

All three regressions failed against the prior behavior, then passed after correction. 27 targeted JVM tests and 13 offline Core tests passed. Personal review: no remaining actionable finding in this increment. Evidence: `stage1-*` in the evidence directory below.

## Stage 2 — service and lifecycle: closed for first-build preparation

- Service-owned TUN retention covers the legacy backend and real redundant factory path. Healthy enable/disable uses an independent descriptor and does not reconnect. The native backend keeps only its existing short-lived source duplicate. A fresh handshake/readiness proof is required after loss; an old handshake cannot claim recovery.
- Preference is device-wide, default off, outside runtime/account namespaces. First enable requires disclosure. Failed persistence/close is reported; failed arming keeps the requested setting and initiates local Stop.
- Explicit Stop uses the existing service cancellation, cleanup and watchdog machinery. Its bounded fallback requires the unchanged owner generation, durable cancelled intent, own UID and exact `:vpn` PID/process name. Automatic watchdog timeout does not kill a retained TUN owner.
- Existing recovery schedules remain authoritative. Network/manual wake admits one immediate attempt; terminal/auth guards remain. No second recovery controller or background monitor was added.
- Notifications use the existing Handler: continuous 20-second outage, immediate actionable/lost/unknown states, deduplication, recovery/Stop clearing, local Stop and retry actions. Captive portal is based on system capability of the selected physical network. Below API 29, unavailable lockdown observation is reported as unknown.

The service baseline passed 310 selected tests. Six targeted mutations were caught: omitted retained-copy close, wrong-process force Stop, wrong notification threshold, stale handshake, delayed immediate retry, and stale source ownership. Mutations were restored. Final integration expands coverage to whole relevant service classes and existing owned-policy tests. Old Unsafe fixtures now initialize the real retention gate; no production null guard was added to accommodate them.

## Stage 3 — app integration and final review: closed for first-build preparation

Implemented:

- Typed native/Rust status (`off`, `armed`, `blocked`, `unknown`) and setting/retry/local Stop commands. Transport failure cannot mean disabled, and unknown future states map to unknown. Native VPN state is independent of bootstrap presentation.
- An Android protection panel available while signed out, offline, busy or after runtime-channel loss. First disclosure, persistent help, actual state/cause, external-lockdown caveat, retry and always-accessible local Stop. Existing 1-second polling is reused. Revision fences discard old reads/writes, including a hung preference request overtaken by Stop.
- Local Stop bypasses authentication/lifecycle waits. It preserves the legacy connection identity for the existing cleanup worker. A foreground snapshot cannot prematurely erase this specific pending cleanup; existing ordinary expected-Stop behavior is preserved. No panel ACK is needed to release local protection.
- Unexpected owner-channel loss uses existing scoped cleanup when protection is retained or uncertain. Explicit Stop/logout/confirmed transitions still use unscoped teardown. Other platforms retain the default behavior.
- Update and every runtime transition have Android confirmation before mutation. Confirmed installation continues through the existing common teardown barrier. Android background installation is deferred to explicit installation: the existing combined install pipeline starts with Stop and has no atomic idle-only admission. Checks remain background; the UI states that installation requires confirmation instead of displaying a misleading automatic-install toggle. Saved preferences are not reset. Non-Android backends retain their previous default behavior.
- Split application recognizes a retained interface after transport loss and uses the existing serialized replacement/rollback path. Saving a preference is no longer reported as effective application when no current owner/connection can apply it. Busy/rejected native ownership remains an explicit apply failure with previous enforcement retained; it is not labelled as a successful live scope change.

Review corrections included stale status after Stop, native VPN before bootstrap, duplicate transition prompts, owner-channel loss accidentally disarming, and loss of legacy cleanup identity. Disabling protection from blocked/unknown state now first confirms the same local user Stop; failure cannot silently save a disabled preference. The cleanup regression includes a failed panel Stop, foreground polling and subsequent successful retry. Eight targeted mutations verify stale status, false certainty on IPC failure, automatic disarm, dropped common confirmation requirement, skipped retained-policy application, repeated-save bypass, discarded cleanup identity, and bypassed Stop before disabling. All injected mutations are confined to the SSD snapshot and restored.

Personal review/fix cycles for all three increments are complete. No remaining actionable code-review finding was identified in the first-build preparation scope. Final verification below ran after restoring the deliberate mutations and correcting the last review findings. Device acceptance remains open; no release-readiness claim follows from unit/compile checks.

## Next stage — first local build, only after a new user request

Use the existing pipeline in `scripts/android/README-runtime-v1.md`, including its local-test container path and identity/signature checks. Do not create a release candidate, publish or install on a user device as an implicit consequence of this checkpoint.

1. Validate SSD mount; use `source /Volumes/Apple-VM/Nelomai/android-050/env.sh || exit 1`. Build only the snapshot under `/Volumes/Apple-VM/Nelomai/android-050/work/tun-ownership-20261028`; never compile the internal source worktree.
2. Build the real Go/JNI backend and Rust common/latest/stable components with the existing scripts. SDK, NDK, Java, Rust, npm dependencies and caches are under this SSD root. The Go archive uses the project's existing 1.25.0 pin, with SHA-256 verified against official Go download metadata; it is a dependency, not an application build.
3. Use isolated local test manifests/keys and inspect the resulting APK with the repository verifier. Keep test artifacts out of release inputs. Preserve the agreed minSdk baseline.
4. Emulator smoke checks: permission, default-off/first disclosure, UI while offline/signed out, preference persistence, initial failure/cancellation, local Stop and truthful unknown status. Emulator routing does not accept OEM behavior.
5. Real-device traffic acceptance: legacy and hot-standby, one/both-slot loss, full native close/recovery, Wi-Fi/LTE, IPv4/working IPv6/DNS, split exclusions and existing/new TCP/UDP flows. Verify no direct path for unaffected protected traffic; do not infer this from a valid descriptor.
6. Exercise live policy replacement/rollback while armed and blocked, including recovery/Stop contention and the no-current-owner case. Existing busy rejection is a safe failure, not acceptance of immediate live edits through every recovery state. If platform ordering or the existing owner boundary cannot satisfy the approved behavior, record the exact failure and correct it before release.
7. Actual stalled-worker/IPC Stop, own-process termination, UI close/recents, VPN-owner death, revoke, reboot and update/runtime confirm/cancel/failure. Verify separately enabled Android lockdown rather than promising direct connectivity after Stop.

## Evidence and boundaries

Evidence root: `/Volumes/Apple-VM/Nelomai/android-050/logs/prebuild-20261029/`.

JVM tests exercise production service/runtime/factory/coordinator code. JNI/network backends and Android establishment/descriptor duplication are replaced with fixtures and independent file-backed descriptors. Process termination is observed through a shadow; no real process is killed. Rust tests substitute panel/tunnel ports. Frontend tests exercise action/race logic and server rendering; they are not an Android WebView visual test. Android-target `cargo check` verifies Rust compilation, not APK packaging or actual traffic.

Kernel TUN lifetime/routing, atomic scope continuity, working IPv6, OEM behavior, true process death and performance under production conditions remain unaccepted. The first build/device stage is required to evaluate them. No VM, emulator, candidate, push or production operation was started in this preparation turn.

### Final verification receipts — 29 October 2026

| Check | Result | Evidence under the root above |
| --- | --- | --- |
| Android service/backend/coordinator and lifecycle JVM tests | 610 passed, 0 failures/errors/skips, 16 selected whole classes | `prebuild-final-jvm.json`, `prebuild-final-jvm.log`, `prebuild-final-jvm-xml/` |
| Frontend action/status races and component rendering | 63 passed in 6 files | `prebuild-final-ui.log` |
| Svelte/TypeScript | 0 errors, 0 warnings | `prebuild-final-ui-check.log` |
| Core split policy, local Stop and foreground reconciliation | 102 + 1 + 13 passed | `prebuild-final-core-{split,local,foreground}.log` |
| Application local Stop during stalled bootstrap | 5 passed | `prebuild-final-application.log` |
| Common runtime boundaries and updater forwarding | 7 + 38 + 10 passed | `prebuild-final-common-{boundaries,updater}.log` |
| Native status models and updater coordinator | 19 + 17 passed | `prebuild-final-{models,updater}.log` |
| Android-target Rust compile check | exit 0 | `prebuild-final-android-check.log`, `prebuild-final-rust.json` |
| Targeted mutation experiments | 6 service + 8 integration mutations detected; restored | `stage2-mutations.json`, `stage3-mutations.json` |
| Source snapshot and whitespace | modified/untracked source hashes match SSD snapshot; `git diff --check` clean | `source-manifest.json` |

The final Rust test rows total 212 tests; earlier red/green and mutation-restoration reruns are not counted again. This is a targeted verification set, not a full-project test run. Gradle ran unit-test tasks only; no application APK was assembled. The next executable stage is the first local test build followed by emulator/device checks.

### Follow-up review — two fixes verified, 29 October 2026

The subsequent requested review found two gaps in the checkpoint above. Both are now corrected:

- Network wake now updates the existing health monitor and native network availability before accelerating a pending recovery attempt. The regression exercises the real coordinator/monitor with substituted panel/native ports, verifies recovery after the existing four-second stabilization boundary, and detects omission of either network update. The existing cancelled-recovery test now also checks network wake after Stop.
- `ACTION_KILL_SWITCH_PREFERENCE` is classified as a non-starting command. It remains available without an authenticated Start session. The regression verifies service dispatch/admission, real enable/disable persistence without starting VPN, and continued Start admission for actual Start/retry commands.

Both new regressions failed before the fixes. Afterward, 156 tests passed across `RedundantConnectionCoordinatorTest`, `VpnPermissionCleanupDispatchTest`, `ServiceTunIntegrationTest`, and `KillSwitchPreferenceTest`, with no failures/errors/skips. Two additional SSD-only mutations (missing monitor update and missing native update) were detected; the tested implementation was restored. Personal review of these changes found no further actionable defect. Unrelated Rust/frontend checks were not repeated because their code and dependencies did not change.

Evidence: `/Volumes/Apple-VM/Nelomai/android-050/logs/review-fixes-20261029/` (`red.log`, `green.log`, `green.json`, `mutations.json`, and `source-manifest.json`). The earlier review reproductions remain in sibling `review-20261029/`. JVM verification still substitutes actual network/JNI/platform establishment and does not constitute device routing acceptance. No APK, emulator, push or production change was performed. The next stage remains the first authorized local test build.
