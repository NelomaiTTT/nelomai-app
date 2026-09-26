# Desktop Hot-Standby Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement desktop two-member hot-standby with primary-first Start and last-active WARM, preserving single connections.

**Architecture:** Keep DesktopConnectionIntent, existing server recovery-v2 API and privileged managers. Share deterministic health/session decisions in client-tunnel; extend platform backends with separately owned slots and one route/DNS owner. Do not enable UI reserve admission before native lifecycle and cleanup are connected.

**Tech Stack:** Rust/Tokio, existing Unix socket and Windows pipe protocols, WG/AWG3 native backends, existing panel API.

**Spec:** `docs/superpowers/specs/2026-09-26-desktop-hot-standby-design.md` (approved 26.09; user explicitly requests implementation immediately after planning).

## Global Constraints

- Existing local branch codex/desktop-redundant-warm, base6b8aa90; no new branch, push, install, production or release.
- Windows/macOS/Linux; Tic/Tak WG and Stray AWG3. No modified vendor changes.
- Existing single connection and Android remain working; killswitch is separate.
- Primary must not wait for reserve. Stop shuts down locally before server ACK.
- Ordinary Stop retains only last-active for one hour with negotiated warm_stop_v1; standby released.
- No host networking/firewall changes in tests. All platform side effects use fakes until hardware authorization.
- Own review/planning by parent. Execute inline; no approval pause between tasks.
- This is a multi-stage feature: shared code alone is not desktop hot-standby completion.

## Review Focus

- Stale successful probe after physical-network switch must not promote a dead standby (Tasks1/3).
- Partial route switch must not claim successful promotion or lose ownership needed for cleanup (Tasks2/3).
- Late Stop ACK from old session must not stop new primary (Task4).
- UI closes while primary dies: native failover continues without GUI/panel roundtrip (Tasks3/5).
- Same VIP and DNS on two native interfaces must not steal active traffic or loop outer UDP (Tasks2/5).

## Native audit before enablement

Confirmed from pinned sources used by scripts/windows/prepare-runtime.ps1:
WireGuardWindows4e6726c23ae9c5cb58e0c9910f3b7515621d133d and
AmneziaWgWindows575626d8f8aa5b64114cf378a08e54bf852d909b:
`tunnel/addressconfig.go` honors TableOff for routes and restrictive firewall,
but still sets interface addresses and DNS. Therefore reserve configs need
Table=off and no DNS, with session owner managing data routes/DNS. Disabling
routes alone is not sufficient. This is code evidence, not a Windows packet test.
Unix backend permits separating configure_interface from configure_peer_routing
and configure_dns, but current singleton managers must not be used twice.

## File structure / boundaries

- `crates/client-tunnel/src/redundancy/health.rs`: deterministic decisions, no I/O.
- `crates/client-tunnel/src/redundancy/probes.rs`: monotonic staggered scheduling and stale ticket fencing.
- `crates/client-tunnel/src/redundancy/session.rs`: owned local session/role transition, Stop fence.
- `crates/client-tunnel/tests/redundant_health.rs`, `redundant_probes.rs`, `redundant_session.rs`: behavioral tests.
- Unix `backend/{linux,macos}.rs`, Windows `windows/{backend,install,service,routes}.rs`: native slot and route/DNS ownership only.
- Existing service lib.rs/request protocols and host loop: dispatch/tick/capabilities, no duplicate daemon.
- client-core/application and `src-tauri/src/connection_intent.rs`: server session lifecycle and UI admission.

### Task 1: Shared health policy and staggered probes

**Files:** Create `crates/client-tunnel/src/redundancy/{mod,health,probes}.rs`; modify `crates/client-tunnel/src/lib.rs`; tests `crates/client-tunnel/tests/redundant_{health,probes}.rs`.

**Interfaces:** Produces `RedundantHealthMonitor::new(initial_network_validated: bool)`,
`network_changed(now_ms: u64, validated: bool)`, `evaluate(now_ms: u64, slots: &[SlotObservation]) -> FailoverDecision`,
`primary_ready(now_ms: u64, slot: &SlotObservation) -> bool`, `failed(...) -> bool`.
Types mirror Android BackendHealth/StandbyProbeState/SlotObservation; monotonic time only.
Produces `ProbeSchedule::new(active: Slot, now_ms: u64)`, `poll(now_ms) -> ProbeBatch`,
`complete(ticket, succeeded: bool, now_ms) -> bool`, `set_standby_available(bool)`,
`network_changed(now_ms)`, `promote(slot, now_ms)`, `stop()`.
Tickets include a process-unique sequence; epoch changes clear accepted in-flight
tickets. ProbeBatch carries both started and expired probes so native cancellation
and failure accounting cannot be skipped. Slot enum A/B prevents invalid indexing.

- [x] Step1: Write behavioral tests for initial primary readiness without standby,
  soft failure corroboration (initial +2 retries), no stale/unproven standby,
  hard failure promotion, pending standby vs stalled, malformed slot sets,
  network stabilization4s, ready dwell15s/3successes, standby failure dwell5s.
  Assert literal decision `switch_to=Some(1)` only for usable reserve;
  initial failed primary probe alone must return no switch.
- [x] Step2: Run `cargo test -p nelomai-client-tunnel --test redundant_health`.
  Expected RED (new policy missing), not a native/host failure.
- [x] Step3: Implement health.rs matching Android decisions, requiring fresh
  handshake and successful probe even for cached READY. No platform side effects.
- [x] Step4: Write probe scheduler tests: primary@0, standby@1000 after failure,
  primary@2000, standby@3000; no concurrent probe per slot; cancel/fence on network
  change/promotion/Stop; late/duplicate/forged tickets ignored. Expire a probe at
  2000ms as failure; never catch up by launching an unbounded batch after sleep.
  Correction during Task2 integration: the earlier1000ms expiry confused the
  standby phase with Android's2000ms DNS response budget. Preserve that budget.
- [x] Step5: RED then implement probes.rs. Primary period2000ms; suspect standby
  phase1000ms; no standby probe without installed slot. Completed primary success
  ends suspicion, but does not counterfeit/cancel delivered standby evidence.
  Continuation: normal standby probes are immediate then5000ms after completion,
  switching to15000ms after three consecutive successes (Android cadence, not a
  substitute for handshake/Ready dwell). A new failure episode cancels an older
  in-flight standby ticket; ProbeBatch.cancelled must be consumed before native
  starts. Epoch change/removal resets normal cadence; repeat failures within one
  episode do not cancel its fresh reserve query.
- [x] Step6: `cargo test -p nelomai-client-tunnel` and changed-file rustfmt/Clippy.
  Expected all pass. Commit shared policies with tests, no feature capability yet.

### Task 2: Platform slot/data-route ownership

Status: **in progress**, not complete. Low-level independently named member
backends/SCM primitives, common route/DNS transactions, bound probes, Unix native
composition and macOS physical policy discovery are implemented. Mac private
pair factory and captured native identity cleanup recovery added. Linux route/rule
adapter and member-only loose RPF added, bound-rule resources connected to the
session planner with primary-first registration. Addressed Windows NT/UAPI
metrics added. Mac host, Windows MSVC and Linux GNU cross-checks now pass.
Linux resolver/factory, Windows network adapter/recovery, launch crash-gap
handling, engine wiring and full lifecycle
integration still required before enabling this path. Same-VIP packet behavior
is not proven by the fake tests.
See `docs/desktop-hot-standby-progress.md` for evidence and remaining gates.

**Files:** Existing Unix/Windows backend/routes/install modules; create each platform's `redundancy.rs` adapter and fake route/process tests adjacent to platform modules.

**Interfaces:** Consume Slot A/B and existing TunnelConfiguration/DesktopTunnelOptions.
Produce session-scoped backend operations `start_slot`, `stop_slot`, `probe_slot`,
`select_active`, `rebind_slots`, `snapshot`, `close_session`; every operation takes
the same typed local ownership key (runtime namespace + session id + generation).
Keep configuration/keys redacted and bounded, separate slot runtime paths.

- [ ] Step1: Add failing fake-backend lifecycle tests: starting B never invokes A
  stop or global DNS restore; probe B cannot use A egress; routes cover IPv4/IPv6.
  Exact fake events after B start must exclude `stop(A)`/`restore_dns`.
- [ ] Step2: Implement Unix interface naming and independent runtime state, extract
  slot operations from singleton orchestration without changing single behavior.
  One owned route/DNS transaction installs active routes and both endpoint bypasses.
- [ ] Step3: Implement Windows slot-specific config/service/interface identities;
  TableOff suppresses native route/default filtering, DNS handled by common owner.
  Validate that configured VIP can be retained across selected-member switching;
  no silent fallback to sequential reconnect. If pinned backend prevents correct
  same-VIP/slot-probe isolation, record concrete evidence before redesigning adapter.
- [ ] Step4: Test partial start/switch/stop failure and restart with exact owned
  state; preserve foreign routes and interfaces. Failed switch must not publish B.
- [ ] Step5: Run full Unix/Windows crate suites plus cfg-specific compilation where
  toolchains exist. Report unsupported cross target separately, never as passed.
  Commit independently reviewable platform adapter changes.

### Task 3: Native session coordinator and IPC

**Files:** `client-tunnel/src/redundancy/session.rs`, both services' lib.rs and service loops, protocol tests.

**Interfaces:** Consume Tasks1/2; produce serialized session snapshot (session id,
generation, active slot, installed members, role/membership generations, Stop phase).
Expose versioned StartRedundant, InstallStandby, StatusRedundant, StopRedundant
and server-role acknowledgement, preserving existing request compatibility rules.

- [ ] Step1: RED session tests for late observation/old role ACK, duplicate Start,
  Stop-before-standby-install and failed native promotion. Active changes only after
  successful native select; Stop advances a fence before async work.
- [ ] Step2: Implement one helper-owned lifecycle with durable scoped state and
  timer-driven probes independent of UI connection. Do not store panel credentials
  in generic transport configuration, command arguments or logs.
- [ ] Step3: RED IPC tests for malformed scope, message bounds, old helper capability,
  redaction and different runtime user. Implement additive capability negotiation
  and request validation; unsupported helper never drops redundancy silently.
- [ ] Step4: Run service/session/IPC suites; fake-clock UI-disconnect test must
  still select usable B. Commit.

### Task 4: Desktop server lifecycle, quick actions and WARM

**Files:** `client-core/src/lib.rs`, `client-application/src/lib.rs`, desktop connection_intent/commands, existing durable stop storage and tests.

**Interfaces:** Consume service session snapshots; reuse start_recovery_v2,
report_redundant_role/acquire/release/commit/stop API types and existing durable operations.

- [ ] Step1: RED test that reserve=true reaches helper as pair contract, not ordinary
  start; primary success unblocks Running while standby API is deliberately pending.
- [ ] Step2: Connect desktop intent generation to recovery-v2 and native capability;
  standby API preparation runs asynchronously and fences each response.
- [ ] Step3: RED tests A→B→Stop keeps B, releases A; full cleanup for logout/revoke/
  runtime switch; old server without warm_stop_v1 uses full Stop.
- [ ] Step4: Implement durable scoped Stop: first attempt before local shutdown,
  control retry outside tunnel every10s, same operation id; only terminal ACK clears
  pending record. Unknown server role reconciles before choosing WARM member.
- [ ] Step5: RED late old Stop ACK/new Start and crash-before-ACK; integrate existing
  scheduler without a parallel retry loop. Run core/application/storage suites;
  verify ordinary single and Android unchanged. Commit.

### Task 5: Cross-layer verification and handoff

**Files:** existing e2e matrix/desktop helper docs; test fixtures for Tasks2–4.

**Interfaces:** Entire previous lifecycle; no new public API.

- [ ] Step1: Add scripted fake integration Start→A traffic→B ready→A failed→B
  traffic→network change→Stop→WARM→Start fresh standby, with unique op/epoch fences.
- [ ] Step2: Test failed candidate commit, stale membership, both transports unavailable,
  helper crash recovery and UI close. Run `cargo test --workspace`, frontend checks
  and relevant Python contract tests. Every failure classified, not silently skipped.
- [ ] Step3: Parent reviews diff/security/lifecycle against spec. Fix real regressions
  via RED/GREEN; retain branch locally, no merge/push/install.
- [ ] Step4: Record native build and packet-test gaps per OS. Hardware acceptance
  remains separate; do not report shared-only code as completed hot-standby.

## Plan self-review

Spec coverage maps: scope/native ownership Tasks2/3; primary-first/health Task1/4;
IPC/backcompat Task3; Stop/WARM Task4; network change Task1/2/3; test gates Task5.
Native signatures for Task2 are intentionally finalized against platform types at
task start, not guessed wrapper code. Any interface change is recorded in the ledger.
No new framework, no one-service-per-slot manager, no Android rewrite.
