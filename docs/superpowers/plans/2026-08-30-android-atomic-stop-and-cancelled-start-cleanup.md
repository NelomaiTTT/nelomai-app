# Android Atomic Stop And Cancelled Start Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove Android Stop/Quick Off cancellation races and guarantee exact cleanup when a locally cancelled runtime start reports `tunnel_start_cancelled` after lease acquisition.

**Architecture:** Add an untyped service-owned cancel-current IPC whose single encrypted-store mutation advances the current generation and clears `desiredActive`; Tauri calls it directly. Quick Toggle selects from one coherent recovery-envelope snapshot and retains the existing dispatch ticket fence. Treat the typed local cancellation callback as compensation evidence only after a durable lease exists: persist `cleanup_pending` with one stop operation ID and run the existing local-then-panel cleanup machine.

**Tech Stack:** Kotlin/JVM Android service/plugin, Rust Tauri mobile plugin and commands, JUnit 4, Cargo tests.

**Spec:** `docs/superpowers/specs/2026-08-28-automatic-connection-intent-recovery-design.md` plus compatibility-fix round 3 parent payload.

## Global Constraints

- No status→cancel sequence for user Stop.
- Preserve typed generation cancel for internal callers.
- Quick Toggle observes desired state and generation from one store snapshot.
- Runtime cancellation cleanup uses the durable lease and exact persisted stop operation ID.
- Local stop precedes panel stop; retry/process death retains cleanup state and the same ID.
- No second scheduler, vendor/panel/production/workflow edits, commit, push, or deploy.

---

### Task 1: Atomic service Stop and coherent Quick Toggle

**Files:**
- Modify: `plugins/tunnel-android/android/src/main/java/AndroidRecoveryStore.kt`
- Modify: `plugins/tunnel-android/android/src/main/java/NelomaiVpnService.kt`
- Modify: `plugins/tunnel-android/android/src/main/java/TunnelServiceProtocol.kt`
- Modify: `plugins/tunnel-android/android/src/main/java/TunnelPlugin.kt`
- Modify: `plugins/tunnel-android/src/mobile.rs`
- Modify: `plugins/tunnel-android/src/desktop.rs`
- Modify: `src-tauri/src/commands.rs`
- Test: corresponding Android store/service/protocol and Rust command/plugin tests

- [x] **Step 1:** Add RED tests proving the production Android Stop route performs one untyped service cancel, and store cancel-current wins an interleaved begin commit.
- [x] **Step 2:** Add RED tests proving Quick Toggle uses one coherent intent snapshot and queued Start completion cannot publish Start after Off.
- [x] **Step 3:** Implement one cancel-current service action/command plus atomic current-store mutation; route Tauri Stop directly to it.
- [x] **Step 4:** Switch Quick Toggle selection to the coherent coordinator snapshot while retaining legacy projection migration and dispatch fencing.
- [x] **Step 5:** Run focused Android/Rust tests GREEN.

### Task 2: Durable cleanup for `tunnel_start_cancelled`

**Files:**
- Modify: `plugins/tunnel-android/android/src/main/java/NelomaiVpnService.kt`
- Test: `plugins/tunnel-android/android/src/test/java/NelomaiVpnServiceTest.kt`

- [x] **Step 1:** Add RED runtime-boundary/coordinator tests for cancellation callbacks before backend work, during backend start, and after backend-up compensation.
- [x] **Step 2:** Add RED reconstruction tests proving failed local and panel cleanup retain the exact stop operation ID and never terminal-strand the lease.
- [x] **Step 3:** Persist cleanup for `tunnel_start_cancelled` after lease acquisition and enter the existing local-first cleanup path without changing the shared terminal classifier.
- [x] **Step 4:** Run focused tests GREEN and self-review exact ID/generation/error paths.

### Task 3: Verification and report

- [x] **Step 1:** Run the full Android JVM suite, plugin tests, app/commands tests, and Android aarch64 check.
- [x] **Step 2:** Run `cargo fmt --all --check` and `git diff --check`.
- [x] **Step 3:** Obtain a narrow read-only review and append RED/GREEN evidence to the Task 12 report.

## Self-Review

- Spec coverage: atomic user Stop, coherent Quick ordering, durable exact compensation, retry/process death.
- Scope: no classifier weakening and no new scheduler.
- Type consistency: public untyped cancel-current is additive; typed cancel remains available.
