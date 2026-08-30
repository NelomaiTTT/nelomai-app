# Android Immediate Connection Cancellation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Invalidate Stop, Quick Off, and logout durably before a busy Android credential executor can release a late start.

**Architecture:** Keep HTTPS, reconciliation, cleanup, and runtime operations on the existing single credential executor. Caller-path cancellation invalidates a small service dispatch ticket and immediately advances the durable connection generation; queued starts carry both the ticket and captured generation, so they abort before refresh when already stale and fail the final store CAS when invalidated during refresh. Quick Toggle uses the ticket's pending desired projection only to order multiple commands that arrive before the first Start persists.

**Tech Stack:** Kotlin/JVM, Android service coordinator/store, JUnit 4.

**Spec:** Parent compatibility-fix round 2 payload plus `docs/superpowers/specs/2026-08-28-automatic-connection-intent-recovery-design.md`.

## Global Constraints

- No HTTPS or runtime work on the service caller/main thread.
- Stop/Off/logout must invalidate the generation before waiting for the executor or operation gate.
- Capability validation and intent persistence retain refresh-before-persist ordering and a final generation CAS.
- Cleanup/reconcile uses the existing executor and exact durable operation IDs.
- No second scheduler, vendor/panel/production/workflow edits, commit, push, or deploy.

---

### Task 1: Dispatch ticket and durable tombstone

**Files:**
- Modify: `plugins/tunnel-android/android/src/main/java/NelomaiVpnService.kt`
- Modify: `plugins/tunnel-android/android/src/main/java/AndroidRecoveryStore.kt`
- Test: `plugins/tunnel-android/android/src/test/java/NelomaiVpnServiceTest.kt`
- Test: `plugins/tunnel-android/android/src/test/java/AndroidRecoveryStoreTest.kt`

**Interfaces:**
- Produces: a dispatch state that issues queued-start tickets, orders Quick toggles, and invalidates tickets synchronously.
- Produces: coordinator begin with an expected durable generation and idempotent cancel that advances the generation even when desired state is already false.

- [x] **Step 1: Add RED tests** for idle cancellation advancing the generation, Stop invalidating a blocked panel response before runtime start, queued Start then Off producing no new intent, immediate logout tombstoning while executor work remains blocked, and queued double-toggle Start→Stop ordering.
- [x] **Step 2: Run the focused JVM tests and confirm failures are caused by queued cancellation and missing dispatch-ticket behavior.**
- [x] **Step 3: Implement the minimal dispatch state, expected-generation begin CAS, and immediate caller-path cancel/logout.**
- [x] **Step 4: Run focused tests GREEN, then the full Android JVM suite.**
- [x] **Step 5: Run Rust app/aarch64/fmt/diff gates, obtain a narrow read-only review, and append RED/GREEN evidence to the Task 12 report.**

## Self-Review

- Spec coverage: immediate durable invalidation, stale queued start abort, busy-runOnce late response handling, logout tombstone, and double-toggle ordering are all explicit.
- Placeholder scan: no deferred implementation or ambiguous error-policy work.
- Type consistency: dispatch tickets remain service-local; the durable generation remains the cross-process CAS token.
