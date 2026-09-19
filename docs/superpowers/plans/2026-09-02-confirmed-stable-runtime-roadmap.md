# Confirmed Stable Runtime Implementation Roadmap

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the manually selected embedded stable runtime without mixing server compatibility, 0.2.16 bootstrap work, and 0.3.0 dual-runtime packaging into one unsafe change set.

**Architecture:** The work is split into three independently reviewable plans. The panel first accepts separate container/runtime identity and supplies device-scoped cleanup; a maintenance line from `632cc4b40872c559a75e5d7104b72bae17ac91c3` then establishes `runtime-v1` and publishes embeddable 0.2.16 payloads; current `main` finally consumes those exact payloads and exposes two runtime slots in 0.3.0.

**Tech Stack:** FastAPI, SQLAlchemy/Alembic, Rust 1.88, Tauri 2, Svelte 5, Kotlin/Gradle, GitHub Actions, Ed25519 release manifests.

**Spec:** `docs/superpowers/specs/2026-09-02-confirmed-stable-runtime-design.md`

## Global Constraints

- The stable runtime is the exact immutable version selected at build time, never “the previous release”.
- `0.2.16` starts from commit `632cc4b40872c559a75e5d7104b72bae17ac91c3`; Android hot-standby remains out of that maintenance line.
- `0.3.0` embeds `latest = 0.3.0` and `stable = 0.2.16`.
- One installed package, one application/package ID, one `install_secret`, one panel device, one server session, and at most one running runtime.
- The setting is manual, persists only for the installed container version, applies after a full application restart, and every container update resets it to latest.
- Switching immediately stops the tunnel. Graceful stop is bounded; process termination is the final local fallback.
- A broken runtime does not trigger automatic fallback, and no external emergency selector is added.
- Slot preferences are isolated and migrate only inside the slot. Operational tunnel state is isolated by exact runtime version.
- Updater and minimum-supported policy use `container_version`; tunnel, recovery, transport, and capability gates use `runtime_version` plus explicit contract versions.
- Developer ID and Apple notarization are not required. macOS keeps Tauri updater verification, signed runtime manifests, hashes, and reproducible ad-hoc signing when the toolchain requires it.
- Linux automated packaging/IPC/test-adapter coverage is required; missing physical Linux tunnel E2E is recorded explicitly.
- Do not edit bundled vendor source or dirty vendor submodules. Any separately authorized vendor change is represented only by a tracked parent-repository patch file.
- Do not touch Fantasy.
- Do not commit secrets, keys, `.env`, signing material, or production configuration.
- No push, panel deploy, release publication, production migration, agent update, or capability enablement occurs without a separate direct user command.
- Commits use Russian messages.

---

## Plan set and mandatory order

1. `docs/superpowers/plans/2026-09-02-confirmed-stable-panel-contract.md`
   - Adds the backward-compatible panel model, request metadata, runtime-aware gates, scoped background credentials, and idempotent runtime-switch reconciliation.
   - Produces a deployable panel revision while old applications continue to work unchanged.
2. `docs/superpowers/plans/2026-09-02-confirmed-stable-bootstrap-0.2.16.md`
   - Executes in an isolated maintenance worktree created from `632cc4b...` because the current main checkout contains unreleased 0.3.0 work.
   - Produces normal 0.2.16 installers and immutable embeddable runtime artifacts, but presents only one usable slot and hides the toggle.
3. `docs/superpowers/plans/2026-09-02-confirmed-stable-dual-runtime-0.3.0.md`
   - Ports reviewed infrastructure to current `main`, explicitly reconciles Android hot-standby/storage/updater conflicts, embeds the exact 0.2.16 artifacts, and enables manual switching.

These plans are sequential dependencies, not parallel work. Within a plan, a task may begin only after the preceding task’s tests and review gate are green.

## Cross-repository gates

### Gate A: panel source ready

- [ ] All panel unit, API, migration, PostgreSQL-operation, and compatibility tests in Plan 1 pass.
- [ ] A clean database migration rehearsal passes against an isolated disposable database; production preflight is not run against the working database.
- [ ] The guarded self-updater deployment remains a separately authorized action.

### Gate B: panel deployed and verified

- [ ] After an explicit deployment command, verify `/health`, deployed Git HEAD, clean checkout, `nelomai-panel`, nginx, and PostgreSQL read-only.
- [ ] Verify old-client login/bootstrap/update and new dual-version login/bootstrap on production without enabling Android hot-standby.
- [ ] Do not start the 0.2.16 release workflow until this gate is recorded.

### Gate C: 0.2.16 artifacts accepted

- [ ] All Plan 2 automated checks pass from the maintenance revision.
- [ ] Upgrade `0.2.15 -> 0.2.16` preserves device identity and auth on Android, macOS, and Windows.
- [ ] Tunnel regression checks pass on Android, macOS, and Windows; Linux automated tests pass and the missing physical tunnel E2E is recorded.
- [ ] Runtime manifests and payload archives for every supported platform/architecture are immutable release assets with recorded manifest SHA-256 values.
- [ ] Release execution and publication remain separately authorized actions.

### Gate D: 0.3.0 dual runtime accepted

- [ ] All Plan 3 automated checks pass on the current main lineage.
- [ ] The final packages byte-compare their embedded stable payloads with the accepted 0.2.16 manifests.
- [ ] Manual `latest -> stable -> latest`, active-tunnel switching, logout, update reset, tile/tray/autostart, and corrupted-stable scenarios pass on available physical platforms.
- [ ] Release execution and publication remain separately authorized actions.

## Integration invariants checked after every plan

```text
identity     = one install_secret -> one AppDevice
update gate  = container_version
tunnel gate  = runtime_version + explicit contracts
active code  = exactly one selected runtime
switch start = forbidden until runtime-switch reconciliation returns clean
logout       = stop/cleanup -> revoke shared session -> clear AuthStore
update       = shutdown barrier -> installer -> new container selects latest
```

## Final combined verification

- [ ] In `nelomai-panel`, run `python -m pytest -q`, `python scripts/migration_check.py`, and `git diff --check` against disposable/local test state only.
- [ ] In `nelomai-app`, run `npm test`, `python contracts/python/validate_fixtures.py`, `python scripts/release-workflow-check.py`, `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, Android JVM tests, and `git diff --check`.
- [ ] Confirm `git status --short` contains only the intended commits plus the two pre-existing dirty vendor submodules.
- [ ] Confirm no command in the execution record pushed, deployed, published a release, migrated production, updated agents, or enabled a capability without direct authorization.
