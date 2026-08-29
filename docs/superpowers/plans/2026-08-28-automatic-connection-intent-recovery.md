# Automatic Connection Intent Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Сделать одно пользовательское нажатие `Старт` устойчивым намерением подключения: временные ошибки повторяются автоматически, зависший dynamic AWG3 заменяется без ручного второго запуска, а Android сохраняет безопасное восстановление и cleanup после смерти UI/VPN-процесса.

**Architecture:** Панель первой публикует выключенный additive-контракт с durable operation journal, reconciliation, staged credentials и server-owned compensation. Затем desktop получает единый in-memory coordinator в Rust core, а Android `:vpn` — единственного persisted owner: Tauri передаёт ему нормализованный intent до любого panel HTTP и не запускает параллельный Rust scheduler. Intent и lease transaction являются частями одного атомарного Android recovery envelope; credential revision хранится отдельно. Capability включается только после серверной проверки; клиент никогда не превращает незавершённую feature-operation в legacy start.

**Tech Stack:** Python 3.11+, FastAPI, SQLAlchemy 2, Alembic, PostgreSQL/SQLite, Python unittest/pytest; Rust 1.88, Tokio, Tauri 2, serde; Kotlin 17, Android `VpnService`, Android Keystore, JUnit; Svelte 5, TypeScript, Vitest.

**Spec:** `docs/superpowers/specs/2026-08-28-automatic-connection-intent-recovery-design.md`

## Global Constraints

- Работу вести в отдельных worktree обоих репозиториев; панель начинать от актуального `origin/main` (на момент составления `68d1400`, migration head `20260828_0052`), приложение — от коммита со спецификацией и планом.
- Не менять и не очищать dirty `vendor/amneziawg-android` и `vendor/amneziawg-go`; патчи vendor не входят в эту задачу.
- Все server routes и поля additive; legacy-клиенты сохраняют прежнюю семантику и не получают `422`.
- `connection_intent_recovery_v1` остаётся `false`, пока schema, routes, worker, документация и production smoke не доступны одновременно.
- Exact replay/reconcile/cancel остаются доступны для уже созданной operation даже после capability downgrade.
- WireGuard-конфигурация, private key, credentials, install secret, адреса и полные error messages не попадают в UI, события и логи.
- Android intent привязан к `BOOT_COUNT`; mismatch отключает intent, но сохраняет незавершённый lease как `stale_cleanup`.
- На Android durable commit intent в `:vpn` подтверждается до первого panel HTTP; Rust/Tauri не является вторым retry-owner.
- Один operation owner за раз: server worker владеет `applying/compensating`, клиент владеет stop только для `applied` lease.
- Personal Tic/Tak не превращается в dynamic, pinned Stray сохраняет cooldown, Stray не получает Tic/Tak egress semantics.
- Kill switch enforcement реализуется отдельным утверждённым планом; здесь добавляются только согласованные `recovering/blocked_terminal` hooks и тесты интеграции state machine.
- Каждый task выполняется RED → GREEN → полный релевантный прогон → независимое ревью → русскоязычный commit.
- Не выполнять deploy, release, push, включение capability или production preflight без отдельной прямой команды.

---

## File map

### Панель: `/Users/altzxd/Documents/GitHub/nelomai-panel`

- `migrations/versions/20260828_0053_connection_intent_recovery.py` — новые journal/token/cleanup таблицы и индексы.
- `app/models.py` — operation journal, staged activation, cleanup job и logout tombstone models.
- `app/client_schemas.py` — additive request/response/capability contracts.
- `app/client_operation_journal.py` — signatures, row/device locks, state transitions и exact replay.
- `app/client_connection_recovery.py` — reconciliation, cancellation и recovery-worker для `applying/compensating`.
- `app/client_connections.py`, `app/client_pools.py` — measured start, stalled AWG3 stop и единая journal/lease/peer transaction boundary.
- `app/client_auth.py` — staged prepare/activate, cleanup-only auth и finalize/revoke ordering.
- `app/client_api.py` — новые background routes.
- `app/config.py`, `app/main.py` — capability defaults и lifecycle worker.
- `panel_compatibility.json`, `app/panel_self_update.py`, `app/panel_update_queue.py`, `scripts/panel_self_update_runner.py` — versioned compatibility floor и проверка target tree до checkout switch.
- `tests/test_client_operation_recovery.py`, `tests/test_client_operation_postgresql.py` — journal, cancellation, crash/retry и настоящий PostgreSQL worker race.
- `tests/test_client_connections.py`, `tests/test_client_pool_lifecycle.py`, `tests/test_client_auth.py`, `tests/test_app_migration.py`, `tests/test_panel_self_update.py` — контрактные и транзакционные регрессии.
- `docs/client_api.md` — authoritative server API.

### Приложение: `/Users/altzxd/Documents/GitHub/nelomai-app`

- `crates/contracts/src/lib.rs` — wire types и stable error/state enums.
- `crates/client-api/src/lib.rs` — normal/background endpoint methods.
- `crates/client-application/src/lib.rs`, `crates/client-application/tests/http_flow.rs` — application facade и HTTP contract tests.
- `contracts/schemas/connection-intent-capability.schema.json`, `contracts/schemas/connection-operation-reconcile.schema.json` и fixtures — общий wire contract и error-policy parity.
- `crates/client-core/src/connection_intent.rs` — pure state machine/backoff/classifier и desktop coordinator policy.
- `crates/client-core/src/lib.rs`, `crates/client-core/tests/runtime.rs` — desktop-only attempt ownership, compensation и lease replacement.
- `src-tauri/src/connection_intent.rs` — desktop task owner, wakeups и notification suppression.
- `src-tauri/src/lib.rs`, `src-tauri/src/commands.rs`, `src-tauri/src/connection_metrics.rs` — scheduler/command/state integration.
- `src/lib/native-client.ts`, `src/lib/app-model.ts`, `src/lib/app-model.test.ts`, `src/routes/+page.svelte` — `recovering/blocked_terminal` UI.
- `plugins/tunnel-android/android/src/main/java/AndroidRecoveryStore.kt`, `AndroidSecureEnvelopeBackend.kt` — один encrypted intent/lease envelope, boot identity и injectable storage seam.
- `plugins/tunnel-android/android/src/main/java/BackgroundCredentialStore.kt` — credential revision, pending token и logout tombstone.
- `plugins/tunnel-android/android/src/main/java/BackgroundConnectionClient.kt` — capabilities/candidates/reconcile/token/finalize API.
- `plugins/tunnel-android/android/src/main/java/NelomaiVpnService.kt` — authoritative Android coordinator.
- `plugins/tunnel-android/src/models.rs`, `plugins/tunnel-android/src/lib.rs`, `plugins/tunnel-android/android/src/main/java/QuickTunnelController.kt`, `TunnelServiceProtocol.kt`, `TunnelPlugin.kt` — typed pre-start IPC, generation и UI↔`:vpn` mutation protocol.
- Новые одноимённые Kotlin test files плюс существующие `BackgroundConnectionClientTest.kt`, `NelomaiVpnServiceTest.kt`, `QuickTunnelControllerTest.kt`.
- `docs/panel_contract.md` — клиентская копия rollout/capability contract.

---

## Phase A — Server compatibility surface

### Task 1: Durable operation, activation and logout schema

**Files:**
- Create: `migrations/versions/20260828_0053_connection_intent_recovery.py`
- Modify: `app/models.py`
- Create: `app/client_operation_journal.py`
- Modify: `tests/test_app_migration.py`
- Create: `tests/test_client_operation_recovery.py`

**Interfaces:**
- Produces: `AppClientOperation`, `AppBackgroundTokenActivation`, `AppClientCleanupJob`, `AppLogoutFinalization`.
- Produces: `ClientOperationState = pending|applying|compensating|applied|terminal|cancelled`.
- Produces: `reserve_operation()`, `lock_operation()`, `transition_operation()`, `replay_result()`.

- [ ] **Step 1: Write failing migration/model tests**

Assert unique `(device_id, operation_id)`, immutable signature hash, indexed due work, one staged activation per device, and a logout tombstone without time-based deletion:

```python
self.assertIn(
    ("device_id", "operation_id"),
    {
        tuple(column.name for column in constraint.columns)
        for constraint in AppClientOperation.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    },
)
self.assertEqual(
    str(AppClientOperation.__table__.c.state.server_default.arg).strip("'"),
    "pending",
)
self.assertFalse(AppLogoutFinalization.__table__.c.completed_at.nullable)
self.assertNotIn("expires_at", AppLogoutFinalization.__table__.c)
```

Import `UniqueConstraint` from SQLAlchemy in the test module.

- [ ] **Step 2: Confirm RED**

Run from the panel worktree:

```bash
.venv/bin/python -m unittest tests.test_app_migration tests.test_client_operation_recovery -v
```

Expected: missing migration, models and journal module.

- [ ] **Step 3: Add the minimal schema and journal API**

Use an explicit immutable signature and typed transition result:

```text
OperationSignature(device_id: str, kind: str, contract_version: int, request_fingerprint: str)
reserve_operation(db: Session, signature: OperationSignature, operation_id: str) -> AppClientOperation
transition_operation(db: Session, operation: AppClientOperation, expected: set[ClientOperationState], target: ClientOperationState, result: dict | None = None) -> bool
```

Store response/result JSON only after validating it contains no configuration or token fields. Use PostgreSQL row locks when available and preserve SQLite test compatibility.

- [ ] **Step 4: Verify migration round-trip and journal invariants**

```bash
.venv/bin/python scripts/migration_check.py
.venv/bin/python -m unittest tests.test_app_migration tests.test_client_operation_recovery -v
.venv/bin/python -m compileall -q app migrations/versions/20260828_0053_connection_intent_recovery.py
```

Expected: upgrade/downgrade succeeds; conflicting signature returns `operation_id_conflict`; terminal replay is immutable.

- [ ] **Step 5: Commit**

```bash
git add migrations/versions/20260828_0053_connection_intent_recovery.py app/models.py app/client_operation_journal.py tests/test_app_migration.py tests/test_client_operation_recovery.py
git commit -m "Добавить журнал операций восстановления"
```

### Task 2: Journal-aware start reconciliation and server compensation

**Files:**
- Create: `app/client_connection_recovery.py`
- Modify: `app/client_connections.py`
- Modify: `app/client_pools.py`
- Modify: `app/client_api.py`
- Modify: `app/client_schemas.py`
- Modify: `app/main.py`
- Modify: `tests/test_client_operation_recovery.py`
- Create: `tests/test_client_operation_postgresql.py`
- Modify: `tests/test_client_connections.py`
- Modify: `tests/test_client_pool_lifecycle.py`

**Interfaces:**
- Produces: `POST /api/client/v1/background/operations/reconcile`.
- Produces: `reconcile_client_operation(db, context, request) -> ClientOperationReconcileResponse`.
- Produces: `recover_due_client_operations(now) -> RecoveryBatchResult`.

- [ ] **Step 1: Add failing race/crash tests**

Cover `cancel_if_absent` tombstone, `pending→cancelled`, cancel during `applying`, crash after agent action, transient compensation failure, exact active replay, terminal lease replay and rollback of journal + reserved lease + peer as one unit:

```python
result = reconcile_client_operation(
    db,
    context,
    operation_id=operation_id,
    kind="start",
    request_fingerprint=fingerprint,
    cancel_if_absent=True,
)
self.assertEqual(result.state, "compensating")
self.assertEqual(result.lease_id, lease.id)
```

- [ ] **Step 2: Confirm RED**

```bash
.venv/bin/python -m unittest tests.test_client_operation_recovery tests.test_client_connections -v
```

- [ ] **Step 3: Linearize start and cancellation**

Before the first DB/agent side effect, CAS `pending→applying`. Persist `execution_step`, reserved lease/peer and action idempotency key before each external action. Split the existing pool helpers into transaction-scoped implementations that use `flush()` but never `commit()` and legacy wrappers that preserve the old committing behavior for unchanged callers. The journal-aware handler owns the single outer transaction; no helper in that path may commit independently. On `cancel_requested`, persist this shape atomically:

```python
CompensationClaim(
    lease_id=lease.id,
    stop_operation_id=deterministic_stop_operation_id(operation.id),
    retry_count=0,
    next_attempt_at=now,
)
```

`applied` returns its lease for client-owned stop; `applying/compensating` never asks the client to issue a competing stop.

- [ ] **Step 4: Add the recovery owner**

Wire a bounded startup/periodic worker in `app/main.py`. It claims due rows with `FOR UPDATE SKIP LOCKED`, repeats the same idempotency key, applies bounded backoff, and writes `terminal` only after authoritative terminal lease state. No worker exception may terminate the panel lifespan task.

Add an opt-in integration test using two independent sessions against a disposable PostgreSQL database from `TEST_DATABASE_URL`. Assert that only one worker claims an `applying/compensating` row, the other skips the locked row, and rollback cannot expose a partial journal/lease/peer state. The test may skip when the variable is absent, but Phase A cannot pass its release checkpoint without one recorded non-skipped run. Never point this test at production.

- [ ] **Step 5: Verify focused behavior**

```bash
.venv/bin/python -m unittest tests.test_client_operation_recovery tests.test_client_connections tests.test_client_pool_lifecycle -v
TEST_DATABASE_URL="$NELOMAI_TEST_POSTGRES_URL" .venv/bin/python -m unittest tests.test_client_operation_postgresql -v
.venv/bin/python -m compileall -q app
```

`NELOMAI_TEST_POSTGRES_URL` must be supplied by the local/CI test environment and must identify an isolated disposable database. Expected: simulated handler death is completed by the worker; the PostgreSQL test is not skipped; two workers cannot claim one action; configuration is never returned after cancel linearization; a forced exception rolls back journal, lease and peer together.

- [ ] **Step 6: Commit**

```bash
git add app/client_connection_recovery.py app/client_connections.py app/client_pools.py app/client_api.py app/client_schemas.py app/main.py tests/test_client_operation_recovery.py tests/test_client_operation_postgresql.py tests/test_client_connections.py tests/test_client_pool_lifecycle.py
git commit -m "Добавить восстановление незавершённых подключений"
```

### Task 3: Stalled AWG3 stop, measured background selection and capability

**Files:**
- Modify: `app/client_schemas.py`
- Modify: `app/client_connections.py`
- Modify: `app/client_api.py`
- Modify: `app/config.py`
- Modify: `tests/test_client_connections.py`
- Modify: `tests/test_client_auth.py`

**Interfaces:**
- Extends: `ClientConnectionStopRequest.failure_code` with `tunnel_data_plane_stalled`.
- Extends: `ClientConnectionStartRequest.require_measured_selection: bool = False`.
- Produces: `GET /background/capabilities`, `GET /background/server-candidates`.
- Extends: normal-auth bootstrap with the initial capability revision/expiry snapshot passed to Android provision.
- Produces stable codes: `connection_stall_verification_unavailable`, `connection_stall_recycle_rate_limited`, `connection_stall_not_recyclable`.

- [ ] **Step 1: Write failing API/eligibility tests**

Test dynamic unpinned AWG3 acceptance, personal/pinned/non-AWG3 rejection, never-connected rejection, 3 operations/15 minutes, replay without a second budget charge, bounded `Retry-After`, and measured-selection rejection of empty/stale probes.

```python
payload = ClientConnectionStopRequest(
    operation_id=str(uuid4()),
    lease_id=lease.id,
    failure_code="tunnel_data_plane_stalled",
)
self.assertEqual(stop_client_connection(self.db, context, **payload.model_dump()).lease.status, AppConnectionLeaseStatus.FAILED)
```

- [ ] **Step 2: Confirm RED**

```bash
.venv/bin/python -m unittest tests.test_client_connections tests.test_client_auth -v
```

- [ ] **Step 3: Implement server validation and additive routes**

Reuse existing candidate selection and agent runtime telemetry. Background start sets `allow_unmeasured_selection = not payload.require_measured_selection`; legacy omission remains `False` and keeps current fallback. Return a capability response with revision/expiry and default the feature flag to `false`.

- [ ] **Step 4: Verify compatibility**

```bash
.venv/bin/python -m unittest tests.test_client_connections tests.test_client_auth -v
```

Expected: old payload fixtures still validate; new feature payloads are rejected or ignored safely while capability is false.

- [ ] **Step 5: Commit**

```bash
git add app/client_schemas.py app/client_connections.py app/client_api.py app/config.py tests/test_client_connections.py tests/test_client_auth.py
git commit -m "Добавить серверный контракт восстановления соединения"
```

### Task 4: Two-phase background credentials and cleanup-before-revoke

**Files:**
- Modify: `app/client_auth.py`
- Modify: `app/client_api.py`
- Modify: `app/client_schemas.py`
- Modify: `app/models.py`
- Modify: `tests/test_client_auth.py`
- Modify: `tests/test_client_operation_recovery.py`

**Interfaces:**
- Produces: `POST /background/token/prepare`, `POST /background/token/activate`, `POST /background/auth/logout-finalize`.
- Produces: `activation_not_applied`, `device_revoked_cleanup_accepted`.
- Changes: logout/logout-all/device revoke accept durable cleanup before token revoke.

- [ ] **Step 1: Write failing credential lifecycle tests**

Include lost prepare response, death before pending save, activation replay after staged TTL, signature conflict, previous overlap, logout while activation is pending, lost finalize response after more than 24 hours, and remote revoke cleanup barrier.

```python
replayed = activate_background_token(
    db,
    staged_secret,
    install_secret,
    activation_operation_id,
    now=staged_expiry + timedelta(days=1),
)
self.assertEqual(replayed.token_generation, applied.token_generation)
```

- [ ] **Step 2: Confirm RED**

```bash
.venv/bin/python -m unittest tests.test_client_auth tests.test_client_operation_recovery -v
```

- [ ] **Step 3: Implement prepare/activate and special replay auth**

For activate, hash request secrets and look up the exact immutable activation signature before staged-expiry validation. Commit active/previous rotation and activation result in one transaction. Never log raw or partial secrets.

- [ ] **Step 4: Implement finalize/revoke ordering**

`logout-finalize` first persists cancellation/cleanup jobs, then revokes tokens and stores one exact tombstone per device/install generation. Do not TTL-delete the tombstone; delete it only after successful provision of the next credential generation or device deletion. A generic `401` is not finalize success.

- [ ] **Step 5: Verify auth and concurrency behavior**

```bash
.venv/bin/python -m unittest tests.test_client_auth tests.test_client_operation_recovery -v
.venv/bin/python -m compileall -q app
```

- [ ] **Step 6: Commit**

```bash
git add app/client_auth.py app/client_api.py app/client_schemas.py app/models.py tests/test_client_auth.py tests/test_client_operation_recovery.py
git commit -m "Добавить безопасную ротацию фоновых токенов"
```

### Task 5: Server docs, compatibility floor and disabled rollout artifact

**Files:**
- Create: `panel_compatibility.json`
- Modify: `app/panel_self_update.py`
- Modify: `app/panel_update_queue.py`
- Modify: `scripts/panel_self_update_runner.py`
- Modify: `tests/test_panel_self_update.py`
- Modify: `docs/client_api.md`
- Create: `docs/connection_intent_recovery_runbook.md`

**Interfaces:**
- Produces: tracked target manifest `PanelCompatibilityManifest(format_version, floor, alembic_floor, permanent_contracts)`.
- Extends: `validate_update_target(repo_dir, target_commit, runner, *, fetch, minimum_floor)` with `git show <target>:panel_compatibility.json` validation before maintenance mode or checkout switch.
- Produces: documented rollout order and read-only production smoke commands.

- [ ] **Step 1: Write failing updater-floor tests**

Assert that the first server artifact declares floor `1`, migration `0053` and permanent contract `connection_intent_recovery_v1`; a later target with a missing/malformed manifest, lower floor, missing migration file or missing reconcile/cancel contract declaration is rejected before maintenance mode and checkout switch. Also assert that the updater reads the target manifest through `git show`, never from the current working tree.

- [ ] **Step 2: Confirm RED**

```bash
.venv/bin/python -m unittest tests.test_panel_self_update -v
```

- [ ] **Step 3: Add the tracked manifest and pre-switch guard**

Create a non-secret manifest with exact schema:

```json
{
  "format_version": 1,
  "floor": 1,
  "alembic_floor": "20260828_0053",
  "permanent_contracts": [
    "connection_intent_recovery_v1",
    "background_operation_reconcile_v1",
    "background_operation_cancel_v1"
  ]
}
```

Activate floor `1` unconditionally with this first server deployment, before the capability can become `true`; this is intentionally stricter than remembering the first enable event and therefore needs no mutable enable-state. Both the web queue and system updater revalidate the exact target commit. Parse `git show <target>:panel_compatibility.json`, reject unknown manifest versions, require `floor >= current floor`, verify the declared Alembic migration exists in the target tree with `git cat-file -e`, and require all permanent contracts from the current manifest in the target manifest. Missing current manifest means bootstrap floor `0` only for the first deployment; once floor `1` is installed, later fast-forward targets cannot remove it.

- [ ] **Step 4: Add exact API documentation**

Document schemas, auth scopes, stable codes, replay retention and capability expiry. The runbook order is: deploy with capability false → migrate → validate worker/routes → enable pilot capability → release client. Do not include production secrets or a production-DB preflight command.

- [ ] **Step 5: Run the complete panel gate**

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m compileall -q app migrations scripts
.venv/bin/ruff check app tests --select F821
git diff --check
```

Expected: all tests pass, feature remains disabled by default, legacy API fixtures are unchanged.

- [ ] **Step 6: Review and commit the server slice**

Perform an independent problems-first review of Tasks 1–5 before commit:

```bash
git add panel_compatibility.json app migrations scripts/panel_self_update_runner.py tests docs/client_api.md docs/connection_intent_recovery_runbook.md
git commit -m "Закрепить выпуск серверного восстановления"
```

**Checkpoint:** Stop here. Panel may be pushed/deployed only by direct command and only through guarded self-updater. Do not begin capability enable until production schema/routes/worker are verified.

---

## Phase B — Shared client and desktop coordinator

### Task 6: Rust wire contract and background API methods

**Files:**
- Modify: `crates/contracts/src/lib.rs`
- Modify: `crates/contracts/tests/fixtures.rs`
- Modify: `contracts/schemas/bootstrap.schema.json`, `contracts/schemas/connection-start.schema.json`
- Modify: `contracts/fixtures/valid/bootstrap.json`, `contracts/fixtures/valid/connection-start.json`
- Create: `contracts/schemas/connection-intent-capability.schema.json`
- Create: `contracts/schemas/connection-operation-reconcile.schema.json`
- Create: `contracts/fixtures/valid/connection-intent-capability.json`
- Create: `contracts/fixtures/valid/connection-operation-reconcile.json`
- Create: `contracts/fixtures/valid/connection-operation-reconcile-conflict.json`
- Create: `contracts/fixtures/valid/connection-intent-error-policy.json`
- Modify: `crates/client-api/src/lib.rs`
- Modify: `crates/client-application/src/lib.rs`
- Modify: `crates/client-application/tests/http_flow.rs`
- Modify: `docs/panel_contract.md`

**Interfaces:**
- Produces: `ConnectionIntentCapability`, `OperationReconcileRequest/Response`, `OperationState`.
- Extends: `ConnectionStartRequest.require_measured_selection` and stalled `failure_code`.
- Produces typed methods `background_capabilities`, `background_candidates`, `reconcile_background_operation`.

- [ ] **Step 1: Add failing serde and HTTP fixture tests**

```rust
assert_eq!(
    serde_json::from_str::<OperationState>(r#""compensating""#).unwrap(),
    OperationState::Compensating,
);
let start: ConnectionStartRequest =
    serde_json::from_str(&fixture("valid/connection-start.json")).unwrap();
assert!(!start.require_measured_selection);
```

Validate the capability and reconcile fixtures against their dedicated schemas, including terminal/conflict states. Treat `connection-intent-error-policy.json` as the parity fixture listing every retryable, bounded-retry and terminal code used by both Rust and Kotlin tests. Verify no Authorization header is sent to candidate probe URLs.

- [ ] **Step 2: Confirm RED**

```bash
cargo test -p nelomai-contracts --test fixtures connection_intent -- --nocapture
cargo test -p nelomai-client-application --test http_flow connection_intent -- --nocapture
```

- [ ] **Step 3: Implement tolerant additive decoding**

Use `#[serde(default)]` for request additions and preserve unknown server fields. Model capability expiry explicitly; `404`, `unsupported`, absent and expired are false only for new logical operations, not for replay of a stored contract version.

- [ ] **Step 4: Verify crate regressions**

```bash
cargo test -p nelomai-contracts
cargo test -p nelomai-client-api
cargo test -p nelomai-client-application
```

- [ ] **Step 5: Commit**

```bash
git add contracts crates/contracts crates/client-api crates/client-application docs/panel_contract.md
git commit -m "Добавить клиентский контракт восстановления"
```

### Task 7: Shared recovery policy and desktop ClientCore coordinator

**Files:**
- Create: `crates/client-core/src/connection_intent.rs`
- Modify: `crates/client-core/src/lib.rs`
- Modify: `crates/client-core/tests/runtime.rs`

**Interfaces:**
- Produces: pure `IntentGeneration`, `RecoveryDecision`, `RetrySchedule` and stable-code classifier validated by the shared error-policy fixture.
- Produces on non-Android targets: `ConnectionIntentCoordinator` and the desktop one-attempt adapter.
- Produces: local `ConnectionIntentStatus = None|Recovering|BlockedTerminal`.
- Produces: `start_or_resume(options, now) -> StartDisposition::Connected|Recovering`.
- Produces: `cancel_intent()`, `wake_for_network_change()`, `handle_stall(trigger)`.

- [ ] **Step 1: Write failing pure state-machine tests**

Cover backoff `0,2,5,15,30,60,300`, wakeup coalescing, one active attempt,
generation cancellation during API/local start/handshake, every retryable,
bounded-retry and user-action code from
`contracts/fixtures/valid/connection-intent-error-policy.json`, one
noninteractive recovery for `service_unavailable`, stable
`android_service_dispatch_unavailable`, terminal `operation_id_conflict`, single
profile-mismatch retry, bounded `Retry-After`, personal/pinned preservation and
dynamic replacement after stalled AWG3.

```rust
assert_eq!(RetrySchedule::default().delays(), [0, 2, 5, 15, 30, 60, 300]);
assert!(coordinator.cancel_intent(old_generation));
assert_eq!(coordinator.accept_result(old_generation), RecoveryDecision::DiscardAndCompensate);
```

- [ ] **Step 2: Confirm RED**

```bash
cargo test -p nelomai-client-core connection_intent -- --nocapture
```

- [ ] **Step 3: Extract desktop one-attempt atomicity without duplicating core start**

On non-Android targets, keep `ClientCore` owner of lease issuance, local tunnel start, handshake and compensation. The desktop coordinator calls a typed one-attempt method and classifies only stable codes. Keep the policy/state types buildable on Android, but gate the Rust attempt adapter and scheduler with `#[cfg(not(target_os = "android"))]`; they must never issue Android panel start or retry. Preserve the full desktop replacement order: rebind → one local restart → local stop → stalled stop/reconcile → cache clear for dynamic only → new measured start.

- [ ] **Step 4: Fix the metrics-context lifetime regression**

Move the active recovery episode above `connection_metrics_context()`. Transition through `Stopping` without dropping normalized options, lease identity or the `armed`-session marker. Do not make the metrics scheduler a second retry owner.

- [ ] **Step 5: Verify core behavior**

```bash
cargo test -p nelomai-client-core connection_intent -- --nocapture
cargo test -p nelomai-client-core --test runtime
```

Expected: temporary failures yield `Recovering`; explicit stop invalidates every late callback; dynamic replacement creates one new operation only after terminal cleanup.

- [ ] **Step 6: Commit**

```bash
git add crates/client-core/src/connection_intent.rs crates/client-core/src/lib.rs crates/client-core/tests/runtime.rs
git commit -m "Добавить координатор намерения подключения"
```

### Task 8: Tauri lifecycle, desktop scheduler and UI states

**Files:**
- Create: `src-tauri/src/connection_intent.rs`
- Modify: `src-tauri/src/lib.rs`
- Modify: `src-tauri/src/commands.rs`
- Modify: `src-tauri/src/connection_metrics.rs`
- Modify: `src/lib/native-client.ts`
- Modify: `src/lib/app-model.ts`
- Modify: `src/lib/app-model.test.ts`
- Modify: `src/routes/+page.svelte`

**Interfaces:**
- Extends: `AppStateResponse.connection_intent_status` and `next_retry_at_unix`.
- Changes: `app_start` returns connected or recovering; `app_stop`, tray stop, logout and update shutdown cancel intent first.
- Produces diagnostics events listed in the spec, once per recovery episode.

- [ ] **Step 1: Add failing command/UI tests**

```rust
assert_eq!(response.connection_intent_status, ConnectionIntentStatus::Recovering);
assert_eq!(response.phase, Phase::Connecting);
```

```ts
expect(primaryAction({ phase: "connecting", connectionIntentStatus: "recovering" })).toBe("stop");
expect(recoveryCopy("recovering")).not.toContain("Старт ещё раз");
```

- [ ] **Step 2: Confirm RED**

```bash
cargo test -p nelomai-app connection_intent -- --nocapture
npm run test:unit -- src/lib/app-model.test.ts
```

- [ ] **Step 3: Replace scheduler ownership**

Create one Tokio task owned by app state on non-Android targets only. Compile its construction and wake wiring behind `#[cfg(not(target_os = "android"))]`. Metrics emits typed stall triggers only. Network change and foreground wake call `wake()` with coalescing. Emit at most one slow-recovery notification/report per episode and keep the five-minute passive retry. Task 11 supplies and verifies the Android command path; this task must not introduce an Android scheduler placeholder or second owner.

- [ ] **Step 4: Implement UI and cancellation wiring**

Show `Восстанавливаем подключение`, keep `Стоп` enabled, preserve terminal action text, and expose `Повторить/Стоп` for `blocked_terminal`. The tray displays disconnect for connected, connecting/recovering and blocked-terminal states.

- [ ] **Step 5: Verify desktop/frontend regressions**

```bash
cargo test -p nelomai-app
npm test
```

- [ ] **Step 6: Commit**

```bash
git add src-tauri/src/connection_intent.rs src-tauri/src/lib.rs src-tauri/src/commands.rs src-tauri/src/connection_metrics.rs src/lib src/routes/+page.svelte
git commit -m "Подключить автоматическое восстановление в приложение"
```

**Checkpoint:** Review Tasks 6–8 problems-first. Do not start Android persistence until desktop/core ownership and cancellation tests are stable.

---

## Phase C — Android durable owner

### Task 9: Atomic Android recovery envelope and testable secure backend

**Files:**
- Create: `plugins/tunnel-android/android/src/main/java/AndroidRecoveryStore.kt`
- Create: `plugins/tunnel-android/android/src/main/java/AndroidSecureEnvelopeBackend.kt`
- Create: `plugins/tunnel-android/android/src/test/java/AndroidRecoveryStoreTest.kt`
- Create: `plugins/tunnel-android/android/src/androidTest/java/AndroidSecureEnvelopeBackendInstrumentedTest.kt`
- Modify: `plugins/tunnel-android/android/build.gradle.kts`
- Modify: `plugins/tunnel-android/android/src/main/java/QuickTunnelController.kt`
- Modify: `plugins/tunnel-android/android/src/test/java/QuickTunnelControllerTest.kt`

**Interfaces:**
- Produces: `AndroidConnectionIntent(generation, bootCount, desiredActive, template, retry)`.
- Produces: `LeasePhase = START_PENDING|LEASE_ACQUIRED|ACTIVE_CHECKPOINT|CLEANUP_PENDING|STALE_CLEANUP`.
- Produces: one encrypted `AndroidRecoveryEnvelope(formatVersion, intent, leaseTransaction)` and logical intent/lease projections over that record.
- Produces injectable `EncryptedRecordBackend` and `BootIdentityProvider`; production implementations use one `SharedPreferences` ciphertext, Android Keystore AES-GCM and `Settings.Global.BOOT_COUNT`.
- Produces CAS methods `beginStart`, `recordLease`, `activateCheckpoint`, `requireCleanup(leaseId, stopOperationId)`, `completeCleanup`.

- [ ] **Step 1: Add failing serialization/boot/race tests**

Use fake `EncryptedRecordBackend` and `BootIdentityProvider` in local JVM tests. Test corrupt store fail-closed, unavailable `BOOT_COUNT`, mismatch before tile/UI/service order, process death in every phase, full replay envelope in `active_checkpoint`, generation overflow handling, durable `stopOperationId`, failed synchronous commit and no credential/configuration fields in plaintext JSON. Inject a write failure at each mutation boundary and assert there is never a state where intent is inactive while the same record still exposes a non-stale boot-mismatched lease, or vice versa.

- [ ] **Step 2: Confirm RED**

```bash
src-tauri/gen/android/gradlew -p plugins/tunnel-android/android testDebugUnitTest --tests '*AndroidRecoveryStoreTest'
```

- [ ] **Step 3: Implement one Keystore-backed recovery envelope**

Serialize intent and lease transaction into one versioned plaintext envelope, encrypt it, and write exactly one ciphertext preference record. Every mutation uses synchronous `commit()` under one process-local gate and expected generation. On boot mismatch, one commit sets `desiredActive=false` and converts any nonterminal lease to `STALE_CLEANUP`; never delete it. Creating cleanup persists lease ID and a newly generated stop operation ID in that same commit. The backend returns failure rather than publishing an in-memory transition when Keystore, boot identity or preferences commit is unavailable.

Configure the library instrumentation runner and reuse the AndroidX test line already present in the generated app:

```kotlin
defaultConfig {
    testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
}
androidTestImplementation("androidx.test:runner:1.5.2")
androidTestImplementation("androidx.test.ext:junit:1.1.4")
```

- [ ] **Step 4: Make QuickTunnelController a view of the recovery store**

Keep the existing broadcast revision API, but source `desiredActive` and generation from the intent projection of `AndroidRecoveryStore`. A failed commit rejects `On/Старт` before any panel request.

- [ ] **Step 5: Verify pure state behavior and the real Android backend**

```bash
src-tauri/gen/android/gradlew -p plugins/tunnel-android/android testDebugUnitTest --tests '*AndroidRecoveryStoreTest' --tests '*QuickTunnelControllerTest'
src-tauri/gen/android/gradlew -p plugins/tunnel-android/android connectedDebugAndroidTest
```

Expected: JVM tests exercise every state/crash branch through fakes; the emulator/device test proves AndroidKeyStore encryption, `BOOT_COUNT` read and atomic SharedPreferences persistence. A connected Android target is required for the second command and its successful result is part of the Phase C checkpoint.

- [ ] **Step 6: Commit**

```bash
git add plugins/tunnel-android/android/build.gradle.kts plugins/tunnel-android/android/src/main/java/AndroidRecoveryStore.kt plugins/tunnel-android/android/src/main/java/AndroidSecureEnvelopeBackend.kt plugins/tunnel-android/android/src/main/java/QuickTunnelController.kt plugins/tunnel-android/android/src/test plugins/tunnel-android/android/src/androidTest
git commit -m "Сохранить Android-намерение подключения"
```

### Task 10: Android credential mutation protocol

**Files:**
- Modify: `plugins/tunnel-android/android/src/main/java/BackgroundCredentialStore.kt`
- Modify: `plugins/tunnel-android/android/src/main/java/BackgroundConnectionClient.kt`
- Modify: `plugins/tunnel-android/android/src/main/java/TunnelServiceProtocol.kt`
- Modify: `plugins/tunnel-android/android/src/main/java/TunnelPlugin.kt`
- Modify: `plugins/tunnel-android/android/src/main/java/NelomaiVpnService.kt`
- Modify: `plugins/tunnel-android/src/models.rs`
- Modify: `plugins/tunnel-android/src/lib.rs`
- Modify: `plugins/tunnel-android/android/src/test/java/BackgroundConnectionClientTest.kt`
- Create: `plugins/tunnel-android/android/src/test/java/BackgroundCredentialStoreTest.kt`
- Create: `plugins/tunnel-android/android/src/androidTest/java/BackgroundCredentialStoreInstrumentedTest.kt`

**Interfaces:**
- Consumes: `EncryptedRecordBackend` from Task 9 with a credential-specific record name and Keystore alias.
- Produces: `BackgroundCredentialEnvelope(revision, active, previous, pending, capability, logoutState)`.
- Produces: `reserveMutation`, `savePendingToken`, `promotePending`, `discardNotApplied`, `beginLogout`, `finalizeLogout`.
- Produces typed API methods for capabilities, candidates, reconcile, prepare, activate and finalize.

- [ ] **Step 1: Add failing mutation/expiry tests**

Inject the secure-record backend rather than calling AndroidKeyStore or a real `Context` from JVM tests. Cover concurrent UI provision versus service rotation, stale revision response, lost activate response, local staged expiry followed by exact replay, `activation_not_applied` discard, capability expiry/downgrade, failed synchronous persistence and logout preventing late promotion.

- [ ] **Step 2: Confirm RED**

```bash
src-tauri/gen/android/gradlew -p plugins/tunnel-android/android testDebugUnitTest --tests '*BackgroundCredentialStoreTest' --tests '*BackgroundConnectionClientTest'
```

- [ ] **Step 3: Upgrade the encrypted credential envelope**

Refactor `BackgroundCredentialStore` to use the same `EncryptedRecordBackend` seam with its own preference record and Keystore alias; keep credential and recovery envelopes logically and physically separate. Migrate format 2 without deleting a valid active token. Передавать в `:vpn` уже
существующий `StoredAuth.install_secret` через расширенный configure-background
IPC и сохранять его рядом с credential; не генерировать второй install secret.
Serialize every mutation through one gate and require expected
`credential_revision` for configure/prepare/activate/clear. Zero temporary token
bytes where the existing API exposes a mutable buffer.

- [ ] **Step 4: Implement journal-aware activation and capability rules**

Expired local staged TTL triggers exact activate replay first. Discard only on `activation_not_applied`. Capability false blocks only new prepare/new logical recovery operations; stored operation reconcile and activation replay keep their original contract version.

- [ ] **Step 5: Verify credential regressions**

```bash
src-tauri/gen/android/gradlew -p plugins/tunnel-android/android testDebugUnitTest --tests '*Background*'
src-tauri/gen/android/gradlew -p plugins/tunnel-android/android connectedDebugAndroidTest
cargo test -p tauri-plugin-tunnel-android
```

Expected: local JVM tests use deterministic fakes; the Android test proves format migration and encrypted persistence through the real Keystore backend.

- [ ] **Step 6: Commit**

```bash
git add plugins/tunnel-android/src plugins/tunnel-android/android/src/main/java/BackgroundCredentialStore.kt plugins/tunnel-android/android/src/main/java/BackgroundConnectionClient.kt plugins/tunnel-android/android/src/main/java/TunnelServiceProtocol.kt plugins/tunnel-android/android/src/main/java/TunnelPlugin.kt plugins/tunnel-android/android/src/main/java/NelomaiVpnService.kt plugins/tunnel-android/android/src/test plugins/tunnel-android/android/src/androidTest
git commit -m "Добавить безопасные фоновые credentials Android"
```

### Task 11: Android service coordinator, reconciliation and logout

**Files:**
- Modify: `plugins/tunnel-android/src/models.rs`
- Modify: `plugins/tunnel-android/src/lib.rs`
- Modify: `plugins/tunnel-android/android/src/main/java/NelomaiVpnService.kt`
- Modify: `plugins/tunnel-android/android/src/main/java/BackgroundConnectionClient.kt`
- Modify: `plugins/tunnel-android/android/src/main/java/TunnelPlugin.kt`
- Modify: `plugins/tunnel-android/android/src/main/java/TunnelServiceProtocol.kt`
- Create: `plugins/tunnel-android/android/src/main/java/ConnectionIntentErrorPolicy.kt`
- Modify: `plugins/tunnel-android/android/src/test/java/NelomaiVpnServiceTest.kt`
- Modify: `plugins/tunnel-android/android/src/test/java/BackgroundConnectionClientTest.kt`
- Create: `plugins/tunnel-android/android/src/test/java/ConnectionIntentErrorPolicyTest.kt`
- Modify: `src-tauri/src/commands.rs`
- Modify: `src-tauri/src/lib.rs`

**Interfaces:**
- Consumes: `AndroidRecoveryStore`, `BackgroundCredentialEnvelope` and the Task 6 wire/error-policy fixtures.
- Changes: `NelomaiVpnService` becomes sole Android retry/restore owner.
- Produces: one serialized operation gate for UI start, Quick Settings, restore and recovery.
- Produces typed Rust/Kotlin IPC `beginConnectionIntent(template)`, `cancelConnectionIntent(generation)` and `connectionIntentStatus()`; successful begin acknowledges durable `:vpn` commit, not panel connection success.
- Changes: `BackgroundConnectionClient.stop(credential, leaseId, operationId)` never creates its own operation ID.
- Produces: durable logout state completed by exact finalize replay.

- [ ] **Step 1: Add failing end-to-end service tests**

Test initial retry without prior successful connection, process death with unknown start, death after lease response, Quick Settings `Off` during network request, boot mismatch cleanup, measured dynamic probes, one active attempt, transient service dispatch, logout offline and lost finalize response after 24 hours. Add fault injection around cleanup: after the first durable `CLEANUP_PENDING`, restart the service and fail multiple stop transports; every request must carry the original stored stop operation ID. Add a Tauri/plugin integration test proving Android UI `app_start` causes zero Rust-side panel-start calls and returns only after the service acknowledges durable `START_PENDING`.

```kotlin
assertEquals(
    LeasePhase.START_PENDING,
    recoveryStore.load()!!.leaseTransaction!!.phase,
)
service.handleQuickOff()
assertFalse(recoveryStore.load()!!.intent.desiredActive)
assertEquals(true, reconcileRequest.cancelIfAbsent)
```

- [ ] **Step 2: Confirm RED**

```bash
src-tauri/gen/android/gradlew -p plugins/tunnel-android/android testDebugUnitTest --tests '*NelomaiVpnServiceTest' --tests '*BackgroundConnectionClientTest'
```

- [ ] **Step 3: Implement start/reconcile/cleanup ownership**

On Android, `app_start` normalizes the selected template but does not call `NativeApplication.start` or any Rust panel-start method. It sends `beginConnectionIntent` through the Rust plugin to `:vpn`; the service atomically persists `START_PENDING` and only then acknowledges the command and starts background HTTP. `app_stop`, tray stop and logout call the typed cancel IPC first. The desktop path remains unchanged and owns its Rust one-attempt coordinator.

Persist `LEASE_ACQUIRED` before local start. After handshake commit `ACTIVE_CHECKPOINT`. Unknown response reconciles first; `not_found` replays the original request/operation ID, `applied` exact-replays configuration, `applying/compensating` polls with backoff, and terminal/cancelled closes the envelope. Stale generation never installs configuration. When cleanup becomes necessary, atomically store lease ID and stop operation ID before leaving the callback; every retry and restore calls `stop(credential, leaseId, storedStopOperationId)` until authoritative success.

- [ ] **Step 4: Implement the Android error policy and measured background candidates**

Implement a Kotlin classifier whose complete parameterized test table is loaded from the same `connection-intent-error-policy.json` used by Rust. Unknown codes and `operation_id_conflict` are terminal; `service_unavailable` has one noninteractive recovery; `android_service_dispatch_unavailable` remains retryable with reconciliation/backoff; profile mismatch and `Retry-After` follow their explicit bounds. No classifier branch may silently mint a replacement operation ID except for codes where the specification explicitly begins a new logical operation.

Probe at most four candidate HTTPS URLs concurrently, with three-second timeout and no auth header. Cache no longer than five minutes or earliest candidate expiry; invalidate on network change. Personal Tic skips candidates.

- [ ] **Step 5: Implement cleanup-before-revoke logout**

On logout atomically set `desiredActive=false`, increment generation and move active token to cleanup-only. Reconcile/cancel and stop before finalize; if immediate finalize is requested, accept the server cleanup-job barrier. Only exact success or `device_revoked_cleanup_accepted` clears the secret; generic `401` leaves `logout_pending`.

- [ ] **Step 6: Verify service and Tauri integration**

```bash
src-tauri/gen/android/gradlew -p plugins/tunnel-android/android testDebugUnitTest
cargo test -p tauri-plugin-tunnel-android
cargo test -p nelomai-app connection_intent -- --nocapture
```

Expected: Android `app_start` has exactly one `:vpn` owner, no Rust/Tauri retry task and no panel request before durable intent acknowledgement; error-policy fixture passes identically in Rust and Kotlin; cleanup reuses one stop operation ID across service restarts.

- [ ] **Step 7: Commit**

```bash
git add plugins/tunnel-android src-tauri/src/commands.rs src-tauri/src/lib.rs
git commit -m "Завершить фоновое восстановление Android"
```

---

## Phase D — Diagnostics, verification and controlled rollout

### Task 12: Episode diagnostics and complete release gates

**Files:**
- Modify: `src-tauri/src/diagnostics.rs`
- Modify: `src-tauri/src/automatic_diagnostics.rs`
- Modify: `plugins/tunnel-android/android/src/main/java/AutomaticDiagnostics.kt`
- Modify: `docs/panel_contract.md`
- Modify: `docs/superpowers/specs/2026-08-23-scoped-kill-switch-design.md`
- Modify only if required by build gates: `.github/workflows/checks.yml`, `.github/workflows/release.yml`

**Interfaces:**
- Produces the safe `connection.intent.*` event set.
- Produces one slow-recovery notification/report per episode.
- Documents `blocked_terminal` handoff to the separate kill-switch implementation.

- [ ] **Step 1: Add failing diagnostic suppression tests**

Assert one report at first 300-second backoff or terminal failure, one notification per episode, reset after successful handshake/new explicit start, and no secrets/configuration/full messages in payloads.

- [ ] **Step 2: Confirm RED**

```bash
cargo test -p nelomai-app connection_intent_diagnostics -- --nocapture
src-tauri/gen/android/gradlew -p plugins/tunnel-android/android testDebugUnitTest --tests '*AutomaticDiagnosticsTest'
```

- [ ] **Step 3: Implement diagnostics and update cross-spec state names**

Use stable reason classes only. Update the scoped kill-switch document so `recovering` preserves `blocked`, `blocked_terminal` stops automatic retries, and confirmed user stop is the only transition to `off` for a previously armed session. Do not implement firewall enforcement in this task.

- [ ] **Step 4: Run full application verification**

```bash
npm test
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
src-tauri/gen/android/gradlew -p plugins/tunnel-android/android testDebugUnitTest
src-tauri/gen/android/gradlew -p plugins/tunnel-android/android connectedDebugAndroidTest
git diff --check
```

The connected Android gate must run on an emulator or test device and may not be replaced by a local JVM result.

- [ ] **Step 5: Review and commit the application slice**

Run an independent problems-first review of Tasks 6–12, then:

```bash
git add crates src-tauri src plugins docs .github/workflows
git commit -m "Завершить автоматическое восстановление подключения"
```

- [ ] **Step 6: Prepare rollout evidence without mutating production**

Record exact panel/app commits, migration head, test totals, capability default, supported contract revision and rollback floor in the runbook. Verify the planned production sequence is:

```text
panel push -> guarded self-update -> read-only health/schema/routes/worker checks
-> capability pilot enable -> pilot observation -> app push/release
```

Do not execute any item in this sequence without a direct user command. Never run production preflight against the working database.

---

## Completion criteria

- A retryable initial or recovery failure no longer asks the user to press `Старт` again.
- Explicit Stop/Quick Settings Off invalidates generation before waiting for an occupied gate.
- Android persists `START_PENDING` before panel HTTP, has no Rust/Tauri retry-owner and reuses one durable stop operation ID through process death.
- Lost start/activate/finalize responses are reconciled without a duplicate lease or lost credential.
- Handler/process death cannot leave a server operation permanently in `applying/compensating`.
- Journal, lease and peer allocation roll back together; the two-worker claim is verified against disposable PostgreSQL rather than inferred from SQLite.
- Dynamic AWG3 stalled replacement respects verification, rate limit and authoritative cleanup.
- Personal/pinned semantics, split tunnel, updater and existing diagnostics remain unchanged.
- Capability can be disabled for new work without orphaning already stored operations.
- Guarded updater rejects a target below the installed manifest floor before maintenance mode or checkout switch.
- Full panel, Rust, frontend and Android gates pass before any push or deploy is proposed.
