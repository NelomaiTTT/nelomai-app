# Confirmed Stable Panel Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the panel backward-compatible with one container version and one active runtime version while providing idempotent device-scoped cleanup before a switched runtime starts a tunnel.

**Architecture:** Add nullable runtime metadata and explicit contract fields without removing legacy `app_version`. A single request metadata parser updates device identity and supplies runtime-aware capability decisions. A dedicated reconciliation service runs under the existing exclusive allocation guard, records operation identity, retires all nonterminal work for one device, and preserves its peer binding and pinned settings.

**Tech Stack:** Python 3.11, FastAPI/Pydantic, SQLAlchemy 2, Alembic, PostgreSQL/SQLite tests, pytest/unittest.

**Spec:** `../nelomai-app/docs/superpowers/specs/2026-09-02-confirmed-stable-runtime-design.md`

## Global Constraints

- Legacy `app_version` and `X-Nelomai-App-Version` remain valid and mean container version.
- New clients send `container_version`, `runtime_version`, `runtime_contract_version`, `runtime_slot`, and `session_generation`; mismatched legacy/container values are rejected.
- Update/minimum-supported checks use container version only.
- Transport, capability, tunnel, background, and recovery compatibility use runtime version and explicit contract versions.
- Reconciliation is device-scoped, idempotent by operation ID, preserves peer binding and pinned preferences, and never adopts an old tunnel.
- Panel changes are additive and deployable before 0.2.16; Android hot-standby capability remains unchanged.
- No production migration or deploy is part of these tasks.

---

### Task 1: Persist container/runtime identity additively

**Files:**
- Create: `migrations/versions/20260902_0056_confirmed_stable_runtime.py`
- Modify: `app/models.py`
- Modify: `scripts/migration_check.py`
- Test: `tests/test_app_migration.py`
- Test: `tests/test_preflight_portability.py`

**Interfaces:**
- Produces: `AppDevice.container_version: str`, `AppDevice.runtime_version: str | None`, `AppDevice.runtime_contract_version: int | None`, `AppDevice.runtime_slot: str | None`, `AppDevice.session_generation: int | None`.
- Produces: `AppSession.client_session_generation: int | None`, binding every runtime-v1 access token to the common broker generation that created or resumed it.
- Compatibility: `AppDevice.app_version` remains a non-null database column and is always synchronized with `container_version` by new request code.

- [ ] **Step 1: Write failing migration/model tests.** Assert upgrade from revision `20260830_0055` backfills `container_version = app_version`, leaves runtime fields nullable, adds nullable `app_sessions.client_session_generation`, creates checks `runtime_contract_version >= 1`, `session_generation >= 1`, `client_session_generation >= 1`, and restricts runtime slot to `latest|stable`; assert downgrade removes only the new columns.
- [ ] **Step 2: Run the focused tests and observe RED.**

```bash
python -m pytest tests/test_app_migration.py tests/test_preflight_portability.py -q
```

Expected: failure because revision `20260902_0056` and the five model attributes do not exist.

- [ ] **Step 3: Implement the additive migration and model.** Use this exact data rule in `upgrade()`:

```python
op.add_column("app_devices", sa.Column("container_version", sa.String(64)))
op.execute("UPDATE app_devices SET container_version = app_version")
op.alter_column("app_devices", "container_version", nullable=False)
op.add_column("app_devices", sa.Column("runtime_version", sa.String(64)))
op.add_column("app_devices", sa.Column("runtime_contract_version", sa.Integer()))
op.add_column("app_devices", sa.Column("runtime_slot", sa.String(16)))
op.add_column("app_devices", sa.Column("session_generation", sa.BigInteger()))
op.add_column("app_sessions", sa.Column("client_session_generation", sa.BigInteger()))
```

Add named check constraints for positive contract/generation and `runtime_slot IN ('latest', 'stable')`. Update migration metadata inventories so backup/restore and schema checks include the columns.

Keep direct legacy model construction working during the additive rollout with a client-side insert default derived from the existing field:

```python
def _legacy_container_version(context: DefaultExecutionContext) -> str:
    return str(context.get_current_parameters()["app_version"])

container_version: Mapped[str] = mapped_column(
    String(64), nullable=False, default=_legacy_container_version
)
```

Add a test that an `AppDevice(app_version="0.2.15", ...)` created by unchanged legacy code persists both columns as `0.2.15`.

- [ ] **Step 4: Run focused tests GREEN and inspect generated SQL for PostgreSQL compatibility.**
- [ ] **Step 5: Commit in the panel repository.**

```bash
git add app/models.py migrations/versions/20260902_0056_confirmed_stable_runtime.py scripts/migration_check.py tests/test_app_migration.py tests/test_preflight_portability.py
git commit -m "Добавить версии контейнера и runtime устройства"
```

### Task 2: Normalize old and runtime-v1 request metadata

**Files:**
- Create: `app/client_runtime.py`
- Modify: `app/client_schemas.py`
- Modify: `app/client_api.py`
- Modify: `app/client_auth.py`
- Test: `tests/test_client_auth.py`
- Test: `tests/test_client_connections.py`

**Interfaces:**
- Produces: immutable `ClientRuntimeIdentity(container_version: str, runtime_version: str, runtime_contract_version: int, runtime_slot: Literal["latest", "stable"], session_generation: int)`.
- Produces: `parse_client_runtime_identity(*, app_version, container_version, runtime_version, runtime_contract_version, runtime_slot, session_generation) -> ClientRuntimeIdentity | None` where `None` means legacy client.
- Produces: `apply_client_runtime_identity(device, identity) -> bool`, synchronizing `app_version` and `container_version`.

- [ ] **Step 1: Add RED schema/parser tests.** Cover legacy login with only `app_version`; runtime-v1 login with all fields; rejection of partial runtime metadata; rejection when `app_version != container_version`; invalid version/slot/contract/generation; and bootstrap headers whose values disagree with login identity.
- [ ] **Step 2: Run RED tests.**

```bash
python -m pytest tests/test_client_auth.py tests/test_client_connections.py -q -k 'version or runtime_identity or bootstrap'
```

- [ ] **Step 3: Add optional fields to `ClientLoginRequest` and one parser.** Do not duplicate parsing inside endpoints. The parser must enforce:

```python
runtime_values = (
    container_version,
    runtime_version,
    runtime_contract_version,
    runtime_slot,
    session_generation,
)
if not any(value is not None for value in runtime_values):
    return None
if not all(value is not None for value in runtime_values):
    raise ClientAuthError(400, "incomplete_runtime_identity", "Неполные данные runtime.")
if app_version != container_version:
    raise ClientAuthError(409, "container_version_mismatch", "Версия контейнера не совпадает.")
```

Login calls `get_or_create_client_device` with container version and then applies the runtime identity before token issuance. Token issuance snapshots `identity.session_generation` into `AppSession.client_session_generation`. Bootstrap reads both new headers and the legacy header, applies the same parser, requires the request generation to match the authenticated session snapshot, and never lets a runtime-only value overwrite container version. A later login may advance the stored device generation only while holding the device lock; it may reuse the same generation for the same live common session, but it may never decrease it.

- [ ] **Step 4: Add container/runtime values to `ClientDeviceView` without deleting existing response fields.** Legacy requests may receive `runtime_version = null`; runtime-v1 requests receive the normalized values.
- [ ] **Step 5: Run focused tests GREEN.**
- [ ] **Step 6: Commit.**

```bash
git add app/client_runtime.py app/client_schemas.py app/client_api.py app/client_auth.py tests/test_client_auth.py tests/test_client_connections.py
git commit -m "Разделить идентичность контейнера и runtime в API"
```

### Task 3: Route compatibility gates to the correct version

**Files:**
- Create: `app/client_runtime_contracts.py`
- Modify: `app/client_runtime.py`
- Modify: `app/client_connections.py`
- Modify: `app/client_transports.py`
- Modify: `app/client_api.py`
- Test: `tests/test_client_releases.py`
- Test: `tests/test_client_connections.py`
- Test: `tests/test_client_auth.py`

**Interfaces:**
- Produces: `client_container_version(device) -> Version | None` and `client_runtime_version(device) -> Version | None`.
- Produces: `GET /api/client/v1/runtime-contracts` with immutable `revision`, supported contract/version ranges, and no mutable device state.
- Consumes: normalized fields from Task 2.

- [ ] **Step 1: Add RED matrix tests.** Use a device with `container_version=0.3.0`, `runtime_version=0.2.16`: update state must be current for 0.3.0, while transport/capability decisions must match 0.2.16. Also prove a legacy 0.2.15 device retains previous behavior.
- [ ] **Step 2: Run RED matrix.**

```bash
python -m pytest tests/test_client_releases.py tests/test_client_connections.py tests/test_client_auth.py -q -k 'container_version or runtime_version or transport or capability'
```

- [ ] **Step 3: Replace direct reads by semantic helpers.** `client_bootstrap_state` and release selection call `client_container_version`; `client_supports_transport`, connection-intent capability selection, redundancy/hot-standby gates, and recovery contract validation call `client_runtime_version` and check explicit contract versions.
- [ ] **Step 4: Add an embedded-runtime support table.** In `app/client_runtime.py`, declare server-owned ranges by contract, not by “latest app”:

```python
SUPPORTED_EMBEDDED_RUNTIME_CONTRACTS = {1: (Version("0.2.16"), None)}
```

`None` is an open upper bound until a later panel change closes it. The public runtime-contract response serializes this exact table with `revision=1`. Release validation must fetch the deployed response, require the expected revision, and reject a stable runtime outside it.

- [ ] **Step 5: Run matrix GREEN and the entire release/connection suites.**
- [ ] **Step 6: Commit.**

```bash
git add app/client_runtime.py app/client_runtime_contracts.py app/client_connections.py app/client_transports.py app/client_api.py tests/test_client_releases.py tests/test_client_connections.py tests/test_client_auth.py
git commit -m "Развести версии обновления и туннельных контрактов"
```

### Task 4: Scope background credentials to runtime and session generation

**Files:**
- Modify: `migrations/versions/20260902_0056_confirmed_stable_runtime.py`
- Modify: `app/models.py`
- Modify: `app/client_auth.py`
- Modify: `app/client_schemas.py`
- Test: `tests/test_client_auth.py`
- Test: `tests/test_app_migration.py`

**Interfaces:**
- Extends `AppBackgroundToken` with `runtime_slot`, `runtime_version`, and `session_generation`.
- Consumes: `ClientRuntimeIdentity` from Task 2.
- Produces: background-token resolution that returns 401 `stale_background_runtime` when any scope differs from the active device identity.

- [ ] **Step 1: Add RED tests.** Prove issuance stores all three scope values; refresh rotation preserves them; slot switch or generation increment invalidates start/recovery use; cleanup-token resolution still permits bounded cleanup for its original scope; logout makes both paths invalid after finalization.
- [ ] **Step 2: Run RED tests.**

```bash
python -m pytest tests/test_client_auth.py tests/test_app_migration.py -q -k 'background and (runtime or generation)'
```

- [ ] **Step 3: Add nullable columns for legacy tokens and populate new tokens from device identity.** Legacy background tokens remain valid under legacy rules until rotated. Runtime-v1 tokens require non-null scope and compare it under the existing session/device locks.
- [ ] **Step 4: Keep cleanup separate from new work.** `resolve_client_background_token` rejects stale scope; `resolve_client_background_cleanup_token` accepts only the token’s recorded device/session and exposes `cleanup_only=True`, so handlers cannot call start/acquire routes with it.
- [ ] **Step 5: Run focused and full auth tests GREEN.**
- [ ] **Step 6: Amend the Task 1 migration commit or create a separate Russian commit if Task 1 has already passed review.**

```bash
git add app/models.py app/client_auth.py app/client_schemas.py migrations/versions/20260902_0056_confirmed_stable_runtime.py tests/test_client_auth.py tests/test_app_migration.py
git commit -m "Привязать фоновые полномочия к runtime и сессии"
```

### Task 5: Add idempotent device-scoped runtime-switch reconciliation

**Files:**
- Create: `app/client_runtime_switch.py`
- Modify: `app/client_schemas.py`
- Modify: `app/client_api.py`
- Modify: `app/client_connections.py`
- Modify: `app/client_connection_recovery.py`
- Modify: `app/client_redundancy.py`
- Test: `tests/test_client_runtime_switch.py`
- Test: `tests/test_client_operation_postgresql.py`

**Interfaces:**
- Produces request `ClientRuntimeSwitchReconcileRequest(operation_id, source_slot, source_runtime_version, target_slot, target_runtime_version, session_generation, cleanup_contract_version=1, lease_ids, redundant_session_ids, client_operation_ids)`.
- Produces response `ClientRuntimeSwitchReconcileResponse(state: Literal["clean", "retry"], operation_id, retired_lease_ids, retired_session_ids, retired_operation_ids, retry_after_seconds)`.
- Produces `reconcile_runtime_switch(db, context, request, now) -> RuntimeSwitchResult`.

- [ ] **Step 1: Add RED service tests for a fixed lease, dynamic lease, pinned lease, allocating start, compensation stop, connected redundant session, degraded redundant session, already-clean device, and repeated identical operation ID.** Verify peer binding, selected pinned peer, user split-tunnel preferences, and device identity are unchanged.
- [ ] **Step 2: Add RED conflict tests.** The same operation ID with a different normalized payload returns 409 `runtime_switch_operation_conflict`; stale session generation returns 409; an authenticated device cannot name another device’s IDs; cleanup-only background credentials may reconcile but may not start a tunnel.
- [ ] **Step 3: Add RED PostgreSQL lock-order tests.** Assert the endpoint enters `client_allocation_guard(exclusive=True)`, locks `AppDevice` first, then active sessions/operations/leases in stable primary-key order, and does not deadlock against ordinary allocation tests.
- [ ] **Step 4: Run RED tests.**

```bash
python -m pytest tests/test_client_runtime_switch.py tests/test_client_operation_postgresql.py -q
```

- [ ] **Step 5: Implement reconciliation using existing lifecycle primitives.** Normalize the request and persist its signature through the existing operation journal. Under one exclusive allocation guard: mark nonterminal client operations cancelled/compensating as their state machine requires; stop every active `AppConnectionSession`; release or fail every active lease for the device through pool/stray cleanup helpers; clear session addresses; leave `AppPeerBinding` and pinned preferences untouched; commit `clean` only when a final query finds no active session, nonterminal operation, or active lease.
- [ ] **Step 6: Return retry instead of false clean.** If an agent has not acknowledged privileged cleanup, persist the existing cleanup job and return `state="retry"`, `retry_after_seconds` clamped to 1–30. Repeating the same operation resumes it and never creates a second cleanup job.
- [ ] **Step 7: Register both bearer and cleanup-background routes at `POST /api/client/v1/connections/runtime-switch/reconcile` through one internal handler.** Reject normal start/acquire while the device’s reconcile operation is not clean.
- [ ] **Step 8: Run focused tests GREEN, then the existing recovery/redundancy/allocation suites.**
- [ ] **Step 9: Commit.**

```bash
git add app/client_runtime_switch.py app/client_schemas.py app/client_api.py app/client_connections.py app/client_connection_recovery.py app/client_redundancy.py tests/test_client_runtime_switch.py tests/test_client_operation_postgresql.py
git commit -m "Добавить очистку устройства при смене runtime"
```

### Task 6: Expose both versions in diagnostics and administration

**Files:**
- Modify: `app/client_schemas.py`
- Modify: `app/client_api.py`
- Modify: `app/client_diagnostics.py`
- Modify: `app/templates/admin_diagnostics.html`
- Modify: `app/templates/admin.html`
- Test: `tests/test_client_diagnostics.py`
- Test: `tests/test_admin_logs_web.py`
- Test: `tests/test_dashboard_presentation.py`

**Interfaces:**
- Extends diagnostic metadata with `container_version`, `runtime_version`, `runtime_slot`, `runtime_contract_version`, `switch_operation_id`, and `switch_phase`.
- Legacy diagnostic `app_version` remains accepted and is rendered as container version.

- [ ] **Step 1: Add RED tests for old and new diagnostic payloads and admin rendering.** Confirm secrets, install ID, tokens, cleanup envelopes, and tunnel configuration are absent from stored/rendered details.
- [ ] **Step 2: Run RED tests.**
- [ ] **Step 3: Add optional diagnostic fields, normalize legacy `app_version`, persist safe metadata, and label both versions explicitly in admin views.** Do not add a Fantasy/template dependency.
- [ ] **Step 4: Run focused tests GREEN.**
- [ ] **Step 5: Commit.**

```bash
git add app/client_schemas.py app/client_api.py app/client_diagnostics.py app/templates/admin_diagnostics.html app/templates/admin.html tests/test_client_diagnostics.py tests/test_admin_logs_web.py tests/test_dashboard_presentation.py
git commit -m "Показать версии контейнера и runtime в диагностике"
```

### Task 7: Prove old/new contract compatibility and prepare the guarded deployment gate

**Files:**
- Modify: `docs/application-updates.md`
- Create: `docs/confirmed-stable-panel-contract.md`
- Modify: `scripts/smoke_check.py`
- Test: `tests/test_client_auth.py`
- Test: `tests/test_client_releases.py`
- Test: `tests/test_client_runtime_switch.py`

**Interfaces:**
- Consumes every interface in Tasks 1–6.
- Produces a source revision safe to deploy additively before the 0.2.16 application release.

- [ ] **Step 1: Add a four-way compatibility test table.** Cover old app/old-shaped request on new panel; runtime-v1 app/new request on new panel; old headers after new login rejected only when they contradict stored runtime-v1 identity; embedded 0.2.16 runtime inside 0.3.0 receiving update state for container 0.3.0 and tunnel gates for runtime 0.2.16.
- [ ] **Step 2: Document exact API fields, error codes, header trust boundary, reconciliation retry semantics, and rollback behavior.** State that production migration/deployment requires a separate user command.
- [ ] **Step 3: Run complete local verification.**

```bash
python -m pytest -q
python scripts/migration_check.py
python scripts/smoke_check.py
git diff --check
```

Expected: all commands exit 0 against local/disposable test state. Do not point preflight or migration commands at the production database.

- [ ] **Step 4: Review the diff for direct `device.app_version` reads.** Only migration/legacy alias code may remain; every policy decision must use the semantic helper.

```bash
rg -n "device\.app_version|X-Nelomai-App-Version|x-nelomai-app-version" app tests
```

- [ ] **Step 5: Commit documentation and compatibility tests.**

```bash
git add docs/application-updates.md docs/confirmed-stable-panel-contract.md scripts/smoke_check.py tests/test_client_auth.py tests/test_client_releases.py tests/test_client_runtime_switch.py
git commit -m "Проверить совместимость панели со встроенным runtime"
```

- [ ] **Step 6: Stop at the deployment boundary.** Report the exact panel HEAD, test evidence, migration revision, and that no deploy/migration/capability change has been performed.
