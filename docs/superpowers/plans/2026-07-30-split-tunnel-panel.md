# Split-tunnel Panel and API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the panel-side source of truth, client API, audit trail, and administrator controls for versioned split-tunnel policies without changing the configuration downloaded by old application versions.

**Architecture:** The panel stores global rules and per-device choices as normalized rows, derives one compact device policy from the device's bound peer, and exposes it through `/api/client/v1`. Native application configurations keep `AllowedIPs = 0.0.0.0/0`; the existing browser/public peer-download flow keeps its current experimental `AllowedIPs` rewrite. An initially disabled feature flag and two revision counters permit controlled rollout and forced synchronization.

**Tech Stack:** Python 3.11, FastAPI, Pydantic 2, SQLAlchemy 2, Alembic, PostgreSQL/SQLite, Jinja2, vanilla JavaScript, unittest, FastAPI TestClient.

## Global Constraints

- Work in `/Users/altzxd/Documents/GitHub/nelomai-panel`; the plan itself lives in the application repository only for coordinated execution.
- Use client API prefix `/api/client/v1`; do not introduce the obsolete `/api/app` prefix from early design notes.
- The global split-tunnel flag is `false` after migration and deployment.
- Existing application versions and all browser/public peer downloads keep working.
- A native application configuration must never be rewritten into an `AllowedIPs` complement.
- The panel returns compact, collapsed IPv4 exclusion CIDRs only; it never expands them into the complement of `0.0.0.0/0`.
- Stage one does not add selective IPv6 exclusions.
- Full installed-application inventory and local physical networks are never uploaded or stored.
- Package IDs are ASCII, case-normalized, at most 255 characters, and match `^[A-Za-z0-9_.]+$`.
- Display names are at most 255 characters.
- At most 512 selected packages, 512 mandatory package IDs, 128 suggested name fragments, and 16,384 compact IPv4 CIDRs are accepted in one effective policy.
- A serialized client settings request is limited to 256 KiB; a serialized effective policy is limited to 1 MiB.
- The cheap revision endpoint creates no panel job and no ordinary audit event.
- Successful no-change policy reads and successful apply reports create no ordinary audit event.
- Audit global changes, promotion, forced synchronization, failed application, and failed rollback only.
- Commit messages are in Russian.
- Do not push or deploy during plan execution unless the user explicitly requests it.

---

## File Map

- Create `migrations/versions/20260730_0037_app_split_tunnel.py`: tables, constraints, indexes, settings, and initial Android rules.
- Modify `app/models.py`: split-tunnel enums, ORM rows, and `AppDevice` relationships.
- Create `app/client_split_tunnel.py`: normalization, revisions, policy projection, hash, settings replacement, statistics, promotion, apply reports, and audit.
- Modify `app/services.py`: expose compact blocked IPv4 networks through a public service function while preserving the legacy download rewrite.
- Modify `app/client_bindings.py`: stop applying the legacy `AllowedIPs` rewrite to native application configurations.
- Modify `app/client_schemas.py`: strict client request/response schemas.
- Modify `app/client_api.py`: four authenticated client endpoints.
- Modify `app/schemas.py`: administrator request/response schemas.
- Modify `app/web.py`: administrator API routes and settings-page projection.
- Modify `app/templates/admin.html`: settings navigation and a focused split-tunnel panel include.
- Create `app/templates/admin_split_tunnel.html`: administrator controls and statistics table.
- Create `app/static/split-tunnel-admin.js`: list editing, promotion, save, and force confirmation.
- Create `app/static/split-tunnel-admin.css`: dashboard-compatible admin styling.
- Modify `docs/client_api.md`: document contracts, sync semantics, privacy, and compatibility.
- Create `tests/test_client_split_tunnel.py`: domain and persistence tests.
- Create `tests/test_client_split_tunnel_api.py`: auth, validation, ownership, and revision tests.
- Create `tests/test_admin_split_tunnel_web.py`: admin authorization, rendering, audit, and frontend payload tests.
- Modify `tests/test_client_peer_binding.py`: prove native configurations are not rewritten.
- Modify existing split-tunnel download tests in the file returned by `rg -l "_apply_split_tunnel_to_peer_payload|split.tunnel" tests`: prove browser/public download behavior remains unchanged.
- Create `tests/frontend/split_tunnel_admin.test.js`: administrator UI behavior.

---

### Task 1: Persist Versioned Rules and Per-Device State

**Files:**
- Create: `migrations/versions/20260730_0037_app_split_tunnel.py`
- Modify: `app/models.py`
- Test: `tests/test_client_split_tunnel.py`

**Interfaces:**
- Produces enum values `mandatory_package`, `suggested_name`, `exclude_selected`, `include_selected`, `applied`, `failed`, and `rolled_back`.
- Produces ORM models `AppSplitTunnelRule`, `AppSplitTunnelDevicePolicy`, `AppSplitTunnelSelection`, `AppSplitTunnelSelectionEvent`, and `AppSplitTunnelApplyState`.
- Produces settings keys `app_split_tunnel_enabled`, `app_split_tunnel_revision`, and `app_split_tunnel_force_revision`.
- Later tasks consume the unique `(kind, normalized_value)` rule constraint and unique `(device_id, package_id)` selection constraint.

- [x] **Step 1: Write failing model and seed tests**

Add a `SplitTunnelPersistenceTests` class using the repository's in-memory SQLite pattern. Assert:

```python
def test_device_policy_defaults_to_exclude_mode_and_local_networks(self) -> None:
    row = AppSplitTunnelDevicePolicy(device_id=self.device.id)
    self.db.add(row)
    self.db.commit()
    self.db.refresh(row)

    self.assertEqual(row.mode, AppSplitTunnelMode.EXCLUDE_SELECTED)
    self.assertTrue(row.exclude_local_networks)

def test_active_selection_is_unique_per_device_and_package(self) -> None:
    self.db.add_all([
        AppSplitTunnelSelection(
            device_id=self.device.id,
            package_id="com.example.app",
            display_name="Example",
        ),
        AppSplitTunnelSelection(
            device_id=self.device.id,
            package_id="com.example.app",
            display_name="Example renamed",
        ),
    ])
    with self.assertRaises(IntegrityError):
        self.db.commit()
```

Add a migration inspection test that imports the migration module, runs `upgrade()` against temporary SQLite through Alembic's existing test helper, and asserts:

```python
assert settings == {
    "app_split_tunnel_enabled": "0",
    "app_split_tunnel_revision": "1",
    "app_split_tunnel_force_revision": "0",
}
assert mandatory_count == 48
assert suggestion_values == {"Яндекс", "MAX", "Ozon"}
```

- [x] **Step 2: Run the focused tests and verify failure**

Run:

```bash
.venv/bin/python -m unittest tests.test_client_split_tunnel -v
```

Expected: FAIL because split-tunnel models and migration do not exist.

- [x] **Step 3: Add enums and ORM relationships**

Add string enums near the existing application enums in `app/models.py`:

```python
class AppSplitTunnelRuleKind(str, Enum):
    MANDATORY_PACKAGE = "mandatory_package"
    SUGGESTED_NAME = "suggested_name"


class AppSplitTunnelMode(str, Enum):
    EXCLUDE_SELECTED = "exclude_selected"
    INCLUDE_SELECTED = "include_selected"


class AppSplitTunnelApplyStatus(str, Enum):
    APPLIED = "applied"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
```

Add these relationships to `AppDevice`:

```python
split_tunnel_policy: Mapped["AppSplitTunnelDevicePolicy | None"] = relationship(
    back_populates="device",
    cascade="all, delete-orphan",
    uselist=False,
    passive_deletes=True,
)
split_tunnel_selections: Mapped[list["AppSplitTunnelSelection"]] = relationship(
    back_populates="device",
    cascade="all, delete-orphan",
    passive_deletes=True,
)
split_tunnel_apply_state: Mapped["AppSplitTunnelApplyState | None"] = relationship(
    back_populates="device",
    cascade="all, delete-orphan",
    uselist=False,
    passive_deletes=True,
)
```

Implement the five models with these exact keys:

```python
class AppSplitTunnelRule(Base):
    __tablename__ = "app_split_tunnel_rules"
    __table_args__ = (
        UniqueConstraint("kind", "normalized_value", name="uq_app_split_tunnel_rule_value"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[AppSplitTunnelRuleKind] = mapped_column(
        Enum(AppSplitTunnelRuleKind, native_enum=False, length=32, values_callable=_enum_values),
        nullable=False,
        index=True,
    )
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    normalized_value: Mapped[str] = mapped_column(String(255), nullable=False)
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class AppSplitTunnelDevicePolicy(Base):
    __tablename__ = "app_split_tunnel_device_policies"

    device_id: Mapped[str] = mapped_column(
        ForeignKey("app_devices.id", ondelete="CASCADE"), primary_key=True
    )
    mode: Mapped[AppSplitTunnelMode] = mapped_column(
        Enum(AppSplitTunnelMode, native_enum=False, length=32, values_callable=_enum_values),
        default=AppSplitTunnelMode.EXCLUDE_SELECTED,
        nullable=False,
    )
    exclude_local_networks: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )
    device: Mapped["AppDevice"] = relationship(back_populates="split_tunnel_policy")


class AppSplitTunnelSelection(Base):
    __tablename__ = "app_split_tunnel_selections"
    __table_args__ = (
        UniqueConstraint("device_id", "package_id", name="uq_app_split_tunnel_selection"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[str] = mapped_column(
        ForeignKey("app_devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    package_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )
    device: Mapped["AppDevice"] = relationship(back_populates="split_tunnel_selections")


class AppSplitTunnelSelectionEvent(Base):
    __tablename__ = "app_split_tunnel_selection_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[str] = mapped_column(
        ForeignKey("app_devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    package_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    selected: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)


class AppSplitTunnelApplyState(Base):
    __tablename__ = "app_split_tunnel_apply_states"

    device_id: Mapped[str] = mapped_column(
        ForeignKey("app_devices.id", ondelete="CASCADE"), primary_key=True
    )
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    force_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    policy_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    status: Mapped[AppSplitTunnelApplyStatus] = mapped_column(
        Enum(AppSplitTunnelApplyStatus, native_enum=False, length=24, values_callable=_enum_values),
        nullable=False,
    )
    error_code: Mapped[str | None] = mapped_column(String(120), nullable=True)
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    device: Mapped["AppDevice"] = relationship(back_populates="split_tunnel_apply_state")
```

- [x] **Step 4: Create the Alembic migration with exact initial data**

Use `revision = "20260730_0037"` and `down_revision = "20260729_0036"`. Create all constraints and indexes represented by the ORM models. Seed the three settings and these exact mandatory package IDs:

```python
MANDATORY_PACKAGE_IDS = (
    "ru.aliexpress.buyer",
    "com.google.android.projection.gearhead",
    "com.logistic.sdek",
    "com.loyaltyplant.partner.frankbybasta",
    "ru.oneme.app",
    "ru.nspk.mirpay",
    "ru.ozon.app.android",
    "ru.vk.store",
    "com.avito.android",
    "ru.gosuslugi.auto",
    "com.whsd.whsdapp",
    "com.apegroup.mcdonaldsrussia",
    "ru.vtb24.mobilebanking.android",
    "com.sdkit.search.app",
    "ru.gosuslugi.goskey",
    "ru.rostel",
    "com.fls.gosuslugispb",
    "ru.dodopizza.app",
    "ru.sigma.gisgkh",
    "com.yandex.mobile.drive",
    "ru.yandex.mobile.gasstations",
    "com.zvooq.openplay",
    "ru.kinopoisk",
    "ru.instamart",
    "ru.filit.mvideo.b2c",
    "ru.tander.magnit",
    "ru.beru.android",
    "ru.megamarket.marketplace",
    "ru.tinkoff.mvno",
    "ru.fns.lkfl",
    "ru.spb.parking",
    "ru.autoins.mobile.osagohelper",
    "ru.sbcs.store",
    "ru.sberbankmobile",
    "com.idamob.tinkoff.android",
    "ru.tinkoff.investing",
    "ru.urentbike.app",
    "ru.yandex.taxi",
    "ru.yandex.key",
    "ru.foodfox.client",
    "ru.plus.bookmate",
    "ru.yandex.metro",
    "ru.yandex.music",
    "com.yandex.bank",
    "ru.yandex.disk",
    "ru.yandex.yandexmaps",
    "com.yandex.lavka",
    "ru.yandex.yandexnavi",
)
SUGGESTED_NAME_FRAGMENTS = ("Яндекс", "MAX", "Ozon")
```

Store mandatory `normalized_value` as lowercase package ID and suggestions as Unicode `casefold()` output generated in Python migration code. The downgrade drops child tables before parent tables and then removes only the three split-tunnel setting keys.

- [x] **Step 5: Run model and migration tests**

Run:

```bash
.venv/bin/python -m unittest tests.test_client_split_tunnel -v
.venv/bin/alembic upgrade head
.venv/bin/alembic downgrade 20260729_0036
.venv/bin/alembic upgrade head
```

Expected: all tests PASS; upgrade/downgrade/upgrade succeeds on the local development database.

- [x] **Step 6: Commit the persistence layer**

```bash
git add app/models.py migrations/versions/20260730_0037_app_split_tunnel.py tests/test_client_split_tunnel.py
git commit -m "Добавить хранение политик split-tunnel"
```

---

### Task 2: Normalize Rules, Replace Device Settings, and Track Revisions

**Files:**
- Create: `app/client_split_tunnel.py`
- Modify: `tests/test_client_split_tunnel.py`

**Interfaces:**
- Produces `normalize_package_id(value: str) -> str`.
- Produces `normalize_name_fragment(value: str) -> tuple[str, str]`.
- Produces `SplitTunnelSelectedPackage(package_id: str, display_name: str)`.
- Produces `load_split_tunnel_revisions(db: Session) -> tuple[bool, int, int]`.
- Produces `replace_device_split_tunnel_settings(db, context, *, mode, exclude_local_networks, selected_packages) -> EffectiveSplitTunnelPolicy`.
- Produces `replace_global_split_tunnel_rules(db, actor, *, enabled, mandatory_packages, suggested_fragments) -> AdminSplitTunnelPage`.
- Produces `force_split_tunnel_sync(db, actor) -> AdminSplitTunnelPage`.
- Later tasks consume revision increments and normalized active selections.

- [x] **Step 1: Write failing normalization and replacement tests**

Add tests for:

```python
def test_package_normalization_is_ascii_lowercase_and_strict(self) -> None:
    self.assertEqual(normalize_package_id(" Com.Example.App "), "com.example.app")
    for invalid in ("", "com/example", "приложение.id", "a" * 256):
        with self.subTest(invalid=invalid), self.assertRaises(SplitTunnelValidationError):
            normalize_package_id(invalid)

def test_replace_settings_deduplicates_and_records_only_changes(self) -> None:
    first = replace_device_split_tunnel_settings(
        self.db,
        self.context,
        mode=AppSplitTunnelMode.EXCLUDE_SELECTED,
        exclude_local_networks=True,
        selected_packages=[
            SplitTunnelSelectedPackage("Com.Example.App", "Example"),
            SplitTunnelSelectedPackage("com.example.app", "Example renamed"),
        ],
    )
    second = replace_device_split_tunnel_settings(
        self.db,
        self.context,
        mode=AppSplitTunnelMode.EXCLUDE_SELECTED,
        exclude_local_networks=True,
        selected_packages=[SplitTunnelSelectedPackage("com.example.app", "Example renamed")],
    )

    self.assertEqual(first.selected_packages, ("com.example.app",))
    self.assertEqual(second.selected_packages, ("com.example.app",))
    self.assertEqual(self.count_selection_events(), 1)
```

Also assert:

- 513 selected packages fail before any database mutation.
- mandatory IDs are removed from active selections and do not create a user-selection event;
- an omitted previously selected package creates one `selected=False` history event;
- changing only display name updates the active row but does not create add/remove history;
- user settings do not increment the global ordinary revision;
- a global update increments ordinary revision exactly once;
- force sync increments only force revision exactly once;
- replacing global rules removes active selection rows that became mandatory while preserving history.

- [x] **Step 2: Run focused tests and verify failure**

Run:

```bash
.venv/bin/python -m unittest tests.test_client_split_tunnel.SplitTunnelPersistenceTests -v
```

Expected: FAIL because the domain service does not exist.

- [x] **Step 3: Implement strict normalization and setting helpers**

Create `app/client_split_tunnel.py` with:

```python
PACKAGE_ID_RE = re.compile(r"^[A-Za-z0-9_.]+$")
MAX_SELECTED_PACKAGES = 512
MAX_MANDATORY_PACKAGES = 512
MAX_SUGGESTED_FRAGMENTS = 128
MAX_EXCLUDED_IPV4_CIDRS = 16_384
POLICY_FORMAT_VERSION = 1


class SplitTunnelValidationError(ValueError):
    pass


@dataclass(frozen=True)
class SplitTunnelSelectedPackage:
    package_id: str
    display_name: str


def normalize_package_id(value: str) -> str:
    normalized = value.strip().lower()
    if not normalized or len(normalized) > 255 or PACKAGE_ID_RE.fullmatch(normalized) is None:
        raise SplitTunnelValidationError("invalid_package_id")
    return normalized


def normalize_name_fragment(value: str) -> tuple[str, str]:
    display = value.strip()
    normalized = display.casefold()
    if not display or len(display) > 255:
        raise SplitTunnelValidationError("invalid_name_fragment")
    return display, normalized
```

Read settings with defaults if a manually created test database has no seeded rows:

```python
def load_split_tunnel_revisions(db: Session) -> tuple[bool, int, int]:
    enabled = _setting_int(db, "app_split_tunnel_enabled", 0) == 1
    revision = max(1, _setting_int(db, "app_split_tunnel_revision", 1))
    force_revision = max(0, _setting_int(db, "app_split_tunnel_force_revision", 0))
    return enabled, revision, force_revision
```

Use a PostgreSQL `SELECT ... FOR UPDATE` on the three `AppSetting` rows before incrementing counters. SQLite tests use the same transaction without `FOR UPDATE`.

- [x] **Step 4: Implement atomic device replacement and history**

Normalize and deduplicate incoming packages by package ID, keeping the last display name. Load mandatory IDs once in the transaction and remove them from the incoming active set. Compare incoming IDs to existing rows:

```python
added = incoming_ids - existing_ids
removed = existing_ids - incoming_ids
retained = incoming_ids & existing_ids
```

Create history rows only for `added` and `removed`, update retained display names, upsert `AppSplitTunnelDevicePolicy`, flush, build the new policy using Task 3's function signature, then commit. Until Task 3 exists, return a private projection containing mode, local-network flag, and selected IDs so this task remains testable.

On validation or policy-build failure, roll back the whole transaction. Never partially replace selections.

- [x] **Step 5: Implement global replacement, promotion, and revisions**

`replace_global_split_tunnel_rules` must normalize and replace both rule kinds in one transaction, set the flag, increment ordinary revision once only when effective global content changed, and write one audit event:

```python
event_type="client.split_tunnel.settings_changed"
message_ru="Администратор изменил настройки split-tunnel приложений."
```

`promote_split_tunnel_package` inserts a mandatory rule, deletes matching active selections, retains selection history, increments ordinary revision, and writes:

```python
event_type="client.split_tunnel.package_promoted"
message_ru=f"Приложение {package_id} добавлено в обязательные исключения split-tunnel."
```

`force_split_tunnel_sync` increments only `app_split_tunnel_force_revision` and writes:

```python
event_type="client.split_tunnel.force_sync"
message_ru="Администратор запустил принудительную синхронизацию split-tunnel."
```

- [x] **Step 6: Run domain tests**

Run:

```bash
.venv/bin/python -m unittest tests.test_client_split_tunnel -v
```

Expected: PASS.

- [x] **Step 7: Commit the domain service**

```bash
git add app/client_split_tunnel.py tests/test_client_split_tunnel.py
git commit -m "Добавить управление правилами split-tunnel"
```

---

### Task 3: Build Compact Effective Policies and Preserve Native `AllowedIPs`

**Files:**
- Modify: `app/services.py`
- Modify: `app/client_bindings.py`
- Modify: `app/client_split_tunnel.py`
- Modify: `tests/test_client_split_tunnel.py`
- Modify: `tests/test_client_peer_binding.py`
- Modify: existing browser/public split-tunnel tests located with `rg -l "_apply_split_tunnel_to_peer_payload|split.tunnel" tests`

**Interfaces:**
- Produces `blocked_ipv4_networks_for_peer(db: Session, peer: Peer) -> list[ipaddress.IPv4Network]`.
- Produces immutable `EffectiveSplitTunnelPolicy`.
- Produces `build_effective_split_tunnel_policy(db: Session, context: ClientAuthContext) -> EffectiveSplitTunnelPolicy`.
- Produces canonical `policy_hash` in the form `sha256:<64 lowercase hex>`.
- Native binding downloads consume raw agent configuration; browser/public downloads still consume `_apply_split_tunnel_to_peer_payload`.

- [x] **Step 1: Write failing policy projection tests**

Create tests that arrange a device binding, global/user/peer block filters, mandatory and suggested rules, then assert:

```python
policy = build_effective_split_tunnel_policy(self.db, self.context)

self.assertEqual(policy.format_version, 1)
self.assertTrue(policy.enabled)
self.assertEqual(policy.mode, AppSplitTunnelMode.EXCLUDE_SELECTED)
self.assertEqual(policy.excluded_ipv4_cidrs, ("198.51.100.0/24", "203.0.113.0/24"))
self.assertRegex(policy.policy_hash, r"^sha256:[0-9a-f]{64}$")
self.assertNotIn("0.0.0.0/1", policy.excluded_ipv4_cidrs)
self.assertNotIn("128.0.0.0/1", policy.excluded_ipv4_cidrs)
```

Add tests that:

- differently ordered database rows yield the same ordered fields and hash;
- changing display-only rule casing to an equivalent normalized value does not change the hash;
- disabled global flag yields `enabled=False` and empty effective rule/CIDR lists while retaining device mode and local-network preference;
- no binding yields an empty CIDR list, not another user's filters;
- more than 16,384 collapsed CIDRs raises `SplitTunnelPolicyError("policy_too_large")`;
- a native binding response still contains `AllowedIPs = 0.0.0.0/0`;
- the existing browser/public download test still observes its current rewritten `AllowedIPs`.

- [x] **Step 2: Run policy and binding tests and verify failure**

Run:

```bash
.venv/bin/python -m unittest \
  tests.test_client_split_tunnel \
  tests.test_client_peer_binding -v
```

Expected: FAIL because policy projection and native/raw separation are absent.

- [x] **Step 3: Expose compact exclusion-network calculation**

Rename only the service boundary:

```python
def blocked_ipv4_networks_for_peer(
    db: Session,
    peer: Peer,
) -> list[ipaddress.IPv4Network]:
    networks = [
        item["network"]
        for item in _split_tunnel_network_items_for_peer(db, peer)
    ]
    return sorted(
        ipaddress.collapse_addresses(networks),
        key=lambda item: (int(item.network_address), item.prefixlen),
    )
```

Change `_apply_split_tunnel_to_peer_payload` to call the new public function. Keep `_subtract_ipv4_networks` and browser/public behavior intact.

- [x] **Step 4: Remove the legacy rewrite from the native binding path**

In `app/client_bindings.py`, remove `_apply_split_tunnel_to_peer_payload` from imports and change `_download_app_peer_configuration` to decode the raw `_extract_download_payload` result:

```python
payload = _extract_download_payload(
    response,
    default_filename=f"{peer.interface.name}-{peer.slot}.conf",
    default_content_type="text/plain; charset=utf-8",
)
content = payload.get("content")
```

Do not alter `download_peer_config` or `download_peer_config_public` in `app/services.py`.

- [x] **Step 5: Implement deterministic policy projection and hash**

Define:

```python
@dataclass(frozen=True)
class EffectiveSplitTunnelPolicy:
    format_version: int
    enabled: bool
    revision: int
    force_revision: int
    policy_hash: str
    mode: AppSplitTunnelMode
    exclude_local_networks: bool
    mandatory_excluded_packages: tuple[str, ...]
    suggested_name_fragments: tuple[str, ...]
    selected_packages: tuple[str, ...]
    excluded_ipv4_cidrs: tuple[str, ...]
    generated_at: datetime
```

Load only the authenticated device and its active `AppPeerBinding`. Sort package IDs by ASCII value, suggestions by normalized value, selected IDs by package ID, and CIDRs by numeric network address then prefix length. Hash only effective content, not `generated_at`, revision counters, or display-only values:

```python
hash_payload = {
    "format_version": 1,
    "enabled": enabled,
    "mode": mode.value,
    "exclude_local_networks": exclude_local_networks,
    "mandatory_excluded_packages": mandatory,
    "suggested_name_fragments": suggestions,
    "selected_packages": selected,
    "excluded_ipv4_cidrs": cidrs,
}
serialized = json.dumps(
    hash_payload,
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
).encode("utf-8")
policy_hash = f"sha256:{hashlib.sha256(serialized).hexdigest()}"
```

If disabled, hash empty effective lists so old clients and the new client receive no split behavior. Do not calculate the IPv4 complement.

- [x] **Step 6: Run policy, binding, and legacy-download tests**

Run:

```bash
.venv/bin/python -m unittest \
  tests.test_client_split_tunnel \
  tests.test_client_peer_binding -v
```

Then run every test module found by:

```bash
rg -l "_apply_split_tunnel_to_peer_payload|split.tunnel" tests
```

Expected: native configuration remains raw; browser/public behavior remains covered and PASS.

- [x] **Step 7: Commit policy projection**

```bash
git add app/services.py app/client_bindings.py app/client_split_tunnel.py \
  tests/test_client_split_tunnel.py tests/test_client_peer_binding.py
git add $(rg -l "_apply_split_tunnel_to_peer_payload|split.tunnel" tests)
git commit -m "Отделить политику приложения от AllowedIPs"
```

---

### Task 4: Expose Authenticated Client Policy Endpoints

**Files:**
- Modify: `app/client_schemas.py`
- Modify: `app/client_api.py`
- Modify: `app/client_split_tunnel.py`
- Create: `tests/test_client_split_tunnel_api.py`

**Interfaces:**
- Produces:
  - `GET /api/client/v1/split-tunnel/revision`
  - `GET /api/client/v1/split-tunnel/policy`
  - `PUT /api/client/v1/split-tunnel/settings`
  - `POST /api/client/v1/split-tunnel/apply-result`
- Client settings use complete replacement semantics.
- Apply-result writes one latest state row per device.

- [x] **Step 1: Write failing API authorization and contract tests**

Use the existing `TestClient` and bearer-token pattern. Assert all four routes return `401` without a token. With a token:

```python
revision = self.client.get(path, headers=self.auth_headers)
self.assertEqual(revision.status_code, 200)
self.assertEqual(revision.json(), {
    "api_version": "1",
    "request_id": revision.json()["request_id"],
    "enabled": False,
    "revision": 1,
    "force_revision": 0,
})
```

Add tests for:

- policy response contains the exact fields from `EffectiveSplitTunnelPolicy`;
- `Cache-Control: no-store` on every response;
- updating settings immediately returns the effective policy;
- another device cannot alter the current device by adding a forged `device_id` because schemas forbid extra fields;
- 513 selected packages, invalid package ID, oversized display name, malformed status, malformed hash, and future format version return `422`;
- two identical apply reports update one row and create no duplicate;
- failed and rolled-back reports create the specified audit events;
- successful apply reports do not create ordinary audit events;
- revision reads do not create audit rows or `PanelJob` rows.

- [x] **Step 2: Run API tests and verify failure**

Run:

```bash
.venv/bin/python -m unittest tests.test_client_split_tunnel_api -v
```

Expected: FAIL with route-not-found/schema import errors.

- [x] **Step 3: Add strict Pydantic schemas**

Add to `app/client_schemas.py`:

```python
class ClientSplitTunnelSelectedPackage(ClientSchema):
    package_id: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9_.]+$")
    display_name: str = Field(min_length=1, max_length=255)


class ClientSplitTunnelSettingsRequest(ClientSchema):
    mode: Literal["exclude_selected", "include_selected"]
    exclude_local_networks: bool
    selected_packages: list[ClientSplitTunnelSelectedPackage] = Field(max_length=512)


class ClientSplitTunnelRevisionResponse(ClientSchema):
    api_version: Literal["1"] = "1"
    request_id: str
    enabled: bool
    revision: int = Field(ge=1)
    force_revision: int = Field(ge=0)


class ClientSplitTunnelPolicyResponse(ClientSchema):
    api_version: Literal["1"] = "1"
    request_id: str
    format_version: Literal[1] = 1
    enabled: bool
    revision: int
    force_revision: int
    policy_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    mode: Literal["exclude_selected", "include_selected"]
    exclude_local_networks: bool
    mandatory_excluded_packages: list[str]
    suggested_name_fragments: list[str]
    selected_packages: list[str]
    excluded_ipv4_cidrs: list[str]
    generated_at: datetime


class ClientSplitTunnelApplyResultRequest(ClientSchema):
    format_version: Literal[1] = 1
    revision: int = Field(ge=1)
    force_revision: int = Field(ge=0)
    policy_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    status: Literal["applied", "failed", "rolled_back"]
    error_code: str | None = Field(default=None, max_length=120, pattern=r"^[a-z0-9_.-]+$")
    applied_at: datetime
```

Use one policy serializer function in `client_api.py`; do not hand-build four subtly different projections.

- [x] **Step 4: Add authenticated routes**

Add routes after `/bootstrap`:

```python
@router.get("/split-tunnel/revision", response_model=ClientSplitTunnelRevisionResponse)
def client_split_tunnel_revision(
    response: Response,
    context: ClientAuthContext = Depends(require_client_auth),
    db: Session = Depends(get_db),
) -> ClientSplitTunnelRevisionResponse:
    _set_no_store(response)
    enabled, revision, force_revision = load_split_tunnel_revisions(db)
    return ClientSplitTunnelRevisionResponse(
        request_id=client_request_id(),
        enabled=enabled,
        revision=revision,
        force_revision=force_revision,
    )
```

The policy route calls `build_effective_split_tunnel_policy`. The settings route converts schema items to `SplitTunnelSelectedPackage` and calls `replace_device_split_tunnel_settings`. The apply-result route calls:

```python
record_split_tunnel_apply_result(
    db,
    context,
    format_version=payload.format_version,
    revision=payload.revision,
    force_revision=payload.force_revision,
    policy_hash=payload.policy_hash,
    status=AppSplitTunnelApplyStatus(payload.status),
    error_code=payload.error_code,
    applied_at=payload.applied_at,
)
```

Map `SplitTunnelValidationError` and `SplitTunnelPolicyError` to `ClientAuthError` with stable codes `invalid_split_tunnel_settings` and `split_tunnel_policy_unavailable`.

- [x] **Step 5: Implement idempotent apply-result recording**

Lock/upsert `AppSplitTunnelApplyState` by authenticated `device_id`. Reject an apply result whose revision is greater than current server revision or whose format is unknown. Permit older results because a device can report after a later admin edit.

Write an audit row only when status is `failed` or `rolled_back`:

```python
event_type = (
    "client.split_tunnel.apply_failed"
    if status == AppSplitTunnelApplyStatus.FAILED
    else "client.split_tunnel.rollback"
)
message_ru = (
    "Не удалось применить политику split-tunnel."
    if status == AppSplitTunnelApplyStatus.FAILED
    else "Приложение восстановило предыдущую политику split-tunnel."
)
```

Deduplicate repeated failure audit by comparing the previously stored tuple `(revision, force_revision, policy_hash, status, error_code)` before writing.

- [x] **Step 6: Run API and domain tests**

Run:

```bash
.venv/bin/python -m unittest \
  tests.test_client_split_tunnel \
  tests.test_client_split_tunnel_api -v
```

Expected: PASS.

- [x] **Step 7: Commit client API**

```bash
git add app/client_schemas.py app/client_api.py app/client_split_tunnel.py \
  tests/test_client_split_tunnel_api.py
git commit -m "Добавить API политик split-tunnel"
```

---

### Task 5: Add Administrator Projection, Statistics, and APIs

**Files:**
- Modify: `app/schemas.py`
- Modify: `app/client_split_tunnel.py`
- Modify: `app/web.py`
- Create: `tests/test_admin_split_tunnel_web.py`

**Interfaces:**
- Produces `get_admin_split_tunnel_page(db, actor) -> AdminSplitTunnelPageView`.
- Produces administrator endpoints:
  - `GET /api/admin/app-split-tunnel`
  - `PUT /api/admin/app-split-tunnel/settings`
  - `POST /api/admin/app-split-tunnel/promote`
  - `POST /api/admin/app-split-tunnel/force-sync`
- Statistics count current active selections only; selection events remain history.

- [x] **Step 1: Write failing administrator authorization and statistics tests**

Assert anonymous requests return `401`; USER, VIP, and BUSINESS return `403`; ADMIN succeeds. Arrange two users and three devices:

```python
self.add_selection(self.device_a, "com.example.app", "Example")
self.add_selection(self.device_b, "com.example.app", "Example")
self.add_selection(self.device_c, "com.other.app", "Other")
```

Assert `com.example.app` reports two unique users only when devices belong to different users, exact device count, and maximum `updated_at`. Remove one active row and add a `selected=False` history event; assert the active count drops while history count remains.

Also assert:

- update settings rejects duplicate normalized rules and invalid values;
- promotion requires exact package ID and confirmation string `ДОБАВИТЬ`;
- force sync requires confirmation string `СИНХРОНИЗИРОВАТЬ`;
- all mutation APIs set `Cache-Control: no-store`;
- audit details contain counts/revisions but never full device inventory or WireGuard data.

- [x] **Step 2: Run admin API tests and verify failure**

Run:

```bash
.venv/bin/python -m unittest tests.test_admin_split_tunnel_web -v
```

Expected: FAIL because admin schemas/routes do not exist.

- [x] **Step 3: Add administrator schemas**

Add strict models in `app/schemas.py`:

```python
class AdminSplitTunnelSettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool
    mandatory_packages: list[str] = Field(max_length=512)
    suggested_name_fragments: list[str] = Field(max_length=128)


class AdminSplitTunnelPromotionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    package_id: str = Field(min_length=1, max_length=255)
    display_name: str = Field(min_length=1, max_length=255)
    confirmation: Literal["ДОБАВИТЬ"]


class AdminSplitTunnelForceSyncRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmation: Literal["СИНХРОНИЗИРОВАТЬ"]
```

Define view models for rules, active statistics, apply state, and the complete page. Use ISO datetimes and integer counters; do not return selection-event rows to the browser in stage one.

- [x] **Step 4: Implement active statistics and admin projection**

Build statistics with grouped SQL over `AppSplitTunnelSelection` joined to `AppDevice`, counting:

```python
func.count(func.distinct(AppDevice.user_id)).label("user_count")
func.count(func.distinct(AppSplitTunnelSelection.device_id)).label("device_count")
func.max(AppSplitTunnelSelection.updated_at).label("last_selected_at")
```

Choose the display name from the most recently updated active row using a deterministic secondary order by row ID. Load apply states with device name, platform, app version, revision, force revision, status, error code, and applied time.

- [x] **Step 5: Add administrator routes**

Use the same administrator dependency as the programs settings APIs. Routes call only `client_split_tunnel.py` domain functions:

```python
@router.get("/api/admin/app-split-tunnel", response_model=AdminSplitTunnelPageView)
def api_admin_split_tunnel(...):
    return get_admin_split_tunnel_page(db, current_user)
```

The `PUT` route replaces global settings in one transaction. Promotion and force routes enforce literal confirmation through Pydantic. Set `Cache-Control: no-store` through a shared response helper.

- [x] **Step 6: Run administrator and client tests**

Run:

```bash
.venv/bin/python -m unittest \
  tests.test_admin_split_tunnel_web \
  tests.test_client_split_tunnel \
  tests.test_client_split_tunnel_api -v
```

Expected: PASS.

- [x] **Step 7: Commit administrator APIs**

```bash
git add app/schemas.py app/client_split_tunnel.py app/web.py \
  tests/test_admin_split_tunnel_web.py
git commit -m "Добавить администрирование split-tunnel"
```

---

### Task 6: Build the Administrator Settings Screen

**Files:**
- Modify: `app/web.py`
- Modify: `app/templates/admin.html`
- Create: `app/templates/admin_split_tunnel.html`
- Create: `app/static/split-tunnel-admin.js`
- Create: `app/static/split-tunnel-admin.css`
- Modify: `tests/test_admin_split_tunnel_web.py`
- Create: `tests/frontend/split_tunnel_admin.test.js`

**Interfaces:**
- Consumes JSON from `GET /api/admin/app-split-tunnel`.
- Produces settings navigation item `Split-tunnel`.
- Produces selectors `[data-split-tunnel-admin]`, `[data-mandatory-list]`, `[data-suggestion-list]`, `[data-split-save]`, and `[data-force-sync]`.

- [x] **Step 1: Write failing page-rendering and frontend tests**

In Python, assert:

```python
response = self.client.get("/admin?tab=settings&settings_view=split_tunnel")
self.assertEqual(response.status_code, 200)
self.assertIn("Split-tunnel", response.text)
self.assertIn("data-split-tunnel-admin", response.text)
self.assertIn("/static/split-tunnel-admin.css", response.text)
self.assertIn("/static/split-tunnel-admin.js", response.text)
self.assertNotIn("PrivateKey", response.text)
```

In Node tests, use a minimal fake DOM/fetch harness and assert:

- adding/removing rows serializes trimmed values;
- save sends one `PUT` with the complete lists;
- promotion sends confirmation `ДОБАВИТЬ`;
- force sync performs a first confirmation dialog and sends `СИНХРОНИЗИРОВАТЬ`;
- failed fetch keeps form values and shows a visible error;
- repeated click while a request is pending sends one request.

- [x] **Step 2: Run frontend and page tests and verify failure**

Run:

```bash
.venv/bin/python -m unittest tests.test_admin_split_tunnel_web -v
node --test tests/frontend/split_tunnel_admin.test.js
```

Expected: FAIL because page assets and markup do not exist.

- [x] **Step 3: Register the settings view and conditional assets**

Add `"split_tunnel"` to `active_settings_view` in `admin_home`. Populate:

```python
"split_tunnel_page": (
    get_admin_split_tunnel_page(db, current_user)
    if active_settings_view == "split_tunnel"
    else None
),
```

Add a settings navigation link after `VPN-клиенты`. Include CSS in the template head and JS before the closing body only when the view is active, with a new cache-busting version string.

- [x] **Step 4: Create focused accessible markup**

`admin_split_tunnel.html` contains:

- one global enable switch;
- one editable mandatory package-ID list;
- one editable suggested-name-fragment list;
- one active-selection statistics table;
- one device apply-state table;
- one primary `Сохранить` command;
- one separate destructive-looking `Принудительная синхронизация` command with explanatory text and confirmation.

Render existing server data as escaped text or `tojson` inside:

```html
<script type="application/json" data-split-tunnel-state>
  {{ split_tunnel_page.model_dump(mode="json") | tojson }}
</script>
```

Do not nest cards inside cards. Keep sections as unframed bands inside the existing admin panel and use 8px-or-less radii.

- [x] **Step 5: Implement list editing and API state updates**

Export pure helpers for Node tests:

```javascript
export function normalizeRows(values) {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

export function settingsPayload(root) {
  return {
    enabled: root.querySelector("[data-enabled]").checked,
    mandatory_packages: normalizeRows(readRows(root, "[data-mandatory-row]")),
    suggested_name_fragments: normalizeRows(readRows(root, "[data-suggestion-row]")),
  };
}
```

Use `textContent`, not `innerHTML`, for server values. Disable only the command currently in flight. After success, redraw counts/revisions from the API response; after failure, preserve unsaved input.

- [x] **Step 6: Run frontend and page tests**

Run:

```bash
node --test tests/frontend/split_tunnel_admin.test.js
.venv/bin/python -m unittest tests.test_admin_split_tunnel_web -v
```

Expected: PASS.

- [x] **Step 7: Commit the administrator screen**

```bash
git add app/web.py app/templates/admin.html app/templates/admin_split_tunnel.html \
  app/static/split-tunnel-admin.js app/static/split-tunnel-admin.css \
  tests/test_admin_split_tunnel_web.py tests/frontend/split_tunnel_admin.test.js
git commit -m "Добавить экран настроек split-tunnel"
```

---

### Task 7: Document the Contract and Run the Panel Release Gate

**Files:**
- Modify: `docs/client_api.md`
- Modify: any files changed by formatting only when the repository's formatter requires it
- Test: all panel tests

**Interfaces:**
- Documents the exact four client routes and four admin routes from Tasks 4 and 5.
- Documents `format_version=1`, normal/force revision semantics, limits, no-store behavior, and native raw `AllowedIPs`.

- [x] **Step 1: Add contract documentation**

Add a `Split-tunnel policy` section to `docs/client_api.md` containing:

```text
GET  /api/client/v1/split-tunnel/revision
GET  /api/client/v1/split-tunnel/policy
PUT  /api/client/v1/split-tunnel/settings
POST /api/client/v1/split-tunnel/apply-result
```

Document:

- complete replacement semantics for selected packages;
- ordinary revision versus force revision;
- immediate response to user settings;
- one-day full sync and five-minute cheap poll expected from clients;
- `format_version=1`;
- compact exclusion CIDRs, never an `AllowedIPs` complement;
- full inventory and local networks never leave the device;
- disabled flag returns no effective rules;
- old clients continue to receive ordinary configurations;
- native binding configuration remains `0.0.0.0/0`;
- failed policy fetch must not disconnect or block a client using a cached policy.

- [ ] **Step 2: Run formatting and static checks**

Run:

```bash
.venv/bin/ruff check app tests
.venv/bin/ruff format --check app tests
git diff --check
```

Expected: all commands exit `0`.

- [x] **Step 3: Run focused release tests**

Run:

```bash
.venv/bin/python -m unittest \
  tests.test_client_split_tunnel \
  tests.test_client_split_tunnel_api \
  tests.test_admin_split_tunnel_web \
  tests.test_client_peer_binding -v
node --test tests/frontend/split_tunnel_admin.test.js
```

Expected: PASS.

- [x] **Step 4: Run the full panel suite**

Run the repository's canonical suite from `pyproject.toml`/README. At minimum:

```bash
.venv/bin/python -m unittest discover -s tests -v
node --test tests/frontend/*.test.js
```

Expected: all tests PASS. If the complete suite exceeds the local timeout, run it in one long-lived terminal session and wait for its final exit code rather than starting duplicate suites.

- [ ] **Step 5: Verify migration on both supported dialect assumptions**

Run local Alembic upgrade on the configured development database and run the SQLite migration tests:

```bash
.venv/bin/alembic upgrade head
.venv/bin/python -m unittest tests.test_client_split_tunnel -v
```

Expected: PASS. Before deployment, production PostgreSQL preflight must run the migration inside the repository's deployment dry-run mechanism; do not manually edit production tables.

- [x] **Step 6: Commit documentation and final panel verification**

```bash
git add docs/client_api.md
git commit -m "Документировать API split-tunnel"
```

Record the final test commands and results in the task handoff. Do not push or deploy.
