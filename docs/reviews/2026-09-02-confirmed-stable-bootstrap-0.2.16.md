# Task12: локальная контрольная точка, не завершение приёмки

Ветка `codex/confirmed-stable-0.2.16`, исходная точка
`d7267ae2153b9dc29a89f2e4ca174599608a0768`. Версия остаётся 0.2.16,
changelog — черновик. Shipping layout остаётся latest-only; пользовательский
переключатель Stable в maintenance-релиз не добавлен.

## Реализовано и проверено локально

- Подписанный slot выбирается production dispatcher только в idle-состоянии;
  engine определяет свою идентичность по kernel executable и подписанным байтам.
  Защищённый маркер, ownership, stale Stop и private operation fences сохранены.
- CommonHost один раз связывает все клоны native transport с установленным
  target текущего incarnation. До привязки Start запрещён; выполняющаяся
  pre-auth очистка не может пересечь привязку. Installed-layout readiness
  отделена от выбранного engine. Проверен реальный Unix socket→dispatcher→child.
- При однозначном отказе из-за истёкшего access разрешён ограниченный refresh
  той же текущей области авторизации. Frozen operation/body/scope не меняются.
  Потерянный rotating refresh остаётся pending и не повторяется; неизвестный
  reconcile не получает разрешение на refresh от последующего 401. Проверены
  restart после известного отказа, accepted retry, unknown dispatch и logout.
- Реальный CommonHost/private child сохраняет installed target при появлении
  pending Stable, до перезапуска процесса.

Команда целевых Rust-проверок:

```sh
cargo test --locked --offline -p nelomai-client-container -p nelomai-contracts -p nelomai-unix-service -p nelomai-windows-service --all-targets
cargo clippy --locked --offline -p nelomai-client-container -p nelomai-contracts -p nelomai-unix-service -p nelomai-windows-service --all-targets -- -D warnings
cargo fmt --all -- --check
```

Первый полный запуск целевой группы: 344 теста, 0 failed/ignored. Это macOS
source-check: Windows-only тесты не превращаются в Windows execution evidence.

## Реальный локальный panel/PG producer

`scripts/run-real-panel-acceptance.py` использует настоящий AuthBroker,
SwitchCoordinator, HTTP ClientApi, fsynced protected test storage, отдельные
процессы и независимые запросы PostgreSQL. Panel — ранее зафиксированный Git
archive `89ef85dc0acc3de409507ca70304c2fe00a1447e`, новая isolated DB
`runtime016_task12_matrix`, миграция head `20260904_0057`. Параметр `--panel-sha`
сам по себе не доказывает происхождение: используется известная подготовленная
архивная копия. `results.json` фиксирует HEAD, diff hash и хеши исходников driver.

```sh
/tmp/nelomai-panel-ci-parity.PyRQE1/venv/bin/python scripts/run-real-panel-acceptance.py \
  --panel-root /tmp/nelomai-runtime-panel-baseline.UjC4TL/panel \
  --panel-sha 89ef85dc0acc3de409507ca70304c2fe00a1447e \
  --database-url postgresql+psycopg://task12_test@127.0.0.1:56589/runtime016_task12_matrix \
  --panel-url http://127.0.0.1:56590 \
  --work /tmp/nelomai-runtime-panel-baseline.UjC4TL/matrix-v13
```

matrix-v13 завершён exit0: семь фаз аварийного выхода; lost committed
reconcile/resume с теми же operation/device/session; delayed cleanup с реальными
jobs/leases и отрицательным/положительным внешним ACK через штатный recovery
worker; истёкший access до reconcile и во время accepted cleanup; отказ при
истёкшем refresh; четыре logout race (refresh/resume × clean/delayed), lost logout
ACK, новый login/family и неизменность новой connected lease после старого replay.
Обычный refresh создаёт один revoked исторический session и один active successor
в той же family/device; runtime-resume replay сохраняет session UUID.

Обратный запуск с `--source-slot stable` и новым work
`/tmp/nelomai-runtime-panel-baseline.UjC4TL/matrix-reverse-v1` также завершён exit0
на том же наборе: Requested сохраняет старую Stable (открытый atomic-intent gap),
шесть следующих фаз завершают Latest/gen2. Это две стороны синтетического
broker/coordinator fixture, не две собранные релизные программы.

Только внешние native/agent эффекты адаптированы: native child действительно
владеет lock и подтверждает его захват; agent ACK проходит реальный worker.
macOS rename-interposer завершает настоящий broker после durable journal rename,
проверяется exit91 и точная фаза; journal не переписывается harness-ом.
Синтетический manifest driver — fixture, не реальный packaged runtime artifact.
Это не доказательство физического туннеля или immutable release-candidate.

## Открытые вопросы спецификации и остаток

1. **Atomic intent gap.** `SwitchCoordinator::request_locked` сначала вызывает
   `begin_requested`, затем отдельно `set_pending_selection`. Сбой между ними
   оставляет Requested и старую preference. Реальная проверка восстанавливает
   старый Latest, сохраняет original operation как superseded и создаёт successor
   с одним generation advance. Это честное наблюдение, но **не соответствие**
   требованию design.md §транзакции, step1: атомарно сохранить pending slot и
   Requested. Первоначальное толкование как допустимого поведения отозвано.
2. **Apply before full restart.** `recover_locked` вызывает resume, local
   admission, `finish_selection` и Complete в ещё текущем owner; UI restart идёт
   отдельным `RuntimeRestart`/`prepare_runtime_restart`→relaunch путём.
   Проверить против design.md требования успешного Apply только после полного
   перезапуска. Task10 reverse-after-Complete и неизменный active target не
   разрешают автоматически это противоречие. Нужна отдельная оценка root.
3. Истёкший refresh пока проверен как безопасный RecoveryRequired/no-admission,
   **не** как завершённая controlled reauthentication. Полный обычный
   logout/cleanup→password-login recovery после этого отказа остаётся непроверен.
4. Полное произведение всех crash/lost-reply фаз с delayed cleanup ещё не
   выполнено. Отдельные delayed/expiry/logout случаи не заменяют его.
5. Точный packaged UI/business HTTP/native tunnel candidate, release trust,
   Windows/Android/Apple hardware и updater install acceptance остаются UNRUN.
   `require-candidate-acceptance.py` безусловно возвращает nonzero: JSON receipt,
   environment approval и локальная матрица не открывают публикацию.

Это checkpoint для scoped/whole-branch review. Root владеет независимыми review
passes. Дорогие clean-source build_only, полные workspace/Android проверки и
финальная приёмка выполняются после разрешения вопросов исходников. Никаких
push, CI, deploy, release, реальных ключей, установки продукта или production DB.

## Task12 fix1: отдельный checkpoint после scoped review

Исторические наблюдения выше сохранены; два пункта исходников исправлены в
ограниченной волне от `d7b06c1754ad8270c7c4e87dfe5f7e40fa426658`, ожидают rereview.
Единственный durable Requested journal теперь является авторитетным pending
intent; preference — восстанавливаемая проекция, которую новый verified startup
принимает без live-retarget текущего CommonHost. Terminal и чужой container
journal не переопределяют новую selection.

Новый Resume ticket разрешён лишь для неизменного verified installed target
координатора; проверка под существующим issuance lock. Уже сохранённый exact
ticket/evidence replay не блокируется. Prepared UUID не означает dispatch.
Отмена до dispatch использует Cancel; неизвестный Apply сначала повторяется
без изменения, затем выполняется отдельный reverse/supersede.

Настоящий CommonHost/private-child тест выявил ещё существовавший отказ первого
cross-slot admission: новый namespace корректно создаётся cleanup_only, а обычный
bind не должен его снимать. Теперь только control cleanup после единственного
exact retained-source match завершает пустой selected namespace и привязывает
новый scope. Проверены отказ для foreign scope/nonempty/changed source и retry
после реального отказа записи старого source; ordinary bind не ослаблен.

Focused GREEN: selection16 + switch10 + transition_auth41 + runtime_state8 =75.
Новый CommonHost до restart сохраняет generation7/Apply0, новый Stable host
достигает generation8/Apply1, повторный Ready не выдаёт второй Apply. Реальные
panel/PG smoke в `/tmp/nelomai-task12-fix1-smoke.wEMcuQ`: Requested exit91 теперь
сохраняет запрошенную Stable и original operation без supersede; clean switch
остаётся AuthResuming/server generation1 до нового процесса; Complete exit91
в новом процессе и ещё один replay сохраняют единственный generation2/session.
Оба восстановленных access проверены настоящим bootstrap.

Producer остаётся instrumented native-effect adapter, не packaged/private-peer
доказательством. Full matrix не перезапускалась в fix1; controlled reauth,
delayed cross-product, clean-source full gates и физическая/candidate приёмка
остаются OPEN/UNRUN. Проверка exact candidate по-прежнему nonzero. Полный fix1
отчёт и точный freeze SHA находятся в рабочем `task-12-fix1-report.md` у root.
