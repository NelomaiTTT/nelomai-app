# Windows 0.4.0: доведение hot standby до аппаратного теста

> **For agentic workers:** Use `superpowers:executing-plans`, inline, one task at a time. Один основной интегратор; не запускать параллельную разработку взаимозависимых контрактов. Этот план заменяет порядок исполнения старого плана, но не отменяет требования безопасности и исторические доказательства.

**Goal:** Завершить Windows carrier/hot-standby расширение для 0.4.0: проверить программный жизненный цикл и подготовить протокол аппаратной приёмки. Версии в коде и параметры сборки/подписи меняются только после отдельного согласования.

## Решение пользователя от 2026-10-07 и контрольная точка переноса

- Разработка перенесена в `Future/windows-hot-standby-0.4.0`, отдельный worktree `.worktrees/windows-hot-standby-0.4.0`. Исходный код и вся его история сохранены от `6f005ddb0bd60629b77d3913f0b7b10e7cc76b20`; последующий коммит переноса меняет только этот план.
- `main` при переносе не сбрасывается, не переписывается и не переименовывается. Стабильную линию от точного коммита опубликованного `v0.3.2` готовит другой агент. Не переносить в неё расширение и не выполнять force-push.
- Самостоятельная функция killswitch перенесена на 0.5.0. Не включать её разработку в эту работу. Уже необходимые WFP/ownership/endpoint guards самого hot standby сохраняются.
- Код ещё маркирован 0.3.3. Это сохранённое состояние разработки, а не согласованная версия следующего кандидата. Версии, release/checks workflows и новые параметры подписанной сборки согласуются отдельно; прежнее поручение запускать кандидат 0.3.3 из `main` больше не применяется.
- Восемь файлов последнего среза закоммичены в `6f005dd`: partial/terminal key reads, исходные владельцы при cleanup и исправление селектора Running ACK в native fixture. Целевые проверки и host/MSVC check/strict Clippy прошли. Windows release service и test EXE собраны за 304.39 с; native GREEN этому SHA пока не приписывается. Начатый до переноса CI `37683714540` проверяет именно этот SHA.
- Последний исполненный VM primary на `52d3a28` дошёл до Running и Closing/11, но не до protected completion/repeat Start. На этом SHA CI: шесть основных jobs и 15/19 native сценариев PASS. Открыты полный lifecycle, RestoreNetwork deadline и остаточная MIB-строка после SDK Close. Этап 2 и этапы 3–6 остаются открытыми; аппаратный failover не проверен.
- Чужие незакоммиченные `member_carrier_recovery.rs`, `member_carrier_recovery_tests.rs` и dirty vendor остались в прежнем checkout и не включены в новую ветку. Recovery sidecar отдельно не принят.
- Рабочие записи и локальные материалы сохранены отдельно от Git с пофайловыми хешами в `/Users/altzxd/Documents/NelomaiWork/windows-hot-standby-0.4.0-20261007`: проверены 4871 файл, 812548362 байта; список в `preservation-manifest.json`. Активные рабочие записи скопированы в новый worktree. Воспроизводимые Python-зависимости и чужие изменения в архив не включены. Исторические журналы читать адресно. Автоматизация остаётся приостановленной.

**Architecture:** Общий серверный алгоритм выдаёт сессию, адрес и независимые пиры. Только Windows разделяет владельца VPN-IP/DNS — carrier C — и addressless WG/AWG A/B. Используем уже написанные компоненты; приоритет — их соединение в реальном Start/Switch/Stop, а не новые уровни абстракции.

**Tech Stack:** Rust, Windows-service, Wintun/WireGuardNT/AWG, IP Helper/WFP, protected records, Tauri/NSIS, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-29-windows-stable-vip-carrier-design.md`.

## Историческая исходная точка на 2026-10-03 и граница результата

- База — опубликованный WIP `afe94f2`, а не установленный старый `b0d796a`. Снимок сделан по просьбе пользователя без свежей проверки; готовность и зелёный CI ему не приписываются.
- `NativePairFactory::prepare` в `crates/windows-service/src/windows/member_pair.rs` пока создаёт прежний `WindowsPairIo`. Написанные carrier-компоненты сами по себе этого не исправляют.
- `member_carrier_registry_metadata.rs` содержит протокол наблюдения и тесты, но его native supplier и подключение к потребителю требуют завершения. Наблюдение metadata не является разрешением на удаление ключа.
- Большой объём реализации уже существует. Не переписывать её заново и не повторять все старые эксперименты. История — в старом плане и `WINDOWS-SHARED-VIP-RESEARCH-2026-09-29.md`; каждый использованный результат сопоставлять с точной проверяемой гипотезой.
- «Готов к аппаратному тесту» не означает «failover работает на железе». Это точный подписанный пакет с интегрированным кодом, пройденными автоматическими воротами и явно перечисленными непроверенными нативными свойствами.

## Global Constraints

- Только собственные `Future/windows-hot-standby-0.4.0` и `.worktrees/windows-hot-standby-0.4.0`; старый checkout и `main` не изменять. Чужие изменения, оба dirty vendor, auth, journals, backups и evidence сохраняются. Никаких новых серверных моделей, ручных production-изменений, релиза/deploy или обхода ворот.
- Ordinary, Android, macOS/Linux и IPC/auth-контракты не менять ради Windows pair.
- Ownership, original handles/ACK, generations, WFP, endpoint bypass и fail-closed обязательны. Не заменять неизвестность успехом, close handle — отсутствием ресурса, равные данные — исходным владельцем.
- Состояние пользовательского Windows-ПК не является воротами редактирования, unit/contract tests, native Windows CI или упаковки. В этом плане не чинить Windows, не очищать очередь обновлений, не менять драйверы/системные файлы и не перезагружать ПК.
- Разработка не отменяет нативные security-gates из spec: код пути можно интегрировать и собрать независимо от ПК; разрешать его реальные эффекты можно только при выполненных условиях допуска. Не выдавать навсегда выключенный новый путь за готовую функцию.
- Если обязательная нативная гипотеза ещё не подтверждена, выделить точный ограниченный gate для подходящей изолированной Windows-среды или начала аппаратной сессии. Пока он открыт, фиксировать «пакет готов, активация ограничена», а не полный GO. Не добавлять флаг обхода проверки.
- Подписание кандидата отложено до отдельного согласования версии 0.4.0 и сборочных параметров. Не менять версии/workflows и не запускать прежнюю комбинацию `ref=main`, `version=0.3.3`. Сохранить требования exact source SHA, обязательных gates, отсутствия publish/tag/release и недублирования успешной сборки.

## Review Focus

1. Потерянный ACK, ошибка записи или panic между эффектом и публикацией: исходный владелец остаётся доступен для точной очистки — задача 2.
2. Повторный Start и смена generation при живом process-level DLL anchor: старая сессия не удерживает новую и не получает её полномочия — задачи 2–3.
3. Ошибка резерва или переключения: нет раннего Healthy, двойного DATA allow и скрытого ordinary fallback — задача 3.
4. SDK удалил ключ, оставил пустой ключ либо чужой процесс заменил его: различимые исходы, без усыновления и ложного Stopped — задача 2.
5. NEW installer helper и OLD cleanup, legacy/неизвестный journal: точная роль и происхождение, никакого Start из cleanup-only — задача 4.

## Порядок работы

Задачи 1 → 2 → 3 → 4 → 5 → 6 последовательны. Windows-host readiness — отдельная линия H, не зависимость задач 1–6. Нативное подтверждение свойств продукта — не ремонт пользовательского ПК: его открытые пункты учитываются отдельно от software-проверок.

- Один интегратор владеет factory, Startup, Pair и terminal-контрактами. Субагент допустим только для независимого кода с заранее зафиксированным входом/выходом; не отдавать одновременно producer и consumer разным исполнителям.
- Каждый рабочий цикл: воспроизведение конкретного разрыва → минимальная правка → целевой тест → inline review → коммит. Исправления review также проходят целевые тесты. Пушить законченные этапы, не копить ещё сутки локальный WIP.
- Нельзя объявлять задачу закрытой по тестам изолированного helper, если его production caller отсутствует. Новому helper нужен вызывающий код в том же этапе.
- Полный workspace — на стабильном объединённом срезе и перед кандидатом, не после каждой строки. После локального изменения повторять затронутые тесты; полный прогон повторять при изменении общих контрактов или финального SHA.
- До нового диагностического опыта записать: какую неизвестность он решает, какое решение изменит и какой критерий окончания. Если он не приближает один из выходов ниже — в отдельный backlog, не в критический путь.
- После двух неудачных попыток соединить один контракт остановить расширение модели: зафиксировать конкретный production call, ожидаемое право/владельца и минимальный failing test. Не заменять проблему серией новых обёрток.
- Отчёт после этапа: рабочий сценарий, оставшийся разрыв, commit, проверка и следующий выход. Не проценты, количество файлов или тестов как суррогат готовности.

## Задача 1. Стабильная база и один исполняемый маршрут

**Files:** `crates/windows-service/src/windows/member_pair.rs`, `member_carrier_startup.rs`, `member_carrier_assembly.rs`, `member_carrier_registry_metadata.rs` и соответствующие `*_tests.rs`; этот план.

**Interfaces:** сохранить `PairFactory::prepare(runtime, command, now)` и `PairFactory::recover(runtime)` как внешнюю границу; использовать существующие `NativeStartupRoot::from_claim_into` и `into_pair_retained_into`. Изменения внутренних сигнатур вносить вместе с их потребителями.

- [x] Один раз снять воспроизводимый baseline: fmt, service tests, strict host Clippy; отдельно native Windows compile/test. Зафиксировать реальные ошибки, не старые счётчики PASS. `6a848f7`; native baseline `fe1dcd5`/CI37070103148, включая query-only metadata denial. Текущий SHA требует отдельного свежего CI.
- [x] Составить короткую таблицу реального маршрута: factory → retained Startup → C → primary → reserve → switch → Stop → terminal retirement. Для каждого ребра — producer, consumer, владелец при Err. Таблица в `.superpowers/sdd/2026-10-03-windows-candidate-completion/progress.md`, интеграция `3e64d40`.
- [x] Добавить `carrier_factory_selects_new_path_for_supported_pair`: production NativePairFactory/selector и carrier composition реально исполнены в native SYSTEM `cold`, f268513/checks37262990273/job111613903261: retained Starting → защищённый Stop → новая session тем же factory → Stop. Подмена только внешних подписанных/private OS inputs. Это закрывает selection/до-DLL маршрут; primary SDK/PIN/repeat и partial cleanup остаются выходами задачи 2.
- [x] Устранить ошибки текущего WIP, включая незавершённый metadata supplier/его использование; не глушить warnings широкими allow. Factory подключён `3e64d40`, bounded native metadata supplier и original-key consumer `fe1dcd5`. Это НЕ issuer удаления surviving key.
- [x] Commit проверенного baseline. Конкретные открытые разрывы: surviving-key disposition; module-only/before-C terminal release; partial cold preparation до Pair; recovery/installer acceptance; actual native factory execution. Типовой selector-test не заменяет фактическое исполнение, предыдущий checkbox открыт.

## Задача 2. Один primary: полный Start → Stop → Start

**Files:** `crates/windows-service/src/windows/member_pair.rs`, `member_carrier_startup.rs`, `member_carrier_assembly.rs`, `member_carrier_ready.rs`, `member_carrier_pair_io.rs`, `member_carrier_keys.rs`, `member_carrier_registry_metadata.rs`, `member_carrier_module_terminal_read.rs`, `member_carrier_terminal_graph.rs`, `member_carrier_terminal_release.rs`; существующие соседние тесты. Новый сквозной тест: `crates/windows-service/src/windows/member_carrier_factory_tests.rs`, подключить в модуль factory.

**Interfaces:** реальный `PairFactory::prepare` возвращает существующий `SessionControl` с carrier-backed native/store, а не тестовую параллельную реализацию. Сохранить caller-retained передачу Startup→Pair и исходные terminal receipts. DLL process anchor не владеет session KeyLock/Pair/DATA.

- [x] RED: `carrier_factory_primary_start_stop_repeat_uses_fresh_session` — actual actor/SessionControl/carrier coordinator `3e64d40`; external IO/store/native-finalizer ACK doubles. Один C и новая session, не нативное доказательство SDK release.
- [ ] RED: table-driven `carrier_factory_partial_start_retains_cleanup_owner` — Starting/Fresh/C/member/Running publication покрыты `3e64d40`; до DLL и load без C не объявлены закрытыми. Ошибка/потеря ACK не теряет handle, не публикует успех и не удаляет чужое.
- [ ] Соединить resident module pin, actual loader ACK и удержание владельцев до fallible публикации. PIN подтверждает lifetime кода, но не rundown ресурсов; не требовать выгрузки pinned DLL при каждом Stop.
- [ ] Закрыть конкретный terminal key path: SDK-deleted original key + подтверждённая parent-relative absence + close ACK; оставшийся созданный ключ требует отдельного доказанного exact-owned disposition. Недостаток прав/SACL, подмена или неоднозначность остаются Pending, не разрешают recursive deletion. Штатный успешный путь обязан действительно завершаться, не вечно Pending по конструкции.
- [ ] Провести очистку всех частичных состояний и normal Stop через тех же владельцев; withdraw/readback permits до освобождения sockets, восстановление rows/DNS, A/C cleanup, затем records/tombstone. Повторный Stop идемпотентен.
- [ ] GREEN целевые startup/keys/module/terminal/factory tests и strict native compile. Inline review и commit.

**Выход:** замкнутый primary lifecycle через production entry. Это программная проверка, не заявление о трафике реального ПК. Без этого выхода не переходить к reserve и не заниматься новой сетевой диагностикой.

## Задача 3. Reserve и переключение на том же carrier

**Files:** `crates/windows-service/src/member_carrier_pair.rs`, `member_carrier_control.rs`, `member_carrier_pair_tests.rs`; `src/windows/member_carrier_pair_io.rs`, `member_carrier_member_controller.rs`, `member_carrier_control.rs`, `member_carrier_guard.rs`, `member_carrier_guard_attestor.rs` и соответствующие тесты; factory integration tests из задачи 2.

**Interfaces:** существующий pair/session command protocol; исходная identity C сохраняется, member generations меняются через действующие receipts/rebind. Серверный API не меняется.

- [ ] RED: `carrier_factory_attach_switch_replace_preserves_carrier` — Start A, attach B, switch A→B→A, replace member, Stop. Один VIP/C, отдельные A/B, generations 1→2→3, stale receipt отвергнут.
- [ ] RED: `carrier_factory_switch_failure_never_grants_two_data_paths` — fault injection на withdraw, route, readback, permit и ACK; отсутствие раннего Healthy/role publish и ordinary fallback.
- [ ] Подключить четыре слоя WFP, active DATA против standby exact probe, независимые source C и egress A/B. Сохранить raw/fragment/transit/protocol negatives и lifetime static base/dynamic allows.
- [ ] Подключить routes/DNS/probes к фактическому coordinator: source C, egress member; DNS baseline принадлежит паре; смена роли не пересоздаёт C. Unsupported family отклоняется до эффектов, IPv6 не теряется молча.
- [ ] GREEN сценарии для WG и AWG rendering, primary-first/reserve failure, split/full, IPv4/IPv6 contract, close/repeat. Inline review и commit.

**Выход:** полный программный сценарий пары и fail-closed переключение. Моки не доказывают два handshake, доставку пакетов, resolver или бесшовность TCP.

## Задача 4. Recovery, отмена и штатное обновление

**Files:** `crates/windows-service/src/windows/member_carrier_recovery.rs`, `member_carrier_recovery_guard.rs`, `member_session.rs`, `member_pair.rs`, соответствующие recovery/session tests; `src-tauri/windows/hooks.nsh` и существующие обработчики installer cleanup, вызываемые этим hook.

**Interfaces:** `PairFactory::recover(runtime)`, `NativePairFactory::from_installer_cleanup`, прежний installer command/exit protocol. Cleanup-only роль не получает prepare/Start.

- [ ] RED: `carrier_factory_recovery_never_resumes_from_journal` — interrupted Start/Switch/Stop, lost ACK, stale boot, foreign/reused index, unknown record, legacy cleanup-only. Никакого усыновления по имени или удаления journal ради успеха.
- [ ] RED: `carrier_factory_cancel_then_stop_retires_exact_session` — EOF/cancel во время старта, повторный Stop, отложенный server Stop; старые IPC/auth гонки не возвращаются.
- [ ] Завершить реальные cleanup consumers, release original roots и protected completion после подтверждения, а не по одному Stopped snapshot.
- [ ] Проверить NEW staged helper→OLD installed cleanup: подписанные bytes/роль/ancestry/held owner; отказ при замене/неверном engine; temporary helper не получает native authority. Не использовать user-PC installer как средство разработки этого протокола.
- [ ] GREEN service/updater и затронутые installer-script tests; ordinary/core regressions. Inline review и commit.

**Выход:** пакет можно передавать на штатный upgrade-тест без заведомо незавершённого recovery/installer пути.

## Задача 5. Финальный интеграционный gate на неизменном SHA

**Files:** затронутые production/test files; `.github/workflows/checks.yml` только если отсутствует необходимая native проверка. Не переделывать CI без причины.

- [ ] Inline review полного изменения относительно последнего рабочего product baseline, а не только последнего маленького коммита: достижимость нового factory, отсутствие необоснованного dead code, ownership на всех Err, WFP order, cleanup, ordinary/installer regressions.
- [ ] Исправить найденное отдельными целевыми RED→GREEN циклами. Не считать «проверено» по отчёту автора компонента.
- [ ] На стабильном состоянии выполнить `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --locked`; штатные npm/scripts проверки согласно workflows. Ожидание: exit0, без новых необъяснённых ignored/skipped.
- [ ] Push exact source; получить успешный GitHub checks, включая native Windows `cargo test -p nelomai-windows-service` и updater. На Windows выполнить strict Clippy затронутого native crate; cross-compile с Mac не подменяет native lane.
- [ ] Свести таблицу native gates: уже доказано / автоматизировано / требует аппаратной сессии, с источником evidence. Особо: resident pin/repeat-start, exact registry disposition, integrated authorization/re-auth, реальный resolver/traffic. Синтетический тест не закрывает аппаратную строку.
- [ ] Убедиться, что новый путь достижим при удовлетворённом preflight, а плохая среда получает конкретный отказ до эффектов. Нельзя считать выполненным постоянный `factory disabled` или безусловный Pending штатного пути.

**Выход:** один SHA с завершённой программной интеграцией и зелёными автоматическими проверками; отдельный список нативных ограничений без скрытых обещаний.

## Задача 6. GitHub-кандидат и передача на аппаратный тест

**Files:** `.github/workflows/release.yml` — использовать, не менять ради зелёного результата; `/Users/altzxd/Documents/Panel/docs/verify-desktop-candidate-033.py` — сначала проверить фактическое расположение и прочитать полностью; отдельный private runroot и checkpoint.

- [ ] После отдельного согласования версии/ref/workflow — один exact-source `sign_candidate` с согласованными параметрами. Не запускать сборку незадействованных компонентов вместо результата задач 2–5.
- [ ] Проверять CI/candidate раз в 10 минут. При red прочитать конкретный лог; app defect → regression/fix/review/push/new SHA, infrastructure → только обоснованный адресный retry. Не дублировать успешную сборку.
- [ ] Проверить source/run, skipped publish, отсутствие tag/release согласованной версии, 22 assets, inventory/SHA256, runtime/updater/Mac signatures. Передать verifier все параметры явно; defaults и имя скрипта исторические. Применимость verifier к 0.4.0 проверить при согласовании сборки.
- [ ] Подготовить handoff: SHA/run, проверенный installer, автоматические результаты, открытые native gates и последовательность hardware-тестов. Отдельно статус пользовательского ПК: UNKNOWN/READY/BLOCKED, он не меняет результат сборки.

**Выход:** проверенный подписанный кандидат и протокол приёмки. Если security gate активации открыт — честно указать условный допуск; сборку и завершение интеграции этим не отменять. Не объявлять candidate hardware PASS.

## Линия H: устройство и последующая аппаратная приёмка

Это отдельная работа, не задача починки кода и не причина остановить задачи 1–6. Не трогать сейчас pending Windows updates или системные файлы. Перед установкой отдельно подтвердить безопасное состояние устройства; при внешнем maintenance-блокере кандидат и все software-результаты сохраняются.

После допуска: свежий backup → нормальный `/S /UPDATE` → Limited UI → actual installed/runtime hashes → обязательные открытые bounded native gates → ordinary контроль → pair.

Матрица: Tic/Tak и Stray; cold Start/Stop/repeat; два независимых свежих handshake **и** source-bound primary/reserve traffic; bounded fault injection с auto-revert/SSH; роли и WARM last-primary; IPv4/IPv6/split/actual resolver; LAN/SSH; native resources/leases cleanup; bounded semantic/pixel Start. UDP recovery и существующие TCP-соединения оценивать отдельно. Результаты FAILED/BLOCKED/NOT RUN не превращать в PASS.

Сохранить evidence и report. Завершение/выключение ПК — только после аппаратной работы и по актуальной на тот момент инструкции пользователя; никаких shutdown в рамках подготовки этого плана.

## Самопроверка плана

- Production entry, partial cleanup, repeated sessions — задача 2; pair/roles/WFP — 3; recovery/installer — 4; общие регрессии и нативный CI — 5; exact signed package — 6; реальные пакеты/отказы/cleanup — H.
- Пять Review Focus привязаны к конкретным тестам. Их названия — новые планируемые тесты, не утверждение об уже существующем PASS.
- Старые native evidence не заменяют интеграцию; unit tests не заменяют hardware. Никаких новых серверных моделей и ослаблений защиты.
- Ремонт текущего Windows не включён в критический путь. Основная единица прогресса — законченный сценарий через production caller.
