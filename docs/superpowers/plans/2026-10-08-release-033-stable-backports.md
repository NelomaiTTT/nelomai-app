# Nelomai 0.3.3: перенос исправлений на стабильную базу

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Подготовить обычный подписанный кандидат0.3.3 на базе выпущенной0.3.2 с согласованными исправлениями; не выпускать до аппаратной проверки.

**Architecture:** Использовать существующее изолированное ответвление0.3.2 с pre-login diagnostics, переносить только необходимые изменения и регрессии. Windows hot-standby0.4.0/carrier/killswitch0.5.0 не включать. Стабилизация и временная расширенная диагностика — отдельные части: этот план исполняет перенос исправлений, а не проектирует новый межпроцессный диагностический протокол.

**Tech Stack:** Rust workspace, Kotlin/Android, Svelte/TypeScript, Python packaging, GitHub Actions, существующие signed runtime/container contracts.

**Spec:** Согласованный пользователем08.10 состав и карта исходных SHA: `/Users/altzxd/Documents/Panel/KNOWN-ISSUES.md`, раздел «Карта исправлений для переноса на базу0.3.2 — аудит08.10.2026». Пользователь отдельно потребовал аппаратную проверку перед выпуском. Согласованная временная диагностика15мин остаётся отдельной обязательной частью релиза, а не считается готовой от выполнения этого плана.

## Global Constraints

- База: `6c33c652965358d05eccc2b7a59d0ecc71aaa0d0`/v0.3.2; рабочая ветка `Future/diagnostics-032-login-upload`, исходный HEAD `e3e4babf9a3c501892e8dd8511a51b6024d3f9ff`.
- Существующий worktree: `/Users/altzxd/Documents/GitHub/nelomai-app/.worktrees/diagnostics-032-login-upload`; не создавать дублирующий worktree и не переключать старый грязный main checkout.
- Новый продукт0.3.3, не0.3.3d и не замена выпущенного0.3.2. Сохранить trusted stable0.2.20 и его проверяемое происхождение.
- Включить NLM013/040(Android delta)/044/048/049/062/063/064. NLM045/065 — отдельная оценка, в обязательный состав этого плана не включены.
- Не переносить wholesale `b2eb2bc`, `a556d3a`, `6b8aa90`, `6f9d112` или ветку0.4.0. Не менять чужие recovery/vendor, production, Windows/Mac установки на этапе разработки.
- Сохранить CI push-trigger ветки `Future/windows-hot-standby-0.4.0`: пользователь сообщил отдельную правку `af4929d189ca881adc9908174ebeb6f819dfac19` (только branches в checks.yml). При версии/интеграцииmain перенести эту строку без кода0.4.0; workflow_dispatch остаётся Linux-only, не считать его полным CI.
- Не сбрасывать auth/journals/data, не ослаблять ownership/admission/IPC/WFP guards, не читать и не печатать секреты.
- Для каждого переноса: исходный SHA, новый SHA, NLM-ID, точная regression и её RED/GREEN. Исторические тесты не заменяют свежую проверку0.3.3.
- Release workflow допускает только `mode=sign_candidate`, exact source_sha, `version=0.3.3`, `critical=false`, `minimum_supported=false`, `panel_notification_ready=false` до завершения аппаратной приёмки. Публичная публикация — отдельное действие.
- Субагенты только для существенного независимого кода; ревью выполнять inline. Первые переносы выполнять последовательно в этом чате, без параллельных правок общих файлов.

## Review Focus

1. Просроченный foreground/auth ответ не должен менять новое подключение после Stop/logout: отрицательные epoch/generation тесты задачи3.
2. Повтор ACK/очистки после обновления не должен разрешать чужой scope или терять новую работу: полный replay набор задачи5.
3. Недоступный owner/панель не должны лишать пользователя локального Stop и локального экспорта: задачи3/4 и release gate.
4. Старый runtime namespace и генераторstable не должны потерять статус/журналы при0.3.3: задачи2/6 и отдельная диагностика.
5. Успех candidate-only pair не означает исправление ordinary0.3.2: каждую переносимую regression адаптировать к действительному стабильному пути, без фиктивного native результата.

## Task 1: NLM-048: контракт диагностических отчётов

**Files:** `src-tauri/src/diagnostics.rs`, `src-tauri/src/automatic_diagnostics.rs`, их существующие тестовые модули.
**Interfaces:** существующий `DiagnosticUploadRequest` и `DesktopAutomaticDiagnostics`; публичную схему не расширять.

- [x] На базеe3e4bab перенести тесты `legacy_intent_reports_retry_without_the_invalid_interval_field`, `legacy_report_repair_does_not_strip_real_or_unknown_session_metadata` изb2eb2bc и проверки нового builder.
- [x] Запустить legacy и connection_intent tests; RED подтверждён именно неверным interval end в очереди и builder (исправлена отдельная тестовая fixture network_incidents String).
- [x] Перенести только builder/точную нормализацию старой очереди: новый interval end=None, старый ID/файл не менять доACK, неизвестную/реальную session metadata не стирать.
- [x] Весь `cargo test -p nelomai-app --lib --locked --offline`:207 PASS,0 fail/ignored. Inline review чистый; отрицательные guards по каждому полю, повтор после ошибки/ACK и persisted builder покрыты. Commit с NLM-048 и исходным полным SHA.

## Task 2: NLM-013: Android status без churn службы

**Files:** `plugins/tunnel-android/android/src/main/java/{TunnelStatusTransport,TunnelServiceProtocol,NelomaiVpnService}.kt`, соответствующие `TunnelStatusTransportTest`/`RedundantStartProtocolTest`; `scripts/android/generate-stable-sources.py` и `scripts/tests/test_generate_stable_sources.py`.
**Interfaces:** существующий statusRPC; не изменять Start/Stop/cancellation policy. Источники5540f1f+bd96f57.

- [x] Existing-client-API regression: RED100 service starts → GREEN1start/1binding/100fresh observations; не compilation failure нового API.
- [x] Перенести status-only binding и endpoint guards, затем generator fix сохранения shared `RuntimeProcessSelection` (отдельный RED→GREEN).
- [x] Проверить release binding после5s inactivity, request deadline30s, binderdeath/revoke/generation/runtime change, false bind, late reply, wrongUID/opcode/API, Stop при сломанном observer.
- [x] Standalone Android plugin projects проверен; full JUnit974PASS/0failed/errors/skipped/45suites. Python generator3PASS.
- [x] `:stable-runtime-android:compileDebugKotlin` PASS; это не shipping APK и не hardware. Inline review без открытых замечаний; commit NLM-013 обоих зависимых срезов. Gradle9/deprecated API warnings сохранены в логах.

## Task 3: NLM-040/049: смысл Stop и актуальное состояние UI

**Files:** `NelomaiVpnService.kt`, `RedundantStopAcknowledgementTest.kt`; `crates/client-core/src/lib.rs`, `crates/client-application/src/lib.rs`, их тесты; `src-tauri/src/commands.rs`; `src/lib/{connection-action,foreground-state}.test.ts`, `src/lib/connection-action.ts`, `src/routes/+page.svelte`.
**Interfaces:** явный current-user Stop сохраняет WARM; targeted cancel/failedStart остаютсяcold. Foreground snapshot ограждён наблюдаемыми epoch/generation/order; никаких новых desktop pair интерфейсов. Источникb2eb2bc, UI follow-up a556d3a только если применим к перенесённой foreground логике.

- [x] RED user button Stop→retainActivePeer=true подтверждён; targetedcancel→false, capability/pending-role guards и неизменность первого cold-решения покрыты.
- [x] RED UI voluntaryStop, поздний Connected после logout и nativeRunning при CoreReady подтверждены; genuineunexpectedstop сохраняет предупреждение.
- [x] Core/application/commands/UI перенесены без desktop pair API; foreground не ждёт network bootstrap. Stable desktop three-field intent projection сохранена.
- [x] Late Start/Stop/logout, admission, offline bootstrap, nativefailure, single-flight, foreground wake покрыты. Дополнительный RED periodic polling подтвердил применимость UI-only a556d3a: passive poll не блокирует Start, foreground barrier не блокирует Stop.
- [x] Rust533PASS/15suites; Android976PASS; npm143PASS/check/build; host strictClippy трёх пакетов/alltargets и actualAndroid Rust check PASS (existing warnings +3 unused Android helpers, не strictAndroidClippy). Inline review без открытых замечаний; аппаратная проверка впереди.

## Task 4: NLM-062/064: обычный Stop и смена протокола

**Files:** `crates/client-core/src/lib.rs`, `crates/client-core/tests/runtime.rs`, `crates/client-core/src/connection_intent.rs`, `src-tauri/src/connection_intent.rs`.
**Interfaces:** существующий durableStopworker и desktop coordinator. Исходникиb0d796a,d2e33ca,409cc34; не переносить desktop_runtime pairfix257a28b или новые поля pairarchitecture ради компиляции теста.

- [x] RED fresh/WARM: StartCancelled вместо повторяемой ошибки панели; unavailable panel/localclose и durable-replay assertions воспроизведены.
- [x] Speculativeauth/nativeclose race удалена, exactoperation journal/worker сохранены. NLM062 commit409003bc0e5c9b97a390e3b30a14074c5f643303, Core280PASS + strictClippy.
- [x] RED completed ordinary intent→сменаTic/Stray DifferentIntentActive подтверждён; retainedStopResponse actualCore проверен; foreign/live/session/pendingStop, новое поколение/inflight/retry guards покрыты.
- [x] d2e33ca+409cc34 смысл перенесён на stable coordinator: snapshot/revalidation + retiredlease/session, без pairarchitecture. Вместо отсутствующего pending_redundant_recovery проверяется существующий pendingStop journal; ошибки чтения запрещают retirement.
- [x] Весь Rust workspace1101PASS/0fail/1ignored/87suites, strictClippy core/application/app alltargets PASS, fmt/diff clean. Inline review исправил misplaced cfg у нового all-desktop helper; без открытых замечаний. Native Windows/hardware остаётся отдельным gate.

## Task 5: NLM-044: согласованная цепочка update recovery

**Files:** `crates/client-storage/src/{runtime_state,startup}.rs`, `crates/client-storage/tests/startup_storage.rs`; `crates/client-container/src/ipc/child_admission.rs`, `src/{switch,update,auth_broker}.rs` внутри client-container; `tests/{cleanup_replay,update,transition_auth}.rs`, `tests/support/runtime_switch_contract.rs`, `tests/test_completed_apply_panel_contract.py`.
**Interfaces:** прежние protectedroot/successorauthority/scope, RuntimeRecordOwner и runtime-switch API. Источники6b8aa90→b2eb2bc→a556d3a, только container/storage.

- [ ] Перенести failing regressions для ACKlost after cleanup, historicaltarget отсутствующего в новом manifest, completedapply predecessor (не отправлять forbidden supersede).
- [ ] Перенести цепочку последовательно, прогоняя каждый набор доGREEN. Новая work/liveowner/несогласованныеpublicjournals/foreignscope/epochrotation должны оставаться отказом.
- [ ] Запустить `cargo test -p nelomai-client-storage -p nelomai-client-container`; выполнить Python actualpanelcontract fixture по инструкциям самого теста с существующим panel окружением, без сетиproduction.
- [ ] Inline review всей цепочки и тестов, commitNLM044. Не включать Macsigning/installer и Windowscoldstart части исходныхкоммитов автоматически.

## Task 6: NLM-063 и согласование сборки0.3.3

**Files:** Android `{RedundantHealthMonitor,RedundantProductionAdapters,RedundantConnectionCoordinator,NelomaiVpnService,TunnelPlugin}.kt` и соответствующие тесты; `package.json`, locks/Cargo manifest versions, `src-tauri/tauri.conf.json`, release/checks workflows и versioned packaging tests.
**Interfaces:** available физическойсети вместо VALIDATED при readiness; независимые реальные probe/handshake обязательны. Version0.3.3 согласована во всех проверках; trustedstable0.2.20 неизменен.

- [ ] Перенести5actual-coordinator regressions изAndroid6f9d112: unvalidatedavailable Tic/Stray допускаются только при здоровыхprobe+handshake; missingnetwork/failedprobe/stalehandshake запрещены; manualrebind не выдумываетtrue.
- [ ] ПолучитьRED, перенести только Android срез, прогнать полный Androidplugin suite и stablecompile; review/commitNLM063.
- [ ] Обновить версии/workflow/gates/fixtures штатно на0.3.3; не ослаблять existingpublishedtag immutable gate или sourceSHA/signature checks. Не включать carrierCI из0.4.0.
- [ ] Сборщик поддержки сейчас содержит literal0.3.2 и versioneddirectory0.3.2: при выпуске перейти на проверенную buildversion, сохранить bounded allowlist исторических0.3.2/stable0.2.20/current0.3.3, добавить regression currentlog+historicaltails+точнаяapp_version. Не подменять неизвестный activeruntime версией контейнера (NLM060 отдельно).
- [ ] Прогнать version/script tests, Androidapp unit suite, fullRustworkspace, npmtest,fmt,Clippy; каждый пропуск явно записать.

## Task 7: Интеграция и аппаратный release gate

**Files:** release/checks workflows только при требуемых выше version changes; release report и NLMреестр. Продуктовых изменений в этой задаче не маскировать.
**Interfaces:** immutable signed candidate artifacts/sourceSHA; отдельное разрешение публикации.

- [ ] До финальной сборки закончить отдельно согласованную временную диагностику15мин с collector-enforced expiry/volume, offafterrestart, sanitizedstorage, manualupload/localsave. Без её собственной проверки релизный состав не считать готовым. Порог объёма/хранения и межпроцессные границы фиксируются её отдельным дизайном, не выдумываются при интеграции backports.
- [ ] Сохранить reviewedproductSHA, новыеbackportSHA/NLM и baseline exclusions. Повторить чистое inline review и полные проверки на итоговомsource.
- [ ] Стабильнуюлинию вернуть вmain обычным fast-forward доставляемым восстановительнымкоммитом: parent актуальныйmain, tree проверенной стабильнойлинии, безforcepush/сбросачужогоcheckout. Точныйgitспособ согласовать с текущим ownership/worktrees; еслиmainизменился, повторитьсверку. История0.4.0 должна оставаться достижимой; будущаяинтеграция требует отдельного merge-плана.
- [ ] Push exactsource; sign_candidate только после пригодногоCI. Проверять runs нечаще10мин; red→точныйlog/cause/fix/test/review, неслепойretry. Не дублировать успешный неизменныйкандидат.
- [ ] Проверить source/run/signatures/SHA256/inventory/updater/runtime/stable, skippedpublish/no0.3.3tagrelease. Читать актуальный verify script полностью; все параметры явно, старыеdefaults неиспользовать.
- [ ] Android hardware: upgrade0.3.2→0.3.3/login/settings preserved; UI/tileTic/Stray ordinary+существующийAndroidreserve Start/Stop/repeat/WARM; idlepoll→backgroundunbind; диагностикалогин/неработающийowner/offlineexport/15мин/volume/restart/manualretry.
- [ ] Windows hardware: normalinstaller freshbackup/actualsignedruntimehash/LimitedUI; ordinaryTic/Stray sourceboundtraffic/Stop/repeat/protocolswitch/authIPC/cleanup/LAN/SSH. Новой desktop pair схемы0.4.0 в матрице нет. Не чиститьauth/journals, не использовать интернетвнеVPN как доказательство.
- [ ] Mac hardware дляNLM044: штатное обновление/cleanupreplay и входбезсбросаданных; Keychainprompts не объявлятьисправленными. ДоступностьWindows/Mac/Android не блокирует разработку, но непройденная обязательнаяhardwareпроверка блокирует выпуск.
- [ ] Server supportupload: локальныеpanelmigration/APIcode ещё неразвёрнуты. Перед end-to-end отправкой нужна отдельно авторизованная штатнаявыкладка и admincode; безнеё можно принять localexport, но нельзя объявить uploadworking.
- [ ] Сохранить результаты соsource/run/deviceidentity; после hardware вынести итог и только затем отдельно решать publish. Ничего не выключать/перезагружать по старым heartbeatинструкциям: актуальнуюдоступность/желаниепользователя подтвердить перед hardware.

## Состояние плана

- План составлен по согласованной картеисправлений, существующимфайлам и текущемуgitсостоянию; inline self-review выполнен.
- Пользователь подтвердил план («да»); исполнение начато. Отмечать выполненные задачи только по свежим проверкам.
- Метод исполнения: inline в текущем чате, независимые срезы с RED→GREEN, review и отдельным коммитом. Не создавать новый чат/автоматизацию.
