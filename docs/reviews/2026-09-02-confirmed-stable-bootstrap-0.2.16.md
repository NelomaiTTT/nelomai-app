# Confirmed Stable bootstrap 0.2.16: итоговое evidence после локальных gates

Ветка `codex/confirmed-stable-0.2.16`. Единственный final whole-branch review
в три прохода выполнен на `59818c392601b6e851b4747d2a609ee276379cc0`:
**0 Critical, 2 Important (P2), 0 Minor; With fixes; not release-ready**.
Единственная fix wave `73a3d4475d05b2272fc1623ddd5eb72379d2167c` прошла
независимый scoped review: **оба P2 ADDRESSED, 0 новых findings**. Отдельный
verification socket fix `3e47b1fc7ed2444704ce6dfe47b33d97d84a6bbf` также
прошёл scoped review: **ADDRESSED, 0 новых findings**. Открытых source-review
замечаний нет.

Product source заморожен на `3e47b1fc7ed2444704ce6dfe47b33d97d84a6bbf`.
Этот итоговый documentation commit меняет только evidence-документ; native builds остаются
привязаны к `3e47b1f` и не переобозначаются сборками documentation commit.

## Новейшие проверенные gates

| Gate | Source и результат | Граница evidence |
| --- | --- | --- |
| Source reviews | Whole-branch `59818c3`: 2 P2; scoped `73a3d44` и socket `3e47b1f`: все ADDRESSED, **0 open** | Единственный broad review и два ограниченных rereview; не release acceptance. |
| Full Rust workspace | `3e47b1f`: `cargo test --workspace --locked --offline`, **914 top-level PASS + 5 nested**, 0 failed/ignored, exit 0 | Включает прежний socket failure и новые regressions; Windows-labelled host tests не означают запуск Windows-only кода на Windows. |
| Full Rust quality | `3e47b1f`: `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`, exit 0, 38.48s; fmt/diff-check exit 0 | Финальный root gate после socket fix. |
| Real-panel/PostgreSQL matrix | Точно `73a3d4475d05b2272fc1623ddd5eb72379d2167c`: без фильтра **54 PASS**, 27 на направление; panel archive `89ef85dc` + `0057` | После неё изменена только публикация Unix socket response; broker/coordinator неизменны. Matrix не запускалась заново на `3e47b1f`; synthetic adapter не доказывает native tunnel admission. |
| Final host native drafts | Точно `3e47b1f`: macOS/aarch64 и Android/aarch64 `build_only` **exit 0**, stable verification **exit 0**; Node 24; root сверил размеры/SHA всех artifacts и оба sizes JSON. Android XML: app 16 + tunnel 416 = **432 PASS**, 0 failed/errors/skipped | Финальные host-supported drafts, не exact installer/candidate и не four-platform release root. |
| Frontend | Неизменённый frontend; Node 24.19.0 / npm 11.17: **95 tests / 12 files PASS**, Svelte 0 errors / 0 warnings, static build PASS | Root повторил проверки в финальной Rust-only wave. |
| Python/contracts/workflows | Исходники проверок не менялись при socket fix: fixtures **32 PASS**, workflow **5+7 PASS**, retry-identity unit **1 test / 2 subcases PASS** | Проверки выполнены root до socket-only изменения; к новому source не переобозначаются. |

Оба финальных native draft используют один public TEST pin
`35cd9a85381733caec0c92e76f68cce594902c04371fa530e8413bc0d1d92e7d`;
это тестовое доверие, а не production release trust.

Версия в `package.json` и `src-tauri/tauri.conf.json` остаётся `0.2.16`.
`CHANGELOG.md` честно помечает её как «в разработке, не выпущена».
Shipping layout по-прежнему latest-only: в 0.2.16 установлен только актуальный
runtime, пользовательский Stable toggle скрыт; hot standby и дублирующий auth
не добавлялись.

## Текущее состояние реализации

- Production dispatcher выбирает только подписанный slot в idle-состоянии;
  immutable stable engine проверяет собственную подписанную identity, а
  CommonHost однократно привязывает native transport к установленному target
  текущего incarnation. Ownership, stale Stop, private-operation и start fences
  сохранены.
- Единственный durable Requested journal является авторитетным switch intent.
  Pending selection восстанавливается как проверенная проекция этого journal;
  terminal, foreign-container и отсутствующий в manifest target не становятся
  новой preference. Ранее открытый atomic-intent gap закрыт и scoped rereview
  помечает finding как addressed.
- Новый server Apply запрещён старому incarnation и разрешается только после
  полного process restart с проверенным selected target. Exact persisted replay
  сохраняется; prepared UUID сам по себе не разрешает новую выдачу. Cancel до
  dispatch и lost/unknown Apply используют отдельные защищённые пути. Ранее
  открытый pre-restart Apply gap закрыт scoped rereview.
- Selected-empty cleanup binding ограничен exact retained source, пустым payload,
  точным target и writer quiescence. Ordinary empty binding не ослаблен; retry
  после отказа записи не создаёт второй Apply.
- Истёкший access допускает только ограниченный refresh той же frozen auth scope.
  Потерянный rotating refresh не повторяется. Истёкший refresh приводит к
  RecoveryRequired/no-admission, после чего обычные logout → durable cleanup
  receipt → password login очищают protected auth и создают generation 2 в
  ожидаемом исходном slot.
- Recovery producer разделяет старый switch process и новый recover process.
  Числовой bounded retry сохраняет operation ID от исходного Pending switch до
  самого первого и всех следующих recover. Exact gen2 replay отделён от
  действительно stale accepted replay после обычного login до gen3; historical
  receipt не может подменить текущую identity или изменить PostgreSQL state.

Scoped rereview fix round 4 помечает последний retry-identity finding как
**ADDRESSED**, не находит нового Critical/Important breakage и сохраняет findings
1–3 предыдущего matrix rereview закрытыми. Это ограниченный verdict harness diff,
не whole-branch acceptance.

## Зафиксированная evidence-хронология

| Evidence | Точная source-точка | Результат и граница |
| --- | --- | --- |
| Atomic intent / post-restart Apply / selected-empty binding | `fd66b16237e125be0648fe75081a7fd4f7227078` | 75 focused Rust PASS; root независимо повторил те же 75 PASS. Последующий fix2 rereview закрыл producer ordering regression. |
| Полные локальные real-panel/PG matrix | `3e7afe6b3fca542aef49faaed1ab83181be1b481` | latest→stable 27 PASS и stable→latest 27 PASS, всего **54 PASS**. По 14 crash-phase, 4 lost-response, 2 controlled reauth и 4 race записи на направление плюс delayed/expiry coverage. Это instrumented local evidence, не packaged candidate. |
| Retry identity fix round 4 | финальный runner связан с `f31088124244e7a9620b9aca80fabe9acca1fa7c` | Unit RED→GREEN и 8 focused real-panel команд: **14 PASS**, по 7 в каждом направлении. Проверены standalone delayed, clean/delayed expiry и clean/delayed lost reconcile/resume. Root независимо повторил unit PASS; scoped rereview чист. |
| Frontend | frontend source `5ff3df65613265e2071ab4473eb58e90b8c916fc`, frontend далее не менялся | Исторический результат: 95 тестов/12 файлов, Svelte 0 errors/0 warnings, production build PASS. Root повторил эти проверки 2026-09-08 на Node 24.19.0 / npm 11.17: те же 95/12 PASS, 0/0, build PASS. |
| Python/contracts/workflows | тот же product source | fixtures 32 PASS; release workflow checks 5+7 PASS. |
| Rust workspace | исторический `5ff3df6` с acceptance-harness WIP, до нынешних двух product fixes | `cargo test --workspace --locked --offline`: 907 top-level тестов + 5 nested child-process executions, 0 failed/ignored, exit 0. Full clippy с `-D warnings` exit 0; root повторил его после matrix freeze за 16.09s. Это не final-fix workspace evidence. |
| Android JVM | исторический product source до final fix wave | Prescribed aggregate `:app:testDebugUnitTest` неоднозначен и до тестов не стартует. Реальные `:app:testArmDebugUnitTest` и `:app:testUniversalDebugUnitTest`: по 16 тестов/4 XML, 0 failed/error/skipped, exit 0. Deprecated API и Gradle 9 warnings остаются. |
| Host-supported native drafts | frozen `3f077c514a2584c26e67e46827bb2acf914669f4` | macOS/aarch64 и Android/aarch64 `build_only` PASS с единым public TEST pin. Android builder выполнил 432 теста без ошибок; macOS payload/codesign и Android stable payload/AAR/resource/license/ELF проверки PASS. |
| Production read-only check | panel HEAD `89ef85dc0acc3de409507ca70304c2fe00a1447e` | health OK, clean checkout, `nelomai-panel`/nginx/PostgreSQL active; `BEGIN READ ONLY` подтвердил Alembic `20260904_0057`. Это тот же commit, что у isolated matrix archive. Deployment/migration/capability changes не выполнялись. |

Исторические 54 matrix PASS этой таблицы принадлежат `3e7afe6`; после них `f310881` получил
узкий retry-identity harness fix и отдельные 14 focused PASS. Полная matrix на
`f310881` заново не запускалась и здесь так не обозначается. Между `3f077c5` и
`f310881` изменены только три acceptance-harness файла; production source
не менялся именно в этом историческом интервале. Нынешняя fix wave меняет
production Rust broker/coordinator, поэтому прежние native drafts и full
workspace результаты не обозначаются evidence финального product source.

## Два замечания final review и проверенные исправления

1. **P2: lifetime exhaustion 16 authorities.** RED: после 16 успешных
   update-cancel/resume следующий цикл (индекс 16) возвращал `RecoveryRequired`.
   Broker теперь атомарно удаляет только завершённые исторические authorities
   и supersede-цепочки с известным resume result, когда durable coordinator
   journal больше не требует их. Current operation, active reconcile,
   completed resume и все successors сохранённых predecessors защищены;
   pending resume/recovery/logout/supersede и непринятый cleanup ACK откладывают
   compaction. In-flight auth также откладывает compaction без ожидания его
   issuance lock перед local stop. Лимиты **16 / 1 MiB** неизменны;
   unresolved authority не удаляется.
   GREEN покрывает 20 полных update-cancel с пересозданием broker/coordinator,
   exact replay текущего Complete, отказ старого retired replay без изменения
   текущей auth, crash до/после protected save, pending зависимости, транзитивную
   supersede-цепочку и реальные logout → ACK consumption → login → 20 transitions.
2. **P2: immediate graceful-stop error.** RED: оба новых теста немедленной
   graceful ошибки воспроизводили отсутствие force intent/receipt.
   Только `Ok(Ok(()))` считается graceful success; ошибка и timeout проходят
   через один durable force-stop путь. GREEN подтверждает forced receipt после
   успеха, отсутствие receipt/stop proof после force failure и точный retry
   после reopen без повторного graceful stop. Существующий тест failed
   pre-stop cancellation теперь явно отказывает обоим stop методам.

Это implementation/test evidence wave `73a3d44`. Последующий независимый
scoped review закрыл оба P2 без новых findings. Финальные root workspace
и host native gates на `3e47b1f` приведены выше; старые `3f077c5` drafts
сохраняются только как историческое evidence.

На source `73a3d44` этой fix wave `cargo test -p nelomai-client-container
-p nelomai-client-storage --locked --offline` завершился exit 0:
**238 top-level PASS + 4 успешных nested test summaries**, 0 failed/ignored.
В их числе transition-auth 41, update 26, auth-broker 37, switch 10,
auth-migration 11, startup-storage 11. Отдельный focused повтор transition-auth
и update — **67/67 PASS**. `cargo clippy -p nelomai-client-container
-p nelomai-client-storage --all-targets --locked --offline -- -D warnings`,
`cargo fmt --all --check` и `git diff --check` — exit 0. Полные команды,
RED/GREEN и журналы находятся в `final-fix-wave-report.md` рабочего evidence
каталога; это ограниченные package gates, не full workspace/native acceptance.

Root также подтвердил неизменность vendor gitlinks и отсутствие совпадений в
tracked filename scan по известным secret-паттернам. Dirty vendor worktrees не
очищались и не использовались как новое evidence.

## Ограничения и незакрытая приёмка

- Whole-branch review выполнен в трёх явных проходах: auth/migration/generation,
  tunnel shutdown/dispatcher/update barrier, artifact integrity/packaging/secrets.
  Оба P2 и отдельный socket defect закрыты независимыми scoped reviews;
  **0 source findings open**, без заявления release readiness.
- Финальные host drafts собраны на `3e47b1f`, используют public TEST trust и
  Node 24. Android stable получил полную native проверку; latest collision input builder
  проверяет с `inspect_native=False`, поэтому full latest native verification
  не заявляется.
- Linux/x86_64 и Windows/x86_64 native drafts отсутствуют; four-platform signed
  root, реальные `.app`/APK installers, installer re-extraction, updater
  signatures и release trust **UNRUN**. Точный release candidate должен быть
  собран и полностью проверен из exact final source; preliminary artifacts не
  являются повторно используемым approval.
- Product installation, elevation, publication, production mutation и реальные
  release keys не выполнялись. Локальная matrix использует synthetic identities
  и documented external test adapters; после снятия cleanup barrier start доходит
  до следующего честного server rule `409 peer_binding_required`, а успешный
  native tunnel/agent start не заявляется.
- Физические Windows/Linux/macOS/Android проверки **UNRUN**. В частности,
  Android tile background/foreground stop regression должна быть проверена на
  физическом устройстве до acceptance.

Source reviews и локальные root gates завершены. Остаётся exact-candidate и
физическая приёмка, перечисленная выше. Ветка не объявляется release-ready;
Task 12 не объявляется полностью завершённой.

## Отдельное исправление сбоя final workspace gate

После fix wave `73a3d4475d05b2272fc1623ddd5eb72379d2167c` root запустил
`cargo test --workspace --locked --offline`. Gate завершился ошибкой в
`common_bound_transport_launches_signed_stable_through_real_dispatcher_socket`:
private server получил `Backend("dispatcher_busy")`, клиент — `TruncatedFrame`.
Отдельный повтор проходил; это новый intermittent verification defect, не
переоткрытие двух предыдущих P2 и не новый broad review.

Причина подтверждена детерминированным RED: mutex dispatcher оставался занят
при публикации уже готового lifecycle response, и запрос клиента на другом
socket мог прийти до освобождения guard. В отдельном исправлении guard
освобождается перед первым response write. Kernel peer identity, authorization,
request read, `handle`/`relay` и формирование ответа сохраняют прежнюю защиту.
Существующий код обработки stream механически вынесен в private generic
helper для regression; test-only writer удерживает возврат write через channel
после публикации полного frame. RED гарантированно даёт `dispatcher_busy`;
barrier освобождается, потоки joined и engine остановлен до assertion.
GREEN допускает реальный private request; настоящий busy mutation guard
по-прежнему отклоняет конкурентный запрос. Sleeps/retry loops не добавлены.

Scoped evidence этого отдельного исправления: socket integration **7/7 PASS**;
`cargo test -p nelomai-unix-service -p nelomai-contracts --locked --offline` —
**131 PASS**, 0 failed/ignored (contracts 19+21+17, Unix unit 50, helper 17,
socket 7). Scoped clippy `--all-targets --locked --offline -- -D warnings`,
`cargo fmt --all --check` и `git diff --check` — exit 0. Независимый socket
**SCOPED review: ADDRESSED, 0 новых findings, 0 open**. Root повторил full
workspace на `3e47b1f`: 914 top-level PASS + 5 nested, exit 0; финальные host
native drafts также PASS. Это заменяет прежний failure как текущий gate,
сохраняя его историю. Matrix `73a3d44`, package tests и исторические full
workspace/native результаты остаются привязаны к своим source-точкам.
