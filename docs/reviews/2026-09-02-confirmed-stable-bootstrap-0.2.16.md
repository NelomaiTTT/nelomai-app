# Confirmed Stable bootstrap 0.2.16: evidence после единственной final fix wave

Ветка `codex/confirmed-stable-0.2.16`. Единственный final whole-branch review
в три прохода выполнен на `59818c392601b6e851b4747d2a609ee276379cc0`:
**0 Critical, 2 Important (P2), 0 Minor; With fixes; not release-ready**.
Этот commit содержит одну разрешённую fix wave поверх указанного HEAD.
Итоговый независимый **SCOPED review двух исправлений — PENDING**;
автор исправлений не объявляет замечания закрытыми review.

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

Полные 54 matrix PASS принадлежат именно `3e7afe6`; после них `f310881` получил
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

Это implementation/test evidence, а не scoped-review approval. Полный Rust
workspace gate и новые host native drafts после freeze выполняет root;
на момент данного commit они **PENDING**. Старые `3f077c5` drafts не являются
final product evidence.

На final source этой fix wave `cargo test -p nelomai-client-container
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
  После двух исправлений независимый final **SCOPED review — PENDING**.
- Host drafts собраны на `3f077c5`, используют TEST trust и Node 26 вместо
  workflow-pinned Node 24. Они не переносят approval на финальный source.
  Android stable получил полную native проверку; latest collision input builder
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

Следующий шаг — scoped review двух исправлений и root gates на frozen source.
Ветка не объявляется release-ready; Task 12 не объявляется полностью завершённой.
