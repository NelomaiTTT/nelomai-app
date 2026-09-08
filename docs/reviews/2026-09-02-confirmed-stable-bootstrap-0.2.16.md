# Confirmed Stable bootstrap 0.2.16: итоговая evidence-точка перед review

Ветка `codex/confirmed-stable-0.2.16`, текущий HEAD
`f31088124244e7a9620b9aca80fabe9acca1fa7c`. Это подготовка к единственному
финальному whole-branch review в три прохода, а не его verdict. Все три прохода
пока **PENDING**.

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
| Frontend | product source `5ff3df65613265e2071ab4473eb58e90b8c916fc`; product source далее не менялся | `npm test`: 95 тестов/12 файлов, exit 0; Svelte 0 errors/0 warnings; production build PASS. |
| Python/contracts/workflows | тот же product source | fixtures 32 PASS; release workflow checks 5+7 PASS. |
| Rust workspace | тот же product source с acceptance-harness WIP; product source далее не менялся | `cargo test --workspace --locked --offline`: 907 top-level тестов + 5 nested child-process executions, 0 failed/ignored, exit 0. Full clippy с `-D warnings` exit 0; root повторил его после matrix freeze за 16.09s. `cargo fmt --all --check` и `git diff --check` exit 0. |
| Android JVM | текущий product source | Prescribed aggregate `:app:testDebugUnitTest` неоднозначен и до тестов не стартует. Реальные `:app:testArmDebugUnitTest` и `:app:testUniversalDebugUnitTest`: по 16 тестов/4 XML, 0 failed/error/skipped, exit 0. Deprecated API и Gradle 9 warnings остаются. |
| Host-supported native drafts | frozen `3f077c514a2584c26e67e46827bb2acf914669f4` | macOS/aarch64 и Android/aarch64 `build_only` PASS с единым public TEST pin. Android builder выполнил 432 теста без ошибок; macOS payload/codesign и Android stable payload/AAR/resource/license/ELF проверки PASS. |
| Production read-only check | panel HEAD `89ef85dc0acc3de409507ca70304c2fe00a1447e` | health OK, clean checkout, `nelomai-panel`/nginx/PostgreSQL active; `BEGIN READ ONLY` подтвердил Alembic `20260904_0057`. Это тот же commit, что у isolated matrix archive. Deployment/migration/capability changes не выполнялись. |

Полные 54 matrix PASS принадлежат именно `3e7afe6`; после них `f310881` получил
узкий retry-identity harness fix и отдельные 14 focused PASS. Полная matrix на
`f310881` заново не запускалась и здесь так не обозначается. Между `3f077c5` и
`f310881` изменены только три acceptance-harness файла; production source
не менялся.

Root также подтвердил неизменность vendor gitlinks и отсутствие совпадений в
tracked filename scan по известным secret-паттернам. Dirty vendor worktrees не
очищались и не использовались как новое evidence.

## Ограничения и незакрытая приёмка

- Финальный whole-branch review в три явных прохода — auth/migration/generation,
  tunnel shutdown/dispatcher/update barrier и artifact integrity/packaging/
  secrets — ещё **PENDING**. Этот документ не предрешает его результат.
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

Следующий шаг — один финальный whole-branch three-pass review на frozen source.
Только после него можно определить оставшиеся blockers; текущая ветка не
объявляется release-ready и Task 12 не объявляется полностью завершённой.
