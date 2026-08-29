# Автоматическое восстановление намерения подключения

## Контекст

Пользователь уже выразил намерение подключиться нажатием `Старт`. Повторное
нажатие той же кнопки после временной ошибки не добавляет приложению новой
информации и не должно быть обязательной частью восстановления.

Отчёты `0.2.12` показали конкретный разрыв в текущей state machine macOS:

1. монитор определяет зависание data plane AWG3;
2. UDP rebind не восстанавливает трафик;
3. локальный restart завершается `tunnel_handshake_timeout`;
4. `ClientCore::recover_stalled_data_plane()` переводит состояние в
   `Stopping`;
5. `connection_metrics_context()` возвращает контекст только для `Connected`;
6. scheduler теряет recovery episode и больше не может продолжить
   восстановление;
7. UI показывает ошибку, предлагающую снова нажать `Старт`.

Похожий UX используется и для временных ошибок первоначального запуска:
панель, выбор кандидата, получение конфигурации, handshake и часть локальных
сетевых ошибок уже безопасно допускают повтор, но повтор инициируется
пользователем.

## Цель

Одно нажатие `Старт` создаёт в текущей process/boot session намерение оставаться
подключённым. Пока причины остаются retryable, оно действует до явного `Стоп`
или Android Quick Settings `Off`. Приложение самостоятельно повторяет все
безопасные операции, заменяет неработающий динамический lease и восстанавливает
туннель после временных сбоев без горячего цикла и без повторных действий
пользователя. Reboot и терминальная причина завершают intent по явно описанным
ниже правилам.

## Не входит в задачу

- автоматический выбор динамического режима вместо явно выбранного личного
  пира;
- обход системного запроса VPN-разрешения;
- автоматическое исправление конфликтов другого VPN, антивируса, прав
  администратора, истёкшего доступа или обязательного обновления;
- сохранение нового намерения подключения после перезапуска ОС;
- изменение поведения Android Quick Settings для пользователя: существующие
  `On/Off` и sticky restore сохраняются, но их persisted state становится
  единственным владельцем Android intent;
- изменение серверного API сверх additive-контракта recovery: capability gate,
  measured background start и сообщение о зависшем data plane;
- Android CPU telemetry — это следующий отдельный этап.

## Основной принцип

`Старт` и `Стоп` меняют желаемое состояние, а не запускают одноразовую попытку:

```text
Старт -> desired=connected -> попытки и recovery выполняются приложением
Стоп  -> desired=disconnected -> текущая попытка отменяется, туннель очищается
```

На desktop намерение хранится только в памяти процесса приложения. На Android
оно атомарно хранится в Android Keystore-backed store процесса `:vpn`, чтобы
переживать обычное завершение UI/Tauri-процесса. Store содержит generation,
нормализованный выбор подключения, безопасные tunnel options и retry metadata,
но не WireGuard-конфигурацию, ключи или session token. Background credential
остаётся отдельным от lease lifecycle. Незавершённый start, active-lease
checkpoint и ожидающий cleanup являются фазами одного атомарного
Keystore-backed `AndroidLeaseTransactionStore` процесса `:vpn`; переход фазы не
требует согласованного commit нескольких файлов. Lease envelope несёт generation
intent, а credential использует собственную монотонную revision.

Android intent привязан к текущей загрузке ОС. Store записывает системный
`BOOT_COUNT` вместе с intent и проверяет его при каждом read, status, tile action
и service restore. Несовпавшая запись атомарно инвалидируется,
`desired_active` становится `false`, а VPN и kill switch остаются `off`.
Порядок запуска BootReceiver, tile и service не является частью корректности.
Если boot identity нельзя безопасно прочитать, restore не выполняется и intent
очищается fail-closed относительно автоматического запуска. Reusable quick plan
можно сохранить для следующего явного `Старт/On`, но он не включает VPN сам.

Каждая фаза lease transaction также хранит `BOOT_COUNT`, но mismatch не удаляет
незавершённую server transaction. Intent
инвалидируется, а такие записи атомарно переводятся в `stale_cleanup`: они
никогда не устанавливают конфигурацию и не включают VPN или kill switch.
Pending start проверяется через operation reconciliation; обнаруженный lease
переводится в pending stop, а уже известный lease освобождается тем же
idempotent stop. Новый `On/Старт` блокируется до подтверждённого cleanup. Если
background credential недоступен, записи сохраняются до открытия приложения;
server-side expiry остаётся последней страховкой, но не заменяет cleanup.

## Архитектура

### 1. Connection intent coordinator

Desktop coordinator живёт над `NativeApplication` в нативном Tauri-слое.
Android использует ту же state-machine semantics, но её авторитетный owner
живёт в `NelomaiVpnService` процесса `:vpn`; Tauri передаёт ему intent и
наблюдает состояние, а не планирует собственные Android retry. Coordinator
владеет:

- поколением операции для защиты от поздних результатов;
- нормализованными `ConnectOptions` и идентификатором устройства;
- cancellation token;
- номером попытки и временем следующего повтора;
- последним безопасным кодом ошибки;
- признаком отправленного уведомления текущего recovery episode.

Android использует новый `AndroidConnectionIntentStore`, отдельный от
UI-state, но разделяющий generation с `QuickTunnelController`. До первой
попытки UI передаёт в `:vpn` нормализованный intent template и убеждается, что
существующий `BackgroundCredentialStore` готов. Ошибка атомарного сохранения
intent является терминальной и происходит до выдачи lease или запуска туннеля.

Перед каждым panel start процесс `:vpn` атомарно записывает в
`AndroidLeaseTransactionStore` фазу `start_pending`: generation, `BOOT_COUNT`,
start operation ID, device/account scope, contract version, нормализованный
replayable request и его fingerprint. Envelope не содержит
WireGuard-конфигурацию, private key или token. Только после успешного commit
отправляется запрос панели. Operation ID не создаётся внутри сетевого вызова и
не меняется при transport timeout, отмене или восстановлении процесса.

Успешный ответ сначала переводит pending start в durable фазу
`lease_acquired`, атомарно связывая её с lease ID, после чего coordinator
повторно проверяет generation, `BOOT_COUNT` и `desired_active`. Запись остаётся
в этой фазе во время `TunnelRuntime.start`, handshake gate и публикации
результата. При stale generation/reboot или локальной ошибке она до освобождения
operation gate атомарно переходит в `cleanup_pending`.

После успешного handshake coordinator одним commit переводит тот же lease
envelope в фазу `active_checkpoint`. Она сохраняет lease ID, start operation ID,
device/account scope, contract version, исходный нормализованный request и
fingerprint; отдельного удаления pending record нет. Если `:vpn` завершился
после commit, но локальный tunnel отсутствует, restore имеет полный exact-replay
request и не создаёт новый lease. При `BOOT_COUNT` mismatch эта фаза становится
`stale_cleanup`, а не удаляется вместе с intent. Envelope очищается только после
подтверждённого server stop или authoritative terminal lease state.

Если результат start неизвестен или `:vpn` завершился до сохранения lease ID,
следующий restore сначала использует background operation reconciliation. Пока
lease активен, exact replay возвращает тот же idempotent start result, включая
пригодную к немедленному использованию конфигурацию. Если lease уже terminal,
панель возвращает authoritative terminal state. Exact replay ни при каком
состоянии не создаёт новый lease. Coordinator очищает pending start после
terminal result и только при всё ещё активном intent создаёт следующую start
operation с новым ID. До reconciliation, active checkpoint либо подтверждённого
cleanup новый пользовательский `Старт` не принимается.

`BackgroundCredentialStore` расширяется install secret текущего устройства,
монотонной `credential_revision`, server capability snapshot с expiry,
authorization tombstone и отдельным encrypted pending-token slot. Секреты
шифруются Android Keystore отдельно от intent, никогда не попадают во frontend,
события или логи и очищаются при logout/revoke. Все `configure`, token
`prepare/activate` и `clear` выполняются процессом `:vpn` через один mutation
gate и compare-and-swap ожидаемой revision.

UI provision до server-запроса резервирует mutation в `:vpn` и получает
mutation ID с ожидаемой revision. Пока reservation жива, background rotation не
начинается; logout/revoke может её отменить немедленно. Поздний UI response
принимается только с тем же mutation ID, device и revision. Reservation имеет
короткий timeout и не меняет действующий credential. Начало logout увеличивает
revision, отменяет mutation и сохраняет `logout_pending`, но переносит active
token в cleanup-only slot вместо немедленного удаления. Он допускает только
operation reconcile/cancel, compensation stop и logout finalize. После
подтверждённого cleanup `clear/logout finalize/revoke`, а также стабильный server
response об уже отозванном token, сохраняют final tombstone и удаляют active и
pending секреты. Поздний результат старой revision не может восстановить
credential.

Новый capability-gated token protocol двухфазный:

1. `POST /background/token/prepare` под normal client auth для UI provision
   либо current background auth плюс install secret для `:vpn` rotation создаёт
   короткоживущий staged token, но не меняет active/previous token. Панель
   хранит staged hash, prepare operation ID и один staged slot на device; новый
   prepare может заменить неприменённый staged token без влияния на active
   credential.
2. Получив response, `:vpn` до любого activate атомарно сохраняет staged secret,
   expiry, server generation, prepare/mutation ID и activation operation ID в
   encrypted pending slot. Mutation reservation принимает только response
   последнего prepare ID. Потерянный prepare response безопасно повторяется
   новой prepare operation: неизвестный staged token истечёт, а active token
   продолжает работать. После durable pending commit новый prepare запрещён до
   activate либо явного discard этой записи.
3. `POST /background/token/activate` аутентифицируется staged token и install
   secret. Запрос несёт activation operation ID; его специальный auth path под
   device lock сначала ищет immutable activation journal по точной сигнатуре
   `{device, activation operation ID, install secret fingerprint, token hash}` и
   только для неизвестной операции проверяет staged state и expiry. Панель
   переводит staged token в active, прежний active — в короткий previous overlap,
   и одной транзакцией сохраняет исходные generation/expiry в journal. Replay
   того же activation с уже active token, в том числе после исходного staged
   expiry, возвращает этот результат и не создаёт новое поколение. Applied
   activation record хранится как минимум до окончания срока выданного active
   credential; после его expiry восстановление всё равно требует UI-owned auth.
4. Только после подтверждённого activate `:vpn` CAS-promotes pending token в
   active и увеличивает `credential_revision`. При потерянном activate response
   pending slot переживает process death и повторяет тот же activation; при
   logout tombstone запрещает позднее promotion.

Server logout, logout-all и device revoke под device lock сначала принимают
durable cancellation/lease-cleanup jobs для незавершённых операций устройства и
только затем отзывают active, previous и staged token вместе с незавершённой
activation operation.

Legacy `POST /background/token` сохраняет прежнюю однофазную семантику только
для старых клиентов. Новый клиент при свежей capability использует исключительно
prepare/activate, поэтому server mutation не может обесценить локальный token до
durable local commit. Ни prepare, ни activate не создают и не вращают основную
access/refresh пару Tauri-сессии. Истечение локально сохранённого staged expiry
не разрешает discard: оно запускает exact activation replay, поскольку
неполученный ответ мог уже сделать token активным. CAS-discard pending slot и
новый prepare допустимы только после authoritative ответа journal-aware activate
`activation_not_applied`, который однозначно означает, что операция не была
применена и staged token истёк либо отклонён. Такой исход не делает credential
терминальным, если прежний active token и capability ещё действительны.
`background_credential_unavailable` возникает только когда active token истёк,
отозван или не восстановлен и authoritative activation reconciliation не
подтвердил, что pending token уже стал active; тогда intent просит открыть
приложение и не продолжает неавторизованные запросы. Существующий
`/background/auth/recover` остаётся UI-owned путём восстановления основной
сессии.

Capability процесса `:vpn` не зависит от жизни UI. Новый additive
`GET /background/capabilities` с background auth возвращает
`connection_intent_recovery_v1`, capability revision и server expiry. UI
provision передаёт первоначальный snapshot вместе с credential, а `:vpn`
обновляет его перед первым использованием нового контракта и после expiry.
Snapshot хранится с credential, но не продлевается локально; отсутствие,
истечение, `false`, `404` или стабильный `unsupported` означают `false`. Такой
downgrade атомарно запрещает создание новых feature operations, поля и failure
code нового контракта, включая подготовку нового token, но не capability
discovery, legacy background start/stop и exact reconciliation уже сохранённой
operation с её исходными contract version и fingerprint. Transport failure при
refresh не превращает ранее истёкший snapshot в `true`.

Для reconciliation без UI панель добавляет additive
`POST /background/operations/reconcile` с background auth. Запрос содержит
operation ID, kind (`start` или `stalled_stop`), исходный request fingerprint и
`cancel_if_absent`; ответ без конфигурации и секретов возвращает состояние
`not_found/pending/applying/compensating/applied/terminal/cancelled`, признак
`cancel_requested`, lease ID и authoritative lease status, когда lease
существует. Lookup выполняется под тем же device lock и по той же journal
signature, что исходная операция.

Start handler до lease mutation резервирует journal record с contract version и
fingerprint в состоянии `pending`. Перед первым pool/lease/agent side effect он
под device и journal row locks выполняет CAS `pending→applying`; это
linearization point операции. `cancel_if_absent=true` создаёт cancellation
tombstone для `not_found` или CAS `pending→cancelled`. Для `applying` он только
устанавливает durable `cancel_requested=true` и ждёт terminal result, не заявляя,
что lease отсутствует.

До каждого внешнего agent action `applying` record атомарно сохраняет его
durable execution step, зарезервированный lease/peer и idempotency key. Поэтому
повтор handler или server recovery worker после process crash может безопасно
проверить authoritative agent state либо повторить тот же action, не создавая
второй lease или peer. Start handler повторно проверяет journal под row lock
перед каждым DB commit, который публикует pool/lease mutation, и после каждого
внешнего agent action.

Увидев `cancel_requested`, handler не возвращает конфигурацию: операция либо
завершается `cancelled` до side effect, либо одной транзакцией переходит в
`compensating` и сохраняет lease ID, детерминированный compensation stop
operation ID, retry count и время следующей попытки. Server recovery worker
сканирует незавершённые `applying` и `compensating` records, под теми же locks
возобновляет idempotent agent/stop action с ограниченным backoff и является
владельцем повторов независимо от жизни исходного HTTP handler и Android
клиента. `applying` с `cancel_requested` после recovery никогда не продолжает
выдачу конфигурации, а переводится в `cancelled` либо `compensating`.

Lease/pool mutation и соответствующий journal transition входят в одну
DB-транзакцию; промежуточный commit без journal state запрещён. `compensating`
переходит в `terminal` только после authoritative terminal lease result;
transient agent/stop failure оставляет record retryable, а reconcile возвращает
lease ID, retry state и следующий срок попытки. Для `applied` cancel возвращает
lease ID для обычного client compensation stop. Cancellation tombstone хранится
не менее 24 часов и всегда дольше максимального proxy/application request
lifetime; GC запрещён, пока связанный lease не terminal.

Для unknown start при всё ещё активном intent coordinator сначала вызывает
reconcile. `pending/applying/compensating` повторяет status с backoff;
`not_found` отправляет исходный start с тем же operation ID; `applied` active
делает exact replay того же start, чтобы повторно получить конфигурацию.
`terminal/cancelled` завершает старую транзакцию; после этого допустима новая
start operation. При explicit `Off`, reboot mismatch или logout используется
`cancel_if_absent=true`: если операция ещё не применена, tombstone блокирует
позднюю выдачу. Для `applying/compensating` server worker является единственным
владельцем stop, а клиент только опрашивает journal и не запускает конкурирующую
compensation. Для `applied` ответ возвращает lease ID, после чего клиент
сохраняет обычный pending stop. В обоих случаях завершение подтверждает только
authoritative terminal lease state. Для stalled-stop `409` coordinator тем же
endpoint получает authoritative lease state и не зависит от common error body.

Capability gate применяется только к созданию новой logical operation. Панель
до первого `true` устанавливает постоянный compatibility floor: tolerant schema,
operation journal, exact replay и reconcile/cancel surface не удаляются
обычным rollback и поддерживают ранее принятые contract versions. Guarded
self-updater отклоняет rollback artifact ниже этого floor. Если этот инвариант
всё же нарушен, клиент не повторяет measured start как legacy unmeasured start:
для известного lease он выполняет новый legacy compensation stop с
`failure_code=null`, а unknown start сохраняет для UI recovery и показывает
`recovery_contract_unavailable` без выдачи нового lease.

Для dynamic режима `BackgroundConnectionClient` получает кандидатов через
новый additive `GET /background/server-candidates` с background auth, но
измеряет их HTTPS probe URL без authorization header по тем же правилам, что
native core: не более четырёх параллельных запросов, timeout три секунды и cache
не дольше пяти минут или earliest candidate expiry. Новый probe snapshot
собирается после смены сети и истечения cache. Background start отправляет
результаты и `require_measured_selection=true`; панель применяет те же правила
freshness/selection, что обычный `/connections/start`. Старый Quick Settings
клиент, не передающий поле, сохраняет legacy unmeasured fallback. Personal Tic
использует bound peer и не запрашивает кандидатов.

`BackgroundConnectionClient` выполняет initial и recovery start из intent
template; успешное предыдущее подключение для создания template не требуется.
Полученная WireGuard-конфигурация передаётся напрямую в `TunnelRuntime` и
обнуляется после использования, как в действующем background start.

Coordinator сериализует все start/recovery-операции. Новый `Старт` при уже
активном совпадающем намерении является идемпотентным. Изменить параметры
подключения можно только после `Стоп`, поэтому параллельные intent с разными
параметрами не создаются.

Нативный core остаётся владельцем атомарности одной попытки: выдачи lease,
запуска локального туннеля, handshake gate, compensation stop и защищённого
хранилища. Coordinator не собирает эти операции вручную и не получает
WireGuard-конфигурацию.

Metrics scheduler больше не выполняет многоступенчатый restart самостоятельно.
Он передаёт платформенному coordinator типизированный stall trigger с текущим
lease, после чего coordinator выполняет одну сериализованную
recovery-транзакцию. На Android native background restore, Quick Settings и
обычный UI-start используют один persisted intent, одну generation и один
operation gate процесса `:vpn`; параллельного Tauri recovery не существует.

### 2. Результат команды Start

`app_start` больше не обязан возвращать ошибку после первой временной неудачи.
Команда возвращает одно из двух безопасных состояний:

- `connected` с установленным `Connection`;
- `recovering`, когда intent принят и следующая попытка запланирована.

`AppStateResponse` и native state event получают отдельное поле
`connection_intent_status` со значениями `none`, `recovering` и
`blocked_terminal`, а для `recovering` — опциональное время следующей попытки.
Это поле не является новой core phase.

Терминальные ошибки по-прежнему возвращаются как `CommandError`. UI оставляет
phase `connecting` для `recovering`, показывает «Восстанавливаем подключение»
и предоставляет `Стоп`, а не заблокированную кнопку или повторный `Старт`.
Пока `connection_intent_status=recovering`, `AppStateResponse` накладывает
`connecting` поверх промежуточных core-фаз
`Ready/ServerUnavailable/Stopping`; исходная core-фаза остаётся доступна только
внутреннему recovery для принятия решений. Для `blocked_terminal` core phase и
kill-switch state не маскируются.

Успех, длительное ожидание и терминальная ошибка фонового восстановления
доставляются существующим событием изменения native-состояния с расширенным
статусом. Периодическая синхронизация state остаётся страховкой, но не является
владельцем recovery.

### 3. Отмена

Для `connecting/recovering` вводится явная отмена intent. UI и desktop tray
используют один и тот же путь:

1. увеличить generation и отменить sleep/сетевую попытку;
2. дождаться завершения уже вошедшей в критическую секцию операции;
3. остановить частично запущенный локальный туннель;
4. выполнить существующий idempotent compensation/pending stop;
5. перейти в `Ready` либо оставить `Stopping`, если cleanup ещё повторяется.

Поздний успех старого generation не может вернуть приложение в `Connected`.
Logout, update shutdown и явное завершение приложения сначала отменяют intent,
а затем используют существующий stop path.

Logout на Android имеет обязательный cleanup-before-revoke protocol:

1. `:vpn` атомарно устанавливает `desired_active=false`, инвалидирует generation
   и token mutation, переводит lease envelope в cancel/cleanup и credential в
   `logout_pending` с cleanup-only token;
2. локальный tunnel останавливается, затем с ещё действующим cleanup-only auth
   выполняются operation reconcile/cancel и все известные compensation stop;
3. после terminal cleanup обычный `/auth/logout` либо новый idempotent
   `POST /background/auth/logout-finalize` отзывает device sessions и все
   background token; только после success `:vpn` удаляет cleanup-only secret и
   сохраняет final logout tombstone;
4. если cleanup временно не завершён, UI-сессия может быть очищена локально, но
   `:vpn` сохраняет scoped `logout_pending` и продолжает только cleanup. Новый
   background provision и `On/Старт` блокируются до finalize;
5. если клиент просит немедленный server logout при незавершённом cleanup,
   finalize под device lock сначала записывает durable server-side cancellation
   и lease-cleanup jobs, затем отзывает credential в той же транзакции. Ответ без
   принятого job является retryable и не разрешает клиенту удалить cleanup auth.

Logout finalize несёт logout operation ID и install secret. После revoke панель
хранит ограниченный finalization tombstone с точной сигнатурой `{device, logout
operation ID, install secret fingerprint, hash прежнего cleanup-only token}`.
Он авторизует только exact replay того же finalize и возвращает исходный success,
не восстанавливая доступ к другим background routes. Tombstone не удаляется по
времени: он живёт до подтверждённого provision следующего credential generation
того же device либо окончательного удаления device record. Устройство после
неограниченного офлайна поэтому может завершить durable `logout_pending`, даже
если исходный finalize response был потерян. Новый provision допускается только
после того, как `:vpn` получил этот success и удалил локальный cleanup-only
secret; provision следующего поколения затем разрешает GC старого tombstone.

Удалённый logout-all/device revoke аналогично сохраняет authoritative device
cleanup tombstone и принимает через finalize route проверку install secret. Он
возвращает отдельный стабильный `device_revoked_cleanup_accepted` только после
durable принятия всех cancellation/lease-cleanup jobs; общий `401`, неизвестный
token или истёкший credential таким подтверждением не считаются и не разрешают
клиенту снять `logout_pending`. Этот server-side порядок не зависит от
доступности клиента. Update shutdown и обычное закрытие приложения не отзывают
background auth и оставляют durable cleanup доступным.

Android Quick Settings `Off` до начала stop атомарно увеличивает persisted
generation, устанавливает `desired_active=false` и отменяет native retry.
Каждый callback start/recovery сверяет generation до установки туннеля и до
публикации успеха. Поэтому поздний результат не может снова включить VPN.
Broadcast revision сообщает Tauri уже принятое состояние; UI-синхронизация не
является владельцем отмены. Новый Android intent после `Off` возможен только
после следующего явного `Старт` или Quick Settings `On`.

Если `Off` произошёл при неизвестном результате start, pending-start запись не
удаляется. После освобождения gate либо следующего service restore `:vpn`
вызывает operation reconcile с `cancel_if_absent=true`, не повторяет start и не
устанавливает конфигурацию. Cancellation tombstone блокирует позднюю выдачу, а
обнаруженный lease атомарно переводится в pending stop. До подтверждённого
cancel/stop `On/Старт` остаётся недоступен, а UI показывает `Stopping`.

Если stale callback уже получил lease и конфигурацию, он обязан:

1. не передавать конфигурацию в backend и немедленно обнулить её;
2. до завершения текущей operation записать lease ID и новый stop operation ID
   переводом `AndroidLeaseTransactionStore` в фазу `cleanup_pending`;
3. после освобождения operation gate выполнить background stop с
   `failure_code=null`;
4. при transport/server failure повторять тот же idempotent stop каждые 30
   секунд до подтверждения панели;
5. очистить pending record только после подтверждённого stop.

Если background credential уже недоступен, pending cleanup не удаляется. После
следующего открытия приложения credential/session recovery и pending stop
выполняются до принятия нового `Старт`; server-side lease expiry остаётся
дополнительной страховкой, но не заменяет клиентскую compensation.

Explicit `Off/Стоп` не ждёт возможности войти в занятый start gate, чтобы
инвалидировать generation. Он сразу публикует `desired_active=false`, затем
показывает `Stopping` до завершения локального stop и server compensation.
Поздний lease не остаётся активным в панели и не превращается в новое intent.

### 4. Классификация ошибок

Автоматически повторяются только ошибки, для которых повтор не требует нового
решения пользователя и не ослабляет безопасность.

#### Автоматический повтор

- transport error и HTTP `5xx` панели;
- `connection_unavailable`;
- `candidate_unavailable`;
- `configuration_fetch_failed`;
- `connection_no_longer_active` с новым operation ID;
- `connection_already_active` после reconcile/cleanup;
- `connection_release_failed` после idempotent pending stop;
- `probe_results_required` после нового probe snapshot;
- `saved_connection_unavailable` для динамического режима через онлайн-выдачу;
- `tunnel_handshake_timeout` после полного compensation stop;
- исходные `service_timeout`, `tunnel_service_timeout` и `service_stopping`
  после проверки фактического состояния;
- `service_unavailable` только после одной неинтерактивной попытки восстановить
  локальный service; повтор того же кода становится терминальным;
- `android_service_dispatch_unavailable` после state reconciliation и backoff;
- `connection_stall_verification_unavailable` с сохранением lease и того же
  stalled-stop operation ID;
- `connection_stall_recycle_rate_limited` с тем же operation ID и задержкой из
  валидного `Retry-After`;
- `udp_rebind_failed` и `udp_rebind_timeout` не выходят наружу как общий
  service failure, а переводят текущую AWG recovery-транзакцию на ступень
  локального restart;
- `endpoint_route_lost` и `endpoint_route_unavailable` после изменения сети
  либо backoff;
- `physical_network_monitor_unavailable`, `physical_egress_unavailable` и
  `local_networks_unavailable` после появления подходящей сети;
- AWG3 stall, для которого rebind и локальный restart не восстановили
  проверяемый handshake/data plane.

`amneziawg_profile_mismatch`, `awg3_profile_apply_failed` и
`awg3_profile_transform_mismatch` допускают только одну повторную онлайн-выдачу
в рамках episode. Повтор той же несовместимой конфигурации не продолжается
бесконечно: повторное совпадение кода становится терминальной ошибкой и просит
отправить диагностику.

#### Требуется действие пользователя

- вход, истёкший доступ и обязательное обновление;
- `device_limit_reached`;
- `ipv6_pool_unavailable`, потому что переход на IPv4 меняет выбранную
  политику пользователя;
- VPN permission required/denied;
- Defender/антивирус и отсутствующий AWG-компонент;
- helper install/authorization errors;
- `service_outdated`, `unsupported_protocol`, `missing_service_version`;
- `unauthorized_client` и `truncated_frame`;
- route conflict с другим VPN;
- повреждение или недоступность защищённого хранилища;
- некорректный ответ API;
- `operation_id_conflict` как нарушение client invariant с одним
  диагностическим отчётом;
- явная отмена системного диалога;
- ошибки, не входящие в allowlist автоматического recovery.

Для additive stalled-recycle contract действуют точные переходы:

| Ответ | Состояние клиента | Следующее действие |
| --- | --- | --- |
| `503 connection_stall_verification_unavailable` | lease и pending stalled stop сохраняются, новый start запрещён | повторить тот же stop operation ID по обычному backoff |
| `429 connection_stall_recycle_rate_limited` | lease и pending stalled stop сохраняются, новый start запрещён | повторить тот же operation ID не раньше валидного `Retry-After`; панель ограничивает header диапазоном `1..900` секунд, при отсутствующем/некорректном header используется 300 секунд |
| `409 connection_stall_not_recyclable` | выполнить один `POST /background/operations/reconcile` для stalled-stop operation | если lease уже `Failed/Released`, cleanup считается завершённым и разрешается новый dynamic start; если lease остаётся активным, episode становится terminal либо `blocked_terminal` |
| `409 operation_id_conflict` | terminal invariant failure | автоматический retry прекращается, создаётся один безопасный диагностический отчёт |

`503/429` не создают новый start operation ID, lease или recovery episode.
Повтор `409 connection_stall_not_recyclable` после единственного reconcile не
зацикливается. Новый dynamic start после подтверждённого terminal lease получает
новый operation ID и не предполагает, что прежний peer был отправлен в recycle.

Нормализованный UI-код `tunnel_service_unavailable` не используется для
решения о retry, потому что он объединяет временные, несовместимые и security
ошибки. Coordinator классифицирует исходный стабильный service code до
преобразования в `CommandError`; UI получает уже выбранное состояние recovery
или terminal action.

Android dispatch больше не возвращает raw-код `tunnel_service_unavailable`:
ошибка запуска/bind к foreground service имеет стабильный source code
`android_service_dispatch_unavailable`. Presentation layer может показать её
тем же пользовательским текстом, но не меняет source code, по которому
принимается recovery-решение.

Личный пир повторяется только как личный пир. Coordinator никогда не меняет
его на динамический режим без отдельного выбора пользователя. Динамическое
подключение сохраняет `allow_alternate=true` и может получить другой сервер.

### 5. Backoff и пробуждение

Последовательность задержек одной intent:

```text
0 с -> 2 с -> 5 с -> 15 с -> 30 с -> 60 с -> 300 с
```

После достижения 300 секунд приложение остаётся в пассивном ожидании и
повторяет попытку не чаще одного раза в 5 минут, пока intent не отменён и
последняя причина остаётся retryable. Терминальная причина переводит intent в
`none` либо `blocked_terminal` и прекращает scheduler. Это не горячий
бесконечный цикл: одновременно существует только одна попытка, а частота имеет
жёсткий верхний предел.

Смена физической сети, восстановление network reachability или возврат
приложения на экран могут один раз обнулить текущую задержку. Несколько
одновременных сигналов объединяются в одно пробуждение. Неуспешный probe сам по
себе не создаёт дополнительную попытку поверх scheduler.

Успешный handshake полностью сбрасывает backoff. Новый stall работающего
соединения начинает новый recovery episode, но остаётся частью того же intent.

### 6. Полная замена динамического соединения

Recovery работающего AWG3 выполняется по ступеням:

1. классифицировать data-plane stall и подтвердить доступность прямого пути;
2. выполнить UDP rebind и проверить tunnel probe/handshake;
3. выполнить один локальный restart и проверить handshake;
4. если локальный restart не помог, полностью остановить backend;
5. после подтверждённого локального stop завершить старый lease через
   idempotent API operation с типизированной причиной;
6. очистить только динамический offline cache старого lease;
7. запросить новый lease с теми же layer/mode/route/egress и
   `allow_alternate=true`;
8. запустить и проверить новый туннель;
9. только после успешной проверки вернуть `Connected`.

Переход `Stopping` внутри этой транзакции не уничтожает intent и recovery
context. Контекст принадлежит coordinator, а не `connection_metrics_context()`.
Metrics scheduler может остановить наблюдение старого lease, не отменяя
замену.

Для личного пира ступень замены повторно запрашивает тот же peer. Для pinned
Stray сохраняется существующий cooldown и запрет обхода server-side recycle
через offline cache.

#### Additive server contract

`ClientConnectionStopRequest.failure_code` расширяется значением
`tunnel_data_plane_stalled`. Оно отправляется только после подтверждённого
stall ранее подключённого AWG3, неуспешных rebind/local restart и завершённого
локального stop.

Клиент отправляет эту причину только для unpinned dynamic pool-backed AWG3.
Personal Tic и pinned Stray используют обычный stop с `failure_code=null` и
сохраняют выбранный peer; автоматический переход в dynamic запрещён.

Панель не доверяет клиентской классификации и принимает причину только если:

- lease принадлежит текущему device и привязан к pool peer;
- lease unpinned, dynamic и использует эффективный transport AWG3;
- lease имеет статус `Issued/Connected`, не завершён и всё ещё привязан к тому
  же peer/device;
- agent runtime подтверждает handshake либо traffic после `issued_at`, то есть
  это не initial handshake failure.

До этих mutable preconditions панель под device lock ищет operation ID в
durable operation journal. Запись содержит неизменяемую сигнатуру `{device,
lease, failure_code}` и состояние `pending/applied/terminal/cancelled`:

1. replay завершённой операции с той же сигнатурой сразу возвращает исходный
   результат независимо от текущего статуса lease;
2. тот же operation ID с другой сигнатурой возвращает
   `operation_id_conflict`;
3. retryable `pending` с той же сигнатурой продолжает исходную операцию;
4. только новый operation ID резервируется и переходит к eligibility, runtime
   verification и rate limit.

Applied result и перевод lease/peer фиксируются одной DB-транзакцией. Ответы
`503/429`, возникшие до mutation, оставляют journal в retryable `pending` и не
расходуют recycle budget. Повтор applied operation не запускает agent
verification, не меняет peer повторно и не расходует budget. Стабильный
`connection_stall_not_recyclable` атомарно сохраняет `terminal` result вместе с
authoritative lease status; последующий reconcile не видит его как бесконечный
`pending`.

Если runtime-проверка временно недоступна, панель возвращает retryable `503
connection_stall_verification_unavailable` и не меняет lease. Для personal,
pinned, non-AWG3, never-connected или уже завершённого lease возвращается
стабильный `409 connection_stall_not_recyclable`; peer не переводится в recycle.

Для прошедшего проверки dynamic lease панель независимо от ранее
наблюдавшегося handshake:

1. переводит lease в `Failed`;
2. отправляет его pool peer в recycle и не возвращает тот же peer новой выдаче;
3. завершает зарезервированную operation journal record: replay разрешён только
   для того же device, lease и failure code, иначе возвращается
   `operation_id_conflict`;
4. учитывает не более трёх новых stalled-recycle операций на device за 15
   минут; idempotent replay не расходует budget. При превышении возвращаются
   `429 connection_stall_recycle_rate_limited` и `Retry-After`, а peer не
   изменяется.

Следующий start использует новый operation ID и `allow_alternate=true`; новый
lease не может ссылаться на отправленный в recycle peer. Другой peer того же
здорового pool допустим, а действующие probe/runtime-policy могут выбрать
другой сервер.

Все поля и background endpoint additive. Старые клиенты продолжают отправлять
`failure_code=null` или `tunnel_handshake_timeout`, не передают
`require_measured_selection` и сохраняют прежнюю семантику.

#### Capability gate и rollout

До server rollout действующий `docs/panel_contract.md` остаётся источником
истины, и клиент не отправляет новые поля или failure code. Реализация выходит
в следующем порядке:

1. панель добавляет schema/fixtures/tests, оба `/connections/stop` и
   `/background/connections/stop`, background capabilities/candidates, measured
   background start, background operation reconcile/cancel, staged-token
   prepare/activate, background logout finalize и durable cleanup jobs, durable
   operation journal, compatibility-floor manifest, rate limit и bootstrap
   capability `connection_intent_recovery_v1=false/true`;
2. тот же panel commit обновляет `docs/panel_contract.md`, после чего панель
   выкатывается guarded self-updater и capability проверяется на production;
3. только затем выпускается клиент. UI и `:vpn` включают новый server contract
   лишь при свежем `connection_intent_recovery_v1=true` из доступного им auth
   channel;
4. при отсутствующей capability клиент не отправляет новые значения и остаётся
   на прежнем start/stop contract без `422`; UI может повторять существующие
   безопасные операции, но не заявляет гарантированный background recovery или
   recycle stalled peer.

Частично выкаченная панель не публикует capability. Новая схема, routes и
behavior должны быть доступны атомарно до её включения. Rollback может
переключить capability в `false` для новых операций, но guarded updater после
первого production enable не принимает artifact без compatibility-floor
manifest и постоянных additive replay/reconcile/cancel routes. Таким образом,
отключение feature не лишает уже начатую operation пути к terminal state.

### 7. Kill switch

Явный `Стоп` отличается от внутреннего recovery:

- initial start до установки защиты остаётся `off`;
- внутренний restart или замена lease сохраняет `blocked`;
- успешное восстановление возвращает `armed`;
- пользовательский `Стоп` снимает intent и переводит защиту в `off` только
  через существующий подтверждённый cleanup.

Действующая scoped kill-switch спецификация обновляется вместе с этим
документом: ограниченным остаётся каждый активный burst, после него coordinator
переходит в пассивный пяти минутный backoff. Это заменяет требование ждать
ручного `Retry`, но сохраняет запрет hot loop, состояние `blocked`, одну
попытку одновременно и доступный в любой момент `Стоп`.

Терминальная ошибка первоначального запуска до `armed` очищает intent и
оставляет kill switch `off`. Терминальная ошибка recovery ранее `armed`-сессии
при включённом kill switch устанавливает
`connection_intent_status=blocked_terminal`: автоматические попытки
прекращаются, но recovery context и защита сохраняются. UI показывает причину,
требуемое действие, `Повторить` и `Стоп`; только подтверждённый `Стоп` снимает
защиту.

### 8. UI и тексты

Пока `connection_intent_status=recovering`:

- заголовок: «Восстанавливаем подключение»;
- кнопка: `Стоп`;
- дополнительный статус после быстрого burst: «Сеть пока недоступна. Следующая
  попытка будет выполнена автоматически»;
- инструкция «нажмите Старт ещё раз» не показывается для allowlist recovery.

Тексты с ручным действием сохраняются только для терминальных ошибок. После
терминальной ошибки initial start intent очищается, phase становится
соответствующим `Ready/Error/AccessExpired/UpdateRequired`, и кнопка снова
становится `Старт`. После терминальной ошибки ранее защищённой сессии
`connection_intent_status` остаётся `blocked_terminal`, исходная core phase и
kill-switch state `blocked` сохраняются, а UI предоставляет `Повторить` и
`Стоп`, пока защита не снята подтверждённым cleanup.

Tray показывает «Отключить VPN» для `Connected`, активного
`connecting/recovering` и `blocked_terminal`, чтобы пользователь мог отменить
намерение или снять fail-closed защиту без открытия окна.

### 9. Диагностика и уведомления

Добавляются безопасные события без конфигурации, адресов и ключей:

- `connection.intent.started`;
- `connection.intent.retry_scheduled` с номером попытки, классом причины и
  задержкой;
- `connection.intent.network_wakeup`;
- `connection.intent.lease_replacement_started`;
- `connection.intent.recovered`;
- `connection.intent.cancelled`;
- `connection.intent.terminal_failure`;
- `connection.intent.slow_recovery_notified`.

Operation ID, request ID и lease ID остаются в существующих ограниченных
полях диагностики. Полный error message не используется как ключ решения:
решения принимаются только по стабильному code.

Автоматический start-failure report не создаётся на каждую попытку. Один отчёт
ставится в очередь при первом переходе к 300-секундному backoff либо при
терминальной ошибке; действующий device/session rate limit сохраняется.

После первого перехода к медленному backoff допускается одно системное
уведомление за episode. Повторные уведомления запрещены до успешного
подключения или нового явного `Старт`.

## Проверки

### Core

- handshake timeout динамического AWG3 полностью компенсируется, получает
  новый operation/lease и успешно подключается без второго пользовательского
  вызова;
- replacement не переиспользует failed dynamic cache;
- pinned cooldown и personal-peer semantics сохраняются;
- повтор profile mismatch ограничен одной новой выдачей;
- терминальные ошибки не входят в автоматический цикл;
- `Стоп` во время API, sleep, local start и handshake делает поздний результат
  недействительным;
- одновременно не выполняются две start/recovery-транзакции.

### macOS recovery

- rebind success завершает episode без restart;
- failed rebind + successful local restart сохраняет lease;
- failed local restart запускает полную замену lease;
- `Stopping` старого lease не теряет intent;
- rate limiter ограничивает активный burst, а coordinator планирует пассивный
  повтор;
- прямой физический outage не создаёт горячего restart loop.

### UI и команды

- временная ошибка возвращает `recovering`, а не инструкцию повторить `Старт`;
- phase `connecting` предоставляет `Стоп`;
- `Стоп` отменяет coordinator и очищает частичное состояние;
- terminal error показывает конкретное пользовательское действие;
- desktop tray отменяет активный intent;
- завершение Android UI-процесса не уничтожает intent и native retry;
- Android initial retry работает из persisted template до первого успешного
  подключения и не сохраняет WireGuard-конфигурацию;
- потерянный ответ background start переживает process death: restore сначала
  reconciles operation, делает exact replay только применённого active start и
  не создаёт второй lease;
- смерть `:vpn` после получения lease, но до local start/handshake сохраняет
  фазу `lease_acquired` и завершает либо tunnel recovery, либо compensation;
- `active_checkpoint` наследует полный replay request/fingerprint из
  `lease_acquired`, переживает очистку intent как `stale_cleanup` и позволяет
  exact replay после process death;
- Quick Settings `Off` при неизвестном результате start оставляет durable
  pending start, создаёт cancellation tombstone через `cancel_if_absent` и не
  разрешает новый `On` до подтверждённого cancel/cleanup;
- Android dynamic background start отправляет свежие probes и не использует
  legacy unmeasured fallback;
- background token обновляется через staged prepare/activate без UI и без
  изменения основной access/refresh-сессии; prepare не инвалидирует active
  token;
- потерянный prepare response, смерть UI до передачи staged token и CAS conflict
  не сокращают срок действия локального active credential;
- потерянный activate response переживает process death и офлайн дольше staged
  TTL: journal-aware replay тем же operation ID выполняется до expiry validation,
  возвращает применённый active credential и не создаёт следующее поколение;
- локальный staged expiry сам по себе не удаляет pending slot; только
  authoritative `activation_not_applied` разрешает CAS-discard и новый prepare
  при действующем active token без terminal credential error;
- late prepare/activate response после UI provision или logout отвергается по
  mutation ID и `credential_revision`; logout tombstone не даёт восстановить
  старый credential;
- `:vpn` получает capability без UI, истёкший snapshot не использует как
  `true`, а `false/404/unsupported` отключают новый contract без цикла `422`;
- capability downgrade запрещает только новые feature operations: pending
  operation сохраняет exact replay/reconcile/cancel до terminal state;
- ошибка сохранения Android intent не выдаёт lease и не запускает туннель;
- Android Quick Settings `Off` инвалидирует generation до stop, а поздний
  Tauri/native callback не восстанавливает туннель, обнуляет конфигурацию и
  ставит поздний lease в pending compensation;
- неуспешная stale compensation переживает process death и повторяется с тем же
  operation ID до подтверждённого stop;
- несовпавший `BOOT_COUNT` отклоняется при первом read независимо от того,
  первым после reboot запущен tile, service или UI;
- pending start/stop и active-lease checkpoint с прежним `BOOT_COUNT` становятся
  stale cleanup, не устанавливают туннель и блокируют новый `On` до cleanup;
- Android logout сохраняет cleanup-only auth до terminal reconcile/stop;
  offline logout завершается через durable server cleanup job и finalize до
  удаления последнего background credential;
- потерянный logout-finalize response после офлайна дольше 24 часов возвращает
  exact success по finalization tombstone, тогда как общий `401` не снимает
  `logout_pending`;
- временные service-коды повторяются, а incompatible/security-коды становятся
  терминальными;
- смена сети объединяет несколько wakeup в одну попытку.

### Регрессии

- существующие start/stop, compensation, pinned, split-tunnel, quick reconnect,
  diagnostics, updater и AWG3 handshake tests остаются зелёными;
- `tunnel_data_plane_stalled` идемпотентно переводит dynamic lease в `Failed`,
  отправляет peer в recycle и отвергается для personal/pinned/non-AWG3;
- новый stalled operation ID нельзя повторно использовать с другим lease или
  failure code;
- applied stalled-stop replay после перевода lease в `Failed` возвращает
  исходный success до eligibility/runtime/rate-limit checks и не расходует
  budget повторно;
- `503 connection_stall_verification_unavailable` и `429
  connection_stall_recycle_rate_limited` сохраняют тот же pending operation ID;
  `429` соблюдает валидный `Retry-After`;
- `409 connection_stall_not_recyclable` выполняет ровно один reconcile и не
  разрешает новый start при всё ещё активном lease;
- четвёртый stalled recycle за 15 минут получает `429` без изменения peer;
- клиент без `connection_intent_recovery_v1` не отправляет новый contract;
- Android background service без свежей capability также не отправляет новый
  logical operation, даже если UI-процесс ранее видел `true`; exact replay
  сохранённой operation при этом остаётся доступен;
- staged-token prepare/activate сохраняет основную Tauri-сессию, не инвалидирует
  active token до durable pending commit и идемпотентно повторяет activate;
- background operation reconcile возвращает authoritative lease state для
  start и stalled stop, а `cancel_if_absent` блокирует позднюю выдачу lease;
- start journal CAS `pending→applying` линеаризует выдачу с cancel; cancel во
  время `applying` приводит к server compensation, и ни один промежуточный
  pool/lease commit не выполняется без согласованного journal transition;
- падение start handler в `applying/compensating` и временная ошибка agent stop
  восстанавливаются server worker с тем же idempotency key до authoritative
  terminal lease; Android-клиент не запускает конкурирующий stop;
- logout/logout-all/device revoke принимают durable cleanup до token revoke;
  finalization tombstone не удаляется по TTL и очищается только следующим
  подтверждённым provision либо удалением device record;
- terminal recovery ранее `armed`-сессии сохраняет `blocked` и доступный
  подтверждённый `Стоп`;
- конфигурация и секреты не появляются в UI, событиях или логах;
- production preflight и production-БД для проверки не используются.

## Наблюдение после выпуска

На пилоте сравниваются:

- количество `tunnel_handshake_timeout` и `connection.intent.recovered`;
- доля recovery через rebind, local restart и replacement lease;
- время от первого сбоя до успешного handshake;
- число терминальных ошибок и отмен пользователем;
- отсутствие повторяющихся уведомлений и start-failure report spam;
- отсутствие параллельных lease и зависших `Stopping` операций.

Успешный критерий: временные ошибки больше не требуют повторного `Старт`, а
неисправимая или требующая решения пользователя причина остаётся явной и не
маскируется автоматическими попытками.
