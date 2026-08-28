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
- изменение серверного API сверх узкого additive-контракта для сообщения о
  зависшем data plane и гарантированной замены его dynamic lease;
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
остаётся в существующем отдельном защищённом хранилище.

Android intent привязан к текущей загрузке ОС. При boot он очищается до любого
sticky restore, поэтому новое поведение не включает VPN после reboot и не
изменяет требование `reboot -> off`. Успешное подключение по-прежнему использует
существующее защищённое хранение конфигурации и platform restore.

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
существующий `BackgroundCredentialStore` готов. `BackgroundConnectionClient`
расширяется так, чтобы выполнять initial и recovery start из этого template
через существующий background transport; успешное предыдущее подключение для
создания template не требуется. Полученная WireGuard-конфигурация передаётся
напрямую в `TunnelRuntime` и обнуляется после использования, как в действующем
background start. Ошибка атомарного сохранения intent является терминальной и
происходит до выдачи lease или запуска туннеля.

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

Android Quick Settings `Off` до начала stop атомарно увеличивает persisted
generation, устанавливает `desired_active=false` и отменяет native retry.
Каждый callback start/recovery сверяет generation до установки туннеля и до
публикации успеха. Поэтому поздний результат не может снова включить VPN.
Broadcast revision сообщает Tauri уже принятое состояние; UI-синхронизация не
является владельцем отмены. Новый Android intent после `Off` возможен только
после следующего явного `Старт` или Quick Settings `On`.

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
- явная отмена системного диалога;
- ошибки, не входящие в allowlist автоматического recovery.

Нормализованный UI-код `tunnel_service_unavailable` не используется для
решения о retry, потому что он объединяет временные, несовместимые и security
ошибки. Coordinator классифицирует исходный стабильный service code до
преобразования в `CommandError`; UI получает уже выбранное состояние recovery
или terminal action.

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

Для dynamic lease панель независимо от ранее наблюдавшегося handshake:

1. переводит lease в `Failed`;
2. отправляет его pool peer в recycle и не возвращает тот же peer новой выдаче;
3. сохраняет idempotency по паре operation ID и failure code;
4. применяет существующие device/session rate limits к повторным сообщениям.

Следующий start использует новый operation ID и `allow_alternate=true`; новый
lease не может ссылаться на отправленный в recycle peer. Другой peer того же
здорового pool допустим, а действующие probe/runtime-policy могут выбрать
другой сервер. Для personal/pinned lease причина не отвязывает peer и не
разрешает динамический fallback: сохраняются binding и действующий cooldown.

Это единственное изменение client API и панели в рамках задачи. Поля остаются
additive, старые клиенты продолжают отправлять `failure_code=null` или
`tunnel_handshake_timeout`.

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
- ошибка сохранения Android intent не выдаёт lease и не запускает туннель;
- Android Quick Settings `Off` инвалидирует generation до stop, а поздний
  Tauri/native callback не восстанавливает туннель;
- reboot очищает Android intent до restore и оставляет VPN/kill switch `off`;
- временные service-коды повторяются, а incompatible/security-коды становятся
  терминальными;
- смена сети объединяет несколько wakeup в одну попытку.

### Регрессии

- существующие start/stop, compensation, pinned, split-tunnel, quick reconnect,
  diagnostics, updater и AWG3 handshake tests остаются зелёными;
- `tunnel_data_plane_stalled` идемпотентно переводит dynamic lease в `Failed`,
  отправляет peer в recycle и не применяется к personal binding;
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
