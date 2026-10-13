# Nelomai 0.3.5: собственный DoT и принятие Stop до очистки резерва

Статус: письменная спецификация для ревью пользователя. Поведение согласовано
в чате; этот документ ещё не утверждён. Продуктовая реализация и сборка не начаты.

## Цель и границы

Пользователь поручил исправить NLM-072 и ускорить готовность следующего Start
по ранее выбранным схемам. База приложения — опубликованная 0.3.4,
`e6e14a7ea07f19ebb9e920092e8429a6122ac512`; база панели —
`11c8a3f6122e59664c83a30a66c323dee307f8cd`.

1. Для строгого Private DNS пользователь явно выбирает собственный hostname
   Nelomai. TLS-запросы внутри поддержанного Tic/Tak VPN используют существующий
   DNS46/NAT46, вне VPN получают обычные DNS-ответы без синтетических адресов.
2. После локального отключения VPN и долговечного принятия Stop панелью можно
   начать новую сессию с другим VPN-IP, не ожидая агентов старой сессии.
   Резерв очищается существующим worker; новый резерв может быть другим пиром
   на другом допустимом сервере. WARM удерживается только для последнего primary.

Не входят: IPv6 внутри TUN, прозрачная поддержка неизменного Quad9 hostname,
собственного DoH приложения, новый менеджер восстановления, новая очередь,
экспериментальная Windows hot-standby 0.4.0, ослабление авторизации/ownership,
автоматическое изменение системного Private DNS, установка сертификатов на
телефон, новые таймауты вместо исправления причин.

В этом проходе запрещены push, GitHub сборка, публикация, production deploy,
правка DNS-записей/сертификатов/системных файлов серверов и установка APK.
Локальные regression-тесты и подготовка миграции не являются выкаткой.

## Подтверждённые исходные ограничения

- Текущий DNS46 находится в панели: `agents/node-tic-agent/scripts/dns46_proxy.py`.
  TCPHandler передаёт реальный `client_address` в `Resolver.handle`; исходный
  адрес используется в SourceMappings и ключе выбора адреса ресурса.
- `app/services.py` выдаёт уникальные `/32` `egress_transit_v4`, агент Tak
  разрешает их на точном Tic-туннеле и в allowlist resolver. Это не обязательно
  исходный VIP телефона. Нельзя заменять адрес клиента на localhost или
  доверять предоставленному клиентом произвольному заголовку идентичности.
- Сейчас TLS-listener отсутствует. Строгий внешний Quad9 не получает
  синтетические A-записи DNS46; Automatic на current SHA аппаратно работает.
- `app/client_connections.py::stop_client_connection` связывает Stop с
  завершением агентской очистки. `STOPPING` считается активной сессией также
  в `app/client_redundancy.py` и partial unique index моделей.
- `AppHotStandbyAddress` уже принадлежит конкретной сессии, не устройству:
  новая сессия может получить другой FREE адрес. Старый QUARANTINED адрес
  нельзя возвращать в FREE раньше полного ACK всех его участников.
- Recovery worker сейчас держит allocation/device/session locks во время
  обращения к агентам. Просто убрать HTTP-ожидание недостаточно: такой worker
  может задержать Start теми же блокировками.
- Android durable recovery и callback-generation guards уже существуют.
  Использовать их, а не удалять Stop/journal или выдавать Ready по одному клику.

## A. NLM-072: DoT как вход существующего DNS46

### A1. Endpoint и включение

- Предлагаемый публичный hostname: `dns.nelomai.ru`, конфигурируемый до выкатки.
  Публикуются только IPv4 endpoint-адреса обслуживающих Tak для этого hostname.
  Приложение не предполагает работоспособности ещё не развёрнутого hostname.
- На каждом обслуживающем Tak TLS предъявляет действительный, доверенный
  Android сертификат этого hostname. Ключи могут быть отдельными для каждого
  узла; они не попадают в панельные ответы, APK, логи или тестовые fixtures.
- Listener TCP/853 — дополнительный вход текущего DNS46 процесса, не новый
  отдельный proxy-manager. По умолчанию он выключен; включение требует полного
  валидированного набора hostname/адресов/пути cert и key/лимитов.
- Сначала проверить cert/key, hostname/срок действия и bind listener, затем
  объявлять готовность и устанавливать точные агентские правила. Неполный TLS
  конфиг не ломает уже работающий UDP/TCP DNS46; готовность DoT при этом false.
- TLS-контекст можно заменить только после проверки нового cert/key. При
  некорректном обновлении сохраняется прежний действительный контекст; истёкший
  сертификат не даёт статус Ready. Выпуск/renewal CA и DNS-записи выполняются
  позже отдельным штатным deployment, не скрытым шагом разработки.

### A2. Источник и маршрут

- TLS завершается на выбранном Tak непосредственно в DNS46-процессе.
  Для запроса от разрешённого transit-IP вызывается существующий
  `Resolver.handle(..., tcp=True, client_address=observed_source)`.
- Точные правила Tic/Tak распространяют DNS46 source-translation на TCP/853
  **только к конфигурируемым собственным DoT endpoint-IP**. На текущем Tak
  эти же назначения направляются к его локальному TLS-listener с сохранением
  адреса transit-клиента. Сертификат hostname остаётся настоящим.
- Не перенаправлять произвольный TLS/853, чужой DoT hostname, весь TCP или
  общий физический firewall. Не принимать identity из PROXY/ECS/HTTP поля
  неаутентифицированного клиента. Ошибка собственных правил не разрешает
  обход TLS, другой клиентский источник или открытый внутренний порт5353.
- Для own-hostname при split-tunnel Android добавляет точные endpoint `/32`
  через существующую подготовку DNS-маршрутов. Адреса берутся из согласованного
  control-plane конфигурационного набора; это не общее правило «весь853».
- Вне VPN listener выдаёт обычные реальные A/AAAA через существующий resolver
  upstream-путь, без Mapper/SourceMappings, Jool allocations и синтетических A.
  Это позволяет сохранять выбранный Private DNS до Start и после Stop.
- Отдельные режимы выбора/кэша для anonymous и VPN клиента: ответы public
  resolver не загрязняют per-client DNS46 policy. Исчезновение разрешённого
  источника прекращает создание его mappings, но не выдаёт их чужому источнику.

### A3. Ограниченность и безопасность

- TLS framing использует двухбайтовую длину DNS; обрабатываются fragmented
  reads и несколько запросов на соединении. Нулевая/оборванная/некорректная
  рамка закрывает только это соединение. Не логировать полные TLS/DNS payloads.
- TLS минимум1.2; проверка сертификата клиентом не отключается. На853 нет
  plaintext режима ни при ошибке handshake, ни при ошибке upstream.
- Отдельный лимит TLS-соединений64, лимит8 на observed source, handshake5с,
  idle15с, максимум64 запросов на соединение. DNS wire frame не более65535байт;
  сохраняется существующий ограниченный query deadline/backend worker pool.
- Anonymous resolver дополнительно ограничен20 запросами/с на source с
  burst40; ограниченный LRU bucket-cache4096. Разрешены только обычные DNS
  queries, не AXFR/IXFR/UPDATE. Не становиться публичным amplification gateway.
- Синтетический DNS46 ответ не объявляется аутентифицированным DNSSEC-ответом
  исходной зоны. Обычные ответы не теряют существующие DNSSEC semantics.
- Upstream-политика DNS46 в этой правке не заменяется целиком. Если отдельно
  включён encrypted upstream, его failure не вызывает скрытый plaintext retry.
- Последовательность собственных NFT changes и disable/rollback проверяется
  по точным object identities; существующие UDP/TCP53/DNS46 guards сохраняются.

### A4. Совместимость и подтверждение

- В панели readiness собственного DoT объявляется отдельно от общей готовности
  DNS46; новый app получает hostname/IPv4 endpoints только после readiness.
  Старые приложения и агенты продолжают нынешний Automatic/обычный DNS путь.
- Android показывает выбранный hostname и краткую инструкцию включения в
  системных настройках. Глобальные настройки не меняются программно.
- Тесты обязаны различать источник VPN/transit, public источник и localhost;
  проверить malformed/fragmented/multiple frames, TLS/лимиты/ошибку cert reload,
  устаревший snapshot, чужое назначение и обратимость точных правил.
- При будущей аппаратной приёмке: реальный strict own-hostname/браузер и
  IPv6-only ресурс на primary/reserve; cold Start, Stop/repeat, LAN/split,
  TLS до/после VPN, кешированный synthetic A до и после failover, сроки TTL и
  совпадение адресных mappings с фактическим Tak. Не засчитывать один
  handshake/свежий uncached DNS как всю приёмку кеша при failover.
- Если существующая кэшированная mapping не пригодна на резерве, доставка
  DoT не принимается до отдельного конкретного исправления этого дефекта;
  нельзя подменять тест свежим lookup или обещать бесшовность.

## B. NLM-040: принятый Stop и новая независимая сессия

### B1. Минимальное расширение контракта

- В текущей redundancy capability добавить `async_stop_v1`, defaultfalse.
  Только явно согласованная сессия нового клиента вправе запросить
  `background_cleanup=true` в существующем session-scoped Stop endpoint.
  Этот параметр входит в неизменный fingerprint принятой операции.
- Ответ добавляет `stop_acceptance` с exact operation/session/lease IDs и
  `accepted=true, cleanup_pending=true`. Это ACK долговечного принятия,
  **не** leaseReleased/sessionStopped/полного окончания очистки.
- Без capability/request сохраняется нынешний synchronous контракт0.3.4;
  старый агент/панель не получают новых полей как обязательных. Новый клиент
  не интерпретирует неизвестный/старый ответ как accepted.
- Новая схема применяется к нормальному пользовательскому session Stop.
  Logout/revocation/runtime-switch, компенсации неудачного Start и неизвестное
  native состояние сохраняют строгие blocking guards; это не общий bypass.

### B2. Долговечное принятие и БД

- Под allocation/device/session/operation locks проверить ownership, актуальное
  членство, session/address, operation fingerprint и удерживаемый currentprimary.
  Одной транзакцией поставить STOPPING, запретить новые роли/candidates,
  зафиксировать выбранный primary, поставить всех нужных участников в
  CLEANUP_PENDING, оставить addressQUARANTINED и записать acceptance операции.
- Добавить nullable `restart_allowed_at` в AppConnectionSession. Только эта
  проверенная транзакция negotiated normalStop ставит значение. Отсутствие
  acceptance после rollback/неизвестного ответа не допускает новый Start.
- Миграция partial unique index активного устройства: конфликтуют
  allocating/connected/degraded и stopping **с restart_allowed_atNULL**.
  Принятая detachedSTOPPING остаётся очищаемой, но не является новым живым
  подключением. SQLite и PostgreSQL должны сохранять одинаковый инвариант.
- Все Start/runtime-admission/active-lease predicates исключают только exact
  принятые detachedcleanup сессии; не исключать всякий STOPPING или всякую
  pending операцию. Нормальный отзыв и неподтверждённое состояние всё ещё блокируют.
- HTTP отвечает только после commit, без native RPC. Повтор exactStop возвращает
  ту же acceptance; другая lease/session/retain/background flag — conflict.
- Acceptance записывается в result существующей операции отдельно от её
  окончательного APPLIED. До полного агентского ACK операция остаётся
  выполняемой/очищаемой; повтор и reconcile различают accepted и completed.
  Раннее acceptance не завершает cleanupjobs и не освобождает ресурсы.

### B3. Новый Start, старый cleanup и WARM

- Новый Start разрешён после native-close ACK и принятого Stop. Он получает
  другую session identity и другой FREE VIP, не старыйQUARANTINED адрес.
  Пиры старой pendingcleanup исключены из выбора; существующий cleanWARM
  lastprimary можно переиспользовать, но не ещё не очищенный пир.
- Если lastprimary ещё очищается, выбрать другой допустимый ready primary.
  Если его нет — честная нехватка ресурса, не unsafe reuse и не зависание на
  очистке чужого резерва. Новый резерв — обычный существующий allocator,
  не обязан использовать сервер старого освобождаемого резерва.
- Recovery использует существующие jobs/monitor. Claim конкретного member и
  immutable lease/session/address/generation snapshot фиксируется коротко;
  agent RPC идёт без широкого allocation/device locks. Финализация требует
  exact-owner/generation CAS и ACK, не слепого выполнения по имени интерфейса.
- Долгий SSH старого резерва не удерживает lock нового Start. Parallel cleanup
  не требуется для успеха первой версии: допустима последовательная фоновая
  очистка, если она не блокирует новое подключение и не меняет его ресурсы.
- Только после primary cleanup ACK lastprimary становится WARM с прежними
  ключами/часовым сроком. Reserve/candidates освобождаются только после их ACK.
  Старый VIP освобождается после полного cleanup; потерянный ответ сохраняет
  карантин/идентичность и допускает безопасный повтор.
- Поздний worker не меняет роли/options/auth/newStart и не очищает новый VIP.
  Старый Stop относится к старой session, не к нынешнему activelease устройства.
- Для повторных быстрых Stop/Start допускается несколько старых detachedcleanup
  сессий; это конечные existing jobs с server limits/address capacity. При
  исчерпании адресов/пиров вернуть bounded retry/resource unavailable.

### B4. Клиентская долговечность и UI

- Перед native закрытием сохранить immutable Stop, intent cancellation epoch
  и ownership. Не считать VPN выключенным при native.stop failure.
- После nativeACK показывать локально выключенный VPN; Startenabled только
  после panelacceptance. Пока панель недоступна — показать «ожидаем принятия
  Stop», сохранить ограниченные повторы, не выдавать новую живую сессию вслепую.
- Accepted старые cleanup envelopes отделены от current transaction в
  существующем durable recovery, максимум8 outstanding envelopes устройства.
  Лимит/expiry не удаляют ещё выполняемую очистку: перед переполнением отказать
  в новой admission. Панель сохраняет cleanup независимо от жизни app-процесса.
- Background/cleanup auth привязан к старому snapshot, не перемещается на
  новую сессию только из-за повторного Start. Старый callback не сбрасывает
  новый desiredActive, generation, auth и отображаемое состояние.
- Failed accepted cleanup виден в диагностике/админке, но не переводит новую
  здоровую сессию в Stopping. Logout/revocation продолжает охватывать все
  собственные активные и pendingcleanup ресурсы без удаления истории.

### B5. Регрессии и будущая аппаратная приёмка

- RED: reserveagent заблокирован, Stopacceptance возвращена, новыйStart реально
  выделяет другойVIP/readyprimary до unblock; lateoldcleanup не меняет новуюсессию.
- Lostreply/commit failure/duplicateStop/changedfingerprint, два параллельных
  Start, два cleanupworkers, revocation/runtime-switch/Start cancellation.
- PrimaryWARM послеACK/повторноеиспользование cleanlease; reservequarantine;
  несколько старыхсессий и адресное/пировое исчерпание безunsafe reuse.
- Реальная PostgreSQL migration+race с отдельными connections/SQLitelifecycle;
  fakeagent применяется только к внешнему I/O, не к транзакциям allocator.
- Android durable restart/Stop→Start/stalecallback, Core/UI неизвестное
  native состояние и NLM071 guards, старый server/client compatibility.
- После нового кандидата отдельно измерить nativeOff, panelacceptance,
  Startenabled, freshprimary handshake/payload и eventualoldcleanup.
  Цель — исключить ожидание агентского ACK; фиксированное число миллисекунд
  всей сети не обещается. Интернет с физической сети не является VPN PASS.

## Порядок работы и выход этапа

Сначала пользователь рассматривает этот документ, затем отдельный проверяемый
план с RED→GREEN этапами. Начинать с Stop vertical slice: durable acceptance →
new session/new VIP → latecleanup guard; затем DoT transport/source identity
и integration. Это позволяет получать проверяемый результат без двух
параллельных незавершённых новых подсистем.

Для обоих изменений: локальные tests → inline review/fixes → независимое review.
Коммит/пуш кода, version bump/build candidate, серверный deploy/TLS provision
и аппаратные проверки — только последующими явно разрешёнными этапами.
Этот документ не является утверждением исправления или аппаратной приёмки.

## Нормативные источники

- [RFC7858: TLS framing, port853, отсутствие plaintext на DoT-порту](https://www.rfc-editor.org/rfc/rfc7858.html#section-3).
- [Android LinkProperties: различие strict hostname и opportunistic Private DNS](https://developer.android.com/reference/android/net/LinkProperties#getPrivateDnsServerName()).
