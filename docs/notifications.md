# Уведомления приложения

Панель хранит единый пользовательский inbox. Windows, macOS и Linux получают
его при открытии приложения и обновляют список, пока окно активно. Android
использует тот же inbox и дополнительно получает FCM push, который только
сообщает о новой записи: потеря push не приводит к потере уведомления.

## Android build

Для сборки с push задаются публичные параметры Android-приложения из Firebase:

```text
NELOMAI_FIREBASE_APPLICATION_ID=1:...:android:...
NELOMAI_FIREBASE_API_KEY=...
NELOMAI_FIREBASE_PROJECT_ID=...
```

Android-приложение в Firebase регистрируется с package ID
`ru.nelomai.client`.

В GitHub они хранятся как repository secrets с теми же именами. Release workflow
останавливает Android-сборку, если любой параметр отсутствует. Эти значения не
дают серверных прав Firebase; service account в репозиторий приложения не
добавляется.

Android запрашивает разрешение на уведомления после успешного входа. FCM token
связывается с текущим устройством, обновляется при последующих запусках и
удаляется на панели при выходе из аккаунта.

## Panel delivery

Панели нужны отдельные серверные параметры:

```text
APP_PUSH_ENABLED=true
APP_PUSH_FIREBASE_PROJECT_ID=...
APP_PUSH_FIREBASE_SERVICE_ACCOUNT=/run/secrets/nelomai-firebase-service-account.json
```

Service account должен иметь только право отправки Firebase Cloud Messaging.
Файл хранится вне Git и читается только пользователем службы панели.
