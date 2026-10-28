use crate::{AuthBroker, BrokerError, LocalAuthStop};
use nelomai_client_api::{ClientApi, LoginRequest, RuntimeTarget};
use nelomai_client_storage::{AuthStore, AuthStoreV1, StorageError, StoredAuth};
use nelomai_contracts::{Platform, RuntimeSlot};
use std::sync::{Arc, Mutex};

struct Memory(Mutex<Option<AuthStoreV1>>);
impl AuthStore for Memory {
    fn load(&self) -> Result<Option<AuthStoreV1>, StorageError> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn save(&self, value: &AuthStoreV1) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = Some(value.clone());
        Ok(())
    }
}
struct Stop;
#[async_trait::async_trait]
impl LocalAuthStop for Stop {
    async fn stop_local(&self) -> Result<(), BrokerError> {
        Ok(())
    }
}
fn broker(base: &str, directory: &std::path::Path) -> AuthBroker {
    let store = Arc::new(Memory(Mutex::new(Some(AuthStoreV1::from_legacy(
        &StoredAuth::new_install(),
    )))));
    AuthBroker::new(ClientApi::new(base).unwrap(), store, Arc::new(Stop))
        .unwrap()
        .with_refresh_diagnostics(directory.to_owned())
}
fn request() -> LoginRequest {
    LoginRequest {
        login: "secret-login".into(),
        password: "secret-password".into(),
        install_secret: "secret-install".into(),
        device_name: "secret-device".into(),
        platform: Platform::Macos,
        platform_version: None,
        architecture: "aarch64".into(),
        app_version: "0.2.16".into(),
    }
}
fn target() -> RuntimeTarget {
    RuntimeTarget {
        container_version: "0.2.16".into(),
        runtime_version: "0.2.16".into(),
        runtime_contract_version: 1,
        runtime_slot: RuntimeSlot::Latest,
    }
}
async fn read_event(dir: &std::path::Path) -> String {
    let file = dir.join("auth-login.jsonl");
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if let Ok(value) = std::fs::read_to_string(&file) {
                return value;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("diagnostic event")
}
#[tokio::test]
async fn login_http_error_persists_safe_category_without_password_or_server_message() {
    use axum::{routing::post, Json, Router};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = Router::new().route("/api/client/v1/auth/login", post(|| async {
        (axum::http::StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"request_id":"secret-request-id", "code":"secret-server-code", "message":"secret-server-message"})))
    }));
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let directory = tempfile::tempdir().unwrap();
    let broker = broker(&base, directory.path());
    assert!(broker.login(&request(), &target()).await.is_err());
    let event = read_event(directory.path()).await;
    let value: serde_json::Value = serde_json::from_str(&event).unwrap();
    assert_eq!(value["kind"], "auth.login.failed");
    assert_eq!(value["code"], "http_server_error");
    assert_eq!(value.as_object().unwrap().len(), 4);
    assert!(!event.contains("secret-"));
    server.abort();
}
#[tokio::test]
async fn refused_connection_is_classified_and_failed_journal_never_changes_login_error() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let directory = tempfile::tempdir().unwrap();
    let broker = broker(&format!("http://{address}"), directory.path());
    assert!(matches!(
        broker.login(&request(), &target()).await,
        Err(BrokerError::Api(_))
    ));
    let event = read_event(directory.path()).await;
    let value: serde_json::Value = serde_json::from_str(&event).unwrap();
    assert_eq!(value["code"], "connect_failed");
    assert!(!event.contains("secret-"));
    let bad = directory.path().join("not-a-directory");
    std::fs::write(&bad, "blocked").unwrap();
    let second = self::broker(&format!("http://{address}"), &bad);
    assert!(matches!(
        second.login(&request(), &target()).await,
        Err(BrokerError::Api(_))
    ));
}
