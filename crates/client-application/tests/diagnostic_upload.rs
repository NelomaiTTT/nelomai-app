use axum::{http::StatusCode, routing::post, Router};
use nelomai_client_api::{AccessSnapshot, ClientApi, DiagnosticUploadRequest};
use nelomai_client_application::ApplicationApi;
use nelomai_client_core::CoreApiError;
use nelomai_contracts::{RuntimeIdentity, RuntimeSlot};
use serde_json::json;
use std::time::Duration;

fn access() -> AccessSnapshot {
    AccessSnapshot::new(
        "synthetic-secret-token".into(),
        RuntimeIdentity {
            container_version: "0.4.0".into(),
            runtime_version: "0.4.0".into(),
            runtime_contract_version: 1,
            slot: RuntimeSlot::Latest,
            session_generation: Some(1),
        },
        1,
        "synthetic-family".into(),
    )
    .unwrap()
}

fn report() -> DiagnosticUploadRequest {
    serde_json::from_value(json!({
        "trigger":"tunnel_stopped", "generated_at_unix":1800000000,
        "app_version":"0.4.0", "architecture":"aarch64",
        "application_log":"synthetic-private-report"
    }))
    .unwrap()
}

fn assert_failure(error: CoreApiError, expected: &str) {
    let CoreApiError::Rejected { code, message, .. } = error else {
        panic!("diagnostic failure category was discarded: {error:?}");
    };
    assert_eq!(code, expected);
    assert!(!message.contains("synthetic"));
    assert!(!message.contains("127.0.0.1"));
}

// These go through the real HTTP client AND ApplicationApi adapter: reverting
// the adapter to the generic conversion loses the actionable failure category.
#[tokio::test]
async fn diagnostic_upload_distinguishes_http_status_and_invalid_response() {
    for (status, body, expected) in [
        (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"api_version":"1","request_id":"synthetic","code":"synthetic-secret-code","message":"synthetic-private-message"}"#,
            "diagnostics_http_503",
        ),
        (
            StatusCode::BAD_GATEWAY,
            "synthetic-private-proxy-error",
            "diagnostics_http_502",
        ),
        (
            StatusCode::OK,
            "synthetic-private-invalid-json",
            "diagnostics_response_decode_failed",
        ),
    ] {
        let router = Router::new().route(
            "/api/client/v1/diagnostics",
            post(move || async move { (status, body) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let error = ApplicationApi::upload_diagnostics(&api, &access(), &report())
            .await
            .unwrap_err();
        server.abort();
        assert_failure(error, expected);
    }
}

#[tokio::test]
async fn diagnostic_upload_distinguishes_connection_failure() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    drop(listener);
    let error = ApplicationApi::upload_diagnostics(&api, &access(), &report())
        .await
        .unwrap_err();
    assert_failure(error, "diagnostics_connect_failed");
}

#[tokio::test]
async fn diagnostic_upload_keeps_authentication_recovery_signals() {
    for (status, code) in [
        (StatusCode::UNAUTHORIZED, "invalid_token"),
        (StatusCode::FORBIDDEN, "access_expired"),
        (StatusCode::UNAUTHORIZED, "invalid_credentials"),
    ] {
        let router = Router::new().route(
            "/api/client/v1/diagnostics",
            post(move || async move {
                (
                    status,
                    axum::Json(json!({"request_id":"synthetic", "code":code,
                    "message":"synthetic-private-message"})),
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let error = ApplicationApi::upload_diagnostics(&api, &access(), &report())
            .await
            .unwrap_err();
        server.abort();
        if code == "invalid_credentials" {
            assert_failure(error, "invalid_credentials");
        } else if status == StatusCode::UNAUTHORIZED {
            assert_eq!(error, CoreApiError::Unauthorized);
        } else {
            assert_eq!(error, CoreApiError::AccessExpired);
        }
    }
}

#[tokio::test]
async fn diagnostic_upload_distinguishes_request_timeout() {
    let router = Router::new().route(
        "/api/client/v1/diagnostics",
        post(|| async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            "unreachable response"
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let error = ApplicationApi::upload_diagnostics(&api, &access(), &report())
        .await
        .unwrap_err();
    server.abort();
    assert_failure(error, "diagnostics_timeout");
}
