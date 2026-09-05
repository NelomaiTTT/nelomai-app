use nelomai_client_api::{
    AccessSnapshot, AuthDevice, ClientApi, LoginRequest, RuntimeLogoutRequest,
    RuntimeResumeRequest, RuntimeTarget,
};
use nelomai_contracts::{Platform, RuntimeIdentity, RuntimeSlot};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::mpsc,
    thread,
    time::Duration,
};

fn identity() -> RuntimeIdentity {
    RuntimeIdentity {
        container_version: "0.2.16".into(),
        runtime_version: "0.2.15".into(),
        runtime_contract_version: 1,
        slot: RuntimeSlot::Stable,
        session_generation: Some(7),
    }
}

#[test]
fn captured_bearer_headers_keep_all_identity_fields_for_update_requests() {
    let snapshot = AccessSnapshot::new(
        "synthetic-access".into(),
        identity(),
        4,
        "synthetic-family".into(),
    )
    .unwrap();
    let headers = snapshot.bearer_headers();
    assert_eq!(
        headers,
        [
            ("authorization", "Bearer synthetic-access".into()),
            ("x-nelomai-app-version", "0.2.16".into()),
            ("x-nelomai-container-version", "0.2.16".into()),
            ("x-nelomai-runtime-version", "0.2.15".into()),
            ("x-nelomai-runtime-contract-version", "1".into()),
            ("x-nelomai-runtime-slot", "stable".into()),
            ("x-nelomai-session-generation", "7".into()),
        ]
    );
}

// The real request boundary must encode the panel contract, not just a builder.
fn server(response: Value) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (send, receive) = mpsc::channel();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        loop {
            let mut chunk = [0; 4096];
            let n = stream.read(&mut chunk).unwrap();
            assert_ne!(n, 0);
            bytes.extend_from_slice(&chunk[..n]);
            if let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
                let len = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .map(|s| s.parse::<usize>().unwrap())
                    .unwrap_or(0);
                if bytes.len() >= end + 4 + len {
                    break;
                }
            }
        }
        send.send(String::from_utf8(bytes).unwrap()).unwrap();
        let body = response.to_string();
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    });
    (url, receive, handle)
}

fn token_response() -> Value {
    json!({"api_version":"1","request_id":"synthetic","token_type":"Bearer",
        "access_token":"synthetic-access","access_expires_in":900,
        "refresh_token":"synthetic-refresh","refresh_expires_in":3600,
        "access":{"state":"active","can_login":true,"can_connect":true,"expires_at":null},
        "device":{"id":"device","name":"test","platform":"macos",
            "container_version":"0.2.16","runtime_version":"0.2.15",
            "runtime_contract_version":1,"runtime_slot":"stable","session_generation":7}})
}

#[tokio::test]
async fn runtime_login_sends_exact_target_without_client_generation() {
    let (url, requests, handle) = server(token_response());
    let api = ClientApi::new(&url).unwrap();
    let result = api
        .login_runtime(
            &LoginRequest {
                login: "test".into(),
                password: "synthetic-password".into(),
                install_secret: "synthetic-install".into(),
                device_name: "test".into(),
                platform: Platform::Macos,
                platform_version: None,
                architecture: "aarch64".into(),
                app_version: "0.0.1".into(),
            },
            &RuntimeTarget::from_identity(&identity()),
        )
        .await
        .unwrap();
    let request = requests.recv_timeout(Duration::from_secs(5)).unwrap();
    let body: Value = serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(body["app_version"], "0.2.16");
    assert_eq!(body["container_version"], "0.2.16");
    assert_eq!(body["runtime_version"], "0.2.15");
    assert_eq!(body["runtime_contract_version"], 1);
    assert_eq!(body["runtime_slot"], "stable");
    assert!(body.get("slot").is_none());
    assert!(body.get("session_generation").is_none());
    assert_eq!(result.device.confirmed_identity().unwrap(), identity());
    handle.join().unwrap();
}

#[tokio::test]
async fn immutable_snapshot_reaches_bootstrap_and_non_bootstrap_bearer_boundary() {
    for bootstrap in [true, false] {
        let (url, requests, handle) = server(
            json!({"api_version":"1","request_id":"s","token":"background","expires_in":60}),
        );
        let snapshot =
            AccessSnapshot::new("synthetic-access".into(), identity(), 3, "family".into()).unwrap();
        let api = ClientApi::new(&url)
            .unwrap()
            .with_access_snapshot(&snapshot)
            .unwrap();
        // JSON decoding need not succeed for bootstrap: assertions concern sent HTTP.
        if bootstrap {
            let _ = api.bootstrap("synthetic-access").await;
        } else {
            api.background_token("synthetic-access").await.unwrap();
        }
        let request = requests
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .to_lowercase();
        for header in [
            "authorization: bearer synthetic-access",
            "x-nelomai-container-version: 0.2.16",
            "x-nelomai-app-version: 0.2.16",
            "x-nelomai-runtime-version: 0.2.15",
            "x-nelomai-runtime-contract-version: 1",
            "x-nelomai-runtime-slot: stable",
            "x-nelomai-session-generation: 7",
        ] {
            assert!(request.contains(header), "missing {header}");
        }
        handle.join().unwrap();
    }
}

#[tokio::test]
async fn scoped_client_rejects_token_or_identity_rebinding_before_http() {
    let snapshot =
        AccessSnapshot::new("synthetic-access".into(), identity(), 3, "family".into()).unwrap();
    let api = ClientApi::new("http://127.0.0.1:1")
        .unwrap()
        .with_access_snapshot(&snapshot)
        .unwrap();
    assert_eq!(
        api.background_token("other-access")
            .await
            .unwrap_err()
            .stable_code(),
        Some("runtime_access_mismatch")
    );
    let mut other = identity();
    other.session_generation = Some(8);
    assert!(api.clone().with_runtime_identity(other).is_err());
    assert!(api.with_app_version("0.3.0").is_err());
    let mut unenrolled = identity();
    unenrolled.session_generation = None;
    assert!(AccessSnapshot::new("access".into(), unenrolled, 0, "family".into()).is_err());
    assert!(!format!("{snapshot:?}").contains("synthetic-access"));
}

#[test]
fn incomplete_or_legacy_device_identity_is_not_enrolled() {
    let old: AuthDevice =
        serde_json::from_value(json!({"id":"d","name":"d","platform":"macos"})).unwrap();
    assert!(old.confirmed_identity().is_err());
    let mut partial = token_response()["device"].clone();
    partial
        .as_object_mut()
        .unwrap()
        .remove("runtime_contract_version");
    let device: AuthDevice = serde_json::from_value(partial).unwrap();
    assert!(device.confirmed_identity().is_err());
}

#[tokio::test]
async fn resume_is_refresh_only_and_decodes_the_actual_response_shape() {
    let (url, requests, handle) = server(json!({"identity":{"container_version":"0.2.16",
        "runtime_version":"0.2.15","runtime_contract_version":1,"runtime_slot":"stable","session_generation":8},
        "access_token":"resumed-access","token_type":"Bearer","access_expires_in":900}));
    let request = RuntimeResumeRequest {
        refresh_token: "synthetic-refresh".into(),
        operation_id: "11111111-1111-4111-8111-111111111111".into(),
        expected_session_generation: Some(7),
        target_identity: RuntimeTarget::from_identity(&identity()),
        reconcile_operation_id: "22222222-2222-4222-8222-222222222222".into(),
        decision: "apply".into(),
    };
    let result = ClientApi::new(&url)
        .unwrap()
        .resume_runtime(&request)
        .await
        .unwrap();
    assert_eq!(result.identity.session_generation, Some(8));
    assert_eq!(result.access_token, "resumed-access");
    let raw = requests.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(raw.starts_with("POST /api/client/v1/runtime/resume "));
    assert!(!raw.to_lowercase().contains("authorization:"));
    let body: Value = serde_json::from_str(raw.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(
        body["target_identity"],
        json!({"container_version":"0.2.16","runtime_version":"0.2.15","runtime_contract_version":1,"runtime_slot":"stable"})
    );
    assert_eq!(body["operation_id"], "11111111-1111-4111-8111-111111111111");
    assert!(!format!("{request:?} {result:?}").contains("synthetic-refresh"));
    assert!(!format!("{result:?}").contains("resumed-access"));
    handle.join().unwrap();
}

#[tokio::test]
async fn logout_uses_protected_proof_endpoint_and_actual_ack_shape() {
    let (url, requests, handle) = server(
        json!({"code":"session_revoked_cleanup_accepted","cleanup_reconcile_operation_id":"cleanup"}),
    );
    let request = RuntimeLogoutRequest {
        operation_id: "11111111-1111-4111-8111-111111111111".into(),
        refresh_token: "logout-proof".into(),
    };
    let response = ClientApi::new(&url)
        .unwrap()
        .logout_runtime(&request)
        .await
        .unwrap();
    assert_eq!(response.code, "session_revoked_cleanup_accepted");
    let raw = requests.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(raw.starts_with("POST /api/client/v1/auth/logout-runtime "));
    assert!(!raw.to_lowercase().contains("authorization:"));
    assert!(!format!("{request:?}").contains("logout-proof"));
    handle.join().unwrap();
}
