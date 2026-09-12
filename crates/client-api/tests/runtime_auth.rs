use nelomai_client_api::{
    AccessSnapshot, AuthDevice, ClientApi, LoginRequest, RuntimeLogoutRequest,
    RuntimeResumeRequest, RuntimeSupersedeRequest, RuntimeSwitchReconcileRequest,
    RuntimeSwitchState, RuntimeTarget,
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
async fn release_history_is_public_and_keeps_notes_without_authentication() {
    let (url, requests, handle) = server(json!({"api_version":"1","entries":[
        {"version":"0.2.18","notes":"Первая строка\n<script>literal</script>"}
    ]}));
    let result = ClientApi::new(&url)
        .unwrap()
        .release_history()
        .await
        .unwrap();
    assert_eq!(
        result.entries[0].notes,
        "Первая строка\n<script>literal</script>"
    );
    let request = requests.recv().unwrap().to_lowercase();
    assert!(request.starts_with("get /api/client/v1/releases/changelog "));
    assert!(!request.contains("authorization:"));
    handle.join().unwrap();
}

#[tokio::test]
async fn release_history_rejects_invalid_and_excessive_payloads() {
    for response in [
        json!({"api_version":"2","entries":[]}),
        json!({"api_version":"1","entries":[{"version":"", "notes":"text"}]}),
        json!({"api_version":"1","entries":[{"version":"0.2.18", "notes":"x".repeat(20_001)}]}),
        json!({"api_version":"1","entries":[{"version":"0.2.18", "notes":"a"},{"version":"0.2.18", "notes":"b"}]}),
        json!({"api_version":"1","entries":(0..51).map(|i|json!({"version":format!("0.0.{i}"),"notes":"ok"})).collect::<Vec<_>>()}),
    ] {
        let (url, _requests, handle) = server(response);
        assert!(ClientApi::new(&url)
            .unwrap()
            .release_history()
            .await
            .is_err());
        handle.join().unwrap();
    }
}

#[tokio::test]
async fn release_history_rejects_http_errors_before_reading_their_body() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = [0; 4096];
        stream.read(&mut request).unwrap();
        // No body follows. The advertised size must not trigger buffering or a
        // JSON read: the public command only needs a generic HTTP failure.
        write!(
            stream,
            "HTTP/1.1 503 Unavailable\r\nContent-Length: 100000000\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
    });
    let error = ClientApi::new(&url)
        .unwrap()
        .release_history()
        .await
        .unwrap_err();
    assert!(
        matches!(error, nelomai_client_api::ClientApiError::Transport(error) if error.is_status())
    );
    handle.join().unwrap();
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
    assert!(raw.starts_with("POST /api/client/v1/auth/runtime/resume "));
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

fn reconcile_request(source_identity: Option<RuntimeIdentity>) -> RuntimeSwitchReconcileRequest {
    RuntimeSwitchReconcileRequest {
        operation_id: "11111111-1111-4111-8111-111111111111".into(),
        source_identity,
        target_identity: RuntimeTarget {
            container_version: "0.2.16".into(),
            runtime_version: "0.2.16".into(),
            runtime_contract_version: 1,
            runtime_slot: RuntimeSlot::Latest,
        },
        expected_session_generation: Some(7),
        cleanup_contract_version: 1,
        lease_ids: vec!["lease-1".into()],
        redundant_session_ids: vec!["session-1".into()],
        client_operation_ids: vec!["operation-1".into()],
    }
}

#[tokio::test]
async fn legacy_bootstrap_and_reconcile_strip_every_app_and_runtime_header() {
    let (url, bootstrap_requests, bootstrap) = server(json!({
        "device":{"id":"device","name":"test","platform":"macos",
            "container_version":"legacy","runtime_version":null,
            "runtime_contract_version":null,"runtime_slot":null,
            "session_generation":null}
    }));
    let api = ClientApi::new(&url)
        .unwrap()
        .with_app_version("0.2.16")
        .unwrap();
    let device = api.legacy_bootstrap_device("legacy-access").await.unwrap();
    assert_eq!(device.id, "device");
    let raw = bootstrap_requests
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
    assert!(raw.starts_with("GET /api/client/v1/bootstrap "));
    assert!(raw
        .to_lowercase()
        .contains("authorization: bearer legacy-access"));
    assert!(!raw.to_lowercase().contains("x-nelomai-"));
    bootstrap.join().unwrap();

    let (url, reconcile_requests, reconcile) = server(json!({
        "state":"clean", "operation_id":"11111111-1111-4111-8111-111111111111",
        "retired_lease_ids":["lease-1"], "retired_session_ids":["session-1"],
        "retired_operation_ids":["operation-1"], "retry_after_seconds":null
    }));
    let mut request = reconcile_request(None);
    request.expected_session_generation = None;
    let response = ClientApi::new(&url)
        .unwrap()
        .with_app_version("0.2.16")
        .unwrap()
        .reconcile_runtime_switch("legacy-access", &request)
        .await
        .unwrap();
    assert_eq!(response.state, RuntimeSwitchState::Clean);
    let raw = reconcile_requests
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
    assert!(raw.starts_with("POST /api/client/v1/connections/runtime-switch/reconcile "));
    assert!(raw
        .to_lowercase()
        .contains("authorization: bearer legacy-access"));
    assert!(!raw.to_lowercase().contains("x-nelomai-"));
    let body: Value = serde_json::from_str(raw.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert!(body["source_identity"].is_null());
    assert!(body["expected_session_generation"].is_null());
    assert_eq!(body["target_identity"]["runtime_slot"], "latest");
    assert!(body["target_identity"].get("slot").is_none());
    reconcile.join().unwrap();
}

#[tokio::test]
async fn enrolled_reconcile_uses_only_the_captured_source_for_headers() {
    let (url, requests, handle) = server(json!({
        "state":"retry", "operation_id":"11111111-1111-4111-8111-111111111111",
        "retired_lease_ids":[], "retired_session_ids":[],
        "retired_operation_ids":[], "retry_after_seconds":1
    }));
    let snapshot = AccessSnapshot::new(
        "source-access".into(),
        identity(),
        3,
        "source-family".into(),
    )
    .unwrap();
    let api = ClientApi::new(&url)
        .unwrap()
        .with_app_version("9.9.9")
        .unwrap()
        .with_captured_source(&snapshot)
        .unwrap();
    let response = api
        .reconcile_runtime_switch(
            snapshot.access_token(),
            &reconcile_request(Some(identity())),
        )
        .await
        .unwrap();
    assert_eq!(response.state, RuntimeSwitchState::Retry);
    let raw = requests.recv_timeout(Duration::from_secs(5)).unwrap();
    let lower = raw.to_lowercase();
    assert!(lower.contains("authorization: bearer source-access"));
    assert!(lower.contains("x-nelomai-app-version: 0.2.16"));
    assert!(!lower.contains("x-nelomai-app-version: 9.9.9"));
    let body: Value = serde_json::from_str(raw.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(body["source_identity"]["runtime_slot"], "stable");
    assert!(body["source_identity"].get("slot").is_none());
    assert_eq!(body["source_identity"]["session_generation"], 7);
    assert_eq!(body["target_identity"]["runtime_slot"], "latest");
    handle.join().unwrap();
}

#[tokio::test]
async fn reconcile_retry_hint_is_nullable_and_supersede_uses_the_actual_refresh_route() {
    let (url, requests, handle) = server(json!({
        "state":"retry", "operation_id":"11111111-1111-4111-8111-111111111111",
        "retired_lease_ids":[], "retired_session_ids":[],
        "retired_operation_ids":[], "retry_after_seconds":null
    }));
    let api = ClientApi::new(&url).unwrap();
    let mut reconcile = reconcile_request(None);
    reconcile.expected_session_generation = None;
    assert_eq!(
        api.reconcile_runtime_switch("legacy-access", &reconcile)
            .await
            .unwrap()
            .state,
        RuntimeSwitchState::Retry
    );
    requests.recv_timeout(Duration::from_secs(5)).unwrap();
    handle.join().unwrap();

    let (url, requests, handle) = server(json!({
        "state":"clean",
        "reconcile_operation_id":"33333333-3333-4333-8333-333333333333",
        "retry_after_seconds":null
    }));
    let request = RuntimeSupersedeRequest {
        refresh_token: "source-refresh".into(),
        operation_id: "22222222-2222-4222-8222-222222222222".into(),
        superseded_reconcile_operation_id: "11111111-1111-4111-8111-111111111111".into(),
        expected_session_generation: Some(7),
        target_identity: reconcile.target_identity,
    };
    let response = ClientApi::new(&url)
        .unwrap()
        .supersede_runtime(&request)
        .await
        .unwrap();
    assert_eq!(
        response.reconcile_operation_id,
        "33333333-3333-4333-8333-333333333333"
    );
    let raw = requests.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(raw.starts_with("POST /api/client/v1/auth/runtime/supersede "));
    assert!(!raw.to_lowercase().contains("authorization:"));
    assert!(!format!("{request:?}").contains("source-refresh"));
    handle.join().unwrap();
}

#[tokio::test]
async fn reconcile_accepts_the_server_full_device_snapshot_beyond_local_hints() {
    let (url, requests, handle) = server(json!({
        "state":"clean", "operation_id":"11111111-1111-4111-8111-111111111111",
        "retired_lease_ids":["server-lease"], "retired_session_ids":["server-session"],
        "retired_operation_ids":["server-operation"], "retry_after_seconds":null
    }));
    let mut request = reconcile_request(None);
    request.expected_session_generation = None;
    request.lease_ids.clear();
    request.redundant_session_ids.clear();
    request.client_operation_ids.clear();
    let response = ClientApi::new(&url)
        .unwrap()
        .reconcile_runtime_switch("legacy-access", &request)
        .await
        .unwrap();
    assert_eq!(response.retired_lease_ids, ["server-lease"]);
    assert_eq!(response.retired_session_ids, ["server-session"]);
    assert_eq!(response.retired_operation_ids, ["server-operation"]);
    requests.recv_timeout(Duration::from_secs(5)).unwrap();
    handle.join().unwrap();
}

#[tokio::test]
async fn reconcile_still_rejects_wrong_operation_invalid_ids_and_oversized_snapshots() {
    let cases = [
        json!({
            "state":"clean", "operation_id":"22222222-2222-4222-8222-222222222222",
            "retired_lease_ids":[], "retired_session_ids":[],
            "retired_operation_ids":[], "retry_after_seconds":null
        }),
        json!({
            "state":"clean", "operation_id":"11111111-1111-4111-8111-111111111111",
            "retired_lease_ids":["duplicate","duplicate"], "retired_session_ids":[],
            "retired_operation_ids":[], "retry_after_seconds":null
        }),
        json!({
            "state":"clean", "operation_id":"11111111-1111-4111-8111-111111111111",
            "retired_lease_ids":(0..1025).map(|index| format!("lease-{index}")).collect::<Vec<_>>(),
            "retired_session_ids":[], "retired_operation_ids":[], "retry_after_seconds":null
        }),
    ];
    for body in cases {
        let (url, requests, handle) = server(body);
        let mut request = reconcile_request(None);
        request.expected_session_generation = None;
        assert_eq!(
            ClientApi::new(&url)
                .unwrap()
                .reconcile_runtime_switch("legacy-access", &request)
                .await
                .unwrap_err()
                .stable_code(),
            Some("invalid_runtime_switch_response")
        );
        requests.recv_timeout(Duration::from_secs(5)).unwrap();
        handle.join().unwrap();
    }
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
