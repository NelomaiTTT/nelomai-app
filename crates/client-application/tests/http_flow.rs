use async_trait::async_trait;
use axum::{
    extract::{Query, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use nelomai_client_api::ClientApi;
use nelomai_client_application::{ClientApplication, LoginParameters};
use nelomai_client_core::{ConnectOptions, NoopLogger, Phase};
use nelomai_client_storage::{SecretStore, StorageError, StoredAuth};
use nelomai_client_tunnel::{TunnelConfiguration, TunnelController, TunnelError, TunnelStatus};
use nelomai_contracts::{BindPeerRequest, Layer, Platform, RouteMode, TicConnectionMode};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

const NOW: i64 = 1_800_000_000;
const LEASE_ID: &str = "11111111-1111-4111-8111-111111111111";
const CONFIGURATION: &str = "[Interface]\nPrivateKey = native-only-e2e-secret\n";

#[derive(Default)]
struct MockPanelState {
    base_url: Mutex<String>,
    bound: AtomicBool,
    candidate_requests: AtomicUsize,
    probe_requests: AtomicUsize,
    start_operations: Mutex<Vec<String>>,
    pinned: AtomicBool,
}

#[derive(Default)]
struct MemoryStore(Mutex<Option<StoredAuth>>);

impl SecretStore for MemoryStore {
    fn load(&self) -> Result<Option<StoredAuth>, StorageError> {
        Ok(self.0.lock().unwrap().clone())
    }

    fn save(&self, auth: &StoredAuth) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = Some(auth.clone());
        Ok(())
    }

    fn delete(&self) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

#[derive(Default)]
struct RecordingTunnel {
    configurations: Mutex<Vec<String>>,
    status: Mutex<TunnelStatus>,
}

#[async_trait]
impl TunnelController for RecordingTunnel {
    async fn start(&self, configuration: TunnelConfiguration) -> Result<(), TunnelError> {
        self.configurations
            .lock()
            .unwrap()
            .push(configuration.expose().to_string());
        *self.status.lock().unwrap() = TunnelStatus::Running;
        Ok(())
    }

    async fn stop(&self) -> Result<(), TunnelError> {
        *self.status.lock().unwrap() = TunnelStatus::Stopped;
        Ok(())
    }

    async fn status(&self) -> Result<TunnelStatus, TunnelError> {
        Ok(*self.status.lock().unwrap())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_http_client_completes_dynamic_stray_warm_reconnect_flow() {
    let panel_state = Arc::new(MockPanelState::default());
    let router = Router::new()
        .route("/api/client/v1/auth/login", post(login))
        .route("/api/client/v1/auth/logout", post(logout))
        .route("/api/client/v1/bootstrap", get(bootstrap))
        .route("/api/client/v1/peer-options", get(peer_options))
        .route("/api/client/v1/device/bind-peer", post(bind_peer))
        .route("/api/client/v1/device/unbind-peer", post(unbind_peer))
        .route("/api/client/v1/server-candidates", get(server_candidates))
        .route("/api/client/v1/connections/start", post(start_connection))
        .route("/api/client/v1/connections/stop", post(stop_connection))
        .route("/api/client/v1/connections/pin-stray", post(pin_stray))
        .route("/api/client/v1/connections/unpin-stray", post(unpin_stray))
        .route("/probe/stray", get(probe))
        .with_state(panel_state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    *panel_state.base_url.lock().unwrap() = base_url.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    let api = Arc::new(ClientApi::new(&base_url).unwrap());
    let store = Arc::new(MemoryStore::default());
    let tunnel = Arc::new(RecordingTunnel::default());
    let application =
        ClientApplication::new(api, store.clone(), tunnel.clone(), Arc::new(NoopLogger));

    let initial = application
        .login(
            LoginParameters {
                login: "test".to_string(),
                password: "password".to_string(),
                device_name: "Test Mac".to_string(),
                platform: Platform::Macos,
                platform_version: Some("15.5".to_string()),
                architecture: "aarch64".to_string(),
                app_version: "0.1.0".to_string(),
            },
            NOW,
        )
        .await
        .unwrap();
    assert!(initial.binding.is_none());
    assert_eq!(application.state().await.phase, Phase::NeedsPeerBinding);

    let peers = application.peer_options().await.unwrap();
    assert_eq!(peers.peers[0].id, "3");
    assert_eq!(peers.peers[0].comment.as_deref(), Some("Ноутбук"));

    application
        .bind_peer(BindPeerRequest {
            peer_id: "3".to_string(),
            preferred_layer: Layer::Stray,
            tic_connection_mode: TicConnectionMode::Dynamic,
            route_mode: RouteMode::Standalone,
        })
        .await
        .unwrap();
    let ready = application.bootstrap(NOW).await.unwrap();
    assert!(ready.binding.is_some());
    assert_eq!(application.state().await.phase, Phase::Ready);

    let options = ConnectOptions {
        layer: Layer::Stray,
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: RouteMode::Standalone,
        probes: Vec::new(),
        allow_alternate: true,
    };
    let first = application.start(options.clone(), NOW).await.unwrap();
    assert_eq!(first.lease_id, LEASE_ID);
    assert_eq!(application.state().await.phase, Phase::Connected);
    let pinned = application.pin_stray().await.unwrap();
    assert!(pinned.pinned);
    assert!(store.load().unwrap().unwrap().pinned_connection.is_some());

    let stopped = application.stop().await.unwrap();
    assert_eq!(stopped.lease_id, LEASE_ID);
    assert_eq!(application.state().await.phase, Phase::Ready);

    let second = application.start(options, NOW + 30).await.unwrap();
    assert_eq!(second.lease_id, LEASE_ID);
    assert!(second.pinned);
    let unpinned = application.unpin_stray(LEASE_ID, NOW + 30).await.unwrap();
    assert!(!unpinned.pinned);
    assert_eq!(
        tunnel.configurations.lock().unwrap().as_slice(),
        [CONFIGURATION, CONFIGURATION]
    );
    assert_eq!(panel_state.candidate_requests.load(Ordering::SeqCst), 1);
    assert_eq!(panel_state.probe_requests.load(Ordering::SeqCst), 1);
    assert_eq!(
        panel_state.start_operations.lock().unwrap()[1],
        LEASE_ID,
        "warm reconnect must reuse the panel lease id"
    );

    let unbound = application.unbind_peer().await.unwrap();
    assert!(unbound.binding.is_none());
    assert_eq!(application.state().await.phase, Phase::NeedsPeerBinding);
    let stored = store.load().unwrap().unwrap();
    assert!(stored.saved_connection.is_none());
    assert!(stored.pinned_connection.is_none());

    application.logout().await.unwrap();
    let stored = store.load().unwrap().unwrap();
    assert!(stored.access_token.is_none());
    assert!(stored.refresh_token.is_none());
    assert!(!stored.install_secret.is_empty());
    assert_eq!(application.state().await.phase, Phase::SignedOut);

    server.abort();
}

async fn login(State(_state): State<Arc<MockPanelState>>, Json(body): Json<Value>) -> Json<Value> {
    assert_eq!(body["login"], "test");
    assert_eq!(body["password"], "password");
    assert_eq!(body["device_name"], "Test Mac");
    assert_eq!(body["platform"], "macos");
    assert!(body["install_secret"].as_str().unwrap().len() >= 43);
    Json(json!({
        "api_version": "1",
        "request_id": "login-request",
        "token_type": "Bearer",
        "access_token": "access-token",
        "access_expires_in": 900,
        "refresh_token": "refresh-token",
        "refresh_expires_in": 7_776_000,
        "access": active_access(),
        "device": {
            "id": "device-1",
            "name": "Test Mac",
            "platform": "macos"
        }
    }))
}

async fn logout(headers: HeaderMap) -> Json<Value> {
    assert_authenticated(&headers);
    Json(json!({
        "api_version": "1",
        "request_id": "logout-request",
        "ok": true
    }))
}

async fn bootstrap(State(state): State<Arc<MockPanelState>>, headers: HeaderMap) -> Json<Value> {
    assert_authenticated(&headers);
    let binding = state.bound.load(Ordering::SeqCst).then(binding);
    Json(json!({
        "api_version": "1",
        "request_id": "bootstrap-request",
        "access": active_access(),
        "device": {
            "id": "device-1",
            "name": "Test Mac",
            "platform": "macos"
        },
        "binding": binding,
        "connection": null,
        "pinned_stray": null,
        "defaults": {
            "layer": "stray",
            "tic_connection_mode": "dynamic",
            "route_mode": "standalone"
        },
        "update": {
            "current_version": "0.1.0",
            "minimum_version": null,
            "update_available": false,
            "required": false,
            "release_notes": null
        }
    }))
}

async fn peer_options(headers: HeaderMap) -> Json<Value> {
    assert_authenticated(&headers);
    Json(json!({
        "api_version": "1",
        "request_id": "peer-options-request",
        "peers": [
            {
                "id": "4",
                "interface_id": "1",
                "interface_name": "Основной",
                "slot": 4,
                "name": "Основной · Пир 4",
                "comment": "Старое устройство",
                "last_handshake_at": "2026-07-25T12:00:00Z",
                "bound_to_app": false,
                "bound_to_this_device": false,
                "selectable": true
            },
            {
                "id": "3",
                "interface_id": "1",
                "interface_name": "Основной",
                "slot": 3,
                "name": "Основной · Пир 3",
                "comment": "Ноутбук",
                "last_handshake_at": null,
                "bound_to_app": false,
                "bound_to_this_device": false,
                "selectable": true
            }
        ]
    }))
}

async fn bind_peer(
    State(state): State<Arc<MockPanelState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    assert_authenticated(&headers);
    assert_eq!(body["peer_id"], "3");
    assert_eq!(body["preferred_layer"], "stray");
    state.bound.store(true, Ordering::SeqCst);
    Json(json!({
        "api_version": "1",
        "request_id": "bind-request",
        "binding": binding(),
        "configuration": null
    }))
}

async fn unbind_peer(State(state): State<Arc<MockPanelState>>, headers: HeaderMap) -> Json<Value> {
    assert_authenticated(&headers);
    state.bound.store(false, Ordering::SeqCst);
    state.pinned.store(false, Ordering::SeqCst);
    Json(json!({
        "api_version": "1",
        "request_id": "unbind-request",
        "binding": null,
        "configuration": null
    }))
}

async fn server_candidates(
    State(state): State<Arc<MockPanelState>>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_authenticated(&headers);
    assert_eq!(query.get("layer").map(String::as_str), Some("stray"));
    state.candidate_requests.fetch_add(1, Ordering::SeqCst);
    let probe_url = format!("{}/probe/stray", state.base_url.lock().unwrap());
    Json(json!({
        "api_version": "1",
        "request_id": "candidate-request",
        "candidates": [{
            "candidate_id": "opaque-candidate-token-e2e",
            "layer": "stray",
            "region_label": "Тест",
            "probe_url": probe_url,
            "expires_at": "2030-01-01T00:00:00Z"
        }]
    }))
}

async fn probe(State(state): State<Arc<MockPanelState>>, headers: HeaderMap) -> StatusCode {
    assert!(
        headers.get(AUTHORIZATION).is_none(),
        "probe endpoint must not receive an access token"
    );
    state.probe_requests.fetch_add(1, Ordering::SeqCst);
    StatusCode::NO_CONTENT
}

async fn start_connection(
    State(state): State<Arc<MockPanelState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    assert_authenticated(&headers);
    assert_eq!(body["layer"], "stray");
    assert_eq!(body["tic_connection_mode"], "dynamic");
    assert_eq!(body["route_mode"], "standalone");
    assert_eq!(
        body["probes"][0]["candidate_id"],
        "opaque-candidate-token-e2e"
    );
    let operation_id = body["operation_id"].as_str().unwrap().to_string();
    let mut operations = state.start_operations.lock().unwrap();
    let reused = !operations.is_empty();
    operations.push(operation_id);
    let pinned = state.pinned.load(Ordering::SeqCst);
    Json(json!({
        "api_version": "1",
        "request_id": "start-request",
        "connection": connection("issued", pinned),
        "configuration": CONFIGURATION,
        "reused": reused
    }))
}

async fn stop_connection(
    State(state): State<Arc<MockPanelState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    assert_authenticated(&headers);
    assert_eq!(body["lease_id"], LEASE_ID);
    let pinned = state.pinned.load(Ordering::SeqCst);
    Json(json!({
        "api_version": "1",
        "request_id": "stop-request",
        "connection": connection("warm", pinned)
    }))
}

async fn pin_stray(
    State(state): State<Arc<MockPanelState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    assert_authenticated(&headers);
    assert_eq!(body["lease_id"], LEASE_ID);
    state.pinned.store(true, Ordering::SeqCst);
    Json(json!({
        "api_version": "1",
        "request_id": "pin-request",
        "connection": connection("connected", true)
    }))
}

async fn unpin_stray(
    State(state): State<Arc<MockPanelState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    assert_authenticated(&headers);
    assert_eq!(body["lease_id"], LEASE_ID);
    state.pinned.store(false, Ordering::SeqCst);
    Json(json!({
        "api_version": "1",
        "request_id": "unpin-request",
        "connection": connection("connected", false)
    }))
}

fn active_access() -> Value {
    json!({
        "state": "active",
        "can_login": true,
        "can_connect": true,
        "expires_at": "2030-01-01T00:00:00Z"
    })
}

fn binding() -> Value {
    json!({
        "id": "binding-1",
        "peer_id": "3",
        "interface_id": "1",
        "interface_name": "Основной",
        "slot": 3,
        "preferred_layer": "stray",
        "tic_connection_mode": "dynamic",
        "route_mode": "standalone"
    })
}

fn connection(status: &str, pinned: bool) -> Value {
    json!({
        "lease_id": LEASE_ID,
        "layer": "stray",
        "tic_connection_mode": "dynamic",
        "route_mode": "standalone",
        "status": status,
        "pinned": pinned,
        "stopped_at": (status == "warm").then_some("2027-01-15T08:00:30Z")
    })
}

fn assert_authenticated(headers: &HeaderMap) {
    assert_eq!(
        headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer access-token")
    );
}
