//! Synthetic compatibility fixtures only. Production Core receives two separate
//! capabilities; these adapters preserve pre-existing operational fault tests.
#![allow(dead_code)] // Shared across suites which use different fixture portions.
use async_trait::async_trait;
use nelomai_client_api::{
    AccessSnapshot, ClientApi, LoginRequest, RuntimeAuthState, RuntimeLogin, TokenResponse,
};
use nelomai_client_core::{
    ClientCore, CoreApi, CoreApiError, CoreError, CoreLocalStop, CoreLogger, RuntimeAuthProvider,
};
use nelomai_client_storage::{
    RuntimePaths, RuntimeStateStore, RuntimeStateV1, SecretStore, SplitTunnelStore, StorageError,
    StoredAuth, StoredSplitTunnelState,
};
use nelomai_client_tunnel::TunnelController;
use nelomai_contracts::{Platform, RuntimeIdentity, RuntimeSlot};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use tokio::sync::Mutex;

#[async_trait]
pub trait TestAuthApi: Send + Sync {
    async fn refresh(&self, token: &str) -> Result<TokenResponse, CoreApiError>;
    async fn login(&self, _: &LoginRequest) -> Result<TokenResponse, CoreApiError> {
        Err(CoreApiError::Unauthorized)
    }
    async fn logout(&self, _: &str) -> Result<(), CoreApiError> {
        Ok(())
    }
}
#[async_trait]
impl TestAuthApi for ClientApi {
    async fn refresh(&self, token: &str) -> Result<TokenResponse, CoreApiError> {
        ClientApi::refresh(self, token.to_owned())
            .await
            .map_err(Into::into)
    }
    async fn login(&self, request: &LoginRequest) -> Result<TokenResponse, CoreApiError> {
        ClientApi::login(self, request).await.map_err(Into::into)
    }
    async fn logout(&self, token: &str) -> Result<(), CoreApiError> {
        ClientApi::logout(self, token)
            .await
            .map(|_| ())
            .map_err(Into::into)
    }
}

pub fn snapshot(token: &str) -> AccessSnapshot {
    snapshot_at(token, 0)
}
fn snapshot_at(token: &str, epoch: u64) -> AccessSnapshot {
    AccessSnapshot::new(
        token.into(),
        RuntimeIdentity {
            slot: RuntimeSlot::Stable,
            runtime_version: "0.2.16".into(),
            container_version: "0.2.16".into(),
            runtime_contract_version: 1,
            session_generation: Some(1),
        },
        epoch,
        "synthetic-family".into(),
    )
    .unwrap()
}

pub struct LegacyRuntime<S> {
    source: Arc<S>,
    paths: RuntimePaths,
}
impl<S> LegacyRuntime<S> {
    pub fn new(source: Arc<S>) -> Self {
        Self {
            source,
            paths: RuntimePaths::new(
                "/synthetic-no-filesystem-access",
                RuntimeSlot::Stable,
                "0.2.16",
            )
            .unwrap(),
        }
    }
}
impl<S: SecretStore> RuntimeStateStore for LegacyRuntime<S> {
    fn paths(&self) -> &RuntimePaths {
        &self.paths
    }
    fn load(&self) -> Result<Option<RuntimeStateV1>, StorageError> {
        Ok(self.source.load()?.map(|s| {
            let mut value =
                RuntimeStateV1::import_legacy(&s, StoredSplitTunnelState::default(), &self.paths);
            value.cleanup_only = false;
            value
        }))
    }
    fn save(&self, value: &RuntimeStateV1) -> Result<(), StorageError> {
        let mut current = self
            .source
            .load()?
            .ok_or(StorageError::RecoveryRequired("missing synthetic state"))?;
        current.saved_connection = value.saved_connection.clone();
        current.pinned_connection = value.pinned_connection.clone();
        current.pending_start = value.pending_start.clone();
        current.pending_stalled_stop = value.pending_stalled_stop.clone();
        current.pending_compensation_stop = value.pending_compensation_stop.clone();
        current.compatibility = value.compatibility.clone();
        self.source.save(&current)
    }
}

pub struct TestOwner<A, S, T> {
    api: Arc<A>,
    source: Arc<S>,
    local: Arc<CoreLocalStop<T>>,
    gate: Mutex<()>,
    epoch: AtomicU64,
    closed: AtomicBool,
}
impl<A, S, T> TestOwner<A, S, T> {
    pub fn new(api: Arc<A>, source: Arc<S>, local: Arc<CoreLocalStop<T>>) -> Self {
        Self {
            api,
            source,
            local,
            gate: Mutex::new(()),
            epoch: AtomicU64::new(0),
            closed: AtomicBool::new(false),
        }
    }
}
#[async_trait]
impl<A: TestAuthApi, S: SecretStore, T: TunnelController> RuntimeAuthProvider
    for TestOwner<A, S, T>
{
    async fn state(&self) -> Result<RuntimeAuthState, CoreError> {
        if self.closed.load(Ordering::SeqCst) {
            return Ok(RuntimeAuthState::LogoutPending);
        }
        Ok(
            if self
                .source
                .load()
                .map_err(|_| CoreError::Storage)?
                .is_some_and(|s| s.access_token.is_some())
            {
                RuntimeAuthState::Active
            } else {
                RuntimeAuthState::LoggedOut
            },
        )
    }
    async fn login(&self, value: RuntimeLogin) -> Result<AccessSnapshot, CoreError> {
        let writers = self.local.runtime_writer_gates();
        let _quiescence = writers.quiesce().await;
        self.local.stop_local().await?;
        let _guard = self.gate.lock().await;
        let mut stored = self
            .source
            .load()
            .map_err(|_| CoreError::Storage)?
            .unwrap_or_else(StoredAuth::new_install);
        let response = self
            .api
            .login(&LoginRequest {
                login: value.login,
                password: value.password,
                device_name: value.device_name,
                install_secret: stored.install_secret.clone(),
                platform: Platform::Macos,
                platform_version: Some("15.5".into()),
                architecture: "aarch64".into(),
                app_version: "0.2.16".into(),
            })
            .await?;
        stored.access_token = Some(response.access_token.clone());
        stored.refresh_token = Some(response.refresh_token);
        // Old account operational cleanup is intentionally no longer done by
        // ClientApplication: tests must assert the coordinator boundary.
        self.source.save(&stored).map_err(|_| CoreError::Storage)?;
        self.closed.store(false, Ordering::SeqCst);
        Ok(snapshot_at(
            &response.access_token,
            self.epoch.load(Ordering::SeqCst),
        ))
    }
    async fn access(&self, stale: Option<&AccessSnapshot>) -> Result<AccessSnapshot, CoreError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(CoreError::SignedOut);
        }
        let _guard = self.gate.lock().await;
        let epoch = self.epoch.load(Ordering::SeqCst);
        let mut stored = self
            .source
            .load()
            .map_err(|_| CoreError::Storage)?
            .ok_or(CoreError::SignedOut)?;
        let current = stored.access_token.clone().ok_or(CoreError::SignedOut)?;
        if let Some(stale) = stale {
            if stale.auth_epoch() != epoch {
                return Err(CoreError::StartCancelled);
            }
            if stale.access_token() == current {
                let response = self
                    .api
                    .refresh(
                        stored
                            .refresh_token
                            .as_deref()
                            .ok_or(CoreError::SignedOut)?,
                    )
                    .await?;
                if self.epoch.load(Ordering::SeqCst) != epoch {
                    return Err(CoreError::StartCancelled);
                }
                stored.access_token = Some(response.access_token.clone());
                stored.refresh_token = Some(response.refresh_token);
                self.source.save(&stored).map_err(|_| CoreError::Storage)?;
                return Ok(snapshot_at(&response.access_token, epoch));
            }
        }
        Ok(snapshot_at(&current, epoch))
    }
    async fn logout(&self) -> Result<(), CoreError> {
        self.closed.store(true, Ordering::SeqCst);
        self.epoch.fetch_add(1, Ordering::SeqCst);
        let local_result = self.local.stop_local().await;
        let mut stored = self
            .source
            .load()
            .map_err(|_| CoreError::Storage)?
            .ok_or(CoreError::SignedOut)?;
        if let Some(access) = &stored.access_token {
            self.api.logout(access).await?;
        }
        stored.access_token = None;
        stored.refresh_token = None;
        self.source.save(&stored).map_err(|_| CoreError::Storage)?;
        local_result
    }
}

pub fn core<
    A: CoreApi + TestAuthApi + 'static,
    S: SecretStore + 'static,
    T: TunnelController + 'static,
    L: CoreLogger,
>(
    api: Arc<A>,
    store: Arc<S>,
    tunnel: Arc<T>,
    logger: Arc<L>,
) -> ClientCore<A, LegacyRuntime<S>, T, L> {
    core_with_split(
        api,
        store,
        Arc::new(nelomai_client_storage::MemorySplitTunnelStore::default()),
        tunnel,
        logger,
    )
}
pub fn core_with_split<
    A: CoreApi + TestAuthApi + 'static,
    S: SecretStore + 'static,
    T: TunnelController + 'static,
    L: CoreLogger,
>(
    api: Arc<A>,
    store: Arc<S>,
    split: Arc<dyn SplitTunnelStore>,
    tunnel: Arc<T>,
    logger: Arc<L>,
) -> ClientCore<A, LegacyRuntime<S>, T, L> {
    let local = CoreLocalStop::new(tunnel);
    let auth = Arc::new(TestOwner::new(api.clone(), store.clone(), local.clone()));
    ClientCore::with_split_tunnel_store(
        api,
        Arc::new(LegacyRuntime::new(store)),
        split,
        auth,
        local,
        logger,
    )
}
