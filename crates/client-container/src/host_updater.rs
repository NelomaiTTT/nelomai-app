//! Common-owned updater. Runtime commands carry actions, never Bearer tokens,
//! download URLs, installer paths or signing identities.
use crate::ipc::PrivateError;
use crate::{AuthBroker, SwitchCoordinator, UpdateBarrier, UpdatePrepare};
use nelomai_client_api::{AccessSnapshot, ClientApi};
use nelomai_client_updater::{
    DownloadProgress, FileUpdatePreferenceStore, InstallResult, UpdateBackend, UpdateBackendError,
    UpdateBarrierError, UpdateBarrierPhase, UpdateCoordinator, UpdateInstallBarrier, UpdateOffer,
    UpdatePhase, UpdatePreferenceStore, UpdatePreferences,
};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostUpdateStatusV1 {
    pub supported: bool,
    pub automatic: bool,
    pub phase: String,
    pub version: Option<String>,
    pub notes: Option<String>,
    pub required: bool,
    pub downloaded: u64,
    pub total: Option<u64>,
    pub error_code: Option<String>,
}
struct Backend(Arc<dyn UpdateBackend>);
#[async_trait::async_trait]
impl UpdateBackend for Backend {
    async fn install(
        &self,
        access: &AccessSnapshot,
        version: &str,
        barrier: UpdateBarrierPhase,
        progress: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
    ) -> Result<InstallResult, UpdateBackendError> {
        self.0.install(access, version, barrier, progress).await
    }
}
struct Barrier(Arc<UpdateBarrier>);
#[async_trait::async_trait]
impl UpdateInstallBarrier for Barrier {
    async fn prepare(&self, target: &str) -> Result<UpdateBarrierPhase, UpdateBarrierError> {
        match self
            .0
            .prepare(target)
            .await
            .map_err(|_| UpdateBarrierError::new("update_shutdown_failed"))?
        {
            UpdatePrepare::LocalStopped => Ok(UpdateBarrierPhase::LocalStopped),
        }
    }
    async fn installer_opened(&self) -> Result<(), UpdateBarrierError> {
        self.0
            .installer_opened()
            .await
            .map_err(|_| UpdateBarrierError::new("update_journal_failed"))
    }
    async fn installer_failed(&self) -> Result<(), UpdateBarrierError> {
        self.0
            .installer_failed()
            .await
            .map_err(|_| UpdateBarrierError::new("update_recovery_failed"))
    }
}
pub(crate) struct HostUpdater {
    api: ClientApi,
    broker: Arc<AuthBroker>,
    preferences: FileUpdatePreferenceStore,
    current: Mutex<UpdatePreferences>,
    offer: Mutex<Option<UpdateOffer>>,
    coordinator: Option<UpdateCoordinator<Backend>>,
    barrier: Arc<UpdateBarrier>,
    version: String,
    installing: AtomicBool,
    refresh_gate: tokio::sync::Mutex<()>,
}
impl HostUpdater {
    pub fn new(
        root: &Path,
        api: ClientApi,
        broker: Arc<AuthBroker>,
        switch: Arc<SwitchCoordinator>,
        version: String,
        backend: Option<Arc<dyn UpdateBackend>>,
    ) -> Result<Self, PrivateError> {
        let preferences = FileUpdatePreferenceStore::new(root.join("updates/preferences.json"));
        let current = preferences
            .load()
            .map_err(|_| PrivateError::RecoveryRequired)?;
        let barrier =
            Arc::new(UpdateBarrier::open(switch).map_err(|_| PrivateError::RecoveryRequired)?);
        let coordinator = backend.map(|backend| {
            UpdateCoordinator::new(
                Arc::new(Backend(backend)),
                Arc::new(Barrier(barrier.clone())),
            )
        });
        Ok(Self {
            api,
            broker,
            preferences,
            current: Mutex::new(current),
            offer: Mutex::new(None),
            coordinator,
            barrier,
            version,
            installing: AtomicBool::new(false),
            refresh_gate: tokio::sync::Mutex::new(()),
        })
    }
    pub async fn recover(&self) -> Result<(), PrivateError> {
        self.barrier
            .recover(&self.version)
            .await
            .map_err(|_| PrivateError::RecoveryRequired)
    }
    pub fn status(&self) -> Result<HostUpdateStatusV1, PrivateError> {
        let automatic = self
            .current
            .lock()
            .map_err(|_| PrivateError::Closed)?
            .automatic;
        let offer = self.offer.lock().map_err(|_| PrivateError::Closed)?.clone();
        let phase = self
            .coordinator
            .as_ref()
            .map(|coordinator| coordinator.phase())
            .unwrap_or_else(|| {
                offer
                    .clone()
                    .map(UpdatePhase::Available)
                    .unwrap_or(UpdatePhase::Idle)
            });
        let (phase, version, downloaded, total, error_code) = match phase {
            UpdatePhase::Idle => ("idle", None, 0, None, None),
            UpdatePhase::Available(offer) => ("available", Some(offer.version), 0, None, None),
            UpdatePhase::Downloading {
                version,
                downloaded,
                total,
            } => ("downloading", Some(version), downloaded, total, None),
            UpdatePhase::ReadyToRestart { version } => {
                ("ready_to_restart", Some(version), 0, None, None)
            }
            UpdatePhase::AwaitingInstallation { version } => {
                ("awaiting_installation", Some(version), 0, None, None)
            }
            UpdatePhase::Failed { version, code } => ("failed", Some(version), 0, None, Some(code)),
        };
        Ok(HostUpdateStatusV1 {
            supported: self.coordinator.is_some(),
            automatic,
            phase: phase.into(),
            version,
            notes: offer.as_ref().and_then(|offer| offer.notes.clone()),
            required: offer.as_ref().is_some_and(|offer| offer.required),
            downloaded,
            total,
            error_code,
        })
    }
    pub fn set_automatic(&self, automatic: bool) -> Result<HostUpdateStatusV1, PrivateError> {
        let mut current = self.current.lock().map_err(|_| PrivateError::Closed)?;
        let next = UpdatePreferences { automatic };
        self.preferences
            .save(next)
            .map_err(|_| PrivateError::RecoveryRequired)?;
        *current = next;
        drop(current);
        self.status()
    }
    pub async fn refresh(self: &Arc<Self>) -> Result<HostUpdateStatusV1, PrivateError> {
        let _gate = self.refresh_gate.lock().await;
        let access = self
            .broker
            .access_token(None)
            .await
            .map_err(|_| PrivateError::RecoveryRequired)?;
        let response = self
            .api
            .clone()
            .with_access_snapshot(&access)
            .map_err(|_| PrivateError::RecoveryRequired)?
            .bootstrap(access.access_token())
            .await
            .map_err(|_| PrivateError::Service)?;
        let offer =
            UpdateOffer::from_state(&response.update).map_err(|_| PrivateError::Protocol)?;
        self.broker
            .with_current_access(&access, || {
                *self
                    .offer
                    .lock()
                    .map_err(|_| crate::BrokerError::RecoveryRequired)? = offer.clone();
                if let Some(coordinator) = &self.coordinator {
                    coordinator.observe(offer);
                }
                Ok(())
            })
            .await
            .map_err(|_| PrivateError::Cancelled)?;
        if self.coordinator.is_some()
            && self
                .current
                .lock()
                .map_err(|_| PrivateError::Closed)?
                .automatic
        {
            self.install(true)?;
        }
        self.status()
    }
    /// Download/installer work belongs to the common owner, not the 10s IPC
    /// waiter. Status is polled; closing the product UI does not cancel updater.
    pub fn install(self: &Arc<Self>, automatic: bool) -> Result<HostUpdateStatusV1, PrivateError> {
        if self.coordinator.is_none() {
            return Err(PrivateError::RecoveryRequired);
        }
        if self
            .installing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let owner = self.clone();
            tokio::spawn(async move {
                if let Ok(access) = owner.broker.access_token(None).await {
                    if let Some(coordinator) = &owner.coordinator {
                        if automatic {
                            let preferences = owner.current.lock().ok().map(|current| *current);
                            if let Some(preferences) = preferences {
                                let _ = coordinator
                                    .install_automatically(&access, preferences)
                                    .await;
                            }
                        } else {
                            let _ = coordinator.install_now(&access).await;
                        }
                    }
                }
                owner.installing.store(false, Ordering::Release);
            });
        }
        self.status()
    }
}
