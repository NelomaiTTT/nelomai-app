//! Common-owned updater. UI commands carry actions and an opaque offer identity,
//! never Bearer tokens, artifact URLs, installer paths or signing authority.
use crate::ipc::PrivateError;
use crate::{AuthBroker, SwitchCoordinator, UpdateBarrier, UpdatePrepare};
use nelomai_client_api::{AccessSnapshot, ClientApi};
use nelomai_client_updater::{
    DownloadProgress, FileUpdatePreferenceStore, InstallResult, PreparedUpdate, ResolvedUpdate,
    UpdateBackend, UpdateBackendError, UpdateBarrierError, UpdateBarrierPhase, UpdateCoordinator,
    UpdateInstallBarrier, UpdateOffer, UpdatePhase, UpdatePreferenceStore, UpdatePreferences,
};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    sync::{Arc, Mutex},
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum UpdateRequestV2 {
    Status {},
    Check {
        reason: UpdateCheckReason,
    },
    Confirm {
        #[serde(rename = "offerId")]
        offer_id: String,
    },
    Defer {
        #[serde(rename = "offerId")]
        offer_id: String,
    },
    Presented {
        #[serde(rename = "offerId")]
        offer_id: String,
    },
    SetAutomatic {
        enabled: bool,
    },
    UiLifecycle {
        foreground: bool,
        #[serde(rename = "newUserLaunch")]
        new_user_launch: bool,
        #[serde(rename = "launchSessionId")]
        launch_session_id: Option<String>,
    },
}
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateCheckReason {
    Startup,
    Timer,
    Foreground,
    Manual,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateStatusV2 {
    pub status: HostUpdateStatusV1,
    pub phase: String,
    pub offer_id: Option<String>,
    pub prompt_pending: bool,
    pub update_available: bool,
}
#[derive(Clone, Copy)]
struct RefreshFailure {
    code: &'static str,
    manual: bool,
}
struct Backend(Arc<dyn UpdateBackend>);
#[async_trait::async_trait]
impl UpdateBackend for Backend {
    async fn resolve(
        &self,
        access: &AccessSnapshot,
        version: &str,
    ) -> Result<Option<ResolvedUpdate>, UpdateBackendError> {
        self.0.resolve(access, version).await
    }
    async fn prepare(
        &self,
        access: &AccessSnapshot,
        resolved: &ResolvedUpdate,
        progress: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
    ) -> Result<PreparedUpdate, UpdateBackendError> {
        self.0.prepare(access, resolved, progress).await
    }
    async fn install_prepared(
        &self,
        prepared: &PreparedUpdate,
        phase: UpdateBarrierPhase,
    ) -> Result<InstallResult, UpdateBackendError> {
        self.0.install_prepared(prepared, phase).await
    }
}
struct Barrier {
    barrier: Arc<UpdateBarrier>,
    broker: Arc<AuthBroker>,
}
#[async_trait::async_trait]
impl UpdateInstallBarrier for Barrier {
    async fn validate_authority(&self, access: &AccessSnapshot) -> Result<(), UpdateBarrierError> {
        self.broker
            .with_current_access(access, || Ok(()))
            .await
            .map_err(|_| UpdateBarrierError::new("update_auth_changed"))
    }
    async fn prepare(&self, target: &str) -> Result<UpdateBarrierPhase, UpdateBarrierError> {
        match self
            .barrier
            .prepare(target)
            .await
            .map_err(|_| UpdateBarrierError::new("update_shutdown_failed"))?
        {
            UpdatePrepare::LocalStopped => Ok(UpdateBarrierPhase::LocalStopped),
        }
    }
    async fn installer_opened(&self) -> Result<(), UpdateBarrierError> {
        let result = self
            .barrier
            .installer_opened()
            .await
            .map_err(|_| UpdateBarrierError::new("update_journal_failed"));
        result
    }
    async fn installer_failed(&self) -> Result<(), UpdateBarrierError> {
        let result = self
            .barrier
            .installer_failed()
            .await
            .map_err(|_| UpdateBarrierError::new("update_recovery_failed"));
        result
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UpdateOperation {
    Idle,
    Refreshing,
    Driving,
    Recovering,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PromptSession {
    launch_session_id: Option<String>,
    deferred_version: Option<String>,
}
pub(crate) struct HostUpdater {
    api: ClientApi,
    broker: Arc<AuthBroker>,
    preferences: FileUpdatePreferenceStore,
    current: Mutex<UpdatePreferences>,
    backend: Option<Arc<dyn UpdateBackend>>,
    coordinator: Option<UpdateCoordinator<Backend>>,
    barrier: Arc<UpdateBarrier>,
    version: String,
    operation: Mutex<UpdateOperation>,
    install_recovery_gate: Arc<tokio::sync::Mutex<()>>,
    refresh_error: Mutex<Option<RefreshFailure>>,
    prompt_path: std::path::PathBuf,
    prompt_session: Mutex<PromptSession>,
    startup_checked: std::sync::atomic::AtomicBool,
    ui_generation: Mutex<u64>,
    android_policy: bool,
    timer: Mutex<Option<tokio::task::AbortHandle>>,
    timer_reset: Arc<tokio::sync::Notify>,
    manual_pending: Mutex<bool>,
    desktop_ui_visible: Mutex<Option<bool>>,
    startup_pending: std::sync::atomic::AtomicBool,
}
impl HostUpdater {
    #[cfg(not(target_os = "android"))]
    pub fn stop_proof(
        &self,
        target: &str,
        phase: crate::UpdateJournalPhase,
    ) -> Result<crate::UpdateStopProof, PrivateError> {
        self.barrier
            .stop_proof(target, phase)
            .map_err(|_| PrivateError::RecoveryRequired)
    }
    #[cfg(not(target_os = "android"))]
    pub fn native_start_blocked(&self) -> Result<bool, PrivateError> {
        self.barrier
            .snapshot()
            .map(|j| j.is_some())
            .map_err(|_| PrivateError::RecoveryRequired)
    }
    pub fn new(
        root: &Path,
        api: ClientApi,
        broker: Arc<AuthBroker>,
        switch: Arc<SwitchCoordinator>,
        version: String,
        backend: Option<Arc<dyn UpdateBackend>>,
    ) -> Result<Self, PrivateError> {
        let barrier =
            Arc::new(UpdateBarrier::open(switch).map_err(|_| PrivateError::RecoveryRequired)?);
        Self::new_with_policy(
            root,
            api,
            broker,
            barrier,
            version,
            backend,
            cfg!(target_os = "android"),
        )
    }
    fn new_with_policy(
        root: &Path,
        api: ClientApi,
        broker: Arc<AuthBroker>,
        barrier: Arc<UpdateBarrier>,
        version: String,
        backend: Option<Arc<dyn UpdateBackend>>,
        android_policy: bool,
    ) -> Result<Self, PrivateError> {
        let preferences = FileUpdatePreferenceStore::new(root.join("updates/preferences.json"));
        let current = preferences
            .load()
            .map_err(|_| PrivateError::RecoveryRequired)?;
        let coordinator = backend.as_ref().map(|backend| {
            UpdateCoordinator::with_foreground_guard(
                Arc::new(Backend(backend.clone())),
                Arc::new(Barrier {
                    barrier: barrier.clone(),
                    broker: broker.clone(),
                }),
                android_policy,
            )
        });
        let gate = coordinator
            .as_ref()
            .map(|c| c.installation_gate())
            .unwrap_or_else(|| Arc::new(tokio::sync::Mutex::new(())));
        let prompt_path = root.join("updates/prompt-session.json");
        // This is UX state, never authorization. Corruption must not prevent
        // owner/VPN startup or resurrect a prior installation decision.
        let prompt_session = if android_policy {
            use std::io::Read;
            let mut bytes = Vec::new();
            std::fs::File::open(&prompt_path)
                .ok()
                .and_then(|f| f.take(4097).read_to_end(&mut bytes).ok())
                .filter(|_| bytes.len() <= 4096)
                .and_then(|_| serde_json::from_slice(&bytes).ok())
                .unwrap_or_default()
        } else {
            PromptSession::default()
        };
        if let Some(coordinator) = &coordinator {
            coordinator.restore_deferred_version(prompt_session.deferred_version.clone());
        }
        Ok(Self {
            api,
            broker,
            preferences,
            current: Mutex::new(current),
            backend,
            coordinator,
            barrier,
            version,
            operation: Mutex::new(UpdateOperation::Idle),
            install_recovery_gate: gate,
            refresh_error: Mutex::new(None),
            prompt_path,
            prompt_session: Mutex::new(prompt_session),
            startup_checked: std::sync::atomic::AtomicBool::new(false),
            ui_generation: Mutex::new(0),
            android_policy,
            timer: Mutex::new(None),
            timer_reset: Arc::new(tokio::sync::Notify::new()),
            manual_pending: Mutex::new(false),
            desktop_ui_visible: Mutex::new(None),
            startup_pending: std::sync::atomic::AtomicBool::new(false),
        })
    }
    pub async fn recover(
        &self,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<(), PrivateError> {
        let _gate = self
            .install_recovery_gate
            .try_lock()
            .map_err(|_| PrivateError::RecoveryRequired)?;
        self.barrier
            .recover_before(&self.version, deadline)
            .await
            .map_err(|_| PrivateError::RecoveryRequired)
    }
    pub fn status(&self) -> Result<HostUpdateStatusV1, PrivateError> {
        let mut status = self.status_v2()?.status;
        // Old runtime has no package-bound confirmation UI. Preserve its shape,
        // report unsupported, and never let it infer silent installation.
        status.supported = false;
        Ok(status)
    }
    pub(crate) fn status_v2(&self) -> Result<UpdateStatusV2, PrivateError> {
        let automatic = self
            .current
            .lock()
            .map_err(|_| PrivateError::Closed)?
            .automatic;
        // A refresh cannot finish between observing its offer and deciding
        // whether this reply is still checking.
        let operation = self.operation.lock().map_err(|_| PrivateError::Closed)?;
        let (phase, offer, prompt_pending) = self
            .coordinator
            .as_ref()
            .map(|c| c.presentation())
            .unwrap_or((UpdatePhase::Idle, None, false));
        let (v2_phase, legacy_phase, version, downloaded, total, error) = match phase {
            UpdatePhase::Idle => ("idle", "idle", None, 0, None, None),
            UpdatePhase::Available(o) => ("available", "available", Some(o.version), 0, None, None),
            UpdatePhase::Downloading {
                version,
                downloaded,
                total,
            } => (
                "downloading",
                "downloading",
                Some(version),
                downloaded,
                total,
                None,
            ),
            UpdatePhase::ReadyToInstall { version } => (
                "ready_to_install",
                "available",
                Some(version),
                0,
                None,
                None,
            ),
            UpdatePhase::Installing { version } => (
                "installing",
                "downloading",
                Some(version),
                0,
                None,
                Some("update_install_preparing".into()),
            ),
            UpdatePhase::ReadyToRestart { version } => (
                "ready_to_restart",
                "ready_to_restart",
                Some(version),
                0,
                None,
                None,
            ),
            UpdatePhase::AwaitingInstallation { version } => (
                "awaiting_installation",
                "awaiting_installation",
                Some(version),
                0,
                None,
                None,
            ),
            UpdatePhase::Failed { version, code } => {
                ("failed", "failed", Some(version), 0, None, Some(code))
            }
        };
        let checking = *operation == UpdateOperation::Refreshing
            || *self
                .manual_pending
                .lock()
                .map_err(|_| PrivateError::Closed)?;
        let error_code = if checking {
            Some("update_refresh_pending".into())
        } else {
            let refresh_error = *self
                .refresh_error
                .lock()
                .map_err(|_| PrivateError::Closed)?;
            let refresh_code = refresh_error.map(|failure| failure.code.into());
            if v2_phase == "failed" && refresh_error.is_some_and(|failure| failure.manual) {
                // A manual check can fail while recovering a previous install.
                // Its result must be visible even when the offer is retained.
                refresh_code
            } else {
                error.or(refresh_code)
            }
        };
        let status = HostUpdateStatusV1 {
            supported: self.coordinator.is_some(),
            automatic,
            phase: legacy_phase.into(),
            version,
            notes: offer.as_ref().and_then(|(_, o)| o.notes.clone()),
            required: offer.as_ref().is_some_and(|(_, o)| o.required),
            downloaded,
            total,
            error_code,
        };
        let update_available =
            offer.is_some() && !matches!(v2_phase, "ready_to_restart" | "awaiting_installation");
        Ok(UpdateStatusV2 {
            status,
            phase: if checking { "checking" } else { v2_phase }.into(),
            offer_id: offer.map(|(id, _)| id),
            prompt_pending,
            update_available,
        })
    }
    pub fn set_automatic(
        self: &Arc<Self>,
        automatic: bool,
    ) -> Result<HostUpdateStatusV1, PrivateError> {
        let mut current = self.current.lock().map_err(|_| PrivateError::Closed)?;
        let next = UpdatePreferences { automatic };
        self.preferences
            .save(next)
            .map_err(|_| PrivateError::RecoveryRequired)?;
        *current = next;
        drop(current);
        if let Some(coordinator) = &self.coordinator {
            coordinator.set_automatic(automatic);
        }
        self.timer_reset.notify_one();
        self.status()
    }
    async fn refresh(&self) -> Result<(), PrivateError> {
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
        let mut offer =
            UpdateOffer::from_state(&response.update).map_err(|_| PrivateError::Protocol)?;
        let resolved = if let (Some(offer), Some(backend)) = (&offer, &self.backend) {
            backend
                .resolve(&access, &offer.version)
                .await
                .map_err(|_| PrivateError::Service)?
        } else {
            None
        };
        if resolved.is_none() {
            offer = None;
        }
        if let (Some(offer), Some(resolved)) = (&offer, &resolved) {
            if offer.version != resolved.version {
                return Err(PrivateError::Protocol);
            }
        }
        self.broker
            .with_current_access(&access, || {
                if let Some(coordinator) = &self.coordinator {
                    coordinator.observe_resolved(offer.zip(resolved), &access);
                }
                Ok(())
            })
            .await
            .map_err(|_| PrivateError::Cancelled)
    }
    pub fn start_refresh(self: &Arc<Self>) -> Result<HostUpdateStatusV1, PrivateError> {
        self.check(UpdateCheckReason::Manual)?;
        self.status()
    }
    pub(crate) fn check(self: &Arc<Self>, reason: UpdateCheckReason) -> Result<(), PrivateError> {
        if reason == UpdateCheckReason::Manual {
            *self
                .manual_pending
                .lock()
                .map_err(|_| PrivateError::Closed)? = true;
        }
        if reason == UpdateCheckReason::Startup
            && !self
                .startup_checked
                .load(std::sync::atomic::Ordering::Acquire)
        {
            self.startup_pending
                .store(true, std::sync::atomic::Ordering::Release);
        }
        // Completing an already accepted cancellation is independent of the
        // preference controlling discovery/download of another update.
        if self.start_cancel_recovery()? {
            return Ok(());
        }
        if reason == UpdateCheckReason::Startup
            && self
                .startup_checked
                .load(std::sync::atomic::Ordering::Acquire)
        {
            return Ok(());
        }
        if matches!(
            reason,
            UpdateCheckReason::Timer | UpdateCheckReason::Foreground
        ) && !self
            .current
            .lock()
            .map_err(|_| PrivateError::Closed)?
            .automatic
        {
            return Ok(());
        }
        if self.android_policy && reason == UpdateCheckReason::Timer {
            return Err(PrivateError::Protocol);
        }
        self.start_check(reason == UpdateCheckReason::Startup)
    }
    fn start_cancel_recovery(self: &Arc<Self>) -> Result<bool, PrivateError> {
        let mut operation = self.operation.lock().map_err(|_| PrivateError::Closed)?;
        if *operation == UpdateOperation::Recovering {
            return Ok(true);
        }
        if *operation != UpdateOperation::Idle {
            return Ok(false);
        }
        let Some(journal) = self
            .barrier
            .snapshot()
            .map_err(|_| PrivateError::RecoveryRequired)?
            .filter(|journal| journal.phase() == crate::UpdateJournalPhase::CancelRequested)
        else {
            return Ok(false);
        };
        let operation_id = journal.operation_id().to_owned();
        *operation = UpdateOperation::Recovering;
        drop(operation);
        let owner = self.clone();
        tokio::spawn(async move {
            // This detached recovery includes server cleanup plus retry waits,
            // unlike one IPC/network request's ten-second budget.
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
            let result = tokio::time::timeout_at(deadline, async {
                let _gate = owner.install_recovery_gate.lock().await;
                owner
                    .barrier
                    .recover_cancel_before(&operation_id, deadline)
                    .await
            })
            .await;
            let completed = matches!(result, Ok(Ok(())));
            if completed {
                // Resume rotated auth. Never retain consent for its predecessor.
                if let Some(coordinator) = &owner.coordinator {
                    coordinator.invalidate();
                }
                *owner.refresh_error.lock().expect("update error poisoned") = None;
            } else {
                owner.fail_pending_refresh(PrivateError::RecoveryRequired);
                owner
                    .startup_pending
                    .store(false, std::sync::atomic::Ordering::Release);
            }
            owner.reset_operation();
            if completed {
                owner.resume_pending_check();
            }
        });
        Ok(true)
    }
    fn start_check(self: &Arc<Self>, queue_startup: bool) -> Result<(), PrivateError> {
        let mut operation = self.operation.lock().map_err(|_| PrivateError::Closed)?;
        if *operation != UpdateOperation::Idle {
            if queue_startup {
                // Coalesce an authenticated startup arriving during a failed
                // pre-login check. Only an explicit new request queues a retry.
                self.startup_pending
                    .store(true, std::sync::atomic::Ordering::Release);
            }
            return Ok(());
        }
        self.startup_pending
            .store(false, std::sync::atomic::Ordering::Release);
        *operation = UpdateOperation::Refreshing;
        drop(operation);
        *self
            .refresh_error
            .lock()
            .map_err(|_| PrivateError::Closed)? = None;
        let owner = self.clone();
        tokio::spawn(async move {
            match owner.refresh().await {
                Ok(()) => {
                    owner
                        .startup_checked
                        .store(true, std::sync::atomic::Ordering::Release);
                    // Serialize completion with Later, which supersedes an
                    // older manual presentation request even during download.
                    let mut pending = owner
                        .manual_pending
                        .lock()
                        .expect("update manual request poisoned");
                    if std::mem::take(&mut *pending) {
                        if let Some(coordinator) = &owner.coordinator {
                            coordinator.request_manual_prompt();
                            coordinator.suppress_notification();
                        }
                        if let Err(error) = owner.save_prompt() {
                            owner.record_refresh_error(error, true);
                        }
                    }
                }
                Err(error) => {
                    owner.fail_pending_refresh(error);
                    if let Some(c) = &owner.coordinator {
                        c.invalidate();
                    }
                }
            }
            owner.reset_operation();
            if !owner.resume_pending_check() {
                let _ = owner.start_drive();
            }
        });
        Ok(())
    }
    pub fn install(self: &Arc<Self>, _automatic: bool) -> Result<HostUpdateStatusV1, PrivateError> {
        Err(PrivateError::Protocol)
    }
    fn start_drive(self: &Arc<Self>) -> Result<(), PrivateError> {
        let Some(coordinator) = &self.coordinator else {
            return Ok(());
        };
        let automatic = self
            .current
            .lock()
            .map_err(|_| PrivateError::Closed)?
            .automatic;
        if !automatic && !coordinator.has_consent() {
            return Ok(());
        }
        if coordinator.offer_id().is_none() {
            return Ok(());
        }
        let mut operation = self.operation.lock().map_err(|_| PrivateError::Closed)?;
        if *operation != UpdateOperation::Idle {
            return Ok(());
        }
        *operation = UpdateOperation::Driving;
        drop(operation);
        let owner = self.clone();
        tokio::spawn(async move {
            if let (Some(coordinator), Ok(access)) =
                (&owner.coordinator, owner.broker.access_token(None).await)
            {
                let automatic = owner.current.lock().map(|p| p.automatic).unwrap_or(false);
                let _ = coordinator.drive(&access, automatic).await;
            } else if let Some(coordinator) = &owner.coordinator {
                coordinator.invalidate();
            }
            owner.reset_operation();
            // A Yes racing with the final ready state must not be lost.
            if !owner.start_cancel_recovery().unwrap_or(false)
                && !owner.resume_pending_check()
                && owner.coordinator.as_ref().is_some_and(|c| c.has_consent())
            {
                let _ = owner.start_drive();
            }
        });
        Ok(())
    }
    #[cfg(test)]
    async fn request_v2(
        self: &Arc<Self>,
        request: UpdateRequestV2,
    ) -> Result<UpdateStatusV2, PrivateError> {
        self.request_v2_for(None, request).await
    }
    pub async fn request_v2_for(
        self: &Arc<Self>,
        generation: Option<u64>,
        request: UpdateRequestV2,
    ) -> Result<UpdateStatusV2, PrivateError> {
        if let UpdateRequestV2::UiLifecycle {
            foreground,
            new_user_launch,
            launch_session_id,
        } = request
        {
            let active = self
                .ui_generation
                .lock()
                .map_err(|_| PrivateError::Closed)?;
            if generation.is_some_and(|generation| generation != *active) {
                return Err(PrivateError::Cancelled);
            }
            self.ui_lifecycle(foreground, new_user_launch, launch_session_id)?;
            if foreground {
                self.start_cancel_recovery()?;
            }
            return self.status_v2();
        }
        // Observation reads current protected state without issuing a refresh;
        // a slow network operation must not block pause/disconnect on this IPC.
        let access = self
            .broker
            .observe()
            .await
            .ok()
            .and_then(|observation| observation.access);
        if let Some(coordinator) = &self.coordinator {
            if let Some(access) = &access {
                coordinator.retain_scope(access);
            } else {
                coordinator.invalidate();
            }
        }
        let active = self
            .ui_generation
            .lock()
            .map_err(|_| PrivateError::Closed)?;
        if generation.is_some_and(|generation| generation != *active) {
            return Err(PrivateError::Cancelled);
        }
        match request {
            UpdateRequestV2::Status {} => {}
            UpdateRequestV2::Check { reason } => self.check(reason)?,
            UpdateRequestV2::SetAutomatic { enabled } => {
                self.set_automatic(enabled)?;
                if enabled {
                    self.check(UpdateCheckReason::Foreground)?;
                }
            }
            UpdateRequestV2::Confirm { offer_id } => {
                self.coordinator
                    .as_ref()
                    .ok_or(PrivateError::Protocol)?
                    .confirm(&offer_id)
                    .map_err(|_| PrivateError::Protocol)?;
                self.save_prompt()?;
                self.start_drive()?;
            }
            UpdateRequestV2::Defer { offer_id } => {
                let mut pending = self
                    .manual_pending
                    .lock()
                    .map_err(|_| PrivateError::Closed)?;
                self.coordinator
                    .as_ref()
                    .ok_or(PrivateError::Protocol)?
                    .defer(&offer_id)
                    .map_err(|_| PrivateError::Protocol)?;
                *pending = false;
                drop(pending);
                self.save_prompt()?;
            }
            UpdateRequestV2::Presented { offer_id } => self
                .coordinator
                .as_ref()
                .ok_or(PrivateError::Protocol)?
                .present(&offer_id)
                .map_err(|_| PrivateError::Protocol)?,
            UpdateRequestV2::UiLifecycle { .. } => unreachable!(),
        }
        self.status_v2()
    }
    fn ui_lifecycle(
        &self,
        foreground: bool,
        new_launch: bool,
        session_id: Option<String>,
    ) -> Result<(), PrivateError> {
        if !self.android_policy {
            if new_launch || session_id.is_some() {
                return Err(PrivateError::Protocol);
            }
            *self
                .desktop_ui_visible
                .lock()
                .map_err(|_| PrivateError::Closed)? = Some(foreground);
            return Ok(());
        }
        let mut session = self
            .prompt_session
            .lock()
            .map_err(|_| PrivateError::Closed)?;
        let changed = if new_launch {
            let id = session_id
                .filter(|id| uuid::Uuid::parse_str(id).is_ok())
                .ok_or(PrivateError::Protocol)?;
            let changed = session.launch_session_id.as_ref() != Some(&id);
            session.launch_session_id = Some(id);
            changed
        } else {
            if session_id.is_some() {
                return Err(PrivateError::Protocol);
            }
            false
        };
        if let Some(coordinator) = &self.coordinator {
            coordinator.set_ui_lifecycle(foreground, changed);
        }
        drop(session);
        if changed {
            self.startup_checked
                .store(false, std::sync::atomic::Ordering::Release);
            self.save_prompt()
        } else {
            Ok(())
        }
    }
    fn save_prompt(&self) -> Result<(), PrivateError> {
        if !self.android_policy {
            return Ok(());
        }
        use std::io::Write;
        let mut session = self
            .prompt_session
            .lock()
            .map_err(|_| PrivateError::Closed)?;
        session.deferred_version = self.coordinator.as_ref().and_then(|c| c.deferred_version());
        let parent = self
            .prompt_path
            .parent()
            .ok_or(PrivateError::RecoveryRequired)?;
        std::fs::create_dir_all(parent).map_err(|_| PrivateError::RecoveryRequired)?;
        let mut file =
            tempfile::NamedTempFile::new_in(parent).map_err(|_| PrivateError::RecoveryRequired)?;
        serde_json::to_writer(&mut file, &*session).map_err(|_| PrivateError::RecoveryRequired)?;
        file.flush().map_err(|_| PrivateError::RecoveryRequired)?;
        file.as_file()
            .sync_all()
            .map_err(|_| PrivateError::RecoveryRequired)?;
        file.persist(&self.prompt_path)
            .map_err(|_| PrivateError::RecoveryRequired)?;
        Ok(())
    }
    pub(crate) fn start_desktop_scheduler(self: &Arc<Self>) {
        if self.android_policy {
            return;
        }
        let mut timer = self.timer.lock().expect("update timer poisoned");
        if timer.is_some() {
            return;
        }
        let weak = Arc::downgrade(self);
        let reset = self.timer_reset.clone();
        let task = tokio::spawn(async move {
            let period = std::time::Duration::from_secs(30 * 60);
            let mut interval =
                tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _=reset.notified()=>interval.reset(),
                    _=interval.tick()=>{
                        let Some(owner)=weak.upgrade() else{return;};let _=owner.check(UpdateCheckReason::Timer);
                    }
                }
            }
        });
        *timer = Some(task.abort_handle());
    }
    pub(crate) fn take_notification(&self) -> Option<UpdateOffer> {
        if self.android_policy
            || !self.current.lock().ok()?.automatic
            || *self.desktop_ui_visible.lock().ok()? != Some(false)
            || *self.manual_pending.lock().ok()?
        {
            return None;
        }
        let coordinator = self.coordinator.as_ref()?;
        if !coordinator.ui_connected() {
            return None;
        }
        coordinator.take_notification()
    }
    pub fn set_ui_connection_probe(&self, probe: Arc<dyn Fn() -> bool + Send + Sync>) {
        if let Some(c) = &self.coordinator {
            c.set_ui_connection_probe(probe);
        }
    }
    pub fn attach_ui(&self) -> u64 {
        let mut generation = self
            .ui_generation
            .lock()
            .expect("update UI generation poisoned");
        *generation = generation
            .checked_add(1)
            .expect("update UI generation exhausted");
        self.ui_disconnected();
        *generation
    }
    pub fn ui_foreground(&self) -> bool {
        self.coordinator.as_ref().is_some_and(|c| {
            c.has_consent()
                && matches!(c.phase(), UpdatePhase::Installing { .. })
                && c.ui_foreground()
        })
    }
    pub(crate) fn auth_revoked(&self) {
        self.startup_checked
            .store(false, std::sync::atomic::Ordering::Release);
        if let Some(c) = &self.coordinator {
            c.invalidate();
        }
    }
    pub fn ui_disconnected(&self) {
        *self
            .desktop_ui_visible
            .lock()
            .expect("update visibility poisoned") = None;
        if let Some(c) = &self.coordinator {
            c.set_ui_lifecycle(false, false);
        }
    }
    fn fail_pending_refresh(&self, error: PrivateError) {
        let mut pending = self
            .manual_pending
            .lock()
            .expect("update manual request poisoned");
        self.record_refresh_error(error, std::mem::take(&mut *pending));
    }
    fn record_refresh_error(&self, error: PrivateError, manual: bool) {
        if let Ok(mut slot) = self.refresh_error.lock() {
            *slot = Some(RefreshFailure {
                code: refresh_error_code(error),
                manual,
            });
        }
    }
    fn resume_pending_check(self: &Arc<Self>) -> bool {
        if self
            .manual_pending
            .lock()
            .map(|pending| *pending)
            .unwrap_or(false)
        {
            let _ = self.start_check(false);
            return true;
        }
        if self
            .startup_pending
            .swap(false, std::sync::atomic::Ordering::AcqRel)
            && !self
                .startup_checked
                .load(std::sync::atomic::Ordering::Acquire)
        {
            let _ = self.check(UpdateCheckReason::Startup);
            return true;
        }
        false
    }
    fn reset_operation(&self) {
        if let Ok(mut operation) = self.operation.lock() {
            *operation = UpdateOperation::Idle;
        }
    }
}
impl Drop for HostUpdater {
    fn drop(&mut self) {
        if let Ok(timer) = self.timer.get_mut() {
            if let Some(timer) = timer.take() {
                timer.abort();
            }
        }
    }
}
fn refresh_error_code(error: PrivateError) -> &'static str {
    match error {
        PrivateError::Timeout => "update_refresh_timeout",
        PrivateError::Service => "update_refresh_service",
        PrivateError::RefreshPending => "update_refresh_auth_pending",
        PrivateError::RefreshRejected => "update_refresh_auth_rejected",
        PrivateError::Cancelled => "update_refresh_cancelled",
        PrivateError::Closed => "update_refresh_closed",
        PrivateError::Protocol => "update_refresh_protocol",
        PrivateError::RecoveryRequired => "update_refresh_recovery_required",
        PrivateError::OutcomeUnknown => "update_refresh_auth_unknown",
        PrivateError::AccessUnavailable => "update_refresh_access_unavailable",
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        LocalAuthStop, RuntimeRecordSwitchControl, SlotSelectionV1, UnavailableRuntimeForceStop,
    };
    use async_trait::async_trait;
    use axum::{
        extract::State,
        routing::{get, post},
        Json, Router,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use nelomai_client_storage::{
        AuthStore, AuthStoreV1, BrokerMetadataV1, ContainerOwnerLock, ProtectedAuthStore,
        ProtectedRecordStore, ProtectedRuntimeStore, RuntimeAuthScope, RuntimePaths,
        RuntimeRecordOwner, RuntimeStateStore, RuntimeStateV1, StorageError, StoredAuth,
    };
    use nelomai_client_tunnel::{TunnelController, TunnelError, TunnelStartRequest, TunnelStatus};
    use nelomai_contracts::{
        verify_container_manifest, ContainerManifestV1, RuntimeArtifactManifestV1, RuntimeFileRole,
        RuntimeFileV1, RuntimeSlot, RuntimeSlotManifestV1, CONTAINER_MANIFEST_SIGNATURE_DOMAIN,
    };
    use serde_json::json;
    use std::{
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Mutex,
        },
        time::Duration,
    };
    use tokio::sync::Notify;

    #[derive(Clone, Default)]
    struct Record(Arc<Mutex<Option<Vec<u8>>>>);
    impl ProtectedRecordStore for Record {
        fn load_record(&self) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn save_record(&self, bytes: &[u8]) -> Result<(), StorageError> {
            *self.0.lock().unwrap() = Some(bytes.to_vec());
            Ok(())
        }
        fn delete_record(&self) -> Result<(), StorageError> {
            *self.0.lock().unwrap() = None;
            Ok(())
        }
    }

    struct Stop;
    #[async_trait]
    impl LocalAuthStop for Stop {
        async fn stop_local(&self) -> Result<(), crate::BrokerError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct Tunnel {
        stops: AtomicUsize,
    }
    #[async_trait]
    impl TunnelController for Tunnel {
        async fn start(&self, _: TunnelStartRequest) -> Result<(), TunnelError> {
            Ok(())
        }
        async fn stop(&self) -> Result<(), TunnelError> {
            self.stops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn status(&self) -> Result<TunnelStatus, TunnelError> {
            Ok(TunnelStatus::Stopped)
        }
    }

    #[derive(Default)]
    struct RecordingBackend {
        versions: Mutex<Vec<String>>,
        files: Mutex<Vec<tempfile::NamedTempFile>>,
        panel: Option<Arc<Panel>>,
    }
    fn test_descriptor(version: &str) -> ResolvedUpdate {
        ResolvedUpdate {
            version: version.into(),
            target: "test".into(),
            artifact_url: "https://nelomai.ru/api/client/v1/updates/artifacts/test".into(),
            signature: "test".into(),
            key_identity: "test".into(),
            sha256: None,
            size_bytes: None,
        }
    }
    fn test_prepared(
        resolved: &ResolvedUpdate,
        files: &Mutex<Vec<tempfile::NamedTempFile>>,
    ) -> PreparedUpdate {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"verified synthetic package").unwrap();
        let prepared =
            PreparedUpdate::from_verified_file(resolved.clone(), file.path().to_owned()).unwrap();
        files.lock().unwrap().push(file);
        prepared
    }

    #[async_trait]
    impl UpdateBackend for RecordingBackend {
        async fn resolve(
            &self,
            _: &AccessSnapshot,
            version: &str,
        ) -> Result<Option<ResolvedUpdate>, UpdateBackendError> {
            if let Some(panel) = &self.panel {
                if panel.fail.load(Ordering::SeqCst) {
                    return Err(UpdateBackendError::new("manifest_unavailable"));
                }
                if panel.version.lock().unwrap().as_str() != version {
                    return Ok(None);
                }
            }
            Ok(Some(test_descriptor(version)))
        }
        async fn prepare(
            &self,
            _: &AccessSnapshot,
            resolved: &ResolvedUpdate,
            _: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
        ) -> Result<PreparedUpdate, UpdateBackendError> {
            Ok(test_prepared(resolved, &self.files))
        }
        async fn install_prepared(
            &self,
            prepared: &PreparedUpdate,
            _: UpdateBarrierPhase,
        ) -> Result<InstallResult, UpdateBackendError> {
            self.versions
                .lock()
                .unwrap()
                .push(prepared.resolved().version.clone());
            Ok(InstallResult::Installed(
                nelomai_client_updater::InstalledUpdate {
                    version: prepared.resolved().version.clone(),
                },
            ))
        }
    }

    fn manifest() -> nelomai_contracts::VerifiedContainerManifest {
        let unsigned = ContainerManifestV1 {
            format_version: 1,
            container_version: "0.2.20".into(),
            release_set_id: "runtime-0.2.20".into(),
            minimum_runtime_contract: 1,
            maximum_runtime_contract: 1,
            stable_release_set_sha256: None,
            stable_platform_manifest_sha256: None,
            slots: vec![RuntimeSlotManifestV1 {
                slot: RuntimeSlot::Latest,
                manifest: RuntimeArtifactManifestV1 {
                    format_version: 1,
                    runtime_version: "0.2.20".into(),
                    source_commit: "0123456789abcdef0123456789abcdef01234567".into(),
                    platform: "linux".into(),
                    architecture: "x86_64".into(),
                    contract_version: 1,
                    files: vec![RuntimeFileV1 {
                        path: "bin/nelomai-runtime".into(),
                        size_bytes: 1,
                        sha256: "a".repeat(64),
                        role: RuntimeFileRole::Executable,
                    }],
                },
            }],
        };
        let bytes = serde_json::to_vec(&serde_json::to_value(unsigned).unwrap()).unwrap();
        let key = SigningKey::from_bytes(&[71; 32]);
        let mut signed = CONTAINER_MANIFEST_SIGNATURE_DOMAIN.to_vec();
        signed.extend_from_slice(&bytes);
        verify_container_manifest(
            &bytes,
            &key.sign(&signed).to_bytes(),
            &key.verifying_key().to_bytes(),
            "linux",
            "x86_64",
        )
        .unwrap()
    }

    struct Panel {
        calls: AtomicUsize,
        fail: AtomicBool,
        version: Mutex<String>,
        release: Notify,
        reconciles: AtomicUsize,
        resumes: AtomicUsize,
        fail_resume: AtomicBool,
        retry_reconcile: AtomicUsize,
    }

    async fn reconcile(
        State(panel): State<Arc<Panel>>,
        Json(body): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        panel.reconciles.fetch_add(1, Ordering::SeqCst);
        if panel
            .retry_reconcile
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Json(json!({"state":"retry","operation_id":body["operation_id"],
                "retired_lease_ids":[],"retired_session_ids":[],"retired_operation_ids":[],
                "retry_after_seconds":1}));
        }
        Json(json!({"state":"clean","operation_id":body["operation_id"],
            "retired_lease_ids":body["lease_ids"],"retired_session_ids":body["redundant_session_ids"],
            "retired_operation_ids":body["client_operation_ids"],"retry_after_seconds":null}))
    }
    async fn resume(
        State(panel): State<Arc<Panel>>,
        Json(body): Json<serde_json::Value>,
    ) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
        panel.resumes.fetch_add(1, Ordering::SeqCst);
        if panel.fail_resume.load(Ordering::SeqCst) {
            return Err(axum::http::StatusCode::SERVICE_UNAVAILABLE);
        }
        assert_eq!(body["decision"], "cancel");
        Ok(Json(json!({"identity":{
            "container_version":body["target_identity"]["container_version"],
            "runtime_version":body["target_identity"]["runtime_version"],
            "runtime_contract_version":body["target_identity"]["runtime_contract_version"],
            "runtime_slot":body["target_identity"]["runtime_slot"],
            "session_generation":body["expected_session_generation"].as_u64().unwrap()+1},
            "access_token":"resumed-access","token_type":"Bearer","access_expires_in":900})))
    }

    async fn bootstrap(
        State(panel): State<Arc<Panel>>,
    ) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
        panel.calls.fetch_add(1, Ordering::SeqCst);
        panel.release.notified().await;
        if panel.fail.swap(false, Ordering::SeqCst) {
            return Err(axum::http::StatusCode::SERVICE_UNAVAILABLE);
        }
        let version = panel.version.lock().unwrap().clone();
        Ok(Json(json!({
            "api_version": "1",
            "request_id": "update-refresh",
            "access": {
                "state": "active",
                "can_login": true,
                "can_connect": true,
                "expires_at": "2030-01-01T00:00:00Z"
            },
            "device": {"id": "device-a", "name": "Mac", "platform": "macos"},
            "binding": null,
            "connection": null,
            "pinned_stray": null,
            "defaults": {"layer": "stray", "tic_connection_mode": "dynamic", "route_mode": "standalone"},
            "update": {
                "current_version": version,
                "minimum_version": null,
                "update_available": true,
                "required": false,
                "release_notes": "test"
            }
        })))
    }

    async fn updater(
        fail_first: bool,
    ) -> (
        Arc<HostUpdater>,
        Arc<Panel>,
        Arc<RecordingBackend>,
        Arc<Tunnel>,
        tokio::task::JoinHandle<()>,
        tempfile::TempDir,
    ) {
        updater_with_installer(fail_first, None).await
    }

    async fn updater_with_installer(
        fail_first: bool,
        installer: Option<Arc<dyn UpdateBackend>>,
    ) -> (
        Arc<HostUpdater>,
        Arc<Panel>,
        Arc<RecordingBackend>,
        Arc<Tunnel>,
        tokio::task::JoinHandle<()>,
        tempfile::TempDir,
    ) {
        let panel = Arc::new(Panel {
            calls: AtomicUsize::new(0),
            fail: AtomicBool::new(fail_first),
            version: Mutex::new("0.2.21".into()),
            release: Notify::new(),
            reconciles: AtomicUsize::new(0),
            resumes: AtomicUsize::new(0),
            fail_resume: AtomicBool::new(false),
            retry_reconcile: AtomicUsize::new(0),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = ClientApi::new(&format!("http://{}", listener.local_addr().unwrap()))
            .unwrap()
            .with_app_version("0.2.20")
            .unwrap();
        let router = Router::new()
            .route("/api/client/v1/bootstrap", get(bootstrap))
            .route(
                "/api/client/v1/connections/runtime-switch/reconcile",
                post(reconcile),
            )
            .route("/api/client/v1/auth/runtime/resume", post(resume))
            .with_state(panel.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("common")).unwrap();
        std::fs::write(
            root.path().join("common/runtime-selection-v1.json"),
            SlotSelectionV1 {
                container_version: "0.2.20".into(),
                selected_slot: RuntimeSlot::Latest,
                pending_slot: None,
            }
            .to_persisted_bytes()
            .unwrap(),
        )
        .unwrap();
        let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
        let auth = Arc::new(ProtectedAuthStore::new(Record::default()));
        let mut legacy = StoredAuth::new_install();
        legacy.access_token = Some("access".into());
        legacy.refresh_token = Some("refresh".into());
        let mut stored = AuthStoreV1::from_legacy(&legacy);
        stored.confirmed_identity = Some(nelomai_contracts::RuntimeIdentity {
            container_version: "0.2.20".into(),
            runtime_version: "0.2.20".into(),
            runtime_contract_version: 1,
            slot: RuntimeSlot::Latest,
            session_generation: Some(1),
        });
        stored.session_generation = Some(1);
        stored.broker = Some(BrokerMetadataV1 {
            family: "family".into(),
            next_attempt: 0,
            pending_request: None,
            completed_resume: None,
            pending_logout: None,
            pending_recovery: None,
            cancelled_login: None,
            authentication_outcome_unknown: false,
            pending_login_account: None,
            confirmed_device_id: Some("device-a".into()),
            pending_push_cleanup_epoch: None,
            transition_authorities: Vec::new(),
        });
        let scope = RuntimeAuthScope {
            auth_epoch: stored.auth_epoch,
            family: stored.broker.as_ref().unwrap().family.clone(),
            identity: stored.confirmed_identity.clone().unwrap(),
        };
        auth.save(&stored).unwrap();
        let broker = Arc::new(AuthBroker::new(api.clone(), auth, Arc::new(Stop)).unwrap());
        let paths = RuntimePaths::new(root.path(), RuntimeSlot::Latest, "0.2.20").unwrap();
        let runtime = ProtectedRuntimeStore::new(Record::default(), paths);
        let mut state = RuntimeStateV1::empty(runtime.paths(), false);
        state.auth_scope = Some(scope);
        runtime.save(&state).unwrap();
        let tunnel = Arc::new(Tunnel::default());
        let local = nelomai_client_core::CoreLocalStop::new(tunnel.clone());
        let control = Arc::new(RuntimeRecordSwitchControl::new(
            RuntimeRecordOwner::new(runtime),
            Vec::new(),
            local,
            Arc::new(UnavailableRuntimeForceStop),
        ));
        let coordinator = Arc::new(
            SwitchCoordinator::open(owner, manifest())
                .unwrap()
                .attach(broker.clone(), control),
        );
        let backend = Arc::new(RecordingBackend {
            panel: Some(panel.clone()),
            ..Default::default()
        });
        let updater = Arc::new(
            HostUpdater::new(
                root.path(),
                api,
                broker,
                coordinator,
                "0.2.20".into(),
                Some(installer.unwrap_or_else(|| backend.clone())),
            )
            .unwrap(),
        );
        updater.set_automatic(false).unwrap();
        (updater, panel, backend, tunnel, server, root)
    }

    #[tokio::test]
    async fn automatic_refresh_never_stops_vpn_without_consent() {
        let (updater, panel, backend, tunnel, server, _root) = updater(false).await;
        updater.set_automatic(true).unwrap();
        updater.start_refresh().unwrap();
        wait_for_calls(&panel, 1).await;
        panel.release.notify_one();
        wait_for_idle(&updater).await;
        assert_eq!(
            tunnel.stops.load(Ordering::SeqCst),
            0,
            "discovery must not stop VPN"
        );
        assert!(backend.versions.lock().unwrap().is_empty());
        server.abort();
    }

    #[tokio::test]
    async fn legacy_install_cannot_bypass_consent() {
        let (updater, _panel, backend, _tunnel, server, _root) = updater(false).await;
        assert!(
            updater.install(false).is_err(),
            "legacy manual command carries no offer identity"
        );
        assert!(
            updater.install(true).is_err(),
            "legacy automatic command carries no consent"
        );
        assert!(backend.versions.lock().unwrap().is_empty());
        server.abort();
    }

    #[tokio::test]
    async fn slow_refresh_returns_immediately_and_duplicate_requests_share_one_flight() {
        let (updater, panel, _backend, _tunnel, server, _root) = updater(false).await;

        let first = tokio::time::timeout(Duration::from_millis(100), async {
            updater.start_refresh()
        })
        .await
        .expect("starting a refresh must not wait for panel I/O")
        .unwrap();
        assert_eq!(first.error_code.as_deref(), Some("update_refresh_pending"));
        let wire = serde_json::to_value(&first).unwrap();
        let keys = wire
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            [
                "automatic",
                "downloaded",
                "errorCode",
                "notes",
                "phase",
                "required",
                "supported",
                "total",
                "version",
            ]
        );
        assert_eq!(
            updater.start_refresh().unwrap().error_code.as_deref(),
            Some("update_refresh_pending")
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while panel.calls.load(Ordering::SeqCst) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(panel.calls.load(Ordering::SeqCst), 1);

        panel.release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), async {
            while updater.status().unwrap().error_code.as_deref() == Some("update_refresh_pending")
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let completed = updater.status().unwrap();
        assert_eq!(completed.phase, "available");
        assert_eq!(completed.version.as_deref(), Some("0.2.21"));
        server.abort();
    }

    #[tokio::test]
    async fn failed_background_refresh_can_be_retried_without_restarting_owner() {
        let (updater, panel, _backend, _tunnel, server, _root) = updater(true).await;

        assert_eq!(
            updater.start_refresh().unwrap().error_code.as_deref(),
            Some("update_refresh_pending")
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while panel.calls.load(Ordering::SeqCst) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        panel.release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), async {
            while updater.status().unwrap().error_code.as_deref() == Some("update_refresh_pending")
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            updater.status().unwrap().error_code.as_deref(),
            Some("update_refresh_service")
        );

        assert_eq!(
            updater.start_refresh().unwrap().error_code.as_deref(),
            Some("update_refresh_pending")
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while panel.calls.load(Ordering::SeqCst) != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        panel.release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), async {
            while updater.status().unwrap().error_code.as_deref() == Some("update_refresh_pending")
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(updater.status().unwrap().version.as_deref(), Some("0.2.21"));
        server.abort();
    }

    #[tokio::test]
    async fn legacy_install_during_refresh_is_rejected_without_a_second_panel_request() {
        let (updater, panel, backend, tunnel, server, _root) = updater(false).await;
        updater.start_refresh().unwrap();
        wait_for_calls(&panel, 1).await;
        assert!(updater.install(false).is_err());
        panel.release.notify_one();
        wait_for_idle(&updater).await;
        assert_eq!(panel.calls.load(Ordering::SeqCst), 1);
        assert!(backend.versions.lock().unwrap().is_empty());
        assert_eq!(tunnel.stops.load(Ordering::SeqCst), 0);
        server.abort();
    }
    async fn discover(updater: &Arc<HostUpdater>, panel: &Panel) {
        updater.start_refresh().unwrap();
        panel.release.notify_one();
        wait_for_idle(updater).await;
    }
    async fn confirm(updater: &Arc<HostUpdater>) {
        let offer_id = updater.status_v2().unwrap().offer_id.unwrap();
        updater
            .request_v2(UpdateRequestV2::Confirm { offer_id })
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn confirmation_rechecks_current_manifest_before_stop() {
        let (updater, panel, backend, tunnel, server, _root) = updater(false).await;
        discover(&updater, &panel).await;
        *panel.version.lock().unwrap() = "0.2.22".into();
        confirm(&updater).await;
        wait_for_idle(&updater).await;
        assert!(backend.versions.lock().unwrap().is_empty());
        assert_eq!(tunnel.stops.load(Ordering::SeqCst), 0);
        assert_eq!(
            updater.status().unwrap().error_code.as_deref(),
            Some("update_offer_changed")
        );
        server.abort();
    }
    #[tokio::test]
    async fn confirmation_does_not_stop_when_fresh_manifest_fails() {
        let (updater, panel, backend, tunnel, server, _root) = updater(false).await;
        discover(&updater, &panel).await;
        panel.fail.store(true, Ordering::SeqCst);
        confirm(&updater).await;
        wait_for_idle(&updater).await;
        assert!(backend.versions.lock().unwrap().is_empty());
        assert_eq!(tunnel.stops.load(Ordering::SeqCst), 0);
        assert!(!updater.coordinator.as_ref().unwrap().has_consent());
        server.abort();
    }
    #[tokio::test]
    async fn duplicate_confirmation_installs_once() {
        let (updater, panel, backend, _tunnel, server, _root) = updater(false).await;
        discover(&updater, &panel).await;
        confirm(&updater).await;
        confirm(&updater).await;
        wait_for_idle(&updater).await;
        assert_eq!(backend.versions.lock().unwrap().as_slice(), ["0.2.21"]);
        server.abort();
    }

    struct CancelledInstaller {
        calls: AtomicUsize,
        entered: Notify,
        release: Notify,
        wait_for_result: bool,
        files: Mutex<Vec<tempfile::NamedTempFile>>,
    }
    impl CancelledInstaller {
        fn new(wait_for_result: bool) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                entered: Notify::new(),
                release: Notify::new(),
                wait_for_result,
                files: Mutex::new(Vec::new()),
            })
        }
    }
    #[async_trait]
    impl UpdateBackend for CancelledInstaller {
        async fn resolve(
            &self,
            _: &AccessSnapshot,
            version: &str,
        ) -> Result<Option<ResolvedUpdate>, UpdateBackendError> {
            Ok(Some(test_descriptor(version)))
        }
        async fn prepare(
            &self,
            _: &AccessSnapshot,
            resolved: &ResolvedUpdate,
            _: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
        ) -> Result<PreparedUpdate, UpdateBackendError> {
            Ok(test_prepared(resolved, &self.files))
        }
        async fn install_prepared(
            &self,
            _: &PreparedUpdate,
            _: UpdateBarrierPhase,
        ) -> Result<InstallResult, UpdateBackendError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            if self.wait_for_result {
                self.release.notified().await;
            }
            Err(UpdateBackendError::new("apk_install_cancelled"))
        }
    }

    #[tokio::test]
    async fn live_installer_keeps_recovery_and_start_blocked_until_its_result() {
        let installer = CancelledInstaller::new(true);
        let (updater, panel, _, _, server, root) =
            updater_with_installer(false, Some(installer.clone())).await;
        discover(&updater, &panel).await;
        confirm(&updater).await;
        tokio::time::timeout(Duration::from_secs(2), installer.entered.notified())
            .await
            .unwrap();
        let path = root.path().join("common/update-journal-v1.json");
        let before = std::fs::read(&path).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&before).unwrap()["phase"],
            "local_stopped"
        );
        let recovered = tokio::time::timeout(
            Duration::from_secs(2),
            updater.recover(Some(
                tokio::time::Instant::now() + Duration::from_millis(500),
            )),
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read(&path).ok(),
            Some(before),
            "recovery must not start cancelling a live installer journal"
        );
        assert!(
            recovered.is_err(),
            "live system installer must retain the update barrier"
        );
        assert!(updater.native_start_blocked().unwrap());
        assert_eq!(panel.reconciles.load(Ordering::SeqCst), 0);
        assert_eq!(panel.resumes.load(Ordering::SeqCst), 0);
        installer.release.notify_one();
        wait_for_idle(&updater).await;
        assert_eq!(
            updater.status().unwrap().error_code.as_deref(),
            Some("apk_install_cancelled")
        );
        assert!(!path.exists());
        updater.recover(None).await.unwrap();
        assert!(!updater.native_start_blocked().unwrap());
        server.abort();
    }

    #[tokio::test]
    async fn public_cancel_pending_recovers_without_restart_when_automatic_is_off() {
        let installer = CancelledInstaller::new(false);
        let (updater, panel, _, tunnel, server, root) =
            updater_with_installer(false, Some(installer.clone())).await;
        panel.retry_reconcile.store(1, Ordering::SeqCst);
        discover(&updater, &panel).await;
        confirm(&updater).await;
        tokio::time::timeout(Duration::from_secs(4), async {
            while *updater.operation.lock().unwrap() != UpdateOperation::Idle {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            !root.path().join("common/update-journal-v1.json").exists(),
            "native Cancel left a durable barrier with no public recovery trigger"
        );
        assert!(!updater.native_start_blocked().unwrap());
        assert_eq!(panel.reconciles.load(Ordering::SeqCst), 2);
        assert_eq!(panel.resumes.load(Ordering::SeqCst), 1);
        assert_eq!(installer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
        assert!(!updater.coordinator.as_ref().unwrap().has_consent());
        assert!(!updater.status().unwrap().automatic);
        server.abort();
    }

    #[tokio::test]
    async fn public_cancel_retries_are_bounded_and_foreground_can_continue() {
        let installer = CancelledInstaller::new(false);
        let (updater, panel, _, tunnel, server, root) =
            updater_with_installer(false, Some(installer.clone())).await;
        panel.retry_reconcile.store(100, Ordering::SeqCst);
        discover(&updater, &panel).await;
        let started = tokio::time::Instant::now();
        confirm(&updater).await;
        tokio::time::timeout(Duration::from_secs(32), async {
            while *updater.operation.lock().unwrap() != UpdateOperation::Idle {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(started.elapsed() >= Duration::from_secs(29));
        assert!(
            panel.reconciles.load(Ordering::SeqCst) <= 32,
            "recovery must respect server retry delay, not spin"
        );
        let path = root.path().join("common/update-journal-v1.json");
        assert!(path.exists());
        assert!(updater.native_start_blocked().unwrap());
        assert_eq!(panel.resumes.load(Ordering::SeqCst), 0);
        panel.retry_reconcile.store(0, Ordering::SeqCst);
        updater
            .request_v2(UpdateRequestV2::UiLifecycle {
                foreground: true,
                new_user_launch: false,
                launch_session_id: None,
            })
            .await
            .unwrap();
        updater
            .request_v2(UpdateRequestV2::UiLifecycle {
                foreground: true,
                new_user_launch: false,
                launch_session_id: None,
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while *updater.operation.lock().unwrap() != UpdateOperation::Idle {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert!(!path.exists());
        assert!(!updater.native_start_blocked().unwrap());
        assert_eq!(panel.resumes.load(Ordering::SeqCst), 1);
        assert_eq!(installer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(tunnel.stops.load(Ordering::SeqCst), 1);
        assert!(!updater.coordinator.as_ref().unwrap().has_consent());
        assert!(!updater.status().unwrap().automatic);
        server.abort();
    }

    #[tokio::test]
    async fn public_startup_during_cancel_is_checked_after_recovery() {
        let installer = CancelledInstaller::new(false);
        let (base, panel, _, _, server, root) =
            updater_with_installer(false, Some(installer.clone())).await;
        let updater = Arc::new(
            HostUpdater::new_with_policy(
                root.path(),
                base.api.clone(),
                base.broker.clone(),
                base.barrier.clone(),
                base.version.clone(),
                base.backend.clone(),
                true,
            )
            .unwrap(),
        );
        updater.set_ui_connection_probe(Arc::new(|| true));
        updater.ui_lifecycle(true, false, None).unwrap();
        panel.retry_reconcile.store(1, Ordering::SeqCst);
        discover(&updater, &panel).await;
        confirm(&updater).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while *updater.operation.lock().unwrap() != UpdateOperation::Recovering {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        updater
            .request_v2(UpdateRequestV2::UiLifecycle {
                foreground: true,
                new_user_launch: true,
                launch_session_id: Some(uuid::Uuid::new_v4().to_string()),
            })
            .await
            .unwrap();
        updater.check(UpdateCheckReason::Startup).unwrap();
        panel.release.notify_one();
        tokio::time::timeout(Duration::from_secs(4), async {
            while *updater.operation.lock().unwrap() != UpdateOperation::Idle {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert!(!root.path().join("common/update-journal-v1.json").exists());
        assert_eq!(
            panel.calls.load(Ordering::SeqCst),
            2,
            "a genuine launch check must survive cancellation recovery"
        );
        assert_eq!(installer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(panel.resumes.load(Ordering::SeqCst), 1);
        assert!(!updater.coordinator.as_ref().unwrap().has_consent());
        server.abort();
    }

    #[tokio::test]
    async fn cancelled_offer_survives_a_real_resume_failure_and_later_recovery() {
        let installer = CancelledInstaller::new(false);
        let (updater, panel, _, _, server, root) =
            updater_with_installer(false, Some(installer.clone())).await;
        panel.fail_resume.store(true, Ordering::SeqCst);
        discover(&updater, &panel).await;
        let old_access = updater.broker.observe().await.unwrap().access.unwrap();
        confirm(&updater).await;
        wait_for_idle(&updater).await;
        assert_eq!(
            updater.status().unwrap().error_code.as_deref(),
            Some("update_recovery_failed")
        );
        let path = root.path().join("common/update-journal-v1.json");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path).unwrap()).unwrap()
                ["phase"],
            "cancel_requested"
        );
        let old_offer = updater.status_v2().unwrap().offer_id;
        updater.check(UpdateCheckReason::Manual).unwrap();
        wait_for_idle(&updater).await;
        assert_eq!(panel.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            updater.status_v2().unwrap().status.error_code.as_deref(),
            Some("update_refresh_recovery_required"),
            "the manual check failed before discovery and must report that failure"
        );
        panel.fail_resume.store(false, Ordering::SeqCst);
        updater.check(UpdateCheckReason::Foreground).unwrap();
        wait_for_idle(&updater).await;
        let new_access = updater.broker.observe().await.unwrap().access.unwrap();
        assert_ne!(
            old_access.identity().session_generation,
            new_access.identity().session_generation
        );
        assert!(!path.exists());
        updater.set_automatic(true).unwrap();
        updater.start_refresh().unwrap();
        wait_for_calls(&panel, 2).await;
        panel.release.notify_one();
        wait_for_idle(&updater).await;
        assert_eq!(
            installer.calls.load(Ordering::SeqCst),
            1,
            "same cancelled offer must not reopen after recovery"
        );
        assert_ne!(
            old_offer,
            updater.status_v2().unwrap().offer_id,
            "recovered auth generation needs a new offer identity"
        );
        assert!(!updater.coordinator.as_ref().unwrap().has_consent());
        discover(&updater, &panel).await;
        confirm(&updater).await;
        wait_for_idle(&updater).await;
        assert_eq!(
            installer.calls.load(Ordering::SeqCst),
            2,
            "manual retry stays permitted"
        );
        server.abort();
    }

    #[tokio::test]
    async fn interrupted_caller_keeps_native_consumer_and_journal_until_result() {
        let installer = CancelledInstaller::new(true);
        let (updater, panel, _, _, server, root) =
            updater_with_installer(false, Some(installer.clone())).await;
        updater.start_refresh().unwrap();
        wait_for_calls(&panel, 1).await;
        panel.release.notify_one();
        wait_for_refresh(&updater).await;
        let owner = updater.clone();
        let id = owner.coordinator.as_ref().unwrap().offer_id().unwrap();
        owner.coordinator.as_ref().unwrap().confirm(&id).unwrap();
        let install = tokio::spawn(async move {
            let access = owner.broker.access_token(None).await.unwrap();
            owner
                .coordinator
                .as_ref()
                .unwrap()
                .drive(&access, false)
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), installer.entered.notified())
            .await
            .unwrap();
        let path = root.path().join("common/update-journal-v1.json");
        assert!(path.exists());
        install.abort();
        assert!(install.await.unwrap_err().is_cancelled());
        assert!(updater.recover(None).await.is_err());
        assert!(path.exists());
        assert!(updater.native_start_blocked().unwrap());
        installer.release.notify_one();
        tokio::time::timeout(Duration::from_secs(2), async {
            while updater.install_recovery_gate.try_lock().is_err() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        updater.recover(None).await.unwrap();
        assert!(!path.exists());
        assert!(!updater.native_start_blocked().unwrap());
        server.abort();
    }

    #[tokio::test]
    async fn replaced_runtime_cannot_reassert_consent_or_delay_current_status() {
        let (updater, panel, backend, _, server, _root) = updater(false).await;
        discover(&updater, &panel).await;
        let old = updater.attach_ui();
        let current = updater.attach_ui();
        let id = updater.coordinator.as_ref().unwrap().offer_id().unwrap();
        assert!(updater
            .request_v2_for(Some(old), UpdateRequestV2::Confirm { offer_id: id })
            .await
            .is_err());
        assert!(!updater.coordinator.as_ref().unwrap().has_consent());
        assert!(backend.versions.lock().unwrap().is_empty());
        updater.check(UpdateCheckReason::Manual).unwrap();
        wait_for_calls(&panel, 2).await;
        tokio::time::timeout(
            Duration::from_millis(100),
            updater.request_v2_for(Some(current), UpdateRequestV2::Status {}),
        )
        .await
        .unwrap()
        .unwrap();
        panel.release.notify_one();
        wait_for_refresh(&updater).await;
        server.abort();
    }

    #[tokio::test]
    async fn desktop_timer_obeys_off_single_flight_and_skips_sleep_backlog() {
        let (updater, panel, _, _, server, _root) = updater(false).await;
        tokio::time::pause();
        updater.start_desktop_scheduler();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1800)).await;
        tokio::task::yield_now().await;
        assert_eq!(panel.calls.load(Ordering::SeqCst), 0);
        updater.set_automatic(true).unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1799)).await;
        tokio::task::yield_now().await;
        assert_eq!(panel.calls.load(Ordering::SeqCst), 0);
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::time::resume();
        wait_for_calls(&panel, 1).await;
        // The unresolved request coalesces ticks/manual checks; no catch-up burst.
        updater.check(UpdateCheckReason::Manual).unwrap();
        assert_eq!(panel.calls.load(Ordering::SeqCst), 1);
        panel.release.notify_one();
        wait_for_idle(&updater).await;
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(7200)).await;
        tokio::time::resume();
        wait_for_calls(&panel, 2).await;
        panel.release.notify_one();
        wait_for_idle(&updater).await;
        tokio::task::yield_now().await;
        assert_eq!(panel.calls.load(Ordering::SeqCst), 2);
        let weak = Arc::downgrade(&updater);
        drop(updater);
        tokio::task::yield_now().await;
        assert!(weak.upgrade().is_none());
        server.abort();
    }

    #[tokio::test]
    async fn android_prompt_file_survives_owner_recreation_but_never_persists_consent() {
        let (base, _panel, _, _, server, root) = updater(false).await;
        let make = || {
            Arc::new(
                HostUpdater::new_with_policy(
                    root.path(),
                    base.api.clone(),
                    base.broker.clone(),
                    base.barrier.clone(),
                    base.version.clone(),
                    base.backend.clone(),
                    true,
                )
                .unwrap(),
            )
        };
        let access = base.broker.access_token(None).await.unwrap();
        let session = uuid::Uuid::new_v4().to_string();
        let first = make();
        first.set_ui_connection_probe(Arc::new(|| true));
        first
            .ui_lifecycle(true, true, Some(session.clone()))
            .unwrap();
        let offer = UpdateOffer {
            version: "0.2.21".into(),
            notes: None,
            required: false,
        };
        let observe = |owner: &HostUpdater| {
            owner
                .coordinator
                .as_ref()
                .unwrap()
                .observe_resolved(Some((offer.clone(), test_descriptor("0.2.21"))), &access)
        };
        observe(&first);
        let id = first.coordinator.as_ref().unwrap().offer_id().unwrap();
        first
            .request_v2(UpdateRequestV2::Defer { offer_id: id })
            .await
            .unwrap();
        drop(first);
        let second = make();
        second.set_ui_connection_probe(Arc::new(|| true));
        observe(&second);
        second.ui_lifecycle(true, false, None).unwrap();
        assert!(!second.coordinator.as_ref().unwrap().prompt_pending());
        second.ui_lifecycle(true, true, Some(session)).unwrap();
        assert!(!second.coordinator.as_ref().unwrap().prompt_pending());
        second
            .ui_lifecycle(true, true, Some(uuid::Uuid::new_v4().to_string()))
            .unwrap();
        assert!(second.coordinator.as_ref().unwrap().prompt_pending());
        second
            .coordinator
            .as_ref()
            .unwrap()
            .confirm(&second.coordinator.as_ref().unwrap().offer_id().unwrap())
            .unwrap();
        second.save_prompt().unwrap();
        drop(second);
        let third = make();
        observe(&third);
        assert!(!third.coordinator.as_ref().unwrap().has_consent());
        let text =
            std::fs::read_to_string(root.path().join("updates/prompt-session.json")).unwrap();
        assert!(!text.contains("consent") && !text.contains("offer_id"));
        drop(third);
        std::fs::write(
            root.path().join("updates/prompt-session.json"),
            vec![b'x'; 5000],
        )
        .unwrap();
        let malformed = make();
        observe(&malformed);
        assert!(!malformed.coordinator.as_ref().unwrap().has_consent());
        server.abort();
    }

    #[tokio::test]
    async fn startup_retry_during_failed_check_is_not_lost_with_automatic_off() {
        let (updater, panel, _, _, server, _root) = updater(true).await;
        updater.check(UpdateCheckReason::Startup).unwrap();
        wait_for_calls(&panel, 1).await;
        updater.check(UpdateCheckReason::Startup).unwrap();
        panel.release.notify_one();
        wait_for_calls(&panel, 2).await;
        panel.release.notify_one();
        wait_for_idle(&updater).await;
        assert!(updater.coordinator.as_ref().unwrap().offer_id().is_some());
        assert_eq!(panel.calls.load(Ordering::SeqCst), 2);
        server.abort();
    }
    async fn wait_for_calls(panel: &Panel, expected: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while panel.calls.load(Ordering::SeqCst) != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    async fn wait_for_refresh(updater: &HostUpdater) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while matches!(
                *updater.operation.lock().unwrap(),
                UpdateOperation::Refreshing
            ) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    async fn wait_for_idle(updater: &HostUpdater) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while *updater.operation.lock().unwrap() != UpdateOperation::Idle {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[derive(Default)]
    struct PausedDownload {
        entered: Notify,
        release: Notify,
        files: Mutex<Vec<tempfile::NamedTempFile>>,
    }
    #[async_trait]
    impl UpdateBackend for PausedDownload {
        async fn resolve(
            &self,
            _: &AccessSnapshot,
            version: &str,
        ) -> Result<Option<ResolvedUpdate>, UpdateBackendError> {
            Ok(Some(test_descriptor(version)))
        }
        async fn prepare(
            &self,
            _: &AccessSnapshot,
            resolved: &ResolvedUpdate,
            _: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
        ) -> Result<PreparedUpdate, UpdateBackendError> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(test_prepared(resolved, &self.files))
        }
    }
    #[tokio::test]
    async fn manual_during_download_preserves_later_on_next_foreground() {
        let download = Arc::new(PausedDownload::default());
        let (base, panel, _, _, server, root) =
            updater_with_installer(false, Some(download.clone())).await;
        let updater = Arc::new(
            HostUpdater::new_with_policy(
                root.path(),
                base.api.clone(),
                base.broker.clone(),
                base.barrier.clone(),
                base.version.clone(),
                base.backend.clone(),
                true,
            )
            .unwrap(),
        );
        updater.set_ui_connection_probe(Arc::new(|| true));
        updater
            .ui_lifecycle(true, true, Some(uuid::Uuid::new_v4().to_string()))
            .unwrap();
        updater.set_automatic(true).unwrap();
        updater.check(UpdateCheckReason::Startup).unwrap();
        wait_for_calls(&panel, 1).await;
        panel.release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), download.entered.notified())
            .await
            .unwrap();
        updater
            .request_v2(UpdateRequestV2::Check {
                reason: UpdateCheckReason::Manual,
            })
            .await
            .unwrap();
        let id = updater.status_v2().unwrap().offer_id.unwrap();
        updater
            .request_v2(UpdateRequestV2::Defer { offer_id: id })
            .await
            .unwrap();
        download.release.notify_one();
        wait_for_idle(&updater).await;
        assert!(!updater.status_v2().unwrap().prompt_pending);
        updater.ui_lifecycle(false, false, None).unwrap();
        updater.ui_lifecycle(true, false, None).unwrap();
        updater.check(UpdateCheckReason::Foreground).unwrap();
        wait_for_calls(&panel, 2).await;
        panel.release.notify_one();
        wait_for_idle(&updater).await;
        server.abort();
        assert!(
            !updater.status_v2().unwrap().prompt_pending,
            "a completed old manual request must not erase newer Later on foreground"
        );
    }

    #[tokio::test]
    async fn genuine_android_launch_checks_once_even_with_warm_owner_and_automatic_off() {
        let (base, panel, _, _, server, root) = updater(false).await;
        let owner = Arc::new(
            HostUpdater::new_with_policy(
                root.path(),
                base.api.clone(),
                base.broker.clone(),
                base.barrier.clone(),
                base.version.clone(),
                base.backend.clone(),
                true,
            )
            .unwrap(),
        );
        owner.set_automatic(false).unwrap();
        let first = uuid::Uuid::new_v4().to_string();
        owner.ui_lifecycle(true, true, Some(first.clone())).unwrap();
        owner.check(UpdateCheckReason::Startup).unwrap();
        wait_for_calls(&panel, 1).await;
        panel.release.notify_one();
        wait_for_idle(&owner).await;
        let id = owner.status_v2().unwrap().offer_id.unwrap();
        owner
            .request_v2(UpdateRequestV2::Defer { offer_id: id })
            .await
            .unwrap();
        owner.ui_lifecycle(false, false, None).unwrap();
        owner.ui_lifecycle(true, true, Some(first)).unwrap();
        owner.check(UpdateCheckReason::Startup).unwrap();
        tokio::task::yield_now().await;
        assert_eq!(panel.calls.load(Ordering::SeqCst), 1);
        assert!(!owner.status_v2().unwrap().prompt_pending);
        owner
            .ui_lifecycle(true, true, Some(uuid::Uuid::new_v4().to_string()))
            .unwrap();
        owner.check(UpdateCheckReason::Startup).unwrap();
        wait_for_calls(&panel, 2).await;
        panel.release.notify_one();
        wait_for_idle(&owner).await;
        assert!(owner.status_v2().unwrap().prompt_pending);
        server.abort();
    }

    #[tokio::test]
    async fn desktop_notification_requires_hidden_admitted_ui_and_automatic() {
        let (owner, _, _, _, server, _root) = updater(false).await;
        let connected = Arc::new(AtomicBool::new(true));
        let probe = connected.clone();
        owner.set_ui_connection_probe(Arc::new(move || probe.load(Ordering::SeqCst)));
        let access = owner.broker.access_token(None).await.unwrap();
        owner.coordinator.as_ref().unwrap().observe_resolved(
            Some((
                UpdateOffer {
                    version: "0.2.21".into(),
                    notes: None,
                    required: false,
                },
                test_descriptor("0.2.21"),
            )),
            &access,
        );
        assert!(owner.take_notification().is_none(), "automatic off");
        owner.set_automatic(true).unwrap();
        assert!(
            owner.take_notification().is_none(),
            "unknown visibility must fail closed"
        );
        let generation = owner.attach_ui();
        let visible = |foreground| UpdateRequestV2::UiLifecycle {
            foreground,
            new_user_launch: false,
            launch_session_id: None,
        };
        owner
            .request_v2_for(Some(generation), visible(true))
            .await
            .unwrap();
        assert!(
            owner.take_notification().is_none(),
            "visible UI already presents the offer"
        );
        owner
            .request_v2_for(Some(generation), visible(false))
            .await
            .unwrap();
        connected.store(false, Ordering::SeqCst);
        assert!(
            owner.take_notification().is_none(),
            "native disconnect before lifecycle delivery"
        );
        connected.store(true, Ordering::SeqCst);
        owner.ui_disconnected();
        assert!(
            owner.take_notification().is_none(),
            "disconnected peer cannot provide visibility"
        );
        let current = owner.attach_ui();
        assert!(owner
            .request_v2_for(Some(generation), visible(false))
            .await
            .is_err());
        assert!(
            owner.take_notification().is_none(),
            "stale peer cannot restore visibility"
        );
        owner
            .request_v2_for(Some(current), visible(false))
            .await
            .unwrap();
        owner.set_automatic(false).unwrap();
        assert!(owner.take_notification().is_none());
        owner.set_automatic(true).unwrap();
        assert!(owner.take_notification().is_some());
        assert!(
            owner.take_notification().is_none(),
            "one banner per version"
        );
        assert!(
            owner
                .request_v2_for(
                    Some(current),
                    UpdateRequestV2::UiLifecycle {
                        foreground: true,
                        new_user_launch: true,
                        launch_session_id: Some(uuid::Uuid::new_v4().to_string())
                    }
                )
                .await
                .is_err(),
            "desktop must not acquire Android launch authority"
        );
        server.abort();
    }
    #[tokio::test]
    async fn manual_during_download_checks_fresh_metadata_once_when_download_finishes() {
        let download = Arc::new(PausedDownload::default());
        let (owner, panel, _, _, server, _root) =
            updater_with_installer(false, Some(download.clone())).await;
        owner.set_automatic(true).unwrap();
        owner.check(UpdateCheckReason::Startup).unwrap();
        wait_for_calls(&panel, 1).await;
        panel.release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), download.entered.notified())
            .await
            .unwrap();
        let id = owner.status_v2().unwrap().offer_id.unwrap();
        owner
            .request_v2(UpdateRequestV2::Defer { offer_id: id })
            .await
            .unwrap();
        for _ in 0..3 {
            owner.check(UpdateCheckReason::Manual).unwrap();
        }
        assert!(
            !owner.status_v2().unwrap().prompt_pending,
            "wait for fresh metadata before reopening"
        );
        download.release.notify_one();
        wait_for_calls(&panel, 2).await;
        assert_eq!(owner.status_v2().unwrap().phase, "checking");
        panel.release.notify_one();
        wait_for_idle(&owner).await;
        assert!(owner.status_v2().unwrap().prompt_pending);
        assert_eq!(panel.calls.load(Ordering::SeqCst), 2);
        server.abort();
    }
    #[tokio::test]
    async fn status_metadata_tracks_only_the_coordinators_current_offer() {
        let (owner, panel, _, _, server, _root) = updater(false).await;
        owner.check(UpdateCheckReason::Startup).unwrap();
        wait_for_calls(&panel, 1).await;
        panel.release.notify_one();
        wait_for_idle(&owner).await;
        let access = owner.broker.access_token(None).await.unwrap();
        let coordinator = owner.coordinator.as_ref().unwrap();
        coordinator.invalidate();

        let idle = owner.status_v2().unwrap();
        assert_eq!(idle.phase, "idle");
        assert!(idle.offer_id.is_none());
        assert!(!idle.update_available);
        assert!(idle.status.notes.is_none());
        assert!(!idle.status.required);

        let offer = UpdateOffer {
            version: "0.2.22".into(),
            notes: Some("current offer notes".into()),
            required: true,
        };
        coordinator.observe_resolved(Some((offer, test_descriptor("0.2.22"))), &access);
        let available = owner.status_v2().unwrap();
        assert_eq!(available.phase, "available");
        assert!(available.offer_id.is_some());
        assert!(available.update_available);
        assert_eq!(available.status.version.as_deref(), Some("0.2.22"));
        assert_eq!(
            available.status.notes.as_deref(),
            Some("current offer notes")
        );
        assert!(available.status.required);
        server.abort();
    }

    #[tokio::test]
    async fn later_during_manual_refresh_wins_over_completion() {
        let (owner, panel, _, _, server, _root) = updater(false).await;
        owner.check(UpdateCheckReason::Startup).unwrap();
        wait_for_calls(&panel, 1).await;
        panel.release.notify_one();
        wait_for_idle(&owner).await;
        let id = owner.status_v2().unwrap().offer_id.unwrap();
        owner.check(UpdateCheckReason::Manual).unwrap();
        wait_for_calls(&panel, 2).await;
        owner
            .request_v2(UpdateRequestV2::Defer { offer_id: id })
            .await
            .unwrap();
        panel.release.notify_one();
        wait_for_idle(&owner).await;
        assert!(!owner.status_v2().unwrap().prompt_pending);
        server.abort();
    }
    #[tokio::test]
    async fn failed_manual_does_not_turn_next_timer_into_manual() {
        let (owner, panel, _, _, server, _root) = updater(true).await;
        let access = owner.broker.access_token(None).await.unwrap();
        let c = owner.coordinator.as_ref().unwrap();
        c.observe_resolved(
            Some((
                UpdateOffer {
                    version: "0.2.21".into(),
                    notes: None,
                    required: false,
                },
                test_descriptor("0.2.21"),
            )),
            &access,
        );
        owner
            .request_v2(UpdateRequestV2::Defer {
                offer_id: c.offer_id().unwrap(),
            })
            .await
            .unwrap();
        owner.check(UpdateCheckReason::Manual).unwrap();
        wait_for_calls(&panel, 1).await;
        panel.release.notify_one();
        wait_for_idle(&owner).await;
        assert_eq!(
            owner.status_v2().unwrap().status.error_code.as_deref(),
            Some("update_refresh_service")
        );
        owner.set_automatic(true).unwrap();
        owner.check(UpdateCheckReason::Timer).unwrap();
        wait_for_calls(&panel, 2).await;
        panel.release.notify_one();
        wait_for_idle(&owner).await;
        assert!(!owner.status_v2().unwrap().prompt_pending);
        server.abort();
    }
    #[tokio::test]
    async fn yes_supersedes_persisted_later_without_persisting_consent() {
        let download = Arc::new(PausedDownload::default());
        let (base, panel, _, _, server, root) =
            updater_with_installer(false, Some(download.clone())).await;
        let owner = Arc::new(
            HostUpdater::new_with_policy(
                root.path(),
                base.api.clone(),
                base.broker.clone(),
                base.barrier.clone(),
                base.version.clone(),
                base.backend.clone(),
                true,
            )
            .unwrap(),
        );
        owner.set_ui_connection_probe(Arc::new(|| true));
        owner
            .ui_lifecycle(true, true, Some(uuid::Uuid::new_v4().to_string()))
            .unwrap();
        owner.check(UpdateCheckReason::Startup).unwrap();
        wait_for_calls(&panel, 1).await;
        panel.release.notify_one();
        wait_for_idle(&owner).await;
        let id = owner.status_v2().unwrap().offer_id.unwrap();
        owner
            .request_v2(UpdateRequestV2::Defer {
                offer_id: id.clone(),
            })
            .await
            .unwrap();
        owner
            .request_v2(UpdateRequestV2::Confirm { offer_id: id })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), download.entered.notified())
            .await
            .unwrap();
        owner.ui_disconnected();
        download.release.notify_one();
        wait_for_idle(&owner).await;
        let recreated = HostUpdater::new_with_policy(
            root.path(),
            base.api.clone(),
            base.broker.clone(),
            base.barrier.clone(),
            base.version.clone(),
            base.backend.clone(),
            true,
        )
        .unwrap();
        assert!(
            recreated
                .coordinator
                .as_ref()
                .unwrap()
                .deferred_version()
                .is_none(),
            "old Later must not return after common recreation"
        );
        assert!(!recreated.coordinator.as_ref().unwrap().has_consent());
        server.abort();
    }
}
