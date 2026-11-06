use crate::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Notify;

#[derive(Clone)]
struct BoundOffer {
    id: String,
    offer: UpdateOffer,
    resolved: ResolvedUpdate,
    access: AccessSnapshot,
}
impl BoundOffer {
    fn same_scope(&self, access: &AccessSnapshot) -> bool {
        self.access.auth_epoch() == access.auth_epoch()
            && self.access.family() == access.family()
            && self.access.identity() == access.identity()
    }
}
struct State {
    phase: UpdatePhase,
    offer: Option<BoundOffer>,
    prepared: Option<PreparedUpdate>,
    consent: bool,
    automatic: bool,
    deferred: Option<String>,
    presented: BTreeSet<String>,
    notified: BTreeSet<String>,
    foreground: bool,
}
type UiProbe = Arc<dyn Fn() -> bool + Send + Sync>;
pub struct UpdateCoordinator<B> {
    backend: Arc<B>,
    barrier: Arc<dyn UpdateInstallBarrier>,
    state: Arc<Mutex<State>>,
    operation: AsyncMutex<()>,
    installation_gate: Arc<AsyncMutex<()>>,
    changed: Notify,
    requires_foreground: bool,
    ui_connection: Arc<Mutex<Option<UiProbe>>>,
}
impl<B: UpdateBackend + 'static> UpdateCoordinator<B> {
    pub fn new(backend: Arc<B>, barrier: Arc<dyn UpdateInstallBarrier>) -> Self {
        Self::with_foreground_guard(backend, barrier, cfg!(target_os = "android"))
    }
    pub fn with_foreground_guard(
        backend: Arc<B>,
        barrier: Arc<dyn UpdateInstallBarrier>,
        required: bool,
    ) -> Self {
        Self {
            backend,
            barrier,
            state: Arc::new(Mutex::new(State {
                phase: UpdatePhase::Idle,
                offer: None,
                prepared: None,
                consent: false,
                automatic: false,
                deferred: None,
                presented: BTreeSet::new(),
                notified: BTreeSet::new(),
                foreground: false,
            })),
            operation: AsyncMutex::new(()),
            installation_gate: Arc::new(AsyncMutex::new(())),
            changed: Notify::new(),
            requires_foreground: required,
            ui_connection: Arc::new(Mutex::new(None)),
        }
    }
    pub fn installation_gate(&self) -> Arc<AsyncMutex<()>> {
        self.installation_gate.clone()
    }
    pub fn phase(&self) -> UpdatePhase {
        self.state
            .lock()
            .expect("update state poisoned")
            .phase
            .clone()
    }
    pub fn offer_id(&self) -> Option<String> {
        self.state
            .lock()
            .expect("update state poisoned")
            .offer
            .as_ref()
            .map(|o| o.id.clone())
    }
    pub fn has_consent(&self) -> bool {
        self.state.lock().expect("update state poisoned").consent
    }
    pub fn deferred_version(&self) -> Option<String> {
        self.state
            .lock()
            .expect("update state poisoned")
            .deferred
            .clone()
    }
    pub fn restore_deferred_version(&self, version: Option<String>) {
        self.state.lock().expect("update state poisoned").deferred = version;
    }
    pub fn set_ui_lifecycle(&self, foreground: bool, new_user_launch: bool) {
        let mut state = self.state.lock().expect("update state poisoned");
        state.foreground = foreground;
        if self.requires_foreground && !foreground {
            // A cancelled early Yes needs a new decision on return. Once the
            // native handoff starts, its own Activity pause must not re-prompt.
            if state.consent && !Self::terminal(&state.phase) {
                if let Some(version) = state.offer.as_ref().map(|o| o.offer.version.clone()) {
                    state.presented.remove(&version);
                }
            }
            state.consent = false;
        }
        if self.requires_foreground && new_user_launch {
            state.deferred = None;
            state.presented.clear();
        }
        drop(state);
        self.changed.notify_one();
    }
    pub fn set_ui_connection_probe(&self, probe: Arc<dyn Fn() -> bool + Send + Sync>) {
        *self.ui_connection.lock().expect("update probe poisoned") = Some(probe);
    }
    pub fn ui_foreground(&self) -> bool {
        let foreground = self.state.lock().expect("update state poisoned").foreground;
        foreground && self.ui_connected()
    }
    pub fn ui_connected(&self) -> bool {
        let probe = self
            .ui_connection
            .lock()
            .expect("update probe poisoned")
            .clone();
        probe.is_some_and(|probe| probe())
    }
    pub fn retain_scope(&self, access: &AccessSnapshot) {
        let stale = self
            .state
            .lock()
            .expect("update state poisoned")
            .offer
            .as_ref()
            .is_some_and(|offer| !offer.same_scope(access));
        if stale {
            self.invalidate();
        }
    }
    pub fn set_automatic(&self, enabled: bool) {
        self.state.lock().expect("update state poisoned").automatic = enabled;
        self.changed.notify_one();
    }
    /// Legacy metadata can be displayed, but cannot mint an installable offer.
    pub fn observe(&self, offer: Option<UpdateOffer>) {
        let mut state = self.state.lock().expect("update state poisoned");
        if Self::terminal(&state.phase) {
            return;
        }
        state.offer = None;
        state.consent = false;
        state.prepared = None;
        state.phase = offer
            .map(UpdatePhase::Available)
            .unwrap_or(UpdatePhase::Idle);
        drop(state);
        self.changed.notify_one();
    }
    pub fn observe_resolved(
        &self,
        offer: Option<(UpdateOffer, ResolvedUpdate)>,
        access: &AccessSnapshot,
    ) {
        let mut state = self.state.lock().expect("update state poisoned");
        if Self::terminal(&state.phase) {
            return;
        }
        let same = match (&state.offer, &offer) {
            (Some(old), Some((_, resolved))) => old.resolved == *resolved && old.same_scope(access),
            _ => false,
        };
        if same {
            if let (Some(old), Some((offer, _))) = (&mut state.offer, offer) {
                old.offer = offer;
            }
            return;
        }
        state.consent = false;
        state.prepared = None;
        state.offer = offer.map(|(offer, resolved)| {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let mut digest = Sha256::new();
            digest.update(resolved.cache_key().unwrap_or_default());
            digest.update(NEXT.fetch_add(1, Ordering::Relaxed).to_le_bytes());
            digest.update(format!("{:?}", std::time::SystemTime::now()).as_bytes());
            BoundOffer {
                id: format!("{:x}", digest.finalize()),
                offer,
                resolved,
                access: access.clone(),
            }
        });
        state.phase = state
            .offer
            .as_ref()
            .map(|o| UpdatePhase::Available(o.offer.clone()))
            .unwrap_or(UpdatePhase::Idle);
        drop(state);
        self.changed.notify_one();
    }
    pub fn invalidate(&self) {
        let mut state = self.state.lock().expect("update state poisoned");
        state.consent = false;
        if !Self::terminal(&state.phase) {
            state.offer = None;
            state.prepared = None;
            state.phase = UpdatePhase::Idle;
        }
        drop(state);
        self.changed.notify_one();
    }
    pub fn confirm(&self, id: &str) -> Result<(), UpdateBackendError> {
        let foreground = self.ui_foreground();
        let mut state = self.state.lock().expect("update state poisoned");
        if state.offer.as_ref().is_none_or(|o| o.id != id) {
            return Err(UpdateBackendError::new("update_offer_changed"));
        }
        if Self::terminal(&state.phase) {
            return Ok(());
        }
        if self.requires_foreground && !foreground {
            return Err(UpdateBackendError::new("update_ui_background"));
        }
        state.consent = true;
        state.deferred = None;
        drop(state);
        self.changed.notify_one();
        Ok(())
    }
    pub fn defer(&self, id: &str) -> Result<(), UpdateBackendError> {
        let mut state = self.state.lock().expect("update state poisoned");
        if Self::terminal(&state.phase) {
            return Err(UpdateBackendError::new("update_install_in_progress"));
        }
        let version = state
            .offer
            .as_ref()
            .filter(|o| o.id == id)
            .ok_or_else(|| UpdateBackendError::new("update_offer_changed"))?
            .offer
            .version
            .clone();
        state.consent = false;
        state.deferred = Some(version.clone());
        state.presented.insert(version);
        drop(state);
        self.changed.notify_one();
        Ok(())
    }
    pub fn prompt_pending(&self) -> bool {
        let state = self.state.lock().expect("update state poisoned");
        state.offer.as_ref().is_some_and(|o| {
            !Self::terminal(&state.phase)
                && !state.consent
                && state.deferred.as_ref() != Some(&o.offer.version)
                && !state.presented.contains(&o.offer.version)
        })
    }
    pub fn present(&self, id: &str) -> Result<(), UpdateBackendError> {
        let mut state = self.state.lock().expect("update state poisoned");
        let version = state
            .offer
            .as_ref()
            .filter(|o| o.id == id)
            .ok_or_else(|| UpdateBackendError::new("update_offer_changed"))?
            .offer
            .version
            .clone();
        state.presented.insert(version);
        Ok(())
    }
    pub fn request_manual_prompt(&self) {
        let mut state = self.state.lock().expect("update state poisoned");
        if let Some(version) = state.offer.as_ref().map(|o| o.offer.version.clone()) {
            state.presented.remove(&version);
            state.deferred = None;
        }
    }
    pub fn suppress_notification(&self) {
        let mut state = self.state.lock().expect("update state poisoned");
        if let Some(version) = state.offer.as_ref().map(|o| o.offer.version.clone()) {
            state.notified.insert(version);
        }
    }
    pub fn take_notification(&self) -> Option<UpdateOffer> {
        let mut state = self.state.lock().expect("update state poisoned");
        if Self::terminal(&state.phase) {
            return None;
        }
        let offer = state.offer.as_ref()?.offer.clone();
        if state.consent
            || state.presented.contains(&offer.version)
            || state.deferred.as_ref() == Some(&offer.version)
        {
            return None;
        }
        state
            .notified
            .insert(offer.version.clone())
            .then_some(offer)
    }
    // Old callers cannot manufacture consent via preferences or a manual boolean.
    pub async fn install_automatically(
        &self,
        _: &AccessSnapshot,
        _: UpdatePreferences,
    ) -> Result<UpdatePhase, UpdateError> {
        Err(UpdateBackendError::new("update_consent_required").into())
    }
    pub async fn install_now(&self, _: &AccessSnapshot) -> Result<UpdatePhase, UpdateError> {
        Err(UpdateBackendError::new("update_consent_required").into())
    }
    fn terminal(phase: &UpdatePhase) -> bool {
        matches!(
            phase,
            UpdatePhase::Installing { .. }
                | UpdatePhase::ReadyToRestart { .. }
                | UpdatePhase::AwaitingInstallation { .. }
        )
    }
    fn current(&self, offer: &BoundOffer) -> bool {
        self.state
            .lock()
            .expect("update state poisoned")
            .offer
            .as_ref()
            .is_some_and(|o| o.id == offer.id)
    }
    fn wanted(&self, offer: &BoundOffer) -> bool {
        let state = self.state.lock().expect("update state poisoned");
        state.offer.as_ref().is_some_and(|o| o.id == offer.id) && (state.automatic || state.consent)
    }
    fn fail(&self, offer: &BoundOffer, code: &str) {
        let mut state = self.state.lock().expect("update state poisoned");
        if state.offer.as_ref().is_some_and(|o| o.id == offer.id) {
            state.consent = false;
            // Retry goes through backend cache admission/signature verification.
            // Release the old lease without deleting bytes; an invalid file can
            // then be replaced, and a valid one can still be reused safely.
            state.prepared = None;
            state.phase = UpdatePhase::Failed {
                version: offer.offer.version.clone(),
                code: code.into(),
            };
        }
    }
    async fn authority(
        &self,
        offer: &BoundOffer,
        access: &AccessSnapshot,
    ) -> Result<(), UpdateError> {
        if !offer.same_scope(access) || !self.current(offer) {
            return Err(UpdateBackendError::new("update_offer_changed").into());
        }
        self.barrier.validate_authority(access).await?;
        if !self.current(offer) {
            return Err(UpdateBackendError::new("update_offer_changed").into());
        }
        Ok(())
    }
    pub async fn drive(
        &self,
        access: &AccessSnapshot,
        automatic: bool,
    ) -> Result<UpdatePhase, UpdateError> {
        self.set_automatic(automatic);
        let _operation = self.operation.lock().await;
        let offer = {
            let state = self.state.lock().expect("update state poisoned");
            if Self::terminal(&state.phase) {
                return Ok(state.phase.clone());
            }
            state.offer.clone()
        };
        let Some(offer) = offer else {
            return Ok(self.phase());
        };
        let result = self.drive_offer(&offer, access).await;
        if let Err(error) = &result {
            let code = match error {
                UpdateError::Backend(e) => e.code(),
                UpdateError::Barrier(e) => e.code(),
            };
            self.fail(&offer, code);
        }
        result
    }
    async fn drive_offer(
        &self,
        offer: &BoundOffer,
        access: &AccessSnapshot,
    ) -> Result<UpdatePhase, UpdateError> {
        if !self.wanted(offer) {
            return Ok(self.phase());
        }
        self.authority(offer, access).await?;
        let cached = self
            .state
            .lock()
            .expect("update state poisoned")
            .prepared
            .clone();
        let prepared = if let Some(prepared) = cached {
            prepared.revalidate_async().await?;
            prepared
        } else {
            {
                self.state.lock().expect("update state poisoned").phase =
                    UpdatePhase::Downloading {
                        version: offer.offer.version.clone(),
                        downloaded: 0,
                        total: offer.resolved.size_bytes,
                    };
            }
            let state = self.state.clone();
            let id = offer.id.clone();
            let version = offer.offer.version.clone();
            let progress = Arc::new(move |p: DownloadProgress| {
                let mut state = state.lock().expect("update state poisoned");
                if state.offer.as_ref().is_some_and(|o| o.id == id) {
                    state.phase = UpdatePhase::Downloading {
                        version: version.clone(),
                        downloaded: p.downloaded,
                        total: p.total,
                    };
                }
            });
            let download = self.backend.prepare(access, &offer.resolved, progress);
            tokio::pin!(download);
            let prepared = loop {
                tokio::select! {
                    result = &mut download => break result?,
                    _ = self.changed.notified() => {
                        if !self.wanted(offer) {
                            let mut state = self.state.lock().expect("update state poisoned");
                            if state.offer.as_ref().is_some_and(|o| o.id == offer.id) { state.phase = UpdatePhase::Available(offer.offer.clone()); }
                            return Ok(state.phase.clone());
                        }
                    }
                }
            };
            if prepared.resolved() != &offer.resolved {
                return Err(UpdateBackendError::new("update_offer_changed").into());
            }
            self.authority(offer, access).await?;
            prepared.revalidate_async().await?;
            let mut state = self.state.lock().expect("update state poisoned");
            state.prepared = Some(prepared.clone());
            prepared
        };
        {
            let mut state = self.state.lock().expect("update state poisoned");
            if state.consent || !matches!(state.phase, UpdatePhase::Failed { .. }) {
                state.phase = UpdatePhase::ReadyToInstall {
                    version: offer.offer.version.clone(),
                };
            }
            if !state.consent {
                return Ok(state.phase.clone());
            }
        }
        // The package named by Yes must still be offered by the authenticated
        // server. Cached bytes or matching version alone are not fresh authority.
        let fresh = self.backend.resolve(access, &offer.offer.version).await?;
        if fresh.as_ref() != Some(&offer.resolved) {
            return Err(UpdateBackendError::new("update_offer_changed").into());
        }
        // Native consumers can outlive a cancelled caller (e.g. system installer).
        // The owned operation retains the gate and journal through their result.
        let installation = self.installation_gate.clone().lock_owned().await;
        self.authority(offer, access).await?;
        prepared.revalidate_async().await?;
        let foreground = self.ui_foreground();
        {
            let mut state = self.state.lock().expect("update state poisoned");
            if !state.consent || (self.requires_foreground && !foreground) {
                // The connection probe may observe disconnect before the pause
                // event. Apply the same early-consent cancellation here.
                if state.consent {
                    state.presented.remove(&offer.offer.version);
                }
                state.consent = false;
                return Ok(state.phase.clone());
            }
            state.phase = UpdatePhase::Installing {
                version: offer.offer.version.clone(),
            };
        }
        let backend = self.backend.clone();
        let barrier = self.barrier.clone();
        let state = self.state.clone();
        let probe = self.ui_connection.clone();
        let requires_foreground = self.requires_foreground;
        let offer = offer.clone();
        let access = access.clone();
        tokio::spawn(async move {
            let _installation = installation;
            let result: Result<UpdatePhase, UpdateError> = async {
                let stopped = barrier.prepare(&offer.offer.version).await?;
                let result = async {
                    prepared.revalidate_async().await?;
                    barrier.validate_authority(&access).await?;
                    let (current, foreground) = {
                        let state = state.lock().expect("update state poisoned");
                        (
                            state.offer.as_ref().is_some_and(|o| o.id == offer.id) && state.consent,
                            state.foreground,
                        )
                    };
                    if !current {
                        return Err(UpdateBackendError::new("update_offer_changed").into());
                    }
                    let connected = probe.lock().expect("update probe poisoned").clone();
                    if requires_foreground && !(foreground && connected.is_some_and(|p| p())) {
                        return Err(UpdateBackendError::new("update_ui_background").into());
                    }
                    backend
                        .install_prepared(&prepared, stopped)
                        .await
                        .map_err(UpdateError::from)
                }
                .await;
                let installed = match result {
                    Ok(InstallResult::Installed(update))
                        if update.version == offer.offer.version =>
                    {
                        UpdatePhase::ReadyToRestart {
                            version: update.version,
                        }
                    }
                    Ok(InstallResult::InstallerOpened(update))
                        if update.version == offer.offer.version =>
                    {
                        UpdatePhase::AwaitingInstallation {
                            version: update.version,
                        }
                    }
                    other => {
                        barrier.installer_failed().await?;
                        return Err(match other {
                            Err(error) => error,
                            Ok(InstallResult::NoUpdate) => {
                                UpdateBackendError::new("update_offer_changed").into()
                            }
                            _ => {
                                UpdateBackendError::new("installed_update_version_mismatch").into()
                            }
                        });
                    }
                };
                barrier.installer_opened().await?;
                Ok(installed)
            }
            .await;
            let mut state = state.lock().expect("update state poisoned");
            state.consent = false;
            if result.is_err() {
                // Also release on completion when the caller was cancelled and
                // cannot reach fail(). The native consumer has finished here.
                state.prepared = None;
            }
            state.phase = match &result {
                Ok(phase) => phase.clone(),
                Err(error) => UpdatePhase::Failed {
                    version: offer.offer.version,
                    code: match error {
                        UpdateError::Backend(e) => e.code(),
                        UpdateError::Barrier(e) => e.code(),
                    }
                    .into(),
                },
            };
            result
        })
        .await
        .map_err(|_| UpdateBackendError::new("update_install_outcome_unknown"))?
    }
}
